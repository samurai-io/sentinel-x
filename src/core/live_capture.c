#include "sentinel_core.h"
#include "sentinel_common.h"
#include "sentinel_ids_ips.h"
#include "sentinel_zero_trust.h"
#include "sentinel_notification.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <features.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <signal.h>

#define MAX_BLOCKED_IPS 128
static char blocked_ips[MAX_BLOCKED_IPS][MAX_IP_LEN];
static int blocked_ips_count = 0;
static pthread_mutex_t block_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool keep_running = true;

// Pipeline evaluator (implemented in main.c)
bool evaluate_pipeline(FirewallEngine *fe, IdsIpsEngine *ids_ips, ZeroTrustEngine *zt, Packet *pkt, char *verdict, size_t len);

static void ips_kernel_block(const char *ip) {
    pthread_mutex_lock(&block_mutex);
    // Check if already blocked in memory
    for (int i = 0; i < blocked_ips_count; i++) {
        if (strcmp(blocked_ips[i], ip) == 0) {
            pthread_mutex_unlock(&block_mutex);
            return;
        }
    }
    
    if (blocked_ips_count < MAX_BLOCKED_IPS) {
        snprintf(blocked_ips[blocked_ips_count], MAX_IP_LEN, "%s", ip);
        blocked_ips_count++;
    }
    pthread_mutex_unlock(&block_mutex);

    sentinel_log(LOG_LEVEL_CRITICAL, "IPS KERNEL DEFENSE: Adding iptables DROP rule for IP: %s", ip);
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "iptables -I INPUT -s %.45s -j DROP", ip);
    int ret = system(cmd);
    (void)ret;
}

static void ips_kernel_cleanup(void) {
    pthread_mutex_lock(&block_mutex);
    if (blocked_ips_count > 0) {
        sentinel_log(LOG_LEVEL_INFO, "Cleaning up %d temporary iptables blocking rules...", blocked_ips_count);
        for (int i = 0; i < blocked_ips_count; i++) {
            char cmd[256];
            snprintf(cmd, sizeof(cmd), "iptables -D INPUT -s %.45s -j DROP", blocked_ips[i]);
            int ret = system(cmd);
            (void)ret;
        }
        blocked_ips_count = 0;
    }
    pthread_mutex_unlock(&block_mutex);
}

static void handle_sigint(int sig) {
    (void)sig;
    keep_running = false;
}

void sentinel_live_capture_start(FirewallEngine *fe, void *ids_ips_ptr, void *zt_ptr, const char *interface_name) {
    IdsIpsEngine *ids_ips = (IdsIpsEngine *)ids_ips_ptr;
    ZeroTrustEngine *zt = (ZeroTrustEngine *)zt_ptr;

    // Register signal handlers for clean teardown of rules on interrupt
    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    // Create raw packet socket
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        sentinel_log(LOG_LEVEL_CRITICAL, "Failed to open raw packet socket. Are you running as root/sudo?");
        return;
    }

    if (interface_name && strlen(interface_name) > 0) {
        if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface_name, strlen(interface_name)) < 0) {
            sentinel_log(LOG_LEVEL_WARNING, "Failed to bind directly to interface %s. Capturing globally.", interface_name);
        } else {
            sentinel_log(LOG_LEVEL_INFO, "Live capture successfully bound to device: %s", interface_name);
        }
    }

    sentinel_log(LOG_LEVEL_INFO, "Real-time network capture active. Monitoring traffic... Press Ctrl+C to terminate.");

    unsigned char buffer[65536];
    while (keep_running) {
        ssize_t data_size = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (data_size < 0) {
            if (keep_running) {
                sentinel_log(LOG_LEVEL_ERROR, "Recvfrom failed reading raw socket frame");
            }
            break;
        }

        // Ethernet frame header check
        if (data_size < 14) continue;

        uint16_t eth_type = (buffer[12] << 8) | buffer[13];
        if (eth_type != 0x0800) {
            continue; // Skip non-IPv4 frames for simplified parsing demo
        }

        size_t ip_offset = 14;
        if ((size_t)data_size < ip_offset + 20) continue;

        unsigned char *ip_hdr = &buffer[ip_offset];
        uint8_t ip_ver = ip_hdr[0] >> 4;
        uint8_t ip_ihl = ip_hdr[0] & 0x0F;
        size_t ip_header_len = ip_ihl * 4;

        if (ip_ver != 4 || (size_t)data_size < ip_offset + ip_header_len) continue;

        uint8_t protocol = ip_hdr[9];

        struct in_addr src_addr, dst_addr;
        memcpy(&src_addr, &ip_hdr[12], 4);
        memcpy(&dst_addr, &ip_hdr[16], 4);

        char src_ip[MAX_IP_LEN];
        char dst_ip[MAX_IP_LEN];
        inet_ntop(AF_INET, &src_addr, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &dst_addr, dst_ip, sizeof(dst_ip));

        // Skip localhost packets to prevent loopback spamming
        if (strcmp(src_ip, "127.0.0.1") == 0 && strcmp(dst_ip, "127.0.0.1") == 0) {
            continue;
        }

        uint16_t src_port = 0;
        uint16_t dst_port = 0;
        uint8_t tcp_flags = 0;
        unsigned char *payload = NULL;
        size_t payload_len = 0;
        ProtocolType proto_type;

        if (protocol == IPPROTO_TCP) {
            proto_type = PROTO_TCP;
            size_t tcp_offset = ip_offset + ip_header_len;
            if ((size_t)data_size < tcp_offset + 20) continue;

            unsigned char *tcp_hdr = &buffer[tcp_offset];
            src_port = (tcp_hdr[0] << 8) | tcp_hdr[1];
            dst_port = (tcp_hdr[2] << 8) | tcp_hdr[3];
            tcp_flags = tcp_hdr[13];

            size_t tcp_doff = (tcp_hdr[12] >> 4) * 4;
            if ((size_t)data_size >= tcp_offset + tcp_doff) {
                payload = tcp_hdr + tcp_doff;
                payload_len = (size_t)data_size - (tcp_offset + tcp_doff);
            }
        } else if (protocol == IPPROTO_UDP) {
            proto_type = PROTO_UDP;
            size_t udp_offset = ip_offset + ip_header_len;
            if ((size_t)data_size < udp_offset + 8) continue;

            unsigned char *udp_hdr = &buffer[udp_offset];
            src_port = (udp_hdr[0] << 8) | udp_hdr[1];
            dst_port = (udp_hdr[2] << 8) | udp_hdr[3];

            payload = udp_hdr + 8;
            payload_len = (size_t)data_size - (udp_offset + 8);
        } else if (protocol == IPPROTO_ICMP) {
            proto_type = PROTO_ICMP;
        } else {
            continue;
        }

        Packet *pkt = sentinel_packet_create(src_ip, dst_ip, src_port, dst_port, proto_type, tcp_flags, payload, payload_len);
        if (!pkt) continue;

        char verdict[512] = {0};
        bool allowed = evaluate_pipeline(fe, ids_ips, zt, pkt, verdict, sizeof(verdict));

        if (!allowed) {
            sentinel_log(LOG_LEVEL_WARNING, "REAL-TIME DROP: Packet from %s:%d -> %s:%d [%s] -> Verdict: %s",
                         pkt->src_ip, pkt->src_port, pkt->dst_ip, pkt->dst_port,
                         pkt->protocol == PROTO_TCP ? "TCP" : (pkt->protocol == PROTO_UDP ? "UDP" : "ICMP"),
                         verdict);

            // Active IPS Response: Drop at kernel-level using iptables
            if (strstr(verdict, "WAF") || strstr(verdict, "IDS/IPS") || strstr(verdict, "Zero Trust")) {
                ips_kernel_block(pkt->src_ip);
            }
        } else {
            // Optional verbose print for debugging normal allowed packets
            // sentinel_log(LOG_LEVEL_DEBUG, "PASS: %s:%d -> %s:%d", pkt->src_ip, pkt->src_port, pkt->dst_ip, pkt->dst_port);
        }

        sentinel_packet_free(pkt);
    }

    close(sock);
    ips_kernel_cleanup();
    sentinel_log(LOG_LEVEL_INFO, "Live capture terminated.");
}
