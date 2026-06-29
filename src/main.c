#include "sentinel_common.h"
#include "sentinel_core.h"
#include "sentinel_dpi.h"
#include "sentinel_waf.h"
#include "sentinel_ids_ips.h"
#include "sentinel_zero_trust.h"
#include "sentinel_notification.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Full multi-layer inspection pipeline orchestration
bool evaluate_pipeline(FirewallEngine *fe, IdsIpsEngine *ids_ips, ZeroTrustEngine *zt, Packet *pkt, char *verdict, size_t len) {
    char reason[256] = {0};

    // 1. IDS/IPS Layer: Check Quarantine & Port Scan Detector
    if (!sentinel_ids_ips_process(ids_ips, pkt, reason, sizeof(reason))) {
        snprintf(verdict, len, "BLOCKED by IDS/IPS (%s)", reason);
        // Alert admin on initial port scan detection
        if (strstr(reason, "Port scan detected") != NULL) {
            char alert_msg[512];
            snprintf(alert_msg, sizeof(alert_msg), "SENTINEL-X IDS ALERT: %s", reason);
            sentinel_send_sms("+916235242509", alert_msg);
        }
        return false;
    }

    // 2. Zero Trust Layer: Evaluate Trust Score
    if (!sentinel_zt_evaluate(zt, pkt, reason, sizeof(reason))) {
        snprintf(verdict, len, "BLOCKED by Zero Trust (%s)", reason);
        return false;
    }

    // 3. Stateful Filter & Rate Limiter Layer
    if (!sentinel_process_packet(fe, pkt, reason, sizeof(reason))) {
        if (strcmp(reason, "Rate limit exceeded") == 0) {
            // Penalize Zero Trust score for rate limiting violation
            sentinel_zt_penalize(zt, pkt->src_ip, 10, "Rate Limit Violations");
        }
        snprintf(verdict, len, "BLOCKED by Core Filter (%s)", reason);
        return false;
    }

    // 4. DPI & WAF Layers (Inspection of parsed/raw payload)
    if (pkt->payload && pkt->payload_len > 0) {
        DpiResult dpi;
        if (sentinel_dpi_inspect(pkt, &dpi)) {
            if (dpi.protocol == DPI_PROTO_HTTP) {
                if (sentinel_waf_inspect(&dpi.meta.http, reason, sizeof(reason))) {
                    sentinel_zt_penalize(zt, pkt->src_ip, 30, reason); // Heavy penalty
                    snprintf(verdict, len, "BLOCKED by WAF (%s)", reason);
                    
                    char alert_msg[512];
                    snprintf(alert_msg, sizeof(alert_msg), "SENTINEL-X WAF ALERT: Exploit from %s. Reason: %s", pkt->src_ip, reason);
                    sentinel_send_sms("+916235242509", alert_msg);
                    return false;
                }
            }
        }

        // Direct raw WAF signature fallback
        if (sentinel_waf_inspect_raw(pkt, reason, sizeof(reason))) {
            sentinel_zt_penalize(zt, pkt->src_ip, 30, reason);
            snprintf(verdict, len, "BLOCKED by WAF Raw (%s)", reason);
            
            char alert_msg[512];
            snprintf(alert_msg, sizeof(alert_msg), "SENTINEL-X WAF ALERT (RAW): Exploit from %s. Reason: %s", pkt->src_ip, reason);
            sentinel_send_sms("+916235242509", alert_msg);
            return false;
        }
    }

    snprintf(verdict, len, "ALLOWED (%s)", reason);
    return true;
}

void print_separator(const char *title) {
    printf("\n================================================================================\n");
    printf("  %s\n", title);
    printf("================================================================================\n");
}

int main(int argc, char **argv) {
    bool live_mode = false;
    char *interface_name = "";

    if (argc > 1 && (strcmp(argv[1], "--live") == 0 || strcmp(argv[1], "-l") == 0)) {
        live_mode = true;
        if (argc > 2) {
            interface_name = argv[2];
        }
    }

    if (live_mode) {
        print_separator("PROJECT SENTINEL-X: LIVE REAL-TIME MODE");
    } else {
        print_separator("PROJECT SENTINEL-X: SIMULATION RUN");
    }

    // Initialize all modular security engines
    // Set Core rate limit: 5 packets/sec, 10 burst capacity
    FirewallEngine *fe = sentinel_engine_create(5, 10);
    IdsIpsEngine *ids_ips = sentinel_ids_ips_create();
    ZeroTrustEngine *zt = sentinel_zt_create();

    if (!fe || !ids_ips || !zt) {
        sentinel_log(LOG_LEVEL_CRITICAL, "Failed to initialize one or more engines. Exiting.");
        return 1;
    }

    // Configure static allowed ports/IP rules (Layer 1 Rule Database)
    sentinel_add_rule(fe, "*", "*", 0, 80, PROTO_TCP, ACTION_ALLOW);   // HTTP
    sentinel_add_rule(fe, "*", "*", 0, 443, PROTO_TCP, ACTION_ALLOW);  // HTTPS
    sentinel_add_rule(fe, "*", "*", 0, 53, PROTO_UDP, ACTION_ALLOW);   // DNS
    sentinel_add_rule(fe, "192.168.1.50", "*", 0, 22, PROTO_TCP, ACTION_ALLOW); // Admin SSH

    if (live_mode) {
        sentinel_live_capture_start(fe, ids_ips, zt, interface_name);

        print_separator("SHUTTING DOWN ALL SENTINEL-X ENGINES");
        sentinel_engine_free(fe);
        sentinel_ids_ips_free(ids_ips);
        sentinel_zt_free(zt);
        return 0;
    }

    char verdict[512];

    // --- CASE 1: Standard Connection Flow (3-Way Handshake & Request) ---
    print_separator("CASE 1: Legitimate HTTP Session");
    
    Packet *syn = sentinel_packet_create("192.168.1.100", "10.0.0.5", 51234, 80, PROTO_TCP, 0x02, NULL, 0);
    evaluate_pipeline(fe, ids_ips, zt, syn, verdict, sizeof(verdict));
    printf("SYN Packet Verdict: %s\n", verdict);
    sentinel_packet_free(syn);

    // Response packet (SYN-ACK)
    Packet *syn_ack = sentinel_packet_create("10.0.0.5", "192.168.1.100", 80, 51234, PROTO_TCP, 0x12, NULL, 0);
    evaluate_pipeline(fe, ids_ips, zt, syn_ack, verdict, sizeof(verdict));
    printf("SYN-ACK Verdict: %s\n", verdict);
    sentinel_packet_free(syn_ack);

    // Request payload (HTTP GET)
    const char *http_req = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
    Packet *http_data = sentinel_packet_create("192.168.1.100", "10.0.0.5", 51234, 80, PROTO_TCP, 0x10, 
                                                (const unsigned char *)http_req, strlen(http_req));
    evaluate_pipeline(fe, ids_ips, zt, http_data, verdict, sizeof(verdict));
    printf("HTTP Data Verdict: %s\n", verdict);
    sentinel_packet_free(http_data);

    // --- CASE 2: Web Application Exploit (SQL Injection) ---
    print_separator("CASE 2: Web Application Exploit (SQL Injection)");
    
    const char *sqli_req = "GET /login?user=admin' OR '1'='1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
    Packet *sqli_data = sentinel_packet_create("192.168.1.100", "10.0.0.5", 51234, 80, PROTO_TCP, 0x10,
                                               (const unsigned char *)sqli_req, strlen(sqli_req));
    evaluate_pipeline(fe, ids_ips, zt, sqli_data, verdict, sizeof(verdict));
    printf("SQL Injection Verdict: %s\n", verdict);
    sentinel_packet_free(sqli_data);

    // Check trust score after penalty
    print_separator("Checking Zero Trust Score Degradation");
    Packet *check_zt = sentinel_packet_create("192.168.1.100", "10.0.0.5", 51234, 80, PROTO_TCP, 0x10, NULL, 0);
    evaluate_pipeline(fe, ids_ips, zt, check_zt, verdict, sizeof(verdict));
    printf("Subsequent Request Verdict: %s\n", verdict);
    sentinel_packet_free(check_zt);

    // --- CASE 3: Reconnaissance (Port Scan Attack) ---
    print_separator("CASE 3: Intrusion Detection & Prevention (Port Scan)");
    const char *attacker_ip = "198.51.100.42";
    
    // Scan multiple ports sequentially to trigger the scan tracker
    for (uint16_t port = 1000; port < 1006; port++) {
        Packet *scan_pkt = sentinel_packet_create(attacker_ip, "10.0.0.5", 43210, port, PROTO_TCP, 0x02, NULL, 0);
        evaluate_pipeline(fe, ids_ips, zt, scan_pkt, verdict, sizeof(verdict));
        printf("Port scan target port %d Verdict: %s\n", port, verdict);
        sentinel_packet_free(scan_pkt);
    }

    // --- CASE 4: Rate Limiting & Denial of Service ---
    print_separator("CASE 4: Core Rate Limiting & Adaptive Block");
    const char *flooder_ip = "203.0.113.88";

    // Allow SYN to establish flow key, then flood
    Packet *flood_init = sentinel_packet_create(flooder_ip, "10.0.0.5", 60000, 80, PROTO_TCP, 0x02, NULL, 0);
    evaluate_pipeline(fe, ids_ips, zt, flood_init, verdict, sizeof(verdict));
    sentinel_packet_free(flood_init);

    for (int i = 0; i < 12; i++) {
        Packet *flood_pkt = sentinel_packet_create(flooder_ip, "10.0.0.5", 60000, 80, PROTO_TCP, 0x10, NULL, 0);
        evaluate_pipeline(fe, ids_ips, zt, flood_pkt, verdict, sizeof(verdict));
        printf("Flood packet #%02d Verdict: %s\n", i + 1, verdict);
        sentinel_packet_free(flood_pkt);
    }

    // --- Clean Up ---
    print_separator("SHUTTING DOWN ALL SENTINEL-X ENGINES");
    sentinel_engine_free(fe);
    sentinel_ids_ips_free(ids_ips);
    sentinel_zt_free(zt);

    return 0;
}
