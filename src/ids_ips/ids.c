#include "sentinel_ids_ips.h"
#include "sentinel_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool sentinel_ids_ips_process(IdsIpsEngine *engine, const Packet *packet, char *alert_msg, size_t msg_len) {
    if (!engine || !packet) return false;

    // 1. Check if host is quarantined (Active Prevention)
    if (sentinel_is_quarantined(engine, packet->src_ip)) {
        if (alert_msg) {
            snprintf(alert_msg, msg_len, "Host %s blocked by IPS (quarantined active)", packet->src_ip);
        }
        return false;
    }

    // 2. Perform Port Scan Detection (Reconnaissance Detection)
    // We only care about connections or initial packet probes (e.g. TCP SYN or UDP port probes)
    bool is_probe = false;
    if (packet->protocol == PROTO_TCP && (packet->tcp_flags & 0x02)) { // SYN
        is_probe = true;
    } else if (packet->protocol == PROTO_UDP) {
        is_probe = true;
    }

    if (is_probe) {
        uint64_t now = sentinel_current_time_ms();
        pthread_mutex_lock(&engine->ids_mutex);
        
        ScanTracker *tracker = (ScanTracker *)hashmap_get(engine->scan_tracker_table, packet->src_ip);
        if (!tracker) {
            tracker = malloc(sizeof(ScanTracker));
            if (tracker) {
                strncpy(tracker->src_ip, packet->src_ip, sizeof(tracker->src_ip) - 1);
                tracker->src_ip[sizeof(tracker->src_ip) - 1] = '\0';
                tracker->unique_port_count = 0;
                tracker->window_start_ms = now;
                tracker->active_alert = false;
                
                hashmap_put(engine->scan_tracker_table, packet->src_ip, tracker);
            }
        }

        if (tracker) {
            // Check if scan window has expired
            if (now - tracker->window_start_ms > SCAN_WINDOW_MS) {
                tracker->unique_port_count = 0;
                tracker->window_start_ms = now;
                tracker->active_alert = false;
            }

            // Check if the destination port was already seen
            bool port_already_seen = false;
            for (int i = 0; i < tracker->unique_port_count; i++) {
                if (tracker->ports_seen[i] == packet->dst_port) {
                    port_already_seen = true;
                    break;
                }
            }

            if (!port_already_seen) {
                if (tracker->unique_port_count < SCAN_PORT_LIMIT) {
                    tracker->ports_seen[tracker->unique_port_count] = packet->dst_port;
                    tracker->unique_port_count++;
                }

                // If port threshold reached, raise alarm and quarantine
                if (tracker->unique_port_count >= SCAN_PORT_LIMIT && !tracker->active_alert) {
                    tracker->active_alert = true;
                    pthread_mutex_unlock(&engine->ids_mutex);

                    if (alert_msg) {
                        snprintf(alert_msg, msg_len, "Port scan detected from %s (%d ports scanned)",
                                 packet->src_ip, tracker->unique_port_count);
                    }
                    sentinel_log(LOG_LEVEL_WARNING, "IDS ALERT: Port scan detected from %s. Active ports: %d",
                                 packet->src_ip, tracker->unique_port_count);

                    // Quarantine the attacker (IPS active action)
                    sentinel_quarantine_host(engine, packet->src_ip, QUARANTINE_DURATION_MS);
                    return false;
                }
            }
        }
        
        pthread_mutex_unlock(&engine->ids_mutex);
    }

    return true;
}
