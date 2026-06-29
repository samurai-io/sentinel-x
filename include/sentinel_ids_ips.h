#ifndef SENTINEL_IDS_IPS_H
#define SENTINEL_IDS_IPS_H

#include "sentinel_core.h"
#include "sentinel_common.h"

#define SCAN_PORT_LIMIT 5
#define SCAN_WINDOW_MS 5000
#define QUARANTINE_DURATION_MS 60000 // 1 minute quarantine

typedef struct {
    char src_ip[MAX_IP_LEN];
    uint16_t ports_seen[SCAN_PORT_LIMIT];
    int unique_port_count;
    uint64_t window_start_ms;
    bool active_alert;
} ScanTracker;

typedef struct {
    HashMap *quarantine_table;
    HashMap *scan_tracker_table;
    pthread_mutex_t ids_mutex;
} IdsIpsEngine;

IdsIpsEngine *sentinel_ids_ips_create(void);
void sentinel_ids_ips_free(IdsIpsEngine *engine);

// Process a packet through IDS/IPS.
// Returns: true if packet is clean; false if packet is malicious or source is quarantined (should drop).
bool sentinel_ids_ips_process(IdsIpsEngine *engine, const Packet *packet, char *alert_msg, size_t msg_len);

// Explicitly quarantine a host
bool sentinel_quarantine_host(IdsIpsEngine *engine, const char *ip_address, uint64_t duration_ms);

// Check if a host is currently quarantined
bool sentinel_is_quarantined(IdsIpsEngine *engine, const char *ip_address);

#endif // SENTINEL_IDS_IPS_H
