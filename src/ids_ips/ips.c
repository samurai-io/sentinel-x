#include "sentinel_ids_ips.h"
#include "sentinel_common.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint64_t quarantine_until_ms;
} QuarantineEntry;

static void free_quarantine_entry(void *val) {
    free(val);
}

static void free_scan_tracker(void *val) {
    free(val);
}

IdsIpsEngine *sentinel_ids_ips_create(void) {
    IdsIpsEngine *engine = malloc(sizeof(IdsIpsEngine));
    if (!engine) return NULL;

    engine->quarantine_table = hashmap_create(1024);
    engine->scan_tracker_table = hashmap_create(1024);
    pthread_mutex_init(&engine->ids_mutex, NULL);

    if (!engine->quarantine_table || !engine->scan_tracker_table) {
        sentinel_ids_ips_free(engine);
        return NULL;
    }

    sentinel_log(LOG_LEVEL_INFO, "IDS/IPS Engine initialized successfully.");
    return engine;
}

void sentinel_ids_ips_free(IdsIpsEngine *engine) {
    if (!engine) return;

    pthread_mutex_destroy(&engine->ids_mutex);

    if (engine->quarantine_table) {
        hashmap_free(engine->quarantine_table, free_quarantine_entry);
    }
    if (engine->scan_tracker_table) {
        hashmap_free(engine->scan_tracker_table, free_scan_tracker);
    }

    free(engine);
    sentinel_log(LOG_LEVEL_INFO, "IDS/IPS Engine shutdown.");
}

bool sentinel_quarantine_host(IdsIpsEngine *engine, const char *ip_address, uint64_t duration_ms) {
    if (!engine || !ip_address) return false;

    QuarantineEntry *entry = malloc(sizeof(QuarantineEntry));
    if (!entry) return false;

    entry->quarantine_until_ms = sentinel_current_time_ms() + duration_ms;

    pthread_mutex_lock(&engine->ids_mutex);
    bool ok = hashmap_put(engine->quarantine_table, ip_address, entry);
    pthread_mutex_unlock(&engine->ids_mutex);

    if (ok) {
        sentinel_log(LOG_LEVEL_WARNING, "IPS ACTIVE RESPONSE: Quarantined host %s for %lu ms", ip_address, duration_ms);
    } else {
        free(entry);
    }

    return ok;
}

bool sentinel_is_quarantined(IdsIpsEngine *engine, const char *ip_address) {
    if (!engine || !ip_address) return false;

    pthread_mutex_lock(&engine->ids_mutex);
    QuarantineEntry *entry = (QuarantineEntry *)hashmap_get(engine->quarantine_table, ip_address);
    uint64_t now = sentinel_current_time_ms();

    if (entry) {
        if (now < entry->quarantine_until_ms) {
            pthread_mutex_unlock(&engine->ids_mutex);
            return true;
        } else {
            // Quarantine expired, remove it
            hashmap_remove(engine->quarantine_table, ip_address, free_quarantine_entry);
        }
    }

    pthread_mutex_unlock(&engine->ids_mutex);
    return false;
}
