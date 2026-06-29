#include "sentinel_zero_trust.h"
#include "sentinel_common.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void free_device_trust(void *val) {
    free(val);
}

ZeroTrustEngine *sentinel_zt_create(void) {
    ZeroTrustEngine *engine = malloc(sizeof(ZeroTrustEngine));
    if (!engine) return NULL;

    engine->trust_table = hashmap_create(1024);
    pthread_mutex_init(&engine->zt_mutex, NULL);

    if (!engine->trust_table) {
        sentinel_zt_free(engine);
        return NULL;
    }

    sentinel_log(LOG_LEVEL_INFO, "Zero Trust Engine initialized successfully.");
    return engine;
}

void sentinel_zt_free(ZeroTrustEngine *engine) {
    if (!engine) return;

    pthread_mutex_destroy(&engine->zt_mutex);
    if (engine->trust_table) {
        hashmap_free(engine->trust_table, free_device_trust);
    }
    free(engine);
    sentinel_log(LOG_LEVEL_INFO, "Zero Trust Engine shutdown.");
}

bool sentinel_zt_evaluate(ZeroTrustEngine *engine, const Packet *packet, char *reason_buf, size_t reason_len) {
    if (!engine || !packet) return false;

    pthread_mutex_lock(&engine->zt_mutex);
    DeviceTrust *device = (DeviceTrust *)hashmap_get(engine->trust_table, packet->src_ip);
    uint64_t now = sentinel_current_time_ms();

    if (!device) {
        device = malloc(sizeof(DeviceTrust));
        if (device) {
            strncpy(device->ip_address, packet->src_ip, sizeof(device->ip_address) - 1);
            device->ip_address[sizeof(device->ip_address) - 1] = '\0';
            strcpy(device->user_name, "anonymous");
            device->trust_score = 80; // Base score for anonymous devices
            device->mfa_verified = false;
            device->last_eval_ms = now;
            
            hashmap_put(engine->trust_table, packet->src_ip, device);
        }
    }

    if (device) {
        device->last_eval_ms = now;

        if (device->trust_score < ZT_MIN_TRUST_SCORE) {
            if (reason_buf) {
                snprintf(reason_buf, reason_len, "Trust score too low: %d (Minimum required: %d)",
                         device->trust_score, ZT_MIN_TRUST_SCORE);
            }
            pthread_mutex_unlock(&engine->zt_mutex);
            sentinel_log(LOG_LEVEL_WARNING, "Zero Trust block: Device %s score is %d", packet->src_ip, device->trust_score);
            return false;
        }

        pthread_mutex_unlock(&engine->zt_mutex);
        return true;
    }

    pthread_mutex_unlock(&engine->zt_mutex);
    return true; // Fallback allow
}

void sentinel_zt_penalize(ZeroTrustEngine *engine, const char *ip_address, int points, const char *reason) {
    if (!engine || !ip_address) return;

    pthread_mutex_lock(&engine->zt_mutex);
    DeviceTrust *device = (DeviceTrust *)hashmap_get(engine->trust_table, ip_address);
    if (device) {
        device->trust_score -= points;
        if (device->trust_score < 0) device->trust_score = 0;
        sentinel_log(LOG_LEVEL_WARNING, "Zero Trust Penalty: Host %s penalized -%d points. Reason: %s. New Score: %d",
                     ip_address, points, reason, device->trust_score);
    }
    pthread_mutex_unlock(&engine->zt_mutex);
}

void sentinel_zt_authenticate(ZeroTrustEngine *engine, const char *ip_address, const char *user_name, bool mfa_ok) {
    if (!engine || !ip_address) return;

    pthread_mutex_lock(&engine->zt_mutex);
    DeviceTrust *device = (DeviceTrust *)hashmap_get(engine->trust_table, ip_address);
    uint64_t now = sentinel_current_time_ms();

    if (!device) {
        device = malloc(sizeof(DeviceTrust));
        if (device) {
            strncpy(device->ip_address, ip_address, sizeof(device->ip_address) - 1);
            device->ip_address[sizeof(device->ip_address) - 1] = '\0';
            hashmap_put(engine->trust_table, ip_address, device);
        }
    }

    if (device) {
        strncpy(device->user_name, user_name ? user_name : "anonymous", sizeof(device->user_name) - 1);
        device->user_name[sizeof(device->user_name) - 1] = '\0';
        device->mfa_verified = mfa_ok;
        device->trust_score = mfa_ok ? 100 : 90;
        device->last_eval_ms = now;

        sentinel_log(LOG_LEVEL_INFO, "Zero Trust Identity Authenticated: Host %s -> User %s, MFA: %s. Trust Score set to %d",
                     ip_address, device->user_name, mfa_ok ? "OK" : "NO", device->trust_score);
    }
    pthread_mutex_unlock(&engine->zt_mutex);
}
