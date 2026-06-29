#include "sentinel_core.h"
#include "sentinel_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void free_rate_limit_bucket(void *val) {
    free(val);
}

static void free_connection_state(void *val) {
    free(val);
}

FirewallEngine *sentinel_engine_create(uint32_t limit_rate, uint32_t limit_burst) {
    FirewallEngine *engine = malloc(sizeof(FirewallEngine));
    if (!engine) return NULL;

    engine->rules = NULL;
    pthread_mutex_init(&engine->rules_mutex, NULL);

    engine->state_table = hashmap_create(STATE_TABLE_SIZE);
    engine->rate_limit_table = hashmap_create(RATE_LIMIT_SIZE);
    engine->rate_limit_rate = limit_rate;
    engine->rate_limit_burst = limit_burst;

    if (!engine->state_table || !engine->rate_limit_table) {
        sentinel_engine_free(engine);
        return NULL;
    }

    sentinel_log(LOG_LEVEL_INFO, "Sentinel Core Engine initialized. Rate: %u/sec, Burst: %u", limit_rate, limit_burst);
    return engine;
}

void sentinel_engine_free(FirewallEngine *engine) {
    if (!engine) return;

    sentinel_clear_rules(engine);
    pthread_mutex_destroy(&engine->rules_mutex);

    if (engine->state_table) {
        hashmap_free(engine->state_table, free_connection_state);
    }
    if (engine->rate_limit_table) {
        hashmap_free(engine->rate_limit_table, free_rate_limit_bucket);
    }

    free(engine);
    sentinel_log(LOG_LEVEL_INFO, "Sentinel Core Engine shutdown successfully.");
}

bool sentinel_add_rule(FirewallEngine *engine, const char *src_ip, const char *dst_ip,
                       uint16_t src_port, uint16_t dst_port, ProtocolType protocol, RuleAction action) {
    if (!engine) return false;

    FirewallRule *rule = malloc(sizeof(FirewallRule));
    if (!rule) return false;

    strncpy(rule->src_ip, src_ip ? src_ip : "*", sizeof(rule->src_ip) - 1);
    rule->src_ip[sizeof(rule->src_ip) - 1] = '\0';

    strncpy(rule->dst_ip, dst_ip ? dst_ip : "*", sizeof(rule->dst_ip) - 1);
    rule->dst_ip[sizeof(rule->dst_ip) - 1] = '\0';

    rule->src_port = src_port;
    rule->dst_port = dst_port;
    rule->protocol = protocol;
    rule->action = action;
    rule->next = NULL;

    pthread_mutex_lock(&engine->rules_mutex);
    if (!engine->rules) {
        engine->rules = rule;
    } else {
        FirewallRule *curr = engine->rules;
        while (curr->next) {
            curr = curr->next;
        }
        curr->next = rule;
    }
    pthread_mutex_unlock(&engine->rules_mutex);

    sentinel_log(LOG_LEVEL_INFO, "Added rule: Src %s:%d -> Dst %s:%d [%s] -> Action: %d",
                 rule->src_ip, rule->src_port, rule->dst_ip, rule->dst_port,
                 protocol == PROTO_TCP ? "TCP" : (protocol == PROTO_UDP ? "UDP" : "ICMP"),
                 action);
    return true;
}

void sentinel_clear_rules(FirewallEngine *engine) {
    if (!engine) return;

    pthread_mutex_lock(&engine->rules_mutex);
    FirewallRule *curr = engine->rules;
    while (curr) {
        FirewallRule *next = curr->next;
        free(curr);
        curr = next;
    }
    engine->rules = NULL;
    pthread_mutex_unlock(&engine->rules_mutex);
}

// Token bucket rate limiting algorithm per source IP
static bool check_rate_limit(FirewallEngine *engine, const char *src_ip) {
    uint64_t now = sentinel_current_time_ms();
    RateLimitBucket *bucket = (RateLimitBucket *)hashmap_get(engine->rate_limit_table, src_ip);

    if (!bucket) {
        bucket = malloc(sizeof(RateLimitBucket));
        if (!bucket) return false; // Fail safe block if OOM

        bucket->tokens = engine->rate_limit_burst;
        bucket->last_update_ms = now;

        if (!hashmap_put(engine->rate_limit_table, src_ip, bucket)) {
            free(bucket);
            return false;
        }
    } else {
        uint64_t elapsed_ms = now - bucket->last_update_ms;
        if (elapsed_ms > 0) {
            uint32_t tokens_to_add = (uint32_t)((elapsed_ms * engine->rate_limit_rate) / 1000);
            if (tokens_to_add > 0) {
                bucket->tokens += tokens_to_add;
                if (bucket->tokens > engine->rate_limit_burst) {
                    bucket->tokens = engine->rate_limit_burst;
                }
                bucket->last_update_ms = now;
            }
        }
    }

    if (bucket->tokens > 0) {
        bucket->tokens--;
        return true;
    }

    return false; // Rate limit exceeded!
}

// Helper: match single rule field
static bool ip_matches(const char *rule_ip, const char *pkt_ip) {
    return (strcmp(rule_ip, "*") == 0 || strcmp(rule_ip, "") == 0 || strcmp(rule_ip, pkt_ip) == 0);
}

static bool port_matches(uint16_t rule_port, uint16_t pkt_port) {
    return (rule_port == 0 || rule_port == pkt_port);
}

// Main packet processing engine
bool sentinel_process_packet(FirewallEngine *engine, Packet *packet, char *reason_buf, size_t reason_len) {
    if (!engine || !packet) {
        if (reason_buf) snprintf(reason_buf, reason_len, "Invalid arguments");
        return false;
    }

    // 1. Check rate limiting
    if (!check_rate_limit(engine, packet->src_ip)) {
        if (reason_buf) snprintf(reason_buf, reason_len, "Rate limit exceeded");
        sentinel_log(LOG_LEVEL_WARNING, "Packet dropped: Rate limit exceeded for source IP %s", packet->src_ip);
        return false;
    }

    // 2. Check stateful connection table
    bool state_exists = false;
    if (check_and_update_state(engine, packet, &state_exists)) {
        if (reason_buf) snprintf(reason_buf, reason_len, "Stateful connection established");
        return true;
    }

    // If packet matches an existing state but state logic returned false (e.g. timeout / invalid transition)
    if (state_exists) {
        if (reason_buf) snprintf(reason_buf, reason_len, "Invalid state transition or expired connection");
        return false;
    }

    // 3. Static Rules matching for initial packet (e.g. TCP SYN or first UDP packet)
    pthread_mutex_lock(&engine->rules_mutex);
    FirewallRule *rule = engine->rules;
    bool match_found = false;
    RuleAction action = ACTION_BLOCK;

    while (rule) {
        if (rule->protocol == packet->protocol &&
            ip_matches(rule->src_ip, packet->src_ip) &&
            ip_matches(rule->dst_ip, packet->dst_ip) &&
            port_matches(rule->src_port, packet->src_port) &&
            port_matches(rule->dst_port, packet->dst_port)) {
            
            match_found = true;
            action = rule->action;
            break;
        }
        rule = rule->next;
    }
    pthread_mutex_unlock(&engine->rules_mutex);

    if (match_found) {
        if (action == ACTION_ALLOW) {
            if (reason_buf) snprintf(reason_buf, reason_len, "Matched static ALLOW rule");
            // Register this flow in stateful tracking table
            create_state_entry(engine, packet);
            return true;
        } else {
            if (reason_buf) snprintf(reason_buf, reason_len, "Matched static BLOCK rule");
            return false;
        }
    }

    // Default Drop (Secure by default)
    if (reason_buf) snprintf(reason_buf, reason_len, "No rules matched (Default Block)");
    return false;
}

// Packet creation helpers
Packet *sentinel_packet_create(const char *src, const char *dst, uint16_t sport, uint16_t dport,
                               ProtocolType proto, uint8_t flags, const unsigned char *payload, size_t len) {
    Packet *p = malloc(sizeof(Packet));
    if (!p) return NULL;

    strncpy(p->src_ip, src, sizeof(p->src_ip) - 1);
    p->src_ip[sizeof(p->src_ip) - 1] = '\0';

    strncpy(p->dst_ip, dst, sizeof(p->dst_ip) - 1);
    p->dst_ip[sizeof(p->dst_ip) - 1] = '\0';

    p->src_port = sport;
    p->dst_port = dport;
    p->protocol = proto;
    p->tcp_flags = flags;
    p->payload_len = len;

    if (len > 0 && payload) {
        p->payload = malloc(len);
        if (!p->payload) {
            free(p);
            return NULL;
        }
        memcpy(p->payload, payload, len);
    } else {
        p->payload = NULL;
    }

    return p;
}

void sentinel_packet_free(Packet *packet) {
    if (!packet) return;
    if (packet->payload) free(packet->payload);
    free(packet);
}
