#include "sentinel_core.h"
#include "sentinel_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Canonical flow key generator (bidirectional)
static void get_canonical_key(const Packet *pkt, char *key_buf, size_t buf_len) {
    int cmp = strcmp(pkt->src_ip, pkt->dst_ip);
    if (cmp < 0 || (cmp == 0 && pkt->src_port < pkt->dst_port)) {
        snprintf(key_buf, buf_len, "%s:%u-%s:%u-%d", pkt->src_ip, pkt->src_port, pkt->dst_ip, pkt->dst_port, pkt->protocol);
    } else {
        snprintf(key_buf, buf_len, "%s:%u-%s:%u-%d", pkt->dst_ip, pkt->dst_port, pkt->src_ip, pkt->src_port, pkt->protocol);
    }
}

static void free_connection_state(void *val) {
    free(val);
}

// Stateful evaluation
// Returns: true if packet is allowed by an existing state; false if state does not exist or invalid transition
bool check_and_update_state(FirewallEngine *engine, const Packet *pkt, bool *state_exists) {
    char key[128];
    get_canonical_key(pkt, key, sizeof(key));

    *state_exists = false;
    ConnectionState *state = (ConnectionState *)hashmap_get(engine->state_table, key);
    uint64_t now = sentinel_current_time_ms();

    if (state) {
        *state_exists = true;
        // Update timeout
        state->last_seen_ms = now;

        if (pkt->protocol == PROTO_TCP) {
            // TCP State transition logic
            if (pkt->tcp_flags & 0x01) { // FIN flag
                state->tcp_state = TCP_STATE_FIN_WAIT;
                sentinel_log(LOG_LEVEL_DEBUG, "TCP Flow %s transitioned to FIN_WAIT", key);
            } else if (pkt->tcp_flags & 0x04) { // RST flag
                state->tcp_state = TCP_STATE_CLOSED;
                sentinel_log(LOG_LEVEL_DEBUG, "TCP Flow %s transitioned to CLOSED (RST)", key);
            } else if (state->tcp_state == TCP_STATE_SYN_SENT) {
                // If we see SYN-ACK or ACK, transition to established
                if ((pkt->tcp_flags & 0x10) || (pkt->tcp_flags & 0x12)) {
                    state->tcp_state = TCP_STATE_ESTABLISHED;
                    sentinel_log(LOG_LEVEL_DEBUG, "TCP Flow %s transitioned to ESTABLISHED", key);
                }
            }
        } else if (pkt->protocol == PROTO_UDP) {
            // UDP flows are simple; check for timeout
            if (now - state->last_seen_ms > 30000) { // 30 seconds idle timeout
                sentinel_log(LOG_LEVEL_DEBUG, "UDP Flow %s timed out, purging", key);
                hashmap_remove(engine->state_table, key, free_connection_state);
                *state_exists = false;
                return false;
            }
        } else if (pkt->protocol == PROTO_ICMP) {
            // ICMP flows are short-lived
            if (now - state->last_seen_ms > 5000) { // 5 seconds timeout
                hashmap_remove(engine->state_table, key, free_connection_state);
                *state_exists = false;
                return false;
            }
        }
        return true;
    }

    return false;
}

// Add state to state table if allowed by rules
bool create_state_entry(FirewallEngine *engine, const Packet *pkt) {
    char key[128];
    get_canonical_key(pkt, key, sizeof(key));

    ConnectionState *state = malloc(sizeof(ConnectionState));
    if (!state) return false;

    strncpy(state->key, key, sizeof(state->key) - 1);
    state->key[sizeof(state->key) - 1] = '\0';
    state->protocol = pkt->protocol;
    state->last_seen_ms = sentinel_current_time_ms();

    if (pkt->protocol == PROTO_TCP) {
        if (pkt->tcp_flags & 0x02) { // SYN
            state->tcp_state = TCP_STATE_SYN_SENT;
        } else {
            state->tcp_state = TCP_STATE_ESTABLISHED;
        }
    } else {
        // UDP & ICMP have no real states, they are tracking flows
        state->tcp_state = TCP_STATE_CLOSED;
    }

    bool ok = hashmap_put(engine->state_table, key, state);
    if (ok) {
        sentinel_log(LOG_LEVEL_DEBUG, "New state tracking created for: %s", key);
    } else {
        free(state);
    }
    return ok;
}
