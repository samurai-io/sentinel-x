#ifndef SENTINEL_ZERO_TRUST_H
#define SENTINEL_ZERO_TRUST_H

#include "sentinel_core.h"
#include "sentinel_common.h"

#define ZT_MIN_TRUST_SCORE 50

typedef struct {
    char ip_address[MAX_IP_LEN];
    char user_name[64];
    int trust_score;            // Range: 0 to 100
    bool mfa_verified;
    uint64_t last_eval_ms;
} DeviceTrust;

typedef struct {
    HashMap *trust_table;
    pthread_mutex_t zt_mutex;
} ZeroTrustEngine;

ZeroTrustEngine *sentinel_zt_create(void);
void sentinel_zt_free(ZeroTrustEngine *engine);

// Evaluates a packet's client state in the Zero Trust engine.
// Returns: true if client matches trust requirements (trust_score >= ZT_MIN_TRUST_SCORE); false if client is untrusted.
bool sentinel_zt_evaluate(ZeroTrustEngine *engine, const Packet *packet, char *reason_buf, size_t reason_len);

// Deduct points from client's trust score due to anomalous or suspicious behavior
void sentinel_zt_penalize(ZeroTrustEngine *engine, const char *ip_address, int points, const char *reason);

// Elevate score or authorize users (e.g. identity providers SAML/OAuth/MFA verification hooks)
void sentinel_zt_authenticate(ZeroTrustEngine *engine, const char *ip_address, const char *user_name, bool mfa_ok);

#endif // SENTINEL_ZERO_TRUST_H
