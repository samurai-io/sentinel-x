#ifndef SENTINEL_CORE_H
#define SENTINEL_CORE_H

#include "sentinel_common.h"
#include <arpa/inet.h>

#define MAX_IP_LEN 46 // Supports IPv6 formatted string
#define STATE_TABLE_SIZE 1024
#define RATE_LIMIT_SIZE 512

typedef enum {
    ACTION_ALLOW,
    ACTION_BLOCK,
    ACTION_LOG
} RuleAction;

typedef enum {
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP
} ProtocolType;

// Rule structure
typedef struct FirewallRule {
    char src_ip[MAX_IP_LEN];
    char dst_ip[MAX_IP_LEN];
    uint16_t src_port;
    uint16_t dst_port;
    ProtocolType protocol;
    RuleAction action;
    struct FirewallRule *next;
} FirewallRule;

// Packet simulation structure
typedef struct {
    char src_ip[MAX_IP_LEN];
    char dst_ip[MAX_IP_LEN];
    uint16_t src_port;
    uint16_t dst_port;
    ProtocolType protocol;
    uint8_t tcp_flags; // e.g. 0x02 for SYN, 0x12 for SYN-ACK, 0x10 for ACK, 0x01 for FIN
    unsigned char *payload;
    size_t payload_len;
} Packet;

// Stateful Connection Tracker Entry
typedef enum {
    TCP_STATE_SYN_SENT,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT,
    TCP_STATE_CLOSED
} TcpState;

typedef struct {
    char key[128]; // Unique flow key "src_ip:src_port->dst_ip:dst_port"
    ProtocolType protocol;
    TcpState tcp_state;
    uint64_t last_seen_ms;
} ConnectionState;

// Rate limit entry
typedef struct {
    uint32_t tokens;
    uint64_t last_update_ms;
} RateLimitBucket;

// Core Engine Context
typedef struct {
    FirewallRule *rules;
    pthread_mutex_t rules_mutex;
    HashMap *state_table;
    HashMap *rate_limit_table;
    uint32_t rate_limit_burst;   // Max tokens
    uint32_t rate_limit_rate;    // Tokens per second
} FirewallEngine;

// Rule APIs
FirewallEngine *sentinel_engine_create(uint32_t limit_rate, uint32_t limit_burst);
void sentinel_engine_free(FirewallEngine *engine);
bool sentinel_add_rule(FirewallEngine *engine, const char *src_ip, const char *dst_ip,
                       uint16_t src_port, uint16_t dst_port, ProtocolType protocol, RuleAction action);
void sentinel_clear_rules(FirewallEngine *engine);

// Engine Core Logic
bool sentinel_process_packet(FirewallEngine *engine, Packet *packet, char *reason_buf, size_t reason_len);

// Stateful Helper APIs (implemented in state_table.c)
bool check_and_update_state(FirewallEngine *engine, const Packet *packet, bool *state_exists);
bool create_state_entry(FirewallEngine *engine, const Packet *packet);

// Helper functions for Packet
Packet *sentinel_packet_create(const char *src, const char *dst, uint16_t sport, uint16_t dport,
                               ProtocolType proto, uint8_t flags, const unsigned char *payload, size_t len);
void sentinel_packet_free(Packet *packet);

// Live Capture controller (implemented in live_capture.c)
void sentinel_live_capture_start(FirewallEngine *fe, void *ids_ips, void *zt, const char *interface_name);

#endif // SENTINEL_CORE_H
