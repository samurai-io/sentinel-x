#ifndef SENTINEL_DPI_H
#define SENTINEL_DPI_H

#include "sentinel_core.h"

typedef enum {
    DPI_PROTO_UNKNOWN,
    DPI_PROTO_HTTP,
    DPI_PROTO_DNS,
    DPI_PROTO_TLS
} DpiProtocol;

typedef struct {
    char method[16];
    char uri[256];
    char host[128];
    char user_agent[256];
} HttpMeta;

typedef struct {
    char query_name[256];
    uint16_t query_type;
} DnsMeta;

typedef struct {
    char sni[256];
    uint16_t tls_version;
    char ja3_hash[33]; // MD5 hash string
} TlsMeta;

typedef struct {
    DpiProtocol protocol;
    union {
        HttpMeta http;
        DnsMeta dns;
        TlsMeta tls;
    } meta;
} DpiResult;

// DPI Inspection main routine
bool sentinel_dpi_inspect(const Packet *packet, DpiResult *result);

// Individual protocol parsers
bool parse_http(const unsigned char *payload, size_t len, HttpMeta *meta);
bool parse_dns(const unsigned char *payload, size_t len, DnsMeta *meta);
bool parse_tls(const unsigned char *payload, size_t len, TlsMeta *meta);

#endif // SENTINEL_DPI_H
