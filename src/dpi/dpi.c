#include "sentinel_dpi.h"
#include "sentinel_common.h"
#include <string.h>

bool sentinel_dpi_inspect(const Packet *packet, DpiResult *result) {
    if (!packet || !packet->payload || packet->payload_len == 0 || !result) {
        return false;
    }

    memset(result, 0, sizeof(DpiResult));
    result->protocol = DPI_PROTO_UNKNOWN;

    // UDP protocol checks
    if (packet->protocol == PROTO_UDP) {
        if (packet->src_port == 53 || packet->dst_port == 53) {
            if (parse_dns(packet->payload, packet->payload_len, &result->meta.dns)) {
                result->protocol = DPI_PROTO_DNS;
                return true;
            }
        }
    }

    // TCP protocol checks
    if (packet->protocol == PROTO_TCP) {
        // Try HTTPS/TLS first if port 443
        if (packet->dst_port == 443 || packet->src_port == 443) {
            if (parse_tls(packet->payload, packet->payload_len, &result->meta.tls)) {
                result->protocol = DPI_PROTO_TLS;
                return true;
            }
        }

        // Try HTTP if port 80 or 8080
        if (packet->dst_port == 80 || packet->src_port == 80 || packet->dst_port == 8080) {
            if (parse_http(packet->payload, packet->payload_len, &result->meta.http)) {
                result->protocol = DPI_PROTO_HTTP;
                return true;
            }
        }

        // General fallback if port doesn't match standard defaults: probe both
        if (parse_tls(packet->payload, packet->payload_len, &result->meta.tls)) {
            result->protocol = DPI_PROTO_TLS;
            return true;
        }
        if (parse_http(packet->payload, packet->payload_len, &result->meta.http)) {
            result->protocol = DPI_PROTO_HTTP;
            return true;
        }
    }

    return false;
}
