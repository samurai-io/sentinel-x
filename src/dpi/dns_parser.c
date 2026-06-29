#include "sentinel_dpi.h"
#include "sentinel_common.h"
#include <stdio.h>
#include <string.h>

bool parse_dns(const unsigned char *payload, size_t len, DnsMeta *meta) {
    if (!payload || len < 12) return false;

    // A basic DNS header is 12 bytes
    // Parse Questions count (bytes 4-5)
    uint16_t questions = (payload[4] << 8) | payload[5];
    if (questions == 0) return false;

    memset(meta, 0, sizeof(DnsMeta));

    size_t offset = 12; // Start of Question Section
    char *qname = meta->query_name;
    size_t qname_offset = 0;

    // Parse the QNAME (Query Name) labels
    while (offset < len) {
        uint8_t label_len = payload[offset];
        
        // End of QNAME
        if (label_len == 0) {
            offset++;
            break;
        }

        // DNS name compression pointer (0xC0 flag), not expected in standard simple queries, but abort for safety
        if ((label_len & 0xC0) == 0xC0) {
            return false;
        }

        if (offset + 1 + label_len > len) {
            return false; // Bounds check
        }

        // Add dot if not first label
        if (qname_offset > 0) {
            if (qname_offset < sizeof(meta->query_name) - 1) {
                qname[qname_offset++] = '.';
            }
        }

        // Copy label characters
        for (uint8_t i = 0; i < label_len; i++) {
            if (qname_offset < sizeof(meta->query_name) - 1) {
                qname[qname_offset++] = payload[offset + 1 + i];
            }
        }

        offset += 1 + label_len;
    }
    qname[qname_offset] = '\0';

    if (offset + 4 <= len) {
        meta->query_type = (payload[offset] << 8) | payload[offset + 1];
    } else {
        return false;
    }

    sentinel_log(LOG_LEVEL_DEBUG, "DPI: Parsed DNS Query for domain: %s (Type: %d)", meta->query_name, meta->query_type);
    return true;
}
