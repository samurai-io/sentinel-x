#include "sentinel_dpi.h"
#include "sentinel_common.h"
#include <stdio.h>
#include <string.h>

bool parse_tls(const unsigned char *payload, size_t len, TlsMeta *meta) {
    if (!payload || len < 47) return false;

    // Check TLS Record Layer: Content Type = Handshake (0x16)
    if (payload[0] != 0x16) return false;

    // Check Handshake Type = ClientHello (0x01)
    if (payload[5] != 0x01) return false;

    memset(meta, 0, sizeof(TlsMeta));
    meta->tls_version = (payload[9] << 8) | payload[10];

    size_t offset = 43; // Points to Session ID Length

    // Session ID
    if (offset >= len) return false;
    uint8_t session_id_len = payload[offset];
    offset += 1 + session_id_len;

    // Cipher Suites
    if (offset + 2 > len) return false;
    uint16_t cipher_suites_len = (payload[offset] << 8) | payload[offset + 1];
    offset += 2 + cipher_suites_len;

    // Compression Methods
    if (offset >= len) return false;
    uint8_t compression_len = payload[offset];
    offset += 1 + compression_len;

    // Extensions Length
    if (offset + 2 > len) return false;
    uint16_t extensions_len = (payload[offset] << 8) | payload[offset + 1];
    offset += 2;

    size_t extensions_end = offset + extensions_len;
    if (extensions_end > len) {
        extensions_end = len; // Clamp to avoid reading beyond buffer
    }

    // Loop through Extensions
    while (offset + 4 <= extensions_end) {
        uint16_t ext_type = (payload[offset] << 8) | payload[offset + 1];
        uint16_t ext_len = (payload[offset + 2] << 8) | payload[offset + 3];
        offset += 4;

        if (offset + ext_len > extensions_end) return false;

        // Server Name Indication (SNI) Extension is 0x0000
        if (ext_type == 0x0000) {
            size_t ext_offset = offset;
            if (ext_offset + 2 > offset + ext_len) return false;
            ext_offset += 2; // Skip Server Name List Length

            if (ext_offset + 3 > offset + ext_len) return false;
            uint8_t name_type = payload[ext_offset];
            uint16_t name_len = (payload[ext_offset + 1] << 8) | payload[ext_offset + 2];
            ext_offset += 3;

            if (name_type == 0x00 && ext_offset + name_len <= offset + ext_len) {
                // Found SNI hostname!
                size_t cpy_len = name_len > (sizeof(meta->sni) - 1) ? (sizeof(meta->sni) - 1) : name_len;
                memcpy(meta->sni, &payload[ext_offset], cpy_len);
                meta->sni[cpy_len] = '\0';
                
                // Let's generate a mock JA3 hash for this demo
                // (In a real system, we'd hash: Version, CipherSuites, Extensions, EC Groups, EC Formats)
                strncpy(meta->ja3_hash, "f7a3f8c0571de444a7f34c264ef5f6b9", sizeof(meta->ja3_hash) - 1);
                meta->ja3_hash[sizeof(meta->ja3_hash) - 1] = '\0';

                sentinel_log(LOG_LEVEL_DEBUG, "DPI: Parsed TLS ClientHello. SNI: %s, Version: 0x%04X", meta->sni, meta->tls_version);
                return true;
            }
        }
        offset += ext_len;
    }

    return false;
}
