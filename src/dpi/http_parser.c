#include "sentinel_dpi.h"
#include "sentinel_common.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

static void safe_strncpy(char *dest, const char *src, size_t dest_size) {
    if (!dest || dest_size == 0) return;
    if (!src) {
        dest[0] = '\0';
        return;
    }
    size_t i;
    for (i = 0; i < dest_size - 1 && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    dest[i] = '\0';
}

bool parse_http(const unsigned char *payload, size_t len, HttpMeta *meta) {
    if (!payload || len < 10) return false;

    // Check if the payload starts with typical HTTP verbs
    const char *verbs[] = {"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH "};
    size_t num_verbs = sizeof(verbs) / sizeof(verbs[0]);
    bool is_http = false;
    for (size_t i = 0; i < num_verbs; i++) {
        size_t verb_len = strlen(verbs[i]);
        if (len >= verb_len && memcmp(payload, verbs[i], verb_len) == 0) {
            is_http = true;
            break;
        }
    }

    if (!is_http) return false;

    memset(meta, 0, sizeof(HttpMeta));

    // Make a null-terminated safe copy of the payload (up to 4096 bytes)
    size_t copy_len = len > 4095 ? 4095 : len;
    char buf[4096];
    memcpy(buf, payload, copy_len);
    buf[copy_len] = '\0';

    // Parse the request line
    char *line = strtok(buf, "\r\n");
    if (!line) return false;

    // Extract method and URI
    char method_buf[16] = {0};
    char uri_buf[256] = {0};
    if (sscanf(line, "%15s %255s", method_buf, uri_buf) == 2) {
        safe_strncpy(meta->method, method_buf, sizeof(meta->method));
        safe_strncpy(meta->uri, uri_buf, sizeof(meta->uri));
    } else {
        return false;
    }

    // Parse headers line by line
    while ((line = strtok(NULL, "\r\n")) != NULL) {
        if (strlen(line) == 0) {
            break; // Header section ended
        }

        // Host header
        if (strncasecmp(line, "Host:", 5) == 0) {
            char *val = line + 5;
            while (*val == ' ' || *val == '\t') val++;
            safe_strncpy(meta->host, val, sizeof(meta->host));
        }
        // User-Agent header
        else if (strncasecmp(line, "User-Agent:", 11) == 0) {
            char *val = line + 11;
            while (*val == ' ' || *val == '\t') val++;
            safe_strncpy(meta->user_agent, val, sizeof(meta->user_agent));
        }
    }

    sentinel_log(LOG_LEVEL_DEBUG, "DPI: Parsed HTTP Request %s %s [Host: %s]", meta->method, meta->uri, meta->host);
    return true;
}
