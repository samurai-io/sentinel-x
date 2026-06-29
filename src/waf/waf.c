#include "sentinel_waf.h"
#include "sentinel_common.h"
#include <string.h>
#include <ctype.h>
#include <stdio.h>

// Custom portable case-insensitive substring finder
static bool str_contains_nocase(const char *haystack, const char *needle) {
    if (!haystack || !needle) return false;
    size_t needle_len = strlen(needle);
    if (needle_len == 0) return true;

    size_t haystack_len = strlen(haystack);
    if (haystack_len < needle_len) return false;

    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        bool match = true;
        for (size_t j = 0; j < needle_len; j++) {
            if (tolower((unsigned char)haystack[i + j]) != tolower((unsigned char)needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

typedef struct {
    const char *pattern;
    const char *attack_name;
} WafSignature;

static const WafSignature sqli_signatures[] = {
    {"UNION SELECT", "SQL Injection: UNION SELECT"},
    {"UNION ALL SELECT", "SQL Injection: UNION ALL SELECT"},
    {"OR 1=1", "SQL Injection: Tautology OR 1=1"},
    {"' OR '", "SQL Injection: Tautology string match"},
    {"SELECT * FROM", "SQL Injection: Table dump SELECT"},
    {"INFORMATION_SCHEMA", "SQL Injection: Schema probing"},
    {NULL, NULL}
};

static const WafSignature xss_signatures[] = {
    {"<script>", "Cross-Site Scripting: Script tag"},
    {"javascript:", "Cross-Site Scripting: JS protocol"},
    {"onerror=", "Cross-Site Scripting: Event handler"},
    {"onload=", "Cross-Site Scripting: Event handler"},
    {"alert(", "Cross-Site Scripting: Alert payload"},
    {"<svg/onload", "Cross-Site Scripting: SVG vector"},
    {NULL, NULL}
};

static const WafSignature path_traversal_signatures[] = {
    {"../", "Path Traversal: Parent directory reference"},
    {"..\\", "Path Traversal: Windows parent directory reference"},
    {"/etc/passwd", "Path Traversal: Critical file read"},
    {"/windows/win.ini", "Path Traversal: Critical file read (Win)"},
    {"..\\..", "Path Traversal: Nested parent directory"},
    {NULL, NULL}
};

static const WafSignature cmd_injection_signatures[] = {
    {"; sh ", "Command Injection: Semicolon sh execution"},
    {"; bash ", "Command Injection: Semicolon bash execution"},
    {"| sh ", "Command Injection: Piping to shell"},
    {"| bash ", "Command Injection: Piping to shell"},
    {"&& id", "Command Injection: Chaining id command"},
    {"&& whoami", "Command Injection: Chaining whoami command"},
    {NULL, NULL}
};

static bool check_all_categories(const char *input, char *reason, size_t reason_len) {
    if (!input || strlen(input) == 0) return false;

    // Check SQLi
    for (int i = 0; sqli_signatures[i].pattern != NULL; i++) {
        if (str_contains_nocase(input, sqli_signatures[i].pattern)) {
            snprintf(reason, reason_len, "%s", sqli_signatures[i].attack_name);
            return true;
        }
    }

    // Check XSS
    for (int i = 0; xss_signatures[i].pattern != NULL; i++) {
        if (str_contains_nocase(input, xss_signatures[i].pattern)) {
            snprintf(reason, reason_len, "%s", xss_signatures[i].attack_name);
            return true;
        }
    }

    // Check Path Traversal
    for (int i = 0; path_traversal_signatures[i].pattern != NULL; i++) {
        if (str_contains_nocase(input, path_traversal_signatures[i].pattern)) {
            snprintf(reason, reason_len, "%s", path_traversal_signatures[i].attack_name);
            return true;
        }
    }

    // Check Command Injection
    for (int i = 0; cmd_injection_signatures[i].pattern != NULL; i++) {
        if (str_contains_nocase(input, cmd_injection_signatures[i].pattern)) {
            snprintf(reason, reason_len, "%s", cmd_injection_signatures[i].attack_name);
            return true;
        }
    }

    return false;
}

bool sentinel_waf_inspect(const HttpMeta *http, char *block_reason, size_t reason_len) {
    if (!http) return false;

    // Inspect URI
    if (check_all_categories(http->uri, block_reason, reason_len)) {
        sentinel_log(LOG_LEVEL_WARNING, "WAF Rule Triggered on URI: %s. Reason: %s", http->uri, block_reason);
        return true;
    }

    // Inspect Host
    if (check_all_categories(http->host, block_reason, reason_len)) {
        sentinel_log(LOG_LEVEL_WARNING, "WAF Rule Triggered on Host: %s. Reason: %s", http->host, block_reason);
        return true;
    }

    // Inspect User-Agent
    if (check_all_categories(http->user_agent, block_reason, reason_len)) {
        sentinel_log(LOG_LEVEL_WARNING, "WAF Rule Triggered on User-Agent: %s. Reason: %s", http->user_agent, block_reason);
        return true;
    }

    return false;
}

bool sentinel_waf_inspect_raw(const Packet *packet, char *block_reason, size_t reason_len) {
    if (!packet || !packet->payload || packet->payload_len == 0) {
        return false;
    }

    // Convert raw payload to safe temp string (up to 4096 bytes)
    size_t copy_len = packet->payload_len > 4095 ? 4095 : packet->payload_len;
    char temp_buf[4096];
    memcpy(temp_buf, packet->payload, copy_len);
    temp_buf[copy_len] = '\0';

    if (check_all_categories(temp_buf, block_reason, reason_len)) {
        sentinel_log(LOG_LEVEL_WARNING, "WAF Raw Inspection Triggered. Source IP: %s. Reason: %s", packet->src_ip, block_reason);
        return true;
    }

    return false;
}
