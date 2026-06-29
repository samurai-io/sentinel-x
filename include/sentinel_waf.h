#ifndef SENTINEL_WAF_H
#define SENTINEL_WAF_H

#include "sentinel_dpi.h"

// Inspects parsed HTTP data for common web attacks (SQLi, XSS, Path Traversal, Command Injection)
// Returns: true if attack is detected (should block); false if clean.
bool sentinel_waf_inspect(const HttpMeta *http, char *block_reason, size_t reason_len);

// Fallback direct raw payload pattern inspection (in case DPI parsing was partial)
bool sentinel_waf_inspect_raw(const Packet *packet, char *block_reason, size_t reason_len);

#endif // SENTINEL_WAF_H
