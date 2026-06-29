#ifndef SENTINEL_COMMON_H
#define SENTINEL_COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <time.h>

// Logging levels
typedef enum {
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_CRITICAL
} LogLevel;

void sentinel_log(LogLevel level, const char *format, ...);
const char *log_level_to_str(LogLevel level);

// Time utility helper
uint64_t sentinel_current_time_ms(void);

// Thread-safe Generic Hashmap interface
typedef struct HashNode {
    char *key;
    void *value;
    struct HashNode *next;
} HashNode;

typedef struct {
    HashNode **buckets;
    size_t size;
    pthread_mutex_t *locks; // Fine-grained locking: one lock per bucket
} HashMap;

HashMap *hashmap_create(size_t size);
void hashmap_free(HashMap *map, void (*free_val_fn)(void *));
bool hashmap_put(HashMap *map, const char *key, void *value);
void *hashmap_get(HashMap *map, const char *key);
bool hashmap_remove(HashMap *map, const char *key, void (*free_val_fn)(void *));

#endif // SENTINEL_COMMON_H
