#include "sentinel_common.h"
#include <stdlib.h>
#include <string.h>

// Fowler-Noll-Vo (FNV-1a) Hash Function
static uint32_t fnv1a_hash(const char *key) {
    uint32_t hash = 2166136261u;
    while (*key) {
        hash ^= (unsigned char)*key++;
        hash *= 16777619u;
    }
    return hash;
}

HashMap *hashmap_create(size_t size) {
    HashMap *map = malloc(sizeof(HashMap));
    if (!map) return NULL;

    map->size = size;
    map->buckets = calloc(size, sizeof(HashNode *));
    if (!map->buckets) {
        free(map);
        return NULL;
    }

    map->locks = malloc(size * sizeof(pthread_mutex_t));
    if (!map->locks) {
        free(map->buckets);
        free(map);
        return NULL;
    }

    for (size_t i = 0; i < size; i++) {
        pthread_mutex_init(&map->locks[i], NULL);
    }

    return map;
}

void hashmap_free(HashMap *map, void (*free_val_fn)(void *)) {
    if (!map) return;

    for (size_t i = 0; i < map->size; i++) {
        pthread_mutex_lock(&map->locks[i]);
        HashNode *node = map->buckets[i];
        while (node) {
            HashNode *tmp = node->next;
            free(node->key);
            if (free_val_fn && node->value) {
                free_val_fn(node->value);
            }
            free(node);
            node = tmp;
        }
        pthread_mutex_unlock(&map->locks[i]);
        pthread_mutex_destroy(&map->locks[i]);
    }

    free(map->buckets);
    free(map->locks);
    free(map);
}

bool hashmap_put(HashMap *map, const char *key, void *value) {
    if (!map || !key) return false;

    uint32_t hash = fnv1a_hash(key);
    size_t index = hash % map->size;

    pthread_mutex_lock(&map->locks[index]);

    HashNode *node = map->buckets[index];
    while (node) {
        if (strcmp(node->key, key) == 0) {
            // Key already exists, replace value (do not free old value here, caller handles replacements if needed,
            // or we just replace the pointer).
            node->value = value;
            pthread_mutex_unlock(&map->locks[index]);
            return true;
        }
        node = node->next;
    }

    // Insert new node at head of bucket chain
    HashNode *new_node = malloc(sizeof(HashNode));
    if (!new_node) {
        pthread_mutex_unlock(&map->locks[index]);
        return false;
    }

    new_node->key = strdup(key);
    new_node->value = value;
    new_node->next = map->buckets[index];
    map->buckets[index] = new_node;

    pthread_mutex_unlock(&map->locks[index]);
    return true;
}

void *hashmap_get(HashMap *map, const char *key) {
    if (!map || !key) return NULL;

    uint32_t hash = fnv1a_hash(key);
    size_t index = hash % map->size;

    pthread_mutex_lock(&map->locks[index]);

    HashNode *node = map->buckets[index];
    void *val = NULL;
    while (node) {
        if (strcmp(node->key, key) == 0) {
            val = node->value;
            break;
        }
        node = node->next;
    }

    pthread_mutex_unlock(&map->locks[index]);
    return val;
}

bool hashmap_remove(HashMap *map, const char *key, void (*free_val_fn)(void *)) {
    if (!map || !key) return false;

    uint32_t hash = fnv1a_hash(key);
    size_t index = hash % map->size;

    pthread_mutex_lock(&map->locks[index]);

    HashNode *prev = NULL;
    HashNode *node = map->buckets[index];
    while (node) {
        if (strcmp(node->key, key) == 0) {
            if (prev) {
                prev->next = node->next;
            } else {
                map->buckets[index] = node->next;
            }
            free(node->key);
            if (free_val_fn && node->value) {
                free_val_fn(node->value);
            }
            free(node);
            pthread_mutex_unlock(&map->locks[index]);
            return true;
        }
        prev = node;
        node = node->next;
    }

    pthread_mutex_unlock(&map->locks[index]);
    return false;
}
