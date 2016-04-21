#include "smc-cache.h"

void smc_cache_init(SMCCache *cache, int capacity)
{
    memset(cache, 0, sizeof(*cache));
    cache->capacity = capacity;
    QTAILQ_INIT(&cache->entries);
    cache->map = g_hash_table_new(g_direct_hash, g_direct_equal);
}

void smc_cache_exit(SMCCache *cache)
{
    SMCCacheEntry *entry, *next;

    g_hash_table_destroy(cache->map);
    cache->map = NULL;

    QTAILQ_FOREACH_SAFE(entry, &cache->entries, node, next) {
        QTAILQ_REMOVE(&cache->entries, entry, node);
        g_free(entry);
    }

    cache->size = 0;
}

static inline SMCCacheEntry *smc_cache_find(SMCCache *cache, uint64_t block_offset,
                                            uint64_t offset)
{
    return g_hash_table_lookup(cache->map,
                               (void *)(uintptr_t)(block_offset + offset));
}

static inline void smc_cache_move_head(SMCCache *cache, SMCCacheEntry *entry)
{
    QTAILQ_REMOVE(&cache->entries, entry, node);
    QTAILQ_INSERT_HEAD(&cache->entries, entry, node);
}

static inline void smc_cache_remove(SMCCache *cache, SMCCacheEntry *entry)
{
    gpointer key = (void *)(uintptr_t)(entry->block_offset + entry->offset);

    g_hash_table_remove(cache->map, key);
    QTAILQ_REMOVE(&cache->entries, entry, node);
    g_free(entry);
}

static inline SMCCacheEntry *smc_cache_insert_head(SMCCache *cache,
                                                   SMCCacheEntry *new_entry)
{
    SMCCacheEntry *entry;
    gpointer key = (void *)(uintptr_t)(new_entry->block_offset +
                                       new_entry->offset);

    if (cache->size == cache->capacity) {
        smc_cache_remove(cache, QTAILQ_LAST(&cache->entries, smc_entries));
        cache->size--;
    }

    entry = g_malloc(sizeof(*entry));
    entry->block_offset = new_entry->block_offset;
    entry->offset = new_entry->offset;
    entry->stamp = new_entry->stamp;
    entry->in_checkpoint = new_entry->in_checkpoint;
    QTAILQ_INSERT_HEAD(&cache->entries, entry, node);
    g_hash_table_insert(cache->map, key, entry);
    cache->size++;
    return entry;
}

void smc_cache_update(SMCCache *cache, uint64_t block_offset, uint64_t offset,
                      uint64_t stamp, uint64_t in_checkpoint)
{
    SMCCacheEntry *entry;
    SMCCacheEntry new_entry = { .block_offset = block_offset,
                                .offset = offset,
                                .stamp = stamp,
                                .in_checkpoint = in_checkpoint,
                              };

    entry = smc_cache_find(cache, block_offset, offset);
    if (entry) {
        /* Entry already exists */
        smc_cache_move_head(cache, entry);
        entry->stamp = stamp;
        entry->in_checkpoint = in_checkpoint;
    } else {
        smc_cache_insert_head(cache, &new_entry);
    }
}

static void smc_cache_test_update_and_show(SMCCache *cache,
                                           uint64_t block_offset,
                                           uint64_t offset)
{
    SMCCacheEntry *entry;

    smc_cache_update(cache, block_offset, offset, 0, 0);
    printf("Cache:");
    SMC_CACHE_FOREACH(entry, cache) {
        printf(" %" PRIu64 ",%" PRIu64, entry->block_offset, entry->offset);
    }
    printf("\n");
}

void smc_cache_unit_test(void)
{
    static bool init = false;
    SMCCache smc_cache;
    int cap = 5;

    if (init) {
        return;
    } else {
        init = true;
    }
    printf("Unit test for SMCCache\n");
    smc_cache_init(&smc_cache, cap);
    smc_cache_test_update_and_show(&smc_cache, 0, 1);
    smc_cache_test_update_and_show(&smc_cache, 0, 2);
    smc_cache_test_update_and_show(&smc_cache, 0, 3);
    smc_cache_test_update_and_show(&smc_cache, 0, 1);
    smc_cache_test_update_and_show(&smc_cache, 0, 1);
    smc_cache_test_update_and_show(&smc_cache, 0, 4);
    smc_cache_test_update_and_show(&smc_cache, 0, 5);
    smc_cache_test_update_and_show(&smc_cache, 0, 3);
    smc_cache_test_update_and_show(&smc_cache, 0, 6);
    smc_cache_exit(&smc_cache);
}
