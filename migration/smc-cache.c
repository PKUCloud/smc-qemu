#include "smc-cache.h"
#include "smc-debug.h"

static const int SMC_CACHE_CAPS[] = {30000, 30000, 6000};

#define SMC_CACHE_SOFT_CAP      30000

static void smc_cache_pre_alloc(SMCCache *cache)
{
    int cap = 0;
    int i;
    SMCCacheEntry *entry;

    for (i = 0; i < SMC_CACHE_MAX_PRI_LEVEL; ++i) {
        cap += cache->levels[i].capacity;
    }
    /* Alloc one more entry in the case that all levels are full and we now
     * want to insert a new entry.
     */
    cap++;
    for (i = 0; i < cap; ++i) {
        entry = g_malloc(sizeof(*entry));
        QTAILQ_INSERT_HEAD(&cache->empty_list, entry, node);
    }
}

void smc_cache_init(SMCCache *cache)
{
    int i;
    SMCCacheLevel *level;

    memset(cache, 0, sizeof(*cache));

    for (i = 0; i < SMC_CACHE_MAX_PRI_LEVEL; ++i) {
        level = &(cache->levels[i]);
        level->size = 0;
        level->capacity = SMC_CACHE_CAPS[i];
        QTAILQ_INIT(&level->entries);
    }
    cache->soft_capacity = SMC_CACHE_SOFT_CAP;
    QTAILQ_INIT(&cache->empty_list);
    cache->map = g_hash_table_new(g_direct_hash, g_direct_equal);

    smc_cache_pre_alloc(cache);
}

void smc_cache_exit(SMCCache *cache)
{
    SMCCacheEntry *entry, *next;
    int i;
    struct smc_entries *head;

    g_hash_table_destroy(cache->map);
    cache->map = NULL;

    for (i = 0; i < SMC_CACHE_MAX_PRI_LEVEL; ++i) {
        head = &(cache->levels[i].entries);
        QTAILQ_FOREACH_SAFE(entry, head, node, next) {
            QTAILQ_REMOVE(head, entry, node);
            g_free(entry);
        }
        cache->levels[i].size = 0;
    }

    QTAILQ_FOREACH_SAFE(entry, &cache->empty_list, node, next) {
        QTAILQ_REMOVE(&cache->empty_list, entry, node);
        g_free(entry);
    }
}

static inline SMCCacheEntry *smc_malloc_entry(SMCCache *cache)
{
    SMCCacheEntry *entry = QTAILQ_FIRST(&cache->empty_list);

    if (entry) {
        QTAILQ_REMOVE(&cache->empty_list, entry, node);
    }
    return entry;
}

static inline void smc_free_entry(SMCCache *cache, SMCCacheEntry *entry)
{
    QTAILQ_INSERT_HEAD(&cache->empty_list, entry, node);
}

static inline SMCCacheEntry *smc_cache_find(SMCCache *cache,
                                            uint64_t block_offset,
                                            uint64_t offset)
{
    return g_hash_table_lookup(cache->map,
                               (void *)(uintptr_t)(block_offset + offset));
}

#define QTAILQ_FOREACH_REVERSE_SAVE(var, head, headname, field, next_var)       \
        for ((var) = (*(((struct headname *)((head)->tqh_last))->tqh_last));    \
             (var) && \
             ((next_var) = (*(((struct headname *)((var)->field.tqe_prev))->tqh_last)), 1); \
             (var) = (next_var))

void smc_cache_zap(SMCCache *cache)
{
    struct smc_entries *head = &(cache->levels[0].entries);
    SMCCacheEntry *entry = QTAILQ_FIRST(head);
    uint64_t oldest = entry->stamp;
    SMCCacheEntry *next_entry;
    int nr_zap = 0;
    GHashTable *map = cache->map;
    gpointer key;

    if (oldest < SMC_CACHE_MAX_STAMP_DIFF) {
        return;
    }
    oldest -= SMC_CACHE_MAX_STAMP_DIFF;
    QTAILQ_FOREACH_REVERSE_SAVE(entry, head, smc_entries, node, next_entry) {
        if (entry->stamp < oldest) {
            key = (void *)(uintptr_t)(entry->block_offset + entry->offset);
            g_hash_table_remove(map, key);
            QTAILQ_REMOVE(head, entry, node);
            smc_free_entry(cache, entry);
            ++nr_zap;
        } else {
            break;
        }
    }
    SMC_LOG(FETCH, "zap %d/%d cache entries", nr_zap, cache->levels[0].size);
    cache->levels[0].size -= nr_zap;
}

static inline void smc_cache_level_remove(SMCCacheLevel *level,
                                          SMCCacheEntry *entry)
{
    QTAILQ_REMOVE(&level->entries, entry, node);
    level->size--;
}

static void smc_cache_level_insert(SMCCache *cache, int lev,
                                   SMCCacheEntry *new_entry)
{
    SMCCacheEntry *entry;
    gpointer key;
    SMCCacheLevel *level = &cache->levels[lev];

    if (level->size == level->capacity) {
        /* Make room for new entry */
        entry = QTAILQ_LAST(&level->entries, smc_entries);
        smc_cache_level_remove(level, entry);

        if (lev == 0 || lev == 1) {
            /* Free this entry */
            key = (void *)(uintptr_t)(entry->block_offset + entry->offset);
            g_hash_table_remove(cache->map, key);
            smc_free_entry(cache, entry);
        } else {
            smc_cache_level_insert(cache, lev - 1, entry);
        }
    }

    new_entry->pri = lev;

    QTAILQ_INSERT_HEAD(&level->entries, new_entry, node);
    level->size++;
}

static inline void smc_cache_level_move_head(SMCCacheLevel *level,
                                             SMCCacheEntry *entry)
{
    QTAILQ_REMOVE(&level->entries, entry, node);
    QTAILQ_INSERT_HEAD(&level->entries, entry, node);
}

void smc_cache_update(SMCCache *cache, uint64_t block_offset, uint64_t offset,
                      uint64_t stamp, uint64_t in_checkpoint)
{
    SMCCacheEntry *entry;
    gpointer key;
    int lev = 0;

    entry = smc_cache_find(cache, block_offset, offset);
    if (entry) {
        /* Entry already exists */
        entry->stamp = stamp;
        entry->in_checkpoint = in_checkpoint;

        lev = entry->pri;
        if (lev == SMC_CACHE_MAX_PRI_LEVEL - 1) {
            smc_cache_level_move_head(&(cache->levels[lev]), entry);
        } else {
            smc_cache_level_remove(&(cache->levels[lev]), entry);
            smc_cache_level_insert(cache, SMC_CACHE_MAX_PRI_LEVEL - 1, entry);
        }
        cache->levels[lev].nr_hits++;
    } else {
        entry = smc_malloc_entry(cache);
        entry->block_offset = block_offset;
        entry->offset = offset;
        entry->stamp = stamp;
        entry->in_checkpoint = in_checkpoint;

        smc_cache_level_insert(cache, lev, entry);
        key = (void *)(uintptr_t)(entry->block_offset + entry->offset);
        g_hash_table_insert(cache->map, key, entry);
    }
    cache->nr_updates++;
}

void smc_cache_stat(SMCCache *cache)
{
    SMCCacheLevel *levels = cache->levels;

    printf("hit/update[%d]: %lf %lf %lf\n", cache->nr_updates,
           levels[2].nr_hits * 1.0 / cache->nr_updates,
           levels[1].nr_hits * 1.0 / cache->nr_updates,
           levels[0].nr_hits * 1.0 / cache->nr_updates);
}

static void smc_cache_test_update_and_show(SMCCache *cache,
                                           uint64_t block_offset,
                                           uint64_t offset)
{
    SMCCacheLevel *level;
    SMCCacheEntry *entry;

    smc_cache_update(cache, block_offset, offset, 0, 0);
    printf("Cache:\n");
    SMC_CACHE_FOREACH_LEVEL(level, cache) {
        printf("\tLevel:");
        SMC_CACHE_FOREACH_ENTRY(entry, level) {
            printf("(%" PRIu64 ", %d)", entry->offset, entry->pri);
        }
        printf("\n");
    }
}

/* Should set the cap to a small value */
void smc_cache_unit_test(void)
{
    static bool init = false;
    SMCCache smc_cache;

    if (init) {
        return;
    } else {
        init = true;
    }
    printf("Unit test for SMCCache\n");
    smc_cache_init(&smc_cache);

    smc_cache_test_update_and_show(&smc_cache, 0, 1);
    smc_cache_test_update_and_show(&smc_cache, 0, 2);
    smc_cache_test_update_and_show(&smc_cache, 0, 3);
    smc_cache_test_update_and_show(&smc_cache, 0, 4);
    smc_cache_test_update_and_show(&smc_cache, 0, 5);
    smc_cache_test_update_and_show(&smc_cache, 0, 6);
    smc_cache_test_update_and_show(&smc_cache, 0, 2);
    smc_cache_test_update_and_show(&smc_cache, 0, 5);
    smc_cache_test_update_and_show(&smc_cache, 0, 4);
    smc_cache_test_update_and_show(&smc_cache, 0, 7);
    smc_cache_test_update_and_show(&smc_cache, 0, 8);
    smc_cache_test_update_and_show(&smc_cache, 0, 3);
    smc_cache_test_update_and_show(&smc_cache, 0, 4);
    smc_cache_test_update_and_show(&smc_cache, 0, 3);
    smc_cache_test_update_and_show(&smc_cache, 0, 5);
    smc_cache_test_update_and_show(&smc_cache, 0, 7);
    smc_cache_test_update_and_show(&smc_cache, 0, 8);
    smc_cache_test_update_and_show(&smc_cache, 0, 9);
    smc_cache_test_update_and_show(&smc_cache, 0, 8);

    smc_cache_exit(&smc_cache);
}
