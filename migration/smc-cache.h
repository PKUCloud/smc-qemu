#ifndef MIGRATION_SMC_CACHE_H
#define MIGRATION_SMC_CACHE_H

#include "qemu/queue.h"
#include "qemu/typedefs.h"
#include "qemu-common.h"

#define SMC_CACHE_MAX_STAMP_DIFF        5
#define SMC_CACHE_MAX_PRI_LEVEL         3


typedef struct SMCCacheEntry {
    /* block_offset and offset as the key */
    uint64_t block_offset;
    uint64_t offset;
    uint64_t stamp;
    uint64_t  in_checkpoint;
    int pri;
    QTAILQ_ENTRY(SMCCacheEntry) node;
} SMCCacheEntry;

QTAILQ_HEAD(smc_entries, SMCCacheEntry);

typedef struct SMCCacheLevel {
    int capacity;
    int size;
    int nr_hits;
    struct smc_entries entries;
} SMCCacheLevel;

typedef struct SMCCache {
    /* We only zap the least priority level */
    int soft_capacity;
    GHashTable *map;
    struct smc_entries empty_list;
    SMCCacheLevel levels[SMC_CACHE_MAX_PRI_LEVEL];
    int nr_updates;
} SMCCache;

void smc_cache_init(SMCCache *cache);
void smc_cache_exit(SMCCache *cache);
void smc_cache_update(SMCCache *cache, uint64_t block_offset, uint64_t offset,
                      uint64_t stamp, uint64_t in_checkpoint);
void smc_cache_zap(SMCCache *cache);
void smc_cache_unit_test(void);
void smc_cache_stat(SMCCache *cache);

static inline bool smc_cache_need_zap(SMCCache *cache)
{
    return cache->levels[0].size >= cache->soft_capacity;
}

#define SMC_CACHE_FOREACH_ENTRY(entry, smc_cache_level) \
        QTAILQ_FOREACH(entry, &(smc_cache_level)->entries, node)

#define SMC_CACHE_FOREACH_LEVEL(level, smc_cache)   \
        for ((level) = &((smc_cache)->levels[SMC_CACHE_MAX_PRI_LEVEL - 1]); \
             (level) >= (smc_cache)->levels; (level)--)
#endif
