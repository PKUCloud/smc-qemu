#ifndef MIGRATION_SMC_CACHE_H
#define MIGRATION_SMC_CACHE_H

#include "qemu/queue.h"
#include "qemu/typedefs.h"
#include "qemu-common.h"

typedef struct SMCCacheEntry {
    /* block_offset and offset as the key */
    uint64_t block_offset;
    uint64_t offset;
    uint64_t stamp;
    uint64_t  in_checkpoint;
    QTAILQ_ENTRY(SMCCacheEntry) node;
} SMCCacheEntry;

typedef struct SMCCache {
    int capacity;
    int size;
    GHashTable *map;
    QTAILQ_HEAD(smc_entries, SMCCacheEntry) entries;
} SMCCache;

void smc_cache_init(SMCCache *cache, int capacity);
void smc_cache_exit(SMCCache *cache);
void smc_cache_update(SMCCache *cache, uint64_t block_offset, uint64_t offset,
                      uint64_t stamp, uint64_t in_checkpoint);
void smc_cache_unit_test(void);

#define SMC_CACHE_FOREACH(entry, smc_cache) \
        QTAILQ_FOREACH(entry, &(smc_cache)->entries, node)
#endif
