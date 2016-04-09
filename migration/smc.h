#ifndef MIGRATION_SMC_H
#define MIGRATION_SMC_H

#include "qemu/typedefs.h"

/* Info about a dirty page within a chunk */
typedef struct SMCDirtyPage {
    /* Offset of the RAMBlock which contains the page */
    uint64_t block_offset;
    /* Offset inside the RAMBlock which contains the page */
    uint64_t offset;
    uint64_t size;
} SMCDirtyPage;

/* Maintain an array of SMCDirtyPage */
typedef struct SMCDirtyPageSet {
    SMCDirtyPage *pages;
    int size;
    int nb_pages;
} SMCDirtyPageSet;

typedef struct SMCInfo {
    SMCDirtyPageSet dirty_pages;
} SMCInfo;

extern SMCInfo glo_smc_info;

void smc_init(SMCInfo *smc_info);
void smc_exit(SMCInfo *smc_info);
void smc_dirty_pages_insert(SMCInfo *smc_info, uint64_t block_offset,
                            uint64_t offset, uint64_t size);
void smc_dirty_pages_reset(SMCInfo *smc_info);
void smc_dirty_pages_from_buf(SMCInfo *smc_info, const void *buf, int nb_pages);
void smc_send_dirty_info(void *opaque, SMCInfo *smc_info);
void smc_recv_dirty_info(void *opaque, SMCInfo *smc_info);

static inline int smc_dirty_pages_count(SMCInfo *smc_info)
{
    return smc_info->dirty_pages.nb_pages;
}

static inline SMCDirtyPage *smc_dirty_pages_info(SMCInfo *smc_info)
{
    return smc_info->dirty_pages.pages;
}
#endif
