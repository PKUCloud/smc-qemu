#ifndef MIGRATION_SMC_H
#define MIGRATION_SMC_H

#include "qemu/typedefs.h"
#include "qemu-common.h"

/* Info about a dirty page within a chunk */
typedef struct SMCDirtyPage {
    /* Offset of the RAMBlock which contains the page */
    uint64_t block_offset;
    /* Offset inside the RAMBlock which contains the page */
    uint64_t offset;
    uint64_t size;
} SMCDirtyPage;

/* Maintain an array of a struct */
typedef struct SMCSet {
    uint8_t *eles;     /* An array of a struct */
    int cap;        /* Total number of the struct @eles can hold */
    int nb_eles;    /* Current number of the struct @eles holds */
    int ele_size;   /* sizeof(struct) */
} SMCSet;

typedef struct SMCInfo {
    bool init;
    SMCSet dirty_pages;
} SMCInfo;

extern SMCInfo glo_smc_info;

void smc_init(SMCInfo *smc_info);
void smc_exit(SMCInfo *smc_info);
void smc_dirty_pages_insert(SMCInfo *smc_info, uint64_t block_offset,
                            uint64_t offset, uint64_t size);
void smc_dirty_pages_reset(SMCInfo *smc_info);
void smc_dirty_pages_insert_from_buf(SMCInfo *smc_info, const void *buf,
                                     int nb_pages);
void smc_send_dirty_info(void *opaque, SMCInfo *smc_info);
void smc_recv_dirty_info(void *opaque, SMCInfo *smc_info);

static inline int smc_dirty_pages_count(SMCInfo *smc_info)
{
    return smc_info->dirty_pages.nb_eles;
}

static inline SMCDirtyPage *smc_dirty_pages_info(SMCInfo *smc_info)
{
    return (SMCDirtyPage *)(smc_info->dirty_pages.eles);
}

static inline bool smc_is_init(SMCInfo *smc_info)
{
    return smc_info->init;
}
#endif
