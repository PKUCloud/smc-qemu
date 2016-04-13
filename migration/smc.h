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

typedef uint64_t    SMC_HASH;

typedef struct SMCFetchPage {
    uint64_t block_offset;
    uint64_t offset;
    uint64_t size;
    SMC_HASH hash;
} SMCFetchPage;

typedef struct SMCInfo {
    bool init;
    SMCSet dirty_pages;
    SMCSet prefetch_pages;
} SMCInfo;

extern SMCInfo glo_smc_info;

void smc_init(SMCInfo *smc_info);
void smc_exit(SMCInfo *smc_info);
void smc_dirty_pages_insert(SMCInfo *smc_info, uint64_t block_offset,
                            uint64_t offset, uint64_t size);
void smc_dirty_pages_reset(SMCInfo *smc_info);
void smc_dirty_pages_insert_from_buf(SMCInfo *smc_info, const void *buf,
                                     int nb_pages);
void smc_prefetch_pages_reset(SMCInfo *smc_info);
void smc_prefetch_pages_insert(SMCInfo *smc_info, uint64_t block_offset,
                               uint64_t offset, uint64_t size, SMC_HASH hash);
void smc_prefetch_pages_insert_from_buf(SMCInfo *smc_info, const void *buf,
                                        int nb_pages);

void smc_send_dirty_info(void *opaque, SMCInfo *smc_info);
int smc_recv_dirty_info(void *opaque, SMCInfo *smc_info);
void smc_recv_prefetch_info(void *opaque, SMCInfo *smc_info,
                            bool request_info);
void smc_sync_notice_dest_to_recv(void *opaque, SMCInfo *smc_info);
int smc_sync_src_ready_to_recv(void *opaque, SMCInfo *smc_info);
int smc_prefetch_dirty_pages(void *opaque, SMCInfo *smc_info);

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

static inline int smc_prefetch_pages_count(SMCInfo *smc_info)
{
    return smc_info->prefetch_pages.nb_eles;
}

static inline SMCFetchPage *smc_prefetch_pages_info(SMCInfo *smc_info)
{
    return (SMCFetchPage *)(smc_info->prefetch_pages.eles);
}
#endif
