#ifndef MIGRATION_SMC_H
#define MIGRATION_SMC_H

#include "qemu/typedefs.h"
#include "qemu-common.h"
#include "smc-debug.h"
#include "smc-cache.h"

//for unsignaled completions
#define NEED_SEND_SIGNAL 1
#define NO_NEED_SEND_SIGNAL 0

//#define SMC_PREFETCH
#define SMC_PML_PREFETCH

#define SMC_DIRTY_FLAGS_IN_CHECKPOINT   0x1U

#define SMC_PREFETCH_RECV_TIME          2
/* TODO: this should match the dev_cap.max_qp_wr,
 * which can be found by using $ ibv_devinfo -v
 */
// #define SMC_NUM_DIRTY_PAGES_SEND        16351
#define SMC_NUM_DIRTY_PAGES_SEND        3000
#define SMC_PML_PREFETCH_ROUND          5
/* default checkpoint frequency */
#define MC_DEFAULT_CHECKPOINT_FREQ_MS   5

/* Info about a dirty page within a chunk */
typedef struct SMCDirtyPage {
    /* Offset of the RAMBlock which contains the page */
    uint64_t block_offset;
    /* Offset inside the RAMBlock which contains the page */
    uint64_t offset;
    uint32_t size;
    uint32_t flags;
} SMCDirtyPage;

/* Info about a dirty page got from a PML sync */
typedef struct SMCPMLPrefetchPage {
    /* Offset of the RAMBlock which contains the page */
    uint64_t block_offset;
    /* Offset inside the RAMBlock which contains the page */
    uint64_t offset;
    uint32_t size;
    bool in_checkpoint;
} SMCPMLPrefetchPage;

/* Info about a backup page which has been COWed during prefetching */
typedef struct SMCPMLBackupPage {
    uint64_t block_offset;
    uint64_t offset;
    uint64_t size;
    uint8_t *data;
    uint8_t *host_addr;
} SMCPMLBackupPage;


/* Maintain an array of a struct */
typedef struct SMCSet {
    uint8_t *eles;     /* An array of a struct */
    int cap;        /* Total number of the struct @eles can hold */
    int nb_eles;    /* Current number of the struct @eles holds */
    int ele_size;   /* sizeof(struct) */
} SMCSet;

/* Maintain an array of SMCSet */
typedef struct SMCSuperSet {
    uint8_t *subsets;      /* An array of SMCSet */
    int cap;            /* Total number of the SMCSet that  @subsets can hold */
    int nb_subsets; /* Current number of the SMCSet that @subsets holds */
} SMCSuperSet;

#define SMC_JHASH_INIT_VAL  1824115964UL
typedef uint32_t    SMC_HASH;

typedef struct SMCFetchPage {
    uint64_t block_offset;
    uint64_t offset;
    uint32_t size;
    uint32_t idx;   /* Index in SMCSet */
    SMC_HASH hash;
} SMCFetchPage;

typedef struct SMCBackupPage {
    uint64_t block_offset;
    uint64_t offset;
    uint64_t size;
    uint8_t *data;
    uint8_t *host_addr;
} SMCBackupPage;

/* Info about how many times dose one page already been prefetched */
typedef struct SMCPMLPrefetchedPageCounter {
    SMCPMLPrefetchPage *prefetched_page;
    uint64_t counter;
} SMCPMLPrefetchedPageCounter;

typedef struct SMCPMLRoundPrefetchInfo{
    uint64_t nb_pages;
    uint64_t prefetch_time;
} SMCPMLRoundPrefetchInfo;

#define SMC_STATE_RECV_CHECKPOINT       0
#define SMC_STATE_PREFETCH_START        1
#define SMC_STATE_PREFETCH_DONE         2
#define SMC_STATE_PREFETCH_ABANDON      3
#define SMC_STATE_TRANSACTION_START     4

#define SMC_FETCH_CACHE_CAP             3000
#define SMC_FETCH_CACHE_SOFT_CAP        3000
#define SMC_PML_PREFETCH_ROUND_LIMIT    100

typedef struct SMCInfo {
    bool init;
    SMCSet dirty_pages;
    SMCSet prefetch_pages;
    /* Pay attention to maintain the dynamically allocated memory */
    SMCSet backup_pages;
    /* Used to find whether a given page is a the prefetch list when the dst
     * is committing the checkpoint.
     * [page_physical_addr] -> the pointer of the corresponding SMCFetchPage
     */
    GHashTable *prefetch_map;
    /* store the prefetched pages' info when using Intel PML */
    SMCSuperSet pml_prefetch_pages;
    /* store the last correct version of one prefetched page*/
    SMCSet pml_backup_pages;
    /* Used to find whether a given page has been prefetched before */
    GHashTable *pml_prefetched_map;
    int state;
    bool need_rollback;
    void *opaque;   /* QEMUFileRDMA */
    SMCCache cache;
    uint64_t nr_checkpoints;
    bool enable_incheckpoint_bitmap;
    //bool need_clear_incheckpoint_bitmap;
    /* store the prefetched info of each round */
    SMCPMLRoundPrefetchInfo  pml_round_prefetch_info[SMC_PML_PREFETCH_ROUND_LIMIT];
    /* store the prefetched pages' info temporary when we sorting them */
    SMCSuperSet pml_unsort_prefetch_pages;
    /* dirty page transmission speed (pages per millisecond) */
    double pml_xmit_speed;
    bool early_flush_buffer;

    // for calc total and per second dirty pages decrease 
    uint64_t stat_nb_unprefetched_pages;
    uint64_t stat_nb_unprefetched_pages_when_do_prefetch;
    uint64_t stat_nb_prefetched_pages;
    double stat_dirty_decrease_rate; 
    int not_to_prefetch_flag;
    unsigned long *prefetch_bitmap;

    uint64_t stat_nb_unprefetched_pages_per_sec;
    uint64_t stat_nb_unprefetched_pages_when_do_prefetch_per_sec;
    uint64_t stat_nb_prefetched_pages_per_sec;
    double stat_dirty_decrease_rate_per_sec; 
    // for calc total and per second dirty pages decrease 
} SMCInfo;

extern SMCInfo glo_smc_info;

void smc_init(SMCInfo *smc_info, void *opaque);
void smc_exit(SMCInfo *smc_info);
void smc_dirty_pages_insert(SMCInfo *smc_info, uint64_t block_offset,
                            uint64_t offset, uint32_t size, uint32_t flags);
void smc_pml_unsort_prefetch_pages_insert(SMCInfo *smc_info,
                                            uint64_t block_offset,
                                            uint64_t offset, 
                                            bool in_checkpoint, 
                                            uint32_t size, int subset_idx);
void smc_pml_sort_prefetch_pages(SMCInfo *smc_info);
void smc_pml_prefetch_pages_next_subset(SMCInfo *smc_info);
void smc_pml_prefetch_pages_reset(SMCInfo *smc_info);
void smc_pml_unsort_prefetch_pages_reset(SMCInfo *smc_info);
void smc_pml_prefetch_pages_insert_from_buf(SMCInfo *smc_info, 
                                     const void *buf, int nb_pages);
void smc_dirty_pages_reset(SMCInfo *smc_info);
void smc_dirty_pages_insert_from_buf(SMCInfo *smc_info, const void *buf,
                                     int nb_pages);
void smc_prefetch_pages_reset(SMCInfo *smc_info);
SMCFetchPage *smc_prefetch_pages_insert(SMCInfo *smc_info,
                                        uint64_t block_offset,
                                        uint64_t offset, uint32_t size,
                                        SMC_HASH hash);
void smc_prefetch_pages_insert_from_buf(SMCInfo *smc_info, const void *buf,
                                        int nb_pages);

int smc_send_dirty_info(void *opaque, SMCInfo *smc_info);
int smc_pml_send_prefetch_signal(void *opaque, bool stop);
int smc_pml_send_prefetch_info(void *opaque, SMCInfo *smc_info);
int smc_pml_send_empty_prefetch_info(void *opaque, SMCInfo *smc_info);
int smc_recv_dirty_info(void *opaque, SMCInfo *smc_info);
int smc_pml_recv_prefetch_info(void *opaque, SMCInfo *smc_info);
int smc_recv_prefetch_info(void *opaque, SMCInfo *smc_info,
                           bool request_info);
int smc_sync_notice_dest_to_recv(void *opaque, SMCInfo *smc_info);
int smc_sync_src_ready_to_recv(void *opaque, SMCInfo *smc_info);
int smc_prefetch_dirty_pages(void *opaque, SMCInfo *smc_info);
int smc_pml_prefetch_dirty_pages(void *opaque, SMCInfo *smc_info);
int smc_pml_recv_round_prefetched_num(void *opaque, SMCInfo *smc_info);
int smc_pml_send_round_prefetched_num(void *opaque, SMCInfo *smc_info);
void smc_backup_pages_insert(SMCInfo *smc_info, uint64_t block_offset,
                             uint64_t offset, uint64_t size,
                             uint8_t *data);
void smc_pml_backup_pages_insert(SMCInfo *smc_info, uint64_t block_offset,
                             uint64_t offset, uint64_t size,
                             uint8_t *data);
void *smc_backup_pages_insert_empty(SMCInfo *smc_info, uint64_t block_offset,
                                    uint64_t offset, uint64_t size,
                                    uint8_t *host_addr);
void *smc_pml_backup_pages_insert_empty(SMCInfo *smc_info, uint64_t block_offset,
                                    uint64_t offset, uint64_t size,
                                    uint8_t *host_addr);

void smc_backup_pages_reset(SMCInfo *smc_info);
void smc_pml_backup_pages_reset(SMCInfo *smc_info);
void smc_recover_backup_pages(SMCInfo *smc_info);
void smc_pml_recover_backup_pages(SMCInfo *smc_info);
void smc_prefetch_page_cal_hash(SMCInfo *smc_info, int index);
void smc_rollback_with_prefetch(SMCInfo *smc_info);
void smc_pml_rollback_with_prefetch(SMCInfo *smc_info);
bool smc_loadvm_need_check_prefetch(SMCInfo *smc_info);
bool smc_check_dirty_page(SMCInfo *smc_info, uint64_t block_offset,
                          uint64_t offset, uint64_t size, SMC_HASH hash_val);

uint8_t *smc_host_addr_from_offset(void *opaque, uint64_t block_offset,
                                   uint64_t offset);
void smc_prefetch_map_gen_from_pages(SMCInfo *smc_info);
void smc_update_prefetch_cache(SMCInfo *smc_info);
int smc_load_page_stub(QEMUFile *f, void *opaque, void *host_addr, long size);
SMCPMLPrefetchPage *smc_pml_prefetch_pages_info(SMCInfo *smc_info);
SMCPMLPrefetchPage *smc_pml_prefetch_pages_get_idex(SMCInfo *smc_info,
                                             int superset_idx, int subset_idx);
int smc_pml_prefetch_pages_count(SMCInfo *smc_info, int superset_idx);
int smc_pml_persist_unprefetched_pages(SMCInfo *smc_info);
void smc_pml_set_bitmap_through_offset(uint64_t block_offset,
                                                    uint64_t offset);
void smc_pml_clear_bitmap_through_offset(uint64_t block_offset,
                                                    uint64_t offset);
uint64_t smc_pml_calculate_xmit_sleep_time(SMCInfo *smc_info, 
                                                       uint64_t remain_time);
void ram_pml_clear_incheckpoint_bitmap(void);

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

static inline void smc_prefetch_map_reset(SMCInfo *smc_info)
{
    g_hash_table_remove_all(smc_info->prefetch_map);
}

static inline void smc_pml_prefetched_map_reset(SMCInfo *smc_info)
{
    g_hash_table_remove_all(smc_info->pml_prefetched_map);
}

static inline void smc_prefetch_map_insert(SMCInfo *smc_info, uint64_t phy_addr,
                                           SMCFetchPage *page)
{
    gpointer key = (void *)(uintptr_t)phy_addr;

    SMC_ASSERT(page);
    SMC_ASSERT(g_hash_table_lookup(smc_info->prefetch_map, key) == NULL);

    g_hash_table_insert(smc_info->prefetch_map, key, page);
}

static inline void smc_pml_prefetched_map_insert(SMCInfo *smc_info, 
                                           uint64_t phy_addr, uint32_t nb_page_prefetched)
{
    gpointer key = (void *)(uintptr_t)phy_addr;
    gpointer value = GUINT_TO_POINTER(nb_page_prefetched);

    g_hash_table_insert(smc_info->pml_prefetched_map, key, value);

    //SMC_LOG(PML, "insert to pml_prefetched_map phy_addr(offset+block_offset)=%" PRIu64 
    //        " counter=%d", phy_addr, nb_page_prefetched);
}

static inline SMCFetchPage *smc_prefetch_map_lookup(SMCInfo *smc_info,
                                                    uint64_t phy_addr)
{
    return g_hash_table_lookup(smc_info->prefetch_map,
                               (void *)(uintptr_t)phy_addr);
}

static inline uint32_t smc_pml_prefetched_map_lookup
                                            (SMCInfo *smc_info, uint64_t phy_addr)
{
    gpointer value;
    uint32_t ret;
    value = g_hash_table_lookup(smc_info->pml_prefetched_map, 
                             (void *)(uintptr_t)phy_addr);
    if (value) {
        ret = GPOINTER_TO_UINT(value);
        //SMC_LOG(PML, "phy_addr(offset+block_offset)=%" PRIu64 " counter=%d",
        //        phy_addr, ret);
        return ret;
    } else {
        return 0;
    }
}

static inline void smc_set_state(SMCInfo *smc_info, int state)
{
    smc_info->state = state;
}

static inline int smc_get_state(SMCInfo *smc_info)
{
    return smc_info->state;
}
#endif
