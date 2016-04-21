#include <stdint.h>
#include <glib.h>
#include <memory.h>
#include <inttypes.h>

#include "qemu/bitmap.h"
#include "smc.h"
#include "smc-debug.h"
#include "jhash.h"

#define SMC_SET_INIT_CAP    256

SMCInfo glo_smc_info;

#define min(x,y) ((x) < (y) ? (x) : (y))
#define max(x,y) ((x) > (y) ? (x) : (y))

static void smc_set_init(SMCSet *smc_set, int ele_size)
{
    smc_set->cap = SMC_SET_INIT_CAP;
    smc_set->ele_size = ele_size;
    smc_set->eles = (uint8_t *)g_malloc0(smc_set->cap * smc_set->ele_size);
    smc_set->nb_eles = 0;
}

static void smc_set_free(SMCSet *smc_set)
{
    if (smc_set->eles) {
        g_free(smc_set->eles);
    }
    smc_set->eles = NULL;
    smc_set->cap = smc_set->nb_eles = smc_set->ele_size = 0;
}

static void smc_set_reset(SMCSet *smc_set)
{
    smc_set->nb_eles = 0;
}

static void smc_set_resize(SMCSet *smc_set, int new_cap)
{
    uint8_t *data;

    SMC_ASSERT(new_cap > smc_set->cap);
    data = (uint8_t *)g_malloc0(new_cap * smc_set->ele_size);
    if (smc_set->nb_eles > 0) {
        memcpy(data, smc_set->eles, min(smc_set->nb_eles, new_cap) *
               smc_set->ele_size);
    }
    g_free(smc_set->eles);
    smc_set->eles = data;
    smc_set->cap = new_cap;
    smc_set->nb_eles = min(smc_set->nb_eles, new_cap);
}

static void *smc_set_insert(SMCSet *smc_set, const void *ele)
{
    uint8_t *new_ele;

    if (smc_set->cap == smc_set->nb_eles) {
        smc_set_resize(smc_set, smc_set->cap + SMC_SET_INIT_CAP);
    }

    new_ele = smc_set->eles + smc_set->nb_eles * smc_set->ele_size;
    memcpy(new_ele, ele, smc_set->ele_size);
    smc_set->nb_eles++;

    return new_ele;
}

static void *smc_set_get_idx(SMCSet *smc_set, int idx)
{
    if (idx >= smc_set->nb_eles || idx < 0) {
        return NULL;
    }
    return smc_set->eles + idx * smc_set->ele_size;
}

static void smc_set_insert_from_buf(SMCSet *smc_set, const void *buf,
                                    int nb_eles)
{
    int new_cap = smc_set->cap;

    if (new_cap - smc_set->nb_eles < nb_eles) {
        do {
            new_cap += SMC_SET_INIT_CAP;
        } while (new_cap - smc_set->nb_eles < nb_eles);
        smc_set_resize(smc_set, new_cap);
    }

    memcpy(smc_set->eles + smc_set->nb_eles * smc_set->ele_size, buf,
           nb_eles * smc_set->ele_size);
    smc_set->nb_eles += nb_eles;
}

void smc_init(SMCInfo *smc_info, void *opaque)
{
    SMC_LOG(INIT, "");
    SMC_ASSERT(!smc_info->init);
    memset(smc_info, 0, sizeof(*smc_info));
    smc_set_init(&smc_info->dirty_pages, sizeof(SMCDirtyPage));
    smc_set_init(&smc_info->prefetch_pages, sizeof(SMCFetchPage));
    smc_set_init(&smc_info->backup_pages, sizeof(SMCBackupPage));
    smc_info->prefetch_bm = bitmap_new(SMC_MAX_PREFETCH_PAGES);
    bitmap_clear(smc_info->prefetch_bm, 0, SMC_MAX_PREFETCH_PAGES);
    smc_info->prefetch_map = g_hash_table_new(g_direct_hash, g_direct_equal);
    smc_info->opaque = opaque;
    smc_cache_init(&smc_info->cache, SMC_FETCH_CACHE_CAP);
    smc_info->init = true;
}

void smc_exit(SMCInfo *smc_info)
{
    SMC_LOG(INIT, "");
    SMC_ASSERT(smc_info->init);
    smc_set_free(&smc_info->dirty_pages);
    smc_set_free(&smc_info->prefetch_pages);
    smc_backup_pages_reset(smc_info);
    smc_set_free(&smc_info->backup_pages);
    g_free(smc_info->prefetch_bm);
    g_hash_table_destroy(smc_info->prefetch_map);
    smc_info->prefetch_bm = NULL;
    smc_cache_exit(&smc_info->cache);
    smc_info->init = false;
}

void smc_dirty_pages_insert(SMCInfo *smc_info, uint64_t block_offset,
                            uint64_t offset, uint32_t size, uint32_t flags)
{
    SMCDirtyPage page = { .block_offset = block_offset,
                          .offset = offset,
                          .size = size,
                          .flags = flags,
                        };

    SMC_ASSERT(smc_info->init);
    SMC_LOG(GEN, "add block_offset=%" PRIu64 " offset=%" PRIu64
            " size=%" PRIu32 " flags=%" PRIu32, block_offset, offset, size,
            flags);
    smc_set_insert(&smc_info->dirty_pages, &page);
}

void smc_dirty_pages_reset(SMCInfo *smc_info)
{
    SMC_LOG(GEN, "dirty_pages=%d", smc_info->dirty_pages.nb_eles);
    SMC_ASSERT(smc_info->init);
    smc_set_reset(&smc_info->dirty_pages);
}

void smc_dirty_pages_insert_from_buf(SMCInfo *smc_info, const void *buf,
                                     int nb_pages)
{
    SMC_LOG(GEN, "copy %d dirty pages info", nb_pages);
    SMC_ASSERT(smc_info->init);
    smc_set_insert_from_buf(&smc_info->dirty_pages, buf, nb_pages);
}

void smc_prefetch_pages_insert_from_buf(SMCInfo *smc_info, const void *buf,
                                        int nb_pages)
{
    SMC_LOG(GEN, "copy %d prefetched pages info", nb_pages);
    SMC_ASSERT(smc_info->init);
    smc_set_insert_from_buf(&smc_info->prefetch_pages, buf, nb_pages);
}

SMCFetchPage *smc_prefetch_pages_insert(SMCInfo *smc_info,
                                        uint64_t block_offset,
                                        uint64_t offset, uint32_t size,
                                        SMC_HASH hash)
{
    SMCFetchPage page  = { .block_offset = block_offset,
                           .offset = offset,
                           .size = size,
                           .hash = hash,
                           .idx = smc_info->prefetch_pages.nb_eles,
                         };

    SMC_ASSERT(smc_info->init);
    SMC_LOG(GEN, "add block_offset=%" PRIu64 " offset=%" PRIu64
            " size=%" PRIu32, block_offset, offset, size);
    return (SMCFetchPage *)smc_set_insert(&smc_info->prefetch_pages, &page);
}

void smc_prefetch_pages_reset(SMCInfo *smc_info)
{
    SMC_LOG(GEN, "prefetch_pages=%d", smc_info->prefetch_pages.nb_eles);
    SMC_ASSERT(smc_info->init);
    smc_set_reset(&smc_info->prefetch_pages);
}

void smc_backup_pages_reset(SMCInfo *smc_info)
{
    SMCBackupPage *page = (SMCBackupPage *)(smc_info->backup_pages.eles);
    int nb_pages = smc_info->backup_pages.nb_eles;
    int i;

    SMC_LOG(GEN, "backup_pages=%d", nb_pages);
    SMC_ASSERT(smc_info->init);
    for (i = 0; i < nb_pages; ++i) {
        g_free(page->data);
        page->data = NULL;
        page++;
    }
    smc_set_reset(&smc_info->backup_pages);
}

void smc_backup_pages_insert(SMCInfo *smc_info, uint64_t block_offset,
                             uint64_t offset, uint64_t size,
                             uint8_t *data)
{
    SMCBackupPage page = { .block_offset = block_offset,
                           .offset = offset,
                           .size = size,
                           .host_addr = data,
                         };
    SMC_ASSERT(smc_info->init);
    SMC_LOG(GEN, "add block_offset=%" PRIu64 " offset=%" PRIu64
            " size=%" PRIu64, block_offset, offset, size);
    page.data = (uint8_t *)g_malloc(size);
    memcpy(page.data, data, size);
    smc_set_insert(&smc_info->backup_pages, &page);
}

/* Do not copy page content */
void *smc_backup_pages_insert_empty(SMCInfo *smc_info, uint64_t block_offset,
                                    uint64_t offset, uint64_t size,
                                    uint8_t *host_addr)
{
    SMCBackupPage page = { .block_offset = block_offset,
                           .offset = offset,
                           .size = size,
                           .host_addr = host_addr,
                         };
    SMC_ASSERT(smc_info->init);
    SMC_LOG(GEN, "add block_offset=%" PRIu64 " offset=%" PRIu64
            " size=%" PRIu64, block_offset, offset, size);
    page.data = (uint8_t *)g_malloc(size);
    smc_set_insert(&smc_info->backup_pages, &page);
    return page.data;
}

void smc_prefetch_page_cal_hash(SMCInfo *smc_info, int index)
{
    SMCFetchPage *fetch_page;
    uint8_t *data;

    fetch_page = (SMCFetchPage *)smc_set_get_idx(&smc_info->prefetch_pages,
                                                 index);
    SMC_ASSERT(fetch_page && (fetch_page->idx == index));
    data = smc_host_addr_from_offset(smc_info->opaque, fetch_page->block_offset,
                                     fetch_page->offset);
    fetch_page->hash = jhash2((uint32_t *)data, fetch_page->size / 4,
                              SMC_JHASH_INIT_VAL);
    SMC_LOG(FETCH, "fetch_page idx=%d hash=%" PRIu32, index, fetch_page->hash);
}

void smc_recover_backup_pages(SMCInfo *smc_info)
{
    SMCBackupPage *page = (SMCBackupPage *)(smc_info->backup_pages.eles);
    int nb_pages = smc_info->backup_pages.nb_eles;
    int i;

    SMC_LOG(GEN, "backup_pages=%d", nb_pages);
    for (i = 0; i < nb_pages; ++i) {
        memcpy(page->host_addr, page->data, page->size);
        g_free(page->data);
        page->data = NULL;
        page++;
    }

    smc_info->backup_pages.nb_eles = 0;
}

void smc_rollback_with_prefetch(SMCInfo *smc_info)
{
    switch (smc_info->state) {
    case SMC_STATE_TRANSACTION_START:
    case SMC_STATE_PREFETCH_START:
    case SMC_STATE_PREFETCH_DONE:
        SMC_LOG(GEN, "rollback with state=%d", smc_info->state);
        smc_recover_backup_pages(smc_info);
        break;

    case SMC_STATE_PREFETCH_ABANDON:
        SMC_ERR("rollback with state=%s","SMC_STATE_PREFETCH_ABANDON");
        break;

    case SMC_STATE_RECV_CHECKPOINT:
        SMC_LOG(GEN, "rollback with state=%s","SMC_STATE_RECV_CHECKPOINT");
        break;

    default:
        SMC_ERR("rollback with unknown state=%d", smc_info->state);
        break;
    }

    smc_prefetch_pages_reset(smc_info);
    smc_backup_pages_reset(smc_info);
    smc_prefetch_map_reset(smc_info);
}

bool smc_loadvm_need_check_prefetch(SMCInfo *smc_info)
{
    if (!smc_info->init) {
        return false;
    }
    if ((smc_info->state == SMC_STATE_PREFETCH_DONE) &&
        !smc_info->need_rollback) {
        return true;
    }
    return false;
}

/* Check if a given page is in the prefetched pages and their contents are
 * identical.
 */
bool smc_check_dirty_page(SMCInfo *smc_info, uint64_t block_offset,
                          uint64_t offset, uint64_t size, SMC_HASH hash_val)
{
    SMCFetchPage *page;
    bool ret = false;

    page = smc_prefetch_map_lookup(smc_info, block_offset + offset);
    if (page) {
        SMC_ASSERT((page->block_offset == block_offset) &&
                   (page->offset == offset) && (page->size == size));

        ret = (page->hash == hash_val);

        SMC_LOG(FETCH, "block_offset=%" PRIu64 " offset=%" PRIu64
                " fetch_hash=%" PRIu32 " cur_hash=%" PRIu32 " same=%d",
                block_offset, offset, page->hash, hash_val, ret);
    }
    return ret;
}

void smc_prefetch_map_gen_from_pages(SMCInfo *smc_info)
{
    SMCFetchPage *page = (SMCFetchPage *)(smc_info->prefetch_pages.eles);
    int nb_pages = smc_info->prefetch_pages.nb_eles;
    int i;

    for (i = 0; i < nb_pages; ++i) {
        smc_prefetch_map_insert(smc_info, page->block_offset + page->offset,
                                page);
        page++;
    }
    SMC_LOG(FETCH, "add %d items in prefetch map", nb_pages);
}

#define SMC_NUM_PRESERVE_PREFETCH_HIT   500
#define SMC_TARGET_PAGE_SIZE            4096
#define SMC_NUM_DIRTY_PAGES_PREFETCH    20000

typedef struct SMCItem {
    uint64_t block_offset;
    uint64_t offset;
} SMCItem;

void smc_update_prefetch_cache(SMCInfo *smc_info)
{
    SMCCache *cache = &smc_info->cache;
    SMCDirtyPage *dirty_page = smc_dirty_pages_info(smc_info);
    int nr_pages = min(smc_dirty_pages_count(smc_info),
                       SMC_NUM_DIRTY_PAGES_PREFETCH);
    SMCItem hits[SMC_NUM_PRESERVE_PREFETCH_HIT];
    int i, nr_hits;
    uint64_t in_checkpoint = smc_info->nr_checkpoints;
    SMC_LOG(FETCH, "update SMCCache according to dirty_pages");

    for (i = 0, nr_hits = 0; i < nr_pages; ++i) {
        SMC_ASSERT(dirty_page->size == SMC_TARGET_PAGE_SIZE);
        if (dirty_page->flags & SMC_DIRTY_FLAGS_IN_CHECKPOINT) {
            /* This page is in checkpoint */
            smc_cache_update(cache, dirty_page->block_offset,
                             dirty_page->offset, 0, in_checkpoint);
        } else {
            /* Valid prefetch in previous checkpoint */
            if (nr_hits < SMC_NUM_PRESERVE_PREFETCH_HIT) {
                hits[nr_hits].block_offset = dirty_page->block_offset;
                hits[nr_hits].offset = dirty_page->offset;
                ++nr_hits;
            } else {
                smc_cache_update(cache, dirty_page->block_offset,
                                 dirty_page->offset, 0, 0);
            }
        }
        ++dirty_page;
    }

    /* We put valid prefetched pages in front of the cache in order to fetch
     * them first.
     */
    for (i = 0; i < nr_hits; ++i) {
        smc_cache_update(cache, hits[i].block_offset, hits[i].offset, 0, 0);
    }
}
