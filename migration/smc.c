#include <stdint.h>
#include <glib.h>
#include <memory.h>
#include <inttypes.h>

#include "qemu/bitmap.h"
#include "smc.h"
#include "smc-debug.h"
#include "jhash.h"

#define SMC_SET_INIT_CAP        40960
#define SMC_SUPERSET_INIT_CAP   20

SMCInfo glo_smc_info;

#define min(x,y) ((x) < (y) ? (x) : (y))
#define max(x,y) ((x) > (y) ? (x) : (y))

static void smc_set_init(SMCSet *smc_set, int ele_size)
{
    smc_set->cap = SMC_SET_INIT_CAP;
    smc_set->ele_size = ele_size;
    /* I am lazy.. Just allocate 2 more bytes for every SMCSet. I think it's OK 
     * except wasting a little memory.
     */
    smc_set->eles = (uint8_t *)g_malloc0(smc_set->cap * smc_set->ele_size + 2);
    smc_set->nb_eles = 0;
}

static void smc_pure_set_init(SMCSet *smc_set, int ele_size)
{
    smc_set->cap = SMC_SET_INIT_CAP;
    smc_set->ele_size = ele_size;
    /* donot alloc 2 more bytes when it is not asked to.
     */
    smc_set->eles = (uint8_t *)g_malloc0(smc_set->cap * smc_set->ele_size);
    smc_set->nb_eles = 0;
}

static void smc_superset_init(SMCSuperSet *smc_superset, 
                                int subset_ele_size)
{
    int i;
    SMCSet *subset;
    
    smc_superset->cap = SMC_SUPERSET_INIT_CAP;
    smc_superset->nb_subsets = 0;
    smc_superset->subsets = (uint8_t *)g_malloc0(smc_superset->cap *
                                sizeof(SMCSet));
    for (i = 0; i < smc_superset->cap; i++) {
        subset = (SMCSet *)(smc_superset->subsets + i * sizeof(SMCSet));
        smc_set_init(subset, subset_ele_size);
    }    
}

#ifdef DEBUG_SMC
void smc_debug_print_pml_prefetch_pages(SMCInfo *smc_info)
{
    SMCSuperSet *smc_superset = &(smc_info->pml_prefetch_pages);
    SMCSet *subset;
    for (int i = 0; i <= smc_superset->nb_subsets; ++i)
    {
        subset = (SMCSet *)(smc_superset->subsets + i * sizeof(SMCSet));
        SMC_LOG(CORE_DUMP, "the %dth subset's eles begins at address %p, the HEAD_IDX is %d", 
                    i, subset->eles, *((uint16_t *)(subset->eles)));
    }    
}
#else
void smc_debug_print_pml_prefetch_pages(SMCInfo *smc_info)
{}
#endif

static void smc_set_free(SMCSet *smc_set)
{
    if (smc_set->eles) {
        printf("********** try to free the smc_set->eles:%p **********\n", smc_set->eles);
        SMC_LOG(CORE_DUMP, "********** try to free the smc_set->eles:%p **********\n", smc_set->eles);
        g_free(smc_set->eles);
        printf("********** the smc_set->eles freed **********\n");
    }
    smc_set->eles = NULL;
    smc_set->cap = smc_set->nb_eles = smc_set->ele_size = 0;
}

static void smc_superset_free(SMCSuperSet *smc_superset)
{
    SMCSet *subset;
    int i;
    
    for (i = 0; i < smc_superset->cap; i++) {
        subset = (SMCSet *) (smc_superset->subsets + 
                 i * sizeof(SMCSet));
        if (subset) {
            printf("********** try to free the %dth subset in smc_info->pml_prefetch_pages **********\n"
                        , i);
            smc_set_free(subset);
            printf("********** the %dth subset in smc_info->pml_prefetch_pages freed **********\n"
                        , i);
        }
    }
    if (smc_superset->subsets) {
        printf("********** try to free smc_info->pml_prefetch_pages.subsets **********\n");
        g_free(smc_superset->subsets);
        printf("********** smc_info->pml_prefetch_pages.subsets freed **********\n");
    }
    smc_superset->nb_subsets = 0;
    smc_superset->cap = 0;
}

static void smc_set_reset(SMCSet *smc_set)
{
    smc_set->nb_eles = 0;
}

static void smc_superset_reset(SMCSuperSet *smc_superset)
{
    SMCSet *subset;
    int i;
    
    for (i = 0; i < smc_superset->cap; i++) {
        subset = (SMCSet *) (smc_superset->subsets + 
                 i * sizeof(SMCSet));
        if (subset) {
            smc_set_reset(subset);
        }
    }
    smc_superset->nb_subsets = 0;
}

static void smc_set_resize(SMCSet *smc_set, int new_cap)
{
    uint8_t *data;

    SMC_ASSERT(new_cap > smc_set->cap);
    data = (uint8_t *)g_malloc0(new_cap * smc_set->ele_size);
    /* At this time we have not sort the linked list yet, so we remain 
     * the first 2 bytes 0.
     */
    if (smc_set->nb_eles > 0) {
        memcpy(data + 2, (smc_set->eles) + 2, min(smc_set->nb_eles, new_cap) *
               smc_set->ele_size);
    }
    g_free(smc_set->eles);
    smc_set->eles = data;
    smc_set->cap = new_cap;
    smc_set->nb_eles = min(smc_set->nb_eles, new_cap);
}

static void smc_superset_resize(SMCSuperSet *smc_superset, int new_cap)
{
    uint8_t *data;
    SMCSet *old_subset, *new_subset;
    int i;

    SMC_ASSERT(new_cap <= SMC_PML_PREFETCH_ROUND_LIMIT);
    SMC_ASSERT(new_cap > smc_superset->cap);
    data = (uint8_t *)g_malloc0(new_cap * sizeof(SMCSet));
    for (i = 0; i < new_cap; i++) {
        new_subset = (SMCSet *)(data + i * sizeof(SMCSet));
        old_subset = (SMCSet *)(smc_superset->subsets);
        smc_set_init(new_subset, old_subset->ele_size);
        if (i < smc_superset->nb_subsets) {
            old_subset = (SMCSet *)(smc_superset->subsets + i * sizeof(SMCSet));
            if (old_subset->cap > new_subset->cap) {
                smc_set_resize(new_subset, old_subset->cap);
            }
            memcpy(new_subset->eles, old_subset->eles, 
                  old_subset->nb_eles * old_subset->ele_size + 2);
            new_subset->ele_size = old_subset->ele_size;
            new_subset->nb_eles = old_subset->nb_eles;
        }
    }
    smc_superset->cap = new_cap;
    smc_superset->subsets = data;
}

static void *smc_superset_get_idex(SMCSuperSet *smc_superset, 
                                        int idx)
{
    if (idx > smc_superset->cap || idx < 0) {
        return NULL;
    }
    return smc_superset->subsets + idx * sizeof(SMCSet);
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
    SMC_LOG(GEN, "after insert, there are %d pages in total", smc_set->nb_eles);

    return new_ele;
}

static void *smc_set_get_idx(SMCSet *smc_set, int idx)
{
    if (idx >= smc_set->nb_eles || idx < 0) {
        return NULL;
    }
    return smc_set->eles + idx * smc_set->ele_size;
}

/* This function is used if different places, we cannot modify it.*/
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

static void smc_prefetch_set_insert_from_buf(SMCSet *smc_set, const void *buf,
                                    int nb_eles)
{
    int new_cap = smc_set->cap;

    if (new_cap < nb_eles) {
        do {
            new_cap += SMC_SET_INIT_CAP;
        } while (new_cap - smc_set->nb_eles < nb_eles);
        smc_set_resize(smc_set, new_cap);
    }

    memcpy(smc_set->eles, buf, nb_eles * smc_set->ele_size + 2);
    smc_set->nb_eles = nb_eles;
}

/* This function is only used when the backup end receive prefetch info, so we 
 * directly modify it.
 * According to the functions that call smc_superset_insert_from_buf finally, 
 * here the subset is empty now, so something reflecting this feature will appear 
 * in smc_prefetch_set_insert_from_buf.
 */
static void smc_superset_insert_from_buf(SMCSuperSet *smc_superset,
                                    int subset_idx, const void *buf, int nb_eles)
{
    SMCSet *subset;

    subset = (SMCSet *)smc_superset_get_idex(smc_superset, subset_idx);
    smc_prefetch_set_insert_from_buf(subset, buf, nb_eles);
}

void smc_init(SMCInfo *smc_info, void *opaque)
{
    SMC_LOG(INIT, "");
    SMC_ASSERT(!smc_info->init);
    memset(smc_info, 0, sizeof(*smc_info));
#ifdef SMC_PREFETCH
    smc_set_init(&smc_info->dirty_pages, sizeof(SMCDirtyPage));
    smc_set_init(&smc_info->prefetch_pages, sizeof(SMCFetchPage));
    smc_set_init(&smc_info->backup_pages, sizeof(SMCBackupPage));
    smc_info->prefetch_map = g_hash_table_new(g_direct_hash, g_direct_equal);
    smc_cache_init(&smc_info->cache);
#endif
#ifdef SMC_PML_PREFETCH
    smc_superset_init(&smc_info->pml_prefetch_pages, sizeof(SMCPMLPrefetchPage));

    SMC_LOG(CORE_DUMP, "\n\n\n\n         ~~~~~ After init ~~~~~");
    smc_debug_print_pml_prefetch_pages(smc_info);

    smc_pure_set_init(&smc_info->pml_backup_pages, sizeof(SMCPMLBackupPage));
    
    smc_info->pml_prefetched_map = g_hash_table_new(g_direct_hash, g_direct_equal);
    smc_info->pml_total_prefetched_map = g_hash_table_new(g_direct_hash, g_direct_equal);
    smc_info->pml_xmit_speed = 0;
#endif
    smc_info->opaque = opaque;
    smc_info->init = true;
    smc_info->enable_incheckpoint_bitmap = false;
    //smc_info->need_clear_incheckpoint_bitmap = false;
#ifdef DEBUG_SMC
    smc_info->max_eles = 0;
    smc_info->nb_more_than_1000 = 0;
#endif
}

void smc_exit(SMCInfo *smc_info)
{
    printf("********** free begins **********\n");
    SMC_LOG(INIT, "");
    SMC_ASSERT(smc_info->init);
#ifdef SMC_PREFETCH
    smc_set_free(&smc_info->dirty_pages);
    smc_set_free(&smc_info->prefetch_pages);
    smc_backup_pages_reset(smc_info);
    smc_set_free(&smc_info->backup_pages);
    g_hash_table_destroy(smc_info->prefetch_map);
    smc_cache_exit(&smc_info->cache);
#endif
#ifdef SMC_PML_PREFETCH

    printf("********** try ro reset smc_info->pml_backup_pages **********\n");
    smc_pml_backup_pages_reset(smc_info);
    printf("********** smc_info->pml_backup_pages resetted **********\n");

    SMC_LOG(CORE_DUMP, "\n\n\n\n         ~~~~~ After reset smc_info->pml_backup_pages ~~~~~");
    smc_debug_print_pml_prefetch_pages(smc_info);


    printf("********** try to free smc_info->pml_backup_pages **********\n");
    smc_set_free(&smc_info->pml_backup_pages);
    printf("********** smc_info->pml_backup_pages freed **********\n");
    
    SMC_LOG(CORE_DUMP, "\n\n\n\n         ~~~~~ After free smc_info->pml_backup_pages ~~~~~");
    smc_debug_print_pml_prefetch_pages(smc_info);


    printf("********** try to destroy smc_info->pml_prefetched_map **********\n");
    g_hash_table_destroy(smc_info->pml_prefetched_map);
    printf("********** smc_info->pml_prefetched_map destroyed **********\n");
    
    SMC_LOG(CORE_DUMP, "\n\n\n\n         ~~~~~ After destroy smc_info->pml_prefetched_map ~~~~~");
    smc_debug_print_pml_prefetch_pages(smc_info);


    printf("********** try to destroy smc_info->pml_total_prefetched_map **********\n");
    g_hash_table_destroy(smc_info->pml_total_prefetched_map);
    printf("********** smc_info->pml_total_prefetched_map destroyed **********\n");
    
    SMC_LOG(CORE_DUMP, "\n\n\n\n         ~~~~~ After destroy smc_info->pml_total_prefetched_map ~~~~~");
    smc_debug_print_pml_prefetch_pages(smc_info);

    printf("********** try to free smc_info->pml_prefetch_pages **********\n");
    smc_superset_free(&smc_info->pml_prefetch_pages);
    printf("********** smc_info->pml_prefetch_pages freed **********\n");

#endif
    smc_info->init = false;
    smc_info->enable_incheckpoint_bitmap = false;
    //smc_info->need_clear_incheckpoint_bitmap = false;
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

void smc_pml_unsort_prefetch_pages_insert(SMCInfo *smc_info,
                                            uint64_t block_offset,
                                            uint64_t offset, 
                                            bool in_checkpoint, 
                                            uint32_t size, int subset_idx)
{
    /*
    SMCPMLPrefetchPage page = { .block_offset = block_offset,
                                .offset = offset,
                                .size = size,
                                .next = SMC_MAX_PREFETCH_OFFSET,
                                .in_checkpoint = in_checkpoint,
                              };
    */
    SMC_ASSERT(smc_info->init);
    /*SMC_LOG(GEN, "add into pml_unsort_prefetch_pages which block_offset=%" PRIu64 
            " offset=%" PRIu64 " size=%" PRIu32 " in_checkpoint=%d subset_idx=%d", 
            block_offset, offset, size, in_checkpoint, subset_idx);*/
    SMCSet *subset;
    uint8_t *new_ele;

    subset = (SMCSet *)smc_superset_get_idex(&smc_info->pml_prefetch_pages, subset_idx);

    if (subset->cap == subset->nb_eles) {
        smc_set_resize(subset, subset->cap + SMC_SET_INIT_CAP);
    }
    //SMC_LOG(SORT, "before insert, there are %d pages in total", subset->nb_eles);
    new_ele = subset->eles + 2 + subset->nb_eles * subset->ele_size;
    subset->nb_eles++;
    /* If we really prefetch 65535 pages, we cannot deal with them yet.*/
    if (subset->nb_eles == SMC_MAX_PREFETCH_OFFSET) {
        SMC_ERR("We prefetch too many dirty pages to deal with.");
    }
    /* Init the structure here, so we reduce some memory copy.*/
    ((SMCPMLPrefetchPage *)new_ele)->block_offset = block_offset;
    ((SMCPMLPrefetchPage *)new_ele)->offset = offset;
    ((SMCPMLPrefetchPage *)new_ele)->size = size;
    /* The next region stores next slot's index.*/
    ((SMCPMLPrefetchPage *)new_ele)->next = subset->nb_eles;
    ((SMCPMLPrefetchPage *)new_ele)->in_checkpoint = in_checkpoint;
    /* SMC_LOG(SORT, "after insert, there are %d pages in total", subset->nb_eles);*/
}

/* Use merge sort to sort the SMCPMLPrefetchPage array, but we regard it as a linked list.*/
void smc_pml_sort_prefetch_pages(SMCInfo *smc_info)
{
    SMCSet *subset;
    uint8_t *eles;
    uint16_t *p_head_idx;
    uint16_t first_idx, second_idx;
    uint32_t interval = 1;
    SMCPMLPrefetchPage temp;
    SMCPMLPrefetchPage *pre;
    SMCPMLPrefetchPage *pages;
    SMCPMLPrefetchPage *last_ele;

    /* Declare temp variables used in the loop here.*/
    uint32_t i;
    //uint16_t si;
    uint32_t fvisit = 0, svisit = 0;
    uint64_t block_offset1, block_offset2;
    uint64_t offset1, offset2;
    uint32_t total_dirty_times1, total_dirty_times2;
    temp.next = 0;

    subset = (SMCSet *)smc_superset_get_idex(&(smc_info->pml_prefetch_pages), 
                        smc_info->pml_prefetch_pages.nb_subsets);

    eles = subset->eles;
    p_head_idx = (uint16_t *)eles;
    pages = (SMCPMLPrefetchPage *)(eles + 2);

    /* bug fix: if there are no dirty pages, we donot need to sort.*/
    if (subset->nb_eles == 0) {
        *p_head_idx = SMC_MAX_PREFETCH_OFFSET;
        return;
    }

    // /* Make the last element's next region "points to NULL"*/
    last_ele = (SMCPMLPrefetchPage *)(subset->eles + 2 +
                                     (subset->nb_eles - 1) * subset->ele_size);
    last_ele->next = SMC_MAX_PREFETCH_OFFSET;
    if (subset->nb_eles == 0)
    {
        printf("!!!!!!!!!!!!!!!!!!!!%d!!!!!!!!!!!!!\n", subset->nb_eles - 1);
    }

    /*    
    for (i = 0; i < subset->nb_eles; ++i) {
        SMC_LOG(SORT, "Before sort, the %uth page to prefetch points to %uth.", i, pages[i].next);
    }
    */
    // Merge Sort begins.
    for (; interval <= subset->nb_eles; interval *= 2) {
        pre = &temp;
        first_idx = pre->next;
        second_idx = pre->next;

        while (first_idx != SMC_MAX_PREFETCH_OFFSET || second_idx != SMC_MAX_PREFETCH_OFFSET) {
            i = 0;
            while (i < interval && second_idx != SMC_MAX_PREFETCH_OFFSET) {
                second_idx = pages[second_idx].next;
                i++;
            }
            fvisit = 0, svisit = 0;
            while (fvisit < interval && svisit < interval && 
                    first_idx != SMC_MAX_PREFETCH_OFFSET && second_idx != SMC_MAX_PREFETCH_OFFSET) {
                block_offset1 = pages[first_idx].block_offset;
                offset1 = pages[first_idx].offset;
                block_offset2 = pages[second_idx].block_offset;
                offset2 = pages[second_idx].offset;
                total_dirty_times1 = smc_pml_total_prefetched_map_lookup(&glo_smc_info,
                                                                  block_offset1 + offset1);
                total_dirty_times2 = smc_pml_total_prefetched_map_lookup(&glo_smc_info,
                                                                  block_offset2 + offset2);
                if (total_dirty_times1 < total_dirty_times2) {
                    pre->next = first_idx;
                    pre = &(pages[first_idx]);
                    first_idx = pages[first_idx].next;
                    fvisit++;
                } else {
                    pre->next = second_idx;
                    pre = &(pages[second_idx]);
                    second_idx = pages[second_idx].next;
                    svisit++;
                }
            }
            while (fvisit < interval && first_idx != SMC_MAX_PREFETCH_OFFSET) {
                pre->next = first_idx;
                pre = &(pages[first_idx]);
                first_idx = pages[first_idx].next;
                fvisit++;
            }
            while (svisit < interval && second_idx != SMC_MAX_PREFETCH_OFFSET) {
                pre->next = second_idx;
                pre = &(pages[second_idx]);
                second_idx = pages[second_idx].next;
                svisit++;
            }
            pre->next = second_idx;
            first_idx = second_idx;
        }
    }
    
    *p_head_idx = temp.next;

    if (subset->nb_eles > smc_info->max_eles) {
        smc_info->max_eles = subset->nb_eles;
    }
    if (subset->nb_eles > 1000) {
        smc_info->nb_more_than_1000++;
    }

    SMC_LOG(BAK_DEAD, "In the %dth subset, there are %d dirty pages, max is %d, more than 1000 dirty pages for %d times.", 
                    smc_info->pml_prefetch_pages.nb_subsets, subset->nb_eles, smc_info->max_eles, smc_info->nb_more_than_1000);
// #ifdef DEBUG_SMC
//     SMC_LOG(CORE_DUMP, "\n\n\n\n         ~~~~~ After sort the pages in pml_prefetch_pages ~~~~~");
//     smc_debug_print_pml_prefetch_pages(&glo_smc_info);
// #endif    
    /*
    si = *p_head_idx;
    i = 0;
    while (si != SMC_MAX_PREFETCH_OFFSET && i < subset->nb_eles) {
        block_offset1 = pages[si].block_offset;
        offset1 = pages[si].offset;
        total_dirty_times1 = smc_pml_total_prefetched_map_lookup(&glo_smc_info,
                                                                  block_offset1 + offset1);
        SMC_LOG(TEST_SORT, "After sort, the %uth page is dirty for %u times, and points to %uth page.", 
                            si, total_dirty_times1, pages[si].next);
        si = pages[si].next;
        i++;
    }
    */
    
    
}

void smc_dirty_pages_reset(SMCInfo *smc_info)
{
    SMC_LOG(GEN, "dirty_pages=%d", smc_info->dirty_pages.nb_eles);
    SMC_ASSERT(smc_info->init);
    smc_set_reset(&smc_info->dirty_pages);
}

void smc_pml_prefetch_pages_reset(SMCInfo *smc_info)
{
    SMC_ASSERT(smc_info->init);
    smc_superset_reset(&smc_info->pml_prefetch_pages);
    SMC_LOG(GEN, "after reset pml_prefetch_pages subset=%d", 
                smc_info->pml_prefetch_pages.nb_subsets);
    SMC_LOG(CORE_DUMP, "\n\n\n\n         ~~~~~ After reset pml_prefetch_pages ~~~~~");
    smc_debug_print_pml_prefetch_pages(smc_info);

}

void smc_dirty_pages_insert_from_buf(SMCInfo *smc_info, const void *buf,
                                     int nb_pages)
{
    SMC_LOG(GEN, "copy %d dirty pages info", nb_pages);
    SMC_ASSERT(smc_info->init);
    smc_set_insert_from_buf(&smc_info->dirty_pages, buf, nb_pages);
}

void smc_pml_prefetch_pages_insert_from_buf(SMCInfo *smc_info, 
                                     const void *buf, int nb_pages)
{
    SMC_LOG(GEN, "copy %d prefetch pages info into pml_prefetch_pages", nb_pages);
    SMC_ASSERT(smc_info->init);
    smc_superset_insert_from_buf(&smc_info->pml_prefetch_pages, 
                                 smc_info->pml_prefetch_pages.nb_subsets, 
                                 buf, nb_pages);
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
    SMC_LOG(GEN, "prefetch_pages subset=%d", smc_info->prefetch_pages.nb_eles);
    SMC_ASSERT(smc_info->init);
    smc_set_reset(&smc_info->prefetch_pages);
}

void smc_pml_prefetch_pages_next_subset(SMCInfo *smc_info)
{
    SMC_LOG(GEN, "prefetch_pages subset=%d", 
            smc_info->pml_prefetch_pages.nb_subsets);
    SMC_ASSERT(smc_info->init);
    smc_info->pml_prefetch_pages.nb_subsets++;
    if (smc_info->pml_prefetch_pages.nb_subsets >= smc_info->pml_prefetch_pages.cap) {
        smc_superset_resize(&smc_info->pml_prefetch_pages, 
                            smc_info->pml_prefetch_pages.nb_subsets + 1);
    }
    SMC_LOG(GEN, "prefetch_pages new subset=%d", 
            smc_info->pml_prefetch_pages.nb_subsets);
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

void smc_pml_backup_pages_reset(SMCInfo *smc_info)
{
    SMCPMLBackupPage *page = (SMCPMLBackupPage *)(smc_info->pml_backup_pages.eles);
    int nb_pages = smc_info->pml_backup_pages.nb_eles;
    int i;

    SMC_LOG(SORT, "pml_backup_pages=%d", nb_pages);
    SMC_ASSERT(smc_info->init);
    for (i = 0; i < nb_pages; ++i) {
        g_free(page->data);
        page->data = NULL;
        page++;
    }
    smc_set_reset(&smc_info->pml_backup_pages);
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

void smc_pml_backup_pages_insert(SMCInfo *smc_info, uint64_t block_offset,
                             uint64_t offset, uint64_t size,
                             uint8_t *data)
{
    SMCPMLBackupPage page = { .block_offset = block_offset,
                              .offset = offset,
                              .size = size,
                              .host_addr = data,
                            };
    SMC_ASSERT(smc_info->init);
    SMC_LOG(GEN, "add block_offset=%" PRIu64 " offset=%" PRIu64
            " size=%" PRIu64, block_offset, offset, size);
    page.data = (uint8_t *)g_malloc(size);
    memcpy(page.data, data, size);
    smc_set_insert(&smc_info->pml_backup_pages, &page);
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

/* Do not copy page content */
void *smc_pml_backup_pages_insert_empty(SMCInfo *smc_info, 
                                    uint64_t block_offset, uint64_t offset, 
                                    uint64_t size, uint8_t *host_addr)
{
    SMCPMLBackupPage page = { .block_offset = block_offset,
                              .offset = offset,
                              .size = size,
                              .host_addr = host_addr,
                            };
    SMC_ASSERT(smc_info->init);
    SMC_LOG(GEN, "add backup_page block_offset=%" PRIu64 " offset=%" PRIu64
            " size=%" PRIu64, block_offset, offset, size);
    page.data = (uint8_t *)g_malloc(size);
    smc_set_insert(&smc_info->pml_backup_pages, &page);
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

void smc_pml_recover_backup_pages(SMCInfo *smc_info)
{
    SMCPMLBackupPage *page = 
                (SMCPMLBackupPage *)(smc_info->pml_backup_pages.eles);
    int nb_pages = smc_info->pml_backup_pages.nb_eles;
    int i;

    SMC_LOG(SIM, "pml_backup_pages=%d", nb_pages);
    for (i = 0; i < nb_pages; ++i) {
        //SMC_LOG(SIM, "page[%d]->host_addr=%" PRIu64 " offset=%" PRIu64 
        //        " size=%" PRIu64, i, page->host_addr, page->offset, page->size);
        memcpy(page->host_addr, page->data, page->size);
        g_free(page->data);
        page->data = NULL;
        page++;
    }

    smc_info->pml_backup_pages.nb_eles = 0;
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

    smc_cache_stat(&smc_info->cache);
}

void smc_pml_rollback_with_prefetch(SMCInfo *smc_info)
{
    switch (smc_info->state) {
    case SMC_STATE_TRANSACTION_START:
    case SMC_STATE_PREFETCH_START:
    case SMC_STATE_PREFETCH_DONE:
        SMC_ERR("rollback with state=%d", smc_info->state);
        smc_pml_recover_backup_pages(smc_info);
        break;

    case SMC_STATE_PREFETCH_ABANDON:
        SMC_ERR("rollback with state=%s","SMC_STATE_PREFETCH_ABANDON");
        break;

    case SMC_STATE_RECV_CHECKPOINT:
        SMC_ERR("rollback with state=%s","SMC_STATE_RECV_CHECKPOINT");
        break;

    default:
        SMC_ERR("rollback with unknown state=%d", smc_info->state);
        break;
    }

    smc_pml_prefetch_pages_reset(smc_info);
    smc_pml_backup_pages_reset(smc_info);
    smc_pml_prefetched_map_reset(smc_info);
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

#define SMC_TARGET_PAGE_SIZE            4096
#define SMC_NUM_DIRTY_PAGES_PREFETCH    SMC_NUM_DIRTY_PAGES_SEND

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
    int i;
    uint64_t nr_checkpoints = smc_info->nr_checkpoints;
    uint64_t in_checkpoint;

    SMC_LOG(FETCH, "update SMCCache according to %d dirty_pages", nr_pages);
    for (i = 0; i < nr_pages; ++i) {
        SMC_ASSERT(dirty_page->size == SMC_TARGET_PAGE_SIZE);
        if (dirty_page->flags & SMC_DIRTY_FLAGS_IN_CHECKPOINT) {
            /* This page is in checkpoint */
            in_checkpoint = nr_checkpoints;
        } else {
            in_checkpoint = 0;
        }
        smc_cache_update(cache, dirty_page->block_offset, dirty_page->offset,
                         nr_checkpoints, in_checkpoint);
        ++dirty_page;
    }
}

uint8_t *smc_pml_prefetch_pages_info(SMCInfo *smc_info)
{
    SMCSet *subset;

    subset = (SMCSet *)smc_superset_get_idex(&smc_info->pml_prefetch_pages, 
                                   smc_info->pml_prefetch_pages.nb_subsets);
    return subset->eles;
}

/* Modify to suit for the linked-list subset->eles*/
SMCPMLPrefetchPage *smc_pml_prefetch_pages_get_idex(SMCInfo *smc_info,
                                             int superset_idx, int subset_idx)
{
    SMCSet *subset;
    SMCSuperSet *superset;
    SMCPMLPrefetchPage *pages;
    int cur_idx, idx = 0;

    superset = &smc_info->pml_prefetch_pages;
    SMC_ASSERT(superset_idx <= superset->nb_subsets);
    subset = (SMCSet *)smc_superset_get_idex(superset, superset_idx);
    SMC_ASSERT(subset_idx <= subset->nb_eles);

    pages = (SMCPMLPrefetchPage *)(subset->eles + 2);
    /* Get head's index.*/
    cur_idx = *((uint16_t *)(subset->eles));

    while(idx < subset_idx) {
        cur_idx = pages[cur_idx].next;
        idx++;
    }

    return pages + cur_idx;
}

int smc_pml_prefetch_pages_count(SMCInfo *smc_info, int superset_idx)
{
    SMCSet *subset;
    SMCSuperSet *superset;

    superset = &smc_info->pml_prefetch_pages;
    SMC_ASSERT(superset_idx <= superset->nb_subsets);
    subset = (SMCSet *)smc_superset_get_idex(superset, superset_idx);
    return subset->nb_eles;
}

/* persist all the unprefetched pages accroding the pml_round_prefetch_info[] */
int smc_pml_persist_unprefetched_pages(SMCInfo *smc_info)
{
    SMCSuperSet *superset = &(smc_info->pml_prefetch_pages);
    SMCSet *subset;
    SMCPMLPrefetchPage *pages;
    int nb_round = superset->nb_subsets;
    int superset_idx;
    int subset_idx;
    int16_t list_idx;
    SMCPMLPrefetchPage *unprefetched_page;

    for (superset_idx = 0; superset_idx < nb_round; superset_idx++) {
        subset = (SMCSet *)smc_superset_get_idex(superset, superset_idx);
        subset_idx = smc_info->pml_round_prefetch_info[superset_idx].nb_pages;
        pages = (SMCPMLPrefetchPage *)(subset->eles + 2);  
        /* Get head's index.*/      
        list_idx = *((uint16_t *)(subset->eles));
        
        if (subset->nb_eles > 0) {
            SMC_LOG(BAK_DEAD, "Round %d: should prefetch %d pages, but we prefetch %d"
                " pages actually, remains %d pages", superset_idx, subset->nb_eles,
                subset_idx, subset->nb_eles - subset_idx);
        }        

        while (subset_idx < subset->nb_eles) {
            unprefetched_page = pages + list_idx;
            list_idx = unprefetched_page->next;
            smc_pml_set_bitmap_through_offset(unprefetched_page->block_offset,
                                              unprefetched_page->offset);
            ++subset_idx;
        }
    }
    return 0;
}

uint64_t smc_pml_calculate_xmit_sleep_time(SMCInfo *smc_info, 
                                                       uint64_t remain_time)
{
    int nb_subsets = (smc_info->pml_prefetch_pages.nb_subsets - 1) < 0 ? 
                     0 : smc_info->pml_prefetch_pages.nb_subsets - 1;
    int nb_dirty_pages = smc_pml_prefetch_pages_count(smc_info, nb_subsets);
    uint64_t sleep_time;
    uint64_t min_prefetch_interval = (MC_DEFAULT_CHECKPOINT_FREQ_MS * 1000) / 
                     (SMC_PML_PREFETCH_ROUND + 1);

    sleep_time = nb_dirty_pages * smc_info->pml_xmit_speed;
    if (sleep_time < min_prefetch_interval) {
        /* at most prefetch @SMC_PML_PREFETCH_ROUND round */
        sleep_time = min_prefetch_interval;
    }
    if (sleep_time + 100 > remain_time) {
        /* don't have enough time to prefetch all pages */
        sleep_time = remain_time;
    }

    SMC_LOG(PML, "sleep_time=%" PRIu64 " remain_time=%" PRIu64,
            sleep_time, remain_time);
    
    return sleep_time;
}
