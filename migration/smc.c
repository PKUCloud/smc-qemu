#include <stdint.h>
#include <glib.h>
#include <memory.h>
#include <inttypes.h>

#include "smc.h"
#include "smc-debug.h"

#define SMC_DIRTY_PAGE_SET_INIT_SIZE    256

SMCInfo glo_smc_info;

#define min(x,y) ((x) < (y) ? (x) : (y))
#define max(x,y) ((x) > (y) ? (x) : (y))

static void smc_dirty_page_set_init(SMCDirtyPageSet *page_set)
{
    page_set->size = SMC_DIRTY_PAGE_SET_INIT_SIZE;
    page_set->pages = (SMCDirtyPage *)g_malloc0(page_set->size *
                                                sizeof(SMCDirtyPage));
    page_set->nb_pages = 0;
}

static void smc_dirty_page_set_free(SMCDirtyPageSet *page_set)
{
    if (page_set->pages) {
        g_free(page_set->pages);
    }
    page_set->pages = NULL;
    page_set->size = 0;
    page_set->nb_pages = 0;
}

static void smc_dirty_page_set_reset(SMCDirtyPageSet *page_set)
{
    page_set->nb_pages = 0;
}

static void smc_dirty_page_set_resize(SMCDirtyPageSet *page_set, int new_size)
{
    SMCDirtyPage *data;

    data = (SMCDirtyPage *)g_malloc0(new_size * sizeof(SMCDirtyPage));
    if (page_set->nb_pages > 0) {
        memcpy(data, page_set->pages, min(page_set->nb_pages, new_size) *
               sizeof(SMCDirtyPage));
    }
    g_free(page_set->pages);
    page_set->pages = data;
    page_set->size = new_size;
    page_set->nb_pages = min(page_set->nb_pages, new_size);
}

static void smc_dirty_page_set_insert(SMCDirtyPageSet *page_set,
                                      const SMCDirtyPage *page)
{
    int idx;

    if (page_set->size == page_set->nb_pages) {
        smc_dirty_page_set_resize(page_set,
                                  page_set->size + SMC_DIRTY_PAGE_SET_INIT_SIZE);
    }

    idx = page_set->nb_pages;
    page_set->pages[idx].block_offset = page->block_offset;
    page_set->pages[idx].offset = page->offset;
    page_set->pages[idx].size = page->size;

    page_set->nb_pages++;
}

static void smc_dirty_page_set_insert_from_buf(SMCDirtyPageSet *page_set,
                                               const SMCDirtyPage *buf,
                                               int nb_pages)
{
    int new_size = page_set->size;

    if (new_size - page_set->nb_pages < nb_pages) {
        do {
            new_size += SMC_DIRTY_PAGE_SET_INIT_SIZE;
        } while (new_size - page_set->nb_pages < nb_pages);
        smc_dirty_page_set_resize(page_set, new_size);
    }

    memcpy(page_set->pages + page_set->nb_pages, buf,
           nb_pages * sizeof(SMCDirtyPage));
    page_set->nb_pages += nb_pages;
}

void smc_init(SMCInfo *smc_info)
{
    SMC_LOG(INIT, "");
    SMC_ASSERT(!smc_info->init);
    memset(smc_info, 0, sizeof(*smc_info));
    smc_dirty_page_set_init(&smc_info->dirty_pages);
    smc_info->init = true;
}

void smc_exit(SMCInfo *smc_info)
{
    SMC_LOG(INIT, "");
    SMC_ASSERT(smc_info->init);
    smc_dirty_page_set_free(&smc_info->dirty_pages);
    smc_info->init = false;
}

void smc_dirty_pages_insert(SMCInfo *smc_info, uint64_t block_offset,
                            uint64_t offset, uint64_t size)
{
    SMCDirtyPage page = { .block_offset = block_offset,
                          .offset = offset,
                          .size = size,
                        };

    SMC_ASSERT(smc_info->init);
    SMC_LOG(GEN, "add block_offset=%" PRIu64 " offset=%" PRIu64
            " size=%" PRIu64, block_offset, offset, size);
    smc_dirty_page_set_insert(&smc_info->dirty_pages, &page);
}

void smc_dirty_pages_reset(SMCInfo *smc_info)
{
    SMC_LOG(GEN, "dirty_pages=%d", smc_info->dirty_pages.nb_pages);
    SMC_ASSERT(smc_info->init);
    smc_dirty_page_set_reset(&smc_info->dirty_pages);
}

void smc_dirty_pages_insert_from_buf(SMCInfo *smc_info, const void *buf,
                                     int nb_pages)
{
    SMC_LOG(GEN, "copy %d dirty pages info", nb_pages);
    SMC_ASSERT(smc_info->init);
    smc_dirty_page_set_insert_from_buf(&smc_info->dirty_pages,
                                       (const SMCDirtyPage *)buf, nb_pages);
}
