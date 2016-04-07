#include <stdint.h>
#include <glib.h>
#include <memory.h>
#include <inttypes.h>

#include "smc.h"
#include "smc-debug.h"

#define SMC_DIRTY_PAGE_SET_INIT_SIZE    256

SMCInfo smc_info;

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

static void smc_dirty_page_set_insert(SMCDirtyPageSet *page_set,
                                      const SMCDirtyPage *page)
{
    SMCDirtyPage *data;
    int new_size;
    int idx;

    if (page_set->size == page_set->nb_pages) {
        new_size = page_set->size + SMC_DIRTY_PAGE_SET_INIT_SIZE;
        data = (SMCDirtyPage *)g_malloc0(new_size * sizeof(SMCDirtyPage));
        memcpy(data, page_set->pages, page_set->size * sizeof(SMCDirtyPage));
        g_free(page_set->pages);
        page_set->pages = data;
        page_set->size = new_size;
    }

    idx = page_set->nb_pages;
    page_set->pages[idx].block_offset = page->block_offset;
    page_set->pages[idx].offset = page->offset;
    page_set->pages[idx].size = page->size;

    page_set->nb_pages++;
}

void smc_init(SMCInfo *smc_info)
{
    SMC_LOG(INIT, "");
    memset(smc_info, 0, sizeof(*smc_info));
    smc_dirty_page_set_init(&smc_info->dirty_pages);
}

void smc_exit(SMCInfo *smc_info)
{
    SMC_LOG(INIT, "");
    smc_dirty_page_set_free(&smc_info->dirty_pages);
}

void smc_dirty_pages_insert(SMCInfo *smc_info, uint64_t block_offset,
                            uint64_t offset, uint64_t size)
{
    SMCDirtyPage page = { .block_offset = block_offset,
                          .offset = offset,
                          .size = size,
                        };

    SMC_LOG(GEN, "add block_offset=%" PRIu64 " offset=%" PRIu64
            " size=%" PRIu64, block_offset, offset, size);
    smc_dirty_page_set_insert(&smc_info->dirty_pages, &page);
}

void smc_dirty_pages_reset(SMCInfo *smc_info)
{
    SMC_LOG(GEN, "dirty_pages=%d", smc_info->dirty_pages.nb_pages);
    smc_dirty_page_set_reset(&smc_info->dirty_pages);
}
