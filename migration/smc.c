#include <stdint.h>
#include <glib.h>
#include <memory.h>
#include <inttypes.h>

#include "smc.h"
#include "smc-debug.h"

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

static void smc_set_insert(SMCSet *smc_set, const void *ele)
{
    if (smc_set->cap == smc_set->nb_eles) {
        smc_set_resize(smc_set, smc_set->cap + SMC_SET_INIT_CAP);
    }

    memcpy(smc_set->eles + smc_set->nb_eles * smc_set->ele_size, ele,
           smc_set->ele_size);
    smc_set->nb_eles++;
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

void smc_init(SMCInfo *smc_info)
{
    SMC_LOG(INIT, "");
    SMC_ASSERT(!smc_info->init);
    memset(smc_info, 0, sizeof(*smc_info));
    smc_set_init(&smc_info->dirty_pages, sizeof(SMCDirtyPage));
    smc_info->init = true;
}

void smc_exit(SMCInfo *smc_info)
{
    SMC_LOG(INIT, "");
    SMC_ASSERT(smc_info->init);
    smc_set_free(&smc_info->dirty_pages);
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
