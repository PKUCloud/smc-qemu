#ifndef _MIGRATION_SMC_DEBUG_H
#define _MIGRATION_SMC_DEBUG_H
#include <stdio.h>

#define DEBUG_SMC

#ifdef DEBUG_SMC
enum {
    SMC_DB_GEN, SMC_DB_INIT,
};
#define SMC_DBBIT(x)    (1 << SMC_DB_##x)
static int smc_dbflags = SMC_DBBIT(GEN) | SMC_DBBIT(INIT);

#define SMC_LOG(what, fmt, ...) do { \
    if (smc_dbflags & SMC_DBBIT(what)) { \
        printf("[SMC]%s: " fmt "\n", __func__, \
               ## __VA_ARGS__); } \
    } while (0)

#else
#define SMC_LOG(what, fmt, ...) do {} while (0)
#endif

#endif
