#ifndef _MIGRATION_SMC_DEBUG_H
#define _MIGRATION_SMC_DEBUG_H
#include <stdio.h>

// #define DEBUG_SMC
//#define STAT_SMC

extern FILE *smc_log_file;

#ifdef DEBUG_SMC
enum {
    SMC_DB_GEN, SMC_DB_INIT, SMC_DB_STREAM, SMC_DB_FETCH, SMC_DB_PML, SMC_DB_SIM,
    SMC_DB_UNSIG, SMC_DB_DEL, SMC_DB_STATISTIC, SMC_DB_DIE, SMC_DB_NEW_UNSIG,
    SMC_DB_PREFETCH_SUM, SMC_DB_SORT, SMC_DB_OLD_SORT, SMC_DB_FREE, SMC_DB_CHECK_LIST,
    SMC_DB_SORTPY, SMC_DB_REALSORT, SMC_DB_REFETCH, SMC_DB_LRU
};
#define SMC_DBBIT(x)    (1 << SMC_DB_##x)
//static int smc_dbflags = 0;
// static int smc_dbflags = SMC_DBBIT(FREE) | SMC_DBBIT(SORT);
// static int smc_dbflags = SMC_DBBIT(CHECK_LIST);
// static int smc_dbflags = SMC_DBBIT(SORTPY);
// static int smc_dbflags = SMC_DBBIT(REALSORT);
static int smc_dbflags = SMC_DBBIT(LRU);


#define SMC_LOG(what, fmt, ...) do { \
    if (smc_dbflags & SMC_DBBIT(what)) { \
        fprintf(smc_log_file, "[SMC]%s: " fmt "\n", __func__, \
               ## __VA_ARGS__); \
        fflush(smc_log_file); } \
    } while (0)

#define SMC_ASSERT(x) do { \
    if (!(x)) { \
        (void)smc_dbflags; \
        fprintf(stderr, "[SMC]error: ASSERTION FAILED! (%s) %s, %s #%d\n", \
                #x, __FILE__, __func__, __LINE__); \
        exit(1); } \
    } while (0)

#else
#define SMC_LOG(what, fmt, ...) do {} while (0)
#define SMC_ASSERT(x) do {} while (0)
#endif

#define SMC_ERR(fmt, ...) do { \
    fprintf(stderr, "[SMC]error(%s): " fmt "\n", __func__, \
            ## __VA_ARGS__); \
    fprintf(smc_log_file, "[SMC]error(%s): " fmt "\n", __func__, \
            ## __VA_ARGS__); \
    } while (0)

#endif

#ifdef STAT_SMC
#define SMC_STAT(fmt, ...) do { \
        fprintf(smc_log_file, fmt "\n", ## __VA_ARGS__); \
        } while (0)
#else
#define SMC_STAT(fmt, ...) do {} while (0)
#endif
