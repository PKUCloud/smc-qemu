#ifndef _MIGRATION_SMC_DEBUG_H
#define _MIGRATION_SMC_DEBUG_H
#include <stdio.h>

#define DEBUG_SMC

extern FILE *smc_log_file;

#ifdef DEBUG_SMC
enum {
    SMC_DB_GEN, SMC_DB_INIT, SMC_DB_STREAM, SMC_DB_FETCH,
};
#define SMC_DBBIT(x)    (1 << SMC_DB_##x)
static int smc_dbflags = SMC_DBBIT(GEN) | SMC_DBBIT(INIT) | SMC_DBBIT(STREAM) |
                         SMC_DBBIT(FETCH);

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
