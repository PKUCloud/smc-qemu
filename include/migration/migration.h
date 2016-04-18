/*
 * QEMU live migration
 *
 * Copyright IBM, Corp. 2008
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#ifndef QEMU_MIGRATION_H
#define QEMU_MIGRATION_H

#include "qapi/qmp/qdict.h"
#include "qemu-common.h"
#include "qemu/thread.h"
#include "qemu/notify.h"
#include "qapi/error.h"
#include "migration/vmstate.h"
#include "qapi-types.h"
#include "exec/cpu-common.h"

#define QEMU_VM_FILE_MAGIC           0x5145564d
#define QEMU_VM_FILE_VERSION_COMPAT  0x00000002
#define QEMU_VM_FILE_VERSION         0x00000003

#define QEMU_VM_EOF                  0x00
#define QEMU_VM_SECTION_START        0x01
#define QEMU_VM_SECTION_PART         0x02
#define QEMU_VM_SECTION_END          0x03
#define QEMU_VM_SECTION_FULL         0x04
#define QEMU_VM_SUBSECTION           0x05
#define QEMU_VM_VMDESCRIPTION        0x06
#define QEMU_VM_SECTION_FOOTER       0x7e

struct MigrationParams {
    bool blk;
    bool shared;
};

typedef struct MigrationState MigrationState;

typedef QLIST_HEAD(, LoadStateEntry) LoadStateEntry_Head;

/* State for the incoming migration */
struct MigrationIncomingState {
    QEMUFile *file;

    /* See savevm.c */
    LoadStateEntry_Head loadvm_handlers;
};

MigrationIncomingState *migration_incoming_get_current(void);
MigrationIncomingState *migration_incoming_state_new(QEMUFile *f);
void migration_incoming_state_destroy(void);

struct MigrationState
{
    int64_t bandwidth_limit;
    size_t bytes_xfer;
    size_t xfer_limit;
    QemuThread *thread;
    QEMUBH *cleanup_bh;
    QEMUFile *file;
    int parameters[MIGRATION_PARAMETER_MAX];

    int state;
    MigrationParams params;
    double mbps;
    /* Rate at which it takes to copy checkpoint before transmission. */
    double copy_mbps;
    int64_t total_time;
    int64_t downtime;
    int64_t expected_downtime;
    int64_t xmit_time;
    int64_t ram_copy_time;
    int64_t log_dirty_time;
    int64_t bitmap_time;
    int64_t dirty_pages_rate;
    int64_t dirty_bytes_rate;
    bool enabled_capabilities[MIGRATION_CAPABILITY_MAX];
    int64_t xbzrle_cache_size;
    int64_t setup_time;
    int64_t dirty_sync_count;
    int64_t checkpoints;
    int64_t total_wait_time;
};

void process_incoming_migration(QEMUFile *f);

void qemu_start_incoming_migration(const char *uri, Error **errp);

uint64_t migrate_max_downtime(void);

void exec_start_incoming_migration(const char *host_port, Error **errp);

void exec_start_outgoing_migration(MigrationState *s, const char *host_port, Error **errp);

void tcp_start_incoming_migration(const char *host_port, Error **errp);

void tcp_start_outgoing_migration(MigrationState *s, const char *host_port, Error **errp);

void unix_start_incoming_migration(const char *path, Error **errp);

void unix_start_outgoing_migration(MigrationState *s, const char *path, Error **errp);

void fd_start_incoming_migration(const char *path, Error **errp);

void fd_start_outgoing_migration(MigrationState *s, const char *fdname, Error **errp);

void rdma_start_outgoing_migration(void *opaque, const char *host_port, Error **errp);

void rdma_start_incoming_migration(const char *host_port, Error **errp);

void migrate_fd_error(MigrationState *s);

void migrate_fd_connect(MigrationState *s);

int migrate_fd_close(MigrationState *s);

void add_migration_state_change_notifier(Notifier *notify);
void remove_migration_state_change_notifier(Notifier *notify);
bool migration_is_active(MigrationState *);
bool migration_is_mc(MigrationState *s);
bool migration_in_setup(MigrationState *);
bool migration_has_finished(MigrationState *);
bool migration_has_failed(MigrationState *);
MigrationState *migrate_get_current(void);

void migrate_compress_threads_create(void);
void migrate_compress_threads_join(void);
void migrate_decompress_threads_create(void);
void migrate_decompress_threads_join(void);
uint64_t ram_bytes_remaining(void);
uint64_t ram_bytes_transferred(void);
uint64_t ram_bytes_total(void);
void free_xbzrle_decoded_buf(void);

void acct_update_position(QEMUFile *f, size_t size, bool zero);

uint64_t dup_mig_bytes_transferred(void);
uint64_t dup_mig_pages_transferred(void);
uint64_t norm_mig_log_dirty_time(void);
uint64_t norm_mig_bitmap_time(void);
uint64_t skipped_mig_bytes_transferred(void);
uint64_t skipped_mig_pages_transferred(void);
uint64_t norm_mig_bytes_transferred(void);
uint64_t norm_mig_pages_transferred(void);
uint64_t xbzrle_mig_bytes_transferred(void);
uint64_t xbzrle_mig_pages_transferred(void);
uint64_t xbzrle_mig_pages_overflow(void);
uint64_t xbzrle_mig_pages_cache_miss(void);
double xbzrle_mig_cache_miss_rate(void);

void acct_clear(void);

void migrate_set_state(MigrationState *s, int old_state, int new_state);

void mc_init_checkpointer(MigrationState *s);
void mc_process_incoming_checkpoints_if_requested(QEMUFile *f);

void ram_handle_compressed(void *host, uint8_t ch, uint64_t size);

/**
 * @migrate_add_blocker - prevent migration from proceeding
 *
 * @reason - an error to be returned whenever migration is attempted
 */
void migrate_add_blocker(Error *reason);

/**
 * @migrate_del_blocker - remove a blocking error from migration
 *
 * @reason - the error blocking migration
 */
void migrate_del_blocker(Error *reason);

bool migrate_zero_blocks(void);

bool migrate_auto_converge(void);

int xbzrle_encode_buffer(uint8_t *old_buf, uint8_t *new_buf, int slen,
                         uint8_t *dst, int dlen);
int xbzrle_decode_buffer(uint8_t *src, int slen, uint8_t *dst, int dlen);

int migrate_use_xbzrle(void);
int64_t migrate_xbzrle_cache_size(void);

int64_t xbzrle_cache_resize(int64_t new_size);

bool migrate_use_compression(void);
int migrate_compress_level(void);
int migrate_compress_threads(void);
int migrate_decompress_threads(void);

void ram_control_before_iterate(QEMUFile *f, uint64_t flags);
void ram_control_after_iterate(QEMUFile *f, uint64_t flags);
void ram_control_load_hook(QEMUFile *f, uint64_t flags);
void ram_control_add(QEMUFile *f, void *host_addr,
                         ram_addr_t block_offset, uint64_t length);
void ram_control_remove(QEMUFile *f, ram_addr_t block_offset);

#define MBPS(bytes, time) time ? ((((double) bytes * 8)         \
        / ((double) time / 1000.0)) / 1000.0 / 1000.0) : 0.0


/* Whenever this is found in the data stream, the flags
 * will be passed to ram_control_load_hook in the incoming-migration
 * side. This lets before_ram_iterate/after_ram_iterate add
 * transport-specific sections to the RAM migration data.
 */
#define RAM_SAVE_FLAG_HOOK     0x80

#define RAM_SAVE_CONTROL_NOT_SUPP -1000
#define RAM_SAVE_CONTROL_DELAYED  -2000
#define RAM_LOAD_CONTROL_NOT_SUPP -3000
#define RAM_LOAD_CONTROL_DELAYED  -4000
#define RAM_COPY_CONTROL_NOT_SUPP -5000
#define RAM_COPY_CONTROL_DELAYED  -6000

#define RDMA_CONTROL_VERSION_CURRENT 1

int ram_control_save_page(QEMUFile *f, ram_addr_t block_offset,
                             uint8_t *host_addr,
                             ram_addr_t offset, long size,
                             uint64_t *bytes_sent);

void ram_mig_init(void);
void savevm_skip_section_footers(void);
int ram_control_load_page(QEMUFile *f,
                             void *host_addr,
                             long size);

int ram_control_copy_page(QEMUFile *f,
                             ram_addr_t block_offset_dest,
                             ram_addr_t offset_dest,
                             ram_addr_t block_offset_source,
                             ram_addr_t offset_source,
                             long size);

int migrate_use_mc(void);
int migrate_use_mc_rdma_copy(void);
void mc_configure_net(MigrationState *s);
void mc_cheat_unregister_tce(DeviceState * d, const VMStateDescription *v, void *o);

#define MC_VERSION 1

int mc_info_load(QEMUFile *f, void *opaque, int version_id);
void mc_info_save(QEMUFile *f, void *opaque);

void qemu_rdma_info_save(QEMUFile *f, void *opaque);
int qemu_rdma_info_load(QEMUFile *f, void *opaque, int version_id);
#endif
