/*
 *  Micro-Checkpointing (MC) support
 *  (a.k.a. Fault Tolerance or Continuous Replication)
 *
 *  Copyright IBM, Corp. 2014
 *
 *  Authors:
 *   Michael R. Hines <mrhines@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 *
 */
#include <libnl3/netlink/route/qdisc/plug.h>
#include <libnl3/netlink/route/class.h>
#include <libnl3/netlink/cli/utils.h>
#include <libnl3/netlink/cli/tc.h>
#include <libnl3/netlink/cli/qdisc.h>
#include <libnl3/netlink/cli/link.h>

#include "qemu-common.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-net.h"
#include "qemu/sockets.h"
#include "migration/migration.h"
#include "migration/qemu-file.h"
#include "qmp-commands.h"
#include "hmp.h"
#include "net/tap-linux.h"
#include "trace/simple.h"
#include "block/block.h"
#include "sysemu/block-backend.h"
#include <sys/ioctl.h>

#include "smc.h"
#include "smc-debug.h"

static void flush_trace_buffer(void) {
#ifdef CONFIG_TRACE_SIMPLE
    st_flush_trace_buffer();
#endif
}

//#define DEBUG_MC
//#define DEBUG_MC_VERBOSE
//#define DEBUG_MC_REALLY_VERBOSE

#ifdef DEBUG_MC
#define DPRINTF(fmt, ...) \
    do { printf("mc: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

#ifdef DEBUG_MC_VERBOSE
#define DDPRINTF(fmt, ...) \
    do { printf("mc: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DDPRINTF(fmt, ...) \
    do { } while (0)
#endif

#ifdef DEBUG_MC_REALLY_VERBOSE
#define DDDPRINTF(fmt, ...) \
    do { printf("mc: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DDDPRINTF(fmt, ...) \
    do { } while (0)
#endif

/*
 * Micro checkpoints (MC)s are typically only a few MB when idle.
 * However, they can easily be very large during heavy workloads.
 * In the *extreme* worst-case, QEMU might need double the amount of main memory
 * than that of what was originally allocated to the virtual machine.
 *
 * To support this variability during transient periods, a MC
 * consists of a linked list of slabs, each of identical size. A better name
 * would be welcome, as the name was only chosen because it resembles linux
 * memory allocation. Because MCs occur several times per second
 * (a frequency of 10s of milliseconds), slabs allow MCs to grow and shrink
 * without constantly re-allocating all memory in place during each checkpoint.
 *
 * During steady-state, the 'head' slab is permanently allocated and never goes
 * away, so when the VM is idle, there is no memory allocation at all.
 * This design supports the use of RDMA. Since RDMA requires memory pinning, we
 * must be able to hold on to a slab for a reasonable amount of time to get any
 * real use out of it.
 *
 * Regardless, the current strategy taken is:
 *
 * 1. If the checkpoint size increases,
 *    then grow the number of slabs to support it,
 *    (if and only if RDMA is activated, these slabs will be pinned.)
 * 2. If the next checkpoint size is smaller than the last one,
      then that's a "strike".
 * 3. After N strikes, cut the size of the slab cache in half
 *    (to a minimum of 1 slab as described before).
 *
 * As of this writing, a typical average size of
 * an Idle-VM checkpoint is under 5MB.
 */

#define MC_SLAB_BUFFER_SIZE     (5UL * 1024UL * 1024UL) /* empirical */
#define MC_DEV_NAME_MAX_SIZE    256

#define MC_DEFAULT_CHECKPOINT_FREQ_MS 40 /* too slow, but best for now */
#define CALC_MAX_STRIKES()                                           \
    do {  max_strikes = (max_strikes_delay_secs * 1000) / freq_ms; } \
    while (0)

/*
 * How many "seconds-worth" of checkpoints to wait before re-evaluating the size
 * of the slab list?
 *
 * #strikes_until_shrink_cache = Function(#checkpoints/sec)
 *
 * Increasing the number of seconds also increases the number of strikes needed
 * to be reached until it is time to cut the cache in half.
 *
 * Below value is open for debate - we just want it to be small enough to ensure
 * that a large, idle slab list doesn't stay too large for too long.
 */
#define MC_DEFAULT_SLAB_MAX_CHECK_DELAY_SECS 10

/*
 * MC serializes the actual RAM page contents in such a way that the actual
 * pages are separated from the meta-data (all the QEMUFile stuff).
 *
 * This is done strictly for the purposes of being able to use RDMA
 * and to replace memcpy() on the local machine for hardware with very
 * fast RAM memory speeds.
 *
 * This serialization requires recording the page descriptions and then
 * pushing them into slabs after the checkpoint has been captured
 * (minus the page data).
 *
 * The memory holding the page descriptions are allocated in unison with the
 * slabs themselves, and thus we need to know in advance the maximum number of
 * page descriptions that can fit into a slab before allocating the slab.
 * It should be safe to assume the *minimum* page size (not the maximum,
 * that would be dangerous) is 4096.
 *
 * We're not actually using this assumption for any memory management
 * management, only as a hint to know how big of an array to allocate.
 *
 * The following adds a fixed-cost of about 40 KB to each slab.
 */
#define MC_MAX_SLAB_COPY_DESCRIPTORS (MC_SLAB_BUFFER_SIZE / 4096)

#define SLAB_RESET(s) do {                      \
                            s->size = 0;      \
                            s->read = 0;      \
                      } while(0)

uint64_t freq_ms = MC_DEFAULT_CHECKPOINT_FREQ_MS;
uint32_t max_strikes_delay_secs = MC_DEFAULT_SLAB_MAX_CHECK_DELAY_SECS;
uint32_t max_strikes = -1;

typedef struct QEMU_PACKED MCCopy {
    uint64_t ramblock_offset;
    uint64_t host_addr;
    uint64_t offset;
    uint64_t size;
} MCCopy;

typedef struct QEMU_PACKED MCCopyset {
    QTAILQ_ENTRY(MCCopyset) node;
    MCCopy copies[MC_MAX_SLAB_COPY_DESCRIPTORS];
    uint64_t nb_copies;
    int idx;
} MCCopyset;

typedef struct QEMU_PACKED MCSlab {
    QTAILQ_ENTRY(MCSlab) node;
    uint8_t buf[MC_SLAB_BUFFER_SIZE];
    uint64_t read;
    uint64_t size;
    int idx;
} MCSlab;

typedef struct MCParams {
    QTAILQ_HEAD(shead, MCSlab) slab_head;
    QTAILQ_HEAD(chead, MCCopyset) copy_head;
    MCSlab *curr_slab;
    MCSlab *mem_slab;
    MCCopyset *curr_copyset;
    MCCopy *copy;
    QEMUFile *file;
    QEMUFile *staging;
    uint64_t start_copyset;
    uint64_t slab_total;
    uint64_t total_copies;
    uint64_t nb_slabs;
    uint64_t pages_loaded;
    uint64_t used_slabs;
    uint32_t slab_strikes;
    uint32_t copy_strikes;
    int nb_copysets;
    uint64_t checkpoints;
} MCParams;

enum {
    MC_TRANSACTION_NACK = 300,
    MC_TRANSACTION_START,
    MC_TRANSACTION_COMMIT,
    MC_TRANSACTION_ABORT,
    MC_TRANSACTION_ACK,
    MC_TRANSACTION_END,
    MC_TRANSACTION_DISK_ENABLE,
    MC_TRANSACTION_DISK_DISABLE,
    MC_TRANSACTION_ANY,
};

static const char * mc_desc[] = {
    [MC_TRANSACTION_NACK] = "NACK",
    [MC_TRANSACTION_START] = "START",
    [MC_TRANSACTION_COMMIT] = "COMMIT",
    [MC_TRANSACTION_ABORT] = "ABORT",
    [MC_TRANSACTION_ACK] = "ACK",
    [MC_TRANSACTION_END] = "END",
    [MC_TRANSACTION_ANY] = "ANY",
};

static struct rtnl_qdisc        *qdisc      = NULL;
static struct nl_sock           *sock       = NULL;
static struct rtnl_tc           *tc         = NULL;
static struct nl_cache          *link_cache = NULL;
static struct rtnl_tc_ops       *ops        = NULL;
static struct nl_cli_tc_module  *tm         = NULL;
static int first_nic_chosen = 0;

/*
 * Assuming a guest can 'try' to fill a 1 Gbps pipe,
 * that works about to 125000000 bytes/sec.
 *
 * Netlink better not be pre-allocating megabytes in the
 * kernel qdisc, that would be crazy....
 */
#define START_BUFFER (1000*1000*1000 / 8)
static int buffer_size = START_BUFFER, new_buffer_size = START_BUFFER;
static const char * parent = "root";
static bool buffering_enabled = false;
static const char * BUFFER_NIC_PREFIX = "ifb";
static QEMUBH *checkpoint_bh = NULL;
static bool mc_requested = false;

int migrate_use_mc(void)
{
    MigrationState *s = migrate_get_current();
    return s->enabled_capabilities[MIGRATION_CAPABILITY_MC];
}

int migrate_use_mc_rdma_copy(void)
{
    MigrationState *s = migrate_get_current();
    return s->enabled_capabilities[MIGRATION_CAPABILITY_MC_RDMA_COPY];
}

static int mc_deliver(int update)
{
    int err, flags = NLM_F_CREATE | NLM_F_REPLACE;

    if (!buffering_enabled) {
        return 1;
    }

    if (!update)
        flags |= NLM_F_EXCL;

    if ((err = rtnl_qdisc_add(sock, qdisc, flags)) < 0) {
        fprintf(stderr, "Unable to control qdisc: %s! %p %p %d\n",
            nl_geterror(err), sock, qdisc, flags);
        return -EINVAL;
    }

    return 0;
}

static int mc_set_buffer_size(int size)
{
    int err;

    if (!buffering_enabled) {
        return 1;
    }

    buffer_size = size;
    new_buffer_size = size;

    if ((err = rtnl_qdisc_plug_set_limit((void *) qdisc, size)) < 0) {
       fprintf(stderr, "MC: Unable to change buffer size: %s\n",
			nl_geterror(err));
       return -EINVAL;
    }

    DPRINTF("Set buffer size to %d bytes\n", size);

    return mc_deliver(1);
}

/*
 * Micro-checkpointing may require buffering network packets.
 * Set that up for the first NIC only.... We'll worry about
 * multiple NICs later.
 */
static void init_mc_nic_buffering(NICState *nic, void *opaque)
{
    char * device = opaque;
    NetClientState * nc = &nic->ncs[0];
    const char * key = "ifname=";
    int keylen = strlen(key);
    char * name;
    int end = 0;
    bool use_fd = false;

    if (first_nic_chosen) {
         fprintf(stderr, "Micro-Checkpointing with multiple NICs not yet supported!\n");
         return;
    }

    if (!nc->peer) {
        fprintf(stderr, "Micro-Checkpoint nic %s does not have peer host device for buffering. VM will not be consistent.\n", nc->name);
        return;
    }

    name = nc->peer->info_str;

    DPRINTF("Checking contents of device [%s] (%s)\n", name, nc->name);

    if (strncmp(name, key, keylen)) {
        fprintf(stderr, "Micro-Checkpoint nic %s does not have 'ifname' "
                        "in its description (%s, %s). Trying workaround...\n",
                        nc->name, name, nc->peer->name);
        key = "fd=";
        keylen = strlen(key);
        if (strncmp(name, key, keylen)) {
            fprintf(stderr, "Still cannot find 'fd=' either. Failure.\n");
            return;
        }

        use_fd = true;
    }

    name += keylen;

    while (name[end++] != (use_fd ? '\0' : ','));

    strncpy(device, name, end - 1);
    memset(&device[end - 1], 0, MC_DEV_NAME_MAX_SIZE - (end - 1));

    if (use_fd) {
        struct ifreq r;
        DPRINTF("Want to retreive name from fd: %d\n", atoi(device));

        if (ioctl(atoi(device), TUNGETIFF, &r) == -1) {
            fprintf(stderr, "Failed to convert fd %s to name.\n", device);
            return;
        }

        DPRINTF("Got name %s!\n", r.ifr_name);
        strcpy(device, r.ifr_name);
    }

    first_nic_chosen = 1;
}

static int mc_suspend_buffering(void)
{
    int err;

    if (!buffering_enabled) {
        return 1;
    }

    if ((err = rtnl_qdisc_plug_release_indefinite((void *) qdisc)) < 0) {
        fprintf(stderr, "MC: Unable to release indefinite: %s\n",
            nl_geterror(err));
        return -EINVAL;
    }

    DPRINTF("Buffering suspended\n");

    return mc_deliver(1);
}

static int mc_disable_buffering(void)
{
    int err;

    if (!buffering_enabled) {
		goto out;
	}

    mc_suspend_buffering();

    if (qdisc && sock && (err = rtnl_qdisc_delete(sock, (void *) qdisc)) < 0) {
        fprintf(stderr, "Unable to release indefinite: %s\n", nl_geterror(err));
    }

out:
    buffering_enabled = false;
    qdisc = NULL;
    sock = NULL;
    tc = NULL;
    link_cache = NULL;
    ops = NULL;
    tm = NULL;

    DPRINTF("Buffering disabled\n");

    return 0;
}

/*
 * Install a Qdisc plug for micro-checkpointing.
 * If it exists already (say, from a previous dead VM or debugging
 * session) then just open all the netlink data structures pointing
 * to the existing plug and replace it.
 *
 * Also, if there is no network device to begin with, then just
 * silently return with buffering_enabled = false.
 */
static int mc_enable_buffering(void)
{
    char dev[MC_DEV_NAME_MAX_SIZE], buffer_dev[MC_DEV_NAME_MAX_SIZE];
    int prefix_len = 0;
    int buffer_prefix_len = strlen(BUFFER_NIC_PREFIX);

    if (buffering_enabled) {
        fprintf(stderr, "Buffering already enable Skipping.\n");
        return 0;
    }

    first_nic_chosen = 0;

    qemu_foreach_nic(init_mc_nic_buffering, dev);

    if (!first_nic_chosen) {
        fprintf(stderr, "MC ERROR: No network devices available."
                " Disabling buffering.\n");
        return 1;
    }

    while ((dev[prefix_len] < '0') || (dev[prefix_len] > '9'))
        prefix_len++;

    strcpy(buffer_dev, BUFFER_NIC_PREFIX);
    strncpy(buffer_dev + buffer_prefix_len,
                dev + prefix_len, strlen(dev) - prefix_len + 1);

    fprintf(stderr, "Initializing buffering for nic %s => %s\n", dev, buffer_dev);

    if (sock == NULL) {
        sock = (struct nl_sock *) nl_cli_alloc_socket();
        if (!sock) {
            fprintf(stderr, "MC: failed to allocate netlink socket\n");
            goto failed;
        }
		nl_cli_connect(sock, NETLINK_ROUTE);
    }

    if (qdisc == NULL) {
        qdisc = nl_cli_qdisc_alloc();
        if (!qdisc) {
            fprintf(stderr, "MC: failed to allocate netlink qdisc\n");
            goto failed;
        }
        tc = (struct rtnl_tc *) qdisc;
    }

    if (link_cache == NULL) {
		link_cache = nl_cli_link_alloc_cache(sock);
        if (!link_cache) {
            fprintf(stderr, "MC: failed to allocate netlink link_cache\n");
            goto failed;
        }
    }

    nl_cli_tc_parse_dev(tc, link_cache, (char *) buffer_dev);
    nl_cli_tc_parse_parent(tc, (char *) parent);

    if (!rtnl_tc_get_ifindex(tc)) {
        fprintf(stderr, "Qdisc device '%s' does not exist!\n", buffer_dev);
        goto failed;
    }

    if (!rtnl_tc_get_parent(tc)) {
        fprintf(stderr, "Qdisc parent '%s' is not valid!\n", parent);
        goto failed;
    }

    if (rtnl_tc_set_kind(tc, "plug") < 0) {
        fprintf(stderr, "Could not open qdisc plug!\n");
        goto failed;
    }

    if (!(ops = rtnl_tc_get_ops(tc))) {
        fprintf(stderr, "Could not open qdisc plug!\n");
        goto failed;
    }

    if (!(tm = nl_cli_tc_lookup(ops))) {
        fprintf(stderr, "Qdisc plug not supported!\n");
        goto failed;
    }

    buffering_enabled = true;

    if (mc_deliver(0) < 0) {
		fprintf(stderr, "First time qdisc create failed\n");
		goto failed;
    }

    DPRINTF("Buffering enabled, size: %d MB.\n", buffer_size / 1024 / 1024);

    if (mc_set_buffer_size(buffer_size) < 0) {
		goto failed;
	}

    if (mc_suspend_buffering() < 0) {
		goto failed;
	}


    return 0;

failed:
    mc_disable_buffering();
    return -EINVAL;
}

static int mc_start_buffer(void)
{
    int err;

    if (!buffering_enabled) {
        return 0;
    }

    if (new_buffer_size != buffer_size) {
        buffer_size = new_buffer_size;
        DPRINTF("MC setting new buffer size to %d\n", buffer_size);
        if (mc_set_buffer_size(buffer_size) < 0)
            return -EINVAL;
    }

    if ((err = rtnl_qdisc_plug_buffer((void *) qdisc)) < 0) {
        fprintf(stderr, "Unable to flush oldest checkpoint: %s\n", nl_geterror(err));
        return -EINVAL;
    }

    DDPRINTF("Inserted checkpoint barrier\n");

    return mc_deliver(1);
}

static int mc_flush_oldest_buffer(void)
{
    int err;

    if (!buffering_enabled) {
        return 0;
    }

    if ((err = rtnl_qdisc_plug_release_one((void *) qdisc)) < 0) {
        fprintf(stderr, "Unable to flush oldest checkpoint: %s\n", nl_geterror(err));
        return -EINVAL;
    }

    DDPRINTF("Flushed oldest checkpoint barrier\n");

    return mc_deliver(1);
}

/*
 * Get the next slab in the list. If there is none, then make one.
 */
static MCSlab *mc_slab_next(MCParams *mc, MCSlab *slab)
{
    if (!QTAILQ_NEXT(slab, node)) {
        int idx = mc->nb_slabs++;
        mc->used_slabs++;
        DDPRINTF("Extending slabs by one: %" PRIu64 " slabs total, "
                 "%" PRIu64 " MB\n", mc->nb_slabs,
                 mc->nb_slabs * sizeof(MCSlab) / 1024UL / 1024UL);
        mc->curr_slab = qemu_memalign(4096, sizeof(MCSlab));
        memset(mc->curr_slab, 0, sizeof(*(mc->curr_slab)));
        mc->curr_slab->idx = idx;
        QTAILQ_INSERT_TAIL(&mc->slab_head, mc->curr_slab, node);
        slab = mc->curr_slab;
        ram_control_add(mc->file, slab->buf,
                (uint64_t) (uintptr_t) slab->buf, MC_SLAB_BUFFER_SIZE);
    } else {
        DDPRINTF("Adding to existing slab: %" PRIu64 " slabs total, "
                 "%" PRIu64 " MB\n", mc->nb_slabs,
                 mc->nb_slabs * sizeof(MCSlab) / 1024UL / 1024UL);
        slab = QTAILQ_NEXT(slab, node);
        mc->used_slabs++;
    }

    mc->curr_slab = slab;
    SLAB_RESET(slab);

    if (slab->idx == mc->start_copyset) {
        DDPRINTF("Found copyset slab @ idx %d\n", slab->idx);
        mc->mem_slab = slab;
    }

    return slab;
}

static int mc_put_buffer(void *opaque, const uint8_t *buf,
                                  int64_t pos, int size)
{
    MCParams *mc = opaque;
    MCSlab *slab = mc->curr_slab;
    uint64_t len = size;

    assert(slab);

    while (len) {
        long put = MIN(MC_SLAB_BUFFER_SIZE - slab->size, len);

        if (put == 0) {
            DDPRINTF("Reached the end of slab %d Need a new one\n", slab->idx);
            goto zero;
        }

        if (mc->copy && migrate_use_mc_rdma_copy()) {
            int ret = ram_control_copy_page(mc->file,
                                        (uint64_t) (uintptr_t) slab->buf,
                                        slab->size,
                                        (ram_addr_t) mc->copy->ramblock_offset,
                                        (ram_addr_t) mc->copy->offset,
                                        put);

            DDDPRINTF("Attempted offloaded memcpy.\n");

            if (ret != RAM_COPY_CONTROL_NOT_SUPP) {
                if (ret == RAM_COPY_CONTROL_DELAYED) {
                    DDDPRINTF("Offloaded memcpy successful.\n");
                    mc->copy->offset += put;
                    goto next;
                } else {
                    fprintf(stderr, "Offloaded memcpy failed: %d\n", ret);
                    return ret;
                }
            }
        }

        DDDPRINTF("Copying to %p from %p, size %" PRId64 "\n",
                 slab->buf + slab->size, buf, put);

        memcpy(slab->buf + slab->size, buf, put);
next:

        buf            += put;
        slab->size     += put;
        len            -= put;
        mc->slab_total += put;

        DDDPRINTF("put: %" PRIu64 " len: %" PRIu64
                  " total %" PRIu64 " size: %" PRIu64 " slab %d\n",
                  put, len, mc->slab_total, slab->size, slab->idx);
zero:
        if (len) {
            slab = mc_slab_next(mc, slab);
        }
    }

    return size;
}

/*
 * Stop the VM, generate the micro checkpoint,
 * but save the dirty memory into staging memory until
 * we can re-activate the VM as soon as possible.
 */
static int capture_checkpoint(MCParams *mc, MigrationState *s)
{
    MCCopyset *copyset;
    int idx, ret = 0;
    uint64_t start, stop, copies = 0;
    int64_t start_time;

    mc->total_copies = 0;
    qemu_mutex_lock_iothread();
    vm_stop_force_state(RUN_STATE_CHECKPOINTING);
    start = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);

    /*
     * If buffering is enabled, insert a Qdisc plug here
     * to hold packets for the *next* MC, (not this one,
     * the packets for this one have already been plugged
     * and will be released after the MC has been transmitted.
     */
    mc_start_buffer();

    qemu_savevm_state_header(mc->staging);
    qemu_savevm_state_begin(mc->staging, &s->params);
    ret = qemu_file_get_error(s->file);

    if (ret < 0) {
        migrate_set_state(s, MIGRATION_STATUS_CHECKPOINTING, MIGRATION_STATUS_FAILED);
    }

    qemu_savevm_state_complete(mc->staging);

    ret = qemu_file_get_error(s->file);
    if (ret < 0) {
        migrate_set_state(s, MIGRATION_STATUS_CHECKPOINTING, MIGRATION_STATUS_FAILED);
        goto out;
    }

    /*
     * The copied memory gets appended to the end of the snapshot, so let's
     * remember where its going to go first and start a new slab.
     */

    start_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);

    if (!mc->total_copies) {
        DDPRINTF("No copysets. Don't copy.\n");
        mc->start_copyset = 0;
        goto skip_copies;
    }

    DDPRINTF("Copyset identifiers complete. Copying memory from %d"
                " copysets...\n", mc->nb_copysets);

    mc_slab_next(mc, mc->curr_slab);
    mc->start_copyset = mc->curr_slab->idx;

    /*
     * Now perform the actual copy of memory into the tail end of the slab list.
     */
    QTAILQ_FOREACH(copyset, &mc->copy_head, node) {
        if (!copyset->nb_copies) {
            break;
        }

        copies += copyset->nb_copies;

        DDDPRINTF("copyset %d copies: %" PRIu64 " total: %" PRIu64 "\n",
                copyset->idx, copyset->nb_copies, copies);

        for (idx = 0; idx < copyset->nb_copies; idx++) {
            uint8_t *addr;
            long size;
            mc->copy = &copyset->copies[idx];
            addr = (uint8_t *) (uintptr_t) (mc->copy->host_addr + mc->copy->offset);
            size = mc_put_buffer(mc, addr, mc->copy->offset, mc->copy->size);
            if (size != mc->copy->size) {
                fprintf(stderr, "Failure to initiate copyset %d index %d\n",
                        copyset->idx, idx);
                migrate_set_state(s, MIGRATION_STATUS_CHECKPOINTING,
                MIGRATION_STATUS_FAILED);
                vm_start();
                goto out;
            }

            DDDPRINTF("Success copyset %d index %d\n", copyset->idx, idx);
        }

        copyset->nb_copies = 0;
    }

    DDPRINTF("Copy complete: %" PRIu64 " pages\n", copies);

skip_copies:
    s->ram_copy_time = (qemu_clock_get_ms(QEMU_CLOCK_REALTIME) - start_time);

    mc->copy = NULL;
    ram_control_before_iterate(mc->file, RAM_CONTROL_FLUSH);
    assert(mc->total_copies == copies);

    stop = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);

    /*
     * MC is safe in staging area. Let the VM go.
     */
    vm_start();
    qemu_fflush(mc->staging);

    s->downtime = stop - start;
out:
    qemu_mutex_unlock_iothread();
    return ret;
}

/*
 * Stop the VM, capture the dirty pages from KVM,
 * then synchronise the dirty bitmap to ,
 * re-activate the VM as soon as possible,
 * 
 */
static void smc_pml_capture_dirty_pages(MCParams *mc, MigrationState *s)
{
    SMC_LOG(PML, "stop the VM and then capture dirty pages");
    qemu_mutex_lock_iothread();
    vm_stop_force_state(RUN_STATE_CHECKPOINTING);
    qemu_prefetch_state_begin(mc->staging);
    vm_start();
    qemu_mutex_unlock_iothread();
    //let VM go as soon as possible
    qemu_prefetch_state_complete(mc->staging);
}


/*
 * Synchronously send a micro-checkpointing command
 */
static int mc_send(QEMUFile *f, uint64_t request)
{
    int ret = 0;

    qemu_put_be64(f, request);

    ret = qemu_file_get_error(f);
    if (ret) {
        fprintf(stderr, "transaction: send error while sending %" PRIu64 ", "
                "bailing: %s\n", request, strerror(-ret));
    } else {
        DDPRINTF("transaction: sent: %s (%" PRIu64 ")\n",
            mc_desc[request], request);
    }

    qemu_fflush(f);

    return ret;
}

/*
 * Synchronously receive a micro-checkpointing command
 */
static int mc_recv(QEMUFile *f, uint64_t request, uint64_t *action)
{
    int ret = 0;
    uint64_t got;

    got = qemu_get_be64(f);

    ret = qemu_file_get_error(f);
    if (ret) {
        fprintf(stderr, "transaction: recv error while expecting %s (%"
                PRIu64 "), bailing: %s\n", mc_desc[request],
                request, strerror(-ret));
    } else {
        if ((request != MC_TRANSACTION_ANY) && request != got) {
            fprintf(stderr, "transaction: was expecting %s (%" PRIu64
                    ") but got %" PRIu64 " instead\n",
                    mc_desc[request], request, got);
            ret = -EINVAL;
        } else {
            DDPRINTF("transaction: recv: %s (%" PRIu64 ")\n",
                     mc_desc[got], got);
            ret = 0;
            if (action) {
                *action = got;
            }
        }
    }

    return ret;
}

static MCSlab *mc_slab_start(MCParams *mc)
{
    if (mc->nb_slabs > 2) {
        if (mc->slab_strikes >= max_strikes) {
            uint64_t nb_slabs_to_free = MAX(1, (((mc->nb_slabs - 1) / 2)));

            DPRINTF("MC has reached max strikes. Will free %"
                    PRIu64 " / %" PRIu64 " slabs max %d, "
                    "checkpoints %" PRIu64 "\n",
                    nb_slabs_to_free, mc->nb_slabs,
                    max_strikes, mc->checkpoints);

            mc->slab_strikes = 0;

            while (nb_slabs_to_free) {
                MCSlab *slab = QTAILQ_LAST(&mc->slab_head, shead);
                ram_control_remove(mc->file, (uint64_t) (uintptr_t) slab->buf);
                QTAILQ_REMOVE(&mc->slab_head, slab, node);
                g_free(slab);
                nb_slabs_to_free--;
                mc->nb_slabs--;
            }

            goto skip;
        } else if (((mc->slab_total <=
                    ((mc->nb_slabs - 1) * MC_SLAB_BUFFER_SIZE)))) {
            mc->slab_strikes++;
            DDPRINTF("MC has strike %d slabs %" PRIu64 " max %d\n",
                     mc->slab_strikes, mc->nb_slabs, max_strikes);
            goto skip;
        }
    }

    if (mc->slab_strikes) {
        DDPRINTF("MC used all slabs. Resetting strikes to zero.\n");
        mc->slab_strikes = 0;
    }
skip:

    mc->used_slabs = 1;
    mc->slab_total = 0;
    mc->curr_slab = QTAILQ_FIRST(&mc->slab_head);
    SLAB_RESET(mc->curr_slab);

    return mc->curr_slab;
}

static MCCopyset *mc_copy_start(MCParams *mc)
{
    if (mc->nb_copysets >= 2) {
        if (mc->copy_strikes >= max_strikes) {
            int nb_copies_to_free = MAX(1, (((mc->nb_copysets - 1) / 2)));

            DPRINTF("MC has reached max strikes. Will free %d / %d copies max %d\n",
                    nb_copies_to_free, mc->nb_copysets, max_strikes);

            mc->copy_strikes = 0;

            while (nb_copies_to_free) {
                MCCopyset * copyset = QTAILQ_LAST(&mc->copy_head, chead);
                QTAILQ_REMOVE(&mc->copy_head, copyset, node);
                g_free(copyset);
                nb_copies_to_free--;
                mc->nb_copysets--;
            }

            goto skip;
        } else if (((mc->total_copies <=
                    ((mc->nb_copysets - 1) * MC_MAX_SLAB_COPY_DESCRIPTORS)))) {
            mc->copy_strikes++;
            DDPRINTF("MC has strike %d copies %d max %d\n",
                     mc->copy_strikes, mc->nb_copysets, max_strikes);
            goto skip;
        }
    }

    if (mc->copy_strikes) {
        DDPRINTF("MC used all copies. Resetting strikes to zero.\n");
        mc->copy_strikes = 0;
    }
skip:

    mc->total_copies = 0;
    mc->curr_copyset = QTAILQ_FIRST(&mc->copy_head);
    mc->curr_copyset->nb_copies = 0;

    return mc->curr_copyset;
}

static void blk_start_replication(bool primary, Error **errp)
{
    /*
    ReplicationMode mode = primary ? REPLICATION_MODE_PRIMARY :
                                     REPLICATION_MODE_SECONDARY;
    BlockBackend *blk, *temp;
    Error *local_err = NULL;

    for (blk = blk_next(NULL); blk; blk = blk_next(blk)) {
        if (blk_is_read_only(blk) || !blk_is_inserted(blk)) {
            continue;
        }

        bdrv_start_replication(blk_bs(blk), mode, &local_err);
        if (local_err) {
            error_propagate(errp, local_err);
            goto fail;
        }
    }

    return;

fail:
    for (temp = blk_next(NULL); temp != blk; temp = blk_next(temp)) {
        bdrv_stop_replication(blk_bs(temp), false, NULL);
    }
    */
}

static void blk_do_checkpoint(Error **errp)
{
    /*
    BlockBackend *blk;
    Error *local_err = NULL;

    for (blk = blk_next(NULL); blk; blk = blk_next(blk)) {
        if (blk_is_read_only(blk) || !blk_is_inserted(blk)) {
            continue;
        }

        bdrv_do_checkpoint(blk_bs(blk), &local_err);
        if (local_err) {
            error_propagate(errp, local_err);
            return;
        }
    }
    */
}

static void blk_stop_replication(bool failover, Error **errp)
{
    /*
    BlockBackend *blk;
    Error *local_err = NULL;

    for (blk = blk_next(NULL); blk; blk = blk_next(blk)) {
        if (blk_is_read_only(blk) || !blk_is_inserted(blk)) {
            continue;
        }

        bdrv_stop_replication(blk_bs(blk), failover, &local_err);
        if (!errp) {
            continue;
        }
        if (local_err) {
            error_propagate(errp, local_err);
            return;
        }
    }
    */
}

/*
 * Main MC loop. Stop the VM, dump the dirty memory
 * into staging, restart the VM, transmit the MC,
 * and then sleep for some milliseconds before
 * starting the next MC.
 */
static void *mc_thread(void *opaque)
{
    MigrationState *s = opaque;
    MCParams mc = { .file = s->file };
    MCSlab * slab;
    void *f_opaque = qemu_file_get_opaque(s->file);
    int64_t initial_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    int ret = 0, fd = qemu_get_fd(s->file), x;
    QEMUFile *mc_control, *mc_staging = NULL;
    uint64_t wait_time = 0;
    Error *local_err = NULL;
    bool blk_enabled = false;
    int64_t fetch_time;

    smc_init(&glo_smc_info, f_opaque);

    if (!(mc_control = qemu_fopen_socket(fd, "rb"))) {
        fprintf(stderr, "Failed to setup read MC control\n");
        goto err;
    }

    if (!(mc_staging = qemu_fopen_mc(&mc, "wb"))) {
        fprintf(stderr, "Failed to setup MC staging area\n");
        goto err;
    }

    if (s->enabled_capabilities[MIGRATION_CAPABILITY_MC_PPC_CHEAT_TCE])
    {
        mc_cheat_unregister_tce(NULL, NULL, NULL);
    }

    mc.staging = mc_staging;

    qemu_set_block(fd);
    socket_set_nodelay(fd);

    s->checkpoints = 0;

    if (s->enabled_capabilities[MIGRATION_CAPABILITY_MC_DISK_DISABLE]) {
        if ((ret = mc_send(s->file, MC_TRANSACTION_DISK_DISABLE) < 0)) {
            fprintf(stderr, "failed to notify backup to start disk buffering\n");
            goto err; 
        }
    } else {
        blk_enabled = true;
        DPRINTF("requesting start for disk replication.\n");
        if ((ret = mc_send(s->file, MC_TRANSACTION_DISK_ENABLE) < 0)) {
            fprintf(stderr, "failed to notify backup to start disk buffering\n");
            goto err; 
        }

        DDPRINTF("awaiting ack for started disk replication.\n");

        if ((ret = mc_recv(mc_control, MC_TRANSACTION_ACK, NULL)) < 0) {
            fprintf(stderr, "failed to receive disk buffering ack from backup\n");
            goto err;
        }

        DDPRINTF("got ack for started disk replication.\n");
        qemu_mutex_lock_iothread();

        DDPRINTF("starting my own (placebo) disk replication.\n");
        blk_start_replication(true, &local_err);
        if (local_err) {
            fprintf(stderr, "Failed to setup disk replication.\n");
            qemu_mutex_unlock_iothread();
            goto err;
        }

        DDPRINTF("started (placebo) disk replication.\n");
        qemu_mutex_unlock_iothread();

    }

    while (s->state == MIGRATION_STATUS_CHECKPOINTING) {
        int64_t start_time, xmit_start, end_time;
        bool commit_sent = false;
        int nr_dirty_pages;
        double tmp;
        int fetch_speed;
#ifdef SMC_PREFETCH
        smc_dirty_pages_reset(&glo_smc_info);
#endif
#ifdef SMC_PML_PREFETCH
        if (smc_is_init(&glo_smc_info)) {
            smc_pml_prefetch_pages_reset(&glo_smc_info);
            /* need to clear smc_pml_incheckpoint_bitmap before 
                        * capturing this checkpoint.
                        */
            glo_smc_info.enable_incheckpoint_bitmap = true;
        }
#endif
        slab = mc_slab_start(&mc);
        mc_copy_start(&mc);
        acct_clear();
        start_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);

        if (capture_checkpoint(&mc, s) < 0) {
            break;
        }

        assert(mc.slab_total);

        xmit_start = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);

        if ((ret = mc_send(s->file, MC_TRANSACTION_START) < 0)) {
            fprintf(stderr, "transaction start failed\n");
            break;
        }

        mc.curr_slab = QTAILQ_FIRST(&mc.slab_head);

        qemu_put_be64(s->file, mc.slab_total);
        qemu_put_be64(s->file, mc.start_copyset);
        qemu_put_be64(s->file, mc.used_slabs);

        qemu_fflush(s->file);

        qemu_mutex_lock_iothread();
        blk_do_checkpoint(&local_err);
        qemu_mutex_unlock_iothread();

        DDPRINTF("Transaction commit\n");

        /*
         * The MC is safe, and VM is running again.
         * Start a transaction and send it.
         */
        ram_control_before_iterate(s->file, RAM_CONTROL_ROUND);

        slab = QTAILQ_FIRST(&mc.slab_head);

        for (x = 0; x < mc.used_slabs; x++) {
            ret = ram_control_save_page(s->file, (uint64_t) (uintptr_t) slab->buf,
                                        NULL, 0, slab->size, NULL);

            if (ret == RAM_SAVE_CONTROL_NOT_SUPP) {
                if (!commit_sent) {
                    if ((ret = mc_send(s->file, MC_TRANSACTION_COMMIT) < 0)) {
                        fprintf(stderr, "transaction commit failed\n");
                        break;
                    }
                    commit_sent = true;
                }

                qemu_put_be64(s->file, slab->size);
                qemu_put_buffer_async(s->file, slab->buf, slab->size);
            } else if ((ret < 0) && (ret != RAM_SAVE_CONTROL_DELAYED)) {
                fprintf(stderr, "failed 1, skipping send\n");
                goto err;
            }

            if (qemu_file_get_error(s->file)) {
                fprintf(stderr, "failed 2, skipping send\n");
                goto err;
            }

            DDPRINTF("Sent idx %d slab size %" PRId64 " all %ld\n",
                x, slab->size, mc.slab_total);

            slab = QTAILQ_NEXT(slab, node);
        }

        if (!commit_sent) {
            ram_control_after_iterate(s->file, RAM_CONTROL_ROUND);
            slab = QTAILQ_FIRST(&mc.slab_head);

            for (x = 0; x < mc.used_slabs; x++) {
                qemu_put_be64(s->file, slab->size);
                slab = QTAILQ_NEXT(slab, node);
            }
        }

        qemu_fflush(s->file);

        if (commit_sent) {
            DDPRINTF("Waiting for commit ACK\n");

            if ((ret = mc_recv(mc_control, MC_TRANSACTION_ACK, NULL)) < 0) {
                goto err;
            }
        }

        ret = qemu_file_get_error(s->file);
        if (ret) {
            fprintf(stderr, "Error sending checkpoint: %d\n", ret);
            goto err;
        }

        DDPRINTF("Memory transfer complete.\n");

#ifdef SMC_PREFETCH
        ret = smc_send_dirty_info(f_opaque, &glo_smc_info);

        if (ret) {
            SMC_ERR("smc_send_dirty_info() failed");
            goto err;
        }
#endif

        /*
         * The MC is safe on the other side now,
         * go along our merry way and release the network
         * packets from the buffer if enabled.
         */
        mc_flush_oldest_buffer();

        end_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);

#ifdef SMC_PREFETCH
        nr_dirty_pages = smc_dirty_pages_count(&glo_smc_info);

        s->nr_dirty_pages += nr_dirty_pages;
        s->nr_trans_pages += mc.total_copies;

        if (nr_dirty_pages) {
            tmp = (nr_dirty_pages - mc.total_copies) * 1.0 / nr_dirty_pages;
        } else {
            tmp = 1;
        }
        s->fetch_rate_sum += tmp;

        SMC_STAT("checkpoint #%" PRIu64 ": dirty_pages %d "
                "transfered_pages %" PRIu64 " rate=%lf", mc.checkpoints,
                nr_dirty_pages, mc.total_copies, tmp);
        
        ret = smc_sync_notice_dest_to_recv(f_opaque, &glo_smc_info);
        if (ret) {
            SMC_ERR("smc_sync_notice_dest_to_recv() failed");
            goto err;
        }
#endif 

        s->total_time = end_time - start_time;
        s->xmit_time = end_time - xmit_start;
        /*
        s->bitmap_time = norm_mig_bitmap_time();
        s->log_dirty_time = norm_mig_log_dirty_time();
        s->mbps = MBPS(mc.slab_total, s->xmit_time);
        s->copy_mbps = MBPS(mc.slab_total, s->ram_copy_time);
        */
        s->bytes_xfer = mc.slab_total;
        s->checkpoints = ++(mc.checkpoints);

        wait_time = (s->xmit_time <= freq_ms) ? (freq_ms - s->xmit_time) : 0;
#ifdef SMC_PREFETCH
        if (wait_time >= SMC_PREFETCH_RECV_TIME) {
            wait_time -= SMC_PREFETCH_RECV_TIME;
        }
#endif

        flush_trace_buffer();

        /*
         * Checkpoint frequency in microseconds.
         *
         * Sometimes, when checkpoints are very large,
         * all of the wait time was dominated by the
         * time taken to copy the checkpoint into the staging area,
         * in which case wait_time, will probably be zero and we
         * will end up diving right back into the next checkpoint
         * as soon as the previous transmission completed.
         */
#ifdef SMC_PML_PREFETCH
        wait_time = wait_time / 2;
#endif
        if (wait_time) {
            SMC_LOG(GEN, "let VM run %" PRIu64 "ms", wait_time);
            s->nr_sleeps++;
            g_usleep(wait_time * 1000);
            s->total_wait_time += wait_time;
        }

#ifdef SMC_PML_PREFETCH
        glo_smc_info.need_clear_incheckpoint_bitmap = true;
        smc_pml_capture_dirty_pages(&mc,s);
        smc_pml_send_prefetch_info(f_opaque, &glo_smc_info);
        smc_pml_prefetch_pages_next_subset(&glo_smc_info);
#endif

        if (wait_time) {
            SMC_LOG(GEN, "after prefetch let VM run %" PRIu64 "ms", wait_time);
            s->nr_sleeps++;
            g_usleep(wait_time * 1000);
            s->total_wait_time += wait_time;
        }
        
        /* TODO: Maybe we should decrease the @wait_time to sleep to get time
         * for receiving the prefetched info.
         * We should decide if we have time to receive the prefetched pages info
         * or not according to the @wait_time.
         */

#ifdef SMC_PREFETCH
        ret = smc_recv_prefetch_info(f_opaque, &glo_smc_info, true);
        if (ret < 0) {
            SMC_ERR("smc_recv_prefetch_info() failed");
            goto err;
        }
#endif
        start_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
        if (start_time > end_time) {
            fetch_time = start_time - end_time;
            fetch_speed = smc_prefetch_pages_count(&glo_smc_info) / fetch_time;
            if (fetch_speed > s->fetch_speed) {
                s->fetch_speed = fetch_speed;
            }
        } else {
            fetch_time = 0;
        }
        SMC_LOG(GEN, "[SMC]bytes %ld xmit_time %" PRId64 " downtime %" PRIu64
                " ram_copy_time %" PRId64 " wait_time %" PRIu64
                " fetch_speed %d fetch_time %" PRId64
                " checkpoints %" PRId64 "\n",
                s->bytes_xfer, s->xmit_time, s->downtime, s->ram_copy_time,
                wait_time, fetch_speed, fetch_time, s->checkpoints);

        if (end_time >= initial_time + 1000) {
            printf("[SMC]bytes %ld xmit_time %" PRId64 " downtime %" PRIu64
                   " ram_copy_time %" PRId64 " wait_time %" PRIu64
                   " fetch_speed %d fetch_time %" PRId64
                   " checkpoints %" PRId64 "\n",
                   s->bytes_xfer, s->xmit_time, s->downtime, s->ram_copy_time,
                   wait_time, fetch_speed, fetch_time, s->checkpoints);
            initial_time = end_time;
        }
    }

    goto out;

err:
    /*
     * TODO: Verify that "disable_buffering" below does not release any traffic.
     */
    migrate_set_state(s, MIGRATION_STATUS_CHECKPOINTING, MIGRATION_STATUS_FAILED);
out:
    smc_exit(&glo_smc_info);

    if (mc_staging) {
        qemu_fclose(mc_staging);
    }

    if (mc_control) {
        qemu_fclose(mc_control);
    }

    mc_disable_buffering();

    local_err = NULL;
    if (blk_enabled) {
        blk_stop_replication(false, &local_err);
        if (local_err) {
            error_report_err(local_err);
        }
    }

    qemu_mutex_lock_iothread();

    if (s->state != MIGRATION_STATUS_FAILED) {
        migrate_set_state(s, MIGRATION_STATUS_CHECKPOINTING, MIGRATION_STATUS_COMPLETED);
    }

    qemu_bh_schedule(s->cleanup_bh);
    qemu_mutex_unlock_iothread();

    return NULL;
}

/*
 * Get the next copyset in the list. If there is none, then make one.
 */
static MCCopyset *mc_copy_next(MCParams *mc, MCCopyset *copyset)
{
    if (!QTAILQ_NEXT(copyset, node)) {
        int idx = mc->nb_copysets++;
        DDPRINTF("Extending copysets by one: %d sets total, "
                 "%" PRIu64 " MB\n", mc->nb_copysets,
                 mc->nb_copysets * sizeof(MCCopyset) / 1024UL / 1024UL);
        mc->curr_copyset = g_malloc(sizeof(MCCopyset));
        mc->curr_copyset->idx = idx;
        QTAILQ_INSERT_TAIL(&mc->copy_head, mc->curr_copyset, node);
        copyset = mc->curr_copyset;
    } else {
        DDPRINTF("Adding to existing copyset: %d sets total, "
                 "%" PRIu64 " MB\n", mc->nb_copysets,
                 mc->nb_copysets * sizeof(MCCopyset) / 1024UL / 1024UL);
        copyset = QTAILQ_NEXT(copyset, node);
    }

    mc->curr_copyset = copyset;
    copyset->nb_copies = 0;

    return copyset;
}

void mc_process_incoming_checkpoints_if_requested(QEMUFile *f)
{
    MCParams mc = { .file = f };
    MCSlab *slab;
    int fd = qemu_get_fd(f);
    void *f_opaque = qemu_file_get_opaque(f);
    QEMUFile *mc_control = NULL, *mc_staging = NULL;
    uint64_t checkpoint_size = 0, action, received = 0;
    uint64_t slabs = 0;
    int got, x, ret, nb_recv_prefetch_pages;
    bool checkpoint_received = 0;
    bool blk_enabled = false;
    Error *local_err = NULL;
    bool need_rollback = false;
    bool need_recv_prefetch_signal = true;

    CALC_MAX_STRIKES();

    if (!mc_requested) {
        DPRINTF("Source has not requested MC. Returning.\n");
        return;
    }

    smc_init(&glo_smc_info, f_opaque);

    if (!(mc_control = qemu_fopen_socket(fd, "wb"))) {
        fprintf(stderr, "Could not make incoming MC control channel\n");
        glo_smc_info.need_rollback = true;
        goto rollback;
    }

    if (!(mc_staging = qemu_fopen_mc(&mc, "rb"))) {
        fprintf(stderr, "Could not make outgoing MC staging area\n");
        glo_smc_info.need_rollback = true;
        goto rollback;
    }

    //qemu_set_block(fd);
    socket_set_nodelay(fd);

    DDPRINTF("Waiting for DISK message.\n");

    ret = mc_recv(f, MC_TRANSACTION_ANY, &action);
    if (ret < 0) {
        fprintf(stderr, "Nobody told us to setup the disk buffer yet.\n");
        goto out;
    }

    DDPRINTF("Got disk message.\n");
    if (action == MC_TRANSACTION_DISK_ENABLE) {
        blk_enabled = true;
        //qemu_mutex_lock_iothread();
        DPRINTF("starting disk replication.\n");
        blk_start_replication(false, &local_err);
        if (local_err) {
            fprintf(stderr, "Failed to setup disk replication.\n");
            qemu_mutex_unlock_iothread();
            goto out;
        }
        DDPRINTF("done starting disk replication.\n");
        //qemu_mutex_unlock_iothread();

        local_err = NULL;

        DDPRINTF("sending ack for disk replication.\n");
        if (mc_send(mc_control, MC_TRANSACTION_ACK) < 0) {
            fprintf(stderr, "Could not notify primary that disk buffer is ready.\n");
            goto out;
        }
    } else if (action == MC_TRANSACTION_DISK_DISABLE) {
        DDPRINTF("disk replication will be disabled.\n");
    } else {
        fprintf(stderr, "unknown message before checkpointing.\n");
        goto out;
    }

    while (true) {
        smc_set_state(&glo_smc_info, SMC_STATE_TRANSACTION_START);
        checkpoint_received = false;
        ret = mc_recv(f, MC_TRANSACTION_ANY, &action);
        if (ret < 0) {
            glo_smc_info.need_rollback = true;
            goto rollback;
        }

        switch(action) {
        case MC_TRANSACTION_START:
            checkpoint_size = qemu_get_be64(f);
            mc.start_copyset = qemu_get_be64(f);
            slabs = qemu_get_be64(f);

            DDPRINTF("Transaction start: size %" PRIu64
                     " copyset start: %" PRIu64 " slabs %" PRIu64 "\n",
                     checkpoint_size, mc.start_copyset, slabs);
            mc.pages_loaded = 0;

            if (qemu_file_get_error(f) < 0) {
                SMC_ERR("QEMUFile error while starting transaction, rollback");
                glo_smc_info.need_rollback = true;
                goto rollback;
            }
            assert(checkpoint_size);
            break;
        case MC_TRANSACTION_COMMIT: /* tcp */
            slab = mc_slab_start(&mc);
            received = 0;

            while (received < checkpoint_size) {
                int total = 0;
                slab->size = qemu_get_be64(f);

                DDPRINTF("Expecting size: %" PRIu64 "\n", slab->size);

                while (total != slab->size) {
                    got = qemu_get_buffer(f, slab->buf + total, slab->size - total);
                    if (got <= 0) {
                        fprintf(stderr, "Error pre-filling checkpoint: %d\n", got);
                        goto rollback;
                    }
                    received += got;
                    total += got;
                    DDPRINTF("Received %d slab %d / %ld received %d total %"
                             PRIu64 "\n", got, total, slab->size,
                             received, checkpoint_size);
                }

                if (received != checkpoint_size) {
                    slab = mc_slab_next(&mc, slab);
                }
            }

            DDPRINTF("Acknowledging successful commit\n");

            if (mc_send(mc_control, MC_TRANSACTION_ACK) < 0) {
                goto rollback;
            }

            checkpoint_received = true;
            break;
        case RAM_SAVE_FLAG_HOOK: /* rdma */
            /*
             * Must be RDMA registration handling. Preallocate
             * the slabs (if not already done in a previous checkpoint)
             * before allowing RDMA to register them.
             */
            slab = mc_slab_start(&mc);

            DDPRINTF("Pre-populating slabs %" PRIu64 "...\n", slabs);

            for(x = 1; x < slabs; x++) {
                slab = mc_slab_next(&mc, slab);
            }

            ram_control_load_hook(f, action);

            DDPRINTF("Hook complete.\n");

            slab = QTAILQ_FIRST(&mc.slab_head);

            for(x = 0; x < slabs; x++) {
                slab->size = qemu_get_be64(f);
                slab = QTAILQ_NEXT(slab, node);
            }

            if (qemu_file_get_error(f) < 0) {
                SMC_ERR("QEMUFile error while receiving checkpoint, rollback");
                glo_smc_info.need_rollback = true;
                goto rollback;
            }

            checkpoint_received = true;
            smc_set_state(&glo_smc_info, SMC_STATE_RECV_CHECKPOINT);
            break;
        default:
            fprintf(stderr, "Unknown MC action: %" PRIu64 "\n", action);
            glo_smc_info.need_rollback = true;
            goto rollback;
        }

        if (checkpoint_received) {
            /* Received dirty page set before parsing the checkpoint so that
             * the Src can continue as soon as possible.
             */
#ifdef SMC_PREFETCH
            if (smc_recv_dirty_info(f_opaque, &glo_smc_info)) {
                need_rollback = true;
                glo_smc_info.need_rollback = true;
                goto apply_checkpoint;
            }

            smc_update_prefetch_cache(&glo_smc_info);

            if (smc_sync_src_ready_to_recv(f_opaque, &glo_smc_info)) {
                need_rollback = true;
                glo_smc_info.need_rollback = true;
                goto apply_checkpoint;
            }

            if (smc_prefetch_dirty_pages(f_opaque, &glo_smc_info)) {
                need_rollback = true;
                glo_smc_info.need_rollback = true;
                goto apply_checkpoint;
            }
#endif
#ifdef SMC_PML_PREFETCH
            smc_pml_prefetch_pages_reset(&glo_smc_info);
            smc_pml_backup_pages_reset(&glo_smc_info);
            smc_pml_prefetched_map_reset(&glo_smc_info);

            if (need_recv_prefetch_signal) {
                ret = smc_pml_block_recv_prefetch_signal(f_opaque, 
                                                         &glo_smc_info);
                if (ret < 0) {
                    SMC_LOG(PML, "failed to recv prefetch signal");
                }
            }
            
            nb_recv_prefetch_pages = smc_pml_recv_prefetch_info(f_opaque, 
                                                            &glo_smc_info);
            if (nb_recv_prefetch_pages < 0) {
                need_rollback = true;
                glo_smc_info.need_rollback = true;
                goto apply_checkpoint;
            }
            ret = smc_pml_prefetch_dirty_pages(f_opaque, &glo_smc_info);
            if (ret < 0) {
                need_rollback = true;
                glo_smc_info.need_rollback = true;
                goto apply_checkpoint;
            }

            smc_set_state(&glo_smc_info, SMC_STATE_PREFETCH_DONE);
            smc_pml_prefetch_pages_next_subset(&glo_smc_info);
#endif

apply_checkpoint:
            SMC_LOG(PML, "start applying checkpoint.");
            mc.curr_slab = QTAILQ_FIRST(&mc.slab_head);
            mc.slab_total = checkpoint_size;

            DDPRINTF("Committed Loading MC state \n");

            mc_copy_start(&mc);

            if (qemu_loadvm_state(mc_staging) < 0) {
                fprintf(stderr, "loadvm transaction failed\n");
                /*
                 * This is fatal. No rollback possible because we have potentially
                 * applied only a subset of the checkpoint to main memory, potentially
                 * leaving the VM in an inconsistent state.
                 */
                goto err;
            }

            local_err = NULL;
            if (blk_enabled) {
                qemu_mutex_lock_iothread();
                blk_do_checkpoint(&local_err);
                qemu_mutex_unlock_iothread();
                if (local_err) {
                    goto out;
                }
            }

            mc.slab_total = checkpoint_size;

            DDPRINTF("Transaction complete. TCP pages: %" PRIu64 "\n", mc.pages_loaded);
            mc.checkpoints++;
            glo_smc_info.nr_checkpoints++;
            if (need_rollback) {
                goto rollback;
            }
        }
    }

rollback:
    fprintf(stderr, "MC: checkpointing stopped. Recovering VM\n");
    if (blk_enabled)
        blk_stop_replication(true, &local_err);
#ifdef SMC_PREFETCH
    smc_rollback_with_prefetch(&glo_smc_info);
#endif
#ifdef SMC_PML_PREFETCH
    smc_pml_rollback_with_prefetch(&glo_smc_info);
#endif
    goto out;
err:
    fprintf(stderr, "Micro Checkpointing Protocol Failed\n");
    if (blk_enabled)
        blk_stop_replication(false, &local_err);
    flush_trace_buffer();
    exit(1);
out:
    smc_exit(&glo_smc_info);

    if (local_err) {
        error_report_err(local_err);
    }
    if (mc_staging) {
        qemu_fclose(mc_staging);
    }

    if (mc_control) {
        qemu_fclose(mc_control);
    }
    flush_trace_buffer();
}

static int mc_get_buffer_internal(void *opaque, uint8_t *buf, int64_t pos,
                                  int size, MCSlab **curr_slab, uint64_t end_idx)
{
    uint64_t len = size;
    uint8_t *data = (uint8_t *) buf;
    MCSlab *slab = *curr_slab;
    MCParams *mc = opaque;

    assert(slab);

    DDDPRINTF("got request for %d bytes %p %p. idx %d\n",
              size, slab, QTAILQ_FIRST(&mc->slab_head), slab->idx);

    while (len && slab) {
        uint64_t get = MIN(slab->size - slab->read, len);

        memcpy(data, slab->buf + slab->read, get);

        data           += get;
        slab->read     += get;
        len            -= get;
        mc->slab_total -= get;

        DDDPRINTF("got: %" PRIu64 " read: %" PRIu64
                 " len %" PRIu64 " slab_total %" PRIu64
                 " size %" PRIu64 " addr: %p slab %d"
                 " requested %d\n",
                 get, slab->read, len, mc->slab_total,
                 slab->size, slab->buf, slab->idx, size);

        if (len) {
            if (slab->idx == end_idx) {
                break;
            }

            slab = QTAILQ_NEXT(slab, node);
        }
    }

    *curr_slab = slab;
    DDDPRINTF("Returning %" PRIu64 " / %d bytes\n", size - len, size);

    return size - len;
}

static int mc_get_buffer(void *opaque, uint8_t *buf, int64_t pos, int size)
{
    MCParams *mc = opaque;

    return mc_get_buffer_internal(mc, buf, pos, size, &mc->curr_slab,
                                  mc->start_copyset - 1);
}

static int mc_load_page(QEMUFile *f, void *opaque, void *host_addr, long size)
{
    MCParams *mc = opaque;

    DDDPRINTF("Loading page into %p of size %" PRIu64 "\n", host_addr, size);
    mc->pages_loaded++;

    return mc_get_buffer_internal(mc, host_addr, 0, size, &mc->mem_slab,
                                  mc->nb_slabs - 1);
}

static inline int smc_get_buffer_internal_stub(void *opaque, uint8_t *buf,
                                               int64_t pos,
                                               int size, MCSlab **curr_slab,
                                               uint64_t end_idx)
{
    uint64_t len = size;
    uint8_t *data = (uint8_t *) buf;
    MCSlab *slab = *curr_slab;
    MCParams *mc = opaque;

    while (len && slab) {
        uint64_t get = MIN(slab->size - slab->read, len);

        data           += get;
        slab->read     += get;
        len            -= get;
        mc->slab_total -= get;

        if (len) {
            if (slab->idx == end_idx) {
                break;
            }

            slab = QTAILQ_NEXT(slab, node);
        }
    }

    *curr_slab = slab;

    return size - len;
}

int smc_load_page_stub(QEMUFile *f, void *opaque, void *host_addr, long size)
{
    MCParams *mc = opaque;

    SMC_LOG(GEN, "skip copying a page");
    mc->pages_loaded++;
    return smc_get_buffer_internal_stub(mc, host_addr, 0, size, &mc->mem_slab,
                                        mc->nb_slabs - 1);
}

/*
 * Provide QEMUFile with an *local* RDMA-based way to do memcpy().
 * This lowers cache pollution and allows the CPU pipeline to
 * remain free for regular use by VMs (as well as by neighbors).
 *
 * In a future implementation, we may attempt to perform this
 * copy *without* stopping the source VM - if the data shows
 * that it can be done effectively.
 */
static int mc_save_page(QEMUFile *f, void *opaque,
                           ram_addr_t block_offset,
                           uint8_t *host_addr,
                           ram_addr_t offset,
                           long size, uint64_t *bytes_sent)
{
    MCParams *mc = opaque;
    MCCopyset *copyset = mc->curr_copyset;
    MCCopy *c;

    if (copyset->nb_copies >= MC_MAX_SLAB_COPY_DESCRIPTORS) {
        copyset = mc_copy_next(mc, copyset);
    }

    c = &copyset->copies[copyset->nb_copies++];
    c->ramblock_offset = (uint64_t) block_offset;
    c->host_addr = (uint64_t) (uintptr_t) host_addr;
    c->offset = (uint64_t) offset;
    c->size = (uint64_t) size;
    mc->total_copies++;

    return RAM_SAVE_CONTROL_DELAYED;
}

static ssize_t mc_writev_buffer(void *opaque, struct iovec *iov,
                                int iovcnt, int64_t pos)
{
    ssize_t len = 0;
    unsigned int i;

    for (i = 0; i < iovcnt; i++) {
        DDDPRINTF("iov # %d, len: %" PRId64 "\n", i, iov[i].iov_len);
        len += mc_put_buffer(opaque, iov[i].iov_base, 0, iov[i].iov_len);
    }

    return len;
}

static int mc_get_fd(void *opaque)
{
    MCParams *mc = opaque;

    return qemu_get_fd(mc->file);
}

static int mc_close(void *opaque)
{
    MCParams *mc = opaque;
    MCSlab *slab, *next;

    QTAILQ_FOREACH_SAFE(slab, &mc->slab_head, node, next) {
        ram_control_remove(mc->file, (uint64_t) (uintptr_t) slab->buf);
        QTAILQ_REMOVE(&mc->slab_head, slab, node);
        g_free(slab);
    }

    mc->curr_slab = NULL;

    return 0;
}
	
static const QEMUFileOps mc_write_ops = {
    .writev_buffer = mc_writev_buffer,
    .put_buffer = mc_put_buffer,
    .get_fd = mc_get_fd,
    .close = mc_close,
    .save_page = mc_save_page,
};

static const QEMUFileOps mc_read_ops = {
    .get_buffer = mc_get_buffer,
    .get_fd = mc_get_fd,
    .close = mc_close,
    .load_page = mc_load_page,
};

QEMUFile *qemu_fopen_mc(void *opaque, const char *mode)
{
    MCParams *mc = opaque;
    MCSlab *slab;
    MCCopyset *copyset;

    if (qemu_file_mode_is_not_valid(mode)) {
        return NULL;
    }

    QTAILQ_INIT(&mc->slab_head);
    QTAILQ_INIT(&mc->copy_head);

    slab = qemu_memalign(8, sizeof(MCSlab));
    memset(slab, 0, sizeof(*slab));
    slab->idx = 0;
    QTAILQ_INSERT_HEAD(&mc->slab_head, slab, node);
    mc->slab_total = 0;
    mc->curr_slab = slab;
    mc->nb_slabs = 1;
    mc->slab_strikes = 0;

    ram_control_add(mc->file, slab->buf, (uint64_t) (uintptr_t) slab->buf, MC_SLAB_BUFFER_SIZE);

    copyset = g_malloc(sizeof(MCCopyset));
    copyset->idx = 0;
    QTAILQ_INSERT_HEAD(&mc->copy_head, copyset, node);
    mc->total_copies = 0;
    mc->curr_copyset = copyset;
    mc->nb_copysets = 1;
    mc->copy_strikes = 0;

    if (mode[0] == 'w') {
        return qemu_fopen_ops(mc, &mc_write_ops);
    }

    return qemu_fopen_ops(mc, &mc_read_ops);
}

static void mc_start_checkpointer(void *opaque) {
    MigrationState *s = opaque;

    if (checkpoint_bh) {
        qemu_bh_delete(checkpoint_bh);
        checkpoint_bh = NULL;
    }

    qemu_mutex_unlock_iothread();
    qemu_thread_join(s->thread);
    g_free(s->thread);
    qemu_mutex_lock_iothread();

    migrate_set_state(s, MIGRATION_STATUS_ACTIVE, MIGRATION_STATUS_CHECKPOINTING);
    s->thread = g_malloc0(sizeof(*s->thread));
	qemu_thread_create(s->thread, "mc_thread", mc_thread, s, QEMU_THREAD_JOINABLE);
}

void mc_init_checkpointer(MigrationState *s)
{
    CALC_MAX_STRIKES();
    checkpoint_bh = qemu_bh_new(mc_start_checkpointer, s);
    qemu_bh_schedule(checkpoint_bh);
}

void qmp_migrate_set_mc_delay(int64_t value, Error **errp)
{
    freq_ms = value;
    CALC_MAX_STRIKES();
    DPRINTF("Setting checkpoint frequency to %" PRId64 " ms and "
            "resetting strikes to %d based on a %d sec delay.\n",
            freq_ms, max_strikes, max_strikes_delay_secs);
}

int mc_info_load(QEMUFile *f, void *opaque, int version_id)
{
    bool mc_enabled = qemu_get_byte(f);

    if (mc_enabled && !mc_requested) {
        DPRINTF("MC is requested\n");
        mc_requested = true;
    }

    max_strikes = qemu_get_be32(f);

    return 0;
}

void mc_info_save(QEMUFile *f, void *opaque)
{
    qemu_put_byte(f, migrate_use_mc());
    qemu_put_be32(f, max_strikes);
}

void mc_configure_net(MigrationState *s)
{
    int ret;

    if (s->enabled_capabilities[MIGRATION_CAPABILITY_MC_NET_DISABLE]) {
        return;
    }

    qemu_fflush(s->file);

    ret = mc_enable_buffering();

    if (ret > 0) {
        s->enabled_capabilities[MIGRATION_CAPABILITY_MC_NET_DISABLE] = true;
    } else {
        if (ret < 0 || mc_start_buffer() < 0) {
            migrate_set_state(s, MIGRATION_STATUS_ACTIVE, MIGRATION_STATUS_FAILED);
        }
    }
}

void mc_cheat_unregister_tce(DeviceState * d, const VMStateDescription *v, void *o) {
    static DeviceState *dev = NULL;
    static const VMStateDescription *vmsd = NULL;
    static void * opaque = NULL;

    if (d) {
        dev = d;
        vmsd = v;
        opaque = o;
    } else if (dev) {
        vmstate_unregister(dev, vmsd, opaque);
    }
}

void smc_print_stat(void)
{
    MigrationState *s = migrate_get_current();

    if (s->checkpoints == 0) {
        return;
    }
    printf("[SMC]Migration State: %s\n", MigrationStatus_lookup[s->state]);
    printf("[SMC]Frequency (ms): %" PRIu64 "\n", freq_ms);
    printf("[SMC]Num of Checkpoints: %" PRId64 "\n", s->checkpoints);
    printf("[SMC]Num of sleeps in MC: %" PRId64 "\n", s->nr_sleeps);
    printf("[SMC]Num of dirty pages: %" PRId64 "\n", s->nr_dirty_pages);
    printf("[SMC]Num of transfered pages: %" PRId64 "\n", s->nr_trans_pages);
    if (s->nr_dirty_pages) {
        printf("[SMC]Average valid prefetch rate: %lf\n",
               (s->nr_dirty_pages - s->nr_trans_pages) * 1.0 /
               s->nr_dirty_pages);
    }
    printf("[SMC]Valid prefetch rate average: %lf\n",
           s->fetch_rate_sum / s->checkpoints);
    if (s->checkpoints) {
        printf("[SMC]Average wait_time: %lf\n", s->total_wait_time * 1.0 /
               s->checkpoints);
    }
    printf("[SMC]Max prefetch speed (pages/ms): %d\n", s->fetch_speed);

    fflush(smc_log_file);
}
