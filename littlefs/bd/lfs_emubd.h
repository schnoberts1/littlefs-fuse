/*
 * Emulating block device, wraps filebd and rambd while providing a bunch
 * of hooks for testing littlefs in various conditions.
 *
 * Copyright (c) 2022, The littlefs authors.
 * Copyright (c) 2017, Arm Limited. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef DBC_LFS_EMUBD_H
#define DBC_LFS_EMUBD_H

#include "lfs.h"
#include "lfs_util.h"
#include "bd/lfs_rambd.h"
#include "bd/lfs_filebd.h"

#ifdef __cplusplus
extern "C"
{
#endif


// Block device specific tracing
#ifndef DBC_LFS_EMUBD_TRACE
#ifdef DBC_LFS_EMUBD_YES_TRACE
#define DBC_LFS_EMUBD_TRACE(...) DBC_LFS_TRACE(__VA_ARGS__)
#else
#define DBC_LFS_EMUBD_TRACE(...)
#endif
#endif

// Mode determining how "bad-blocks" behave during testing. This simulates
// some real-world circumstances such as progs not sticking (prog-noop),
// a readonly disk (erase-noop), and ECC failures (read-error).
//
// Not that read-noop is not allowed. Read _must_ return a consistent (but
// may be arbitrary) value on every read.
typedef enum dbc_lfs_emubd_badblock_behavior {
    DBC_LFS_EMUBD_BADBLOCK_PROGERROR  = 0, // Error on prog
    DBC_LFS_EMUBD_BADBLOCK_ERASEERROR = 1, // Error on erase
    DBC_LFS_EMUBD_BADBLOCK_READERROR  = 2, // Error on read
    DBC_LFS_EMUBD_BADBLOCK_PROGNOOP   = 3, // Prog does nothing silently
    DBC_LFS_EMUBD_BADBLOCK_ERASENOOP  = 4, // Erase does nothing silently
} dbc_lfs_emubd_badblock_behavior_t;

// Mode determining how power-loss behaves during testing. For now this
// only supports a noop behavior, leaving the data on-disk untouched.
typedef enum dbc_lfs_emubd_powerloss_behavior {
    DBC_LFS_EMUBD_POWERLOSS_NOOP = 0, // Progs are atomic
    DBC_LFS_EMUBD_POWERLOSS_OOO  = 1, // Blocks are written out-of-order
} dbc_lfs_emubd_powerloss_behavior_t;

// Type for measuring read/program/erase operations
typedef uint64_t dbc_lfs_emubd_io_t;
typedef int64_t dbc_lfs_emubd_sio_t;

// Type for measuring wear
typedef uint32_t dbc_lfs_emubd_wear_t;
typedef int32_t dbc_lfs_emubd_swear_t;

// Type for tracking power-cycles
typedef uint32_t dbc_lfs_emubd_powercycles_t;
typedef int32_t dbc_lfs_emubd_spowercycles_t;

// Type for delays in nanoseconds
typedef uint64_t dbc_lfs_emubd_sleep_t;
typedef int64_t dbc_lfs_emubd_ssleep_t;

// emubd config, this is required for testing
struct dbc_lfs_emubd_config {
    // Minimum size of a read operation in bytes.
    dbc_lfs_size_t read_size;

    // Minimum size of a program operation in bytes.
    dbc_lfs_size_t prog_size;

    // Size of an erase operation in bytes.
    dbc_lfs_size_t erase_size;

    // Number of erase blocks on the device.
    dbc_lfs_size_t erase_count;

    // 8-bit erase value to use for simulating erases. -1 does not simulate
    // erases, which can speed up testing by avoiding the extra block-device
    // operations to store the erase value.
    int32_t erase_value;

    // Number of erase cycles before a block becomes "bad". The exact behavior
    // of bad blocks is controlled by badblock_behavior.
    uint32_t erase_cycles;

    // The mode determining how bad-blocks fail
    dbc_lfs_emubd_badblock_behavior_t badblock_behavior;

    // Number of write operations (erase/prog) before triggering a power-loss.
    // power_cycles=0 disables this. The exact behavior of power-loss is
    // controlled by a combination of powerloss_behavior and powerloss_cb.
    dbc_lfs_emubd_powercycles_t power_cycles;

    // The mode determining how power-loss affects disk
    dbc_lfs_emubd_powerloss_behavior_t powerloss_behavior;

    // Function to call to emulate power-loss. The exact behavior of power-loss
    // is up to the runner to provide.
    void (*powerloss_cb)(void*);

    // Data for power-loss callback
    void *powerloss_data;

    // True to track when power-loss could have occured. Note this involves 
    // heavy memory usage!
    bool track_branches;

    // Path to file to use as a mirror of the disk. This provides a way to view
    // the current state of the block device.
    const char *disk_path;

    // Artificial delay in nanoseconds, there is no purpose for this other
    // than slowing down the simulation.
    dbc_lfs_emubd_sleep_t read_sleep;

    // Artificial delay in nanoseconds, there is no purpose for this other
    // than slowing down the simulation.
    dbc_lfs_emubd_sleep_t prog_sleep;

    // Artificial delay in nanoseconds, there is no purpose for this other
    // than slowing down the simulation.
    dbc_lfs_emubd_sleep_t erase_sleep;
};

// A reference counted block
typedef struct dbc_lfs_emubd_block {
    uint32_t rc;
    dbc_lfs_emubd_wear_t wear;

    uint8_t data[];
} dbc_lfs_emubd_block_t;

// Disk mirror
typedef struct dbc_lfs_emubd_disk {
    uint32_t rc;
    int fd;
    uint8_t *scratch;
} dbc_lfs_emubd_disk_t;

// emubd state
typedef struct dbc_lfs_emubd {
    // array of copy-on-write blocks
    dbc_lfs_emubd_block_t **blocks;

    // some other test state
    dbc_lfs_emubd_io_t readed;
    dbc_lfs_emubd_io_t proged;
    dbc_lfs_emubd_io_t erased;
    dbc_lfs_emubd_powercycles_t power_cycles;
    dbc_lfs_ssize_t ooo_block;
    dbc_lfs_emubd_block_t *ooo_data;
    dbc_lfs_emubd_disk_t *disk;

    const struct dbc_lfs_emubd_config *cfg;
} dbc_lfs_emubd_t;


/// Block device API ///

// Create an emulating block device using the geometry in dbc_lfs_config
int dbc_lfs_emubd_create(const struct dbc_lfs_config *cfg,
        const struct dbc_lfs_emubd_config *bdcfg);

// Clean up memory associated with block device
int dbc_lfs_emubd_destroy(const struct dbc_lfs_config *cfg);

// Read a block
int dbc_lfs_emubd_read(const struct dbc_lfs_config *cfg, dbc_lfs_block_t block,
        dbc_lfs_off_t off, void *buffer, dbc_lfs_size_t size);

// Program a block
//
// The block must have previously been erased.
int dbc_lfs_emubd_prog(const struct dbc_lfs_config *cfg, dbc_lfs_block_t block,
        dbc_lfs_off_t off, const void *buffer, dbc_lfs_size_t size);

// Erase a block
//
// A block must be erased before being programmed. The
// state of an erased block is undefined.
int dbc_lfs_emubd_erase(const struct dbc_lfs_config *cfg, dbc_lfs_block_t block);

// Sync the block device
int dbc_lfs_emubd_sync(const struct dbc_lfs_config *cfg);


/// Additional extended API for driving test features ///

// A CRC of a block for debugging purposes
int dbc_lfs_emubd_crc(const struct dbc_lfs_config *cfg,
        dbc_lfs_block_t block, uint32_t *crc);

// A CRC of the entire block device for debugging purposes
int dbc_lfs_emubd_bdcrc(const struct dbc_lfs_config *cfg, uint32_t *crc);

// Get total amount of bytes read
dbc_lfs_emubd_sio_t dbc_lfs_emubd_readed(const struct dbc_lfs_config *cfg);

// Get total amount of bytes programmed
dbc_lfs_emubd_sio_t dbc_lfs_emubd_proged(const struct dbc_lfs_config *cfg);

// Get total amount of bytes erased
dbc_lfs_emubd_sio_t dbc_lfs_emubd_erased(const struct dbc_lfs_config *cfg);

// Manually set amount of bytes read
int dbc_lfs_emubd_setreaded(const struct dbc_lfs_config *cfg, dbc_lfs_emubd_io_t readed);

// Manually set amount of bytes programmed
int dbc_lfs_emubd_setproged(const struct dbc_lfs_config *cfg, dbc_lfs_emubd_io_t proged);

// Manually set amount of bytes erased
int dbc_lfs_emubd_seterased(const struct dbc_lfs_config *cfg, dbc_lfs_emubd_io_t erased);

// Get simulated wear on a given block
dbc_lfs_emubd_swear_t dbc_lfs_emubd_wear(const struct dbc_lfs_config *cfg,
        dbc_lfs_block_t block);

// Manually set simulated wear on a given block
int dbc_lfs_emubd_setwear(const struct dbc_lfs_config *cfg,
        dbc_lfs_block_t block, dbc_lfs_emubd_wear_t wear);

// Get the remaining power-cycles
dbc_lfs_emubd_spowercycles_t dbc_lfs_emubd_powercycles(
        const struct dbc_lfs_config *cfg);

// Manually set the remaining power-cycles
int dbc_lfs_emubd_setpowercycles(const struct dbc_lfs_config *cfg,
        dbc_lfs_emubd_powercycles_t power_cycles);

// Create a copy-on-write copy of the state of this block device
int dbc_lfs_emubd_copy(const struct dbc_lfs_config *cfg, dbc_lfs_emubd_t *copy);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
