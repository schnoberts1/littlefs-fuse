/*
 * Block device emulated in a file
 *
 * Copyright (c) 2022, The littlefs authors.
 * Copyright (c) 2017, Arm Limited. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef DBC_LFS_FILEBD_H
#define DBC_LFS_FILEBD_H

#include "lfs.h"
#include "lfs_util.h"

#ifdef __cplusplus
extern "C"
{
#endif


// Block device specific tracing
#ifndef DBC_LFS_FILEBD_TRACE
#ifdef DBC_LFS_FILEBD_YES_TRACE
#define DBC_LFS_FILEBD_TRACE(...) DBC_LFS_TRACE(__VA_ARGS__)
#else
#define DBC_LFS_FILEBD_TRACE(...)
#endif
#endif

// filebd config
struct dbc_lfs_filebd_config {
    // Minimum size of a read operation in bytes.
    dbc_lfs_size_t read_size;

    // Minimum size of a program operation in bytes.
    dbc_lfs_size_t prog_size;

    // Size of an erase operation in bytes.
    dbc_lfs_size_t erase_size;

    // Number of erase blocks on the device.
    dbc_lfs_size_t erase_count;
};

// filebd state
typedef struct dbc_lfs_filebd {
    int fd;
    const struct dbc_lfs_filebd_config *cfg;
} dbc_lfs_filebd_t;


// Create a file block device
int dbc_lfs_filebd_create(const struct dbc_lfs_config *cfg, const char *path,
        const struct dbc_lfs_filebd_config *bdcfg);

// Clean up memory associated with block device
int dbc_lfs_filebd_destroy(const struct dbc_lfs_config *cfg);

// Read a block
int dbc_lfs_filebd_read(const struct dbc_lfs_config *cfg, dbc_lfs_block_t block,
        dbc_lfs_off_t off, void *buffer, dbc_lfs_size_t size);

// Program a block
//
// The block must have previously been erased.
int dbc_lfs_filebd_prog(const struct dbc_lfs_config *cfg, dbc_lfs_block_t block,
        dbc_lfs_off_t off, const void *buffer, dbc_lfs_size_t size);

// Erase a block
//
// A block must be erased before being programmed. The
// state of an erased block is undefined.
int dbc_lfs_filebd_erase(const struct dbc_lfs_config *cfg, dbc_lfs_block_t block);

// Sync the block device
int dbc_lfs_filebd_sync(const struct dbc_lfs_config *cfg);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
