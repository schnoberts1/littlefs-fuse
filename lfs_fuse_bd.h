/*
 * Linux user-space block device wrapper
 *
 * Copyright (c) 2022, the littlefs authors.
 * Copyright (c) 2017, Arm Limited. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef DBC_LFS_FUSE_BD_H
#define DBC_LFS_FUSE_BD_H

#include "lfs.h"


// Create a block device with path to dev block device
int dbc_lfs_fuse_bd_create(struct dbc_lfs_config *cfg, const char *path);

// Clean up memory associated with emu block device
void dbc_lfs_fuse_bd_destroy(const struct dbc_lfs_config *cfg);

// Read a block
int dbc_lfs_fuse_bd_read(const struct dbc_lfs_config *cfg, dbc_lfs_block_t block,
        dbc_lfs_off_t off, void *buffer, dbc_lfs_size_t size);

// Program a block
//
// The block must have previously been erased.
int dbc_lfs_fuse_bd_prog(const struct dbc_lfs_config *cfg, dbc_lfs_block_t block,
        dbc_lfs_off_t off, const void *buffer, dbc_lfs_size_t size);

// Erase a block
//
// A block must be erased before being programmed. The
// state of an erased block is undefined.
int dbc_lfs_fuse_bd_erase(const struct dbc_lfs_config *cfg, dbc_lfs_block_t block);

// Sync the block device
int dbc_lfs_fuse_bd_sync(const struct dbc_lfs_config *cfg);


#endif
