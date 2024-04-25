/*
 * Block device emulated in RAM
 *
 * Copyright (c) 2022, The littlefs authors.
 * Copyright (c) 2017, Arm Limited. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bd/dbc_lfs_rambd.h"

int dbc_lfs_rambd_create(const struct dbc_lfs_config *cfg,
        const struct dbc_lfs_rambd_config *bdcfg) {
    DBC_LFS_RAMBD_TRACE("dbc_lfs_rambd_create(%p {.context=%p, "
                ".read=%p, .prog=%p, .erase=%p, .sync=%p}, "
                "%p {.read_size=%"PRIu32", .prog_size=%"PRIu32", "
                ".erase_size=%"PRIu32", .erase_count=%"PRIu32", "
                ".buffer=%p})",
            (void*)cfg, cfg->context,
            (void*)(uintptr_t)cfg->read, (void*)(uintptr_t)cfg->prog,
            (void*)(uintptr_t)cfg->erase, (void*)(uintptr_t)cfg->sync,
            (void*)bdcfg,
            bdcfg->read_size, bdcfg->prog_size, bdcfg->erase_size,
            bdcfg->erase_count, bdcfg->buffer);
    dbc_lfs_rambd_t *bd = cfg->context;
    bd->cfg = bdcfg;

    // allocate buffer?
    if (bd->cfg->buffer) {
        bd->buffer = bd->cfg->buffer;
    } else {
        bd->buffer = dbc_lfs_malloc(bd->cfg->erase_size * bd->cfg->erase_count);
        if (!bd->buffer) {
            DBC_LFS_RAMBD_TRACE("dbc_lfs_rambd_create -> %d", DBC_LFS_ERR_NOMEM);
            return DBC_LFS_ERR_NOMEM;
        }
    }

    // zero for reproducibility
    memset(bd->buffer, 0, bd->cfg->erase_size * bd->cfg->erase_count);

    DBC_LFS_RAMBD_TRACE("dbc_lfs_rambd_create -> %d", 0);
    return 0;
}

int dbc_lfs_rambd_destroy(const struct dbc_lfs_config *cfg) {
    DBC_LFS_RAMBD_TRACE("dbc_lfs_rambd_destroy(%p)", (void*)cfg);
    // clean up memory
    dbc_lfs_rambd_t *bd = cfg->context;
    if (!bd->cfg->buffer) {
        dbc_lfs_free(bd->buffer);
    }
    DBC_LFS_RAMBD_TRACE("dbc_lfs_rambd_destroy -> %d", 0);
    return 0;
}

int dbc_lfs_rambd_read(const struct dbc_lfs_config *cfg, dbc_lfs_block_t block,
        dbc_lfs_off_t off, void *buffer, dbc_lfs_size_t size) {
    DBC_LFS_RAMBD_TRACE("dbc_lfs_rambd_read(%p, "
                "0x%"PRIx32", %"PRIu32", %p, %"PRIu32")",
            (void*)cfg, block, off, buffer, size);
    dbc_lfs_rambd_t *bd = cfg->context;

    // check if read is valid
    DBC_LFS_ASSERT(block < bd->cfg->erase_count);
    DBC_LFS_ASSERT(off  % bd->cfg->read_size == 0);
    DBC_LFS_ASSERT(size % bd->cfg->read_size == 0);
    DBC_LFS_ASSERT(off+size <= bd->cfg->erase_size);

    // read data
    memcpy(buffer, &bd->buffer[block*bd->cfg->erase_size + off], size);

    DBC_LFS_RAMBD_TRACE("dbc_lfs_rambd_read -> %d", 0);
    return 0;
}

int dbc_lfs_rambd_prog(const struct dbc_lfs_config *cfg, dbc_lfs_block_t block,
        dbc_lfs_off_t off, const void *buffer, dbc_lfs_size_t size) {
    DBC_LFS_RAMBD_TRACE("dbc_lfs_rambd_prog(%p, "
                "0x%"PRIx32", %"PRIu32", %p, %"PRIu32")",
            (void*)cfg, block, off, buffer, size);
    dbc_lfs_rambd_t *bd = cfg->context;

    // check if write is valid
    DBC_LFS_ASSERT(block < bd->cfg->erase_count);
    DBC_LFS_ASSERT(off  % bd->cfg->prog_size == 0);
    DBC_LFS_ASSERT(size % bd->cfg->prog_size == 0);
    DBC_LFS_ASSERT(off+size <= bd->cfg->erase_size);

    // program data
    memcpy(&bd->buffer[block*bd->cfg->erase_size + off], buffer, size);

    DBC_LFS_RAMBD_TRACE("dbc_lfs_rambd_prog -> %d", 0);
    return 0;
}

int dbc_lfs_rambd_erase(const struct dbc_lfs_config *cfg, dbc_lfs_block_t block) {
    DBC_LFS_RAMBD_TRACE("dbc_lfs_rambd_erase(%p, 0x%"PRIx32" (%"PRIu32"))",
            (void*)cfg, block, ((dbc_lfs_rambd_t*)cfg->context)->cfg->erase_size);
    dbc_lfs_rambd_t *bd = cfg->context;

    // check if erase is valid
    DBC_LFS_ASSERT(block < bd->cfg->erase_count);

    // erase is a noop
    (void)block;

    DBC_LFS_RAMBD_TRACE("dbc_lfs_rambd_erase -> %d", 0);
    return 0;
}

int dbc_lfs_rambd_sync(const struct dbc_lfs_config *cfg) {
    DBC_LFS_RAMBD_TRACE("dbc_lfs_rambd_sync(%p)", (void*)cfg);

    // sync is a noop
    (void)cfg;

    DBC_LFS_RAMBD_TRACE("dbc_lfs_rambd_sync -> %d", 0);
    return 0;
}
