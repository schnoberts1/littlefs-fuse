/*
 * Block device emulated in a file
 *
 * Copyright (c) 2022, The littlefs authors.
 * Copyright (c) 2017, Arm Limited. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bd/lfs_filebd.h"

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#endif

int dbc_lfs_filebd_create(const struct dbc_lfs_config *cfg, const char *path,
        const struct dbc_lfs_filebd_config *bdcfg) {
    DBC_LFS_FILEBD_TRACE("dbc_lfs_filebd_create(%p {.context=%p, "
                ".read=%p, .prog=%p, .erase=%p, .sync=%p}, "
                "\"%s\", "
                "%p {.read_size=%"PRIu32", .prog_size=%"PRIu32", "
                ".erase_size=%"PRIu32", .erase_count=%"PRIu32"})",
            (void*)cfg, cfg->context,
            (void*)(uintptr_t)cfg->read, (void*)(uintptr_t)cfg->prog,
            (void*)(uintptr_t)cfg->erase, (void*)(uintptr_t)cfg->sync,
            path,
            (void*)bdcfg,
            bdcfg->read_size, bdcfg->prog_size, bdcfg->erase_size,
            bdcfg->erase_count);
    dbc_lfs_filebd_t *bd = cfg->context;
    bd->cfg = bdcfg;

    // open file
    #ifdef _WIN32
    bd->fd = open(path, O_RDWR | O_CREAT | O_BINARY, 0666);
    #else
    bd->fd = open(path, O_RDWR | O_CREAT, 0666);
    #endif

    if (bd->fd < 0) {
        int err = -errno;
        DBC_LFS_FILEBD_TRACE("dbc_lfs_filebd_create -> %d", err);
        return err;
    }

    DBC_LFS_FILEBD_TRACE("dbc_lfs_filebd_create -> %d", 0);
    return 0;
}

int dbc_lfs_filebd_destroy(const struct dbc_lfs_config *cfg) {
    DBC_LFS_FILEBD_TRACE("dbc_lfs_filebd_destroy(%p)", (void*)cfg);
    dbc_lfs_filebd_t *bd = cfg->context;
    int err = close(bd->fd);
    if (err < 0) {
        err = -errno;
        DBC_LFS_FILEBD_TRACE("dbc_lfs_filebd_destroy -> %d", err);
        return err;
    }
    DBC_LFS_FILEBD_TRACE("dbc_lfs_filebd_destroy -> %d", 0);
    return 0;
}

int dbc_lfs_filebd_read(const struct dbc_lfs_config *cfg, dbc_lfs_block_t block,
        dbc_lfs_off_t off, void *buffer, dbc_lfs_size_t size) {
    DBC_LFS_FILEBD_TRACE("dbc_lfs_filebd_read(%p, "
                "0x%"PRIx32", %"PRIu32", %p, %"PRIu32")",
            (void*)cfg, block, off, buffer, size);
    dbc_lfs_filebd_t *bd = cfg->context;

    // check if read is valid
    DBC_LFS_ASSERT(block < bd->cfg->erase_count);
    DBC_LFS_ASSERT(off  % bd->cfg->read_size == 0);
    DBC_LFS_ASSERT(size % bd->cfg->read_size == 0);
    DBC_LFS_ASSERT(off+size <= bd->cfg->erase_size);

    // zero for reproducibility (in case file is truncated)
    memset(buffer, 0, size);

    // read
    off_t res1 = lseek(bd->fd,
            (off_t)block*bd->cfg->erase_size + (off_t)off, SEEK_SET);
    if (res1 < 0) {
        int err = -errno;
        DBC_LFS_FILEBD_TRACE("dbc_lfs_filebd_read -> %d", err);
        return err;
    }

    ssize_t res2 = read(bd->fd, buffer, size);
    if (res2 < 0) {
        int err = -errno;
        DBC_LFS_FILEBD_TRACE("dbc_lfs_filebd_read -> %d", err);
        return err;
    }

    DBC_LFS_FILEBD_TRACE("dbc_lfs_filebd_read -> %d", 0);
    return 0;
}

int dbc_lfs_filebd_prog(const struct dbc_lfs_config *cfg, dbc_lfs_block_t block,
        dbc_lfs_off_t off, const void *buffer, dbc_lfs_size_t size) {
    DBC_LFS_FILEBD_TRACE("dbc_lfs_filebd_prog(%p, "
                "0x%"PRIx32", %"PRIu32", %p, %"PRIu32")",
            (void*)cfg, block, off, buffer, size);
    dbc_lfs_filebd_t *bd = cfg->context;

    // check if write is valid
    DBC_LFS_ASSERT(block < bd->cfg->erase_count);
    DBC_LFS_ASSERT(off  % bd->cfg->prog_size == 0);
    DBC_LFS_ASSERT(size % bd->cfg->prog_size == 0);
    DBC_LFS_ASSERT(off+size <= bd->cfg->erase_size);

    // program data
    off_t res1 = lseek(bd->fd,
            (off_t)block*bd->cfg->erase_size + (off_t)off, SEEK_SET);
    if (res1 < 0) {
        int err = -errno;
        DBC_LFS_FILEBD_TRACE("dbc_lfs_filebd_prog -> %d", err);
        return err;
    }

    ssize_t res2 = write(bd->fd, buffer, size);
    if (res2 < 0) {
        int err = -errno;
        DBC_LFS_FILEBD_TRACE("dbc_lfs_filebd_prog -> %d", err);
        return err;
    }

    DBC_LFS_FILEBD_TRACE("dbc_lfs_filebd_prog -> %d", 0);
    return 0;
}

int dbc_lfs_filebd_erase(const struct dbc_lfs_config *cfg, dbc_lfs_block_t block) {
    DBC_LFS_FILEBD_TRACE("dbc_lfs_filebd_erase(%p, 0x%"PRIx32" (%"PRIu32"))",
            (void*)cfg, block, ((dbc_lfs_file_t*)cfg->context)->cfg->erase_size);
    dbc_lfs_filebd_t *bd = cfg->context;

    // check if erase is valid
    DBC_LFS_ASSERT(block < bd->cfg->erase_count);

    // erase is a noop
    (void)block;

    DBC_LFS_FILEBD_TRACE("dbc_lfs_filebd_erase -> %d", 0);
    return 0;
}

int dbc_lfs_filebd_sync(const struct dbc_lfs_config *cfg) {
    DBC_LFS_FILEBD_TRACE("dbc_lfs_filebd_sync(%p)", (void*)cfg);

    // file sync
    dbc_lfs_filebd_t *bd = cfg->context;
    #ifdef _WIN32
    int err = FlushFileBuffers((HANDLE) _get_osfhandle(bd->fd)) ? 0 : -1;
    #else
    int err = fsync(bd->fd);
    #endif
    if (err) {
        err = -errno;
        DBC_LFS_FILEBD_TRACE("dbc_lfs_filebd_sync -> %d", 0);
        return err;
    }

    DBC_LFS_FILEBD_TRACE("dbc_lfs_filebd_sync -> %d", 0);
    return 0;
}
