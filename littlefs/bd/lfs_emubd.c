/*
 * Emulating block device, wraps filebd and rambd while providing a bunch
 * of hooks for testing littlefs in various conditions.
 *
 * Copyright (c) 2022, The littlefs authors.
 * Copyright (c) 2017, Arm Limited. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L
#endif

#include "bd/dbc_lfs_emubd.h"

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#endif


// access to lazily-allocated/copy-on-write blocks
//
// Note we can only modify a block if we have exclusive access to it (rc == 1)
//

static dbc_lfs_emubd_block_t *dbc_lfs_emubd_incblock(dbc_lfs_emubd_block_t *block) {
    if (block) {
        block->rc += 1;
    }
    return block;
}

static void dbc_lfs_emubd_decblock(dbc_lfs_emubd_block_t *block) {
    if (block) {
        block->rc -= 1;
        if (block->rc == 0) {
            free(block);
        }
    }
}

static dbc_lfs_emubd_block_t *dbc_lfs_emubd_mutblock(
        const struct dbc_lfs_config *cfg,
        dbc_lfs_emubd_block_t **block) {
    dbc_lfs_emubd_t *bd = cfg->context;
    dbc_lfs_emubd_block_t *block_ = *block;
    if (block_ && block_->rc == 1) {
        // rc == 1? can modify
        return block_;

    } else if (block_) {
        // rc > 1? need to create a copy
        dbc_lfs_emubd_block_t *nblock = malloc(
                sizeof(dbc_lfs_emubd_block_t) + bd->cfg->erase_size);
        if (!nblock) {
            return NULL;
        }

        memcpy(nblock, block_,
                sizeof(dbc_lfs_emubd_block_t) + bd->cfg->erase_size);
        nblock->rc = 1;

        dbc_lfs_emubd_decblock(block_);
        *block = nblock;
        return nblock;

    } else {
        // no block? need to allocate
        dbc_lfs_emubd_block_t *nblock = malloc(
                sizeof(dbc_lfs_emubd_block_t) + bd->cfg->erase_size);
        if (!nblock) {
            return NULL;
        }

        nblock->rc = 1;
        nblock->wear = 0;

        // zero for consistency
        memset(nblock->data,
                (bd->cfg->erase_value != -1) ? bd->cfg->erase_value : 0,
                bd->cfg->erase_size);

        *block = nblock;
        return nblock;
    }
}


// emubd create/destroy

int dbc_lfs_emubd_create(const struct dbc_lfs_config *cfg,
        const struct dbc_lfs_emubd_config *bdcfg) {
    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_create(%p {.context=%p, "
                ".read=%p, .prog=%p, .erase=%p, .sync=%p}, "
                "%p {.read_size=%"PRIu32", .prog_size=%"PRIu32", "
                ".erase_size=%"PRIu32", .erase_count=%"PRIu32", "
                ".erase_value=%"PRId32", .erase_cycles=%"PRIu32", "
                ".badblock_behavior=%"PRIu8", .power_cycles=%"PRIu32", "
                ".powerloss_behavior=%"PRIu8", .powerloss_cb=%p, "
                ".powerloss_data=%p, .track_branches=%d})",
            (void*)cfg, cfg->context,
            (void*)(uintptr_t)cfg->read, (void*)(uintptr_t)cfg->prog,
            (void*)(uintptr_t)cfg->erase, (void*)(uintptr_t)cfg->sync,
            (void*)bdcfg,
            bdcfg->read_size, bdcfg->prog_size, bdcfg->erase_size,
            bdcfg->erase_count, bdcfg->erase_value, bdcfg->erase_cycles,
            bdcfg->badblock_behavior, bdcfg->power_cycles,
            bdcfg->powerloss_behavior, (void*)(uintptr_t)bdcfg->powerloss_cb,
            bdcfg->powerloss_data, bdcfg->track_branches);
    dbc_lfs_emubd_t *bd = cfg->context;
    bd->cfg = bdcfg;

    // allocate our block array, all blocks start as uninitialized
    bd->blocks = malloc(bd->cfg->erase_count * sizeof(dbc_lfs_emubd_block_t*));
    if (!bd->blocks) {
        DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_create -> %d", DBC_LFS_ERR_NOMEM);
        return DBC_LFS_ERR_NOMEM;
    }
    memset(bd->blocks, 0, bd->cfg->erase_count * sizeof(dbc_lfs_emubd_block_t*));

    // setup testing things
    bd->readed = 0;
    bd->proged = 0;
    bd->erased = 0;
    bd->power_cycles = bd->cfg->power_cycles;
    bd->ooo_block = -1;
    bd->ooo_data = NULL;
    bd->disk = NULL;

    if (bd->cfg->disk_path) {
        bd->disk = malloc(sizeof(dbc_lfs_emubd_disk_t));
        if (!bd->disk) {
            DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_create -> %d", DBC_LFS_ERR_NOMEM);
            return DBC_LFS_ERR_NOMEM;
        }
        bd->disk->rc = 1;
        bd->disk->scratch = NULL;

        #ifdef _WIN32
        bd->disk->fd = open(bd->cfg->disk_path,
                O_RDWR | O_CREAT | O_BINARY, 0666);
        #else
        bd->disk->fd = open(bd->cfg->disk_path,
                O_RDWR | O_CREAT, 0666);
        #endif
        if (bd->disk->fd < 0) {
            int err = -errno;
            DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_create -> %d", err);
            return err;
        }

        // if we're emulating erase values, we can keep a block around in
        // memory of just the erase state to speed up emulated erases
        if (bd->cfg->erase_value != -1) {
            bd->disk->scratch = malloc(bd->cfg->erase_size);
            if (!bd->disk->scratch) {
                DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_create -> %d", DBC_LFS_ERR_NOMEM);
                return DBC_LFS_ERR_NOMEM;
            }
            memset(bd->disk->scratch,
                    bd->cfg->erase_value,
                    bd->cfg->erase_size);

            // go ahead and erase all of the disk, otherwise the file will not
            // match our internal representation
            for (size_t i = 0; i < bd->cfg->erase_count; i++) {
                ssize_t res = write(bd->disk->fd,
                        bd->disk->scratch,
                        bd->cfg->erase_size);
                if (res < 0) {
                    int err = -errno;
                    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_create -> %d", err);
                    return err;
                }
            }
        }
    }

    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_create -> %d", 0);
    return 0;
}

int dbc_lfs_emubd_destroy(const struct dbc_lfs_config *cfg) {
    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_destroy(%p)", (void*)cfg);
    dbc_lfs_emubd_t *bd = cfg->context;

    // decrement reference counts
    for (dbc_lfs_block_t i = 0; i < bd->cfg->erase_count; i++) {
        dbc_lfs_emubd_decblock(bd->blocks[i]);
    }
    free(bd->blocks);

    // clean up other resources 
    dbc_lfs_emubd_decblock(bd->ooo_data);
    if (bd->disk) {
        bd->disk->rc -= 1;
        if (bd->disk->rc == 0) {
            close(bd->disk->fd);
            free(bd->disk->scratch);
            free(bd->disk);
        }
    }

    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_destroy -> %d", 0);
    return 0;
}


// powerloss hook
static int dbc_lfs_emubd_powerloss(const struct dbc_lfs_config *cfg) {
    dbc_lfs_emubd_t *bd = cfg->context;

    // emulate out-of-order writes?
    dbc_lfs_emubd_block_t *ooo_data = NULL;
    if (bd->cfg->powerloss_behavior == DBC_LFS_EMUBD_POWERLOSS_OOO
            && bd->ooo_block != -1) {
        // since writes between syncs are allowed to be out-of-order, it
        // shouldn't hurt to restore the first write on powerloss, right?
        ooo_data = bd->blocks[bd->ooo_block];
        bd->blocks[bd->ooo_block] = dbc_lfs_emubd_incblock(bd->ooo_data);

        // mirror to disk file?
        if (bd->disk
                && (bd->blocks[bd->ooo_block]
                    || bd->cfg->erase_value != -1)) {
            off_t res1 = lseek(bd->disk->fd,
                    (off_t)bd->ooo_block*bd->cfg->erase_size,
                    SEEK_SET);
            if (res1 < 0) {
                return -errno;
            }

            ssize_t res2 = write(bd->disk->fd,
                    (bd->blocks[bd->ooo_block])
                        ? bd->blocks[bd->ooo_block]->data
                        : bd->disk->scratch,
                    bd->cfg->erase_size);
            if (res2 < 0) {
                return -errno;
            }
        }
    }

    // simulate power loss
    bd->cfg->powerloss_cb(bd->cfg->powerloss_data);

    // if we continue, undo out-of-order write emulation
    if (bd->cfg->powerloss_behavior == DBC_LFS_EMUBD_POWERLOSS_OOO
            && bd->ooo_block != -1) {
        dbc_lfs_emubd_decblock(bd->blocks[bd->ooo_block]);
        bd->blocks[bd->ooo_block] = ooo_data;

        // mirror to disk file?
        if (bd->disk
                && (bd->blocks[bd->ooo_block]
                    || bd->cfg->erase_value != -1)) {
            off_t res1 = lseek(bd->disk->fd,
                    (off_t)bd->ooo_block*bd->cfg->erase_size,
                    SEEK_SET);
            if (res1 < 0) {
                return -errno;
            }

            ssize_t res2 = write(bd->disk->fd,
                    (bd->blocks[bd->ooo_block])
                        ? bd->blocks[bd->ooo_block]->data
                        : bd->disk->scratch,
                    bd->cfg->erase_size);
            if (res2 < 0) {
                return -errno;
            }
        }
    }

    return 0;
}


// block device API

int dbc_lfs_emubd_read(const struct dbc_lfs_config *cfg, dbc_lfs_block_t block,
        dbc_lfs_off_t off, void *buffer, dbc_lfs_size_t size) {
    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_read(%p, "
                "0x%"PRIx32", %"PRIu32", %p, %"PRIu32")",
            (void*)cfg, block, off, buffer, size);
    dbc_lfs_emubd_t *bd = cfg->context;

    // check if read is valid
    DBC_LFS_ASSERT(block < bd->cfg->erase_count);
    DBC_LFS_ASSERT(off  % bd->cfg->read_size == 0);
    DBC_LFS_ASSERT(size % bd->cfg->read_size == 0);
    DBC_LFS_ASSERT(off+size <= bd->cfg->erase_size);

    // get the block
    const dbc_lfs_emubd_block_t *b = bd->blocks[block];
    if (b) {
        // block bad?
        if (bd->cfg->erase_cycles && b->wear >= bd->cfg->erase_cycles &&
                bd->cfg->badblock_behavior == DBC_LFS_EMUBD_BADBLOCK_READERROR) {
            DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_read -> %d", DBC_LFS_ERR_CORRUPT);
            return DBC_LFS_ERR_CORRUPT;
        }

        // read data
        memcpy(buffer, &b->data[off], size);
    } else {
        // zero for consistency
        memset(buffer,
                (bd->cfg->erase_value != -1) ? bd->cfg->erase_value : 0,
                size);
    }   

    // track reads
    bd->readed += size;
    if (bd->cfg->read_sleep) {
        int err = nanosleep(&(struct timespec){
                .tv_sec=bd->cfg->read_sleep/1000000000,
                .tv_nsec=bd->cfg->read_sleep%1000000000},
            NULL);
        if (err) {
            err = -errno;
            DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_read -> %d", err);
            return err;
        }
    }

    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_read -> %d", 0);
    return 0;
}

int dbc_lfs_emubd_prog(const struct dbc_lfs_config *cfg, dbc_lfs_block_t block,
        dbc_lfs_off_t off, const void *buffer, dbc_lfs_size_t size) {
    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_prog(%p, "
                "0x%"PRIx32", %"PRIu32", %p, %"PRIu32")",
            (void*)cfg, block, off, buffer, size);
    dbc_lfs_emubd_t *bd = cfg->context;

    // check if write is valid
    DBC_LFS_ASSERT(block < bd->cfg->erase_count);
    DBC_LFS_ASSERT(off  % bd->cfg->prog_size == 0);
    DBC_LFS_ASSERT(size % bd->cfg->prog_size == 0);
    DBC_LFS_ASSERT(off+size <= bd->cfg->erase_size);

    // get the block
    dbc_lfs_emubd_block_t *b = dbc_lfs_emubd_mutblock(cfg, &bd->blocks[block]);
    if (!b) {
        DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_prog -> %d", DBC_LFS_ERR_NOMEM);
        return DBC_LFS_ERR_NOMEM;
    }

    // block bad?
    if (bd->cfg->erase_cycles && b->wear >= bd->cfg->erase_cycles) {
        if (bd->cfg->badblock_behavior ==
                DBC_LFS_EMUBD_BADBLOCK_PROGERROR) {
            DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_prog -> %d", DBC_LFS_ERR_CORRUPT);
            return DBC_LFS_ERR_CORRUPT;
        } else if (bd->cfg->badblock_behavior ==
                DBC_LFS_EMUBD_BADBLOCK_PROGNOOP ||
                bd->cfg->badblock_behavior ==
                DBC_LFS_EMUBD_BADBLOCK_ERASENOOP) {
            DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_prog -> %d", 0);
            return 0;
        }
    }

    // were we erased properly?
    if (bd->cfg->erase_value != -1) {
        for (dbc_lfs_off_t i = 0; i < size; i++) {
            DBC_LFS_ASSERT(b->data[off+i] == bd->cfg->erase_value);
        }
    }

    // prog data
    memcpy(&b->data[off], buffer, size);

    // mirror to disk file?
    if (bd->disk) {
        off_t res1 = lseek(bd->disk->fd,
                (off_t)block*bd->cfg->erase_size + (off_t)off,
                SEEK_SET);
        if (res1 < 0) {
            int err = -errno;
            DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_prog -> %d", err);
            return err;
        }

        ssize_t res2 = write(bd->disk->fd, buffer, size);
        if (res2 < 0) {
            int err = -errno;
            DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_prog -> %d", err);
            return err;
        }
    }

    // track progs
    bd->proged += size;
    if (bd->cfg->prog_sleep) {
        int err = nanosleep(&(struct timespec){
                .tv_sec=bd->cfg->prog_sleep/1000000000,
                .tv_nsec=bd->cfg->prog_sleep%1000000000},
            NULL);
        if (err) {
            err = -errno;
            DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_prog -> %d", err);
            return err;
        }
    }

    // lose power?
    if (bd->power_cycles > 0) {
        bd->power_cycles -= 1;
        if (bd->power_cycles == 0) {
            int err = dbc_lfs_emubd_powerloss(cfg);
            if (err) {
                DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_prog -> %d", err);
                return err;
            }
        }
    }

    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_prog -> %d", 0);
    return 0;
}

int dbc_lfs_emubd_erase(const struct dbc_lfs_config *cfg, dbc_lfs_block_t block) {
    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_erase(%p, 0x%"PRIx32" (%"PRIu32"))",
            (void*)cfg, block, ((dbc_lfs_emubd_t*)cfg->context)->cfg->erase_size);
    dbc_lfs_emubd_t *bd = cfg->context;

    // check if erase is valid
    DBC_LFS_ASSERT(block < bd->cfg->erase_count);

    // emulate out-of-order writes? save first write
    if (bd->cfg->powerloss_behavior == DBC_LFS_EMUBD_POWERLOSS_OOO
            && bd->ooo_block == -1) {
        bd->ooo_block = block;
        bd->ooo_data = dbc_lfs_emubd_incblock(bd->blocks[block]);
    }

    // get the block
    dbc_lfs_emubd_block_t *b = dbc_lfs_emubd_mutblock(cfg, &bd->blocks[block]);
    if (!b) {
        DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_erase -> %d", DBC_LFS_ERR_NOMEM);
        return DBC_LFS_ERR_NOMEM;
    }

    // block bad?
    if (bd->cfg->erase_cycles) {
        if (b->wear >= bd->cfg->erase_cycles) {
            if (bd->cfg->badblock_behavior ==
                    DBC_LFS_EMUBD_BADBLOCK_ERASEERROR) {
                DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_erase -> %d", DBC_LFS_ERR_CORRUPT);
                return DBC_LFS_ERR_CORRUPT;
            } else if (bd->cfg->badblock_behavior ==
                    DBC_LFS_EMUBD_BADBLOCK_ERASENOOP) {
                DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_erase -> %d", 0);
                return 0;
            }
        } else {
            // mark wear
            b->wear += 1;
        }
    }

    // emulate an erase value?
    if (bd->cfg->erase_value != -1) {
        memset(b->data, bd->cfg->erase_value, bd->cfg->erase_size);

        // mirror to disk file?
        if (bd->disk) {
            off_t res1 = lseek(bd->disk->fd,
                    (off_t)block*bd->cfg->erase_size,
                    SEEK_SET);
            if (res1 < 0) {
                int err = -errno;
                DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_erase -> %d", err);
                return err;
            }

            ssize_t res2 = write(bd->disk->fd,
                    bd->disk->scratch,
                    bd->cfg->erase_size);
            if (res2 < 0) {
                int err = -errno;
                DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_erase -> %d", err);
                return err;
            }
        }
    }

    // track erases
    bd->erased += bd->cfg->erase_size;
    if (bd->cfg->erase_sleep) {
        int err = nanosleep(&(struct timespec){
                .tv_sec=bd->cfg->erase_sleep/1000000000,
                .tv_nsec=bd->cfg->erase_sleep%1000000000},
            NULL);
        if (err) {
            err = -errno;
            DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_erase -> %d", err);
            return err;
        }
    }

    // lose power?
    if (bd->power_cycles > 0) {
        bd->power_cycles -= 1;
        if (bd->power_cycles == 0) {
            int err = dbc_lfs_emubd_powerloss(cfg);
            if (err) {
                DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_erase -> %d", err);
                return err;
            }
        }
    }

    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_erase -> %d", 0);
    return 0;
}

int dbc_lfs_emubd_sync(const struct dbc_lfs_config *cfg) {
    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_sync(%p)", (void*)cfg);
    dbc_lfs_emubd_t *bd = cfg->context;

    // emulate out-of-order writes? reset first write, writes
    // cannot be out-of-order across sync
    if (bd->cfg->powerloss_behavior == DBC_LFS_EMUBD_POWERLOSS_OOO) {
        dbc_lfs_emubd_decblock(bd->ooo_data);
        bd->ooo_block = -1;
        bd->ooo_data = NULL;
    }

    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_sync -> %d", 0);
    return 0;
}


/// Additional extended API for driving test features ///

static int dbc_lfs_emubd_crc_(const struct dbc_lfs_config *cfg,
        dbc_lfs_block_t block, uint32_t *crc) {
    dbc_lfs_emubd_t *bd = cfg->context;

    // check if crc is valid
    DBC_LFS_ASSERT(block < cfg->block_count);

    // crc the block
    uint32_t crc_ = 0xffffffff;
    const dbc_lfs_emubd_block_t *b = bd->blocks[block];
    if (b) {
        crc_ = dbc_lfs_crc(crc_, b->data, cfg->block_size);
    } else {
        uint8_t erase_value = (bd->cfg->erase_value != -1)
                ? bd->cfg->erase_value
                : 0;
        for (dbc_lfs_size_t i = 0; i < cfg->block_size; i++) {
            crc_ = dbc_lfs_crc(crc_, &erase_value, 1);
        }
    }
    *crc = 0xffffffff ^ crc_;

    return 0;
}

int dbc_lfs_emubd_crc(const struct dbc_lfs_config *cfg,
        dbc_lfs_block_t block, uint32_t *crc) {
    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_crc(%p, %"PRIu32", %p)",
            (void*)cfg, block, crc);
    int err = dbc_lfs_emubd_crc_(cfg, block, crc);
    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_crc -> %d", err);
    return err;
}

int dbc_lfs_emubd_bdcrc(const struct dbc_lfs_config *cfg, uint32_t *crc) {
    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_bdcrc(%p, %p)", (void*)cfg, crc);

    uint32_t crc_ = 0xffffffff;
    for (dbc_lfs_block_t i = 0; i < cfg->block_count; i++) {
        uint32_t i_crc;
        int err = dbc_lfs_emubd_crc_(cfg, i, &i_crc);
        if (err) {
            DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_bdcrc -> %d", err);
            return err;
        }

        crc_ = dbc_lfs_crc(crc_, &i_crc, sizeof(uint32_t));
    }
    *crc = 0xffffffff ^ crc_;

    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_bdcrc -> %d", 0);
    return 0;
}

dbc_lfs_emubd_sio_t dbc_lfs_emubd_readed(const struct dbc_lfs_config *cfg) {
    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_readed(%p)", (void*)cfg);
    dbc_lfs_emubd_t *bd = cfg->context;
    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_readed -> %"PRIu64, bd->readed);
    return bd->readed;
}

dbc_lfs_emubd_sio_t dbc_lfs_emubd_proged(const struct dbc_lfs_config *cfg) {
    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_proged(%p)", (void*)cfg);
    dbc_lfs_emubd_t *bd = cfg->context;
    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_proged -> %"PRIu64, bd->proged);
    return bd->proged;
}

dbc_lfs_emubd_sio_t dbc_lfs_emubd_erased(const struct dbc_lfs_config *cfg) {
    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_erased(%p)", (void*)cfg);
    dbc_lfs_emubd_t *bd = cfg->context;
    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_erased -> %"PRIu64, bd->erased);
    return bd->erased;
}

int dbc_lfs_emubd_setreaded(const struct dbc_lfs_config *cfg, dbc_lfs_emubd_io_t readed) {
    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_setreaded(%p, %"PRIu64")", (void*)cfg, readed);
    dbc_lfs_emubd_t *bd = cfg->context;
    bd->readed = readed;
    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_setreaded -> %d", 0);
    return 0;
}

int dbc_lfs_emubd_setproged(const struct dbc_lfs_config *cfg, dbc_lfs_emubd_io_t proged) {
    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_setproged(%p, %"PRIu64")", (void*)cfg, proged);
    dbc_lfs_emubd_t *bd = cfg->context;
    bd->proged = proged;
    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_setproged -> %d", 0);
    return 0;
}

int dbc_lfs_emubd_seterased(const struct dbc_lfs_config *cfg, dbc_lfs_emubd_io_t erased) {
    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_seterased(%p, %"PRIu64")", (void*)cfg, erased);
    dbc_lfs_emubd_t *bd = cfg->context;
    bd->erased = erased;
    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_seterased -> %d", 0);
    return 0;
}

dbc_lfs_emubd_swear_t dbc_lfs_emubd_wear(const struct dbc_lfs_config *cfg,
        dbc_lfs_block_t block) {
    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_wear(%p, %"PRIu32")", (void*)cfg, block);
    dbc_lfs_emubd_t *bd = cfg->context;

    // check if block is valid
    DBC_LFS_ASSERT(block < bd->cfg->erase_count);

    // get the wear
    dbc_lfs_emubd_wear_t wear;
    const dbc_lfs_emubd_block_t *b = bd->blocks[block];
    if (b) {
        wear = b->wear;
    } else {
        wear = 0;
    }

    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_wear -> %"PRIi32, wear);
    return wear;
}

int dbc_lfs_emubd_setwear(const struct dbc_lfs_config *cfg,
        dbc_lfs_block_t block, dbc_lfs_emubd_wear_t wear) {
    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_setwear(%p, %"PRIu32", %"PRIi32")",
            (void*)cfg, block, wear);
    dbc_lfs_emubd_t *bd = cfg->context;

    // check if block is valid
    DBC_LFS_ASSERT(block < bd->cfg->erase_count);

    // set the wear
    dbc_lfs_emubd_block_t *b = dbc_lfs_emubd_mutblock(cfg, &bd->blocks[block]);
    if (!b) {
        DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_setwear -> %d", DBC_LFS_ERR_NOMEM);
        return DBC_LFS_ERR_NOMEM;
    }
    b->wear = wear;

    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_setwear -> %d", 0);
    return 0;
}

dbc_lfs_emubd_spowercycles_t dbc_lfs_emubd_powercycles(
        const struct dbc_lfs_config *cfg) {
    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_powercycles(%p)", (void*)cfg);
    dbc_lfs_emubd_t *bd = cfg->context;

    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_powercycles -> %"PRIi32, bd->power_cycles);
    return bd->power_cycles;
}

int dbc_lfs_emubd_setpowercycles(const struct dbc_lfs_config *cfg,
        dbc_lfs_emubd_powercycles_t power_cycles) {
    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_setpowercycles(%p, %"PRIi32")",
            (void*)cfg, power_cycles);
    dbc_lfs_emubd_t *bd = cfg->context;

    bd->power_cycles = power_cycles;

    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_powercycles -> %d", 0);
    return 0;
}

int dbc_lfs_emubd_copy(const struct dbc_lfs_config *cfg, dbc_lfs_emubd_t *copy) {
    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_copy(%p, %p)", (void*)cfg, (void*)copy);
    dbc_lfs_emubd_t *bd = cfg->context;

    // lazily copy over our block array
    copy->blocks = malloc(bd->cfg->erase_count * sizeof(dbc_lfs_emubd_block_t*));
    if (!copy->blocks) {
        DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_copy -> %d", DBC_LFS_ERR_NOMEM);
        return DBC_LFS_ERR_NOMEM;
    }

    for (size_t i = 0; i < bd->cfg->erase_count; i++) {
        copy->blocks[i] = dbc_lfs_emubd_incblock(bd->blocks[i]);
    }

    // other state
    copy->readed = bd->readed;
    copy->proged = bd->proged;
    copy->erased = bd->erased;
    copy->power_cycles = bd->power_cycles;
    copy->ooo_block = bd->ooo_block;
    copy->ooo_data = dbc_lfs_emubd_incblock(bd->ooo_data);
    copy->disk = bd->disk;
    if (copy->disk) {
        copy->disk->rc += 1;
    }
    copy->cfg = bd->cfg;

    DBC_LFS_EMUBD_TRACE("dbc_lfs_emubd_copy -> %d", 0);
    return 0;
}

