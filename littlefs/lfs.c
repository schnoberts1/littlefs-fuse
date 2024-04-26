/*
 * The little filesystem
 *
 * Copyright (c) 2022, The littlefs authors.
 * Copyright (c) 2017, Arm Limited. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "lfs.h"
#include "lfs_util.h"


// some constants used throughout the code
#define DBC_LFS_BLOCK_NULL ((dbc_lfs_block_t)-1)
#define DBC_LFS_BLOCK_INLINE ((dbc_lfs_block_t)-2)

enum {
    DBC_LFS_OK_RELOCATED = 1,
    DBC_LFS_OK_DROPPED   = 2,
    DBC_LFS_OK_ORPHANED  = 3,
};

enum {
    DBC_LFS_CMP_EQ = 0,
    DBC_LFS_CMP_LT = 1,
    DBC_LFS_CMP_GT = 2,
};


/// Caching block device operations ///

static inline void dbc_lfs_cache_drop(dbc_lfs_t *lfs, dbc_lfs_cache_t *rcache) {
    // do not zero, cheaper if cache is readonly or only going to be
    // written with identical data (during relocates)
    (void)lfs;
    rcache->block = DBC_LFS_BLOCK_NULL;
}

static inline void dbc_lfs_cache_zero(dbc_lfs_t *lfs, dbc_lfs_cache_t *pcache) {
    // zero to avoid information leak
    memset(pcache->buffer, 0xff, lfs->cfg->cache_size);
    pcache->block = DBC_LFS_BLOCK_NULL;
}

static int dbc_lfs_bd_read(dbc_lfs_t *lfs,
        const dbc_lfs_cache_t *pcache, dbc_lfs_cache_t *rcache, dbc_lfs_size_t hint,
        dbc_lfs_block_t block, dbc_lfs_off_t off,
        void *buffer, dbc_lfs_size_t size) {
    uint8_t *data = buffer;
    if (off+size > lfs->cfg->block_size
            || (lfs->block_count && block >= lfs->block_count)) {
        return DBC_LFS_ERR_CORRUPT;
    }

    while (size > 0) {
        dbc_lfs_size_t diff = size;

        if (pcache && block == pcache->block &&
                off < pcache->off + pcache->size) {
            if (off >= pcache->off) {
                // is already in pcache?
                diff = dbc_lfs_min(diff, pcache->size - (off-pcache->off));
                memcpy(data, &pcache->buffer[off-pcache->off], diff);

                data += diff;
                off += diff;
                size -= diff;
                continue;
            }

            // pcache takes priority
            diff = dbc_lfs_min(diff, pcache->off-off);
        }

        if (block == rcache->block &&
                off < rcache->off + rcache->size) {
            if (off >= rcache->off) {
                // is already in rcache?
                diff = dbc_lfs_min(diff, rcache->size - (off-rcache->off));
                memcpy(data, &rcache->buffer[off-rcache->off], diff);

                data += diff;
                off += diff;
                size -= diff;
                continue;
            }

            // rcache takes priority
            diff = dbc_lfs_min(diff, rcache->off-off);
        }

        if (size >= hint && off % lfs->cfg->read_size == 0 &&
                size >= lfs->cfg->read_size) {
            // bypass cache?
            diff = dbc_lfs_aligndown(diff, lfs->cfg->read_size);
            int err = lfs->cfg->read(lfs->cfg, block, off, data, diff);
            if (err) {
                return err;
            }

            data += diff;
            off += diff;
            size -= diff;
            continue;
        }

        // load to cache, first condition can no longer fail
        DBC_LFS_ASSERT(!lfs->block_count || block < lfs->block_count);
        rcache->block = block;
        rcache->off = dbc_lfs_aligndown(off, lfs->cfg->read_size);
        rcache->size = dbc_lfs_min(
                dbc_lfs_min(
                    dbc_lfs_alignup(off+hint, lfs->cfg->read_size),
                    lfs->cfg->block_size)
                - rcache->off,
                lfs->cfg->cache_size);
        int err = lfs->cfg->read(lfs->cfg, rcache->block,
                rcache->off, rcache->buffer, rcache->size);
        DBC_LFS_ASSERT(err <= 0);
        if (err) {
            return err;
        }
    }

    return 0;
}

static int dbc_lfs_bd_cmp(dbc_lfs_t *lfs,
        const dbc_lfs_cache_t *pcache, dbc_lfs_cache_t *rcache, dbc_lfs_size_t hint,
        dbc_lfs_block_t block, dbc_lfs_off_t off,
        const void *buffer, dbc_lfs_size_t size) {
    const uint8_t *data = buffer;
    dbc_lfs_size_t diff = 0;

    for (dbc_lfs_off_t i = 0; i < size; i += diff) {
        uint8_t dat[8];

        diff = dbc_lfs_min(size-i, sizeof(dat));
        int err = dbc_lfs_bd_read(lfs,
                pcache, rcache, hint-i,
                block, off+i, &dat, diff);
        if (err) {
            return err;
        }

        int res = memcmp(dat, data + i, diff);
        if (res) {
            return res < 0 ? DBC_LFS_CMP_LT : DBC_LFS_CMP_GT;
        }
    }

    return DBC_LFS_CMP_EQ;
}

static int dbc_lfs_bd_crc(dbc_lfs_t *lfs,
        const dbc_lfs_cache_t *pcache, dbc_lfs_cache_t *rcache, dbc_lfs_size_t hint,
        dbc_lfs_block_t block, dbc_lfs_off_t off, dbc_lfs_size_t size, uint32_t *crc) {
    dbc_lfs_size_t diff = 0;

    for (dbc_lfs_off_t i = 0; i < size; i += diff) {
        uint8_t dat[8];
        diff = dbc_lfs_min(size-i, sizeof(dat));
        int err = dbc_lfs_bd_read(lfs,
                pcache, rcache, hint-i,
                block, off+i, &dat, diff);
        if (err) {
            return err;
        }

        *crc = dbc_lfs_crc(*crc, &dat, diff);
    }

    return 0;
}

#ifndef DBC_LFS_READONLY
static int dbc_lfs_bd_flush(dbc_lfs_t *lfs,
        dbc_lfs_cache_t *pcache, dbc_lfs_cache_t *rcache, bool validate) {
    if (pcache->block != DBC_LFS_BLOCK_NULL && pcache->block != DBC_LFS_BLOCK_INLINE) {
        DBC_LFS_ASSERT(pcache->block < lfs->block_count);
        dbc_lfs_size_t diff = dbc_lfs_alignup(pcache->size, lfs->cfg->prog_size);
        int err = lfs->cfg->prog(lfs->cfg, pcache->block,
                pcache->off, pcache->buffer, diff);
        DBC_LFS_ASSERT(err <= 0);
        if (err) {
            return err;
        }

        if (validate) {
            // check data on disk
            dbc_lfs_cache_drop(lfs, rcache);
            int res = dbc_lfs_bd_cmp(lfs,
                    NULL, rcache, diff,
                    pcache->block, pcache->off, pcache->buffer, diff);
            if (res < 0) {
                return res;
            }

            if (res != DBC_LFS_CMP_EQ) {
                return DBC_LFS_ERR_CORRUPT;
            }
        }

        dbc_lfs_cache_zero(lfs, pcache);
    }

    return 0;
}
#endif

#ifndef DBC_LFS_READONLY
static int dbc_lfs_bd_sync(dbc_lfs_t *lfs,
        dbc_lfs_cache_t *pcache, dbc_lfs_cache_t *rcache, bool validate) {
    dbc_lfs_cache_drop(lfs, rcache);

    int err = dbc_lfs_bd_flush(lfs, pcache, rcache, validate);
    if (err) {
        return err;
    }

    err = lfs->cfg->sync(lfs->cfg);
    DBC_LFS_ASSERT(err <= 0);
    return err;
}
#endif

#ifndef DBC_LFS_READONLY
static int dbc_lfs_bd_prog(dbc_lfs_t *lfs,
        dbc_lfs_cache_t *pcache, dbc_lfs_cache_t *rcache, bool validate,
        dbc_lfs_block_t block, dbc_lfs_off_t off,
        const void *buffer, dbc_lfs_size_t size) {
    const uint8_t *data = buffer;
    DBC_LFS_ASSERT(block == DBC_LFS_BLOCK_INLINE || block < lfs->block_count);
    DBC_LFS_ASSERT(off + size <= lfs->cfg->block_size);

    while (size > 0) {
        if (block == pcache->block &&
                off >= pcache->off &&
                off < pcache->off + lfs->cfg->cache_size) {
            // already fits in pcache?
            dbc_lfs_size_t diff = dbc_lfs_min(size,
                    lfs->cfg->cache_size - (off-pcache->off));
            memcpy(&pcache->buffer[off-pcache->off], data, diff);

            data += diff;
            off += diff;
            size -= diff;

            pcache->size = dbc_lfs_max(pcache->size, off - pcache->off);
            if (pcache->size == lfs->cfg->cache_size) {
                // eagerly flush out pcache if we fill up
                int err = dbc_lfs_bd_flush(lfs, pcache, rcache, validate);
                if (err) {
                    return err;
                }
            }

            continue;
        }

        // pcache must have been flushed, either by programming and
        // entire block or manually flushing the pcache
        DBC_LFS_ASSERT(pcache->block == DBC_LFS_BLOCK_NULL);

        // prepare pcache, first condition can no longer fail
        pcache->block = block;
        pcache->off = dbc_lfs_aligndown(off, lfs->cfg->prog_size);
        pcache->size = 0;
    }

    return 0;
}
#endif

#ifndef DBC_LFS_READONLY
static int dbc_lfs_bd_erase(dbc_lfs_t *lfs, dbc_lfs_block_t block) {
    DBC_LFS_ASSERT(block < lfs->block_count);
    int err = lfs->cfg->erase(lfs->cfg, block);
    DBC_LFS_ASSERT(err <= 0);
    return err;
}
#endif


/// Small type-level utilities ///
// operations on block pairs
static inline void dbc_lfs_pair_swap(dbc_lfs_block_t pair[2]) {
    dbc_lfs_block_t t = pair[0];
    pair[0] = pair[1];
    pair[1] = t;
}

static inline bool dbc_lfs_pair_isnull(const dbc_lfs_block_t pair[2]) {
    return pair[0] == DBC_LFS_BLOCK_NULL || pair[1] == DBC_LFS_BLOCK_NULL;
}

static inline int dbc_lfs_pair_cmp(
        const dbc_lfs_block_t paira[2],
        const dbc_lfs_block_t pairb[2]) {
    return !(paira[0] == pairb[0] || paira[1] == pairb[1] ||
             paira[0] == pairb[1] || paira[1] == pairb[0]);
}

static inline bool dbc_lfs_pair_issync(
        const dbc_lfs_block_t paira[2],
        const dbc_lfs_block_t pairb[2]) {
    return (paira[0] == pairb[0] && paira[1] == pairb[1]) ||
           (paira[0] == pairb[1] && paira[1] == pairb[0]);
}

static inline void dbc_lfs_pair_fromle32(dbc_lfs_block_t pair[2]) {
    pair[0] = dbc_lfs_fromle32(pair[0]);
    pair[1] = dbc_lfs_fromle32(pair[1]);
}

#ifndef DBC_LFS_READONLY
static inline void dbc_lfs_pair_tole32(dbc_lfs_block_t pair[2]) {
    pair[0] = dbc_lfs_tole32(pair[0]);
    pair[1] = dbc_lfs_tole32(pair[1]);
}
#endif

// operations on 32-bit entry tags
typedef uint32_t dbc_lfs_tag_t;
typedef int32_t dbc_lfs_stag_t;

#define DBC_LFS_MKTAG(type, id, size) \
    (((dbc_lfs_tag_t)(type) << 20) | ((dbc_lfs_tag_t)(id) << 10) | (dbc_lfs_tag_t)(size))

#define DBC_LFS_MKTAG_IF(cond, type, id, size) \
    ((cond) ? DBC_LFS_MKTAG(type, id, size) : DBC_LFS_MKTAG(DBC_LFS_FROM_NOOP, 0, 0))

#define DBC_LFS_MKTAG_IF_ELSE(cond, type1, id1, size1, type2, id2, size2) \
    ((cond) ? DBC_LFS_MKTAG(type1, id1, size1) : DBC_LFS_MKTAG(type2, id2, size2))

static inline bool dbc_lfs_tag_isvalid(dbc_lfs_tag_t tag) {
    return !(tag & 0x80000000);
}

static inline bool dbc_lfs_tag_isdelete(dbc_lfs_tag_t tag) {
    return ((int32_t)(tag << 22) >> 22) == -1;
}

static inline uint16_t dbc_lfs_tag_type1(dbc_lfs_tag_t tag) {
    return (tag & 0x70000000) >> 20;
}

static inline uint16_t dbc_lfs_tag_type2(dbc_lfs_tag_t tag) {
    return (tag & 0x78000000) >> 20;
}

static inline uint16_t dbc_lfs_tag_type3(dbc_lfs_tag_t tag) {
    return (tag & 0x7ff00000) >> 20;
}

static inline uint8_t dbc_lfs_tag_chunk(dbc_lfs_tag_t tag) {
    return (tag & 0x0ff00000) >> 20;
}

static inline int8_t dbc_lfs_tag_splice(dbc_lfs_tag_t tag) {
    return (int8_t)dbc_lfs_tag_chunk(tag);
}

static inline uint16_t dbc_lfs_tag_id(dbc_lfs_tag_t tag) {
    return (tag & 0x000ffc00) >> 10;
}

static inline dbc_lfs_size_t dbc_lfs_tag_size(dbc_lfs_tag_t tag) {
    return tag & 0x000003ff;
}

static inline dbc_lfs_size_t dbc_lfs_tag_dsize(dbc_lfs_tag_t tag) {
    return sizeof(tag) + dbc_lfs_tag_size(tag + dbc_lfs_tag_isdelete(tag));
}

// operations on attributes in attribute lists
struct dbc_lfs_mattr {
    dbc_lfs_tag_t tag;
    const void *buffer;
};

struct dbc_lfs_diskoff {
    dbc_lfs_block_t block;
    dbc_lfs_off_t off;
};

#define DBC_LFS_MKATTRS(...) \
    (struct dbc_lfs_mattr[]){__VA_ARGS__}, \
    sizeof((struct dbc_lfs_mattr[]){__VA_ARGS__}) / sizeof(struct dbc_lfs_mattr)

// operations on global state
static inline void dbc_lfs_gstate_xor(dbc_lfs_gstate_t *a, const dbc_lfs_gstate_t *b) {
    for (int i = 0; i < 3; i++) {
        ((uint32_t*)a)[i] ^= ((const uint32_t*)b)[i];
    }
}

static inline bool dbc_lfs_gstate_iszero(const dbc_lfs_gstate_t *a) {
    for (int i = 0; i < 3; i++) {
        if (((uint32_t*)a)[i] != 0) {
            return false;
        }
    }
    return true;
}

#ifndef DBC_LFS_READONLY
static inline bool dbc_lfs_gstate_hasorphans(const dbc_lfs_gstate_t *a) {
    return dbc_lfs_tag_size(a->tag);
}

static inline uint8_t dbc_lfs_gstate_getorphans(const dbc_lfs_gstate_t *a) {
    return dbc_lfs_tag_size(a->tag) & 0x1ff;
}

static inline bool dbc_lfs_gstate_hasmove(const dbc_lfs_gstate_t *a) {
    return dbc_lfs_tag_type1(a->tag);
}
#endif

static inline bool dbc_lfs_gstate_needssuperblock(const dbc_lfs_gstate_t *a) {
    return dbc_lfs_tag_size(a->tag) >> 9;
}

static inline bool dbc_lfs_gstate_hasmovehere(const dbc_lfs_gstate_t *a,
        const dbc_lfs_block_t *pair) {
    return dbc_lfs_tag_type1(a->tag) && dbc_lfs_pair_cmp(a->pair, pair) == 0;
}

static inline void dbc_lfs_gstate_fromle32(dbc_lfs_gstate_t *a) {
    a->tag     = dbc_lfs_fromle32(a->tag);
    a->pair[0] = dbc_lfs_fromle32(a->pair[0]);
    a->pair[1] = dbc_lfs_fromle32(a->pair[1]);
}

#ifndef DBC_LFS_READONLY
static inline void dbc_lfs_gstate_tole32(dbc_lfs_gstate_t *a) {
    a->tag     = dbc_lfs_tole32(a->tag);
    a->pair[0] = dbc_lfs_tole32(a->pair[0]);
    a->pair[1] = dbc_lfs_tole32(a->pair[1]);
}
#endif

// operations on forward-CRCs used to track erased state
struct dbc_lfs_fcrc {
    dbc_lfs_size_t size;
    uint32_t crc;
};

static void dbc_lfs_fcrc_fromle32(struct dbc_lfs_fcrc *fcrc) {
    fcrc->size = dbc_lfs_fromle32(fcrc->size);
    fcrc->crc = dbc_lfs_fromle32(fcrc->crc);
}

#ifndef DBC_LFS_READONLY
static void dbc_lfs_fcrc_tole32(struct dbc_lfs_fcrc *fcrc) {
    fcrc->size = dbc_lfs_tole32(fcrc->size);
    fcrc->crc = dbc_lfs_tole32(fcrc->crc);
}
#endif

// other endianness operations
static void dbc_lfs_ctz_fromle32(struct dbc_lfs_ctz *ctz) {
    ctz->head = dbc_lfs_fromle32(ctz->head);
    ctz->size = dbc_lfs_fromle32(ctz->size);
}

#ifndef DBC_LFS_READONLY
static void dbc_lfs_ctz_tole32(struct dbc_lfs_ctz *ctz) {
    ctz->head = dbc_lfs_tole32(ctz->head);
    ctz->size = dbc_lfs_tole32(ctz->size);
}
#endif

static inline void dbc_lfs_superblock_fromle32(dbc_lfs_superblock_t *superblock) {
    superblock->version     = dbc_lfs_fromle32(superblock->version);
    superblock->block_size  = dbc_lfs_fromle32(superblock->block_size);
    superblock->block_count = dbc_lfs_fromle32(superblock->block_count);
    superblock->name_max    = dbc_lfs_fromle32(superblock->name_max);
    superblock->file_max    = dbc_lfs_fromle32(superblock->file_max);
    superblock->attr_max    = dbc_lfs_fromle32(superblock->attr_max);
}

#ifndef DBC_LFS_READONLY
static inline void dbc_lfs_superblock_tole32(dbc_lfs_superblock_t *superblock) {
    superblock->version     = dbc_lfs_tole32(superblock->version);
    superblock->block_size  = dbc_lfs_tole32(superblock->block_size);
    superblock->block_count = dbc_lfs_tole32(superblock->block_count);
    superblock->name_max    = dbc_lfs_tole32(superblock->name_max);
    superblock->file_max    = dbc_lfs_tole32(superblock->file_max);
    superblock->attr_max    = dbc_lfs_tole32(superblock->attr_max);
}
#endif

#ifndef DBC_LFS_NO_ASSERT
static bool dbc_lfs_mlist_isopen(struct dbc_lfs_mlist *head,
        struct dbc_lfs_mlist *node) {
    for (struct dbc_lfs_mlist **p = &head; *p; p = &(*p)->next) {
        if (*p == (struct dbc_lfs_mlist*)node) {
            return true;
        }
    }

    return false;
}
#endif

static void dbc_lfs_mlist_remove(dbc_lfs_t *lfs, struct dbc_lfs_mlist *mlist) {
    for (struct dbc_lfs_mlist **p = &lfs->mlist; *p; p = &(*p)->next) {
        if (*p == mlist) {
            *p = (*p)->next;
            break;
        }
    }
}

static void dbc_lfs_mlist_append(dbc_lfs_t *lfs, struct dbc_lfs_mlist *mlist) {
    mlist->next = lfs->mlist;
    lfs->mlist = mlist;
}

// some other filesystem operations
static uint32_t dbc_lfs_fs_disk_version(dbc_lfs_t *lfs) {
    (void)lfs;
#ifdef DBC_LFS_MULTIVERSION
    if (lfs->cfg->disk_version) {
        return lfs->cfg->disk_version;
    } else
#endif
    {
        return DBC_LFS_DISK_VERSION;
    }
}

static uint16_t dbc_lfs_fs_disk_version_major(dbc_lfs_t *lfs) {
    return 0xffff & (dbc_lfs_fs_disk_version(lfs) >> 16);

}

static uint16_t dbc_lfs_fs_disk_version_minor(dbc_lfs_t *lfs) {
    return 0xffff & (dbc_lfs_fs_disk_version(lfs) >> 0);
}


/// Internal operations predeclared here ///
#ifndef DBC_LFS_READONLY
static int dbc_lfs_dir_commit(dbc_lfs_t *lfs, dbc_lfs_mdir_t *dir,
        const struct dbc_lfs_mattr *attrs, int attrcount);
static int dbc_lfs_dir_compact(dbc_lfs_t *lfs,
        dbc_lfs_mdir_t *dir, const struct dbc_lfs_mattr *attrs, int attrcount,
        dbc_lfs_mdir_t *source, uint16_t begin, uint16_t end);
static dbc_lfs_ssize_t dbc_lfs_file_flushedwrite(dbc_lfs_t *lfs, dbc_lfs_file_t *file,
        const void *buffer, dbc_lfs_size_t size);
static dbc_lfs_ssize_t dbc_lfs_file_write_(dbc_lfs_t *lfs, dbc_lfs_file_t *file,
        const void *buffer, dbc_lfs_size_t size);
static int dbc_lfs_file_sync_(dbc_lfs_t *lfs, dbc_lfs_file_t *file);
static int dbc_lfs_file_outline(dbc_lfs_t *lfs, dbc_lfs_file_t *file);
static int dbc_lfs_file_flush(dbc_lfs_t *lfs, dbc_lfs_file_t *file);

static int dbc_lfs_fs_deorphan(dbc_lfs_t *lfs, bool powerloss);
static int dbc_lfs_fs_preporphans(dbc_lfs_t *lfs, int8_t orphans);
static void dbc_lfs_fs_prepmove(dbc_lfs_t *lfs,
        uint16_t id, const dbc_lfs_block_t pair[2]);
static int dbc_lfs_fs_pred(dbc_lfs_t *lfs, const dbc_lfs_block_t dir[2],
        dbc_lfs_mdir_t *pdir);
static dbc_lfs_stag_t dbc_lfs_fs_parent(dbc_lfs_t *lfs, const dbc_lfs_block_t dir[2],
        dbc_lfs_mdir_t *parent);
static int dbc_lfs_fs_forceconsistency(dbc_lfs_t *lfs);
#endif

static void dbc_lfs_fs_prepsuperblock(dbc_lfs_t *lfs, bool needssuperblock);

#ifdef DBC_LFS_MIGRATE
static int lfs1_traverse(dbc_lfs_t *lfs,
        int (*cb)(void*, dbc_lfs_block_t), void *data);
#endif

static int dbc_lfs_dir_rewind_(dbc_lfs_t *lfs, dbc_lfs_dir_t *dir);

static dbc_lfs_ssize_t dbc_lfs_file_flushedread(dbc_lfs_t *lfs, dbc_lfs_file_t *file,
        void *buffer, dbc_lfs_size_t size);
static dbc_lfs_ssize_t dbc_lfs_file_read_(dbc_lfs_t *lfs, dbc_lfs_file_t *file,
        void *buffer, dbc_lfs_size_t size);
static int dbc_lfs_file_close_(dbc_lfs_t *lfs, dbc_lfs_file_t *file);
static dbc_lfs_soff_t dbc_lfs_file_size_(dbc_lfs_t *lfs, dbc_lfs_file_t *file);

static dbc_lfs_ssize_t dbc_lfs_fs_size_(dbc_lfs_t *lfs);
static int dbc_lfs_fs_traverse_(dbc_lfs_t *lfs,
        int (*cb)(void *data, dbc_lfs_block_t block), void *data,
        bool includeorphans);

static int dbc_lfs_deinit(dbc_lfs_t *lfs);
static int dbc_lfs_unmount_(dbc_lfs_t *lfs);


/// Block allocator ///

// allocations should call this when all allocated blocks are committed to
// the filesystem
//
// after a checkpoint, the block allocator may realloc any untracked blocks
static void dbc_lfs_alloc_ckpoint(dbc_lfs_t *lfs) {
    lfs->lookahead.ckpoint = lfs->block_count;
}

// drop the lookahead buffer, this is done during mounting and failed
// traversals in order to avoid invalid lookahead state
static void dbc_lfs_alloc_drop(dbc_lfs_t *lfs) {
    lfs->lookahead.size = 0;
    lfs->lookahead.next = 0;
    dbc_lfs_alloc_ckpoint(lfs);
}

#ifndef DBC_LFS_READONLY
static int dbc_lfs_alloc_lookahead(void *p, dbc_lfs_block_t block) {
    dbc_lfs_t *lfs = (dbc_lfs_t*)p;
    dbc_lfs_block_t off = ((block - lfs->lookahead.start)
            + lfs->block_count) % lfs->block_count;

    if (off < lfs->lookahead.size) {
        lfs->lookahead.buffer[off / 8] |= 1U << (off % 8);
    }

    return 0;
}
#endif

#ifndef DBC_LFS_READONLY
static int dbc_lfs_alloc_scan(dbc_lfs_t *lfs) {
    // move lookahead buffer to the first unused block
    //
    // note we limit the lookahead buffer to at most the amount of blocks
    // checkpointed, this prevents the math in dbc_lfs_alloc from underflowing
    lfs->lookahead.start = (lfs->lookahead.start + lfs->lookahead.next) 
            % lfs->block_count;
    lfs->lookahead.next = 0;
    lfs->lookahead.size = dbc_lfs_min(
            8*lfs->cfg->lookahead_size,
            lfs->lookahead.ckpoint);

    // find mask of free blocks from tree
    memset(lfs->lookahead.buffer, 0, lfs->cfg->lookahead_size);
    int err = dbc_lfs_fs_traverse_(lfs, dbc_lfs_alloc_lookahead, lfs, true);
    if (err) {
        dbc_lfs_alloc_drop(lfs);
        return err;
    }

    return 0;
}
#endif

#ifndef DBC_LFS_READONLY
static int dbc_lfs_alloc(dbc_lfs_t *lfs, dbc_lfs_block_t *block) {
    while (true) {
        // scan our lookahead buffer for free blocks
        while (lfs->lookahead.next < lfs->lookahead.size) {
            if (!(lfs->lookahead.buffer[lfs->lookahead.next / 8]
                    & (1U << (lfs->lookahead.next % 8)))) {
                // found a free block
                *block = (lfs->lookahead.start + lfs->lookahead.next)
                        % lfs->block_count;

                // eagerly find next free block to maximize how many blocks
                // dbc_lfs_alloc_ckpoint makes available for scanning
                while (true) {
                    lfs->lookahead.next += 1;
                    lfs->lookahead.ckpoint -= 1;

                    if (lfs->lookahead.next >= lfs->lookahead.size
                            || !(lfs->lookahead.buffer[lfs->lookahead.next / 8]
                                & (1U << (lfs->lookahead.next % 8)))) {
                        return 0;
                    }
                }
            }

            lfs->lookahead.next += 1;
            lfs->lookahead.ckpoint -= 1;
        }

        // In order to keep our block allocator from spinning forever when our
        // filesystem is full, we mark points where there are no in-flight
        // allocations with a checkpoint before starting a set of allocations.
        //
        // If we've looked at all blocks since the last checkpoint, we report
        // the filesystem as out of storage.
        //
        if (lfs->lookahead.ckpoint <= 0) {
            DBC_LFS_ERROR("No more free space 0x%"PRIx32,
                    (lfs->lookahead.start + lfs->lookahead.next)
                        % lfs->block_count);
            return DBC_LFS_ERR_NOSPC;
        }

        // No blocks in our lookahead buffer, we need to scan the filesystem for
        // unused blocks in the next lookahead window.
        int err = dbc_lfs_alloc_scan(lfs);
        if(err) {
            return err;
        }
    }
}
#endif

/// Metadata pair and directory operations ///
static dbc_lfs_stag_t dbc_lfs_dir_getslice(dbc_lfs_t *lfs, const dbc_lfs_mdir_t *dir,
        dbc_lfs_tag_t gmask, dbc_lfs_tag_t gtag,
        dbc_lfs_off_t goff, void *gbuffer, dbc_lfs_size_t gsize) {
    dbc_lfs_off_t off = dir->off;
    dbc_lfs_tag_t ntag = dir->etag;
    dbc_lfs_stag_t gdiff = 0;

    // synthetic moves
    if (dbc_lfs_gstate_hasmovehere(&lfs->gdisk, dir->pair) &&
            dbc_lfs_tag_id(gmask) != 0) {
        if (dbc_lfs_tag_id(lfs->gdisk.tag) == dbc_lfs_tag_id(gtag)) {
            return DBC_LFS_ERR_NOENT;
        } else if (dbc_lfs_tag_id(lfs->gdisk.tag) < dbc_lfs_tag_id(gtag)) {
            gdiff -= DBC_LFS_MKTAG(0, 1, 0);
        }
    }

    // iterate over dir block backwards (for faster lookups)
    while (off >= sizeof(dbc_lfs_tag_t) + dbc_lfs_tag_dsize(ntag)) {
        off -= dbc_lfs_tag_dsize(ntag);
        dbc_lfs_tag_t tag = ntag;
        int err = dbc_lfs_bd_read(lfs,
                NULL, &lfs->rcache, sizeof(ntag),
                dir->pair[0], off, &ntag, sizeof(ntag));
        if (err) {
            return err;
        }

        ntag = (dbc_lfs_frombe32(ntag) ^ tag) & 0x7fffffff;

        if (dbc_lfs_tag_id(gmask) != 0 &&
                dbc_lfs_tag_type1(tag) == DBC_LFS_TYPE_SPLICE &&
                dbc_lfs_tag_id(tag) <= dbc_lfs_tag_id(gtag - gdiff)) {
            if (tag == (DBC_LFS_MKTAG(DBC_LFS_TYPE_CREATE, 0, 0) |
                    (DBC_LFS_MKTAG(0, 0x3ff, 0) & (gtag - gdiff)))) {
                // found where we were created
                return DBC_LFS_ERR_NOENT;
            }

            // move around splices
            gdiff += DBC_LFS_MKTAG(0, dbc_lfs_tag_splice(tag), 0);
        }

        if ((gmask & tag) == (gmask & (gtag - gdiff))) {
            if (dbc_lfs_tag_isdelete(tag)) {
                return DBC_LFS_ERR_NOENT;
            }

            dbc_lfs_size_t diff = dbc_lfs_min(dbc_lfs_tag_size(tag), gsize);
            err = dbc_lfs_bd_read(lfs,
                    NULL, &lfs->rcache, diff,
                    dir->pair[0], off+sizeof(tag)+goff, gbuffer, diff);
            if (err) {
                return err;
            }

            memset((uint8_t*)gbuffer + diff, 0, gsize - diff);

            return tag + gdiff;
        }
    }

    return DBC_LFS_ERR_NOENT;
}

static dbc_lfs_stag_t dbc_lfs_dir_get(dbc_lfs_t *lfs, const dbc_lfs_mdir_t *dir,
        dbc_lfs_tag_t gmask, dbc_lfs_tag_t gtag, void *buffer) {
    return dbc_lfs_dir_getslice(lfs, dir,
            gmask, gtag,
            0, buffer, dbc_lfs_tag_size(gtag));
}

static int dbc_lfs_dir_getread(dbc_lfs_t *lfs, const dbc_lfs_mdir_t *dir,
        const dbc_lfs_cache_t *pcache, dbc_lfs_cache_t *rcache, dbc_lfs_size_t hint,
        dbc_lfs_tag_t gmask, dbc_lfs_tag_t gtag,
        dbc_lfs_off_t off, void *buffer, dbc_lfs_size_t size) {
    uint8_t *data = buffer;
    if (off+size > lfs->cfg->block_size) {
        return DBC_LFS_ERR_CORRUPT;
    }

    while (size > 0) {
        dbc_lfs_size_t diff = size;

        if (pcache && pcache->block == DBC_LFS_BLOCK_INLINE &&
                off < pcache->off + pcache->size) {
            if (off >= pcache->off) {
                // is already in pcache?
                diff = dbc_lfs_min(diff, pcache->size - (off-pcache->off));
                memcpy(data, &pcache->buffer[off-pcache->off], diff);

                data += diff;
                off += diff;
                size -= diff;
                continue;
            }

            // pcache takes priority
            diff = dbc_lfs_min(diff, pcache->off-off);
        }

        if (rcache->block == DBC_LFS_BLOCK_INLINE &&
                off < rcache->off + rcache->size) {
            if (off >= rcache->off) {
                // is already in rcache?
                diff = dbc_lfs_min(diff, rcache->size - (off-rcache->off));
                memcpy(data, &rcache->buffer[off-rcache->off], diff);

                data += diff;
                off += diff;
                size -= diff;
                continue;
            }

            // rcache takes priority
            diff = dbc_lfs_min(diff, rcache->off-off);
        }

        // load to cache, first condition can no longer fail
        rcache->block = DBC_LFS_BLOCK_INLINE;
        rcache->off = dbc_lfs_aligndown(off, lfs->cfg->read_size);
        rcache->size = dbc_lfs_min(dbc_lfs_alignup(off+hint, lfs->cfg->read_size),
                lfs->cfg->cache_size);
        int err = dbc_lfs_dir_getslice(lfs, dir, gmask, gtag,
                rcache->off, rcache->buffer, rcache->size);
        if (err < 0) {
            return err;
        }
    }

    return 0;
}

#ifndef DBC_LFS_READONLY
static int dbc_lfs_dir_traverse_filter(void *p,
        dbc_lfs_tag_t tag, const void *buffer) {
    dbc_lfs_tag_t *filtertag = p;
    (void)buffer;

    // which mask depends on unique bit in tag structure
    uint32_t mask = (tag & DBC_LFS_MKTAG(0x100, 0, 0))
            ? DBC_LFS_MKTAG(0x7ff, 0x3ff, 0)
            : DBC_LFS_MKTAG(0x700, 0x3ff, 0);

    // check for redundancy
    if ((mask & tag) == (mask & *filtertag) ||
            dbc_lfs_tag_isdelete(*filtertag) ||
            (DBC_LFS_MKTAG(0x7ff, 0x3ff, 0) & tag) == (
                DBC_LFS_MKTAG(DBC_LFS_TYPE_DELETE, 0, 0) |
                    (DBC_LFS_MKTAG(0, 0x3ff, 0) & *filtertag))) {
        *filtertag = DBC_LFS_MKTAG(DBC_LFS_FROM_NOOP, 0, 0);
        return true;
    }

    // check if we need to adjust for created/deleted tags
    if (dbc_lfs_tag_type1(tag) == DBC_LFS_TYPE_SPLICE &&
            dbc_lfs_tag_id(tag) <= dbc_lfs_tag_id(*filtertag)) {
        *filtertag += DBC_LFS_MKTAG(0, dbc_lfs_tag_splice(tag), 0);
    }

    return false;
}
#endif

#ifndef DBC_LFS_READONLY
// maximum recursive depth of dbc_lfs_dir_traverse, the deepest call:
//
// traverse with commit
// '-> traverse with move
//     '-> traverse with filter
//
#define DBC_LFS_DIR_TRAVERSE_DEPTH 3

struct dbc_lfs_dir_traverse {
    const dbc_lfs_mdir_t *dir;
    dbc_lfs_off_t off;
    dbc_lfs_tag_t ptag;
    const struct dbc_lfs_mattr *attrs;
    int attrcount;

    dbc_lfs_tag_t tmask;
    dbc_lfs_tag_t ttag;
    uint16_t begin;
    uint16_t end;
    int16_t diff;

    int (*cb)(void *data, dbc_lfs_tag_t tag, const void *buffer);
    void *data;

    dbc_lfs_tag_t tag;
    const void *buffer;
    struct dbc_lfs_diskoff disk;
};

static int dbc_lfs_dir_traverse(dbc_lfs_t *lfs,
        const dbc_lfs_mdir_t *dir, dbc_lfs_off_t off, dbc_lfs_tag_t ptag,
        const struct dbc_lfs_mattr *attrs, int attrcount,
        dbc_lfs_tag_t tmask, dbc_lfs_tag_t ttag,
        uint16_t begin, uint16_t end, int16_t diff,
        int (*cb)(void *data, dbc_lfs_tag_t tag, const void *buffer), void *data) {
    // This function in inherently recursive, but bounded. To allow tool-based
    // analysis without unnecessary code-cost we use an explicit stack
    struct dbc_lfs_dir_traverse stack[DBC_LFS_DIR_TRAVERSE_DEPTH-1];
    unsigned sp = 0;
    int res;

    // iterate over directory and attrs
    dbc_lfs_tag_t tag;
    const void *buffer;
    struct dbc_lfs_diskoff disk = {0};
    while (true) {
        {
            if (off+dbc_lfs_tag_dsize(ptag) < dir->off) {
                off += dbc_lfs_tag_dsize(ptag);
                int err = dbc_lfs_bd_read(lfs,
                        NULL, &lfs->rcache, sizeof(tag),
                        dir->pair[0], off, &tag, sizeof(tag));
                if (err) {
                    return err;
                }

                tag = (dbc_lfs_frombe32(tag) ^ ptag) | 0x80000000;
                disk.block = dir->pair[0];
                disk.off = off+sizeof(dbc_lfs_tag_t);
                buffer = &disk;
                ptag = tag;
            } else if (attrcount > 0) {
                tag = attrs[0].tag;
                buffer = attrs[0].buffer;
                attrs += 1;
                attrcount -= 1;
            } else {
                // finished traversal, pop from stack?
                res = 0;
                break;
            }

            // do we need to filter?
            dbc_lfs_tag_t mask = DBC_LFS_MKTAG(0x7ff, 0, 0);
            if ((mask & tmask & tag) != (mask & tmask & ttag)) {
                continue;
            }

            if (dbc_lfs_tag_id(tmask) != 0) {
                DBC_LFS_ASSERT(sp < DBC_LFS_DIR_TRAVERSE_DEPTH);
                // recurse, scan for duplicates, and update tag based on
                // creates/deletes
                stack[sp] = (struct dbc_lfs_dir_traverse){
                    .dir        = dir,
                    .off        = off,
                    .ptag       = ptag,
                    .attrs      = attrs,
                    .attrcount  = attrcount,
                    .tmask      = tmask,
                    .ttag       = ttag,
                    .begin      = begin,
                    .end        = end,
                    .diff       = diff,
                    .cb         = cb,
                    .data       = data,
                    .tag        = tag,
                    .buffer     = buffer,
                    .disk       = disk,
                };
                sp += 1;

                tmask = 0;
                ttag = 0;
                begin = 0;
                end = 0;
                diff = 0;
                cb = dbc_lfs_dir_traverse_filter;
                data = &stack[sp-1].tag;
                continue;
            }
        }

popped:
        // in filter range?
        if (dbc_lfs_tag_id(tmask) != 0 &&
                !(dbc_lfs_tag_id(tag) >= begin && dbc_lfs_tag_id(tag) < end)) {
            continue;
        }

        // handle special cases for mcu-side operations
        if (dbc_lfs_tag_type3(tag) == DBC_LFS_FROM_NOOP) {
            // do nothing
        } else if (dbc_lfs_tag_type3(tag) == DBC_LFS_FROM_MOVE) {
            // Without this condition, dbc_lfs_dir_traverse can exhibit an
            // extremely expensive O(n^3) of nested loops when renaming.
            // This happens because dbc_lfs_dir_traverse tries to filter tags by
            // the tags in the source directory, triggering a second
            // dbc_lfs_dir_traverse with its own filter operation.
            //
            // traverse with commit
            // '-> traverse with filter
            //     '-> traverse with move
            //         '-> traverse with filter
            //
            // However we don't actually care about filtering the second set of
            // tags, since duplicate tags have no effect when filtering.
            //
            // This check skips this unnecessary recursive filtering explicitly,
            // reducing this runtime from O(n^3) to O(n^2).
            if (cb == dbc_lfs_dir_traverse_filter) {
                continue;
            }

            // recurse into move
            stack[sp] = (struct dbc_lfs_dir_traverse){
                .dir        = dir,
                .off        = off,
                .ptag       = ptag,
                .attrs      = attrs,
                .attrcount  = attrcount,
                .tmask      = tmask,
                .ttag       = ttag,
                .begin      = begin,
                .end        = end,
                .diff       = diff,
                .cb         = cb,
                .data       = data,
                .tag        = DBC_LFS_MKTAG(DBC_LFS_FROM_NOOP, 0, 0),
            };
            sp += 1;

            uint16_t fromid = dbc_lfs_tag_size(tag);
            uint16_t toid = dbc_lfs_tag_id(tag);
            dir = buffer;
            off = 0;
            ptag = 0xffffffff;
            attrs = NULL;
            attrcount = 0;
            tmask = DBC_LFS_MKTAG(0x600, 0x3ff, 0);
            ttag = DBC_LFS_MKTAG(DBC_LFS_TYPE_STRUCT, 0, 0);
            begin = fromid;
            end = fromid+1;
            diff = toid-fromid+diff;
        } else if (dbc_lfs_tag_type3(tag) == DBC_LFS_FROM_USERATTRS) {
            for (unsigned i = 0; i < dbc_lfs_tag_size(tag); i++) {
                const struct dbc_lfs_attr *a = buffer;
                res = cb(data, DBC_LFS_MKTAG(DBC_LFS_TYPE_USERATTR + a[i].type,
                        dbc_lfs_tag_id(tag) + diff, a[i].size), a[i].buffer);
                if (res < 0) {
                    return res;
                }

                if (res) {
                    break;
                }
            }
        } else {
            res = cb(data, tag + DBC_LFS_MKTAG(0, diff, 0), buffer);
            if (res < 0) {
                return res;
            }

            if (res) {
                break;
            }
        }
    }

    if (sp > 0) {
        // pop from the stack and return, fortunately all pops share
        // a destination
        dir         = stack[sp-1].dir;
        off         = stack[sp-1].off;
        ptag        = stack[sp-1].ptag;
        attrs       = stack[sp-1].attrs;
        attrcount   = stack[sp-1].attrcount;
        tmask       = stack[sp-1].tmask;
        ttag        = stack[sp-1].ttag;
        begin       = stack[sp-1].begin;
        end         = stack[sp-1].end;
        diff        = stack[sp-1].diff;
        cb          = stack[sp-1].cb;
        data        = stack[sp-1].data;
        tag         = stack[sp-1].tag;
        buffer      = stack[sp-1].buffer;
        disk        = stack[sp-1].disk;
        sp -= 1;
        goto popped;
    } else {
        return res;
    }
}
#endif

static dbc_lfs_stag_t dbc_lfs_dir_fetchmatch(dbc_lfs_t *lfs,
        dbc_lfs_mdir_t *dir, const dbc_lfs_block_t pair[2],
        dbc_lfs_tag_t fmask, dbc_lfs_tag_t ftag, uint16_t *id,
        int (*cb)(void *data, dbc_lfs_tag_t tag, const void *buffer), void *data) {
    // we can find tag very efficiently during a fetch, since we're already
    // scanning the entire directory
    dbc_lfs_stag_t besttag = -1;

    // if either block address is invalid we return DBC_LFS_ERR_CORRUPT here,
    // otherwise later writes to the pair could fail
    if (lfs->block_count 
            && (pair[0] >= lfs->block_count || pair[1] >= lfs->block_count)) {
        return DBC_LFS_ERR_CORRUPT;
    }

    // find the block with the most recent revision
    uint32_t revs[2] = {0, 0};
    int r = 0;
    for (int i = 0; i < 2; i++) {
        int err = dbc_lfs_bd_read(lfs,
                NULL, &lfs->rcache, sizeof(revs[i]),
                pair[i], 0, &revs[i], sizeof(revs[i]));
        revs[i] = dbc_lfs_fromle32(revs[i]);
        if (err && err != DBC_LFS_ERR_CORRUPT) {
            return err;
        }

        if (err != DBC_LFS_ERR_CORRUPT &&
                dbc_lfs_scmp(revs[i], revs[(i+1)%2]) > 0) {
            r = i;
        }
    }

    dir->pair[0] = pair[(r+0)%2];
    dir->pair[1] = pair[(r+1)%2];
    dir->rev = revs[(r+0)%2];
    dir->off = 0; // nonzero = found some commits

    // now scan tags to fetch the actual dir and find possible match
    for (int i = 0; i < 2; i++) {
        dbc_lfs_off_t off = 0;
        dbc_lfs_tag_t ptag = 0xffffffff;

        uint16_t tempcount = 0;
        dbc_lfs_block_t temptail[2] = {DBC_LFS_BLOCK_NULL, DBC_LFS_BLOCK_NULL};
        bool tempsplit = false;
        dbc_lfs_stag_t tempbesttag = besttag;

        // assume not erased until proven otherwise
        bool maybeerased = false;
        bool hasfcrc = false;
        struct dbc_lfs_fcrc fcrc;

        dir->rev = dbc_lfs_tole32(dir->rev);
        uint32_t crc = dbc_lfs_crc(0xffffffff, &dir->rev, sizeof(dir->rev));
        dir->rev = dbc_lfs_fromle32(dir->rev);

        while (true) {
            // extract next tag
            dbc_lfs_tag_t tag;
            off += dbc_lfs_tag_dsize(ptag);
            int err = dbc_lfs_bd_read(lfs,
                    NULL, &lfs->rcache, lfs->cfg->block_size,
                    dir->pair[0], off, &tag, sizeof(tag));
            if (err) {
                if (err == DBC_LFS_ERR_CORRUPT) {
                    // No more space in the block to search for a dtag
                    // can't continue?
                    break;
                }
                return err;
            }

            crc = dbc_lfs_crc(crc, &tag, sizeof(tag));
            tag = dbc_lfs_frombe32(tag) ^ ptag;

            // next commit not yet programmed?
            if (!dbc_lfs_tag_isvalid(tag)) {
                // we only might be erased if the last tag was a crc
                maybeerased = (dbc_lfs_tag_type2(ptag) == DBC_LFS_TYPE_CCRC);
                break;
            // out of range?
            } else if (off + dbc_lfs_tag_dsize(tag) > lfs->cfg->block_size) {
                break;
            }

            ptag = tag;

            if (dbc_lfs_tag_type2(tag) == DBC_LFS_TYPE_CCRC) {
                // check the crc attr
                uint32_t dcrc;
                err = dbc_lfs_bd_read(lfs,
                        NULL, &lfs->rcache, lfs->cfg->block_size,
                        dir->pair[0], off+sizeof(tag), &dcrc, sizeof(dcrc));
                if (err) {
                    if (err == DBC_LFS_ERR_CORRUPT) {
                        break;
                    }
                    return err;
                }
                dcrc = dbc_lfs_fromle32(dcrc);

                if (crc != dcrc) {
                    break;
                }

                // reset the next bit if we need to
                ptag ^= (dbc_lfs_tag_t)(dbc_lfs_tag_chunk(tag) & 1U) << 31;

                // toss our crc into the filesystem seed for
                // pseudorandom numbers, note we use another crc here
                // as a collection function because it is sufficiently
                // random and convenient
                lfs->seed = dbc_lfs_crc(lfs->seed, &crc, sizeof(crc));

                // update with what's found so far
                besttag = tempbesttag;
                dir->off = off + dbc_lfs_tag_dsize(tag);
                dir->etag = ptag;
                dir->count = tempcount;
                dir->tail[0] = temptail[0];
                dir->tail[1] = temptail[1];
                dir->split = tempsplit;

                // reset crc, hasfcrc
                crc = 0xffffffff;
                continue;
            }

            // crc the entry first, hopefully leaving it in the cache
            err = dbc_lfs_bd_crc(lfs,
                    NULL, &lfs->rcache, lfs->cfg->block_size,
                    dir->pair[0], off+sizeof(tag),
                    dbc_lfs_tag_dsize(tag)-sizeof(tag), &crc);
            if (err) {
                if (err == DBC_LFS_ERR_CORRUPT) {
                    break;
                }
                return err;
            }

            // directory modification tags?
            if (dbc_lfs_tag_type1(tag) == DBC_LFS_TYPE_NAME) {
                // increase count of files if necessary
                if (dbc_lfs_tag_id(tag) >= tempcount) {
                    tempcount = dbc_lfs_tag_id(tag) + 1;
                }
            } else if (dbc_lfs_tag_type1(tag) == DBC_LFS_TYPE_SPLICE) {
                tempcount += dbc_lfs_tag_splice(tag);

                if (tag == (DBC_LFS_MKTAG(DBC_LFS_TYPE_DELETE, 0, 0) |
                        (DBC_LFS_MKTAG(0, 0x3ff, 0) & tempbesttag))) {
                    tempbesttag |= 0x80000000;
                } else if (tempbesttag != -1 &&
                        dbc_lfs_tag_id(tag) <= dbc_lfs_tag_id(tempbesttag)) {
                    tempbesttag += DBC_LFS_MKTAG(0, dbc_lfs_tag_splice(tag), 0);
                }
            } else if (dbc_lfs_tag_type1(tag) == DBC_LFS_TYPE_TAIL) {
                tempsplit = (dbc_lfs_tag_chunk(tag) & 1);

                err = dbc_lfs_bd_read(lfs,
                        NULL, &lfs->rcache, lfs->cfg->block_size,
                        dir->pair[0], off+sizeof(tag), &temptail, 8);
                if (err) {
                    if (err == DBC_LFS_ERR_CORRUPT) {
                        break;
                    }
                    return err;
                }
                dbc_lfs_pair_fromle32(temptail);
            } else if (dbc_lfs_tag_type3(tag) == DBC_LFS_TYPE_FCRC) {
                err = dbc_lfs_bd_read(lfs,
                        NULL, &lfs->rcache, lfs->cfg->block_size,
                        dir->pair[0], off+sizeof(tag),
                        &fcrc, sizeof(fcrc));
                if (err) {
                    if (err == DBC_LFS_ERR_CORRUPT) {
                        break;
                    }
                }

                dbc_lfs_fcrc_fromle32(&fcrc);
                hasfcrc = true;
            }

            // found a match for our fetcher?
            if ((fmask & tag) == (fmask & ftag)) {
                int res = cb(data, tag, &(struct dbc_lfs_diskoff){
                        dir->pair[0], off+sizeof(tag)});
                if (res < 0) {
                    if (res == DBC_LFS_ERR_CORRUPT) {
                        break;
                    }
                    return res;
                }

                if (res == DBC_LFS_CMP_EQ) {
                    // found a match
                    tempbesttag = tag;
                } else if ((DBC_LFS_MKTAG(0x7ff, 0x3ff, 0) & tag) ==
                        (DBC_LFS_MKTAG(0x7ff, 0x3ff, 0) & tempbesttag)) {
                    // found an identical tag, but contents didn't match
                    // this must mean that our besttag has been overwritten
                    tempbesttag = -1;
                } else if (res == DBC_LFS_CMP_GT &&
                        dbc_lfs_tag_id(tag) <= dbc_lfs_tag_id(tempbesttag)) {
                    // found a greater match, keep track to keep things sorted
                    tempbesttag = tag | 0x80000000;
                }
            }
        }

        // found no valid commits?
        if (dir->off == 0) {
            // try the other block?
            dbc_lfs_pair_swap(dir->pair);
            dir->rev = revs[(r+1)%2];
            continue;
        }

        // did we end on a valid commit? we may have an erased block
        dir->erased = false;
        if (maybeerased && dir->off % lfs->cfg->prog_size == 0) {
        #ifdef DBC_LFS_MULTIVERSION
            // note versions < lfs2.1 did not have fcrc tags, if
            // we're < lfs2.1 treat missing fcrc as erased data
            //
            // we don't strictly need to do this, but otherwise writing
            // to lfs2.0 disks becomes very inefficient
            if (dbc_lfs_fs_disk_version(lfs) < 0x00020001) {
                dir->erased = true;

            } else
        #endif
            if (hasfcrc) {
                // check for an fcrc matching the next prog's erased state, if
                // this failed most likely a previous prog was interrupted, we
                // need a new erase
                uint32_t fcrc_ = 0xffffffff;
                int err = dbc_lfs_bd_crc(lfs,
                        NULL, &lfs->rcache, lfs->cfg->block_size,
                        dir->pair[0], dir->off, fcrc.size, &fcrc_);
                if (err && err != DBC_LFS_ERR_CORRUPT) {
                    return err;
                }

                // found beginning of erased part?
                dir->erased = (fcrc_ == fcrc.crc);
            }
        }

        // synthetic move
        if (dbc_lfs_gstate_hasmovehere(&lfs->gdisk, dir->pair)) {
            if (dbc_lfs_tag_id(lfs->gdisk.tag) == dbc_lfs_tag_id(besttag)) {
                besttag |= 0x80000000;
            } else if (besttag != -1 &&
                    dbc_lfs_tag_id(lfs->gdisk.tag) < dbc_lfs_tag_id(besttag)) {
                besttag -= DBC_LFS_MKTAG(0, 1, 0);
            }
        }

        // found tag? or found best id?
        if (id) {
            *id = dbc_lfs_min(dbc_lfs_tag_id(besttag), dir->count);
        }

        if (dbc_lfs_tag_isvalid(besttag)) {
            return besttag;
        } else if (dbc_lfs_tag_id(besttag) < dir->count) {
            return DBC_LFS_ERR_NOENT;
        } else {
            return 0;
        }
    }

    DBC_LFS_ERROR("Corrupted dir pair at {0x%"PRIx32", 0x%"PRIx32"}",
            dir->pair[0], dir->pair[1]);
    return DBC_LFS_ERR_CORRUPT;
}

static int dbc_lfs_dir_fetch(dbc_lfs_t *lfs,
        dbc_lfs_mdir_t *dir, const dbc_lfs_block_t pair[2]) {
    // note, mask=-1, tag=-1 can never match a tag since this
    // pattern has the invalid bit set
    return (int)dbc_lfs_dir_fetchmatch(lfs, dir, pair,
            (dbc_lfs_tag_t)-1, (dbc_lfs_tag_t)-1, NULL, NULL, NULL);
}

static int dbc_lfs_dir_getgstate(dbc_lfs_t *lfs, const dbc_lfs_mdir_t *dir,
        dbc_lfs_gstate_t *gstate) {
    dbc_lfs_gstate_t temp;
    dbc_lfs_stag_t res = dbc_lfs_dir_get(lfs, dir, DBC_LFS_MKTAG(0x7ff, 0, 0),
            DBC_LFS_MKTAG(DBC_LFS_TYPE_MOVESTATE, 0, sizeof(temp)), &temp);
    if (res < 0 && res != DBC_LFS_ERR_NOENT) {
        return res;
    }

    if (res != DBC_LFS_ERR_NOENT) {
        // xor together to find resulting gstate
        dbc_lfs_gstate_fromle32(&temp);
        dbc_lfs_gstate_xor(gstate, &temp);
    }

    return 0;
}

static int dbc_lfs_dir_getinfo(dbc_lfs_t *lfs, dbc_lfs_mdir_t *dir,
        uint16_t id, struct dbc_lfs_info *info) {
    if (id == 0x3ff) {
        // special case for root
        strcpy(info->name, "/");
        info->type = DBC_LFS_TYPE_DIR;
        return 0;
    }

    dbc_lfs_stag_t tag = dbc_lfs_dir_get(lfs, dir, DBC_LFS_MKTAG(0x780, 0x3ff, 0),
            DBC_LFS_MKTAG(DBC_LFS_TYPE_NAME, id, lfs->name_max+1), info->name);
    if (tag < 0) {
        return (int)tag;
    }

    info->type = dbc_lfs_tag_type3(tag);

    struct dbc_lfs_ctz ctz;
    tag = dbc_lfs_dir_get(lfs, dir, DBC_LFS_MKTAG(0x700, 0x3ff, 0),
            DBC_LFS_MKTAG(DBC_LFS_TYPE_STRUCT, id, sizeof(ctz)), &ctz);
    if (tag < 0) {
        return (int)tag;
    }
    dbc_lfs_ctz_fromle32(&ctz);

    if (dbc_lfs_tag_type3(tag) == DBC_LFS_TYPE_CTZSTRUCT) {
        info->size = ctz.size;
    } else if (dbc_lfs_tag_type3(tag) == DBC_LFS_TYPE_INLINESTRUCT) {
        info->size = dbc_lfs_tag_size(tag);
    }

    return 0;
}

struct dbc_lfs_dir_find_match {
    dbc_lfs_t *lfs;
    const void *name;
    dbc_lfs_size_t size;
};

static int dbc_lfs_dir_find_match(void *data,
        dbc_lfs_tag_t tag, const void *buffer) {
    struct dbc_lfs_dir_find_match *name = data;
    dbc_lfs_t *lfs = name->lfs;
    const struct dbc_lfs_diskoff *disk = buffer;

    // compare with disk
    dbc_lfs_size_t diff = dbc_lfs_min(name->size, dbc_lfs_tag_size(tag));
    int res = dbc_lfs_bd_cmp(lfs,
            NULL, &lfs->rcache, diff,
            disk->block, disk->off, name->name, diff);
    if (res != DBC_LFS_CMP_EQ) {
        return res;
    }

    // only equal if our size is still the same
    if (name->size != dbc_lfs_tag_size(tag)) {
        return (name->size < dbc_lfs_tag_size(tag)) ? DBC_LFS_CMP_LT : DBC_LFS_CMP_GT;
    }

    // found a match!
    return DBC_LFS_CMP_EQ;
}

static dbc_lfs_stag_t dbc_lfs_dir_find(dbc_lfs_t *lfs, dbc_lfs_mdir_t *dir,
        const char **path, uint16_t *id) {
    // we reduce path to a single name if we can find it
    const char *name = *path;
    if (id) {
        *id = 0x3ff;
    }

    // default to root dir
    dbc_lfs_stag_t tag = DBC_LFS_MKTAG(DBC_LFS_TYPE_DIR, 0x3ff, 0);
    dir->tail[0] = lfs->root[0];
    dir->tail[1] = lfs->root[1];

    while (true) {
nextname:
        // skip slashes
        name += strspn(name, "/");
        dbc_lfs_size_t namelen = strcspn(name, "/");

        // skip '.' and root '..'
        if ((namelen == 1 && memcmp(name, ".", 1) == 0) ||
            (namelen == 2 && memcmp(name, "..", 2) == 0)) {
            name += namelen;
            goto nextname;
        }

        // skip if matched by '..' in name
        const char *suffix = name + namelen;
        dbc_lfs_size_t sufflen;
        int depth = 1;
        while (true) {
            suffix += strspn(suffix, "/");
            sufflen = strcspn(suffix, "/");
            if (sufflen == 0) {
                break;
            }

            if (sufflen == 2 && memcmp(suffix, "..", 2) == 0) {
                depth -= 1;
                if (depth == 0) {
                    name = suffix + sufflen;
                    goto nextname;
                }
            } else {
                depth += 1;
            }

            suffix += sufflen;
        }

        // found path
        if (name[0] == '\0') {
            return tag;
        }

        // update what we've found so far
        *path = name;

        // only continue if we hit a directory
        if (dbc_lfs_tag_type3(tag) != DBC_LFS_TYPE_DIR) {
            return DBC_LFS_ERR_NOTDIR;
        }

        // grab the entry data
        if (dbc_lfs_tag_id(tag) != 0x3ff) {
            dbc_lfs_stag_t res = dbc_lfs_dir_get(lfs, dir, DBC_LFS_MKTAG(0x700, 0x3ff, 0),
                    DBC_LFS_MKTAG(DBC_LFS_TYPE_STRUCT, dbc_lfs_tag_id(tag), 8), dir->tail);
            if (res < 0) {
                return res;
            }
            dbc_lfs_pair_fromle32(dir->tail);
        }

        // find entry matching name
        while (true) {
            tag = dbc_lfs_dir_fetchmatch(lfs, dir, dir->tail,
                    DBC_LFS_MKTAG(0x780, 0, 0),
                    DBC_LFS_MKTAG(DBC_LFS_TYPE_NAME, 0, namelen),
                     // are we last name?
                    (strchr(name, '/') == NULL) ? id : NULL,
                    dbc_lfs_dir_find_match, &(struct dbc_lfs_dir_find_match){
                        lfs, name, namelen});
            if (tag < 0) {
                return tag;
            }

            if (tag) {
                break;
            }

            if (!dir->split) {
                return DBC_LFS_ERR_NOENT;
            }
        }

        // to next name
        name += namelen;
    }
}

// commit logic
struct dbc_lfs_commit {
    dbc_lfs_block_t block;
    dbc_lfs_off_t off;
    dbc_lfs_tag_t ptag;
    uint32_t crc;

    dbc_lfs_off_t begin;
    dbc_lfs_off_t end;
};

#ifndef DBC_LFS_READONLY
static int dbc_lfs_dir_commitprog(dbc_lfs_t *lfs, struct dbc_lfs_commit *commit,
        const void *buffer, dbc_lfs_size_t size) {
    int err = dbc_lfs_bd_prog(lfs,
            &lfs->pcache, &lfs->rcache, false,
            commit->block, commit->off ,
            (const uint8_t*)buffer, size);
    if (err) {
        return err;
    }

    commit->crc = dbc_lfs_crc(commit->crc, buffer, size);
    commit->off += size;
    return 0;
}
#endif

#ifndef DBC_LFS_READONLY
static int dbc_lfs_dir_commitattr(dbc_lfs_t *lfs, struct dbc_lfs_commit *commit,
        dbc_lfs_tag_t tag, const void *buffer) {
    // check if we fit
    dbc_lfs_size_t dsize = dbc_lfs_tag_dsize(tag);
    if (commit->off + dsize > commit->end) {
        return DBC_LFS_ERR_NOSPC;
    }

    // write out tag
    dbc_lfs_tag_t ntag = dbc_lfs_tobe32((tag & 0x7fffffff) ^ commit->ptag);
    int err = dbc_lfs_dir_commitprog(lfs, commit, &ntag, sizeof(ntag));
    if (err) {
        return err;
    }

    if (!(tag & 0x80000000)) {
        // from memory
        err = dbc_lfs_dir_commitprog(lfs, commit, buffer, dsize-sizeof(tag));
        if (err) {
            return err;
        }
    } else {
        // from disk
        const struct dbc_lfs_diskoff *disk = buffer;
        for (dbc_lfs_off_t i = 0; i < dsize-sizeof(tag); i++) {
            // rely on caching to make this efficient
            uint8_t dat;
            err = dbc_lfs_bd_read(lfs,
                    NULL, &lfs->rcache, dsize-sizeof(tag)-i,
                    disk->block, disk->off+i, &dat, 1);
            if (err) {
                return err;
            }

            err = dbc_lfs_dir_commitprog(lfs, commit, &dat, 1);
            if (err) {
                return err;
            }
        }
    }

    commit->ptag = tag & 0x7fffffff;
    return 0;
}
#endif

#ifndef DBC_LFS_READONLY

static int dbc_lfs_dir_commitcrc(dbc_lfs_t *lfs, struct dbc_lfs_commit *commit) {
    // align to program units
    //
    // this gets a bit complex as we have two types of crcs:
    // - 5-word crc with fcrc to check following prog (middle of block)
    // - 2-word crc with no following prog (end of block)
    const dbc_lfs_off_t end = dbc_lfs_alignup(
            dbc_lfs_min(commit->off + 5*sizeof(uint32_t), lfs->cfg->block_size),
            lfs->cfg->prog_size);

    dbc_lfs_off_t off1 = 0;
    uint32_t crc1 = 0;

    // create crc tags to fill up remainder of commit, note that
    // padding is not crced, which lets fetches skip padding but
    // makes committing a bit more complicated
    while (commit->off < end) {
        dbc_lfs_off_t noff = (
                dbc_lfs_min(end - (commit->off+sizeof(dbc_lfs_tag_t)), 0x3fe)
                + (commit->off+sizeof(dbc_lfs_tag_t)));
        // too large for crc tag? need padding commits
        if (noff < end) {
            noff = dbc_lfs_min(noff, end - 5*sizeof(uint32_t));
        }

        // space for fcrc?
        uint8_t eperturb = (uint8_t)-1;
        if (noff >= end && noff <= lfs->cfg->block_size - lfs->cfg->prog_size) {
            // first read the leading byte, this always contains a bit
            // we can perturb to avoid writes that don't change the fcrc
            int err = dbc_lfs_bd_read(lfs,
                    NULL, &lfs->rcache, lfs->cfg->prog_size,
                    commit->block, noff, &eperturb, 1);
            if (err && err != DBC_LFS_ERR_CORRUPT) {
                return err;
            }

        #ifdef DBC_LFS_MULTIVERSION
            // unfortunately fcrcs break mdir fetching < lfs2.1, so only write
            // these if we're a >= lfs2.1 filesystem
            if (dbc_lfs_fs_disk_version(lfs) <= 0x00020000) {
                // don't write fcrc
            } else
        #endif
            {
                // find the expected fcrc, don't bother avoiding a reread
                // of the eperturb, it should still be in our cache
                struct dbc_lfs_fcrc fcrc = {
                    .size = lfs->cfg->prog_size,
                    .crc = 0xffffffff
                };
                err = dbc_lfs_bd_crc(lfs,
                        NULL, &lfs->rcache, lfs->cfg->prog_size,
                        commit->block, noff, fcrc.size, &fcrc.crc);
                if (err && err != DBC_LFS_ERR_CORRUPT) {
                    return err;
                }

                dbc_lfs_fcrc_tole32(&fcrc);
                err = dbc_lfs_dir_commitattr(lfs, commit,
                        DBC_LFS_MKTAG(DBC_LFS_TYPE_FCRC, 0x3ff, sizeof(struct dbc_lfs_fcrc)),
                        &fcrc);
                if (err) {
                    return err;
                }
            }
        }

        // build commit crc
        struct {
            dbc_lfs_tag_t tag;
            uint32_t crc;
        } ccrc;
        dbc_lfs_tag_t ntag = DBC_LFS_MKTAG(
                DBC_LFS_TYPE_CCRC + (((uint8_t)~eperturb) >> 7), 0x3ff,
                noff - (commit->off+sizeof(dbc_lfs_tag_t)));
        ccrc.tag = dbc_lfs_tobe32(ntag ^ commit->ptag);
        commit->crc = dbc_lfs_crc(commit->crc, &ccrc.tag, sizeof(dbc_lfs_tag_t));
        ccrc.crc = dbc_lfs_tole32(commit->crc);

        int err = dbc_lfs_bd_prog(lfs,
                &lfs->pcache, &lfs->rcache, false,
                commit->block, commit->off, &ccrc, sizeof(ccrc));
        if (err) {
            return err;
        }

        // keep track of non-padding checksum to verify
        if (off1 == 0) {
            off1 = commit->off + sizeof(dbc_lfs_tag_t);
            crc1 = commit->crc;
        }

        commit->off = noff;
        // perturb valid bit?
        commit->ptag = ntag ^ ((0x80UL & ~eperturb) << 24);
        // reset crc for next commit
        commit->crc = 0xffffffff;

        // manually flush here since we don't prog the padding, this confuses
        // the caching layer
        if (noff >= end || noff >= lfs->pcache.off + lfs->cfg->cache_size) {
            // flush buffers
            int err = dbc_lfs_bd_sync(lfs, &lfs->pcache, &lfs->rcache, false);
            if (err) {
                return err;
            }
        }
    }

    // successful commit, check checksums to make sure
    //
    // note that we don't need to check padding commits, worst
    // case if they are corrupted we would have had to compact anyways
    dbc_lfs_off_t off = commit->begin;
    uint32_t crc = 0xffffffff;
    int err = dbc_lfs_bd_crc(lfs,
            NULL, &lfs->rcache, off1+sizeof(uint32_t),
            commit->block, off, off1-off, &crc);
    if (err) {
        return err;
    }

    // check non-padding commits against known crc
    if (crc != crc1) {
        return DBC_LFS_ERR_CORRUPT;
    }

    // make sure to check crc in case we happen to pick
    // up an unrelated crc (frozen block?)
    err = dbc_lfs_bd_crc(lfs,
            NULL, &lfs->rcache, sizeof(uint32_t),
            commit->block, off1, sizeof(uint32_t), &crc);
    if (err) {
        return err;
    }

    if (crc != 0) {
        return DBC_LFS_ERR_CORRUPT;
    }

    return 0;
}
#endif

#ifndef DBC_LFS_READONLY
static int dbc_lfs_dir_alloc(dbc_lfs_t *lfs, dbc_lfs_mdir_t *dir) {
    // allocate pair of dir blocks (backwards, so we write block 1 first)
    for (int i = 0; i < 2; i++) {
        int err = dbc_lfs_alloc(lfs, &dir->pair[(i+1)%2]);
        if (err) {
            return err;
        }
    }

    // zero for reproducibility in case initial block is unreadable
    dir->rev = 0;

    // rather than clobbering one of the blocks we just pretend
    // the revision may be valid
    int err = dbc_lfs_bd_read(lfs,
            NULL, &lfs->rcache, sizeof(dir->rev),
            dir->pair[0], 0, &dir->rev, sizeof(dir->rev));
    dir->rev = dbc_lfs_fromle32(dir->rev);
    if (err && err != DBC_LFS_ERR_CORRUPT) {
        return err;
    }

    // to make sure we don't immediately evict, align the new revision count
    // to our block_cycles modulus, see dbc_lfs_dir_compact for why our modulus
    // is tweaked this way
    if (lfs->cfg->block_cycles > 0) {
        dir->rev = dbc_lfs_alignup(dir->rev, ((lfs->cfg->block_cycles+1)|1));
    }

    // set defaults
    dir->off = sizeof(dir->rev);
    dir->etag = 0xffffffff;
    dir->count = 0;
    dir->tail[0] = DBC_LFS_BLOCK_NULL;
    dir->tail[1] = DBC_LFS_BLOCK_NULL;
    dir->erased = false;
    dir->split = false;

    // don't write out yet, let caller take care of that
    return 0;
}
#endif

#ifndef DBC_LFS_READONLY
static int dbc_lfs_dir_drop(dbc_lfs_t *lfs, dbc_lfs_mdir_t *dir, dbc_lfs_mdir_t *tail) {
    // steal state
    int err = dbc_lfs_dir_getgstate(lfs, tail, &lfs->gdelta);
    if (err) {
        return err;
    }

    // steal tail
    dbc_lfs_pair_tole32(tail->tail);
    err = dbc_lfs_dir_commit(lfs, dir, DBC_LFS_MKATTRS(
            {DBC_LFS_MKTAG(DBC_LFS_TYPE_TAIL + tail->split, 0x3ff, 8), tail->tail}));
    dbc_lfs_pair_fromle32(tail->tail);
    if (err) {
        return err;
    }

    return 0;
}
#endif

#ifndef DBC_LFS_READONLY
static int dbc_lfs_dir_split(dbc_lfs_t *lfs,
        dbc_lfs_mdir_t *dir, const struct dbc_lfs_mattr *attrs, int attrcount,
        dbc_lfs_mdir_t *source, uint16_t split, uint16_t end) {
    // create tail metadata pair
    dbc_lfs_mdir_t tail;
    int err = dbc_lfs_dir_alloc(lfs, &tail);
    if (err) {
        return err;
    }

    tail.split = dir->split;
    tail.tail[0] = dir->tail[0];
    tail.tail[1] = dir->tail[1];

    // note we don't care about DBC_LFS_OK_RELOCATED
    int res = dbc_lfs_dir_compact(lfs, &tail, attrs, attrcount, source, split, end);
    if (res < 0) {
        return res;
    }

    dir->tail[0] = tail.pair[0];
    dir->tail[1] = tail.pair[1];
    dir->split = true;

    // update root if needed
    if (dbc_lfs_pair_cmp(dir->pair, lfs->root) == 0 && split == 0) {
        lfs->root[0] = tail.pair[0];
        lfs->root[1] = tail.pair[1];
    }

    return 0;
}
#endif

#ifndef DBC_LFS_READONLY
static int dbc_lfs_dir_commit_size(void *p, dbc_lfs_tag_t tag, const void *buffer) {
    dbc_lfs_size_t *size = p;
    (void)buffer;

    *size += dbc_lfs_tag_dsize(tag);
    return 0;
}
#endif

#ifndef DBC_LFS_READONLY
struct dbc_lfs_dir_commit_commit {
    dbc_lfs_t *lfs;
    struct dbc_lfs_commit *commit;
};
#endif

#ifndef DBC_LFS_READONLY
static int dbc_lfs_dir_commit_commit(void *p, dbc_lfs_tag_t tag, const void *buffer) {
    struct dbc_lfs_dir_commit_commit *commit = p;
    return dbc_lfs_dir_commitattr(commit->lfs, commit->commit, tag, buffer);
}
#endif

#ifndef DBC_LFS_READONLY
static bool dbc_lfs_dir_needsrelocation(dbc_lfs_t *lfs, dbc_lfs_mdir_t *dir) {
    // If our revision count == n * block_cycles, we should force a relocation,
    // this is how littlefs wear-levels at the metadata-pair level. Note that we
    // actually use (block_cycles+1)|1, this is to avoid two corner cases:
    // 1. block_cycles = 1, which would prevent relocations from terminating
    // 2. block_cycles = 2n, which, due to aliasing, would only ever relocate
    //    one metadata block in the pair, effectively making this useless
    return (lfs->cfg->block_cycles > 0
            && ((dir->rev + 1) % ((lfs->cfg->block_cycles+1)|1) == 0));
}
#endif

#ifndef DBC_LFS_READONLY
static int dbc_lfs_dir_compact(dbc_lfs_t *lfs,
        dbc_lfs_mdir_t *dir, const struct dbc_lfs_mattr *attrs, int attrcount,
        dbc_lfs_mdir_t *source, uint16_t begin, uint16_t end) {
    // save some state in case block is bad
    bool relocated = false;
    bool tired = dbc_lfs_dir_needsrelocation(lfs, dir);

    // increment revision count
    dir->rev += 1;

    // do not proactively relocate blocks during migrations, this
    // can cause a number of failure states such: clobbering the
    // v1 superblock if we relocate root, and invalidating directory
    // pointers if we relocate the head of a directory. On top of
    // this, relocations increase the overall complexity of
    // dbc_lfs_migration, which is already a delicate operation.
#ifdef DBC_LFS_MIGRATE
    if (lfs->lfs1) {
        tired = false;
    }
#endif

    if (tired && dbc_lfs_pair_cmp(dir->pair, (const dbc_lfs_block_t[2]){0, 1}) != 0) {
        // we're writing too much, time to relocate
        goto relocate;
    }

    // begin loop to commit compaction to blocks until a compact sticks
    while (true) {
        {
            // setup commit state
            struct dbc_lfs_commit commit = {
                .block = dir->pair[1],
                .off = 0,
                .ptag = 0xffffffff,
                .crc = 0xffffffff,

                .begin = 0,
                .end = (lfs->cfg->metadata_max ?
                    lfs->cfg->metadata_max : lfs->cfg->block_size) - 8,
            };

            // erase block to write to
            int err = dbc_lfs_bd_erase(lfs, dir->pair[1]);
            if (err) {
                if (err == DBC_LFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }

            // write out header
            dir->rev = dbc_lfs_tole32(dir->rev);
            err = dbc_lfs_dir_commitprog(lfs, &commit,
                    &dir->rev, sizeof(dir->rev));
            dir->rev = dbc_lfs_fromle32(dir->rev);
            if (err) {
                if (err == DBC_LFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }

            // traverse the directory, this time writing out all unique tags
            err = dbc_lfs_dir_traverse(lfs,
                    source, 0, 0xffffffff, attrs, attrcount,
                    DBC_LFS_MKTAG(0x400, 0x3ff, 0),
                    DBC_LFS_MKTAG(DBC_LFS_TYPE_NAME, 0, 0),
                    begin, end, -begin,
                    dbc_lfs_dir_commit_commit, &(struct dbc_lfs_dir_commit_commit){
                        lfs, &commit});
            if (err) {
                if (err == DBC_LFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }

            // commit tail, which may be new after last size check
            if (!dbc_lfs_pair_isnull(dir->tail)) {
                dbc_lfs_pair_tole32(dir->tail);
                err = dbc_lfs_dir_commitattr(lfs, &commit,
                        DBC_LFS_MKTAG(DBC_LFS_TYPE_TAIL + dir->split, 0x3ff, 8),
                        dir->tail);
                dbc_lfs_pair_fromle32(dir->tail);
                if (err) {
                    if (err == DBC_LFS_ERR_CORRUPT) {
                        goto relocate;
                    }
                    return err;
                }
            }

            // bring over gstate?
            dbc_lfs_gstate_t delta = {0};
            if (!relocated) {
                dbc_lfs_gstate_xor(&delta, &lfs->gdisk);
                dbc_lfs_gstate_xor(&delta, &lfs->gstate);
            }
            dbc_lfs_gstate_xor(&delta, &lfs->gdelta);
            delta.tag &= ~DBC_LFS_MKTAG(0, 0, 0x3ff);

            err = dbc_lfs_dir_getgstate(lfs, dir, &delta);
            if (err) {
                return err;
            }

            if (!dbc_lfs_gstate_iszero(&delta)) {
                dbc_lfs_gstate_tole32(&delta);
                err = dbc_lfs_dir_commitattr(lfs, &commit,
                        DBC_LFS_MKTAG(DBC_LFS_TYPE_MOVESTATE, 0x3ff,
                            sizeof(delta)), &delta);
                if (err) {
                    if (err == DBC_LFS_ERR_CORRUPT) {
                        goto relocate;
                    }
                    return err;
                }
            }

            // complete commit with crc
            err = dbc_lfs_dir_commitcrc(lfs, &commit);
            if (err) {
                if (err == DBC_LFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }

            // successful compaction, swap dir pair to indicate most recent
            DBC_LFS_ASSERT(commit.off % lfs->cfg->prog_size == 0);
            dbc_lfs_pair_swap(dir->pair);
            dir->count = end - begin;
            dir->off = commit.off;
            dir->etag = commit.ptag;
            // update gstate
            lfs->gdelta = (dbc_lfs_gstate_t){0};
            if (!relocated) {
                lfs->gdisk = lfs->gstate;
            }
        }
        break;

relocate:
        // commit was corrupted, drop caches and prepare to relocate block
        relocated = true;
        dbc_lfs_cache_drop(lfs, &lfs->pcache);
        if (!tired) {
            DBC_LFS_DEBUG("Bad block at 0x%"PRIx32, dir->pair[1]);
        }

        // can't relocate superblock, filesystem is now frozen
        if (dbc_lfs_pair_cmp(dir->pair, (const dbc_lfs_block_t[2]){0, 1}) == 0) {
            DBC_LFS_WARN("Superblock 0x%"PRIx32" has become unwritable",
                    dir->pair[1]);
            return DBC_LFS_ERR_NOSPC;
        }

        // relocate half of pair
        int err = dbc_lfs_alloc(lfs, &dir->pair[1]);
        if (err && (err != DBC_LFS_ERR_NOSPC || !tired)) {
            return err;
        }

        tired = false;
        continue;
    }

    return relocated ? DBC_LFS_OK_RELOCATED : 0;
}
#endif

#ifndef DBC_LFS_READONLY
static int dbc_lfs_dir_splittingcompact(dbc_lfs_t *lfs, dbc_lfs_mdir_t *dir,
        const struct dbc_lfs_mattr *attrs, int attrcount,
        dbc_lfs_mdir_t *source, uint16_t begin, uint16_t end) {
    while (true) {
        // find size of first split, we do this by halving the split until
        // the metadata is guaranteed to fit
        //
        // Note that this isn't a true binary search, we never increase the
        // split size. This may result in poorly distributed metadata but isn't
        // worth the extra code size or performance hit to fix.
        dbc_lfs_size_t split = begin;
        while (end - split > 1) {
            dbc_lfs_size_t size = 0;
            int err = dbc_lfs_dir_traverse(lfs,
                    source, 0, 0xffffffff, attrs, attrcount,
                    DBC_LFS_MKTAG(0x400, 0x3ff, 0),
                    DBC_LFS_MKTAG(DBC_LFS_TYPE_NAME, 0, 0),
                    split, end, -split,
                    dbc_lfs_dir_commit_size, &size);
            if (err) {
                return err;
            }

            // space is complicated, we need room for:
            //
            // - tail:         4+2*4 = 12 bytes
            // - gstate:       4+3*4 = 16 bytes
            // - move delete:  4     = 4 bytes
            // - crc:          4+4   = 8 bytes
            //                 total = 40 bytes
            //
            // And we cap at half a block to avoid degenerate cases with
            // nearly-full metadata blocks.
            //
            if (end - split < 0xff
                    && size <= dbc_lfs_min(
                        lfs->cfg->block_size - 40,
                        dbc_lfs_alignup(
                            (lfs->cfg->metadata_max
                                ? lfs->cfg->metadata_max
                                : lfs->cfg->block_size)/2,
                            lfs->cfg->prog_size))) {
                break;
            }

            split = split + ((end - split) / 2);
        }

        if (split == begin) {
            // no split needed
            break;
        }

        // split into two metadata pairs and continue
        int err = dbc_lfs_dir_split(lfs, dir, attrs, attrcount,
                source, split, end);
        if (err && err != DBC_LFS_ERR_NOSPC) {
            return err;
        }

        if (err) {
            // we can't allocate a new block, try to compact with degraded
            // performance
            DBC_LFS_WARN("Unable to split {0x%"PRIx32", 0x%"PRIx32"}",
                    dir->pair[0], dir->pair[1]);
            break;
        } else {
            end = split;
        }
    }

    if (dbc_lfs_dir_needsrelocation(lfs, dir)
            && dbc_lfs_pair_cmp(dir->pair, (const dbc_lfs_block_t[2]){0, 1}) == 0) {
        // oh no! we're writing too much to the superblock,
        // should we expand?
        dbc_lfs_ssize_t size = dbc_lfs_fs_size_(lfs);
        if (size < 0) {
            return size;
        }

        // littlefs cannot reclaim expanded superblocks, so expand cautiously
        //
        // if our filesystem is more than ~88% full, don't expand, this is
        // somewhat arbitrary
        if (lfs->block_count - size > lfs->block_count/8) {
            DBC_LFS_DEBUG("Expanding superblock at rev %"PRIu32, dir->rev);
            int err = dbc_lfs_dir_split(lfs, dir, attrs, attrcount,
                    source, begin, end);
            if (err && err != DBC_LFS_ERR_NOSPC) {
                return err;
            }

            if (err) {
                // welp, we tried, if we ran out of space there's not much
                // we can do, we'll error later if we've become frozen
                DBC_LFS_WARN("Unable to expand superblock");
            } else {
                end = begin;
            }
        }
    }

    return dbc_lfs_dir_compact(lfs, dir, attrs, attrcount, source, begin, end);
}
#endif

#ifndef DBC_LFS_READONLY
static int dbc_lfs_dir_relocatingcommit(dbc_lfs_t *lfs, dbc_lfs_mdir_t *dir,
        const dbc_lfs_block_t pair[2],
        const struct dbc_lfs_mattr *attrs, int attrcount,
        dbc_lfs_mdir_t *pdir) {
    int state = 0;

    // calculate changes to the directory
    bool hasdelete = false;
    for (int i = 0; i < attrcount; i++) {
        if (dbc_lfs_tag_type3(attrs[i].tag) == DBC_LFS_TYPE_CREATE) {
            dir->count += 1;
        } else if (dbc_lfs_tag_type3(attrs[i].tag) == DBC_LFS_TYPE_DELETE) {
            DBC_LFS_ASSERT(dir->count > 0);
            dir->count -= 1;
            hasdelete = true;
        } else if (dbc_lfs_tag_type1(attrs[i].tag) == DBC_LFS_TYPE_TAIL) {
            dir->tail[0] = ((dbc_lfs_block_t*)attrs[i].buffer)[0];
            dir->tail[1] = ((dbc_lfs_block_t*)attrs[i].buffer)[1];
            dir->split = (dbc_lfs_tag_chunk(attrs[i].tag) & 1);
            dbc_lfs_pair_fromle32(dir->tail);
        }
    }

    // should we actually drop the directory block?
    if (hasdelete && dir->count == 0) {
        DBC_LFS_ASSERT(pdir);
        int err = dbc_lfs_fs_pred(lfs, dir->pair, pdir);
        if (err && err != DBC_LFS_ERR_NOENT) {
            return err;
        }

        if (err != DBC_LFS_ERR_NOENT && pdir->split) {
            state = DBC_LFS_OK_DROPPED;
            goto fixmlist;
        }
    }

    if (dir->erased) {
        // try to commit
        struct dbc_lfs_commit commit = {
            .block = dir->pair[0],
            .off = dir->off,
            .ptag = dir->etag,
            .crc = 0xffffffff,

            .begin = dir->off,
            .end = (lfs->cfg->metadata_max ?
                lfs->cfg->metadata_max : lfs->cfg->block_size) - 8,
        };

        // traverse attrs that need to be written out
        dbc_lfs_pair_tole32(dir->tail);
        int err = dbc_lfs_dir_traverse(lfs,
                dir, dir->off, dir->etag, attrs, attrcount,
                0, 0, 0, 0, 0,
                dbc_lfs_dir_commit_commit, &(struct dbc_lfs_dir_commit_commit){
                    lfs, &commit});
        dbc_lfs_pair_fromle32(dir->tail);
        if (err) {
            if (err == DBC_LFS_ERR_NOSPC || err == DBC_LFS_ERR_CORRUPT) {
                goto compact;
            }
            return err;
        }

        // commit any global diffs if we have any
        dbc_lfs_gstate_t delta = {0};
        dbc_lfs_gstate_xor(&delta, &lfs->gstate);
        dbc_lfs_gstate_xor(&delta, &lfs->gdisk);
        dbc_lfs_gstate_xor(&delta, &lfs->gdelta);
        delta.tag &= ~DBC_LFS_MKTAG(0, 0, 0x3ff);
        if (!dbc_lfs_gstate_iszero(&delta)) {
            err = dbc_lfs_dir_getgstate(lfs, dir, &delta);
            if (err) {
                return err;
            }

            dbc_lfs_gstate_tole32(&delta);
            err = dbc_lfs_dir_commitattr(lfs, &commit,
                    DBC_LFS_MKTAG(DBC_LFS_TYPE_MOVESTATE, 0x3ff,
                        sizeof(delta)), &delta);
            if (err) {
                if (err == DBC_LFS_ERR_NOSPC || err == DBC_LFS_ERR_CORRUPT) {
                    goto compact;
                }
                return err;
            }
        }

        // finalize commit with the crc
        err = dbc_lfs_dir_commitcrc(lfs, &commit);
        if (err) {
            if (err == DBC_LFS_ERR_NOSPC || err == DBC_LFS_ERR_CORRUPT) {
                goto compact;
            }
            return err;
        }

        // successful commit, update dir
        DBC_LFS_ASSERT(commit.off % lfs->cfg->prog_size == 0);
        dir->off = commit.off;
        dir->etag = commit.ptag;
        // and update gstate
        lfs->gdisk = lfs->gstate;
        lfs->gdelta = (dbc_lfs_gstate_t){0};

        goto fixmlist;
    }

compact:
    // fall back to compaction
    dbc_lfs_cache_drop(lfs, &lfs->pcache);

    state = dbc_lfs_dir_splittingcompact(lfs, dir, attrs, attrcount,
            dir, 0, dir->count);
    if (state < 0) {
        return state;
    }

    goto fixmlist;

fixmlist:;
    // this complicated bit of logic is for fixing up any active
    // metadata-pairs that we may have affected
    //
    // note we have to make two passes since the mdir passed to
    // dbc_lfs_dir_commit could also be in this list, and even then
    // we need to copy the pair so they don't get clobbered if we refetch
    // our mdir.
    dbc_lfs_block_t oldpair[2] = {pair[0], pair[1]};
    for (struct dbc_lfs_mlist *d = lfs->mlist; d; d = d->next) {
        if (dbc_lfs_pair_cmp(d->m.pair, oldpair) == 0) {
            d->m = *dir;
            if (d->m.pair != pair) {
                for (int i = 0; i < attrcount; i++) {
                    if (dbc_lfs_tag_type3(attrs[i].tag) == DBC_LFS_TYPE_DELETE &&
                            d->id == dbc_lfs_tag_id(attrs[i].tag)) {
                        d->m.pair[0] = DBC_LFS_BLOCK_NULL;
                        d->m.pair[1] = DBC_LFS_BLOCK_NULL;
                    } else if (dbc_lfs_tag_type3(attrs[i].tag) == DBC_LFS_TYPE_DELETE &&
                            d->id > dbc_lfs_tag_id(attrs[i].tag)) {
                        d->id -= 1;
                        if (d->type == DBC_LFS_TYPE_DIR) {
                            ((dbc_lfs_dir_t*)d)->pos -= 1;
                        }
                    } else if (dbc_lfs_tag_type3(attrs[i].tag) == DBC_LFS_TYPE_CREATE &&
                            d->id >= dbc_lfs_tag_id(attrs[i].tag)) {
                        d->id += 1;
                        if (d->type == DBC_LFS_TYPE_DIR) {
                            ((dbc_lfs_dir_t*)d)->pos += 1;
                        }
                    }
                }
            }

            while (d->id >= d->m.count && d->m.split) {
                // we split and id is on tail now
                d->id -= d->m.count;
                int err = dbc_lfs_dir_fetch(lfs, &d->m, d->m.tail);
                if (err) {
                    return err;
                }
            }
        }
    }

    return state;
}
#endif

#ifndef DBC_LFS_READONLY
static int dbc_lfs_dir_orphaningcommit(dbc_lfs_t *lfs, dbc_lfs_mdir_t *dir,
        const struct dbc_lfs_mattr *attrs, int attrcount) {
    // check for any inline files that aren't RAM backed and
    // forcefully evict them, needed for filesystem consistency
    for (dbc_lfs_file_t *f = (dbc_lfs_file_t*)lfs->mlist; f; f = f->next) {
        if (dir != &f->m && dbc_lfs_pair_cmp(f->m.pair, dir->pair) == 0 &&
                f->type == DBC_LFS_TYPE_REG && (f->flags & DBC_LFS_F_INLINE) &&
                f->ctz.size > lfs->cfg->cache_size) {
            int err = dbc_lfs_file_outline(lfs, f);
            if (err) {
                return err;
            }

            err = dbc_lfs_file_flush(lfs, f);
            if (err) {
                return err;
            }
        }
    }

    dbc_lfs_block_t lpair[2] = {dir->pair[0], dir->pair[1]};
    dbc_lfs_mdir_t ldir = *dir;
    dbc_lfs_mdir_t pdir;
    int state = dbc_lfs_dir_relocatingcommit(lfs, &ldir, dir->pair,
            attrs, attrcount, &pdir);
    if (state < 0) {
        return state;
    }

    // update if we're not in mlist, note we may have already been
    // updated if we are in mlist
    if (dbc_lfs_pair_cmp(dir->pair, lpair) == 0) {
        *dir = ldir;
    }

    // commit was successful, but may require other changes in the
    // filesystem, these would normally be tail recursive, but we have
    // flattened them here avoid unbounded stack usage

    // need to drop?
    if (state == DBC_LFS_OK_DROPPED) {
        // steal state
        int err = dbc_lfs_dir_getgstate(lfs, dir, &lfs->gdelta);
        if (err) {
            return err;
        }

        // steal tail, note that this can't create a recursive drop
        lpair[0] = pdir.pair[0];
        lpair[1] = pdir.pair[1];
        dbc_lfs_pair_tole32(dir->tail);
        state = dbc_lfs_dir_relocatingcommit(lfs, &pdir, lpair, DBC_LFS_MKATTRS(
                    {DBC_LFS_MKTAG(DBC_LFS_TYPE_TAIL + dir->split, 0x3ff, 8),
                        dir->tail}),
                NULL);
        dbc_lfs_pair_fromle32(dir->tail);
        if (state < 0) {
            return state;
        }

        ldir = pdir;
    }

    // need to relocate?
    bool orphans = false;
    while (state == DBC_LFS_OK_RELOCATED) {
        DBC_LFS_DEBUG("Relocating {0x%"PRIx32", 0x%"PRIx32"} "
                    "-> {0x%"PRIx32", 0x%"PRIx32"}",
                lpair[0], lpair[1], ldir.pair[0], ldir.pair[1]);
        state = 0;

        // update internal root
        if (dbc_lfs_pair_cmp(lpair, lfs->root) == 0) {
            lfs->root[0] = ldir.pair[0];
            lfs->root[1] = ldir.pair[1];
        }

        // update internally tracked dirs
        for (struct dbc_lfs_mlist *d = lfs->mlist; d; d = d->next) {
            if (dbc_lfs_pair_cmp(lpair, d->m.pair) == 0) {
                d->m.pair[0] = ldir.pair[0];
                d->m.pair[1] = ldir.pair[1];
            }

            if (d->type == DBC_LFS_TYPE_DIR &&
                    dbc_lfs_pair_cmp(lpair, ((dbc_lfs_dir_t*)d)->head) == 0) {
                ((dbc_lfs_dir_t*)d)->head[0] = ldir.pair[0];
                ((dbc_lfs_dir_t*)d)->head[1] = ldir.pair[1];
            }
        }

        // find parent
        dbc_lfs_stag_t tag = dbc_lfs_fs_parent(lfs, lpair, &pdir);
        if (tag < 0 && tag != DBC_LFS_ERR_NOENT) {
            return tag;
        }

        bool hasparent = (tag != DBC_LFS_ERR_NOENT);
        if (tag != DBC_LFS_ERR_NOENT) {
            // note that if we have a parent, we must have a pred, so this will
            // always create an orphan
            int err = dbc_lfs_fs_preporphans(lfs, +1);
            if (err) {
                return err;
            }

            // fix pending move in this pair? this looks like an optimization but
            // is in fact _required_ since relocating may outdate the move.
            uint16_t moveid = 0x3ff;
            if (dbc_lfs_gstate_hasmovehere(&lfs->gstate, pdir.pair)) {
                moveid = dbc_lfs_tag_id(lfs->gstate.tag);
                DBC_LFS_DEBUG("Fixing move while relocating "
                        "{0x%"PRIx32", 0x%"PRIx32"} 0x%"PRIx16"\n",
                        pdir.pair[0], pdir.pair[1], moveid);
                dbc_lfs_fs_prepmove(lfs, 0x3ff, NULL);
                if (moveid < dbc_lfs_tag_id(tag)) {
                    tag -= DBC_LFS_MKTAG(0, 1, 0);
                }
            }

            dbc_lfs_block_t ppair[2] = {pdir.pair[0], pdir.pair[1]};
            dbc_lfs_pair_tole32(ldir.pair);
            state = dbc_lfs_dir_relocatingcommit(lfs, &pdir, ppair, DBC_LFS_MKATTRS(
                        {DBC_LFS_MKTAG_IF(moveid != 0x3ff,
                            DBC_LFS_TYPE_DELETE, moveid, 0), NULL},
                        {tag, ldir.pair}),
                    NULL);
            dbc_lfs_pair_fromle32(ldir.pair);
            if (state < 0) {
                return state;
            }

            if (state == DBC_LFS_OK_RELOCATED) {
                lpair[0] = ppair[0];
                lpair[1] = ppair[1];
                ldir = pdir;
                orphans = true;
                continue;
            }
        }

        // find pred
        int err = dbc_lfs_fs_pred(lfs, lpair, &pdir);
        if (err && err != DBC_LFS_ERR_NOENT) {
            return err;
        }
        DBC_LFS_ASSERT(!(hasparent && err == DBC_LFS_ERR_NOENT));

        // if we can't find dir, it must be new
        if (err != DBC_LFS_ERR_NOENT) {
            if (dbc_lfs_gstate_hasorphans(&lfs->gstate)) {
                // next step, clean up orphans
                err = dbc_lfs_fs_preporphans(lfs, -hasparent);
                if (err) {
                    return err;
                }
            }

            // fix pending move in this pair? this looks like an optimization
            // but is in fact _required_ since relocating may outdate the move.
            uint16_t moveid = 0x3ff;
            if (dbc_lfs_gstate_hasmovehere(&lfs->gstate, pdir.pair)) {
                moveid = dbc_lfs_tag_id(lfs->gstate.tag);
                DBC_LFS_DEBUG("Fixing move while relocating "
                        "{0x%"PRIx32", 0x%"PRIx32"} 0x%"PRIx16"\n",
                        pdir.pair[0], pdir.pair[1], moveid);
                dbc_lfs_fs_prepmove(lfs, 0x3ff, NULL);
            }

            // replace bad pair, either we clean up desync, or no desync occured
            lpair[0] = pdir.pair[0];
            lpair[1] = pdir.pair[1];
            dbc_lfs_pair_tole32(ldir.pair);
            state = dbc_lfs_dir_relocatingcommit(lfs, &pdir, lpair, DBC_LFS_MKATTRS(
                        {DBC_LFS_MKTAG_IF(moveid != 0x3ff,
                            DBC_LFS_TYPE_DELETE, moveid, 0), NULL},
                        {DBC_LFS_MKTAG(DBC_LFS_TYPE_TAIL + pdir.split, 0x3ff, 8),
                            ldir.pair}),
                    NULL);
            dbc_lfs_pair_fromle32(ldir.pair);
            if (state < 0) {
                return state;
            }

            ldir = pdir;
        }
    }

    return orphans ? DBC_LFS_OK_ORPHANED : 0;
}
#endif

#ifndef DBC_LFS_READONLY
static int dbc_lfs_dir_commit(dbc_lfs_t *lfs, dbc_lfs_mdir_t *dir,
        const struct dbc_lfs_mattr *attrs, int attrcount) {
    int orphans = dbc_lfs_dir_orphaningcommit(lfs, dir, attrs, attrcount);
    if (orphans < 0) {
        return orphans;
    }

    if (orphans) {
        // make sure we've removed all orphans, this is a noop if there
        // are none, but if we had nested blocks failures we may have
        // created some
        int err = dbc_lfs_fs_deorphan(lfs, false);
        if (err) {
            return err;
        }
    }

    return 0;
}
#endif


/// Top level directory operations ///
#ifndef DBC_LFS_READONLY
static int dbc_lfs_mkdir_(dbc_lfs_t *lfs, const char *path) {
    // deorphan if we haven't yet, needed at most once after poweron
    int err = dbc_lfs_fs_forceconsistency(lfs);
    if (err) {
        return err;
    }

    struct dbc_lfs_mlist cwd;
    cwd.next = lfs->mlist;
    uint16_t id;
    err = dbc_lfs_dir_find(lfs, &cwd.m, &path, &id);
    if (!(err == DBC_LFS_ERR_NOENT && id != 0x3ff)) {
        return (err < 0) ? err : DBC_LFS_ERR_EXIST;
    }

    // check that name fits
    dbc_lfs_size_t nlen = strlen(path);
    if (nlen > lfs->name_max) {
        return DBC_LFS_ERR_NAMETOOLONG;
    }

    // build up new directory
    dbc_lfs_alloc_ckpoint(lfs);
    dbc_lfs_mdir_t dir;
    err = dbc_lfs_dir_alloc(lfs, &dir);
    if (err) {
        return err;
    }

    // find end of list
    dbc_lfs_mdir_t pred = cwd.m;
    while (pred.split) {
        err = dbc_lfs_dir_fetch(lfs, &pred, pred.tail);
        if (err) {
            return err;
        }
    }

    // setup dir
    dbc_lfs_pair_tole32(pred.tail);
    err = dbc_lfs_dir_commit(lfs, &dir, DBC_LFS_MKATTRS(
            {DBC_LFS_MKTAG(DBC_LFS_TYPE_SOFTTAIL, 0x3ff, 8), pred.tail}));
    dbc_lfs_pair_fromle32(pred.tail);
    if (err) {
        return err;
    }

    // current block not end of list?
    if (cwd.m.split) {
        // update tails, this creates a desync
        err = dbc_lfs_fs_preporphans(lfs, +1);
        if (err) {
            return err;
        }

        // it's possible our predecessor has to be relocated, and if
        // our parent is our predecessor's predecessor, this could have
        // caused our parent to go out of date, fortunately we can hook
        // ourselves into littlefs to catch this
        cwd.type = 0;
        cwd.id = 0;
        lfs->mlist = &cwd;

        dbc_lfs_pair_tole32(dir.pair);
        err = dbc_lfs_dir_commit(lfs, &pred, DBC_LFS_MKATTRS(
                {DBC_LFS_MKTAG(DBC_LFS_TYPE_SOFTTAIL, 0x3ff, 8), dir.pair}));
        dbc_lfs_pair_fromle32(dir.pair);
        if (err) {
            lfs->mlist = cwd.next;
            return err;
        }

        lfs->mlist = cwd.next;
        err = dbc_lfs_fs_preporphans(lfs, -1);
        if (err) {
            return err;
        }
    }

    // now insert into our parent block
    dbc_lfs_pair_tole32(dir.pair);
    err = dbc_lfs_dir_commit(lfs, &cwd.m, DBC_LFS_MKATTRS(
            {DBC_LFS_MKTAG(DBC_LFS_TYPE_CREATE, id, 0), NULL},
            {DBC_LFS_MKTAG(DBC_LFS_TYPE_DIR, id, nlen), path},
            {DBC_LFS_MKTAG(DBC_LFS_TYPE_DIRSTRUCT, id, 8), dir.pair},
            {DBC_LFS_MKTAG_IF(!cwd.m.split,
                DBC_LFS_TYPE_SOFTTAIL, 0x3ff, 8), dir.pair}));
    dbc_lfs_pair_fromle32(dir.pair);
    if (err) {
        return err;
    }

    return 0;
}
#endif

static int dbc_lfs_dir_open_(dbc_lfs_t *lfs, dbc_lfs_dir_t *dir, const char *path) {
    dbc_lfs_stag_t tag = dbc_lfs_dir_find(lfs, &dir->m, &path, NULL);
    if (tag < 0) {
        return tag;
    }

    if (dbc_lfs_tag_type3(tag) != DBC_LFS_TYPE_DIR) {
        return DBC_LFS_ERR_NOTDIR;
    }

    dbc_lfs_block_t pair[2];
    if (dbc_lfs_tag_id(tag) == 0x3ff) {
        // handle root dir separately
        pair[0] = lfs->root[0];
        pair[1] = lfs->root[1];
    } else {
        // get dir pair from parent
        dbc_lfs_stag_t res = dbc_lfs_dir_get(lfs, &dir->m, DBC_LFS_MKTAG(0x700, 0x3ff, 0),
                DBC_LFS_MKTAG(DBC_LFS_TYPE_STRUCT, dbc_lfs_tag_id(tag), 8), pair);
        if (res < 0) {
            return res;
        }
        dbc_lfs_pair_fromle32(pair);
    }

    // fetch first pair
    int err = dbc_lfs_dir_fetch(lfs, &dir->m, pair);
    if (err) {
        return err;
    }

    // setup entry
    dir->head[0] = dir->m.pair[0];
    dir->head[1] = dir->m.pair[1];
    dir->id = 0;
    dir->pos = 0;

    // add to list of mdirs
    dir->type = DBC_LFS_TYPE_DIR;
    dbc_lfs_mlist_append(lfs, (struct dbc_lfs_mlist *)dir);

    return 0;
}

static int dbc_lfs_dir_close_(dbc_lfs_t *lfs, dbc_lfs_dir_t *dir) {
    // remove from list of mdirs
    dbc_lfs_mlist_remove(lfs, (struct dbc_lfs_mlist *)dir);

    return 0;
}

static int dbc_lfs_dir_read_(dbc_lfs_t *lfs, dbc_lfs_dir_t *dir, struct dbc_lfs_info *info) {
    memset(info, 0, sizeof(*info));

    // special offset for '.' and '..'
    if (dir->pos == 0) {
        info->type = DBC_LFS_TYPE_DIR;
        strcpy(info->name, ".");
        dir->pos += 1;
        return true;
    } else if (dir->pos == 1) {
        info->type = DBC_LFS_TYPE_DIR;
        strcpy(info->name, "..");
        dir->pos += 1;
        return true;
    }

    while (true) {
        if (dir->id == dir->m.count) {
            if (!dir->m.split) {
                return false;
            }

            int err = dbc_lfs_dir_fetch(lfs, &dir->m, dir->m.tail);
            if (err) {
                return err;
            }

            dir->id = 0;
        }

        int err = dbc_lfs_dir_getinfo(lfs, &dir->m, dir->id, info);
        if (err && err != DBC_LFS_ERR_NOENT) {
            return err;
        }

        dir->id += 1;
        if (err != DBC_LFS_ERR_NOENT) {
            break;
        }
    }

    dir->pos += 1;
    return true;
}

static int dbc_lfs_dir_seek_(dbc_lfs_t *lfs, dbc_lfs_dir_t *dir, dbc_lfs_off_t off) {
    // simply walk from head dir
    int err = dbc_lfs_dir_rewind_(lfs, dir);
    if (err) {
        return err;
    }

    // first two for ./..
    dir->pos = dbc_lfs_min(2, off);
    off -= dir->pos;

    // skip superblock entry
    dir->id = (off > 0 && dbc_lfs_pair_cmp(dir->head, lfs->root) == 0);

    while (off > 0) {
        if (dir->id == dir->m.count) {
            if (!dir->m.split) {
                return DBC_LFS_ERR_INVAL;
            }

            err = dbc_lfs_dir_fetch(lfs, &dir->m, dir->m.tail);
            if (err) {
                return err;
            }

            dir->id = 0;
        }

        int diff = dbc_lfs_min(dir->m.count - dir->id, off);
        dir->id += diff;
        dir->pos += diff;
        off -= diff;
    }

    return 0;
}

static dbc_lfs_soff_t dbc_lfs_dir_tell_(dbc_lfs_t *lfs, dbc_lfs_dir_t *dir) {
    (void)lfs;
    return dir->pos;
}

static int dbc_lfs_dir_rewind_(dbc_lfs_t *lfs, dbc_lfs_dir_t *dir) {
    // reload the head dir
    int err = dbc_lfs_dir_fetch(lfs, &dir->m, dir->head);
    if (err) {
        return err;
    }

    dir->id = 0;
    dir->pos = 0;
    return 0;
}


/// File index list operations ///
static int dbc_lfs_ctz_index(dbc_lfs_t *lfs, dbc_lfs_off_t *off) {
    dbc_lfs_off_t size = *off;
    dbc_lfs_off_t b = lfs->cfg->block_size - 2*4;
    dbc_lfs_off_t i = size / b;
    if (i == 0) {
        return 0;
    }

    i = (size - 4*(dbc_lfs_popc(i-1)+2)) / b;
    *off = size - b*i - 4*dbc_lfs_popc(i);
    return i;
}

static int dbc_lfs_ctz_find(dbc_lfs_t *lfs,
        const dbc_lfs_cache_t *pcache, dbc_lfs_cache_t *rcache,
        dbc_lfs_block_t head, dbc_lfs_size_t size,
        dbc_lfs_size_t pos, dbc_lfs_block_t *block, dbc_lfs_off_t *off) {
    if (size == 0) {
        *block = DBC_LFS_BLOCK_NULL;
        *off = 0;
        return 0;
    }

    dbc_lfs_off_t current = dbc_lfs_ctz_index(lfs, &(dbc_lfs_off_t){size-1});
    dbc_lfs_off_t target = dbc_lfs_ctz_index(lfs, &pos);

    while (current > target) {
        dbc_lfs_size_t skip = dbc_lfs_min(
                dbc_lfs_npw2(current-target+1) - 1,
                dbc_lfs_ctz(current));

        int err = dbc_lfs_bd_read(lfs,
                pcache, rcache, sizeof(head),
                head, 4*skip, &head, sizeof(head));
        head = dbc_lfs_fromle32(head);
        if (err) {
            return err;
        }

        current -= 1 << skip;
    }

    *block = head;
    *off = pos;
    return 0;
}

#ifndef DBC_LFS_READONLY
static int dbc_lfs_ctz_extend(dbc_lfs_t *lfs,
        dbc_lfs_cache_t *pcache, dbc_lfs_cache_t *rcache,
        dbc_lfs_block_t head, dbc_lfs_size_t size,
        dbc_lfs_block_t *block, dbc_lfs_off_t *off) {
    while (true) {
        // go ahead and grab a block
        dbc_lfs_block_t nblock;
        int err = dbc_lfs_alloc(lfs, &nblock);
        if (err) {
            return err;
        }

        {
            err = dbc_lfs_bd_erase(lfs, nblock);
            if (err) {
                if (err == DBC_LFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }

            if (size == 0) {
                *block = nblock;
                *off = 0;
                return 0;
            }

            dbc_lfs_size_t noff = size - 1;
            dbc_lfs_off_t index = dbc_lfs_ctz_index(lfs, &noff);
            noff = noff + 1;

            // just copy out the last block if it is incomplete
            if (noff != lfs->cfg->block_size) {
                for (dbc_lfs_off_t i = 0; i < noff; i++) {
                    uint8_t data;
                    err = dbc_lfs_bd_read(lfs,
                            NULL, rcache, noff-i,
                            head, i, &data, 1);
                    if (err) {
                        return err;
                    }

                    err = dbc_lfs_bd_prog(lfs,
                            pcache, rcache, true,
                            nblock, i, &data, 1);
                    if (err) {
                        if (err == DBC_LFS_ERR_CORRUPT) {
                            goto relocate;
                        }
                        return err;
                    }
                }

                *block = nblock;
                *off = noff;
                return 0;
            }

            // append block
            index += 1;
            dbc_lfs_size_t skips = dbc_lfs_ctz(index) + 1;
            dbc_lfs_block_t nhead = head;
            for (dbc_lfs_off_t i = 0; i < skips; i++) {
                nhead = dbc_lfs_tole32(nhead);
                err = dbc_lfs_bd_prog(lfs, pcache, rcache, true,
                        nblock, 4*i, &nhead, 4);
                nhead = dbc_lfs_fromle32(nhead);
                if (err) {
                    if (err == DBC_LFS_ERR_CORRUPT) {
                        goto relocate;
                    }
                    return err;
                }

                if (i != skips-1) {
                    err = dbc_lfs_bd_read(lfs,
                            NULL, rcache, sizeof(nhead),
                            nhead, 4*i, &nhead, sizeof(nhead));
                    nhead = dbc_lfs_fromle32(nhead);
                    if (err) {
                        return err;
                    }
                }
            }

            *block = nblock;
            *off = 4*skips;
            return 0;
        }

relocate:
        DBC_LFS_DEBUG("Bad block at 0x%"PRIx32, nblock);

        // just clear cache and try a new block
        dbc_lfs_cache_drop(lfs, pcache);
    }
}
#endif

static int dbc_lfs_ctz_traverse(dbc_lfs_t *lfs,
        const dbc_lfs_cache_t *pcache, dbc_lfs_cache_t *rcache,
        dbc_lfs_block_t head, dbc_lfs_size_t size,
        int (*cb)(void*, dbc_lfs_block_t), void *data) {
    if (size == 0) {
        return 0;
    }

    dbc_lfs_off_t index = dbc_lfs_ctz_index(lfs, &(dbc_lfs_off_t){size-1});

    while (true) {
        int err = cb(data, head);
        if (err) {
            return err;
        }

        if (index == 0) {
            return 0;
        }

        dbc_lfs_block_t heads[2];
        int count = 2 - (index & 1);
        err = dbc_lfs_bd_read(lfs,
                pcache, rcache, count*sizeof(head),
                head, 0, &heads, count*sizeof(head));
        heads[0] = dbc_lfs_fromle32(heads[0]);
        heads[1] = dbc_lfs_fromle32(heads[1]);
        if (err) {
            return err;
        }

        for (int i = 0; i < count-1; i++) {
            err = cb(data, heads[i]);
            if (err) {
                return err;
            }
        }

        head = heads[count-1];
        index -= count;
    }
}


/// Top level file operations ///
static int dbc_lfs_file_opencfg_(dbc_lfs_t *lfs, dbc_lfs_file_t *file,
        const char *path, int flags,
        const struct dbc_lfs_file_config *cfg) {
#ifndef DBC_LFS_READONLY
    // deorphan if we haven't yet, needed at most once after poweron
    if ((flags & DBC_LFS_O_WRONLY) == DBC_LFS_O_WRONLY) {
        int err = dbc_lfs_fs_forceconsistency(lfs);
        if (err) {
            return err;
        }
    }
#else
    DBC_LFS_ASSERT((flags & DBC_LFS_O_RDONLY) == DBC_LFS_O_RDONLY);
#endif

    // setup simple file details
    int err;
    file->cfg = cfg;
    file->flags = flags;
    file->pos = 0;
    file->off = 0;
    file->cache.buffer = NULL;

    // allocate entry for file if it doesn't exist
    dbc_lfs_stag_t tag = dbc_lfs_dir_find(lfs, &file->m, &path, &file->id);
    if (tag < 0 && !(tag == DBC_LFS_ERR_NOENT && file->id != 0x3ff)) {
        err = tag;
        goto cleanup;
    }

    // get id, add to list of mdirs to catch update changes
    file->type = DBC_LFS_TYPE_REG;
    dbc_lfs_mlist_append(lfs, (struct dbc_lfs_mlist *)file);

#ifdef DBC_LFS_READONLY
    if (tag == DBC_LFS_ERR_NOENT) {
        err = DBC_LFS_ERR_NOENT;
        goto cleanup;
#else
    if (tag == DBC_LFS_ERR_NOENT) {
        if (!(flags & DBC_LFS_O_CREAT)) {
            err = DBC_LFS_ERR_NOENT;
            goto cleanup;
        }

        // check that name fits
        dbc_lfs_size_t nlen = strlen(path);
        if (nlen > lfs->name_max) {
            err = DBC_LFS_ERR_NAMETOOLONG;
            goto cleanup;
        }

        // get next slot and create entry to remember name
        err = dbc_lfs_dir_commit(lfs, &file->m, DBC_LFS_MKATTRS(
                {DBC_LFS_MKTAG(DBC_LFS_TYPE_CREATE, file->id, 0), NULL},
                {DBC_LFS_MKTAG(DBC_LFS_TYPE_REG, file->id, nlen), path},
                {DBC_LFS_MKTAG(DBC_LFS_TYPE_INLINESTRUCT, file->id, 0), NULL}));

        // it may happen that the file name doesn't fit in the metadata blocks, e.g., a 256 byte file name will
        // not fit in a 128 byte block.
        err = (err == DBC_LFS_ERR_NOSPC) ? DBC_LFS_ERR_NAMETOOLONG : err;
        if (err) {
            goto cleanup;
        }

        tag = DBC_LFS_MKTAG(DBC_LFS_TYPE_INLINESTRUCT, 0, 0);
    } else if (flags & DBC_LFS_O_EXCL) {
        err = DBC_LFS_ERR_EXIST;
        goto cleanup;
#endif
    } else if (dbc_lfs_tag_type3(tag) != DBC_LFS_TYPE_REG) {
        err = DBC_LFS_ERR_ISDIR;
        goto cleanup;
#ifndef DBC_LFS_READONLY
    } else if (flags & DBC_LFS_O_TRUNC) {
        // truncate if requested
        tag = DBC_LFS_MKTAG(DBC_LFS_TYPE_INLINESTRUCT, file->id, 0);
        file->flags |= DBC_LFS_F_DIRTY;
#endif
    } else {
        // try to load what's on disk, if it's inlined we'll fix it later
        tag = dbc_lfs_dir_get(lfs, &file->m, DBC_LFS_MKTAG(0x700, 0x3ff, 0),
                DBC_LFS_MKTAG(DBC_LFS_TYPE_STRUCT, file->id, 8), &file->ctz);
        if (tag < 0) {
            err = tag;
            goto cleanup;
        }
        dbc_lfs_ctz_fromle32(&file->ctz);
    }

    // fetch attrs
    for (unsigned i = 0; i < file->cfg->attr_count; i++) {
        // if opened for read / read-write operations
        if ((file->flags & DBC_LFS_O_RDONLY) == DBC_LFS_O_RDONLY) {
            dbc_lfs_stag_t res = dbc_lfs_dir_get(lfs, &file->m,
                    DBC_LFS_MKTAG(0x7ff, 0x3ff, 0),
                    DBC_LFS_MKTAG(DBC_LFS_TYPE_USERATTR + file->cfg->attrs[i].type,
                        file->id, file->cfg->attrs[i].size),
                        file->cfg->attrs[i].buffer);
            if (res < 0 && res != DBC_LFS_ERR_NOENT) {
                err = res;
                goto cleanup;
            }
        }

#ifndef DBC_LFS_READONLY
        // if opened for write / read-write operations
        if ((file->flags & DBC_LFS_O_WRONLY) == DBC_LFS_O_WRONLY) {
            if (file->cfg->attrs[i].size > lfs->attr_max) {
                err = DBC_LFS_ERR_NOSPC;
                goto cleanup;
            }

            file->flags |= DBC_LFS_F_DIRTY;
        }
#endif
    }

    // allocate buffer if needed
    if (file->cfg->buffer) {
        file->cache.buffer = file->cfg->buffer;
    } else {
        file->cache.buffer = dbc_lfs_malloc(lfs->cfg->cache_size);
        if (!file->cache.buffer) {
            err = DBC_LFS_ERR_NOMEM;
            goto cleanup;
        }
    }

    // zero to avoid information leak
    dbc_lfs_cache_zero(lfs, &file->cache);

    if (dbc_lfs_tag_type3(tag) == DBC_LFS_TYPE_INLINESTRUCT) {
        // load inline files
        file->ctz.head = DBC_LFS_BLOCK_INLINE;
        file->ctz.size = dbc_lfs_tag_size(tag);
        file->flags |= DBC_LFS_F_INLINE;
        file->cache.block = file->ctz.head;
        file->cache.off = 0;
        file->cache.size = lfs->cfg->cache_size;

        // don't always read (may be new/trunc file)
        if (file->ctz.size > 0) {
            dbc_lfs_stag_t res = dbc_lfs_dir_get(lfs, &file->m,
                    DBC_LFS_MKTAG(0x700, 0x3ff, 0),
                    DBC_LFS_MKTAG(DBC_LFS_TYPE_STRUCT, file->id,
                        dbc_lfs_min(file->cache.size, 0x3fe)),
                    file->cache.buffer);
            if (res < 0) {
                err = res;
                goto cleanup;
            }
        }
    }

    return 0;

cleanup:
    // clean up lingering resources
#ifndef DBC_LFS_READONLY
    file->flags |= DBC_LFS_F_ERRED;
#endif
    dbc_lfs_file_close_(lfs, file);
    return err;
}

#ifndef DBC_LFS_NO_MALLOC
static int dbc_lfs_file_open_(dbc_lfs_t *lfs, dbc_lfs_file_t *file,
        const char *path, int flags) {
    static const struct dbc_lfs_file_config defaults = {0};
    int err = dbc_lfs_file_opencfg_(lfs, file, path, flags, &defaults);
    return err;
}
#endif

static int dbc_lfs_file_close_(dbc_lfs_t *lfs, dbc_lfs_file_t *file) {
#ifndef DBC_LFS_READONLY
    int err = dbc_lfs_file_sync_(lfs, file);
#else
    int err = 0;
#endif

    // remove from list of mdirs
    dbc_lfs_mlist_remove(lfs, (struct dbc_lfs_mlist*)file);

    // clean up memory
    if (!file->cfg->buffer) {
        dbc_lfs_free(file->cache.buffer);
    }

    return err;
}


#ifndef DBC_LFS_READONLY
static int dbc_lfs_file_relocate(dbc_lfs_t *lfs, dbc_lfs_file_t *file) {
    while (true) {
        // just relocate what exists into new block
        dbc_lfs_block_t nblock;
        int err = dbc_lfs_alloc(lfs, &nblock);
        if (err) {
            return err;
        }

        err = dbc_lfs_bd_erase(lfs, nblock);
        if (err) {
            if (err == DBC_LFS_ERR_CORRUPT) {
                goto relocate;
            }
            return err;
        }

        // either read from dirty cache or disk
        for (dbc_lfs_off_t i = 0; i < file->off; i++) {
            uint8_t data;
            if (file->flags & DBC_LFS_F_INLINE) {
                err = dbc_lfs_dir_getread(lfs, &file->m,
                        // note we evict inline files before they can be dirty
                        NULL, &file->cache, file->off-i,
                        DBC_LFS_MKTAG(0xfff, 0x1ff, 0),
                        DBC_LFS_MKTAG(DBC_LFS_TYPE_INLINESTRUCT, file->id, 0),
                        i, &data, 1);
                if (err) {
                    return err;
                }
            } else {
                err = dbc_lfs_bd_read(lfs,
                        &file->cache, &lfs->rcache, file->off-i,
                        file->block, i, &data, 1);
                if (err) {
                    return err;
                }
            }

            err = dbc_lfs_bd_prog(lfs,
                    &lfs->pcache, &lfs->rcache, true,
                    nblock, i, &data, 1);
            if (err) {
                if (err == DBC_LFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }
        }

        // copy over new state of file
        memcpy(file->cache.buffer, lfs->pcache.buffer, lfs->cfg->cache_size);
        file->cache.block = lfs->pcache.block;
        file->cache.off = lfs->pcache.off;
        file->cache.size = lfs->pcache.size;
        dbc_lfs_cache_zero(lfs, &lfs->pcache);

        file->block = nblock;
        file->flags |= DBC_LFS_F_WRITING;
        return 0;

relocate:
        DBC_LFS_DEBUG("Bad block at 0x%"PRIx32, nblock);

        // just clear cache and try a new block
        dbc_lfs_cache_drop(lfs, &lfs->pcache);
    }
}
#endif

#ifndef DBC_LFS_READONLY
static int dbc_lfs_file_outline(dbc_lfs_t *lfs, dbc_lfs_file_t *file) {
    file->off = file->pos;
    dbc_lfs_alloc_ckpoint(lfs);
    int err = dbc_lfs_file_relocate(lfs, file);
    if (err) {
        return err;
    }

    file->flags &= ~DBC_LFS_F_INLINE;
    return 0;
}
#endif

static int dbc_lfs_file_flush(dbc_lfs_t *lfs, dbc_lfs_file_t *file) {
    if (file->flags & DBC_LFS_F_READING) {
        if (!(file->flags & DBC_LFS_F_INLINE)) {
            dbc_lfs_cache_drop(lfs, &file->cache);
        }
        file->flags &= ~DBC_LFS_F_READING;
    }

#ifndef DBC_LFS_READONLY
    if (file->flags & DBC_LFS_F_WRITING) {
        dbc_lfs_off_t pos = file->pos;

        if (!(file->flags & DBC_LFS_F_INLINE)) {
            // copy over anything after current branch
            dbc_lfs_file_t orig = {
                .ctz.head = file->ctz.head,
                .ctz.size = file->ctz.size,
                .flags = DBC_LFS_O_RDONLY,
                .pos = file->pos,
                .cache = lfs->rcache,
            };
            dbc_lfs_cache_drop(lfs, &lfs->rcache);

            while (file->pos < file->ctz.size) {
                // copy over a byte at a time, leave it up to caching
                // to make this efficient
                uint8_t data;
                dbc_lfs_ssize_t res = dbc_lfs_file_flushedread(lfs, &orig, &data, 1);
                if (res < 0) {
                    return res;
                }

                res = dbc_lfs_file_flushedwrite(lfs, file, &data, 1);
                if (res < 0) {
                    return res;
                }

                // keep our reference to the rcache in sync
                if (lfs->rcache.block != DBC_LFS_BLOCK_NULL) {
                    dbc_lfs_cache_drop(lfs, &orig.cache);
                    dbc_lfs_cache_drop(lfs, &lfs->rcache);
                }
            }

            // write out what we have
            while (true) {
                int err = dbc_lfs_bd_flush(lfs, &file->cache, &lfs->rcache, true);
                if (err) {
                    if (err == DBC_LFS_ERR_CORRUPT) {
                        goto relocate;
                    }
                    return err;
                }

                break;

relocate:
                DBC_LFS_DEBUG("Bad block at 0x%"PRIx32, file->block);
                err = dbc_lfs_file_relocate(lfs, file);
                if (err) {
                    return err;
                }
            }
        } else {
            file->pos = dbc_lfs_max(file->pos, file->ctz.size);
        }

        // actual file updates
        file->ctz.head = file->block;
        file->ctz.size = file->pos;
        file->flags &= ~DBC_LFS_F_WRITING;
        file->flags |= DBC_LFS_F_DIRTY;

        file->pos = pos;
    }
#endif

    return 0;
}

#ifndef DBC_LFS_READONLY
static int dbc_lfs_file_sync_(dbc_lfs_t *lfs, dbc_lfs_file_t *file) {
    if (file->flags & DBC_LFS_F_ERRED) {
        // it's not safe to do anything if our file errored
        return 0;
    }

    int err = dbc_lfs_file_flush(lfs, file);
    if (err) {
        file->flags |= DBC_LFS_F_ERRED;
        return err;
    }


    if ((file->flags & DBC_LFS_F_DIRTY) &&
            !dbc_lfs_pair_isnull(file->m.pair)) {
        // before we commit metadata, we need sync the disk to make sure
        // data writes don't complete after metadata writes
        if (!(file->flags & DBC_LFS_F_INLINE)) {
            err = dbc_lfs_bd_sync(lfs, &lfs->pcache, &lfs->rcache, false);
            if (err) {
                return err;
            }
        }

        // update dir entry
        uint16_t type;
        const void *buffer;
        dbc_lfs_size_t size;
        struct dbc_lfs_ctz ctz;
        if (file->flags & DBC_LFS_F_INLINE) {
            // inline the whole file
            type = DBC_LFS_TYPE_INLINESTRUCT;
            buffer = file->cache.buffer;
            size = file->ctz.size;
        } else {
            // update the ctz reference
            type = DBC_LFS_TYPE_CTZSTRUCT;
            // copy ctz so alloc will work during a relocate
            ctz = file->ctz;
            dbc_lfs_ctz_tole32(&ctz);
            buffer = &ctz;
            size = sizeof(ctz);
        }

        // commit file data and attributes
        err = dbc_lfs_dir_commit(lfs, &file->m, DBC_LFS_MKATTRS(
                {DBC_LFS_MKTAG(type, file->id, size), buffer},
                {DBC_LFS_MKTAG(DBC_LFS_FROM_USERATTRS, file->id,
                    file->cfg->attr_count), file->cfg->attrs}));
        if (err) {
            file->flags |= DBC_LFS_F_ERRED;
            return err;
        }

        file->flags &= ~DBC_LFS_F_DIRTY;
    }

    return 0;
}
#endif

static dbc_lfs_ssize_t dbc_lfs_file_flushedread(dbc_lfs_t *lfs, dbc_lfs_file_t *file,
        void *buffer, dbc_lfs_size_t size) {
    uint8_t *data = buffer;
    dbc_lfs_size_t nsize = size;

    if (file->pos >= file->ctz.size) {
        // eof if past end
        return 0;
    }

    size = dbc_lfs_min(size, file->ctz.size - file->pos);
    nsize = size;

    while (nsize > 0) {
        // check if we need a new block
        if (!(file->flags & DBC_LFS_F_READING) ||
                file->off == lfs->cfg->block_size) {
            if (!(file->flags & DBC_LFS_F_INLINE)) {
                int err = dbc_lfs_ctz_find(lfs, NULL, &file->cache,
                        file->ctz.head, file->ctz.size,
                        file->pos, &file->block, &file->off);
                if (err) {
                    return err;
                }
            } else {
                file->block = DBC_LFS_BLOCK_INLINE;
                file->off = file->pos;
            }

            file->flags |= DBC_LFS_F_READING;
        }

        // read as much as we can in current block
        dbc_lfs_size_t diff = dbc_lfs_min(nsize, lfs->cfg->block_size - file->off);
        if (file->flags & DBC_LFS_F_INLINE) {
            int err = dbc_lfs_dir_getread(lfs, &file->m,
                    NULL, &file->cache, lfs->cfg->block_size,
                    DBC_LFS_MKTAG(0xfff, 0x1ff, 0),
                    DBC_LFS_MKTAG(DBC_LFS_TYPE_INLINESTRUCT, file->id, 0),
                    file->off, data, diff);
            if (err) {
                return err;
            }
        } else {
            int err = dbc_lfs_bd_read(lfs,
                    NULL, &file->cache, lfs->cfg->block_size,
                    file->block, file->off, data, diff);
            if (err) {
                return err;
            }
        }

        file->pos += diff;
        file->off += diff;
        data += diff;
        nsize -= diff;
    }

    return size;
}

static dbc_lfs_ssize_t dbc_lfs_file_read_(dbc_lfs_t *lfs, dbc_lfs_file_t *file,
        void *buffer, dbc_lfs_size_t size) {
    DBC_LFS_ASSERT((file->flags & DBC_LFS_O_RDONLY) == DBC_LFS_O_RDONLY);

#ifndef DBC_LFS_READONLY
    if (file->flags & DBC_LFS_F_WRITING) {
        // flush out any writes
        int err = dbc_lfs_file_flush(lfs, file);
        if (err) {
            return err;
        }
    }
#endif

    return dbc_lfs_file_flushedread(lfs, file, buffer, size);
}


#ifndef DBC_LFS_READONLY
static dbc_lfs_ssize_t dbc_lfs_file_flushedwrite(dbc_lfs_t *lfs, dbc_lfs_file_t *file,
        const void *buffer, dbc_lfs_size_t size) {
    const uint8_t *data = buffer;
    dbc_lfs_size_t nsize = size;

    if ((file->flags & DBC_LFS_F_INLINE) &&
            dbc_lfs_max(file->pos+nsize, file->ctz.size) > lfs->inline_max) {
        // inline file doesn't fit anymore
        int err = dbc_lfs_file_outline(lfs, file);
        if (err) {
            file->flags |= DBC_LFS_F_ERRED;
            return err;
        }
    }

    while (nsize > 0) {
        // check if we need a new block
        if (!(file->flags & DBC_LFS_F_WRITING) ||
                file->off == lfs->cfg->block_size) {
            if (!(file->flags & DBC_LFS_F_INLINE)) {
                if (!(file->flags & DBC_LFS_F_WRITING) && file->pos > 0) {
                    // find out which block we're extending from
                    int err = dbc_lfs_ctz_find(lfs, NULL, &file->cache,
                            file->ctz.head, file->ctz.size,
                            file->pos-1, &file->block, &(dbc_lfs_off_t){0});
                    if (err) {
                        file->flags |= DBC_LFS_F_ERRED;
                        return err;
                    }

                    // mark cache as dirty since we may have read data into it
                    dbc_lfs_cache_zero(lfs, &file->cache);
                }

                // extend file with new blocks
                dbc_lfs_alloc_ckpoint(lfs);
                int err = dbc_lfs_ctz_extend(lfs, &file->cache, &lfs->rcache,
                        file->block, file->pos,
                        &file->block, &file->off);
                if (err) {
                    file->flags |= DBC_LFS_F_ERRED;
                    return err;
                }
            } else {
                file->block = DBC_LFS_BLOCK_INLINE;
                file->off = file->pos;
            }

            file->flags |= DBC_LFS_F_WRITING;
        }

        // program as much as we can in current block
        dbc_lfs_size_t diff = dbc_lfs_min(nsize, lfs->cfg->block_size - file->off);
        while (true) {
            int err = dbc_lfs_bd_prog(lfs, &file->cache, &lfs->rcache, true,
                    file->block, file->off, data, diff);
            if (err) {
                if (err == DBC_LFS_ERR_CORRUPT) {
                    goto relocate;
                }
                file->flags |= DBC_LFS_F_ERRED;
                return err;
            }

            break;
relocate:
            err = dbc_lfs_file_relocate(lfs, file);
            if (err) {
                file->flags |= DBC_LFS_F_ERRED;
                return err;
            }
        }

        file->pos += diff;
        file->off += diff;
        data += diff;
        nsize -= diff;

        dbc_lfs_alloc_ckpoint(lfs);
    }

    return size;
}

static dbc_lfs_ssize_t dbc_lfs_file_write_(dbc_lfs_t *lfs, dbc_lfs_file_t *file,
        const void *buffer, dbc_lfs_size_t size) {
    DBC_LFS_ASSERT((file->flags & DBC_LFS_O_WRONLY) == DBC_LFS_O_WRONLY);

    if (file->flags & DBC_LFS_F_READING) {
        // drop any reads
        int err = dbc_lfs_file_flush(lfs, file);
        if (err) {
            return err;
        }
    }

    if ((file->flags & DBC_LFS_O_APPEND) && file->pos < file->ctz.size) {
        file->pos = file->ctz.size;
    }

    if (file->pos + size > lfs->file_max) {
        // Larger than file limit?
        return DBC_LFS_ERR_FBIG;
    }

    if (!(file->flags & DBC_LFS_F_WRITING) && file->pos > file->ctz.size) {
        // fill with zeros
        dbc_lfs_off_t pos = file->pos;
        file->pos = file->ctz.size;

        while (file->pos < pos) {
            dbc_lfs_ssize_t res = dbc_lfs_file_flushedwrite(lfs, file, &(uint8_t){0}, 1);
            if (res < 0) {
                return res;
            }
        }
    }

    dbc_lfs_ssize_t nsize = dbc_lfs_file_flushedwrite(lfs, file, buffer, size);
    if (nsize < 0) {
        return nsize;
    }

    file->flags &= ~DBC_LFS_F_ERRED;
    return nsize;
}
#endif

static dbc_lfs_soff_t dbc_lfs_file_seek_(dbc_lfs_t *lfs, dbc_lfs_file_t *file,
        dbc_lfs_soff_t off, int whence) {
    // find new pos
    dbc_lfs_off_t npos = file->pos;
    if (whence == DBC_LFS_SEEK_SET) {
        npos = off;
    } else if (whence == DBC_LFS_SEEK_CUR) {
        if ((dbc_lfs_soff_t)file->pos + off < 0) {
            return DBC_LFS_ERR_INVAL;
        } else {
            npos = file->pos + off;
        }
    } else if (whence == DBC_LFS_SEEK_END) {
        dbc_lfs_soff_t res = dbc_lfs_file_size_(lfs, file) + off;
        if (res < 0) {
            return DBC_LFS_ERR_INVAL;
        } else {
            npos = res;
        }
    }

    if (npos > lfs->file_max) {
        // file position out of range
        return DBC_LFS_ERR_INVAL;
    }

    if (file->pos == npos) {
        // noop - position has not changed
        return npos;
    }

    // if we're only reading and our new offset is still in the file's cache
    // we can avoid flushing and needing to reread the data
    if (
#ifndef DBC_LFS_READONLY
        !(file->flags & DBC_LFS_F_WRITING)
#else
        true
#endif
            ) {
        int oindex = dbc_lfs_ctz_index(lfs, &(dbc_lfs_off_t){file->pos});
        dbc_lfs_off_t noff = npos;
        int nindex = dbc_lfs_ctz_index(lfs, &noff);
        if (oindex == nindex
                && noff >= file->cache.off
                && noff < file->cache.off + file->cache.size) {
            file->pos = npos;
            file->off = noff;
            return npos;
        }
    }

    // write out everything beforehand, may be noop if rdonly
    int err = dbc_lfs_file_flush(lfs, file);
    if (err) {
        return err;
    }

    // update pos
    file->pos = npos;
    return npos;
}

#ifndef DBC_LFS_READONLY
static int dbc_lfs_file_truncate_(dbc_lfs_t *lfs, dbc_lfs_file_t *file, dbc_lfs_off_t size) {
    DBC_LFS_ASSERT((file->flags & DBC_LFS_O_WRONLY) == DBC_LFS_O_WRONLY);

    if (size > DBC_LFS_FILE_MAX) {
        return DBC_LFS_ERR_INVAL;
    }

    dbc_lfs_off_t pos = file->pos;
    dbc_lfs_off_t oldsize = dbc_lfs_file_size_(lfs, file);
    if (size < oldsize) {
        // revert to inline file?
        if (size <= lfs->inline_max) {
            // flush+seek to head
            dbc_lfs_soff_t res = dbc_lfs_file_seek_(lfs, file, 0, DBC_LFS_SEEK_SET);
            if (res < 0) {
                return (int)res;
            }

            // read our data into rcache temporarily
            dbc_lfs_cache_drop(lfs, &lfs->rcache);
            res = dbc_lfs_file_flushedread(lfs, file,
                    lfs->rcache.buffer, size);
            if (res < 0) {
                return (int)res;
            }

            file->ctz.head = DBC_LFS_BLOCK_INLINE;
            file->ctz.size = size;
            file->flags |= DBC_LFS_F_DIRTY | DBC_LFS_F_READING | DBC_LFS_F_INLINE;
            file->cache.block = file->ctz.head;
            file->cache.off = 0;
            file->cache.size = lfs->cfg->cache_size;
            memcpy(file->cache.buffer, lfs->rcache.buffer, size);

        } else {
            // need to flush since directly changing metadata
            int err = dbc_lfs_file_flush(lfs, file);
            if (err) {
                return err;
            }

            // lookup new head in ctz skip list
            err = dbc_lfs_ctz_find(lfs, NULL, &file->cache,
                    file->ctz.head, file->ctz.size,
                    size-1, &file->block, &(dbc_lfs_off_t){0});
            if (err) {
                return err;
            }

            // need to set pos/block/off consistently so seeking back to
            // the old position does not get confused
            file->pos = size;
            file->ctz.head = file->block;
            file->ctz.size = size;
            file->flags |= DBC_LFS_F_DIRTY | DBC_LFS_F_READING;
        }
    } else if (size > oldsize) {
        // flush+seek if not already at end
        dbc_lfs_soff_t res = dbc_lfs_file_seek_(lfs, file, 0, DBC_LFS_SEEK_END);
        if (res < 0) {
            return (int)res;
        }

        // fill with zeros
        while (file->pos < size) {
            res = dbc_lfs_file_write_(lfs, file, &(uint8_t){0}, 1);
            if (res < 0) {
                return (int)res;
            }
        }
    }

    // restore pos
    dbc_lfs_soff_t res = dbc_lfs_file_seek_(lfs, file, pos, DBC_LFS_SEEK_SET);
    if (res < 0) {
      return (int)res;
    }

    return 0;
}
#endif

static dbc_lfs_soff_t dbc_lfs_file_tell_(dbc_lfs_t *lfs, dbc_lfs_file_t *file) {
    (void)lfs;
    return file->pos;
}

static int dbc_lfs_file_rewind_(dbc_lfs_t *lfs, dbc_lfs_file_t *file) {
    dbc_lfs_soff_t res = dbc_lfs_file_seek_(lfs, file, 0, DBC_LFS_SEEK_SET);
    if (res < 0) {
        return (int)res;
    }

    return 0;
}

static dbc_lfs_soff_t dbc_lfs_file_size_(dbc_lfs_t *lfs, dbc_lfs_file_t *file) {
    (void)lfs;

#ifndef DBC_LFS_READONLY
    if (file->flags & DBC_LFS_F_WRITING) {
        return dbc_lfs_max(file->pos, file->ctz.size);
    }
#endif

    return file->ctz.size;
}


/// General fs operations ///
static int dbc_lfs_stat_(dbc_lfs_t *lfs, const char *path, struct dbc_lfs_info *info) {
    dbc_lfs_mdir_t cwd;
    dbc_lfs_stag_t tag = dbc_lfs_dir_find(lfs, &cwd, &path, NULL);
    if (tag < 0) {
        return (int)tag;
    }

    return dbc_lfs_dir_getinfo(lfs, &cwd, dbc_lfs_tag_id(tag), info);
}

#ifndef DBC_LFS_READONLY
static int dbc_lfs_remove_(dbc_lfs_t *lfs, const char *path) {
    // deorphan if we haven't yet, needed at most once after poweron
    int err = dbc_lfs_fs_forceconsistency(lfs);
    if (err) {
        return err;
    }

    dbc_lfs_mdir_t cwd;
    dbc_lfs_stag_t tag = dbc_lfs_dir_find(lfs, &cwd, &path, NULL);
    if (tag < 0 || dbc_lfs_tag_id(tag) == 0x3ff) {
        return (tag < 0) ? (int)tag : DBC_LFS_ERR_INVAL;
    }

    struct dbc_lfs_mlist dir;
    dir.next = lfs->mlist;
    if (dbc_lfs_tag_type3(tag) == DBC_LFS_TYPE_DIR) {
        // must be empty before removal
        dbc_lfs_block_t pair[2];
        dbc_lfs_stag_t res = dbc_lfs_dir_get(lfs, &cwd, DBC_LFS_MKTAG(0x700, 0x3ff, 0),
                DBC_LFS_MKTAG(DBC_LFS_TYPE_STRUCT, dbc_lfs_tag_id(tag), 8), pair);
        if (res < 0) {
            return (int)res;
        }
        dbc_lfs_pair_fromle32(pair);

        err = dbc_lfs_dir_fetch(lfs, &dir.m, pair);
        if (err) {
            return err;
        }

        if (dir.m.count > 0 || dir.m.split) {
            return DBC_LFS_ERR_NOTEMPTY;
        }

        // mark fs as orphaned
        err = dbc_lfs_fs_preporphans(lfs, +1);
        if (err) {
            return err;
        }

        // I know it's crazy but yes, dir can be changed by our parent's
        // commit (if predecessor is child)
        dir.type = 0;
        dir.id = 0;
        lfs->mlist = &dir;
    }

    // delete the entry
    err = dbc_lfs_dir_commit(lfs, &cwd, DBC_LFS_MKATTRS(
            {DBC_LFS_MKTAG(DBC_LFS_TYPE_DELETE, dbc_lfs_tag_id(tag), 0), NULL}));
    if (err) {
        lfs->mlist = dir.next;
        return err;
    }

    lfs->mlist = dir.next;
    if (dbc_lfs_tag_type3(tag) == DBC_LFS_TYPE_DIR) {
        // fix orphan
        err = dbc_lfs_fs_preporphans(lfs, -1);
        if (err) {
            return err;
        }

        err = dbc_lfs_fs_pred(lfs, dir.m.pair, &cwd);
        if (err) {
            return err;
        }

        err = dbc_lfs_dir_drop(lfs, &cwd, &dir.m);
        if (err) {
            return err;
        }
    }

    return 0;
}
#endif

#ifndef DBC_LFS_READONLY
static int dbc_lfs_rename_(dbc_lfs_t *lfs, const char *oldpath, const char *newpath) {
    // deorphan if we haven't yet, needed at most once after poweron
    int err = dbc_lfs_fs_forceconsistency(lfs);
    if (err) {
        return err;
    }

    // find old entry
    dbc_lfs_mdir_t oldcwd;
    dbc_lfs_stag_t oldtag = dbc_lfs_dir_find(lfs, &oldcwd, &oldpath, NULL);
    if (oldtag < 0 || dbc_lfs_tag_id(oldtag) == 0x3ff) {
        return (oldtag < 0) ? (int)oldtag : DBC_LFS_ERR_INVAL;
    }

    // find new entry
    dbc_lfs_mdir_t newcwd;
    uint16_t newid;
    dbc_lfs_stag_t prevtag = dbc_lfs_dir_find(lfs, &newcwd, &newpath, &newid);
    if ((prevtag < 0 || dbc_lfs_tag_id(prevtag) == 0x3ff) &&
            !(prevtag == DBC_LFS_ERR_NOENT && newid != 0x3ff)) {
        return (prevtag < 0) ? (int)prevtag : DBC_LFS_ERR_INVAL;
    }

    // if we're in the same pair there's a few special cases...
    bool samepair = (dbc_lfs_pair_cmp(oldcwd.pair, newcwd.pair) == 0);
    uint16_t newoldid = dbc_lfs_tag_id(oldtag);

    struct dbc_lfs_mlist prevdir;
    prevdir.next = lfs->mlist;
    if (prevtag == DBC_LFS_ERR_NOENT) {
        // check that name fits
        dbc_lfs_size_t nlen = strlen(newpath);
        if (nlen > lfs->name_max) {
            return DBC_LFS_ERR_NAMETOOLONG;
        }

        // there is a small chance we are being renamed in the same
        // directory/ to an id less than our old id, the global update
        // to handle this is a bit messy
        if (samepair && newid <= newoldid) {
            newoldid += 1;
        }
    } else if (dbc_lfs_tag_type3(prevtag) != dbc_lfs_tag_type3(oldtag)) {
        return (dbc_lfs_tag_type3(prevtag) == DBC_LFS_TYPE_DIR)
                ? DBC_LFS_ERR_ISDIR
                : DBC_LFS_ERR_NOTDIR;
    } else if (samepair && newid == newoldid) {
        // we're renaming to ourselves??
        return 0;
    } else if (dbc_lfs_tag_type3(prevtag) == DBC_LFS_TYPE_DIR) {
        // must be empty before removal
        dbc_lfs_block_t prevpair[2];
        dbc_lfs_stag_t res = dbc_lfs_dir_get(lfs, &newcwd, DBC_LFS_MKTAG(0x700, 0x3ff, 0),
                DBC_LFS_MKTAG(DBC_LFS_TYPE_STRUCT, newid, 8), prevpair);
        if (res < 0) {
            return (int)res;
        }
        dbc_lfs_pair_fromle32(prevpair);

        // must be empty before removal
        err = dbc_lfs_dir_fetch(lfs, &prevdir.m, prevpair);
        if (err) {
            return err;
        }

        if (prevdir.m.count > 0 || prevdir.m.split) {
            return DBC_LFS_ERR_NOTEMPTY;
        }

        // mark fs as orphaned
        err = dbc_lfs_fs_preporphans(lfs, +1);
        if (err) {
            return err;
        }

        // I know it's crazy but yes, dir can be changed by our parent's
        // commit (if predecessor is child)
        prevdir.type = 0;
        prevdir.id = 0;
        lfs->mlist = &prevdir;
    }

    if (!samepair) {
        dbc_lfs_fs_prepmove(lfs, newoldid, oldcwd.pair);
    }

    // move over all attributes
    err = dbc_lfs_dir_commit(lfs, &newcwd, DBC_LFS_MKATTRS(
            {DBC_LFS_MKTAG_IF(prevtag != DBC_LFS_ERR_NOENT,
                DBC_LFS_TYPE_DELETE, newid, 0), NULL},
            {DBC_LFS_MKTAG(DBC_LFS_TYPE_CREATE, newid, 0), NULL},
            {DBC_LFS_MKTAG(dbc_lfs_tag_type3(oldtag), newid, strlen(newpath)), newpath},
            {DBC_LFS_MKTAG(DBC_LFS_FROM_MOVE, newid, dbc_lfs_tag_id(oldtag)), &oldcwd},
            {DBC_LFS_MKTAG_IF(samepair,
                DBC_LFS_TYPE_DELETE, newoldid, 0), NULL}));
    if (err) {
        lfs->mlist = prevdir.next;
        return err;
    }

    // let commit clean up after move (if we're different! otherwise move
    // logic already fixed it for us)
    if (!samepair && dbc_lfs_gstate_hasmove(&lfs->gstate)) {
        // prep gstate and delete move id
        dbc_lfs_fs_prepmove(lfs, 0x3ff, NULL);
        err = dbc_lfs_dir_commit(lfs, &oldcwd, DBC_LFS_MKATTRS(
                {DBC_LFS_MKTAG(DBC_LFS_TYPE_DELETE, dbc_lfs_tag_id(oldtag), 0), NULL}));
        if (err) {
            lfs->mlist = prevdir.next;
            return err;
        }
    }

    lfs->mlist = prevdir.next;
    if (prevtag != DBC_LFS_ERR_NOENT
            && dbc_lfs_tag_type3(prevtag) == DBC_LFS_TYPE_DIR) {
        // fix orphan
        err = dbc_lfs_fs_preporphans(lfs, -1);
        if (err) {
            return err;
        }

        err = dbc_lfs_fs_pred(lfs, prevdir.m.pair, &newcwd);
        if (err) {
            return err;
        }

        err = dbc_lfs_dir_drop(lfs, &newcwd, &prevdir.m);
        if (err) {
            return err;
        }
    }

    return 0;
}
#endif

static dbc_lfs_ssize_t dbc_lfs_getattr_(dbc_lfs_t *lfs, const char *path,
        uint8_t type, void *buffer, dbc_lfs_size_t size) {
    dbc_lfs_mdir_t cwd;
    dbc_lfs_stag_t tag = dbc_lfs_dir_find(lfs, &cwd, &path, NULL);
    if (tag < 0) {
        return tag;
    }

    uint16_t id = dbc_lfs_tag_id(tag);
    if (id == 0x3ff) {
        // special case for root
        id = 0;
        int err = dbc_lfs_dir_fetch(lfs, &cwd, lfs->root);
        if (err) {
            return err;
        }
    }

    tag = dbc_lfs_dir_get(lfs, &cwd, DBC_LFS_MKTAG(0x7ff, 0x3ff, 0),
            DBC_LFS_MKTAG(DBC_LFS_TYPE_USERATTR + type,
                id, dbc_lfs_min(size, lfs->attr_max)),
            buffer);
    if (tag < 0) {
        if (tag == DBC_LFS_ERR_NOENT) {
            return DBC_LFS_ERR_NOATTR;
        }

        return tag;
    }

    return dbc_lfs_tag_size(tag);
}

#ifndef DBC_LFS_READONLY
static int dbc_lfs_commitattr(dbc_lfs_t *lfs, const char *path,
        uint8_t type, const void *buffer, dbc_lfs_size_t size) {
    dbc_lfs_mdir_t cwd;
    dbc_lfs_stag_t tag = dbc_lfs_dir_find(lfs, &cwd, &path, NULL);
    if (tag < 0) {
        return tag;
    }

    uint16_t id = dbc_lfs_tag_id(tag);
    if (id == 0x3ff) {
        // special case for root
        id = 0;
        int err = dbc_lfs_dir_fetch(lfs, &cwd, lfs->root);
        if (err) {
            return err;
        }
    }

    return dbc_lfs_dir_commit(lfs, &cwd, DBC_LFS_MKATTRS(
            {DBC_LFS_MKTAG(DBC_LFS_TYPE_USERATTR + type, id, size), buffer}));
}
#endif

#ifndef DBC_LFS_READONLY
static int dbc_lfs_setattr_(dbc_lfs_t *lfs, const char *path,
        uint8_t type, const void *buffer, dbc_lfs_size_t size) {
    if (size > lfs->attr_max) {
        return DBC_LFS_ERR_NOSPC;
    }

    return dbc_lfs_commitattr(lfs, path, type, buffer, size);
}
#endif

#ifndef DBC_LFS_READONLY
static int dbc_lfs_removeattr_(dbc_lfs_t *lfs, const char *path, uint8_t type) {
    return dbc_lfs_commitattr(lfs, path, type, NULL, 0x3ff);
}
#endif


/// Filesystem operations ///

// compile time checks, see lfs.h for why these limits exist
#if DBC_LFS_NAME_MAX > 1022
#error "Invalid DBC_LFS_NAME_MAX, must be <= 1022"
#endif

#if DBC_LFS_FILE_MAX > 2147483647
#error "Invalid DBC_LFS_FILE_MAX, must be <= 2147483647"
#endif

#if DBC_LFS_ATTR_MAX > 1022
#error "Invalid DBC_LFS_ATTR_MAX, must be <= 1022"
#endif

// common filesystem initialization
static int dbc_lfs_init(dbc_lfs_t *lfs, const struct dbc_lfs_config *cfg) {
    lfs->cfg = cfg;
    lfs->block_count = cfg->block_count;  // May be 0
    int err = 0;

#ifdef DBC_LFS_MULTIVERSION
    // this driver only supports minor version < current minor version
    DBC_LFS_ASSERT(!lfs->cfg->disk_version || (
            (0xffff & (lfs->cfg->disk_version >> 16))
                    == DBC_LFS_DISK_VERSION_MAJOR
                && (0xffff & (lfs->cfg->disk_version >> 0))
                    <= DBC_LFS_DISK_VERSION_MINOR));
#endif

    // check that bool is a truthy-preserving type
    //
    // note the most common reason for this failure is a before-c99 compiler,
    // which littlefs currently does not support
    DBC_LFS_ASSERT((bool)0x80000000);

    // validate that the lfs-cfg sizes were initiated properly before
    // performing any arithmetic logics with them
    DBC_LFS_ASSERT(lfs->cfg->read_size != 0);
    DBC_LFS_ASSERT(lfs->cfg->prog_size != 0);
    DBC_LFS_ASSERT(lfs->cfg->cache_size != 0);

    // check that block size is a multiple of cache size is a multiple
    // of prog and read sizes
    DBC_LFS_ASSERT(lfs->cfg->cache_size % lfs->cfg->read_size == 0);
    DBC_LFS_ASSERT(lfs->cfg->cache_size % lfs->cfg->prog_size == 0);
    DBC_LFS_ASSERT(lfs->cfg->block_size % lfs->cfg->cache_size == 0);

    // check that the block size is large enough to fit all ctz pointers
    DBC_LFS_ASSERT(lfs->cfg->block_size >= 128);
    // this is the exact calculation for all ctz pointers, if this fails
    // and the simpler assert above does not, math must be broken
    DBC_LFS_ASSERT(4*dbc_lfs_npw2(0xffffffff / (lfs->cfg->block_size-2*4))
            <= lfs->cfg->block_size);

    // block_cycles = 0 is no longer supported.
    //
    // block_cycles is the number of erase cycles before littlefs evicts
    // metadata logs as a part of wear leveling. Suggested values are in the
    // range of 100-1000, or set block_cycles to -1 to disable block-level
    // wear-leveling.
    DBC_LFS_ASSERT(lfs->cfg->block_cycles != 0);

    // check that compact_thresh makes sense
    //
    // metadata can't be compacted below block_size/2, and metadata can't
    // exceed a block_size
    DBC_LFS_ASSERT(lfs->cfg->compact_thresh == 0
            || lfs->cfg->compact_thresh >= lfs->cfg->block_size/2);
    DBC_LFS_ASSERT(lfs->cfg->compact_thresh == (dbc_lfs_size_t)-1
            || lfs->cfg->compact_thresh <= lfs->cfg->block_size);

    // setup read cache
    if (lfs->cfg->read_buffer) {
        lfs->rcache.buffer = lfs->cfg->read_buffer;
    } else {
        lfs->rcache.buffer = dbc_lfs_malloc(lfs->cfg->cache_size);
        if (!lfs->rcache.buffer) {
            err = DBC_LFS_ERR_NOMEM;
            goto cleanup;
        }
    }

    // setup program cache
    if (lfs->cfg->prog_buffer) {
        lfs->pcache.buffer = lfs->cfg->prog_buffer;
    } else {
        lfs->pcache.buffer = dbc_lfs_malloc(lfs->cfg->cache_size);
        if (!lfs->pcache.buffer) {
            err = DBC_LFS_ERR_NOMEM;
            goto cleanup;
        }
    }

    // zero to avoid information leaks
    dbc_lfs_cache_zero(lfs, &lfs->rcache);
    dbc_lfs_cache_zero(lfs, &lfs->pcache);

    // setup lookahead buffer, note mount finishes initializing this after
    // we establish a decent pseudo-random seed
    DBC_LFS_ASSERT(lfs->cfg->lookahead_size > 0);
    if (lfs->cfg->lookahead_buffer) {
        lfs->lookahead.buffer = lfs->cfg->lookahead_buffer;
    } else {
        lfs->lookahead.buffer = dbc_lfs_malloc(lfs->cfg->lookahead_size);
        if (!lfs->lookahead.buffer) {
            err = DBC_LFS_ERR_NOMEM;
            goto cleanup;
        }
    }

    // check that the size limits are sane
    DBC_LFS_ASSERT(lfs->cfg->name_max <= DBC_LFS_NAME_MAX);
    lfs->name_max = lfs->cfg->name_max;
    if (!lfs->name_max) {
        lfs->name_max = DBC_LFS_NAME_MAX;
    }

    DBC_LFS_ASSERT(lfs->cfg->file_max <= DBC_LFS_FILE_MAX);
    lfs->file_max = lfs->cfg->file_max;
    if (!lfs->file_max) {
        lfs->file_max = DBC_LFS_FILE_MAX;
    }

    DBC_LFS_ASSERT(lfs->cfg->attr_max <= DBC_LFS_ATTR_MAX);
    lfs->attr_max = lfs->cfg->attr_max;
    if (!lfs->attr_max) {
        lfs->attr_max = DBC_LFS_ATTR_MAX;
    }

    DBC_LFS_ASSERT(lfs->cfg->metadata_max <= lfs->cfg->block_size);

    DBC_LFS_ASSERT(lfs->cfg->inline_max == (dbc_lfs_size_t)-1
            || lfs->cfg->inline_max <= lfs->cfg->cache_size);
    DBC_LFS_ASSERT(lfs->cfg->inline_max == (dbc_lfs_size_t)-1
            || lfs->cfg->inline_max <= lfs->attr_max);
    DBC_LFS_ASSERT(lfs->cfg->inline_max == (dbc_lfs_size_t)-1
            || lfs->cfg->inline_max <= ((lfs->cfg->metadata_max)
                ? lfs->cfg->metadata_max
                : lfs->cfg->block_size)/8);
    lfs->inline_max = lfs->cfg->inline_max;
    if (lfs->inline_max == (dbc_lfs_size_t)-1) {
        lfs->inline_max = 0;
    } else if (lfs->inline_max == 0) {
        lfs->inline_max = dbc_lfs_min(
                lfs->cfg->cache_size,
                dbc_lfs_min(
                    lfs->attr_max,
                    ((lfs->cfg->metadata_max)
                        ? lfs->cfg->metadata_max
                        : lfs->cfg->block_size)/8));
    }

    // setup default state
    lfs->root[0] = DBC_LFS_BLOCK_NULL;
    lfs->root[1] = DBC_LFS_BLOCK_NULL;
    lfs->mlist = NULL;
    lfs->seed = 0;
    lfs->gdisk = (dbc_lfs_gstate_t){0};
    lfs->gstate = (dbc_lfs_gstate_t){0};
    lfs->gdelta = (dbc_lfs_gstate_t){0};
#ifdef DBC_LFS_MIGRATE
    lfs->lfs1 = NULL;
#endif

    return 0;

cleanup:
    dbc_lfs_deinit(lfs);
    return err;
}

static int dbc_lfs_deinit(dbc_lfs_t *lfs) {
    // free allocated memory
    if (!lfs->cfg->read_buffer) {
        dbc_lfs_free(lfs->rcache.buffer);
    }

    if (!lfs->cfg->prog_buffer) {
        dbc_lfs_free(lfs->pcache.buffer);
    }

    if (!lfs->cfg->lookahead_buffer) {
        dbc_lfs_free(lfs->lookahead.buffer);
    }

    return 0;
}



#ifndef DBC_LFS_READONLY
static int dbc_lfs_format_(dbc_lfs_t *lfs, const struct dbc_lfs_config *cfg) {
    int err = 0;
    {
        err = dbc_lfs_init(lfs, cfg);
        if (err) {
            return err;
        }

        DBC_LFS_ASSERT(cfg->block_count != 0);

        // create free lookahead
        memset(lfs->lookahead.buffer, 0, lfs->cfg->lookahead_size);
        lfs->lookahead.start = 0;
        lfs->lookahead.size = dbc_lfs_min(8*lfs->cfg->lookahead_size,
                lfs->block_count);
        lfs->lookahead.next = 0;
        dbc_lfs_alloc_ckpoint(lfs);

        // create root dir
        dbc_lfs_mdir_t root;
        err = dbc_lfs_dir_alloc(lfs, &root);
        if (err) {
            goto cleanup;
        }

        // write one superblock
        dbc_lfs_superblock_t superblock = {
            .version     = dbc_lfs_fs_disk_version(lfs),
            .block_size  = lfs->cfg->block_size,
            .block_count = lfs->block_count,
            .name_max    = lfs->name_max,
            .file_max    = lfs->file_max,
            .attr_max    = lfs->attr_max,
        };

        dbc_lfs_superblock_tole32(&superblock);
        err = dbc_lfs_dir_commit(lfs, &root, DBC_LFS_MKATTRS(
                {DBC_LFS_MKTAG(DBC_LFS_TYPE_CREATE, 0, 0), NULL},
                {DBC_LFS_MKTAG(DBC_LFS_TYPE_SUPERBLOCK, 0, 8), "littlefs"},
                {DBC_LFS_MKTAG(DBC_LFS_TYPE_INLINESTRUCT, 0, sizeof(superblock)),
                    &superblock}));
        if (err) {
            goto cleanup;
        }

        // force compaction to prevent accidentally mounting any
        // older version of littlefs that may live on disk
        root.erased = false;
        err = dbc_lfs_dir_commit(lfs, &root, NULL, 0);
        if (err) {
            goto cleanup;
        }

        // sanity check that fetch works
        err = dbc_lfs_dir_fetch(lfs, &root, (const dbc_lfs_block_t[2]){0, 1});
        if (err) {
            goto cleanup;
        }
    }

cleanup:
    dbc_lfs_deinit(lfs);
    return err;

}
#endif

static int dbc_lfs_mount_(dbc_lfs_t *lfs, const struct dbc_lfs_config *cfg) {
    int err = dbc_lfs_init(lfs, cfg);
    if (err) {
        return err;
    }

    // scan directory blocks for superblock and any global updates
    dbc_lfs_mdir_t dir = {.tail = {0, 1}};
    dbc_lfs_block_t tortoise[2] = {DBC_LFS_BLOCK_NULL, DBC_LFS_BLOCK_NULL};
    dbc_lfs_size_t tortoise_i = 1;
    dbc_lfs_size_t tortoise_period = 1;
    while (!dbc_lfs_pair_isnull(dir.tail)) {
        // detect cycles with Brent's algorithm
        if (dbc_lfs_pair_issync(dir.tail, tortoise)) {
            DBC_LFS_WARN("Cycle detected in tail list");
            err = DBC_LFS_ERR_CORRUPT;
            goto cleanup;
        }
        if (tortoise_i == tortoise_period) {
            tortoise[0] = dir.tail[0];
            tortoise[1] = dir.tail[1];
            tortoise_i = 0;
            tortoise_period *= 2;
        }
        tortoise_i += 1;

        // fetch next block in tail list
        dbc_lfs_stag_t tag = dbc_lfs_dir_fetchmatch(lfs, &dir, dir.tail,
                DBC_LFS_MKTAG(0x7ff, 0x3ff, 0),
                DBC_LFS_MKTAG(DBC_LFS_TYPE_SUPERBLOCK, 0, 8),
                NULL,
                dbc_lfs_dir_find_match, &(struct dbc_lfs_dir_find_match){
                    lfs, "littlefs", 8});
        if (tag < 0) {
            err = tag;
            goto cleanup;
        }

        // has superblock?
        if (tag && !dbc_lfs_tag_isdelete(tag)) {
            // update root
            lfs->root[0] = dir.pair[0];
            lfs->root[1] = dir.pair[1];

            // grab superblock
            dbc_lfs_superblock_t superblock;
            tag = dbc_lfs_dir_get(lfs, &dir, DBC_LFS_MKTAG(0x7ff, 0x3ff, 0),
                    DBC_LFS_MKTAG(DBC_LFS_TYPE_INLINESTRUCT, 0, sizeof(superblock)),
                    &superblock);
            if (tag < 0) {
                err = tag;
                goto cleanup;
            }
            dbc_lfs_superblock_fromle32(&superblock);

            // check version
            uint16_t major_version = (0xffff & (superblock.version >> 16));
            uint16_t minor_version = (0xffff & (superblock.version >>  0));
            if (major_version != dbc_lfs_fs_disk_version_major(lfs)
                    || minor_version > dbc_lfs_fs_disk_version_minor(lfs)) {
                DBC_LFS_ERROR("Invalid version "
                        "v%"PRIu16".%"PRIu16" != v%"PRIu16".%"PRIu16,
                        major_version,
                        minor_version,
                        dbc_lfs_fs_disk_version_major(lfs),
                        dbc_lfs_fs_disk_version_minor(lfs));
                err = DBC_LFS_ERR_INVAL;
                goto cleanup;
            }

            // found older minor version? set an in-device only bit in the
            // gstate so we know we need to rewrite the superblock before
            // the first write
            if (minor_version < dbc_lfs_fs_disk_version_minor(lfs)) {
                DBC_LFS_DEBUG("Found older minor version "
                        "v%"PRIu16".%"PRIu16" < v%"PRIu16".%"PRIu16,
                        major_version,
                        minor_version,
                        dbc_lfs_fs_disk_version_major(lfs),
                        dbc_lfs_fs_disk_version_minor(lfs));
                // note this bit is reserved on disk, so fetching more gstate
                // will not interfere here
                dbc_lfs_fs_prepsuperblock(lfs, true);
            }

            // check superblock configuration
            if (superblock.name_max) {
                if (superblock.name_max > lfs->name_max) {
                    DBC_LFS_ERROR("Unsupported name_max (%"PRIu32" > %"PRIu32")",
                            superblock.name_max, lfs->name_max);
                    err = DBC_LFS_ERR_INVAL;
                    goto cleanup;
                }

                lfs->name_max = superblock.name_max;
            }

            if (superblock.file_max) {
                if (superblock.file_max > lfs->file_max) {
                    DBC_LFS_ERROR("Unsupported file_max (%"PRIu32" > %"PRIu32")",
                            superblock.file_max, lfs->file_max);
                    err = DBC_LFS_ERR_INVAL;
                    goto cleanup;
                }

                lfs->file_max = superblock.file_max;
            }

            if (superblock.attr_max) {
                if (superblock.attr_max > lfs->attr_max) {
                    DBC_LFS_ERROR("Unsupported attr_max (%"PRIu32" > %"PRIu32")",
                            superblock.attr_max, lfs->attr_max);
                    err = DBC_LFS_ERR_INVAL;
                    goto cleanup;
                }

                lfs->attr_max = superblock.attr_max;

                // we also need to update inline_max in case attr_max changed
                lfs->inline_max = dbc_lfs_min(lfs->inline_max, lfs->attr_max);
            }

            // this is where we get the block_count from disk if block_count=0
            if (lfs->cfg->block_count
                    && superblock.block_count != lfs->cfg->block_count) {
                DBC_LFS_ERROR("Invalid block count (%"PRIu32" != %"PRIu32")",
                        superblock.block_count, lfs->cfg->block_count);
                err = DBC_LFS_ERR_INVAL;
                goto cleanup;
            }

            lfs->block_count = superblock.block_count;

            if (superblock.block_size != lfs->cfg->block_size) {
                DBC_LFS_ERROR("Invalid block size (%"PRIu32" != %"PRIu32")",
                        superblock.block_size, lfs->cfg->block_size);
                err = DBC_LFS_ERR_INVAL;
                goto cleanup;
            }
        }

        // has gstate?
        err = dbc_lfs_dir_getgstate(lfs, &dir, &lfs->gstate);
        if (err) {
            goto cleanup;
        }
    }

    // update littlefs with gstate
    if (!dbc_lfs_gstate_iszero(&lfs->gstate)) {
        DBC_LFS_DEBUG("Found pending gstate 0x%08"PRIx32"%08"PRIx32"%08"PRIx32,
                lfs->gstate.tag,
                lfs->gstate.pair[0],
                lfs->gstate.pair[1]);
    }
    lfs->gstate.tag += !dbc_lfs_tag_isvalid(lfs->gstate.tag);
    lfs->gdisk = lfs->gstate;

    // setup free lookahead, to distribute allocations uniformly across
    // boots, we start the allocator at a random location
    lfs->lookahead.start = lfs->seed % lfs->block_count;
    dbc_lfs_alloc_drop(lfs);

    return 0;

cleanup:
    dbc_lfs_unmount_(lfs);
    return err;
}

static int dbc_lfs_unmount_(dbc_lfs_t *lfs) {
    return dbc_lfs_deinit(lfs);
}


/// Filesystem filesystem operations ///
static int dbc_lfs_fs_stat_(dbc_lfs_t *lfs, struct dbc_lfs_fsinfo *fsinfo) {
    // if the superblock is up-to-date, we must be on the most recent
    // minor version of littlefs
    if (!dbc_lfs_gstate_needssuperblock(&lfs->gstate)) {
        fsinfo->disk_version = dbc_lfs_fs_disk_version(lfs);

    // otherwise we need to read the minor version on disk
    } else {
        // fetch the superblock
        dbc_lfs_mdir_t dir;
        int err = dbc_lfs_dir_fetch(lfs, &dir, lfs->root);
        if (err) {
            return err;
        }

        dbc_lfs_superblock_t superblock;
        dbc_lfs_stag_t tag = dbc_lfs_dir_get(lfs, &dir, DBC_LFS_MKTAG(0x7ff, 0x3ff, 0),
                DBC_LFS_MKTAG(DBC_LFS_TYPE_INLINESTRUCT, 0, sizeof(superblock)),
                &superblock);
        if (tag < 0) {
            return tag;
        }
        dbc_lfs_superblock_fromle32(&superblock);

        // read the on-disk version
        fsinfo->disk_version = superblock.version;
    }

    // filesystem geometry
    fsinfo->block_size = lfs->cfg->block_size;
    fsinfo->block_count = lfs->block_count;

    // other on-disk configuration, we cache all of these for internal use
    fsinfo->name_max = lfs->name_max;
    fsinfo->file_max = lfs->file_max;
    fsinfo->attr_max = lfs->attr_max;

    return 0;
}

int dbc_lfs_fs_traverse_(dbc_lfs_t *lfs,
        int (*cb)(void *data, dbc_lfs_block_t block), void *data,
        bool includeorphans) {
    // iterate over metadata pairs
    dbc_lfs_mdir_t dir = {.tail = {0, 1}};

#ifdef DBC_LFS_MIGRATE
    // also consider v1 blocks during migration
    if (lfs->lfs1) {
        int err = lfs1_traverse(lfs, cb, data);
        if (err) {
            return err;
        }

        dir.tail[0] = lfs->root[0];
        dir.tail[1] = lfs->root[1];
    }
#endif

    dbc_lfs_block_t tortoise[2] = {DBC_LFS_BLOCK_NULL, DBC_LFS_BLOCK_NULL};
    dbc_lfs_size_t tortoise_i = 1;
    dbc_lfs_size_t tortoise_period = 1;
    while (!dbc_lfs_pair_isnull(dir.tail)) {
        // detect cycles with Brent's algorithm
        if (dbc_lfs_pair_issync(dir.tail, tortoise)) {
            DBC_LFS_WARN("Cycle detected in tail list");
            return DBC_LFS_ERR_CORRUPT;
        }
        if (tortoise_i == tortoise_period) {
            tortoise[0] = dir.tail[0];
            tortoise[1] = dir.tail[1];
            tortoise_i = 0;
            tortoise_period *= 2;
        }
        tortoise_i += 1;

        for (int i = 0; i < 2; i++) {
            int err = cb(data, dir.tail[i]);
            if (err) {
                return err;
            }
        }

        // iterate through ids in directory
        int err = dbc_lfs_dir_fetch(lfs, &dir, dir.tail);
        if (err) {
            return err;
        }

        for (uint16_t id = 0; id < dir.count; id++) {
            struct dbc_lfs_ctz ctz;
            dbc_lfs_stag_t tag = dbc_lfs_dir_get(lfs, &dir, DBC_LFS_MKTAG(0x700, 0x3ff, 0),
                    DBC_LFS_MKTAG(DBC_LFS_TYPE_STRUCT, id, sizeof(ctz)), &ctz);
            if (tag < 0) {
                if (tag == DBC_LFS_ERR_NOENT) {
                    continue;
                }
                return tag;
            }
            dbc_lfs_ctz_fromle32(&ctz);

            if (dbc_lfs_tag_type3(tag) == DBC_LFS_TYPE_CTZSTRUCT) {
                err = dbc_lfs_ctz_traverse(lfs, NULL, &lfs->rcache,
                        ctz.head, ctz.size, cb, data);
                if (err) {
                    return err;
                }
            } else if (includeorphans &&
                    dbc_lfs_tag_type3(tag) == DBC_LFS_TYPE_DIRSTRUCT) {
                for (int i = 0; i < 2; i++) {
                    err = cb(data, (&ctz.head)[i]);
                    if (err) {
                        return err;
                    }
                }
            }
        }
    }

#ifndef DBC_LFS_READONLY
    // iterate over any open files
    for (dbc_lfs_file_t *f = (dbc_lfs_file_t*)lfs->mlist; f; f = f->next) {
        if (f->type != DBC_LFS_TYPE_REG) {
            continue;
        }

        if ((f->flags & DBC_LFS_F_DIRTY) && !(f->flags & DBC_LFS_F_INLINE)) {
            int err = dbc_lfs_ctz_traverse(lfs, &f->cache, &lfs->rcache,
                    f->ctz.head, f->ctz.size, cb, data);
            if (err) {
                return err;
            }
        }

        if ((f->flags & DBC_LFS_F_WRITING) && !(f->flags & DBC_LFS_F_INLINE)) {
            int err = dbc_lfs_ctz_traverse(lfs, &f->cache, &lfs->rcache,
                    f->block, f->pos, cb, data);
            if (err) {
                return err;
            }
        }
    }
#endif

    return 0;
}

#ifndef DBC_LFS_READONLY
static int dbc_lfs_fs_pred(dbc_lfs_t *lfs,
        const dbc_lfs_block_t pair[2], dbc_lfs_mdir_t *pdir) {
    // iterate over all directory directory entries
    pdir->tail[0] = 0;
    pdir->tail[1] = 1;
    dbc_lfs_block_t tortoise[2] = {DBC_LFS_BLOCK_NULL, DBC_LFS_BLOCK_NULL};
    dbc_lfs_size_t tortoise_i = 1;
    dbc_lfs_size_t tortoise_period = 1;
    while (!dbc_lfs_pair_isnull(pdir->tail)) {
        // detect cycles with Brent's algorithm
        if (dbc_lfs_pair_issync(pdir->tail, tortoise)) {
            DBC_LFS_WARN("Cycle detected in tail list");
            return DBC_LFS_ERR_CORRUPT;
        }
        if (tortoise_i == tortoise_period) {
            tortoise[0] = pdir->tail[0];
            tortoise[1] = pdir->tail[1];
            tortoise_i = 0;
            tortoise_period *= 2;
        }
        tortoise_i += 1;

        if (dbc_lfs_pair_cmp(pdir->tail, pair) == 0) {
            return 0;
        }

        int err = dbc_lfs_dir_fetch(lfs, pdir, pdir->tail);
        if (err) {
            return err;
        }
    }

    return DBC_LFS_ERR_NOENT;
}
#endif

#ifndef DBC_LFS_READONLY
struct dbc_lfs_fs_parent_match {
    dbc_lfs_t *lfs;
    const dbc_lfs_block_t pair[2];
};
#endif

#ifndef DBC_LFS_READONLY
static int dbc_lfs_fs_parent_match(void *data,
        dbc_lfs_tag_t tag, const void *buffer) {
    struct dbc_lfs_fs_parent_match *find = data;
    dbc_lfs_t *lfs = find->lfs;
    const struct dbc_lfs_diskoff *disk = buffer;
    (void)tag;

    dbc_lfs_block_t child[2];
    int err = dbc_lfs_bd_read(lfs,
            &lfs->pcache, &lfs->rcache, lfs->cfg->block_size,
            disk->block, disk->off, &child, sizeof(child));
    if (err) {
        return err;
    }

    dbc_lfs_pair_fromle32(child);
    return (dbc_lfs_pair_cmp(child, find->pair) == 0) ? DBC_LFS_CMP_EQ : DBC_LFS_CMP_LT;
}
#endif

#ifndef DBC_LFS_READONLY
static dbc_lfs_stag_t dbc_lfs_fs_parent(dbc_lfs_t *lfs, const dbc_lfs_block_t pair[2],
        dbc_lfs_mdir_t *parent) {
    // use fetchmatch with callback to find pairs
    parent->tail[0] = 0;
    parent->tail[1] = 1;
    dbc_lfs_block_t tortoise[2] = {DBC_LFS_BLOCK_NULL, DBC_LFS_BLOCK_NULL};
    dbc_lfs_size_t tortoise_i = 1;
    dbc_lfs_size_t tortoise_period = 1;
    while (!dbc_lfs_pair_isnull(parent->tail)) {
        // detect cycles with Brent's algorithm
        if (dbc_lfs_pair_issync(parent->tail, tortoise)) {
            DBC_LFS_WARN("Cycle detected in tail list");
            return DBC_LFS_ERR_CORRUPT;
        }
        if (tortoise_i == tortoise_period) {
            tortoise[0] = parent->tail[0];
            tortoise[1] = parent->tail[1];
            tortoise_i = 0;
            tortoise_period *= 2;
        }
        tortoise_i += 1;

        dbc_lfs_stag_t tag = dbc_lfs_dir_fetchmatch(lfs, parent, parent->tail,
                DBC_LFS_MKTAG(0x7ff, 0, 0x3ff),
                DBC_LFS_MKTAG(DBC_LFS_TYPE_DIRSTRUCT, 0, 8),
                NULL,
                dbc_lfs_fs_parent_match, &(struct dbc_lfs_fs_parent_match){
                    lfs, {pair[0], pair[1]}});
        if (tag && tag != DBC_LFS_ERR_NOENT) {
            return tag;
        }
    }

    return DBC_LFS_ERR_NOENT;
}
#endif

static void dbc_lfs_fs_prepsuperblock(dbc_lfs_t *lfs, bool needssuperblock) {
    lfs->gstate.tag = (lfs->gstate.tag & ~DBC_LFS_MKTAG(0, 0, 0x200))
            | (uint32_t)needssuperblock << 9;
}

#ifndef DBC_LFS_READONLY
static int dbc_lfs_fs_preporphans(dbc_lfs_t *lfs, int8_t orphans) {
    DBC_LFS_ASSERT(dbc_lfs_tag_size(lfs->gstate.tag) > 0x000 || orphans >= 0);
    DBC_LFS_ASSERT(dbc_lfs_tag_size(lfs->gstate.tag) < 0x1ff || orphans <= 0);
    lfs->gstate.tag += orphans;
    lfs->gstate.tag = ((lfs->gstate.tag & ~DBC_LFS_MKTAG(0x800, 0, 0)) |
            ((uint32_t)dbc_lfs_gstate_hasorphans(&lfs->gstate) << 31));

    return 0;
}
#endif

#ifndef DBC_LFS_READONLY
static void dbc_lfs_fs_prepmove(dbc_lfs_t *lfs,
        uint16_t id, const dbc_lfs_block_t pair[2]) {
    lfs->gstate.tag = ((lfs->gstate.tag & ~DBC_LFS_MKTAG(0x7ff, 0x3ff, 0)) |
            ((id != 0x3ff) ? DBC_LFS_MKTAG(DBC_LFS_TYPE_DELETE, id, 0) : 0));
    lfs->gstate.pair[0] = (id != 0x3ff) ? pair[0] : 0;
    lfs->gstate.pair[1] = (id != 0x3ff) ? pair[1] : 0;
}
#endif

#ifndef DBC_LFS_READONLY
static int dbc_lfs_fs_desuperblock(dbc_lfs_t *lfs) {
    if (!dbc_lfs_gstate_needssuperblock(&lfs->gstate)) {
        return 0;
    }

    DBC_LFS_DEBUG("Rewriting superblock {0x%"PRIx32", 0x%"PRIx32"}",
            lfs->root[0],
            lfs->root[1]);

    dbc_lfs_mdir_t root;
    int err = dbc_lfs_dir_fetch(lfs, &root, lfs->root);
    if (err) {
        return err;
    }

    // write a new superblock
    dbc_lfs_superblock_t superblock = {
        .version     = dbc_lfs_fs_disk_version(lfs),
        .block_size  = lfs->cfg->block_size,
        .block_count = lfs->block_count,
        .name_max    = lfs->name_max,
        .file_max    = lfs->file_max,
        .attr_max    = lfs->attr_max,
    };

    dbc_lfs_superblock_tole32(&superblock);
    err = dbc_lfs_dir_commit(lfs, &root, DBC_LFS_MKATTRS(
            {DBC_LFS_MKTAG(DBC_LFS_TYPE_INLINESTRUCT, 0, sizeof(superblock)),
                &superblock}));
    if (err) {
        return err;
    }

    dbc_lfs_fs_prepsuperblock(lfs, false);
    return 0;
}
#endif

#ifndef DBC_LFS_READONLY
static int dbc_lfs_fs_demove(dbc_lfs_t *lfs) {
    if (!dbc_lfs_gstate_hasmove(&lfs->gdisk)) {
        return 0;
    }

    // Fix bad moves
    DBC_LFS_DEBUG("Fixing move {0x%"PRIx32", 0x%"PRIx32"} 0x%"PRIx16,
            lfs->gdisk.pair[0],
            lfs->gdisk.pair[1],
            dbc_lfs_tag_id(lfs->gdisk.tag));

    // no other gstate is supported at this time, so if we found something else
    // something most likely went wrong in gstate calculation
    DBC_LFS_ASSERT(dbc_lfs_tag_type3(lfs->gdisk.tag) == DBC_LFS_TYPE_DELETE);

    // fetch and delete the moved entry
    dbc_lfs_mdir_t movedir;
    int err = dbc_lfs_dir_fetch(lfs, &movedir, lfs->gdisk.pair);
    if (err) {
        return err;
    }

    // prep gstate and delete move id
    uint16_t moveid = dbc_lfs_tag_id(lfs->gdisk.tag);
    dbc_lfs_fs_prepmove(lfs, 0x3ff, NULL);
    err = dbc_lfs_dir_commit(lfs, &movedir, DBC_LFS_MKATTRS(
            {DBC_LFS_MKTAG(DBC_LFS_TYPE_DELETE, moveid, 0), NULL}));
    if (err) {
        return err;
    }

    return 0;
}
#endif

#ifndef DBC_LFS_READONLY
static int dbc_lfs_fs_deorphan(dbc_lfs_t *lfs, bool powerloss) {
    if (!dbc_lfs_gstate_hasorphans(&lfs->gstate)) {
        return 0;
    }

    // Check for orphans in two separate passes:
    // - 1 for half-orphans (relocations)
    // - 2 for full-orphans (removes/renames)
    //
    // Two separate passes are needed as half-orphans can contain outdated
    // references to full-orphans, effectively hiding them from the deorphan
    // search.
    //
    int pass = 0;
    while (pass < 2) {
        // Fix any orphans
        dbc_lfs_mdir_t pdir = {.split = true, .tail = {0, 1}};
        dbc_lfs_mdir_t dir;
        bool moreorphans = false;

        // iterate over all directory directory entries
        while (!dbc_lfs_pair_isnull(pdir.tail)) {
            int err = dbc_lfs_dir_fetch(lfs, &dir, pdir.tail);
            if (err) {
                return err;
            }

            // check head blocks for orphans
            if (!pdir.split) {
                // check if we have a parent
                dbc_lfs_mdir_t parent;
                dbc_lfs_stag_t tag = dbc_lfs_fs_parent(lfs, pdir.tail, &parent);
                if (tag < 0 && tag != DBC_LFS_ERR_NOENT) {
                    return tag;
                }

                if (pass == 0 && tag != DBC_LFS_ERR_NOENT) {
                    dbc_lfs_block_t pair[2];
                    dbc_lfs_stag_t state = dbc_lfs_dir_get(lfs, &parent,
                            DBC_LFS_MKTAG(0x7ff, 0x3ff, 0), tag, pair);
                    if (state < 0) {
                        return state;
                    }
                    dbc_lfs_pair_fromle32(pair);

                    if (!dbc_lfs_pair_issync(pair, pdir.tail)) {
                        // we have desynced
                        DBC_LFS_DEBUG("Fixing half-orphan "
                                "{0x%"PRIx32", 0x%"PRIx32"} "
                                "-> {0x%"PRIx32", 0x%"PRIx32"}",
                                pdir.tail[0], pdir.tail[1], pair[0], pair[1]);

                        // fix pending move in this pair? this looks like an
                        // optimization but is in fact _required_ since
                        // relocating may outdate the move.
                        uint16_t moveid = 0x3ff;
                        if (dbc_lfs_gstate_hasmovehere(&lfs->gstate, pdir.pair)) {
                            moveid = dbc_lfs_tag_id(lfs->gstate.tag);
                            DBC_LFS_DEBUG("Fixing move while fixing orphans "
                                    "{0x%"PRIx32", 0x%"PRIx32"} 0x%"PRIx16"\n",
                                    pdir.pair[0], pdir.pair[1], moveid);
                            dbc_lfs_fs_prepmove(lfs, 0x3ff, NULL);
                        }

                        dbc_lfs_pair_tole32(pair);
                        state = dbc_lfs_dir_orphaningcommit(lfs, &pdir, DBC_LFS_MKATTRS(
                                {DBC_LFS_MKTAG_IF(moveid != 0x3ff,
                                    DBC_LFS_TYPE_DELETE, moveid, 0), NULL},
                                {DBC_LFS_MKTAG(DBC_LFS_TYPE_SOFTTAIL, 0x3ff, 8),
                                    pair}));
                        dbc_lfs_pair_fromle32(pair);
                        if (state < 0) {
                            return state;
                        }

                        // did our commit create more orphans?
                        if (state == DBC_LFS_OK_ORPHANED) {
                            moreorphans = true;
                        }

                        // refetch tail
                        continue;
                    }
                }

                // note we only check for full orphans if we may have had a
                // power-loss, otherwise orphans are created intentionally
                // during operations such as dbc_lfs_mkdir
                if (pass == 1 && tag == DBC_LFS_ERR_NOENT && powerloss) {
                    // we are an orphan
                    DBC_LFS_DEBUG("Fixing orphan {0x%"PRIx32", 0x%"PRIx32"}",
                            pdir.tail[0], pdir.tail[1]);

                    // steal state
                    err = dbc_lfs_dir_getgstate(lfs, &dir, &lfs->gdelta);
                    if (err) {
                        return err;
                    }

                    // steal tail
                    dbc_lfs_pair_tole32(dir.tail);
                    int state = dbc_lfs_dir_orphaningcommit(lfs, &pdir, DBC_LFS_MKATTRS(
                            {DBC_LFS_MKTAG(DBC_LFS_TYPE_TAIL + dir.split, 0x3ff, 8),
                                dir.tail}));
                    dbc_lfs_pair_fromle32(dir.tail);
                    if (state < 0) {
                        return state;
                    }

                    // did our commit create more orphans?
                    if (state == DBC_LFS_OK_ORPHANED) {
                        moreorphans = true;
                    }

                    // refetch tail
                    continue;
                }
            }

            pdir = dir;
        }

        pass = moreorphans ? 0 : pass+1;
    }

    // mark orphans as fixed
    return dbc_lfs_fs_preporphans(lfs, -dbc_lfs_gstate_getorphans(&lfs->gstate));
}
#endif

#ifndef DBC_LFS_READONLY
static int dbc_lfs_fs_forceconsistency(dbc_lfs_t *lfs) {
    int err = dbc_lfs_fs_desuperblock(lfs);
    if (err) {
        return err;
    }

    err = dbc_lfs_fs_demove(lfs);
    if (err) {
        return err;
    }

    err = dbc_lfs_fs_deorphan(lfs, true);
    if (err) {
        return err;
    }

    return 0;
}
#endif

#ifndef DBC_LFS_READONLY
static int dbc_lfs_fs_mkconsistent_(dbc_lfs_t *lfs) {
    // dbc_lfs_fs_forceconsistency does most of the work here
    int err = dbc_lfs_fs_forceconsistency(lfs);
    if (err) {
        return err;
    }

    // do we have any pending gstate?
    dbc_lfs_gstate_t delta = {0};
    dbc_lfs_gstate_xor(&delta, &lfs->gdisk);
    dbc_lfs_gstate_xor(&delta, &lfs->gstate);
    if (!dbc_lfs_gstate_iszero(&delta)) {
        // dbc_lfs_dir_commit will implicitly write out any pending gstate
        dbc_lfs_mdir_t root;
        err = dbc_lfs_dir_fetch(lfs, &root, lfs->root);
        if (err) {
            return err;
        }

        err = dbc_lfs_dir_commit(lfs, &root, NULL, 0);
        if (err) {
            return err;
        }
    }

    return 0;
}
#endif

static int dbc_lfs_fs_size_count(void *p, dbc_lfs_block_t block) {
    (void)block;
    dbc_lfs_size_t *size = p;
    *size += 1;
    return 0;
}

static dbc_lfs_ssize_t dbc_lfs_fs_size_(dbc_lfs_t *lfs) {
    dbc_lfs_size_t size = 0;
    int err = dbc_lfs_fs_traverse_(lfs, dbc_lfs_fs_size_count, &size, false);
    if (err) {
        return err;
    }

    return size;
}

// explicit garbage collection
#ifndef DBC_LFS_READONLY
static int dbc_lfs_fs_gc_(dbc_lfs_t *lfs) {
    // force consistency, even if we're not necessarily going to write,
    // because this function is supposed to take care of janitorial work
    // isn't it?
    int err = dbc_lfs_fs_forceconsistency(lfs);
    if (err) {
        return err;
    }

    // try to compact metadata pairs, note we can't really accomplish
    // anything if compact_thresh doesn't at least leave a prog_size
    // available
    if (lfs->cfg->compact_thresh
            < lfs->cfg->block_size - lfs->cfg->prog_size) {
        // iterate over all mdirs
        dbc_lfs_mdir_t mdir = {.tail = {0, 1}};
        while (!dbc_lfs_pair_isnull(mdir.tail)) {
            err = dbc_lfs_dir_fetch(lfs, &mdir, mdir.tail);
            if (err) {
                return err;
            }

            // not erased? exceeds our compaction threshold?
            if (!mdir.erased || ((lfs->cfg->compact_thresh == 0)
                    ? mdir.off > lfs->cfg->block_size - lfs->cfg->block_size/8
                    : mdir.off > lfs->cfg->compact_thresh)) {
                // the easiest way to trigger a compaction is to mark
                // the mdir as unerased and add an empty commit
                mdir.erased = false;
                err = dbc_lfs_dir_commit(lfs, &mdir, NULL, 0);
                if (err) {
                    return err;
                }
            }
        }
    }

    // try to populate the lookahead buffer, unless it's already full
    if (lfs->lookahead.size < 8*lfs->cfg->lookahead_size) {
        err = dbc_lfs_alloc_scan(lfs);
        if (err) {
            return err;
        }
    }

    return 0;
}
#endif

#ifndef DBC_LFS_READONLY
static int dbc_lfs_fs_grow_(dbc_lfs_t *lfs, dbc_lfs_size_t block_count) {
    // shrinking is not supported
    DBC_LFS_ASSERT(block_count >= lfs->block_count);

    if (block_count > lfs->block_count) {
        lfs->block_count = block_count;

        // fetch the root
        dbc_lfs_mdir_t root;
        int err = dbc_lfs_dir_fetch(lfs, &root, lfs->root);
        if (err) {
            return err;
        }

        // update the superblock
        dbc_lfs_superblock_t superblock;
        dbc_lfs_stag_t tag = dbc_lfs_dir_get(lfs, &root, DBC_LFS_MKTAG(0x7ff, 0x3ff, 0),
                DBC_LFS_MKTAG(DBC_LFS_TYPE_INLINESTRUCT, 0, sizeof(superblock)),
                &superblock);
        if (tag < 0) {
            return tag;
        }
        dbc_lfs_superblock_fromle32(&superblock);

        superblock.block_count = lfs->block_count;

        dbc_lfs_superblock_tole32(&superblock);
        err = dbc_lfs_dir_commit(lfs, &root, DBC_LFS_MKATTRS(
                {tag, &superblock}));
        if (err) {
            return err;
        }
    }

    return 0;
}
#endif

#ifdef DBC_LFS_MIGRATE
////// Migration from littelfs v1 below this //////

/// Version info ///

// Software library version
// Major (top-nibble), incremented on backwards incompatible changes
// Minor (bottom-nibble), incremented on feature additions
#define LFS1_VERSION 0x00010007
#define LFS1_VERSION_MAJOR (0xffff & (LFS1_VERSION >> 16))
#define LFS1_VERSION_MINOR (0xffff & (LFS1_VERSION >>  0))

// Version of On-disk data structures
// Major (top-nibble), incremented on backwards incompatible changes
// Minor (bottom-nibble), incremented on feature additions
#define LFS1_DISK_VERSION 0x00010001
#define LFS1_DISK_VERSION_MAJOR (0xffff & (LFS1_DISK_VERSION >> 16))
#define LFS1_DISK_VERSION_MINOR (0xffff & (LFS1_DISK_VERSION >>  0))


/// v1 Definitions ///

// File types
enum lfs1_type {
    LFS1_TYPE_REG        = 0x11,
    LFS1_TYPE_DIR        = 0x22,
    LFS1_TYPE_SUPERBLOCK = 0x2e,
};

typedef struct lfs1 {
    dbc_lfs_block_t root[2];
} lfs1_t;

typedef struct lfs1_entry {
    dbc_lfs_off_t off;

    struct lfs1_disk_entry {
        uint8_t type;
        uint8_t elen;
        uint8_t alen;
        uint8_t nlen;
        union {
            struct {
                dbc_lfs_block_t head;
                dbc_lfs_size_t size;
            } file;
            dbc_lfs_block_t dir[2];
        } u;
    } d;
} lfs1_entry_t;

typedef struct lfs1_dir {
    struct lfs1_dir *next;
    dbc_lfs_block_t pair[2];
    dbc_lfs_off_t off;

    dbc_lfs_block_t head[2];
    dbc_lfs_off_t pos;

    struct lfs1_disk_dir {
        uint32_t rev;
        dbc_lfs_size_t size;
        dbc_lfs_block_t tail[2];
    } d;
} lfs1_dir_t;

typedef struct lfs1_superblock {
    dbc_lfs_off_t off;

    struct lfs1_disk_superblock {
        uint8_t type;
        uint8_t elen;
        uint8_t alen;
        uint8_t nlen;
        dbc_lfs_block_t root[2];
        uint32_t block_size;
        uint32_t block_count;
        uint32_t version;
        char magic[8];
    } d;
} lfs1_superblock_t;


/// Low-level wrappers v1->v2 ///
static void lfs1_crc(uint32_t *crc, const void *buffer, size_t size) {
    *crc = dbc_lfs_crc(*crc, buffer, size);
}

static int lfs1_bd_read(dbc_lfs_t *lfs, dbc_lfs_block_t block,
        dbc_lfs_off_t off, void *buffer, dbc_lfs_size_t size) {
    // if we ever do more than writes to alternating pairs,
    // this may need to consider pcache
    return dbc_lfs_bd_read(lfs, &lfs->pcache, &lfs->rcache, size,
            block, off, buffer, size);
}

static int lfs1_bd_crc(dbc_lfs_t *lfs, dbc_lfs_block_t block,
        dbc_lfs_off_t off, dbc_lfs_size_t size, uint32_t *crc) {
    for (dbc_lfs_off_t i = 0; i < size; i++) {
        uint8_t c;
        int err = lfs1_bd_read(lfs, block, off+i, &c, 1);
        if (err) {
            return err;
        }

        lfs1_crc(crc, &c, 1);
    }

    return 0;
}


/// Endian swapping functions ///
static void lfs1_dir_fromle32(struct lfs1_disk_dir *d) {
    d->rev     = dbc_lfs_fromle32(d->rev);
    d->size    = dbc_lfs_fromle32(d->size);
    d->tail[0] = dbc_lfs_fromle32(d->tail[0]);
    d->tail[1] = dbc_lfs_fromle32(d->tail[1]);
}

static void lfs1_dir_tole32(struct lfs1_disk_dir *d) {
    d->rev     = dbc_lfs_tole32(d->rev);
    d->size    = dbc_lfs_tole32(d->size);
    d->tail[0] = dbc_lfs_tole32(d->tail[0]);
    d->tail[1] = dbc_lfs_tole32(d->tail[1]);
}

static void lfs1_entry_fromle32(struct lfs1_disk_entry *d) {
    d->u.dir[0] = dbc_lfs_fromle32(d->u.dir[0]);
    d->u.dir[1] = dbc_lfs_fromle32(d->u.dir[1]);
}

static void lfs1_entry_tole32(struct lfs1_disk_entry *d) {
    d->u.dir[0] = dbc_lfs_tole32(d->u.dir[0]);
    d->u.dir[1] = dbc_lfs_tole32(d->u.dir[1]);
}

static void lfs1_superblock_fromle32(struct lfs1_disk_superblock *d) {
    d->root[0]     = dbc_lfs_fromle32(d->root[0]);
    d->root[1]     = dbc_lfs_fromle32(d->root[1]);
    d->block_size  = dbc_lfs_fromle32(d->block_size);
    d->block_count = dbc_lfs_fromle32(d->block_count);
    d->version     = dbc_lfs_fromle32(d->version);
}


///// Metadata pair and directory operations ///
static inline dbc_lfs_size_t lfs1_entry_size(const lfs1_entry_t *entry) {
    return 4 + entry->d.elen + entry->d.alen + entry->d.nlen;
}

static int lfs1_dir_fetch(dbc_lfs_t *lfs,
        lfs1_dir_t *dir, const dbc_lfs_block_t pair[2]) {
    // copy out pair, otherwise may be aliasing dir
    const dbc_lfs_block_t tpair[2] = {pair[0], pair[1]};
    bool valid = false;

    // check both blocks for the most recent revision
    for (int i = 0; i < 2; i++) {
        struct lfs1_disk_dir test;
        int err = lfs1_bd_read(lfs, tpair[i], 0, &test, sizeof(test));
        lfs1_dir_fromle32(&test);
        if (err) {
            if (err == DBC_LFS_ERR_CORRUPT) {
                continue;
            }
            return err;
        }

        if (valid && dbc_lfs_scmp(test.rev, dir->d.rev) < 0) {
            continue;
        }

        if ((0x7fffffff & test.size) < sizeof(test)+4 ||
            (0x7fffffff & test.size) > lfs->cfg->block_size) {
            continue;
        }

        uint32_t crc = 0xffffffff;
        lfs1_dir_tole32(&test);
        lfs1_crc(&crc, &test, sizeof(test));
        lfs1_dir_fromle32(&test);
        err = lfs1_bd_crc(lfs, tpair[i], sizeof(test),
                (0x7fffffff & test.size) - sizeof(test), &crc);
        if (err) {
            if (err == DBC_LFS_ERR_CORRUPT) {
                continue;
            }
            return err;
        }

        if (crc != 0) {
            continue;
        }

        valid = true;

        // setup dir in case it's valid
        dir->pair[0] = tpair[(i+0) % 2];
        dir->pair[1] = tpair[(i+1) % 2];
        dir->off = sizeof(dir->d);
        dir->d = test;
    }

    if (!valid) {
        DBC_LFS_ERROR("Corrupted dir pair at {0x%"PRIx32", 0x%"PRIx32"}",
                tpair[0], tpair[1]);
        return DBC_LFS_ERR_CORRUPT;
    }

    return 0;
}

static int lfs1_dir_next(dbc_lfs_t *lfs, lfs1_dir_t *dir, lfs1_entry_t *entry) {
    while (dir->off + sizeof(entry->d) > (0x7fffffff & dir->d.size)-4) {
        if (!(0x80000000 & dir->d.size)) {
            entry->off = dir->off;
            return DBC_LFS_ERR_NOENT;
        }

        int err = lfs1_dir_fetch(lfs, dir, dir->d.tail);
        if (err) {
            return err;
        }

        dir->off = sizeof(dir->d);
        dir->pos += sizeof(dir->d) + 4;
    }

    int err = lfs1_bd_read(lfs, dir->pair[0], dir->off,
            &entry->d, sizeof(entry->d));
    lfs1_entry_fromle32(&entry->d);
    if (err) {
        return err;
    }

    entry->off = dir->off;
    dir->off += lfs1_entry_size(entry);
    dir->pos += lfs1_entry_size(entry);
    return 0;
}

/// littlefs v1 specific operations ///
int lfs1_traverse(dbc_lfs_t *lfs, int (*cb)(void*, dbc_lfs_block_t), void *data) {
    if (dbc_lfs_pair_isnull(lfs->lfs1->root)) {
        return 0;
    }

    // iterate over metadata pairs
    lfs1_dir_t dir;
    lfs1_entry_t entry;
    dbc_lfs_block_t cwd[2] = {0, 1};

    while (true) {
        for (int i = 0; i < 2; i++) {
            int err = cb(data, cwd[i]);
            if (err) {
                return err;
            }
        }

        int err = lfs1_dir_fetch(lfs, &dir, cwd);
        if (err) {
            return err;
        }

        // iterate over contents
        while (dir.off + sizeof(entry.d) <= (0x7fffffff & dir.d.size)-4) {
            err = lfs1_bd_read(lfs, dir.pair[0], dir.off,
                    &entry.d, sizeof(entry.d));
            lfs1_entry_fromle32(&entry.d);
            if (err) {
                return err;
            }

            dir.off += lfs1_entry_size(&entry);
            if ((0x70 & entry.d.type) == (0x70 & LFS1_TYPE_REG)) {
                err = dbc_lfs_ctz_traverse(lfs, NULL, &lfs->rcache,
                        entry.d.u.file.head, entry.d.u.file.size, cb, data);
                if (err) {
                    return err;
                }
            }
        }

        // we also need to check if we contain a threaded v2 directory
        dbc_lfs_mdir_t dir2 = {.split=true, .tail={cwd[0], cwd[1]}};
        while (dir2.split) {
            err = dbc_lfs_dir_fetch(lfs, &dir2, dir2.tail);
            if (err) {
                break;
            }

            for (int i = 0; i < 2; i++) {
                err = cb(data, dir2.pair[i]);
                if (err) {
                    return err;
                }
            }
        }

        cwd[0] = dir.d.tail[0];
        cwd[1] = dir.d.tail[1];

        if (dbc_lfs_pair_isnull(cwd)) {
            break;
        }
    }

    return 0;
}

static int lfs1_moved(dbc_lfs_t *lfs, const void *e) {
    if (dbc_lfs_pair_isnull(lfs->lfs1->root)) {
        return 0;
    }

    // skip superblock
    lfs1_dir_t cwd;
    int err = lfs1_dir_fetch(lfs, &cwd, (const dbc_lfs_block_t[2]){0, 1});
    if (err) {
        return err;
    }

    // iterate over all directory directory entries
    lfs1_entry_t entry;
    while (!dbc_lfs_pair_isnull(cwd.d.tail)) {
        err = lfs1_dir_fetch(lfs, &cwd, cwd.d.tail);
        if (err) {
            return err;
        }

        while (true) {
            err = lfs1_dir_next(lfs, &cwd, &entry);
            if (err && err != DBC_LFS_ERR_NOENT) {
                return err;
            }

            if (err == DBC_LFS_ERR_NOENT) {
                break;
            }

            if (!(0x80 & entry.d.type) &&
                 memcmp(&entry.d.u, e, sizeof(entry.d.u)) == 0) {
                return true;
            }
        }
    }

    return false;
}

/// Filesystem operations ///
static int lfs1_mount(dbc_lfs_t *lfs, struct lfs1 *lfs1,
        const struct dbc_lfs_config *cfg) {
    int err = 0;
    {
        err = dbc_lfs_init(lfs, cfg);
        if (err) {
            return err;
        }

        lfs->lfs1 = lfs1;
        lfs->lfs1->root[0] = DBC_LFS_BLOCK_NULL;
        lfs->lfs1->root[1] = DBC_LFS_BLOCK_NULL;

        // setup free lookahead
        lfs->lookahead.start = 0;
        lfs->lookahead.size = 0;
        lfs->lookahead.next = 0;
        dbc_lfs_alloc_ckpoint(lfs);

        // load superblock
        lfs1_dir_t dir;
        lfs1_superblock_t superblock;
        err = lfs1_dir_fetch(lfs, &dir, (const dbc_lfs_block_t[2]){0, 1});
        if (err && err != DBC_LFS_ERR_CORRUPT) {
            goto cleanup;
        }

        if (!err) {
            err = lfs1_bd_read(lfs, dir.pair[0], sizeof(dir.d),
                    &superblock.d, sizeof(superblock.d));
            lfs1_superblock_fromle32(&superblock.d);
            if (err) {
                goto cleanup;
            }

            lfs->lfs1->root[0] = superblock.d.root[0];
            lfs->lfs1->root[1] = superblock.d.root[1];
        }

        if (err || memcmp(superblock.d.magic, "littlefs", 8) != 0) {
            DBC_LFS_ERROR("Invalid superblock at {0x%"PRIx32", 0x%"PRIx32"}",
                    0, 1);
            err = DBC_LFS_ERR_CORRUPT;
            goto cleanup;
        }

        uint16_t major_version = (0xffff & (superblock.d.version >> 16));
        uint16_t minor_version = (0xffff & (superblock.d.version >>  0));
        if ((major_version != LFS1_DISK_VERSION_MAJOR ||
             minor_version > LFS1_DISK_VERSION_MINOR)) {
            DBC_LFS_ERROR("Invalid version v%d.%d", major_version, minor_version);
            err = DBC_LFS_ERR_INVAL;
            goto cleanup;
        }

        return 0;
    }

cleanup:
    dbc_lfs_deinit(lfs);
    return err;
}

static int lfs1_unmount(dbc_lfs_t *lfs) {
    return dbc_lfs_deinit(lfs);
}

/// v1 migration ///
static int dbc_lfs_migrate_(dbc_lfs_t *lfs, const struct dbc_lfs_config *cfg) {
    struct lfs1 lfs1;

    // Indeterminate filesystem size not allowed for migration.
    DBC_LFS_ASSERT(cfg->block_count != 0);

    int err = lfs1_mount(lfs, &lfs1, cfg);
    if (err) {
        return err;
    }

    {
        // iterate through each directory, copying over entries
        // into new directory
        lfs1_dir_t dir1;
        dbc_lfs_mdir_t dir2;
        dir1.d.tail[0] = lfs->lfs1->root[0];
        dir1.d.tail[1] = lfs->lfs1->root[1];
        while (!dbc_lfs_pair_isnull(dir1.d.tail)) {
            // iterate old dir
            err = lfs1_dir_fetch(lfs, &dir1, dir1.d.tail);
            if (err) {
                goto cleanup;
            }

            // create new dir and bind as temporary pretend root
            err = dbc_lfs_dir_alloc(lfs, &dir2);
            if (err) {
                goto cleanup;
            }

            dir2.rev = dir1.d.rev;
            dir1.head[0] = dir1.pair[0];
            dir1.head[1] = dir1.pair[1];
            lfs->root[0] = dir2.pair[0];
            lfs->root[1] = dir2.pair[1];

            err = dbc_lfs_dir_commit(lfs, &dir2, NULL, 0);
            if (err) {
                goto cleanup;
            }

            while (true) {
                lfs1_entry_t entry1;
                err = lfs1_dir_next(lfs, &dir1, &entry1);
                if (err && err != DBC_LFS_ERR_NOENT) {
                    goto cleanup;
                }

                if (err == DBC_LFS_ERR_NOENT) {
                    break;
                }

                // check that entry has not been moved
                if (entry1.d.type & 0x80) {
                    int moved = lfs1_moved(lfs, &entry1.d.u);
                    if (moved < 0) {
                        err = moved;
                        goto cleanup;
                    }

                    if (moved) {
                        continue;
                    }

                    entry1.d.type &= ~0x80;
                }

                // also fetch name
                char name[DBC_LFS_NAME_MAX+1];
                memset(name, 0, sizeof(name));
                err = lfs1_bd_read(lfs, dir1.pair[0],
                        entry1.off + 4+entry1.d.elen+entry1.d.alen,
                        name, entry1.d.nlen);
                if (err) {
                    goto cleanup;
                }

                bool isdir = (entry1.d.type == LFS1_TYPE_DIR);

                // create entry in new dir
                err = dbc_lfs_dir_fetch(lfs, &dir2, lfs->root);
                if (err) {
                    goto cleanup;
                }

                uint16_t id;
                err = dbc_lfs_dir_find(lfs, &dir2, &(const char*){name}, &id);
                if (!(err == DBC_LFS_ERR_NOENT && id != 0x3ff)) {
                    err = (err < 0) ? err : DBC_LFS_ERR_EXIST;
                    goto cleanup;
                }

                lfs1_entry_tole32(&entry1.d);
                err = dbc_lfs_dir_commit(lfs, &dir2, DBC_LFS_MKATTRS(
                        {DBC_LFS_MKTAG(DBC_LFS_TYPE_CREATE, id, 0), NULL},
                        {DBC_LFS_MKTAG_IF_ELSE(isdir,
                            DBC_LFS_TYPE_DIR, id, entry1.d.nlen,
                            DBC_LFS_TYPE_REG, id, entry1.d.nlen),
                                name},
                        {DBC_LFS_MKTAG_IF_ELSE(isdir,
                            DBC_LFS_TYPE_DIRSTRUCT, id, sizeof(entry1.d.u),
                            DBC_LFS_TYPE_CTZSTRUCT, id, sizeof(entry1.d.u)),
                                &entry1.d.u}));
                lfs1_entry_fromle32(&entry1.d);
                if (err) {
                    goto cleanup;
                }
            }

            if (!dbc_lfs_pair_isnull(dir1.d.tail)) {
                // find last block and update tail to thread into fs
                err = dbc_lfs_dir_fetch(lfs, &dir2, lfs->root);
                if (err) {
                    goto cleanup;
                }

                while (dir2.split) {
                    err = dbc_lfs_dir_fetch(lfs, &dir2, dir2.tail);
                    if (err) {
                        goto cleanup;
                    }
                }

                dbc_lfs_pair_tole32(dir2.pair);
                err = dbc_lfs_dir_commit(lfs, &dir2, DBC_LFS_MKATTRS(
                        {DBC_LFS_MKTAG(DBC_LFS_TYPE_SOFTTAIL, 0x3ff, 8), dir1.d.tail}));
                dbc_lfs_pair_fromle32(dir2.pair);
                if (err) {
                    goto cleanup;
                }
            }

            // Copy over first block to thread into fs. Unfortunately
            // if this fails there is not much we can do.
            DBC_LFS_DEBUG("Migrating {0x%"PRIx32", 0x%"PRIx32"} "
                        "-> {0x%"PRIx32", 0x%"PRIx32"}",
                    lfs->root[0], lfs->root[1], dir1.head[0], dir1.head[1]);

            err = dbc_lfs_bd_erase(lfs, dir1.head[1]);
            if (err) {
                goto cleanup;
            }

            err = dbc_lfs_dir_fetch(lfs, &dir2, lfs->root);
            if (err) {
                goto cleanup;
            }

            for (dbc_lfs_off_t i = 0; i < dir2.off; i++) {
                uint8_t dat;
                err = dbc_lfs_bd_read(lfs,
                        NULL, &lfs->rcache, dir2.off,
                        dir2.pair[0], i, &dat, 1);
                if (err) {
                    goto cleanup;
                }

                err = dbc_lfs_bd_prog(lfs,
                        &lfs->pcache, &lfs->rcache, true,
                        dir1.head[1], i, &dat, 1);
                if (err) {
                    goto cleanup;
                }
            }

            err = dbc_lfs_bd_flush(lfs, &lfs->pcache, &lfs->rcache, true);
            if (err) {
                goto cleanup;
            }
        }

        // Create new superblock. This marks a successful migration!
        err = lfs1_dir_fetch(lfs, &dir1, (const dbc_lfs_block_t[2]){0, 1});
        if (err) {
            goto cleanup;
        }

        dir2.pair[0] = dir1.pair[0];
        dir2.pair[1] = dir1.pair[1];
        dir2.rev = dir1.d.rev;
        dir2.off = sizeof(dir2.rev);
        dir2.etag = 0xffffffff;
        dir2.count = 0;
        dir2.tail[0] = lfs->lfs1->root[0];
        dir2.tail[1] = lfs->lfs1->root[1];
        dir2.erased = false;
        dir2.split = true;

        dbc_lfs_superblock_t superblock = {
            .version     = DBC_LFS_DISK_VERSION,
            .block_size  = lfs->cfg->block_size,
            .block_count = lfs->cfg->block_count,
            .name_max    = lfs->name_max,
            .file_max    = lfs->file_max,
            .attr_max    = lfs->attr_max,
        };

        dbc_lfs_superblock_tole32(&superblock);
        err = dbc_lfs_dir_commit(lfs, &dir2, DBC_LFS_MKATTRS(
                {DBC_LFS_MKTAG(DBC_LFS_TYPE_CREATE, 0, 0), NULL},
                {DBC_LFS_MKTAG(DBC_LFS_TYPE_SUPERBLOCK, 0, 8), "littlefs"},
                {DBC_LFS_MKTAG(DBC_LFS_TYPE_INLINESTRUCT, 0, sizeof(superblock)),
                    &superblock}));
        if (err) {
            goto cleanup;
        }

        // sanity check that fetch works
        err = dbc_lfs_dir_fetch(lfs, &dir2, (const dbc_lfs_block_t[2]){0, 1});
        if (err) {
            goto cleanup;
        }

        // force compaction to prevent accidentally mounting v1
        dir2.erased = false;
        err = dbc_lfs_dir_commit(lfs, &dir2, NULL, 0);
        if (err) {
            goto cleanup;
        }
    }

cleanup:
    lfs1_unmount(lfs);
    return err;
}

#endif


/// Public API wrappers ///

// Here we can add tracing/thread safety easily

// Thread-safe wrappers if enabled
#ifdef DBC_LFS_THREADSAFE
#define DBC_LFS_LOCK(cfg)   cfg->lock(cfg)
#define DBC_LFS_UNLOCK(cfg) cfg->unlock(cfg)
#else
#define DBC_LFS_LOCK(cfg)   ((void)cfg, 0)
#define DBC_LFS_UNLOCK(cfg) ((void)cfg)
#endif

// Public API
#ifndef DBC_LFS_READONLY
int dbc_lfs_format(dbc_lfs_t *lfs, const struct dbc_lfs_config *cfg) {
    int err = DBC_LFS_LOCK(cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_format(%p, %p {.context=%p, "
                ".read=%p, .prog=%p, .erase=%p, .sync=%p, "
                ".read_size=%"PRIu32", .prog_size=%"PRIu32", "
                ".block_size=%"PRIu32", .block_count=%"PRIu32", "
                ".block_cycles=%"PRIu32", .cache_size=%"PRIu32", "
                ".lookahead_size=%"PRIu32", .read_buffer=%p, "
                ".prog_buffer=%p, .lookahead_buffer=%p, "
                ".name_max=%"PRIu32", .file_max=%"PRIu32", "
                ".attr_max=%"PRIu32"})",
            (void*)lfs, (void*)cfg, cfg->context,
            (void*)(uintptr_t)cfg->read, (void*)(uintptr_t)cfg->prog,
            (void*)(uintptr_t)cfg->erase, (void*)(uintptr_t)cfg->sync,
            cfg->read_size, cfg->prog_size, cfg->block_size, cfg->block_count,
            cfg->block_cycles, cfg->cache_size, cfg->lookahead_size,
            cfg->read_buffer, cfg->prog_buffer, cfg->lookahead_buffer,
            cfg->name_max, cfg->file_max, cfg->attr_max);

    err = dbc_lfs_format_(lfs, cfg);

    DBC_LFS_TRACE("dbc_lfs_format -> %d", err);
    DBC_LFS_UNLOCK(cfg);
    return err;
}
#endif

int dbc_lfs_mount(dbc_lfs_t *lfs, const struct dbc_lfs_config *cfg) {
    int err = DBC_LFS_LOCK(cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_mount(%p, %p {.context=%p, "
                ".read=%p, .prog=%p, .erase=%p, .sync=%p, "
                ".read_size=%"PRIu32", .prog_size=%"PRIu32", "
                ".block_size=%"PRIu32", .block_count=%"PRIu32", "
                ".block_cycles=%"PRIu32", .cache_size=%"PRIu32", "
                ".lookahead_size=%"PRIu32", .read_buffer=%p, "
                ".prog_buffer=%p, .lookahead_buffer=%p, "
                ".name_max=%"PRIu32", .file_max=%"PRIu32", "
                ".attr_max=%"PRIu32"})",
            (void*)lfs, (void*)cfg, cfg->context,
            (void*)(uintptr_t)cfg->read, (void*)(uintptr_t)cfg->prog,
            (void*)(uintptr_t)cfg->erase, (void*)(uintptr_t)cfg->sync,
            cfg->read_size, cfg->prog_size, cfg->block_size, cfg->block_count,
            cfg->block_cycles, cfg->cache_size, cfg->lookahead_size,
            cfg->read_buffer, cfg->prog_buffer, cfg->lookahead_buffer,
            cfg->name_max, cfg->file_max, cfg->attr_max);

    err = dbc_lfs_mount_(lfs, cfg);

    DBC_LFS_TRACE("dbc_lfs_mount -> %d", err);
    DBC_LFS_UNLOCK(cfg);
    return err;
}

int dbc_lfs_unmount(dbc_lfs_t *lfs) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_unmount(%p)", (void*)lfs);

    err = dbc_lfs_unmount_(lfs);

    DBC_LFS_TRACE("dbc_lfs_unmount -> %d", err);
    DBC_LFS_UNLOCK(lfs->cfg);
    return err;
}

#ifndef DBC_LFS_READONLY
int dbc_lfs_remove(dbc_lfs_t *lfs, const char *path) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_remove(%p, \"%s\")", (void*)lfs, path);

    err = dbc_lfs_remove_(lfs, path);

    DBC_LFS_TRACE("dbc_lfs_remove -> %d", err);
    DBC_LFS_UNLOCK(lfs->cfg);
    return err;
}
#endif

#ifndef DBC_LFS_READONLY
int dbc_lfs_rename(dbc_lfs_t *lfs, const char *oldpath, const char *newpath) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_rename(%p, \"%s\", \"%s\")", (void*)lfs, oldpath, newpath);

    err = dbc_lfs_rename_(lfs, oldpath, newpath);

    DBC_LFS_TRACE("dbc_lfs_rename -> %d", err);
    DBC_LFS_UNLOCK(lfs->cfg);
    return err;
}
#endif

int dbc_lfs_stat(dbc_lfs_t *lfs, const char *path, struct dbc_lfs_info *info) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_stat(%p, \"%s\", %p)", (void*)lfs, path, (void*)info);

    err = dbc_lfs_stat_(lfs, path, info);

    DBC_LFS_TRACE("dbc_lfs_stat -> %d", err);
    DBC_LFS_UNLOCK(lfs->cfg);
    return err;
}

dbc_lfs_ssize_t dbc_lfs_getattr(dbc_lfs_t *lfs, const char *path,
        uint8_t type, void *buffer, dbc_lfs_size_t size) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_getattr(%p, \"%s\", %"PRIu8", %p, %"PRIu32")",
            (void*)lfs, path, type, buffer, size);

    dbc_lfs_ssize_t res = dbc_lfs_getattr_(lfs, path, type, buffer, size);

    DBC_LFS_TRACE("dbc_lfs_getattr -> %"PRId32, res);
    DBC_LFS_UNLOCK(lfs->cfg);
    return res;
}

#ifndef DBC_LFS_READONLY
int dbc_lfs_setattr(dbc_lfs_t *lfs, const char *path,
        uint8_t type, const void *buffer, dbc_lfs_size_t size) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_setattr(%p, \"%s\", %"PRIu8", %p, %"PRIu32")",
            (void*)lfs, path, type, buffer, size);

    err = dbc_lfs_setattr_(lfs, path, type, buffer, size);

    DBC_LFS_TRACE("dbc_lfs_setattr -> %d", err);
    DBC_LFS_UNLOCK(lfs->cfg);
    return err;
}
#endif

#ifndef DBC_LFS_READONLY
int dbc_lfs_removeattr(dbc_lfs_t *lfs, const char *path, uint8_t type) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_removeattr(%p, \"%s\", %"PRIu8")", (void*)lfs, path, type);

    err = dbc_lfs_removeattr_(lfs, path, type);

    DBC_LFS_TRACE("dbc_lfs_removeattr -> %d", err);
    DBC_LFS_UNLOCK(lfs->cfg);
    return err;
}
#endif

#ifndef DBC_LFS_NO_MALLOC
int dbc_lfs_file_open(dbc_lfs_t *lfs, dbc_lfs_file_t *file, const char *path, int flags) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_file_open(%p, %p, \"%s\", %x)",
            (void*)lfs, (void*)file, path, flags);
    DBC_LFS_ASSERT(!dbc_lfs_mlist_isopen(lfs->mlist, (struct dbc_lfs_mlist*)file));

    err = dbc_lfs_file_open_(lfs, file, path, flags);

    DBC_LFS_TRACE("dbc_lfs_file_open -> %d", err);
    DBC_LFS_UNLOCK(lfs->cfg);
    return err;
}
#endif

int dbc_lfs_file_opencfg(dbc_lfs_t *lfs, dbc_lfs_file_t *file,
        const char *path, int flags,
        const struct dbc_lfs_file_config *cfg) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_file_opencfg(%p, %p, \"%s\", %x, %p {"
                 ".buffer=%p, .attrs=%p, .attr_count=%"PRIu32"})",
            (void*)lfs, (void*)file, path, flags,
            (void*)cfg, cfg->buffer, (void*)cfg->attrs, cfg->attr_count);
    DBC_LFS_ASSERT(!dbc_lfs_mlist_isopen(lfs->mlist, (struct dbc_lfs_mlist*)file));

    err = dbc_lfs_file_opencfg_(lfs, file, path, flags, cfg);

    DBC_LFS_TRACE("dbc_lfs_file_opencfg -> %d", err);
    DBC_LFS_UNLOCK(lfs->cfg);
    return err;
}

int dbc_lfs_file_close(dbc_lfs_t *lfs, dbc_lfs_file_t *file) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_file_close(%p, %p)", (void*)lfs, (void*)file);
    DBC_LFS_ASSERT(dbc_lfs_mlist_isopen(lfs->mlist, (struct dbc_lfs_mlist*)file));

    err = dbc_lfs_file_close_(lfs, file);

    DBC_LFS_TRACE("dbc_lfs_file_close -> %d", err);
    DBC_LFS_UNLOCK(lfs->cfg);
    return err;
}

#ifndef DBC_LFS_READONLY
int dbc_lfs_file_sync(dbc_lfs_t *lfs, dbc_lfs_file_t *file) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_file_sync(%p, %p)", (void*)lfs, (void*)file);
    DBC_LFS_ASSERT(dbc_lfs_mlist_isopen(lfs->mlist, (struct dbc_lfs_mlist*)file));

    err = dbc_lfs_file_sync_(lfs, file);

    DBC_LFS_TRACE("dbc_lfs_file_sync -> %d", err);
    DBC_LFS_UNLOCK(lfs->cfg);
    return err;
}
#endif

dbc_lfs_ssize_t dbc_lfs_file_read(dbc_lfs_t *lfs, dbc_lfs_file_t *file,
        void *buffer, dbc_lfs_size_t size) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_file_read(%p, %p, %p, %"PRIu32")",
            (void*)lfs, (void*)file, buffer, size);
    DBC_LFS_ASSERT(dbc_lfs_mlist_isopen(lfs->mlist, (struct dbc_lfs_mlist*)file));

    dbc_lfs_ssize_t res = dbc_lfs_file_read_(lfs, file, buffer, size);

    DBC_LFS_TRACE("dbc_lfs_file_read -> %"PRId32, res);
    DBC_LFS_UNLOCK(lfs->cfg);
    return res;
}

#ifndef DBC_LFS_READONLY
dbc_lfs_ssize_t dbc_lfs_file_write(dbc_lfs_t *lfs, dbc_lfs_file_t *file,
        const void *buffer, dbc_lfs_size_t size) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_file_write(%p, %p, %p, %"PRIu32")",
            (void*)lfs, (void*)file, buffer, size);
    DBC_LFS_ASSERT(dbc_lfs_mlist_isopen(lfs->mlist, (struct dbc_lfs_mlist*)file));

    dbc_lfs_ssize_t res = dbc_lfs_file_write_(lfs, file, buffer, size);

    DBC_LFS_TRACE("dbc_lfs_file_write -> %"PRId32, res);
    DBC_LFS_UNLOCK(lfs->cfg);
    return res;
}
#endif

dbc_lfs_soff_t dbc_lfs_file_seek(dbc_lfs_t *lfs, dbc_lfs_file_t *file,
        dbc_lfs_soff_t off, int whence) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_file_seek(%p, %p, %"PRId32", %d)",
            (void*)lfs, (void*)file, off, whence);
    DBC_LFS_ASSERT(dbc_lfs_mlist_isopen(lfs->mlist, (struct dbc_lfs_mlist*)file));

    dbc_lfs_soff_t res = dbc_lfs_file_seek_(lfs, file, off, whence);

    DBC_LFS_TRACE("dbc_lfs_file_seek -> %"PRId32, res);
    DBC_LFS_UNLOCK(lfs->cfg);
    return res;
}

#ifndef DBC_LFS_READONLY
int dbc_lfs_file_truncate(dbc_lfs_t *lfs, dbc_lfs_file_t *file, dbc_lfs_off_t size) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_file_truncate(%p, %p, %"PRIu32")",
            (void*)lfs, (void*)file, size);
    DBC_LFS_ASSERT(dbc_lfs_mlist_isopen(lfs->mlist, (struct dbc_lfs_mlist*)file));

    err = dbc_lfs_file_truncate_(lfs, file, size);

    DBC_LFS_TRACE("dbc_lfs_file_truncate -> %d", err);
    DBC_LFS_UNLOCK(lfs->cfg);
    return err;
}
#endif

dbc_lfs_soff_t dbc_lfs_file_tell(dbc_lfs_t *lfs, dbc_lfs_file_t *file) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_file_tell(%p, %p)", (void*)lfs, (void*)file);
    DBC_LFS_ASSERT(dbc_lfs_mlist_isopen(lfs->mlist, (struct dbc_lfs_mlist*)file));

    dbc_lfs_soff_t res = dbc_lfs_file_tell_(lfs, file);

    DBC_LFS_TRACE("dbc_lfs_file_tell -> %"PRId32, res);
    DBC_LFS_UNLOCK(lfs->cfg);
    return res;
}

int dbc_lfs_file_rewind(dbc_lfs_t *lfs, dbc_lfs_file_t *file) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_file_rewind(%p, %p)", (void*)lfs, (void*)file);

    err = dbc_lfs_file_rewind_(lfs, file);

    DBC_LFS_TRACE("dbc_lfs_file_rewind -> %d", err);
    DBC_LFS_UNLOCK(lfs->cfg);
    return err;
}

dbc_lfs_soff_t dbc_lfs_file_size(dbc_lfs_t *lfs, dbc_lfs_file_t *file) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_file_size(%p, %p)", (void*)lfs, (void*)file);
    DBC_LFS_ASSERT(dbc_lfs_mlist_isopen(lfs->mlist, (struct dbc_lfs_mlist*)file));

    dbc_lfs_soff_t res = dbc_lfs_file_size_(lfs, file);

    DBC_LFS_TRACE("dbc_lfs_file_size -> %"PRId32, res);
    DBC_LFS_UNLOCK(lfs->cfg);
    return res;
}

#ifndef DBC_LFS_READONLY
int dbc_lfs_mkdir(dbc_lfs_t *lfs, const char *path) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_mkdir(%p, \"%s\")", (void*)lfs, path);

    err = dbc_lfs_mkdir_(lfs, path);

    DBC_LFS_TRACE("dbc_lfs_mkdir -> %d", err);
    DBC_LFS_UNLOCK(lfs->cfg);
    return err;
}
#endif

int dbc_lfs_dir_open(dbc_lfs_t *lfs, dbc_lfs_dir_t *dir, const char *path) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_dir_open(%p, %p, \"%s\")", (void*)lfs, (void*)dir, path);
    DBC_LFS_ASSERT(!dbc_lfs_mlist_isopen(lfs->mlist, (struct dbc_lfs_mlist*)dir));

    err = dbc_lfs_dir_open_(lfs, dir, path);

    DBC_LFS_TRACE("dbc_lfs_dir_open -> %d", err);
    DBC_LFS_UNLOCK(lfs->cfg);
    return err;
}

int dbc_lfs_dir_close(dbc_lfs_t *lfs, dbc_lfs_dir_t *dir) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_dir_close(%p, %p)", (void*)lfs, (void*)dir);

    err = dbc_lfs_dir_close_(lfs, dir);

    DBC_LFS_TRACE("dbc_lfs_dir_close -> %d", err);
    DBC_LFS_UNLOCK(lfs->cfg);
    return err;
}

int dbc_lfs_dir_read(dbc_lfs_t *lfs, dbc_lfs_dir_t *dir, struct dbc_lfs_info *info) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_dir_read(%p, %p, %p)",
            (void*)lfs, (void*)dir, (void*)info);

    err = dbc_lfs_dir_read_(lfs, dir, info);

    DBC_LFS_TRACE("dbc_lfs_dir_read -> %d", err);
    DBC_LFS_UNLOCK(lfs->cfg);
    return err;
}

int dbc_lfs_dir_seek(dbc_lfs_t *lfs, dbc_lfs_dir_t *dir, dbc_lfs_off_t off) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_dir_seek(%p, %p, %"PRIu32")",
            (void*)lfs, (void*)dir, off);

    err = dbc_lfs_dir_seek_(lfs, dir, off);

    DBC_LFS_TRACE("dbc_lfs_dir_seek -> %d", err);
    DBC_LFS_UNLOCK(lfs->cfg);
    return err;
}

dbc_lfs_soff_t dbc_lfs_dir_tell(dbc_lfs_t *lfs, dbc_lfs_dir_t *dir) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_dir_tell(%p, %p)", (void*)lfs, (void*)dir);

    dbc_lfs_soff_t res = dbc_lfs_dir_tell_(lfs, dir);

    DBC_LFS_TRACE("dbc_lfs_dir_tell -> %"PRId32, res);
    DBC_LFS_UNLOCK(lfs->cfg);
    return res;
}

int dbc_lfs_dir_rewind(dbc_lfs_t *lfs, dbc_lfs_dir_t *dir) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_dir_rewind(%p, %p)", (void*)lfs, (void*)dir);

    err = dbc_lfs_dir_rewind_(lfs, dir);

    DBC_LFS_TRACE("dbc_lfs_dir_rewind -> %d", err);
    DBC_LFS_UNLOCK(lfs->cfg);
    return err;
}

int dbc_lfs_fs_stat(dbc_lfs_t *lfs, struct dbc_lfs_fsinfo *fsinfo) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_fs_stat(%p, %p)", (void*)lfs, (void*)fsinfo);

    err = dbc_lfs_fs_stat_(lfs, fsinfo);

    DBC_LFS_TRACE("dbc_lfs_fs_stat -> %d", err);
    DBC_LFS_UNLOCK(lfs->cfg);
    return err;
}

dbc_lfs_ssize_t dbc_lfs_fs_size(dbc_lfs_t *lfs) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_fs_size(%p)", (void*)lfs);

    dbc_lfs_ssize_t res = dbc_lfs_fs_size_(lfs);

    DBC_LFS_TRACE("dbc_lfs_fs_size -> %"PRId32, res);
    DBC_LFS_UNLOCK(lfs->cfg);
    return res;
}

int dbc_lfs_fs_traverse(dbc_lfs_t *lfs, int (*cb)(void *, dbc_lfs_block_t), void *data) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_fs_traverse(%p, %p, %p)",
            (void*)lfs, (void*)(uintptr_t)cb, data);

    err = dbc_lfs_fs_traverse_(lfs, cb, data, true);

    DBC_LFS_TRACE("dbc_lfs_fs_traverse -> %d", err);
    DBC_LFS_UNLOCK(lfs->cfg);
    return err;
}

#ifndef DBC_LFS_READONLY
int dbc_lfs_fs_mkconsistent(dbc_lfs_t *lfs) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_fs_mkconsistent(%p)", (void*)lfs);

    err = dbc_lfs_fs_mkconsistent_(lfs);

    DBC_LFS_TRACE("dbc_lfs_fs_mkconsistent -> %d", err);
    DBC_LFS_UNLOCK(lfs->cfg);
    return err;
}
#endif

#ifndef DBC_LFS_READONLY
int dbc_lfs_fs_gc(dbc_lfs_t *lfs) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_fs_gc(%p)", (void*)lfs);

    err = dbc_lfs_fs_gc_(lfs);

    DBC_LFS_TRACE("dbc_lfs_fs_gc -> %d", err);
    DBC_LFS_UNLOCK(lfs->cfg);
    return err;
}
#endif

#ifndef DBC_LFS_READONLY
int dbc_lfs_fs_grow(dbc_lfs_t *lfs, dbc_lfs_size_t block_count) {
    int err = DBC_LFS_LOCK(lfs->cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_fs_grow(%p, %"PRIu32")", (void*)lfs, block_count);

    err = dbc_lfs_fs_grow_(lfs, block_count);

    DBC_LFS_TRACE("dbc_lfs_fs_grow -> %d", err);
    DBC_LFS_UNLOCK(lfs->cfg);
    return err;
}
#endif

#ifdef DBC_LFS_MIGRATE
int dbc_lfs_migrate(dbc_lfs_t *lfs, const struct dbc_lfs_config *cfg) {
    int err = DBC_LFS_LOCK(cfg);
    if (err) {
        return err;
    }
    DBC_LFS_TRACE("dbc_lfs_migrate(%p, %p {.context=%p, "
                ".read=%p, .prog=%p, .erase=%p, .sync=%p, "
                ".read_size=%"PRIu32", .prog_size=%"PRIu32", "
                ".block_size=%"PRIu32", .block_count=%"PRIu32", "
                ".block_cycles=%"PRIu32", .cache_size=%"PRIu32", "
                ".lookahead_size=%"PRIu32", .read_buffer=%p, "
                ".prog_buffer=%p, .lookahead_buffer=%p, "
                ".name_max=%"PRIu32", .file_max=%"PRIu32", "
                ".attr_max=%"PRIu32"})",
            (void*)lfs, (void*)cfg, cfg->context,
            (void*)(uintptr_t)cfg->read, (void*)(uintptr_t)cfg->prog,
            (void*)(uintptr_t)cfg->erase, (void*)(uintptr_t)cfg->sync,
            cfg->read_size, cfg->prog_size, cfg->block_size, cfg->block_count,
            cfg->block_cycles, cfg->cache_size, cfg->lookahead_size,
            cfg->read_buffer, cfg->prog_buffer, cfg->lookahead_buffer,
            cfg->name_max, cfg->file_max, cfg->attr_max);

    err = dbc_lfs_migrate_(lfs, cfg);

    DBC_LFS_TRACE("dbc_lfs_migrate -> %d", err);
    DBC_LFS_UNLOCK(cfg);
    return err;
}
#endif

