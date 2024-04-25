/*
 * FUSE wrapper for the littlefs
 *
 * Copyright (c) 2022, the littlefs authors.
 * Copyright (c) 2017, Arm Limited. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#define FUSE_USE_VERSION 26

#ifdef linux
// needed for a few things fuse depends on
#define _XOPEN_SOURCE 700
#endif

#include <fuse/fuse.h>
#include "lfs.h"
#include "lfs_util.h"
#include "lfs_fuse_bd.h"

#include <stdio.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>


// littefs-fuse version
//
// Note this is different from the littlefs core version, and littlefs
// on-disk version
//
// Major (top-nibble), incremented on backwards incompatible changes
// Minor (bottom-nibble), incremented on feature additions
#define DBC_LFS_FUSE_VERSION 0x00020007
#define DBC_LFS_FUSE_VERSION_MAJOR (0xffff & (DBC_LFS_FUSE_VERSION >> 16))
#define DBC_LFS_FUSE_VERSION_MINOR (0xffff & (DBC_LFS_FUSE_VERSION >>  0))


// config and other state
static struct dbc_lfs_config config = {0};
static const char *device = NULL;
static bool stat_ = false;
static bool format = false;
static bool migrate = false;
static dbc_lfs_t lfs;


// actual fuse functions
void dbc_lfs_fuse_defaults(struct dbc_lfs_config *config) {
    // default to 512 erase cycles, arbitrary value
    if (!config->block_cycles) {
        config->block_cycles = 512;
    }

    // defaults, ram is less of a concern here than what
    // littlefs is used to, so these may end up a bit funny
    if (!config->prog_size) {
        config->prog_size = config->block_size;
    }

    if (!config->read_size) {
        config->read_size = config->block_size;
    }

    if (!config->cache_size) {
        config->cache_size = config->block_size;
    }

    // arbitrary, though we have a lot of RAM here
    if (!config->lookahead_size) {
        config->lookahead_size = 8192;
    }
}

void *dbc_lfs_fuse_init(struct fuse_conn_info *conn) {
    // set that we want to take care of O_TRUNC
    conn->want |= FUSE_CAP_ATOMIC_O_TRUNC;

    // we also support writes of any size
    conn->want |= FUSE_CAP_BIG_WRITES;

    return 0;
}

int dbc_lfs_fuse_stat(void) {
    int err = dbc_lfs_fuse_bd_create(&config, device);
    if (err) {
        return err;
    }

    dbc_lfs_fuse_defaults(&config);

    err = dbc_lfs_mount(&lfs, &config);
    if (err) {
        goto failed;
    }

    // get on-disk info
    struct dbc_lfs_fsinfo fsinfo;
    err = dbc_lfs_fs_stat(&lfs, &fsinfo);
    if (err) {
        goto failed;
    }

    // get block usage
    dbc_lfs_ssize_t in_use = dbc_lfs_fs_size(&lfs);
    if (in_use < 0) {
        err = in_use;
        goto failed;
    }

    // print to stdout
    printf("disk_version: lfs%d.%d\n",
            0xffff & (fsinfo.disk_version >> 16),
            0xffff & (fsinfo.disk_version >>  0));
    printf("block_size: %d\n", config.block_size);
    printf("block_count: %d\n", config.block_count);
    printf("  used: %d/%d (%.1f%%)\n",
            in_use,
            config.block_count,
            100.0f * (float)in_use / (float)config.block_count);
    printf("  free: %d/%d (%.1f%%)\n",
            config.block_count-in_use,
            config.block_count,
            100.0f * (float)(config.block_count-in_use)
                / (float)config.block_count);
    printf("name_max: %d\n", fsinfo.name_max);
    printf("file_max: %d\n", fsinfo.file_max);
    printf("attr_max: %d\n", fsinfo.attr_max);

    err = dbc_lfs_unmount(&lfs);

failed:
    dbc_lfs_fuse_bd_destroy(&config);
    return err;
}

int dbc_lfs_fuse_format(void) {
    int err = dbc_lfs_fuse_bd_create(&config, device);
    if (err) {
        return err;
    }

    dbc_lfs_fuse_defaults(&config);

    err = dbc_lfs_format(&lfs, &config);

    dbc_lfs_fuse_bd_destroy(&config);
    return err;
}

int dbc_lfs_fuse_migrate(void) {
    int err = dbc_lfs_fuse_bd_create(&config, device);
    if (err) {
        return err;
    }

    dbc_lfs_fuse_defaults(&config);

    err = dbc_lfs_migrate(&lfs, &config);

    dbc_lfs_fuse_bd_destroy(&config);
    return err;
}

int dbc_lfs_fuse_mount(void) {
    int err = dbc_lfs_fuse_bd_create(&config, device);
    if (err) {
        return err;
    }

    dbc_lfs_fuse_defaults(&config);

    return dbc_lfs_mount(&lfs, &config);
}

void dbc_lfs_fuse_destroy(void *eh) {
    dbc_lfs_unmount(&lfs);
    dbc_lfs_fuse_bd_destroy(&config);
}

int dbc_lfs_fuse_statfs(const char *path, struct statvfs *s) {
    memset(s, 0, sizeof(struct statvfs));

    // get the on-disk name_max from littlefs
    struct dbc_lfs_fsinfo fsinfo;
    int err = dbc_lfs_fs_stat(&lfs, &fsinfo);
    if (err) {
        return err;
    }

    // get the filesystem block usage from littlefs
    dbc_lfs_ssize_t in_use = dbc_lfs_fs_size(&lfs);
    if (in_use < 0) {
        return in_use;
    }

    s->f_bsize = config.block_size;
    s->f_frsize = config.block_size;
    s->f_blocks = config.block_count;
    s->f_bfree = config.block_count - in_use;
    s->f_bavail = config.block_count - in_use;
    s->f_namemax = fsinfo.name_max;

    return 0;
}

static void dbc_lfs_fuse_tostat(struct stat *s, struct dbc_lfs_info *info) {
    memset(s, 0, sizeof(struct stat));

    s->st_size = info->size;
    s->st_mode = S_IRWXU | S_IRWXG | S_IRWXO;

    switch (info->type) {
        case DBC_LFS_TYPE_DIR: s->st_mode |= S_IFDIR; break;
        case DBC_LFS_TYPE_REG: s->st_mode |= S_IFREG; break;
    }
}

int dbc_lfs_fuse_getattr(const char *path, struct stat *s) {
    struct dbc_lfs_info info;
    int err = dbc_lfs_stat(&lfs, path, &info);
    if (err) {
        return err;
    }

    dbc_lfs_fuse_tostat(s, &info);
    return 0;
}

int dbc_lfs_fuse_access(const char *path, int mask) {
    struct dbc_lfs_info info;
    return dbc_lfs_stat(&lfs, path, &info);
}

int dbc_lfs_fuse_mkdir(const char *path, mode_t mode) {
    return dbc_lfs_mkdir(&lfs, path);
}

int dbc_lfs_fuse_opendir(const char *path, struct fuse_file_info *fi) {
    dbc_lfs_dir_t *dir = malloc(sizeof(dbc_lfs_dir_t));
    memset(dir, 0, sizeof(dbc_lfs_dir_t));

    int err = dbc_lfs_dir_open(&lfs, dir, path);
    if (err) {
        free(dir);
        return err;
    }

    fi->fh = (uint64_t)dir;
    return 0;
}

int dbc_lfs_fuse_releasedir(const char *path, struct fuse_file_info *fi) {
    dbc_lfs_dir_t *dir = (dbc_lfs_dir_t*)fi->fh;

    int err = dbc_lfs_dir_close(&lfs, dir);
    free(dir);
    return err;
}

int dbc_lfs_fuse_readdir(const char *path, void *buf,
        fuse_fill_dir_t filler, off_t offset,
        struct fuse_file_info *fi) {
    
    dbc_lfs_dir_t *dir = (dbc_lfs_dir_t*)fi->fh;
    struct stat s;
    struct dbc_lfs_info info;

    while (true) {
        int err = dbc_lfs_dir_read(&lfs, dir, &info);
        if (err != 1) {
            return err;
        }

        dbc_lfs_fuse_tostat(&s, &info);
        filler(buf, info.name, &s, 0);
    }
}

int dbc_lfs_fuse_rename(const char *from, const char *to) {
    return dbc_lfs_rename(&lfs, from, to);
}

int dbc_lfs_fuse_unlink(const char *path) {
    return dbc_lfs_remove(&lfs, path);
}

int dbc_lfs_fuse_open(const char *path, struct fuse_file_info *fi) {
    dbc_lfs_file_t *file = malloc(sizeof(dbc_lfs_file_t));
    memset(file, 0, sizeof(dbc_lfs_file_t));

    int flags = 0;
    if ((fi->flags & 3) == O_RDONLY) flags |= DBC_LFS_O_RDONLY;
    if ((fi->flags & 3) == O_WRONLY) flags |= DBC_LFS_O_WRONLY;
    if ((fi->flags & 3) == O_RDWR)   flags |= DBC_LFS_O_RDWR;
    if (fi->flags & O_CREAT)         flags |= DBC_LFS_O_CREAT;
    if (fi->flags & O_EXCL)          flags |= DBC_LFS_O_EXCL;
    if (fi->flags & O_TRUNC)         flags |= DBC_LFS_O_TRUNC;
    if (fi->flags & O_APPEND)        flags |= DBC_LFS_O_APPEND;

    int err = dbc_lfs_file_open(&lfs, file, path, flags);
    if (err) {
        free(file);
        return err;
    }

    fi->fh = (uint64_t)file;
    return 0;
}

int dbc_lfs_fuse_release(const char *path, struct fuse_file_info *fi) {
    dbc_lfs_file_t *file = (dbc_lfs_file_t*)fi->fh;

    int err = dbc_lfs_file_close(&lfs, file);
    free(file);
    return err;
}

int dbc_lfs_fuse_fgetattr(const char *path, struct stat *s,
        struct fuse_file_info *fi) {
    dbc_lfs_file_t *file = (dbc_lfs_file_t*)fi->fh;

    dbc_lfs_fuse_tostat(s, &(struct dbc_lfs_info){
        .size = dbc_lfs_file_size(&lfs, file),
        .type = DBC_LFS_TYPE_REG,
    });

    return 0;
}

int dbc_lfs_fuse_read(const char *path, char *buf, size_t size,
        off_t off, struct fuse_file_info *fi) {
    dbc_lfs_file_t *file = (dbc_lfs_file_t*)fi->fh;

    if (dbc_lfs_file_tell(&lfs, file) != off) {
        dbc_lfs_soff_t soff = dbc_lfs_file_seek(&lfs, file, off, DBC_LFS_SEEK_SET);
        if (soff < 0) {
            return soff;
        }
    }

    return dbc_lfs_file_read(&lfs, file, buf, size);
}

int dbc_lfs_fuse_write(const char *path, const char *buf, size_t size,
        off_t off, struct fuse_file_info *fi) {
    dbc_lfs_file_t *file = (dbc_lfs_file_t*)fi->fh;

    if (dbc_lfs_file_tell(&lfs, file) != off) {
        dbc_lfs_soff_t soff = dbc_lfs_file_seek(&lfs, file, off, DBC_LFS_SEEK_SET);
        if (soff < 0) {
            return soff;
        }
    }

    return dbc_lfs_file_write(&lfs, file, buf, size);
}

int dbc_lfs_fuse_fsync(const char *path, int isdatasync,
        struct fuse_file_info *fi) {
    dbc_lfs_file_t *file = (dbc_lfs_file_t*)fi->fh;
    return dbc_lfs_file_sync(&lfs, file);
}

int dbc_lfs_fuse_flush(const char *path, struct fuse_file_info *fi) {
    dbc_lfs_file_t *file = (dbc_lfs_file_t*)fi->fh;
    return dbc_lfs_file_sync(&lfs, file);
}

int dbc_lfs_fuse_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    int err = dbc_lfs_fuse_open(path, fi);
    if (err) {
        return err;
    }

    return dbc_lfs_fuse_fsync(path, 0, fi);
}

int dbc_lfs_fuse_ftruncate(const char *path, off_t size,
        struct fuse_file_info *fi) {
    dbc_lfs_file_t *file = (dbc_lfs_file_t*)fi->fh;
    return dbc_lfs_file_truncate(&lfs, file, size);
}

int dbc_lfs_fuse_truncate(const char *path, off_t size) {
    dbc_lfs_file_t file;
    int err = dbc_lfs_file_open(&lfs, &file, path, DBC_LFS_O_WRONLY);
    if (err) {
        return err;
    }

    err = dbc_lfs_file_truncate(&lfs, &file, size);
    if (err) {
        return err;
    }

    return dbc_lfs_file_close(&lfs, &file);
}

// unsupported functions
int dbc_lfs_fuse_link(const char *from, const char *to) {
    // not supported, fail
    return -EPERM;
}

int dbc_lfs_fuse_mknod(const char *path, mode_t mode, dev_t dev) {
    // not supported, fail
    return -EPERM;
}

int dbc_lfs_fuse_chmod(const char *path, mode_t mode) {
    // not supported, always succeed
    return 0;
}

int dbc_lfs_fuse_chown(const char *path, uid_t uid, gid_t gid) {
    // not supported, fail
    return -EPERM;
}

int dbc_lfs_fuse_utimens(const char *path, const struct timespec ts[2]) {
    // not supported, always succeed
    return 0;
}

static struct fuse_operations dbc_lfs_fuse_ops = {
    .init       = dbc_lfs_fuse_init,
    .destroy    = dbc_lfs_fuse_destroy,
    .statfs     = dbc_lfs_fuse_statfs,

    .getattr    = dbc_lfs_fuse_getattr,
    .access     = dbc_lfs_fuse_access,

    .mkdir      = dbc_lfs_fuse_mkdir,
    .rmdir      = dbc_lfs_fuse_unlink,
    .opendir    = dbc_lfs_fuse_opendir,
    .releasedir = dbc_lfs_fuse_releasedir,
    .readdir    = dbc_lfs_fuse_readdir,

    .rename     = dbc_lfs_fuse_rename,
    .unlink     = dbc_lfs_fuse_unlink,

    .open       = dbc_lfs_fuse_open,
    .create     = dbc_lfs_fuse_create,
    .truncate   = dbc_lfs_fuse_truncate,
    .release    = dbc_lfs_fuse_release,
    .fgetattr   = dbc_lfs_fuse_fgetattr,
    .read       = dbc_lfs_fuse_read,
    .write      = dbc_lfs_fuse_write,
    .fsync      = dbc_lfs_fuse_fsync,
    .flush      = dbc_lfs_fuse_flush,

    .link       = dbc_lfs_fuse_link,
    .symlink    = dbc_lfs_fuse_link,
    .mknod      = dbc_lfs_fuse_mknod,
    .chmod      = dbc_lfs_fuse_chmod,
    .chown      = dbc_lfs_fuse_chown,
    .utimens    = dbc_lfs_fuse_utimens,
};


// binding into fuse and general ui
enum dbc_lfs_fuse_keys {
    KEY_HELP,
    KEY_VERSION,
    KEY_STAT,
    KEY_FORMAT,
    KEY_MIGRATE,
    KEY_DISK_VERSION,
};

#define OPT(t, p) { t, offsetof(struct dbc_lfs_config, p), 0}
static struct fuse_opt dbc_lfs_fuse_opts[] = {
    FUSE_OPT_KEY("--stat",      KEY_STAT),
    FUSE_OPT_KEY("--format",    KEY_FORMAT),
    FUSE_OPT_KEY("--migrate",   KEY_MIGRATE),
    {"-d=",                     -1U, KEY_DISK_VERSION},
    {"--disk_version=",         -1U, KEY_DISK_VERSION},
    OPT("-b=%"                  SCNu32, block_size),
    OPT("--block_size=%"        SCNu32, block_size),
    OPT("--block_count=%"       SCNu32, block_count),
    OPT("--block_cycles=%"      SCNu32, block_cycles),
    OPT("--read_size=%"         SCNu32, read_size),
    OPT("--prog_size=%"         SCNu32, prog_size),
    OPT("--cache_size=%"        SCNu32, cache_size),
    OPT("--lookahead_size=%"    SCNu32, lookahead_size),
    OPT("--name_max=%"          SCNu32, name_max),
    OPT("--file_max=%"          SCNu32, file_max),
    OPT("--attr_max=%"          SCNu32, attr_max),
    FUSE_OPT_KEY("-V",          KEY_VERSION),
    FUSE_OPT_KEY("--version",   KEY_VERSION),
    FUSE_OPT_KEY("-h",          KEY_HELP),
    FUSE_OPT_KEY("--help",      KEY_HELP),
    FUSE_OPT_END
};

static const char help_text[] =
"usage: %s [options] device mountpoint\n"
"\n"
"general options:\n"
"    -o opt,[opt...]        FUSE options\n"
"    -h   --help            print help\n"
"    -V   --version         print version\n"
"\n"
"littlefs options:\n"
"    --stat                 print filesystem info instead of mounting\n"
"    --format               format instead of mounting\n"
"    --migrate              migrate previous version  instead of mounting\n"
"    -d   --disk_version    attempt to use this on-disk version of littlefs\n"
"    -b   --block_size      logical block size, overrides the block device\n"
"    --block_count          block count, overrides the block device\n"
"    --block_cycles         number of erase cycles before eviction (512)\n"
"    --read_size            readable unit (block_size)\n"
"    --prog_size            programmable unit (block_size)\n"
"    --cache_size           size of caches (block_size)\n"
"    --lookahead_size       size of lookahead buffer (8192)\n"
"    --name_max             max size of file names (255)\n"
"    --file_max             max size of file contents (2147483647)\n"
"    --attr_max             max size of custom attributes (1022)\n"
"\n";

int dbc_lfs_fuse_opt_proc(void *data, const char *arg,
        int key, struct fuse_args *args) {

    // option parsing
    switch (key) {
        case FUSE_OPT_KEY_NONOPT:
            if (!device) {
                device = strdup(arg);
                return 0;
            }
            break;

        case KEY_STAT:
            stat_ = true;
            return 0;

        case KEY_FORMAT:
            format = true;
            return 0;

        case KEY_MIGRATE:
            migrate = true;
            return 0;
            
        case KEY_HELP:
            fprintf(stderr, help_text, args->argv[0]);
            fuse_opt_add_arg(args, "-ho");
            fuse_main(args->argc, args->argv, &dbc_lfs_fuse_ops, NULL);
            exit(1);
            
        case KEY_VERSION:
            fprintf(stderr, "littlefs-fuse version: v%d.%d\n",
                DBC_LFS_FUSE_VERSION_MAJOR, DBC_LFS_FUSE_VERSION_MINOR);
            fprintf(stderr, "littlefs version: v%d.%d\n",
                DBC_LFS_VERSION_MAJOR, DBC_LFS_VERSION_MINOR);
            fprintf(stderr, "littlefs disk version: lfs%d.%d\n",
                DBC_LFS_DISK_VERSION_MAJOR, DBC_LFS_DISK_VERSION_MINOR);
            fuse_opt_add_arg(args, "--version");
            fuse_main(args->argc, args->argv, &dbc_lfs_fuse_ops, NULL);
            exit(0);

        case KEY_DISK_VERSION: {
            // skip opt prefix
            const char *arg_ = strchr(arg, '=');
            if (arg_) {
                arg = arg_ + 1;
            }

            // parse out the requested disk version
            // supported formats:
            // - no-prefix       - 2.1
            // - v-prefix        - v2.1
            // - lfs-prefix      - lfs2.1
            // - littlefs-prefix - littlefs2.1
            const char *orig_arg = arg;
            if (strlen(arg) >= strlen("v")
                    && memcmp(arg, "v", strlen("v")) == 0) {
                arg += strlen("v");
            } else if (strlen(arg) >= strlen("lfs")
                    && memcmp(arg, "lfs", strlen("lfs")) == 0) {
                arg += strlen("lfs");
            } else if (strlen(arg) >= strlen("littlefs")
                    && memcmp(arg, "littlefs", strlen("littlefs")) == 0) {
                arg += strlen("littlefs");
            }

            char *parsed;
            uintmax_t major = strtoumax(arg, &parsed, 0);
            if (parsed == arg) {
                goto invalid_version;
            }
            arg = parsed;

            if (arg[0] != '.') {
                goto invalid_version;
            }
            arg += 1;

            uintmax_t minor = strtoumax(arg, &parsed, 0);
            if (parsed == arg) {
                goto invalid_version;
            }
            arg = parsed;

            if (arg[0] != '\0') {
                goto invalid_version;
            }

            if (major > 0xffff || minor > 0xffff) {
                goto invalid_version;
            }

            config.disk_version
                    = ((major & 0xffff) << 16)
                    | ((minor & 0xffff) <<  0);
            return 0;

        invalid_version:
            fprintf(stderr, "invalid disk version: \"%s\"\n", orig_arg);
            exit(1);
        }
    }

    return 1;
}

int main(int argc, char *argv[]) {
    // parse custom options
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    fuse_opt_parse(&args, &config, dbc_lfs_fuse_opts, dbc_lfs_fuse_opt_proc);
    if (!device) {
        fprintf(stderr, "missing device parameter\n");
        exit(1);
    }

    if (stat_) {
        // stat time, no mount
        int err = dbc_lfs_fuse_stat();
        if (err) {
            DBC_LFS_ERROR("%s", strerror(-err));
            exit(-err);
        }
        exit(0);
    }

    if (format) {
        // format time, no mount
        int err = dbc_lfs_fuse_format();
        if (err) {
            DBC_LFS_ERROR("%s", strerror(-err));
            exit(-err);
        }
        exit(0);
    }

    if (migrate) {
        // migrate time, no mount
        int err = dbc_lfs_fuse_migrate();
        if (err) {
            DBC_LFS_ERROR("%s", strerror(-err));
            exit(-err);
        }
        exit(0);
    }

    // go ahead and mount so errors are reported before backgrounding
    int err = dbc_lfs_fuse_mount();
    if (err) {
        DBC_LFS_ERROR("%s", strerror(-err));
        exit(-err);
    }

    // always single-threaded
    fuse_opt_add_arg(&args, "-s");

    // enter fuse
    err = fuse_main(args.argc, args.argv, &dbc_lfs_fuse_ops, NULL);
    if (err) {
        dbc_lfs_fuse_destroy(NULL);
    }

    return err;
}
