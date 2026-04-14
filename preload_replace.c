/*
 * preload_replace.c — GLIBC LD_PRELOAD path-rewriting shim
 *
 * Intercepts ~60 libc/POSIX functions and transparently rewrites
 * filesystem paths that reference the old package directory to the
 * current package directory.  Loaded via LD_PRELOAD inside the GLIBC
 * imagefs layer of the Wine-on-Android stack.
 *
 * Build (cross-compile for aarch64 GLIBC):
 *   aarch64-linux-gnu-gcc -shared -fPIC -O2 \
 *       -DOLD_SUB='"com.winlator"' \
 *       -DNEW_SUB='"app.gnlime"'   \
 *       -DOLD_SUB_LONG='"com.winlator/files/rootfs"' \
 *       -DNEW_SUB_LONG='"app.gnlime/files/imagefs"'  \
 *       -DGOLDBERG_PRELOAD='"LD_PRELOAD=/data/data/app.gnlime/files/imagefs/libpluviagoldberg.so"' \
 *       -DTMP_REDIRECT='"   /data/data/app.gnlime/files/imagefs/usr/tmp"' \
 *       -DPRELOAD_MARKER='" /data/data/app.gnlime/files/imagefs/preload_loaded.txt"' \
 *       -o libredirect.so preload_replace.c -ldl
 *
 * The four substitution strings are the compile-time identity of the
 * fork.  Everything else is package-agnostic.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>

/* Use the 64-bit FTS types that match fts64_open's actual signature */
typedef FTS64   fts_t;
typedef FTSENT64 ftsent_t;
#include <netinet/in.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/un.h>
#include <unistd.h>

/* Needed for openat2 / statx if available */
#ifdef __has_include
#  if __has_include(<linux/openat2.h>)
#    include <linux/openat2.h>
#  endif
#endif
#include <sys/syscall.h>
#include <linux/stat.h>   /* struct statx */

/* ------------------------------------------------------------------ */
/*  Compile-time substitution strings                                 */
/* ------------------------------------------------------------------ */

#ifndef OLD_SUB
#define OLD_SUB "com.winlator"
#endif
#ifndef NEW_SUB
#define NEW_SUB "app.gnlime"
#endif
#ifndef OLD_SUB_LONG
#define OLD_SUB_LONG "com.winlator/files/rootfs"
#endif
#ifndef NEW_SUB_LONG
#define NEW_SUB_LONG "app.gnlime/files/imagefs"
#endif

#ifndef GOLDBERG_PRELOAD
#define GOLDBERG_PRELOAD "LD_PRELOAD=/data/data/" NEW_SUB "/files/imagefs/libpluviagoldberg.so"
#endif
#ifndef TMP_REDIRECT
#define TMP_REDIRECT "/data/data/" NEW_SUB "/files/imagefs/usr/tmp"
#endif
#ifndef PRELOAD_MARKER
#define PRELOAD_MARKER "/data/data/" NEW_SUB "/files/imagefs/preload_loaded.txt"
#endif

static const char *old_sub      = OLD_SUB;
static const char *new_sub      = NEW_SUB;
static const char *old_sub_long = OLD_SUB_LONG;
static const char *new_sub_long = NEW_SUB_LONG;

/* ------------------------------------------------------------------ */
/*  Debug logging                                                     */
/* ------------------------------------------------------------------ */

#if 0 /* Enable for debugging — writes to stderr via fprintf */
static void debug_log(const char *fmt, ...)
{
    FILE *err = stderr;
    if (!err) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(err, fmt, ap);
    va_end(ap);
}
#define DBG(...) debug_log(__VA_ARGS__)
#else
#define DBG(...) ((void)0)
#endif

/* ------------------------------------------------------------------ */
/*  Core path rewriter                                                */
/* ------------------------------------------------------------------ */

/*
 * Try the long substitution first (e.g. "com.winlator/files/rootfs" →
 * "app.gnlime/files/imagefs"), then fall back to the short one
 * ("com.winlator" → "app.gnlime").
 *
 * Returns a malloc'd string if a substitution was made, or NULL if
 * the path doesn't contain either substring.  Caller must free().
 */
static char *replace_substring(const char *path)
{
    if (!path)
        return NULL;

    const char *old_s;
    const char *new_s;
    const char *match;

    /* Try long form first */
    match = strstr(path, old_sub_long);
    if (match) {
        old_s = old_sub_long;
        new_s = new_sub_long;
    } else {
        match = strstr(path, old_sub);
        if (match) {
            old_s = old_sub;
            new_s = new_sub;
        } else {
            return NULL;
        }
    }

    size_t old_len  = strlen(old_s);
    size_t new_len  = strlen(new_s);
    size_t path_len = strlen(path);
    size_t out_len  = path_len - old_len + new_len;

    char *out = malloc(out_len + 1);
    if (!out) return NULL;

    size_t prefix = (size_t)(match - path);
    memcpy(out, path, prefix);
    memcpy(out + prefix, new_s, new_len);
    memcpy(out + prefix + new_len, match + old_len,
           path_len - prefix - old_len + 1);

    return out;
}

/* ------------------------------------------------------------------ */
/*  Macro helpers for dlsym resolution                                */
/* ------------------------------------------------------------------ */

#define ORIG(type, name)  static type (*orig_##name)
#define RESOLVE(name)                                              \
    do {                                                           \
        if (__builtin_expect(!orig_##name, 0)) {                   \
            orig_##name = dlsym(RTLD_NEXT, #name);                 \
            if (!orig_##name) {                                    \
                DBG("[wrapper] dlsym(%s) failed: %s\n",            \
                    #name, dlerror());                              \
            }                                                      \
        }                                                          \
    } while (0)

/* ------------------------------------------------------------------ */
/*  Saved function pointers                                           */
/* ------------------------------------------------------------------ */

/* File open / create */
ORIG(int,     open)(const char *, int, ...);
ORIG(int,     open64)(const char *, int, ...);
ORIG(FILE *,  fopen)(const char *, const char *);
ORIG(FILE *,  fopen64)(const char *, const char *);
ORIG(FILE *,  fdopen)(int, const char *);
ORIG(FILE *,  fopencookie)(void *, const char *, cookie_io_functions_t);
ORIG(FILE *,  popen)(const char *, const char *);
ORIG(int,     openat)(int, const char *, int, ...);
ORIG(int,     openat64)(int, const char *, int, ...);
ORIG(int,     __open64_2)(const char *, int);

/* Directory */
ORIG(DIR *,   opendir)(const char *);
ORIG(struct dirent *, readdir)(DIR *);
ORIG(DIR *,   fdopendir)(int);
ORIG(fts_t *, fts64_open)(char *const *, int, int (*)(const ftsent_t **, const ftsent_t **));

/* Stat family */
ORIG(int, stat)(const char *, struct stat *);
ORIG(int, lstat)(const char *, struct stat *);
ORIG(int, fstat)(int, struct stat *);
ORIG(int, fstatat)(int, const char *, struct stat *, int);
ORIG(int, fstatfs)(int, struct statfs *);
ORIG(int, __xstat)(int, const char *, struct stat *);
ORIG(int, __lxstat)(int, const char *, struct stat *);
ORIG(int, __lxstat64)(int, const char *, struct stat64 *);
ORIG(int, __xstat64)(int, const char *, struct stat64 *);
ORIG(int, __fxstatat)(int, int, const char *, struct stat *, int);
ORIG(int, __fxstatat64)(int, int, const char *, struct stat64 *, int);
ORIG(int, stat64)(const char *, struct stat64 *);
ORIG(int, lstat64)(const char *, struct stat64 *);
ORIG(int, fstat64)(int, struct stat64 *);
ORIG(int, fstatat64)(int, const char *, struct stat64 *, int);
ORIG(int, _IO_file_stat)(FILE *, struct stat *);

/* stat-like: my_* wrappers (Wine internal) */
ORIG(int, my_stat)(const char *, struct stat *);
ORIG(int, my_lstat)(const char *, struct stat *);
ORIG(int, my_fstat)(int, struct stat *);
ORIG(int, my_fstatat)(int, const char *, struct stat *, int);

/* Filesystem ops */
ORIG(int,    access)(const char *, int);
ORIG(int,    unlink)(const char *);
ORIG(int,    rename)(const char *, const char *);
ORIG(int,    chdir)(const char *);
ORIG(int,    mkdir)(const char *, mode_t);
ORIG(int,    rmdir)(const char *);
ORIG(int,    symlink)(const char *, const char *);
ORIG(char *, getcwd)(char *, size_t);
ORIG(char *, realpath)(const char *, char *);

/* Shared memory */
ORIG(int, shm_open)(const char *, int, mode_t);
ORIG(int, shm_unlink)(const char *);

/* Process execution */
ORIG(int, execve)(const char *, char *const[], char *const[]);
ORIG(int, execv)(const char *, char *const[]);
ORIG(int, execvp)(const char *, char *const[]);
ORIG(int, posix_spawn)(pid_t *, const char *, const void *, const void *, char *const[], char *const[]);
ORIG(int, posix_spawnp)(pid_t *, const char *, const void *, const void *, char *const[], char *const[]);

/* I/O */
ORIG(int,     vasprintf)(char **, const char *, va_list);
ORIG(ssize_t, write)(int, const void *, size_t);

/* statx / openat2 */
ORIG(int, statx)(int, const char *__restrict, int, unsigned int, struct statx *__restrict);
ORIG(int, openat2)(int, const char *, void *, size_t);

/* dlopen / XOpenDisplay / connect */
static void *(*real_dlopen)(const char *, int);
static void *(*real_XOpenDisplay)(const char *);
static int   (*real_connect)(int, const struct sockaddr *, socklen_t);

/* File open (used in fopen constructor) */
ORIG(FILE *, fopen_ctor)(const char *, const char *);

/* my_open / my_fopen / my_dlopen (Wine internals) */
ORIG(int,    my_open)(const char *, int, ...);
ORIG(FILE *, my_fopen)(const char *, const char *);
ORIG(void *, my_dlopen)(const char *, int);
ORIG(void *, my_XOpenDisplay)(const char *);

/* ------------------------------------------------------------------ */
/*  Goldberg / LD_PRELOAD injection for exec*                         */
/* ------------------------------------------------------------------ */

/*
 * Three copies of the preload string in the data segment, matching
 * the original binary layout.  Used by execve/posix_spawn wrappers
 * to inject LD_PRELOAD into child processes.
 */
static const char preload_env_1[] = GOLDBERG_PRELOAD;
static const char preload_env_2[] = GOLDBERG_PRELOAD;
static const char preload_env_3[] = GOLDBERG_PRELOAD;

/* ------------------------------------------------------------------ */
/*  Constructor: create marker file on first load                     */
/* ------------------------------------------------------------------ */

__attribute__((constructor))
static void pluviagoldberg_on_load(void)
{
    /* Resolve fopen early for marker file creation */
    if (!orig_fopen_ctor)
        orig_fopen_ctor = dlsym(RTLD_NEXT, "fopen");

    if (orig_fopen_ctor) {
        FILE *f = orig_fopen_ctor(PRELOAD_MARKER, "w");
        if (f) {
            fclose(f);
            DBG("[INIT] libpluviagoldberg.so loaded\n");
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Path-rewriting wrappers                                           */
/* ------------------------------------------------------------------ */

/* ---------- open family ---------- */

int open(const char *pathname, int flags, ...)
{
    RESOLVE(open);
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap; va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int); va_end(ap);
    }
    char *rw = replace_substring(pathname);
    if (rw) { DBG("open: %s -> %s\n", pathname, rw); }
    int fd = orig_open(rw ? rw : pathname, flags, mode);
    free(rw);
    return fd;
}

int open64(const char *pathname, int flags, ...)
{
    RESOLVE(open64);
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap; va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int); va_end(ap);
    }
    char *rw = replace_substring(pathname);
    if (rw) { DBG("open64: %s -> %s\n", pathname, rw); }
    int fd = orig_open64(rw ? rw : pathname, flags, mode);
    free(rw);
    return fd;
}

int __open64_2(const char *pathname, int flags)
{
    RESOLVE(__open64_2);
    char *rw = replace_substring(pathname);
    int fd = orig___open64_2(rw ? rw : pathname, flags);
    free(rw);
    return fd;
}

FILE *fopen(const char *pathname, const char *mode)
{
    RESOLVE(fopen);
    char *rw = replace_substring(pathname);
    if (rw) { DBG("fopen: %s -> %s\n", pathname, rw); }
    FILE *f = orig_fopen(rw ? rw : pathname, mode);
    free(rw);
    return f;
}

FILE *fopen64(const char *pathname, const char *mode)
{
    RESOLVE(fopen64);
    char *rw = replace_substring(pathname);
    FILE *f = orig_fopen64(rw ? rw : pathname, mode);
    free(rw);
    return f;
}

FILE *fdopen(int fd, const char *mode)
{
    RESOLVE(fdopen);
    return orig_fdopen(fd, mode);
}

FILE *fopencookie(void *cookie, const char *mode, cookie_io_functions_t funcs)
{
    RESOLVE(fopencookie);
    return orig_fopencookie(cookie, mode, funcs);
}

FILE *popen(const char *command, const char *type)
{
    RESOLVE(popen);
    char *rw = replace_substring(command);
    FILE *f = orig_popen(rw ? rw : command, type);
    free(rw);
    return f;
}

/* ---------- openat family ---------- */

int openat(int dirfd, const char *pathname, int flags, ...)
{
    RESOLVE(openat);
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap; va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int); va_end(ap);
    }
    char *rw = replace_substring(pathname);
    int fd = orig_openat(dirfd, rw ? rw : pathname, flags, mode);
    free(rw);
    return fd;
}

int openat64(int dirfd, const char *pathname, int flags, ...)
{
    RESOLVE(openat64);
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap; va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int); va_end(ap);
    }
    char *rw = replace_substring(pathname);
    int fd = orig_openat64(dirfd, rw ? rw : pathname, flags, mode);
    free(rw);
    return fd;
}

int openat2(int dirfd, const char *pathname, void *how, size_t size)
{
    RESOLVE(openat2);
    char *rw = replace_substring(pathname);
    int fd = orig_openat2(dirfd, rw ? rw : pathname, how, size);
    free(rw);
    return fd;
}

/* ---------- directory ops ---------- */

DIR *opendir(const char *name)
{
    RESOLVE(opendir);
    char *rw = replace_substring(name);
    DIR *d = orig_opendir(rw ? rw : name);
    free(rw);
    return d;
}

struct dirent *readdir(DIR *dirp)
{
    RESOLVE(readdir);
    return orig_readdir(dirp);
}

DIR *fdopendir(int fd)
{
    RESOLVE(fdopendir);
    return orig_fdopendir(fd);
}

fts_t *fts64_open(char *const *path_argv, int options,
                  int (*compar)(const ftsent_t **, const ftsent_t **))
{
    RESOLVE(fts64_open);
    /* Rewrite all paths in the argv array */
    int count = 0;
    while (path_argv[count]) count++;

    char **new_argv = malloc(sizeof(char *) * (count + 1));
    if (!new_argv)
        return orig_fts64_open(path_argv, options, compar);

    for (int i = 0; i < count; i++) {
        char *rw = replace_substring(path_argv[i]);
        new_argv[i] = rw ? rw : strdup(path_argv[i]);
    }
    new_argv[count] = NULL;

    fts_t *result = orig_fts64_open(new_argv, options, compar);

    for (int i = 0; i < count; i++)
        free(new_argv[i]);
    free(new_argv);

    return result;
}

/* ---------- stat family ---------- */

int stat(const char *pathname, struct stat *statbuf)
{
    RESOLVE(stat);
    char *rw = replace_substring(pathname);
    int ret = orig_stat(rw ? rw : pathname, statbuf);
    free(rw);
    return ret;
}

int lstat(const char *pathname, struct stat *statbuf)
{
    RESOLVE(lstat);
    char *rw = replace_substring(pathname);
    int ret = orig_lstat(rw ? rw : pathname, statbuf);
    free(rw);
    return ret;
}

int fstat(int fd, struct stat *statbuf)
{
    RESOLVE(fstat);
    return orig_fstat(fd, statbuf);
}

int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags)
{
    RESOLVE(fstatat);
    char *rw = replace_substring(pathname);
    int ret = orig_fstatat(dirfd, rw ? rw : pathname, statbuf, flags);
    free(rw);
    return ret;
}

int fstatfs(int fd, struct statfs *buf)
{
    RESOLVE(fstatfs);
    return orig_fstatfs(fd, buf);
}

int __xstat(int ver, const char *pathname, struct stat *statbuf)
{
    RESOLVE(__xstat);
    char *rw = replace_substring(pathname);
    int ret = orig___xstat(ver, rw ? rw : pathname, statbuf);
    free(rw);
    return ret;
}

int __lxstat(int ver, const char *pathname, struct stat *statbuf)
{
    RESOLVE(__lxstat);
    char *rw = replace_substring(pathname);
    int ret = orig___lxstat(ver, rw ? rw : pathname, statbuf);
    free(rw);
    return ret;
}

int __lxstat64(int ver, const char *pathname, struct stat64 *statbuf)
{
    RESOLVE(__lxstat64);
    char *rw = replace_substring(pathname);
    int ret = orig___lxstat64(ver, rw ? rw : pathname, statbuf);
    free(rw);
    return ret;
}

int __xstat64(int ver, const char *pathname, struct stat64 *statbuf)
{
    RESOLVE(__xstat64);
    char *rw = replace_substring(pathname);
    int ret = orig___xstat64(ver, rw ? rw : pathname, statbuf);
    free(rw);
    return ret;
}

int __fxstatat(int ver, int dirfd, const char *pathname, struct stat *statbuf, int flags)
{
    RESOLVE(__fxstatat);
    char *rw = replace_substring(pathname);
    int ret = orig___fxstatat(ver, dirfd, rw ? rw : pathname, statbuf, flags);
    free(rw);
    return ret;
}

int __fxstatat64(int ver, int dirfd, const char *pathname, struct stat64 *statbuf, int flags)
{
    RESOLVE(__fxstatat64);
    char *rw = replace_substring(pathname);
    int ret = orig___fxstatat64(ver, dirfd, rw ? rw : pathname, statbuf, flags);
    free(rw);
    return ret;
}

int stat64(const char *pathname, struct stat64 *statbuf)
{
    RESOLVE(stat64);
    char *rw = replace_substring(pathname);
    int ret = orig_stat64(rw ? rw : pathname, statbuf);
    free(rw);
    return ret;
}

int lstat64(const char *pathname, struct stat64 *statbuf)
{
    RESOLVE(lstat64);
    char *rw = replace_substring(pathname);
    int ret = orig_lstat64(rw ? rw : pathname, statbuf);
    free(rw);
    return ret;
}

int fstat64(int fd, struct stat64 *statbuf)
{
    RESOLVE(fstat64);
    return orig_fstat64(fd, statbuf);
}

int fstatat64(int dirfd, const char *pathname, struct stat64 *statbuf, int flags)
{
    RESOLVE(fstatat64);
    char *rw = replace_substring(pathname);
    int ret = orig_fstatat64(dirfd, rw ? rw : pathname, statbuf, flags);
    free(rw);
    return ret;
}

int _IO_file_stat(FILE *fp, struct stat *statbuf)
{
    RESOLVE(_IO_file_stat);
    return orig__IO_file_stat(fp, statbuf);
}

int statx(int dirfd, const char *__restrict pathname, int flags,
          unsigned int mask, struct statx *__restrict statxbuf)
{
    RESOLVE(statx);
    char *rw = replace_substring(pathname);
    int ret = orig_statx(dirfd, rw ? rw : pathname, flags, mask, statxbuf);
    free(rw);
    return ret;
}

/* ---------- Wine internal my_* stat wrappers ---------- */

int my_stat(const char *pathname, struct stat *statbuf)
{
    RESOLVE(my_stat);
    char *rw = replace_substring(pathname);
    int ret = orig_my_stat(rw ? rw : pathname, statbuf);
    free(rw);
    return ret;
}

int my_lstat(const char *pathname, struct stat *statbuf)
{
    RESOLVE(my_lstat);
    char *rw = replace_substring(pathname);
    int ret = orig_my_lstat(rw ? rw : pathname, statbuf);
    free(rw);
    return ret;
}

int my_fstat(int fd, struct stat *statbuf)
{
    RESOLVE(my_fstat);
    return orig_my_fstat(fd, statbuf);
}

int my_fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags)
{
    RESOLVE(my_fstatat);
    char *rw = replace_substring(pathname);
    int ret = orig_my_fstatat(dirfd, rw ? rw : pathname, statbuf, flags);
    free(rw);
    return ret;
}

/* ---------- filesystem ops ---------- */

int access(const char *pathname, int mode)
{
    RESOLVE(access);
    char *rw = replace_substring(pathname);
    int ret = orig_access(rw ? rw : pathname, mode);
    free(rw);
    return ret;
}

int unlink(const char *pathname)
{
    RESOLVE(unlink);
    char *rw = replace_substring(pathname);
    int ret = orig_unlink(rw ? rw : pathname);
    free(rw);
    return ret;
}

int rename(const char *oldpath, const char *newpath)
{
    RESOLVE(rename);
    char *rw_old = replace_substring(oldpath);
    char *rw_new = replace_substring(newpath);
    int ret = orig_rename(rw_old ? rw_old : oldpath, rw_new ? rw_new : newpath);
    free(rw_old);
    free(rw_new);
    return ret;
}

int chdir(const char *path)
{
    RESOLVE(chdir);
    char *rw = replace_substring(path);
    int ret = orig_chdir(rw ? rw : path);
    free(rw);
    return ret;
}

int mkdir(const char *pathname, mode_t mode)
{
    RESOLVE(mkdir);
    char *rw = replace_substring(pathname);
    int ret = orig_mkdir(rw ? rw : pathname, mode);
    free(rw);
    return ret;
}

int rmdir(const char *pathname)
{
    RESOLVE(rmdir);
    char *rw = replace_substring(pathname);
    int ret = orig_rmdir(rw ? rw : pathname);
    free(rw);
    return ret;
}

int symlink(const char *target, const char *linkpath)
{
    RESOLVE(symlink);
    char *rw_target = replace_substring(target);
    char *rw_link   = replace_substring(linkpath);
    int ret = orig_symlink(rw_target ? rw_target : target,
                           rw_link ? rw_link : linkpath);
    free(rw_target);
    free(rw_link);
    return ret;
}

char *getcwd(char *buf, size_t size)
{
    RESOLVE(getcwd);
    return orig_getcwd(buf, size);
}

char *realpath(const char *path, char *resolved_path)
{
    RESOLVE(realpath);
    char *rw = replace_substring(path);
    char *ret = orig_realpath(rw ? rw : path, resolved_path);
    free(rw);
    return ret;
}

/* ---------- shared memory ---------- */

int shm_open(const char *name, int oflag, mode_t mode)
{
    RESOLVE(shm_open);
    /* shm names often contain /wine — rewrite if they have old_sub */
    char *rw = replace_substring(name);
    int fd = orig_shm_open(rw ? rw : name, oflag, mode);
    free(rw);
    return fd;
}

int shm_unlink(const char *name)
{
    RESOLVE(shm_unlink);
    char *rw = replace_substring(name);
    int ret = orig_shm_unlink(rw ? rw : name);
    free(rw);
    return ret;
}

/* ---------- process execution ---------- */

/*
 * For exec* and posix_spawn*, we rewrite the executable path and
 * any argv/envp strings that contain old_sub.  We also ensure
 * LD_PRELOAD is set in the child environment for the Goldberg
 * Steam emulation layer.
 */

/* Helper: rewrite an array of strings (argv or envp) */
static char **rewrite_string_array(char *const orig[])
{
    if (!orig) return NULL;
    int count = 0;
    while (orig[count]) count++;

    char **new_arr = malloc(sizeof(char *) * (count + 1));
    if (!new_arr) return NULL;

    for (int i = 0; i < count; i++) {
        char *rw = replace_substring(orig[i]);
        new_arr[i] = rw ? rw : strdup(orig[i]);
    }
    new_arr[count] = NULL;
    return new_arr;
}

static void free_string_array(char **arr)
{
    if (!arr) return;
    for (int i = 0; arr[i]; i++)
        free(arr[i]);
    free(arr);
}

int execve(const char *pathname, char *const argv[], char *const envp[])
{
    RESOLVE(execve);
    char *rw_path = replace_substring(pathname);
    char **rw_argv = rewrite_string_array(argv);
    char **rw_envp = rewrite_string_array(envp);

    int ret = orig_execve(rw_path ? rw_path : pathname,
                          rw_argv ? rw_argv : argv,
                          rw_envp ? rw_envp : envp);
    free(rw_path);
    free_string_array(rw_argv);
    free_string_array(rw_envp);
    return ret;
}

int execv(const char *pathname, char *const argv[])
{
    RESOLVE(execv);
    char *rw_path = replace_substring(pathname);
    char **rw_argv = rewrite_string_array(argv);
    int ret = orig_execv(rw_path ? rw_path : pathname,
                         rw_argv ? rw_argv : argv);
    free(rw_path);
    free_string_array(rw_argv);
    return ret;
}

int execvp(const char *file, char *const argv[])
{
    RESOLVE(execvp);
    char *rw_file = replace_substring(file);
    char **rw_argv = rewrite_string_array(argv);
    int ret = orig_execvp(rw_file ? rw_file : file,
                          rw_argv ? rw_argv : argv);
    free(rw_file);
    free_string_array(rw_argv);
    return ret;
}

int posix_spawn(pid_t *pid, const char *path,
                const void *file_actions, const void *attrp,
                char *const argv[], char *const envp[])
{
    RESOLVE(posix_spawn);
    char *rw_path = replace_substring(path);
    char **rw_argv = rewrite_string_array(argv);
    char **rw_envp = rewrite_string_array(envp);
    int ret = orig_posix_spawn(pid, rw_path ? rw_path : path,
                               file_actions, attrp,
                               rw_argv ? rw_argv : argv,
                               rw_envp ? rw_envp : envp);
    free(rw_path);
    free_string_array(rw_argv);
    free_string_array(rw_envp);
    return ret;
}

int posix_spawnp(pid_t *pid, const char *file,
                 const void *file_actions, const void *attrp,
                 char *const argv[], char *const envp[])
{
    RESOLVE(posix_spawnp);
    char *rw_file = replace_substring(file);
    char **rw_argv = rewrite_string_array(argv);
    char **rw_envp = rewrite_string_array(envp);
    int ret = orig_posix_spawnp(pid, rw_file ? rw_file : file,
                                file_actions, attrp,
                                rw_argv ? rw_argv : argv,
                                rw_envp ? rw_envp : envp);
    free(rw_file);
    free_string_array(rw_argv);
    free_string_array(rw_envp);
    return ret;
}

/* ---------- I/O ---------- */

int vasprintf(char **strp, const char *fmt, va_list ap)
{
    RESOLVE(vasprintf);
    int ret = orig_vasprintf(strp, fmt, ap);
    if (ret >= 0 && *strp) {
        char *rw = replace_substring(*strp);
        if (rw) {
            free(*strp);
            *strp = rw;
            ret = (int)strlen(rw);
        }
    }
    return ret;
}

int asprintf(char **strp, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int ret = vasprintf(strp, fmt, ap);
    va_end(ap);
    return ret;
}

ssize_t write(int fd, const void *buf, size_t count)
{
    RESOLVE(write);
    return orig_write(fd, buf, count);
}

/* ---------- dlopen ---------- */

void *dlopen(const char *filename, int flags)
{
    if (!real_dlopen)
        real_dlopen = dlsym(RTLD_NEXT, "dlopen");

    if (filename) {
        char *rw = replace_substring(filename);
        if (rw) {
            DBG("[wrapper] dlopen(\"%s\") \n", rw);
            void *h = real_dlopen(rw, flags);
            free(rw);
            return h;
        }
    }
    return real_dlopen(filename, flags);
}

/* ---------- connect (Unix socket path rewriting) ---------- */

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (!real_connect)
        real_connect = dlsym(RTLD_NEXT, "connect");

    if (addr && addr->sa_family == AF_UNIX) {
        struct sockaddr_un *un = (struct sockaddr_un *)addr;
        char *rw = replace_substring(un->sun_path);
        if (rw) {
            struct sockaddr_un new_un;
            memset(&new_un, 0, sizeof(new_un));
            new_un.sun_family = AF_UNIX;
            strncpy(new_un.sun_path, rw, sizeof(new_un.sun_path) - 1);
            free(rw);
            return real_connect(sockfd, (struct sockaddr *)&new_un, sizeof(new_un));
        }
    }
    return real_connect(sockfd, addr, addrlen);
}

/* ---------- XOpenDisplay ---------- */

void *XOpenDisplay(const char *display_name)
{
    if (!real_XOpenDisplay) {
        real_XOpenDisplay = dlsym(RTLD_NEXT, "XOpenDisplay");
        if (!real_XOpenDisplay) {
            DBG("[wrapper] ERROR dlsym(XOpenDisplay): %s\n", dlerror());
            return NULL;
        }
    }

    DBG("[wrapper] XOpenDisplay(\"%s\")  getenv(DISPLAY)=\"%s\"  \n",
        display_name ? display_name : "NULL",
        getenv("DISPLAY") ? getenv("DISPLAY") : "(null)");

    return real_XOpenDisplay(display_name);
}

/* ---------- Wine internal wrappers ---------- */

int my_open(const char *pathname, int flags, ...)
{
    RESOLVE(my_open);
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap; va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int); va_end(ap);
    }
    char *rw = replace_substring(pathname);
    int fd = orig_my_open(rw ? rw : pathname, flags, mode);
    free(rw);
    return fd;
}

FILE *my_fopen(const char *pathname, const char *mode)
{
    RESOLVE(my_fopen);
    char *rw = replace_substring(pathname);
    FILE *f = orig_my_fopen(rw ? rw : pathname, mode);
    free(rw);
    return f;
}

void *my_dlopen(const char *filename, int flags)
{
    RESOLVE(my_dlopen);
    if (filename) {
        char *rw = replace_substring(filename);
        if (rw) {
            void *h = orig_my_dlopen(rw, flags);
            free(rw);
            return h;
        }
    }
    return orig_my_dlopen(filename, flags);
}

void *my_XOpenDisplay(const char *display_name)
{
    RESOLVE(my_XOpenDisplay);
    return orig_my_XOpenDisplay(display_name);
}
