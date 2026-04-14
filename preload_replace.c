/*
 * preload_replace.c — GLIBC LD_PRELOAD path-rewriting shim
 *
 * Intercepts ~62 libc/POSIX functions and transparently rewrites
 * filesystem paths that reference the old package directory to the
 * current package directory.  Loaded via LD_PRELOAD inside the GLIBC
 * imagefs layer of the Wine-on-Android stack.
 *
 * Build (cross-compile for aarch64 GLIBC):
 *   aarch64-linux-gnu-gcc -shared -fPIC -O2 -Wall \
 *       -Wno-unused-function -Wno-unused-const-variable \
 *       -DOLD_SUB='"com.winlator"' \
 *       -DNEW_SUB='"app.gnlime"' \
 *       -DOLD_SUB_LONG='"com.winlator/files/rootfs"' \
 *       -DNEW_SUB_LONG='"app.gnlime/files/imagefs"' \
 *       -DGOLDBERG_PRELOAD='"LD_PRELOAD=/data/data/app.gnlime/files/imagefs/libpluviagoldberg.so"' \
 *       -DTMP_REDIRECT='"/data/data/app.gnlime/files/imagefs/usr/tmp"' \
 *       -DPRELOAD_MARKER='"/data/data/app.gnlime/files/imagefs/preload_loaded.txt"' \
 *       -o libredirect.so preload_replace.c -ldl
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>

typedef FTS64    fts_t;
typedef FTSENT64 ftsent_t;

#include <arpa/inet.h>
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

/* Use volatile to prevent GCC from optimizing away the symbol names */
static const char * volatile old_sub      = OLD_SUB;
static const char * volatile new_sub      = NEW_SUB;
static const char * volatile old_sub_long = OLD_SUB_LONG;
static const char * volatile new_sub_long = NEW_SUB_LONG;

/* Force strcat/ntohs/strcpy through PLT — GCC may inline these otherwise */
static char *(*volatile strcat_fn)(char *, const char *) = strcat;
static char *(*volatile strcpy_fn)(char *, const char *) = strcpy;
static uint16_t (*volatile ntohs_fn)(uint16_t) = ntohs;

/* Force environ/__environ symbols into the binary */
static char ** volatile *environ_ref      = &environ;
static char ** volatile *__environ_ref    = &__environ;

/* dlopen/connect/XOpenDisplay use file-scope pointers ("real_*" not "orig_*")
 * matching the original binary's symbol names */
static void *(*real_dlopen)(const char *, int);
static int   (*real_connect)(int, const struct sockaddr *, socklen_t);
static void *(*real_XOpenDisplay)(const char *);

/* extern environ declarations — used by execv/execvp */
extern char **__environ;
extern char **environ;

/*
 * Force certain symbols into the string table even when the compiler
 * inlines or optimizes away the call.  These volatile pointers ensure
 * the linker sees a relocation and emits the symbol name.
 */


/* ------------------------------------------------------------------ */
/*  Debug logging                                                     */
/* ------------------------------------------------------------------ */

static void debug_log(const char *label, const char *msg)
{
    fprintf(stderr, "[libredirect] %s: %s\n", label, msg);
}

/* ------------------------------------------------------------------ */
/*  Core path rewriter                                                */
/* ------------------------------------------------------------------ */

static char *replace_substring(const char *path)
{
    if (!path)
        return NULL;

    /* /tmp and /tmp/... -> TMP_REDIRECT and TMP_REDIRECT/... */
    if (path[0] == '/' && path[1] == 't' && path[2] == 'm' && path[3] == 'p' &&
        (path[4] == '\0' || path[4] == '/')) {
        const char *suffix = path + 4; /* "" or "/..." */
        size_t redir_len = strlen(TMP_REDIRECT);
        size_t suffix_len = strlen(suffix);
        char *out = malloc(redir_len + suffix_len + 1);
        if (!out) {
            debug_log("replace_substring", "malloc failed");
            return NULL;
        }
        strcpy_fn(out, TMP_REDIRECT);
        strcat_fn(out, suffix);
        return out;
    }

    const char *match;
    const char *old_s;
    const char *new_s;

    /* Try long form first: com.winlator/files/rootfs -> pkg/files/imagefs */
    match = strstr(path, old_sub_long);
    if (match) {
        old_s = old_sub_long;
        new_s = new_sub_long;
    } else {
        /* Short form: com.winlator -> pkg */
        match = strstr(path, old_sub);
        if (!match)
            return NULL;
        old_s = old_sub;
        new_s = new_sub;
    }

    size_t old_len  = strlen(old_s);
    size_t new_len  = strlen(new_s);
    size_t path_len = strlen(path);
    size_t prefix   = (size_t)(match - path);
    size_t out_len  = path_len - old_len + new_len;

    char *out = malloc(out_len + 1);
    if (!out) {
        debug_log("replace_substring", "malloc failed");
        return NULL;
    }

    /* Build result with strcpy/strcat for string table match */
    out[0] = '\0';
    if (prefix > 0) {
        strncpy(out, path, prefix);
        out[prefix] = '\0';
    }
    strcat_fn(out, new_s);
    strcat_fn(out, match + old_len);

    return out;
}

/* ------------------------------------------------------------------ */
/*  Helper: rewrite string arrays (argv / envp)                       */
/* ------------------------------------------------------------------ */

static inline __attribute__((always_inline)) char **rewrite_string_array(char *const orig[])
{
    if (!orig) return NULL;
    int count = 0;
    while (orig[count]) count++;

    char **new_arr = malloc(sizeof(char *) * (count + 1));
    if (!new_arr) return NULL;

    for (int i = 0; i < count; i++) {
        char *rw = replace_substring(orig[i]);
        new_arr[i] = rw ? rw : ({ size_t _l = strlen(orig[i])+1; char *_p = malloc(_l); if(_p) strcpy_fn(_p, orig[i]); _p; });
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

/* ------------------------------------------------------------------ */
/*  Helper: inject LD_PRELOAD into envp                               */
/* ------------------------------------------------------------------ */

static inline __attribute__((always_inline)) char **inject_preload(char *const envp[], const char *preload_str)
{
    if (!envp) return NULL;

    int count = 0;
    int preload_idx = -1;
    while (envp[count]) {
        if (strncmp(envp[count], "LD_PRELOAD=", 11) == 0)
            preload_idx = count;
        count++;
    }

    char **new_envp = malloc(sizeof(char *) * (count + 2));
    if (!new_envp) return NULL;

    for (int i = 0; i < count; i++)
        new_envp[i] = envp[i];

    if (preload_idx >= 0) {
        new_envp[preload_idx] = (char *)preload_str;
        new_envp[count] = NULL;
    } else {
        new_envp[count] = (char *)preload_str;
        new_envp[count + 1] = NULL;
    }

    return new_envp;
}

/* ================================================================== */
/*  HOOKED FUNCTIONS                                                  */
/*  Each uses a function-local static pointer resolved via dlsym.     */
/*  Each references its label and error label as string literals.      */
/* ================================================================== */

/* ---------- open family ---------- */

int open(const char *pathname, int flags, ...)
{
    static int (*orig_open)(const char *, int, ...);
    if (!orig_open) { orig_open = dlsym(RTLD_NEXT, "open"); if (!orig_open) debug_log("open", "open_error"); }
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap; va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int); va_end(ap);
    }
    char *rw = replace_substring(pathname);
    int fd = orig_open(rw ? rw : pathname, flags, mode);
    free(rw);
    return fd;
}

int open64(const char *pathname, int flags, ...)
{
    static int (*orig_open64)(const char *, int, ...);
    if (!orig_open64) { orig_open64 = dlsym(RTLD_NEXT, "open64"); if (!orig_open64) debug_log("open64", "open64_error"); }
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap; va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int); va_end(ap);
    }
    char *rw = replace_substring(pathname);
    int fd = orig_open64(rw ? rw : pathname, flags, mode);
    free(rw);
    return fd;
}

FILE *fopen(const char *pathname, const char *mode)
{
    static FILE *(*orig_fopen)(const char *, const char *);
    if (!orig_fopen) { orig_fopen = dlsym(RTLD_NEXT, "fopen"); if (!orig_fopen) debug_log("fopen", "fopen_error"); }
    char *rw = replace_substring(pathname);
    FILE *f = orig_fopen(rw ? rw : pathname, mode);
    free(rw);
    return f;
}

FILE *fopen64(const char *pathname, const char *mode)
{
    static FILE *(*orig_fopen64)(const char *, const char *);
    if (!orig_fopen64) { orig_fopen64 = dlsym(RTLD_NEXT, "fopen64"); if (!orig_fopen64) debug_log("fopen64", "fopen64_error"); }
    char *rw = replace_substring(pathname);
    FILE *f = orig_fopen64(rw ? rw : pathname, mode);
    free(rw);
    return f;
}

FILE *fdopen(int fd, const char *mode)
{
    static FILE *(*orig_fdopen)(int, const char *);
    if (!orig_fdopen) { orig_fdopen = dlsym(RTLD_NEXT, "fdopen"); if (!orig_fdopen) debug_log("fdopen", "fdopen_error"); }
    return orig_fdopen(fd, mode);
}

FILE *fopencookie(void *cookie, const char *mode, cookie_io_functions_t funcs)
{
    static FILE *(*orig_fopencookie)(void *, const char *, cookie_io_functions_t);
    if (!orig_fopencookie) { orig_fopencookie = dlsym(RTLD_NEXT, "fopencookie"); if (!orig_fopencookie) debug_log("fopencookie", "fopencookie_error"); }
    return orig_fopencookie(cookie, mode, funcs);
}

FILE *popen(const char *command, const char *type)
{
    static FILE *(*orig_popen)(const char *, const char *);
    if (!orig_popen) { orig_popen = dlsym(RTLD_NEXT, "popen"); if (!orig_popen) debug_log("popen", "popen_error"); }
    char *rw = replace_substring(command);
    FILE *f = orig_popen(rw ? rw : command, type);
    free(rw);
    return f;
}

/* ---------- openat family ---------- */

int openat(int dirfd, const char *pathname, int flags, ...)
{
    static int (*orig_openat)(int, const char *, int, ...);
    if (!orig_openat) { orig_openat = dlsym(RTLD_NEXT, "openat"); if (!orig_openat) debug_log("openat", "openat_error"); }
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
    static int (*orig_openat64)(int, const char *, int, ...);
    if (!orig_openat64) { orig_openat64 = dlsym(RTLD_NEXT, "openat64"); if (!orig_openat64) debug_log("openat64", "openat64_error"); }
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
    static int (*orig_openat2)(int, const char *, void *, size_t);
    if (!orig_openat2) { orig_openat2 = dlsym(RTLD_NEXT, "openat2"); if (!orig_openat2) debug_log("openat2", "openat2_error"); }
    char *rw = replace_substring(pathname);
    int fd = orig_openat2(dirfd, rw ? rw : pathname, how, size);
    free(rw);
    return fd;
}

int __open64_2(const char *pathname, int flags)
{
    static int (*orig___open64_2)(const char *, int);
    if (!orig___open64_2) { orig___open64_2 = dlsym(RTLD_NEXT, "__open64_2"); }
    char *rw = replace_substring(pathname);
    int fd = orig___open64_2(rw ? rw : pathname, flags);
    free(rw);
    return fd;
}

/* ---------- directory ops ---------- */

DIR *opendir(const char *name)
{
    static DIR *(*orig_opendir)(const char *);
    if (!orig_opendir) { orig_opendir = dlsym(RTLD_NEXT, "opendir"); if (!orig_opendir) debug_log("opendir", "opendir_error"); }
    char *rw = replace_substring(name);
    DIR *d = orig_opendir(rw ? rw : name);
    free(rw);
    return d;
}

struct dirent *readdir(DIR *dirp)
{
    static struct dirent *(*orig_readdir)(DIR *);
    if (!orig_readdir) { orig_readdir = dlsym(RTLD_NEXT, "readdir"); }
    return orig_readdir(dirp);
}

DIR *fdopendir(int fd)
{
    static DIR *(*orig_fdopendir)(int);
    if (!orig_fdopendir) { orig_fdopendir = dlsym(RTLD_NEXT, "fdopendir"); if (!orig_fdopendir) debug_log("fdopendir", "fdopendir_error"); }
    return orig_fdopendir(fd);
}

fts_t *fts64_open(char *const *path_argv, int options,
                  int (*compar)(const ftsent_t **, const ftsent_t **))
{
    static fts_t *(*orig_fts64_open)(char *const *, int, int (*)(const ftsent_t **, const ftsent_t **));
    if (!orig_fts64_open) { orig_fts64_open = dlsym(RTLD_NEXT, "fts64_open"); if (!orig_fts64_open) debug_log("fts64_open", "fts64_open_error"); }

    int count = 0;
    while (path_argv[count]) count++;

    char **new_argv = malloc(sizeof(char *) * (count + 1));
    if (!new_argv)
        return orig_fts64_open(path_argv, options, compar);

    for (int i = 0; i < count; i++) {
        char *rw = replace_substring(path_argv[i]);
        new_argv[i] = rw ? rw : ({ size_t _l = strlen(path_argv[i])+1; char *_p = malloc(_l); if(_p) strcpy_fn(_p, path_argv[i]); _p; });
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
    static int (*orig_stat)(const char *, struct stat *);
    if (!orig_stat) { orig_stat = dlsym(RTLD_NEXT, "stat"); if (!orig_stat) debug_log("stat", "stat_error"); }
    char *rw = replace_substring(pathname);
    int ret = orig_stat(rw ? rw : pathname, statbuf);
    free(rw);
    return ret;
}

int lstat(const char *pathname, struct stat *statbuf)
{
    static int (*orig_lstat)(const char *, struct stat *);
    if (!orig_lstat) { orig_lstat = dlsym(RTLD_NEXT, "lstat"); if (!orig_lstat) debug_log("lstat", "lstat_error"); }
    char *rw = replace_substring(pathname);
    int ret = orig_lstat(rw ? rw : pathname, statbuf);
    free(rw);
    return ret;
}

int fstat(int fd, struct stat *statbuf)
{
    static int (*orig_fstat)(int, struct stat *);
    if (!orig_fstat) { orig_fstat = dlsym(RTLD_NEXT, "fstat"); if (!orig_fstat) debug_log("fstat", "fstat_error"); }
    debug_log("fstat  <fd>", "");
    return orig_fstat(fd, statbuf);
}

int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags)
{
    static int (*orig_fstatat)(int, const char *, struct stat *, int);
    if (!orig_fstatat) { orig_fstatat = dlsym(RTLD_NEXT, "fstatat"); if (!orig_fstatat) debug_log("fstatat", "fstatat_error"); }
    char *rw = replace_substring(pathname);
    int ret = orig_fstatat(dirfd, rw ? rw : pathname, statbuf, flags);
    free(rw);
    return ret;
}

int fstatfs(int fd, struct statfs *buf)
{
    static int (*orig_fstatfs)(int, struct statfs *);
    if (!orig_fstatfs) { orig_fstatfs = dlsym(RTLD_NEXT, "fstatfs"); if (!orig_fstatfs) debug_log("fstatfs", "fstatfs_error"); }
    return orig_fstatfs(fd, buf);
}

int __xstat(int ver, const char *pathname, struct stat *statbuf)
{
    static int (*orig___xstat)(int, const char *, struct stat *);
    if (!orig___xstat) { orig___xstat = dlsym(RTLD_NEXT, "__xstat"); if (!orig___xstat) debug_log("__xstat", "__xstat_error"); }
    char *rw = replace_substring(pathname);
    int ret = orig___xstat(ver, rw ? rw : pathname, statbuf);
    free(rw);
    return ret;
}

int __lxstat(int ver, const char *pathname, struct stat *statbuf)
{
    static int (*orig___lxstat)(int, const char *, struct stat *);
    if (!orig___lxstat) { orig___lxstat = dlsym(RTLD_NEXT, "__lxstat"); if (!orig___lxstat) debug_log("__lxstat", "__lxstat_error"); }
    char *rw = replace_substring(pathname);
    int ret = orig___lxstat(ver, rw ? rw : pathname, statbuf);
    free(rw);
    return ret;
}

int __lxstat64(int ver, const char *pathname, struct stat64 *statbuf)
{
    static int (*orig___lxstat64)(int, const char *, struct stat64 *);
    if (!orig___lxstat64) { orig___lxstat64 = dlsym(RTLD_NEXT, "__lxstat64"); if (!orig___lxstat64) debug_log("__lxstat64", "__lxstat64_error"); }
    char *rw = replace_substring(pathname);
    int ret = orig___lxstat64(ver, rw ? rw : pathname, statbuf);
    free(rw);
    return ret;
}

int __xstat64(int ver, const char *pathname, struct stat64 *statbuf)
{
    static int (*orig___xstat64)(int, const char *, struct stat64 *);
    if (!orig___xstat64) { orig___xstat64 = dlsym(RTLD_NEXT, "__xstat64"); if (!orig___xstat64) debug_log("__xstat64", "__xstat64_error"); }
    char *rw = replace_substring(pathname);
    int ret = orig___xstat64(ver, rw ? rw : pathname, statbuf);
    free(rw);
    return ret;
}

int __fxstatat(int ver, int dirfd, const char *pathname, struct stat *statbuf, int flags)
{
    static int (*orig___fxstatat)(int, int, const char *, struct stat *, int);
    if (!orig___fxstatat) { orig___fxstatat = dlsym(RTLD_NEXT, "__fxstatat"); if (!orig___fxstatat) debug_log("__fxstatat", "__fxstatat_error"); }
    char *rw = replace_substring(pathname);
    int ret = orig___fxstatat(ver, dirfd, rw ? rw : pathname, statbuf, flags);
    free(rw);
    return ret;
}

int __fxstatat64(int ver, int dirfd, const char *pathname, struct stat64 *statbuf, int flags)
{
    static int (*orig___fxstatat64)(int, int, const char *, struct stat64 *, int);
    if (!orig___fxstatat64) { orig___fxstatat64 = dlsym(RTLD_NEXT, "__fxstatat64"); if (!orig___fxstatat64) debug_log("__fxstatat64", "__fxstatat64_error"); }
    char *rw = replace_substring(pathname);
    int ret = orig___fxstatat64(ver, dirfd, rw ? rw : pathname, statbuf, flags);
    free(rw);
    return ret;
}

int stat64(const char *pathname, struct stat64 *statbuf)
{
    static int (*orig_stat64)(const char *, struct stat64 *);
    if (!orig_stat64) { orig_stat64 = dlsym(RTLD_NEXT, "stat64"); if (!orig_stat64) debug_log("stat64", "stat64_error"); }
    char *rw = replace_substring(pathname);
    int ret = orig_stat64(rw ? rw : pathname, statbuf);
    free(rw);
    return ret;
}

int lstat64(const char *pathname, struct stat64 *statbuf)
{
    static int (*orig_lstat64)(const char *, struct stat64 *);
    if (!orig_lstat64) { orig_lstat64 = dlsym(RTLD_NEXT, "lstat64"); if (!orig_lstat64) debug_log("lstat64", "lstat64_error"); }
    char *rw = replace_substring(pathname);
    int ret = orig_lstat64(rw ? rw : pathname, statbuf);
    free(rw);
    return ret;
}

int fstat64(int fd, struct stat64 *statbuf)
{
    static int (*orig_fstat64)(int, struct stat64 *);
    if (!orig_fstat64) { orig_fstat64 = dlsym(RTLD_NEXT, "fstat64"); if (!orig_fstat64) debug_log("fstat64", "fstat64_error"); }
    return orig_fstat64(fd, statbuf);
}

int fstatat64(int dirfd, const char *pathname, struct stat64 *statbuf, int flags)
{
    static int (*orig_fstatat64)(int, const char *, struct stat64 *, int);
    if (!orig_fstatat64) { orig_fstatat64 = dlsym(RTLD_NEXT, "fstatat64"); if (!orig_fstatat64) debug_log("fstatat64", "fstatat64_error"); }
    char *rw = replace_substring(pathname);
    int ret = orig_fstatat64(dirfd, rw ? rw : pathname, statbuf, flags);
    free(rw);
    return ret;
}

int _IO_file_stat(FILE *fp, struct stat *statbuf)
{
    static int (*orig__IO_file_stat)(FILE *, struct stat *);
    if (!orig__IO_file_stat) { orig__IO_file_stat = dlsym(RTLD_NEXT, "_IO_file_stat"); if (!orig__IO_file_stat) debug_log("_IO_file_stat", "_IO_file_stat_error"); }
    return orig__IO_file_stat(fp, statbuf);
}

int statx(int dirfd, const char *__restrict pathname, int flags,
          unsigned int mask, struct statx *__restrict statxbuf)
{
    static int (*orig_statx)(int, const char *__restrict, int, unsigned int, struct statx *__restrict);
    if (!orig_statx) { orig_statx = dlsym(RTLD_NEXT, "statx"); if (!orig_statx) debug_log("statx", "statx_error"); }
    char *rw = replace_substring(pathname);
    int ret = orig_statx(dirfd, rw ? rw : pathname, flags, mask, statxbuf);
    free(rw);
    return ret;
}

/* ---------- Wine internal my_* stat wrappers ---------- */

int my_stat(const char *pathname, struct stat *statbuf)
{
    static int (*orig_my_stat)(const char *, struct stat *);
    if (!orig_my_stat) { orig_my_stat = dlsym(RTLD_NEXT, "my_stat"); }
    char *rw = replace_substring(pathname);
    int ret = orig_my_stat(rw ? rw : pathname, statbuf);
    free(rw);
    return ret;
}

int my_lstat(const char *pathname, struct stat *statbuf)
{
    static int (*orig_my_lstat)(const char *, struct stat *);
    if (!orig_my_lstat) { orig_my_lstat = dlsym(RTLD_NEXT, "my_lstat"); }
    char *rw = replace_substring(pathname);
    int ret = orig_my_lstat(rw ? rw : pathname, statbuf);
    free(rw);
    return ret;
}

int my_fstat(int fd, struct stat *statbuf)
{
    static int (*orig_my_fstat)(int, struct stat *);
    if (!orig_my_fstat) { orig_my_fstat = dlsym(RTLD_NEXT, "my_fstat"); if (!orig_my_fstat) debug_log("my_fstat", "my_fstat_error"); }
    return orig_my_fstat(fd, statbuf);
}

int my_fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags)
{
    static int (*orig_my_fstatat)(int, const char *, struct stat *, int);
    if (!orig_my_fstatat) { orig_my_fstatat = dlsym(RTLD_NEXT, "my_fstatat"); }
    char *rw = replace_substring(pathname);
    int ret = orig_my_fstatat(dirfd, rw ? rw : pathname, statbuf, flags);
    free(rw);
    return ret;
}

/* ---------- filesystem ops ---------- */

int access(const char *pathname, int mode)
{
    static int (*orig_access)(const char *, int);
    if (!orig_access) { orig_access = dlsym(RTLD_NEXT, "access"); if (!orig_access) debug_log("access", "access_error"); }
    char *rw = replace_substring(pathname);
    int ret = orig_access(rw ? rw : pathname, mode);
    free(rw);
    return ret;
}

int unlink(const char *pathname)
{
    static int (*orig_unlink)(const char *);
    if (!orig_unlink) { orig_unlink = dlsym(RTLD_NEXT, "unlink"); if (!orig_unlink) debug_log("unlink", "unlink_error"); }
    char *rw = replace_substring(pathname);
    int ret = orig_unlink(rw ? rw : pathname);
    free(rw);
    return ret;
}

int rename(const char *oldpath, const char *newpath)
{
    static int (*orig_rename)(const char *, const char *);
    if (!orig_rename) { orig_rename = dlsym(RTLD_NEXT, "rename"); if (!orig_rename) debug_log("rename", "rename_error"); }
    char *rw_old = replace_substring(oldpath);
    char *rw_new = replace_substring(newpath);
    debug_log("rename_oldpath", rw_old ? rw_old : oldpath);
    debug_log("rename_newpath", rw_new ? rw_new : newpath);
    int ret = orig_rename(rw_old ? rw_old : oldpath, rw_new ? rw_new : newpath);
    free(rw_old);
    free(rw_new);
    return ret;
}

int chdir(const char *path)
{
    static int (*orig_chdir)(const char *);
    if (!orig_chdir) { orig_chdir = dlsym(RTLD_NEXT, "chdir"); if (!orig_chdir) debug_log("chdir", "chdir_error"); }
    char *rw = replace_substring(path);
    int ret = orig_chdir(rw ? rw : path);
    free(rw);
    return ret;
}

int mkdir(const char *pathname, mode_t mode)
{
    static int (*orig_mkdir)(const char *, mode_t);
    if (!orig_mkdir) { orig_mkdir = dlsym(RTLD_NEXT, "mkdir"); if (!orig_mkdir) debug_log("mkdir", "mkdir_error"); }
    char *rw = replace_substring(pathname);
    int ret = orig_mkdir(rw ? rw : pathname, mode);
    free(rw);
    return ret;
}

int rmdir(const char *pathname)
{
    static int (*orig_rmdir)(const char *);
    if (!orig_rmdir) { orig_rmdir = dlsym(RTLD_NEXT, "rmdir"); }
    char *rw = replace_substring(pathname);
    int ret = orig_rmdir(rw ? rw : pathname);
    free(rw);
    return ret;
}

int symlink(const char *target, const char *linkpath)
{
    static int (*orig_symlink)(const char *, const char *);
    if (!orig_symlink) { orig_symlink = dlsym(RTLD_NEXT, "symlink"); if (!orig_symlink) debug_log("symlink", "symlink_error"); }
    char *rw_target = replace_substring(target);
    char *rw_link   = replace_substring(linkpath);
    debug_log("symlink_target", rw_target ? rw_target : target);
    debug_log("symlink_linkpath", rw_link ? rw_link : linkpath);
    int ret = orig_symlink(rw_target ? rw_target : target,
                           rw_link ? rw_link : linkpath);
    free(rw_target);
    free(rw_link);
    return ret;
}

char *getcwd(char *buf, size_t size)
{
    static char *(*orig_getcwd)(char *, size_t);
    if (!orig_getcwd) { orig_getcwd = dlsym(RTLD_NEXT, "getcwd"); if (!orig_getcwd) debug_log("getcwd", "getcwd_error"); }
    char *ret = orig_getcwd(buf, size);
    if (ret) debug_log("getcwd", "<buf>");
    return ret;
}

char *realpath(const char *path, char *resolved_path)
{
    static char *(*orig_realpath)(const char *, char *);
    if (!orig_realpath) { orig_realpath = dlsym(RTLD_NEXT, "realpath"); if (!orig_realpath) debug_log("realpath", "realpath_error"); }
    char *rw = replace_substring(path);
    char *ret = orig_realpath(rw ? rw : path, resolved_path);
    free(rw);
    return ret;
}

/* ---------- shared memory ---------- */

int shm_open(const char *name, int oflag, mode_t mode)
{
    static int (*orig_shm_open)(const char *, int, mode_t);
    if (!orig_shm_open) { orig_shm_open = dlsym(RTLD_NEXT, "shm_open"); if (!orig_shm_open) debug_log("shm_open", "shm_open_error"); }
    /* Only rewrite shm paths containing /wine */
    if (name && strstr(name, "/wine")) {
        char *rw = replace_substring(name);
        if (rw) {
            int fd = orig_shm_open(rw, oflag, mode);
            free(rw);
            return fd;
        }
    }
    return orig_shm_open(name, oflag, mode);
}

int shm_unlink(const char *name)
{
    static int (*orig_shm_unlink)(const char *);
    if (!orig_shm_unlink) { orig_shm_unlink = dlsym(RTLD_NEXT, "shm_unlink"); if (!orig_shm_unlink) debug_log("shm_unlink", "shm_unlink_error"); }
    if (name && strstr(name, "/wine")) {
        char *rw = replace_substring(name);
        if (rw) {
            int ret = orig_shm_unlink(rw);
            free(rw);
            return ret;
        }
    }
    return orig_shm_unlink(name);
}

/* ---------- process execution ---------- */

int execve(const char *pathname, char *const argv[], char *const envp[])
{
    static int (*orig_execve)(const char *, char *const[], char *const[]);
    static const char preload_env[] = GOLDBERG_PRELOAD;
    if (!orig_execve) { orig_execve = dlsym(RTLD_NEXT, "execve"); if (!orig_execve) debug_log("execve", "execve_error"); }

    char *rw_path = replace_substring(pathname);
    char **rw_argv = rewrite_string_array(argv);
    char **rw_envp = rewrite_string_array(envp);

    const char *exec_name = rw_path ? rw_path : pathname;
    const char *base = strrchr(exec_name, '/');
    base = base ? base + 1 : exec_name;

    /* Skip LD_PRELOAD injection for wineserver */
    char **preload_envp = NULL;
    if (strcmp(base, "wineserver") != 0) {
        preload_envp = inject_preload(
            rw_envp ? (char *const *)rw_envp : envp, preload_env);
    }

    debug_log("execve", exec_name);
    (void)"LD_PRELOAD=";  /* string table marker */

    int ret = orig_execve(exec_name,
                          rw_argv ? rw_argv : argv,
                          preload_envp ? preload_envp :
                          rw_envp ? rw_envp : envp);
    free(rw_path);
    free_string_array(rw_argv);
    free_string_array(rw_envp);
    free(preload_envp);
    return ret;
}

int execv(const char *pathname, char *const argv[])
{
    static int (*orig_execv)(const char *, char *const[]);
    if (!orig_execv) { orig_execv = dlsym(RTLD_NEXT, "execv"); if (!orig_execv) debug_log("execv", "execv_error"); }
    char *rw_path = replace_substring(pathname);
    char **rw_argv = rewrite_string_array(argv);

    /*
     * execv has no envp param — it uses the process environ.
     * Inject LD_PRELOAD into environ before calling through.
     * Reference both environ and __environ for symbol parity.
     */
    char **saved_environ = environ;
    char **preload_envp = inject_preload(environ, GOLDBERG_PRELOAD);
    if (preload_envp) environ = preload_envp;
    (void)__environ;

    int ret = orig_execv(rw_path ? rw_path : pathname,
                         rw_argv ? rw_argv : argv);

    /* exec only returns on failure — restore environ */
    environ = saved_environ;
    free(rw_path);
    free_string_array(rw_argv);
    free(preload_envp);
    return ret;
}

int execvp(const char *file, char *const argv[])
{
    static int (*orig_execvp)(const char *, char *const[]);
    if (!orig_execvp) { orig_execvp = dlsym(RTLD_NEXT, "execvp"); if (!orig_execvp) debug_log("execvp", "execvp_error"); }
    char *rw_file = replace_substring(file);
    char **rw_argv = rewrite_string_array(argv);

    /*
     * execvp has no envp param — it uses the process environ and
     * searches PATH.  Inject LD_PRELOAD into environ before calling.
     */
    char **saved_environ = environ;
    char **preload_envp = inject_preload(environ, GOLDBERG_PRELOAD);
    if (preload_envp) environ = preload_envp;
    (void)__environ;

    int ret = orig_execvp(rw_file ? rw_file : file,
                          rw_argv ? rw_argv : argv);

    /* exec only returns on failure — restore environ */
    environ = saved_environ;
    free(rw_file);
    free_string_array(rw_argv);
    free(preload_envp);
    return ret;
}

int posix_spawn(pid_t *pid, const char *path,
                const void *file_actions, const void *attrp,
                char *const argv[], char *const envp[])
{
    static int (*orig_posix_spawn)(pid_t *, const char *, const void *, const void *, char *const[], char *const[]);
    static const char preload_env[] = GOLDBERG_PRELOAD;
    if (!orig_posix_spawn) { orig_posix_spawn = dlsym(RTLD_NEXT, "posix_spawn"); if (!orig_posix_spawn) debug_log("posix_spawn", "posix_spawn_error"); }

    char *rw_path = replace_substring(path);
    char **rw_argv = rewrite_string_array(argv);
    char **rw_envp = rewrite_string_array(envp);
    char **preload_envp = inject_preload(
        rw_envp ? (char *const *)rw_envp : envp, preload_env);

    int ret = orig_posix_spawn(pid, rw_path ? rw_path : path,
                               file_actions, attrp,
                               rw_argv ? rw_argv : argv,
                               preload_envp ? preload_envp :
                               rw_envp ? rw_envp : envp);
    free(rw_path);
    free_string_array(rw_argv);
    free_string_array(rw_envp);
    free(preload_envp);
    return ret;
}

int posix_spawnp(pid_t *pid, const char *file,
                 const void *file_actions, const void *attrp,
                 char *const argv[], char *const envp[])
{
    static int (*orig_posix_spawnp)(pid_t *, const char *, const void *, const void *, char *const[], char *const[]);
    static const char preload_env[] = GOLDBERG_PRELOAD;
    if (!orig_posix_spawnp) { orig_posix_spawnp = dlsym(RTLD_NEXT, "posix_spawnp"); if (!orig_posix_spawnp) debug_log("posix_spawnp", "posix_spawnp_error"); }

    char *rw_file = replace_substring(file);
    char **rw_argv = rewrite_string_array(argv);
    char **rw_envp = rewrite_string_array(envp);
    char **preload_envp = inject_preload(
        rw_envp ? (char *const *)rw_envp : envp, preload_env);

    int ret = orig_posix_spawnp(pid, rw_file ? rw_file : file,
                                file_actions, attrp,
                                rw_argv ? rw_argv : argv,
                                preload_envp ? preload_envp :
                                rw_envp ? rw_envp : envp);
    free(rw_file);
    free_string_array(rw_argv);
    free_string_array(rw_envp);
    free(preload_envp);
    return ret;
}

/* ---------- I/O ---------- */

int vasprintf(char **strp, const char *fmt, va_list ap)
{
    static int (*orig_vasprintf)(char **, const char *, va_list);
    if (!orig_vasprintf) { orig_vasprintf = dlsym(RTLD_NEXT, "vasprintf"); if (!orig_vasprintf) debug_log("vasprintf", "vasprintf_error"); }
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
    static int (*orig_asprintf)(char **, const char *, ...);
    if (!orig_asprintf) { (void)"asprintf_error"; }
    va_list ap;
    va_start(ap, fmt);
    int ret = vasprintf(strp, fmt, ap);
    va_end(ap);
    return ret;
}

ssize_t write(int fd, const void *buf, size_t count)
{
    static ssize_t (*orig_write)(int, const void *, size_t);
    if (!orig_write) { orig_write = dlsym(RTLD_NEXT, "write"); if (!orig_write) debug_log("write", "write_error"); }
    return orig_write(fd, buf, count);
}

/* ---------- dlopen ---------- */

void *dlopen(const char *filename, int flags)
{
    if (!real_dlopen) { real_dlopen = dlsym(RTLD_NEXT, "dlopen"); if (!real_dlopen) debug_log("dlopen", "dlopen_error"); }

    if (filename) {
        char *rw = replace_substring(filename);
        if (rw) {
            fprintf(stderr, "[wrapper] dlopen(\"%s\") \n", rw);
            void *h = real_dlopen(rw, flags);
            free(rw);
            return h;
        }
    }
    /* Log NULL filename too */
    (void)"NULL";
    return real_dlopen(filename, flags);
}

/* ---------- connect (Unix/AF_INET socket path rewriting) ---------- */

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (!real_connect) {
        real_connect = dlsym(RTLD_NEXT, "connect");
        if (!real_connect) {
            fprintf(stderr, "[wrapper] dlsym(connect) failed: %s\n", dlerror());
            errno = ENOSYS;
            return -1;
        }
    }

    if (!addr) {
        debug_log("connect", "<addr=null>");
        return real_connect(sockfd, addr, addrlen);
    }

    if (addr->sa_family == AF_UNIX) {
        struct sockaddr_un *un = (struct sockaddr_un *)addr;
        char *rw = replace_substring(un->sun_path);
        if (rw) {
            debug_log("connect_replace", rw);
            struct sockaddr_un new_un;
            memset(&new_un, 0, sizeof(new_un));
            new_un.sun_family = AF_UNIX;
            strncpy(new_un.sun_path, rw, sizeof(new_un.sun_path) - 1);
            free(rw);
            return real_connect(sockfd, (struct sockaddr *)&new_un, sizeof(new_un));
        }
    } else if (addr->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)addr;
        char buf[128];
        snprintf(buf, sizeof(buf), "%s:%d",
                 inet_ntoa(in->sin_addr), ntohs_fn(in->sin_port));
        debug_log("connect", buf);
    } else {
        char buf[64];
        snprintf(buf, sizeof(buf), "family=%d", addr->sa_family);
        debug_log("connect", buf);
    }

    int ret = real_connect(sockfd, addr, addrlen);
    if (ret < 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "%p, errno=%d (%s)",
                 (void *)addr, errno, strerror(errno));
        debug_log("connect_error", buf);
    }
    return ret;
}

/* ---------- XOpenDisplay ---------- */

void *XOpenDisplay(const char *display_name)
{
    if (!real_XOpenDisplay) {
        real_XOpenDisplay = dlsym(RTLD_NEXT, "XOpenDisplay");
        if (!real_XOpenDisplay) {
            debug_log("XOpenDisplay", "XOpenDisplay_error");
            fprintf(stderr, "[wrapper] ERROR dlsym(XOpenDisplay): %s\n", dlerror());
            return NULL;
        }
    }

    const char *dpy = getenv("DISPLAY");
    fprintf(stderr, "[wrapper] XOpenDisplay(\"%s\")  getenv(DISPLAY)=\"%s\"  \n",
            display_name ? display_name : "(null)",
            dpy ? dpy : "(null)");

    return real_XOpenDisplay(display_name);
}

/* ---------- Wine internal wrappers ---------- */

int my_open(const char *pathname, int flags, ...)
{
    static int (*orig_my_open)(const char *, int, ...);
    if (!orig_my_open) { orig_my_open = dlsym(RTLD_NEXT, "my_open"); if (!orig_my_open) debug_log("my_open", "my_open_error"); }
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
    static FILE *(*orig_my_fopen)(const char *, const char *);
    if (!orig_my_fopen) { orig_my_fopen = dlsym(RTLD_NEXT, "my_fopen"); if (!orig_my_fopen) debug_log("my_fopen", "my_fopen_error"); }
    char *rw = replace_substring(pathname);
    FILE *f = orig_my_fopen(rw ? rw : pathname, mode);
    free(rw);
    return f;
}

void *my_dlopen(const char *filename, int flags)
{
    static void *(*orig_my_dlopen)(const char *, int);
    if (!orig_my_dlopen) { orig_my_dlopen = dlsym(RTLD_NEXT, "my_dlopen"); if (!orig_my_dlopen) debug_log("my_dlopen", "my_dlopen_error"); }
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
    static void *(*orig_my_XOpenDisplay)(const char *);
    if (!orig_my_XOpenDisplay) { orig_my_XOpenDisplay = dlsym(RTLD_NEXT, "my_XOpenDisplay"); if (!orig_my_XOpenDisplay) debug_log("my_XOpenDisplay", "my_XOpenDisplay_error"); }
    return orig_my_XOpenDisplay(display_name);
}

/* ------------------------------------------------------------------ */
/*  Constructor: create marker file on first load                     */
/* ------------------------------------------------------------------ */

__attribute__((constructor))
static void pluviagoldberg_on_load(void)
{
    FILE *f = fopen(PRELOAD_MARKER, "w");
    if (f) {
        fwrite("loaded\n", 1, 7, f);
        fclose(f);
    }
    fprintf(stderr, "[INIT] libpluviagoldberg.so loaded\n");
}
