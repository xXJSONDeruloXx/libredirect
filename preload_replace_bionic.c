/*
 * preload_replace_bionic.c — Bionic (Android) LD_PRELOAD shim
 *
 * Intercepts filesystem syscall wrappers and rewrites paths that
 * contain the legacy package name to the current package name.
 * Loaded via LD_PRELOAD on the bionic (Android-native) side of
 * the Wine-on-Android stack (wine-bionic, box64-bionic).
 *
 * Build (Android NDK):
 *   $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang \
 *       -shared -fPIC -O2 -DNDEBUG \
 *       -DOLD_PKG='"com.winlator.cmod"' \
 *       -DNEW_PKG='"app.gnlime"'        \
 *       -o libredirect-bionic.so preload_replace_bionic.c -ldl
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/input.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/*  Compile-time package IDs (override with -D at build time)         */
/* ------------------------------------------------------------------ */

#ifndef OLD_PKG
#define OLD_PKG "com.winlator.cmod"
#endif

#ifndef NEW_PKG
#define NEW_PKG "app.gnlime"
#endif

static const char *old_pkg = OLD_PKG;
static const char *new_pkg = NEW_PKG;

/* ------------------------------------------------------------------ */
/*  Logging (uses raw write() to avoid recursion into hooked funcs)   */
/* ------------------------------------------------------------------ */

static void log_print(const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0)
        write(STDERR_FILENO, buf, (size_t)n);
}

#ifdef NDEBUG
#define LOG_WRAP(tag, from, to) ((void)0)
#else
static void log_wrap(const char *tag, const char *from, const char *to)
{
    log_print("rewrite (%s): %s -> %s\n", tag, from, to);
}
#define LOG_WRAP(tag, from, to) log_wrap(tag, from, to)
#endif

/* ------------------------------------------------------------------ */
/*  Real function pointers (resolved lazily via dlsym)                */
/* ------------------------------------------------------------------ */

static int (*real_open)(const char *, int, ...);
static int (*real_ioctl)(int, unsigned long, ...);
static ssize_t (*real_read)(int, void *, size_t);
static int (*real_openat)(int, const char *, int, ...);
static int (*real_fstatat)(int, const char *, struct stat *, int);

#define RESOLVE(name)                                              \
    do {                                                           \
        if (__builtin_expect(!real_##name, 0))                     \
            real_##name = dlsym(RTLD_NEXT, #name);                 \
    } while (0)

/* ------------------------------------------------------------------ */
/*  Path rewriting                                                    */
/* ------------------------------------------------------------------ */

/*
 * If `path` contains old_pkg, return a malloc'd copy with old_pkg
 * replaced by new_pkg.  Caller must free().  Returns NULL if no match.
 */
static char *replace(const char *path)
{
    if (!path)
        return NULL;

    const char *match = strstr(path, old_pkg);
    if (!match)
        return NULL;

    size_t old_len = strlen(old_pkg);
    size_t new_len = strlen(new_pkg);
    size_t path_len = strlen(path);
    size_t result_len = path_len - old_len + new_len;

    char *result = malloc(result_len + 1);
    if (!result)
        return NULL;

    size_t prefix = (size_t)(match - path);
    memcpy(result, path, prefix);
    memcpy(result + prefix, new_pkg, new_len);
    memcpy(result + prefix + new_len, match + old_len,
           path_len - prefix - old_len + 1);

    return result;
}

/* ------------------------------------------------------------------ */
/*  Helper: is this fd an /dev/input/event* node?                     */
/* ------------------------------------------------------------------ */

static int is_event_node(int fd)
{
    char link[64];
    char target[256];
    ssize_t n;

    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    n = readlink(link, target, sizeof(target) - 1);
    if (n <= 0)
        return 0;
    target[n] = '\0';
    return strncmp(target, "/dev/input/event", 16) == 0;
}

/* ------------------------------------------------------------------ */
/*  Common open logic (shared by open and open64)                     */
/* ------------------------------------------------------------------ */

static int open_common(const char *func_name, const char *pathname, int flags, mode_t mode)
{
    RESOLVE(open);
    char *rewritten = replace(pathname);
    if (rewritten) {
        LOG_WRAP(func_name, pathname, rewritten);
        int fd = real_open(rewritten, flags, mode);
        free(rewritten);
        return fd;
    }
    return real_open(pathname, flags, mode);
}

/* ------------------------------------------------------------------ */
/*  Hooked functions                                                  */
/* ------------------------------------------------------------------ */

int open(const char *pathname, int flags, ...)
{
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return open_common("open", pathname, flags, mode);
}

int open64(const char *pathname, int flags, ...)
{
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return open_common("open", pathname, flags | O_LARGEFILE, mode);
}

int openat(int dirfd, const char *pathname, int flags, ...)
{
    RESOLVE(openat);
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    char *rewritten = replace(pathname);
    if (rewritten) {
        LOG_WRAP("openat", pathname, rewritten);
        int fd = real_openat(dirfd, rewritten, flags, mode);
        free(rewritten);
        return fd;
    }
    return real_openat(dirfd, pathname, flags, mode);
}

int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags)
{
    RESOLVE(fstatat);
    char *rewritten = replace(pathname);
    if (rewritten) {
        LOG_WRAP("fstatat", pathname, rewritten);
        int ret = real_fstatat(dirfd, rewritten, statbuf, flags);
        free(rewritten);
        return ret;
    }
    return real_fstatat(dirfd, pathname, statbuf, flags);
}

/*
 * read() — intercepts reads on /dev/input/event* fds.
 * Rewrites the device name in struct input_id responses if it
 * contains old_pkg.  This ensures the gamepad appears with the
 * correct package identity.
 */
ssize_t read(int fd, void *buf, size_t count)
{
    RESOLVE(read);
    ssize_t n = real_read(fd, buf, count);
    if (n > 0 && is_event_node(fd)) {
        /* Scan the read buffer for old_pkg and rewrite in-place */
        char *haystack = (char *)buf;
        char *match = strstr(haystack, old_pkg);
        if (match && (match - haystack + strlen(new_pkg)) <= (size_t)n) {
            size_t old_len = strlen(old_pkg);
            size_t new_len = strlen(new_pkg);
            LOG_WRAP("read", old_pkg, new_pkg);
            memcpy(match, new_pkg, new_len);
            if (new_len < old_len) {
                /* Zero-fill remainder to keep buffer clean */
                memset(match + new_len, 0, old_len - new_len);
            }
        }
    }
    return n;
}

/*
 * ioctl() — intercepts EVIOCGNAME on /dev/input/event* fds.
 * Rewrites the device name if it contains old_pkg.
 */
int ioctl(int fd, unsigned long request, ...)
{
    RESOLVE(ioctl);
    va_list ap;
    va_start(ap, request);
    void *arg = va_arg(ap, void *);
    va_end(ap);

    int ret = real_ioctl(fd, request, arg);

    /* EVIOCGNAME returns the device name as a string in arg */
    if (ret >= 0 && is_event_node(fd) && _IOC_TYPE(request) == 'E' &&
        _IOC_NR(request) == (_IOC_NR(EVIOCGNAME(0)))) {
        char *name = (char *)arg;
        char *match = strstr(name, old_pkg);
        if (match) {
            size_t old_len = strlen(old_pkg);
            size_t new_len = strlen(new_pkg);
            LOG_WRAP("ioctl", old_pkg, new_pkg);
            memcpy(match, new_pkg, new_len);
            if (new_len < old_len)
                memset(match + new_len, 0, old_len - new_len);
        }
    }

    return ret;
}
