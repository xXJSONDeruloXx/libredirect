# libredirect

`LD_PRELOAD` shim libraries that intercept filesystem calls and rewrite
package paths at runtime. Used by Wine-on-Android forks (GameNative,
Winlator, etc.) to run under a different Android package ID without
modifying upstream binaries.

## What it does

Wine/Box64 binaries contain hardcoded references to the original
Winlator package directory (`com.winlator`). These shims transparently
rewrite those paths to your package's data directory at runtime via
`LD_PRELOAD`.

| Library | Target | Hooks | Rewrite |
|---------|--------|-------|---------|
| `libredirect.so` | GLIBC imagefs layer | ~60 libc functions | `com.winlator/files/rootfs` → `<pkg>/files/imagefs` |
| `libredirect-bionic.so` | Android bionic layer | 6 functions | `com.winlator.cmod` → `<pkg>` |

### Hooked functions (GLIBC)

`open`, `open64`, `fopen`, `fopen64`, `openat`, `openat64`, `openat2`,
`stat`, `lstat`, `fstat`, `fstatat`, `statx`, `access`, `unlink`,
`rename`, `chdir`, `mkdir`, `rmdir`, `symlink`, `realpath`, `getcwd`,
`opendir`, `readdir`, `dlopen`, `connect` (AF_UNIX), `shm_open`,
`shm_unlink`, `execve`, `execv`, `execvp`, `posix_spawn`,
`posix_spawnp`, `XOpenDisplay`, and all `64`/`__xstat` variants.

### Hooked functions (bionic)

`open`, `open64`, `openat`, `fstatat`, `read` (gamepad input rewriting),
`ioctl` (EVIOCGNAME rewriting).

## Building

### Download prebuilt

Grab the latest release from the
[Releases page](https://github.com/xXJSONDeruloXx/libredirect/releases).

### Build locally

**GLIBC version** (cross-compile for aarch64):
```bash
# With local cross-compiler
sudo apt install gcc-aarch64-linux-gnu
make glibc

# Or via Docker
make docker-build
```

**Bionic version** (requires Android NDK):
```bash
export NDK_HOME=/path/to/android-ndk-r28b
make bionic
```

**Both:**
```bash
make
```

### Custom package IDs

```bash
make OLD_SUB=com.winlator NEW_SUB=app.myfork
```

Output goes to `out/`.

## Packaging

Pack the built libraries into `redirect.tzst` for use in the APK assets:

```bash
mkdir -p pkg/usr/lib
cp out/libredirect.so out/libredirect-bionic.so pkg/usr/lib/
tar -C pkg -cf - usr/ | zstd -o redirect.tzst
```

## Architecture

```
Android layer (bionic):
  wine-bionic, box64-bionic
       ↓ LD_PRELOAD
  libredirect-bionic.so    com.winlator.cmod → <your-pkg>

GLIBC layer (inside imagefs):
  wineserver, wine, box64 (GLIBC)
       ↓ LD_PRELOAD
  libredirect.so           com.winlator/files/rootfs → <your-pkg>/files/imagefs
```

## License

GPL-3.0 — same as [GameNative](https://github.com/utkarshdalal/GameNative).
