# Building IOR

How to build and test IOR on Linux, macOS, and Windows.

## Backend overview

IOR picks an I/O backend automatically:

| Platform | Backend |
|----------|---------|
| Linux    | io_uring if liburing is present, else thread backend |
| macOS / FreeBSD | thread backend |
| Windows  | IOCP |

On Linux you can force the thread backend (`-DIOR_FORCE_THREADS=ON`). On Windows
only IOCP is compiled.

## Quick start

**Linux / macOS:**
```bash
git clone https://github.com/libior/ior.git
cd ior
cmake -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

**Windows** (after the one-time [setup](#windows) below):
```bat
cmake --preset windows-msvc
cmake --build --preset windows-msvc
ctest --preset windows-msvc
```

## Requirements

- CMake 3.15+ (3.21+ for presets; 4.2+ for the VS 2026 generator)
- A C11 compiler: GCC, Clang, or MSVC
- pthreads on Unix (system-provided)
- **liburing** (optional, Linux) for io_uring: `apt install liburing-dev` /
  `dnf install liburing-devel` / `pacman -S liburing`
- **cmocka** (optional, for tests):
  - Linux: `apt install libcmocka-dev` / `dnf install libcmocka-devel` / `pacman -S cmocka`
  - macOS: `brew install cmocka`
  - Windows: installed automatically from `vcpkg.json` (see below)

## Platform notes

### Linux

Defaults to io_uring when liburing is found, thread backend otherwise. No special
steps. On kernels older than 5.1 (no io_uring), force the thread backend with
`-DIOR_FORCE_THREADS=ON`.

### macOS

Always uses the thread backend (no io_uring/IOCP). Apple Clang supports C11
atomics and pthreads out of the box.

```bash
xcode-select --install
brew install cmake cmocka ninja
cmake -B build && cmake --build build
ctest --test-dir build --output-on-failure
```

ASan and UBSan are available (`-DIOR_ENABLE_ASAN=ON`, `-DIOR_ENABLE_UBSAN=ON`);
TSan works on recent toolchains.

### Windows

Builds with MSVC and uses IOCP. The only external dependency is cmocka (tests),
which is declared in `vcpkg.json` and installed by vcpkg automatically at
configure time - there is no manual `vcpkg install`.

**One-time setup:**

1. **CMake** - `winget install Kitware.CMake` (or cmake.org installer with "Add
   to PATH"). Use 4.2+ if you want the VS 2026 generator.
2. **MSVC** - Visual Studio 2022 (v17) or 2026 (v18), any edition, or the
   standalone **Build Tools for Visual Studio** with the "Desktop development
   with C++" workload.
3. **vcpkg** - clone and bootstrap, then set `VCPKG_ROOT` so the presets find the
   toolchain. Do *not* run `vcpkg install` - the manifest handles cmocka.
   ```bat
   git clone https://github.com/microsoft/vcpkg.git C:\vcpkg
   C:\vcpkg\bootstrap-vcpkg.bat
   set VCPKG_ROOT=C:\vcpkg
   ```
   Set `VCPKG_ROOT` permanently via the System Environment Variables panel. (The
   vcpkg bundled with Visual Studio also works, since IOR uses a manifest.)

**Build and test** with the presets. The first configure builds and caches
cmocka, so it is slower than later runs:

```bat
cmake --preset windows-msvc
cmake --build --preset windows-msvc
ctest --preset windows-msvc
```

`windows-msvc` auto-selects the newest installed Visual Studio. To pin one, use
`windows-vs2022` or `windows-vs2026` instead.

Without presets, pass the generator and the vcpkg toolchain (required so the
manifest resolves cmocka):

```bat
cmake -B build -G "Visual Studio 17 2022" -A x64 ^
  -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build --config RelWithDebInfo
ctest --test-dir build -C RelWithDebInfo --output-on-failure
```

Use `"Visual Studio 18 2026"` for VS 2026 (CMake 4.2+). `-A x64` must match the
cmocka triplet (`x64-windows`), or `find_package(cmocka)` fails.

**VS Code:** install the **CMake Tools** extension, open the folder, pick the
`windows-msvc` preset from the status bar.

**Multi-config:** the VS generator chooses the build type at build time via
`--config` (e.g. `cmake --build build --config Debug`); `CMAKE_BUILD_TYPE` is
ignored.

**AddressSanitizer:** use the `windows-msvc-asan` preset (Debug, in a separate
`build-asan` dir). Tests need `clang_rt.asan_dynamic-x86_64.dll` on `PATH` -
easiest from a **Developer PowerShell for VS**; the test preset also adds it
automatically when `VCToolsInstallDir` is set. UBSan and TSan are unavailable
with MSVC (the options are ignored with a warning).

## Build options

Set with `-D<OPTION>=<VALUE>`.

| Option | Default | Description |
|--------|---------|-------------|
| `CMAKE_BUILD_TYPE` | RelWithDebInfo | Build type (single-config generators) |
| `CMAKE_INSTALL_PREFIX` | /usr/local | Install directory |
| `IOR_BUILD_TESTS` | ON | Build the test suite |
| `IOR_WITH_URING` | ON | Look for liburing (Linux only) |
| `IOR_FORCE_THREADS` | OFF | Use the thread backend even if io_uring works |
| `IOR_FORCE_PIPE` | OFF | Force pipe instead of eventfd (testing) |
| `IOR_ENABLE_LOG` | OFF | Enable the logging system |
| `IOR_LOG_LEVEL` | 2 | 0=TRACE 1=DEBUG 2=INFO 3=WARN 4=ERROR |
| `IOR_ENABLE_ASAN` | OFF | AddressSanitizer (GCC/Clang/MSVC) |
| `IOR_ENABLE_UBSAN` | OFF | UndefinedBehaviorSanitizer (GCC/Clang only) |
| `IOR_ENABLE_TSAN` | OFF | ThreadSanitizer (GCC/Clang only) |

`IOR_WITH_URING=OFF` never looks for liburing; `IOR_FORCE_THREADS=ON` ignores a
working io_uring. Both yield the thread backend on Linux and have no effect on
Windows/macOS.

Build types (GCC/Clang): Debug `-g -O0`, Release `-O3 -DNDEBUG`, RelWithDebInfo
`-O2 -g`, MinSizeRel `-Os -DNDEBUG`. Default is RelWithDebInfo on single-config
generators.

**Examples:**
```bash
# Debug + TRACE logging + thread backend
cmake -B build -DIOR_FORCE_THREADS=ON -DCMAKE_BUILD_TYPE=Debug \
               -DIOR_ENABLE_LOG=ON -DIOR_LOG_LEVEL=0
cmake --build build
IOR_LOG_FILE=./debug.log ./build/tests/test_read_write   # or stderr if unset

# AddressSanitizer
cmake -B build-asan -DCMAKE_BUILD_TYPE=Debug -DIOR_ENABLE_ASAN=ON
```

## Testing

```bash
ctest --test-dir build --output-on-failure   # all
ctest --test-dir build -R test_basic          # by name/pattern
ctest --test-dir build -j4                     # parallel
ctest --test-dir build -N                      # list
```

Windows multi-config needs the config: `ctest --test-dir build -C RelWithDebInfo
--output-on-failure`.

Individual binaries live in `build/tests/` (Unix) or `build\tests\<Config>\`
(Windows), e.g. `./test_basic`, `./test_splice` (if splice detected),
`./test_uring_backend` (if liburing), `test_iocp_backend.exe` (Windows).

## Installation

**Unix:**
```bash
sudo cmake --build build --target install        # to /usr/local
# custom prefix:
cmake -B build -DCMAKE_INSTALL_PREFIX=/opt/ior && cmake --build build
sudo cmake --build build --target install
# uninstall:
sudo xargs rm < build/install_manifest.txt
```

**Windows** (default prefix needs an elevated prompt, so a workspace prefix is
easier):
```bat
cmake --preset windows-msvc -DCMAKE_INSTALL_PREFIX=C:/dev/ior-install
cmake --build --preset windows-msvc
cmake --install build --config RelWithDebInfo
```

Installed layout: headers in `include/ior/` (`ior.h`, `config.h`), library in
`lib/` (`libior.a` / `ior.lib`), plus `pkgconfig/ior.pc` (unused on MSVC).

## Using IOR

**Unix** - pkg-config or manual:
```bash
gcc myapp.c $(pkg-config --cflags --libs ior) -o myapp
gcc myapp.c -I/usr/local/include -L/usr/local/lib -lior -lpthread -o myapp
```
CMake:
```cmake
find_package(PkgConfig REQUIRED)
pkg_check_modules(IOR REQUIRED ior)
target_include_directories(myapp PRIVATE ${IOR_INCLUDE_DIRS})
target_link_libraries(myapp PRIVATE ${IOR_LIBRARIES})
```

**Windows** - link `ior.lib` and `ws2_32`; pkg-config is not used:
```cmake
target_include_directories(myapp PRIVATE C:/dev/ior-install/include)
target_link_libraries(myapp PRIVATE C:/dev/ior-install/lib/ior.lib ws2_32)
```

## Troubleshooting

**cmocka not found (Windows)** - CMake didn't configure through the vcpkg
toolchain. Check `echo %VCPKG_ROOT%` is set and that you used a preset (or passed
`-DCMAKE_TOOLCHAIN_FILE`). `-A x64` must match the `x64-windows` triplet.

**ASan DLL missing (Windows)** - `clang_rt.asan_dynamic-x86_64.dll` not on
`PATH`. Run from a Developer PowerShell for VS, or use `ctest --preset
windows-msvc-asan`.

**liburing not found (Linux)** - install `pkg-config`, or pass
`-DLIBURING_INCLUDE_DIRS=...` and `-DLIBURING_LIBRARIES=...`.

**Runtime library errors (Unix)** - `export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH`,
or add `/usr/local/lib` to `/etc/ld.so.conf.d/` and run `sudo ldconfig`.

## Development

clang-format (tabs for indentation):
```bash
find src tests -name "*.[ch]" | xargs clang-format -i              # format
find src tests -name "*.[ch]" | xargs clang-format --dry-run -Werror  # check
```
