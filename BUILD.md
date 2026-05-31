# Building IOR

This document describes how to build and test the IOR library on Linux, macOS, and Windows.

## Backend overview

IOR selects an I/O backend automatically based on platform and available libraries:

| Platform | Default backend | Fallback |
|----------|-----------------|----------|
| Linux    | io_uring (if liburing present) | thread backend |
| macOS    | thread backend  | - |
| FreeBSD  | thread backend  | - |
| Windows  | IOCP            | - |

On Linux you can force the thread backend for testing. On Windows the IOCP
backend is always used; the thread and io_uring backends are not compiled.

## Quick Start (Linux / macOS)
```bash
# Clone the repository
git clone https://github.com/libior/ior.git
cd ior

# Configure and build
cmake -B build
cmake --build build

# Run tests
ctest --test-dir build --output-on-failure

# Install
sudo cmake --build build --target install
```

## Quick Start (Windows)

Windows needs CMake, the MSVC toolset (Visual Studio 2022), and vcpkg to supply
cmocka for the tests. See the full [Windows](#windows) section below for the
one-time setup; once that is done:

```bat
:: Configure (uses CMakePresets.json)
cmake --preset windows-msvc

:: Build
cmake --build --preset windows-msvc

:: Test
ctest --preset windows-msvc
```

## Requirements

### Required
- CMake 3.15 or later (3.21+ recommended for preset support; 4.2+ required for the Visual Studio 2026 generator)
- C11-compatible compiler (GCC, Clang, MSVC)
- POSIX threads (pthread) on Unix/Linux/macOS - provided by the system

### Optional
- **liburing** (Linux only) - for native io_uring support
  - Ubuntu/Debian: `sudo apt install liburing-dev`
  - Fedora/RHEL: `sudo dnf install liburing-devel`
  - Arch: `sudo pacman -S liburing`
- **cmocka** - for running tests
  - Ubuntu/Debian: `sudo apt install libcmocka-dev`
  - Fedora/RHEL: `sudo dnf install libcmocka-devel`
  - Arch: `sudo pacman -S cmocka`
  - macOS (Homebrew): `brew install cmocka`
  - Windows (vcpkg): `vcpkg install cmocka:x64-windows`

## Platform Guides

### Linux

The default configuration enables io_uring when liburing is detected, and falls
back to the thread backend otherwise. No special steps are needed:

```bash
cmake -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

To install liburing for native io_uring support, see the table above.

### macOS

macOS has no io_uring or IOCP, so IOR always uses the portable thread backend.
Install the toolchain and cmocka with Homebrew:

```bash
# Xcode command-line tools provide clang and make
xcode-select --install

# CMake and cmocka via Homebrew
brew install cmake cmocka ninja

# Configure and build
cmake -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

Apple Clang fully supports C11 atomics and pthreads, so the build works out of
the box. AddressSanitizer and UndefinedBehaviorSanitizer are available
(`-DIOR_ENABLE_ASAN=ON`, `-DIOR_ENABLE_UBSAN=ON`); ThreadSanitizer is also
supported on recent toolchains.

### Windows

On Windows, IOR builds with the MSVC toolset and uses the IOCP backend. The only
external dependency is cmocka (for tests), supplied through vcpkg.

#### 1. Install CMake

```bat
winget install Kitware.CMake
```

Or download the installer from cmake.org and enable "Add to PATH". Verify:

```bat
cmake --version
```

#### 2. Install the MSVC toolset

Visual Studio provides the MSVC C compiler. Either Visual Studio 2022 (v17) or
Visual Studio 2026 (v18) works; any edition, including the free Community
edition, is fine. Both run on Windows 10 and Windows 11. If you only want the
compiler without the full IDE, install the **Build Tools for Visual Studio**
(2022 or 2026) and select the "Desktop development with C++" workload. VS Code
itself is not a compiler - it drives MSVC.

If you plan to use the Visual Studio 2026 generator, note that CMake support for
it was added in CMake 4.2, so install CMake 4.2 or later. VS 2022 works with any
CMake 3.15+.

#### 3. Install vcpkg and cmocka

```bat
git clone https://github.com/microsoft/vcpkg.git C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat
C:\vcpkg\vcpkg install cmocka:x64-windows
```

Set `VCPKG_ROOT` so the presets can find the toolchain file. For the current
session:

```bat
set VCPKG_ROOT=C:\vcpkg
```

To make it permanent, add `VCPKG_ROOT` via the Windows
System Environment Variables panel.

#### 4. Configure, build, and test

Using the presets (recommended):

```bat
cmake --preset windows-msvc
cmake --build --preset windows-msvc
ctest --preset windows-msvc
```

The `windows-msvc` preset does not pin a generator, so CMake auto-selects the
newest installed Visual Studio (2022 or 2026). If you have both installed and
want to pin a specific one, use the explicit presets instead:

```bat
cmake --preset windows-vs2022   :: forces "Visual Studio 17 2022"
cmake --preset windows-vs2026   :: forces "Visual Studio 18 2026" (needs CMake 4.2+)
```

Or manually, without presets. Pick the generator that matches your install:

```bat
:: Visual Studio 2022
cmake -B build -G "Visual Studio 17 2022" -A x64 ^
  -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake

:: Visual Studio 2026 (CMake 4.2+)
cmake -B build -G "Visual Studio 18 2026" -A x64 ^
  -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake

:: Then build and test (either generator)
cmake --build build --config RelWithDebInfo
ctest --test-dir build -C RelWithDebInfo --output-on-failure
```

Omitting `-G` entirely also works; CMake picks the newest Visual Studio it finds.

> **Note on `-A x64`:** the architecture must match the vcpkg triplet you
> installed cmocka for (`x64-windows`). A mismatch makes `find_package(cmocka)`
> fail to find a compatible build.

#### Building from VS Code

Install the **CMake Tools** extension, open the project folder, and select the
`windows-msvc` preset from the status bar. Configure and build using the status
bar buttons. The preset already points at the vcpkg toolchain, so no manual path
entry is needed.

#### Multi-config note

The Visual Studio generator is *multi-config*: the build type (Debug, Release,
RelWithDebInfo) is chosen at **build time** with `--config`, not at configure
time. `CMAKE_BUILD_TYPE` is ignored with this generator. To build a Debug
configuration:

```bat
cmake --build build --config Debug
```

#### AddressSanitizer on Windows

MSVC supports AddressSanitizer. Use the dedicated preset:

```bat
cmake --preset windows-msvc-asan
cmake --build --preset windows-msvc-asan
```

UndefinedBehaviorSanitizer and ThreadSanitizer are not available with MSVC; the
corresponding options are ignored (with a warning) on that compiler.

## Build Types

| Build Type      | GCC/Clang Flags | Use Case                          |
|-----------------|-----------------|-----------------------------------|
| Debug           | `-g -O0`        | Development, debugging with gdb   |
| Release         | `-O3 -DNDEBUG`  | Production, maximum performance   |
| RelWithDebInfo  | `-O2 -g`        | Profiling, debugging optimized    |
| MinSizeRel      | `-Os -DNDEBUG`  | Minimal binary size               |

**Default:** RelWithDebInfo (single-config generators only; see the Windows
multi-config note above).

### Examples (Linux / macOS)
```bash
# Default (optimized + debug symbols)
cmake -B build
cmake --build build

# Debug build
cmake -B build-debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build-debug

# Release build
cmake -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release
```

## Build Options

Configure with `-D<OPTION>=<VALUE>`.

### Core Options

| Option                  | Default        | Description                                    |
|-------------------------|----------------|------------------------------------------------|
| `CMAKE_BUILD_TYPE`      | RelWithDebInfo | Build type (single-config generators)          |
| `CMAKE_INSTALL_PREFIX`  | /usr/local     | Installation directory                         |
| `IOR_BUILD_TESTS`       | ON             | Build test suite                               |

### Backend Options

| Option              | Default | Description                                         |
|---------------------|---------|-----------------------------------------------------|
| `IOR_WITH_URING`    | ON      | Look for liburing on Linux (Linux-only)             |
| `IOR_FORCE_THREADS` | OFF     | Use the thread backend even if io_uring works       |

`IOR_WITH_URING=OFF` means "never look for liburing at all." `IOR_FORCE_THREADS=ON`
means "io_uring may be present, but use the thread backend anyway" - useful for
exercising the portable backend on a machine that has working io_uring. Both
result in the thread backend on Linux; they differ only in intent. Neither has
any effect on Windows or macOS.

### Advanced Options

| Option           | Default | Description                                    |
|------------------|---------|------------------------------------------------|
| `IOR_FORCE_PIPE` | OFF     | Force pipe instead of eventfd (testing)        |
| `IOR_ENABLE_LOG` | OFF     | Enable logging system for debugging            |
| `IOR_LOG_LEVEL`  | 2       | Log level: 0=TRACE, 1=DEBUG, 2=INFO, 3=WARN, 4=ERROR |

### Sanitizer Options

| Option              | Default | GCC/Clang | MSVC | Description                       |
|---------------------|---------|-----------|------|-----------------------------------|
| `IOR_ENABLE_ASAN`   | OFF     | yes       | yes  | AddressSanitizer (memory)         |
| `IOR_ENABLE_UBSAN`  | OFF     | yes       | no   | UndefinedBehaviorSanitizer        |
| `IOR_ENABLE_TSAN`   | OFF     | yes       | no   | ThreadSanitizer (data races)      |

### Examples
```bash
# Build without io_uring support (Linux)
cmake -B build -DIOR_WITH_URING=OFF

# Force thread backend (Linux)
cmake -B build -DIOR_FORCE_THREADS=ON

# Debug + logging at TRACE level + thread backend
cmake -B build -DIOR_FORCE_THREADS=ON -DCMAKE_BUILD_TYPE=Debug \
               -DIOR_ENABLE_LOG=ON -DIOR_LOG_LEVEL=0
cmake --build build
./build/tests/test_read_write 2>&1 | tee debug.log

# Log to a file instead of stderr
IOR_LOG_FILE=./debug.log ./build/tests/test_read_write

# Debug build with AddressSanitizer
cmake -B build-asan -DCMAKE_BUILD_TYPE=Debug -DIOR_ENABLE_ASAN=ON

# Debug build with ThreadSanitizer (Linux/macOS only)
cmake -B build-tsan -DCMAKE_BUILD_TYPE=Debug -DIOR_ENABLE_TSAN=ON
```

## Testing

### Running Tests
```bash
# All tests
ctest --test-dir build --output-on-failure

# From the build directory
cd build && ctest --output-on-failure

# Verbose
ctest --test-dir build --verbose

# Specific test / pattern
ctest --test-dir build -R test_basic
ctest --test-dir build -R thread

# Parallel
ctest --test-dir build -j4

# List tests
ctest --test-dir build -N
```

On Windows with a multi-config generator, pass the configuration:

```bat
ctest --test-dir build -C RelWithDebInfo --output-on-failure
```

### Running Individual Tests

On Linux/macOS the binaries are under `build/tests/`:

```bash
cd build/tests
./test_basic
./test_read_write
./test_timeout

# Linux-specific
./test_splice            # if splice support detected
./test_uring_backend     # if liburing available
```

On Windows they are under `build\tests\<Config>\`:

```bat
build\tests\RelWithDebInfo\test_basic.exe
build\tests\RelWithDebInfo\test_read_write.exe
```

## Installation

### Unix (Linux / macOS)
```bash
# Default (/usr/local)
sudo cmake --build build --target install

# Custom prefix
cmake -B build -DCMAKE_INSTALL_PREFIX=/opt/ior
cmake --build build
sudo cmake --build build --target install

# Uninstall
sudo xargs rm < build/install_manifest.txt
```

Installed layout:
```
/usr/local/
  include/ior/
    ior.h
    config.h
  lib/
    libior.a
    pkgconfig/ior.pc
```

### Windows

The default prefix (`C:\Program Files\ior`) requires an elevated prompt, so a
custom prefix in your workspace is usually easier. Set the prefix at configure
time, then install with the matching `--config`:

```bat
cmake --preset windows-msvc -DCMAKE_INSTALL_PREFIX=C:/dev/ior-install
cmake --build --preset windows-msvc
cmake --install build --config RelWithDebInfo
```

Installed layout:
```
<prefix>\
  include\ior\
    ior.h
    config.h
  lib\
    ior.lib
    pkgconfig\ior.pc   (pkg-config file; not used by MSVC)
```

## Using IOR in Your Project

### Unix (Linux / macOS)

With pkg-config:
```bash
gcc myapp.c $(pkg-config --cflags --libs ior) -o myapp
```

With CMake:
```cmake
find_package(PkgConfig REQUIRED)
pkg_check_modules(IOR REQUIRED ior)

add_executable(myapp myapp.c)
target_include_directories(myapp PRIVATE ${IOR_INCLUDE_DIRS})
target_link_libraries(myapp PRIVATE ${IOR_LIBRARIES})
```

Manual compilation:
```bash
gcc myapp.c -I/usr/local/include -L/usr/local/lib -lior -lpthread -o myapp
```

### Windows

Link against `ior.lib` and `ws2_32.lib`, and add the install `include` directory
to your include path. With CMake, point `CMAKE_PREFIX_PATH` at the install prefix
and link the libraries directly:

```cmake
add_executable(myapp myapp.c)
target_include_directories(myapp PRIVATE C:/dev/ior-install/include)
target_link_libraries(myapp PRIVATE C:/dev/ior-install/lib/ior.lib ws2_32)
```

pkg-config is not used on MSVC; the generated `ior.pc` is installed but ignored.

## Troubleshooting

### cmocka not found (Windows)

Confirm vcpkg installed it for the matching triplet and that `VCPKG_ROOT` is set:

```bat
C:\vcpkg\vcpkg list
echo %VCPKG_ROOT%
```

The configure command must point at the vcpkg toolchain file, and the
architecture (`-A x64`) must match the triplet (`x64-windows`).

### liburing not found (Linux)

```bash
# Install pkg-config
sudo apt install pkg-config   # Ubuntu/Debian
sudo dnf install pkgconfig    # Fedora/RHEL

# Or specify paths manually
cmake -B build -DLIBURING_INCLUDE_DIRS=/usr/local/include \
               -DLIBURING_LIBRARIES=/usr/local/lib/liburing.so
```

### Runtime library errors (Unix)

```bash
# Temporary
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# Permanent (root)
sudo sh -c 'echo /usr/local/lib > /etc/ld.so.conf.d/local.conf'
sudo ldconfig
```

### Tests fail on older kernels (Linux)

On Linux < 5.1 without io_uring, force the thread backend:

```bash
cmake -B build -DIOR_FORCE_THREADS=ON
cmake --build build
ctest --test-dir build
```

## Development

### Code Formatting

The project uses clang-format with tabs for indentation:

```bash
# Format all sources
find src tests -name "*.[ch]" | xargs clang-format -i

# Check formatting
find src tests -name "*.[ch]" | xargs clang-format --dry-run -Werror
```
