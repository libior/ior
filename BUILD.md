# Building IOR

This document describes how to build and test the IOR library.

## Quick Start
```bash
# Clone the repository
git clone https://github.com/yourusername/ior.git
cd ior

# Configure and build
cmake -B build
cmake --build build

# Run tests
ctest --test-dir build --output-on-failure

# Install
sudo cmake --build build --target install
```

## Requirements

### Required
- CMake 3.15 or later
- C11-compatible compiler (GCC, Clang, MSVC)
- POSIX threads (pthread on Unix/Linux)

### Optional
- **liburing** (Linux only) - for native io_uring support
  - On Ubuntu/Debian: `sudo apt install liburing-dev`
  - On Fedora/RHEL: `sudo dnf install liburing-devel`
  - On Arch: `sudo pacman -S liburing`
- **cmocka** - for running tests
  - On Ubuntu/Debian: `sudo apt install libcmocka-dev`
  - On Fedora/RHEL: `sudo dnf install libcmocka-devel`
  - On Arch: `sudo pacman -S cmocka`

## Build Types

CMake supports several build types with different optimization and debug settings:

| Build Type      | Flags           | Use Case                          |
|-----------------|-----------------|-----------------------------------|
| Debug           | `-g -O0`        | Development, debugging with gdb   |
| Release         | `-O3 -DNDEBUG`  | Production, maximum performance   |
| RelWithDebInfo  | `-O2 -g`        | Profiling, debugging optimized    |
| MinSizeRel      | `-Os -DNDEBUG`  | Minimal binary size               |

**Default:** RelWithDebInfo

### Examples
```bash
# RelWithDebInfo build (default - optimized + debug symbols)
cmake -B build
cmake --build build

# Debug build (no optimization, full debug info)
cmake -B build-debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build-debug

# Release build (maximum optimization, no debug symbols)
cmake -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release
```

## Build Options

Configure the build with `-D<OPTION>=<VALUE>`:

### Core Options

| Option                  | Default        | Description                                    |
|-------------------------|----------------|------------------------------------------------|
| `CMAKE_BUILD_TYPE`      | RelWithDebInfo | Build type: Debug, Release, RelWithDebInfo     |
| `CMAKE_INSTALL_PREFIX`  | /usr/local     | Installation directory                         |
| `IOR_BUILD_TESTS`       | ON             | Build test suite                               |

### Backend Options

| Option              | Default | Description                                         |
|---------------------|---------|-----------------------------------------------------|
| `IOR_WITH_URING`    | ON      | Enable io_uring support (requires liburing)         |
| `IOR_FORCE_THREADS` | OFF     | Force thread backend (disable io_uring for testing) |

### Advanced Options

| Option           | Default | Description                                    |
|------------------|---------|------------------------------------------------|
| `IOR_FORCE_PIPE` | OFF     | Force pipe instead of eventfd (testing)        |

### Sanitizer Options (Debug builds)

| Option              | Default | Description                           |
|---------------------|---------|---------------------------------------|
| `IOR_ENABLE_ASAN`   | OFF     | Enable AddressSanitizer (memory)      |
| `IOR_ENABLE_UBSAN`  | OFF     | Enable UndefinedBehaviorSanitizer     |
| `IOR_ENABLE_TSAN`   | OFF     | Enable ThreadSanitizer (data races)   |

### Examples
```bash
# Build without io_uring support
cmake -B build -DIOR_WITH_URING=OFF
cmake --build build

# Build without tests
cmake -B build -DIOR_BUILD_TESTS=OFF
cmake --build build

# Force thread backend (ignore io_uring)
cmake -B build -DIOR_FORCE_THREADS=ON
cmake --build build

# Debug build with AddressSanitizer
cmake -B build-asan -DCMAKE_BUILD_TYPE=Debug -DIOR_ENABLE_ASAN=ON
cmake --build build-asan

# Debug build with ThreadSanitizer (finds race conditions)
cmake -B build-tsan -DCMAKE_BUILD_TYPE=Debug -DIOR_ENABLE_TSAN=ON
cmake --build build-tsan
```

## Testing

### Running Tests
```bash
# Run all tests
ctest --test-dir build --output-on-failure

# Or from build directory
cd build
ctest --output-on-failure

# Verbose output
ctest --verbose

# Run specific test
ctest -R test_basic

# Run tests matching pattern
ctest -R thread

# Run in parallel
ctest -j4

# List available tests
ctest -N
```

### Running Individual Tests
```bash
cd build/tests

# Run specific test
./test_basic
./test_read_write
./test_timeout
./test_ring
./test_event
./test_threads_backend

# Linux-specific tests
./test_splice           # splice support
./test_uring_backend    # if liburing available
```

## Installation
```bash
# Default installation (/usr/local)
sudo cmake --build build --target install

# Custom installation directory
cmake -B build -DCMAKE_INSTALL_PREFIX=/opt/ior
cmake --build build
sudo cmake --build build --target install

# Uninstall
sudo xargs rm < build/install_manifest.txt
```

### Installed Files
```
/usr/local/
├── include/ior/
│   ├── ior.h
│   └── config.h
├── lib/
│   ├── libior.a
│   └── pkgconfig/ior.pc
```

## Using IOR in Your Project

### With pkg-config
```bash
gcc myapp.c $(pkg-config --cflags --libs ior) -o myapp
```

### With CMake
```cmake
find_package(PkgConfig REQUIRED)
pkg_check_modules(IOR REQUIRED ior)

add_executable(myapp myapp.c)
target_include_directories(myapp PRIVATE ${IOR_INCLUDE_DIRS})
target_link_libraries(myapp PRIVATE ${IOR_LIBRARIES})
```

### Manual Compilation
```bash
gcc myapp.c -I/usr/local/include -L/usr/local/lib -lior -lpthread -o myapp
```

## Troubleshooting

### liburing not found

If you have liburing installed but CMake can't find it:
```bash
# Install pkg-config
sudo apt install pkg-config  # Ubuntu/Debian
sudo dnf install pkgconfig   # Fedora/RHEL

# Or specify path manually
cmake -B build -DLIBURING_INCLUDE_DIRS=/usr/local/include \
               -DLIBURING_LIBRARIES=/usr/local/lib/liburing.so
```

### Runtime library errors

If tests fail with "cannot open shared object file":
```bash
# Temporary fix
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
ctest --test-dir build

# Permanent fix (requires root)
sudo sh -c 'echo /usr/local/lib > /etc/ld.so.conf.d/local.conf'
sudo ldconfig
```

### Tests fail on older kernels

If you're on Linux < 5.1 without io_uring support:
```bash
# Force thread backend
cmake -B build -DIOR_FORCE_THREADS=ON
cmake --build build
ctest --test-dir build
```

## Development

### Code Formatting

The project uses clang-format with tabs for indentation:
```bash
# Format all source files
find src tests -name "*.[ch]" | xargs clang-format -i

# Check formatting
find src tests -name "*.[ch]" | xargs clang-format --dry-run -Werror
```
