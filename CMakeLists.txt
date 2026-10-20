cmake_minimum_required(VERSION 3.20)

# Prefer clang, fall back to gcc
if(NOT CMAKE_C_COMPILER)
  find_program(WC_CLANG_PATH clang)
  find_program(WC_GCC_PATH gcc)
  if(WC_CLANG_PATH)
    set(CMAKE_C_COMPILER ${WC_CLANG_PATH})
  elseif(WC_GCC_PATH)
    set(CMAKE_C_COMPILER ${WC_GCC_PATH})
  endif()
endif()

project(cryptopals LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_COLOR_DIAGNOSTICS ON)

message(STATUS "C Compiler: ${CMAKE_C_COMPILER}")

# Default to Debug if not specified
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

set(VALID_BUILD_TYPES Debug Release DebugNoSan)
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS ${VALID_BUILD_TYPES})

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# Debug: sanitizers + no optimisation. -fno-sanitize-recover=all makes UBSan
# hard-abort on the first violation instead of warning and continuing.
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-fsanitize=address,undefined")

# DebugNoSan: debug info, no sanitizers - clean for lldb/gdb
set(CMAKE_C_FLAGS_DEBUGNOSAN "-g -O0 -fno-omit-frame-pointer")
set(CMAKE_EXE_LINKER_FLAGS_DEBUGNOSAN "")

# Release: full optimisation
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE "")


option(WC_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)

set(WARN_FLAGS
    -Wall
    -Wextra
    -Wshadow
    -Wno-unused-parameter
    -Wconversion
    -Wsign-conversion
    -Wstrict-prototypes
    -Wold-style-definition
    -Wmissing-prototypes
    -Wwrite-strings
    -Wpointer-arith
    -Wformat=2
    -Wnull-dereference
    -Wundef
    -Wimplicit-fallthrough
)

if(WC_WARNINGS_AS_ERRORS)
  list(APPEND WARN_FLAGS -Werror)
endif()


set(SRC_FILES
    src/wc_imp.c
    # set1
    src/set1/set1.c
    src/set1/challenge1.c
    src/set1/challenge2.c
    src/set1/challenge3.c
    src/set1/challenge4.c
)

add_executable(main
    src/main.c
    ${SRC_FILES}
)

target_include_directories(main PRIVATE include external)
target_compile_options(main PRIVATE ${WARN_FLAGS})



