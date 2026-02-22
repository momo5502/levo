cmake_minimum_required(VERSION 3.22)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

project(levo
  LANGUAGES C CXX
)

if(NOT DEFINED CMAKE_PREFIX_PATH AND NOT DEFINED ENV{CMAKE_PREFIX_PATH})
  set(DEFAULT_PREFIX "${CMAKE_SOURCE_DIR}/dependencies/install")
  if(NOT EXISTS "${DEFAULT_PREFIX}/${CMAKE_SYSTEM}.build")
    message(FATAL_ERROR "Default dependency prefix not found: ${DEFAULT_PREFIX}\nTo build the dependencies, run:\n  cmake -B dependencies/build -S dependencies\n  cmake --build dependencies/build\nAlternatively specify the prefix manually:\n  cmake -B build \"-DCMAKE_PREFIX_PATH:FILEPATH=/path/to/dependencies/install\"")
  else()
    set(CMAKE_PREFIX_PATH "${DEFAULT_PREFIX}")
  endif()
endif()

# Set the optimization level

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Temporarily disabled, as a lot of C98-incompatibility warnings pollute the output
#add_compile_options(-Wall -Wextra)
if(MSVC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

  set(CMAKE_CXX_FLAGS_DEBUG "/Zi /Od")
  set(CMAKE_CXX_FLAGS_RELEASE "/O2 /DNDEBUG")
  #set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "/Zi /Od")
else()
  set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -fno-limit-debug-info")
  set(CMAKE_CXX_FLAGS_RELEASE "-O3 -g0 -fomit-frame-pointer -march=native")
endif()

# Find the dependencies

set(GFLAGS_USE_TARGET_NAMESPACE ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMake")

find_package(LLVM-Wrapper REQUIRED)
find_package(remill REQUIRED)

add_subdirectory(source)
