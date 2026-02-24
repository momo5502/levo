if(NOT TARGET remill_settings)
    message(FATAL_ERROR "Could not find target 'remill_settings' (did remill update?)")
endif()
get_target_property(HELPER_REMILL_INCLUDE_DIR remill_settings INTERFACE_INCLUDE_DIRECTORIES)
if(HELPER_REMILL_INCLUDE STREQUAL "HELPER_REMILL_INCLUDE_DIR-NOTFOUND")
    message(FATAL_ERROR "Could not determine remill include directory")
endif()
set(HELPER_REMILL_SYSROOT_DIR "${HELPER_REMILL_INCLUDE_DIR}/remill/Arch/Runtime/sysroot")
if(NOT EXISTS "${HELPER_REMILL_SYSROOT_DIR}")
    message(FATAL_ERROR "Could not find remill sysroot directory: ${HELPER_REMILL_SYSROOT_DIR}")
endif()

file(GLOB_RECURSE SRC_FILES CONFIGURE_DEPENDS
  *.cpp
  *.hpp
  *.rc
)

list(SORT SRC_FILES)

macro(add_runtime_library bitness)
add_library(runtime_${bitness} ${SRC_FILES})
target_include_directories(runtime_${bitness} PRIVATE ${HELPER_REMILL_INCLUDE_DIR})
target_compile_definitions(runtime_${bitness} PRIVATE -DADDRESS_SIZE_BITS=${bitness})
target_link_libraries(runtime_${bitness} PRIVATE shared)
endmacro()

add_runtime_library(32)
add_runtime_library(64)

add_custom_target(runtime ALL DEPENDS runtime_32 runtime_64)
