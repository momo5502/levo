file(GLOB_RECURSE SRC_FILES CONFIGURE_DEPENDS
  *.cpp
  *.hpp
  *.rc
)

list(SORT SRC_FILES)

add_executable(${PROJECT_NAME} ${SRC_FILES})

# Pass LLVM tools dir so we can run llc/clang for --compile (compile and link bytecode)
if(DEFINED LLVM_TOOLS_BINARY_DIR)
  target_compile_definitions(${PROJECT_NAME} PRIVATE
    "LLVM_TOOLS_DIR=\"${LLVM_TOOLS_BINARY_DIR}\""
  )
endif()

target_link_libraries(${PROJECT_NAME} PRIVATE
  LLVM-Wrapper
  remill
  remill_settings
  shared
)

add_dependencies(${PROJECT_NAME} runtime)