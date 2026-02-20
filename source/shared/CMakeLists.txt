file(GLOB_RECURSE SRC_FILES CONFIGURE_DEPENDS
  *.cpp
  *.hpp
)

list(SORT SRC_FILES)

add_library(shared ${SRC_FILES})

target_include_directories(shared INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/../)
