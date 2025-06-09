find_package(PkgConfig)
pkg_check_modules(PC_LZ4 lz4)

if (PC_LZ4_FOUND)
  set(LZ4_LIBRARIES ${PC_LZ4_LIBRARIES})
  set(LZ4_INCLUDE_DIRS ${PC_LZ4_INCLUDE_DIRS})
endif()

find_path(LZ4_INCLUDE_DIR
  NAMES lz4.h
  HINTS ${PC_LZ4_INCLUDEDIR} ${CMAKE_SOURCE_DIR}/include /usr/include /usr/local/include
)

if (LZ4_INCLUDE_DIR)
  message(STATUS "Found LZ4 include directory: ${LZ4_INCLUDE_DIR}")
endif()

find_library(LZ4_LIBRARY
  NAMES lz4
  HINTS ${PC_LZ4_LIBDIR} ${CMAKE_SOURCE_DIR}/lib /usr/lib /usr/local/lib
)

if (LZ4_LIBRARY)
  message(STATUS "Found LZ4 library: ${LZ4_LIBRARY}")
endif()

if (LZ4_INCLUDE_DIR AND LZ4_LIBRARY)
  set(HAVE_LZ4 TRUE)
  message(STATUS "LZ4 is found and usable.")

  set(LZ4_LIBRARIES ${LZ4_LIBRARY})
  set(LZ4_INCLUDE_DIRS ${LZ4_INCLUDE_DIR})
endif()

mark_as_advanced(
  LZ4_INCLUDE_DIR
  LZ4_LIBRARY
)

if (HAVE_LZ4)
  add_library(lz4::lz4 UNKNOWN IMPORTED)
  set_target_properties(lz4::lz4 PROPERTIES
    IMPORTED_LOCATION "${LZ4_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${LZ4_INCLUDE_DIR}"
  )
endif()
