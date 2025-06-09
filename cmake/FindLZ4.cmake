find_package(PkgConfig REQUIRED)
pkg_check_modules(PC_LZ4 lz4)

if (PC_LZ4_FOUND)
    set(LZ4_LIBRARIES ${PC_LZ4_LIBRARIES})
    set(LZ4_INCLUDE_DIRS ${PC_LZ4_INCLUDE_DIRS})
else()
    message(WARNING "liblz4 not found using pkg-config. Ensure it is installed.")
endif()

find_path(LZ4_INCLUDE_DIR
    NAMES lz4.h
    HINTS ${PC_LZ4_INCLUDEDIR} ${CMAKE_SOURCE_DIR}/include /usr/include/liblz4 /usr/local/include
)

find_library(LZ4_LIBRARY
    NAMES lz4
    HINTS ${PC_LZ4_LIBDIR} ${CMAKE_SOURCE_DIR}/lib /usr/lib /usr/local/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    lz4
    REQUIRED_VARS LZ4_INCLUDE_DIR LZ4_LIBRARY
)

if (lz4_FOUND)
    message(STATUS "liblz4 found:")
    message(STATUS "  Include dirs: ${LZ4_INCLUDE_DIR}")
    message(STATUS "  Libraries: ${LZ4_LIBRARY}")
else()
    message(FATAL_ERROR "liblz4 not found! Please ensure the library is installed.")
endif()

mark_as_advanced(LZ4_INCLUDE_DIR LZ4_LIBRARY)
