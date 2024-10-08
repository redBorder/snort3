set(GEOLITE_INCLUDE_DIR "/usr/local/include")
set(GEOLITE_LIBRARY "libgeolite2++.a")

find_path(GEOLITE_INCLUDE_DIR
    NAMES GeoLite2PP.hpp
    HINTS ${PC_GEOLITE_INCLUDEDIR} ${CMAKE_SOURCE_DIR}/include /usr/include /usr/local/include
)

find_library(GEOLITE_LIBRARY
    NAMES geolite2++
    HINTS ${PC_GEOLITE_LIBDIR} ${CMAKE_SOURCE_DIR}/lib /usr/lib /usr/local/lib
)

find_library(MAXMINDDB_LIBRARY
    NAMES maxminddb
    HINTS /usr/lib64 ${PC_MAXMINDDB_LIBDIR} ${CMAKE_SOURCE_DIR}/lib /usr/lib /usr/local/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    GEOLITE
    REQUIRED_VARS GEOLITE_INCLUDE_DIR GEOLITE_LIBRARY
)

if (GEOLITE_FOUND)
    message(STATUS "libGEOLITE found: ${GEOLITE_LIBRARY}")
else()
    message(FATAL_ERROR "libGEOLITE not found! Please ensure the library is installed.")
endif()

mark_as_advanced(
    GEOLITE_INCLUDE_DIR
    GEOLITE_LIBRARY
    MAXMINDDB_LIBRARY
)
