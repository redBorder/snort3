# FindAWS.cmake

find_package(PkgConfig)

# We do NOT rely on pkg-config include/lib dirs since they are empty on your system.
# Instead, use hints passed from outside or defaults.

if(NOT DEFINED AWS_INCLUDE_DIR_HINT)
  set(AWS_INCLUDE_DIR_HINT "/usr/lib/include")
endif()

if(NOT DEFINED AWS_LIBRARIES_DIR_HINT)
  set(AWS_LIBRARIES_DIR_HINT "/usr/lib/lib64")
endif()

find_path(AWS_INCLUDE_DIR
  NAMES aws/core/Aws.h
  HINTS ${AWS_INCLUDE_DIR_HINT}
)

find_library(AWS_CORE_LIBRARY
  NAMES aws-cpp-sdk-core
  HINTS ${AWS_LIBRARIES_DIR_HINT}
)

find_library(AWS_S3_LIBRARY
  NAMES aws-cpp-sdk-s3
  HINTS ${AWS_LIBRARIES_DIR_HINT}
)

if (AWS_INCLUDE_DIR AND AWS_CORE_LIBRARY AND AWS_S3_LIBRARY)
  set(HAVE_AWS TRUE)
  message(STATUS "AWS SDK found and usable.")
else()
  set(HAVE_AWS FALSE)
  message(WARNING "AWS SDK not fully found.")
endif()

mark_as_advanced(
  AWS_INCLUDE_DIR
  AWS_CORE_LIBRARY
  AWS_S3_LIBRARY
)

message(STATUS "AWS_INCLUDE_DIR = ${AWS_INCLUDE_DIR}")
message(STATUS "AWS_CORE_LIBRARY = ${AWS_CORE_LIBRARY}")
message(STATUS "AWS_S3_LIBRARY = ${AWS_S3_LIBRARY}")

if (HAVE_AWS)
  add_library(AWS::Core UNKNOWN IMPORTED)
  set_target_properties(AWS::Core PROPERTIES
    IMPORTED_LOCATION "${AWS_CORE_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${AWS_INCLUDE_DIR}"
  )

  add_library(AWS::S3 UNKNOWN IMPORTED)
  set_target_properties(AWS::S3 PROPERTIES
    IMPORTED_LOCATION "${AWS_S3_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${AWS_INCLUDE_DIR}"
    INTERFACE_LINK_LIBRARIES AWS::Core
  )
endif()
