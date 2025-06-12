find_package(PkgConfig)
pkg_check_modules(PC_AWS REQUIRED aws-cpp-sdk-core aws-cpp-sdk-s3)

# Include directories
find_path(AWS_INCLUDE_DIR
  NAMES aws/core/Aws.h
  HINTS ${PC_AWS_INCLUDEDIR}
)

find_library(AWS_CORE_LIBRARY
  NAMES aws-cpp-sdk-core
  HINTS ${PC_AWS_LIBDIR}
)

find_library(AWS_S3_LIBRARY
  NAMES aws-cpp-sdk-s3
  HINTS ${PC_AWS_LIBDIR}
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
