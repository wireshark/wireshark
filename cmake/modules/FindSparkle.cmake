#
# Find the Sparkle framework
#
# This defines the following:
#  SPARKLE_FOUND        - True if we found Sparkle
#  SPARKLE_INCLUDE_DIRS - Path to Sparkle.h, empty if not found
#  SPARKLE_LIBRARIES    - Path to Sparkle.framework, empty if not found
#  SPARKLE_VERSION      - Sparkle framework bundle version

include(FindPackageHandleStandardArgs)

file(GLOB USR_LOCAL_HINT "/usr/local/Sparkle-[1-9]*/")
file(GLOB HOMEBREW_HINT "/usr/local/Caskroom/sparkle/[1-9]*/")

find_path(SPARKLE_INCLUDE_DIR Sparkle.h
  HINTS ${USR_LOCAL_HINT} ${HOMEBREW_HINT}
)
find_library(SPARKLE_LIBRARY NAMES Sparkle
  HINTS ${USR_LOCAL_HINT} ${HOMEBREW_HINT}
)

# https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFrameworks/Concepts/FrameworkAnatomy.html
find_file(_info_plist Info.plist
  ${SPARKLE_LIBRARY}/Resources
  ${SPARKLE_LIBRARY}/Versions/Current/Resources
  ${SPARKLE_LIBRARY}/Versions/A/Resources
  NO_DEFAULT_PATH
)

if(_info_plist)
  execute_process(COMMAND defaults read ${_info_plist} CFBundleVersion
    OUTPUT_VARIABLE SPARKLE_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
endif()

find_package_handle_standard_args(Sparkle
  REQUIRED_VARS SPARKLE_INCLUDE_DIR SPARKLE_LIBRARY
  VERSION_VAR SPARKLE_VERSION
)

if(SPARKLE_FOUND)
  set(SPARKLE_LIBRARIES ${SPARKLE_LIBRARY} )
  set(SPARKLE_INCLUDE_DIRS ${SPARKLE_INCLUDE_DIR} )
else(SPARKLE_FOUND)
  set(SPARKLE_LIBRARIES )
  set(SPARKLE_INCLUDE_DIRS )
endif(SPARKLE_FOUND)

mark_as_advanced(SPARKLE_INCLUDE_DIR SPARKLE_LIBRARY)
