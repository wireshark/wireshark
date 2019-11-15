#
# Find the Sparkle framework
#
# This defines the following:
#  SPARKLE_FOUND        - True if we found Sparkle
#  SPARKLE_INCLUDE_DIRS - Path to Sparkle.h, empty if not found
#  SPARKLE_LIBRARIES    - Path to Sparkle.framework, empty if not found

include(FindPackageHandleStandardArgs)

file(GLOB USR_LOCAL_HINT "/usr/local/Sparkle-[1-9]*/")
file(GLOB HOMEBREW_HINT "/usr/local/Caskroom/sparkle/[1-9]*/")

find_path(SPARKLE_INCLUDE_DIR Sparkle.h
  HINTS ${USR_LOCAL_HINT} ${HOMEBREW_HINT}
)
find_library(SPARKLE_LIBRARY NAMES Sparkle
  HINTS ${USR_LOCAL_HINT} ${HOMEBREW_HINT}
)

find_package_handle_standard_args(Sparkle DEFAULT_MSG SPARKLE_INCLUDE_DIR SPARKLE_LIBRARY)

if(SPARKLE_FOUND)
  set(SPARKLE_LIBRARIES ${SPARKLE_LIBRARY} )
  set(SPARKLE_INCLUDE_DIRS ${SPARKLE_INCLUDE_DIR} )
else(SPARKLE_FOUND)
  set(SPARKLE_LIBRARIES )
  set(SPARKLE_INCLUDE_DIRS )
endif(SPARKLE_FOUND)

mark_as_advanced(SPARKLE_INCLUDE_DIR SPARKLE_LIBRARY)
