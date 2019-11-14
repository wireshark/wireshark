#
# Find the Sparkle framework
#
# This defines the following:
#  SPARKLE_FOUND       - True if we found Sparkle
#  SPARKLE_INCLUDE_DIR - Path to Sparkle.h
#  SPARKLE_LIBRARY     - Path to Sparkle.framework

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
mark_as_advanced(SPARKLE_INCLUDE_DIR SPARKLE_LIBRARY)
