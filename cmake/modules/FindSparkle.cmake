#
# Find the Sparkle framework
#
# This defines the following:
#  SPARKLE_FOUND        - True if we found Sparkle
#  SPARKLE_INCLUDE_DIRS - Path to Sparkle.h, empty if not found
#  SPARKLE_LIBRARIES    - Path to Sparkle.framework, empty if not found
#  SPARKLE_VERSION      - Sparkle framework bundle version

include(FindPackageHandleStandardArgs)

set(FETCH_ARTIFACTS_HINT "${OSX_APP_LIBPREFIX}/sparkle/")
file(GLOB USR_LOCAL_HINT "/usr/local/Sparkle-[2-9]*/")
file(GLOB HOMEBREW_HINT "/opt/homebrew/Caskroom/sparkle/[2-9]*/" "/usr/local/Caskroom/sparkle/[2-9]*/")

find_path(SPARKLE_INCLUDE_DIR Sparkle.h
  HINTS ${FETCH_ARTIFACTS_HINT} ${USR_LOCAL_HINT} ${HOMEBREW_HINT}
)
find_library(SPARKLE_LIBRARY NAMES Sparkle
  HINTS ${FETCH_ARTIFACTS_HINT} ${USR_LOCAL_HINT} ${HOMEBREW_HINT}
)

# Sparkle doesn't appear to provide a version macro, and its Info.plist versions
# are all over the place. Check for SPUStandardUpdaterController.h, which was
# added in version 2.
set(SPARKLE_VERSION 1)

find_file(_spustandardupdatercontroller_h SPUStandardUpdaterController.h
  ${SPARKLE_LIBRARY}/Headers
  NO_DEFAULT_PATH
)

if(_spustandardupdatercontroller_h)
  set(SPARKLE_VERSION 2)
endif()

unset(_spustandardupdatercontroller_h CACHE)

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
  set(SPARKLE_VERSION 0)
endif(SPARKLE_FOUND)

mark_as_advanced(SPARKLE_INCLUDE_DIR SPARKLE_LIBRARY)
