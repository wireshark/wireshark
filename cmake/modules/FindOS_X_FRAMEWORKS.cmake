#
# - Find macOS frameworks
# Find various macOS frameworks if we're on macOS
#
#  APPLE_APPLICATION_SERVICES_LIBRARY - ApplicationServices framework
#  APPLE_CORE_FOUNDATION_LIBRARY      - CoreFoundation frameowkr
#  APPLE_SYSTEM_CONFIGURATION_LIBRARY - SystemConfiguration framework
#  HAVE_OS_X_FRAMEWORKS               - True if we're on macOS


if(APPLE)
	#
	# We assume that APPLE means macOS so that we have the macOS
	# frameworks.
	#
	set(HAVE_OS_X_FRAMEWORKS 1)
	set(OS_X_FRAMEWORKS_FOUND TRUE)
	FIND_LIBRARY (APPLE_APPLICATION_SERVICES_LIBRARY ApplicationServices)
	FIND_LIBRARY (APPLE_CORE_FOUNDATION_LIBRARY CoreFoundation)
	FIND_LIBRARY (APPLE_SYSTEM_CONFIGURATION_LIBRARY SystemConfiguration)
endif()
