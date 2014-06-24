#
# - Find OS X frameworks
# Find various OS X frameworks if we're on OS X
#
#  APPLE_APPLICATION_SERVICES_LIBRARY - ApplicationServices framework
#  APPLE_CORE_FOUNDATION_LIBRARY      - CoreFoundation frameowkr
#  APPLE_SYSTEM_CONFIGURATION_LIBRARY - SystemConfiguration framework
#  HAVE_OS_X_FRAMEWORKS               - True if we're on OS X


if(APPLE)
	#
	# We assume that APPLE means OS X so that we have the OS X
	# frameworks.
	#
	set(HAVE_OS_X_FRAMEWORKS 1)
	set(OS_X_FRAMEWORKS_FOUND TRUE)
	FIND_LIBRARY (APPLE_APPLICATION_SERVICES_LIBRARY ApplicationServices)
	FIND_LIBRARY (APPLE_CORE_FOUNDATION_LIBRARY CoreFoundation)
	FIND_LIBRARY (APPLE_SYSTEM_CONFIGURATION_LIBRARY SystemConfiguration)
endif()
