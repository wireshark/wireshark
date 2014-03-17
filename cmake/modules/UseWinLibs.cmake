#

# Right now this is a more or less inelegant hack to get Windows
# builds going with MSVC

if( WIN32 )

	# We might need something like "if (CMAKE_COMPILER_ID MATCHES "MSVC")"
	# here to support other compilers on Windows.

	set( WIN_PSAPI_LIBRARY    psapi.lib )
	set( WIN_WSOCK32_LIBRARY  wsock32.lib )
	set( WIN_COMCTL32_LIBRARY comctl32.lib )

	# Looks like this is not needed after all
	# set( WIN_SETARGV_OBJECT   setargv.obj )
	#
	# set( WS_LINK_FLAGS ${WS_LINK_FLAGS} "${WIN_SETARGV_OBJECT}" )

endif()
