#
# $Id$
#

# Right now this is a more or less inelegant hack to get Windows
# builds going with MSVC

if( WIN32 )

	# We might need something like "if (CMAKE_COMPILER_ID MATCHES "MSVC")"
	# here to support other compilers on Windows.

	set( WIN_WSOCK32_LIBRARY  wsock32.lib )

	set( WIN_SETARGV_OBJECT   setargv.obj )

	set( WS_LINK_FLAGS ${WS_LINK_FLAGS} "${WIN_SETARGV_OBJECT}" )

endif()
