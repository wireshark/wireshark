#
find_program(MAKE_EXE NAMES gmake nmake make)
include(ExternalProject)

message(DEBUG "Compiler: ${CMAKE_C_COMPILER} Ar: ${CMAKE_C_COMPILER_AR} Ranlib: ${CMAKE_C_COMPILER_RANLIB}")

set(_staging_dir "${CMAKE_BINARY_DIR}/staging")

if(MINGW)
	set(_target mingw)
elseif(CMAKE_SYSTEM_NAME MATCHES Linux)
	set(_target linux)
elseif(UNIX)
	set(_target posix)
else()
	set(_target generic)
endif()

set(HAVE_LUA TRUE)
set(LUA_INCLUDE_DIRS "${_staging_dir}/include")
set(LUA_LIBRARIES "${_staging_dir}/lib/liblua.a")
set(LUA_FOUND TRUE CACHE INTERNAL "")

#
# The install patch isn't strictly necessary for Lua but it's cleaner to install
# external projects to a staging directory first, and the normal install target
# does not work with MinGW.
#
ExternalProject_Add(lua52
	URL               https://www.lua.org/ftp/lua-5.2.4.tar.gz
	URL_HASH          SHA256=b9e2e4aad6789b3b63a056d442f7b39f0ecfca3ae0f1fc0ae4e9614401b69f4b
	PATCH_COMMAND     patch -p1 < ${CMAKE_CURRENT_LIST_DIR}/0001-Add-an-install-static-target.patch
	CONFIGURE_COMMAND ""
	BUILD_COMMAND     ${MAKE_EXE} MYCFLAGS=-fPIC CC=${CMAKE_C_COMPILER} AR=${CMAKE_C_COMPILER_AR}\ rcu RANLIB=${CMAKE_C_COMPILER_RANLIB} ${_target}
	BUILD_IN_SOURCE   True
	BUILD_BYPRODUCTS  ${LUA_LIBRARIES}
	INSTALL_COMMAND   ${MAKE_EXE} INSTALL_TOP=${_staging_dir} install-static
)
