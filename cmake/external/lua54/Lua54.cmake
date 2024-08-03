#
find_program(MAKE_EXE NAMES gmake nmake make)
include(ExternalProject)

message(DEBUG "Compiler: ${CMAKE_C_COMPILER} Ar: ${CMAKE_AR} Ranlib: ${CMAKE_RANLIB}")

set(_staging_dir "${CMAKE_BINARY_DIR}/staging")

if(MINGW)
	set(_target mingw)
elseif(APPLE)
	set(_target macosx)
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
set(Lua_FOUND TRUE CACHE INTERNAL "")
# Fresh Lua 5.3+ install always has 64-bit lua_Integers (unlike Lua 5.2)
set(LUA_INTEGER_SIZE 8 CACHE INTERNAL "Size of lua_Integer")

set(_lua54_cflags "-fPIC")
if(APPLE)
	set(_lua54_cflags "${lua54_cflags} -isysroot ${CMAKE_OSX_SYSROOT}")
endif()

#
# The install patch isn't strictly necessary for Lua but it's cleaner to install
# external projects to a staging directory first, and the normal install target
# does not work with MinGW.
#
ExternalProject_Add(lua54
	URL               https://gitlab.com/wireshark/wireshark-development-libraries/-/raw/main/public/src/lua/lua-5.4.6.tar.gz
	URL               https://www.lua.org/ftp/lua-5.4.6.tar.gz
	URL_HASH          SHA256=7d5ea1b9cb6aa0b59ca3dde1c6adcb57ef83a1ba8e5432c0ecd06bf439b3ad88
	PATCH_COMMAND     patch -p1 < ${CMAKE_CURRENT_LIST_DIR}/0001-Add-an-install-static-target.patch
	CONFIGURE_COMMAND ""
	BUILD_COMMAND     ${MAKE_EXE} MYCFLAGS=${_lua54_cflags} CC=${CMAKE_C_COMPILER} AR=${CMAKE_AR}\ rcu RANLIB=${CMAKE_RANLIB} ${_target}
	BUILD_IN_SOURCE   True
	BUILD_BYPRODUCTS  ${LUA_LIBRARIES}
	INSTALL_COMMAND   ${MAKE_EXE} INSTALL_TOP=${_staging_dir} install-static
)
