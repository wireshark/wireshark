
set(REX_SRC
	common.c
	pcre2/lpcre2.c
	pcre2/lpcre2_f.c
)

add_library(lrexlib STATIC ${REX_SRC})

target_link_libraries(lrexlib PRIVATE
	${LUA_LIBRARIES}
	${PCRE2_LIBRARIES}
)

target_include_directories(lrexlib SYSTEM PRIVATE
	${CMAKE_SOURCE_DIR}/epan
	${LUA_INCLUDE_DIRS}
	${PCRE2_INCLUDE_DIRS}
)

add_dependencies(lrexlib register_wslua)

add_compile_definitions(
	VERSION=\"2.9.1\"
	PCRE2_CODE_UNIT_WIDTH=8
)
