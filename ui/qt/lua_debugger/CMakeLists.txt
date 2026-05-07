# CMakeLists.txt
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set(WIRESHARK_LUA_DEBUGGER_HEADERS
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger.h
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_breakpoints.h
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_code_editor.h
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_dialog.h
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_evaluate.h
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_error_frame.h
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_files.h
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_find_frame.h
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_goto_line_frame.h
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_pause.h
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_settings.h
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_stack.h
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_utils.h
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_variables.h
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_watch.h
)

set(WIRESHARK_LUA_DEBUGGER_SRCS
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_breakpoints.cpp
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_code_editor.cpp
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_dialog.cpp
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_evaluate.cpp
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_error_frame.cpp
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_files.cpp
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_find_frame.cpp
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_goto_line_frame.cpp
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_pause.cpp
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_settings.cpp
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_stack.cpp
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_utils.cpp
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_variables.cpp
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_watch.cpp
)

set(WIRESHARK_LUA_DEBUGGER_UI
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_dialog.ui
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_error_frame.ui
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_find_frame.ui
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_goto_line_frame.ui
)
