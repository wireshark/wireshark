/** @file
 *
 * Wireshark's interface to the Lua Programming Language
 * for file handling related source files.
 *
 * (c) 2014, Hadriel Kaplan <hadrielk@yahoo.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


/* See wslua_file_common.c for details */

#include "wslua.h"
#include <wiretap/wtap_opttypes.h>
#include <wiretap/wtap_module.h>

/* this is way overkill for this one member, but in case we need to add
   more in the future, the plumbing will be here */
typedef struct _file_priv_t {
    int table_ref;
} file_priv_t;

/* create and set the wtap->priv private data for the file instance */

/**
 * @brief Creates private data for a wtap structure.
 *
 * @param L Lua state.
 * @param wth Pointer to the wtap structure.
 */
extern void create_wth_priv(lua_State* L, wtap *wth);

/* gets the private data table from wtap */

/**
 * @brief Retrieves the private data table reference from a wtap structure.
 *
 * @param L The Lua state.
 * @param wth The wtap structure.
 * @return The number of values pushed onto the stack.
 */
extern int get_wth_priv_table_ref(lua_State* L, wtap *wth);

/**
 * @brief Sets the private data table reference for a wtap structure.
 *
 * Sets the private data to wtap - the table is presumed on top of stack
 *
 * @param L The Lua state.
 * @param wth The wtap structure.
 * @return The number of values pushed onto the stack.
 */
extern int set_wth_priv_table_ref(lua_State* L, wtap *wth);

/**
 * @brief Removes private data associated with a wtap structure.
 *
 * remove, deref, and free the wtap->priv data
 *
 * @param L The Lua state.
 * @param wth Pointer to the wtap structure whose private data is to be removed.
 */
extern void remove_wth_priv(lua_State* L, wtap *wth);

/**
 * @brief Creates private data for a wtap_dumper structure.
 *
 * Create and set the wtap_dumper->priv private data for the file instance
 *
 * @param L Lua state.
 * @param wdh Pointer to the wtap_dumper structure.
 */
extern void create_wdh_priv(lua_State* L, wtap_dumper *wdh);

/**
 * @brief Retrieves the private data table reference from a wtap_dumper structure.
 * @param L Lua state.
 * @param wdh Pointer to the wtap_dumper structure.
 * @return int Number of values on the stack.
 */
extern int get_wdh_priv_table_ref(lua_State* L, wtap_dumper *wdh);

/**
 * @brief Set or remove a Lua table reference in the wtap_dumper's private data.
 *
 * sets the private data to wtap - the table is presumed on top of stack
 *
 * @param L The Lua state.
 * @param wdh The wtap_dumper structure.
 * @return int Number of values on the stack.
 */
extern int set_wdh_priv_table_ref(lua_State* L, wtap_dumper *wdh);

/**
 * @brief Removes private data associated with a wtap_dumper.
 *
 * remove and deref the wtap_dumper->priv data
 *
 * @param L Lua state.
 * @param wdh Pointer to the wtap_dumper whose private data is to be removed.
 */
extern void remove_wdh_priv(lua_State* L, wtap_dumper *wdh);

/* implemented in other c files than wslua_file_common.c */

/**
 * @brief Pushes a CaptureInfo object onto the Lua stack.
 *
 * @param L The Lua state.
 * @param wth The wtap structure.
 * @param first_time Indicates if this is the first time the function is called.
 * @return A pointer to the pushed CaptureInfo object or NULL on error.
 */
extern CaptureInfo* push_CaptureInfo(lua_State* L, wtap *wth, const bool first_time);

/**
 * @brief Pushes a CaptureInfoConst object onto the Lua stack.
 *
 * @param L The Lua state.
 * @param wdh The wtap_dumper pointer.
 * @return A pointer to the pushed CaptureInfoConst object, or NULL if an error occurs.
 */
extern CaptureInfoConst* push_CaptureInfoConst(lua_State* L, wtap_dumper *wdh);

/**
 * @brief Pushes a File object onto the Lua stack.
 *
 * @param L The Lua state.
 * @param ft The FILE_T to wrap.
 * @return A pointer to the pushed File object.
 */
extern File* push_File(lua_State* L, FILE_T ft);

/**
 * @brief Pushes a wtap_dumper object to Lua.
 *
 * @param L The Lua state.
 * @param wdh The wtap_dumper object to push.
 * @return File* A pointer to the pushed File object.
 */
extern File* push_Wdh(lua_State* L, wtap_dumper *wdh);

/**
 * @brief Pushes a FrameInfo object onto the Lua stack.
 *
 * @param L The Lua state to push the FrameInfo onto.
 * @param rec The wtap_rec structure containing frame information.
 * @return A pointer to the pushed FrameInfo object.
 */
extern FrameInfo* push_FrameInfo(lua_State* L, wtap_rec *rec);

/**
 * @brief Pushes a FrameInfoConst object onto the Lua stack.
 *
 * @param L The Lua state to operate on.
 * @param rec A pointer to the wtap_rec structure representing the frame record.
 * @param pd A pointer to the packet data.
 * @return A pointer to the pushed FrameInfoConst object.
 */
extern FrameInfoConst* push_FrameInfoConst(lua_State* L, const wtap_rec *rec, const uint8_t *pd);


/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
