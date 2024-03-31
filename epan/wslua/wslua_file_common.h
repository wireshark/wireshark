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
#include <wiretap/wtap-int.h>

/* this is way overkill for this one member, but in case we need to add
   more in the future, the plumbing will be here */
typedef struct _file_priv_t {
    int table_ref;
} file_priv_t;

/* create and set the wtap->priv private data for the file instance */
extern void create_wth_priv(lua_State* L, wtap *wth);

/* gets the private data table from wtap */
extern int get_wth_priv_table_ref(lua_State* L, wtap *wth);

/* sets the private data to wtap - the table is presumed on top of stack */
extern int set_wth_priv_table_ref(lua_State* L, wtap *wth);

/* remove, deref, and free the wtap->priv data */
extern void remove_wth_priv(lua_State* L, wtap *wth);

/* create and set the wtap_dumper->priv private data for the file instance */
extern void create_wdh_priv(lua_State* L, wtap_dumper *wdh);

/* get the private data from wtap_dumper */
extern int get_wdh_priv_table_ref(lua_State* L, wtap_dumper *wdh);

/* sets the private data to wtap - the table is presumed on top of stack */
extern int set_wdh_priv_table_ref(lua_State* L, wtap_dumper *wdh);

/* remove and deref the wtap_dumper->priv data */
extern void remove_wdh_priv(lua_State* L, wtap_dumper *wdh);

/* implemented in other c files than wslua_file_common.c */
extern CaptureInfo* push_CaptureInfo(lua_State* L, wtap *wth, const bool first_time);
extern CaptureInfoConst* push_CaptureInfoConst(lua_State* L, wtap_dumper *wdh);
extern File* push_File(lua_State* L, FILE_T ft);
extern File* push_Wdh(lua_State* L, wtap_dumper *wdh);
extern FrameInfo* push_FrameInfo(lua_State* L, wtap_rec *rec, Buffer* buf);
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
