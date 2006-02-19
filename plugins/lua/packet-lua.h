/*
 * packet-lua.h
 *
 * Ethereal's interface to the Lua Programming Language
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _PACKET_LUA_H
#define _PACKET_LUA_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <errno.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <wiretap/wtap.h>
#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/epan_dissect.h>
#include <epan/tap.h>
#include <epan/filesystem.h>
#include <epan/report_err.h>
#include <epan/emem.h>
#include <epan/funnel.h>

#define LUA_DISSECTORS_TABLE "dissectors"
#define LUA_INIT_ROUTINES "init_routines"
#define LUA_HANDOFF_ROUTINES "handoff_routines"
#define LOG_DOMAIN_LUA "Lua"

struct _eth_tvbrange {
    tvbuff_t* tvb;
    int offset;
    int len;
};

typedef struct _eth_field_t {
    int hfid;
    char* name;
    char* abbr;
    char* blob;
    enum ftenum type;
    base_display_e base;
    value_string* vs;
    guint32 mask;
} eth_field_t;

typedef enum {PREF_NONE,PREF_BOOL,PREF_UINT,PREF_STRING} pref_type_t;

typedef struct _eth_pref_t {
    gchar* name;
    gchar* label;
    gchar* desc;
    pref_type_t type;
    union {
        gboolean b;
        guint u;
        const gchar* s;
    } value;
    
    struct _eth_pref_t* next;
    struct _eth_proto_t* proto;
} eth_pref_t;

typedef struct _eth_proto_t {
    int hfid;
    char* name;
    char* desc;
    hf_register_info* hfarray;
    gboolean hf_registered;
    module_t *prefs_module;
    eth_pref_t prefs;
    dissector_handle_t handle;
    gboolean is_postdissector;
} eth_proto_t;


typedef struct {const gchar* str; enum ftenum id; } eth_ft_types_t;

#define PROTO_FIELD "ProtoField"
typedef struct _eth_field_t* ProtoField;

#define PROTO_FIELD_ARRAY "ProtoFieldArray"
typedef GArray* ProtoFieldArray;

#define SUBTREE "SubTree"
typedef int* SubTree;

#define PROTO "Protocol"
typedef struct _eth_proto_t* Proto;

#define DISSECTOR_TABLE "DissectorTable"
typedef struct _eth_distbl_t {
    dissector_table_t table;
    gchar* name;
}* DissectorTable;

#define DISSECTOR "Dissector"
typedef dissector_handle_t Dissector;

#define BYTE_ARRAY "ByteArray"
typedef GByteArray* ByteArray;

#define TVB "Tvb"
typedef tvbuff_t* Tvb;

#define TVB_RANGE "TvbRange"
typedef struct _eth_tvbrange* TvbRange; 

#define COLUMN "Column"
typedef struct _eth_col_info {
    column_info* cinfo;
    gint col;
}* Column;

#define COLUMNS "Columns"
typedef column_info* Columns;

#define PINFO "Pinfo"
typedef packet_info* Pinfo;

#define PROTO_TREE "ProtoTree"
typedef proto_tree* ProtoTree;

#define ITEM "ProtoItem"
typedef proto_item* ProtoItem;

#define ADDRESS "Address"
typedef address* Address;

#define FIELD "Field"
typedef header_field_info** Field;

#define TAP "Tap"
typedef struct _eth_tap* Tap;

#define TEXT_WINDOW "TextWindow"
typedef funnel_text_window_t* TextWindow;

#define DUMPER "Dumper"
typedef wtap_dumper* Dumper;

#define PSEUDOHEADER "PseudoHeader"
typedef struct lua_pseudo_header* PseudoHeader;

#define NOP

/*
 * toXxx(L,idx) gets a Xxx from an index (Lua Error if fails)
 * checkXxx(L,idx) gets a Xxx from an index after calling check_code (No Lua Error if it fails)
 * pushXxx(L,xxx) pushes an Xxx into the stack
 * isXxx(L,idx) tests whether we have an Xxx at idx
 *
 * LUA_CLASS_DEFINE must be used without trailing ';'
 */
#define LUA_CLASS_DEFINE(C,CN,check_code) \
C to##C(lua_State* L, int index) { \
    C* v = (C*)lua_touserdata (L, index); \
    if (!v) luaL_typerror(L,index,CN); \
    return *v; \
} \
C check##C(lua_State* L, int index) { \
    C* p; \
    luaL_checktype(L,index,LUA_TUSERDATA); \
    p = (C*)luaL_checkudata(L, index, CN); \
    check_code; \
    return p ? *p : NULL; \
} \
C* push##C(lua_State* L, C v) { \
    C* p = lua_newuserdata(L,sizeof(C)); *p = v; \
    luaL_getmetatable(L, CN); lua_setmetatable(L, -2); \
    return p; \
}\
gboolean is##C(lua_State* L,int i) { \
        return (gboolean)(lua_isuserdata(L,i) && luaL_checkudata(L,3,CN)); \
} \
C shift##C(lua_State* L,int i) { \
    C* p; \
    if ((p = (C*)luaL_checkudata(L, i, CN))) {\
        lua_remove(L,i); \
        return *p; \
    } else { \
        return NULL; \
    } \
}


#ifdef HAVE_LUA_5_1

#define REGISTER_FULL_CLASS(CN,methods,meta) { \
	luaL_register (L, CN, methods); \
	luaL_newmetatable (L, CN); \
	luaL_register (L, NULL, meta); \
	lua_pushliteral(L, "__index"); \
	lua_pushvalue(L, -3); \
	lua_rawset(L, -3); \
	lua_pushliteral(L, "__metatable"); \
	lua_pushvalue(L, -3); \
	lua_rawset(L, -3); \
	lua_pop(L, 1); \
}

#define REGISTER_META(CN,meta) luaL_newmetatable (L, CN);   luaL_register (L, NULL, meta); 

#define INIT_LUA(L) L = luaL_newstate(); luaL_openlibs(L);

#else /* Lua 5.0 */

#define REGISTER_FULL_CLASS(CN,methods,meta) { \
	luaL_openlib(L, CN, methods, 0); \
	luaL_newmetatable(L, CN); \
	luaL_openlib(L, 0, meta, 0); \
	lua_pushliteral(L, "__index"); \
	lua_pushvalue(L, -3); \
	lua_rawset(L, -3); \
	lua_pushliteral(L, "__metatable"); \
	lua_pushvalue(L, -3); \
	lua_rawset(L, -3); \
	lua_pop(L, 1); \
}

#define REGISTER_META(CN,meta) luaL_newmetatable (L, CN); luaL_openlib (L, NULL, meta, 0);

#define INIT_LUA(L) L = lua_open(); luaopen_base(L); luaopen_table(L); luaopen_io(L); luaopen_string(L);

#endif


extern packet_info* lua_pinfo;
extern proto_tree* lua_tree;
extern tvbuff_t* lua_tvb;
extern int lua_malformed;
extern dissector_handle_t lua_data_handle;
extern gboolean lua_initialized;
extern int lua_dissectors_table_ref;

#define LUA_CLASS_DECLARE(C,CN) \
extern C to##C(lua_State* L, int index); \
extern C check##C(lua_State* L, int index); \
extern C* push##C(lua_State* L, C v); \
extern int C##_register(lua_State* L); \
extern gboolean is##C(lua_State* L,int i); \
extern C shift##C(lua_State* L,int i)



LUA_CLASS_DECLARE(Tap,TAP);
LUA_CLASS_DECLARE(Field,FIELD);
LUA_CLASS_DECLARE(ProtoField,PROTO_FIELD);
LUA_CLASS_DECLARE(ProtoFieldArray,PROTO_FIELD_ARRAY);
LUA_CLASS_DECLARE(SubTree,SUBTREE);
LUA_CLASS_DECLARE(Proto,PROTO);
LUA_CLASS_DECLARE(ByteArray,BYTE_ARRAY);
LUA_CLASS_DECLARE(Tvb,TVB);
LUA_CLASS_DECLARE(TvbRange,TVB_RANGE);
LUA_CLASS_DECLARE(Column,COLUMN);
LUA_CLASS_DECLARE(Columns,COLUMNS);
LUA_CLASS_DECLARE(Pinfo,PINFO);
LUA_CLASS_DECLARE(ProtoTree,TREE);
LUA_CLASS_DECLARE(ProtoItem,ITEM);
LUA_CLASS_DECLARE(Dissector,DISSECTOR);
LUA_CLASS_DECLARE(DissectorTable,DISSECTOR_TABLE);
LUA_CLASS_DECLARE(Address,ADDRESS);
LUA_CLASS_DECLARE(TextWindow,TEXT_WINDOW);
LUA_CLASS_DECLARE(Dumper,DUMPER);
LUA_CLASS_DECLARE(PseudoHeader,PSEUDOHEADER);

extern void dissect_lua(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree);
extern int lua_tap_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt, const void *data _U_);
extern void lua_tap_reset(void *tapdata);
extern void lua_tap_draw(void *tapdata);

extern const gchar* lua_shiftstring(lua_State* L,int idx);

extern int lua_register_menu(lua_State* L);
extern int lua_new_dialog(lua_State* L);
extern int lua_gui_enabled(lua_State* L);
extern void proto_register_lua(void);
extern GString* lua_register_all_taps(void);
extern void lua_prime_all_fields(proto_tree* tree);
extern void lua_register_subtrees(void);

extern void push_Tvb(lua_State* L, Tvb tvb);
extern void clear_outstanding_tvbs(void);

extern void push_Pinfo(lua_State* L, Pinfo p);
extern void clear_outstanding_pinfos(void);

extern void push_ProtoTree(lua_State* L, ProtoTree t);
extern void clear_outstanding_trees(void);

#endif
