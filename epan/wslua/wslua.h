/*
 * wslua.h
 *
 * Wireshark's interface to the Lua Programming Language
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 * (c) 2007, Tamas Regos <tamas.regos@ericsson.com>
 * (c) 2008, Balint Reczey <balint.reczey@ericsson.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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

#include <glib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
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
#include <epan/tvbparse.h>
#include <epan/epan.h>
#include <epan/nstime.h>

#include "declare_wslua.h"

/** @file
 * @ingroup wslua_group
 */

#define WSLUA_INIT_ROUTINES "init_routines"
#define LOG_DOMAIN_LUA "wslua"

struct _wslua_tvb {
    tvbuff_t* ws_tvb;
    gboolean expired;
};

struct _wslua_pinfo {
    packet_info* ws_pinfo;
    gboolean expired;
};

struct _wslua_tvbrange {
    struct _wslua_tvb* tvb;
    int offset;
    int len;
};

struct _wslua_tw {
    funnel_text_window_t* ws_tw;
    gboolean expired;
};

typedef struct _wslua_field_t {
    int hfid;
    int ett;
    char* name;
    char* abbr;
    char* blob;
    enum ftenum type;
    base_display_e base;
    const void* vs;
    guint32 mask;
} wslua_field_t;

/**
 * PREF_OBSOLETE is used for preferences that a module used to support
 * but no longer supports; we give different error messages for them.
 */
typedef enum {
    PREF_UINT,
    PREF_BOOL,
    PREF_ENUM,
    PREF_STRING,
    PREF_RANGE,
    PREF_STATIC_TEXT,
    PREF_OBSOLETE
} pref_type_t;

typedef struct _wslua_pref_t {
    gchar* name;
    gchar* label;
    gchar* desc;
    pref_type_t type;
    union {
        gboolean b;
        guint u;
        const gchar* s;
        gint e;
        range_t *r;
        void* p;
    } value;
    union {
      guint32 max_value;		/**< maximum value of a range */
      struct {
          const enum_val_t *enumvals;    /**< list of name & values */
          gboolean radio_buttons;    /**< TRUE if it should be shown as
                         radio buttons rather than as an
                         option menu or combo box in
                         the preferences tab */
      } enum_info;            /**< for PREF_ENUM */
    } info;                    /**< display/text file information */

    struct _wslua_pref_t* next;
    struct _wslua_proto_t* proto;
} wslua_pref_t;

typedef struct _wslua_proto_t {
    gchar* name;
    gchar* desc;
    int hfid;
    int ett;
    wslua_pref_t prefs;
    int fields;
    module_t *prefs_module;
    dissector_handle_t handle;
    gboolean is_postdissector;
} wslua_proto_t;

struct _wslua_distbl_t {
    dissector_table_t table;
    gchar* name;
};

struct _wslua_col_info {
    column_info* cinfo;
    gint col;
    gboolean expired;
};

struct _wslua_cols {
    column_info* cinfo;
    gboolean expired;
};

struct _wslua_treeitem {
    proto_item* item;
    proto_tree* tree;
    gboolean expired;
};

typedef void (*tap_extractor_t)(lua_State*,const void*);

struct _wslua_tap {
    gchar* name;
    gchar* filter;
    tap_extractor_t extractor;
    lua_State* L;
    int packet_ref;
    int draw_ref;
    int init_ref;
};

#  define DIRECTORY_T GDir
#  define FILE_T gchar
#  define OPENDIR_OP(name) g_dir_open(name, 0, dir->dummy)
#  define DIRGETNEXT_OP(dir) g_dir_read_name(dir)
#  define GETFNAME_OP(file) (file);
#  define CLOSEDIR_OP(dir) g_dir_close(dir)

struct _wslua_dir {
    DIRECTORY_T* dir;
    char* ext;
    GError** dummy;
};

struct _wslua_progdlg {
    funnel_progress_window_t* pw;
    char* title;
    char* task;
    gboolean stopped;
};

typedef struct { const char* name; tap_extractor_t extractor; } tappable_t;

typedef struct {const gchar* str; enum ftenum id; } wslua_ft_types_t;

typedef wslua_pref_t* Pref;
typedef wslua_pref_t* Prefs;
typedef struct _wslua_field_t* ProtoField;
typedef struct _wslua_proto_t* Proto;
typedef struct _wslua_distbl_t* DissectorTable;
typedef dissector_handle_t Dissector;
typedef GByteArray* ByteArray;
typedef struct _wslua_tvb* Tvb;
typedef struct _wslua_tvbrange* TvbRange; 
typedef struct _wslua_col_info* Column;
typedef struct _wslua_cols* Columns;
typedef struct _wslua_pinfo* Pinfo;
typedef struct _wslua_treeitem* TreeItem;
typedef address* Address;
typedef nstime_t* NSTime;
typedef gint64* Int64;
typedef guint64* UInt64;
typedef header_field_info** Field;
typedef field_info* FieldInfo;
typedef struct _wslua_tap* Listener;
typedef struct _wslua_tw* TextWindow;
typedef struct _wslua_progdlg* ProgDlg;
typedef wtap_dumper* Dumper;
typedef struct lua_pseudo_header* PseudoHeader;
typedef tvbparse_t* Parser;
typedef tvbparse_wanted_t* Rule;
typedef tvbparse_elem_t* Node;
typedef tvbparse_action_t* Shortcut;
typedef struct _wslua_main* WireShark;
typedef struct _wslua_dir* Dir;

/*
 * toXxx(L,idx) gets a Xxx from an index (Lua Error if fails)
 * checkXxx(L,idx) gets a Xxx from an index after calling check_code (No Lua Error if it fails)
 * pushXxx(L,xxx) pushes an Xxx into the stack
 * isXxx(L,idx) tests whether we have an Xxx at idx
 * shiftXxx(L,idx) removes and returns an Xxx from idx only if it has a type of Xxx, returns NULL otherwise
 * WSLUA_CLASS_DEFINE must be used with a trailing ';'
 * (a dummy typedef is used to be syntactically correct)
 */
#define WSLUA_CLASS_DEFINE(C,check_code,push_code) \
C to##C(lua_State* L, int idx) { \
    C* v = (C*)lua_touserdata (L, idx); \
    if (!v) luaL_typerror(L,idx,#C); \
    return *v; \
} \
C check##C(lua_State* L, int idx) { \
    C* p; \
    luaL_checktype(L,idx,LUA_TUSERDATA); \
    p = (C*)luaL_checkudata(L, idx, #C); \
    check_code; \
    return p ? *p : NULL; \
} \
C* push##C(lua_State* L, C v) { \
    C* p; \
    luaL_checkstack(L,2,"Unable to grow stack\n"); \
    p = lua_newuserdata(L,sizeof(C)); *p = v; \
    luaL_getmetatable(L, #C); lua_setmetatable(L, -2); \
    push_code; \
    return p; \
}\
gboolean is##C(lua_State* L,int i) { \
    void *p; \
    if(!lua_isuserdata(L,i)) return FALSE; \
    p = lua_touserdata(L, i); \
    lua_getfield(L, LUA_REGISTRYINDEX, #C); \
    if (p == NULL || !lua_getmetatable(L, i) || !lua_rawequal(L, -1, -2)) p=NULL; \
    lua_pop(L, 2); \
    return p ? TRUE : FALSE; \
} \
C shift##C(lua_State* L,int i) { \
    C* p; \
    if(!lua_isuserdata(L,i)) return NULL; \
    p = lua_touserdata(L, i); \
    lua_getfield(L, LUA_REGISTRYINDEX, #C); \
    if (p == NULL || !lua_getmetatable(L, i) || !lua_rawequal(L, -1, -2)) p=NULL; \
    lua_pop(L, 2); \
    if (p) { lua_remove(L,i); return *p; }\
    else return NULL;\
} \
typedef int dummy##C

#ifdef HAVE_LUA_5_1

#define WSLUA_REGISTER_CLASS(C) { \
    luaL_register (L, #C, C ## _methods); \
    luaL_newmetatable (L, #C); \
    luaL_register (L, NULL, C ## _meta); \
    lua_pushliteral(L, "__index"); \
    lua_pushvalue(L, -3); \
    lua_rawset(L, -3); \
    lua_pushliteral(L, "__metatable"); \
    lua_pushvalue(L, -3); \
    lua_rawset(L, -3); \
    lua_pop(L, 2); \
}

#define WSLUA_REGISTER_META(C) { \
    luaL_newmetatable (L, #C); \
    luaL_register (L, NULL, C ## _meta); \
    lua_pop(L,1); \
}

#define WSLUA_INIT(L) \
    luaL_openlibs(L); \
    wslua_register_classes(L); \
    wslua_register_functions(L);

#endif

#define WSLUA_FUNCTION extern int 
#define WSLUA_REGISTER_FUNCTION(name)     { lua_pushstring(L, #name); lua_pushcfunction(L, wslua_## name); lua_settable(L, LUA_GLOBALSINDEX); }
#define WSLUA_REGISTER extern int

#define WSLUA_METHOD static int 
#define WSLUA_CONSTRUCTOR static int 
#define WSLUA_ATTR_SET static int 
#define WSLUA_ATTR_GET static int 
#define WSLUA_METAMETHOD static int

#define WSLUA_METHODS static const luaL_reg 
#define WSLUA_META static const luaL_reg
#define WSLUA_CLASS_FNREG(class,name) { #name, class##_##name }

#define WSLUA_ERROR(name,error) { luaL_error(L, ep_strdup_printf("%s%s", #name ": " ,error) ); return 0; }
#define WSLUA_ARG_ERROR(name,attr,error) { luaL_argerror(L,WSLUA_ARG_ ## name ## _ ## attr, #name  ": " error); return 0; }
#define WSLUA_OPTARG_ERROR(name,attr,error) { luaL_argerror(L,WSLUA_OPTARG_##name##_ ##attr, #name  ": " error); return 0; }

#define WSLUA_REG_GLOBAL_BOOL(L,n,v) { lua_pushstring(L,n); lua_pushboolean(L,v); lua_settable(L, LUA_GLOBALSINDEX); }
#define WSLUA_REG_GLOBAL_STRING(L,n,v) { lua_pushstring(L,n); lua_pushstring(L,v); lua_settable(L, LUA_GLOBALSINDEX); }
#define WSLUA_REG_GLOBAL_NUMBER(L,n,v) { lua_pushstring(L,n); lua_pushnumber(L,v); lua_settable(L, LUA_GLOBALSINDEX); }

#define WSLUA_RETURN(i) return (i);

#define WSLUA_API extern

#define NOP
#define FAIL_ON_NULL(s) if (! *p) luaL_argerror(L,idx,s)

/* Clears or marks references that connects Lua to Wireshark structures */
#define CLEAR_OUTSTANDING(C, marker, marker_val) void clear_outstanding_##C(void) { \
    while (outstanding_##C->len) { \
        C p = (C)g_ptr_array_remove_index_fast(outstanding_##C,0); \
        if (p) { \
            if (p->marker != marker_val) \
                p->marker = marker_val; \
            else \
                g_free(p); \
        } \
    } \
} 

#define WSLUA_CLASS_DECLARE(C) \
extern C to##C(lua_State* L, int idx); \
extern C check##C(lua_State* L, int idx); \
extern C* push##C(lua_State* L, C v); \
extern int C##_register(lua_State* L); \
extern gboolean is##C(lua_State* L,int i); \
extern C shift##C(lua_State* L,int i)

extern packet_info* lua_pinfo;
extern TreeItem lua_tree;
extern tvbuff_t* lua_tvb;
extern int lua_malformed;
extern dissector_handle_t lua_data_handle;
extern gboolean lua_initialized;
extern int lua_dissectors_table_ref;

WSLUA_DECLARE_CLASSES()
WSLUA_DECLARE_FUNCTIONS()

extern lua_State* wslua_state(void);

extern gboolean wslua_optbool(lua_State* L, int n, gboolean def);
extern const gchar* lua_shiftstring(lua_State* L,int idx);
extern int dissect_lua(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree);

extern void proto_register_lua(void);
extern GString* lua_register_all_taps(void);
extern void lua_prime_all_fields(proto_tree* tree);

extern int Proto_commit(lua_State* L);

extern Tvb* push_Tvb(lua_State* L, tvbuff_t* tvb);
extern void clear_outstanding_Tvb(void);

extern Pinfo* push_Pinfo(lua_State* L, packet_info* p);
extern void clear_outstanding_Pinfo(void);
extern void clear_outstanding_Column(void);
extern void clear_outstanding_Columns(void);

extern TreeItem* push_TreeItem(lua_State* L, TreeItem ti);
extern void clear_outstanding_TreeItem(void);

extern void wslua_print_stack(char* s, lua_State* L);

extern int wslua_init(register_cb cb, gpointer client_data);

extern tap_extractor_t wslua_get_tap_extractor(const gchar* name);
extern int wslua_set_tap_enums(lua_State* L);

extern int luaopen_bit(lua_State *L);

#endif
