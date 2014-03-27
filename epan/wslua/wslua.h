/*
 * wslua.h
 *
 * Wireshark's interface to the Lua Programming Language
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 * (c) 2007, Tamas Regos <tamas.regos@ericsson.com>
 * (c) 2008, Balint Reczey <balint.reczey@ericsson.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _PACKET_LUA_H
#define _PACKET_LUA_H

#include <glib.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <wiretap/wtap.h>

#include <wsutil/report_err.h>
#include <wsutil/nstime.h>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/to_str.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/epan_dissect.h>
#include <epan/tap.h>
#include <epan/column-utils.h>
#include <wsutil/filesystem.h>
#include <epan/funnel.h>
#include <epan/tvbparse.h>
#include <epan/epan.h>
#include <epan/expert.h>

#include "declare_wslua.h"

/** @file
 * @ingroup wslua_group
 */

#define WSLUA_INIT_ROUTINES "init_routines"
#define WSLUA_PREFS_CHANGED "prefs_changed"
#define LOG_DOMAIN_LUA "wslua"

/* type conversion macros - lua_Number is a double, so casting isn't kosher; and
   using Lua's already-available lua_tointeger() and luaL_checkint() might be different
   on different machines; so use these instead please! */
#define wslua_togint(L,i)       (gint)            ( lua_tointeger(L,i) )
#define wslua_togint32(L,i)     (gint32)          ( lua_tonumber(L,i) )
#define wslua_togint64(L,i)     (gint64)          ( lua_tonumber(L,i) )
#define wslua_toguint(L,i)      (guint)           ( lua_tointeger(L,i) )
#define wslua_toguint32(L,i)    (guint32)         ( lua_tonumber(L,i) )
#define wslua_toguint64(L,i)    (guint64)         ( lua_tonumber(L,i) )

#define wslua_checkgint(L,i)    (gint)            ( luaL_checkint(L,i) )
#define wslua_checkgint32(L,i)  (gint32)          ( luaL_checknumber(L,i) )
#define wslua_checkgint64(L,i)  (gint64)          ( luaL_checknumber(L,i) )
#define wslua_checkguint(L,i)   (guint)           ( luaL_checkint(L,i) )
#define wslua_checkguint32(L,i) (guint32)         ( luaL_checknumber(L,i) )
#define wslua_checkguint64(L,i) (guint64)         ( luaL_checknumber(L,i) )

#define wslua_optgint(L,i,d)    (gint)            ( luaL_optint(L,i,d) )
#define wslua_optgint32(L,i,d)  (gint32)          ( luaL_optnumber(L,i,d) )
#define wslua_optgint64(L,i,d)  (gint64)          ( luaL_optnumber(L,i,d) )
#define wslua_optguint(L,i,d)   (guint)           ( luaL_optint(L,i,d) )
#define wslua_optguint32(L,i,d) (guint32)         ( luaL_optnumber(L,i,d) )
#define wslua_optguint64(L,i,d) (guint64)         ( luaL_optnumber(L,i,d) )


struct _wslua_tvb {
    tvbuff_t* ws_tvb;
    gboolean expired;
    gboolean need_free;
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
    unsigned base;
    const void* vs;
    guint32 mask;
} wslua_field_t;

typedef struct _wslua_expert_field_t {
    expert_field ids;
    const gchar *abbr;
    const gchar *text;
    int group;
    int severity;
} wslua_expert_field_t;

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
        gchar* s;
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
    int expert_info_table_ref;
    expert_module_t *expert_module;
    module_t *prefs_module;
    dissector_handle_t handle;
    gboolean is_postdissector;
} wslua_proto_t;

struct _wslua_distbl_t {
    dissector_table_t table;
    const gchar* name;
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

struct _wslua_private_table {
    GHashTable *table;
    gboolean is_allocated;
    gboolean expired;
};

struct _wslua_treeitem {
    proto_item* item;
    proto_tree* tree;
    gboolean expired;
};

struct _wslua_field_info {
    field_info *ws_fi;
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
    int reset_ref;
    gboolean all_fields;
};

/* a "File" object can be different things under the hood. It can either
   be a FILE_T from wtap struct, which it is during read operations, or it
   can be a wtap_dumper struct during write operations. A wtap_dumper struct
   has a FILE_T member, but we can't only store its pointer here because
   dump operations need the whole thing to write out with. Ugh. */
struct _wslua_file {
    FILE_T   file;
    wtap_dumper *wdh;   /* will be NULL during read usage */
    gboolean expired;
};

/* a "CaptureInfo" object can also be different things under the hood. */
struct _wslua_captureinfo {
    wtap *wth;          /* will be NULL during write usage */
    wtap_dumper *wdh;   /* will be NULL during read usage */
    gboolean expired;
};

struct _wslua_phdr {
    struct wtap_pkthdr *phdr; /* this also exists in wtap struct, but is different for seek_read ops */
    Buffer *buf;              /* can't use the one in wtap because it's different for seek_read ops */
    gboolean expired;
};

struct _wslua_const_phdr {
    const struct wtap_pkthdr *phdr;
    const guint8 *pd;
    gboolean expired;
};

struct _wslua_filehandler {
    struct file_type_subtype_info finfo;
    gboolean is_reader;
    gboolean is_writer;
    gchar* description;
    gchar* type;
    gchar* extensions;
    lua_State* L;
    int read_open_ref;
    int read_ref;
    int seek_read_ref;
    int read_close_ref;
    int seq_read_close_ref;
    int can_write_encap_ref;
    int write_open_ref;
    int write_ref;
    int write_close_ref;
    int file_type;
    gboolean registered;
};

struct _wslua_dir {
    GDir* dir;
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
typedef struct _wslua_expert_field_t* ProtoExpert;
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
typedef gint64 Int64;
typedef guint64 UInt64;
typedef header_field_info** Field;
typedef struct _wslua_field_info* FieldInfo;
typedef struct _wslua_tap* Listener;
typedef struct _wslua_tw* TextWindow;
typedef struct _wslua_progdlg* ProgDlg;
typedef struct _wslua_file* File;
typedef struct _wslua_captureinfo* CaptureInfo;
typedef struct _wslua_captureinfo* CaptureInfoConst;
typedef struct _wslua_phdr* FrameInfo;
typedef struct _wslua_const_phdr* FrameInfoConst;
typedef struct _wslua_filehandler* FileHandler;
typedef wtap_dumper* Dumper;
typedef struct lua_pseudo_header* PseudoHeader;
typedef tvbparse_t* Parser;
typedef tvbparse_wanted_t* Rule;
typedef tvbparse_elem_t* Node;
typedef tvbparse_action_t* Shortcut;
typedef struct _wslua_main* WireShark;
typedef struct _wslua_dir* Dir;
typedef struct _wslua_private_table* PrivateTable;
typedef gchar* Struct;

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
    WSLUA_CLASS_DEFINE_BASE(C,check_code,push_code,NULL)

#define WSLUA_CLASS_DEFINE_BASE(C,check_code,push_code,retval) \
C to##C(lua_State* L, int idx) { \
    C* v = (C*)lua_touserdata (L, idx); \
    if (!v) luaL_error(L, "bad argument %d (%s expected, got %s)", idx, #C, lua_typename(L, lua_type(L, idx))); \
    return v ? *v : retval; \
} \
C check##C(lua_State* L, int idx) { \
    C* p; \
    luaL_checktype(L,idx,LUA_TUSERDATA); \
    p = (C*)luaL_checkudata(L, idx, #C); \
    check_code; \
    return p ? *p : retval; \
} \
C* push##C(lua_State* L, C v) { \
    C* p; \
    luaL_checkstack(L,2,"Unable to grow stack\n"); \
    p = (C*)lua_newuserdata(L,sizeof(C)); *p = v; \
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
    if(!lua_isuserdata(L,i)) return retval; \
    p = (C*)lua_touserdata(L, i); \
    lua_getfield(L, LUA_REGISTRYINDEX, #C); \
    if (p == NULL || !lua_getmetatable(L, i) || !lua_rawequal(L, -1, -2)) p=NULL; \
    lua_pop(L, 2); \
    if (p) { lua_remove(L,i); return *p; }\
    else return retval;\
} \
typedef int dummy##C

typedef struct _wslua_attribute_table {
    const gchar  *fieldname;
    lua_CFunction getfunc;
    lua_CFunction setfunc;
} wslua_attribute_table;
extern int wslua_reg_attributes(lua_State *L, const wslua_attribute_table *t, gboolean is_getter);
extern int wslua_set__index(lua_State *L);

#define WSLUA_TYPEOF_FIELD "__typeof"

#ifdef HAVE_LUA

#define WSLUA_REGISTER_META(C) { \
    /* check for existing metatable in registry */ \
    luaL_getmetatable(L, #C); \
    if (!lua_isnil (L, -1)) { \
        fprintf(stderr, "ERROR: Attempt to register metatable '%s' which already exists in Lua registry\n", #C); \
        exit(1); \
    } \
    lua_pop (L, 1); \
    /* create a new metatable and register metamethods into it */ \
    luaL_newmetatable (L, #C); \
    wslua_setfuncs (L, C ## _meta, 0); \
    /* add a metatable field named '__typeof' = the class name, this is used by the typeof() Lua func */ \
    lua_pushstring(L, #C); \
    lua_setfield(L, -2, WSLUA_TYPEOF_FIELD); \
     /* add the '__gc' metamethod with a C-function named Class__gc */ \
    /* this will force ALL wslua classes to have a Class__gc function defined, which is good */ \
    lua_pushcfunction(L, C ## __gc); \
    lua_setfield(L, -2, "__gc"); \
    /* pop the metatable */ \
    lua_pop(L, 1); \
}

#define WSLUA_REGISTER_CLASS(C) { \
    /* check for existing class table in global */ \
    lua_getglobal (L, #C); \
    if (!lua_isnil (L, -1)) { \
        fprintf(stderr, "ERROR: Attempt to register class '%s' which already exists in global Lua table\n", #C); \
        exit(1); \
    } \
    lua_pop (L, 1); \
    /* create new class method table and 'register' the class methods into it */ \
    lua_newtable (L); \
    wslua_setfuncs (L, C ## _methods, 0); \
    /* add a method-table field named '__typeof' = the class name, this is used by the typeof() Lua func */ \
    lua_pushstring(L, #C); \
    lua_setfield(L, -2, WSLUA_TYPEOF_FIELD); \
    /* setup the meta table */ \
    WSLUA_REGISTER_META(C); \
    luaL_getmetatable(L, #C); \
    /* the following sets the __index metamethod appropriately */ \
    wslua_set__index(L); \
    /* set the metatable to be the class's metatable, so scripts can inspect it, and metamethods work for class tables */ \
    lua_setmetatable(L, -2); \
    /* set the class methods table as the global class table */ \
    lua_setglobal (L, #C); \
}

/* see comments for wslua_reg_attributes and wslua_attribute_dispatcher to see how this attribute stuff works */
#define WSLUA_REGISTER_ATTRIBUTES(C) { \
    /* get metatable from Lua registry */ \
    luaL_getmetatable(L, #C); \
    if (lua_isnil(L, -1)) { \
        fprintf(stderr, "ERROR: Attempt to register attributes without a pre-existing metatable for '%s' in Lua registry\n", #C); \
        exit(1); \
    } \
    /* register the getters/setters in their tables */ \
    wslua_reg_attributes(L, C##_attributes, TRUE); \
    wslua_reg_attributes(L, C##_attributes, FALSE); \
    lua_pop(L, 1); /* pop the metatable */ \
}

#define WSLUA_INIT(L) \
    luaL_openlibs(L); \
    wslua_register_classes(L); \
    wslua_register_functions(L);

#endif

#define WSLUA_FUNCTION extern int

#define WSLUA_REGISTER_FUNCTION(name)     { lua_pushcfunction(L, wslua_## name); lua_setglobal(L, #name); }

#define WSLUA_REGISTER extern int

#define WSLUA_METHOD static int
#define WSLUA_CONSTRUCTOR static int
#define WSLUA_ATTR_SET static int
#define WSLUA_ATTR_GET static int
#define WSLUA_METAMETHOD static int

#define WSLUA_METHODS static const luaL_Reg
#define WSLUA_META static const luaL_Reg
#define WSLUA_CLASS_FNREG(class,name) { #name, class##_##name }
#define WSLUA_CLASS_FNREG_ALIAS(class,aliasname,name) { #aliasname, class##_##name }
#define WSLUA_CLASS_MTREG(class,name) { "__" #name, class##__##name }

#define WSLUA_ATTRIBUTES static const wslua_attribute_table
/* following are useful macros for the rows in the array created by above */
#define WSLUA_ATTRIBUTE_RWREG(class,name) { #name, class##_get_##name, class##_set_##name }
#define WSLUA_ATTRIBUTE_ROREG(class,name) { #name, class##_get_##name, NULL }
#define WSLUA_ATTRIBUTE_WOREG(class,name) { #name, NULL, class##_set_##name }

#define WSLUA_ATTRIBUTE_FUNC_SETTER(C,field) \
    static int C##_set_##field (lua_State* L) { \
        C obj = check##C (L,1); \
        if (! lua_isfunction(L,-1) ) \
            return luaL_error(L, "%s's attribute `%s' must be a function", #C , #field ); \
        if (obj->field##_ref != LUA_NOREF) \
            /* there was one registered before, remove it */ \
            luaL_unref(L, LUA_REGISTRYINDEX, obj->field##_ref); \
        obj->field##_ref = luaL_ref(L, LUA_REGISTRYINDEX); \
        return 0; \
    } \
    /* silly little trick so we can add a semicolon after this macro */ \
    static int C##_set_##field(lua_State*)

#define WSLUA_ATTRIBUTE_GET(C,name,block) \
    static int C##_get_##name (lua_State* L) { \
        C obj = check##C (L,1); \
        block \
        return 1; \
    } \
    /* silly little trick so we can add a semicolon after this macro */ \
    static int C##_get_##name(lua_State*)

#define WSLUA_ATTRIBUTE_NAMED_BOOLEAN_GETTER(C,name,member) \
    WSLUA_ATTRIBUTE_GET(C,name,{lua_pushboolean(L, obj->member );})

#define WSLUA_ATTRIBUTE_NAMED_NUMBER_GETTER(C,name,member) \
    WSLUA_ATTRIBUTE_GET(C,name,{lua_pushnumber(L,(lua_Number)(obj->member));})

#define WSLUA_ATTRIBUTE_NUMBER_GETTER(C,member) \
    WSLUA_ATTRIBUTE_NAMED_NUMBER_GETTER(C,member,member)

#define WSLUA_ATTRIBUTE_BLOCK_NUMBER_GETTER(C,name,block) \
    WSLUA_ATTRIBUTE_GET(C,name,{lua_pushnumber(L,(lua_Number)(block));})

#define WSLUA_ATTRIBUTE_NAMED_STRING_GETTER(C,name,member) \
    WSLUA_ATTRIBUTE_GET(C,name, { \
        lua_pushstring(L,obj->member); /* this pushes nil if obj->member is null */ \
    })

#define WSLUA_ATTRIBUTE_STRING_GETTER(C,member) \
    WSLUA_ATTRIBUTE_NAMED_STRING_GETTER(C,member,member)


#define WSLUA_ATTRIBUTE_SET(C,name,block) \
    static int C##_set_##name (lua_State* L) { \
        C obj = check##C (L,1); \
        block; \
        return 0; \
    } \
    /* silly little trick so we can add a semicolon after this macro */ \
    static int C##_set_##name(lua_State*)

#define WSLUA_ATTRIBUTE_NAMED_BOOLEAN_SETTER(C,name,member) \
    WSLUA_ATTRIBUTE_SET(C,name, { \
        if (! lua_isboolean(L,-1) ) \
            return luaL_error(L, "%s's attribute `%s' must be a boolean", #C , #name ); \
        obj->member = lua_toboolean(L,-1); \
    })

/* to make this integral-safe, we treat it as int32 and then cast
   Note: this will truncate 64-bit integers (but then Lua itself only has doubles */
#define WSLUA_ATTRIBUTE_NAMED_NUMBER_SETTER(C,name,member,cast) \
    WSLUA_ATTRIBUTE_SET(C,name, { \
        if (! lua_isnumber(L,-1) ) \
            return luaL_error(L, "%s's attribute `%s' must be a number", #C , #name ); \
        obj->member = (cast) wslua_togint32(L,-1); \
    })

#define WSLUA_ATTRIBUTE_NUMBER_SETTER(C,member,cast) \
    WSLUA_ATTRIBUTE_NAMED_NUMBER_SETTER(C,member,member,cast)

#define WSLUA_ATTRIBUTE_NAMED_STRING_SETTER(C,field,member,need_free) \
    static int C##_set_##field (lua_State* L) { \
        C obj = check##C (L,1); \
        gchar* s = NULL; \
        if (lua_isstring(L,-1) || lua_isnil(L,-1)) { \
            s = g_strdup(lua_tostring(L,-1)); \
        } else { \
            return luaL_error(L, "%s's attribute `%s' must be a string or nil", #C , #field ); \
        } \
        if (obj->member != NULL && need_free) \
            g_free((void*) obj->member); \
        obj->member = s; \
        return 0; \
    } \
    /* silly little trick so we can add a semicolon after this macro */ \
    static int C##_set_##field(lua_State*)

#define WSLUA_ATTRIBUTE_STRING_SETTER(C,field,need_free) \
    WSLUA_ATTRIBUTE_NAMED_STRING_SETTER(C,field,field,need_free)

#define WSLUA_ERROR(name,error) { luaL_error(L, "%s%s", #name ": " ,error); }
#define WSLUA_ARG_ERROR(name,attr,error) { luaL_argerror(L,WSLUA_ARG_ ## name ## _ ## attr, #name  ": " error); }
#define WSLUA_OPTARG_ERROR(name,attr,error) { luaL_argerror(L,WSLUA_OPTARG_##name##_ ##attr, #name  ": " error); }

#define WSLUA_REG_GLOBAL_BOOL(L,n,v) { lua_pushboolean(L,v); lua_setglobal(L,n); }
#define WSLUA_REG_GLOBAL_STRING(L,n,v) { lua_pushstring(L,v); lua_setglobal(L,n); }
#define WSLUA_REG_GLOBAL_NUMBER(L,n,v) { lua_pushnumber(L,v); lua_setglobal(L,n); }

#define WSLUA_RETURN(i) return (i);

#define WSLUA_API extern

/* empty macro arguments trigger ISO C90 warnings, so do this */
#define NOP (void)p

#define FAIL_ON_NULL(s) if (! *p) luaL_argerror(L,idx,"null " s)

#define FAIL_ON_NULL_MEMBER_OR_EXPIRED(s,member) if (!*p) { \
        luaL_argerror(L,idx,"null " s); \
    } else if ((*p)->member == NULL) { \
        luaL_argerror(L,idx,"null " s " member " #member); \
    } else if ((*p)->expired) { \
        luaL_argerror(L,idx,"expired " s); \
    }

#define FAIL_ON_NULL_OR_EXPIRED(s) if (!*p) { \
        luaL_argerror(L,idx,"null " s); \
    } else if ((*p)->expired) { \
        luaL_argerror(L,idx,"expired " s); \
    }

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
extern dissector_handle_t lua_data_handle;
extern gboolean lua_initialized;
extern int lua_dissectors_table_ref;
extern int lua_heur_dissectors_table_ref;

WSLUA_DECLARE_CLASSES()
WSLUA_DECLARE_FUNCTIONS()

extern lua_State* wslua_state(void);

extern int wslua__concat(lua_State* L);
extern gboolean wslua_toboolean(lua_State* L, int n);
extern gboolean wslua_checkboolean(lua_State* L, int n);
extern gboolean wslua_optbool(lua_State* L, int n, gboolean def);
extern lua_Integer wslua_tointeger(lua_State* L, int n);
extern int wslua_optboolint(lua_State* L, int n, int def);
extern const char* wslua_checklstring_only(lua_State* L, int n, size_t *l);
extern const char* wslua_checkstring_only(lua_State* L, int n);
extern const gchar* lua_shiftstring(lua_State* L,int idx);
extern void wslua_setfuncs(lua_State *L, const luaL_Reg *l, int nup);
extern const gchar* wslua_typeof_unknown;
extern const gchar* wslua_typeof(lua_State *L, int idx);
extern gboolean wslua_get_table(lua_State *L, int idx, const gchar *name);
extern gboolean wslua_get_field(lua_State *L, int idx, const gchar *name);
extern void wslua_assert_table_field_new(lua_State *L, int idx, const gchar *name);
extern int dissect_lua(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data);
extern int heur_dissect_lua(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data);
extern expert_field* wslua_get_expert_field(const int group, const int severity);
extern void wslua_prefs_changed(void);
extern void proto_register_lua(void);
extern GString* lua_register_all_taps(void);
extern void wslua_prime_dfilter(epan_dissect_t *edt);
extern void lua_prime_all_fields(proto_tree* tree);

extern int Proto_commit(lua_State* L);

extern void Int64_pack(lua_State* L, luaL_Buffer *b, gint idx, gboolean asLittleEndian);
extern int Int64_unpack(lua_State* L, const gchar *buff, gboolean asLittleEndian);
extern void UInt64_pack(lua_State* L, luaL_Buffer *b, gint idx, gboolean asLittleEndian);
extern int UInt64_unpack(lua_State* L, const gchar *buff, gboolean asLittleEndian);

extern Tvb* push_Tvb(lua_State* L, tvbuff_t* tvb);
extern gboolean push_TvbRange(lua_State* L, tvbuff_t* tvb, int offset, int len);
extern void clear_outstanding_Tvb(void);
extern void clear_outstanding_TvbRange(void);

extern Pinfo* push_Pinfo(lua_State* L, packet_info* p);
extern void clear_outstanding_Pinfo(void);
extern void clear_outstanding_Column(void);
extern void clear_outstanding_Columns(void);
extern void clear_outstanding_PrivateTable(void);

extern TreeItem* push_TreeItem(lua_State* L, TreeItem ti);
extern void clear_outstanding_TreeItem(void);

extern void clear_outstanding_FieldInfo(void);

extern void wslua_print_stack(char* s, lua_State* L);

extern int wslua_init(register_cb cb, gpointer client_data);
extern int wslua_cleanup(void);

extern tap_extractor_t wslua_get_tap_extractor(const gchar* name);
extern int wslua_set_tap_enums(lua_State* L);

extern int wslua_is_field_available(lua_State* L, const char* field_abbr);

extern char* wslua_get_actual_filename(const char* fname);

extern int wslua_bin2hex(lua_State* L, const guint8* data, const guint len, const gboolean lowercase, const gchar* sep);
extern int wslua_hex2bin(lua_State* L, const char* data, const guint len, const gchar* sep);
extern int luaopen_rex_glib(lua_State *L);

#endif
