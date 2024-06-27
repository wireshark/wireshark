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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _PACKET_LUA_H
#define _PACKET_LUA_H

#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <ws_log_defs.h>

#include <wiretap/wtap.h>

#include <wsutil/report_message.h>
#include <wsutil/nstime.h>
#include <wsutil/ws_assert.h>
#include <wsutil/wslog.h>

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

#include <epan/wslua/declare_wslua.h>

/** @file
 * @ingroup wslua_group
 */

#define WSLUA_INIT_ROUTINES "init_routines"
#define WSLUA_PREFS_CHANGED "prefs_changed"

/* type conversion macros - lua_Number is a double, so casting isn't kosher; and
   using Lua's already-available lua_tointeger() and luaL_checkinteger() might be
   different on different machines; so use these instead please!

   It can be important to choose the correct version of signed or unsigned
   conversion macros; don't assume that you can freely convert to the signed
   or unsigned integer of the same size later:

   On 32-bit Windows x86, Lua 5.2 and earlier must use lua_tounsigned() and
   luaL_checkunsigned() due to the use of float to integer inlined assembly.
   (#18367)
   On ARM, casting from a negative floating point number to an unsigned integer
   type doesn't perform wraparound conversion in the same way as casting from
   float to the same size signed integer then to unsigned does, unlike x86[-64].
   (Commit 15392c324d5eaefcaa298cdee09cd5b40b12e09c)

   On Lua 5.3 and later, numbers are stored as a kind of union between
   Lua_Number and Lua_Integer. On 5.2 and earlier. all numbers are stored
   as Lua_Number internally.

   Be careful about using the 64-bit functions, as they convert from double
   and lose precision at high values. See wslua_int64.c and the types there.
   TODO: Check if Lua_Integer is 64 bit on Lua 5.3 and later.
*/
#define wslua_toint(L,i)       (int)             ( lua_tointeger(L,i) )
#define wslua_toint32(L,i)     (int32_t)         ( lua_tointeger(L,i) )
#define wslua_toint64(L,i)     (int64_t)         ( lua_tonumber(L,i) )
#define wslua_touint64(L,i)    (uint64_t)        ( lua_tonumber(L,i) )

#define wslua_checkint(L,i)    (int)             ( luaL_checkinteger(L,i) )
#define wslua_checkint32(L,i)  (int32_t)         ( luaL_checkinteger(L,i) )
#define wslua_checkint64(L,i)  (int64_t)         ( luaL_checknumber(L,i) )
#define wslua_checkuint64(L,i) (uint64_t)        ( luaL_checknumber(L,i) )

#define wslua_optint(L,i,d)    (int)             ( luaL_optinteger(L,i,d) )
#define wslua_optint32(L,i,d)  (int32_t)         ( luaL_optinteger(L,i,d) )
#define wslua_optint64(L,i,d)  (int64_t)         ( luaL_optnumber(L,i,d) )
#define wslua_optuint64(L,i,d) (uint64_t)        ( luaL_optnumber(L,i,d) )

/**
 * On Lua 5.3 and later, the unsigned conversions may not be defined
 * (depending on a compatibility define), and they're just casts if they
 * are.
 */
#if LUA_VERSION_NUM < 503
#define wslua_touint(L,i)      (unsigned)        ( lua_tounsigned(L,i) )
#define wslua_touint32(L,i)    (uint32_t)        ( lua_tounsigned(L,i) )
#define wslua_checkuint(L,i)   (unsigned)        ( luaL_checkunsigned(L,i) )
#define wslua_checkuint32(L,i) (uint32_t)        ( luaL_checkunsigned(L,i) )
#define wslua_optuint(L,i,d)   (unsigned)        ( luaL_optunsigned(L,i,d) )
#define wslua_optuint32(L,i,d) (uint32_t)        ( luaL_optunsigned(L,i,d) )
#else
#define wslua_touint(L,i)      (unsigned)        ( lua_tointeger(L,i) )
#define wslua_touint32(L,i)    (uint32_t)        ( lua_tointeger(L,i) )
#define wslua_checkuint(L,i)   (unsigned)        ( luaL_checkinteger(L,i) )
#define wslua_checkuint32(L,i) (uint32_t)        ( luaL_checkinteger(L,i) )
#define wslua_optuint(L,i,d)   (unsigned)        ( luaL_optinteger(L,i,d) )
#define wslua_optuint32(L,i,d) (uint32_t)        ( luaL_optinteger(L,i,d) )
#endif

struct _wslua_tvb {
    tvbuff_t* ws_tvb;
    bool expired;
    bool need_free;
};

struct _wslua_pinfo {
    packet_info* ws_pinfo;
    bool expired;
};

struct _wslua_tvbrange {
    struct _wslua_tvb* tvb;
    int offset;
    int len;
};

struct _wslua_tw {
    funnel_text_window_t* ws_tw;
    bool expired;
    void* close_cb_data;
};

typedef struct _wslua_field_t {
    int hfid;
    int ett;
    char* name;
    char* abbrev;
    char* blob;
    enum ftenum type;
    unsigned base;
    const void* vs;
    int valuestring_ref;
    uint64_t mask;
} wslua_field_t;

typedef struct _wslua_expert_field_t {
    expert_field ids;
    const char *abbrev;
    const char *text;
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
    char* name;
    char* label;
    char* desc;
    pref_type_t type;
    union {
        bool b;
        unsigned u;
        char* s;
        int e;
        range_t *r;
        void* p;
    } value;
    union {
      uint32_t max_value;         /**< maximum value of a range */
      struct {
          const enum_val_t *enumvals;    /**< list of name & values */
          bool radio_buttons;    /**< true if it should be shown as
                         radio buttons rather than as an
                         option menu or combo box in
                         the preferences tab */
      } enum_info;            /**< for PREF_ENUM */
      char* default_s;       /**< default value for value.s */
    } info;                    /**< display/text file information */

    struct _wslua_pref_t* next;
    struct _wslua_proto_t* proto;
    int ref;            /* Reference to enable Proto to deregister prefs. */
} wslua_pref_t;

typedef struct _wslua_proto_t {
    char* name;
    char* loname;
    char* desc;
    int hfid;
    int ett;
    wslua_pref_t prefs;
    int fields;
    int expert_info_table_ref;
    expert_module_t *expert_module;
    module_t *prefs_module;
    dissector_handle_t handle;
    GArray *hfa;
    GArray *etta;
    GArray *eia;
    bool is_postdissector;
    bool expired;
} wslua_proto_t;

/* a "DissectorTable" object can be different things under the hood,
 * since its heuristic_new() can create a heur_dissector_list_t that
 * needs to be deregistered. */
struct _wslua_distbl_t {
    dissector_table_t table;
    heur_dissector_list_t heur_list;
    const char* name;
    const char* ui_name;
    bool created;
    bool expired;
};

struct _wslua_col_info {
    column_info* cinfo;
    int col;
    bool expired;
};

struct _wslua_cols {
    column_info* cinfo;
    bool expired;
};

struct _wslua_private_table {
    GHashTable *table;
    bool is_allocated;
    bool expired;
};

struct _wslua_treeitem {
    proto_item* item;
    proto_tree* tree;
    bool expired;
};

// Internal structure for wslua_field.c to track info about registered fields.
struct _wslua_header_field_info {
    char *name;
    header_field_info *hfi;
};

struct _wslua_field_info {
    field_info *ws_fi;
    bool expired;
};

typedef void (*tap_extractor_t)(lua_State*,const void*);

struct _wslua_tap {
    char* name;
    char* filter;
    tap_extractor_t extractor;
    lua_State* L;
    int packet_ref;
    int draw_ref;
    int reset_ref;
    bool all_fields;
};

/* a "File" object can be different things under the hood. It can either
   be a FILE_T from wtap struct, which it is during read operations, or it
   can be a wtap_dumper struct during write operations. A wtap_dumper struct
   has a FILE_T member, but we can't only store its pointer here because
   dump operations need the whole thing to write out with. Ugh. */
struct _wslua_file {
    FILE_T   file;
    wtap_dumper *wdh;   /* will be NULL during read usage */
    bool expired;
};

/* a "CaptureInfo" object can also be different things under the hood. */
struct _wslua_captureinfo {
    wtap *wth;          /* will be NULL during write usage */
    wtap_dumper *wdh;   /* will be NULL during read usage */
    bool expired;
};

struct _wslua_phdr {
    wtap_rec *rec;      /* this also exists in wtap struct, but is different for seek_read ops */
    Buffer *buf;        /* can't use the one in wtap because it's different for seek_read ops */
    bool expired;
};

struct _wslua_const_phdr {
    const wtap_rec *rec;
    const uint8_t *pd;
    bool expired;
};

struct _wslua_filehandler {
    struct file_type_subtype_info finfo;
    bool is_reader;
    bool is_writer;
    char* internal_description; /* XXX - this is redundant; finfo.description should suffice */
    char* type;
    char* extensions;
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
    bool registered;
    bool removed; /* This is set during reload Lua plugins */
};

struct _wslua_dir {
    GDir* dir;
    char* ext;
};

struct _wslua_progdlg {
    struct progdlg* pw;
    char* title;
    char* task;
    bool stopped;
};

typedef struct { const char* name; tap_extractor_t extractor; } tappable_t;

typedef struct {const char* str; enum ftenum id; } wslua_ft_types_t;

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
typedef int64_t Int64;
typedef uint64_t UInt64;
typedef struct _wslua_header_field_info* Field;
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
typedef struct _wslua_dir* Dir;
typedef struct _wslua_private_table* PrivateTable;
typedef char* Struct;

/*
 * toXxx(L,idx) gets a Xxx from an index (Lua Error if fails)
 * checkXxx(L,idx) gets a Xxx from an index after calling check_code (No Lua Error if it fails)
 * pushXxx(L,xxx) pushes an Xxx into the stack
 * isXxx(L,idx) tests whether we have an Xxx at idx
 * shiftXxx(L,idx) removes and returns an Xxx from idx only if it has a type of Xxx, returns NULL otherwise
 * WSLUA_CLASS_DEFINE must be used with a trailing ';'
 * (a dummy typedef is used to be syntactically correct)
 */
#define WSLUA_CLASS_DEFINE(C,check_code) \
    WSLUA_CLASS_DEFINE_BASE(C,check_code,NULL)

#define WSLUA_CLASS_DEFINE_BASE(C,check_code,retval) \
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
    return p; \
}\
bool is##C(lua_State* L,int i) { \
    void *p; \
    if(!lua_isuserdata(L,i)) return false; \
    p = lua_touserdata(L, i); \
    lua_getfield(L, LUA_REGISTRYINDEX, #C); \
    if (p == NULL || !lua_getmetatable(L, i) || !lua_rawequal(L, -1, -2)) p=NULL; \
    lua_pop(L, 2); \
    return p ? true : false; \
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
    const char   *fieldname;
    lua_CFunction getfunc;
    lua_CFunction setfunc;
} wslua_attribute_table;
extern int wslua_reg_attributes(lua_State *L, const wslua_attribute_table *t, bool is_getter);

#define WSLUA_TYPEOF_FIELD "__typeof"

#ifdef HAVE_LUA

/* temporary transition macro to reduce duplication in WSLUA_REGISTER_xxx. */
#define WSLUA_REGISTER_GC(C) \
    luaL_getmetatable(L, #C); \
     /* add the '__gc' metamethod with a C-function named Class__gc */ \
    /* this will force ALL wslua classes to have a Class__gc function defined, which is good */ \
    lua_pushcfunction(L, C ## __gc); \
    lua_setfield(L, -2, "__gc"); \
    /* pop the metatable */ \
    lua_pop(L, 1)

#define __WSLUA_REGISTER_META(C, ATTRS) { \
    const wslua_class C ## _class = { \
        .name               = #C, \
        .instance_meta      = C ## _meta, \
        .attrs              = ATTRS \
    }; \
    wslua_register_classinstance_meta(L, &C ## _class); \
    WSLUA_REGISTER_GC(C); \
}

#define WSLUA_REGISTER_META(C)  __WSLUA_REGISTER_META(C, NULL)
#define WSLUA_REGISTER_META_WITH_ATTRS(C) \
    __WSLUA_REGISTER_META(C, C ## _attributes)

#define __WSLUA_REGISTER_CLASS(C, ATTRS) { \
    const wslua_class C ## _class = { \
        .name               = #C, \
        .class_methods      = C ## _methods, \
        .class_meta         = C ## _meta, \
        .instance_methods   = C ## _methods, \
        .instance_meta      = C ## _meta, \
        .attrs              = ATTRS \
    }; \
    wslua_register_class(L, &C ## _class); \
    WSLUA_REGISTER_GC(C); \
}

#define WSLUA_REGISTER_CLASS(C)  __WSLUA_REGISTER_CLASS(C, NULL)
#define WSLUA_REGISTER_CLASS_WITH_ATTRS(C) \
    __WSLUA_REGISTER_CLASS(C, C ## _attributes)

#define WSLUA_INIT(L) \
    luaL_openlibs(L); \
    wslua_register_classes(L); \
    wslua_register_functions(L);

#endif

#define WSLUA_FUNCTION extern int
/* This is for functions intended only to be used in init.lua */
#define WSLUA_INTERNAL_FUNCTION extern int

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
    typedef void __dummy##C##_set_##field

#define WSLUA_ATTRIBUTE_GET(C,name,block) \
    static int C##_get_##name (lua_State* L) { \
        C obj = check##C (L,1); \
        block \
        return 1; \
    } \
    /* silly little trick so we can add a semicolon after this macro */ \
    typedef void __dummy##C##_get_##name

#define WSLUA_ATTRIBUTE_NAMED_BOOLEAN_GETTER(C,name,member) \
    WSLUA_ATTRIBUTE_GET(C,name,{lua_pushboolean(L, obj->member );})

#define WSLUA_ATTRIBUTE_NAMED_INTEGER_GETTER(C,name,member) \
    WSLUA_ATTRIBUTE_GET(C,name,{lua_pushinteger(L,(lua_Integer)(obj->member));})

#define WSLUA_ATTRIBUTE_INTEGER_GETTER(C,member) \
    WSLUA_ATTRIBUTE_NAMED_INTEGER_GETTER(C,member,member)

#define WSLUA_ATTRIBUTE_BLOCK_NUMBER_GETTER(C,name,block) \
    WSLUA_ATTRIBUTE_GET(C,name,{lua_pushnumber(L,(lua_Number)(block));})

#define WSLUA_ATTRIBUTE_NAMED_STRING_GETTER(C,name,member) \
    WSLUA_ATTRIBUTE_GET(C,name, { \
        lua_pushstring(L,obj->member); /* this pushes nil if obj->member is null */ \
    })

#define WSLUA_ATTRIBUTE_STRING_GETTER(C,member) \
    WSLUA_ATTRIBUTE_NAMED_STRING_GETTER(C,member,member)

#define WSLUA_ATTRIBUTE_NAMED_OPT_BLOCK_STRING_GETTER(C,name,member,option) \
    WSLUA_ATTRIBUTE_GET(C,name, { \
        char* str;  \
        if ((obj->member) && (obj->member->len > 0)) { \
            if (wtap_block_get_string_option_value(g_array_index(obj->member, wtap_block_t, 0), option, &str) == WTAP_OPTTYPE_SUCCESS) { \
                lua_pushstring(L,str); \
            } \
        } \
    })

/*
 * XXX - we need to support Lua programs getting instances of a "multiple
 * allowed" option other than the first option.
 */
#define WSLUA_ATTRIBUTE_NAMED_OPT_BLOCK_NTH_STRING_GETTER(C,name,member,option) \
    WSLUA_ATTRIBUTE_GET(C,name, { \
        char* str;  \
        if ((obj->member) && (obj->member->len > 0)) { \
            if (wtap_block_get_nth_string_option_value(g_array_index(obj->member, wtap_block_t, 0), option, 0, &str) == WTAP_OPTTYPE_SUCCESS) { \
                lua_pushstring(L,str); \
            } \
        } \
    })

#define WSLUA_ATTRIBUTE_SET(C,name,block) \
    static int C##_set_##name (lua_State* L) { \
        C obj = check##C (L,1); \
        block; \
        return 0; \
    } \
    /* silly little trick so we can add a semicolon after this macro */ \
    typedef void __dummy##C##_set_##name

#define WSLUA_ATTRIBUTE_NAMED_BOOLEAN_SETTER(C,name,member) \
    WSLUA_ATTRIBUTE_SET(C,name, { \
        if (! lua_isboolean(L,-1) ) \
            return luaL_error(L, "%s's attribute `%s' must be a boolean", #C , #name ); \
        obj->member = lua_toboolean(L,-1); \
    })

/* to make this integral-safe, we treat it as int32 and then cast
   Note: This will truncate 64-bit integers (but then Lua itself only has doubles */
#define WSLUA_ATTRIBUTE_NAMED_INTEGER_SETTER(C,name,member,cast) \
    WSLUA_ATTRIBUTE_SET(C,name, { \
        if (! lua_isinteger(L,-1) ) \
            return luaL_error(L, "%s's attribute `%s' must be an integer", #C , #name ); \
        obj->member = (cast) wslua_toint32(L,-1); \
    })

#define WSLUA_ATTRIBUTE_INTEGER_SETTER(C,member,cast) \
    WSLUA_ATTRIBUTE_NAMED_INTEGER_SETTER(C,member,member,cast)

#define WSLUA_ATTRIBUTE_NAMED_STRING_SETTER(C,field,member,need_free) \
    static int C##_set_##field (lua_State* L) { \
        C obj = check##C (L,1); \
        char* s = NULL; \
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
    typedef void __dummy##C##_set_##field

#define WSLUA_ATTRIBUTE_STRING_SETTER(C,field,need_free) \
    WSLUA_ATTRIBUTE_NAMED_STRING_SETTER(C,field,field,need_free)

#define WSLUA_ATTRIBUTE_NAMED_OPT_BLOCK_STRING_SETTER(C,field,member,option) \
    static int C##_set_##field (lua_State* L) { \
        C obj = check##C (L,1); \
        char* s = NULL; \
        if (lua_isstring(L,-1) || lua_isnil(L,-1)) { \
            s = g_strdup(lua_tostring(L,-1)); \
        } else { \
            return luaL_error(L, "%s's attribute `%s' must be a string or nil", #C , #field ); \
        } \
        if ((obj->member) && (obj->member->len > 0)) { \
            wtap_block_set_string_option_value(g_array_index(obj->member, wtap_block_t, 0), option, s, strlen(s)); \
        } \
        g_free(s); \
        return 0; \
    } \
    /* silly little trick so we can add a semicolon after this macro */ \
    typedef void __dummy##C##_set_##field

#define WSLUA_ATTRIBUTE_NAMED_OPT_BLOCK_NTH_STRING_SETTER(C,field,member,option) \
    static int C##_set_##field (lua_State* L) { \
        C obj = check##C (L,1); \
        char* s = NULL; \
        if (lua_isstring(L,-1) || lua_isnil(L,-1)) { \
            s = g_strdup(lua_tostring(L,-1)); \
        } else { \
            return luaL_error(L, "%s's attribute `%s' must be a string or nil", #C , #field ); \
        } \
        if ((obj->member) && (obj->member->len > 0)) { \
            wtap_block_set_nth_string_option_value(g_array_index(obj->member, wtap_block_t, 0), option, 0, s, strlen(s)); \
        } \
        g_free(s); \
        return 0; \
    } \
    /* silly little trick so we can add a semicolon after this macro */ \
    typedef void __dummy##C##_set_##field

#define WSLUA_ERROR(name,error) { luaL_error(L, "%s%s", #name ": " ,error); }
#define WSLUA_ARG_ERROR(name,attr,error) { luaL_argerror(L,WSLUA_ARG_ ## name ## _ ## attr, #name  ": " error); }
#define WSLUA_OPTARG_ERROR(name,attr,error) { luaL_argerror(L,WSLUA_OPTARG_##name##_ ##attr, #name  ": " error); }

#define WSLUA_REG_GLOBAL_BOOL(L,n,v) { lua_pushboolean(L,v); lua_setglobal(L,n); }
#define WSLUA_REG_GLOBAL_STRING(L,n,v) { lua_pushstring(L,v); lua_setglobal(L,n); }
#define WSLUA_REG_GLOBAL_INTEGER(L,n,v) { lua_pushinteger(L,v); lua_setglobal(L,n); }

#define WSLUA_RETURN(i) return (i)

#define WSLUA_API extern

/* empty macro arguments trigger ISO C90 warnings, so do this */
#define NOP (void)p

#define FAIL_ON_NULL(s) if (! *p) luaL_argerror(L,idx,"null " s)

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
extern bool is##C(lua_State* L,int i); \
extern C shift##C(lua_State* L,int i)


/* Throws a Wireshark exception, catchable via normal exceptions.h routines. */
#define THROW_LUA_ERROR(...) \
    THROW_FORMATTED(DissectorError, __VA_ARGS__)

/* Catches any Wireshark exceptions in code and convert it into a Lua error.
 * Normal restrictions for TRY/CATCH apply, in particular, do not return! */
#define WRAP_NON_LUA_EXCEPTIONS(code) \
{ \
    volatile bool has_error = false; \
    TRY { \
        code \
    } CATCH_ALL { \
        lua_pushstring(L, GET_MESSAGE);  \
        has_error = true; \
    } ENDTRY; \
    if (has_error) { lua_error(L); } \
}


extern packet_info* lua_pinfo;
extern TreeItem lua_tree;
extern tvbuff_t* lua_tvb;
extern bool lua_initialized;
extern int lua_dissectors_table_ref;
extern int lua_heur_dissectors_table_ref;

WSLUA_DECLARE_CLASSES()
WSLUA_DECLARE_FUNCTIONS()

extern lua_State* wslua_state(void);


/* wslua_internals.c */
/**
 * @brief Type for defining new classes.
 *
 * A new class is defined as a Lua table type. Instances of this class are
 * created through pushXxx which sets the appropriate metatable.
 */
typedef struct _wslua_class {
    const char *name;                   /**< Class name that is exposed to Lua code. */
    const luaL_Reg *class_methods;      /**< Methods for the static class (optional) */
    const luaL_Reg *class_meta;         /**< Metatable for the static class (optional) */
    const luaL_Reg *instance_methods;   /**< Methods for class instances. (optional) */
    const luaL_Reg *instance_meta;      /**< Metatable for class instances (optional) */
    const wslua_attribute_table *attrs; /**< Table of getters/setters for attributes on class instances (optional). */
} wslua_class;
void wslua_register_classinstance_meta(lua_State *L, const wslua_class *cls_def);
void wslua_register_class(lua_State *L, const wslua_class *cls_def);

extern int wslua__concat(lua_State* L);
extern bool wslua_toboolean(lua_State* L, int n);
extern bool wslua_checkboolean(lua_State* L, int n);
extern bool wslua_optbool(lua_State* L, int n, bool def);
extern lua_Integer wslua_tointeger(lua_State* L, int n);
extern int wslua_optboolint(lua_State* L, int n, int def);
extern const char* wslua_checklstring_only(lua_State* L, int n, size_t *l);
extern const char* wslua_checkstring_only(lua_State* L, int n);
extern void wslua_setfuncs(lua_State *L, const luaL_Reg *l, int nup);
extern const char* wslua_typeof_unknown;
extern const char* wslua_typeof(lua_State *L, int idx);
extern bool wslua_get_table(lua_State *L, int idx, const char *name);
extern bool wslua_get_field(lua_State *L, int idx, const char *name);
extern int dissect_lua(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data);
extern bool heur_dissect_lua(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data);
extern expert_field* wslua_get_expert_field(const int group, const int severity);
extern void wslua_prefs_changed(void);
extern void proto_register_lua(void);
extern GString* lua_register_all_taps(void);
extern void wslua_prime_dfilter(epan_dissect_t *edt);
extern bool wslua_has_field_extractors(void);
extern void lua_prime_all_fields(proto_tree* tree);

extern int Proto_commit(lua_State* L);

extern TreeItem create_TreeItem(proto_tree* tree, proto_item* item);

extern void clear_outstanding_FuncSavers(void);

extern void Int64_pack(lua_State* L, luaL_Buffer *b, int idx, bool asLittleEndian);
extern int Int64_unpack(lua_State* L, const char *buff, bool asLittleEndian);
extern void UInt64_pack(lua_State* L, luaL_Buffer *b, int idx, bool asLittleEndian);
extern int UInt64_unpack(lua_State* L, const char *buff, bool asLittleEndian);
extern uint64_t getUInt64(lua_State *L, int i);

extern Tvb* push_Tvb(lua_State* L, tvbuff_t* tvb);
extern int push_wsluaTvb(lua_State* L, Tvb t);
extern bool push_TvbRange(lua_State* L, tvbuff_t* tvb, int offset, int len);
extern void clear_outstanding_Tvb(void);
extern void clear_outstanding_TvbRange(void);

extern Pinfo* push_Pinfo(lua_State* L, packet_info* p);
extern void clear_outstanding_Pinfo(void);
extern void clear_outstanding_Column(void);
extern void clear_outstanding_Columns(void);
extern void clear_outstanding_PrivateTable(void);

extern int get_hf_wslua_text(void);
extern TreeItem push_TreeItem(lua_State *L, proto_tree *tree, proto_item *item);
extern void clear_outstanding_TreeItem(void);

extern FieldInfo* push_FieldInfo(lua_State *L, field_info* f);
extern void clear_outstanding_FieldInfo(void);

extern void wslua_print_stack(char* s, lua_State* L);

extern void wslua_init(register_cb cb, void *client_data);
extern void wslua_early_cleanup(void);
extern void wslua_cleanup(void);

extern tap_extractor_t wslua_get_tap_extractor(const char* name);
extern int wslua_set_tap_enums(lua_State* L);

extern ProtoField wslua_is_field_available(lua_State* L, const char* field_abbr);

extern char* wslua_get_actual_filename(const char* fname);

extern int wslua_bin2hex(lua_State* L, const uint8_t* data, const unsigned len, const bool lowercase, const char* sep);
extern int wslua_hex2bin(lua_State* L, const char* data, const unsigned len, const char* sep);
extern int luaopen_rex_pcre2(lua_State *L);

extern const char* get_current_plugin_version(void);
extern void clear_current_plugin_version(void);

extern int wslua_deregister_heur_dissectors(lua_State* L);
extern int wslua_deregister_protocols(lua_State* L);
extern int wslua_deregister_dissector_tables(lua_State* L);
extern int wslua_deregister_listeners(lua_State* L);
extern int wslua_deregister_fields(lua_State* L);
extern int wslua_deregister_filehandlers(lua_State* L);
extern void wslua_deregister_menus(void);

extern void wslua_init_wtap_filetypes(lua_State* L);

#endif

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
