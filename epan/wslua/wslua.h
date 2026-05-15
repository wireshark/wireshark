/*
 * wslua.h
 *
 * Wireshark's interface to the Lua Programming Language
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 * (c) 2007, Tamas Regos <tamas.regos@ericsson.com>
 * (c) 2008, Balint Reczey <balint.reczey@ericsson.com>
 * (c) 2025, Bartis Csaba <bracsek@bracsek.eu>
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
#include <epan/uat-int.h>
#include <epan/uat.h>
#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/proto.h>
#include <epan/epan_dissect.h>
#include <epan/tap.h>
#include <epan/column-utils.h>
#include <wsutil/filesystem.h>
#include <wsutil/wsgcrypt.h>
#include <epan/funnel.h>
#include <epan/tvbparse.h>
#include <epan/epan.h>
#include <epan/expert.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>
#include <epan/conversation.h>

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
    unsigned offset;
    unsigned len;
};

struct _wslua_tw {
    funnel_text_window_t* ws_tw;
    bool expired;
    void* close_cb_data;
    char* title;
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

typedef struct _wslua_pref_t {
    char* name;
    char* label;
    char* desc;
    pref_type_e type;
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
      struct {
          uat_field_t *uat_field_list; /**< list of field configurations */
      } uat_field_list_info; /**< for PREF_UAT */
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

typedef struct _wslua_conv_data_t {
    conversation_t* conv;
    int data_ref;
} wslua_conv_data_t;

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

/*
 * _func_saver stores function refs so that Lua won't garbage collect them prematurely.
 * It is only used by tcp_dissect_pdus right now.
 */
struct _wslua_func_saver {
    lua_State* state;
    int get_len_ref;
    int dissect_ref;
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

struct _wslua_rec {
    wtap_rec *rec;
    bool expired;
};

struct _wslua_const_rec {
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
    char* path;
};

struct _wslua_progdlg {
    struct progdlg* pw;
    char* title;
    char* task;
    bool stopped;
};

typedef struct { const char* name; tap_extractor_t extractor; } tappable_t;

typedef struct {const char* str; enum ftenum id; } wslua_ft_types_t;
typedef struct {const char* str; conversation_type id; } wslua_conv_types_t;

typedef wslua_pref_t* Pref;
typedef wslua_pref_t* Prefs;
typedef struct _wslua_field_t* ProtoField;
typedef struct _wslua_expert_field_t* ProtoExpert;
typedef struct _wslua_proto_t* Proto;
typedef struct _wslua_distbl_t* DissectorTable;
typedef dissector_handle_t Dissector;
typedef GByteArray* ByteArray;
typedef gcry_cipher_hd_t* GcryptCipher;
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
typedef struct _wslua_rec* FrameInfo;
typedef struct _wslua_const_rec* FrameInfoConst;
typedef struct _wslua_filehandler* FileHandler;
typedef wtap_dumper* Dumper;
typedef struct lua_pseudo_header* PseudoHeader;
typedef tvbparse_t* Parser;
typedef tvbparse_wanted_t* Rule;
typedef tvbparse_elem_t* Node;
typedef tvbparse_action_t* Shortcut;
typedef struct _wslua_dir* Dir;
typedef struct _wslua_private_table* PrivateTable;
typedef conversation_t* Conversation;
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

/**
 * @brief Registers attributes for a Lua table.
 *
 * This function registers getter and setter functions for fields in a Lua table.
 *
 * @param L The Lua state.
 * @param t A pointer to the attribute table containing field names and their corresponding getter and setter functions.
 * @param is_getter If true, registers only the getter functions; if false, registers both getter and setter functions.
 * @return An integer indicating success or failure of the registration process.
 */
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

/* Body of a __pairs metamethod that hands the generic-for protocol
 * a stateless iterator `C##_pairs_iter`. The iterator must accept
 * (self, prev_key_or_nil) and return the next (key, value) pair or a
 * single nil when done. Use inside a WSLUA_METAMETHOD body so the
 * caller retains control of any doc comments shown in the manual. */
#define WSLUA_STATELESS_PAIRS_BODY(C)                 \
    check##C(L, 1);                                   \
    lua_pushcfunction(L, C##_pairs_iter);             \
    lua_pushvalue(L, 1);                              \
    lua_pushnil(L);                                   \
    return 3

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

#define WSLUA_ERROR(name,error) { luaL_error(L, "%s%s", #name ": ", error); }
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
 * Normal restrictions for TRY/CATCH apply, in particular, do not return!
 *
 * This means do not call lua[L]_error() inside code, as that longjmps out
 * of the TRY block to the Lua pcall! Use THROW_LUA_ERROR, which is caught
 * and then converted into a Lua error.
 *
 * XXX: We CATCH_ALL here, although there's little point in catching
 * OutOfMemoryError here. (Is CATCH_BOUNDS_AND_DISSECTOR_ERRORS sufficient?)
 * There are some Exceptions that we catch and show but don't want to add
 * the Lua error malformed expert info to the tree: BoundsError,
 * FragmentBoundsError, and ScsiBoundsError (show_exception doesn't consider
 * those malformed). The traceback might (or might not) be useful for those.
 * Putting an extra malformed expert info in the tree in the cases that are
 * malformed seems not so bad, but we might want to reduce that. Perhaps
 * at least we could have a separate LuaError type and not call show_exception
 * for that (we still need to handle some Lua errors that don't use this in
 * dissector_error_handler.)
 */
#define WRAP_NON_LUA_EXCEPTIONS(code) \
{ \
    volatile bool has_error = false; \
    TRY { \
        code \
    } CATCH3(BoundsError, FragmentBoundsError, ScsiBoundsError) { \
        show_exception(lua_tvb, lua_pinfo, lua_tree->tree, EXCEPT_CODE, GET_MESSAGE); \
    } CATCH_ALL { \
        show_exception(lua_tvb, lua_pinfo, lua_tree->tree, EXCEPT_CODE, GET_MESSAGE); \
        lua_pushfstring(L, "%s: %s", __func__, GET_MESSAGE ? GET_MESSAGE : "Malformed packet"); \
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
extern const char* lua_app_env_var_prefix;
extern GPtrArray* lua_outstanding_FuncSavers;

WSLUA_DECLARE_CLASSES()
WSLUA_DECLARE_FUNCTIONS()

/**
 * @brief Retrieves the Lua state associated with Wireshark.
 *
 * This function returns a pointer to the Lua state used by Wireshark for scripting and extensions.
 *
 * @return A pointer to the lua_State structure representing the Lua state.
 */
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

/**
 * @brief Registers a class instance meta table.
 *
 * This function registers a metatable for use by class instances in Lua. It sets up the metatable with methods and attributes defined in the provided class definition.
 *
 * @param L The Lua state.
 * @param cls_def Pointer to the class definition containing the meta and method information.
 */
void wslua_register_classinstance_meta(lua_State *L, const wslua_class *cls_def);

/**
 * @brief Registers a new Lua class in the global table.
 *
 * @param L The Lua state.
 * @param cls_def A pointer to the class definition structure.
 */
void wslua_register_class(lua_State *L, const wslua_class *cls_def);

/**
 * @brief Concatenates two objects to a string.
 *
 * This function attempts to convert the first and second arguments to strings using the __tostring metamethod,
 * and then concatenates them. If the metamethod is not available, it pushes the value as is.
 *
 * @param L The Lua state.
 * @return Number of values on the stack (1).
 */
extern int wslua__concat(lua_State* L);

/**
 * @brief Converts a Lua value to a boolean.
 *
 * This function checks if the given Lua value is a boolean or nil, and returns its boolean value.
 * If the value is a number, it converts 0 to false and any other number to true.
 * If the value is neither a boolean nor a number, it raises an error.
 *
 * @param L The Lua state.
 * @param n The index of the value on the stack.
 * @return The boolean value.
 */
extern bool wslua_toboolean(lua_State* L, int n);

/**
 * @brief Checks if a Lua value at a given index is a boolean.
 *
 * This function checks if the value at the specified index is a boolean or nil.
 *
 * @param L The Lua state.
 * @param n The index of the value to check.
 * @return bool True if the value is a boolean or nil, false otherwise.
 */
extern bool wslua_checkboolean(lua_State* L, int n);

/**
 * @brief Checks if a Lua value at a given index is a boolean and returns its value, or a default value if not.
 *
 * @param L The Lua state.
 * @param n The index of the value to check.
 * @param def The default value to return if the value is not a boolean.
 * @return The boolean value from the Lua stack, or the default value.
 */
extern bool wslua_optbool(lua_State* L, int n, bool def);

/**
 * @brief Converts a Lua value to an integer.
 *
 * @param L The Lua state.
 * @param n The index of the value on the stack.
 * @return The integer value.
 */
extern lua_Integer wslua_tointeger(lua_State* L, int n);

/**
 * @brief Retrieves an optional boolean or integer value from the Lua stack.
 *
 * @param L The Lua state.
 * @param n The index of the value on the stack.
 * @param def The default value if the value is not a boolean or integer.
 * @return The retrieved value, either from the stack or the default.
 */
extern int wslua_optboolint(lua_State* L, int n, int def);

/**
 * @brief Checks if the value at the given index is a Lua string and returns it.
 *
 * @param L The Lua state.
 * @param n The index of the value to check.
 * @param l A pointer to store the length of the string.
 * @return The checked Lua string, or throws an error if not a string.
 */
extern const char* wslua_checklstring_only(lua_State* L, int n, size_t *l);

/**
 * @brief Checks if a Lua value at a given index is a string.
 *
 * @param L The Lua state.
 * @param n The index of the value to check.
 * @return const char* The string value, or NULL if not a string.
 */
extern const char* wslua_checkstring_only(lua_State* L, int n);

/**
 * @brief Set functions in a Lua table.
 *
 * @param L The Lua state.
 * @param l Array of function definitions.
 * @param nup Number of upvalues to pass to each function.
 */
extern void wslua_setfuncs(lua_State *L, const luaL_Reg *l, int nup);

extern const char* wslua_typeof_unknown;

/**
 * @brief Return a human-readable type name for the Lua value at a stack index.
 *
 * @param L   The Lua state.
 * @param idx Stack index of the value to inspect.
 * @return A static or interned string naming the Lua type or wslua class
 *         of the value. The pointer is valid for the lifetime of the
 *         interpreter; do not free it.
 */
extern const char *wslua_typeof(lua_State *L, int idx);

/**
 * @brief Push a named field from a Lua table onto the stack.
 *
 * @param L    The Lua state.
 * @param idx  Stack index of the table to query.
 * @param name The string key to look up in the table.
 * @return true if the field was found and a non-nil value was pushed;
 *         false if the field is absent or nil (nothing is pushed in that
 *         case).
 */
extern bool wslua_get_table(lua_State *L, int idx, const char *name);

/**
 * @brief Push a named field from a Lua value's metatable or environment.
 *
 * @param L    The Lua state.
 * @param idx  Stack index of the object whose field should be fetched.
 * @param name The field name to retrieve.
 * @return true if a non-nil value was pushed onto the stack;
 *         false if the field is absent or nil.
 */
extern bool wslua_get_field(lua_State *L, int idx, const char *name);

/**
 * @brief C-side entry point for all Lua-based protocol dissectors.
 *
 * @param tvb   The packet data buffer.
 * @param pinfo Packet metadata and column information.
 * @param tree  The protocol tree root for this packet.
 * @param data  Optional opaque data passed from the parent dissector
 *              (may be NULL).
 * @return The number of bytes consumed, as returned by the Lua function,
 *         or 0 if the dissector declined the packet.
 */
extern int dissect_lua(tvbuff_t *tvb, packet_info *pinfo,
                       proto_tree *tree, void *data);

/**
 * @brief C-side entry point for all Lua-based heuristic dissectors.
 *
 * @param tvb   The packet data buffer.
 * @param pinfo Packet metadata and column information.
 * @param tree  The protocol tree root for this packet.
 * @param data  Optional opaque data passed from the parent dissector
 *              (may be NULL).
 * @return true if the Lua heuristic claimed the packet; false if the
 *         payload was not recognised and the framework should try the
 *         next heuristic.
 */
extern bool heur_dissect_lua(tvbuff_t *tvb, packet_info *pinfo,
                              proto_tree *tree, void *data);

/**
 * @brief Retrieves an expert field based on group and severity.
 *
 * @param group The group of the expert field.
 * @param severity The severity level of the expert field.
 * @return A pointer to the expert field if found, otherwise a pointer to an error field.
 */
extern expert_field* wslua_get_expert_field(const int group, const int severity);

/**
 * @brief Notify Lua scripts that preferences have changed.
 *
 * This function is called when Wireshark's preferences are modified, and it
 * notifies any registered Lua scripts about this change.
 */
extern void wslua_prefs_changed(void);

/**
 * @brief Registers the Lua protocol.
 *
 * This function registers the Lua protocol with Wireshark, allowing Lua scripts to define and use custom protocols.
 */
extern void proto_register_lua(void);

/**
 * @brief Registers all Lua taps.
 *
 * This function registers all Lua taps with Wireshark, enabling Lua scripts to create and use custom taps for packet analysis.
 *
 * @return A GString containing the names of all registered taps.
 */
extern GString* lua_register_all_taps(void);

/**
 * @brief Prime the dissector filter with a protocol tree.
 *
 * This function primes the dissector filter with the protocol tree from an epan_dissect_t structure.
 *
 * @param edt The epan_dissect_t structure containing the protocol tree to prime the filter with.
 */
extern void wslua_prime_dfilter(epan_dissect_t *edt);

/**
 * @brief Checks if there are any registered field extractors.
 *
 * @return true if there are registered field extractors, false otherwise.
 */
extern bool wslua_has_field_extractors(void);

/**
 * @brief Primes all fields in the protocol tree.
 *
 * This function primes all fields in the given protocol tree, preparing them for use in Lua scripts.
 *
 * @param tree The protocol tree to prime.
 */
extern void lua_prime_all_fields(proto_tree* tree);

/**
 * @brief Commits protocol changes.
 *
 * This function commits any pending protocol changes made during the current Lua script execution.
 *
 * @param L The Lua state.
 * @return 0 on success, non-zero on failure.
 */
extern int Proto_commit(lua_State* L);

/**
 * @brief Creates a new TreeItem.
 *
 * @param tree The parent proto_tree.
 * @param item The associated proto_item.
 * @return A newly created TreeItem.
 */
extern TreeItem create_TreeItem(proto_tree* tree, proto_item* item);

/**
 * @brief Clears outstanding function savers associated with a Lua state.
 *
 * @param L The Lua state to clear function savers for.
 */
extern void clear_outstanding_FuncSavers(lua_State* L);

/**
 * @brief Packs a 64-bit integer into a Lua string using the specified endianness.
 *
 * @param L The Lua state.
 * @param b The Lua buffer to add the packed data to.
 * @param idx The index of the integer on the Lua stack.
 * @param asLittleEndian Whether to pack in little-endian format.
 */
extern void Int64_pack(lua_State* L, luaL_Buffer *b, int idx, bool asLittleEndian);

/**
 * @brief Unpacks a 64-bit integer from a buffer with specified endianness and pushes it onto the Lua stack.
 *
 * @param L The Lua state.
 * @param buff The buffer containing the packed integer.
 * @param asLittleEndian Whether the integer is packed in little-endian format.
 * @return The number of values pushed onto the Lua stack (1).
 */
extern int Int64_unpack(lua_State* L, const char *buff, bool asLittleEndian);

/**
 * @brief Packs a 64-bit unsigned integer into a Lua string buffer with specified endianness.
 *
 * @param L The Lua state.
 * @param b The Lua buffer to pack the integer into.
 * @param idx The index of the integer in the Lua stack.
 * @param asLittleEndian Whether to pack the integer in little-endian format.
 */
extern void UInt64_pack(lua_State* L, luaL_Buffer *b, int idx, bool asLittleEndian);

/**
 * @brief Unpacks a 64-bit unsigned integer from a buffer with specified endianness and pushes it onto the Lua stack.
 *
 * @param L The Lua state.
 * @param buff The buffer containing the packed unsigned integer.
 * @param asLittleEndian Whether the unsigned integer is packed in little-endian format.
 * @return The number of values pushed onto the Lua stack (1).
 */
extern int UInt64_unpack(lua_State* L, const char *buff, bool asLittleEndian);

/**
 * @brief Retrieves a 64-bit unsigned integer from the Lua stack.
 *
 * This function checks the type of the value at the specified index on the Lua stack
 * and converts it to a uint64_t. It supports numbers, strings, and Int64 userdata types.
 *
 * @param L The Lua state.
 * @param i The index on the Lua stack where the value is located.
 * @return The 64-bit unsigned integer value.
 */
extern uint64_t getUInt64(lua_State *L, int i);

/**
 * @brief Pushes a tvbuff_t to the Lua stack as a Tvb object.
 *
 * @param L The Lua state.
 * @param tvb The tvbuff_t to push.
 * @return A pointer to the pushed Tvb object.
 */
extern Tvb* push_Tvb(lua_State* L, tvbuff_t* tvb);

/**
 * @brief Pushes a Tvb object onto the Lua stack.
 *
 * @param L The Lua state.
 * @param t The Tvb object to push.
 * @return An integer indicating success or failure of the push operation.
 */
extern int push_wsluaTvb(lua_State* L, Tvb t);

/**
 * @brief Pushes a TvbRange object onto the Lua stack.
 *
 * @param L The Lua state.
 * @param tvb The tvbuff_t object.
 * @param offset The offset within the tvbuff_t.
 * @param len The length of the range to push.
 * @return true If successful, false otherwise.
 */
extern bool push_TvbRange(lua_State* L, tvbuff_t* tvb, int offset, int len);

/**
 * @brief Clears all outstanding Tvb objects.
 *
 * This function removes and frees all Tvb objects from the outstanding_Tvb array.
 */
extern void clear_outstanding_Tvb(void);

/**
 * @brief Clears all outstanding TvbRange objects.
 */
extern void clear_outstanding_TvbRange(void);

/**
 * @brief Pushes a packet information structure onto the Lua stack.
 *
 * @param L The Lua state.
 * @param p The Wireshark packet information structure.
 * @return A pointer to the pushed packet information structure.
 */
extern Pinfo* push_Pinfo(lua_State* L, packet_info* p);

/**
 * @brief Clears all outstanding Pinfo objects.
 */
extern void clear_outstanding_Pinfo(void);

/**
 * @brief Clears all outstanding Column objects.
 */
extern void clear_outstanding_Column(void);

/**
 * @brief Clears all outstanding Column objects.
 */
extern void clear_outstanding_Columns(void);

/**
 * @brief Clears any outstanding PrivateTable entries.
 */
extern void clear_outstanding_PrivateTable(void);

/**
 * @brief Retrieves the value of hf_wslua_text.
 *
 * @return The value of hf_wslua_text.
 */
extern int get_hf_wslua_text(void);

/**
 * @brief Pushes a TreeItem onto the Lua stack.
 *
 * @param L The Lua state.
 * @param tree The protocol tree associated with the item.
 * @param item The protocol item to push.
 * @return A pointer to the pushed TreeItem on the Lua stack.
 */
extern TreeItem push_TreeItem(lua_State *L, proto_tree *tree, proto_item *item);

/**
 * @brief Clears all outstanding TreeItem objects.
 */
extern void clear_outstanding_TreeItem(void);

/**
 * @brief Pushes a field information object onto the Lua stack.
 *
 * @param L The Lua state.
 * @param f The field information to push.
 * @return A pointer to the pushed field information.
 */
extern FieldInfo* push_FieldInfo(lua_State *L, field_info* f);

/**
 * @brief Clears any outstanding FieldInfo structures.
 */
extern void clear_outstanding_FieldInfo(void);

/**
 * @brief Prints the stack of a Lua state with a given prefix.
 *
 * @param s The prefix string to prepend to each stack entry.
 * @param L The Lua state whose stack is to be printed.
 */
extern void wslua_print_stack(char* s, lua_State* L);

/**
 * @brief Initialize Wireshark Lua support.
 *
 * Registers a callback function and initializes various components for Wireshark Lua.
 *
 * @param cb Callback function to be registered.
 * @param client_data Data to be passed to the callback function.
 * @param app_env_var_prefix Prefix for application environment variables.
 */
extern void wslua_init(register_cb cb, void *client_data, const char* app_env_var_prefix);

/**
 * @brief Performs early cleanup of Lua resources.
 */
extern void wslua_early_cleanup(void);

/**
 * @brief Cleans up Lua resources.
 *
 * This function closes the Lua state if it exists and resets initialization flags.
 */
extern void wslua_cleanup(void);

/**
 * @brief Retrieves a tap extractor by name.
 *
 * @param name The name of the tap extractor to retrieve.
 * @return A pointer to the tap extractor, or NULL if not found.
 */
extern tap_extractor_t wslua_get_tap_extractor(const char* name);

/**
 * @brief Set tap enumerations in Lua.
 *
 * @param L The Lua state.
 * @return Number of values pushed to the stack.
 */
extern int wslua_set_tap_enums(lua_State* L);

extern ProtoField wslua_is_field_available(lua_State* L, const char* field_abbr);

 /**
  * @brief Retrieves the actual filename with normalized path separators.
  *
  * @param fname The original filename to process.
  * @return A new string containing the cleaned and normalized filename, or NULL if the file does not exist.
  */
extern char* wslua_get_actual_filename(const char* fname);

 /**
  * @brief Convert binary data to hexadecimal string.
  *
  * Converts a given binary data buffer into a hexadecimal string representation.
  *
  * @param L Lua state.
  * @param data Pointer to the binary data.
  * @param len Length of the binary data.
  * @param lowercase If true, use lowercase letters in the output; otherwise, use uppercase.
  * @param sep Separator between bytes in the output string.
  * @return Number of values pushed onto the Lua stack.
  */
extern int wslua_bin2hex(lua_State* L, const uint8_t* data, const unsigned len, const bool lowercase, const char* sep);

/**
 * @brief Convert hexadecimal string to binary data.
 *
 * @param L Lua state.
 * @param data Hexadecimal string to convert.
 * @param len Length of the hexadecimal string.
 * @param sep Separator between bytes (optional).
 * @return Number of bytes written to the buffer or -1 on error.
 */
extern int wslua_hex2bin(lua_State* L, const char* data, const unsigned len, const char* sep);

/**
 * @brief Open the Lua library for PCRE2 regular expressions.
 *
 * @param L The Lua state to register the library with.
 * @return The number of values pushed onto the stack.
 */
extern int luaopen_rex_pcre2(lua_State *L);

/**
 * @brief Get the current plugin version.
 *
 * @return The current plugin version as a string.
 */
extern const char* get_current_plugin_version(void);

/**
 * @brief Clear the current plugin version.
 */
extern void clear_current_plugin_version(void);

/**
 * @brief Deregisters all Lua-based heuristics dissectors.
 *
 * This function iterates through all registered heuristic dissectors and removes them from the system.
 *
 * @param L The Lua state.
 * @return 0 on success, non-zero on failure.
 */
extern int wslua_deregister_heur_dissectors(lua_State* L);

/**
 * @brief Deregisters all Lua-based protocol dissectors.
 *
 * This function iterates through all registered protocol dissectors and removes them from the system.
 *
 * @param L The Lua state.
 * @return 0 on success, non-zero on failure.
 */
extern int wslua_deregister_protocols(lua_State* L);

/**
 * @brief Deregisters all registered dissector tables.
 *
 * This function iterates through all registered dissector tables and deregisters them.
 *
 * @param L The Lua state.
 * @return 0 on success.
 */
extern int wslua_deregister_dissector_tables(lua_State* L);

/**
 * @brief Deregisters all registered listeners.
 *
 * This function iterates through all registered listeners and deregisters them.
 *
 * @param L The Lua state.
 * @return 0 on success.
 */
extern int wslua_deregister_listeners(lua_State* L);

/**
 * @brief Deregisters Lua fields.
 *
 * @param L The Lua state.
 * @return Number of values on the stack.
 */
extern int wslua_deregister_fields(lua_State* L);

/**
 * @brief Deregisters file handlers and menus in Wireshark's Lua environment.
 *
 * This function is responsible for cleaning up resources associated with file handlers and menus registered by Lua scripts.
 *
 * @param L The Lua state from which to deregister the file handlers.
 */
extern int wslua_deregister_filehandlers(lua_State* L);

/**
 * @brief Deregisters all menus registered by Wireshark Lua.
 *
 * This function is responsible for removing all menu items that were previously registered
 * by Wireshark's Lua scripting interface.
 */
extern void wslua_deregister_menus(void);

/**
 * @brief Initialize Wireshark Lua file types.
 *
 * This function initializes the Wireshark Lua file types by creating a table
 * indexed by strings, where each entry contains a name and a corresponding file type.
 *
 * @param L The Lua state to initialize.
 */
extern void wslua_init_wtap_filetypes(lua_State* L);

 /**
  * @brief Retrieves the enumeration of conversation types for Lua inspection.
  *
  * @return const wslua_conv_types_t* A pointer to the conversation type enumeration.
  */
extern const wslua_conv_types_t* wslua_inspect_convtype_enum(void);

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
