/*
 * wslua_internals.c
 *
 * Wireshark's interface to the Lua Programming Language
 *
 * This file is for internal WSLUA functions - not ones exposed into Lua.
 *
 * (c) 2013, Hadriel Kaplan <hadrielk@yahoo.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "wslua.h"
#include <wsutil/ws_printf.h> /* ws_debug_printf */

/* Several implementation details (__getters, __setters, __methods) were exposed
 * to Lua code. These are normally not used by dissectors, just for debugging
 * (and the "wslua global" test). Enable by setting WSLUA_WITH_INTROSPECTION */
#define WSLUA_WITH_INTROSPECTION

#if LUA_VERSION_NUM == 501
/* Compatibility with Lua 5.1, function was added in 5.2 */
static
int lua_absindex(lua_State *L, int idx) {
  return (idx > 0 || idx <= LUA_REGISTRYINDEX)
         ? idx
         : lua_gettop(L) + 1 + idx;
}
#endif

WSLUA_API int wslua__concat(lua_State* L) {
    /* Concatenate two objects to a string */
    if (!luaL_callmeta(L,1,"__tostring"))
        lua_pushvalue(L,1);
    if (!luaL_callmeta(L,2,"__tostring"))
        lua_pushvalue(L,2);

    lua_concat(L,2);

    return 1;
}

/* like lua_toboolean, except only coerces int, nil, and bool, and errors on other types.
   note that normal lua_toboolean returns 1 for any Lua value different from false and
   nil; otherwise it returns 0. So a string would give a 0, as would a number of 1.
   This function errors if the arg is a string, and sets the boolean to 1 for any
   number other than 0. Like toboolean, this returns FALSE if the arg was missing. */
WSLUA_API gboolean wslua_toboolean(lua_State* L, int n) {
    gboolean val = FALSE;

    if ( lua_isboolean(L,n) ||  lua_isnil(L,n)  || lua_gettop(L) < n ) {
        val = lua_toboolean(L,n);
    } else if ( lua_type(L,n) == LUA_TNUMBER ) {
        int num = (int)luaL_checkinteger(L,n);
        val = num != 0 ? TRUE : FALSE;
    } else {
        luaL_argerror(L,n,"must be a boolean or number");
    }

    return val;
}

/* like luaL_checkinteger, except for booleans - this does not coerce other types */
WSLUA_API gboolean wslua_checkboolean(lua_State* L, int n) {

    if (!lua_isboolean(L,n) ) {
        luaL_argerror(L,n,"must be a boolean");
    }

    return lua_toboolean(L,n);;
}

WSLUA_API gboolean wslua_optbool(lua_State* L, int n, gboolean def) {
    gboolean val = FALSE;

    if ( lua_isboolean(L,n) ) {
        val = lua_toboolean(L,n);
    } else if ( lua_isnil(L,n) || lua_gettop(L) < n ){
        val = def;
    } else {
        luaL_argerror(L,n,"must be a boolean");
    }

    return val;
}

/* like lua_tointeger, except only coerces int, nil, and bool, and errors on other types.
   note that normal lua_tointeger does not coerce nil or bool, but does coerce strings. */
WSLUA_API lua_Integer wslua_tointeger(lua_State* L, int n) {
    lua_Integer val = 0;

    if ( lua_type(L,n) == LUA_TNUMBER) {
        val = lua_tointeger(L,n);
    } else if ( lua_isboolean(L,n) ) {
        val = (lua_Integer) (lua_toboolean(L,n));
    } else if ( lua_isnil(L,n) ) {
        val = 0;
    } else {
        luaL_argerror(L,n,"must be a integer, boolean or nil");
    }

    return val;
}

/* like luaL_optint, except converts/handles Lua booleans as well */
WSLUA_API int wslua_optboolint(lua_State* L, int n, int def) {
    int val = 0;

    if ( lua_isnumber(L,n) ) {
        val = (int)lua_tointeger(L,n);
    } else if ( lua_isboolean(L,n) ) {
        val = lua_toboolean(L,n) ? 1 : 0;
    } else if ( lua_isnil(L,n) || lua_gettop(L) < n ){
        val = def;
    } else {
        luaL_argerror(L,n,"must be a boolean or integer");
    }

    return val;
}

/* like luaL_checklstring, except no coercion */
WSLUA_API const char* wslua_checklstring_only(lua_State* L, int n, size_t *l) {

    if (lua_type(L,n) != LUA_TSTRING) {
        luaL_argerror(L,n,"must be a Lua string");
    }

    return luaL_checklstring(L, n, l);
}

/* like luaL_checkstring, except no coercion */
WSLUA_API const char* wslua_checkstring_only(lua_State* L, int n) {
    return wslua_checklstring_only(L, n, NULL);
}

/* following is based on the luaL_setfuncs() from Lua 5.2, so we can use it in pre-5.2 */
WSLUA_API void wslua_setfuncs(lua_State *L, const luaL_Reg *l, int nup) {
  luaL_checkstack(L, nup, "too many upvalues");
  for (; l->name != NULL; l++) {  /* fill the table with given functions */
    int i;
    for (i = 0; i < nup; i++)  /* copy upvalues to the top */
      lua_pushvalue(L, -nup);
    lua_pushcclosure(L, l->func, nup);  /* closure with those upvalues */
    lua_setfield(L, -(nup + 2), l->name);
  }
  lua_pop(L, nup);  /* remove upvalues */
}

/**
 * Identical to lua_getfield, but without triggering the __newindex metamethod.
 * The resulting value is returned on the Lua stack.
 */
static void lua_rawgetfield(lua_State *L, int idx, const char *k) {
    idx = lua_absindex(L, idx);
    lua_pushstring(L, k);
    lua_rawget(L, idx);
}

/**
 * Identical to lua_setfield, but without triggering the __newindex metamethod.
 * The value to be set is taken from the Lua stack.
 */
static void lua_rawsetfield (lua_State *L, int idx, const char *k) {
    idx = lua_absindex(L, idx);
    lua_pushstring(L, k);
    lua_insert(L, -2);
    lua_rawset(L, idx);
}

WSLUA_API void wslua_print_stack(char* s, lua_State* L) {
    int i;

    for (i=1;i<=lua_gettop(L);i++) {
        ws_debug_printf("%s-%i: %s\n",s,i,lua_typename (L,lua_type(L, i)));
    }
    ws_debug_printf("\n");
}

/* C-code function equivalent of the typeof() function we created in Lua.
 * The Lua one is for Lua scripts to use, this one is for C-code to use.
 */
const gchar* wslua_typeof_unknown = "UNKNOWN";
const gchar* wslua_typeof(lua_State *L, int idx) {
    const gchar *classname = wslua_typeof_unknown;
    /* we'll try getting the class name for error reporting*/
    if (luaL_getmetafield(L, idx, WSLUA_TYPEOF_FIELD)) {
        classname = luaL_optstring(L, -1, wslua_typeof_unknown);
        lua_pop(L,1); /* pop __typeof result */
    }
    else if (lua_type(L,idx) == LUA_TTABLE) {
        lua_rawgetfield(L, idx, WSLUA_TYPEOF_FIELD);
        classname = luaL_optstring(L, -1, wslua_typeof_unknown);
        lua_pop(L,1); /* pop __typeof result */
    }
    return classname;
}

/* this gets a Lua table of the given name, from the table at the given
 * location idx. If it does not get a table, it pops whatever it got
 * and returns false.
 */
gboolean wslua_get_table(lua_State *L, int idx, const gchar *name) {
    gboolean result = TRUE;
    lua_rawgetfield(L, idx, name);
    if (!lua_istable(L,-1)) {
        lua_pop(L,1);
        result = FALSE;
    }
    return result;
}

/* this gets a table field of the given name, from the table at the given
 * location idx. If it does not get a field, it pops whatever it got
 * and returns false.
 */
gboolean wslua_get_field(lua_State *L, int idx, const gchar *name) {
    gboolean result = TRUE;
    lua_rawgetfield(L, idx, name);
    if (lua_isnil(L,-1)) {
        lua_pop(L,1);
        result = FALSE;
    }
    return result;
}

/**
 * The __index metamethod for classes. Expected upvalues: class name.
 */
static int wslua_classmeta_index(lua_State *L) {
    const char *fieldname = luaL_checkstring(L, 2);
    const char *classname = luaL_checkstring(L, lua_upvalueindex(1));

    return luaL_error(L, "No such '%s' function/property for object type '%s'", fieldname, classname);
}

/**
 * The __index/__newindex metamethod for class instances. Expected upvalues:
 * class name, getters/getters, __index/__newindex class instance metamethod,
 * class methods (getters only). See wslua_register_classinstance_meta.
 *
 * It first tries to find an attribute getter/setter, then an instance method
 * (getters only), then the __index/__newindex metamethod of the class instance
 * metatable and finally it gives up with an error.
 *
 * Getters are invoked with the table as parameter. Setters are invoked with the
 * table and the value as parameter.
 */
static int wslua_instancemeta_index_impl(lua_State *L, gboolean is_getter)
{
    const char *fieldname = luaL_checkstring(L, 2);
    const int attr_idx = lua_upvalueindex(2);
    const int fallback_idx = lua_upvalueindex(3);
    const int methods_idx = lua_upvalueindex(4);

    /* Check for getter/setter */
    if (lua_istable(L, attr_idx)) {
        lua_rawgetfield(L, attr_idx, fieldname);
        if (lua_iscfunction(L, -1)) {
            lua_CFunction cfunc = lua_tocfunction(L, -1);
            lua_pop(L, 1);      /* Remove cfunction from stack */
            lua_remove(L, 2);   /* Remove key from stack */
            /*
             * Note: This re-uses the current closure as optimization, exposing
             * its upvalues via pseudo-indices. The alternative is to create a
             * new C closure (via lua_call), but this is more expensive.
             * Callees should not rely on the availability of the upvalues.
             */
            return (*cfunc)(L);
        }
    }

    /* If this is a getter, and the getter has methods, try them. */
    if (is_getter && lua_istable(L, methods_idx)) {
        lua_rawgetfield(L, methods_idx, fieldname);
        if (!lua_isnil(L, -1)) {
            /* Return method from methods table. */
            return 1;
        }
        lua_pop(L, 1); /* Remove nil from stack. */
    }

    /* Use function from the class instance metatable (if any). */
    if (lua_iscfunction(L, fallback_idx)) {
        lua_CFunction cfunc = lua_tocfunction(L, fallback_idx);
        /* Note, unlike getters/setters functions, the key must be preserved! */
        return (*cfunc)(L);
    }

    const char *classname = luaL_checkstring(L, lua_upvalueindex(1));
    return luaL_error(L, "No such '%s' method/field for object type '%s'", fieldname, classname);
}

static int wslua_instancemeta_index(lua_State *L)
{
    return wslua_instancemeta_index_impl(L, TRUE);
}

static int wslua_instancemeta_newindex(lua_State *L)
{
    return wslua_instancemeta_index_impl(L, FALSE);
}

/* Pushes a hex string of the binary data argument. */
int wslua_bin2hex(lua_State* L, const guint8* data, const guint len, const gboolean lowercase, const gchar* sep) {
    luaL_Buffer b;
    guint i = 0;
    static const char byte_to_str_upper[256][3] = {
        "00","01","02","03","04","05","06","07","08","09","0A","0B","0C","0D","0E","0F",
        "10","11","12","13","14","15","16","17","18","19","1A","1B","1C","1D","1E","1F",
        "20","21","22","23","24","25","26","27","28","29","2A","2B","2C","2D","2E","2F",
        "30","31","32","33","34","35","36","37","38","39","3A","3B","3C","3D","3E","3F",
        "40","41","42","43","44","45","46","47","48","49","4A","4B","4C","4D","4E","4F",
        "50","51","52","53","54","55","56","57","58","59","5A","5B","5C","5D","5E","5F",
        "60","61","62","63","64","65","66","67","68","69","6A","6B","6C","6D","6E","6F",
        "70","71","72","73","74","75","76","77","78","79","7A","7B","7C","7D","7E","7F",
        "80","81","82","83","84","85","86","87","88","89","8A","8B","8C","8D","8E","8F",
        "90","91","92","93","94","95","96","97","98","99","9A","9B","9C","9D","9E","9F",
        "A0","A1","A2","A3","A4","A5","A6","A7","A8","A9","AA","AB","AC","AD","AE","AF",
        "B0","B1","B2","B3","B4","B5","B6","B7","B8","B9","BA","BB","BC","BD","BE","BF",
        "C0","C1","C2","C3","C4","C5","C6","C7","C8","C9","CA","CB","CC","CD","CE","CF",
        "D0","D1","D2","D3","D4","D5","D6","D7","D8","D9","DA","DB","DC","DD","DE","DF",
        "E0","E1","E2","E3","E4","E5","E6","E7","E8","E9","EA","EB","EC","ED","EE","EF",
        "F0","F1","F2","F3","F4","F5","F6","F7","F8","F9","FA","FB","FC","FD","FE","FF"
    };
    static const char byte_to_str_lower[256][3] = {
        "00","01","02","03","04","05","06","07","08","09","0a","0b","0c","0d","0e","0f",
        "10","11","12","13","14","15","16","17","18","19","1a","1b","1c","1d","1e","1f",
        "20","21","22","23","24","25","26","27","28","29","2a","2b","2c","2d","2e","2f",
        "30","31","32","33","34","35","36","37","38","39","3a","3b","3c","3d","3e","3f",
        "40","41","42","43","44","45","46","47","48","49","4a","4b","4c","4d","4e","4f",
        "50","51","52","53","54","55","56","57","58","59","5a","5b","5c","5d","5e","5f",
        "60","61","62","63","64","65","66","67","68","69","6a","6b","6c","6d","6e","6f",
        "70","71","72","73","74","75","76","77","78","79","7a","7b","7c","7d","7e","7f",
        "80","81","82","83","84","85","86","87","88","89","8a","8b","8c","8d","8e","8f",
        "90","91","92","93","94","95","96","97","98","99","9a","9b","9c","9d","9e","9f",
        "a0","a1","a2","a3","a4","a5","a6","a7","a8","a9","aa","ab","ac","ad","ae","af",
        "b0","b1","b2","b3","b4","b5","b6","b7","b8","b9","ba","bb","bc","bd","be","bf",
        "c0","c1","c2","c3","c4","c5","c6","c7","c8","c9","ca","cb","cc","cd","ce","cf",
        "d0","d1","d2","d3","d4","d5","d6","d7","d8","d9","da","db","dc","dd","de","df",
        "e0","e1","e2","e3","e4","e5","e6","e7","e8","e9","ea","eb","ec","ed","ee","ef",
        "f0","f1","f2","f3","f4","f5","f6","f7","f8","f9","fa","fb","fc","fd","fe","ff"
    };
    const char (*byte_to_str)[3] = byte_to_str_upper;
    const guint last = len - 1;

    if (lowercase) byte_to_str = byte_to_str_lower;

    luaL_buffinit(L, &b);

    for (i = 0; i < len; i++) {
        luaL_addlstring(&b, &(*byte_to_str[data[i]]), 2);
        if (sep && i < last) luaL_addstring(&b, sep);
    }

    luaL_pushresult(&b);

    return 1;
}

/* Pushes a binary string of the hex-ascii data argument. */
int wslua_hex2bin(lua_State* L, const char* data, const guint len, const gchar* sep) {
    luaL_Buffer b;
    guint i = 0;
    guint seplen = 0;
    gint8 c, d;

    static const gint8 str_to_nibble[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
         0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1,
        -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };

    if (sep) seplen = (guint) strlen(sep);

    luaL_buffinit(L, &b);

    for (i = 0; i < len;) {
        c = str_to_nibble[(guchar)data[i]];
        if (c < 0) {
            if (seplen && strncmp(&data[i], sep, seplen) == 0) {
                i += seplen;
                continue;
            } else {
                break;
            }
        }
        d = str_to_nibble[(guchar)data[++i]];
        if (d < 0) break;
        luaL_addchar(&b, (c * 16) + d);
        i++;
    }

    luaL_pushresult(&b);

    return 1;
}

/**
 * Creates a table of getters/setters and pushes it on the Lua stack.
 *
 * Additionally, a sanity check is performed to detect colliding getters/setters
 * and method names.
 */
static void wslua_push_attributes(lua_State *L, const wslua_attribute_table *t, gboolean is_getter, int methods_idx)
{
    if (!t) {
        /* No property accessors? Nothing to do. */
        //lua_pushnil(L);
        lua_newtable(L);  /* wslua_reg_attributes requires a table for the moment. */
        return;
    }

    /* If there is a methods table, prepare for a collission check. */
    if (lua_istable(L, methods_idx)) {
        methods_idx = lua_absindex(L, methods_idx);
    } else {
        methods_idx = 0;
    }

    lua_newtable(L);
    /* Fill the getter/setter table with given functions. */
    for (; t->fieldname != NULL; t++) {
        lua_CFunction cfunc = is_getter ? t->getfunc : t->setfunc;
        if (cfunc) {
            /* if there's a previous methods table, make sure this attribute name doesn't collide */
            if (methods_idx) {
                lua_rawgetfield(L, methods_idx, t->fieldname);
                if (!lua_isnil(L, -1)) {
                    g_error("'%s' attribute name already exists as method name for class\n", t->fieldname);
                }
                lua_pop(L,1);  /* pop the nil */
            }
            lua_pushcfunction(L, cfunc);
            lua_rawsetfield(L, -2, t->fieldname);
        }
    }
}

/**
 * Registers the metatable for class instances. See the documentation of
 * wslua_register_class for the exact metatable.
 */
void wslua_register_classinstance_meta(lua_State *L, const wslua_class *cls_def)
{
    /* Register metatable for use by class instances. STACK = { MT } */
    /* NOTE: The name can be changed as long as luaL_checkudata is also adapted */
    luaL_newmetatable(L, cls_def->name);
    if (cls_def->instance_meta) {
        wslua_setfuncs(L, cls_def->instance_meta, 0);
    }

    /* Set the __typeof attribute to the class name (for use by "typeof" in Lua code). */
    lua_pushstring(L, cls_def->name);
    lua_rawsetfield(L, -2, WSLUA_TYPEOF_FIELD);

    /* Create table to store method names. STACK = { MT, methods } */
    if (cls_def->instance_methods) {
        lua_newtable(L);
        wslua_setfuncs(L, cls_def->instance_methods, 0);
    } else {
        lua_pushnil(L);
    }

    /* Prepare __index method on metatable. */
    lua_pushstring(L, cls_def->name);                       /* upval 1: class name */
    wslua_push_attributes(L, cls_def->attrs, TRUE, -2);     /* upval 2: getters table */
#ifdef WSLUA_WITH_INTROSPECTION
    lua_pushvalue(L, -1);
    lua_rawsetfield(L, -5, "__getters"); /* set (transition) property on mt, remove later! */
#endif
    lua_rawgetfield(L, -4, "__index");                      /* upval 3: fallback __index method from metatable */
    lua_pushvalue(L, -4);                                   /* upval 4: class methods table */
    lua_pushcclosure(L, wslua_instancemeta_index, 4);
    lua_rawsetfield(L, -3, "__index");

    /* Prepare __newindex method on metatable. */
    lua_pushstring(L, cls_def->name);                       /* upval 1: class name */
    wslua_push_attributes(L, cls_def->attrs, FALSE, -2);    /* upval 2: setters table */
#ifdef WSLUA_WITH_INTROSPECTION
    lua_pushvalue(L, -1);
    lua_rawsetfield(L, -5, "__setters"); /* set (transition) property on mt, remove later! */
#endif
    lua_rawgetfield(L, -4, "__newindex");                   /* upval 3: fallback __newindex method from metatable */
    lua_pushcclosure(L, wslua_instancemeta_newindex, 3);
    lua_rawsetfield(L, -3, "__newindex");

    /* Pop metatable + methods table. STACK = { } */
    lua_pop(L, 2);
}

/**
 * Registers a new class for use in Lua with the specified properties. The
 * metatable for the class instance is internally registered with the given
 * name.
 *
 * This functions basically creates a class (type table) with this structure:
 *
 *  Class = { class_methods }
 *  Class.__typeof = "Class"                -- NOTE: Might be removed in future
 *  Class.__metatable = { class_meta }
 *  Class.__metatable.__typeof = "Class"    -- NOTE: Might be removed in future
 *  Class.__metatable.__index = function_that_errors_out
 *  Class.__metatable.__newindex = function_that_errors_out
 *
 * It also registers another metatable for class instances (type userdata):
 *
 *  mt = { instance_meta }
 *  mt.__typeof = "Class"
 *  -- will be passed upvalues (see wslua_instancemeta_index_impl).
 *  mt.__index = function_that_finds_right_property_or_method_getter
 *  mt.__newindex = function_thaon_that_finds_right_property_or_method_setter
 *
 * For backwards compatibility, introspection is still possible (this detail
 * might be removed in the future though, do not rely on this!):
 *
 *  Class.__metatable.__methods = Class
 *  Class.__metatable.__getters = { __typeof = "getter", getter_attrs }
 *  Class.__metatable.__setters = { __typeof = "setter", setter_attrs }
 */
void wslua_register_class(lua_State *L, const wslua_class *cls_def)
{
    /* Check for existing global variables/classes with the same name. */
    lua_getglobal(L, cls_def->name);
    if (!lua_isnil (L, -1)) {
        g_error("Attempt to register class '%s' which already exists in global Lua table\n", cls_def->name);
    }
    lua_pop(L, 1);

    /* Create new table for class. STACK = { table } */
    lua_newtable(L);
    if (cls_def->class_methods) {
        wslua_setfuncs(L, cls_def->class_methods, 0);
    }

#ifdef WSLUA_WITH_INTROSPECTION
    /* Set __typeof to the class name, used by wslua_typeof. Might be removed in
     * the future as the type can already be determined from the metatable. */
    lua_pushstring(L, cls_def->name);
    lua_rawsetfield(L, -2, WSLUA_TYPEOF_FIELD);
#endif

    /* Create new metatable for class. STACK = { table, CLASSMT } */
    lua_newtable(L);
    if (cls_def->class_meta) {
        /* Set metamethods on metatable for class. */
        wslua_setfuncs(L, cls_def->class_meta, 0);
    }
#ifdef WSLUA_WITH_INTROSPECTION
    /* Set __typeof to the class name. Might be removed in the future, a "class"
     * is not of the type "(name of class)", instead it is of type "class".
     * Instances of this class should be of type "(name of class)". */
    lua_pushstring(L, cls_def->name);
    lua_rawsetfield(L, -2, WSLUA_TYPEOF_FIELD);
#endif

    /* For backwards compatibility, error out when a non-existing property is being accessed. */
    lua_pushstring(L, cls_def->name);
    lua_pushcclosure(L, wslua_classmeta_index, 1);
    lua_rawsetfield(L, -2, "__index");

    /* Prevent properties from being set on classes. Previously this was always
     * forbidden for classes with attributes (such as Listener), this extends
     * the restriction to all classes. */
    lua_pushstring(L, cls_def->name);
    lua_pushcclosure(L, wslua_classmeta_index, 1);
    lua_rawsetfield(L, -2, "__newindex");

    /* Set metatable on class. STACK = { table } */
    lua_setmetatable(L, -2);

    wslua_register_classinstance_meta(L, cls_def);

#ifdef WSLUA_WITH_INTROSPECTION
    /* XXX remove these? It looks like an internal implementation detail that is
     * no longer needed but is added here to pass the wslua tests (API check) */
    lua_getmetatable(L, -1);                /* Stack = { table, CLASSMT } */
    luaL_getmetatable(L, cls_def->name);    /* Stack = { table, CLASSMT, MT } */

    lua_rawgetfield(L, -1, "__getters");    /* __getters from instance MT */
    lua_pushstring(L, "getter");
    lua_rawsetfield(L, -2, WSLUA_TYPEOF_FIELD);
    lua_rawsetfield(L, -3, "__getters");    /* Set property on class MT */

    lua_rawgetfield(L, -1, "__setters");    /* setters from instance MT */
    lua_pushstring(L, "setter");
    lua_rawsetfield(L, -2, WSLUA_TYPEOF_FIELD);
    lua_rawsetfield(L, -3, "__setters");    /* Set property on class MT */
    lua_pop(L, 1);                          /* Stack = { table, CLASSMT } */

    lua_pushvalue(L, -2);
    lua_rawsetfield(L, -2, "__methods");    /* CLASSMT.__methods = Class */
    lua_pop(L, 1);                          /* Stack = { table } */
#endif

    /* Set the class methods table as global name. STACK = { } */
    lua_setglobal(L, cls_def->name);
}

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
