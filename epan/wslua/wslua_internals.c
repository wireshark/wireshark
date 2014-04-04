/*
 * wslua_internals.c
 *
 * Wireshark's interface to the Lua Programming Language
 *
 * This file is for internal WSLUA functions - not ones exposed into Lua.
 *
 * (c) 2013, Hadriel Kaplan <hadrielk@yahoo.com>
 *
 * $Id: wslua_internals.c 47885 2013-02-25 22:05:28Z hadrielk $
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

#include "config.h"
#include "wslua.h"

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
        int num = luaL_checkint(L,n);
        val = num != 0 ? TRUE : FALSE;
    } else {
        luaL_argerror(L,n,"must be a boolean or number");
    }

    return val;
}

/* like luaL_checkint, except for booleans - this does not coerce other types */
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

WSLUA_API const gchar* lua_shiftstring(lua_State* L, int i) {
    const gchar* p = luaL_checkstring(L, i);

    if (p) {
        lua_remove(L,i);
        return p;
    } else {
        return NULL;
    }
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

/* identical to lua_getfield but without triggering metamethods
   warning: cannot be used directly with negative index (and shouldn't be changed to)
   decrement your negative index if you want to use this */
static void lua_rawgetfield(lua_State *L, int idx, const char *k) {
    lua_pushstring(L, k);
    lua_rawget(L, idx);
}

/* identical to lua_setfield but without triggering metamethods
   warning: cannot be used with negative index (and shouldn't be changed to)
   decrement your negative index if you want to use this */
static void lua_rawsetfield (lua_State *L, int idx, const char *k) {
    lua_pushstring(L, k);
    lua_insert(L, -2);
    lua_rawset(L, idx);
}

WSLUA_API void wslua_print_stack(char* s, lua_State* L) {
    int i;

    for (i=1;i<=lua_gettop(L);i++) {
        printf("%s-%i: %s\n",s,i,lua_typename (L,lua_type(L, i)));
    }
    printf("\n");
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
 * warning: cannot be used with pseudo-indeces like LUA_REGISTRYINDEX
 */
gboolean wslua_get_table(lua_State *L, int idx, const gchar *name) {
    gboolean result = TRUE;
    if (idx < 0) idx--;
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
 * warning: cannot be used with pseudo-indeces like LUA_REGISTRYINDEX
 */
gboolean wslua_get_field(lua_State *L, int idx, const gchar *name) {
    gboolean result = TRUE;
    if (idx < 0) idx--;
    lua_rawgetfield(L, idx, name);
    if (lua_isnil(L,-1)) {
        lua_pop(L,1);
        result = FALSE;
    }
    return result;
}

/* This verifies/asserts that field 'name' doesn't already exist in table at location idx.
 * If it does, this EXITS wireshark, because this is a fundamental programming error.
 * As such, this function is only useful for special circumstances, notably
 * those that will happen on application start every time, as opposed to
 * something that could happen only if a Lua script makes it happen.
 */
void wslua_assert_table_field_new(lua_State *L, int idx, const gchar *name) {
    lua_rawgetfield(L, idx, name);
    if (!lua_isnil (L, -1)) {
        fprintf(stderr, "ERROR: Field %s already exists!\n", name);
        exit(1);
    }
    lua_pop (L, 1); /* pop the nil */ \
}

/* This function is an attribute field __index/__newindex (ie, getter/setter) dispatcher.
 * What the heck does that mean?  Well, when a Lua script tries to retrieve a
 * table/userdata field by doing this:
 *     local foo = myobj.fieldname
 * if 'fieldname' does not exist in the 'myobj' table/userdata, then Lua calls
 * the '__index' metamethod of the table/userdata, and puts onto the Lua
 * stack the table and fieldname string.  So this function here handles that,
 * by dispatching that request to the appropriate getter function in the
 * __getters table within the metatable of the userdata.  That table and
 * its functions were populated by the WSLUA_REGISTER_ATTRIBUTES() macro, and
 * really by wslua_reg_attributes().
 */
static int wslua_attribute_dispatcher (lua_State *L) {
    lua_CFunction cfunc = NULL;
    const gchar *fieldname = lua_shiftstring(L,2); /* remove the field name */
    const gchar *classname = NULL;
    const gchar *type = NULL;

    /* the userdata object is at index 1, fieldname was at 2 but no longer,
       now we get the getter/setter table at upvalue 1  */
    if (!lua_istable(L, lua_upvalueindex(1)))
        return luaL_error(L, "Accessor dispatcher cannot retrieve the getter/setter table");

    lua_rawgetfield(L, lua_upvalueindex(1), fieldname); /* field's cfunction is now at -1 */

    if (!lua_iscfunction(L, -1)) {
        lua_pop(L,1); /* pop whatever we got before */
        /* check if there's a methods table */
        if (lua_istable(L, lua_upvalueindex(2))) {
            lua_rawgetfield(L, lua_upvalueindex(2), fieldname);
            if (lua_iscfunction(L,-1)) {
                /* we found a method for Lua to call, so give it back to Lua */
                return 1;
            }
            lua_pop(L,1); /* pop whatever we got before */
        }
        classname = wslua_typeof(L, 1);
        type = wslua_typeof(L, lua_upvalueindex(1));
        lua_pop(L, 1); /* pop the nil/invalid getfield result */
        return luaL_error(L, "No such '%s' %s attribute/field for object type '%s'", fieldname, type, classname);
    }

    cfunc = lua_tocfunction(L, -1);
    lua_pop(L, 1); /* pop the cfunction */

    /* the stack is now as if it had been calling the getter/setter c-function directly, so do it */
    return (*cfunc)(L);
}


/* This function "registers" attribute functions - i.e., getters/setters for Lua objects.
 * This way we don't have to write the __index/__newindex function dispatcher for every
 * wslua class.  Instead, your class should use WSLUA_REGISTER_ATTRIBUTES(classname), which
 * ultimately calls this one - it calls it twice: once to register getters, once to register
 * setters.
 *
 * The way this all works is every wslua class has a metatable.  One of the fields of that
 * metatable is a __index field, used for "getter" access, and a __newindex field used for
 * "setter" access.  If the __index field's _value_ is a Lua table, then Lua looks
 * up that table, as it does for class methods for example; but if the __index field's
 * value is a function/cfunction, Lua calls it instead to get/set the field.  So
 * we use that behavior to access our getters/setters, by creating a table of getter
 * cfunctions, saving that as an upvalue of a dispatcher cfunction, and using that
 * dispatcher cfunction as the value of the __index field of the metatable of the wslua object.
 *
 * In some cases, the metatable _index/__newindex will already be a function; for example if
 * class methods were registered, then __index will already be a function  In that case, we
 * move the __methods table to be an upvalue of the attribute dispatcher function.  The attribute
 * dispatcher will look for it and return the method, if it doesn't find an attribute field.
 * The code below makes sure the attribute names don't overlap with method names.
 *
 * This function assumes there's a class metatable on top of the stack when it's initially called,
 * and leaves it on top when done.
 */
int wslua_reg_attributes(lua_State *L, const wslua_attribute_table *t, gboolean is_getter) {
    int midx = lua_gettop(L);
    const gchar *metafield = is_getter ? "__index" : "__newindex";
    int idx;
    int nup = 1; /* number of upvalues */

    if (!lua_istable(L, midx)) {
        fprintf(stderr, "No metatable in the Lua stack when registering attributes!\n");
        exit(1);
    }

    /* check if there's a __index/__newindex table already - could be if this class has methods */
    lua_rawgetfield(L, midx, metafield);
    if (lua_isnil(L, -1)) {
        /* there isn't one, pop the nil */
        lua_pop(L,1);
    }
    else if (lua_istable(L, -1)) {
        /* there is one, so make it be the attribute dispatchers upvalue #2 table */
        nup = 2;
    }
    else if (lua_iscfunction(L, -1)) {
        /* there's a methods __index dispatcher, copy the __methods table */
        lua_pop(L,1); /* pop the cfunction */
        lua_rawgetfield(L, midx, "__methods");
        if (!lua_istable(L, -1)) {
            /* oh oh, something's wrong */
            fprintf(stderr, "got a __index cfunction but no __methods table when registering attributes!\n");
            exit(1);
        }
        nup = 2;
    }
    else {
        fprintf(stderr, "'%s' field is not a table in the Lua stack when registering attributes!\n", metafield);
        exit(1);
    }

    /* make our new getter/setter table - we don't need to pop it later */
    lua_newtable(L);
    idx = lua_gettop(L);

    /* fill the getter/setter table with given functions */
    for (; t->fieldname != NULL; t++) {
        lua_CFunction cfunc = is_getter ? t->getfunc : t->setfunc;
        if (cfunc) {
            /* if there's a previous methods table, make sure this attribute name doesn't collide */
            if (nup > 1) {
                lua_rawgetfield(L, -2, t->fieldname);
                if (!lua_isnil(L,-1)) {
                    fprintf(stderr, "'%s' attribute name already exists as method name for the class\n", t->fieldname);
                    exit(1);
                }
                lua_pop(L,1);  /* pop the nil */
            }
            lua_pushcfunction(L, cfunc);
            lua_rawsetfield(L, idx, t->fieldname);
        }
    }

    /* push the getter/setter table name into its table, for error reporting purposes */
    lua_pushstring(L, (is_getter ? "getter" : "setter"));
    lua_rawsetfield(L, idx, WSLUA_TYPEOF_FIELD);

    /* copy table into the class's metatable, for introspection */
    lua_pushvalue(L, idx);
    lua_rawsetfield(L, midx, (is_getter ? "__getters" : "__setters"));

    if (nup > 1) {
        /* we've got more than one upvalue, so move the new getter/setter to the bottom-most of those */
        lua_insert(L,-nup);
    }

    /* we should now be back to having gettter/setter table at -1 (or -2 if there was a previous methods table) */
    /* create upvalue of getter/setter table for wslua_attribute_dispatcher function */
    lua_pushcclosure(L, wslua_attribute_dispatcher, nup); /* pushes cfunc with upvalue, removes getter/setter table */
    lua_rawsetfield(L, midx, metafield); /* sets this dispatch function as __index/__newindex field of metatable */

    /* we should now be back to real metatable being on top */
    return 0;
}

/* similar to __index metamethod but without triggering more metamethods */
static int wslua__index(lua_State *L) {
    const gchar *fieldname = lua_shiftstring(L,2); /* remove the field name */

    /* the userdata object or table is at index 1, fieldname was at 2 but no longer,
       now we get the metatable, so we can get the methods table */
    if (!lua_getmetatable(L,1)) {
        /* this should be impossible */
        return luaL_error(L, "No such '%s' field", fieldname);
    }

    lua_rawgetfield(L, 2, "__methods"); /* method table is now at 3 */
    lua_remove(L,2); /* remove metatable, methods table is at 2 */

    if (!lua_istable(L, -1)) {
        const gchar *classname = wslua_typeof(L, 1);
        lua_pop(L, 1); /* pop the nil getfield result */
        return luaL_error(L, "No such '%s' field for object type '%s'", fieldname, classname);
    }

    lua_rawgetfield(L, 2, fieldname); /* field's value/function is now at 3 */
    lua_remove(L,2); /* remove methods table, field value si at 2 */

    if (lua_isnil(L, -1)) {
        const gchar *classname = wslua_typeof(L, 1);
        lua_pop(L, 1); /* pop the nil getfield result */
        return luaL_error(L, "No such '%s' function/method/field for object type '%s'", fieldname, classname);
    }

    /* we found a method for Lua to call, or a value of some type, so give it back to Lua */
    return 1;
}

/*
 * This function assumes there's a class methods table at index 1, and its metatable at 2,
 * when it's initially called, and leaves them that way when done.
 */
int wslua_set__index(lua_State *L) {

    if (!lua_istable(L, 2) || !lua_istable(L, 1)) {
        fprintf(stderr, "No metatable or class table in the Lua stack when registering __index!\n");
        exit(1);
    }

    /* push a copy of the class methods table, and set it to be the metatable's __methods field */
    lua_pushvalue (L, 1);
    lua_rawsetfield(L, 2, "__methods");

    /* set the wslua__index to be the __index metamethod */
    lua_pushcfunction(L, wslua__index);
    lua_rawsetfield(L, 2, "__index");

    /* we should now be back to real metatable being on top */
    return 0;
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
    char c, d;

    static const char str_to_nibble[256] = {
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
        c = str_to_nibble[(int)data[i]];
        if (c < 0) {
            if (seplen && strncmp(&data[i], sep, seplen) == 0) {
                i += seplen;
                continue;
            } else {
                break;
            }
        }
        d = str_to_nibble[(int)data[++i]];
        if (d < 0) break;
        luaL_addchar(&b, (c * 16) + d);
        i++;
    }

    luaL_pushresult(&b);

    return 1;
}
