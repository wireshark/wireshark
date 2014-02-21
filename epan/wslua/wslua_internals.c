/*
 *  wslua_internals.c
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

/* identical to lua_getfield but without triggering metamethods */
WSLUA_API void lua_rawgetfield(lua_State *L, int idx, const char *k) {
    lua_pushstring(L, k);
    lua_rawget(L, idx);
}

/* identical to lua_setfield but without triggering metamethods */
WSLUA_API void lua_rawsetfield (lua_State *L, int idx, const char *k) {
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
        return luaL_error(L, "Accessor dispatcher cannot retrieve the metatable");

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
 * In some cases, the metatable _index/__newindex will already be a table; for example if
 * class methods were registered, then __index will already be a table.  In that case, we
 * move the existing one to be an upvalue of the attribute dispatcher function.  The attribute
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
