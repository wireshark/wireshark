/*
 * wslua_file_common.c
 *
 * Wireshark's interface to the Lua Programming Language
 * for file handling related source file internal functions.
 *
 * (c) 2014, Hadriel Kaplan <hadrielk@yahoo.com>
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

/************
 * The following is for handling private data for the duration of the file
 * read_open/read/close cycle, or write_open/write/write_close cycle.
 * In other words it handles the "priv" member of wtap and wtap_dumper,
 * but for the Lua script's use. A Lua script can set a Lua table
 * to CaptureInfo/CaptureInfoConst and have it saved and retrievable this way.
 * We need to offer that, because there needs to be a way for Lua scripts
 * to save state for a given file's operations cycle. Since there can be
 * two files opened at the same time for the same Lua script (due to reload
 * and other such events), the script can't just have one file state.
 */

#include "wslua_file_common.h"


/* create and set the wtap->priv private data for the file instance */
void create_wth_priv(lua_State* L, wtap *wth) {
    file_priv_t *priv = (file_priv_t*)g_malloc(sizeof(file_priv_t));

    if (wth->priv != NULL) {
        luaL_error(L, "Cannot create wtap private data because there already is private data");
        return;
    }
    priv->table_ref = LUA_NOREF;
    wth->priv = (void*) priv;
}

/* gets the private data table from wtap */
int get_wth_priv_table_ref(lua_State* L, wtap *wth) {
    file_priv_t *priv = (file_priv_t*) wth->priv;

    if (!priv) {
        /* shouldn't be possible */
        luaL_error(L, "Cannot get wtap private data: it is null");
        return LUA_NOREF;
    }

    /* the following might push a nil, but that's ok */
    lua_rawgeti(L, LUA_REGISTRYINDEX, priv->table_ref);

    return 1;
}

/* sets the private data to wtap - the table is presumed on top of stack */
int set_wth_priv_table_ref(lua_State* L, wtap *wth) {
    file_priv_t *priv = (file_priv_t*) wth->priv;

    if (!priv) {
        /* shouldn't be possible */
        luaL_error(L, "Cannot get wtap private data: it is null");
        return 0;
    }

    if (lua_isnil(L, -1)){
        /* user is setting it nil - ok, de-ref any previous one */
        luaL_unref(L, LUA_REGISTRYINDEX, priv->table_ref);
        priv->table_ref = LUA_NOREF;
        return 0;
    }

    if (!lua_istable(L, -1)) {
        luaL_error(L, "The private_table member can only be set to a table or nil");
        return 0;
    }

    /* if we had a table already referenced, de-ref it first */
    if (priv->table_ref != LUA_NOREF) {
        luaL_unref(L, LUA_REGISTRYINDEX, priv->table_ref);
    }

    priv->table_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    return 0;
}

/* remove, deref, and free the wtap->priv data */
void remove_wth_priv(lua_State* L, wtap *wth) {
    file_priv_t *priv = (file_priv_t*) wth->priv;

    if (!priv) {
        /* shouldn't be possible */
        luaL_error(L, "Cannot remove wtap private data: it is null");
        return;
    }

    luaL_unref(L, LUA_REGISTRYINDEX, priv->table_ref);

    g_free(wth->priv);
    wth->priv = NULL;
}

/* create and set the wtap_dumper->priv private data for the file instance */
void create_wdh_priv(lua_State* L, wtap_dumper *wdh) {
    file_priv_t *priv = (file_priv_t*)g_malloc(sizeof(file_priv_t));

    if (wdh->priv != NULL) {
        luaL_error(L, "Cannot create wtap_dumper private data because there already is private data");
        return;
    }
    priv->table_ref = LUA_NOREF;
    wdh->priv = (void*) priv;
}

/* get the private data from wtap_dumper */
int get_wdh_priv_table_ref(lua_State* L, wtap_dumper *wdh) {
    file_priv_t *priv = (file_priv_t*) wdh->priv;

    if (!priv) {
        /* shouldn't be possible */
        luaL_error(L, "Cannot get wtap_dumper private data: it is null");
        return LUA_NOREF;
    }

    /* the following might push a nil, but that's ok */
    lua_rawgeti(L, LUA_REGISTRYINDEX, priv->table_ref);

    return 1;
}

/* sets the private data to wtap - the table is presumed on top of stack */
int set_wdh_priv_table_ref(lua_State* L, wtap_dumper *wdh) {
    file_priv_t *priv = (file_priv_t*) wdh->priv;

    if (!priv) {
        /* shouldn't be possible */
        luaL_error(L, "Cannot get wtap private data: it is null");
        return 0;
    }

    if (lua_isnil(L, -1)){
        /* user is setting it nil - ok, de-ref any previous one */
        luaL_unref(L, LUA_REGISTRYINDEX, priv->table_ref);
        priv->table_ref = LUA_NOREF;
        return 0;
    }

    if (!lua_istable(L, -1)) {
        luaL_error(L, "The private_table member can only be set to a table or nil");
        return 0;
    }

    /* if we had a table already referenced, de-ref it first */
    if (priv->table_ref != LUA_NOREF) {
        luaL_unref(L, LUA_REGISTRYINDEX, priv->table_ref);
    }

    priv->table_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    return 0;
}

/* remove and deref the wtap_dumper->priv data */
void remove_wdh_priv(lua_State* L, wtap_dumper *wdh) {
    file_priv_t *priv = (file_priv_t*) wdh->priv;

    if (!priv) {
        /* shouldn't be possible */
        luaL_error(L, "Cannot remove wtap_dumper private data: it is null");
        return;
    }

    luaL_unref(L, LUA_REGISTRYINDEX, priv->table_ref);
    /* we do NOT free wtap_dumper's priv member - wtap_dump_close() free's it */
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
