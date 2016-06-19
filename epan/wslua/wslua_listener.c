/*
 * wslua_listener.c
 *
 * Wireshark's interface to the Lua Programming Language
 *
 *  Implementation of tap Listeners
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
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

/* WSLUA_MODULE Listener Post-dissection packet analysis */

#include "wslua.h"

WSLUA_CLASS_DEFINE(Listener,FAIL_ON_NULL("Listener"));
/*
    A `Listener` is called once for every packet that matches a certain filter or has a certain tap.
    It can read the tree, the packet's `Tvb` buffer as well as the tapped data, but it cannot
    add elements to the tree.
 */

static int tap_packet_cb_error_handler(lua_State* L) {
    const gchar* error =  lua_tostring(L,1);
    static gchar* last_error = NULL;
    static int repeated = 0;
    static int next = 2;
    gchar* where =  (lua_pinfo) ?
        wmem_strdup_printf(NULL, "Lua: on packet %i Error During execution of Listener Packet Callback",lua_pinfo->num) :
        wmem_strdup_printf(NULL, "Lua: Error During execution of Listener Packet Callback") ;

    /* show the error the 1st, 3rd, 5th, 9th, 17th, 33th... time it appears to avoid window flooding */
    /* XXX the last series of identical errors won't be shown (the user however gets at least one message) */

    if (! last_error) {
        report_failure("%s:\n%s",where,error);
        last_error = g_strdup(error);
        repeated = 0;
        next = 2;
        wmem_free(NULL, where);
        return 0;
    }

    if (g_str_equal(last_error,error) ) {
        repeated++;
        if ( repeated == next ) {
            report_failure("%s happened %i times:\n %s",where,repeated,error);
            next *= 2;
        }
    } else {
        report_failure("%s happened %i times:\n %s",where,repeated,last_error);
        g_free(last_error);
        last_error = g_strdup(error);
        repeated = 0;
        next = 2;
        report_failure("%s:\n %s",where,error);
    }

    wmem_free(NULL, where);
    return 0;
}


static gboolean lua_tap_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt, const void *data) {
    Listener tap = (Listener)tapdata;
    gboolean retval = FALSE;

    if (tap->packet_ref == LUA_NOREF) return FALSE;

    lua_settop(tap->L,0);

    lua_pushcfunction(tap->L,tap_packet_cb_error_handler);
    lua_rawgeti(tap->L, LUA_REGISTRYINDEX, tap->packet_ref);

    push_Pinfo(tap->L, pinfo);
    push_Tvb(tap->L, edt->tvb);

    if (tap->extractor) {
        tap->extractor(tap->L,data);
    } else {
        lua_pushnil(tap->L);
    }

    lua_pinfo = pinfo;
    lua_tvb = edt->tvb;
    lua_tree = create_TreeItem(edt->tree, NULL);

    switch ( lua_pcall(tap->L,3,1,1) ) {
        case 0:
            retval = luaL_optinteger(tap->L,-1,1) == 0 ? FALSE : TRUE;
            break;
        case LUA_ERRRUN:
            break;
        case LUA_ERRMEM:
            g_warning("Memory alloc error while calling listener tap callback packet");
            break;
        default:
            g_assert_not_reached();
            break;
    }

    clear_outstanding_Pinfo();
    clear_outstanding_Tvb();

    lua_pinfo = NULL;
    lua_tvb = NULL;
    lua_tree = NULL;

    return retval;
}

static int tap_reset_cb_error_handler(lua_State* L) {
    const gchar* error =  lua_tostring(L,1);
    report_failure("Lua: Error During execution of Listener init Callback:\n %s",error);
    return 1;
}

static void lua_tap_reset(void *tapdata) {
    Listener tap = (Listener)tapdata;

    if (tap->reset_ref == LUA_NOREF) return;

    lua_pushcfunction(tap->L,tap_reset_cb_error_handler);
    lua_rawgeti(tap->L, LUA_REGISTRYINDEX, tap->reset_ref);

    switch ( lua_pcall(tap->L,0,0,1) ) {
        case 0:
            break;
        case LUA_ERRRUN:
            g_warning("Runtime error while calling a listener's init()");
            break;
        case LUA_ERRMEM:
            g_warning("Memory alloc error while calling a listener's init()");
            break;
        default:
            g_assert_not_reached();
            break;
    }
}

static void lua_tap_draw(void *tapdata) {
    Listener tap = (Listener)tapdata;
    const gchar* error;
    if (tap->draw_ref == LUA_NOREF) return;

    lua_pushcfunction(tap->L,tap_reset_cb_error_handler);
    lua_rawgeti(tap->L, LUA_REGISTRYINDEX, tap->draw_ref);

    switch ( lua_pcall(tap->L,0,0,1) ) {
        case 0:
            /* OK */
            break;
        case LUA_ERRRUN:
            error = lua_tostring(tap->L,-1);
            g_warning("Runtime error while calling a listener's draw(): %s",error);
            break;
        case LUA_ERRMEM:
            g_warning("Memory alloc error while calling a listener's draw()");
            break;
        default:
            g_assert_not_reached();
            break;
    }
}

/* TODO: we should probably use a Lua table here */
static GPtrArray *listeners = NULL;

static void deregister_Listener (lua_State* L _U_, Listener tap) {
    if (tap->all_fields) {
        epan_set_always_visible(FALSE);
        tap->all_fields = FALSE;
    }

    remove_tap_listener(tap);

    g_free(tap->filter);
    g_free(tap->name);
    g_free(tap);
}

WSLUA_CONSTRUCTOR Listener_new(lua_State* L) {
    /* Creates a new `Listener` listener object. */
#define WSLUA_OPTARG_Listener_new_TAP 1 /* The name of this tap. */
#define WSLUA_OPTARG_Listener_new_FILTER 2 /* A filter that when matches the `tap.packet` function gets
                                              called (use nil to be called for every packet). */
#define WSLUA_OPTARG_Listener_new_ALLFIELDS 3 /* Whether to generate all fields. (default=false)
                                                 Note: this impacts performance. */

    const gchar* tap_type = luaL_optstring(L,WSLUA_OPTARG_Listener_new_TAP,"frame");
    const gchar* filter = luaL_optstring(L,WSLUA_OPTARG_Listener_new_FILTER,NULL);
    const gboolean all_fields = wslua_optbool(L, WSLUA_OPTARG_Listener_new_ALLFIELDS, FALSE);
    Listener tap;
    GString* error;

    tap = (Listener)g_malloc(sizeof(struct _wslua_tap));

    tap->name = g_strdup(tap_type);
    tap->filter = filter ? g_strdup(filter) : NULL;
    tap->extractor = wslua_get_tap_extractor(tap_type);
    tap->L = L;
    tap->packet_ref = LUA_NOREF;
    tap->draw_ref = LUA_NOREF;
    tap->reset_ref = LUA_NOREF;
    tap->all_fields = all_fields;

    /*
     * XXX - do all Lua taps require the protocol tree?  If not, it might
     * be useful to have a way to indicate whether any do.
     *
     * XXX - do any Lua taps require the columns?  If so, we either need
     * to request them for this tap, or do so if any Lua taps require them.
     */
    error = register_tap_listener(tap_type, tap, tap->filter, TL_REQUIRES_PROTO_TREE, lua_tap_reset, lua_tap_packet, lua_tap_draw);

    if (error) {
        g_free(tap->filter);
        g_free(tap->name);
        g_free(tap);
        /* WSLUA_ERROR(new_tap,"tap registration error"); */
        lua_pushfstring(L,"Error while registering tap:\n%s",error->str);
        g_string_free(error,TRUE);
        luaL_error(L,lua_tostring(L,-1));
    }

    if (all_fields) {
        epan_set_always_visible(TRUE);
    }

    g_ptr_array_add(listeners, tap);

    pushListener(L,tap);
    WSLUA_RETURN(1); /* The newly created Listener listener object */
}

/* Allow dissector key names to be sorted alphabetically */
static gint
compare_dissector_key_name(gconstpointer dissector_a, gconstpointer dissector_b)
{
  return strcmp((const char*)dissector_a, (const char*)dissector_b);
}

WSLUA_CONSTRUCTOR Listener_list (lua_State *L) {
    /* Gets a Lua array table of all registered `Listener` tap names.

       Note: this is an expensive operation, and should only be used for troubleshooting.

       @since 1.11.3
     */
    GList* list = get_tap_names();
    GList* elist = NULL;
    int i = 1;

    if (!list) return luaL_error(L,"Cannot retrieve tap name list");

    list = g_list_sort(list, (GCompareFunc)compare_dissector_key_name);
    elist = g_list_first(list);

    lua_newtable(L);
    for (i=1; elist; i++, elist = g_list_next(elist)) {
        lua_pushstring(L,(const char *) elist->data);
        lua_rawseti(L,1,i);
    }

    g_list_free(list);
    WSLUA_RETURN(1); /* The array table of registered tap names */
}

WSLUA_METHOD Listener_remove(lua_State* L) {
    /* Removes a tap `Listener`. */
    Listener tap = checkListener(L,1);

    if (listeners && g_ptr_array_remove(listeners, tap)) {
        deregister_Listener(L, tap);
    }

    return 0;
}

WSLUA_METAMETHOD Listener__tostring(lua_State* L) {
    /* Generates a string of debug info for the tap `Listener`. */
    Listener tap = checkListener(L,1);

    lua_pushfstring(L,"Listener(%s) filter: %s",tap->name, tap->filter ? tap->filter : "NONE");

    return 1;
}


/* WSLUA_ATTRIBUTE Listener_packet WO A function that will be called once every packet matches the
    `Listener` listener filter.

    When later called by Wireshark, the `packet` function will be given:
      1. A `Pinfo` object
      2. A `Tvb` object
      3. A `tapinfo` table

    @code function tap.packet(pinfo,tvb,tapinfo) ... end @endcode

    @note `tapinfo` is a table of info based on the `Listener`'s type, or nil.
*/
WSLUA_ATTRIBUTE_FUNC_SETTER(Listener,packet);


/* WSLUA_ATTRIBUTE Listener_draw WO A function that will be called once every few seconds to redraw the GUI objects;
            in Tshark this funtion is called only at the very end of the capture file.

    When later called by Wireshark, the `draw` function will not be given any arguments.

    @code function tap.draw() ... end @endcode
*/
WSLUA_ATTRIBUTE_FUNC_SETTER(Listener,draw);

/* WSLUA_ATTRIBUTE Listener_reset WO A function that will be called at the end of the capture run.

    When later called by Wireshark, the `reset` function will not be given any arguments.

    @code function tap.reset() ... end @endcode
*/
WSLUA_ATTRIBUTE_FUNC_SETTER(Listener,reset);


static int Listener__gc(lua_State* L _U_) {
    /* do NOT free Listener here, only in deregister_Listener */
    return 0;
}

/* This table is ultimately registered as a sub-table of the class' metatable,
 * and if __index/__newindex is invoked then it calls the appropriate function
 * from this table for getting/setting the members.
 */
WSLUA_ATTRIBUTES Listener_attributes[] = {
    WSLUA_ATTRIBUTE_WOREG(Listener,packet),
    WSLUA_ATTRIBUTE_WOREG(Listener,draw),
    WSLUA_ATTRIBUTE_WOREG(Listener,reset),
    { NULL, NULL, NULL }
};

WSLUA_METHODS Listener_methods[] = {
    WSLUA_CLASS_FNREG(Listener,new),
    WSLUA_CLASS_FNREG(Listener,remove),
    WSLUA_CLASS_FNREG(Listener,list),
    { NULL, NULL }
};

WSLUA_META Listener_meta[] = {
    WSLUA_CLASS_MTREG(Listener,tostring),
    { NULL, NULL }
};

int Listener_register(lua_State* L) {
    wslua_set_tap_enums(L);

    listeners = g_ptr_array_new();

    WSLUA_REGISTER_CLASS(Listener);
    WSLUA_REGISTER_ATTRIBUTES(Listener);
    return 0;
}

static void deregister_tap_listener (gpointer data, gpointer userdata) {
    lua_State *L = (lua_State *) userdata;
    Listener tap = (Listener) data;
    deregister_Listener(L, tap);
}

int wslua_deregister_listeners(lua_State* L) {
    g_ptr_array_foreach(listeners, deregister_tap_listener, L);
    g_ptr_array_free(listeners, FALSE);
    listeners = NULL;

    return 0;
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
