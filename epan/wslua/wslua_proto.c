/*
 * wslua_proto.c
 *
 * wireshark's interface to the Lua Programming Language
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 * (c) 2007, Tamas Regos <tamas.regos@ericsson.com>
 * (c) 2014, Stig Bjorlykke <stig@bjorlykke.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "wslua.h"
#include <epan/dissectors/packet-tcp.h>
#include <epan/exceptions.h>

/* WSLUA_MODULE Proto Functions For New Protocols And Dissectors

   The classes and functions in this chapter allow Lua scripts to create new protocols for Wireshark.
    <<lua_class_Proto,`Proto`>> protocol objects can have <<lua_class_Pref,`Pref`>> preferences, <<lua_class_ProtoField,`ProtoField`>> fields for filterable values that can be displayed in a details view tree, functions for dissecting the new protocol, and so on.

   The dissection function can be hooked into existing protocol tables through <<lua_class_DissectorTable,`DissectorTable`>> so that the new protocol dissector function gets called by that protocol, and the new dissector can itself call on other, already existing protocol dissectors by retrieving and calling the <<lua_class_Dissector,`Dissector`>> object.
   A <<lua_class_Proto,`Proto`>> dissector can also be used as a post-dissector, at the end of every frame's dissection, or as a heuristic dissector.
*/


/*
 * _func_saver stores function refs so that Lua won't garbage collect them prematurely.
 * It is only used by tcp_dissect_pdus right now.
 */
typedef struct _func_saver {
    lua_State* state;
    int get_len_ref;
    int dissect_ref;
} func_saver_t;

static GPtrArray* outstanding_FuncSavers = NULL;

void clear_outstanding_FuncSavers(void) {
    while (outstanding_FuncSavers->len) {
        func_saver_t* fs = (func_saver_t*)g_ptr_array_remove_index_fast(outstanding_FuncSavers,0);
        if (fs->state) {
            lua_State* L = fs->state;
            if (fs->get_len_ref != LUA_NOREF) {
                luaL_unref(L, LUA_REGISTRYINDEX, fs->get_len_ref);
            }
            if (fs->dissect_ref != LUA_NOREF) {
                luaL_unref(L, LUA_REGISTRYINDEX, fs->dissect_ref);
            }
        }
        g_free(fs);
    }
}


WSLUA_CLASS_DEFINE(Proto,FAIL_ON_NULL("Proto"));
/*
  A new protocol in Wireshark.
  Protocols have several uses.
  The main one is to dissect a protocol, but they can also be dummies used to register preferences for other purposes.
 */

static int protocols_table_ref = LUA_NOREF;

WSLUA_CONSTRUCTOR Proto_new(lua_State* L) { /* Creates a new <<lua_class_Proto,`Proto`>> object. */
#define WSLUA_ARG_Proto_new_NAME 1 /* The name of the protocol. */
#define WSLUA_ARG_Proto_new_DESC 2 /* A Long Text description of the protocol (usually lowercase). */
    const gchar* name = luaL_checkstring(L,WSLUA_ARG_Proto_new_NAME);
    const gchar* desc = luaL_checkstring(L,WSLUA_ARG_Proto_new_DESC);
    Proto proto;
    gchar *loname, *hiname;

    /* TODO: should really make a common function for all of wslua that does checkstring and non-empty at same time */
    if (!name[0]) {
        WSLUA_ARG_ERROR(Proto_new,NAME,"must not be an empty string");
        return 0;
    }

    if (!desc[0]) {
        WSLUA_ARG_ERROR(Proto_new,DESC,"must not be an empty string");
        return 0;
    }

    if (proto_name_already_registered(desc)) {
        WSLUA_ARG_ERROR(Proto_new,DESC,"there cannot be two protocols with the same description");
        return 0;
    }

    loname = g_ascii_strdown(name, -1);
    if (proto_check_field_name(loname)) {
        g_free(loname);
        WSLUA_ARG_ERROR(Proto_new,NAME,"invalid character in name");
        return 0;
    }

    hiname = g_ascii_strup(name, -1);
    if ((proto_get_id_by_short_name(hiname) != -1) ||
        (proto_get_id_by_filter_name(loname) != -1))
    {
        g_free(loname);
        g_free(hiname);
        WSLUA_ARG_ERROR(Proto_new,NAME,"there cannot be two protocols with the same name");
        return 0;
    }

    proto = g_new0(wslua_proto_t, 1);

    proto->name = hiname;
    proto->loname = loname;
    proto->desc = g_strdup(desc);
    proto->hfid = proto_register_protocol(proto->desc,hiname,loname);
    proto->ett = -1;
    proto->is_postdissector = FALSE;
    proto->expired = FALSE;

    lua_newtable (L);
    proto->fields = luaL_ref(L, LUA_REGISTRYINDEX);

    lua_newtable (L);
    proto->expert_info_table_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    proto->expert_module = expert_register_protocol(proto->hfid);

    proto->prefs.name = NULL;
    proto->prefs.label = NULL;
    proto->prefs.desc = NULL;
    proto->prefs.value.u = 0;
    proto->prefs.next = NULL;
    proto->prefs.proto = proto;

    proto->prefs_module = NULL;
    proto->handle = NULL;

    lua_rawgeti(L, LUA_REGISTRYINDEX, protocols_table_ref);

    lua_pushstring(L,loname);
    pushProto(L,proto);

    lua_settable(L, -3);

    pushProto(L,proto);

    WSLUA_RETURN(1); /* The newly created <<lua_class_Proto,`Proto`>> object. */
}

WSLUA_METAMETHOD Proto__call(lua_State* L) { /* Creates a <<lua_class_Proto,`Proto`>> object. */
#define WSLUA_ARG_Proto__call_NAME 1 /* The name of the protocol. */
#define WSLUA_ARG_Proto__call_DESC 2 /* A Long Text description of the protocol (usually lowercase). */
    lua_remove(L,1); /* remove the table */
    WSLUA_RETURN(Proto_new(L)); /* The new <<lua_class_Proto,`Proto`>> object. */
}

static int Proto__tostring(lua_State* L) {
    Proto proto = checkProto(L,1);

    lua_pushfstring(L, "Proto: %s", proto->name);

    return 1;
}

WSLUA_FUNCTION wslua_register_postdissector(lua_State* L) {
    /* Make a <<lua_class_Proto,`Proto`>> protocol (with a dissector function) a post-dissector.
       It will be called for every frame after dissection. */
#define WSLUA_ARG_register_postdissector_PROTO 1 /* The protocol to be used as post-dissector. */
#define WSLUA_OPTARG_register_postdissector_ALLFIELDS 2 /* Whether to generate all fields.
                                                           Note: This impacts performance (default=false). */

    Proto proto = checkProto(L,WSLUA_ARG_register_postdissector_PROTO);
    const gboolean all_fields = wslua_optbool(L, WSLUA_OPTARG_register_postdissector_ALLFIELDS, FALSE);

    if(!proto->is_postdissector) {
        if (! proto->handle) {
            proto->handle = register_dissector(proto->loname, dissect_lua, proto->hfid);
        }

        register_postdissector(proto->handle);
        proto->is_postdissector = TRUE;
    } else {
        luaL_argerror(L,1,"this protocol is already registered as postdissector");
    }

    if (all_fields) {
        /*
         * XXX - are there any Lua postdissectors that need "all fields",
         * i.e. the entire protocol tree, or do they just look for
         * *particular* fields, with field extractors?
         *
         * And do all of them require the actual *displayed* format of
         * the fields they need?
         *
         * If not, this is overkill.
         */
        epan_set_always_visible(TRUE);
    }

    return 0;
}

WSLUA_METHOD Proto_register_heuristic(lua_State* L) {
    /* Registers a heuristic dissector function for this <<lua_class_Proto,`Proto`>> protocol,
       for the given heuristic list name.

       When later called, the passed-in function will be given:
           1. A <<lua_class_Tvb,`Tvb`>> object
           2. A <<lua_class_Pinfo,`Pinfo`>> object
           3. A <<lua_class_TreeItem,`TreeItem`>> object

       The function must return `true` if the payload is for it, else `false`.

       The function should perform as much verification as possible to ensure the payload is for it,
       and dissect the packet (including setting TreeItem info and such) only if the payload is for it,
       before returning true or false.

       Since version 1.99.1, this function also accepts a Dissector object as the second argument,
       to allow re-using the same Lua code as the `function proto.dissector(...)`. In this case,
       the Dissector must return a Lua number of the number of bytes consumed/parsed: if 0 is returned,
       it will be treated the same as a `false` return for the heuristic; if a positive or negative
       number is returned, then the it will be treated the same as a `true` return for the heuristic,
       meaning the packet is for this protocol and no other heuristic will be tried.

       @since 1.11.3
     */
#define WSLUA_ARG_Proto_register_heuristic_LISTNAME 2 /* The heuristic list name this function
                                                         is a heuristic for (e.g., "udp" or
                                                         "infiniband.payload"). */
#define WSLUA_ARG_Proto_register_heuristic_FUNC 3 /* A Lua function that will be invoked for
                                                     heuristic dissection. */
    Proto proto = checkProto(L,1);
    const gchar *listname = luaL_checkstring(L, WSLUA_ARG_Proto_register_heuristic_LISTNAME);
    const gchar *proto_name = proto->name;
    const int top = lua_gettop(L);
    gchar *short_name;

    if (!proto_name || proto->hfid == -1) {
        /* this shouldn't happen - internal bug if it does */
        luaL_error(L,"Proto_register_heuristic: got NULL proto name or invalid hfid");
        return 0;
    }

    /* verify listname has a heuristic list */
    if (!has_heur_dissector_list(listname)) {
        luaL_error(L, "there is no heuristic list for '%s'", listname);
        return 0;
    }

    short_name = wmem_strconcat(NULL, proto->loname, "_", listname, NULL);

    /* verify that this is not already registered */
    if (find_heur_dissector_by_unique_short_name(short_name)) {
        wmem_free(NULL, short_name);
        luaL_error(L, "'%s' is already registered as heuristic", proto->loname);
        return 0;
    }
    wmem_free(NULL, short_name);

    /* we'll check if the second form of this function was called: when the second arg is
       a Dissector obejct. The truth is we don't need the Dissector object to do this
       form of registration, but someday we might... so we're using it as a boolean arg
       right now and in the future might use it for other things in this registration.
     */
    if (isDissector(L, WSLUA_ARG_Proto_register_heuristic_FUNC)) {
        /* retrieve the Dissector's Lua function... first get the table of all dissector funcs */
        lua_rawgeti(L, LUA_REGISTRYINDEX, lua_dissectors_table_ref);
        /* then get the one for this Proto */
        lua_getfield(L, -1, proto_name);

        if (!lua_isfunction(L,-1)) {
            /* this shouldn't be possible */
            luaL_error(L,"Proto_register_heuristic: could not get lua function from lua_dissectors_table");
            return 0;
        }
        /* replace the Dissector with the function */
        lua_replace(L, WSLUA_ARG_Proto_register_heuristic_FUNC);
        /* pop the lua_dissectors_table */
        lua_pop(L, 1);
        ws_assert(top == lua_gettop(L));
    }

    /* heuristic functions are stored in a table in the registry; the registry has a
     * table at reference lua_heur_dissectors_table_ref, and that table has keys for
     * the heuristic listname (e.g., "udp", "tcp", etc.), and that key's value is a
     * table of keys of the Proto->name, and their value is the function.
     * So it's like registry[table_ref][heur_list_name][proto_name] = func
     */
    if (lua_isfunction(L,WSLUA_ARG_Proto_register_heuristic_FUNC)) {
        /* insert the heur dissector into the heur dissectors table */
        lua_rawgeti(L, LUA_REGISTRYINDEX, lua_heur_dissectors_table_ref);
        /* the heuristic lists table is now at -1 */
        if (!lua_istable(L,-1)) {
            /* this shouldn't be possible */
            luaL_error(L,"Proto_register_heuristic: could not get lua_heur_dissectors table from registry");
            return 0;
        }

        if (!wslua_get_table(L,-1,listname)) {
            /* no one's registered a lua heuristic for this list, so make a new list table */
            lua_newtable(L);
            lua_pushvalue(L,-1); /* duplicate the table so we can set it as a field */
            lua_setfield(L,-3,listname); /* sets this new list table into the lists table */
        }
        else if (wslua_get_field(L,-1,proto_name)) {
            luaL_error(L,"A heuristic dissector for Proto '%s' is already registered for the '%s' list", proto_name, listname);
            return 0;
        }

        /* copy the func, set it as the value for key proto_name in listname's table */
        lua_pushvalue(L,WSLUA_ARG_Proto_register_heuristic_FUNC);
        lua_setfield(L,-2,proto_name);

        /* ok, we're done with lua stuff, pop what we added to the stack */
        lua_pop(L,2); /* pop the lists table and the listname table */
        ws_assert(top == lua_gettop(L));

        short_name = wmem_strconcat(NULL, proto->loname, "_", listname, NULL);

        /* now register the single/common heur_dissect_lua function */
        /* XXX - ADD PARAMETERS FOR NEW heur_dissector_add PARAMETERS!!! */
        heur_dissector_add(listname, heur_dissect_lua, proto_name, short_name, proto->hfid, HEURISTIC_ENABLE);

        wmem_free(NULL, short_name);
    } else {
        luaL_argerror(L,3,"The heuristic dissector must be a function");
    }
    return 0;
}

/* WSLUA_ATTRIBUTE Proto_dissector RW The protocol's dissector, a function you define.

   When later called, the function will be given:
       1. A <<lua_class_Tvb,`Tvb`>> object
       2. A <<lua_class_Pinfo,`Pinfo`>> object
       3. A <<lua_class_TreeItem,`TreeItem`>> object
*/
static int Proto_get_dissector(lua_State* L) {
    Proto proto = checkProto(L,1);

    if (proto->handle) {
        pushDissector(L,proto->handle);
        return 1;
    } else {
        luaL_error(L,"The protocol hasn't been registered yet");
        return 0;
    }
}

static int Proto_set_dissector(lua_State* L) {
    Proto proto = checkProto(L,1);

    if (lua_isfunction(L,2)) {
        /* insert the dissector into the dissectors table */
        lua_rawgeti(L, LUA_REGISTRYINDEX, lua_dissectors_table_ref);
        lua_replace(L, 1);
        lua_pushstring(L,proto->name);
        lua_insert(L, 2); /* function is now at 3 */
        lua_settable(L,1);

        if (! proto->handle) {
            proto->handle = register_dissector(proto->loname, dissect_lua, proto->hfid);
        }
    } else {
        luaL_argerror(L,2,"The dissector of a protocol must be a function");
    }
    return 0;
}

/* WSLUA_ATTRIBUTE Proto_prefs RO The preferences of this dissector. */
static int Proto_get_prefs(lua_State* L) {
    Proto proto = checkProto(L,1);
    pushPrefs(L,&proto->prefs);
    return 1;
}

/* WSLUA_ATTRIBUTE Proto_prefs_changed WO The preferences changed routine of this dissector,
   a Lua function you define.
 */
static int Proto_set_prefs_changed(lua_State* L) {
    Proto proto = checkProto(L,1);

    if (lua_isfunction(L,2)) {
        /* insert the prefs changed callback into the prefs_changed table */
        lua_getglobal(L, WSLUA_PREFS_CHANGED);
        lua_replace(L, 1);
        lua_pushstring(L,proto->name);
        lua_insert(L, 2); /* function is now at 3 */
        lua_settable(L,1);
    }  else {
        luaL_argerror(L,2,"The prefs of a protocol must be a function");
    }
    return 0;
}

/* WSLUA_ATTRIBUTE Proto_init WO The init routine of this dissector, a function you define.

   The called init function is passed no arguments.
*/
static int Proto_set_init(lua_State* L) {
    Proto proto = checkProto(L,1);

    if (lua_isfunction(L,2)) {
        /* insert the init routine into the init_routines table */
        lua_getglobal(L, WSLUA_INIT_ROUTINES);
        lua_replace(L, 1);
        lua_pushstring(L,proto->name);
        lua_insert(L, 2); /* function is now at 3 */
        lua_settable(L,1);
    }  else {
        luaL_argerror(L,2,"The initializer of a protocol must be a function");
    }
    return 0;
}

/* WSLUA_ATTRIBUTE Proto_name RO The name given to this dissector. */
WSLUA_ATTRIBUTE_STRING_GETTER(Proto,name);

/* WSLUA_ATTRIBUTE Proto_description RO The description given to this dissector. */
WSLUA_ATTRIBUTE_NAMED_STRING_GETTER(Proto,description,desc);

/* WSLUA_ATTRIBUTE Proto_fields RW The `ProtoField`++'++s Lua table of this dissector. */
static int Proto_get_fields(lua_State* L) {
    Proto proto = checkProto(L,1);
    lua_rawgeti(L, LUA_REGISTRYINDEX, proto->fields);
    return 1;
}

static int Proto_set_fields(lua_State* L) {
    Proto proto = checkProto(L,1);
#define FIELDS_TABLE 2
#define NEW_TABLE 3
#define NEW_FIELD 3

    lua_rawgeti(L, LUA_REGISTRYINDEX, proto->fields);
    lua_insert(L,FIELDS_TABLE);

    if( lua_istable(L,NEW_TABLE)) {
        for (lua_pushnil(L); lua_next(L, NEW_TABLE); ) {
            if (isProtoField(L,5)) {
                luaL_ref(L,FIELDS_TABLE);
            } else if (! lua_isnil(L,5) ) {
                return luaL_error(L,"only ProtoFields should be in the table");
            }
        }
    } else if (isProtoField(L,NEW_FIELD)){
        lua_pushvalue(L, NEW_FIELD);
        luaL_ref(L,FIELDS_TABLE);

    } else {
        return luaL_error(L,"either a ProtoField or an array of protofields");
    }

    lua_pushvalue(L, 3);

    return 1;
}

/* WSLUA_ATTRIBUTE Proto_experts RW The expert info Lua table of this `Proto`.

   @since 1.11.3
 */
static int Proto_get_experts(lua_State* L) {
    Proto proto = checkProto(L,1);
    lua_rawgeti(L, LUA_REGISTRYINDEX, proto->expert_info_table_ref);
    return 1;
}

static int Proto_set_experts(lua_State* L) {
    Proto proto = checkProto(L,1);
#define EI_TABLE 2
#define NEW_TABLE 3
#define NEW_FIELD 3

    lua_rawgeti(L, LUA_REGISTRYINDEX, proto->expert_info_table_ref);
    lua_insert(L,EI_TABLE);

    if( lua_istable(L,NEW_TABLE)) {
        for (lua_pushnil(L); lua_next(L, NEW_TABLE); ) {
            if (isProtoExpert(L,5)) {
                luaL_ref(L,EI_TABLE);
            } else if (! lua_isnil(L,5) ) {
                return luaL_error(L,"only ProtoExperts should be in the table");
            }
        }
    } else if (isProtoExpert(L,NEW_FIELD)){
        lua_pushvalue(L, NEW_FIELD);
        luaL_ref(L,EI_TABLE);

    } else {
        return luaL_error(L,"either a ProtoExpert or an array of ProtoExperts");
    }

    lua_pushvalue(L, 3);

    return 1;
}

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int Proto__gc(lua_State* L) {
    /* Proto is registered twice, once in protocols_table_ref and once returned from Proto_new.
     * It will not be freed unless deregistered.
     */
    Proto proto = toProto(L,1);

    if (!proto->expired) {
        proto->expired = TRUE;
    } else if (proto->hfid == -2) {
        /* Only free deregistered Proto */
        g_free(proto);
    }

    return 0;
}

/* This table is ultimately registered as a sub-table of the class' metatable,
 * and if __index/__newindex is invoked then it calls the appropriate function
 * from this table for getting/setting the members.
 */
WSLUA_ATTRIBUTES Proto_attributes[] = {
    WSLUA_ATTRIBUTE_RWREG(Proto,dissector),
    WSLUA_ATTRIBUTE_RWREG(Proto,fields),
    WSLUA_ATTRIBUTE_RWREG(Proto,experts),
    WSLUA_ATTRIBUTE_ROREG(Proto,prefs),
    WSLUA_ATTRIBUTE_WOREG(Proto,prefs_changed),
    WSLUA_ATTRIBUTE_WOREG(Proto,init),
    WSLUA_ATTRIBUTE_ROREG(Proto,name),
    WSLUA_ATTRIBUTE_ROREG(Proto,description),
    { NULL, NULL, NULL }
};

WSLUA_METHODS Proto_methods[] = {
    WSLUA_CLASS_FNREG(Proto,new),
    WSLUA_CLASS_FNREG(Proto,register_heuristic),
    { NULL, NULL }
};

WSLUA_META Proto_meta[] = {
    WSLUA_CLASS_MTREG(Proto,tostring),
    WSLUA_CLASS_MTREG(Proto,call),
    { NULL, NULL }
};

int Proto_register(lua_State* L) {
    WSLUA_REGISTER_CLASS_WITH_ATTRS(Proto);

    outstanding_FuncSavers = g_ptr_array_new();

    lua_newtable(L);
    protocols_table_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    return 0;
}

/**
 * Query field abbr that is defined and bound to a Proto in lua.
 * They are not registered until the end of the initialization.
 */
ProtoField wslua_is_field_available(lua_State* L, const char* field_abbr) {
    lua_rawgeti(L, LUA_REGISTRYINDEX, protocols_table_ref);
    lua_pushnil(L);
    while (lua_next(L, -2)) {
        Proto proto;
        proto = checkProto(L, -1);

        lua_rawgeti(L, LUA_REGISTRYINDEX, proto->fields);

        lua_pushnil(L);
        while (lua_next(L, -2)) {
            ProtoField f = checkProtoField(L, -1);
            if (strcmp(field_abbr, f->abbrev) == 0) {
                /* found! */
                lua_pop(L, 6);
                return f;
            }
            lua_pop(L, 1); /* table value */
        }
        lua_pop(L, 2); /* proto->fields and table value */
    }
    lua_pop(L, 1); /* protocols_table_ref */

    return NULL;
}

int wslua_deregister_heur_dissectors(lua_State* L) {
    /* for each registered heur dissector do... */
    lua_rawgeti(L, LUA_REGISTRYINDEX, lua_heur_dissectors_table_ref);
    for (lua_pushnil(L); lua_next(L, -2); lua_pop(L, 1)) {
        const gchar *listname = luaL_checkstring(L, -2);
        for (lua_pushnil(L); lua_next(L, -2); lua_pop(L, 1)) {
            const gchar *proto_name = luaL_checkstring(L, -2);
            int proto_id = proto_get_id_by_short_name(proto_name);
            heur_dissector_delete(listname, heur_dissect_lua, proto_id);
        }
    }
    lua_pop(L, 1); /* lua_heur_dissectors_table_ref */

    return 0;
}

int wslua_deregister_protocols(lua_State* L) {
    /* for each registered Proto protocol do... */
    lua_rawgeti(L, LUA_REGISTRYINDEX, protocols_table_ref);
    for (lua_pushnil(L); lua_next(L, -2); lua_pop(L, 1)) {
        Proto proto;
        proto = checkProto(L, -1);

        if (proto->handle) {
            deregister_dissector(proto->loname);
        }
        if (proto->prefs_module) {
            Pref pref;
            prefs_deregister_protocol(proto->hfid);
            /* Preferences are unregistered, now free its memory via Pref__gc */
            for (pref = proto->prefs.next; pref; pref = pref->next) {
                int pref_ref = pref->ref;
                pref->ref = LUA_NOREF;
                luaL_unref(L, LUA_REGISTRYINDEX, pref_ref);
            }
        }
        if (proto->expert_module) {
            expert_deregister_protocol(proto->expert_module);
        }
        proto_deregister_protocol(proto->name);

        /* for each registered ProtoField do... */
        lua_rawgeti(L, LUA_REGISTRYINDEX, proto->fields);
        for (lua_pushnil(L); lua_next(L, -2); lua_pop(L, 1)) {
            ProtoField f = checkProtoField(L, -1);

            /* Memory ownership was previously transferred to epan in Proto_commit */
            f->name = NULL;
            f->abbrev = NULL;
            f->vs = NULL;
            f->blob = NULL;

            f->hfid = -2; /* Deregister ProtoField, freed in ProtoField__gc */
        }
        lua_pop(L, 1);

        /* for each registered ProtoExpert do... */
        lua_rawgeti(L, LUA_REGISTRYINDEX, proto->expert_info_table_ref);
        for (lua_pushnil(L); lua_next(L, -2); lua_pop(L, 1)) {
            ProtoExpert pe = checkProtoExpert(L,-1);

            /* Memory ownership was previously transferred to epan in Proto_commit */
            pe->abbrev = NULL;
            pe->text = NULL;

            pe->ids.hf = -2; /* Deregister ProtoExpert, freed in ProtoExpert__gc */
        }
        lua_pop(L, 1);

        if (proto->hfa && proto->hfa->len) {
            proto_add_deregistered_data(g_array_free(proto->hfa,FALSE));
        } else {
            g_array_free(proto->hfa,TRUE);
        }

        /* No need for deferred deletion of subtree indexes */
        g_array_free(proto->etta,TRUE);

        if (proto->eia && proto->eia->len) {
            proto_add_deregistered_data(g_array_free(proto->eia,FALSE));
        } else {
            g_array_free(proto->eia,TRUE);
        }

        proto->hfid = -2; /* Deregister Proto, freed in Proto__gc */
    }

    lua_pop(L, 1); /* protocols_table_ref */

    return 0;
}

int Proto_commit(lua_State* L) {
    lua_settop(L,0);
    /* the following gets the table of registered Proto protocols and puts it on the stack (index=1) */
    lua_rawgeti(L, LUA_REGISTRYINDEX, protocols_table_ref);

    /* for each registered Proto protocol do... */
    for (lua_pushnil(L); lua_next(L, 1); lua_pop(L, 2)) {
        /* lua_next() pop'ed the nil, pushed a table entry key at index=2, with value at index=3.
           In our case, the key is the Proto's name, and the value is the Proto object.
           At next iteration, the value (Proto object) and ProtoExperts table will be pop'ed due
           to lua_pop(L, 2), and when lua_next() returns 0 (no more table entries), it will have
           pop'ed the final key itself, leaving just the protocols_table_ref table on the stack.
         */
        Proto proto = checkProto(L,3);
        gint*   ettp = NULL;

        proto->hfa  = g_array_new(TRUE,TRUE,sizeof(hf_register_info));
        proto->etta = g_array_new(TRUE,TRUE,sizeof(gint*));
        proto->eia  = g_array_new(TRUE,TRUE,sizeof(ei_register_info));

        ettp = &(proto->ett);
        g_array_append_val(proto->etta,ettp);

        /* get the Lua table of ProtoFields, push it on the stack (index=3) */
        lua_rawgeti(L, LUA_REGISTRYINDEX, proto->fields);

        /* for each ProtoField in the Lua table do... */
        for (lua_pushnil(L); lua_next(L, 4); lua_pop(L, 1)) {
            ProtoField f = checkProtoField(L,6);
            hf_register_info hfri = { NULL, { NULL, NULL, FT_NONE, 0, NULL, 0, NULL, HFILL } };
            ettp = &(f->ett);

            hfri.p_id = &(f->hfid);
            hfri.hfinfo.name = f->name;
            hfri.hfinfo.abbrev = f->abbrev;
            hfri.hfinfo.type = f->type;
            hfri.hfinfo.display = f->base;
            hfri.hfinfo.strings = VALS(f->vs);
            hfri.hfinfo.bitmask = f->mask;
            hfri.hfinfo.blurb = f->blob;

            // XXX this will leak resources.
            if (f->hfid != -2) {
                return luaL_error(L,"fields can be registered only once");
            }

            f->hfid = -1;
            g_array_append_val(proto->hfa,hfri);
            g_array_append_val(proto->etta,ettp);
        }

        /* register the proto fields */
        proto_register_field_array(proto->hfid,(hf_register_info*)(void*)proto->hfa->data,proto->hfa->len);
        proto_register_subtree_array((gint**)(void*)proto->etta->data,proto->etta->len);

        lua_pop(L,1); /* pop the table of ProtoFields */

        /* now do the same thing for expert fields */

        /* get the Lua table of ProtoExperts, push it on the stack (index=2) */
        lua_rawgeti(L, LUA_REGISTRYINDEX, proto->expert_info_table_ref);

        /* for each ProtoExpert in the Lua table do... */
        for (lua_pushnil(L); lua_next(L, 4); lua_pop(L, 1)) {
            ProtoExpert e = checkProtoExpert(L,6);
            ei_register_info eiri = { NULL, { NULL, 0, 0, NULL, EXPFILL } };

            eiri.ids             = &(e->ids);
            eiri.eiinfo.name     = e->abbrev;
            eiri.eiinfo.group    = e->group;
            eiri.eiinfo.severity = e->severity;
            eiri.eiinfo.summary  = e->text;

            if (e->ids.ei != EI_INIT_EI || e->ids.hf != -2) {
                return luaL_error(L,"expert fields can be registered only once");
            }

            e->ids.hf = -1;
            g_array_append_val(proto->eia,eiri);
        }

        expert_register_field_array(proto->expert_module, (ei_register_info*)(void*)proto->eia->data, proto->eia->len);

        /* Proto object and ProtoFields table will be pop'ed by lua_pop(L, 2) in for statement */
    }

    lua_pop(L,1); /* pop the protocols_table_ref */

    return 0;
}

static guint
wslua_dissect_tcp_get_pdu_len(packet_info *pinfo, tvbuff_t *tvb,
                              int offset, void *data)
{
    /* WARNING: called from a TRY block, do not call luaL_error! */
    func_saver_t* fs = (func_saver_t*)data;
    lua_State* L = fs->state;
    int pdu_len = 0;

    lua_settop(L, 0);
    lua_rawgeti(L, LUA_REGISTRYINDEX, fs->get_len_ref);

    if (lua_isfunction(L,1)) {

        push_Tvb(L,tvb);
        push_Pinfo(L,pinfo);
        lua_pushinteger(L,offset);

        if  ( lua_pcall(L,3,1,0) ) {
            THROW_LUA_ERROR("Lua Error in dissect_tcp_pdus get_len_func: %s", lua_tostring(L,-1));
        } else {
            /* if the Lua dissector reported the consumed bytes, pass it to our caller */
            if (lua_isnumber(L, -1)) {
                /* we got the pdu_len */
                pdu_len = wslua_togint(L, -1);
                lua_pop(L, 1);
            } else {
                THROW_LUA_ERROR("Lua Error dissect_tcp_pdus: get_len_func did not return a Lua number of the PDU length");
            }
        }

    } else {
        REPORT_DISSECTOR_BUG("Lua Error in dissect_tcp_pdus: did not find the get_len_func dissector");
    }

    return pdu_len;
}

static int
wslua_dissect_tcp_dissector(tvbuff_t *tvb, packet_info *pinfo,
                            proto_tree *tree, void *data)
{
    /* WARNING: called from a TRY block, do not call luaL_error! */
    func_saver_t* fs = (func_saver_t*)data;
    lua_State* L = fs->state;
    int consumed_bytes = 0;

    lua_settop(L, 0);
    lua_rawgeti(L, LUA_REGISTRYINDEX, fs->dissect_ref);

    if (lua_isfunction(L,1)) {

        push_Tvb(L,tvb);
        push_Pinfo(L,pinfo);
        /* XXX: not sure if it's kosher to just use the tree as the item */
        push_TreeItem(L, tree, (proto_item*)tree);

        if  ( lua_pcall(L,3,1,0) ) {
            THROW_LUA_ERROR("dissect_tcp_pdus dissect_func: %s", lua_tostring(L, -1));
        } else {
            /* if the Lua dissector reported the consumed bytes, pass it to our caller */
            if (lua_isnumber(L, -1)) {
                /* we got the consumed bytes or the missing bytes as a negative number */
                consumed_bytes = wslua_togint(L, -1);
                lua_pop(L, 1);
            }
        }

    } else {
        REPORT_DISSECTOR_BUG("dissect_tcp_pdus: did not find the dissect_func dissector");
    }

    return consumed_bytes;
}


WSLUA_FUNCTION wslua_dissect_tcp_pdus(lua_State* L) {
    /* Make the TCP-layer invoke the given Lua dissection function for each
       PDU in the TCP segment, of the length returned by the given get_len_func
       function.

       This function is useful for protocols that run over TCP and that are
       either a fixed length always, or have a minimum size and have a length
       field encoded within that minimum portion that identifies their full
       length. For such protocols, their protocol dissector function can invoke
       this `dissect_tcp_pdus()` function to make it easier to handle dissecting
       their protocol's messages (i.e., their protocol data unit (PDU)). This
       function shouild not be used for protocols whose PDU length cannot be
       determined from a fixed minimum portion, such as HTTP or Telnet.

       @since 1.99.2
     */
#define WSLUA_ARG_dissect_tcp_pdus_TVB 1 /* The Tvb buffer to dissect PDUs from. */
#define WSLUA_ARG_dissect_tcp_pdus_TREE 2 /* The Tvb buffer to dissect PDUs from. */
#define WSLUA_ARG_dissect_tcp_pdus_MIN_HEADER_SIZE 3 /* The number of bytes
                        in the fixed-length part of the PDU. */
#define WSLUA_ARG_dissect_tcp_pdus_GET_LEN_FUNC 4 /* A Lua function that will be
                        called for each PDU, to determine the full length of the
                        PDU. The called function will be given (1) the `Tvb` object
                        of the whole `Tvb` (possibly reassembled), (2) the `Pinfo` object,
                        and (3) an offset number of the index of the first byte
                        of the PDU (i.e., its first header byte). The Lua function
                        must return a Lua number of the full length of the PDU. */
#define WSLUA_ARG_dissect_tcp_pdus_DISSECT_FUNC 5 /* A Lua function that will be
                        called for each PDU, to dissect the PDU. The called
                        function will be given (1) the `Tvb` object of the PDU's
                        `Tvb` (possibly reassembled), (2) the `Pinfo` object,
                        and (3) the `TreeItem` object. The Lua function must
                        return a Lua number of the number of bytes read/handled,
                        which would typically be the `Tvb:len()`.*/
#define WSLUA_OPTARG_dissect_tcp_pdus_DESEGMENT 6 /* Whether to reassemble PDUs
                        crossing TCP segment boundaries or not. (default=true) */
    Tvb tvb = checkTvb(L,WSLUA_ARG_dissect_tcp_pdus_TVB);
    TreeItem ti = checkTreeItem(L,WSLUA_ARG_dissect_tcp_pdus_TREE);
    guint fixed_len = (guint)luaL_checkinteger(L,WSLUA_ARG_dissect_tcp_pdus_MIN_HEADER_SIZE);
    gboolean proto_desegment = wslua_optbool(L, WSLUA_OPTARG_dissect_tcp_pdus_DESEGMENT, TRUE);

    if (!lua_pinfo) {
        luaL_error(L,"dissect_tcp_pdus can only be invoked while in a dissect function");
        return 0;
    }

    if (lua_isfunction(L,WSLUA_ARG_dissect_tcp_pdus_GET_LEN_FUNC) &&
        lua_isfunction(L,WSLUA_ARG_dissect_tcp_pdus_DISSECT_FUNC))
    {
        /* save the Lua functions so that we can call them later */
        func_saver_t* fs = g_new(func_saver_t, 1);

        lua_settop(L, WSLUA_ARG_dissect_tcp_pdus_DISSECT_FUNC);

        fs->state = L;
        /* the following pops the top function and sets a ref to it in the registry */
        fs->dissect_ref = luaL_ref(L, LUA_REGISTRYINDEX);
        fs->get_len_ref = luaL_ref(L, LUA_REGISTRYINDEX);

        /* save the passed-in function refs, so Lua's garbage collector won't
           destroy them before they get invoked */
        g_ptr_array_add(outstanding_FuncSavers, fs);

        WRAP_NON_LUA_EXCEPTIONS(
            tcp_dissect_pdus(tvb->ws_tvb, lua_pinfo, ti->tree, proto_desegment,
                             fixed_len, wslua_dissect_tcp_get_pdu_len,
                             wslua_dissect_tcp_dissector, (void*)fs);
        )
    } else {
        luaL_error(L,"The third and fourth arguments need to be Lua functions");
    }
    return 0;
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
