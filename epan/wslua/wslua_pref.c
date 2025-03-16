/*
 * wslua_pref.c
 *
 * Wireshark's interface to the Lua Programming Language
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 * (c) 2008, Balint Reczey <balint.reczey@ericsson.com>
 * (c) 2011, Stig Bjorlykke <stig@bjorlykke.org>
 * (c) 2014, Hadriel Kaplan <hadrielk@yahoo.com>
 * (c) 2025, Bartis Csaba <bracsek@bracsek.eu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "wslua.h"

#define MAXIMUM_ALLOWED_UAT_FIELD_COUNT 10

/*
 * Definition of a UAT string container structure.
 *
 * "field_data" is the pointer array to the fields values
 * "uat_filename" is the file name of currently ussed uat
 */

typedef struct {
    char *field_data[MAXIMUM_ALLOWED_UAT_FIELD_COUNT];
    char *uat_filename;
} uat_container_t;

/*
 * Sanity-checks a UAT record.
 *
 * This function do a record checks with the uat_update_cb function from
 * preferences_uat_callbacks.lua Lua file.
 *
 * r is the record from uat
 * err a pointer for showing checks error messages
 */
static bool uat_update_cb(void *r, char **err)
{
    uat_container_t *record = (uat_container_t *)r;
    lua_State *L = luaL_newstate();
    luaL_openlibs(L);
    char *full_path = g_strjoin(G_DIR_SEPARATOR_S,
        get_persconffile_path("", false),
        "plugins", "preferences_uat_callbacks.lua", NULL);
    /* if checker file not exist we will accept all walues! */
    if (!file_exists(full_path)) {
        return true;
    }
    /* search checker function from file */
    if (luaL_dofile(L, full_path) != LUA_OK) {
        lua_close(L);
        return false;
    }
    lua_getglobal(L, "uat_update_cb");
    if (!lua_isfunction(L, -1)) {
        return false;
    }
    /* prepare values for checker function */
    /* first parameter with records values */
    lua_newtable(L);
    for (int i = 0; i < MAXIMUM_ALLOWED_UAT_FIELD_COUNT; i++) {
        lua_pushinteger(L, i);
        lua_pushstring(L, record->field_data[i]);
        lua_settable(L, -3);
    }
    /* second parameter uat filename */
    lua_pushstring(L, record->uat_filename);
    /* call the function with 2 parameter */
    if (lua_pcall(L, 2, 2, 0) != LUA_OK) {
        lua_pop(L, 1);
        lua_close(L);
        return false;
    }
    /* 1th parameter the received result as boolean */
    if (!lua_isboolean(L, -2)) {
        return false;
    }
    bool bool_result = lua_toboolean(L, -2);
    if (lua_isstring(L, -1)) {
        const char *str_result = lua_tostring(L, -1);
        /* returned error as string showed on gui */
        *err = g_strdup(str_result);
        lua_pop(L, 2);
    }
    lua_close(L);
    return bool_result;
}

static void txtmod_string_set_cb(
    void* rec,
    const char* buf,
    unsigned len,
    const void* u1,
    const void* u2)
{
    const uint8_t * index = (const uint8_t *)u1;
    char * uat_file_name = (char *)u2;
    uat_container_t * record = (uat_container_t*)rec;
    unsigned field_data_length;
    char* new_val = uat_unesc(buf,len,&field_data_length);
    g_free((record->field_data[*index]));
    record->field_data[*index] = new_val;
    record->uat_filename = uat_file_name;
}

static void txtmod_string_tostr_cb(
void* rec,
char** out_ptr,
unsigned* out_len,
const void* u1,
const void* UNUSED_PARAMETER(u2))
{
    const uint8_t * index = (const uint8_t *)u1;
    uat_container_t * record = (uat_container_t*)rec;
    if (record->field_data[*index]) {
        *out_ptr = uat_esc(record->field_data[*index], (unsigned)strlen(record->field_data[*index]));
        *out_len = (unsigned)strlen(*out_ptr);
    } else {
        *out_ptr = g_strdup("");
        *out_len = 0;
    }
}

/* UAT variables */
static uat_t *uat;
static uat_container_t *perf_uat_data;
static unsigned num_perf_uat_data;

/* WSLUA_CONTINUE_MODULE Proto */


WSLUA_CLASS_DEFINE(Pref,NOP); /* A preference of a <<lua_class_Proto,`Proto`>>. */

static range_t* get_range(lua_State *L, int idx_r, int idx_m);

static enum_val_t* get_enum(lua_State *L, int idx)
{
    double seq;
    const char *str1, *str2;
    enum_val_t *ret, last = {NULL, NULL, -1};
    GArray* es = g_array_new(true,true,sizeof(enum_val_t));

    luaL_checktype(L, idx, LUA_TTABLE);
    lua_pushnil(L);  /* first key */

    while (lua_next(L, idx)) {
        enum_val_t e = {NULL, NULL, -1};

        luaL_checktype(L, -1, LUA_TTABLE);
        lua_pushnil(L);
        lua_next(L, -2);
        if (! lua_isstring(L,-1)) {
            luaL_argerror(L,idx,"First value of an enum table must be string");
            g_array_free(es,true);
            return NULL;
        }
        str1 = lua_tostring(L, -1);

        lua_pop(L, 1);
        lua_next(L, -2);
        if (! lua_isstring(L,-1)) {
            luaL_argerror(L,idx,"Second value of an enum table must be string");
            g_array_free(es,true);
            return NULL;
        }
        str2 = lua_tostring(L, -1);

        lua_pop(L, 1);
        lua_next(L, -2);
        if (! lua_isnumber(L,-1)) {
            luaL_argerror(L,idx,"Third value of an enum table must be an integer");
            g_array_free(es,true);
            return NULL;
        }
        seq = lua_tonumber(L, -1);

        e.name = g_strdup(str1);
        e.description = g_strdup(str2);
        e.value = (uint32_t)seq;

        g_array_append_val(es,e);

        lua_pop(L, 3);  /* removes 'value'; keeps 'key' for next iteration */
    }

    g_array_append_val(es,last);

    ret = (enum_val_t*)(void*)g_array_free(es, false);

    return ret;
}

static uat_field_t* get_uat_flds_array(lua_State *L, int idx, char * uat_filename)
{
    const char *str1, *str2;
    uint8_t index = 0;
    uat_field_t *ret, last = {NULL, NULL, PT_TXTMOD_STRING,
        {0, txtmod_string_set_cb, txtmod_string_tostr_cb}, {0, 0, 0}, 0, NULL, NULL};
    /* Container to store fields */
    GArray* fs = g_array_new(true,true,sizeof(uat_field_t));
    luaL_checktype(L, idx, LUA_TTABLE);
    lua_pushnil(L);

    while (lua_next(L, idx)) {
        uat_field_t f = {NULL, NULL, PT_TXTMOD_STRING,
            {0, txtmod_string_set_cb, txtmod_string_tostr_cb}, {0, 0, 0}, 0, NULL, NULL};
        /* field title */
        luaL_checktype(L, -1, LUA_TTABLE);
        lua_pushnil(L);
        lua_next(L, -2);
        if (! lua_isstring(L,-1)) {
            luaL_argerror(L,idx,"First value of an UAT table config must be string");
            g_array_free(fs,true);
            return NULL;
        }
        str1 = lua_tostring(L, -1);
        /* field description */
        lua_pop(L, 1);
        lua_next(L, -2);
        if (! lua_isstring(L,-1)) {
            luaL_argerror(L,idx,"Second value of an UAT table config must be string");
            g_array_free(fs,true);
            return NULL;
        }
        str2 = lua_tostring(L, -1);
        /* configure fields, attach index and filename pointer to each field */
        f.title = g_strdup(str1);
        f.desc = g_strdup(str2);
        f.cbdata.chk = g_new(uint8_t, 1);
        *(uint8_t *)f.cbdata.chk = index;
        f.cbdata.set = g_new(uint8_t, 1);
        *(uint8_t *)f.cbdata.set = index;
        f.cbdata.tostr = g_new(uint8_t, 1);
        *(uint8_t *)f.cbdata.tostr = index;
        f.fld_data = uat_filename;

        g_array_append_val(fs,f);
        index = index + 1;
        /* limiting fields count */
        if(index >= MAXIMUM_ALLOWED_UAT_FIELD_COUNT) {
            return NULL;
        }
        lua_pop(L, 3);
    }
    g_array_append_val(fs,last);
    ret = (uat_field_t*)(void*)g_array_free(fs, false);
    return ret;
}

static int new_pref(lua_State* L, pref_type_t type) {
    const char* label = luaL_optstring(L,1,NULL);
    const char* descr = luaL_optstring(L,3,"");

    Pref pref = g_new0(wslua_pref_t, 1);
    pref->label = g_strdup(label);
    pref->desc = g_strdup(descr);
    pref->type = type;
    pref->ref = LUA_NOREF;

    switch(type) {
        case PREF_BOOL: {
            bool def = wslua_toboolean(L,2);
            pref->value.b = def;
            break;
        }
        case PREF_UINT: {
            uint32_t def = wslua_optint32(L,2,0);
            pref->value.u = def;
            break;
        }
        case PREF_STRING: {
            char* def = g_strdup(luaL_optstring(L,2,""));
            /*
             * prefs_register_string_preference() assumes that the
             * variable for the preference points to a static
             * string that is the initial (default) value of the
             * preference.  It makes a g_strdup()ed copy of that
             * string, and assigns a pointer to that string to
             * the variable.
             *
             * Our default string is *not* a static string, it's
             * a g_strdup()ed copy of a string from Lua, so it would
             * be leaked.
             *
             * We save it in info.default_s, as well as setting the
             * initial value of the preference from it, so that we
             * can free it after prefs_register_string_preference()
             * returns.
             *
             * (Would that we were programming in a language where
             * the details of memory management were handled by the
             * compiler and language support....)
             */
            pref->value.s = def;
            pref->info.default_s = def;
            break;
        }
        case PREF_ENUM: {
            uint32_t def = wslua_optint32(L,2,0);
            enum_val_t *enum_val = get_enum(L,4);
            bool radio = wslua_toboolean(L,5);
            pref->value.e = def;
            pref->info.enum_info.enumvals = enum_val;
            pref->info.enum_info.radio_buttons = radio;
            break;
        }
        case PREF_RANGE: {
            range_t *range = get_range(L,2,4);
            uint32_t max = wslua_optint32(L,4,0);
            pref->value.r = range;
            pref->info.max_value = max;
            break;
        }
        case PREF_STATIC_TEXT: {
            /* This is just a static text. */
            break;
        }
        case PREF_UAT: {
            /* get filename */
            const char* uat_file_name = luaL_optstring(L,4,"");
            pref->value.s = g_strdup(uat_file_name);
            /* process fields */
            uat_field_t *flds_array = get_uat_flds_array(L,2, pref->value.s);
            pref->info.uat_field_list_info.uat_field_list = flds_array;
            break;
        }
        default:
            ws_assert_not_reached();
            break;

    }

    pushPref(L,pref);
    return 1;
}

WSLUA_CONSTRUCTOR Pref_bool(lua_State* L) {
    /*
    Creates a boolean preference to be added to a <<lua_class_attrib_proto_prefs,`Proto.prefs`>> Lua table.

    ===== Example

    [source,lua]
    ----
    -- create a Boolean preference named "bar" for Foo Protocol
    -- (assuming Foo doesn't already have a preference named "bar")
    proto_foo.prefs.bar = Pref.bool( "Bar", true, "Baz and all the rest" )
    ----
    */
#define WSLUA_ARG_Pref_bool_LABEL 1 /* The Label (text in the right side of the
                                       preference input) for this preference. */
#define WSLUA_ARG_Pref_bool_DEFAULT 2 /* The default value for this preference. */
#define WSLUA_ARG_Pref_bool_DESCRIPTION 3 /* A description of this preference. */
    return new_pref(L,PREF_BOOL);
}

WSLUA_CONSTRUCTOR Pref_uint(lua_State* L) {
    /* Creates an (unsigned) integer preference to be added to a <<lua_class_attrib_proto_prefs,`Proto.prefs`>> Lua table. */
#define WSLUA_ARG_Pref_uint_LABEL 1 /* The Label (text in the right side of the
                                       preference input) for this preference. */
#define WSLUA_ARG_Pref_uint_DEFAULT 2 /* The default value for this preference. */
#define WSLUA_ARG_Pref_uint_DESCRIPTION 3 /* A description of what this preference is. */
    return new_pref(L,PREF_UINT);
}

WSLUA_CONSTRUCTOR Pref_string(lua_State* L) {
    /* Creates a string preference to be added to a <<lua_class_attrib_proto_prefs,`Proto.prefs`>> Lua table. */
#define WSLUA_ARG_Pref_string_LABEL 1 /* The Label (text in the right side of the
                                         preference input) for this preference. */
#define WSLUA_ARG_Pref_string_DEFAULT 2 /* The default value for this preference. */
#define WSLUA_ARG_Pref_string_DESCRIPTION 3 /* A description of what this preference is. */
    return new_pref(L,PREF_STRING);
}

WSLUA_CONSTRUCTOR Pref_enum(lua_State* L) {
    /*
    Creates an enum preference to be added to a <<lua_class_attrib_proto_prefs,`Proto.prefs`>> Lua table.

    ===== Example:

    [source,lua]
    ----
    local OUTPUT_OFF        = 0
    local OUTPUT_DEBUG      = 1
    local OUTPUT_INFO       = 2
    local OUTPUT_WARN       = 3
    local OUTPUT_ERROR      = 4

    local output_tab = {
            { 1, "Off"              , OUTPUT_OFF },
            { 2, "Debug"            , OUTPUT_DEBUG },
            { 3, "Information"      , OUTPUT_INFO },
            { 4, "Warning"          , OUTPUT_WARN },
            { 5, "Error"            , OUTPUT_ERROR },
    }

    -- Create enum preference that shows as Combo Box under
    -- Foo Protocol's preferences
    proto_foo.prefs.outputlevel = Pref.enum(
            "Output Level",                 -- label
            OUTPUT_INFO,                    -- default value
            "Verbosity of log output",      -- description
            output_tab,                     -- enum table
            false                           -- show as combo box
    )

    -- Then, we can query the value of the selected preference.
    -- This line prints "Output Level: 3" assuming the selected
    -- output level is _INFO.
    debug( "Output Level: " .. proto_foo.prefs.outputlevel )
    ----
    */
#define WSLUA_ARG_Pref_enum_LABEL 1 /* The Label (text in the right side of the
                                       preference input) for this preference. */
#define WSLUA_ARG_Pref_enum_DEFAULT 2 /* The default value for this preference. */
#define WSLUA_ARG_Pref_enum_DESCRIPTION 3 /* A description of what this preference is. */
#define WSLUA_ARG_Pref_enum_ENUM 4 /* An enum Lua table. */
#define WSLUA_ARG_Pref_enum_RADIO 5 /* Radio button (true) or Combobox (false). */
    return new_pref(L,PREF_ENUM);
}

WSLUA_CONSTRUCTOR Pref_range(lua_State* L) {
    /* Creates a range (numeric text entry) preference to be added to a <<lua_class_attrib_proto_prefs,`Proto.prefs`>> Lua table. */
#define WSLUA_ARG_Pref_range_LABEL 1 /* The Label (text in the right side of the preference
                                        input) for this preference. */
#define WSLUA_ARG_Pref_range_DEFAULT 2 /* The default value for this preference, e.g., "53",
                                          "10-30", or "10-30,53,55,100-120". */
#define WSLUA_ARG_Pref_range_DESCRIPTION 3 /* A description of what this preference is. */
#define WSLUA_ARG_Pref_range_MAX 4 /* The maximum value. */
    return new_pref(L,PREF_RANGE);
}

WSLUA_CONSTRUCTOR Pref_statictext(lua_State* L) {
    /* Creates a static text string to be added to a <<lua_class_attrib_proto_prefs,`Proto.prefs`>> Lua table. */
#define WSLUA_ARG_Pref_statictext_LABEL 1 /* The static text. */
#define WSLUA_ARG_Pref_statictext_DESCRIPTION 2 /* The static text description. */
    return new_pref(L,PREF_STATIC_TEXT);
}

WSLUA_CONSTRUCTOR Pref_uat(lua_State* L) {
    /*
    Creates an uat preference to be added to a <<lua_class_attrib_proto_prefs,`Proto.prefs`>> Lua table.

    ===== Example:

    [source,lua]
    ----
    local fieldlist = {
        {"field 1", "Description 1"},
        {"field 2", "Description 2"},
    }

    -- Create a uat preference that appears as a button on the Foo Protocol preference page.
    -- The user accessible table can be edited with this button.
    proto_foo.prefs.preference_uat_name = Pref.uat("Label", fieldlist, "Description", "uat_filename")

    -- Value checker:

    -- Create a file in Personal Lua plugins directory named as preferences_uat_callbacks.lua
    -- Create a checker function named as uat_update_cb:
    -- The uat editor will call this function for checks the values.
    function uat_update_cb(records, uat_filename)
        print("UAT filename: " .. uat_filename)
        print("UAT record 0 = " .. records[0])
        print("UAT record 1 = " .. records[1])
        local result = true
        local errstring = ""
        -- do not allow 5 in the "field 1
        if (tonumber(records[0]) == 5) then
            result = false
            errstring = "Firsct collumn cannot be 5!"
        end
        print("Check result = " .. tostring(result))
        -- return check result as boolean and errstring if needed
        return result, errstring
    end
    ----
    */
#define WSLUA_ARG_Pref_uat_FIELD_CONFIG 2 /* Fields names and description table. */
#define WSLUA_ARG_Pref_uat_DESCRIPTION 3 /* A description of what this preference is. */
#define WSLUA_ARG_Pref_uat_FILE_NAME 4 /* The name of the uat file. */
    return new_pref(L,PREF_UAT);
}

static range_t* get_range(lua_State *L, int idx_r, int idx_m)
{
    static range_t *ret = NULL;
    const char *pattern = luaL_checkstring(L, idx_r);

    switch (range_convert_str(wmem_epan_scope(), &ret, pattern, wslua_toint32(L, idx_m))) {
        case CVT_NO_ERROR:
          break;
        case CVT_SYNTAX_ERROR:
          WSLUA_ARG_ERROR(Pref_range,DEFAULT,"syntax error in default range");
          return 0;
        case CVT_NUMBER_TOO_BIG:
          WSLUA_ARG_ERROR(Pref_range,DEFAULT,"value too large in default range");
          return 0;
        default:
          WSLUA_ARG_ERROR(Pref_range,DEFAULT,"unknown error in default range");
          return 0;
    }

    return ret;
}

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int Pref__gc(lua_State* L) {
    Pref pref = toPref(L,1);

    if (pref->ref != LUA_NOREF) {
        // Did the user try to call __gc explicitly while it was registered to a
        // protocol? Forbid that!
        luaL_error(L, "Direct call to __gc is forbidden");
        return 0;
    }

    g_free(pref->name);
    g_free(pref->label);
    g_free(pref->desc);
    switch (pref->type) {
        case PREF_STRING:
            /*
             * Free the initial string value; if it's not NULL, that
             * means this is a never-registered preference, so the
             * initial value hasn't been freed.
             */
            g_free(pref->info.default_s);
            break;
        case PREF_ENUM: {
            /*
             * Free the enum values allocated in get_enum().
             */
            const enum_val_t *enum_valp = pref->info.enum_info.enumvals;
            while (enum_valp->name) {
                g_free((char *)enum_valp->name);
                g_free((char *)enum_valp->description);
                enum_valp++;
            }
            g_free((enum_val_t *)pref->info.enum_info.enumvals);
            break;
        }
        case PREF_UAT: {
            /*
            * Free the uat values allocated in get_uat_flds_array().
            */
            const uat_field_t *field_valp = pref->info.uat_field_list_info.uat_field_list;
            while (field_valp->name) {
                g_free((char *)field_valp->title);
                g_free((char *)field_valp->desc);
                g_free((uint8_t *)field_valp->cbdata.chk);
                g_free((uint8_t *)field_valp->cbdata.set);
                g_free((uint8_t *)field_valp->cbdata.tostr);
                g_free((char *)field_valp->fld_data);
                field_valp++;
            }
            g_free((uat_field_t *)pref->info.uat_field_list_info.uat_field_list);
            g_free(pref->value.s);
            break;
        }
        default:
            break;
    }
    g_free(pref);

    return 0;
}

WSLUA_METHODS Pref_methods[] = {
    WSLUA_CLASS_FNREG(Pref,bool),
    WSLUA_CLASS_FNREG(Pref,uint),
    WSLUA_CLASS_FNREG(Pref,string),
    WSLUA_CLASS_FNREG(Pref,enum),
    WSLUA_CLASS_FNREG(Pref,range),
    WSLUA_CLASS_FNREG(Pref,statictext),
    WSLUA_CLASS_FNREG(Pref,uat),
    { NULL, NULL }
};

WSLUA_META Pref_meta[] = {
    { NULL, NULL }
};


WSLUA_REGISTER Pref_register(lua_State* L) {
    WSLUA_REGISTER_CLASS(Pref);
    return 0;
}

WSLUA_CLASS_DEFINE(Prefs,NOP); /* The table of preferences of a protocol. */

WSLUA_METAMETHOD Prefs__newindex(lua_State* L) {
    /* Creates a new preference. */
#define WSLUA_ARG_Prefs__newindex_NAME 2 /* The abbreviation of this preference. */
#define WSLUA_ARG_Prefs__newindex_PREF 3 /* A valid but still unassigned Pref object. */

    Pref prefs_p = checkPrefs(L,1);
    const char* name = luaL_checkstring(L,WSLUA_ARG_Prefs__newindex_NAME);
    Pref pref = checkPref(L,WSLUA_ARG_Prefs__newindex_PREF);
    Pref p;
    const char *c;

    if (! prefs_p ) return 0;

    if (! pref ) {
        WSLUA_ARG_ERROR(Prefs__newindex,PREF,"must be a valid Pref");
        return 0;
    }

    if (pref->name) {
        WSLUA_ARG_ERROR(Prefs__newindex,NAME,"cannot change existing preference");
        return 0;
    }

    if (pref->proto) {
        WSLUA_ARG_ERROR(Prefs__newindex,PREF,"cannot be added to more than one protocol");
        return 0;
    }

    p = prefs_p;

    do {
        if ( p->name && g_str_equal(p->name,name) ) {
            luaL_error(L,"a preference named %s exists already",name);
            return 0;
        }
        /*
         * Make sure that only lower-case ASCII letters, numbers,
         * underscores, and dots appear in the preference name.
         */
        for (c = name; *c != '\0'; c++) {
            if (!g_ascii_islower(*c) && !g_ascii_isdigit(*c) && *c != '_' && *c != '.')
            {
                luaL_error(L,"illegal preference name \"%s\", only lower-case ASCII letters, "
                             "numbers, underscores and dots may be used", name);
                return 0;
            }
        }

        if ( ! p->next) {
            // Keep a reference to the Pref to ensure it remains valid
            // until the protocol is deregistered.
            lua_pushvalue(L, WSLUA_ARG_Prefs__newindex_PREF);
            pref->ref = luaL_ref(L, LUA_REGISTRYINDEX);

            p->next = pref;
            pref->name = g_strdup(name);

            if (!pref->label)
                pref->label = g_strdup(name);

            if (!prefs_p->proto->prefs_module) {
                prefs_p->proto->prefs_module = prefs_register_protocol(prefs_p->proto->hfid,
                                                                       wslua_prefs_changed);
            }

            switch(pref->type) {
                case PREF_BOOL:
                    prefs_register_bool_preference(prefs_p->proto->prefs_module,
                                                   pref->name,
                                                   pref->label,
                                                   pref->desc,
                                                   &(pref->value.b));
                    break;
                case PREF_UINT:
                    prefs_register_uint_preference(prefs_p->proto->prefs_module,
                                                   pref->name,
                                                   pref->label,
                                                   pref->desc,
                                                   10,
                                                   &(pref->value.u));
                    break;
                case PREF_STRING:
                    prefs_register_string_preference(prefs_p->proto->prefs_module,
                                                     pref->name,
                                                     pref->label,
                                                     pref->desc,
                                                     (const char **)(&(pref->value.s)));
                    /*
                     * We're finished with the initial string value; see
                     * the comment in new_pref().
                     */
                    g_free(pref->info.default_s);
                    pref->info.default_s = NULL;
                    break;
                case PREF_ENUM:
                    prefs_register_enum_preference(prefs_p->proto->prefs_module,
                                                     pref->name,
                                                     pref->label,
                                                     pref->desc,
                                                     &(pref->value.e),
                                                     pref->info.enum_info.enumvals,
                                                     pref->info.enum_info.radio_buttons);
                    break;
                case PREF_RANGE:
                    prefs_register_range_preference(prefs_p->proto->prefs_module,
                                                     pref->name,
                                                     pref->label,
                                                     pref->desc,
                                                     &(pref->value.r),
                                                     pref->info.max_value);
                    break;
                case PREF_STATIC_TEXT:
                    prefs_register_static_text_preference(prefs_p->proto->prefs_module,
                                                     pref->name,
                                                     pref->label,
                                                     pref->desc);
                    break;
                case PREF_UAT:
                    /* Create a UAT for preferences */
                    {
                        uat = uat_new(pref->label,
                            sizeof(uat_container_t),                            /* record size */
                            pref->value.s,                                      /* filename */
                            true,                                               /* from_profile */
                            &perf_uat_data,                                     /* data_ptr */
                            &num_perf_uat_data,                                 /* numitems_ptr */
                            UAT_AFFECTS_DISSECTION,                             /* affects dissection of packets, but not set of named fields */
                            NULL,                                               /* help */
                            NULL,                                               /* copy callback */
                            uat_update_cb,                                      /* update callback */
                            NULL,                                               /* free callback */
                            NULL,                                               /* post update callback */
                            NULL,                                               /* reset callback */
                            pref->info.uat_field_list_info.uat_field_list);     /* UAT field definitions */
                        prefs_register_uat_preference(prefs_p->proto->prefs_module, pref->value.s,
                            pref->label,
                            pref->desc,
                            uat);
                    }
                    break;
                default:
                    WSLUA_ERROR(Prefs__newindex,"Unknown Pref type");
                    break;
            }

            pref->proto = p->proto;

            WSLUA_RETURN(0);
        }
    } while (( p = p->next ));

    luaL_error(L,"this should not happen!");

    WSLUA_RETURN(0);
}

WSLUA_METAMETHOD Prefs__index(lua_State* L) {
    /*
    Get the value of a preference setting.

    ===== Example

    [source,lua]
    ----
    -- print the value of Foo's preference named "bar"
    debug( "bar = " .. proto_foo.prefs.bar )
    ----
    */
#define WSLUA_ARG_Prefs__index_NAME 2 /* The abbreviation of this preference. */

    Pref prefs_p = checkPrefs(L,1);
    const char* name = luaL_checkstring(L,WSLUA_ARG_Prefs__index_NAME);

    if (! prefs_p ) return 0;

    if (!prefs_p->next) {
        luaL_error(L,"No preference is registered yet");
        return 0;
    }

    prefs_p = prefs_p->next;

    do {
        if ( g_str_equal(prefs_p->name,name) ) {
            switch (prefs_p->type) {
                case PREF_BOOL: lua_pushboolean(L, prefs_p->value.b); break;
                case PREF_UINT: lua_pushinteger(L,(lua_Integer)prefs_p->value.u); break;
                case PREF_STRING: lua_pushstring(L,prefs_p->value.s); break;
                case PREF_ENUM: lua_pushinteger(L,(lua_Integer)prefs_p->value.e); break;
                case PREF_RANGE:
                    {
                    char *push_str = range_convert_range(NULL, prefs_p->value.r);
                    lua_pushstring(L, push_str);
                    wmem_free(NULL, push_str);
                    }
                    break;
                default: WSLUA_ERROR(Prefs__index,"Unknown Pref type"); return 0;
            }
            WSLUA_RETURN(1); /* The current value of the preference. */
        }
    } while (( prefs_p = prefs_p->next ));

    WSLUA_ARG_ERROR(Prefs__index,NAME,"no preference named like this");
    return 0;
}

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int Prefs__gc(lua_State* L _U_) {
    /* do NOT free Prefs, it's a static part of Proto */
    return 0;
}

WSLUA_META Prefs_meta[] = {
    WSLUA_CLASS_MTREG(Prefs,newindex),
    WSLUA_CLASS_MTREG(Prefs,index),
    { NULL, NULL }
};

WSLUA_REGISTER Prefs_register(lua_State* L) {
    WSLUA_REGISTER_META(Prefs);
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
