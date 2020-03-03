/*
 * init_wslua.c
 *
 * Wireshark's interface to the Lua Programming Language
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "wslua.h"
#include "init_wslua.h"
#include <epan/dissectors/packet-frame.h>
#include <math.h>
#include <epan/expert.h>
#include <epan/ex-opt.h>
#include <wsutil/privileges.h>
#include <wsutil/file_util.h>
#include <wsutil/ws_printf.h> /* ws_debug_printf */

/* linked list of Lua plugins */
typedef struct _wslua_plugin {
    gchar       *name;            /**< plugin name */
    gchar       *version;         /**< plugin version */
    gchar       *filename;        /**< plugin filename */
    struct _wslua_plugin *next;
} wslua_plugin;

static wslua_plugin *wslua_plugin_list = NULL;

static lua_State* L = NULL;

/* XXX: global variables? Really?? Yuck. These could be done differently,
   using the Lua registry */
packet_info* lua_pinfo;
struct _wslua_treeitem* lua_tree;
tvbuff_t* lua_tvb;
wslua_logger_t wslua_logger;
int lua_dissectors_table_ref = LUA_NOREF;
int lua_heur_dissectors_table_ref = LUA_NOREF;

static int proto_lua = -1;

static int hf_wslua_fake = -1;
static int hf_wslua_text = -1;

static expert_field ei_lua_error = EI_INIT;

static expert_field ei_lua_proto_checksum_comment = EI_INIT;
static expert_field ei_lua_proto_checksum_chat    = EI_INIT;
static expert_field ei_lua_proto_checksum_note    = EI_INIT;
static expert_field ei_lua_proto_checksum_warn    = EI_INIT;
static expert_field ei_lua_proto_checksum_error   = EI_INIT;

static expert_field ei_lua_proto_sequence_comment = EI_INIT;
static expert_field ei_lua_proto_sequence_chat    = EI_INIT;
static expert_field ei_lua_proto_sequence_note    = EI_INIT;
static expert_field ei_lua_proto_sequence_warn    = EI_INIT;
static expert_field ei_lua_proto_sequence_error   = EI_INIT;

static expert_field ei_lua_proto_response_comment = EI_INIT;
static expert_field ei_lua_proto_response_chat    = EI_INIT;
static expert_field ei_lua_proto_response_note    = EI_INIT;
static expert_field ei_lua_proto_response_warn    = EI_INIT;
static expert_field ei_lua_proto_response_error   = EI_INIT;

static expert_field ei_lua_proto_request_comment = EI_INIT;
static expert_field ei_lua_proto_request_chat    = EI_INIT;
static expert_field ei_lua_proto_request_note    = EI_INIT;
static expert_field ei_lua_proto_request_warn    = EI_INIT;
static expert_field ei_lua_proto_request_error   = EI_INIT;

static expert_field ei_lua_proto_undecoded_comment = EI_INIT;
static expert_field ei_lua_proto_undecoded_chat    = EI_INIT;
static expert_field ei_lua_proto_undecoded_note    = EI_INIT;
static expert_field ei_lua_proto_undecoded_warn    = EI_INIT;
static expert_field ei_lua_proto_undecoded_error   = EI_INIT;

static expert_field ei_lua_proto_reassemble_comment = EI_INIT;
static expert_field ei_lua_proto_reassemble_chat    = EI_INIT;
static expert_field ei_lua_proto_reassemble_note    = EI_INIT;
static expert_field ei_lua_proto_reassemble_warn    = EI_INIT;
static expert_field ei_lua_proto_reassemble_error   = EI_INIT;

static expert_field ei_lua_proto_malformed_comment = EI_INIT;
static expert_field ei_lua_proto_malformed_chat    = EI_INIT;
static expert_field ei_lua_proto_malformed_note    = EI_INIT;
static expert_field ei_lua_proto_malformed_warn    = EI_INIT;
static expert_field ei_lua_proto_malformed_error   = EI_INIT;

static expert_field ei_lua_proto_debug_comment = EI_INIT;
static expert_field ei_lua_proto_debug_chat    = EI_INIT;
static expert_field ei_lua_proto_debug_note    = EI_INIT;
static expert_field ei_lua_proto_debug_warn    = EI_INIT;
static expert_field ei_lua_proto_debug_error   = EI_INIT;

static expert_field ei_lua_proto_protocol_comment = EI_INIT;
static expert_field ei_lua_proto_protocol_chat    = EI_INIT;
static expert_field ei_lua_proto_protocol_note    = EI_INIT;
static expert_field ei_lua_proto_protocol_warn    = EI_INIT;
static expert_field ei_lua_proto_protocol_error   = EI_INIT;

static expert_field ei_lua_proto_security_comment = EI_INIT;
static expert_field ei_lua_proto_security_chat    = EI_INIT;
static expert_field ei_lua_proto_security_note    = EI_INIT;
static expert_field ei_lua_proto_security_warn    = EI_INIT;
static expert_field ei_lua_proto_security_error   = EI_INIT;

static expert_field ei_lua_proto_comments_comment = EI_INIT;
static expert_field ei_lua_proto_comments_chat    = EI_INIT;
static expert_field ei_lua_proto_comments_note    = EI_INIT;
static expert_field ei_lua_proto_comments_warn    = EI_INIT;
static expert_field ei_lua_proto_comments_error   = EI_INIT;

static expert_field ei_lua_proto_deprecated_comment = EI_INIT;
static expert_field ei_lua_proto_deprecated_chat    = EI_INIT;
static expert_field ei_lua_proto_deprecated_note    = EI_INIT;
static expert_field ei_lua_proto_deprecated_warn    = EI_INIT;
static expert_field ei_lua_proto_deprecated_error   = EI_INIT;

static gboolean
lua_pinfo_end(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_,
        void *user_data _U_)
{
    clear_outstanding_Tvb();
    clear_outstanding_TvbRange();
    clear_outstanding_Pinfo();
    clear_outstanding_Column();
    clear_outstanding_Columns();
    clear_outstanding_PrivateTable();
    clear_outstanding_TreeItem();
    clear_outstanding_FieldInfo();
    clear_outstanding_FuncSavers();

    /* keep invoking this callback later? */
    return FALSE;
}

static int wslua_not_register_menu(lua_State* LS) {
    luaL_error(LS,"too late to register a menu");
    return 0;
}

/* a getter for wslua_tree.c's TreeItem_add_item_any() to use */
int get_hf_wslua_text(void) {
    return hf_wslua_text;
}

int dissect_lua(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_) {
    int consumed_bytes = tvb_captured_length(tvb);
    tvbuff_t *saved_lua_tvb = lua_tvb;
    packet_info *saved_lua_pinfo = lua_pinfo;
    struct _wslua_treeitem *saved_lua_tree = lua_tree;
    lua_pinfo = pinfo;
    lua_tvb = tvb;

    /*
     * almost equivalent to Lua:
     * dissectors[current_proto](tvb,pinfo,tree)
     */

    lua_settop(L,0);

    lua_rawgeti(L, LUA_REGISTRYINDEX, lua_dissectors_table_ref);

    lua_pushstring(L, pinfo->current_proto);
    lua_gettable(L, -2);

    lua_remove(L,1);


    if (lua_isfunction(L,1)) {

        push_Tvb(L,tvb);
        push_Pinfo(L,pinfo);
        lua_tree = push_TreeItem(L, tree, proto_tree_add_item(tree, hf_wslua_fake, tvb, 0, 0, ENC_NA));
        proto_item_set_hidden(lua_tree->item);

        if  ( lua_pcall(L,3,1,0) ) {
            proto_tree_add_expert_format(tree, pinfo, &ei_lua_error, tvb, 0, 0, "Lua Error: %s", lua_tostring(L,-1));
        } else {

            /* if the Lua dissector reported the consumed bytes, pass it to our caller */
            if (lua_isnumber(L, -1)) {
                /* we got the consumed bytes or the missing bytes as a negative number */
                consumed_bytes = wslua_togint(L, -1);
                lua_pop(L, 1);
            }
        }

    } else {
        proto_tree_add_expert_format(tree, pinfo, &ei_lua_error, tvb, 0, 0,
                    "Lua Error: did not find the %s dissector in the dissectors table", pinfo->current_proto);
    }

    wmem_register_callback(pinfo->pool, lua_pinfo_end, NULL);

    lua_pinfo = saved_lua_pinfo;
    lua_tree = saved_lua_tree;
    lua_tvb = saved_lua_tvb;

    return consumed_bytes;

}

/** Type of a heuristic dissector, used in heur_dissector_add().
 *
 * @param tvb the tvbuff with the (remaining) packet data
 * @param pinfo the packet info of this packet (additional info)
 * @param tree the protocol tree to be build or NULL
 * @return TRUE if the packet was recognized by the sub-dissector (stop dissection here)
 */
gboolean heur_dissect_lua(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_) {
    gboolean result = FALSE;
    tvbuff_t *saved_lua_tvb = lua_tvb;
    packet_info *saved_lua_pinfo = lua_pinfo;
    struct _wslua_treeitem *saved_lua_tree = lua_tree;
    lua_tvb = tvb;
    lua_pinfo = pinfo;

    g_assert(tvb && pinfo);

    if (!pinfo->heur_list_name || !pinfo->current_proto) {
        proto_tree_add_expert_format(tree, pinfo, &ei_lua_error, tvb, 0, 0,
                "internal error in heur_dissect_lua: NULL list name or current proto");
        return FALSE;
    }

    /* heuristic functions are stored in a table in the registry; the registry has a
     * table at reference lua_heur_dissectors_table_ref, and that table has keys for
     * the heuristic listname (e.g., "udp", "tcp", etc.), and that key's value is a
     * table of keys of the Proto->name, and their value is the function.
     * So it's like registry[table_ref][heur_list_name][proto_name] = func
     */

    lua_settop(L,0);

    /* get the table of all lua heuristic dissector lists */
    lua_rawgeti(L, LUA_REGISTRYINDEX, lua_heur_dissectors_table_ref);

    /* get the table inside that, for the lua heuristic dissectors of the requested heur list */
    if (!wslua_get_table(L, -1, pinfo->heur_list_name)) {
        /* this shouldn't happen */
        lua_settop(L,0);
        proto_tree_add_expert_format(tree, pinfo, &ei_lua_error, tvb, 0, 0,
                "internal error in heur_dissect_lua: no %s heur list table", pinfo->heur_list_name);
        return FALSE;
    }

    /* get the table inside that, for the specific lua heuristic dissector */
    if (!wslua_get_field(L,-1,pinfo->current_proto)) {
        /* this shouldn't happen */
        lua_settop(L,0);
        proto_tree_add_expert_format(tree, pinfo, &ei_lua_error, tvb, 0, 0,
                "internal error in heur_dissect_lua: no %s heuristic dissector for list %s",
                        pinfo->current_proto, pinfo->heur_list_name);
        return FALSE;
    }

    /* remove the table of all lists (the one in the registry) */
    lua_remove(L,1);
    /* remove the heur_list_name heur list table */
    lua_remove(L,1);

    if (!lua_isfunction(L,-1)) {
        /* this shouldn't happen */
        lua_settop(L,0);
        proto_tree_add_expert_format(tree, pinfo, &ei_lua_error, tvb, 0, 0,
                "internal error in heur_dissect_lua: %s heuristic dissector is not a function", pinfo->current_proto);
        return FALSE;
    }

    push_Tvb(L,tvb);
    push_Pinfo(L,pinfo);
    lua_tree = push_TreeItem(L, tree, proto_tree_add_item(tree, hf_wslua_fake, tvb, 0, 0, ENC_NA));
    proto_item_set_hidden(lua_tree->item);

    if  ( lua_pcall(L,3,1,0) ) {
        proto_tree_add_expert_format(tree, pinfo, &ei_lua_error, tvb, 0, 0,
                "Lua Error: error calling %s heuristic dissector: %s", pinfo->current_proto, lua_tostring(L,-1));
        lua_settop(L,0);
    } else {
        if (lua_isboolean(L, -1) || lua_isnil(L, -1)) {
            result = lua_toboolean(L, -1);
        } else if (lua_type(L, -1) == LUA_TNUMBER) {
            result = lua_tointeger(L,-1) != 0 ? TRUE : FALSE;
        } else {
            proto_tree_add_expert_format(tree, pinfo, &ei_lua_error, tvb, 0, 0,
                    "Lua Error: invalid return value from Lua %s heuristic dissector", pinfo->current_proto);
        }
        lua_pop(L, 1);
    }

    wmem_register_callback(pinfo->pool, lua_pinfo_end, NULL);

    lua_pinfo = saved_lua_pinfo;
    lua_tree = saved_lua_tree;
    lua_tvb = saved_lua_tvb;

    return result;
}

static void iter_table_and_call(lua_State* LS, const gchar* table_name, lua_CFunction error_handler) {
    lua_settop(LS,0);

    lua_pushcfunction(LS,error_handler);
    lua_getglobal(LS, table_name);

    if (!lua_istable(LS, 2)) {
        report_failure("Lua: either `%s' does not exist or it is not a table!\n",table_name);
        lua_close(LS);
        L = NULL;
        return;
    }

    lua_pushnil(LS);

    while (lua_next(LS, 2)) {
        const gchar* name = lua_tostring(L,-2);

        if (lua_isfunction(LS,-1)) {

            if ( lua_pcall(LS,0,0,1) ) {
                    lua_pop(LS,1);
            }

        } else {
            report_failure("Lua: Something not a function got its way into the %s.%s",table_name,name);
            lua_close(LS);
            L = NULL;
            return;
        }
    }

    lua_settop(LS,0);
}


static int init_error_handler(lua_State* LS) {
    const gchar* error =  lua_tostring(LS,1);
    report_failure("Lua: Error During execution of Initialization:\n %s",error);
    return 0;
}


static gboolean init_routine_initialized = FALSE;
static void wslua_init_routine(void) {

    if ( ! init_routine_initialized ) {
        /*
         * This must be done only once during the entire life of
         * tshark/wireshark, because it must be done only once per the life of
         * the Lua state/engine, so we guard this with the boolean above;
         * otherwise it would occur every time a file is opened (every time
         * epan_new() is called).
         *
         * If we ever allow the Lua state to be restarted, or to have multiple
         * Lua states, we'll need to change this.
         */
        lua_prime_all_fields(NULL);
        init_routine_initialized = TRUE;
    }

    if (L) {
        iter_table_and_call(L, WSLUA_INIT_ROUTINES,init_error_handler);
    }

}

static void wslua_cleanup_routine(void) {
    if (L) {
        iter_table_and_call(L, WSLUA_INIT_ROUTINES,init_error_handler);
    }
}

static int prefs_changed_error_handler(lua_State* LS) {
    const gchar* error =  lua_tostring(LS,1);
    report_failure("Lua: Error During execution of prefs apply callback:\n %s",error);
    return 0;
}

void wslua_prefs_changed(void) {
    if (L) {
        iter_table_and_call(L, WSLUA_PREFS_CHANGED,prefs_changed_error_handler);
    }
}

static const char *getF(lua_State *LS _U_, void *ud, size_t *size)
{
    FILE *f=(FILE *)ud;
    static char buff[512];
    if (feof(f)) return NULL;
    *size=fread(buff,1,sizeof(buff),f);
    return (*size>0) ? buff : NULL;
}

static int error_handler_with_callback(lua_State *LS) {
#if LUA_VERSION_NUM >= 502
    const char *msg = lua_tostring(LS, 1);
    luaL_traceback(LS, LS, msg, 1);     /* push message with traceback.  */
    lua_remove(LS, -2);                 /* remove original msg */
#else
    /* Return error message, unmodified */
    (void)LS;
#endif
    return 1;
}

static void wslua_add_plugin(const gchar *name, const gchar *version, const gchar *filename)
{
    wslua_plugin *new_plug, *lua_plug;

    lua_plug = wslua_plugin_list;
    new_plug = (wslua_plugin *)g_malloc(sizeof(wslua_plugin));

    if (!lua_plug) { /* the list is empty */
        wslua_plugin_list = new_plug;
    } else {
        while (lua_plug->next != NULL) {
            lua_plug = lua_plug->next;
        }
        lua_plug->next = new_plug;
    }

    new_plug->name = g_strdup(name);
    new_plug->version = g_strdup(version);
    new_plug->filename = g_strdup(filename);
    new_plug->next = NULL;
}

static void wslua_clear_plugin_list(void)
{
    wslua_plugin *lua_plug;

    while (wslua_plugin_list) {
        lua_plug = wslua_plugin_list;
        wslua_plugin_list = wslua_plugin_list->next;
        g_free (lua_plug->name);
        g_free (lua_plug->version);
        g_free (lua_plug->filename);
        g_free (lua_plug);
    }
}

static int lua_script_push_args(const int script_num) {
    gchar* argname = g_strdup_printf("lua_script%d", script_num);
    const gchar* argvalue = NULL;
    int i, count = ex_opt_count(argname);

    for (i = 0; i < count; i++) {
        argvalue = ex_opt_get_nth(argname, i);
        lua_pushstring(L,argvalue);
    }

    g_free(argname);
    return count;
}

#define FILE_NAME_KEY "__FILE__"
#define DIR_NAME_KEY "__DIR__"
#define DIR_SEP_NAME_KEY "__DIR_SEPARATOR__"
/* assumes a loaded chunk's function is on top of stack */
static void set_file_environment(const gchar* filename, const gchar* dirname) {
    const char* path;

    lua_newtable(L); /* environment for script (index 3) */

    lua_pushstring(L, filename); /* tell the script about its filename */
    lua_setfield(L, -2, FILE_NAME_KEY); /* make it accessible at __FILE__ */

    lua_pushstring(L, dirname); /* tell the script about its dirname */
    lua_setfield(L, -2, DIR_NAME_KEY); /* make it accessible at __DIR__ */

    lua_pushstring(L, G_DIR_SEPARATOR_S); /* tell the script the directory separator */
    lua_setfield(L, -2, DIR_SEP_NAME_KEY); /* make it accessible at __DIR__ */

    lua_newtable(L); /* new metatable */

#if LUA_VERSION_NUM >= 502
    lua_pushglobaltable(L);
#else
    lua_pushvalue(L, LUA_GLOBALSINDEX);
#endif
    /* prepend the directory name to _G.package.path */
    lua_getfield(L, -1, "package"); /* get the package table from the global table */
    lua_getfield(L, -1, "path");    /* get the path field from the package table */
    path = luaL_checkstring(L, -1); /* get the path string */
    lua_pop(L, 1);                  /* pop the path string */
    /* prepend the various paths */
    lua_pushfstring(L, "%s" G_DIR_SEPARATOR_S "?.lua;%s" G_DIR_SEPARATOR_S "?.lua;%s" G_DIR_SEPARATOR_S "?.lua;%s",
                    dirname, get_plugins_pers_dir(), get_plugins_dir(), path);
    lua_setfield(L, -2, "path");    /* set the new string to be the path field of the package table */
    lua_setfield(L, -2, "package"); /* set the package table to be the package field of the global */

    lua_setfield(L, -2, "__index"); /* make metatable's __index point to global table */

    lua_setmetatable(L, -2); /* pop metatable, set it as metatable of environment */

#if LUA_VERSION_NUM >= 502
    lua_setupvalue(L, -2, 1); /* pop environment and assign it to upvalue 1 */
#else
    lua_setfenv(L, -2); /* pop environment and set it as the func's environment */
#endif
}


/* If file_count > 0 then it's a command-line-added user script, and the count
 * represents which user script it is (first=1, second=2, etc.).
 * If dirname != NULL, then it's a user script and the dirname will get put in a file environment
 * If dirname == NULL then it's a wireshark script and no file environment is created
 */
static gboolean lua_load_script(const gchar* filename, const gchar* dirname, const int file_count) {
    FILE* file;
    int error;
    int numargs = 0;

    if (! ( file = ws_fopen(filename,"r")) ) {
        report_open_failure(filename,errno,FALSE);
        return FALSE;
    }

    lua_settop(L,0);

    lua_pushcfunction(L, error_handler_with_callback);
    /* The source argument should start with '@' to indicate a file. */
    lua_pushfstring(L, "@%s", filename);

#if LUA_VERSION_NUM >= 502
    error = lua_load(L, getF, file, lua_tostring(L, -1), NULL);
#else
    error = lua_load(L, getF, file, lua_tostring(L, -1));
#endif

    switch (error) {
        case 0: /* LUA_OK */
            if (dirname) {
                set_file_environment(filename, dirname);
            }
            if (file_count > 0) {
                numargs = lua_script_push_args(file_count);
            }
            error = lua_pcall(L, numargs, 0, 1);
            if (error) {
                switch (error) {
                    case LUA_ERRRUN:
                        report_failure("Lua: Error during loading:\n%s", lua_tostring(L, -1));
                        break;
                    case LUA_ERRMEM:
                        report_failure("Lua: Error during loading: out of memory");
                        break;
                    case LUA_ERRERR:
                        report_failure("Lua: Error during loading: error while retrieving error message");
                        break;
                    default:
                        report_failure("Lua: Error during loading: unknown error %d", error);
                        break;
                }
            }
            break;

        case LUA_ERRSYNTAX:
            report_failure("Lua: syntax error: %s", lua_tostring(L, -1));
            break;

        case LUA_ERRMEM:
            report_failure("Lua: memory allocation error during precompilation of %s", filename);
            break;

        default:
            report_failure("Lua: unknown error during precompilation of %s: %d", filename, error);
            break;
    }
    fclose(file);
    lua_pop(L, 2);  /* pop the filename and error handler */
    return error == 0;
}

/* This one is used to load the init.lua scripts, or anything else
 * that shouldn't really be considered a real plugin.
 */
static gboolean lua_load_internal_script(const gchar* filename) {
    return lua_load_script(filename, NULL, 0);
}

/* This one is used to load plugins: either from the plugin directories,
 *   or from the command line.
 */
static gboolean lua_load_plugin_script(const gchar* name,
                                       const gchar* filename,
                                       const gchar* dirname,
                                       const int file_count)
{
    if (lua_load_script(filename, dirname, file_count)) {
        wslua_add_plugin(name, get_current_plugin_version(), filename);
        clear_current_plugin_version();
        return TRUE;
    }
    return FALSE;
}


static void basic_logger(const gchar *log_domain _U_,
                          GLogLevelFlags log_level _U_,
                          const gchar *message,
                          gpointer user_data _U_) {
    fputs(message,stderr);
}

static int wslua_panic(lua_State* LS) {
    g_error("LUA PANIC: %s",lua_tostring(LS,-1));
    /** g_error() does an abort() and thus never returns **/
    return 0; /* keep gcc happy */
}

static int lua_load_plugins(const char *dirname, register_cb cb, gpointer client_data,
                            gboolean count_only, const gboolean is_user, GHashTable *loaded_files)
{
    WS_DIR        *dir;             /* scanned directory */
    WS_DIRENT     *file;            /* current file */
    gchar         *filename, *dot;
    const gchar   *name;
    int            plugins_counter = 0;

    if ((dir = ws_dir_open(dirname, 0, NULL)) != NULL) {
        while ((file = ws_dir_read_name(dir)) != NULL) {
            name = ws_dir_get_name(file);

            if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
                continue;        /* skip "." and ".." */

            filename = g_strdup_printf("%s" G_DIR_SEPARATOR_S "%s", dirname, name);
            if (test_for_directory(filename) == EISDIR) {
                plugins_counter += lua_load_plugins(filename, cb, client_data, count_only, is_user, loaded_files);
                g_free(filename);
                continue;
            }

            /* skip files starting wih . */
            if (name[0] == '.') {
                g_free(filename);
                continue;
            }

            /* skip anything but files with .lua suffix */
            dot = strrchr(name, '.');
            if (dot == NULL || g_ascii_strcasecmp(dot+1, "lua") != 0) {
                g_free(filename);
                continue;
            }

            /* Check if we have already loaded this file name, if provided with a set */
            if (loaded_files && g_hash_table_lookup_extended(loaded_files, name, NULL, NULL)) {
                g_free(filename);
                continue;
            }

            if (file_exists(filename)) {
                if (!count_only) {
                    if (cb)
                        (*cb)(RA_LUA_PLUGINS, name, client_data);
                    lua_load_plugin_script(name, filename, is_user ? dirname : NULL, 0);
                }
                if (loaded_files) {
                    g_hash_table_insert(loaded_files, g_strdup(name), NULL);
                }
                plugins_counter++;
            }
            g_free(filename);
        }
        ws_dir_close(dir);
    }

    return plugins_counter;
}

static int lua_load_global_plugins(register_cb cb, gpointer client_data,
                                    gboolean count_only)
{
    return lua_load_plugins(get_plugins_dir(), cb, client_data, count_only, FALSE, NULL);
}

static int lua_load_pers_plugins(register_cb cb, gpointer client_data,
                                    gboolean count_only)
{
    int plugins_counter = 0;

    /* aux table (set) to make sure we only load each file once (by name) */
    GHashTable *loaded_user_scripts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

    /* load user scripts */
    plugins_counter += lua_load_plugins(get_plugins_pers_dir(), cb, client_data, count_only, TRUE, loaded_user_scripts);

    /* for backward compatibility check old plugin directory */
    char *old_path = get_persconffile_path("plugins", FALSE);
    if (strcmp(get_plugins_pers_dir(), old_path) != 0) {
        plugins_counter += lua_load_plugins(old_path, cb, client_data, count_only, TRUE, loaded_user_scripts);
    }
    g_free(old_path);

    g_hash_table_destroy(loaded_user_scripts);

    return plugins_counter;
}

int wslua_count_plugins(void) {
    gchar* filename;
    int plugins_counter;

    /* count global scripts */
    plugins_counter = lua_load_global_plugins(NULL, NULL, TRUE);

    /* count users init.lua */
    filename = get_persconffile_path("init.lua", FALSE);
    if ((file_exists(filename))) {
        plugins_counter++;
    }
    g_free(filename);

    /* count user scripts */
    plugins_counter += lua_load_pers_plugins(NULL, NULL, TRUE);

    /* count scripts from command line */
    plugins_counter += ex_opt_count("lua_script");

    return plugins_counter;
}

void wslua_plugins_get_descriptions(wslua_plugin_description_callback callback, void *user_data) {
    wslua_plugin  *lua_plug;

    for (lua_plug = wslua_plugin_list; lua_plug != NULL; lua_plug = lua_plug->next)
    {
        callback(lua_plug->name, lua_plug->version, wslua_plugin_type_name(),
                 lua_plug->filename, user_data);
    }
}

static void
print_wslua_plugin_description(const char *name, const char *version,
                               const char *description, const char *filename,
                               void *user_data _U_)
{
    ws_debug_printf("%s\t%s\t%s\t%s\n", name, version, description, filename);
}

void
wslua_plugins_dump_all(void)
{
    wslua_plugins_get_descriptions(print_wslua_plugin_description, NULL);
}

const char *wslua_plugin_type_name(void) {
    return "lua script";
}

static ei_register_info* ws_lua_ei = NULL;
static int ws_lua_ei_len = 0;

expert_field*
wslua_get_expert_field(const int group, const int severity)
{
    int i;
    const ei_register_info *ei = ws_lua_ei;

    g_assert(ei);

    for (i=0; i < ws_lua_ei_len; i++, ei++) {
        if (ei->eiinfo.group == group && ei->eiinfo.severity == severity)
            return ei->ids;
    }

    return &ei_lua_error;
}

static void *
wslua_allocf(void *ud _U_, void *ptr, size_t osize _U_, size_t nsize)
{
    /* g_realloc frees ptr if nsize==0 and returns NULL (as desired).
     * Furthermore it simplifies error handling by aborting on OOM */
    return g_realloc(ptr, nsize);
}

void wslua_init(register_cb cb, gpointer client_data) {
    gchar* filename;
    const funnel_ops_t* ops = funnel_get_funnel_ops();
    gboolean enable_lua = TRUE;
    gboolean run_anyway = FALSE;
    expert_module_t* expert_lua;
    int file_count = 1;
    static gboolean first_time = TRUE;
    int i;

    static hf_register_info hf[] = {
        { &hf_wslua_fake,
          { "Wireshark Lua fake item",     "_ws.lua.fake",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Fake internal item for Wireshark Lua", HFILL }},
        { &hf_wslua_text,
          { "Wireshark Lua text",     "_ws.lua.text",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };

    static ei_register_info ei[] = {
        /* the following are created so we can continue to support the TreeItem_add_expert_info()
           function to Lua scripts. That function doesn't know what registered protocol to use,
           so it uses the "_ws.lua" one. */
        /* XXX: it seems to me we should not be offering PI_GROUP_MASK nor PI_SEVERITY_MASK since
           they are not real settings, so I'm not adding them below (should they also not be exported
           into Lua? they are right now.) */
        /* NOTE: do not add expert entries at the top of this array - only at the bottom. This array
           is not only used by expert.c, but also by wslua_get_expert_field() to find the appropriate
           "dummy" entry. So this array's ordering matters. */
        { &ei_lua_proto_checksum_comment,   { "_ws.lua.proto.comment", PI_CHECKSUM, PI_COMMENT ,"Protocol Comment", EXPFILL }},
        { &ei_lua_proto_checksum_chat,      { "_ws.lua.proto.chat",    PI_CHECKSUM, PI_CHAT    ,"Protocol Chat",    EXPFILL }},
        { &ei_lua_proto_checksum_note,      { "_ws.lua.proto.note",    PI_CHECKSUM, PI_NOTE    ,"Protocol Note",    EXPFILL }},
        { &ei_lua_proto_checksum_warn,      { "_ws.lua.proto.warning", PI_CHECKSUM, PI_WARN    ,"Protocol Warning", EXPFILL }},
        { &ei_lua_proto_checksum_error,     { "_ws.lua.proto.error",   PI_CHECKSUM, PI_ERROR   ,"Protocol Error",   EXPFILL }},

        { &ei_lua_proto_sequence_comment,   { "_ws.lua.proto.comment", PI_SEQUENCE, PI_COMMENT ,"Protocol Comment", EXPFILL }},
        { &ei_lua_proto_sequence_chat,      { "_ws.lua.proto.chat",    PI_SEQUENCE, PI_CHAT    ,"Protocol Chat",    EXPFILL }},
        { &ei_lua_proto_sequence_note,      { "_ws.lua.proto.note",    PI_SEQUENCE, PI_NOTE    ,"Protocol Note",    EXPFILL }},
        { &ei_lua_proto_sequence_warn,      { "_ws.lua.proto.warning", PI_SEQUENCE, PI_WARN    ,"Protocol Warning", EXPFILL }},
        { &ei_lua_proto_sequence_error,     { "_ws.lua.proto.error",   PI_SEQUENCE, PI_ERROR   ,"Protocol Error",   EXPFILL }},

        { &ei_lua_proto_response_comment,   { "_ws.lua.proto.comment", PI_RESPONSE_CODE, PI_COMMENT ,"Protocol Comment", EXPFILL }},
        { &ei_lua_proto_response_chat,      { "_ws.lua.proto.chat",    PI_RESPONSE_CODE, PI_CHAT    ,"Protocol Chat",    EXPFILL }},
        { &ei_lua_proto_response_note,      { "_ws.lua.proto.note",    PI_RESPONSE_CODE, PI_NOTE    ,"Protocol Note",    EXPFILL }},
        { &ei_lua_proto_response_warn,      { "_ws.lua.proto.warning", PI_RESPONSE_CODE, PI_WARN    ,"Protocol Warning", EXPFILL }},
        { &ei_lua_proto_response_error,     { "_ws.lua.proto.error",   PI_RESPONSE_CODE, PI_ERROR   ,"Protocol Error",   EXPFILL }},

        { &ei_lua_proto_request_comment,    { "_ws.lua.proto.comment", PI_REQUEST_CODE, PI_COMMENT ,"Protocol Comment", EXPFILL }},
        { &ei_lua_proto_request_chat,       { "_ws.lua.proto.chat",    PI_REQUEST_CODE, PI_CHAT    ,"Protocol Chat",    EXPFILL }},
        { &ei_lua_proto_request_note,       { "_ws.lua.proto.note",    PI_REQUEST_CODE, PI_NOTE    ,"Protocol Note",    EXPFILL }},
        { &ei_lua_proto_request_warn,       { "_ws.lua.proto.warning", PI_REQUEST_CODE, PI_WARN    ,"Protocol Warning", EXPFILL }},
        { &ei_lua_proto_request_error,      { "_ws.lua.proto.error",   PI_REQUEST_CODE, PI_ERROR   ,"Protocol Error",   EXPFILL }},

        { &ei_lua_proto_undecoded_comment,  { "_ws.lua.proto.comment", PI_UNDECODED, PI_COMMENT ,"Protocol Comment", EXPFILL }},
        { &ei_lua_proto_undecoded_chat,     { "_ws.lua.proto.chat",    PI_UNDECODED, PI_CHAT    ,"Protocol Chat",    EXPFILL }},
        { &ei_lua_proto_undecoded_note,     { "_ws.lua.proto.note",    PI_UNDECODED, PI_NOTE    ,"Protocol Note",    EXPFILL }},
        { &ei_lua_proto_undecoded_warn,     { "_ws.lua.proto.warning", PI_UNDECODED, PI_WARN    ,"Protocol Warning", EXPFILL }},
        { &ei_lua_proto_undecoded_error,    { "_ws.lua.proto.error",   PI_UNDECODED, PI_ERROR   ,"Protocol Error",   EXPFILL }},

        { &ei_lua_proto_reassemble_comment, { "_ws.lua.proto.comment", PI_REASSEMBLE, PI_COMMENT ,"Protocol Comment", EXPFILL }},
        { &ei_lua_proto_reassemble_chat,    { "_ws.lua.proto.chat",    PI_REASSEMBLE, PI_CHAT    ,"Protocol Chat",    EXPFILL }},
        { &ei_lua_proto_reassemble_note,    { "_ws.lua.proto.note",    PI_REASSEMBLE, PI_NOTE    ,"Protocol Note",    EXPFILL }},
        { &ei_lua_proto_reassemble_warn,    { "_ws.lua.proto.warning", PI_REASSEMBLE, PI_WARN    ,"Protocol Warning", EXPFILL }},
        { &ei_lua_proto_reassemble_error,   { "_ws.lua.proto.error",   PI_REASSEMBLE, PI_ERROR   ,"Protocol Error",   EXPFILL }},

        { &ei_lua_proto_malformed_comment,  { "_ws.lua.proto.comment", PI_MALFORMED, PI_COMMENT ,"Protocol Comment", EXPFILL }},
        { &ei_lua_proto_malformed_chat,     { "_ws.lua.proto.chat",    PI_MALFORMED, PI_CHAT    ,"Protocol Chat",    EXPFILL }},
        { &ei_lua_proto_malformed_note,     { "_ws.lua.proto.note",    PI_MALFORMED, PI_NOTE    ,"Protocol Note",    EXPFILL }},
        { &ei_lua_proto_malformed_warn,     { "_ws.lua.proto.warning", PI_MALFORMED, PI_WARN    ,"Protocol Warning", EXPFILL }},
        { &ei_lua_proto_malformed_error,    { "_ws.lua.proto.error",   PI_MALFORMED, PI_ERROR   ,"Protocol Error",   EXPFILL }},

        { &ei_lua_proto_debug_comment,      { "_ws.lua.proto.comment", PI_DEBUG, PI_COMMENT ,"Protocol Comment", EXPFILL }},
        { &ei_lua_proto_debug_chat,         { "_ws.lua.proto.chat",    PI_DEBUG, PI_CHAT    ,"Protocol Chat",    EXPFILL }},
        { &ei_lua_proto_debug_note,         { "_ws.lua.proto.note",    PI_DEBUG, PI_NOTE    ,"Protocol Note",    EXPFILL }},
        { &ei_lua_proto_debug_warn,         { "_ws.lua.proto.warning", PI_DEBUG, PI_WARN    ,"Protocol Warning", EXPFILL }},
        { &ei_lua_proto_debug_error,        { "_ws.lua.proto.error",   PI_DEBUG, PI_ERROR   ,"Protocol Error",   EXPFILL }},

        { &ei_lua_proto_protocol_comment,   { "_ws.lua.proto.comment", PI_PROTOCOL, PI_COMMENT ,"Protocol Comment", EXPFILL }},
        { &ei_lua_proto_protocol_chat,      { "_ws.lua.proto.chat",    PI_PROTOCOL, PI_CHAT    ,"Protocol Chat",    EXPFILL }},
        { &ei_lua_proto_protocol_note,      { "_ws.lua.proto.note",    PI_PROTOCOL, PI_NOTE    ,"Protocol Note",    EXPFILL }},
        { &ei_lua_proto_protocol_warn,      { "_ws.lua.proto.warning", PI_PROTOCOL, PI_WARN    ,"Protocol Warning", EXPFILL }},
        { &ei_lua_proto_protocol_error,     { "_ws.lua.proto.error",   PI_PROTOCOL, PI_ERROR   ,"Protocol Error",   EXPFILL }},

        { &ei_lua_proto_security_comment,   { "_ws.lua.proto.comment", PI_SECURITY, PI_COMMENT ,"Protocol Comment", EXPFILL }},
        { &ei_lua_proto_security_chat,      { "_ws.lua.proto.chat",    PI_SECURITY, PI_CHAT    ,"Protocol Chat",    EXPFILL }},
        { &ei_lua_proto_security_note,      { "_ws.lua.proto.note",    PI_SECURITY, PI_NOTE    ,"Protocol Note",    EXPFILL }},
        { &ei_lua_proto_security_warn,      { "_ws.lua.proto.warning", PI_SECURITY, PI_WARN    ,"Protocol Warning", EXPFILL }},
        { &ei_lua_proto_security_error,     { "_ws.lua.proto.error",   PI_SECURITY, PI_ERROR   ,"Protocol Error",   EXPFILL }},

        { &ei_lua_proto_comments_comment,   { "_ws.lua.proto.comment", PI_COMMENTS_GROUP, PI_COMMENT ,"Protocol Comment", EXPFILL }},
        { &ei_lua_proto_comments_chat,      { "_ws.lua.proto.chat",    PI_COMMENTS_GROUP, PI_CHAT    ,"Protocol Chat",    EXPFILL }},
        { &ei_lua_proto_comments_note,      { "_ws.lua.proto.note",    PI_COMMENTS_GROUP, PI_NOTE    ,"Protocol Note",    EXPFILL }},
        { &ei_lua_proto_comments_warn,      { "_ws.lua.proto.warning", PI_COMMENTS_GROUP, PI_WARN    ,"Protocol Warning", EXPFILL }},
        { &ei_lua_proto_comments_error,     { "_ws.lua.proto.error",   PI_COMMENTS_GROUP, PI_ERROR   ,"Protocol Error",   EXPFILL }},

        { &ei_lua_proto_deprecated_comment, { "_ws.lua.proto.comment", PI_DEPRECATED, PI_COMMENT ,"Protocol Comment", EXPFILL }},
        { &ei_lua_proto_deprecated_chat,    { "_ws.lua.proto.chat",    PI_DEPRECATED, PI_CHAT    ,"Protocol Chat",    EXPFILL }},
        { &ei_lua_proto_deprecated_note,    { "_ws.lua.proto.note",    PI_DEPRECATED, PI_NOTE    ,"Protocol Note",    EXPFILL }},
        { &ei_lua_proto_deprecated_warn,    { "_ws.lua.proto.warning", PI_DEPRECATED, PI_WARN    ,"Protocol Warning", EXPFILL }},
        { &ei_lua_proto_deprecated_error,   { "_ws.lua.proto.error",   PI_DEPRECATED, PI_ERROR   ,"Protocol Error",   EXPFILL }},

        /* this one is for reporting errors executing Lua code */
        { &ei_lua_error, { "_ws.lua.error", PI_UNDECODED, PI_ERROR ,"Lua Error", EXPFILL }},
    };

    if (first_time) {
        ws_lua_ei = ei;
        ws_lua_ei_len = array_length(ei);
    }

    /* set up the logger */
    wslua_logger = ops ? ops->logger : basic_logger;

    if (!L) {
        L = lua_newstate(wslua_allocf, NULL);
    }

    WSLUA_INIT(L);

#if LUA_VERSION_NUM == 501
    /* table.unpack was introduced with Lua 5.2, alias it to unpack. */
    lua_getglobal(L, "table");
    lua_getglobal(L, "unpack");
    lua_setfield(L, -2, "unpack");
    lua_pop(L, 1);
#endif

    if (first_time) {
        proto_lua = proto_register_protocol("Lua Dissection", "Lua Dissection", "_ws.lua");
        proto_register_field_array(proto_lua, hf, array_length(hf));
        expert_lua = expert_register_protocol(proto_lua);
        expert_register_field_array(expert_lua, ei, array_length(ei));
    }

    lua_atpanic(L,wslua_panic);

    /* the init_routines table (accessible by the user) */
    lua_newtable (L);
    lua_setglobal(L, WSLUA_INIT_ROUTINES);

    /* the dissectors table goes in the registry (not accessible) */
    lua_newtable (L);
    lua_dissectors_table_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_newtable (L);
    lua_heur_dissectors_table_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    /* the preferences apply_cb table (accessible by the user) */
    lua_newtable (L);
    lua_setglobal(L, WSLUA_PREFS_CHANGED);

    /* set running_superuser variable to its proper value */
    WSLUA_REG_GLOBAL_BOOL(L,"running_superuser",started_with_special_privs());

    /* special constant used by PDU reassembly handling */
    /* see dissect_lua() for notes */
    WSLUA_REG_GLOBAL_NUMBER(L,"DESEGMENT_ONE_MORE_SEGMENT",DESEGMENT_ONE_MORE_SEGMENT);

    /* load system's init.lua */
    filename = get_datafile_path("init.lua");
    if (( file_exists(filename))) {
        lua_load_internal_script(filename);
    }

    g_free(filename);
    filename = NULL;

    /* check if lua is to be disabled */
    lua_getglobal(L, "disable_lua"); // 2.6 and earlier, deprecated
    if (lua_isboolean(L,-1)) {
        enable_lua = ! lua_toboolean(L,-1);
    }
    lua_pop(L,1);  /* pop the getglobal result */

    lua_getglobal(L, "enable_lua"); // 3.0 and later
    if (lua_isboolean(L,-1)) {
        enable_lua = lua_toboolean(L,-1);
    }
    lua_pop(L,1);  /* pop the getglobal result */

    if (!enable_lua) {
        /* disable lua */
        lua_close(L);
        L = NULL;
        first_time = FALSE;
        return;
    }

    /* load global scripts */
    lua_load_global_plugins(cb, client_data, FALSE);

    /* check whether we should run other scripts even if running superuser */
    lua_getglobal(L,"run_user_scripts_when_superuser");

    if (lua_isboolean(L,-1) && lua_toboolean(L,-1)) {
        run_anyway = TRUE;
    }
    lua_pop(L,1);  /* pop the getglobal result */

    /* if we are indeed superuser run user scripts only if told to do so */
    if ( (!started_with_special_privs()) || run_anyway ) {
        /* load users init.lua */
        filename = get_persconffile_path("init.lua", FALSE);
        if ((file_exists(filename))) {
            if (cb)
                (*cb)(RA_LUA_PLUGINS, get_basename(filename), client_data);
            lua_load_internal_script(filename);
        }
        g_free(filename);

        /* load user scripts */
        lua_load_pers_plugins(cb, client_data, FALSE);

        /* load scripts from command line */
        for (i = 0; i < ex_opt_count("lua_script"); i++) {
            const gchar *script_filename = ex_opt_get_nth("lua_script", i);
            char* dirname = g_strdup(script_filename);
            char* dname = get_dirname(dirname);

            if (cb)
                (*cb)(RA_LUA_PLUGINS, get_basename(script_filename), client_data);

            lua_load_plugin_script(ws_dir_get_name(script_filename),
                                   script_filename,
                                   dname ? dname : "",
                                   file_count);
            file_count++;
            g_free(dirname);
        }
    }

    if (first_time) {
        /* at this point we're set up so register the init and cleanup routines */
        register_init_routine(wslua_init_routine);
        register_cleanup_routine(wslua_cleanup_routine);
    }

    /*
     * after this point it is too late to register a menu
     * disable the function to avoid weirdness
     */
    lua_pushcfunction(L, wslua_not_register_menu);
    lua_setglobal(L, "register_menu");

    /* set up some essential globals */
    lua_pinfo = NULL;
    lua_tree = NULL;
    lua_tvb = NULL;

    Proto_commit(L);

    first_time = FALSE;
}

void wslua_early_cleanup(void) {
    wslua_deregister_protocols(L);
}

void wslua_reload_plugins (register_cb cb, gpointer client_data) {
    const funnel_ops_t* ops = funnel_get_funnel_ops();

    if (cb)
        (*cb)(RA_LUA_DEREGISTER, NULL, client_data);

    if (ops->close_dialogs)
        ops->close_dialogs();

    wslua_deregister_heur_dissectors(L);
    wslua_deregister_protocols(L);
    wslua_deregister_dissector_tables(L);
    wslua_deregister_listeners(L);
    wslua_deregister_fields(L);
    wslua_deregister_filehandlers(L);
    wslua_deregister_menus();
    wslua_clear_plugin_list();

    wslua_cleanup();
    wslua_init(cb, client_data);    /* reinitialize */
}

void wslua_cleanup(void) {
    /* cleanup lua */
    if (L) {
        lua_close(L);
        L = NULL;
    }
    init_routine_initialized = FALSE;
}

lua_State* wslua_state(void) { return L; }

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
