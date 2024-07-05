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
#define WS_LOG_DOMAIN LOG_DOMAIN_WSLUA

#include "wslua.h"
#include "init_wslua.h"

#include <epan/dissectors/packet-frame.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <epan/expert.h>
#include <epan/ex-opt.h>
#include <epan/introspection.h>
#include <wiretap/introspection.h>
#include <wsutil/privileges.h>
#include <wsutil/file_util.h>
#include <wsutil/wslog.h>

/* linked list of Lua plugins */
typedef struct _wslua_plugin {
    char       *name;            /**< plugin name */
    char       *version;         /**< plugin version */
    char       *filename;        /**< plugin filename */
    struct _wslua_plugin *next;
} wslua_plugin;

static wslua_plugin *wslua_plugin_list;

static lua_State* L;

static void (*wslua_gui_print_func_ptr)(const char *, void *);
static void *wslua_gui_print_data_ptr;
static int wslua_lua_print_func_ref = LUA_NOREF;

/* XXX: global variables? Really?? Yuck. These could be done differently,
   using the Lua registry */
packet_info* lua_pinfo;
struct _wslua_treeitem* lua_tree;
tvbuff_t* lua_tvb;
int lua_dissectors_table_ref = LUA_NOREF;
int lua_heur_dissectors_table_ref = LUA_NOREF;

static int proto_lua;

static int hf_wslua_fake;
static int hf_wslua_text;

static expert_field ei_lua_error;

static expert_field ei_lua_proto_checksum_comment;
static expert_field ei_lua_proto_checksum_chat;
static expert_field ei_lua_proto_checksum_note;
static expert_field ei_lua_proto_checksum_warn;
static expert_field ei_lua_proto_checksum_error;

static expert_field ei_lua_proto_sequence_comment;
static expert_field ei_lua_proto_sequence_chat;
static expert_field ei_lua_proto_sequence_note;
static expert_field ei_lua_proto_sequence_warn;
static expert_field ei_lua_proto_sequence_error;

static expert_field ei_lua_proto_response_comment;
static expert_field ei_lua_proto_response_chat;
static expert_field ei_lua_proto_response_note;
static expert_field ei_lua_proto_response_warn;
static expert_field ei_lua_proto_response_error;

static expert_field ei_lua_proto_request_comment;
static expert_field ei_lua_proto_request_chat;
static expert_field ei_lua_proto_request_note;
static expert_field ei_lua_proto_request_warn;
static expert_field ei_lua_proto_request_error;

static expert_field ei_lua_proto_undecoded_comment;
static expert_field ei_lua_proto_undecoded_chat;
static expert_field ei_lua_proto_undecoded_note;
static expert_field ei_lua_proto_undecoded_warn;
static expert_field ei_lua_proto_undecoded_error;

static expert_field ei_lua_proto_reassemble_comment;
static expert_field ei_lua_proto_reassemble_chat;
static expert_field ei_lua_proto_reassemble_note;
static expert_field ei_lua_proto_reassemble_warn;
static expert_field ei_lua_proto_reassemble_error;

static expert_field ei_lua_proto_malformed_comment;
static expert_field ei_lua_proto_malformed_chat;
static expert_field ei_lua_proto_malformed_note;
static expert_field ei_lua_proto_malformed_warn;
static expert_field ei_lua_proto_malformed_error;

static expert_field ei_lua_proto_debug_comment;
static expert_field ei_lua_proto_debug_chat;
static expert_field ei_lua_proto_debug_note;
static expert_field ei_lua_proto_debug_warn;
static expert_field ei_lua_proto_debug_error;

static expert_field ei_lua_proto_protocol_comment;
static expert_field ei_lua_proto_protocol_chat;
static expert_field ei_lua_proto_protocol_note;
static expert_field ei_lua_proto_protocol_warn;
static expert_field ei_lua_proto_protocol_error;

static expert_field ei_lua_proto_security_comment;
static expert_field ei_lua_proto_security_chat;
static expert_field ei_lua_proto_security_note;
static expert_field ei_lua_proto_security_warn;
static expert_field ei_lua_proto_security_error;

static expert_field ei_lua_proto_comments_comment;
static expert_field ei_lua_proto_comments_chat;
static expert_field ei_lua_proto_comments_note;
static expert_field ei_lua_proto_comments_warn;
static expert_field ei_lua_proto_comments_error;

static expert_field ei_lua_proto_decryption_comment;
static expert_field ei_lua_proto_decryption_chat;
static expert_field ei_lua_proto_decryption_note;
static expert_field ei_lua_proto_decryption_warn;
static expert_field ei_lua_proto_decryption_error;

static expert_field ei_lua_proto_assumption_comment;
static expert_field ei_lua_proto_assumption_chat;
static expert_field ei_lua_proto_assumption_note;
static expert_field ei_lua_proto_assumption_warn;
static expert_field ei_lua_proto_assumption_error;

static expert_field ei_lua_proto_deprecated_comment;
static expert_field ei_lua_proto_deprecated_chat;
static expert_field ei_lua_proto_deprecated_note;
static expert_field ei_lua_proto_deprecated_warn;
static expert_field ei_lua_proto_deprecated_error;

static expert_field ei_lua_proto_receive_comment;
static expert_field ei_lua_proto_receive_chat;
static expert_field ei_lua_proto_receive_note;
static expert_field ei_lua_proto_receive_warn;
static expert_field ei_lua_proto_receive_error;

static expert_field ei_lua_proto_interface_comment;
static expert_field ei_lua_proto_interface_chat;
static expert_field ei_lua_proto_interface_note;
static expert_field ei_lua_proto_interface_warn;
static expert_field ei_lua_proto_interface_error;

static int ett_wslua_traceback;

static bool
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
    return false;
}

static int wslua_not_register_menu(lua_State* LS) {
    luaL_error(LS,"too late to register a menu");
    return 0;
}

/* a getter for wslua_tree.c's TreeItem_add_item_any() to use */
int get_hf_wslua_text(void) {
    return hf_wslua_text;
}


// Attach the lua traceback to the proto_tree
static int dissector_error_handler(lua_State *LS) {
    // Entering, stack: [ error_handler, dissector, errmsg ]

    proto_item *tb_item;
    proto_tree *tb_tree;

    // Add the expert info Lua error message
    proto_tree_add_expert_format(lua_tree->tree, lua_pinfo, &ei_lua_error, lua_tvb, 0, 0,
            "Lua Error: %s", lua_tostring(LS,-1));

    // Create a new proto sub_tree for the traceback
    tb_item = proto_tree_add_text_internal(lua_tree->tree, lua_tvb, 0, 0, "Lua Traceback");
    tb_tree = proto_item_add_subtree(tb_item, ett_wslua_traceback);

    // Push the traceback onto the stack
    // After call, stack: [ error_handler, dissector, errmsg, tb_string ]
    luaL_traceback(LS, LS, NULL, 1);

    // Get the string length of the traceback. Note that the string
    // has a terminating NUL, but string_length doesn't include it.
    // The lua docs say the string can have NULs in it too, but we
    // ignore that because the traceback string shouldn't have them.
    // This function does not own the string; it's still owned by lua.
    size_t string_length;
    const char *orig_tb_string = lua_tolstring(LS, -1, &string_length);

    // We make the copy so we can modify the string. Don't forget the
    // extra byte for the terminating NUL!
    char *tb_string = (char*) g_memdup2(orig_tb_string, string_length+1);

    // The string has tabs and new lines in it
    // We will add proto_items for each new-line-delimited sub-string.
    // We also convert tabs to spaces, because the Wireshark GUI
    // shows tabs literally as "\t".

    // 'beginning' is the beginning of the sub-string
    char *beginning = tb_string;

    // 'p' is the pointer to the byte as we iterate over the string
    char *p = tb_string;

    size_t i;
    bool skip_initial_tabs = true;
    size_t last_eol_i = 0;
    for (i = 0 ; i < string_length ; i++) {
        // At the beginning of a sub-string, we will convert tabs to spaces
        if (skip_initial_tabs) {
            if (*p == '\t') {
                *p = ' ';
            } else {
                // Once we hit the first non-tab character in a substring,
                // we won't convert tabs (until the next substring)
                skip_initial_tabs = false;
            }
        }
        // If we see a newline, we add the substring to the proto tree
        if (*p == '\n') {
            // Terminate the string.
            *p = '\0';
            proto_tree_add_text_internal(tb_tree, lua_tvb, 0, 0, "%s", beginning);
            beginning = ++p;
            skip_initial_tabs = true;
            last_eol_i = i;
        } else {
            ++p;
        }
    }

    // The last portion of the string doesn't have a newline, so add it here
    // after the loop. But to be sure, check that we didn't just add it, in
    // case lua decides to change it in the future.
    if ( last_eol_i < i-1 ) {
        proto_tree_add_text_internal(tb_tree, lua_tvb, 0, 0, "%s", beginning);
    }

    // Cleanup
    g_free(tb_string);

    // Return the same original error message
    return -2;
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

    // set the stack top be index 0
    lua_settop(L,0);

    // After call, stack: [ error_handler_func ]
    lua_pushcfunction(L, dissector_error_handler);

    // Push the dissectors table onto the the stack
    // After call, stack: [ error_handler_func, dissectors_table ]
    lua_rawgeti(L, LUA_REGISTRYINDEX, lua_dissectors_table_ref);

    // Push a copy of the current_proto string onto the stack
    // After call, stack: [ error_handler_func, dissectors_table, current_proto ]
    lua_pushstring(L, pinfo->current_proto);

    // dissectors_table[current_proto], a dissector, goes into the stack
    // The key (current_proto) is popped off the stack.
    // After call, stack: [ error_handler_func, dissectors_table, dissector ]
    lua_gettable(L, -2);

    // We don't need the dissectors_table in the stack
    // After call, stack: [ error_handler_func, dissector ]
    lua_remove(L,2);

    // Is the dissector a function?
    if (lua_isfunction(L,2)) {

        // After call, stack: [ error_handler_func, dissector, tvb ]
        push_Tvb(L,tvb);
        // After call, stack: [ error_handler_func, dissector, tvb, pinfo ]
        push_Pinfo(L,pinfo);
        // After call, stack: [ error_handler_func, dissector, tvb, pinfo, TreeItem ]
        lua_tree = push_TreeItem(L, tree, proto_tree_add_item(tree, hf_wslua_fake, tvb, 0, 0, ENC_NA));
        proto_item_set_hidden(lua_tree->item);

        if  ( lua_pcall(L, /*num_args=*/3, /*num_results=*/1, /*error_handler_func_stack_position=*/1) ) {
            // do nothing; the traceback error message handler function does everything
        } else {

            /* if the Lua dissector reported the consumed bytes, pass it to our caller */
            if (lua_isnumber(L, -1)) {
                /* we got the consumed bytes or the missing bytes as a negative number */
                consumed_bytes = wslua_toint(L, -1);
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
 * @return true if the packet was recognized by the sub-dissector (stop dissection here)
 */
bool heur_dissect_lua(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_) {
    bool result = false;
    tvbuff_t *saved_lua_tvb = lua_tvb;
    packet_info *saved_lua_pinfo = lua_pinfo;
    struct _wslua_treeitem *saved_lua_tree = lua_tree;
    lua_tvb = tvb;
    lua_pinfo = pinfo;

    ws_assert(tvb && pinfo);

    if (!pinfo->heur_list_name || !pinfo->current_proto) {
        proto_tree_add_expert_format(tree, pinfo, &ei_lua_error, tvb, 0, 0,
                "internal error in heur_dissect_lua: NULL list name or current proto");
        return false;
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
        return false;
    }

    /* get the table inside that, for the specific lua heuristic dissector */
    if (!wslua_get_field(L,-1,pinfo->current_proto)) {
        /* this shouldn't happen */
        lua_settop(L,0);
        proto_tree_add_expert_format(tree, pinfo, &ei_lua_error, tvb, 0, 0,
                "internal error in heur_dissect_lua: no %s heuristic dissector for list %s",
                        pinfo->current_proto, pinfo->heur_list_name);
        return false;
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
        return false;
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
            result = lua_tointeger(L,-1) != 0 ? true : false;
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

static void iter_table_and_call(lua_State* LS, const char* table_name, lua_CFunction error_handler) {
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
        const char* name = lua_tostring(L,-2);

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
    const char* error =  lua_tostring(LS,1);
    report_failure("Lua: Error during execution of initialization:\n %s",error);
    return 0;
}


static bool init_routine_initialized;
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
        init_routine_initialized = true;
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
    const char* error =  lua_tostring(LS,1);
    report_failure("Lua: Error during execution of prefs apply callback:\n %s",error);
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
    const char *msg = lua_tostring(LS, 1);
    luaL_traceback(LS, LS, msg, 1);     /* push message with traceback.  */
    lua_remove(LS, -2);                 /* remove original msg */
    return 1;
}

static void wslua_add_plugin(const char *name, const char *version, const char *filename)
{
    wslua_plugin *new_plug, *lua_plug;

    lua_plug = wslua_plugin_list;
    new_plug = g_new(wslua_plugin, 1);

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
    char* argname = ws_strdup_printf("lua_script%d", script_num);
    const char* argvalue = NULL;
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
static void set_file_environment(const char* filename, const char* dirname) {
    const char* path;

    lua_newtable(L); /* environment for script (index 3) */

    lua_pushstring(L, filename); /* tell the script about its filename */
    lua_setfield(L, -2, FILE_NAME_KEY); /* make it accessible at __FILE__ */

    lua_pushstring(L, dirname); /* tell the script about its dirname */
    lua_setfield(L, -2, DIR_NAME_KEY); /* make it accessible at __DIR__ */

    lua_pushstring(L, G_DIR_SEPARATOR_S); /* tell the script the directory separator */
    lua_setfield(L, -2, DIR_SEP_NAME_KEY); /* make it accessible at __DIR__ */

    lua_newtable(L); /* new metatable */

    lua_pushglobaltable(L);

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

    lua_setupvalue(L, -2, 1); /* pop environment and assign it to upvalue 1 */

}


/* If file_count > 0 then it's a command-line-added user script, and the count
 * represents which user script it is (first=1, second=2, etc.).
 * If dirname != NULL, then it's a user script and the dirname will get put in a file environment
 * If dirname == NULL then it's a wireshark script and no file environment is created
 */
static bool lua_load_script(const char* filename, const char* dirname, const int file_count) {
    FILE* file;
    int error;
    int numargs = 0;

    if (! ( file = ws_fopen(filename,"r")) ) {
        report_open_failure(filename,errno,false);
        return false;
    }

    lua_settop(L,0);

    lua_pushcfunction(L, error_handler_with_callback);
    /* The source argument should start with '@' to indicate a file. */
    lua_pushfstring(L, "@%s", filename);

    error = lua_load(L, getF, file, lua_tostring(L, -1), NULL);

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
static bool lua_load_internal_script(const char* filename) {
    return lua_load_script(filename, NULL, 0);
}

/* This one is used to load plugins: either from the plugin directories,
 *   or from the command line.
 */
static gboolean lua_load_plugin_script(const char* name,
                                       const char* filename,
                                       const char* dirname,
                                       const int file_count)
{
    ws_debug("Loading lua script: %s", filename);
    if (lua_load_script(filename, dirname, file_count)) {
        wslua_add_plugin(name, get_current_plugin_version(), filename);
        clear_current_plugin_version();
        return true;
    }
    return false;
}

static int wslua_panic(lua_State* LS) {
    ws_error("LUA PANIC: %s",lua_tostring(LS,-1));
    /** ws_error() does an abort() and thus never returns **/
    return 0; /* keep gcc happy */
}

static int string_compare(const void *a, const void *b) {
    return strcmp((const char*)a, (const char*)b);
}

static int lua_load_plugins(const char *dirname, register_cb cb, void *client_data,
                            bool count_only, const bool is_user, GHashTable *loaded_files,
                            int depth)
{
    WS_DIR        *dir;             /* scanned directory */
    WS_DIRENT     *file;            /* current file */
    char          *filename, *dot;
    const char    *name;
    int            plugins_counter = 0;
    GList         *sorted_dirnames = NULL;
    GList         *sorted_filenames = NULL;
    GList         *l = NULL;

    if ((dir = ws_dir_open(dirname, 0, NULL)) != NULL) {
        while ((file = ws_dir_read_name(dir)) != NULL) {
            name = ws_dir_get_name(file);

            if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
                /* skip "." and ".." */
                continue;
            }
            if (depth == 0 && strcmp(name, "init.lua") == 0) {
                /* If we are in the root directory skip the special "init.lua"
                 * file that was already loaded before every other user script.
                 * (If we are below the root script directory we just treat it like any other
                 * lua script.) */
                continue;
            }

            filename = ws_strdup_printf("%s" G_DIR_SEPARATOR_S "%s", dirname, name);
            if (test_for_directory(filename) == EISDIR) {
                sorted_dirnames = g_list_prepend(sorted_dirnames, (void *)filename);
                continue;
            }

            /* skip files starting with . */
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

            if (file_exists(filename)) {
                sorted_filenames = g_list_prepend(sorted_filenames, (void *)filename);
            }
            else {
                g_free(filename);
            }
        }
        ws_dir_close(dir);
    }

    /* Depth first; ie, process subdirectories (in ASCIIbetical order) before files */
    if (sorted_dirnames != NULL) {
        sorted_dirnames = g_list_sort(sorted_dirnames, string_compare);
        for (l = sorted_dirnames; l != NULL; l = l->next) {
            plugins_counter += lua_load_plugins((const char *)l->data, cb, client_data, count_only, is_user, loaded_files, depth + 1);
        }
        g_list_free_full(sorted_dirnames, g_free);
    }

    /* Process files in ASCIIbetical order */
    if (sorted_filenames != NULL) {
        sorted_filenames = g_list_sort(sorted_filenames, string_compare);
        for (l = sorted_filenames; l != NULL; l = l->next) {
            filename = (char *)l->data;
            name = strrchr(filename, G_DIR_SEPARATOR) + 1;

            /* Check if we have already loaded this file name, if provided with a set */
            if (loaded_files && g_hash_table_lookup_extended(loaded_files, name, NULL, NULL)) {
                continue;
            }

            if (!count_only) {
                if (cb)
                    (*cb)(RA_LUA_PLUGINS, name, client_data);
                lua_load_plugin_script(name, filename, is_user ? dirname : NULL, 0);

                if (loaded_files) {
                    g_hash_table_insert(loaded_files, g_strdup(name), NULL);
                }
            }
            plugins_counter++;
        }
        g_list_free_full(sorted_filenames, g_free);
    }

    return plugins_counter;
}

static int lua_load_global_plugins(register_cb cb, void *client_data,
                                    bool count_only)
{
    return lua_load_plugins(get_plugins_dir(), cb, client_data, count_only, false, NULL, 0);
}

static int lua_load_pers_plugins(register_cb cb, void *client_data,
                                    bool count_only)
{
    int plugins_counter = 0;

    /* aux table (set) to make sure we only load each file once (by name) */
    GHashTable *loaded_user_scripts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

    /* load user scripts */
    plugins_counter += lua_load_plugins(get_plugins_pers_dir(), cb, client_data, count_only, true, loaded_user_scripts, 0);

    /* for backward compatibility check old plugin directory */
    char *old_path = get_persconffile_path("plugins", false);
    if (strcmp(get_plugins_pers_dir(), old_path) != 0) {
        plugins_counter += lua_load_plugins(old_path, cb, client_data, count_only, true, loaded_user_scripts, 0);
    }
    g_free(old_path);

    g_hash_table_destroy(loaded_user_scripts);

    return plugins_counter;
}

int wslua_count_plugins(void) {
    int plugins_counter;

    /* count global scripts */
    plugins_counter = lua_load_global_plugins(NULL, NULL, true);

    /* count user scripts */
    plugins_counter += lua_load_pers_plugins(NULL, NULL, true);

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
    printf("%s\t%s\t%s\t%s\n", name, version, description, filename);
}

void
wslua_plugins_dump_all(void)
{
    wslua_plugins_get_descriptions(print_wslua_plugin_description, NULL);
}

const char *wslua_plugin_type_name(void) {
    return "lua script";
}

static ei_register_info* ws_lua_ei;
static int ws_lua_ei_len;

expert_field*
wslua_get_expert_field(const int group, const int severity)
{
    int i;
    const ei_register_info *ei = ws_lua_ei;

    ws_assert(ei);

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

#define WSLUA_EPAN_ENUMS_TABLE  "_EPAN"
#define WSLUA_WTAP_ENUMS_TABLE  "_WTAP"

#define WSLUA_BASE_TABLE        "base"
#define WSLUA_FTYPE_TABLE       "ftypes"
#define WSLUA_FRAMETYPE_TABLE   "frametype"
#define WSLUA_EXPERT_TABLE      "expert"
#define WSLUA_EXPERT_GROUP_TABLE    "group"
#define WSLUA_EXPERT_SEVERITY_TABLE "severity"
#define WSLUA_WTAP_ENCAPS_TABLE     "wtap_encaps"
#define WSLUA_WTAP_TSPREC_TABLE     "wtap_tsprecs"
#define WSLUA_WTAP_COMMENTS_TABLE   "wtap_comments"
#define WSLUA_WTAP_RECTYPES_TABLE   "wtap_rec_types"
#define WSLUA_WTAP_PRESENCE_FLAGS_TABLE "wtap_presence_flags"

static void
add_table_symbol(const char *table, const char *name, int value)
{
    /* Get table from the global environment. */
    lua_getglobal(L, table);
    /* Set symbol in table. */
    lua_pushstring(L, name);
    lua_pushinteger(L, value);
    lua_settable(L, -3);
    /* Pop table from stack. */
    lua_pop(L, 1);
}

static void
add_global_symbol(const char *name, int value)
{
    /* Set symbol in global environment. */
    lua_pushinteger(L, value);
    lua_setglobal(L, name);
}

static void
add_pi_severity_symbol(const char *name, int value)
{
    lua_getglobal(L, WSLUA_EXPERT_TABLE);
    lua_getfield(L, -1, WSLUA_EXPERT_SEVERITY_TABLE);
    lua_pushinteger(L, value);
    lua_setfield(L, -2, name);
    lua_pop(L, 2);
}

static void
add_pi_group_symbol(const char *name, int value)
{
    lua_getglobal(L, WSLUA_EXPERT_TABLE);
    lua_getfield(L, -1, WSLUA_EXPERT_GROUP_TABLE);
    lua_pushinteger(L, value);
    lua_setfield(L, -2, name);
    lua_pop(L, 2);
}

static void
add_menu_group_symbol(const char *name, int value)
{
    /* Set symbol in global environment. */
    lua_pushinteger(L, value);
    char *str = g_strdup(name);
    char *s = strstr(str, "_GROUP_");
    if (s == NULL) {
        g_free(str);
        return;
    }
    *s = '\0';
    s += strlen("_GROUP_");
    char *str2 = ws_strdup_printf("MENU_%s_%s", str, s);
    lua_setglobal(L, str2);
    g_free(str);
    g_free(str2);
}

/*
 * Read introspection constants and add them according to the historical
 * (sometimes arbitrary) rules of make-init-lua.py. For efficiency reasons
 * we only loop the enums array once.
 */
static void
wslua_add_introspection(void)
{
    const ws_enum_t *ep;

    /* Add empty tables to be populated. */
    lua_newtable(L);
    lua_setglobal(L, WSLUA_BASE_TABLE);
    lua_newtable(L);
    lua_setglobal(L, WSLUA_FTYPE_TABLE);
    lua_newtable(L);
    lua_setglobal(L, WSLUA_FRAMETYPE_TABLE);
    lua_newtable(L);
    lua_pushstring(L, WSLUA_EXPERT_GROUP_TABLE);
    lua_newtable(L);
    lua_settable(L, -3);
    lua_pushstring(L, WSLUA_EXPERT_SEVERITY_TABLE);
    lua_newtable(L);
    lua_settable(L, -3);
    lua_setglobal(L, WSLUA_EXPERT_TABLE);
    /* Add catch-all _EPAN table. */
    lua_newtable(L);
    lua_setglobal(L, WSLUA_EPAN_ENUMS_TABLE);

    for (ep = epan_inspect_enums(); ep->symbol != NULL; ep++) {

        if (g_str_has_prefix(ep->symbol, "BASE_")) {
            add_table_symbol(WSLUA_BASE_TABLE, ep->symbol + strlen("BASE_"), ep->value);
        }
        else if (g_str_has_prefix(ep->symbol, "SEP_")) {
            add_table_symbol(WSLUA_BASE_TABLE, ep->symbol + strlen("SEP_"), ep->value);
        }
        else if (g_str_has_prefix(ep->symbol, "ABSOLUTE_TIME_")) {
            add_table_symbol(WSLUA_BASE_TABLE, ep->symbol + strlen("ABSOLUTE_TIME_"), ep->value);
        }
        else if (g_str_has_prefix(ep->symbol, "ENC_")) {
            add_global_symbol(ep->symbol, ep->value);
        }
        else if (g_str_has_prefix(ep->symbol, "FT_FRAMENUM_")) {
            add_table_symbol(WSLUA_FRAMETYPE_TABLE, ep->symbol + strlen("FT_FRAMENUM_"), ep->value);
        }
        else if (g_str_has_prefix(ep->symbol, "FT_")) {
            add_table_symbol(WSLUA_FTYPE_TABLE, ep->symbol + strlen("FT_"), ep->value);
        }
        else if (g_str_has_prefix(ep->symbol, "PI_")) {
            if (ep->value & PI_SEVERITY_MASK) {
                add_pi_severity_symbol(ep->symbol + strlen("PI_"), ep->value);
            }
            else {
                 add_pi_group_symbol(ep->symbol + strlen("PI_"), ep->value);
            }
            /* For backward compatibility. */
            add_global_symbol(ep->symbol, ep->value);
        }
        else if (g_str_has_prefix(ep->symbol, "REGISTER_")) {
            add_menu_group_symbol(ep->symbol + strlen("REGISTER_"), ep->value);
        }
        add_table_symbol(WSLUA_EPAN_ENUMS_TABLE, ep->symbol, ep->value);
    }

    /* Add empty tables to be populated. */
    lua_newtable(L);
    lua_setglobal(L, WSLUA_WTAP_ENCAPS_TABLE);
    lua_newtable(L);
    lua_setglobal(L, WSLUA_WTAP_TSPREC_TABLE);
    lua_newtable(L);
    lua_setglobal(L, WSLUA_WTAP_COMMENTS_TABLE);
    lua_newtable(L);
    lua_setglobal(L, WSLUA_WTAP_RECTYPES_TABLE);
    lua_newtable(L);
    lua_setglobal(L, WSLUA_WTAP_PRESENCE_FLAGS_TABLE);
    /* Add catch-all _WTAP table. */
    lua_newtable(L);
    lua_setglobal(L, WSLUA_WTAP_ENUMS_TABLE);

    for (ep = wtap_inspect_enums(); ep->symbol != NULL; ep++) {

        if (g_str_has_prefix(ep->symbol, "WTAP_ENCAP_")) {
            add_table_symbol(WSLUA_WTAP_ENCAPS_TABLE, ep->symbol + strlen("WTAP_ENCAP_"), ep->value);
        }
        else if (g_str_has_prefix(ep->symbol, "WTAP_TSPREC_")) {
            add_table_symbol(WSLUA_WTAP_TSPREC_TABLE, ep->symbol + strlen("WTAP_TSPREC_"), ep->value);
        }
        else if (g_str_has_prefix(ep->symbol, "WTAP_COMMENT_")) {
            add_table_symbol(WSLUA_WTAP_COMMENTS_TABLE, ep->symbol + strlen("WTAP_COMMENT_"), ep->value);
        }
        else if (g_str_has_prefix(ep->symbol, "REC_TYPE_")) {
            add_table_symbol(WSLUA_WTAP_RECTYPES_TABLE, ep->symbol + strlen("REC_TYPE_"), ep->value);
        }
        else if (g_str_has_prefix(ep->symbol, "WTAP_HAS_")) {
            add_table_symbol(WSLUA_WTAP_PRESENCE_FLAGS_TABLE, ep->symbol + strlen("WTAP_HAS_"), ep->value);
        }
        add_table_symbol(WSLUA_WTAP_ENUMS_TABLE, ep->symbol, ep->value);
    }
}

static void wslua_add_deprecated(void)
{
    /* For backward compatibility. */
    lua_getglobal(L, "wtap_encaps");
    lua_setglobal(L, "wtap");

    /*
     * Generate the wtap_filetypes items for file types, for backwards
     * compatibility.
     * We no longer have WTAP_FILE_TYPE_SUBTYPE_ #defines;
     * built-in file types are registered the same way that
     * plugin file types are registered.
     *
     * New code should use wtap_name_to_file_type_subtype to
     * look up file types by name.
     */
    wslua_init_wtap_filetypes(L);

    /* Old / deprecated menu groups. These shoudn't be used in new code. */
    lua_getglobal(L, "MENU_PACKET_ANALYZE_UNSORTED");
    lua_setglobal(L, "MENU_ANALYZE_UNSORTED");
    lua_getglobal(L, "MENU_ANALYZE_CONVERSATION_FILTER");
    lua_setglobal(L, "MENU_ANALYZE_CONVERSATION");
    lua_getglobal(L, "MENU_STAT_CONVERSATION_LIST");
    lua_setglobal(L, "MENU_STAT_CONVERSATION");
    lua_getglobal(L, "MENU_STAT_ENDPOINT_LIST");
    lua_setglobal(L, "MENU_STAT_ENDPOINT");
    lua_getglobal(L, "MENU_STAT_RESPONSE_TIME");
    lua_setglobal(L, "MENU_STAT_RESPONSE");
    lua_getglobal(L, "MENU_PACKET_STAT_UNSORTED");
    lua_setglobal(L, "MENU_STAT_UNSORTED");
    lua_getglobal(L, "MENU_TELEPHONY_UNSORTED");
    lua_setglobal(L, "MENU_STAT_TELEPHONY");
    lua_getglobal(L, "MENU_TELEPHONY_ANSI");
    lua_setglobal(L, "MENU_STAT_TELEPHONY_ANSI");
    lua_getglobal(L, "MENU_TELEPHONY_GSM");
    lua_setglobal(L, "MENU_STAT_TELEPHONY_GSM");
    lua_getglobal(L, "MENU_TELEPHONY_3GPP_UU");
    lua_setglobal(L, "MENU_STAT_TELEPHONY_3GPP_UU");
    lua_getglobal(L, "MENU_TELEPHONY_MTP3");
    lua_setglobal(L, "MENU_STAT_TELEPHONY_MTP3");
    lua_getglobal(L, "MENU_TELEPHONY_SCTP");
    lua_setglobal(L, "MENU_STAT_TELEPHONY_SCTP");

    /* deprecated function names */
    lua_getglobal(L, "Dir");
    lua_getfield(L, -1, "global_config_path");
    lua_setglobal(L, "datafile_path");
    lua_getfield(L, -1, "personal_config_path");
    lua_setglobal(L, "persconffile_path");
    lua_pop(L, 1);
}

static int wslua_console_print(lua_State *_L);

static const char *lua_error_msg(int code)
{
    switch (code) {
        case LUA_ERRSYNTAX: return "syntax error during precompilation";
        case LUA_ERRMEM:    return "memory allocation error";
#if LUA_VERSION_NUM == 502
        case LUA_ERRGCMM:   return "error while running a __gc metamethod";
#endif
        case LUA_ERRRUN:    return "runtime error";
        case LUA_ERRERR:    return "error while running the message handler";
        default:            break; /* Should not happen. */
    }
    return "unknown error";
}

static int lua_funnel_console_eval(const char *console_input,
                                        char **error_ptr,
                                        char **error_hint,
                                        void *callback_data _U_)
{
    int lcode;

    const int curr_top = lua_gettop(L);

    // If it starts with an equals sign replace it with "return"
    char *codestr;
    while (g_ascii_isspace(*console_input))
        console_input++;
    if (*console_input == '=')
        codestr = ws_strdup_printf("return %s", console_input+1);
    else
        codestr = (char *)console_input; /* Violate const safety to avoid a strdup() */

    ws_noisy("Console input: %s", codestr);
    lcode = luaL_loadstring(L, codestr);
    /* Free only if we called strdup(). */
    if (codestr != console_input)
        g_free(codestr);
    codestr = NULL;

    if (lcode != LUA_OK) {
        ws_debug("luaL_loadstring(): %s (%d)", lua_error_msg(lcode), lcode);
        if (error_hint) {
            *error_hint = g_strdup(lua_error_msg(lcode));
        }
        /* If we have an error message return it. */
        if (error_ptr && !lua_isnil(L, -1)) {
            *error_ptr = g_strdup(lua_tostring(L, -1));
        }
        return -1;
    }

    lcode = lua_pcall(L, 0, LUA_MULTRET, 0);
    if (lcode != LUA_OK) {
        ws_debug("lua_pcall(): %s (%d)", lua_error_msg(lcode), lcode);
        if (error_hint) {
            *error_hint = g_strdup(lua_error_msg(lcode));
        }
        /* If we have an error message return it. */
        if (error_ptr && !lua_isnil(L, -1)) {
            *error_ptr = g_strdup(lua_tostring(L, -1));
        }
        return 1;
    }

    // If we have values returned print them all
    if (lua_gettop(L) > curr_top) {  /* any arguments? */
        lua_pushcfunction(L, wslua_console_print);
        lua_insert(L, curr_top+1);
        lcode = lua_pcall(L, lua_gettop(L)-curr_top-1, 0, 0);
        if (lcode != LUA_OK) {
            /* Error printing result */
            if (error_hint)
                *error_hint = ws_strdup_printf("error printing return values: %s", lua_error_msg(lcode));
            return 1;
        }
    }

    // For any new Protos, register their ProtoFields and ProtoExperts with epan
    lua_pushcfunction(L, Proto_commit);
    lcode = lua_pcall(L, 0, 0, 0);
    if (lcode != LUA_OK) {
        /* Error initializing new ProtoFields */
        if (error_hint)
            *error_hint = ws_strdup_printf("error initialzing protocol fields: %s", lua_error_msg(lcode));
        /* If we have an error message return it. */
        if (error_ptr && !lua_isnil(L, -1)) {
            *error_ptr = g_strdup(lua_tostring(L, -1));
        }
        return 1;
    }

    // Maintain stack discipline
    if (lua_gettop(L) != curr_top) {
        ws_critical("Expected stack top == %d, have %d", curr_top, lua_gettop(L));
    }

    ws_noisy("Success");
    return 0;
}

/* Receives C print function pointer as first upvalue. */
/* Receives C print function data pointer as second upvalue. */
static int wslua_console_print(lua_State *_L)
{
    GString *gstr = g_string_new(NULL);
    const char *repr;

    /* Print arguments. */
    for (int i = 1; i <= lua_gettop(_L); i++) {
            repr = luaL_tolstring(_L, i, NULL);
            if (i > 1)
                g_string_append_c(gstr, '\t');
            g_string_append(gstr, repr);
            lua_pop(_L, 1);
    }
    g_string_append_c(gstr, '\n');

    if (wslua_gui_print_func_ptr == NULL) {
        ws_critical("GUI print function not registered; Trying to print: %s", gstr->str);
    }
    else {
        wslua_gui_print_func_ptr(gstr->str, wslua_gui_print_data_ptr);
    }
    g_string_free(gstr, TRUE);
    return 0;
}

// Replace lua print function with a custom print function.
// We will place the original function in the Lua registry and return the reference.
static void lua_funnel_console_open(void (*print_func_ptr)(const char *, void *),
                                        void *print_data_ptr,
                                        void *callback_data _U_)
{
    /* Store original print value in the registry (even if it is nil). */
    lua_getglobal(L, "print");
    wslua_lua_print_func_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    /* Set new "print" function (to output to the GUI) */
    lua_pushcfunction(L, wslua_console_print);
    lua_setglobal(L, "print");

    /* Save the globals */
    ws_assert(print_func_ptr);
    wslua_gui_print_func_ptr = print_func_ptr;
    wslua_gui_print_data_ptr = print_data_ptr;
}

// Restore original Lua print function. Clean state.
static void lua_funnel_console_close(void *callback_data _U_)
{
    /* Restore the original print function. */
    int ref = (int)wslua_lua_print_func_ref;
    /* push original function into stack */
    lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
    lua_setglobal(L, "print");
    /* Release reference */
    luaL_unref(L, LUA_REGISTRYINDEX, ref);

    /* Clear the globals. */
    wslua_gui_print_func_ptr = NULL;
    wslua_gui_print_data_ptr = NULL;
    wslua_lua_print_func_ref = LUA_NOREF;
}

static int wslua_file_exists(lua_State *_L)
{
    const char *path = luaL_checkstring(_L, 1);
    lua_pushboolean(_L, g_file_test(path, G_FILE_TEST_EXISTS));
    return 1;
}

static int wslua_lua_typeof(lua_State *_L)
{
    const char *classname = wslua_typeof(_L, 1);
    lua_pushstring(_L, classname);
    return 1;
}

/* Other useful constants */
void wslua_add_useful_constants(void)
{
    const funnel_ops_t *ops = funnel_get_funnel_ops();
    char *path;

    WSLUA_REG_GLOBAL_BOOL(L,"GUI_ENABLED",ops && ops->new_dialog);

    /* DATA_DIR has a trailing directory separator. */
    path = get_datafile_path("");
    lua_pushfstring(L, "%s"G_DIR_SEPARATOR_S, path);
    g_free(path);
    lua_setglobal(L, "DATA_DIR");

    /* USER_DIR has a trailing directory separator. */
    path = get_persconffile_path("", false);
    lua_pushfstring(L, "%s"G_DIR_SEPARATOR_S, path);
    g_free(path);
    lua_setglobal(L, "USER_DIR");

    lua_pushcfunction(L, wslua_file_exists);
    lua_setglobal(L, "file_exists");

    lua_pushcfunction(L, wslua_lua_typeof);
    lua_setglobal(L, "typeof");
}

void wslua_init(register_cb cb, void *client_data) {
    char* filename;
    bool enable_lua = true;
    bool run_anyway = false;
    expert_module_t* expert_lua;
    int file_count = 1;
    static bool first_time = true;
    int i;
    int error;

    static hf_register_info hf[] = {
        { &hf_wslua_fake,
          { "Wireshark Lua fake item",     "_ws.lua.fake",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Fake internal item for Wireshark Lua", HFILL }},
        { &hf_wslua_text,
          { "Wireshark Lua text",     "_ws.lua.text",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };
    static int *ett[] = {
            &ett_wslua_traceback,
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

        { &ei_lua_proto_decryption_comment, { "_ws.lua.proto.comment", PI_DECRYPTION, PI_COMMENT ,"Protocol Comment", EXPFILL }},
        { &ei_lua_proto_decryption_chat,    { "_ws.lua.proto.chat",    PI_DECRYPTION, PI_CHAT    ,"Protocol Chat",    EXPFILL }},
        { &ei_lua_proto_decryption_note,    { "_ws.lua.proto.note",    PI_DECRYPTION, PI_NOTE    ,"Protocol Note",    EXPFILL }},
        { &ei_lua_proto_decryption_warn,    { "_ws.lua.proto.warning", PI_DECRYPTION, PI_WARN    ,"Protocol Warning", EXPFILL }},
        { &ei_lua_proto_decryption_error,   { "_ws.lua.proto.error",   PI_DECRYPTION, PI_ERROR   ,"Protocol Error",   EXPFILL }},

        { &ei_lua_proto_assumption_comment, { "_ws.lua.proto.comment", PI_ASSUMPTION, PI_COMMENT ,"Protocol Comment", EXPFILL }},
        { &ei_lua_proto_assumption_chat,    { "_ws.lua.proto.chat",    PI_ASSUMPTION, PI_CHAT    ,"Protocol Chat",    EXPFILL }},
        { &ei_lua_proto_assumption_note,    { "_ws.lua.proto.note",    PI_ASSUMPTION, PI_NOTE    ,"Protocol Note",    EXPFILL }},
        { &ei_lua_proto_assumption_warn,    { "_ws.lua.proto.warning", PI_ASSUMPTION, PI_WARN    ,"Protocol Warning", EXPFILL }},
        { &ei_lua_proto_assumption_error,   { "_ws.lua.proto.error",   PI_ASSUMPTION, PI_ERROR   ,"Protocol Error",   EXPFILL }},

        { &ei_lua_proto_deprecated_comment, { "_ws.lua.proto.comment", PI_DEPRECATED, PI_COMMENT ,"Protocol Comment", EXPFILL }},
        { &ei_lua_proto_deprecated_chat,    { "_ws.lua.proto.chat",    PI_DEPRECATED, PI_CHAT    ,"Protocol Chat",    EXPFILL }},
        { &ei_lua_proto_deprecated_note,    { "_ws.lua.proto.note",    PI_DEPRECATED, PI_NOTE    ,"Protocol Note",    EXPFILL }},
        { &ei_lua_proto_deprecated_warn,    { "_ws.lua.proto.warning", PI_DEPRECATED, PI_WARN    ,"Protocol Warning", EXPFILL }},
        { &ei_lua_proto_deprecated_error,   { "_ws.lua.proto.error",   PI_DEPRECATED, PI_ERROR   ,"Protocol Error",   EXPFILL }},

        { &ei_lua_proto_receive_comment,    { "_ws.lua.proto.comment", PI_RECEIVE, PI_COMMENT    ,"Protocol Comment", EXPFILL }},
        { &ei_lua_proto_receive_chat,       { "_ws.lua.proto.chat",    PI_RECEIVE, PI_CHAT       ,"Protocol Chat",    EXPFILL }},
        { &ei_lua_proto_receive_note,       { "_ws.lua.proto.note",    PI_RECEIVE, PI_NOTE       ,"Protocol Note",    EXPFILL }},
        { &ei_lua_proto_receive_warn,       { "_ws.lua.proto.warning", PI_RECEIVE, PI_WARN       ,"Protocol Warning", EXPFILL }},
        { &ei_lua_proto_receive_error,      { "_ws.lua.proto.error",   PI_RECEIVE, PI_ERROR      ,"Protocol Error",   EXPFILL }},

        { &ei_lua_proto_interface_comment,  { "_ws.lua.proto.comment", PI_INTERFACE, PI_COMMENT  ,"Protocol Comment", EXPFILL }},
        { &ei_lua_proto_interface_chat,     { "_ws.lua.proto.chat",    PI_INTERFACE, PI_CHAT     ,"Protocol Chat",    EXPFILL }},
        { &ei_lua_proto_interface_note,     { "_ws.lua.proto.note",    PI_INTERFACE, PI_NOTE     ,"Protocol Note",    EXPFILL }},
        { &ei_lua_proto_interface_warn,     { "_ws.lua.proto.warning", PI_INTERFACE, PI_WARN     ,"Protocol Warning", EXPFILL }},
        { &ei_lua_proto_interface_error,    { "_ws.lua.proto.error",   PI_INTERFACE, PI_ERROR    ,"Protocol Error",   EXPFILL }},

        /* this one is for reporting errors executing Lua code */
        { &ei_lua_error, { "_ws.lua.error", PI_UNDECODED, PI_ERROR ,"Lua Error", EXPFILL }},
    };

    if (first_time) {
        ws_lua_ei = ei;
        ws_lua_ei_len = array_length(ei);
    }

    if (!L) {
        L = lua_newstate(wslua_allocf, NULL);
    }

    WSLUA_INIT(L);

    if (first_time) {
        proto_lua = proto_register_protocol("Lua Dissection", "Lua Dissection", "_ws.lua");
        proto_register_field_array(proto_lua, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
        expert_lua = expert_register_protocol(proto_lua);
        expert_register_field_array(expert_lua, ei, array_length(ei));
    }

    lua_atpanic(L,wslua_panic);

    /*
     * The init_routines table (accessible by the user).
     *
     * For a table a, a.init is syntactic sugar for a["init"], and
     *
     *    function t.a.b.c.f () body end
     *
     * is syntactic sugar for
     *
     *    t.a.b.c.f = function () body end
     *
     * so
     *
     *    function proto.init () body end
     *
     * means
     *
     *    proto["init"] = function () body end
     *
     * and the Proto class has an "init" method, with Proto_set_init()
     * being the setter for that method; that routine adds the Lua
     * function passed to it as a Lua argument to the WSLUA_INIT_ROUTINES
     * table - i.e., "init_routines".
     */
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
    WSLUA_REG_GLOBAL_INTEGER(L,"DESEGMENT_ONE_MORE_SEGMENT",DESEGMENT_ONE_MORE_SEGMENT);

    /* the possible values for Pinfo's p2p_dir attribute */
    WSLUA_REG_GLOBAL_INTEGER(L,"P2P_DIR_UNKNOWN",-1);
    WSLUA_REG_GLOBAL_INTEGER(L,"P2P_DIR_SENT",0);
    WSLUA_REG_GLOBAL_INTEGER(L,"P2P_DIR_RECV",1);

    wslua_add_introspection();

    wslua_add_useful_constants();

    wslua_add_deprecated();

    // Register Lua's console menu (in the GUI)
    if (first_time) {
        funnel_register_console_menu("Lua",
                                        lua_funnel_console_eval,
                                        lua_funnel_console_open,
                                        lua_funnel_console_close,
                                        NULL, NULL);
    }
    else if (wslua_gui_print_func_ptr) {
        // If we we have an open GUI console dialog re-register the global "print to console" function
        lua_funnel_console_open(wslua_gui_print_func_ptr, wslua_gui_print_data_ptr, NULL);
    }

    /* load system's init.lua */
    filename = g_build_filename(get_plugins_dir(), "init.lua", (char *)NULL);
    if (file_exists(filename)) {
        ws_debug("Loading init.lua file: %s", filename);
        lua_load_internal_script(filename);
    }
    g_free(filename);

    /* load user's init.lua */
    /* if we are indeed superuser run user scripts only if told to do so */
    if (!started_with_special_privs() || run_anyway) {
        filename = g_build_filename(get_plugins_pers_dir(), "init.lua", (char *)NULL);
        if (file_exists(filename)) {
            ws_debug("Loading init.lua file: %s", filename);
            lua_load_internal_script(filename);
        }
        g_free(filename);

        /* For backward compatibility also load it from the configuration directory. */
        filename = get_persconffile_path("init.lua", false);
        if (file_exists(filename)) {
            ws_message("Loading init.lua file from deprecated path: %s", filename);
            lua_load_internal_script(filename);
        }
        g_free(filename);
    }

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
        first_time = false;
        return;
    }

    /* load global scripts */
    lua_load_global_plugins(cb, client_data, false);

    /* check whether we should run other scripts even if running superuser */
    lua_getglobal(L,"run_user_scripts_when_superuser");

    if (lua_isboolean(L,-1) && lua_toboolean(L,-1)) {
        run_anyway = true;
    }
    lua_pop(L,1);  /* pop the getglobal result */

    /* if we are indeed superuser run user scripts only if told to do so */
    if (!started_with_special_privs() || run_anyway) {

        /* load user scripts */
        lua_load_pers_plugins(cb, client_data, false);

        /* load scripts from command line */
        for (i = 0; i < ex_opt_count("lua_script"); i++) {
            const char *script_filename = ex_opt_get_nth("lua_script", i);
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

    /* Unfortunately, by waiting to register the hfi and ei now, Lua
     * can't figure out which file had the error and provide a traceback,
     * so no special error handler.
     */
    lua_pushcfunction(L, Proto_commit);
    error = lua_pcall(L, 0, 0, 0);
    if (error) {
        switch (error) {
            case LUA_ERRRUN:
                report_failure("Lua: Error initializing protocols:\n%s", lua_tostring(L, -1));
                break;
            case LUA_ERRMEM:
                report_failure("Lua: Error initializing protocols: out of memory");
                break;
            case LUA_ERRERR:
                report_failure("Lua: Error initializing protocols: error while retrieving error message");
                break;
            default:
                report_failure("Lua: Error initializing protocols: unknown error %d", error);
                break;
        }
    }

    first_time = false;
}

void wslua_early_cleanup(void) {
    wslua_deregister_protocols(L);
}

void wslua_reload_plugins (register_cb cb, void *client_data) {
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
    init_routine_initialized = false;
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
