/*
 *  wslua_gui.c
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

#include <epan/wmem_scopes.h>

#include "wslua.h"

/* WSLUA_MODULE Gui GUI Support */

static const funnel_ops_t* ops = NULL;

struct _lua_menu_data {
    lua_State* L;
    int cb_ref;
};

static int menu_cb_error_handler(lua_State* L) {
    const gchar* error =  lua_tostring(L,1);
    report_failure("Lua: Error during execution of Menu callback:\n %s",error);
    return 0;
}

WSLUA_FUNCTION wslua_gui_enabled(lua_State* L) { /* Checks if we're running inside a GUI (i.e. Wireshark) or not. */
    lua_pushboolean(L,GPOINTER_TO_INT(ops && ops->add_button));
    WSLUA_RETURN(1); /* Boolean `true` if a GUI is available, `false` if it isn't. */
}

static void lua_menu_callback(gpointer data) {
    struct _lua_menu_data* md = (struct _lua_menu_data *)data;
    lua_State* L = md->L;

    lua_settop(L,0);
    lua_pushcfunction(L,menu_cb_error_handler);
    lua_rawgeti(L, LUA_REGISTRYINDEX, md->cb_ref);

    switch ( lua_pcall(L,0,0,1) ) {
        case 0:
            break;
        case LUA_ERRRUN:
            ws_warning("Runtime error while calling menu callback");
            break;
        case LUA_ERRMEM:
            ws_warning("Memory alloc error while calling menu callback");
            break;
        case LUA_ERRERR:
            ws_warning("Error while running the error handler function for menu callback");
            break;
        default:
            ws_assert_not_reached();
            break;
    }

    return;
}

WSLUA_FUNCTION wslua_register_menu(lua_State* L) { /*  Register a menu item in one of the main menus. Requires a GUI. */
#define WSLUA_ARG_register_menu_NAME 1 /* The name of the menu item. Use slashes to separate submenus. (e.g. menu:Lua Scripts[My Fancy Statistics]). (string) */
#define WSLUA_ARG_register_menu_ACTION 2 /* The function to be called when the menu item is invoked. The function must take no arguments and return nothing. */
#define WSLUA_OPTARG_register_menu_GROUP 3 /*
    Where to place the item in the menu hierarchy.
    If omitted, defaults to MENU_STAT_GENERIC.
    Valid packet (Wireshark) items are:
    * MENU_PACKET_ANALYZE_UNSORTED: menu:Analyze[]
    * MENU_PACKET_STAT_UNSORTED: menu:Statistics[]
    * MENU_STAT_GENERIC: menu:Statistics[], first section
    * MENU_STAT_CONVERSATION_LIST: menu:Statistics[Conversation List]
    * MENU_STAT_ENDPOINT_LIST: menu:Statistics[Endpoint List]
    * MENU_STAT_RESPONSE_TIME: menu:Statistics[Service Response Time]
    * MENU_STAT_RSERPOOL = menu:Statistics[Reliable Server Pooling (RSerPool)]
    * MENU_STAT_TELEPHONY: menu:Telephony[]
    * MENU_STAT_TELEPHONY_ANSI: menu:Telephony[ANSI]
    * MENU_STAT_TELEPHONY_GSM: menu:Telephony[GSM]
    * MENU_STAT_TELEPHONY_LTE: menu:Telephony[LTE]
    * MENU_STAT_TELEPHONY_MTP3: menu:Telephony[MTP3]
    * MENU_STAT_TELEPHONY_SCTP: menu:Telephony[SCTP]
    * MENU_ANALYZE: menu:Analyze[]
    * MENU_ANALYZE_CONVERSATION: menu:Analyze[Conversation Filter]
    * MENU_TOOLS_UNSORTED: menu:Tools[]

    Valid log (Logwolf) items are:
    * MENU_LOG_ANALYZE_UNSORTED: menu:Analyze[]
    * MENU_LOG_STAT_UNSORTED = 16

    The following are deprecated and shouldn't be used in new code:
    * MENU_ANALYZE_UNSORTED, superseded by MENU_PACKET_ANALYZE_UNSORTED
    * MENU_ANALYZE_CONVERSATION, superseded by MENU_ANALYZE_CONVERSATION_FILTER
    * MENU_STAT_CONVERSATION, superseded by MENU_STAT_CONVERSATION_LIST
    * MENU_STAT_ENDPOINT, superseded by MENU_STAT_ENDPOINT_LIST
    * MENU_STAT_RESPONSE, superseded by MENU_STAT_RESPONSE_TIME
    * MENU_STAT_UNSORTED, superseded by MENU_PACKET_STAT_UNSORTED
 */

    const gchar* name = luaL_checkstring(L,WSLUA_ARG_register_menu_NAME);
    struct _lua_menu_data* md;
    gboolean retap = FALSE;
    register_stat_group_t group = (register_stat_group_t)wslua_optguint(L,WSLUA_OPTARG_register_menu_GROUP,REGISTER_STAT_GROUP_GENERIC);

    if ( group > REGISTER_TOOLS_GROUP_UNSORTED) {
        WSLUA_OPTARG_ERROR(register_menu,GROUP,"Must be a defined MENU_* (see init.lua)");
        return 0;
    }

    if (!lua_isfunction(L,WSLUA_ARG_register_menu_ACTION)) {
        WSLUA_ARG_ERROR(register_menu,ACTION,"Must be a function");
        return 0;
    }

    md = g_new(struct _lua_menu_data, 1);
    md->L = L;

    lua_pushvalue(L, 2);
    md->cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_remove(L,2);

    funnel_register_menu(name,
                         group,
                         lua_menu_callback,
                         md,
                         g_free,
                         retap);

    WSLUA_RETURN(0);
}

void wslua_deregister_menus(void) {
    funnel_deregister_menus(lua_menu_callback);
}

struct _dlg_cb_data {
    lua_State* L;
    int func_ref;
};

static int dlg_cb_error_handler(lua_State* L) {
    const gchar* error =  lua_tostring(L,1);
    report_failure("Lua: Error during execution of Dialog callback:\n %s",error);
    return 0;
}

static void lua_dialog_cb(gchar** user_input, void* data) {
    struct _dlg_cb_data* dcbd = (struct _dlg_cb_data *)data;
    int i = 0;
    gchar* input;
    lua_State* L = dcbd->L;

    lua_settop(L,0);
    lua_pushcfunction(L,dlg_cb_error_handler);
    lua_rawgeti(L, LUA_REGISTRYINDEX, dcbd->func_ref);

    for (i = 0; (input = user_input[i]) ; i++) {
        lua_pushstring(L,input);
        g_free(input);
    }

    g_free(user_input);

    switch ( lua_pcall(L,i,0,1) ) {
        case 0:
            break;
        case LUA_ERRRUN:
            ws_warning("Runtime error while calling dialog callback");
            break;
        case LUA_ERRMEM:
            ws_warning("Memory alloc error while calling dialog callback");
            break;
        case LUA_ERRERR:
            ws_warning("Error while running the error handler function for dialog callback");
            break;
        default:
            ws_assert_not_reached();
            break;
    }

}

struct _close_cb_data {
    lua_State* L;
    int func_ref;
    TextWindow wslua_tw;
};


static int text_win_close_cb_error_handler(lua_State* L) {
    const gchar* error =  lua_tostring(L,1);
    report_failure("Lua: Error during execution of TextWindow close callback:\n %s",error);
    return 0;
}

static void text_win_close_cb(void* data) {
    struct _close_cb_data* cbd = (struct _close_cb_data *)data;
    lua_State* L = cbd->L;

    if (cbd->L) { /* close function is set */

        lua_settop(L,0);
        lua_pushcfunction(L,text_win_close_cb_error_handler);
        lua_rawgeti(L, LUA_REGISTRYINDEX, cbd->func_ref);

        switch ( lua_pcall(L,0,0,1) ) {
            case 0:
                break;
            case LUA_ERRRUN:
                ws_warning("Runtime error during execution of TextWindow close callback");
                break;
            case LUA_ERRMEM:
                ws_warning("Memory alloc error during execution of TextWindow close callback");
                break;
            case LUA_ERRERR:
                ws_warning("Error while running the error handler function for TextWindow close callback");
                break;
            default:
                break;
        }
    }

    if (cbd->wslua_tw->expired) {
        g_free(cbd->wslua_tw);
        g_free(cbd);
    } else {
        cbd->wslua_tw->expired = TRUE;
    }

}

WSLUA_FUNCTION wslua_new_dialog(lua_State* L) { /*
    Displays a dialog, prompting for input. The dialog includes an btn:[OK] button and btn:[Cancel] button. Requires a GUI.

    .An input dialog in action
    image::wsdg_graphics/wslua-new-dialog.png[{small-screenshot-attrs}]

    ===== Example

    [source,lua]
    ----
    if not gui_enabled() then return end

    -- Prompt for IP and port and then print them to stdout
    local label_ip = "IP address"
    local label_port = "Port"
    local function print_ip(ip, port)
            print(label_ip, ip)
            print(label_port, port)
    end
    new_dialog("Enter IP address", print_ip, label_ip, label_port)

    -- Prompt for 4 numbers and then print their product to stdout
    new_dialog(
            "Enter 4 numbers",
            function (a, b, c, d) print(a * b * c * d) end,
            "a", "b", "c", "d"
            )
    ----
    */
#define WSLUA_ARG_new_dialog_TITLE 1 /* The title of the dialog. */
#define WSLUA_ARG_new_dialog_ACTION 2 /* Action to be performed when the user presses btn:[OK]. */
/* WSLUA_MOREARGS new_dialog Strings to be used a labels of the dialog's fields. Each string creates a new labeled field. The first field is required.
Instead of a strings it is possible to provide tables with fields 'name' and 'value' of type string. Then the created dialog's field will labeld with the content of name and prefilled with the content of value.*/

    const gchar* title;
    int top = lua_gettop(L);
    int i;
    GPtrArray* field_names;
    GPtrArray* field_values;
    struct _dlg_cb_data* dcbd;

    if (! ops) {
        luaL_error(L,"the GUI facility has to be enabled");
        return 0;
    }

    if (!ops->new_dialog) {
        WSLUA_ERROR(new_dialog,"GUI not available");
        return 0;
    }

    title = luaL_checkstring(L,WSLUA_ARG_new_dialog_TITLE);

    if (! lua_isfunction(L,WSLUA_ARG_new_dialog_ACTION)) {
        WSLUA_ARG_ERROR(new_dialog,ACTION,"Must be a function");
        return 0;
    }

    if (top < 3) {
        WSLUA_ERROR(new_dialog,"At least one field required");
        return 0;
    }


    dcbd = g_new(struct _dlg_cb_data, 1);
    dcbd->L = L;

    lua_remove(L,1);

    lua_pushvalue(L, 1);
    dcbd->func_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_remove(L,1);

    field_names = g_ptr_array_new_with_free_func(g_free);
    field_values = g_ptr_array_new_with_free_func(g_free);

    top -= 2;

    for (i = 1; i <= top; i++)
    {
        if (lua_isstring(L, i))
        {
            gchar* field_name = g_strdup(luaL_checkstring(L, i));
            gchar* field_value = g_strdup("");
            g_ptr_array_add(field_names, (gpointer)field_name);
            g_ptr_array_add(field_values, (gpointer)field_value);
        }
        else if (lua_istable(L, i))
        {
            lua_getfield(L, i, "name");
            lua_getfield(L, i, "value");

            if (!lua_isstring(L, -2))
            {
                lua_pop(L, 2);

                g_ptr_array_free(field_names, TRUE);
                g_ptr_array_free(field_values, TRUE);
                g_free(dcbd);
                WSLUA_ERROR(new_dialog, "All fields must be strings or a table with a string field 'name'.");
                return 0;
            }

            gchar* field_name = g_strdup(luaL_checkstring(L, -2));
            gchar* field_value = lua_isstring(L, -1) ?
                g_strdup(luaL_checkstring(L, -1)) :
                g_strdup("");

            g_ptr_array_add(field_names, (gpointer)field_name);
            g_ptr_array_add(field_values, (gpointer)field_value);

            lua_pop(L, 2);
        }
        else
        {
            g_ptr_array_free(field_names, TRUE);
            g_ptr_array_free(field_values, TRUE);
            g_free(dcbd);
            WSLUA_ERROR(new_dialog, "All fields must be strings or a table with a string field 'name'.");
            return 0;
        }
    }

    g_ptr_array_add(field_names, NULL);
    g_ptr_array_add(field_values, NULL);

    ops->new_dialog(ops->ops_id, title, (const gchar**)(field_names->pdata), (const gchar**)(field_values->pdata), lua_dialog_cb, dcbd, g_free);

    g_ptr_array_free(field_names, TRUE);
    g_ptr_array_free(field_values, TRUE);

    WSLUA_RETURN(0);
}

WSLUA_CLASS_DEFINE(ProgDlg,FAIL_ON_NULL("ProgDlg"));
/*
    Creates and manages a modal progress bar.
    This is intended to be used with
    http://lua-users.org/wiki/CoroutinesTutorial[coroutines],
    where a main UI thread controls the progress bar dialog while a background coroutine (worker thread) yields to the main thread between steps.
    The main thread checks the status of the btn:[Cancel] button and if it's not set, returns control to the coroutine.

    .A progress bar in action
    image::wsdg_graphics/wslua-progdlg.png[{medium-screenshot-attrs}]

    The legacy (GTK+) user interface displayed this as a separate dialog, hence the “Dlg” suffix.
    The Qt user interface shows a progress bar inside the main status bar.
*/

WSLUA_CONSTRUCTOR ProgDlg_new(lua_State* L) { /*
    Creates and displays a new `ProgDlg` progress bar with a btn:[Cancel] button and optional title.
    It is highly recommended that you wrap code that uses a `ProgDlg` instance because it does not automatically close itself upon encountering an error.
    Requires a GUI.

    ===== Example

    [source,lua]
    ----
    if not gui_enabled() then return end

    local p = ProgDlg.new("Constructing", "tacos")

    -- We have to wrap the ProgDlg code in a pcall in case some unexpected
    -- error occurs.
    local ok, errmsg = pcall(function()
            local co = coroutine.create(
                    function()
                            local limit = 100000
                            for i=1,limit do
                                    print("co", i)
                                    coroutine.yield(i/limit, "step "..i.." of "..limit)
                            end
                    end
            )

            -- Whenever coroutine yields, check the status of the cancel button to determine
            -- when to break. Wait up to 20 sec for coroutine to finish.
            local start_time = os.time()
            while coroutine.status(co) ~= 'dead' do
                    local elapsed = os.time() - start_time

                    -- Quit if cancel button pressed or 20 seconds elapsed
                    if p:stopped() or elapsed > 20 then
                            break
                    end

                    local res, val, val2 = coroutine.resume(co)
                    if not res or res == false then
                            if val then
                                    debug(val)
                            end
                            print('coroutine error')
                            break
                    end

                    -- show progress in progress dialog
                    p:update(val, val2)
            end
    end)

    p:close()

    if not ok and errmsg then
            report_failure(errmsg)
    end
    ----
*/
#define WSLUA_OPTARG_ProgDlg_new_TITLE 1 /* Title of the progress bar. Defaults to "Progress". */
#define WSLUA_OPTARG_ProgDlg_new_TASK 2  /* Optional task name, which will be appended to the title. Defaults to the empty string (""). */
    ProgDlg pd = (ProgDlg)g_malloc(sizeof(struct _wslua_progdlg));
    pd->title = g_strdup(luaL_optstring(L,WSLUA_OPTARG_ProgDlg_new_TITLE,"Progress"));
    pd->task = g_strdup(luaL_optstring(L,WSLUA_OPTARG_ProgDlg_new_TASK,""));
    pd->stopped = FALSE;

    if (ops->new_progress_window) {
        pd->pw = ops->new_progress_window(ops->ops_id, pd->title, pd->task, TRUE, &(pd->stopped));
    } else {
        g_free (pd);
        WSLUA_ERROR(ProgDlg_new, "GUI not available");
        return 0;
    }

    pushProgDlg(L,pd);

    WSLUA_RETURN(1); /* The newly created `ProgDlg` object. */
}

WSLUA_METHOD ProgDlg_update(lua_State* L) { /* Sets the progress dialog's progress bar position based on percentage done. */
#define WSLUA_ARG_ProgDlg_update_PROGRESS 2  /* Progress value, e.g. 0.75. Value must be between 0.0 and 1.0 inclusive. */
#define WSLUA_OPTARG_ProgDlg_update_TASK 3  /* Task name. Currently ignored. Defaults to empty string (""). */
    ProgDlg pd = checkProgDlg(L,1);
    double pr = lua_tonumber(L,WSLUA_ARG_ProgDlg_update_PROGRESS);
    const gchar* task = luaL_optstring(L,WSLUA_OPTARG_ProgDlg_update_TASK,"");

    if (!ops->update_progress) {
        WSLUA_ERROR(ProgDlg_update,"GUI not available");
        return 0;
    }

    g_free(pd->task);
    pd->task = g_strdup(task);

    /* XXX, dead code: pd already dereferenced. should it be: !pd->task?
    if (!pd) {
        WSLUA_ERROR(ProgDlg_update,"Cannot be called for something not a ProgDlg");
    } */

    if (pr >= 0.0 && pr <= 1.0) {
        ops->update_progress(pd->pw, (float) pr, task);
    } else {
        WSLUA_ERROR(ProgDlg_update,"Progress value out of range (must be between 0.0 and 1.0)");
        return 0;
    }

    return 0;
}

WSLUA_METHOD ProgDlg_stopped(lua_State* L) { /* Checks whether the user has pressed the btn:[Cancel] button. */
    ProgDlg pd = checkProgDlg(L,1);

    lua_pushboolean(L,pd->stopped);

    WSLUA_RETURN(1); /* Boolean `true` if the user has asked to stop the operation, `false` otherwise. */
}



WSLUA_METHOD ProgDlg_close(lua_State* L) { /* Hides the progress bar. */
    ProgDlg pd = checkProgDlg(L,1);

    if (!ops->destroy_progress_window) {
        WSLUA_ERROR(ProgDlg_close,"GUI not available");
        return 0;
    }

    if (pd->pw) {
        ops->destroy_progress_window(pd->pw);
        pd->pw = NULL;
    }
    return 0;
}


static int ProgDlg__tostring(lua_State* L) {
    ProgDlg pd = checkProgDlg(L,1);

    lua_pushfstring(L, "%sstopped",pd->stopped?"":"not ");

    WSLUA_RETURN(1); /* A string specifying whether the Progress Dialog has stopped or not. */
}

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int ProgDlg__gc(lua_State* L) {
    ProgDlg pd = toProgDlg(L,1);

    if (pd) {
        if (pd->pw && ops->destroy_progress_window) {
            ops->destroy_progress_window(pd->pw);
        }

        g_free(pd);
    } else {
        luaL_error(L, "ProgDlg__gc has being passed something else!");
    }

    return 0;
}


WSLUA_METHODS ProgDlg_methods[] = {
    WSLUA_CLASS_FNREG(ProgDlg,new),
    WSLUA_CLASS_FNREG(ProgDlg,update),
    WSLUA_CLASS_FNREG(ProgDlg,stopped),
    WSLUA_CLASS_FNREG(ProgDlg,close),
    { NULL, NULL }
};

WSLUA_META ProgDlg_meta[] = {
    WSLUA_CLASS_MTREG(ProgDlg,tostring),
    { NULL, NULL }
};

int ProgDlg_register(lua_State* L) {

    ops = funnel_get_funnel_ops();

    WSLUA_REGISTER_CLASS(ProgDlg);

    return 0;
}



WSLUA_CLASS_DEFINE(TextWindow,FAIL_ON_NULL_OR_EXPIRED("TextWindow")); /*

    Creates and manages a text window.
    The text can be read-only or editable, and buttons can be added below the text.

    .A text window in action
    image::wsdg_graphics/wslua-textwindow.png[{medium-screenshot-attrs}]
*/

/* XXX: button and close callback data is being leaked */
/* XXX: lua callback function and TextWindow are not garbage collected because
   they stay in LUA_REGISTRYINDEX forever */

WSLUA_CONSTRUCTOR TextWindow_new(lua_State* L) { /*
    Creates a new `TextWindow` text window and displays it.
    Requires a GUI.

    ===== Example

    [source,lua]
    ----
    if not gui_enabled() then return end

    -- create new text window and initialize its text
    local win = TextWindow.new("Log")
    win:set("Hello world!")

    -- add buttons to clear text window and to enable editing
    win:add_button("Clear", function() win:clear() end)
    win:add_button("Enable edit", function() win:set_editable(true) end)

    -- add button to change text to uppercase
    win:add_button("Uppercase", function()
            local text = win:get_text()
            if text ~= "" then
                    win:set(string.upper(text))
            end
    end)

    -- print "closing" to stdout when the user closes the text windw
    win:set_atclose(function() print("closing") end)
    ----

*/
#define WSLUA_OPTARG_TextWindow_new_TITLE 1 /* Title of the new window. Optional. Defaults to "Untitled Window". */

    const gchar* title;
    TextWindow tw = NULL;
    struct _close_cb_data* default_cbd;

    if (!ops->new_text_window || !ops->set_close_cb) {
        WSLUA_ERROR(TextWindow_new,"GUI not available");
        return 0;
    }

    title = luaL_optstring(L,WSLUA_OPTARG_TextWindow_new_TITLE, "Untitled Window");
    tw = g_new(struct _wslua_tw, 1);
    tw->expired = FALSE;
    tw->ws_tw = ops->new_text_window(ops->ops_id, title);

    default_cbd = g_new(struct _close_cb_data, 1);

    default_cbd->L = NULL;
    default_cbd->func_ref = 0;
    default_cbd->wslua_tw = tw;

    tw->close_cb_data = (void *)default_cbd;

    ops->set_close_cb(tw->ws_tw,text_win_close_cb,default_cbd);

    pushTextWindow(L,tw);

    WSLUA_RETURN(1); /* The newly created `TextWindow` object. */
}

WSLUA_METHOD TextWindow_set_atclose(lua_State* L) { /* Set the function that will be called when the text window closes. */
#define WSLUA_ARG_TextWindow_at_close_ACTION 2 /* A Lua function to be executed when the user closes the text window. */

    TextWindow tw = checkTextWindow(L,1);
    struct _close_cb_data* cbd;

    if (!ops->set_close_cb) {
        WSLUA_ERROR(TextWindow_set_atclose,"GUI not available");
        return 0;
    }

    lua_settop(L,2);

    if (! lua_isfunction(L,2)) {
        WSLUA_ARG_ERROR(TextWindow_at_close,ACTION,"Must be a function");
        return 0;
    }

    cbd = g_new(struct _close_cb_data, 1);

    cbd->L = L;
    cbd->func_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    cbd->wslua_tw = tw;

    g_free(tw->close_cb_data);
    tw->close_cb_data = (void *)cbd;

    ops->set_close_cb(tw->ws_tw,text_win_close_cb,cbd);

    /* XXX: this is a bad way to do this - should copy the object on to the stack first */
    WSLUA_RETURN(1); /* The `TextWindow` object. */
}

WSLUA_METHOD TextWindow_set(lua_State* L) { /* Sets the text to be displayed. */
#define WSLUA_ARG_TextWindow_set_TEXT 2 /* The text to be displayed. */

    TextWindow tw = checkTextWindow(L,1);
    const gchar* text = luaL_checkstring(L,WSLUA_ARG_TextWindow_set_TEXT);

    if (!ops->set_text) {
        WSLUA_ERROR(TextWindow_set,"GUI not available");
        return 0;
    }

    ops->set_text(tw->ws_tw,text);

    /* XXX: this is a bad way to do this - should copy the object on to the stack first */
    WSLUA_RETURN(1); /* The `TextWindow` object. */
}

WSLUA_METHOD TextWindow_append(lua_State* L) { /* Appends text to the current window contents. */
#define WSLUA_ARG_TextWindow_append_TEXT 2 /* The text to be appended. */
    TextWindow tw = checkTextWindow(L,1);
    const gchar* text = luaL_checkstring(L,WSLUA_ARG_TextWindow_append_TEXT);

    if (!ops->append_text) {
        WSLUA_ERROR(TextWindow_append,"GUI not available");
        return 0;
    }

    ops->append_text(tw->ws_tw,text);

    /* XXX: this is a bad way to do this - should copy the object on to the stack first */
    WSLUA_RETURN(1); /* The `TextWindow` object. */
}

WSLUA_METHOD TextWindow_prepend(lua_State* L) { /* Prepends text to the current window contents. */
#define WSLUA_ARG_TextWindow_prepend_TEXT 2 /* The text to be prepended. */
    TextWindow tw = checkTextWindow(L,1);
    const gchar* text = luaL_checkstring(L,WSLUA_ARG_TextWindow_prepend_TEXT);

    if (!ops->prepend_text) {
        WSLUA_ERROR(TextWindow_prepend,"GUI not available");
        return 0;
    }

    ops->prepend_text(tw->ws_tw,text);

    /* XXX: this is a bad way to do this - should copy the object on to the stack first */
    WSLUA_RETURN(1); /* The `TextWindow` object. */
}

WSLUA_METHOD TextWindow_clear(lua_State* L) { /* Erases all of the text in the window. */
    TextWindow tw = checkTextWindow(L,1);

    if (!ops->clear_text) {
        WSLUA_ERROR(TextWindow_clear,"GUI not available");
        return 0;
    }

    ops->clear_text(tw->ws_tw);

    /* XXX: this is a bad way to do this - should copy the object on to the stack first */
    WSLUA_RETURN(1); /* The `TextWindow` object. */
}

WSLUA_METHOD TextWindow_get_text(lua_State* L) { /* Get the text of the window. */
    TextWindow tw = checkTextWindow(L,1);
    const gchar* text;

    if (!ops->get_text) {
        WSLUA_ERROR(TextWindow_get_text,"GUI not available");
        return 0;
    }

    text = ops->get_text(tw->ws_tw);

    lua_pushstring(L,text);
    WSLUA_RETURN(1); /* The `TextWindow`++'++s text. */
}

WSLUA_METHOD TextWindow_close(lua_State* L) { /* Close the window. */
    TextWindow tw = checkTextWindow(L,1);

    if (!ops->destroy_text_window) {
        WSLUA_ERROR(TextWindow_get_text,"GUI not available");
        return 0;
    }

    ops->destroy_text_window(tw->ws_tw);
    tw->ws_tw = NULL;

    return 0;
}

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int TextWindow__gc(lua_State* L) {
    TextWindow tw = toTextWindow(L,1);

    if (!tw)
        return 0;

    if (!tw->expired) {
        tw->expired = TRUE;
        if (ops->destroy_text_window) {
            ops->destroy_text_window(tw->ws_tw);
        }
    } else {
        g_free(tw->close_cb_data);
        g_free(tw);
    }

    return 0;
}

WSLUA_METHOD TextWindow_set_editable(lua_State* L) { /* Make this text window editable. */
#define WSLUA_OPTARG_TextWindow_set_editable_EDITABLE 2 /* `true` to make the text editable, `false` otherwise. Defaults to `true`. */

    TextWindow tw = checkTextWindow(L,1);
    gboolean editable = wslua_optbool(L,WSLUA_OPTARG_TextWindow_set_editable_EDITABLE,TRUE);

    if (!ops->set_editable) {
        WSLUA_ERROR(TextWindow_set_editable,"GUI not available");
        return 0;
    }

    ops->set_editable(tw->ws_tw,editable);

    WSLUA_RETURN(1); /* The `TextWindow` object. */
}

typedef struct _wslua_bt_cb_t {
    lua_State* L;
    int func_ref;
    int wslua_tw_ref;
} wslua_bt_cb_t;

static gboolean wslua_button_callback(funnel_text_window_t* ws_tw, void* data) {
    wslua_bt_cb_t* cbd = (wslua_bt_cb_t *)data;
    lua_State* L = cbd->L;
    (void) ws_tw; /* ws_tw is unused since we need wslua_tw_ref and it is stored in cbd */

    lua_settop(L,0);
    lua_pushcfunction(L,dlg_cb_error_handler);
    lua_rawgeti(L, LUA_REGISTRYINDEX, cbd->func_ref);
    lua_rawgeti(L, LUA_REGISTRYINDEX, cbd->wslua_tw_ref);

    switch ( lua_pcall(L,1,0,1) ) {
        case 0:
            break;
        case LUA_ERRRUN:
            ws_warning("Runtime error while calling button callback");
            break;
        case LUA_ERRMEM:
            ws_warning("Memory alloc error while calling button callback");
            break;
        case LUA_ERRERR:
            ws_warning("Error while running the error handler function for button callback");
            break;
        default:
            ws_assert_not_reached();
            break;
    }

    return TRUE;
}

WSLUA_METHOD TextWindow_add_button(lua_State* L) {
    /* Adds a button with an action handler to the text window. */
#define WSLUA_ARG_TextWindow_add_button_LABEL 2 /* The button label. */
#define WSLUA_ARG_TextWindow_add_button_FUNCTION 3 /* The Lua function to be called when the button is pressed. */
    TextWindow tw = checkTextWindow(L,1);
    const gchar* label = luaL_checkstring(L,WSLUA_ARG_TextWindow_add_button_LABEL);

    funnel_bt_t* fbt;
    wslua_bt_cb_t* cbd;

    if (!ops->add_button) {
        WSLUA_ERROR(TextWindow_add_button,"GUI not available");
        return 0;
    }

    if (! lua_isfunction(L,WSLUA_ARG_TextWindow_add_button_FUNCTION) ) {
        WSLUA_ARG_ERROR(TextWindow_add_button,FUNCTION,"must be a function");
        return 0;
    }

    lua_settop(L,3);

    if (ops->add_button) {
        fbt = g_new(funnel_bt_t, 1);
        cbd = g_new(wslua_bt_cb_t, 1);

        fbt->tw = tw->ws_tw;
        fbt->func = wslua_button_callback;
        fbt->data = cbd;
        fbt->free_fcn = g_free;
        fbt->free_data_fcn = g_free;

        cbd->L = L;
        cbd->func_ref = luaL_ref(L, LUA_REGISTRYINDEX);
        cbd->wslua_tw_ref = luaL_ref(L, LUA_REGISTRYINDEX);

        ops->add_button(tw->ws_tw,fbt,label);
    }

    WSLUA_RETURN(1); /* The `TextWindow` object. */
}

WSLUA_METHODS TextWindow_methods[] = {
    WSLUA_CLASS_FNREG(TextWindow,new),
    WSLUA_CLASS_FNREG(TextWindow,set),
    WSLUA_CLASS_FNREG(TextWindow,append),
    WSLUA_CLASS_FNREG(TextWindow,prepend),
    WSLUA_CLASS_FNREG(TextWindow,clear),
    WSLUA_CLASS_FNREG(TextWindow,set_atclose),
    WSLUA_CLASS_FNREG(TextWindow,set_editable),
    WSLUA_CLASS_FNREG(TextWindow,get_text),
    WSLUA_CLASS_FNREG(TextWindow,add_button),
    WSLUA_CLASS_FNREG(TextWindow,close),
    { NULL, NULL }
};

WSLUA_META TextWindow_meta[] = {
    {"__tostring", TextWindow_get_text},
    { NULL, NULL }
};

int TextWindow_register(lua_State* L) {

    ops = funnel_get_funnel_ops();

    WSLUA_REGISTER_CLASS(TextWindow);

    return 0;
}


WSLUA_FUNCTION wslua_retap_packets(lua_State* L) {
    /*
     Rescans all packets and runs each <<lua_class_Listener, tap listener>> without reconstructing the display.
     */
    if ( ops->retap_packets ) {
        ops->retap_packets(ops->ops_id);
    } else {
        WSLUA_ERROR(wslua_retap_packets, "GUI not available");
    }

    return 0;
}


WSLUA_FUNCTION wslua_copy_to_clipboard(lua_State* L) { /* Copy a string into the clipboard. Requires a GUI. */
#define WSLUA_ARG_copy_to_clipboard_TEXT 1 /* The string to be copied into the clipboard. */
    const char* copied_str = luaL_checkstring(L,WSLUA_ARG_copy_to_clipboard_TEXT);
    GString* gstr;
    if (!ops->copy_to_clipboard) {
        WSLUA_ERROR(copy_to_clipboard, "GUI not available");
        return 0;
    }

    gstr = g_string_new(copied_str);

    ops->copy_to_clipboard(gstr);

    g_string_free(gstr,TRUE);

    return 0;
}

WSLUA_FUNCTION wslua_open_capture_file(lua_State* L) { /* Open and display a capture file. Requires a GUI. */
#define WSLUA_ARG_open_capture_file_FILENAME 1 /* The name of the file to be opened. */
#define WSLUA_ARG_open_capture_file_FILTER 2 /* The https://gitlab.com/wireshark/wireshark/-/wikis/DisplayFilters[display filter] to be applied once the file is opened. */

    const char* fname = luaL_checkstring(L,WSLUA_ARG_open_capture_file_FILENAME);
    const char* filter = luaL_optstring(L,WSLUA_ARG_open_capture_file_FILTER,NULL);
    char* error = NULL;

    if (!ops->open_file) {
        WSLUA_ERROR(open_capture_file, "GUI not available");
        return 0;
    }

    if (! ops->open_file(ops->ops_id, fname, filter, &error) ) {
        lua_pushboolean(L,FALSE);

        if (error) {
            lua_pushstring(L,error);
            g_free(error);
        } else
            lua_pushnil(L);

        return 2;
    } else {
        lua_pushboolean(L,TRUE);
        return 1;
    }
}

WSLUA_FUNCTION wslua_get_filter(lua_State* L) { /* Get the main filter text. */
    const char *filter_str = NULL;

    if (!ops->get_filter) {
        WSLUA_ERROR(get_filter, "GUI not available");
        return 0;
    }

    filter_str = ops->get_filter(ops->ops_id);
    lua_pushstring(L,filter_str);

    return 1;
}

WSLUA_FUNCTION wslua_set_filter(lua_State* L) { /* Set the main filter text. */
#define WSLUA_ARG_set_filter_TEXT 1 /* The filter's text. */
    const char* filter_str = luaL_checkstring(L,WSLUA_ARG_set_filter_TEXT);

    if (!ops->set_filter) {
        WSLUA_ERROR(set_filter, "GUI not available");
        return 0;
    }

    ops->set_filter(ops->ops_id, filter_str);

    return 0;
}

WSLUA_FUNCTION wslua_get_color_filter_slot(lua_State* L) { /*
    Gets the current https://gitlab.com/wireshark/wireshark/-/wikis/ColoringRules[packet coloring rule] (by index) for the
    current session. Wireshark reserves 10 slots for these coloring rules. Requires a GUI.
*/
#define WSLUA_ARG_get_color_filter_slot_ROW 1 /*
    The index (1-10) of the desired color filter value in the temporary coloring rules list.

    .Default background colors
    [cols="3",options="header"]
    |===
    |Index |RGB (hex) |Color
    |1  |ffc0c0 |{set:cellbgcolor:#ffc0c0} pink 1
    |2  |ffc0ff |{set:cellbgcolor:#ffc0ff} pink 2
    |3  |e0c0e0 |{set:cellbgcolor:#e0c0e0} purple 1
    |4  |c0c0ff |{set:cellbgcolor:#c0c0ff} purple 2
    |5  |c0e0e0 |{set:cellbgcolor:#c0e0e0} green 1
    |6  |c0ffff |{set:cellbgcolor:#c0ffff} green 2
    |7  |c0ffc0 |{set:cellbgcolor:#c0ffc0} green 3
    |8  |ffffc0 |{set:cellbgcolor:#ffffc0} yellow 1
    |9  |e0e0c0 |{set:cellbgcolor:#e0e0c0} yellow 2
    |10 |e0e0e0 |{set:cellbgcolor:#e0e0e0} gray
    |===
    */
    guint8 row = (guint8)luaL_checkinteger(L, WSLUA_ARG_get_color_filter_slot_ROW);
    gchar* filter_str = NULL;

    if (!ops->get_color_filter_slot) {
        WSLUA_ERROR(get_color_filter_slot, "GUI not available");
        return 0;
    }

    filter_str = ops->get_color_filter_slot(row);
    if (filter_str == NULL) {
        lua_pushnil(L);
    } else {
        lua_pushstring(L, filter_str);
        g_free(filter_str);
    }

    return 1;
}

WSLUA_FUNCTION wslua_set_color_filter_slot(lua_State* L) { /*
    Sets a https://gitlab.com/wireshark/wireshark/-/wikis/ColoringRules[packet coloring rule] (by index) for the current session.
    Wireshark reserves 10 slots for these coloring rules.
    Requires a GUI.
*/
#define WSLUA_ARG_set_color_filter_slot_ROW 1 /*
    The index (1-10) of the desired color in the temporary coloring rules list.
    The default foreground is black and the default backgrounds are listed below.

    // XXX We need get the colors working, e.g. by adding them to a stylesheet.
    .Default background colors
    [cols="3",options="header"]
    |===
    |Index |RGB (hex) |Color
    |1  |ffc0c0 |{set:cellbgcolor:#ffc0c0} pink 1
    |2  |ffc0ff |{set:cellbgcolor:#ffc0ff} pink 2
    |3  |e0c0e0 |{set:cellbgcolor:#e0c0e0} purple 1
    |4  |c0c0ff |{set:cellbgcolor:#c0c0ff} purple 2
    |5  |c0e0e0 |{set:cellbgcolor:#c0e0e0} green 1
    |6  |c0ffff |{set:cellbgcolor:#c0ffff} green 2
    |7  |c0ffc0 |{set:cellbgcolor:#c0ffc0} green 3
    |8  |ffffc0 |{set:cellbgcolor:#ffffc0} yellow 1
    |9  |e0e0c0 |{set:cellbgcolor:#e0e0c0} yellow 2
    |10 |e0e0e0 |{set:cellbgcolor:#e0e0e0} gray
    |===

    The color list can be set from the command line using two unofficial preferences: `gui.colorized_frame.bg` and `gui.colorized_frame.fg`, which require 10 hex RGB codes (6 hex digits each), e.g.
    ----
    wireshark -o gui.colorized_frame.bg:${RGB0},${RGB1},${RGB2},${RGB3},${RGB4},${RGB5},${RGB6},${RGB7},${RGB8},${RGB9}
    ----

    For example, this command yields the same results as the table above (and with all foregrounds set to black):
    ----
    wireshark -o gui.colorized_frame.bg:ffc0c0,ffc0ff,e0c0e0,c0c0ff,c0e0e0,c0ffff,c0ffc0,ffffc0,e0e0c0,e0e0e0 -o gui.colorized_frame.fg:000000,000000,000000,000000,000000,000000,000000,000000,000000,000000
    ----
    */
#define WSLUA_ARG_set_color_filter_slot_TEXT  2 /* The https://gitlab.com/wireshark/wireshark/-/wikis/DisplayFilters[display filter] for selecting packets to be colorized
. */
    guint8 row = (guint8)luaL_checkinteger(L,WSLUA_ARG_set_color_filter_slot_ROW);
    const gchar* filter_str = luaL_checkstring(L,WSLUA_ARG_set_color_filter_slot_TEXT);

    if (!ops->set_color_filter_slot) {
        WSLUA_ERROR(set_color_filter_slot, "GUI not available");
        return 0;
    }

    ops->set_color_filter_slot(row, filter_str);

    return 0;
}

WSLUA_FUNCTION wslua_apply_filter(lua_State* L) { /*
    Apply the filter in the main filter box.
    Requires a GUI.

    [WARNING]
    ====
    Avoid calling this from within a dissector function or else an infinite loop can occur if it causes the dissector to be called again.
    This function is best used in a button callback (from a dialog or text window) or menu callback.
    ====
    */
    if (!ops->apply_filter) {
        WSLUA_ERROR(apply_filter, "GUI not available");
        return 0;
    }

    ops->apply_filter(ops->ops_id);

    return 0;
}


WSLUA_FUNCTION wslua_reload(lua_State* L) { /* Reload the current capture file.  Deprecated. Use reload_packets() instead. */

    if (!ops->reload_packets) {
        WSLUA_ERROR(reload, "GUI not available");
        return 0;
    }

    ops->reload_packets(ops->ops_id);

    return 0;
}


WSLUA_FUNCTION wslua_reload_packets(lua_State* L) { /*
    Reload the current capture file.
    Requires a GUI.

    [WARNING]
    ====
    Avoid calling this from within a dissector function or else an infinite loop can occur if it causes the dissector to be called again.
    This function is best used in a button callback (from a dialog or text window) or menu callback.
    ====
    */

    if (!ops->reload_packets) {
        WSLUA_ERROR(reload, "GUI not available");
        return 0;
    }

    ops->reload_packets(ops->ops_id);

    return 0;
}


WSLUA_FUNCTION wslua_redissect_packets(lua_State* L) { /*
    Redissect all packets in the current capture file.
    Requires a GUI.

    [WARNING]
    ====
    Avoid calling this from within a dissector function or else an infinite loop can occur if it causes the dissector to be called again.
    This function is best used in a button callback (from a dialog or text window) or menu callback.
    ====
    */

    if (!ops->redissect_packets) {
        WSLUA_ERROR(reload, "GUI not available");
        return 0;
    }

    ops->redissect_packets(ops->ops_id);

    return 0;
}


WSLUA_FUNCTION wslua_reload_lua_plugins(lua_State* L) { /* Reload all Lua plugins. */

    if (!ops->reload_lua_plugins) {
        WSLUA_ERROR(reload_lua_plugins, "GUI not available");
        return 0;
    }

    ops->reload_lua_plugins(ops->ops_id);

    return 0;
}


WSLUA_FUNCTION wslua_browser_open_url(lua_State* L) { /*
    Opens an URL in a web browser. Requires a GUI.

    [WARNING]
    ====
    Do not pass an untrusted URL to this function.

    It will be passed to the system's URL handler, which might execute malicious code, switch on your Bluetooth-connected foghorn, or any of a number of unexpected or harmful things.
    ====
    */
#define WSLUA_ARG_browser_open_url_URL 1 /* The url. */
    const char* url = luaL_checkstring(L,WSLUA_ARG_browser_open_url_URL);

    if (!ops->browser_open_url) {
        WSLUA_ERROR(browser_open_url, "GUI not available");
        return 0;
    }

    ops->browser_open_url(url);

    return 0;
}

WSLUA_FUNCTION wslua_browser_open_data_file(lua_State* L) { /*
    Open a file located in the data directory (specified in the Wireshark preferences) in the web browser.
    If the file does not exist, the function silently ignores the request.
    Requires a GUI.

    [WARNING]
    ====
    Do not pass an untrusted URL to this function.

    It will be passed to the system's URL handler, which might execute malicious code, switch on your Bluetooth-connected foghorn, or any of a number of unexpected or harmful things.
    ====
    */
#define WSLUA_ARG_browser_open_data_file_FILENAME 1 /* The file name. */
    const char* file = luaL_checkstring(L,WSLUA_ARG_browser_open_data_file_FILENAME);

    if (!ops->browser_open_data_file) {
        WSLUA_ERROR(browser_open_data_file, "GUI not available");
        return 0;
    }

    ops->browser_open_data_file(file);

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
