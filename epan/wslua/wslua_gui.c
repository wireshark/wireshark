/*
 *  wslua_gui.c
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * $Id$
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

/* WSLUA_MODULE Gui GUI support */

static const funnel_ops_t* ops = NULL;

struct _lua_menu_data {
    lua_State* L;
    int cb_ref;
};

static int menu_cb_error_handler(lua_State* L) {
    const gchar* error =  lua_tostring(L,1);
    report_failure("Lua: Error During execution of Menu Callback:\n %s",error);
    return 0;
}

WSLUA_FUNCTION wslua_gui_enabled(lua_State* L) { /* Checks whether the GUI facility is enabled. */
    lua_pushboolean(L,GPOINTER_TO_INT(ops && ops->add_button));
    WSLUA_RETURN(1); /* A boolean: true if it is enabled, false if it isn't. */
}

static void lua_menu_callback(gpointer data) {
    struct _lua_menu_data* md = data;
    lua_State* L = md->L;

    lua_settop(L,0);
    lua_pushcfunction(L,menu_cb_error_handler);
    lua_rawgeti(L, LUA_REGISTRYINDEX, md->cb_ref);

    switch ( lua_pcall(L,0,0,1) ) {
        case 0:
            break;
        case LUA_ERRRUN:
            g_warning("Runtime error while calling menu callback");
            break;
        case LUA_ERRMEM:
            g_warning("Memory alloc error while calling menu callback");
            break;
        default:
            g_assert_not_reached();
            break;
    }

    return;
}

WSLUA_FUNCTION wslua_register_menu(lua_State* L) { /*  Register a menu item in one of the main menus. */
#define WSLUA_ARG_register_menu_NAME 1 /* The name of the menu item. The submenus are to be separated by '/'s. (string) */
#define WSLUA_ARG_register_menu_ACTION 2 /* The function to be called when the menu item is invoked. (function taking no arguments and returning nothing)  */
#define WSLUA_OPTARG_register_menu_GROUP 3 /* The menu group into which the menu item is to be inserted. If omitted, defaults to MENU_STAT_GENERIC. One of:
                                              MENU_STAT_UNSORTED (Statistics),
                                              MENU_STAT_GENERIC (Statistics, first section),
                                              MENU_STAT_CONVERSATION (Statistics/Conversation List),
                                              MENU_STAT_ENDPOINT (Statistics/Endpoint List),
                                              MENU_STAT_RESPONSE (Statistics/Service Response Time),
                                              MENU_STAT_TELEPHONY (Telephony), MENU_ANALYZE (Analyze),
                                              MENU_ANALYZE_CONVERSATION (Analyze/Conversation Filter),
                                              MENU_TOOLS_UNSORTED (Tools). (number) */

    const gchar* name = luaL_checkstring(L,WSLUA_ARG_register_menu_NAME);
    struct _lua_menu_data* md;
    gboolean retap = FALSE;
    register_stat_group_t group = (int)luaL_optnumber(L,WSLUA_OPTARG_register_menu_GROUP,REGISTER_STAT_GROUP_GENERIC);

    if ( group > REGISTER_TOOLS_GROUP_UNSORTED)
        WSLUA_OPTARG_ERROR(register_menu,GROUP,"Must be a defined MENU_* (see init.lua)");

    if(!name)
        WSLUA_ARG_ERROR(register_menu,NAME,"Must be a string");

    if (!lua_isfunction(L,WSLUA_ARG_register_menu_ACTION))
        WSLUA_ARG_ERROR(register_menu,ACTION,"Must be a function");

    md = g_malloc(sizeof(struct _lua_menu_data));
    md->L = L;

    lua_pushvalue(L, 2);
    md->cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_remove(L,2);

    funnel_register_menu(name,
                         group,
                         lua_menu_callback,
                         md,
                         retap);

    WSLUA_RETURN(0);
}




struct _dlg_cb_data {
    lua_State* L;
    int func_ref;
};

static int dlg_cb_error_handler(lua_State* L) {
    const gchar* error =  lua_tostring(L,1);
    report_failure("Lua: Error During execution of dialog callback:\n %s",error);
    return 0;
}

static void lua_dialog_cb(gchar** user_input, void* data) {
    struct _dlg_cb_data* dcbd = data;
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
            g_warning("Runtime error while calling dialog callback");
            break;
        case LUA_ERRMEM:
            g_warning("Memory alloc error while calling dialog callback");
            break;
        default:
            g_assert_not_reached();
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
    report_failure("Lua: Error During execution of TextWindow close callback:\n %s",error);
    return 0;
}

static void text_win_close_cb(void* data) {
    struct _close_cb_data* cbd = data;
    lua_State* L = cbd->L;

    if (cbd->L) { /* close function is set */

        lua_settop(L,0);
        lua_pushcfunction(L,text_win_close_cb_error_handler);
        lua_rawgeti(L, LUA_REGISTRYINDEX, cbd->func_ref);

        switch ( lua_pcall(L,0,0,1) ) {
            case 0:
                break;
            case LUA_ERRRUN:
                g_warning("Runtime error during execution of TextWindow close callback");
                break;
            case LUA_ERRMEM:
                g_warning("Memory alloc error during execution of TextWindow close callback");
                break;
            default:
                break;
        }
    }

    if (cbd->wslua_tw->expired) {
        g_free(cbd->wslua_tw);
    } else {
        cbd->wslua_tw->expired = TRUE;
    }

}

WSLUA_FUNCTION wslua_new_dialog(lua_State* L) { /* Pops up a new dialog */
#define WSLUA_ARG_new_dialog_TITLE 1 /* Title of the dialog's window. */
#define WSLUA_ARG_new_dialog_ACTION 2 /* Action to be performed when OKd. */
/* WSLUA_MOREARGS new_dialog A series of strings to be used as labels of the dialog's fields */

    const gchar* title;
    int top = lua_gettop(L);
    int i;
    GPtrArray* labels;
    struct _dlg_cb_data* dcbd;

    if (! ops) {
        luaL_error(L,"the GUI facility has to be enabled");
        return 0;
    }

    if (!ops->new_dialog) {
        WSLUA_ERROR(new_dialog,"GUI not available");
    }

    if (! (title  = luaL_checkstring(L,WSLUA_ARG_new_dialog_TITLE)) ) {
        WSLUA_ARG_ERROR(new_dialog,TITLE,"Must be a string");
    }

    if (! lua_isfunction(L,WSLUA_ARG_new_dialog_ACTION)) {
        WSLUA_ARG_ERROR(new_dialog,ACTION,"Must be a function");
    }

    if (top < 3) {
        WSLUA_ERROR(new_dialog,"At least one field required");
    }


    dcbd = g_malloc(sizeof(struct _dlg_cb_data));
    dcbd->L = L;

    lua_remove(L,1);

    lua_pushvalue(L, 1);
    dcbd->func_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_remove(L,1);

    labels = g_ptr_array_new();

    top -= 2;

    for (i = 1; i <= top; i++) {
        gchar* label = (void*)luaL_checkstring(L,i);

        /* XXX leaks labels on error */
        if (! label)
            WSLUA_ERROR(new_dialog,"All fields must be strings");

        g_ptr_array_add(labels,label);
    }

    g_ptr_array_add(labels,NULL);

    ops->new_dialog(title, (const gchar**)labels->pdata, lua_dialog_cb, dcbd);

    g_ptr_array_free(labels,FALSE);

    WSLUA_RETURN(0);
}



WSLUA_CLASS_DEFINE(ProgDlg,NOP,NOP); /* Manages a progress bar dialog. */

WSLUA_CONSTRUCTOR ProgDlg_new(lua_State* L) { /* Creates a new TextWindow. */
#define WSLUA_OPTARG_ProgDlg_new_TITLE 2 /* Title of the new window, defaults to "Progress". */
#define WSLUA_OPTARG_ProgDlg_new_TASK 3  /* Current task, defaults to "". */
    ProgDlg pd = g_malloc(sizeof(struct _wslua_progdlg));
    pd->title = g_strdup(luaL_optstring(L,WSLUA_OPTARG_ProgDlg_new_TITLE,"Progress"));
    pd->task = g_strdup(luaL_optstring(L,WSLUA_OPTARG_ProgDlg_new_TASK,""));
    pd->stopped = FALSE;

    if (ops->new_progress_window) {
        pd->pw = ops->new_progress_window(pd->title,pd->task,TRUE,&(pd->stopped));
    } else {
        WSLUA_ERROR(ProgDlg_new, "GUI not available");
    }

    pushProgDlg(L,pd);

    WSLUA_RETURN(1); /* The newly created TextWindow object. */
}

WSLUA_METHOD ProgDlg_update(lua_State* L) { /* Appends text */
#define WSLUA_ARG_ProgDlg_update_PROGRESS 2  /* Part done ( e.g. 0.75 ). */
#define WSLUA_OPTARG_ProgDlg_update_TASK 3  /* Current task, defaults to "". */
    ProgDlg pd = checkProgDlg(L,1);
    double pr = lua_tonumber(L,WSLUA_ARG_ProgDlg_update_PROGRESS);
    const gchar* task = luaL_optstring(L,WSLUA_OPTARG_ProgDlg_update_TASK,"");

    if (!ops->update_progress) {
        WSLUA_ERROR(ProgDlg_update,"GUI not available");
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
    }

    return 0;
}

WSLUA_METHOD ProgDlg_stopped(lua_State* L) { /* Checks wheher the user has pressed the stop button.  */
    ProgDlg pd = checkProgDlg(L,1);

    if (!pd) {
        WSLUA_ERROR(ProgDlg_stopped,"Cannot be called for something not a ProgDlg");
    }

    lua_pushboolean(L,pd->stopped);

    WSLUA_RETURN(1); /* true if the user has asked to stop the progress. */
}



WSLUA_METHOD ProgDlg_close(lua_State* L) { /* Appends text */
    ProgDlg pd = checkProgDlg(L,1);

    if (!ops->destroy_progress_window) {
        WSLUA_ERROR(ProgDlg_close,"GUI not available");
    }

    if (!pd) {
        WSLUA_ERROR(ProgDlg_update,"Cannot be called for something not a ProgDlg");
    }

    if (pd->pw) {
        ops->destroy_progress_window(pd->pw);
        pd->pw = NULL;
    }
    return 0;
}


static int ProgDlg__tostring(lua_State* L) {
    ProgDlg pd = checkProgDlg(L,1);

    if (pd) {
        lua_pushstring(L,ep_strdup_printf("%sstopped",pd->stopped?"":"not "));
    } else {
        luaL_error(L, "ProgDlg__tostring has being passed something else!");
    }

    return 0;
}

static int ProgDlg__gc(lua_State* L) {
    ProgDlg pd = checkProgDlg(L,1);

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
    {"new",ProgDlg_new},
    {"update",ProgDlg_update},
    {"stopped",ProgDlg_stopped},
    {"close",ProgDlg_close},
    {0, 0}
};

WSLUA_META ProgDlg_meta[] = {
    {"__tostring", ProgDlg__tostring},
    {"__gc", ProgDlg__gc},
    {0, 0}
};

int ProgDlg_register(lua_State* L) {

    ops = funnel_get_funnel_ops();

    WSLUA_REGISTER_CLASS(ProgDlg);

    return 1;
}



WSLUA_CLASS_DEFINE(TextWindow,NOP,NOP); /* Manages a text window. */

/* XXX: button and close callback data is being leaked */
/* XXX: lua callback function and TextWindow are not garbage collected because
   they stay in LUA_REGISTRYINDEX forever */

WSLUA_CONSTRUCTOR TextWindow_new(lua_State* L) { /* Creates a new TextWindow. */
#define WSLUA_OPTARG_TextWindow_new_TITLE 1 /* Title of the new window. */

    const gchar* title;
    TextWindow tw = NULL;
    struct _close_cb_data* default_cbd;

    if (!ops->new_text_window || !ops->set_close_cb) {
        WSLUA_ERROR(TextWindow_new,"GUI not available");
    }

    title = luaL_optstring(L,WSLUA_OPTARG_TextWindow_new_TITLE,"Untitled Window");
    tw = g_malloc(sizeof(struct _wslua_tw));
    tw->expired = FALSE;
    tw->ws_tw = ops->new_text_window(title);

    default_cbd = g_malloc(sizeof(struct _close_cb_data));

    default_cbd->L = NULL;
    default_cbd->func_ref = 0;
    default_cbd->wslua_tw = tw;

    ops->set_close_cb(tw->ws_tw,text_win_close_cb,default_cbd);

    pushTextWindow(L,tw);

    WSLUA_RETURN(1); /* The newly created TextWindow object. */
}

WSLUA_METHOD TextWindow_set_atclose(lua_State* L) { /* Set the function that will be called when the window closes */
#define WSLUA_ARG_TextWindow_at_close_ACTION 2 /* A function to be executed when the user closes the window */

    TextWindow tw = checkTextWindow(L,1);
    struct _close_cb_data* cbd;

    if (!ops->set_close_cb) {
        WSLUA_ERROR(TextWindow_set_atclose,"GUI not available");
    }

    if (!tw)
        WSLUA_ERROR(TextWindow_at_close,"Cannot be called for something not a TextWindow");

    lua_settop(L,2);

    if (! lua_isfunction(L,2))
        WSLUA_ARG_ERROR(TextWindow_at_close,ACTION,"Must be a function");

    cbd = g_malloc(sizeof(struct _close_cb_data));

    cbd->L = L;
    cbd->func_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    cbd->wslua_tw = tw;

    ops->set_close_cb(tw->ws_tw,text_win_close_cb,cbd);

    WSLUA_RETURN(1); /* The TextWindow object. */
}

WSLUA_METHOD TextWindow_set(lua_State* L) { /* Sets the text. */
#define WSLUA_ARG_TextWindow_set_TEXT 2 /* The text to be used. */

    TextWindow tw = checkTextWindow(L,1);
    const gchar* text = luaL_checkstring(L,WSLUA_ARG_TextWindow_set_TEXT);

    if (!ops->set_text)
        WSLUA_ERROR(TextWindow_set,"GUI not available");

    if (!tw)
        WSLUA_ERROR(TextWindow_set,"Cannot be called for something not a TextWindow");

    if (tw->expired)
        WSLUA_ERROR(TextWindow_set,"Expired TextWindow");

    if (!text)
        WSLUA_ARG_ERROR(TextWindow_set,TEXT,"Must be a string");

    ops->set_text(tw->ws_tw,text);

    WSLUA_RETURN(1); /* The TextWindow object. */
}

WSLUA_METHOD TextWindow_append(lua_State* L) { /* Appends text */
#define WSLUA_ARG_TextWindow_append_TEXT 2 /* The text to be appended */
    TextWindow tw = checkTextWindow(L,1);
    const gchar* text = luaL_checkstring(L,WSLUA_ARG_TextWindow_append_TEXT);

    if (!ops->append_text)
        WSLUA_ERROR(TextWindow_append,"GUI not available");

    if (!tw)
        WSLUA_ERROR(TextWindow_append,"Cannot be called for something not a TextWindow");

    if (tw->expired)
        WSLUA_ERROR(TextWindow_append,"Expired TextWindow");

    if (!text)
        WSLUA_ARG_ERROR(TextWindow_append,TEXT,"Must be a string");

    ops->append_text(tw->ws_tw,text);

    WSLUA_RETURN(1); /* The TextWindow object. */
}

WSLUA_METHOD TextWindow_prepend(lua_State* L) { /* Prepends text */
#define WSLUA_ARG_TextWindow_prepend_TEXT 2 /* The text to be appended */
    TextWindow tw = checkTextWindow(L,1);
    const gchar* text = luaL_checkstring(L,WSLUA_ARG_TextWindow_prepend_TEXT);

    if (!ops->prepend_text)
        WSLUA_ERROR(TextWindow_prepend,"GUI not available");

    if (!tw)
        WSLUA_ERROR(TextWindow_prepend,"Cannot be called for something not a TextWindow");

    if (tw->expired)
        WSLUA_ERROR(TextWindow_prepend,"Expired TextWindow");

     if (!text)
        WSLUA_ARG_ERROR(TextWindow_prepend,TEXT,"Must be a string");

    ops->prepend_text(tw->ws_tw,text);

    WSLUA_RETURN(1); /* The TextWindow object. */
}

WSLUA_METHOD TextWindow_clear(lua_State* L) { /* Erases all text in the window. */
    TextWindow tw = checkTextWindow(L,1);

    if (!ops->clear_text)
        WSLUA_ERROR(TextWindow_clear,"GUI not available");

    if (!tw)
        WSLUA_ERROR(TextWindow_clear,"Cannot be called for something not a TextWindow");

    if (tw->expired)
        WSLUA_ERROR(TextWindow_clear,"Expired TextWindow");

    ops->clear_text(tw->ws_tw);

    WSLUA_RETURN(1); /* The TextWindow object. */
}

WSLUA_METHOD TextWindow_get_text(lua_State* L) { /* Get the text of the window */
    TextWindow tw = checkTextWindow(L,1);
    const gchar* text;

    if (!ops->get_text)
        WSLUA_ERROR(TextWindow_get_text,"GUI not available");

    if (!tw)
        WSLUA_ERROR(TextWindow_get_text,"Cannot be called for something not a TextWindow");

    if (tw->expired)
        WSLUA_ERROR(TextWindow_get_text,"Expired TextWindow");

    text = ops->get_text(tw->ws_tw);

    lua_pushstring(L,text);
    WSLUA_RETURN(1); /* The TextWindow's text. */
}

static int TextWindow__gc(lua_State* L) {
    TextWindow tw = checkTextWindow(L,1);

    if (!tw)
        return 0;

    if (!tw->expired) {
        tw->expired = TRUE;
        if (ops->destroy_text_window) {
            ops->destroy_text_window(tw->ws_tw);
        }
    } else {
        g_free(tw);
    }


    return 0;
}

WSLUA_METHOD TextWindow_set_editable(lua_State* L) { /* Make this window editable */
#define WSLUA_OPTARG_TextWindow_set_editable_EDITABLE 2 /* A boolean flag, defaults to true */

    TextWindow tw = checkTextWindow(L,1);
    gboolean editable = wslua_optbool(L,WSLUA_OPTARG_TextWindow_set_editable_EDITABLE,TRUE);

    if (!ops->set_editable)
        WSLUA_ERROR(TextWindow_set_editable,"GUI not available");

    if (!tw)
        WSLUA_ERROR(TextWindow_set_editable,"Cannot be called for something not a TextWindow");

    if (tw->expired)
        WSLUA_ERROR(TextWindow_set_editable,"Expired TextWindow");

    if (ops->set_editable)
        ops->set_editable(tw->ws_tw,editable);

    WSLUA_RETURN(1); /* The TextWindow object. */
}

typedef struct _wslua_bt_cb_t {
    lua_State* L;
    int func_ref;
    int wslua_tw_ref;
} wslua_bt_cb_t;

static gboolean wslua_button_callback(funnel_text_window_t* ws_tw, void* data) {
    wslua_bt_cb_t* cbd = data;
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
            g_warning("Runtime error while calling button callback");
            break;
        case LUA_ERRMEM:
            g_warning("Memory alloc error while calling button callback");
            break;
        default:
            g_assert_not_reached();
            break;
    }

    return TRUE;
}

WSLUA_METHOD TextWindow_add_button(lua_State* L) {
#define WSLUA_ARG_TextWindow_add_button_LABEL 2 /* The label of the button */
#define WSLUA_ARG_TextWindow_add_button_FUNCTION 3 /* The function to be called when clicked */
    TextWindow tw = checkTextWindow(L,1);
    const gchar* label = luaL_checkstring(L,WSLUA_ARG_TextWindow_add_button_LABEL);

    funnel_bt_t* fbt;
    wslua_bt_cb_t* cbd;

    if (!ops->add_button)
        WSLUA_ERROR(TextWindow_add_button,"GUI not available");

    if (!tw)
        WSLUA_ERROR(TextWindow_add_button,"Cannot be called for something not a TextWindow");

    if (tw->expired)
        WSLUA_ERROR(TextWindow_add_button,"Expired TextWindow");

    if (! lua_isfunction(L,WSLUA_ARG_TextWindow_add_button_FUNCTION) )
        WSLUA_ARG_ERROR(TextWindow_add_button,FUNCTION,"must be a function");

    lua_settop(L,3);

    if (ops->add_button) {
        fbt = g_malloc(sizeof(funnel_bt_t));
        cbd = g_malloc(sizeof(wslua_bt_cb_t));

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

    WSLUA_RETURN(1); /* The TextWindow object. */
}

WSLUA_METHODS TextWindow_methods[] = {
    WSLUA_CLASS_FNREG(TextWindow,new),
    WSLUA_CLASS_FNREG(TextWindow,set),
    WSLUA_CLASS_FNREG(TextWindow,new),
    WSLUA_CLASS_FNREG(TextWindow,append),
    WSLUA_CLASS_FNREG(TextWindow,prepend),
    WSLUA_CLASS_FNREG(TextWindow,clear),
    WSLUA_CLASS_FNREG(TextWindow,set_atclose),
    WSLUA_CLASS_FNREG(TextWindow,set_editable),
    WSLUA_CLASS_FNREG(TextWindow,get_text),
    WSLUA_CLASS_FNREG(TextWindow,add_button),
    {0, 0}
};

WSLUA_META TextWindow_meta[] = {
    {"__tostring", TextWindow_get_text},
    {"__gc", TextWindow__gc},
    {0, 0}
};

int TextWindow_register(lua_State* L) {

    ops = funnel_get_funnel_ops();

    WSLUA_REGISTER_CLASS(TextWindow);

    return 1;
}


WSLUA_FUNCTION wslua_retap_packets(lua_State* L) {
    /*
     Rescan all packets and just run taps - don't reconstruct the display.
     */
    if ( ops->retap_packets ) {
        ops->retap_packets();
    } else {
        WSLUA_ERROR(wslua_retap_packets, "GUI not available");
    }

    return 0;
}


WSLUA_FUNCTION wslua_copy_to_clipboard(lua_State* L) { /* Copy a string into the clipboard */
#define WSLUA_ARG_copy_to_clipboard_TEXT 1 /* The string to be copied into the clipboard. */
    const char* copied_str = luaL_checkstring(L,WSLUA_ARG_copy_to_clipboard_TEXT);
    GString* gstr;
    if (!ops->copy_to_clipboard) {
        WSLUA_ERROR(copy_to_clipboard, "GUI not available");
    }

    if (!copied_str) {
        WSLUA_ARG_ERROR(copy_to_clipboard,TEXT,"Must be a string");
    }

    gstr = g_string_new(copied_str);

    ops->copy_to_clipboard(gstr);

    g_string_free(gstr,TRUE);

    return 0;
}

WSLUA_FUNCTION wslua_open_capture_file(lua_State* L) { /* Open and display a capture file */
#define WSLUA_ARG_open_capture_file_FILENAME 1 /* The name of the file to be opened. */
#define WSLUA_ARG_open_capture_file_FILTER 2 /* A filter to be applied as the file gets opened. */

    const char* fname = luaL_checkstring(L,WSLUA_ARG_open_capture_file_FILENAME);
    const char* filter = luaL_optstring(L,WSLUA_ARG_open_capture_file_FILTER,NULL);
    const char* error = NULL;

    if (!ops->open_file) {
        WSLUA_ERROR(open_capture_file, "GUI not available");
    }

    if (!fname) {
        WSLUA_ARG_ERROR(open_capture_file,FILENAME,"Must be a string");
    }

    if (! ops->open_file(fname,filter,&error) ) {
        lua_pushboolean(L,FALSE);

        if (error)
            lua_pushstring(L,error);
        else
            lua_pushnil(L);

        return 2;
    } else {
        lua_pushboolean(L,TRUE);
        return 1;
    }
}

WSLUA_FUNCTION wslua_get_filter(lua_State* L) { /* Get the main filter text */
    const char *filter_str = NULL;

    if (!ops->get_filter) {
        WSLUA_ERROR(get_filter, "GUI not available");
    }

    filter_str = ops->get_filter();
    lua_pushstring(L,filter_str);

    return 1;
}

WSLUA_FUNCTION wslua_set_filter(lua_State* L) { /* Set the main filter text */
#define WSLUA_ARG_set_filter_TEXT 1 /* The filter's text. */
    const char* filter_str = luaL_checkstring(L,WSLUA_ARG_set_filter_TEXT);

    if (!ops->set_filter) {
        WSLUA_ERROR(set_filter, "GUI not available");
    }

    if (!filter_str) {
        WSLUA_ARG_ERROR(set_filter,TEXT,"Must be a string");
    }

    ops->set_filter(filter_str);

    return 0;
}

WSLUA_FUNCTION wslua_set_color_filter_slot(lua_State* L) { /* Set packet-coloring rule for the current session */
#define WSLUA_ARG_set_color_filter_slot_ROW 1 /* The index of the desired color in the temporary coloring rules list */
#define WSLUA_ARG_set_color_filter_slot_TEXT  2 /* Display filter for selecting packets to be colorized */
    guint8 row = luaL_checkint(L,WSLUA_ARG_set_color_filter_slot_ROW);
    const gchar* filter_str = luaL_checkstring(L,WSLUA_ARG_set_color_filter_slot_TEXT);

    if (!ops->set_color_filter_slot) {
        WSLUA_ERROR(set_color_filter_slot, "GUI not available");
    }

    if (!filter_str) {
        WSLUA_ARG_ERROR(set_color_filter_slot,TEXT,"Must be a string");
    }

    ops->set_color_filter_slot(row, filter_str);

    return 0;
}

WSLUA_FUNCTION wslua_apply_filter(lua_State* L) { /* Apply the filter in the main filter box */
    if (!ops->apply_filter) {
        WSLUA_ERROR(apply_filter, "GUI not available");
    }

    ops->apply_filter();

    return 0;
}


WSLUA_FUNCTION wslua_reload(lua_State* L) { /* Reload the current capture file */

    if (!ops->reload) {
        WSLUA_ERROR(reload, "GUI not available");
    }

    ops->reload();

    return 0;
}


WSLUA_FUNCTION wslua_browser_open_url(lua_State* L) { /* Open an url in a browser */
#define WSLUA_ARG_browser_open_url_URL 1 /* The url. */
    const char* url = luaL_checkstring(L,WSLUA_ARG_browser_open_url_URL);

    if (!ops->browser_open_url) {
        WSLUA_ERROR(browser_open_url, "GUI not available");
    }

    if (!url) {
        WSLUA_ARG_ERROR(browser_open_url,URL,"Must be a string");
    }

    ops->browser_open_url(url);

    return 0;
}

WSLUA_FUNCTION wslua_browser_open_data_file(lua_State* L) { /* Open an file in a browser */
#define WSLUA_ARG_browser_open_data_file_FILENAME 1 /* The url. */
    const char* file = luaL_checkstring(L,WSLUA_ARG_browser_open_data_file_FILENAME);

    if (!ops->browser_open_data_file) {
        WSLUA_ERROR(browser_open_data_file, "GUI not available");
    }

    if (!file) {
        WSLUA_ARG_ERROR(browser_open_data_file,FILENAME,"Must be a string");
    }

    ops->browser_open_data_file(file);

    return 0;
}



