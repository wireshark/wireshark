/*
 *  lua_gui.c
 *  
 * (c) 2006, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
 * 
 * $Id: wslua_gui.c 18611 2006-06-29 13:49:56Z lego $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include "wslua.h"

static const funnel_ops_t* ops = NULL;

struct _lua_menu_data {
    lua_State* L;
    int cb_ref;
    int data_ref;
};

static int menu_cb_error_handler(lua_State* L) {
    const gchar* error =  lua_tostring(L,1);
    report_failure("Lua: Error During execution of Menu Callback:\n %s",error);
    return 0;    
}

WSLUA_FUNCTION wslua_gui_enabled(lua_State* L) { /* Checks whether the GUI facility is enabled. */
    lua_pushboolean(L,GPOINTER_TO_INT(ops));
    WSLUA_RETURN(1); /* A boolean: true if it is enabled, false if it isn't. */
}

void lua_menu_callback(gpointer data) {
    struct _lua_menu_data* md = data;

    lua_pushcfunction(md->L,menu_cb_error_handler);
    lua_rawgeti(md->L, LUA_REGISTRYINDEX, md->cb_ref);
    lua_rawgeti(md->L, LUA_REGISTRYINDEX, md->data_ref);
        
    lua_pcall(md->L,1,0,1);
    
    return;
}

WSLUA_FUNCTION wslua_register_menu(lua_State* L) { /*  Register a menu item in the Statistics menu. */
#define WSLUA_ARG_register_menu_NAME 1 /* The name of the menu item. */
#define WSLUA_ARG_register_menu_ACTION 2 /* The function to be called when the menu item is invoked. */
#define WSLUA_OPTARG_register_menu_USERDATA 3 /* To be passed to the action. */
	
    const gchar* name = luaL_checkstring(L,WSLUA_ARG_register_menu_NAME);
    struct _lua_menu_data* md;
    gboolean retap = FALSE;
    
	if(!name)
		WSLUA_ARG_ERROR(register_menu,NAME,"must be a string");
	
    if (!lua_isfunction(L,WSLUA_ARG_register_menu_ACTION)) 
		WSLUA_ARG_ERROR(register_menu,ACTION,"must be a function");
    
    md = g_malloc(sizeof(struct _lua_menu_data));
    md->L = L;
    
    lua_pushvalue(L, 2);
    md->cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    
    if ( lua_gettop(L) > 2) {
        lua_pushvalue(L, WSLUA_OPTARG_register_menu_USERDATA);
        md->data_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    } else {
        md->data_ref = LUA_NOREF;
    }

    funnel_register_menu(name,
                         REGISTER_STAT_GROUP_GENERIC,
                         lua_menu_callback,
                         md,
                         retap);

    WSLUA_RETURN(0);
}




struct _dlg_cb_data {
    lua_State* L;
    int func_ref;
    int data_ref;
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
    lua_rawgeti(L, LUA_REGISTRYINDEX, dcbd->data_ref);
    
    for (i = 0; (input = user_input[i]) ; i++) {
        lua_pushstring(L,input);
        g_free(input);
    }
    
    g_free(user_input);
    
    switch ( lua_pcall(L,i+1,0,1) ) {
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
    
    if (! (title  = luaL_checkstring(L,WSLUA_ARG_new_dialog_TITLE)) ) {
        WSLUA_ARG_ERROR(new_dialog,TITLE,"must be a string");
        return 0;
    }
    
    if (! lua_isfunction(L,WSLUA_ARG_new_dialog_ACTION)) {
        WSLUA_ARG_ERROR(new_dialog,ACTION,"must be a function");
        return 0;
    }
    
    if (top < 3) {
        WSLUA_ERROR(new_dialog,"at least one field required");
        return 0;
    }
    
    
    dcbd = g_malloc(sizeof(struct _dlg_cb_data));
    dcbd->L = L;
    
    lua_remove(L,1);
    
    lua_pushvalue(L, 1);
    dcbd->func_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_remove(L,1);
    
    lua_pushvalue(L, 1);
    dcbd->data_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_remove(L,1);
    
    labels = g_ptr_array_new();
    
    top -= 3;
    
    for (i = 1; i <= top; i++) {
        gchar* label = (void*)luaL_checkstring(L,i);
		
		/* XXX leaks labels on error */
		if (! label) 
			WSLUA_ERROR(new_dialog,"all fields must be strings");
		
        g_ptr_array_add(labels,label);
    }
    
    g_ptr_array_add(labels,NULL);
    
    ops->new_dialog(title, (const gchar**)labels->pdata, lua_dialog_cb, dcbd);
    
    g_ptr_array_free(labels,TRUE);
    
    WSLUA_RETURN(0);
}



WSLUA_CLASS_DEFINE(TextWindow,NOP,NOP); /* Manages a text window. */

WSLUA_CONSTRUCTOR TextWindow_new(lua_State* L) { /* Creates a new TextWindow. */
#define WSLUA_OPTARG_TextWindow_new_TITLE 1 /* Title of the new window. */

    const gchar* title;
    TextWindow tw;

	title = luaL_optstring(L,WSLUA_OPTARG_TextWindow_new_TITLE,"Untitled Window");
    tw = ops->new_text_window(title);
    pushTextWindow(L,tw);
    
	WSLUA_RETURN(1); /* The newly created TextWindow object. */
}

struct _close_cb_data {
    lua_State* L;
    int func_ref;
    int data_ref;
};

int text_win_close_cb_error_handler(lua_State* L) {
    const gchar* error =  lua_tostring(L,1);
    report_failure("Lua: Error During execution of TextWindow close callback:\n %s",error);
    return 0;    
}

static void text_win_close_cb(void* data) {
    struct _close_cb_data* cbd = data;
    lua_State* L = cbd->L;

    lua_pushcfunction(L,text_win_close_cb_error_handler);
    lua_rawgeti(L, LUA_REGISTRYINDEX, cbd->func_ref);
    lua_rawgeti(L, LUA_REGISTRYINDEX, cbd->data_ref);
    
    switch ( lua_pcall(L,1,0,1) ) {
        case 0:
            break;
        case LUA_ERRRUN:
            g_warning("Runtime error during execution of TextWindow close callback");
            break;
        case LUA_ERRMEM:
            g_warning("Memory alloc error during execution of TextWindow close callback");
            break;
        default:
            g_assert_not_reached();
            break;
    }
}

WSLUA_METHOD TextWindow_set_atclose(lua_State* L) { /* Set the function that will be called when the window closes */
#define WSLUA_ARG_TextWindow_at_close_ACTION 2 /* A function to be executed when the user closes the window */

    TextWindow tw = checkTextWindow(L,1);
    struct _close_cb_data* cbd;

	if (!tw)
		WSLUA_ERROR(TextWindow_at_close,"cannot be called for something not a TextWindow");

    lua_settop(L,3);

    if (! lua_isfunction(L,2))
        WSLUA_ARG_ERROR(TextWindow_at_close,ACTION,"must be a function");
    
    cbd = g_malloc(sizeof(struct _close_cb_data));

    cbd->L = L;
    cbd->data_ref = luaL_ref(L,  LUA_REGISTRYINDEX);
    cbd->func_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    
    ops->set_close_cb(tw,text_win_close_cb,cbd);
    
    pushTextWindow(L,tw);
	WSLUA_RETURN(1); /* The TextWindow object. */
}

WSLUA_METHOD TextWindow_set(lua_State* L) { /* Sets the text. */
#define WSLUA_ARG_TextWindow_set_TEXT 2 /* The text to be used. */

    TextWindow tw = checkTextWindow(L,1);
    const gchar* text = luaL_checkstring(L,2);

	if (!tw)
		WSLUA_ERROR(TextWindow_set,"cannot be called for something not a TextWindow");

    if (!text)
		WSLUA_ARG_ERROR(TextWindow_set,TEXT,"must be a string");
    
    ops->set_text(tw,text);
    
    pushTextWindow(L,tw);
	WSLUA_RETURN(1); /* The TextWindow object. */
}

WSLUA_METHOD TextWindow_append(lua_State* L) { /* Appends text */
#define WSLUA_ARG_TextWindow_append_TEXT 2 /* The text to be appended */ 
    TextWindow tw = checkTextWindow(L,1);
    const gchar* text = luaL_checkstring(L,2);
    
	if (!tw)
		WSLUA_ERROR(TextWindow_append,"cannot be called for something not a TextWindow");

	if (!text)
		WSLUA_ARG_ERROR(TextWindow_append,TEXT,"must be a string");

    ops->append_text(tw,text);
    
    pushTextWindow(L,tw);
	WSLUA_RETURN(1); /* The TextWindow object. */
}

WSLUA_METHOD TextWindow_prepend(lua_State* L) { /* Prepends text */
#define WSLUA_ARG_TextWindow_prepend_TEXT 2 /* The text to be appended */ 
    TextWindow tw = checkTextWindow(L,1);
    const gchar* text = luaL_checkstring(L,2);
    
	if (!tw)
		WSLUA_ERROR(TextWindow_prepend,"cannot be called for something not a TextWindow");

 	if (!text)
		WSLUA_ARG_ERROR(TextWindow_prepend,TEXT,"must be a string");
   
    ops->prepend_text(tw,text);
    
    pushTextWindow(L,tw);
	WSLUA_RETURN(1); /* The TextWindow object. */
}

WSLUA_METHOD TextWindow_clear(lua_State* L) { /* Errases all text in the window. */
    TextWindow tw = checkTextWindow(L,1);
    
	if (!tw)
		WSLUA_ERROR(TextWindow_clear,"cannot be called for something not a TextWindow");

    ops->clear_text(tw);
    
    pushTextWindow(L,tw);
	WSLUA_RETURN(1); /* The TextWindow object. */
}

WSLUA_METHOD TextWindow_get_text(lua_State* L) { /* Get the text of the window */
    TextWindow tw = checkTextWindow(L,1);
	const gchar* text;

	if (!tw)
		WSLUA_ERROR(TextWindow_get_text,"cannot be called for something not a TextWindow");

	text = ops->get_text(tw);

    lua_pushstring(L,text);
	WSLUA_RETURN(1); /* The TextWindow's text. */
}

static int TextWindow__gc(lua_State* L) {
    TextWindow tw = checkTextWindow(L,1);

	if (!tw)
		WSLUA_ERROR(TextWindow_gc,"cannot be called for something not a TextWindow");

    ops->destroy_text_window(tw);
    return 1;
}

WSLUA_METHOD TextWindow_set_editable(lua_State* L) { /* Set the function that will be called when the window closes */
#define WSLUA_OPTARG_TextWindow_at_close_EDITABLE 2 /* A boolean flag, defaults to true */

	TextWindow tw = checkTextWindow(L,1);
	gboolean editable = luaL_optint(L,2,1);

	if (!tw)
		WSLUA_ERROR(TextWindow_at_close,"cannot be called for something not a TextWindow");

	if (ops->set_editable)
		ops->set_editable(tw,editable);
	
	pushTextWindow(L,tw);
	WSLUA_RETURN(1); /* The TextWindow object. */
}

typedef struct _wslua_bt_cb_t {
	lua_State* L;
	int func_ref;
	int data_ref;
} wslua_bt_cb_t;

static gboolean wslua_button_callback(funnel_text_window_t* tw, void* data) {
	wslua_bt_cb_t* cbd = data;
	lua_State* L = cbd->L;
	
	lua_settop(L,0);
	lua_pushcfunction(L,dlg_cb_error_handler);
	lua_rawgeti(L, LUA_REGISTRYINDEX, cbd->func_ref);
	pushTextWindow(L,tw);
	lua_rawgeti(L, LUA_REGISTRYINDEX, cbd->data_ref);
	
	switch ( lua_pcall(L,2,0,1) ) {
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
#define WSLUA_ARG_TextWindow_add_button_DATA 4 /* The data to be passed to the function (other than the window) */ 
	TextWindow tw = checkTextWindow(L,1);
	const gchar* label = luaL_checkstring(L,WSLUA_ARG_TextWindow_add_button_LABEL);
	
	funnel_bt_t* fbt;
	wslua_bt_cb_t* cbd;
	
	if (!tw)
		WSLUA_ERROR(TextWindow_at_close,"cannot be called for something not a TextWindow");
	
	if (! lua_isfunction(L,WSLUA_ARG_TextWindow_add_button_FUNCTION) )
		WSLUA_ARG_ERROR(TextWindow_add_button,FUNCTION,"must be a function");

	lua_settop(L,4);

	if (ops->add_button) {
		fbt = ep_alloc(sizeof(funnel_bt_t));
		cbd = ep_alloc(sizeof(wslua_bt_cb_t));

		fbt->tw = tw;
		fbt->func = wslua_button_callback;
		fbt->data = cbd;
		
		cbd->L = L;
		cbd->data_ref = luaL_ref(L, LUA_REGISTRYINDEX);
		cbd->func_ref = luaL_ref(L, LUA_REGISTRYINDEX);

		ops->add_button(tw,fbt,label);
	}
	
	pushTextWindow(L,tw);
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
		WSLUA_ERROR(wslua_retap_packets, "does not work on TShark");
	}
	
	return 0;
}


