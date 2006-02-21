/*
 *  lua_gui.c
 *  
 * (c) 2006, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
 * 
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include "elua.h"

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

int lua_gui_enabled(lua_State* L) {
    lua_pushboolean(L,GPOINTER_TO_INT(ops));
    return 1;
}

void lua_menu_callback(gpointer data) {
    struct _lua_menu_data* md = data;

    lua_pushcfunction(md->L,menu_cb_error_handler);
    lua_rawgeti(md->L, LUA_REGISTRYINDEX, md->cb_ref);
    lua_rawgeti(md->L, LUA_REGISTRYINDEX, md->data_ref);
        
    lua_pcall(md->L,1,0,1);
    
    return;
}

ELUA_FUNCTION elua_register_menu(lua_State* L) { /*  Register a menu item in the Statistics menu. */
#define ELUA_ARG_register_menu_NAME 1 /* The name of the menu item. */
#define ELUA_ARG_register_menu_ACTION 2 /* The function to be called when the menu item is invoked. */
#define ELUA_OPTARG_register_menu_RETAP 3 /* Whether to rerun the packet list after the menu is invoked. */
#define ELUA_OPTARG_register_menu_USERDATA 4 /* To be passed to the action. */
	
    const gchar* name = luaL_checkstring(L,ELUA_ARG_register_menu_NAME);
    struct _lua_menu_data* md;
    gboolean retap = FALSE;
    
	if(!name)
		ELUA_ARG_ERROR(register_menu,NAME,"must be a string");
	
    if (!lua_isfunction(L,ELUA_ARG_register_menu_ACTION)) 
		ELUA_ARG_ERROR(register_menu,ACTION,"must be a function");
    
    md = g_malloc(sizeof(struct _lua_menu_data));
    md->L = L;
    
    lua_pushvalue(L, 2);
    md->cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    
    if ( lua_gettop(L) > 2) {
        retap = lua_toboolean(L,ELUA_OPTARG_register_menu_RETAP);
    }

    if ( lua_gettop(L) > 3) {
        lua_pushvalue(L, ELUA_OPTARG_register_menu_USERDATA);
        md->data_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    } else {
        md->data_ref = LUA_NOREF;
    }

    funnel_register_menu(name,
                         REGISTER_STAT_GROUP_GENERIC,
                         lua_menu_callback,
                         md,
                         retap);

    ELUA_FINAL_RETURN(0);
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

ELUA_FUNCTION elua_new_dialog(lua_State* L) { /* Pops up a new dialog */
#define ELUA_ARG_new_dialog_TITLE 1 /* Title of the dialog's window. */
#define ELUA_ARG_new_dialog_ACTION 1 /* Action to be performed when OKd. */
/* ELUA_EXTRARGS new_dialog : a series of strings to be used as labels of the dialog */

    const gchar* title;
    int top = lua_gettop(L);
    int i;
    GPtrArray* labels;
    struct _dlg_cb_data* dcbd;
    
    if (! ops) {
        luaL_error(L,"GUI not available");
        return 0;
    }
    
    if (! (title  = luaL_checkstring(L,ELUA_ARG_new_dialog_TITLE)) ) {
        ELUA_ARG_ERROR(new_dialog,TITLE,"must be a string");
        return 0;
    }
    
    if (! lua_isfunction(L,ELUA_ARG_new_dialog_ACTION)) {
        ELUA_ARG_ERROR(new_dialog,ACTION,"must be a function");
        return 0;
    }
    
    if (top < 3) {
        ELUA_ERROR(new_dialog,"at least one field required");
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
			ELUA_ERROR(new_dialog,"fields must be strings");
		
        g_ptr_array_add(labels,label);
    }
    
    g_ptr_array_add(labels,NULL);
    
    ops->new_dialog(title, (const gchar**)labels->pdata, lua_dialog_cb, dcbd);
    
    g_ptr_array_free(labels,TRUE);
    
    ELUA_FINAL_RETURN(0);
}



ELUA_CLASS_DEFINE(TextWindow,NOP) /* Manages a text window. */

ELUA_CONSTRUCTOR TextWindow_new(lua_State* L) { /* Creates a new TextWindow. */
#define ELUA_OPTARG_TextWindow_new_TITLE 1 /* Title of the new window. */

    const gchar* title;
    TextWindow tw;

	title = luaL_optstring(L,ELUA_OPTARG_TextWindow_new_TITLE,"Untitled Window");
    tw = ops->new_text_window(title);
    pushTextWindow(L,tw);
    
	ELUA_FINAL_RETURN(1); /* A TextWindow object */
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

ELUA_METHOD TextWindow_at_close(lua_State* L) { /* Set the function that will be called when the window closes */
#define ELUA_ARG_TextWindow_at_close_ACTION 2 /* A function to be executed when the user closes the window */

    TextWindow tw = shiftTextWindow(L,1);
    struct _close_cb_data* cbd;

    lua_settop(L,2);

    if (! lua_isfunction(L,1))
        ELUA_ARG_ERROR(TextWindow_at_close,ACTION,"must be a function");
    
    cbd = g_malloc(sizeof(struct _close_cb_data));

    cbd->L = L;
    cbd->data_ref = luaL_ref(L,  LUA_REGISTRYINDEX);
    cbd->func_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    
    ops->set_close_cb(tw,text_win_close_cb,cbd);
    
    pushTextWindow(L,tw);
	ELUA_FINAL_RETURN(1); /* The TextWindow object. */
}

ELUA_METHOD TextWindow_set(lua_State* L) { /* Sets the text. */
#define ELUA_ARG_TextWindow_set_TEXT 2 /* The text to be used. */

    TextWindow tw = shiftTextWindow(L,1);
    const gchar* text = luaL_checkstring(L,1);

    if (!text)
		ELUA_ARG_ERROR(TextWindow_set,TEXT,"must be a string");
    
    ops->set_text(tw,text);
    
    pushTextWindow(L,tw);
	ELUA_FINAL_RETURN(1); /* The TextWindow object. */
}

ELUA_METHOD TextWindow_append(lua_State* L) { /* Appends text */
#define ELUA_ARG_TextWindow_append_TEXT 2 /* The text to be appended */ 
    TextWindow tw = shiftTextWindow(L,1);
    const gchar* text = luaL_checkstring(L,1);
    
	if (!text)
		ELUA_ARG_ERROR(TextWindow_append,TEXT,"must be a string");

    ops->append_text(tw,text);
    
    pushTextWindow(L,tw);
	ELUA_FINAL_RETURN(1); /* The TextWindow object. */
}

ELUA_METHOD TextWindow_prepend(lua_State* L) { /* Prepends text */
#define ELUA_ARG_TextWindow_prepend_TEXT 2 /* The text to be appended */ 
    TextWindow tw = shiftTextWindow(L,1);
    const gchar* text = luaL_checkstring(L,1);
    
 	if (!text)
		ELUA_ARG_ERROR(TextWindow_prepend,TEXT,"must be a string");
   
    ops->prepend_text(tw,text);
    
    pushTextWindow(L,tw);
	ELUA_FINAL_RETURN(1); /* The TextWindow object. */
}

ELUA_METHOD TextWindow_clear(lua_State* L) { /* Errases all text in the window. */
    TextWindow tw = shiftTextWindow(L,1);
    
    ops->clear_text(tw);
    
    pushTextWindow(L,tw);
	ELUA_FINAL_RETURN(1); /* The TextWindow object. */
}

ELUA_METHOD TextWindow_get_text(lua_State* L) { /* Get the text of the window */
    TextWindow tw = shiftTextWindow(L,1);
    const gchar* text = ops->get_text(tw);
    
    lua_pushstring(L,text);
	ELUA_FINAL_RETURN(1); /* The TextWindow's text. */
}

static int TextWindow_gc(lua_State* L) {
    TextWindow tw = shiftTextWindow(L,1);
    
    ops->destroy_text_window(tw);
    return 1;
}


ELUA_METHODS TextWindow_methods[] = {
	ELUA_CLASS_FNREG(TextWindow,new),
	ELUA_CLASS_FNREG(TextWindow,set),
	ELUA_CLASS_FNREG(TextWindow,new),
	ELUA_CLASS_FNREG(TextWindow,append),
	ELUA_CLASS_FNREG(TextWindow,prepend),
	ELUA_CLASS_FNREG(TextWindow,clear),
	ELUA_CLASS_FNREG(TextWindow,at_close),
    {0, 0}
};

static const luaL_reg TextWindow_meta[] = {
    {"__tostring", TextWindow_get_text},
    {"__gc", TextWindow_gc},
    {0, 0}
};

int TextWindow_register(lua_State* L) {
    
    ops = funnel_get_funnel_ops();
    
	ELUA_REGISTER_CLASS(TextWindow);
    
    return 1;
}


