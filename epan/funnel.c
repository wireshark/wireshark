/*
 *  funnel.c
 *
 * EPAN's GUI mini-API
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

#include <epan/funnel.h>

typedef struct _funnel_menu_t {
    const char *name;
    REGISTER_STAT_GROUP_E group;
    void (*callback)(gpointer);
    gpointer callback_data;
    gboolean retap;
    struct _funnel_menu_t* next;
} funnel_menu_t;

static const funnel_ops_t* ops = NULL;
static funnel_menu_t* menus = NULL;

const funnel_ops_t* funnel_get_funnel_ops() { return ops;  }
void funnel_set_funnel_ops(const funnel_ops_t* o) { ops = o; }

void funnel_register_menu(const char *name,
                          REGISTER_STAT_GROUP_E group,
                          void (*callback)(gpointer),
                          gpointer callback_data,
                          gboolean retap) {
    funnel_menu_t* m = g_malloc(sizeof(funnel_menu_t));
    m->name = g_strdup(name);
    m->group = group;
    m->callback = callback;
    m->callback_data = callback_data;
    m->retap = retap;
    m->next = NULL;
    
    if (!menus)  {
        menus = m;
    } else {
        funnel_menu_t* c;
        for (c = menus; c->next; c = c->next);
        c->next = m;
    }
}

void funnel_register_all_menus(funnel_registration_cb_t r_cb) {
    funnel_menu_t* c;
    for (c = menus; c; c = c->next) {
        r_cb(c->name,c->group,c->callback,c->callback_data,c->retap);
    }
}



