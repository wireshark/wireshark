/*
 *  funnel.c
 *
 * EPAN's GUI mini-API
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

#include <epan/funnel.h>

typedef struct _funnel_menu_t {
    char *name;
    register_stat_group_t group;
    funnel_menu_callback callback;
    gpointer callback_data;
    funnel_menu_callback_data_free callback_data_free;
    gboolean retap;
    struct _funnel_menu_t* next;
} funnel_menu_t;

/* XXX This assumes one main window and one capture file. */
static const funnel_ops_t* ops = NULL;
static funnel_menu_t* registered_menus = NULL;
static funnel_menu_t* added_menus = NULL;
static funnel_menu_t* removed_menus = NULL;
static gboolean menus_registered = FALSE;

const funnel_ops_t* funnel_get_funnel_ops(void) { return ops;  }
void funnel_set_funnel_ops(const funnel_ops_t* o) { ops = o; }

static void funnel_insert_menu (funnel_menu_t** menu_list, funnel_menu_t *menu)
{
    if (!(*menu_list))  {
        *menu_list = menu;
    } else {
        funnel_menu_t* c;
        for (c = *menu_list; c->next; c = c->next);
        c->next = menu;
    }
}

static void funnel_remove_menu (funnel_menu_t ** menu_list, funnel_menu_t *menu)
{
    funnel_menu_t *m = *menu_list, *p = NULL;

    while (m) {
        if (m->callback == menu->callback) {
            if (p) {
                p->next = m->next;
            } else {
                *menu_list = m->next;
            }
            g_free(m->name);
            if (m->callback_data_free) {
                m->callback_data_free(m->callback_data);
            }
            g_free(m);
            if (p) {
                m = p->next;
            } else {
                m = *menu_list;
            }
        } else {
            p = m;
            m = m->next;
        }
    }
}

static void funnel_clear_menu (funnel_menu_t** menu_list)
{
    funnel_menu_t *m;

    while (*menu_list) {
        m = *menu_list;
        *menu_list = m->next;
        g_free(m->name);
        g_free(m);
    }
    *menu_list = NULL;
}

void funnel_register_menu(const char *name,
                          register_stat_group_t group,
                          funnel_menu_callback callback,
                          gpointer callback_data,
                          funnel_menu_callback_data_free callback_data_free,
                          gboolean retap)
{
    funnel_menu_t* m = (funnel_menu_t *)g_malloc(sizeof(funnel_menu_t));
    m->name = g_strdup(name);
    m->group = group;
    m->callback = callback;
    m->callback_data = callback_data;
    m->callback_data_free = callback_data_free;
    m->retap = retap;
    m->next = NULL;

    funnel_insert_menu(&registered_menus, m);
    if (menus_registered) {
        funnel_menu_t* m_r = (funnel_menu_t *)g_memdup(m, sizeof *m);
        m_r->name = g_strdup(name);
        funnel_insert_menu(&added_menus, m_r);
    }
}

void funnel_deregister_menus(funnel_menu_callback callback)
{
    funnel_menu_t* m = (funnel_menu_t *)g_malloc0(sizeof(funnel_menu_t));
    m->callback = callback;

    funnel_remove_menu(&registered_menus, m);
    funnel_insert_menu(&removed_menus, m);
}

void funnel_register_all_menus(funnel_registration_cb_t r_cb)
{
    funnel_menu_t* c;
    for (c = registered_menus; c; c = c->next) {
        r_cb(c->name,c->group,c->callback,c->callback_data,c->retap);
    }
    menus_registered = TRUE;
}

void funnel_reload_menus(funnel_deregistration_cb_t d_cb,
                         funnel_registration_cb_t r_cb)
{
    funnel_menu_t* c;
    for (c = removed_menus; c; c = c->next) {
        d_cb(c->callback);
    }
    for (c = added_menus; c; c = c->next) {
        r_cb(c->name,c->group,c->callback,c->callback_data,c->retap);
    }

    funnel_clear_menu(&removed_menus);
    funnel_clear_menu(&added_menus);
}

void funnel_cleanup(void)
{
    funnel_clear_menu(&registered_menus);
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
