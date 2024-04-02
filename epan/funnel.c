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
#include <wsutil/glib-compat.h>

typedef struct _funnel_menu_t {
    char *name;
    register_stat_group_t group;
    funnel_menu_callback callback;
    void *callback_data;
    funnel_menu_callback_data_free callback_data_free;
    bool retap;
    struct _funnel_menu_t* next;
} funnel_menu_t;

typedef struct _console_menu {
    char *name;
    funnel_console_eval_cb_t eval_cb;
    funnel_console_open_cb_t open_cb;
    funnel_console_close_cb_t close_cb;
    void *user_data;
    funnel_console_data_free_cb_t data_free_cb;
} funnel_console_menu_t;

/* XXX This assumes one main window and one capture file. */
static const funnel_ops_t* ops;
static funnel_menu_t* registered_menus;
static funnel_menu_t* added_menus;
static funnel_menu_t* removed_menus;
static bool menus_registered;

/**
 * Represents a single packet menu entry and callback
 */
typedef struct _funnel_packet_menu_t {
    char *name;                           /**< Name to display in the GUI */
    char *required_fields;                /**< comma-separated list of fields
                                               that must be present for the
                                               packet menu to be displayed */
    funnel_packet_menu_callback callback; /**< Lua function to be called on
                                               menu item selection. */
    void *callback_data;                  /**< Lua state for the callback
                                               function */
    bool retap;                           /**< Whether or not to rescan the
                                               capture file's packets */
    struct _funnel_packet_menu_t* next;   /**< Pointer to the next
                                               _funnel_packet_menu_t for the
                                               singly-linked list
                                               implemenation */
} funnel_packet_menu_t;

/*
 * List of all registered funnel_packet_menu_t's
 */
static funnel_packet_menu_t* registered_packet_menus;

static GSList *registered_console_menus;

/*
 * true if the packet menus were modified since the last registration
 */
static bool packet_menus_modified;
static void funnel_clear_packet_menu (funnel_packet_menu_t** menu_list);

const funnel_ops_t* funnel_get_funnel_ops(void) { return ops;  }
void funnel_set_funnel_ops(const funnel_ops_t* o) { ops = o; }

static void funnel_clear_console_menu(void);

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
                          void *callback_data,
                          funnel_menu_callback_data_free callback_data_free,
                          bool retap)
{
    funnel_menu_t* m = g_new(funnel_menu_t, 1);
    m->name = g_strdup(name);
    m->group = group;
    m->callback = callback;
    m->callback_data = callback_data;
    m->callback_data_free = callback_data_free;
    m->retap = retap;
    m->next = NULL;

    funnel_insert_menu(&registered_menus, m);
    if (menus_registered) {
        funnel_menu_t* m_r = (funnel_menu_t *)g_memdup2(m, sizeof *m);
        m_r->name = g_strdup(name);
        funnel_insert_menu(&added_menus, m_r);
    }
}

void funnel_deregister_menus(funnel_menu_callback callback)
{
    funnel_menu_t* m = g_new0(funnel_menu_t, 1);
    m->callback = callback;

    funnel_remove_menu(&registered_menus, m);
    funnel_insert_menu(&removed_menus, m);

    // Clear and free memory of packet menus
    funnel_clear_packet_menu(&registered_packet_menus);
    packet_menus_modified = true;
}

void funnel_register_all_menus(funnel_registration_cb_t r_cb)
{
    funnel_menu_t* c;
    for (c = registered_menus; c; c = c->next) {
        r_cb(c->name,c->group,c->callback,c->callback_data,c->retap);
    }
    menus_registered = true;
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


/*
 * Inserts a funnel_packet_menu_t into a list of funnel_packet_menu_t's
 *
 * @param menu_list the list of menus that the menu will be added to
 * @param menu the menu to add to the list of menus
 */
static void funnel_insert_packet_menu (funnel_packet_menu_t** menu_list, funnel_packet_menu_t *menu)
{
    if (!(*menu_list))  {
        *menu_list = menu;
    } else {
        funnel_packet_menu_t* c;
        for (c = *menu_list; c->next; c = c->next);
        c->next = menu;
    }
}

/**
 * Entry point for Lua code to register a packet menu
 *
 * Stores the menu name and callback from the Lua code
 * into registered_packet_menus so that the
 * Wireshark GUI code can retrieve it with
 * funnel_register_all_packet_menus().
 */
void funnel_register_packet_menu(const char *name,
                                 const char *required_fields,
                                 funnel_packet_menu_callback callback,
                                 void *callback_data,
                                 bool retap)
{
    funnel_packet_menu_t* m = g_new0(funnel_packet_menu_t, 1);
    m->name = g_strdup(name);
    m->required_fields = g_strdup(required_fields);
    m->callback = callback;
    m->callback_data = callback_data;
    m->retap = retap;
    m->next = NULL;

    funnel_insert_packet_menu(&registered_packet_menus, m);
    packet_menus_modified = true;
}

/**
 * Clears a list of funnel_packet_menu_t's and free()s all associated memory
 *
 * @param menu_list the list of menus to clear
 */
static void funnel_clear_packet_menu (funnel_packet_menu_t** menu_list)
{
    funnel_packet_menu_t *m;

    while (*menu_list) {
        m = *menu_list;
        *menu_list = m->next;
        g_free(m->name);
        g_free(m->required_fields);
        if (m->callback_data) {
            g_free(m->callback_data);
        }
        g_free(m);
    }
    *menu_list = NULL;
}

/**
 * Entry point for Wireshark GUI to obtain all registered packet menus
 *
 * Calls the supplied callback for each packet menu registered with
 * funnel_register_packet_menu().
 *
 * @param r_cb the callback function to call with each registered packet menu
 */
void funnel_register_all_packet_menus(funnel_registration_packet_cb_t r_cb)
{
    funnel_packet_menu_t* c;
    for (c = registered_packet_menus; c; c = c->next) {
        r_cb(c->name,c->required_fields,c->callback,c->callback_data,c->retap);
    }
    packet_menus_modified = false;
}

/**
 * Returns whether the packet menus have been modified since they were last registered
 *
 * @return true if the packet menus were modified since the last registration
 */
bool funnel_packet_menus_modified(void)
{
    return packet_menus_modified;
}

void funnel_cleanup(void)
{
    funnel_clear_menu(&registered_menus);
    funnel_clear_packet_menu(&registered_packet_menus);
    funnel_clear_console_menu();
}

/**
 * Entry point for code to register a console menu
 */
void funnel_register_console_menu(const char *name,
                                funnel_console_eval_cb_t eval_cb,
                                funnel_console_open_cb_t open_cb,
                                funnel_console_close_cb_t close_cb,
                                void *callback_data,
                                funnel_console_data_free_cb_t free_data)
{
    funnel_console_menu_t* m = g_new0(funnel_console_menu_t, 1);
    m->name = g_strdup(name);
    m->eval_cb = eval_cb;
    m->open_cb = open_cb;
    m->close_cb = close_cb;
    m->user_data = callback_data;
    m->data_free_cb = free_data;

    registered_console_menus = g_slist_prepend(registered_console_menus, m);
}

void funnel_register_all_console_menus(funnel_registration_console_cb_t r_cb)
{
    GSList *l;
    for (l = registered_console_menus; l != NULL; l = l->next) {
        funnel_console_menu_t *m = l->data;
        r_cb(m->name, m->eval_cb, m->open_cb, m->close_cb, m->user_data);
    }
}

static void funnel_clear_console_menu(void)
{
    GSList *l;
    for (l = registered_console_menus; l != NULL; l = l->next) {
        funnel_console_menu_t *m = l->data;
        g_free(m->name);
        if (m->data_free_cb && m->user_data) {
            m->data_free_cb(m->user_data);
        }
        g_free(l->data);
        l->data = NULL;
    }
    g_slist_free(registered_console_menus);
    registered_console_menus = NULL;
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
