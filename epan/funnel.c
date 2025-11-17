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
} funnel_menu_t;

typedef struct _console_menu {
    char *name;
    funnel_console_eval_cb_t eval_cb;
    funnel_console_open_cb_t open_cb;
    funnel_console_close_cb_t close_cb;
    void *user_data;
    funnel_console_data_free_cb_t data_free_cb;
} funnel_console_menu_t;

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
} funnel_packet_menu_t;


/* XXX This assumes one main window and one capture file. */
static const funnel_ops_t* ops;
static GSList* registered_menus;
static GSList* added_menus;
static GSList* removed_menus;
static bool menus_registered;

/*
 * List of all registered funnel_packet_menu_t's
 */
static GSList* registered_packet_menus;

static GSList* registered_console_menus;

/*
 * true if the packet menus were modified since the last registration
 */
static bool packet_menus_modified;

static void free_funnel_packet_menu(gpointer data, gpointer user_data);

const funnel_ops_t* funnel_get_funnel_ops(void) { return ops;  }

static void free_funnel_menu(gpointer data, gpointer user_data _U_) {
    funnel_menu_t* m = (funnel_menu_t*)data;
    g_free(m->name);
    if (m->callback_data_free) {
        m->callback_data_free(m->callback_data);
    }
    g_free(m);
}

static void funnel_remove_menu (GSList** menu_list, funnel_menu_t *menu)
{
    GSList* current = *menu_list;
    while (current != NULL)
    {
        GSList* next = current->next; // Store the next pointer BEFORE potentially removing current
        funnel_menu_t* m = (funnel_menu_t*)current->data;
        if (m->callback == menu->callback)
        {
            free_funnel_menu(m, NULL);
            *menu_list = g_slist_remove(*menu_list, current->data);
        }

        current = next; // Move to the stored next pointer
    }
}

static void funnel_clear_menu (GSList** menu_list, GFunc free_func)
{
    g_slist_foreach(*menu_list, free_func, NULL);
    g_slist_free(*menu_list);
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

    registered_menus = g_slist_append(registered_menus, m);
    if (menus_registered) {
        funnel_menu_t* m_r = (funnel_menu_t *)g_memdup2(m, sizeof *m);
        m_r->name = g_strdup(name);
        added_menus = g_slist_append(added_menus, m_r);
    }
}

void funnel_deregister_menus(funnel_menu_callback callback)
{
    funnel_menu_t* m = g_new0(funnel_menu_t, 1);
    m->callback = callback;

    funnel_remove_menu(&registered_menus, m);
    removed_menus = g_slist_append(removed_menus, m);

    // Clear and free memory of packet menus
    funnel_clear_menu(&registered_packet_menus, free_funnel_packet_menu);
    packet_menus_modified = true;
}

static void funnel_register_all_menus(funnel_registration_cb_t r_cb)
{
    if (r_cb == NULL)
        return;

    for (GSList* l = registered_menus; l; l = l->next)
    {
        funnel_menu_t* c = (funnel_menu_t*)l->data;
        r_cb(c->name,c->group,c->callback,c->callback_data,c->retap);
    }
}

void funnel_reload_menus(funnel_deregistration_cb_t d_cb,
                         funnel_registration_cb_t r_cb)
{
    GSList* l;
    for (l = removed_menus; l; l = l->next)
    {
        funnel_menu_t* c = (funnel_menu_t*)l->data;
        d_cb(c->callback);
    }
    for (l = added_menus; l; l = l->next)
    {
        funnel_menu_t* c = (funnel_menu_t*)l->data;
        r_cb(c->name,c->group,c->callback,c->callback_data,c->retap);
    }

    funnel_clear_menu(&removed_menus, free_funnel_menu);
    funnel_clear_menu(&added_menus, free_funnel_menu);
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

    registered_packet_menus = g_slist_append(registered_packet_menus, m);

    packet_menus_modified = true;
}

static void free_funnel_packet_menu(gpointer data, gpointer user_data _U_) {
    funnel_packet_menu_t* m = (funnel_packet_menu_t*)data;
    g_free(m->name);
    g_free(m->required_fields);
    if (m->callback_data) {
        g_free(m->callback_data);
    }
    g_free(m);
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
    for (GSList* l = registered_packet_menus; l; l = l->next)
    {
        funnel_packet_menu_t* c = (funnel_packet_menu_t*)l->data;
        r_cb(c->name, c->required_fields, c->callback, c->callback_data, c->retap);
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

static void funnel_register_all_console_menus(funnel_registration_console_cb_t r_cb)
{
    if (r_cb == NULL)
        return;

    GSList *l;
    for (l = registered_console_menus; l != NULL; l = l->next) {
        funnel_console_menu_t *m = l->data;
        r_cb(m->name, m->eval_cb, m->open_cb, m->close_cb, m->user_data);
    }
}

static void free_funnel_console_menu(gpointer data, gpointer user_data _U_)
{
    funnel_console_menu_t* m = data;
    g_free(m->name);
    if (m->data_free_cb) {
        m->data_free_cb(m->user_data);
    }
    g_free(m);
}

void funnel_ops_init(const funnel_ops_t* o, funnel_registration_cb_t r_cb, funnel_registration_console_cb_t rconsole_cb)
{
    ops = o;
    funnel_register_all_menus(r_cb);
    funnel_register_all_console_menus(rconsole_cb);
    menus_registered = true;
}

bool funnel_menu_registered(void)
{
    return menus_registered;
}

void funnel_cleanup(void)
{
    funnel_clear_menu(&registered_menus, free_funnel_menu);
    funnel_clear_menu(&registered_packet_menus, free_funnel_packet_menu);
    funnel_clear_menu(&registered_console_menus, free_funnel_console_menu);
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
