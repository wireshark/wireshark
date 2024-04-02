/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __IFACE_TOOLBAR_H__
#define __IFACE_TOOLBAR_H__

#include <stdbool.h>

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum {
    INTERFACE_TYPE_UNKNOWN,
    INTERFACE_TYPE_BOOLEAN,
    INTERFACE_TYPE_BUTTON,
    INTERFACE_TYPE_SELECTOR,
    INTERFACE_TYPE_STRING
} iface_toolbar_ctrl_type;

typedef enum {
    INTERFACE_ROLE_UNKNOWN,
    INTERFACE_ROLE_CONTROL,
    INTERFACE_ROLE_HELP,
    INTERFACE_ROLE_LOGGER,
    INTERFACE_ROLE_RESTORE
} iface_toolbar_ctrl_role;

typedef struct _iface_toolbar_value {
    int num;
    char *value;
    char *display;
    bool is_default;
} iface_toolbar_value;

typedef struct _iface_toolbar_control {
    int num;
    iface_toolbar_ctrl_type ctrl_type;
    iface_toolbar_ctrl_role ctrl_role;
    char *display;
    char *validation;
    bool is_required;
    char *tooltip;
    char *placeholder;
    union {
        bool boolean;
        char *string;
    } default_value;
    GList *values;
} iface_toolbar_control;

typedef struct _iface_toolbar {
    char *menu_title;
    char *help;
    GList *ifnames;
    GList *controls;
} iface_toolbar;

typedef void (*iface_toolbar_add_cb_t)(const iface_toolbar *);
typedef void (*iface_toolbar_remove_cb_t)(const char *);

void iface_toolbar_add(const iface_toolbar *toolbar);

void iface_toolbar_remove(const char *menu_title);

bool iface_toolbar_use(void);

void iface_toolbar_register_cb(iface_toolbar_add_cb_t, iface_toolbar_remove_cb_t);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __IFACE_TOOLBAR_H__ */
