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

/**
 * @brief Data type of a toolbar control widget exposed by an interface toolbar.
 */
typedef enum {
    INTERFACE_TYPE_UNKNOWN,  /**< Type has not been set or is unrecognised */
    INTERFACE_TYPE_BOOLEAN,  /**< A toggle / checkbox control (true or false) */
    INTERFACE_TYPE_BUTTON,   /**< A momentary push-button control */
    INTERFACE_TYPE_SELECTOR, /**< A drop-down selector control with a fixed list of values */
    INTERFACE_TYPE_STRING    /**< A free-form text-entry control */
} iface_toolbar_ctrl_type;

/**
 * @brief Functional role of a toolbar control within the interface toolbar.
 */
typedef enum {
    INTERFACE_ROLE_UNKNOWN,  /**< Role has not been set or is unrecognised */
    INTERFACE_ROLE_CONTROL,  /**< Primary control that sends a value to the extcap interface */
    INTERFACE_ROLE_HELP,     /**< Opens a help resource for the toolbar */
    INTERFACE_ROLE_LOGGER,   /**< Displays log output from the extcap interface */
    INTERFACE_ROLE_RESTORE   /**< Restores all controls to their default values */
} iface_toolbar_ctrl_role;

/**
 * @brief A single selectable value entry for a selector-type toolbar control.
 */
typedef struct _iface_toolbar_value {
    int   num;        /**< Numeric identifier for this value, sent to the extcap interface */
    char *value;      /**< Machine-readable value string passed to the extcap interface */
    char *display;    /**< Human-readable label shown in the selector widget */
    bool  is_default; /**< True if this entry should be selected by default */
} iface_toolbar_value;

/**
 * @brief Describes a single control widget within an interface toolbar.
 */
typedef struct _iface_toolbar_control {
    int                     num;           /**< Numeric identifier for this control */
    iface_toolbar_ctrl_type ctrl_type;     /**< Widget type (boolean, button, selector, string) */
    iface_toolbar_ctrl_role ctrl_role;     /**< Functional role of this control */
    char                   *display;       /**< Label displayed next to the control */
    char                   *validation;    /**< Optional regex used to validate string input */
    bool                    is_required;   /**< True if the control must have a value before capture starts */
    char                   *tooltip;       /**< Tooltip text shown on hover */
    char                   *placeholder;   /**< Placeholder text for string controls when empty */
    union {
        bool  boolean; /**< Default value for a boolean control */
        char *string;  /**< Default value for a string or selector control */
    } default_value;   /**< Default value, interpreted according to @p ctrl_type */
    GList *values;     /**< Ordered list of ::iface_toolbar_value entries (selector controls only) */
} iface_toolbar_control;

/**
 * @brief Describes an interface toolbar and the set of controls it exposes.
 */
typedef struct _iface_toolbar {
    char  *menu_title; /**< Display name of the toolbar shown in the Interfaces menu */
    char  *help;       /**< URL or text providing help documentation for this toolbar */
    GList *ifnames;    /**< List of interface name strings this toolbar applies to */
    GList *controls;   /**< Ordered list of ::iface_toolbar_control widgets in this toolbar */
} iface_toolbar;

typedef void (*iface_toolbar_add_cb_t)(const iface_toolbar *);
typedef void (*iface_toolbar_remove_cb_t)(const char *);

/**
 * @brief Adds an interface toolbar to the application.
 *
 * @param toolbar Pointer to the interface toolbar structure to be added.
 */
void iface_toolbar_add(const iface_toolbar *toolbar);

/**
 * @brief Removes an interface toolbar item from the menu.
 *
 * @param menu_title The title of the menu item to remove.
 */
void iface_toolbar_remove(const char *menu_title);

/**
 * @brief Checks if the interface toolbar is in use.
 *
 * @return true if an add callback is registered, false otherwise.
 */
bool iface_toolbar_use(void);

/**
 * @brief Registers callback functions for interface toolbar operations.
 *
 * @param add_cb Callback function to be called when an item is added to the toolbar.
 * @param remove_cb Callback function to be called when an item is removed from the toolbar.
 */
void iface_toolbar_register_cb(iface_toolbar_add_cb_t add_cb, iface_toolbar_remove_cb_t remove_cb);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __IFACE_TOOLBAR_H__ */
