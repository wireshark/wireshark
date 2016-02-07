/* prefs-int.h
 * Definitions for implementation of preference handling routines;
 * used by "friends" of the preferences type.
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

#ifndef __PREFS_INT_H__
#define __PREFS_INT_H__

#include <stdio.h>
#include "ws_symbol_export.h"
#include <epan/wmem/wmem.h>

/**
 *@file
 */

struct pref_module {
    const char *name;           /**< name of module */
    const char *title;          /**< title of module (displayed in preferences list) */
    const char *description;    /**< Description of module (displayed in preferences notebook) */
    void (*apply_cb)(void);     /**< routine to call when preferences applied */
    GList *prefs;               /**< list of its preferences */
    struct pref_module *parent; /**< parent module */
    wmem_tree_t *submodules;    /**< list of its submodules */
    int numprefs;               /**< number of non-obsolete preferences */
    gboolean prefs_changed;     /**< if TRUE, a preference has changed since we last checked */
    gboolean obsolete;          /**< if TRUE, this is a module that used to
                                 * exist but no longer does
                                 */
    gboolean use_gui;           /**< Determines whether or not the module will use the generic
                                  * GUI interface/APIs with the preference value or if its own
                                  * independent GUI will be provided.  This allows all preferences
                                  * to have a common API for reading/writing, but not require them to
                                  * use simple GUI controls to change the options.  In general, the "general"
                                  * Wireshark preferences should have this set to FALSE, while the protocol
                                  * modules will have this set to TRUE */
};

typedef struct {
    module_t *module;
    FILE     *pf;
} write_pref_arg_t;

/**
 * Module used for protocol preferences.
 * With MSVC and a libwireshark.dll, we need a special declaration.
 */
WS_DLL_PUBLIC module_t *protocols_module;

typedef void (*pref_custom_free_cb) (pref_t* pref);
typedef void (*pref_custom_reset_cb) (pref_t* pref);
typedef prefs_set_pref_e (*pref_custom_set_cb) (pref_t* pref, const gchar* value, gboolean* changed);
/* typedef void (*pref_custom_write_cb) (pref_t* pref, write_pref_arg_t* arg); Deprecated. */
/* pref_custom_type_name_cb should return NULL for internal / hidden preferences. */
typedef const char * (*pref_custom_type_name_cb) (void);
typedef char * (*pref_custom_type_description_cb) (void);
typedef gboolean (*pref_custom_is_default_cb) (pref_t* pref);
typedef char * (*pref_custom_to_str_cb) (pref_t* pref, gboolean default_val);

/** Structure to hold callbacks for PREF_CUSTOM type */
struct pref_custom_cbs {
    pref_custom_free_cb free_cb;
    pref_custom_reset_cb reset_cb;
    pref_custom_set_cb set_cb;
    /* pref_custom_write_cb write_cb; Deprecated. */
    pref_custom_type_name_cb type_name_cb;
    pref_custom_type_description_cb type_description_cb;
    pref_custom_is_default_cb is_default_cb;
    pref_custom_to_str_cb to_str_cb;
};

/**
 * PREF_OBSOLETE is used for preferences that a module used to support
 * but no longer supports; we give different error messages for them.
 */
#define PREF_UINT        (1u << 0)
#define PREF_BOOL        (1u << 1)
#define PREF_ENUM        (1u << 2)
#define PREF_STRING      (1u << 3)
#define PREF_RANGE       (1u << 4)
#define PREF_STATIC_TEXT (1u << 5)
#define PREF_UAT         (1u << 6)
#define PREF_FILENAME    (1u << 7)
#define PREF_COLOR       (1u << 8) /* XXX - These are only supported for "internal" (non-protocol) */
#define PREF_CUSTOM      (1u << 9) /* use and not as a generic protocol preference */
#define PREF_OBSOLETE    (1u << 10)
#define PREF_DIRNAME     (1u << 11)

typedef enum {
	GUI_ALL,
	GUI_GTK,
	GUI_QT
} gui_type_t;

/** Struct to hold preference data */
struct preference {
    const char *name;                /**< name of preference */
    const char *title;               /**< title to use in GUI */
    const char *description;         /**< human-readable description of preference */
    int ordinal;                     /**< ordinal number of this preference */
    int type;                        /**< type of that preference */
    gui_type_t gui;                  /**< type of the GUI (QT, GTK or both) the preference is registered for */
    union {                          /* The Qt preference code assumes that these will all be pointers (and unique) */
        guint *uint;
        gboolean *boolp;
        gint *enump;
        char **string;
        range_t **range;
        struct epan_uat* uat;
        color_t *colorp;
        GList** list;
    } varp;                          /**< pointer to variable storing the value */
    union {
        guint uint;
        gboolean boolval;
        gint enumval;
        char *string;
        range_t *range;
        color_t color;
        GList* list;
    } stashed_val;                     /**< original value, when editing from the GUI */
    union {
        guint uint;
        gboolean boolval;
        gint enumval;
        char *string;
        range_t *range;
        color_t color;
        GList* list;
    } default_val;                   /**< the default value of the preference */
    union {
      guint base;                    /**< input/output base, for PREF_UINT */
      guint32 max_value;             /**< maximum value of a range */
      struct {
        const enum_val_t *enumvals;  /**< list of name & values */
        gboolean radio_buttons;      /**< TRUE if it should be shown as
                                          radio buttons rather than as an
                                          option menu or combo box in
                                          the preferences tab */
      } enum_info;                   /**< for PREF_ENUM */
    } info;                          /**< display/text file information */
    struct pref_custom_cbs custom_cbs;   /**< for PREF_CUSTOM */
    void    *control;                /**< handle for GUI control for this preference. GTK+ only? */
};

/* read_prefs_file: read in a generic config file and do a callback to */
/* pref_set_pair_fct() for every key/value pair found */
/**
 * Given a string of the form "<pref name>:<pref value>", as might appear
 * as an argument to a "-o" option, parse it and set the preference in
 * question.
 * @return an indication of whether it succeeded or failed
 * in some fashion.
 */
typedef prefs_set_pref_e (*pref_set_pair_cb) (gchar *key, const gchar *value, void *private_data, gboolean return_range_errors);

/** Set the value of a string-like preference. */
WS_DLL_PUBLIC
void
prefs_set_string_like_value(pref_t *pref, const gchar *value, gboolean *changed);

/** Set the value of a range preference.  Return FALSE on error, TRUE otherwise. */
WS_DLL_PUBLIC
gboolean
prefs_set_range_value(pref_t *pref, const gchar *value, gboolean *changed);

/** Set the value of an enum preference. */
WS_DLL_PUBLIC
void
prefs_set_enum_value(pref_t *pref, const gchar *value, gboolean *changed);

/** read the preferences file (or similar) and call the callback
 * function to set each key/value pair found
 */
WS_DLL_PUBLIC
int
read_prefs_file(const char *pf_path, FILE *pf, pref_set_pair_cb pref_set_pair_fct, void *private_data);

/** Convert a string list preference to a preference string.
 *
 * Given a GList of gchar pointers, create a quoted, comma-separated
 * string. Should be used with prefs_get_string_list() and
 * prefs_clear_string_list().
 *
 * @param sl String list.
 * @return Quoted, joined, and wrapped string. May be empty.
 */
WS_DLL_PUBLIC
char *
join_string_list(GList *sl);

#endif /* prefs-int.h */
