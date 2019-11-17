/* prefs-int.h
 * Definitions for implementation of preference handling routines;
 * used by "friends" of the preferences type.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PREFS_INT_H__
#define __PREFS_INT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

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
    unsigned int prefs_changed_flags;    /**< Bitmask of the types of changes done by module preferences since we last checked */
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
    unsigned int effect_flags;  /**< Flags of types effected by preference (PREF_TYPE_DISSECTION, PREF_EFFECT_CAPTURE, etc).
                                     These flags will be set in all module's preferences on creation. Flags must be non-zero
                                     to ensure saving to disk */
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
typedef prefs_set_pref_e (*pref_custom_set_cb) (pref_t* pref, const gchar* value, unsigned int* changed_flags);
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
#define PREF_UINT             (1u << 0)
#define PREF_BOOL             (1u << 1)
#define PREF_ENUM             (1u << 2)
#define PREF_STRING           (1u << 3)
#define PREF_RANGE            (1u << 4)
#define PREF_STATIC_TEXT      (1u << 5)
#define PREF_UAT              (1u << 6)
#define PREF_SAVE_FILENAME    (1u << 7)
#define PREF_COLOR            (1u << 8) /* XXX - These are only supported for "internal" (non-protocol) */
#define PREF_CUSTOM           (1u << 9) /* use and not as a generic protocol preference */
#define PREF_OBSOLETE         (1u << 10)
#define PREF_DIRNAME          (1u << 11)
#define PREF_DECODE_AS_UINT   (1u << 12)     /* XXX - These are only supported for "internal" (non-protocol) */
#define PREF_DECODE_AS_RANGE  (1u << 13) /* use and not as a generic protocol preference */
#define PREF_OPEN_FILENAME    (1u << 14)

typedef enum {
	GUI_ALL,
	GUI_GTK,
	GUI_QT
} gui_type_t;

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

WS_DLL_PUBLIC
const char* prefs_get_description(pref_t *pref);

WS_DLL_PUBLIC
const char* prefs_get_title(pref_t *pref);

WS_DLL_PUBLIC
const char* prefs_get_name(pref_t *pref);

WS_DLL_PUBLIC
int prefs_get_type(pref_t *pref);

WS_DLL_PUBLIC
gui_type_t prefs_get_gui_type(pref_t *pref);

WS_DLL_PUBLIC guint32 prefs_get_max_value(pref_t *pref);

/* Bitmask of flags for the effect of a preference in Wireshark */
#define PREF_EFFECT_DISSECTION        (1u << 0)
#define PREF_EFFECT_CAPTURE           (1u << 1)
#define PREF_EFFECT_GUI               (1u << 2)
#define PREF_EFFECT_FONT              (1u << 3)
#define PREF_EFFECT_GUI_LAYOUT        (1u << 4)
#define PREF_EFFECT_FIELDS            (1u << 5)
#define PREF_EFFECT_CUSTOM            (1u << 31)

/** Fetch flags that show the effect of the preference
 *
 * @param pref A preference.
 *
 * @return A bitmask of the types of things the preference will
 * effect.
 */
WS_DLL_PUBLIC
unsigned int prefs_get_effect_flags(pref_t *pref);

/** Set flags for the effect of the preference
 * The intention is to distinguish preferences that affect
 * dissection from those that don't. A bitmask was added to
 * provide greater flexibility in the types of effects
 * preferences can have.
 *
 * @param pref A preference.
 * @param flags Bitmask of flags to apply to preference. Note that flags
 * must be non-zero to ensure preference is properly saved to disk.
 *
 */
WS_DLL_PUBLIC
void prefs_set_effect_flags(pref_t *pref, unsigned int flags);

/** Same as prefs_set_effect_flags, just different way to get preference
 */
WS_DLL_PUBLIC
void prefs_set_effect_flags_by_name(module_t * module, const char *pref, unsigned int flags);

/** Fetch flags that show module's preferences effect
 * The flag values of the module will be applied to any individual preferences
 * of the module when they are created
 *
 * @param module A preference module.
 *
 * @return A bitmask of the types of things the module's preferences will
 * effect.
 */
WS_DLL_PUBLIC
unsigned int prefs_get_module_effect_flags(module_t * module);

/** Set flags for module's preferences effect
 * The intention is to distinguish preferences that affect
 * dissection from those that don't. Since modules are a grouping
 * of preferences, it's likely that a whole module will want the
 * same flags for its preferences. The flag values of the module will
 * be applied to any individual preferences of the module when they
 * are created
 *
 * @param module A preference module.
 * @param flags Bitmask of flags to apply to module. Note that flags
 * must be non-zero to ensure preferences are properly saved to disk.
 *
 */
WS_DLL_PUBLIC
void prefs_set_module_effect_flags(module_t * module, unsigned int flags);

WS_DLL_PUBLIC
gboolean prefs_set_range_value_work(pref_t *pref, const gchar *value,
                           gboolean return_range_errors, unsigned int *changed_flags);

WS_DLL_PUBLIC
unsigned int
prefs_set_stashed_range_value(pref_t *pref, const gchar *value);

/** Add a range value of a range preference. */
WS_DLL_PUBLIC
void
prefs_range_add_value(pref_t *pref, guint32 val);

/** Remove a range value of a range preference. */
WS_DLL_PUBLIC
void
prefs_range_remove_value(pref_t *pref, guint32 val);


WS_DLL_PUBLIC unsigned int prefs_set_bool_value(pref_t *pref, gboolean value, pref_source_t source);
WS_DLL_PUBLIC gboolean prefs_get_bool_value(pref_t *pref, pref_source_t source);
WS_DLL_PUBLIC void prefs_invert_bool_value(pref_t *pref, pref_source_t source);

WS_DLL_PUBLIC unsigned int prefs_set_uint_value(pref_t *pref, guint value, pref_source_t source);
WS_DLL_PUBLIC guint prefs_get_uint_base(pref_t *pref);
WS_DLL_PUBLIC guint prefs_get_uint_value_real(pref_t *pref, pref_source_t source);


WS_DLL_PUBLIC unsigned int prefs_set_enum_value(pref_t *pref, gint value, pref_source_t source);
WS_DLL_PUBLIC gint prefs_get_enum_value(pref_t *pref, pref_source_t source);
WS_DLL_PUBLIC const enum_val_t* prefs_get_enumvals(pref_t *pref);
WS_DLL_PUBLIC gboolean prefs_get_enum_radiobuttons(pref_t *pref);

WS_DLL_PUBLIC gboolean prefs_set_color_value(pref_t *pref, color_t value, pref_source_t source);
WS_DLL_PUBLIC color_t* prefs_get_color_value(pref_t *pref, pref_source_t source);

WS_DLL_PUBLIC unsigned int prefs_set_custom_value(pref_t *pref, const char *value, pref_source_t source);

WS_DLL_PUBLIC unsigned int prefs_set_string_value(pref_t *pref, const char* value, pref_source_t source);
WS_DLL_PUBLIC char* prefs_get_string_value(pref_t *pref, pref_source_t source);

WS_DLL_PUBLIC struct epan_uat* prefs_get_uat_value(pref_t *pref);

WS_DLL_PUBLIC gboolean prefs_set_range_value(pref_t *pref, range_t *value, pref_source_t source);
WS_DLL_PUBLIC range_t* prefs_get_range_value_real(pref_t *pref, pref_source_t source);

WS_DLL_PUBLIC gboolean prefs_add_decode_as_value(pref_t *pref, guint value, gboolean replace);
WS_DLL_PUBLIC gboolean prefs_remove_decode_as_value(pref_t *pref, guint value, gboolean set_default);

WS_DLL_PUBLIC void reset_pref(pref_t *pref);

/** read the preferences file (or similar) and call the callback
 * function to set each key/value pair found
 */
WS_DLL_PUBLIC
int
read_prefs_file(const char *pf_path, FILE *pf, pref_set_pair_cb pref_set_pair_fct, void *private_data);

WS_DLL_PUBLIC
gboolean
prefs_pref_is_default(pref_t *pref);

/** "Stash" a preference.
 * Copy a preference to its stashed value. Can be called from prefs_pref_foreach().
 *
 * @param pref A preference.
 * @param unused unused
 */
WS_DLL_PUBLIC
guint pref_stash(pref_t *pref, gpointer unused);

typedef struct pref_unstash_data
{
    /* Used to set prefs_changed member to TRUE if the preference
       differs from its stashed values. Also used by "decode as" types
       to look up dissector short name */
    module_t *module;
    /* Qt uses stashed values to then "applies" them
      during unstash.  Use this flag for that behavior */
    gboolean handle_decode_as;
} pref_unstash_data_t;

/** "Unstash" a preference.
 * Set a preference to its stashed value. Can be called from prefs_pref_foreach().
 *
 * @param pref A preference.
 * @param unstash_data_p A pointer to a pref_unstash_data_t structure.
 *
 * @return Always returns 0.
 */
WS_DLL_PUBLIC
guint pref_unstash(pref_t *pref, gpointer unstash_data_p);

/** Clean up a stashed preference.
 * Can be called from prefs_pref_foreach().
 *
 * @param pref A preference.
 * @param unused unused
 *
 * @return Always returns 0.
 */
WS_DLL_PUBLIC
guint pref_clean_stash(pref_t *pref, gpointer unused);

/** Set a stashed preference to its default value.
 *
 *@param pref A preference.
 */
WS_DLL_PUBLIC
void reset_stashed_pref(pref_t *pref);

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

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* prefs-int.h */
