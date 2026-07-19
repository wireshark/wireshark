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
#pragma once
#include <stdio.h>
#include "ws_symbol_export.h"
#include <epan/wmem_scopes.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 *@file
 */

/**
 * @brief Represents a preference module grouping related preferences under a named, hierarchical entry in the preferences system.
 */
struct pref_module {
    const char *name;           /**< name of module */
    const char *title;          /**< title of module (displayed in preferences list) */
    const char *description;    /**< Description of module (displayed in preferences notebook) */
    const char *help;           /**< Module help page (passed to user_guide_url() to generate a URL) */
    void (*apply_cb)(void);     /**< routine to call when preferences applied */
    wmem_allocator_t* scope;    /**< memory scope allocator for this module */
    GList *prefs;               /**< list of its preferences */
    struct pref_module *parent; /**< parent module */
    wmem_tree_t *submodules;    /**< list of its submodules */
    int numprefs;               /**< number of non-obsolete preferences */
    unsigned int prefs_changed_flags;    /**< Bitmask of the types of changes done by module preferences since we last checked */
    bool obsolete;              /**< if true, this is a module that used to
                                 * exist but no longer does
                                 */
    bool use_gui;               /**< Determines whether or not the module will use the generic
                                  * GUI interface/APIs with the preference value or if its own
                                  * independent GUI will be provided.  This allows all preferences
                                  * to have a common API for reading/writing, but not require them to
                                  * use simple GUI controls to change the options.  In general, the "general"
                                  * Wireshark preferences should have this set to false, while the protocol
                                  * modules will have this set to true */
    unsigned int effect_flags;  /**< Flags of types effected by preference (PREF_EFFECT_DISSECTION, PREF_EFFECT_CAPTURE, etc).
                                     These flags will be set in all module's preferences on creation. Flags must be non-zero
                                     to ensure saving to disk */
};

/**
 * @brief Bundles a preference module with a file handle for use during preference serialization.
 */
typedef struct {
    module_t* module; /**< The preference module whose preferences are being written. */
    FILE*     pf;     /**< The output file handle to which preferences are being written. */
} write_pref_arg_t;


/**
 * @brief Callback invoked to free any resources allocated by a custom preference.
 * @param pref The custom preference to free.
 */
typedef void (*pref_custom_free_cb)(pref_t* pref);

/**
 * @brief Callback invoked to reset a custom preference to its default value.
 * @param pref The custom preference to reset.
 */
typedef void (*pref_custom_reset_cb)(pref_t* pref);

/**
 * @brief Callback invoked to set a custom preference from a string value, reporting which flags changed.
 * @param pref          The custom preference to update.
 * @param value         The new value as a string to parse and apply.
 * @param changed_flags Bitmask updated to indicate which aspects of the preference changed.
 * @return A prefs_set_pref_e result code indicating success or the nature of any error.
 */
typedef prefs_set_pref_e (*pref_custom_set_cb)(pref_t* pref, const char* value, unsigned int* changed_flags);

/* typedef void (*pref_custom_write_cb) (pref_t* pref, write_pref_arg_t* arg); Deprecated. */

/**
 * @brief Callback that returns the type name string for a custom preference; returns NULL for internal or hidden preferences.
 * @return A string identifying the preference type, or NULL if the preference should be hidden.
 */
typedef const char* (*pref_custom_type_name_cb)(void);

/**
 * @brief Callback that returns a newly allocated human-readable description of a custom preference type.
 * @return A newly allocated string describing the preference type; caller is responsible for freeing it.
 */
typedef char* (*pref_custom_type_description_cb)(void);

/**
 * @brief Callback that reports whether a custom preference currently holds its default value.
 * @param pref The custom preference to check.
 * @return True if the preference is set to its default value, false otherwise.
 */
typedef bool (*pref_custom_is_default_cb)(pref_t* pref);

/**
 * @brief Callback that serializes a custom preference to a newly allocated string.
 * @param pref        The custom preference to serialize.
 * @param default_val True to serialize the default value, false to serialize the current value.
 * @return A newly allocated string representation of the preference value; caller is responsible for freeing it.
 */
typedef char* (*pref_custom_to_str_cb)(pref_t* pref, bool default_val);

/**
 * @brief Callback table for a PREF_CUSTOM preference, providing lifecycle and serialization hooks.
 */
struct pref_custom_cbs {
    pref_custom_free_cb             free_cb;             /**< Releases any resources owned by the custom preference value */
    pref_custom_reset_cb            reset_cb;            /**< Resets the custom preference to its default value */
    pref_custom_set_cb              set_cb;              /**< Parses and applies a new value to the custom preference */
    /* pref_custom_write_cb write_cb; Deprecated. */
    pref_custom_type_name_cb        type_name_cb;        /**< Returns a short type name string for the custom preference */
    pref_custom_type_description_cb type_description_cb; /**< Returns a human-readable description of the custom preference type */
    pref_custom_is_default_cb       is_default_cb;       /**< Returns true if the custom preference currently holds its default value */
    pref_custom_to_str_cb           to_str_cb;           /**< Serializes the current custom preference value to a string */
};


/**
 * @brief Discriminator tag identifying the type and UI representation of a preference entry.
 *
 * Annotations:
 * - (1) Not used in new code; retained for backward compatibility.
 * - (2) Like PREF_RANGE but also registers the value as a Decode As handler.
 * - (3) Value is stored but never written to the preferences file.
 * - (4) TCP simultaneous-open ambiguity resolution enum.
 * - (5) Selects a subdissector by name from a dissector table.
 */
typedef enum {
    PREF_UINT,               /**< Unsigned integer preference */
    PREF_BOOL,               /**< Boolean (true/false) preference */
    PREF_ENUM,               /**< Enumerated value preference, chosen from a fixed value_string list */
    PREF_STRING,             /**< Free-form string preference */
    PREF_RANGE,              /**< Port/value range preference (e.g., "80,443,8080-8090") */
    PREF_STATIC_TEXT,        /**< Non-editable informational label displayed in the preferences UI */
    PREF_UAT,                /**< User Accessible Table (UAT) preference */
    PREF_SAVE_FILENAME,      /**< File path preference for a file to be written/saved */
    PREF_COLOR,              /**< Color preference (1); not used in new code */
    PREF_CUSTOM,             /**< Custom preference with user-supplied callbacks (1); not used in new code */
    PREF_DIRNAME,            /**< Directory path preference */
    PREF_DECODE_AS_RANGE,    /**< Range preference that also registers a Decode As mapping (2) */
    PREF_OPEN_FILENAME,      /**< File path preference for a file to be read/opened */
    PREF_PASSWORD,           /**< Sensitive string preference; stored in memory but never persisted to disk (3) */
    PREF_PROTO_TCP_SNDAMB_ENUM, /**< Enum preference for resolving TCP simultaneous-open ambiguity (4) */
    PREF_DISSECTOR,          /**< Subdissector selection preference; names a dissector within a table (5) */
    PREF_INT,                /**< Signed integer preference */
    PREF_FLOAT               /**< Floating-point preference */
} pref_type_e;

/*
 * (1) These are only supported for "internal" (non-protocol) use
 *     and not as a generic protocol preference.
 * (2) Internal use only, not a generic protocol preference.
 * (3) Like string, but never saved to prefs file.
 * (4) Dedicated to TCP PROTOCOL for handling manual SEQ interpretation,
 *     and allow users manage the sender traffic ambiguities
 * (5) Like string, but with dissector name syntax check.
 */

/* read_prefs_file: read in a generic config file and do a callback to */
/* pref_set_pair_fct() for every key/value pair found */
/**
 * @brief Set a preference based on a key-value pair.
 *
 * Given a string of the form "<pref name>:<pref value>", as might appear
 * as an argument to a "-o" option, parse it and set the preference in
 * question.
 * @param key The name of the preference to set.
 * @param value The value to set the preference to.
 * @param private_data Private data to pass to the callback function.
 * @param return_range_errors If true, return errors related to range values.
 * @return an indication of whether it succeeded or failed
 * in some fashion.
 */
typedef prefs_set_pref_e (*pref_set_pair_cb) (char *key, const char *value, void *private_data, bool return_range_errors);

/**
 * @brief Get the description of a preference.
 *
 * @param pref Pointer to the preference structure.
 * @return Description of the preference.
 */
WS_DLL_PUBLIC
const char* prefs_get_description(pref_t *pref);

/**
 * @brief Get the title of a preference.
 *
 * @param pref Pointer to the preference structure.
 * @return Title of the preference.
 */
WS_DLL_PUBLIC
const char* prefs_get_title(pref_t *pref);

/**
 * @brief Fetch the name of a preference.
 * @param pref Pointer to the preference structure.
 * @return The name of the preference as a constant string.
 */
WS_DLL_PUBLIC
const char* prefs_get_name(pref_t *pref);

/**
 * @brief Retrieves the type of a preference.
 *
 * @param pref Pointer to the preference structure.
 * @return Type of the preference.
 */
WS_DLL_PUBLIC
int prefs_get_type(pref_t *pref);

/**
 * @brief Fetches the maximum value for a preference.
 *
 * @param pref Pointer to the preference structure.
 * @return The name of the preference as a constant string.
 */
WS_DLL_PUBLIC uint32_t prefs_get_max_value(pref_t *pref);

/**
 * @brief Fetch flags that show the effect of the preference
 *
 * @param pref A preference.
 *
 * @return A bitmask of the types of things the preference will
 * effect.
 */
WS_DLL_PUBLIC
unsigned int prefs_get_effect_flags(pref_t *pref);

/**
 * @brief Set flags for the effect of the preference
 *
 * The intention is to distinguish preferences that affect
 * dissection from those that don't. A bitmask was added to
 * provide greater flexibility in the types of effects
 * preferences can have.
 *
 * @param pref A preference.
 * @param flags Bitmask of flags to apply to preference. Note that flags
 * must be non-zero to ensure preference is properly saved to disk.
 */
WS_DLL_PUBLIC
void prefs_set_effect_flags(pref_t *pref, unsigned int flags);

/**
 * @brief Same as prefs_set_effect_flags, just different way to get preference
 * @param module A preference module.
 * @param pref The name of the preference to set the flags for.
 * @param flags Bitmask of flags to apply to preference. Note that flags
 * must be non-zero to ensure preference is properly saved to disk.
 */
WS_DLL_PUBLIC
void prefs_set_effect_flags_by_name(module_t * module, const char *pref, unsigned int flags);

/**
 * @brief Fetch flags that show module's preferences effect
 *
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

/**
 * @brief Iterate through all modules with preferences
 *
 * @param module_list The tree of modules to iterate through
 * @param callback The callback function to call for each module
 * @param user_data User data to pass to the callback function
 * @param skip_obsolete If true, skip obsolete preferences
 *
 * @return The return value of the callback function if it returns non-zero,
 *         otherwise 0
 */
WS_DLL_PUBLIC
unsigned prefs_module_list_foreach(const wmem_tree_t* module_list, module_cb callback,
    void* user_data, bool skip_obsolete);

/**
 * @brief Set flags for module's preferences effect
 *
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
 */
WS_DLL_PUBLIC
void prefs_set_module_effect_flags(module_t * module, unsigned int flags);


/**
 * @brief Set a range value for a range preference.
 *
 * @param pref Pointer to the preference structure.
 * @param value The new range value as a string.
 * @param return_range_errors If true, return errors related to range values.
 * @param changed_flags Pointer to store flags indicating changes.
 * @return True if the value was successfully set, false otherwise.
 */
WS_DLL_PUBLIC
bool prefs_set_range_value_work(pref_t *pref, const char *value,
                           bool return_range_errors, unsigned int *changed_flags);

/**
 * @brief Set a stashed range value for a preference.
 *
 * @param pref Pointer to the preference structure.
 * @param value String representation of the range value.
 * @return unsigned int Effect flags after setting the stashed value.
 */
WS_DLL_PUBLIC
unsigned int
prefs_set_stashed_range_value(pref_t *pref, const char *value);

/**
 * @brief Add a range value of a range preference.
 * @param pref Pointer to the preference structure.
 * @param val The value to add.
 */
WS_DLL_PUBLIC
void
prefs_range_add_value(pref_t *pref, uint32_t val);

/**
 * @brief Remove a range value of a range preference.
 * @param pref Pointer to the preference structure.
 * @param val The value to remove.
 */
WS_DLL_PUBLIC
void
prefs_range_remove_value(pref_t *pref, uint32_t val);

 /**
  * @brief Set a boolean preference value.
  *
  * @param pref Pointer to the preference structure.
  * @param value The new boolean value.
  * @param source The source of the preference change.
  * @return unsigned int Flags indicating changes made.
  */

WS_DLL_PUBLIC unsigned int prefs_set_bool_value(pref_t *pref, bool value, pref_source_t source);

/**
 * @brief Get the boolean value of a preference.
 *
 * @param pref Pointer to the preference structure.
 * @param source The source from which to retrieve the value (default, stashed, or current).
 * @return true if the preference is set to true, false otherwise.
 */
WS_DLL_PUBLIC bool prefs_get_bool_value(pref_t *pref, pref_source_t source);

/**
 * @brief Inverts the boolean value of a preference based on the specified source.
 *
 * @param pref Pointer to the preference structure.
 * @param source The source from which to invert the value (default, stashed, or current).
 */
WS_DLL_PUBLIC void prefs_invert_bool_value(pref_t *pref, pref_source_t source);

/**
 * @brief Set an unsigned integer preference value.
 *
 * @param pref Pointer to the preference structure.
 * @param value The new unsigned integer value.
 * @param source The source of the preference change (default, stashed, or current).
 * @return unsigned int Flags indicating the effect of the change.
 */
WS_DLL_PUBLIC unsigned int prefs_set_uint_value(pref_t *pref, unsigned value, pref_source_t source);

/**
 * @brief Get the base value of an unsigned integer preference.
 *
 * @param pref Pointer to the preference structure.
 * @return The base value of the unsigned integer preference.
 */
WS_DLL_PUBLIC unsigned prefs_get_uint_base(pref_t *pref);

/**
 * @brief Get the unsigned integer value of a preference.
 *
 * @param pref Pointer to the preference structure.
 * @param source The source from which to retrieve the value (default, stashed, or current).
 * @return The unsigned integer value of the preference.
 */
WS_DLL_PUBLIC unsigned prefs_get_uint_value(pref_t *pref, pref_source_t source);

/**
 * @brief Set an integer preference value.
 *
 * @param pref Pointer to the preference structure.
 * @param value The new integer value to set.
 * @param source The source of the preference change (default, stashed, or current).
 * @return unsigned int Flags indicating the effects of the change.
 */
WS_DLL_PUBLIC unsigned int prefs_set_int_value(pref_t* pref, int value, pref_source_t source);

/**
 * @brief Get the integer value of a preference based on the specified source.
 *
 * @param pref Pointer to the preference structure.
 * @param source The source from which to retrieve the value (default, stashed, or current).
 * @return int The integer value of the preference.
 */
WS_DLL_PUBLIC int prefs_get_int_value(pref_t* pref, pref_source_t source);

/**
 * @brief Set a float value for a preference.
 *
 * @param pref Pointer to the preference structure.
 * @param value The new float value to set.
 * @param source The source of the preference change (default, stashed, or current).
 * @return unsigned int Flags indicating the effect of the change.
 */
WS_DLL_PUBLIC unsigned int prefs_set_float_value(pref_t* pref, double value, pref_source_t source);

/**
 * @brief Get the float value of a preference.
 *
 * @param pref Pointer to the preference structure.
 * @param source The source from which to retrieve the value (default, stashed, or current).
 * @return double The float value of the preference.
 */
WS_DLL_PUBLIC double prefs_get_float_value(pref_t* pref, pref_source_t source);

 /**
  * @brief Set an enum preference value.
  *
  * @param pref Pointer to the preference structure.
  * @param value The new enum value.
  * @param source The source of the preference change.
  * @return unsigned int Flags indicating changes made.
  */

WS_DLL_PUBLIC unsigned int prefs_set_enum_value(pref_t *pref, int value, pref_source_t source);

/**
 * @brief Set an enum value for a preference.
 *
 * @param pref The preference to set.
 * @param value The string representation of the enum value.
 * @param source The source of the preference change.
 * @return unsigned int The new enum value.
 */
WS_DLL_PUBLIC unsigned int prefs_set_enum_string_value(pref_t *pref, const char *value, pref_source_t source);

/**
 * @brief Get the current value of an enumeration preference.
 *
 * @param pref Pointer to the preference structure.
 * @param source The source from which to retrieve the value (default, stashed, or current).
 * @return int The current value of the enumeration preference.
 */
WS_DLL_PUBLIC int prefs_get_enum_value(pref_t *pref, pref_source_t source);

/**
 * @brief Get the enumeration values for a preference.
 *
 * @param pref Pointer to the preference structure.
 * @return const enum_val_t* Pointer to the enumeration values.
 */
WS_DLL_PUBLIC const enum_val_t* prefs_get_enumvals(pref_t *pref);

/**
 * @brief Get the radio button values for an enumeration preference.
 *
 * @param pref Pointer to the preference structure.
 * @return bool True if the enumeration has radio buttons, false otherwise.
 */
WS_DLL_PUBLIC bool prefs_get_enum_radiobuttons(pref_t *pref);

/**
 * @brief Set a color value for a preference.
 *
 * @param pref Pointer to the preference structure.
 * @param value The new color value.
 * @param source The source of the preference value.
 * @return true if the value was changed, false otherwise.
 */
WS_DLL_PUBLIC bool prefs_set_color_value(pref_t *pref, color_t value, pref_source_t source);

/**
 * @brief Get the color value for a preference based on the specified source.
 *
 * @param pref The preference structure.
 * @param source The source of the preference value (default, stashed, or current).
 * @return Pointer to the color value.
 */
WS_DLL_PUBLIC color_t* prefs_get_color_value(pref_t *pref, pref_source_t source);

/**
 * @brief Set a custom value for a preference.
 *
 * @param pref Pointer to the preference structure.
 * @param value The new value to set.
 * @param source The source of the preference change.
 * @return unsigned int Number of preferences that have changed.
 */
WS_DLL_PUBLIC unsigned int prefs_set_custom_value(pref_t *pref, const char *value, pref_source_t source);

/**
 * @brief Set a string value for a preference.
 *
 * @param pref Pointer to the preference structure.
 * @param value The new string value to set.
 * @param source The source of the preference change.
 * @return Flags indicating changes, or 0 if no change.
 */
WS_DLL_PUBLIC unsigned int prefs_set_string_value(pref_t *pref, const char* value, pref_source_t source);

/**
 * @brief Get the string value of a preference.
 *
 * @param pref Pointer to the preference structure.
 * @param source The source from which to retrieve the value (default, stashed, or current).
 * @return The string value of the preference.
 */
WS_DLL_PUBLIC const char *prefs_get_string_value(pref_t *pref, pref_source_t source);

/**
 * @brief Get the UAT value for a preference.
 *
 * @param pref The preference to get the UAT value from.
 * @return Pointer to the UAT value, or NULL if not set.
 */
WS_DLL_PUBLIC struct epan_uat* prefs_get_uat_value(pref_t *pref);

/**
 * @brief Set a range value for a preference.
 *
 * @param pref Pointer to the preference structure.
 * @param value Pointer to the new range value.
 * @param source Source of the preference value (default, stashed, or current).
 * @return true if the value was changed, false otherwise.
 */
WS_DLL_PUBLIC bool prefs_set_range_value(pref_t *pref, range_t *value, pref_source_t source);

/**
 * @brief Get the range value for a preference based on the specified source.
 *
 * @param pref Pointer to the preference structure.
 * @param source The source of the preference value (default, stashed, or current).
 * @return Pointer to the range value of the preference.
 */
WS_DLL_PUBLIC range_t* prefs_get_range_value_real(pref_t *pref, pref_source_t source);

/**
 * @brief Adds or replaces a decode-as value for a preference.
 *
 * @param pref Pointer to the preference structure.
 * @param value The value to add or replace.
 * @param replace If true, replace the existing value if it exists.
 * @return True if the operation was successful, false otherwise.
 */
WS_DLL_PUBLIC bool prefs_add_decode_as_value(pref_t *pref, unsigned value, bool replace);

/**
 * @brief Removes a decode-as value from a preference.
 *
 * @param pref The preference to modify.
 * @param value The value to remove.
 * @param set_default Whether to set the default if the value is the only one in the range.
 * @return true If the operation was successful, false otherwise.
 */
WS_DLL_PUBLIC bool prefs_remove_decode_as_value(pref_t *pref, unsigned value, bool set_default);

/**
 * @brief Set a password value for a preference.
 *
 * @param pref Pointer to the preference structure.
 * @param value The new password value to set.
 * @param source The source of the preference change (default, stashed, or current).
 * @return unsigned int Flags indicating the effect of the change.
 */
WS_DLL_PUBLIC unsigned int prefs_set_password_value(pref_t *pref, const char* value, pref_source_t source);

/**
 * @brief Get the password value for a preference.
 *
 * @param pref The preference to get the value from.
 * @param source The source of the preference value.
 * @return const char* The password value, or NULL if not found.
 */
WS_DLL_PUBLIC const char *prefs_get_password_value(pref_t *pref, pref_source_t source);

 /**
  * @brief Add a list value to a preference.
  *
  * @param pref Pointer to the preference structure.
  * @param value The value to add to the list.
  * @param source The source of the preference value.
  * @return true if the value was added successfully, false otherwise.
  */
WS_DLL_PUBLIC bool prefs_add_list_value(pref_t *pref, void *value, pref_source_t source);

/**
 * @brief Get the list value for a preference based on the source.
 *
 * @param pref The preference to retrieve the list value from.
 * @param source The source of the preference value (default, stashed, or current).
 * @return GList* The list value corresponding to the preference and source.
 */
WS_DLL_PUBLIC GList* prefs_get_list_value(pref_t *pref, pref_source_t source);

/**
 * @brief Reset a preference to its default value.
 *
 * @param pref Pointer to the preference to be reset.
 */
WS_DLL_PUBLIC void reset_pref(pref_t *pref);

/**
 * @brief Get the list of all modules with preferences (used for iterating through all preferences)
 * @return The tree of modules with preferences.
 */
WS_DLL_PUBLIC const wmem_tree_t* prefs_get_module_tree(void);

/**
 * @brief Read the preferences file (or similar) and call the callback
 * function to set each key/value pair found
 *
 * @param pf_path The path to the preferences file.
 * @param pf The file pointer to the preferences file.
 * @param pref_set_pair_fct The callback function to set each key/value pair.
 * @param private_data User data to pass to the callback function.
 * @return The result of reading the preferences file, or an error code if it fails
 */
WS_DLL_PUBLIC
int
read_prefs_file(const char *pf_path, FILE *pf, pref_set_pair_cb pref_set_pair_fct, void *private_data);

/**
 * @brief Read the preferences for a specific module.
 *
 * Given a module name, read the preferences associated with only that module.
 * Checks for a file in the personal configuration directory named after the
 * module with a ".cfg" extension added first.
 *
 * @param name The preference module name, e.g. "extcap".
 * @param app_env_var_prefix The prefix for the application environment variable.
 */
WS_DLL_PUBLIC
void
prefs_read_module(const char *name, const char* app_env_var_prefix);

/**
 * @brief Check if a preference is at its default value.
 *
 * @param pref The preference to check.
 * @return true if the preference is at its default value, false otherwise.
 */
WS_DLL_PUBLIC
bool
prefs_pref_is_default(pref_t *pref);

/**
 * @brief "Stash" a preference.
 * Copy a preference to its stashed value. Can be called from prefs_pref_foreach().
 *
 * @param pref A preference.
 * @param unused unused
 */
WS_DLL_PUBLIC
unsigned pref_stash(pref_t *pref, void *unused);

/**
 * @brief Carries context data used when unstashing preferences back to their live values.
 */
typedef struct pref_unstash_data
{
    module_t* module;          /**< The preference module being unstashed; used to detect and flag any changes
                                    between the current and stashed preference values. */
    bool      handle_decode_as; /**< When true, stashed values are applied as "decode as" overrides during
                                     unstashing, matching the behavior required by the Qt preferences UI. */
} pref_unstash_data_t;

/**
 * @brief Get the effect_flags from a stashed preference.
 * Can be called from prefs_pref_foreach().
 *
 * @param pref A preference.
 * @param unstash_data_p A pointer to a pref_unstash_data_t structure.
 *
 * @return Always returns 0.
 */
WS_DLL_PUBLIC
unsigned pref_get_changed_flags(pref_t *pref, void *unstash_data_p);

/**
 * @brief "Unstash" a preference.
 * Set a preference to its stashed value. Can be called from prefs_pref_foreach().
 *
 * @param pref A preference.
 * @param unstash_data_p A pointer to a pref_unstash_data_t structure.
 *
 * @return Always returns 0.
 */
WS_DLL_PUBLIC
unsigned pref_unstash(pref_t *pref, void *unstash_data_p);

/**
 * @brief Clean up a stashed preference.
 * Can be called from prefs_pref_foreach().
 *
 * @param pref A preference.
 * @param unused unused
 *
 * @return Always returns 0.
 */
WS_DLL_PUBLIC
unsigned pref_clean_stash(pref_t *pref, void *unused);

/**
 * @brief Set a stashed preference to its default value.
 *
 *@param pref A preference.
 */
WS_DLL_PUBLIC
void reset_stashed_pref(pref_t *pref);

/**
 * @brief Convert a string list preference to a preference string.
 *
 * Given a GList of char pointers, create a quoted, comma-separated
 * string. Should be used with prefs_get_string_list() and
 * prefs_clear_string_list().
 *
 * @param sl String list.
 * @return Quoted, joined, and wrapped string. May be empty.
 */
WS_DLL_PUBLIC
char *
join_string_list(GList *sl);

/**
 * @brief Sanitize a string so that it can be written to a preference file.
 *
 * The preference file format (along with some other Wireshark file formats)
 * expects one entry per line. This takes a string, which may come from user
 * input, and converts line terminators (along with adjacent whitespace) into
 * a single space.
 */
WS_DLL_PUBLIC
char *
prefs_sanitize_string(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */
