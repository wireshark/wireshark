/** @file
 *
 *  User Accessible Tables
 *  Maintain an array of user accessible data structures
 *  Internal interface
 *
 * (c) 2007, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#pragma once
#include <glib.h>

#include "uat.h"
#include "ws_symbol_export.h"

#include <wsutil/profile_inherit.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _uat_fld_rep_t uat_fld_rep_t;
typedef struct _uat_rep_t uat_rep_t;

typedef void (*uat_rep_fld_free_cb_t)(uat_fld_rep_t*);
typedef void (*uat_rep_free_cb_t)(uat_rep_t*);

/**
 * @brief Holds per-field display and cleanup state for a single column in a UAT record's GUI representation.
 */
typedef struct _fld_data_t {
    unsigned           colnum;   /**< Zero-based column index this field data corresponds to in the UAT table. */
    uat_fld_rep_t*     rep;      /**< Opaque GUI representation handle for this field's current display state. */
    uat_rep_fld_free_cb_t free_rep; /**< Callback used to release the GUI representation handle when no longer needed. */
} fld_data_t;

/**
 * @brief Represents a User Accessible Table (UAT), managing a set of user-editable records exposed to a dissector.
 */
struct epan_uat {
    char*                name;             /**< Internal name identifying this UAT, used for registration and file naming. */
    size_t               record_size;      /**< Size in bytes of a single UAT record struct. */
    char*                filename;         /**< Name of the file (within the profile directory) used to persist this UAT. */
    bool                 from_profile;     /**< True if this UAT is loaded from the current profile directory rather than the global config. */
    char*                help;             /**< Help topic identifier passed to user_guide_url() to generate documentation link. */
    unsigned             flags;            /**< Bitmask of UAT_* flags controlling behavior during load, save, and reset. */
    void**               user_ptr;         /**< Pointer to the dissector's array variable that receives the validated record array. */
    unsigned*            nrows_p;          /**< Pointer to the dissector's count variable that receives the number of valid records. */
    uat_copy_cb_t        copy_cb;          /**< Callback invoked to deep-copy a record's variable-length fields. */
    uat_update_cb_t      update_cb;        /**< Callback invoked to validate a record after editing; returns an error string on failure. */
    uat_free_cb_t        free_cb;          /**< Callback invoked to release variable-length fields owned by a record. */
    uat_post_update_cb_t post_update_cb;   /**< Callback invoked after the full UAT has been updated and validated. */
    uat_reset_cb_t       reset_cb;         /**< Callback invoked to reset the UAT to its default state. */

    uat_field_t*         fields;           /**< Array of field descriptors defining the columns of this UAT. */
    const char**         default_values;   /**< Array of default value strings, one per column, used when creating new records. */
    unsigned             ncols;            /**< Number of columns (fields) in each UAT record. */
    GArray*              user_data;        /**< Array of fully validated records exposed to the dissector via user_ptr. */
    GArray*              raw_data;         /**< Array of all records including potentially invalid ones; for internal UAT use only. */
    GArray*              valid_data;       /**< Parallel boolean array indicating whether each record in raw_data passed validation. */
    bool                 changed;          /**< True if the UAT has unsaved changes since it was last loaded or saved. */
    uat_rep_t*           rep;              /**< Opaque GUI representation handle for the UAT table as a whole. */
    uat_rep_free_cb_t    free_rep;         /**< Callback used to release the UAT-level GUI representation handle. */
    bool                 loaded;           /**< True if the UAT has been successfully loaded from its backing file. */
    GPtrArray*           sources;          /**< Parallel to raw_data: the parent profile a record is inherited from, or NULL for an own record. */
    profile_inherit_e    inherit_mode;     /**< Where the records come from, for a UAT loaded from the profile. */
    GArray*              key_fields;       /**< Indexes of the fields identifying a record when ignoring duplicates from parent profiles; empty for all fields. */
    int                  enabled_field;    /**< Index of a bool field which, if false, keeps a record from being inherited; -1 for none. */
    bool                 own_from_global;  /**< True if the own records were read from the global file, and are unchanged defaults. */
    bool                 loading_inherited; /**< True while reading a parent profile's file; its records are not exposed to the dissectors yet. */
    GHashTable*          override_keys;    /**< While adding inherited records for editing: the keys of the own records, which an inherited record with the same key is kept for, but not used; NULL otherwise. */
    bool                 own_read;         /**< True if the own records had records when read: the profile's file, or the global records used without one. Only then is a file without records written. */
};

/**
 * @brief Get the actual filename for the UAT.
 * @param uat The UAT for which to get the filename.
 * @param for_writing Whether the file is being written to.
 * @param app_env_var_prefix The prefix for the application environment variable.
 * @return A pointer to the actual filename string.
 */
WS_DLL_PUBLIC
char* uat_get_actual_filename(uat_t* uat, bool for_writing, const char* app_env_var_prefix);

/**
 * @brief Clones the given record and stores it internally in the UAT. If it is
 * considered a valid record, then it will also be cloned and stored in the
 * externally visible list.
 * @param uat The UAT to which the record will be added.
 * @param orig_rec_ptr Pointer to the record to be added.
 * @param valid_rec Whether the record is considered valid or not.
 * @return A pointer to the internal record stored in the UAT.
 */
WS_DLL_PUBLIC
void* uat_add_record(uat_t *uat, const void *orig_rec_ptr, bool valid_rec);

/**
 * @brief Marks the internal record in the UAT as valid or invalid. The record must
 * exist in the UAT.
 * @param uat The UAT containing the record.
 * @param record Pointer to the record to be updated.
 * @param valid_rec Whether the record is considered valid or not.
 */
WS_DLL_PUBLIC
void uat_update_record(uat_t *uat, const void *record, bool valid_rec);

/**
 * @brief Changes the order of two internal UAT records.
 * @param uat The UAT containing the records.
 * @param idx_a Index of the first record.
 * @param idx_b Index of the second record.
 */
WS_DLL_PUBLIC
void uat_swap(uat_t *uat, unsigned idx_a, unsigned idx_b);

/**
 * @brief Inserts the record at the given index in the internal record list.
 * @param uat The UAT containing the records.
 * @param rec_idx Index at which to insert the record.
 * @param src_record Pointer to the record to be inserted.
 */
WS_DLL_PUBLIC
void uat_insert_record_idx(uat_t *uat, unsigned rec_idx, const void *src_record);

/**
 * @brief Removes the record with the given index from the internal record list.
 * @param uat The UAT containing the records.
 * @param rec_idx Index of the record to be removed.
 */
WS_DLL_PUBLIC
void uat_remove_record_idx(uat_t *uat, unsigned rec_idx);

/**
 * @brief Removes the given number of records starting with the given index from
 * the internal record list. If the UAT has a free_cb it is called for
 * the removed records.
 * @param uat The UAT containing the records.
 * @param rec_idx Index of the first record to be removed.
 * @param count Number of records to be removed.
 */
WS_DLL_PUBLIC
void uat_remove_record_range(uat_t *uat, unsigned rec_idx, unsigned count);

/**
 * @brief Moves the entry from the old position to the new one
 * @param uat The UAT containing the records.
 * @param old_idx Index of the record to be moved.
 * @param new_idx Index where the record should be moved.
 */
WS_DLL_PUBLIC
void uat_move_index(uat_t *uat, unsigned old_idx, unsigned new_idx);

/**
 * @brief Removes and destroys all records from the UAT.
 * @param uat The UAT containing the records.
 */
WS_DLL_PUBLIC
void uat_clear(uat_t *uat);

/**
 * @brief Saves the records from an UAT to file.
 * Returns true on success and false on failure, storing the reason in 'error'
 * (which must be freed using g_free).
 * @param uat The UAT containing the records to be saved.
 * @param app_env_var_prefix The prefix of the environment variable to be used for the filename. The actual environment variable name will be this prefix followed by "_UAT_FILENAME". If the environment variable is not set, a default filename will be used.
 * @param error Pointer to a char* where an error message will be stored in case of failure. The caller is responsible for freeing this memory using g_free.
 * @return true on success, false on failure.
 */
WS_DLL_PUBLIC
bool uat_save(uat_t *uat, const char* app_env_var_prefix, char **error);

/**
 * @brief Loads records from a file, appending them to the UAT.
 *
 * Unlike uat_load(), this does not call the post update callback. Valid
 * records are appended to the records exposed to the dissectors as well,
 * which the caller may drop again.
 * @param uat The UAT.
 * @param fname The file to read.
 * @param errx Set to a g_malloc()'d error message on failure.
 * @param opened Set to true if the file was opened, even if reading it failed; may be NULL.
 * @return true on success.
 */
bool uat_load_file(uat_t *uat, const char *fname, char **errx, bool *opened);

/**
 * @brief Loads the records of a UAT from its profile file and the parent profiles.
 *
 * The profile's own records come first, then the records from the parent
 * profiles, nearest parent first. Records from a parent duplicating a record
 * from a nearer profile, or disabled in the parent, are not inherited.
 * @param uat The UAT, which should be empty.
 * @param mode The inherit mode.
 * @param app_env_var_prefix The prefix for the application environment variable.
 * @param errx Set to a g_malloc()'d error message on failure.
 * @return true on success.
 */
bool uat_load_inherited(uat_t *uat, profile_inherit_e mode, const char *app_env_var_prefix, char **errx);

/**
 * @brief Whether a record is inherited from a parent profile.
 * @param uat The UAT.
 * @param idx The index of the record.
 * @return true if inherited.
 */
WS_DLL_PUBLIC
bool uat_record_is_inherited(uat_t *uat, unsigned idx);

/**
 * @brief The parent profile a record is inherited from.
 * @param uat The UAT.
 * @param idx The index of the record.
 * @return The profile name, or NULL for an own record.
 */
WS_DLL_PUBLIC
const char *uat_record_source(uat_t *uat, unsigned idx);

/**
 * @brief The number of the profile's own records, which come first.
 * @param uat The UAT.
 * @return The number of own records.
 */
WS_DLL_PUBLIC
unsigned uat_own_count(uat_t *uat);

/**
 * @brief Selects where the records of a UAT come from, reloading the inherited records.
 *
 * In PROFILE_INHERIT_PARENT_ONLY mode the own records are removed, and the
 * profile's file is not written by uat_save(); another mode reads them again.
 * @param uat The UAT.
 * @param mode The inherit mode.
 * @param app_env_var_prefix The prefix for the application environment variable.
 * @param errx Set to a g_malloc()'d error message on failure.
 * @return true on success.
 */
WS_DLL_PUBLIC
bool uat_set_inherit_mode(uat_t *uat, profile_inherit_e mode, const char *app_env_var_prefix, char **errx);

/**
 * @brief Moves the records inherited from parent profiles after the own records.
 *
 * Used after appending own records, e.g. when copying from another profile.
 * The records exposed to the dissectors are updated if any moved.
 * @param uat The UAT.
 * @return true if any record moved.
 */
WS_DLL_PUBLIC
bool uat_move_inherited_last(uat_t *uat);

/**
 * @brief The key identifying a record when ignoring duplicates from parent profiles.
 * @param uat The UAT.
 * @param idx The index of the record.
 * @return A g_malloc()'d string.
 */
WS_DLL_PUBLIC
char *uat_record_key_string(uat_t *uat, unsigned idx);

/**
 * @brief Marks the own records as changed by the user.
 *
 * Own records read from the global file are otherwise taken as defaults,
 * which are dropped when the records are inherited from the parents.
 * @param uat The UAT.
 */
WS_DLL_PUBLIC
void uat_own_records_edited(uat_t *uat);

/**
 * @brief Removes the records inherited from parent profiles.
 * @param uat The UAT.
 */
WS_DLL_PUBLIC
void uat_remove_inherited_records(uat_t *uat);

/**
 * @brief Appends the records inherited from parent profiles for the selected mode.
 *
 * Records duplicating a record already in the UAT are not inherited, so
 * this is used to refresh the inherited records after own records changed.
 * @param uat The UAT, which should have no inherited records.
 * @param app_env_var_prefix The prefix for the application environment variable.
 * @param errx Set to a g_malloc()'d error message on failure.
 * @return true on success.
 */
WS_DLL_PUBLIC
bool uat_add_inherited_records(uat_t *uat, const char *app_env_var_prefix, char **errx);

/**
 * @brief Where the records of a UAT come from.
 * @param uat The UAT.
 * @return The inherit mode.
 */
WS_DLL_PUBLIC
profile_inherit_e uat_get_inherit_mode(uat_t *uat);

/**
 * @brief Loads the records for all registered UATs from file.
 * @param app_env_var_prefix The prefix of the environment variable to be used for the filename. The actual environment variable name will be this prefix followed by "_UAT_FILENAME". If the environment variable is not set, a default filename will be used.
 */
void uat_load_all(const char* app_env_var_prefix);

/**
 * @brief Dump given UAT record to string in form which can be later loaded with uat_load_str().
 *
 * XXX - In fact this only dumps a single field. To produce the format for
 * uat_load_str(), join all the fields as CSV records, escaping and double-
 * quoting field types other than PT_TXTMOD_HEXBYTES. Perhaps we should have
 * a function that dumps the entire record.
 *
 * @param rec Pointer to the record to be dumped.
 * @param f Pointer to the field to be dumped.
 * @return A g_malloced string containing the dumped field.
 */
WS_DLL_PUBLIC
char *uat_fld_tostr(void *rec, uat_field_t *f);

/**
 * @brief Dump UAT record entries to string in form which can be later loaded with uat_load_str().
 * Returns a g_malloced string.
 *
 * @param uat The UAT containing the record to be dumped.
 * @param rec Pointer to the record to be dumped.
 * @return A g_malloced string containing the dumped record.
 */
WS_DLL_PUBLIC
char *uat_record_tostr(const uat_t *uat, void *rec);

/**
 * Exposes the array of valid records to the UAT consumer (dissectors), updating
 * the contents of 'data_ptr' and 'num_items_ptr' (see 'uat_new').
 */
#define UAT_UPDATE(uat) do { *((uat)->user_ptr) = (void*)((uat)->user_data->data); *((uat)->nrows_p) = (uat)->user_data->len; } while(0)
/**
 * Get a record from the array of all UAT entries, whether they are semantically
 * valid or not. This memory must only be used internally in the UAT core and
 * must not be exposed to dissectors.
 */
#define UAT_INDEX_PTR(uat,idx) (uat->raw_data->data + (uat->record_size * (idx)))
/**
 * Get a record from the array of all valid entries. These records will be
 * shared with UAT consumers (dissectors).
 */
#define UAT_USER_INDEX_PTR(uat,idx) (uat->user_data->data + (uat->record_size * (idx)))

#ifdef __cplusplus
}
#endif /* __cplusplus */

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
