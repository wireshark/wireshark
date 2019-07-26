/*
 *  uat-int.h
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
#ifndef __UAT_INT_H__
#define __UAT_INT_H__

#include "uat.h"
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _uat_fld_rep_t uat_fld_rep_t;
typedef struct _uat_rep_t uat_rep_t;

typedef void (*uat_rep_fld_free_cb_t)(uat_fld_rep_t*);
typedef void (*uat_rep_free_cb_t)(uat_rep_t*);

typedef struct _fld_data_t {
    guint colnum;
    uat_fld_rep_t* rep;
    uat_rep_fld_free_cb_t free_rep;
} fld_data_t;

struct epan_uat {
    char* name;
    size_t record_size;
    char* filename;
    gboolean from_profile;
    char* help;
    guint flags;
    void** user_ptr;    /**< Pointer to a dissector variable where an array of valid records are stored. */
    guint* nrows_p;     /**< Pointer to a dissector variable where the number of valid records in user_ptr are written. */
    uat_copy_cb_t copy_cb;
    uat_update_cb_t update_cb;
    uat_free_cb_t free_cb;
    uat_post_update_cb_t post_update_cb;
    uat_reset_cb_t reset_cb;

    uat_field_t* fields;
    guint ncols;
    GArray* user_data;  /**< An array of valid records that will be exposed to the dissector. */
    GArray* raw_data;   /**< An array of records containing possibly invalid data. For internal use only. */
    GArray* valid_data; /**< An array of booleans describing whether the records in 'raw_data' are valid or not. */
    gboolean changed;
    uat_rep_t* rep;
    uat_rep_free_cb_t free_rep;
    gboolean loaded;
    gboolean from_global;
};

WS_DLL_PUBLIC
gchar* uat_get_actual_filename(uat_t* uat, gboolean for_writing);

/**
 * Clones the given record and stores it internally in the UAT. If it is
 * considered a valid record, then it will also be cloned and stored in the
 * externally visible list.
 */
WS_DLL_PUBLIC
void* uat_add_record(uat_t *uat, const void *orig_rec_ptr, gboolean valid_rec);

/**
 * Marks the internal record in the UAT as valid or invalid. The record must
 * exist in the UAT.
 */
WS_DLL_PUBLIC
void uat_update_record(uat_t *uat, const void *record, gboolean valid_rec);

/**
 * Changes the order of two internal UAT records.
 */
WS_DLL_PUBLIC
void uat_swap(uat_t *uat, guint idx_a, guint idx_b);

/**
 * Inserts the record at the given index in the internal record list.
 */
WS_DLL_PUBLIC
void uat_insert_record_idx(uat_t *uat, guint rec_idx, const void *src_record);

/**
 * Removes the record with the given index from the internal record list.
 */
WS_DLL_PUBLIC
void uat_remove_record_idx(uat_t *uat, guint rec_idx);

/**
 * Moves the entry from the old position to the new one
 */
WS_DLL_PUBLIC
void uat_move_index(uat_t *uat, guint old_idx, guint new_idx);

/**
 * Removes and destroys all records from the UAT.
 */
WS_DLL_PUBLIC
void uat_clear(uat_t *uat);

/**
 * Saves the records from an UAT to file.
 * Returns TRUE on success and FALSE on failure, storing the reason in 'error'
 * (which must be freed using g_free).
 */
WS_DLL_PUBLIC
gboolean uat_save(uat_t *uat, char **error);

/**
 * Loads the records for all registered UATs from file.
 */
void uat_load_all(void);

/**
 * Dump given UAT record to string in form, which can be later loaded with uat_load_str().
 */
WS_DLL_PUBLIC
char *uat_fld_tostr(void *rec, uat_field_t *f);

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

#endif /* __UAT_INT_H__ */

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
