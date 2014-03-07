/*
 *  uat-int.h
 *
 *  User Accessible Tables
 *  Mantain an array of user accessible data strucures
 *  Internal interface
 *
 * (c) 2007, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
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
    const char* name;
    size_t record_size;
    const char* filename;
    gboolean from_profile;
    const char* help;
    guint flags;
    void** user_ptr;
    guint* nrows_p;
    uat_copy_cb_t copy_cb;
    uat_update_cb_t update_cb;
    uat_free_cb_t free_cb;
    uat_post_update_cb_t post_update_cb;

    uat_field_t* fields;
    guint ncols;
    GArray* user_data;
    GArray* raw_data;
    GArray* valid_data;
    gboolean changed;
    uat_rep_t* rep;
    uat_rep_free_cb_t free_rep;
    gboolean loaded;
    gboolean from_global;
};

WS_DLL_PUBLIC
gchar* uat_get_actual_filename(uat_t* uat, gboolean for_writing);

void uat_init(void);

void uat_reset(void);

WS_DLL_PUBLIC
void* uat_add_record(uat_t*, const void* orig_rec_ptr, gboolean valid_rec);

WS_DLL_PUBLIC
void uat_swap(uat_t*, guint idx_a, guint idx_b);

WS_DLL_PUBLIC
void uat_remove_record_idx(uat_t*, guint rec_idx);

void uat_destroy(uat_t*);

WS_DLL_PUBLIC
void uat_clear(uat_t*);

WS_DLL_PUBLIC
gboolean uat_save(uat_t* , const char** );

void uat_load_all(void);

#define UAT_UPDATE(uat) do { *((uat)->user_ptr) = (void*)((uat)->user_data->data); *((uat)->nrows_p) = (uat)->user_data->len; } while(0)
#define UAT_INDEX_PTR(uat,idx) (uat->raw_data->data + (uat->record_size * (idx)))
#define UAT_USER_INDEX_PTR(uat,idx) (uat->user_data->data + (uat->record_size * (idx)))

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UAT_INT_H__ */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
