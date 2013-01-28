/*
 *  uat-int.h
 *
 *  $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */
#ifndef _UAT_INT_H_
#define _UAT_INT_H_

#include "uat.h"

typedef struct _uat_fld_rep_t uat_fld_rep_t;
typedef struct _uat_rep_t uat_rep_t;

typedef void (*uat_rep_fld_free_cb_t)(uat_fld_rep_t*);
typedef void (*uat_rep_free_cb_t)(uat_rep_t*);

typedef struct _fld_data_t {
	guint colnum;
	uat_fld_rep_t* rep;
	uat_rep_fld_free_cb_t free_rep;
} fld_data_t;

struct _uat_t {
	const char* name;	
	size_t record_size;
	const char* filename;
	gboolean from_profile;
	const char* help;
	const char* category;
	void** user_ptr;
	guint* nrows_p;
	uat_copy_cb_t copy_cb;
	uat_update_cb_t update_cb;
	uat_free_cb_t free_cb;
	uat_post_update_cb_t post_update_cb;
	
	uat_field_t* fields;
	guint ncols;
	GArray* user_data;
	gboolean changed;
	uat_rep_t* rep;
	uat_rep_free_cb_t free_rep;
	gboolean loaded;
	gboolean from_global;
};

gchar* uat_get_actual_filename(uat_t* uat, gboolean for_writing);

void uat_init(void);

void uat_reset(void);

void* uat_add_record(uat_t*, const void* orig_rec_ptr);

void uat_swap(uat_t*, guint idx_a, guint idx_b);

void uat_remove_record_idx(uat_t*, guint rec_idx);

void uat_destroy(uat_t*);

void uat_clear(uat_t*);

gboolean uat_save(uat_t* , char** );

void uat_load_all(void);

#define UAT_UPDATE(uat) do { *((uat)->user_ptr) = (void*)((uat)->user_data->data); *((uat)->nrows_p) = (uat)->user_data->len; } while(0)
#define UAT_INDEX_PTR(uat,idx) (uat->user_data->data + (uat->record_size * (idx)))
#endif
