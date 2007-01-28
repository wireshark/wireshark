/*
 *  uat-int.h
 *
 *  User Accessible Tables
 *  Mantain an array of user accessible data strucures
 *  Internal interface
 *
 *  (c) 2007, Luis E. Garcia Ontanon
 *
 */
#ifndef _UAT_INT_H_
#define _UAT_INT_H_

#include "uat.h"

typedef struct _uat_fld_rep_t uat_fld_rep_t;
typedef struct _uat_rep_t uat_rep_t;

typedef void (*uat_rep_fld_free_cb_t)(uat_fld_rep_t*);
typedef void (*uat_rep_free_cb_t)(uat_rep_t*);

typedef struct _uat_fld_t {
	char* name;
	uat_text_mode_t mode;
	uat_fld_chk_cb_t chk_cb;
	uat_fld_set_cb_t set_cb;
	uat_fld_tostr_cb_t tostr_cb;
	
	guint colnum;
	uat_fld_rep_t* rep;
	uat_rep_fld_free_cb_t free_rep;
	
	struct _uat_fld_t* next;
} uat_fld_t;

struct _uat_t {
	char* name;	
	size_t record_size;
	char* filename;
	void** user_ptr;
	guint* nrows_p;
	uat_copy_cb_t copy_cb;
	uat_update_cb_t update_cb;
	uat_free_cb_t free_cb;

	uat_fld_t* fields;
	guint ncols;
	GArray* user_data;
	gboolean finalized;
	gboolean locked;
	
	uat_rep_t* rep;
	uat_rep_free_cb_t free_rep;
};

gchar* uat_get_actual_filename(uat_t* uat, gboolean for_writing);
void uat_init(void);
void uat_reset(void);
void* uat_add_record(uat_t*, const void* orig_rec_ptr);
void uat_remove_record_idx(uat_t*, guint rec_idx);
void uat_destroy(uat_t*);
gboolean uat_save(uat_t* dt, char** error);
gboolean uat_load(uat_t* dt, char** error);

#define UAT_UPDATE(uat) do { *((uat)->user_ptr) = (void*)((uat)->user_data->data); *((uat)->nrows_p) = (uat)->user_data->len; } while(0)

#endif
