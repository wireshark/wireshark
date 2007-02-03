/*
 *  uat.c
 *
 * $Id$
 *
 *  User Accessible Tables
 *  Mantain an array of user accessible data strucures
 *
 * (c) 2007, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
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
 */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>

#include <glib.h>
#include <epan/emem.h>
#include <epan/report_err.h>
#include <epan/filesystem.h>
#include <epan/packet.h>

#include "uat-int.h"

static GPtrArray* all_uats = NULL;

void uat_init(void) {
	all_uats = g_ptr_array_new();
}

uat_t* uat_new(const char* name,
			   size_t size,
			   char* filename,
			   void** data_ptr,
			   guint* numitems_ptr,
			   uat_copy_cb_t copy_cb,
			   uat_update_cb_t update_cb,
			   uat_free_cb_t free_cb,
			   uat_field_t* flds_array) {
	uat_t* uat = g_malloc(sizeof(uat_t));
	guint i;
	
	if (!all_uats)
		all_uats = g_ptr_array_new();
	
	g_ptr_array_add(all_uats,uat);
	
	g_assert(name && size && filename && data_ptr && numitems_ptr);
	
	uat->name = g_strdup(name);
	uat->record_size = size;
	uat->filename = g_strdup(filename);
	uat->user_ptr = data_ptr;
	uat->nrows_p = numitems_ptr;
	uat->copy_cb = copy_cb;
	uat->update_cb = update_cb;
	uat->free_cb = free_cb;
	uat->fields = flds_array;
	uat->user_data = g_array_new(FALSE,FALSE,uat->record_size);
	uat->rep = NULL;
	uat->free_rep = NULL;
	
	for (i=0;flds_array[i].name;i++) {
		fld_data_t* f = g_malloc(sizeof(fld_data_t));
	
		f->colnum = i+1;
		f->rep = NULL;
		f->free_rep = NULL;
		
		flds_array[i].priv = f;
	}
	
	uat->ncols = i;
	
	
	*data_ptr = NULL;
	*numitems_ptr = 0;
	
	return uat;
}

void* uat_add_record(uat_t* uat, const void* data) {
	void* rec;

	g_array_append_vals (uat->user_data, data, 1);
	
	rec = uat->user_data->data + (uat->record_size * (uat->user_data->len-1));
	
	if (uat->copy_cb) {
		uat->copy_cb(rec, data, uat->record_size);
	}
	
	UAT_UPDATE(uat);
	
	return rec;
}

void uat_remove_record_idx(uat_t* uat, guint idx) {
	
	g_assert( idx < uat->user_data->len );

	if (uat->free_cb) {
		uat->free_cb(UAT_INDEX_PTR(uat,idx));
	}
	
	g_array_remove_index(uat->user_data, idx);
	
	UAT_UPDATE(uat);

}

gchar* uat_get_actual_filename(uat_t* uat, gboolean for_writing) {
	gchar* pers_fname =  get_persconffile_path(uat->filename,for_writing);

	if (! for_writing ) {
		gchar* data_fname = get_datafile_path(uat->filename);
		
		if (file_exists(data_fname)) {
			return data_fname;
		}
	}
	
	if ((! file_exists(pers_fname) ) && (! for_writing ) ) {
		return NULL;
	}
	
	return pers_fname;
}

static void putfld(FILE* fp, void* rec, uat_field_t* f) {
	guint fld_len;
	char* fld_ptr;
	
	f->cb.tostr(rec,&fld_ptr,&fld_len,f->cbdata.tostr,f->fld_data);
	
	switch(f->mode){
		case  PT_TXTMOD_STRING: {
			guint i;
			
			putc('"',fp);
			
			for(i=0;i<fld_len;i++) {
				char c = fld_ptr[i];
				
				if (c == '"') {
					fputs("\134\042",fp);
				} else if (isprint(c)) {
					putc(c,fp);
				} else {
					fprintf(fp,"\\x%.2x",c);
				}
			}
			
			putc('"',fp);
			return;
		}
		case PT_TXTMOD_HEXBYTES: {
			guint i;
			
			for(i=0;i<fld_len;i++) {
				fprintf(fp,"%.2x",fld_ptr[i]);
			}
			
			return;
		}
		default:
			g_assert_not_reached();
	}
}

gboolean uat_save(uat_t* uat, char** error) {
	guint i;
	gchar* fname = uat_get_actual_filename(uat,TRUE);
	FILE* fp;
	
	if (! fname ) return FALSE;

	fp = fopen(fname,"w");
	
	if (!fp) {
		*error = ep_strdup_printf("uat_save: error opening '%s': %s",fname,strerror(errno));
		return FALSE;
	}

	*error = NULL;

	for ( i = 0 ; i < uat->user_data->len ; i++ ) {
		void* rec = uat->user_data->data + (uat->record_size * i);
		uat_field_t* f;
		guint j;

		f = uat->fields;
		
			
		for( j=0 ; j < uat->ncols ; j++ ) {
			putfld(fp, rec, &(f[j]));
			fputs((j == uat->ncols - 1) ? "\n" : "," ,fp);
		}

	}

	fclose(fp);
	
	return TRUE;
}

void uat_destroy(uat_t* uat) {
	/* XXX still missing a destructor */
	g_ptr_array_remove(all_uats,uat);
	
}

void* uat_dup(uat_t* uat, guint* len_p) {
	guint size = (uat->record_size * uat->user_data->len);
	*len_p = size;
	return size ? g_memdup(uat->user_data->data,size) : NULL ;
}

void* uat_se_dup(uat_t* uat, guint* len_p) {
	guint size = (uat->record_size * uat->user_data->len);
	*len_p = size;
	return size ? se_memdup(uat->user_data->data,size) : NULL ;
}

void uat_cleanup(void) {
	while( all_uats->len ) {
		uat_destroy((uat_t*)all_uats->pdata);
	}

	g_ptr_array_free(all_uats,TRUE);
}

void uat_load_all(void) {
	guint i;
	gchar* err;
	
	for (i=0; i < all_uats->len; i++) {
		uat_t* u = g_ptr_array_index(all_uats,i);
		err = NULL;
		
		uat_load(u, &err);
		
		if (err) {
			report_failure("Error loading table '%s': %s",u->name,err);
		}
	}
}

gboolean uat_fld_chk_str(void* u1 _U_, const char* strptr, unsigned len _U_, void* u2 _U_, void* u3 _U_, char** err) {
	if (strptr == NULL) {
		*err = "NULL pointer";
		return FALSE;
	}
	
	*err = NULL;
	return TRUE;
}

gboolean uat_fld_chk_proto(void* u1 _U_, const char* strptr, unsigned len, void* u2 _U_, void* u3 _U_, char** err) {
	char* name = ep_strndup(strptr,len);
	g_strdown(name);
	g_strchug(name);
	if (find_dissector(name)) {
		*err = NULL;
		return TRUE;
	} else {
		*err = "dissector not found";
		return FALSE;
	}
}

gboolean uat_fld_chk_num_dec(void* u1 _U_, const char* strptr, unsigned len, void* u2 _U_, void* u3 _U_, char** err) {
	char* str = ep_strndup(strptr,len);
	long i = strtol(str,&str,10);
	
	if ( ( i == 0) && (errno == ERANGE || errno == EINVAL) ) {
		*err = strerror(errno);
		return FALSE;
	}
	
	*err = NULL;
	return TRUE;
}

gboolean uat_fld_chk_num_hex(void* u1 _U_, const char* strptr, unsigned len, void* u2 _U_, void* u3 _U_, char** err) {
	char* str = ep_strndup(strptr,len);
	long i = strtol(str,&str,16);
	
	if ( ( i == 0) && (errno == ERANGE || errno == EINVAL) ) {
		*err = strerror(errno);
		return FALSE;
	}
	
	*err = NULL;
	return TRUE;
}

CHK_STR_IS_DEF(isprint)
CHK_STR_IS_DEF(isalpha)
CHK_STR_IS_DEF(isalnum)
CHK_STR_IS_DEF(isdigit)
CHK_STR_IS_DEF(isxdigit)

