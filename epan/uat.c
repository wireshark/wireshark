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
#include <epan/filesystem.h>

#include "uat-int.h"

static GPtrArray* all_uats = NULL;

void uat_init(void) {
	all_uats = g_ptr_array_new();
}

uat_t* uat_start(const char* name,
				 size_t size,
				 char* filename,
				 void** data_ptr,
				 guint* num_items_ptr,
				 uat_copy_cb_t copy_cb,
				 uat_update_cb_t update_cb,
				 uat_free_cb_t free_cb) {
	
	uat_t* uat = g_malloc(sizeof(uat_t));
	g_ptr_array_add(all_uats,uat);
	
	g_assert(name && size && filename && data_ptr && num_items_ptr);
	
	uat->name = g_strdup(name);
	uat->record_size = size;
	uat->filename = g_strdup(filename);
	uat->user_ptr = data_ptr;
	uat->nrows_p = num_items_ptr;
	uat->copy_cb = copy_cb;
	uat->update_cb = update_cb;
	uat->free_cb = free_cb;
	
	uat->fields = NULL;
	uat->ncols = 0;
	uat->user_data = g_array_new(FALSE,FALSE,uat->record_size);
	uat->finalized = FALSE;
	uat->rep = NULL;
	uat->free_rep = NULL;
	
	return uat;
}

void uat_add_field(uat_t* uat,
				   const char* name,
				   uat_text_mode_t mode,
				   uat_fld_chk_cb_t chk_cb,
				   uat_fld_set_cb_t set_cb,
				   uat_fld_tostr_cb_t tostr_cb) {
	
	uat_fld_t* f = g_malloc(sizeof(uat_fld_t));

	g_assert( name && set_cb && tostr_cb && (! uat->finalized ) 
			  && (mode == PT_TXTMOD_STRING || mode == PT_TXTMOD_HEXBYTES) );
	
	f->name = g_strdup(name);
	f->mode = mode;
	f->chk_cb = chk_cb;
	f->set_cb = set_cb;
	f->tostr_cb = tostr_cb;

	f->rep = NULL;
	f->free_rep = NULL;	
	f->colnum = uat->ncols;
	f->next = NULL;

	uat->ncols++;
	
	if (uat->fields) {
		uat_fld_t* c;
		for (c = uat->fields; c->next; c = c->next) ;
		c->next = f;
	} else {
		uat->fields = f;	
	}
}

void uat_finalize(uat_t* uat) {
	UAT_UPDATE(uat);
	uat->finalized = TRUE;
}

uat_t* uat_new(const char* uat_name,
			   size_t size,
			   char* filename,
			   void** data_ptr,
			   guint* numitems_ptr,
			   uat_copy_cb_t copy_cb,
			   uat_update_cb_t update_cb,
			   uat_free_cb_t free_cb,
			   char** error,
			   ...) {
	uat_t* uat = uat_start(uat_name, size, filename, data_ptr, numitems_ptr, copy_cb, update_cb, free_cb);
	va_list ap;
	char* name;
	uat_text_mode_t mode;
	uat_fld_chk_cb_t chk_cb;
	uat_fld_set_cb_t set_cb;
	uat_fld_tostr_cb_t tostr_cb;
	va_start(ap,error);
	
	name = va_arg(ap,char*);
	
	do {
		mode = va_arg(ap,uat_text_mode_t);
		chk_cb = va_arg(ap,uat_fld_chk_cb_t);
		set_cb = va_arg(ap,uat_fld_set_cb_t);
		tostr_cb = va_arg(ap,uat_fld_tostr_cb_t);

		uat_add_field(uat, name, mode, chk_cb, set_cb, tostr_cb);
		
		name = va_arg(ap,char*);
	} while (name);
	
	va_end(ap);
	
	uat_finalize(uat);
	
	uat_load(uat,error);
	
	return uat;
}

void* uat_add_record(uat_t* uat, const void* data) {
	void* rec;
	
	g_assert( uat->finalized );
	
	g_array_append_vals (uat->user_data, data, 1);
	
	rec = uat->user_data->data + (uat->record_size * (uat->user_data->len-1));
	
	if (uat->copy_cb) {
		uat->copy_cb(rec, data, uat->record_size);
	}
	
	
	UAT_UPDATE(uat);
	
	return rec;
}

void uat_remove_record_idx(uat_t* uat, guint idx) {
	
	g_assert( uat->finalized && idx < uat->user_data->len);

	g_array_remove_index(uat->user_data, idx);
	
	UAT_UPDATE(uat);

}


gchar* uat_get_actual_filename(uat_t* uat, gboolean for_writing) {
	gchar* pers_fname =  get_persconffile_path(uat->filename,for_writing);
	
	if (! file_exists(pers_fname)) {
		gchar* data_fname = get_datafile_path(uat->filename);
		
		if (file_exists(data_fname)) {
			return data_fname;
		}
	}
	
	return pers_fname;
}

static void putfld(FILE* fp, void* rec, uat_fld_t* f) {
	guint fld_len;
	char* fld_ptr;
	
	f->tostr_cb(rec,&fld_ptr,&fld_len);
	
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
	FILE* fp = fopen(fname,"w");
	

	if (!fp) {
		*error = ep_strdup_printf("uat_save: error opening '%s': %s",fname,strerror(errno));
		return FALSE;
	}

	*error = NULL;

	for ( i = 0 ; i < uat->user_data->len - 1 ; i++ ) {
		void* rec = uat->user_data->data + (uat->record_size * (uat->user_data->len-1));
		uat_fld_t* f;
		
		f = uat->fields;
		
		putfld(fp, rec, f);
			
		while (( f = f->next )) {
			fputs(",",fp);
			putfld(fp, rec, f);				
		}

		fputs("\n",fp);
	}

	fclose(fp);
	
	return TRUE;
}

void uat_destroy(uat_t* uat) {
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

