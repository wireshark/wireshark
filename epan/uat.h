/*
 *  uat.h
 *
 *  User Accessible Tables
 *  Mantain an array of user accessible data strucures
 *  
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

#ifndef _UAT_H_
#define _UAT_H_

/*
 * uat mantains a dynamically allocated table accessible to the user
 * via a file and/or gui tables.
 *
 * the file is located either in userdir(when first read or when writen) or
 * in datadir for defaults (read only , it will be always written to userdir).
 *
 * the behaviour of the table is controlled by a series of callbacks
 * the caller must provide.
 *
 * BEWARE that the user can change an uat at (almost) any time, 
 * That is pointers to records in an uat are valid only during the call
 * to the function that obtains them (do not store them).
 *
 * UATs are meant for short tables of user data (passwords and such) there's
 * no quick access, you must iterate through them each time to fetch the record
 * you are looking for. Use uat_dup() or uat_se_dup() if necessary.
 *
 * Only users via gui or editing the file can add/remove records your code cannot.
 */

/* obscure data type to handle an uat */
typedef struct _uat_t uat_t;

/********************************************
 * Callbacks:
 * these instruct uat on how to deal with user info and data in records
 ********************************************/

/********
 * Callbacks for the entire table (these deal with entire records)
 ********/

/*
 * Copy CB
 * used to copy a record
 * optional, memcpy will be used if not given
 * copy(dest,orig,len)
 */
typedef void* (*uat_copy_cb_t)(void*, const void*, unsigned);

/*
 *
 * Free CB
 *
 * destroy a record's child data
 * (do not free the container, it will be handled by uat)
 * it is optional, no child data will be freed if no present
 * free(record)
 */
typedef void (*uat_free_cb_t)(void*);

/*
 * Update CB
 *
 * to be called after all record fields has been updated
 * optional, record will be updated always if not given
 * update(record,&error)
 */
typedef void (*uat_update_cb_t)(void* , char** );


/*******
 * Callbacks for single fields (these deal with single values)
 * the caller should provide one of these for every field!
 ********/

/* 
 * given an input string (ptr, len) checks if the value is OK for a field in the record.
 * it will return TRUE if OK or else
 * it will return FALSE and may set *error to inform the user on what's
 * wrong with the given input
 * optional, if not given any input is considered OK and the set cb will be called
 * chk(record, ptr, len, &error)
 */
typedef gboolean (*uat_fld_chk_cb_t)(void*, const char*, unsigned, char**);

/*
 * Set Field CB
 *
 * given an input string (ptr, len) sets the value of a field in the record,
 * it will return TRUE if OK or else
 * it will return FALSE and may set *error to inform the user on what's
 * wrong with the given input
 * it is mandatory
 * set(record, ptr, len)
 */
typedef void (*uat_fld_set_cb_t)(void*, const char*, unsigned);

/*
 * given a record returns a string representation of the field
 * mandatory
 * tostr(record, &ptr, &len)
 */
typedef void (*uat_fld_tostr_cb_t)(void*, char**, unsigned*);




/*********** 
 * Text Mode
 *
 * used for file and dialog representation of fileds in columns,
 * when the file is read it modifies the way the value is passed back to the fld_set_cb 
 * (see definition bellow for description)
 ***********/

typedef enum _uat_text_mode_t {
	PT_TXTMOD_NONE,
	/* not used */
	
	PT_TXTMOD_STRING,
	/*
	 file:
		 reads:
			 ,"\x20\x00\x30", as " \00",3
			 ,"", as "",0
			 ,, as NULL,0
		 writes:
			 ,"\x20\x30\x00\x20", for " 0\0 ",4
			 ,"", for *, 0
			 ,, for NULL, *
	 dialog:
		 accepts \x?? and other escapes
		 gets "",0 on empty string
	 */
	PT_TXTMOD_HEXBYTES,
	/*
	 file:
		 reads:
			 ,A1b2C3d4, as "\001\002\003\004",4
			 ,, as NULL,0
		 writes:
			 ,, on NULL, *
			 ,a1b2c3d4, on "\001\002\003\004",4
	 dialog:
		 "a1b2c3d4" as "\001\002\003\004",4
		 "a1 b2:c3d4" as "\001\002\003\004",4
		 "" as NULL,0
		 "invalid" as NULL,3
		 "a1b" as NULL, 1
	 */
} uat_text_mode_t;


/*
 * uat_new()
 *
 * creates a new uat
 *
 * name: the name of the table
 *
 * data_ptr: a pointer to a null terminated array of pointers to the data
 *
 * default_data: a pinter to a struct containing default values
 *
 * size: the size of the structure
 *
 * filename: the filename to be used (either in userdir or datadir)
 *
 * copy_cb: a function that copies the data in the struct
 *
 * update_cb: will be called when a record is updated
 *
 * free_cb: will be called to destroy a struct in the dataset
 *
 *
 * followed by a list of N quintuplets terminated by a NULL, each quituplet has:
 *
 *   field_name: a string with the name of the field ([a-zA-Z0-9_-]+)
 *
 *   field_mode: see comments for enum _uat_text_mode_t below
 *
 *   field_chk_cb: a function that given a string will check the given value 
 *
 *   field_set_cb: a function that given a string will set the value in the data structure
 * 
 *   field_tostr_cb: a function that given a record generates a string,len pair representing this file
 * 
 */
uat_t* uat_new(const char* name,
			   size_t size,
			   char* filename,
			   void** data_ptr,
			   guint* num_items,
			   uat_copy_cb_t copy_cb,
			   uat_update_cb_t update_cb,
			   uat_free_cb_t free_cb,
			   char** error,
			   ...);


/* 
 * uat_start()
 * as uat_new() but leaves the dyntable without fields
 */
uat_t* uat_start(const char* name,
				 size_t size,
				 char* filename,
				 void** data_ptr,
				 guint* num_items,
				 uat_copy_cb_t copy_cb,
				 uat_update_cb_t update_cb,
				 uat_free_cb_t free_cb);

/* 
 * uat_add_field()
 * adds a field to a uat created with uat_start(),
 * see uat_new() for description of arguments
 */
void uat_add_field(uat_t*,
				   const char* name,
				   uat_text_mode_t mode,
				   uat_fld_chk_cb_t chk_cb,
				   uat_fld_set_cb_t set_cb,
				   uat_fld_tostr_cb_t tostr_cb);

/* 
 * uat_finalize()
 * once fields have been added it makes the uat usable, leaves it locked.
 */
void uat_finalize(uat_t*);

/*
 * uat_dup()
 * uat_se_dup()
 * make a reliable copy of an uat for internal use,
 * so that pointers to records can be kept through calls.
 * return NULL on zero len.
 */
void* uat_dup(uat_t*, guint* len_p); /* to be freed */
void* uat_se_dup(uat_t*, guint* len_p);

#endif

