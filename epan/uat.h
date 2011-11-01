/*
 *  uat.h
 *
 *  $Id$
 *
 *  User Accessible Tables
 *  Mantain an array of user accessible data strucures
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
 * Callbacks dealing with the entire table
 ********/

/*
 * Post-Update CB
 *
 * to be called after to the table has being edited
 * Will be called once the user clicks the Apply or OK button
 * optional
 */
typedef void (*uat_post_update_cb_t)(void);


/********
 * Callbacks dealing with records (these deal with entire records)
 ********/

/*
 * Copy CB
 * used to copy a record
 * optional, memcpy will be used if not given
 * copy(dest,orig,len)
 */
typedef void* (*uat_copy_cb_t)(void*, const void*, size_t);

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
 * to be called after any record fields had been updated
 * optional, record will be updated always if not given
 * update(record,&error)
 */
typedef void (*uat_update_cb_t)(void* , const char** );


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
 * chk(record, ptr, len, chk_data, fld_data, &error)
 */
typedef gboolean (*uat_fld_chk_cb_t)(void*, const char*, unsigned, const void*, const void*, const char**);

/*
 * Set Field CB
 *
 * given an input string (ptr, len) sets the value of a field in the record,
 * it will return TRUE if OK or else
 * it will return FALSE and may set *error to inform the user on what's
 * wrong with the given input
 * it is mandatory
 * set(record, ptr, len, set_data, fld_data)
 */
typedef void (*uat_fld_set_cb_t)(void*, const char*, unsigned, const void*, const void*);

/*
 * given a record returns a string representation of the field
 * mandatory
 * tostr(record, &out_ptr, &out_len, tostr_data, fld_data)
 */
typedef void (*uat_fld_tostr_cb_t)(void*, const char**, unsigned*, const void*, const void*);

/***********
 * Text Mode
 *
 * used for file and dialog representation of fields in columns,
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
	PT_TXTMOD_ENUM,

	PT_TXTMOD_FILENAME,
	/* processed like a PT_TXTMOD_STRING, but shows a filename dialog */
	PT_TXTMOD_DIRECTORYNAME
	/* processed like a PT_TXTMOD_STRING, but shows a directory dialog */
} uat_text_mode_t;

/*
 * Fields
 *
 *
 */
typedef struct _uat_field_t {
	const char* name;
	const char* title;
	uat_text_mode_t mode;

	struct {
		uat_fld_chk_cb_t chk;
		uat_fld_set_cb_t set;
		uat_fld_tostr_cb_t tostr;
	} cb;

	struct {
		const void* chk;
		const void* set;
		const void* tostr;
	} cbdata;

	const void* fld_data;

	const char* desc;
	struct _fld_data_t* priv;
} uat_field_t;

#define FLDFILL NULL
#define UAT_END_FIELDS {NULL,NULL,PT_TXTMOD_NONE,{0,0,0},{0,0,0},0,0,FLDFILL}


#define UAT_CAT_GENERAL "General"
#define UAT_CAT_PORTS "Port Assignments"
#define UAT_CAT_CRYPTO "Decryption"
#define UAT_CAT_FFMT "File Formats"

/** Create a new uat
 *
 * @param name The name of the table
 * @param size The size of the structure
 * @param filename The filename to be used (either in userdir or datadir)
 * @param from_profile TRUE if profie directory to be used
 * @param data_ptr A pointer to a null terminated array of pointers to the data
 * @param num_items_ptr
 * @param category
 * @param help A pointer to help text
 * @param copy_cb A function that copies the data in the struct
 * @param update_cb Will be called when a record is updated
 * @param free_cb Will be called to destroy a struct in the dataset
 * @param post_update_cb Will be called once the user clicks the Apply or OK button
 * @param flds_array A pointer to an array of uat_field_t structs
 *
 * @return A freshly-allocated and populated uat_t struct.
 */
uat_t* uat_new(const char* name,
			   size_t size,
			   const char* filename,
			   gboolean from_profile,
			   void** data_ptr,
			   guint* num_items_ptr,
			   const char* category,
			   const char* help,
			   uat_copy_cb_t copy_cb,
			   uat_update_cb_t update_cb,
			   uat_free_cb_t free_cb,
			   uat_post_update_cb_t post_update_cb,
			   uat_field_t* flds_array);

/** Populate a uat using its file.
 *
 * @param uat_in Pointer to a uat. Must not be NULL.
 * @param err Upon failure, points to an error string.
 *
 * @return TRUE on success, FALSE on failure.
 */
gboolean uat_load(uat_t* uat_in, char** err);

/** Create or update a single uat entry using a string.
 *
 * @param uat_in Pointer to a uat. Must not be NULL.
 * @param entry The string representation of the entry. Format must match
 * what's written to the uat's output file.
 * @param err Upon failure, points to an error string.
 *
 * @return TRUE on success, FALSE on failure.
 */
gboolean uat_load_str(uat_t* uat_in, char* entry, char** err);

/** Given a uat name or filename, find its pointer.
 *
 * @param name The name or filename of the uat
 *
 * @return A pointer to the uat on success, NULL on failure.
 */
uat_t *uat_find(gchar *name);

/*
 * uat_dup()
 * uat_se_dup()
 * make a reliable copy of an uat for internal use,
 * so that pointers to records can be kept through calls.
 * return NULL on zero len.
 */
void* uat_dup(uat_t*, guint* len_p); /* to be freed */
void* uat_se_dup(uat_t*, guint* len_p);
uat_t* uat_get_table_by_name(const char* name);

/*
 * Some common uat_fld_chk_cbs
 */
gboolean uat_fld_chk_str(void*, const char*, unsigned, const void*, const void*, const char** err);
gboolean uat_fld_chk_oid(void*, const char*, unsigned, const void*, const void*, const char** err);
gboolean uat_fld_chk_proto(void*, const char*, unsigned, const void*, const void*, const char** err);
gboolean uat_fld_chk_num_dec(void*, const char*, unsigned, const void*, const void*, const char** err);
gboolean uat_fld_chk_num_hex(void*, const char*, unsigned, const void*, const void*, const char** err);
gboolean uat_fld_chk_enum(void*, const char*, unsigned, const void*, const void*, const char**);
gboolean uat_fld_chk_range(void*, const char*, unsigned, const void*, const void*, const char**);

#define CHK_STR_IS_DECL(what) \
gboolean uat_fld_chk_str_ ## what (void*, const char*, unsigned, const void*, const void*, const char**)

typedef void (*uat_cb_t)(void* uat,void* user_data);
void uat_foreach_table(uat_cb_t cb,void* user_data);
void uat_unload_all(void);

char* uat_undquote(const char* si, guint in_len, guint* len_p);
char* uat_unbinstring(const char* si, guint in_len, guint* len_p);
char* uat_unesc(const char* si, guint in_len, guint* len_p);
char* uat_esc(const char* buf, guint len);

/* Some strings entirely made of ... already declared */
CHK_STR_IS_DECL(isprint);
CHK_STR_IS_DECL(isalpha);
CHK_STR_IS_DECL(isalnum);
CHK_STR_IS_DECL(isdigit);
CHK_STR_IS_DECL(isxdigit);

#define CHK_STR_IS_DEF(what) \
gboolean uat_fld_chk_str_ ## what (void* u1 _U_, const char* strptr, unsigned len, const void* u2 _U_, const void* u3 _U_, const char** err) { \
	guint i; for (i=0;i<len;i++) { \
		char c = strptr[i]; \
			if (! what((int)c)) { \
				*err = ep_strdup_printf("invalid char pos=%d value=%.2x",i,c); return FALSE;  } } \
		*err = NULL; return TRUE; }


/*
 * Macros
 *   to define basic uat_fld_set_cbs, uat_fld_tostr_cbs
 *   for those elements in uat_field_t array
 */

/*
 * CSTRING macros,
 *    a simple c-string contained in (((rec_t*)rec)->(field_name))
 */
#define UAT_CSTRING_CB_DEF(basename,field_name,rec_t) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* u1 _U_, const void* u2 _U_) {\
    char* new_buf = g_strndup(buf,len); \
	g_free((((rec_t*)rec)->field_name)); \
	(((rec_t*)rec)->field_name) = new_buf; } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, const char** out_ptr, unsigned* out_len, const void* u1 _U_, const void* u2 _U_) {\
		if (((rec_t*)rec)->field_name ) { \
			*out_ptr = (((rec_t*)rec)->field_name); \
			*out_len = (unsigned)strlen((((rec_t*)rec)->field_name)); \
		} else { \
			*out_ptr = ""; *out_len = 0; } }

#define UAT_FLD_CSTRING(basename,field_name,title,desc) \
	{#field_name, title, PT_TXTMOD_STRING,{uat_fld_chk_str,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

#define UAT_FLD_CSTRING_ISPRINT(basename,field_name,title,desc) \
	{#field_name, title, PT_TXTMOD_STRING,{uat_fld_chk_str_isprint,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

#define UAT_FLD_CSTRING_OTHER(basename,field_name,title,chk,desc) \
	{#field_name, title, PT_TXTMOD_STRING,{ chk ,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

/*
 * FILENAME and DIRECTORYNAME,
 *    a simple c-string contained in (((rec_t*)rec)->(field_name))
 */
#define UAT_FILENAME_CB_DEF(basename,field_name,rec_t) UAT_CSTRING_CB_DEF(basename,field_name,rec_t)

#define UAT_FLD_FILENAME(basename,field_name,title,desc) \
	{#field_name, title, PT_TXTMOD_FILENAME,{uat_fld_chk_str,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

#define UAT_FLD_FILENAME_OTHER(basename,field_name,title,chk,desc) \
	{#field_name, title, PT_TXTMOD_FILENAME,{chk,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

#define UAT_DIRECTORYNAME_CB_DEF(basename,field_name,rec_t) UAT_CSTRING_CB_DEF(basename,field_name,rec_t)

#define UAT_FLD_DIRECTORYNAME(basename,field_name,title,desc) \
	{#field_name, title, PT_TXTMOD_DIRECTORYNAME,{uat_fld_chk_str,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

/*
 * OID - just a CSTRING with a specific check routine
 */
#define UAT_FLD_OID(basename,field_name,title,desc) \
	{#field_name, title, PT_TXTMOD_STRING,{uat_fld_chk_oid,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}


/*
 * LSTRING MACROS
 */
#define UAT_LSTRING_CB_DEF(basename,field_name,rec_t,ptr_element,len_element) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* u1 _U_, const void* u2 _U_) {\
	char* new_val = uat_unesc(buf,len,&(((rec_t*)rec)->len_element)); \
        g_free((((rec_t*)rec)->ptr_element)); \
	(((rec_t*)rec)->ptr_element) = new_val; }\
static void basename ## _ ## field_name ## _tostr_cb(void* rec, const char** out_ptr, unsigned* out_len, const void* u1 _U_, const void* u2 _U_) {\
	if (((rec_t*)rec)->ptr_element ) { \
		*out_ptr = uat_esc(((rec_t*)rec)->ptr_element, (((rec_t*)rec)->len_element)); \
		*out_len = (unsigned)strlen(*out_ptr); \
	} else { \
		*out_ptr = ""; *out_len = 0; } }

#define UAT_FLD_LSTRING(basename,field_name,title, desc) \
{#field_name, title, PT_TXTMOD_STRING,{0,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}


/*
 * BUFFER macros,
 *    a buffer_ptr contained in (((rec_t*)rec)->(field_name))
 *    and its len in (((rec_t*)rec)->(len_name))
 *  XXX: UNTESTED and probably BROKEN
 */
#define UAT_BUFFER_CB_DEF(basename,field_name,rec_t,ptr_element,len_element) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* u1 _U_, const void* u2 _U_) {\
        char* new_buf = len ? g_memdup(buf,len) : NULL; \
	g_free((((rec_t*)rec)->ptr_element)); \
	(((rec_t*)rec)->ptr_element) = new_buf; \
	(((rec_t*)rec)->len_element) = len; } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, const char** out_ptr, unsigned* out_len, const void* u1 _U_, const void* u2 _U_) {\
	*out_ptr = ((rec_t*)rec)->ptr_element ? ep_memdup(((rec_t*)rec)->ptr_element,((rec_t*)rec)->len_element) : ""; \
	*out_len = ((rec_t*)rec)->len_element; }

#define UAT_FLD_BUFFER(basename,field_name,title,desc) \
	{#field_name, title, PT_TXTMOD_HEXBYTES,{0,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}


/*
 * DEC Macros,
 *   a decimal number contained in
 */
#define UAT_DEC_CB_DEF(basename,field_name,rec_t) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* u1 _U_, const void* u2 _U_) {\
	((rec_t*)rec)->field_name = strtol(ep_strndup(buf,len),NULL,10); } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, const char** out_ptr, unsigned* out_len, const void* u1 _U_, const void* u2 _U_) {\
	*out_ptr = ep_strdup_printf("%d",((rec_t*)rec)->field_name); \
	*out_len = (unsigned)strlen(*out_ptr); }

#define UAT_FLD_DEC(basename,field_name,title,desc) \
	{#field_name, title, PT_TXTMOD_STRING,{uat_fld_chk_num_dec,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}


/*
 * HEX Macros,
 *   an hexadecimal number contained in
 */
#define UAT_HEX_CB_DEF(basename,field_name,rec_t) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* u1 _U_, const void* u2 _U_) {\
	((rec_t*)rec)->field_name = strtol(ep_strndup(buf,len),NULL,16); } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, const char** out_ptr, unsigned* out_len, const void* u1 _U_, const void* u2 _U_) {\
	*out_ptr = ep_strdup_printf("%x",((rec_t*)rec)->field_name); \
	*out_len = (unsigned)strlen(*out_ptr); }

#define UAT_FLD_HEX(basename,field_name,title,desc) \
{#field_name, title, PT_TXTMOD_STRING,{uat_fld_chk_num_hex,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}


/*
 * ENUM macros
 *  enum_t: name = ((enum_t*)ptr)->strptr
 *          value = ((enum_t*)ptr)->value
 *  rec_t:
 *        value
 */
#define UAT_VS_DEF(basename,field_name,rec_t,default_val,default_str) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* vs, const void* u2 _U_) {\
	guint i; \
	char* str = ep_strndup(buf,len); \
	const char* cstr; ((rec_t*)rec)->field_name = default_val; \
	for(i=0; ( cstr = ((value_string*)vs)[i].strptr ) ;i++) { \
		if (g_str_equal(cstr,str)) { \
			((rec_t*)rec)->field_name = ((value_string*)vs)[i].value; return; } } } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, const char** out_ptr, unsigned* out_len, const void* vs, const void* u2 _U_) {\
	guint i; \
	*out_ptr = ep_strdup(default_str); \
	*out_len = (unsigned)strlen(default_str);\
	for(i=0;((value_string*)vs)[i].strptr;i++) { \
		if ( ((value_string*)vs)[i].value == ((rec_t*)rec)->field_name ) { \
			*out_ptr = ep_strdup(((value_string*)vs)[i].strptr); \
			*out_len = (unsigned)strlen(*out_ptr); return; } } }

#define UAT_VS_CSTRING_DEF(basename,field_name,rec_t,default_val,default_str) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* vs, const void* u2 _U_) {\
	guint i; \
	char* str = ep_strndup(buf,len); \
	const char* cstr; ((rec_t*)rec)->field_name = default_val; \
	for(i=0; ( cstr = ((value_string*)vs)[i].strptr ) ;i++) { \
		if (g_str_equal(cstr,str)) { \
		  ((rec_t*)rec)->field_name = g_strdup(((value_string*)vs)[i].strptr); return; } } } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, const char** out_ptr, unsigned* out_len, const void* vs _U_, const void* u2 _U_) {\
		if (((rec_t*)rec)->field_name ) { \
			*out_ptr = (((rec_t*)rec)->field_name); \
			*out_len = (unsigned)strlen((((rec_t*)rec)->field_name)); \
		} else { \
			*out_ptr = ""; *out_len = 0; } }

#define UAT_FLD_VS(basename,field_name,title,enum,desc) \
	{#field_name, title, PT_TXTMOD_ENUM,{uat_fld_chk_enum,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{&(enum),&(enum),&(enum)},&(enum),desc,FLDFILL}


/*
 * PROTO macros
 */

#define UAT_PROTO_DEF(basename, field_name, dissector_field, name_field, rec_t) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* u1 _U_, const void* u2 _U_) {\
	if (len) { \
		((rec_t*)rec)->name_field = g_strndup(buf,len); g_ascii_strdown(((rec_t*)rec)->name_field, -1); g_strchug(((rec_t*)rec)->name_field); \
		((rec_t*)rec)->dissector_field = find_dissector(((rec_t*)rec)->name_field); \
	} else { \
		((rec_t*)rec)->dissector_field = find_dissector("data"); \
		((rec_t*)rec)->name_field = NULL; \
		} } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, const char** out_ptr, unsigned* out_len, const void* u1 _U_, const void* u2 _U_) {\
	if ( ((rec_t*)rec)->name_field ) { \
		*out_ptr = (((rec_t*)rec)->name_field); \
		*out_len = (unsigned)strlen(*out_ptr); \
	} else { \
		*out_ptr = ""; *out_len = 0; } }


#define UAT_FLD_PROTO(basename,field_name,title,desc) \
	{#field_name, title, PT_TXTMOD_STRING,{uat_fld_chk_proto,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

/*
 * RANGE macros
 */

#define UAT_RANGE_CB_DEF(basename,field_name,rec_t) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* u1 _U_, const void* u2) {\
	char* rng = ep_strndup(buf,len);\
		range_convert_str(&(((rec_t*)rec)->field_name), rng,GPOINTER_TO_UINT(u2)); \
	} \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, const char** out_ptr, unsigned* out_len, const void* u1 _U_, const void* u2 _U_) {\
	if ( ((rec_t*)rec)->field_name ) { \
		*out_ptr = range_convert_range(((rec_t*)rec)->field_name); \
		*out_len = (unsigned)strlen(*out_ptr); \
	} else { \
		*out_ptr = ""; *out_len = 0; } }


#define UAT_FLD_RANGE(basename,field_name,title,max,desc) \
	{#field_name, title, PT_TXTMOD_STRING,{uat_fld_chk_range,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},\
	  {0,0,0},GUINT_TO_POINTER(max),desc,FLDFILL}

#endif
