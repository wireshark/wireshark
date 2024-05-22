/** @file
 *
 *  User Accessible Tables
 *  Maintain an array of user accessible data structures
 *
 * (c) 2007, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __UAT_H__
#define __UAT_H__

#include <stdlib.h>

#include "ws_symbol_export.h"
#include <wsutil/strtoi.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * UAT maintains a dynamically allocated table accessible to the user
 * via a file and/or via GUI preference dialogs.
 *
 * The file is read from and written in the personal configuration directory. If
 * there is no such file, defaults will be loaded from the global data
 * directory.
 *
 * The behaviour of the table is controlled by a series of callbacks which
 * the caller (e.g. a dissector) must provide.
 *
 * BEWARE that the user can change an UAT at (almost) any time (via the GUI).
 * That is, pointers to records in an UAT are valid only during the call
 * to the function that obtains them (do not store pointers to these records).
 * The records contents are only guaranteed to be valid in the post_update_cb
 * function. (Implementation detail: currently a race condition is possible
 * where the UAT consumer (dissector code) tries to use the UAT while the GUI
 * user frees a record resulting in use-after-free. This is not ideal and might
 * be fixed later.)
 *
 * UATs are meant for short tables of user data (passwords and such), there is
 * no quick access, you must iterate through them each time to fetch the record
 * you are looking for.
 *
 * Only users via GUI or editing the file can add/remove records, your
 * (dissector) code cannot.
 */

/* obscure data type to handle an uat */
typedef struct epan_uat uat_t;
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
 * To be called by the GUI code after to the table has being edited.
 * Will be called once the user clicks the Apply or OK button
 * optional
 */
typedef void (*uat_post_update_cb_t)(void);


/********
 * Callbacks dealing with records (these deal with entire records)
 ********/

/**
 * Copy CB
 * copy(dest, source, len)
 *
 * Used to duplicate the contents of one record to another.
 * Optional, memcpy will be used if not given.
 */
typedef void* (*uat_copy_cb_t)(void *dest, const void *source, size_t len);

/**
 * Free CB
 * free(record)
 *
 * Destroy the contents of a record, possibly freeing some fields.
 * Do not free the container itself, this memory is owned by the UAT core.
 * Optional if the record contains no pointers that need to be freed.
 */
typedef void (*uat_free_cb_t)(void *record);

/**
 * Reset DB
 *
 * Used to free resources associated with a UAT loaded from file (e.g. post_update_cb)
 * Optional.
 */
typedef void (*uat_reset_cb_t)(void);

/**
 * Update CB
 * update(record,&error)
 *
 * Validates the contents of the record contents, to be called after any record
 * fields had been updated (either from file or after modifications in the GUI).
 *
 * Optional, the record will be considered valid if the callback is omitted.
 * It must return true if the contents are considered valid and false otherwise
 * in which case the failure reason is set in 'error'. The error string will be
 * freed by g_free.
 *
 * XXX: This should only validate the record. Any changes to the record
 * made here will *not* be persistent if the UAT is saved again, unless
 * the same changes are also done to a new record created by the copy cb,
 * e.g. by having the the copy callback call this.
 * It should probably be made into a const void* to make that clear.
 */
typedef bool (*uat_update_cb_t)(void *record, char **error);


/*******
 * Callbacks for single fields (these deal with single values)
 * the caller should provide one of these for every field!
 ********/

/*
 * Check CB
 * chk(record, ptr, len, chk_data, fld_data, &error)
 *
 * given an input string (ptr, len) checks if the value is OK for a field in the record.
 * it will return true if OK or else
 * it will return false and set *error to inform the user on what's
 * wrong with the given input
 * The error string must be allocated with g_malloc() or
 * a routine that calls it.
 * optional, if not given any input is considered OK and the set cb will be called
 */
typedef bool (*uat_fld_chk_cb_t)(void *record, const char *ptr, unsigned len, const void *chk_data, const void *fld_data, char **error);

/*
 * Set Field CB
 * set(record, ptr, len, set_data, fld_data)
 *
 * given an input string (ptr, len) sets the value of a field in the record,
 * it is mandatory
 */
typedef void (*uat_fld_set_cb_t)(void *record, const char *ptr, unsigned len, const void *set_data, const void *fld_data);

/*
 * Convert-to-string CB
 * tostr(record, &out_ptr, &out_len, tostr_data, fld_data)
 *
 * given a record returns a string representation of the field
 * mandatory
 */
typedef void (*uat_fld_tostr_cb_t)(void *record, char **out_ptr, unsigned *out_len, const void *tostr_data, const void *fld_data);

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
             ,"\x20\x00\x30", as " \00",3 ("space nil zero" of length 3)
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
             ,A1b2C3d4, as "\xa1\xb2\xc3\xd4",4
             ,, as NULL,0
         writes:
             ,, on NULL, *
             ,a1b2c3d4, on "\xa1\xb2\xc3\xd4",4
     dialog:
         interprets the following input ... as ...:
         "a1b2c3d4" as "\xa1\xb2\xc3\xd4",4
         "a1 b2:c3d4" as "\xa1\xb2\xc3\xd4",4
         "" as NULL,0
         "invalid" as NULL,3
         "a1b" as NULL, 1
     */
    PT_TXTMOD_ENUM,
    /* Read/Writes/displays the string value (not number!) */
    PT_TXTMOD_DISSECTOR,
    /* Shows a combobox of dissectors */

    PT_TXTMOD_COLOR,
    /* Reads/Writes/display color in #RRGGBB format */

    PT_TXTMOD_FILENAME,
    /* processed like a PT_TXTMOD_STRING, but shows a filename dialog */
    PT_TXTMOD_DIRECTORYNAME,
    /* processed like a PT_TXTMOD_STRING, but shows a directory dialog */
    PT_TXTMOD_DISPLAY_FILTER,
    /* processed like a PT_TXTMOD_STRING, but verifies display filter */
    PT_TXTMOD_PROTO_FIELD,
    /* processed like a PT_TXTMOD_STRING, but verifies protocol field name (e.g tcp.flags.syn) */
    PT_TXTMOD_BOOL
    /* Displays a checkbox for value */
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

/*
 * Flags to indicate what the settings in this UAT affect.
 * This is used when UATs are changed interactively, to indicate what needs
 * to be redone when the UAT is changed.
 *
 * UAT_AFFECTS_FIELDS does *not* trigger a redissection, so usually one
 * will also want UAT_AFFECTS_DISSECTION. A rare exception is changing
 * the defined dfilter macros.
 */
#define UAT_AFFECTS_DISSECTION	0x00000001	/* affects packet dissection */
#define UAT_AFFECTS_FIELDS	0x00000002	/* affects what named fields exist */

/** Create a new UAT.
 *
 * @param name The name of the table
 * @param size The size of the structure
 * @param filename The filename to be used (either in userdir or datadir)
 * @param from_profile true if profile directory to be used
 * @param data_ptr Although a void*, this is really a pointer to a null terminated array of pointers to the data
 * @param num_items_ptr A pointer with number of items
 * @param flags flags indicating what this UAT affects
 * @param help A pointer to help text
 * @param copy_cb A function that copies the data in the struct
 * @param update_cb Will be called when a record is updated
 * @param free_cb Will be called to destroy a struct in the dataset
 * @param post_update_cb Will be called once the user clicks the Apply or OK button
 * @param reset_cb Will be called to destroy internal data
 * @param flds_array A pointer to an array of uat_field_t structs
 *
 * @return A freshly-allocated and populated uat_t struct.
 */
WS_DLL_PUBLIC
uat_t* uat_new(const char* name,
               size_t size,
               const char* filename,
               bool from_profile,
               void* data_ptr,
               unsigned* num_items_ptr,
               unsigned flags,
               const char* help,
               uat_copy_cb_t copy_cb,
               uat_update_cb_t update_cb,
               uat_free_cb_t free_cb,
               uat_post_update_cb_t post_update_cb,
               uat_reset_cb_t reset_cb,
               uat_field_t* flds_array);

/** Free and deregister a single UAT.
 *
 */
WS_DLL_PUBLIC
void uat_destroy(uat_t *uat);

/** Cleanup all UATs.
 *
 */
void uat_cleanup(void);

/** Populate a UAT using its file.
 *
 * @param uat_in Pointer to a uat. Must not be NULL.
 * @param filename Filename to load, NULL to fetch from current profile.
 * @param err Upon failure, points to an error string.
 *
 * @return true on success, false on failure.
 */
WS_DLL_PUBLIC
bool uat_load(uat_t* uat_in, const char *filename, char** err);

/** Create or update a single UAT entry using a string.
 *
 * @param uat_in Pointer to a uat. Must not be NULL.
 * @param entry The string representation of the entry. Format must match
 * what's written to the uat's output file.
 * @param err Upon failure, points to an error string.
 *
 * @return true on success, false on failure.
 */
bool uat_load_str(uat_t* uat_in, const char* entry, char** err);

/** Given a UAT name or filename, find its pointer.
 *
 * @param name The name or filename of the uat
 *
 * @return A pointer to the uat on success, NULL on failure.
 */
uat_t *uat_find(char *name);

WS_DLL_PUBLIC
uat_t* uat_get_table_by_name(const char* name);

/**
 * Provide default field values for a UAT.
 *
 * This can be used to provide forward compatibility when fields are added
 * to a UAT.
 *
 * @param uat_in Pointer to a uat. Must not be NULL.
 * @param default_values An array of strings with default values. Must
 * be the same length as flds_array. Individual elements can be NULL,
 * and can be used to distinguish between mandatory and optional fields,
 * e.g. { NULL, NULL, NULL, "default value (optional)" }
 * @todo Use this to provide default values for empty tables.
 */
WS_DLL_PUBLIC
void uat_set_default_values(uat_t *uat_in, const char *default_values[]);

/*
 * Some common uat_fld_chk_cbs
 */
WS_DLL_PUBLIC
bool uat_fld_chk_str(void*, const char*, unsigned, const void*, const void*, char** err);
bool uat_fld_chk_oid(void*, const char*, unsigned, const void*, const void*, char** err);
WS_DLL_PUBLIC
bool uat_fld_chk_proto(void*, const char*, unsigned, const void*, const void*, char** err);
WS_DLL_PUBLIC
bool uat_fld_chk_num_dec(void*, const char*, unsigned, const void*, const void*, char** err);
WS_DLL_PUBLIC
bool uat_fld_chk_num_dec64(void*, const char*, unsigned, const void*, const void*, char** err);
WS_DLL_PUBLIC
bool uat_fld_chk_num_hex(void*, const char*, unsigned, const void*, const void*, char** err);
WS_DLL_PUBLIC
bool uat_fld_chk_num_hex64(void*, const char*, unsigned, const void*, const void*, char** err);
WS_DLL_PUBLIC
bool uat_fld_chk_num_signed_dec(void*, const char*, unsigned, const void*, const void*, char** err);
WS_DLL_PUBLIC
bool uat_fld_chk_num_signed_dec64(void*, const char*, unsigned, const void*, const void*, char** err);
WS_DLL_PUBLIC
bool uat_fld_chk_bool(void*, const char*, unsigned, const void*, const void*, char** err);
WS_DLL_PUBLIC
bool uat_fld_chk_enum(void*, const char*, unsigned, const void*, const void*, char**);
WS_DLL_PUBLIC
bool uat_fld_chk_range(void*, const char*, unsigned, const void*, const void*, char**);
WS_DLL_PUBLIC
bool uat_fld_chk_color(void*, const char*, unsigned, const void*, const void*, char**);

typedef void (*uat_cb_t)(void* uat,void* user_data);
WS_DLL_PUBLIC
void uat_foreach_table(uat_cb_t cb,void* user_data);
void uat_unload_all(void);

char* uat_undquote(const char* si, unsigned in_len, unsigned* len_p);
char* uat_unbinstring(const char* si, unsigned in_len, unsigned* len_p);
char* uat_unesc(const char* si, unsigned in_len, unsigned* len_p);
char* uat_esc(const char* buf, unsigned len);

/* Some strings entirely made of ... already declared */

WS_DLL_PUBLIC
bool uat_fld_chk_str_isprint(void*, const char*, unsigned, const void*, const void*, char**);

WS_DLL_PUBLIC
bool uat_fld_chk_str_isalpha(void*, const char*, unsigned, const void*, const void*, char**);

WS_DLL_PUBLIC
bool uat_fld_chk_str_isalnum(void*, const char*, unsigned, const void*, const void*, char**);

WS_DLL_PUBLIC
bool uat_fld_chk_str_isdigit(void*, const char*, unsigned, const void*, const void*, char**);

WS_DLL_PUBLIC
bool uat_fld_chk_str_isxdigit(void*, const char*, unsigned, const void*, const void*, char**);


/*
 * Macros
 *   to define basic uat_fld_set_cbs, uat_fld_tostr_cbs
 *   for those elements in uat_field_t array
 */

#ifdef __cplusplus
#define UNUSED_PARAMETER(n)
#else
#define UNUSED_PARAMETER(n) n _U_
#endif

/*
 * CSTRING macros,
 *    a simple c-string contained in (((rec_t*)rec)->(field_name))
 */
#define UAT_CSTRING_CB_DEF(basename,field_name,rec_t) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    char* new_buf = g_strndup(buf,len); \
    g_free((((rec_t*)rec)->field_name)); \
    (((rec_t*)rec)->field_name) = new_buf; } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, char** out_ptr, unsigned* out_len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    if (((rec_t*)rec)->field_name ) { \
        *out_ptr = g_strdup((((rec_t*)rec)->field_name)); \
        *out_len = (unsigned)strlen((((rec_t*)rec)->field_name)); \
    } else { \
        *out_ptr = g_strdup(""); *out_len = 0; \
    } }

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

/* XXX UAT_FLD_FILENAME is currently unused. */
#define UAT_FLD_FILENAME(basename,field_name,title,desc) \
    {#field_name, title, PT_TXTMOD_FILENAME,{uat_fld_chk_str,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

/*
 * Both the Qt and GTK+ UIs assume that we're opening a preexisting
 * file. We might want to split the ..._FILENAME defines into
 * ..._FILE_OPEN and ..._FILE_SAVE if we ever need to specify a
 * file that we're creating.
 */
#define UAT_FLD_FILENAME_OTHER(basename,field_name,title,chk,desc) \
    {#field_name, title, PT_TXTMOD_FILENAME,{chk,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

#define UAT_DIRECTORYNAME_CB_DEF(basename,field_name,rec_t) UAT_CSTRING_CB_DEF(basename,field_name,rec_t)

#define UAT_FLD_DIRECTORYNAME(basename,field_name,title,desc) \
    {#field_name, title, PT_TXTMOD_DIRECTORYNAME,{uat_fld_chk_str,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

/*
 * DISPLAY_FILTER,
 *    a simple c-string contained in (((rec_t*)rec)->(field_name))
 */
#define UAT_DISPLAY_FILTER_CB_DEF(basename,field_name,rec_t) UAT_CSTRING_CB_DEF(basename,field_name,rec_t)

#define UAT_FLD_DISPLAY_FILTER(basename,field_name,title,desc) \
    {#field_name, title, PT_TXTMOD_DISPLAY_FILTER, {uat_fld_chk_str,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

/*
 * PROTO_FIELD,
 *    a simple c-string contained in (((rec_t*)rec)->(field_name))
 */
#define UAT_PROTO_FIELD_CB_DEF(basename,field_name,rec_t) UAT_CSTRING_CB_DEF(basename,field_name,rec_t)

#define UAT_FLD_PROTO_FIELD(basename,field_name,title,desc) \
    {#field_name, title, PT_TXTMOD_PROTO_FIELD, {uat_fld_chk_str,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

/*
 * OID - just a CSTRING with a specific check routine
 */
#define UAT_FLD_OID(basename,field_name,title,desc) \
    {#field_name, title, PT_TXTMOD_STRING,{uat_fld_chk_oid,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}


/*
 * LSTRING MACROS
 */
#define UAT_LSTRING_CB_DEF(basename,field_name,rec_t,ptr_element,len_element) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    char* new_val = uat_unesc(buf,len,&(((rec_t*)rec)->len_element)); \
    g_free((((rec_t*)rec)->ptr_element)); \
    (((rec_t*)rec)->ptr_element) = new_val; } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, char** out_ptr, unsigned* out_len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    if (((rec_t*)rec)->ptr_element ) { \
        *out_ptr = uat_esc(((rec_t*)rec)->ptr_element, (((rec_t*)rec)->len_element)); \
        *out_len = (unsigned)strlen(*out_ptr); \
    } else { \
        *out_ptr = g_strdup(""); \
        *out_len = 0; \
    } }

#define UAT_FLD_LSTRING(basename,field_name,title, desc) \
{#field_name, title, PT_TXTMOD_STRING,{0,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}


/*
 * BUFFER macros,
 *    a buffer_ptr contained in (((rec_t*)rec)->(field_name))
 *    and its len in (((rec_t*)rec)->(len_name))
 */
#define UAT_BUFFER_CB_DEF(basename,field_name,rec_t,ptr_element,len_element) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    unsigned char* new_buf = len ? (unsigned char *)g_memdup2(buf,len) : NULL; \
    g_free((((rec_t*)rec)->ptr_element)); \
    (((rec_t*)rec)->ptr_element) = new_buf; \
    (((rec_t*)rec)->len_element) = len; } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, char** out_ptr, unsigned* out_len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    *out_ptr = ((rec_t*)rec)->ptr_element ? (char*)g_memdup2(((rec_t*)rec)->ptr_element,((rec_t*)rec)->len_element) : g_strdup(""); \
    *out_len = ((rec_t*)rec)->len_element; }

#define UAT_FLD_BUFFER(basename,field_name,title,desc) \
    {#field_name, title, PT_TXTMOD_HEXBYTES,{0,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}


/*
 * DEC Macros,
 *   an unsigned decimal number contained in (((rec_t*)rec)->(field_name))
 */
#define UAT_DEC_CB_DEF(basename,field_name,rec_t) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    char* tmp_str = g_strndup(buf,len); \
    ws_strtou32(tmp_str, NULL, &((rec_t*)rec)->field_name); \
    g_free(tmp_str); } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, char** out_ptr, unsigned* out_len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    *out_ptr = ws_strdup_printf("%u",((rec_t*)rec)->field_name); \
    *out_len = (unsigned)strlen(*out_ptr); }

#define UAT_FLD_DEC(basename,field_name,title,desc) \
    {#field_name, title, PT_TXTMOD_STRING,{uat_fld_chk_num_dec,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

 /*
  *   an unsigned 64bit decimal number contained in (((rec_t*)rec)->(field_name))
  */
#define UAT_DEC64_CB_DEF(basename,field_name,rec_t) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    char* tmp_str = g_strndup(buf,len); \
    ws_strtou64(tmp_str, NULL, &((rec_t*)rec)->field_name); \
    g_free(tmp_str); } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, char** out_ptr, unsigned* out_len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    *out_ptr = ws_strdup_printf("%" PRIu64,((rec_t*)rec)->field_name); \
    *out_len = (unsigned)strlen(*out_ptr); }

#define UAT_FLD_DEC64(basename,field_name,title,desc) \
    {#field_name, title, PT_TXTMOD_STRING,{uat_fld_chk_num_dec64,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

/*
 *   a *signed* decimal number contained in (((rec_t*)rec)->(field_name))
 */
#define UAT_SIGNED_DEC_CB_DEF(basename,field_name,rec_t) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    char* tmp_str = g_strndup(buf,len); \
    ws_strtoi32(tmp_str, NULL, &((rec_t*)rec)->field_name); \
    g_free(tmp_str); } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, char** out_ptr, unsigned* out_len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    *out_ptr = ws_strdup_printf("%d",((rec_t*)rec)->field_name); \
    *out_len = (unsigned)strlen(*out_ptr); }

#define UAT_FLD_SIGNED_DEC(basename,field_name,title,desc) \
    {#field_name, title, PT_TXTMOD_STRING,{uat_fld_chk_num_signed_dec,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

 /*
  *   and a *signed* 64bit decimal number contained in (((rec_t*)rec)->(field_name))
  */
#define UAT_SIGNED_DEC64_CB_DEF(basename,field_name,rec_t) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    char* tmp_str = g_strndup(buf,len); \
    ws_strtoi64(tmp_str, NULL, &((rec_t*)rec)->field_name); \
    g_free(tmp_str); } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, char** out_ptr, unsigned* out_len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    *out_ptr = ws_strdup_printf("%" PRId64,((rec_t*)rec)->field_name); \
    *out_len = (unsigned)strlen(*out_ptr); }

#define UAT_FLD_SIGNED_DEC64(basename,field_name,title,desc) \
    {#field_name, title, PT_TXTMOD_STRING,{uat_fld_chk_num_signed_dec64,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

#define UAT_FLD_NONE(basename,field_name,title,desc) \
    {#field_name, title, PT_TXTMOD_NONE,{uat_fld_chk_num_dec,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}


/*
 * HEX Macros,
 *   an unsigned hexadecimal number contained in (((rec_t*)rec)->(field_name))
 */
#define UAT_HEX_CB_DEF(basename,field_name,rec_t) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    char* tmp_str = g_strndup(buf,len); \
    ws_hexstrtou32(tmp_str, NULL, &((rec_t*)rec)->field_name); \
    g_free(tmp_str); } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, char** out_ptr, unsigned* out_len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    *out_ptr = ws_strdup_printf("%x",((rec_t*)rec)->field_name); \
    *out_len = (unsigned)strlen(*out_ptr); }

#define UAT_FLD_HEX(basename,field_name,title,desc) \
{#field_name, title, PT_TXTMOD_STRING,{uat_fld_chk_num_hex,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

 /*
  * HEX Macros for 64bit,
  *   an unsigned long long hexadecimal number contained in (((rec_t*)rec)->(field_name))
  */
#define UAT_HEX64_CB_DEF(basename,field_name,rec_t) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    char* tmp_str = g_strndup(buf,len); \
    ws_hexstrtou64(tmp_str, NULL, &((rec_t*)rec)->field_name); \
    g_free(tmp_str); } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, char** out_ptr, unsigned* out_len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    *out_ptr = ws_strdup_printf("%" PRIx64,((rec_t*)rec)->field_name); \
    *out_len = (unsigned)strlen(*out_ptr); }

#define UAT_FLD_HEX64(basename,field_name,title,desc) \
{#field_name, title, PT_TXTMOD_STRING,{uat_fld_chk_num_hex64,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

/*
 * BOOL Macros,
 *   an boolean value contained in (((rec_t*)rec)->(field_name))
 *
 * Write "TRUE" or "FALSE" for backwards compatibility with pre-4.4
 * versions that expect that capitalization.
 */
#define UAT_BOOL_CB_DEF(basename,field_name,rec_t) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    char* tmp_str = g_strndup(buf,len); \
    if (tmp_str && g_ascii_strcasecmp(tmp_str, "true") == 0) \
        ((rec_t*)rec)->field_name = 1; \
    else \
        ((rec_t*)rec)->field_name = 0; \
    g_free(tmp_str); } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, char** out_ptr, unsigned* out_len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    *out_ptr = ws_strdup_printf("%s",((rec_t*)rec)->field_name ? "TRUE" : "FALSE"); \
    *out_len = (unsigned)strlen(*out_ptr); }

#define UAT_FLD_BOOL(basename,field_name,title,desc) \
{#field_name, title, PT_TXTMOD_BOOL,{uat_fld_chk_bool,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

/*
 * ENUM macros
 *  enum_t: name = ((enum_t*)ptr)->strptr
 *          value = ((enum_t*)ptr)->value
 *  rec_t:
 *        value
 */
#define UAT_VS_DEF(basename,field_name,rec_t,default_t,default_val,default_str) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* vs, const void* UNUSED_PARAMETER(u2)) {\
    unsigned i; \
    char* str = g_strndup(buf,len); \
    const char* cstr; \
    ((rec_t*)rec)->field_name = default_val; \
    for(i=0; ( cstr = ((const value_string*)vs)[i].strptr ) ;i++) { \
        if (g_str_equal(cstr,str)) { \
            ((rec_t*)rec)->field_name = (default_t)((const value_string*)vs)[i].value; \
            g_free(str); \
            return; \
        } \
    } \
    g_free(str); } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, char** out_ptr, unsigned* out_len, const void* vs, const void* UNUSED_PARAMETER(u2)) {\
    unsigned i; \
    for(i=0;((const value_string*)vs)[i].strptr;i++) { \
        if ( ((const value_string*)vs)[i].value == ((rec_t*)rec)->field_name ) { \
            *out_ptr = g_strdup(((const value_string*)vs)[i].strptr); \
            *out_len = (unsigned)strlen(*out_ptr); \
            return; \
        } \
    } \
    *out_ptr = g_strdup(default_str); \
    *out_len = (unsigned)strlen(default_str); }

#define UAT_VS_CSTRING_DEF(basename,field_name,rec_t,default_val,default_str) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* vs, const void* UNUSED_PARAMETER(u2)) {\
    unsigned i; \
    char* str = g_strndup(buf,len); \
    const char* cstr; \
    ((rec_t*)rec)->field_name = default_val; \
    for(i=0; ( cstr = ((const value_string*)vs)[i].strptr ) ;i++) { \
        if (g_str_equal(cstr,str)) { \
          ((rec_t*)rec)->field_name = g_strdup(((const value_string*)vs)[i].strptr); \
          g_free(str); \
          return; \
        } \
    } \
    g_free(str);} \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, char** out_ptr, unsigned* out_len, const void* UNUSED_PARAMETER(vs), const void* UNUSED_PARAMETER(u2)) {\
    if (((rec_t*)rec)->field_name ) { \
        *out_ptr = g_strdup((((rec_t*)rec)->field_name)); \
        *out_len = (unsigned)strlen((((rec_t*)rec)->field_name)); \
    } else { \
        *out_ptr = g_strdup(""); *out_len = 0; } }

#define UAT_FLD_VS(basename,field_name,title,enum,desc) \
    {#field_name, title, PT_TXTMOD_ENUM,{uat_fld_chk_enum,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{&(enum),&(enum),&(enum)},&(enum),desc,FLDFILL}


/*
 * Color Macros,
 *   an #RRGGBB color value contained in (((rec_t*)rec)->(field_name))
 */
#define UAT_COLOR_CB_DEF(basename,field_name,rec_t) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    if (len < 1) { \
        ((rec_t*)rec)->field_name = 0; \
        return; \
    } \
    char* tmp_str = g_strndup(buf+1,len-1); \
    ((rec_t*)rec)->field_name = (unsigned)strtol(tmp_str,NULL,16); \
    g_free(tmp_str); } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, char** out_ptr, unsigned* out_len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    *out_ptr = ws_strdup_printf("#%06X",((rec_t*)rec)->field_name); \
    *out_len = (unsigned)strlen(*out_ptr); }

#define UAT_FLD_COLOR(basename,field_name,title,desc) \
{#field_name, title, PT_TXTMOD_COLOR,{uat_fld_chk_color,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}


/*
 * DISSECTOR macros
 */

#define UAT_DISSECTOR_DEF(basename, field_name, dissector_field, name_field, rec_t) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    if (len) { \
        ((rec_t*)rec)->name_field = g_strndup(buf, len); \
        g_strstrip(((rec_t*)rec)->name_field); \
        ((rec_t*)rec)->dissector_field = find_dissector(((rec_t*)rec)->name_field); \
    } else { \
        ((rec_t*)rec)->dissector_field = find_dissector("data"); \
        ((rec_t*)rec)->name_field = NULL; \
    } } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, char** out_ptr, unsigned* out_len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    if ( ((rec_t*)rec)->name_field ) { \
        *out_ptr = g_strdup((((rec_t*)rec)->name_field)); \
        *out_len = (unsigned)strlen(*out_ptr); \
    } else { \
        *out_ptr = g_strdup(""); *out_len = 0; \
    } }


#define UAT_FLD_DISSECTOR(basename,field_name,title,desc) \
    {#field_name, title, PT_TXTMOD_DISSECTOR,{uat_fld_chk_proto,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

/*
 * RANGE macros
 */

#define UAT_RANGE_CB_DEF(basename,field_name,rec_t) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* UNUSED_PARAMETER(u1), const void* u2) {\
    char* rng = g_strndup(buf,len);\
        range_convert_str(NULL, &(((rec_t*)rec)->field_name), rng,GPOINTER_TO_UINT(u2)); \
        g_free(rng); \
    } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, char** out_ptr, unsigned* out_len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    if ( ((rec_t*)rec)->field_name ) { \
        *out_ptr = range_convert_range(NULL, ((rec_t*)rec)->field_name); \
        *out_len = (unsigned)strlen(*out_ptr); \
    } else { \
        *out_ptr = g_strdup(""); *out_len = 0; \
    } }


#define UAT_FLD_RANGE(basename,field_name,title,max,desc) \
    {#field_name, title, PT_TXTMOD_STRING,{uat_fld_chk_range,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},\
      {0,0,0},GUINT_TO_POINTER(max),desc,FLDFILL}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UAT_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
