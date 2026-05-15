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
#pragma once
#include <stdlib.h>

#include "ws_symbol_export.h"
#include <wsutil/strtoi.h>
#include <wsutil/dtoa.h>

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

/* opaque data type to handle an uat */
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
 * @param help A pointer to the name of a Users Guide section
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

/**
 * @brief Free and deregister a single UAT.
 * @param uat The UAT to be destroyed.
 */
WS_DLL_PUBLIC
void uat_destroy(uat_t *uat);

/**
 * @brief Cleanup all UATs.
 *
 */
void uat_cleanup(void);

/**
 * @brief Populate a UAT using its file.
 *
 * @param uat_in Pointer to a uat. Must not be NULL.
 * @param filename Filename to load, NULL to fetch from current profile.
 * @param app_env_var_prefix The prefix for the application environment variable used to get the personal config directory.
 * @param err Upon failure, points to an error string.
 *
 * @return true on success, false on failure.
 */
WS_DLL_PUBLIC
bool uat_load(uat_t* uat_in, const char *filename, const char* app_env_var_prefix, char** err);

/**
 * @brief Create or update a single UAT entry using a string.
 *
 * @param uat_in Pointer to a uat. Must not be NULL.
 * @param entry The string representation of the entry. Format must match
 * what's written to the uat's output file.
 * @param err Upon failure, points to an error string.
 *
 * @return true on success, false on failure.
 */
WS_DLL_PUBLIC
bool uat_load_str(uat_t* uat_in, const char* entry, char** err);

/**
 * @brief Given a UAT name or filename, find its pointer.
 *
 * @param name The name or filename of the uat
 *
 * @return A pointer to the uat on success, NULL on failure.
 */
uat_t *uat_find(char *name);

/**
 * @brief Retrieve a UAT table by its name.
 *
 * @param name The name of the UAT table to retrieve. Must not be NULL.
 * @return Pointer to the UAT table if found, otherwise NULL.
 */
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
/**
 * @brief UAT field validator for generic string values.
 *
 * @param record      Pointer to the UAT record being validated (unused).
 * @param ptr         The NUL-terminated string value to validate.
 * @param len         Length of @p ptr in bytes, not including the terminator.
 * @param chk_data    Field-level checker data supplied at UAT field
 *                    registration time (unused).
 * @param fld_data    Record-level field data (unused).
 * @param err         On failure, receives a newly allocated human-readable
 *                    error string that the UAT framework will display and
 *                    then @c g_free(). Set to NULL on success.
 * @return true if the value is acceptable; false if validation failed and
 *         @p *err has been set.
 */
WS_DLL_PUBLIC
bool uat_fld_chk_str(void *record, const char *ptr, unsigned len,
                     const void *chk_data, const void *fld_data, char **err);

/**
 * @brief UAT field validator for ASN.1 Object Identifier strings.
 *
 * @param record      Pointer to the UAT record being validated (unused).
 * @param ptr         The NUL-terminated OID string to validate.
 * @param len         Length of @p ptr in bytes, not including the terminator.
 * @param chk_data    Field-level checker data supplied at UAT field
 *                    registration time (unused).
 * @param fld_data    Record-level field data (unused).
 * @param err         On failure, receives a newly allocated error string
 *                    describing the OID syntax violation. Set to NULL on
 *                    success.
 * @return true if @p ptr is a valid dotted-decimal OID; false otherwise.
 */
WS_DLL_PUBLIC
bool uat_fld_chk_oid(void *record, const char *ptr, unsigned len,
                     const void *chk_data, const void *fld_data, char **err);

/**
 * @brief UAT field validator for Wireshark protocol name strings.
 *
 * @param record      Pointer to the UAT record being validated (unused).
 * @param ptr         The NUL-terminated protocol short name to validate
 *                    (e.g. @c "http", @c "tls").
 * @param len         Length of @p ptr in bytes, not including the terminator.
 * @param chk_data    Field-level checker data supplied at UAT field
 *                    registration time (unused).
 * @param fld_data    Record-level field data (unused).
 * @param err         On failure, receives a newly allocated error string
 *                    stating that the protocol is unknown. Set to NULL on
 *                    success.
 * @return true if @p ptr names a registered protocol; false otherwise.
 */
WS_DLL_PUBLIC
bool uat_fld_chk_proto(void *record, const char *ptr, unsigned len,
                       const void *chk_data, const void *fld_data, char **err);

/**
 * @brief Checks if a field name is valid.
 *
 * @param u1 User data pointer, not used in this function.
 * @param strptr String to check.
 * @param len Length of the string being checked.
 * @param u2 User data pointer, not used in this function.
 * @param u3 User data pointer, not used in this function.
 * @param err Error message buffer if an error occurs.
 * @return true if the field value is valid, false otherwise.
 */
WS_DLL_PUBLIC
bool uat_fld_chk_field(void* u1, const char* strptr, unsigned len, const void* u2, const void* u3, char** err);

/**
 * @brief Checks if a field value is a valid decimal number.
 *
 * @param u1 User data pointer, not used in this function.
 * @param strptr String to check.
 * @param len Length of the string being checked.
 * @param u2 User data pointer, not used in this function.
 * @param u3 User data pointer, not used in this function.
 * @param err Error message buffer if an error occurs.
 * @return true if the field value is valid, false otherwise.
 */
WS_DLL_PUBLIC
bool uat_fld_chk_num_dec(void* u1, const char* strptr, unsigned len, const void* u2, const void* u3, char** err);

/**
 * @brief Checks if a field value is a valid decimal 64-bit number.
 *
 * @param u1 User data pointer, not used in this function.
 * @param strptr String to check.
 * @param len Length of the string being checked.
 * @param u2 User data pointer, not used in this function.
 * @param u3 User data pointer, not used in this function.
 * @param err Error message buffer if an error occurs.
 * @return true if the field value is valid, false otherwise.
 */
WS_DLL_PUBLIC
bool uat_fld_chk_num_dec64(void* u1, const char* strptr, unsigned len, const void* u2, const void* u3, char** err);

/**
 * @brief Checks if a field contains a valid hexadecimal number.
 *
 * @param u1 User data pointer, not used in this function.
 * @param strptr String to check.
 * @param len Length of the string being checked.
 * @param u2 User data pointer, not used in this function.
 * @param u3 User data pointer, not used in this function.
 * @param err Error message buffer if an error occurs.
 * @return true if the field value is valid, false otherwise.
 */
WS_DLL_PUBLIC
bool uat_fld_chk_num_hex(void* u1, const char* strptr, unsigned len, const void* u2, const void* u3, char** err);

/**
 * @brief Check if a field contains a valid hexadecimal number.
 *
 * @param u1 User data pointer, not used in this function.
 * @param strptr String to check.
 * @param len Length of the string being checked.
 * @param u2 User data pointer, not used in this function.
 * @param u3 User data pointer, not used in this function.
 * @param err Error message buffer if an error occurs.
 * @return true if the field value is valid, false otherwise.
 */
WS_DLL_PUBLIC
bool uat_fld_chk_num_hex64(void* u1, const char* strptr, unsigned len, const void* u2, const void* u3, char** err);

/**
 * @brief Check if a field contains a signed decimal number.
 *
 * @param u1 User data pointer, not used in this function.
 * @param strptr String to check.
 * @param len Length of the string being checked.
 * @param u2 User data pointer, not used in this function.
 * @param u3 User data pointer, not used in this function.
 * @param err Error message buffer if an error occurs.
 * @return true if the field value is valid, false otherwise.
 */
WS_DLL_PUBLIC
bool uat_fld_chk_num_signed_dec(void* u1, const char* strptr, unsigned len, const void* u2, const void* u3, char** err);

/**
 * @brief Check if a field value is a signed decimal 64-bit number.
 *
 * @param u1 User data pointer, not used in this function.
 * @param strptr String to check.
 * @param len Length of the string being checked.
 * @param u2 User data pointer, not used in this function.
 * @param u3 User data pointer, not used in this function.
 * @param err Error message buffer if an error occurs.
 * @return true if the field value is valid, false otherwise.
 */
WS_DLL_PUBLIC
bool uat_fld_chk_num_signed_dec64(void* u1, const char* strptr, unsigned len, const void* u2, const void* u3, char** err);

/**
 * @brief Check if a field value is a numeric double.
 *
 * @param u1 User data pointer, not used in this function.
 * @param strptr String to check.
 * @param len Length of the string being checked.
 * @param u2 User data pointer, not used in this function.
 * @param u3 User data pointer, not used in this function.
 * @param err Error message buffer if an error occurs.
 * @return true if the field value is valid, false otherwise.
 */
WS_DLL_PUBLIC
bool uat_fld_chk_num_dbl(void* u1, const char* strptr, unsigned len, const void* u2, const void* u3, char** err);

/**
 * @brief Check if a field value is a boolean.
 *
 * @param u1 User data pointer, not used in this function.
 * @param strptr String to check.
 * @param len Length of the string being checked.
 * @param u2 User data pointer, not used in this function.
 * @param u3 User data pointer, not used in this function.
 * @param err Error message buffer if an error occurs.
 * @return true if the field value is valid, false otherwise.
 */
WS_DLL_PUBLIC
bool uat_fld_chk_bool(void* u1, const char* strptr, unsigned len, const void* u2, const void* u3, char** err);

/**
 * @brief Checks if a field value is a valid enum.
 *
 * @param u1 User data pointer, not used in this function.
 * @param strptr String to check.
 * @param len Length of the string being checked.
 * @param v Value string.
 * @param u3 User data pointer, not used in this function.
 * @param err Error message buffer if an error occurs.
 * @return true if the field value is valid, false otherwise.
 */
WS_DLL_PUBLIC
bool uat_fld_chk_enum(void* u1, const char* strptr, unsigned len, const void* v, const void* u3, char** err);

/**
 * @brief Checks if a field value is a  range object.
 *
 * @param u1 User data pointer, not used in this function.
 * @param strptr String to check.
 * @param len Length of the string being checked.
 * @param u2 User data pointer, not used in this function.
 * @param u3 User data pointer, not used in this function.
 * @param err Error message buffer if an error occurs.
 * @return true if the field value is valid, false otherwise.
 */
WS_DLL_PUBLIC
bool uat_fld_chk_range(void* u1, const char* strptr, unsigned len, const void* u2, const void* u3, char** err);

/**
 * @brief Checks if a color field is valid.
 *
 * @param u1 User data pointer, not used in this function.
 * @param strptr String to check.
 * @param len Length of the string being checked.
 * @param u2 User data pointer, not used in this function.
 * @param u3 User data pointer, not used in this function.
 * @param err Error message buffer if an error occurs.
 * @return true if the field value is valid, false otherwise.
 */
WS_DLL_PUBLIC
bool uat_fld_chk_color(void* u1, const char* strptr, unsigned len, const void* u2, const void* u3, char** err);

typedef void (*uat_cb_t)(void* uat,void* user_data);

/**
 * @brief Iterates over all UAT tables and calls a callback function for each.
 *
 * @param cb Callback function to be called for each UAT table.
 * @param user_data User data to be passed to the callback function.
 */
WS_DLL_PUBLIC
void uat_foreach_table(uat_cb_t cb,void* user_data);

/**
 * @brief Unloads all UATs that are not loaded from a profile.
 *
 * This function iterates through all UATs and unloads those that are not marked as being loaded from a profile.
 */
void uat_unload_all(void);

/**
 * @brief Converts an ASCII string using C-style escapes (e.g., for unprintable
 *
 * Converts an ASCII string using C-style escapes (e.g., for unprintable
 * characters) into a "stringlike" array of bytes that may include internal
 * NUL bytes and other unprintable characters. This is the PT_TEXTMOD_STRING
 * format.
 *
 * @param si     The escaped ASCII input string.
 * @param in_len Length of @p si in bytes, not including any NUL terminator.
 * @param len_p  Receives the length of the returned byte array in bytes.
 * @return A newly allocated byte array of @p *len_p bytes. The caller must
 *         free it with @c g_free().
 */
uint8_t *uat_unesc(const char *si, unsigned in_len, unsigned *len_p);

/**
 * @brief Decode a quoted, C-style escaped ASCII string into a raw byte array.
 *
 * The same as uat_unesc, but removing the first and last byte. The
 * assumption is that the first and last byte are quote characters. When
 * writing the PT_TEXTMOD_STRING format to file, the escaped string is
 * enclosed in quotes; this function undoes that.
 *
 * TODO - This should probably return a uint8_t* as well, but requires
 * changing types (or casting pointers) in several other files to do so.
 *
 * @param si     The quoted, escaped ASCII input string (including surrounding
 *               quote characters).
 * @param in_len Length of @p si in bytes, including the quote characters.
 * @param len_p  Receives the length of the decoded byte array in bytes.
 * @return A newly allocated byte array of @p *len_p bytes. The caller must
 *         free it with @c g_free().
 */
char *uat_undquote(const char *si, unsigned in_len, unsigned *len_p);

/**
 * @brief Encode a raw byte array as a NUL-terminated C-style escaped ASCII string.
 *
 * Converts a "stringlike" array of bytes into a null-terminated ASCII string
 * using C-style escapes. The inverse of uat_unesc.
 *
 * @param buf The raw byte array to encode.
 * @param len Number of bytes in @p buf.
 * @return A newly allocated NUL-terminated escaped ASCII string. The caller
 *         must free it with @c g_free().
 */
char *uat_esc(const uint8_t *buf, unsigned len);

/**
 * @brief Decode an ASCII hex-digit string into a raw byte array.
 *
 * Converts a ASCII hexstring into an array of bytes. Used to convert
 * the PT_TXTMOD_HEXBYTES format.
 * TODO - This should probably return a uint8_t* as well.
 *
 * @param si     The ASCII hex-digit input string.
 * @param in_len Length of @p si in bytes.
 * @param len_p  Receives the number of decoded bytes in the returned array.
 * @return A newly allocated byte array of @p *len_p bytes, or NULL if
 *         @p si contains non-hex characters or an odd number of digits.
 *         The caller must free it with @c g_free().
 */
char *uat_unbinstring(const char *si, unsigned in_len, unsigned *len_p);

/* Some strings entirely made of ... already declared */

/**
 * @brief Checks if a string contains only printable characters.
 *
 * @param u1 User data pointer, not used in this function.
 * @param strptr String to check.
 * @param len Length of the string being checked.
 * @param u2 User data pointer, not used in this function.
 * @param u3 User data pointer, not used in this function.
 * @param err Error message buffer if an error occurs.
 * @return true if the field value is valid, false otherwise.
 */
WS_DLL_PUBLIC
bool uat_fld_chk_str_isprint(void* u1, const char* strptr, unsigned len, const void* u2, const void* u3, char** err);

/**
 * @brief Checks if a string contains only alphabetic characters.
 *
 * @param u1 User data pointer, not used in this function.
 * @param strptr String to check.
 * @param len Length of the string being checked.
 * @param u2 User data pointer, not used in this function.
 * @param u3 User data pointer, not used in this function.
 * @param err Error message buffer if an error occurs.
 * @return true if the field value is valid, false otherwise.
 */
WS_DLL_PUBLIC
bool uat_fld_chk_str_isalpha(void* u1, const char* strptr, unsigned len, const void* u2, const void* u3, char** err);

/**
 * @brief Checks if a string is alphanumeric.
 *
 * @param u1 User data pointer, not used in this function.
 * @param strptr String to check.
 * @param len Length of the string being checked.
 * @param u2 User data pointer, not used in this function.
 * @param u3 User data pointer, not used in this function.
 * @param err Error message buffer if an error occurs.
 * @return true if the field value is valid, false otherwise.
 */
WS_DLL_PUBLIC
bool uat_fld_chk_str_isalnum(void* u1, const char* strptr, unsigned len, const void* u2, const void* u3, char** err);

/**
 * @brief Checks if a string contains only digits.
 *
 * @param u1 User data pointer, not used in this function.
 * @param strptr String to check.
 * @param len Length of the string being checked.
 * @param u2 User data pointer, not used in this function.
 * @param u3 User data pointer, not used in this function.
 * @param err Error message buffer if an error occurs.
 * @return true if the field value is valid, false otherwise.
 */
WS_DLL_PUBLIC
bool uat_fld_chk_str_isdigit(void* u1, const char* strptr, unsigned len, const void* u2, const void* u3, char** err);

/**
 * @brief Checks if a string contains only hexadecimal digits.
 *
 * @param u1 User data pointer, not used in this function.
 * @param strptr String to check.
 * @param len Length of the string being checked.
 * @param u2 User data pointer, not used in this function.
 * @param u3 User data pointer, not used in this function.
 * @param err Error message buffer if an error occurs.
 * @return true if the field value is valid, false otherwise.
 */
WS_DLL_PUBLIC
bool uat_fld_chk_str_isxdigit(void* u1, const char* strptr, unsigned len, const void* u2, const void* u3, char** err);


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
    {#field_name, title, PT_TXTMOD_PROTO_FIELD, {uat_fld_chk_field,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

/*
 * OID - just a CSTRING with a specific check routine
 */
#define UAT_FLD_OID(basename,field_name,title,desc) \
    {#field_name, title, PT_TXTMOD_STRING,{uat_fld_chk_oid,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}


/*
 * LSTRING MACROS - a "string" with an explicit length, so it can contain
 * internal null characters and possibly unprintable characters, that are
 * displayed to the user and written to the file using C-style escapes. An
 * alternative to BUFFER for when the data is often but not necessarily an
 * ASCII printable string, such as in some types of encryption keys.
 */
#define UAT_LSTRING_CB_DEF(basename,field_name,rec_t,ptr_element,len_element) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    uint8_t* new_val = uat_unesc(buf,len,&(((rec_t*)rec)->len_element)); \
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
 * DBL Macros,
 *   a double precision floating-point number contained in (((rec_t*)rec)->(field_name))
 *
 *   [using g_ascii_dtostr() would be fine for tostr_cb for storing data, but
 *   produces more ugly looking values when presenting to the user. dtoa_g_fmt
 *   produces the shortest string which also is a unique round-trip for any
 *   particular value.]
 */
#define UAT_DBL_CB_DEF(basename,field_name,rec_t) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    char* tmp_str = g_strndup(buf,len); \
    ((rec_t*)rec)->field_name = g_ascii_strtod(tmp_str, NULL); \
    g_free(tmp_str); } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, char** out_ptr, unsigned* out_len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    char buf[32]; \
    *out_ptr = ws_strdup(dtoa_g_fmt(buf, ((rec_t*)rec)->field_name)); \
    *out_len = (unsigned)strlen(*out_ptr); }

#define UAT_FLD_DBL(basename,field_name,title,desc) \
    {#field_name, title, PT_TXTMOD_STRING,{uat_fld_chk_num_dbl,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

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

#define UAT_FLD_DISSECTOR_OTHER(basename,field_name,title,chk,desc) \
    {#field_name, title, PT_TXTMOD_DISSECTOR,{chk,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

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
