/* sinsp-span.h
 *
 * By Gerald Combs
 * Copyright (C) 2022 Sysdig, Inc.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __SINSP_SPAN_H__
#define __SINSP_SPAN_H__

#include <stdint.h>

#include <epan/ftypes/ftypes.h>
#include <wsutil/wmem/wmem.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define FALCO_FIELD_NAME_PREFIX "falco."

#define N_PROC_LINEAGE_ENTRIES 16
#define N_PROC_LINEAGE_ENTRY_FIELDS 4

typedef struct sinsp_source_info_t sinsp_source_info_t;
typedef struct sinsp_span_t sinsp_span_t;

/**
 * @brief Numeric display format applied to a sinsp field value.
 */
typedef enum sinsp_field_display_format_e {
    SFDF_UNKNOWN,     /**< Format not specified or not applicable. */
    SFDF_DECIMAL,     /**< Render value in base-10 decimal. */
    SFDF_HEXADECIMAL, /**< Render value in base-16 hexadecimal. */
    SFDF_OCTAL        /**< Render value in base-8 octal. */
} sinsp_field_display_format_e;


/**
 * @brief High-level syscall/event field categories.
 *
 * Should match sinsp_filter_check_list in libsinsp as closely as possible.
 */
typedef enum sinsp_syscall_category_e {
    SSC_EVENT,        /**< Generic event fields (gen_event, event). */
    SSC_EVTARGS,      /**< Event argument fields. */
    SSC_PROCESS,      /**< Process/thread fields (thread). */
    SSC_PROCLINEAGE,  /**< Process lineage/ancestry fields. */
    SSC_USER,         /**< User identity fields. */
    SSC_GROUP,        /**< Group identity fields. */
    SSC_CONTAINER,    /**< Container metadata fields. */
    SSC_FD,           /**< File descriptor fields (fd). */
    SSC_FS,           /**< Filesystem path fields (fs.path). */
/*  SSC_SYSLOG, */    /**< Syslog fields — omitted: collides with the syslog dissector. */
    SSC_FDLIST,       /**< File descriptor list fields (fdlist). */
    SSC_OTHER,        /**< Catch-all category for unclassified fields ("falco.*"). */
    NUM_SINSP_SYSCALL_CATEGORIES /**< Sentinel: total number of categories. */
} sinsp_syscall_category_e;


/**
 * @brief Metadata describing a single sinsp filter/display field.
 */
typedef struct sinsp_field_info_t {
    enum ftenum                  type;            /**< Wireshark field type (FT_*). */
    sinsp_field_display_format_e display_format;  /**< Preferred numeric display format. */
    char abbrev[64];                              /**< Filter name used in display-filter expressions. */
    char display[64];                             /**< Human-readable column/display name. */
    char description[1024];                       /**< Long-form description shown in field reference. */
    bool skip;            /**< @c true for fields that are not handled (e.g. lists and tables). */
    bool is_info;         /**< @c true if the field should be shown as an info column candidate. */
    bool is_conversation; /**< @c true if the field participates in conversation tracking. */
    bool is_numeric_address; /**< @c true if the field represents a numeric network address. */
} sinsp_field_info_t;


/** @brief Size of the inline small-buffer members inside sinsp_field_extract_t::res. */
#define SFE_SMALL_BUF_SIZE 8

/**
 * @brief Holds a single extracted field value from a sinsp syscall event.
 *
 * The active union member is determined by the field's @c ftenum type.
 * @c res_len and @c field_idx are output parameters populated by the
 * extraction routine.
 */
typedef struct sinsp_field_extract_t {
    /** @brief Extracted value; the active member depends on the field type. */
    union {
        uint8_t    *bytes;                     /**< Raw byte buffer (FT_BYTES / FT_UINT_BYTES). */
        const char *str;                       /**< NUL-terminated string pointer (FT_STRING). */
        int32_t     i32;                       /**< Signed 32-bit integer. */
        int64_t     i64;                       /**< Signed 64-bit integer. */
        uint32_t    u32;                       /**< Unsigned 32-bit integer. */
        uint64_t    u64;                       /**< Unsigned 64-bit integer. */
        double      dbl;                       /**< Double-precision float. */
        bool        boolean;                   /**< Boolean value. */
        char        small_str[SFE_SMALL_BUF_SIZE];   /**< Inline string for short values (≤ SFE_SMALL_BUF_SIZE bytes). */
        uint8_t     small_bytes[SFE_SMALL_BUF_SIZE]; /**< Inline byte array for short values (≤ SFE_SMALL_BUF_SIZE bytes). */
    } res;
    int      res_len;   /**< [out] Byte length of the extracted value (meaningful for bytes/string types). */
    uint16_t field_idx; /**< [out] Index of the matched field, populated for syscall events. */
} sinsp_field_extract_t;


/**
 * @brief Combined byte size of an ss_plugin_event header plus the three
 *        length-prefix fields (plugin ID length, data length, plugin ID).
 */
#define PLUGIN_EVENT_HEADER_SIZE (26 + 4 + 4 + 4)

/**
 * @brief Holds a single field extraction request/result for a plugin event.
 *
 * Members marked [in] are populated by the caller before extraction;
 * members marked [out] are filled in by the extraction routine.
 * Members marked [in, out] serve a dual role.
 */
typedef struct plugin_field_extract_t {
    uint32_t    field_id;    /**< [out] Matched field ID for syscall events; [in] requested field ID for plugin events. */
    const char *field_name;  /**< [in]  Field name string as used in filter expressions. */
    enum ftenum type;        /**< [in, out] Wireshark field type; may be refined by the extractor. */
    bool        is_present;  /**< [out] @c true if the field was present and successfully extracted. */
    bool        is_generated;/**< [out] @c true if the value was synthetically generated rather than decoded from raw data. */

    /** @brief Extracted value; the active member is determined by @c type. */
    union {
        uint8_t    *bytes;    /**< Raw byte buffer. */
        const char *str;      /**< NUL-terminated string pointer. */
        int32_t     i32;      /**< Signed 32-bit integer. */
        int64_t     i64;      /**< Signed 64-bit integer. */
        uint32_t    u32;      /**< Unsigned 32-bit integer. */
        uint64_t    u64;      /**< Unsigned 64-bit integer. */
        double      dbl;      /**< Double-precision float. */
        uint8_t     ipv6[16]; /**< IPv6 address (128-bit, network byte order). */
        bool        boolean;  /**< Boolean value. */
    } res;
    int data_start;  /**< [out] Byte offset within the event buffer where the field data begins. */
    int data_length; /**< [out] Byte length of the field data within the event buffer. */
} plugin_field_extract_t;

/**
 * @brief Creates a new sinsp_span_t object.
 *
 * This function allocates memory for a new sinsp_span_t object and initializes it with default values.
 *
 * @return A pointer to the newly created sinsp_span_t object.
 */
sinsp_span_t *create_sinsp_span(void);

/**
 * @brief Destroys a sinsp_span_t object.
 *
 * @param sinsp_span The span to be destroyed.
 */
void destroy_sinsp_span(sinsp_span_t *sinsp_span);

// Common routines
/**
 * @brief Returns the numeric identifier of the given sinsp source.
 *
 * @param ssi  Pointer to the sinsp source info instance to query.
 * @return     Numeric source ID.
 */
uint32_t get_sinsp_source_id(sinsp_source_info_t *ssi);

/**
 * @brief Returns the last error string recorded by the given sinsp source.
 *
 * @param ssi  Pointer to the sinsp source info instance to query.
 * @return     NUL-terminated error string, or an empty string if no error
 *             has occurred.
 */
const char *get_sinsp_source_last_error(sinsp_source_info_t *ssi);

/**
 * @brief Returns the name of the given sinsp source.
 *
 * @param ssi  Pointer to the sinsp source info instance to query.
 * @return     NUL-terminated source name string.
 */
const char *get_sinsp_source_name(sinsp_source_info_t *ssi);

/**
 * @brief Returns a human-readable description of the given sinsp source.
 *
 * @param ssi  Pointer to the sinsp source info instance to query.
 * @return     NUL-terminated description string.
 */
const char *get_sinsp_source_description(sinsp_source_info_t *ssi);

/**
 * @brief Retrieves information about a field in a sinsp_source_info_t structure.
 *
 * @param ssi Pointer to the sinsp_source_info_t structure.
 * @param field_num Index of the field to retrieve information for.
 * @param field Pointer to a sinsp_field_info_t structure where the field information will be stored.
 * @return true if the field information was successfully retrieved, false otherwise.
 */
bool get_sinsp_source_field_info(sinsp_source_info_t *ssi, size_t field_num, sinsp_field_info_t *field);

// libsinsp builtin syscall routines.

/**
 * @brief Creates a syscall source for a span.
 *
 * @param sinsp_span Pointer to the sinsp_span_t structure.
 * @param ssi_ptr Pointer to a pointer that will receive the sinsp_source_info_t structure.
 */
void create_sinsp_syscall_source(sinsp_span_t *sinsp_span, sinsp_source_info_t **ssi_ptr);

/**
 * @brief Opens a sinsp capture file.
 *
 * This function initializes and opens a sinsp span for capturing events from a specified file.
 *
 * @param sinsp_span Pointer to the sinsp span structure that will be initialized.
 * @param filepath The path to the capture file to open.
 */
void open_sinsp_capture(sinsp_span_t *sinsp_span, const char *filepath);

//uint32_t process_syscall_capture(sinsp_span_t * sinsp_span, sinsp_source_info_t *ssi, uint32_t to_event);

/**
 * @brief Closes a sinsp capture.
 *
 * @param sinsp_span Pointer to the sinsp span representing the capture session.
 */
void close_sinsp_capture(sinsp_span_t *sinsp_span);

/**
 * @brief Extract syscall source fields from a span.
 *
 * @param sinsp_span The span containing the syscall events.
 * @param ssi The source info for the span.
 * @param frame_num The frame number to extract fields from.
 * @param sinsp_fields Pointer to store the extracted fields.
 * @param sinsp_field_len Pointer to store the length of the extracted fields.
 * @param sisnp_evt_info Pointer to store event information.
 * @return true if extraction is successful, false otherwise.
 */
bool extract_syscall_source_fields(sinsp_span_t *sinsp_span, sinsp_source_info_t *ssi, uint32_t frame_num, sinsp_field_extract_t **sinsp_fields, uint32_t *sinsp_field_len, void** sisnp_evt_info);

/**
 * @brief Retrieves the parent category of a syscall based on the field check index.
 *
 * @param ssi Pointer to the source information structure.
 * @param field_check_idx Index used to determine the syscall category.
 * @return The parent category of the syscall, or SSC_OTHER if out of bounds.
 */
sinsp_syscall_category_e get_syscall_parent_category(sinsp_source_info_t *ssi, size_t field_check_idx);

/**
 * @brief Retrieves previously extracted syscall field values for a given frame
 *        using the built-in libsinsp syscall source, without requiring an explicit
 *        sinsp_source_info_t handle.
 *
 * @param sinsp_span      Span context that owns the libsinsp engine and the
 *                        syscall source registration.
 * @param frame_num       Wireshark frame number identifying the packet whose
 *                        corresponding syscall event is to be queried.
 * @param sinsp_fields    Output pointer set to the array of sinsp_field_extract_t
 *                        structures containing the extracted field values.
 * @param sinsp_field_len Output pointer set to the number of elements in
 *                        @p sinsp_fields.
 * @param sinsp_evt_info  Output pointer set to an opaque handle for the
 *                        underlying sinsp event; pass to get_evt_arg_name() or
 *                        evt_creates_fd() for further introspection.
 * @return @c true if field extraction succeeded and @p sinsp_fields is valid;
 *         @c false if the frame has no associated syscall event or extraction failed.
 */
bool get_extracted_syscall_source_fields(sinsp_span_t *sinsp_span, uint32_t frame_num, sinsp_field_extract_t **sinsp_fields, uint32_t *sinsp_field_len, void** sinsp_evt_info);

/**
 * @brief Retrieves the name of an event argument.
 *
 * @param sinsp_evt_info Pointer to the event information structure.
 * @param arg_num The index of the argument to retrieve.
 * @return A pointer to the argument name, or NULL if the argument number exceeds the event parameter count.
 */
char* get_evt_arg_name(void* sinsp_evt_info, uint32_t arg_num);

/**
 * @brief Checks if an event creates a file descriptor.
 *
 * @param sinsp_evt_info Pointer to the event information structure.
 * @return true if the event creates a file descriptor, false otherwise.
 */
bool evt_creates_fd(void* sinsp_evt_info);

// Extractor plugin routines.
// These roughly match common_plugin_info

/**
 * @brief Creates a new sinsp_plugin_source object.
 *
 * @param sinsp_span The span containing the plugin information.
 * @param libname The name of the library to register as a plugin.
 * @param ssi_ptr Pointer to store the created sinsp_source_info_t object.
 * @return char* A string error message if an error occurred, otherwise NULL.
 */
char *create_sinsp_plugin_source(sinsp_span_t *sinsp_span, const char* libname, sinsp_source_info_t **ssi_ptr);

/**
 * @brief Get the number of fields in a sinsp source.
 *
 * @param ssi Pointer to the sinsp_source_info_t structure.
 * @return size_t The number of fields.
 */
size_t get_sinsp_source_nfields(sinsp_source_info_t *ssi);

/**
 * @brief Extracts plugin source fields from an event.
 *
 * This function extracts fields from a given event and populates the provided
 * structure with the extracted data.
 *
 * @param ssi Pointer to the source information structure.
 * @param event_num The event number.
 * @param evt_data Pointer to the event data.
 * @param evt_datalen Length of the event data.
 * @param pool Memory allocator for temporary storage.
 * @param sinsp_fields Pointer to the structure where extracted fields will be stored.
 * @param sinsp_field_len Maximum length of the fields structure.
 * @return true if extraction is successful, false otherwise.
 */
bool extract_plugin_source_fields(sinsp_source_info_t *ssi, uint32_t event_num, const uint8_t *evt_data, uint32_t evt_datalen, wmem_allocator_t *pool, plugin_field_extract_t *sinsp_fields, uint32_t sinsp_field_len);


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // __SINSP_SPAN_H__
