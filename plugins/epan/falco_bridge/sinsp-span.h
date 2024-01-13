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

typedef enum sinsp_field_display_format_e {
    SFDF_UNKNOWN,
    SFDF_DECIMAL,
    SFDF_HEXADECIMAL,
    SFDF_OCTAL
} sinsp_field_display_format_e;

// Should match sinsp_filter_check_list in libsinsp as closely as possible.

typedef enum sinsp_syscall_category_e {
    SSC_EVENT, // gen_event, event
    SSC_EVTARGS, // event arguments
    SSC_PROCESS, // thread
    SSC_PROCLINEAGE, // process lineage
    SSC_USER, // user
    SSC_GROUP, // group
    SSC_CONTAINER, // container
    SSC_FD, // fd
    SSC_FS, // fs.path
//    SSC_SYSLOG, // syslog. Collides with syslog dissector so skip for now.
    SSC_FDLIST, // fdlist
    SSC_OTHER, // "falco.", catch-all
    NUM_SINSP_SYSCALL_CATEGORIES
} sinsp_syscall_category_e;

typedef struct sinsp_field_info_t {
    enum ftenum type;
    sinsp_field_display_format_e display_format;
    char abbrev[64]; // filter name
    char display[64]; // display name
    char description[1024];
    bool is_hidden;
    bool is_conversation;
    bool is_info;
    bool is_numeric_address;
} sinsp_field_info_t;

#define SFE_SMALL_BUF_SIZE 8
typedef struct sinsp_field_extract_t {
    union {
        uint8_t *bytes;
        const char *str;
        int32_t i32;
        int64_t i64;
        uint32_t u32;
        uint64_t u64;
        double dbl;
        bool boolean;
        char small_str[SFE_SMALL_BUF_SIZE];
        uint8_t small_bytes[SFE_SMALL_BUF_SIZE];
    } res;
    int res_len;                // out
    uint16_t field_idx;          // out for syscalls
} sinsp_field_extract_t;

typedef struct plugin_field_extract_t {
    uint32_t field_id;          // out for syscalls, in for plugins
    const char *field_name;     // in
    enum ftenum type;           // in, out
    bool is_present;            // out
    union {
        uint8_t *bytes;
        const char *str;
        int32_t i32;
        int64_t i64;
        uint32_t u32;
        uint64_t u64;
        double dbl;
        uint8_t ipv6[16];
        bool boolean;
    } res;
    int res_len;                // out
//    sinsp_syscall_category_e parent_category;     // out
} plugin_field_extract_t;

sinsp_span_t *create_sinsp_span(void);
void destroy_sinsp_span(sinsp_span_t *sinsp_span);

// Common routines
uint32_t get_sinsp_source_id(sinsp_source_info_t *ssi);
const char *get_sinsp_source_last_error(sinsp_source_info_t *ssi);
const char *get_sinsp_source_name(sinsp_source_info_t *ssi);
const char* get_sinsp_source_description(sinsp_source_info_t *ssi);
bool get_sinsp_source_field_info(sinsp_source_info_t *ssi, size_t field_num, sinsp_field_info_t *field);
char* get_evt_arg_name(void* sinp_evt_info, uint32_t arg_num);

// libsinsp builtin syscall routines.
void create_sinsp_syscall_source(sinsp_span_t *sinsp_span, sinsp_source_info_t **ssi_ptr);
void open_sinsp_capture(sinsp_span_t *sinsp_span, const char *filepath);
//uint32_t process_syscall_capture(sinsp_span_t * sinsp_span, sinsp_source_info_t *ssi, uint32_t to_event);
void close_sinsp_capture(sinsp_span_t *sinsp_span);
bool extract_syscall_source_fields(sinsp_span_t *sinsp_span, sinsp_source_info_t *ssi, uint32_t frame_num, sinsp_field_extract_t **sinsp_fields, uint32_t *sinsp_field_len, void** sinp_evt_info);
sinsp_syscall_category_e get_syscall_parent_category(sinsp_source_info_t *ssi, size_t field_check_idx);
bool get_extracted_syscall_source_fields(sinsp_span_t *sinsp_span, uint32_t frame_num, sinsp_field_extract_t **sinsp_fields, uint32_t *sinsp_field_len, void** sinp_evt_info);

// Extractor plugin routines.
// These roughly match common_plugin_info
char *create_sinsp_plugin_source(sinsp_span_t *sinsp_span, const char* libname, sinsp_source_info_t **ssi_ptr);
size_t get_sinsp_source_nfields(sinsp_source_info_t *ssi);
bool extract_plugin_source_fields(sinsp_source_info_t *ssi, uint32_t event_num, uint8_t *evt_data, uint32_t evt_datalen, wmem_allocator_t *pool, plugin_field_extract_t *sinsp_fields, uint32_t sinsp_field_len);


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // __SINSP_SPAN_H__
