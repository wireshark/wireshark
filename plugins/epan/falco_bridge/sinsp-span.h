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

#include <wsutil/wmem/wmem.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct sinsp_source_info_t sinsp_source_info_t;
typedef struct sinsp_span_t sinsp_span_t;

typedef enum sinsp_field_type_e {
    SFT_UNKNOWN,
    SFT_STRINGZ,
    SFT_UINT64,
} sinsp_field_type_e;

typedef enum sinsp_field_display_format_e {
    SFDF_UNKNOWN,
    SFDF_DECIMAL,
    SFDF_HEXADECIMAL,
    SFDF_OCTAL
} sinsp_field_display_format_e;

typedef struct sinsp_field_info_t {
    sinsp_field_type_e type;
    sinsp_field_display_format_e display_format;
    char abbrev[64]; // filter name
    char display[64]; // display name
    char description[1024];
    bool is_hidden;
    bool is_conversation;
    bool is_info;
} sinsp_field_info_t;

typedef struct sinsp_field_extract_t {
    uint32_t field_id;          // in
    const char *field_name;     // in
    sinsp_field_type_e type;    // in, out
    bool is_present;            // out
    const char *res_str;        // out
    uint64_t res_u64;           // out
} sinsp_field_extract_t;

sinsp_span_t *create_sinsp_span(void);
void destroy_sinsp_span(sinsp_span_t *sinsp_span);

char *create_sinsp_source(sinsp_span_t *sinsp_span, const char* libname, sinsp_source_info_t **ssi_ptr);

// Extractor plugin routines.
// These roughly match common_plugin_info
uint32_t get_sinsp_source_id(sinsp_source_info_t *ssi);
const char *get_sinsp_source_last_error(sinsp_source_info_t *ssi);
const char *get_sinsp_source_name(sinsp_source_info_t *ssi);
const char* get_sinsp_source_description(sinsp_source_info_t *ssi);
size_t get_sinsp_source_nfields(sinsp_source_info_t *ssi);
bool get_sinsp_source_field_info(sinsp_source_info_t *ssi, size_t field_num, sinsp_field_info_t *field);
bool extract_sisnp_source_fields(sinsp_source_info_t *ssi, uint32_t evt_num, uint8_t *evt_data, uint32_t evt_datalen, wmem_allocator_t *pool, sinsp_field_extract_t *sinsp_fields, uint32_t sinsp_field_len);


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // __SINSP_SPAN_H__
