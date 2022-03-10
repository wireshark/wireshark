/* sinsp-span.cpp
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

#include "config.h"

#include <stddef.h>
#include <stdint.h>

#include <glib.h>

// epan/address.h and driver/ppm_events_public.h both define PT_NONE, so
// handle libsinsp calls here.

#include <wsutil/wmem/wmem.h>

typedef struct hf_register_info hf_register_info;

typedef struct ss_plugin_info ss_plugin_info;

#include "sinsp-span.h"

#include <sinsp.h>

typedef struct sinsp_source_info_t {
    sinsp_source_plugin *source;
    const char *name;
    const char *description;
    char *last_error;
    const char *fields;
} sinsp_source_info_t;

typedef struct sinsp_span_t {
    sinsp inspector;
} sinsp_span_t;

sinsp_span_t *create_sinsp_span()
{
    return new(sinsp_span_t);
}

void destroy_sinsp_span(sinsp_span_t *sinsp_span) {
    delete(sinsp_span);
}

/*
 * Populate a source_plugin_info struct with the symbols coming from a library loaded via libsinsp
 */
bool
create_sinsp_source(sinsp_span_t *sinsp_span, const char* libname, sinsp_source_info_t **ssi_ptr)
{
    sinsp_source_info_t *ssi = new(sinsp_source_info_t);
    ssi->source = NULL;
    sinsp_plugin *sp = sinsp_source_plugin::register_plugin(&sinsp_span->inspector, libname, "{}").get();
    if (sp->type() == TYPE_SOURCE_PLUGIN) {
        ssi->source = dynamic_cast<sinsp_source_plugin *>(sp);
    }
    if (!ssi->source) {
        delete ssi;
        return false;
    }

    ssi->name = strdup(ssi->source->name().c_str());
    ssi->description = strdup(ssi->source->description().c_str());
    ssi->last_error = NULL;
    *ssi_ptr = ssi;
    return true;
}

uint32_t get_sinsp_source_id(sinsp_source_info_t *ssi)
{
    return ssi->source->id();
}

uint32_t get_sinsp_source_required_api_version_major(sinsp_source_info_t *ssi)
{
    return ssi->source->required_api_version().m_version_major;
}

uint32_t get_sinsp_source_required_api_version_minor(sinsp_source_info_t *ssi)
{
    return ssi->source->required_api_version().m_version_minor;
}

uint32_t get_sinsp_source_required_api_version_patch(sinsp_source_info_t *ssi)
{
    return ssi->source->required_api_version().m_version_patch;
}

bool init_sinsp_source(sinsp_source_info_t *ssi, const char *config)
{
    return ssi->source->init(config);
}

uint32_t get_sinsp_source_type(sinsp_source_info_t *ssi)
{
    return ssi->source->type();
}

const char *get_sinsp_source_last_error(sinsp_source_info_t *ssi)
{
    if (ssi->last_error) {
        free(ssi->last_error);
    }
    ssi->last_error = strdup(ssi->source->get_last_error().c_str());
    return ssi->last_error;
}

const char *get_sinsp_source_name(sinsp_source_info_t *ssi)
{
    return ssi->name;
}

const char *get_sinsp_source_description(sinsp_source_info_t *ssi)
{
    return ssi->description;
}

uint32_t get_sinsp_source_nfields(sinsp_source_info_t *ssi)
{
    return ssi->source->nfields();
}

bool get_sinsp_source_field_info(sinsp_source_info_t *ssi, unsigned field_num, sinsp_field_info_t *field)
{
    if (field_num >= ssi->source->nfields()) {
        return false;
    }

    const filtercheck_field_info *ffi = &ssi->source->fields()[field_num];

    switch (ffi->m_type) {
    case PT_CHARBUF:
        field->type = SFT_STRINGZ;
        break;
    case PT_UINT64:
        field->type = SFT_UINT64;
        break;
    default:
        field->type = SFT_UNKNOWN;
    }

    switch (ffi->m_print_format) {
    case PF_DEC:
        field->display_format = SFDF_DECIMAL;
        break;
    case PF_HEX:
        field->display_format = SFDF_HEXADECIMAL;
        break;
    case PF_OCT:
        field->display_format = SFDF_OCTAL;
        break;
    default:
        field->display_format = SFDF_UNKNOWN;
    }

    g_strlcpy(field->abbrev, ffi->m_name, sizeof(ffi->m_name));
    g_strlcpy(field->display, ffi->m_display, sizeof(ffi->m_display));
    g_strlcpy(field->description, ffi->m_description, sizeof(ffi->m_description));

    field->is_hidden = ffi->m_flags & EPF_TABLE_ONLY;
    field->is_info = ffi->m_flags & EPF_INFO;
    field->is_conversation = ffi->m_flags & EPF_CONVERSATION;

    return true;
}

bool extract_sisnp_source_field(sinsp_source_info_t *ssi, uint32_t evt_num, uint8_t *evt_data, uint32_t evt_datalen, wmem_allocator_t *pool, sinsp_field_extract_t *sfe)
{
    ss_plugin_event evt = { evt_num, evt_data, evt_datalen, (uint64_t) -1 };
    sinsp_plugin::ext_field field;
    // We must supply field_id, field, arg, and type.
    field.field_id = sfe->field_id;
    field.field = sfe->field_name;
//    field.arg = NULL;
    field.ftype = sfe->type == SFT_STRINGZ ? PT_CHARBUF : PT_UINT64;

    if (!ssi->source->extract_field(evt, field)) {
        return false;
    }

    sfe->is_present = field.field_present;
    if (field.field_present) {
        if (field.ftype == PT_CHARBUF) {
            sfe->res_str = wmem_strdup(pool, field.res_str.c_str());
        } else if (field.ftype == PT_UINT64) {
            sfe->res_u64 = field.res_u64;
        } else {
            return false;
        }
    }
    return true;
}
