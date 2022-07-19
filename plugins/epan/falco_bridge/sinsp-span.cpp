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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4100)
#pragma warning(disable:4267)
#endif

// epan/address.h and driver/ppm_events_public.h both define PT_NONE, so
// handle libsinsp calls here.

typedef struct hf_register_info hf_register_info;

typedef struct ss_plugin_info ss_plugin_info;

#include "sinsp-span.h"

#include <sinsp.h>

typedef struct sinsp_source_info_t {
    sinsp_plugin *source;
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
char *
create_sinsp_source(sinsp_span_t *sinsp_span, const char* libname, sinsp_source_info_t **ssi_ptr)
{
    char *err_str = NULL;
    sinsp_source_info_t *ssi = new sinsp_source_info_t();

    try {
        sinsp_plugin *sp = sinsp_span->inspector.register_plugin(libname).get();
        if (sp->caps() & CAP_EXTRACTION) {
            ssi->source = dynamic_cast<sinsp_plugin *>(sp);
        } else {
            err_str = g_strdup_printf("%s has unsupported plugin capabilities 0x%02x", libname, sp->caps());
        }
    } catch (const sinsp_exception& e) {
        err_str = g_strdup_printf("Caught sinsp exception %s", e.what());
    }

    std::string init_err;
    if (!ssi->source->init("{}", init_err)) {
        err_str = g_strdup_printf("Unable to initialize %s: %s", libname, init_err.c_str());
    }

    if (err_str) {
        delete ssi;
        return err_str;
    }

    ssi->name = strdup(ssi->source->name().c_str());
    ssi->description = strdup(ssi->source->description().c_str());
    *ssi_ptr = ssi;
    return NULL;
}

uint32_t get_sinsp_source_id(sinsp_source_info_t *ssi)
{
    return ssi->source->id();
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

size_t get_sinsp_source_nfields(sinsp_source_info_t *ssi)
{
    return ssi->source->fields().size();
}

bool get_sinsp_source_field_info(sinsp_source_info_t *ssi, size_t field_num, sinsp_field_info_t *field)
{
    if (field_num >= ssi->source->fields().size()) {
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

// The code below, falcosecurity/libs, and falcosecurity/plugins need to be in alignment.
// The Makefile in /plugins defines FALCOSECURITY_LIBS_REVISION and uses that version of
// plugin_info.h. We need to build against a compatible revision of /libs.
bool extract_sisnp_source_fields(sinsp_source_info_t *ssi, uint32_t evt_num, uint8_t *evt_data, uint32_t evt_datalen, wmem_allocator_t *pool, sinsp_field_extract_t *sinsp_fields, uint32_t sinsp_field_len)
{
    ss_plugin_event evt = { evt_num, evt_data, evt_datalen, (uint64_t) -1 };
    std::vector<ss_plugin_extract_field> fields;

    fields.resize(sinsp_field_len);
    // We must supply field_id, field, arg, and type.
    for (size_t i = 0; i < sinsp_field_len; i++) {
        fields.at(i).field_id = sinsp_fields[i].field_id;
        fields.at(i).field = sinsp_fields[i].field_name;
        if (sinsp_fields[i].type == SFT_STRINGZ) {
            fields.at(i).ftype = FTYPE_STRING;
        } else {
            fields.at(i).ftype = FTYPE_UINT64;
        }
    }

    bool status = true;
    if (!ssi->source->extract_fields(evt, sinsp_field_len, fields.data())) {
        status = false;
    }

    for (size_t i = 0; i < sinsp_field_len; i++) {
        sinsp_fields[i].is_present = fields.at(i).res_len > 0;
        if (sinsp_fields[i].is_present) {
            if (fields.at(i).ftype == PT_CHARBUF) {
                sinsp_fields[i].res_str = wmem_strdup(pool, *fields.at(i).res.str);
            } else if (fields.at(i).ftype == PT_UINT64) {
                sinsp_fields[i].res_u64 = *fields.at(i).res.u64;
            } else {
                status = false;
            }
        }
    }
    return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
