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
    std::vector<const filter_check_info *> syscall_filter_checks;
    std::vector<gen_event_filter_check *> syscall_event_filter_checks;
    std::vector<const filtercheck_field_info *> syscall_filter_fields;
    std::map<const filtercheck_field_info *, size_t> ffi_to_sf_idx;
    std::map<size_t, sinsp_syscall_category_e> field_to_category;
    sinsp_evt *evt;
    uint8_t *evt_storage;
    size_t evt_storage_size;
    const char *name;
    const char *description;
    char *last_error;
} sinsp_source_info_t;

typedef struct sinsp_span_t {
    sinsp inspector;
    sinsp_filter_check_list filter_checks;
} sinsp_span_t;

sinsp_span_t *create_sinsp_span()
{
    sinsp_span_t *span = new(sinsp_span_t);

    return span;
}

void destroy_sinsp_span(sinsp_span_t *sinsp_span) {
    delete(sinsp_span);
}

static sinsp_syscall_category_e filtercheck_name_to_category(const std::string fc_name) {
    // Must match libsinsp/sinsp_filtercheck_*.cpp
    std::map<const char *, sinsp_syscall_category_e> fc_name_to_category = {
        { "evt", SSC_EVENT },
        { "process", SSC_PROCESS },
        { "user", SSC_USER },
        { "group", SSC_GROUP },
        { "container", SSC_CONTAINER },
        { "fd", SSC_FD },
        { "fdlist", SSC_FDLIST },
        { "fs.path", SSC_FS },
    };

    for (const auto ptc : fc_name_to_category) {
        if (ptc.first == fc_name) {
            return ptc.second;
        }
    }
    return SSC_OTHER;
}

/*
 * Populate a sinsp_source_info_t struct with the symbols coming from libsinsp's builtin syscall extractors
 */
void create_sinsp_syscall_source(sinsp_span_t *sinsp_span, sinsp_source_info_t **ssi_ptr) {
    sinsp_source_info_t *ssi = new sinsp_source_info_t();

    std::shared_ptr<gen_event_filter_factory> factory(new sinsp_filter_factory(NULL, sinsp_span->filter_checks));
    sinsp_filter_factory filter_factory(&sinsp_span->inspector, sinsp_span->filter_checks);
    std::vector<const filter_check_info*> all_syscall_fields;

    // Extract the fields defined in filterchecks.{cpp,h}

    sinsp_span->filter_checks.get_all_fields(all_syscall_fields);
    for (const auto fci : all_syscall_fields) {
        if (fci->m_flags == filter_check_info::FL_HIDDEN) {
            continue;
        }
        sinsp_syscall_category_e syscall_category = filtercheck_name_to_category(fci->m_name);

        for (int i = 0; i < fci->m_nfields; i++) {
            const filtercheck_field_info *ffi = &fci->m_fields[i];
            if (ffi->m_flags == filtercheck_field_flags::EPF_NONE) {
                gen_event_filter_check *gefc = filter_factory.new_filtercheck(ffi->m_name);
                if (!gefc) {
                    continue;
                }
                gefc->parse_field_name(ffi->m_name, true, false);
                ssi->ffi_to_sf_idx[ffi] = ssi->syscall_filter_fields.size();
                ssi->field_to_category[ssi->syscall_filter_fields.size()] = syscall_category;
                ssi->syscall_event_filter_checks.push_back(gefc);
                ssi->syscall_filter_fields.push_back(ffi);
            }
        }
        ssi->syscall_filter_checks.push_back(fci);
    }

    ssi->evt = new sinsp_evt(&sinsp_span->inspector);
    ssi->evt_storage_size = 4096;
    ssi->evt_storage = (uint8_t *) g_malloc(ssi->evt_storage_size);
    ssi->name = strdup(sinsp_syscall_event_source_name);
    ssi->description = strdup(sinsp_syscall_event_source_name);
    *ssi_ptr = ssi;
    return;
}

/*
 * Populate a sinsp_source_info_t struct with the symbols coming from a library loaded via libsinsp
 */
char *
create_sinsp_plugin_source(sinsp_span_t *sinsp_span, const char* libname, sinsp_source_info_t **ssi_ptr)
{
    sinsp_source_info_t *ssi = new sinsp_source_info_t();

    char *err_str = NULL;
    try {
        auto sp = sinsp_span->inspector.register_plugin(libname);
        if (sp->caps() & CAP_EXTRACTION) {
            ssi->source = dynamic_cast<sinsp_plugin *>(sp.get());
        } else {
            err_str = g_strdup_printf("%s has unsupported plugin capabilities 0x%02x", libname, sp->caps());
        }
    } catch (const sinsp_exception& e) {
        err_str = g_strdup_printf("Caught sinsp exception %s", e.what());
    }

    std::string init_err;
    if (!err_str) {
        if (!ssi->source->init("{}", init_err)) {
            err_str = g_strdup_printf("Unable to initialize %s: %s", libname, init_err.c_str());
        }
    }
    if (err_str) {
        delete ssi;
        return err_str;
    }

    ssi->evt = new sinsp_evt(&sinsp_span->inspector);
    ssi->evt_storage_size = 4096;
    ssi->evt_storage = (uint8_t *) g_malloc(ssi->evt_storage_size);
    ssi->name = strdup(ssi->source->name().c_str());
    ssi->description = strdup(ssi->source->description().c_str());
    *ssi_ptr = ssi;
    return NULL;
}

uint32_t get_sinsp_source_id(sinsp_source_info_t *ssi)
{
    if (ssi->source) {
        return ssi->source->id();
    }
    return 0;
}

const char *get_sinsp_source_last_error(sinsp_source_info_t *ssi)
{
    if (ssi->source) {
        if (ssi->last_error) {
            free(ssi->last_error);
        }
        ssi->last_error = strdup(ssi->source->get_last_error().c_str());
    }
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
    if (ssi->source) {
        return ssi->source->fields().size();
    }

    return ssi->syscall_filter_fields.size();
}

bool get_sinsp_source_field_info(sinsp_source_info_t *ssi, size_t field_num, sinsp_field_info_t *field)
{
    if (field_num >= get_sinsp_source_nfields(ssi)) {
        return false;
    }

    const filtercheck_field_info *ffi = NULL;

    if (ssi->source) {
        ffi = &ssi->source->fields()[field_num];
        g_strlcpy(field->abbrev, ffi->m_name, sizeof(field->abbrev));
    } else {
        ffi = ssi->syscall_filter_fields[field_num];
        if (ssi->field_to_category[field_num] == SSC_OTHER) {
            snprintf(field->abbrev, sizeof(field->abbrev), FALCO_FIELD_NAME_PREFIX "%s", ffi->m_name);
        } else {
            snprintf(field->abbrev, sizeof(field->abbrev), "%s", ffi->m_name);
        }
    }

    field->is_numeric_address = false;

    switch (ffi->m_type) {
    case PT_INT8:
        field->type = FT_INT8;
        break;
    case PT_INT16:
        field->type = FT_INT16;
        break;
    case PT_INT32:
        field->type = FT_INT32;
        break;
    case PT_INT64:
        field->type = FT_INT64;
        break;
    case PT_UINT8:
        field->type = FT_UINT8;
        break;
    case PT_UINT16:
    case PT_PORT:
        field->type = FT_UINT16;
        break;
    case PT_UINT32:
        field->type = FT_UINT32;
        break;
    case PT_UINT64:
    case PT_RELTIME:
    case PT_ABSTIME:
        field->type = FT_UINT64;
        break;
    case PT_CHARBUF:
        field->type = FT_STRINGZ;
        break;
//        field->type = FT_RELATIVE_TIME;
//        break;
//        field->type = FT_ABSOLUTE_TIME;
//        field->type = FT_UINT64;
//        field->display_format = SFDF_DECIMAL;
        break;
    case PT_BYTEBUF:
        field->type = FT_BYTES;
    case PT_BOOL:
        field->type = FT_BOOLEAN;
        break;
    case PT_DOUBLE:
        field->type = FT_DOUBLE;
        break;
    case PT_IPADDR:
        field->type = FT_BYTES;
        field->is_numeric_address = true;
        break;
    default:
        ws_debug("Unknown Falco parameter type %d for %s", ffi->m_type, field->abbrev);
        field->type = FT_BYTES;
    }

    switch (ffi->m_print_format) {
    case PF_DEC:
    case PF_10_PADDED_DEC:
    case PF_ID:
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
        break;
    }

    g_strlcpy(field->display, ffi->m_display, sizeof(field->display));
    g_strlcpy(field->description, ffi->m_description, sizeof(field->description));

    field->is_hidden = ffi->m_flags & EPF_TABLE_ONLY;
    field->is_info = ffi->m_flags & EPF_INFO;
    field->is_conversation = ffi->m_flags & EPF_CONVERSATION;

    return true;
}

void open_sinsp_capture(sinsp_span_t *sinsp_span, const char *filepath)
{
    sinsp_span->inspector.open_savefile(filepath);
}

void close_sinsp_capture(sinsp_span_t *sinsp_span)
{
    sinsp_span->inspector.close();
}

bool extract_syscall_source_fields(sinsp_source_info_t *ssi, uint16_t event_type, uint32_t nparams, uint64_t ts, uint64_t thread_id, uint16_t cpu_id, uint8_t *evt_data, uint32_t evt_datalen, wmem_allocator_t *pool, sinsp_field_extract_t *sinsp_fields, uint32_t sinsp_field_len) {
    if (ssi->source) {
        return false;
    }

    uint32_t payload_hdr_size = (nparams + 1) * 4;
    uint32_t tot_evt_len = (uint32_t)sizeof(scap_evt) + evt_datalen;
    if (ssi->evt_storage_size < tot_evt_len) {
        while (ssi->evt_storage_size < tot_evt_len) {
            ssi->evt_storage_size *= 2;
        }
        ssi->evt_storage = (uint8_t *) g_realloc(ssi->evt_storage, ssi->evt_storage_size);
    }
    scap_evt *sevt = (scap_evt *) ssi->evt_storage;

    sevt->ts = ts;
    sevt->tid = thread_id;
    sevt->len = tot_evt_len - payload_hdr_size;
    sevt->type = event_type;
    sevt->nparams = nparams;

    memcpy(ssi->evt_storage + sizeof(scap_evt), evt_data, evt_datalen);
    ssi->evt->init(ssi->evt_storage, cpu_id);

    for (size_t sf_idx = 0; sf_idx < sinsp_field_len; sf_idx++) {
        sinsp_fields[sf_idx].is_present = false;
    }

    bool status = false;
    for (size_t fc_idx = 0; fc_idx < ssi->syscall_event_filter_checks.size(); fc_idx++) {
        std::vector<extract_value_t> values;
        auto gefc = ssi->syscall_event_filter_checks[fc_idx];
        values.clear();
        if (!gefc->extract(ssi->evt, values, false) || values.size() < 1) {
            continue;
        }
        auto ffi = ssi->syscall_filter_fields[fc_idx];
        if (ffi->m_flags == filtercheck_field_flags::EPF_NONE && values[0].len > 0) {
            size_t sf_idx = ssi->ffi_to_sf_idx[ffi];
            // XXX Use memcpy instead of all this casting?
            switch (ffi->m_type) {
            case PT_INT8:
                sinsp_fields[sf_idx].res.i32 = *(int8_t*)values[0].ptr;
                break;
            case PT_INT16:
                sinsp_fields[sf_idx].res.i32 = *(int16_t*)values[0].ptr;
                break;
            case PT_INT32:
                sinsp_fields[sf_idx].res.i32 = *(int32_t*)values[0].ptr;
                break;
            case PT_INT64:
                sinsp_fields[sf_idx].res.i64 = *(int64_t *)values[0].ptr;
                break;
            case PT_UINT8:
                sinsp_fields[sf_idx].res.u32 = *(uint8_t*)values[0].ptr;
                break;
            case PT_UINT16:
            case PT_PORT:
                sinsp_fields[sf_idx].res.u32 = *(int16_t*)values[0].ptr;
                break;
            case PT_UINT32:
                sinsp_fields[sf_idx].res.u32 = *(int32_t*)values[0].ptr;
                break;
            case PT_UINT64:
            case PT_RELTIME:
            case PT_ABSTIME:
                sinsp_fields[sf_idx].res.u64 = *(uint64_t *)values[0].ptr;
                break;
            case PT_CHARBUF:
                sinsp_fields[sf_idx].res.str = (char *) wmem_strdup(pool, (const char *) values[0].ptr);
                // XXX - Not needed? This sometimes runs into length mismatches.
                // sinsp_fields[sf_idx].res.str[values[0].len] = '\0';
                break;
            case PT_BOOL:
                sinsp_fields[sf_idx].res.boolean = (bool)(uint32_t) *(uint32_t*)values[0].ptr;
                break;
            case PT_DOUBLE:
                sinsp_fields[sf_idx].res.dbl = *(double*)values[0].ptr;
                break;
            default:
                sinsp_fields[sf_idx].res.bytes = (uint8_t*) wmem_memdup(pool, (const uint8_t *) values[0].ptr, values[0].len);
            }

            sinsp_fields[sf_idx].res_len = values[0].len;
            sinsp_fields[sf_idx].is_present = true;
            sinsp_fields[sf_idx].parent_category = ssi->field_to_category[fc_idx];
        }
        status = true;
    }

    return status;
}

// The code below, falcosecurity/libs, and falcosecurity/plugins need to be in alignment.
// The Makefile in /plugins defines FALCOSECURITY_LIBS_REVISION and uses that version of
// plugin_info.h. We need to build against a compatible revision of /libs.
bool extract_plugin_source_fields(sinsp_source_info_t *ssi, uint32_t event_num, uint8_t *evt_data, uint32_t evt_datalen, wmem_allocator_t *pool, sinsp_field_extract_t *sinsp_fields, uint32_t sinsp_field_len)
{
    if (!ssi->source) {
        return false;
    }

    std::vector<ss_plugin_extract_field> fields;

    // PPME_PLUGINEVENT_E events have the following format:
    // | scap_evt header | uint32_t sizeof(id) = 4 | uint32_t evt_datalen | uint32_t id | uint8_t[] evt_data |

    uint32_t payload_hdr[3] = {4, evt_datalen, ssi->source->id()};
//    uint32_t payload_hdr_size = (nparams + 1) * 4;
    uint32_t tot_evt_len = (uint32_t)sizeof(scap_evt) + sizeof(payload_hdr) + evt_datalen;
    if (ssi->evt_storage_size < tot_evt_len) {
        while (ssi->evt_storage_size < tot_evt_len) {
            ssi->evt_storage_size *= 2;
        }
        ssi->evt_storage = (uint8_t *) g_realloc(ssi->evt_storage, ssi->evt_storage_size);
    }
    scap_evt *sevt = (scap_evt *) ssi->evt_storage;

    sevt->ts = -1;
    sevt->tid = -1;
    sevt->len = tot_evt_len;
    sevt->type = PPME_PLUGINEVENT_E;
    sevt->nparams = 2; // Plugin ID + evt_data;

    memcpy(ssi->evt_storage + sizeof(scap_evt), payload_hdr, sizeof(payload_hdr));
    memcpy(ssi->evt_storage + sizeof(scap_evt) + sizeof(payload_hdr), evt_data, evt_datalen);
    ssi->evt->init(ssi->evt_storage, 0);
    ssi->evt->set_num(event_num);

    fields.resize(sinsp_field_len);
    // We must supply field_id, field, arg, and type.
    for (size_t i = 0; i < sinsp_field_len; i++) {
        fields.at(i).field_id = sinsp_fields[i].field_id;
        fields.at(i).field = sinsp_fields[i].field_name;
        if (sinsp_fields[i].type == FT_STRINGZ) {
            fields.at(i).ftype = FTYPE_STRING;
        } else {
            fields.at(i).ftype = FTYPE_UINT64;
        }
    }

    bool status = true;
    if (!ssi->source->extract_fields(ssi->evt, sinsp_field_len, fields.data())) {
        status = false;
    }

    for (size_t i = 0; i < sinsp_field_len; i++) {
        sinsp_fields[i].is_present = fields.at(i).res_len > 0;
        if (sinsp_fields[i].is_present) {
            if (fields.at(i).ftype == PT_CHARBUF) {
                sinsp_fields[i].res.str = wmem_strdup(pool, *fields.at(i).res.str);
            } else if (fields.at(i).ftype == PT_UINT64) {
                sinsp_fields[i].res.u64 = *fields.at(i).res.u64;
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
