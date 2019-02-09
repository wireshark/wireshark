/* wsjson.h
 * Routines for serializing data as JSON.
 *
 * Copyright 2018, Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __JSON_DUMPER_H__
#define __JSON_DUMPER_H__

#include "ws_symbol_export.h"
#include <glib.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Example:
 *
 *  json_dumper dumper = {
 *      .output_file = stdout,
 *      .flags = JSON_DUMPER_FLAGS_PRETTY_PRINT,
 *  };
 *  json_dumper_begin_object(&dumper);
 *  json_dumper_set_member_name(&dumper, "key");
 *  json_dumper_value_string(&dumper, "value");
 *  json_dumper_set_member_name(&dumper, "array");
 *  json_dumper_begin_array(&dumper);
 *  json_dumper_value_anyf(&dumper, "true");
 *  json_dumper_value_double(&dumper, 1.0);
 *  json_dumper_begin_base64(&dumper);
 *  json_dumper_write_base64(&dumper, (const guchar *)"abcd", 4);
 *  json_dumper_write_base64(&dumper, (const guchar *)"1234", 4);
 *  json_dumper_end_base64(&dumper);
 *  json_dumper_begin_object(&dumper);
 *  json_dumper_end_object(&dumper);
 *  json_dumper_begin_array(&dumper);
 *  json_dumper_end_array(&dumper);
 *  json_dumper_end_array(&dumper);
 *  json_dumper_end_object(&dumper);
 *  json_dumper_finish(&dumper);
 */

/** Maximum object/array nesting depth. */
#define JSON_DUMPER_MAX_DEPTH   1100
typedef struct json_dumper {
    FILE   *output_file;    /**< Output file, must be set. */
#define JSON_DUMPER_FLAGS_PRETTY_PRINT  (1 << 0)    /* Enable pretty printing. */
#define JSON_DUMPER_DOT_TO_UNDERSCORE   (1 << 1)    /* Convert dots to underscores in keys */
    int     flags;
    /* for internal use, initialize with zeroes. */
    int     current_depth;
    gint    base64_state;
    gint    base64_save;
    guint8  state[JSON_DUMPER_MAX_DEPTH];
} json_dumper;

WS_DLL_PUBLIC void
json_dumper_begin_object(json_dumper *dumper);

WS_DLL_PUBLIC void
json_dumper_set_member_name(json_dumper *dumper, const char *name);

WS_DLL_PUBLIC void
json_dumper_end_object(json_dumper *dumper);

WS_DLL_PUBLIC void
json_dumper_begin_array(json_dumper *dumper);

WS_DLL_PUBLIC void
json_dumper_end_array(json_dumper *dumper);

WS_DLL_PUBLIC void
json_dumper_value_string(json_dumper *dumper, const char *value);

WS_DLL_PUBLIC void
json_dumper_value_double(json_dumper *dumper, double value);

/**
 * Dump number, "true", "false" or "null" values.
 */
WS_DLL_PUBLIC void
json_dumper_value_anyf(json_dumper *dumper, const char *format, ...)
G_GNUC_PRINTF(2, 3);

/**
 * Dump literal values (like json_dumper_value_anyf), but taking a va_list
 * as parameter. String values MUST be properly quoted by the caller, no
 * escaping occurs. Do not use with untrusted data.
 */
WS_DLL_PUBLIC void
json_dumper_value_va_list(json_dumper *dumper, const char *format, va_list ap);

WS_DLL_PUBLIC void
json_dumper_begin_base64(json_dumper *dumper);

WS_DLL_PUBLIC void
json_dumper_end_base64(json_dumper *dumper);

WS_DLL_PUBLIC void
json_dumper_write_base64(json_dumper *dumper, const guchar *data, size_t len);

/**
 * Finishes dumping data. Returns TRUE if everything is okay and FALSE if
 * something went wrong (open/close mismatch, missing values, etc.).
 */
WS_DLL_PUBLIC gboolean
json_dumper_finish(json_dumper *dumper);

#ifdef __cplusplus
}
#endif

#endif /* __JSON_DUMPER_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
