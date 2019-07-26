/* extcap_parser.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __EXTCAP_PARSER_H__
#define __EXTCAP_PARSER_H__

#include <stdio.h>
#include <glib.h>
#include <string.h>

#include <config.h>
#include "ui/iface_toolbar.h"

typedef enum {
    EXTCAP_SENTENCE_UNKNOWN,
    EXTCAP_SENTENCE_ARG,
    EXTCAP_SENTENCE_VALUE,
    EXTCAP_SENTENCE_EXTCAP,
    EXTCAP_SENTENCE_INTERFACE,
    EXTCAP_SENTENCE_DLT,
    EXTCAP_SENTENCE_CONTROL
} extcap_sentence_type;

typedef enum {
    /* Simple types */
    EXTCAP_ARG_UNKNOWN,
    EXTCAP_ARG_INTEGER,
    EXTCAP_ARG_UNSIGNED,
    EXTCAP_ARG_LONG,
    EXTCAP_ARG_DOUBLE,
    EXTCAP_ARG_BOOLEAN,
    EXTCAP_ARG_BOOLFLAG,
    EXTCAP_ARG_STRING,
    EXTCAP_ARG_PASSWORD,
    /* Complex GUI types which are populated with value sentences */
    EXTCAP_ARG_SELECTOR,
    EXTCAP_ARG_RADIO,
    EXTCAP_ARG_MULTICHECK,
    EXTCAP_ARG_FILESELECT,
    EXTCAP_ARG_TIMESTAMP
} extcap_arg_type;

typedef enum {
    /* value types */
    EXTCAP_PARAM_UNKNOWN,
    EXTCAP_PARAM_ARGNUM,
    EXTCAP_PARAM_CALL,
    EXTCAP_PARAM_DISPLAY,
    EXTCAP_PARAM_TYPE,
    EXTCAP_PARAM_ARG,
    EXTCAP_PARAM_DEFAULT,
    EXTCAP_PARAM_VALUE,
    EXTCAP_PARAM_RANGE,
    EXTCAP_PARAM_TOOLTIP,
    EXTCAP_PARAM_PLACEHOLDER,
    EXTCAP_PARAM_NAME,
    EXTCAP_PARAM_ENABLED,
    EXTCAP_PARAM_FILE_MUSTEXIST,
    EXTCAP_PARAM_FILE_EXTENSION,
    EXTCAP_PARAM_GROUP,
    EXTCAP_PARAM_PARENT,
    EXTCAP_PARAM_REQUIRED,
    EXTCAP_PARAM_RELOAD,
    EXTCAP_PARAM_SAVE,
    EXTCAP_PARAM_VALIDATION,
    EXTCAP_PARAM_VERSION,
    EXTCAP_PARAM_HELP,
    EXTCAP_PARAM_CONTROL,
    EXTCAP_PARAM_ROLE
} extcap_param_type;

#define ENUM_KEY(s) GUINT_TO_POINTER((guint)s)

/* Values for a given sentence; values are all stored as a call
 * and a value string, or a valid range, so we only need to store
 * those and repeat them */
typedef struct _extcap_value {
    int arg_num;

    gchar *call;
    gchar *display;
    gboolean enabled;
    gboolean is_default;
    gchar *parent;
} extcap_value;

/* Complex-ish struct for storing complex values */
typedef struct _extcap_complex {
    extcap_arg_type complex_type;
    gchar * _val;
} extcap_complex;

/* An argument sentence and accompanying options */
typedef struct _extcap_arg {
    int arg_num;

    gchar *call;
    gchar *display;
    gchar *tooltip;
    gchar *placeholder;

    gchar * fileextension;
    gboolean fileexists;

    gboolean is_required;
    gboolean save;

    gboolean reload;

    gchar * regexp;

    gchar * group;

    extcap_arg_type arg_type;

    extcap_complex *range_start;
    extcap_complex *range_end;
    extcap_complex *default_complex;

    gchar ** pref_valptr; /**< A copy of the pointer containing the current preference value. */
    gchar * device_name;

    GList * values;
} extcap_arg;

typedef struct _extcap_interface {
    gchar * call;
    gchar * display;
    gchar * version;
    gchar * help;
    gchar * extcap_path;

    extcap_sentence_type if_type;
} extcap_interface;

typedef struct _extcap_dlt {
    gint number;
    gchar *name;
    gchar *display;
} extcap_dlt;

typedef struct _extcap_token_sentence {
    gchar *sentence;

    GHashTable *param_list;
} extcap_token_sentence;

#ifdef __cplusplus
extern "C" {
#endif

/* Parse a string into a complex type */
extcap_complex *extcap_parse_complex(extcap_arg_type complex_type,
        const gchar *data);

/* Free a complex */
void extcap_free_complex(extcap_complex *comp);

/* Print a complex value out for debug */
void extcap_printf_complex(extcap_complex *comp);

/*
 * Return a string representation of a complex type
 * Caller is responsible for calling g_free on the returned string
 */
gchar *extcap_get_complex_as_string(extcap_complex *comp);

gint extcap_complex_get_int(extcap_complex *comp);
guint extcap_complex_get_uint(extcap_complex *comp);
gint64 extcap_complex_get_long(extcap_complex *comp);
gdouble extcap_complex_get_double(extcap_complex *comp);
gboolean extcap_complex_get_bool(extcap_complex *comp);
gchar *extcap_complex_get_string(extcap_complex *comp);

/* compares the default value of an element with a given parameter */
gboolean extcap_compare_is_default(extcap_arg *element, extcap_complex *test);


/* Free a single argument */
void extcap_free_arg(extcap_arg *a);

/* Free entire toolbar control structure */
void extcap_free_toolbar_control(iface_toolbar_control *control);

/* Free an entire arg list */
void extcap_free_arg_list(GList *a);


/** Parser for extcap data */

/* Parse all sentences for args and values */
GList * extcap_parse_args(gchar *output);

/* Parse all sentences for values */
GList * extcap_parse_values(gchar *output);

/* Parse all sentences for interfaces */
GList * extcap_parse_interfaces(gchar *output, GList **control_items);

/* Parse all sentences for DLTs */
GList * extcap_parse_dlts(gchar *output);

#ifdef __cplusplus
}
#endif

#endif

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
