/* extcap_parser.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __EXTCAP_PARSER_H__
#define __EXTCAP_PARSER_H__

#include <stdio.h>
#include <glib.h>
#include <string.h>

typedef enum {
    EXTCAP_SENTENCE_UNKNOWN,
    EXTCAP_SENTENCE_ARG,
    EXTCAP_SENTENCE_VALUE,
    EXTCAP_SENTENCE_EXTCAP,
    EXTCAP_SENTENCE_INTERFACE,
    EXTCAP_SENTENCE_DLT
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
    EXTCAP_ARG_FILESELECT
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
    EXTCAP_PARAM_NAME,
    EXTCAP_PARAM_ENABLED,
    EXTCAP_PARAM_FILE_MUSTEXIST,
    EXTCAP_PARAM_FILE_EXTENSION,
    EXTCAP_PARAM_PARENT,
    EXTCAP_PARAM_REQUIRED,
    EXTCAP_PARAM_SAVE,
    EXTCAP_PARAM_VALIDATION,
    EXTCAP_PARAM_VERSION
} extcap_param_type;

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

    gchar * fileextension;
    gboolean fileexists;

    gboolean is_required;
    gboolean save;

    gchar * regexp;

    extcap_arg_type arg_type;

    extcap_complex *range_start;
    extcap_complex *range_end;
    extcap_complex *default_complex;

    gchar ** pref_valptr; /**< A copy of the pointer containing the current preference value. */
    gchar * device_name;

    GList * values;
} extcap_arg;

typedef struct _extcap_if {
    gchar * extcap_path;
    GList * interfaces;
} extcap_if;

typedef struct _extcap_interface {
    gchar *call;
    gchar *display;
    gchar *version;

    extcap_sentence_type if_type;
    struct _extcap_interface *next_interface;
} extcap_interface;

typedef struct _extcap_dlt {
    gint number;
    gchar *name;
    gchar *display;

    struct _extcap_dlt *next_dlt;
} extcap_dlt;

/* Parser internals */
typedef struct _extcap_token_param {
    gchar *arg;
    gchar *value;

    extcap_param_type param_type;

    struct _extcap_token_param *next_token;
} extcap_token_param;

typedef struct _extcap_token_sentence {
    gchar *sentence;

    extcap_token_param *param_list;

    struct _extcap_token_sentence *next_sentence;
} extcap_token_sentence;

#ifdef __cplusplus
extern "C" {
#endif

extcap_interface *extcap_new_interface(void);
void extcap_free_interface(extcap_interface *interface);

extcap_dlt *extcap_new_dlt(void);
void extcap_free_dlt(extcap_dlt *dlt);

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

void extcap_free_tokenized_param(extcap_token_param *v);
void extcap_free_tokenized_sentence(extcap_token_sentence *s);
void extcap_free_tokenized_sentence_list(extcap_token_sentence *f);

/* Turn a sentence into logical tokens, don't validate beyond basic syntax */
extcap_token_sentence *extcap_tokenize_sentence(const gchar *s);

/* Tokenize a set of sentences (such as the output of a g_spawn_sync) */
extcap_token_sentence *extcap_tokenize_sentences(const gchar *s);

/* Find an argument in the extcap_arg list which matches the given arg=X number */
extcap_arg *extcap_find_numbered_arg(extcap_arg *first, int number);

/* Find the first occurrence in a parameter list of a parameter of the given type */
extcap_token_param *extcap_find_param_by_type(extcap_token_param *first,
        extcap_param_type t);

void extcap_free_value(extcap_value *v);

/* Free a single argument */
void extcap_free_arg(extcap_arg *a);

/* Free an entire arg list */
void extcap_free_arg_list(GList *a);

/*
 * Parse a tokenized sentence and validate.  If a new sentence is created, the result
 * is returned in 'ra'.  On error, < 0 is returned.  Not all sentences will create a
 * new returned sentence (VALUE sentences, for example)
 */
extcap_arg * extcap_parse_arg_sentence(GList * args, extcap_token_sentence *s);

/* Parse all sentences for args and values */
GList * extcap_parse_args(extcap_token_sentence *first_s);

/*
 * Parse a tokenized set of sentences and validate, looking for interface definitions.
 */
int extcap_parse_interface_sentence(extcap_token_sentence *s,
        extcap_interface **ri);

/* Parse all sentences for interfaces */
int extcap_parse_interfaces(extcap_token_sentence *first_s,
        extcap_interface **first_int);

/* Parse a tokenized set of sentences and validate, looking for DLT definitions */
int extcap_parse_dlt_sentence(extcap_token_sentence *s, extcap_dlt **ri);

/* Parse all sentences for DLTs */
int extcap_parse_dlts(extcap_token_sentence *first_s, extcap_dlt **first_dlt);

#ifdef __cplusplus
}
#endif

#endif

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
