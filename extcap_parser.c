/* extcap_parser.c
 *
 * Routines for extcap external capture
 * Copyright 2013, Mike Ryan <mikeryan@lacklustre.net>
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

#include <config.h>

#include <stdio.h>
#include <glib.h>
#include <string.h>

#include "extcap.h"
#include "extcap_parser.h"

void extcap_printf_complex(extcap_complex *comp) {
    gchar *ret = extcap_get_complex_as_string(comp);
    printf("%s", ret);
    g_free(ret);
}

gchar *extcap_get_complex_as_string(extcap_complex *comp) {
    return (comp ? g_strdup(comp->_val) : NULL);
}

extcap_complex *extcap_parse_complex(extcap_arg_type complex_type,
        const gchar *data) {

    extcap_complex *rc = g_new0(extcap_complex, 1);

    rc->_val = g_strdup(data);
    rc->complex_type = complex_type;

    return rc;
}

gboolean extcap_compare_is_default(extcap_arg *element, extcap_complex *test) {
    if ( element == NULL || element->default_complex == NULL || test == NULL )
        return FALSE;

    if ( g_strcmp0(element->default_complex->_val, test->_val) == 0 )
        return TRUE;

    return FALSE;
}

void extcap_free_complex(extcap_complex *comp) {
    if ( comp )
        g_free(comp->_val);
    g_free(comp);
}

gint extcap_complex_get_int(extcap_complex *comp) {
    if ( comp == NULL || comp->_val == NULL || comp->complex_type != EXTCAP_ARG_INTEGER )
        return (gint)0;

    return (gint) g_ascii_strtoll(comp->_val, NULL, 10);
}

guint extcap_complex_get_uint(extcap_complex *comp) {
    if ( comp == NULL || comp->_val == NULL || comp->complex_type != EXTCAP_ARG_UNSIGNED )
        return (guint)0;
    return (guint) g_ascii_strtoull(comp->_val, NULL, 10);
}

gint64 extcap_complex_get_long(extcap_complex *comp) {
    if ( comp == NULL || comp->_val == NULL || comp->complex_type != EXTCAP_ARG_LONG )
        return (gint64)0;
    return g_ascii_strtoll( comp->_val, NULL, 10 );
}

gdouble extcap_complex_get_double(extcap_complex *comp) {
    if ( comp == NULL || comp->_val == NULL || comp->complex_type != EXTCAP_ARG_DOUBLE )
        return (gdouble)0;
    return g_strtod( comp->_val, NULL );
}

gboolean extcap_complex_get_bool(extcap_complex *comp) {
    if ( comp == NULL || comp->_val == NULL  )
        return FALSE;

    if ( comp->complex_type != EXTCAP_ARG_BOOLEAN && comp->complex_type != EXTCAP_ARG_BOOLFLAG )
        return FALSE;

    return g_regex_match_simple(EXTCAP_BOOLEAN_REGEX, comp->_val, G_REGEX_CASELESS, (GRegexMatchFlags)0 );
}

gchar *extcap_complex_get_string(extcap_complex *comp) {
    /* Not checking for argument type, to use this method as fallback if only strings are needed */
    return comp != NULL ? comp->_val : NULL;
}

void extcap_free_tokenized_param(extcap_token_param *v) {
    if (v != NULL)
    {
        g_free(v->arg);
        g_free(v->value);
    }

    g_free(v);
}

void extcap_free_tokenized_sentence(extcap_token_sentence *s) {
    extcap_token_param *tv;

    if (s == NULL)
        return;

    if (s->sentence != NULL)
        g_free(s->sentence);

    while (s->param_list != NULL ) {
        tv = s->param_list;
        s->param_list = tv->next_token;

        extcap_free_tokenized_param(tv);
    }
    g_free(s);
}

void extcap_free_tokenized_sentence_list(extcap_token_sentence *f) {
    extcap_token_sentence *t;

    while (f != NULL ) {
        t = f->next_sentence;
        extcap_free_tokenized_sentence(f);
        f = t;
    }
}

extcap_token_sentence *extcap_tokenize_sentence(const gchar *s) {
    extcap_token_param *tv = NULL;
    GRegex * regex = NULL;
    GMatchInfo * match_info = NULL;
    GError * error = NULL;

    extcap_token_sentence *rs = g_new(extcap_token_sentence, 1);

    rs->sentence = NULL;
    rs->next_sentence = NULL;
    rs->param_list = NULL;

    /* Regex for catching just the allowed values for sentences */
    if ( ( regex = g_regex_new ( "^[\\t| ]*(arg|value|interface|extcap|dlt)(?=[\\t| ]+\\{)",
            (GRegexCompileFlags) G_REGEX_CASELESS, (GRegexMatchFlags) 0, NULL ) ) != NULL ) {
        g_regex_match ( regex, s, (GRegexMatchFlags) 0, &match_info );

        if ( g_match_info_matches ( match_info ) )
            rs->sentence = g_match_info_fetch(match_info, 0);

        g_match_info_free ( match_info );
        g_regex_unref ( regex );
    }
    /* No valid sentence found, exiting here */
    if ( rs->sentence == NULL ) {
        extcap_free_tokenized_sentence(rs);
        return NULL;
    }

    /* Capture the argument and the value of the list. This will ensure,
     * that regex patterns given to {validation=} are parsed correctly,
     * as long as }{ does not occur within the pattern */
    regex = g_regex_new ( "\\{([a-zA-Z_-]*?)\\=(.*?)\\}(?=\\{|$|\\s)",
            (GRegexCompileFlags) G_REGEX_CASELESS, (GRegexMatchFlags) 0, NULL );
    if ( regex != NULL ) {
        g_regex_match_full(regex, s, -1, 0, (GRegexMatchFlags) 0, &match_info, &error );
        while(g_match_info_matches(match_info)) {
            gchar * arg = g_match_info_fetch ( match_info, 1 );

            if ( arg == NULL )
                break;

            tv = g_new(extcap_token_param, 1);
            tv->arg = arg;
            tv->value = g_match_info_fetch ( match_info, 2 );

            if (g_ascii_strcasecmp(tv->arg, "number") == 0) {
                tv->param_type = EXTCAP_PARAM_ARGNUM;
            } else if (g_ascii_strcasecmp(tv->arg, "call") == 0) {
                tv->param_type = EXTCAP_PARAM_CALL;
            } else if (g_ascii_strcasecmp(tv->arg, "display") == 0) {
                tv->param_type = EXTCAP_PARAM_DISPLAY;
            } else if (g_ascii_strcasecmp(tv->arg, "type") == 0) {
                tv->param_type = EXTCAP_PARAM_TYPE;
            } else if (g_ascii_strcasecmp(tv->arg, "arg") == 0) {
                tv->param_type = EXTCAP_PARAM_ARG;
            } else if (g_ascii_strcasecmp(tv->arg, "default") == 0) {
                tv->param_type = EXTCAP_PARAM_DEFAULT;
            } else if (g_ascii_strcasecmp(tv->arg, "value") == 0) {
                tv->param_type = EXTCAP_PARAM_VALUE;
            } else if (g_ascii_strcasecmp(tv->arg, "range") == 0) {
                tv->param_type = EXTCAP_PARAM_RANGE;
            } else if (g_ascii_strcasecmp(tv->arg, "tooltip") == 0) {
                tv->param_type = EXTCAP_PARAM_TOOLTIP;
            } else if (g_ascii_strcasecmp(tv->arg, "mustexist") == 0) {
                tv->param_type = EXTCAP_PARAM_FILE_MUSTEXIST;
            } else if (g_ascii_strcasecmp(tv->arg, "fileext") == 0) {
                tv->param_type = EXTCAP_PARAM_FILE_EXTENSION;
            } else if (g_ascii_strcasecmp(tv->arg, "name") == 0) {
                tv->param_type = EXTCAP_PARAM_NAME;
            } else if (g_ascii_strcasecmp(tv->arg, "enabled") == 0) {
                tv->param_type = EXTCAP_PARAM_ENABLED;
            } else if (g_ascii_strcasecmp(tv->arg, "parent") == 0) {
                tv->param_type = EXTCAP_PARAM_PARENT;
            } else if (g_ascii_strcasecmp(tv->arg, "required") == 0) {
                tv->param_type = EXTCAP_PARAM_REQUIRED;
            } else if (g_ascii_strcasecmp(tv->arg, "save") == 0) {
                tv->param_type = EXTCAP_PARAM_SAVE;
            } else if (g_ascii_strcasecmp(tv->arg, "validation") == 0) {
                tv->param_type = EXTCAP_PARAM_VALIDATION;
            } else if (g_ascii_strcasecmp(tv->arg, "version") == 0) {
                tv->param_type = EXTCAP_PARAM_VERSION;
            } else {
                tv->param_type = EXTCAP_PARAM_UNKNOWN;
            }

            tv->next_token = rs->param_list;
            rs->param_list = tv;

            g_match_info_next(match_info, &error);
        }
        g_match_info_free(match_info);
        g_regex_unref(regex);
    }

    return rs;
}

extcap_token_sentence *extcap_tokenize_sentences(const gchar *s) {
    extcap_token_sentence *first = NULL, *cur = NULL, *last = NULL;

    gchar **list, **list_iter;

    list_iter = list = g_strsplit(s, "\n", 0);

    while (*list_iter != NULL ) {
        cur = extcap_tokenize_sentence(*list_iter);

        if (cur != NULL) {
            if (first == NULL) {
                first = cur;
                last = cur;
            } else {
                last->next_sentence = cur;
                last = cur;
            }
        }

        list_iter++;
    }

    g_strfreev(list);

    return first;
}

extcap_token_param *extcap_find_param_by_type(extcap_token_param *first,
        extcap_param_type t) {
    while (first != NULL ) {
        if (first->param_type == t) {
            return first;
        }

        first = first->next_token;
    }

    return NULL ;
}

void extcap_free_value(extcap_value *v) {
    if (v == NULL)
        return;

    g_free(v->call);
    g_free(v->display);

    g_free(v);
}

extcap_interface *extcap_new_interface(void) {
    extcap_interface *r = g_new(extcap_interface, 1);

    r->call = r->display = r->version = NULL;
    r->if_type = EXTCAP_SENTENCE_UNKNOWN;
    r->next_interface = NULL;

    return r;
}

void extcap_free_interface(extcap_interface *i) {
    extcap_interface *next_i = i;

    while (i) {
        next_i = i->next_interface;
        g_free(i->call);
        g_free(i->display);
        g_free(i->version);
        g_free(i);
        i = next_i;
    }
}

extcap_dlt *extcap_new_dlt(void) {
    extcap_dlt *r = g_new(extcap_dlt, 1);

    r->number = -1;
    r->name = r->display = NULL;
    r->next_dlt = NULL;

    return r;
}

void extcap_free_dlt(extcap_dlt *d) {
    if (d == NULL)
        return;

    g_free(d->name);
    g_free(d->display);
}

static void extcap_free_valuelist(gpointer data, gpointer user_data _U_) {
    extcap_free_value((extcap_value *) data);
}

void extcap_free_arg(extcap_arg *a) {

    if (a == NULL)
        return;

    g_free(a->call);
    g_free(a->display);
    g_free(a->tooltip);
    g_free(a->fileextension);
    g_free(a->regexp);
    g_free(a->device_name);

    if (a->range_start != NULL)
        extcap_free_complex(a->range_start);

    if (a->range_end != NULL)
        extcap_free_complex(a->range_end);

    if (a->default_complex != NULL)
        extcap_free_complex(a->default_complex);

    g_list_foreach(a->values, (GFunc) extcap_free_valuelist, NULL);
}

static void extcap_free_arg_list_cb(gpointer listentry, gpointer data _U_) {
    if (listentry != NULL)
        extcap_free_arg((extcap_arg *) listentry);
}

void extcap_free_arg_list(GList *a) {
    g_list_foreach(a, extcap_free_arg_list_cb, NULL);
    g_list_free(a);
}

static gint glist_find_numbered_arg(gconstpointer listelem, gconstpointer needle) {
    if (((const extcap_arg *) listelem)->arg_num == *((const int*) needle))
        return 0;
    return 1;
}

extcap_arg *extcap_parse_arg_sentence(GList * args, extcap_token_sentence *s) {
    extcap_token_param *v = NULL;
    extcap_arg *target_arg = NULL;
    extcap_value *value = NULL;
    GList * entry = NULL;
    int tint;
    extcap_sentence_type sent = EXTCAP_SENTENCE_UNKNOWN;

    if (s == NULL)
        return target_arg;

    if (g_ascii_strcasecmp(s->sentence, "arg") == 0) {
        sent = EXTCAP_SENTENCE_ARG;
        /* printf("ARG sentence\n"); */
    } else if (g_ascii_strcasecmp(s->sentence, "value") == 0) {
        sent = EXTCAP_SENTENCE_VALUE;
        /* printf("VALUE sentence\n"); */
    }

    if (sent == EXTCAP_SENTENCE_ARG) {
        target_arg = g_new0(extcap_arg, 1);
        target_arg->arg_type = EXTCAP_ARG_UNKNOWN;
        target_arg->save = TRUE;

        if ((v = extcap_find_param_by_type(s->param_list, EXTCAP_PARAM_ARGNUM))
                == NULL) {
            extcap_free_arg(target_arg);
            return NULL ;
        }

        if (sscanf(v->value, "%d", &(target_arg->arg_num)) != 1) {
            extcap_free_arg(target_arg);
            return NULL ;
        }

        if ((v = extcap_find_param_by_type(s->param_list, EXTCAP_PARAM_CALL))
                == NULL) {
            extcap_free_arg(target_arg);
            return NULL ;
        }
        target_arg->call = g_strdup(v->value);

        /* No value only parameters allowed */
        if (strlen(target_arg->call) == 0) {
            extcap_free_arg(target_arg);
            return NULL ;
        }

        if ((v = extcap_find_param_by_type(s->param_list, EXTCAP_PARAM_DISPLAY))
                == NULL) {
            extcap_free_arg(target_arg);
            return NULL ;
        }
        target_arg->display = g_strdup(v->value);

        if ((v = extcap_find_param_by_type(s->param_list, EXTCAP_PARAM_TOOLTIP))
                != NULL) {
            target_arg->tooltip = g_strdup(v->value);
        }

        if ((v = extcap_find_param_by_type(s->param_list, EXTCAP_PARAM_FILE_MUSTEXIST))
                != NULL) {
            target_arg->fileexists = g_regex_match_simple(EXTCAP_BOOLEAN_REGEX, v->value, G_REGEX_CASELESS, (GRegexMatchFlags)0 );
        }

        if ((v = extcap_find_param_by_type(s->param_list, EXTCAP_PARAM_FILE_EXTENSION))
                != NULL) {
            target_arg->fileextension = g_strdup(v->value);
        }

        if ((v = extcap_find_param_by_type(s->param_list, EXTCAP_PARAM_VALIDATION))
                != NULL) {
            target_arg->regexp = g_strdup(v->value);
        }

        if ((v = extcap_find_param_by_type(s->param_list, EXTCAP_PARAM_REQUIRED))
                != NULL) {
            target_arg->is_required = g_regex_match_simple(EXTCAP_BOOLEAN_REGEX, v->value, G_REGEX_CASELESS, (GRegexMatchFlags)0 );
        }

        if ((v = extcap_find_param_by_type(s->param_list, EXTCAP_PARAM_TYPE))
                == NULL) {
            /* printf("no type in ARG sentence\n"); */
            extcap_free_arg(target_arg);
            return NULL ;
        }

        if (g_ascii_strcasecmp(v->value, "integer") == 0) {
            target_arg->arg_type = EXTCAP_ARG_INTEGER;
        } else if (g_ascii_strcasecmp(v->value, "unsigned") == 0) {
            target_arg->arg_type = EXTCAP_ARG_UNSIGNED;
        } else if (g_ascii_strcasecmp(v->value, "long") == 0) {
            target_arg->arg_type = EXTCAP_ARG_LONG;
        } else if (g_ascii_strcasecmp(v->value, "double") == 0) {
            target_arg->arg_type = EXTCAP_ARG_DOUBLE;
        } else if (g_ascii_strcasecmp(v->value, "boolean") == 0) {
            target_arg->arg_type = EXTCAP_ARG_BOOLEAN;
        } else if (g_ascii_strcasecmp(v->value, "boolflag") == 0) {
            target_arg->arg_type = EXTCAP_ARG_BOOLFLAG;
        } else if (g_ascii_strcasecmp(v->value, "selector") == 0) {
            target_arg->arg_type = EXTCAP_ARG_SELECTOR;
        } else if (g_ascii_strcasecmp(v->value, "radio") == 0) {
            target_arg->arg_type = EXTCAP_ARG_RADIO;
        } else if (g_ascii_strcasecmp(v->value, "string") == 0) {
            target_arg->arg_type = EXTCAP_ARG_STRING;
        } else if (g_ascii_strcasecmp(v->value, "password") == 0) {
            target_arg->arg_type = EXTCAP_ARG_PASSWORD;
            /* default setting is to not save passwords */
            target_arg->save = FALSE;
        } else if (g_ascii_strcasecmp(v->value, "fileselect") == 0) {
            target_arg->arg_type = EXTCAP_ARG_FILESELECT;
        } else if (g_ascii_strcasecmp(v->value, "multicheck") == 0) {
            target_arg->arg_type = EXTCAP_ARG_MULTICHECK;
        } else {
            printf("invalid type %s in ARG sentence\n", v->value);
            extcap_free_arg(target_arg);
            return NULL ;
        }

        if ((v = extcap_find_param_by_type(s->param_list, EXTCAP_PARAM_SAVE))
                != NULL) {
            target_arg->save = g_regex_match_simple(EXTCAP_BOOLEAN_REGEX, v->value, G_REGEX_CASELESS, (GRegexMatchFlags)0 );
        }

        if ((v = extcap_find_param_by_type(s->param_list, EXTCAP_PARAM_RANGE))
                != NULL) {
            gchar *cp = g_strstr_len(v->value, -1, ",");

            if (cp == NULL) {
                printf("invalid range, expected value,value got %s\n",
                        v->value);
                extcap_free_arg(target_arg);
                return NULL ;
            }

            if ((target_arg->range_start = extcap_parse_complex(
                    target_arg->arg_type, v->value)) == NULL) {
                printf("invalid range, expected value,value got %s\n",
                        v->value);
                extcap_free_arg(target_arg);
                return NULL ;
            }

            if ((target_arg->range_end = extcap_parse_complex(
                    target_arg->arg_type, cp + 1)) == NULL) {
                printf("invalid range, expected value,value got %s\n",
                        v->value);
                extcap_free_arg(target_arg);
                return NULL ;
            }
        }

        if ((v = extcap_find_param_by_type(s->param_list, EXTCAP_PARAM_DEFAULT))
                != NULL) {
            if ( target_arg->arg_type != EXTCAP_ARG_MULTICHECK && target_arg->arg_type != EXTCAP_ARG_SELECTOR )
            {
                if ((target_arg->default_complex = extcap_parse_complex(
                        target_arg->arg_type, v->value)) == NULL) {
                    printf("invalid default, couldn't parse %s\n", v->value);
                }
            }
        }

    } else if (sent == EXTCAP_SENTENCE_VALUE) {
        if ((v = extcap_find_param_by_type(s->param_list, EXTCAP_PARAM_ARG))
                == NULL) {
            printf("no arg in VALUE sentence\n");
            return NULL ;
        }

        if (sscanf(v->value, "%d", &tint) != 1) {
            printf("invalid arg in VALUE sentence\n");
            return NULL ;
        }

        ;
        if ((entry = g_list_find_custom(args, &tint, glist_find_numbered_arg))
                == NULL) {
            printf("couldn't find arg %d in list for VALUE sentence\n", tint);
            return NULL ;
        }

        value = g_new0(extcap_value, 1);
        value->arg_num = tint;

        if ((v = extcap_find_param_by_type(s->param_list, EXTCAP_PARAM_VALUE))
                == NULL) {
            /* printf("no value in VALUE sentence\n"); */
            extcap_free_value(value);
            return NULL ;
        }
        value->call = g_strdup(v->value);

        if ((v = extcap_find_param_by_type(s->param_list, EXTCAP_PARAM_DISPLAY))
                == NULL) {
            /* printf("no display in VALUE sentence\n"); */
            extcap_free_value(value);
            return NULL ;
        }
        value->display = g_strdup(v->value);

        if ((v = extcap_find_param_by_type(s->param_list, EXTCAP_PARAM_PARENT))
                != NULL) {
            value->parent = g_strdup(v->value);
        }

        if ((v = extcap_find_param_by_type(s->param_list, EXTCAP_PARAM_DEFAULT))
                != NULL) {
            /* printf("found default value\n"); */
            value->is_default = g_regex_match_simple(EXTCAP_BOOLEAN_REGEX, v->value, G_REGEX_CASELESS, (GRegexMatchFlags)0 );
        }

        if ((v = extcap_find_param_by_type(s->param_list, EXTCAP_PARAM_ENABLED))
                != NULL) {
            value->enabled = g_regex_match_simple(EXTCAP_BOOLEAN_REGEX, v->value, G_REGEX_CASELESS, (GRegexMatchFlags)0 );
        }

        ((extcap_arg*) entry->data)->values = g_list_append(
                ((extcap_arg*) entry->data)->values, value);

        return NULL ;
    }

    return target_arg;
}

GList * extcap_parse_args(extcap_token_sentence *first_s) {
    GList * args = NULL;

    while (first_s) {
        extcap_arg *ra = NULL;

        if ((ra = extcap_parse_arg_sentence(args, first_s)) != NULL)
            args = g_list_append(args, (gpointer) ra);

        first_s = first_s->next_sentence;
    }

    return args;
}

int extcap_parse_interface_sentence(extcap_token_sentence *s,
        extcap_interface **ri) {
    extcap_token_param *v = NULL;
    extcap_sentence_type sent = EXTCAP_SENTENCE_UNKNOWN;

    *ri = NULL;

    if (s == NULL)
        return -1;

    if (g_ascii_strcasecmp(s->sentence, "interface") == 0) {
        sent = EXTCAP_SENTENCE_INTERFACE;
    } else if (g_ascii_strcasecmp(s->sentence, "extcap") == 0) {
        sent = EXTCAP_SENTENCE_EXTCAP;
    }

    if (sent == EXTCAP_SENTENCE_UNKNOWN)
        return -1;

    *ri = extcap_new_interface();

    (*ri)->if_type = sent;

    if ((v = extcap_find_param_by_type(s->param_list, EXTCAP_PARAM_VALUE))
            == NULL && sent == EXTCAP_SENTENCE_INTERFACE) {
        printf("No value in INTERFACE sentence\n");
        extcap_free_interface(*ri);
        return -1;
    }
    if ( v != NULL )
       (*ri)->call = g_strdup(v->value);

    if ((v = extcap_find_param_by_type(s->param_list, EXTCAP_PARAM_DISPLAY))
            == NULL && sent == EXTCAP_SENTENCE_INTERFACE) {
        printf("No display in INTERFACE sentence\n");
        extcap_free_interface(*ri);
        return -1;
    }
    if ( v != NULL )
        (*ri)->display = g_strdup(v->value);

    if ((v = extcap_find_param_by_type(s->param_list, EXTCAP_PARAM_VERSION))
            != NULL) {
        (*ri)->version = g_strdup(v->value);
    }

    return 1;
}

int extcap_parse_interfaces(extcap_token_sentence *first_s,
        extcap_interface **first_int) {
    extcap_interface *first_i = NULL, *last_i = NULL;

    while (first_s) {
        extcap_interface *ri;

        if (extcap_parse_interface_sentence(first_s, &ri) >= 0 && ri != NULL) {
            if (first_i == NULL) {
                first_i = last_i = ri;
            } else {
                last_i->next_interface = ri;
                last_i = ri;
            }
        }

        first_s = first_s->next_sentence;
    }

    *first_int = first_i;

    return 1;
}

int extcap_parse_dlt_sentence(extcap_token_sentence *s, extcap_dlt **rd) {
    extcap_token_param *v = NULL;
    extcap_sentence_type sent = EXTCAP_SENTENCE_UNKNOWN;

    *rd = NULL;

    if (s == NULL)
        return -1;

    if (g_ascii_strcasecmp(s->sentence, "dlt") == 0) {
        sent = EXTCAP_SENTENCE_DLT;
    }

    if (sent == EXTCAP_SENTENCE_UNKNOWN)
        return -1;

    *rd = extcap_new_dlt();

    if ((v = extcap_find_param_by_type(s->param_list, EXTCAP_PARAM_ARGNUM))
            == NULL) {
        printf("No number in DLT sentence\n");
        extcap_free_dlt(*rd);
        return -1;
    }
    if (sscanf(v->value, "%d", &((*rd)->number)) != 1) {
        printf("Invalid number in DLT sentence\n");
        extcap_free_dlt(*rd);
        return -1;
    }

    if ((v = extcap_find_param_by_type(s->param_list, EXTCAP_PARAM_NAME))
            == NULL) {
        printf("No name in DLT sentence\n");
        extcap_free_dlt(*rd);
        return -1;
    }
    (*rd)->name = g_strdup(v->value);

    if ((v = extcap_find_param_by_type(s->param_list, EXTCAP_PARAM_DISPLAY))
            == NULL) {
        printf("No display in DLT sentence\n");
        extcap_free_dlt(*rd);
        return -1;
    }
    (*rd)->display = g_strdup(v->value);

    return 1;
}

int extcap_parse_dlts(extcap_token_sentence *first_s, extcap_dlt **first_dlt) {
    extcap_dlt *first_d = NULL, *last_d = NULL;

    while (first_s) {
        extcap_dlt *rd;

        if (extcap_parse_dlt_sentence(first_s, &rd) >= 0 && rd != NULL) {
            if (first_d == NULL) {
                first_d = last_d = rd;
            } else {
                last_d->next_dlt = rd;
                last_d = rd;
            }
        }

        first_s = first_s->next_sentence;
    }

    *first_dlt = first_d;

    return 1;
}

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
