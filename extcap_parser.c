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

#include "extcap_parser.h"

void extcap_printf_complex(extcap_complex *comp) {
    gchar *ret = extcap_get_complex_as_string(comp);
    printf("%s", ret);
    g_free(ret);
}

gchar *extcap_get_complex_as_string(extcap_complex *comp) {
    /* Pick an arbitrary size that should be big enough */
    gchar *ret = g_new(gchar, 32);

    if (comp == NULL) {
        g_snprintf(ret, 32, "(null)");
        return ret;
    }

    switch (comp->complex_type) {
    case EXTCAP_ARG_INTEGER:
        g_snprintf(ret, 32, "%d", comp->complex_value.int_value);
        break;
    case EXTCAP_ARG_UNSIGNED:
        g_snprintf(ret, 32, "%u", comp->complex_value.uint_value);
        break;
    case EXTCAP_ARG_LONG:
        g_snprintf(ret, 32, "%ld", comp->complex_value.long_value);
        break;
    case EXTCAP_ARG_DOUBLE:
        g_snprintf(ret, 32, "%f", comp->complex_value.double_value);
        break;
    case EXTCAP_ARG_BOOLEAN:
        g_snprintf(ret, 32, "%s",
                comp->complex_value.bool_value ? "true" : "false");
        break;
    case EXTCAP_ARG_STRING:
    case EXTCAP_ARG_FILESELECT:
        g_free(ret);
        ret = g_strdup(comp->complex_value.string_value);
        break;
    default:
        /* Nulling out the return string */
        g_snprintf(ret, 32, " ");
        break;
    }

    return ret;
}

extcap_complex *extcap_parse_complex(extcap_arg_type complex_type,
        const gchar *data) {
    extcap_complex *rc = g_new(extcap_complex, 1);
    gboolean success = FALSE;
    long double exp_f;

    switch (complex_type) {
    case EXTCAP_ARG_INTEGER:
        if (sscanf(data, "%Lf", &exp_f) == 1) {
            rc->complex_value.int_value = (int) exp_f;
            success = TRUE;
            break;
        }
        break;
    case EXTCAP_ARG_UNSIGNED:
        if (sscanf(data, "%Lf", &exp_f) == 1) {
            rc->complex_value.uint_value = (unsigned int) exp_f;
            success = TRUE;
            break;
        }
        break;
    case EXTCAP_ARG_LONG:
        if (sscanf(data, "%Lf", &exp_f) == 1) {
            rc->complex_value.long_value = (long) exp_f;
            success = TRUE;
            break;
        }
        break;
    case EXTCAP_ARG_DOUBLE:
        if (sscanf(data, "%Lf", &exp_f) == 1) {
            rc->complex_value.double_value = (double) exp_f;
            success = TRUE;
            break;
        }
        break;
    case EXTCAP_ARG_BOOLEAN:
    case EXTCAP_ARG_BOOLFLAG:
        if (data[0] == 't' || data[0] == 'T' || data[0] == '1') {
            rc->complex_value.bool_value = 1;
        } else {
            rc->complex_value.bool_value = 0;
        }
        success = TRUE;
        break;
    case EXTCAP_ARG_STRING:
    case EXTCAP_ARG_FILESELECT:
        rc->complex_value.string_value = g_strdup(data);
        success = TRUE;
        break;
    default:
        break;
    }

    if (!success) {
        g_free(rc);
        return NULL ;
    }

    rc->complex_type = complex_type;
    rc->value_filled = TRUE;

    return rc;
}

gboolean extcap_compare_is_default(extcap_arg *element, extcap_complex *test) {
    gboolean result = FALSE;

    if (element->default_complex == NULL)
        return result;

    switch (element->arg_type) {
    case EXTCAP_ARG_INTEGER:
        if (extcap_complex_get_int(test)
                == extcap_complex_get_int(element->default_complex))
            result = TRUE;
        break;
    case EXTCAP_ARG_UNSIGNED:
        if (extcap_complex_get_uint(test)
                == extcap_complex_get_uint(element->default_complex))
            result = TRUE;
        break;
    case EXTCAP_ARG_LONG:
        if (extcap_complex_get_long(test)
                == extcap_complex_get_long(element->default_complex))
            result = TRUE;
        break;
    case EXTCAP_ARG_DOUBLE:
        if (extcap_complex_get_double(test)
                == extcap_complex_get_double(element->default_complex))
            result = TRUE;
        break;
    case EXTCAP_ARG_BOOLEAN:
    case EXTCAP_ARG_BOOLFLAG:
        if (extcap_complex_get_bool(test)
                == extcap_complex_get_bool(element->default_complex))
            result = TRUE;
        break;
    case EXTCAP_ARG_STRING:
        if (strcmp(extcap_complex_get_string(test),
                extcap_complex_get_string(element->default_complex)) == 0)
            result = TRUE;
        break;

    default:
        break;
    }

    return result;
}

void extcap_free_complex(extcap_complex *comp) {
    if (comp->complex_type == EXTCAP_ARG_STRING
            || comp->complex_type == EXTCAP_ARG_FILESELECT)
        g_free(comp->complex_value.string_value);

    g_free(comp);
}

int extcap_complex_get_int(extcap_complex *comp) {
    if ( comp == NULL )
        return (int)0;
    return comp->complex_value.int_value;
}

unsigned int extcap_complex_get_uint(extcap_complex *comp) {
    if ( comp == NULL )
        return (unsigned int)0;
    return comp->complex_value.uint_value;
}

long extcap_complex_get_long(extcap_complex *comp) {
    if ( comp == NULL )
        return (long)0;
    return comp->complex_value.long_value;
}

double extcap_complex_get_double(extcap_complex *comp) {
    if ( comp == NULL )
        return (double)0;
    return comp->complex_value.double_value;
}

gboolean extcap_complex_get_bool(extcap_complex *comp) {
    if ( comp == NULL )
        return FALSE;
    return comp->complex_value.bool_value;
}

gchar *extcap_complex_get_string(extcap_complex *comp) {
    return comp->complex_value.string_value;
}

void extcap_free_tokenized_param(extcap_token_param *v) {
    if (v == NULL)
        return;

    if (v->arg != NULL)
        g_free(v->arg);

    if (v->value != NULL)
        g_free(v->value);

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
    gchar *b, *e, *eq;

    extcap_token_param *tv = NULL;

    extcap_token_sentence *rs = g_new(extcap_token_sentence, 1);

    rs->sentence = NULL;
    rs->next_sentence = NULL;
    rs->param_list = NULL;

    if ((b = g_strstr_len(s, -1, " ")) == NULL) {
        extcap_free_tokenized_sentence(rs);
        return NULL ;
    }

    rs->sentence = g_strndup(s, b - s);

    if ((b = g_strstr_len(s, -1, "{")) == NULL) {
        /* printf("debug - tokenizer - sentence with no values\n"); */
        extcap_free_tokenized_sentence(rs);
        return NULL ;
    }

    while (b != NULL ) {
        if ((e = g_strstr_len(b, -1, "}")) == NULL) {
            /* printf("debug - tokenizer - invalid, missing }\n"); */
            extcap_free_tokenized_sentence(rs);
            return NULL ;
        }

        if ((eq = g_strstr_len(b, -1, "=")) == NULL) {
            /* printf("debug - tokenizer - invalid, missing =\n"); */
            extcap_free_tokenized_sentence(rs);
            return NULL ;
        }

        b++;
        e--;

        if (b >= eq || e <= eq) {
            /* printf("debug - tokenizer - invalid, missing arg or value in {}\n"); */
            extcap_free_tokenized_sentence(rs);
            return NULL ;
        }

        tv = g_new(extcap_token_param, 1);
        tv->arg = g_strndup(b, eq - b);
        tv->value = g_strndup(eq + 1, e - eq);

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
        } else if (g_ascii_strcasecmp(tv->arg, "name") == 0) {
            tv->param_type = EXTCAP_PARAM_NAME;
        } else if (g_ascii_strcasecmp(tv->arg, "enabled") == 0) {
            tv->param_type = EXTCAP_PARAM_ENABLED;
        } else if (g_ascii_strcasecmp(tv->arg, "parent") == 0) {
            tv->param_type = EXTCAP_PARAM_PARENT;
        } else {
            tv->param_type = EXTCAP_PARAM_UNKNOWN;
        }

        tv->next_token = rs->param_list;
        rs->param_list = tv;

        /* printf("debug - tokenizer - got '%s' = '%s'\n", tv->arg, tv->value); */

        b = e + 1;
        if ((size_t) (b - s) > strlen(s))
            break;

        b = g_strstr_len(b, -1, "{");
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

    if (v->call != NULL)
        g_free(v->call);

    if (v->display != NULL)
        g_free(v->display);

    g_free(v);
}

extcap_interface *extcap_new_interface(void) {
    extcap_interface *r = g_new(extcap_interface, 1);

    r->call = r->display = NULL;
    r->next_interface = NULL;

    return r;
}

void extcap_free_interface(extcap_interface *i) {
    if (i == NULL)
        return;

    if (i->call != NULL)
        g_free(i->call);

    if (i->display != NULL)
        g_free(i->display);
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

    if (d->name != NULL)
        g_free(d->name);

    if (d->display != NULL)
        g_free(d->display);
}

extcap_arg *extcap_new_arg(void) {
    extcap_arg *r = g_new(extcap_arg, 1);

    r->call = NULL;
    r->display = NULL;
    r->tooltip = NULL;
    r->arg_type = EXTCAP_ARG_UNKNOWN;
    r->range_start = NULL;
    r->range_end = NULL;
    r->default_complex = NULL;
    r->fileexists = FALSE;

    r->values = NULL;
    /*r->next_arg = NULL; */

    return r;
}

static void extcap_free_valuelist(gpointer data, gpointer user_data _U_) {
    extcap_free_value((extcap_value *) data);
}

void extcap_free_arg(extcap_arg *a) {

    if (a == NULL)
        return;

    if (a->call != NULL)
        g_free(a->call);

    if (a->display != NULL)
        g_free(a->display);

    if (a->tooltip != NULL)
        g_free(a->tooltip);

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
        target_arg = extcap_new_arg();

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
            target_arg->fileexists = (v->value[0] == 't' || v->value[0] == 'T');
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
        } else if (g_ascii_strcasecmp(v->value, "fileselect") == 0) {
            target_arg->arg_type = EXTCAP_ARG_FILESELECT;
        } else if (g_ascii_strcasecmp(v->value, "multicheck") == 0) {
            target_arg->arg_type = EXTCAP_ARG_MULTICHECK;
        } else {
            printf("invalid type %s in ARG sentence\n", v->value);
            extcap_free_arg(target_arg);
            return NULL ;
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
            if ((target_arg->default_complex = extcap_parse_complex(
                    target_arg->arg_type, v->value)) == NULL) {
                printf("invalid default, couldn't parse %s\n", v->value);
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

        value = g_new(extcap_value, 1);
        value->display = NULL;
        value->call = NULL;
        value->enabled = FALSE;
        value->is_default = FALSE;
        value->arg_num = tint;
        value->parent = NULL;

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
            value->is_default = (v->value[0] == 't' || v->value[0] == 'T');
        }

        if ((v = extcap_find_param_by_type(s->param_list, EXTCAP_PARAM_ENABLED))
                != NULL) {
            value->enabled = (v->value[0] == 't' || v->value[0] == 'T');
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
        /* printf("INTERFACE sentence\n"); */
    }

    if (sent == EXTCAP_SENTENCE_UNKNOWN)
        return -1;

    *ri = extcap_new_interface();

    if ((v = extcap_find_param_by_type(s->param_list, EXTCAP_PARAM_VALUE))
            == NULL) {
        printf("No value in INTERFACE sentence\n");
        extcap_free_interface(*ri);
        return -1;
    }
    (*ri)->call = g_strdup(v->value);

    if ((v = extcap_find_param_by_type(s->param_list, EXTCAP_PARAM_DISPLAY))
            == NULL) {
        printf("No display in INTERFACE sentence\n");
        extcap_free_interface(*ri);
        return -1;
    }
    (*ri)->display = g_strdup(v->value);

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
