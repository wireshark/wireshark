/* drange.c
 * Routines for providing general range support to the dfilter library
 *
 * Copyright (c) 2000 by Ed Warnicke <hagbard@physics.rutgers.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs
 * Copyright 1999 Gerald Combs
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "drange.h"

#include <errno.h>
#include <stdlib.h>


/* drange_node constructor */
drange_node*
drange_node_new(void)
{
    drange_node* new_range_node;

    new_range_node = g_new(drange_node,1);
    new_range_node->start_offset = 0;
    new_range_node->length = 0;
    new_range_node->end_offset = 0;
    new_range_node->ending = DRANGE_NODE_END_T_UNINITIALIZED;
    return new_range_node;
}

static gboolean
drange_str_to_gint32(const char *s, gint32 *pint, char **endptr, char **err_ptr)
{
    long integer;

    errno = 0;
    integer = strtol(s, endptr, 0);
    if (errno == EINVAL || *endptr == s) {
        /* This isn't a valid number. */
        *err_ptr = ws_strdup_printf("\"%s\" is not a valid number.", s);
        return FALSE;
    }
    if (errno == ERANGE || integer > G_MAXINT32 || integer < G_MININT32) {
        *err_ptr = ws_strdup_printf("\"%s\" causes an integer overflow.", s);
        return FALSE;
    }
    *pint = (gint32)integer;
    return TRUE;
}

/* drange_node constructor from string */
drange_node*
drange_node_from_str(const char *range_str, char **err_ptr)
{
    const char *str;
    char *endptr;
    gint32 lower, upper;
    drange_node_end_t end = DRANGE_NODE_END_T_UNINITIALIZED;
    drange_node *dn;
    gboolean ok;

    /*
     * The following syntax governs slices:
     * [i:j]    i = start_offset, j = length
     * [i-j]    i = start_offset, j = end_offset, inclusive.
     * [i]      i = start_offset, length = 1
     * [:j]     start_offset = 0, length = j
     * [i:]     start_offset = i, end_offset = end_of_field
     */

    str = range_str;
    if (*str == ':') {
        lower = 0;
        /* Do not advance 'str' here. */
    }
    else {
        if (!drange_str_to_gint32(str, &lower, &endptr, err_ptr))
            return NULL;
        str = endptr;
    }

    while (*str != '\0' && g_ascii_isspace(*str))
        str++;

    if (*str == '-') {
        str++;
        end = DRANGE_NODE_END_T_OFFSET;
        ok = drange_str_to_gint32(str, &upper, &endptr, err_ptr);
        str = endptr;
    }
    else if (*str == ':') {
        str++;
        if (*str == '\0') {
            end = DRANGE_NODE_END_T_TO_THE_END;
            ok = TRUE;
        }
        else {
            end = DRANGE_NODE_END_T_LENGTH;
            ok = drange_str_to_gint32(str, &upper, &endptr, err_ptr);
            str = endptr;
        }
    }
    else if (*str == '\0') {
        end = DRANGE_NODE_END_T_LENGTH;
        upper = 1;
        ok = TRUE;
    }
    else {
        ok = FALSE;
    }

    while (*str != '\0' && g_ascii_isspace(*str))
        str++;

    if (!ok || *str != '\0') {
        *err_ptr = ws_strdup_printf("\"%s\" is not a valid range.", range_str);
        return NULL;
    }

    dn = drange_node_new();
    drange_node_set_start_offset(dn, lower);
    switch (end) {
        case DRANGE_NODE_END_T_LENGTH:
            if (upper <= 0) {
                *err_ptr = ws_strdup_printf("Range %s isn't valid "
                                    "because length %d isn't positive",
                                    range_str, upper);
                drange_node_free(dn);
                return NULL;
            }
            drange_node_set_length(dn, upper);
            break;
        case DRANGE_NODE_END_T_OFFSET:
            if ((lower < 0 && upper > 0) || (lower > 0 && upper < 0)) {
                *err_ptr = ws_strdup_printf("Range %s isn't valid "
                                    "because %d and %d have different signs",
                                    range_str, lower, upper);
                drange_node_free(dn);
                return NULL;
            }
            if (upper <= lower) {
                *err_ptr = ws_strdup_printf("Range %s isn't valid "
                                    "because %d is greater or equal than %d",
                                    range_str, lower, upper);
                drange_node_free(dn);
                return NULL;
            }
            drange_node_set_end_offset(dn, upper);
            break;
        case DRANGE_NODE_END_T_TO_THE_END:
            drange_node_set_to_the_end(dn);
            break;
        default:
            ws_assert_not_reached();
            break;
    }

    return dn;
}

static drange_node*
drange_node_dup(drange_node *org)
{
    drange_node *new_range_node;

    if (!org)
        return NULL;

    new_range_node = g_new(drange_node,1);
    new_range_node->start_offset = org->start_offset;
    new_range_node->length = org->length;
    new_range_node->end_offset = org->end_offset;
    new_range_node->ending = org->ending;
    return new_range_node;
}

/* drange_node destructor */
void
drange_node_free(drange_node* drnode)
{
    g_free(drnode);
}

/* drange_node accessors */
gint
drange_node_get_start_offset(drange_node* drnode)
{
    ws_assert(drnode->ending != DRANGE_NODE_END_T_UNINITIALIZED);
    return drnode->start_offset;
}

gint
drange_node_get_length(drange_node* drnode)
{
    ws_assert(drnode->ending == DRANGE_NODE_END_T_LENGTH);
    return drnode->length;
}

gint
drange_node_get_end_offset(drange_node* drnode)
{
    ws_assert(drnode->ending == DRANGE_NODE_END_T_OFFSET);
    return drnode->end_offset;
}

drange_node_end_t
drange_node_get_ending(drange_node* drnode)
{
    ws_assert(drnode->ending != DRANGE_NODE_END_T_UNINITIALIZED);
    return drnode->ending;
}

/* drange_node mutators */
void
drange_node_set_start_offset(drange_node* drnode, gint offset)
{
    drnode->start_offset = offset;
}

void
drange_node_set_length(drange_node* drnode, gint length)
{
    drnode->length = length;
    drnode->ending = DRANGE_NODE_END_T_LENGTH;
}

void
drange_node_set_end_offset(drange_node* drnode, gint offset)
{
    drnode->end_offset = offset;
    drnode->ending = DRANGE_NODE_END_T_OFFSET;
}


void
drange_node_set_to_the_end(drange_node* drnode)
{
    drnode->ending = DRANGE_NODE_END_T_TO_THE_END;
}

/* drange constructor */
drange_t *
drange_new(drange_node* drnode)
{
    drange_t * new_drange;
    new_drange = g_new(drange_t,1);
    new_drange->range_list = NULL;
    new_drange->has_total_length = TRUE;
    new_drange->total_length = 0;
    new_drange->min_start_offset = G_MAXINT;
    new_drange->max_start_offset = G_MININT;

    if (drnode)
            drange_append_drange_node(new_drange, drnode);

    return new_drange;
}

static void
drange_append_wrapper(gpointer data, gpointer user_data)
{
    drange_node *drnode = (drange_node *)data;
    drange_t    *dr             = (drange_t *)user_data;

    drange_append_drange_node(dr, drnode);
}

drange_t *
drange_new_from_list(GSList *list)
{
    drange_t    *new_drange;

    new_drange = drange_new(NULL);
    g_slist_foreach(list, drange_append_wrapper, new_drange);
    return new_drange;
}

drange_t *
drange_dup(drange_t *org)
{
    drange_t *new_drange;
    GSList *p;

    if (!org)
        return NULL;

    new_drange = drange_new(NULL);
    for (p = org->range_list; p; p = p->next) {
        drange_node *drnode = (drange_node *)p->data;
        drange_append_drange_node(new_drange, drange_node_dup(drnode));
    }
    return new_drange;
}


/* drange destructor */
void
drange_free(drange_t * dr)
{
    drange_node_free_list(dr->range_list);
    g_free(dr);
}

/* Call drange_node destructor on all list items */
void
drange_node_free_list(GSList* list)
{
    g_slist_free_full(list, g_free);
}

/* drange accessors */
gboolean drange_has_total_length(drange_t * dr) { return dr->has_total_length; }
gint drange_get_total_length(drange_t * dr)     { return dr->total_length; }
gint drange_get_min_start_offset(drange_t * dr) { return dr->min_start_offset; }
gint drange_get_max_start_offset(drange_t * dr) { return dr->max_start_offset; }

static void
update_drange_with_node(drange_t *dr, drange_node *drnode)
{
    if(drnode->ending == DRANGE_NODE_END_T_TO_THE_END){
        dr->has_total_length = FALSE;
    }
    else if(dr->has_total_length){
        dr->total_length += drnode->length;
    }
    if(drnode->start_offset < dr->min_start_offset){
        dr->min_start_offset = drnode->start_offset;
    }
    if(drnode->start_offset > dr->max_start_offset){
        dr->max_start_offset = drnode->start_offset;
    }
}

/* drange mutators */
void
drange_prepend_drange_node(drange_t * dr, drange_node* drnode)
{
    if(drnode != NULL){
        dr->range_list = g_slist_prepend(dr->range_list,drnode);
        update_drange_with_node(dr, drnode);
    }
}

void
drange_append_drange_node(drange_t * dr, drange_node* drnode)
{
    if(drnode != NULL){
        dr->range_list = g_slist_append(dr->range_list,drnode);
        update_drange_with_node(dr, drnode);
    }
}

void
drange_foreach_drange_node(drange_t * dr, GFunc func, gpointer funcdata)
{
    g_slist_foreach(dr->range_list,func,funcdata);
}

char *
drange_node_tostr(const drange_node *rn)
{
    if (rn->ending == DRANGE_NODE_END_T_TO_THE_END)
        return ws_strdup_printf("%d:", rn->start_offset);
    else if(rn->ending == DRANGE_NODE_END_T_OFFSET)
        return ws_strdup_printf("%d-%d", rn->start_offset, rn->end_offset);
    else if (rn->ending == DRANGE_NODE_END_T_LENGTH)
        return ws_strdup_printf("%d:%d", rn->start_offset, rn->length);
    else
        return ws_strdup_printf("%d/%d/%d/U", rn->start_offset, rn->length, rn->end_offset);
}

char *
drange_tostr(const drange_t *dr)
{
    GString *repr = g_string_new("");
    GSList *range_list = dr->range_list;
    char *s;

    while (range_list) {
        s = drange_node_tostr(range_list->data);
        g_string_append(repr, s);
        g_free(s);
        range_list = g_slist_next(range_list);
        if (range_list != NULL) {
            g_string_append_c(repr, ',');
        }
    }

    return g_string_free(repr, FALSE);
}

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
