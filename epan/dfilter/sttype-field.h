/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef STTYPE_FIELD_H
#define STTYPE_FIELD_H

#include "syntax-tree.h"
#include "drange.h"


header_field_info *
sttype_field_hfinfo(stnode_t *node);

ftenum_t
sttype_field_ftenum(stnode_t *node);

drange_t *
sttype_field_drange(stnode_t *node);

drange_t *
sttype_field_drange_steal(stnode_t *node);

/* Set a range */
void
sttype_field_set_range(stnode_t *node, GSList* drange_list);

void
sttype_field_set_range1(stnode_t *node, drange_node *rn);

void
sttype_field_set_drange(stnode_t *node, drange_t *dr);

char *
sttype_field_set_number(stnode_t *node, const char *number_str);

/* Clear the 'drange' variable to remove responsibility for
 * freeing it. */
void
sttype_field_remove_drange(stnode_t *node);

#endif
