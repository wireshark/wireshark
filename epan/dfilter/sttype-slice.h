/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef STTYPE_SLICE_H
#define STTYPE_SLICE_H

#include "syntax-tree.h"
#include "drange.h"


stnode_t *
sttype_slice_entity(stnode_t *node);

drange_t *
sttype_slice_drange(stnode_t *node);

drange_t *
sttype_slice_drange_steal(stnode_t *node);

/* Set a range */
void
sttype_slice_set(stnode_t *node, stnode_t *field, GSList* drange_list);

void
sttype_slice_set1(stnode_t *node, stnode_t *field, drange_node *rn);

void
sttype_slice_set_drange(stnode_t *node, stnode_t *field, drange_t *dr);

/* Clear the 'drange' variable to remove responsibility for
 * freeing it. */
void
sttype_slice_remove_drange(stnode_t *node);

#endif
