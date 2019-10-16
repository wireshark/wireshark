/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef STTYPE_SET_H
#define STTYPE_SET_H

#include <glib.h>

#include "ws_attributes.h"

void
sttype_set_replace_element(stnode_t *node, stnode_t *oldnode, stnode_t *newnode);

gboolean
sttype_set_convert_to_range(stnode_t **node_left, stnode_t **node_right);

void
set_nodelist_free(GSList *params);

#endif
