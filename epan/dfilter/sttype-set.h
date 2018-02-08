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

void
set_nodelist_free(GSList *params);

#endif
