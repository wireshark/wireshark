/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SEMCHECK_H
#define SEMCHECK_H

#include "dfilter-int.h"

bool
dfw_semcheck(dfwork_t *dfw);

ftenum_t
check_arithmetic(dfwork_t *dfw, stnode_t *st_node, ftenum_t logical_ftype);

ftenum_t
check_function(dfwork_t *dfw, stnode_t *st_node, ftenum_t logical_ftype);

ftenum_t
check_slice(dfwork_t *dfw, stnode_t *st, ftenum_t logical_ftype);

void
resolve_unparsed(dfwork_t *dfw, stnode_t *st, bool strict);

ftenum_t
get_logical_ftype(dfwork_t *dfw, stnode_t *st_node);

bool
compatible_ftypes(ftenum_t a, ftenum_t b);

#endif
