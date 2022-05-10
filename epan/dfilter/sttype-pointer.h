/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef STTYPE_POINTER_H
#define STTYPE_POINTER_H

#include "dfilter-int.h"
#include <epan/ftypes/ftypes.h>

ftenum_t
sttype_pointer_ftenum(stnode_t *node);

#endif
