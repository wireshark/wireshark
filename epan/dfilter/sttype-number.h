/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef STTYPE_NUMBER_H
#define STTYPE_NUMBER_H

#include "dfilter-int.h"

stnumber_t
sttype_number_get_type(stnode_t*st);

void
sttype_number_set_integer(stnode_t *st, int64_t value);

int64_t
sttype_number_get_integer(stnode_t *st);

void
sttype_number_set_unsigned(stnode_t *st, uint64_t value);

uint64_t
sttype_number_get_unsigned(stnode_t *st);

void
sttype_number_set_float(stnode_t *st, double value);

double
sttype_number_get_float(stnode_t *st);

#endif
