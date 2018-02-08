/* gencode.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef GENCODE_H
#define GENCODE_H

void
dfw_gencode(dfwork_t *dfw);

int*
dfw_interesting_fields(dfwork_t *dfw, int *caller_num_fields);

#endif
