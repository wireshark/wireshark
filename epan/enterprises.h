/* populate_global_enterprises.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <wireshark.h>

const char* global_enterprises_lookup(uint32_t value);

WS_DLL_PUBLIC
void global_enterprises_dump(FILE *fp);
