/* popcount.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __POPCOUNT_H__
#define __POPCOUNT_H__

#include "ws_symbol_export.h"

WS_DLL_PUBLIC int popcount(unsigned int mask);

#endif /* __POPCOUNT_H__ */

