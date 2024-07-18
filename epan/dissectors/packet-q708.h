/* packet-q708.h
 * Routine and tables for analyzing an ISPC according to Q.708
 * Copyright 2010, Gerasimos Dimitriadis <dimeg [AT] intracom.gr>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_Q708_H__
#define __PACKET_Q708_H__

#include "ws_symbol_export.h"

WS_DLL_PUBLIC
void analyze_q708_ispc(tvbuff_t *tvb, proto_tree *tree, int offset, int length, uint16_t ispc);

#endif /* __PACKET_Q708_H__ */
