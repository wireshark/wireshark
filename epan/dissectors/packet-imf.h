/* packet-imf.h
 * Routines for Internet Message Format (IMF) packet disassembly
 *
 * Copyright (c) 2007 by Graeme Lunt
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_IMF_H__
#define __PACKET_IMF_H__

#include <epan/packet.h>

/* Find the end of the next IMF field in the tvb.
 * This is not necessarily the first \r\n as there may be continuation lines.
 *
 * If we have found the last field (terminated by \r\n\r\n) we indicate this in last_field .
 */
int imf_find_field_end(tvbuff_t *tvb, int offset, int max_length, bool *last_field);

#endif /* __PACKET_IMF_H__ */
