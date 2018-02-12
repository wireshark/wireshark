/*
 * Routines for H.223 packet dissection
 * 2004 Richard van der Hoff <richardv@mxtelecom.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_H223_H__
#define __PACKET_H223_H__

void proto_register_h223 (void);
void proto_reg_handoff_h223(void);

#endif  /* __PACKET_H223_H__ */
