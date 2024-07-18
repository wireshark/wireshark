/* packet-osi-options.h
 * Defines for OSI options part decode
 *
 * Ralf Schneider <Ralf.Schneider@t-online.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _PACKET_OSI_OPTIONS_H__
#define _PACKET_OSI_OPTIONS_H__

/*
 * published API functions
 */
extern void dissect_osi_options( unsigned char, tvbuff_t *, int, proto_tree *, packet_info *);
extern void proto_register_osi_options(void);

#endif /* _PACKET_OSI_OPTIONS_H__ */
