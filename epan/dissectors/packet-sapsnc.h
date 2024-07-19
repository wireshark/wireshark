/* packet-sapsnc.h
 * Routines for SAP SNC (Secure Network Connectoin) dissection
 * Copyright 2022, Martin Gallo <martin.gallo [AT] gmail.com>
 * Code contributed by SecureAuth Corp.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_SAPPSNC_H__
#define __PACKET_SAPPSNC_H__

#include <epan/packet.h>

extern /**
 * Dissect an SNC Frame. If data it's found for wrapped/signed frames, it
 * returns a new TVB buffer with the content. This function can be called
 * from any dissector that wants SNC frames to be decoded.
 */
tvbuff_t*
dissect_sapsnc_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset);

#endif /* __PACKET_SAPPSNC_H__ */
