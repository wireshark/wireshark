/* packet-mpeg-descriptor.c
 * Routines for MPEG2 (ISO/ISO 13818-1) dissectors
 * Copyright 2012, Guy Martin <gmsoft@tuxicoman.be>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef __PACKET_MPEG_DESCRIPTOR_H_
#define __PACKET_MPEG_DESCRIPTOR_H_

#include <epan/packet.h>
#include <wsutil/value_string.h>

extern value_string_ext mpeg_descr_service_type_vals_ext;
extern value_string_ext mpeg_descr_data_bcast_id_vals_ext;

unsigned proto_mpeg_descriptor_dissect(tvbuff_t *tvb, packet_info* pinfo, unsigned offset, proto_tree *tree);
unsigned proto_mpeg_descriptor_loop_dissect(tvbuff_t *tvb, packet_info* pinfo, unsigned offset, unsigned loop_len, proto_tree *tree);

#endif
