/* packet-sscop.h
 * definitions for SSCOP (Q.2110, Q.SAAL) frame disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

typedef struct _sscop_info_t {
	guint8 type;
	guint32 payload_len;
} sscop_info_t;

typedef struct _sscop_payload_info {
	dissector_handle_t subdissector;
} sscop_payload_info;

typedef enum {
  DATA_DISSECTOR = 1,
  Q2931_DISSECTOR = 2,
  SSCF_NNI_DISSECTOR = 3,
  ALCAP_DISSECTOR = 4,
  NBAP_DISSECTOR = 5
} Dissector_Option;

extern gboolean sscop_allowed_subdissector(dissector_handle_t handle);
extern void dissect_sscop_and_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dissector_handle_t handle);
