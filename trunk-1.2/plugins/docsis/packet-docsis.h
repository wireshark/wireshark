/* packet-docsis.h
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __PACKET_DOCSIS_H__
#define __PACKET_DOCSIS_H__

void proto_reg_handoff_docsis_bpkmattr (void);
void proto_reg_handoff_docsis_bpkmreq (void);
void proto_reg_handoff_docsis_bpkmrsp (void);
void proto_reg_handoff_docsis (void);
void proto_reg_handoff_docsis_dsaack (void);
void proto_reg_handoff_docsis_dsareq (void);
void proto_reg_handoff_docsis_dsarsp (void);
void proto_reg_handoff_docsis_dscack (void);
void proto_reg_handoff_docsis_dscreq (void);
void proto_reg_handoff_docsis_dscrsp (void);
void proto_reg_handoff_docsis_dsdreq (void);
void proto_reg_handoff_docsis_dsdrsp (void);
void proto_reg_handoff_docsis_mgmt (void);
void proto_reg_handoff_docsis_map (void);
void proto_reg_handoff_docsis_regack (void);
void proto_reg_handoff_docsis_regreq (void);
void proto_reg_handoff_docsis_regrsp (void);
void proto_reg_handoff_docsis_rngreq (void);
void proto_reg_handoff_docsis_rngrsp (void);
void proto_reg_handoff_docsis_tlv (void);
void proto_reg_handoff_docsis_uccreq (void);
void proto_reg_handoff_docsis_uccrsp (void);
void proto_reg_handoff_docsis_ucd (void);
void proto_reg_handoff_docsis_type29ucd (void);
void proto_reg_handoff_docsis_dcd (void);
void proto_reg_handoff_docsis_dccreq (void);
void proto_reg_handoff_docsis_dccrsp (void);
void proto_reg_handoff_docsis_dccack (void);
void proto_reg_handoff_docsis_vsif (void);
void proto_reg_handoff_docsis_intrngreq (void);
  

void proto_register_docsis_bpkmattr (void);
void proto_register_docsis_bpkmreq (void);
void proto_register_docsis_bpkmrsp (void);
void proto_register_docsis (void);
void proto_register_docsis_dsaack (void);
void proto_register_docsis_dsareq (void);
void proto_register_docsis_dsarsp (void);
void proto_register_docsis_dscack (void);
void proto_register_docsis_dscreq (void);
void proto_register_docsis_dscrsp (void);
void proto_register_docsis_dsdreq (void);
void proto_register_docsis_dsdrsp (void);
void proto_register_docsis_mgmt (void);
void proto_register_docsis_map (void);
void proto_register_docsis_regack (void);
void proto_register_docsis_regreq (void);
void proto_register_docsis_regrsp (void);
void proto_register_docsis_rngreq (void);
void proto_register_docsis_rngrsp (void);
void proto_register_docsis_tlv (void);
void proto_register_docsis_uccreq (void);
void proto_register_docsis_uccrsp (void);
void proto_register_docsis_ucd (void);
void proto_register_docsis_type29ucd (void);
void proto_register_docsis_dcd (void);
void proto_register_docsis_dccreq (void);
void proto_register_docsis_dccrsp (void);
void proto_register_docsis_dccack (void);
void proto_register_docsis_vsif (void);
void proto_register_docsis_intrngreq (void);
#endif
