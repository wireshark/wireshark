/* packet-fc-sp.h
 * Routines for Fibre Channel Security Protocol
 * This decoder is for FC-SP version 1.1
 * Copyright 2003 Dinesh G Dutt (ddutt@cisco.com)
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifndef __PACKET_FCSP_H_
#define __PACKET_FCSP_H_

/* Message Codes */
#define FC_AUTH_MSG_AUTH_REJECT        0x0A 
#define FC_AUTH_MSG_AUTH_NEGOTIATE     0x0B 
#define FC_AUTH_MSG_AUTH_DONE          0x0C 
#define FC_AUTH_DHCHAP_CHALLENGE       0x10 
#define FC_AUTH_DHCHAP_REPLY           0x11 
#define FC_AUTH_DHCHAP_SUCCESS         0x12 
#define FC_AUTH_FCAP_REQUEST           0x13 
#define FC_AUTH_FCAP_ACKNOWLEDGE       0x14 
#define FC_AUTH_FCAP_CONFIRM           0x15 
#define FC_AUTH_FCPAP_INIT             0x16 
#define FC_AUTH_FCPAP_ACCEPT           0x17 
#define FC_AUTH_FCPAP_COMPLETE         0x18

#define FC_AUTH_NAME_TYPE_WWN          0x1

#define FC_AUTH_PROTO_TYPE_DHCHAP      0x1
#define FC_AUTH_PROTO_TYPE_FCAP        0x2

#define FC_AUTH_DHCHAP_HASH_MD5        0x5
#define FC_AUTH_DHCHAP_HASH_SHA1       0x6

#define FC_AUTH_DHCHAP_PARAM_HASHLIST  0x1
#define FC_AUTH_DHCHAP_PARAM_DHgIDLIST 0x2

void dissect_fcsp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

#endif
