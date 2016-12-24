/* decoders.h
* Header file for the TRANSUM response time analyzer post-dissector
* By Paul Offord <paul.offord@advance7.com>
* Copyright 2016 Advance Seven Limited
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
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#include "config.h"

int decode_syn(packet_info *pinfo, proto_tree *tree, PKT_INFO* pkt_info);
int decode_dcerpc(packet_info *pinfo, proto_tree *tree, PKT_INFO* pkt_info);
int decode_smb(packet_info *pinfo, proto_tree *tree, PKT_INFO* pkt_info, PKT_INFO* subpackets);
int decode_gtcp(packet_info *pinfo, proto_tree *tree, PKT_INFO* pkt_info);
int decode_dns(packet_info *pinfo, proto_tree *tree, PKT_INFO* pkt_info);
int decode_gudp(packet_info *pinfo, proto_tree *tree, PKT_INFO* pkt_info);

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
