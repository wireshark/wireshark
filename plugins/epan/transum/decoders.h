/* decoders.h
 * Header file for the TRANSUM response time analyzer post-dissector
 * By Paul Offord <paul.offord@advance7.com>
 * Copyright 2016 Advance Seven Limited
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

int decode_syn(packet_info *pinfo, proto_tree *tree, PKT_INFO* pkt_info);
int decode_dcerpc(packet_info *pinfo, proto_tree *tree, PKT_INFO* pkt_info);
int decode_smb(packet_info *pinfo, proto_tree *tree, PKT_INFO* pkt_info, PKT_INFO* subpackets);
int decode_gtcp(packet_info *pinfo, proto_tree *tree, PKT_INFO* pkt_info);
int decode_dns(packet_info *pinfo, proto_tree *tree, PKT_INFO* pkt_info);
int decode_gudp(packet_info *pinfo, proto_tree *tree, PKT_INFO* pkt_info);

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
