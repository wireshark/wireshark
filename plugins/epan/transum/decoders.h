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

 /**
  * @brief Decodes SYN packets.
  *
  * @param pinfo Packet information structure.
  * @param tree Protocol tree for displaying decoded data.
  * @param pkt_info Packet information structure.
  * @return int 0 on success, -1 on failure.
  */
int decode_syn(packet_info *pinfo, proto_tree *tree, PKT_INFO* pkt_info);

/**
 * @brief Decodes DCE/RPC packets.
 *
 * @param pinfo Packet information structure.
 * @param tree Protocol tree for displaying decoded data.
 * @param pkt_info Packet information structure.
 * @return int 0 on success, -1 on failure.
 */
int decode_dcerpc(packet_info *pinfo, proto_tree *tree, PKT_INFO* pkt_info);

/**
 * @brief Decodes SMB packets.
 *
 * @param pinfo Packet information structure.
 * @param tree Protocol tree for displaying decoded data.
 * @param pkt_info Packet information structure.
 * @param subpackets Subpacket information structure.
 * @return int 0 on success, -1 on failure.
 */
int decode_smb(packet_info *pinfo, proto_tree *tree, PKT_INFO* pkt_info, PKT_INFO* subpackets);

/**
 * @brief Decodes GTCP packets.
 *
 * @param pinfo Packet information structure.
 * @param tree Protocol tree for displaying decoded data.
 * @param pkt_info Packet information structure.
 * @return int 0 on success, -1 on failure.
 */
int decode_gtcp(packet_info *pinfo, proto_tree *tree, PKT_INFO* pkt_info);

/**
 * @brief Decodes DNS packets.
 *
 * @param pinfo Packet information structure.
 * @param tree Protocol tree for displaying decoded data.
 * @param pkt_info Packet information structure.
 * @return int 0 on success, -1 on failure.
 */
int decode_dns(packet_info *pinfo, proto_tree *tree, PKT_INFO* pkt_info);

 /**
  * @brief Decodes GUDP packet information.
  *
  * Extracts source and destination ports from the packet info and populates pkt_info with relevant data.
  * If specific fields are found in the tree, they are used to update pkt_info.
  *
  * @param pinfo Pointer to the packet information structure.
  * @param tree Pointer to the protocol tree for decoding.
  * @param pkt_info Pointer to the packet info structure to be populated.
  * @return int Error code if extraction fails, 0 otherwise.
  */
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
