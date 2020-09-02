/*
 * packet-wifi-dpp.h
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

int
dissect_wifi_dpp_public_action(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, void *data _U_);
