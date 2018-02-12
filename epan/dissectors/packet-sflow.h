/* packet-sflow.h
 * sFlow v5 dissection implemented according to the specifications
 * at http://www.sflow.org/sflow_version_5.txt
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_SFLOW_H__
#define __PACKET_SFLOW_H__

#define SFLOW_245_HEADER_ETHERNET            1
#define SFLOW_245_HEADER_TOKENBUS            2
#define SFLOW_245_HEADER_TOKENRING           3
#define SFLOW_245_HEADER_FDDI                4
#define SFLOW_245_HEADER_FRAME_RELAY         5
#define SFLOW_245_HEADER_X25                 6
#define SFLOW_245_HEADER_PPP                 7

/* We don't have an SMDS dissector yet
 *
 * Switched multimegabit data service (SMDS) was a connectionless service
 * used to connect LANs, MANs and WANs to exchange data. SMDS was based on
 * the IEEE 802.6 DQDB standard. SMDS fragmented its datagrams into smaller
 * "cells" for transport, and can be viewed as a technological precursor of ATM.
 */
#define SFLOW_245_HEADER_SMDS                8

/*
 * No AAL5 (ATM Adaptation Layer 5) dissector available.
 * What does the packet look like?  An AAL5 PDU?  Where
 * do the VPI/VCI pair appear, if anywhere?
 */
#define SFLOW_245_HEADER_AAL5                9
#define SFLOW_245_HEADER_AAL5_IP            10

#define SFLOW_245_HEADER_IPv4               11
#define SFLOW_245_HEADER_IPv6               12
#define SFLOW_245_HEADER_MPLS               13

/* wireshark does not have POS dissector yet */
#define SFLOW_5_HEADER_POS                  14

#define SFLOW_5_HEADER_80211_MAC            15

/* XXX - No handles for these, need to be converted into "dissectors" */
#define SFLOW_5_HEADER_80211_AMPDU          16 /* "wlan_aggregate" */
#define SFLOW_5_HEADER_80211_AMSDU_SUBFRAME 17

#endif
