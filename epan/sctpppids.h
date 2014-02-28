/* sctpppids.h
 * Declarations of SCTP payload protocol IDs.
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

#ifndef __SCTPPPIDS_H__
#define __SCTPPPIDS_H__

/*
 * SCTP payload protocol IDs.
 * From http://www.iana.org/assignments/sctp-parameters
 * as of 2014/02/28
 *
 * Please do not put non-IANA-registered PPIDs here.  Put them in the dissector
 * using them instead (and consider registering them!).
 */
#define NOT_SPECIFIED_PROTOCOL_ID                       0
#define IUA_PAYLOAD_PROTOCOL_ID                         1
#define M2UA_PAYLOAD_PROTOCOL_ID                        2
#define M3UA_PAYLOAD_PROTOCOL_ID                        3
#define SUA_PAYLOAD_PROTOCOL_ID                         4
#define M2PA_PAYLOAD_PROTOCOL_ID                        5
#define V5UA_PAYLOAD_PROTOCOL_ID                        6
#define H248_PAYLOAD_PROTOCOL_ID                        7
#define BICC_PAYLOAD_PROTOCOL_ID                        8
#define TALI_PAYLOAD_PROTOCOL_ID                        9
#define DUA_PAYLOAD_PROTOCOL_ID                        10
#define ASAP_PAYLOAD_PROTOCOL_ID                       11
#define ENRP_PAYLOAD_PROTOCOL_ID                       12
#define H323_PAYLOAD_PROTOCOL_ID                       13
#define QIPC_PAYLOAD_PROTOCOL_ID                       14
#define SIMCO_PAYLOAD_PROTOCOL_ID                      15
#define DDP_SEG_CHUNK_PROTOCOL_ID                      16
#define DDP_STREAM_SES_CTRL_PROTOCOL_ID                17
#define S1AP_PAYLOAD_PROTOCOL_ID                       18
#define RUA_PAYLOAD_PROTOCOL_ID                        19
#define HNBAP_PAYLOAD_PROTOCOL_ID                      20
#define FORCES_HP_PAYLOAD_PROTOCOL_ID                  21
#define FORCES_MP_PAYLOAD_PROTOCOL_ID                  22
#define FORCES_LP_PAYLOAD_PROTOCOL_ID                  23
#define SBC_AP_PAYLOAD_PROTOCOL_ID                     24
#define NBAP_PAYLOAD_PROTOCOL_ID                       25
/* Unassigned 26 */
#define X2AP_PAYLOAD_PROTOCOL_ID                       27
#define IRCP_PAYLOAD_PROTOCOL_ID                       28
#define LCS_AP_PAYLOAD_PROTOCOL_ID                     29
#define MPICH2_PAYLOAD_PROTOCOL_ID                     30
#define SABP_PAYLOAD_PROTOCOL_ID                       31
#define FGP_PAYLOAD_PROTOCOL_ID                        32
#define PPP_PAYLOAD_PROTOCOL_ID                        33
#define CALCAPP_PAYLOAD_PROTOCOL_ID                    34
#define SSP_PAYLOAD_PROTOCOL_ID                        35
#define NPMP_CTRL_PAYLOAD_PROTOCOL_ID                  36
#define NPMP_DATA_PAYLOAD_PROTOCOL_ID                  37
#define ECHO_PAYLOAD_PROTOCOL_ID                       38
#define DISCARD_PAYLOAD_PROTOCOL_ID                    39
#define DAYTIME_PAYLOAD_PROTOCOL_ID                    40
#define CHARGEN_PAYLOAD_PROTOCOL_ID                    41
#define PROTO_3GPP_RNA_PROTOCOL_ID                     42
#define PROTO_3GPP_M2AP_PROTOCOL_ID                    43
#define PROTO_3GPP_M3AP_PROTOCOL_ID                    44
#define SSH_PAYLOAD_PROTOCOL_ID                        45
#define DIAMETER_PROTOCOL_ID                           46
#define DIAMETER_DTLS_PROTOCOL_ID                      47
#define R14P_BER_PROTOCOL_ID                           48
/* Unassigned 49 */
#define WEBRTC_CONTROL_PAYLOAD_PROTOCOL_ID             50
#define WEBRTC_DOMSTRING_LAST_PAYLOAD_PROTOCOL_ID      51
#define WEBRTC_BINARY_DATA_PARTIAL_PAYLOAD_PROTOCOL_ID 52
#define WEBRTC_BINARY_DATA_LAST_PAYLOAD_PROTOCOL_ID    53
#define WEBRTC_DOMSTRING_PARTIAL_PAYLOAD_PROTOCOL_ID   54
#define TGPP_PUA_PAYLOAD_PROTOCOL_ID                   55

#endif /* sctpppids.h */
