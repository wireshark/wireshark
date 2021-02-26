/* sctpppids.h
 * Declarations of SCTP payload protocol IDs.
 *
 * Copyright 2011-2021 by Thomas Dreibholz <dreibh [AT] iem.uni-due.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/sctpppids.h>
#include <epan/addr_resolv.h>
#include <epan/strutil.h>

/*
 * Based on https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml
 * as of February 22, 2021
 */
static const value_string sctp_payload_proto_id_values[] = {
  { NOT_SPECIFIED_PROTOCOL_ID,                      "not specified" },
  { IUA_PAYLOAD_PROTOCOL_ID,                        "IUA" },
  { M2UA_PAYLOAD_PROTOCOL_ID,                       "M2UA" },
  { M3UA_PAYLOAD_PROTOCOL_ID,                       "M3UA" },
  { SUA_PAYLOAD_PROTOCOL_ID,                        "SUA" },
  { M2PA_PAYLOAD_PROTOCOL_ID,                       "M2PA" },
  { V5UA_PAYLOAD_PROTOCOL_ID,                       "V5UA" },
  { H248_PAYLOAD_PROTOCOL_ID,                       "H.248/MEGACO" },
  { BICC_PAYLOAD_PROTOCOL_ID,                       "BICC/Q.2150.3" },
  { TALI_PAYLOAD_PROTOCOL_ID,                       "TALI" },
  { DUA_PAYLOAD_PROTOCOL_ID,                        "DUA" },
  { ASAP_PAYLOAD_PROTOCOL_ID,                       "ASAP" },
  { ENRP_PAYLOAD_PROTOCOL_ID,                       "ENRP" },
  { H323_PAYLOAD_PROTOCOL_ID,                       "H.323" },
  { QIPC_PAYLOAD_PROTOCOL_ID,                       "Q.IPC/Q.2150.3" },
  { SIMCO_PAYLOAD_PROTOCOL_ID,                      "SIMCO" },
  { DDP_SEG_CHUNK_PROTOCOL_ID,                      "DDP Segment Chunk" },
  { DDP_STREAM_SES_CTRL_PROTOCOL_ID,                "DDP Stream Session Control" },
  { S1AP_PAYLOAD_PROTOCOL_ID,                       "S1 Application Protocol (S1AP)" },
  { RUA_PAYLOAD_PROTOCOL_ID,                        "RUA" },
  { HNBAP_PAYLOAD_PROTOCOL_ID,                      "HNBAP" },
  { FORCES_HP_PAYLOAD_PROTOCOL_ID,                  "ForCES-HP" },
  { FORCES_MP_PAYLOAD_PROTOCOL_ID,                  "ForCES-MP" },
  { FORCES_LP_PAYLOAD_PROTOCOL_ID,                  "ForCES-LP" },
  { SBC_AP_PAYLOAD_PROTOCOL_ID,                     "SBc-AP" },
  { NBAP_PAYLOAD_PROTOCOL_ID,                       "NBAP" },
  { 26,                                             "Unassigned" },     /* Unassigned 26 */
  { X2AP_PAYLOAD_PROTOCOL_ID,                       "X2AP" },
  { IRCP_PAYLOAD_PROTOCOL_ID,                       "IRCP" },
  { LCS_AP_PAYLOAD_PROTOCOL_ID,                     "LCS-AP" },
  { MPICH2_PAYLOAD_PROTOCOL_ID,                     "MPICH2" },
  { SABP_PAYLOAD_PROTOCOL_ID,                       "SABP" },
  { FGP_PAYLOAD_PROTOCOL_ID,                        "Fractal Generator Protocol" },
  { PPP_PAYLOAD_PROTOCOL_ID,                        "Ping Pong Protocol" },
  { CALCAPP_PAYLOAD_PROTOCOL_ID,                    "CalcApp Protocol" },
  { SSP_PAYLOAD_PROTOCOL_ID,                        "Scripting Service Protocol" },
  { NPMP_CTRL_PAYLOAD_PROTOCOL_ID,                  "NetPerfMeter Control" },
  { NPMP_DATA_PAYLOAD_PROTOCOL_ID,                  "NetPerfMeter Data" },
  { ECHO_PAYLOAD_PROTOCOL_ID,                       "Echo" },
  { DISCARD_PAYLOAD_PROTOCOL_ID,                    "Discard" },
  { DAYTIME_PAYLOAD_PROTOCOL_ID,                    "Daytime" },
  { CHARGEN_PAYLOAD_PROTOCOL_ID,                    "Character Generator" },
  { PROTO_3GPP_RNA_PROTOCOL_ID,                     "3GPP RNA" },
  { PROTO_3GPP_M2AP_PROTOCOL_ID,                    "3GPP M2AP" },
  { PROTO_3GPP_M3AP_PROTOCOL_ID,                    "3GPP M3AP" },
  { SSH_PAYLOAD_PROTOCOL_ID,                        "SSH" },
  { DIAMETER_PROTOCOL_ID,                           "DIAMETER" },
  { DIAMETER_DTLS_PROTOCOL_ID,                      "DIAMETER over DTLS" },
  { R14P_BER_PROTOCOL_ID,                           "R14P" },
  { 49,                                             "Unassigned" },     /* Unassigned 49 */
  { WEBRTC_DCEP_PROTOCOL_ID,                        "WebRTC Control" },
  { WEBRTC_STRING_PAYLOAD_PROTOCOL_ID,              "WebRTC String" },
  { WEBRTC_BINARY_PARTIAL_PAYLOAD_PROTOCOL_ID,      "WebRTC Binary Partial (Deprecated)" },
  { WEBRTC_BINARY_PAYLOAD_PROTOCOL_ID,              "WebRTC Binary" },
  { WEBRTC_STRING_PARTIAL_PAYLOAD_PROTOCOL_ID,      "WebRTC String Partial (Deprecated)" },
  { PROTO_3GPP_PUA_PAYLOAD_PROTOCOL_ID,             "3GPP PUA" },
  { WEBRTC_STRING_EMPTY_PAYLOAD_PROTOCOL_ID,        "WebRTC String Empty" },
  { WEBRTC_BINARY_EMPTY_PAYLOAD_PROTOCOL_ID,        "WebRTC Binary Empty" },
  { XWAP_PROTOCOL_ID,                               "XwAP" },
  { XW_CONTROL_PLANE_PROTOCOL_ID,                   "Xw - Control Plane" },
  { NGAP_PROTOCOL_ID,                               "NGAP" },
  { XNAP_PROTOCOL_ID,                               "XnAP" },
  { F1AP_PROTOCOL_ID,                               "F1 AP" },
  { ELE2_PROTOCOL_ID,                               "ELE2 Lawful Interception" },
  { NGAP_OVER_DTLS_PROTOCOL_ID,                     "NGAP over DTLS" },
  { XNAP_OVER_DTLS_PROTOCOL_ID,                     "XnAP over DTLS" },
  { F1AP_OVER_DTLS_PROTOCOL_ID,                     "F1AP over DTLS" },
  { E1AP_OVER_DTLS_PROTOCOL_ID,                     "E1AP over DTLS" },
  { E2_CP_PROTOCOL_ID,                              "E2-CP" },
  { E2_UP_PROTOCOL_ID,                              "E2-UP" },
  { E2_DU_PROTOCOL_ID,                              "E2-DU" },
  { W1AP_PROTOCOL_ID,                               "W1AP" },

  { 0,                                              NULL } };


value_string_ext sctpppid_val_ext = VALUE_STRING_EXT_INIT(sctp_payload_proto_id_values);

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
