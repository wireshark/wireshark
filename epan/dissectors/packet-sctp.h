/* packet-sctp.h
 *
 * Definition of SCTP specific structures used by tap listeners.
 *
 * Copyright 2004 Michael Tuexen <tuexen [AT] fh-muenster.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_SCTP_H__
#define __PACKET_SCTP_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define MAXIMUM_NUMBER_OF_TVBS 2048

struct _sctp_info {
  bool incomplete;
  bool adler32_calculated;
  bool adler32_correct;
  bool crc32c_calculated;
  bool crc32c_correct;
  bool checksum_zero;
  bool vtag_reflected;
  uint16_t sport;
  uint16_t dport;
  address ip_src;
  address ip_dst;
  uint32_t verification_tag;
  uint16_t assoc_index;
  uint16_t direction;
  uint32_t number_of_tvbs;
  tvbuff_t *tvb[MAXIMUM_NUMBER_OF_TVBS];
};

typedef struct _sctp_fragment {
  uint32_t frame_num;
  uint32_t tsn;
  uint32_t len;
  uint32_t ppi;
  unsigned char *data;
  struct _sctp_fragment *next;
} sctp_fragment;

typedef struct _sctp_frag_be {
  sctp_fragment* fragment;
  struct _sctp_frag_be *next;
} sctp_frag_be;

typedef struct _sctp_complete_msg {
  uint32_t begin;
  uint32_t end;
  sctp_fragment* reassembled_in;
  uint32_t len;
  unsigned char *data;
  struct _sctp_complete_msg *next;
} sctp_complete_msg;

typedef struct _sctp_frag_msg {
  sctp_frag_be* begins;
  sctp_frag_be* ends;
  sctp_fragment* fragments;
  sctp_complete_msg* messages;
  uint32_t ppi;
  struct _sctp_frag_msg* next;
} sctp_frag_msg;

#define SCTP_DATA_CHUNK_ID               0
#define SCTP_INIT_CHUNK_ID               1
#define SCTP_INIT_ACK_CHUNK_ID           2
#define SCTP_SACK_CHUNK_ID               3
#define SCTP_HEARTBEAT_CHUNK_ID          4
#define SCTP_HEARTBEAT_ACK_CHUNK_ID      5
#define SCTP_ABORT_CHUNK_ID              6
#define SCTP_SHUTDOWN_CHUNK_ID           7
#define SCTP_SHUTDOWN_ACK_CHUNK_ID       8
#define SCTP_ERROR_CHUNK_ID              9
#define SCTP_COOKIE_ECHO_CHUNK_ID       10
#define SCTP_COOKIE_ACK_CHUNK_ID        11
#define SCTP_ECNE_CHUNK_ID              12
#define SCTP_CWR_CHUNK_ID               13
#define SCTP_SHUTDOWN_COMPLETE_CHUNK_ID 14
#define SCTP_AUTH_CHUNK_ID              15
#define SCTP_NR_SACK_CHUNK_ID           16
#define SCTP_I_DATA_CHUNK_ID          0x40
#define SCTP_ASCONF_ACK_CHUNK_ID      0x80
#define SCTP_PKTDROP_CHUNK_ID         0x81
#define SCTP_RE_CONFIG_CHUNK_ID       0x82
#define SCTP_PAD_CHUNK_ID             0x84
#define SCTP_FORWARD_TSN_CHUNK_ID     0xC0
#define SCTP_ASCONF_CHUNK_ID          0xC1
#define SCTP_I_FORWARD_TSN_CHUNK_ID   0xC2
#define SCTP_IETF_EXT                 0xFF

#define IS_SCTP_CHUNK_TYPE(t) \
	(((t) <= SCTP_NR_SACK_CHUNK_ID) || \
	 ((t) == SCTP_I_DATA_CHUNK_ID) || \
	 ((t) == SCTP_FORWARD_TSN_CHUNK_ID) || \
	 ((t) == SCTP_ASCONF_CHUNK_ID) || \
	 ((t) == SCTP_ASCONF_ACK_CHUNK_ID) || \
	 ((t) == SCTP_PKTDROP_CHUNK_ID))


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
#define GDT_PROTOCOL_ID                                49
#define WEBRTC_DCEP_PROTOCOL_ID                        50
#define WEBRTC_STRING_PAYLOAD_PROTOCOL_ID              51
#define WEBRTC_BINARY_PARTIAL_PAYLOAD_PROTOCOL_ID      52
#define WEBRTC_BINARY_PAYLOAD_PROTOCOL_ID              53
#define WEBRTC_STRING_PARTIAL_PAYLOAD_PROTOCOL_ID      54
#define PROTO_3GPP_PUA_PAYLOAD_PROTOCOL_ID             55
#define WEBRTC_STRING_EMPTY_PAYLOAD_PROTOCOL_ID        56
#define WEBRTC_BINARY_EMPTY_PAYLOAD_PROTOCOL_ID        57
#define XWAP_PROTOCOL_ID                               58
#define XW_CONTROL_PLANE_PROTOCOL_ID                   59
#define NGAP_PROTOCOL_ID                               60
#define XNAP_PROTOCOL_ID                               61
#define F1AP_PROTOCOL_ID                               62
#define HTTP_SCTP_PROTOCOL_ID                          63
#define E1AP_PROTOCOL_ID                               64
#define ELE2_PROTOCOL_ID                               65
#define NGAP_OVER_DTLS_PROTOCOL_ID                     66
#define XNAP_OVER_DTLS_PROTOCOL_ID                     67
#define F1AP_OVER_DTLS_PROTOCOL_ID                     68
#define E1AP_OVER_DTLS_PROTOCOL_ID                     69
#define E2_CP_PROTOCOL_ID                              70
#define E2_UP_PROTOCOL_ID                              71
#define E2_DU_PROTOCOL_ID                              72
#define W1AP_PROTOCOL_ID                               73

WS_DLL_PUBLIC value_string_ext sctpppid_val_ext;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
