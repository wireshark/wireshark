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

WS_DLL_PUBLIC const value_string chunk_type_values[];

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
