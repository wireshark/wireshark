/* packet-h225.h
 * Routines for h225 packet dissection
 * Copyright 2005, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_H225_H
#define PACKET_H225_H

typedef enum _h225_msg_type {
  H225_RAS,
  H225_CS,
  H225_OTHERS
} h225_msg_type;

typedef enum _h225_cs_type {
  H225_SETUP,
  H225_CALL_PROCEDING,
  H225_CONNECT,
  H225_ALERTING,
  H225_INFORMATION,
  H225_RELEASE_COMPLET,
  H225_FACILITY,
  H225_PROGRESS,
  H225_EMPTY,
  H225_STATUS,
  H225_STATUS_INQUIRY,
  H225_SETUP_ACK,
  H225_NOTIFY,
  H225_OTHER
} h225_cs_type;

typedef struct _h225_packet_info {
  h225_msg_type msg_type;          /* ras or cs message */
  h225_cs_type  cs_type;           /* cs message type */
  int           msg_tag;           /* message tag*/
  int           reason;            /* reason tag, if available */
  unsigned      requestSeqNum;     /* request sequence number of ras-message, if available */
  e_guid_t      guid;              /* globally unique call id */
  bool          is_duplicate;      /* true, if this is a repeated message */
  bool          request_available; /* true, if response matches to a request */
  nstime_t      delta_time;        /* this is the RAS response time delay */
  /* added for h225 conversations analysis */
  bool          is_faststart;      /* true, if faststart field is included */
  bool          is_h245;
  bool          is_h245Tunneling;
  uint32_t      h245_address;
  uint16_t      h245_port;
  char          dialedDigits[129]; /* Dialed Digits in the LRQ and LCF used for voip analysis */
  bool          is_destinationInfo;
  char          frame_label[50];   /* the Frame label used by graph_analysis, what is an abbreviation of cinfo */
} h225_packet_info;

/*
 * the following allows TAP code access to the messages
 * without having to duplicate it. With MSVC and a
 * libwireshark.dll, we need a special declaration.
 */

#include <epan/asn1.h>
#include "packet-per.h"

#include "packet-h225-exp.h"

#endif  /* PACKET_H225_H */

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
