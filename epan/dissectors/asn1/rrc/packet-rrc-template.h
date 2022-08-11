/* packet-rrc-template.h
 * Copyright 2009, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_RRC_H
#define PACKET_RRC_H

#include <epan/asn1.h>    /* Needed for non asn1 dissectors?*/

extern int proto_rrc;
#include "packet-rrc-exp.h"

enum rrc_message_type {
  RRC_MESSAGE_TYPE_INVALID    = 0,
  RRC_MESSAGE_TYPE_PCCH        = 1,
  RRC_MESSAGE_TYPE_UL_CCCH,
  RRC_MESSAGE_TYPE_DL_CCCH,
  RRC_MESSAGE_TYPE_UL_DCCH,
  RRC_MESSAGE_TYPE_DL_DCCH,
  RRC_MESSAGE_TYPE_BCCH_FACH
};

enum nas_sys_info_gsm_map {
  RRC_NAS_SYS_UNKNOWN = 0,
  RRC_NAS_SYS_INFO_CS,
  RRC_NAS_SYS_INFO_PS,
  RRC_NAS_SYS_INFO_CN_COMMON
};

enum rrc_ue_state {
  RRC_UE_STATE_UNKNOWN = 0,
  RRC_UE_STATE_CELL_DCH,
  RRC_UE_STATE_CELL_FACH,
  RRC_UE_STATE_CELL_PCH,
  RRC_UE_STATE_URA_PCH
};

#define MAX_RRC_FRAMES    64
typedef struct rrc_info
{
  enum rrc_message_type msgtype[MAX_RRC_FRAMES];
  guint16 hrnti[MAX_RRC_FRAMES];
} rrc_info;

/*Struct for storing ciphering information*/
typedef struct rrc_ciphering_info
{
  int seq_no[31][2];    /*Indicates for each Rbid when ciphering starts - Indexers are [BearerID][Direction]*/
  GTree * /*guint32*/ start_cs;    /*Start value for CS counter*/
  GTree * /*guint32*/ start_ps;    /*Start value for PS counter*/
  gint32 ciphering_algorithm;    /*Indicates which type of ciphering algorithm used*/
  gint32 integrity_algorithm;    /*Indicates which type of integrity algorithm used*/
  guint32 setup_frame[2];    /*Store which frame contained this information - Indexer is [Direction]*/
  guint32 ps_conf_counters[31][2];    /*This should also be made for CS*/

} rrc_ciphering_info;

extern GTree * hsdsch_muxed_flows;
extern GTree * rrc_ciph_info_tree;
extern wmem_tree_t* rrc_global_urnti_crnti_map;

#endif  /* PACKET_RRC_H */
