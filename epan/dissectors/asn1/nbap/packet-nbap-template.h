/* packet-nbap-template.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_NBAP_H
#define PACKET_NBAP_H

#include "packet-umts_rlc.h"
#include "packet-umts_mac.h"

/*
 * Ericsson specific mapping for various dissector settings.
 * Must be altered for other equipment.
 */

/*Array are indexed on logical channel id, meaning they need to be defined for 1-15*/
/* Mapping from logical channel id to MAC content type ie. DCCH or DTCH*/
extern guint8 lchId_type_table[];

/* Mapping logicalchannel id to RLC_MODE */
extern guint8 lchId_rlc_map[];

/* Mapping Scrambling Codes to C-RNC Contexts */
extern wmem_tree_t *nbap_scrambling_code_crncc_map;
/* Mapping C-RNC Contexts to U-RNTIs */
extern wmem_tree_t *nbap_crncc_urnti_map;

#endif
