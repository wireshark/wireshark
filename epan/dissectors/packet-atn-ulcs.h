/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-atn-ulcs.h                                                          */
/* asn2wrs.py -u -q -L -p atn-ulcs -c ./atn-ulcs.cnf -s ./packet-atn-ulcs-template -D . -O ../.. atn-ulcs.asn */

/* packet-atn-ulcs.h
 * Definitions for atn packet disassembly structures and routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef PACKET_ATN_ULCS_H
#define PACKET_ATN_ULCS_H

#include "packet.h"

#include <epan/wmem_scopes.h>

enum msg_type {
    um,
    dm,
    no_msg
};

enum ae_qualifier {
    ads = 0,
    cma =1, /* contact management (CM) */
    cpdlc = 2, /* "plain old" CPDLC */
    ati = 3 ,
    arf =10 ,
    met =11,
    gac =12,
    pmcpdlc =22,  /* "protected mode" CPDLC */
    unknown = -1
};

typedef struct atn_conversation_t {
    int ae_qualifier; /* A/G application type  */
} atn_conversation_t;

atn_conversation_t * create_atn_conversation(
    address*,
    uint16_t,
    address*,
    atn_conversation_t*);

atn_conversation_t * find_atn_conversation(
    address*,
    uint16_t,
    address*);

/* struct for conversation data reconstruction used in AARQ and AARE */
/* if transport data is larger than 32 octets AARQ/AARE is contained */
/* within DT frames which have only dest_ref, but no src_ref */
/* if AARQ/AARQ is contained within CR/CC only src_ref is present in CR */
/* while CC provides src_ref and dstref */
typedef struct aarq_data_t {
    bool aarq_pending; /* flag tells whether AARQ/sequence is pending (true)  */
                           /* required not to mix up different AARQ/AARE sequences */
                           /* during simultaneous establishment of transport connections */
                           /* i.e. GND facility initialises cpcstart and cmcontact at the same time */
    atn_conversation_t* cv; /* pointer to AARQ conversation */
} aarq_data_t;

wmem_tree_t *get_atn_conversation_tree(void);

uint32_t get_aircraft_24_bit_address_from_nsap(packet_info *);
int check_heur_msg_type(packet_info *);

#endif

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
