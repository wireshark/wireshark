/* packet-atn-ulcs.h
 * Definitions for atn packet disassembly structures and routines
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
#ifndef PACKET_ATN_ULCS_H
#define PACKET_ATN_ULCS_H

#include <config.h>

#include "packet.h"

#include <epan/wmem/wmem.h>

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
    gint ae_qualifier; /* A/G application type  */
} atn_conversation_t;

atn_conversation_t * create_atn_conversation(
    address*,
    guint16,
    address*,
    atn_conversation_t*);

atn_conversation_t * find_atn_conversation(
    address*,
    guint16,
    address*);

/* struct for conversation data reconstruction used in AARQ and AARE */
/* if transport data is larger than 32 octets AARQ/AARE is contained */
/* within DT frames which have only dest_ref, but no src_ref */
/* if AARQ/AARQ is contained within CR/CC only src_ref is present in CR */
/* while CC provides src_ref and dstref */
typedef struct aarq_data_t {
    gboolean aarq_pending; /* flag tells whether AARQ/sequence is pending (true)  */
                           /* required not to mix up different AARQ/AARE sequences */
                           /* during simoultanous establishment of transport connections */
                           /* i.e. GND facility initialises cpcstart and cmcontact at the same time */
    atn_conversation_t* cv; /* pointer to AARQ conversation */
} aarq_data_t;

wmem_tree_t *get_atn_conversation_tree(void);

guint32 get_aircraft_24_bit_address_from_nsap(packet_info *);
int check_heur_msg_type(packet_info *);

#endif

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
