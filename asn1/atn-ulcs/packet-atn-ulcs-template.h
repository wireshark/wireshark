/* c-basic-offset: 2; tab-width: 2; indent-tabs-mode: t
 * vi: set shiftwidth=2 tabstop=2 noexpandtab:
 * :indentSize=2:tabSize=2:noTabs=false:
 */

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

#include "config.h"

#include "packet.h"

#include <epan/wmem/wmem.h>

/* IA5 charset (7-bit) for PER IA5 decoding */
static const gchar ia5alpha[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, \
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, \
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,	\
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, \
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,	\
		0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,	\
		0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,	\
		0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,	\
		0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, '\0'
};

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
		pmcpdlc =22,	/* "protected mode" CPDLC */
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
 * c-basic-offset: 2
 * tab-width: 2
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=2 tabstop=2 noexpandtab:
 * :indentSize=2:tabSize=2:noTabs=false:
 */
