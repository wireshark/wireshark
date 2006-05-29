/* packet-ansi_a.h
 *
 * $Id$
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>,
 * In association with Telos Technology Inc.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

typedef struct _ansi_a_tap_rec_t {
    /*
     * value from packet-bssap.h
     */
    guint8		pdu_type;
    guint8		message_type;
} ansi_a_tap_rec_t;


/*
 * the following allows TAP code access to the messages
 * without having to duplicate it. With MSVC and a 
 * libwireshark.dll, we need a special declaration.
 */
ETH_VAR_IMPORT const value_string ansi_a_ios401_bsmap_strings[];
ETH_VAR_IMPORT const value_string ansi_a_ios401_dtap_strings[];

/*
 * allows ANSI MAP to use this for IS-880 enhancements
 */
extern const value_string ansi_a_ios401_elem_1_strings[];

/*
 * maximum number of strings that are allowed
 * 255 because IEI are 1 octet in length
 *
 * this define is required by dissectors that need to
 * size based on the 'ansi_a_ios401_elem_1_strings'
 * array
 */
#define	ANSI_A_MAX_NUM_IOS401_ELEM_1_STRINGS	255
