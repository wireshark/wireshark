/* packet-gsm_sms.h
 *
 * Copyright 2004, Michael Lum <mlum [AT] telostech.com>,
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

enum character_set {
    OTHER,
    GSM_7BITS,
    ASCII_7BITS
};

/*
 * contains a subset of parameters dissected from the UDH
 * that are useful in the GSM SMS dissector or other dissectors
 * (packet-ansi_637.c)
 */
typedef struct {
    guint16     sm_id;          /* message identifier */
    guint16     frags;          /* total number of fragments */
    guint16     frag;           /* fragment number */
    guint16     port_src;       /* application port addressing scheme source port */
    guint16     port_dst;       /* application port addressing scheme destination port */
} gsm_sms_udh_fields_t;

void dis_field_udh(tvbuff_t *tvb, proto_tree *tree, guint32 *offset, guint32 *length,
                   guint8 *udl, enum character_set cset, guint8 *fill_bits, gsm_sms_udh_fields_t *p_udh_fields);

/* Data structure that can be optionally given to gsm_sms dissector */
typedef struct _gsm_sms_data_t {
    gboolean stk_packing_required;
} gsm_sms_data_t;
