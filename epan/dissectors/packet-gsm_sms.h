/* packet-gsm_sms.h
 *
 * Copyright 2004, Michael Lum <mlum [AT] telostech.com>,
 * In association with Telos Technology Inc.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_GSM_SMS_H_
#define __PACKET_GSM_SMS_H_

enum character_set {
    OTHER,
    GSM_7BITS,
    ASCII_7BITS,
    GSM_7BITS_UNPACKED,
    UCS2
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

void dis_field_udh(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 *offset, guint32 *length,
                   guint8 *udl, enum character_set cset, guint8 *fill_bits, gsm_sms_udh_fields_t *p_udh_fields);

void dis_field_addr(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 *offset_p, const gchar *title);

/* Data structure that can be optionally given to gsm_sms dissector */
typedef struct _gsm_sms_data_t {
    gboolean stk_packing_required;
} gsm_sms_data_t;

#endif
