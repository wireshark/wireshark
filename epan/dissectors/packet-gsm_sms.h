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
    uint16_t    sm_id;          /* message identifier */
    uint16_t    frags;          /* total number of fragments */
    uint16_t    frag;           /* fragment number */
    uint16_t    port_src;       /* application port addressing scheme source port */
    uint16_t    port_dst;       /* application port addressing scheme destination port */
} gsm_sms_udh_fields_t;

void dis_field_udh(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, uint32_t *offset, uint32_t *length,
                   uint8_t *udl, enum character_set cset, uint8_t *fill_bits, gsm_sms_udh_fields_t *p_udh_fields);

void dis_field_addr(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, uint32_t *offset_p, const char *title);

/* Data structure that can be optionally given to gsm_sms dissector */
typedef struct _gsm_sms_data_t {
    bool stk_packing_required;
} gsm_sms_data_t;

#endif
