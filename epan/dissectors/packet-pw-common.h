/* packet-pw-common.h
 * Interface of pw-common module
 * Copyright 2009, Artem Tamazov <artem.tamazov@tellabs.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_PW_COMMON_H
#define PACKET_PW_COMMON_H

#include <glib.h>
#include <epan/packet.h>

#define PWC_SIZEOF_CW 4

extern const char pwc_longname_pw_satop[];
extern const char pwc_longname_pw_cesopsn[];
extern const char pwc_longname_pw_atm_n1_cw[];
extern const char pwc_longname_pw_atm_n1_nocw[];
extern const char pwc_longname_pw_atm_11_or_aal5_pdu[];
extern const char pwc_longname_pw_atm_aal5_sdu[];

extern const value_string pwc_vals_cw_l_bit[];
extern const value_string pwc_vals_cw_r_bit[];
extern const value_string pwc_vals_cw_frag[];

typedef enum {
	PWC_CW_BAD_BITS03 		= 1 << 0
	,PWC_CW_BAD_PAYLEN_LT_0		= 1 << 1
	,PWC_CW_BAD_PAYLEN_GT_PACKET	= 1 << 2
	,PWC_CW_BAD_LEN_MUST_BE_0	= 1 << 3
	,PWC_CW_BAD_FRAG 		= 1 << 4
	,PWC_CW_BAD_RSV 		= 1 << 5
	,PWC_CW_BAD_FLAGS 		= 1 << 8
	,PWC_CW_BAD_PAYLEN_LE_0		= 1 << 9
	,PWC_CW_BAD_PADDING_NE_0	= 1 << 10
	,PWC_ANYOF_CW_BAD	= PWC_CW_BAD_BITS03
				+ PWC_CW_BAD_PAYLEN_LT_0
				+ PWC_CW_BAD_PAYLEN_GT_PACKET
				+ PWC_CW_BAD_LEN_MUST_BE_0
				+ PWC_CW_BAD_FRAG
				+ PWC_CW_BAD_RSV
				+ PWC_CW_BAD_FLAGS
				+ PWC_CW_BAD_PAYLEN_LE_0
				+ PWC_CW_BAD_PADDING_NE_0
	,PWC_CW_SUSPECT_LM		= 1 << 6
	,PWC_ANYOF_CW_SUSPECT	= PWC_CW_SUSPECT_LM
	,PWC_PAY_SIZE_BAD		= 1 << 7
}
pwc_packet_properties_t;
#define PWC_PACKET_PROPERTIES_T_INITIALIZER 0

typedef enum {
	PWC_DEMUX_MPLS = 0
	,PWC_DEMUX_UDP		/*IPv4/IPv6 and UDP as demultiplexing layer*/
	,PWC_DEMUX_L2TP		/*IPv4/IPv6 and L2TPv3 as demultiplexing layer*/
}
pwc_demux_type_t;

extern void pwc_item_append_cw(proto_item* item, const guint32 cw, const gboolean append_text);
extern void pwc_item_append_text_n_items(proto_item* item, const int n, const char * const item_text);

#endif
