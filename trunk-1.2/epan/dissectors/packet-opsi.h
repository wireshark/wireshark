/* packet-opsi.h
 * Routines for OPSI protocol dissection
 * Copyright 2004, Laurent Rabret <laurent.rabret@i.hate.spams.org>
 *
 * $Id$
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


#ifndef __PACKET_OPSI_H__
#define __PACKET_OPSI_H__

/* TCP destination port dedicated to the OPSI protocol */
#define TCP_PORT_OPSI		4002

/* Information position in OPSI header */
#define MAJOR_VERSION_OFFSET	0
#define MINOR_VERSION_OFFSET	1
#define CODE_OFFSET		2
#define HOOK_ID_OFFSET		3
#define PACKET_LENGTH_OFFSET	4
#define SESSION_OFFSET		6

#define HEADER_LENGTH		8


/* Valid OPSI code values */
#define DISCOVER_REQUEST	1
#define DISCOVER_RESPONSE	2
#define SERVICE_REQUEST 	3
#define SERVICE_ACCEPT		4
#define SERVICE_REJECT		5
#define	TERMINATE_REQUEST	6

/* Internal structure to dissect attributes */
typedef struct {
	guint16		attribute_type;		/* attribute code */
        const char	*tree_text;             /* text for fold out */
        gint		*tree_id;               /* id for add_item */
        int*		hf_type_attribute;	/* id for seach option */
        void		(*dissect)(tvbuff_t *tvb, proto_tree *tree, int* hfValue, int offset, int length);
} opsi_attribute_handle_t;


/* Attributes codes */
#define USER_NAME_ATTRIBUTE		1
#define USER_PASSWD_ATTRIBUTE		2
#define CHAP_PASSWD_ATTRIBUTE		3
#define NAS_IP_ADDRESS_ATTRIBUTE	4
#define NAS_PORT_ATTRIBUTE		5
#define SERVICE_TYPE_ATTRIBUTE		6
#define FRAMED_PROTOCOL_ATTRIBUTE	7
#define FRAMED_ADDRESS_ATTRIBUTE	8
#define FRAMED_NETMASK_ATTRIBUTE	9
#define FRAMED_ROUTING_ATTRIBUTE	10
#define FRAMED_FILTER_ATTRIBUTE		11
#define FRAMED_MTU_ATTRIBUTE		12
#define FRAMED_COMPRESSION_ATTRIBUTE	13
#define CALLED_STATION_ID_ATTRIBUTE	30
#define CALLING_STATION_ID_ATTRIBUTE	31
#define NAS_IDENTIFIER			32
#define ACCOUNTING_40_ATTRIBUTE		40
#define ACCOUNTING_41_ATTRIBUTE		41
#define ACCOUNTING_42_ATTRIBUTE		42
#define ACCOUNTING_43_ATTRIBUTE		43
#define ACCOUNTING_SESSION_ID_ATTRIBUTE	44
#define ACCOUNTING_45_ATTRIBUTE		45
#define ACCOUNTING_46_ATTRIBUTE		46
#define ACCOUNTING_47_ATTRIBUTE		47
#define ACCOUNTING_48_ATTRIBUTE		48
#define ACCOUNTING_49_ATTRIBUTE		49
#define ACCOUNTING_50_ATTRIBUTE		50
#define ACCOUNTING_51_ATTRIBUTE		51
#define ACCOUNTING_52_ATTRIBUTE		52
#define ACCOUNTING_53_ATTRIBUTE		53
#define ACCOUNTING_54_ATTRIBUTE		54
#define ACCOUNTING_55_ATTRIBUTE		55
#define ACCOUNTING_56_ATTRIBUTE		56
#define ACCOUNTING_57_ATTRIBUTE		57
#define ACCOUNTING_58_ATTRIBUTE		58
#define ACCOUNTING_59_ATTRIBUTE		59
#define CHAP_CHALLENGE_ATTRIBUTE	60
#define NAS_PORT_TYPE_ATTRIBUTE		61
#define DESIGNATION_NUMBER_ATTRIBUTE	77
#define NAS_PORT_ID_ATTRIBUTE		87

#define SMC_AAAID_ATTRIBUTE		651
#define SMC_VPNID_ATTRIBUTE		652
#define SMC_VPNNAME_ATTRIBUTE		653
#define SMC_RANID_ATTRIBUTE		654
#define SMC_RANIP_ATTRIBUTE		655
#define SMC_RANNAME_ATTRIBUTE		656
#define SMC_POPID_ATTRIBUTE		657
#define SMC_POPNAME_ATTRIBUTE		658
#define SMC_SMCID_ATTRIBUTE		659
#define SMC_RECEIVE_TIME_ATTRIBUTE	660
#define SMC_STAT_TIME_ATTRIBUTE		661

#define OPSI_FLAGS_ATTRIBUTE		674
#define OPSI_APPLICATION_NAME_ATTRIBUTE	675

/*
 * Published API functions.  NOTE, "local" API functions 
 * only valid from the packet-opsi file.
 */

extern void decode_string_attribute(tvbuff_t *tvb, proto_tree *tree, int* hfValue, int offset, int length);
extern void decode_ipv4_attribute(tvbuff_t *tvb, proto_tree *tree, int* hfValue, int offset, int length);
extern void decode_longint_attribute(tvbuff_t *tvb, proto_tree *tree, int* hfValue, int offset, int length);
extern void decode_value_string_attribute(tvbuff_t *tvb, proto_tree *tree, int* hfValue, int offset, int length);
extern void decode_time_attribute(tvbuff_t *tvb, proto_tree *tree, int* hfValue, int offset, int length);
#endif
