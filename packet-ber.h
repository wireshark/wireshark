/* packet-ber.h
 * Helpers for ASN.1/BER dissection
 * Ronnie Sahlberg (C) 2004
 *
 * $Id: packet-ber.h,v 1.1 2004/02/20 10:04:10 sahlberg Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

typedef int (*ber_callback)(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);

#define BER_CLASS_UNI	0x00
#define BER_CLASS_APP	0x01
#define BER_CLASS_CON	0x02
#define BER_CLASS_PRI	0x03


#define BER_UNI_TAG_BOOLEAN	0x01
#define BER_UNI_TAG_INTEGER	0x02
#define BER_UNI_TAG_BITSTRING	0x03
#define BER_UNI_TAG_OCTETSTRING	0x04
#define BER_UNI_TAG_SEQUENCE	0x10
#define BER_UNI_TAG_GENTIME	0x18
#define BER_UNI_TAG_GENSTR	0x1b

/* this function dissects the identifier octer of the BER TLV.
 * We only handle TAGs (and LENGTHs) that fit inside 32 bit integers.
 */
int dissect_ber_identifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, guint8 *class, gboolean *pc, guint32 *tag);

/* this function dissects the identifier octer of the BER TLV.
 * We only handle (TAGs and) LENGTHs that fit inside 32 bit integers.
 */
int dissect_ber_length(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, guint32 *length);

/* func is NULL normally but
 * if the octet string contains an ber encode struct we provide func as the 
 * dissector for that struct
 */
int dissect_ber_octet_string(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, ber_callback func);

int dissect_ber_integer(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, guint32 *value);


int dissect_ber_boolean(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id);


#define BER_FLAGS_OPTIONAL	0x00000001
typedef struct _ber_sequence {
	guint8	class;
	guint32	tag;
	guint32	flags;
	ber_callback	func;
} ber_sequence;

/* this function dissects a BER sequence 
 */
int dissect_ber_sequence(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, ber_sequence *seq, gint hf_id, gint ett_id);


typedef struct _ber_choice {
	guint8	class;
	guint32	tag;
	ber_callback	func;
} ber_choice;


/* this function dissects a BER choice 
 */
int dissect_ber_choice(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_choice *ch, gint hf_id, gint ett_id);


/* this function dissects a BER GeneralString
 */
int dissect_ber_GeneralString(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, char *name_string, int name_len);


/* this function dissects a BER sequence of
 */
int dissect_ber_sequence_of(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, ber_callback func, gint hf_id, gint ett_id);


int dissect_ber_generalized_time(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id);

/* this function dissects a BER BIT-STRING
 */
int dissect_ber_bitstring(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, gint hf_id, gint ett_id, unsigned char *bitstring, int bitstring_len, proto_item **it, proto_tree **tr);


extern proto_item *ber_last_created_item;
