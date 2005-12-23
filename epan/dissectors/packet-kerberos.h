/* packet-kerberos.h
 *
 * $Id$
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

#ifndef __PACKET_KERBEROS_H
#define __PACKET_KERBEROS_H

/* This is a list of callback functions a caller can use to specify that
   octet strings in kerberos to be passed back to application specific
   dissectors, outside of kerberos.
   This is used for dissection of application specific data for PacketCable
   KRB_SAFE user data and eventually to pass kerberos session keys
   to future DCERPC decryption and other uses.
   The list is terminated by {0, NULL }
*/
#define KRB_CBTAG_SAFE_USER_DATA	        1
#define KRB_CBTAG_PRIV_USER_DATA	        2
typedef struct _kerberos_callbacks {
	int tag;
	int (*callback)(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree);
} kerberos_callbacks;

/* Function prototypes */

gint
dissect_kerberos_main(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean do_col_info, kerberos_callbacks *cb);

int
dissect_krb5_Checksum(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);

int
dissect_krb5_ctime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);

int dissect_krb5_cname(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);
int dissect_krb5_realm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);
guint32 kerberos_output_keytype(void);

guint get_krb_pdu_len(tvbuff_t *tvb, int offset);

gint kerberos_rm_to_reclen(guint krb_rm);

void
show_krb_recordmark(proto_tree *tree, tvbuff_t *tvb, gint start, guint32 krb_rm);

#ifdef HAVE_KERBEROS
#define KRB_MAX_ORIG_LEN	256

#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)
typedef struct _enc_key_t {
	struct _enc_key_t	*next;
	int keytype;
	int keylength;
	char *keyvalue;
	char 			key_origin[KRB_MAX_ORIG_LEN+1];
} enc_key_t;
extern enc_key_t *enc_key_list;

guint8 *
decrypt_krb5_data(proto_tree *tree, packet_info *pinfo,
			int usage,
			int length,
			const guint8 *cryptotext,
			int keytype);

#endif /* HAVE_HEIMDAL_KERBEROS || HAVE_MIT_KERBEROS */

#endif /* HAVE_KERBEROS */

#endif /* __PACKET_KERBEROS_H */
