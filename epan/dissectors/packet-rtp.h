/* packet-rtp.h
 *
 * Routines for RTP dissection
 * RTP = Real time Transport Protocol
 *
 * $Id$
 *
 * Copyright 2000, Philips Electronics N.V.
 * Written by Andreas Sikkema <andreas.sikkema@philips.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

struct _rtp_info {
	unsigned int  info_version;
	gboolean      info_padding_set;
	gboolean      info_marker_set;
	gboolean	  info_is_video;
	unsigned int  info_payload_type;
	unsigned int  info_padding_count;
	guint16       info_seq_num;
	guint32       info_timestamp;
	guint32       info_sync_src;
	guint         info_data_len;       /* length of raw rtp data as reported */
	gboolean      info_all_data_present; /* FALSE if data is cut off */
	guint         info_payload_offset; /* start of payload relative to info_data */
	guint         info_payload_len;    /* length of payload (incl padding) */
	gboolean      info_is_srtp;
	guint32		  info_setup_frame_num; /* the frame num of the packet that set this RTP connection */
	const guint8* info_data;           /* pointer to raw rtp data */
	gchar		  *info_payload_type_str;
	gint		  info_payload_rate;
	/*
	* info_data: pointer to raw rtp data = header + payload incl. padding.
	* That should be safe because the "epan_dissect_t" constructed for the packet
	*  has not yet been freed when the taps are called.
	* (destroying the "epan_dissect_t" will end up freeing all the tvbuffs
	*  and hence invalidating pointers to their data).
	* See "add_packet_to_packet_list()" for details.
	*/
};

/* definitions for SRTP dissection */

/* Encryption algorithms */
#define SRTP_ENC_ALG_NOT_SET	0	/* Data not available/empty record */
#define SRTP_ENC_ALG_NULL		1	/* non-encrypted SRTP payload - may still be authenticated */
#define SRTP_ENC_ALG_AES_CM		2	/* SRTP default algorithm */
#define SRTP_ENC_ALG_AES_F8		3

/* Authentication algorithms */
#define SRTP_AUTH_ALG_NONE			0	/* no auth tag in SRTP/RTP payload */
#define SRTP_AUTH_ALG_HMAC_SHA1		1	/* SRTP default algorithm */


#if 0	/* these are only needed once the dissector include the crypto functions to decrypt and/or authenticate */
struct srtp_key_info
{
    guint8		*master_key;			/* pointer to an se_alloc'ed master key */
    guint8		*master_salt;			/* pointer to an se_alloc'ed salt for this master key - NULL if no salt */
    guint8		key_generation_rate;	/* encoded as the power of 2, 0..24, or 255 (=zero rate) */
                                        /* Either the MKI value is used (in which case from=to=0), or the <from,to> values are used (and MKI=0) */
    guint32		from_roc;				/* 32 MSBs of a 48 bit value - frame from which this key is valid (roll-over counter part) */
    guint16		from_seq;				/* 16 LSBs of a 48 bit value - frame from which this key is valid (sequence number part) */
    guint32		to_roc;					/* 32 MSBs of a 48 bit value - frame to which this key is valid (roll-over counter part) */
    guint16		to_seq;					/* 16 LSBs of a 48 bit value - frame to which this key is valid (sequence number part) */
    guint32		mki;					/* the MKI value associated with this key */
};
#endif

struct srtp_info
{
    guint      encryption_algorithm;	/* at present only NULL vs non-NULL matter */
    guint      auth_algorithm;			/* at present only NULL vs non-NULL matter */
    guint      mki_len;					/* number of octets used for the MKI in the RTP payload */
    guint      auth_tag_len;			/* number of octets used for the Auth Tag in the RTP payload */
#if 0	/* these are only needed once the dissector include the crypto functions to decrypt and/or authenticate */
    struct srtp_key_info **master_keys; /* an array of pointers to master keys and their info, the array and each key struct being se_alloc'ed  */
    void       *enc_alg_info,			/* algorithm-dependent info struct - may be void for default alg with default params */
    void       *auth_alg_info			/* algorithm-dependent info struct - void for default alg with default params */
#endif
};

/* Info to save in RTP conversation / packet-info */
#define MAX_RTP_SETUP_METHOD_SIZE 7
struct _rtp_conversation_info
{
	gchar   method[MAX_RTP_SETUP_METHOD_SIZE + 1];
	guint32 frame_number;			/* the frame where this conversation is started */
	gboolean is_video;
	GHashTable *rtp_dyn_payload;	/* a hash table with the dynamic RTP payload */

	guint32 extended_seqno;			/* the sequence number, extended to a 32-bit
									 * int to guarantee it increasing monotonically
									 */

	struct _rtp_private_conv_info *rtp_conv_info; /* conversation info private
	                                               * to the rtp dissector
												   */
	struct srtp_info *srtp_info;    /* SRTP context */
};

typedef struct {
	char *encoding_name;
	int   sample_rate;
} encoding_name_and_rate_t;

/* Add an RTP conversation with the given details */
void rtp_add_address(packet_info *pinfo,
                     address *addr, int port,
                     int other_port,
                     const gchar *setup_method, 
                     guint32 setup_frame_number,
					 gboolean is_video,
                     GHashTable *rtp_dyn_payload);

/* Add an SRTP conversation with the given details */
void srtp_add_address(packet_info *pinfo,
                     address *addr, int port,
                     int other_port,
                     const gchar *setup_method, 
                     guint32 setup_frame_number,
					 gboolean is_video,
                     GHashTable *rtp_dyn_payload,
                     struct srtp_info *srtp_info);

/* Free and destroy the dyn_payload hash table */
void rtp_free_hash_dyn_payload(GHashTable *rtp_dyn_payload);

