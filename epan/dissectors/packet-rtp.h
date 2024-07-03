/* packet-rtp.h
 *
 * Routines for RTP dissection
 * RTP = Real time Transport Protocol
 *
 * Copyright 2000, Philips Electronics N.V.
 * Written by Andreas Sikkema <andreas.sikkema@philips.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_RTP_H__
#define __PACKET_RTP_H__

#include "epan/packet.h"
#include "ws_symbol_export.h"

#include "packet-btavdtp.h"
#include "packet-sdp.h"

#define RTP_MEDIA_AUDIO 1
#define RTP_MEDIA_VIDEO 2
#define RTP_MEDIA_OTHER 4

struct _rtp_info {
	unsigned int  info_version;
	bool          info_padding_set;
	bool          info_marker_set;
	uint32_t      info_media_types;
	unsigned int  info_payload_type;
	uint16_t      info_seq_num;
	uint32_t      info_extended_seq_num;
	uint32_t      info_timestamp;
	uint64_t      info_extended_timestamp;
	uint32_t      info_sync_src;
	unsigned      info_data_len;       /* length of raw rtp data as reported */
	bool          info_all_data_present; /* false if data is cut off */
	unsigned      info_payload_offset; /* start of payload relative to info_data */
	unsigned      info_payload_len;    /* length of payload (not incl padding) */
	bool          info_is_srtp;
	uint32_t      info_setup_frame_num; /* the frame num of the packet that set this RTP connection */
	const uint8_t* info_data;           /* pointer to raw rtp data */
	const char    *info_payload_type_str;
	int           info_payload_rate;
	unsigned      info_payload_channels;
	wmem_map_t    *info_payload_fmtp_map;
	bool          info_is_ed137;
	const char    *info_ed137_info;    /* pointer to static string, no freeing is required */
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
/* https://www.iana.org/assignments/srtp-protection/srtp-protection.xhtml */

/* Encryption algorithms */
#define SRTP_ENC_ALG_NOT_SET	0	/* Data not available/empty record */
#define SRTP_ENC_ALG_NULL		1	/* non-encrypted SRTP payload - may still be authenticated */
#define SRTP_ENC_ALG_AES_CM		2	/* SRTP default algorithm */
#define SRTP_ENC_ALG_AES_F8		3
#define SRTP_ENC_ALG_AES_GCM            4       /* RFC 7714 */

/* Authentication algorithms */
#define SRTP_AUTH_ALG_NONE			0	/* no auth tag in SRTP/RTP payload */
#define SRTP_AUTH_ALG_HMAC_SHA1		1	/* SRTP default algorithm */
#define SRTP_AUTH_ALG_GMAC		2	/* RFC 7714 */


#if 0	/* these are only needed once the dissector include the crypto functions to decrypt and/or authenticate */
struct srtp_key_info
{
    uint8_t		*master_key;			/* pointer to an wmem_file_scope'ed master key */
    uint8_t		*master_salt;			/* pointer to an wmem_file_scope'ed salt for this master key - NULL if no salt */
    uint8_t		key_generation_rate;	/* encoded as the power of 2, 0..24, or 255 (=zero rate) */
                                        /* Either the MKI value is used (in which case from=to=0), or the <from,to> values are used (and MKI=0) */
    uint32_t		from_roc;				/* 32 MSBs of a 48 bit value - frame from which this key is valid (roll-over counter part) */
    uint16_t		from_seq;				/* 16 LSBs of a 48 bit value - frame from which this key is valid (sequence number part) */
    uint32_t		to_roc;					/* 32 MSBs of a 48 bit value - frame to which this key is valid (roll-over counter part) */
    uint16_t		to_seq;					/* 16 LSBs of a 48 bit value - frame to which this key is valid (sequence number part) */
    uint32_t		mki;					/* the MKI value associated with this key */
};
#endif

struct srtp_info
{
    unsigned   encryption_algorithm;	/* at present only NULL vs non-NULL matter */
    unsigned   auth_algorithm;			/* at present only NULL vs non-NULL matter */
    unsigned   mki_len;					/* number of octets used for the MKI in the RTP payload */
    unsigned   auth_tag_len;			/* number of octets used for the Auth Tag in the RTP payload */
#if 0	/* these are only needed once the dissector include the crypto functions to decrypt and/or authenticate */
    struct srtp_key_info **master_keys; /* an array of pointers to master keys and their info, the array and each key struct being wmem_file_scope'ed  */
    void       *enc_alg_info,			/* algorithm-dependent info struct - may be void for default alg with default params */
    void       *auth_alg_info			/* algorithm-dependent info struct - void for default alg with default params */
#endif
};

/* an opaque object holding the hash table - use accessor functions to create/destroy/find */
typedef struct _rtp_dyn_payload_t rtp_dyn_payload_t;

/* RTP dynamic payload handling - use the following to create, insert, lookup, and free the
   dynamic payload information. Internally, RTP creates the GHashTable with a wmem file scope
   and increments the ref_count when it saves the info to conversations later. The calling
   dissector (SDP, H.245, etc.) uses these functions as an interface. If the calling dissector
   is done with the rtp_dyn_payload_t* for good, it should call rtp_dyn_payload_free() which
   will decrement the ref_count and free's it if the ref_count is 0. In the worst case, it
   will get free'd when the wmem file scope is over.

   This was changed because there were too many bugs with SDP's handling of memory ownership
   of the GHashTable, with RTP freeing things SDP didn't think were free'ed. And also because
   the GHashTables never got free'd in many cases by several dissectors.
 */

/* creates a new hashtable and sets ref_count to 1, returning the newly created object */
WS_DLL_PUBLIC
rtp_dyn_payload_t* rtp_dyn_payload_new(void);

/* Creates a copy of the given dynamic payload information. */
rtp_dyn_payload_t* rtp_dyn_payload_dup(rtp_dyn_payload_t *rtp_dyn_payload);

/* Inserts the given payload type key, for the encoding name, sample rate and
   audio channels, into the hash table. Copy all the format parameters in the
   map given into the format parameter map for the new entry.
   This makes copies of the encoding name and the format parameters, scoped to
   the life of the capture file or sooner if rtp_dyn_payload_free is called.

   @param rtp_dyn_payload The hashtable of dynamic payload information
   @param pt The RTP dynamic payload type number to insert
   @param encoding_name The encoding name to assign to the payload type
   @param sample_rate The sample rate to assign to the payload type
   @param channels The number of audio channels to assign to the payload type (unnecessary for video)
   @param fmtp_map A map of format parameters to add to the new entry (can be NULL)
 */
WS_DLL_PUBLIC
void rtp_dyn_payload_insert_full(rtp_dyn_payload_t *rtp_dyn_payload,
							const unsigned pt,
							const char* encoding_name,
							const int sample_rate,
							const unsigned channels,
							wmem_map_t* fmtp_map);

/* Inserts the given payload type key, for the encoding name, sample rate, and
   channels, into the hash table.
   This makes copies of the encoding name, scoped to the life of the capture
   file or sooner if rtp_dyn_payload_free is called.

   @param rtp_dyn_payload The hashtable of dynamic payload information
   @param pt The RTP dynamic payload type number to insert
   @param encoding_name The encoding name to assign to the payload type
   @param sample_rate The sample rate to assign to the payload type
   @param channels The number of audio channels to assign to the payload type (unnecessary for video)
 */
WS_DLL_PUBLIC
void rtp_dyn_payload_insert(rtp_dyn_payload_t *rtp_dyn_payload,
							const unsigned pt,
							const char* encoding_name,
							const int sample_rate,
							const unsigned channels);

/*
 * Adds the given format parameter to the fmtp_map for the given payload type
 * in the RTP dynamic payload hashtable, if that payload type has been
 * inserted with rtp_dyn_payload_insert. The format parameter name and value
 * are copied, with scope the lifetime of the capture file.
 *
 * @param rtp_dyn_payload The hashtable of dynamic payload information
 * @param pt The RTP payload type number the parameter is for
 * @param name The name of the format parameter to add
 * @param value The value of the format parameter to add
 */
WS_DLL_PUBLIC
void rtp_dyn_payload_add_fmtp(rtp_dyn_payload_t *rtp_dyn_payload,
				const unsigned pt,
				const char* name,
				const char* value);

/* Replaces the given payload type key in the hash table, with the encoding name and sample rate.
   This makes copies of the encoding name, scoped to the life of the capture file or sooner if
   rtp_dyn_payload_free is called. The replaced encoding name is free'd immediately. */
/* Not used anymore
WS_DLL_PUBLIC
void rtp_dyn_payload_replace(rtp_dyn_payload_t *rtp_dyn_payload,
							const unsigned pt,
							const char* encoding_name,
							const int sample_rate);
*/

/* removes the given payload type */
/* Not used anymore
WS_DLL_PUBLIC
bool rtp_dyn_payload_remove(rtp_dyn_payload_t *rtp_dyn_payload, const unsigned pt);
*/

/* retrieves the encoding name for the given payload type; the string returned is only valid
   until the entry is replaced, removed, or the hash table is destroyed, so duplicate it if
   you need it long. */
WS_DLL_PUBLIC
const char* rtp_dyn_payload_get_name(rtp_dyn_payload_t *rtp_dyn_payload, const unsigned pt);

/*
   Retrieves the encoding name, sample rate, and format parameters map for the
   given payload type. The encoding string pointed to is only valid until
   the entry is replaced, removed, or the hash table is destroyed, so duplicate
   it if you need it long. Each of the three output parameters are optional and
   can be NULL.

   @param rtp_dyn_payload The hashtable of dynamic payload information
   @param pt The RTP payload type number to look up
   @param[out] encoding_name The encoding name assigned to that payload type
   @param[out] sample_rate The sample rate assigned to that payload type
   @param[out] channels The number of audio channels for that payload type
   @param[out] fmtp_map The map of format parameters assigned to that type
   @return true if successful, false if there is no entry for that payload type
*/
WS_DLL_PUBLIC
bool rtp_dyn_payload_get_full(rtp_dyn_payload_t *rtp_dyn_payload, const unsigned pt,
								  const char **encoding_name, int *sample_rate, unsigned *channels, wmem_map_t **fmtp_map);

/* Free's and destroys the dyn_payload hash table; internally this decrements the ref_count
   and only free's it if the ref_count == 0. */
WS_DLL_PUBLIC
void rtp_dyn_payload_free(rtp_dyn_payload_t *rtp_dyn_payload);


#ifdef DEBUG_CONVERSATION
/* used for printing out debugging info, if DEBUG_CONVERSATION is defined */
void rtp_dump_dyn_payload(rtp_dyn_payload_t *rtp_dyn_payload);
#endif

/* Proto data key values */
#define RTP_CONVERSATION_PROTO_DATA     0
#define RTP_DECODE_AS_PROTO_DATA        1

#define MAX_RTP_SETUP_METHOD_SIZE 11
/** Info to save in RTP packet-info */
/** XXX: This is wasteful of memory. The only things that really need
 * to be saved per-packet, as opposed to once per conversation, are the
 * extended seqno and timestamp.
 */
struct _rtp_packet_info
{
    char    method[MAX_RTP_SETUP_METHOD_SIZE + 1];
    uint32_t frame_number;                           /**> the frame where this conversation is started */
    uint32_t media_types;
    rtp_dyn_payload_t *rtp_dyn_payload;             /**> the dynamic RTP payload info - see comments above */

    uint32_t extended_seqno;                         /**> the sequence number, extended to a 32-bit
                                                     * int to guarantee it increasing monotonically
                                                     */
    uint64_t extended_timestamp;                     /**> timestamp extended to 64-bit */
    struct _rtp_private_conv_info *rtp_conv_info;   /**> conversation info private
                                                     * to the rtp dissector
                                                     */
    struct srtp_info *srtp_info;                    /* SRTP context */
    bta2dp_codec_info_t *bta2dp_info;
    btvdp_codec_info_t *btvdp_info;
    wmem_array_t *rtp_sdp_setup_info_list;           /**> List with data from all SDP occurences for this stream holding a call ID)*/
};

/* Add an RTP conversation with the given details */
WS_DLL_PUBLIC
void rtp_add_address(packet_info *pinfo,
                     const port_type ptype,
                     address *addr, int port,
                     int other_port,
                     const char *setup_method,
                     uint32_t setup_frame_number,
                     uint32_t media_types,
                     rtp_dyn_payload_t *rtp_dyn_payload);

/* Add an SRTP conversation with the given details */
WS_DLL_PUBLIC
void srtp_add_address(packet_info *pinfo,
                     const port_type ptype,
                     address *addr, int port,
                     int other_port,
                     const char *setup_method,
                     uint32_t setup_frame_number,
                     uint32_t media_types,
                     rtp_dyn_payload_t *rtp_dyn_payload,
                     struct srtp_info *srtp_info,
                     sdp_setup_info_t *setup_info);

/* Add an Bluetooth conversation with the given details */
void
bluetooth_add_address(packet_info *pinfo, address *addr, uint32_t stream_number,
         const char *setup_method, uint32_t setup_frame_number,
         uint32_t media_types, void *data);

/* Dissect the header only, without side effects */
WS_DLL_PUBLIC
int dissect_rtp_shim_header(tvbuff_t *tvb, int start,
                             packet_info *pinfo, proto_tree *tree,
                             struct _rtp_info *rtp_info);

struct _rtp_pkt_info {
    unsigned payload_len;
    uint8_t padding_len; /* without padding count byte */
};

#endif /*__PACKET_RTP_H__*/
