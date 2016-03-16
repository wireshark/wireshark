/* packet-gssapi.c
 * Dissector for GSS-API tokens as described in rfc2078, section 3.1
 * Copyright 2002, Tim Potter <tpot@samba.org>
 * Copyright 2002, Richard Sharpe <rsharpe@samba.org> Added a few
 *		   bits and pieces ...
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

#include "config.h"


#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/show_exception.h>
#include <epan/proto_data.h>

#include "packet-ber.h"
#include "packet-dcerpc.h"
#include "packet-gssapi.h"

void proto_register_gssapi(void);
void proto_reg_handoff_gssapi(void);

static int proto_gssapi = -1;

static int hf_gssapi_token_object = -1;
static int hf_gssapi_auth_verifier = -1;
static int hf_gssapi_auth_credentials = -1;
static int hf_gssapi_oid = -1;
static int hf_gssapi_segments = -1;
static int hf_gssapi_segment = -1;
static int hf_gssapi_segment_overlap = -1;
static int hf_gssapi_segment_overlap_conflict = -1;
static int hf_gssapi_segment_multiple_tails = -1;
static int hf_gssapi_segment_too_long_fragment = -1;
static int hf_gssapi_segment_error = -1;
static int hf_gssapi_segment_count = -1;
static int hf_gssapi_reassembled_in = -1;
static int hf_gssapi_reassembled_length = -1;

static gint ett_gssapi = -1;
static gint ett_gssapi_segment = -1;
static gint ett_gssapi_segments = -1;

static expert_field ei_gssapi_unknown_header = EI_INIT;

static gboolean gssapi_reassembly = TRUE;

typedef struct _gssapi_conv_info_t {
	gssapi_oid_value *oid;

	wmem_tree_t *frags;

	gboolean do_reassembly;  /* this field is used on first sequential scan of packets to help indicate when the next blob is a fragment continuing a previous one */
	int first_frame;
	int frag_offset;
} gssapi_conv_info_t;

typedef struct _gssapi_frag_info_t {
	guint32 first_frame;
	guint32 reassembled_in;
} gssapi_frag_info_t;

static const fragment_items gssapi_frag_items = {
	&ett_gssapi_segment,
	&ett_gssapi_segments,

	&hf_gssapi_segments,
	&hf_gssapi_segment,
	&hf_gssapi_segment_overlap,
	&hf_gssapi_segment_overlap_conflict,
	&hf_gssapi_segment_multiple_tails,
	&hf_gssapi_segment_too_long_fragment,
	&hf_gssapi_segment_error,
	&hf_gssapi_segment_count,
	NULL,
	&hf_gssapi_reassembled_length,
	/* Reassembled data field */
	NULL,
	"fragments"
};


static reassembly_table gssapi_reassembly_table;

static void
gssapi_reassembly_init(void)
{
	reassembly_table_init(&gssapi_reassembly_table,
	                      &addresses_reassembly_table_functions);
}

static void
gssapi_reassembly_cleanup(void)
{
	reassembly_table_destroy(&gssapi_reassembly_table);
}

/*
 * Subdissectors
 */

static dissector_handle_t ntlmssp_handle;
static dissector_handle_t ntlmssp_payload_handle;
static dissector_handle_t ntlmssp_verf_handle;
static dissector_handle_t ntlmssp_data_only_handle;
static dissector_handle_t spnego_krb5_wrap_handle;

static GHashTable *gssapi_oids;

static gint
gssapi_oid_equal(gconstpointer k1, gconstpointer k2)
{
	const char *key1 = (const char *)k1;
	const char *key2 = (const char *)k2;

	return strcmp(key1, key2) == 0;
}

static guint
gssapi_oid_hash(gconstpointer k)
{
	const char *key = (const char *)k;
	guint hash = 0, i;

	for (i = 0; key[i]; i++)
		hash += key[i];

	return hash;
}

void
gssapi_init_oid(const char *oid, int proto, int ett, dissector_handle_t handle,
		dissector_handle_t wrap_handle, const gchar *comment)
{
	char *key = g_strdup(oid);
	gssapi_oid_value *value = (gssapi_oid_value *)g_malloc(sizeof(*value));

	value->proto = find_protocol_by_id(proto);
	value->ett = ett;
	value->handle = handle;
	value->wrap_handle = wrap_handle;
	value->comment = comment;

	g_hash_table_insert(gssapi_oids, key, value);
	register_ber_oid_dissector_handle(key, handle, proto, comment);
}

/*
 * This takes an OID in text string form as
 * an argument.
 */
gssapi_oid_value *
gssapi_lookup_oid_str(const char *oid_key)
{
	gssapi_oid_value *value;
	if(!oid_key){
		return NULL;
	}
	value = (gssapi_oid_value *)g_hash_table_lookup(gssapi_oids, oid_key);
	return value;
}

static int
dissect_gssapi_work(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		    gboolean is_verifier, gssapi_encrypt_info_t* encrypt_info)
{
	proto_item *volatile item;
	proto_tree *volatile subtree;
	volatile int return_offset = 0;
	gssapi_conv_info_t *volatile gss_info;
	gssapi_oid_value *oidvalue;
	dissector_handle_t handle;
	conversation_t *conversation;
	tvbuff_t *oid_tvb;
	int len, start_offset, oid_start_offset;
	volatile int offset;
	gint8 appclass;
	gboolean pc, ind_field;
	gint32 tag;
	guint32 len1;
	const char *oid;
	fragment_head *fd_head=NULL;
	gssapi_frag_info_t *fi;
	tvbuff_t *volatile gss_tvb=NULL;
	asn1_ctx_t asn1_ctx;

	start_offset=0;
	offset=0;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
	/*
	 * We don't know whether the data is encrypted, so say it's
	 * not, for now.  The subdissector must set gssapi_data_encrypted
	 * if it is.
	 */
	encrypt_info->gssapi_data_encrypted = FALSE;


	/*
	 * We need a conversation for later
	 */
	conversation = find_or_create_conversation(pinfo);

	gss_info = (gssapi_conv_info_t *)conversation_get_proto_data(conversation, proto_gssapi);
	if (!gss_info) {
		gss_info = wmem_new(wmem_file_scope(), gssapi_conv_info_t);
		gss_info->oid=NULL;
		gss_info->do_reassembly=FALSE;
		gss_info->frags=wmem_tree_new(wmem_file_scope());

		conversation_add_proto_data(conversation, proto_gssapi, gss_info);
	}

	item = proto_tree_add_item(
		tree, proto_gssapi, tvb, offset, -1, ENC_NA);

	subtree = proto_item_add_subtree(item, ett_gssapi);

	/*
	 * Catch the ReportedBoundsError exception; the stuff we've been
	 * handed doesn't necessarily run to the end of the packet, it's
	 * an item inside a packet, so if it happens to be malformed (or
	 * we, or a dissector we call, has a bug), so that an exception
	 * is thrown, we want to report the error, but return and let
	 * our caller dissect the rest of the packet.
	 *
	 * If it gets a BoundsError, we can stop, as there's nothing more
	 * in the packet after our blob to see, so we just re-throw the
	 * exception.
	 */
	TRY {
		gss_tvb=tvb;


		/* First of all, if it's the first time we see this packet
		 * then check whether we are in the middle of reassembly or not
		 */
		if( (!pinfo->fd->flags.visited)
		&&  (gss_info->do_reassembly)
		&&  (gssapi_reassembly) ){
			fi=(gssapi_frag_info_t *)wmem_tree_lookup32(gss_info->frags, gss_info->first_frame);
			if(!fi){
				goto done;
			}
			wmem_tree_insert32(gss_info->frags, pinfo->num, fi);
			fd_head=fragment_add(&gssapi_reassembly_table,
				tvb, 0, pinfo, fi->first_frame, NULL,
				gss_info->frag_offset,
				tvb_captured_length(tvb), TRUE);
			gss_info->frag_offset+=tvb_captured_length(tvb);

			/* we need more fragments */
			if(!fd_head){
				goto done;
			}

			/* this blob is now fully reassembled */
			gss_info->do_reassembly=FALSE;
			fi->reassembled_in=pinfo->num;

			gss_tvb=tvb_new_chain(tvb, fd_head->tvb_data);
			add_new_data_source(pinfo, gss_tvb, "Reassembled GSSAPI");
		}
		/* We have seen this packet before.
		 * Is this blob part of reassembly or a normal blob ?
		 */
		if( (pinfo->fd->flags.visited)
		&&  (gssapi_reassembly) ){
			fi=(gssapi_frag_info_t *)wmem_tree_lookup32(gss_info->frags, pinfo->num);
			if(fi){
				fd_head=fragment_get(&gssapi_reassembly_table,
					pinfo, fi->first_frame, NULL);
				if(fd_head && (fd_head->flags&FD_DEFRAGMENTED)){
					if(pinfo->num==fi->reassembled_in){
					        proto_item *frag_tree_item;
						gss_tvb=tvb_new_chain(tvb, fd_head->tvb_data);
						add_new_data_source(pinfo, gss_tvb, "Reassembled GSSAPI");
						show_fragment_tree(fd_head, &gssapi_frag_items, tree, pinfo, tvb, &frag_tree_item);
					} else {
						proto_item *it;
						it=proto_tree_add_uint(tree, hf_gssapi_reassembled_in, tvb, 0, 0, fi->reassembled_in);
					        PROTO_ITEM_SET_GENERATED(it);
						goto done;
					}
				}
			}
		}

		/* Read header */
		offset = get_ber_identifier(gss_tvb, offset, &appclass, &pc, &tag);
		offset = get_ber_length(gss_tvb, offset, &len1, &ind_field);


		if (!(appclass == BER_CLASS_APP && pc && tag == 0)) {
		  /* It could be NTLMSSP, with no OID.  This can happen
		     for anything that microsoft calls 'Negotiate' or GSS-SPNEGO */
			if ((tvb_captured_length_remaining(gss_tvb, start_offset)>7) && (tvb_strneql(gss_tvb, start_offset, "NTLMSSP", 7) == 0)) {
				return_offset = call_dissector(ntlmssp_handle,
							tvb_new_subset_remaining(gss_tvb, start_offset),
							pinfo, subtree);
				goto done;
			}
			/* Maybe it's new NTLMSSP payload */
			if ((tvb_captured_length_remaining(gss_tvb, start_offset)>16) &&
			   ((tvb_memeql(gss_tvb, start_offset, "\x01\x00\x00\x00", 4) == 0))) {
				return_offset = call_dissector(ntlmssp_payload_handle,
							tvb_new_subset_remaining(gss_tvb, start_offset),
							pinfo, subtree);
				encrypt_info->gssapi_data_encrypted = TRUE;
				goto done;
			}
			if ((tvb_captured_length_remaining(gss_tvb, start_offset)==16) &&
			   ((tvb_memeql(gss_tvb, start_offset, "\x01\x00\x00\x00", 4) == 0))) {
				if( is_verifier ) {
					return_offset = call_dissector(ntlmssp_verf_handle,
									tvb_new_subset_remaining(gss_tvb, start_offset),
									pinfo, subtree);
				}
				else if( encrypt_info->gssapi_encrypted_tvb ) {
					return_offset = call_dissector_with_data(ntlmssp_data_only_handle,
									tvb_new_subset_remaining(encrypt_info->gssapi_encrypted_tvb, 0),
									pinfo, subtree, &encrypt_info->gssapi_decrypted_tvb);
					encrypt_info->gssapi_data_encrypted = TRUE;
				}
		   		goto done;
		  	}

		  /* Maybe it's new GSSKRB5 CFX Wrapping */
		  if ((tvb_captured_length_remaining(gss_tvb, start_offset)>2) &&
		      ((tvb_memeql(gss_tvb, start_offset, "\04\x04", 2) == 0) ||
		       (tvb_memeql(gss_tvb, start_offset, "\05\x04", 2) == 0))) {
		    return_offset = call_dissector_with_data(spnego_krb5_wrap_handle,
						   tvb_new_subset_remaining(gss_tvb, start_offset),
						   pinfo, subtree, encrypt_info);
		    goto done;
		  }

		  /*
		   * If we do not recognise an Application class,
		   * then we are probably dealing with an inner context
		   * token or a wrap token, and we should retrieve the
		   * gssapi_oid_value pointer from the per-frame data or,
		   * if there is no per-frame data (as would be the case
		   * the first time we dissect this frame), from the
		   * conversation that exists or that we created from
		   * pinfo (and then make it per-frame data).
		   * We need to make it per-frame data as there can be
		   * more than one GSS-API negotiation in a conversation.
		   *
		   * Note! We "cheat". Since we only need the pointer,
		   * we store that as the data.  (That's not really
		   * "cheating" - the per-frame data and per-conversation
		   * data code doesn't care what you supply as a data
		   * pointer; it just treats it as an opaque pointer, it
		   * doesn't dereference it or free what it points to.)
		   */
		  oidvalue = (gssapi_oid_value *)p_get_proto_data(wmem_file_scope(), pinfo, proto_gssapi, 0);
		  if (!oidvalue && !pinfo->fd->flags.visited)
		  {
		    /* No handle attached to this frame, but it's the first */
		    /* pass, so it'd be attached to the conversation. */
		    oidvalue = gss_info->oid;
		    if (gss_info->oid)
		      p_add_proto_data(wmem_file_scope(), pinfo, proto_gssapi, 0, gss_info->oid);
		  }
		  if (!oidvalue)
		  {
			  proto_tree_add_expert_format(subtree, pinfo, &ei_gssapi_unknown_header, gss_tvb, start_offset, 0,
					      "Unknown header (class=%d, pc=%d, tag=%d)",
					      appclass, pc, tag);
		    return_offset = tvb_captured_length(gss_tvb);
		    goto done;
		  } else {
		    tvbuff_t *oid_tvb_local;

		    oid_tvb_local = tvb_new_subset_remaining(gss_tvb, start_offset);
		    if (is_verifier)
			handle = oidvalue->wrap_handle;
		    else
			handle = oidvalue->handle;
		    len = call_dissector_with_data(handle, oid_tvb_local, pinfo, subtree, encrypt_info);
		    if (len == 0)
			return_offset = tvb_captured_length(gss_tvb);
		    else
			return_offset = start_offset + len;
		    goto done; /* We are finished here */
		  }
		}

		/* Read oid */
		oid_start_offset=offset;
		offset=dissect_ber_object_identifier_str(FALSE, &asn1_ctx, subtree, gss_tvb, offset, hf_gssapi_oid, &oid);
		oidvalue = gssapi_lookup_oid_str(oid);


		/* Check if we need reassembly of this blob.
		 * Only try reassembly for OIDs we recognize
		 * and when we have the entire tvb
		 *
		 * SMB will sometimes split one large GSSAPI blob
		 * across multiple SMB/SessionSetup commands.
		 * While we should look at the uid returned in the response
		 * to the first SessionSetup and use that as a key
		 * instead for simplicity we assume there will not be several
		 * such authentication at once on a single tcp session
		 */
		if( (!pinfo->fd->flags.visited)
		&&  (oidvalue)
		&&  (tvb_captured_length(gss_tvb)==tvb_reported_length(gss_tvb))
		&&  (len1>(guint32)tvb_captured_length_remaining(gss_tvb, oid_start_offset))
		&&  (gssapi_reassembly) ){
			fi=wmem_new(wmem_file_scope(), gssapi_frag_info_t);
			fi->first_frame=pinfo->num;
			fi->reassembled_in=0;
			wmem_tree_insert32(gss_info->frags, pinfo->num, fi);

			fragment_add(&gssapi_reassembly_table,
				gss_tvb, 0, pinfo, pinfo->num, NULL,
				0, tvb_captured_length(gss_tvb), TRUE);
			fragment_set_tot_len(&gssapi_reassembly_table,
				pinfo, pinfo->num, NULL, len1+oid_start_offset);

			gss_info->do_reassembly=TRUE;
			gss_info->first_frame=pinfo->num;
			gss_info->frag_offset=tvb_captured_length(gss_tvb);
			goto done;
		}


		/*
		 * Hand off to subdissector.
		 */

		if ((oidvalue == NULL) ||
		    !proto_is_protocol_enabled(oidvalue->proto)) {
			/* No dissector for this oid */
			proto_tree_add_item(subtree, hf_gssapi_token_object, gss_tvb, oid_start_offset, -1, ENC_NA);

			return_offset = tvb_captured_length(gss_tvb);
			goto done;
		}

		/* Save a pointer to the data for the OID for the
		 * GSSAPI protocol for this conversation.
		 */

		/*
		 * Now add the proto data ...
		 * but only if it is not already there.
		 */
		if(!gss_info->oid){
		  gss_info->oid=oidvalue;
		}

		if (is_verifier) {
			handle = oidvalue->wrap_handle;
			if (handle != NULL) {
				oid_tvb = tvb_new_subset_remaining(gss_tvb, offset);
				len = call_dissector_with_data(handle, oid_tvb, pinfo, subtree, encrypt_info);
				if (len == 0)
					return_offset = tvb_captured_length(gss_tvb);
				else
					return_offset = offset + len;
			} else {
				proto_tree_add_item(subtree, hf_gssapi_auth_verifier, gss_tvb, offset, -1, ENC_NA);
				return_offset = tvb_captured_length(gss_tvb);
			}
		} else {
			handle = oidvalue->handle;
			if (handle != NULL) {
				oid_tvb = tvb_new_subset_remaining(gss_tvb, offset);
				len = call_dissector_with_data(handle, oid_tvb, pinfo, subtree, encrypt_info);
				if (len == 0)
					return_offset = tvb_captured_length(gss_tvb);
				else
					return_offset = offset + len;
			} else {
				proto_tree_add_item(subtree, hf_gssapi_auth_credentials, gss_tvb, offset, -1, ENC_NA);
				return_offset = tvb_captured_length(gss_tvb);
			}
		}

	 done:
		;
	} CATCH_NONFATAL_ERRORS {
		/*
		 * Somebody threw an exception that means that there
		 * was a problem dissecting the payload; that means
		 * that a dissector was found, so we don't need to
		 * dissect the payload as data or update the protocol
		 * or info columns.
		 *
		 * Just show the exception and then drive on to show
		 * the trailer, after noting that a dissector was found
		 * and restoring the protocol value that was in effect
		 * before we called the subdissector.
		 */
		show_exception(gss_tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
	} ENDTRY;

	proto_item_set_len(item, return_offset);
	return return_offset;
}

static int
dissect_gssapi_work_wrapper(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gssapi_encrypt_info_t* encrypt_info, gboolean is_verifier)
{
	int ret;
	gssapi_encrypt_info_t pass_encrypt_info;

	/* Ensure a non-null encryption structure */
	if (encrypt_info != NULL)
	{
		pass_encrypt_info = *encrypt_info;
	}
	else
	{
		memset(&pass_encrypt_info, 0, sizeof(pass_encrypt_info));
	}

	ret = dissect_gssapi_work(tvb, pinfo, tree, is_verifier, &pass_encrypt_info);

	/* Restore any changes to provided encryption structure */
	if (encrypt_info != NULL)
	{
		*encrypt_info = pass_encrypt_info;
	}

	return ret;
}

static int
dissect_gssapi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	return dissect_gssapi_work_wrapper(tvb, pinfo, tree, (gssapi_encrypt_info_t*)data, FALSE);
}

static int
dissect_gssapi_verf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	return dissect_gssapi_work_wrapper(tvb, pinfo, tree, (gssapi_encrypt_info_t*)data, TRUE);
}

void
proto_register_gssapi(void)
{
	static hf_register_info hf[] = {
	{ &hf_gssapi_oid,
		{ "OID", "gss-api.OID", FT_STRING, BASE_NONE,
		  NULL, 0, "This is a GSS-API Object Identifier", HFILL }},
	{ &hf_gssapi_token_object,
		{ "Token object", "gss-api.token_object", FT_BYTES, BASE_NONE,
		  NULL, 0, NULL, HFILL }},
	{ &hf_gssapi_auth_verifier,
		{ "Authentication verifier", "gss-api.auth_verifier", FT_BYTES, BASE_NONE,
		  NULL, 0, NULL, HFILL }},
	{ &hf_gssapi_auth_credentials,
		{ "Authentication credentials", "gss-api.auth_credentials", FT_BYTES, BASE_NONE,
		  NULL, 0, NULL, HFILL }},
	{ &hf_gssapi_segment,
		{ "GSSAPI Segment", "gss-api.segment", FT_FRAMENUM, BASE_NONE,
		  NULL, 0x0, NULL, HFILL }},
	{ &hf_gssapi_segments,
		{ "GSSAPI Segments", "gss-api.segment.segments", FT_NONE, BASE_NONE,
		  NULL, 0x0, NULL, HFILL }},
	{ &hf_gssapi_segment_overlap,
		{ "Fragment overlap",	"gss-api.segment.overlap", FT_BOOLEAN, BASE_NONE,
		   NULL, 0x0, "Fragment overlaps with other fragments", HFILL }},
	{ &hf_gssapi_segment_overlap_conflict,
		{ "Conflicting data in fragment overlap",	"gss-api.segment.overlap.conflict", FT_BOOLEAN, BASE_NONE,
		  NULL, 0x0, "Overlapping fragments contained conflicting data", HFILL }},
	{ &hf_gssapi_segment_multiple_tails,
		{ "Multiple tail fragments found",	"gss-api.segment.multipletails", FT_BOOLEAN, BASE_NONE,
		  NULL, 0x0, "Several tails were found when defragmenting the packet", HFILL }},
	{ &hf_gssapi_segment_too_long_fragment,
		{ "Fragment too long",	"gss-api.segment.toolongfragment", FT_BOOLEAN, BASE_NONE,
		  NULL, 0x0, "Fragment contained data past end of packet", HFILL }},
	{ &hf_gssapi_segment_error,
		{ "Defragmentation error", "gss-api.segment.error", FT_FRAMENUM, BASE_NONE,
		  NULL, 0x0, "Defragmentation error due to illegal fragments", HFILL }},
	{ &hf_gssapi_segment_count,
		{ "Fragment count", "gss-api.segment.count", FT_UINT32, BASE_DEC,
		  NULL, 0x0, NULL, HFILL }},
	{ &hf_gssapi_reassembled_in,
		{ "Reassembled In", "gss-api.reassembled_in", FT_FRAMENUM, BASE_NONE,
		  NULL, 0x0, "The frame where this pdu is reassembled", HFILL }},
	{ &hf_gssapi_reassembled_length,
		{ "Reassembled GSSAPI length", "gss-api.reassembled.length", FT_UINT32, BASE_DEC,
		  NULL, 0x0, "The total length of the reassembled payload", HFILL }},
	};

	static gint *ett[] = {
		&ett_gssapi,
		&ett_gssapi_segment,
		&ett_gssapi_segments,
	};

	static ei_register_info ei[] = {
		{ &ei_gssapi_unknown_header, { "gssapi.unknown_header", PI_PROTOCOL, PI_WARN, "Unknown header", EXPFILL }},
	};

	module_t *gssapi_module;
	expert_module_t *expert_gssapi;

	proto_gssapi = proto_register_protocol(
		"GSS-API Generic Security Service Application Program Interface",
		"GSS-API", "gss-api");

	gssapi_module = prefs_register_protocol(proto_gssapi, NULL);
	prefs_register_bool_preference(gssapi_module, "gssapi_reassembly",
		"Reassemble fragmented GSSAPI blobs",
		"Whether or not to try reassembling GSSAPI blobs spanning multiple (SMB/SessionSetup) PDUs",
		&gssapi_reassembly);
	proto_register_field_array(proto_gssapi, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_gssapi = expert_register_protocol(proto_gssapi);
	expert_register_field_array(expert_gssapi, ei, array_length(ei));

	register_dissector("gssapi", dissect_gssapi, proto_gssapi);
	register_dissector("gssapi_verf", dissect_gssapi_verf, proto_gssapi);

	gssapi_oids = g_hash_table_new(gssapi_oid_hash, gssapi_oid_equal);
	register_init_routine(gssapi_reassembly_init);
	register_cleanup_routine(gssapi_reassembly_cleanup);
}

static int
wrap_dissect_gssapi(tvbuff_t *tvb, int offset, packet_info *pinfo,
		    proto_tree *tree, dcerpc_info *di _U_, guint8 *drep _U_)
{
	tvbuff_t *auth_tvb;

	auth_tvb = tvb_new_subset_remaining(tvb, offset);

	dissect_gssapi(auth_tvb, pinfo, tree, NULL);

	return tvb_captured_length_remaining(tvb, offset);
}

int
wrap_dissect_gssapi_verf(tvbuff_t *tvb, int offset, packet_info *pinfo,
			 proto_tree *tree, dcerpc_info *di _U_, guint8 *drep _U_)
{
	tvbuff_t *auth_tvb;

	auth_tvb = tvb_new_subset_remaining(tvb, offset);

	return dissect_gssapi_verf(auth_tvb, pinfo, tree, NULL);
}

tvbuff_t *
wrap_dissect_gssapi_payload(tvbuff_t *data_tvb, tvbuff_t *auth_tvb,
			    int offset _U_, packet_info *pinfo,
			    dcerpc_auth_info *auth_info _U_)
{
	tvbuff_t *result;
	gssapi_encrypt_info_t gssapi_encrypt;

	memset(&gssapi_encrypt, 0x0, sizeof(gssapi_encrypt_info_t));

	/* we need a full auth and a full data tvb or else we can't
	   decrypt anything
	*/
	if((!auth_tvb)||(!data_tvb)){
		return NULL;
	}

	gssapi_encrypt.decrypt_gssapi_tvb=DECRYPT_GSSAPI_DCE;
	gssapi_encrypt.gssapi_encrypted_tvb=data_tvb;

	dissect_gssapi(auth_tvb, pinfo, NULL, &gssapi_encrypt);
	result=gssapi_encrypt.gssapi_decrypted_tvb;

	return result;
}

static dcerpc_auth_subdissector_fns gssapi_auth_fns = {
	wrap_dissect_gssapi,		        /* Bind */
	wrap_dissect_gssapi,	 	        /* Bind ACK */
	wrap_dissect_gssapi,			/* AUTH3 */
	wrap_dissect_gssapi_verf, 		/* Request verifier */
	wrap_dissect_gssapi_verf,		/* Response verifier */
	wrap_dissect_gssapi_payload,		/* Request data */
	wrap_dissect_gssapi_payload             /* Response data */
};

void
proto_reg_handoff_gssapi(void)
{
	dissector_handle_t gssapi_handle;

	ntlmssp_handle = find_dissector_add_dependency("ntlmssp", proto_gssapi);
	ntlmssp_payload_handle = find_dissector_add_dependency("ntlmssp_payload", proto_gssapi);
	ntlmssp_verf_handle = find_dissector_add_dependency("ntlmssp_verf", proto_gssapi);
	ntlmssp_data_only_handle = find_dissector_add_dependency("ntlmssp_data_only", proto_gssapi);
	spnego_krb5_wrap_handle = find_dissector_add_dependency("spnego-krb5-wrap", proto_gssapi);

	register_dcerpc_auth_subdissector(DCE_C_AUTHN_LEVEL_CONNECT,
					  DCE_C_RPC_AUTHN_PROTOCOL_SPNEGO,
					  &gssapi_auth_fns);
	register_dcerpc_auth_subdissector(DCE_C_AUTHN_LEVEL_PKT_INTEGRITY,
					  DCE_C_RPC_AUTHN_PROTOCOL_SPNEGO,
					  &gssapi_auth_fns);
	register_dcerpc_auth_subdissector(DCE_C_AUTHN_LEVEL_PKT_PRIVACY,
					  DCE_C_RPC_AUTHN_PROTOCOL_SPNEGO,
					  &gssapi_auth_fns);

	gssapi_handle = find_dissector("gssapi");
	dissector_add_string("dns.tsig.mac", "gss.microsoft.com", gssapi_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
