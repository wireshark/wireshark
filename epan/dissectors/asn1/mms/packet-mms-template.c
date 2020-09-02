/* packet-mms_asn1.c
 *
 * Ronnie Sahlberg 2005
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/asn1.h>
#include <epan/expert.h>
#include <epan/proto_data.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-mms.h"

#define PNAME  "MMS"
#define PSNAME "MMS"
#define PFNAME "mms"

void proto_register_mms(void);
void proto_reg_handoff_mms(void);

/* Initialize the protocol and registered fields */
static int proto_mms = -1;

#include "packet-mms-hf.c"

/* Initialize the subtree pointers */
static gint ett_mms = -1;
#include "packet-mms-ett.c"

static expert_field ei_mms_mal_timeofday_encoding = EI_INIT;
static expert_field ei_mms_mal_utctime_encoding = EI_INIT;
static expert_field ei_mms_zero_pdu = EI_INIT;

/*****************************************************************************/
/* Packet private data                                                       */
/* For this dissector, all access to actx->private_data should be made       */
/* through this API, which ensures that they will not overwrite each other!! */
/*****************************************************************************/

#define BUFFER_SIZE_PRE 10
#define BUFFER_SIZE_MORE 1024

typedef struct mms_private_data_t
{
	char preCinfo[BUFFER_SIZE_PRE];
	char moreCinfo[BUFFER_SIZE_MORE];
} mms_private_data_t;


/* Helper function to get or create the private data struct */
static
mms_private_data_t* mms_get_private_data(asn1_ctx_t *actx)
{
	packet_info *pinfo = actx->pinfo;
	mms_private_data_t *private_data = (mms_private_data_t *)p_get_proto_data(pinfo->pool, pinfo, proto_mms, pinfo->curr_layer_num);
	if(private_data != NULL )
		return private_data;
	else {
		private_data = wmem_new0(pinfo->pool, mms_private_data_t);
		p_add_proto_data(pinfo->pool, pinfo, proto_mms, pinfo->curr_layer_num, private_data);
		return private_data;
	}
}

/* Helper function to test presence of private data struct */
static gboolean
mms_has_private_data(asn1_ctx_t *actx)
{
	packet_info *pinfo = actx->pinfo;
	return (p_get_proto_data(pinfo->pool, pinfo, proto_mms, pinfo->curr_layer_num) != NULL);
}

static void
private_data_add_preCinfo(asn1_ctx_t *actx, guint32 val)
{
	mms_private_data_t *private_data = (mms_private_data_t*)mms_get_private_data(actx);
	g_snprintf(private_data->preCinfo, BUFFER_SIZE_PRE, "%02d ", val);
}

static char*
private_data_get_preCinfo(asn1_ctx_t *actx)
{
	mms_private_data_t *private_data = (mms_private_data_t*)mms_get_private_data(actx);
	return private_data->preCinfo;
}

static void
private_data_add_moreCinfo_id(asn1_ctx_t *actx, tvbuff_t *tvb)
{
	mms_private_data_t *private_data = (mms_private_data_t*)mms_get_private_data(actx);
	g_strlcat(private_data->moreCinfo, " ", BUFFER_SIZE_MORE);
	g_strlcat(private_data->moreCinfo, tvb_get_string_enc(wmem_packet_scope(),
				tvb, 2, tvb_get_guint8(tvb, 1), ENC_STRING), BUFFER_SIZE_MORE);
}

static void
private_data_add_moreCinfo_float(asn1_ctx_t *actx, tvbuff_t *tvb)
{
	mms_private_data_t *private_data = (mms_private_data_t*)mms_get_private_data(actx);
	g_snprintf(private_data->moreCinfo, BUFFER_SIZE_MORE,
				" %f", tvb_get_ieee_float(tvb, 1, ENC_BIG_ENDIAN));
}

static char*
private_data_get_moreCinfo(asn1_ctx_t *actx)
{
	mms_private_data_t *private_data = (mms_private_data_t*)mms_get_private_data(actx);
	return private_data->moreCinfo;
}

/*****************************************************************************/


#include "packet-mms-fn.c"

/*
* Dissect MMS PDUs inside a PPDU.
*/
static int
dissect_mms(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
	int offset = 0;
	int old_offset;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_mms, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_mms);
	}
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MMS");
	col_clear(pinfo->cinfo, COL_INFO);

	while (tvb_reported_length_remaining(tvb, offset) > 0){
		old_offset=offset;
		offset=dissect_mms_MMSpdu(FALSE, tvb, offset, &asn1_ctx , tree, -1);
		if(offset == old_offset){
			proto_tree_add_expert(tree, pinfo, &ei_mms_zero_pdu, tvb, offset, -1);
			break;
		}
	}
	return tvb_captured_length(tvb);
}


/*--- proto_register_mms -------------------------------------------*/
void proto_register_mms(void) {

	/* List of fields */
	static hf_register_info hf[] =
	{
#include "packet-mms-hfarr.c"
	};

	/* List of subtrees */
	static gint *ett[] = {
		&ett_mms,
#include "packet-mms-ettarr.c"
	};

	static ei_register_info ei[] = {
		{ &ei_mms_mal_timeofday_encoding, { "mms.malformed.timeofday_encoding", PI_MALFORMED, PI_WARN, "BER Error: malformed TimeOfDay encoding", EXPFILL }},
		{ &ei_mms_mal_utctime_encoding, { "mms.malformed.utctime", PI_MALFORMED, PI_WARN, "BER Error: malformed IEC61850 UTCTime encoding", EXPFILL }},
		{ &ei_mms_zero_pdu, { "mms.zero_pdu", PI_PROTOCOL, PI_ERROR, "Internal error, zero-byte MMS PDU", EXPFILL }},
	};

	expert_module_t* expert_mms;

	/* Register protocol */
	proto_mms = proto_register_protocol(PNAME, PSNAME, PFNAME);
	register_dissector("mms", dissect_mms, proto_mms);
	/* Register fields and subtrees */
	proto_register_field_array(proto_mms, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_mms = expert_register_protocol(proto_mms);
	expert_register_field_array(expert_mms, ei, array_length(ei));

}


static gboolean
dissect_mms_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	/* must check that this really is an mms packet */
	int offset = 0;
	guint32 length = 0 ;
	guint32 oct;
	gint idx = 0 ;

	gint8 tmp_class;
	gboolean tmp_pc;
	gint32 tmp_tag;

		/* first, check do we have at least 2 bytes (pdu) */
	if (!tvb_bytes_exist(tvb, 0, 2))
		return FALSE;	/* no */

	/* can we recognize MMS PDU ? Return FALSE if  not */
	/*   get MMS PDU type */
	offset = get_ber_identifier(tvb, offset, &tmp_class, &tmp_pc, &tmp_tag);

	/* check MMS type */

	/* Class should be constructed */
	if (tmp_class!=BER_CLASS_CON)
		return FALSE;

	/* see if the tag is a valid MMS PDU */
	try_val_to_str_idx(tmp_tag, mms_MMSpdu_vals, &idx);
	if  (idx == -1) {
	 	return FALSE;  /* no, it isn't an MMS PDU */
	}

	/* check MMS length  */
	oct = tvb_get_guint8(tvb, offset)& 0x7F;
	if (oct==0)
		/* MMS requires length after tag so not MMS if indefinite length*/
		return FALSE;

	offset = get_ber_length(tvb, offset, &length, NULL);
	/* do we have enough bytes? */
	if (!tvb_bytes_exist(tvb, offset, length))
		return FALSE;

	dissect_mms(tvb, pinfo, parent_tree, data);
	return TRUE;
}

/*--- proto_reg_handoff_mms --- */
void proto_reg_handoff_mms(void) {
	register_ber_oid_dissector("1.0.9506.2.3", dissect_mms, proto_mms,"MMS");
	register_ber_oid_dissector("1.0.9506.2.1", dissect_mms, proto_mms,"mms-abstract-syntax-version1(1)");
	heur_dissector_add("cotp", dissect_mms_heur, "MMS over COTP", "mms_cotp", proto_mms, HEURISTIC_ENABLE);
	heur_dissector_add("cotp_is", dissect_mms_heur, "MMS over COTP (inactive subset)", "mms_cotp_is", proto_mms, HEURISTIC_ENABLE);
}

