/* packet-nbap-template.c
 * Routines for UMTS Node B Application Part(NBAP) packet dissection
 * Copyright 2005, 2009 Anders Broman <anders.broman@ericsson.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Ref: 3GPP TS 25.433 version 6.6.0 Release 6
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/sctpppids.h>
#include <epan/asn1.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/uat.h>

#include "packet-per.h"
#include "packet-isup.h"
#include "packet-umts_fp.h"
#include "packet-umts_mac.h"
#include "packet-rrc.h"
#include "packet-rlc.h"
#include "packet-nbap.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "UTRAN Iub interface NBAP signalling"
#define PSNAME "NBAP"
#define PFNAME "nbap"


#define NBAP_IGNORE_PORT 255

/* Debug */
#if 0
#define nbap_debug0(str) g_warning(str)
#define nbap_debug1(str,p1) g_warning(str,p1)
#define nbap_debug2(str,p1,p2) g_warning(str,p1,p2)
#define nbap_debug3(str,p1,p2,p3) g_warning(str,p1,p2,p3)
#else
#define nbap_debug0(str)
#define nbap_debug1(str,p1)
#define nbap_debug2(str,p1,p2)
#define nbap_debug3(str,p1,p2,p3)
#endif

/* Global variables */
dissector_handle_t fp_handle;
static guint32	transportLayerAddress_ipv4;
static guint16	BindingID_port;
static guint32	com_context_id;
static int cfn;

#include "packet-nbap-val.h"

/* Initialize the protocol and registered fields */
static int proto_nbap = -1;
static int hf_nbap_transportLayerAddress_ipv4 = -1;
static int hf_nbap_transportLayerAddress_ipv6 = -1;
static int hf_nbap_transportLayerAddress_nsap = -1;

#include "packet-nbap-hf.c"

/* Initialize the subtree pointers */
static int ett_nbap = -1;
static int ett_nbap_TransportLayerAddress = -1;
static int ett_nbap_TransportLayerAddress_nsap = -1;
static int ett_nbap_ib_sg_data = -1;

#include "packet-nbap-ett.c"


extern int proto_fp;

/*
 * Structure to build information needed to dissect the FP flow beeing set up.
 */
struct _nbap_msg_info_for_fp
{
	guint32 ProcedureCode;
	guint32 ddMode;
	gboolean is_uplink;
	gint channel;                       /* see definitions in packet-umts_fp.h Channel types */
	guint8  dch_crc_present;            /* 0=No, 1=Yes, 2=Unknown */
};

typedef struct
{
	gint num_dch_in_flow;
	gint next_dch;
	gint num_ul_chans;
	gint ul_chan_tf_size[MAX_FP_CHANS];
	gint ul_chan_num_tbs[MAX_FP_CHANS];
	gint num_dl_chans;
	gint dl_chan_tf_size[MAX_FP_CHANS];
	gint dl_chan_num_tbs[MAX_FP_CHANS];

}nbap_dch_channel_info_t;

nbap_dch_channel_info_t nbap_dch_chnl_info[maxNrOfDCHs];

/* Struct to collect E-DCH data in a packet
 * As the address data comes before the ddi entries
 * we save the address to be able to find the conversation and update the
 * conversation data.
 */
typedef struct
{
	address 	crnc_address;
	guint16		crnc_port;
	gint		no_ddi_entries;
	guint8		edch_ddi[MAX_EDCH_DDIS];
	guint		edch_macd_pdu_size[MAX_EDCH_DDIS];
	guint8		edch_type;  /* 1 means T2 */
	guint8		lchId[MAX_EDCH_DDIS];	/*Logical channel ids.*/

} nbap_edch_channel_info_t;

nbap_edch_channel_info_t nbap_edch_channel_info[maxNrOfEDCHMACdFlows];


typedef struct
{
	guint32 	crnc_address;
	guint16		crnc_port[maxNrOfEDCHMACdFlows];

} nbap_edch_port_info_t;

nbap_edch_port_info_t * nbap_edch_port_info;

typedef struct
{
	address 			crnc_address;
	guint16				crnc_port;
	enum fp_rlc_mode	rlc_mode;
	guint32				hsdsch_physical_layer_category;
	guint8				entity;	/* "ns" means type 1 and "ehs" means type 2, type 3 == ?*/
} nbap_hsdsch_channel_info_t;

nbap_hsdsch_channel_info_t nbap_hsdsch_channel_info[maxNrOfMACdFlows];

typedef struct
{
	address 			crnc_address;
	guint16				crnc_port;
	enum fp_rlc_mode	rlc_mode;

} nbap_common_channel_info_t;

nbap_common_channel_info_t nbap_common_channel_info[maxNrOfMACdFlows];	/*TODO: Fix this!*/

gint g_num_dch_in_flow;
/* maxNrOfTFs					INTEGER ::= 32 */
gint g_dchs_in_flow_list[maxNrOfTFs];

gint hsdsch_macdflow_ids[maxNrOfMACdFlows];

gint hrnti;

guint node_b_com_context_id;

static GTree * edch_flow_port_map = NULL;

/*Stuff for mapping NodeB-Comuncation Context ID to CRNC Communication Context ID*/
typedef struct com_ctxt_{
		/*guint	nodeb_context;*/
		guint	crnc_context;
		guint	frame_num;
}nbap_com_context_id;
gboolean crcn_context_present = FALSE;
static GTree * com_context_map;

struct _nbap_msg_info_for_fp g_nbap_msg_info_for_fp;

/* Global variables */
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;
static guint32 ddMode;
static const gchar *ProcedureID;
static guint32 t_dch_id, dch_id, prev_dch_id, commonphysicalchannelid, e_dch_macdflow_id, hsdsch_macdflow_id=3,
	   e_dch_ddi_value,logical_channel_id,common_macdflow_id;
static guint32 MACdPDU_Size, commontransportchannelid;
static guint num_items;
static gint paging_indications;
static guint32 ib_type, segment_type;

enum TransportFormatSet_type_enum
{
	NBAP_DCH_UL,
	NBAP_DCH_DL,
	NBAP_CPCH,
	NBAP_FACH,
	NBAP_PCH
};

enum TransportFormatSet_type_enum transportFormatSet_type;

/* This table is used externally from FP, MAC and such, TODO: merge this with
 * lch_contents[] */
guint8 lchId_type_table[]= {
	MAC_CONTENT_UNKNOWN,	/*Should't happen*/
	MAC_CONTENT_DCCH,		/* 1 to 4 SRB => DCCH*/
	MAC_CONTENT_DCCH,
	MAC_CONTENT_DCCH,
	MAC_CONTENT_DCCH,
	MAC_CONTENT_CS_DTCH,	/* 5 to 7 Conv CS speech => ?*/
	MAC_CONTENT_CS_DTCH,
	MAC_CONTENT_CS_DTCH,
	MAC_CONTENT_DCCH,		/* 8 SRB => DCCH*/
	MAC_CONTENT_PS_DTCH,	/* 9 maps to DTCH*/
	MAC_CONTENT_UNKNOWN,	/* 10 Conv CS unknown*/
	MAC_CONTENT_PS_DTCH,	/* 11 Interactive PS => DTCH*/
	MAC_CONTENT_PS_DTCH,	/* 12 Streaming PS => DTCH*/
	MAC_CONTENT_CS_DTCH,	/* 13 Streaming CS*/
	MAC_CONTENT_PS_DTCH,	/* 14 Interatictive PS => DTCH*/
	MAC_CONTENT_CCCH		/* This is CCCH? */
};
/* Preference variables */
static int lch1_content = MAC_CONTENT_DCCH;
static int lch2_content = MAC_CONTENT_DCCH;
static int lch3_content = MAC_CONTENT_DCCH;
static int lch4_content = MAC_CONTENT_DCCH;
static int lch5_content = MAC_CONTENT_CS_DTCH;
static int lch6_content = MAC_CONTENT_CS_DTCH;
static int lch7_content = MAC_CONTENT_CS_DTCH;
static int lch8_content = MAC_CONTENT_DCCH;
static int lch9_content = MAC_CONTENT_PS_DTCH;
static int lch10_content = MAC_CONTENT_UNKNOWN;
static int lch11_content = MAC_CONTENT_PS_DTCH;
static int lch12_content = MAC_CONTENT_PS_DTCH;
static int lch13_content = MAC_CONTENT_CS_DTCH;
static int lch14_content = MAC_CONTENT_PS_DTCH;
static int lch15_content = MAC_CONTENT_CCCH;
static int lch16_content = MAC_CONTENT_DCCH;
/* Array with preference variables for easy looping, TODO: merge this with
 * lchId_type_table[] */
static int * lch_contents[] = {&lch1_content, &lch2_content, &lch3_content,
	&lch4_content, &lch5_content, &lch6_content, &lch7_content, &lch8_content,
	&lch9_content, &lch10_content, &lch11_content, &lch12_content, &lch13_content,
	&lch14_content, &lch15_content, &lch16_content};
static const enum_val_t content_types[] = {
	{"MAC_CONTENT_UNKNOWN", "MAC_CONTENT_UNKNOWN", MAC_CONTENT_UNKNOWN},
	{"MAC_CONTENT_DCCH", "MAC_CONTENT_DCCH", MAC_CONTENT_DCCH},
	{"MAC_CONTENT_PS_DTCH", "MAC_CONTENT_PS_DTCH", MAC_CONTENT_PS_DTCH},
	{"MAC_CONTENT_CS_DTCH", "MAC_CONTENT_CS_DTCH", MAC_CONTENT_CS_DTCH},
	{"MAC_CONTENT_CCCH", "MAC_CONTENT_CCCH", MAC_CONTENT_CCCH},
	{NULL, NULL, -1}};
typedef struct {
	const char *name;
	const char *title;
	const char *description;
} preference_strings;
/* This is used when registering preferences, name, title, description */
static const preference_strings ch_strings[] = {
	{"lch1_content", "Logical Channel 1 Content", "foo"},
	{"lch2_content", "Logical Channel 2 Content", "foo"},
	{"lch3_content", "Logical Channel 3 Content", "foo"},
	{"lch4_content", "Logical Channel 4 Content", "foo"},
	{"lch5_content", "Logical Channel 5 Content", "foo"},
	{"lch6_content", "Logical Channel 6 Content", "foo"},
	{"lch7_content", "Logical Channel 7 Content", "foo"},
	{"lch8_content", "Logical Channel 8 Content", "foo"},
	{"lch9_content", "Logical Channel 9 Content", "foo"},
	{"lch10_content", "Logical Channel 10 Content", "foo"},
	{"lch11_content", "Logical Channel 11 Content", "foo"},
	{"lch12_content", "Logical Channel 12 Content", "foo"},
	{"lch13_content", "Logical Channel 13 Content", "foo"},
	{"lch14_content", "Logical Channel 14 Content", "foo"},
	{"lch15_content", "Logical Channel 15 Content", "foo"},
	{"lch16_content", "Logical Channel 16 Content", "foo"}};

/* Dissector tables */
static dissector_table_t nbap_ies_dissector_table;
static dissector_table_t nbap_extension_dissector_table;
static dissector_table_t nbap_proc_imsg_dissector_table;
static dissector_table_t nbap_proc_sout_dissector_table;
static dissector_table_t nbap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

/*Easy way to add hsdhsch binds for corner cases*/
static void add_hsdsch_bind(packet_info * pinfo, proto_tree * tree);

#include "packet-nbap-fn.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(nbap_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, FALSE, NULL)) ? tvb_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(nbap_extension_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, FALSE, NULL)) ? tvb_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  if (!ProcedureID) return 0;
  return (dissector_try_string(nbap_proc_imsg_dissector_table, ProcedureID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  if (!ProcedureID) return 0;
  return (dissector_try_string(nbap_proc_sout_dissector_table, ProcedureID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  if (!ProcedureID) return 0;
  return (dissector_try_string(nbap_proc_uout_dissector_table, ProcedureID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}
static void add_hsdsch_bind(packet_info *pinfo, proto_tree * tree){
	address 	null_addr;
	conversation_t *conversation = NULL;
	umts_fp_conversation_info_t *umts_fp_conversation_info;
	guint32 i;

	if (pinfo->fd->flags.visited){
		return;
	}

	/* Set port to zero use that as an indication of wether we have data or not */
	SET_ADDRESS(&null_addr, AT_NONE, 0, NULL);
	for (i = 0; i < maxNrOfMACdFlows; i++) {
		if (nbap_hsdsch_channel_info[i].crnc_port != 0){
			conversation = find_conversation(pinfo->fd->num, &(nbap_hsdsch_channel_info[i].crnc_address), &null_addr,
                               PT_UDP,
                               nbap_hsdsch_channel_info[i].crnc_port, 0, NO_ADDR_B);


			if (conversation == NULL) {
				/* It's not part of any conversation - create a new one. */
				conversation = conversation_new(pinfo->fd->num, &(nbap_hsdsch_channel_info[i].crnc_address),
					&null_addr, PT_UDP, nbap_hsdsch_channel_info[i].crnc_port,
					0, NO_ADDR2|NO_PORT2);

				/* Set dissector */
				conversation_set_dissector(conversation, fp_handle);

				if(pinfo->link_dir==P2P_DIR_DL){
					umts_fp_conversation_info = se_new0(umts_fp_conversation_info_t);
					/* Fill in the HSDSCH relevant data */

					umts_fp_conversation_info->iface_type        = IuB_Interface;
					umts_fp_conversation_info->division          = Division_FDD;
					umts_fp_conversation_info->channel           = CHANNEL_HSDSCH;
					umts_fp_conversation_info->dl_frame_number   = 0;
					umts_fp_conversation_info->ul_frame_number   = pinfo->fd->num;
					SE_COPY_ADDRESS(&(umts_fp_conversation_info->crnc_address), &nbap_hsdsch_channel_info[i].crnc_address);
					umts_fp_conversation_info->crnc_port         = nbap_hsdsch_channel_info[i].crnc_port;

					/*Added june 3, normally just the iterator variable*/
					umts_fp_conversation_info->hsdsch_macdflow_id = i ; /*hsdsch_macdflow_ids[i];*/ /* hsdsch_macdflow_id;*/

					/* Cheat and use the DCH entries */
					umts_fp_conversation_info->num_dch_in_flow++;
					umts_fp_conversation_info->dchs_in_flow_list[umts_fp_conversation_info->num_dch_in_flow -1] = i;

					/*XXX: Is this craziness, what is physical_layer? */
					if(nbap_hsdsch_channel_info[i].entity == entity_not_specified ){
						/*Error*/
						expert_add_info_format(pinfo, tree, PI_MALFORMED,PI_ERROR, "HSDSCH Entity not specified!");
					}else{
						umts_fp_conversation_info->hsdsch_entity = nbap_hsdsch_channel_info[i].entity;
					}
					umts_fp_conversation_info->rlc_mode = nbap_hsdsch_channel_info[i].rlc_mode;
					set_umts_fp_conv_data(conversation, umts_fp_conversation_info);
				}
			}
		}
	}

}
static gint nbap_key_cmp(gconstpointer a_ptr, gconstpointer b_ptr, gpointer ignore _U_){
	if( GPOINTER_TO_INT(a_ptr) > GPOINTER_TO_INT(b_ptr) ){
		return  -1;
	}
	return GPOINTER_TO_INT(a_ptr) < GPOINTER_TO_INT(b_ptr);
}
/*static void nbap_free_key(gpointer key ){
			g_free(key);

	}*/
static void nbap_free_value(gpointer value ){
			g_free(value);
	}

static void nbap_init(void){
	guint8 i;
	/*Cleanup*/
	if(com_context_map){
		g_tree_destroy(com_context_map);
	}
/*	if(edch_flow_port_map){
		g_tree_destroy(edch_flow_port_map);
	}*/
	/*Initialize*/
	com_context_map = g_tree_new_full(nbap_key_cmp,
                       NULL,      /* data pointer, optional */
                       NULL,
                       nbap_free_value);
                       
                       
                           /*Initialize structure for muxed flow indication*/
    edch_flow_port_map = g_tree_new_full(nbap_key_cmp,
                       NULL,      /* data pointer, optional */
                       NULL,
                       NULL);
                       
    for (i = 0; i < 15; i++) {
		lchId_type_table[i+1] = *lch_contents[i];
	}
}
static void
dissect_nbap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item	*nbap_item = NULL;
	proto_tree	*nbap_tree = NULL;
	int i;
	/* make entry in the Protocol column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NBAP");

	/* create the nbap protocol tree */
	nbap_item = proto_tree_add_item(tree, proto_nbap, tvb, 0, -1, ENC_NA);
	nbap_tree = proto_item_add_subtree(nbap_item, ett_nbap);

	/*Do a little cleanup just as a precaution*/
	for (i = 0; i < maxNrOfMACdFlows; i++) {
		nbap_hsdsch_channel_info[i].entity = hs;
	}

	dissect_NBAP_PDU_PDU(tvb, pinfo, nbap_tree);
}

/*--- proto_register_nbap -------------------------------------------*/
void proto_register_nbap(void)
{
	module_t *nbap_module;
	guint8 i;

	/* List of fields */
	static hf_register_info hf[] = {
	{ &hf_nbap_transportLayerAddress_ipv4,
	  { "transportLayerAddress IPv4", "nbap.transportLayerAddress_ipv4",
		FT_IPv4, BASE_NONE, NULL, 0,
		NULL, HFILL }},
	{ &hf_nbap_transportLayerAddress_ipv6,
	  { "transportLayerAddress IPv6", "nbap.transportLayerAddress_ipv6",
		FT_IPv6, BASE_NONE, NULL, 0,
		NULL, HFILL }},
	{ &hf_nbap_transportLayerAddress_nsap,
	  { "transportLayerAddress NSAP", "nbap.transportLayerAddress_NSAP",
		FT_BYTES, BASE_NONE, NULL, 0,
		NULL, HFILL }},
	#include "packet-nbap-hfarr.c"
	};

	/* List of subtrees */
	static gint *ett[] = {
		&ett_nbap,
		&ett_nbap_TransportLayerAddress,
		&ett_nbap_TransportLayerAddress_nsap,
		&ett_nbap_ib_sg_data,
	#include "packet-nbap-ettarr.c"
	};

	/* Register protocol */
	proto_nbap = proto_register_protocol(PNAME, PSNAME, PFNAME);
	/* Register fields and subtrees */
	proto_register_field_array(proto_nbap, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register dissector */
	register_dissector("nbap", dissect_nbap, proto_nbap);

	nbap_module = prefs_register_protocol(proto_nbap, NULL);

	/* Register preferences for mapping logical channel IDs to MAC content types. */
	for (i = 0; i < 16; i++) {
		prefs_register_enum_preference(nbap_module, ch_strings[i].name, ch_strings[i].title, ch_strings[i].description, lch_contents[i], content_types, FALSE);
	}

	/* Register dissector tables */
	nbap_ies_dissector_table = register_dissector_table("nbap.ies", "NBAP-PROTOCOL-IES", FT_UINT32, BASE_DEC);
	nbap_extension_dissector_table = register_dissector_table("nbap.extension", "NBAP-PROTOCOL-EXTENSION", FT_UINT32, BASE_DEC);
	nbap_proc_imsg_dissector_table = register_dissector_table("nbap.proc.imsg", "NBAP-ELEMENTARY-PROCEDURE InitiatingMessage", FT_STRING, BASE_NONE);
	nbap_proc_sout_dissector_table = register_dissector_table("nbap.proc.sout", "NBAP-ELEMENTARY-PROCEDURE SuccessfulOutcome", FT_STRING, BASE_NONE);
	nbap_proc_uout_dissector_table = register_dissector_table("nbap.proc.uout", "NBAP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", FT_STRING, BASE_NONE);

	register_init_routine(nbap_init);
}

/*
#define	EXTRA_PPI 1
*/
/*--- proto_reg_handoff_nbap ---------------------------------------*/
void
proto_reg_handoff_nbap(void)
{
	dissector_handle_t nbap_handle;

	nbap_handle = find_dissector("nbap");
	fp_handle = find_dissector("fp");
	dissector_add_uint("sctp.ppi", NBAP_PAYLOAD_PROTOCOL_ID, nbap_handle);
#ifdef EXTRA_PPI
		dissector_add_uint("sctp.ppi", 17, nbap_handle);
#endif
	dissector_add_handle("sctp.port", nbap_handle);  /* for "decode-as" */

#include "packet-nbap-dis-tab.c"
}


