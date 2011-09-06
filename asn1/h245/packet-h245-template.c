/* packet-h245_asn1.c
 * Routines for h245 packet dissection
 * Copyright 2004, Anders Broman <anders.broman@ericsson.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * To quote the author of the previous H245 dissector:
 *   "This is a complete replacement of the previous limitied dissector
 * that Ronnie was crazy enough to write by hand. It was a lot of time
 * to hack it by hand, but it is incomplete and buggy and it is good when
 * it will go away."
 * Ronnie did a great job and all the VoIP users had made good use of it!
 * Credit to Tomas Kukosa for developing the asn2wrs compiler.
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>

#include <string.h>

#include <epan/prefs.h>
#include <epan/t35.h>
#include <epan/emem.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/tap.h>
#include "packet-tpkt.h"
#include "packet-per.h"
#include "packet-h323.h"
#include "packet-h245.h"
#include "packet-rtp.h"
#include "packet-rtcp.h"
#include "packet-t38.h"

#define PNAME  "MULTIMEDIA-SYSTEM-CONTROL"
#define PSNAME "H.245"
#define PFNAME "h245"

static dissector_handle_t rtp_handle=NULL;
static dissector_handle_t rtcp_handle=NULL;
static dissector_handle_t t38_handle=NULL;
static dissector_table_t nsp_object_dissector_table;
static dissector_table_t nsp_h221_dissector_table;
static dissector_table_t gef_name_dissector_table;
static dissector_table_t gef_content_dissector_table;
static dissector_handle_t nsp_handle;
static dissector_handle_t data_handle;
static dissector_handle_t MultimediaSystemControlMessage_handle;
static dissector_handle_t h263_handle = NULL;
static dissector_handle_t amr_handle = NULL;

static void init_h245_packet_info(h245_packet_info *pi);
static int hf_h245_pdu_type = -1;
static int hf_h245Manufacturer = -1;
static int hf_h245_subMessageIdentifier_standard = -1;
static int h245_tap = -1;
static int h245dg_tap = -1;
h245_packet_info *h245_pi=NULL;

static gboolean h245_reassembly = TRUE;
static gboolean h245_shorttypes = FALSE;

#include "packet-h245-val.h"

static const value_string h245_RequestMessage_short_vals[] = {
	{ RequestMessage_nonStandard              ,	"NSM" },
	{ RequestMessage_masterSlaveDetermination ,	"MSD" },
	{ RequestMessage_terminalCapabilitySet    ,	"TCS" },
	{ RequestMessage_openLogicalChannel       ,	"OLC" },
	{ RequestMessage_closeLogicalChannel      ,	"CLC" },
	{ RequestMessage_requestChannelClose      ,	"RCC" },
	{ RequestMessage_multiplexEntrySend       ,	"MES" },
	{ RequestMessage_requestMultiplexEntry    ,	"RME" },
	{ RequestMessage_requestMode              ,	"RM"  },
	{ RequestMessage_roundTripDelayRequest    ,	"RTDR" },
	{ RequestMessage_maintenanceLoopRequest   ,	"MLR" },
	{ RequestMessage_communicationModeRequest ,	"CMR" },
	{ RequestMessage_conferenceRequest        ,	"CR"  },
	{ RequestMessage_multilinkRequest         ,	"MR"  },
	{ RequestMessage_logicalChannelRateRequest,	"LCRR" },
	{ RequestMessage_genericRequest           ,	"GR"  },
	{  0, NULL }
};
static const value_string h245_ResponseMessage_short_vals[] = {
	{ ResponseMessage_nonStandard                   ,	"NSM" },
	{ ResponseMessage_masterSlaveDeterminationAck   ,	"MSDAck" },
	{ ResponseMessage_masterSlaveDeterminationReject,	"MSDReject" },
	{ ResponseMessage_terminalCapabilitySetAck      ,	"TCSAck" },
	{ ResponseMessage_terminalCapabilitySetReject   ,	"TCSReject" },
	{ ResponseMessage_openLogicalChannelAck         ,	"OLCAck" },
	{ ResponseMessage_openLogicalChannelReject      ,	"OLCReject" },
	{ ResponseMessage_closeLogicalChannelAck        ,	"CLCAck" },
	{ ResponseMessage_requestChannelCloseAck        ,	"RCCAck" },
	{ ResponseMessage_requestChannelCloseReject     ,	"RCCReject" },
	{ ResponseMessage_multiplexEntrySendAck         ,	"MESAck" },
	{ ResponseMessage_multiplexEntrySendReject      ,	"MESReject" },
	{ ResponseMessage_requestMultiplexEntryAck      ,	"RMEAck" },
	{ ResponseMessage_requestMultiplexEntryReject   ,	"RMEReject" },
	{ ResponseMessage_requestModeAck                ,	"RMAck" },
	{ ResponseMessage_requestModeReject             ,	"RMReject" },
	{ ResponseMessage_roundTripDelayResponse        ,	"RTDResponse" },
	{ ResponseMessage_maintenanceLoopAck            ,	"MLAck" },
	{ ResponseMessage_maintenanceLoopReject         ,	"MLReject" },
	{ ResponseMessage_communicationModeResponse     ,	"CMResponse" },
	{ ResponseMessage_conferenceResponse            ,	"CResponse" },
	{ ResponseMessage_multilinkResponse             ,	"MResponse" },
	{ ResponseMessage_logicalChannelRateAcknowledge ,	"LCRAck" },
	{ ResponseMessage_logicalChannelRateReject      ,	"LCRReject" },
	{ ResponseMessage_genericResponse               ,	"GR" },
	{  0, NULL }
};
static const value_string h245_IndicationMessage_short_vals[] = {
	{ IndicationMessage_nonStandard                             ,	"NSM" },
	{ IndicationMessage_functionNotUnderstood                   ,	"FNU" },
	{ IndicationMessage_masterSlaveDeterminationRelease         ,	"MSDRelease" },
	{ IndicationMessage_terminalCapabilitySetRelease            ,	"TCSRelease" },
	{ IndicationMessage_openLogicalChannelConfirm               ,	"OLCConfirm" },
	{ IndicationMessage_requestChannelCloseRelease              ,	"RCCRelease" },
	{ IndicationMessage_multiplexEntrySendRelease               ,	"MESRelease" },
	{ IndicationMessage_requestMultiplexEntryRelease            ,	"RMERelease" },
	{ IndicationMessage_requestModeRelease                      ,	"RMRelease" },
	{ IndicationMessage_miscellaneousIndication                 ,	"MI" },
	{ IndicationMessage_jitterIndication                        ,	"JI" },
	{ IndicationMessage_h223SkewIndication                      ,	"H223SI" },
	{ IndicationMessage_newATMVCIndication                      ,	"NATMVCI" },
	{ IndicationMessage_userInput                               ,	"UII" },
	{ IndicationMessage_h2250MaximumSkewIndication              ,	"H2250MSI" },
	{ IndicationMessage_mcLocationIndication                    ,	"MCLI" },
	{ IndicationMessage_conferenceIndication                    ,	"CI" },
	{ IndicationMessage_vendorIdentification                    ,	"VI" },
	{ IndicationMessage_functionNotSupported                    ,	"FNS" },
	{ IndicationMessage_multilinkIndication                     ,	"MultilinkIndication" },
	{ IndicationMessage_logicalChannelRateRelease               ,	"LCRRelease" },
	{ IndicationMessage_flowControlIndication                   ,	"FCIndication" },
	{ IndicationMessage_mobileMultilinkReconfigurationIndication,	"MMRI" },
	{ IndicationMessage_genericIndication                       ,	"GI" },
	{  0, NULL }
};
static const value_string h245_CommandMessage_short_vals[] = {
	{ CommandMessage_nonStandard                          ,	"NSM" },
	{ CommandMessage_maintenanceLoopOffCommand            ,	"MLOC" },
	{ CommandMessage_sendTerminalCapabilitySet            ,	"STCS" },
	{ CommandMessage_encryptionCommand                    ,	"EC" },
	{ CommandMessage_flowControlCommand                   ,	"FCC" },
	{ CommandMessage_endSessionCommand                    ,	"ESC" },
	{ CommandMessage_miscellaneousCommand                 ,	"MC" },
	{ CommandMessage_communicationModeCommand             ,	"CMC" },
	{ CommandMessage_conferenceCommand                    ,	"CC" },
	{ CommandMessage_h223MultiplexReconfiguration         ,	"H223MR" },
	{ CommandMessage_newATMVCCommand                      ,	"NATMVCC" },
	{ CommandMessage_mobileMultilinkReconfigurationCommand,	"MMRC" },
	{ CommandMessage_genericCommand                       ,	"GC" },
	{  0, NULL }
};

static const value_string h245_AudioCapability_short_vals[] = {
  { AudioCapability_nonStandard           , "nonStd" },
  { AudioCapability_g711Alaw64k           , "g711A" },
  { AudioCapability_g711Alaw56k           , "g711A56k" },
  { AudioCapability_g711Ulaw64k           , "g711U" },
  { AudioCapability_g711Ulaw56k           , "g711U56k" },
  { AudioCapability_g722_64k              , "g722-64k" },
  { AudioCapability_g722_56k              , "g722-56k" },
  { AudioCapability_g722_48k              , "g722-48k" },
  { AudioCapability_g7231                 , "g7231" },
  { AudioCapability_g728                  , "g728" },
  { AudioCapability_g729                  , "g729" },
  { AudioCapability_g729AnnexA            , "g729A" },
  { AudioCapability_is11172AudioCapability, "is11172" },
  { AudioCapability_is13818AudioCapability, "is13818" },
  { AudioCapability_g729wAnnexB           , "g729B" },
  { AudioCapability_g729AnnexAwAnnexB     , "g729AB" },
  { AudioCapability_g7231AnnexCCapability , "g7231C" },
  { AudioCapability_gsmFullRate           , "gsmFR" },
  { AudioCapability_gsmHalfRate           , "gsmHR" },
  { AudioCapability_gsmEnhancedFullRate   , "gsmEFR" },
  { AudioCapability_genericAudioCapability, "generic" },
  { AudioCapability_g729Extensions        , "g729Ext" },
  { AudioCapability_vbd                   , "vbd" },
  { AudioCapability_audioTelephonyEvent   , "audioTelEvent" },
  { AudioCapability_audioTone             , "audioTone" },
  {  0, NULL }
};

/* To put the codec type only in COL_INFO when
   an OLC is read */
const char* codec_type = NULL;
static guint32 rfc_number;

typedef struct _unicast_addr_t {
  address addr;
  guint8 addr_buf[16];
  guint32 port;
} unicast_addr_t;

typedef struct _channel_info_t {
  gchar data_type_str[32];
  unicast_addr_t *upcoming_addr;
  unicast_addr_t media_addr;
  unicast_addr_t media_control_addr;
  unsigned int rfc2198;
  gboolean srtp_flag;
  gboolean is_video;
} channel_info_t;

typedef struct _olc_info_t {
  guint16 fwd_lc_num;
  channel_info_t fwd_lc;
  channel_info_t rev_lc;
} olc_info_t;

static GHashTable* h245_pending_olc_reqs = NULL;
static gboolean fast_start = FALSE;
static olc_info_t *upcoming_olc = NULL;
static channel_info_t *upcoming_channel = NULL;

/* NonStandardParameter */
static const char *nsiOID;
static guint32 h221NonStandard;
static guint32 t35CountryCode;
static guint32 t35Extension;
static guint32 manufacturerCode;

static const value_string h245_RFC_number_vals[] = {
	{  2190,	"RFC 2190 - H.263 Video Streams" },
	{  2198,	"RFC 2198 - RTP Payload for Redundant Audio Data" },
	{  2429,	"RFC 2429 - 1998 Version of ITU-T Rec. H.263 Video (H.263+)" },
	{  3016,	"RFC 3016 - RTP Payload Format for MPEG-4 Audio/Visual Streams" },
	{  3267,	"RFC 3267 - Adaptive Multi-Rate (AMR) and Adaptive Multi-Rate Wideband (AMR-WB)" },
	{  3984,	"RFC 3984 - RTP Payload Format for H.264 Video" },
	{  0, NULL }
};

/* Table 7/H.239 subMessageIdentifier values */
static const value_string h245_h239subMessageIdentifier_vals[] = {
  {   1, "flowControlReleaseRequest" },
  {   2, "flowControlReleaseResponse" },
  {   3, "presentationTokenRequest" },
  {   4, "presentationTokenResponse" },
  {   5, "presentationTokenRelease" },
  {   6, "presentationTokenIndicateOwner" },
  { 0, NULL }
};


/* h223 multiplex codes */
static h223_set_mc_handle_t h223_set_mc_handle = NULL;
h223_mux_element *h223_me=NULL;
guint8 h223_mc=0;
void h245_set_h223_set_mc_handle( h223_set_mc_handle_t handle )
{
	h223_set_mc_handle = handle;
}

/* h223 logical channels */
typedef struct {
	h223_lc_params *fw_channel_params;
	h223_lc_params *rev_channel_params;
} h223_pending_olc;

static GHashTable*          h223_pending_olc_reqs[] = { NULL, NULL };
static dissector_handle_t   h245_lc_dissector;
static guint16              h245_lc_temp;
static guint16              h223_fw_lc_num;
static guint16              h223_rev_lc_num;
static h223_lc_params      *h223_lc_params_temp;
static h223_lc_params      *h223_fw_lc_params;
static h223_lc_params      *h223_rev_lc_params;
static h223_add_lc_handle_t h223_add_lc_handle = NULL;

static void h223_lc_init_dir( int dir )
{
	if ( h223_pending_olc_reqs[dir] )
		g_hash_table_destroy( h223_pending_olc_reqs[dir] );
	h223_pending_olc_reqs[dir] = g_hash_table_new( g_direct_hash, g_direct_equal );
}

static void h223_lc_init( void )
{
	h223_lc_init_dir( P2P_DIR_SENT );
	h223_lc_init_dir( P2P_DIR_RECV );
	h223_lc_params_temp = NULL;
	h245_lc_dissector = NULL;
	h223_fw_lc_num = 0;
}

static void h245_init(void)
{
	if ( h245_pending_olc_reqs)
		g_hash_table_destroy(h245_pending_olc_reqs);
	h245_pending_olc_reqs = g_hash_table_new(g_str_hash, g_str_equal);

	h223_lc_init();
}

void h245_set_h223_add_lc_handle( h223_add_lc_handle_t handle )
{
	h223_add_lc_handle = handle;
}

static const gchar *gen_olc_key(guint16 lc_num, address *dst_addr, address *src_addr)
{
  return ep_strdup_printf("%s/%s/%u", ep_address_to_str(dst_addr), ep_address_to_str(src_addr), lc_num);
}

static void update_unicast_addr(unicast_addr_t *req_addr, unicast_addr_t *ack_addr)
{
  if (ack_addr->addr.type!=AT_NONE && ack_addr->port!=0) {
    memcpy(req_addr->addr_buf, ack_addr->addr_buf, sizeof(req_addr->addr_buf));
    SET_ADDRESS(&req_addr->addr, ack_addr->addr.type, ack_addr->addr.len, req_addr->addr_buf);
    req_addr->port = ack_addr->port;
  }
}

static void free_encoding_name_str (void *ptr)
{
  encoding_name_and_rate_t *encoding_name_and_rate = (encoding_name_and_rate_t *)ptr;

  if (encoding_name_and_rate->encoding_name) {
    g_free(encoding_name_and_rate->encoding_name);
  }
}

static void h245_setup_channels(packet_info *pinfo, channel_info_t *upcoming_channel_lcl)
{
	gint *key;
	GHashTable *rtp_dyn_payload = NULL;
	struct srtp_info *dummy_srtp_info = NULL;

	if (!upcoming_channel_lcl) return;

	/* T.38 */
	if (!strcmp(upcoming_channel_lcl->data_type_str, "t38fax")) {
		if (upcoming_channel_lcl->media_addr.addr.type!=AT_NONE && upcoming_channel_lcl->media_addr.port!=0 && t38_handle) {
			t38_add_address(pinfo, &upcoming_channel_lcl->media_addr.addr,
							upcoming_channel_lcl->media_addr.port, 0,
							"H245", pinfo->fd->num);
		}
		return;
	}

	/* (S)RTP, (S)RTCP */
	if (upcoming_channel_lcl->rfc2198 > 0) {
		encoding_name_and_rate_t *encoding_name_and_rate = g_malloc( sizeof(encoding_name_and_rate_t));
		rtp_dyn_payload = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, free_encoding_name_str);
		encoding_name_and_rate->encoding_name = g_strdup("red");
		encoding_name_and_rate->sample_rate = 8000;
		key = g_malloc(sizeof(gint));
		*key = upcoming_channel_lcl->rfc2198;
		g_hash_table_insert(rtp_dyn_payload, key, encoding_name_and_rate);
	}

	if (upcoming_channel_lcl->srtp_flag) {
		dummy_srtp_info = se_alloc0(sizeof(struct srtp_info));
	}

	/* DEBUG 	g_warning("h245_setup_channels media_addr.addr.type %u port %u",upcoming_channel_lcl->media_addr.addr.type, upcoming_channel_lcl->media_addr.port );
	*/
	if (upcoming_channel_lcl->media_addr.addr.type!=AT_NONE && upcoming_channel_lcl->media_addr.port!=0 && rtp_handle) {
		srtp_add_address(pinfo, &upcoming_channel_lcl->media_addr.addr,
						upcoming_channel_lcl->media_addr.port, 0,
						"H245", pinfo->fd->num, upcoming_channel_lcl->is_video , rtp_dyn_payload, dummy_srtp_info);
	}
	if (upcoming_channel_lcl->media_control_addr.addr.type!=AT_NONE && upcoming_channel_lcl->media_control_addr.port!=0 && rtcp_handle) {
		srtcp_add_address(pinfo, &upcoming_channel_lcl->media_control_addr.addr,
						upcoming_channel_lcl->media_control_addr.port, 0,
						"H245", pinfo->fd->num, dummy_srtp_info);
	}
}

/* Initialize the protocol and registered fields */
static int proto_h245 = -1;
#include "packet-h245-hf.c"

/* Initialize the subtree pointers */
static int ett_h245 = -1;
static int ett_h245_returnedFunction = -1;
#include "packet-h245-ett.c"

/* Forward declarations */
static int dissect_h245_MultimediaSystemControlMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static void reset_h245_pi(void *dummy _U_)
{
	h245_pi = NULL; /* Make sure we don't leave ep_alloc()ated memory lying around */
}

#include "packet-h245-fn.c"

static void
dissect_h245(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	/*
	 * MultimediaSystemControlMessage_handle is the handle for
	 * dissect_h245_h245, so we don't want to do any h245_pi or tap stuff here.
	 */
	dissect_tpkt_encap(tvb, pinfo, parent_tree, h245_reassembly, MultimediaSystemControlMessage_handle);
}


static void
dissect_h245_h245(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *it;
	proto_tree *tr;
	guint32 offset=0;
	asn1_ctx_t asn1_ctx;

	fast_start = FALSE;
	/* Clean up from any previous packet dissection */
	upcoming_olc = NULL;
	upcoming_channel = NULL;
	codec_type = NULL;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);

	it=proto_tree_add_protocol_format(parent_tree, proto_h245, tvb, 0, tvb_length(tvb), PSNAME);
	tr=proto_item_add_subtree(it, ett_h245);

	/* assume that whilst there is more tvb data, there are more h245 commands */
	while ( tvb_length_remaining( tvb, offset>>3 )>0 ){
		CLEANUP_PUSH(reset_h245_pi, NULL);
		h245_pi=ep_alloc(sizeof(h245_packet_info));
		init_h245_packet_info(h245_pi);
		asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
		offset = dissect_h245_MultimediaSystemControlMessage(tvb, offset, &asn1_ctx, tr, hf_h245_pdu_type);
		tap_queue_packet(h245dg_tap, pinfo, h245_pi);
		offset = (offset+0x07) & 0xfffffff8;
		CLEANUP_CALL_AND_POP;
	}
}

void
dissect_h245_FastStart_OLC(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, char *codec_str) {

  fast_start = TRUE;
  /* Clean up from any previous packet dissection */
  upcoming_olc = NULL;
  upcoming_channel = NULL;
  codec_type = NULL;

  dissect_OpenLogicalChannel_PDU(tvb, pinfo, tree);

  if (h245_pi != NULL)
	  h245_pi->msg_type = H245_OpenLogChn;

  if (codec_str && codec_type){
        g_strlcpy(codec_str, codec_type, 50);
  }

}

/*--- proto_register_h245 -------------------------------------------*/
void proto_register_h245(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_h245_pdu_type,
 { "PDU Type", "h245.pdu_type", FT_UINT32, BASE_DEC,
		VALS(h245_MultimediaSystemControlMessage_vals), 0, "Type of H.245 PDU", HFILL }},
	{ &hf_h245Manufacturer,
		{ "H.245 Manufacturer", "h245.Manufacturer", FT_UINT32, BASE_HEX,
		VALS(H221ManufacturerCode_vals), 0, "h245.H.221 Manufacturer", HFILL }},
    { &hf_h245_subMessageIdentifier_standard,
      { "subMessageIdentifier", "h245.subMessageIdentifier.standard",
        FT_UINT32, BASE_DEC, VALS(h245_h239subMessageIdentifier_vals), 0,
        NULL, HFILL }},

#include "packet-h245-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_h245,
	  &ett_h245_returnedFunction,
#include "packet-h245-ettarr.c"
  };
  module_t *h245_module;

  /* Register protocol */
  proto_h245 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_init_routine(h245_init);
  /* Register fields and subtrees */
  proto_register_field_array(proto_h245, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* From Ronnie Sahlbergs original H245 dissector */

  h245_module = prefs_register_protocol(proto_h245, NULL);
  prefs_register_bool_preference(h245_module, "reassembly",
		"Reassemble H.245 messages spanning multiple TCP segments",
		"Whether the H.245 dissector should reassemble messages spanning multiple TCP segments."
		" To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
		&h245_reassembly);
  prefs_register_bool_preference(h245_module, "shorttypes",
		"Show short message types",
		"Whether the dissector should show short names or the long names from the standard",
		&h245_shorttypes);
  register_dissector("h245dg", dissect_h245_h245, proto_h245);
  register_dissector("h245", dissect_h245, proto_h245);

  nsp_object_dissector_table = register_dissector_table("h245.nsp.object", "H.245 NonStandardParameter (object)", FT_STRING, BASE_NONE);
  nsp_h221_dissector_table = register_dissector_table("h245.nsp.h221", "H.245 NonStandardParameter (h221)", FT_UINT32, BASE_HEX);
  gef_name_dissector_table = register_dissector_table("h245.gef.name", "H.245 Generic Extensible Framework (names)", FT_STRING, BASE_NONE);
  gef_content_dissector_table = register_dissector_table("h245.gef.content", "H.245 Generic Extensible Framework", FT_STRING, BASE_NONE);

  h245_tap = register_tap("h245");
  h245dg_tap = register_tap("h245dg");

  oid_add_from_string("h239ControlCapability","0.0.8.239.1.1");
  oid_add_from_string("h239ExtendedVideoCapability","0.0.8.239.1.2");
  oid_add_from_string("generic-message","0.0.8.239.2");
  oid_add_from_string("h245 version 3","0.0.8.245.0.3");
  oid_add_from_string("h245 version 4","0.0.8.245.0.4");
  oid_add_from_string("h245 version 5","0.0.8.245.0.5");
  oid_add_from_string("h245 version 6","0.0.8.245.0.6");
  oid_add_from_string("h245 version 7","0.0.8.245.0.7");
  oid_add_from_string("h245 version 8","0.0.8.245.0.8");
  oid_add_from_string("h245 version 9","0.0.8.245.0.9");
  oid_add_from_string("h245 version 10","0.0.8.245.0.10");
  oid_add_from_string("h245 version 11","0.0.8.245.0.11");
  oid_add_from_string("h245 version 12","0.0.8.245.0.12");
  oid_add_from_string("h245 version 13","0.0.8.245.0.13");
  /* This capability is defined in Annex E. */
  oid_add_from_string("ISO/IEC 14496-2 MPEG-4 video","0.0.8.245.1.0.0");
  /* This capability is defined in Annex H. */
  oid_add_from_string("ISO/IEC 14496-3 MPEG-4 audio","0.0.8.245.1.1.0");
  /* This capability is defined in Annex I. */
  oid_add_from_string("AMR","0.0.8.245.1.1.1");
  /* This capability is defined in Annex J. */
  oid_add_from_string("acelp","0.0.8.245.1.1.2");
  /* This capability is defined in Annex K. */
  oid_add_from_string("us1","0.0.8.245.1.1.3");
  /* This capability is defined in Annex L. */
  oid_add_from_string("is127evrc","0.0.8.245.1.1.4");
  /* This capability is defined in Annex M. */
  oid_add_from_string("ISO/IEC 13818-7","0.0.8.245.1.1.5");
  /* This capability is defined in Annex N. */
  oid_add_from_string("rfc3389","0.0.8.245.1.1.6");
  /* This capability is defined in Annex O. */
  oid_add_from_string("L-16","0.0.8.245.1.1.7");
  /* This capability is defined in Annex P. */
  oid_add_from_string("bounded-audio-stream","0.0.8.245.1.1.8");
  /* This capability is defined in Annex R. */
  oid_add_from_string("AMR-NB","0.0.8.245.1.1.9");
  /* This capability is defined in Annex R. */
  oid_add_from_string("AMR-WB","0.0.8.245.1.1.10");
  /* This capability is defined in Annex S. */
  oid_add_from_string("ilbc","0.0.8.245.1.1.11");

  oid_add_from_string("ISO/IEC 14496-1","0.0.8.245.1.2.0");
  oid_add_from_string("Nx64","0.0.8.245.1.2.1");
  oid_add_from_string("logical-channel-bit-ratemanagement","0.0.8.245.1.3.0");

  oid_add_from_string("h264 generic-capabilities","0.0.8.241.0.0.1");
  oid_add_from_string("iPpacketization_h241AnnexA(single NAL unit mode)","0.0.8.241.0.0.0.0");
  oid_add_from_string("iPpacketization_RFC3984NonInterleaved","0.0.8.241.0.0.0.1");
  oid_add_from_string("iPpacketization_RFC3984Interleaved","0.0.8.241.0.0.0.2");
}


/*--- proto_reg_handoff_h245 ---------------------------------------*/
void proto_reg_handoff_h245(void) {
	dissector_handle_t h245_handle;

	rtp_handle = find_dissector("rtp");
	rtcp_handle = find_dissector("rtcp");
	t38_handle = find_dissector("t38");
	data_handle = find_dissector("data");
	h263_handle = find_dissector("h263data");
	amr_handle = find_dissector("amr_if2_nb");


	h245_handle = find_dissector("h245");
	dissector_add_handle("tcp.port", h245_handle);
	MultimediaSystemControlMessage_handle = find_dissector("h245dg");
	dissector_add_handle("udp.port", MultimediaSystemControlMessage_handle);
}

static void init_h245_packet_info(h245_packet_info *pi)
{
        if(pi == NULL) {
                return;
        }

        pi->msg_type = H245_OTHER;
		pi->frame_label[0] = '\0';
		g_snprintf(pi->comment, sizeof(pi->comment), "H245 ");
}

