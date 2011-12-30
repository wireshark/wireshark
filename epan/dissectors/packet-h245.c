/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-h245.c                                                              */
/* ../../tools/asn2wrs.py -p h245 -c ./h245.cnf -s ./packet-h245-template -D . -O ../../epan/dissectors MULTIMEDIA-SYSTEM-CONTROL.asn */

/* Input file: packet-h245-template.c */

#line 1 "../../asn1/h245/packet-h245-template.c"
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


/*--- Included file: packet-h245-val.h ---*/
#line 1 "../../asn1/h245/packet-h245-val.h"

typedef enum _AudioCapability_enum {
  AudioCapability_nonStandard =   0,
  AudioCapability_g711Alaw64k =   1,
  AudioCapability_g711Alaw56k =   2,
  AudioCapability_g711Ulaw64k =   3,
  AudioCapability_g711Ulaw56k =   4,
  AudioCapability_g722_64k =   5,
  AudioCapability_g722_56k =   6,
  AudioCapability_g722_48k =   7,
  AudioCapability_g7231 =   8,
  AudioCapability_g728 =   9,
  AudioCapability_g729 =  10,
  AudioCapability_g729AnnexA =  11,
  AudioCapability_is11172AudioCapability =  12,
  AudioCapability_is13818AudioCapability =  13,
  AudioCapability_g729wAnnexB =  14,
  AudioCapability_g729AnnexAwAnnexB =  15,
  AudioCapability_g7231AnnexCCapability =  16,
  AudioCapability_gsmFullRate =  17,
  AudioCapability_gsmHalfRate =  18,
  AudioCapability_gsmEnhancedFullRate =  19,
  AudioCapability_genericAudioCapability =  20,
  AudioCapability_g729Extensions =  21,
  AudioCapability_vbd =  22,
  AudioCapability_audioTelephonyEvent =  23,
  AudioCapability_audioTone =  24
} AudioCapability_enum;

typedef enum _RequestMessage_enum {
  RequestMessage_nonStandard =   0,
  RequestMessage_masterSlaveDetermination =   1,
  RequestMessage_terminalCapabilitySet =   2,
  RequestMessage_openLogicalChannel =   3,
  RequestMessage_closeLogicalChannel =   4,
  RequestMessage_requestChannelClose =   5,
  RequestMessage_multiplexEntrySend =   6,
  RequestMessage_requestMultiplexEntry =   7,
  RequestMessage_requestMode =   8,
  RequestMessage_roundTripDelayRequest =   9,
  RequestMessage_maintenanceLoopRequest =  10,
  RequestMessage_communicationModeRequest =  11,
  RequestMessage_conferenceRequest =  12,
  RequestMessage_multilinkRequest =  13,
  RequestMessage_logicalChannelRateRequest =  14,
  RequestMessage_genericRequest =  15
} RequestMessage_enum;

typedef enum _ResponseMessage_enum {
  ResponseMessage_nonStandard =   0,
  ResponseMessage_masterSlaveDeterminationAck =   1,
  ResponseMessage_masterSlaveDeterminationReject =   2,
  ResponseMessage_terminalCapabilitySetAck =   3,
  ResponseMessage_terminalCapabilitySetReject =   4,
  ResponseMessage_openLogicalChannelAck =   5,
  ResponseMessage_openLogicalChannelReject =   6,
  ResponseMessage_closeLogicalChannelAck =   7,
  ResponseMessage_requestChannelCloseAck =   8,
  ResponseMessage_requestChannelCloseReject =   9,
  ResponseMessage_multiplexEntrySendAck =  10,
  ResponseMessage_multiplexEntrySendReject =  11,
  ResponseMessage_requestMultiplexEntryAck =  12,
  ResponseMessage_requestMultiplexEntryReject =  13,
  ResponseMessage_requestModeAck =  14,
  ResponseMessage_requestModeReject =  15,
  ResponseMessage_roundTripDelayResponse =  16,
  ResponseMessage_maintenanceLoopAck =  17,
  ResponseMessage_maintenanceLoopReject =  18,
  ResponseMessage_communicationModeResponse =  19,
  ResponseMessage_conferenceResponse =  20,
  ResponseMessage_multilinkResponse =  21,
  ResponseMessage_logicalChannelRateAcknowledge =  22,
  ResponseMessage_logicalChannelRateReject =  23,
  ResponseMessage_genericResponse =  24
} ResponseMessage_enum;

typedef enum _CommandMessage_enum {
  CommandMessage_nonStandard =   0,
  CommandMessage_maintenanceLoopOffCommand =   1,
  CommandMessage_sendTerminalCapabilitySet =   2,
  CommandMessage_encryptionCommand =   3,
  CommandMessage_flowControlCommand =   4,
  CommandMessage_endSessionCommand =   5,
  CommandMessage_miscellaneousCommand =   6,
  CommandMessage_communicationModeCommand =   7,
  CommandMessage_conferenceCommand =   8,
  CommandMessage_h223MultiplexReconfiguration =   9,
  CommandMessage_newATMVCCommand =  10,
  CommandMessage_mobileMultilinkReconfigurationCommand =  11,
  CommandMessage_genericCommand =  12
} CommandMessage_enum;

typedef enum _IndicationMessage_enum {
  IndicationMessage_nonStandard =   0,
  IndicationMessage_functionNotUnderstood =   1,
  IndicationMessage_masterSlaveDeterminationRelease =   2,
  IndicationMessage_terminalCapabilitySetRelease =   3,
  IndicationMessage_openLogicalChannelConfirm =   4,
  IndicationMessage_requestChannelCloseRelease =   5,
  IndicationMessage_multiplexEntrySendRelease =   6,
  IndicationMessage_requestMultiplexEntryRelease =   7,
  IndicationMessage_requestModeRelease =   8,
  IndicationMessage_miscellaneousIndication =   9,
  IndicationMessage_jitterIndication =  10,
  IndicationMessage_h223SkewIndication =  11,
  IndicationMessage_newATMVCIndication =  12,
  IndicationMessage_userInput =  13,
  IndicationMessage_h2250MaximumSkewIndication =  14,
  IndicationMessage_mcLocationIndication =  15,
  IndicationMessage_conferenceIndication =  16,
  IndicationMessage_vendorIdentification =  17,
  IndicationMessage_functionNotSupported =  18,
  IndicationMessage_multilinkIndication =  19,
  IndicationMessage_logicalChannelRateRelease =  20,
  IndicationMessage_flowControlIndication =  21,
  IndicationMessage_mobileMultilinkReconfigurationIndication =  22,
  IndicationMessage_genericIndication =  23
} IndicationMessage_enum;

/*--- End of included file: packet-h245-val.h ---*/
#line 88 "../../asn1/h245/packet-h245-template.c"

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

/*--- Included file: packet-h245-hf.c ---*/
#line 1 "../../asn1/h245/packet-h245-hf.c"
static int hf_h245_OpenLogicalChannel_PDU = -1;   /* OpenLogicalChannel */
static int hf_h245_request = -1;                  /* RequestMessage */
static int hf_h245_response = -1;                 /* ResponseMessage */
static int hf_h245_command = -1;                  /* CommandMessage */
static int hf_h245_indication = -1;               /* IndicationMessage */
static int hf_h245_nonStandardMsg = -1;           /* NonStandardMessage */
static int hf_h245_masterSlaveDetermination = -1;  /* MasterSlaveDetermination */
static int hf_h245_terminalCapabilitySet = -1;    /* TerminalCapabilitySet */
static int hf_h245_openLogicalChannel = -1;       /* OpenLogicalChannel */
static int hf_h245_closeLogicalChannel = -1;      /* CloseLogicalChannel */
static int hf_h245_requestChannelClose = -1;      /* RequestChannelClose */
static int hf_h245_multiplexEntrySend = -1;       /* MultiplexEntrySend */
static int hf_h245_requestMultiplexEntry = -1;    /* RequestMultiplexEntry */
static int hf_h245_requestMode = -1;              /* RequestMode */
static int hf_h245_roundTripDelayRequest = -1;    /* RoundTripDelayRequest */
static int hf_h245_maintenanceLoopRequest = -1;   /* MaintenanceLoopRequest */
static int hf_h245_communicationModeRequest = -1;  /* CommunicationModeRequest */
static int hf_h245_conferenceRequest = -1;        /* ConferenceRequest */
static int hf_h245_multilinkRequest = -1;         /* MultilinkRequest */
static int hf_h245_logicalChannelRateRequest = -1;  /* LogicalChannelRateRequest */
static int hf_h245_genericRequest = -1;           /* GenericMessage */
static int hf_h245_masterSlaveDeterminationAck = -1;  /* MasterSlaveDeterminationAck */
static int hf_h245_masterSlaveDeterminationReject = -1;  /* MasterSlaveDeterminationReject */
static int hf_h245_terminalCapabilitySetAck = -1;  /* TerminalCapabilitySetAck */
static int hf_h245_terminalCapabilitySetReject = -1;  /* TerminalCapabilitySetReject */
static int hf_h245_openLogicalChannelAck = -1;    /* OpenLogicalChannelAck */
static int hf_h245_openLogicalChannelReject = -1;  /* OpenLogicalChannelReject */
static int hf_h245_closeLogicalChannelAck = -1;   /* CloseLogicalChannelAck */
static int hf_h245_requestChannelCloseAck = -1;   /* RequestChannelCloseAck */
static int hf_h245_requestChannelCloseReject = -1;  /* RequestChannelCloseReject */
static int hf_h245_multiplexEntrySendAck = -1;    /* MultiplexEntrySendAck */
static int hf_h245_multiplexEntrySendReject = -1;  /* MultiplexEntrySendReject */
static int hf_h245_requestMultiplexEntryAck = -1;  /* RequestMultiplexEntryAck */
static int hf_h245_requestMultiplexEntryReject = -1;  /* RequestMultiplexEntryReject */
static int hf_h245_requestModeAck = -1;           /* RequestModeAck */
static int hf_h245_requestModeReject = -1;        /* RequestModeReject */
static int hf_h245_roundTripDelayResponse = -1;   /* RoundTripDelayResponse */
static int hf_h245_maintenanceLoopAck = -1;       /* MaintenanceLoopAck */
static int hf_h245_maintenanceLoopReject = -1;    /* MaintenanceLoopReject */
static int hf_h245_communicationModeResponse = -1;  /* CommunicationModeResponse */
static int hf_h245_conferenceResponse = -1;       /* ConferenceResponse */
static int hf_h245_multilinkResponse = -1;        /* MultilinkResponse */
static int hf_h245_logicalChannelRateAcknowledge = -1;  /* LogicalChannelRateAcknowledge */
static int hf_h245_logicalChannelRateReject = -1;  /* LogicalChannelRateReject */
static int hf_h245_genericResponse = -1;          /* GenericMessage */
static int hf_h245_maintenanceLoopOffCommand = -1;  /* MaintenanceLoopOffCommand */
static int hf_h245_sendTerminalCapabilitySet = -1;  /* SendTerminalCapabilitySet */
static int hf_h245_encryptionCommand = -1;        /* EncryptionCommand */
static int hf_h245_flowControlCommand = -1;       /* FlowControlCommand */
static int hf_h245_endSessionCommand = -1;        /* EndSessionCommand */
static int hf_h245_miscellaneousCommand = -1;     /* MiscellaneousCommand */
static int hf_h245_communicationModeCommand = -1;  /* CommunicationModeCommand */
static int hf_h245_conferenceCommand = -1;        /* ConferenceCommand */
static int hf_h245_h223MultiplexReconfiguration = -1;  /* H223MultiplexReconfiguration */
static int hf_h245_newATMVCCommand = -1;          /* NewATMVCCommand */
static int hf_h245_mobileMultilinkReconfigurationCommand = -1;  /* MobileMultilinkReconfigurationCommand */
static int hf_h245_genericCommand = -1;           /* GenericMessage */
static int hf_h245_functionNotUnderstood = -1;    /* FunctionNotUnderstood */
static int hf_h245_masterSlaveDeterminationRelease = -1;  /* MasterSlaveDeterminationRelease */
static int hf_h245_terminalCapabilitySetRelease = -1;  /* TerminalCapabilitySetRelease */
static int hf_h245_openLogicalChannelConfirm = -1;  /* OpenLogicalChannelConfirm */
static int hf_h245_requestChannelCloseRelease = -1;  /* RequestChannelCloseRelease */
static int hf_h245_multiplexEntrySendRelease = -1;  /* MultiplexEntrySendRelease */
static int hf_h245_requestMultiplexEntryRelease = -1;  /* RequestMultiplexEntryRelease */
static int hf_h245_requestModeRelease = -1;       /* RequestModeRelease */
static int hf_h245_miscellaneousIndication = -1;  /* MiscellaneousIndication */
static int hf_h245_jitterIndication = -1;         /* JitterIndication */
static int hf_h245_h223SkewIndication = -1;       /* H223SkewIndication */
static int hf_h245_newATMVCIndication = -1;       /* NewATMVCIndication */
static int hf_h245_userInput = -1;                /* UserInputIndication */
static int hf_h245_h2250MaximumSkewIndication = -1;  /* H2250MaximumSkewIndication */
static int hf_h245_mcLocationIndication = -1;     /* MCLocationIndication */
static int hf_h245_conferenceIndication = -1;     /* ConferenceIndication */
static int hf_h245_vendorIdentification = -1;     /* VendorIdentification */
static int hf_h245_functionNotSupported = -1;     /* FunctionNotSupported */
static int hf_h245_multilinkIndication = -1;      /* MultilinkIndication */
static int hf_h245_logicalChannelRateRelease = -1;  /* LogicalChannelRateRelease */
static int hf_h245_flowControlIndication = -1;    /* FlowControlIndication */
static int hf_h245_mobileMultilinkReconfigurationIndication = -1;  /* MobileMultilinkReconfigurationIndication */
static int hf_h245_genericIndication = -1;        /* GenericMessage */
static int hf_h245_messageIdentifier = -1;        /* CapabilityIdentifier */
static int hf_h245_subMessageIdentifier = -1;     /* T_subMessageIdentifier */
static int hf_h245_messageContent = -1;           /* T_messageContent */
static int hf_h245_messageContent_item = -1;      /* T_messageContent_item */
static int hf_h245_nonStandardData = -1;          /* NonStandardParameter */
static int hf_h245_nonStandardIdentifier = -1;    /* NonStandardIdentifier */
static int hf_h245_nsd_data = -1;                 /* T_nsd_data */
static int hf_h245_object = -1;                   /* T_object */
static int hf_h245_h221NonStandardID = -1;        /* H221NonStandardID */
static int hf_h245_t35CountryCode = -1;           /* T_t35CountryCode */
static int hf_h245_t35Extension = -1;             /* T_t35Extension */
static int hf_h245_manufacturerCode = -1;         /* T_manufacturerCode */
static int hf_h245_terminalType = -1;             /* INTEGER_0_255 */
static int hf_h245_statusDeterminationNumber = -1;  /* INTEGER_0_16777215 */
static int hf_h245_decision = -1;                 /* T_decision */
static int hf_h245_master = -1;                   /* NULL */
static int hf_h245_slave = -1;                    /* NULL */
static int hf_h245_msd_rej_cause = -1;            /* MasterSlaveDeterminationRejectCause */
static int hf_h245_identicalNumbers = -1;         /* NULL */
static int hf_h245_sequenceNumber = -1;           /* SequenceNumber */
static int hf_h245_protocolIdentifier = -1;       /* OBJECT_IDENTIFIER */
static int hf_h245_multiplexCapability = -1;      /* MultiplexCapability */
static int hf_h245_capabilityTable = -1;          /* SET_SIZE_1_256_OF_CapabilityTableEntry */
static int hf_h245_capabilityTable_item = -1;     /* CapabilityTableEntry */
static int hf_h245_capabilityDescriptors = -1;    /* SET_SIZE_1_256_OF_CapabilityDescriptor */
static int hf_h245_capabilityDescriptors_item = -1;  /* CapabilityDescriptor */
static int hf_h245_genericInformation = -1;       /* SEQUENCE_OF_GenericInformation */
static int hf_h245_genericInformation_item = -1;  /* GenericInformation */
static int hf_h245_capabilityTableEntryNumber = -1;  /* CapabilityTableEntryNumber */
static int hf_h245_capability = -1;               /* Capability */
static int hf_h245_capabilityDescriptorNumber = -1;  /* CapabilityDescriptorNumber */
static int hf_h245_simultaneousCapabilities = -1;  /* SET_SIZE_1_256_OF_AlternativeCapabilitySet */
static int hf_h245_simultaneousCapabilities_item = -1;  /* AlternativeCapabilitySet */
static int hf_h245_AlternativeCapabilitySet_item = -1;  /* CapabilityTableEntryNumber */
static int hf_h245_tcs_rej_cause = -1;            /* TerminalCapabilitySetRejectCause */
static int hf_h245_unspecified = -1;              /* NULL */
static int hf_h245_undefinedTableEntryUsed = -1;  /* NULL */
static int hf_h245_descriptorCapacityExceeded = -1;  /* NULL */
static int hf_h245_tableEntryCapacityExceeded = -1;  /* T_tableEntryCapacityExceeded */
static int hf_h245_highestEntryNumberProcessed = -1;  /* CapabilityTableEntryNumber */
static int hf_h245_noneProcessed = -1;            /* NULL */
static int hf_h245_nonStandard = -1;              /* NonStandardParameter */
static int hf_h245_receiveVideoCapability = -1;   /* VideoCapability */
static int hf_h245_transmitVideoCapability = -1;  /* VideoCapability */
static int hf_h245_receiveAndTransmitVideoCapability = -1;  /* VideoCapability */
static int hf_h245_receiveAudioCapability = -1;   /* AudioCapability */
static int hf_h245_transmitAudioCapability = -1;  /* AudioCapability */
static int hf_h245_receiveAndTransmitAudioCapability = -1;  /* AudioCapability */
static int hf_h245_receiveDataApplicationCapability = -1;  /* DataApplicationCapability */
static int hf_h245_transmitDataApplicationCapability = -1;  /* DataApplicationCapability */
static int hf_h245_receiveAndTransmitDataApplicationCapability = -1;  /* DataApplicationCapability */
static int hf_h245_h233EncryptionTransmitCapability = -1;  /* BOOLEAN */
static int hf_h245_h233EncryptionReceiveCapability = -1;  /* T_h233EncryptionReceiveCapability */
static int hf_h245_h233IVResponseTime = -1;       /* INTEGER_0_255 */
static int hf_h245_conferenceCapability = -1;     /* ConferenceCapability */
static int hf_h245_h235SecurityCapability = -1;   /* H235SecurityCapability */
static int hf_h245_maxPendingReplacementFor = -1;  /* INTEGER_0_255 */
static int hf_h245_receiveUserInputCapability = -1;  /* UserInputCapability */
static int hf_h245_transmitUserInputCapability = -1;  /* UserInputCapability */
static int hf_h245_receiveAndTransmitUserInputCapability = -1;  /* UserInputCapability */
static int hf_h245_genericControlCapability = -1;  /* GenericCapability */
static int hf_h245_receiveMultiplexedStreamCapability = -1;  /* MultiplexedStreamCapability */
static int hf_h245_transmitMultiplexedStreamCapability = -1;  /* MultiplexedStreamCapability */
static int hf_h245_receiveAndTransmitMultiplexedStreamCapability = -1;  /* MultiplexedStreamCapability */
static int hf_h245_receiveRTPAudioTelephonyEventCapability = -1;  /* AudioTelephonyEventCapability */
static int hf_h245_receiveRTPAudioToneCapability = -1;  /* AudioToneCapability */
static int hf_h245_depFecCapability = -1;         /* DepFECCapability */
static int hf_h245_multiplePayloadStreamCapability = -1;  /* MultiplePayloadStreamCapability */
static int hf_h245_fecCapability = -1;            /* FECCapability */
static int hf_h245_redundancyEncodingCap = -1;    /* RedundancyEncodingCapability */
static int hf_h245_oneOfCapabilities = -1;        /* AlternativeCapabilitySet */
static int hf_h245_encryptionAuthenticationAndIntegrity = -1;  /* EncryptionAuthenticationAndIntegrity */
static int hf_h245_mediaCapability = -1;          /* CapabilityTableEntryNumber */
static int hf_h245_h222Capability = -1;           /* H222Capability */
static int hf_h245_h223Capability = -1;           /* H223Capability */
static int hf_h245_v76Capability = -1;            /* V76Capability */
static int hf_h245_h2250Capability = -1;          /* H2250Capability */
static int hf_h245_genericMultiplexCapability = -1;  /* GenericCapability */
static int hf_h245_numberOfVCs = -1;              /* INTEGER_1_256 */
static int hf_h245_vcCapability = -1;             /* SET_OF_VCCapability */
static int hf_h245_vcCapability_item = -1;        /* VCCapability */
static int hf_h245_aal1 = -1;                     /* T_aal1 */
static int hf_h245_nullClockRecovery = -1;        /* BOOLEAN */
static int hf_h245_srtsClockRecovery_bool = -1;   /* BOOLEAN */
static int hf_h245_adaptiveClockRecovery = -1;    /* BOOLEAN */
static int hf_h245_nullErrorCorrection = -1;      /* BOOLEAN */
static int hf_h245_longInterleaver = -1;          /* BOOLEAN */
static int hf_h245_shortInterleaver = -1;         /* BOOLEAN */
static int hf_h245_errorCorrectionOnly = -1;      /* BOOLEAN */
static int hf_h245_structuredDataTransfer = -1;   /* BOOLEAN */
static int hf_h245_partiallyFilledCells = -1;     /* BOOLEAN */
static int hf_h245_aal5 = -1;                     /* T_aal5 */
static int hf_h245_forwardMaximumSDUSize = -1;    /* INTEGER_0_65535 */
static int hf_h245_backwardMaximumSDUSize = -1;   /* INTEGER_0_65535 */
static int hf_h245_transportStream_bool = -1;     /* BOOLEAN */
static int hf_h245_programStream = -1;            /* BOOLEAN */
static int hf_h245_availableBitRates = -1;        /* T_availableBitRates */
static int hf_h245_avb_type = -1;                 /* Avb_type */
static int hf_h245_singleBitRate = -1;            /* INTEGER_1_65535 */
static int hf_h245_rangeOfBitRates = -1;          /* T_rangeOfBitRates */
static int hf_h245_lowerBitRate = -1;             /* INTEGER_1_65535 */
static int hf_h245_higherBitRate = -1;            /* INTEGER_1_65535 */
static int hf_h245_aal1ViaGateway = -1;           /* T_aal1ViaGateway */
static int hf_h245_gatewayAddress = -1;           /* SET_SIZE_1_256_OF_Q2931Address */
static int hf_h245_gatewayAddress_item = -1;      /* Q2931Address */
static int hf_h245_srtsClockRecoveryflag = -1;    /* BOOLEAN */
static int hf_h245_transportWithI_frames = -1;    /* BOOLEAN */
static int hf_h245_videoWithAL1 = -1;             /* BOOLEAN */
static int hf_h245_videoWithAL2 = -1;             /* BOOLEAN */
static int hf_h245_videoWithAL3 = -1;             /* BOOLEAN */
static int hf_h245_audioWithAL1 = -1;             /* BOOLEAN */
static int hf_h245_audioWithAL2 = -1;             /* BOOLEAN */
static int hf_h245_audioWithAL3 = -1;             /* BOOLEAN */
static int hf_h245_dataWithAL1 = -1;              /* BOOLEAN */
static int hf_h245_dataWithAL2 = -1;              /* BOOLEAN */
static int hf_h245_dataWithAL3 = -1;              /* BOOLEAN */
static int hf_h245_maximumAl2SDUSize = -1;        /* INTEGER_0_65535 */
static int hf_h245_maximumAl3SDUSize = -1;        /* INTEGER_0_65535 */
static int hf_h245_maximumDelayJitter = -1;       /* INTEGER_0_1023 */
static int hf_h245_h223MultiplexTableCapability = -1;  /* T_h223MultiplexTableCapability */
static int hf_h245_basic = -1;                    /* NULL */
static int hf_h245_enhanced = -1;                 /* T_enhanced */
static int hf_h245_maximumNestingDepth = -1;      /* INTEGER_1_15 */
static int hf_h245_maximumElementListSize = -1;   /* INTEGER_2_255 */
static int hf_h245_maximumSubElementListSize = -1;  /* INTEGER_2_255 */
static int hf_h245_maxMUXPDUSizeCapability = -1;  /* BOOLEAN */
static int hf_h245_nsrpSupport = -1;              /* BOOLEAN */
static int hf_h245_mobileOperationTransmitCapability = -1;  /* T_mobileOperationTransmitCapability */
static int hf_h245_modeChangeCapability = -1;     /* BOOLEAN */
static int hf_h245_h223AnnexA = -1;               /* BOOLEAN */
static int hf_h245_h223AnnexADoubleFlagFlag = -1;  /* BOOLEAN */
static int hf_h245_h223AnnexB = -1;               /* BOOLEAN */
static int hf_h245_h223AnnexBwithHeader = -1;     /* BOOLEAN */
static int hf_h245_h223AnnexCCapability = -1;     /* H223AnnexCCapability */
static int hf_h245_bitRate_1_19200 = -1;          /* INTEGER_1_19200 */
static int hf_h245_mobileMultilinkFrameCapability = -1;  /* T_mobileMultilinkFrameCapability */
static int hf_h245_maximumSampleSize = -1;        /* INTEGER_1_255 */
static int hf_h245_maximumPayloadLength = -1;     /* INTEGER_1_65025 */
static int hf_h245_videoWithAL1M = -1;            /* BOOLEAN */
static int hf_h245_videoWithAL2M = -1;            /* BOOLEAN */
static int hf_h245_videoWithAL3M = -1;            /* BOOLEAN */
static int hf_h245_audioWithAL1M = -1;            /* BOOLEAN */
static int hf_h245_audioWithAL2M = -1;            /* BOOLEAN */
static int hf_h245_audioWithAL3M = -1;            /* BOOLEAN */
static int hf_h245_dataWithAL1M = -1;             /* BOOLEAN */
static int hf_h245_dataWithAL2M = -1;             /* BOOLEAN */
static int hf_h245_dataWithAL3M = -1;             /* BOOLEAN */
static int hf_h245_alpduInterleaving = -1;        /* BOOLEAN */
static int hf_h245_maximumAL1MPDUSize = -1;       /* INTEGER_0_65535 */
static int hf_h245_maximumAL2MSDUSize = -1;       /* INTEGER_0_65535 */
static int hf_h245_maximumAL3MSDUSize = -1;       /* INTEGER_0_65535 */
static int hf_h245_rsCodeCapability = -1;         /* BOOLEAN */
static int hf_h245_suspendResumeCapabilitywAddress = -1;  /* BOOLEAN */
static int hf_h245_suspendResumeCapabilitywoAddress = -1;  /* BOOLEAN */
static int hf_h245_rejCapability = -1;            /* BOOLEAN */
static int hf_h245_sREJCapability = -1;           /* BOOLEAN */
static int hf_h245_mREJCapability = -1;           /* BOOLEAN */
static int hf_h245_crc8bitCapability = -1;        /* BOOLEAN */
static int hf_h245_crc16bitCapability = -1;       /* BOOLEAN */
static int hf_h245_crc32bitCapability = -1;       /* BOOLEAN */
static int hf_h245_uihCapability = -1;            /* BOOLEAN */
static int hf_h245_numOfDLCS = -1;                /* INTEGER_2_8191 */
static int hf_h245_twoOctetAddressFieldCapability = -1;  /* BOOLEAN */
static int hf_h245_loopBackTestCapability = -1;   /* BOOLEAN */
static int hf_h245_n401Capability = -1;           /* INTEGER_1_4095 */
static int hf_h245_maxWindowSizeCapability = -1;  /* INTEGER_1_127 */
static int hf_h245_v75Capability = -1;            /* V75Capability */
static int hf_h245_audioHeader = -1;              /* BOOLEAN */
static int hf_h245_maximumAudioDelayJitter = -1;  /* INTEGER_0_1023 */
static int hf_h245_receiveMultipointCapability = -1;  /* MultipointCapability */
static int hf_h245_transmitMultipointCapability = -1;  /* MultipointCapability */
static int hf_h245_receiveAndTransmitMultipointCapability = -1;  /* MultipointCapability */
static int hf_h245_mcCapability = -1;             /* T_mcCapability */
static int hf_h245_centralizedConferenceMC = -1;  /* BOOLEAN */
static int hf_h245_decentralizedConferenceMC = -1;  /* BOOLEAN */
static int hf_h245_rtcpVideoControlCapability = -1;  /* BOOLEAN */
static int hf_h245_mediaPacketizationCapability = -1;  /* MediaPacketizationCapability */
static int hf_h245_transportCapability = -1;      /* TransportCapability */
static int hf_h245_redundancyEncodingCapability = -1;  /* SEQUENCE_SIZE_1_256_OF_RedundancyEncodingCapability */
static int hf_h245_redundancyEncodingCapability_item = -1;  /* RedundancyEncodingCapability */
static int hf_h245_logicalChannelSwitchingCapability = -1;  /* BOOLEAN */
static int hf_h245_t120DynamicPortCapability = -1;  /* BOOLEAN */
static int hf_h245_h261aVideoPacketization = -1;  /* BOOLEAN */
static int hf_h245_rtpPayloadTypes = -1;          /* SEQUENCE_SIZE_1_256_OF_RTPPayloadType */
static int hf_h245_rtpPayloadTypes_item = -1;     /* RTPPayloadType */
static int hf_h245_qosMode = -1;                  /* QOSMode */
static int hf_h245_tokenRate = -1;                /* INTEGER_1_4294967295 */
static int hf_h245_bucketSize = -1;               /* INTEGER_1_4294967295 */
static int hf_h245_peakRate = -1;                 /* INTEGER_1_4294967295 */
static int hf_h245_minPoliced = -1;               /* INTEGER_1_4294967295 */
static int hf_h245_maxPktSize = -1;               /* INTEGER_1_4294967295 */
static int hf_h245_guaranteedQOS = -1;            /* NULL */
static int hf_h245_controlledLoad = -1;           /* NULL */
static int hf_h245_maxNTUSize = -1;               /* INTEGER_0_65535 */
static int hf_h245_atmUBR = -1;                   /* BOOLEAN */
static int hf_h245_atmrtVBR = -1;                 /* BOOLEAN */
static int hf_h245_atmnrtVBR = -1;                /* BOOLEAN */
static int hf_h245_atmABR = -1;                   /* BOOLEAN */
static int hf_h245_atmCBR = -1;                   /* BOOLEAN */
static int hf_h245_nonStandardParameter = -1;     /* NonStandardParameter */
static int hf_h245_value = -1;                    /* INTEGER_0_255 */
static int hf_h245_servicePrioritySignalled = -1;  /* BOOLEAN */
static int hf_h245_servicePriorityValue = -1;     /* ServicePriorityValue */
static int hf_h245_serviceClass = -1;             /* INTEGER_0_4095 */
static int hf_h245_serviceSubclass = -1;          /* INTEGER_0_255 */
static int hf_h245_desired = -1;                  /* NULL */
static int hf_h245_required = -1;                 /* NULL */
static int hf_h245_class0 = -1;                   /* NULL */
static int hf_h245_class1 = -1;                   /* NULL */
static int hf_h245_class2 = -1;                   /* NULL */
static int hf_h245_class3 = -1;                   /* NULL */
static int hf_h245_class4 = -1;                   /* NULL */
static int hf_h245_class5 = -1;                   /* NULL */
static int hf_h245_qosType = -1;                  /* QOSType */
static int hf_h245_qosClass = -1;                 /* QOSClass */
static int hf_h245_averageRate = -1;              /* INTEGER_1_4294967295 */
static int hf_h245_burst = -1;                    /* INTEGER_1_4294967295 */
static int hf_h245_rsvpParameters = -1;           /* RSVPParameters */
static int hf_h245_atmParameters = -1;            /* ATMParameters */
static int hf_h245_localQoS = -1;                 /* BOOLEAN */
static int hf_h245_genericTransportParameters = -1;  /* GenericTransportParameters */
static int hf_h245_servicePriority = -1;          /* ServicePriority */
static int hf_h245_authorizationParameter = -1;   /* AuthorizationParameters */
static int hf_h245_qosDescriptor = -1;            /* QOSDescriptor */
static int hf_h245_dscpValue = -1;                /* INTEGER_0_63 */
static int hf_h245_ip_UDP = -1;                   /* NULL */
static int hf_h245_ip_TCP = -1;                   /* NULL */
static int hf_h245_atm_AAL5_UNIDIR = -1;          /* NULL */
static int hf_h245_atm_AAL5_BIDIR = -1;           /* NULL */
static int hf_h245_atm_AAL5_compressed = -1;      /* T_atm_AAL5_compressed */
static int hf_h245_variable_delta = -1;           /* BOOLEAN */
static int hf_h245_mediaTransport = -1;           /* MediaTransportType */
static int hf_h245_qOSCapabilities = -1;          /* SEQUENCE_SIZE_1_256_OF_QOSCapability */
static int hf_h245_qOSCapabilities_item = -1;     /* QOSCapability */
static int hf_h245_mediaChannelCapabilities = -1;  /* SEQUENCE_SIZE_1_256_OF_MediaChannelCapability */
static int hf_h245_mediaChannelCapabilities_item = -1;  /* MediaChannelCapability */
static int hf_h245_redundancyEncodingMethod = -1;  /* RedundancyEncodingMethod */
static int hf_h245_primaryEncoding = -1;          /* CapabilityTableEntryNumber */
static int hf_h245_secondaryEncodingCapability = -1;  /* SEQUENCE_SIZE_1_256_OF_CapabilityTableEntryNumber */
static int hf_h245_secondaryEncodingCapability_item = -1;  /* CapabilityTableEntryNumber */
static int hf_h245_rtpAudioRedundancyEncoding = -1;  /* NULL */
static int hf_h245_rtpH263VideoRedundancyEncoding = -1;  /* RTPH263VideoRedundancyEncoding */
static int hf_h245_numberOfThreads = -1;          /* INTEGER_1_16 */
static int hf_h245_framesBetweenSyncPoints = -1;  /* INTEGER_1_256 */
static int hf_h245_frameToThreadMapping = -1;     /* T_frameToThreadMapping */
static int hf_h245_roundrobin = -1;               /* NULL */
static int hf_h245_custom = -1;                   /* SEQUENCE_SIZE_1_256_OF_RTPH263VideoRedundancyFrameMapping */
static int hf_h245_custom_item = -1;              /* RTPH263VideoRedundancyFrameMapping */
static int hf_h245_containedThreads = -1;         /* T_containedThreads */
static int hf_h245_containedThreads_item = -1;    /* INTEGER_0_15 */
static int hf_h245_threadNumber = -1;             /* INTEGER_0_15 */
static int hf_h245_frameSequence = -1;            /* T_frameSequence */
static int hf_h245_frameSequence_item = -1;       /* INTEGER_0_255 */
static int hf_h245_multicastCapability = -1;      /* BOOLEAN */
static int hf_h245_multiUniCastConference = -1;   /* BOOLEAN */
static int hf_h245_mediaDistributionCapability = -1;  /* SEQUENCE_OF_MediaDistributionCapability */
static int hf_h245_mediaDistributionCapability_item = -1;  /* MediaDistributionCapability */
static int hf_h245_centralizedControl = -1;       /* BOOLEAN */
static int hf_h245_distributedControl = -1;       /* BOOLEAN */
static int hf_h245_centralizedAudio = -1;         /* BOOLEAN */
static int hf_h245_distributedAudio = -1;         /* BOOLEAN */
static int hf_h245_centralizedVideo = -1;         /* BOOLEAN */
static int hf_h245_distributedVideo = -1;         /* BOOLEAN */
static int hf_h245_centralizedData = -1;          /* SEQUENCE_OF_DataApplicationCapability */
static int hf_h245_centralizedData_item = -1;     /* DataApplicationCapability */
static int hf_h245_distributedData = -1;          /* SEQUENCE_OF_DataApplicationCapability */
static int hf_h245_distributedData_item = -1;     /* DataApplicationCapability */
static int hf_h245_h261VideoCapability = -1;      /* H261VideoCapability */
static int hf_h245_h262VideoCapability = -1;      /* H262VideoCapability */
static int hf_h245_h263VideoCapability = -1;      /* H263VideoCapability */
static int hf_h245_is11172VideoCapability = -1;   /* IS11172VideoCapability */
static int hf_h245_genericVideoCapability = -1;   /* GenericCapability */
static int hf_h245_extendedVideoCapability = -1;  /* ExtendedVideoCapability */
static int hf_h245_videoCapability = -1;          /* SEQUENCE_OF_VideoCapability */
static int hf_h245_videoCapability_item = -1;     /* VideoCapability */
static int hf_h245_videoCapabilityExtension = -1;  /* SEQUENCE_OF_GenericCapability */
static int hf_h245_videoCapabilityExtension_item = -1;  /* GenericCapability */
static int hf_h245_qcifMPI_1_4 = -1;              /* INTEGER_1_4 */
static int hf_h245_cifMPI_1_4 = -1;               /* INTEGER_1_4 */
static int hf_h245_temporalSpatialTradeOffCapability = -1;  /* BOOLEAN */
static int hf_h245_maxBitRate_1_19200 = -1;       /* INTEGER_1_19200 */
static int hf_h245_stillImageTransmission = -1;   /* BOOLEAN */
static int hf_h245_videoBadMBsCap = -1;           /* BOOLEAN */
static int hf_h245_profileAndLevel_SPatML = -1;   /* BOOLEAN */
static int hf_h245_profileAndLevel_MPatLL = -1;   /* BOOLEAN */
static int hf_h245_profileAndLevel_MPatML = -1;   /* BOOLEAN */
static int hf_h245_profileAndLevel_MPatH_14 = -1;  /* BOOLEAN */
static int hf_h245_profileAndLevel_MPatHL = -1;   /* BOOLEAN */
static int hf_h245_profileAndLevel_SNRatLL = -1;  /* BOOLEAN */
static int hf_h245_profileAndLevel_SNRatML = -1;  /* BOOLEAN */
static int hf_h245_profileAndLevel_SpatialatH_14 = -1;  /* BOOLEAN */
static int hf_h245_profileAndLevel_HPatML = -1;   /* BOOLEAN */
static int hf_h245_profileAndLevel_HPatH_14 = -1;  /* BOOLEAN */
static int hf_h245_profileAndLevel_HPatHL = -1;   /* BOOLEAN */
static int hf_h245_videoBitRate = -1;             /* INTEGER_0_1073741823 */
static int hf_h245_vbvBufferSize = -1;            /* INTEGER_0_262143 */
static int hf_h245_samplesPerLine = -1;           /* INTEGER_0_16383 */
static int hf_h245_linesPerFrame = -1;            /* INTEGER_0_16383 */
static int hf_h245_framesPerSecond = -1;          /* INTEGER_0_15 */
static int hf_h245_luminanceSampleRate = -1;      /* INTEGER_0_4294967295 */
static int hf_h245_sqcifMPI_1_32 = -1;            /* INTEGER_1_32 */
static int hf_h245_qcifMPI = -1;                  /* INTEGER_1_32 */
static int hf_h245_cifMPI = -1;                   /* INTEGER_1_32 */
static int hf_h245_cif4MPI_1_32 = -1;             /* INTEGER_1_32 */
static int hf_h245_cif16MPI_1_32 = -1;            /* INTEGER_1_32 */
static int hf_h245_maxBitRate = -1;               /* INTEGER_1_192400 */
static int hf_h245_unrestrictedVector = -1;       /* BOOLEAN */
static int hf_h245_arithmeticCoding = -1;         /* BOOLEAN */
static int hf_h245_advancedPrediction = -1;       /* BOOLEAN */
static int hf_h245_pbFrames = -1;                 /* BOOLEAN */
static int hf_h245_hrd_B = -1;                    /* INTEGER_0_524287 */
static int hf_h245_bppMaxKb = -1;                 /* INTEGER_0_65535 */
static int hf_h245_slowSqcifMPI = -1;             /* INTEGER_1_3600 */
static int hf_h245_slowQcifMPI = -1;              /* INTEGER_1_3600 */
static int hf_h245_slowCifMPI = -1;               /* INTEGER_1_3600 */
static int hf_h245_slowCif4MPI = -1;              /* INTEGER_1_3600 */
static int hf_h245_slowCif16MPI = -1;             /* INTEGER_1_3600 */
static int hf_h245_errorCompensation = -1;        /* BOOLEAN */
static int hf_h245_enhancementLayerInfo = -1;     /* EnhancementLayerInfo */
static int hf_h245_h263Options = -1;              /* H263Options */
static int hf_h245_baseBitRateConstrained = -1;   /* BOOLEAN */
static int hf_h245_snrEnhancement = -1;           /* SET_SIZE_1_14_OF_EnhancementOptions */
static int hf_h245_snrEnhancement_item = -1;      /* EnhancementOptions */
static int hf_h245_spatialEnhancement = -1;       /* SET_SIZE_1_14_OF_EnhancementOptions */
static int hf_h245_spatialEnhancement_item = -1;  /* EnhancementOptions */
static int hf_h245_bPictureEnhancement = -1;      /* SET_SIZE_1_14_OF_BEnhancementParameters */
static int hf_h245_bPictureEnhancement_item = -1;  /* BEnhancementParameters */
static int hf_h245_enhancementOptions = -1;       /* EnhancementOptions */
static int hf_h245_numberOfBPictures = -1;        /* INTEGER_1_64 */
static int hf_h245_advancedIntraCodingMode = -1;  /* BOOLEAN */
static int hf_h245_deblockingFilterMode = -1;     /* BOOLEAN */
static int hf_h245_improvedPBFramesMode = -1;     /* BOOLEAN */
static int hf_h245_unlimitedMotionVectors = -1;   /* BOOLEAN */
static int hf_h245_fullPictureFreeze = -1;        /* BOOLEAN */
static int hf_h245_partialPictureFreezeAndRelease = -1;  /* BOOLEAN */
static int hf_h245_resizingPartPicFreezeAndRelease = -1;  /* BOOLEAN */
static int hf_h245_fullPictureSnapshot = -1;      /* BOOLEAN */
static int hf_h245_partialPictureSnapshot = -1;   /* BOOLEAN */
static int hf_h245_videoSegmentTagging = -1;      /* BOOLEAN */
static int hf_h245_progressiveRefinement = -1;    /* BOOLEAN */
static int hf_h245_dynamicPictureResizingByFour = -1;  /* BOOLEAN */
static int hf_h245_dynamicPictureResizingSixteenthPel = -1;  /* BOOLEAN */
static int hf_h245_dynamicWarpingHalfPel = -1;    /* BOOLEAN */
static int hf_h245_dynamicWarpingSixteenthPel = -1;  /* BOOLEAN */
static int hf_h245_independentSegmentDecoding = -1;  /* BOOLEAN */
static int hf_h245_slicesInOrder_NonRect = -1;    /* BOOLEAN */
static int hf_h245_slicesInOrder_Rect = -1;       /* BOOLEAN */
static int hf_h245_slicesNoOrder_NonRect = -1;    /* BOOLEAN */
static int hf_h245_slicesNoOrder_Rect = -1;       /* BOOLEAN */
static int hf_h245_alternateInterVLCMode = -1;    /* BOOLEAN */
static int hf_h245_modifiedQuantizationMode = -1;  /* BOOLEAN */
static int hf_h245_reducedResolutionUpdate = -1;  /* BOOLEAN */
static int hf_h245_transparencyParameters = -1;   /* TransparencyParameters */
static int hf_h245_separateVideoBackChannel = -1;  /* BOOLEAN */
static int hf_h245_refPictureSelection = -1;      /* RefPictureSelection */
static int hf_h245_customPictureClockFrequency = -1;  /* SET_SIZE_1_16_OF_CustomPictureClockFrequency */
static int hf_h245_customPictureClockFrequency_item = -1;  /* CustomPictureClockFrequency */
static int hf_h245_customPictureFormat = -1;      /* SET_SIZE_1_16_OF_CustomPictureFormat */
static int hf_h245_customPictureFormat_item = -1;  /* CustomPictureFormat */
static int hf_h245_modeCombos = -1;               /* SET_SIZE_1_16_OF_H263VideoModeCombos */
static int hf_h245_modeCombos_item = -1;          /* H263VideoModeCombos */
static int hf_h245_h263Version3Options = -1;      /* H263Version3Options */
static int hf_h245_presentationOrder = -1;        /* INTEGER_1_256 */
static int hf_h245_offset_x = -1;                 /* INTEGER_M262144_262143 */
static int hf_h245_offset_y = -1;                 /* INTEGER_M262144_262143 */
static int hf_h245_scale_x = -1;                  /* INTEGER_1_255 */
static int hf_h245_scale_y = -1;                  /* INTEGER_1_255 */
static int hf_h245_additionalPictureMemory = -1;  /* T_additionalPictureMemory */
static int hf_h245_sqcifAdditionalPictureMemory = -1;  /* INTEGER_1_256 */
static int hf_h245_qcifAdditionalPictureMemory = -1;  /* INTEGER_1_256 */
static int hf_h245_cifAdditionalPictureMemory = -1;  /* INTEGER_1_256 */
static int hf_h245_cif4AdditionalPictureMemory = -1;  /* INTEGER_1_256 */
static int hf_h245_cif16AdditionalPictureMemory = -1;  /* INTEGER_1_256 */
static int hf_h245_bigCpfAdditionalPictureMemory = -1;  /* INTEGER_1_256 */
static int hf_h245_videoMux = -1;                 /* BOOLEAN */
static int hf_h245_videoBackChannelSend = -1;     /* T_videoBackChannelSend */
static int hf_h245_none = -1;                     /* NULL */
static int hf_h245_ackMessageOnly = -1;           /* NULL */
static int hf_h245_nackMessageOnly = -1;          /* NULL */
static int hf_h245_ackOrNackMessageOnly = -1;     /* NULL */
static int hf_h245_ackAndNackMessage = -1;        /* NULL */
static int hf_h245_enhancedReferencePicSelect = -1;  /* T_enhancedReferencePicSelect */
static int hf_h245_subPictureRemovalParameters = -1;  /* T_subPictureRemovalParameters */
static int hf_h245_mpuHorizMBs = -1;              /* INTEGER_1_128 */
static int hf_h245_mpuVertMBs = -1;               /* INTEGER_1_72 */
static int hf_h245_mpuTotalNumber = -1;           /* INTEGER_1_65536 */
static int hf_h245_clockConversionCode = -1;      /* INTEGER_1000_1001 */
static int hf_h245_clockDivisor = -1;             /* INTEGER_1_127 */
static int hf_h245_sqcifMPI = -1;                 /* INTEGER_1_2048 */
static int hf_h245_qcifMPI_1_2048 = -1;           /* INTEGER_1_2048 */
static int hf_h245_cifMPI2_1_2048 = -1;           /* INTEGER_1_2048 */
static int hf_h245_cif4MPI = -1;                  /* INTEGER_1_2048 */
static int hf_h245_cif16MPI = -1;                 /* INTEGER_1_2048 */
static int hf_h245_maxCustomPictureWidth = -1;    /* INTEGER_1_2048 */
static int hf_h245_maxCustomPictureHeight = -1;   /* INTEGER_1_2048 */
static int hf_h245_minCustomPictureWidth = -1;    /* INTEGER_1_2048 */
static int hf_h245_minCustomPictureHeight = -1;   /* INTEGER_1_2048 */
static int hf_h245_mPI = -1;                      /* T_mPI */
static int hf_h245_standardMPI = -1;              /* INTEGER_1_31 */
static int hf_h245_customPCF = -1;                /* T_customPCF */
static int hf_h245_customPCF_item = -1;           /* T_customPCF_item */
static int hf_h245_customMPI = -1;                /* INTEGER_1_2048 */
static int hf_h245_pixelAspectInformation = -1;   /* T_pixelAspectInformation */
static int hf_h245_anyPixelAspectRatio = -1;      /* BOOLEAN */
static int hf_h245_pixelAspectCode = -1;          /* T_pixelAspectCode */
static int hf_h245_pixelAspectCode_item = -1;     /* INTEGER_1_14 */
static int hf_h245_extendedPAR = -1;              /* T_extendedPAR */
static int hf_h245_extendedPAR_item = -1;         /* T_extendedPAR_item */
static int hf_h245_width = -1;                    /* INTEGER_1_255 */
static int hf_h245_height = -1;                   /* INTEGER_1_255 */
static int hf_h245_h263VideoUncoupledModes = -1;  /* H263ModeComboFlags */
static int hf_h245_h263VideoCoupledModes = -1;    /* SET_SIZE_1_16_OF_H263ModeComboFlags */
static int hf_h245_h263VideoCoupledModes_item = -1;  /* H263ModeComboFlags */
static int hf_h245_referencePicSelect = -1;       /* BOOLEAN */
static int hf_h245_enhancedReferencePicSelectBool = -1;  /* BOOLEAN */
static int hf_h245_dataPartitionedSlices = -1;    /* BOOLEAN */
static int hf_h245_fixedPointIDCT0 = -1;          /* BOOLEAN */
static int hf_h245_interlacedFields = -1;         /* BOOLEAN */
static int hf_h245_currentPictureHeaderRepetition = -1;  /* BOOLEAN */
static int hf_h245_previousPictureHeaderRepetition = -1;  /* BOOLEAN */
static int hf_h245_nextPictureHeaderRepetition = -1;  /* BOOLEAN */
static int hf_h245_pictureNumberBoolean = -1;     /* BOOLEAN */
static int hf_h245_spareReferencePictures = -1;   /* BOOLEAN */
static int hf_h245_constrainedBitstream = -1;     /* BOOLEAN */
static int hf_h245_pictureRate = -1;              /* INTEGER_0_15 */
static int hf_h245_g711Alaw64k = -1;              /* INTEGER_1_256 */
static int hf_h245_g711Alaw56k = -1;              /* INTEGER_1_256 */
static int hf_h245_g711Ulaw64k = -1;              /* INTEGER_1_256 */
static int hf_h245_g711Ulaw56k = -1;              /* INTEGER_1_256 */
static int hf_h245_g722_64k = -1;                 /* INTEGER_1_256 */
static int hf_h245_g722_56k = -1;                 /* INTEGER_1_256 */
static int hf_h245_g722_48k = -1;                 /* INTEGER_1_256 */
static int hf_h245_g7231 = -1;                    /* T_g7231 */
static int hf_h245_maxAl_sduAudioFrames = -1;     /* INTEGER_1_256 */
static int hf_h245_silenceSuppression = -1;       /* BOOLEAN */
static int hf_h245_g728 = -1;                     /* INTEGER_1_256 */
static int hf_h245_g729 = -1;                     /* INTEGER_1_256 */
static int hf_h245_g729AnnexA = -1;               /* INTEGER_1_256 */
static int hf_h245_is11172AudioCapability = -1;   /* IS11172AudioCapability */
static int hf_h245_is13818AudioCapability = -1;   /* IS13818AudioCapability */
static int hf_h245_g729wAnnexB = -1;              /* INTEGER_1_256 */
static int hf_h245_g729AnnexAwAnnexB = -1;        /* INTEGER_1_256 */
static int hf_h245_g7231AnnexCCapability = -1;    /* G7231AnnexCCapability */
static int hf_h245_gsmFullRate = -1;              /* GSMAudioCapability */
static int hf_h245_gsmHalfRate = -1;              /* GSMAudioCapability */
static int hf_h245_gsmEnhancedFullRate = -1;      /* GSMAudioCapability */
static int hf_h245_genericAudioCapability = -1;   /* GenericCapability */
static int hf_h245_g729Extensions = -1;           /* G729Extensions */
static int hf_h245_vbd = -1;                      /* VBDCapability */
static int hf_h245_audioTelephonyEvent = -1;      /* NoPTAudioTelephonyEventCapability */
static int hf_h245_audioTone = -1;                /* NoPTAudioToneCapability */
static int hf_h245_audioUnit = -1;                /* INTEGER_1_256 */
static int hf_h245_annexA = -1;                   /* BOOLEAN */
static int hf_h245_annexB = -1;                   /* BOOLEAN */
static int hf_h245_annexD = -1;                   /* BOOLEAN */
static int hf_h245_annexE = -1;                   /* BOOLEAN */
static int hf_h245_annexF = -1;                   /* BOOLEAN */
static int hf_h245_annexG = -1;                   /* BOOLEAN */
static int hf_h245_annexH = -1;                   /* BOOLEAN */
static int hf_h245_highRateMode0 = -1;            /* INTEGER_27_78 */
static int hf_h245_highRateMode1 = -1;            /* INTEGER_27_78 */
static int hf_h245_lowRateMode0 = -1;             /* INTEGER_23_66 */
static int hf_h245_lowRateMode1 = -1;             /* INTEGER_23_66 */
static int hf_h245_sidMode0 = -1;                 /* INTEGER_6_17 */
static int hf_h245_sidMode1 = -1;                 /* INTEGER_6_17 */
static int hf_h245_g723AnnexCAudioMode = -1;      /* G723AnnexCAudioMode */
static int hf_h245_audioLayer1 = -1;              /* BOOLEAN */
static int hf_h245_audioLayer2 = -1;              /* BOOLEAN */
static int hf_h245_audioLayer3 = -1;              /* BOOLEAN */
static int hf_h245_audioSampling32k = -1;         /* BOOLEAN */
static int hf_h245_audioSampling44k1 = -1;        /* BOOLEAN */
static int hf_h245_audioSampling48k = -1;         /* BOOLEAN */
static int hf_h245_singleChannel = -1;            /* BOOLEAN */
static int hf_h245_twoChannels = -1;              /* BOOLEAN */
static int hf_h245_bitRate_1_448 = -1;            /* INTEGER_1_448 */
static int hf_h245_audioSampling16k = -1;         /* BOOLEAN */
static int hf_h245_audioSampling22k05 = -1;       /* BOOLEAN */
static int hf_h245_audioSampling24k = -1;         /* BOOLEAN */
static int hf_h245_threeChannels2_1 = -1;         /* BOOLEAN */
static int hf_h245_threeChannels3_0 = -1;         /* BOOLEAN */
static int hf_h245_fourChannels2_0_2_0 = -1;      /* BOOLEAN */
static int hf_h245_fourChannels2_2 = -1;          /* BOOLEAN */
static int hf_h245_fourChannels3_1 = -1;          /* BOOLEAN */
static int hf_h245_fiveChannels3_0_2_0 = -1;      /* BOOLEAN */
static int hf_h245_fiveChannels3_2 = -1;          /* BOOLEAN */
static int hf_h245_lowFrequencyEnhancement = -1;  /* BOOLEAN */
static int hf_h245_multilingual = -1;             /* BOOLEAN */
static int hf_h245_bitRate2_1_1130 = -1;          /* INTEGER_1_1130 */
static int hf_h245_audioUnitSize = -1;            /* INTEGER_1_256 */
static int hf_h245_comfortNoise = -1;             /* BOOLEAN */
static int hf_h245_scrambled = -1;                /* BOOLEAN */
static int hf_h245_vbd_cap_type = -1;             /* AudioCapability */
static int hf_h245_t120 = -1;                     /* DataProtocolCapability */
static int hf_h245_dsm_cc = -1;                   /* DataProtocolCapability */
static int hf_h245_userData = -1;                 /* DataProtocolCapability */
static int hf_h245_t84 = -1;                      /* T_t84 */
static int hf_h245_t84Protocol = -1;              /* DataProtocolCapability */
static int hf_h245_t84Profile = -1;               /* T84Profile */
static int hf_h245_t434 = -1;                     /* DataProtocolCapability */
static int hf_h245_h224 = -1;                     /* DataProtocolCapability */
static int hf_h245_nlpidProtocol = -1;            /* DataProtocolCapability */
static int hf_h245_nlpidData = -1;                /* OCTET_STRING */
static int hf_h245_nlpid = -1;                    /* Nlpid */
static int hf_h245_dsvdControl = -1;              /* NULL */
static int hf_h245_h222DataPartitioning = -1;     /* DataProtocolCapability */
static int hf_h245_t30fax = -1;                   /* DataProtocolCapability */
static int hf_h245_t140 = -1;                     /* DataProtocolCapability */
static int hf_h245_t38fax = -1;                   /* T_t38fax */
static int hf_h245_t38FaxProtocol = -1;           /* DataProtocolCapability */
static int hf_h245_t38FaxProfile = -1;            /* T38FaxProfile */
static int hf_h245_genericDataCapability = -1;    /* GenericCapability */
static int hf_h245_application = -1;              /* Application */
static int hf_h245_maxBitRate2_0_4294967295 = -1;  /* INTEGER_0_4294967295 */
static int hf_h245_v14buffered = -1;              /* NULL */
static int hf_h245_v42lapm = -1;                  /* NULL */
static int hf_h245_hdlcFrameTunnelling = -1;      /* NULL */
static int hf_h245_h310SeparateVCStack = -1;      /* NULL */
static int hf_h245_h310SingleVCStack = -1;        /* NULL */
static int hf_h245_transparent = -1;              /* NULL */
static int hf_h245_segmentationAndReassembly = -1;  /* NULL */
static int hf_h245_hdlcFrameTunnelingwSAR = -1;   /* NULL */
static int hf_h245_v120 = -1;                     /* NULL */
static int hf_h245_separateLANStack = -1;         /* NULL */
static int hf_h245_v76wCompression = -1;          /* T_v76wCompression */
static int hf_h245_transmitCompression = -1;      /* CompressionType */
static int hf_h245_receiveCompression = -1;       /* CompressionType */
static int hf_h245_transmitAndReceiveCompression = -1;  /* CompressionType */
static int hf_h245_tcp = -1;                      /* NULL */
static int hf_h245_udp = -1;                      /* NULL */
static int hf_h245_v42bis = -1;                   /* V42bis */
static int hf_h245_numberOfCodewords = -1;        /* INTEGER_1_65536 */
static int hf_h245_maximumStringLength = -1;      /* INTEGER_1_256 */
static int hf_h245_t84Unrestricted = -1;          /* NULL */
static int hf_h245_t84Restricted = -1;            /* T_t84Restricted */
static int hf_h245_qcif_bool = -1;                /* BOOLEAN */
static int hf_h245_cif_bool = -1;                 /* BOOLEAN */
static int hf_h245_ccir601Seq = -1;               /* BOOLEAN */
static int hf_h245_ccir601Prog = -1;              /* BOOLEAN */
static int hf_h245_hdtvSeq = -1;                  /* BOOLEAN */
static int hf_h245_hdtvProg = -1;                 /* BOOLEAN */
static int hf_h245_g3FacsMH200x100 = -1;          /* BOOLEAN */
static int hf_h245_g3FacsMH200x200 = -1;          /* BOOLEAN */
static int hf_h245_g4FacsMMR200x100 = -1;         /* BOOLEAN */
static int hf_h245_g4FacsMMR200x200 = -1;         /* BOOLEAN */
static int hf_h245_jbig200x200Seq = -1;           /* BOOLEAN */
static int hf_h245_jbig200x200Prog = -1;          /* BOOLEAN */
static int hf_h245_jbig300x300Seq = -1;           /* BOOLEAN */
static int hf_h245_jbig300x300Prog = -1;          /* BOOLEAN */
static int hf_h245_digPhotoLow = -1;              /* BOOLEAN */
static int hf_h245_digPhotoMedSeq = -1;           /* BOOLEAN */
static int hf_h245_digPhotoMedProg = -1;          /* BOOLEAN */
static int hf_h245_digPhotoHighSeq = -1;          /* BOOLEAN */
static int hf_h245_digPhotoHighProg = -1;         /* BOOLEAN */
static int hf_h245_fillBitRemoval = -1;           /* BOOLEAN */
static int hf_h245_transcodingJBIG = -1;          /* BOOLEAN */
static int hf_h245_transcodingMMR = -1;           /* BOOLEAN */
static int hf_h245_version = -1;                  /* INTEGER_0_255 */
static int hf_h245_t38FaxRateManagement = -1;     /* T38FaxRateManagement */
static int hf_h245_t38FaxUdpOptions = -1;         /* T38FaxUdpOptions */
static int hf_h245_t38FaxTcpOptions = -1;         /* T38FaxTcpOptions */
static int hf_h245_localTCF = -1;                 /* NULL */
static int hf_h245_transferredTCF = -1;           /* NULL */
static int hf_h245_t38FaxMaxBuffer = -1;          /* INTEGER */
static int hf_h245_t38FaxMaxDatagram = -1;        /* INTEGER */
static int hf_h245_t38FaxUdpEC = -1;              /* T_t38FaxUdpEC */
static int hf_h245_t38UDPFEC = -1;                /* NULL */
static int hf_h245_t38UDPRedundancy = -1;         /* NULL */
static int hf_h245_t38TCPBidirectionalMode = -1;  /* BOOLEAN */
static int hf_h245_encryptionCapability = -1;     /* EncryptionCapability */
static int hf_h245_authenticationCapability = -1;  /* AuthenticationCapability */
static int hf_h245_integrityCapability = -1;      /* IntegrityCapability */
static int hf_h245_genericH235SecurityCapability = -1;  /* GenericCapability */
static int hf_h245_EncryptionCapability_item = -1;  /* MediaEncryptionAlgorithm */
static int hf_h245_algorithm = -1;                /* OBJECT_IDENTIFIER */
static int hf_h245_antiSpamAlgorithm = -1;        /* OBJECT_IDENTIFIER */
static int hf_h245_ui_nonStandard = -1;           /* SEQUENCE_SIZE_1_16_OF_NonStandardParameter */
static int hf_h245_ui_nonStandard_item = -1;      /* NonStandardParameter */
static int hf_h245_basicString = -1;              /* NULL */
static int hf_h245_iA5String = -1;                /* NULL */
static int hf_h245_generalString = -1;            /* NULL */
static int hf_h245_dtmf = -1;                     /* NULL */
static int hf_h245_hookflash = -1;                /* NULL */
static int hf_h245_extendedAlphanumericFlag = -1;  /* NULL */
static int hf_h245_encryptedBasicString = -1;     /* NULL */
static int hf_h245_encryptedIA5String = -1;       /* NULL */
static int hf_h245_encryptedGeneralString = -1;   /* NULL */
static int hf_h245_secureDTMF = -1;               /* NULL */
static int hf_h245_genericUserInputCapability = -1;  /* GenericCapability */
static int hf_h245_nonStandardParams = -1;        /* SEQUENCE_OF_NonStandardParameter */
static int hf_h245_nonStandardParams_item = -1;   /* NonStandardParameter */
static int hf_h245_chairControlCapability = -1;   /* BOOLEAN */
static int hf_h245_videoIndicateMixingCapability = -1;  /* BOOLEAN */
static int hf_h245_multipointVisualizationCapability = -1;  /* BOOLEAN */
static int hf_h245_capabilityIdentifier = -1;     /* CapabilityIdentifier */
static int hf_h245_collapsing = -1;               /* T_collapsing */
static int hf_h245_collapsing_item = -1;          /* T_collapsing_item */
static int hf_h245_nonCollapsing = -1;            /* T_nonCollapsing */
static int hf_h245_nonCollapsing_item = -1;       /* T_nonCollapsing_item */
static int hf_h245_nonCollapsingRaw = -1;         /* T_nonCollapsingRaw */
static int hf_h245_transport = -1;                /* DataProtocolCapability */
static int hf_h245_standardOid = -1;              /* T_standardOid */
static int hf_h245_h221NonStandard = -1;          /* NonStandardParameter */
static int hf_h245_uuid = -1;                     /* OCTET_STRING_SIZE_16 */
static int hf_h245_domainBased = -1;              /* IA5String_SIZE_1_64 */
static int hf_h245_parameterIdentifier = -1;      /* ParameterIdentifier */
static int hf_h245_parameterValue = -1;           /* ParameterValue */
static int hf_h245_supersedes = -1;               /* SEQUENCE_OF_ParameterIdentifier */
static int hf_h245_supersedes_item = -1;          /* ParameterIdentifier */
static int hf_h245_standard = -1;                 /* T_standard */
static int hf_h245_logical = -1;                  /* NULL */
static int hf_h245_booleanArray = -1;             /* T_booleanArray */
static int hf_h245_unsignedMin = -1;              /* T_unsignedMin */
static int hf_h245_unsignedMax = -1;              /* T_unsignedMax */
static int hf_h245_unsigned32Min = -1;            /* T_unsigned32Min */
static int hf_h245_unsigned32Max = -1;            /* T_unsigned32Max */
static int hf_h245_octetString = -1;              /* T_octetString */
static int hf_h245_genericParameters = -1;        /* SEQUENCE_OF_GenericParameter */
static int hf_h245_genericParameters_item = -1;   /* GenericParameter */
static int hf_h245_multiplexFormat = -1;          /* MultiplexFormat */
static int hf_h245_controlOnMuxStream = -1;       /* BOOLEAN */
static int hf_h245_capabilityOnMuxStream = -1;    /* SET_SIZE_1_256_OF_AlternativeCapabilitySet */
static int hf_h245_capabilityOnMuxStream_item = -1;  /* AlternativeCapabilitySet */
static int hf_h245_dynamicRTPPayloadType = -1;    /* INTEGER_96_127 */
static int hf_h245_audioTelephoneEvent = -1;      /* GeneralString */
static int hf_h245_capabilities = -1;             /* SET_SIZE_1_256_OF_AlternativeCapabilitySet */
static int hf_h245_capabilities_item = -1;        /* AlternativeCapabilitySet */
static int hf_h245_fecc_rfc2733 = -1;             /* FECC_rfc2733 */
static int hf_h245_redundancyEncodingBool = -1;   /* BOOLEAN */
static int hf_h245_separateStreamBool = -1;       /* T_separateStreamBool */
static int hf_h245_separatePort = -1;             /* BOOLEAN */
static int hf_h245_samePortBool = -1;             /* BOOLEAN */
static int hf_h245_protectedCapability = -1;      /* CapabilityTableEntryNumber */
static int hf_h245_fecScheme = -1;                /* OBJECT_IDENTIFIER */
static int hf_h245_rfc2733rfc2198 = -1;           /* MaxRedundancy */
static int hf_h245_rfc2733sameport = -1;          /* MaxRedundancy */
static int hf_h245_rfc2733diffport = -1;          /* MaxRedundancy */
static int hf_h245_rfc2733Format = -1;            /* Rfc2733Format */
static int hf_h245_olc_fw_lcn = -1;               /* OLC_fw_lcn */
static int hf_h245_forwardLogicalChannelParameters = -1;  /* T_forwardLogicalChannelParameters */
static int hf_h245_portNumber = -1;               /* INTEGER_0_65535 */
static int hf_h245_dataType = -1;                 /* DataType */
static int hf_h245_olc_forw_multiplexParameters = -1;  /* OLC_forw_multiplexParameters */
static int hf_h245_h222LogicalChannelParameters = -1;  /* H222LogicalChannelParameters */
static int hf_h245_olc_fw_h223_params = -1;       /* OLC_fw_h223_params */
static int hf_h245_v76LogicalChannelParameters = -1;  /* V76LogicalChannelParameters */
static int hf_h245_h2250LogicalChannelParameters = -1;  /* H2250LogicalChannelParameters */
static int hf_h245_forwardLogicalChannelDependency = -1;  /* LogicalChannelNumber */
static int hf_h245_replacementFor = -1;           /* LogicalChannelNumber */
static int hf_h245_reverseLogicalChannelParameters = -1;  /* OLC_reverseLogicalChannelParameters */
static int hf_h245_olc_rev_multiplexParameter = -1;  /* OLC_rev_multiplexParameters */
static int hf_h245_olc_rev_h223_params = -1;      /* OLC_rev_h223_params */
static int hf_h245_reverseLogicalChannelDependency = -1;  /* LogicalChannelNumber */
static int hf_h245_separateStack = -1;            /* NetworkAccessParameters */
static int hf_h245_encryptionSync = -1;           /* EncryptionSync */
static int hf_h245_distribution = -1;             /* T_distribution */
static int hf_h245_unicast = -1;                  /* NULL */
static int hf_h245_multicast = -1;                /* NULL */
static int hf_h245_networkAddress = -1;           /* T_networkAddress */
static int hf_h245_q2931Address = -1;             /* Q2931Address */
static int hf_h245_e164Address = -1;              /* T_e164Address */
static int hf_h245_localAreaAddress = -1;         /* TransportAddress */
static int hf_h245_associateConference = -1;      /* BOOLEAN */
static int hf_h245_externalReference = -1;        /* OCTET_STRING_SIZE_1_255 */
static int hf_h245_t120SetupProcedure = -1;       /* T_t120SetupProcedure */
static int hf_h245_originateCall = -1;            /* NULL */
static int hf_h245_waitForCall = -1;              /* NULL */
static int hf_h245_issueQuery = -1;               /* NULL */
static int hf_h245_address = -1;                  /* T_address */
static int hf_h245_internationalNumber = -1;      /* NumericString_SIZE_1_16 */
static int hf_h245_nsapAddress = -1;              /* OCTET_STRING_SIZE_1_20 */
static int hf_h245_subaddress = -1;               /* OCTET_STRING_SIZE_1_20 */
static int hf_h245_audioHeaderPresent = -1;       /* BOOLEAN */
static int hf_h245_nullData = -1;                 /* NULL */
static int hf_h245_videoData = -1;                /* VideoCapability */
static int hf_h245_audioData = -1;                /* AudioCapability */
static int hf_h245_data = -1;                     /* DataApplicationCapability */
static int hf_h245_encryptionData = -1;           /* EncryptionMode */
static int hf_h245_h235Control = -1;              /* NonStandardParameter */
static int hf_h245_h235Media = -1;                /* H235Media */
static int hf_h245_multiplexedStream = -1;        /* MultiplexedStreamParameter */
static int hf_h245_redundancyEncoding = -1;       /* RedundancyEncoding */
static int hf_h245_multiplePayloadStream = -1;    /* MultiplePayloadStream */
static int hf_h245_depFec = -1;                   /* DepFECData */
static int hf_h245_fec = -1;                      /* FECData */
static int hf_h245_mediaType = -1;                /* T_mediaType */
static int hf_h245_resourceID = -1;               /* INTEGER_0_65535 */
static int hf_h245_subChannelID = -1;             /* INTEGER_0_8191 */
static int hf_h245_pcr_pid = -1;                  /* INTEGER_0_8191 */
static int hf_h245_programDescriptors = -1;       /* OCTET_STRING */
static int hf_h245_streamDescriptors = -1;        /* OCTET_STRING */
static int hf_h245_adaptationLayerType = -1;      /* T_adaptationLayerType */
static int hf_h245_h223_al_type_al1Framed = -1;   /* T_h223_al_type_al1Framed */
static int hf_h245_h223_al_type_al1NotFramed = -1;  /* T_h223_al_type_al1NotFramed */
static int hf_h245_h223_al_type_al2WithoutSequenceNumbers = -1;  /* T_h223_al_type_al2WithoutSequenceNumbers */
static int hf_h245_h223_al_type_al2WithSequenceNumbers = -1;  /* T_h223_al_type_al2WithSequenceNumbers */
static int hf_h245_controlFieldOctets = -1;       /* T_controlFieldOctets */
static int hf_h245_al3_sendBufferSize = -1;       /* T_al3_sendBufferSize */
static int hf_h245_h223_al_type_al3 = -1;         /* T_h223_al_type_al3 */
static int hf_h245_h223_al_type_al1M = -1;        /* T_h223_al_type_al1M */
static int hf_h245_h223_al_type_al2M = -1;        /* T_h223_al_type_al2M */
static int hf_h245_h223_al_type_al3M = -1;        /* T_h223_al_type_al3M */
static int hf_h245_h223_lc_segmentableFlag = -1;  /* T_h223_lc_segmentableFlag */
static int hf_h245_transferMode = -1;             /* T_transferMode */
static int hf_h245_framed = -1;                   /* NULL */
static int hf_h245_unframed = -1;                 /* NULL */
static int hf_h245_aL1HeaderFEC = -1;             /* AL1HeaderFEC */
static int hf_h245_sebch16_7 = -1;                /* NULL */
static int hf_h245_golay24_12 = -1;               /* NULL */
static int hf_h245_crcLength2 = -1;               /* AL1CrcLength */
static int hf_h245_crc4bit = -1;                  /* NULL */
static int hf_h245_crc12bit = -1;                 /* NULL */
static int hf_h245_crc20bit = -1;                 /* NULL */
static int hf_h245_crc28bit = -1;                 /* NULL */
static int hf_h245_crc8bit = -1;                  /* NULL */
static int hf_h245_crc16bit = -1;                 /* NULL */
static int hf_h245_crc32bit = -1;                 /* NULL */
static int hf_h245_crcNotUsed = -1;               /* NULL */
static int hf_h245_rcpcCodeRate = -1;             /* INTEGER_8_32 */
static int hf_h245_noArq = -1;                    /* NULL */
static int hf_h245_typeIArq = -1;                 /* H223AnnexCArqParameters */
static int hf_h245_typeIIArq = -1;                /* H223AnnexCArqParameters */
static int hf_h245_arqType = -1;                  /* ArqType */
static int hf_h245_alsduSplitting = -1;           /* BOOLEAN */
static int hf_h245_rsCodeCorrection = -1;         /* INTEGER_0_127 */
static int hf_h245_aL2HeaderFEC = -1;             /* AL2HeaderFEC */
static int hf_h245_sebch16_5 = -1;                /* NULL */
static int hf_h245_headerFormat = -1;             /* T_headerFormat */
static int hf_h245_crlength2 = -1;                /* AL3CrcLength */
static int hf_h245_numberOfRetransmissions = -1;  /* T_numberOfRetransmissions */
static int hf_h245_finite = -1;                   /* INTEGER_0_16 */
static int hf_h245_infinite = -1;                 /* NULL */
static int hf_h245_sendBufferSize = -1;           /* INTEGER_0_16777215 */
static int hf_h245_hdlcParameters = -1;           /* V76HDLCParameters */
static int hf_h245_suspendResume = -1;            /* T_suspendResume */
static int hf_h245_noSuspendResume = -1;          /* NULL */
static int hf_h245_suspendResumewAddress = -1;    /* NULL */
static int hf_h245_suspendResumewoAddress = -1;   /* NULL */
static int hf_h245_uIH = -1;                      /* BOOLEAN */
static int hf_h245_v76_mode = -1;                 /* V76LCP_mode */
static int hf_h245_eRM = -1;                      /* T_eRM */
static int hf_h245_windowSize = -1;               /* INTEGER_1_127 */
static int hf_h245_recovery = -1;                 /* T_recovery */
static int hf_h245_rej = -1;                      /* NULL */
static int hf_h245_sREJ = -1;                     /* NULL */
static int hf_h245_mSREJ = -1;                    /* NULL */
static int hf_h245_uNERM = -1;                    /* NULL */
static int hf_h245_v75Parameters = -1;            /* V75Parameters */
static int hf_h245_crcLength = -1;                /* CRCLength */
static int hf_h245_n401 = -1;                     /* INTEGER_1_4095 */
static int hf_h245_loopbackTestProcedure = -1;    /* BOOLEAN */
static int hf_h245_sessionID_0_255 = -1;          /* INTEGER_0_255 */
static int hf_h245_associatedSessionID = -1;      /* INTEGER_1_255 */
static int hf_h245_mediaChannel = -1;             /* T_mediaChannel */
static int hf_h245_mediaGuaranteedDelivery = -1;  /* BOOLEAN */
static int hf_h245_mediaControlChannel = -1;      /* T_mediaControlChannel */
static int hf_h245_mediaControlGuaranteedDelivery = -1;  /* BOOLEAN */
static int hf_h245_destination = -1;              /* TerminalLabel */
static int hf_h245_mediaPacketization = -1;       /* T_mediaPacketization */
static int hf_h245_h261aVideoPacketizationFlag = -1;  /* NULL */
static int hf_h245_rtpPayloadType = -1;           /* RTPPayloadType */
static int hf_h245_source = -1;                   /* TerminalLabel */
static int hf_h245_payloadDescriptor = -1;        /* T_payloadDescriptor */
static int hf_h245_rfc_number = -1;               /* T_rfc_number */
static int hf_h245_oid = -1;                      /* OBJECT_IDENTIFIER */
static int hf_h245_rtpPayloadType_01 = -1;        /* T_rtpPayloadType */
static int hf_h245_secondaryEncoding = -1;        /* DataType */
static int hf_h245_rtpRedundancyEncoding = -1;    /* T_rtpRedundancyEncoding */
static int hf_h245_primary = -1;                  /* RedundancyEncodingElement */
static int hf_h245_secondary = -1;                /* SEQUENCE_OF_RedundancyEncodingElement */
static int hf_h245_secondary_item = -1;           /* RedundancyEncodingElement */
static int hf_h245_payloadType = -1;              /* INTEGER_0_127 */
static int hf_h245_elements = -1;                 /* SEQUENCE_OF_MultiplePayloadStreamElement */
static int hf_h245_elements_item = -1;            /* MultiplePayloadStreamElement */
static int hf_h245_dep_rfc2733 = -1;              /* RFC2733Data */
static int hf_h245_fec_data_mode = -1;            /* FECdata_mode */
static int hf_h245_redundancyEncodingFlag = -1;   /* NULL */
static int hf_h245_differentPort = -1;            /* T_differentPort */
static int hf_h245_protectedSessionID = -1;       /* INTEGER_1_255 */
static int hf_h245_protectedPayloadType = -1;     /* INTEGER_0_127 */
static int hf_h245_samePort = -1;                 /* T_samePort */
static int hf_h245_separateStream = -1;           /* DepSeparateStream */
static int hf_h245_rfc2733 = -1;                  /* T_rfc2733 */
static int hf_h245_pktMode = -1;                  /* T_pktMode */
static int hf_h245_rfc2198coding = -1;            /* NULL */
static int hf_h245_mode_rfc2733sameport = -1;     /* T_mode_rfc2733sameport */
static int hf_h245_mode_rfc2733diffport = -1;     /* T_mode_rfc2733diffport */
static int hf_h245_protectedChannel = -1;         /* LogicalChannelNumber */
static int hf_h245_unicastAddress = -1;           /* UnicastAddress */
static int hf_h245_multicastAddress = -1;         /* MulticastAddress */
static int hf_h245_iPAddress = -1;                /* T_iPAddress */
static int hf_h245_ip4_network = -1;              /* Ipv4_network */
static int hf_h245_tsapIdentifier = -1;           /* TsapIdentifier */
static int hf_h245_iPXAddress = -1;               /* T_iPXAddress */
static int hf_h245_node = -1;                     /* OCTET_STRING_SIZE_6 */
static int hf_h245_netnum = -1;                   /* OCTET_STRING_SIZE_4 */
static int hf_h245_ipx_tsapIdentifier = -1;       /* OCTET_STRING_SIZE_2 */
static int hf_h245_iP6Address = -1;               /* T_iP6Address */
static int hf_h245_ip6_network = -1;              /* OCTET_STRING_SIZE_16 */
static int hf_h245_ipv6_tsapIdentifier = -1;      /* INTEGER_0_65535 */
static int hf_h245_netBios = -1;                  /* OCTET_STRING_SIZE_16 */
static int hf_h245_iPSourceRouteAddress = -1;     /* T_iPSourceRouteAddress */
static int hf_h245_routing = -1;                  /* T_routing */
static int hf_h245_strict = -1;                   /* NULL */
static int hf_h245_loose = -1;                    /* NULL */
static int hf_h245_network = -1;                  /* OCTET_STRING_SIZE_4 */
static int hf_h245_iPSrcRoute_tsapIdentifier = -1;  /* INTEGER_0_65535 */
static int hf_h245_route = -1;                    /* T_route */
static int hf_h245_route_item = -1;               /* OCTET_STRING_SIZE_4 */
static int hf_h245_nsap = -1;                     /* OCTET_STRING_SIZE_1_20 */
static int hf_h245_nonStandardAddress = -1;       /* NonStandardParameter */
static int hf_h245_mIPAddress = -1;               /* MIPAddress */
static int hf_h245_mip4_network = -1;             /* OCTET_STRING_SIZE_4 */
static int hf_h245_multicast_tsapIdentifier = -1;  /* INTEGER_0_65535 */
static int hf_h245_mIP6Address = -1;              /* MIP6Address */
static int hf_h245_mip6_network = -1;             /* OCTET_STRING_SIZE_16 */
static int hf_h245_multicast_IPv6_tsapIdentifier = -1;  /* INTEGER_0_65535 */
static int hf_h245_synchFlag = -1;                /* INTEGER_0_255 */
static int hf_h245_h235Key = -1;                  /* OCTET_STRING_SIZE_1_65535 */
static int hf_h245_escrowentry = -1;              /* SEQUENCE_SIZE_1_256_OF_EscrowData */
static int hf_h245_escrowentry_item = -1;         /* EscrowData */
static int hf_h245_genericParameter = -1;         /* GenericParameter */
static int hf_h245_escrowID = -1;                 /* OBJECT_IDENTIFIER */
static int hf_h245_escrowValue = -1;              /* BIT_STRING_SIZE_1_65535 */
static int hf_h245_olc_ack_fw_lcn = -1;           /* OLC_ack_fw_lcn */
static int hf_h245_olc_ack_reverseLogicalChannelParameters = -1;  /* OLC_ack_reverseLogicalChannelParameters */
static int hf_h245_reverseLogicalChannelNumber = -1;  /* T_reverseLogicalChannelNumber */
static int hf_h245_olc_ack_multiplexParameters = -1;  /* T_olc_ack_multiplexParameters */
static int hf_h245_forwardMultiplexAckParameters = -1;  /* T_forwardMultiplexAckParameters */
static int hf_h245_h2250LogicalChannelAckParameters = -1;  /* H2250LogicalChannelAckParameters */
static int hf_h245_forwardLogicalChannelNumber = -1;  /* LogicalChannelNumber */
static int hf_h245_olc_rej_cause = -1;            /* OpenLogicalChannelRejectCause */
static int hf_h245_unsuitableReverseParameters = -1;  /* NULL */
static int hf_h245_dataTypeNotSupported = -1;     /* NULL */
static int hf_h245_dataTypeNotAvailable = -1;     /* NULL */
static int hf_h245_unknownDataType = -1;          /* NULL */
static int hf_h245_dataTypeALCombinationNotSupported = -1;  /* NULL */
static int hf_h245_multicastChannelNotAllowed = -1;  /* NULL */
static int hf_h245_insufficientBandwidth = -1;    /* NULL */
static int hf_h245_separateStackEstablishmentFailed = -1;  /* NULL */
static int hf_h245_invalidSessionID = -1;         /* NULL */
static int hf_h245_masterSlaveConflict = -1;      /* NULL */
static int hf_h245_waitForCommunicationMode = -1;  /* NULL */
static int hf_h245_invalidDependentChannel = -1;  /* NULL */
static int hf_h245_replacementForRejected = -1;   /* NULL */
static int hf_h245_securityDenied = -1;           /* NULL */
static int hf_h245_qoSControlNotSupported = -1;   /* NULL */
static int hf_h245_sessionID = -1;                /* INTEGER_1_255 */
static int hf_h245_ack_mediaChannel = -1;         /* Ack_mediaChannel */
static int hf_h245_ack_mediaControlChannel = -1;  /* Ack_mediaControlChannel */
static int hf_h245_flowControlToZero = -1;        /* BOOLEAN */
static int hf_h245_cLC_source = -1;               /* T_cLC_source */
static int hf_h245_user = -1;                     /* NULL */
static int hf_h245_lcse = -1;                     /* NULL */
static int hf_h245_clc_reason = -1;               /* Clc_reason */
static int hf_h245_unknown = -1;                  /* NULL */
static int hf_h245_reopen = -1;                   /* NULL */
static int hf_h245_reservationFailure = -1;       /* NULL */
static int hf_h245_networkErrorCode = -1;         /* INTEGER_0_255 */
static int hf_h245_qosCapability = -1;            /* QOSCapability */
static int hf_h245_reason = -1;                   /* T_reason */
static int hf_h245_normal = -1;                   /* NULL */
static int hf_h245_req_chan_clos_rej_cause = -1;  /* RequestChannelCloseRejectCause */
static int hf_h245_multiplexEntryDescriptors = -1;  /* SET_SIZE_1_15_OF_MultiplexEntryDescriptor */
static int hf_h245_multiplexEntryDescriptors_item = -1;  /* MultiplexEntryDescriptor */
static int hf_h245_multiplexTableEntryNumber = -1;  /* MultiplexTableEntryNumber */
static int hf_h245_elementList = -1;              /* T_elementList */
static int hf_h245_elementList_item = -1;         /* MultiplexElement */
static int hf_h245_me_type = -1;                  /* Me_type */
static int hf_h245_logicalChannelNum = -1;        /* T_logicalChannelNum */
static int hf_h245_subElementList = -1;           /* T_subElementList */
static int hf_h245_subElementList_item = -1;      /* MultiplexElement */
static int hf_h245_me_repeatCount = -1;           /* ME_repeatCount */
static int hf_h245_me_repeatCount_finite = -1;    /* ME_finiteRepeatCount */
static int hf_h245_untilClosingFlag = -1;         /* T_untilClosingFlag */
static int hf_h245_multiplexTableEntryNumbers = -1;  /* SET_SIZE_1_15_OF_MultiplexTableEntryNumber */
static int hf_h245_multiplexTableEntryNumbers_item = -1;  /* MultiplexTableEntryNumber */
static int hf_h245_sendRejectionDescriptions = -1;  /* SET_SIZE_1_15_OF_MultiplexEntryRejectionDescriptions */
static int hf_h245_sendRejectionDescriptions_item = -1;  /* MultiplexEntryRejectionDescriptions */
static int hf_h245_mux_rej_cause = -1;            /* MultiplexEntryRejectionDescriptionsCause */
static int hf_h245_unspecifiedCause = -1;         /* NULL */
static int hf_h245_descriptorTooComplex = -1;     /* NULL */
static int hf_h245_entryNumbers = -1;             /* SET_SIZE_1_15_OF_MultiplexTableEntryNumber */
static int hf_h245_entryNumbers_item = -1;        /* MultiplexTableEntryNumber */
static int hf_h245_rejectionDescriptions = -1;    /* SET_SIZE_1_15_OF_RequestMultiplexEntryRejectionDescriptions */
static int hf_h245_rejectionDescriptions_item = -1;  /* RequestMultiplexEntryRejectionDescriptions */
static int hf_h245_req_mux_rej_cause = -1;        /* RequestMultiplexEntryRejectionDescriptionsCause */
static int hf_h245_requestedModes = -1;           /* SEQUENCE_SIZE_1_256_OF_ModeDescription */
static int hf_h245_requestedModes_item = -1;      /* ModeDescription */
static int hf_h245_req_mode_ack_response = -1;    /* Req_mode_ack_response */
static int hf_h245_willTransmitMostPreferredMode = -1;  /* NULL */
static int hf_h245_willTransmitLessPreferredMode = -1;  /* NULL */
static int hf_h245_req_rej_cause = -1;            /* RequestModeRejectCause */
static int hf_h245_modeUnavailable = -1;          /* NULL */
static int hf_h245_multipointConstraint = -1;     /* NULL */
static int hf_h245_requestDenied = -1;            /* NULL */
static int hf_h245_ModeDescription_item = -1;     /* ModeElement */
static int hf_h245_videoMode = -1;                /* VideoMode */
static int hf_h245_audioMode = -1;                /* AudioMode */
static int hf_h245_dataMode = -1;                 /* DataMode */
static int hf_h245_encryptionMode = -1;           /* EncryptionMode */
static int hf_h245_h235Mode = -1;                 /* H235Mode */
static int hf_h245_multiplexedStreamMode = -1;    /* MultiplexedStreamParameter */
static int hf_h245_redundancyEncodingDTMode = -1;  /* RedundancyEncodingDTMode */
static int hf_h245_multiplePayloadStreamMode = -1;  /* MultiplePayloadStreamMode */
static int hf_h245_depFecMode = -1;               /* DepFECMode */
static int hf_h245_fecMode = -1;                  /* FECMode */
static int hf_h245_type = -1;                     /* ModeElementType */
static int hf_h245_h223ModeParameters = -1;       /* H223ModeParameters */
static int hf_h245_v76ModeParameters = -1;        /* V76ModeParameters */
static int hf_h245_h2250ModeParameters = -1;      /* H2250ModeParameters */
static int hf_h245_genericModeParameters = -1;    /* GenericCapability */
static int hf_h245_multiplexedStreamModeParameters = -1;  /* MultiplexedStreamModeParameters */
static int hf_h245_logicalChannelNumber = -1;     /* LogicalChannelNumber */
static int hf_h245_mediaMode = -1;                /* T_mediaMode */
static int hf_h245_prmary_dtmode = -1;            /* RedundancyEncodingDTModeElement */
static int hf_h245_secondaryDTM = -1;             /* SEQUENCE_OF_RedundancyEncodingDTModeElement */
static int hf_h245_secondaryDTM_item = -1;        /* RedundancyEncodingDTModeElement */
static int hf_h245_re_type = -1;                  /* Re_type */
static int hf_h245_mpsmElements = -1;             /* SEQUENCE_OF_MultiplePayloadStreamElementMode */
static int hf_h245_mpsmElements_item = -1;        /* MultiplePayloadStreamElementMode */
static int hf_h245_rfc2733Mode = -1;              /* T_rfc2733Mode */
static int hf_h245_fec_mode = -1;                 /* FEC_mode */
static int hf_h245_protectedElement = -1;         /* ModeElementType */
static int hf_h245_adaptationLayer = -1;          /* AdaptationLayerType */
static int hf_h245_al1Framed = -1;                /* NULL */
static int hf_h245_al1NotFramed = -1;             /* NULL */
static int hf_h245_al2WithoutSequenceNumbers = -1;  /* NULL */
static int hf_h245_al2WithSequenceNumbers = -1;   /* NULL */
static int hf_h245_al3 = -1;                      /* Al3 */
static int hf_h245_al1M = -1;                     /* H223AL1MParameters */
static int hf_h245_al2M = -1;                     /* H223AL2MParameters */
static int hf_h245_al3M = -1;                     /* H223AL3MParameters */
static int hf_h245_segmentableFlag = -1;          /* BOOLEAN */
static int hf_h245_redundancyEncodingMode = -1;   /* RedundancyEncodingMode */
static int hf_h245_secondaryEncodingMode = -1;    /* T_secondaryEncodingMode */
static int hf_h245_h261VideoMode = -1;            /* H261VideoMode */
static int hf_h245_h262VideoMode = -1;            /* H262VideoMode */
static int hf_h245_h263VideoMode = -1;            /* H263VideoMode */
static int hf_h245_is11172VideoMode = -1;         /* IS11172VideoMode */
static int hf_h245_genericVideoMode = -1;         /* GenericCapability */
static int hf_h245_h261_resolution = -1;          /* H261Resolution */
static int hf_h245_qcif = -1;                     /* NULL */
static int hf_h245_cif = -1;                      /* NULL */
static int hf_h245_profileAndLevel = -1;          /* T_profileAndLevel */
static int hf_h245_profileAndLevel_SPatMLMode = -1;  /* NULL */
static int hf_h245_profileAndLevel_MPatLLMode = -1;  /* NULL */
static int hf_h245_profileAndLevel_MPatMLMode = -1;  /* NULL */
static int hf_h245_profileAndLevel_MPatH_14Mode = -1;  /* NULL */
static int hf_h245_profileAndLevel_MPatHLMode = -1;  /* NULL */
static int hf_h245_profileAndLevel_SNRatLLMode = -1;  /* NULL */
static int hf_h245_profileAndLevel_SNRatMLMode = -1;  /* NULL */
static int hf_h245_profileAndLevel_SpatialatH_14Mode = -1;  /* NULL */
static int hf_h245_profileAndLevel_HPatMLMode = -1;  /* NULL */
static int hf_h245_profileAndLevel_HPatH_14Mode = -1;  /* NULL */
static int hf_h245_profileAndLevel_HPatHLMode = -1;  /* NULL */
static int hf_h245_h263_resolution = -1;          /* H263Resolution */
static int hf_h245_sqcif = -1;                    /* NULL */
static int hf_h245_cif4 = -1;                     /* NULL */
static int hf_h245_cif16 = -1;                    /* NULL */
static int hf_h245_custom_res = -1;               /* NULL */
static int hf_h245_g711Alaw64k_mode = -1;         /* NULL */
static int hf_h245_g711Alaw56k_mode = -1;         /* NULL */
static int hf_h245_g711Ulaw64k_mode = -1;         /* NULL */
static int hf_h245_g711Ulaw56k_mode = -1;         /* NULL */
static int hf_h245_g722_64k_mode = -1;            /* NULL */
static int hf_h245_g722_56k_mode = -1;            /* NULL */
static int hf_h245_g722_48k_mode = -1;            /* NULL */
static int hf_h245_g728_mode = -1;                /* NULL */
static int hf_h245_g729_mode = -1;                /* NULL */
static int hf_h245_g729AnnexA_mode = -1;          /* NULL */
static int hf_h245_g7231_mode = -1;               /* Mode_g7231 */
static int hf_h245_noSilenceSuppressionLowRate = -1;  /* NULL */
static int hf_h245_noSilenceSuppressionHighRate = -1;  /* NULL */
static int hf_h245_silenceSuppressionLowRate = -1;  /* NULL */
static int hf_h245_silenceSuppressionHighRate = -1;  /* NULL */
static int hf_h245_is11172AudioMode = -1;         /* IS11172AudioMode */
static int hf_h245_is13818AudioMode = -1;         /* IS13818AudioMode */
static int hf_h245_g7231AnnexCMode = -1;          /* G7231AnnexCMode */
static int hf_h245_genericAudioMode = -1;         /* GenericCapability */
static int hf_h245_vbd_mode = -1;                 /* VBDMode */
static int hf_h245_audioLayer = -1;               /* T_audioLayer */
static int hf_h245_audioLayer1Mode = -1;          /* NULL */
static int hf_h245_audioLayer2Mode = -1;          /* NULL */
static int hf_h245_audioLayer3Mode = -1;          /* NULL */
static int hf_h245_audioSampling = -1;            /* T_audioSampling */
static int hf_h245_audioSampling32kMode = -1;     /* NULL */
static int hf_h245_audioSampling44k1Mode = -1;    /* NULL */
static int hf_h245_audioSampling48kMode = -1;     /* NULL */
static int hf_h245_is11172multichannelType = -1;  /* IS11172_multichannelType */
static int hf_h245_singleChannelMode = -1;        /* NULL */
static int hf_h245_twoChannelStereo = -1;         /* NULL */
static int hf_h245_twoChannelDual = -1;           /* NULL */
static int hf_h245_audioLayerMode = -1;           /* IS13818AudioLayer */
static int hf_h245_audioSamplingMode = -1;        /* IS13818AudioSampling */
static int hf_h245_audioSampling16kMode = -1;     /* NULL */
static int hf_h245_audioSampling22k05Mode = -1;   /* NULL */
static int hf_h245_audioSampling24kMode = -1;     /* NULL */
static int hf_h245_is13818MultichannelType = -1;  /* IS13818MultichannelType */
static int hf_h245_threeChannels2_1Mode = -1;     /* NULL */
static int hf_h245_threeChannels3_0Mode = -1;     /* NULL */
static int hf_h245_fourChannels2_0_2_0Mode = -1;  /* NULL */
static int hf_h245_fourChannels2_2Mode = -1;      /* NULL */
static int hf_h245_fourChannels3_1Mode = -1;      /* NULL */
static int hf_h245_fiveChannels3_0_2_0Mode = -1;  /* NULL */
static int hf_h245_fiveChannels3_2Mode = -1;      /* NULL */
static int hf_h245_vbd_type = -1;                 /* AudioMode */
static int hf_h245_datamodeapplication = -1;      /* DataModeApplication */
static int hf_h245_t84DataProtocolCapability = -1;  /* DataProtocolCapability */
static int hf_h245_t38faxDataProtocolCapability = -1;  /* T38faxApp */
static int hf_h245_genericDataMode = -1;          /* GenericCapability */
static int hf_h245_bitRate_0_4294967295 = -1;     /* INTEGER_0_4294967295 */
static int hf_h245_h233Encryption = -1;           /* NULL */
static int hf_h245_mlr_type = -1;                 /* Mlr_type */
static int hf_h245_systemLoop = -1;               /* NULL */
static int hf_h245_mediaLoop = -1;                /* LogicalChannelNumber */
static int hf_h245_logicalChannelLoop = -1;       /* LogicalChannelNumber */
static int hf_h245_mla_type = -1;                 /* Mla_type */
static int hf_h245_mlrej_type = -1;               /* Mlrej_type */
static int hf_h245_maintloop_rej_cause = -1;      /* MaintenanceLoopRejectCause */
static int hf_h245_canNotPerformLoop = -1;        /* NULL */
static int hf_h245_communicationModeTable = -1;   /* SET_SIZE_1_256_OF_CommunicationModeTableEntry */
static int hf_h245_communicationModeTable_item = -1;  /* CommunicationModeTableEntry */
static int hf_h245_terminalLabel = -1;            /* TerminalLabel */
static int hf_h245_sessionDescription = -1;       /* BMPString_SIZE_1_128 */
static int hf_h245_entryDataType = -1;            /* T_entryDataType */
static int hf_h245_cm_mediaChannel = -1;          /* Cm_mediaChannel */
static int hf_h245_cm_mediaControlChannel = -1;   /* TransportAddress */
static int hf_h245_sessionDependency = -1;        /* INTEGER_1_255 */
static int hf_h245_terminalListRequest = -1;      /* NULL */
static int hf_h245_makeMeChair = -1;              /* NULL */
static int hf_h245_cancelMakeMeChair = -1;        /* NULL */
static int hf_h245_dropTerminal = -1;             /* TerminalLabel */
static int hf_h245_requestTerminalID = -1;        /* TerminalLabel */
static int hf_h245_enterH243Password = -1;        /* NULL */
static int hf_h245_enterH243TerminalID = -1;      /* NULL */
static int hf_h245_enterH243ConferenceID = -1;    /* NULL */
static int hf_h245_enterExtensionAddress = -1;    /* NULL */
static int hf_h245_requestChairTokenOwner = -1;   /* NULL */
static int hf_h245_requestTerminalCertificate = -1;  /* T_requestTerminalCertificate */
static int hf_h245_certSelectionCriteria = -1;    /* CertSelectionCriteria */
static int hf_h245_sRandom = -1;                  /* INTEGER_1_4294967295 */
static int hf_h245_broadcastMyLogicalChannel = -1;  /* LogicalChannelNumber */
static int hf_h245_makeTerminalBroadcaster = -1;  /* TerminalLabel */
static int hf_h245_sendThisSource = -1;           /* TerminalLabel */
static int hf_h245_requestAllTerminalIDs = -1;    /* NULL */
static int hf_h245_remoteMCRequest = -1;          /* RemoteMCRequest */
static int hf_h245_CertSelectionCriteria_item = -1;  /* Criteria */
static int hf_h245_field = -1;                    /* OBJECT_IDENTIFIER */
static int hf_h245_criteriaValue = -1;            /* OCTET_STRING_SIZE_1_65535 */
static int hf_h245_mcuNumber = -1;                /* McuNumber */
static int hf_h245_terminalNumber = -1;           /* TerminalNumber */
static int hf_h245_mCTerminalIDResponse = -1;     /* T_mCTerminalIDResponse */
static int hf_h245_terminalID = -1;               /* TerminalID */
static int hf_h245_terminalIDResponse = -1;       /* T_terminalIDResponse */
static int hf_h245_conferenceIDResponse = -1;     /* T_conferenceIDResponse */
static int hf_h245_conferenceID = -1;             /* ConferenceID */
static int hf_h245_passwordResponse = -1;         /* T_passwordResponse */
static int hf_h245_password = -1;                 /* Password */
static int hf_h245_terminalListResponse = -1;     /* SET_SIZE_1_256_OF_TerminalLabel */
static int hf_h245_terminalListResponse_item = -1;  /* TerminalLabel */
static int hf_h245_videoCommandReject = -1;       /* NULL */
static int hf_h245_terminalDropReject = -1;       /* NULL */
static int hf_h245_makeMeChairResponse = -1;      /* T_makeMeChairResponse */
static int hf_h245_grantedChairToken = -1;        /* NULL */
static int hf_h245_deniedChairToken = -1;         /* NULL */
static int hf_h245_extensionAddressResponse = -1;  /* T_extensionAddressResponse */
static int hf_h245_extensionAddress = -1;         /* TerminalID */
static int hf_h245_chairTokenOwnerResponse = -1;  /* T_chairTokenOwnerResponse */
static int hf_h245_terminalCertificateResponse = -1;  /* T_terminalCertificateResponse */
static int hf_h245_certificateResponse = -1;      /* OCTET_STRING_SIZE_1_65535 */
static int hf_h245_broadcastMyLogicalChannelResponse = -1;  /* T_broadcastMyLogicalChannelResponse */
static int hf_h245_grantedBroadcastMyLogicalChannel = -1;  /* NULL */
static int hf_h245_deniedBroadcastMyLogicalChannel = -1;  /* NULL */
static int hf_h245_makeTerminalBroadcasterResponse = -1;  /* T_makeTerminalBroadcasterResponse */
static int hf_h245_grantedMakeTerminalBroadcaster = -1;  /* NULL */
static int hf_h245_deniedMakeTerminalBroadcaster = -1;  /* NULL */
static int hf_h245_sendThisSourceResponse = -1;   /* T_sendThisSourceResponse */
static int hf_h245_grantedSendThisSource = -1;    /* NULL */
static int hf_h245_deniedSendThisSource = -1;     /* NULL */
static int hf_h245_requestAllTerminalIDsResponse = -1;  /* RequestAllTerminalIDsResponse */
static int hf_h245_remoteMCResponse = -1;         /* RemoteMCResponse */
static int hf_h245_terminalInformation = -1;      /* SEQUENCE_OF_TerminalInformation */
static int hf_h245_terminalInformation_item = -1;  /* TerminalInformation */
static int hf_h245_masterActivate = -1;           /* NULL */
static int hf_h245_slaveActivate = -1;            /* NULL */
static int hf_h245_deActivate = -1;               /* NULL */
static int hf_h245_accept = -1;                   /* NULL */
static int hf_h245_reject = -1;                   /* T_reject */
static int hf_h245_functionNotSupportedFlag = -1;  /* NULL */
static int hf_h245_callInformationReq = -1;       /* CallInformationReq */
static int hf_h245_maxNumberOfAdditionalConnections = -1;  /* INTEGER_1_65535 */
static int hf_h245_addConnectionReq = -1;         /* AddConnectionReq */
static int hf_h245_dialingInformation = -1;       /* DialingInformation */
static int hf_h245_removeConnectionReq = -1;      /* RemoveConnectionReq */
static int hf_h245_connectionIdentifier = -1;     /* ConnectionIdentifier */
static int hf_h245_maximumHeaderIntervalReq = -1;  /* MaximumHeaderIntervalReq */
static int hf_h245_requestType = -1;              /* T_requestType */
static int hf_h245_currentIntervalInformation = -1;  /* NULL */
static int hf_h245_requestedInterval = -1;        /* INTEGER_0_65535 */
static int hf_h245_callInformationResp = -1;      /* CallInformationResp */
static int hf_h245_callAssociationNumber = -1;    /* INTEGER_0_4294967295 */
static int hf_h245_addConnectionResp = -1;        /* AddConnectionResp */
static int hf_h245_responseCode = -1;             /* T_responseCode */
static int hf_h245_accepted = -1;                 /* NULL */
static int hf_h245_rejected = -1;                 /* T_rejected */
static int hf_h245_connectionsNotAvailable = -1;  /* NULL */
static int hf_h245_userRejected = -1;             /* NULL */
static int hf_h245_removeConnectionResp = -1;     /* RemoveConnectionResp */
static int hf_h245_maximumHeaderIntervalResp = -1;  /* MaximumHeaderIntervalResp */
static int hf_h245_currentInterval = -1;          /* INTEGER_0_65535 */
static int hf_h245_crcDesired = -1;               /* T_crcDesired */
static int hf_h245_excessiveError = -1;           /* T_excessiveError */
static int hf_h245_differential = -1;             /* SET_SIZE_1_65535_OF_DialingInformationNumber */
static int hf_h245_differential_item = -1;        /* DialingInformationNumber */
static int hf_h245_infoNotAvailable = -1;         /* INTEGER_1_65535 */
static int hf_h245_networkAddressNum = -1;        /* NumericString_SIZE_0_40 */
static int hf_h245_subAddress = -1;               /* IA5String_SIZE_1_40 */
static int hf_h245_networkType = -1;              /* SET_SIZE_1_255_OF_DialingInformationNetworkType */
static int hf_h245_networkType_item = -1;         /* DialingInformationNetworkType */
static int hf_h245_n_isdn = -1;                   /* NULL */
static int hf_h245_gstn = -1;                     /* NULL */
static int hf_h245_mobile = -1;                   /* NULL */
static int hf_h245_channelTag = -1;               /* INTEGER_0_4294967295 */
static int hf_h245_sequenceNum = -1;              /* INTEGER_0_4294967295 */
static int hf_h245_maximumBitRate = -1;           /* MaximumBitRate */
static int hf_h245_rejectReason = -1;             /* LogicalChannelRateRejectReason */
static int hf_h245_currentMaximumBitRate = -1;    /* MaximumBitRate */
static int hf_h245_undefinedReason = -1;          /* NULL */
static int hf_h245_insufficientResources = -1;    /* NULL */
static int hf_h245_specificRequest = -1;          /* T_specificRequest */
static int hf_h245_multiplexCapabilityBool = -1;  /* BOOLEAN */
static int hf_h245_capabilityTableEntryNumbers = -1;  /* SET_SIZE_1_65535_OF_CapabilityTableEntryNumber */
static int hf_h245_capabilityTableEntryNumbers_item = -1;  /* CapabilityTableEntryNumber */
static int hf_h245_capabilityDescriptorNumbers = -1;  /* SET_SIZE_1_256_OF_CapabilityDescriptorNumber */
static int hf_h245_capabilityDescriptorNumbers_item = -1;  /* CapabilityDescriptorNumber */
static int hf_h245_genericRequestFlag = -1;       /* NULL */
static int hf_h245_encryptionSE = -1;             /* OCTET_STRING */
static int hf_h245_encryptionIVRequest = -1;      /* NULL */
static int hf_h245_encryptionAlgorithmID = -1;    /* T_encryptionAlgorithmID */
static int hf_h245_h233AlgorithmIdentifier = -1;  /* SequenceNumber */
static int hf_h245_associatedAlgorithm = -1;      /* NonStandardParameter */
static int hf_h245_wholeMultiplex = -1;           /* NULL */
static int hf_h245_scope = -1;                    /* Scope */
static int hf_h245_res_maximumBitRate = -1;       /* INTEGER_0_16777215 */
static int hf_h245_noRestriction = -1;            /* NULL */
static int hf_h245_restriction = -1;              /* Restriction */
static int hf_h245_disconnect = -1;               /* NULL */
static int hf_h245_gstnOptions = -1;              /* T_gstnOptions */
static int hf_h245_telephonyMode = -1;            /* NULL */
static int hf_h245_v8bis = -1;                    /* NULL */
static int hf_h245_v34DSVD = -1;                  /* NULL */
static int hf_h245_v34DuplexFAX = -1;             /* NULL */
static int hf_h245_v34H324 = -1;                  /* NULL */
static int hf_h245_isdnOptions = -1;              /* T_isdnOptions */
static int hf_h245_v140 = -1;                     /* NULL */
static int hf_h245_terminalOnHold = -1;           /* NULL */
static int hf_h245_cancelBroadcastMyLogicalChannel = -1;  /* LogicalChannelNumber */
static int hf_h245_cancelMakeTerminalBroadcaster = -1;  /* NULL */
static int hf_h245_cancelSendThisSource = -1;     /* NULL */
static int hf_h245_dropConference = -1;           /* NULL */
static int hf_h245_substituteConferenceIDCommand = -1;  /* SubstituteConferenceIDCommand */
static int hf_h245_conferenceIdentifier = -1;     /* OCTET_STRING_SIZE_16 */
static int hf_h245_masterToSlave = -1;            /* NULL */
static int hf_h245_slaveToMaster = -1;            /* NULL */
static int hf_h245_mc_type = -1;                  /* Mc_type */
static int hf_h245_equaliseDelay = -1;            /* NULL */
static int hf_h245_zeroDelay = -1;                /* NULL */
static int hf_h245_multipointModeCommand = -1;    /* NULL */
static int hf_h245_cancelMultipointModeCommand = -1;  /* NULL */
static int hf_h245_videoFreezePicture = -1;       /* NULL */
static int hf_h245_videoFastUpdatePicture = -1;   /* NULL */
static int hf_h245_videoFastUpdateGOB = -1;       /* T_videoFastUpdateGOB */
static int hf_h245_firstGOB = -1;                 /* INTEGER_0_17 */
static int hf_h245_numberOfGOBs = -1;             /* INTEGER_1_18 */
static int hf_h245_videoTemporalSpatialTradeOff = -1;  /* INTEGER_0_31 */
static int hf_h245_videoSendSyncEveryGOB = -1;    /* NULL */
static int hf_h245_videoSendSyncEveryGOBCancel = -1;  /* NULL */
static int hf_h245_videoFastUpdateMB = -1;        /* T_videoFastUpdateMB */
static int hf_h245_firstGOB_0_255 = -1;           /* INTEGER_0_255 */
static int hf_h245_firstMB_1_8192 = -1;           /* INTEGER_1_8192 */
static int hf_h245_numberOfMBs = -1;              /* INTEGER_1_8192 */
static int hf_h245_maxH223MUXPDUsize = -1;        /* INTEGER_1_65535 */
static int hf_h245_encryptionUpdate = -1;         /* EncryptionSync */
static int hf_h245_encryptionUpdateRequest = -1;  /* EncryptionUpdateRequest */
static int hf_h245_switchReceiveMediaOff = -1;    /* NULL */
static int hf_h245_switchReceiveMediaOn = -1;     /* NULL */
static int hf_h245_progressiveRefinementStart = -1;  /* T_progressiveRefinementStart */
static int hf_h245_repeatCount = -1;              /* T_repeatCount */
static int hf_h245_doOneProgression = -1;         /* NULL */
static int hf_h245_doContinuousProgressions = -1;  /* NULL */
static int hf_h245_doOneIndependentProgression = -1;  /* NULL */
static int hf_h245_doContinuousIndependentProgressions = -1;  /* NULL */
static int hf_h245_progressiveRefinementAbortOne = -1;  /* NULL */
static int hf_h245_progressiveRefinementAbortContinuous = -1;  /* NULL */
static int hf_h245_videoBadMBs = -1;              /* T_videoBadMBs */
static int hf_h245_firstMB = -1;                  /* INTEGER_1_9216 */
static int hf_h245_numberOfMBs1_1_9216 = -1;      /* INTEGER_1_9216 */
static int hf_h245_temporalReference = -1;        /* INTEGER_0_1023 */
static int hf_h245_lostPicture = -1;              /* SEQUENCE_OF_PictureReference */
static int hf_h245_lostPicture_item = -1;         /* PictureReference */
static int hf_h245_lostPartialPicture = -1;       /* T_lostPartialPicture */
static int hf_h245_pictureReference = -1;         /* PictureReference */
static int hf_h245_recoveryReferencePicture = -1;  /* SEQUENCE_OF_PictureReference */
static int hf_h245_recoveryReferencePicture_item = -1;  /* PictureReference */
static int hf_h245_encryptionUpdateCommand = -1;  /* T_encryptionUpdateCommand */
static int hf_h245_encryptionUpdateAck = -1;      /* T_encryptionUpdateAck */
static int hf_h245_direction = -1;                /* EncryptionUpdateDirection */
static int hf_h245_secureChannel = -1;            /* BOOLEAN */
static int hf_h245_sharedSecret = -1;             /* BOOLEAN */
static int hf_h245_certProtectedKey = -1;         /* BOOLEAN */
static int hf_h245_keyProtectionMethod = -1;      /* KeyProtectionMethod */
static int hf_h245_pictureNumber = -1;            /* INTEGER_0_1023 */
static int hf_h245_longTermPictureIndex = -1;     /* INTEGER_0_255 */
static int hf_h245_h223ModeChange = -1;           /* T_h223ModeChange */
static int hf_h245_toLevel0 = -1;                 /* NULL */
static int hf_h245_toLevel1 = -1;                 /* NULL */
static int hf_h245_toLevel2 = -1;                 /* NULL */
static int hf_h245_toLevel2withOptionalHeader = -1;  /* NULL */
static int hf_h245_h223AnnexADoubleFlag = -1;     /* T_h223AnnexADoubleFlag */
static int hf_h245_start = -1;                    /* NULL */
static int hf_h245_stop = -1;                     /* NULL */
static int hf_h245_bitRate = -1;                  /* INTEGER_1_65535 */
static int hf_h245_bitRateLockedToPCRClock = -1;  /* BOOLEAN */
static int hf_h245_bitRateLockedToNetworkClock = -1;  /* BOOLEAN */
static int hf_h245_cmd_aal = -1;                  /* Cmd_aal */
static int hf_h245_cmd_aal1 = -1;                 /* Cmd_aal1 */
static int hf_h245_cmd_clockRecovery = -1;        /* Cmd_clockRecovery */
static int hf_h245_nullClockRecoveryflag = -1;    /* NULL */
static int hf_h245_srtsClockRecovery = -1;        /* NULL */
static int hf_h245_adaptiveClockRecoveryFlag = -1;  /* NULL */
static int hf_h245_cmd_errorCorrection = -1;      /* Cmd_errorCorrection */
static int hf_h245_nullErrorCorrectionFlag = -1;  /* NULL */
static int hf_h245_longInterleaverFlag = -1;      /* NULL */
static int hf_h245_shortInterleaverFlag = -1;     /* NULL */
static int hf_h245_errorCorrectionOnlyFlag = -1;  /* NULL */
static int hf_h245_cmd_aal5 = -1;                 /* Cmd_aal5 */
static int hf_h245_cmd_multiplex = -1;            /* Cmd_multiplex */
static int hf_h245_noMultiplex = -1;              /* NULL */
static int hf_h245_transportStream = -1;          /* NULL */
static int hf_h245_programStreamFlag = -1;        /* NULL */
static int hf_h245_cmd_reverseParameters = -1;    /* Cmd_reverseParameters */
static int hf_h245_cmdr_multiplex = -1;           /* CmdR_multiplex */
static int hf_h245_sampleSize = -1;               /* INTEGER_1_255 */
static int hf_h245_samplesPerFrame = -1;          /* INTEGER_1_255 */
static int hf_h245_status = -1;                   /* T_status */
static int hf_h245_synchronized = -1;             /* NULL */
static int hf_h245_reconfiguration = -1;          /* NULL */
static int hf_h245_fns_cause = -1;                /* FunctionNotSupportedCause */
static int hf_h245_syntaxError = -1;              /* NULL */
static int hf_h245_semanticError = -1;            /* NULL */
static int hf_h245_unknownFunction = -1;          /* NULL */
static int hf_h245_returnedFunction = -1;         /* T_returnedFunction */
static int hf_h245_sbeNumber = -1;                /* INTEGER_0_9 */
static int hf_h245_terminalNumberAssign = -1;     /* TerminalLabel */
static int hf_h245_terminalJoinedConference = -1;  /* TerminalLabel */
static int hf_h245_terminalLeftConference = -1;   /* TerminalLabel */
static int hf_h245_seenByAtLeastOneOther = -1;    /* NULL */
static int hf_h245_cancelSeenByAtLeastOneOther = -1;  /* NULL */
static int hf_h245_seenByAll = -1;                /* NULL */
static int hf_h245_cancelSeenByAll = -1;          /* NULL */
static int hf_h245_terminalYouAreSeeing = -1;     /* TerminalLabel */
static int hf_h245_requestForFloor = -1;          /* NULL */
static int hf_h245_withdrawChairToken = -1;       /* NULL */
static int hf_h245_floorRequested = -1;           /* TerminalLabel */
static int hf_h245_terminalYouAreSeeingInSubPictureNumber = -1;  /* TerminalYouAreSeeingInSubPictureNumber */
static int hf_h245_videoIndicateCompose = -1;     /* VideoIndicateCompose */
static int hf_h245_masterMCU = -1;                /* NULL */
static int hf_h245_cancelMasterMCU = -1;          /* NULL */
static int hf_h245_subPictureNumber = -1;         /* INTEGER_0_255 */
static int hf_h245_compositionNumber = -1;        /* INTEGER_0_255 */
static int hf_h245_mi_type = -1;                  /* Mi_type */
static int hf_h245_logicalChannelActive = -1;     /* NULL */
static int hf_h245_logicalChannelInactive = -1;   /* NULL */
static int hf_h245_multipointConference = -1;     /* NULL */
static int hf_h245_cancelMultipointConference = -1;  /* NULL */
static int hf_h245_multipointZeroComm = -1;       /* NULL */
static int hf_h245_cancelMultipointZeroComm = -1;  /* NULL */
static int hf_h245_multipointSecondaryStatus = -1;  /* NULL */
static int hf_h245_cancelMultipointSecondaryStatus = -1;  /* NULL */
static int hf_h245_videoIndicateReadyToActivate = -1;  /* NULL */
static int hf_h245_videoNotDecodedMBs = -1;       /* T_videoNotDecodedMBs */
static int hf_h245_temporalReference_0_255 = -1;  /* INTEGER_0_255 */
static int hf_h245_estimatedReceivedJitterMantissa = -1;  /* INTEGER_0_3 */
static int hf_h245_estimatedReceivedJitterExponent = -1;  /* INTEGER_0_7 */
static int hf_h245_skippedFrameCount = -1;        /* INTEGER_0_15 */
static int hf_h245_additionalDecoderBuffer = -1;  /* INTEGER_0_262143 */
static int hf_h245_logicalChannelNumber1 = -1;    /* LogicalChannelNumber */
static int hf_h245_logicalChannelNumber2 = -1;    /* LogicalChannelNumber */
static int hf_h245_skew = -1;                     /* INTEGER_0_4095 */
static int hf_h245_maximumSkew = -1;              /* INTEGER_0_4095 */
static int hf_h245_signalAddress = -1;            /* TransportAddress */
static int hf_h245_vendor = -1;                   /* NonStandardIdentifier */
static int hf_h245_productNumber = -1;            /* OCTET_STRING_SIZE_1_256 */
static int hf_h245_versionNumber = -1;            /* OCTET_STRING_SIZE_1_256 */
static int hf_h245_ind_aal = -1;                  /* Ind_aal */
static int hf_h245_ind_aal1 = -1;                 /* Ind_aal1 */
static int hf_h245_ind_clockRecovery = -1;        /* Ind_clockRecovery */
static int hf_h245_ind_errorCorrection = -1;      /* Ind_errorCorrection */
static int hf_h245_ind_aal5 = -1;                 /* Ind_aal5 */
static int hf_h245_ind_multiplex = -1;            /* Ind_multiplex */
static int hf_h245_ind_reverseParameters = -1;    /* Ind_reverseParameters */
static int hf_h245_indr_multiplex = -1;           /* IndR_multiplex */
static int hf_h245_iv8 = -1;                      /* IV8 */
static int hf_h245_iv16 = -1;                     /* IV16 */
static int hf_h245_iv = -1;                       /* OCTET_STRING */
static int hf_h245_alphanumeric = -1;             /* GeneralString */
static int hf_h245_userInputSupportIndication = -1;  /* T_userInputSupportIndication */
static int hf_h245_signal = -1;                   /* T_signal */
static int hf_h245_signalType = -1;               /* T_signalType */
static int hf_h245_duration = -1;                 /* INTEGER_1_65535 */
static int hf_h245_rtp = -1;                      /* T_rtp */
static int hf_h245_timestamp = -1;                /* INTEGER_0_4294967295 */
static int hf_h245_expirationTime = -1;           /* INTEGER_0_4294967295 */
static int hf_h245_rtpPayloadIndication = -1;     /* NULL */
static int hf_h245_paramS = -1;                   /* Params */
static int hf_h245_encryptedSignalType = -1;      /* OCTET_STRING_SIZE_1 */
static int hf_h245_algorithmOID = -1;             /* OBJECT_IDENTIFIER */
static int hf_h245_signalUpdate = -1;             /* T_signalUpdate */
static int hf_h245_si_rtp = -1;                   /* Si_rtp */
static int hf_h245_extendedAlphanumeric = -1;     /* T_extendedAlphanumeric */
static int hf_h245_encrypted = -1;                /* OCTET_STRING */
static int hf_h245_encryptedAlphanumeric = -1;    /* EncryptedAlphanumeric */

/*--- End of included file: packet-h245-hf.c ---*/
#line 398 "../../asn1/h245/packet-h245-template.c"

/* Initialize the subtree pointers */
static int ett_h245 = -1;
static int ett_h245_returnedFunction = -1;

/*--- Included file: packet-h245-ett.c ---*/
#line 1 "../../asn1/h245/packet-h245-ett.c"
static gint ett_h245_MultimediaSystemControlMessage = -1;
static gint ett_h245_RequestMessage = -1;
static gint ett_h245_ResponseMessage = -1;
static gint ett_h245_CommandMessage = -1;
static gint ett_h245_IndicationMessage = -1;
static gint ett_h245_GenericMessage = -1;
static gint ett_h245_T_messageContent = -1;
static gint ett_h245_NonStandardMessage = -1;
static gint ett_h245_NonStandardParameter = -1;
static gint ett_h245_NonStandardIdentifier = -1;
static gint ett_h245_H221NonStandardID = -1;
static gint ett_h245_MasterSlaveDetermination = -1;
static gint ett_h245_MasterSlaveDeterminationAck = -1;
static gint ett_h245_T_decision = -1;
static gint ett_h245_MasterSlaveDeterminationReject = -1;
static gint ett_h245_MasterSlaveDeterminationRejectCause = -1;
static gint ett_h245_MasterSlaveDeterminationRelease = -1;
static gint ett_h245_TerminalCapabilitySet = -1;
static gint ett_h245_SET_SIZE_1_256_OF_CapabilityTableEntry = -1;
static gint ett_h245_SET_SIZE_1_256_OF_CapabilityDescriptor = -1;
static gint ett_h245_SEQUENCE_OF_GenericInformation = -1;
static gint ett_h245_CapabilityTableEntry = -1;
static gint ett_h245_CapabilityDescriptor = -1;
static gint ett_h245_SET_SIZE_1_256_OF_AlternativeCapabilitySet = -1;
static gint ett_h245_AlternativeCapabilitySet = -1;
static gint ett_h245_TerminalCapabilitySetAck = -1;
static gint ett_h245_TerminalCapabilitySetReject = -1;
static gint ett_h245_TerminalCapabilitySetRejectCause = -1;
static gint ett_h245_T_tableEntryCapacityExceeded = -1;
static gint ett_h245_TerminalCapabilitySetRelease = -1;
static gint ett_h245_Capability = -1;
static gint ett_h245_T_h233EncryptionReceiveCapability = -1;
static gint ett_h245_H235SecurityCapability = -1;
static gint ett_h245_MultiplexCapability = -1;
static gint ett_h245_H222Capability = -1;
static gint ett_h245_SET_OF_VCCapability = -1;
static gint ett_h245_VCCapability = -1;
static gint ett_h245_T_aal1 = -1;
static gint ett_h245_T_aal5 = -1;
static gint ett_h245_T_availableBitRates = -1;
static gint ett_h245_Avb_type = -1;
static gint ett_h245_T_rangeOfBitRates = -1;
static gint ett_h245_T_aal1ViaGateway = -1;
static gint ett_h245_SET_SIZE_1_256_OF_Q2931Address = -1;
static gint ett_h245_H223Capability = -1;
static gint ett_h245_T_h223MultiplexTableCapability = -1;
static gint ett_h245_T_enhanced = -1;
static gint ett_h245_T_mobileOperationTransmitCapability = -1;
static gint ett_h245_T_mobileMultilinkFrameCapability = -1;
static gint ett_h245_H223AnnexCCapability = -1;
static gint ett_h245_V76Capability = -1;
static gint ett_h245_V75Capability = -1;
static gint ett_h245_H2250Capability = -1;
static gint ett_h245_T_mcCapability = -1;
static gint ett_h245_SEQUENCE_SIZE_1_256_OF_RedundancyEncodingCapability = -1;
static gint ett_h245_MediaPacketizationCapability = -1;
static gint ett_h245_SEQUENCE_SIZE_1_256_OF_RTPPayloadType = -1;
static gint ett_h245_RSVPParameters = -1;
static gint ett_h245_QOSMode = -1;
static gint ett_h245_ATMParameters = -1;
static gint ett_h245_ServicePriorityValue = -1;
static gint ett_h245_ServicePriority = -1;
static gint ett_h245_AuthorizationParameters = -1;
static gint ett_h245_QOSType = -1;
static gint ett_h245_QOSClass = -1;
static gint ett_h245_QOSDescriptor = -1;
static gint ett_h245_GenericTransportParameters = -1;
static gint ett_h245_QOSCapability = -1;
static gint ett_h245_MediaTransportType = -1;
static gint ett_h245_T_atm_AAL5_compressed = -1;
static gint ett_h245_MediaChannelCapability = -1;
static gint ett_h245_TransportCapability = -1;
static gint ett_h245_SEQUENCE_SIZE_1_256_OF_QOSCapability = -1;
static gint ett_h245_SEQUENCE_SIZE_1_256_OF_MediaChannelCapability = -1;
static gint ett_h245_RedundancyEncodingCapability = -1;
static gint ett_h245_SEQUENCE_SIZE_1_256_OF_CapabilityTableEntryNumber = -1;
static gint ett_h245_RedundancyEncodingMethod = -1;
static gint ett_h245_RTPH263VideoRedundancyEncoding = -1;
static gint ett_h245_T_frameToThreadMapping = -1;
static gint ett_h245_SEQUENCE_SIZE_1_256_OF_RTPH263VideoRedundancyFrameMapping = -1;
static gint ett_h245_T_containedThreads = -1;
static gint ett_h245_RTPH263VideoRedundancyFrameMapping = -1;
static gint ett_h245_T_frameSequence = -1;
static gint ett_h245_MultipointCapability = -1;
static gint ett_h245_SEQUENCE_OF_MediaDistributionCapability = -1;
static gint ett_h245_MediaDistributionCapability = -1;
static gint ett_h245_SEQUENCE_OF_DataApplicationCapability = -1;
static gint ett_h245_VideoCapability = -1;
static gint ett_h245_ExtendedVideoCapability = -1;
static gint ett_h245_SEQUENCE_OF_VideoCapability = -1;
static gint ett_h245_SEQUENCE_OF_GenericCapability = -1;
static gint ett_h245_H261VideoCapability = -1;
static gint ett_h245_H262VideoCapability = -1;
static gint ett_h245_H263VideoCapability = -1;
static gint ett_h245_EnhancementLayerInfo = -1;
static gint ett_h245_SET_SIZE_1_14_OF_EnhancementOptions = -1;
static gint ett_h245_SET_SIZE_1_14_OF_BEnhancementParameters = -1;
static gint ett_h245_BEnhancementParameters = -1;
static gint ett_h245_EnhancementOptions = -1;
static gint ett_h245_H263Options = -1;
static gint ett_h245_SET_SIZE_1_16_OF_CustomPictureClockFrequency = -1;
static gint ett_h245_SET_SIZE_1_16_OF_CustomPictureFormat = -1;
static gint ett_h245_SET_SIZE_1_16_OF_H263VideoModeCombos = -1;
static gint ett_h245_TransparencyParameters = -1;
static gint ett_h245_RefPictureSelection = -1;
static gint ett_h245_T_additionalPictureMemory = -1;
static gint ett_h245_T_videoBackChannelSend = -1;
static gint ett_h245_T_enhancedReferencePicSelect = -1;
static gint ett_h245_T_subPictureRemovalParameters = -1;
static gint ett_h245_CustomPictureClockFrequency = -1;
static gint ett_h245_CustomPictureFormat = -1;
static gint ett_h245_T_mPI = -1;
static gint ett_h245_T_customPCF = -1;
static gint ett_h245_T_customPCF_item = -1;
static gint ett_h245_T_pixelAspectInformation = -1;
static gint ett_h245_T_pixelAspectCode = -1;
static gint ett_h245_T_extendedPAR = -1;
static gint ett_h245_T_extendedPAR_item = -1;
static gint ett_h245_H263VideoModeCombos = -1;
static gint ett_h245_SET_SIZE_1_16_OF_H263ModeComboFlags = -1;
static gint ett_h245_H263ModeComboFlags = -1;
static gint ett_h245_H263Version3Options = -1;
static gint ett_h245_IS11172VideoCapability = -1;
static gint ett_h245_AudioCapability = -1;
static gint ett_h245_T_g7231 = -1;
static gint ett_h245_G729Extensions = -1;
static gint ett_h245_G7231AnnexCCapability = -1;
static gint ett_h245_G723AnnexCAudioMode = -1;
static gint ett_h245_IS11172AudioCapability = -1;
static gint ett_h245_IS13818AudioCapability = -1;
static gint ett_h245_GSMAudioCapability = -1;
static gint ett_h245_VBDCapability = -1;
static gint ett_h245_DataApplicationCapability = -1;
static gint ett_h245_Application = -1;
static gint ett_h245_T_t84 = -1;
static gint ett_h245_Nlpid = -1;
static gint ett_h245_T_t38fax = -1;
static gint ett_h245_DataProtocolCapability = -1;
static gint ett_h245_T_v76wCompression = -1;
static gint ett_h245_CompressionType = -1;
static gint ett_h245_V42bis = -1;
static gint ett_h245_T84Profile = -1;
static gint ett_h245_T_t84Restricted = -1;
static gint ett_h245_T38FaxProfile = -1;
static gint ett_h245_T38FaxRateManagement = -1;
static gint ett_h245_T38FaxUdpOptions = -1;
static gint ett_h245_T_t38FaxUdpEC = -1;
static gint ett_h245_T38FaxTcpOptions = -1;
static gint ett_h245_EncryptionAuthenticationAndIntegrity = -1;
static gint ett_h245_EncryptionCapability = -1;
static gint ett_h245_MediaEncryptionAlgorithm = -1;
static gint ett_h245_AuthenticationCapability = -1;
static gint ett_h245_IntegrityCapability = -1;
static gint ett_h245_UserInputCapability = -1;
static gint ett_h245_SEQUENCE_SIZE_1_16_OF_NonStandardParameter = -1;
static gint ett_h245_ConferenceCapability = -1;
static gint ett_h245_SEQUENCE_OF_NonStandardParameter = -1;
static gint ett_h245_GenericCapability = -1;
static gint ett_h245_T_collapsing = -1;
static gint ett_h245_T_nonCollapsing = -1;
static gint ett_h245_CapabilityIdentifier = -1;
static gint ett_h245_GenericParameter = -1;
static gint ett_h245_SEQUENCE_OF_ParameterIdentifier = -1;
static gint ett_h245_ParameterIdentifier = -1;
static gint ett_h245_ParameterValue = -1;
static gint ett_h245_SEQUENCE_OF_GenericParameter = -1;
static gint ett_h245_MultiplexedStreamCapability = -1;
static gint ett_h245_MultiplexFormat = -1;
static gint ett_h245_AudioTelephonyEventCapability = -1;
static gint ett_h245_AudioToneCapability = -1;
static gint ett_h245_NoPTAudioTelephonyEventCapability = -1;
static gint ett_h245_NoPTAudioToneCapability = -1;
static gint ett_h245_MultiplePayloadStreamCapability = -1;
static gint ett_h245_DepFECCapability = -1;
static gint ett_h245_FECC_rfc2733 = -1;
static gint ett_h245_T_separateStreamBool = -1;
static gint ett_h245_FECCapability = -1;
static gint ett_h245_Rfc2733Format = -1;
static gint ett_h245_OpenLogicalChannel = -1;
static gint ett_h245_T_forwardLogicalChannelParameters = -1;
static gint ett_h245_OLC_forw_multiplexParameters = -1;
static gint ett_h245_OLC_reverseLogicalChannelParameters = -1;
static gint ett_h245_OLC_rev_multiplexParameters = -1;
static gint ett_h245_NetworkAccessParameters = -1;
static gint ett_h245_T_distribution = -1;
static gint ett_h245_T_networkAddress = -1;
static gint ett_h245_T_t120SetupProcedure = -1;
static gint ett_h245_Q2931Address = -1;
static gint ett_h245_T_address = -1;
static gint ett_h245_V75Parameters = -1;
static gint ett_h245_DataType = -1;
static gint ett_h245_H235Media = -1;
static gint ett_h245_T_mediaType = -1;
static gint ett_h245_MultiplexedStreamParameter = -1;
static gint ett_h245_H222LogicalChannelParameters = -1;
static gint ett_h245_H223LogicalChannelParameters = -1;
static gint ett_h245_T_adaptationLayerType = -1;
static gint ett_h245_Al3 = -1;
static gint ett_h245_H223AL1MParameters = -1;
static gint ett_h245_T_transferMode = -1;
static gint ett_h245_AL1HeaderFEC = -1;
static gint ett_h245_AL1CrcLength = -1;
static gint ett_h245_ArqType = -1;
static gint ett_h245_H223AL2MParameters = -1;
static gint ett_h245_AL2HeaderFEC = -1;
static gint ett_h245_H223AL3MParameters = -1;
static gint ett_h245_T_headerFormat = -1;
static gint ett_h245_AL3CrcLength = -1;
static gint ett_h245_H223AnnexCArqParameters = -1;
static gint ett_h245_T_numberOfRetransmissions = -1;
static gint ett_h245_V76LogicalChannelParameters = -1;
static gint ett_h245_T_suspendResume = -1;
static gint ett_h245_V76LCP_mode = -1;
static gint ett_h245_T_eRM = -1;
static gint ett_h245_T_recovery = -1;
static gint ett_h245_V76HDLCParameters = -1;
static gint ett_h245_CRCLength = -1;
static gint ett_h245_H2250LogicalChannelParameters = -1;
static gint ett_h245_T_mediaPacketization = -1;
static gint ett_h245_RTPPayloadType = -1;
static gint ett_h245_T_payloadDescriptor = -1;
static gint ett_h245_RedundancyEncoding = -1;
static gint ett_h245_T_rtpRedundancyEncoding = -1;
static gint ett_h245_SEQUENCE_OF_RedundancyEncodingElement = -1;
static gint ett_h245_RedundancyEncodingElement = -1;
static gint ett_h245_MultiplePayloadStream = -1;
static gint ett_h245_SEQUENCE_OF_MultiplePayloadStreamElement = -1;
static gint ett_h245_MultiplePayloadStreamElement = -1;
static gint ett_h245_DepFECData = -1;
static gint ett_h245_RFC2733Data = -1;
static gint ett_h245_FECdata_mode = -1;
static gint ett_h245_DepSeparateStream = -1;
static gint ett_h245_T_differentPort = -1;
static gint ett_h245_T_samePort = -1;
static gint ett_h245_FECData = -1;
static gint ett_h245_T_rfc2733 = -1;
static gint ett_h245_T_pktMode = -1;
static gint ett_h245_T_mode_rfc2733sameport = -1;
static gint ett_h245_T_mode_rfc2733diffport = -1;
static gint ett_h245_TransportAddress = -1;
static gint ett_h245_UnicastAddress = -1;
static gint ett_h245_T_iPAddress = -1;
static gint ett_h245_T_iPXAddress = -1;
static gint ett_h245_T_iP6Address = -1;
static gint ett_h245_T_iPSourceRouteAddress = -1;
static gint ett_h245_T_routing = -1;
static gint ett_h245_T_route = -1;
static gint ett_h245_MulticastAddress = -1;
static gint ett_h245_MIPAddress = -1;
static gint ett_h245_MIP6Address = -1;
static gint ett_h245_EncryptionSync = -1;
static gint ett_h245_SEQUENCE_SIZE_1_256_OF_EscrowData = -1;
static gint ett_h245_EscrowData = -1;
static gint ett_h245_OpenLogicalChannelAck = -1;
static gint ett_h245_OLC_ack_reverseLogicalChannelParameters = -1;
static gint ett_h245_T_olc_ack_multiplexParameters = -1;
static gint ett_h245_T_forwardMultiplexAckParameters = -1;
static gint ett_h245_OpenLogicalChannelReject = -1;
static gint ett_h245_OpenLogicalChannelRejectCause = -1;
static gint ett_h245_OpenLogicalChannelConfirm = -1;
static gint ett_h245_H2250LogicalChannelAckParameters = -1;
static gint ett_h245_CloseLogicalChannel = -1;
static gint ett_h245_T_cLC_source = -1;
static gint ett_h245_Clc_reason = -1;
static gint ett_h245_CloseLogicalChannelAck = -1;
static gint ett_h245_RequestChannelClose = -1;
static gint ett_h245_T_reason = -1;
static gint ett_h245_RequestChannelCloseAck = -1;
static gint ett_h245_RequestChannelCloseReject = -1;
static gint ett_h245_RequestChannelCloseRejectCause = -1;
static gint ett_h245_RequestChannelCloseRelease = -1;
static gint ett_h245_MultiplexEntrySend = -1;
static gint ett_h245_SET_SIZE_1_15_OF_MultiplexEntryDescriptor = -1;
static gint ett_h245_MultiplexEntryDescriptor = -1;
static gint ett_h245_T_elementList = -1;
static gint ett_h245_MultiplexElement = -1;
static gint ett_h245_Me_type = -1;
static gint ett_h245_T_subElementList = -1;
static gint ett_h245_ME_repeatCount = -1;
static gint ett_h245_MultiplexEntrySendAck = -1;
static gint ett_h245_SET_SIZE_1_15_OF_MultiplexTableEntryNumber = -1;
static gint ett_h245_MultiplexEntrySendReject = -1;
static gint ett_h245_SET_SIZE_1_15_OF_MultiplexEntryRejectionDescriptions = -1;
static gint ett_h245_MultiplexEntryRejectionDescriptions = -1;
static gint ett_h245_MultiplexEntryRejectionDescriptionsCause = -1;
static gint ett_h245_MultiplexEntrySendRelease = -1;
static gint ett_h245_RequestMultiplexEntry = -1;
static gint ett_h245_RequestMultiplexEntryAck = -1;
static gint ett_h245_RequestMultiplexEntryReject = -1;
static gint ett_h245_SET_SIZE_1_15_OF_RequestMultiplexEntryRejectionDescriptions = -1;
static gint ett_h245_RequestMultiplexEntryRejectionDescriptions = -1;
static gint ett_h245_RequestMultiplexEntryRejectionDescriptionsCause = -1;
static gint ett_h245_RequestMultiplexEntryRelease = -1;
static gint ett_h245_RequestMode = -1;
static gint ett_h245_SEQUENCE_SIZE_1_256_OF_ModeDescription = -1;
static gint ett_h245_RequestModeAck = -1;
static gint ett_h245_Req_mode_ack_response = -1;
static gint ett_h245_RequestModeReject = -1;
static gint ett_h245_RequestModeRejectCause = -1;
static gint ett_h245_RequestModeRelease = -1;
static gint ett_h245_ModeDescription = -1;
static gint ett_h245_ModeElementType = -1;
static gint ett_h245_ModeElement = -1;
static gint ett_h245_H235Mode = -1;
static gint ett_h245_T_mediaMode = -1;
static gint ett_h245_MultiplexedStreamModeParameters = -1;
static gint ett_h245_RedundancyEncodingDTMode = -1;
static gint ett_h245_SEQUENCE_OF_RedundancyEncodingDTModeElement = -1;
static gint ett_h245_RedundancyEncodingDTModeElement = -1;
static gint ett_h245_Re_type = -1;
static gint ett_h245_MultiplePayloadStreamMode = -1;
static gint ett_h245_SEQUENCE_OF_MultiplePayloadStreamElementMode = -1;
static gint ett_h245_MultiplePayloadStreamElementMode = -1;
static gint ett_h245_DepFECMode = -1;
static gint ett_h245_T_rfc2733Mode = -1;
static gint ett_h245_FEC_mode = -1;
static gint ett_h245_FECMode = -1;
static gint ett_h245_H223ModeParameters = -1;
static gint ett_h245_AdaptationLayerType = -1;
static gint ett_h245_V76ModeParameters = -1;
static gint ett_h245_H2250ModeParameters = -1;
static gint ett_h245_RedundancyEncodingMode = -1;
static gint ett_h245_T_secondaryEncodingMode = -1;
static gint ett_h245_VideoMode = -1;
static gint ett_h245_H261VideoMode = -1;
static gint ett_h245_H261Resolution = -1;
static gint ett_h245_H262VideoMode = -1;
static gint ett_h245_T_profileAndLevel = -1;
static gint ett_h245_H263VideoMode = -1;
static gint ett_h245_H263Resolution = -1;
static gint ett_h245_IS11172VideoMode = -1;
static gint ett_h245_AudioMode = -1;
static gint ett_h245_Mode_g7231 = -1;
static gint ett_h245_IS11172AudioMode = -1;
static gint ett_h245_T_audioLayer = -1;
static gint ett_h245_T_audioSampling = -1;
static gint ett_h245_IS11172_multichannelType = -1;
static gint ett_h245_IS13818AudioMode = -1;
static gint ett_h245_IS13818AudioLayer = -1;
static gint ett_h245_IS13818AudioSampling = -1;
static gint ett_h245_IS13818MultichannelType = -1;
static gint ett_h245_G7231AnnexCMode = -1;
static gint ett_h245_VBDMode = -1;
static gint ett_h245_DataMode = -1;
static gint ett_h245_DataModeApplication = -1;
static gint ett_h245_T38faxApp = -1;
static gint ett_h245_EncryptionMode = -1;
static gint ett_h245_RoundTripDelayRequest = -1;
static gint ett_h245_RoundTripDelayResponse = -1;
static gint ett_h245_MaintenanceLoopRequest = -1;
static gint ett_h245_Mlr_type = -1;
static gint ett_h245_MaintenanceLoopAck = -1;
static gint ett_h245_Mla_type = -1;
static gint ett_h245_MaintenanceLoopReject = -1;
static gint ett_h245_Mlrej_type = -1;
static gint ett_h245_MaintenanceLoopRejectCause = -1;
static gint ett_h245_MaintenanceLoopOffCommand = -1;
static gint ett_h245_CommunicationModeCommand = -1;
static gint ett_h245_SET_SIZE_1_256_OF_CommunicationModeTableEntry = -1;
static gint ett_h245_CommunicationModeRequest = -1;
static gint ett_h245_CommunicationModeResponse = -1;
static gint ett_h245_CommunicationModeTableEntry = -1;
static gint ett_h245_T_entryDataType = -1;
static gint ett_h245_ConferenceRequest = -1;
static gint ett_h245_T_requestTerminalCertificate = -1;
static gint ett_h245_CertSelectionCriteria = -1;
static gint ett_h245_Criteria = -1;
static gint ett_h245_TerminalLabel = -1;
static gint ett_h245_ConferenceResponse = -1;
static gint ett_h245_T_mCTerminalIDResponse = -1;
static gint ett_h245_T_terminalIDResponse = -1;
static gint ett_h245_T_conferenceIDResponse = -1;
static gint ett_h245_T_passwordResponse = -1;
static gint ett_h245_SET_SIZE_1_256_OF_TerminalLabel = -1;
static gint ett_h245_T_makeMeChairResponse = -1;
static gint ett_h245_T_extensionAddressResponse = -1;
static gint ett_h245_T_chairTokenOwnerResponse = -1;
static gint ett_h245_T_terminalCertificateResponse = -1;
static gint ett_h245_T_broadcastMyLogicalChannelResponse = -1;
static gint ett_h245_T_makeTerminalBroadcasterResponse = -1;
static gint ett_h245_T_sendThisSourceResponse = -1;
static gint ett_h245_RequestAllTerminalIDsResponse = -1;
static gint ett_h245_SEQUENCE_OF_TerminalInformation = -1;
static gint ett_h245_TerminalInformation = -1;
static gint ett_h245_RemoteMCRequest = -1;
static gint ett_h245_RemoteMCResponse = -1;
static gint ett_h245_T_reject = -1;
static gint ett_h245_MultilinkRequest = -1;
static gint ett_h245_CallInformationReq = -1;
static gint ett_h245_AddConnectionReq = -1;
static gint ett_h245_RemoveConnectionReq = -1;
static gint ett_h245_MaximumHeaderIntervalReq = -1;
static gint ett_h245_T_requestType = -1;
static gint ett_h245_MultilinkResponse = -1;
static gint ett_h245_CallInformationResp = -1;
static gint ett_h245_AddConnectionResp = -1;
static gint ett_h245_T_responseCode = -1;
static gint ett_h245_T_rejected = -1;
static gint ett_h245_RemoveConnectionResp = -1;
static gint ett_h245_MaximumHeaderIntervalResp = -1;
static gint ett_h245_MultilinkIndication = -1;
static gint ett_h245_T_crcDesired = -1;
static gint ett_h245_T_excessiveError = -1;
static gint ett_h245_DialingInformation = -1;
static gint ett_h245_SET_SIZE_1_65535_OF_DialingInformationNumber = -1;
static gint ett_h245_DialingInformationNumber = -1;
static gint ett_h245_SET_SIZE_1_255_OF_DialingInformationNetworkType = -1;
static gint ett_h245_DialingInformationNetworkType = -1;
static gint ett_h245_ConnectionIdentifier = -1;
static gint ett_h245_LogicalChannelRateRequest = -1;
static gint ett_h245_LogicalChannelRateAcknowledge = -1;
static gint ett_h245_LogicalChannelRateReject = -1;
static gint ett_h245_LogicalChannelRateRejectReason = -1;
static gint ett_h245_LogicalChannelRateRelease = -1;
static gint ett_h245_SendTerminalCapabilitySet = -1;
static gint ett_h245_T_specificRequest = -1;
static gint ett_h245_SET_SIZE_1_65535_OF_CapabilityTableEntryNumber = -1;
static gint ett_h245_SET_SIZE_1_256_OF_CapabilityDescriptorNumber = -1;
static gint ett_h245_EncryptionCommand = -1;
static gint ett_h245_T_encryptionAlgorithmID = -1;
static gint ett_h245_FlowControlCommand = -1;
static gint ett_h245_Scope = -1;
static gint ett_h245_Restriction = -1;
static gint ett_h245_EndSessionCommand = -1;
static gint ett_h245_T_gstnOptions = -1;
static gint ett_h245_T_isdnOptions = -1;
static gint ett_h245_ConferenceCommand = -1;
static gint ett_h245_SubstituteConferenceIDCommand = -1;
static gint ett_h245_EncryptionUpdateDirection = -1;
static gint ett_h245_MiscellaneousCommand = -1;
static gint ett_h245_Mc_type = -1;
static gint ett_h245_T_videoFastUpdateGOB = -1;
static gint ett_h245_T_videoFastUpdateMB = -1;
static gint ett_h245_T_progressiveRefinementStart = -1;
static gint ett_h245_T_repeatCount = -1;
static gint ett_h245_T_videoBadMBs = -1;
static gint ett_h245_SEQUENCE_OF_PictureReference = -1;
static gint ett_h245_T_lostPartialPicture = -1;
static gint ett_h245_T_encryptionUpdateCommand = -1;
static gint ett_h245_T_encryptionUpdateAck = -1;
static gint ett_h245_KeyProtectionMethod = -1;
static gint ett_h245_EncryptionUpdateRequest = -1;
static gint ett_h245_PictureReference = -1;
static gint ett_h245_H223MultiplexReconfiguration = -1;
static gint ett_h245_T_h223ModeChange = -1;
static gint ett_h245_T_h223AnnexADoubleFlag = -1;
static gint ett_h245_NewATMVCCommand = -1;
static gint ett_h245_Cmd_aal = -1;
static gint ett_h245_Cmd_aal1 = -1;
static gint ett_h245_Cmd_clockRecovery = -1;
static gint ett_h245_Cmd_errorCorrection = -1;
static gint ett_h245_Cmd_aal5 = -1;
static gint ett_h245_Cmd_multiplex = -1;
static gint ett_h245_Cmd_reverseParameters = -1;
static gint ett_h245_CmdR_multiplex = -1;
static gint ett_h245_MobileMultilinkReconfigurationCommand = -1;
static gint ett_h245_T_status = -1;
static gint ett_h245_FunctionNotUnderstood = -1;
static gint ett_h245_FunctionNotSupported = -1;
static gint ett_h245_FunctionNotSupportedCause = -1;
static gint ett_h245_ConferenceIndication = -1;
static gint ett_h245_TerminalYouAreSeeingInSubPictureNumber = -1;
static gint ett_h245_VideoIndicateCompose = -1;
static gint ett_h245_MiscellaneousIndication = -1;
static gint ett_h245_Mi_type = -1;
static gint ett_h245_T_videoNotDecodedMBs = -1;
static gint ett_h245_JitterIndication = -1;
static gint ett_h245_H223SkewIndication = -1;
static gint ett_h245_H2250MaximumSkewIndication = -1;
static gint ett_h245_MCLocationIndication = -1;
static gint ett_h245_VendorIdentification = -1;
static gint ett_h245_NewATMVCIndication = -1;
static gint ett_h245_Ind_aal = -1;
static gint ett_h245_Ind_aal1 = -1;
static gint ett_h245_Ind_clockRecovery = -1;
static gint ett_h245_Ind_errorCorrection = -1;
static gint ett_h245_Ind_aal5 = -1;
static gint ett_h245_Ind_multiplex = -1;
static gint ett_h245_Ind_reverseParameters = -1;
static gint ett_h245_IndR_multiplex = -1;
static gint ett_h245_Params = -1;
static gint ett_h245_UserInputIndication = -1;
static gint ett_h245_T_userInputSupportIndication = -1;
static gint ett_h245_T_signal = -1;
static gint ett_h245_T_rtp = -1;
static gint ett_h245_T_signalUpdate = -1;
static gint ett_h245_Si_rtp = -1;
static gint ett_h245_T_extendedAlphanumeric = -1;
static gint ett_h245_EncryptedAlphanumeric = -1;
static gint ett_h245_FlowControlIndication = -1;
static gint ett_h245_MobileMultilinkReconfigurationIndication = -1;

/*--- End of included file: packet-h245-ett.c ---*/
#line 403 "../../asn1/h245/packet-h245-template.c"

/* Forward declarations */
static int dissect_h245_MultimediaSystemControlMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static void reset_h245_pi(void *dummy _U_)
{
	h245_pi = NULL; /* Make sure we don't leave ep_alloc()ated memory lying around */
}


/*--- Included file: packet-h245-fn.c ---*/
#line 1 "../../asn1/h245/packet-h245-fn.c"
/*--- Cyclic dependencies ---*/

/* GenericParameter -> ParameterValue -> ParameterValue/genericParameter -> GenericParameter */
static int dissect_h245_GenericParameter(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* VideoCapability -> ExtendedVideoCapability -> ExtendedVideoCapability/videoCapability -> VideoCapability */
static int dissect_h245_VideoCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* AudioCapability -> VBDCapability -> AudioCapability */
static int dissect_h245_AudioCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* DataType -> H235Media -> H235Media/mediaType -> RedundancyEncoding -> DataType */
/* DataType -> H235Media -> H235Media/mediaType -> RedundancyEncoding -> RedundancyEncoding/rtpRedundancyEncoding -> RedundancyEncodingElement -> DataType */
/* DataType -> H235Media -> H235Media/mediaType -> MultiplePayloadStream -> MultiplePayloadStream/elements -> MultiplePayloadStreamElement -> DataType */
static int dissect_h245_DataType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* MultiplexElement -> MultiplexElement/type -> MultiplexElement/type/subElementList -> MultiplexElement */
static int dissect_h245_MultiplexElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* AudioMode -> VBDMode -> AudioMode */
static int dissect_h245_AudioMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* ModeElementType -> RedundancyEncodingDTMode -> RedundancyEncodingDTModeElement -> RedundancyEncodingDTModeElement/type -> FECMode -> ModeElementType */
/* ModeElementType -> MultiplePayloadStreamMode -> MultiplePayloadStreamMode/elements -> MultiplePayloadStreamElementMode -> ModeElementType */
static int dissect_h245_ModeElementType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);




static int
dissect_h245_T_object(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_object_identifier_str(tvb, offset, actx, tree, hf_index, &nsiOID);

  return offset;
}



static int
dissect_h245_T_t35CountryCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &t35CountryCode, FALSE);

  return offset;
}



static int
dissect_h245_T_t35Extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &t35Extension, FALSE);

  return offset;
}



static int
dissect_h245_T_manufacturerCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &manufacturerCode, FALSE);

  return offset;
}


static const per_sequence_t H221NonStandardID_sequence[] = {
  { &hf_h245_t35CountryCode , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_T_t35CountryCode },
  { &hf_h245_t35Extension   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_T_t35Extension },
  { &hf_h245_manufacturerCode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_T_manufacturerCode },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H221NonStandardID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 970 "../../asn1/h245/h245.cnf"
  t35CountryCode = 0;
  t35Extension = 0;
  manufacturerCode = 0;

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H221NonStandardID, H221NonStandardID_sequence);

#line 974 "../../asn1/h245/h245.cnf"
  h221NonStandard = ((t35CountryCode * 256) + t35Extension) * 65536 + manufacturerCode;
  proto_tree_add_uint(tree, hf_h245Manufacturer, tvb, (offset>>3)-4, 4, h221NonStandard);

  return offset;
}


static const value_string h245_NonStandardIdentifier_vals[] = {
  {   0, "object" },
  {   1, "h221NonStandard" },
  { 0, NULL }
};

static const per_choice_t NonStandardIdentifier_choice[] = {
  {   0, &hf_h245_object         , ASN1_NO_EXTENSIONS     , dissect_h245_T_object },
  {   1, &hf_h245_h221NonStandardID, ASN1_NO_EXTENSIONS     , dissect_h245_H221NonStandardID },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_NonStandardIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 951 "../../asn1/h245/h245.cnf"
	gint32 value;

	nsiOID = "";
	h221NonStandard = 0;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_NonStandardIdentifier, NonStandardIdentifier_choice,
                                 &value);

	switch (value) {
		case 0 :  /* object */
			nsp_handle = dissector_get_string_handle(nsp_object_dissector_table, nsiOID);
			break;
		case 1 :  /* h221NonStandard */
			nsp_handle = dissector_get_uint_handle(nsp_h221_dissector_table, h221NonStandard);
			break;
		default :
			nsp_handle = NULL;
    }


  return offset;
}



static int
dissect_h245_T_nsd_data(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 985 "../../asn1/h245/h245.cnf"
  tvbuff_t *next_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &next_tvb);

  if (next_tvb && tvb_length(next_tvb)) {
    call_dissector((nsp_handle)?nsp_handle:data_handle, next_tvb, actx->pinfo, tree);
  }


  return offset;
}


static const per_sequence_t NonStandardParameter_sequence[] = {
  { &hf_h245_nonStandardIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_NonStandardIdentifier },
  { &hf_h245_nsd_data       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_T_nsd_data },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_NonStandardParameter(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 983 "../../asn1/h245/h245.cnf"
  nsp_handle = NULL;

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_NonStandardParameter, NonStandardParameter_sequence);

  return offset;
}


static const per_sequence_t NonStandardMessage_sequence[] = {
  { &hf_h245_nonStandardData, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_NonStandardParameter },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_NonStandardMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_NonStandardMessage, NonStandardMessage_sequence);

  return offset;
}



static int
dissect_h245_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_h245_INTEGER_0_16777215(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16777215U, NULL, FALSE);

  return offset;
}


static const per_sequence_t MasterSlaveDetermination_sequence[] = {
  { &hf_h245_terminalType   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_255 },
  { &hf_h245_statusDeterminationNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_16777215 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MasterSlaveDetermination(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MasterSlaveDetermination, MasterSlaveDetermination_sequence);

#line 573 "../../asn1/h245/h245.cnf"

if (h245_pi != NULL)
  h245_pi->msg_type = H245_MastSlvDet;

  return offset;
}



static int
dissect_h245_SequenceNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_h245_OBJECT_IDENTIFIER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_h245_INTEGER_1_256(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, FALSE);

  return offset;
}



static int
dissect_h245_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t T_aal1_sequence[] = {
  { &hf_h245_nullClockRecovery, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_srtsClockRecovery_bool, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_adaptiveClockRecovery, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_nullErrorCorrection, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_longInterleaver, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_shortInterleaver, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_errorCorrectionOnly, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_structuredDataTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_partiallyFilledCells, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_aal1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_aal1, T_aal1_sequence);

  return offset;
}



static int
dissect_h245_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_aal5_sequence[] = {
  { &hf_h245_forwardMaximumSDUSize, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_65535 },
  { &hf_h245_backwardMaximumSDUSize, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_65535 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_aal5(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_aal5, T_aal5_sequence);

  return offset;
}



static int
dissect_h245_INTEGER_1_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_rangeOfBitRates_sequence[] = {
  { &hf_h245_lowerBitRate   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_65535 },
  { &hf_h245_higherBitRate  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_65535 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_rangeOfBitRates(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_rangeOfBitRates, T_rangeOfBitRates_sequence);

  return offset;
}


static const value_string h245_Avb_type_vals[] = {
  {   0, "singleBitRate" },
  {   1, "rangeOfBitRates" },
  { 0, NULL }
};

static const per_choice_t Avb_type_choice[] = {
  {   0, &hf_h245_singleBitRate  , ASN1_NO_EXTENSIONS     , dissect_h245_INTEGER_1_65535 },
  {   1, &hf_h245_rangeOfBitRates, ASN1_NO_EXTENSIONS     , dissect_h245_T_rangeOfBitRates },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_Avb_type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_Avb_type, Avb_type_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_availableBitRates_sequence[] = {
  { &hf_h245_avb_type       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_Avb_type },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_availableBitRates(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_availableBitRates, T_availableBitRates_sequence);

  return offset;
}



static int
dissect_h245_NumericString_SIZE_1_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_NumericString(tvb, offset, actx, tree, hf_index,
                                          1, 16, FALSE);

  return offset;
}



static int
dissect_h245_OCTET_STRING_SIZE_1_20(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 20, FALSE, NULL);

  return offset;
}


static const value_string h245_T_address_vals[] = {
  {   0, "internationalNumber" },
  {   1, "nsapAddress" },
  { 0, NULL }
};

static const per_choice_t T_address_choice[] = {
  {   0, &hf_h245_internationalNumber, ASN1_EXTENSION_ROOT    , dissect_h245_NumericString_SIZE_1_16 },
  {   1, &hf_h245_nsapAddress    , ASN1_EXTENSION_ROOT    , dissect_h245_OCTET_STRING_SIZE_1_20 },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_address(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_address, T_address_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Q2931Address_sequence[] = {
  { &hf_h245_address        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_address },
  { &hf_h245_subaddress     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_OCTET_STRING_SIZE_1_20 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_Q2931Address(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_Q2931Address, Q2931Address_sequence);

  return offset;
}


static const per_sequence_t SET_SIZE_1_256_OF_Q2931Address_set_of[1] = {
  { &hf_h245_gatewayAddress_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_Q2931Address },
};

static int
dissect_h245_SET_SIZE_1_256_OF_Q2931Address(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h245_SET_SIZE_1_256_OF_Q2931Address, SET_SIZE_1_256_OF_Q2931Address_set_of,
                                             1, 256, FALSE);

  return offset;
}


static const per_sequence_t T_aal1ViaGateway_sequence[] = {
  { &hf_h245_gatewayAddress , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SET_SIZE_1_256_OF_Q2931Address },
  { &hf_h245_nullClockRecovery, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_srtsClockRecoveryflag, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_adaptiveClockRecovery, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_nullErrorCorrection, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_longInterleaver, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_shortInterleaver, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_errorCorrectionOnly, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_structuredDataTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_partiallyFilledCells, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_aal1ViaGateway(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_aal1ViaGateway, T_aal1ViaGateway_sequence);

  return offset;
}


static const per_sequence_t VCCapability_sequence[] = {
  { &hf_h245_aal1           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_T_aal1 },
  { &hf_h245_aal5           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_T_aal5 },
  { &hf_h245_transportStream_bool, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_programStream  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_availableBitRates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_availableBitRates },
  { &hf_h245_aal1ViaGateway , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_T_aal1ViaGateway },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_VCCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_VCCapability, VCCapability_sequence);

  return offset;
}


static const per_sequence_t SET_OF_VCCapability_set_of[1] = {
  { &hf_h245_vcCapability_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_VCCapability },
};

static int
dissect_h245_SET_OF_VCCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_h245_SET_OF_VCCapability, SET_OF_VCCapability_set_of);

  return offset;
}


static const per_sequence_t H222Capability_sequence[] = {
  { &hf_h245_numberOfVCs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_256 },
  { &hf_h245_vcCapability   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SET_OF_VCCapability },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H222Capability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H222Capability, H222Capability_sequence);

  return offset;
}



static int
dissect_h245_INTEGER_0_1023(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, FALSE);

  return offset;
}



static int
dissect_h245_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_h245_INTEGER_1_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 15U, NULL, FALSE);

  return offset;
}



static int
dissect_h245_INTEGER_2_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            2U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_enhanced_sequence[] = {
  { &hf_h245_maximumNestingDepth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_15 },
  { &hf_h245_maximumElementListSize, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_2_255 },
  { &hf_h245_maximumSubElementListSize, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_2_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_enhanced(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_enhanced, T_enhanced_sequence);

  return offset;
}


static const value_string h245_T_h223MultiplexTableCapability_vals[] = {
  {   0, "basic" },
  {   1, "enhanced" },
  { 0, NULL }
};

static const per_choice_t T_h223MultiplexTableCapability_choice[] = {
  {   0, &hf_h245_basic          , ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   1, &hf_h245_enhanced       , ASN1_NO_EXTENSIONS     , dissect_h245_T_enhanced },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_h223MultiplexTableCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_h223MultiplexTableCapability, T_h223MultiplexTableCapability_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_mobileOperationTransmitCapability_sequence[] = {
  { &hf_h245_modeChangeCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_h223AnnexA     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_h223AnnexADoubleFlagFlag, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_h223AnnexB     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_h223AnnexBwithHeader, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_mobileOperationTransmitCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_mobileOperationTransmitCapability, T_mobileOperationTransmitCapability_sequence);

  return offset;
}


static const per_sequence_t H223AnnexCCapability_sequence[] = {
  { &hf_h245_videoWithAL1M  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_videoWithAL2M  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_videoWithAL3M  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_audioWithAL1M  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_audioWithAL2M  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_audioWithAL3M  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_dataWithAL1M   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_dataWithAL2M   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_dataWithAL3M   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_alpduInterleaving, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_maximumAL1MPDUSize, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_65535 },
  { &hf_h245_maximumAL2MSDUSize, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_65535 },
  { &hf_h245_maximumAL3MSDUSize, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_65535 },
  { &hf_h245_rsCodeCapability, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H223AnnexCCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H223AnnexCCapability, H223AnnexCCapability_sequence);

  return offset;
}



static int
dissect_h245_INTEGER_1_19200(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 19200U, NULL, FALSE);

  return offset;
}



static int
dissect_h245_INTEGER_1_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_h245_INTEGER_1_65025(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65025U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_mobileMultilinkFrameCapability_sequence[] = {
  { &hf_h245_maximumSampleSize, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_255 },
  { &hf_h245_maximumPayloadLength, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_65025 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_mobileMultilinkFrameCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_mobileMultilinkFrameCapability, T_mobileMultilinkFrameCapability_sequence);

  return offset;
}


static const per_sequence_t H223Capability_sequence[] = {
  { &hf_h245_transportWithI_frames, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_videoWithAL1   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_videoWithAL2   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_videoWithAL3   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_audioWithAL1   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_audioWithAL2   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_audioWithAL3   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_dataWithAL1    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_dataWithAL2    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_dataWithAL3    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_maximumAl2SDUSize, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_65535 },
  { &hf_h245_maximumAl3SDUSize, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_65535 },
  { &hf_h245_maximumDelayJitter, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_1023 },
  { &hf_h245_h223MultiplexTableCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_h223MultiplexTableCapability },
  { &hf_h245_maxMUXPDUSizeCapability, ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_nsrpSupport    , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_mobileOperationTransmitCapability, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_T_mobileOperationTransmitCapability },
  { &hf_h245_h223AnnexCCapability, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_H223AnnexCCapability },
  { &hf_h245_bitRate_1_19200, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_INTEGER_1_19200 },
  { &hf_h245_mobileMultilinkFrameCapability, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_T_mobileMultilinkFrameCapability },
  { NULL, 0, 0, NULL }
};

int
dissect_h245_H223Capability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H223Capability, H223Capability_sequence);

  return offset;
}



static int
dissect_h245_INTEGER_2_8191(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            2U, 8191U, NULL, FALSE);

  return offset;
}



static int
dissect_h245_INTEGER_1_4095(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 4095U, NULL, FALSE);

  return offset;
}



static int
dissect_h245_INTEGER_1_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t V75Capability_sequence[] = {
  { &hf_h245_audioHeader    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_V75Capability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_V75Capability, V75Capability_sequence);

  return offset;
}


static const per_sequence_t V76Capability_sequence[] = {
  { &hf_h245_suspendResumeCapabilitywAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_suspendResumeCapabilitywoAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_rejCapability  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_sREJCapability , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_mREJCapability , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_crc8bitCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_crc16bitCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_crc32bitCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_uihCapability  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_numOfDLCS      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_2_8191 },
  { &hf_h245_twoOctetAddressFieldCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_loopBackTestCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_n401Capability , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_4095 },
  { &hf_h245_maxWindowSizeCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_127 },
  { &hf_h245_v75Capability  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_V75Capability },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_V76Capability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_V76Capability, V76Capability_sequence);

  return offset;
}



static int
dissect_h245_INTEGER_1_65536(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65536U, NULL, FALSE);

  return offset;
}


static const per_sequence_t V42bis_sequence[] = {
  { &hf_h245_numberOfCodewords, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_65536 },
  { &hf_h245_maximumStringLength, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_256 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_V42bis(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_V42bis, V42bis_sequence);

  return offset;
}


static const value_string h245_CompressionType_vals[] = {
  {   0, "v42bis" },
  { 0, NULL }
};

static const per_choice_t CompressionType_choice[] = {
  {   0, &hf_h245_v42bis         , ASN1_EXTENSION_ROOT    , dissect_h245_V42bis },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_CompressionType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_CompressionType, CompressionType_choice,
                                 NULL);

  return offset;
}


static const value_string h245_T_v76wCompression_vals[] = {
  {   0, "transmitCompression" },
  {   1, "receiveCompression" },
  {   2, "transmitAndReceiveCompression" },
  { 0, NULL }
};

static const per_choice_t T_v76wCompression_choice[] = {
  {   0, &hf_h245_transmitCompression, ASN1_EXTENSION_ROOT    , dissect_h245_CompressionType },
  {   1, &hf_h245_receiveCompression, ASN1_EXTENSION_ROOT    , dissect_h245_CompressionType },
  {   2, &hf_h245_transmitAndReceiveCompression, ASN1_EXTENSION_ROOT    , dissect_h245_CompressionType },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_v76wCompression(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_v76wCompression, T_v76wCompression_choice,
                                 NULL);

  return offset;
}


const value_string DataProtocolCapability_vals[] = {
  {   0, "nonStandard" },
  {   1, "v14buffered" },
  {   2, "v42lapm" },
  {   3, "hdlcFrameTunnelling" },
  {   4, "h310SeparateVCStack" },
  {   5, "h310SingleVCStack" },
  {   6, "transparent" },
  {   7, "segmentationAndReassembly" },
  {   8, "hdlcFrameTunnelingwSAR" },
  {   9, "v120" },
  {  10, "separateLANStack" },
  {  11, "v76wCompression" },
  {  12, "tcp" },
  {  13, "udp" },
  { 0, NULL }
};

static const per_choice_t DataProtocolCapability_choice[] = {
  {   0, &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardParameter },
  {   1, &hf_h245_v14buffered    , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_v42lapm        , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   3, &hf_h245_hdlcFrameTunnelling, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   4, &hf_h245_h310SeparateVCStack, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   5, &hf_h245_h310SingleVCStack, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   6, &hf_h245_transparent    , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   7, &hf_h245_segmentationAndReassembly, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {   8, &hf_h245_hdlcFrameTunnelingwSAR, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {   9, &hf_h245_v120           , ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {  10, &hf_h245_separateLANStack, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {  11, &hf_h245_v76wCompression, ASN1_NOT_EXTENSION_ROOT, dissect_h245_T_v76wCompression },
  {  12, &hf_h245_tcp            , ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {  13, &hf_h245_udp            , ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

int
dissect_h245_DataProtocolCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_DataProtocolCapability, DataProtocolCapability_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_t84Restricted_sequence[] = {
  { &hf_h245_qcif_bool      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_cif_bool       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_ccir601Seq     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_ccir601Prog    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_hdtvSeq        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_hdtvProg       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_g3FacsMH200x100, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_g3FacsMH200x200, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_g4FacsMMR200x100, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_g4FacsMMR200x200, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_jbig200x200Seq , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_jbig200x200Prog, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_jbig300x300Seq , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_jbig300x300Prog, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_digPhotoLow    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_digPhotoMedSeq , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_digPhotoMedProg, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_digPhotoHighSeq, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_digPhotoHighProg, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_t84Restricted(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_t84Restricted, T_t84Restricted_sequence);

  return offset;
}


static const value_string h245_T84Profile_vals[] = {
  {   0, "t84Unrestricted" },
  {   1, "t84Restricted" },
  { 0, NULL }
};

static const per_choice_t T84Profile_choice[] = {
  {   0, &hf_h245_t84Unrestricted, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   1, &hf_h245_t84Restricted  , ASN1_NO_EXTENSIONS     , dissect_h245_T_t84Restricted },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T84Profile(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T84Profile, T84Profile_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_t84_sequence[] = {
  { &hf_h245_t84Protocol    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_DataProtocolCapability },
  { &hf_h245_t84Profile     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_T84Profile },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_t84(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_t84, T_t84_sequence);

  return offset;
}



static int
dissect_h245_OCTET_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t Nlpid_sequence[] = {
  { &hf_h245_nlpidProtocol  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_DataProtocolCapability },
  { &hf_h245_nlpidData      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_Nlpid(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_Nlpid, Nlpid_sequence);

  return offset;
}


static const value_string h245_T38FaxRateManagement_vals[] = {
  {   0, "localTCF" },
  {   1, "transferredTCF" },
  { 0, NULL }
};

static const per_choice_t T38FaxRateManagement_choice[] = {
  {   0, &hf_h245_localTCF       , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_transferredTCF , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T38FaxRateManagement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T38FaxRateManagement, T38FaxRateManagement_choice,
                                 NULL);

  return offset;
}



static int
dissect_h245_INTEGER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string h245_T_t38FaxUdpEC_vals[] = {
  {   0, "t38UDPFEC" },
  {   1, "t38UDPRedundancy" },
  { 0, NULL }
};

static const per_choice_t T_t38FaxUdpEC_choice[] = {
  {   0, &hf_h245_t38UDPFEC      , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_t38UDPRedundancy, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_t38FaxUdpEC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_t38FaxUdpEC, T_t38FaxUdpEC_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T38FaxUdpOptions_sequence[] = {
  { &hf_h245_t38FaxMaxBuffer, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_h245_INTEGER },
  { &hf_h245_t38FaxMaxDatagram, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_h245_INTEGER },
  { &hf_h245_t38FaxUdpEC    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_T_t38FaxUdpEC },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T38FaxUdpOptions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T38FaxUdpOptions, T38FaxUdpOptions_sequence);

  return offset;
}


static const per_sequence_t T38FaxTcpOptions_sequence[] = {
  { &hf_h245_t38TCPBidirectionalMode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T38FaxTcpOptions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T38FaxTcpOptions, T38FaxTcpOptions_sequence);

  return offset;
}


static const per_sequence_t T38FaxProfile_sequence[] = {
  { &hf_h245_fillBitRemoval , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_transcodingJBIG, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_transcodingMMR , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_version        , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_255 },
  { &hf_h245_t38FaxRateManagement, ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_h245_T38FaxRateManagement },
  { &hf_h245_t38FaxUdpOptions, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_T38FaxUdpOptions },
  { &hf_h245_t38FaxTcpOptions, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_T38FaxTcpOptions },
  { NULL, 0, 0, NULL }
};

int
dissect_h245_T38FaxProfile(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T38FaxProfile, T38FaxProfile_sequence);

  return offset;
}


static const per_sequence_t T_t38fax_sequence[] = {
  { &hf_h245_t38FaxProtocol , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_DataProtocolCapability },
  { &hf_h245_t38FaxProfile  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_T38FaxProfile },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_t38fax(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_t38fax, T_t38fax_sequence);

  return offset;
}



static int
dissect_h245_T_standardOid(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 730 "../../asn1/h245/h245.cnf"
  const gchar *standard_oid_str = NULL;
  gef_ctx_t *gefx;

  offset = dissect_per_object_identifier_str(tvb, offset, actx, tree, hf_index, &standard_oid_str);

  gefx = gef_ctx_get(actx->private_data);
  if (gefx) gefx->id = standard_oid_str;

  if(strcmp(standard_oid_str,"0.0.8.235.0.3.76") == 0) {  /* MIKEY */
    if (upcoming_channel)
	  upcoming_channel->srtp_flag = TRUE;
  }

  if(!h245_lc_dissector && strcmp(standard_oid_str,"0.0.8.245.1.1.1") == 0)
	h245_lc_dissector = amr_handle;


  return offset;
}



static int
dissect_h245_OCTET_STRING_SIZE_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       16, 16, FALSE, NULL);

  return offset;
}



static int
dissect_h245_IA5String_SIZE_1_64(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 64, FALSE);

  return offset;
}


static const value_string h245_CapabilityIdentifier_vals[] = {
  {   0, "standard" },
  {   1, "h221NonStandard" },
  {   2, "uuid" },
  {   3, "domainBased" },
  { 0, NULL }
};

static const per_choice_t CapabilityIdentifier_choice[] = {
  {   0, &hf_h245_standardOid    , ASN1_EXTENSION_ROOT    , dissect_h245_T_standardOid },
  {   1, &hf_h245_h221NonStandard, ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardParameter },
  {   2, &hf_h245_uuid           , ASN1_EXTENSION_ROOT    , dissect_h245_OCTET_STRING_SIZE_16 },
  {   3, &hf_h245_domainBased    , ASN1_EXTENSION_ROOT    , dissect_h245_IA5String_SIZE_1_64 },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_CapabilityIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 716 "../../asn1/h245/h245.cnf"
  gef_ctx_t *gefx;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_CapabilityIdentifier, CapabilityIdentifier_choice,
                                 NULL);

#line 718 "../../asn1/h245/h245.cnf"
  gef_ctx_update_key(gef_ctx_get(actx->private_data));
  /* DEBUG */ /*proto_tree_add_text(tree, tvb, offset>>3, 0, "*** DEBUG CapabilityIdentifier: %s", gef_ctx_get(actx->private_data)->key);*/
  gefx = gef_ctx_get(actx->private_data);
  if (gefx) {
    /* DEBUG */ /*proto_tree_add_text(tree, tvb, offset>>3, 0, "*** DEBUG dissector_try_string: %s", gefx->key);*/
    actx->pinfo->private_data = actx;
    dissector_try_string(gef_name_dissector_table, gefx->key, tvb_new_subset(tvb, offset>>3, 0, 0), actx->pinfo, tree);
  }
  actx->private_data = gefx;  /* subdissector could overwrite it */

  return offset;
}



static int
dissect_h245_INTEGER_0_4294967295(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}



static int
dissect_h245_T_standard(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 761 "../../asn1/h245/h245.cnf"
  guint32 value_int = (guint32)-1;
  gef_ctx_t *gefx;

  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, &value_int, FALSE);

  gefx = gef_ctx_get(actx->private_data);
  if (gefx) gefx->id = ep_strdup_printf("%d", value_int);


  return offset;
}


static const value_string h245_ParameterIdentifier_vals[] = {
  {   0, "standard" },
  {   1, "h221NonStandard" },
  {   2, "uuid" },
  {   3, "domainBased" },
  { 0, NULL }
};

static const per_choice_t ParameterIdentifier_choice[] = {
  {   0, &hf_h245_standard       , ASN1_EXTENSION_ROOT    , dissect_h245_T_standard },
  {   1, &hf_h245_h221NonStandard, ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardParameter },
  {   2, &hf_h245_uuid           , ASN1_EXTENSION_ROOT    , dissect_h245_OCTET_STRING_SIZE_16 },
  {   3, &hf_h245_domainBased    , ASN1_EXTENSION_ROOT    , dissect_h245_IA5String_SIZE_1_64 },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_ParameterIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 747 "../../asn1/h245/h245.cnf"
  gef_ctx_t *gefx;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_ParameterIdentifier, ParameterIdentifier_choice,
                                 NULL);

#line 749 "../../asn1/h245/h245.cnf"
  gef_ctx_update_key(gef_ctx_get(actx->private_data));
  /* DEBUG */ /*proto_tree_add_text(tree, tvb, offset>>3, 0, "*** DEBUG ParameterIdentifier: %s", gef_ctx_get(actx->private_data)->key);*/
  gefx = gef_ctx_get(actx->private_data);
  if (gefx) {
    /* DEBUG */ /*proto_tree_add_text(tree, tvb, offset>>3, 0, "*** DEBUG dissector_try_string: %s", gefx->key);*/
    actx->pinfo->private_data = actx;
    dissector_try_string(gef_name_dissector_table, gefx->key, tvb_new_subset(tvb, offset>>3, 0, 0), actx->pinfo, tree);
  }
  actx->private_data = gefx;  /* subdissector could overwrite it */

  return offset;
}



static int
dissect_h245_T_booleanArray(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 770 "../../asn1/h245/h245.cnf"
  guint32 value;
  guint8 *buf;
  tvbuff_t *value_tvb;
  gef_ctx_t *gefx;

  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &value, FALSE);

  gefx = gef_ctx_get(actx->private_data);
  if (gefx) {
    buf = ep_alloc(sizeof(guint8));
    buf[0] = value;
    value_tvb = tvb_new_child_real_data(tvb, buf, sizeof(guint8), sizeof(guint8));
    /* DEBUG */ /*proto_tree_add_text(tree, tvb, offset>>3, 0, "*** DEBUG dissector_try_string: %s", gefx->key);*/
    add_new_data_source(actx->pinfo, value_tvb, "booleanArray");
    dissector_try_string(gef_content_dissector_table, gefx->key, value_tvb, actx->pinfo, tree);
  }


  return offset;
}



static int
dissect_h245_T_unsignedMin(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 787 "../../asn1/h245/h245.cnf"
  guint32 value;
  guint8 *buf;
  tvbuff_t *value_tvb;
  gef_ctx_t *gefx;

  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &value, FALSE);

  gefx = gef_ctx_get(actx->private_data);
  if (gefx) {
    buf = ep_alloc(sizeof(guint16));
    phtons(buf, value);
    value_tvb = tvb_new_child_real_data(tvb, buf, sizeof(guint16), sizeof(guint16));
    /* DEBUG */ /*proto_tree_add_text(tree, tvb, offset>>3, 0, "*** DEBUG dissector_try_string: %s", gefx->key);*/
    add_new_data_source(actx->pinfo, value_tvb, "unsignedMin");
    dissector_try_string(gef_content_dissector_table, gefx->key, value_tvb, actx->pinfo, tree);
  }


  return offset;
}



static int
dissect_h245_T_unsignedMax(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 804 "../../asn1/h245/h245.cnf"
  guint32 value;
  guint8 *buf;
  tvbuff_t *value_tvb;
  gef_ctx_t *gefx;

  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &value, FALSE);

  gefx = gef_ctx_get(actx->private_data);
  if (gefx) {
    buf = ep_alloc(sizeof(guint16));
    phtons(buf, value);
    value_tvb = tvb_new_child_real_data(tvb, buf, sizeof(guint16), sizeof(guint16));
    /* DEBUG */ /*proto_tree_add_text(tree, tvb, offset>>3, 0, "*** DEBUG dissector_try_string: %s", gefx->key);*/
    add_new_data_source(actx->pinfo, value_tvb, "unsignedMax");
    dissector_try_string(gef_content_dissector_table, gefx->key, value_tvb, actx->pinfo, tree);
  }


  return offset;
}



static int
dissect_h245_T_unsigned32Min(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 821 "../../asn1/h245/h245.cnf"
  guint32 value;
  guint8 *buf;
  tvbuff_t *value_tvb;
  gef_ctx_t *gefx;

  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, &value, FALSE);

  gefx = gef_ctx_get(actx->private_data);
  if (gefx) {
    buf = ep_alloc(sizeof(guint32));
    phtonl(buf, value);
    value_tvb = tvb_new_child_real_data(tvb, buf, sizeof(guint32), sizeof(guint32));
    /* DEBUG */ /*proto_tree_add_text(tree, tvb, offset>>3, 0, "*** DEBUG dissector_try_string: %s", gefx->key);*/
    add_new_data_source(actx->pinfo, value_tvb, "unsigned32Min");
    dissector_try_string(gef_content_dissector_table, gefx->key, value_tvb, actx->pinfo, tree);
  }


  return offset;
}



static int
dissect_h245_T_unsigned32Max(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 838 "../../asn1/h245/h245.cnf"
  guint32 value;
  guint8 *buf;
  tvbuff_t *value_tvb;
  gef_ctx_t *gefx;

  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, &value, FALSE);

  gefx = gef_ctx_get(actx->private_data);
  if (gefx) {
    buf = ep_alloc(sizeof(guint32));
    phtonl(buf, value);
    value_tvb = tvb_new_child_real_data(tvb, buf, sizeof(guint32), sizeof(guint32));
    /* DEBUG */ /*proto_tree_add_text(tree, tvb, offset>>3, 0, "*** DEBUG dissector_try_string: %s", gefx->key);*/
    add_new_data_source(actx->pinfo, value_tvb, "unsigned32Max");
    dissector_try_string(gef_content_dissector_table, gefx->key, value_tvb, actx->pinfo, tree);
  }


  return offset;
}



static int
dissect_h245_T_octetString(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 855 "../../asn1/h245/h245.cnf"
  tvbuff_t *value_tvb;
  gef_ctx_t *gefx;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &value_tvb);

  gefx = gef_ctx_get(actx->private_data);
  if (gefx) {
    /* DEBUG */ /*proto_tree_add_text(tree, tvb, offset>>3, 0, "*** DEBUG dissector_try_string: %s", gefx->key);*/
    dissector_try_string(gef_content_dissector_table, gefx->key, value_tvb, actx->pinfo, tree);
  }


  return offset;
}


static const per_sequence_t SEQUENCE_OF_GenericParameter_sequence_of[1] = {
  { &hf_h245_genericParameters_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_GenericParameter },
};

static int
dissect_h245_SEQUENCE_OF_GenericParameter(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h245_SEQUENCE_OF_GenericParameter, SEQUENCE_OF_GenericParameter_sequence_of);

  return offset;
}


static const value_string h245_ParameterValue_vals[] = {
  {   0, "logical" },
  {   1, "booleanArray" },
  {   2, "unsignedMin" },
  {   3, "unsignedMax" },
  {   4, "unsigned32Min" },
  {   5, "unsigned32Max" },
  {   6, "octetString" },
  {   7, "genericParameter" },
  { 0, NULL }
};

static const per_choice_t ParameterValue_choice[] = {
  {   0, &hf_h245_logical        , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_booleanArray   , ASN1_EXTENSION_ROOT    , dissect_h245_T_booleanArray },
  {   2, &hf_h245_unsignedMin    , ASN1_EXTENSION_ROOT    , dissect_h245_T_unsignedMin },
  {   3, &hf_h245_unsignedMax    , ASN1_EXTENSION_ROOT    , dissect_h245_T_unsignedMax },
  {   4, &hf_h245_unsigned32Min  , ASN1_EXTENSION_ROOT    , dissect_h245_T_unsigned32Min },
  {   5, &hf_h245_unsigned32Max  , ASN1_EXTENSION_ROOT    , dissect_h245_T_unsigned32Max },
  {   6, &hf_h245_octetString    , ASN1_EXTENSION_ROOT    , dissect_h245_T_octetString },
  {   7, &hf_h245_genericParameters, ASN1_EXTENSION_ROOT    , dissect_h245_SEQUENCE_OF_GenericParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_ParameterValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_ParameterValue, ParameterValue_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_ParameterIdentifier_sequence_of[1] = {
  { &hf_h245_supersedes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_ParameterIdentifier },
};

static int
dissect_h245_SEQUENCE_OF_ParameterIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h245_SEQUENCE_OF_ParameterIdentifier, SEQUENCE_OF_ParameterIdentifier_sequence_of);

  return offset;
}


static const per_sequence_t GenericParameter_sequence[] = {
  { &hf_h245_parameterIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_ParameterIdentifier },
  { &hf_h245_parameterValue , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_ParameterValue },
  { &hf_h245_supersedes     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_SEQUENCE_OF_ParameterIdentifier },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_GenericParameter(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_GenericParameter, GenericParameter_sequence);

  return offset;
}



static int
dissect_h245_T_collapsing_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 672 "../../asn1/h245/h245.cnf"
  gef_ctx_t *parent_gefx;

  parent_gefx = gef_ctx_get(actx->private_data);
  actx->private_data = gef_ctx_alloc(parent_gefx, "collapsing");

  offset = dissect_h245_GenericParameter(tvb, offset, actx, tree, hf_index);

#line 677 "../../asn1/h245/h245.cnf"
  actx->private_data = parent_gefx;

  return offset;
}


static const per_sequence_t T_collapsing_sequence_of[1] = {
  { &hf_h245_collapsing_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_T_collapsing_item },
};

static int
dissect_h245_T_collapsing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h245_T_collapsing, T_collapsing_sequence_of);

  return offset;
}



static int
dissect_h245_T_nonCollapsing_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 681 "../../asn1/h245/h245.cnf"
  gef_ctx_t *parent_gefx;

  parent_gefx = gef_ctx_get(actx->private_data);
  actx->private_data = gef_ctx_alloc(parent_gefx, "nonCollapsing");

  offset = dissect_h245_GenericParameter(tvb, offset, actx, tree, hf_index);

#line 686 "../../asn1/h245/h245.cnf"
  actx->private_data = parent_gefx;

  return offset;
}


static const per_sequence_t T_nonCollapsing_sequence_of[1] = {
  { &hf_h245_nonCollapsing_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_T_nonCollapsing_item },
};

static int
dissect_h245_T_nonCollapsing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h245_T_nonCollapsing, T_nonCollapsing_sequence_of);

  return offset;
}



static int
dissect_h245_T_nonCollapsingRaw(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 690 "../../asn1/h245/h245.cnf"
  tvbuff_t *value_tvb;
  gef_ctx_t *parent_gefx;
  gef_ctx_t *gefx;

  parent_gefx = gef_ctx_get(actx->private_data);
  actx->private_data = gef_ctx_alloc(parent_gefx, "nonCollapsingRaw");
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &value_tvb);

  gefx = gef_ctx_get(actx->private_data);
  if (gefx) {
    /* DEBUG */ /*proto_tree_add_text(tree, tvb, offset>>3, 0, "*** DEBUG dissector_try_string: %s", gefx->key);*/
    actx->pinfo->private_data = actx;
    dissector_try_string(gef_content_dissector_table, gefx->key, value_tvb, actx->pinfo, tree);
  }
  actx->private_data = parent_gefx;


  return offset;
}


static const per_sequence_t GenericCapability_sequence[] = {
  { &hf_h245_capabilityIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_CapabilityIdentifier },
  { &hf_h245_maxBitRate2_0_4294967295, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_4294967295 },
  { &hf_h245_collapsing     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_T_collapsing },
  { &hf_h245_nonCollapsing  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_T_nonCollapsing },
  { &hf_h245_nonCollapsingRaw, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_T_nonCollapsingRaw },
  { &hf_h245_transport      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_DataProtocolCapability },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_GenericCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 665 "../../asn1/h245/h245.cnf"
  void *priv_data = actx->private_data;
  actx->private_data = gef_ctx_alloc(NULL, "GenericCapability");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_GenericCapability, GenericCapability_sequence);

#line 668 "../../asn1/h245/h245.cnf"
  actx->private_data = priv_data;

  return offset;
}


static const value_string h245_Application_vals[] = {
  {   0, "nonStandard" },
  {   1, "t120" },
  {   2, "dsm-cc" },
  {   3, "userData" },
  {   4, "t84" },
  {   5, "t434" },
  {   6, "h224" },
  {   7, "nlpid" },
  {   8, "dsvdControl" },
  {   9, "h222DataPartitioning" },
  {  10, "t30fax" },
  {  11, "t140" },
  {  12, "t38fax" },
  {  13, "genericDataCapability" },
  { 0, NULL }
};

static const per_choice_t Application_choice[] = {
  {   0, &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardParameter },
  {   1, &hf_h245_t120           , ASN1_EXTENSION_ROOT    , dissect_h245_DataProtocolCapability },
  {   2, &hf_h245_dsm_cc         , ASN1_EXTENSION_ROOT    , dissect_h245_DataProtocolCapability },
  {   3, &hf_h245_userData       , ASN1_EXTENSION_ROOT    , dissect_h245_DataProtocolCapability },
  {   4, &hf_h245_t84            , ASN1_EXTENSION_ROOT    , dissect_h245_T_t84 },
  {   5, &hf_h245_t434           , ASN1_EXTENSION_ROOT    , dissect_h245_DataProtocolCapability },
  {   6, &hf_h245_h224           , ASN1_EXTENSION_ROOT    , dissect_h245_DataProtocolCapability },
  {   7, &hf_h245_nlpid          , ASN1_EXTENSION_ROOT    , dissect_h245_Nlpid },
  {   8, &hf_h245_dsvdControl    , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   9, &hf_h245_h222DataPartitioning, ASN1_EXTENSION_ROOT    , dissect_h245_DataProtocolCapability },
  {  10, &hf_h245_t30fax         , ASN1_NOT_EXTENSION_ROOT, dissect_h245_DataProtocolCapability },
  {  11, &hf_h245_t140           , ASN1_NOT_EXTENSION_ROOT, dissect_h245_DataProtocolCapability },
  {  12, &hf_h245_t38fax         , ASN1_NOT_EXTENSION_ROOT, dissect_h245_T_t38fax },
  {  13, &hf_h245_genericDataCapability, ASN1_NOT_EXTENSION_ROOT, dissect_h245_GenericCapability },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_Application(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 503 "../../asn1/h245/h245.cnf"
  gint32 value;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_Application, Application_choice,
                                 &value);

        codec_type = val_to_str(value, h245_Application_vals, "<unknown>");


  return offset;
}


static const per_sequence_t DataApplicationCapability_sequence[] = {
  { &hf_h245_application    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_Application },
  { &hf_h245_maxBitRate2_0_4294967295, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_4294967295 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_DataApplicationCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_DataApplicationCapability, DataApplicationCapability_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_DataApplicationCapability_sequence_of[1] = {
  { &hf_h245_centralizedData_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_DataApplicationCapability },
};

static int
dissect_h245_SEQUENCE_OF_DataApplicationCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h245_SEQUENCE_OF_DataApplicationCapability, SEQUENCE_OF_DataApplicationCapability_sequence_of);

  return offset;
}


static const per_sequence_t MediaDistributionCapability_sequence[] = {
  { &hf_h245_centralizedControl, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_distributedControl, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_centralizedAudio, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_distributedAudio, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_centralizedVideo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_distributedVideo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_centralizedData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_SEQUENCE_OF_DataApplicationCapability },
  { &hf_h245_distributedData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_SEQUENCE_OF_DataApplicationCapability },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MediaDistributionCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MediaDistributionCapability, MediaDistributionCapability_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_MediaDistributionCapability_sequence_of[1] = {
  { &hf_h245_mediaDistributionCapability_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_MediaDistributionCapability },
};

static int
dissect_h245_SEQUENCE_OF_MediaDistributionCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h245_SEQUENCE_OF_MediaDistributionCapability, SEQUENCE_OF_MediaDistributionCapability_sequence_of);

  return offset;
}


static const per_sequence_t MultipointCapability_sequence[] = {
  { &hf_h245_multicastCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_multiUniCastConference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_mediaDistributionCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SEQUENCE_OF_MediaDistributionCapability },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MultipointCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MultipointCapability, MultipointCapability_sequence);

  return offset;
}


static const per_sequence_t T_mcCapability_sequence[] = {
  { &hf_h245_centralizedConferenceMC, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_decentralizedConferenceMC, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_mcCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_mcCapability, T_mcCapability_sequence);

  return offset;
}



static int
dissect_h245_T_rfc_number(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32768U, &rfc_number, TRUE);

  return offset;
}


static const value_string h245_T_payloadDescriptor_vals[] = {
  {   0, "nonStandardIdentifier" },
  {   1, "rfc-number" },
  {   2, "oid" },
  { 0, NULL }
};

static const per_choice_t T_payloadDescriptor_choice[] = {
  {   0, &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardParameter },
  {   1, &hf_h245_rfc_number     , ASN1_EXTENSION_ROOT    , dissect_h245_T_rfc_number },
  {   2, &hf_h245_oid            , ASN1_EXTENSION_ROOT    , dissect_h245_OBJECT_IDENTIFIER },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_payloadDescriptor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_payloadDescriptor, T_payloadDescriptor_choice,
                                 NULL);

  return offset;
}



static int
dissect_h245_T_rtpPayloadType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 936 "../../asn1/h245/h245.cnf"
  unsigned int pt;

  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, &pt, FALSE);


  if ((rfc_number == 2198) && upcoming_channel) {
    upcoming_channel->rfc2198 = pt;
  }


  return offset;
}


static const per_sequence_t RTPPayloadType_sequence[] = {
  { &hf_h245_payloadDescriptor, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_payloadDescriptor },
  { &hf_h245_rtpPayloadType_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_T_rtpPayloadType },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RTPPayloadType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 928 "../../asn1/h245/h245.cnf"
  rfc_number = 0;

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RTPPayloadType, RTPPayloadType_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_256_OF_RTPPayloadType_sequence_of[1] = {
  { &hf_h245_rtpPayloadTypes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_RTPPayloadType },
};

static int
dissect_h245_SEQUENCE_SIZE_1_256_OF_RTPPayloadType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h245_SEQUENCE_SIZE_1_256_OF_RTPPayloadType, SEQUENCE_SIZE_1_256_OF_RTPPayloadType_sequence_of,
                                                  1, 256, FALSE);

  return offset;
}


static const per_sequence_t MediaPacketizationCapability_sequence[] = {
  { &hf_h245_h261aVideoPacketization, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_rtpPayloadTypes, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_SEQUENCE_SIZE_1_256_OF_RTPPayloadType },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MediaPacketizationCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MediaPacketizationCapability, MediaPacketizationCapability_sequence);

  return offset;
}


static const value_string h245_QOSMode_vals[] = {
  {   0, "guaranteedQOS" },
  {   1, "controlledLoad" },
  { 0, NULL }
};

static const per_choice_t QOSMode_choice[] = {
  {   0, &hf_h245_guaranteedQOS  , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_controlledLoad , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_QOSMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_QOSMode, QOSMode_choice,
                                 NULL);

  return offset;
}



static int
dissect_h245_INTEGER_1_4294967295(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 4294967295U, NULL, FALSE);

  return offset;
}


static const per_sequence_t RSVPParameters_sequence[] = {
  { &hf_h245_qosMode        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_QOSMode },
  { &hf_h245_tokenRate      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_4294967295 },
  { &hf_h245_bucketSize     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_4294967295 },
  { &hf_h245_peakRate       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_4294967295 },
  { &hf_h245_minPoliced     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_4294967295 },
  { &hf_h245_maxPktSize     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_4294967295 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RSVPParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RSVPParameters, RSVPParameters_sequence);

  return offset;
}


static const per_sequence_t ATMParameters_sequence[] = {
  { &hf_h245_maxNTUSize     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_65535 },
  { &hf_h245_atmUBR         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_atmrtVBR       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_atmnrtVBR      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_atmABR         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_atmCBR         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_ATMParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_ATMParameters, ATMParameters_sequence);

  return offset;
}


static const per_sequence_t GenericTransportParameters_sequence[] = {
  { &hf_h245_nonStandardData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_NonStandardParameter },
  { &hf_h245_averageRate    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_4294967295 },
  { &hf_h245_burst          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_4294967295 },
  { &hf_h245_peakRate       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_4294967295 },
  { &hf_h245_maxPktSize     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_4294967295 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_GenericTransportParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_GenericTransportParameters, GenericTransportParameters_sequence);

  return offset;
}


static const per_sequence_t ServicePriorityValue_sequence[] = {
  { &hf_h245_nonStandardParameter, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_NonStandardParameter },
  { &hf_h245_value          , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_ServicePriorityValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_ServicePriorityValue, ServicePriorityValue_sequence);

  return offset;
}



static int
dissect_h245_INTEGER_0_4095(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ServicePriority_sequence[] = {
  { &hf_h245_nonStandardData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_NonStandardParameter },
  { &hf_h245_servicePrioritySignalled, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_servicePriorityValue, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_ServicePriorityValue },
  { &hf_h245_serviceClass   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_INTEGER_0_4095 },
  { &hf_h245_serviceSubclass, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_ServicePriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_ServicePriority, ServicePriority_sequence);

  return offset;
}


static const per_sequence_t AuthorizationParameters_sequence[] = {
  { &hf_h245_nonStandardData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_NonStandardParameter },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_AuthorizationParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_AuthorizationParameters, AuthorizationParameters_sequence);

  return offset;
}


static const value_string h245_QOSType_vals[] = {
  {   0, "desired" },
  {   1, "required" },
  { 0, NULL }
};

static const per_choice_t QOSType_choice[] = {
  {   0, &hf_h245_desired        , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_required       , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_QOSType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_QOSType, QOSType_choice,
                                 NULL);

  return offset;
}


static const value_string h245_QOSClass_vals[] = {
  {   0, "class0" },
  {   1, "class1" },
  {   2, "class2" },
  {   3, "class3" },
  {   4, "class4" },
  {   5, "class5" },
  { 0, NULL }
};

static const per_choice_t QOSClass_choice[] = {
  {   0, &hf_h245_class0         , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_class1         , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_class2         , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   3, &hf_h245_class3         , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   4, &hf_h245_class4         , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   5, &hf_h245_class5         , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_QOSClass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_QOSClass, QOSClass_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t QOSDescriptor_sequence[] = {
  { &hf_h245_nonStandardData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_NonStandardParameter },
  { &hf_h245_qosType        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_QOSType },
  { &hf_h245_qosClass       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_QOSClass },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_QOSDescriptor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_QOSDescriptor, QOSDescriptor_sequence);

  return offset;
}



static int
dissect_h245_INTEGER_0_63(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, FALSE);

  return offset;
}


static const per_sequence_t QOSCapability_sequence[] = {
  { &hf_h245_nonStandardData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_NonStandardParameter },
  { &hf_h245_rsvpParameters , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_RSVPParameters },
  { &hf_h245_atmParameters  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_ATMParameters },
  { &hf_h245_localQoS       , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_BOOLEAN },
  { &hf_h245_genericTransportParameters, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_GenericTransportParameters },
  { &hf_h245_servicePriority, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_ServicePriority },
  { &hf_h245_authorizationParameter, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_AuthorizationParameters },
  { &hf_h245_qosDescriptor  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_QOSDescriptor },
  { &hf_h245_dscpValue      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_INTEGER_0_63 },
  { NULL, 0, 0, NULL }
};

int
dissect_h245_QOSCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_QOSCapability, QOSCapability_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_256_OF_QOSCapability_sequence_of[1] = {
  { &hf_h245_qOSCapabilities_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_QOSCapability },
};

static int
dissect_h245_SEQUENCE_SIZE_1_256_OF_QOSCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h245_SEQUENCE_SIZE_1_256_OF_QOSCapability, SEQUENCE_SIZE_1_256_OF_QOSCapability_sequence_of,
                                                  1, 256, FALSE);

  return offset;
}


static const per_sequence_t T_atm_AAL5_compressed_sequence[] = {
  { &hf_h245_variable_delta , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_atm_AAL5_compressed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_atm_AAL5_compressed, T_atm_AAL5_compressed_sequence);

  return offset;
}


static const value_string h245_MediaTransportType_vals[] = {
  {   0, "ip-UDP" },
  {   1, "ip-TCP" },
  {   2, "atm-AAL5-UNIDIR" },
  {   3, "atm-AAL5-BIDIR" },
  {   4, "atm-AAL5-compressed" },
  { 0, NULL }
};

static const per_choice_t MediaTransportType_choice[] = {
  {   0, &hf_h245_ip_UDP         , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_ip_TCP         , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_atm_AAL5_UNIDIR, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   3, &hf_h245_atm_AAL5_BIDIR , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   4, &hf_h245_atm_AAL5_compressed, ASN1_NOT_EXTENSION_ROOT, dissect_h245_T_atm_AAL5_compressed },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_MediaTransportType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_MediaTransportType, MediaTransportType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MediaChannelCapability_sequence[] = {
  { &hf_h245_mediaTransport , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_MediaTransportType },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MediaChannelCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MediaChannelCapability, MediaChannelCapability_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_256_OF_MediaChannelCapability_sequence_of[1] = {
  { &hf_h245_mediaChannelCapabilities_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_MediaChannelCapability },
};

static int
dissect_h245_SEQUENCE_SIZE_1_256_OF_MediaChannelCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h245_SEQUENCE_SIZE_1_256_OF_MediaChannelCapability, SEQUENCE_SIZE_1_256_OF_MediaChannelCapability_sequence_of,
                                                  1, 256, FALSE);

  return offset;
}


static const per_sequence_t TransportCapability_sequence[] = {
  { &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_NonStandardParameter },
  { &hf_h245_qOSCapabilities, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_SEQUENCE_SIZE_1_256_OF_QOSCapability },
  { &hf_h245_mediaChannelCapabilities, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_SEQUENCE_SIZE_1_256_OF_MediaChannelCapability },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_TransportCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_TransportCapability, TransportCapability_sequence);

  return offset;
}



static int
dissect_h245_INTEGER_1_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 16U, NULL, FALSE);

  return offset;
}



static int
dissect_h245_INTEGER_0_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_frameSequence_sequence_of[1] = {
  { &hf_h245_frameSequence_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_255 },
};

static int
dissect_h245_T_frameSequence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h245_T_frameSequence, T_frameSequence_sequence_of,
                                                  1, 256, FALSE);

  return offset;
}


static const per_sequence_t RTPH263VideoRedundancyFrameMapping_sequence[] = {
  { &hf_h245_threadNumber   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_15 },
  { &hf_h245_frameSequence  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_frameSequence },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RTPH263VideoRedundancyFrameMapping(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RTPH263VideoRedundancyFrameMapping, RTPH263VideoRedundancyFrameMapping_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_256_OF_RTPH263VideoRedundancyFrameMapping_sequence_of[1] = {
  { &hf_h245_custom_item    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_RTPH263VideoRedundancyFrameMapping },
};

static int
dissect_h245_SEQUENCE_SIZE_1_256_OF_RTPH263VideoRedundancyFrameMapping(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h245_SEQUENCE_SIZE_1_256_OF_RTPH263VideoRedundancyFrameMapping, SEQUENCE_SIZE_1_256_OF_RTPH263VideoRedundancyFrameMapping_sequence_of,
                                                  1, 256, FALSE);

  return offset;
}


static const value_string h245_T_frameToThreadMapping_vals[] = {
  {   0, "roundrobin" },
  {   1, "custom" },
  { 0, NULL }
};

static const per_choice_t T_frameToThreadMapping_choice[] = {
  {   0, &hf_h245_roundrobin     , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_custom         , ASN1_EXTENSION_ROOT    , dissect_h245_SEQUENCE_SIZE_1_256_OF_RTPH263VideoRedundancyFrameMapping },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_frameToThreadMapping(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_frameToThreadMapping, T_frameToThreadMapping_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_containedThreads_sequence_of[1] = {
  { &hf_h245_containedThreads_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_15 },
};

static int
dissect_h245_T_containedThreads(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h245_T_containedThreads, T_containedThreads_sequence_of,
                                                  1, 256, FALSE);

  return offset;
}


static const per_sequence_t RTPH263VideoRedundancyEncoding_sequence[] = {
  { &hf_h245_numberOfThreads, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_16 },
  { &hf_h245_framesBetweenSyncPoints, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_256 },
  { &hf_h245_frameToThreadMapping, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_frameToThreadMapping },
  { &hf_h245_containedThreads, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_T_containedThreads },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RTPH263VideoRedundancyEncoding(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RTPH263VideoRedundancyEncoding, RTPH263VideoRedundancyEncoding_sequence);

  return offset;
}


static const value_string h245_RedundancyEncodingMethod_vals[] = {
  {   0, "nonStandard" },
  {   1, "rtpAudioRedundancyEncoding" },
  {   2, "rtpH263VideoRedundancyEncoding" },
  { 0, NULL }
};

static const per_choice_t RedundancyEncodingMethod_choice[] = {
  {   0, &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardParameter },
  {   1, &hf_h245_rtpAudioRedundancyEncoding, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_rtpH263VideoRedundancyEncoding, ASN1_NOT_EXTENSION_ROOT, dissect_h245_RTPH263VideoRedundancyEncoding },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_RedundancyEncodingMethod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_RedundancyEncodingMethod, RedundancyEncodingMethod_choice,
                                 NULL);

  return offset;
}



static int
dissect_h245_CapabilityTableEntryNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_256_OF_CapabilityTableEntryNumber_sequence_of[1] = {
  { &hf_h245_secondaryEncodingCapability_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_CapabilityTableEntryNumber },
};

static int
dissect_h245_SEQUENCE_SIZE_1_256_OF_CapabilityTableEntryNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h245_SEQUENCE_SIZE_1_256_OF_CapabilityTableEntryNumber, SEQUENCE_SIZE_1_256_OF_CapabilityTableEntryNumber_sequence_of,
                                                  1, 256, FALSE);

  return offset;
}


static const per_sequence_t RedundancyEncodingCapability_sequence[] = {
  { &hf_h245_redundancyEncodingMethod, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_RedundancyEncodingMethod },
  { &hf_h245_primaryEncoding, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_CapabilityTableEntryNumber },
  { &hf_h245_secondaryEncodingCapability, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_SEQUENCE_SIZE_1_256_OF_CapabilityTableEntryNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RedundancyEncodingCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RedundancyEncodingCapability, RedundancyEncodingCapability_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_256_OF_RedundancyEncodingCapability_sequence_of[1] = {
  { &hf_h245_redundancyEncodingCapability_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_RedundancyEncodingCapability },
};

static int
dissect_h245_SEQUENCE_SIZE_1_256_OF_RedundancyEncodingCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h245_SEQUENCE_SIZE_1_256_OF_RedundancyEncodingCapability, SEQUENCE_SIZE_1_256_OF_RedundancyEncodingCapability_sequence_of,
                                                  1, 256, FALSE);

  return offset;
}


static const per_sequence_t H2250Capability_sequence[] = {
  { &hf_h245_maximumAudioDelayJitter, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_1023 },
  { &hf_h245_receiveMultipointCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_MultipointCapability },
  { &hf_h245_transmitMultipointCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_MultipointCapability },
  { &hf_h245_receiveAndTransmitMultipointCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_MultipointCapability },
  { &hf_h245_mcCapability   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_mcCapability },
  { &hf_h245_rtcpVideoControlCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_mediaPacketizationCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_MediaPacketizationCapability },
  { &hf_h245_transportCapability, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_TransportCapability },
  { &hf_h245_redundancyEncodingCapability, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_SEQUENCE_SIZE_1_256_OF_RedundancyEncodingCapability },
  { &hf_h245_logicalChannelSwitchingCapability, ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_t120DynamicPortCapability, ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H2250Capability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H2250Capability, H2250Capability_sequence);

  return offset;
}


static const value_string h245_MultiplexCapability_vals[] = {
  {   0, "nonStandard" },
  {   1, "h222Capability" },
  {   2, "h223Capability" },
  {   3, "v76Capability" },
  {   4, "h2250Capability" },
  {   5, "genericMultiplexCapability" },
  { 0, NULL }
};

static const per_choice_t MultiplexCapability_choice[] = {
  {   0, &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardParameter },
  {   1, &hf_h245_h222Capability , ASN1_EXTENSION_ROOT    , dissect_h245_H222Capability },
  {   2, &hf_h245_h223Capability , ASN1_EXTENSION_ROOT    , dissect_h245_H223Capability },
  {   3, &hf_h245_v76Capability  , ASN1_EXTENSION_ROOT    , dissect_h245_V76Capability },
  {   4, &hf_h245_h2250Capability, ASN1_NOT_EXTENSION_ROOT, dissect_h245_H2250Capability },
  {   5, &hf_h245_genericMultiplexCapability, ASN1_NOT_EXTENSION_ROOT, dissect_h245_GenericCapability },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_MultiplexCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_MultiplexCapability, MultiplexCapability_choice,
                                 NULL);

  return offset;
}



static int
dissect_h245_INTEGER_1_4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 4U, NULL, FALSE);

  return offset;
}


static const per_sequence_t H261VideoCapability_sequence[] = {
  { &hf_h245_qcifMPI_1_4    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_4 },
  { &hf_h245_cifMPI_1_4     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_4 },
  { &hf_h245_temporalSpatialTradeOffCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_maxBitRate_1_19200, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_19200 },
  { &hf_h245_stillImageTransmission, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_videoBadMBsCap , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H261VideoCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H261VideoCapability, H261VideoCapability_sequence);

  return offset;
}



static int
dissect_h245_INTEGER_0_1073741823(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1073741823U, NULL, FALSE);

  return offset;
}



static int
dissect_h245_INTEGER_0_262143(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 262143U, NULL, FALSE);

  return offset;
}



static int
dissect_h245_INTEGER_0_16383(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16383U, NULL, FALSE);

  return offset;
}


static const per_sequence_t H262VideoCapability_sequence[] = {
  { &hf_h245_profileAndLevel_SPatML, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_profileAndLevel_MPatLL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_profileAndLevel_MPatML, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_profileAndLevel_MPatH_14, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_profileAndLevel_MPatHL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_profileAndLevel_SNRatLL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_profileAndLevel_SNRatML, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_profileAndLevel_SpatialatH_14, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_profileAndLevel_HPatML, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_profileAndLevel_HPatH_14, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_profileAndLevel_HPatHL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_videoBitRate   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_1073741823 },
  { &hf_h245_vbvBufferSize  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_262143 },
  { &hf_h245_samplesPerLine , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_16383 },
  { &hf_h245_linesPerFrame  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_16383 },
  { &hf_h245_framesPerSecond, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_15 },
  { &hf_h245_luminanceSampleRate, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_4294967295 },
  { &hf_h245_videoBadMBsCap , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H262VideoCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H262VideoCapability, H262VideoCapability_sequence);

  return offset;
}



static int
dissect_h245_INTEGER_1_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32U, NULL, FALSE);

  return offset;
}



static int
dissect_h245_INTEGER_1_192400(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 192400U, NULL, FALSE);

  return offset;
}



static int
dissect_h245_INTEGER_0_524287(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 524287U, NULL, FALSE);

  return offset;
}



static int
dissect_h245_INTEGER_1_3600(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 3600U, NULL, FALSE);

  return offset;
}



static int
dissect_h245_INTEGER_M262144_262143(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -262144, 262143U, NULL, FALSE);

  return offset;
}


static const per_sequence_t TransparencyParameters_sequence[] = {
  { &hf_h245_presentationOrder, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_256 },
  { &hf_h245_offset_x       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_M262144_262143 },
  { &hf_h245_offset_y       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_M262144_262143 },
  { &hf_h245_scale_x        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_255 },
  { &hf_h245_scale_y        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_TransparencyParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_TransparencyParameters, TransparencyParameters_sequence);

  return offset;
}


static const per_sequence_t T_additionalPictureMemory_sequence[] = {
  { &hf_h245_sqcifAdditionalPictureMemory, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_256 },
  { &hf_h245_qcifAdditionalPictureMemory, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_256 },
  { &hf_h245_cifAdditionalPictureMemory, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_256 },
  { &hf_h245_cif4AdditionalPictureMemory, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_256 },
  { &hf_h245_cif16AdditionalPictureMemory, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_256 },
  { &hf_h245_bigCpfAdditionalPictureMemory, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_256 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_additionalPictureMemory(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_additionalPictureMemory, T_additionalPictureMemory_sequence);

  return offset;
}


static const value_string h245_T_videoBackChannelSend_vals[] = {
  {   0, "none" },
  {   1, "ackMessageOnly" },
  {   2, "nackMessageOnly" },
  {   3, "ackOrNackMessageOnly" },
  {   4, "ackAndNackMessage" },
  { 0, NULL }
};

static const per_choice_t T_videoBackChannelSend_choice[] = {
  {   0, &hf_h245_none           , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_ackMessageOnly , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_nackMessageOnly, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   3, &hf_h245_ackOrNackMessageOnly, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   4, &hf_h245_ackAndNackMessage, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_videoBackChannelSend(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_videoBackChannelSend, T_videoBackChannelSend_choice,
                                 NULL);

  return offset;
}



static int
dissect_h245_INTEGER_1_128(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 128U, NULL, FALSE);

  return offset;
}



static int
dissect_h245_INTEGER_1_72(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 72U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_subPictureRemovalParameters_sequence[] = {
  { &hf_h245_mpuHorizMBs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_128 },
  { &hf_h245_mpuVertMBs     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_72 },
  { &hf_h245_mpuTotalNumber , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_65536 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_subPictureRemovalParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_subPictureRemovalParameters, T_subPictureRemovalParameters_sequence);

  return offset;
}


static const per_sequence_t T_enhancedReferencePicSelect_sequence[] = {
  { &hf_h245_subPictureRemovalParameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_T_subPictureRemovalParameters },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_enhancedReferencePicSelect(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_enhancedReferencePicSelect, T_enhancedReferencePicSelect_sequence);

  return offset;
}


static const per_sequence_t RefPictureSelection_sequence[] = {
  { &hf_h245_additionalPictureMemory, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_T_additionalPictureMemory },
  { &hf_h245_videoMux       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_videoBackChannelSend, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_videoBackChannelSend },
  { &hf_h245_enhancedReferencePicSelect, ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_h245_T_enhancedReferencePicSelect },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RefPictureSelection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RefPictureSelection, RefPictureSelection_sequence);

  return offset;
}



static int
dissect_h245_INTEGER_1000_1001(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1000U, 1001U, NULL, FALSE);

  return offset;
}



static int
dissect_h245_INTEGER_1_2048(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 2048U, NULL, FALSE);

  return offset;
}


static const per_sequence_t CustomPictureClockFrequency_sequence[] = {
  { &hf_h245_clockConversionCode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1000_1001 },
  { &hf_h245_clockDivisor   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_127 },
  { &hf_h245_sqcifMPI       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_2048 },
  { &hf_h245_qcifMPI_1_2048 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_2048 },
  { &hf_h245_cifMPI2_1_2048 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_2048 },
  { &hf_h245_cif4MPI        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_2048 },
  { &hf_h245_cif16MPI       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_2048 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_CustomPictureClockFrequency(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_CustomPictureClockFrequency, CustomPictureClockFrequency_sequence);

  return offset;
}


static const per_sequence_t SET_SIZE_1_16_OF_CustomPictureClockFrequency_set_of[1] = {
  { &hf_h245_customPictureClockFrequency_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_CustomPictureClockFrequency },
};

static int
dissect_h245_SET_SIZE_1_16_OF_CustomPictureClockFrequency(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h245_SET_SIZE_1_16_OF_CustomPictureClockFrequency, SET_SIZE_1_16_OF_CustomPictureClockFrequency_set_of,
                                             1, 16, FALSE);

  return offset;
}



static int
dissect_h245_INTEGER_1_31(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 31U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_customPCF_item_sequence[] = {
  { &hf_h245_clockConversionCode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1000_1001 },
  { &hf_h245_clockDivisor   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_127 },
  { &hf_h245_customMPI      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_2048 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_customPCF_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_customPCF_item, T_customPCF_item_sequence);

  return offset;
}


static const per_sequence_t T_customPCF_set_of[1] = {
  { &hf_h245_customPCF_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_T_customPCF_item },
};

static int
dissect_h245_T_customPCF(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h245_T_customPCF, T_customPCF_set_of,
                                             1, 16, FALSE);

  return offset;
}


static const per_sequence_t T_mPI_sequence[] = {
  { &hf_h245_standardMPI    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_31 },
  { &hf_h245_customPCF      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_T_customPCF },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_mPI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_mPI, T_mPI_sequence);

  return offset;
}



static int
dissect_h245_INTEGER_1_14(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 14U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_pixelAspectCode_set_of[1] = {
  { &hf_h245_pixelAspectCode_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_14 },
};

static int
dissect_h245_T_pixelAspectCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h245_T_pixelAspectCode, T_pixelAspectCode_set_of,
                                             1, 14, FALSE);

  return offset;
}


static const per_sequence_t T_extendedPAR_item_sequence[] = {
  { &hf_h245_width          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_255 },
  { &hf_h245_height         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_extendedPAR_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_extendedPAR_item, T_extendedPAR_item_sequence);

  return offset;
}


static const per_sequence_t T_extendedPAR_set_of[1] = {
  { &hf_h245_extendedPAR_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_T_extendedPAR_item },
};

static int
dissect_h245_T_extendedPAR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h245_T_extendedPAR, T_extendedPAR_set_of,
                                             1, 256, FALSE);

  return offset;
}


static const value_string h245_T_pixelAspectInformation_vals[] = {
  {   0, "anyPixelAspectRatio" },
  {   1, "pixelAspectCode" },
  {   2, "extendedPAR" },
  { 0, NULL }
};

static const per_choice_t T_pixelAspectInformation_choice[] = {
  {   0, &hf_h245_anyPixelAspectRatio, ASN1_EXTENSION_ROOT    , dissect_h245_BOOLEAN },
  {   1, &hf_h245_pixelAspectCode, ASN1_EXTENSION_ROOT    , dissect_h245_T_pixelAspectCode },
  {   2, &hf_h245_extendedPAR    , ASN1_EXTENSION_ROOT    , dissect_h245_T_extendedPAR },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_pixelAspectInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_pixelAspectInformation, T_pixelAspectInformation_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CustomPictureFormat_sequence[] = {
  { &hf_h245_maxCustomPictureWidth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_2048 },
  { &hf_h245_maxCustomPictureHeight, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_2048 },
  { &hf_h245_minCustomPictureWidth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_2048 },
  { &hf_h245_minCustomPictureHeight, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_2048 },
  { &hf_h245_mPI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_mPI },
  { &hf_h245_pixelAspectInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_pixelAspectInformation },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_CustomPictureFormat(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_CustomPictureFormat, CustomPictureFormat_sequence);

  return offset;
}


static const per_sequence_t SET_SIZE_1_16_OF_CustomPictureFormat_set_of[1] = {
  { &hf_h245_customPictureFormat_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_CustomPictureFormat },
};

static int
dissect_h245_SET_SIZE_1_16_OF_CustomPictureFormat(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h245_SET_SIZE_1_16_OF_CustomPictureFormat, SET_SIZE_1_16_OF_CustomPictureFormat_set_of,
                                             1, 16, FALSE);

  return offset;
}


static const per_sequence_t H263Version3Options_sequence[] = {
  { &hf_h245_dataPartitionedSlices, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_fixedPointIDCT0, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_interlacedFields, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_currentPictureHeaderRepetition, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_previousPictureHeaderRepetition, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_nextPictureHeaderRepetition, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_pictureNumberBoolean, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_spareReferencePictures, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H263Version3Options(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H263Version3Options, H263Version3Options_sequence);

  return offset;
}


static const per_sequence_t H263ModeComboFlags_sequence[] = {
  { &hf_h245_unrestrictedVector, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_arithmeticCoding, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_advancedPrediction, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_pbFrames       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_advancedIntraCodingMode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_deblockingFilterMode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_unlimitedMotionVectors, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_slicesInOrder_NonRect, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_slicesInOrder_Rect, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_slicesNoOrder_NonRect, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_slicesNoOrder_Rect, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_improvedPBFramesMode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_referencePicSelect, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_dynamicPictureResizingByFour, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_dynamicPictureResizingSixteenthPel, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_dynamicWarpingHalfPel, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_dynamicWarpingSixteenthPel, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_reducedResolutionUpdate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_independentSegmentDecoding, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_alternateInterVLCMode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_modifiedQuantizationMode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_enhancedReferencePicSelectBool, ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_h263Version3Options, ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_h245_H263Version3Options },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H263ModeComboFlags(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H263ModeComboFlags, H263ModeComboFlags_sequence);

  return offset;
}


static const per_sequence_t SET_SIZE_1_16_OF_H263ModeComboFlags_set_of[1] = {
  { &hf_h245_h263VideoCoupledModes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_H263ModeComboFlags },
};

static int
dissect_h245_SET_SIZE_1_16_OF_H263ModeComboFlags(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h245_SET_SIZE_1_16_OF_H263ModeComboFlags, SET_SIZE_1_16_OF_H263ModeComboFlags_set_of,
                                             1, 16, FALSE);

  return offset;
}


static const per_sequence_t H263VideoModeCombos_sequence[] = {
  { &hf_h245_h263VideoUncoupledModes, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_H263ModeComboFlags },
  { &hf_h245_h263VideoCoupledModes, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SET_SIZE_1_16_OF_H263ModeComboFlags },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H263VideoModeCombos(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H263VideoModeCombos, H263VideoModeCombos_sequence);

  return offset;
}


static const per_sequence_t SET_SIZE_1_16_OF_H263VideoModeCombos_set_of[1] = {
  { &hf_h245_modeCombos_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_H263VideoModeCombos },
};

static int
dissect_h245_SET_SIZE_1_16_OF_H263VideoModeCombos(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h245_SET_SIZE_1_16_OF_H263VideoModeCombos, SET_SIZE_1_16_OF_H263VideoModeCombos_set_of,
                                             1, 16, FALSE);

  return offset;
}


static const per_sequence_t H263Options_sequence[] = {
  { &hf_h245_advancedIntraCodingMode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_deblockingFilterMode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_improvedPBFramesMode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_unlimitedMotionVectors, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_fullPictureFreeze, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_partialPictureFreezeAndRelease, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_resizingPartPicFreezeAndRelease, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_fullPictureSnapshot, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_partialPictureSnapshot, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_videoSegmentTagging, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_progressiveRefinement, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_dynamicPictureResizingByFour, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_dynamicPictureResizingSixteenthPel, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_dynamicWarpingHalfPel, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_dynamicWarpingSixteenthPel, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_independentSegmentDecoding, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_slicesInOrder_NonRect, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_slicesInOrder_Rect, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_slicesNoOrder_NonRect, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_slicesNoOrder_Rect, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_alternateInterVLCMode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_modifiedQuantizationMode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_reducedResolutionUpdate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_transparencyParameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_TransparencyParameters },
  { &hf_h245_separateVideoBackChannel, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_refPictureSelection, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_RefPictureSelection },
  { &hf_h245_customPictureClockFrequency, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_SET_SIZE_1_16_OF_CustomPictureClockFrequency },
  { &hf_h245_customPictureFormat, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_SET_SIZE_1_16_OF_CustomPictureFormat },
  { &hf_h245_modeCombos     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_SET_SIZE_1_16_OF_H263VideoModeCombos },
  { &hf_h245_videoBadMBsCap , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_h263Version3Options, ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_h245_H263Version3Options },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H263Options(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H263Options, H263Options_sequence);

  return offset;
}


static const per_sequence_t EnhancementOptions_sequence[] = {
  { &hf_h245_sqcifMPI_1_32  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_32 },
  { &hf_h245_qcifMPI        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_32 },
  { &hf_h245_cifMPI         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_32 },
  { &hf_h245_cif4MPI_1_32   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_32 },
  { &hf_h245_cif16MPI_1_32  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_32 },
  { &hf_h245_maxBitRate     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_192400 },
  { &hf_h245_unrestrictedVector, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_arithmeticCoding, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_temporalSpatialTradeOffCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_slowSqcifMPI   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_3600 },
  { &hf_h245_slowQcifMPI    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_3600 },
  { &hf_h245_slowCifMPI     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_3600 },
  { &hf_h245_slowCif4MPI    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_3600 },
  { &hf_h245_slowCif16MPI   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_3600 },
  { &hf_h245_errorCompensation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_h263Options    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_H263Options },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_EnhancementOptions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_EnhancementOptions, EnhancementOptions_sequence);

  return offset;
}


static const per_sequence_t SET_SIZE_1_14_OF_EnhancementOptions_set_of[1] = {
  { &hf_h245_snrEnhancement_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_EnhancementOptions },
};

static int
dissect_h245_SET_SIZE_1_14_OF_EnhancementOptions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h245_SET_SIZE_1_14_OF_EnhancementOptions, SET_SIZE_1_14_OF_EnhancementOptions_set_of,
                                             1, 14, FALSE);

  return offset;
}



static int
dissect_h245_INTEGER_1_64(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 64U, NULL, FALSE);

  return offset;
}


static const per_sequence_t BEnhancementParameters_sequence[] = {
  { &hf_h245_enhancementOptions, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_EnhancementOptions },
  { &hf_h245_numberOfBPictures, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_64 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_BEnhancementParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_BEnhancementParameters, BEnhancementParameters_sequence);

  return offset;
}


static const per_sequence_t SET_SIZE_1_14_OF_BEnhancementParameters_set_of[1] = {
  { &hf_h245_bPictureEnhancement_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_BEnhancementParameters },
};

static int
dissect_h245_SET_SIZE_1_14_OF_BEnhancementParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h245_SET_SIZE_1_14_OF_BEnhancementParameters, SET_SIZE_1_14_OF_BEnhancementParameters_set_of,
                                             1, 14, FALSE);

  return offset;
}


static const per_sequence_t EnhancementLayerInfo_sequence[] = {
  { &hf_h245_baseBitRateConstrained, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_snrEnhancement , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_SET_SIZE_1_14_OF_EnhancementOptions },
  { &hf_h245_spatialEnhancement, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_SET_SIZE_1_14_OF_EnhancementOptions },
  { &hf_h245_bPictureEnhancement, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_SET_SIZE_1_14_OF_BEnhancementParameters },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_EnhancementLayerInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_EnhancementLayerInfo, EnhancementLayerInfo_sequence);

  return offset;
}


static const per_sequence_t H263VideoCapability_sequence[] = {
  { &hf_h245_sqcifMPI_1_32  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_32 },
  { &hf_h245_qcifMPI        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_32 },
  { &hf_h245_cifMPI         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_32 },
  { &hf_h245_cif4MPI_1_32   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_32 },
  { &hf_h245_cif16MPI_1_32  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_32 },
  { &hf_h245_maxBitRate     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_192400 },
  { &hf_h245_unrestrictedVector, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_arithmeticCoding, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_advancedPrediction, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_pbFrames       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_temporalSpatialTradeOffCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_hrd_B          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_524287 },
  { &hf_h245_bppMaxKb       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_65535 },
  { &hf_h245_slowSqcifMPI   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_INTEGER_1_3600 },
  { &hf_h245_slowQcifMPI    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_INTEGER_1_3600 },
  { &hf_h245_slowCifMPI     , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_INTEGER_1_3600 },
  { &hf_h245_slowCif4MPI    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_INTEGER_1_3600 },
  { &hf_h245_slowCif16MPI   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_INTEGER_1_3600 },
  { &hf_h245_errorCompensation, ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_enhancementLayerInfo, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_EnhancementLayerInfo },
  { &hf_h245_h263Options    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_H263Options },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H263VideoCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H263VideoCapability, H263VideoCapability_sequence);

#line 364 "../../asn1/h245/h245.cnf"
  h245_lc_dissector = h263_handle;

  return offset;
}


static const per_sequence_t IS11172VideoCapability_sequence[] = {
  { &hf_h245_constrainedBitstream, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_videoBitRate   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_1073741823 },
  { &hf_h245_vbvBufferSize  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_262143 },
  { &hf_h245_samplesPerLine , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_16383 },
  { &hf_h245_linesPerFrame  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_16383 },
  { &hf_h245_pictureRate    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_15 },
  { &hf_h245_luminanceSampleRate, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_4294967295 },
  { &hf_h245_videoBadMBsCap , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_IS11172VideoCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_IS11172VideoCapability, IS11172VideoCapability_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_VideoCapability_sequence_of[1] = {
  { &hf_h245_videoCapability_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_VideoCapability },
};

static int
dissect_h245_SEQUENCE_OF_VideoCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h245_SEQUENCE_OF_VideoCapability, SEQUENCE_OF_VideoCapability_sequence_of);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_GenericCapability_sequence_of[1] = {
  { &hf_h245_videoCapabilityExtension_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_GenericCapability },
};

static int
dissect_h245_SEQUENCE_OF_GenericCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h245_SEQUENCE_OF_GenericCapability, SEQUENCE_OF_GenericCapability_sequence_of);

  return offset;
}


static const per_sequence_t ExtendedVideoCapability_sequence[] = {
  { &hf_h245_videoCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SEQUENCE_OF_VideoCapability },
  { &hf_h245_videoCapabilityExtension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_SEQUENCE_OF_GenericCapability },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_ExtendedVideoCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_ExtendedVideoCapability, ExtendedVideoCapability_sequence);

  return offset;
}


static const value_string h245_VideoCapability_vals[] = {
  {   0, "nonStandard" },
  {   1, "h261VideoCapability" },
  {   2, "h262VideoCapability" },
  {   3, "h263VideoCapability" },
  {   4, "is11172VideoCapability" },
  {   5, "genericVideoCapability" },
  {   6, "extendedVideoCapability" },
  { 0, NULL }
};

static const per_choice_t VideoCapability_choice[] = {
  {   0, &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardParameter },
  {   1, &hf_h245_h261VideoCapability, ASN1_EXTENSION_ROOT    , dissect_h245_H261VideoCapability },
  {   2, &hf_h245_h262VideoCapability, ASN1_EXTENSION_ROOT    , dissect_h245_H262VideoCapability },
  {   3, &hf_h245_h263VideoCapability, ASN1_EXTENSION_ROOT    , dissect_h245_H263VideoCapability },
  {   4, &hf_h245_is11172VideoCapability, ASN1_EXTENSION_ROOT    , dissect_h245_IS11172VideoCapability },
  {   5, &hf_h245_genericVideoCapability, ASN1_NOT_EXTENSION_ROOT, dissect_h245_GenericCapability },
  {   6, &hf_h245_extendedVideoCapability, ASN1_NOT_EXTENSION_ROOT, dissect_h245_ExtendedVideoCapability },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_VideoCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 495 "../../asn1/h245/h245.cnf"
  gint32 value;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_VideoCapability, VideoCapability_choice,
                                 &value);

        codec_type = val_to_str(value, h245_VideoCapability_vals, "<unknown>");



  return offset;
}


static const per_sequence_t T_g7231_sequence[] = {
  { &hf_h245_maxAl_sduAudioFrames, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_256 },
  { &hf_h245_silenceSuppression, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_g7231(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_g7231, T_g7231_sequence);

  return offset;
}



static int
dissect_h245_INTEGER_1_448(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 448U, NULL, FALSE);

  return offset;
}


static const per_sequence_t IS11172AudioCapability_sequence[] = {
  { &hf_h245_audioLayer1    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_audioLayer2    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_audioLayer3    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_audioSampling32k, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_audioSampling44k1, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_audioSampling48k, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_singleChannel  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_twoChannels    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_bitRate_1_448  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_448 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_IS11172AudioCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_IS11172AudioCapability, IS11172AudioCapability_sequence);

  return offset;
}



static int
dissect_h245_INTEGER_1_1130(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1130U, NULL, FALSE);

  return offset;
}


static const per_sequence_t IS13818AudioCapability_sequence[] = {
  { &hf_h245_audioLayer1    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_audioLayer2    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_audioLayer3    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_audioSampling16k, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_audioSampling22k05, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_audioSampling24k, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_audioSampling32k, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_audioSampling44k1, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_audioSampling48k, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_singleChannel  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_twoChannels    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_threeChannels2_1, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_threeChannels3_0, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_fourChannels2_0_2_0, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_fourChannels2_2, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_fourChannels3_1, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_fiveChannels3_0_2_0, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_fiveChannels3_2, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_lowFrequencyEnhancement, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_multilingual   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_bitRate2_1_1130, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_1130 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_IS13818AudioCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_IS13818AudioCapability, IS13818AudioCapability_sequence);

  return offset;
}



static int
dissect_h245_INTEGER_27_78(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            27U, 78U, NULL, FALSE);

  return offset;
}



static int
dissect_h245_INTEGER_23_66(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            23U, 66U, NULL, FALSE);

  return offset;
}



static int
dissect_h245_INTEGER_6_17(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            6U, 17U, NULL, FALSE);

  return offset;
}


static const per_sequence_t G723AnnexCAudioMode_sequence[] = {
  { &hf_h245_highRateMode0  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_27_78 },
  { &hf_h245_highRateMode1  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_27_78 },
  { &hf_h245_lowRateMode0   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_23_66 },
  { &hf_h245_lowRateMode1   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_23_66 },
  { &hf_h245_sidMode0       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_6_17 },
  { &hf_h245_sidMode1       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_6_17 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_G723AnnexCAudioMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_G723AnnexCAudioMode, G723AnnexCAudioMode_sequence);

  return offset;
}


static const per_sequence_t G7231AnnexCCapability_sequence[] = {
  { &hf_h245_maxAl_sduAudioFrames, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_256 },
  { &hf_h245_silenceSuppression, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_g723AnnexCAudioMode, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_G723AnnexCAudioMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_G7231AnnexCCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_G7231AnnexCCapability, G7231AnnexCCapability_sequence);

  return offset;
}


static const per_sequence_t GSMAudioCapability_sequence[] = {
  { &hf_h245_audioUnitSize  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_256 },
  { &hf_h245_comfortNoise   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_scrambled      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_GSMAudioCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_GSMAudioCapability, GSMAudioCapability_sequence);

  return offset;
}


static const per_sequence_t G729Extensions_sequence[] = {
  { &hf_h245_audioUnit      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_256 },
  { &hf_h245_annexA         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_annexB         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_annexD         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_annexE         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_annexF         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_annexG         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_annexH         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_G729Extensions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_G729Extensions, G729Extensions_sequence);

  return offset;
}


static const per_sequence_t VBDCapability_sequence[] = {
  { &hf_h245_vbd_cap_type   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_AudioCapability },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_VBDCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_VBDCapability, VBDCapability_sequence);

  return offset;
}



static int
dissect_h245_GeneralString(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_GeneralString(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t NoPTAudioTelephonyEventCapability_sequence[] = {
  { &hf_h245_audioTelephoneEvent, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_GeneralString },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_NoPTAudioTelephonyEventCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_NoPTAudioTelephonyEventCapability, NoPTAudioTelephonyEventCapability_sequence);

  return offset;
}


static const per_sequence_t NoPTAudioToneCapability_sequence[] = {
  { NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};

static int
dissect_h245_NoPTAudioToneCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_NoPTAudioToneCapability, NoPTAudioToneCapability_sequence);

  return offset;
}


static const value_string h245_AudioCapability_vals[] = {
  { AudioCapability_nonStandard, "nonStandard" },
  { AudioCapability_g711Alaw64k, "g711Alaw64k" },
  { AudioCapability_g711Alaw56k, "g711Alaw56k" },
  { AudioCapability_g711Ulaw64k, "g711Ulaw64k" },
  { AudioCapability_g711Ulaw56k, "g711Ulaw56k" },
  { AudioCapability_g722_64k, "g722-64k" },
  { AudioCapability_g722_56k, "g722-56k" },
  { AudioCapability_g722_48k, "g722-48k" },
  { AudioCapability_g7231, "g7231" },
  { AudioCapability_g728, "g728" },
  { AudioCapability_g729, "g729" },
  { AudioCapability_g729AnnexA, "g729AnnexA" },
  { AudioCapability_is11172AudioCapability, "is11172AudioCapability" },
  { AudioCapability_is13818AudioCapability, "is13818AudioCapability" },
  { AudioCapability_g729wAnnexB, "g729wAnnexB" },
  { AudioCapability_g729AnnexAwAnnexB, "g729AnnexAwAnnexB" },
  { AudioCapability_g7231AnnexCCapability, "g7231AnnexCCapability" },
  { AudioCapability_gsmFullRate, "gsmFullRate" },
  { AudioCapability_gsmHalfRate, "gsmHalfRate" },
  { AudioCapability_gsmEnhancedFullRate, "gsmEnhancedFullRate" },
  { AudioCapability_genericAudioCapability, "genericAudioCapability" },
  { AudioCapability_g729Extensions, "g729Extensions" },
  { AudioCapability_vbd, "vbd" },
  { AudioCapability_audioTelephonyEvent, "audioTelephonyEvent" },
  { AudioCapability_audioTone, "audioTone" },
  { 0, NULL }
};

static const per_choice_t AudioCapability_choice[] = {
  { AudioCapability_nonStandard, &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardParameter },
  { AudioCapability_g711Alaw64k, &hf_h245_g711Alaw64k    , ASN1_EXTENSION_ROOT    , dissect_h245_INTEGER_1_256 },
  { AudioCapability_g711Alaw56k, &hf_h245_g711Alaw56k    , ASN1_EXTENSION_ROOT    , dissect_h245_INTEGER_1_256 },
  { AudioCapability_g711Ulaw64k, &hf_h245_g711Ulaw64k    , ASN1_EXTENSION_ROOT    , dissect_h245_INTEGER_1_256 },
  { AudioCapability_g711Ulaw56k, &hf_h245_g711Ulaw56k    , ASN1_EXTENSION_ROOT    , dissect_h245_INTEGER_1_256 },
  { AudioCapability_g722_64k, &hf_h245_g722_64k       , ASN1_EXTENSION_ROOT    , dissect_h245_INTEGER_1_256 },
  { AudioCapability_g722_56k, &hf_h245_g722_56k       , ASN1_EXTENSION_ROOT    , dissect_h245_INTEGER_1_256 },
  { AudioCapability_g722_48k, &hf_h245_g722_48k       , ASN1_EXTENSION_ROOT    , dissect_h245_INTEGER_1_256 },
  { AudioCapability_g7231, &hf_h245_g7231          , ASN1_EXTENSION_ROOT    , dissect_h245_T_g7231 },
  { AudioCapability_g728, &hf_h245_g728           , ASN1_EXTENSION_ROOT    , dissect_h245_INTEGER_1_256 },
  { AudioCapability_g729, &hf_h245_g729           , ASN1_EXTENSION_ROOT    , dissect_h245_INTEGER_1_256 },
  { AudioCapability_g729AnnexA, &hf_h245_g729AnnexA     , ASN1_EXTENSION_ROOT    , dissect_h245_INTEGER_1_256 },
  { AudioCapability_is11172AudioCapability, &hf_h245_is11172AudioCapability, ASN1_EXTENSION_ROOT    , dissect_h245_IS11172AudioCapability },
  { AudioCapability_is13818AudioCapability, &hf_h245_is13818AudioCapability, ASN1_EXTENSION_ROOT    , dissect_h245_IS13818AudioCapability },
  { AudioCapability_g729wAnnexB, &hf_h245_g729wAnnexB    , ASN1_NOT_EXTENSION_ROOT, dissect_h245_INTEGER_1_256 },
  { AudioCapability_g729AnnexAwAnnexB, &hf_h245_g729AnnexAwAnnexB, ASN1_NOT_EXTENSION_ROOT, dissect_h245_INTEGER_1_256 },
  { AudioCapability_g7231AnnexCCapability, &hf_h245_g7231AnnexCCapability, ASN1_NOT_EXTENSION_ROOT, dissect_h245_G7231AnnexCCapability },
  { AudioCapability_gsmFullRate, &hf_h245_gsmFullRate    , ASN1_NOT_EXTENSION_ROOT, dissect_h245_GSMAudioCapability },
  { AudioCapability_gsmHalfRate, &hf_h245_gsmHalfRate    , ASN1_NOT_EXTENSION_ROOT, dissect_h245_GSMAudioCapability },
  { AudioCapability_gsmEnhancedFullRate, &hf_h245_gsmEnhancedFullRate, ASN1_NOT_EXTENSION_ROOT, dissect_h245_GSMAudioCapability },
  { AudioCapability_genericAudioCapability, &hf_h245_genericAudioCapability, ASN1_NOT_EXTENSION_ROOT, dissect_h245_GenericCapability },
  { AudioCapability_g729Extensions, &hf_h245_g729Extensions , ASN1_NOT_EXTENSION_ROOT, dissect_h245_G729Extensions },
  { AudioCapability_vbd, &hf_h245_vbd            , ASN1_NOT_EXTENSION_ROOT, dissect_h245_VBDCapability },
  { AudioCapability_audioTelephonyEvent, &hf_h245_audioTelephonyEvent, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NoPTAudioTelephonyEventCapability },
  { AudioCapability_audioTone, &hf_h245_audioTone      , ASN1_NOT_EXTENSION_ROOT, dissect_h245_NoPTAudioToneCapability },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_AudioCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 488 "../../asn1/h245/h245.cnf"
  gint32 value;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_AudioCapability, AudioCapability_choice,
                                 &value);

        codec_type = val_to_str(value, h245_AudioCapability_short_vals, "<unknown>");


  return offset;
}


static const per_sequence_t T_h233EncryptionReceiveCapability_sequence[] = {
  { &hf_h245_h233IVResponseTime, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_h233EncryptionReceiveCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_h233EncryptionReceiveCapability, T_h233EncryptionReceiveCapability_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_NonStandardParameter_sequence_of[1] = {
  { &hf_h245_nonStandardParams_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_NonStandardParameter },
};

static int
dissect_h245_SEQUENCE_OF_NonStandardParameter(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h245_SEQUENCE_OF_NonStandardParameter, SEQUENCE_OF_NonStandardParameter_sequence_of);

  return offset;
}


static const per_sequence_t ConferenceCapability_sequence[] = {
  { &hf_h245_nonStandardParams, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_SEQUENCE_OF_NonStandardParameter },
  { &hf_h245_chairControlCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_videoIndicateMixingCapability, ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_multipointVisualizationCapability, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_ConferenceCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_ConferenceCapability, ConferenceCapability_sequence);

  return offset;
}


static const value_string h245_MediaEncryptionAlgorithm_vals[] = {
  {   0, "nonStandard" },
  {   1, "algorithm" },
  { 0, NULL }
};

static const per_choice_t MediaEncryptionAlgorithm_choice[] = {
  {   0, &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardParameter },
  {   1, &hf_h245_algorithm      , ASN1_EXTENSION_ROOT    , dissect_h245_OBJECT_IDENTIFIER },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_MediaEncryptionAlgorithm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_MediaEncryptionAlgorithm, MediaEncryptionAlgorithm_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t EncryptionCapability_sequence_of[1] = {
  { &hf_h245_EncryptionCapability_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_MediaEncryptionAlgorithm },
};

static int
dissect_h245_EncryptionCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h245_EncryptionCapability, EncryptionCapability_sequence_of,
                                                  1, 256, FALSE);

  return offset;
}


static const per_sequence_t AuthenticationCapability_sequence[] = {
  { &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_NonStandardParameter },
  { &hf_h245_antiSpamAlgorithm, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_OBJECT_IDENTIFIER },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_AuthenticationCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_AuthenticationCapability, AuthenticationCapability_sequence);

  return offset;
}


static const per_sequence_t IntegrityCapability_sequence[] = {
  { &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_NonStandardParameter },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_IntegrityCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_IntegrityCapability, IntegrityCapability_sequence);

  return offset;
}


static const per_sequence_t EncryptionAuthenticationAndIntegrity_sequence[] = {
  { &hf_h245_encryptionCapability, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_EncryptionCapability },
  { &hf_h245_authenticationCapability, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_AuthenticationCapability },
  { &hf_h245_integrityCapability, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_IntegrityCapability },
  { &hf_h245_genericH235SecurityCapability, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_GenericCapability },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_EncryptionAuthenticationAndIntegrity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_EncryptionAuthenticationAndIntegrity, EncryptionAuthenticationAndIntegrity_sequence);

  return offset;
}


static const per_sequence_t H235SecurityCapability_sequence[] = {
  { &hf_h245_encryptionAuthenticationAndIntegrity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_EncryptionAuthenticationAndIntegrity },
  { &hf_h245_mediaCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_CapabilityTableEntryNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H235SecurityCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H235SecurityCapability, H235SecurityCapability_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_16_OF_NonStandardParameter_sequence_of[1] = {
  { &hf_h245_ui_nonStandard_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_NonStandardParameter },
};

static int
dissect_h245_SEQUENCE_SIZE_1_16_OF_NonStandardParameter(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h245_SEQUENCE_SIZE_1_16_OF_NonStandardParameter, SEQUENCE_SIZE_1_16_OF_NonStandardParameter_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}


static const value_string h245_UserInputCapability_vals[] = {
  {   0, "nonStandard" },
  {   1, "basicString" },
  {   2, "iA5String" },
  {   3, "generalString" },
  {   4, "dtmf" },
  {   5, "hookflash" },
  {   6, "extendedAlphanumeric" },
  {   7, "encryptedBasicString" },
  {   8, "encryptedIA5String" },
  {   9, "encryptedGeneralString" },
  {  10, "secureDTMF" },
  {  11, "genericUserInputCapability" },
  { 0, NULL }
};

static const per_choice_t UserInputCapability_choice[] = {
  {   0, &hf_h245_ui_nonStandard , ASN1_EXTENSION_ROOT    , dissect_h245_SEQUENCE_SIZE_1_16_OF_NonStandardParameter },
  {   1, &hf_h245_basicString    , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_iA5String      , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   3, &hf_h245_generalString  , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   4, &hf_h245_dtmf           , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   5, &hf_h245_hookflash      , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   6, &hf_h245_extendedAlphanumericFlag, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {   7, &hf_h245_encryptedBasicString, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {   8, &hf_h245_encryptedIA5String, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {   9, &hf_h245_encryptedGeneralString, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {  10, &hf_h245_secureDTMF     , ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {  11, &hf_h245_genericUserInputCapability, ASN1_NOT_EXTENSION_ROOT, dissect_h245_GenericCapability },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_UserInputCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_UserInputCapability, UserInputCapability_choice,
                                 NULL);

  return offset;
}


static const value_string h245_MultiplexFormat_vals[] = {
  {   0, "nonStandard" },
  {   1, "h222Capability" },
  {   2, "h223Capability" },
  { 0, NULL }
};

static const per_choice_t MultiplexFormat_choice[] = {
  {   0, &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardParameter },
  {   1, &hf_h245_h222Capability , ASN1_EXTENSION_ROOT    , dissect_h245_H222Capability },
  {   2, &hf_h245_h223Capability , ASN1_EXTENSION_ROOT    , dissect_h245_H223Capability },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_MultiplexFormat(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_MultiplexFormat, MultiplexFormat_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t AlternativeCapabilitySet_sequence_of[1] = {
  { &hf_h245_AlternativeCapabilitySet_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_CapabilityTableEntryNumber },
};

static int
dissect_h245_AlternativeCapabilitySet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h245_AlternativeCapabilitySet, AlternativeCapabilitySet_sequence_of,
                                                  1, 256, FALSE);

  return offset;
}


static const per_sequence_t SET_SIZE_1_256_OF_AlternativeCapabilitySet_set_of[1] = {
  { &hf_h245_simultaneousCapabilities_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_AlternativeCapabilitySet },
};

static int
dissect_h245_SET_SIZE_1_256_OF_AlternativeCapabilitySet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h245_SET_SIZE_1_256_OF_AlternativeCapabilitySet, SET_SIZE_1_256_OF_AlternativeCapabilitySet_set_of,
                                             1, 256, FALSE);

  return offset;
}


static const per_sequence_t MultiplexedStreamCapability_sequence[] = {
  { &hf_h245_multiplexFormat, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_MultiplexFormat },
  { &hf_h245_controlOnMuxStream, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_capabilityOnMuxStream, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_SET_SIZE_1_256_OF_AlternativeCapabilitySet },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MultiplexedStreamCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MultiplexedStreamCapability, MultiplexedStreamCapability_sequence);

  return offset;
}



static int
dissect_h245_INTEGER_96_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            96U, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t AudioTelephonyEventCapability_sequence[] = {
  { &hf_h245_dynamicRTPPayloadType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_96_127 },
  { &hf_h245_audioTelephoneEvent, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_GeneralString },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_AudioTelephonyEventCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_AudioTelephonyEventCapability, AudioTelephonyEventCapability_sequence);

  return offset;
}


static const per_sequence_t AudioToneCapability_sequence[] = {
  { &hf_h245_dynamicRTPPayloadType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_96_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_AudioToneCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_AudioToneCapability, AudioToneCapability_sequence);

  return offset;
}


static const per_sequence_t T_separateStreamBool_sequence[] = {
  { &hf_h245_separatePort   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_samePortBool   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_separateStreamBool(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_separateStreamBool, T_separateStreamBool_sequence);

  return offset;
}


static const per_sequence_t FECC_rfc2733_sequence[] = {
  { &hf_h245_redundancyEncodingBool, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_separateStreamBool, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_separateStreamBool },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_FECC_rfc2733(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_FECC_rfc2733, FECC_rfc2733_sequence);

  return offset;
}


static const value_string h245_DepFECCapability_vals[] = {
  {   0, "rfc2733" },
  { 0, NULL }
};

static const per_choice_t DepFECCapability_choice[] = {
  {   0, &hf_h245_fecc_rfc2733   , ASN1_EXTENSION_ROOT    , dissect_h245_FECC_rfc2733 },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_DepFECCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_DepFECCapability, DepFECCapability_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MultiplePayloadStreamCapability_sequence[] = {
  { &hf_h245_capabilities   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SET_SIZE_1_256_OF_AlternativeCapabilitySet },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MultiplePayloadStreamCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MultiplePayloadStreamCapability, MultiplePayloadStreamCapability_sequence);

  return offset;
}



static int
dissect_h245_MaxRedundancy(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, NO_BOUND, NULL, FALSE);

  return offset;
}


static const value_string h245_Rfc2733Format_vals[] = {
  {   0, "rfc2733rfc2198" },
  {   1, "rfc2733sameport" },
  {   2, "rfc2733diffport" },
  { 0, NULL }
};

static const per_choice_t Rfc2733Format_choice[] = {
  {   0, &hf_h245_rfc2733rfc2198 , ASN1_NO_EXTENSIONS     , dissect_h245_MaxRedundancy },
  {   1, &hf_h245_rfc2733sameport, ASN1_NO_EXTENSIONS     , dissect_h245_MaxRedundancy },
  {   2, &hf_h245_rfc2733diffport, ASN1_NO_EXTENSIONS     , dissect_h245_MaxRedundancy },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_Rfc2733Format(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_Rfc2733Format, Rfc2733Format_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t FECCapability_sequence[] = {
  { &hf_h245_protectedCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_CapabilityTableEntryNumber },
  { &hf_h245_fecScheme      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_OBJECT_IDENTIFIER },
  { &hf_h245_rfc2733Format  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_Rfc2733Format },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_FECCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_FECCapability, FECCapability_sequence);

  return offset;
}


const value_string h245_Capability_vals[] = {
  {   0, "nonStandard" },
  {   1, "receiveVideoCapability" },
  {   2, "transmitVideoCapability" },
  {   3, "receiveAndTransmitVideoCapability" },
  {   4, "receiveAudioCapability" },
  {   5, "transmitAudioCapability" },
  {   6, "receiveAndTransmitAudioCapability" },
  {   7, "receiveDataApplicationCapability" },
  {   8, "transmitDataApplicationCapability" },
  {   9, "receiveAndTransmitDataApplicationCapability" },
  {  10, "h233EncryptionTransmitCapability" },
  {  11, "h233EncryptionReceiveCapability" },
  {  12, "conferenceCapability" },
  {  13, "h235SecurityCapability" },
  {  14, "maxPendingReplacementFor" },
  {  15, "receiveUserInputCapability" },
  {  16, "transmitUserInputCapability" },
  {  17, "receiveAndTransmitUserInputCapability" },
  {  18, "genericControlCapability" },
  {  19, "receiveMultiplexedStreamCapability" },
  {  20, "transmitMultiplexedStreamCapability" },
  {  21, "receiveAndTransmitMultiplexedStreamCapability" },
  {  22, "receiveRTPAudioTelephonyEventCapability" },
  {  23, "receiveRTPAudioToneCapability" },
  {  24, "depFecCapability" },
  {  25, "multiplePayloadStreamCapability" },
  {  26, "fecCapability" },
  {  27, "redundancyEncodingCap" },
  {  28, "oneOfCapabilities" },
  { 0, NULL }
};

static const per_choice_t Capability_choice[] = {
  {   0, &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardParameter },
  {   1, &hf_h245_receiveVideoCapability, ASN1_EXTENSION_ROOT    , dissect_h245_VideoCapability },
  {   2, &hf_h245_transmitVideoCapability, ASN1_EXTENSION_ROOT    , dissect_h245_VideoCapability },
  {   3, &hf_h245_receiveAndTransmitVideoCapability, ASN1_EXTENSION_ROOT    , dissect_h245_VideoCapability },
  {   4, &hf_h245_receiveAudioCapability, ASN1_EXTENSION_ROOT    , dissect_h245_AudioCapability },
  {   5, &hf_h245_transmitAudioCapability, ASN1_EXTENSION_ROOT    , dissect_h245_AudioCapability },
  {   6, &hf_h245_receiveAndTransmitAudioCapability, ASN1_EXTENSION_ROOT    , dissect_h245_AudioCapability },
  {   7, &hf_h245_receiveDataApplicationCapability, ASN1_EXTENSION_ROOT    , dissect_h245_DataApplicationCapability },
  {   8, &hf_h245_transmitDataApplicationCapability, ASN1_EXTENSION_ROOT    , dissect_h245_DataApplicationCapability },
  {   9, &hf_h245_receiveAndTransmitDataApplicationCapability, ASN1_EXTENSION_ROOT    , dissect_h245_DataApplicationCapability },
  {  10, &hf_h245_h233EncryptionTransmitCapability, ASN1_EXTENSION_ROOT    , dissect_h245_BOOLEAN },
  {  11, &hf_h245_h233EncryptionReceiveCapability, ASN1_EXTENSION_ROOT    , dissect_h245_T_h233EncryptionReceiveCapability },
  {  12, &hf_h245_conferenceCapability, ASN1_NOT_EXTENSION_ROOT, dissect_h245_ConferenceCapability },
  {  13, &hf_h245_h235SecurityCapability, ASN1_NOT_EXTENSION_ROOT, dissect_h245_H235SecurityCapability },
  {  14, &hf_h245_maxPendingReplacementFor, ASN1_NOT_EXTENSION_ROOT, dissect_h245_INTEGER_0_255 },
  {  15, &hf_h245_receiveUserInputCapability, ASN1_NOT_EXTENSION_ROOT, dissect_h245_UserInputCapability },
  {  16, &hf_h245_transmitUserInputCapability, ASN1_NOT_EXTENSION_ROOT, dissect_h245_UserInputCapability },
  {  17, &hf_h245_receiveAndTransmitUserInputCapability, ASN1_NOT_EXTENSION_ROOT, dissect_h245_UserInputCapability },
  {  18, &hf_h245_genericControlCapability, ASN1_NOT_EXTENSION_ROOT, dissect_h245_GenericCapability },
  {  19, &hf_h245_receiveMultiplexedStreamCapability, ASN1_NOT_EXTENSION_ROOT, dissect_h245_MultiplexedStreamCapability },
  {  20, &hf_h245_transmitMultiplexedStreamCapability, ASN1_NOT_EXTENSION_ROOT, dissect_h245_MultiplexedStreamCapability },
  {  21, &hf_h245_receiveAndTransmitMultiplexedStreamCapability, ASN1_NOT_EXTENSION_ROOT, dissect_h245_MultiplexedStreamCapability },
  {  22, &hf_h245_receiveRTPAudioTelephonyEventCapability, ASN1_NOT_EXTENSION_ROOT, dissect_h245_AudioTelephonyEventCapability },
  {  23, &hf_h245_receiveRTPAudioToneCapability, ASN1_NOT_EXTENSION_ROOT, dissect_h245_AudioToneCapability },
  {  24, &hf_h245_depFecCapability, ASN1_NOT_EXTENSION_ROOT, dissect_h245_DepFECCapability },
  {  25, &hf_h245_multiplePayloadStreamCapability, ASN1_NOT_EXTENSION_ROOT, dissect_h245_MultiplePayloadStreamCapability },
  {  26, &hf_h245_fecCapability  , ASN1_NOT_EXTENSION_ROOT, dissect_h245_FECCapability },
  {  27, &hf_h245_redundancyEncodingCap, ASN1_NOT_EXTENSION_ROOT, dissect_h245_RedundancyEncodingCapability },
  {  28, &hf_h245_oneOfCapabilities, ASN1_NOT_EXTENSION_ROOT, dissect_h245_AlternativeCapabilitySet },
  { 0, NULL, 0, NULL }
};

int
dissect_h245_Capability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_Capability, Capability_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CapabilityTableEntry_sequence[] = {
  { &hf_h245_capabilityTableEntryNumber, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_CapabilityTableEntryNumber },
  { &hf_h245_capability     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_h245_Capability },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_CapabilityTableEntry(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_CapabilityTableEntry, CapabilityTableEntry_sequence);

  return offset;
}


static const per_sequence_t SET_SIZE_1_256_OF_CapabilityTableEntry_set_of[1] = {
  { &hf_h245_capabilityTable_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_CapabilityTableEntry },
};

static int
dissect_h245_SET_SIZE_1_256_OF_CapabilityTableEntry(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h245_SET_SIZE_1_256_OF_CapabilityTableEntry, SET_SIZE_1_256_OF_CapabilityTableEntry_set_of,
                                             1, 256, FALSE);

  return offset;
}



static int
dissect_h245_CapabilityDescriptorNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t CapabilityDescriptor_sequence[] = {
  { &hf_h245_capabilityDescriptorNumber, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_CapabilityDescriptorNumber },
  { &hf_h245_simultaneousCapabilities, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_h245_SET_SIZE_1_256_OF_AlternativeCapabilitySet },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_CapabilityDescriptor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_CapabilityDescriptor, CapabilityDescriptor_sequence);

  return offset;
}


static const per_sequence_t SET_SIZE_1_256_OF_CapabilityDescriptor_set_of[1] = {
  { &hf_h245_capabilityDescriptors_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_CapabilityDescriptor },
};

static int
dissect_h245_SET_SIZE_1_256_OF_CapabilityDescriptor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h245_SET_SIZE_1_256_OF_CapabilityDescriptor, SET_SIZE_1_256_OF_CapabilityDescriptor_set_of,
                                             1, 256, FALSE);

  return offset;
}



static int
dissect_h245_T_subMessageIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 620 "../../asn1/h245/h245.cnf"
  guint32 subMessageIdentifer;
  gef_ctx_t *gefx;

  gefx = gef_ctx_get(actx->private_data);
  if (gefx) {
	/* If this is a standard generic message use hf_h245_subMessageIdentifier_standard to get
	 * the value translated and make it fileterable.
	 */
    if (strcmp("GenericMessage/0.0.8.239.2", gefx->key) == 0) {
      hf_index = hf_h245_subMessageIdentifier_standard;
    }
  }
  
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, &subMessageIdentifer, FALSE);

  if (gefx) {
    gefx->subid = ep_strdup_printf("%u", subMessageIdentifer);
    gef_ctx_update_key(gef_ctx_get(actx->private_data));
    /* DEBUG */ /*proto_tree_add_text(tree, tvb, offset>>3, 0, "*** DEBUG CapabilityIdentifier: %s", gef_ctx_get(actx->private_data)->key);*/
  }
  if (hf_index == hf_h245_subMessageIdentifier_standard)
  {
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s", val_to_str(subMessageIdentifer, h245_h239subMessageIdentifier_vals, "<unknown>") );
    g_snprintf(h245_pi->frame_label, 50, "%s", val_to_str(subMessageIdentifer, h245_h239subMessageIdentifier_vals, "<unknown>"));
  }


  return offset;
}



static int
dissect_h245_T_messageContent_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 647 "../../asn1/h245/h245.cnf"
  gef_ctx_t *parent_gefx;

  parent_gefx = gef_ctx_get(actx->private_data);
  actx->private_data = gef_ctx_alloc(parent_gefx, NULL);

  offset = dissect_h245_GenericParameter(tvb, offset, actx, tree, hf_index);

#line 652 "../../asn1/h245/h245.cnf"
  actx->private_data = parent_gefx;

  return offset;
}


static const per_sequence_t T_messageContent_sequence_of[1] = {
  { &hf_h245_messageContent_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_T_messageContent_item },
};

static int
dissect_h245_T_messageContent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h245_T_messageContent, T_messageContent_sequence_of);

  return offset;
}


static const per_sequence_t GenericMessage_sequence[] = {
  { &hf_h245_messageIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_CapabilityIdentifier },
  { &hf_h245_subMessageIdentifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_T_subMessageIdentifier },
  { &hf_h245_messageContent , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_T_messageContent },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_GenericMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 606 "../../asn1/h245/h245.cnf"
  void *priv_data = actx->private_data;
  gef_ctx_t *gefx;

  /* check if not inherited from GenericInformation */
  gefx = gef_ctx_get(actx->private_data);
  if (!gefx) {
    gefx = gef_ctx_alloc(NULL, "GenericMessage");
    actx->private_data = gefx;
  }

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_GenericMessage, GenericMessage_sequence);

#line 616 "../../asn1/h245/h245.cnf"
  actx->private_data = priv_data;

  return offset;
}



static int
dissect_h245_GenericInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 657 "../../asn1/h245/h245.cnf"
  void *priv_data = actx->private_data;
  actx->private_data = gef_ctx_alloc(NULL, "GenericInformation");

  offset = dissect_h245_GenericMessage(tvb, offset, actx, tree, hf_index);

#line 660 "../../asn1/h245/h245.cnf"
  actx->private_data = priv_data;

  return offset;
}


static const per_sequence_t SEQUENCE_OF_GenericInformation_sequence_of[1] = {
  { &hf_h245_genericInformation_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_GenericInformation },
};

static int
dissect_h245_SEQUENCE_OF_GenericInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h245_SEQUENCE_OF_GenericInformation, SEQUENCE_OF_GenericInformation_sequence_of);

  return offset;
}


static const per_sequence_t TerminalCapabilitySet_sequence[] = {
  { &hf_h245_sequenceNumber , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SequenceNumber },
  { &hf_h245_protocolIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_OBJECT_IDENTIFIER },
  { &hf_h245_multiplexCapability, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_MultiplexCapability },
  { &hf_h245_capabilityTable, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_SET_SIZE_1_256_OF_CapabilityTableEntry },
  { &hf_h245_capabilityDescriptors, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_SET_SIZE_1_256_OF_CapabilityDescriptor },
  { &hf_h245_genericInformation, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_SEQUENCE_OF_GenericInformation },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_TerminalCapabilitySet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_TerminalCapabilitySet, TerminalCapabilitySet_sequence);

#line 591 "../../asn1/h245/h245.cnf"

if (h245_pi != NULL)
  h245_pi->msg_type = H245_TermCapSet;

  return offset;
}



static int
dissect_h245_LogicalChannelNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 123 "../../asn1/h245/h245.cnf"
  guint32 value;
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, &value, FALSE);

  h245_lc_temp = value & 0xfff;


  return offset;
}



static int
dissect_h245_OLC_fw_lcn(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_h245_LogicalChannelNumber(tvb, offset, actx, tree, hf_index);

#line 164 "../../asn1/h245/h245.cnf"
  if (upcoming_olc) upcoming_olc->fwd_lc_num = h245_lc_temp;
  h223_fw_lc_num = h245_lc_temp;

  return offset;
}


static const value_string h245_EncryptionMode_vals[] = {
  {   0, "nonStandard" },
  {   1, "h233Encryption" },
  { 0, NULL }
};

static const per_choice_t EncryptionMode_choice[] = {
  {   0, &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardParameter },
  {   1, &hf_h245_h233Encryption , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_EncryptionMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_EncryptionMode, EncryptionMode_choice,
                                 NULL);

  return offset;
}



static int
dissect_h245_INTEGER_0_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t RedundancyEncodingElement_sequence[] = {
  { &hf_h245_dataType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_DataType },
  { &hf_h245_payloadType    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RedundancyEncodingElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RedundancyEncodingElement, RedundancyEncodingElement_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_RedundancyEncodingElement_sequence_of[1] = {
  { &hf_h245_secondary_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_RedundancyEncodingElement },
};

static int
dissect_h245_SEQUENCE_OF_RedundancyEncodingElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h245_SEQUENCE_OF_RedundancyEncodingElement, SEQUENCE_OF_RedundancyEncodingElement_sequence_of);

  return offset;
}


static const per_sequence_t T_rtpRedundancyEncoding_sequence[] = {
  { &hf_h245_primary        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_RedundancyEncodingElement },
  { &hf_h245_secondary      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_SEQUENCE_OF_RedundancyEncodingElement },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_rtpRedundancyEncoding(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_rtpRedundancyEncoding, T_rtpRedundancyEncoding_sequence);

  return offset;
}


static const per_sequence_t RedundancyEncoding_sequence[] = {
  { &hf_h245_redundancyEncodingMethod, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_RedundancyEncodingMethod },
  { &hf_h245_secondaryEncoding, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_DataType },
  { &hf_h245_rtpRedundancyEncoding, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_T_rtpRedundancyEncoding },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RedundancyEncoding(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RedundancyEncoding, RedundancyEncoding_sequence);

  return offset;
}


static const per_sequence_t MultiplePayloadStreamElement_sequence[] = {
  { &hf_h245_dataType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_DataType },
  { &hf_h245_payloadType    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MultiplePayloadStreamElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MultiplePayloadStreamElement, MultiplePayloadStreamElement_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_MultiplePayloadStreamElement_sequence_of[1] = {
  { &hf_h245_elements_item  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_MultiplePayloadStreamElement },
};

static int
dissect_h245_SEQUENCE_OF_MultiplePayloadStreamElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h245_SEQUENCE_OF_MultiplePayloadStreamElement, SEQUENCE_OF_MultiplePayloadStreamElement_sequence_of);

  return offset;
}


static const per_sequence_t MultiplePayloadStream_sequence[] = {
  { &hf_h245_elements       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SEQUENCE_OF_MultiplePayloadStreamElement },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MultiplePayloadStream(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MultiplePayloadStream, MultiplePayloadStream_sequence);

  return offset;
}


static const per_sequence_t T_differentPort_sequence[] = {
  { &hf_h245_protectedSessionID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_255 },
  { &hf_h245_protectedPayloadType, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_differentPort(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_differentPort, T_differentPort_sequence);

  return offset;
}


static const per_sequence_t T_samePort_sequence[] = {
  { &hf_h245_protectedPayloadType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_samePort(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_samePort, T_samePort_sequence);

  return offset;
}


static const value_string h245_DepSeparateStream_vals[] = {
  {   0, "differentPort" },
  {   1, "samePort" },
  { 0, NULL }
};

static const per_choice_t DepSeparateStream_choice[] = {
  {   0, &hf_h245_differentPort  , ASN1_EXTENSION_ROOT    , dissect_h245_T_differentPort },
  {   1, &hf_h245_samePort       , ASN1_EXTENSION_ROOT    , dissect_h245_T_samePort },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_DepSeparateStream(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_DepSeparateStream, DepSeparateStream_choice,
                                 NULL);

  return offset;
}


static const value_string h245_FECdata_mode_vals[] = {
  {   0, "redundancyEncoding" },
  {   1, "separateStream" },
  { 0, NULL }
};

static const per_choice_t FECdata_mode_choice[] = {
  {   0, &hf_h245_redundancyEncodingFlag, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_separateStream , ASN1_EXTENSION_ROOT    , dissect_h245_DepSeparateStream },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_FECdata_mode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_FECdata_mode, FECdata_mode_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RFC2733Data_sequence[] = {
  { &hf_h245_fec_data_mode  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_FECdata_mode },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RFC2733Data(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RFC2733Data, RFC2733Data_sequence);

  return offset;
}


static const value_string h245_DepFECData_vals[] = {
  {   0, "rfc2733" },
  { 0, NULL }
};

static const per_choice_t DepFECData_choice[] = {
  {   0, &hf_h245_dep_rfc2733    , ASN1_NO_EXTENSIONS     , dissect_h245_RFC2733Data },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_DepFECData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_DepFECData, DepFECData_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_mode_rfc2733sameport_sequence[] = {
  { NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};

static int
dissect_h245_T_mode_rfc2733sameport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_mode_rfc2733sameport, T_mode_rfc2733sameport_sequence);

  return offset;
}


static const per_sequence_t T_mode_rfc2733diffport_sequence[] = {
  { &hf_h245_protectedChannel, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_LogicalChannelNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_mode_rfc2733diffport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_mode_rfc2733diffport, T_mode_rfc2733diffport_sequence);

  return offset;
}


static const value_string h245_T_pktMode_vals[] = {
  {   0, "rfc2198coding" },
  {   1, "rfc2733sameport" },
  {   2, "rfc2733diffport" },
  { 0, NULL }
};

static const per_choice_t T_pktMode_choice[] = {
  {   0, &hf_h245_rfc2198coding  , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_mode_rfc2733sameport, ASN1_EXTENSION_ROOT    , dissect_h245_T_mode_rfc2733sameport },
  {   2, &hf_h245_mode_rfc2733diffport, ASN1_EXTENSION_ROOT    , dissect_h245_T_mode_rfc2733diffport },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_pktMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_pktMode, T_pktMode_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_rfc2733_sequence[] = {
  { &hf_h245_protectedPayloadType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_127 },
  { &hf_h245_fecScheme      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_OBJECT_IDENTIFIER },
  { &hf_h245_pktMode        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_pktMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_rfc2733(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_rfc2733, T_rfc2733_sequence);

  return offset;
}


static const value_string h245_FECData_vals[] = {
  {   0, "rfc2733" },
  { 0, NULL }
};

static const per_choice_t FECData_choice[] = {
  {   0, &hf_h245_rfc2733        , ASN1_EXTENSION_ROOT    , dissect_h245_T_rfc2733 },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_FECData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_FECData, FECData_choice,
                                 NULL);

  return offset;
}


static const value_string h245_T_mediaType_vals[] = {
  {   0, "nonStandard" },
  {   1, "videoData" },
  {   2, "audioData" },
  {   3, "data" },
  {   4, "redundancyEncoding" },
  {   5, "multiplePayloadStream" },
  {   6, "depFec" },
  {   7, "fec" },
  { 0, NULL }
};

static const per_choice_t T_mediaType_choice[] = {
  {   0, &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardParameter },
  {   1, &hf_h245_videoData      , ASN1_EXTENSION_ROOT    , dissect_h245_VideoCapability },
  {   2, &hf_h245_audioData      , ASN1_EXTENSION_ROOT    , dissect_h245_AudioCapability },
  {   3, &hf_h245_data           , ASN1_EXTENSION_ROOT    , dissect_h245_DataApplicationCapability },
  {   4, &hf_h245_redundancyEncoding, ASN1_NOT_EXTENSION_ROOT, dissect_h245_RedundancyEncoding },
  {   5, &hf_h245_multiplePayloadStream, ASN1_NOT_EXTENSION_ROOT, dissect_h245_MultiplePayloadStream },
  {   6, &hf_h245_depFec         , ASN1_NOT_EXTENSION_ROOT, dissect_h245_DepFECData },
  {   7, &hf_h245_fec            , ASN1_NOT_EXTENSION_ROOT, dissect_h245_FECData },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_mediaType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_mediaType, T_mediaType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t H235Media_sequence[] = {
  { &hf_h245_encryptionAuthenticationAndIntegrity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_EncryptionAuthenticationAndIntegrity },
  { &hf_h245_mediaType      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_mediaType },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H235Media(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H235Media, H235Media_sequence);

  return offset;
}


static const per_sequence_t MultiplexedStreamParameter_sequence[] = {
  { &hf_h245_multiplexFormat, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_MultiplexFormat },
  { &hf_h245_controlOnMuxStream, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MultiplexedStreamParameter(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MultiplexedStreamParameter, MultiplexedStreamParameter_sequence);

  return offset;
}


static const value_string h245_DataType_vals[] = {
  {   0, "nonStandard" },
  {   1, "nullData" },
  {   2, "videoData" },
  {   3, "audioData" },
  {   4, "data" },
  {   5, "encryptionData" },
  {   6, "h235Control" },
  {   7, "h235Media" },
  {   8, "multiplexedStream" },
  {   9, "redundancyEncoding" },
  {  10, "multiplePayloadStream" },
  {  11, "depFec" },
  {  12, "fec" },
  { 0, NULL }
};

static const per_choice_t DataType_choice[] = {
  {   0, &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardParameter },
  {   1, &hf_h245_nullData       , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_videoData      , ASN1_EXTENSION_ROOT    , dissect_h245_VideoCapability },
  {   3, &hf_h245_audioData      , ASN1_EXTENSION_ROOT    , dissect_h245_AudioCapability },
  {   4, &hf_h245_data           , ASN1_EXTENSION_ROOT    , dissect_h245_DataApplicationCapability },
  {   5, &hf_h245_encryptionData , ASN1_EXTENSION_ROOT    , dissect_h245_EncryptionMode },
  {   6, &hf_h245_h235Control    , ASN1_NOT_EXTENSION_ROOT, dissect_h245_NonStandardParameter },
  {   7, &hf_h245_h235Media      , ASN1_NOT_EXTENSION_ROOT, dissect_h245_H235Media },
  {   8, &hf_h245_multiplexedStream, ASN1_NOT_EXTENSION_ROOT, dissect_h245_MultiplexedStreamParameter },
  {   9, &hf_h245_redundancyEncoding, ASN1_NOT_EXTENSION_ROOT, dissect_h245_RedundancyEncoding },
  {  10, &hf_h245_multiplePayloadStream, ASN1_NOT_EXTENSION_ROOT, dissect_h245_MultiplePayloadStream },
  {  11, &hf_h245_depFec         , ASN1_NOT_EXTENSION_ROOT, dissect_h245_DepFECData },
  {  12, &hf_h245_fec            , ASN1_NOT_EXTENSION_ROOT, dissect_h245_FECData },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_DataType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1012 "../../asn1/h245/h245.cnf"
gint choice_index;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_DataType, DataType_choice,
                                 &choice_index);


if (upcoming_channel){
	if (choice_index==2){
		upcoming_channel->is_video=TRUE;
	}else{
		upcoming_channel->is_video=FALSE;
	}
}



  return offset;
}



static int
dissect_h245_INTEGER_0_8191(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8191U, NULL, FALSE);

  return offset;
}


static const per_sequence_t H222LogicalChannelParameters_sequence[] = {
  { &hf_h245_resourceID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_65535 },
  { &hf_h245_subChannelID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_8191 },
  { &hf_h245_pcr_pid        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_8191 },
  { &hf_h245_programDescriptors, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_OCTET_STRING },
  { &hf_h245_streamDescriptors, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H222LogicalChannelParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H222LogicalChannelParameters, H222LogicalChannelParameters_sequence);

  return offset;
}



static int
dissect_h245_T_h223_al_type_al1Framed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 295 "../../asn1/h245/h245.cnf"
  if(h223_lc_params_temp)
	h223_lc_params_temp->al_type = al1Framed;

  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_h245_T_h223_al_type_al1NotFramed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 300 "../../asn1/h245/h245.cnf"
  if(h223_lc_params_temp)
	h223_lc_params_temp->al_type = al1NotFramed;

  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_h245_T_h223_al_type_al2WithoutSequenceNumbers(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 305 "../../asn1/h245/h245.cnf"
  if(h223_lc_params_temp)
	h223_lc_params_temp->al_type = al2WithoutSequenceNumbers;

  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_h245_T_h223_al_type_al2WithSequenceNumbers(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 310 "../../asn1/h245/h245.cnf"
  if(h223_lc_params_temp)
	h223_lc_params_temp->al_type = al2WithSequenceNumbers;

  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_h245_T_controlFieldOctets(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 324 "../../asn1/h245/h245.cnf"
  guint32 value;
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2U, &value, FALSE);

  if(h223_lc_params_temp && h223_lc_params_temp->al_params)
	((h223_al3_params*)h223_lc_params_temp->al_params)->control_field_octets = value & 3 ;


  return offset;
}



static int
dissect_h245_T_al3_sendBufferSize(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 333 "../../asn1/h245/h245.cnf"
  guint32 value;
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16777215U, &value, FALSE);

  if(h223_lc_params_temp && h223_lc_params_temp->al_params)
	((h223_al3_params*)h223_lc_params_temp->al_params)->send_buffer_size = value & 0xfffff;


  return offset;
}


static const per_sequence_t Al3_sequence[] = {
  { &hf_h245_controlFieldOctets, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_T_controlFieldOctets },
  { &hf_h245_al3_sendBufferSize, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_T_al3_sendBufferSize },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_Al3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_Al3, Al3_sequence);

  return offset;
}



static int
dissect_h245_T_h223_al_type_al3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 315 "../../asn1/h245/h245.cnf"
 if(h223_lc_params_temp) {
	h223_lc_params_temp->al_type = al3;
	h223_lc_params_temp->al_params = se_alloc(sizeof(h223_al3_params));
  }

  offset = dissect_h245_Al3(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string h245_T_transferMode_vals[] = {
  {   0, "framed" },
  {   1, "unframed" },
  { 0, NULL }
};

static const per_choice_t T_transferMode_choice[] = {
  {   0, &hf_h245_framed         , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_unframed       , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_transferMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_transferMode, T_transferMode_choice,
                                 NULL);

  return offset;
}


static const value_string h245_AL1HeaderFEC_vals[] = {
  {   0, "sebch16-7" },
  {   1, "golay24-12" },
  { 0, NULL }
};

static const per_choice_t AL1HeaderFEC_choice[] = {
  {   0, &hf_h245_sebch16_7      , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_golay24_12     , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_AL1HeaderFEC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_AL1HeaderFEC, AL1HeaderFEC_choice,
                                 NULL);

  return offset;
}


static const value_string h245_AL1CrcLength_vals[] = {
  {   0, "crc4bit" },
  {   1, "crc12bit" },
  {   2, "crc20bit" },
  {   3, "crc28bit" },
  {   4, "crc8bit" },
  {   5, "crc16bit" },
  {   6, "crc32bit" },
  {   7, "crcNotUsed" },
  { 0, NULL }
};

static const per_choice_t AL1CrcLength_choice[] = {
  {   0, &hf_h245_crc4bit        , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_crc12bit       , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_crc20bit       , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   3, &hf_h245_crc28bit       , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   4, &hf_h245_crc8bit        , ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {   5, &hf_h245_crc16bit       , ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {   6, &hf_h245_crc32bit       , ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {   7, &hf_h245_crcNotUsed     , ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_AL1CrcLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_AL1CrcLength, AL1CrcLength_choice,
                                 NULL);

  return offset;
}



static int
dissect_h245_INTEGER_8_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            8U, 32U, NULL, FALSE);

  return offset;
}



static int
dissect_h245_INTEGER_0_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16U, NULL, FALSE);

  return offset;
}


static const value_string h245_T_numberOfRetransmissions_vals[] = {
  {   0, "finite" },
  {   1, "infinite" },
  { 0, NULL }
};

static const per_choice_t T_numberOfRetransmissions_choice[] = {
  {   0, &hf_h245_finite         , ASN1_EXTENSION_ROOT    , dissect_h245_INTEGER_0_16 },
  {   1, &hf_h245_infinite       , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_numberOfRetransmissions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_numberOfRetransmissions, T_numberOfRetransmissions_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t H223AnnexCArqParameters_sequence[] = {
  { &hf_h245_numberOfRetransmissions, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_numberOfRetransmissions },
  { &hf_h245_sendBufferSize , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_16777215 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H223AnnexCArqParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H223AnnexCArqParameters, H223AnnexCArqParameters_sequence);

  return offset;
}


static const value_string h245_ArqType_vals[] = {
  {   0, "noArq" },
  {   1, "typeIArq" },
  {   2, "typeIIArq" },
  { 0, NULL }
};

static const per_choice_t ArqType_choice[] = {
  {   0, &hf_h245_noArq          , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_typeIArq       , ASN1_EXTENSION_ROOT    , dissect_h245_H223AnnexCArqParameters },
  {   2, &hf_h245_typeIIArq      , ASN1_EXTENSION_ROOT    , dissect_h245_H223AnnexCArqParameters },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_ArqType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_ArqType, ArqType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t H223AL1MParameters_sequence[] = {
  { &hf_h245_transferMode   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_transferMode },
  { &hf_h245_aL1HeaderFEC   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_AL1HeaderFEC },
  { &hf_h245_crcLength2     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_AL1CrcLength },
  { &hf_h245_rcpcCodeRate   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_8_32 },
  { &hf_h245_arqType        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_ArqType },
  { &hf_h245_alpduInterleaving, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_alsduSplitting , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_rsCodeCorrection, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_INTEGER_0_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H223AL1MParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H223AL1MParameters, H223AL1MParameters_sequence);

  return offset;
}



static int
dissect_h245_T_h223_al_type_al1M(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 340 "../../asn1/h245/h245.cnf"
  if(h223_lc_params_temp)
	h223_lc_params_temp->al_type = al1M;

  offset = dissect_h245_H223AL1MParameters(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string h245_AL2HeaderFEC_vals[] = {
  {   0, "sebch16-5" },
  {   1, "golay24-12" },
  { 0, NULL }
};

static const per_choice_t AL2HeaderFEC_choice[] = {
  {   0, &hf_h245_sebch16_5      , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_golay24_12     , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_AL2HeaderFEC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_AL2HeaderFEC, AL2HeaderFEC_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t H223AL2MParameters_sequence[] = {
  { &hf_h245_aL2HeaderFEC   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_AL2HeaderFEC },
  { &hf_h245_alpduInterleaving, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H223AL2MParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H223AL2MParameters, H223AL2MParameters_sequence);

  return offset;
}



static int
dissect_h245_T_h223_al_type_al2M(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 345 "../../asn1/h245/h245.cnf"
  if(h223_lc_params_temp)
	h223_lc_params_temp->al_type = al2M;

  offset = dissect_h245_H223AL2MParameters(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string h245_T_headerFormat_vals[] = {
  {   0, "sebch16-7" },
  {   1, "golay24-12" },
  { 0, NULL }
};

static const per_choice_t T_headerFormat_choice[] = {
  {   0, &hf_h245_sebch16_7      , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_golay24_12     , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_headerFormat(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_headerFormat, T_headerFormat_choice,
                                 NULL);

  return offset;
}


static const value_string h245_AL3CrcLength_vals[] = {
  {   0, "crc4bit" },
  {   1, "crc12bit" },
  {   2, "crc20bit" },
  {   3, "crc28bit" },
  {   4, "crc8bit" },
  {   5, "crc16bit" },
  {   6, "crc32bit" },
  {   7, "crcNotUsed" },
  { 0, NULL }
};

static const per_choice_t AL3CrcLength_choice[] = {
  {   0, &hf_h245_crc4bit        , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_crc12bit       , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_crc20bit       , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   3, &hf_h245_crc28bit       , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   4, &hf_h245_crc8bit        , ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {   5, &hf_h245_crc16bit       , ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {   6, &hf_h245_crc32bit       , ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {   7, &hf_h245_crcNotUsed     , ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_AL3CrcLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_AL3CrcLength, AL3CrcLength_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t H223AL3MParameters_sequence[] = {
  { &hf_h245_headerFormat   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_headerFormat },
  { &hf_h245_crlength2      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_AL3CrcLength },
  { &hf_h245_rcpcCodeRate   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_8_32 },
  { &hf_h245_arqType        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_ArqType },
  { &hf_h245_alpduInterleaving, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_rsCodeCorrection, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_INTEGER_0_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H223AL3MParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H223AL3MParameters, H223AL3MParameters_sequence);

  return offset;
}



static int
dissect_h245_T_h223_al_type_al3M(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 350 "../../asn1/h245/h245.cnf"
  if(h223_lc_params_temp)
	h223_lc_params_temp->al_type = al3M;

  offset = dissect_h245_H223AL3MParameters(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string h245_T_adaptationLayerType_vals[] = {
  {   0, "nonStandard" },
  {   1, "al1Framed" },
  {   2, "al1NotFramed" },
  {   3, "al2WithoutSequenceNumbers" },
  {   4, "al2WithSequenceNumbers" },
  {   5, "al3" },
  {   6, "al1M" },
  {   7, "al2M" },
  {   8, "al3M" },
  { 0, NULL }
};

static const per_choice_t T_adaptationLayerType_choice[] = {
  {   0, &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardParameter },
  {   1, &hf_h245_h223_al_type_al1Framed, ASN1_EXTENSION_ROOT    , dissect_h245_T_h223_al_type_al1Framed },
  {   2, &hf_h245_h223_al_type_al1NotFramed, ASN1_EXTENSION_ROOT    , dissect_h245_T_h223_al_type_al1NotFramed },
  {   3, &hf_h245_h223_al_type_al2WithoutSequenceNumbers, ASN1_EXTENSION_ROOT    , dissect_h245_T_h223_al_type_al2WithoutSequenceNumbers },
  {   4, &hf_h245_h223_al_type_al2WithSequenceNumbers, ASN1_EXTENSION_ROOT    , dissect_h245_T_h223_al_type_al2WithSequenceNumbers },
  {   5, &hf_h245_h223_al_type_al3, ASN1_EXTENSION_ROOT    , dissect_h245_T_h223_al_type_al3 },
  {   6, &hf_h245_h223_al_type_al1M, ASN1_NOT_EXTENSION_ROOT, dissect_h245_T_h223_al_type_al1M },
  {   7, &hf_h245_h223_al_type_al2M, ASN1_NOT_EXTENSION_ROOT, dissect_h245_T_h223_al_type_al2M },
  {   8, &hf_h245_h223_al_type_al3M, ASN1_NOT_EXTENSION_ROOT, dissect_h245_T_h223_al_type_al3M },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_adaptationLayerType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_adaptationLayerType, T_adaptationLayerType_choice,
                                 NULL);

  return offset;
}



static int
dissect_h245_T_h223_lc_segmentableFlag(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 357 "../../asn1/h245/h245.cnf"
  gboolean value;
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, &value);

  if(h223_lc_params_temp)
	h223_lc_params_temp->segmentable = value;


  return offset;
}


static const per_sequence_t H223LogicalChannelParameters_sequence[] = {
  { &hf_h245_adaptationLayerType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_adaptationLayerType },
  { &hf_h245_h223_lc_segmentableFlag, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_h223_lc_segmentableFlag },
  { NULL, 0, 0, NULL }
};

int
dissect_h245_H223LogicalChannelParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H223LogicalChannelParameters, H223LogicalChannelParameters_sequence);

  return offset;
}



static int
dissect_h245_OLC_fw_h223_params(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 186 "../../asn1/h245/h245.cnf"
  h223_fw_lc_params = se_alloc(sizeof(h223_lc_params));
  h223_fw_lc_params->al_type = al_nonStandard;
  h223_fw_lc_params->al_params = NULL;
  h223_fw_lc_params->segmentable = 0;
  h223_fw_lc_params->subdissector = NULL;
  h223_lc_params_temp = h223_fw_lc_params;

  offset = dissect_h245_H223LogicalChannelParameters(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string h245_CRCLength_vals[] = {
  {   0, "crc8bit" },
  {   1, "crc16bit" },
  {   2, "crc32bit" },
  { 0, NULL }
};

static const per_choice_t CRCLength_choice[] = {
  {   0, &hf_h245_crc8bit        , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_crc16bit       , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_crc32bit       , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_CRCLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_CRCLength, CRCLength_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t V76HDLCParameters_sequence[] = {
  { &hf_h245_crcLength      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_CRCLength },
  { &hf_h245_n401           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_4095 },
  { &hf_h245_loopbackTestProcedure, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_V76HDLCParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_V76HDLCParameters, V76HDLCParameters_sequence);

  return offset;
}


static const value_string h245_T_suspendResume_vals[] = {
  {   0, "noSuspendResume" },
  {   1, "suspendResumewAddress" },
  {   2, "suspendResumewoAddress" },
  { 0, NULL }
};

static const per_choice_t T_suspendResume_choice[] = {
  {   0, &hf_h245_noSuspendResume, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_suspendResumewAddress, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_suspendResumewoAddress, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_suspendResume(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_suspendResume, T_suspendResume_choice,
                                 NULL);

  return offset;
}


static const value_string h245_T_recovery_vals[] = {
  {   0, "rej" },
  {   1, "sREJ" },
  {   2, "mSREJ" },
  { 0, NULL }
};

static const per_choice_t T_recovery_choice[] = {
  {   0, &hf_h245_rej            , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_sREJ           , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_mSREJ          , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_recovery(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_recovery, T_recovery_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_eRM_sequence[] = {
  { &hf_h245_windowSize     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_127 },
  { &hf_h245_recovery       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_recovery },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_eRM(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_eRM, T_eRM_sequence);

  return offset;
}


static const value_string h245_V76LCP_mode_vals[] = {
  {   0, "eRM" },
  {   1, "uNERM" },
  { 0, NULL }
};

static const per_choice_t V76LCP_mode_choice[] = {
  {   0, &hf_h245_eRM            , ASN1_EXTENSION_ROOT    , dissect_h245_T_eRM },
  {   1, &hf_h245_uNERM          , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_V76LCP_mode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_V76LCP_mode, V76LCP_mode_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t V75Parameters_sequence[] = {
  { &hf_h245_audioHeaderPresent, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_V75Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_V75Parameters, V75Parameters_sequence);

  return offset;
}


static const per_sequence_t V76LogicalChannelParameters_sequence[] = {
  { &hf_h245_hdlcParameters , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_V76HDLCParameters },
  { &hf_h245_suspendResume  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_suspendResume },
  { &hf_h245_uIH            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_v76_mode       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_V76LCP_mode },
  { &hf_h245_v75Parameters  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_V75Parameters },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_V76LogicalChannelParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_V76LogicalChannelParameters, V76LogicalChannelParameters_sequence);

  return offset;
}



static int
dissect_h245_Ipv4_network(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 870 "../../asn1/h245/h245.cnf"
  tvbuff_t *value_tvb;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, &value_tvb);


  if (upcoming_channel && upcoming_channel->upcoming_addr) {
    tvb_memcpy(value_tvb, upcoming_channel->upcoming_addr->addr_buf, 0, 4);
    SET_ADDRESS(&upcoming_channel->upcoming_addr->addr, AT_IPv4, 4, upcoming_channel->upcoming_addr->addr_buf);
  }


  return offset;
}



static int
dissect_h245_TsapIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 881 "../../asn1/h245/h245.cnf"
  guint32 tsapIdentifier;

  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &tsapIdentifier, FALSE);


  if (upcoming_channel && upcoming_channel->upcoming_addr) {
    upcoming_channel->upcoming_addr->port = tsapIdentifier;
  }


  return offset;
}


static const per_sequence_t T_iPAddress_sequence[] = {
  { &hf_h245_ip4_network    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_Ipv4_network },
  { &hf_h245_tsapIdentifier , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_TsapIdentifier },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_iPAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_iPAddress, T_iPAddress_sequence);

  return offset;
}



static int
dissect_h245_OCTET_STRING_SIZE_6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       6, 6, FALSE, NULL);

  return offset;
}



static int
dissect_h245_OCTET_STRING_SIZE_4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, NULL);

  return offset;
}



static int
dissect_h245_OCTET_STRING_SIZE_2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}


static const per_sequence_t T_iPXAddress_sequence[] = {
  { &hf_h245_node           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_OCTET_STRING_SIZE_6 },
  { &hf_h245_netnum         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_OCTET_STRING_SIZE_4 },
  { &hf_h245_ipx_tsapIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_OCTET_STRING_SIZE_2 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_iPXAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_iPXAddress, T_iPXAddress_sequence);

  return offset;
}


static const per_sequence_t T_iP6Address_sequence[] = {
  { &hf_h245_ip6_network    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_OCTET_STRING_SIZE_16 },
  { &hf_h245_ipv6_tsapIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_65535 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_iP6Address(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_iP6Address, T_iP6Address_sequence);

  return offset;
}


static const value_string h245_T_routing_vals[] = {
  {   0, "strict" },
  {   1, "loose" },
  { 0, NULL }
};

static const per_choice_t T_routing_choice[] = {
  {   0, &hf_h245_strict         , ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   1, &hf_h245_loose          , ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_routing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_routing, T_routing_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_route_sequence_of[1] = {
  { &hf_h245_route_item     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_OCTET_STRING_SIZE_4 },
};

static int
dissect_h245_T_route(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h245_T_route, T_route_sequence_of);

  return offset;
}


static const per_sequence_t T_iPSourceRouteAddress_sequence[] = {
  { &hf_h245_routing        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_routing },
  { &hf_h245_network        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_OCTET_STRING_SIZE_4 },
  { &hf_h245_iPSrcRoute_tsapIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_65535 },
  { &hf_h245_route          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_route },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_iPSourceRouteAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_iPSourceRouteAddress, T_iPSourceRouteAddress_sequence);

  return offset;
}


const value_string h245_UnicastAddress_vals[] = {
  {   0, "iPAddress" },
  {   1, "iPXAddress" },
  {   2, "iP6Address" },
  {   3, "netBios" },
  {   4, "iPSourceRouteAddress" },
  {   5, "nsap" },
  {   6, "nonStandardAddress" },
  { 0, NULL }
};

static const per_choice_t UnicastAddress_choice[] = {
  {   0, &hf_h245_iPAddress      , ASN1_EXTENSION_ROOT    , dissect_h245_T_iPAddress },
  {   1, &hf_h245_iPXAddress     , ASN1_EXTENSION_ROOT    , dissect_h245_T_iPXAddress },
  {   2, &hf_h245_iP6Address     , ASN1_EXTENSION_ROOT    , dissect_h245_T_iP6Address },
  {   3, &hf_h245_netBios        , ASN1_EXTENSION_ROOT    , dissect_h245_OCTET_STRING_SIZE_16 },
  {   4, &hf_h245_iPSourceRouteAddress, ASN1_EXTENSION_ROOT    , dissect_h245_T_iPSourceRouteAddress },
  {   5, &hf_h245_nsap           , ASN1_NOT_EXTENSION_ROOT, dissect_h245_OCTET_STRING_SIZE_1_20 },
  {   6, &hf_h245_nonStandardAddress, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

int
dissect_h245_UnicastAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_UnicastAddress, UnicastAddress_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MIPAddress_sequence[] = {
  { &hf_h245_mip4_network   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_OCTET_STRING_SIZE_4 },
  { &hf_h245_multicast_tsapIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_65535 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MIPAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MIPAddress, MIPAddress_sequence);

  return offset;
}


static const per_sequence_t MIP6Address_sequence[] = {
  { &hf_h245_mip6_network   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_OCTET_STRING_SIZE_16 },
  { &hf_h245_multicast_IPv6_tsapIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_65535 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MIP6Address(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MIP6Address, MIP6Address_sequence);

  return offset;
}


const value_string h245_MulticastAddress_vals[] = {
  {   0, "iPAddress" },
  {   1, "iP6Address" },
  {   2, "nsap" },
  {   3, "nonStandardAddress" },
  { 0, NULL }
};

static const per_choice_t MulticastAddress_choice[] = {
  {   0, &hf_h245_mIPAddress     , ASN1_EXTENSION_ROOT    , dissect_h245_MIPAddress },
  {   1, &hf_h245_mIP6Address    , ASN1_EXTENSION_ROOT    , dissect_h245_MIP6Address },
  {   2, &hf_h245_nsap           , ASN1_NOT_EXTENSION_ROOT, dissect_h245_OCTET_STRING_SIZE_1_20 },
  {   3, &hf_h245_nonStandardAddress, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

int
dissect_h245_MulticastAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_MulticastAddress, MulticastAddress_choice,
                                 NULL);

  return offset;
}


const value_string h245_TransportAddress_vals[] = {
  {   0, "unicastAddress" },
  {   1, "multicastAddress" },
  { 0, NULL }
};

static const per_choice_t TransportAddress_choice[] = {
  {   0, &hf_h245_unicastAddress , ASN1_EXTENSION_ROOT    , dissect_h245_UnicastAddress },
  {   1, &hf_h245_multicastAddress, ASN1_EXTENSION_ROOT    , dissect_h245_MulticastAddress },
  { 0, NULL, 0, NULL }
};

int
dissect_h245_TransportAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_TransportAddress, TransportAddress_choice,
                                 NULL);

  return offset;
}



static int
dissect_h245_T_mediaChannel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 900 "../../asn1/h245/h245.cnf"
  if (upcoming_channel)
    upcoming_channel->upcoming_addr = &upcoming_channel->media_addr;

  offset = dissect_h245_TransportAddress(tvb, offset, actx, tree, hf_index);

#line 904 "../../asn1/h245/h245.cnf"
  if (upcoming_channel)
    upcoming_channel->upcoming_addr = NULL;

  return offset;
}



static int
dissect_h245_T_mediaControlChannel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 918 "../../asn1/h245/h245.cnf"
  if (upcoming_channel)
    upcoming_channel->upcoming_addr = &upcoming_channel->media_control_addr;

  offset = dissect_h245_TransportAddress(tvb, offset, actx, tree, hf_index);

#line 922 "../../asn1/h245/h245.cnf"
  if (upcoming_channel)
    upcoming_channel->upcoming_addr = NULL;

  return offset;
}



static int
dissect_h245_McuNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 192U, NULL, FALSE);

  return offset;
}



static int
dissect_h245_TerminalNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 192U, NULL, FALSE);

  return offset;
}


static const per_sequence_t TerminalLabel_sequence[] = {
  { &hf_h245_mcuNumber      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_McuNumber },
  { &hf_h245_terminalNumber , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_TerminalNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_TerminalLabel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_TerminalLabel, TerminalLabel_sequence);

  return offset;
}


static const value_string h245_T_mediaPacketization_vals[] = {
  {   0, "h261aVideoPacketization" },
  {   1, "rtpPayloadType" },
  { 0, NULL }
};

static const per_choice_t T_mediaPacketization_choice[] = {
  {   0, &hf_h245_h261aVideoPacketizationFlag, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_rtpPayloadType , ASN1_NOT_EXTENSION_ROOT, dissect_h245_RTPPayloadType },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_mediaPacketization(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_mediaPacketization, T_mediaPacketization_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t H2250LogicalChannelParameters_sequence[] = {
  { &hf_h245_nonStandardParams, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_SEQUENCE_OF_NonStandardParameter },
  { &hf_h245_sessionID_0_255, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_255 },
  { &hf_h245_associatedSessionID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_255 },
  { &hf_h245_mediaChannel   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_T_mediaChannel },
  { &hf_h245_mediaGuaranteedDelivery, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_BOOLEAN },
  { &hf_h245_mediaControlChannel, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_T_mediaControlChannel },
  { &hf_h245_mediaControlGuaranteedDelivery, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_BOOLEAN },
  { &hf_h245_silenceSuppression, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_BOOLEAN },
  { &hf_h245_destination    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_TerminalLabel },
  { &hf_h245_dynamicRTPPayloadType, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_96_127 },
  { &hf_h245_mediaPacketization, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_T_mediaPacketization },
  { &hf_h245_transportCapability, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_TransportCapability },
  { &hf_h245_redundancyEncoding, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_RedundancyEncoding },
  { &hf_h245_source         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_TerminalLabel },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H2250LogicalChannelParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H2250LogicalChannelParameters, H2250LogicalChannelParameters_sequence);

  return offset;
}


static const value_string h245_OLC_forw_multiplexParameters_vals[] = {
  {   0, "h222LogicalChannelParameters" },
  {   1, "h223LogicalChannelParameters" },
  {   2, "v76LogicalChannelParameters" },
  {   3, "h2250LogicalChannelParameters" },
  {   4, "none" },
  { 0, NULL }
};

static const per_choice_t OLC_forw_multiplexParameters_choice[] = {
  {   0, &hf_h245_h222LogicalChannelParameters, ASN1_EXTENSION_ROOT    , dissect_h245_H222LogicalChannelParameters },
  {   1, &hf_h245_olc_fw_h223_params, ASN1_EXTENSION_ROOT    , dissect_h245_OLC_fw_h223_params },
  {   2, &hf_h245_v76LogicalChannelParameters, ASN1_EXTENSION_ROOT    , dissect_h245_V76LogicalChannelParameters },
  {   3, &hf_h245_h2250LogicalChannelParameters, ASN1_NOT_EXTENSION_ROOT, dissect_h245_H2250LogicalChannelParameters },
  {   4, &hf_h245_none           , ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_OLC_forw_multiplexParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_OLC_forw_multiplexParameters, OLC_forw_multiplexParameters_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_forwardLogicalChannelParameters_sequence[] = {
  { &hf_h245_portNumber     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_65535 },
  { &hf_h245_dataType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_DataType },
  { &hf_h245_olc_forw_multiplexParameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_OLC_forw_multiplexParameters },
  { &hf_h245_forwardLogicalChannelDependency, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_LogicalChannelNumber },
  { &hf_h245_replacementFor , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_LogicalChannelNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_forwardLogicalChannelParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 169 "../../asn1/h245/h245.cnf"

  upcoming_channel = (upcoming_olc) ? &upcoming_olc->fwd_lc : NULL;

  h245_lc_dissector = NULL;
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_forwardLogicalChannelParameters, T_forwardLogicalChannelParameters_sequence);

  if(h223_lc_params_temp && h245_lc_dissector)
	h223_lc_params_temp->subdissector = h245_lc_dissector;
  else if(h223_lc_params_temp)
	h223_lc_params_temp->subdissector = data_handle;

  if (upcoming_channel && codec_type) {
    g_strlcpy(upcoming_channel->data_type_str, codec_type, sizeof(upcoming_channel->data_type_str));
  }
  upcoming_channel = NULL;


  return offset;
}



static int
dissect_h245_OLC_rev_h223_params(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 207 "../../asn1/h245/h245.cnf"
  h223_rev_lc_params = se_alloc(sizeof(h223_lc_params));
  h223_rev_lc_params->al_type = al_nonStandard;
  h223_rev_lc_params->al_params = NULL;
  h223_rev_lc_params->segmentable = 0;
  h223_rev_lc_params->subdissector = NULL;
  h223_lc_params_temp = h223_rev_lc_params;

  offset = dissect_h245_H223LogicalChannelParameters(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string h245_OLC_rev_multiplexParameters_vals[] = {
  {   0, "h223LogicalChannelParameters" },
  {   1, "v76LogicalChannelParameters" },
  {   2, "h2250LogicalChannelParameters" },
  { 0, NULL }
};

static const per_choice_t OLC_rev_multiplexParameters_choice[] = {
  {   0, &hf_h245_olc_rev_h223_params, ASN1_EXTENSION_ROOT    , dissect_h245_OLC_rev_h223_params },
  {   1, &hf_h245_v76LogicalChannelParameters, ASN1_EXTENSION_ROOT    , dissect_h245_V76LogicalChannelParameters },
  {   2, &hf_h245_h2250LogicalChannelParameters, ASN1_NOT_EXTENSION_ROOT, dissect_h245_H2250LogicalChannelParameters },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_OLC_rev_multiplexParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_OLC_rev_multiplexParameters, OLC_rev_multiplexParameters_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t OLC_reverseLogicalChannelParameters_sequence[] = {
  { &hf_h245_dataType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_DataType },
  { &hf_h245_olc_rev_multiplexParameter, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_OLC_rev_multiplexParameters },
  { &hf_h245_reverseLogicalChannelDependency, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_LogicalChannelNumber },
  { &hf_h245_replacementFor , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_LogicalChannelNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_OLC_reverseLogicalChannelParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 195 "../../asn1/h245/h245.cnf"

  upcoming_channel = (upcoming_olc) ? &upcoming_olc->rev_lc : NULL;

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_OLC_reverseLogicalChannelParameters, OLC_reverseLogicalChannelParameters_sequence);

	
  if (upcoming_channel && codec_type) {
    g_strlcpy(upcoming_channel->data_type_str, codec_type, sizeof(upcoming_channel->data_type_str));
  }
  upcoming_channel = NULL;


  return offset;
}


static const value_string h245_T_distribution_vals[] = {
  {   0, "unicast" },
  {   1, "multicast" },
  { 0, NULL }
};

static const per_choice_t T_distribution_choice[] = {
  {   0, &hf_h245_unicast        , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_multicast      , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_distribution(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_distribution, T_distribution_choice,
                                 NULL);

  return offset;
}



static int
dissect_h245_T_e164Address(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,
                                                      1, 128, FALSE, "0123456789#*,", 13,
                                                      NULL);

  return offset;
}


static const value_string h245_T_networkAddress_vals[] = {
  {   0, "q2931Address" },
  {   1, "e164Address" },
  {   2, "localAreaAddress" },
  { 0, NULL }
};

static const per_choice_t T_networkAddress_choice[] = {
  {   0, &hf_h245_q2931Address   , ASN1_EXTENSION_ROOT    , dissect_h245_Q2931Address },
  {   1, &hf_h245_e164Address    , ASN1_EXTENSION_ROOT    , dissect_h245_T_e164Address },
  {   2, &hf_h245_localAreaAddress, ASN1_EXTENSION_ROOT    , dissect_h245_TransportAddress },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_networkAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_networkAddress, T_networkAddress_choice,
                                 NULL);

  return offset;
}



static int
dissect_h245_OCTET_STRING_SIZE_1_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 255, FALSE, NULL);

  return offset;
}


static const value_string h245_T_t120SetupProcedure_vals[] = {
  {   0, "originateCall" },
  {   1, "waitForCall" },
  {   2, "issueQuery" },
  { 0, NULL }
};

static const per_choice_t T_t120SetupProcedure_choice[] = {
  {   0, &hf_h245_originateCall  , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_waitForCall    , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_issueQuery     , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_t120SetupProcedure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_t120SetupProcedure, T_t120SetupProcedure_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t NetworkAccessParameters_sequence[] = {
  { &hf_h245_distribution   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_T_distribution },
  { &hf_h245_networkAddress , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_networkAddress },
  { &hf_h245_associateConference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_externalReference, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_OCTET_STRING_SIZE_1_255 },
  { &hf_h245_t120SetupProcedure, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_T_t120SetupProcedure },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_NetworkAccessParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_NetworkAccessParameters, NetworkAccessParameters_sequence);

  return offset;
}



static int
dissect_h245_OCTET_STRING_SIZE_1_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 65535, FALSE, NULL);

  return offset;
}



static int
dissect_h245_BIT_STRING_SIZE_1_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 65535, FALSE, NULL);

  return offset;
}


static const per_sequence_t EscrowData_sequence[] = {
  { &hf_h245_escrowID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_OBJECT_IDENTIFIER },
  { &hf_h245_escrowValue    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BIT_STRING_SIZE_1_65535 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_EscrowData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_EscrowData, EscrowData_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_256_OF_EscrowData_sequence_of[1] = {
  { &hf_h245_escrowentry_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_EscrowData },
};

static int
dissect_h245_SEQUENCE_SIZE_1_256_OF_EscrowData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h245_SEQUENCE_SIZE_1_256_OF_EscrowData, SEQUENCE_SIZE_1_256_OF_EscrowData_sequence_of,
                                                  1, 256, FALSE);

  return offset;
}


static const per_sequence_t EncryptionSync_sequence[] = {
  { &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_NonStandardParameter },
  { &hf_h245_synchFlag      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_255 },
  { &hf_h245_h235Key        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_OCTET_STRING_SIZE_1_65535 },
  { &hf_h245_escrowentry    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_SEQUENCE_SIZE_1_256_OF_EscrowData },
  { &hf_h245_genericParameter, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_GenericParameter },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_EncryptionSync(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 708 "../../asn1/h245/h245.cnf"
  void *priv_data = actx->private_data;
  actx->private_data = gef_ctx_alloc(NULL, "EncryptionSync");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_EncryptionSync, EncryptionSync_sequence);

#line 711 "../../asn1/h245/h245.cnf"
  actx->private_data = priv_data;

  return offset;
}


static const per_sequence_t OpenLogicalChannel_sequence[] = {
  { &hf_h245_olc_fw_lcn     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_OLC_fw_lcn },
  { &hf_h245_forwardLogicalChannelParameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_forwardLogicalChannelParameters },
  { &hf_h245_reverseLogicalChannelParameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_OLC_reverseLogicalChannelParameters },
  { &hf_h245_separateStack  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_NetworkAccessParameters },
  { &hf_h245_encryptionSync , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_EncryptionSync },
  { &hf_h245_genericInformation, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_SEQUENCE_OF_GenericInformation },
  { NULL, 0, 0, NULL }
};

int
dissect_h245_OpenLogicalChannel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 130 "../../asn1/h245/h245.cnf"
  gint32 temp;

  upcoming_olc = (!actx->pinfo->fd->flags.visited) ? se_alloc0(sizeof(olc_info_t)) : NULL;

  h223_fw_lc_num = 0;
  h223_lc_params_temp = NULL;

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_OpenLogicalChannel, OpenLogicalChannel_sequence);


  if(h223_fw_lc_num != 0 && h223_fw_lc_params) {
	h223_pending_olc *pending = se_alloc(sizeof(h223_pending_olc));
	pending->fw_channel_params = h223_fw_lc_params;
	pending->rev_channel_params = h223_rev_lc_params;
	temp = h223_fw_lc_num;
	if (actx->pinfo->p2p_dir > -1)
		g_hash_table_insert(h223_pending_olc_reqs[actx->pinfo->p2p_dir], GINT_TO_POINTER(temp), pending);
  }

  if (upcoming_olc) {
    if (fast_start) {
      h245_setup_channels(actx->pinfo, &upcoming_olc->rev_lc);
    } else {
      g_hash_table_insert(h245_pending_olc_reqs, 
        se_strdup(gen_olc_key(upcoming_olc->fwd_lc_num, &actx->pinfo->dst, &actx->pinfo->src)), 
        upcoming_olc);
    }
  }
  upcoming_olc = NULL;

  if (h245_pi != NULL)
    h245_pi->msg_type = H245_OpenLogChn;


  return offset;
}


static const value_string h245_T_cLC_source_vals[] = {
  {   0, "user" },
  {   1, "lcse" },
  { 0, NULL }
};

static const per_choice_t T_cLC_source_choice[] = {
  {   0, &hf_h245_user           , ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   1, &hf_h245_lcse           , ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_cLC_source(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_cLC_source, T_cLC_source_choice,
                                 NULL);

  return offset;
}


static const value_string h245_Clc_reason_vals[] = {
  {   0, "unknown" },
  {   1, "reopen" },
  {   2, "reservationFailure" },
  {   3, "networkErrorCode" },
  { 0, NULL }
};

static const per_choice_t Clc_reason_choice[] = {
  {   0, &hf_h245_unknown        , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_reopen         , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_reservationFailure, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   3, &hf_h245_networkErrorCode, ASN1_NOT_EXTENSION_ROOT, dissect_h245_INTEGER_0_255 },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_Clc_reason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_Clc_reason, Clc_reason_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CloseLogicalChannel_sequence[] = {
  { &hf_h245_forwardLogicalChannelNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_LogicalChannelNumber },
  { &hf_h245_cLC_source     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_cLC_source },
  { &hf_h245_clc_reason     , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_h245_Clc_reason },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_CloseLogicalChannel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_CloseLogicalChannel, CloseLogicalChannel_sequence);

#line 549 "../../asn1/h245/h245.cnf"

if (h245_pi != NULL)
  h245_pi->msg_type = H245_CloseLogChn;

  return offset;
}


static const value_string h245_T_reason_vals[] = {
  {   0, "unknown" },
  {   1, "normal" },
  {   2, "reopen" },
  {   3, "reservationFailure" },
  {   4, "networkErrorCode" },
  { 0, NULL }
};

static const per_choice_t T_reason_choice[] = {
  {   0, &hf_h245_unknown        , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_normal         , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_reopen         , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   3, &hf_h245_reservationFailure, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   4, &hf_h245_networkErrorCode, ASN1_NOT_EXTENSION_ROOT, dissect_h245_INTEGER_0_255 },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_reason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_reason, T_reason_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RequestChannelClose_sequence[] = {
  { &hf_h245_forwardLogicalChannelNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_LogicalChannelNumber },
  { &hf_h245_qosCapability  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_QOSCapability },
  { &hf_h245_reason         , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_h245_T_reason },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RequestChannelClose(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RequestChannelClose, RequestChannelClose_sequence);

  return offset;
}



static int
dissect_h245_MultiplexTableEntryNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 66 "../../asn1/h245/h245.cnf"
  guint32 value;
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 15U, &value, FALSE);

  h223_mc = value & 0xf;


  return offset;
}



static int
dissect_h245_T_logicalChannelNum(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 93 "../../asn1/h245/h245.cnf"
  /*MultiplexElement/type/logicalChannelNumber*/
  guint32 value;
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &value, FALSE);

  h223_me->sublist = NULL;
  h223_me->vc = value & 0xffff;


  return offset;
}


static const per_sequence_t T_subElementList_sequence_of[1] = {
  { &hf_h245_subElementList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_MultiplexElement },
};

static int
dissect_h245_T_subElementList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 101 "../../asn1/h245/h245.cnf"
  h223_mux_element dummy_me, *parent_me = h223_me;
  memset (&dummy_me, 0, sizeof (h223_mux_element));
  h223_me = &dummy_me;
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h245_T_subElementList, T_subElementList_sequence_of,
                                                  2, 255, FALSE);

  parent_me->sublist = dummy_me.next;
  h223_me = parent_me;
  h223_me->vc = 0;


  return offset;
}


static const value_string h245_Me_type_vals[] = {
  {   0, "logicalChannelNumber" },
  {   1, "subElementList" },
  { 0, NULL }
};

static const per_choice_t Me_type_choice[] = {
  {   0, &hf_h245_logicalChannelNum, ASN1_NO_EXTENSIONS     , dissect_h245_T_logicalChannelNum },
  {   1, &hf_h245_subElementList , ASN1_NO_EXTENSIONS     , dissect_h245_T_subElementList },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_Me_type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_Me_type, Me_type_choice,
                                 NULL);

  return offset;
}



static int
dissect_h245_ME_finiteRepeatCount(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 117 "../../asn1/h245/h245.cnf"
  guint32 value;
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, &value, FALSE);

  h223_me->repeat_count = value & 0xffff;


  return offset;
}



static int
dissect_h245_T_untilClosingFlag(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

#line 111 "../../asn1/h245/h245.cnf"
  h223_me->repeat_count = 0;

  return offset;
}


static const value_string h245_ME_repeatCount_vals[] = {
  {   0, "finite" },
  {   1, "untilClosingFlag" },
  { 0, NULL }
};

static const per_choice_t ME_repeatCount_choice[] = {
  {   0, &hf_h245_me_repeatCount_finite, ASN1_NO_EXTENSIONS     , dissect_h245_ME_finiteRepeatCount },
  {   1, &hf_h245_untilClosingFlag, ASN1_NO_EXTENSIONS     , dissect_h245_T_untilClosingFlag },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_ME_repeatCount(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_ME_repeatCount, ME_repeatCount_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MultiplexElement_sequence[] = {
  { &hf_h245_me_type        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_Me_type },
  { &hf_h245_me_repeatCount , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_ME_repeatCount },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MultiplexElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 83 "../../asn1/h245/h245.cnf"
  /*MultiplexElement*/
  h223_mux_element* me = se_alloc(sizeof(h223_mux_element));
  h223_me->next = me;
  h223_me = me;
  h223_me->next = NULL;

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MultiplexElement, MultiplexElement_sequence);

  return offset;
}


static const per_sequence_t T_elementList_sequence_of[1] = {
  { &hf_h245_elementList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_MultiplexElement },
};

static int
dissect_h245_T_elementList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 72 "../../asn1/h245/h245.cnf"
  /* create a h223_mux_element to hold onto the head of the list, since
   * h223_me will track the tail */
  h223_mux_element dummy_me;
  memset (&dummy_me, 0, sizeof (h223_mux_element));
  h223_me = &dummy_me;
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h245_T_elementList, T_elementList_sequence_of,
                                                  1, 256, FALSE);

  /* set h223_me to the head of the list for MEDescriptor to pick up */
  h223_me = dummy_me.next;


  return offset;
}


static const per_sequence_t MultiplexEntryDescriptor_sequence[] = {
  { &hf_h245_multiplexTableEntryNumber, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_MultiplexTableEntryNumber },
  { &hf_h245_elementList    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_h245_T_elementList },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MultiplexEntryDescriptor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 54 "../../asn1/h245/h245.cnf"
  /*MultiplexEntryDescriptor*/
  h223_me = NULL;
  h223_mc = 0;
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MultiplexEntryDescriptor, MultiplexEntryDescriptor_sequence);

  if(h223_set_mc_handle)
    (*h223_set_mc_handle)(actx->pinfo, h223_mc, h223_me);
 /* stuff */


  return offset;
}


static const per_sequence_t SET_SIZE_1_15_OF_MultiplexEntryDescriptor_set_of[1] = {
  { &hf_h245_multiplexEntryDescriptors_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_MultiplexEntryDescriptor },
};

static int
dissect_h245_SET_SIZE_1_15_OF_MultiplexEntryDescriptor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h245_SET_SIZE_1_15_OF_MultiplexEntryDescriptor, SET_SIZE_1_15_OF_MultiplexEntryDescriptor_set_of,
                                             1, 15, FALSE);

  return offset;
}


static const per_sequence_t MultiplexEntrySend_sequence[] = {
  { &hf_h245_sequenceNumber , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SequenceNumber },
  { &hf_h245_multiplexEntryDescriptors, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SET_SIZE_1_15_OF_MultiplexEntryDescriptor },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MultiplexEntrySend(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MultiplexEntrySend, MultiplexEntrySend_sequence);

  return offset;
}


static const per_sequence_t SET_SIZE_1_15_OF_MultiplexTableEntryNumber_set_of[1] = {
  { &hf_h245_multiplexTableEntryNumbers_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_MultiplexTableEntryNumber },
};

static int
dissect_h245_SET_SIZE_1_15_OF_MultiplexTableEntryNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h245_SET_SIZE_1_15_OF_MultiplexTableEntryNumber, SET_SIZE_1_15_OF_MultiplexTableEntryNumber_set_of,
                                             1, 15, FALSE);

  return offset;
}


static const per_sequence_t RequestMultiplexEntry_sequence[] = {
  { &hf_h245_entryNumbers   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SET_SIZE_1_15_OF_MultiplexTableEntryNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RequestMultiplexEntry(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RequestMultiplexEntry, RequestMultiplexEntry_sequence);

  return offset;
}


static const value_string h245_H261Resolution_vals[] = {
  {   0, "qcif" },
  {   1, "cif" },
  { 0, NULL }
};

static const per_choice_t H261Resolution_choice[] = {
  {   0, &hf_h245_qcif           , ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   1, &hf_h245_cif            , ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_H261Resolution(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_H261Resolution, H261Resolution_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t H261VideoMode_sequence[] = {
  { &hf_h245_h261_resolution, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_H261Resolution },
  { &hf_h245_bitRate_1_19200, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_19200 },
  { &hf_h245_stillImageTransmission, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H261VideoMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H261VideoMode, H261VideoMode_sequence);

  return offset;
}


static const value_string h245_T_profileAndLevel_vals[] = {
  {   0, "profileAndLevel-SPatML" },
  {   1, "profileAndLevel-MPatLL" },
  {   2, "profileAndLevel-MPatML" },
  {   3, "profileAndLevel-MPatH-14" },
  {   4, "profileAndLevel-MPatHL" },
  {   5, "profileAndLevel-SNRatLL" },
  {   6, "profileAndLevel-SNRatML" },
  {   7, "profileAndLevel-SpatialatH-14" },
  {   8, "profileAndLevel-HPatML" },
  {   9, "profileAndLevel-HPatH-14" },
  {  10, "profileAndLevel-HPatHL" },
  { 0, NULL }
};

static const per_choice_t T_profileAndLevel_choice[] = {
  {   0, &hf_h245_profileAndLevel_SPatMLMode, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_profileAndLevel_MPatLLMode, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_profileAndLevel_MPatMLMode, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   3, &hf_h245_profileAndLevel_MPatH_14Mode, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   4, &hf_h245_profileAndLevel_MPatHLMode, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   5, &hf_h245_profileAndLevel_SNRatLLMode, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   6, &hf_h245_profileAndLevel_SNRatMLMode, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   7, &hf_h245_profileAndLevel_SpatialatH_14Mode, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   8, &hf_h245_profileAndLevel_HPatMLMode, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   9, &hf_h245_profileAndLevel_HPatH_14Mode, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {  10, &hf_h245_profileAndLevel_HPatHLMode, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_profileAndLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_profileAndLevel, T_profileAndLevel_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t H262VideoMode_sequence[] = {
  { &hf_h245_profileAndLevel, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_profileAndLevel },
  { &hf_h245_videoBitRate   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_1073741823 },
  { &hf_h245_vbvBufferSize  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_262143 },
  { &hf_h245_samplesPerLine , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_16383 },
  { &hf_h245_linesPerFrame  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_16383 },
  { &hf_h245_framesPerSecond, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_15 },
  { &hf_h245_luminanceSampleRate, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_4294967295 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H262VideoMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H262VideoMode, H262VideoMode_sequence);

  return offset;
}


static const value_string h245_H263Resolution_vals[] = {
  {   0, "sqcif" },
  {   1, "qcif" },
  {   2, "cif" },
  {   3, "cif4" },
  {   4, "cif16" },
  {   5, "custom" },
  { 0, NULL }
};

static const per_choice_t H263Resolution_choice[] = {
  {   0, &hf_h245_sqcif          , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_qcif           , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_cif            , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   3, &hf_h245_cif4           , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   4, &hf_h245_cif16          , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   5, &hf_h245_custom_res     , ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_H263Resolution(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_H263Resolution, H263Resolution_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t H263VideoMode_sequence[] = {
  { &hf_h245_h263_resolution, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_H263Resolution },
  { &hf_h245_bitRate_1_19200, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_19200 },
  { &hf_h245_unrestrictedVector, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_arithmeticCoding, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_advancedPrediction, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_pbFrames       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_errorCompensation, ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_enhancementLayerInfo, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_EnhancementLayerInfo },
  { &hf_h245_h263Options    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_H263Options },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H263VideoMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H263VideoMode, H263VideoMode_sequence);

  return offset;
}


static const per_sequence_t IS11172VideoMode_sequence[] = {
  { &hf_h245_constrainedBitstream, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_videoBitRate   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_1073741823 },
  { &hf_h245_vbvBufferSize  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_262143 },
  { &hf_h245_samplesPerLine , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_16383 },
  { &hf_h245_linesPerFrame  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_16383 },
  { &hf_h245_pictureRate    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_15 },
  { &hf_h245_luminanceSampleRate, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_4294967295 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_IS11172VideoMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_IS11172VideoMode, IS11172VideoMode_sequence);

  return offset;
}


static const value_string h245_VideoMode_vals[] = {
  {   0, "nonStandard" },
  {   1, "h261VideoMode" },
  {   2, "h262VideoMode" },
  {   3, "h263VideoMode" },
  {   4, "is11172VideoMode" },
  {   5, "genericVideoMode" },
  { 0, NULL }
};

static const per_choice_t VideoMode_choice[] = {
  {   0, &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardParameter },
  {   1, &hf_h245_h261VideoMode  , ASN1_EXTENSION_ROOT    , dissect_h245_H261VideoMode },
  {   2, &hf_h245_h262VideoMode  , ASN1_EXTENSION_ROOT    , dissect_h245_H262VideoMode },
  {   3, &hf_h245_h263VideoMode  , ASN1_EXTENSION_ROOT    , dissect_h245_H263VideoMode },
  {   4, &hf_h245_is11172VideoMode, ASN1_EXTENSION_ROOT    , dissect_h245_IS11172VideoMode },
  {   5, &hf_h245_genericVideoMode, ASN1_NOT_EXTENSION_ROOT, dissect_h245_GenericCapability },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_VideoMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 517 "../../asn1/h245/h245.cnf"
  gint32 value;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_VideoMode, VideoMode_choice,
                                 &value);

  codec_type = val_to_str(value, h245_VideoMode_vals, "<unknown>");


  return offset;
}


static const value_string h245_Mode_g7231_vals[] = {
  {   0, "noSilenceSuppressionLowRate" },
  {   1, "noSilenceSuppressionHighRate" },
  {   2, "silenceSuppressionLowRate" },
  {   3, "silenceSuppressionHighRate" },
  { 0, NULL }
};

static const per_choice_t Mode_g7231_choice[] = {
  {   0, &hf_h245_noSilenceSuppressionLowRate, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   1, &hf_h245_noSilenceSuppressionHighRate, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   2, &hf_h245_silenceSuppressionLowRate, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   3, &hf_h245_silenceSuppressionHighRate, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_Mode_g7231(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_Mode_g7231, Mode_g7231_choice,
                                 NULL);

  return offset;
}


static const value_string h245_T_audioLayer_vals[] = {
  {   0, "audioLayer1" },
  {   1, "audioLayer2" },
  {   2, "audioLayer3" },
  { 0, NULL }
};

static const per_choice_t T_audioLayer_choice[] = {
  {   0, &hf_h245_audioLayer1Mode, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   1, &hf_h245_audioLayer2Mode, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   2, &hf_h245_audioLayer3Mode, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_audioLayer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_audioLayer, T_audioLayer_choice,
                                 NULL);

  return offset;
}


static const value_string h245_T_audioSampling_vals[] = {
  {   0, "audioSampling32k" },
  {   1, "audioSampling44k1" },
  {   2, "audioSampling48k" },
  { 0, NULL }
};

static const per_choice_t T_audioSampling_choice[] = {
  {   0, &hf_h245_audioSampling32kMode, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   1, &hf_h245_audioSampling44k1Mode, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   2, &hf_h245_audioSampling48kMode, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_audioSampling(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_audioSampling, T_audioSampling_choice,
                                 NULL);

  return offset;
}


static const value_string h245_IS11172_multichannelType_vals[] = {
  {   0, "singleChannel" },
  {   1, "twoChannelStereo" },
  {   2, "twoChannelDual" },
  { 0, NULL }
};

static const per_choice_t IS11172_multichannelType_choice[] = {
  {   0, &hf_h245_singleChannelMode, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   1, &hf_h245_twoChannelStereo, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   2, &hf_h245_twoChannelDual , ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_IS11172_multichannelType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_IS11172_multichannelType, IS11172_multichannelType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t IS11172AudioMode_sequence[] = {
  { &hf_h245_audioLayer     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_audioLayer },
  { &hf_h245_audioSampling  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_audioSampling },
  { &hf_h245_is11172multichannelType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_IS11172_multichannelType },
  { &hf_h245_bitRate_1_448  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_448 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_IS11172AudioMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_IS11172AudioMode, IS11172AudioMode_sequence);

  return offset;
}


static const value_string h245_IS13818AudioLayer_vals[] = {
  {   0, "audioLayer1" },
  {   1, "audioLayer2" },
  {   2, "audioLayer3" },
  { 0, NULL }
};

static const per_choice_t IS13818AudioLayer_choice[] = {
  {   0, &hf_h245_audioLayer1Mode, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   1, &hf_h245_audioLayer2Mode, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   2, &hf_h245_audioLayer3Mode, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_IS13818AudioLayer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_IS13818AudioLayer, IS13818AudioLayer_choice,
                                 NULL);

  return offset;
}


static const value_string h245_IS13818AudioSampling_vals[] = {
  {   0, "audioSampling16k" },
  {   1, "audioSampling22k05" },
  {   2, "audioSampling24k" },
  {   3, "audioSampling32k" },
  {   4, "audioSampling44k1" },
  {   5, "audioSampling48k" },
  { 0, NULL }
};

static const per_choice_t IS13818AudioSampling_choice[] = {
  {   0, &hf_h245_audioSampling16kMode, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   1, &hf_h245_audioSampling22k05Mode, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   2, &hf_h245_audioSampling24kMode, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   3, &hf_h245_audioSampling32kMode, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   4, &hf_h245_audioSampling44k1Mode, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   5, &hf_h245_audioSampling48kMode, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_IS13818AudioSampling(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_IS13818AudioSampling, IS13818AudioSampling_choice,
                                 NULL);

  return offset;
}


static const value_string h245_IS13818MultichannelType_vals[] = {
  {   0, "singleChannel" },
  {   1, "twoChannelStereo" },
  {   2, "twoChannelDual" },
  {   3, "threeChannels2-1" },
  {   4, "threeChannels3-0" },
  {   5, "fourChannels2-0-2-0" },
  {   6, "fourChannels2-2" },
  {   7, "fourChannels3-1" },
  {   8, "fiveChannels3-0-2-0" },
  {   9, "fiveChannels3-2" },
  { 0, NULL }
};

static const per_choice_t IS13818MultichannelType_choice[] = {
  {   0, &hf_h245_singleChannelMode, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   1, &hf_h245_twoChannelStereo, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   2, &hf_h245_twoChannelDual , ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   3, &hf_h245_threeChannels2_1Mode, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   4, &hf_h245_threeChannels3_0Mode, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   5, &hf_h245_fourChannels2_0_2_0Mode, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   6, &hf_h245_fourChannels2_2Mode, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   7, &hf_h245_fourChannels3_1Mode, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   8, &hf_h245_fiveChannels3_0_2_0Mode, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   9, &hf_h245_fiveChannels3_2Mode, ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_IS13818MultichannelType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_IS13818MultichannelType, IS13818MultichannelType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t IS13818AudioMode_sequence[] = {
  { &hf_h245_audioLayerMode , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_IS13818AudioLayer },
  { &hf_h245_audioSamplingMode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_IS13818AudioSampling },
  { &hf_h245_is13818MultichannelType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_IS13818MultichannelType },
  { &hf_h245_lowFrequencyEnhancement, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_multilingual   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_bitRate2_1_1130, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_1130 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_IS13818AudioMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_IS13818AudioMode, IS13818AudioMode_sequence);

  return offset;
}


static const per_sequence_t G7231AnnexCMode_sequence[] = {
  { &hf_h245_maxAl_sduAudioFrames, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_256 },
  { &hf_h245_silenceSuppression, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_g723AnnexCAudioMode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_G723AnnexCAudioMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_G7231AnnexCMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_G7231AnnexCMode, G7231AnnexCMode_sequence);

  return offset;
}


static const per_sequence_t VBDMode_sequence[] = {
  { &hf_h245_vbd_type       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_AudioMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_VBDMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_VBDMode, VBDMode_sequence);

  return offset;
}


static const value_string h245_AudioMode_vals[] = {
  {   0, "nonStandard" },
  {   1, "g711Alaw64k" },
  {   2, "g711Alaw56k" },
  {   3, "g711Ulaw64k" },
  {   4, "g711Ulaw56k" },
  {   5, "g722-64k" },
  {   6, "g722-56k" },
  {   7, "g722-48k" },
  {   8, "g728" },
  {   9, "g729" },
  {  10, "g729AnnexA" },
  {  11, "g7231" },
  {  12, "is11172AudioMode" },
  {  13, "is13818AudioMode" },
  {  14, "g729wAnnexB" },
  {  15, "g729AnnexAwAnnexB" },
  {  16, "g7231AnnexCMode" },
  {  17, "gsmFullRate" },
  {  18, "gsmHalfRate" },
  {  19, "gsmEnhancedFullRate" },
  {  20, "genericAudioMode" },
  {  21, "g729Extensions" },
  {  22, "vbd" },
  { 0, NULL }
};

static const per_choice_t AudioMode_choice[] = {
  {   0, &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardParameter },
  {   1, &hf_h245_g711Alaw64k_mode, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_g711Alaw56k_mode, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   3, &hf_h245_g711Ulaw64k_mode, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   4, &hf_h245_g711Ulaw56k_mode, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   5, &hf_h245_g722_64k_mode  , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   6, &hf_h245_g722_56k_mode  , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   7, &hf_h245_g722_48k_mode  , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   8, &hf_h245_g728_mode      , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   9, &hf_h245_g729_mode      , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {  10, &hf_h245_g729AnnexA_mode, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {  11, &hf_h245_g7231_mode     , ASN1_EXTENSION_ROOT    , dissect_h245_Mode_g7231 },
  {  12, &hf_h245_is11172AudioMode, ASN1_EXTENSION_ROOT    , dissect_h245_IS11172AudioMode },
  {  13, &hf_h245_is13818AudioMode, ASN1_EXTENSION_ROOT    , dissect_h245_IS13818AudioMode },
  {  14, &hf_h245_g729wAnnexB    , ASN1_NOT_EXTENSION_ROOT, dissect_h245_INTEGER_1_256 },
  {  15, &hf_h245_g729AnnexAwAnnexB, ASN1_NOT_EXTENSION_ROOT, dissect_h245_INTEGER_1_256 },
  {  16, &hf_h245_g7231AnnexCMode, ASN1_NOT_EXTENSION_ROOT, dissect_h245_G7231AnnexCMode },
  {  17, &hf_h245_gsmFullRate    , ASN1_NOT_EXTENSION_ROOT, dissect_h245_GSMAudioCapability },
  {  18, &hf_h245_gsmHalfRate    , ASN1_NOT_EXTENSION_ROOT, dissect_h245_GSMAudioCapability },
  {  19, &hf_h245_gsmEnhancedFullRate, ASN1_NOT_EXTENSION_ROOT, dissect_h245_GSMAudioCapability },
  {  20, &hf_h245_genericAudioMode, ASN1_NOT_EXTENSION_ROOT, dissect_h245_GenericCapability },
  {  21, &hf_h245_g729Extensions , ASN1_NOT_EXTENSION_ROOT, dissect_h245_G729Extensions },
  {  22, &hf_h245_vbd_mode       , ASN1_NOT_EXTENSION_ROOT, dissect_h245_VBDMode },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_AudioMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 510 "../../asn1/h245/h245.cnf"
  gint32 value;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_AudioMode, AudioMode_choice,
                                 &value);

  codec_type = val_to_str(value, h245_AudioMode_vals, "<unknown>");


  return offset;
}


static const per_sequence_t T38faxApp_sequence[] = {
  { &hf_h245_t38FaxProtocol , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_DataProtocolCapability },
  { &hf_h245_t38FaxProfile  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_T38FaxProfile },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T38faxApp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T38faxApp, T38faxApp_sequence);

  return offset;
}


static const value_string h245_DataModeApplication_vals[] = {
  {   0, "nonStandard" },
  {   1, "t120" },
  {   2, "dsm-cc" },
  {   3, "userData" },
  {   4, "t84" },
  {   5, "t434" },
  {   6, "h224" },
  {   7, "nlpid" },
  {   8, "dsvdControl" },
  {   9, "h222DataPartitioning" },
  {  10, "t30fax" },
  {  11, "t140" },
  {  12, "t38fax" },
  {  13, "genericDataMode" },
  { 0, NULL }
};

static const per_choice_t DataModeApplication_choice[] = {
  {   0, &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardParameter },
  {   1, &hf_h245_t120           , ASN1_EXTENSION_ROOT    , dissect_h245_DataProtocolCapability },
  {   2, &hf_h245_dsm_cc         , ASN1_EXTENSION_ROOT    , dissect_h245_DataProtocolCapability },
  {   3, &hf_h245_userData       , ASN1_EXTENSION_ROOT    , dissect_h245_DataProtocolCapability },
  {   4, &hf_h245_t84DataProtocolCapability, ASN1_EXTENSION_ROOT    , dissect_h245_DataProtocolCapability },
  {   5, &hf_h245_t434           , ASN1_EXTENSION_ROOT    , dissect_h245_DataProtocolCapability },
  {   6, &hf_h245_h224           , ASN1_EXTENSION_ROOT    , dissect_h245_DataProtocolCapability },
  {   7, &hf_h245_nlpid          , ASN1_EXTENSION_ROOT    , dissect_h245_Nlpid },
  {   8, &hf_h245_dsvdControl    , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   9, &hf_h245_h222DataPartitioning, ASN1_EXTENSION_ROOT    , dissect_h245_DataProtocolCapability },
  {  10, &hf_h245_t30fax         , ASN1_NOT_EXTENSION_ROOT, dissect_h245_DataProtocolCapability },
  {  11, &hf_h245_t140           , ASN1_NOT_EXTENSION_ROOT, dissect_h245_DataProtocolCapability },
  {  12, &hf_h245_t38faxDataProtocolCapability, ASN1_NOT_EXTENSION_ROOT, dissect_h245_T38faxApp },
  {  13, &hf_h245_genericDataMode, ASN1_NOT_EXTENSION_ROOT, dissect_h245_GenericCapability },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_DataModeApplication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 524 "../../asn1/h245/h245.cnf"
  gint32 value;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_DataModeApplication, DataModeApplication_choice,
                                 &value);

  codec_type = val_to_str(value, h245_DataModeApplication_vals, "<unknown>");


  return offset;
}


static const per_sequence_t DataMode_sequence[] = {
  { &hf_h245_datamodeapplication, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_DataModeApplication },
  { &hf_h245_bitRate_0_4294967295, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_4294967295 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_DataMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_DataMode, DataMode_sequence);

  return offset;
}


static const value_string h245_T_mediaMode_vals[] = {
  {   0, "nonStandard" },
  {   1, "videoMode" },
  {   2, "audioMode" },
  {   3, "dataMode" },
  { 0, NULL }
};

static const per_choice_t T_mediaMode_choice[] = {
  {   0, &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardParameter },
  {   1, &hf_h245_videoMode      , ASN1_EXTENSION_ROOT    , dissect_h245_VideoMode },
  {   2, &hf_h245_audioMode      , ASN1_EXTENSION_ROOT    , dissect_h245_AudioMode },
  {   3, &hf_h245_dataMode       , ASN1_EXTENSION_ROOT    , dissect_h245_DataMode },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_mediaMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_mediaMode, T_mediaMode_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t H235Mode_sequence[] = {
  { &hf_h245_encryptionAuthenticationAndIntegrity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_EncryptionAuthenticationAndIntegrity },
  { &hf_h245_mediaMode      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_mediaMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H235Mode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H235Mode, H235Mode_sequence);

  return offset;
}


static const per_sequence_t FECMode_sequence[] = {
  { &hf_h245_protectedElement, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_ModeElementType },
  { &hf_h245_fecScheme      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_OBJECT_IDENTIFIER },
  { &hf_h245_rfc2733Format  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_Rfc2733Format },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_FECMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_FECMode, FECMode_sequence);

  return offset;
}


static const value_string h245_Re_type_vals[] = {
  {   0, "nonStandard" },
  {   1, "videoMode" },
  {   2, "audioMode" },
  {   3, "dataMode" },
  {   4, "encryptionMode" },
  {   5, "h235Mode" },
  {   6, "fecMode" },
  { 0, NULL }
};

static const per_choice_t Re_type_choice[] = {
  {   0, &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardParameter },
  {   1, &hf_h245_videoMode      , ASN1_EXTENSION_ROOT    , dissect_h245_VideoMode },
  {   2, &hf_h245_audioMode      , ASN1_EXTENSION_ROOT    , dissect_h245_AudioMode },
  {   3, &hf_h245_dataMode       , ASN1_EXTENSION_ROOT    , dissect_h245_DataMode },
  {   4, &hf_h245_encryptionMode , ASN1_EXTENSION_ROOT    , dissect_h245_EncryptionMode },
  {   5, &hf_h245_h235Mode       , ASN1_EXTENSION_ROOT    , dissect_h245_H235Mode },
  {   6, &hf_h245_fecMode        , ASN1_NOT_EXTENSION_ROOT, dissect_h245_FECMode },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_Re_type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_Re_type, Re_type_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RedundancyEncodingDTModeElement_sequence[] = {
  { &hf_h245_re_type        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_Re_type },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RedundancyEncodingDTModeElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RedundancyEncodingDTModeElement, RedundancyEncodingDTModeElement_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_RedundancyEncodingDTModeElement_sequence_of[1] = {
  { &hf_h245_secondaryDTM_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_RedundancyEncodingDTModeElement },
};

static int
dissect_h245_SEQUENCE_OF_RedundancyEncodingDTModeElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h245_SEQUENCE_OF_RedundancyEncodingDTModeElement, SEQUENCE_OF_RedundancyEncodingDTModeElement_sequence_of);

  return offset;
}


static const per_sequence_t RedundancyEncodingDTMode_sequence[] = {
  { &hf_h245_redundancyEncodingMethod, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_RedundancyEncodingMethod },
  { &hf_h245_prmary_dtmode  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_RedundancyEncodingDTModeElement },
  { &hf_h245_secondaryDTM   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SEQUENCE_OF_RedundancyEncodingDTModeElement },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RedundancyEncodingDTMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RedundancyEncodingDTMode, RedundancyEncodingDTMode_sequence);

  return offset;
}


static const per_sequence_t MultiplePayloadStreamElementMode_sequence[] = {
  { &hf_h245_type           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_ModeElementType },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MultiplePayloadStreamElementMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MultiplePayloadStreamElementMode, MultiplePayloadStreamElementMode_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_MultiplePayloadStreamElementMode_sequence_of[1] = {
  { &hf_h245_mpsmElements_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_MultiplePayloadStreamElementMode },
};

static int
dissect_h245_SEQUENCE_OF_MultiplePayloadStreamElementMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h245_SEQUENCE_OF_MultiplePayloadStreamElementMode, SEQUENCE_OF_MultiplePayloadStreamElementMode_sequence_of);

  return offset;
}


static const per_sequence_t MultiplePayloadStreamMode_sequence[] = {
  { &hf_h245_mpsmElements   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SEQUENCE_OF_MultiplePayloadStreamElementMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MultiplePayloadStreamMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MultiplePayloadStreamMode, MultiplePayloadStreamMode_sequence);

  return offset;
}


static const value_string h245_FEC_mode_vals[] = {
  {   0, "redundancyEncoding" },
  {   1, "separateStream" },
  { 0, NULL }
};

static const per_choice_t FEC_mode_choice[] = {
  {   0, &hf_h245_redundancyEncodingFlag, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_separateStream , ASN1_EXTENSION_ROOT    , dissect_h245_DepSeparateStream },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_FEC_mode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_FEC_mode, FEC_mode_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_rfc2733Mode_sequence[] = {
  { &hf_h245_fec_mode       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_FEC_mode },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_rfc2733Mode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_rfc2733Mode, T_rfc2733Mode_sequence);

  return offset;
}


static const value_string h245_DepFECMode_vals[] = {
  {   0, "rfc2733Mode" },
  { 0, NULL }
};

static const per_choice_t DepFECMode_choice[] = {
  {   0, &hf_h245_rfc2733Mode    , ASN1_EXTENSION_ROOT    , dissect_h245_T_rfc2733Mode },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_DepFECMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_DepFECMode, DepFECMode_choice,
                                 NULL);

  return offset;
}


static const value_string h245_ModeElementType_vals[] = {
  {   0, "nonStandard" },
  {   1, "videoMode" },
  {   2, "audioMode" },
  {   3, "dataMode" },
  {   4, "encryptionMode" },
  {   5, "h235Mode" },
  {   6, "multiplexedStreamMode" },
  {   7, "redundancyEncodingDTMode" },
  {   8, "multiplePayloadStreamMode" },
  {   9, "depFecMode" },
  {  10, "fecMode" },
  { 0, NULL }
};

static const per_choice_t ModeElementType_choice[] = {
  {   0, &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardParameter },
  {   1, &hf_h245_videoMode      , ASN1_EXTENSION_ROOT    , dissect_h245_VideoMode },
  {   2, &hf_h245_audioMode      , ASN1_EXTENSION_ROOT    , dissect_h245_AudioMode },
  {   3, &hf_h245_dataMode       , ASN1_EXTENSION_ROOT    , dissect_h245_DataMode },
  {   4, &hf_h245_encryptionMode , ASN1_EXTENSION_ROOT    , dissect_h245_EncryptionMode },
  {   5, &hf_h245_h235Mode       , ASN1_NOT_EXTENSION_ROOT, dissect_h245_H235Mode },
  {   6, &hf_h245_multiplexedStreamMode, ASN1_NOT_EXTENSION_ROOT, dissect_h245_MultiplexedStreamParameter },
  {   7, &hf_h245_redundancyEncodingDTMode, ASN1_NOT_EXTENSION_ROOT, dissect_h245_RedundancyEncodingDTMode },
  {   8, &hf_h245_multiplePayloadStreamMode, ASN1_NOT_EXTENSION_ROOT, dissect_h245_MultiplePayloadStreamMode },
  {   9, &hf_h245_depFecMode     , ASN1_NOT_EXTENSION_ROOT, dissect_h245_DepFECMode },
  {  10, &hf_h245_fecMode        , ASN1_NOT_EXTENSION_ROOT, dissect_h245_FECMode },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_ModeElementType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_ModeElementType, ModeElementType_choice,
                                 NULL);

  return offset;
}


static const value_string h245_AdaptationLayerType_vals[] = {
  {   0, "nonStandard" },
  {   1, "al1Framed" },
  {   2, "al1NotFramed" },
  {   3, "al2WithoutSequenceNumbers" },
  {   4, "al2WithSequenceNumbers" },
  {   5, "al3" },
  {   6, "al1M" },
  {   7, "al2M" },
  {   8, "al3M" },
  { 0, NULL }
};

static const per_choice_t AdaptationLayerType_choice[] = {
  {   0, &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardParameter },
  {   1, &hf_h245_al1Framed      , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_al1NotFramed   , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   3, &hf_h245_al2WithoutSequenceNumbers, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   4, &hf_h245_al2WithSequenceNumbers, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   5, &hf_h245_al3            , ASN1_EXTENSION_ROOT    , dissect_h245_Al3 },
  {   6, &hf_h245_al1M           , ASN1_NOT_EXTENSION_ROOT, dissect_h245_H223AL1MParameters },
  {   7, &hf_h245_al2M           , ASN1_NOT_EXTENSION_ROOT, dissect_h245_H223AL2MParameters },
  {   8, &hf_h245_al3M           , ASN1_NOT_EXTENSION_ROOT, dissect_h245_H223AL3MParameters },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_AdaptationLayerType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_AdaptationLayerType, AdaptationLayerType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t H223ModeParameters_sequence[] = {
  { &hf_h245_adaptationLayer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_AdaptationLayerType },
  { &hf_h245_segmentableFlag, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H223ModeParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H223ModeParameters, H223ModeParameters_sequence);

  return offset;
}


static const value_string h245_V76ModeParameters_vals[] = {
  {   0, "suspendResumewAddress" },
  {   1, "suspendResumewoAddress" },
  { 0, NULL }
};

static const per_choice_t V76ModeParameters_choice[] = {
  {   0, &hf_h245_suspendResumewAddress, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_suspendResumewoAddress, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_V76ModeParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_V76ModeParameters, V76ModeParameters_choice,
                                 NULL);

  return offset;
}


static const value_string h245_T_secondaryEncodingMode_vals[] = {
  {   0, "nonStandard" },
  {   1, "audioData" },
  { 0, NULL }
};

static const per_choice_t T_secondaryEncodingMode_choice[] = {
  {   0, &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardParameter },
  {   1, &hf_h245_audioMode      , ASN1_EXTENSION_ROOT    , dissect_h245_AudioMode },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_secondaryEncodingMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_secondaryEncodingMode, T_secondaryEncodingMode_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RedundancyEncodingMode_sequence[] = {
  { &hf_h245_redundancyEncodingMethod, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_RedundancyEncodingMethod },
  { &hf_h245_secondaryEncodingMode, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_T_secondaryEncodingMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RedundancyEncodingMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RedundancyEncodingMode, RedundancyEncodingMode_sequence);

  return offset;
}


static const per_sequence_t H2250ModeParameters_sequence[] = {
  { &hf_h245_redundancyEncodingMode, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_RedundancyEncodingMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H2250ModeParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H2250ModeParameters, H2250ModeParameters_sequence);

  return offset;
}


static const per_sequence_t MultiplexedStreamModeParameters_sequence[] = {
  { &hf_h245_logicalChannelNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_LogicalChannelNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MultiplexedStreamModeParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MultiplexedStreamModeParameters, MultiplexedStreamModeParameters_sequence);

  return offset;
}


static const per_sequence_t ModeElement_sequence[] = {
  { &hf_h245_type           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_ModeElementType },
  { &hf_h245_h223ModeParameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_H223ModeParameters },
  { &hf_h245_v76ModeParameters, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_V76ModeParameters },
  { &hf_h245_h2250ModeParameters, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_H2250ModeParameters },
  { &hf_h245_genericModeParameters, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_GenericCapability },
  { &hf_h245_multiplexedStreamModeParameters, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_MultiplexedStreamModeParameters },
  { &hf_h245_logicalChannelNumber, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_LogicalChannelNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_ModeElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_ModeElement, ModeElement_sequence);

  return offset;
}


static const per_sequence_t ModeDescription_set_of[1] = {
  { &hf_h245_ModeDescription_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_ModeElement },
};

static int
dissect_h245_ModeDescription(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h245_ModeDescription, ModeDescription_set_of,
                                             1, 256, FALSE);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_256_OF_ModeDescription_sequence_of[1] = {
  { &hf_h245_requestedModes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_ModeDescription },
};

static int
dissect_h245_SEQUENCE_SIZE_1_256_OF_ModeDescription(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h245_SEQUENCE_SIZE_1_256_OF_ModeDescription, SEQUENCE_SIZE_1_256_OF_ModeDescription_sequence_of,
                                                  1, 256, FALSE);

  return offset;
}


static const per_sequence_t RequestMode_sequence[] = {
  { &hf_h245_sequenceNumber , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SequenceNumber },
  { &hf_h245_requestedModes , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SEQUENCE_SIZE_1_256_OF_ModeDescription },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RequestMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RequestMode, RequestMode_sequence);

  return offset;
}


static const per_sequence_t RoundTripDelayRequest_sequence[] = {
  { &hf_h245_sequenceNumber , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SequenceNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RoundTripDelayRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RoundTripDelayRequest, RoundTripDelayRequest_sequence);

  return offset;
}


static const value_string h245_Mlr_type_vals[] = {
  {   0, "systemLoop" },
  {   1, "mediaLoop" },
  {   2, "logicalChannelLoop" },
  { 0, NULL }
};

static const per_choice_t Mlr_type_choice[] = {
  {   0, &hf_h245_systemLoop     , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_mediaLoop      , ASN1_EXTENSION_ROOT    , dissect_h245_LogicalChannelNumber },
  {   2, &hf_h245_logicalChannelLoop, ASN1_EXTENSION_ROOT    , dissect_h245_LogicalChannelNumber },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_Mlr_type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_Mlr_type, Mlr_type_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MaintenanceLoopRequest_sequence[] = {
  { &hf_h245_mlr_type       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_Mlr_type },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MaintenanceLoopRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MaintenanceLoopRequest, MaintenanceLoopRequest_sequence);

  return offset;
}


static const per_sequence_t CommunicationModeRequest_sequence[] = {
  { NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};

static int
dissect_h245_CommunicationModeRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_CommunicationModeRequest, CommunicationModeRequest_sequence);

  return offset;
}


static const per_sequence_t Criteria_sequence[] = {
  { &hf_h245_field          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_OBJECT_IDENTIFIER },
  { &hf_h245_criteriaValue  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_OCTET_STRING_SIZE_1_65535 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_Criteria(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_Criteria, Criteria_sequence);

  return offset;
}


static const per_sequence_t CertSelectionCriteria_sequence_of[1] = {
  { &hf_h245_CertSelectionCriteria_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_Criteria },
};

static int
dissect_h245_CertSelectionCriteria(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h245_CertSelectionCriteria, CertSelectionCriteria_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}


static const per_sequence_t T_requestTerminalCertificate_sequence[] = {
  { &hf_h245_terminalLabel  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_TerminalLabel },
  { &hf_h245_certSelectionCriteria, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_CertSelectionCriteria },
  { &hf_h245_sRandom        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_4294967295 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_requestTerminalCertificate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_requestTerminalCertificate, T_requestTerminalCertificate_sequence);

  return offset;
}


static const value_string h245_RemoteMCRequest_vals[] = {
  {   0, "masterActivate" },
  {   1, "slaveActivate" },
  {   2, "deActivate" },
  { 0, NULL }
};

static const per_choice_t RemoteMCRequest_choice[] = {
  {   0, &hf_h245_masterActivate , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_slaveActivate  , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_deActivate     , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_RemoteMCRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_RemoteMCRequest, RemoteMCRequest_choice,
                                 NULL);

  return offset;
}


static const value_string h245_ConferenceRequest_vals[] = {
  {   0, "terminalListRequest" },
  {   1, "makeMeChair" },
  {   2, "cancelMakeMeChair" },
  {   3, "dropTerminal" },
  {   4, "requestTerminalID" },
  {   5, "enterH243Password" },
  {   6, "enterH243TerminalID" },
  {   7, "enterH243ConferenceID" },
  {   8, "enterExtensionAddress" },
  {   9, "requestChairTokenOwner" },
  {  10, "requestTerminalCertificate" },
  {  11, "broadcastMyLogicalChannel" },
  {  12, "makeTerminalBroadcaster" },
  {  13, "sendThisSource" },
  {  14, "requestAllTerminalIDs" },
  {  15, "remoteMCRequest" },
  { 0, NULL }
};

static const per_choice_t ConferenceRequest_choice[] = {
  {   0, &hf_h245_terminalListRequest, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_makeMeChair    , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_cancelMakeMeChair, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   3, &hf_h245_dropTerminal   , ASN1_EXTENSION_ROOT    , dissect_h245_TerminalLabel },
  {   4, &hf_h245_requestTerminalID, ASN1_EXTENSION_ROOT    , dissect_h245_TerminalLabel },
  {   5, &hf_h245_enterH243Password, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   6, &hf_h245_enterH243TerminalID, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   7, &hf_h245_enterH243ConferenceID, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   8, &hf_h245_enterExtensionAddress, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {   9, &hf_h245_requestChairTokenOwner, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {  10, &hf_h245_requestTerminalCertificate, ASN1_NOT_EXTENSION_ROOT, dissect_h245_T_requestTerminalCertificate },
  {  11, &hf_h245_broadcastMyLogicalChannel, ASN1_NOT_EXTENSION_ROOT, dissect_h245_LogicalChannelNumber },
  {  12, &hf_h245_makeTerminalBroadcaster, ASN1_NOT_EXTENSION_ROOT, dissect_h245_TerminalLabel },
  {  13, &hf_h245_sendThisSource , ASN1_NOT_EXTENSION_ROOT, dissect_h245_TerminalLabel },
  {  14, &hf_h245_requestAllTerminalIDs, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {  15, &hf_h245_remoteMCRequest, ASN1_NOT_EXTENSION_ROOT, dissect_h245_RemoteMCRequest },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_ConferenceRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_ConferenceRequest, ConferenceRequest_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CallInformationReq_sequence[] = {
  { &hf_h245_maxNumberOfAdditionalConnections, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_65535 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_CallInformationReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_CallInformationReq, CallInformationReq_sequence);

  return offset;
}



static int
dissect_h245_NumericString_SIZE_0_40(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_NumericString(tvb, offset, actx, tree, hf_index,
                                          0, 40, FALSE);

  return offset;
}



static int
dissect_h245_IA5String_SIZE_1_40(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 40, FALSE);

  return offset;
}


static const value_string h245_DialingInformationNetworkType_vals[] = {
  {   0, "nonStandard" },
  {   1, "n-isdn" },
  {   2, "gstn" },
  {   3, "mobile" },
  { 0, NULL }
};

static const per_choice_t DialingInformationNetworkType_choice[] = {
  {   0, &hf_h245_nonStandardMsg , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardMessage },
  {   1, &hf_h245_n_isdn         , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_gstn           , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   3, &hf_h245_mobile         , ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_DialingInformationNetworkType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_DialingInformationNetworkType, DialingInformationNetworkType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SET_SIZE_1_255_OF_DialingInformationNetworkType_set_of[1] = {
  { &hf_h245_networkType_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_DialingInformationNetworkType },
};

static int
dissect_h245_SET_SIZE_1_255_OF_DialingInformationNetworkType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h245_SET_SIZE_1_255_OF_DialingInformationNetworkType, SET_SIZE_1_255_OF_DialingInformationNetworkType_set_of,
                                             1, 255, FALSE);

  return offset;
}


static const per_sequence_t DialingInformationNumber_sequence[] = {
  { &hf_h245_networkAddressNum, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_NumericString_SIZE_0_40 },
  { &hf_h245_subAddress     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_IA5String_SIZE_1_40 },
  { &hf_h245_networkType    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SET_SIZE_1_255_OF_DialingInformationNetworkType },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_DialingInformationNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_DialingInformationNumber, DialingInformationNumber_sequence);

  return offset;
}


static const per_sequence_t SET_SIZE_1_65535_OF_DialingInformationNumber_set_of[1] = {
  { &hf_h245_differential_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_DialingInformationNumber },
};

static int
dissect_h245_SET_SIZE_1_65535_OF_DialingInformationNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h245_SET_SIZE_1_65535_OF_DialingInformationNumber, SET_SIZE_1_65535_OF_DialingInformationNumber_set_of,
                                             1, 65535, FALSE);

  return offset;
}


static const value_string h245_DialingInformation_vals[] = {
  {   0, "nonStandard" },
  {   1, "differential" },
  {   2, "infoNotAvailable" },
  { 0, NULL }
};

static const per_choice_t DialingInformation_choice[] = {
  {   0, &hf_h245_nonStandardMsg , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardMessage },
  {   1, &hf_h245_differential   , ASN1_EXTENSION_ROOT    , dissect_h245_SET_SIZE_1_65535_OF_DialingInformationNumber },
  {   2, &hf_h245_infoNotAvailable, ASN1_EXTENSION_ROOT    , dissect_h245_INTEGER_1_65535 },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_DialingInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_DialingInformation, DialingInformation_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t AddConnectionReq_sequence[] = {
  { &hf_h245_sequenceNumber , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SequenceNumber },
  { &hf_h245_dialingInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_DialingInformation },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_AddConnectionReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_AddConnectionReq, AddConnectionReq_sequence);

  return offset;
}


static const per_sequence_t ConnectionIdentifier_sequence[] = {
  { &hf_h245_channelTag     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_4294967295 },
  { &hf_h245_sequenceNum    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_4294967295 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_ConnectionIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_ConnectionIdentifier, ConnectionIdentifier_sequence);

  return offset;
}


static const per_sequence_t RemoveConnectionReq_sequence[] = {
  { &hf_h245_connectionIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_ConnectionIdentifier },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RemoveConnectionReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RemoveConnectionReq, RemoveConnectionReq_sequence);

  return offset;
}


static const value_string h245_T_requestType_vals[] = {
  {   0, "currentIntervalInformation" },
  {   1, "requestedInterval" },
  { 0, NULL }
};

static const per_choice_t T_requestType_choice[] = {
  {   0, &hf_h245_currentIntervalInformation, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_requestedInterval, ASN1_EXTENSION_ROOT    , dissect_h245_INTEGER_0_65535 },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_requestType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_requestType, T_requestType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MaximumHeaderIntervalReq_sequence[] = {
  { &hf_h245_requestType    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_requestType },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MaximumHeaderIntervalReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MaximumHeaderIntervalReq, MaximumHeaderIntervalReq_sequence);

  return offset;
}


static const value_string h245_MultilinkRequest_vals[] = {
  {   0, "nonStandard" },
  {   1, "callInformation" },
  {   2, "addConnection" },
  {   3, "removeConnection" },
  {   4, "maximumHeaderInterval" },
  { 0, NULL }
};

static const per_choice_t MultilinkRequest_choice[] = {
  {   0, &hf_h245_nonStandardMsg , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardMessage },
  {   1, &hf_h245_callInformationReq, ASN1_EXTENSION_ROOT    , dissect_h245_CallInformationReq },
  {   2, &hf_h245_addConnectionReq, ASN1_EXTENSION_ROOT    , dissect_h245_AddConnectionReq },
  {   3, &hf_h245_removeConnectionReq, ASN1_EXTENSION_ROOT    , dissect_h245_RemoveConnectionReq },
  {   4, &hf_h245_maximumHeaderIntervalReq, ASN1_EXTENSION_ROOT    , dissect_h245_MaximumHeaderIntervalReq },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_MultilinkRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_MultilinkRequest, MultilinkRequest_choice,
                                 NULL);

  return offset;
}



static int
dissect_h245_MaximumBitRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}


static const per_sequence_t LogicalChannelRateRequest_sequence[] = {
  { &hf_h245_sequenceNumber , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SequenceNumber },
  { &hf_h245_logicalChannelNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_LogicalChannelNumber },
  { &hf_h245_maximumBitRate , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_MaximumBitRate },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_LogicalChannelRateRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_LogicalChannelRateRequest, LogicalChannelRateRequest_sequence);

  return offset;
}


static const value_string h245_RequestMessage_vals[] = {
  { RequestMessage_nonStandard, "nonStandard" },
  { RequestMessage_masterSlaveDetermination, "masterSlaveDetermination" },
  { RequestMessage_terminalCapabilitySet, "terminalCapabilitySet" },
  { RequestMessage_openLogicalChannel, "openLogicalChannel" },
  { RequestMessage_closeLogicalChannel, "closeLogicalChannel" },
  { RequestMessage_requestChannelClose, "requestChannelClose" },
  { RequestMessage_multiplexEntrySend, "multiplexEntrySend" },
  { RequestMessage_requestMultiplexEntry, "requestMultiplexEntry" },
  { RequestMessage_requestMode, "requestMode" },
  { RequestMessage_roundTripDelayRequest, "roundTripDelayRequest" },
  { RequestMessage_maintenanceLoopRequest, "maintenanceLoopRequest" },
  { RequestMessage_communicationModeRequest, "communicationModeRequest" },
  { RequestMessage_conferenceRequest, "conferenceRequest" },
  { RequestMessage_multilinkRequest, "multilinkRequest" },
  { RequestMessage_logicalChannelRateRequest, "logicalChannelRateRequest" },
  { RequestMessage_genericRequest, "genericRequest" },
  { 0, NULL }
};

static const per_choice_t RequestMessage_choice[] = {
  { RequestMessage_nonStandard, &hf_h245_nonStandardMsg , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardMessage },
  { RequestMessage_masterSlaveDetermination, &hf_h245_masterSlaveDetermination, ASN1_EXTENSION_ROOT    , dissect_h245_MasterSlaveDetermination },
  { RequestMessage_terminalCapabilitySet, &hf_h245_terminalCapabilitySet, ASN1_EXTENSION_ROOT    , dissect_h245_TerminalCapabilitySet },
  { RequestMessage_openLogicalChannel, &hf_h245_openLogicalChannel, ASN1_EXTENSION_ROOT    , dissect_h245_OpenLogicalChannel },
  { RequestMessage_closeLogicalChannel, &hf_h245_closeLogicalChannel, ASN1_EXTENSION_ROOT    , dissect_h245_CloseLogicalChannel },
  { RequestMessage_requestChannelClose, &hf_h245_requestChannelClose, ASN1_EXTENSION_ROOT    , dissect_h245_RequestChannelClose },
  { RequestMessage_multiplexEntrySend, &hf_h245_multiplexEntrySend, ASN1_EXTENSION_ROOT    , dissect_h245_MultiplexEntrySend },
  { RequestMessage_requestMultiplexEntry, &hf_h245_requestMultiplexEntry, ASN1_EXTENSION_ROOT    , dissect_h245_RequestMultiplexEntry },
  { RequestMessage_requestMode, &hf_h245_requestMode    , ASN1_EXTENSION_ROOT    , dissect_h245_RequestMode },
  { RequestMessage_roundTripDelayRequest, &hf_h245_roundTripDelayRequest, ASN1_EXTENSION_ROOT    , dissect_h245_RoundTripDelayRequest },
  { RequestMessage_maintenanceLoopRequest, &hf_h245_maintenanceLoopRequest, ASN1_EXTENSION_ROOT    , dissect_h245_MaintenanceLoopRequest },
  { RequestMessage_communicationModeRequest, &hf_h245_communicationModeRequest, ASN1_NOT_EXTENSION_ROOT, dissect_h245_CommunicationModeRequest },
  { RequestMessage_conferenceRequest, &hf_h245_conferenceRequest, ASN1_NOT_EXTENSION_ROOT, dissect_h245_ConferenceRequest },
  { RequestMessage_multilinkRequest, &hf_h245_multilinkRequest, ASN1_NOT_EXTENSION_ROOT, dissect_h245_MultilinkRequest },
  { RequestMessage_logicalChannelRateRequest, &hf_h245_logicalChannelRateRequest, ASN1_NOT_EXTENSION_ROOT, dissect_h245_LogicalChannelRateRequest },
  { RequestMessage_genericRequest, &hf_h245_genericRequest , ASN1_NOT_EXTENSION_ROOT, dissect_h245_GenericMessage },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_RequestMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 368 "../../asn1/h245/h245.cnf"
  gint32 value;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_RequestMessage, RequestMessage_choice,
                                 &value);

	if ( h245_shorttypes == TRUE )
	    {
	        	col_prepend_fstr(actx->pinfo->cinfo, COL_INFO, "%s ",
				val_to_str(value, h245_RequestMessage_short_vals, "<unknown>"));
		}
		else
		{
	        	col_prepend_fstr(actx->pinfo->cinfo, COL_INFO, "%s ",
				val_to_str(value, h245_RequestMessage_vals, "<unknown>"));
		}

	if (( codec_type != NULL ) && ( value == RequestMessage_openLogicalChannel) ){
		col_append_fstr(actx->pinfo->cinfo, COL_INFO, "(%s) ", codec_type );
	}

        col_set_fence(actx->pinfo->cinfo,COL_INFO);

    /* Add to packet info */
	if (h245_pi == NULL)
		return offset;

    if (strlen(h245_pi->frame_label) == 0)
    {
      g_snprintf(h245_pi->frame_label, 50, "%s", val_to_str(value, h245_RequestMessage_short_vals, "UKN"));

      /* if it is OLC or RM*/
      if ((codec_type != NULL) && (( value == RequestMessage_openLogicalChannel) || ( value == RequestMessage_requestMode)))
      {
        g_strlcat(h245_pi->frame_label, " (", 50);
        g_strlcat(h245_pi->frame_label, codec_type, 50);
        g_strlcat(h245_pi->frame_label, ")", 50);
      }
    }
    g_strlcat(h245_pi->comment, val_to_str(value, h245_RequestMessage_vals, "<unknown>"), 50);


  return offset;
}


static const value_string h245_T_decision_vals[] = {
  {   0, "master" },
  {   1, "slave" },
  { 0, NULL }
};

static const per_choice_t T_decision_choice[] = {
  {   0, &hf_h245_master         , ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  {   1, &hf_h245_slave          , ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_decision(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_decision, T_decision_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MasterSlaveDeterminationAck_sequence[] = {
  { &hf_h245_decision       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_decision },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MasterSlaveDeterminationAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MasterSlaveDeterminationAck, MasterSlaveDeterminationAck_sequence);

#line 531 "../../asn1/h245/h245.cnf"

if (h245_pi != NULL)
  h245_pi->msg_type = H245_MastSlvDetAck;

  return offset;
}


static const value_string h245_MasterSlaveDeterminationRejectCause_vals[] = {
  {   0, "identicalNumbers" },
  { 0, NULL }
};

static const per_choice_t MasterSlaveDeterminationRejectCause_choice[] = {
  {   0, &hf_h245_identicalNumbers, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_MasterSlaveDeterminationRejectCause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_MasterSlaveDeterminationRejectCause, MasterSlaveDeterminationRejectCause_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MasterSlaveDeterminationReject_sequence[] = {
  { &hf_h245_msd_rej_cause  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_MasterSlaveDeterminationRejectCause },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MasterSlaveDeterminationReject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MasterSlaveDeterminationReject, MasterSlaveDeterminationReject_sequence);

#line 537 "../../asn1/h245/h245.cnf"

if (h245_pi != NULL)
  h245_pi->msg_type = H245_MastSlvDetRjc;

  return offset;
}


static const per_sequence_t TerminalCapabilitySetAck_sequence[] = {
  { &hf_h245_sequenceNumber , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SequenceNumber },
  { &hf_h245_genericInformation, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_SEQUENCE_OF_GenericInformation },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_TerminalCapabilitySetAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_TerminalCapabilitySetAck, TerminalCapabilitySetAck_sequence);

#line 567 "../../asn1/h245/h245.cnf"

if (h245_pi != NULL)
  h245_pi->msg_type = H245_TermCapSetAck;

  return offset;
}


static const value_string h245_T_tableEntryCapacityExceeded_vals[] = {
  {   0, "highestEntryNumberProcessed" },
  {   1, "noneProcessed" },
  { 0, NULL }
};

static const per_choice_t T_tableEntryCapacityExceeded_choice[] = {
  {   0, &hf_h245_highestEntryNumberProcessed, ASN1_NO_EXTENSIONS     , dissect_h245_CapabilityTableEntryNumber },
  {   1, &hf_h245_noneProcessed  , ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_tableEntryCapacityExceeded(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_tableEntryCapacityExceeded, T_tableEntryCapacityExceeded_choice,
                                 NULL);

  return offset;
}


static const value_string h245_TerminalCapabilitySetRejectCause_vals[] = {
  {   0, "unspecified" },
  {   1, "undefinedTableEntryUsed" },
  {   2, "descriptorCapacityExceeded" },
  {   3, "tableEntryCapacityExceeded" },
  { 0, NULL }
};

static const per_choice_t TerminalCapabilitySetRejectCause_choice[] = {
  {   0, &hf_h245_unspecified    , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_undefinedTableEntryUsed, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_descriptorCapacityExceeded, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   3, &hf_h245_tableEntryCapacityExceeded, ASN1_EXTENSION_ROOT    , dissect_h245_T_tableEntryCapacityExceeded },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_TerminalCapabilitySetRejectCause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_TerminalCapabilitySetRejectCause, TerminalCapabilitySetRejectCause_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t TerminalCapabilitySetReject_sequence[] = {
  { &hf_h245_sequenceNumber , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SequenceNumber },
  { &hf_h245_tcs_rej_cause  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_TerminalCapabilitySetRejectCause },
  { &hf_h245_genericInformation, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_SEQUENCE_OF_GenericInformation },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_TerminalCapabilitySetReject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_TerminalCapabilitySetReject, TerminalCapabilitySetReject_sequence);

#line 579 "../../asn1/h245/h245.cnf"

if (h245_pi != NULL)
  h245_pi->msg_type = H245_TermCapSetRjc;

  return offset;
}



static int
dissect_h245_OLC_ack_fw_lcn(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_h245_LogicalChannelNumber(tvb, offset, actx, tree, hf_index);

#line 275 "../../asn1/h245/h245.cnf"
  if (upcoming_olc) upcoming_olc->fwd_lc_num = h245_lc_temp;
  h223_fw_lc_num = h245_lc_temp;

  return offset;
}



static int
dissect_h245_T_reverseLogicalChannelNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_h245_LogicalChannelNumber(tvb, offset, actx, tree, hf_index);

#line 289 "../../asn1/h245/h245.cnf"
  h223_rev_lc_num = h245_lc_temp;

  return offset;
}


static const value_string h245_T_olc_ack_multiplexParameters_vals[] = {
  {   0, "h222LogicalChannelParameters" },
  {   1, "h2250LogicalChannelParameters" },
  { 0, NULL }
};

static const per_choice_t T_olc_ack_multiplexParameters_choice[] = {
  {   0, &hf_h245_h222LogicalChannelParameters, ASN1_EXTENSION_ROOT    , dissect_h245_H222LogicalChannelParameters },
  {   1, &hf_h245_h2250LogicalChannelParameters, ASN1_NOT_EXTENSION_ROOT, dissect_h245_H2250LogicalChannelParameters },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_olc_ack_multiplexParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_olc_ack_multiplexParameters, T_olc_ack_multiplexParameters_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t OLC_ack_reverseLogicalChannelParameters_sequence[] = {
  { &hf_h245_reverseLogicalChannelNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_reverseLogicalChannelNumber },
  { &hf_h245_portNumber     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_65535 },
  { &hf_h245_olc_ack_multiplexParameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_T_olc_ack_multiplexParameters },
  { &hf_h245_replacementFor , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_LogicalChannelNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_OLC_ack_reverseLogicalChannelParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_OLC_ack_reverseLogicalChannelParameters, OLC_ack_reverseLogicalChannelParameters_sequence);

  return offset;
}



static int
dissect_h245_Ack_mediaChannel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 891 "../../asn1/h245/h245.cnf"
  if (upcoming_channel)
    upcoming_channel->upcoming_addr = &upcoming_channel->media_addr;

  offset = dissect_h245_TransportAddress(tvb, offset, actx, tree, hf_index);

#line 895 "../../asn1/h245/h245.cnf"
  if (upcoming_channel)
    upcoming_channel->upcoming_addr = NULL;

  return offset;
}



static int
dissect_h245_Ack_mediaControlChannel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 909 "../../asn1/h245/h245.cnf"
  if (upcoming_channel)
    upcoming_channel->upcoming_addr = &upcoming_channel->media_control_addr;

  offset = dissect_h245_TransportAddress(tvb, offset, actx, tree, hf_index);

#line 913 "../../asn1/h245/h245.cnf"
  if (upcoming_channel)
    upcoming_channel->upcoming_addr = NULL;

  return offset;
}


static const per_sequence_t H2250LogicalChannelAckParameters_sequence[] = {
  { &hf_h245_nonStandardParams, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_SEQUENCE_OF_NonStandardParameter },
  { &hf_h245_sessionID      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_255 },
  { &hf_h245_ack_mediaChannel, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_Ack_mediaChannel },
  { &hf_h245_ack_mediaControlChannel, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_Ack_mediaControlChannel },
  { &hf_h245_dynamicRTPPayloadType, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_96_127 },
  { &hf_h245_flowControlToZero, ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_portNumber     , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_INTEGER_0_65535 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H2250LogicalChannelAckParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H2250LogicalChannelAckParameters, H2250LogicalChannelAckParameters_sequence);

  return offset;
}


static const value_string h245_T_forwardMultiplexAckParameters_vals[] = {
  {   0, "h2250LogicalChannelAckParameters" },
  { 0, NULL }
};

static const per_choice_t T_forwardMultiplexAckParameters_choice[] = {
  {   0, &hf_h245_h2250LogicalChannelAckParameters, ASN1_EXTENSION_ROOT    , dissect_h245_H2250LogicalChannelAckParameters },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_forwardMultiplexAckParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 280 "../../asn1/h245/h245.cnf"

  upcoming_channel = (upcoming_olc) ? &upcoming_olc->fwd_lc : NULL;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_forwardMultiplexAckParameters, T_forwardMultiplexAckParameters_choice,
                                 NULL);

	
  upcoming_channel = NULL;


  return offset;
}


static const per_sequence_t OpenLogicalChannelAck_sequence[] = {
  { &hf_h245_olc_ack_fw_lcn , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_OLC_ack_fw_lcn },
  { &hf_h245_olc_ack_reverseLogicalChannelParameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_OLC_ack_reverseLogicalChannelParameters },
  { &hf_h245_separateStack  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_NetworkAccessParameters },
  { &hf_h245_forwardMultiplexAckParameters, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_T_forwardMultiplexAckParameters },
  { &hf_h245_encryptionSync , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_EncryptionSync },
  { &hf_h245_genericInformation, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_SEQUENCE_OF_GenericInformation },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_OpenLogicalChannelAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 219 "../../asn1/h245/h245.cnf"
  guint32 temp;
  int p2p_dir;
  h223_pending_olc *pend;
  const gchar *olc_key;
  olc_info_t *olc_req;

  upcoming_olc = (!actx->pinfo->fd->flags.visited) ? ep_alloc0(sizeof(olc_info_t)) : NULL;

  h223_fw_lc_num = 0;
  h223_rev_lc_num = 0;
	
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_OpenLogicalChannelAck, OpenLogicalChannelAck_sequence);


  temp = h223_fw_lc_num;
  p2p_dir = actx->pinfo->p2p_dir;
  
  if(actx->pinfo->p2p_dir == P2P_DIR_SENT)
	actx->pinfo->p2p_dir = P2P_DIR_RECV;
  else
	actx->pinfo->p2p_dir = P2P_DIR_SENT;
  pend = g_hash_table_lookup( h223_pending_olc_reqs[actx->pinfo->p2p_dir], GINT_TO_POINTER(temp) );
  if (pend) {
	DISSECTOR_ASSERT( ( h223_rev_lc_num &&  pend->rev_channel_params)
				   || (!h223_rev_lc_num && !pend->rev_channel_params) );
	if(h223_add_lc_handle) {
	  (*h223_add_lc_handle)( actx->pinfo, h223_fw_lc_num, pend->fw_channel_params );
	  if(h223_rev_lc_num)
		(*h223_add_lc_handle)( actx->pinfo, h223_rev_lc_num, pend->rev_channel_params );
	}
  } else {
	/* we missed the OpenLogicalChannel packet */
  }
  actx->pinfo->p2p_dir = p2p_dir;

  if (upcoming_olc) {
    olc_key = gen_olc_key(upcoming_olc->fwd_lc_num, &actx->pinfo->src, &actx->pinfo->dst);
    olc_req = g_hash_table_lookup(h245_pending_olc_reqs, olc_key);
    if (olc_req) {
      update_unicast_addr(&olc_req->fwd_lc.media_addr, &upcoming_olc->fwd_lc.media_addr);
      update_unicast_addr(&olc_req->fwd_lc.media_control_addr, &upcoming_olc->fwd_lc.media_control_addr);
      update_unicast_addr(&olc_req->rev_lc.media_addr, &upcoming_olc->rev_lc.media_addr);
      update_unicast_addr(&olc_req->rev_lc.media_control_addr, &upcoming_olc->rev_lc.media_control_addr);
      h245_setup_channels(actx->pinfo, &olc_req->fwd_lc);
      h245_setup_channels(actx->pinfo, &olc_req->rev_lc);
      g_hash_table_remove(h245_pending_olc_reqs, olc_key);
    } else {
      h245_setup_channels(actx->pinfo, &upcoming_olc->fwd_lc);
    }
  }
  upcoming_olc = NULL;

  if (h245_pi != NULL)
	h245_pi->msg_type = H245_OpenLogChnAck;


  return offset;
}


static const value_string h245_OpenLogicalChannelRejectCause_vals[] = {
  {   0, "unspecified" },
  {   1, "unsuitableReverseParameters" },
  {   2, "dataTypeNotSupported" },
  {   3, "dataTypeNotAvailable" },
  {   4, "unknownDataType" },
  {   5, "dataTypeALCombinationNotSupported" },
  {   6, "multicastChannelNotAllowed" },
  {   7, "insufficientBandwidth" },
  {   8, "separateStackEstablishmentFailed" },
  {   9, "invalidSessionID" },
  {  10, "masterSlaveConflict" },
  {  11, "waitForCommunicationMode" },
  {  12, "invalidDependentChannel" },
  {  13, "replacementForRejected" },
  {  14, "securityDenied" },
  {  15, "qoSControlNotSupported" },
  { 0, NULL }
};

static const per_choice_t OpenLogicalChannelRejectCause_choice[] = {
  {   0, &hf_h245_unspecified    , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_unsuitableReverseParameters, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_dataTypeNotSupported, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   3, &hf_h245_dataTypeNotAvailable, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   4, &hf_h245_unknownDataType, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   5, &hf_h245_dataTypeALCombinationNotSupported, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   6, &hf_h245_multicastChannelNotAllowed, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {   7, &hf_h245_insufficientBandwidth, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {   8, &hf_h245_separateStackEstablishmentFailed, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {   9, &hf_h245_invalidSessionID, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {  10, &hf_h245_masterSlaveConflict, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {  11, &hf_h245_waitForCommunicationMode, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {  12, &hf_h245_invalidDependentChannel, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {  13, &hf_h245_replacementForRejected, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {  14, &hf_h245_securityDenied , ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {  15, &hf_h245_qoSControlNotSupported, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_OpenLogicalChannelRejectCause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_OpenLogicalChannelRejectCause, OpenLogicalChannelRejectCause_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t OpenLogicalChannelReject_sequence[] = {
  { &hf_h245_forwardLogicalChannelNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_LogicalChannelNumber },
  { &hf_h245_olc_rej_cause  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_OpenLogicalChannelRejectCause },
  { &hf_h245_genericInformation, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_SEQUENCE_OF_GenericInformation },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_OpenLogicalChannelReject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_OpenLogicalChannelReject, OpenLogicalChannelReject_sequence);

#line 543 "../../asn1/h245/h245.cnf"

if (h245_pi != NULL)
  h245_pi->msg_type = H245_OpenLogChnRjc;

  return offset;
}


static const per_sequence_t CloseLogicalChannelAck_sequence[] = {
  { &hf_h245_forwardLogicalChannelNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_LogicalChannelNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_CloseLogicalChannelAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_CloseLogicalChannelAck, CloseLogicalChannelAck_sequence);

#line 555 "../../asn1/h245/h245.cnf"

if (h245_pi != NULL)
  h245_pi->msg_type = H245_CloseLogChnAck;

  return offset;
}


static const per_sequence_t RequestChannelCloseAck_sequence[] = {
  { &hf_h245_forwardLogicalChannelNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_LogicalChannelNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RequestChannelCloseAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RequestChannelCloseAck, RequestChannelCloseAck_sequence);

  return offset;
}


static const value_string h245_RequestChannelCloseRejectCause_vals[] = {
  {   0, "unspecified" },
  { 0, NULL }
};

static const per_choice_t RequestChannelCloseRejectCause_choice[] = {
  {   0, &hf_h245_unspecified    , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_RequestChannelCloseRejectCause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_RequestChannelCloseRejectCause, RequestChannelCloseRejectCause_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RequestChannelCloseReject_sequence[] = {
  { &hf_h245_forwardLogicalChannelNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_LogicalChannelNumber },
  { &hf_h245_req_chan_clos_rej_cause, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_RequestChannelCloseRejectCause },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RequestChannelCloseReject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RequestChannelCloseReject, RequestChannelCloseReject_sequence);

  return offset;
}


static const per_sequence_t MultiplexEntrySendAck_sequence[] = {
  { &hf_h245_sequenceNumber , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SequenceNumber },
  { &hf_h245_multiplexTableEntryNumbers, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SET_SIZE_1_15_OF_MultiplexTableEntryNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MultiplexEntrySendAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MultiplexEntrySendAck, MultiplexEntrySendAck_sequence);

  return offset;
}


static const value_string h245_MultiplexEntryRejectionDescriptionsCause_vals[] = {
  {   0, "unspecifiedCause" },
  {   1, "descriptorTooComplex" },
  { 0, NULL }
};

static const per_choice_t MultiplexEntryRejectionDescriptionsCause_choice[] = {
  {   0, &hf_h245_unspecifiedCause, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_descriptorTooComplex, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_MultiplexEntryRejectionDescriptionsCause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_MultiplexEntryRejectionDescriptionsCause, MultiplexEntryRejectionDescriptionsCause_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MultiplexEntryRejectionDescriptions_sequence[] = {
  { &hf_h245_multiplexTableEntryNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_MultiplexTableEntryNumber },
  { &hf_h245_mux_rej_cause  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_MultiplexEntryRejectionDescriptionsCause },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MultiplexEntryRejectionDescriptions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MultiplexEntryRejectionDescriptions, MultiplexEntryRejectionDescriptions_sequence);

  return offset;
}


static const per_sequence_t SET_SIZE_1_15_OF_MultiplexEntryRejectionDescriptions_set_of[1] = {
  { &hf_h245_sendRejectionDescriptions_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_MultiplexEntryRejectionDescriptions },
};

static int
dissect_h245_SET_SIZE_1_15_OF_MultiplexEntryRejectionDescriptions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h245_SET_SIZE_1_15_OF_MultiplexEntryRejectionDescriptions, SET_SIZE_1_15_OF_MultiplexEntryRejectionDescriptions_set_of,
                                             1, 15, FALSE);

  return offset;
}


static const per_sequence_t MultiplexEntrySendReject_sequence[] = {
  { &hf_h245_sequenceNumber , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SequenceNumber },
  { &hf_h245_sendRejectionDescriptions, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SET_SIZE_1_15_OF_MultiplexEntryRejectionDescriptions },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MultiplexEntrySendReject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MultiplexEntrySendReject, MultiplexEntrySendReject_sequence);

  return offset;
}


static const per_sequence_t RequestMultiplexEntryAck_sequence[] = {
  { &hf_h245_entryNumbers   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SET_SIZE_1_15_OF_MultiplexTableEntryNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RequestMultiplexEntryAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RequestMultiplexEntryAck, RequestMultiplexEntryAck_sequence);

  return offset;
}


static const value_string h245_RequestMultiplexEntryRejectionDescriptionsCause_vals[] = {
  {   0, "unspecifiedCause" },
  { 0, NULL }
};

static const per_choice_t RequestMultiplexEntryRejectionDescriptionsCause_choice[] = {
  {   0, &hf_h245_unspecifiedCause, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_RequestMultiplexEntryRejectionDescriptionsCause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_RequestMultiplexEntryRejectionDescriptionsCause, RequestMultiplexEntryRejectionDescriptionsCause_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RequestMultiplexEntryRejectionDescriptions_sequence[] = {
  { &hf_h245_multiplexTableEntryNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_MultiplexTableEntryNumber },
  { &hf_h245_req_mux_rej_cause, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_RequestMultiplexEntryRejectionDescriptionsCause },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RequestMultiplexEntryRejectionDescriptions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RequestMultiplexEntryRejectionDescriptions, RequestMultiplexEntryRejectionDescriptions_sequence);

  return offset;
}


static const per_sequence_t SET_SIZE_1_15_OF_RequestMultiplexEntryRejectionDescriptions_set_of[1] = {
  { &hf_h245_rejectionDescriptions_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_RequestMultiplexEntryRejectionDescriptions },
};

static int
dissect_h245_SET_SIZE_1_15_OF_RequestMultiplexEntryRejectionDescriptions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h245_SET_SIZE_1_15_OF_RequestMultiplexEntryRejectionDescriptions, SET_SIZE_1_15_OF_RequestMultiplexEntryRejectionDescriptions_set_of,
                                             1, 15, FALSE);

  return offset;
}


static const per_sequence_t RequestMultiplexEntryReject_sequence[] = {
  { &hf_h245_entryNumbers   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SET_SIZE_1_15_OF_MultiplexTableEntryNumber },
  { &hf_h245_rejectionDescriptions, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SET_SIZE_1_15_OF_RequestMultiplexEntryRejectionDescriptions },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RequestMultiplexEntryReject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RequestMultiplexEntryReject, RequestMultiplexEntryReject_sequence);

  return offset;
}


static const value_string h245_Req_mode_ack_response_vals[] = {
  {   0, "willTransmitMostPreferredMode" },
  {   1, "willTransmitLessPreferredMode" },
  { 0, NULL }
};

static const per_choice_t Req_mode_ack_response_choice[] = {
  {   0, &hf_h245_willTransmitMostPreferredMode, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_willTransmitLessPreferredMode, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_Req_mode_ack_response(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_Req_mode_ack_response, Req_mode_ack_response_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RequestModeAck_sequence[] = {
  { &hf_h245_sequenceNumber , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SequenceNumber },
  { &hf_h245_req_mode_ack_response, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_Req_mode_ack_response },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RequestModeAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RequestModeAck, RequestModeAck_sequence);

  return offset;
}


static const value_string h245_RequestModeRejectCause_vals[] = {
  {   0, "modeUnavailable" },
  {   1, "multipointConstraint" },
  {   2, "requestDenied" },
  { 0, NULL }
};

static const per_choice_t RequestModeRejectCause_choice[] = {
  {   0, &hf_h245_modeUnavailable, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_multipointConstraint, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_requestDenied  , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_RequestModeRejectCause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_RequestModeRejectCause, RequestModeRejectCause_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RequestModeReject_sequence[] = {
  { &hf_h245_sequenceNumber , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SequenceNumber },
  { &hf_h245_req_rej_cause  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_RequestModeRejectCause },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RequestModeReject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RequestModeReject, RequestModeReject_sequence);

  return offset;
}


static const per_sequence_t RoundTripDelayResponse_sequence[] = {
  { &hf_h245_sequenceNumber , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SequenceNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RoundTripDelayResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RoundTripDelayResponse, RoundTripDelayResponse_sequence);

  return offset;
}


static const value_string h245_Mla_type_vals[] = {
  {   0, "systemLoop" },
  {   1, "mediaLoop" },
  {   2, "logicalChannelLoop" },
  { 0, NULL }
};

static const per_choice_t Mla_type_choice[] = {
  {   0, &hf_h245_systemLoop     , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_mediaLoop      , ASN1_EXTENSION_ROOT    , dissect_h245_LogicalChannelNumber },
  {   2, &hf_h245_logicalChannelLoop, ASN1_EXTENSION_ROOT    , dissect_h245_LogicalChannelNumber },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_Mla_type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_Mla_type, Mla_type_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MaintenanceLoopAck_sequence[] = {
  { &hf_h245_mla_type       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_Mla_type },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MaintenanceLoopAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MaintenanceLoopAck, MaintenanceLoopAck_sequence);

  return offset;
}


static const value_string h245_Mlrej_type_vals[] = {
  {   0, "systemLoop" },
  {   1, "mediaLoop" },
  {   2, "logicalChannelLoop" },
  { 0, NULL }
};

static const per_choice_t Mlrej_type_choice[] = {
  {   0, &hf_h245_systemLoop     , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_mediaLoop      , ASN1_EXTENSION_ROOT    , dissect_h245_LogicalChannelNumber },
  {   2, &hf_h245_logicalChannelLoop, ASN1_EXTENSION_ROOT    , dissect_h245_LogicalChannelNumber },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_Mlrej_type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_Mlrej_type, Mlrej_type_choice,
                                 NULL);

  return offset;
}


static const value_string h245_MaintenanceLoopRejectCause_vals[] = {
  {   0, "canNotPerformLoop" },
  { 0, NULL }
};

static const per_choice_t MaintenanceLoopRejectCause_choice[] = {
  {   0, &hf_h245_canNotPerformLoop, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_MaintenanceLoopRejectCause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_MaintenanceLoopRejectCause, MaintenanceLoopRejectCause_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MaintenanceLoopReject_sequence[] = {
  { &hf_h245_mlrej_type     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_Mlrej_type },
  { &hf_h245_maintloop_rej_cause, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_MaintenanceLoopRejectCause },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MaintenanceLoopReject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MaintenanceLoopReject, MaintenanceLoopReject_sequence);

  return offset;
}



static int
dissect_h245_BMPString_SIZE_1_128(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_BMPString(tvb, offset, actx, tree, hf_index,
                                          1, 128, FALSE);

  return offset;
}


static const value_string h245_T_entryDataType_vals[] = {
  {   0, "videoData" },
  {   1, "audioData" },
  {   2, "data" },
  { 0, NULL }
};

static const per_choice_t T_entryDataType_choice[] = {
  {   0, &hf_h245_videoData      , ASN1_EXTENSION_ROOT    , dissect_h245_VideoCapability },
  {   1, &hf_h245_audioData      , ASN1_EXTENSION_ROOT    , dissect_h245_AudioCapability },
  {   2, &hf_h245_data           , ASN1_EXTENSION_ROOT    , dissect_h245_DataApplicationCapability },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_entryDataType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_entryDataType, T_entryDataType_choice,
                                 NULL);

  return offset;
}



static int
dissect_h245_Cm_mediaChannel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_h245_TransportAddress(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t CommunicationModeTableEntry_sequence[] = {
  { &hf_h245_nonStandardParams, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_SEQUENCE_OF_NonStandardParameter },
  { &hf_h245_sessionID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_255 },
  { &hf_h245_associatedSessionID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_255 },
  { &hf_h245_terminalLabel  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_TerminalLabel },
  { &hf_h245_sessionDescription, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BMPString_SIZE_1_128 },
  { &hf_h245_entryDataType  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_entryDataType },
  { &hf_h245_cm_mediaChannel, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_Cm_mediaChannel },
  { &hf_h245_mediaGuaranteedDelivery, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_BOOLEAN },
  { &hf_h245_cm_mediaControlChannel, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_TransportAddress },
  { &hf_h245_mediaControlGuaranteedDelivery, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_BOOLEAN },
  { &hf_h245_redundancyEncoding, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_RedundancyEncoding },
  { &hf_h245_sessionDependency, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_INTEGER_1_255 },
  { &hf_h245_destination    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_TerminalLabel },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_CommunicationModeTableEntry(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_CommunicationModeTableEntry, CommunicationModeTableEntry_sequence);

  return offset;
}


static const per_sequence_t SET_SIZE_1_256_OF_CommunicationModeTableEntry_set_of[1] = {
  { &hf_h245_communicationModeTable_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_CommunicationModeTableEntry },
};

static int
dissect_h245_SET_SIZE_1_256_OF_CommunicationModeTableEntry(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h245_SET_SIZE_1_256_OF_CommunicationModeTableEntry, SET_SIZE_1_256_OF_CommunicationModeTableEntry_set_of,
                                             1, 256, FALSE);

  return offset;
}


static const value_string h245_CommunicationModeResponse_vals[] = {
  {   0, "communicationModeTable" },
  { 0, NULL }
};

static const per_choice_t CommunicationModeResponse_choice[] = {
  {   0, &hf_h245_communicationModeTable, ASN1_EXTENSION_ROOT    , dissect_h245_SET_SIZE_1_256_OF_CommunicationModeTableEntry },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_CommunicationModeResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_CommunicationModeResponse, CommunicationModeResponse_choice,
                                 NULL);

  return offset;
}



static int
dissect_h245_TerminalID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 128, FALSE, NULL);

  return offset;
}


static const per_sequence_t T_mCTerminalIDResponse_sequence[] = {
  { &hf_h245_terminalLabel  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_TerminalLabel },
  { &hf_h245_terminalID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_TerminalID },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_mCTerminalIDResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_mCTerminalIDResponse, T_mCTerminalIDResponse_sequence);

  return offset;
}


static const per_sequence_t T_terminalIDResponse_sequence[] = {
  { &hf_h245_terminalLabel  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_TerminalLabel },
  { &hf_h245_terminalID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_TerminalID },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_terminalIDResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_terminalIDResponse, T_terminalIDResponse_sequence);

  return offset;
}



static int
dissect_h245_ConferenceID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 32, FALSE, NULL);

  return offset;
}


static const per_sequence_t T_conferenceIDResponse_sequence[] = {
  { &hf_h245_terminalLabel  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_TerminalLabel },
  { &hf_h245_conferenceID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_ConferenceID },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_conferenceIDResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_conferenceIDResponse, T_conferenceIDResponse_sequence);

  return offset;
}



static int
dissect_h245_Password(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 32, FALSE, NULL);

  return offset;
}


static const per_sequence_t T_passwordResponse_sequence[] = {
  { &hf_h245_terminalLabel  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_TerminalLabel },
  { &hf_h245_password       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_Password },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_passwordResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_passwordResponse, T_passwordResponse_sequence);

  return offset;
}


static const per_sequence_t SET_SIZE_1_256_OF_TerminalLabel_set_of[1] = {
  { &hf_h245_terminalListResponse_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_TerminalLabel },
};

static int
dissect_h245_SET_SIZE_1_256_OF_TerminalLabel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h245_SET_SIZE_1_256_OF_TerminalLabel, SET_SIZE_1_256_OF_TerminalLabel_set_of,
                                             1, 256, FALSE);

  return offset;
}


static const value_string h245_T_makeMeChairResponse_vals[] = {
  {   0, "grantedChairToken" },
  {   1, "deniedChairToken" },
  { 0, NULL }
};

static const per_choice_t T_makeMeChairResponse_choice[] = {
  {   0, &hf_h245_grantedChairToken, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_deniedChairToken, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_makeMeChairResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_makeMeChairResponse, T_makeMeChairResponse_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_extensionAddressResponse_sequence[] = {
  { &hf_h245_extensionAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_TerminalID },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_extensionAddressResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_extensionAddressResponse, T_extensionAddressResponse_sequence);

  return offset;
}


static const per_sequence_t T_chairTokenOwnerResponse_sequence[] = {
  { &hf_h245_terminalLabel  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_TerminalLabel },
  { &hf_h245_terminalID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_TerminalID },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_chairTokenOwnerResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_chairTokenOwnerResponse, T_chairTokenOwnerResponse_sequence);

  return offset;
}


static const per_sequence_t T_terminalCertificateResponse_sequence[] = {
  { &hf_h245_terminalLabel  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_TerminalLabel },
  { &hf_h245_certificateResponse, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_OCTET_STRING_SIZE_1_65535 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_terminalCertificateResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_terminalCertificateResponse, T_terminalCertificateResponse_sequence);

  return offset;
}


static const value_string h245_T_broadcastMyLogicalChannelResponse_vals[] = {
  {   0, "grantedBroadcastMyLogicalChannel" },
  {   1, "deniedBroadcastMyLogicalChannel" },
  { 0, NULL }
};

static const per_choice_t T_broadcastMyLogicalChannelResponse_choice[] = {
  {   0, &hf_h245_grantedBroadcastMyLogicalChannel, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_deniedBroadcastMyLogicalChannel, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_broadcastMyLogicalChannelResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_broadcastMyLogicalChannelResponse, T_broadcastMyLogicalChannelResponse_choice,
                                 NULL);

  return offset;
}


static const value_string h245_T_makeTerminalBroadcasterResponse_vals[] = {
  {   0, "grantedMakeTerminalBroadcaster" },
  {   1, "deniedMakeTerminalBroadcaster" },
  { 0, NULL }
};

static const per_choice_t T_makeTerminalBroadcasterResponse_choice[] = {
  {   0, &hf_h245_grantedMakeTerminalBroadcaster, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_deniedMakeTerminalBroadcaster, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_makeTerminalBroadcasterResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_makeTerminalBroadcasterResponse, T_makeTerminalBroadcasterResponse_choice,
                                 NULL);

  return offset;
}


static const value_string h245_T_sendThisSourceResponse_vals[] = {
  {   0, "grantedSendThisSource" },
  {   1, "deniedSendThisSource" },
  { 0, NULL }
};

static const per_choice_t T_sendThisSourceResponse_choice[] = {
  {   0, &hf_h245_grantedSendThisSource, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_deniedSendThisSource, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_sendThisSourceResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_sendThisSourceResponse, T_sendThisSourceResponse_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t TerminalInformation_sequence[] = {
  { &hf_h245_terminalLabel  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_TerminalLabel },
  { &hf_h245_terminalID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_TerminalID },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_TerminalInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_TerminalInformation, TerminalInformation_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_TerminalInformation_sequence_of[1] = {
  { &hf_h245_terminalInformation_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_TerminalInformation },
};

static int
dissect_h245_SEQUENCE_OF_TerminalInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h245_SEQUENCE_OF_TerminalInformation, SEQUENCE_OF_TerminalInformation_sequence_of);

  return offset;
}


static const per_sequence_t RequestAllTerminalIDsResponse_sequence[] = {
  { &hf_h245_terminalInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SEQUENCE_OF_TerminalInformation },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RequestAllTerminalIDsResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RequestAllTerminalIDsResponse, RequestAllTerminalIDsResponse_sequence);

  return offset;
}


static const value_string h245_T_reject_vals[] = {
  {   0, "unspecified" },
  {   1, "functionNotSupported" },
  { 0, NULL }
};

static const per_choice_t T_reject_choice[] = {
  {   0, &hf_h245_unspecified    , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_functionNotSupportedFlag, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_reject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_reject, T_reject_choice,
                                 NULL);

  return offset;
}


static const value_string h245_RemoteMCResponse_vals[] = {
  {   0, "accept" },
  {   1, "reject" },
  { 0, NULL }
};

static const per_choice_t RemoteMCResponse_choice[] = {
  {   0, &hf_h245_accept         , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_reject         , ASN1_EXTENSION_ROOT    , dissect_h245_T_reject },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_RemoteMCResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_RemoteMCResponse, RemoteMCResponse_choice,
                                 NULL);

  return offset;
}


static const value_string h245_ConferenceResponse_vals[] = {
  {   0, "mCTerminalIDResponse" },
  {   1, "terminalIDResponse" },
  {   2, "conferenceIDResponse" },
  {   3, "passwordResponse" },
  {   4, "terminalListResponse" },
  {   5, "videoCommandReject" },
  {   6, "terminalDropReject" },
  {   7, "makeMeChairResponse" },
  {   8, "extensionAddressResponse" },
  {   9, "chairTokenOwnerResponse" },
  {  10, "terminalCertificateResponse" },
  {  11, "broadcastMyLogicalChannelResponse" },
  {  12, "makeTerminalBroadcasterResponse" },
  {  13, "sendThisSourceResponse" },
  {  14, "requestAllTerminalIDsResponse" },
  {  15, "remoteMCResponse" },
  { 0, NULL }
};

static const per_choice_t ConferenceResponse_choice[] = {
  {   0, &hf_h245_mCTerminalIDResponse, ASN1_EXTENSION_ROOT    , dissect_h245_T_mCTerminalIDResponse },
  {   1, &hf_h245_terminalIDResponse, ASN1_EXTENSION_ROOT    , dissect_h245_T_terminalIDResponse },
  {   2, &hf_h245_conferenceIDResponse, ASN1_EXTENSION_ROOT    , dissect_h245_T_conferenceIDResponse },
  {   3, &hf_h245_passwordResponse, ASN1_EXTENSION_ROOT    , dissect_h245_T_passwordResponse },
  {   4, &hf_h245_terminalListResponse, ASN1_EXTENSION_ROOT    , dissect_h245_SET_SIZE_1_256_OF_TerminalLabel },
  {   5, &hf_h245_videoCommandReject, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   6, &hf_h245_terminalDropReject, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   7, &hf_h245_makeMeChairResponse, ASN1_EXTENSION_ROOT    , dissect_h245_T_makeMeChairResponse },
  {   8, &hf_h245_extensionAddressResponse, ASN1_NOT_EXTENSION_ROOT, dissect_h245_T_extensionAddressResponse },
  {   9, &hf_h245_chairTokenOwnerResponse, ASN1_NOT_EXTENSION_ROOT, dissect_h245_T_chairTokenOwnerResponse },
  {  10, &hf_h245_terminalCertificateResponse, ASN1_NOT_EXTENSION_ROOT, dissect_h245_T_terminalCertificateResponse },
  {  11, &hf_h245_broadcastMyLogicalChannelResponse, ASN1_NOT_EXTENSION_ROOT, dissect_h245_T_broadcastMyLogicalChannelResponse },
  {  12, &hf_h245_makeTerminalBroadcasterResponse, ASN1_NOT_EXTENSION_ROOT, dissect_h245_T_makeTerminalBroadcasterResponse },
  {  13, &hf_h245_sendThisSourceResponse, ASN1_NOT_EXTENSION_ROOT, dissect_h245_T_sendThisSourceResponse },
  {  14, &hf_h245_requestAllTerminalIDsResponse, ASN1_NOT_EXTENSION_ROOT, dissect_h245_RequestAllTerminalIDsResponse },
  {  15, &hf_h245_remoteMCResponse, ASN1_NOT_EXTENSION_ROOT, dissect_h245_RemoteMCResponse },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_ConferenceResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_ConferenceResponse, ConferenceResponse_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CallInformationResp_sequence[] = {
  { &hf_h245_dialingInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_DialingInformation },
  { &hf_h245_callAssociationNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_4294967295 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_CallInformationResp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_CallInformationResp, CallInformationResp_sequence);

  return offset;
}


static const value_string h245_T_rejected_vals[] = {
  {   0, "connectionsNotAvailable" },
  {   1, "userRejected" },
  { 0, NULL }
};

static const per_choice_t T_rejected_choice[] = {
  {   0, &hf_h245_connectionsNotAvailable, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_userRejected   , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_rejected(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_rejected, T_rejected_choice,
                                 NULL);

  return offset;
}


static const value_string h245_T_responseCode_vals[] = {
  {   0, "accepted" },
  {   1, "rejected" },
  { 0, NULL }
};

static const per_choice_t T_responseCode_choice[] = {
  {   0, &hf_h245_accepted       , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_rejected       , ASN1_EXTENSION_ROOT    , dissect_h245_T_rejected },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_responseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_responseCode, T_responseCode_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t AddConnectionResp_sequence[] = {
  { &hf_h245_sequenceNumber , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SequenceNumber },
  { &hf_h245_responseCode   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_responseCode },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_AddConnectionResp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_AddConnectionResp, AddConnectionResp_sequence);

  return offset;
}


static const per_sequence_t RemoveConnectionResp_sequence[] = {
  { &hf_h245_connectionIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_ConnectionIdentifier },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RemoveConnectionResp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RemoveConnectionResp, RemoveConnectionResp_sequence);

  return offset;
}


static const per_sequence_t MaximumHeaderIntervalResp_sequence[] = {
  { &hf_h245_currentInterval, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_65535 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MaximumHeaderIntervalResp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MaximumHeaderIntervalResp, MaximumHeaderIntervalResp_sequence);

  return offset;
}


static const value_string h245_MultilinkResponse_vals[] = {
  {   0, "nonStandard" },
  {   1, "callInformation" },
  {   2, "addConnection" },
  {   3, "removeConnection" },
  {   4, "maximumHeaderInterval" },
  { 0, NULL }
};

static const per_choice_t MultilinkResponse_choice[] = {
  {   0, &hf_h245_nonStandardMsg , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardMessage },
  {   1, &hf_h245_callInformationResp, ASN1_EXTENSION_ROOT    , dissect_h245_CallInformationResp },
  {   2, &hf_h245_addConnectionResp, ASN1_EXTENSION_ROOT    , dissect_h245_AddConnectionResp },
  {   3, &hf_h245_removeConnectionResp, ASN1_EXTENSION_ROOT    , dissect_h245_RemoveConnectionResp },
  {   4, &hf_h245_maximumHeaderIntervalResp, ASN1_EXTENSION_ROOT    , dissect_h245_MaximumHeaderIntervalResp },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_MultilinkResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_MultilinkResponse, MultilinkResponse_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t LogicalChannelRateAcknowledge_sequence[] = {
  { &hf_h245_sequenceNumber , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SequenceNumber },
  { &hf_h245_logicalChannelNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_LogicalChannelNumber },
  { &hf_h245_maximumBitRate , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_MaximumBitRate },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_LogicalChannelRateAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_LogicalChannelRateAcknowledge, LogicalChannelRateAcknowledge_sequence);

  return offset;
}


static const value_string h245_LogicalChannelRateRejectReason_vals[] = {
  {   0, "undefinedReason" },
  {   1, "insufficientResources" },
  { 0, NULL }
};

static const per_choice_t LogicalChannelRateRejectReason_choice[] = {
  {   0, &hf_h245_undefinedReason, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_insufficientResources, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_LogicalChannelRateRejectReason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_LogicalChannelRateRejectReason, LogicalChannelRateRejectReason_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t LogicalChannelRateReject_sequence[] = {
  { &hf_h245_sequenceNumber , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SequenceNumber },
  { &hf_h245_logicalChannelNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_LogicalChannelNumber },
  { &hf_h245_rejectReason   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_LogicalChannelRateRejectReason },
  { &hf_h245_currentMaximumBitRate, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_MaximumBitRate },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_LogicalChannelRateReject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_LogicalChannelRateReject, LogicalChannelRateReject_sequence);

  return offset;
}


static const value_string h245_ResponseMessage_vals[] = {
  { ResponseMessage_nonStandard, "nonStandard" },
  { ResponseMessage_masterSlaveDeterminationAck, "masterSlaveDeterminationAck" },
  { ResponseMessage_masterSlaveDeterminationReject, "masterSlaveDeterminationReject" },
  { ResponseMessage_terminalCapabilitySetAck, "terminalCapabilitySetAck" },
  { ResponseMessage_terminalCapabilitySetReject, "terminalCapabilitySetReject" },
  { ResponseMessage_openLogicalChannelAck, "openLogicalChannelAck" },
  { ResponseMessage_openLogicalChannelReject, "openLogicalChannelReject" },
  { ResponseMessage_closeLogicalChannelAck, "closeLogicalChannelAck" },
  { ResponseMessage_requestChannelCloseAck, "requestChannelCloseAck" },
  { ResponseMessage_requestChannelCloseReject, "requestChannelCloseReject" },
  { ResponseMessage_multiplexEntrySendAck, "multiplexEntrySendAck" },
  { ResponseMessage_multiplexEntrySendReject, "multiplexEntrySendReject" },
  { ResponseMessage_requestMultiplexEntryAck, "requestMultiplexEntryAck" },
  { ResponseMessage_requestMultiplexEntryReject, "requestMultiplexEntryReject" },
  { ResponseMessage_requestModeAck, "requestModeAck" },
  { ResponseMessage_requestModeReject, "requestModeReject" },
  { ResponseMessage_roundTripDelayResponse, "roundTripDelayResponse" },
  { ResponseMessage_maintenanceLoopAck, "maintenanceLoopAck" },
  { ResponseMessage_maintenanceLoopReject, "maintenanceLoopReject" },
  { ResponseMessage_communicationModeResponse, "communicationModeResponse" },
  { ResponseMessage_conferenceResponse, "conferenceResponse" },
  { ResponseMessage_multilinkResponse, "multilinkResponse" },
  { ResponseMessage_logicalChannelRateAcknowledge, "logicalChannelRateAcknowledge" },
  { ResponseMessage_logicalChannelRateReject, "logicalChannelRateReject" },
  { ResponseMessage_genericResponse, "genericResponse" },
  { 0, NULL }
};

static const per_choice_t ResponseMessage_choice[] = {
  { ResponseMessage_nonStandard, &hf_h245_nonStandardMsg , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardMessage },
  { ResponseMessage_masterSlaveDeterminationAck, &hf_h245_masterSlaveDeterminationAck, ASN1_EXTENSION_ROOT    , dissect_h245_MasterSlaveDeterminationAck },
  { ResponseMessage_masterSlaveDeterminationReject, &hf_h245_masterSlaveDeterminationReject, ASN1_EXTENSION_ROOT    , dissect_h245_MasterSlaveDeterminationReject },
  { ResponseMessage_terminalCapabilitySetAck, &hf_h245_terminalCapabilitySetAck, ASN1_EXTENSION_ROOT    , dissect_h245_TerminalCapabilitySetAck },
  { ResponseMessage_terminalCapabilitySetReject, &hf_h245_terminalCapabilitySetReject, ASN1_EXTENSION_ROOT    , dissect_h245_TerminalCapabilitySetReject },
  { ResponseMessage_openLogicalChannelAck, &hf_h245_openLogicalChannelAck, ASN1_EXTENSION_ROOT    , dissect_h245_OpenLogicalChannelAck },
  { ResponseMessage_openLogicalChannelReject, &hf_h245_openLogicalChannelReject, ASN1_EXTENSION_ROOT    , dissect_h245_OpenLogicalChannelReject },
  { ResponseMessage_closeLogicalChannelAck, &hf_h245_closeLogicalChannelAck, ASN1_EXTENSION_ROOT    , dissect_h245_CloseLogicalChannelAck },
  { ResponseMessage_requestChannelCloseAck, &hf_h245_requestChannelCloseAck, ASN1_EXTENSION_ROOT    , dissect_h245_RequestChannelCloseAck },
  { ResponseMessage_requestChannelCloseReject, &hf_h245_requestChannelCloseReject, ASN1_EXTENSION_ROOT    , dissect_h245_RequestChannelCloseReject },
  { ResponseMessage_multiplexEntrySendAck, &hf_h245_multiplexEntrySendAck, ASN1_EXTENSION_ROOT    , dissect_h245_MultiplexEntrySendAck },
  { ResponseMessage_multiplexEntrySendReject, &hf_h245_multiplexEntrySendReject, ASN1_EXTENSION_ROOT    , dissect_h245_MultiplexEntrySendReject },
  { ResponseMessage_requestMultiplexEntryAck, &hf_h245_requestMultiplexEntryAck, ASN1_EXTENSION_ROOT    , dissect_h245_RequestMultiplexEntryAck },
  { ResponseMessage_requestMultiplexEntryReject, &hf_h245_requestMultiplexEntryReject, ASN1_EXTENSION_ROOT    , dissect_h245_RequestMultiplexEntryReject },
  { ResponseMessage_requestModeAck, &hf_h245_requestModeAck , ASN1_EXTENSION_ROOT    , dissect_h245_RequestModeAck },
  { ResponseMessage_requestModeReject, &hf_h245_requestModeReject, ASN1_EXTENSION_ROOT    , dissect_h245_RequestModeReject },
  { ResponseMessage_roundTripDelayResponse, &hf_h245_roundTripDelayResponse, ASN1_EXTENSION_ROOT    , dissect_h245_RoundTripDelayResponse },
  { ResponseMessage_maintenanceLoopAck, &hf_h245_maintenanceLoopAck, ASN1_EXTENSION_ROOT    , dissect_h245_MaintenanceLoopAck },
  { ResponseMessage_maintenanceLoopReject, &hf_h245_maintenanceLoopReject, ASN1_EXTENSION_ROOT    , dissect_h245_MaintenanceLoopReject },
  { ResponseMessage_communicationModeResponse, &hf_h245_communicationModeResponse, ASN1_NOT_EXTENSION_ROOT, dissect_h245_CommunicationModeResponse },
  { ResponseMessage_conferenceResponse, &hf_h245_conferenceResponse, ASN1_NOT_EXTENSION_ROOT, dissect_h245_ConferenceResponse },
  { ResponseMessage_multilinkResponse, &hf_h245_multilinkResponse, ASN1_NOT_EXTENSION_ROOT, dissect_h245_MultilinkResponse },
  { ResponseMessage_logicalChannelRateAcknowledge, &hf_h245_logicalChannelRateAcknowledge, ASN1_NOT_EXTENSION_ROOT, dissect_h245_LogicalChannelRateAcknowledge },
  { ResponseMessage_logicalChannelRateReject, &hf_h245_logicalChannelRateReject, ASN1_NOT_EXTENSION_ROOT, dissect_h245_LogicalChannelRateReject },
  { ResponseMessage_genericResponse, &hf_h245_genericResponse, ASN1_NOT_EXTENSION_ROOT, dissect_h245_GenericMessage },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_ResponseMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 408 "../../asn1/h245/h245.cnf"
  gint32 value;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_ResponseMessage, ResponseMessage_choice,
                                 &value);

	    if ( h245_shorttypes == TRUE )
	        {
	        	col_prepend_fstr(actx->pinfo->cinfo, COL_INFO, "%s ",
				val_to_str(value, h245_ResponseMessage_short_vals, "<unknown>"));
		}
		else
		{
	        	col_prepend_fstr(actx->pinfo->cinfo, COL_INFO, "%s ",
				val_to_str(value, h245_ResponseMessage_vals, "<unknown>"));
		}

	col_set_fence(actx->pinfo->cinfo,COL_INFO);

	if (h245_pi != NULL){
		/* Add to packet info */
		if ( strlen(h245_pi->frame_label) == 0 ){
		   g_snprintf(h245_pi->frame_label, 50, "%s", val_to_str(value, h245_ResponseMessage_short_vals, "UKN"));
		}
		g_strlcat(h245_pi->comment, val_to_str(value, h245_ResponseMessage_vals, "<unknown>"), 50);
	}



  return offset;
}


static const per_sequence_t MaintenanceLoopOffCommand_sequence[] = {
  { NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};

static int
dissect_h245_MaintenanceLoopOffCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MaintenanceLoopOffCommand, MaintenanceLoopOffCommand_sequence);

  return offset;
}


static const per_sequence_t SET_SIZE_1_65535_OF_CapabilityTableEntryNumber_set_of[1] = {
  { &hf_h245_capabilityTableEntryNumbers_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_CapabilityTableEntryNumber },
};

static int
dissect_h245_SET_SIZE_1_65535_OF_CapabilityTableEntryNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h245_SET_SIZE_1_65535_OF_CapabilityTableEntryNumber, SET_SIZE_1_65535_OF_CapabilityTableEntryNumber_set_of,
                                             1, 65535, FALSE);

  return offset;
}


static const per_sequence_t SET_SIZE_1_256_OF_CapabilityDescriptorNumber_set_of[1] = {
  { &hf_h245_capabilityDescriptorNumbers_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_CapabilityDescriptorNumber },
};

static int
dissect_h245_SET_SIZE_1_256_OF_CapabilityDescriptorNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h245_SET_SIZE_1_256_OF_CapabilityDescriptorNumber, SET_SIZE_1_256_OF_CapabilityDescriptorNumber_set_of,
                                             1, 256, FALSE);

  return offset;
}


static const per_sequence_t T_specificRequest_sequence[] = {
  { &hf_h245_multiplexCapabilityBool, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_capabilityTableEntryNumbers, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_SET_SIZE_1_65535_OF_CapabilityTableEntryNumber },
  { &hf_h245_capabilityDescriptorNumbers, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_SET_SIZE_1_256_OF_CapabilityDescriptorNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_specificRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_specificRequest, T_specificRequest_sequence);

  return offset;
}


static const value_string h245_SendTerminalCapabilitySet_vals[] = {
  {   0, "specificRequest" },
  {   1, "genericRequest" },
  { 0, NULL }
};

static const per_choice_t SendTerminalCapabilitySet_choice[] = {
  {   0, &hf_h245_specificRequest, ASN1_EXTENSION_ROOT    , dissect_h245_T_specificRequest },
  {   1, &hf_h245_genericRequestFlag, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_SendTerminalCapabilitySet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_SendTerminalCapabilitySet, SendTerminalCapabilitySet_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_encryptionAlgorithmID_sequence[] = {
  { &hf_h245_h233AlgorithmIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_SequenceNumber },
  { &hf_h245_associatedAlgorithm, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_NonStandardParameter },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_encryptionAlgorithmID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_encryptionAlgorithmID, T_encryptionAlgorithmID_sequence);

  return offset;
}


static const value_string h245_EncryptionCommand_vals[] = {
  {   0, "encryptionSE" },
  {   1, "encryptionIVRequest" },
  {   2, "encryptionAlgorithmID" },
  { 0, NULL }
};

static const per_choice_t EncryptionCommand_choice[] = {
  {   0, &hf_h245_encryptionSE   , ASN1_EXTENSION_ROOT    , dissect_h245_OCTET_STRING },
  {   1, &hf_h245_encryptionIVRequest, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_encryptionAlgorithmID, ASN1_EXTENSION_ROOT    , dissect_h245_T_encryptionAlgorithmID },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_EncryptionCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_EncryptionCommand, EncryptionCommand_choice,
                                 NULL);

  return offset;
}


static const value_string h245_Scope_vals[] = {
  {   0, "logicalChannelNumber" },
  {   1, "resourceID" },
  {   2, "wholeMultiplex" },
  { 0, NULL }
};

static const per_choice_t Scope_choice[] = {
  {   0, &hf_h245_logicalChannelNumber, ASN1_NO_EXTENSIONS     , dissect_h245_LogicalChannelNumber },
  {   1, &hf_h245_resourceID     , ASN1_NO_EXTENSIONS     , dissect_h245_INTEGER_0_65535 },
  {   2, &hf_h245_wholeMultiplex , ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_Scope(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_Scope, Scope_choice,
                                 NULL);

  return offset;
}


static const value_string h245_Restriction_vals[] = {
  {   0, "maximumBitRate" },
  {   1, "noRestriction" },
  { 0, NULL }
};

static const per_choice_t Restriction_choice[] = {
  {   0, &hf_h245_res_maximumBitRate, ASN1_NO_EXTENSIONS     , dissect_h245_INTEGER_0_16777215 },
  {   1, &hf_h245_noRestriction  , ASN1_NO_EXTENSIONS     , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_Restriction(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_Restriction, Restriction_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t FlowControlCommand_sequence[] = {
  { &hf_h245_scope          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_Scope },
  { &hf_h245_restriction    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_Restriction },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_FlowControlCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_FlowControlCommand, FlowControlCommand_sequence);

  return offset;
}


static const value_string h245_T_gstnOptions_vals[] = {
  {   0, "telephonyMode" },
  {   1, "v8bis" },
  {   2, "v34DSVD" },
  {   3, "v34DuplexFAX" },
  {   4, "v34H324" },
  { 0, NULL }
};

static const per_choice_t T_gstnOptions_choice[] = {
  {   0, &hf_h245_telephonyMode  , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_v8bis          , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_v34DSVD        , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   3, &hf_h245_v34DuplexFAX   , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   4, &hf_h245_v34H324        , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_gstnOptions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_gstnOptions, T_gstnOptions_choice,
                                 NULL);

  return offset;
}


static const value_string h245_T_isdnOptions_vals[] = {
  {   0, "telephonyMode" },
  {   1, "v140" },
  {   2, "terminalOnHold" },
  { 0, NULL }
};

static const per_choice_t T_isdnOptions_choice[] = {
  {   0, &hf_h245_telephonyMode  , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_v140           , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_terminalOnHold , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_isdnOptions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_isdnOptions, T_isdnOptions_choice,
                                 NULL);

  return offset;
}


static const value_string h245_EndSessionCommand_vals[] = {
  {   0, "nonStandard" },
  {   1, "disconnect" },
  {   2, "gstnOptions" },
  {   3, "isdnOptions" },
  {   4, "genericInformation" },
  { 0, NULL }
};

static const per_choice_t EndSessionCommand_choice[] = {
  {   0, &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardParameter },
  {   1, &hf_h245_disconnect     , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_gstnOptions    , ASN1_EXTENSION_ROOT    , dissect_h245_T_gstnOptions },
  {   3, &hf_h245_isdnOptions    , ASN1_NOT_EXTENSION_ROOT, dissect_h245_T_isdnOptions },
  {   4, &hf_h245_genericInformation, ASN1_NOT_EXTENSION_ROOT, dissect_h245_SEQUENCE_OF_GenericInformation },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_EndSessionCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_EndSessionCommand, EndSessionCommand_choice,
                                 NULL);

  return offset;
}



static int
dissect_h245_INTEGER_0_17(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 17U, NULL, FALSE);

  return offset;
}



static int
dissect_h245_INTEGER_1_18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 18U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_videoFastUpdateGOB_sequence[] = {
  { &hf_h245_firstGOB       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_17 },
  { &hf_h245_numberOfGOBs   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_18 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_videoFastUpdateGOB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_videoFastUpdateGOB, T_videoFastUpdateGOB_sequence);

  return offset;
}



static int
dissect_h245_INTEGER_0_31(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 31U, NULL, FALSE);

  return offset;
}



static int
dissect_h245_INTEGER_1_8192(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 8192U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_videoFastUpdateMB_sequence[] = {
  { &hf_h245_firstGOB_0_255 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_255 },
  { &hf_h245_firstMB_1_8192 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_8192 },
  { &hf_h245_numberOfMBs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_8192 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_videoFastUpdateMB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_videoFastUpdateMB, T_videoFastUpdateMB_sequence);

  return offset;
}


static const per_sequence_t KeyProtectionMethod_sequence[] = {
  { &hf_h245_secureChannel  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_sharedSecret   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_certProtectedKey, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_KeyProtectionMethod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_KeyProtectionMethod, KeyProtectionMethod_sequence);

  return offset;
}


static const per_sequence_t EncryptionUpdateRequest_sequence[] = {
  { &hf_h245_keyProtectionMethod, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_KeyProtectionMethod },
  { &hf_h245_synchFlag      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_EncryptionUpdateRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_EncryptionUpdateRequest, EncryptionUpdateRequest_sequence);

  return offset;
}


static const value_string h245_T_repeatCount_vals[] = {
  {   0, "doOneProgression" },
  {   1, "doContinuousProgressions" },
  {   2, "doOneIndependentProgression" },
  {   3, "doContinuousIndependentProgressions" },
  { 0, NULL }
};

static const per_choice_t T_repeatCount_choice[] = {
  {   0, &hf_h245_doOneProgression, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_doContinuousProgressions, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_doOneIndependentProgression, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   3, &hf_h245_doContinuousIndependentProgressions, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_repeatCount(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_repeatCount, T_repeatCount_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_progressiveRefinementStart_sequence[] = {
  { &hf_h245_repeatCount    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_repeatCount },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_progressiveRefinementStart(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_progressiveRefinementStart, T_progressiveRefinementStart_sequence);

  return offset;
}



static int
dissect_h245_INTEGER_1_9216(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 9216U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_videoBadMBs_sequence[] = {
  { &hf_h245_firstMB        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_9216 },
  { &hf_h245_numberOfMBs1_1_9216, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_9216 },
  { &hf_h245_temporalReference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_1023 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_videoBadMBs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_videoBadMBs, T_videoBadMBs_sequence);

  return offset;
}


static const value_string h245_PictureReference_vals[] = {
  {   0, "pictureNumber" },
  {   1, "longTermPictureIndex" },
  { 0, NULL }
};

static const per_choice_t PictureReference_choice[] = {
  {   0, &hf_h245_pictureNumber  , ASN1_EXTENSION_ROOT    , dissect_h245_INTEGER_0_1023 },
  {   1, &hf_h245_longTermPictureIndex, ASN1_EXTENSION_ROOT    , dissect_h245_INTEGER_0_255 },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_PictureReference(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_PictureReference, PictureReference_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_PictureReference_sequence_of[1] = {
  { &hf_h245_lostPicture_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245_PictureReference },
};

static int
dissect_h245_SEQUENCE_OF_PictureReference(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h245_SEQUENCE_OF_PictureReference, SEQUENCE_OF_PictureReference_sequence_of);

  return offset;
}


static const per_sequence_t T_lostPartialPicture_sequence[] = {
  { &hf_h245_pictureReference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_PictureReference },
  { &hf_h245_firstMB        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_9216 },
  { &hf_h245_numberOfMBs1_1_9216, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_9216 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_lostPartialPicture(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_lostPartialPicture, T_lostPartialPicture_sequence);

  return offset;
}


static const per_sequence_t T_encryptionUpdateCommand_sequence[] = {
  { &hf_h245_encryptionSync , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_EncryptionSync },
  { &hf_h245_multiplePayloadStream, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_MultiplePayloadStream },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_encryptionUpdateCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_encryptionUpdateCommand, T_encryptionUpdateCommand_sequence);

  return offset;
}


static const per_sequence_t T_encryptionUpdateAck_sequence[] = {
  { &hf_h245_synchFlag      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_encryptionUpdateAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_encryptionUpdateAck, T_encryptionUpdateAck_sequence);

  return offset;
}


static const value_string h245_Mc_type_vals[] = {
  {   0, "equaliseDelay" },
  {   1, "zeroDelay" },
  {   2, "multipointModeCommand" },
  {   3, "cancelMultipointModeCommand" },
  {   4, "videoFreezePicture" },
  {   5, "videoFastUpdatePicture" },
  {   6, "videoFastUpdateGOB" },
  {   7, "videoTemporalSpatialTradeOff" },
  {   8, "videoSendSyncEveryGOB" },
  {   9, "videoSendSyncEveryGOBCancel" },
  {  10, "videoFastUpdateMB" },
  {  11, "maxH223MUXPDUsize" },
  {  12, "encryptionUpdate" },
  {  13, "encryptionUpdateRequest" },
  {  14, "switchReceiveMediaOff" },
  {  15, "switchReceiveMediaOn" },
  {  16, "progressiveRefinementStart" },
  {  17, "progressiveRefinementAbortOne" },
  {  18, "progressiveRefinementAbortContinuous" },
  {  19, "videoBadMBs" },
  {  20, "lostPicture" },
  {  21, "lostPartialPicture" },
  {  22, "recoveryReferencePicture" },
  {  23, "encryptionUpdateCommand" },
  {  24, "encryptionUpdateAck" },
  { 0, NULL }
};

static const per_choice_t Mc_type_choice[] = {
  {   0, &hf_h245_equaliseDelay  , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_zeroDelay      , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_multipointModeCommand, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   3, &hf_h245_cancelMultipointModeCommand, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   4, &hf_h245_videoFreezePicture, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   5, &hf_h245_videoFastUpdatePicture, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   6, &hf_h245_videoFastUpdateGOB, ASN1_EXTENSION_ROOT    , dissect_h245_T_videoFastUpdateGOB },
  {   7, &hf_h245_videoTemporalSpatialTradeOff, ASN1_EXTENSION_ROOT    , dissect_h245_INTEGER_0_31 },
  {   8, &hf_h245_videoSendSyncEveryGOB, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   9, &hf_h245_videoSendSyncEveryGOBCancel, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {  10, &hf_h245_videoFastUpdateMB, ASN1_NOT_EXTENSION_ROOT, dissect_h245_T_videoFastUpdateMB },
  {  11, &hf_h245_maxH223MUXPDUsize, ASN1_NOT_EXTENSION_ROOT, dissect_h245_INTEGER_1_65535 },
  {  12, &hf_h245_encryptionUpdate, ASN1_NOT_EXTENSION_ROOT, dissect_h245_EncryptionSync },
  {  13, &hf_h245_encryptionUpdateRequest, ASN1_NOT_EXTENSION_ROOT, dissect_h245_EncryptionUpdateRequest },
  {  14, &hf_h245_switchReceiveMediaOff, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {  15, &hf_h245_switchReceiveMediaOn, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {  16, &hf_h245_progressiveRefinementStart, ASN1_NOT_EXTENSION_ROOT, dissect_h245_T_progressiveRefinementStart },
  {  17, &hf_h245_progressiveRefinementAbortOne, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {  18, &hf_h245_progressiveRefinementAbortContinuous, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {  19, &hf_h245_videoBadMBs    , ASN1_NOT_EXTENSION_ROOT, dissect_h245_T_videoBadMBs },
  {  20, &hf_h245_lostPicture    , ASN1_NOT_EXTENSION_ROOT, dissect_h245_SEQUENCE_OF_PictureReference },
  {  21, &hf_h245_lostPartialPicture, ASN1_NOT_EXTENSION_ROOT, dissect_h245_T_lostPartialPicture },
  {  22, &hf_h245_recoveryReferencePicture, ASN1_NOT_EXTENSION_ROOT, dissect_h245_SEQUENCE_OF_PictureReference },
  {  23, &hf_h245_encryptionUpdateCommand, ASN1_NOT_EXTENSION_ROOT, dissect_h245_T_encryptionUpdateCommand },
  {  24, &hf_h245_encryptionUpdateAck, ASN1_NOT_EXTENSION_ROOT, dissect_h245_T_encryptionUpdateAck },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_Mc_type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_Mc_type, Mc_type_choice,
                                 NULL);

  return offset;
}


static const value_string h245_EncryptionUpdateDirection_vals[] = {
  {   0, "masterToSlave" },
  {   1, "slaveToMaster" },
  { 0, NULL }
};

static const per_choice_t EncryptionUpdateDirection_choice[] = {
  {   0, &hf_h245_masterToSlave  , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_slaveToMaster  , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_EncryptionUpdateDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_EncryptionUpdateDirection, EncryptionUpdateDirection_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MiscellaneousCommand_sequence[] = {
  { &hf_h245_logicalChannelNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_LogicalChannelNumber },
  { &hf_h245_mc_type        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_Mc_type },
  { &hf_h245_direction      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_EncryptionUpdateDirection },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MiscellaneousCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MiscellaneousCommand, MiscellaneousCommand_sequence);

  return offset;
}


static const per_sequence_t CommunicationModeCommand_sequence[] = {
  { &hf_h245_communicationModeTable, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SET_SIZE_1_256_OF_CommunicationModeTableEntry },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_CommunicationModeCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_CommunicationModeCommand, CommunicationModeCommand_sequence);

  return offset;
}


static const per_sequence_t SubstituteConferenceIDCommand_sequence[] = {
  { &hf_h245_conferenceIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_OCTET_STRING_SIZE_16 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_SubstituteConferenceIDCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_SubstituteConferenceIDCommand, SubstituteConferenceIDCommand_sequence);

  return offset;
}


static const value_string h245_ConferenceCommand_vals[] = {
  {   0, "broadcastMyLogicalChannel" },
  {   1, "cancelBroadcastMyLogicalChannel" },
  {   2, "makeTerminalBroadcaster" },
  {   3, "cancelMakeTerminalBroadcaster" },
  {   4, "sendThisSource" },
  {   5, "cancelSendThisSource" },
  {   6, "dropConference" },
  {   7, "substituteConferenceIDCommand" },
  { 0, NULL }
};

static const per_choice_t ConferenceCommand_choice[] = {
  {   0, &hf_h245_broadcastMyLogicalChannel, ASN1_EXTENSION_ROOT    , dissect_h245_LogicalChannelNumber },
  {   1, &hf_h245_cancelBroadcastMyLogicalChannel, ASN1_EXTENSION_ROOT    , dissect_h245_LogicalChannelNumber },
  {   2, &hf_h245_makeTerminalBroadcaster, ASN1_EXTENSION_ROOT    , dissect_h245_TerminalLabel },
  {   3, &hf_h245_cancelMakeTerminalBroadcaster, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   4, &hf_h245_sendThisSource , ASN1_EXTENSION_ROOT    , dissect_h245_TerminalLabel },
  {   5, &hf_h245_cancelSendThisSource, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   6, &hf_h245_dropConference , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   7, &hf_h245_substituteConferenceIDCommand, ASN1_NOT_EXTENSION_ROOT, dissect_h245_SubstituteConferenceIDCommand },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_ConferenceCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_ConferenceCommand, ConferenceCommand_choice,
                                 NULL);

  return offset;
}


static const value_string h245_T_h223ModeChange_vals[] = {
  {   0, "toLevel0" },
  {   1, "toLevel1" },
  {   2, "toLevel2" },
  {   3, "toLevel2withOptionalHeader" },
  { 0, NULL }
};

static const per_choice_t T_h223ModeChange_choice[] = {
  {   0, &hf_h245_toLevel0       , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_toLevel1       , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_toLevel2       , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   3, &hf_h245_toLevel2withOptionalHeader, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_h223ModeChange(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_h223ModeChange, T_h223ModeChange_choice,
                                 NULL);

  return offset;
}


static const value_string h245_T_h223AnnexADoubleFlag_vals[] = {
  {   0, "start" },
  {   1, "stop" },
  { 0, NULL }
};

static const per_choice_t T_h223AnnexADoubleFlag_choice[] = {
  {   0, &hf_h245_start          , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_stop           , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_h223AnnexADoubleFlag(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_h223AnnexADoubleFlag, T_h223AnnexADoubleFlag_choice,
                                 NULL);

  return offset;
}


static const value_string h245_H223MultiplexReconfiguration_vals[] = {
  {   0, "h223ModeChange" },
  {   1, "h223AnnexADoubleFlag" },
  { 0, NULL }
};

static const per_choice_t H223MultiplexReconfiguration_choice[] = {
  {   0, &hf_h245_h223ModeChange , ASN1_EXTENSION_ROOT    , dissect_h245_T_h223ModeChange },
  {   1, &hf_h245_h223AnnexADoubleFlag, ASN1_EXTENSION_ROOT    , dissect_h245_T_h223AnnexADoubleFlag },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_H223MultiplexReconfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_H223MultiplexReconfiguration, H223MultiplexReconfiguration_choice,
                                 NULL);

  return offset;
}


static const value_string h245_Cmd_clockRecovery_vals[] = {
  {   0, "nullClockRecovery" },
  {   1, "srtsClockRecovery" },
  {   2, "adaptiveClockRecovery" },
  { 0, NULL }
};

static const per_choice_t Cmd_clockRecovery_choice[] = {
  {   0, &hf_h245_nullClockRecoveryflag, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_srtsClockRecovery, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_adaptiveClockRecoveryFlag, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_Cmd_clockRecovery(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_Cmd_clockRecovery, Cmd_clockRecovery_choice,
                                 NULL);

  return offset;
}


static const value_string h245_Cmd_errorCorrection_vals[] = {
  {   0, "nullErrorCorrection" },
  {   1, "longInterleaver" },
  {   2, "shortInterleaver" },
  {   3, "errorCorrectionOnly" },
  { 0, NULL }
};

static const per_choice_t Cmd_errorCorrection_choice[] = {
  {   0, &hf_h245_nullErrorCorrectionFlag, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_longInterleaverFlag, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_shortInterleaverFlag, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   3, &hf_h245_errorCorrectionOnlyFlag, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_Cmd_errorCorrection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_Cmd_errorCorrection, Cmd_errorCorrection_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Cmd_aal1_sequence[] = {
  { &hf_h245_cmd_clockRecovery, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_Cmd_clockRecovery },
  { &hf_h245_cmd_errorCorrection, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_Cmd_errorCorrection },
  { &hf_h245_structuredDataTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_partiallyFilledCells, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_Cmd_aal1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_Cmd_aal1, Cmd_aal1_sequence);

  return offset;
}


static const per_sequence_t Cmd_aal5_sequence[] = {
  { &hf_h245_forwardMaximumSDUSize, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_65535 },
  { &hf_h245_backwardMaximumSDUSize, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_65535 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_Cmd_aal5(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_Cmd_aal5, Cmd_aal5_sequence);

  return offset;
}


static const value_string h245_Cmd_aal_vals[] = {
  {   0, "aal1" },
  {   1, "aal5" },
  { 0, NULL }
};

static const per_choice_t Cmd_aal_choice[] = {
  {   0, &hf_h245_cmd_aal1       , ASN1_EXTENSION_ROOT    , dissect_h245_Cmd_aal1 },
  {   1, &hf_h245_cmd_aal5       , ASN1_EXTENSION_ROOT    , dissect_h245_Cmd_aal5 },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_Cmd_aal(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_Cmd_aal, Cmd_aal_choice,
                                 NULL);

  return offset;
}


static const value_string h245_Cmd_multiplex_vals[] = {
  {   0, "noMultiplex" },
  {   1, "transportStream" },
  {   2, "programStream" },
  { 0, NULL }
};

static const per_choice_t Cmd_multiplex_choice[] = {
  {   0, &hf_h245_noMultiplex    , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_transportStream, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_programStreamFlag, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_Cmd_multiplex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_Cmd_multiplex, Cmd_multiplex_choice,
                                 NULL);

  return offset;
}


static const value_string h245_CmdR_multiplex_vals[] = {
  {   0, "noMultiplex" },
  {   1, "transportStream" },
  {   2, "programStream" },
  { 0, NULL }
};

static const per_choice_t CmdR_multiplex_choice[] = {
  {   0, &hf_h245_noMultiplex    , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_transportStream, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_programStreamFlag, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_CmdR_multiplex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_CmdR_multiplex, CmdR_multiplex_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Cmd_reverseParameters_sequence[] = {
  { &hf_h245_bitRate        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_65535 },
  { &hf_h245_bitRateLockedToPCRClock, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_bitRateLockedToNetworkClock, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_cmdr_multiplex , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_CmdR_multiplex },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_Cmd_reverseParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_Cmd_reverseParameters, Cmd_reverseParameters_sequence);

  return offset;
}


static const per_sequence_t NewATMVCCommand_sequence[] = {
  { &hf_h245_resourceID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_65535 },
  { &hf_h245_bitRate        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_65535 },
  { &hf_h245_bitRateLockedToPCRClock, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_bitRateLockedToNetworkClock, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_cmd_aal        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_Cmd_aal },
  { &hf_h245_cmd_multiplex  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_Cmd_multiplex },
  { &hf_h245_cmd_reverseParameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_Cmd_reverseParameters },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_NewATMVCCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_NewATMVCCommand, NewATMVCCommand_sequence);

  return offset;
}


static const value_string h245_T_status_vals[] = {
  {   0, "synchronized" },
  {   1, "reconfiguration" },
  { 0, NULL }
};

static const per_choice_t T_status_choice[] = {
  {   0, &hf_h245_synchronized   , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_reconfiguration, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_status(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_status, T_status_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MobileMultilinkReconfigurationCommand_sequence[] = {
  { &hf_h245_sampleSize     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_255 },
  { &hf_h245_samplesPerFrame, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_255 },
  { &hf_h245_status         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_status },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MobileMultilinkReconfigurationCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MobileMultilinkReconfigurationCommand, MobileMultilinkReconfigurationCommand_sequence);

  return offset;
}


static const value_string h245_CommandMessage_vals[] = {
  { CommandMessage_nonStandard, "nonStandard" },
  { CommandMessage_maintenanceLoopOffCommand, "maintenanceLoopOffCommand" },
  { CommandMessage_sendTerminalCapabilitySet, "sendTerminalCapabilitySet" },
  { CommandMessage_encryptionCommand, "encryptionCommand" },
  { CommandMessage_flowControlCommand, "flowControlCommand" },
  { CommandMessage_endSessionCommand, "endSessionCommand" },
  { CommandMessage_miscellaneousCommand, "miscellaneousCommand" },
  { CommandMessage_communicationModeCommand, "communicationModeCommand" },
  { CommandMessage_conferenceCommand, "conferenceCommand" },
  { CommandMessage_h223MultiplexReconfiguration, "h223MultiplexReconfiguration" },
  { CommandMessage_newATMVCCommand, "newATMVCCommand" },
  { CommandMessage_mobileMultilinkReconfigurationCommand, "mobileMultilinkReconfigurationCommand" },
  { CommandMessage_genericCommand, "genericCommand" },
  { 0, NULL }
};

static const per_choice_t CommandMessage_choice[] = {
  { CommandMessage_nonStandard, &hf_h245_nonStandardMsg , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardMessage },
  { CommandMessage_maintenanceLoopOffCommand, &hf_h245_maintenanceLoopOffCommand, ASN1_EXTENSION_ROOT    , dissect_h245_MaintenanceLoopOffCommand },
  { CommandMessage_sendTerminalCapabilitySet, &hf_h245_sendTerminalCapabilitySet, ASN1_EXTENSION_ROOT    , dissect_h245_SendTerminalCapabilitySet },
  { CommandMessage_encryptionCommand, &hf_h245_encryptionCommand, ASN1_EXTENSION_ROOT    , dissect_h245_EncryptionCommand },
  { CommandMessage_flowControlCommand, &hf_h245_flowControlCommand, ASN1_EXTENSION_ROOT    , dissect_h245_FlowControlCommand },
  { CommandMessage_endSessionCommand, &hf_h245_endSessionCommand, ASN1_EXTENSION_ROOT    , dissect_h245_EndSessionCommand },
  { CommandMessage_miscellaneousCommand, &hf_h245_miscellaneousCommand, ASN1_EXTENSION_ROOT    , dissect_h245_MiscellaneousCommand },
  { CommandMessage_communicationModeCommand, &hf_h245_communicationModeCommand, ASN1_NOT_EXTENSION_ROOT, dissect_h245_CommunicationModeCommand },
  { CommandMessage_conferenceCommand, &hf_h245_conferenceCommand, ASN1_NOT_EXTENSION_ROOT, dissect_h245_ConferenceCommand },
  { CommandMessage_h223MultiplexReconfiguration, &hf_h245_h223MultiplexReconfiguration, ASN1_NOT_EXTENSION_ROOT, dissect_h245_H223MultiplexReconfiguration },
  { CommandMessage_newATMVCCommand, &hf_h245_newATMVCCommand, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NewATMVCCommand },
  { CommandMessage_mobileMultilinkReconfigurationCommand, &hf_h245_mobileMultilinkReconfigurationCommand, ASN1_NOT_EXTENSION_ROOT, dissect_h245_MobileMultilinkReconfigurationCommand },
  { CommandMessage_genericCommand, &hf_h245_genericCommand , ASN1_NOT_EXTENSION_ROOT, dissect_h245_GenericMessage },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_CommandMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 462 "../../asn1/h245/h245.cnf"
  gint32 value;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_CommandMessage, CommandMessage_choice,
                                 &value);

	   if ( h245_shorttypes == TRUE )
	        {
	        	col_prepend_fstr(actx->pinfo->cinfo, COL_INFO, "%s ",
				val_to_str(value, h245_CommandMessage_short_vals, "<unknown>"));
		}
		else
		{
	        	col_prepend_fstr(actx->pinfo->cinfo, COL_INFO, "%s ",
				val_to_str(value, h245_CommandMessage_vals, "<unknown>"));
		}

	col_set_fence(actx->pinfo->cinfo,COL_INFO);
    /* Add to packet info */
    if (h245_pi != NULL){
      if ( strlen(h245_pi->frame_label) == 0 ){
        g_snprintf(h245_pi->frame_label, 50, "%s", val_to_str(value, h245_CommandMessage_short_vals, "UKN"));
      }
	  g_strlcat(h245_pi->comment, val_to_str(value, h245_CommandMessage_vals, "<unknown>"), 50);
    }



  return offset;
}


static const value_string h245_FunctionNotUnderstood_vals[] = {
  {   0, "request" },
  {   1, "response" },
  {   2, "command" },
  { 0, NULL }
};

static const per_choice_t FunctionNotUnderstood_choice[] = {
  {   0, &hf_h245_request        , ASN1_NO_EXTENSIONS     , dissect_h245_RequestMessage },
  {   1, &hf_h245_response       , ASN1_NO_EXTENSIONS     , dissect_h245_ResponseMessage },
  {   2, &hf_h245_command        , ASN1_NO_EXTENSIONS     , dissect_h245_CommandMessage },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_FunctionNotUnderstood(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_FunctionNotUnderstood, FunctionNotUnderstood_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MasterSlaveDeterminationRelease_sequence[] = {
  { NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};

static int
dissect_h245_MasterSlaveDeterminationRelease(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MasterSlaveDeterminationRelease, MasterSlaveDeterminationRelease_sequence);

#line 585 "../../asn1/h245/h245.cnf"

if (h245_pi != NULL)
  h245_pi->msg_type = H245_MastSlvDetRls;

  return offset;
}


static const per_sequence_t TerminalCapabilitySetRelease_sequence[] = {
  { &hf_h245_genericInformation, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_SEQUENCE_OF_GenericInformation },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_TerminalCapabilitySetRelease(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_TerminalCapabilitySetRelease, TerminalCapabilitySetRelease_sequence);

#line 597 "../../asn1/h245/h245.cnf"

if (h245_pi != NULL)
  h245_pi->msg_type = H245_TermCapSetRls;

  return offset;
}


static const per_sequence_t OpenLogicalChannelConfirm_sequence[] = {
  { &hf_h245_forwardLogicalChannelNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_LogicalChannelNumber },
  { &hf_h245_genericInformation, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_SEQUENCE_OF_GenericInformation },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_OpenLogicalChannelConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_OpenLogicalChannelConfirm, OpenLogicalChannelConfirm_sequence);

#line 561 "../../asn1/h245/h245.cnf"

if (h245_pi != NULL)
  h245_pi->msg_type = H245_OpenLogChnCnf;

  return offset;
}


static const per_sequence_t RequestChannelCloseRelease_sequence[] = {
  { &hf_h245_forwardLogicalChannelNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_LogicalChannelNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RequestChannelCloseRelease(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RequestChannelCloseRelease, RequestChannelCloseRelease_sequence);

  return offset;
}


static const per_sequence_t MultiplexEntrySendRelease_sequence[] = {
  { &hf_h245_multiplexTableEntryNumbers, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SET_SIZE_1_15_OF_MultiplexTableEntryNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MultiplexEntrySendRelease(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MultiplexEntrySendRelease, MultiplexEntrySendRelease_sequence);

  return offset;
}


static const per_sequence_t RequestMultiplexEntryRelease_sequence[] = {
  { &hf_h245_entryNumbers   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_SET_SIZE_1_15_OF_MultiplexTableEntryNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_RequestMultiplexEntryRelease(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RequestMultiplexEntryRelease, RequestMultiplexEntryRelease_sequence);

  return offset;
}


static const per_sequence_t RequestModeRelease_sequence[] = {
  { NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};

static int
dissect_h245_RequestModeRelease(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_RequestModeRelease, RequestModeRelease_sequence);

  return offset;
}


static const per_sequence_t T_videoNotDecodedMBs_sequence[] = {
  { &hf_h245_firstMB_1_8192 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_8192 },
  { &hf_h245_numberOfMBs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_8192 },
  { &hf_h245_temporalReference_0_255, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_videoNotDecodedMBs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_videoNotDecodedMBs, T_videoNotDecodedMBs_sequence);

  return offset;
}


static const value_string h245_Mi_type_vals[] = {
  {   0, "logicalChannelActive" },
  {   1, "logicalChannelInactive" },
  {   2, "multipointConference" },
  {   3, "cancelMultipointConference" },
  {   4, "multipointZeroComm" },
  {   5, "cancelMultipointZeroComm" },
  {   6, "multipointSecondaryStatus" },
  {   7, "cancelMultipointSecondaryStatus" },
  {   8, "videoIndicateReadyToActivate" },
  {   9, "videoTemporalSpatialTradeOff" },
  {  10, "videoNotDecodedMBs" },
  {  11, "transportCapability" },
  { 0, NULL }
};

static const per_choice_t Mi_type_choice[] = {
  {   0, &hf_h245_logicalChannelActive, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_logicalChannelInactive, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_multipointConference, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   3, &hf_h245_cancelMultipointConference, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   4, &hf_h245_multipointZeroComm, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   5, &hf_h245_cancelMultipointZeroComm, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   6, &hf_h245_multipointSecondaryStatus, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   7, &hf_h245_cancelMultipointSecondaryStatus, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   8, &hf_h245_videoIndicateReadyToActivate, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   9, &hf_h245_videoTemporalSpatialTradeOff, ASN1_EXTENSION_ROOT    , dissect_h245_INTEGER_0_31 },
  {  10, &hf_h245_videoNotDecodedMBs, ASN1_NOT_EXTENSION_ROOT, dissect_h245_T_videoNotDecodedMBs },
  {  11, &hf_h245_transportCapability, ASN1_NOT_EXTENSION_ROOT, dissect_h245_TransportCapability },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_Mi_type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_Mi_type, Mi_type_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MiscellaneousIndication_sequence[] = {
  { &hf_h245_logicalChannelNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_LogicalChannelNumber },
  { &hf_h245_mi_type        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_Mi_type },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MiscellaneousIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MiscellaneousIndication, MiscellaneousIndication_sequence);

  return offset;
}



static int
dissect_h245_INTEGER_0_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, FALSE);

  return offset;
}



static int
dissect_h245_INTEGER_0_7(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}


static const per_sequence_t JitterIndication_sequence[] = {
  { &hf_h245_scope          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_Scope },
  { &hf_h245_estimatedReceivedJitterMantissa, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_3 },
  { &hf_h245_estimatedReceivedJitterExponent, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_7 },
  { &hf_h245_skippedFrameCount, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_15 },
  { &hf_h245_additionalDecoderBuffer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_262143 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_JitterIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_JitterIndication, JitterIndication_sequence);

  return offset;
}


static const per_sequence_t H223SkewIndication_sequence[] = {
  { &hf_h245_logicalChannelNumber1, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_LogicalChannelNumber },
  { &hf_h245_logicalChannelNumber2, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_LogicalChannelNumber },
  { &hf_h245_skew           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_4095 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H223SkewIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H223SkewIndication, H223SkewIndication_sequence);

  return offset;
}


static const value_string h245_Ind_clockRecovery_vals[] = {
  {   0, "nullClockRecovery" },
  {   1, "srtsClockRecovery" },
  {   2, "adaptiveClockRecovery" },
  { 0, NULL }
};

static const per_choice_t Ind_clockRecovery_choice[] = {
  {   0, &hf_h245_nullClockRecoveryflag, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_srtsClockRecovery, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_adaptiveClockRecoveryFlag, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_Ind_clockRecovery(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_Ind_clockRecovery, Ind_clockRecovery_choice,
                                 NULL);

  return offset;
}


static const value_string h245_Ind_errorCorrection_vals[] = {
  {   0, "nullErrorCorrection" },
  {   1, "longInterleaver" },
  {   2, "shortInterleaver" },
  {   3, "errorCorrectionOnly" },
  { 0, NULL }
};

static const per_choice_t Ind_errorCorrection_choice[] = {
  {   0, &hf_h245_nullErrorCorrectionFlag, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_longInterleaverFlag, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_shortInterleaverFlag, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   3, &hf_h245_errorCorrectionOnlyFlag, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_Ind_errorCorrection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_Ind_errorCorrection, Ind_errorCorrection_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Ind_aal1_sequence[] = {
  { &hf_h245_ind_clockRecovery, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_Ind_clockRecovery },
  { &hf_h245_ind_errorCorrection, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_Ind_errorCorrection },
  { &hf_h245_structuredDataTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_partiallyFilledCells, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_Ind_aal1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_Ind_aal1, Ind_aal1_sequence);

  return offset;
}


static const per_sequence_t Ind_aal5_sequence[] = {
  { &hf_h245_forwardMaximumSDUSize, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_65535 },
  { &hf_h245_backwardMaximumSDUSize, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_65535 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_Ind_aal5(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_Ind_aal5, Ind_aal5_sequence);

  return offset;
}


static const value_string h245_Ind_aal_vals[] = {
  {   0, "aal1" },
  {   1, "aal5" },
  { 0, NULL }
};

static const per_choice_t Ind_aal_choice[] = {
  {   0, &hf_h245_ind_aal1       , ASN1_EXTENSION_ROOT    , dissect_h245_Ind_aal1 },
  {   1, &hf_h245_ind_aal5       , ASN1_EXTENSION_ROOT    , dissect_h245_Ind_aal5 },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_Ind_aal(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_Ind_aal, Ind_aal_choice,
                                 NULL);

  return offset;
}


static const value_string h245_Ind_multiplex_vals[] = {
  {   0, "noMultiplex" },
  {   1, "transportStream" },
  {   2, "programStream" },
  { 0, NULL }
};

static const per_choice_t Ind_multiplex_choice[] = {
  {   0, &hf_h245_noMultiplex    , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_transportStream, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_programStreamFlag, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_Ind_multiplex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_Ind_multiplex, Ind_multiplex_choice,
                                 NULL);

  return offset;
}


static const value_string h245_IndR_multiplex_vals[] = {
  {   0, "noMultiplex" },
  {   1, "transportStream" },
  {   2, "programStream" },
  { 0, NULL }
};

static const per_choice_t IndR_multiplex_choice[] = {
  {   0, &hf_h245_noMultiplex    , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_transportStream, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_programStreamFlag, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_IndR_multiplex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_IndR_multiplex, IndR_multiplex_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Ind_reverseParameters_sequence[] = {
  { &hf_h245_bitRate        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_65535 },
  { &hf_h245_bitRateLockedToPCRClock, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_bitRateLockedToNetworkClock, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_indr_multiplex , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_IndR_multiplex },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_Ind_reverseParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_Ind_reverseParameters, Ind_reverseParameters_sequence);

  return offset;
}


static const per_sequence_t NewATMVCIndication_sequence[] = {
  { &hf_h245_resourceID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_65535 },
  { &hf_h245_bitRate        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_65535 },
  { &hf_h245_bitRateLockedToPCRClock, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_bitRateLockedToNetworkClock, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_BOOLEAN },
  { &hf_h245_ind_aal        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_Ind_aal },
  { &hf_h245_ind_multiplex  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_Ind_multiplex },
  { &hf_h245_ind_reverseParameters, ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_h245_Ind_reverseParameters },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_NewATMVCIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_NewATMVCIndication, NewATMVCIndication_sequence);

  return offset;
}


static const value_string h245_T_userInputSupportIndication_vals[] = {
  {   0, "nonStandard" },
  {   1, "basicString" },
  {   2, "iA5String" },
  {   3, "generalString" },
  {   4, "encryptedBasicString" },
  {   5, "encryptedIA5String" },
  {   6, "encryptedGeneralString" },
  { 0, NULL }
};

static const per_choice_t T_userInputSupportIndication_choice[] = {
  {   0, &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardParameter },
  {   1, &hf_h245_basicString    , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_iA5String      , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   3, &hf_h245_generalString  , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   4, &hf_h245_encryptedBasicString, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {   5, &hf_h245_encryptedIA5String, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {   6, &hf_h245_encryptedGeneralString, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_T_userInputSupportIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_T_userInputSupportIndication, T_userInputSupportIndication_choice,
                                 NULL);

  return offset;
}



static int
dissect_h245_T_signalType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,
                                                      1, 1, FALSE, "0123456789#*ABCD!", 17,
                                                      NULL);

  return offset;
}


static const per_sequence_t T_rtp_sequence[] = {
  { &hf_h245_timestamp      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_4294967295 },
  { &hf_h245_expirationTime , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_0_4294967295 },
  { &hf_h245_logicalChannelNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_LogicalChannelNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_rtp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_rtp, T_rtp_sequence);

  return offset;
}



static int
dissect_h245_IV8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, FALSE, NULL);

  return offset;
}



static int
dissect_h245_IV16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       16, 16, FALSE, NULL);

  return offset;
}


static const per_sequence_t Params_sequence[] = {
  { &hf_h245_iv8            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_IV8 },
  { &hf_h245_iv16           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_IV16 },
  { &hf_h245_iv             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_Params(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_Params, Params_sequence);

  return offset;
}



static int
dissect_h245_OCTET_STRING_SIZE_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, FALSE, NULL);

  return offset;
}


static const per_sequence_t T_signal_sequence[] = {
  { &hf_h245_signalType     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_T_signalType },
  { &hf_h245_duration       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_INTEGER_1_65535 },
  { &hf_h245_rtp            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_T_rtp },
  { &hf_h245_rtpPayloadIndication, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_NULL },
  { &hf_h245_paramS         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_Params },
  { &hf_h245_encryptedSignalType, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_OCTET_STRING_SIZE_1 },
  { &hf_h245_algorithmOID   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_OBJECT_IDENTIFIER },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_signal(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_signal, T_signal_sequence);

  return offset;
}


static const per_sequence_t Si_rtp_sequence[] = {
  { &hf_h245_logicalChannelNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_LogicalChannelNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_Si_rtp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_Si_rtp, Si_rtp_sequence);

  return offset;
}


static const per_sequence_t T_signalUpdate_sequence[] = {
  { &hf_h245_duration       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_65535 },
  { &hf_h245_si_rtp         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_Si_rtp },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_signalUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_signalUpdate, T_signalUpdate_sequence);

  return offset;
}


static const per_sequence_t EncryptedAlphanumeric_sequence[] = {
  { &hf_h245_algorithmOID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_OBJECT_IDENTIFIER },
  { &hf_h245_paramS         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_Params },
  { &hf_h245_encrypted      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_EncryptedAlphanumeric(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_EncryptedAlphanumeric, EncryptedAlphanumeric_sequence);

  return offset;
}


static const per_sequence_t T_extendedAlphanumeric_sequence[] = {
  { &hf_h245_alphanumeric   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_GeneralString },
  { &hf_h245_rtpPayloadIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_NULL },
  { &hf_h245_encryptedAlphanumeric, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245_EncryptedAlphanumeric },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_extendedAlphanumeric(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_extendedAlphanumeric, T_extendedAlphanumeric_sequence);

  return offset;
}


static const value_string h245_UserInputIndication_vals[] = {
  {   0, "nonStandard" },
  {   1, "alphanumeric" },
  {   2, "userInputSupportIndication" },
  {   3, "signal" },
  {   4, "signalUpdate" },
  {   5, "extendedAlphanumeric" },
  {   6, "encryptedAlphanumeric" },
  {   7, "genericInformation" },
  { 0, NULL }
};

static const per_choice_t UserInputIndication_choice[] = {
  {   0, &hf_h245_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardParameter },
  {   1, &hf_h245_alphanumeric   , ASN1_EXTENSION_ROOT    , dissect_h245_GeneralString },
  {   2, &hf_h245_userInputSupportIndication, ASN1_NOT_EXTENSION_ROOT, dissect_h245_T_userInputSupportIndication },
  {   3, &hf_h245_signal         , ASN1_NOT_EXTENSION_ROOT, dissect_h245_T_signal },
  {   4, &hf_h245_signalUpdate   , ASN1_NOT_EXTENSION_ROOT, dissect_h245_T_signalUpdate },
  {   5, &hf_h245_extendedAlphanumeric, ASN1_NOT_EXTENSION_ROOT, dissect_h245_T_extendedAlphanumeric },
  {   6, &hf_h245_encryptedAlphanumeric, ASN1_NOT_EXTENSION_ROOT, dissect_h245_EncryptedAlphanumeric },
  {   7, &hf_h245_genericInformation, ASN1_NOT_EXTENSION_ROOT, dissect_h245_SEQUENCE_OF_GenericInformation },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_UserInputIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_UserInputIndication, UserInputIndication_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t H2250MaximumSkewIndication_sequence[] = {
  { &hf_h245_logicalChannelNumber1, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_LogicalChannelNumber },
  { &hf_h245_logicalChannelNumber2, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_LogicalChannelNumber },
  { &hf_h245_maximumSkew    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_4095 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_H2250MaximumSkewIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_H2250MaximumSkewIndication, H2250MaximumSkewIndication_sequence);

  return offset;
}


static const per_sequence_t MCLocationIndication_sequence[] = {
  { &hf_h245_signalAddress  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_TransportAddress },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MCLocationIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MCLocationIndication, MCLocationIndication_sequence);

  return offset;
}



static int
dissect_h245_INTEGER_0_9(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9U, NULL, FALSE);

  return offset;
}


static const per_sequence_t TerminalYouAreSeeingInSubPictureNumber_sequence[] = {
  { &hf_h245_terminalNumber , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_TerminalNumber },
  { &hf_h245_subPictureNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_255 },
  { &hf_h245_mcuNumber      , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_h245_McuNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_TerminalYouAreSeeingInSubPictureNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_TerminalYouAreSeeingInSubPictureNumber, TerminalYouAreSeeingInSubPictureNumber_sequence);

  return offset;
}


static const per_sequence_t VideoIndicateCompose_sequence[] = {
  { &hf_h245_compositionNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_VideoIndicateCompose(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_VideoIndicateCompose, VideoIndicateCompose_sequence);

  return offset;
}


static const value_string h245_ConferenceIndication_vals[] = {
  {   0, "sbeNumber" },
  {   1, "terminalNumberAssign" },
  {   2, "terminalJoinedConference" },
  {   3, "terminalLeftConference" },
  {   4, "seenByAtLeastOneOther" },
  {   5, "cancelSeenByAtLeastOneOther" },
  {   6, "seenByAll" },
  {   7, "cancelSeenByAll" },
  {   8, "terminalYouAreSeeing" },
  {   9, "requestForFloor" },
  {  10, "withdrawChairToken" },
  {  11, "floorRequested" },
  {  12, "terminalYouAreSeeingInSubPictureNumber" },
  {  13, "videoIndicateCompose" },
  {  14, "masterMCU" },
  {  15, "cancelMasterMCU" },
  { 0, NULL }
};

static const per_choice_t ConferenceIndication_choice[] = {
  {   0, &hf_h245_sbeNumber      , ASN1_EXTENSION_ROOT    , dissect_h245_INTEGER_0_9 },
  {   1, &hf_h245_terminalNumberAssign, ASN1_EXTENSION_ROOT    , dissect_h245_TerminalLabel },
  {   2, &hf_h245_terminalJoinedConference, ASN1_EXTENSION_ROOT    , dissect_h245_TerminalLabel },
  {   3, &hf_h245_terminalLeftConference, ASN1_EXTENSION_ROOT    , dissect_h245_TerminalLabel },
  {   4, &hf_h245_seenByAtLeastOneOther, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   5, &hf_h245_cancelSeenByAtLeastOneOther, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   6, &hf_h245_seenByAll      , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   7, &hf_h245_cancelSeenByAll, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   8, &hf_h245_terminalYouAreSeeing, ASN1_EXTENSION_ROOT    , dissect_h245_TerminalLabel },
  {   9, &hf_h245_requestForFloor, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {  10, &hf_h245_withdrawChairToken, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {  11, &hf_h245_floorRequested , ASN1_NOT_EXTENSION_ROOT, dissect_h245_TerminalLabel },
  {  12, &hf_h245_terminalYouAreSeeingInSubPictureNumber, ASN1_NOT_EXTENSION_ROOT, dissect_h245_TerminalYouAreSeeingInSubPictureNumber },
  {  13, &hf_h245_videoIndicateCompose, ASN1_NOT_EXTENSION_ROOT, dissect_h245_VideoIndicateCompose },
  {  14, &hf_h245_masterMCU      , ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  {  15, &hf_h245_cancelMasterMCU, ASN1_NOT_EXTENSION_ROOT, dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_ConferenceIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_ConferenceIndication, ConferenceIndication_choice,
                                 NULL);

  return offset;
}



static int
dissect_h245_OCTET_STRING_SIZE_1_256(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 256, FALSE, NULL);

  return offset;
}


static const per_sequence_t VendorIdentification_sequence[] = {
  { &hf_h245_vendor         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_NonStandardIdentifier },
  { &hf_h245_productNumber  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_OCTET_STRING_SIZE_1_256 },
  { &hf_h245_versionNumber  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_OCTET_STRING_SIZE_1_256 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_VendorIdentification(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_VendorIdentification, VendorIdentification_sequence);

  return offset;
}


static const value_string h245_FunctionNotSupportedCause_vals[] = {
  {   0, "syntaxError" },
  {   1, "semanticError" },
  {   2, "unknownFunction" },
  { 0, NULL }
};

static const per_choice_t FunctionNotSupportedCause_choice[] = {
  {   0, &hf_h245_syntaxError    , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   1, &hf_h245_semanticError  , ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  {   2, &hf_h245_unknownFunction, ASN1_EXTENSION_ROOT    , dissect_h245_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_FunctionNotSupportedCause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_FunctionNotSupportedCause, FunctionNotSupportedCause_choice,
                                 NULL);

  return offset;
}



static int
dissect_h245_T_returnedFunction(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 994 "../../asn1/h245/h245.cnf"
  tvbuff_t *next_tvb = NULL;
  proto_item *item;
  proto_tree *subtree;
  h245_packet_info *saved_h245_pi;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &next_tvb);


 if (next_tvb && tvb_length(next_tvb)) {
	saved_h245_pi = h245_pi;
	h245_pi = NULL;
	item = proto_tree_add_text(tree, next_tvb, 0, -1,"The returned function");
	subtree = proto_item_add_subtree(item, ett_h245_returnedFunction);
	PROTO_ITEM_SET_GENERATED(item);
	dissect_h245_MultimediaSystemControlMessage(next_tvb, 0, actx, subtree, hf_h245_pdu_type);
	h245_pi = saved_h245_pi;
 }



  return offset;
}


static const per_sequence_t FunctionNotSupported_sequence[] = {
  { &hf_h245_fns_cause      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_FunctionNotSupportedCause },
  { &hf_h245_returnedFunction, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245_T_returnedFunction },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_FunctionNotSupported(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_FunctionNotSupported, FunctionNotSupported_sequence);

  return offset;
}


static const per_sequence_t T_crcDesired_sequence[] = {
  { NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};

static int
dissect_h245_T_crcDesired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_crcDesired, T_crcDesired_sequence);

  return offset;
}


static const per_sequence_t T_excessiveError_sequence[] = {
  { &hf_h245_connectionIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_ConnectionIdentifier },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_T_excessiveError(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_T_excessiveError, T_excessiveError_sequence);

  return offset;
}


static const value_string h245_MultilinkIndication_vals[] = {
  {   0, "nonStandard" },
  {   1, "crcDesired" },
  {   2, "excessiveError" },
  { 0, NULL }
};

static const per_choice_t MultilinkIndication_choice[] = {
  {   0, &hf_h245_nonStandardMsg , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardMessage },
  {   1, &hf_h245_crcDesired     , ASN1_EXTENSION_ROOT    , dissect_h245_T_crcDesired },
  {   2, &hf_h245_excessiveError , ASN1_EXTENSION_ROOT    , dissect_h245_T_excessiveError },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_MultilinkIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_MultilinkIndication, MultilinkIndication_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t LogicalChannelRateRelease_sequence[] = {
  { NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};

static int
dissect_h245_LogicalChannelRateRelease(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_LogicalChannelRateRelease, LogicalChannelRateRelease_sequence);

  return offset;
}


static const per_sequence_t FlowControlIndication_sequence[] = {
  { &hf_h245_scope          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_Scope },
  { &hf_h245_restriction    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_Restriction },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_FlowControlIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_FlowControlIndication, FlowControlIndication_sequence);

  return offset;
}


static const per_sequence_t MobileMultilinkReconfigurationIndication_sequence[] = {
  { &hf_h245_sampleSize     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_255 },
  { &hf_h245_samplesPerFrame, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245_INTEGER_1_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h245_MobileMultilinkReconfigurationIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h245_MobileMultilinkReconfigurationIndication, MobileMultilinkReconfigurationIndication_sequence);

  return offset;
}


static const value_string h245_IndicationMessage_vals[] = {
  { IndicationMessage_nonStandard, "nonStandard" },
  { IndicationMessage_functionNotUnderstood, "functionNotUnderstood" },
  { IndicationMessage_masterSlaveDeterminationRelease, "masterSlaveDeterminationRelease" },
  { IndicationMessage_terminalCapabilitySetRelease, "terminalCapabilitySetRelease" },
  { IndicationMessage_openLogicalChannelConfirm, "openLogicalChannelConfirm" },
  { IndicationMessage_requestChannelCloseRelease, "requestChannelCloseRelease" },
  { IndicationMessage_multiplexEntrySendRelease, "multiplexEntrySendRelease" },
  { IndicationMessage_requestMultiplexEntryRelease, "requestMultiplexEntryRelease" },
  { IndicationMessage_requestModeRelease, "requestModeRelease" },
  { IndicationMessage_miscellaneousIndication, "miscellaneousIndication" },
  { IndicationMessage_jitterIndication, "jitterIndication" },
  { IndicationMessage_h223SkewIndication, "h223SkewIndication" },
  { IndicationMessage_newATMVCIndication, "newATMVCIndication" },
  { IndicationMessage_userInput, "userInput" },
  { IndicationMessage_h2250MaximumSkewIndication, "h2250MaximumSkewIndication" },
  { IndicationMessage_mcLocationIndication, "mcLocationIndication" },
  { IndicationMessage_conferenceIndication, "conferenceIndication" },
  { IndicationMessage_vendorIdentification, "vendorIdentification" },
  { IndicationMessage_functionNotSupported, "functionNotSupported" },
  { IndicationMessage_multilinkIndication, "multilinkIndication" },
  { IndicationMessage_logicalChannelRateRelease, "logicalChannelRateRelease" },
  { IndicationMessage_flowControlIndication, "flowControlIndication" },
  { IndicationMessage_mobileMultilinkReconfigurationIndication, "mobileMultilinkReconfigurationIndication" },
  { IndicationMessage_genericIndication, "genericIndication" },
  { 0, NULL }
};

static const per_choice_t IndicationMessage_choice[] = {
  { IndicationMessage_nonStandard, &hf_h245_nonStandardMsg , ASN1_EXTENSION_ROOT    , dissect_h245_NonStandardMessage },
  { IndicationMessage_functionNotUnderstood, &hf_h245_functionNotUnderstood, ASN1_EXTENSION_ROOT    , dissect_h245_FunctionNotUnderstood },
  { IndicationMessage_masterSlaveDeterminationRelease, &hf_h245_masterSlaveDeterminationRelease, ASN1_EXTENSION_ROOT    , dissect_h245_MasterSlaveDeterminationRelease },
  { IndicationMessage_terminalCapabilitySetRelease, &hf_h245_terminalCapabilitySetRelease, ASN1_EXTENSION_ROOT    , dissect_h245_TerminalCapabilitySetRelease },
  { IndicationMessage_openLogicalChannelConfirm, &hf_h245_openLogicalChannelConfirm, ASN1_EXTENSION_ROOT    , dissect_h245_OpenLogicalChannelConfirm },
  { IndicationMessage_requestChannelCloseRelease, &hf_h245_requestChannelCloseRelease, ASN1_EXTENSION_ROOT    , dissect_h245_RequestChannelCloseRelease },
  { IndicationMessage_multiplexEntrySendRelease, &hf_h245_multiplexEntrySendRelease, ASN1_EXTENSION_ROOT    , dissect_h245_MultiplexEntrySendRelease },
  { IndicationMessage_requestMultiplexEntryRelease, &hf_h245_requestMultiplexEntryRelease, ASN1_EXTENSION_ROOT    , dissect_h245_RequestMultiplexEntryRelease },
  { IndicationMessage_requestModeRelease, &hf_h245_requestModeRelease, ASN1_EXTENSION_ROOT    , dissect_h245_RequestModeRelease },
  { IndicationMessage_miscellaneousIndication, &hf_h245_miscellaneousIndication, ASN1_EXTENSION_ROOT    , dissect_h245_MiscellaneousIndication },
  { IndicationMessage_jitterIndication, &hf_h245_jitterIndication, ASN1_EXTENSION_ROOT    , dissect_h245_JitterIndication },
  { IndicationMessage_h223SkewIndication, &hf_h245_h223SkewIndication, ASN1_EXTENSION_ROOT    , dissect_h245_H223SkewIndication },
  { IndicationMessage_newATMVCIndication, &hf_h245_newATMVCIndication, ASN1_EXTENSION_ROOT    , dissect_h245_NewATMVCIndication },
  { IndicationMessage_userInput, &hf_h245_userInput      , ASN1_EXTENSION_ROOT    , dissect_h245_UserInputIndication },
  { IndicationMessage_h2250MaximumSkewIndication, &hf_h245_h2250MaximumSkewIndication, ASN1_NOT_EXTENSION_ROOT, dissect_h245_H2250MaximumSkewIndication },
  { IndicationMessage_mcLocationIndication, &hf_h245_mcLocationIndication, ASN1_NOT_EXTENSION_ROOT, dissect_h245_MCLocationIndication },
  { IndicationMessage_conferenceIndication, &hf_h245_conferenceIndication, ASN1_NOT_EXTENSION_ROOT, dissect_h245_ConferenceIndication },
  { IndicationMessage_vendorIdentification, &hf_h245_vendorIdentification, ASN1_NOT_EXTENSION_ROOT, dissect_h245_VendorIdentification },
  { IndicationMessage_functionNotSupported, &hf_h245_functionNotSupported, ASN1_NOT_EXTENSION_ROOT, dissect_h245_FunctionNotSupported },
  { IndicationMessage_multilinkIndication, &hf_h245_multilinkIndication, ASN1_NOT_EXTENSION_ROOT, dissect_h245_MultilinkIndication },
  { IndicationMessage_logicalChannelRateRelease, &hf_h245_logicalChannelRateRelease, ASN1_NOT_EXTENSION_ROOT, dissect_h245_LogicalChannelRateRelease },
  { IndicationMessage_flowControlIndication, &hf_h245_flowControlIndication, ASN1_NOT_EXTENSION_ROOT, dissect_h245_FlowControlIndication },
  { IndicationMessage_mobileMultilinkReconfigurationIndication, &hf_h245_mobileMultilinkReconfigurationIndication, ASN1_NOT_EXTENSION_ROOT, dissect_h245_MobileMultilinkReconfigurationIndication },
  { IndicationMessage_genericIndication, &hf_h245_genericIndication, ASN1_NOT_EXTENSION_ROOT, dissect_h245_GenericMessage },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_IndicationMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 435 "../../asn1/h245/h245.cnf"
  gint32 value;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_IndicationMessage, IndicationMessage_choice,
                                 &value);

        if ( h245_shorttypes == TRUE )
	        {
	        	col_prepend_fstr(actx->pinfo->cinfo, COL_INFO, "%s ",
				val_to_str(value, h245_IndicationMessage_short_vals, "<unknown>"));
		}
		else
		{
	        	col_prepend_fstr(actx->pinfo->cinfo, COL_INFO, "%s ",
				val_to_str(value, h245_IndicationMessage_vals, "<unknown>"));
		}

	col_set_fence(actx->pinfo->cinfo,COL_INFO);
    /* Add to packet info */
    if (h245_pi  !=NULL){
      if ( strlen(h245_pi->frame_label) == 0 ){
	    g_snprintf(h245_pi->frame_label, 50, "%s", val_to_str(value, h245_IndicationMessage_short_vals, "UKN"));
	  }
      g_strlcat(h245_pi->comment, val_to_str(value, h245_IndicationMessage_vals, "<unknown>"), 50);

    }



  return offset;
}


static const value_string h245_MultimediaSystemControlMessage_vals[] = {
  {   0, "request" },
  {   1, "response" },
  {   2, "command" },
  {   3, "indication" },
  { 0, NULL }
};

static const per_choice_t MultimediaSystemControlMessage_choice[] = {
  {   0, &hf_h245_request        , ASN1_EXTENSION_ROOT    , dissect_h245_RequestMessage },
  {   1, &hf_h245_response       , ASN1_EXTENSION_ROOT    , dissect_h245_ResponseMessage },
  {   2, &hf_h245_command        , ASN1_EXTENSION_ROOT    , dissect_h245_CommandMessage },
  {   3, &hf_h245_indication     , ASN1_EXTENSION_ROOT    , dissect_h245_IndicationMessage },
  { 0, NULL, 0, NULL }
};

static int
dissect_h245_MultimediaSystemControlMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h245_MultimediaSystemControlMessage, MultimediaSystemControlMessage_choice,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static void dissect_OpenLogicalChannel_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  dissect_h245_OpenLogicalChannel(tvb, 0, &asn1_ctx, tree, hf_h245_OpenLogicalChannel_PDU);
}


/*--- End of included file: packet-h245-fn.c ---*/
#line 412 "../../asn1/h245/packet-h245-template.c"

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


/*--- Included file: packet-h245-hfarr.c ---*/
#line 1 "../../asn1/h245/packet-h245-hfarr.c"
    { &hf_h245_OpenLogicalChannel_PDU,
      { "OpenLogicalChannel", "h245.OpenLogicalChannel",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_request,
      { "request", "h245.request",
        FT_UINT32, BASE_DEC, VALS(h245_RequestMessage_vals), 0,
        "RequestMessage", HFILL }},
    { &hf_h245_response,
      { "response", "h245.response",
        FT_UINT32, BASE_DEC, VALS(h245_ResponseMessage_vals), 0,
        "ResponseMessage", HFILL }},
    { &hf_h245_command,
      { "command", "h245.command",
        FT_UINT32, BASE_DEC, VALS(h245_CommandMessage_vals), 0,
        "CommandMessage", HFILL }},
    { &hf_h245_indication,
      { "indication", "h245.indication",
        FT_UINT32, BASE_DEC, VALS(h245_IndicationMessage_vals), 0,
        "IndicationMessage", HFILL }},
    { &hf_h245_nonStandardMsg,
      { "nonStandard", "h245.nonStandard",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardMessage", HFILL }},
    { &hf_h245_masterSlaveDetermination,
      { "masterSlaveDetermination", "h245.masterSlaveDetermination",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_terminalCapabilitySet,
      { "terminalCapabilitySet", "h245.terminalCapabilitySet",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_openLogicalChannel,
      { "openLogicalChannel", "h245.openLogicalChannel",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_closeLogicalChannel,
      { "closeLogicalChannel", "h245.closeLogicalChannel",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_requestChannelClose,
      { "requestChannelClose", "h245.requestChannelClose",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_multiplexEntrySend,
      { "multiplexEntrySend", "h245.multiplexEntrySend",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_requestMultiplexEntry,
      { "requestMultiplexEntry", "h245.requestMultiplexEntry",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_requestMode,
      { "requestMode", "h245.requestMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_roundTripDelayRequest,
      { "roundTripDelayRequest", "h245.roundTripDelayRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_maintenanceLoopRequest,
      { "maintenanceLoopRequest", "h245.maintenanceLoopRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_communicationModeRequest,
      { "communicationModeRequest", "h245.communicationModeRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_conferenceRequest,
      { "conferenceRequest", "h245.conferenceRequest",
        FT_UINT32, BASE_DEC, VALS(h245_ConferenceRequest_vals), 0,
        NULL, HFILL }},
    { &hf_h245_multilinkRequest,
      { "multilinkRequest", "h245.multilinkRequest",
        FT_UINT32, BASE_DEC, VALS(h245_MultilinkRequest_vals), 0,
        NULL, HFILL }},
    { &hf_h245_logicalChannelRateRequest,
      { "logicalChannelRateRequest", "h245.logicalChannelRateRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_genericRequest,
      { "genericRequest", "h245.genericRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "GenericMessage", HFILL }},
    { &hf_h245_masterSlaveDeterminationAck,
      { "masterSlaveDeterminationAck", "h245.masterSlaveDeterminationAck",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_masterSlaveDeterminationReject,
      { "masterSlaveDeterminationReject", "h245.masterSlaveDeterminationReject",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_terminalCapabilitySetAck,
      { "terminalCapabilitySetAck", "h245.terminalCapabilitySetAck",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_terminalCapabilitySetReject,
      { "terminalCapabilitySetReject", "h245.terminalCapabilitySetReject",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_openLogicalChannelAck,
      { "openLogicalChannelAck", "h245.openLogicalChannelAck",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_openLogicalChannelReject,
      { "openLogicalChannelReject", "h245.openLogicalChannelReject",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_closeLogicalChannelAck,
      { "closeLogicalChannelAck", "h245.closeLogicalChannelAck",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_requestChannelCloseAck,
      { "requestChannelCloseAck", "h245.requestChannelCloseAck",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_requestChannelCloseReject,
      { "requestChannelCloseReject", "h245.requestChannelCloseReject",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_multiplexEntrySendAck,
      { "multiplexEntrySendAck", "h245.multiplexEntrySendAck",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_multiplexEntrySendReject,
      { "multiplexEntrySendReject", "h245.multiplexEntrySendReject",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_requestMultiplexEntryAck,
      { "requestMultiplexEntryAck", "h245.requestMultiplexEntryAck",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_requestMultiplexEntryReject,
      { "requestMultiplexEntryReject", "h245.requestMultiplexEntryReject",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_requestModeAck,
      { "requestModeAck", "h245.requestModeAck",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_requestModeReject,
      { "requestModeReject", "h245.requestModeReject",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_roundTripDelayResponse,
      { "roundTripDelayResponse", "h245.roundTripDelayResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_maintenanceLoopAck,
      { "maintenanceLoopAck", "h245.maintenanceLoopAck",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_maintenanceLoopReject,
      { "maintenanceLoopReject", "h245.maintenanceLoopReject",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_communicationModeResponse,
      { "communicationModeResponse", "h245.communicationModeResponse",
        FT_UINT32, BASE_DEC, VALS(h245_CommunicationModeResponse_vals), 0,
        NULL, HFILL }},
    { &hf_h245_conferenceResponse,
      { "conferenceResponse", "h245.conferenceResponse",
        FT_UINT32, BASE_DEC, VALS(h245_ConferenceResponse_vals), 0,
        NULL, HFILL }},
    { &hf_h245_multilinkResponse,
      { "multilinkResponse", "h245.multilinkResponse",
        FT_UINT32, BASE_DEC, VALS(h245_MultilinkResponse_vals), 0,
        NULL, HFILL }},
    { &hf_h245_logicalChannelRateAcknowledge,
      { "logicalChannelRateAcknowledge", "h245.logicalChannelRateAcknowledge",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_logicalChannelRateReject,
      { "logicalChannelRateReject", "h245.logicalChannelRateReject",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_genericResponse,
      { "genericResponse", "h245.genericResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "GenericMessage", HFILL }},
    { &hf_h245_maintenanceLoopOffCommand,
      { "maintenanceLoopOffCommand", "h245.maintenanceLoopOffCommand",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_sendTerminalCapabilitySet,
      { "sendTerminalCapabilitySet", "h245.sendTerminalCapabilitySet",
        FT_UINT32, BASE_DEC, VALS(h245_SendTerminalCapabilitySet_vals), 0,
        NULL, HFILL }},
    { &hf_h245_encryptionCommand,
      { "encryptionCommand", "h245.encryptionCommand",
        FT_UINT32, BASE_DEC, VALS(h245_EncryptionCommand_vals), 0,
        NULL, HFILL }},
    { &hf_h245_flowControlCommand,
      { "flowControlCommand", "h245.flowControlCommand",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_endSessionCommand,
      { "endSessionCommand", "h245.endSessionCommand",
        FT_UINT32, BASE_DEC, VALS(h245_EndSessionCommand_vals), 0,
        NULL, HFILL }},
    { &hf_h245_miscellaneousCommand,
      { "miscellaneousCommand", "h245.miscellaneousCommand",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_communicationModeCommand,
      { "communicationModeCommand", "h245.communicationModeCommand",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_conferenceCommand,
      { "conferenceCommand", "h245.conferenceCommand",
        FT_UINT32, BASE_DEC, VALS(h245_ConferenceCommand_vals), 0,
        NULL, HFILL }},
    { &hf_h245_h223MultiplexReconfiguration,
      { "h223MultiplexReconfiguration", "h245.h223MultiplexReconfiguration",
        FT_UINT32, BASE_DEC, VALS(h245_H223MultiplexReconfiguration_vals), 0,
        NULL, HFILL }},
    { &hf_h245_newATMVCCommand,
      { "newATMVCCommand", "h245.newATMVCCommand",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_mobileMultilinkReconfigurationCommand,
      { "mobileMultilinkReconfigurationCommand", "h245.mobileMultilinkReconfigurationCommand",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_genericCommand,
      { "genericCommand", "h245.genericCommand",
        FT_NONE, BASE_NONE, NULL, 0,
        "GenericMessage", HFILL }},
    { &hf_h245_functionNotUnderstood,
      { "functionNotUnderstood", "h245.functionNotUnderstood",
        FT_UINT32, BASE_DEC, VALS(h245_FunctionNotUnderstood_vals), 0,
        NULL, HFILL }},
    { &hf_h245_masterSlaveDeterminationRelease,
      { "masterSlaveDeterminationRelease", "h245.masterSlaveDeterminationRelease",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_terminalCapabilitySetRelease,
      { "terminalCapabilitySetRelease", "h245.terminalCapabilitySetRelease",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_openLogicalChannelConfirm,
      { "openLogicalChannelConfirm", "h245.openLogicalChannelConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_requestChannelCloseRelease,
      { "requestChannelCloseRelease", "h245.requestChannelCloseRelease",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_multiplexEntrySendRelease,
      { "multiplexEntrySendRelease", "h245.multiplexEntrySendRelease",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_requestMultiplexEntryRelease,
      { "requestMultiplexEntryRelease", "h245.requestMultiplexEntryRelease",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_requestModeRelease,
      { "requestModeRelease", "h245.requestModeRelease",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_miscellaneousIndication,
      { "miscellaneousIndication", "h245.miscellaneousIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_jitterIndication,
      { "jitterIndication", "h245.jitterIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_h223SkewIndication,
      { "h223SkewIndication", "h245.h223SkewIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_newATMVCIndication,
      { "newATMVCIndication", "h245.newATMVCIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_userInput,
      { "userInput", "h245.userInput",
        FT_UINT32, BASE_DEC, VALS(h245_UserInputIndication_vals), 0,
        "UserInputIndication", HFILL }},
    { &hf_h245_h2250MaximumSkewIndication,
      { "h2250MaximumSkewIndication", "h245.h2250MaximumSkewIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_mcLocationIndication,
      { "mcLocationIndication", "h245.mcLocationIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_conferenceIndication,
      { "conferenceIndication", "h245.conferenceIndication",
        FT_UINT32, BASE_DEC, VALS(h245_ConferenceIndication_vals), 0,
        NULL, HFILL }},
    { &hf_h245_vendorIdentification,
      { "vendorIdentification", "h245.vendorIdentification",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_functionNotSupported,
      { "functionNotSupported", "h245.functionNotSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_multilinkIndication,
      { "multilinkIndication", "h245.multilinkIndication",
        FT_UINT32, BASE_DEC, VALS(h245_MultilinkIndication_vals), 0,
        NULL, HFILL }},
    { &hf_h245_logicalChannelRateRelease,
      { "logicalChannelRateRelease", "h245.logicalChannelRateRelease",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_flowControlIndication,
      { "flowControlIndication", "h245.flowControlIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_mobileMultilinkReconfigurationIndication,
      { "mobileMultilinkReconfigurationIndication", "h245.mobileMultilinkReconfigurationIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_genericIndication,
      { "genericIndication", "h245.genericIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        "GenericMessage", HFILL }},
    { &hf_h245_messageIdentifier,
      { "messageIdentifier", "h245.messageIdentifier",
        FT_UINT32, BASE_DEC, VALS(h245_CapabilityIdentifier_vals), 0,
        "CapabilityIdentifier", HFILL }},
    { &hf_h245_subMessageIdentifier,
      { "subMessageIdentifier", "h245.subMessageIdentifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_messageContent,
      { "messageContent", "h245.messageContent",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_messageContent_item,
      { "messageContent item", "h245.messageContent_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_messageContent_item", HFILL }},
    { &hf_h245_nonStandardData,
      { "nonStandardData", "h245.nonStandardData",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_h245_nonStandardIdentifier,
      { "nonStandardIdentifier", "h245.nonStandardIdentifier",
        FT_UINT32, BASE_DEC, VALS(h245_NonStandardIdentifier_vals), 0,
        NULL, HFILL }},
    { &hf_h245_nsd_data,
      { "data", "h245.data",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_nsd_data", HFILL }},
    { &hf_h245_object,
      { "object", "h245.object",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_h221NonStandardID,
      { "h221NonStandard", "h245.h221NonStandard",
        FT_NONE, BASE_NONE, NULL, 0,
        "H221NonStandardID", HFILL }},
    { &hf_h245_t35CountryCode,
      { "t35CountryCode", "h245.t35CountryCode",
        FT_UINT32, BASE_DEC, VALS(T35CountryCode_vals), 0,
        NULL, HFILL }},
    { &hf_h245_t35Extension,
      { "t35Extension", "h245.t35Extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_manufacturerCode,
      { "manufacturerCode", "h245.manufacturerCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_terminalType,
      { "terminalType", "h245.terminalType",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h245_statusDeterminationNumber,
      { "statusDeterminationNumber", "h245.statusDeterminationNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16777215", HFILL }},
    { &hf_h245_decision,
      { "decision", "h245.decision",
        FT_UINT32, BASE_DEC, VALS(h245_T_decision_vals), 0,
        NULL, HFILL }},
    { &hf_h245_master,
      { "master", "h245.master",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_slave,
      { "slave", "h245.slave",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_msd_rej_cause,
      { "cause", "h245.cause",
        FT_UINT32, BASE_DEC, VALS(h245_MasterSlaveDeterminationRejectCause_vals), 0,
        "MasterSlaveDeterminationRejectCause", HFILL }},
    { &hf_h245_identicalNumbers,
      { "identicalNumbers", "h245.identicalNumbers",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_sequenceNumber,
      { "sequenceNumber", "h245.sequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_protocolIdentifier,
      { "protocolIdentifier", "h245.protocolIdentifier",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_h245_multiplexCapability,
      { "multiplexCapability", "h245.multiplexCapability",
        FT_UINT32, BASE_DEC, VALS(h245_MultiplexCapability_vals), 0,
        NULL, HFILL }},
    { &hf_h245_capabilityTable,
      { "capabilityTable", "h245.capabilityTable",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_256_OF_CapabilityTableEntry", HFILL }},
    { &hf_h245_capabilityTable_item,
      { "CapabilityTableEntry", "h245.CapabilityTableEntry",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_capabilityDescriptors,
      { "capabilityDescriptors", "h245.capabilityDescriptors",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_256_OF_CapabilityDescriptor", HFILL }},
    { &hf_h245_capabilityDescriptors_item,
      { "CapabilityDescriptor", "h245.CapabilityDescriptor",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_genericInformation,
      { "genericInformation", "h245.genericInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_GenericInformation", HFILL }},
    { &hf_h245_genericInformation_item,
      { "GenericInformation", "h245.GenericInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_capabilityTableEntryNumber,
      { "capabilityTableEntryNumber", "h245.capabilityTableEntryNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_capability,
      { "capability", "h245.capability",
        FT_UINT32, BASE_DEC, VALS(h245_Capability_vals), 0,
        NULL, HFILL }},
    { &hf_h245_capabilityDescriptorNumber,
      { "capabilityDescriptorNumber", "h245.capabilityDescriptorNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_simultaneousCapabilities,
      { "simultaneousCapabilities", "h245.simultaneousCapabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_256_OF_AlternativeCapabilitySet", HFILL }},
    { &hf_h245_simultaneousCapabilities_item,
      { "AlternativeCapabilitySet", "h245.AlternativeCapabilitySet",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_AlternativeCapabilitySet_item,
      { "alternativeCapability", "h245.CapabilityTableEntryNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CapabilityTableEntryNumber", HFILL }},
    { &hf_h245_tcs_rej_cause,
      { "cause", "h245.cause",
        FT_UINT32, BASE_DEC, VALS(h245_TerminalCapabilitySetRejectCause_vals), 0,
        "TerminalCapabilitySetRejectCause", HFILL }},
    { &hf_h245_unspecified,
      { "unspecified", "h245.unspecified",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_undefinedTableEntryUsed,
      { "undefinedTableEntryUsed", "h245.undefinedTableEntryUsed",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_descriptorCapacityExceeded,
      { "descriptorCapacityExceeded", "h245.descriptorCapacityExceeded",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_tableEntryCapacityExceeded,
      { "tableEntryCapacityExceeded", "h245.tableEntryCapacityExceeded",
        FT_UINT32, BASE_DEC, VALS(h245_T_tableEntryCapacityExceeded_vals), 0,
        NULL, HFILL }},
    { &hf_h245_highestEntryNumberProcessed,
      { "highestEntryNumberProcessed", "h245.highestEntryNumberProcessed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CapabilityTableEntryNumber", HFILL }},
    { &hf_h245_noneProcessed,
      { "noneProcessed", "h245.noneProcessed",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_nonStandard,
      { "nonStandard", "h245.nonStandard",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_h245_receiveVideoCapability,
      { "receiveVideoCapability", "h245.receiveVideoCapability",
        FT_UINT32, BASE_DEC, VALS(h245_VideoCapability_vals), 0,
        "VideoCapability", HFILL }},
    { &hf_h245_transmitVideoCapability,
      { "transmitVideoCapability", "h245.transmitVideoCapability",
        FT_UINT32, BASE_DEC, VALS(h245_VideoCapability_vals), 0,
        "VideoCapability", HFILL }},
    { &hf_h245_receiveAndTransmitVideoCapability,
      { "receiveAndTransmitVideoCapability", "h245.receiveAndTransmitVideoCapability",
        FT_UINT32, BASE_DEC, VALS(h245_VideoCapability_vals), 0,
        "VideoCapability", HFILL }},
    { &hf_h245_receiveAudioCapability,
      { "receiveAudioCapability", "h245.receiveAudioCapability",
        FT_UINT32, BASE_DEC, VALS(h245_AudioCapability_vals), 0,
        "AudioCapability", HFILL }},
    { &hf_h245_transmitAudioCapability,
      { "transmitAudioCapability", "h245.transmitAudioCapability",
        FT_UINT32, BASE_DEC, VALS(h245_AudioCapability_vals), 0,
        "AudioCapability", HFILL }},
    { &hf_h245_receiveAndTransmitAudioCapability,
      { "receiveAndTransmitAudioCapability", "h245.receiveAndTransmitAudioCapability",
        FT_UINT32, BASE_DEC, VALS(h245_AudioCapability_vals), 0,
        "AudioCapability", HFILL }},
    { &hf_h245_receiveDataApplicationCapability,
      { "receiveDataApplicationCapability", "h245.receiveDataApplicationCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        "DataApplicationCapability", HFILL }},
    { &hf_h245_transmitDataApplicationCapability,
      { "transmitDataApplicationCapability", "h245.transmitDataApplicationCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        "DataApplicationCapability", HFILL }},
    { &hf_h245_receiveAndTransmitDataApplicationCapability,
      { "receiveAndTransmitDataApplicationCapability", "h245.receiveAndTransmitDataApplicationCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        "DataApplicationCapability", HFILL }},
    { &hf_h245_h233EncryptionTransmitCapability,
      { "h233EncryptionTransmitCapability", "h245.h233EncryptionTransmitCapability",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_h233EncryptionReceiveCapability,
      { "h233EncryptionReceiveCapability", "h245.h233EncryptionReceiveCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_h233IVResponseTime,
      { "h233IVResponseTime", "h245.h233IVResponseTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h245_conferenceCapability,
      { "conferenceCapability", "h245.conferenceCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_h235SecurityCapability,
      { "h235SecurityCapability", "h245.h235SecurityCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_maxPendingReplacementFor,
      { "maxPendingReplacementFor", "h245.maxPendingReplacementFor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h245_receiveUserInputCapability,
      { "receiveUserInputCapability", "h245.receiveUserInputCapability",
        FT_UINT32, BASE_DEC, VALS(h245_UserInputCapability_vals), 0,
        "UserInputCapability", HFILL }},
    { &hf_h245_transmitUserInputCapability,
      { "transmitUserInputCapability", "h245.transmitUserInputCapability",
        FT_UINT32, BASE_DEC, VALS(h245_UserInputCapability_vals), 0,
        "UserInputCapability", HFILL }},
    { &hf_h245_receiveAndTransmitUserInputCapability,
      { "receiveAndTransmitUserInputCapability", "h245.receiveAndTransmitUserInputCapability",
        FT_UINT32, BASE_DEC, VALS(h245_UserInputCapability_vals), 0,
        "UserInputCapability", HFILL }},
    { &hf_h245_genericControlCapability,
      { "genericControlCapability", "h245.genericControlCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        "GenericCapability", HFILL }},
    { &hf_h245_receiveMultiplexedStreamCapability,
      { "receiveMultiplexedStreamCapability", "h245.receiveMultiplexedStreamCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        "MultiplexedStreamCapability", HFILL }},
    { &hf_h245_transmitMultiplexedStreamCapability,
      { "transmitMultiplexedStreamCapability", "h245.transmitMultiplexedStreamCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        "MultiplexedStreamCapability", HFILL }},
    { &hf_h245_receiveAndTransmitMultiplexedStreamCapability,
      { "receiveAndTransmitMultiplexedStreamCapability", "h245.receiveAndTransmitMultiplexedStreamCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        "MultiplexedStreamCapability", HFILL }},
    { &hf_h245_receiveRTPAudioTelephonyEventCapability,
      { "receiveRTPAudioTelephonyEventCapability", "h245.receiveRTPAudioTelephonyEventCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        "AudioTelephonyEventCapability", HFILL }},
    { &hf_h245_receiveRTPAudioToneCapability,
      { "receiveRTPAudioToneCapability", "h245.receiveRTPAudioToneCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        "AudioToneCapability", HFILL }},
    { &hf_h245_depFecCapability,
      { "depFecCapability", "h245.depFecCapability",
        FT_UINT32, BASE_DEC, VALS(h245_DepFECCapability_vals), 0,
        NULL, HFILL }},
    { &hf_h245_multiplePayloadStreamCapability,
      { "multiplePayloadStreamCapability", "h245.multiplePayloadStreamCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_fecCapability,
      { "fecCapability", "h245.fecCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_redundancyEncodingCap,
      { "redundancyEncodingCap", "h245.redundancyEncodingCap",
        FT_NONE, BASE_NONE, NULL, 0,
        "RedundancyEncodingCapability", HFILL }},
    { &hf_h245_oneOfCapabilities,
      { "oneOfCapabilities", "h245.oneOfCapabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AlternativeCapabilitySet", HFILL }},
    { &hf_h245_encryptionAuthenticationAndIntegrity,
      { "encryptionAuthenticationAndIntegrity", "h245.encryptionAuthenticationAndIntegrity",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_mediaCapability,
      { "mediaCapability", "h245.mediaCapability",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CapabilityTableEntryNumber", HFILL }},
    { &hf_h245_h222Capability,
      { "h222Capability", "h245.h222Capability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_h223Capability,
      { "h223Capability", "h245.h223Capability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_v76Capability,
      { "v76Capability", "h245.v76Capability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_h2250Capability,
      { "h2250Capability", "h245.h2250Capability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_genericMultiplexCapability,
      { "genericMultiplexCapability", "h245.genericMultiplexCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        "GenericCapability", HFILL }},
    { &hf_h245_numberOfVCs,
      { "numberOfVCs", "h245.numberOfVCs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_256", HFILL }},
    { &hf_h245_vcCapability,
      { "vcCapability", "h245.vcCapability",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_VCCapability", HFILL }},
    { &hf_h245_vcCapability_item,
      { "VCCapability", "h245.VCCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_aal1,
      { "aal1", "h245.aal1",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_nullClockRecovery,
      { "nullClockRecovery", "h245.nullClockRecovery",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_srtsClockRecovery_bool,
      { "srtsClockRecovery", "h245.srtsClockRecovery",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_adaptiveClockRecovery,
      { "adaptiveClockRecovery", "h245.adaptiveClockRecovery",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_nullErrorCorrection,
      { "nullErrorCorrection", "h245.nullErrorCorrection",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_longInterleaver,
      { "longInterleaver", "h245.longInterleaver",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_shortInterleaver,
      { "shortInterleaver", "h245.shortInterleaver",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_errorCorrectionOnly,
      { "errorCorrectionOnly", "h245.errorCorrectionOnly",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_structuredDataTransfer,
      { "structuredDataTransfer", "h245.structuredDataTransfer",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_partiallyFilledCells,
      { "partiallyFilledCells", "h245.partiallyFilledCells",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_aal5,
      { "aal5", "h245.aal5",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_forwardMaximumSDUSize,
      { "forwardMaximumSDUSize", "h245.forwardMaximumSDUSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h245_backwardMaximumSDUSize,
      { "backwardMaximumSDUSize", "h245.backwardMaximumSDUSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h245_transportStream_bool,
      { "transportStream", "h245.transportStream",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_programStream,
      { "programStream", "h245.programStream",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_availableBitRates,
      { "availableBitRates", "h245.availableBitRates",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_avb_type,
      { "type", "h245.type",
        FT_UINT32, BASE_DEC, VALS(h245_Avb_type_vals), 0,
        "Avb_type", HFILL }},
    { &hf_h245_singleBitRate,
      { "singleBitRate", "h245.singleBitRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65535", HFILL }},
    { &hf_h245_rangeOfBitRates,
      { "rangeOfBitRates", "h245.rangeOfBitRates",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_lowerBitRate,
      { "lowerBitRate", "h245.lowerBitRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65535", HFILL }},
    { &hf_h245_higherBitRate,
      { "higherBitRate", "h245.higherBitRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65535", HFILL }},
    { &hf_h245_aal1ViaGateway,
      { "aal1ViaGateway", "h245.aal1ViaGateway",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_gatewayAddress,
      { "gatewayAddress", "h245.gatewayAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_256_OF_Q2931Address", HFILL }},
    { &hf_h245_gatewayAddress_item,
      { "Q2931Address", "h245.Q2931Address",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_srtsClockRecoveryflag,
      { "srtsClockRecovery", "h245.srtsClockRecovery",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_transportWithI_frames,
      { "transportWithI-frames", "h245.transportWithI_frames",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_videoWithAL1,
      { "videoWithAL1", "h245.videoWithAL1",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_videoWithAL2,
      { "videoWithAL2", "h245.videoWithAL2",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_videoWithAL3,
      { "videoWithAL3", "h245.videoWithAL3",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_audioWithAL1,
      { "audioWithAL1", "h245.audioWithAL1",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_audioWithAL2,
      { "audioWithAL2", "h245.audioWithAL2",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_audioWithAL3,
      { "audioWithAL3", "h245.audioWithAL3",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_dataWithAL1,
      { "dataWithAL1", "h245.dataWithAL1",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_dataWithAL2,
      { "dataWithAL2", "h245.dataWithAL2",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_dataWithAL3,
      { "dataWithAL3", "h245.dataWithAL3",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_maximumAl2SDUSize,
      { "maximumAl2SDUSize", "h245.maximumAl2SDUSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h245_maximumAl3SDUSize,
      { "maximumAl3SDUSize", "h245.maximumAl3SDUSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h245_maximumDelayJitter,
      { "maximumDelayJitter", "h245.maximumDelayJitter",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_h245_h223MultiplexTableCapability,
      { "h223MultiplexTableCapability", "h245.h223MultiplexTableCapability",
        FT_UINT32, BASE_DEC, VALS(h245_T_h223MultiplexTableCapability_vals), 0,
        NULL, HFILL }},
    { &hf_h245_basic,
      { "basic", "h245.basic",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_enhanced,
      { "enhanced", "h245.enhanced",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_maximumNestingDepth,
      { "maximumNestingDepth", "h245.maximumNestingDepth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_15", HFILL }},
    { &hf_h245_maximumElementListSize,
      { "maximumElementListSize", "h245.maximumElementListSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_2_255", HFILL }},
    { &hf_h245_maximumSubElementListSize,
      { "maximumSubElementListSize", "h245.maximumSubElementListSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_2_255", HFILL }},
    { &hf_h245_maxMUXPDUSizeCapability,
      { "maxMUXPDUSizeCapability", "h245.maxMUXPDUSizeCapability",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_nsrpSupport,
      { "nsrpSupport", "h245.nsrpSupport",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_mobileOperationTransmitCapability,
      { "mobileOperationTransmitCapability", "h245.mobileOperationTransmitCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_modeChangeCapability,
      { "modeChangeCapability", "h245.modeChangeCapability",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_h223AnnexA,
      { "h223AnnexA", "h245.h223AnnexA",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_h223AnnexADoubleFlagFlag,
      { "h223AnnexADoubleFlag", "h245.h223AnnexADoubleFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_h223AnnexB,
      { "h223AnnexB", "h245.h223AnnexB",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_h223AnnexBwithHeader,
      { "h223AnnexBwithHeader", "h245.h223AnnexBwithHeader",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_h223AnnexCCapability,
      { "h223AnnexCCapability", "h245.h223AnnexCCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_bitRate_1_19200,
      { "bitRate", "h245.bitRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_19200", HFILL }},
    { &hf_h245_mobileMultilinkFrameCapability,
      { "mobileMultilinkFrameCapability", "h245.mobileMultilinkFrameCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_maximumSampleSize,
      { "maximumSampleSize", "h245.maximumSampleSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_255", HFILL }},
    { &hf_h245_maximumPayloadLength,
      { "maximumPayloadLength", "h245.maximumPayloadLength",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65025", HFILL }},
    { &hf_h245_videoWithAL1M,
      { "videoWithAL1M", "h245.videoWithAL1M",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_videoWithAL2M,
      { "videoWithAL2M", "h245.videoWithAL2M",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_videoWithAL3M,
      { "videoWithAL3M", "h245.videoWithAL3M",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_audioWithAL1M,
      { "audioWithAL1M", "h245.audioWithAL1M",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_audioWithAL2M,
      { "audioWithAL2M", "h245.audioWithAL2M",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_audioWithAL3M,
      { "audioWithAL3M", "h245.audioWithAL3M",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_dataWithAL1M,
      { "dataWithAL1M", "h245.dataWithAL1M",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_dataWithAL2M,
      { "dataWithAL2M", "h245.dataWithAL2M",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_dataWithAL3M,
      { "dataWithAL3M", "h245.dataWithAL3M",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_alpduInterleaving,
      { "alpduInterleaving", "h245.alpduInterleaving",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_maximumAL1MPDUSize,
      { "maximumAL1MPDUSize", "h245.maximumAL1MPDUSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h245_maximumAL2MSDUSize,
      { "maximumAL2MSDUSize", "h245.maximumAL2MSDUSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h245_maximumAL3MSDUSize,
      { "maximumAL3MSDUSize", "h245.maximumAL3MSDUSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h245_rsCodeCapability,
      { "rsCodeCapability", "h245.rsCodeCapability",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_suspendResumeCapabilitywAddress,
      { "suspendResumeCapabilitywAddress", "h245.suspendResumeCapabilitywAddress",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_suspendResumeCapabilitywoAddress,
      { "suspendResumeCapabilitywoAddress", "h245.suspendResumeCapabilitywoAddress",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_rejCapability,
      { "rejCapability", "h245.rejCapability",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_sREJCapability,
      { "sREJCapability", "h245.sREJCapability",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_mREJCapability,
      { "mREJCapability", "h245.mREJCapability",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_crc8bitCapability,
      { "crc8bitCapability", "h245.crc8bitCapability",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_crc16bitCapability,
      { "crc16bitCapability", "h245.crc16bitCapability",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_crc32bitCapability,
      { "crc32bitCapability", "h245.crc32bitCapability",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_uihCapability,
      { "uihCapability", "h245.uihCapability",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_numOfDLCS,
      { "numOfDLCS", "h245.numOfDLCS",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_2_8191", HFILL }},
    { &hf_h245_twoOctetAddressFieldCapability,
      { "twoOctetAddressFieldCapability", "h245.twoOctetAddressFieldCapability",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_loopBackTestCapability,
      { "loopBackTestCapability", "h245.loopBackTestCapability",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_n401Capability,
      { "n401Capability", "h245.n401Capability",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_4095", HFILL }},
    { &hf_h245_maxWindowSizeCapability,
      { "maxWindowSizeCapability", "h245.maxWindowSizeCapability",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_127", HFILL }},
    { &hf_h245_v75Capability,
      { "v75Capability", "h245.v75Capability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_audioHeader,
      { "audioHeader", "h245.audioHeader",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_maximumAudioDelayJitter,
      { "maximumAudioDelayJitter", "h245.maximumAudioDelayJitter",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_h245_receiveMultipointCapability,
      { "receiveMultipointCapability", "h245.receiveMultipointCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        "MultipointCapability", HFILL }},
    { &hf_h245_transmitMultipointCapability,
      { "transmitMultipointCapability", "h245.transmitMultipointCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        "MultipointCapability", HFILL }},
    { &hf_h245_receiveAndTransmitMultipointCapability,
      { "receiveAndTransmitMultipointCapability", "h245.receiveAndTransmitMultipointCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        "MultipointCapability", HFILL }},
    { &hf_h245_mcCapability,
      { "mcCapability", "h245.mcCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_centralizedConferenceMC,
      { "centralizedConferenceMC", "h245.centralizedConferenceMC",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_decentralizedConferenceMC,
      { "decentralizedConferenceMC", "h245.decentralizedConferenceMC",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_rtcpVideoControlCapability,
      { "rtcpVideoControlCapability", "h245.rtcpVideoControlCapability",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_mediaPacketizationCapability,
      { "mediaPacketizationCapability", "h245.mediaPacketizationCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_transportCapability,
      { "transportCapability", "h245.transportCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_redundancyEncodingCapability,
      { "redundancyEncodingCapability", "h245.redundancyEncodingCapability",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_256_OF_RedundancyEncodingCapability", HFILL }},
    { &hf_h245_redundancyEncodingCapability_item,
      { "RedundancyEncodingCapability", "h245.RedundancyEncodingCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_logicalChannelSwitchingCapability,
      { "logicalChannelSwitchingCapability", "h245.logicalChannelSwitchingCapability",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_t120DynamicPortCapability,
      { "t120DynamicPortCapability", "h245.t120DynamicPortCapability",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_h261aVideoPacketization,
      { "h261aVideoPacketization", "h245.h261aVideoPacketization",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_rtpPayloadTypes,
      { "rtpPayloadType", "h245.rtpPayloadType",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_256_OF_RTPPayloadType", HFILL }},
    { &hf_h245_rtpPayloadTypes_item,
      { "RTPPayloadType", "h245.RTPPayloadType",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_qosMode,
      { "qosMode", "h245.qosMode",
        FT_UINT32, BASE_DEC, VALS(h245_QOSMode_vals), 0,
        NULL, HFILL }},
    { &hf_h245_tokenRate,
      { "tokenRate", "h245.tokenRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_4294967295", HFILL }},
    { &hf_h245_bucketSize,
      { "bucketSize", "h245.bucketSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_4294967295", HFILL }},
    { &hf_h245_peakRate,
      { "peakRate", "h245.peakRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_4294967295", HFILL }},
    { &hf_h245_minPoliced,
      { "minPoliced", "h245.minPoliced",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_4294967295", HFILL }},
    { &hf_h245_maxPktSize,
      { "maxPktSize", "h245.maxPktSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_4294967295", HFILL }},
    { &hf_h245_guaranteedQOS,
      { "guaranteedQOS", "h245.guaranteedQOS",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_controlledLoad,
      { "controlledLoad", "h245.controlledLoad",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_maxNTUSize,
      { "maxNTUSize", "h245.maxNTUSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h245_atmUBR,
      { "atmUBR", "h245.atmUBR",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_atmrtVBR,
      { "atmrtVBR", "h245.atmrtVBR",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_atmnrtVBR,
      { "atmnrtVBR", "h245.atmnrtVBR",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_atmABR,
      { "atmABR", "h245.atmABR",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_atmCBR,
      { "atmCBR", "h245.atmCBR",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_nonStandardParameter,
      { "nonStandardParameter", "h245.nonStandardParameter",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_value,
      { "value", "h245.value",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h245_servicePrioritySignalled,
      { "servicePrioritySignalled", "h245.servicePrioritySignalled",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_servicePriorityValue,
      { "servicePriorityValue", "h245.servicePriorityValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_serviceClass,
      { "serviceClass", "h245.serviceClass",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4095", HFILL }},
    { &hf_h245_serviceSubclass,
      { "serviceSubclass", "h245.serviceSubclass",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h245_desired,
      { "desired", "h245.desired",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_required,
      { "required", "h245.required",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_class0,
      { "class0", "h245.class0",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_class1,
      { "class1", "h245.class1",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_class2,
      { "class2", "h245.class2",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_class3,
      { "class3", "h245.class3",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_class4,
      { "class4", "h245.class4",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_class5,
      { "class5", "h245.class5",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_qosType,
      { "qosType", "h245.qosType",
        FT_UINT32, BASE_DEC, VALS(h245_QOSType_vals), 0,
        NULL, HFILL }},
    { &hf_h245_qosClass,
      { "qosClass", "h245.qosClass",
        FT_UINT32, BASE_DEC, VALS(h245_QOSClass_vals), 0,
        NULL, HFILL }},
    { &hf_h245_averageRate,
      { "averageRate", "h245.averageRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_4294967295", HFILL }},
    { &hf_h245_burst,
      { "burst", "h245.burst",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_4294967295", HFILL }},
    { &hf_h245_rsvpParameters,
      { "rsvpParameters", "h245.rsvpParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_atmParameters,
      { "atmParameters", "h245.atmParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_localQoS,
      { "localQoS", "h245.localQoS",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_genericTransportParameters,
      { "genericTransportParameters", "h245.genericTransportParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_servicePriority,
      { "servicePriority", "h245.servicePriority",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_authorizationParameter,
      { "authorizationParameter", "h245.authorizationParameter",
        FT_NONE, BASE_NONE, NULL, 0,
        "AuthorizationParameters", HFILL }},
    { &hf_h245_qosDescriptor,
      { "qosDescriptor", "h245.qosDescriptor",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_dscpValue,
      { "dscpValue", "h245.dscpValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_h245_ip_UDP,
      { "ip-UDP", "h245.ip_UDP",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_ip_TCP,
      { "ip-TCP", "h245.ip_TCP",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_atm_AAL5_UNIDIR,
      { "atm-AAL5-UNIDIR", "h245.atm_AAL5_UNIDIR",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_atm_AAL5_BIDIR,
      { "atm-AAL5-BIDIR", "h245.atm_AAL5_BIDIR",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_atm_AAL5_compressed,
      { "atm-AAL5-compressed", "h245.atm_AAL5_compressed",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_variable_delta,
      { "variable-delta", "h245.variable_delta",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_mediaTransport,
      { "mediaTransport", "h245.mediaTransport",
        FT_UINT32, BASE_DEC, VALS(h245_MediaTransportType_vals), 0,
        "MediaTransportType", HFILL }},
    { &hf_h245_qOSCapabilities,
      { "qOSCapabilities", "h245.qOSCapabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_256_OF_QOSCapability", HFILL }},
    { &hf_h245_qOSCapabilities_item,
      { "QOSCapability", "h245.QOSCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_mediaChannelCapabilities,
      { "mediaChannelCapabilities", "h245.mediaChannelCapabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_256_OF_MediaChannelCapability", HFILL }},
    { &hf_h245_mediaChannelCapabilities_item,
      { "MediaChannelCapability", "h245.MediaChannelCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_redundancyEncodingMethod,
      { "redundancyEncodingMethod", "h245.redundancyEncodingMethod",
        FT_UINT32, BASE_DEC, VALS(h245_RedundancyEncodingMethod_vals), 0,
        NULL, HFILL }},
    { &hf_h245_primaryEncoding,
      { "primaryEncoding", "h245.primaryEncoding",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CapabilityTableEntryNumber", HFILL }},
    { &hf_h245_secondaryEncodingCapability,
      { "secondaryEncoding", "h245.secondaryEncoding",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_256_OF_CapabilityTableEntryNumber", HFILL }},
    { &hf_h245_secondaryEncodingCapability_item,
      { "CapabilityTableEntryNumber", "h245.CapabilityTableEntryNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_rtpAudioRedundancyEncoding,
      { "rtpAudioRedundancyEncoding", "h245.rtpAudioRedundancyEncoding",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_rtpH263VideoRedundancyEncoding,
      { "rtpH263VideoRedundancyEncoding", "h245.rtpH263VideoRedundancyEncoding",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_numberOfThreads,
      { "numberOfThreads", "h245.numberOfThreads",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_16", HFILL }},
    { &hf_h245_framesBetweenSyncPoints,
      { "framesBetweenSyncPoints", "h245.framesBetweenSyncPoints",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_256", HFILL }},
    { &hf_h245_frameToThreadMapping,
      { "frameToThreadMapping", "h245.frameToThreadMapping",
        FT_UINT32, BASE_DEC, VALS(h245_T_frameToThreadMapping_vals), 0,
        NULL, HFILL }},
    { &hf_h245_roundrobin,
      { "roundrobin", "h245.roundrobin",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_custom,
      { "custom", "h245.custom",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_256_OF_RTPH263VideoRedundancyFrameMapping", HFILL }},
    { &hf_h245_custom_item,
      { "RTPH263VideoRedundancyFrameMapping", "h245.RTPH263VideoRedundancyFrameMapping",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_containedThreads,
      { "containedThreads", "h245.containedThreads",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_containedThreads_item,
      { "containedThreads item", "h245.containedThreads_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_h245_threadNumber,
      { "threadNumber", "h245.threadNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_h245_frameSequence,
      { "frameSequence", "h245.frameSequence",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_frameSequence_item,
      { "frameSequence item", "h245.frameSequence_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h245_multicastCapability,
      { "multicastCapability", "h245.multicastCapability",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_multiUniCastConference,
      { "multiUniCastConference", "h245.multiUniCastConference",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_mediaDistributionCapability,
      { "mediaDistributionCapability", "h245.mediaDistributionCapability",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_MediaDistributionCapability", HFILL }},
    { &hf_h245_mediaDistributionCapability_item,
      { "MediaDistributionCapability", "h245.MediaDistributionCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_centralizedControl,
      { "centralizedControl", "h245.centralizedControl",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_distributedControl,
      { "distributedControl", "h245.distributedControl",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_centralizedAudio,
      { "centralizedAudio", "h245.centralizedAudio",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_distributedAudio,
      { "distributedAudio", "h245.distributedAudio",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_centralizedVideo,
      { "centralizedVideo", "h245.centralizedVideo",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_distributedVideo,
      { "distributedVideo", "h245.distributedVideo",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_centralizedData,
      { "centralizedData", "h245.centralizedData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_DataApplicationCapability", HFILL }},
    { &hf_h245_centralizedData_item,
      { "DataApplicationCapability", "h245.DataApplicationCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_distributedData,
      { "distributedData", "h245.distributedData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_DataApplicationCapability", HFILL }},
    { &hf_h245_distributedData_item,
      { "DataApplicationCapability", "h245.DataApplicationCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_h261VideoCapability,
      { "h261VideoCapability", "h245.h261VideoCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_h262VideoCapability,
      { "h262VideoCapability", "h245.h262VideoCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_h263VideoCapability,
      { "h263VideoCapability", "h245.h263VideoCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_is11172VideoCapability,
      { "is11172VideoCapability", "h245.is11172VideoCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_genericVideoCapability,
      { "genericVideoCapability", "h245.genericVideoCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        "GenericCapability", HFILL }},
    { &hf_h245_extendedVideoCapability,
      { "extendedVideoCapability", "h245.extendedVideoCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_videoCapability,
      { "videoCapability", "h245.videoCapability",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_VideoCapability", HFILL }},
    { &hf_h245_videoCapability_item,
      { "VideoCapability", "h245.VideoCapability",
        FT_UINT32, BASE_DEC, VALS(h245_VideoCapability_vals), 0,
        NULL, HFILL }},
    { &hf_h245_videoCapabilityExtension,
      { "videoCapabilityExtension", "h245.videoCapabilityExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_GenericCapability", HFILL }},
    { &hf_h245_videoCapabilityExtension_item,
      { "GenericCapability", "h245.GenericCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_qcifMPI_1_4,
      { "qcifMPI", "h245.qcifMPI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_4", HFILL }},
    { &hf_h245_cifMPI_1_4,
      { "cifMPI", "h245.cifMPI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_4", HFILL }},
    { &hf_h245_temporalSpatialTradeOffCapability,
      { "temporalSpatialTradeOffCapability", "h245.temporalSpatialTradeOffCapability",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_maxBitRate_1_19200,
      { "maxBitRate", "h245.maxBitRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_19200", HFILL }},
    { &hf_h245_stillImageTransmission,
      { "stillImageTransmission", "h245.stillImageTransmission",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_videoBadMBsCap,
      { "videoBadMBsCap", "h245.videoBadMBsCap",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_profileAndLevel_SPatML,
      { "profileAndLevel-SPatML", "h245.profileAndLevel_SPatML",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_profileAndLevel_MPatLL,
      { "profileAndLevel-MPatLL", "h245.profileAndLevel_MPatLL",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_profileAndLevel_MPatML,
      { "profileAndLevel-MPatML", "h245.profileAndLevel_MPatML",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_profileAndLevel_MPatH_14,
      { "profileAndLevel-MPatH-14", "h245.profileAndLevel_MPatH_14",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_profileAndLevel_MPatHL,
      { "profileAndLevel-MPatHL", "h245.profileAndLevel_MPatHL",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_profileAndLevel_SNRatLL,
      { "profileAndLevel-SNRatLL", "h245.profileAndLevel_SNRatLL",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_profileAndLevel_SNRatML,
      { "profileAndLevel-SNRatML", "h245.profileAndLevel_SNRatML",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_profileAndLevel_SpatialatH_14,
      { "profileAndLevel-SpatialatH-14", "h245.profileAndLevel_SpatialatH_14",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_profileAndLevel_HPatML,
      { "profileAndLevel-HPatML", "h245.profileAndLevel_HPatML",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_profileAndLevel_HPatH_14,
      { "profileAndLevel-HPatH-14", "h245.profileAndLevel_HPatH_14",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_profileAndLevel_HPatHL,
      { "profileAndLevel-HPatHL", "h245.profileAndLevel_HPatHL",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_videoBitRate,
      { "videoBitRate", "h245.videoBitRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1073741823", HFILL }},
    { &hf_h245_vbvBufferSize,
      { "vbvBufferSize", "h245.vbvBufferSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_262143", HFILL }},
    { &hf_h245_samplesPerLine,
      { "samplesPerLine", "h245.samplesPerLine",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16383", HFILL }},
    { &hf_h245_linesPerFrame,
      { "linesPerFrame", "h245.linesPerFrame",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16383", HFILL }},
    { &hf_h245_framesPerSecond,
      { "framesPerSecond", "h245.framesPerSecond",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_h245_luminanceSampleRate,
      { "luminanceSampleRate", "h245.luminanceSampleRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_h245_sqcifMPI_1_32,
      { "sqcifMPI", "h245.sqcifMPI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_32", HFILL }},
    { &hf_h245_qcifMPI,
      { "qcifMPI", "h245.qcifMPI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_32", HFILL }},
    { &hf_h245_cifMPI,
      { "cifMPI", "h245.cifMPI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_32", HFILL }},
    { &hf_h245_cif4MPI_1_32,
      { "cif4MPI", "h245.cif4MPI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_32", HFILL }},
    { &hf_h245_cif16MPI_1_32,
      { "cif16MPI", "h245.cif16MPI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_32", HFILL }},
    { &hf_h245_maxBitRate,
      { "maxBitRate", "h245.maxBitRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_192400", HFILL }},
    { &hf_h245_unrestrictedVector,
      { "unrestrictedVector", "h245.unrestrictedVector",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_arithmeticCoding,
      { "arithmeticCoding", "h245.arithmeticCoding",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_advancedPrediction,
      { "advancedPrediction", "h245.advancedPrediction",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_pbFrames,
      { "pbFrames", "h245.pbFrames",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_hrd_B,
      { "hrd-B", "h245.hrd_B",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_524287", HFILL }},
    { &hf_h245_bppMaxKb,
      { "bppMaxKb", "h245.bppMaxKb",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h245_slowSqcifMPI,
      { "slowSqcifMPI", "h245.slowSqcifMPI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_3600", HFILL }},
    { &hf_h245_slowQcifMPI,
      { "slowQcifMPI", "h245.slowQcifMPI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_3600", HFILL }},
    { &hf_h245_slowCifMPI,
      { "slowCifMPI", "h245.slowCifMPI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_3600", HFILL }},
    { &hf_h245_slowCif4MPI,
      { "slowCif4MPI", "h245.slowCif4MPI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_3600", HFILL }},
    { &hf_h245_slowCif16MPI,
      { "slowCif16MPI", "h245.slowCif16MPI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_3600", HFILL }},
    { &hf_h245_errorCompensation,
      { "errorCompensation", "h245.errorCompensation",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_enhancementLayerInfo,
      { "enhancementLayerInfo", "h245.enhancementLayerInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_h263Options,
      { "h263Options", "h245.h263Options",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_baseBitRateConstrained,
      { "baseBitRateConstrained", "h245.baseBitRateConstrained",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_snrEnhancement,
      { "snrEnhancement", "h245.snrEnhancement",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_14_OF_EnhancementOptions", HFILL }},
    { &hf_h245_snrEnhancement_item,
      { "EnhancementOptions", "h245.EnhancementOptions",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_spatialEnhancement,
      { "spatialEnhancement", "h245.spatialEnhancement",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_14_OF_EnhancementOptions", HFILL }},
    { &hf_h245_spatialEnhancement_item,
      { "EnhancementOptions", "h245.EnhancementOptions",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_bPictureEnhancement,
      { "bPictureEnhancement", "h245.bPictureEnhancement",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_14_OF_BEnhancementParameters", HFILL }},
    { &hf_h245_bPictureEnhancement_item,
      { "BEnhancementParameters", "h245.BEnhancementParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_enhancementOptions,
      { "enhancementOptions", "h245.enhancementOptions",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_numberOfBPictures,
      { "numberOfBPictures", "h245.numberOfBPictures",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_64", HFILL }},
    { &hf_h245_advancedIntraCodingMode,
      { "advancedIntraCodingMode", "h245.advancedIntraCodingMode",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_deblockingFilterMode,
      { "deblockingFilterMode", "h245.deblockingFilterMode",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_improvedPBFramesMode,
      { "improvedPBFramesMode", "h245.improvedPBFramesMode",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_unlimitedMotionVectors,
      { "unlimitedMotionVectors", "h245.unlimitedMotionVectors",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_fullPictureFreeze,
      { "fullPictureFreeze", "h245.fullPictureFreeze",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_partialPictureFreezeAndRelease,
      { "partialPictureFreezeAndRelease", "h245.partialPictureFreezeAndRelease",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_resizingPartPicFreezeAndRelease,
      { "resizingPartPicFreezeAndRelease", "h245.resizingPartPicFreezeAndRelease",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_fullPictureSnapshot,
      { "fullPictureSnapshot", "h245.fullPictureSnapshot",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_partialPictureSnapshot,
      { "partialPictureSnapshot", "h245.partialPictureSnapshot",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_videoSegmentTagging,
      { "videoSegmentTagging", "h245.videoSegmentTagging",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_progressiveRefinement,
      { "progressiveRefinement", "h245.progressiveRefinement",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_dynamicPictureResizingByFour,
      { "dynamicPictureResizingByFour", "h245.dynamicPictureResizingByFour",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_dynamicPictureResizingSixteenthPel,
      { "dynamicPictureResizingSixteenthPel", "h245.dynamicPictureResizingSixteenthPel",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_dynamicWarpingHalfPel,
      { "dynamicWarpingHalfPel", "h245.dynamicWarpingHalfPel",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_dynamicWarpingSixteenthPel,
      { "dynamicWarpingSixteenthPel", "h245.dynamicWarpingSixteenthPel",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_independentSegmentDecoding,
      { "independentSegmentDecoding", "h245.independentSegmentDecoding",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_slicesInOrder_NonRect,
      { "slicesInOrder-NonRect", "h245.slicesInOrder_NonRect",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_slicesInOrder_Rect,
      { "slicesInOrder-Rect", "h245.slicesInOrder_Rect",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_slicesNoOrder_NonRect,
      { "slicesNoOrder-NonRect", "h245.slicesNoOrder_NonRect",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_slicesNoOrder_Rect,
      { "slicesNoOrder-Rect", "h245.slicesNoOrder_Rect",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_alternateInterVLCMode,
      { "alternateInterVLCMode", "h245.alternateInterVLCMode",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_modifiedQuantizationMode,
      { "modifiedQuantizationMode", "h245.modifiedQuantizationMode",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_reducedResolutionUpdate,
      { "reducedResolutionUpdate", "h245.reducedResolutionUpdate",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_transparencyParameters,
      { "transparencyParameters", "h245.transparencyParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_separateVideoBackChannel,
      { "separateVideoBackChannel", "h245.separateVideoBackChannel",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_refPictureSelection,
      { "refPictureSelection", "h245.refPictureSelection",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_customPictureClockFrequency,
      { "customPictureClockFrequency", "h245.customPictureClockFrequency",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_16_OF_CustomPictureClockFrequency", HFILL }},
    { &hf_h245_customPictureClockFrequency_item,
      { "CustomPictureClockFrequency", "h245.CustomPictureClockFrequency",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_customPictureFormat,
      { "customPictureFormat", "h245.customPictureFormat",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_16_OF_CustomPictureFormat", HFILL }},
    { &hf_h245_customPictureFormat_item,
      { "CustomPictureFormat", "h245.CustomPictureFormat",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_modeCombos,
      { "modeCombos", "h245.modeCombos",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_16_OF_H263VideoModeCombos", HFILL }},
    { &hf_h245_modeCombos_item,
      { "H263VideoModeCombos", "h245.H263VideoModeCombos",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_h263Version3Options,
      { "h263Version3Options", "h245.h263Version3Options",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_presentationOrder,
      { "presentationOrder", "h245.presentationOrder",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_256", HFILL }},
    { &hf_h245_offset_x,
      { "offset-x", "h245.offset_x",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M262144_262143", HFILL }},
    { &hf_h245_offset_y,
      { "offset-y", "h245.offset_y",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M262144_262143", HFILL }},
    { &hf_h245_scale_x,
      { "scale-x", "h245.scale_x",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_255", HFILL }},
    { &hf_h245_scale_y,
      { "scale-y", "h245.scale_y",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_255", HFILL }},
    { &hf_h245_additionalPictureMemory,
      { "additionalPictureMemory", "h245.additionalPictureMemory",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_sqcifAdditionalPictureMemory,
      { "sqcifAdditionalPictureMemory", "h245.sqcifAdditionalPictureMemory",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_256", HFILL }},
    { &hf_h245_qcifAdditionalPictureMemory,
      { "qcifAdditionalPictureMemory", "h245.qcifAdditionalPictureMemory",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_256", HFILL }},
    { &hf_h245_cifAdditionalPictureMemory,
      { "cifAdditionalPictureMemory", "h245.cifAdditionalPictureMemory",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_256", HFILL }},
    { &hf_h245_cif4AdditionalPictureMemory,
      { "cif4AdditionalPictureMemory", "h245.cif4AdditionalPictureMemory",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_256", HFILL }},
    { &hf_h245_cif16AdditionalPictureMemory,
      { "cif16AdditionalPictureMemory", "h245.cif16AdditionalPictureMemory",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_256", HFILL }},
    { &hf_h245_bigCpfAdditionalPictureMemory,
      { "bigCpfAdditionalPictureMemory", "h245.bigCpfAdditionalPictureMemory",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_256", HFILL }},
    { &hf_h245_videoMux,
      { "videoMux", "h245.videoMux",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_videoBackChannelSend,
      { "videoBackChannelSend", "h245.videoBackChannelSend",
        FT_UINT32, BASE_DEC, VALS(h245_T_videoBackChannelSend_vals), 0,
        NULL, HFILL }},
    { &hf_h245_none,
      { "none", "h245.none",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_ackMessageOnly,
      { "ackMessageOnly", "h245.ackMessageOnly",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_nackMessageOnly,
      { "nackMessageOnly", "h245.nackMessageOnly",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_ackOrNackMessageOnly,
      { "ackOrNackMessageOnly", "h245.ackOrNackMessageOnly",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_ackAndNackMessage,
      { "ackAndNackMessage", "h245.ackAndNackMessage",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_enhancedReferencePicSelect,
      { "enhancedReferencePicSelect", "h245.enhancedReferencePicSelect",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_subPictureRemovalParameters,
      { "subPictureRemovalParameters", "h245.subPictureRemovalParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_mpuHorizMBs,
      { "mpuHorizMBs", "h245.mpuHorizMBs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_128", HFILL }},
    { &hf_h245_mpuVertMBs,
      { "mpuVertMBs", "h245.mpuVertMBs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_72", HFILL }},
    { &hf_h245_mpuTotalNumber,
      { "mpuTotalNumber", "h245.mpuTotalNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65536", HFILL }},
    { &hf_h245_clockConversionCode,
      { "clockConversionCode", "h245.clockConversionCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1000_1001", HFILL }},
    { &hf_h245_clockDivisor,
      { "clockDivisor", "h245.clockDivisor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_127", HFILL }},
    { &hf_h245_sqcifMPI,
      { "sqcifMPI", "h245.sqcifMPI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_2048", HFILL }},
    { &hf_h245_qcifMPI_1_2048,
      { "qcifMPI", "h245.qcifMPI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_2048", HFILL }},
    { &hf_h245_cifMPI2_1_2048,
      { "cifMPI", "h245.cifMPI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_2048", HFILL }},
    { &hf_h245_cif4MPI,
      { "cif4MPI", "h245.cif4MPI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_2048", HFILL }},
    { &hf_h245_cif16MPI,
      { "cif16MPI", "h245.cif16MPI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_2048", HFILL }},
    { &hf_h245_maxCustomPictureWidth,
      { "maxCustomPictureWidth", "h245.maxCustomPictureWidth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_2048", HFILL }},
    { &hf_h245_maxCustomPictureHeight,
      { "maxCustomPictureHeight", "h245.maxCustomPictureHeight",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_2048", HFILL }},
    { &hf_h245_minCustomPictureWidth,
      { "minCustomPictureWidth", "h245.minCustomPictureWidth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_2048", HFILL }},
    { &hf_h245_minCustomPictureHeight,
      { "minCustomPictureHeight", "h245.minCustomPictureHeight",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_2048", HFILL }},
    { &hf_h245_mPI,
      { "mPI", "h245.mPI",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_standardMPI,
      { "standardMPI", "h245.standardMPI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_31", HFILL }},
    { &hf_h245_customPCF,
      { "customPCF", "h245.customPCF",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_customPCF_item,
      { "customPCF item", "h245.customPCF_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_customMPI,
      { "customMPI", "h245.customMPI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_2048", HFILL }},
    { &hf_h245_pixelAspectInformation,
      { "pixelAspectInformation", "h245.pixelAspectInformation",
        FT_UINT32, BASE_DEC, VALS(h245_T_pixelAspectInformation_vals), 0,
        NULL, HFILL }},
    { &hf_h245_anyPixelAspectRatio,
      { "anyPixelAspectRatio", "h245.anyPixelAspectRatio",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_pixelAspectCode,
      { "pixelAspectCode", "h245.pixelAspectCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_pixelAspectCode_item,
      { "pixelAspectCode item", "h245.pixelAspectCode_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_14", HFILL }},
    { &hf_h245_extendedPAR,
      { "extendedPAR", "h245.extendedPAR",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_extendedPAR_item,
      { "extendedPAR item", "h245.extendedPAR_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_width,
      { "width", "h245.width",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_255", HFILL }},
    { &hf_h245_height,
      { "height", "h245.height",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_255", HFILL }},
    { &hf_h245_h263VideoUncoupledModes,
      { "h263VideoUncoupledModes", "h245.h263VideoUncoupledModes",
        FT_NONE, BASE_NONE, NULL, 0,
        "H263ModeComboFlags", HFILL }},
    { &hf_h245_h263VideoCoupledModes,
      { "h263VideoCoupledModes", "h245.h263VideoCoupledModes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_16_OF_H263ModeComboFlags", HFILL }},
    { &hf_h245_h263VideoCoupledModes_item,
      { "H263ModeComboFlags", "h245.H263ModeComboFlags",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_referencePicSelect,
      { "referencePicSelect", "h245.referencePicSelect",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_enhancedReferencePicSelectBool,
      { "enhancedReferencePicSelect", "h245.enhancedReferencePicSelect",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_dataPartitionedSlices,
      { "dataPartitionedSlices", "h245.dataPartitionedSlices",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_fixedPointIDCT0,
      { "fixedPointIDCT0", "h245.fixedPointIDCT0",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_interlacedFields,
      { "interlacedFields", "h245.interlacedFields",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_currentPictureHeaderRepetition,
      { "currentPictureHeaderRepetition", "h245.currentPictureHeaderRepetition",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_previousPictureHeaderRepetition,
      { "previousPictureHeaderRepetition", "h245.previousPictureHeaderRepetition",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_nextPictureHeaderRepetition,
      { "nextPictureHeaderRepetition", "h245.nextPictureHeaderRepetition",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_pictureNumberBoolean,
      { "pictureNumber", "h245.pictureNumber",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_spareReferencePictures,
      { "spareReferencePictures", "h245.spareReferencePictures",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_constrainedBitstream,
      { "constrainedBitstream", "h245.constrainedBitstream",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_pictureRate,
      { "pictureRate", "h245.pictureRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_h245_g711Alaw64k,
      { "g711Alaw64k", "h245.g711Alaw64k",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_256", HFILL }},
    { &hf_h245_g711Alaw56k,
      { "g711Alaw56k", "h245.g711Alaw56k",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_256", HFILL }},
    { &hf_h245_g711Ulaw64k,
      { "g711Ulaw64k", "h245.g711Ulaw64k",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_256", HFILL }},
    { &hf_h245_g711Ulaw56k,
      { "g711Ulaw56k", "h245.g711Ulaw56k",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_256", HFILL }},
    { &hf_h245_g722_64k,
      { "g722-64k", "h245.g722_64k",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_256", HFILL }},
    { &hf_h245_g722_56k,
      { "g722-56k", "h245.g722_56k",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_256", HFILL }},
    { &hf_h245_g722_48k,
      { "g722-48k", "h245.g722_48k",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_256", HFILL }},
    { &hf_h245_g7231,
      { "g7231", "h245.g7231",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_maxAl_sduAudioFrames,
      { "maxAl-sduAudioFrames", "h245.maxAl_sduAudioFrames",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_256", HFILL }},
    { &hf_h245_silenceSuppression,
      { "silenceSuppression", "h245.silenceSuppression",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_g728,
      { "g728", "h245.g728",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_256", HFILL }},
    { &hf_h245_g729,
      { "g729", "h245.g729",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_256", HFILL }},
    { &hf_h245_g729AnnexA,
      { "g729AnnexA", "h245.g729AnnexA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_256", HFILL }},
    { &hf_h245_is11172AudioCapability,
      { "is11172AudioCapability", "h245.is11172AudioCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_is13818AudioCapability,
      { "is13818AudioCapability", "h245.is13818AudioCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_g729wAnnexB,
      { "g729wAnnexB", "h245.g729wAnnexB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_256", HFILL }},
    { &hf_h245_g729AnnexAwAnnexB,
      { "g729AnnexAwAnnexB", "h245.g729AnnexAwAnnexB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_256", HFILL }},
    { &hf_h245_g7231AnnexCCapability,
      { "g7231AnnexCCapability", "h245.g7231AnnexCCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_gsmFullRate,
      { "gsmFullRate", "h245.gsmFullRate",
        FT_NONE, BASE_NONE, NULL, 0,
        "GSMAudioCapability", HFILL }},
    { &hf_h245_gsmHalfRate,
      { "gsmHalfRate", "h245.gsmHalfRate",
        FT_NONE, BASE_NONE, NULL, 0,
        "GSMAudioCapability", HFILL }},
    { &hf_h245_gsmEnhancedFullRate,
      { "gsmEnhancedFullRate", "h245.gsmEnhancedFullRate",
        FT_NONE, BASE_NONE, NULL, 0,
        "GSMAudioCapability", HFILL }},
    { &hf_h245_genericAudioCapability,
      { "genericAudioCapability", "h245.genericAudioCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        "GenericCapability", HFILL }},
    { &hf_h245_g729Extensions,
      { "g729Extensions", "h245.g729Extensions",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_vbd,
      { "vbd", "h245.vbd",
        FT_NONE, BASE_NONE, NULL, 0,
        "VBDCapability", HFILL }},
    { &hf_h245_audioTelephonyEvent,
      { "audioTelephonyEvent", "h245.audioTelephonyEvent",
        FT_NONE, BASE_NONE, NULL, 0,
        "NoPTAudioTelephonyEventCapability", HFILL }},
    { &hf_h245_audioTone,
      { "audioTone", "h245.audioTone",
        FT_NONE, BASE_NONE, NULL, 0,
        "NoPTAudioToneCapability", HFILL }},
    { &hf_h245_audioUnit,
      { "audioUnit", "h245.audioUnit",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_256", HFILL }},
    { &hf_h245_annexA,
      { "annexA", "h245.annexA",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_annexB,
      { "annexB", "h245.annexB",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_annexD,
      { "annexD", "h245.annexD",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_annexE,
      { "annexE", "h245.annexE",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_annexF,
      { "annexF", "h245.annexF",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_annexG,
      { "annexG", "h245.annexG",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_annexH,
      { "annexH", "h245.annexH",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_highRateMode0,
      { "highRateMode0", "h245.highRateMode0",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_27_78", HFILL }},
    { &hf_h245_highRateMode1,
      { "highRateMode1", "h245.highRateMode1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_27_78", HFILL }},
    { &hf_h245_lowRateMode0,
      { "lowRateMode0", "h245.lowRateMode0",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_23_66", HFILL }},
    { &hf_h245_lowRateMode1,
      { "lowRateMode1", "h245.lowRateMode1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_23_66", HFILL }},
    { &hf_h245_sidMode0,
      { "sidMode0", "h245.sidMode0",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_6_17", HFILL }},
    { &hf_h245_sidMode1,
      { "sidMode1", "h245.sidMode1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_6_17", HFILL }},
    { &hf_h245_g723AnnexCAudioMode,
      { "g723AnnexCAudioMode", "h245.g723AnnexCAudioMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_audioLayer1,
      { "audioLayer1", "h245.audioLayer1",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_audioLayer2,
      { "audioLayer2", "h245.audioLayer2",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_audioLayer3,
      { "audioLayer3", "h245.audioLayer3",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_audioSampling32k,
      { "audioSampling32k", "h245.audioSampling32k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_audioSampling44k1,
      { "audioSampling44k1", "h245.audioSampling44k1",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_audioSampling48k,
      { "audioSampling48k", "h245.audioSampling48k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_singleChannel,
      { "singleChannel", "h245.singleChannel",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_twoChannels,
      { "twoChannels", "h245.twoChannels",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_bitRate_1_448,
      { "bitRate", "h245.bitRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_448", HFILL }},
    { &hf_h245_audioSampling16k,
      { "audioSampling16k", "h245.audioSampling16k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_audioSampling22k05,
      { "audioSampling22k05", "h245.audioSampling22k05",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_audioSampling24k,
      { "audioSampling24k", "h245.audioSampling24k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_threeChannels2_1,
      { "threeChannels2-1", "h245.threeChannels2_1",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_threeChannels3_0,
      { "threeChannels3-0", "h245.threeChannels3_0",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_fourChannels2_0_2_0,
      { "fourChannels2-0-2-0", "h245.fourChannels2_0_2_0",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_fourChannels2_2,
      { "fourChannels2-2", "h245.fourChannels2_2",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_fourChannels3_1,
      { "fourChannels3-1", "h245.fourChannels3_1",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_fiveChannels3_0_2_0,
      { "fiveChannels3-0-2-0", "h245.fiveChannels3_0_2_0",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_fiveChannels3_2,
      { "fiveChannels3-2", "h245.fiveChannels3_2",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_lowFrequencyEnhancement,
      { "lowFrequencyEnhancement", "h245.lowFrequencyEnhancement",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_multilingual,
      { "multilingual", "h245.multilingual",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_bitRate2_1_1130,
      { "bitRate", "h245.bitRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_1130", HFILL }},
    { &hf_h245_audioUnitSize,
      { "audioUnitSize", "h245.audioUnitSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_256", HFILL }},
    { &hf_h245_comfortNoise,
      { "comfortNoise", "h245.comfortNoise",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_scrambled,
      { "scrambled", "h245.scrambled",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_vbd_cap_type,
      { "type", "h245.type",
        FT_UINT32, BASE_DEC, VALS(h245_AudioCapability_vals), 0,
        "AudioCapability", HFILL }},
    { &hf_h245_t120,
      { "t120", "h245.t120",
        FT_UINT32, BASE_DEC, VALS(DataProtocolCapability_vals), 0,
        "DataProtocolCapability", HFILL }},
    { &hf_h245_dsm_cc,
      { "dsm-cc", "h245.dsm_cc",
        FT_UINT32, BASE_DEC, VALS(DataProtocolCapability_vals), 0,
        "DataProtocolCapability", HFILL }},
    { &hf_h245_userData,
      { "userData", "h245.userData",
        FT_UINT32, BASE_DEC, VALS(DataProtocolCapability_vals), 0,
        "DataProtocolCapability", HFILL }},
    { &hf_h245_t84,
      { "t84", "h245.t84",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_t84Protocol,
      { "t84Protocol", "h245.t84Protocol",
        FT_UINT32, BASE_DEC, VALS(DataProtocolCapability_vals), 0,
        "DataProtocolCapability", HFILL }},
    { &hf_h245_t84Profile,
      { "t84Profile", "h245.t84Profile",
        FT_UINT32, BASE_DEC, VALS(h245_T84Profile_vals), 0,
        NULL, HFILL }},
    { &hf_h245_t434,
      { "t434", "h245.t434",
        FT_UINT32, BASE_DEC, VALS(DataProtocolCapability_vals), 0,
        "DataProtocolCapability", HFILL }},
    { &hf_h245_h224,
      { "h224", "h245.h224",
        FT_UINT32, BASE_DEC, VALS(DataProtocolCapability_vals), 0,
        "DataProtocolCapability", HFILL }},
    { &hf_h245_nlpidProtocol,
      { "nlpidProtocol", "h245.nlpidProtocol",
        FT_UINT32, BASE_DEC, VALS(DataProtocolCapability_vals), 0,
        "DataProtocolCapability", HFILL }},
    { &hf_h245_nlpidData,
      { "nlpidData", "h245.nlpidData",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_h245_nlpid,
      { "nlpid", "h245.nlpid",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_dsvdControl,
      { "dsvdControl", "h245.dsvdControl",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_h222DataPartitioning,
      { "h222DataPartitioning", "h245.h222DataPartitioning",
        FT_UINT32, BASE_DEC, VALS(DataProtocolCapability_vals), 0,
        "DataProtocolCapability", HFILL }},
    { &hf_h245_t30fax,
      { "t30fax", "h245.t30fax",
        FT_UINT32, BASE_DEC, VALS(DataProtocolCapability_vals), 0,
        "DataProtocolCapability", HFILL }},
    { &hf_h245_t140,
      { "t140", "h245.t140",
        FT_UINT32, BASE_DEC, VALS(DataProtocolCapability_vals), 0,
        "DataProtocolCapability", HFILL }},
    { &hf_h245_t38fax,
      { "t38fax", "h245.t38fax",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_t38FaxProtocol,
      { "t38FaxProtocol", "h245.t38FaxProtocol",
        FT_UINT32, BASE_DEC, VALS(DataProtocolCapability_vals), 0,
        "DataProtocolCapability", HFILL }},
    { &hf_h245_t38FaxProfile,
      { "t38FaxProfile", "h245.t38FaxProfile",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_genericDataCapability,
      { "genericDataCapability", "h245.genericDataCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        "GenericCapability", HFILL }},
    { &hf_h245_application,
      { "application", "h245.application",
        FT_UINT32, BASE_DEC, VALS(h245_Application_vals), 0,
        NULL, HFILL }},
    { &hf_h245_maxBitRate2_0_4294967295,
      { "maxBitRate", "h245.maxBitRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_h245_v14buffered,
      { "v14buffered", "h245.v14buffered",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_v42lapm,
      { "v42lapm", "h245.v42lapm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_hdlcFrameTunnelling,
      { "hdlcFrameTunnelling", "h245.hdlcFrameTunnelling",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_h310SeparateVCStack,
      { "h310SeparateVCStack", "h245.h310SeparateVCStack",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_h310SingleVCStack,
      { "h310SingleVCStack", "h245.h310SingleVCStack",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_transparent,
      { "transparent", "h245.transparent",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_segmentationAndReassembly,
      { "segmentationAndReassembly", "h245.segmentationAndReassembly",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_hdlcFrameTunnelingwSAR,
      { "hdlcFrameTunnelingwSAR", "h245.hdlcFrameTunnelingwSAR",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_v120,
      { "v120", "h245.v120",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_separateLANStack,
      { "separateLANStack", "h245.separateLANStack",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_v76wCompression,
      { "v76wCompression", "h245.v76wCompression",
        FT_UINT32, BASE_DEC, VALS(h245_T_v76wCompression_vals), 0,
        NULL, HFILL }},
    { &hf_h245_transmitCompression,
      { "transmitCompression", "h245.transmitCompression",
        FT_UINT32, BASE_DEC, VALS(h245_CompressionType_vals), 0,
        "CompressionType", HFILL }},
    { &hf_h245_receiveCompression,
      { "receiveCompression", "h245.receiveCompression",
        FT_UINT32, BASE_DEC, VALS(h245_CompressionType_vals), 0,
        "CompressionType", HFILL }},
    { &hf_h245_transmitAndReceiveCompression,
      { "transmitAndReceiveCompression", "h245.transmitAndReceiveCompression",
        FT_UINT32, BASE_DEC, VALS(h245_CompressionType_vals), 0,
        "CompressionType", HFILL }},
    { &hf_h245_tcp,
      { "tcp", "h245.tcp",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_udp,
      { "udp", "h245.udp",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_v42bis,
      { "v42bis", "h245.v42bis",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_numberOfCodewords,
      { "numberOfCodewords", "h245.numberOfCodewords",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65536", HFILL }},
    { &hf_h245_maximumStringLength,
      { "maximumStringLength", "h245.maximumStringLength",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_256", HFILL }},
    { &hf_h245_t84Unrestricted,
      { "t84Unrestricted", "h245.t84Unrestricted",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_t84Restricted,
      { "t84Restricted", "h245.t84Restricted",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_qcif_bool,
      { "qcif", "h245.qcif",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_cif_bool,
      { "cif", "h245.cif",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_ccir601Seq,
      { "ccir601Seq", "h245.ccir601Seq",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_ccir601Prog,
      { "ccir601Prog", "h245.ccir601Prog",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_hdtvSeq,
      { "hdtvSeq", "h245.hdtvSeq",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_hdtvProg,
      { "hdtvProg", "h245.hdtvProg",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_g3FacsMH200x100,
      { "g3FacsMH200x100", "h245.g3FacsMH200x100",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_g3FacsMH200x200,
      { "g3FacsMH200x200", "h245.g3FacsMH200x200",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_g4FacsMMR200x100,
      { "g4FacsMMR200x100", "h245.g4FacsMMR200x100",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_g4FacsMMR200x200,
      { "g4FacsMMR200x200", "h245.g4FacsMMR200x200",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_jbig200x200Seq,
      { "jbig200x200Seq", "h245.jbig200x200Seq",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_jbig200x200Prog,
      { "jbig200x200Prog", "h245.jbig200x200Prog",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_jbig300x300Seq,
      { "jbig300x300Seq", "h245.jbig300x300Seq",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_jbig300x300Prog,
      { "jbig300x300Prog", "h245.jbig300x300Prog",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_digPhotoLow,
      { "digPhotoLow", "h245.digPhotoLow",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_digPhotoMedSeq,
      { "digPhotoMedSeq", "h245.digPhotoMedSeq",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_digPhotoMedProg,
      { "digPhotoMedProg", "h245.digPhotoMedProg",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_digPhotoHighSeq,
      { "digPhotoHighSeq", "h245.digPhotoHighSeq",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_digPhotoHighProg,
      { "digPhotoHighProg", "h245.digPhotoHighProg",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_fillBitRemoval,
      { "fillBitRemoval", "h245.fillBitRemoval",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_transcodingJBIG,
      { "transcodingJBIG", "h245.transcodingJBIG",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_transcodingMMR,
      { "transcodingMMR", "h245.transcodingMMR",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_version,
      { "version", "h245.version",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h245_t38FaxRateManagement,
      { "t38FaxRateManagement", "h245.t38FaxRateManagement",
        FT_UINT32, BASE_DEC, VALS(h245_T38FaxRateManagement_vals), 0,
        NULL, HFILL }},
    { &hf_h245_t38FaxUdpOptions,
      { "t38FaxUdpOptions", "h245.t38FaxUdpOptions",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_t38FaxTcpOptions,
      { "t38FaxTcpOptions", "h245.t38FaxTcpOptions",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_localTCF,
      { "localTCF", "h245.localTCF",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_transferredTCF,
      { "transferredTCF", "h245.transferredTCF",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_t38FaxMaxBuffer,
      { "t38FaxMaxBuffer", "h245.t38FaxMaxBuffer",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_h245_t38FaxMaxDatagram,
      { "t38FaxMaxDatagram", "h245.t38FaxMaxDatagram",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_h245_t38FaxUdpEC,
      { "t38FaxUdpEC", "h245.t38FaxUdpEC",
        FT_UINT32, BASE_DEC, VALS(h245_T_t38FaxUdpEC_vals), 0,
        NULL, HFILL }},
    { &hf_h245_t38UDPFEC,
      { "t38UDPFEC", "h245.t38UDPFEC",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_t38UDPRedundancy,
      { "t38UDPRedundancy", "h245.t38UDPRedundancy",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_t38TCPBidirectionalMode,
      { "t38TCPBidirectionalMode", "h245.t38TCPBidirectionalMode",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_encryptionCapability,
      { "encryptionCapability", "h245.encryptionCapability",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_authenticationCapability,
      { "authenticationCapability", "h245.authenticationCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_integrityCapability,
      { "integrityCapability", "h245.integrityCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_genericH235SecurityCapability,
      { "genericH235SecurityCapability", "h245.genericH235SecurityCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        "GenericCapability", HFILL }},
    { &hf_h245_EncryptionCapability_item,
      { "MediaEncryptionAlgorithm", "h245.MediaEncryptionAlgorithm",
        FT_UINT32, BASE_DEC, VALS(h245_MediaEncryptionAlgorithm_vals), 0,
        NULL, HFILL }},
    { &hf_h245_algorithm,
      { "algorithm", "h245.algorithm",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_h245_antiSpamAlgorithm,
      { "antiSpamAlgorithm", "h245.antiSpamAlgorithm",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_h245_ui_nonStandard,
      { "nonStandard", "h245.nonStandard",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_16_OF_NonStandardParameter", HFILL }},
    { &hf_h245_ui_nonStandard_item,
      { "NonStandardParameter", "h245.NonStandardParameter",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_basicString,
      { "basicString", "h245.basicString",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_iA5String,
      { "iA5String", "h245.iA5String",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_generalString,
      { "generalString", "h245.generalString",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_dtmf,
      { "dtmf", "h245.dtmf",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_hookflash,
      { "hookflash", "h245.hookflash",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_extendedAlphanumericFlag,
      { "extendedAlphanumeric", "h245.extendedAlphanumeric",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_encryptedBasicString,
      { "encryptedBasicString", "h245.encryptedBasicString",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_encryptedIA5String,
      { "encryptedIA5String", "h245.encryptedIA5String",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_encryptedGeneralString,
      { "encryptedGeneralString", "h245.encryptedGeneralString",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_secureDTMF,
      { "secureDTMF", "h245.secureDTMF",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_genericUserInputCapability,
      { "genericUserInputCapability", "h245.genericUserInputCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        "GenericCapability", HFILL }},
    { &hf_h245_nonStandardParams,
      { "nonStandardData", "h245.nonStandardData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_NonStandardParameter", HFILL }},
    { &hf_h245_nonStandardParams_item,
      { "NonStandardParameter", "h245.NonStandardParameter",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_chairControlCapability,
      { "chairControlCapability", "h245.chairControlCapability",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_videoIndicateMixingCapability,
      { "videoIndicateMixingCapability", "h245.videoIndicateMixingCapability",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_multipointVisualizationCapability,
      { "multipointVisualizationCapability", "h245.multipointVisualizationCapability",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_capabilityIdentifier,
      { "capabilityIdentifier", "h245.capabilityIdentifier",
        FT_UINT32, BASE_DEC, VALS(h245_CapabilityIdentifier_vals), 0,
        NULL, HFILL }},
    { &hf_h245_collapsing,
      { "collapsing", "h245.collapsing",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_collapsing_item,
      { "collapsing item", "h245.collapsing_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_nonCollapsing,
      { "nonCollapsing", "h245.nonCollapsing",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_nonCollapsing_item,
      { "nonCollapsing item", "h245.nonCollapsing_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_nonCollapsingRaw,
      { "nonCollapsingRaw", "h245.nonCollapsingRaw",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_transport,
      { "transport", "h245.transport",
        FT_UINT32, BASE_DEC, VALS(DataProtocolCapability_vals), 0,
        "DataProtocolCapability", HFILL }},
    { &hf_h245_standardOid,
      { "standard", "h245.standard",
        FT_OID, BASE_NONE, NULL, 0,
        "T_standardOid", HFILL }},
    { &hf_h245_h221NonStandard,
      { "h221NonStandard", "h245.h221NonStandard",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_h245_uuid,
      { "uuid", "h245.uuid",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_16", HFILL }},
    { &hf_h245_domainBased,
      { "domainBased", "h245.domainBased",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_64", HFILL }},
    { &hf_h245_parameterIdentifier,
      { "parameterIdentifier", "h245.parameterIdentifier",
        FT_UINT32, BASE_DEC, VALS(h245_ParameterIdentifier_vals), 0,
        NULL, HFILL }},
    { &hf_h245_parameterValue,
      { "parameterValue", "h245.parameterValue",
        FT_UINT32, BASE_DEC, VALS(h245_ParameterValue_vals), 0,
        NULL, HFILL }},
    { &hf_h245_supersedes,
      { "supersedes", "h245.supersedes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ParameterIdentifier", HFILL }},
    { &hf_h245_supersedes_item,
      { "ParameterIdentifier", "h245.ParameterIdentifier",
        FT_UINT32, BASE_DEC, VALS(h245_ParameterIdentifier_vals), 0,
        NULL, HFILL }},
    { &hf_h245_standard,
      { "standard", "h245.standard",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_logical,
      { "logical", "h245.logical",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_booleanArray,
      { "booleanArray", "h245.booleanArray",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_unsignedMin,
      { "unsignedMin", "h245.unsignedMin",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_unsignedMax,
      { "unsignedMax", "h245.unsignedMax",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_unsigned32Min,
      { "unsigned32Min", "h245.unsigned32Min",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_unsigned32Max,
      { "unsigned32Max", "h245.unsigned32Max",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_octetString,
      { "octetString", "h245.octetString",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_genericParameters,
      { "genericParameter", "h245.genericParameter",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_GenericParameter", HFILL }},
    { &hf_h245_genericParameters_item,
      { "GenericParameter", "h245.GenericParameter",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_multiplexFormat,
      { "multiplexFormat", "h245.multiplexFormat",
        FT_UINT32, BASE_DEC, VALS(h245_MultiplexFormat_vals), 0,
        NULL, HFILL }},
    { &hf_h245_controlOnMuxStream,
      { "controlOnMuxStream", "h245.controlOnMuxStream",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_capabilityOnMuxStream,
      { "capabilityOnMuxStream", "h245.capabilityOnMuxStream",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_256_OF_AlternativeCapabilitySet", HFILL }},
    { &hf_h245_capabilityOnMuxStream_item,
      { "AlternativeCapabilitySet", "h245.AlternativeCapabilitySet",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_dynamicRTPPayloadType,
      { "dynamicRTPPayloadType", "h245.dynamicRTPPayloadType",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_96_127", HFILL }},
    { &hf_h245_audioTelephoneEvent,
      { "audioTelephoneEvent", "h245.audioTelephoneEvent",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralString", HFILL }},
    { &hf_h245_capabilities,
      { "capabilities", "h245.capabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_256_OF_AlternativeCapabilitySet", HFILL }},
    { &hf_h245_capabilities_item,
      { "AlternativeCapabilitySet", "h245.AlternativeCapabilitySet",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_fecc_rfc2733,
      { "rfc2733", "h245.rfc2733",
        FT_NONE, BASE_NONE, NULL, 0,
        "FECC_rfc2733", HFILL }},
    { &hf_h245_redundancyEncodingBool,
      { "redundancyEncoding", "h245.redundancyEncoding",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_separateStreamBool,
      { "separateStream", "h245.separateStream",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_separateStreamBool", HFILL }},
    { &hf_h245_separatePort,
      { "separatePort", "h245.separatePort",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_samePortBool,
      { "samePort", "h245.samePort",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_protectedCapability,
      { "protectedCapability", "h245.protectedCapability",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CapabilityTableEntryNumber", HFILL }},
    { &hf_h245_fecScheme,
      { "fecScheme", "h245.fecScheme",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_h245_rfc2733rfc2198,
      { "rfc2733rfc2198", "h245.rfc2733rfc2198",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MaxRedundancy", HFILL }},
    { &hf_h245_rfc2733sameport,
      { "rfc2733sameport", "h245.rfc2733sameport",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MaxRedundancy", HFILL }},
    { &hf_h245_rfc2733diffport,
      { "rfc2733diffport", "h245.rfc2733diffport",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MaxRedundancy", HFILL }},
    { &hf_h245_rfc2733Format,
      { "rfc2733Format", "h245.rfc2733Format",
        FT_UINT32, BASE_DEC, VALS(h245_Rfc2733Format_vals), 0,
        NULL, HFILL }},
    { &hf_h245_olc_fw_lcn,
      { "forwardLogicalChannelNumber", "h245.forwardLogicalChannelNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "OLC_fw_lcn", HFILL }},
    { &hf_h245_forwardLogicalChannelParameters,
      { "forwardLogicalChannelParameters", "h245.forwardLogicalChannelParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_portNumber,
      { "portNumber", "h245.portNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h245_dataType,
      { "dataType", "h245.dataType",
        FT_UINT32, BASE_DEC, VALS(h245_DataType_vals), 0,
        NULL, HFILL }},
    { &hf_h245_olc_forw_multiplexParameters,
      { "multiplexParameters", "h245.multiplexParameters",
        FT_UINT32, BASE_DEC, VALS(h245_OLC_forw_multiplexParameters_vals), 0,
        "OLC_forw_multiplexParameters", HFILL }},
    { &hf_h245_h222LogicalChannelParameters,
      { "h222LogicalChannelParameters", "h245.h222LogicalChannelParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_olc_fw_h223_params,
      { "h223LogicalChannelParameters", "h245.h223LogicalChannelParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "OLC_fw_h223_params", HFILL }},
    { &hf_h245_v76LogicalChannelParameters,
      { "v76LogicalChannelParameters", "h245.v76LogicalChannelParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_h2250LogicalChannelParameters,
      { "h2250LogicalChannelParameters", "h245.h2250LogicalChannelParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_forwardLogicalChannelDependency,
      { "forwardLogicalChannelDependency", "h245.forwardLogicalChannelDependency",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LogicalChannelNumber", HFILL }},
    { &hf_h245_replacementFor,
      { "replacementFor", "h245.replacementFor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LogicalChannelNumber", HFILL }},
    { &hf_h245_reverseLogicalChannelParameters,
      { "reverseLogicalChannelParameters", "h245.reverseLogicalChannelParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "OLC_reverseLogicalChannelParameters", HFILL }},
    { &hf_h245_olc_rev_multiplexParameter,
      { "multiplexParameters", "h245.multiplexParameters",
        FT_UINT32, BASE_DEC, VALS(h245_OLC_rev_multiplexParameters_vals), 0,
        "OLC_rev_multiplexParameters", HFILL }},
    { &hf_h245_olc_rev_h223_params,
      { "h223LogicalChannelParameters", "h245.h223LogicalChannelParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "OLC_rev_h223_params", HFILL }},
    { &hf_h245_reverseLogicalChannelDependency,
      { "reverseLogicalChannelDependency", "h245.reverseLogicalChannelDependency",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LogicalChannelNumber", HFILL }},
    { &hf_h245_separateStack,
      { "separateStack", "h245.separateStack",
        FT_NONE, BASE_NONE, NULL, 0,
        "NetworkAccessParameters", HFILL }},
    { &hf_h245_encryptionSync,
      { "encryptionSync", "h245.encryptionSync",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_distribution,
      { "distribution", "h245.distribution",
        FT_UINT32, BASE_DEC, VALS(h245_T_distribution_vals), 0,
        NULL, HFILL }},
    { &hf_h245_unicast,
      { "unicast", "h245.unicast",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_multicast,
      { "multicast", "h245.multicast",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_networkAddress,
      { "networkAddress", "h245.networkAddress",
        FT_UINT32, BASE_DEC, VALS(h245_T_networkAddress_vals), 0,
        NULL, HFILL }},
    { &hf_h245_q2931Address,
      { "q2931Address", "h245.q2931Address",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_e164Address,
      { "e164Address", "h245.e164Address",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_localAreaAddress,
      { "localAreaAddress", "h245.localAreaAddress",
        FT_UINT32, BASE_DEC, VALS(h245_TransportAddress_vals), 0,
        "TransportAddress", HFILL }},
    { &hf_h245_associateConference,
      { "associateConference", "h245.associateConference",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_externalReference,
      { "externalReference", "h245.externalReference",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_255", HFILL }},
    { &hf_h245_t120SetupProcedure,
      { "t120SetupProcedure", "h245.t120SetupProcedure",
        FT_UINT32, BASE_DEC, VALS(h245_T_t120SetupProcedure_vals), 0,
        NULL, HFILL }},
    { &hf_h245_originateCall,
      { "originateCall", "h245.originateCall",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_waitForCall,
      { "waitForCall", "h245.waitForCall",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_issueQuery,
      { "issueQuery", "h245.issueQuery",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_address,
      { "address", "h245.address",
        FT_UINT32, BASE_DEC, VALS(h245_T_address_vals), 0,
        NULL, HFILL }},
    { &hf_h245_internationalNumber,
      { "internationalNumber", "h245.internationalNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumericString_SIZE_1_16", HFILL }},
    { &hf_h245_nsapAddress,
      { "nsapAddress", "h245.nsapAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_h245_subaddress,
      { "subaddress", "h245.subaddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_h245_audioHeaderPresent,
      { "audioHeaderPresent", "h245.audioHeaderPresent",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_nullData,
      { "nullData", "h245.nullData",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_videoData,
      { "videoData", "h245.videoData",
        FT_UINT32, BASE_DEC, VALS(h245_VideoCapability_vals), 0,
        "VideoCapability", HFILL }},
    { &hf_h245_audioData,
      { "audioData", "h245.audioData",
        FT_UINT32, BASE_DEC, VALS(h245_AudioCapability_vals), 0,
        "AudioCapability", HFILL }},
    { &hf_h245_data,
      { "data", "h245.data",
        FT_NONE, BASE_NONE, NULL, 0,
        "DataApplicationCapability", HFILL }},
    { &hf_h245_encryptionData,
      { "encryptionData", "h245.encryptionData",
        FT_UINT32, BASE_DEC, VALS(h245_EncryptionMode_vals), 0,
        "EncryptionMode", HFILL }},
    { &hf_h245_h235Control,
      { "h235Control", "h245.h235Control",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_h245_h235Media,
      { "h235Media", "h245.h235Media",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_multiplexedStream,
      { "multiplexedStream", "h245.multiplexedStream",
        FT_NONE, BASE_NONE, NULL, 0,
        "MultiplexedStreamParameter", HFILL }},
    { &hf_h245_redundancyEncoding,
      { "redundancyEncoding", "h245.redundancyEncoding",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_multiplePayloadStream,
      { "multiplePayloadStream", "h245.multiplePayloadStream",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_depFec,
      { "depFec", "h245.depFec",
        FT_UINT32, BASE_DEC, VALS(h245_DepFECData_vals), 0,
        "DepFECData", HFILL }},
    { &hf_h245_fec,
      { "fec", "h245.fec",
        FT_UINT32, BASE_DEC, VALS(h245_FECData_vals), 0,
        "FECData", HFILL }},
    { &hf_h245_mediaType,
      { "mediaType", "h245.mediaType",
        FT_UINT32, BASE_DEC, VALS(h245_T_mediaType_vals), 0,
        NULL, HFILL }},
    { &hf_h245_resourceID,
      { "resourceID", "h245.resourceID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h245_subChannelID,
      { "subChannelID", "h245.subChannelID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_8191", HFILL }},
    { &hf_h245_pcr_pid,
      { "pcr-pid", "h245.pcr_pid",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_8191", HFILL }},
    { &hf_h245_programDescriptors,
      { "programDescriptors", "h245.programDescriptors",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_h245_streamDescriptors,
      { "streamDescriptors", "h245.streamDescriptors",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_h245_adaptationLayerType,
      { "adaptationLayerType", "h245.adaptationLayerType",
        FT_UINT32, BASE_DEC, VALS(h245_T_adaptationLayerType_vals), 0,
        NULL, HFILL }},
    { &hf_h245_h223_al_type_al1Framed,
      { "al1Framed", "h245.al1Framed",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_h223_al_type_al1Framed", HFILL }},
    { &hf_h245_h223_al_type_al1NotFramed,
      { "al1NotFramed", "h245.al1NotFramed",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_h223_al_type_al1NotFramed", HFILL }},
    { &hf_h245_h223_al_type_al2WithoutSequenceNumbers,
      { "al2WithoutSequenceNumbers", "h245.al2WithoutSequenceNumbers",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_h223_al_type_al2WithoutSequenceNumbers", HFILL }},
    { &hf_h245_h223_al_type_al2WithSequenceNumbers,
      { "al2WithSequenceNumbers", "h245.al2WithSequenceNumbers",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_h223_al_type_al2WithSequenceNumbers", HFILL }},
    { &hf_h245_controlFieldOctets,
      { "controlFieldOctets", "h245.controlFieldOctets",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_al3_sendBufferSize,
      { "sendBufferSize", "h245.sendBufferSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_al3_sendBufferSize", HFILL }},
    { &hf_h245_h223_al_type_al3,
      { "al3", "h245.al3",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_h223_al_type_al3", HFILL }},
    { &hf_h245_h223_al_type_al1M,
      { "al1M", "h245.al1M",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_h223_al_type_al1M", HFILL }},
    { &hf_h245_h223_al_type_al2M,
      { "al2M", "h245.al2M",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_h223_al_type_al2M", HFILL }},
    { &hf_h245_h223_al_type_al3M,
      { "al3M", "h245.al3M",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_h223_al_type_al3M", HFILL }},
    { &hf_h245_h223_lc_segmentableFlag,
      { "segmentableFlag", "h245.segmentableFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "T_h223_lc_segmentableFlag", HFILL }},
    { &hf_h245_transferMode,
      { "transferMode", "h245.transferMode",
        FT_UINT32, BASE_DEC, VALS(h245_T_transferMode_vals), 0,
        NULL, HFILL }},
    { &hf_h245_framed,
      { "framed", "h245.framed",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_unframed,
      { "unframed", "h245.unframed",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_aL1HeaderFEC,
      { "headerFEC", "h245.headerFEC",
        FT_UINT32, BASE_DEC, VALS(h245_AL1HeaderFEC_vals), 0,
        "AL1HeaderFEC", HFILL }},
    { &hf_h245_sebch16_7,
      { "sebch16-7", "h245.sebch16_7",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_golay24_12,
      { "golay24-12", "h245.golay24_12",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_crcLength2,
      { "crcLength", "h245.crcLength",
        FT_UINT32, BASE_DEC, VALS(h245_AL1CrcLength_vals), 0,
        "AL1CrcLength", HFILL }},
    { &hf_h245_crc4bit,
      { "crc4bit", "h245.crc4bit",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_crc12bit,
      { "crc12bit", "h245.crc12bit",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_crc20bit,
      { "crc20bit", "h245.crc20bit",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_crc28bit,
      { "crc28bit", "h245.crc28bit",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_crc8bit,
      { "crc8bit", "h245.crc8bit",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_crc16bit,
      { "crc16bit", "h245.crc16bit",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_crc32bit,
      { "crc32bit", "h245.crc32bit",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_crcNotUsed,
      { "crcNotUsed", "h245.crcNotUsed",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_rcpcCodeRate,
      { "rcpcCodeRate", "h245.rcpcCodeRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_8_32", HFILL }},
    { &hf_h245_noArq,
      { "noArq", "h245.noArq",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_typeIArq,
      { "typeIArq", "h245.typeIArq",
        FT_NONE, BASE_NONE, NULL, 0,
        "H223AnnexCArqParameters", HFILL }},
    { &hf_h245_typeIIArq,
      { "typeIIArq", "h245.typeIIArq",
        FT_NONE, BASE_NONE, NULL, 0,
        "H223AnnexCArqParameters", HFILL }},
    { &hf_h245_arqType,
      { "arqType", "h245.arqType",
        FT_UINT32, BASE_DEC, VALS(h245_ArqType_vals), 0,
        NULL, HFILL }},
    { &hf_h245_alsduSplitting,
      { "alsduSplitting", "h245.alsduSplitting",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_rsCodeCorrection,
      { "rsCodeCorrection", "h245.rsCodeCorrection",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_h245_aL2HeaderFEC,
      { "headerFEC", "h245.headerFEC",
        FT_UINT32, BASE_DEC, VALS(h245_AL2HeaderFEC_vals), 0,
        "AL2HeaderFEC", HFILL }},
    { &hf_h245_sebch16_5,
      { "sebch16-5", "h245.sebch16_5",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_headerFormat,
      { "headerFormat", "h245.headerFormat",
        FT_UINT32, BASE_DEC, VALS(h245_T_headerFormat_vals), 0,
        NULL, HFILL }},
    { &hf_h245_crlength2,
      { "crcLength", "h245.crcLength",
        FT_UINT32, BASE_DEC, VALS(h245_AL3CrcLength_vals), 0,
        "AL3CrcLength", HFILL }},
    { &hf_h245_numberOfRetransmissions,
      { "numberOfRetransmissions", "h245.numberOfRetransmissions",
        FT_UINT32, BASE_DEC, VALS(h245_T_numberOfRetransmissions_vals), 0,
        NULL, HFILL }},
    { &hf_h245_finite,
      { "finite", "h245.finite",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16", HFILL }},
    { &hf_h245_infinite,
      { "infinite", "h245.infinite",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_sendBufferSize,
      { "sendBufferSize", "h245.sendBufferSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16777215", HFILL }},
    { &hf_h245_hdlcParameters,
      { "hdlcParameters", "h245.hdlcParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "V76HDLCParameters", HFILL }},
    { &hf_h245_suspendResume,
      { "suspendResume", "h245.suspendResume",
        FT_UINT32, BASE_DEC, VALS(h245_T_suspendResume_vals), 0,
        NULL, HFILL }},
    { &hf_h245_noSuspendResume,
      { "noSuspendResume", "h245.noSuspendResume",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_suspendResumewAddress,
      { "suspendResumewAddress", "h245.suspendResumewAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_suspendResumewoAddress,
      { "suspendResumewoAddress", "h245.suspendResumewoAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_uIH,
      { "uIH", "h245.uIH",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_v76_mode,
      { "mode", "h245.mode",
        FT_UINT32, BASE_DEC, VALS(h245_V76LCP_mode_vals), 0,
        "V76LCP_mode", HFILL }},
    { &hf_h245_eRM,
      { "eRM", "h245.eRM",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_windowSize,
      { "windowSize", "h245.windowSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_127", HFILL }},
    { &hf_h245_recovery,
      { "recovery", "h245.recovery",
        FT_UINT32, BASE_DEC, VALS(h245_T_recovery_vals), 0,
        NULL, HFILL }},
    { &hf_h245_rej,
      { "rej", "h245.rej",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_sREJ,
      { "sREJ", "h245.sREJ",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_mSREJ,
      { "mSREJ", "h245.mSREJ",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_uNERM,
      { "uNERM", "h245.uNERM",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_v75Parameters,
      { "v75Parameters", "h245.v75Parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_crcLength,
      { "crcLength", "h245.crcLength",
        FT_UINT32, BASE_DEC, VALS(h245_CRCLength_vals), 0,
        NULL, HFILL }},
    { &hf_h245_n401,
      { "n401", "h245.n401",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_4095", HFILL }},
    { &hf_h245_loopbackTestProcedure,
      { "loopbackTestProcedure", "h245.loopbackTestProcedure",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_sessionID_0_255,
      { "sessionID", "h245.sessionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h245_associatedSessionID,
      { "associatedSessionID", "h245.associatedSessionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_255", HFILL }},
    { &hf_h245_mediaChannel,
      { "mediaChannel", "h245.mediaChannel",
        FT_UINT32, BASE_DEC, VALS(h245_TransportAddress_vals), 0,
        NULL, HFILL }},
    { &hf_h245_mediaGuaranteedDelivery,
      { "mediaGuaranteedDelivery", "h245.mediaGuaranteedDelivery",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_mediaControlChannel,
      { "mediaControlChannel", "h245.mediaControlChannel",
        FT_UINT32, BASE_DEC, VALS(h245_TransportAddress_vals), 0,
        NULL, HFILL }},
    { &hf_h245_mediaControlGuaranteedDelivery,
      { "mediaControlGuaranteedDelivery", "h245.mediaControlGuaranteedDelivery",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_destination,
      { "destination", "h245.destination",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminalLabel", HFILL }},
    { &hf_h245_mediaPacketization,
      { "mediaPacketization", "h245.mediaPacketization",
        FT_UINT32, BASE_DEC, VALS(h245_T_mediaPacketization_vals), 0,
        NULL, HFILL }},
    { &hf_h245_h261aVideoPacketizationFlag,
      { "h261aVideoPacketization", "h245.h261aVideoPacketization",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_rtpPayloadType,
      { "rtpPayloadType", "h245.rtpPayloadType",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_source,
      { "source", "h245.source",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminalLabel", HFILL }},
    { &hf_h245_payloadDescriptor,
      { "payloadDescriptor", "h245.payloadDescriptor",
        FT_UINT32, BASE_DEC, VALS(h245_T_payloadDescriptor_vals), 0,
        NULL, HFILL }},
    { &hf_h245_rfc_number,
      { "rfc-number", "h245.rfc_number",
        FT_UINT32, BASE_DEC, VALS(h245_RFC_number_vals), 0,
        NULL, HFILL }},
    { &hf_h245_oid,
      { "oid", "h245.oid",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_h245_rtpPayloadType_01,
      { "payloadType", "h245.payloadType",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_rtpPayloadType", HFILL }},
    { &hf_h245_secondaryEncoding,
      { "secondaryEncoding", "h245.secondaryEncoding",
        FT_UINT32, BASE_DEC, VALS(h245_DataType_vals), 0,
        "DataType", HFILL }},
    { &hf_h245_rtpRedundancyEncoding,
      { "rtpRedundancyEncoding", "h245.rtpRedundancyEncoding",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_primary,
      { "primary", "h245.primary",
        FT_NONE, BASE_NONE, NULL, 0,
        "RedundancyEncodingElement", HFILL }},
    { &hf_h245_secondary,
      { "secondary", "h245.secondary",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_RedundancyEncodingElement", HFILL }},
    { &hf_h245_secondary_item,
      { "RedundancyEncodingElement", "h245.RedundancyEncodingElement",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_payloadType,
      { "payloadType", "h245.payloadType",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_h245_elements,
      { "elements", "h245.elements",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_MultiplePayloadStreamElement", HFILL }},
    { &hf_h245_elements_item,
      { "MultiplePayloadStreamElement", "h245.MultiplePayloadStreamElement",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_dep_rfc2733,
      { "rfc2733", "h245.rfc2733",
        FT_NONE, BASE_NONE, NULL, 0,
        "RFC2733Data", HFILL }},
    { &hf_h245_fec_data_mode,
      { "mode", "h245.mode",
        FT_UINT32, BASE_DEC, VALS(h245_FECdata_mode_vals), 0,
        "FECdata_mode", HFILL }},
    { &hf_h245_redundancyEncodingFlag,
      { "redundancyEncoding", "h245.redundancyEncoding",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_differentPort,
      { "differentPort", "h245.differentPort",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_protectedSessionID,
      { "protectedSessionID", "h245.protectedSessionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_255", HFILL }},
    { &hf_h245_protectedPayloadType,
      { "protectedPayloadType", "h245.protectedPayloadType",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_h245_samePort,
      { "samePort", "h245.samePort",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_separateStream,
      { "separateStream", "h245.separateStream",
        FT_UINT32, BASE_DEC, VALS(h245_DepSeparateStream_vals), 0,
        "DepSeparateStream", HFILL }},
    { &hf_h245_rfc2733,
      { "rfc2733", "h245.rfc2733",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_pktMode,
      { "pktMode", "h245.pktMode",
        FT_UINT32, BASE_DEC, VALS(h245_T_pktMode_vals), 0,
        NULL, HFILL }},
    { &hf_h245_rfc2198coding,
      { "rfc2198coding", "h245.rfc2198coding",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_mode_rfc2733sameport,
      { "rfc2733sameport", "h245.rfc2733sameport",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_mode_rfc2733sameport", HFILL }},
    { &hf_h245_mode_rfc2733diffport,
      { "rfc2733diffport", "h245.rfc2733diffport",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_mode_rfc2733diffport", HFILL }},
    { &hf_h245_protectedChannel,
      { "protectedChannel", "h245.protectedChannel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LogicalChannelNumber", HFILL }},
    { &hf_h245_unicastAddress,
      { "unicastAddress", "h245.unicastAddress",
        FT_UINT32, BASE_DEC, VALS(h245_UnicastAddress_vals), 0,
        NULL, HFILL }},
    { &hf_h245_multicastAddress,
      { "multicastAddress", "h245.multicastAddress",
        FT_UINT32, BASE_DEC, VALS(h245_MulticastAddress_vals), 0,
        NULL, HFILL }},
    { &hf_h245_iPAddress,
      { "iPAddress", "h245.iPAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_ip4_network,
      { "network", "h245.network",
        FT_IPv4, BASE_NONE, NULL, 0,
        "Ipv4_network", HFILL }},
    { &hf_h245_tsapIdentifier,
      { "tsapIdentifier", "h245.tsapIdentifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_iPXAddress,
      { "iPXAddress", "h245.iPXAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_node,
      { "node", "h245.node",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_6", HFILL }},
    { &hf_h245_netnum,
      { "netnum", "h245.netnum",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_h245_ipx_tsapIdentifier,
      { "tsapIdentifier", "h245.tsapIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_2", HFILL }},
    { &hf_h245_iP6Address,
      { "iP6Address", "h245.iP6Address",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_ip6_network,
      { "network", "h245.network",
        FT_IPv6, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_16", HFILL }},
    { &hf_h245_ipv6_tsapIdentifier,
      { "tsapIdentifier", "h245.tsapIdentifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h245_netBios,
      { "netBios", "h245.netBios",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_16", HFILL }},
    { &hf_h245_iPSourceRouteAddress,
      { "iPSourceRouteAddress", "h245.iPSourceRouteAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_routing,
      { "routing", "h245.routing",
        FT_UINT32, BASE_DEC, VALS(h245_T_routing_vals), 0,
        NULL, HFILL }},
    { &hf_h245_strict,
      { "strict", "h245.strict",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_loose,
      { "loose", "h245.loose",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_network,
      { "network", "h245.network",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_h245_iPSrcRoute_tsapIdentifier,
      { "tsapIdentifier", "h245.tsapIdentifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h245_route,
      { "route", "h245.route",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_route_item,
      { "route item", "h245.route_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_h245_nsap,
      { "nsap", "h245.nsap",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_h245_nonStandardAddress,
      { "nonStandardAddress", "h245.nonStandardAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_h245_mIPAddress,
      { "iPAddress", "h245.iPAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "MIPAddress", HFILL }},
    { &hf_h245_mip4_network,
      { "network", "h245.network",
        FT_IPv4, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_h245_multicast_tsapIdentifier,
      { "tsapIdentifier", "h245.tsapIdentifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h245_mIP6Address,
      { "iP6Address", "h245.iP6Address",
        FT_NONE, BASE_NONE, NULL, 0,
        "MIP6Address", HFILL }},
    { &hf_h245_mip6_network,
      { "network", "h245.network",
        FT_IPv6, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_16", HFILL }},
    { &hf_h245_multicast_IPv6_tsapIdentifier,
      { "tsapIdentifier", "h245.tsapIdentifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h245_synchFlag,
      { "synchFlag", "h245.synchFlag",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h245_h235Key,
      { "h235Key", "h245.h235Key",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_65535", HFILL }},
    { &hf_h245_escrowentry,
      { "escrowentry", "h245.escrowentry",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_256_OF_EscrowData", HFILL }},
    { &hf_h245_escrowentry_item,
      { "EscrowData", "h245.EscrowData",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_genericParameter,
      { "genericParameter", "h245.genericParameter",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_escrowID,
      { "escrowID", "h245.escrowID",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_h245_escrowValue,
      { "escrowValue", "h245.escrowValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1_65535", HFILL }},
    { &hf_h245_olc_ack_fw_lcn,
      { "forwardLogicalChannelNumber", "h245.forwardLogicalChannelNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "OLC_ack_fw_lcn", HFILL }},
    { &hf_h245_olc_ack_reverseLogicalChannelParameters,
      { "reverseLogicalChannelParameters", "h245.reverseLogicalChannelParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "OLC_ack_reverseLogicalChannelParameters", HFILL }},
    { &hf_h245_reverseLogicalChannelNumber,
      { "reverseLogicalChannelNumber", "h245.reverseLogicalChannelNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_olc_ack_multiplexParameters,
      { "multiplexParameters", "h245.multiplexParameters",
        FT_UINT32, BASE_DEC, VALS(h245_T_olc_ack_multiplexParameters_vals), 0,
        "T_olc_ack_multiplexParameters", HFILL }},
    { &hf_h245_forwardMultiplexAckParameters,
      { "forwardMultiplexAckParameters", "h245.forwardMultiplexAckParameters",
        FT_UINT32, BASE_DEC, VALS(h245_T_forwardMultiplexAckParameters_vals), 0,
        NULL, HFILL }},
    { &hf_h245_h2250LogicalChannelAckParameters,
      { "h2250LogicalChannelAckParameters", "h245.h2250LogicalChannelAckParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_forwardLogicalChannelNumber,
      { "forwardLogicalChannelNumber", "h245.forwardLogicalChannelNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LogicalChannelNumber", HFILL }},
    { &hf_h245_olc_rej_cause,
      { "cause", "h245.cause",
        FT_UINT32, BASE_DEC, VALS(h245_OpenLogicalChannelRejectCause_vals), 0,
        "OpenLogicalChannelRejectCause", HFILL }},
    { &hf_h245_unsuitableReverseParameters,
      { "unsuitableReverseParameters", "h245.unsuitableReverseParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_dataTypeNotSupported,
      { "dataTypeNotSupported", "h245.dataTypeNotSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_dataTypeNotAvailable,
      { "dataTypeNotAvailable", "h245.dataTypeNotAvailable",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_unknownDataType,
      { "unknownDataType", "h245.unknownDataType",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_dataTypeALCombinationNotSupported,
      { "dataTypeALCombinationNotSupported", "h245.dataTypeALCombinationNotSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_multicastChannelNotAllowed,
      { "multicastChannelNotAllowed", "h245.multicastChannelNotAllowed",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_insufficientBandwidth,
      { "insufficientBandwidth", "h245.insufficientBandwidth",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_separateStackEstablishmentFailed,
      { "separateStackEstablishmentFailed", "h245.separateStackEstablishmentFailed",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_invalidSessionID,
      { "invalidSessionID", "h245.invalidSessionID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_masterSlaveConflict,
      { "masterSlaveConflict", "h245.masterSlaveConflict",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_waitForCommunicationMode,
      { "waitForCommunicationMode", "h245.waitForCommunicationMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_invalidDependentChannel,
      { "invalidDependentChannel", "h245.invalidDependentChannel",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_replacementForRejected,
      { "replacementForRejected", "h245.replacementForRejected",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_securityDenied,
      { "securityDenied", "h245.securityDenied",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_qoSControlNotSupported,
      { "qoSControlNotSupported", "h245.qoSControlNotSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_sessionID,
      { "sessionID", "h245.sessionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_255", HFILL }},
    { &hf_h245_ack_mediaChannel,
      { "mediaChannel", "h245.mediaChannel",
        FT_UINT32, BASE_DEC, VALS(h245_TransportAddress_vals), 0,
        "Ack_mediaChannel", HFILL }},
    { &hf_h245_ack_mediaControlChannel,
      { "mediaControlChannel", "h245.mediaControlChannel",
        FT_UINT32, BASE_DEC, VALS(h245_TransportAddress_vals), 0,
        "Ack_mediaControlChannel", HFILL }},
    { &hf_h245_flowControlToZero,
      { "flowControlToZero", "h245.flowControlToZero",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_cLC_source,
      { "source", "h245.source",
        FT_UINT32, BASE_DEC, VALS(h245_T_cLC_source_vals), 0,
        "T_cLC_source", HFILL }},
    { &hf_h245_user,
      { "user", "h245.user",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_lcse,
      { "lcse", "h245.lcse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_clc_reason,
      { "reason", "h245.reason",
        FT_UINT32, BASE_DEC, VALS(h245_Clc_reason_vals), 0,
        "Clc_reason", HFILL }},
    { &hf_h245_unknown,
      { "unknown", "h245.unknown",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_reopen,
      { "reopen", "h245.reopen",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_reservationFailure,
      { "reservationFailure", "h245.reservationFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_networkErrorCode,
      { "networkErrorCode", "h245.networkErrorCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h245_qosCapability,
      { "qosCapability", "h245.qosCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_reason,
      { "reason", "h245.reason",
        FT_UINT32, BASE_DEC, VALS(h245_T_reason_vals), 0,
        NULL, HFILL }},
    { &hf_h245_normal,
      { "normal", "h245.normal",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_req_chan_clos_rej_cause,
      { "cause", "h245.cause",
        FT_UINT32, BASE_DEC, VALS(h245_RequestChannelCloseRejectCause_vals), 0,
        "RequestChannelCloseRejectCause", HFILL }},
    { &hf_h245_multiplexEntryDescriptors,
      { "multiplexEntryDescriptors", "h245.multiplexEntryDescriptors",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_15_OF_MultiplexEntryDescriptor", HFILL }},
    { &hf_h245_multiplexEntryDescriptors_item,
      { "MultiplexEntryDescriptor", "h245.MultiplexEntryDescriptor",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_multiplexTableEntryNumber,
      { "multiplexTableEntryNumber", "h245.multiplexTableEntryNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_elementList,
      { "elementList", "h245.elementList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_elementList_item,
      { "MultiplexElement", "h245.MultiplexElement",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_me_type,
      { "type", "h245.type",
        FT_UINT32, BASE_DEC, VALS(h245_Me_type_vals), 0,
        "Me_type", HFILL }},
    { &hf_h245_logicalChannelNum,
      { "logicalChannelNumber", "h245.logicalChannelNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_logicalChannelNum", HFILL }},
    { &hf_h245_subElementList,
      { "subElementList", "h245.subElementList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_subElementList_item,
      { "MultiplexElement", "h245.MultiplexElement",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_me_repeatCount,
      { "repeatCount", "h245.repeatCount",
        FT_UINT32, BASE_DEC, VALS(h245_ME_repeatCount_vals), 0,
        "ME_repeatCount", HFILL }},
    { &hf_h245_me_repeatCount_finite,
      { "finite", "h245.finite",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ME_finiteRepeatCount", HFILL }},
    { &hf_h245_untilClosingFlag,
      { "untilClosingFlag", "h245.untilClosingFlag",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_multiplexTableEntryNumbers,
      { "multiplexTableEntryNumber", "h245.multiplexTableEntryNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_15_OF_MultiplexTableEntryNumber", HFILL }},
    { &hf_h245_multiplexTableEntryNumbers_item,
      { "MultiplexTableEntryNumber", "h245.MultiplexTableEntryNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_sendRejectionDescriptions,
      { "rejectionDescriptions", "h245.rejectionDescriptions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_15_OF_MultiplexEntryRejectionDescriptions", HFILL }},
    { &hf_h245_sendRejectionDescriptions_item,
      { "MultiplexEntryRejectionDescriptions", "h245.MultiplexEntryRejectionDescriptions",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_mux_rej_cause,
      { "cause", "h245.cause",
        FT_UINT32, BASE_DEC, VALS(h245_MultiplexEntryRejectionDescriptionsCause_vals), 0,
        "MultiplexEntryRejectionDescriptionsCause", HFILL }},
    { &hf_h245_unspecifiedCause,
      { "unspecifiedCause", "h245.unspecifiedCause",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_descriptorTooComplex,
      { "descriptorTooComplex", "h245.descriptorTooComplex",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_entryNumbers,
      { "entryNumbers", "h245.entryNumbers",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_15_OF_MultiplexTableEntryNumber", HFILL }},
    { &hf_h245_entryNumbers_item,
      { "MultiplexTableEntryNumber", "h245.MultiplexTableEntryNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_rejectionDescriptions,
      { "rejectionDescriptions", "h245.rejectionDescriptions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_15_OF_RequestMultiplexEntryRejectionDescriptions", HFILL }},
    { &hf_h245_rejectionDescriptions_item,
      { "RequestMultiplexEntryRejectionDescriptions", "h245.RequestMultiplexEntryRejectionDescriptions",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_req_mux_rej_cause,
      { "cause", "h245.cause",
        FT_UINT32, BASE_DEC, VALS(h245_RequestMultiplexEntryRejectionDescriptionsCause_vals), 0,
        "RequestMultiplexEntryRejectionDescriptionsCause", HFILL }},
    { &hf_h245_requestedModes,
      { "requestedModes", "h245.requestedModes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_256_OF_ModeDescription", HFILL }},
    { &hf_h245_requestedModes_item,
      { "ModeDescription", "h245.ModeDescription",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_req_mode_ack_response,
      { "response", "h245.response",
        FT_UINT32, BASE_DEC, VALS(h245_Req_mode_ack_response_vals), 0,
        "Req_mode_ack_response", HFILL }},
    { &hf_h245_willTransmitMostPreferredMode,
      { "willTransmitMostPreferredMode", "h245.willTransmitMostPreferredMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_willTransmitLessPreferredMode,
      { "willTransmitLessPreferredMode", "h245.willTransmitLessPreferredMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_req_rej_cause,
      { "cause", "h245.cause",
        FT_UINT32, BASE_DEC, VALS(h245_RequestModeRejectCause_vals), 0,
        "RequestModeRejectCause", HFILL }},
    { &hf_h245_modeUnavailable,
      { "modeUnavailable", "h245.modeUnavailable",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_multipointConstraint,
      { "multipointConstraint", "h245.multipointConstraint",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_requestDenied,
      { "requestDenied", "h245.requestDenied",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_ModeDescription_item,
      { "ModeElement", "h245.ModeElement",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_videoMode,
      { "videoMode", "h245.videoMode",
        FT_UINT32, BASE_DEC, VALS(h245_VideoMode_vals), 0,
        NULL, HFILL }},
    { &hf_h245_audioMode,
      { "audioMode", "h245.audioMode",
        FT_UINT32, BASE_DEC, VALS(h245_AudioMode_vals), 0,
        NULL, HFILL }},
    { &hf_h245_dataMode,
      { "dataMode", "h245.dataMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_encryptionMode,
      { "encryptionMode", "h245.encryptionMode",
        FT_UINT32, BASE_DEC, VALS(h245_EncryptionMode_vals), 0,
        NULL, HFILL }},
    { &hf_h245_h235Mode,
      { "h235Mode", "h245.h235Mode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_multiplexedStreamMode,
      { "multiplexedStreamMode", "h245.multiplexedStreamMode",
        FT_NONE, BASE_NONE, NULL, 0,
        "MultiplexedStreamParameter", HFILL }},
    { &hf_h245_redundancyEncodingDTMode,
      { "redundancyEncodingDTMode", "h245.redundancyEncodingDTMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_multiplePayloadStreamMode,
      { "multiplePayloadStreamMode", "h245.multiplePayloadStreamMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_depFecMode,
      { "depFecMode", "h245.depFecMode",
        FT_UINT32, BASE_DEC, VALS(h245_DepFECMode_vals), 0,
        NULL, HFILL }},
    { &hf_h245_fecMode,
      { "fecMode", "h245.fecMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_type,
      { "type", "h245.type",
        FT_UINT32, BASE_DEC, VALS(h245_ModeElementType_vals), 0,
        "ModeElementType", HFILL }},
    { &hf_h245_h223ModeParameters,
      { "h223ModeParameters", "h245.h223ModeParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_v76ModeParameters,
      { "v76ModeParameters", "h245.v76ModeParameters",
        FT_UINT32, BASE_DEC, VALS(h245_V76ModeParameters_vals), 0,
        NULL, HFILL }},
    { &hf_h245_h2250ModeParameters,
      { "h2250ModeParameters", "h245.h2250ModeParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_genericModeParameters,
      { "genericModeParameters", "h245.genericModeParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "GenericCapability", HFILL }},
    { &hf_h245_multiplexedStreamModeParameters,
      { "multiplexedStreamModeParameters", "h245.multiplexedStreamModeParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_logicalChannelNumber,
      { "logicalChannelNumber", "h245.logicalChannelNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_mediaMode,
      { "mediaMode", "h245.mediaMode",
        FT_UINT32, BASE_DEC, VALS(h245_T_mediaMode_vals), 0,
        NULL, HFILL }},
    { &hf_h245_prmary_dtmode,
      { "primary", "h245.primary",
        FT_NONE, BASE_NONE, NULL, 0,
        "RedundancyEncodingDTModeElement", HFILL }},
    { &hf_h245_secondaryDTM,
      { "secondary", "h245.secondary",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_RedundancyEncodingDTModeElement", HFILL }},
    { &hf_h245_secondaryDTM_item,
      { "RedundancyEncodingDTModeElement", "h245.RedundancyEncodingDTModeElement",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_re_type,
      { "type", "h245.type",
        FT_UINT32, BASE_DEC, VALS(h245_Re_type_vals), 0,
        "Re_type", HFILL }},
    { &hf_h245_mpsmElements,
      { "elements", "h245.elements",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_MultiplePayloadStreamElementMode", HFILL }},
    { &hf_h245_mpsmElements_item,
      { "MultiplePayloadStreamElementMode", "h245.MultiplePayloadStreamElementMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_rfc2733Mode,
      { "rfc2733Mode", "h245.rfc2733Mode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_fec_mode,
      { "mode", "h245.mode",
        FT_UINT32, BASE_DEC, VALS(h245_FEC_mode_vals), 0,
        "FEC_mode", HFILL }},
    { &hf_h245_protectedElement,
      { "protectedElement", "h245.protectedElement",
        FT_UINT32, BASE_DEC, VALS(h245_ModeElementType_vals), 0,
        "ModeElementType", HFILL }},
    { &hf_h245_adaptationLayer,
      { "adaptationLayerType", "h245.adaptationLayerType",
        FT_UINT32, BASE_DEC, VALS(h245_AdaptationLayerType_vals), 0,
        NULL, HFILL }},
    { &hf_h245_al1Framed,
      { "al1Framed", "h245.al1Framed",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_al1NotFramed,
      { "al1NotFramed", "h245.al1NotFramed",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_al2WithoutSequenceNumbers,
      { "al2WithoutSequenceNumbers", "h245.al2WithoutSequenceNumbers",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_al2WithSequenceNumbers,
      { "al2WithSequenceNumbers", "h245.al2WithSequenceNumbers",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_al3,
      { "al3", "h245.al3",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_al1M,
      { "al1M", "h245.al1M",
        FT_NONE, BASE_NONE, NULL, 0,
        "H223AL1MParameters", HFILL }},
    { &hf_h245_al2M,
      { "al2M", "h245.al2M",
        FT_NONE, BASE_NONE, NULL, 0,
        "H223AL2MParameters", HFILL }},
    { &hf_h245_al3M,
      { "al3M", "h245.al3M",
        FT_NONE, BASE_NONE, NULL, 0,
        "H223AL3MParameters", HFILL }},
    { &hf_h245_segmentableFlag,
      { "segmentableFlag", "h245.segmentableFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_redundancyEncodingMode,
      { "redundancyEncodingMode", "h245.redundancyEncodingMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_secondaryEncodingMode,
      { "secondaryEncoding", "h245.secondaryEncoding",
        FT_UINT32, BASE_DEC, VALS(h245_T_secondaryEncodingMode_vals), 0,
        "T_secondaryEncodingMode", HFILL }},
    { &hf_h245_h261VideoMode,
      { "h261VideoMode", "h245.h261VideoMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_h262VideoMode,
      { "h262VideoMode", "h245.h262VideoMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_h263VideoMode,
      { "h263VideoMode", "h245.h263VideoMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_is11172VideoMode,
      { "is11172VideoMode", "h245.is11172VideoMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_genericVideoMode,
      { "genericVideoMode", "h245.genericVideoMode",
        FT_NONE, BASE_NONE, NULL, 0,
        "GenericCapability", HFILL }},
    { &hf_h245_h261_resolution,
      { "resolution", "h245.resolution",
        FT_UINT32, BASE_DEC, VALS(h245_H261Resolution_vals), 0,
        "H261Resolution", HFILL }},
    { &hf_h245_qcif,
      { "qcif", "h245.qcif",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_cif,
      { "cif", "h245.cif",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_profileAndLevel,
      { "profileAndLevel", "h245.profileAndLevel",
        FT_UINT32, BASE_DEC, VALS(h245_T_profileAndLevel_vals), 0,
        NULL, HFILL }},
    { &hf_h245_profileAndLevel_SPatMLMode,
      { "profileAndLevel-SPatML", "h245.profileAndLevel_SPatML",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_profileAndLevel_MPatLLMode,
      { "profileAndLevel-MPatLL", "h245.profileAndLevel_MPatLL",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_profileAndLevel_MPatMLMode,
      { "profileAndLevel-MPatML", "h245.profileAndLevel_MPatML",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_profileAndLevel_MPatH_14Mode,
      { "profileAndLevel-MPatH-14", "h245.profileAndLevel_MPatH_14",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_profileAndLevel_MPatHLMode,
      { "profileAndLevel-MPatHL", "h245.profileAndLevel_MPatHL",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_profileAndLevel_SNRatLLMode,
      { "profileAndLevel-SNRatLL", "h245.profileAndLevel_SNRatLL",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_profileAndLevel_SNRatMLMode,
      { "profileAndLevel-SNRatML", "h245.profileAndLevel_SNRatML",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_profileAndLevel_SpatialatH_14Mode,
      { "profileAndLevel-SpatialatH-14", "h245.profileAndLevel_SpatialatH_14",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_profileAndLevel_HPatMLMode,
      { "profileAndLevel-HPatML", "h245.profileAndLevel_HPatML",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_profileAndLevel_HPatH_14Mode,
      { "profileAndLevel-HPatH-14", "h245.profileAndLevel_HPatH_14",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_profileAndLevel_HPatHLMode,
      { "profileAndLevel-HPatHL", "h245.profileAndLevel_HPatHL",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_h263_resolution,
      { "resolution", "h245.resolution",
        FT_UINT32, BASE_DEC, VALS(h245_H263Resolution_vals), 0,
        "H263Resolution", HFILL }},
    { &hf_h245_sqcif,
      { "sqcif", "h245.sqcif",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_cif4,
      { "cif4", "h245.cif4",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_cif16,
      { "cif16", "h245.cif16",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_custom_res,
      { "custom", "h245.custom",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_g711Alaw64k_mode,
      { "g711Alaw64k", "h245.g711Alaw64k",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_g711Alaw56k_mode,
      { "g711Alaw56k", "h245.g711Alaw56k",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_g711Ulaw64k_mode,
      { "g711Ulaw64k", "h245.g711Ulaw64k",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_g711Ulaw56k_mode,
      { "g711Ulaw56k", "h245.g711Ulaw56k",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_g722_64k_mode,
      { "g722-64k", "h245.g722_64k",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_g722_56k_mode,
      { "g722-56k", "h245.g722_56k",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_g722_48k_mode,
      { "g722-48k", "h245.g722_48k",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_g728_mode,
      { "g728", "h245.g728",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_g729_mode,
      { "g729", "h245.g729",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_g729AnnexA_mode,
      { "g729AnnexA", "h245.g729AnnexA",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_g7231_mode,
      { "g7231", "h245.g7231",
        FT_UINT32, BASE_DEC, VALS(h245_Mode_g7231_vals), 0,
        "Mode_g7231", HFILL }},
    { &hf_h245_noSilenceSuppressionLowRate,
      { "noSilenceSuppressionLowRate", "h245.noSilenceSuppressionLowRate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_noSilenceSuppressionHighRate,
      { "noSilenceSuppressionHighRate", "h245.noSilenceSuppressionHighRate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_silenceSuppressionLowRate,
      { "silenceSuppressionLowRate", "h245.silenceSuppressionLowRate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_silenceSuppressionHighRate,
      { "silenceSuppressionHighRate", "h245.silenceSuppressionHighRate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_is11172AudioMode,
      { "is11172AudioMode", "h245.is11172AudioMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_is13818AudioMode,
      { "is13818AudioMode", "h245.is13818AudioMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_g7231AnnexCMode,
      { "g7231AnnexCMode", "h245.g7231AnnexCMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_genericAudioMode,
      { "genericAudioMode", "h245.genericAudioMode",
        FT_NONE, BASE_NONE, NULL, 0,
        "GenericCapability", HFILL }},
    { &hf_h245_vbd_mode,
      { "vbd", "h245.vbd",
        FT_NONE, BASE_NONE, NULL, 0,
        "VBDMode", HFILL }},
    { &hf_h245_audioLayer,
      { "audioLayer", "h245.audioLayer",
        FT_UINT32, BASE_DEC, VALS(h245_T_audioLayer_vals), 0,
        NULL, HFILL }},
    { &hf_h245_audioLayer1Mode,
      { "audioLayer1", "h245.audioLayer1",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_audioLayer2Mode,
      { "audioLayer2", "h245.audioLayer2",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_audioLayer3Mode,
      { "audioLayer3", "h245.audioLayer3",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_audioSampling,
      { "audioSampling", "h245.audioSampling",
        FT_UINT32, BASE_DEC, VALS(h245_T_audioSampling_vals), 0,
        NULL, HFILL }},
    { &hf_h245_audioSampling32kMode,
      { "audioSampling32k", "h245.audioSampling32k",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_audioSampling44k1Mode,
      { "audioSampling44k1", "h245.audioSampling44k1",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_audioSampling48kMode,
      { "audioSampling48k", "h245.audioSampling48k",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_is11172multichannelType,
      { "multichannelType", "h245.multichannelType",
        FT_UINT32, BASE_DEC, VALS(h245_IS11172_multichannelType_vals), 0,
        "IS11172_multichannelType", HFILL }},
    { &hf_h245_singleChannelMode,
      { "singleChannel", "h245.singleChannel",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_twoChannelStereo,
      { "twoChannelStereo", "h245.twoChannelStereo",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_twoChannelDual,
      { "twoChannelDual", "h245.twoChannelDual",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_audioLayerMode,
      { "audioLayer", "h245.audioLayer",
        FT_UINT32, BASE_DEC, VALS(h245_IS13818AudioLayer_vals), 0,
        "IS13818AudioLayer", HFILL }},
    { &hf_h245_audioSamplingMode,
      { "audioSampling", "h245.audioSampling",
        FT_UINT32, BASE_DEC, VALS(h245_IS13818AudioSampling_vals), 0,
        "IS13818AudioSampling", HFILL }},
    { &hf_h245_audioSampling16kMode,
      { "audioSampling16k", "h245.audioSampling16k",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_audioSampling22k05Mode,
      { "audioSampling22k05", "h245.audioSampling22k05",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_audioSampling24kMode,
      { "audioSampling24k", "h245.audioSampling24k",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_is13818MultichannelType,
      { "multichannelType", "h245.multichannelType",
        FT_UINT32, BASE_DEC, VALS(h245_IS13818MultichannelType_vals), 0,
        "IS13818MultichannelType", HFILL }},
    { &hf_h245_threeChannels2_1Mode,
      { "threeChannels2-1", "h245.threeChannels2_1",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_threeChannels3_0Mode,
      { "threeChannels3-0", "h245.threeChannels3_0",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_fourChannels2_0_2_0Mode,
      { "fourChannels2-0-2-0", "h245.fourChannels2_0_2_0",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_fourChannels2_2Mode,
      { "fourChannels2-2", "h245.fourChannels2_2",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_fourChannels3_1Mode,
      { "fourChannels3-1", "h245.fourChannels3_1",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_fiveChannels3_0_2_0Mode,
      { "fiveChannels3-0-2-0", "h245.fiveChannels3_0_2_0",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_fiveChannels3_2Mode,
      { "fiveChannels3-2", "h245.fiveChannels3_2",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_vbd_type,
      { "type", "h245.type",
        FT_UINT32, BASE_DEC, VALS(h245_AudioMode_vals), 0,
        "AudioMode", HFILL }},
    { &hf_h245_datamodeapplication,
      { "application", "h245.application",
        FT_UINT32, BASE_DEC, VALS(h245_DataModeApplication_vals), 0,
        "DataModeApplication", HFILL }},
    { &hf_h245_t84DataProtocolCapability,
      { "t84", "h245.t84",
        FT_UINT32, BASE_DEC, VALS(DataProtocolCapability_vals), 0,
        "DataProtocolCapability", HFILL }},
    { &hf_h245_t38faxDataProtocolCapability,
      { "t38fax", "h245.t38fax",
        FT_NONE, BASE_NONE, NULL, 0,
        "T38faxApp", HFILL }},
    { &hf_h245_genericDataMode,
      { "genericDataMode", "h245.genericDataMode",
        FT_NONE, BASE_NONE, NULL, 0,
        "GenericCapability", HFILL }},
    { &hf_h245_bitRate_0_4294967295,
      { "bitRate", "h245.bitRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_h245_h233Encryption,
      { "h233Encryption", "h245.h233Encryption",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_mlr_type,
      { "type", "h245.type",
        FT_UINT32, BASE_DEC, VALS(h245_Mlr_type_vals), 0,
        "Mlr_type", HFILL }},
    { &hf_h245_systemLoop,
      { "systemLoop", "h245.systemLoop",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_mediaLoop,
      { "mediaLoop", "h245.mediaLoop",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LogicalChannelNumber", HFILL }},
    { &hf_h245_logicalChannelLoop,
      { "logicalChannelLoop", "h245.logicalChannelLoop",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LogicalChannelNumber", HFILL }},
    { &hf_h245_mla_type,
      { "type", "h245.type",
        FT_UINT32, BASE_DEC, VALS(h245_Mla_type_vals), 0,
        "Mla_type", HFILL }},
    { &hf_h245_mlrej_type,
      { "type", "h245.type",
        FT_UINT32, BASE_DEC, VALS(h245_Mlrej_type_vals), 0,
        "Mlrej_type", HFILL }},
    { &hf_h245_maintloop_rej_cause,
      { "cause", "h245.cause",
        FT_UINT32, BASE_DEC, VALS(h245_MaintenanceLoopRejectCause_vals), 0,
        "MaintenanceLoopRejectCause", HFILL }},
    { &hf_h245_canNotPerformLoop,
      { "canNotPerformLoop", "h245.canNotPerformLoop",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_communicationModeTable,
      { "communicationModeTable", "h245.communicationModeTable",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_256_OF_CommunicationModeTableEntry", HFILL }},
    { &hf_h245_communicationModeTable_item,
      { "CommunicationModeTableEntry", "h245.CommunicationModeTableEntry",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_terminalLabel,
      { "terminalLabel", "h245.terminalLabel",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_sessionDescription,
      { "sessionDescription", "h245.sessionDescription",
        FT_STRING, BASE_NONE, NULL, 0,
        "BMPString_SIZE_1_128", HFILL }},
    { &hf_h245_entryDataType,
      { "dataType", "h245.dataType",
        FT_UINT32, BASE_DEC, VALS(h245_T_entryDataType_vals), 0,
        "T_entryDataType", HFILL }},
    { &hf_h245_cm_mediaChannel,
      { "mediaChannel", "h245.mediaChannel",
        FT_UINT32, BASE_DEC, VALS(h245_TransportAddress_vals), 0,
        "Cm_mediaChannel", HFILL }},
    { &hf_h245_cm_mediaControlChannel,
      { "mediaControlChannel", "h245.mediaControlChannel",
        FT_UINT32, BASE_DEC, VALS(h245_TransportAddress_vals), 0,
        "TransportAddress", HFILL }},
    { &hf_h245_sessionDependency,
      { "sessionDependency", "h245.sessionDependency",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_255", HFILL }},
    { &hf_h245_terminalListRequest,
      { "terminalListRequest", "h245.terminalListRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_makeMeChair,
      { "makeMeChair", "h245.makeMeChair",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_cancelMakeMeChair,
      { "cancelMakeMeChair", "h245.cancelMakeMeChair",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_dropTerminal,
      { "dropTerminal", "h245.dropTerminal",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminalLabel", HFILL }},
    { &hf_h245_requestTerminalID,
      { "requestTerminalID", "h245.requestTerminalID",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminalLabel", HFILL }},
    { &hf_h245_enterH243Password,
      { "enterH243Password", "h245.enterH243Password",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_enterH243TerminalID,
      { "enterH243TerminalID", "h245.enterH243TerminalID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_enterH243ConferenceID,
      { "enterH243ConferenceID", "h245.enterH243ConferenceID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_enterExtensionAddress,
      { "enterExtensionAddress", "h245.enterExtensionAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_requestChairTokenOwner,
      { "requestChairTokenOwner", "h245.requestChairTokenOwner",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_requestTerminalCertificate,
      { "requestTerminalCertificate", "h245.requestTerminalCertificate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_certSelectionCriteria,
      { "certSelectionCriteria", "h245.certSelectionCriteria",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_sRandom,
      { "sRandom", "h245.sRandom",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_4294967295", HFILL }},
    { &hf_h245_broadcastMyLogicalChannel,
      { "broadcastMyLogicalChannel", "h245.broadcastMyLogicalChannel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LogicalChannelNumber", HFILL }},
    { &hf_h245_makeTerminalBroadcaster,
      { "makeTerminalBroadcaster", "h245.makeTerminalBroadcaster",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminalLabel", HFILL }},
    { &hf_h245_sendThisSource,
      { "sendThisSource", "h245.sendThisSource",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminalLabel", HFILL }},
    { &hf_h245_requestAllTerminalIDs,
      { "requestAllTerminalIDs", "h245.requestAllTerminalIDs",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_remoteMCRequest,
      { "remoteMCRequest", "h245.remoteMCRequest",
        FT_UINT32, BASE_DEC, VALS(h245_RemoteMCRequest_vals), 0,
        NULL, HFILL }},
    { &hf_h245_CertSelectionCriteria_item,
      { "Criteria", "h245.Criteria",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_field,
      { "field", "h245.field",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_h245_criteriaValue,
      { "value", "h245.value",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_65535", HFILL }},
    { &hf_h245_mcuNumber,
      { "mcuNumber", "h245.mcuNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_terminalNumber,
      { "terminalNumber", "h245.terminalNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_mCTerminalIDResponse,
      { "mCTerminalIDResponse", "h245.mCTerminalIDResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_terminalID,
      { "terminalID", "h245.terminalID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_terminalIDResponse,
      { "terminalIDResponse", "h245.terminalIDResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_conferenceIDResponse,
      { "conferenceIDResponse", "h245.conferenceIDResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_conferenceID,
      { "conferenceID", "h245.conferenceID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_passwordResponse,
      { "passwordResponse", "h245.passwordResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_password,
      { "password", "h245.password",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_terminalListResponse,
      { "terminalListResponse", "h245.terminalListResponse",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_256_OF_TerminalLabel", HFILL }},
    { &hf_h245_terminalListResponse_item,
      { "TerminalLabel", "h245.TerminalLabel",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_videoCommandReject,
      { "videoCommandReject", "h245.videoCommandReject",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_terminalDropReject,
      { "terminalDropReject", "h245.terminalDropReject",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_makeMeChairResponse,
      { "makeMeChairResponse", "h245.makeMeChairResponse",
        FT_UINT32, BASE_DEC, VALS(h245_T_makeMeChairResponse_vals), 0,
        NULL, HFILL }},
    { &hf_h245_grantedChairToken,
      { "grantedChairToken", "h245.grantedChairToken",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_deniedChairToken,
      { "deniedChairToken", "h245.deniedChairToken",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_extensionAddressResponse,
      { "extensionAddressResponse", "h245.extensionAddressResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_extensionAddress,
      { "extensionAddress", "h245.extensionAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TerminalID", HFILL }},
    { &hf_h245_chairTokenOwnerResponse,
      { "chairTokenOwnerResponse", "h245.chairTokenOwnerResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_terminalCertificateResponse,
      { "terminalCertificateResponse", "h245.terminalCertificateResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_certificateResponse,
      { "certificateResponse", "h245.certificateResponse",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_65535", HFILL }},
    { &hf_h245_broadcastMyLogicalChannelResponse,
      { "broadcastMyLogicalChannelResponse", "h245.broadcastMyLogicalChannelResponse",
        FT_UINT32, BASE_DEC, VALS(h245_T_broadcastMyLogicalChannelResponse_vals), 0,
        NULL, HFILL }},
    { &hf_h245_grantedBroadcastMyLogicalChannel,
      { "grantedBroadcastMyLogicalChannel", "h245.grantedBroadcastMyLogicalChannel",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_deniedBroadcastMyLogicalChannel,
      { "deniedBroadcastMyLogicalChannel", "h245.deniedBroadcastMyLogicalChannel",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_makeTerminalBroadcasterResponse,
      { "makeTerminalBroadcasterResponse", "h245.makeTerminalBroadcasterResponse",
        FT_UINT32, BASE_DEC, VALS(h245_T_makeTerminalBroadcasterResponse_vals), 0,
        NULL, HFILL }},
    { &hf_h245_grantedMakeTerminalBroadcaster,
      { "grantedMakeTerminalBroadcaster", "h245.grantedMakeTerminalBroadcaster",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_deniedMakeTerminalBroadcaster,
      { "deniedMakeTerminalBroadcaster", "h245.deniedMakeTerminalBroadcaster",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_sendThisSourceResponse,
      { "sendThisSourceResponse", "h245.sendThisSourceResponse",
        FT_UINT32, BASE_DEC, VALS(h245_T_sendThisSourceResponse_vals), 0,
        NULL, HFILL }},
    { &hf_h245_grantedSendThisSource,
      { "grantedSendThisSource", "h245.grantedSendThisSource",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_deniedSendThisSource,
      { "deniedSendThisSource", "h245.deniedSendThisSource",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_requestAllTerminalIDsResponse,
      { "requestAllTerminalIDsResponse", "h245.requestAllTerminalIDsResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_remoteMCResponse,
      { "remoteMCResponse", "h245.remoteMCResponse",
        FT_UINT32, BASE_DEC, VALS(h245_RemoteMCResponse_vals), 0,
        NULL, HFILL }},
    { &hf_h245_terminalInformation,
      { "terminalInformation", "h245.terminalInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_TerminalInformation", HFILL }},
    { &hf_h245_terminalInformation_item,
      { "TerminalInformation", "h245.TerminalInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_masterActivate,
      { "masterActivate", "h245.masterActivate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_slaveActivate,
      { "slaveActivate", "h245.slaveActivate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_deActivate,
      { "deActivate", "h245.deActivate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_accept,
      { "accept", "h245.accept",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_reject,
      { "reject", "h245.reject",
        FT_UINT32, BASE_DEC, VALS(h245_T_reject_vals), 0,
        NULL, HFILL }},
    { &hf_h245_functionNotSupportedFlag,
      { "functionNotSupported", "h245.functionNotSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_callInformationReq,
      { "callInformation", "h245.callInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallInformationReq", HFILL }},
    { &hf_h245_maxNumberOfAdditionalConnections,
      { "maxNumberOfAdditionalConnections", "h245.maxNumberOfAdditionalConnections",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65535", HFILL }},
    { &hf_h245_addConnectionReq,
      { "addConnection", "h245.addConnection",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddConnectionReq", HFILL }},
    { &hf_h245_dialingInformation,
      { "dialingInformation", "h245.dialingInformation",
        FT_UINT32, BASE_DEC, VALS(h245_DialingInformation_vals), 0,
        NULL, HFILL }},
    { &hf_h245_removeConnectionReq,
      { "removeConnection", "h245.removeConnection",
        FT_NONE, BASE_NONE, NULL, 0,
        "RemoveConnectionReq", HFILL }},
    { &hf_h245_connectionIdentifier,
      { "connectionIdentifier", "h245.connectionIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_maximumHeaderIntervalReq,
      { "maximumHeaderInterval", "h245.maximumHeaderInterval",
        FT_NONE, BASE_NONE, NULL, 0,
        "MaximumHeaderIntervalReq", HFILL }},
    { &hf_h245_requestType,
      { "requestType", "h245.requestType",
        FT_UINT32, BASE_DEC, VALS(h245_T_requestType_vals), 0,
        NULL, HFILL }},
    { &hf_h245_currentIntervalInformation,
      { "currentIntervalInformation", "h245.currentIntervalInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_requestedInterval,
      { "requestedInterval", "h245.requestedInterval",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h245_callInformationResp,
      { "callInformation", "h245.callInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallInformationResp", HFILL }},
    { &hf_h245_callAssociationNumber,
      { "callAssociationNumber", "h245.callAssociationNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_h245_addConnectionResp,
      { "addConnection", "h245.addConnection",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddConnectionResp", HFILL }},
    { &hf_h245_responseCode,
      { "responseCode", "h245.responseCode",
        FT_UINT32, BASE_DEC, VALS(h245_T_responseCode_vals), 0,
        NULL, HFILL }},
    { &hf_h245_accepted,
      { "accepted", "h245.accepted",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_rejected,
      { "rejected", "h245.rejected",
        FT_UINT32, BASE_DEC, VALS(h245_T_rejected_vals), 0,
        NULL, HFILL }},
    { &hf_h245_connectionsNotAvailable,
      { "connectionsNotAvailable", "h245.connectionsNotAvailable",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_userRejected,
      { "userRejected", "h245.userRejected",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_removeConnectionResp,
      { "removeConnection", "h245.removeConnection",
        FT_NONE, BASE_NONE, NULL, 0,
        "RemoveConnectionResp", HFILL }},
    { &hf_h245_maximumHeaderIntervalResp,
      { "maximumHeaderInterval", "h245.maximumHeaderInterval",
        FT_NONE, BASE_NONE, NULL, 0,
        "MaximumHeaderIntervalResp", HFILL }},
    { &hf_h245_currentInterval,
      { "currentInterval", "h245.currentInterval",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h245_crcDesired,
      { "crcDesired", "h245.crcDesired",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_excessiveError,
      { "excessiveError", "h245.excessiveError",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_differential,
      { "differential", "h245.differential",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_65535_OF_DialingInformationNumber", HFILL }},
    { &hf_h245_differential_item,
      { "DialingInformationNumber", "h245.DialingInformationNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_infoNotAvailable,
      { "infoNotAvailable", "h245.infoNotAvailable",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65535", HFILL }},
    { &hf_h245_networkAddressNum,
      { "networkAddress", "h245.networkAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumericString_SIZE_0_40", HFILL }},
    { &hf_h245_subAddress,
      { "subAddress", "h245.subAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_40", HFILL }},
    { &hf_h245_networkType,
      { "networkType", "h245.networkType",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_255_OF_DialingInformationNetworkType", HFILL }},
    { &hf_h245_networkType_item,
      { "DialingInformationNetworkType", "h245.DialingInformationNetworkType",
        FT_UINT32, BASE_DEC, VALS(h245_DialingInformationNetworkType_vals), 0,
        NULL, HFILL }},
    { &hf_h245_n_isdn,
      { "n-isdn", "h245.n_isdn",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_gstn,
      { "gstn", "h245.gstn",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_mobile,
      { "mobile", "h245.mobile",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_channelTag,
      { "channelTag", "h245.channelTag",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_h245_sequenceNum,
      { "sequenceNumber", "h245.sequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_h245_maximumBitRate,
      { "maximumBitRate", "h245.maximumBitRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_rejectReason,
      { "rejectReason", "h245.rejectReason",
        FT_UINT32, BASE_DEC, VALS(h245_LogicalChannelRateRejectReason_vals), 0,
        "LogicalChannelRateRejectReason", HFILL }},
    { &hf_h245_currentMaximumBitRate,
      { "currentMaximumBitRate", "h245.currentMaximumBitRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MaximumBitRate", HFILL }},
    { &hf_h245_undefinedReason,
      { "undefinedReason", "h245.undefinedReason",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_insufficientResources,
      { "insufficientResources", "h245.insufficientResources",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_specificRequest,
      { "specificRequest", "h245.specificRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_multiplexCapabilityBool,
      { "multiplexCapability", "h245.multiplexCapability",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_capabilityTableEntryNumbers,
      { "capabilityTableEntryNumbers", "h245.capabilityTableEntryNumbers",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_65535_OF_CapabilityTableEntryNumber", HFILL }},
    { &hf_h245_capabilityTableEntryNumbers_item,
      { "CapabilityTableEntryNumber", "h245.CapabilityTableEntryNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_capabilityDescriptorNumbers,
      { "capabilityDescriptorNumbers", "h245.capabilityDescriptorNumbers",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_256_OF_CapabilityDescriptorNumber", HFILL }},
    { &hf_h245_capabilityDescriptorNumbers_item,
      { "CapabilityDescriptorNumber", "h245.CapabilityDescriptorNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_genericRequestFlag,
      { "genericRequest", "h245.genericRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_encryptionSE,
      { "encryptionSE", "h245.encryptionSE",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_h245_encryptionIVRequest,
      { "encryptionIVRequest", "h245.encryptionIVRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_encryptionAlgorithmID,
      { "encryptionAlgorithmID", "h245.encryptionAlgorithmID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_h233AlgorithmIdentifier,
      { "h233AlgorithmIdentifier", "h245.h233AlgorithmIdentifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SequenceNumber", HFILL }},
    { &hf_h245_associatedAlgorithm,
      { "associatedAlgorithm", "h245.associatedAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_h245_wholeMultiplex,
      { "wholeMultiplex", "h245.wholeMultiplex",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_scope,
      { "scope", "h245.scope",
        FT_UINT32, BASE_DEC, VALS(h245_Scope_vals), 0,
        NULL, HFILL }},
    { &hf_h245_res_maximumBitRate,
      { "maximumBitRate", "h245.maximumBitRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16777215", HFILL }},
    { &hf_h245_noRestriction,
      { "noRestriction", "h245.noRestriction",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_restriction,
      { "restriction", "h245.restriction",
        FT_UINT32, BASE_DEC, VALS(h245_Restriction_vals), 0,
        NULL, HFILL }},
    { &hf_h245_disconnect,
      { "disconnect", "h245.disconnect",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_gstnOptions,
      { "gstnOptions", "h245.gstnOptions",
        FT_UINT32, BASE_DEC, VALS(h245_T_gstnOptions_vals), 0,
        NULL, HFILL }},
    { &hf_h245_telephonyMode,
      { "telephonyMode", "h245.telephonyMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_v8bis,
      { "v8bis", "h245.v8bis",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_v34DSVD,
      { "v34DSVD", "h245.v34DSVD",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_v34DuplexFAX,
      { "v34DuplexFAX", "h245.v34DuplexFAX",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_v34H324,
      { "v34H324", "h245.v34H324",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_isdnOptions,
      { "isdnOptions", "h245.isdnOptions",
        FT_UINT32, BASE_DEC, VALS(h245_T_isdnOptions_vals), 0,
        NULL, HFILL }},
    { &hf_h245_v140,
      { "v140", "h245.v140",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_terminalOnHold,
      { "terminalOnHold", "h245.terminalOnHold",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_cancelBroadcastMyLogicalChannel,
      { "cancelBroadcastMyLogicalChannel", "h245.cancelBroadcastMyLogicalChannel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LogicalChannelNumber", HFILL }},
    { &hf_h245_cancelMakeTerminalBroadcaster,
      { "cancelMakeTerminalBroadcaster", "h245.cancelMakeTerminalBroadcaster",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_cancelSendThisSource,
      { "cancelSendThisSource", "h245.cancelSendThisSource",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_dropConference,
      { "dropConference", "h245.dropConference",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_substituteConferenceIDCommand,
      { "substituteConferenceIDCommand", "h245.substituteConferenceIDCommand",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_conferenceIdentifier,
      { "conferenceIdentifier", "h245.conferenceIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_16", HFILL }},
    { &hf_h245_masterToSlave,
      { "masterToSlave", "h245.masterToSlave",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_slaveToMaster,
      { "slaveToMaster", "h245.slaveToMaster",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_mc_type,
      { "type", "h245.type",
        FT_UINT32, BASE_DEC, VALS(h245_Mc_type_vals), 0,
        "Mc_type", HFILL }},
    { &hf_h245_equaliseDelay,
      { "equaliseDelay", "h245.equaliseDelay",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_zeroDelay,
      { "zeroDelay", "h245.zeroDelay",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_multipointModeCommand,
      { "multipointModeCommand", "h245.multipointModeCommand",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_cancelMultipointModeCommand,
      { "cancelMultipointModeCommand", "h245.cancelMultipointModeCommand",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_videoFreezePicture,
      { "videoFreezePicture", "h245.videoFreezePicture",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_videoFastUpdatePicture,
      { "videoFastUpdatePicture", "h245.videoFastUpdatePicture",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_videoFastUpdateGOB,
      { "videoFastUpdateGOB", "h245.videoFastUpdateGOB",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_firstGOB,
      { "firstGOB", "h245.firstGOB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_17", HFILL }},
    { &hf_h245_numberOfGOBs,
      { "numberOfGOBs", "h245.numberOfGOBs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_18", HFILL }},
    { &hf_h245_videoTemporalSpatialTradeOff,
      { "videoTemporalSpatialTradeOff", "h245.videoTemporalSpatialTradeOff",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31", HFILL }},
    { &hf_h245_videoSendSyncEveryGOB,
      { "videoSendSyncEveryGOB", "h245.videoSendSyncEveryGOB",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_videoSendSyncEveryGOBCancel,
      { "videoSendSyncEveryGOBCancel", "h245.videoSendSyncEveryGOBCancel",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_videoFastUpdateMB,
      { "videoFastUpdateMB", "h245.videoFastUpdateMB",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_firstGOB_0_255,
      { "firstGOB", "h245.firstGOB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h245_firstMB_1_8192,
      { "firstMB", "h245.firstMB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_8192", HFILL }},
    { &hf_h245_numberOfMBs,
      { "numberOfMBs", "h245.numberOfMBs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_8192", HFILL }},
    { &hf_h245_maxH223MUXPDUsize,
      { "maxH223MUXPDUsize", "h245.maxH223MUXPDUsize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65535", HFILL }},
    { &hf_h245_encryptionUpdate,
      { "encryptionUpdate", "h245.encryptionUpdate",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptionSync", HFILL }},
    { &hf_h245_encryptionUpdateRequest,
      { "encryptionUpdateRequest", "h245.encryptionUpdateRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_switchReceiveMediaOff,
      { "switchReceiveMediaOff", "h245.switchReceiveMediaOff",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_switchReceiveMediaOn,
      { "switchReceiveMediaOn", "h245.switchReceiveMediaOn",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_progressiveRefinementStart,
      { "progressiveRefinementStart", "h245.progressiveRefinementStart",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_repeatCount,
      { "repeatCount", "h245.repeatCount",
        FT_UINT32, BASE_DEC, VALS(h245_T_repeatCount_vals), 0,
        NULL, HFILL }},
    { &hf_h245_doOneProgression,
      { "doOneProgression", "h245.doOneProgression",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_doContinuousProgressions,
      { "doContinuousProgressions", "h245.doContinuousProgressions",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_doOneIndependentProgression,
      { "doOneIndependentProgression", "h245.doOneIndependentProgression",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_doContinuousIndependentProgressions,
      { "doContinuousIndependentProgressions", "h245.doContinuousIndependentProgressions",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_progressiveRefinementAbortOne,
      { "progressiveRefinementAbortOne", "h245.progressiveRefinementAbortOne",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_progressiveRefinementAbortContinuous,
      { "progressiveRefinementAbortContinuous", "h245.progressiveRefinementAbortContinuous",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_videoBadMBs,
      { "videoBadMBs", "h245.videoBadMBs",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_firstMB,
      { "firstMB", "h245.firstMB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_9216", HFILL }},
    { &hf_h245_numberOfMBs1_1_9216,
      { "numberOfMBs", "h245.numberOfMBs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_9216", HFILL }},
    { &hf_h245_temporalReference,
      { "temporalReference", "h245.temporalReference",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_h245_lostPicture,
      { "lostPicture", "h245.lostPicture",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_PictureReference", HFILL }},
    { &hf_h245_lostPicture_item,
      { "PictureReference", "h245.PictureReference",
        FT_UINT32, BASE_DEC, VALS(h245_PictureReference_vals), 0,
        NULL, HFILL }},
    { &hf_h245_lostPartialPicture,
      { "lostPartialPicture", "h245.lostPartialPicture",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_pictureReference,
      { "pictureReference", "h245.pictureReference",
        FT_UINT32, BASE_DEC, VALS(h245_PictureReference_vals), 0,
        NULL, HFILL }},
    { &hf_h245_recoveryReferencePicture,
      { "recoveryReferencePicture", "h245.recoveryReferencePicture",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_PictureReference", HFILL }},
    { &hf_h245_recoveryReferencePicture_item,
      { "PictureReference", "h245.PictureReference",
        FT_UINT32, BASE_DEC, VALS(h245_PictureReference_vals), 0,
        NULL, HFILL }},
    { &hf_h245_encryptionUpdateCommand,
      { "encryptionUpdateCommand", "h245.encryptionUpdateCommand",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_encryptionUpdateAck,
      { "encryptionUpdateAck", "h245.encryptionUpdateAck",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_direction,
      { "direction", "h245.direction",
        FT_UINT32, BASE_DEC, VALS(h245_EncryptionUpdateDirection_vals), 0,
        "EncryptionUpdateDirection", HFILL }},
    { &hf_h245_secureChannel,
      { "secureChannel", "h245.secureChannel",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_sharedSecret,
      { "sharedSecret", "h245.sharedSecret",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_certProtectedKey,
      { "certProtectedKey", "h245.certProtectedKey",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_keyProtectionMethod,
      { "keyProtectionMethod", "h245.keyProtectionMethod",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_pictureNumber,
      { "pictureNumber", "h245.pictureNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_h245_longTermPictureIndex,
      { "longTermPictureIndex", "h245.longTermPictureIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h245_h223ModeChange,
      { "h223ModeChange", "h245.h223ModeChange",
        FT_UINT32, BASE_DEC, VALS(h245_T_h223ModeChange_vals), 0,
        NULL, HFILL }},
    { &hf_h245_toLevel0,
      { "toLevel0", "h245.toLevel0",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_toLevel1,
      { "toLevel1", "h245.toLevel1",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_toLevel2,
      { "toLevel2", "h245.toLevel2",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_toLevel2withOptionalHeader,
      { "toLevel2withOptionalHeader", "h245.toLevel2withOptionalHeader",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_h223AnnexADoubleFlag,
      { "h223AnnexADoubleFlag", "h245.h223AnnexADoubleFlag",
        FT_UINT32, BASE_DEC, VALS(h245_T_h223AnnexADoubleFlag_vals), 0,
        NULL, HFILL }},
    { &hf_h245_start,
      { "start", "h245.start",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_stop,
      { "stop", "h245.stop",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_bitRate,
      { "bitRate", "h245.bitRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65535", HFILL }},
    { &hf_h245_bitRateLockedToPCRClock,
      { "bitRateLockedToPCRClock", "h245.bitRateLockedToPCRClock",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_bitRateLockedToNetworkClock,
      { "bitRateLockedToNetworkClock", "h245.bitRateLockedToNetworkClock",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h245_cmd_aal,
      { "aal", "h245.aal",
        FT_UINT32, BASE_DEC, VALS(h245_Cmd_aal_vals), 0,
        "Cmd_aal", HFILL }},
    { &hf_h245_cmd_aal1,
      { "aal1", "h245.aal1",
        FT_NONE, BASE_NONE, NULL, 0,
        "Cmd_aal1", HFILL }},
    { &hf_h245_cmd_clockRecovery,
      { "clockRecovery", "h245.clockRecovery",
        FT_UINT32, BASE_DEC, VALS(h245_Cmd_clockRecovery_vals), 0,
        "Cmd_clockRecovery", HFILL }},
    { &hf_h245_nullClockRecoveryflag,
      { "nullClockRecovery", "h245.nullClockRecovery",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_srtsClockRecovery,
      { "srtsClockRecovery", "h245.srtsClockRecovery",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_adaptiveClockRecoveryFlag,
      { "adaptiveClockRecovery", "h245.adaptiveClockRecovery",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_cmd_errorCorrection,
      { "errorCorrection", "h245.errorCorrection",
        FT_UINT32, BASE_DEC, VALS(h245_Cmd_errorCorrection_vals), 0,
        "Cmd_errorCorrection", HFILL }},
    { &hf_h245_nullErrorCorrectionFlag,
      { "nullErrorCorrection", "h245.nullErrorCorrection",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_longInterleaverFlag,
      { "longInterleaver", "h245.longInterleaver",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_shortInterleaverFlag,
      { "shortInterleaver", "h245.shortInterleaver",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_errorCorrectionOnlyFlag,
      { "errorCorrectionOnly", "h245.errorCorrectionOnly",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_cmd_aal5,
      { "aal5", "h245.aal5",
        FT_NONE, BASE_NONE, NULL, 0,
        "Cmd_aal5", HFILL }},
    { &hf_h245_cmd_multiplex,
      { "multiplex", "h245.multiplex",
        FT_UINT32, BASE_DEC, VALS(h245_Cmd_multiplex_vals), 0,
        "Cmd_multiplex", HFILL }},
    { &hf_h245_noMultiplex,
      { "noMultiplex", "h245.noMultiplex",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_transportStream,
      { "transportStream", "h245.transportStream",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_programStreamFlag,
      { "programStream", "h245.programStream",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_cmd_reverseParameters,
      { "reverseParameters", "h245.reverseParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "Cmd_reverseParameters", HFILL }},
    { &hf_h245_cmdr_multiplex,
      { "multiplex", "h245.multiplex",
        FT_UINT32, BASE_DEC, VALS(h245_CmdR_multiplex_vals), 0,
        "CmdR_multiplex", HFILL }},
    { &hf_h245_sampleSize,
      { "sampleSize", "h245.sampleSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_255", HFILL }},
    { &hf_h245_samplesPerFrame,
      { "samplesPerFrame", "h245.samplesPerFrame",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_255", HFILL }},
    { &hf_h245_status,
      { "status", "h245.status",
        FT_UINT32, BASE_DEC, VALS(h245_T_status_vals), 0,
        NULL, HFILL }},
    { &hf_h245_synchronized,
      { "synchronized", "h245.synchronized",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_reconfiguration,
      { "reconfiguration", "h245.reconfiguration",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_fns_cause,
      { "cause", "h245.cause",
        FT_UINT32, BASE_DEC, VALS(h245_FunctionNotSupportedCause_vals), 0,
        "FunctionNotSupportedCause", HFILL }},
    { &hf_h245_syntaxError,
      { "syntaxError", "h245.syntaxError",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_semanticError,
      { "semanticError", "h245.semanticError",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_unknownFunction,
      { "unknownFunction", "h245.unknownFunction",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_returnedFunction,
      { "returnedFunction", "h245.returnedFunction",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_sbeNumber,
      { "sbeNumber", "h245.sbeNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_9", HFILL }},
    { &hf_h245_terminalNumberAssign,
      { "terminalNumberAssign", "h245.terminalNumberAssign",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminalLabel", HFILL }},
    { &hf_h245_terminalJoinedConference,
      { "terminalJoinedConference", "h245.terminalJoinedConference",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminalLabel", HFILL }},
    { &hf_h245_terminalLeftConference,
      { "terminalLeftConference", "h245.terminalLeftConference",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminalLabel", HFILL }},
    { &hf_h245_seenByAtLeastOneOther,
      { "seenByAtLeastOneOther", "h245.seenByAtLeastOneOther",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_cancelSeenByAtLeastOneOther,
      { "cancelSeenByAtLeastOneOther", "h245.cancelSeenByAtLeastOneOther",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_seenByAll,
      { "seenByAll", "h245.seenByAll",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_cancelSeenByAll,
      { "cancelSeenByAll", "h245.cancelSeenByAll",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_terminalYouAreSeeing,
      { "terminalYouAreSeeing", "h245.terminalYouAreSeeing",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminalLabel", HFILL }},
    { &hf_h245_requestForFloor,
      { "requestForFloor", "h245.requestForFloor",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_withdrawChairToken,
      { "withdrawChairToken", "h245.withdrawChairToken",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_floorRequested,
      { "floorRequested", "h245.floorRequested",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminalLabel", HFILL }},
    { &hf_h245_terminalYouAreSeeingInSubPictureNumber,
      { "terminalYouAreSeeingInSubPictureNumber", "h245.terminalYouAreSeeingInSubPictureNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_videoIndicateCompose,
      { "videoIndicateCompose", "h245.videoIndicateCompose",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_masterMCU,
      { "masterMCU", "h245.masterMCU",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_cancelMasterMCU,
      { "cancelMasterMCU", "h245.cancelMasterMCU",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_subPictureNumber,
      { "subPictureNumber", "h245.subPictureNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h245_compositionNumber,
      { "compositionNumber", "h245.compositionNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h245_mi_type,
      { "type", "h245.type",
        FT_UINT32, BASE_DEC, VALS(h245_Mi_type_vals), 0,
        "Mi_type", HFILL }},
    { &hf_h245_logicalChannelActive,
      { "logicalChannelActive", "h245.logicalChannelActive",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_logicalChannelInactive,
      { "logicalChannelInactive", "h245.logicalChannelInactive",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_multipointConference,
      { "multipointConference", "h245.multipointConference",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_cancelMultipointConference,
      { "cancelMultipointConference", "h245.cancelMultipointConference",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_multipointZeroComm,
      { "multipointZeroComm", "h245.multipointZeroComm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_cancelMultipointZeroComm,
      { "cancelMultipointZeroComm", "h245.cancelMultipointZeroComm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_multipointSecondaryStatus,
      { "multipointSecondaryStatus", "h245.multipointSecondaryStatus",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_cancelMultipointSecondaryStatus,
      { "cancelMultipointSecondaryStatus", "h245.cancelMultipointSecondaryStatus",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_videoIndicateReadyToActivate,
      { "videoIndicateReadyToActivate", "h245.videoIndicateReadyToActivate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_videoNotDecodedMBs,
      { "videoNotDecodedMBs", "h245.videoNotDecodedMBs",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_temporalReference_0_255,
      { "temporalReference", "h245.temporalReference",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h245_estimatedReceivedJitterMantissa,
      { "estimatedReceivedJitterMantissa", "h245.estimatedReceivedJitterMantissa",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_h245_estimatedReceivedJitterExponent,
      { "estimatedReceivedJitterExponent", "h245.estimatedReceivedJitterExponent",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_h245_skippedFrameCount,
      { "skippedFrameCount", "h245.skippedFrameCount",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_h245_additionalDecoderBuffer,
      { "additionalDecoderBuffer", "h245.additionalDecoderBuffer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_262143", HFILL }},
    { &hf_h245_logicalChannelNumber1,
      { "logicalChannelNumber1", "h245.logicalChannelNumber1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LogicalChannelNumber", HFILL }},
    { &hf_h245_logicalChannelNumber2,
      { "logicalChannelNumber2", "h245.logicalChannelNumber2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LogicalChannelNumber", HFILL }},
    { &hf_h245_skew,
      { "skew", "h245.skew",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4095", HFILL }},
    { &hf_h245_maximumSkew,
      { "maximumSkew", "h245.maximumSkew",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4095", HFILL }},
    { &hf_h245_signalAddress,
      { "signalAddress", "h245.signalAddress",
        FT_UINT32, BASE_DEC, VALS(h245_TransportAddress_vals), 0,
        "TransportAddress", HFILL }},
    { &hf_h245_vendor,
      { "vendor", "h245.vendor",
        FT_UINT32, BASE_DEC, VALS(h245_NonStandardIdentifier_vals), 0,
        "NonStandardIdentifier", HFILL }},
    { &hf_h245_productNumber,
      { "productNumber", "h245.productNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_256", HFILL }},
    { &hf_h245_versionNumber,
      { "versionNumber", "h245.versionNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_256", HFILL }},
    { &hf_h245_ind_aal,
      { "aal", "h245.aal",
        FT_UINT32, BASE_DEC, VALS(h245_Ind_aal_vals), 0,
        "Ind_aal", HFILL }},
    { &hf_h245_ind_aal1,
      { "aal1", "h245.aal1",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ind_aal1", HFILL }},
    { &hf_h245_ind_clockRecovery,
      { "clockRecovery", "h245.clockRecovery",
        FT_UINT32, BASE_DEC, VALS(h245_Ind_clockRecovery_vals), 0,
        "Ind_clockRecovery", HFILL }},
    { &hf_h245_ind_errorCorrection,
      { "errorCorrection", "h245.errorCorrection",
        FT_UINT32, BASE_DEC, VALS(h245_Ind_errorCorrection_vals), 0,
        "Ind_errorCorrection", HFILL }},
    { &hf_h245_ind_aal5,
      { "aal5", "h245.aal5",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ind_aal5", HFILL }},
    { &hf_h245_ind_multiplex,
      { "multiplex", "h245.multiplex",
        FT_UINT32, BASE_DEC, VALS(h245_Ind_multiplex_vals), 0,
        "Ind_multiplex", HFILL }},
    { &hf_h245_ind_reverseParameters,
      { "reverseParameters", "h245.reverseParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ind_reverseParameters", HFILL }},
    { &hf_h245_indr_multiplex,
      { "multiplex", "h245.multiplex",
        FT_UINT32, BASE_DEC, VALS(h245_IndR_multiplex_vals), 0,
        "IndR_multiplex", HFILL }},
    { &hf_h245_iv8,
      { "iv8", "h245.iv8",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_iv16,
      { "iv16", "h245.iv16",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_iv,
      { "iv", "h245.iv",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_h245_alphanumeric,
      { "alphanumeric", "h245.alphanumeric",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralString", HFILL }},
    { &hf_h245_userInputSupportIndication,
      { "userInputSupportIndication", "h245.userInputSupportIndication",
        FT_UINT32, BASE_DEC, VALS(h245_T_userInputSupportIndication_vals), 0,
        NULL, HFILL }},
    { &hf_h245_signal,
      { "signal", "h245.signal",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_signalType,
      { "signalType", "h245.signalType",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_duration,
      { "duration", "h245.duration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65535", HFILL }},
    { &hf_h245_rtp,
      { "rtp", "h245.rtp",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_timestamp,
      { "timestamp", "h245.timestamp",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_h245_expirationTime,
      { "expirationTime", "h245.expirationTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_h245_rtpPayloadIndication,
      { "rtpPayloadIndication", "h245.rtpPayloadIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_paramS,
      { "paramS", "h245.paramS",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_encryptedSignalType,
      { "encryptedSignalType", "h245.encryptedSignalType",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_h245_algorithmOID,
      { "algorithmOID", "h245.algorithmOID",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_h245_signalUpdate,
      { "signalUpdate", "h245.signalUpdate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_si_rtp,
      { "rtp", "h245.rtp",
        FT_NONE, BASE_NONE, NULL, 0,
        "Si_rtp", HFILL }},
    { &hf_h245_extendedAlphanumeric,
      { "extendedAlphanumeric", "h245.extendedAlphanumeric",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h245_encrypted,
      { "encrypted", "h245.encrypted",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_h245_encryptedAlphanumeric,
      { "encryptedAlphanumeric", "h245.encryptedAlphanumeric",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/*--- End of included file: packet-h245-hfarr.c ---*/
#line 493 "../../asn1/h245/packet-h245-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_h245,
	  &ett_h245_returnedFunction,

/*--- Included file: packet-h245-ettarr.c ---*/
#line 1 "../../asn1/h245/packet-h245-ettarr.c"
    &ett_h245_MultimediaSystemControlMessage,
    &ett_h245_RequestMessage,
    &ett_h245_ResponseMessage,
    &ett_h245_CommandMessage,
    &ett_h245_IndicationMessage,
    &ett_h245_GenericMessage,
    &ett_h245_T_messageContent,
    &ett_h245_NonStandardMessage,
    &ett_h245_NonStandardParameter,
    &ett_h245_NonStandardIdentifier,
    &ett_h245_H221NonStandardID,
    &ett_h245_MasterSlaveDetermination,
    &ett_h245_MasterSlaveDeterminationAck,
    &ett_h245_T_decision,
    &ett_h245_MasterSlaveDeterminationReject,
    &ett_h245_MasterSlaveDeterminationRejectCause,
    &ett_h245_MasterSlaveDeterminationRelease,
    &ett_h245_TerminalCapabilitySet,
    &ett_h245_SET_SIZE_1_256_OF_CapabilityTableEntry,
    &ett_h245_SET_SIZE_1_256_OF_CapabilityDescriptor,
    &ett_h245_SEQUENCE_OF_GenericInformation,
    &ett_h245_CapabilityTableEntry,
    &ett_h245_CapabilityDescriptor,
    &ett_h245_SET_SIZE_1_256_OF_AlternativeCapabilitySet,
    &ett_h245_AlternativeCapabilitySet,
    &ett_h245_TerminalCapabilitySetAck,
    &ett_h245_TerminalCapabilitySetReject,
    &ett_h245_TerminalCapabilitySetRejectCause,
    &ett_h245_T_tableEntryCapacityExceeded,
    &ett_h245_TerminalCapabilitySetRelease,
    &ett_h245_Capability,
    &ett_h245_T_h233EncryptionReceiveCapability,
    &ett_h245_H235SecurityCapability,
    &ett_h245_MultiplexCapability,
    &ett_h245_H222Capability,
    &ett_h245_SET_OF_VCCapability,
    &ett_h245_VCCapability,
    &ett_h245_T_aal1,
    &ett_h245_T_aal5,
    &ett_h245_T_availableBitRates,
    &ett_h245_Avb_type,
    &ett_h245_T_rangeOfBitRates,
    &ett_h245_T_aal1ViaGateway,
    &ett_h245_SET_SIZE_1_256_OF_Q2931Address,
    &ett_h245_H223Capability,
    &ett_h245_T_h223MultiplexTableCapability,
    &ett_h245_T_enhanced,
    &ett_h245_T_mobileOperationTransmitCapability,
    &ett_h245_T_mobileMultilinkFrameCapability,
    &ett_h245_H223AnnexCCapability,
    &ett_h245_V76Capability,
    &ett_h245_V75Capability,
    &ett_h245_H2250Capability,
    &ett_h245_T_mcCapability,
    &ett_h245_SEQUENCE_SIZE_1_256_OF_RedundancyEncodingCapability,
    &ett_h245_MediaPacketizationCapability,
    &ett_h245_SEQUENCE_SIZE_1_256_OF_RTPPayloadType,
    &ett_h245_RSVPParameters,
    &ett_h245_QOSMode,
    &ett_h245_ATMParameters,
    &ett_h245_ServicePriorityValue,
    &ett_h245_ServicePriority,
    &ett_h245_AuthorizationParameters,
    &ett_h245_QOSType,
    &ett_h245_QOSClass,
    &ett_h245_QOSDescriptor,
    &ett_h245_GenericTransportParameters,
    &ett_h245_QOSCapability,
    &ett_h245_MediaTransportType,
    &ett_h245_T_atm_AAL5_compressed,
    &ett_h245_MediaChannelCapability,
    &ett_h245_TransportCapability,
    &ett_h245_SEQUENCE_SIZE_1_256_OF_QOSCapability,
    &ett_h245_SEQUENCE_SIZE_1_256_OF_MediaChannelCapability,
    &ett_h245_RedundancyEncodingCapability,
    &ett_h245_SEQUENCE_SIZE_1_256_OF_CapabilityTableEntryNumber,
    &ett_h245_RedundancyEncodingMethod,
    &ett_h245_RTPH263VideoRedundancyEncoding,
    &ett_h245_T_frameToThreadMapping,
    &ett_h245_SEQUENCE_SIZE_1_256_OF_RTPH263VideoRedundancyFrameMapping,
    &ett_h245_T_containedThreads,
    &ett_h245_RTPH263VideoRedundancyFrameMapping,
    &ett_h245_T_frameSequence,
    &ett_h245_MultipointCapability,
    &ett_h245_SEQUENCE_OF_MediaDistributionCapability,
    &ett_h245_MediaDistributionCapability,
    &ett_h245_SEQUENCE_OF_DataApplicationCapability,
    &ett_h245_VideoCapability,
    &ett_h245_ExtendedVideoCapability,
    &ett_h245_SEQUENCE_OF_VideoCapability,
    &ett_h245_SEQUENCE_OF_GenericCapability,
    &ett_h245_H261VideoCapability,
    &ett_h245_H262VideoCapability,
    &ett_h245_H263VideoCapability,
    &ett_h245_EnhancementLayerInfo,
    &ett_h245_SET_SIZE_1_14_OF_EnhancementOptions,
    &ett_h245_SET_SIZE_1_14_OF_BEnhancementParameters,
    &ett_h245_BEnhancementParameters,
    &ett_h245_EnhancementOptions,
    &ett_h245_H263Options,
    &ett_h245_SET_SIZE_1_16_OF_CustomPictureClockFrequency,
    &ett_h245_SET_SIZE_1_16_OF_CustomPictureFormat,
    &ett_h245_SET_SIZE_1_16_OF_H263VideoModeCombos,
    &ett_h245_TransparencyParameters,
    &ett_h245_RefPictureSelection,
    &ett_h245_T_additionalPictureMemory,
    &ett_h245_T_videoBackChannelSend,
    &ett_h245_T_enhancedReferencePicSelect,
    &ett_h245_T_subPictureRemovalParameters,
    &ett_h245_CustomPictureClockFrequency,
    &ett_h245_CustomPictureFormat,
    &ett_h245_T_mPI,
    &ett_h245_T_customPCF,
    &ett_h245_T_customPCF_item,
    &ett_h245_T_pixelAspectInformation,
    &ett_h245_T_pixelAspectCode,
    &ett_h245_T_extendedPAR,
    &ett_h245_T_extendedPAR_item,
    &ett_h245_H263VideoModeCombos,
    &ett_h245_SET_SIZE_1_16_OF_H263ModeComboFlags,
    &ett_h245_H263ModeComboFlags,
    &ett_h245_H263Version3Options,
    &ett_h245_IS11172VideoCapability,
    &ett_h245_AudioCapability,
    &ett_h245_T_g7231,
    &ett_h245_G729Extensions,
    &ett_h245_G7231AnnexCCapability,
    &ett_h245_G723AnnexCAudioMode,
    &ett_h245_IS11172AudioCapability,
    &ett_h245_IS13818AudioCapability,
    &ett_h245_GSMAudioCapability,
    &ett_h245_VBDCapability,
    &ett_h245_DataApplicationCapability,
    &ett_h245_Application,
    &ett_h245_T_t84,
    &ett_h245_Nlpid,
    &ett_h245_T_t38fax,
    &ett_h245_DataProtocolCapability,
    &ett_h245_T_v76wCompression,
    &ett_h245_CompressionType,
    &ett_h245_V42bis,
    &ett_h245_T84Profile,
    &ett_h245_T_t84Restricted,
    &ett_h245_T38FaxProfile,
    &ett_h245_T38FaxRateManagement,
    &ett_h245_T38FaxUdpOptions,
    &ett_h245_T_t38FaxUdpEC,
    &ett_h245_T38FaxTcpOptions,
    &ett_h245_EncryptionAuthenticationAndIntegrity,
    &ett_h245_EncryptionCapability,
    &ett_h245_MediaEncryptionAlgorithm,
    &ett_h245_AuthenticationCapability,
    &ett_h245_IntegrityCapability,
    &ett_h245_UserInputCapability,
    &ett_h245_SEQUENCE_SIZE_1_16_OF_NonStandardParameter,
    &ett_h245_ConferenceCapability,
    &ett_h245_SEQUENCE_OF_NonStandardParameter,
    &ett_h245_GenericCapability,
    &ett_h245_T_collapsing,
    &ett_h245_T_nonCollapsing,
    &ett_h245_CapabilityIdentifier,
    &ett_h245_GenericParameter,
    &ett_h245_SEQUENCE_OF_ParameterIdentifier,
    &ett_h245_ParameterIdentifier,
    &ett_h245_ParameterValue,
    &ett_h245_SEQUENCE_OF_GenericParameter,
    &ett_h245_MultiplexedStreamCapability,
    &ett_h245_MultiplexFormat,
    &ett_h245_AudioTelephonyEventCapability,
    &ett_h245_AudioToneCapability,
    &ett_h245_NoPTAudioTelephonyEventCapability,
    &ett_h245_NoPTAudioToneCapability,
    &ett_h245_MultiplePayloadStreamCapability,
    &ett_h245_DepFECCapability,
    &ett_h245_FECC_rfc2733,
    &ett_h245_T_separateStreamBool,
    &ett_h245_FECCapability,
    &ett_h245_Rfc2733Format,
    &ett_h245_OpenLogicalChannel,
    &ett_h245_T_forwardLogicalChannelParameters,
    &ett_h245_OLC_forw_multiplexParameters,
    &ett_h245_OLC_reverseLogicalChannelParameters,
    &ett_h245_OLC_rev_multiplexParameters,
    &ett_h245_NetworkAccessParameters,
    &ett_h245_T_distribution,
    &ett_h245_T_networkAddress,
    &ett_h245_T_t120SetupProcedure,
    &ett_h245_Q2931Address,
    &ett_h245_T_address,
    &ett_h245_V75Parameters,
    &ett_h245_DataType,
    &ett_h245_H235Media,
    &ett_h245_T_mediaType,
    &ett_h245_MultiplexedStreamParameter,
    &ett_h245_H222LogicalChannelParameters,
    &ett_h245_H223LogicalChannelParameters,
    &ett_h245_T_adaptationLayerType,
    &ett_h245_Al3,
    &ett_h245_H223AL1MParameters,
    &ett_h245_T_transferMode,
    &ett_h245_AL1HeaderFEC,
    &ett_h245_AL1CrcLength,
    &ett_h245_ArqType,
    &ett_h245_H223AL2MParameters,
    &ett_h245_AL2HeaderFEC,
    &ett_h245_H223AL3MParameters,
    &ett_h245_T_headerFormat,
    &ett_h245_AL3CrcLength,
    &ett_h245_H223AnnexCArqParameters,
    &ett_h245_T_numberOfRetransmissions,
    &ett_h245_V76LogicalChannelParameters,
    &ett_h245_T_suspendResume,
    &ett_h245_V76LCP_mode,
    &ett_h245_T_eRM,
    &ett_h245_T_recovery,
    &ett_h245_V76HDLCParameters,
    &ett_h245_CRCLength,
    &ett_h245_H2250LogicalChannelParameters,
    &ett_h245_T_mediaPacketization,
    &ett_h245_RTPPayloadType,
    &ett_h245_T_payloadDescriptor,
    &ett_h245_RedundancyEncoding,
    &ett_h245_T_rtpRedundancyEncoding,
    &ett_h245_SEQUENCE_OF_RedundancyEncodingElement,
    &ett_h245_RedundancyEncodingElement,
    &ett_h245_MultiplePayloadStream,
    &ett_h245_SEQUENCE_OF_MultiplePayloadStreamElement,
    &ett_h245_MultiplePayloadStreamElement,
    &ett_h245_DepFECData,
    &ett_h245_RFC2733Data,
    &ett_h245_FECdata_mode,
    &ett_h245_DepSeparateStream,
    &ett_h245_T_differentPort,
    &ett_h245_T_samePort,
    &ett_h245_FECData,
    &ett_h245_T_rfc2733,
    &ett_h245_T_pktMode,
    &ett_h245_T_mode_rfc2733sameport,
    &ett_h245_T_mode_rfc2733diffport,
    &ett_h245_TransportAddress,
    &ett_h245_UnicastAddress,
    &ett_h245_T_iPAddress,
    &ett_h245_T_iPXAddress,
    &ett_h245_T_iP6Address,
    &ett_h245_T_iPSourceRouteAddress,
    &ett_h245_T_routing,
    &ett_h245_T_route,
    &ett_h245_MulticastAddress,
    &ett_h245_MIPAddress,
    &ett_h245_MIP6Address,
    &ett_h245_EncryptionSync,
    &ett_h245_SEQUENCE_SIZE_1_256_OF_EscrowData,
    &ett_h245_EscrowData,
    &ett_h245_OpenLogicalChannelAck,
    &ett_h245_OLC_ack_reverseLogicalChannelParameters,
    &ett_h245_T_olc_ack_multiplexParameters,
    &ett_h245_T_forwardMultiplexAckParameters,
    &ett_h245_OpenLogicalChannelReject,
    &ett_h245_OpenLogicalChannelRejectCause,
    &ett_h245_OpenLogicalChannelConfirm,
    &ett_h245_H2250LogicalChannelAckParameters,
    &ett_h245_CloseLogicalChannel,
    &ett_h245_T_cLC_source,
    &ett_h245_Clc_reason,
    &ett_h245_CloseLogicalChannelAck,
    &ett_h245_RequestChannelClose,
    &ett_h245_T_reason,
    &ett_h245_RequestChannelCloseAck,
    &ett_h245_RequestChannelCloseReject,
    &ett_h245_RequestChannelCloseRejectCause,
    &ett_h245_RequestChannelCloseRelease,
    &ett_h245_MultiplexEntrySend,
    &ett_h245_SET_SIZE_1_15_OF_MultiplexEntryDescriptor,
    &ett_h245_MultiplexEntryDescriptor,
    &ett_h245_T_elementList,
    &ett_h245_MultiplexElement,
    &ett_h245_Me_type,
    &ett_h245_T_subElementList,
    &ett_h245_ME_repeatCount,
    &ett_h245_MultiplexEntrySendAck,
    &ett_h245_SET_SIZE_1_15_OF_MultiplexTableEntryNumber,
    &ett_h245_MultiplexEntrySendReject,
    &ett_h245_SET_SIZE_1_15_OF_MultiplexEntryRejectionDescriptions,
    &ett_h245_MultiplexEntryRejectionDescriptions,
    &ett_h245_MultiplexEntryRejectionDescriptionsCause,
    &ett_h245_MultiplexEntrySendRelease,
    &ett_h245_RequestMultiplexEntry,
    &ett_h245_RequestMultiplexEntryAck,
    &ett_h245_RequestMultiplexEntryReject,
    &ett_h245_SET_SIZE_1_15_OF_RequestMultiplexEntryRejectionDescriptions,
    &ett_h245_RequestMultiplexEntryRejectionDescriptions,
    &ett_h245_RequestMultiplexEntryRejectionDescriptionsCause,
    &ett_h245_RequestMultiplexEntryRelease,
    &ett_h245_RequestMode,
    &ett_h245_SEQUENCE_SIZE_1_256_OF_ModeDescription,
    &ett_h245_RequestModeAck,
    &ett_h245_Req_mode_ack_response,
    &ett_h245_RequestModeReject,
    &ett_h245_RequestModeRejectCause,
    &ett_h245_RequestModeRelease,
    &ett_h245_ModeDescription,
    &ett_h245_ModeElementType,
    &ett_h245_ModeElement,
    &ett_h245_H235Mode,
    &ett_h245_T_mediaMode,
    &ett_h245_MultiplexedStreamModeParameters,
    &ett_h245_RedundancyEncodingDTMode,
    &ett_h245_SEQUENCE_OF_RedundancyEncodingDTModeElement,
    &ett_h245_RedundancyEncodingDTModeElement,
    &ett_h245_Re_type,
    &ett_h245_MultiplePayloadStreamMode,
    &ett_h245_SEQUENCE_OF_MultiplePayloadStreamElementMode,
    &ett_h245_MultiplePayloadStreamElementMode,
    &ett_h245_DepFECMode,
    &ett_h245_T_rfc2733Mode,
    &ett_h245_FEC_mode,
    &ett_h245_FECMode,
    &ett_h245_H223ModeParameters,
    &ett_h245_AdaptationLayerType,
    &ett_h245_V76ModeParameters,
    &ett_h245_H2250ModeParameters,
    &ett_h245_RedundancyEncodingMode,
    &ett_h245_T_secondaryEncodingMode,
    &ett_h245_VideoMode,
    &ett_h245_H261VideoMode,
    &ett_h245_H261Resolution,
    &ett_h245_H262VideoMode,
    &ett_h245_T_profileAndLevel,
    &ett_h245_H263VideoMode,
    &ett_h245_H263Resolution,
    &ett_h245_IS11172VideoMode,
    &ett_h245_AudioMode,
    &ett_h245_Mode_g7231,
    &ett_h245_IS11172AudioMode,
    &ett_h245_T_audioLayer,
    &ett_h245_T_audioSampling,
    &ett_h245_IS11172_multichannelType,
    &ett_h245_IS13818AudioMode,
    &ett_h245_IS13818AudioLayer,
    &ett_h245_IS13818AudioSampling,
    &ett_h245_IS13818MultichannelType,
    &ett_h245_G7231AnnexCMode,
    &ett_h245_VBDMode,
    &ett_h245_DataMode,
    &ett_h245_DataModeApplication,
    &ett_h245_T38faxApp,
    &ett_h245_EncryptionMode,
    &ett_h245_RoundTripDelayRequest,
    &ett_h245_RoundTripDelayResponse,
    &ett_h245_MaintenanceLoopRequest,
    &ett_h245_Mlr_type,
    &ett_h245_MaintenanceLoopAck,
    &ett_h245_Mla_type,
    &ett_h245_MaintenanceLoopReject,
    &ett_h245_Mlrej_type,
    &ett_h245_MaintenanceLoopRejectCause,
    &ett_h245_MaintenanceLoopOffCommand,
    &ett_h245_CommunicationModeCommand,
    &ett_h245_SET_SIZE_1_256_OF_CommunicationModeTableEntry,
    &ett_h245_CommunicationModeRequest,
    &ett_h245_CommunicationModeResponse,
    &ett_h245_CommunicationModeTableEntry,
    &ett_h245_T_entryDataType,
    &ett_h245_ConferenceRequest,
    &ett_h245_T_requestTerminalCertificate,
    &ett_h245_CertSelectionCriteria,
    &ett_h245_Criteria,
    &ett_h245_TerminalLabel,
    &ett_h245_ConferenceResponse,
    &ett_h245_T_mCTerminalIDResponse,
    &ett_h245_T_terminalIDResponse,
    &ett_h245_T_conferenceIDResponse,
    &ett_h245_T_passwordResponse,
    &ett_h245_SET_SIZE_1_256_OF_TerminalLabel,
    &ett_h245_T_makeMeChairResponse,
    &ett_h245_T_extensionAddressResponse,
    &ett_h245_T_chairTokenOwnerResponse,
    &ett_h245_T_terminalCertificateResponse,
    &ett_h245_T_broadcastMyLogicalChannelResponse,
    &ett_h245_T_makeTerminalBroadcasterResponse,
    &ett_h245_T_sendThisSourceResponse,
    &ett_h245_RequestAllTerminalIDsResponse,
    &ett_h245_SEQUENCE_OF_TerminalInformation,
    &ett_h245_TerminalInformation,
    &ett_h245_RemoteMCRequest,
    &ett_h245_RemoteMCResponse,
    &ett_h245_T_reject,
    &ett_h245_MultilinkRequest,
    &ett_h245_CallInformationReq,
    &ett_h245_AddConnectionReq,
    &ett_h245_RemoveConnectionReq,
    &ett_h245_MaximumHeaderIntervalReq,
    &ett_h245_T_requestType,
    &ett_h245_MultilinkResponse,
    &ett_h245_CallInformationResp,
    &ett_h245_AddConnectionResp,
    &ett_h245_T_responseCode,
    &ett_h245_T_rejected,
    &ett_h245_RemoveConnectionResp,
    &ett_h245_MaximumHeaderIntervalResp,
    &ett_h245_MultilinkIndication,
    &ett_h245_T_crcDesired,
    &ett_h245_T_excessiveError,
    &ett_h245_DialingInformation,
    &ett_h245_SET_SIZE_1_65535_OF_DialingInformationNumber,
    &ett_h245_DialingInformationNumber,
    &ett_h245_SET_SIZE_1_255_OF_DialingInformationNetworkType,
    &ett_h245_DialingInformationNetworkType,
    &ett_h245_ConnectionIdentifier,
    &ett_h245_LogicalChannelRateRequest,
    &ett_h245_LogicalChannelRateAcknowledge,
    &ett_h245_LogicalChannelRateReject,
    &ett_h245_LogicalChannelRateRejectReason,
    &ett_h245_LogicalChannelRateRelease,
    &ett_h245_SendTerminalCapabilitySet,
    &ett_h245_T_specificRequest,
    &ett_h245_SET_SIZE_1_65535_OF_CapabilityTableEntryNumber,
    &ett_h245_SET_SIZE_1_256_OF_CapabilityDescriptorNumber,
    &ett_h245_EncryptionCommand,
    &ett_h245_T_encryptionAlgorithmID,
    &ett_h245_FlowControlCommand,
    &ett_h245_Scope,
    &ett_h245_Restriction,
    &ett_h245_EndSessionCommand,
    &ett_h245_T_gstnOptions,
    &ett_h245_T_isdnOptions,
    &ett_h245_ConferenceCommand,
    &ett_h245_SubstituteConferenceIDCommand,
    &ett_h245_EncryptionUpdateDirection,
    &ett_h245_MiscellaneousCommand,
    &ett_h245_Mc_type,
    &ett_h245_T_videoFastUpdateGOB,
    &ett_h245_T_videoFastUpdateMB,
    &ett_h245_T_progressiveRefinementStart,
    &ett_h245_T_repeatCount,
    &ett_h245_T_videoBadMBs,
    &ett_h245_SEQUENCE_OF_PictureReference,
    &ett_h245_T_lostPartialPicture,
    &ett_h245_T_encryptionUpdateCommand,
    &ett_h245_T_encryptionUpdateAck,
    &ett_h245_KeyProtectionMethod,
    &ett_h245_EncryptionUpdateRequest,
    &ett_h245_PictureReference,
    &ett_h245_H223MultiplexReconfiguration,
    &ett_h245_T_h223ModeChange,
    &ett_h245_T_h223AnnexADoubleFlag,
    &ett_h245_NewATMVCCommand,
    &ett_h245_Cmd_aal,
    &ett_h245_Cmd_aal1,
    &ett_h245_Cmd_clockRecovery,
    &ett_h245_Cmd_errorCorrection,
    &ett_h245_Cmd_aal5,
    &ett_h245_Cmd_multiplex,
    &ett_h245_Cmd_reverseParameters,
    &ett_h245_CmdR_multiplex,
    &ett_h245_MobileMultilinkReconfigurationCommand,
    &ett_h245_T_status,
    &ett_h245_FunctionNotUnderstood,
    &ett_h245_FunctionNotSupported,
    &ett_h245_FunctionNotSupportedCause,
    &ett_h245_ConferenceIndication,
    &ett_h245_TerminalYouAreSeeingInSubPictureNumber,
    &ett_h245_VideoIndicateCompose,
    &ett_h245_MiscellaneousIndication,
    &ett_h245_Mi_type,
    &ett_h245_T_videoNotDecodedMBs,
    &ett_h245_JitterIndication,
    &ett_h245_H223SkewIndication,
    &ett_h245_H2250MaximumSkewIndication,
    &ett_h245_MCLocationIndication,
    &ett_h245_VendorIdentification,
    &ett_h245_NewATMVCIndication,
    &ett_h245_Ind_aal,
    &ett_h245_Ind_aal1,
    &ett_h245_Ind_clockRecovery,
    &ett_h245_Ind_errorCorrection,
    &ett_h245_Ind_aal5,
    &ett_h245_Ind_multiplex,
    &ett_h245_Ind_reverseParameters,
    &ett_h245_IndR_multiplex,
    &ett_h245_Params,
    &ett_h245_UserInputIndication,
    &ett_h245_T_userInputSupportIndication,
    &ett_h245_T_signal,
    &ett_h245_T_rtp,
    &ett_h245_T_signalUpdate,
    &ett_h245_Si_rtp,
    &ett_h245_T_extendedAlphanumeric,
    &ett_h245_EncryptedAlphanumeric,
    &ett_h245_FlowControlIndication,
    &ett_h245_MobileMultilinkReconfigurationIndication,

/*--- End of included file: packet-h245-ettarr.c ---*/
#line 500 "../../asn1/h245/packet-h245-template.c"
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

