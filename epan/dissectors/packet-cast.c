/* packet-cast.c
 *
 * Dissector for the CAST Client Control Protocol
 *   (The "D-Channel"-Protocol for Cisco Systems' IP-Phones)
 *
 * $Id$
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

/* This implementation is based on a draft version of the 3.0
 * specification
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/emem.h>

#include "packet-tcp.h"

#define TCP_PORT_CAST 4224


/* I will probably need this again when I change things
 * to function pointers, but let me use the existing
 * infrastructure for now
 *
 * typedef struct {
 *   guint32	id;
 *   char *	name;
 * } message_id_t;
 */

static const value_string  message_id[] = {

  {0x0000, "KeepAliveMessage"},
  {0x0001, "KeepAliveVersionMessage"},
  {0x0002, "KeepAliveVersionACKMessage"},
  {0x0003, "UpdateCapabilitiesMessage"},
  {0x0004, "EmptyCapabilitiesMessage"},
  {0x0005, "OpenMultiMediaReceiveChannelMessage"},
  {0x0006, "OpenMultiMediaReceiveChannelACKMessage"},
  {0x0007, "CloseMultiMediaReceiveChannelMessage"},
  {0x0008, "StartMultiMediaTransmissionMessage"},
  {0x0009, "StopMultiMediaTransmissionMessage"},
  {0x000A, "MiscellaneousCommandMessage"},
  {0x000B, "FlowControlCommandMessage"},
  {0x000C, "ClearConferenceMessage"},
  {0x000D, "CallStateMessage"},
  {0x000E, "RequestCallStateMessage"},
  {0x000F, "RequestAllCallStatesMessage"},
  {0x0010, "CallInfoMessage"},
  {0x0011, "RequestCallInfoMessage"},
  {0x0012, "CallFocusMessage"},
  {0x0013, "MakeCallMessage"},
  {0x0014, "HangUpMessage"},
  {0x0015, "AnswerMessage"},

  {0x0040, "KeepAliveACKMessage"},
  {0x0041, "StreamStartMessage"},
  {0x0042, "StreamStopMessage"},
  {0x0043, "MuteStartMessage"},
  {0x0044, "MuteStopMessage"},
  {0x0045, "SpeakerStartMessage"},
  {0x0046, "SpeakerStopMessage"},
  {0x0047, "StreamStartMessageWithCodec"},

  {0x0050, "VIEODiscoveryprotocol"},
  {0x0051, "VIEOControlprotocol"},

  {0x0060, "T120protocol"},
  {0x0061, "T121protocol"},
  {0x0062, "T122protocol"},

  {0x0070, "IMSessionDiscoveryprotocol"},
  {0x0071, "IMSessionControlprotocol"},

  {0x0074, "SlidesDiscoveryprotocol"},
  {0x0075, "SlidesControlprotocol"},

  {0x0080, "CastTunnelMessage"},

  {0x0090, "RemoteRequestMessage"},
  {0x0091, "RemoteResponseMessage"},

  {0x00A0, "CollabDiscoveryprotocol"},
  {0x00A1, "CollabControlprotocol"},

  {0x00A4, "FECCDiscoveryprotocol"},
  {0x00A5, "FECCControlprotocol"},

  {0x00B0, "ClockSyncprotocol"},
  {0x00B1, "StreamSyncprotocol"},

  {0x00B4, "MediaDiscoveryprotocol"},
  {0x00B5, "MediaControlprotocol"},

  {0x00C0, "SessionDiscoveryprotocol"},
  {0x00C1, "SessionControlprotocol"},

  {0x00C4, "ConferenceDiscoveryprotocol"},
  {0x00C5, "Conferenceprotocol"},

  {0x00CC, "SCCPCallControlProxyprotocol"},

  {0x00D0, "CallDiscoveryprotocol"},
  {0x00D1, "CallControlprotocol"},

  {0     , NULL}	/* terminator */
};

static const value_string  audioCodecTypes[] = {
  {1  , "G711"},
  {1  , "G729"},
  {2  , "GSM"},
  {3  , "G723"},
  {4  , "G722"},
  {5  , "WideBand"},
  { 0    , NULL}
};

static const value_string orcStatus[] = {
  {0   , "orcOk"},
  {1   , "orcError"},
  {0   , NULL}
};

static const value_string mediaPayloads[] = {
  {1   , "Non-standard codec"},
  {2   , "G.711 A-law 64k"},
  {3   , "G.711 A-law 56k"},
  {4   , "G.711 u-law 64k"},
  {5   , "G.711 u-law 56k"},
  {6   , "G.722 64k"},
  {7   , "G.722 56k"},
  {8   , "G.722 48k"},
  {9   , "G.723.1"},
  {10  , "G.728"},
  {11  , "G.729"},
  {12  , "G.729 Annex A"},
  {13  , "IS11172 AudioCap"},	/* IS11172 is an ISO MPEG standard */
  {14  , "IS13818 AudioCap"},	/* IS13818 is an ISO MPEG standard */
  {15  , "G.729 Annex B"},
  {16  , "G.729 Annex A+Annex B"},
  {18  , "GSM Full Rate"},
  {19  , "GSM Half Rate"},
  {20  , "GSM Enhanced Full Rate"},
  {25  , "Wideband 256k"},
  {32  , "Data 64k"},
  {33  , "Data 56k"},
  {80  , "GSM"},
  {81  , "ActiveVoice"},
  {82  , "G.726 32K"},
  {83  , "G.726 24K"},
  {84  , "G.726 16K"},
  {85  , "G.729B"},
  {86  , "G.729B Low Complexity"},
	{100 , "H261"},
 	{101 , "H263"},
	{102 , "Vieo"},
	{105 , "T120"},
	{106 , "H224"},
	{257 , "RFC2833_DynPayload"},
  {0  , NULL}
};

static const value_string cast_Layouts[] = {
  {0  , "NoLayout"},
  {1  , "OneByOne"},
  {2  , "OneByTwo"},
  {3  , "TwoByTwo"},
  {4  , "TwoByTwo3Alt1"},
  {5  , "TwoByTwo3Alt2"},
  {6  , "ThreeByThree"},
  {7  , "ThreeByThree6Alt1"},
  {8  , "ThreeByThree6Alt2"},
  {9  , "ThreeByThree4Alt1"},
  {10 , "ThreeByThree4Alt2"},
  {0  , NULL}
};

static const value_string cast_transmitOrReceive[] = {
  {1  , "Station_Receive_only"},
  {2  , "Station_Transmit_only"},
  {3  , "Station_Receive_Transmit"},
  {0  , NULL}
};

static const value_string cast_formatTypes[] = {
  {1  , "sqcif (128x96)"},
  {2  , "qcif (176x144)"},
  {3  , "cif (352x288)"},
  {4  , "4cif (704x576)"},
  {5  , "16cif (1408x1152)"},
  {6  , "custom_base"},
  {0  , NULL}
};

static const value_string cast_echoCancelTypes[] = {
  {0    , "Media_EchoCancellation_Off"},
  {1    , "Media_EchoCancellation_On"},
  {0    , NULL}
};

static const value_string cast_g723BitRates[] = {
  {1   , "Media_G723BRate_5_3"},
  {2   , "Media_G723BRate_6_4"},
  {0   , NULL}
};

static const value_string cast_miscCommandType[] = {
  {0  , "videoFreezePicture"},
  {1  , "videoFastUpdatePicture"},
  {2  , "videoFastUpdateGOB"},
  {3  , "videoFastUpdateMB"},
  {4  , "lostPicture"},
  {5  , "lostPartialPicture"},
  {6  , "recoveryReferencePicture"},
  {7  , "temporalSpatialTradeOff"},
  {0  , NULL}
};

static const value_string cast_callStateTypes[] = {
  {0  , "TsIdle"},
  {1  , "TsOffHook"},
  {2  , "TsOnHook"},
  {3  , "TsRingOut"},
  {4  , "TsRingIn"},
  {5  , "TsConnected"},
  {6  , "TsBusy"},
  {7  , "TsCongestion"},
  {8  , "TsHold"},
  {9  , "TsCallWaiting"},
  {10 , "TsCallTransfer"},
  {11 , "TsCallPark"},
  {12 , "TsProceed"},
  {13 , "TsCallRemoteMultiline"},
  {14 , "TsInvalidNumber"},
  {15 , "TsMaxState"},
  {0  , NULL}
};

/* Defined Call Type */
static const value_string cast_callTypes[] = {
  {1   , "InBoundCall"},
  {2   , "OutBoundCall"},
  {3   , "ForwardCall"},
  {0   , NULL}
};

static const value_string cast_callSecurityStatusTypes[] = {
  {0   , "CallSecurityStatusUnknown"},
  {1   , "CallSecurityStatusNotAuthenticated"},
  {2   , "CallSecurityStatusAuthenticated"},
  {0   , NULL}
};


#define MAX_CUSTOM_PICTURES				6
#define MAX_SERVICE_TYPE				4
#define MAX_LAYOUT_WITH_SAME_SERVICE	5
#define MAX_PICTURE_FORMAT			 5
#define MAX_REFERENCE_PICTURE		 4
#define MAX_LEVEL_PREFERENCE		 4
#define StationMaxVideoCapabilities	10
#define StationMaxDataCapabilities   5
#define StationMaxNameSize 40           /* max size of calling party's name  */
#define StationMaxDirnumSize 24         /* max size of calling or called party dirnum  */


static void dissect_cast(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Initialize the protocol and registered fields */
static int proto_cast          = -1;
static int hf_cast_data_length = -1;
static int hf_cast_reserved    = -1;
static int hf_cast_messageid   = -1;
static int hf_cast_version   = -1;
static int hf_cast_ORCStatus = -1;
static int hf_cast_ipAddress = -1;
static int hf_cast_portNumber = -1;
static int hf_cast_passThruPartyID = -1;
static int hf_cast_callIdentifier = -1;
static int hf_cast_conferenceID = -1;
static int hf_cast_payloadType = -1;
static int hf_cast_lineInstance = -1;
static int hf_cast_payloadCapability = -1;
static int hf_cast_isConferenceCreator = -1;
static int hf_cast_payload_rfc_number = -1;
static int hf_cast_videoCapCount = -1;
static int hf_cast_dataCapCount = -1;
static int hf_cast_RTPPayloadFormat = -1;
static int hf_cast_customPictureFormatCount = -1;
static int hf_cast_pictureWidth = -1;
static int hf_cast_pictureHeight = -1;
static int hf_cast_pixelAspectRatio = -1;
static int hf_cast_clockConversionCode = -1;
static int hf_cast_clockDivisor = -1;
static int hf_cast_activeStreamsOnRegistration = -1;
static int hf_cast_maxBW = -1;
static int hf_cast_serviceResourceCount = -1;
static int hf_cast_layoutCount = -1;
static int hf_cast_layout = -1;
static int hf_cast_maxConferences = -1;
static int hf_cast_activeConferenceOnRegistration = -1;
static int hf_cast_transmitOrReceive = -1;
static int hf_cast_levelPreferenceCount = -1;
static int hf_cast_transmitPreference = -1;
static int hf_cast_format = -1;
static int hf_cast_maxBitRate = -1;
static int hf_cast_minBitRate = -1;
static int hf_cast_MPI = -1;
static int hf_cast_serviceNumber = -1;
static int hf_cast_temporalSpatialTradeOffCapability = -1;
static int hf_cast_stillImageTransmission = -1;
static int hf_cast_h263_capability_bitfield = -1;
static int hf_cast_annexNandWFutureUse = -1;
static int hf_cast_modelNumber = -1;
static int hf_cast_bandwidth = -1;
static int hf_cast_protocolDependentData = -1;
static int hf_cast_DSCPValue = -1;
static int hf_cast_serviceNum = -1;
static int hf_cast_precedenceValue = -1;
static int hf_cast_maxStreams = -1;
static int hf_cast_millisecondPacketSize = -1;
static int hf_cast_echoCancelType = -1;
static int hf_cast_g723BitRate = -1;
static int hf_cast_bitRate = -1;
static int hf_cast_pictureFormatCount = -1;
static int hf_cast_confServiceNum = -1;
static int hf_cast_miscCommandType = -1;
static int hf_cast_temporalSpatialTradeOff = -1;
static int hf_cast_firstGOB = -1;
static int hf_cast_numberOfGOBs = -1;
static int hf_cast_firstMB = -1;
static int hf_cast_numberOfMBs = -1;
static int hf_cast_pictureNumber = -1;
static int hf_cast_longTermPictureIndex = -1;
static int hf_cast_recoveryReferencePictureCount = -1;
static int hf_cast_calledParty = -1;
static int hf_cast_privacy = -1;
static int hf_cast_precedenceLv = -1;
static int hf_cast_precedenceDm = -1;
static int hf_cast_callState = -1;
static int hf_cast_callingPartyName = -1;
static int hf_cast_callingParty = -1;
static int hf_cast_calledPartyName = -1;
static int hf_cast_callType = -1;
static int hf_cast_originalCalledPartyName = -1;
static int hf_cast_originalCalledParty = -1;
static int hf_cast_lastRedirectingPartyName = -1;
static int hf_cast_lastRedirectingParty = -1;
static int hf_cast_cgpnVoiceMailbox = -1;
static int hf_cast_cdpnVoiceMailbox = -1;
static int hf_cast_originalCdpnVoiceMailbox = -1;
static int hf_cast_lastRedirectingVoiceMailbox = -1;
static int hf_cast_originalCdpnRedirectReason = -1;
static int hf_cast_lastRedirectingReason = -1;
static int hf_cast_callInstance = -1;
static int hf_cast_callSecurityStatus = -1;
static int hf_cast_directoryNumber = -1;
static int hf_cast_requestorIpAddress = -1;
static int hf_cast_stationIpAddress = -1;
static int hf_cast_stationFriendlyName = -1;
static int hf_cast_stationGUID = -1;
static int hf_cast_audio = -1;



/* Initialize the subtree pointers */
static gint ett_cast          = -1;
static gint ett_cast_tree     = -1;

/* desegmentation of SCCP */
static gboolean cast_desegment = TRUE;

static dissector_handle_t data_handle;

/* Dissect a single CAST PDU */
static void dissect_cast_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  int offset = 0;

  /* Header fields */
  guint32 hdr_data_length;
  guint32 hdr_marker;
  guint32 data_messageid;
  const gchar *messageid_str;
  /*  guint32 data_size; */

  guint i = 0;
  guint t = 0;
  int count;
  int val;

  /* Set up structures we will need to add the protocol subtree and manage it */
  proto_item *ti;
  proto_tree *cast_tree = NULL;
  proto_item *ti_sub;
  proto_tree *cast_sub_tree;
  proto_tree *cast_sub_tree_sav;
  proto_tree *cast_sub_tree_sav_sav;

  hdr_data_length = tvb_get_letohl(tvb, offset);
  hdr_marker      = tvb_get_letohl(tvb, offset+4);
  data_messageid  = tvb_get_letohl(tvb, offset+8);

  /* In the interest of speed, if "tree" is NULL, don't do any work not
   * necessary to generate protocol tree items. */
  if (tree) {
    ti = proto_tree_add_item(tree, proto_cast, tvb, offset, hdr_data_length+8, FALSE);
    cast_tree = proto_item_add_subtree(ti, ett_cast);
    proto_tree_add_uint(cast_tree, hf_cast_data_length, tvb, offset, 4, hdr_data_length);
    proto_tree_add_uint(cast_tree, hf_cast_reserved, tvb, offset+4, 4, hdr_marker);
  }

  messageid_str = val_to_str(data_messageid, message_id, "0x%08X (Unknown)");

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_str(pinfo->cinfo, COL_INFO, messageid_str);
  }

  if (tree) {
    proto_tree_add_uint(cast_tree, hf_cast_messageid, tvb,offset+8, 4, data_messageid );
  }

  if (tree) {
    switch(data_messageid) {

    case 0x0 :    /* keepAlive */
      /* no data in message */
      break;

    case 0x1 :    /* KeepAliveVersion */
      proto_tree_add_item(cast_tree, hf_cast_version, tvb, offset+12, 4, TRUE);
      break;

    case 0x2 :    /* KeepAliveVersionAck */
      proto_tree_add_item(cast_tree, hf_cast_version, tvb, offset+12, 4, TRUE);
      break;

    case 0x3 :    /* UpdateCapabilities */
      /* to do - this message is very large and will span multiple packets, it would be nice to someday */
      /* find out a way to join the next packet and get the complete message to decode */
      proto_tree_add_item(cast_tree, hf_cast_videoCapCount, tvb, offset+12, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_dataCapCount, tvb, offset+16, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_RTPPayloadFormat, tvb, offset+20, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_customPictureFormatCount, tvb, offset+24, 4, TRUE);
      count = offset+28;
      /* total of 120 bytes */
      for ( i = 0; i < MAX_CUSTOM_PICTURES; i++ ) {
		    ti_sub = proto_tree_add_text(cast_tree, tvb, offset, 20, "customPictureFormat[%d]", i);
		    cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
        proto_tree_add_item(cast_sub_tree, hf_cast_pictureWidth, tvb, count, 4, TRUE);
        count+= 4;
        proto_tree_add_item(cast_sub_tree, hf_cast_pictureHeight, tvb, count, 4, TRUE);
        count+= 4;
        proto_tree_add_item(cast_sub_tree, hf_cast_pixelAspectRatio, tvb, count, 4, TRUE);
        count+= 4;
        proto_tree_add_item(cast_sub_tree, hf_cast_clockConversionCode, tvb, count, 4, TRUE);
        count+= 4;
        proto_tree_add_item(cast_sub_tree, hf_cast_clockDivisor, tvb, count, 4, TRUE);
        count+= 4;
      }
      ti_sub = proto_tree_add_text(cast_tree, tvb, offset, 8, "confResources");
      cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
      proto_tree_add_item(cast_sub_tree, hf_cast_activeStreamsOnRegistration, tvb, count, 4, TRUE);
      count+= 4;
      proto_tree_add_item(cast_sub_tree, hf_cast_maxBW, tvb, count, 4, TRUE);
      count+= 4;
      proto_tree_add_item(cast_sub_tree, hf_cast_serviceResourceCount, tvb, count, 4, TRUE);
      count+= 4;
      cast_sub_tree_sav = cast_sub_tree;
      /* total of 160 bytes */
      for ( i = 0; i < MAX_SERVICE_TYPE; i++ ) {
        ti_sub = proto_tree_add_text(cast_sub_tree_sav, tvb, offset, 20, "serviceResource[%d]", i);
        cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
        proto_tree_add_item(cast_sub_tree, hf_cast_layoutCount, tvb, count, 4, TRUE);
        count+= 4;
        cast_sub_tree_sav_sav = cast_sub_tree_sav;
        for ( t = 0; t < MAX_LAYOUT_WITH_SAME_SERVICE; t++ ) {
		      ti_sub = proto_tree_add_text(cast_sub_tree_sav, tvb, offset, 20, "layouts[%d]", t);
		      cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
          proto_tree_add_item(cast_sub_tree, hf_cast_layout, tvb, count, 4, TRUE);
          count+= 4;
        }
        cast_sub_tree = cast_sub_tree_sav_sav;
        proto_tree_add_item(cast_sub_tree, hf_cast_serviceNum, tvb, count, 4, TRUE);
        count+= 4;
        proto_tree_add_item(cast_sub_tree, hf_cast_maxStreams, tvb, count, 4, TRUE);
        count+= 4;
        proto_tree_add_item(cast_sub_tree, hf_cast_maxConferences, tvb, count, 4, TRUE);
        count+= 4;
        proto_tree_add_item(cast_sub_tree, hf_cast_activeConferenceOnRegistration, tvb, count, 4, TRUE);
        count+= 4;
      }
      /* total of 176 bytes */
      for ( i = 0; i < StationMaxVideoCapabilities; i++ ) {
        ti_sub = proto_tree_add_text(cast_tree, tvb, offset, 20, "vidCaps[%d]", i);
        cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
        proto_tree_add_item(cast_sub_tree, hf_cast_payloadCapability, tvb, count, 4, TRUE);
        count+= 4;
        proto_tree_add_item(cast_sub_tree, hf_cast_transmitOrReceive, tvb, count, 4, TRUE);
        count+= 4;
        proto_tree_add_item(cast_sub_tree, hf_cast_levelPreferenceCount, tvb, count, 4, TRUE);
        count+= 4;
        cast_sub_tree_sav = cast_sub_tree;
        for ( t = 0; t < MAX_LEVEL_PREFERENCE; t++ ) {
          ti_sub = proto_tree_add_text(cast_sub_tree_sav, tvb, offset, 20, "levelPreference[%d]", t);
          cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
          proto_tree_add_item(cast_sub_tree, hf_cast_transmitPreference, tvb, count, 4, TRUE);
          count+= 4;
          proto_tree_add_item(cast_sub_tree, hf_cast_format, tvb, count, 4, TRUE);
          count+= 4;
          proto_tree_add_item(cast_sub_tree, hf_cast_maxBitRate, tvb, count, 4, TRUE);
          count+= 4;
          proto_tree_add_item(cast_sub_tree, hf_cast_minBitRate, tvb, count, 4, TRUE);
          count+= 4;
          proto_tree_add_item(cast_sub_tree, hf_cast_MPI, tvb, count, 4, TRUE);
          count+= 4;
          proto_tree_add_item(cast_sub_tree, hf_cast_serviceNumber, tvb, count, 4, TRUE);
          count+= 4;
        }

        /* H.261 */
        ti_sub = proto_tree_add_text(cast_sub_tree_sav, tvb, offset, 8, "h261VideoCapability");
        cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
        proto_tree_add_item(cast_sub_tree, hf_cast_temporalSpatialTradeOffCapability, tvb, count, 4, TRUE);
        proto_tree_add_item(cast_sub_tree, hf_cast_stillImageTransmission, tvb, count+4, 4, TRUE);

        /* H.263 */
        ti_sub = proto_tree_add_text(cast_sub_tree_sav, tvb, offset, 8, "h263VideoCapability");
        cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
        proto_tree_add_item(cast_sub_tree, hf_cast_h263_capability_bitfield, tvb, count, 4, TRUE);
        proto_tree_add_item(cast_sub_tree, hf_cast_annexNandWFutureUse, tvb, count+4, 4, TRUE);

        /* Vieo */
        ti_sub = proto_tree_add_text(cast_sub_tree_sav, tvb, offset, 8, "vieoVideoCapability");
        cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
        proto_tree_add_item(cast_sub_tree, hf_cast_modelNumber, tvb, count, 4, TRUE);
        count+= 4;
        proto_tree_add_item(cast_sub_tree, hf_cast_bandwidth, tvb, count, 4, TRUE);
        count+= 4;
      }
      /* total 80 bytes */
      for ( i = 0; i < StationMaxDataCapabilities; i++ ) {
        ti_sub = proto_tree_add_text(cast_tree, tvb, offset, 20, "dataCaps[%d]", i);
        cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
        proto_tree_add_item(cast_sub_tree, hf_cast_payloadCapability, tvb, count, 4, TRUE);
        count+= 4;
        proto_tree_add_item(cast_sub_tree, hf_cast_transmitOrReceive, tvb, count, 4, TRUE);
        count+= 4;
        proto_tree_add_item(cast_sub_tree, hf_cast_protocolDependentData, tvb, count, 4, TRUE);
        count+= 4;
        proto_tree_add_item(cast_sub_tree, hf_cast_maxBitRate, tvb, count, 4, TRUE);
        count+= 4;
      }
      break;

    case 0x4 :    /*  */
      break;

    case 0x5 :    /* OpenMultiMediaReceiveChannel */
      proto_tree_add_item(cast_tree, hf_cast_conferenceID, tvb, offset+12, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_passThruPartyID, tvb, offset+16, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_payloadCapability, tvb, offset+20, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_lineInstance, tvb, offset+24, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_callIdentifier, tvb, offset+28, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_payload_rfc_number, tvb, offset+32, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_payloadType, tvb, offset+36, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_isConferenceCreator, tvb, offset+40, 4, TRUE);

      /* add audio part of union */
      ti_sub = proto_tree_add_text(cast_tree, tvb, offset, 12, "audioParameters");
      cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
      proto_tree_add_item(cast_sub_tree, hf_cast_millisecondPacketSize, tvb, offset+44, 4, TRUE);
      proto_tree_add_item(cast_sub_tree, hf_cast_echoCancelType, tvb, offset+48, 4, TRUE);
      proto_tree_add_item(cast_sub_tree, hf_cast_g723BitRate, tvb, offset+52, 4, TRUE);

      /* add video part of union */
      ti_sub = proto_tree_add_text(cast_tree, tvb, offset, 30, "videoParameters");
      cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
      proto_tree_add_item(cast_sub_tree, hf_cast_bitRate, tvb, offset+44, 4, TRUE);
      proto_tree_add_item(cast_sub_tree, hf_cast_pictureFormatCount, tvb, offset+48, 4, TRUE);
      cast_sub_tree_sav = cast_sub_tree;
      count = offset+52;
      for ( i = 0; i < MAX_PICTURE_FORMAT; i++ ) {
        ti_sub = proto_tree_add_text(cast_sub_tree_sav, tvb, offset, 8 * MAX_PICTURE_FORMAT, "pictureFormat[%d]", i);
        cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
        proto_tree_add_item(cast_sub_tree, hf_cast_format, tvb, count, 4, TRUE);
        count += 4;
        proto_tree_add_item(cast_sub_tree, hf_cast_MPI, tvb, count, 4, TRUE);
        count += 4;
      }
      cast_sub_tree = cast_sub_tree_sav;
      proto_tree_add_item(cast_sub_tree, hf_cast_confServiceNum, tvb, count, 4, TRUE);
      count += 4;

      /* add H261 part of union */
      ti_sub = proto_tree_add_text(cast_sub_tree_sav, tvb, offset, 8, "h261VideoCapability");
      cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
      proto_tree_add_item(cast_sub_tree, hf_cast_temporalSpatialTradeOffCapability, tvb, count, 4, TRUE);
      proto_tree_add_item(cast_sub_tree, hf_cast_stillImageTransmission, tvb, count+4, 4, TRUE);

      /* add H263 part of union */
      ti_sub = proto_tree_add_text(cast_sub_tree_sav, tvb, offset, 8, "h263VideoCapability");
      cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
      proto_tree_add_item(cast_sub_tree, hf_cast_h263_capability_bitfield, tvb, count, 4, TRUE);
      proto_tree_add_item(cast_sub_tree, hf_cast_annexNandWFutureUse, tvb, count+4, 4, TRUE);

      /* add Vieo part of union */
      ti_sub = proto_tree_add_text(cast_sub_tree_sav, tvb, offset, 8, "vieoVideoCapability");
      cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
      proto_tree_add_item(cast_sub_tree, hf_cast_modelNumber, tvb, count, 4, TRUE);
      count += 4;
      proto_tree_add_item(cast_sub_tree, hf_cast_bandwidth, tvb, count, 4, TRUE);

      /* add data part of union */
      ti_sub = proto_tree_add_text(cast_tree, tvb, offset, 8, "dataParameters");
      cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
      proto_tree_add_item(cast_sub_tree, hf_cast_protocolDependentData, tvb, offset+44, 4, TRUE);
      proto_tree_add_item(cast_sub_tree, hf_cast_maxBitRate, tvb, offset+48, 4, TRUE);
      break;

    case 0x6 :    /* OpenMultiMediaReceiveChannelACK */
      proto_tree_add_item(cast_tree, hf_cast_ORCStatus, tvb, offset+12, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_ipAddress, tvb, offset+16, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_portNumber, tvb, offset+20, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_passThruPartyID, tvb, offset+24, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_callIdentifier, tvb, offset+28, 4, TRUE);
      break;

    case 0x7 :    /* CloseMultiMediaReceiveChannel */
      proto_tree_add_item(cast_tree, hf_cast_conferenceID, tvb, offset+12, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_passThruPartyID, tvb, offset+16, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_callIdentifier, tvb, offset+20, 4, TRUE);
      break;

    case 0x8 :    /* StartMultiMediaTransmission */
      proto_tree_add_item(cast_tree, hf_cast_conferenceID, tvb, offset+12, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_passThruPartyID, tvb, offset+16, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_payloadCapability, tvb, offset+20, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_ipAddress, tvb, offset+24, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_portNumber, tvb, offset+28, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_callIdentifier, tvb, offset+32, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_payload_rfc_number, tvb, offset+36, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_payloadType, tvb, offset+40, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_DSCPValue, tvb, offset+44, 4, TRUE);

      /* add video part of union */
		  ti_sub = proto_tree_add_text(cast_tree, tvb, offset, 30, "videoParameters");
		  cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
      proto_tree_add_item(cast_sub_tree, hf_cast_bitRate, tvb, offset+48, 4, TRUE);
      proto_tree_add_item(cast_sub_tree, hf_cast_pictureFormatCount, tvb, offset+52, 4, TRUE);
      cast_sub_tree_sav = cast_sub_tree;
      count = offset+56;
      for ( i = 0; i < MAX_PICTURE_FORMAT; i++ ) {
        ti_sub = proto_tree_add_text(cast_sub_tree_sav, tvb, offset, 8 * MAX_PICTURE_FORMAT, "pictureFormat[%d]", i);
        cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
        proto_tree_add_item(cast_sub_tree, hf_cast_format, tvb, count, 4, TRUE);
        count += 4;
        proto_tree_add_item(cast_sub_tree, hf_cast_MPI, tvb, count, 4, TRUE);
        count += 4;
      }
      cast_sub_tree = cast_sub_tree_sav;
      proto_tree_add_item(cast_sub_tree, hf_cast_confServiceNum, tvb, count, 4, TRUE);
      count += 4;

      val = count;
      /* add H261 part of union */
      ti_sub = proto_tree_add_text(cast_sub_tree_sav, tvb, offset, 8, "h261VideoCapability");
      cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
      proto_tree_add_item(cast_sub_tree, hf_cast_temporalSpatialTradeOffCapability, tvb, count, 4, TRUE);
      count += 4;
      proto_tree_add_item(cast_sub_tree, hf_cast_stillImageTransmission, tvb, count, 4, TRUE);

      /* add H263 part of union */
      count = val;
      ti_sub = proto_tree_add_text(cast_sub_tree_sav, tvb, offset, 8, "h263VideoCapability");
      cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
      proto_tree_add_item(cast_sub_tree, hf_cast_h263_capability_bitfield, tvb, count, 4, TRUE);
      count += 4;
      proto_tree_add_item(cast_sub_tree, hf_cast_annexNandWFutureUse, tvb, count, 4, TRUE);

      /* add Vieo part of union */
      count = val;
      ti_sub = proto_tree_add_text(cast_sub_tree_sav, tvb, offset, 8, "vieoVideoCapability");
      cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
      proto_tree_add_item(cast_sub_tree, hf_cast_modelNumber, tvb, count, 4, TRUE);
      count += 4;
      proto_tree_add_item(cast_sub_tree, hf_cast_bandwidth, tvb, count, 4, TRUE);

      /* add data part of union */
      ti_sub = proto_tree_add_text(cast_tree, tvb, offset, 8, "dataParameters");
      cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
      proto_tree_add_item(cast_sub_tree, hf_cast_protocolDependentData, tvb, offset+48, 4, TRUE);
      proto_tree_add_item(cast_sub_tree, hf_cast_maxBitRate, tvb, offset+52, 4, TRUE);
      break;

    case 0x9 :    /* StopMultiMediaTransmission */
      proto_tree_add_item(cast_tree, hf_cast_conferenceID, tvb, offset+12, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_passThruPartyID, tvb, offset+16, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_callIdentifier, tvb, offset+20, 4, TRUE);
      break;

    case 0xA :    /* MiscellaneousCommand */
      proto_tree_add_item(cast_tree, hf_cast_conferenceID, tvb, offset+12, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_passThruPartyID, tvb, offset+16, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_callIdentifier, tvb, offset+20, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_miscCommandType, tvb, offset+24, 4, TRUE);

      /* show videoFreezePicture */
      /* not sure of format */

      /* show videoFastUpdatePicture */
      /* not sure of format */

      /* show videoFastUpdateGOB */
      ti_sub = proto_tree_add_text(cast_tree, tvb, offset, 8, "videoFastUpdateGOB");
      cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
      proto_tree_add_item(cast_sub_tree, hf_cast_firstGOB, tvb, offset+28, 4, TRUE);
      proto_tree_add_item(cast_sub_tree, hf_cast_numberOfGOBs, tvb, offset+32, 4, TRUE);

      /* show videoFastUpdateMB */
      ti_sub = proto_tree_add_text(cast_tree, tvb, offset, 8, "videoFastUpdateGOB");
      cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
      proto_tree_add_item(cast_sub_tree, hf_cast_firstGOB, tvb, offset+28, 4, TRUE);
      proto_tree_add_item(cast_sub_tree, hf_cast_firstMB, tvb, offset+32, 4, TRUE);
      proto_tree_add_item(cast_sub_tree, hf_cast_numberOfMBs, tvb, offset+36, 4, TRUE);

      /* show lostPicture */
      ti_sub = proto_tree_add_text(cast_tree, tvb, offset, 8, "lostPicture");
      cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
      proto_tree_add_item(cast_sub_tree, hf_cast_pictureNumber, tvb, offset+28, 4, TRUE);
      proto_tree_add_item(cast_sub_tree, hf_cast_longTermPictureIndex, tvb, offset+32, 4, TRUE);

      /* show lostPartialPicture */
      ti_sub = proto_tree_add_text(cast_tree, tvb, offset, 8, "lostPartialPicture");
      cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
      proto_tree_add_item(cast_sub_tree, hf_cast_pictureNumber, tvb, offset+28, 4, TRUE);
      proto_tree_add_item(cast_sub_tree, hf_cast_longTermPictureIndex, tvb, offset+32, 4, TRUE);
      proto_tree_add_item(cast_sub_tree, hf_cast_firstMB, tvb, offset+36, 4, TRUE);
      proto_tree_add_item(cast_sub_tree, hf_cast_numberOfMBs, tvb, offset+40, 4, TRUE);

      /* show recoveryReferencePicture */
      ti_sub = proto_tree_add_text(cast_tree, tvb, offset, 8, "recoveryReferencePicture");
      cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
      proto_tree_add_item(cast_sub_tree, hf_cast_recoveryReferencePictureCount, tvb, offset+28, 4, TRUE);
      cast_sub_tree_sav = cast_sub_tree;
      for ( i = 0; i < MAX_REFERENCE_PICTURE; i++ ) {
        ti_sub = proto_tree_add_text(cast_sub_tree_sav, tvb, offset, 8, "recoveryReferencePicture[%d]", i);
        cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
        proto_tree_add_item(cast_sub_tree, hf_cast_pictureNumber, tvb, offset+32+(i*8), 4, TRUE);
        proto_tree_add_item(cast_sub_tree, hf_cast_longTermPictureIndex, tvb, offset+36+(i*8), 4, TRUE);
      }

      /* show temporalSpatialTradeOff */
      ti_sub = proto_tree_add_text(cast_tree, tvb, offset, 4, "temporalSpatialTradeOff");
      cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
      proto_tree_add_item(cast_sub_tree, hf_cast_temporalSpatialTradeOff, tvb, offset+28, 4, TRUE);
      break;

    case 0xB :    /* FlowControlCommand */
      proto_tree_add_item(cast_tree, hf_cast_conferenceID, tvb, offset+12, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_passThruPartyID, tvb, offset+16, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_callIdentifier, tvb, offset+20, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_maxBitRate, tvb, offset+24, 4, TRUE);
      break;

    case 0xC :    /* ClearConference */
      proto_tree_add_item(cast_tree, hf_cast_conferenceID, tvb, offset+12, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_serviceNum, tvb, offset+16, 4, TRUE);
      break;

    case 0xD :    /* CallState */
      proto_tree_add_item(cast_tree, hf_cast_callState, tvb, offset+12, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_lineInstance, tvb, offset+16, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_callIdentifier, tvb, offset+20, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_privacy, tvb, offset+24, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_precedenceLv, tvb, offset+28, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_precedenceDm, tvb, offset+32, 4, TRUE);
      break;

    case 0xE :    /* RequestCallState */
      proto_tree_add_item(cast_tree, hf_cast_callIdentifier, tvb, offset+12, 4, TRUE);
      break;

    case 0xF :    /* RequestAllCallStates */
      /* no data in message */
      break;

    case 0x10 :    /* CallInfo */
      i = offset+12;
      proto_tree_add_item(cast_tree, hf_cast_callingPartyName, tvb, i, StationMaxNameSize, TRUE);
      i += StationMaxNameSize;
      proto_tree_add_item(cast_tree, hf_cast_callingParty, tvb, i, StationMaxDirnumSize, TRUE);
      i += StationMaxDirnumSize;
      proto_tree_add_item(cast_tree, hf_cast_calledPartyName, tvb, i, StationMaxNameSize, TRUE);
      i += StationMaxNameSize;
      proto_tree_add_item(cast_tree, hf_cast_calledParty, tvb, i, StationMaxDirnumSize, TRUE);
      i += StationMaxDirnumSize;
      proto_tree_add_item(cast_tree, hf_cast_lineInstance, tvb, i, 4, TRUE);
      i += 4;
      proto_tree_add_item(cast_tree, hf_cast_callIdentifier, tvb, i, 4, TRUE);
      i += 4;
      proto_tree_add_item(cast_tree, hf_cast_callType, tvb, i, 4, TRUE);
      i += 4;
      proto_tree_add_item(cast_tree, hf_cast_originalCalledPartyName, tvb, i, StationMaxNameSize, TRUE);
      i += StationMaxNameSize;
      proto_tree_add_item(cast_tree, hf_cast_originalCalledParty, tvb, i, StationMaxDirnumSize, TRUE);
      i += StationMaxDirnumSize;
      proto_tree_add_item(cast_tree, hf_cast_lastRedirectingPartyName, tvb, i, StationMaxNameSize, TRUE);
      i += StationMaxNameSize;
      proto_tree_add_item(cast_tree, hf_cast_lastRedirectingParty, tvb, i, StationMaxDirnumSize, TRUE);
      i += StationMaxDirnumSize;
      proto_tree_add_item(cast_tree, hf_cast_originalCdpnRedirectReason, tvb, i, 4, TRUE);
      i += 4;
      proto_tree_add_item(cast_tree, hf_cast_lastRedirectingReason, tvb, i, 4, TRUE);
      i += 4;
      proto_tree_add_item(cast_tree, hf_cast_cgpnVoiceMailbox, tvb, i, StationMaxDirnumSize, TRUE);
      i += StationMaxDirnumSize;
      proto_tree_add_item(cast_tree, hf_cast_cdpnVoiceMailbox, tvb, i, StationMaxDirnumSize, TRUE);
      i += StationMaxDirnumSize;
      proto_tree_add_item(cast_tree, hf_cast_originalCdpnVoiceMailbox, tvb, i, StationMaxDirnumSize, TRUE);
      i += StationMaxDirnumSize;
      proto_tree_add_item(cast_tree, hf_cast_lastRedirectingVoiceMailbox, tvb, i, StationMaxDirnumSize, TRUE);
      i += StationMaxDirnumSize;
      proto_tree_add_item(cast_tree, hf_cast_callInstance, tvb, i, 4, TRUE);
      i += 4;
      proto_tree_add_item(cast_tree, hf_cast_callSecurityStatus, tvb, i, 4, TRUE);
      i += 4;
      val = tvb_get_letohl( tvb, i);
      ti_sub = proto_tree_add_text(cast_tree, tvb, offset, 8, "partyPIRestrictionBits");
      cast_sub_tree = proto_item_add_subtree(ti_sub, ett_cast_tree);
      proto_tree_add_text(cast_sub_tree, tvb, i, 4,
        decode_boolean_bitfield( val, 0x01, 4*8, "Does RestrictCallingPartyName", "Doesn't RestrictCallingPartyName"));
      proto_tree_add_text(cast_sub_tree, tvb, i, 4,
        decode_boolean_bitfield( val, 0x02, 4*8, "Does RestrictCallingPartyNumber", "Doesn't RestrictCallingPartyNumber"));
      proto_tree_add_text(cast_sub_tree, tvb, i, 4,
        decode_boolean_bitfield( val, 0x04, 4*8, "Does RestrictCalledPartyName", "Doesn't RestrictCalledPartyName"));
      proto_tree_add_text(cast_sub_tree, tvb, i, 4,
        decode_boolean_bitfield( val, 0x08, 4*8, "Does RestrictCalledPartyNumber", "Doesn't RestrictCalledPartyNumber"));
      proto_tree_add_text(cast_sub_tree, tvb, i, 4,
        decode_boolean_bitfield( val, 0x10, 4*8, "Does RestrictOriginalCalledPartyName", "Doesn't RestrictOriginalCalledPartyName"));
      proto_tree_add_text(cast_sub_tree, tvb, i, 4,
        decode_boolean_bitfield( val, 0x20, 4*8, "Does RestrictOriginalCalledPartyNumber", "Doesn't RestrictOriginalCalledPartyNumber"));
      proto_tree_add_text(cast_sub_tree, tvb, i, 4,
        decode_boolean_bitfield( val, 0x40, 4*8, "Does RestrictLastRedirectPartyName", "Doesn't RestrictLastRedirectPartyName"));
      proto_tree_add_text(cast_sub_tree, tvb, i, 4,
        decode_boolean_bitfield( val, 0x80, 4*8, "Does RestrictLastRedirectPartyNumber", "Doesn't RestrictLastRedirectPartyNumber"));
      break;

    case 0x11 :    /* RequestCallInfo */
      proto_tree_add_item(cast_tree, hf_cast_lineInstance, tvb, offset+12, 4, TRUE);
      break;

    case 0x12 :    /* CallFocus */
      proto_tree_add_item(cast_tree, hf_cast_lineInstance, tvb, offset+12, 4, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_callIdentifier, tvb, offset+16, 4, TRUE);
      break;

    case 0x13 :    /* MakeCall */
      proto_tree_add_item(cast_tree, hf_cast_calledParty, tvb, offset+12, StationMaxDirnumSize, TRUE);
      proto_tree_add_item(cast_tree, hf_cast_lineInstance, tvb, offset+16, 4, TRUE);
      break;

    case 0x14 :    /* HangUp */
      proto_tree_add_item(cast_tree, hf_cast_lineInstance, tvb, offset+12, 4, TRUE);
      break;

    case 0x15 :    /* Answer */
      proto_tree_add_item(cast_tree, hf_cast_lineInstance, tvb, offset+12, 4, TRUE);
      break;

    case 0x40 :    /* keepAliveAck */
      /* no data in message */
      break;

    case 0x41 :    /* StreamStart */
      /* no data in message */
      break;

    case 0x42 :    /* StreamStop */
      /* no data in message */
      break;

    case 0x43 :    /* MuteStart */
      /* no data in message */
      break;

    case 0x44 :    /* MuteStop */
      /* no data in message */
      break;

    case 0x45 :    /* SpeakerStart */
      /* no data in message */
      break;

    case 0x46 :    /* SpeakerStop */
      /* no data in message */
      break;

    case 0x47 :    /* StreamStartMessageWithCodec */
      proto_tree_add_item(cast_tree, hf_cast_audio, tvb, offset+12, 4, TRUE);
      break;


    case 0x50 :    /* VIEODiscoveryprotocol */
      break;

    case 0x51 :    /* VIEOControlprotocol */
      break;


    case 0x60 :    /* VeT120protocol */
      break;

    case 0x61 :    /* VeT121protocol */
      break;

    case 0x62 :    /* VeT122protocol */
      break;


    case 0x70 :    /* IMSessionDiscoveryprotocol */
      break;

    case 0x71 :    /* IMSessionControlprotocol */
      break;


    case 0x74 :    /* SlidesDiscoveryprotocol */
      break;

    case 0x75 :    /* SlidesControlprotocol */
      break;


    case 0x80 :    /* Tunnel */
      break;

    case 0x90 :    /* RemoteInfoRequest */
      i = offset+12;
      proto_tree_add_item(cast_tree, hf_cast_stationFriendlyName, tvb, i, StationMaxNameSize, TRUE);
      i += StationMaxNameSize;
      proto_tree_add_item(cast_tree, hf_cast_stationGUID, tvb, i, StationMaxNameSize, TRUE);
      i += StationMaxNameSize;
      proto_tree_add_item(cast_tree, hf_cast_requestorIpAddress, tvb, i, 4, TRUE);
      break;

    case 0x91 :    /* RemoteInfoResponse */
      i = offset+12;
      proto_tree_add_item(cast_tree, hf_cast_stationFriendlyName, tvb, i, StationMaxNameSize, TRUE);
      i += StationMaxNameSize;
      proto_tree_add_item(cast_tree, hf_cast_stationGUID, tvb, i, StationMaxNameSize, TRUE);
      i += StationMaxNameSize;
      proto_tree_add_item(cast_tree, hf_cast_stationIpAddress, tvb, i, 4, TRUE);
      i += 4;
      proto_tree_add_item(cast_tree, hf_cast_directoryNumber, tvb, i, StationMaxNameSize, TRUE);
      break;


    case 0xA0 :    /* CollabDiscoveryprotocol */
      break;

    case 0xA1 :    /* CollabControlprotocol */
      break;


    case 0xA4 :    /* FECCDiscoveryprotocol */
      break;

    case 0xA5 :    /* FECCControlprotocol */
      break;


    case 0xB0 :    /* ClockSyncprotocol */
      break;

    case 0xB1 :    /* StreamSyncprotocol */
      break;


    case 0xB4 :    /* MediaDiscoveryprotocol */
      break;

    case 0xB5 :    /* MediaControlprotocol */
      break;


    case 0xC0 :    /* SessionDiscoveryprotocol */
      break;

    case 0xC1 :    /* SessionControlprotocol */
      break;


    case 0xC4 :    /* ConferenceDiscoveryprotocol */
      break;

    case 0xC5 :    /* Conferenceprotocol */
      break;


    case 0xCC :    /* SCCPCallControlProxyprotocol */
      break;


    case 0xD0 :    /* CallDiscoveryprotocol */
      break;

    case 0xD1 :    /* CallControlprotocol */
      break;


    default:
      break;
    }
  }
}

/* Get the length of a single CAST PDU */
static guint get_cast_pdu_len(tvbuff_t *tvb, int offset)
{
  guint32 hdr_data_length;

  /*
   * Get the length of the CAST packet.
   */
  hdr_data_length = tvb_get_letohl(tvb, offset);

  /*
   * That length doesn't include the length of the header itself;
   * add that in.
   */
  return hdr_data_length + 8;
}

/* Code to actually dissect the packets */
static void dissect_cast(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  /* The general structure of a packet: {IP-Header|TCP-Header|n*CAST}
   * CAST-Packet: {Header(Size, Reserved)|Data(MessageID, Message-Data)}
   */
  /* Header fields */
  volatile guint32 hdr_data_length;
  guint32 hdr_marker;

  /* check, if this is really an SKINNY packet, they start with a length + 0 */

  /* get relevant header information */
  hdr_data_length = tvb_get_letohl(tvb, 0);
  hdr_marker      = tvb_get_letohl(tvb, 4);

  /*  data_size       = MIN(8+hdr_data_length, tvb_length(tvb)) - 0xC; */

  if (hdr_data_length < 4 || hdr_marker != 0) {
    /* Not an CAST packet, just happened to use the same port */
    call_dissector(data_handle,tvb, pinfo, tree);
    return;
  }

  /* Make entries in Protocol column and Info column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CAST");
  }

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_set_str(pinfo->cinfo, COL_INFO, "Cast Client Control Protocol");
  }
  tcp_dissect_pdus(tvb, pinfo, tree, cast_desegment, 4, get_cast_pdu_len, dissect_cast_pdu);
}

/* Register the protocol with Ethereal */
void
proto_register_cast(void)
{
  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_cast_data_length,
      { "Data Length", "cast.data_length",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Number of bytes in the data portion.",
	HFILL }
    },

    { &hf_cast_reserved,
      { "Marker", "cast.marker",
	FT_UINT32, BASE_HEX, NULL, 0x0,
	"Marker value should ne zero.",
	HFILL }
    },

    /* FIXME: Enable use of message name ???  */
    { &hf_cast_messageid,
      { "Message ID", "cast.messageid",
	FT_UINT32, BASE_HEX, VALS(message_id), 0x0,
	"The function requested/done with this message.",
	HFILL }
    },

    { &hf_cast_version,
      { "Version", "cast.version",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The version in the keepalive version messages.",
	HFILL }
    },

    { &hf_cast_ORCStatus,
      { "ORCStatus", "cast.ORCStatus",
	FT_UINT32, BASE_DEC, VALS(orcStatus), 0x0,
	"The status of the opened receive channel.",
	HFILL }
    },

    { &hf_cast_ipAddress,
      { "IP Address", "cast.ipAddress",
	FT_IPv4, BASE_NONE, NULL, 0x0,
	"An IP address",
	HFILL }
    },

    { &hf_cast_portNumber,
      { "Port Number", "cast.portNumber",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"A port number",
	HFILL }
    },

    { &hf_cast_passThruPartyID,
      { "PassThruPartyID", "cast.passThruPartyID",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The pass thru party id",
	HFILL }
    },

    { &hf_cast_callIdentifier,
      { "Call Identifier", "cast.callIdentifier",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Call identifier for this call.",
	HFILL }
    },

    { &hf_cast_conferenceID,
      { "Conference ID", "cast.conferenceID",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The conference ID",
	HFILL }
    },

    { &hf_cast_payloadType,
      { "PayloadType", "cast.payloadType",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"PayloadType.",
	HFILL }
    },

    { &hf_cast_lineInstance,
      { "Line Instance", "cast.lineInstance",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The display call plane associated with this call.",
	HFILL }
    },

    { &hf_cast_payloadCapability,
      { "PayloadCapability", "cast.payloadCapability",
	FT_UINT32, BASE_DEC, VALS(mediaPayloads), 0x0,
	"The payload capability for this media capability structure.",
	HFILL }
    },

    { &hf_cast_isConferenceCreator,
      { "IsConferenceCreator", "cast.isConferenceCreator",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"IsConferenceCreator.",
	HFILL }
    },

    { &hf_cast_payload_rfc_number,
      { "Payload_rfc_number", "cast.payload_rfc_number",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Payload_rfc_number.",
	HFILL }
    },

    { &hf_cast_videoCapCount,
      { "VideoCapCount", "cast.videoCapCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"VideoCapCount.",
	HFILL }
    },

    { &hf_cast_dataCapCount,
      { "DataCapCount", "cast.dataCapCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"DataCapCount.",
	HFILL }
    },

    { &hf_cast_RTPPayloadFormat,
      { "RTPPayloadFormat", "cast.RTPPayloadFormat",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"RTPPayloadFormat.",
	HFILL }
    },

    { &hf_cast_customPictureFormatCount,
      { "CustomPictureFormatCount", "cast.customPictureFormatCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"CustomPictureFormatCount.",
	HFILL }
    },

    { &hf_cast_pictureWidth,
      { "PictureWidth", "cast.pictureWidth",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"PictureWidth.",
	HFILL }
    },

    { &hf_cast_pictureHeight,
      { "PictureHeight", "cast.pictureHeight",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"PictureHeight.",
	HFILL }
    },

    { &hf_cast_pixelAspectRatio,
      { "PixelAspectRatio", "cast.pixelAspectRatio",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"PixelAspectRatio.",
	HFILL }
    },

    { &hf_cast_clockConversionCode,
      { "ClockConversionCode", "cast.clockConversionCode",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"ClockConversionCode.",
	HFILL }
    },

    { &hf_cast_clockDivisor,
      { "ClockDivisor", "cast.clockDivisor",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Clock Divisor.",
	HFILL }
    },

    { &hf_cast_activeStreamsOnRegistration,
      { "ActiveStreamsOnRegistration", "cast.activeStreamsOnRegistration",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"ActiveStreamsOnRegistration.",
	HFILL }
    },

    { &hf_cast_maxBW,
      { "MaxBW", "cast.maxBW",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"MaxBW.",
	HFILL }
    },

    { &hf_cast_serviceResourceCount,
      { "ServiceResourceCount", "cast.serviceResourceCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"ServiceResourceCount.",
	HFILL }
    },

    { &hf_cast_layoutCount,
      { "LayoutCount", "cast.layoutCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"LayoutCount.",
	HFILL }
    },

    { &hf_cast_layout,
      { "Layout", "cast.layout",
	FT_UINT32, BASE_DEC, VALS(cast_Layouts), 0x0,
	"Layout",
	HFILL }
    },

    { &hf_cast_maxConferences,
      { "MaxConferences", "cast.maxConferences",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"MaxConferences.",
	HFILL }
    },

    { &hf_cast_activeConferenceOnRegistration,
      { "ActiveConferenceOnRegistration", "cast.activeConferenceOnRegistration",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"ActiveConferenceOnRegistration.",
	HFILL }
    },

    { &hf_cast_transmitOrReceive,
      { "TransmitOrReceive", "cast.transmitOrReceive",
	FT_UINT32, BASE_DEC, VALS(cast_transmitOrReceive), 0x0,
	"TransmitOrReceive",
	HFILL }
    },

    { &hf_cast_levelPreferenceCount,
      { "LevelPreferenceCount", "cast.levelPreferenceCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"LevelPreferenceCount.",
	HFILL }
    },

    { &hf_cast_transmitPreference,
      { "TransmitPreference", "cast.transmitPreference",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"TransmitPreference.",
	HFILL }
    },

    { &hf_cast_format,
      { "Format", "cast.format",
	FT_UINT32, BASE_DEC, VALS(cast_formatTypes), 0x0,
	"Format.",
	HFILL }
    },

    { &hf_cast_maxBitRate,
      { "MaxBitRate", "cast.maxBitRate",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"MaxBitRate.",
	HFILL }
    },

    { &hf_cast_minBitRate,
      { "MinBitRate", "cast.minBitRate",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"MinBitRate.",
	HFILL }
    },

    { &hf_cast_MPI,
      { "MPI", "cast.MPI",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"MPI.",
	HFILL }
    },

    { &hf_cast_serviceNumber,
      { "ServiceNumber", "cast.serviceNumber",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"ServiceNumber.",
	HFILL }
    },

    { &hf_cast_temporalSpatialTradeOffCapability,
      { "TemporalSpatialTradeOffCapability", "cast.temporalSpatialTradeOffCapability",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"TemporalSpatialTradeOffCapability.",
	HFILL }
    },

    { &hf_cast_stillImageTransmission,
      { "StillImageTransmission", "cast.stillImageTransmission",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"StillImageTransmission.",
	HFILL }
    },

    { &hf_cast_h263_capability_bitfield,
      { "H263_capability_bitfield", "cast.h263_capability_bitfield",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"H263_capability_bitfield.",
	HFILL }
    },

    { &hf_cast_annexNandWFutureUse,
      { "AnnexNandWFutureUse", "cast.annexNandWFutureUse",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"AnnexNandWFutureUse.",
	HFILL }
    },

    { &hf_cast_modelNumber,
      { "ModelNumber", "cast.modelNumber",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"ModelNumber.",
	HFILL }
    },

    { &hf_cast_bandwidth,
      { "Bandwidth", "cast.bandwidth",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Bandwidth.",
	HFILL }
    },

    { &hf_cast_protocolDependentData,
      { "ProtocolDependentData", "cast.protocolDependentData",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"ProtocolDependentData.",
	HFILL }
    },

    { &hf_cast_DSCPValue,
      { "DSCPValue", "cast.DSCPValue",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"DSCPValue.",
	HFILL }
    },

    { &hf_cast_serviceNum,
      { "ServiceNum", "cast.serviceNum",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"ServiceNum.",
	HFILL }
    },

    { &hf_cast_precedenceValue,
      { "Precedence", "cast.precedenceValue",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Precedence value",
	HFILL }
    },

    { &hf_cast_maxStreams,
      { "MaxStreams", "cast.maxStreams",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"32 bit unsigned integer indicating the maximum number of simultansous RTP duplex streams that the client can handle.",
	HFILL }
    },

    { &hf_cast_millisecondPacketSize,
      { "MS/Packet", "cast.millisecondPacketSize",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The number of milliseconds of conversation in each packet",
	HFILL }
    },

    { &hf_cast_echoCancelType,
      { "Echo Cancel Type", "cast.echoCancelType",
	FT_UINT32, BASE_DEC, VALS(cast_echoCancelTypes), 0x0,
	"Is echo cancelling enabled or not",
	HFILL }
    },

    { &hf_cast_g723BitRate,
      { "G723 BitRate", "cast.g723BitRate",
	FT_UINT32, BASE_DEC, VALS(cast_g723BitRates), 0x0,
	"The G723 bit rate for this stream/JUNK if not g723 stream",
	HFILL }
    },

    { &hf_cast_pictureFormatCount,
      { "PictureFormatCount", "cast.pictureFormatCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"PictureFormatCount.",
	HFILL }
    },

    { &hf_cast_confServiceNum,
      { "ConfServiceNum", "cast.confServiceNum",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"ConfServiceNum.",
	HFILL }
    },

    { &hf_cast_miscCommandType,
      { "MiscCommandType", "cast.miscCommandType",
	FT_UINT32, BASE_DEC, VALS(cast_miscCommandType), 0x0,
	"MiscCommandType",
	HFILL }
    },

    { &hf_cast_temporalSpatialTradeOff,
      { "TemporalSpatialTradeOff", "cast.temporalSpatialTradeOff",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"TemporalSpatialTradeOff.",
	HFILL }
    },

    { &hf_cast_firstGOB,
      { "FirstGOB", "cast.firstGOB",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"FirstGOB.",
	HFILL }
    },

    { &hf_cast_numberOfGOBs,
      { "NumberOfGOBs", "cast.numberOfGOBs",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"NumberOfGOBs.",
	HFILL }
    },

    { &hf_cast_firstMB,
      { "FirstMB", "cast.firstMB",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"FirstMB.",
	HFILL }
    },

    { &hf_cast_numberOfMBs,
      { "NumberOfMBs", "cast.numberOfMBs",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"NumberOfMBs.",
	HFILL }
    },

    { &hf_cast_pictureNumber,
      { "PictureNumber", "cast.pictureNumber",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"PictureNumber.",
	HFILL }
    },

    { &hf_cast_longTermPictureIndex,
      { "LongTermPictureIndex", "cast.longTermPictureIndex",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"LongTermPictureIndex.",
	HFILL }
    },

    { &hf_cast_recoveryReferencePictureCount,
      { "RecoveryReferencePictureCount", "cast.recoveryReferencePictureCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"RecoveryReferencePictureCount.",
	HFILL }
    },

    { &hf_cast_calledParty,
      { "CalledParty", "cast.calledParty",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The number called.",
	HFILL }
    },

    { &hf_cast_privacy,
      { "Privacy", "cast.privacy",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Privacy.",
	HFILL }
    },

    { &hf_cast_precedenceLv,
      { "PrecedenceLv", "cast.precedenceLv",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Precedence Level.",
	HFILL }
    },

    { &hf_cast_precedenceDm,
      { "PrecedenceDm", "cast.precedenceDm",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Precedence Domain.",
	HFILL }
    },

    { &hf_cast_callState,
      { "CallState", "cast.callState",
	FT_UINT32, BASE_DEC, VALS(cast_callStateTypes), 0x0,
	"CallState.",
	HFILL }
    },

    { &hf_cast_callingPartyName,
      { "Calling Party Name", "cast.callingPartyName",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The passed name of the calling party.",
	HFILL }
    },

    { &hf_cast_callingParty,
      { "Calling Party", "cast.callingPartyName",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The passed number of the calling party.",
	HFILL }
    },

    { &hf_cast_calledPartyName,
      { "Called Party Name", "cast.calledPartyName",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The name of the party we are calling.",
	HFILL }
    },

    { &hf_cast_callType,
      { "Call Type", "cast.callType",
	FT_UINT32, BASE_DEC, VALS(cast_callTypes), 0x0,
	"What type of call, in/out/etc",
	HFILL }
    },

    { &hf_cast_originalCalledPartyName,
      { "Original Called Party Name", "cast.originalCalledPartyName",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"name of the original person who placed the call.",
	HFILL }
    },

    { &hf_cast_originalCalledParty,
      { "Original Called Party", "cast.originalCalledParty",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The number of the original calling party.",
	HFILL }
    },

    { &hf_cast_lastRedirectingPartyName,
      { "LastRedirectingPartyName", "cast.lastRedirectingPartyName",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LastRedirectingPartyName.",
	HFILL }
    },

    { &hf_cast_lastRedirectingParty,
      { "LastRedirectingParty", "cast.lastRedirectingParty",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LastRedirectingParty.",
	HFILL }
    },

    { &hf_cast_cgpnVoiceMailbox,
      { "CgpnVoiceMailbox", "cast.cgpnVoiceMailbox",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"CgpnVoiceMailbox.",
	HFILL }
    },

    { &hf_cast_cdpnVoiceMailbox,
      { "CdpnVoiceMailbox", "cast.cdpnVoiceMailbox",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"CdpnVoiceMailbox.",
	HFILL }
    },

    { &hf_cast_originalCdpnVoiceMailbox,
      { "OriginalCdpnVoiceMailbox", "cast.originalCdpnVoiceMailbox",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"OriginalCdpnVoiceMailbox.",
	HFILL }
    },

    { &hf_cast_lastRedirectingVoiceMailbox,
      { "LastRedirectingVoiceMailbox", "cast.lastRedirectingVoiceMailbox",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LastRedirectingVoiceMailbox.",
	HFILL }
    },

    { &hf_cast_originalCdpnRedirectReason,
      { "OriginalCdpnRedirectReason", "cast.originalCdpnRedirectReason",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"OriginalCdpnRedirectReason.",
	HFILL }
    },

    { &hf_cast_lastRedirectingReason,
      { "LastRedirectingReason", "cast.lastRedirectingReason",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"LastRedirectingReason.",
	HFILL }
    },

    { &hf_cast_callInstance,
      { "CallInstance", "cast.callInstance",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"CallInstance.",
	HFILL }
    },

    { &hf_cast_callSecurityStatus,
      { "CallSecurityStatus", "cast.callSecurityStatus",
	FT_UINT32, BASE_DEC, VALS(cast_callSecurityStatusTypes), 0x0,
	"CallSecurityStatus.",
	HFILL }
    },

    { &hf_cast_directoryNumber,
      { "Directory Number", "cast.directoryNumber",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The number we are reporting statistics for.",
	HFILL }
    },

    { &hf_cast_requestorIpAddress,
      { "RequestorIpAddress", "cast.requestorIpAddress",
	FT_IPv4, BASE_NONE, NULL, 0x0,
	"RequestorIpAddress",
	HFILL }
    },

    { &hf_cast_stationIpAddress,
      { "StationIpAddress", "cast.stationIpAddress",
	FT_IPv4, BASE_NONE, NULL, 0x0,
	"StationIpAddress",
	HFILL }
    },

    { &hf_cast_stationFriendlyName,
      { "StationFriendlyName", "cast.stationFriendlyName",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"StationFriendlyName.",
	HFILL }
    },

    { &hf_cast_stationGUID,
      { "stationGUID", "cast.stationGUID",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"stationGUID.",
	HFILL }
    },

    { &hf_cast_audio,
      { "AudioCodec", "cast.audio",
	FT_UINT32, BASE_DEC, VALS(audioCodecTypes), 0x0,
	"The audio codec that is in use.",
	HFILL }
    },

    { &hf_cast_bitRate,
      { "BitRate", "skinny.bitRate",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"BitRate.",
	HFILL }
    },

  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_cast,
    &ett_cast_tree,
  };

  module_t *cast_module;

  /* Register the protocol name and description */
  proto_cast = proto_register_protocol("Cast Client Control Protocol",
					 "CAST", "cast");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_cast, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  cast_module = prefs_register_protocol(proto_cast, NULL);
  prefs_register_bool_preference(cast_module, "reassembly", /*"desegment",*/
    "Reassemble CAST messages spanning multiple TCP segments",
    "Whether the CAST dissector should reassemble messages spanning multiple TCP segments."
    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &cast_desegment);
}

void
proto_reg_handoff_cast(void)
{
  dissector_handle_t cast_handle;

  data_handle = find_dissector("data");
  cast_handle = create_dissector_handle(dissect_cast, proto_cast);
  dissector_add("tcp.port", TCP_PORT_CAST, cast_handle);
}

