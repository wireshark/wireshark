/* packet-skinny.c
 *
 * Dissector for the Skinny Client Control Protocol
 *   (The "D-Channel"-Protocol for Cisco Systems' IP-Phones)
 * Copyright 2001, Joerg Mayer (email: see AUTHORS file)
 *
 * Further decode work by pee@erkkila.org 
 *
 * This file is based on packet-aim.c, which is
 * Copyright 2000, Ralf Hoelzer <ralf@well.com>
 *
 * $Id: packet-skinny.c,v 1.12 2002/03/19 11:26:23 guy Exp $
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
#include "prefs.h"

#include "packet-frame.h"

#define TCP_PORT_SKINNY 2000

#define SKINNY_SOFTKEY0  0x01
#define SKINNY_SOFTKEY1  0x02
#define SKINNY_SOFTKEY2  0x04
#define SKINNY_SOFTKEY3  0x08
#define SKINNY_SOFTKEY4  0x10
#define SKINNY_SOFTKEY5  0x20
#define SKINNY_SOFTKEY6  0x40
#define SKINNY_SOFTKEY7  0x80
#define SKINNY_SOFTKEY8  0x100
#define SKINNY_SOFTKEY9  0x200
#define SKINNY_SOFTKEY10 0x400
#define SKINNY_SOFTKEY11 0x800
#define SKINNY_SOFTKEY12 0x1000
#define SKINNY_SOFTKEY13 0x2000
#define SKINNY_SOFTKEY14 0x4000
#define SKINNY_SOFTKEY15 0x8000

/* KeyMap Show/No Show */
static const true_false_string softKeyMapValues = {
  "Show",
  "Do Not Show"
};


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

  /* Station -> Callmanager */
  {0x0000, "KeepAliveMessage"},
  {0x0001, "RegisterMessage"},
  {0x0002, "IpPortMessage"},
  {0x0003, "KeypadButtonMessage"},
  {0x0004, "EnblocCallMessage"},
  {0x0005, "StimulusMessage"},
  {0x0006, "OffHookMessage"},
  {0x0007, "OnHookMessage"},
  {0x0008, "HookFlashMessage"},
  {0x0009, "ForwardStatReqMessage"},
  {0x000A, "SpeedDialStatReqMessage"},
  {0x000B, "LineStatReqMessage"},
  {0x000C, "ConfigStatReqMessage"},
  {0x000D, "TimeDateReqMessage"},
  {0x000E, "ButtonTemplateReqMessage"},
  {0x000F, "VersionReqMessage"},
  {0x0010, "CapabilitiesResMessage"},
  {0x0011, "MediaPortListMessage"},
  {0x0012, "ServerReqMessage"},
  {0x0020, "AlarmMessage"},
  {0x0021, "MulticastMediaReceptionAck"},
  {0x0022, "OpenReceiveChannelAck"},
  {0x0023, "ConnectionStatisticsRes"},
  {0x0024, "OffHookWithCgpnMessage"},
  {0x0025, "SoftKeySetReqMessage"},
  {0x0026, "SoftKeyEventMessage"},
  {0x0027, "UnregisterMessage"},
  {0x0028, "SoftKeyTemplateReqMessage"},
  {0x0029, "RegisterTokenReq"},
  {0x002B, "unknownClientMessage1"},
  {0x002D, "unknownClientMessage2"},
  
  /* Callmanager -> Station */
  /* 0x0000, 0x0003? */
  {0x0081, "RegisterAckMessage"},
  {0x0082, "StartToneMessage"},
  {0x0083, "StopToneMessage"},
  {0x0085, "SetRingerMessage"},
  {0x0086, "SetLampMessage"},
  {0x0087, "SetHkFDetectMessage"},
  {0x0088, "SetSpeakerModeMessage"},
  {0x0089, "SetMicroModeMessage"},
  {0x008A, "StartMediaTransmission"},
  {0x008B, "StopMediaTransmission"},
  {0x008C, "StartMediaReception"},
  {0x008D, "StopMediaReception"},
  {0x008F, "CallInfoMessage"},
  {0x0090, "ForwardStatMessage"},
  {0x0091, "SpeedDialStatMessage"},
  {0x0092, "LineStatMessage"},
  {0x0093, "ConfigStatMessage"},
  {0x0094, "DefineTimeDate"},
  {0x0095, "StartSessionTransmission"},
  {0x0096, "StopSessionTransmission"},
  {0x0097, "ButtonTemplateMessage"},
  {0x0098, "VersionMessage"},
  {0x0099, "DisplayTextMessage"},
  {0x009A, "ClearDisplay"},
  {0x009B, "CapabilitiesReqMessage"},
  {0x009C, "EnunciatorCommandMessage"},
  {0x009D, "RegisterRejectMessage"},
  {0x009E, "ServerResMessage"},
  {0x009F, "Reset"},
  {0x0100, "KeepAliveAckMessage"},
  {0x0101, "StartMulticastMediaReception"},
  {0x0102, "StartMulticastMediaTransmission"},
  {0x0103, "StopMulticastMediaReception"},
  {0x0104, "StopMulticastMediaTransmission"},
  {0x0105, "OpenReceiveChannel"},
  {0x0106, "CloseReceiveChannel"},
  {0x0107, "ConnectionStatisticsReq"},
  {0x0108, "SoftKeyTemplateResMessage"},
  {0x0109, "SoftKeySetResMessage"},
  {0x0110, "SelectSoftKeysMessage"},
  {0x0111, "CallStateMessage"},
  {0x0112, "DisplayPromptStatusMessage"},
  {0x0113, "ClearPromptStatusMessage"},
  {0x0114, "DisplayNotifyMessage"},
  {0x0115, "ClearNotifyMessage"},
  {0x0116, "ActivateCallPlaneMessage"},
  {0x0117, "DeactivateCallPlaneMessage"},
  {0x0118, "UnregisterAckMessage"},
  {0x0119, "BackSpaceReqMessage"},
  {0x011A, "RegisterTokenAck"},
  {0x011B, "RegisterTokenReject"},
  {0x011D, "unknownForwardMessage1"},

  {0     , NULL}	/* terminator */
};

/*
 * Device type to text conversion table
 */
static const value_string  deviceTypes[] = {
  {1  , "DeviceStation30SPplus"},
  {2  , "DeviceStation12SPplus"},
  {3  , "DeviceStation12SP"},
  {4  , "DeviceStation12"},
  {5  , "DeviceStation30VIP"},
  {6  , "DeviceStationTelecaster"},
  {7  , "DeviceStationTelecasterMgr"},
  {8  , "DeviceStationTelecasterBus"},
  {20 , "DeviceVirtual30SPplus"},
  {21 , "DeviceStationPhoneApplication"},
  {30 , "DeviceAnalogAccess"},
  {40 , "DeviceDigitalAccessPRI"},
  {41 , "DeviceDigitalAccessT1"},
  {42 , "DeviceDigitalAccessTitan2"},
  {47 , "DeviceAnalogAccessElvis"},
  {49 , "DeviceDigitalAccessLennon"},
  {50 , "DeviceConferenceBridge"},
  {51 , "DeviceConferenceBridgeYoko"},
  {60 , "DeviceH225"},
  {61 , "DeviceH323Phone"},
  {62 , "DeviceH323Trunk"},
  {70 , "DeviceMusicOnHold"},
  {71 , "DevicePilot"},
  {72 , "DeviceTapiPort"},
  {73 , "DeviceTapiRoutePoint"},
  {80 , "DeviceVoiceInBox"},
  {81 , "DeviceVoiceInboxAdmin"},
  {82 , "DeviceLineAnnunciator"},
  {90 , "DeviceRouteList"},
  {100, "DeviceLoadSimulator"},
  {110, "DeviceMediaTerminationPoint"},
  {111, "DeviceMediaTerminationPointYoko"},
  {120, "DeviceMGCPStation"},
  {121, "DeviceMGCPTrunk"},
  {122, "DeviceRASProxy"},
  {255, "DeviceNotDefined"},
  { 0    , NULL}
};

/*
 * keypad button -> text conversion
 */
static const value_string keypadButtons[] = {
  {0x0   , "Zero"},
  {0x1   , "One"},
  {0x2   , "Two"},
  {0x3   , "Three"},
  {0x4   , "Four"},
  {0x5   , "Five"},
  {0x6   , "Six"},
  {0x7   , "Seven"},
  {0x8   , "Eight"},
  {0x9   , "Nine"},
  {0xa   , "A"},
  {0xb   , "B"},
  {0xc   , "C"},
  {0xd   , "D"},
  {0xe   , "Star"},
  {0xf   , "Pound"},
  {0     , NULL}
};

static const value_string deviceStimuli[] = {
  {1    , "SsLastNumberRedial"},
  {2    , "SsSpeedDial"},
  {3    , "SsHold"},
  {4    , "SsTransfer"},
  {5    , "SsForwardAll"},
  {6    , "SsForwardBusy"},
  {7    , "SsForwardNoAnswer"},
  {8    , "SsDisplay"},
  {9    , "SsLine"},
  {0xa  , "SsT120Chat"},
  {0xb  , "SsT120Whiteboard"},
  {0xc  , "SsT120ApplicationSharing"},
  {0xd  , "SsT120FileTransfer"},
  {0xe  , "SsVideo"},
  {0xf  , "SsVoiceMail"},
  {0x11 , "SsAutoAnswer"},
  {0x21 , "SsGenericAppB1"},
  {0x22 , "SsGenericAppB2"},
  {0x23 , "SsGenericAppB3"},
  {0x24 , "SsGenericAppB4"},
  {0x25 , "SsGenericAppB5"},
  {0x7b , "SsMeetMeConference"},
  {0x7d , "SsConference=0x7d"},
  {0x7e , "SsCallPark=0x7e"},
  {0x7f , "SsCallPickup"},
  {0x80 , "SsGroupCallPickup=80"},
  {0,NULL}
};


/* Note i'm only using 7 later on cuz i'm lazy ;) */
#define DeviceMaxCapabilities 18 /* max capabilities allowed in Cap response message */

static const value_string mediaPayloads[] = {
  {1   , "Media_Payload_NonStandard"},
  {2   , "Media_Payload_G711Alaw64k"},
  {3   , "Media_Payload_G711Alaw56k"},
  {4   , "Media_Payload_G711Ulaw64k"},
  {5   , "Media_Payload_G711Ulaw56k"},
  {6   , "Media_Payload_G722_64k"},
  {7   , "Media_Payload_G722_56k"},
  {8   , "Media_Payload_G722_48k"},
  {9   , "Media_Payload_G7231"},
  {10  , "Media_Payload_G728"},
  {11  , "Media_Payload_G729"},
  {12  , "Media_Payload_G729AnnexA"},
  {13  , "Media_Payload_Is11172AudioCap"},
  {14  , "Media_Payload_Is13818AudioCap"},
  {15  , "Media_Payload_G729AnnexB"},
  {16  , "Media_Payload_G729AnnexAwAnnexB"},
  {32  , "Media_Payload_Data64"},
  {33  , "Media_Payload_Data56"},
  {80  , "Media_Payload_GSM"},
  {81  , "Media_Payload_ActiveVoice"},
  {82  , "Media_Payload_G726_32K"},
  {83  , "Media_Payload_G726_24K"},
  {84  , "Media_Payload_G726_16K"},
  {85  , "Media_Payload_G729_B"},
  {86  , "Media_Payload_G729_B_LOW_COMPLEXITY"},
  {0  , NULL}
};

static const value_string alarmSeverities[] = {
  {0   , "severityCritical"},
  {7   , "severityMajor"},
  {8   , "severityMinor"},
  {1   , "severityWarning"},
  {10  , "severityMarginal"},
  {4   , "severityUnknown"},
  {2   , "severityInformational"},
  {20  , "severityTraceInfo"},
  {0  , NULL}
};

static const value_string multicastMediaReceptionStatus[] = {
  {0  , "mmrOk"},
  {1  , "mmrError"},
  {0  , NULL}
};

static const value_string openReceiveChanStatus[] = {
  {0   , "orcOk"},
  {1   , "orcError"},
  {0   , NULL}
};


static const value_string statsProcessingTypes[] = {
  {0   , "clearStats"},
  {1   , "doNotClearStats"},
  {0   , NULL}
};

#define SkMaxSoftKeyCount 18 /* this value should be the same as the max soft key value */
static const value_string softKeyEvents[] = {
  {1   , "SkRedial"},
  {2   , "SkNewCall"},
  {3   , "SkHold"},
  {4   , "SkTrnsfer"},
  {5   , "SkCFwdAll"},
  {6   , "SkCFwdBusy"},
  {7   , "SkCFwdNoAnswer"},
  {8   , "SkBackSpace"},
  {9   , "SkEndCall"},
  {10  , "SkResume"},
  {11  , "SkAnswer"},
  {12  , "SkInfo"},
  {13  , "SkConfrn"},
  {14  , "SkPark"},
  {15  , "SkJoin"},
  {16  , "SkMeetMeConfrn"},
  {17  , "SkCallPickUp"},
  {18  , "SkGrpCallPickUp"},
  {0   , NULL}
};

/* Define info index for each softkey event for Telecaster station. */
static const value_string softKeyIndexes[] = {
  {301  , "SkRedialInfoIndex"},
  {302  , "SkNewCallInfoIndex"},
  {303  , "SkHoldInfoIndex"},
  {304  , "SkTrnsferInfoIndex"},
  {305  , "SkCFwdAllInfoIndex"},
  {306  , "SkCFwdBusyInfoIndex"},     /* not used yet */
  {307  , "SkCFwdNoAnswerInfoIndex"}, /* not used yet */
  {308  , "SkBackSpaceInfoIndex"},
  {309  , "SkEndCallInfoIndex"},
  {310  , "SkResumeInfoIndex"},
  {311  , "SkAnswerInfoIndex"},
  {312  , "SkInfoInfoIndex"},
  {313  , "SkConfrnInfoIndex"},
  {314  , "SkParkInfoIndex"},
  {315  , "SkJoinInfoIndex"},
  {316  , "SkMeetMeConfrnInfoIndex"},
  {317  , "SkCallPickUpInfoIndex"},
  {318  , "SkGrpCallPickUpInfoIndex"},
  {0   , NULL}
};


static const value_string buttonDefinitions[] = {
  {1    , "BtLastNumberRedial"},
  {2    , "BtSpeedDial"},
  {3    , "BtHold"},
  {4    , "BtTransfer"},
  {5    , "BtForwardAll"},
  {6    , "BtForwardBusy"},
  {7    , "BtForwardNoAnswer"},
  {8    , "BtDisplay"},
  {9    , "BtLine"},
  {0xa  , "BtT120Chat"},
  {0xb  , "BtT120Whiteboard"},
  {0xc  , "BtT120ApplicationSharing"},
  {0xd  , "BtT120FileTransfer"},
  {0xe  , "BtVideo"},
  {0x10 , "BtAnswerRelease"},
  {0xf0 , "BtKeypad"},
  {0xfd , "BtAEC"},
  {0xff , "BtUndefined"},
  {0   , NULL}
};

#define StationTotalSoftKeySets 10 /* total number of the soft key sets */
static const value_string keySetNames[] = {
  {0   , "OnHook"},
  {1   , "Connected"},
  {2   , "OnHold"},
  {3   , "RingIn"},
  {4   , "OffHook"},
  {5   , "Connected with transfer"},
  {6   , "Digits after dialing first digit"},
  {7   , "Connected with conference"},
  {8   , "RingOut"},
  {9   , "OffHook with features"},
  {0   , NULL}
};

/* Define soft key labels for the Telecaster station */
static const value_string softKeyLabel[] = { 
  {0   , "undefined"},
  {1   , "Redial"},
  {2   , "NewCall"},
  {3   , "Hold"},
  {4   , "Trnsfer"},
  {5   , "CFwdAll"},
  {6   , "CFwdBusy"},
  {7   , "CFwdNoAnswer"},
  {8   , "<<"},
  {9   , "EndCall"},
  {10  , "Resume"},
  {11  , "Answer"},
  {12  , "Info"},
  {13  , "Confrn"},
  {14  , "Park"},
  {15  , "Join"},
  {16  , "MeetMe"},
  {17  , "PickUp"},
  {18  , "GPickUp"},
  {0   , NULL}
}; 


/* 
 * define lamp modes; 
 * lamp cadence is defined as follows 
 * Wink (on 80%) = 448msec on / 64msec off 
 * Flash (fast flash) = 32msec on / 32msec off 
 * Blink (on 50%) = 512msec on / 512msec off 
 * On (on steady) 
 */
static const value_string stationLampModes[] = {
  {0   , "Undefined"},
  {0x1 , "LampOff"},
  {0x2 , "LampOn"},
  {0x3 , "LampWink"},
  {0x4 , "LampFlash"},
  {0x5 , "LampBlink"},
  {0   , NULL}
}; 


# define NUM_MEDIA_PAYLOADTYPES 19 
static char *Media_PayloadList[] = { 
  "Undefined", 
  "Media_Payload_NonStandard", 
  "Media_Payload_G711Alaw64k", 
  "Media_Payload_G711Alaw56k", 
  "Media_Payload_G711Ulaw64k", 
  "Media_Payload_G711Ulaw56k", 
  "Media_Payload_G722_64k", 
  "Media_Payload_G722_56k", 
  "Media_Payload_G722_48k", 
  "Media_Payload_G7231", 
  "Media_Payload_G728", 
  "Media_Payload_G729", 
  "Media_Payload_G729AnnexA", 
  "Media_Payload_Is11172AudioCap", 
  "Media_Payload_Is13818AudioCap", 
  "Media_Payload_G729AnnexB", 
  "Media_Payload_G729AnnexAwAnnexB", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Media_Payload_Data64", 
  "Media_Payload_Data56", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Undefined", 
  "Media_Payload_GSM", 
  "Media_Payload_ActiveVoice", 
  "Media_Payload_G726_32K", 
  "Media_Payload_G726_24K", 
  "Media_Payload_G726_16K", 
  "Media_Payload_G729_B", 
  "Media_Payload_G729_B_LOW_COMPLEXITY", 
  "Undefined", 
  "Undefined" 
}; 

#define StationMaxDirnumSize 24         /* max size of calling or called party dirnum  */
#define StationMaxNameSize 40           /* max size of calling party's name  */
#define StationMaxDeviceNameSize 16     /* max size of station's IP name  */
#define StationMaxSpeedDials 10         /* max number of speed dial numbers allowed on a station */
#define StationMaxVersionSize 16        /* max chars in version string  */
#define StationMaxButtonTemplateSize 42 /* max button template size */ 
#define StationMaxDisplayTextSize 33    /* max text size in DisplayText message */
#define StationMaxPorts 10              /* max number of ports on one device */
#define StationDateTemplateSize 6       /* date template in the form M/D/Y, D/M/Y, ... */
#define StationMaxServerNameSize 48     /* max size of server name */
#define StationMaxServers 5             /* max servers */
#define StationMaxDeviceDirnums 1024    /* max dir numbers per SCM device */
#define StationMaxDirnums 64            /* max dir numbers per physical station (also used in db request msg); */
#define StationMaxSoftKeyLabelSize 16   /* max label size in the message */
#define StationMaxSoftKeyDefinition 32       /* max number of soft key definition in the message */
#define StationMaxSoftKeySetDefinition 16    /* max number of soft key set definition in the message */
#define StationMaxSoftKeyIndex 16            /* max number of soft key indices in a station soft key set */
#define StationMaxDisplayPromptStatusSize 32 /* max status text size in the display status message */
#define StationMaxDisplayNotifySize 32       /* max prompt text size in the display prompt message */

static void dissect_skinny(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Initialize the protocol and registered fields */
static int proto_skinny          = -1;
static int hf_skinny_data_length = -1;
static int hf_skinny_reserved    = -1;
static int hf_skinny_messageid   = -1;
static int hf_skinny_deviceName  = -1;
static int hf_skinny_stationUserId = -1;
static int hf_skinny_stationInstance = -1;
static int hf_skinny_deviceType = -1;
static int hf_skinny_maxStreams = -1;
static int hf_skinny_stationIpPort = -1;
static int hf_skinny_stationKeypadButton = -1;
static int hf_skinny_calledParty = -1;
static int hf_skinny_stimulus = -1;
static int hf_skinny_stimulusInstance = -1;
static int hf_skinny_lineNumber = -1;
static int hf_skinny_speedDialNumber = -1;
static int hf_skinny_capCount = -1;
static int hf_skinny_payloadCapability = -1;
static int hf_skinny_maxFramesPerPacket = -1;
static int hf_skinny_alarmSeverity = -1;
static int hf_skinny_alarmParam1 = -1;
static int hf_skinny_alarmParam2 = -1;
static int hf_skinny_receptionStatus = -1;
static int hf_skinny_passThruPartyID = -1;
static int hf_skinny_ORCStatus = -1;
static int hf_skinny_ipAddress = -1;
static int hf_skinny_portNumber = -1;
static int hf_skinny_statsProcessingType = -1;
static int hf_skinny_callIdentifier = -1;
static int hf_skinny_packetsSent = -1;
static int hf_skinny_octetsSent  = -1;
static int hf_skinny_packetsRecv = -1;
static int hf_skinny_octetsRecv  = -1;
static int hf_skinny_packetsLost = -1;
static int hf_skinny_latency     = -1;
static int hf_skinny_jitter      = -1;
static int hf_skinny_directoryNumber = -1;
static int hf_skinny_softKeyEvent = -1;
static int hf_skinny_lineInstance = -1;
static int hf_skinny_keepAliveInterval = -1;
static int hf_skinny_dateTemplate = -1;
static int hf_skinny_secondaryKeepAliveInterval = -1;
static int hf_skinny_buttonOffset = -1;
static int hf_skinny_buttonCount = -1;
static int hf_skinny_totalButtonCount = -1;
static int hf_skinny_buttonInstanceNumber = -1;
static int hf_skinny_buttonDefinition = -1;
static int hf_skinny_softKeyOffset = -1;
static int hf_skinny_softKeyCount = -1;
static int hf_skinny_totalSoftKeyCount = -1;
static int hf_skinny_softKeyLabel = -1;
static int hf_skinny_softKeySetOffset = -1;
static int hf_skinny_softKeySetCount = -1;
static int hf_skinny_totalSoftKeySetCount = -1;
static int hf_skinny_softKeyTemplateIndex = -1;
static int hf_skinny_softKeyInfoIndex = -1;
static int hf_skinny_softKeySetDescription = -1;
static int hf_skinny_softKeyMap = -1;
static int hf_skinny_softKey0 = -1;
static int hf_skinny_softKey1 = -1;
static int hf_skinny_softKey2 = -1;
static int hf_skinny_softKey3 = -1;
static int hf_skinny_softKey4 = -1;
static int hf_skinny_softKey5 = -1;
static int hf_skinny_softKey6 = -1;
static int hf_skinny_softKey7 = -1;
static int hf_skinny_softKey8 = -1;
static int hf_skinny_softKey9 = -1;
static int hf_skinny_softKey10 = -1;
static int hf_skinny_softKey11 = -1;
static int hf_skinny_softKey12 = -1;
static int hf_skinny_softKey13 = -1;
static int hf_skinny_softKey14 = -1;
static int hf_skinny_softKey15 = -1;
static int hf_skinny_lampMode = -1;
static int hf_skinny_messageTimeOutValue = -1;
static int hf_skinny_displayMessage = -1;
static int hf_skinny_lineDirNumber = -1;
static int hf_skinny_lineFullyQualifiedDisplayName = -1;
static int hf_skinny_speedDialDirNumber = -1;
static int hf_skinny_speedDialDisplayName = -1;
static int hf_skinny_dateYear = -1;
static int hf_skinny_dateMonth = -1;
static int hf_skinny_dayOfWeek = -1;
static int hf_skinny_dateDay = -1;
static int hf_skinny_dateHour = -1;
static int hf_skinny_dateMinute = -1;
static int hf_skinny_dateSeconds = -1;
static int hf_skinny_dateMilliseconds = -1;
static int hf_skinny_timeStamp = -1;


static int hf_skinny_extension   = -1;
static int hf_skinny_unknown = -1;
static int hf_skinny_ipDest = -1;
static int hf_skinny_ipSrc = -1;
static int hf_skinny_destPort = -1;
static int hf_skinny_srcPort = -1;
static int hf_skinny_softKeyNumber = -1;
static int hf_skinny_line = -1;
static int hf_skinny_dialedDigit = -1;

/* Initialize the subtree pointers */
static gint ett_skinny          = -1;
static gint ett_skinny_softKeyMap = -1;

/* desegmentation of SCCP */
static gboolean skinny_desegment = TRUE;

static dissector_handle_t data_handle;

/* Dissect a single SCCP PDU */
static void dissect_skinny_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  int offset = 0;

  /* Header fields */
  guint32 hdr_data_length;
  guint32 hdr_reserved;
  guint32 data_messageid;
  gchar   *messageid_str;
  /*  guint32 data_size; */

  guint32 unknown1 = 0;
  guint32 unknown2 = 0;
  guint32 unknown3 = 0;
  guint32 unknown4 = 0;
  guint32 unknown5 = 0;
  guint32 unknown6 = 0;
  guint32 unknown7 = 0;
  guint32 unknown8 = 0;
  guint32 unknown9 = 0;
  guint32 unknown10 = 0;

  int extensionLength = 10;
  int displayLength   = 100;
  char extension[extensionLength];
  char displayMessage[displayLength];
  guint i = 0;
  int j = 0;

  guint32 capCount;
  guint32 softKeyCount;
  guint32 softKeySetCount;
  guint16 validKeyMask;
  
  /* Set up structures we will need to add the protocol subtree and manage it */
  proto_item *ti;
  proto_tree *skinny_tree = NULL;
  
  proto_item *skm = NULL;
  proto_item *skm_tree = NULL;

  hdr_data_length = tvb_get_letohl(tvb, offset);
  hdr_reserved    = tvb_get_letohl(tvb, offset+4);
  data_messageid  = tvb_get_letohl(tvb, offset+8);

  /* In the interest of speed, if "tree" is NULL, don't do any work not
   * necessary to generate protocol tree items. */
  if (tree) {
    ti = proto_tree_add_item(tree, proto_skinny, tvb, offset, hdr_data_length+8, FALSE); 
    skinny_tree = proto_item_add_subtree(ti, ett_skinny);
    proto_tree_add_uint(skinny_tree, hf_skinny_data_length, tvb, offset, 4, hdr_data_length);  
    proto_tree_add_uint(skinny_tree, hf_skinny_reserved, tvb, offset+4, 4, hdr_reserved);
  }

  messageid_str = val_to_str(data_messageid, message_id, "0x%08X (Unknown)");

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_str(pinfo->cinfo, COL_INFO, messageid_str);
  }

  if (tree) {
    proto_tree_add_uint(skinny_tree, hf_skinny_messageid, tvb,offset+8, 4, data_messageid );
  }

  if (tree) {
    switch(data_messageid) {

    /* cases that do not need to be decoded */
    case 0x0 :    /* keepAlive */
      break;

    case 0x6 :    /* offHook */
      break;

    case 0x7 :    /* onHook    */
      break;

    case 0x8 :    /* hookFlash */
      break;
      
    case 0xc :    /* configStateReqMessage */
      break;
      
    case 0xd :    /* timeDateReqMessage */
      break;

    case 0xe :    /* buttoneTemplateReqMessage */
      break;

    case 0xf :    /* stationVersionReqMessage */
      break;
      
    case 0x12 :   /* stationServerReqMessage */
      break;
      
    case 0x25 :   /* softKeySetReqMessage */
      break;

    case 0x27 :   /* unregisterMessage */
      break;

    case 0x28 :   /* softKeyTemplateRequest */
      break;

    case 0x83 :   /* stopTone */
      break;

    case 0x9b :   /* capabilitiesReqMessage */
      break;

    case 0x100 :    /* keepAliveAck */
      break;
	
    /*
     ** cases that need decode
     **
     */

    case 0x1 :   /* register message */
      proto_tree_add_item(skinny_tree, hf_skinny_deviceName, tvb, offset+12, StationMaxDeviceNameSize, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_stationUserId, tvb, offset+28, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_stationInstance, tvb, offset+32, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_ipSrc, tvb, offset+36, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_deviceType, tvb, offset+40, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_maxStreams, tvb, offset+44, 4, TRUE);
      break;

    case 0x2 :  /* ipPortMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_stationIpPort, tvb, offset+12, 2, FALSE);
      break;

    case 0x3 :  /* keyPadButtonMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_stationKeypadButton, tvb, offset+12, 4, TRUE);
      break;

    case 0x4 :  /* stationEnblocCallMessage -- This decode NOT verified*/
      proto_tree_add_item(skinny_tree, hf_skinny_calledParty, tvb, offset+12, StationMaxDirnumSize, TRUE);
      break;
      
    case 0x5 : /* stationStimulusMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_stimulus, tvb, offset+12, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_stimulusInstance, tvb, offset+16, 4, TRUE);
      break;

    case 0x9  : /* stationForwardStatReqMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_lineNumber, tvb, offset+12, 4, TRUE);
      break;
      
    case 0xa :  /* speedDialStatReqMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_speedDialNumber, tvb, offset+12, 4, TRUE);
      break;

    case 0xb :  /* LineStatReqMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_lineNumber, tvb, offset+12, 4, TRUE);
      break;

    case 0x10 :  /* capabilitiesResMessage  - VERIFIED AS IS*/
      /* FIXME -- we are only going to decode the first 7 protocol fields for now cuz that's all it sent me
       * on the phone i was working with. I should probably skip the struct decode and use a more piece
       * type method using the capCount definition to control the decode loop
       *
       * basically changing StationMaxCapabilities definition
       *
       */	
      capCount = tvb_get_letohl(tvb, offset+12);
      proto_tree_add_uint(skinny_tree, hf_skinny_capCount, tvb, offset+12, 4, capCount);
      for (i = 0; i < capCount; i++) {
	proto_tree_add_item(skinny_tree, hf_skinny_payloadCapability, tvb, offset+(i*16)+16, 4, TRUE);
	proto_tree_add_item(skinny_tree, hf_skinny_maxFramesPerPacket, tvb, offset+(i*16)+20, 4, TRUE);
	/* FIXME -- decode the union under here as required, is always 0 on my equipment */
      }
      break;

    case 0x20 :   /* stationAlarmMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_alarmSeverity, tvb, offset+12, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_displayMessage, tvb, offset+16, 80, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_alarmParam1, tvb, offset+96, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_alarmParam2, tvb, offset+100, 4, TRUE);
      break;

    case 0x21 : /* stationMulticastMediaReceptionAck - This decode NOT verified*/
      proto_tree_add_item(skinny_tree, hf_skinny_receptionStatus, tvb, offset+12, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+16, 4, TRUE);
      break;
      
    case 0x22 : /* stationOpenReceiveChannelAck */
      proto_tree_add_item(skinny_tree, hf_skinny_ORCStatus, tvb, offset+12, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_ipAddress, tvb, offset+16, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_portNumber, tvb, offset+20, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+24, 4, TRUE);
      break;	

    case 0x23    :  /* stationConnectionStatisticsRes */
      proto_tree_add_item(skinny_tree, hf_skinny_directoryNumber, tvb, offset+12, StationMaxDirnumSize, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+36, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_statsProcessingType, tvb, offset+40, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_packetsSent, tvb, offset+44, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_octetsSent, tvb, offset+48, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_packetsRecv, tvb, offset+52, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_octetsRecv, tvb, offset+56, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_packetsLost, tvb, offset+60, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_jitter, tvb, offset+64, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_latency, tvb, offset+68, 4, TRUE);
      break;
      
    case 0x26 :  /* softKeyEventMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_softKeyEvent, tvb, offset+12, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_unknown, tvb, offset+16, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+20, 4, TRUE);
      break;

      /*
       *
       * message not in the spec
       *
       */
    case 0x2b :  /* unknownClientMessage1 */
      unknown1 = tvb_get_letohl(tvb, offset+12);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
      break;

    case 0x2d :  /* unknownClientMessage2 */
      unknown1 = tvb_get_letohl(tvb, offset+12);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
      break;

      /* 
       *
       *  Call manager -> client messages start here(ish)
       *
       */
    case 0x81 :  /* registerAck */
      proto_tree_add_item(skinny_tree, hf_skinny_keepAliveInterval, tvb, offset+12, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_dateTemplate, tvb, offset+16, StationDateTemplateSize, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_secondaryKeepAliveInterval, tvb, offset+24, 4, TRUE);
      break;

    case 0x82 :  /* startTone */
      unknown1 = tvb_get_letohl(tvb, offset+12);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
      break;

    case 0x85 : /* setRingerMessage */
      unknown1 = tvb_get_letohl(tvb, offset+12);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
      break;
	
    case 0x86 : /* setLampMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_stimulus, tvb, offset+12, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_stimulusInstance, tvb, offset+16, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_lampMode, tvb, offset+20, 4, TRUE);
      break;

    case 0x88 : /* setSpeakerModeMessage */
      unknown1 = tvb_get_letohl(tvb, offset+12);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
      break;
	
    case 0x8a :
      unknown1  = tvb_get_letohl(tvb, offset+12);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
      unknown2  = tvb_get_letohl(tvb, offset+16);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+16, 4, unknown2);
      proto_tree_add_item(skinny_tree, hf_skinny_ipDest,   tvb, offset+20, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_destPort,tvb, offset+24, 4, TRUE);
      unknown5  = tvb_get_letohl(tvb, offset+28);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+28, 4, unknown5);
      unknown6  = tvb_get_letohl(tvb, offset+32);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+32, 4, unknown6);
      unknown7  = tvb_get_letohl(tvb, offset+36);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+36, 4, unknown7);
      unknown8  = tvb_get_letohl(tvb, offset+40);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+40, 4, unknown8);
      unknown9  = tvb_get_letohl(tvb, offset+44);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+44, 4, unknown9);
      unknown10 = tvb_get_letohl(tvb, offset+48);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+48, 4, unknown10);
      break;

    case 0x8b :  /* stopMediaTransmission */
      unknown1 = tvb_get_letohl(tvb, offset+12);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
      unknown2 = tvb_get_letohl(tvb, offset+16);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+16, 4, unknown2);
      break;

    case 0x91 : /* speedDialStatMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_speedDialNumber, tvb, offset+12, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_speedDialDirNumber, tvb, offset+16, StationMaxDirnumSize, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_speedDialDisplayName, tvb, offset+40, StationMaxNameSize, TRUE);
      break;

    case 0x92 : /* lineStatMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_lineNumber, tvb, offset+12, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_lineDirNumber, tvb, offset+16, StationMaxDirnumSize, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_lineFullyQualifiedDisplayName, tvb, offset+16+StationMaxDirnumSize, StationMaxNameSize, TRUE);
      break;

    case 0x94 : /* stationDefineTimeDate */
      proto_tree_add_item(skinny_tree, hf_skinny_dateYear,   tvb, offset+12, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_dateMonth,  tvb, offset+16, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_dayOfWeek,  tvb, offset+20, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_dateDay,    tvb, offset+24, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_dateHour,   tvb, offset+28, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_dateMinute, tvb, offset+32, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_dateSeconds,tvb, offset+36, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_dateMilliseconds,tvb, offset+40, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_timeStamp, tvb, offset+44, 4, TRUE);
      break;
      
    case 0x97 :  /* buttonTemplateMessage  */
      /*
       * FIXME
       * This decode prints out oogly subtree maybe? or something besides the VALS...
       * note to self: uint8 != 4 kk thx info ^_^
       *
       */
      proto_tree_add_item(skinny_tree, hf_skinny_buttonOffset, tvb, offset+12, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_buttonCount,  tvb, offset+16, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_totalButtonCount, tvb, offset+20, 4, TRUE);
      for (i = 0; i < StationMaxButtonTemplateSize; i++) {
	proto_tree_add_item(skinny_tree, hf_skinny_buttonInstanceNumber, tvb, offset+(i*2)+24, 1, TRUE);
	proto_tree_add_item(skinny_tree, hf_skinny_buttonDefinition, tvb, offset+(i*2)+25, 1, TRUE);
      }
      break;

    case 0x99 :  /* displayTextMessage */
      memset(displayMessage, '\0', displayLength);
      tvb_memcpy(tvb, displayMessage, offset+12, 32);
      proto_tree_add_string(skinny_tree, hf_skinny_displayMessage, tvb, offset+12, strlen(displayMessage), displayMessage);        
      unknown1  = tvb_get_letohl(tvb, offset+44);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+44, 4, unknown1);
      break;

    case 0x9d : /* stationRegisterReject */
      break;
      
    case 0x9f :   /* reset */
      unknown1  = tvb_get_letohl(tvb, offset+12);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
      break;

    case 0x105 : /* open receive channel */
      unknown1 = tvb_get_letohl(tvb, offset+12);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
      unknown2 = tvb_get_letohl(tvb, offset+16);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+16, 4, unknown2);
      unknown3 = tvb_get_letohl(tvb, offset+20);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+20, 4, unknown3);
      unknown4 = tvb_get_letohl(tvb, offset+24);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+24, 4, unknown4);
      unknown5 = tvb_get_letohl(tvb, offset+28);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+28, 4, unknown5);
      unknown6 = tvb_get_letohl(tvb, offset+32);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+32, 4, unknown6);
      break;

    case 0x106 :  /* closeReceiveChannel */
      unknown1 = tvb_get_letohl(tvb, offset+12);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
      unknown2 = tvb_get_letohl(tvb, offset+16);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+16, 4, unknown2);
      break;

    case 0x107 :      
      memset(extension, '\0', extensionLength);
      tvb_get_nstringz0(tvb, offset+12, extensionLength, extension);
      proto_tree_add_string(skinny_tree, hf_skinny_extension, tvb, offset+12, strlen(extension), extension);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+36, 4, TRUE);
      break;

    case 0x108 :   /* softkeyTemplateResMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_softKeyOffset, tvb, offset+12, 4, TRUE);
      softKeyCount = tvb_get_letohl(tvb, offset+16);
      proto_tree_add_uint(skinny_tree, hf_skinny_softKeyCount, tvb, offset+16, 4, softKeyCount);
      proto_tree_add_item(skinny_tree, hf_skinny_totalSoftKeyCount, tvb, offset+20, 4, TRUE);
      for (i = 0; ((i < StationMaxSoftKeyDefinition) && (i < softKeyCount)); i++){
	proto_tree_add_item(skinny_tree, hf_skinny_softKeyLabel, tvb, offset+(i*20)+24, StationMaxSoftKeyLabelSize, TRUE);
	proto_tree_add_item(skinny_tree, hf_skinny_softKeyEvent, tvb, offset+(i*20)+40, 4, TRUE);
      }
      /* there is more data here, but it doesn't make a whole lot of sense, I imagine
       * it's just some not zero'd out stuff in the packet or... 
       */
      break;

    case 0x109 : /* softkeysetres */
      proto_tree_add_item(skinny_tree, hf_skinny_softKeySetOffset, tvb, offset+12, 4, TRUE);
      softKeySetCount = tvb_get_letohl(tvb, offset+16);
      proto_tree_add_uint(skinny_tree, hf_skinny_softKeySetCount, tvb, offset+16, 4, softKeySetCount);
      proto_tree_add_item(skinny_tree, hf_skinny_totalSoftKeySetCount, tvb, offset+20, 4, TRUE);
      for (i = 0; ((i < StationMaxSoftKeySetDefinition) && (i < softKeySetCount)); i++) {
	proto_tree_add_uint(skinny_tree, hf_skinny_softKeySetDescription, tvb, offset+(i*20)+24+j,1,i);
	for (j = 0; j < StationMaxSoftKeyIndex; j++) {
	  proto_tree_add_item(skinny_tree, hf_skinny_softKeyTemplateIndex, tvb, offset+(i*20)+24+j, 1, TRUE);
	}
	for (j = 0; j < StationMaxSoftKeyIndex; j++) {
	  proto_tree_add_item(skinny_tree, hf_skinny_softKeyInfoIndex, tvb, offset+(i*20)+25+(j*2), 2, TRUE);
	}
      }
      break;
      
    case 0x110 : /* selectSoftKeys */
      proto_tree_add_item(skinny_tree, hf_skinny_lineInstance, tvb, offset+12, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+16, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_softKeySetDescription, tvb, offset+20, 4, TRUE);
      validKeyMask = tvb_get_letohs(tvb, offset + 24);
      skm = proto_tree_add_uint(skinny_tree, hf_skinny_softKeyMap, tvb, offset + 24, 1, validKeyMask);
      skm_tree = proto_item_add_subtree(skm, ett_skinny_softKeyMap);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey0,  tvb, offset + 24, 1, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey1,  tvb, offset + 24, 1, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey2,  tvb, offset + 24, 1, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey3,  tvb, offset + 24, 1, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey4,  tvb, offset + 24, 1, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey5,  tvb, offset + 24, 1, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey6,  tvb, offset + 24, 1, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey7,  tvb, offset + 24, 1, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey8,  tvb, offset + 24, 1, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey9,  tvb, offset + 24, 1, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey10, tvb, offset + 24, 1, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey11, tvb, offset + 24, 1, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey12, tvb, offset + 24, 1, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey13, tvb, offset + 24, 1, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey14, tvb, offset + 24, 1, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey15, tvb, offset + 24, 1, validKeyMask);
      break;
      
    case 0x111 :
      unknown1 = tvb_get_letohl(tvb, offset+12);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
      unknown2 = tvb_get_letohl(tvb, offset+16);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+16, 4, unknown2);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+20, 4, TRUE);
      break;
      
    case 0x112 :
      proto_tree_add_item(skinny_tree, hf_skinny_messageTimeOutValue, tvb, offset+12, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_displayMessage, tvb, offset+16, StationMaxDisplayPromptStatusSize, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_lineInstance, tvb, offset+48, 4, TRUE);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+52, 4, TRUE);
      break;
      
    case 0x113:
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+16, 4, TRUE);
      break;
      
    case 0x114 :
      unknown1 = tvb_get_letohl(tvb, offset+12);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
      memset(displayMessage,'\0',displayLength);
      tvb_memcpy(tvb, displayMessage, offset+16, 16);
      proto_tree_add_string(skinny_tree, hf_skinny_displayMessage, tvb, offset+16, strlen(displayMessage), displayMessage);
      unknown2 = tvb_get_letohl(tvb, offset+32);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+32, 4, unknown2);
      unknown3 = tvb_get_letohl(tvb, offset+36);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+36, 4, unknown3);
      unknown4 = tvb_get_letohl(tvb, offset+40);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+40, 4, unknown4);
      unknown5 = tvb_get_letohl(tvb, offset+44);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+44, 4, unknown5);
      break;
      
    case 0x116 :
      unknown1 = tvb_get_letohl(tvb, offset+12);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
      break;

    case 0x118 :    /* unregisterAckMessage */
      unknown1 = tvb_get_letohl(tvb, offset+12);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
      break;

    case 0x11D :
      unknown1       = tvb_get_letohl(tvb, offset+36);
      proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+36, 4, unknown1);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+40, 4, TRUE);
      break;
      
    default:
      break;
    }
  }
}

/* Code to actually dissect the packets */
static void dissect_skinny(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  /* The general structure of a packet: {IP-Header|TCP-Header|n*SKINNY}
   * SKINNY-Packet: {Header(Size, Reserved)|Data(MessageID, Message-Data)}
   */
  
  volatile int offset = 0;
  int length_remaining;
  int length;
  tvbuff_t *next_tvb;

  /* Header fields */
  volatile guint32 hdr_data_length;
  guint32 hdr_reserved;

  /* check, if this is really an SKINNY packet, they start with a length + 0 */
  
  /* get relevant header information */
  hdr_data_length = tvb_get_letohl(tvb, 0);
  hdr_reserved    = tvb_get_letohl(tvb, 4);

  /*  data_size       = MIN(8+hdr_data_length, tvb_length(tvb)) - 0xC; */
  
  /* hdr_data_length > 1024 is just a heuristic. Better values/checks welcome */
  if (hdr_data_length < 4 || hdr_data_length > 1024 || hdr_reserved != 0) {
    /* Not an SKINNY packet, just happened to use the same port */
    call_dissector(data_handle,tvb, pinfo, tree);
    return;
  }
  
  /* Make entries in Protocol column and Info column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SKINNY");
  }
  
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_set_str(pinfo->cinfo, COL_INFO, "Skinny Client Control Protocol");
  }
  
  while (tvb_reported_length_remaining(tvb, offset) != 0) {
    length_remaining = tvb_length_remaining(tvb, offset);

    /*
     * Can we do reassembly?
     */
    if (skinny_desegment && pinfo->can_desegment) {
      /*
       * Yes - is the length field in the SCCP header split across
       * segment boundaries?
       */
      if (length_remaining < 4) {
	/*
	 * Yes.  Tell the TCP dissector where the data for this message
	 * starts in the data it handed us, and how many more bytes we
	 * need, and return.
	 */
	pinfo->desegment_offset = offset;
	pinfo->desegment_len = 4 - length_remaining;
	return;
      }
    }

    /*
     * Get the length of the SCCP packet.
     */
    hdr_data_length = tvb_get_letohl(tvb, offset);

    /*
     * Can we do reassembly?
     */
    if (skinny_desegment && pinfo->can_desegment) {
      /*
       * Yes - is the SCCP packet split across segment boundaries?
       */
      if ((guint32)length_remaining < hdr_data_length + 8) {
	/*
	 * Yes.  Tell the TCP dissector where the data for this message
	 * starts in the data it handed us, and how many more bytes we
	 * need, and return.
	 */
	pinfo->desegment_offset = offset;
	pinfo->desegment_len = (hdr_data_length + 8) - length_remaining;
	return;
      }
    }

    /*
     * Construct a tvbuff containing the amount of the payload we have
     * available.  Make its reported length the amount of data in the
     * SCCP packet.
     *
     * XXX - if reassembly isn't enabled. the subdissector will throw a
     * BoundsError exception, rather than a ReportedBoundsError exception.
     * We really want a tvbuff where the length is "length", the reported
     * length is "hdr_data_length + 8", and the "if the snapshot length
     * were infinite" length is the minimum of the reported length of
     * the tvbuff handed to us and "hdr_data_length + 8", with a new type
     * of exception thrown if the offset is within the reported length but
     * beyond that third length, with that exception getting the
     * "Unreassembled Packet" error.
     */
    length = length_remaining;
    if ((guint32)length > hdr_data_length + 8)
      length = hdr_data_length + 8;
    next_tvb = tvb_new_subset(tvb, offset, length, hdr_data_length + 8);

    /*
     * Dissect the SCCP packet.
     *
     * Catch the ReportedBoundsError exception; if this particular message
     * happens to get a ReportedBoundsError exception, that doesn't mean
     * that we should stop dissecting SCCP messages within this frame or
     * chunk of reassembled data.
     *
     * If it gets a BoundsError, we can stop, as there's nothing more to
     * see, so we just re-throw it.
     */
    TRY {
      dissect_skinny_pdu(next_tvb, pinfo, tree);
    }
    CATCH(BoundsError) {
      RETHROW;
    }
    CATCH(ReportedBoundsError) {
      show_reported_bounds_error(tvb, pinfo, tree);
    }
    ENDTRY;

    /*
     * Skip the SCCP header and the payload.
     */
    offset += hdr_data_length + 8;
  }
}

/* Register the protocol with Ethereal */
void 
proto_register_skinny(void)
{                 
  
  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_skinny_data_length,
      { "Data Length", "skinny.data_length",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Number of bytes in the data portion.",
	HFILL }
    },
    { &hf_skinny_reserved,
      { "Reserved", "skinny.reserved",
	FT_UINT32, BASE_HEX, NULL, 0x0,
	"Reserved for future(?) use.",
	HFILL }
    },
    /* FIXME: Enable use of message name ???  */
    { &hf_skinny_messageid,
      { "Message ID", "skinny.messageid",
	FT_UINT32, BASE_HEX, VALS(message_id), 0x0,
	"The function requested/done with this message.",
	HFILL }
    },

    { &hf_skinny_deviceName,
      { "DeviceName", "skinny.deviceName",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The device name of the phone.",
	HFILL }
    },

    { &hf_skinny_stationUserId,
      { "StationUserId", "skinny.stationUserId",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The station user id.",
	HFILL }
    },

    { &hf_skinny_stationInstance,
      { "StationInstance", "skinny.stationInstance",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The stations instance.",
	HFILL }
    },

    { &hf_skinny_deviceType,
      { "DeviceType", "skinny.deviceType",
	FT_UINT32, BASE_DEC, VALS(deviceTypes), 0x0,
	"DeviceType of the station.",
	HFILL }
    },

    { &hf_skinny_maxStreams,
      { "MaxStreams", "skinny.maxStreams",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"32 bit unsigned integer indicating the maximum number of simultansous RTP duplex streams that the client can handle.",
	HFILL }
    },

    { &hf_skinny_stationIpPort,
      { "StationIpPort", "skinny.stationIpPort",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"The station IP port",
	HFILL }
    },

    { &hf_skinny_stationKeypadButton,
      { "KeypadButton", "skinny.stationKeypadButton",
	FT_UINT32, BASE_HEX, VALS(keypadButtons), 0x0,
	"The button pressed on the phone.",
	HFILL }
    },

    { &hf_skinny_calledParty,
      { "CalledParty", "skinny.calledParty",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The number called.",
	HFILL }
    },

    { &hf_skinny_stimulus,
      { "Stimulus", "skinny.stimulus",
	FT_UINT32, BASE_HEX, VALS(deviceStimuli), 0x0,
	"Reason for the device stimulus message.",
	HFILL }
    },

    { &hf_skinny_stimulusInstance,
      { "StimulusInstance", "skinny.stimulusInstance",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The instance of the stimulus",
	HFILL }
    },

    { &hf_skinny_lineNumber,
      { "LineNumber", "skinny.lineNumber",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Line Number",
	HFILL }
    },

    { &hf_skinny_speedDialNumber,
      { "SpeedDialNumber", "skinny.speedDialNumber",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Which speed dial number",
	HFILL }
    },

    { &hf_skinny_capCount,
      { "CapCount", "skinny.capCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"How many capabilities",
	HFILL }
    },

    { &hf_skinny_payloadCapability,
      { "PayloadCapability", "skinny.payloadCapability",
	FT_UINT32, BASE_DEC, VALS(mediaPayloads), 0x0,
	"The payload capability for this media capability structure.",
	HFILL }
    },

    { &hf_skinny_maxFramesPerPacket,
      { "MaxFramesPerPacket", "skinny.maxFramesPerPacket",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Max frames per packet",
	HFILL }
    },

    { &hf_skinny_alarmSeverity,
      { "AlarmSeverity", "skinny.alarmSeverity",
	FT_UINT32, BASE_DEC, VALS(alarmSeverities), 0x0,
	"The severity of the reported alarm.",
	HFILL }
    },

    { &hf_skinny_alarmParam1,
      { "AlarmParam1", "skinny.alarmParam1",
	FT_UINT32, BASE_HEX, NULL, 0x0,
	"An as yet undecoded param1 value from the alarm message",
	HFILL }
    },

    { &hf_skinny_alarmParam2,
      { "AlarmParam2", "skinny.alarmParam2",
	FT_IPv4, BASE_NONE, NULL, 0x0,
	"This is the second alarm parameter i think it's an ip address",
	HFILL }
    },

    { &hf_skinny_receptionStatus,
      { "ReceptionStatus", "skinny.receptionStatus",
	FT_UINT32, BASE_DEC, VALS(multicastMediaReceptionStatus), 0x0,
	"The current status of the multicast media.",
	HFILL }
    },

    { &hf_skinny_passThruPartyID,
      { "PassThruPartyID", "skinny.passThruPartyID",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The pass thru party id",
	HFILL }
    },

    { &hf_skinny_ORCStatus,
      { "OpenReceiveChannelStatus", "skinny.openReceiveChannelStatus",
	FT_UINT32, BASE_DEC, VALS(openReceiveChanStatus), 0x0,
	"The status of the opened receive channel.",
	HFILL }
    },

    { &hf_skinny_ipAddress,
      { "IP Address", "skinny.ipAddress",
	FT_IPv4, BASE_NONE, NULL, 0x0,
	"An IP address",
	HFILL }
    },

    { &hf_skinny_portNumber,
      { "Port Number", "skinny.portNumber",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"A port number",
	HFILL }
    },

    { &hf_skinny_statsProcessingType,
      { "StatsProcessingType", "skinny.statsProcessingType",
	FT_UINT32, BASE_DEC, VALS(statsProcessingTypes), 0x0,
	"What do do after you send the stats.",
	HFILL }
    },

    { &hf_skinny_callIdentifier,
      { "Call Identifier", "skinny.callIdentifier",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Call identifier for this call.",
	HFILL }
    },

    { &hf_skinny_packetsSent,
      { "Packets Sent", "skinny.packetsSent",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Packets Sent during the call.",
	HFILL }
    },

    { &hf_skinny_octetsSent,
      { "Octets Sent", "skinny.octetsSent",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Octets sent during the call.",
	HFILL }
    },

    { &hf_skinny_packetsRecv,
      { "Packets Received", "skinny.packetsRecv",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Packets received during the call.",
	HFILL }
    },

    { &hf_skinny_octetsRecv,
      { "Octets Received", "skinny.octetsRecv",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Octets received during the call.",
	HFILL }
    },

    { &hf_skinny_packetsLost,
      { "Packets Lost", "skinny.packetsLost",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Packets lost during the call.",
	HFILL }
    },

    { &hf_skinny_latency,
      { "Latency(ms)", "skinny.latency",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Average packet latency during the call.",
	HFILL }
    },

    { &hf_skinny_jitter,
      { "Jitter", "skinny.jitter",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Average jitter during the call.",
	HFILL }
    },

    { &hf_skinny_directoryNumber,
      { "Directory Number", "skinny.directoryNumber",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The number we are reporting statistics for.",
	HFILL }
    },

    { &hf_skinny_lineInstance,
      { "Line Instance", "skinny.lineInstance",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The display call plane associated with this call.",
	HFILL }
    },

    { &hf_skinny_softKeyEvent,
      { "SoftKeyEvent", "skinny.softKeyEvent",
	FT_UINT32, BASE_DEC, VALS(softKeyEvents), 0x0,
	"Which softkey event is being reported.",
	HFILL }
    },

    { &hf_skinny_keepAliveInterval,
      { "KeepAliveInterval", "skinny.keepAliveInterval",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"How often are keep alives exchanges between the client and the call manager.",
	HFILL }
    },

    { &hf_skinny_secondaryKeepAliveInterval,
      { "SecondaryKeepAliveInterval", "skinny.secondaryKeepAliveInterval",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"How often are keep alives exchanges between the client and the secondary call manager.",
	HFILL }
    },

    { &hf_skinny_dateTemplate,
      { "DateTemplate", "skinny.dateTemplate",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The display format for the date/time on the phone.",
	HFILL }
    },

    { &hf_skinny_buttonOffset,
      { "ButtonOffset", "skinny.buttonOffset",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Offset is the number of the first button referenced by this message.",
	HFILL }
    },

    { &hf_skinny_buttonCount,
      { "ButtonCount", "skinny.buttonCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Number of (VALID) button definitions in this message.",
	HFILL }
    },

    { &hf_skinny_totalButtonCount,
      { "TotalButtonCount", "skinny.totalButtonCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The total number of buttons defined for this phone.",
	HFILL }
    },

    { &hf_skinny_buttonInstanceNumber,
      { "InstanceNumber", "skinny.buttonInstanceNumber",
	FT_UINT8, BASE_HEX, VALS(keypadButtons), 0x0,
	"The button instance number for a button or the StationKeyPad value, repeats allowed.",
	HFILL }
    },

    { &hf_skinny_buttonDefinition,
      { "ButtonDefinition", "skinny.buttonDefinition",
	FT_UINT8, BASE_HEX, VALS(buttonDefinitions), 0x0,
	"The button type for this instance (ie line, speed dial, ....",
	HFILL }
    },

    { &hf_skinny_softKeyOffset,
      { "SoftKeyOffset", "skinny.softKeyOffset",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The offset for the first soft key in this message.",
	HFILL }
    },

    { &hf_skinny_softKeyCount,
      { "SoftKeyCount", "skinny.softKeyCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The number of valid softkeys in this message.",
	HFILL }
    },

    { &hf_skinny_totalSoftKeyCount,
      { "TotalSoftKeyCount", "skinny.totalSoftKeyCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The total number of softkeys for this device.",
	HFILL }
    },

    { &hf_skinny_softKeyLabel,
      { "SoftKeyLabel", "skinny.softKeyLabel",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The text label for this soft key.",
	HFILL }
    },

    { &hf_skinny_softKeySetOffset,
      { "SoftKeySetOffset", "skinny.softKeySetOffset",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The offset for the first soft key set in this message.",
	HFILL }
    },

    { &hf_skinny_softKeySetCount,
      { "SoftKeySetCount", "skinny.softKeySetCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The number of valid softkey sets in this message.",
	HFILL }
    },

    { &hf_skinny_totalSoftKeySetCount,
      { "TotalSoftKeySetCount", "skinny.totalSoftKeySetCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The total number of softkey sets for this device.",
	HFILL }
    },

    { &hf_skinny_softKeyTemplateIndex,
      { "SoftKeyTemplateIndex", "skinny.softKeyTemplateIndex",
	FT_UINT8, BASE_DEC, VALS(softKeyEvents), 0x0,
	"Array of size 16 8-bit unsigned ints containing an index into the softKeyTemplate.",
	HFILL }
    },

    { &hf_skinny_softKeyInfoIndex,
      { "SoftKeyInfoIndex", "skinny.softKeyInfoIndex",
	FT_UINT16, BASE_DEC, VALS(softKeyIndexes), 0x0,
	"Array of size 16 16-bit unsigned integers containing an index into the soft key description information.",
	HFILL }
    },

    { &hf_skinny_softKeySetDescription,
      { "SoftKeySet", "skinny.softKeySetDescription",
	FT_UINT8, BASE_DEC, VALS(keySetNames), 0x0,
	"A text description of what this softkey when this softkey set is displayed",
	HFILL }
    },

    { &hf_skinny_softKeyMap,
      { "SoftKeyMap","skinny.softKeyMap", 
	FT_UINT16, BASE_HEX, NULL, 0x0,
	"", 
	HFILL }
    },
    
    { &hf_skinny_softKey0,
      { "SoftKey0", "skinny.softKeyMap.0", 
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY0,
	"", 
	HFILL }
    },

    { &hf_skinny_softKey1,
      { "SoftKey1", "skinny.softKeyMap.1", 
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY1,
	"", 
	HFILL }
    },

    { &hf_skinny_softKey2,
      { "SoftKey2", "skinny.softKeyMap.2", 
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY2,
	"", 
	HFILL }
    },

    { &hf_skinny_softKey3,
      { "SoftKey3", "skinny.softKeyMap.3",
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY3,
	"", 
	HFILL }
    },

    { &hf_skinny_softKey4,
      { "SoftKey4", "skinny.softKeyMap.4", 
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY4,
	"", 
	HFILL }
    },

    { &hf_skinny_softKey5,
      { "SoftKey5", "skinny.softKeyMap.5", 
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY5,
	"", 
	HFILL }
    },

    { &hf_skinny_softKey6,
      { "SoftKey6", "skinny.softKeyMap.6", 
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY6,
	"", 
	HFILL }
    },

    { &hf_skinny_softKey7,
      { "SoftKey7", "skinny.softKeyMap.7", 
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY7,
	"", 
	HFILL }
    },

    { &hf_skinny_softKey8,
      { "SoftKey8", "skinny.softKeyMap.8", 
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY8,
	"", 
	HFILL }
    },

    { &hf_skinny_softKey9,
      { "SoftKey9", "skinny.softKeyMap.9", 
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY9,
	"", 
	HFILL }
    },

    { &hf_skinny_softKey10,
      { "SoftKey10", "skinny.softKeyMap.10", 
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY10,
	"", 
	HFILL }
    },

    { &hf_skinny_softKey11,
      { "SoftKey11", "skinny.softKeyMap.11", 
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY11,
	"", 
	HFILL }
    },

    { &hf_skinny_softKey12,
      { "SoftKey12", "skinny.softKeyMap.12", 
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY12,
	"", 
	HFILL }
    },

    { &hf_skinny_softKey13,
      { "SoftKey13", "skinny.softKeyMap.13", 
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY13,
	"", 
	HFILL }
    },

    { &hf_skinny_softKey14,
      { "SoftKey14", "skinny.softKeyMap.14", 
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY14,
	"", 
	HFILL }
    },

    { &hf_skinny_softKey15,
      { "SoftKey15", "skinny.softKeyMap.15", 
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY15,
	"", 
	HFILL }
    },

    { &hf_skinny_lampMode,
      { "LampMode", "skinny.lampMode", 
	FT_UINT32, BASE_DEC, VALS(stationLampModes), 0x0,
	"The lamp mode", 
	HFILL }
    },

    { &hf_skinny_messageTimeOutValue,
      { "Message Timeout", "skinny.messageTimeOutValue", 
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The timeout in seconds for this message", 
	HFILL }
    },

    { &hf_skinny_displayMessage,
      { "DisplayMessage", "skinny.displayMessage",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The message displayed on the phone.",
	HFILL }
    },

    { &hf_skinny_lineDirNumber,
      { "Line Dir Number", "skinny.lineDirNumber",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The directory number for this line.",
	HFILL }
    },

    { &hf_skinny_lineFullyQualifiedDisplayName,
      { "DisplayName", "skinny.fqdn",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The full display name for this line.",
	HFILL }
    },

    { &hf_skinny_speedDialDirNumber,
      { "SpeedDial Number", "skinny.speedDialDirNum",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"the number to dial for this speed dial.",
	HFILL }
    },

    { &hf_skinny_speedDialDisplayName,
      { "SpeedDial Display", "skinny.speedDialDisplay",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The text to display for this speed dial.",
	HFILL }
    },

    { &hf_skinny_dateYear,
      { "Year", "skinny.year",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The current year",
	HFILL }
    },

    { &hf_skinny_dateMonth,
      { "Month", "skinny.month",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The current month",
	HFILL }
    },

    { &hf_skinny_dayOfWeek,
      { "DayOfWeek", "skinny.dayOfWeek",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The day of the week",
	HFILL }
    },

    { &hf_skinny_dateDay,
      { "Day", "skinny.day",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The day of the current month",
	HFILL }
    },

    { &hf_skinny_dateHour,
      { "Hour", "skinny.hour",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Hour of the day",
	HFILL }
    },

    { &hf_skinny_dateMinute,
      { "Minute", "skinny.minute",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Minute",
	HFILL }
    },

    { &hf_skinny_dateSeconds,
      { "Seconds", "skinny.dateSeconds",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Seconds",
	HFILL }
    },

    { &hf_skinny_dateMilliseconds,
      { "Milliseconds", "skinny.dateMilliseconds",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Milliseconds",
	HFILL }
    },

    { &hf_skinny_timeStamp,
      { "Timestamp", "skinny.timeStamp",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Time stamp for the call reference",
	HFILL }
    },







    /* */


    { &hf_skinny_extension,
      { "Extension", "skinny.extension",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The extension this packets is for.",
	HFILL }
    },




    { &hf_skinny_unknown,
      { "Unknown Long", "skinny.unknown",
	FT_UINT32, BASE_HEX, NULL, 0x0,
	"An as yet undecoded long value",
	HFILL }
    },
   
    { &hf_skinny_ipSrc,
      { "IP Source", "skinny.ipSrc",
	FT_IPv4, BASE_NONE, NULL, 0x0,
	"Ip source address",
	HFILL }
    },

    { &hf_skinny_ipDest,
      { "IP Destination", "skinny.ipDest",
	FT_IPv4, BASE_NONE, NULL, 0x0,
	"IP destination address",
	HFILL }
    },



    { &hf_skinny_destPort,
      { "Destination Port", "skinny.destPort",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Destination Port",
	HFILL }
    },

    { &hf_skinny_srcPort,
      { "Source Port", "skinny.srcPort",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Source Port",
	HFILL }
    },

    { &hf_skinny_softKeyNumber,
      { "SoftKey", "skinny.softKeyNumber",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"SoftKey",
	HFILL }
    },

    { &hf_skinny_dialedDigit,
      { "Dialed Digit", "skinny.dialedDigit",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Dialed Digit",
	HFILL }
    },

    { &hf_skinny_line,
      { "Line", "skinny.line",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Line",
	HFILL }
    },

  };
  
  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_skinny,
    &ett_skinny_softKeyMap,
  };

  module_t *skinny_module;

  /* Register the protocol name and description */
  proto_skinny = proto_register_protocol("Skinny Client Control Protocol",
					 "SKINNY", "skinny");
  
  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_skinny, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  skinny_module = prefs_register_protocol(proto_skinny, NULL);
  prefs_register_bool_preference(skinny_module, "desegment",
    "Desegment all SCCP messages spanning multiple TCP segments",
    "Whether the SCCP dissector should desegment all messages spanning multiple TCP segments",
    &skinny_desegment);
};

void
proto_reg_handoff_skinny(void)
{
  dissector_handle_t skinny_handle;

  data_handle = find_dissector("data");
  skinny_handle = create_dissector_handle(dissect_skinny, proto_skinny);
  dissector_add("tcp.port", TCP_PORT_SKINNY, skinny_handle);
}
