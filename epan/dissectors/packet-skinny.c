/* packet-skinny.c
 *
 * Dissector for the Skinny Client Control Protocol
 *   (The "D-Channel"-Protocol for Cisco Systems' IP-Phones)
 * Copyright 2001, Joerg Mayer (see AUTHORS file)
 *
 * Paul E. Erkkila (pee@erkkila.org) - fleshed out the decode
 * skeleton to report values for most message/message fields.
 * Much help from Guy Harris on figuring out the wireshark api.
 *
 * This file is based on packet-aim.c, which is
 * Copyright 2000, Ralf Hoelzer <ralf@well.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/* This implementation is based on a draft version of the 3.0
 * specification
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/tap.h>

#include "packet-rtp.h"
#include "packet-tcp.h"
#include "packet-ssl.h"
#include "packet-skinny.h"

#define TCP_PORT_SKINNY 2000
#define SSL_PORT_SKINNY 2443 /* IANA assigned to PowerClient Central Storage Facility */

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

#define BASIC_MSG_TYPE 0x00
#define CM7_MSG_TYPE_A 0x12
#define CM7_MSG_TYPE_B 0x11

static const value_string header_version[] = {
  { BASIC_MSG_TYPE, "Basic" },
  { CM7_MSG_TYPE_A, "CM7 type A" },
  { CM7_MSG_TYPE_B, "CM7 type B" },
  { 0             , NULL }
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
  {0x002A, "MediaTransmissionFailure"},
  {0x002B, "HeadsetStatusMessage"},
  {0x002C, "MediaResourceNotification"},
  {0x002D, "RegisterAvailableLinesMessage"},
  {0x002E, "DeviceToUserDataMessage"},
  {0x002F, "DeviceToUserDataResponseMessage"},
  {0x0030, "UpdateCapabilitiesMessage"},
  {0x0031, "OpenMultiMediaReceiveChannelAckMessage"},
  {0x0032, "ClearConferenceMessage"},
  {0x0033, "ServiceURLStatReqMessage"},
  {0x0034, "FeatureStatReqMessage"},
  {0x0035, "CreateConferenceResMessage"},
  {0x0036, "DeleteConferenceResMessage"},
  {0x0037, "ModifyConferenceResMessage"},
  {0x0038, "AddParticipantResMessage"},
  {0x0039, "AuditConferenceResMessage"},
  {0x0040, "AuditParticipantResMessage"},
  {0x0041, "DeviceToUserDataVersion1Message"},
  {0x0042, "DeviceToUserDataResponseVersion1Message"},
  {0x0048, "DialedPhoneBookMessage"},

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

  {0x011C, "StartMediaFailureDetection"},
  {0x011D, "DialedNumberMessage"},
  {0x011E, "UserToDeviceDataMessage"},
  {0x011F, "FeatureStatMessage"},
  {0x0120, "DisplayPriNotifyMessage"},
  {0x0121, "ClearPriNotifyMessage"},
  {0x0122, "StartAnnouncementMessage"},
  {0x0123, "StopAnnouncementMessage"},
  {0x0124, "AnnouncementFinishMessage"},
  {0x0127, "NotifyDtmfToneMessage"},
  {0x0128, "SendDtmfToneMessage"},
  {0x0129, "SubscribeDtmfPayloadReqMessage"},
  {0x012A, "SubscribeDtmfPayloadResMessage"},
  {0x012B, "SubscribeDtmfPayloadErrMessage"},
  {0x012C, "UnSubscribeDtmfPayloadReqMessage"},
  {0x012D, "UnSubscribeDtmfPayloadResMessage"},
  {0x012E, "UnSubscribeDtmfPayloadErrMessage"},
  {0x012F, "ServiceURLStatMessage"},
  {0x0130, "CallSelectStatMessage"},
  {0x0131, "OpenMultiMediaChannelMessage"},
  {0x0132, "StartMultiMediaTransmission"},
  {0x0133, "StopMultiMediaTransmission"},
  {0x0134, "MiscellaneousCommandMessage"},
  {0x0135, "FlowControlCommandMessage"},
  {0x0136, "CloseMultiMediaReceiveChannel"},
  {0x0137, "CreateConferenceReqMessage"},
  {0x0138, "DeleteConferenceReqMessage"},
  {0x0139, "ModifyConferenceReqMessage"},
  {0x013A, "AddParticipantReqMessage"},
  {0x013B, "DropParticipantReqMessage"},
  {0x013C, "AuditConferenceReqMessage"},
  {0x013D, "AuditParticipantReqMessage"},
  {0x013F, "UserToDeviceDataVersion1Message"},
  {0x014A, "CM5CallInfoMessage"},
  {0x0152, "DialedPhoneBookAckMessage"},
  {0x015A, "XMLAlarmMessage"},

  {0     , NULL}	/* terminator */
};
static value_string_ext message_id_ext = VALUE_STRING_EXT_INIT(message_id);

/*
 * Device type to text conversion table
 */
static const value_string  deviceTypes[] = {
  {1  , "30SPplus"},
  {2  , "12SPplus"},
  {3  , "12SP"},
  {4  , "12"},
  {5  , "30VIP"},
  {6  , "Telecaster"},
  {7  , "TelecasterMgr"},
  {8  , "TelecasterBus"},
  {9  , "Polycom"},
  {10 , "VGC"},
  {12 , "ATA"},
  {20 , "Virtual30SPplus"},
  {21 , "PhoneApplication"},
  {30 , "AnalogAccess"},
  {40 , "DigitalAccessPRI"},
  {41 , "DigitalAccessT1"},
  {42 , "DigitalAccessTitan2"},
  {43 , "DigitalAccessLennon"},
  {47 , "AnalogAccessElvis"},
  {50 , "ConferenceBridge"},
  {51 , "ConferenceBridgeYoko"},
  {52 , "ConferenceBridgeDixieLand"},
  {53 , "ConferenceBridgeSummit"},
  {60 , "H225"},
  {61 , "H323Phone"},
  {62 , "H323Trunk"},
  {70 , "MusicOnHold"},
  {71 , "Pilot"},
  {72 , "TapiPort"},
  {73 , "TapiRoutePoint"},
  {80 , "VoiceInBox"},
  {81 , "VoiceInboxAdmin"},
  {82 , "LineAnnunciator"},
  {83 , "SoftwareMtpDixieLand"},
  {84 , "CiscoMediaServer"},
  {85 , "ConferenceBridgeFlint"},
  {90 , "RouteList"},
  {100, "LoadSimulator"},
  {110, "MediaTerminationPoint"},
  {111, "MediaTerminationPointYoko"},
  {112, "MediaTerminationPointDixieLand"},
  {113, "MediaTerminationPointSummit"},
  {120, "MGCPStation"},
  {121, "MGCPTrunk"},
  {122, "RASProxy"},
  {125, "Trunk"},
  {126, "Annunciator"},
  {127, "MonitorBridge"},
  {128, "Recorder"},
  {129, "MonitorBridgeYoko"},
  {131, "SipTrunk"},
  {254, "UnknownMGCPGateway"},
  {255, "NotDefined"},
  { 0    , NULL}
};
static value_string_ext deviceTypes_ext = VALUE_STRING_EXT_INIT(deviceTypes);

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
static value_string_ext keypadButtons_ext = VALUE_STRING_EXT_INIT(keypadButtons);

static const value_string deviceStimuli[] = {
  {0x1  , "LastNumberRedial"},
  {0x2  , "SpeedDial"},
  {0x3  , "Hold"},
  {0x4  , "Transfer"},
  {0x5  , "ForwardAll"},
  {0x6  , "ForwardBusy"},
  {0x7  , "ForwardNoAnswer"},
  {0x8  , "Display"},
  {0x9  , "Line"},
  {0xa  , "T120Chat"},
  {0xb  , "T120Whiteboard"},
  {0xc  , "T120ApplicationSharing"},
  {0xd  , "T120FileTransfer"},
  {0xe  , "Video"},
  {0xf  , "VoiceMail"},
  {0x10 , "AutoAnswerRelease"},
  {0x11 , "AutoAnswer"},
  {0x12 , "Select"},
  {0x13 , "Privacy"},
  {0x14 , "ServiceURL"},
  {0x1B , "MaliciousCall"},
  {0x21 , "GenericAppB1"},
  {0x22 , "GenericAppB2"},
  {0x23 , "GenericAppB3"},
  {0x24 , "GenericAppB4"},
  {0x25 , "GenericAppB5"},
  {0x7b , "MeetMeConference"},
  {0x7d , "Conference"},
  {0x7e , "CallPark"},
  {0x7f , "CallPickup"},
  {0x80 , "GroupCallPickup"},
  {0,NULL}
};
static value_string_ext deviceStimuli_ext = VALUE_STRING_EXT_INIT(deviceStimuli);


/* Note i'm only using 7 later on cuz i'm lazy ;) */
#define DeviceMaxCapabilities 18 /* max capabilities allowed in Cap response message */

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
  {102 , "Video"},
  {105 , "T120"},
  {106 , "H224"},
  {257 , "RFC2833_DynPayload"},
  {0  , NULL}
};
static value_string_ext mediaPayloads_ext = VALUE_STRING_EXT_INIT(mediaPayloads);

static const value_string alarmSeverities[] = {
  {0   , "Critical"},
  {1   , "Warning"},
  {2   , "Informational"},
  {4   , "Unknown"},
  {7   , "Major"},
  {8   , "Minor"},
  {10  , "Marginal"},
  {20  , "TraceInfo"},
  {0  , NULL}
};
static value_string_ext alarmSeverities_ext = VALUE_STRING_EXT_INIT(alarmSeverities);

static const value_string multicastMediaReceptionStatus[] = {
  {0  , "Ok"},
  {1  , "Error"},
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
  {1   , "Redial"},
  {2   , "NewCall"},
  {3   , "Hold"},
  {4   , "Transfer"},
  {5   , "CFwdAll"},
  {6   , "CFwdBusy"},
  {7   , "CFwdNoAnswer"},
  {8   , "BackSpace"},
  {9   , "EndCall"},
  {10  , "Resume"},
  {11  , "Answer"},
  {12  , "Info"},
  {13  , "Confrn"},
  {14  , "Park"},
  {15  , "Join"},
  {16  , "MeetMeConfrn"},
  {17  , "CallPickUp"},
  {18  , "GrpCallPickUp"},
  {0   , NULL}
};
static value_string_ext softKeyEvents_ext = VALUE_STRING_EXT_INIT(softKeyEvents);

/* Define info index for each softkey event for Telecaster station. */
static const value_string softKeyIndexes[] = {
  {301  , "RedialInfoIndex"},
  {302  , "NewCallInfoIndex"},
  {303  , "HoldInfoIndex"},
  {304  , "TrnsferInfoIndex"},
  {305  , "CFwdAllInfoIndex"},
  {306  , "CFwdBusyInfoIndex"},     /* not used yet */
  {307  , "CFwdNoAnswerInfoIndex"}, /* not used yet */
  {308  , "BackSpaceInfoIndex"},
  {309  , "EndCallInfoIndex"},
  {310  , "ResumeInfoIndex"},
  {311  , "AnswerInfoIndex"},
  {312  , "InfoInfoIndex"},
  {313  , "ConfrnInfoIndex"},
  {314  , "ParkInfoIndex"},
  {315  , "JoinInfoIndex"},
  {316  , "MeetMeConfrnInfoIndex"},
  {317  , "CallPickUpInfoIndex"},
  {318  , "GrpCallPickUpInfoIndex"},
  {0   , NULL}
};
static value_string_ext softKeyIndexes_ext = VALUE_STRING_EXT_INIT(softKeyIndexes);


static const value_string buttonDefinitions[] = {
  {0x1  , "LastNumberRedial"},
  {0x2  , "SpeedDial"},
  {0x3  , "Hold"},
  {0x4  , "Transfer"},
  {0x5  , "ForwardAll"},
  {0x6  , "ForwardBusy"},
  {0x7  , "ForwardNoAnswer"},
  {0x8  , "Display"},
  {0x9  , "Line"},
  {0xa  , "T120Chat"},
  {0xb  , "T120Whiteboard"},
  {0xc  , "T120ApplicationSharing"},
  {0xd  , "T120FileTransfer"},
  {0xe  , "Video"},
  {0x10 , "AnswerRelease"},
  {0xf0 , "Keypad"},
  {0xfd , "AEC"},
  {0xff , "Undefined"},
  {0   , NULL}
};
static value_string_ext buttonDefinitions_ext = VALUE_STRING_EXT_INIT(buttonDefinitions);

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
static value_string_ext keySetNames_ext = VALUE_STRING_EXT_INIT(keySetNames);

#if 0
/* Define soft key labels for the Telecaster station */
static const value_string softKeyLabel[] _U_ = {
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
#endif

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
  {0x1 , "Off"},
  {0x2 , "On"},
  {0x3 , "Wink"},
  {0x4 , "Flash"},
  {0x5 , "Blink"},
  {0   , NULL}
};
static value_string_ext stationLampModes_ext = VALUE_STRING_EXT_INIT(stationLampModes);

/* Defined the Call States to be sent to the Telecaste station.
 * These are NOT the call states used in CM internally. Instead,
 * they are the call states sent from CM and understood by the Telecaster station
 */
static const value_string skinny_stationCallStates[] = {
  {1   , "OffHook"},
  {2   , "OnHook"},
  {3   , "RingOut"},
  {4   , "RingIn"},
  {5   , "Connected"},
  {6   , "Busy"},
  {7   , "Congestion"},
  {8   , "Hold"},
  {9   , "CallWaiting"},
  {10  , "CallTransfer"},
  {11  , "CallPark"},
  {12  , "Proceed"},
  {13  , "CallRemoteMultiline"},
  {14  , "InvalidNumber"},
  {0   , NULL}
};
static value_string_ext skinny_stationCallStates_ext = VALUE_STRING_EXT_INIT(skinny_stationCallStates);

/* Defined Call Type */
static const value_string skinny_callTypes[] = {
  {1   , "InBoundCall"},
  {2   , "OutBoundCall"},
  {3   , "ForwardCall"},
  {0   , NULL}
};

/*
 * define station-playable tones;
 * for tone definitions see SR-TSV-002275, "BOC Notes on the LEC Networks -- 1994"
 */
static const value_string skinny_deviceTones[] = {
  {0x0  , "Silence"},
  {0x1  , "Dtmf1"},
  {0x2  , "Dtmf2"},
  {0x3  , "Dtmf3"},
  {0x4  , "Dtmf4"},
  {0x5  , "Dtmf5"},
  {0x6  , "Dtmf6"},
  {0x7  , "Dtmf7"},
  {0x8  , "Dtmf8"},
  {0x9  , "Dtmf9"},
  {0xa  , "Dtmf0"},
  {0xe  , "DtmfStar"},
  {0xf  , "DtmfPound"},
  {0x10 , "DtmfA"},
  {0x11 , "DtmfB"},
  {0x12 , "DtmfC"},
  {0x13 , "DtmfD"},
  {0x21 , "InsideDialTone"},
  {0x22 , "OutsideDialTone"},
  {0x23 , "LineBusyTone"},
  {0x24 , "AlertingTone"},
  {0x25 , "ReorderTone"},
  {0x26 , "RecorderWarningTone"},
  {0x27 , "RecorderDetectedTone"},
  {0x28 , "RevertingTone"},
  {0x29 , "ReceiverOffHookTone"},
  {0x2a , "PartialDialTone"},
  {0x2b , "NoSuchNumberTone"},
  {0x2c , "BusyVerificationTone"},
  {0x2d , "CallWaitingTone"},
  {0x2e , "ConfirmationTone"},
  {0x2f , "CampOnIndicationTone"},
  {0x30 , "RecallDialTone"},
  {0x31 , "ZipZip"},
  {0x32 , "Zip"},
  {0x33 , "BeepBonk"},
  {0x34 , "MusicTone"},
  {0x35 , "HoldTone"},
  {0x36 , "TestTone"},
  {0x37 , "DtMoniterWarningTone"},
  {0x40 , "AddCallWaiting"},
  {0x41 , "PriorityCallWait"},
  {0x42 , "RecallDial"},
  {0x43 , "BargIn"},
  {0x44 , "DistinctAlert"},
  {0x45 , "PriorityAlert"},
  {0x46 , "ReminderRing"},
  {0x47 , "PrecedenceRingBack"},
  {0x48 , "PreemptionTone"},
  {0x50 , "MF1"},
  {0x51 , "MF2"},
  {0x52 , "MF3"},
  {0x53 , "MF4"},
  {0x54 , "MF5"},
  {0x55 , "MF6"},
  {0x56 , "MF7"},
  {0x57 , "MF8"},
  {0x58 , "MF9"},
  {0x59 , "MF0"},
  {0x5a , "MFKP1"},
  {0x5b , "MFST"},
  {0x5c , "MFKP2"},
  {0x5d , "MFSTP"},
  {0x5e , "MFST3P"},
  {0x5f , "MILLIWATT"},
  {0x60 , "MILLIWATTTEST"},
  {0x61 , "HIGHTONE"},
  {0x62 , "FLASHOVERRIDE"},
  {0x63 , "FLASH"},
  {0x64 , "PRIORITY"},
  {0x65 , "IMMEDIATE"},
  {0x66 , "PREAMPWARN"},
  {0x67 , "2105HZ"},
  {0x68 , "2600HZ"},
  {0x69 , "440HZ"},
  {0x6a , "300HZ"},
  {0x77 , "MLPP_PALA"},
  {0x78 , "MLPP_ICA"},
  {0x79 , "MLPP_VCA"},
  {0x7A , "MLPP_BPA"},
  {0x7B , "MLPP_BNEA"},
  {0x7C , "MLPP_UPA"},
  {0x7f , "NoTone"},
  {0   , NULL}
};
static value_string_ext skinny_deviceTones_ext = VALUE_STRING_EXT_INIT(skinny_deviceTones);

/* define ring types */
static const value_string skinny_ringTypes[] = {
  {0x1  , "RingOff"},
  {0x2  , "InsideRing"},
  {0x3  , "OutsideRing"},
  {0x4  , "FeatureRing"},
  {0x5  , "FlashOnly"},
  {0x6  , "PrecedenceRing"},
  {0   , NULL}
};
static value_string_ext skinny_ringTypes_ext = VALUE_STRING_EXT_INIT(skinny_ringTypes);

static const value_string skinny_ringModes[] = {
  {0x1  , "RingForever"},
  {0x2  , "RingOnce"},
  {0   , NULL}
};

static const value_string skinny_speakerModes[] = {
  {1   , "SpeakerOn"},
  {2   , "SpeakerOff"},
  {0   , NULL}
};

static const value_string skinny_silenceSuppressionModes[] = {
  {0   , "Media_SilenceSuppression_Off"},
  {1   , "Media_SilenceSuppression_On"},
  {0   , NULL}
};

static const value_string skinny_g723BitRates[] = {
  {1   , "Media_G723BRate_5_3"},
  {2   , "Media_G723BRate_6_4"},
  {0   , NULL}
};

/* define device reset types  */
static const value_string skinny_deviceResetTypes[] = {
  {1   , "DEVICE_RESET"},
  {2   , "DEVICE_RESTART"},
  {0   , NULL}
};

static const value_string skinny_echoCancelTypes[] = {
  {0    , "Media_EchoCancellation_Off"},
  {1    , "Media_EchoCancellation_On"},
  {0    , NULL}
};

static const value_string skinny_deviceUnregisterStatusTypes[] = {
  {0   , "Ok"},
  {1   , "Error"},
  {2   , "NAK"}, /* Unregister request is rejected for reaso n such as existence of a call */
  {0   , NULL}
};

static const value_string skinny_createConfResults[] = {
  {0   , "Ok"},
  {1   , "ResourceNotAvailable"},
  {2   , "ConferenceAlreadyExist"},
  {3   , "SystemErr"},
  {0   , NULL}
};

static const value_string skinny_modifyConfResults[] = {
  {0   , "Ok"},
  {1   , "ResourceNotAvailable"},
  {2   , "ConferenceNotExist"},
  {3   , "InvalidParameter"},
  {4   , "MoreActiveCallsThanReserved"},
  {5   , "InvalidResourceType"},
  {6   , "SystemErr"},
  {0   , NULL}
};
static value_string_ext skinny_modifyConfResults_ext = VALUE_STRING_EXT_INIT(skinny_modifyConfResults);

static const value_string skinny_deleteConfResults[] = {
  {0   , "Ok"},
  {1   , "ConferenceNotExist"},
  {2   , "SystemErr"},
  {0   , NULL}
};

static const value_string skinny_addParticipantResults[] = {
  {0   , "Ok"},
  {1   , "ResourceNotAvailable"},
  {2   , "ConferenceNotExist"},
  {3   , "DuplicateCallRef"},
  {4   , "SystemErr"},
  {0   , NULL}
};
static value_string_ext skinny_addParticipantResults_ext = VALUE_STRING_EXT_INIT(skinny_addParticipantResults);

static const value_string skinny_auditParticipantResults[] = {
  {0   , "Ok"},
  {1   , "ConferenceNotExist"},
  {0   , NULL}
};

/* define hook flash detection mode */
static const value_string skinny_hookFlashDetectModes[] = {
  {1   , "HookFlashOn"},
  {2   , "HookFlashOff"},
  {0   , NULL}
};

/* define headset mode */
static const value_string skinny_headsetModes[] = {
  {1   , "HeadsetOn"},
  {2   , "HeadsetOff"},
  {0   , NULL}
};

/* define station microphone modes;
 * Mic On - The speakerphone's microphone is turned on ONLY if the phone is in the "Speaker On (Off Hook)"
 * state (see above).
 * Mic Off - The microphone is turned off or, if it's not on, the command is ignored.
 */
static const value_string skinny_microphoneModes[] = {
  {1   , "MicOn"},
  {2   , "MicOff"},
  {0   , NULL}
};

/* define the session request types */
static const value_string skinny_sessionTypes[] = {
  {1   , "Chat"},
  {2   , "Whiteboard"},
  {4   , "ApplicationSharing"},
  {8   , "FileTransfer"},
  {10  , "Video"},
  {0   , NULL}
};
static value_string_ext skinny_sessionTypes_ext = VALUE_STRING_EXT_INIT(skinny_sessionTypes);

static const value_string skinny_mediaEnunciationTypes[] = {
  {1  , "None"},
  {2  , "CallPark"},
  {0  , NULL}
};

static const value_string skinny_resourceTypes[] = {
  {1  , "Conference"},
  {2  , "IVR"},
  {0  , NULL}
};

static const value_string skinny_sequenceFlags[] = {
  {0  , "StationSequenceFirst"},
  {1  , "StationSequenceMore"},
  {2  , "StationSequenceLast"},
  {0  , NULL}
};

static const value_string skinny_Layouts[] = {
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
static value_string_ext skinny_Layouts_ext = VALUE_STRING_EXT_INIT(skinny_Layouts);

static const value_string skinny_transmitOrReceive[] = {
  {1  , "Station_Receive_only"},
  {2  , "Station_Transmit_only"},
  {3  , "Station_Receive_Transmit"},
  {0  , NULL}
};

static const value_string skinny_endOfAnnAck[] = {
  {0  , "NoAnnAckRequired"},
  {1  , "AnnAckRequired"},
  {0  , NULL}
};

static const value_string skinny_annPlayMode[] = {
  {0  , "AnnXmlConfigMode"},
  {1  , "AnnOneShotMode"},
  {2  , "AnnContinuousMode"},
  {0  , NULL}
};

static const value_string skinny_annPlayStatus[] = {
  {0  , "PlayToneOK"},
  {1  , "PlayToneErr"},
  {0  , NULL}
};

static const value_string skinny_miscCommandType[] = {
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
static value_string_ext skinny_miscCommandType_ext = VALUE_STRING_EXT_INIT(skinny_miscCommandType);

static const value_string skinny_formatTypes[] = {
  {1  , "sqcif (128x96)"},
  {2  , "qcif (176x144)"},
  {3  , "cif (352x288)"},
  {4  , "4cif (704x576)"},
  {5  , "16cif (1408x1152)"},
  {6  , "custom_base"},
  {0  , NULL}
};
static value_string_ext skinny_formatTypes_ext = VALUE_STRING_EXT_INIT(skinny_formatTypes);

static const value_string cast_callSecurityStatusTypes[] = {
  {0   , "CallSecurityStatusUnknown"},
  {1   , "CallSecurityStatusNotAuthenticated"},
  {2   , "CallSecurityStatusAuthenticated"},
  {0   , NULL}
};

#define StationMaxDirnumSize 24         /* max size of calling or called party dirnum  */
#define StationMaxNameSize 40           /* max size of calling party's name  */
#define StationMaxDisplayNameSize 44    /* max size of display name  */
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
#define StationMaxAlarmMessageSize 80        /* max size for an alarm message */
#define StationMaxUserDeviceDataSize 2000    /* max size of user data between application and device */
#define StationMaxConference 32
#define AppConferenceIDSize 32
#define AppDataSize 24
#define MAX_CUSTOM_PICTURES 6
#define MAX_LAYOUT_WITH_SAME_SERVICE 5
#define MAX_SERVICE_TYPE 4
#define DeviceMaxCapabilities 18         /* max capabilities allowed in Cap response message */
#define StationMaxCapabilities       DeviceMaxCapabilities
#define StationMaxVideoCapabilities 10
#define StationMaxDataCapabilities  5
#define MAX_LEVEL_PREFERENCE 4
#define MaxAnnouncementList 32
#define StationMaxMonitorParties 16      /* Max Monitor Bridge whisper matrix parties,  rm, M&R in Parche */
#define StationMaxServiceURLSize 256	 /* max number of service URLs length */
#define MAX_PICTURE_FORMAT 5
#define MAX_REFERENCE_PICTURE 4

/* Initialize the protocol and registered fields */
static int proto_skinny          = -1;
static int hf_skinny_data_length = -1;
static int hf_skinny_hdr_version = -1;
static int hf_skinny_messageid   = -1;
static int hf_skinny_deviceName  = -1;
static int hf_skinny_stationUserId = -1;
static int hf_skinny_stationInstance = -1;
static int hf_skinny_deviceType = -1;
static int hf_skinny_maxStreams = -1;
static int hf_skinny_stationIpPort = -1;
static int hf_skinny_stationKeypadButton = -1;
static int hf_skinny_calledPartyNumber = -1;
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
static int hf_skinny_lineDisplayName = -1;
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
static int hf_skinny_callState = -1;
static int hf_skinny_deviceTone = -1;
static int hf_skinny_callingPartyName = -1;
static int hf_skinny_callingPartyNumber = -1;
static int hf_skinny_calledPartyName = -1;
static int hf_skinny_callType = -1;
static int hf_skinny_originalCalledPartyName = -1;
static int hf_skinny_originalCalledParty = -1;
static int hf_skinny_ringType = -1;
static int hf_skinny_ringMode = -1;
static int hf_skinny_speakerMode = -1;
static int hf_skinny_remoteIpAddr = -1;
static int hf_skinny_remotePortNumber = -1;
static int hf_skinny_millisecondPacketSize = -1;
static int hf_skinny_precedenceValue = -1;
static int hf_skinny_silenceSuppression = -1;
static int hf_skinny_g723BitRate = -1;
static int hf_skinny_conferenceID = -1;
static int hf_skinny_deviceResetType = -1;
static int hf_skinny_echoCancelType = -1;
static int hf_skinny_deviceUnregisterStatus = -1;
static int hf_skinny_hookFlashDetectMode = -1;
static int hf_skinny_detectInterval = -1;
static int hf_skinny_microphoneMode = -1;
static int hf_skinny_headsetMode = -1;
static int hf_skinny_unknown = -1;
static int hf_skinny_rawData = -1;
static int hf_skinny_xmlData = -1;
static int hf_skinny_activeForward = -1;
static int hf_skinny_forwardAllActive = -1;
static int hf_skinny_forwardBusyActive = -1;
static int hf_skinny_forwardNoAnswerActive = -1;
static int hf_skinny_forwardNumber = -1;
static int hf_skinny_serverName = -1;
static int hf_skinny_numberLines = -1;
static int hf_skinny_numberSpeedDials = -1;
static int hf_skinny_userName = -1;
static int hf_skinny_sessionType = -1;
static int hf_skinny_version = -1;
static int hf_skinny_mediaEnunciationType = -1;
static int hf_skinny_serverIdentifier = -1;
static int hf_skinny_serverListenPort = -1;
static int hf_skinny_serverIpAddress = -1;
static int hf_skinny_multicastIpAddress = -1;
static int hf_skinny_multicastPort = -1;
static int hf_skinny_tokenRejWaitTime = -1;
static int hf_skinny_numberOfInServiceStreams = -1;
static int hf_skinny_maxStreamsPerConf = -1;
static int hf_skinny_numberOfOutOfServiceStreams = -1;
static int hf_skinny_applicationID = -1;
static int hf_skinny_serviceNum = -1;
static int hf_skinny_serviceURLIndex = -1;
static int hf_skinny_featureIndex = -1;
static int hf_skinny_createConfResults = -1;
static int hf_skinny_modifyConfResults = -1;
static int hf_skinny_deleteConfResults = -1;
static int hf_skinny_addParticipantResults = -1;
static int hf_skinny_passThruData = -1;
static int hf_skinny_last = -1;
static int hf_skinny_numberOfEntries = -1;
static int hf_skinny_auditParticipantResults = -1;
static int hf_skinny_participantEntry = -1;
static int hf_skinny_resourceTypes = -1;
static int hf_skinny_numberOfReservedParticipants = -1;
static int hf_skinny_numberOfActiveParticipants = -1;
static int hf_skinny_appID = -1;
static int hf_skinny_appData = -1;
static int hf_skinny_appConfID = -1;
static int hf_skinny_sequenceFlag = -1;
static int hf_skinny_displayPriority = -1;
static int hf_skinny_appInstanceID = -1;
static int hf_skinny_routingID = -1;
static int hf_skinny_audioCapCount = -1;
static int hf_skinny_videoCapCount = -1;
static int hf_skinny_dataCapCount = -1;
static int hf_skinny_RTPPayloadFormat = -1;
static int hf_skinny_customPictureFormatCount = -1;
static int hf_skinny_pictureWidth = -1;
static int hf_skinny_pictureHeight = -1;
static int hf_skinny_pixelAspectRatio = -1;
static int hf_skinny_clockConversionCode = -1;
static int hf_skinny_clockDivisor = -1;
static int hf_skinny_activeStreamsOnRegistration = -1;
static int hf_skinny_maxBW = -1;
static int hf_skinny_serviceResourceCount = -1;
static int hf_skinny_layoutCount = -1;
static int hf_skinny_layout = -1;
static int hf_skinny_maxConferences = -1;
static int hf_skinny_activeConferenceOnRegistration = -1;
static int hf_skinny_transmitOrReceive = -1;
static int hf_skinny_levelPreferenceCount = -1;
static int hf_skinny_transmitPreference = -1;
static int hf_skinny_format = -1;
static int hf_skinny_maxBitRate = -1;
static int hf_skinny_minBitRate = -1;
static int hf_skinny_MPI = -1;
static int hf_skinny_serviceNumber = -1;
static int hf_skinny_temporalSpatialTradeOffCapability = -1;
static int hf_skinny_stillImageTransmission = -1;
static int hf_skinny_h263_capability_bitfield = -1;
static int hf_skinny_annexNandWFutureUse = -1;
static int hf_skinny_modelNumber = -1;
static int hf_skinny_bandwidth = -1;
static int hf_skinny_protocolDependentData = -1;
static int hf_skinny_priority = -1;
static int hf_skinny_payloadDtmf = -1;
static int hf_skinny_featureID = -1;
static int hf_skinny_featureTextLabel = -1;
static int hf_skinny_featureStatus = -1;
static int hf_skinny_notify = -1;
static int hf_skinny_endOfAnnAck = -1;
static int hf_skinny_annPlayMode = -1;
static int hf_skinny_annPlayStatus = -1;
static int hf_skinny_locale = -1;
static int hf_skinny_country = -1;
static int hf_skinny_matrixConfPartyID = -1;
static int hf_skinny_hearingConfPartyMask = -1;
static int hf_skinny_serviceURL = -1;
static int hf_skinny_serviceURLDisplayName = -1;
static int hf_skinny_callSelectStat = -1;
static int hf_skinny_isConferenceCreator = -1;
static int hf_skinny_payload_rfc_number = -1;
static int hf_skinny_payloadType = -1;
static int hf_skinny_bitRate = -1;
static int hf_skinny_pictureFormatCount = -1;
static int hf_skinny_confServiceNum = -1;
static int hf_skinny_DSCPValue = -1;
static int hf_skinny_miscCommandType = -1;
static int hf_skinny_temporalSpatialTradeOff = -1;
static int hf_skinny_firstGOB = -1;
static int hf_skinny_numberOfGOBs = -1;
static int hf_skinny_firstMB = -1;
static int hf_skinny_numberOfMBs = -1;
static int hf_skinny_pictureNumber = -1;
static int hf_skinny_longTermPictureIndex = -1;
static int hf_skinny_recoveryReferencePictureCount = -1;
static int hf_skinny_transactionID = -1;
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
static int hf_skinny_directoryIndex = -1;
static int hf_skinny_directoryPhoneNumber = -1;

/* Skinny content type and internet media type used by other dissectors
 *  * are the same.  List of media types from IANA at:
 *   * http://www.iana.org/assignments/media-types/index.html */
static dissector_table_t media_type_dissector_table;

/* Initialize the subtree pointers */
static gint ett_skinny          = -1;
static gint ett_skinny_tree     = -1;
static gint ett_skinny_softKeyMap = -1;

/* desegmentation of SCCP */
static gboolean skinny_desegment = TRUE;

static dissector_handle_t rtp_handle=NULL;

/* tap register id */
static int skinny_tap = -1;

/* skinny protocol tap info */
#define MAX_SKINNY_MESSAGES_IN_PACKET 10
static skinny_info_t pi_arr[MAX_SKINNY_MESSAGES_IN_PACKET];
static int pi_current = 0;
static skinny_info_t *si;

/* Get the length of a single SCCP PDU */
static guint get_skinny_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  guint32 hdr_data_length;

  /*
   * Get the length of the SCCP packet.
   */
  hdr_data_length = tvb_get_letohl(tvb, offset);

  /*
   * That length doesn't include the length of the header itself;
   * add that in.
   */
  return hdr_data_length + 8;
}

static void
dissect_skinny_xml(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, const gint start, gint length)
{
  proto_item *item = NULL;
  proto_tree *subtree = NULL;
  tvbuff_t *next_tvb;
  dissector_handle_t handle;

  item = proto_tree_add_item(tree, hf_skinny_xmlData, tvb, start, length, ENC_ASCII|ENC_NA);
  subtree = proto_item_add_subtree(item, 0);
  next_tvb = tvb_new_subset(tvb, start, length, -1);
  handle = dissector_get_string_handle(media_type_dissector_table, "text/xml");
  if (handle != NULL) {
    call_dissector(handle, next_tvb, pinfo, subtree);
   }
}

/* Dissect a single SCCP PDU */
static void
dissect_skinny_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  int offset = 0;
  gboolean is_video = FALSE; /* FIX ME: need to indicate video or not */

  /* Header fields */
  guint32 hdr_data_length;
  guint32 hdr_version;
  guint32 data_messageid;
  /*  guint32 data_size; */

  guint i = 0;
  guint t = 0;
  int j = 0;
  guint count;
  int val;

  guint32 capCount;
  guint32 softKeyCount;
  guint32 softKeySetCount;
  guint16 validKeyMask;

  /* Set up structures we will need to add the protocol subtree and manage it */
  proto_item *ti;
  proto_tree *skinny_tree = NULL;
  proto_item *ti_sub;
  proto_tree *skinny_sub_tree;
  proto_tree *skinny_sub_tree_sav;
  proto_tree *skinny_sub_tree_sav_sav;

  proto_item *skm = NULL;
  proto_item *skm_tree = NULL;

  hdr_data_length = tvb_get_letohl(tvb, offset);
  hdr_version     = tvb_get_letohl(tvb, offset+4);
  data_messageid  = tvb_get_letohl(tvb, offset+8);

  /* Initialise stat info for passing to tap */
  pi_current++;
  if (pi_current == MAX_SKINNY_MESSAGES_IN_PACKET)
  {
	/* Overwrite info in first struct if run out of space... */
	pi_current = 0;
  }
  si = &pi_arr[pi_current];
  si->messId = data_messageid;
  si->messageName = val_to_str_ext(data_messageid, &message_id_ext, "0x%08X (Unknown)");
  si->callId = 0;
  si->lineId = 0;
  si->passThruId = 0;
  si->callState = 0;
  g_free(si->callingParty);
  si->callingParty = NULL;
  g_free(si->calledParty);
  si->calledParty = NULL;

  /* In the interest of speed, if "tree" is NULL, don't do any work not
   * necessary to generate protocol tree items. */
  if (tree) {
    ti = proto_tree_add_item(tree, proto_skinny, tvb, offset, hdr_data_length+8, ENC_BIG_ENDIAN);
    skinny_tree = proto_item_add_subtree(ti, ett_skinny);
    proto_tree_add_uint(skinny_tree, hf_skinny_data_length, tvb, offset, 4, hdr_data_length);
    proto_tree_add_uint(skinny_tree, hf_skinny_hdr_version, tvb, offset+4, 4, hdr_version);
  }

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_fstr(pinfo->cinfo, COL_INFO,"%s ", si->messageName);
	col_set_fence(pinfo->cinfo, COL_INFO);
  }

  if (tree) {
    proto_tree_add_uint(skinny_tree, hf_skinny_messageid, tvb,offset+8, 4, data_messageid );
  }

  {
    switch(data_messageid) {

    case 0x0000: /* KeepAliveMessage */
      break;

    case 0x0001: /* RegisterMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_deviceName, tvb, offset+12, StationMaxDeviceNameSize, ENC_ASCII|ENC_NA);
      proto_tree_add_item(skinny_tree, hf_skinny_stationUserId, tvb, offset+28, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_stationInstance, tvb, offset+32, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_ipAddress, tvb, offset+36, 4, ENC_BIG_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_deviceType, tvb, offset+40, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_maxStreams, tvb, offset+44, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x0002: /* IpPortMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_stationIpPort, tvb, offset+12, 2, ENC_BIG_ENDIAN);
      break;

    case 0x0003: /* KeypadButtonMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_stationKeypadButton, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      if (hdr_data_length > 8) {
          proto_tree_add_item(skinny_tree, hf_skinny_lineInstance, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
		  proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
		  si->lineId = tvb_get_letohl(tvb, offset+16);
		  si->callId = tvb_get_letohl(tvb, offset+20);
      }
      break;

    case 0x0004: /* EnblocCallMessage -- This decode NOT verified*/
      proto_tree_add_item(skinny_tree, hf_skinny_calledPartyNumber, tvb, offset+12, StationMaxDirnumSize, ENC_ASCII|ENC_NA);
      break;

    case 0x0005: /* StimulusMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_stimulus, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_stimulusInstance, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      if (hdr_data_length > 12) {
		  proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
	      si->callId = tvb_get_letohl(tvb, offset+20);
      }
      break;

    case 0x0006: /* OffHookMessage */
      if (hdr_data_length > 4) {
		  proto_tree_add_item(skinny_tree, hf_skinny_lineInstance, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
		  proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
		  si->lineId = tvb_get_letohl(tvb, offset+12);
		  si->callId = tvb_get_letohl(tvb, offset+16);
      }
      break;

    case 0x0007: /* OnHookMessage */
      if (hdr_data_length > 4) {
		  proto_tree_add_item(skinny_tree, hf_skinny_lineInstance, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
		  proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
		  si->lineId = tvb_get_letohl(tvb, offset+12);
		  si->callId = tvb_get_letohl(tvb, offset+16);
      }
      break;

    case 0x0008: /* HookFlashMessage */
      break;

    case 0x0009: /* ForwardStatReqMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_lineNumber, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x000a: /* SpeedDialStatReqMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_speedDialNumber, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x000b: /* LineStatReqMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_lineNumber, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x000c: /* ConfigStatReqMessage */
      break;

    case 0x000d: /* TimeDateReqMessage */
      break;

    case 0x000e: /* ButtonTemplateReqMessage */
      break;

    case 0x000f: /* VersionReqMessage */
      break;

    case 0x0010: /* CapabilitiesResMessage  - VERIFIED AS IS */
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
	      proto_tree_add_item(skinny_tree, hf_skinny_payloadCapability, tvb, offset+(i*16)+16, 4, ENC_LITTLE_ENDIAN);
	      proto_tree_add_item(skinny_tree, hf_skinny_maxFramesPerPacket, tvb, offset+(i*16)+20, 2, ENC_LITTLE_ENDIAN);
	      /* FIXME -- decode the union under here as required, is always 0 on my equipment */
      }
      break;

    case 0x0011: /* MediaPortListMessage */
      break;

    case 0x0012: /* ServerReqMessage */
      break;

    case 0x0020: /* AlarmMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_alarmSeverity, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_displayMessage, tvb, offset+16, StationMaxAlarmMessageSize, ENC_ASCII|ENC_NA);
      proto_tree_add_item(skinny_tree, hf_skinny_alarmParam1, tvb, offset+96, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_alarmParam2, tvb, offset+100, 4, ENC_BIG_ENDIAN);
      break;

    case 0x0021: /* MulticastMediaReceptionAck - This decode NOT verified */
      proto_tree_add_item(skinny_tree, hf_skinny_receptionStatus, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      si->passThruId = tvb_get_letohl(tvb, offset+16);
      break;

    case 0x0022: /* OpenReceiveChannelAck */
      if (hdr_version == BASIC_MSG_TYPE) {
        proto_tree_add_item(skinny_tree, hf_skinny_ORCStatus, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(skinny_tree, hf_skinny_ipAddress, tvb, offset+16, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(skinny_tree, hf_skinny_portNumber, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+24, 4, ENC_LITTLE_ENDIAN);
        if (rtp_handle) {
          address src_addr;
          guint32 ipv4_address;

          src_addr.type = AT_IPv4;
          src_addr.len = 4;
          src_addr.data = (guint8 *)&ipv4_address;
          ipv4_address = tvb_get_ipv4(tvb, offset+16);
          rtp_add_address(pinfo, &src_addr, tvb_get_letohl(tvb, offset+20), 0, "Skinny", pinfo->fd->num, is_video, NULL);
        }
        si->passThruId = tvb_get_letohl(tvb, offset+24);
      } else if (hdr_version == CM7_MSG_TYPE_A || hdr_version == CM7_MSG_TYPE_B) {
        proto_tree_add_item(skinny_tree, hf_skinny_ORCStatus, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
        /* unknown uint32_t stuff */
        proto_tree_add_item(skinny_tree, hf_skinny_ipAddress, tvb, offset+20, 4, ENC_BIG_ENDIAN);
        /* 3x unknown uint32_t stuff, space for IPv6 maybe */
        proto_tree_add_item(skinny_tree, hf_skinny_portNumber, tvb, offset+36, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+40, 4, ENC_LITTLE_ENDIAN);
        if (rtp_handle) {
          address src_addr;
          guint32 ipv4_address;

          src_addr.type = AT_IPv4;
          src_addr.len = 4;
          src_addr.data = (guint8 *)&ipv4_address;
          ipv4_address = tvb_get_ipv4(tvb, offset+20);
          rtp_add_address(pinfo, &src_addr, tvb_get_letohl(tvb, offset+36), 0, "Skinny", pinfo->fd->num, is_video, NULL);
        }
        si->passThruId = tvb_get_letohl(tvb, offset+40);
      }
      break;

    case 0x0023: /* ConnectionStatisticsRes */
      proto_tree_add_item(skinny_tree, hf_skinny_directoryNumber, tvb, offset+12, StationMaxDirnumSize, ENC_ASCII|ENC_NA);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+36, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_statsProcessingType, tvb, offset+40, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_packetsSent, tvb, offset+44, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_octetsSent, tvb, offset+48, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_packetsRecv, tvb, offset+52, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_octetsRecv, tvb, offset+56, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_packetsLost, tvb, offset+60, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_jitter, tvb, offset+64, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_latency, tvb, offset+68, 4, ENC_LITTLE_ENDIAN);
      si->callId = tvb_get_letohl(tvb, offset+36);
      break;

    case 0x0024: /* OffHookWithCgpnMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_calledPartyNumber, tvb, offset+12,StationMaxDirnumSize, ENC_ASCII|ENC_NA);
      break;

    case 0x0025: /* SoftKeySetReqMessage */
      break;

    case 0x0026: /* SoftKeyEventMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_softKeyEvent, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_lineInstance, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      si->lineId = tvb_get_letohl(tvb, offset+16);
      si->callId = tvb_get_letohl(tvb, offset+20);
      break;

    case 0x0027: /* UnregisterMessage */
      break;

    case 0x0028: /* softKeyTemplateRequest */
      break;

    case 0x0029: /* RegisterTokenReq */
      proto_tree_add_item(skinny_tree, hf_skinny_deviceName, tvb, offset+12, 4, ENC_ASCII|ENC_NA);
      i = offset+12+StationMaxDeviceNameSize;
      proto_tree_add_item(skinny_tree, hf_skinny_stationUserId, tvb, i, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_stationInstance, tvb, i+4, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_ipAddress, tvb, i+8, 4, ENC_BIG_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_deviceType, tvb, i+12, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x002A: /* MediaTransmissionFailure */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_ipAddress, tvb, offset+20, 4, ENC_BIG_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_portNumber, tvb, offset+24, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+28, 4, ENC_LITTLE_ENDIAN);
      si->passThruId = tvb_get_letohl(tvb, offset+16);
      si->callId = tvb_get_letohl(tvb, offset+28);
      break;

    case 0x002B: /* HeadsetStatusMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_headsetMode, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x002C: /* MediaResourceNotification */
      proto_tree_add_item(skinny_tree, hf_skinny_deviceType, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_numberOfInServiceStreams, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_maxStreamsPerConf, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_numberOfOutOfServiceStreams, tvb, offset+24, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x002D: /* RegisterAvailableLinesMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_numberLines, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x002E: /* DeviceToUserDataMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_applicationID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_lineInstance, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_transactionID, tvb, offset+24, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_data_length, tvb, offset+28, 4, ENC_LITTLE_ENDIAN);
      count = tvb_get_letohl( tvb, offset+28);
      dissect_skinny_xml(skinny_tree, tvb, pinfo, offset+30, count);
      si->lineId = tvb_get_letohl(tvb, offset+16);
      si->callId = tvb_get_letohl(tvb, offset+20);
      break;

    case 0x002F: /* DeviceToUserDataResponseMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_applicationID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_lineInstance, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_transactionID, tvb, offset+24, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_data_length, tvb, offset+28, 4, ENC_LITTLE_ENDIAN);
      count = tvb_get_letohl( tvb, offset+28);
      dissect_skinny_xml(skinny_tree, tvb, pinfo, offset+30, count);
      si->lineId = tvb_get_letohl(tvb, offset+12);
      si->callId = tvb_get_letohl(tvb, offset+16);
      break;

    case 0x0030: /* UpdateCapabilitiesMessage */
      /* to do - this message is very large and will span multiple packets, it would be nice to someday */
      /* find out a way to join the next packet and get the complete message to decode */
      proto_tree_add_item(skinny_tree, hf_skinny_audioCapCount, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_videoCapCount, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_dataCapCount, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_RTPPayloadFormat, tvb, offset+24, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_customPictureFormatCount, tvb, offset+28, 4, ENC_LITTLE_ENDIAN);
      count = offset+32;
      for ( i = 0; i < MAX_CUSTOM_PICTURES; i++ ) {
        ti_sub = proto_tree_add_text(skinny_tree, tvb, offset, 20, "customPictureFormat[%d]", i);
        skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
        proto_tree_add_item(skinny_sub_tree, hf_skinny_pictureWidth, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count+= 4;
        proto_tree_add_item(skinny_sub_tree, hf_skinny_pictureHeight, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count+= 4;
        proto_tree_add_item(skinny_sub_tree, hf_skinny_pixelAspectRatio, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count+= 4;
        proto_tree_add_item(skinny_sub_tree, hf_skinny_clockConversionCode, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count+= 4;
        proto_tree_add_item(skinny_sub_tree, hf_skinny_clockDivisor, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count+= 4;
      }
      ti_sub = proto_tree_add_text(skinny_tree, tvb, offset, 8, "confResources");
      skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
      proto_tree_add_item(skinny_sub_tree, hf_skinny_activeStreamsOnRegistration, tvb, count, 4, ENC_LITTLE_ENDIAN);
      count+= 4;
      proto_tree_add_item(skinny_sub_tree, hf_skinny_maxBW, tvb, count, 4, ENC_LITTLE_ENDIAN);
      count+= 4;
      proto_tree_add_item(skinny_sub_tree, hf_skinny_serviceResourceCount, tvb, count, 4, ENC_LITTLE_ENDIAN);
      count+= 4;
      skinny_sub_tree_sav = skinny_sub_tree;
      for ( i = 0; i < MAX_SERVICE_TYPE; i++ ) {
        ti_sub = proto_tree_add_text(skinny_sub_tree_sav, tvb, offset, 20, "serviceResource[%d]", i);
        skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
        proto_tree_add_item(skinny_sub_tree, hf_skinny_layoutCount, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count+= 4;
        skinny_sub_tree_sav_sav = skinny_sub_tree_sav;
        for ( t = 0; t < MAX_LAYOUT_WITH_SAME_SERVICE; t++ ) {
          ti_sub = proto_tree_add_text(skinny_sub_tree_sav, tvb, offset, 20, "layouts[%d]", t);
          skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
          proto_tree_add_item(skinny_sub_tree, hf_skinny_layout, tvb, count, 4, ENC_LITTLE_ENDIAN);
          count+= 4;
        }
        skinny_sub_tree = skinny_sub_tree_sav_sav;
        proto_tree_add_item(skinny_sub_tree, hf_skinny_serviceNum, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count+= 4;
        proto_tree_add_item(skinny_sub_tree, hf_skinny_maxStreams, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count+= 4;
        proto_tree_add_item(skinny_sub_tree, hf_skinny_maxConferences, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count+= 4;
        proto_tree_add_item(skinny_sub_tree, hf_skinny_activeConferenceOnRegistration, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count+= 4;
      }
      for ( i = 0; i < StationMaxCapabilities; i++ ) {
        ti_sub = proto_tree_add_text(skinny_tree, tvb, offset, 20, "audiocaps[%d]", i);
        skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
        proto_tree_add_item(skinny_sub_tree, hf_skinny_payloadCapability, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count+= 4;
        proto_tree_add_item(skinny_sub_tree, hf_skinny_maxFramesPerPacket, tvb, count, 2, ENC_LITTLE_ENDIAN);
        count+= 4;
        /* skip past union it is only for G723 */
        count+= 8;
      }
      for ( i = 0; i < StationMaxVideoCapabilities; i++ ) {
        ti_sub = proto_tree_add_text(skinny_tree, tvb, offset, 20, "vidCaps[%d]", i);
        skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
        proto_tree_add_item(skinny_sub_tree, hf_skinny_payloadCapability, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count+= 4;
        proto_tree_add_item(skinny_sub_tree, hf_skinny_transmitOrReceive, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count+= 4;
        proto_tree_add_item(skinny_sub_tree, hf_skinny_levelPreferenceCount, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count+= 4;
        skinny_sub_tree_sav = skinny_sub_tree;
        for ( t = 0; t < MAX_LEVEL_PREFERENCE; t++ ) {
          ti_sub = proto_tree_add_text(skinny_sub_tree_sav, tvb, offset, 20, "levelPreference[%d]", t);
          skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
          proto_tree_add_item(skinny_sub_tree, hf_skinny_transmitPreference, tvb, count, 4, ENC_LITTLE_ENDIAN);
          count+= 4;
          proto_tree_add_item(skinny_sub_tree, hf_skinny_format, tvb, count, 4, ENC_LITTLE_ENDIAN);
          count+= 4;
          proto_tree_add_item(skinny_sub_tree, hf_skinny_maxBitRate, tvb, count, 4, ENC_LITTLE_ENDIAN);
          count+= 4;
          proto_tree_add_item(skinny_sub_tree, hf_skinny_minBitRate, tvb, count, 4, ENC_LITTLE_ENDIAN);
          count+= 4;
          proto_tree_add_item(skinny_sub_tree, hf_skinny_MPI, tvb, count, 4, ENC_LITTLE_ENDIAN);
          count+= 4;
          proto_tree_add_item(skinny_sub_tree, hf_skinny_serviceNumber, tvb, count, 4, ENC_LITTLE_ENDIAN);
          count+= 4;
        }
        val = count;

        /* H.261 */
        ti_sub = proto_tree_add_text(skinny_sub_tree_sav, tvb, offset, 8, "h261VideoCapability");
        skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
        proto_tree_add_item(skinny_sub_tree, hf_skinny_temporalSpatialTradeOffCapability, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count+= 4;
        proto_tree_add_item(skinny_sub_tree, hf_skinny_stillImageTransmission, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count+= 4;

        /* H.263 */
        count = val;
        ti_sub = proto_tree_add_text(skinny_sub_tree_sav, tvb, offset, 8, "h263VideoCapability");
        skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
        proto_tree_add_item(skinny_sub_tree, hf_skinny_h263_capability_bitfield, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count+= 4;
        proto_tree_add_item(skinny_sub_tree, hf_skinny_annexNandWFutureUse, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count+= 4;

        /* Video */
        count = val;
        ti_sub = proto_tree_add_text(skinny_sub_tree_sav, tvb, offset, 8, "vieoVideoCapability");
        skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
        proto_tree_add_item(skinny_sub_tree, hf_skinny_modelNumber, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count+= 4;
        proto_tree_add_item(skinny_sub_tree, hf_skinny_bandwidth, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count+= 4;
      }
      for ( i = 0; i < StationMaxDataCapabilities; i++ ) {
        ti_sub = proto_tree_add_text(skinny_tree, tvb, offset, 20, "dataCaps[%d]", i);
        skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
        proto_tree_add_item(skinny_sub_tree, hf_skinny_payloadCapability, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count+= 4;
        proto_tree_add_item(skinny_sub_tree, hf_skinny_transmitOrReceive, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count+= 4;
        proto_tree_add_item(skinny_sub_tree, hf_skinny_protocolDependentData, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count+= 4;
        proto_tree_add_item(skinny_sub_tree, hf_skinny_maxBitRate, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count+= 4;
      }
      break;

    case 0x0031: /* OpenMultiMediaReceiveChannelAckMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_ORCStatus, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_ipAddress, tvb, offset+16, 4, ENC_BIG_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_portNumber, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+24, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+28, 4, ENC_LITTLE_ENDIAN);
      si->passThruId = tvb_get_letohl(tvb, offset+24);
      si->callId = tvb_get_letohl(tvb, offset+28);
      break;

    case 0x0032: /* ClearConferenceMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_serviceNum, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x0033: /* ServiceURLStatReqMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_serviceURLIndex, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x0034: /* FeatureStatReqMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_featureIndex, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x0035: /* CreateConferenceResMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_createConfResults, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_data_length, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      count = tvb_get_letohl( tvb, offset+20);
      proto_tree_add_uint(skinny_tree, hf_skinny_passThruData, tvb, offset+24, 1, count);
      break;

    case 0x0036: /* DeleteConferenceResMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_deleteConfResults, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x0037: /* ModifyConferenceResMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_modifyConfResults, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_data_length, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      count = tvb_get_letohl( tvb, offset+20);
      proto_tree_add_uint(skinny_tree, hf_skinny_passThruData, tvb, offset+24, 1, count);
      break;

    case 0x0038: /* AddParticipantResMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_addParticipantResults, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      si->callId = tvb_get_letohl(tvb, offset+16);
      break;

    case 0x0039: /* AuditConferenceResMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_last, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_numberOfEntries, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      count = offset+20;
      for ( i = 0; i < StationMaxConference; i++ ) {
        proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count += 4;
        proto_tree_add_item(skinny_tree, hf_skinny_resourceTypes, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count += 4;
        proto_tree_add_item(skinny_tree, hf_skinny_numberOfReservedParticipants, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count += 4;
        proto_tree_add_item(skinny_tree, hf_skinny_numberOfActiveParticipants, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count += 4;
        proto_tree_add_item(skinny_tree, hf_skinny_appID, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count += 4;
        proto_tree_add_uint(skinny_tree, hf_skinny_appConfID, tvb, count, 1, AppConferenceIDSize);
        count += AppConferenceIDSize;
        proto_tree_add_uint(skinny_tree, hf_skinny_appData, tvb, count, 1, AppDataSize);
        count += AppDataSize;
      }
      break;

    case 0x0040: /* AuditParticipantResMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_auditParticipantResults, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_last, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_numberOfEntries, tvb, offset+24, 4, ENC_LITTLE_ENDIAN);
      count = tvb_get_letohl( tvb, offset+24);
      for ( i = 0; i < count; i++ ) {
        proto_tree_add_item(skinny_tree, hf_skinny_participantEntry, tvb, offset+28+(i*4), 4, ENC_LITTLE_ENDIAN);
      }
      break;

    case 0x0041: /* DeviceToUserDataVersion1Message */
      proto_tree_add_item(skinny_tree, hf_skinny_applicationID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_lineInstance, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_transactionID, tvb, offset+24, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_data_length, tvb, offset+28, 4, ENC_LITTLE_ENDIAN);
      count = tvb_get_letohl( tvb, offset+28);
      proto_tree_add_item(skinny_tree, hf_skinny_sequenceFlag, tvb, offset+30, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_displayPriority, tvb, offset+34, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+38, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_appInstanceID, tvb, offset+42, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_routingID, tvb, offset+46, 4, ENC_LITTLE_ENDIAN);
      dissect_skinny_xml(skinny_tree, tvb, pinfo, offset+50, count);
      si->lineId = tvb_get_letohl(tvb, offset+16);
      si->callId = tvb_get_letohl(tvb, offset+20);
      break;

    case 0x0042: /* DeviceToUserDataResponseVersion1Message */
      proto_tree_add_item(skinny_tree, hf_skinny_applicationID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_lineInstance, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_transactionID, tvb, offset+24, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_data_length, tvb, offset+28, 4, ENC_LITTLE_ENDIAN);
      count = tvb_get_letohl( tvb, offset+28);
      proto_tree_add_item(skinny_tree, hf_skinny_sequenceFlag, tvb, offset+30, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_displayPriority, tvb, offset+34, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+38, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_appInstanceID, tvb, offset+42, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_routingID, tvb, offset+46, 4, ENC_LITTLE_ENDIAN);
      dissect_skinny_xml(skinny_tree, tvb, pinfo, offset+50, count);
      si->lineId = tvb_get_letohl(tvb, offset+16);
      si->callId = tvb_get_letohl(tvb, offset+20);
      break;

    case 0x0048: /* DialedPhoneBookMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_directoryIndex, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_lineInstance, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_unknown, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_directoryPhoneNumber, tvb, offset+24, 256, ENC_ASCII|ENC_NA);
      break;


      /*
       *
       *  Call manager -> client messages start here(ish)
       *
       */
    case 0x0081: /* RegisterAckMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_keepAliveInterval, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_dateTemplate, tvb, offset+16, StationDateTemplateSize, ENC_ASCII|ENC_NA);
      proto_tree_add_item(skinny_tree, hf_skinny_secondaryKeepAliveInterval, tvb, offset+24, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x0082: /* StartToneMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_deviceTone, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      /* offset 16 to 19: reserved */
      if (hdr_data_length > 12) {
		  proto_tree_add_item(skinny_tree, hf_skinny_lineInstance, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
		  proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+24, 4, ENC_LITTLE_ENDIAN);
		  si->lineId = tvb_get_letohl(tvb, offset+20);
		  si->callId = tvb_get_letohl(tvb, offset+24);
      }
      break;

    case 0x0083: /* StopToneMessage */
      if (hdr_data_length > 4) {
		  proto_tree_add_item(skinny_tree, hf_skinny_lineInstance, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
		  proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
		  si->lineId = tvb_get_letohl(tvb, offset+12);
		  si->callId = tvb_get_letohl(tvb, offset+16);
      }
      break;

    case 0x0085: /* SetRingerMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_ringType, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_ringMode, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      if (hdr_data_length > 12) {
		  proto_tree_add_item(skinny_tree, hf_skinny_lineInstance, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
		  proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+24, 4, ENC_LITTLE_ENDIAN);
		  si->lineId = tvb_get_letohl(tvb, offset+20);
		  si->callId = tvb_get_letohl(tvb, offset+24);
      }
      break;

    case 0x0086: /* SetLampMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_stimulus, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_stimulusInstance, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_lampMode, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x0087: /* SetHookFlashDetectModeMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_hookFlashDetectMode, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_detectInterval, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x0088: /* SetSpeakerModeMessage */

      proto_tree_add_item(skinny_tree, hf_skinny_speakerMode, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x0089: /* SetMicroModeMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_microphoneMode, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x008a: /* StartMediaTransmission */
      if (hdr_version == BASIC_MSG_TYPE) {
        proto_tree_add_item(skinny_tree, hf_skinny_conferenceID,          tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID,       tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(skinny_tree, hf_skinny_remoteIpAddr,          tvb, offset+20, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(skinny_tree, hf_skinny_remotePortNumber,      tvb, offset+24, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(skinny_tree, hf_skinny_millisecondPacketSize, tvb, offset+28, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(skinny_tree, hf_skinny_payloadCapability,     tvb, offset+32, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(skinny_tree, hf_skinny_precedenceValue,       tvb, offset+36, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(skinny_tree, hf_skinny_silenceSuppression,    tvb, offset+40, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(skinny_tree, hf_skinny_maxFramesPerPacket,    tvb, offset+44, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(skinny_tree, hf_skinny_g723BitRate,           tvb, offset+48, 4, ENC_LITTLE_ENDIAN);
        if (rtp_handle) {
          address src_addr;
          guint32 ipv4_address;

          src_addr.type = AT_IPv4;
          src_addr.len = 4;
          src_addr.data = (char *)&ipv4_address;
          ipv4_address = tvb_get_ipv4(tvb, offset+20);
          rtp_add_address(pinfo, &src_addr, tvb_get_letohl(tvb, offset+24), 0, "Skinny", pinfo->fd->num, is_video, NULL);
        }
        si->passThruId = tvb_get_letohl(tvb, offset+16);
      }
      else if (hdr_version == CM7_MSG_TYPE_A || hdr_version == CM7_MSG_TYPE_B)
      {
        proto_tree_add_item(skinny_tree, hf_skinny_conferenceID,          tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID,       tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
        /* unknown uint32_t stuff */
        proto_tree_add_item(skinny_tree, hf_skinny_remoteIpAddr,          tvb, offset+24, 4, ENC_BIG_ENDIAN);
        /* 3x unknown uint32_t stuff, space for IPv6 maybe */
        proto_tree_add_item(skinny_tree, hf_skinny_remotePortNumber,      tvb, offset+40, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(skinny_tree, hf_skinny_millisecondPacketSize, tvb, offset+44, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(skinny_tree, hf_skinny_payloadCapability,     tvb, offset+48, 4, ENC_LITTLE_ENDIAN);
        /* There is some more... */
        /* proto_tree_add_item(skinny_tree, hf_skinny_precedenceValue,       tvb, offset+52, 4, ENC_LITTLE_ENDIAN); */
        /* proto_tree_add_item(skinny_tree, hf_skinny_silenceSuppression,    tvb, offset+56, 4, ENC_LITTLE_ENDIAN); */
        /* proto_tree_add_item(skinny_tree, hf_skinny_maxFramesPerPacket,    tvb, offset+60, 2, ENC_LITTLE_ENDIAN); */
        /* proto_tree_add_item(skinny_tree, hf_skinny_g723BitRate,           tvb, offset+62, 4, ENC_LITTLE_ENDIAN); */
        if (rtp_handle) {
          address src_addr;
          guint32 ipv4_address;

          src_addr.type = AT_IPv4;
          src_addr.len = 4;
          src_addr.data = (char *)&ipv4_address;
          ipv4_address = tvb_get_ipv4(tvb, offset+24);
          rtp_add_address(pinfo, &src_addr, tvb_get_letohl(tvb, offset+40), 0, "Skinny", pinfo->fd->num, is_video, NULL);
        }
        si->passThruId = tvb_get_letohl(tvb, offset+16);
      }
      break;

    case 0x008b: /* StopMediaTransmission */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      si->passThruId = tvb_get_letohl(tvb, offset+16);
      break;

    case 0x008c: /* StartMediaReception */
      break;

    case 0x008d: /* StopMediaReception */
      break;

    case 0x008f: /* CallInfoMessage */
      i = offset+12;
      proto_tree_add_item(skinny_tree, hf_skinny_callingPartyName, tvb, i, StationMaxNameSize, ENC_ASCII|ENC_NA);
      proto_tree_add_item(skinny_tree, hf_skinny_callingPartyNumber, tvb, i, StationMaxDirnumSize, ENC_ASCII|ENC_NA);
      i += StationMaxNameSize;
      si->callingParty = g_strdup(tvb_format_stringzpad(tvb, i, StationMaxDirnumSize));
      i += StationMaxDirnumSize;
      proto_tree_add_item(skinny_tree, hf_skinny_calledPartyName, tvb, i, StationMaxNameSize, ENC_ASCII|ENC_NA);
      i += StationMaxNameSize;
      proto_tree_add_item(skinny_tree, hf_skinny_calledPartyNumber, tvb, i, StationMaxDirnumSize, ENC_ASCII|ENC_NA);
      si->calledParty = g_strdup(tvb_format_stringzpad(tvb, i, StationMaxDirnumSize));
      i += StationMaxDirnumSize;
      proto_tree_add_item(skinny_tree, hf_skinny_lineInstance, tvb, i, 4, ENC_LITTLE_ENDIAN);
      si->lineId = tvb_get_letohl(tvb, i);
      i += 4;
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, i, 4, ENC_LITTLE_ENDIAN);
      si->callId = tvb_get_letohl(tvb, i);
      i += 4;
      proto_tree_add_item(skinny_tree, hf_skinny_callType, tvb, i, 4, ENC_LITTLE_ENDIAN);
      i += 4;
      proto_tree_add_item(skinny_tree, hf_skinny_originalCalledPartyName, tvb, i, StationMaxNameSize, ENC_ASCII|ENC_NA);
      i += StationMaxNameSize;
      proto_tree_add_item(skinny_tree, hf_skinny_originalCalledParty, tvb, i, StationMaxDirnumSize, ENC_ASCII|ENC_NA);
      i += StationMaxDirnumSize;
      proto_tree_add_item(skinny_tree, hf_cast_lastRedirectingPartyName, tvb, i, StationMaxNameSize, ENC_ASCII|ENC_NA);
      i += StationMaxNameSize;
      proto_tree_add_item(skinny_tree, hf_cast_lastRedirectingParty, tvb, i, StationMaxDirnumSize, ENC_ASCII|ENC_NA);
      i += StationMaxDirnumSize;
      proto_tree_add_item(skinny_tree, hf_cast_originalCdpnRedirectReason, tvb, i, 4, ENC_LITTLE_ENDIAN);
      i += 4;
      proto_tree_add_item(skinny_tree, hf_cast_lastRedirectingReason, tvb, i, 4, ENC_LITTLE_ENDIAN);
      i += 4;
      proto_tree_add_item(skinny_tree, hf_cast_cgpnVoiceMailbox, tvb, i, StationMaxDirnumSize, ENC_ASCII|ENC_NA);
      i += StationMaxDirnumSize;
      proto_tree_add_item(skinny_tree, hf_cast_cdpnVoiceMailbox, tvb, i, StationMaxDirnumSize, ENC_ASCII|ENC_NA);
      i += StationMaxDirnumSize;
      proto_tree_add_item(skinny_tree, hf_cast_originalCdpnVoiceMailbox, tvb, i, StationMaxDirnumSize, ENC_ASCII|ENC_NA);
      i += StationMaxDirnumSize;
      proto_tree_add_item(skinny_tree, hf_cast_lastRedirectingVoiceMailbox, tvb, i, StationMaxDirnumSize, ENC_ASCII|ENC_NA);
      i += StationMaxDirnumSize;
      proto_tree_add_item(skinny_tree, hf_cast_callInstance, tvb, i, 4, ENC_LITTLE_ENDIAN);
      i += 4;
      proto_tree_add_item(skinny_tree, hf_cast_callSecurityStatus, tvb, i, 4, ENC_LITTLE_ENDIAN);
      i += 4;
      val = tvb_get_letohl( tvb, i);
      ti_sub = proto_tree_add_text(skinny_tree, tvb, i, 8, "partyPIRestrictionBits");
      skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
      proto_tree_add_text(skinny_sub_tree, tvb, i, 4, "%s",
	      decode_boolean_bitfield( val, 0x01, 4*8, "Does RestrictCallingPartyName", "Doesn't RestrictCallingPartyName"));
      proto_tree_add_text(skinny_sub_tree, tvb, i, 4, "%s",
	      decode_boolean_bitfield( val, 0x02, 4*8, "Does RestrictCallingPartyNumber", "Doesn't RestrictCallingPartyNumber"));
      proto_tree_add_text(skinny_sub_tree, tvb, i, 4, "%s",
	      decode_boolean_bitfield( val, 0x04, 4*8, "Does RestrictCalledPartyName", "Doesn't RestrictCalledPartyName"));
      proto_tree_add_text(skinny_sub_tree, tvb, i, 4, "%s",
	      decode_boolean_bitfield( val, 0x08, 4*8, "Does RestrictCalledPartyNumber", "Doesn't RestrictCalledPartyNumber"));
      proto_tree_add_text(skinny_sub_tree, tvb, i, 4, "%s",
	      decode_boolean_bitfield( val, 0x10, 4*8, "Does RestrictOriginalCalledPartyName", "Doesn't RestrictOriginalCalledPartyName"));
      proto_tree_add_text(skinny_sub_tree, tvb, i, 4, "%s",
	      decode_boolean_bitfield( val, 0x20, 4*8, "Does RestrictOriginalCalledPartyNumber", "Doesn't RestrictOriginalCalledPartyNumber"));
      proto_tree_add_text(skinny_sub_tree, tvb, i, 4, "%s",
	      decode_boolean_bitfield( val, 0x40, 4*8, "Does RestrictLastRedirectPartyName", "Doesn't RestrictLastRedirectPartyName"));
      proto_tree_add_text(skinny_sub_tree, tvb, i, 4, "%s",
	      decode_boolean_bitfield( val, 0x80, 4*8, "Does RestrictLastRedirectPartyNumber", "Doesn't RestrictLastRedirectPartyNumber"));
      break;

    case 0x0090: /* ForwardStatMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_activeForward, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_lineNumber, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_forwardAllActive, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_forwardNumber, tvb, offset+24, StationMaxDirnumSize, ENC_ASCII|ENC_NA);
      i = offset+24+StationMaxDirnumSize;
      proto_tree_add_item(skinny_tree, hf_skinny_forwardBusyActive, tvb, i, 4, ENC_LITTLE_ENDIAN);
      i += 4;
      proto_tree_add_item(skinny_tree, hf_skinny_forwardNumber, tvb, i, StationMaxDirnumSize, ENC_ASCII|ENC_NA);
      i += StationMaxDirnumSize;
      proto_tree_add_item(skinny_tree, hf_skinny_forwardNoAnswerActive, tvb, i, 4, ENC_LITTLE_ENDIAN);
      i += 4;
      proto_tree_add_item(skinny_tree, hf_skinny_forwardNumber, tvb, i, StationMaxDirnumSize, ENC_ASCII|ENC_NA);
      break;

    case 0x0091: /* SpeedDialStatMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_speedDialNumber, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_speedDialDirNumber, tvb, offset+16, StationMaxDirnumSize, ENC_ASCII|ENC_NA);
      proto_tree_add_item(skinny_tree, hf_skinny_speedDialDisplayName, tvb, offset+40, StationMaxNameSize, ENC_ASCII|ENC_NA);
      break;

    case 0x0092: /* LineStatMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_lineNumber, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_lineDirNumber, tvb, offset+16, StationMaxDirnumSize, ENC_ASCII|ENC_NA);
      proto_tree_add_item(skinny_tree, hf_skinny_lineFullyQualifiedDisplayName, tvb, offset+16+StationMaxDirnumSize, StationMaxNameSize, ENC_ASCII|ENC_NA);
      proto_tree_add_item(skinny_tree, hf_skinny_lineDisplayName, tvb, offset+16+StationMaxDirnumSize+StationMaxNameSize, StationMaxDisplayNameSize, ENC_ASCII|ENC_NA);
      break;

    case 0x0093: /* ConfigStatMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_deviceName, tvb, offset+12, StationMaxDeviceNameSize, ENC_ASCII|ENC_NA);
      i = offset+12+StationMaxDeviceNameSize;
      proto_tree_add_item(skinny_tree, hf_skinny_stationUserId, tvb, i, 4, ENC_LITTLE_ENDIAN);
      i += 4;
      proto_tree_add_item(skinny_tree, hf_skinny_stationInstance, tvb, i, 4, ENC_LITTLE_ENDIAN);
      i += 4;
      proto_tree_add_item(skinny_tree, hf_skinny_userName, tvb, i, StationMaxNameSize, ENC_ASCII|ENC_NA);
      i += StationMaxNameSize;
      proto_tree_add_item(skinny_tree, hf_skinny_serverName, tvb, i, StationMaxNameSize, ENC_ASCII|ENC_NA);
      i += StationMaxNameSize;
      proto_tree_add_item(skinny_tree, hf_skinny_numberLines, tvb, i, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_numberSpeedDials, tvb, i+4, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x0094: /* DefineTimeDate */
      proto_tree_add_item(skinny_tree, hf_skinny_dateYear,   tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_dateMonth,  tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_dayOfWeek,  tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_dateDay,    tvb, offset+24, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_dateHour,   tvb, offset+28, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_dateMinute, tvb, offset+32, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_dateSeconds,tvb, offset+36, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_dateMilliseconds,tvb, offset+40, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_timeStamp, tvb, offset+44, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x0095: /* StartSessionTransmission */
      proto_tree_add_item(skinny_tree, hf_skinny_remoteIpAddr,  tvb, offset+12, 4, ENC_BIG_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_sessionType, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x0096: /* StopSessionTransmission */
      proto_tree_add_item(skinny_tree, hf_skinny_remoteIpAddr,  tvb, offset+12, 4, ENC_BIG_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_sessionType, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x0097: /* ButtonTemplateMessage  */
      /*
       * FIXME
       * This decode prints out oogly subtree maybe? or something besides the VALS...
       * note to self: uint8 != 4 kk thx info ^_^
       *
       */
      proto_tree_add_item(skinny_tree, hf_skinny_buttonOffset, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_buttonCount,  tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_totalButtonCount, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      for (i = 0; i < StationMaxButtonTemplateSize; i++) {
	      proto_tree_add_item(skinny_tree, hf_skinny_buttonInstanceNumber, tvb, offset+(i*2)+24, 1, ENC_LITTLE_ENDIAN);
	      proto_tree_add_item(skinny_tree, hf_skinny_buttonDefinition, tvb, offset+(i*2)+25, 1, ENC_LITTLE_ENDIAN);
      }
      break;

    case 0x0098: /* VersionMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_version, tvb, offset+12, StationMaxVersionSize, ENC_ASCII|ENC_NA);
      break;

    case 0x0099: /* DisplayTextMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_displayMessage, tvb, offset+12, StationMaxDisplayTextSize, ENC_ASCII|ENC_NA);
      break;

    case 0x009a: /* ClearDisplay */
      break;

    case 0x009b: /* CapabilitiesReqMessage */
      break;

    case 0x009c: /* EnunciatorCommandMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_mediaEnunciationType, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      for (i = 0; i < StationMaxDirnumSize; i++) {
	      proto_tree_add_item(skinny_tree, hf_skinny_unknown, tvb, offset+16+(i*4), 4, ENC_LITTLE_ENDIAN);
      }
      i = offset+16+StationMaxDirnumSize;
      proto_tree_add_item(skinny_tree, hf_skinny_mediaEnunciationType, tvb, i, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x009d: /* RegisterRejectMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_displayMessage, tvb, offset+12, StationMaxDisplayTextSize, ENC_ASCII|ENC_NA);
      break;

    case 0x009e: /* ServerResMessage */
      for (i = 0; i < StationMaxServers; i++) {
	      proto_tree_add_item(skinny_tree, hf_skinny_serverIdentifier, tvb, offset+12+(i*StationMaxServers), StationMaxServerNameSize, ENC_ASCII|ENC_NA);
      }
      j = offset+12+(i*StationMaxServers);
      for (i = 0; i < StationMaxServers; i++) {
	      proto_tree_add_item(skinny_tree, hf_skinny_serverListenPort, tvb, j+(i*4), 4,  ENC_LITTLE_ENDIAN);
      }
      j = j+(i*4);
      for (i = 0; i < StationMaxServers; i++) {
	      proto_tree_add_item(skinny_tree, hf_skinny_serverIpAddress, tvb, j+(i*4), 4, ENC_BIG_ENDIAN);
      }
      break;

    case 0x009f: /* Reset */
      proto_tree_add_item(skinny_tree, hf_skinny_deviceResetType, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x0100: /* KeepAliveAckMessage */
      break;

    case 0x0101: /* StartMulticastMediaReception */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_multicastIpAddress, tvb, offset+20, 4, ENC_BIG_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_multicastPort, tvb, offset+24, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_millisecondPacketSize, tvb, offset+28, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_payloadCapability, tvb, offset+32, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_echoCancelType, tvb, offset+36, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_g723BitRate, tvb, offset+40, 4, ENC_LITTLE_ENDIAN);
      si->passThruId = tvb_get_letohl(tvb, offset+16);
      break;

    case 0x0102: /* StartMulticastMediaTransmission */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_multicastIpAddress, tvb, offset+20, 4, ENC_BIG_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_multicastPort, tvb, offset+24, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_millisecondPacketSize, tvb, offset+28, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_payloadCapability, tvb, offset+32, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_precedenceValue, tvb, offset+36, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_silenceSuppression, tvb, offset+40, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_maxFramesPerPacket, tvb, offset+44, 2, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_g723BitRate, tvb, offset+48, 4, ENC_LITTLE_ENDIAN);
      si->passThruId = tvb_get_letohl(tvb, offset+16);
      break;

    case 0x0103: /* StopMulticastMediaReception */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      si->passThruId = tvb_get_letohl(tvb, offset+16);
      break;

    case 0x0104: /* StopMulticastMediaTransmission */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      si->passThruId = tvb_get_letohl(tvb, offset+16);
      break;

    case 0x105: /* OpenReceiveChannel */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID,            tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID,         tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_millisecondPacketSize,   tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_payloadCapability,       tvb, offset+24, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_echoCancelType,          tvb, offset+28, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_g723BitRate,             tvb, offset+32, 4, ENC_LITTLE_ENDIAN);
      si->passThruId = tvb_get_letohl(tvb, offset+16);
      break;

    case 0x0106: /* CloseReceiveChannel */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      si->passThruId = tvb_get_letohl(tvb, offset+16);
      break;

    case 0x0107: /* ConnectionStatisticsReq */

      i = 12;
      proto_tree_add_item(skinny_tree, hf_skinny_directoryNumber, tvb, i, StationMaxDirnumSize, ENC_ASCII|ENC_NA);
      i = 12 + StationMaxDirnumSize;
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, i, 4, ENC_LITTLE_ENDIAN);
      si->callId = tvb_get_letohl(tvb, i);
      i = i+4;
      proto_tree_add_item(skinny_tree, hf_skinny_statsProcessingType, tvb, i, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x0108: /* SoftKeyTemplateResMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_softKeyOffset, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      softKeyCount = tvb_get_letohl(tvb, offset+16);
      proto_tree_add_uint(skinny_tree, hf_skinny_softKeyCount, tvb, offset+16, 4, softKeyCount);
      proto_tree_add_item(skinny_tree, hf_skinny_totalSoftKeyCount, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      for (i = 0; ((i < StationMaxSoftKeyDefinition) && (i < softKeyCount)); i++){
	      proto_tree_add_item(skinny_tree, hf_skinny_softKeyLabel, tvb, offset+(i*20)+24, StationMaxSoftKeyLabelSize, ENC_ASCII|ENC_NA);
	      proto_tree_add_item(skinny_tree, hf_skinny_softKeyEvent, tvb, offset+(i*20)+40, 4, ENC_LITTLE_ENDIAN);
      }
      /* there is more data here, but it doesn't make a whole lot of sense, I imagine
       * it's just some not zero'd out stuff in the packet or...
       */
      break;

    case 0x0109: /* SoftKeySetResMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_softKeySetOffset, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      softKeySetCount = tvb_get_letohl(tvb, offset+16);
      proto_tree_add_uint(skinny_tree, hf_skinny_softKeySetCount, tvb, offset+16, 4, softKeySetCount);
      proto_tree_add_item(skinny_tree, hf_skinny_totalSoftKeySetCount, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      for (i = 0; ((i < StationMaxSoftKeySetDefinition) && (i < softKeySetCount)); i++) {
	      proto_tree_add_uint(skinny_tree, hf_skinny_softKeySetDescription, tvb, offset+24+(i*48) , 1, i);
	      for (j = 0; j < StationMaxSoftKeyIndex; j++) {
	        proto_tree_add_item(skinny_tree, hf_skinny_softKeyTemplateIndex, tvb, offset+24+(i*48)+j, 1, ENC_LITTLE_ENDIAN);
	      }
	      for (j = 0; j < StationMaxSoftKeyIndex; j++) {
	        proto_tree_add_item(skinny_tree, hf_skinny_softKeyInfoIndex, tvb, offset+24+(i*48)+StationMaxSoftKeyIndex+(j*2), 2, ENC_LITTLE_ENDIAN);
	      }
      }
      break;

    case 0x0110: /* SelectSoftKeysMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_lineInstance, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_softKeySetDescription, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      validKeyMask = tvb_get_letohs(tvb, offset + 24);
      skm = proto_tree_add_uint(skinny_tree, hf_skinny_softKeyMap, tvb, offset + 24, 4, validKeyMask);
      skm_tree = proto_item_add_subtree(skm, ett_skinny_softKeyMap);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey0,  tvb, offset + 24, 4, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey1,  tvb, offset + 24, 4, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey2,  tvb, offset + 24, 4, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey3,  tvb, offset + 24, 4, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey4,  tvb, offset + 24, 4, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey5,  tvb, offset + 24, 4, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey6,  tvb, offset + 24, 4, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey7,  tvb, offset + 24, 4, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey8,  tvb, offset + 24, 4, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey9,  tvb, offset + 24, 4, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey10, tvb, offset + 24, 4, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey11, tvb, offset + 24, 4, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey12, tvb, offset + 24, 4, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey13, tvb, offset + 24, 4, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey14, tvb, offset + 24, 4, validKeyMask);
      proto_tree_add_boolean(skm_tree, hf_skinny_softKey15, tvb, offset + 24, 4, validKeyMask);
      si->lineId = tvb_get_letohl(tvb, offset+12);
      si->callId = tvb_get_letohl(tvb, offset+16);
      break;

    case 0x0111: /* CallStateMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_callState, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_lineInstance, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      si->lineId = tvb_get_letohl(tvb, offset+16);
      si->callId = tvb_get_letohl(tvb, offset+20);
      si->callState = tvb_get_letohl(tvb, offset+12);
      break;

    case 0x0112: /* DisplayPromptStatusMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_messageTimeOutValue, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_displayMessage, tvb, offset+16, StationMaxDisplayPromptStatusSize, ENC_ASCII|ENC_NA);
      proto_tree_add_item(skinny_tree, hf_skinny_lineInstance, tvb, offset+48, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+52, 4, ENC_LITTLE_ENDIAN);
      si->lineId = tvb_get_letohl(tvb, offset+48);
      si->callId = tvb_get_letohl(tvb, offset+52);
      break;

    case 0x0113: /* ClearPromptStatusMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_lineInstance  , tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      si->lineId = tvb_get_letohl(tvb, offset+12);
      si->callId = tvb_get_letohl(tvb, offset+16);
      break;

    case 0x0114: /* DisplayNotifyMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_messageTimeOutValue, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_displayMessage, tvb, offset+16, StationMaxDisplayNotifySize , ENC_ASCII|ENC_NA);
      break;

    case 0x0115: /* ClearNotifyMessage */
      break;

    case 0x0116: /* ActivateCallPlaneMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_lineInstance, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      si->lineId = tvb_get_letohl(tvb, offset+12);
      break;

    case 0x0117: /* DeactivateCallPlaneMessage */
      break;

    case 0x0118: /* UnregisterAckMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_deviceUnregisterStatus, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x0119: /* BackSpaceReqMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_lineInstance, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      si->lineId = tvb_get_letohl(tvb, offset+12);
      si->callId = tvb_get_letohl(tvb, offset+16);
      break;

    case 0x011a: /* RegisterTokenAck */
      break;

    case 0x011B: /* RegisterTokenReject */
      proto_tree_add_item(skinny_tree, hf_skinny_tokenRejWaitTime, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x011C: /* StartMediaFailureDetection */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_millisecondPacketSize, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_payloadCapability, tvb, offset+24, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_echoCancelType, tvb, offset+28, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_g723BitRate, tvb, offset+32, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+34, 4, ENC_LITTLE_ENDIAN);
      si->passThruId = tvb_get_letohl(tvb, offset+16);
      si->callId = tvb_get_letohl(tvb, offset+34);
      break;

    case 0x011D: /* DialedNumberMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_calledPartyNumber, tvb, offset+12, StationMaxDirnumSize, ENC_ASCII|ENC_NA);
      proto_tree_add_item(skinny_tree, hf_skinny_lineInstance, tvb, offset+12+StationMaxDirnumSize, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+12+StationMaxDirnumSize+4, 4, ENC_LITTLE_ENDIAN);
      si->lineId = tvb_get_letohl(tvb, offset+12+StationMaxDirnumSize);
      si->callId = tvb_get_letohl(tvb, offset+16+StationMaxDirnumSize);
      break;

    case 0x011E: /* UserToDeviceDataMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_applicationID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_lineInstance, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_transactionID, tvb, offset+24, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_data_length, tvb, offset+28, 4, ENC_LITTLE_ENDIAN);
      count = tvb_get_letohl( tvb, offset+28);
      dissect_skinny_xml(skinny_tree, tvb, pinfo, offset+30, count);
      si->lineId = tvb_get_letohl(tvb, offset+16);
      si->callId = tvb_get_letohl(tvb, offset+20);
      break;

    case 0x011F: /* FeatureStatMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_featureIndex, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_featureID, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_featureTextLabel, tvb, offset+20, StationMaxNameSize, ENC_ASCII|ENC_NA);
      proto_tree_add_item(skinny_tree, hf_skinny_featureStatus, tvb, offset+20+StationMaxNameSize, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x0120: /* DisplayPriNotifyMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_messageTimeOutValue, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_priority, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_notify, tvb, offset+16, StationMaxDisplayNotifySize, ENC_ASCII|ENC_NA);
      break;

    case 0x0121: /* ClearPriNotifyMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_priority, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x0122: /* StartAnnouncementMessage */
      count = offset+12;
      for ( i = 0; i < MaxAnnouncementList; i++ ) {
        proto_tree_add_item(skinny_tree, hf_skinny_locale, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count += 4;
        proto_tree_add_item(skinny_tree, hf_skinny_country, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count += 4;
        proto_tree_add_item(skinny_tree, hf_skinny_deviceTone, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count += 4;
      }
      proto_tree_add_item(skinny_tree, hf_skinny_endOfAnnAck, tvb, count, 4, ENC_LITTLE_ENDIAN);
      count += 4;
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, count, 4, ENC_LITTLE_ENDIAN);
      count += 4;

      for ( i = 0; i < StationMaxMonitorParties; i++ ) {
        proto_tree_add_item(skinny_tree, hf_skinny_matrixConfPartyID, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count += 4;
      }
      proto_tree_add_item(skinny_tree, hf_skinny_hearingConfPartyMask, tvb, count, 4, ENC_LITTLE_ENDIAN);
      count += 4;
      proto_tree_add_item(skinny_tree, hf_skinny_annPlayMode, tvb, count, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x0123: /* StopAnnouncementMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x0124: /* AnnouncementFinishMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_annPlayStatus, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x0127: /* NotifyDtmfToneMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_deviceTone, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      si->passThruId = tvb_get_letohl(tvb, offset+20);
      break;

    case 0x0128: /* SendDtmfToneMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_deviceTone, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      si->passThruId = tvb_get_letohl(tvb, offset+20);
      break;

    case 0x0129: /* SubscribeDtmfPayloadReqMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_payloadDtmf, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      si->passThruId = tvb_get_letohl(tvb, offset+20);
      break;

    case 0x012A: /* SubscribeDtmfPayloadResMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_payloadDtmf, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      si->passThruId = tvb_get_letohl(tvb, offset+20);
      break;

    case 0x012B: /* SubscribeDtmfPayloadErrMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_payloadDtmf, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      si->passThruId = tvb_get_letohl(tvb, offset+20);
      break;

    case 0x012C: /* UnSubscribeDtmfPayloadReqMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_payloadDtmf, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      si->passThruId = tvb_get_letohl(tvb, offset+20);
      break;

    case 0x012D: /* UnSubscribeDtmfPayloadResMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_payloadDtmf, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      si->passThruId = tvb_get_letohl(tvb, offset+20);
      break;

    case 0x012E: /* UnSubscribeDtmfPayloadErrMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_payloadDtmf, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      si->passThruId = tvb_get_letohl(tvb, offset+20);
      break;

    case 0x012F: /* ServiceURLStatMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_serviceURLIndex, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_serviceURL, tvb, offset+16, StationMaxServiceURLSize, ENC_ASCII|ENC_NA);
      proto_tree_add_item(skinny_tree, hf_skinny_serviceURLDisplayName, tvb, offset+16+StationMaxServiceURLSize, StationMaxNameSize, ENC_ASCII|ENC_NA);
      break;

    case 0x0130: /* CallSelectStatMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_callSelectStat, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_lineInstance, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      si->lineId = tvb_get_letohl(tvb, offset+16);
      si->callId = tvb_get_letohl(tvb, offset+20);
      break;

    case 0x0131: /* OpenMultiMediaChannelMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_payloadCapability, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_lineInstance, tvb, offset+24, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+28, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_payload_rfc_number, tvb, offset+32, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_payloadType, tvb, offset+36, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_isConferenceCreator, tvb, offset+40, 4, ENC_LITTLE_ENDIAN);
      si->passThruId = tvb_get_letohl(tvb, offset+16);
      si->lineId = tvb_get_letohl(tvb, offset+24);
      si->callId = tvb_get_letohl(tvb, offset+28);

      /* add audio part of union */
		  ti_sub = proto_tree_add_text(skinny_tree, tvb, offset, 12, "audioParameters");
		  skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
      proto_tree_add_item(skinny_sub_tree, hf_skinny_millisecondPacketSize, tvb, offset+44, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_sub_tree, hf_skinny_echoCancelType, tvb, offset+48, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_sub_tree, hf_skinny_g723BitRate, tvb, offset+52, 4, ENC_LITTLE_ENDIAN);

      /* add video part of union */
		  ti_sub = proto_tree_add_text(skinny_tree, tvb, offset, 30, "vidParameters");
		  skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
      proto_tree_add_item(skinny_sub_tree, hf_skinny_bitRate, tvb, offset+44, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_sub_tree, hf_skinny_pictureFormatCount, tvb, offset+48, 4, ENC_LITTLE_ENDIAN);
      skinny_sub_tree_sav = skinny_sub_tree;
      count = offset+52;
      for ( i = 0; i < MAX_PICTURE_FORMAT; i++ ) {
		    ti_sub = proto_tree_add_text(skinny_sub_tree_sav, tvb, offset, 8 * MAX_PICTURE_FORMAT, "pictureFormat[%d]", i);
		    skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
        proto_tree_add_item(skinny_sub_tree, hf_skinny_format, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count += 4;
        proto_tree_add_item(skinny_sub_tree, hf_skinny_MPI, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count += 4;
      }
      skinny_sub_tree = skinny_sub_tree_sav;
      proto_tree_add_item(skinny_sub_tree, hf_skinny_confServiceNum, tvb, count, 4, ENC_LITTLE_ENDIAN);
      count += 4;

      val = count;
      /* add H261 part of union */
		  ti_sub = proto_tree_add_text(skinny_sub_tree_sav, tvb, offset, 8, "h261VideoCapability");
		  skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
	    proto_tree_add_item(skinny_sub_tree, hf_skinny_temporalSpatialTradeOffCapability, tvb, count, 4, ENC_LITTLE_ENDIAN);
      count += 4;
	    proto_tree_add_item(skinny_sub_tree, hf_skinny_stillImageTransmission, tvb, count, 4, ENC_LITTLE_ENDIAN);

      /* add H263 part of union */
      count = val;
		  ti_sub = proto_tree_add_text(skinny_sub_tree_sav, tvb, offset, 8, "h263VideoCapability");
		  skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
	    proto_tree_add_item(skinny_sub_tree, hf_skinny_h263_capability_bitfield, tvb, count, 4, ENC_LITTLE_ENDIAN);
      count += 4;
	    proto_tree_add_item(skinny_sub_tree, hf_skinny_annexNandWFutureUse, tvb, count, 4, ENC_LITTLE_ENDIAN);

      /* add Vieo part of union */
      count = val;
		  ti_sub = proto_tree_add_text(skinny_sub_tree_sav, tvb, offset, 8, "vieoVideoCapability");
		  skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
	    proto_tree_add_item(skinny_sub_tree, hf_skinny_modelNumber, tvb, count, 4, ENC_LITTLE_ENDIAN);
      count += 4;
	    proto_tree_add_item(skinny_sub_tree, hf_skinny_bandwidth, tvb, count, 4, ENC_LITTLE_ENDIAN);

      /* add data part of union */
		  ti_sub = proto_tree_add_text(skinny_tree, tvb, offset, 8, "dataParameters");
		  skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
	    proto_tree_add_item(skinny_sub_tree, hf_skinny_protocolDependentData, tvb, offset+44, 4, ENC_LITTLE_ENDIAN);
	    proto_tree_add_item(skinny_sub_tree, hf_skinny_maxBitRate, tvb, offset+48, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x0132: /* StartMultiMediaTransmission */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_payloadCapability, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_ipAddress, tvb, offset+24, 4, ENC_BIG_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_portNumber, tvb, offset+28, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+32, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_payload_rfc_number, tvb, offset+36, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_payloadType, tvb, offset+40, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_DSCPValue, tvb, offset+44, 4, ENC_LITTLE_ENDIAN);
      si->passThruId = tvb_get_letohl(tvb, offset+16);
      si->callId = tvb_get_letohl(tvb, offset+32);

      /* add audio part of union */
		  ti_sub = proto_tree_add_text(skinny_tree, tvb, offset, 12, "audioParameters");
		  skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
      proto_tree_add_item(skinny_sub_tree, hf_skinny_millisecondPacketSize, tvb, offset+48, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_sub_tree, hf_skinny_echoCancelType, tvb, offset+52, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_sub_tree, hf_skinny_g723BitRate, tvb, offset+56, 4, ENC_LITTLE_ENDIAN);

      /* add video part of union */
		  ti_sub = proto_tree_add_text(skinny_tree, tvb, offset, 30, "vidParameters");
		  skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
      proto_tree_add_item(skinny_sub_tree, hf_skinny_bitRate, tvb, offset+48, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_sub_tree, hf_skinny_pictureFormatCount, tvb, offset+52, 4, ENC_LITTLE_ENDIAN);
      skinny_sub_tree_sav = skinny_sub_tree;
      count = offset+56;
      for ( i = 0; i < MAX_PICTURE_FORMAT; i++ ) {
		    ti_sub = proto_tree_add_text(skinny_sub_tree_sav, tvb, offset, 8 * MAX_PICTURE_FORMAT, "pictureFormat[%d]", i);
		    skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
        proto_tree_add_item(skinny_sub_tree, hf_skinny_format, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count += 4;
        proto_tree_add_item(skinny_sub_tree, hf_skinny_MPI, tvb, count, 4, ENC_LITTLE_ENDIAN);
        count += 4;
      }
      skinny_sub_tree = skinny_sub_tree_sav;
      proto_tree_add_item(skinny_sub_tree, hf_skinny_confServiceNum, tvb, count, 4, ENC_LITTLE_ENDIAN);
      count += 4;

      val = count;
      /* add H261 part of union */
		  ti_sub = proto_tree_add_text(skinny_sub_tree_sav, tvb, offset, 8, "h261VideoCapability");
		  skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
	    proto_tree_add_item(skinny_sub_tree, hf_skinny_temporalSpatialTradeOffCapability, tvb, count, 4, ENC_LITTLE_ENDIAN);
      count += 4;
	    proto_tree_add_item(skinny_sub_tree, hf_skinny_stillImageTransmission, tvb, count, 4, ENC_LITTLE_ENDIAN);

      /* add H263 part of union */
      count = val;
		  ti_sub = proto_tree_add_text(skinny_sub_tree_sav, tvb, offset, 8, "h263VideoCapability");
		  skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
	    proto_tree_add_item(skinny_sub_tree, hf_skinny_h263_capability_bitfield, tvb, count, 4, ENC_LITTLE_ENDIAN);
      count += 4;
	    proto_tree_add_item(skinny_sub_tree, hf_skinny_annexNandWFutureUse, tvb, count, 4, ENC_LITTLE_ENDIAN);

      /* add Vieo part of union */
      count = val;
		  ti_sub = proto_tree_add_text(skinny_sub_tree_sav, tvb, offset, 8, "vieoVideoCapability");
		  skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
	    proto_tree_add_item(skinny_sub_tree, hf_skinny_modelNumber, tvb, count, 4, ENC_LITTLE_ENDIAN);
      count += 4;
	    proto_tree_add_item(skinny_sub_tree, hf_skinny_bandwidth, tvb, count, 4, ENC_LITTLE_ENDIAN);

      /* add data part of union */
		  ti_sub = proto_tree_add_text(skinny_tree, tvb, offset, 8, "dataParameters");
		  skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
	    proto_tree_add_item(skinny_sub_tree, hf_skinny_protocolDependentData, tvb, offset+48, 4, ENC_LITTLE_ENDIAN);
	    proto_tree_add_item(skinny_sub_tree, hf_skinny_maxBitRate, tvb, offset+52, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x0133: /* StopMultiMediaTransmission */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      si->passThruId = tvb_get_letohl(tvb, offset+16);
      si->callId = tvb_get_letohl(tvb, offset+20);
      break;

    case 0x0134: /* MiscellaneousCommandMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_miscCommandType, tvb, offset+24, 4, ENC_LITTLE_ENDIAN);
      si->passThruId = tvb_get_letohl(tvb, offset+16);
      si->callId = tvb_get_letohl(tvb, offset+20);

      /* show videoFreezePicture */
      /* not sure of format */

      /* show videoFastUpdatePicture */
      /* not sure of format */

      /* show videoFastUpdateGOB */
		  ti_sub = proto_tree_add_text(skinny_tree, tvb, offset, 8, "videoFastUpdateGOB");
		  skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
      proto_tree_add_item(skinny_sub_tree, hf_skinny_firstGOB, tvb, offset+28, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_sub_tree, hf_skinny_numberOfGOBs, tvb, offset+32, 4, ENC_LITTLE_ENDIAN);

      /* show videoFastUpdateMB */
		  ti_sub = proto_tree_add_text(skinny_tree, tvb, offset, 8, "videoFastUpdateGOB");
		  skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
      proto_tree_add_item(skinny_sub_tree, hf_skinny_firstGOB, tvb, offset+28, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_sub_tree, hf_skinny_firstMB, tvb, offset+32, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_sub_tree, hf_skinny_numberOfMBs, tvb, offset+36, 4, ENC_LITTLE_ENDIAN);

      /* show lostPicture */
		  ti_sub = proto_tree_add_text(skinny_tree, tvb, offset, 8, "lostPicture");
		  skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
      proto_tree_add_item(skinny_sub_tree, hf_skinny_pictureNumber, tvb, offset+28, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_sub_tree, hf_skinny_longTermPictureIndex, tvb, offset+32, 4, ENC_LITTLE_ENDIAN);

      /* show lostPartialPicture */
		  ti_sub = proto_tree_add_text(skinny_tree, tvb, offset, 8, "lostPartialPicture");
		  skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
      proto_tree_add_item(skinny_sub_tree, hf_skinny_pictureNumber, tvb, offset+28, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_sub_tree, hf_skinny_longTermPictureIndex, tvb, offset+32, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_sub_tree, hf_skinny_firstMB, tvb, offset+36, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_sub_tree, hf_skinny_numberOfMBs, tvb, offset+40, 4, ENC_LITTLE_ENDIAN);

      /* show recoveryReferencePicture */
		  ti_sub = proto_tree_add_text(skinny_tree, tvb, offset, 8, "recoveryReferencePicture");
		  skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
      proto_tree_add_item(skinny_sub_tree, hf_skinny_recoveryReferencePictureCount, tvb, offset+28, 4, ENC_LITTLE_ENDIAN);
      skinny_sub_tree_sav = skinny_sub_tree;
      for ( i = 0; i < MAX_REFERENCE_PICTURE; i++ ) {
		    ti_sub = proto_tree_add_text(skinny_sub_tree_sav, tvb, offset, 8, "recoveryReferencePicture[%d]", i);
		    skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
        proto_tree_add_item(skinny_sub_tree, hf_skinny_pictureNumber, tvb, offset+32+(i*8), 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(skinny_sub_tree, hf_skinny_longTermPictureIndex, tvb, offset+36+(i*8), 4, ENC_LITTLE_ENDIAN);
      }

      /* show temporalSpatialTradeOff */
		  ti_sub = proto_tree_add_text(skinny_tree, tvb, offset, 4, "temporalSpatialTradeOff");
		  skinny_sub_tree = proto_item_add_subtree(ti_sub, ett_skinny_tree);
      proto_tree_add_item(skinny_sub_tree, hf_skinny_temporalSpatialTradeOff, tvb, offset+28, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x0135: /* FlowControlCommandMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_maxBitRate, tvb, offset+24, 4, ENC_LITTLE_ENDIAN);
      si->passThruId = tvb_get_letohl(tvb, offset+16);
      si->callId = tvb_get_letohl(tvb, offset+20);
      break;

    case 0x0136: /* CloseMultiMediaReceiveChannel */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_passThruPartyID, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      si->passThruId = tvb_get_letohl(tvb, offset+16);
      si->callId = tvb_get_letohl(tvb, offset+20);
      break;

    case 0x0137: /* CreateConferenceReqMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_numberOfReservedParticipants, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_resourceTypes, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_appID, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      count = offset+24;
      proto_tree_add_uint(skinny_tree, hf_skinny_appConfID, tvb, count, 1, AppConferenceIDSize);
      count += AppConferenceIDSize;
      proto_tree_add_uint(skinny_tree, hf_skinny_appData, tvb, count, 1, AppDataSize);
      count += AppDataSize;
      proto_tree_add_item(skinny_tree, hf_skinny_data_length, tvb, count, 4, ENC_LITTLE_ENDIAN);
      val = tvb_get_letohl( tvb, count);
      count += 4;
      proto_tree_add_uint(skinny_tree, hf_skinny_passThruData, tvb, count, 1, val);
      break;

    case 0x0138: /* DeleteConferenceReqMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x0139: /* ModifyConferenceReqMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_numberOfReservedParticipants, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_appID, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      count = offset+24;
      proto_tree_add_uint(skinny_tree, hf_skinny_appConfID, tvb, count, 1, AppConferenceIDSize);
      count += AppConferenceIDSize;
      proto_tree_add_uint(skinny_tree, hf_skinny_appData, tvb, count, 1, AppDataSize);
      count += AppDataSize;
      proto_tree_add_item(skinny_tree, hf_skinny_data_length, tvb, count, 4, ENC_LITTLE_ENDIAN);
      val = tvb_get_letohl( tvb, count);
      count += 4;
      proto_tree_add_uint(skinny_tree, hf_skinny_passThruData, tvb, count, 1, val);
      break;

    case 0x013A: /* AddParticipantReqMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      si->callId = tvb_get_letohl(tvb, offset+16);
      break;

    case 0x013B: /* DropParticipantReqMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      si->callId = tvb_get_letohl(tvb, offset+16);
      break;

    case 0x013C: /* AuditConferenceReqMessage */
      break;

    case 0x013D: /* AuditParticipantReqMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x013F: /* UserToDeviceDataVersion1Message */
      proto_tree_add_item(skinny_tree, hf_skinny_applicationID, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_lineInstance, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_transactionID, tvb, offset+24, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_data_length, tvb, offset+28, 4, ENC_LITTLE_ENDIAN);
      count = tvb_get_letohl( tvb, offset+28);
      proto_tree_add_item(skinny_tree, hf_skinny_sequenceFlag, tvb, offset+30, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_displayPriority, tvb, offset+34, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_conferenceID, tvb, offset+38, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_appInstanceID, tvb, offset+42, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_routingID, tvb, offset+46, 4, ENC_LITTLE_ENDIAN);
      dissect_skinny_xml(skinny_tree, tvb, pinfo, offset+50, count);
      si->lineId = tvb_get_letohl(tvb, offset+16);
      si->callId = tvb_get_letohl(tvb, offset+20);
      break;

    case 0x014A: /* CM5CallInfoMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_lineInstance, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callIdentifier, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_callType, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      si->lineId = tvb_get_letohl(tvb, offset+12);
      /* 5x unknown uint32_t stuff */
        /* strings */
        {
        i = offset+44;
        if(hdr_version == BASIC_MSG_TYPE)
        {
          /* 8x party numbers */
          count = tvb_strnlen(tvb, i, -1)+1;
          proto_tree_add_item(skinny_tree, hf_skinny_callingPartyNumber, tvb, i, count, ENC_ASCII|ENC_NA);
          i += count;
          count = tvb_strnlen(tvb, i, -1)+1;
          proto_tree_add_item(skinny_tree, hf_skinny_calledPartyNumber, tvb, i, count, ENC_ASCII|ENC_NA);
          i += count;
          count = tvb_strnlen(tvb, i, -1)+1;
          proto_tree_add_item(skinny_tree, hf_skinny_originalCalledParty, tvb, i, count, ENC_ASCII|ENC_NA);
          i += count;
          count = tvb_strnlen(tvb, i, -1)+1;
          proto_tree_add_item(skinny_tree, hf_cast_lastRedirectingParty, tvb, i, count, ENC_ASCII|ENC_NA);
          i += count;
          count = tvb_strnlen(tvb, i, -1)+1;
          proto_tree_add_item(skinny_tree, hf_cast_cgpnVoiceMailbox, tvb, i, count, ENC_ASCII|ENC_NA);
          i += count;
          count = tvb_strnlen(tvb, i, -1)+1;
          proto_tree_add_item(skinny_tree, hf_cast_cdpnVoiceMailbox, tvb, i, count, ENC_ASCII|ENC_NA);
          i += count;
          count = tvb_strnlen(tvb, i, -1)+1;
          proto_tree_add_item(skinny_tree, hf_cast_originalCdpnVoiceMailbox, tvb, i, count, ENC_ASCII|ENC_NA);
          i += count;
          count = tvb_strnlen(tvb, i, -1)+1;
          proto_tree_add_item(skinny_tree, hf_cast_lastRedirectingVoiceMailbox, tvb, i, count, ENC_ASCII|ENC_NA);
          i += count;
          /* 4x party names */
          count = tvb_strnlen(tvb, i, -1)+1;
          proto_tree_add_item(skinny_tree, hf_skinny_callingPartyName, tvb, i, count, ENC_ASCII|ENC_NA);
          i += count;
          count = tvb_strnlen(tvb, i, -1)+1;
          proto_tree_add_item(skinny_tree, hf_skinny_calledPartyName, tvb, i, count, ENC_ASCII|ENC_NA);
          i += count;
          count = tvb_strnlen(tvb, i, -1)+1;
          proto_tree_add_item(skinny_tree, hf_skinny_originalCalledPartyName, tvb, i, count, ENC_ASCII|ENC_NA);
          i += count;
          count = tvb_strnlen(tvb, i, -1)+1;
          proto_tree_add_item(skinny_tree, hf_cast_lastRedirectingPartyName, tvb, i, count, ENC_ASCII|ENC_NA);
        }
        else if(hdr_version == CM7_MSG_TYPE_B || hdr_version == CM7_MSG_TYPE_A)
        {/* I'm not sure. Not enough examples. */
          /* 8x party numbers */
          count = tvb_strnlen(tvb, i, -1)+1;
          proto_tree_add_item(skinny_tree, hf_skinny_callingPartyNumber, tvb, i, count, ENC_ASCII|ENC_NA);
          i += count;
          count = tvb_strnlen(tvb, i, -1)+1;
          proto_tree_add_item(skinny_tree, hf_cast_cgpnVoiceMailbox, tvb, i, count, ENC_ASCII|ENC_NA);
          i += count;
          count = tvb_strnlen(tvb, i, -1)+1;
          proto_tree_add_item(skinny_tree, hf_skinny_calledPartyNumber, tvb, i, count, ENC_ASCII|ENC_NA);
          i += count;
          count = tvb_strnlen(tvb, i, -1)+1;
          proto_tree_add_item(skinny_tree, hf_skinny_originalCalledParty, tvb, i, count, ENC_ASCII|ENC_NA);
          i += count;
          count = tvb_strnlen(tvb, i, -1)+1;
          proto_tree_add_item(skinny_tree, hf_cast_lastRedirectingParty, tvb, i, count, ENC_ASCII|ENC_NA);
          i += count;
          count = tvb_strnlen(tvb, i, -1)+1;
          proto_tree_add_item(skinny_tree, hf_cast_cdpnVoiceMailbox, tvb, i, count, ENC_ASCII|ENC_NA);
          i += count;
          count = tvb_strnlen(tvb, i, -1)+1;
          proto_tree_add_item(skinny_tree, hf_cast_originalCdpnVoiceMailbox, tvb, i, count, ENC_ASCII|ENC_NA);
          i += count;
          count = tvb_strnlen(tvb, i, -1)+1;
          proto_tree_add_item(skinny_tree, hf_cast_lastRedirectingVoiceMailbox, tvb, i, count, ENC_ASCII|ENC_NA);
          i += count;
          /* 4x party names */
          count = tvb_strnlen(tvb, i, -1)+1;
          proto_tree_add_item(skinny_tree, hf_skinny_callingPartyName, tvb, i, count, ENC_ASCII|ENC_NA);
          i += count;
          count = tvb_strnlen(tvb, i, -1)+1;
          proto_tree_add_item(skinny_tree, hf_skinny_calledPartyName, tvb, i, count, ENC_ASCII|ENC_NA);
          i += count;
          count = tvb_strnlen(tvb, i, -1)+1;
          proto_tree_add_item(skinny_tree, hf_skinny_originalCalledPartyName, tvb, i, count, ENC_ASCII|ENC_NA);
          i += count;
          count = tvb_strnlen(tvb, i, -1)+1;
          proto_tree_add_item(skinny_tree, hf_cast_lastRedirectingPartyName, tvb, i, count, ENC_ASCII|ENC_NA);
        }
      }
      break;

    case 0x0152: /* DialedPhoneBookAckMessage */
      proto_tree_add_item(skinny_tree, hf_skinny_directoryIndex, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_lineInstance, tvb, offset+16, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_unknown, tvb, offset+20, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(skinny_tree, hf_skinny_unknown, tvb, offset+24, 4, ENC_LITTLE_ENDIAN);
      break;

    case 0x015A: /* XMLAlarmMessage */
      dissect_skinny_xml(skinny_tree, tvb, pinfo, offset+12, hdr_data_length-4);
      break;

    default:
      proto_tree_add_item(skinny_tree, hf_skinny_rawData, tvb, offset+12, hdr_data_length-4, ENC_NA);
      break;
    }
  }
  tap_queue_packet(skinny_tap, pinfo, si);
}


/* Code to actually dissect the packets */
static gboolean
dissect_skinny(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  /* The general structure of a packet: {IP-Header|TCP-Header|n*SKINNY}
   * SKINNY-Packet: {Header(Size, Reserved)|Data(MessageID, Message-Data)}
   */
  /* Header fields */
  guint32 hdr_data_length;
  guint32 hdr_version;

  /* check, if this is really an SKINNY packet, they start with a length + 0 */

  if (tvb_length_remaining(tvb, 0) < 8)
  {
    return FALSE;
  }
  /* get relevant header information */
  hdr_data_length = tvb_get_letohl(tvb, 0);
  hdr_version     = tvb_get_letohl(tvb, 4);

  /*  data_size       = MIN(8+hdr_data_length, tvb_length(tvb)) - 0xC; */

  if ((hdr_data_length < 4) ||
      ((hdr_version != BASIC_MSG_TYPE) &&
       (hdr_version != CM7_MSG_TYPE_A) &&
       (hdr_version != CM7_MSG_TYPE_B))
     )
  {
      /* Not an SKINNY packet, just happened to use the same port */
    return FALSE;
  }

  /* Make entries in Protocol column and Info column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SKINNY");

  col_set_str(pinfo->cinfo, COL_INFO, "Skinny Client Control Protocol");

  tcp_dissect_pdus(tvb, pinfo, tree, skinny_desegment, 4,
	get_skinny_pdu_len, dissect_skinny_pdu);

  return TRUE;
}

/* Register the protocol with Wireshark */
void
proto_register_skinny(void)
{

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_skinny_data_length,
      { "Data length", "skinny.data_length",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Number of bytes in the data portion.",
	HFILL }
    },
    { &hf_skinny_hdr_version,
      { "Header version", "skinny.hdr_version",
	FT_UINT32, BASE_HEX, VALS(header_version), 0x0,
	NULL,
	HFILL }
    },
    /* FIXME: Enable use of message name ???  */
    { &hf_skinny_messageid,
      { "Message ID", "skinny.messageid",
	FT_UINT32, BASE_HEX|BASE_EXT_STRING, &message_id_ext, 0x0,
	"The function requested/done with this message.",
	HFILL }
    },

    { &hf_skinny_deviceName,
      { "Device name", "skinny.deviceName",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The device name of the phone.",
	HFILL }
    },

    { &hf_skinny_stationUserId,
      { "Station user ID", "skinny.stationUserId",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_stationInstance,
      { "Station instance", "skinny.stationInstance",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_deviceType,
      { "Device type", "skinny.deviceType",
	FT_UINT32, BASE_DEC|BASE_EXT_STRING, &deviceTypes_ext, 0x0,
	"DeviceType of the station.",
	HFILL }
    },

    { &hf_skinny_maxStreams,
      { "Max streams", "skinny.maxStreams",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"32 bit unsigned integer indicating the maximum number of simultansous RTP duplex streams that the client can handle.",
	HFILL }
    },

    { &hf_skinny_stationIpPort,
      { "Station ip port", "skinny.stationIpPort",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_stationKeypadButton,
      { "Keypad button", "skinny.stationKeypadButton",
	FT_UINT32, BASE_HEX|BASE_EXT_STRING, &keypadButtons_ext, 0x0,
	"The button pressed on the phone.",
	HFILL }
    },

    { &hf_skinny_calledPartyNumber,
      { "Called party number", "skinny.calledParty",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The number called.",
	HFILL }
    },

    { &hf_skinny_stimulus,
      { "Stimulus", "skinny.stimulus",
	FT_UINT32, BASE_HEX|BASE_EXT_STRING, &deviceStimuli_ext, 0x0,
	"Reason for the device stimulus message.",
	HFILL }
    },

    { &hf_skinny_stimulusInstance,
      { "Stimulus instance", "skinny.stimulusInstance",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_lineNumber,
      { "Line number", "skinny.lineNumber",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_speedDialNumber,
      { "Speed-dial number", "skinny.speedDialNumber",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Which speed dial number",
	HFILL }
    },

    { &hf_skinny_capCount,
      { "Capabilities count", "skinny.capCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"How many capabilities",
	HFILL }
    },

    { &hf_skinny_payloadCapability,
      { "Payload capability", "skinny.payloadCapability",
	FT_UINT32, BASE_DEC|BASE_EXT_STRING, &mediaPayloads_ext, 0x0,
	"The payload capability for this media capability structure.",
	HFILL }
    },

    { &hf_skinny_maxFramesPerPacket,
      { "Max frames per packet", "skinny.maxFramesPerPacket",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_alarmSeverity,
      { "Alarm severity", "skinny.alarmSeverity",
	FT_UINT32, BASE_DEC|BASE_EXT_STRING, &alarmSeverities_ext, 0x0,
	"The severity of the reported alarm.",
	HFILL }
    },

    { &hf_skinny_alarmParam1,
      { "Alarm param 1", "skinny.alarmParam1",
	FT_UINT32, BASE_HEX, NULL, 0x0,
	"An as yet undecoded param1 value from the alarm message",
	HFILL }
    },

    { &hf_skinny_alarmParam2,
      { "Alarm param 2", "skinny.alarmParam2",
	FT_IPv4, BASE_NONE, NULL, 0x0,
	"This is the second alarm parameter i think it's an ip address",
	HFILL }
    },

    { &hf_skinny_receptionStatus,
      { "Reception status", "skinny.receptionStatus",
	FT_UINT32, BASE_DEC, VALS(multicastMediaReceptionStatus), 0x0,
	"The current status of the multicast media.",
	HFILL }
    },

    { &hf_skinny_passThruPartyID,
      { "Pass-thru party ID", "skinny.passThruPartyID",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_ORCStatus,
      { "Opened receive-channel status", "skinny.openReceiveChannelStatus",
	FT_UINT32, BASE_DEC, VALS(openReceiveChanStatus), 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_ipAddress,
      { "IP address", "skinny.ipAddress",
	FT_IPv4, BASE_NONE, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_portNumber,
      { "Port number", "skinny.portNumber",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_statsProcessingType,
      { "Stats processing type", "skinny.statsProcessingType",
	FT_UINT32, BASE_DEC, VALS(statsProcessingTypes), 0x0,
	"What do do after you send the stats.",
	HFILL }
    },

    { &hf_skinny_callIdentifier,
      { "Call identifier", "skinny.callIdentifier",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_packetsSent,
      { "Packets sent", "skinny.packetsSent",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_octetsSent,
      { "Octets sent", "skinny.octetsSent",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_packetsRecv,
      { "Packets Received", "skinny.packetsRecv",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_octetsRecv,
      { "Octets received", "skinny.octetsRecv",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_packetsLost,
      { "Packets lost", "skinny.packetsLost",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
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
      { "Directory number", "skinny.directoryNumber",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The number we are reporting statistics for.",
	HFILL }
    },

    { &hf_skinny_lineInstance,
      { "Line instance", "skinny.lineInstance",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The display call plane associated with this call.",
	HFILL }
    },

    { &hf_skinny_softKeyEvent,
      { "Soft-key event", "skinny.softKeyEvent",
	FT_UINT32, BASE_DEC|BASE_EXT_STRING, &softKeyEvents_ext, 0x0,
	"Which softkey event is being reported.",
	HFILL }
    },

    { &hf_skinny_keepAliveInterval,
      { "Keep-alive interval", "skinny.keepAliveInterval",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"How often are keep alives exchanges between the client and the call manager.",
	HFILL }
    },

    { &hf_skinny_secondaryKeepAliveInterval,
      { "Secondary keep-alive interval", "skinny.secondaryKeepAliveInterval",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"How often are keep alives exchanges between the client and the secondary call manager.",
	HFILL }
    },

    { &hf_skinny_dateTemplate,
      { "Date template", "skinny.dateTemplate",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The display format for the date/time on the phone.",
	HFILL }
    },

    { &hf_skinny_buttonOffset,
      { "Button offset", "skinny.buttonOffset",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Offset is the number of the first button referenced by this message.",
	HFILL }
    },

    { &hf_skinny_buttonCount,
      { "Buttons count", "skinny.buttonCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Number of (VALID) button definitions in this message.",
	HFILL }
    },

    { &hf_skinny_totalButtonCount,
      { "Total buttons count", "skinny.totalButtonCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The total number of buttons defined for this phone.",
	HFILL }
    },

    { &hf_skinny_buttonInstanceNumber,
      { "Instance number", "skinny.buttonInstanceNumber",
	FT_UINT8, BASE_HEX|BASE_EXT_STRING, &keypadButtons_ext, 0x0,
	"The button instance number for a button or the StationKeyPad value, repeats allowed.",
	HFILL }
    },

    { &hf_skinny_buttonDefinition,
      { "Button definition", "skinny.buttonDefinition",
	FT_UINT8, BASE_HEX|BASE_EXT_STRING, &buttonDefinitions_ext, 0x0,
	"The button type for this instance (ie line, speed dial, ....",
	HFILL }
    },

    { &hf_skinny_softKeyOffset,
      { "Soft-Key offset", "skinny.softKeyOffset",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The offset for the first soft key in this message.",
	HFILL }
    },

    { &hf_skinny_softKeyCount,
      { "Soft-keys count", "skinny.softKeyCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The number of valid softkeys in this message.",
	HFILL }
    },

    { &hf_skinny_totalSoftKeyCount,
      { "Total soft-keys count", "skinny.totalSoftKeyCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The total number of softkeys for this device.",
	HFILL }
    },

    { &hf_skinny_softKeyLabel,
      { "Soft-key label", "skinny.softKeyLabel",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The text label for this soft key.",
	HFILL }
    },

    { &hf_skinny_softKeySetOffset,
      { "Soft-key-set offset", "skinny.softKeySetOffset",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The offset for the first soft key set in this message.",
	HFILL }
    },

    { &hf_skinny_softKeySetCount,
      { "Soft-key-sets count", "skinny.softKeySetCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The number of valid softkey sets in this message.",
	HFILL }
    },

    { &hf_skinny_totalSoftKeySetCount,
      { "Total soft-key-sets count", "skinny.totalSoftKeySetCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The total number of softkey sets for this device.",
	HFILL }
    },

    { &hf_skinny_softKeyTemplateIndex,
      { "Soft-key template index", "skinny.softKeyTemplateIndex",
	FT_UINT8, BASE_DEC|BASE_EXT_STRING, &softKeyEvents_ext, 0x0,
	"Array of size 16 8-bit unsigned ints containing an index into the softKeyTemplate.",
	HFILL }
    },

    { &hf_skinny_softKeyInfoIndex,
      { "Soft-key info index", "skinny.softKeyInfoIndex",
	FT_UINT16, BASE_DEC|BASE_EXT_STRING, &softKeyIndexes_ext, 0x0,
	"Array of size 16 16-bit unsigned integers containing an index into the soft key description information.",
	HFILL }
    },

    { &hf_skinny_softKeySetDescription,
      { "Soft-key set description", "skinny.softKeySetDescription",
	FT_UINT8, BASE_DEC|BASE_EXT_STRING, &keySetNames_ext, 0x0,
	"A text description of what this softkey when this softkey set is displayed",
	HFILL }
    },

    { &hf_skinny_softKeyMap,
      { "Soft-key map","skinny.softKeyMap",
	FT_UINT16, BASE_HEX, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_softKey0,
      { "SoftKey0", "skinny.softKeyMap.0",
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY0,
	NULL,
	HFILL }
    },

    { &hf_skinny_softKey1,
      { "SoftKey1", "skinny.softKeyMap.1",
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY1,
	NULL,
	HFILL }
    },

    { &hf_skinny_softKey2,
      { "SoftKey2", "skinny.softKeyMap.2",
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY2,
	NULL,
	HFILL }
    },

    { &hf_skinny_softKey3,
      { "SoftKey3", "skinny.softKeyMap.3",
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY3,
	NULL,
	HFILL }
    },

    { &hf_skinny_softKey4,
      { "SoftKey4", "skinny.softKeyMap.4",
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY4,
	NULL,
	HFILL }
    },

    { &hf_skinny_softKey5,
      { "SoftKey5", "skinny.softKeyMap.5",
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY5,
	NULL,
	HFILL }
    },

    { &hf_skinny_softKey6,
      { "SoftKey6", "skinny.softKeyMap.6",
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY6,
	NULL,
	HFILL }
    },

    { &hf_skinny_softKey7,
      { "SoftKey7", "skinny.softKeyMap.7",
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY7,
	NULL,
	HFILL }
    },

    { &hf_skinny_softKey8,
      { "SoftKey8", "skinny.softKeyMap.8",
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY8,
	NULL,
	HFILL }
    },

    { &hf_skinny_softKey9,
      { "SoftKey9", "skinny.softKeyMap.9",
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY9,
	NULL,
	HFILL }
    },

    { &hf_skinny_softKey10,
      { "SoftKey10", "skinny.softKeyMap.10",
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY10,
	NULL,
	HFILL }
    },

    { &hf_skinny_softKey11,
      { "SoftKey11", "skinny.softKeyMap.11",
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY11,
	NULL,
	HFILL }
    },

    { &hf_skinny_softKey12,
      { "SoftKey12", "skinny.softKeyMap.12",
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY12,
	NULL,
	HFILL }
    },

    { &hf_skinny_softKey13,
      { "SoftKey13", "skinny.softKeyMap.13",
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY13,
	NULL,
	HFILL }
    },

    { &hf_skinny_softKey14,
      { "SoftKey14", "skinny.softKeyMap.14",
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY14,
	NULL,
	HFILL }
    },

    { &hf_skinny_softKey15,
      { "SoftKey15", "skinny.softKeyMap.15",
	FT_BOOLEAN, 16, TFS(&softKeyMapValues), SKINNY_SOFTKEY15,
	NULL,
	HFILL }
    },

    { &hf_skinny_lampMode,
      { "Lamp mode", "skinny.lampMode",
	FT_UINT32, BASE_DEC|BASE_EXT_STRING, &stationLampModes_ext, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_messageTimeOutValue,
      { "Message time-out", "skinny.messageTimeOutValue",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The timeout in seconds for this message",
	HFILL }
    },

    { &hf_skinny_displayMessage,
      { "Display message", "skinny.displayMessage",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The message displayed on the phone.",
	HFILL }
    },

    { &hf_skinny_lineDirNumber,
      { "Line directory number", "skinny.lineDirNumber",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The directory number for this line.",
	HFILL }
    },

    { &hf_skinny_lineFullyQualifiedDisplayName,
      { "Fully qualified display name", "skinny.fqdn",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The full display name for this line.",
	HFILL }
    },

    { &hf_skinny_lineDisplayName,
      { "Display name", "skinny.displayName",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The display name for this line.",
	HFILL }
    },

    { &hf_skinny_speedDialDirNumber,
      { "Speed-dial number", "skinny.speedDialDirNum",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"the number to dial for this speed dial.",
	HFILL }
    },

    { &hf_skinny_speedDialDisplayName,
      { "Speed-dial display", "skinny.speedDialDisplay",
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
      { "Day of week", "skinny.dayOfWeek",
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
	NULL,
	HFILL }
    },

    { &hf_skinny_dateSeconds,
      { "Seconds", "skinny.dateSeconds",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_dateMilliseconds,
      { "Milliseconds", "skinny.dateMilliseconds",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_timeStamp,
      { "Timestamp", "skinny.timeStamp",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Time stamp for the call reference",
	HFILL }
    },
    { &hf_skinny_callState,
      { "Call state", "skinny.callState",
	FT_UINT32, BASE_DEC|BASE_EXT_STRING, &skinny_stationCallStates_ext, 0x0,
	"The D channel call state of the call",
	HFILL }
    },

    { &hf_skinny_deviceTone,
      { "Tone", "skinny.deviceTone",
	FT_UINT32, BASE_HEX|BASE_EXT_STRING, &skinny_deviceTones_ext, 0x0,
	"Which tone to play",
	HFILL }
    },

    { &hf_skinny_callingPartyName,
      { "Calling party name", "skinny.callingPartyName",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The passed name of the calling party.",
	HFILL }
    },

    { &hf_skinny_callingPartyNumber,
      { "Calling party number", "skinny.callingParty",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The passed number of the calling party.",
	HFILL }
    },

    { &hf_skinny_calledPartyName,
      { "Called party name", "skinny.calledPartyName",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The name of the party we are calling.",
	HFILL }
    },

    { &hf_skinny_callType,
      { "Call type", "skinny.callType",
	FT_UINT32, BASE_DEC, VALS(skinny_callTypes), 0x0,
	"What type of call, in/out/etc",
	HFILL }
    },

    { &hf_skinny_originalCalledPartyName,
      { "Original called party name", "skinny.originalCalledPartyName",
	FT_STRING, BASE_NONE, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_originalCalledParty,
      { "Original called party number", "skinny.originalCalledParty",
	FT_STRING, BASE_NONE, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_ringType,
      { "Ring type", "skinny.ringType",
	FT_UINT32, BASE_HEX|BASE_EXT_STRING, &skinny_ringTypes_ext, 0x0,
	"What type of ring to play",
	HFILL }
    },

    { &hf_skinny_ringMode,
      { "Ring mode", "skinny.ringMode",
	FT_UINT32, BASE_HEX, VALS(skinny_ringModes), 0x0,
	"What mode of ring to play",
	HFILL }
    },

    { &hf_skinny_speakerMode,
      { "Speaker", "skinny.speakerMode",
	FT_UINT32, BASE_HEX, VALS(skinny_speakerModes), 0x0,
	"This message sets the speaker mode on/off",
	HFILL }
    },

    { &hf_skinny_remoteIpAddr,
      { "Remote IP address", "skinny.remoteIpAddr",
	FT_IPv4, BASE_NONE, NULL, 0x0,
	"The remote end ip address for this stream",
	HFILL }
    },

    { &hf_skinny_remotePortNumber,
      { "Remote port", "skinny.remotePortNumber",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The remote port number listening for this stream",
	HFILL }
    },

    { &hf_skinny_millisecondPacketSize,
      { "MS/packet", "skinny.millisecondPacketSize",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The number of milliseconds of conversation in each packet",
	HFILL }
    },

    { &hf_skinny_precedenceValue,
      { "Precedence", "skinny.precedenceValue",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_silenceSuppression,
      { "Silence suppression", "skinny.silenceSuppression",
	FT_UINT32, BASE_HEX, VALS(skinny_silenceSuppressionModes), 0x0,
	"Mode for silence suppression",
	HFILL }
    },

    { &hf_skinny_g723BitRate,
      { "G723 bitrate", "skinny.g723BitRate",
	FT_UINT32, BASE_DEC, VALS(skinny_g723BitRates), 0x0,
	"The G723 bit rate for this stream/JUNK if not g723 stream",
	HFILL }
    },

    { &hf_skinny_conferenceID,
      { "Conference ID", "skinny.conferenceID",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_deviceResetType,
      { "Reset type", "skinny.deviceResetType",
	FT_UINT32, BASE_DEC, VALS(skinny_deviceResetTypes), 0x0,
	"How the devices it to be reset (reset/restart)",
	HFILL }
    },

    { &hf_skinny_echoCancelType,
      { "Echo-cancel type", "skinny.echoCancelType",
	FT_UINT32, BASE_DEC, VALS(skinny_echoCancelTypes), 0x0,
	"Is echo cancelling enabled or not",
	HFILL }
    },

    { &hf_skinny_deviceUnregisterStatus,
      { "Unregister status", "skinny.deviceUnregisterStatus",
	FT_UINT32, BASE_DEC, VALS(skinny_deviceUnregisterStatusTypes), 0x0,
	"The status of the device unregister request (*CAN* be refused)",
	HFILL }
    },

    { &hf_skinny_hookFlashDetectMode,
      { "Hook flash mode", "skinny.hookFlashDetectMode",
	FT_UINT32, BASE_DEC, VALS(skinny_hookFlashDetectModes), 0x0,
	"Which method to use to detect that a hook flash has occured",
	HFILL }
    },

    { &hf_skinny_detectInterval,
      { "HF Detect Interval", "skinny.detectInterval",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The number of milliseconds that determines a hook flash has occured",
	HFILL }
    },

    { &hf_skinny_headsetMode,
      { "Headset mode", "skinny.headsetMode",
	FT_UINT32, BASE_DEC, VALS(skinny_headsetModes), 0x0,
	"Turns on and off the headset on the set",
	HFILL }
    },

    { &hf_skinny_microphoneMode,
      { "Microphone mode", "skinny.microphoneMode",
	FT_UINT32, BASE_DEC, VALS(skinny_microphoneModes), 0x0,
	"Turns on and off the microphone on the set",
	HFILL }
    },

    { &hf_skinny_activeForward,
      { "Active forward", "skinny.activeForward",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"This is non zero to indicate that a forward is active on the line",
	HFILL }
    },

    { &hf_skinny_forwardAllActive,
      { "Forward all", "skinny.forwardAllActive",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Forward all calls",
	HFILL }
    },

    { &hf_skinny_forwardBusyActive,
      { "Forward busy", "skinny.forwardBusyActive",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Forward calls when busy",
	HFILL }
    },

    { &hf_skinny_forwardNoAnswerActive,
      { "Forward no answer", "skinny.forwardNoAnswerActive",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Forward only when no answer",
	HFILL }
    },

    { &hf_skinny_forwardNumber,
      { "Forward number", "skinny.forwardNumber",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The number to forward calls to.",
	HFILL }
    },

    { &hf_skinny_userName,
      { "Username", "skinny.userName",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"Username for this device.",
	HFILL }
    },

    { &hf_skinny_serverName,
      { "Server name", "skinny.serverName",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The server name for this device.",
	HFILL }
    },

    { &hf_skinny_numberLines,
      { "Number of lines", "skinny.numberLines",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"How many lines this device has",
	HFILL }
    },

    { &hf_skinny_numberSpeedDials,
      { "Number of speed-dials", "skinny.numberSpeedDials",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The number of speed dials this device has",
	HFILL }
    },

    { &hf_skinny_sessionType,
      { "Session type", "skinny.sessionType",
	FT_UINT32, BASE_DEC|BASE_EXT_STRING, &skinny_sessionTypes_ext, 0x0,
	"The type of this session.",
	HFILL }
    },

    { &hf_skinny_version,
      { "Version", "skinny.version",
	FT_STRING, BASE_NONE, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_mediaEnunciationType,
      { "Enunciation type", "skinny.mediaEnunciationType",
	FT_UINT32, BASE_DEC, VALS(skinny_mediaEnunciationTypes), 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_serverIdentifier,
      { "Server identifier", "skinny.serverIdentifier",
	FT_STRING, BASE_NONE, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_serverListenPort,
      { "Server port", "skinny.serverListenPort",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_serverIpAddress,
      { "Server IP address", "skinny.serverIpAddress",
	FT_IPv4, BASE_NONE, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_multicastPort,
      { "Multicast port", "skinny.multicastPort",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_multicastIpAddress,
      { "Multicast IP address", "skinny.multicastIpAddress",
	FT_IPv4, BASE_NONE, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_tokenRejWaitTime,
      { "Retry wait time", "skinny.tokenRejWaitTime",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_unknown,
      { "Unknown data", "skinny.unknown",
	FT_UINT32, BASE_HEX, NULL, 0x0,
	"Place holder for unknown data.",
	HFILL }
    },

    { &hf_skinny_rawData,
      { "Unknown raw data", "skinny.rawData",
	FT_BYTES, BASE_NONE, NULL, 0x0,
	"Place holder for unknown raw data.",
	HFILL }
    },

    { &hf_skinny_xmlData,
      { "XML data", "skinny.xmlData",
	FT_STRING, BASE_NONE, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_numberOfInServiceStreams,
      { "Number of in-service streams", "skinny.numberOfInServiceStreams",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_maxStreamsPerConf,
      { "Max streams per conf", "skinny.maxStreamsPerConf",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_numberOfOutOfServiceStreams,
      { "Number of out-of-service streams", "skinny.numberOfOutOfServiceStreams",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_applicationID,
      { "Application ID", "skinny.applicationID",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Application ID.",
	HFILL }
    },

    { &hf_skinny_transactionID,
      { "Transaction ID", "skinny.transactionID",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_serviceNum,
      { "Service number", "skinny.serviceNum",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_serviceURLIndex,
      { "Service URL index", "skinny.serviceURLIndex",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_featureIndex,
      { "Feature index", "skinny.featureIndex",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_createConfResults,
      { "Create conf results", "skinny.createConfResults",
	FT_UINT32, BASE_DEC, VALS(skinny_createConfResults), 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_modifyConfResults,
      { "Modify conf results", "skinny.modifyConfResults",
	FT_UINT32, BASE_DEC|BASE_EXT_STRING, &skinny_modifyConfResults_ext, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_deleteConfResults,
      { "Delete conf results", "skinny.deleteConfResults",
	FT_UINT32, BASE_DEC, VALS(skinny_deleteConfResults), 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_addParticipantResults,
      { "Add participant results", "skinny.addParticipantResults",
	FT_UINT32, BASE_DEC|BASE_EXT_STRING, &skinny_addParticipantResults_ext, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_passThruData,
      { "Pass-thru data", "skinny.passThruData",
	FT_UINT8, BASE_HEX, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_auditParticipantResults,
      { "Audit participant results", "skinny.auditParticipantResults",
	FT_UINT32, BASE_DEC, VALS(skinny_auditParticipantResults), 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_last,
      { "Last", "skinny.last",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_numberOfEntries,
      { "Number of entries", "skinny.numberOfEntries",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_participantEntry,
      { "Participant entry", "skinny.participantEntry",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_resourceTypes,
      { "ResourceType", "skinny.resourceTypes",
	FT_UINT32, BASE_DEC, VALS(skinny_resourceTypes), 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_numberOfReservedParticipants,
      { "Number of reserved participants", "skinny.numberOfReservedParticipants",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_numberOfActiveParticipants,
      { "Number of active participants", "skinny.numberOfActiveParticipants",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_appID,
      { "Application ID", "skinny.appID",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_appData,
      { "Application data", "skinny.appData",
	FT_UINT8, BASE_HEX, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_appConfID,
      { "Application conf ID", "skinny.appConfID",
	FT_UINT8, BASE_HEX, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_sequenceFlag,
      { "Sequence flag", "skinny.sequenceFlag",
	FT_UINT32, BASE_DEC, VALS(skinny_sequenceFlags), 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_displayPriority,
      { "Display priority", "skinny.displayPriority",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_appInstanceID,
      { "Application instance ID", "skinny.appInstanceID",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_routingID,
      { "Routing ID", "skinny.routingID",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_audioCapCount,
      { "Audio cap count", "skinny.audioCapCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_videoCapCount,
      { "Video cap count", "skinny.videoCapCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_dataCapCount,
      { "Data cap count", "skinny.dataCapCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_RTPPayloadFormat,
      { "RTP payload format", "skinny.RTPPayloadFormat",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_customPictureFormatCount,
      { "Custom picture format count", "skinny.customPictureFormatCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_pictureWidth,
      { "Picture width", "skinny.pictureWidth",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_pictureHeight,
      { "Picture height", "skinny.pictureHeight",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_pixelAspectRatio,
      { "Pixel aspect ratio", "skinny.pixelAspectRatio",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_clockConversionCode,
      { "Clock conversion code", "skinny.clockConversionCode",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_clockDivisor,
      { "Clock divisor", "skinny.clockDivisor",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_activeStreamsOnRegistration,
      { "Active streams on registration", "skinny.activeStreamsOnRegistration",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_maxBW,
      { "Max BW", "skinny.maxBW",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_serviceResourceCount,
      { "Service resource count", "skinny.serviceResourceCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_layoutCount,
      { "Layout count", "skinny.layoutCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_layout,
      { "Layout", "skinny.layout",
	FT_UINT32, BASE_DEC|BASE_EXT_STRING, &skinny_Layouts_ext, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_maxConferences,
      { "Max conferences", "skinny.maxConferences",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_activeConferenceOnRegistration,
      { "Active conference on registration", "skinny.activeConferenceOnRegistration",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_transmitOrReceive,
      { "Transmit or receive", "skinny.transmitOrReceive",
	FT_UINT32, BASE_DEC, VALS(skinny_transmitOrReceive), 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_levelPreferenceCount,
      { "Level preference count", "skinny.levelPreferenceCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_transmitPreference,
      { "Transmit preference", "skinny.transmitPreference",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_format,
      { "Format", "skinny.format",
	FT_UINT32, BASE_DEC|BASE_EXT_STRING, &skinny_formatTypes_ext, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_maxBitRate,
      { "Max bitrate", "skinny.maxBitRate",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_minBitRate,
      { "Min bitrate", "skinny.minBitRate",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_MPI,
      { "MPI", "skinny.MPI",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_serviceNumber,
      { "Service number", "skinny.serviceNumber",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_temporalSpatialTradeOffCapability,
      { "Temporal spatial trade off capability", "skinny.temporalSpatialTradeOffCapability",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_stillImageTransmission,
      { "Still image transmission", "skinny.stillImageTransmission",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_h263_capability_bitfield,
      { "H263 capability bitfield", "skinny.h263_capability_bitfield",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_annexNandWFutureUse,
      { "Annex N and W future use", "skinny.annexNandWFutureUse",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_modelNumber,
      { "Model number", "skinny.modelNumber",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_bandwidth,
      { "Bandwidth", "skinny.bandwidth",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_protocolDependentData,
      { "Protocol dependent data", "skinny.protocolDependentData",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_priority,
      { "Priority", "skinny.priority",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_payloadDtmf,
      { "Payload DTMF", "skinny.payloadDtmf",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"RTP payload type.",
	HFILL }
    },

    { &hf_skinny_featureID,
      { "Feature ID", "skinny.featureID",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_featureTextLabel,
      { "Feature text label", "skinny.featureTextLabel",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The feature label text that is displayed on the phone.",
	HFILL }
    },

    { &hf_skinny_featureStatus,
      { "Feature status", "skinny.featureStatus",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_notify,
      { "Notify", "skinny.notify",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The message notify text that is displayed on the phone.",
	HFILL }
    },

    { &hf_skinny_endOfAnnAck,
      { "End of ann. ack", "skinny.endOfAnnAck",
	FT_UINT32, BASE_DEC, VALS(skinny_endOfAnnAck), 0x0,
	"End of announcement ack.",
	HFILL }
    },

    { &hf_skinny_annPlayMode,
      { "Ann. play mode", "skinny.annPlayMode",
	FT_UINT32, BASE_DEC, VALS(skinny_annPlayMode), 0x0,
	"Announcement play mode.",
	HFILL }
    },

    { &hf_skinny_annPlayStatus,
      { "Ann. play status", "skinny.annPlayStatus",
	FT_UINT32, BASE_DEC, VALS(skinny_annPlayStatus), 0x0,
	"Announcement play status.",
	HFILL }
    },

    { &hf_skinny_locale,
      { "Locale", "skinny.locale",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"User locale ID.",
	HFILL }
    },

    { &hf_skinny_country,
      { "Country", "skinny.country",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Country ID (Network locale).",
	HFILL }
    },

    { &hf_skinny_matrixConfPartyID,
      { "Matrix conf party ID", "skinny.matrixConfPartyID",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Existing conference parties.",
	HFILL }
    },

    { &hf_skinny_hearingConfPartyMask,
      { "Hearing conf party mask", "skinny.hearingConfPartyMask",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Bit mask of conference parties to hear media received on this stream.  Bit0 = matrixConfPartyID[0], Bit1 = matrixConfPartiID[1].",
	HFILL }
    },

    { &hf_skinny_serviceURL,
      { "Service URL value", "skinny.serviceURL",
	FT_STRING, BASE_NONE, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_serviceURLDisplayName,
      { "Service URL display name", "skinny.serviceURLDisplayName",
	FT_STRING, BASE_NONE, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_callSelectStat,
      { "Call select stat", "skinny.callSelectStat",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_isConferenceCreator,
      { "Is conference creator", "skinny.isConferenceCreator",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_payload_rfc_number,
      { "Payload RFC number", "skinny.payload_rfc_number",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_payloadType,
      { "Payload type", "skinny.payloadType",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_bitRate,
      { "Bitrate", "skinny.bitRate",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_pictureFormatCount,
      { "Picture format count", "skinny.pictureFormatCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_confServiceNum,
      { "Conf service number", "skinny.confServiceNum",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Conference service number.",
	HFILL }
    },

    { &hf_skinny_DSCPValue,
      { "DSCP value", "skinny.DSCPValue",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_miscCommandType,
      { "Misc command type", "skinny.miscCommandType",
	FT_UINT32, BASE_DEC|BASE_EXT_STRING, &skinny_miscCommandType_ext, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_temporalSpatialTradeOff,
      { "Temporal spatial trade-off", "skinny.temporalSpatialTradeOff",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_firstGOB,
      { "First GOB", "skinny.firstGOB",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_numberOfGOBs,
      { "Number of GOBs", "skinny.numberOfGOBs",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_firstMB,
      { "First MB", "skinny.firstMB",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_numberOfMBs,
      { "Number of MBs", "skinny.numberOfMBs",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_pictureNumber,
      { "Picture number", "skinny.pictureNumber",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_longTermPictureIndex,
      { "Long-term picture index", "skinny.longTermPictureIndex",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_recoveryReferencePictureCount,
      { "Recovery-reference picture count", "skinny.recoveryReferencePictureCount",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_cast_lastRedirectingPartyName,
      { "Last redirecting party name", "cast.lastRedirectingPartyName",
	FT_STRING, BASE_NONE, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_cast_lastRedirectingParty,
      { "Last redirecting party", "cast.lastRedirectingParty",
	FT_STRING, BASE_NONE, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_cast_cgpnVoiceMailbox,
      { "Calling party voice mailbox", "cast.cgpnVoiceMailbox",
	FT_STRING, BASE_NONE, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_cast_cdpnVoiceMailbox,
      { "Called party voice mailbox", "cast.cdpnVoiceMailbox",
	FT_STRING, BASE_NONE, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_cast_originalCdpnVoiceMailbox,
      { "Original called party voice mailbox", "cast.originalCdpnVoiceMailbox",
	FT_STRING, BASE_NONE, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_cast_lastRedirectingVoiceMailbox,
      { "Last redirecting voice mailbox", "cast.lastRedirectingVoiceMailbox",
	FT_STRING, BASE_NONE, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_cast_originalCdpnRedirectReason,
      { "Original called party redirect reason", "cast.originalCdpnRedirectReason",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_cast_lastRedirectingReason,
      { "Last redirecting reason", "cast.lastRedirectingReason",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_cast_callInstance,
      { "Call instance", "cast.callInstance",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_cast_callSecurityStatus,
      { "Call security status", "cast.callSecurityStatus",
	FT_UINT32, BASE_DEC, VALS(cast_callSecurityStatusTypes), 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_directoryIndex,
      { "Directory index", "skinny.directoryIndex",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL,
	HFILL }
    },

    { &hf_skinny_directoryPhoneNumber,
      { "Directory phone number", "skinny.directoryPhoneNumber",
	FT_STRING, BASE_NONE, NULL, 0x0,
	NULL,
	HFILL }
    },

  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_skinny,
    &ett_skinny_tree,
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
    "Reassemble SCCP messages spanning multiple TCP segments",
    "Whether the SCCP dissector should reassemble messages spanning multiple TCP segments."
    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &skinny_desegment);

  skinny_tap = register_tap("skinny");
}

void
proto_reg_handoff_skinny(void)
{
  static gboolean skinny_prefs_initialized = FALSE;
  dissector_handle_t skinny_handle;

  if (!skinny_prefs_initialized) {
    rtp_handle = find_dissector("rtp");
    /* Skinny content type and internet media type used by other dissectors are the same */
    media_type_dissector_table = find_dissector_table("media_type");
    skinny_handle = new_create_dissector_handle(dissect_skinny, proto_skinny);
    dissector_add_uint("tcp.port", TCP_PORT_SKINNY, skinny_handle);
    ssl_dissector_add(SSL_PORT_SKINNY, "skinny", TRUE);
    skinny_prefs_initialized = TRUE;
  }
}

