/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-atn-cpdlc.c                                                         */
/* asn2wrs.py -u -L -p atn-cpdlc -c ./atn-cpdlc.cnf -s ./packet-atn-cpdlc-template -D . -O ../.. atn-cpdlc.asn */

/* Input file: packet-atn-cpdlc-template.c */

#line 1 "./asn1/atn-cpdlc/packet-atn-cpdlc-template.c"
/* packet-atn-cpdlc-template.c
 * By Mathias Guettler <guettler@web.de>
 * Copyright 2013
 *
 * Routines for ATN Cpdlcc protocol packet disassembly

 * details see:
 * http://en.wikipedia.org/wiki/CPDLC
 * http://members.optusnet.com.au/~cjr/introduction.htm

 * standards:
 * http://legacy.icao.int/anb/panels/acp/repository.cfm

 * note:
 * We are dealing with ATN/CPDLC aka ICAO Doc 9705 Ed2 here
 * (CPDLC may also be transmitted via ACARS/AOA aka "FANS-1/A ").

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

/*
 developper comments:
  Which CPDLC messages are supported ?
    Protected Mode CPDLC (AeQualifier 22) and Plain Old CPDLC (AeQualifier 2)
    The dissector has been tested with ICAO doc9705 Edition2 compliant traffic.
*/

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/conversation.h>
#include "packet-ber.h"
#include "packet-per.h"
#include "packet-atn-ulcs.h"

#define ATN_CPDLC_PROTO "ICAO Doc9705 CPDLC"

void proto_register_atn_cpdlc(void);
void proto_reg_handoff_atn_cpdlc(void);

static const char *object_identifier_id;

/* IA5 charset (7-bit) for PER IA5 decoding */
static const gchar ia5alpha[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, \
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, \
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, \
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, \
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, \
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, \
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, \
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, \
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, '\0'
};

/* forward declarations */
static int dissect_GroundPDUs_PDU(
    tvbuff_t *tvb _U_,
    packet_info *pinfo _U_,
    proto_tree *tree _U_,
    void *data _U_);
static int dissect_AircraftPDUs_PDU(
    tvbuff_t *tvb _U_,
    packet_info *pinfo _U_,
    proto_tree *tree _U_,
    void *data _U_);
static int dissect_ProtectedGroundPDUs_PDU(
    tvbuff_t *tvb _U_,
    packet_info *pinfo _U_,
    proto_tree *tree _U_,
    void *data _U_);
static int dissect_ProtectedAircraftPDUs_PDU(
    tvbuff_t *tvb _U_,
    packet_info *pinfo _U_,
    proto_tree *tree _U_,
    void *data _U_);


/*--- Included file: packet-atn-cpdlc-hf.c ---*/
#line 1 "./asn1/atn-cpdlc/packet-atn-cpdlc-hf.c"
static int hf_atn_cpdlc_GroundPDUs_PDU = -1;      /* GroundPDUs */
static int hf_atn_cpdlc_AircraftPDUs_PDU = -1;    /* AircraftPDUs */
static int hf_atn_cpdlc_ProtectedGroundPDUs_PDU = -1;  /* ProtectedGroundPDUs */
static int hf_atn_cpdlc_ProtectedAircraftPDUs_PDU = -1;  /* ProtectedAircraftPDUs */
static int hf_atn_cpdlc_abortUser = -1;           /* CPDLCUserAbortReason */
static int hf_atn_cpdlc_abortProvider = -1;       /* CPDLCProviderAbortReason */
static int hf_atn_cpdlc_startup = -1;             /* UplinkMessage */
static int hf_atn_cpdlc_groundpdus_send = -1;     /* ATCUplinkMessage */
static int hf_atn_cpdlc_forward = -1;             /* ATCForwardMessage */
static int hf_atn_cpdlc_forwardresponse = -1;     /* ATCForwardResponse */
static int hf_atn_cpdlc_noMessage = -1;           /* NULL */
static int hf_atn_cpdlc_aTCUplinkMessage = -1;    /* ATCUplinkMessage */
static int hf_atn_cpdlc_startdown = -1;           /* StartDownMessage */
static int hf_atn_cpdlc_aircraftpdus_send = -1;   /* ATCDownlinkMessage */
static int hf_atn_cpdlc_mode = -1;                /* Mode */
static int hf_atn_cpdlc_startDownlinkMessage = -1;  /* DownlinkMessage */
static int hf_atn_cpdlc_aTCDownlinkMessage = -1;  /* ATCDownlinkMessage */
static int hf_atn_cpdlc_pmcpdlcuserabortreason = -1;  /* PMCPDLCUserAbortReason */
static int hf_atn_cpdlc_pmcpdlcproviderabortreason = -1;  /* PMCPDLCProviderAbortReason */
static int hf_atn_cpdlc_protecteduplinkmessage = -1;  /* ProtectedUplinkMessage */
static int hf_atn_cpdlc_algorithmIdentifier = -1;  /* AlgorithmIdentifier */
static int hf_atn_cpdlc_protectedMessage = -1;    /* CPDLCMessage */
static int hf_atn_cpdlc_integrityCheck = -1;      /* BIT_STRING */
static int hf_atn_cpdlc_forwardHeader = -1;       /* ForwardHeader */
static int hf_atn_cpdlc_forwardMessage = -1;      /* ForwardMessage */
static int hf_atn_cpdlc_dateTime = -1;            /* DateTimeGroup */
static int hf_atn_cpdlc_aircraftID = -1;          /* AircraftFlightIdentification */
static int hf_atn_cpdlc_aircraftAddress = -1;     /* AircraftAddress */
static int hf_atn_cpdlc_upElementIDs = -1;        /* BIT_STRING */
static int hf_atn_cpdlc_downElementIDs = -1;      /* BIT_STRING */
static int hf_atn_cpdlc_protectedstartDownmessage = -1;  /* ProtectedStartDownMessage */
static int hf_atn_cpdlc_send = -1;                /* ProtectedDownlinkMessage */
static int hf_atn_cpdlc_protectedmode = -1;       /* ProtectedMode */
static int hf_atn_cpdlc_protecteddownlinkmessage = -1;  /* ProtectedDownlinkMessage */
static int hf_atn_cpdlc_header = -1;              /* ATCMessageHeader */
static int hf_atn_cpdlc_atcuplinkmessage_messagedata = -1;  /* ATCUplinkMessageData */
static int hf_atn_cpdlc_atcuplinkmessagedata_elementids = -1;  /* SEQUENCE_SIZE_1_5_OF_ATCUplinkMsgElementId */
static int hf_atn_cpdlc_atcuplinkmessagedata_elementids_item = -1;  /* ATCUplinkMsgElementId */
static int hf_atn_cpdlc_atcuplinkmessagedata_constraineddata = -1;  /* T_atcuplinkmessagedata_constraineddata */
static int hf_atn_cpdlc_routeClearanceData = -1;  /* SEQUENCE_SIZE_1_2_OF_RouteClearance */
static int hf_atn_cpdlc_routeClearanceData_item = -1;  /* RouteClearance */
static int hf_atn_cpdlc_atcdownlinkmessage_messagedata = -1;  /* ATCDownlinkMessageData */
static int hf_atn_cpdlc_atcdownlinkmessagedata_elementids = -1;  /* SEQUENCE_SIZE_1_5_OF_ATCDownlinkMsgElementId */
static int hf_atn_cpdlc_atcdownlinkmessagedata_elementids_item = -1;  /* ATCDownlinkMsgElementId */
static int hf_atn_cpdlc_atcdownlinkmessagedata_constraineddata = -1;  /* T_atcdownlinkmessagedata_constraineddata */
static int hf_atn_cpdlc_messageIdNumber = -1;     /* MsgIdentificationNumber */
static int hf_atn_cpdlc_messageRefNumber = -1;    /* MsgReferenceNumber */
static int hf_atn_cpdlc_logicalAck = -1;          /* LogicalAck */
static int hf_atn_cpdlc_uM0NULL = -1;             /* NULL */
static int hf_atn_cpdlc_uM1NULL = -1;             /* NULL */
static int hf_atn_cpdlc_uM2NULL = -1;             /* NULL */
static int hf_atn_cpdlc_uM3NULL = -1;             /* NULL */
static int hf_atn_cpdlc_uM4NULL = -1;             /* NULL */
static int hf_atn_cpdlc_uM5NULL = -1;             /* NULL */
static int hf_atn_cpdlc_uM6Level = -1;            /* Level */
static int hf_atn_cpdlc_uM7Time = -1;             /* Time */
static int hf_atn_cpdlc_uM8Position = -1;         /* Position */
static int hf_atn_cpdlc_uM9Time = -1;             /* Time */
static int hf_atn_cpdlc_uM10Position = -1;        /* Position */
static int hf_atn_cpdlc_uM11Time = -1;            /* Time */
static int hf_atn_cpdlc_uM12Position = -1;        /* Position */
static int hf_atn_cpdlc_uM13TimeLevel = -1;       /* TimeLevel */
static int hf_atn_cpdlc_uM14PositionLevel = -1;   /* PositionLevel */
static int hf_atn_cpdlc_uM15TimeLevel = -1;       /* TimeLevel */
static int hf_atn_cpdlc_uM16PositionLevel = -1;   /* PositionLevel */
static int hf_atn_cpdlc_uM17TimeLevel = -1;       /* TimeLevel */
static int hf_atn_cpdlc_uM18PositionLevel = -1;   /* PositionLevel */
static int hf_atn_cpdlc_uM19Level = -1;           /* Level */
static int hf_atn_cpdlc_uM20Level = -1;           /* Level */
static int hf_atn_cpdlc_uM21TimeLevel = -1;       /* TimeLevel */
static int hf_atn_cpdlc_uM22PositionLevel = -1;   /* PositionLevel */
static int hf_atn_cpdlc_uM23Level = -1;           /* Level */
static int hf_atn_cpdlc_uM24TimeLevel = -1;       /* TimeLevel */
static int hf_atn_cpdlc_uM25PositionLevel = -1;   /* PositionLevel */
static int hf_atn_cpdlc_uM26LevelTime = -1;       /* LevelTime */
static int hf_atn_cpdlc_uM27LevelPosition = -1;   /* LevelPosition */
static int hf_atn_cpdlc_uM28LevelTime = -1;       /* LevelTime */
static int hf_atn_cpdlc_uM29LevelPosition = -1;   /* LevelPosition */
static int hf_atn_cpdlc_uM30LevelLevel = -1;      /* LevelLevel */
static int hf_atn_cpdlc_uM31LevelLevel = -1;      /* LevelLevel */
static int hf_atn_cpdlc_uM32LevelLevel = -1;      /* LevelLevel */
static int hf_atn_cpdlc_uM33NULL = -1;            /* NULL */
static int hf_atn_cpdlc_uM34Level = -1;           /* Level */
static int hf_atn_cpdlc_uM35Level = -1;           /* Level */
static int hf_atn_cpdlc_uM36Level = -1;           /* Level */
static int hf_atn_cpdlc_uM37Level = -1;           /* Level */
static int hf_atn_cpdlc_uM38Level = -1;           /* Level */
static int hf_atn_cpdlc_uM39Level = -1;           /* Level */
static int hf_atn_cpdlc_uM40NULL = -1;            /* NULL */
static int hf_atn_cpdlc_uM41NULL = -1;            /* NULL */
static int hf_atn_cpdlc_uM42PositionLevel = -1;   /* PositionLevel */
static int hf_atn_cpdlc_uM43PositionLevel = -1;   /* PositionLevel */
static int hf_atn_cpdlc_uM44PositionLevel = -1;   /* PositionLevel */
static int hf_atn_cpdlc_uM45PositionLevel = -1;   /* PositionLevel */
static int hf_atn_cpdlc_uM46PositionLevel = -1;   /* PositionLevel */
static int hf_atn_cpdlc_uM47PositionLevel = -1;   /* PositionLevel */
static int hf_atn_cpdlc_uM48PositionLevel = -1;   /* PositionLevel */
static int hf_atn_cpdlc_uM49PositionLevel = -1;   /* PositionLevel */
static int hf_atn_cpdlc_uM50PositionLevelLevel = -1;  /* PositionLevelLevel */
static int hf_atn_cpdlc_uM51PositionTime = -1;    /* PositionTime */
static int hf_atn_cpdlc_uM52PositionTime = -1;    /* PositionTime */
static int hf_atn_cpdlc_uM53PositionTime = -1;    /* PositionTime */
static int hf_atn_cpdlc_uM54PositionTimeTime = -1;  /* PositionTimeTime */
static int hf_atn_cpdlc_uM55PositionSpeed = -1;   /* PositionSpeed */
static int hf_atn_cpdlc_uM56PositionSpeed = -1;   /* PositionSpeed */
static int hf_atn_cpdlc_uM57PositionSpeed = -1;   /* PositionSpeed */
static int hf_atn_cpdlc_uM58PositionTimeLevel = -1;  /* PositionTimeLevel */
static int hf_atn_cpdlc_uM59PositionTimeLevel = -1;  /* PositionTimeLevel */
static int hf_atn_cpdlc_uM60PositionTimeLevel = -1;  /* PositionTimeLevel */
static int hf_atn_cpdlc_uM61PositionLevelSpeed = -1;  /* PositionLevelSpeed */
static int hf_atn_cpdlc_uM62TimePositionLevel = -1;  /* TimePositionLevel */
static int hf_atn_cpdlc_uM63TimePositionLevelSpeed = -1;  /* TimePositionLevelSpeed */
static int hf_atn_cpdlc_uM64DistanceSpecifiedDirection = -1;  /* DistanceSpecifiedDirection */
static int hf_atn_cpdlc_uM65PositionDistanceSpecifiedDirection = -1;  /* PositionDistanceSpecifiedDirection */
static int hf_atn_cpdlc_uM66TimeDistanceSpecifiedDirection = -1;  /* TimeDistanceSpecifiedDirection */
static int hf_atn_cpdlc_uM67NULL = -1;            /* NULL */
static int hf_atn_cpdlc_uM68Position = -1;        /* Position */
static int hf_atn_cpdlc_uM69Time = -1;            /* Time */
static int hf_atn_cpdlc_uM70Position = -1;        /* Position */
static int hf_atn_cpdlc_uM71Time = -1;            /* Time */
static int hf_atn_cpdlc_uM72NULL = -1;            /* NULL */
static int hf_atn_cpdlc_uM73DepartureClearance = -1;  /* DepartureClearance */
static int hf_atn_cpdlc_uM74Position = -1;        /* Position */
static int hf_atn_cpdlc_uM75Position = -1;        /* Position */
static int hf_atn_cpdlc_uM76TimePosition = -1;    /* TimePosition */
static int hf_atn_cpdlc_uM77PositionPosition = -1;  /* PositionPosition */
static int hf_atn_cpdlc_uM78LevelPosition = -1;   /* LevelPosition */
static int hf_atn_cpdlc_uM79PositionRouteClearance = -1;  /* PositionRouteClearanceIndex */
static int hf_atn_cpdlc_uM80RouteClearance = -1;  /* RouteClearanceIndex */
static int hf_atn_cpdlc_uM81ProcedureName = -1;   /* ProcedureName */
static int hf_atn_cpdlc_uM82DistanceSpecifiedDirection = -1;  /* DistanceSpecifiedDirection */
static int hf_atn_cpdlc_uM83PositionRouteClearance = -1;  /* PositionRouteClearanceIndex */
static int hf_atn_cpdlc_uM84PositionProcedureName = -1;  /* PositionProcedureName */
static int hf_atn_cpdlc_uM85RouteClearance = -1;  /* RouteClearanceIndex */
static int hf_atn_cpdlc_uM86PositionRouteClearance = -1;  /* PositionRouteClearanceIndex */
static int hf_atn_cpdlc_uM87Position = -1;        /* Position */
static int hf_atn_cpdlc_uM88PositionPosition = -1;  /* PositionPosition */
static int hf_atn_cpdlc_uM89TimePosition = -1;    /* TimePosition */
static int hf_atn_cpdlc_uM90LevelPosition = -1;   /* LevelPosition */
static int hf_atn_cpdlc_uM91HoldClearance = -1;   /* HoldClearance */
static int hf_atn_cpdlc_uM92PositionLevel = -1;   /* PositionLevel */
static int hf_atn_cpdlc_uM93Time = -1;            /* Time */
static int hf_atn_cpdlc_uM94DirectionDegrees = -1;  /* DirectionDegrees */
static int hf_atn_cpdlc_uM95DirectionDegrees = -1;  /* DirectionDegrees */
static int hf_atn_cpdlc_uM96NULL = -1;            /* NULL */
static int hf_atn_cpdlc_uM97PositionDegrees = -1;  /* PositionDegrees */
static int hf_atn_cpdlc_uM98DirectionDegrees = -1;  /* DirectionDegrees */
static int hf_atn_cpdlc_uM99ProcedureName = -1;   /* ProcedureName */
static int hf_atn_cpdlc_uM100TimeSpeed = -1;      /* TimeSpeed */
static int hf_atn_cpdlc_uM101PositionSpeed = -1;  /* PositionSpeed */
static int hf_atn_cpdlc_uM102LevelSpeed = -1;     /* LevelSpeed */
static int hf_atn_cpdlc_uM103TimeSpeedSpeed = -1;  /* TimeSpeedSpeed */
static int hf_atn_cpdlc_uM104PositionSpeedSpeed = -1;  /* PositionSpeedSpeed */
static int hf_atn_cpdlc_uM105LevelSpeedSpeed = -1;  /* LevelSpeedSpeed */
static int hf_atn_cpdlc_uM106Speed = -1;          /* Speed */
static int hf_atn_cpdlc_uM107NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM108Speed = -1;          /* Speed */
static int hf_atn_cpdlc_uM109Speed = -1;          /* Speed */
static int hf_atn_cpdlc_uM110SpeedSpeed = -1;     /* SpeedSpeed */
static int hf_atn_cpdlc_uM111Speed = -1;          /* Speed */
static int hf_atn_cpdlc_uM112Speed = -1;          /* Speed */
static int hf_atn_cpdlc_uM113Speed = -1;          /* Speed */
static int hf_atn_cpdlc_uM114Speed = -1;          /* Speed */
static int hf_atn_cpdlc_uM115Speed = -1;          /* Speed */
static int hf_atn_cpdlc_uM116NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM117UnitNameFrequency = -1;  /* UnitNameFrequency */
static int hf_atn_cpdlc_uM118PositionUnitNameFrequency = -1;  /* PositionUnitNameFrequency */
static int hf_atn_cpdlc_uM119TimeUnitNameFrequency = -1;  /* TimeUnitNameFrequency */
static int hf_atn_cpdlc_uM120UnitNameFrequency = -1;  /* UnitNameFrequency */
static int hf_atn_cpdlc_uM121PositionUnitNameFrequency = -1;  /* PositionUnitNameFrequency */
static int hf_atn_cpdlc_uM122TimeUnitNameFrequency = -1;  /* TimeUnitNameFrequency */
static int hf_atn_cpdlc_uM123Code = -1;           /* Code */
static int hf_atn_cpdlc_uM124NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM125NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM126NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM127NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM128Level = -1;          /* Level */
static int hf_atn_cpdlc_uM129Level = -1;          /* Level */
static int hf_atn_cpdlc_uM130Position = -1;       /* Position */
static int hf_atn_cpdlc_uM131NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM132NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM133NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM134SpeedTypeSpeedTypeSpeedType = -1;  /* SpeedTypeSpeedTypeSpeedType */
static int hf_atn_cpdlc_uM135NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM136NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM137NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM138NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM139NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM140NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM141NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM142NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM143NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM144NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM145NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM146NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM147NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM148Level = -1;          /* Level */
static int hf_atn_cpdlc_uM149LevelPosition = -1;  /* LevelPosition */
static int hf_atn_cpdlc_uM150LevelTime = -1;      /* LevelTime */
static int hf_atn_cpdlc_uM151Speed = -1;          /* Speed */
static int hf_atn_cpdlc_uM152DistanceSpecifiedDirection = -1;  /* DistanceSpecifiedDirection */
static int hf_atn_cpdlc_uM153Altimeter = -1;      /* Altimeter */
static int hf_atn_cpdlc_uM154NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM155Position = -1;       /* Position */
static int hf_atn_cpdlc_uM156NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM157Frequency = -1;      /* Frequency */
static int hf_atn_cpdlc_uM158AtisCode = -1;       /* ATISCode */
static int hf_atn_cpdlc_uM159ErrorInformation = -1;  /* ErrorInformation */
static int hf_atn_cpdlc_uM160Facility = -1;       /* Facility */
static int hf_atn_cpdlc_uM161NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM162NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM163FacilityDesignation = -1;  /* FacilityDesignation */
static int hf_atn_cpdlc_uM164NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM165NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM166TrafficType = -1;    /* TrafficType */
static int hf_atn_cpdlc_uM167NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM168NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM169FreeText = -1;       /* FreeText */
static int hf_atn_cpdlc_uM170FreeText = -1;       /* FreeText */
static int hf_atn_cpdlc_uM171VerticalRate = -1;   /* VerticalRate */
static int hf_atn_cpdlc_uM172VerticalRate = -1;   /* VerticalRate */
static int hf_atn_cpdlc_uM173VerticalRate = -1;   /* VerticalRate */
static int hf_atn_cpdlc_uM174VerticalRate = -1;   /* VerticalRate */
static int hf_atn_cpdlc_uM175Level = -1;          /* Level */
static int hf_atn_cpdlc_uM176NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM177NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM178NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM179NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM180LevelLevel = -1;     /* LevelLevel */
static int hf_atn_cpdlc_uM181ToFromPosition = -1;  /* ToFromPosition */
static int hf_atn_cpdlc_uM182NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM183FreeText = -1;       /* FreeText */
static int hf_atn_cpdlc_uM184TimeToFromPosition = -1;  /* TimeToFromPosition */
static int hf_atn_cpdlc_uM185PositionLevel = -1;  /* PositionLevel */
static int hf_atn_cpdlc_uM186PositionLevel = -1;  /* PositionLevel */
static int hf_atn_cpdlc_uM187FreeText = -1;       /* FreeText */
static int hf_atn_cpdlc_uM188PositionSpeed = -1;  /* PositionSpeed */
static int hf_atn_cpdlc_uM189Speed = -1;          /* Speed */
static int hf_atn_cpdlc_uM190Degrees = -1;        /* Degrees */
static int hf_atn_cpdlc_uM191NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM192LevelTime = -1;      /* LevelTime */
static int hf_atn_cpdlc_uM193NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM194FreeText = -1;       /* FreeText */
static int hf_atn_cpdlc_uM195FreeText = -1;       /* FreeText */
static int hf_atn_cpdlc_uM196FreeText = -1;       /* FreeText */
static int hf_atn_cpdlc_uM197FreeText = -1;       /* FreeText */
static int hf_atn_cpdlc_uM198FreeText = -1;       /* FreeText */
static int hf_atn_cpdlc_uM199FreeText = -1;       /* FreeText */
static int hf_atn_cpdlc_uM200NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM201NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM202NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM203FreeText = -1;       /* FreeText */
static int hf_atn_cpdlc_uM204FreeText = -1;       /* FreeText */
static int hf_atn_cpdlc_uM205FreeText = -1;       /* FreeText */
static int hf_atn_cpdlc_uM206FreeText = -1;       /* FreeText */
static int hf_atn_cpdlc_uM207FreeText = -1;       /* FreeText */
static int hf_atn_cpdlc_uM208FreeText = -1;       /* FreeText */
static int hf_atn_cpdlc_uM209LevelPosition = -1;  /* LevelPosition */
static int hf_atn_cpdlc_uM210Position = -1;       /* Position */
static int hf_atn_cpdlc_uM211NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM212FacilityDesignationATISCode = -1;  /* FacilityDesignationATISCode */
static int hf_atn_cpdlc_uM213FacilityDesignationAltimeter = -1;  /* FacilityDesignationAltimeter */
static int hf_atn_cpdlc_uM214RunwayRVR = -1;      /* RunwayRVR */
static int hf_atn_cpdlc_uM215DirectionDegrees = -1;  /* DirectionDegrees */
static int hf_atn_cpdlc_uM216NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM217NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM218NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM219Level = -1;          /* Level */
static int hf_atn_cpdlc_uM220Level = -1;          /* Level */
static int hf_atn_cpdlc_uM221Degrees = -1;        /* Degrees */
static int hf_atn_cpdlc_uM222NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM223NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM224NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM225NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM226Time = -1;           /* Time */
static int hf_atn_cpdlc_uM227NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM228Position = -1;       /* Position */
static int hf_atn_cpdlc_uM229NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM230NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM231NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM232NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM233NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM234NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM235NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM236NULL = -1;           /* NULL */
static int hf_atn_cpdlc_uM237NULL = -1;           /* NULL */
static int hf_atn_cpdlc_dM0NULL = -1;             /* NULL */
static int hf_atn_cpdlc_dM1NULL = -1;             /* NULL */
static int hf_atn_cpdlc_dM2NULL = -1;             /* NULL */
static int hf_atn_cpdlc_dM3NULL = -1;             /* NULL */
static int hf_atn_cpdlc_dM4NULL = -1;             /* NULL */
static int hf_atn_cpdlc_dM5NULL = -1;             /* NULL */
static int hf_atn_cpdlc_dM6Level = -1;            /* Level */
static int hf_atn_cpdlc_dM7LevelLevel = -1;       /* LevelLevel */
static int hf_atn_cpdlc_dM8Level = -1;            /* Level */
static int hf_atn_cpdlc_dM9Level = -1;            /* Level */
static int hf_atn_cpdlc_dM10Level = -1;           /* Level */
static int hf_atn_cpdlc_dM11PositionLevel = -1;   /* PositionLevel */
static int hf_atn_cpdlc_dM12PositionLevel = -1;   /* PositionLevel */
static int hf_atn_cpdlc_dM13TimeLevel = -1;       /* TimeLevel */
static int hf_atn_cpdlc_dM14TimeLevel = -1;       /* TimeLevel */
static int hf_atn_cpdlc_dM15DistanceSpecifiedDirection = -1;  /* DistanceSpecifiedDirection */
static int hf_atn_cpdlc_dM16PositionDistanceSpecifiedDirection = -1;  /* PositionDistanceSpecifiedDirection */
static int hf_atn_cpdlc_dM17TimeDistanceSpecifiedDirection = -1;  /* TimeDistanceSpecifiedDirection */
static int hf_atn_cpdlc_dM18Speed = -1;           /* Speed */
static int hf_atn_cpdlc_dM19SpeedSpeed = -1;      /* SpeedSpeed */
static int hf_atn_cpdlc_dM20NULL = -1;            /* NULL */
static int hf_atn_cpdlc_dM21Frequency = -1;       /* Frequency */
static int hf_atn_cpdlc_dM22Position = -1;        /* Position */
static int hf_atn_cpdlc_dM23ProcedureName = -1;   /* ProcedureName */
static int hf_atn_cpdlc_dM24RouteClearance = -1;  /* RouteClearanceIndex */
static int hf_atn_cpdlc_dM25ClearanceType = -1;   /* ClearanceType */
static int hf_atn_cpdlc_dM26PositionRouteClearance = -1;  /* PositionRouteClearanceIndex */
static int hf_atn_cpdlc_dM27DistanceSpecifiedDirection = -1;  /* DistanceSpecifiedDirection */
static int hf_atn_cpdlc_dM28Level = -1;           /* Level */
static int hf_atn_cpdlc_dM29Level = -1;           /* Level */
static int hf_atn_cpdlc_dM30Level = -1;           /* Level */
static int hf_atn_cpdlc_dM31Position = -1;        /* Position */
static int hf_atn_cpdlc_dM32Level = -1;           /* Level */
static int hf_atn_cpdlc_dM33Position = -1;        /* Position */
static int hf_atn_cpdlc_dM34Speed = -1;           /* Speed */
static int hf_atn_cpdlc_dM35Degrees = -1;         /* Degrees */
static int hf_atn_cpdlc_dM36Degrees = -1;         /* Degrees */
static int hf_atn_cpdlc_dM37Level = -1;           /* Level */
static int hf_atn_cpdlc_dM38Level = -1;           /* Level */
static int hf_atn_cpdlc_dM39Speed = -1;           /* Speed */
static int hf_atn_cpdlc_dM40RouteClearance = -1;  /* RouteClearanceIndex */
static int hf_atn_cpdlc_dM41NULL = -1;            /* NULL */
static int hf_atn_cpdlc_dM42Position = -1;        /* Position */
static int hf_atn_cpdlc_dM43Time = -1;            /* Time */
static int hf_atn_cpdlc_dM44Position = -1;        /* Position */
static int hf_atn_cpdlc_dM45Position = -1;        /* Position */
static int hf_atn_cpdlc_dM46Time = -1;            /* Time */
static int hf_atn_cpdlc_dM47Code = -1;            /* Code */
static int hf_atn_cpdlc_dM48PositionReport = -1;  /* PositionReport */
static int hf_atn_cpdlc_dM49Speed = -1;           /* Speed */
static int hf_atn_cpdlc_dM50SpeedSpeed = -1;      /* SpeedSpeed */
static int hf_atn_cpdlc_dM51NULL = -1;            /* NULL */
static int hf_atn_cpdlc_dM52NULL = -1;            /* NULL */
static int hf_atn_cpdlc_dM53NULL = -1;            /* NULL */
static int hf_atn_cpdlc_dM54Level = -1;           /* Level */
static int hf_atn_cpdlc_dM55NULL = -1;            /* NULL */
static int hf_atn_cpdlc_dM56NULL = -1;            /* NULL */
static int hf_atn_cpdlc_dM57RemainingFuelPersonsOnBoard = -1;  /* RemainingFuelPersonsOnBoard */
static int hf_atn_cpdlc_dM58NULL = -1;            /* NULL */
static int hf_atn_cpdlc_dM59PositionRouteClearance = -1;  /* PositionRouteClearanceIndex */
static int hf_atn_cpdlc_dM60DistanceSpecifiedDirection = -1;  /* DistanceSpecifiedDirection */
static int hf_atn_cpdlc_dM61Level = -1;           /* Level */
static int hf_atn_cpdlc_dM62ErrorInformation = -1;  /* ErrorInformation */
static int hf_atn_cpdlc_dM63NULL = -1;            /* NULL */
static int hf_atn_cpdlc_dM64FacilityDesignation = -1;  /* FacilityDesignation */
static int hf_atn_cpdlc_dM65NULL = -1;            /* NULL */
static int hf_atn_cpdlc_dM66NULL = -1;            /* NULL */
static int hf_atn_cpdlc_dM67FreeText = -1;        /* FreeText */
static int hf_atn_cpdlc_dM68FreeText = -1;        /* FreeText */
static int hf_atn_cpdlc_dM69NULL = -1;            /* NULL */
static int hf_atn_cpdlc_dM70Degrees = -1;         /* Degrees */
static int hf_atn_cpdlc_dM71Degrees = -1;         /* Degrees */
static int hf_atn_cpdlc_dM72Level = -1;           /* Level */
static int hf_atn_cpdlc_dM73Versionnumber = -1;   /* VersionNumber */
static int hf_atn_cpdlc_dM74NULL = -1;            /* NULL */
static int hf_atn_cpdlc_dM75NULL = -1;            /* NULL */
static int hf_atn_cpdlc_dM76LevelLevel = -1;      /* LevelLevel */
static int hf_atn_cpdlc_dM77LevelLevel = -1;      /* LevelLevel */
static int hf_atn_cpdlc_dM78TimeDistanceToFromPosition = -1;  /* TimeDistanceToFromPosition */
static int hf_atn_cpdlc_dM79AtisCode = -1;        /* ATISCode */
static int hf_atn_cpdlc_dM80DistanceSpecifiedDirection = -1;  /* DistanceSpecifiedDirection */
static int hf_atn_cpdlc_dM81LevelTime = -1;       /* LevelTime */
static int hf_atn_cpdlc_dM82Level = -1;           /* Level */
static int hf_atn_cpdlc_dM83SpeedTime = -1;       /* SpeedTime */
static int hf_atn_cpdlc_dM84Speed = -1;           /* Speed */
static int hf_atn_cpdlc_dM85DistanceSpecifiedDirectionTime = -1;  /* DistanceSpecifiedDirectionTime */
static int hf_atn_cpdlc_dM86DistanceSpecifiedDirection = -1;  /* DistanceSpecifiedDirection */
static int hf_atn_cpdlc_dM87Level = -1;           /* Level */
static int hf_atn_cpdlc_dM88Level = -1;           /* Level */
static int hf_atn_cpdlc_dM89UnitnameFrequency = -1;  /* UnitNameFrequency */
static int hf_atn_cpdlc_dM90FreeText = -1;        /* FreeText */
static int hf_atn_cpdlc_dM91FreeText = -1;        /* FreeText */
static int hf_atn_cpdlc_dM92FreeText = -1;        /* FreeText */
static int hf_atn_cpdlc_dM93FreeText = -1;        /* FreeText */
static int hf_atn_cpdlc_dM94FreeText = -1;        /* FreeText */
static int hf_atn_cpdlc_dM95FreeText = -1;        /* FreeText */
static int hf_atn_cpdlc_dM96FreeText = -1;        /* FreeText */
static int hf_atn_cpdlc_dM97FreeText = -1;        /* FreeText */
static int hf_atn_cpdlc_dM98FreeText = -1;        /* FreeText */
static int hf_atn_cpdlc_dM99NULL = -1;            /* NULL */
static int hf_atn_cpdlc_dM100NULL = -1;           /* NULL */
static int hf_atn_cpdlc_dM101NULL = -1;           /* NULL */
static int hf_atn_cpdlc_dM102NULL = -1;           /* NULL */
static int hf_atn_cpdlc_dM103NULL = -1;           /* NULL */
static int hf_atn_cpdlc_dM104PositionTime = -1;   /* PositionTime */
static int hf_atn_cpdlc_dM105Airport = -1;        /* Airport */
static int hf_atn_cpdlc_dM106Level = -1;          /* Level */
static int hf_atn_cpdlc_dM107NULL = -1;           /* NULL */
static int hf_atn_cpdlc_dM108NULL = -1;           /* NULL */
static int hf_atn_cpdlc_dM109Time = -1;           /* Time */
static int hf_atn_cpdlc_dM110Position = -1;       /* Position */
static int hf_atn_cpdlc_dM111TimePosition = -1;   /* TimePosition */
static int hf_atn_cpdlc_dM112NULL = -1;           /* NULL */
static int hf_atn_cpdlc_dM113SpeedTypeSpeedTypeSpeedTypeSpeed = -1;  /* SpeedTypeSpeedTypeSpeedTypeSpeed */
static int hf_atn_cpdlc_altimeterEnglish = -1;    /* AltimeterEnglish */
static int hf_atn_cpdlc_altimeterMetric = -1;     /* AltimeterMetric */
static int hf_atn_cpdlc_position = -1;            /* Position */
static int hf_atn_cpdlc_aTWDistance = -1;         /* ATWDistance */
static int hf_atn_cpdlc_speed = -1;               /* Speed */
static int hf_atn_cpdlc_aTWLevels = -1;           /* ATWLevelSequence */
static int hf_atn_cpdlc_atw = -1;                 /* ATWLevelTolerance */
static int hf_atn_cpdlc_level = -1;               /* Level */
static int hf_atn_cpdlc_ATWLevelSequence_item = -1;  /* ATWLevel */
static int hf_atn_cpdlc_atwDistanceTolerance = -1;  /* ATWDistanceTolerance */
static int hf_atn_cpdlc_distance = -1;            /* Distance */
static int hf_atn_cpdlc_Code_item = -1;           /* CodeOctalDigit */
static int hf_atn_cpdlc_time = -1;                /* Time */
static int hf_atn_cpdlc_timeTolerance = -1;       /* TimeTolerance */
static int hf_atn_cpdlc_year = -1;                /* Year */
static int hf_atn_cpdlc_month = -1;               /* Month */
static int hf_atn_cpdlc_day = -1;                 /* Day */
static int hf_atn_cpdlc_date = -1;                /* Date */
static int hf_atn_cpdlc_timehhmmss = -1;          /* Timehhmmss */
static int hf_atn_cpdlc_degreesMagnetic = -1;     /* DegreesMagnetic */
static int hf_atn_cpdlc_degreesTrue = -1;         /* DegreesTrue */
static int hf_atn_cpdlc_aircraftFlightIdentification = -1;  /* AircraftFlightIdentification */
static int hf_atn_cpdlc_clearanceLimit = -1;      /* Position */
static int hf_atn_cpdlc_flightInformation = -1;   /* FlightInformation */
static int hf_atn_cpdlc_furtherInstructions = -1;  /* FurtherInstructions */
static int hf_atn_cpdlc_direction = -1;           /* Direction */
static int hf_atn_cpdlc_degrees = -1;             /* Degrees */
static int hf_atn_cpdlc_distanceNm = -1;          /* DistanceNm */
static int hf_atn_cpdlc_distanceKm = -1;          /* DistanceKm */
static int hf_atn_cpdlc_distanceSpecifiedNm = -1;  /* DistanceSpecifiedNm */
static int hf_atn_cpdlc_distanceSpecifiedKm = -1;  /* DistanceSpecifiedKm */
static int hf_atn_cpdlc_distanceSpecified = -1;   /* DistanceSpecified */
static int hf_atn_cpdlc_distanceSpecifiedDirection = -1;  /* DistanceSpecifiedDirection */
static int hf_atn_cpdlc_noFacility = -1;          /* NULL */
static int hf_atn_cpdlc_facilityDesignation = -1;  /* FacilityDesignation */
static int hf_atn_cpdlc_altimeter = -1;           /* Altimeter */
static int hf_atn_cpdlc_aTISCode = -1;            /* ATISCode */
static int hf_atn_cpdlc_fixname_name = -1;        /* Fix */
static int hf_atn_cpdlc_latlon = -1;              /* LatitudeLongitude */
static int hf_atn_cpdlc_routeOfFlight = -1;       /* RouteInformation */
static int hf_atn_cpdlc_levelsOfFlight = -1;      /* LevelsOfFlight */
static int hf_atn_cpdlc_routeAndLevels = -1;      /* RouteAndLevels */
static int hf_atn_cpdlc_frequencyhf = -1;         /* Frequencyhf */
static int hf_atn_cpdlc_frequencyvhf = -1;        /* Frequencyvhf */
static int hf_atn_cpdlc_frequencyuhf = -1;        /* Frequencyuhf */
static int hf_atn_cpdlc_frequencysatchannel = -1;  /* Frequencysatchannel */
static int hf_atn_cpdlc_code = -1;                /* Code */
static int hf_atn_cpdlc_frequencyDeparture = -1;  /* UnitNameFrequency */
static int hf_atn_cpdlc_clearanceExpiryTime = -1;  /* Time */
static int hf_atn_cpdlc_airportDeparture = -1;    /* Airport */
static int hf_atn_cpdlc_airportDestination = -1;  /* Airport */
static int hf_atn_cpdlc_timeDeparture = -1;       /* TimeDeparture */
static int hf_atn_cpdlc_runwayDeparture = -1;     /* Runway */
static int hf_atn_cpdlc_revisionNumber = -1;      /* RevisionNumber */
static int hf_atn_cpdlc_holdatwaypointspeedlow = -1;  /* Speed */
static int hf_atn_cpdlc_aTWlevel = -1;            /* ATWLevel */
static int hf_atn_cpdlc_holdatwaypointspeedhigh = -1;  /* Speed */
static int hf_atn_cpdlc_eFCtime = -1;             /* Time */
static int hf_atn_cpdlc_legtype = -1;             /* LegType */
static int hf_atn_cpdlc_legType = -1;             /* LegType */
static int hf_atn_cpdlc_fromSelection = -1;       /* InterceptCourseFromSelection */
static int hf_atn_cpdlc_publishedIdentifier = -1;  /* PublishedIdentifier */
static int hf_atn_cpdlc_latitudeLongitude = -1;   /* LatitudeLongitude */
static int hf_atn_cpdlc_placeBearingPlaceBearing = -1;  /* PlaceBearingPlaceBearing */
static int hf_atn_cpdlc_placeBearingDistance = -1;  /* PlaceBearingDistance */
static int hf_atn_cpdlc_latitudeType = -1;        /* LatitudeType */
static int hf_atn_cpdlc_latitudeDirection = -1;   /* LatitudeDirection */
static int hf_atn_cpdlc_latitudeWholeDegrees = -1;  /* LatitudeWholeDegrees */
static int hf_atn_cpdlc_minutesLatLon = -1;       /* MinutesLatLon */
static int hf_atn_cpdlc_latlonWholeMinutes = -1;  /* LatLonWholeMinutes */
static int hf_atn_cpdlc_secondsLatLon = -1;       /* SecondsLatLon */
static int hf_atn_cpdlc_latitude = -1;            /* Latitude */
static int hf_atn_cpdlc_longitude = -1;           /* Longitude */
static int hf_atn_cpdlc_latitudeDegrees = -1;     /* LatitudeDegrees */
static int hf_atn_cpdlc_latitudeDegreesMinutes = -1;  /* LatitudeDegreesMinutes */
static int hf_atn_cpdlc_latitudeDMS = -1;         /* LatitudeDegreesMinutesSeconds */
static int hf_atn_cpdlc_latitudeReportingPoints = -1;  /* LatitudeReportingPoints */
static int hf_atn_cpdlc_longitudeReportingPoints = -1;  /* LongitudeReportingPoints */
static int hf_atn_cpdlc_legDistanceEnglish = -1;  /* LegDistanceEnglish */
static int hf_atn_cpdlc_legDistanceMetric = -1;   /* LegDistanceMetric */
static int hf_atn_cpdlc_legDistance = -1;         /* LegDistance */
static int hf_atn_cpdlc_legTime = -1;             /* LegTime */
static int hf_atn_cpdlc_singleLevel = -1;         /* LevelType */
static int hf_atn_cpdlc_blockLevel = -1;          /* SEQUENCE_SIZE_2_OF_LevelType */
static int hf_atn_cpdlc_blockLevel_item = -1;     /* LevelType */
static int hf_atn_cpdlc_LevelLevel_item = -1;     /* Level */
static int hf_atn_cpdlc_procedureName = -1;       /* ProcedureName */
static int hf_atn_cpdlc_levelProcedureName = -1;  /* LevelProcedureName */
static int hf_atn_cpdlc_levelspeed_speed = -1;    /* SpeedSpeed */
static int hf_atn_cpdlc_speeds = -1;              /* SpeedSpeed */
static int hf_atn_cpdlc_levelFeet = -1;           /* LevelFeet */
static int hf_atn_cpdlc_levelMeters = -1;         /* LevelMeters */
static int hf_atn_cpdlc_levelFlightLevel = -1;    /* LevelFlightLevel */
static int hf_atn_cpdlc_levelFlightLevelMetric = -1;  /* LevelFlightLevelMetric */
static int hf_atn_cpdlc_longitudeType = -1;       /* LongitudeType */
static int hf_atn_cpdlc_longitudeDirection = -1;  /* LongitudeDirection */
static int hf_atn_cpdlc_longitudeWholeDegrees = -1;  /* LongitudeWholeDegrees */
static int hf_atn_cpdlc_latLonWholeMinutes = -1;  /* LatLonWholeMinutes */
static int hf_atn_cpdlc_longitudeDegrees = -1;    /* LongitudeDegrees */
static int hf_atn_cpdlc_longitudeDegreesMinutes = -1;  /* LongitudeDegreesMinutes */
static int hf_atn_cpdlc_longitudeDMS = -1;        /* LongitudeDegreesMinutesSeconds */
static int hf_atn_cpdlc_navaid_name = -1;         /* NavaidName */
static int hf_atn_cpdlc_PlaceBearingPlaceBearing_item = -1;  /* PlaceBearing */
static int hf_atn_cpdlc_fixName = -1;             /* FixName */
static int hf_atn_cpdlc_navaid = -1;              /* Navaid */
static int hf_atn_cpdlc_airport = -1;             /* Airport */
static int hf_atn_cpdlc_levels = -1;              /* LevelLevel */
static int hf_atn_cpdlc_positionlevel = -1;       /* PositionLevel */
static int hf_atn_cpdlc_PositionPosition_item = -1;  /* Position */
static int hf_atn_cpdlc_positioncurrent = -1;     /* Position */
static int hf_atn_cpdlc_timeatpositioncurrent = -1;  /* Time */
static int hf_atn_cpdlc_fixnext = -1;             /* Position */
static int hf_atn_cpdlc_timeetaatfixnext = -1;    /* Time */
static int hf_atn_cpdlc_fixnextplusone = -1;      /* Position */
static int hf_atn_cpdlc_timeetaatdestination = -1;  /* Time */
static int hf_atn_cpdlc_remainingFuel = -1;       /* RemainingFuel */
static int hf_atn_cpdlc_temperature = -1;         /* Temperature */
static int hf_atn_cpdlc_winds = -1;               /* Winds */
static int hf_atn_cpdlc_turbulence = -1;          /* Turbulence */
static int hf_atn_cpdlc_icing = -1;               /* Icing */
static int hf_atn_cpdlc_speedground = -1;         /* SpeedGround */
static int hf_atn_cpdlc_verticalChange = -1;      /* VerticalChange */
static int hf_atn_cpdlc_trackAngle = -1;          /* Degrees */
static int hf_atn_cpdlc_heading = -1;             /* Degrees */
static int hf_atn_cpdlc_humidity = -1;            /* Humidity */
static int hf_atn_cpdlc_reportedWaypointPosition = -1;  /* Position */
static int hf_atn_cpdlc_reportedWaypointTime = -1;  /* Time */
static int hf_atn_cpdlc_reportedWaypointLevel = -1;  /* Level */
static int hf_atn_cpdlc_routeClearanceIndex = -1;  /* RouteClearanceIndex */
static int hf_atn_cpdlc_positionTime = -1;        /* PositionTime */
static int hf_atn_cpdlc_times = -1;               /* TimeTime */
static int hf_atn_cpdlc_unitname = -1;            /* UnitName */
static int hf_atn_cpdlc_frequency = -1;           /* Frequency */
static int hf_atn_cpdlc_type = -1;                /* ProcedureType */
static int hf_atn_cpdlc_procedure = -1;           /* Procedure */
static int hf_atn_cpdlc_transition = -1;          /* ProcedureTransition */
static int hf_atn_cpdlc_personsOnBoard = -1;      /* PersonsOnBoard */
static int hf_atn_cpdlc_latLonReportingPoints = -1;  /* LatLonReportingPoints */
static int hf_atn_cpdlc_degreeIncrement = -1;     /* DegreeIncrement */
static int hf_atn_cpdlc_procedureDeparture = -1;  /* ProcedureName */
static int hf_atn_cpdlc_runwayArrival = -1;       /* Runway */
static int hf_atn_cpdlc_procedureApproach = -1;   /* ProcedureName */
static int hf_atn_cpdlc_procedureArrival = -1;    /* ProcedureName */
static int hf_atn_cpdlc_routeInformations = -1;   /* SEQUENCE_SIZE_1_128_OF_RouteInformation */
static int hf_atn_cpdlc_routeInformations_item = -1;  /* RouteInformation */
static int hf_atn_cpdlc_routeInformationAdditional = -1;  /* RouteInformationAdditional */
static int hf_atn_cpdlc_aTSRouteDesignator = -1;  /* ATSRouteDesignator */
static int hf_atn_cpdlc_aTWAlongTrackWaypoints = -1;  /* SEQUENCE_SIZE_1_8_OF_ATWAlongTrackWaypoint */
static int hf_atn_cpdlc_aTWAlongTrackWaypoints_item = -1;  /* ATWAlongTrackWaypoint */
static int hf_atn_cpdlc_reportingpoints = -1;     /* ReportingPoints */
static int hf_atn_cpdlc_interceptCourseFroms = -1;  /* SEQUENCE_SIZE_1_4_OF_InterceptCourseFrom */
static int hf_atn_cpdlc_interceptCourseFroms_item = -1;  /* InterceptCourseFrom */
static int hf_atn_cpdlc_holdAtWaypoints = -1;     /* SEQUENCE_SIZE_1_8_OF_Holdatwaypoint */
static int hf_atn_cpdlc_holdAtWaypoints_item = -1;  /* Holdatwaypoint */
static int hf_atn_cpdlc_waypointSpeedLevels = -1;  /* SEQUENCE_SIZE_1_32_OF_WaypointSpeedLevel */
static int hf_atn_cpdlc_waypointSpeedLevels_item = -1;  /* WaypointSpeedLevel */
static int hf_atn_cpdlc_rTARequiredTimeArrivals = -1;  /* SEQUENCE_SIZE_1_32_OF_RTARequiredTimeArrival */
static int hf_atn_cpdlc_rTARequiredTimeArrivals_item = -1;  /* RTARequiredTimeArrival */
static int hf_atn_cpdlc_rTATime = -1;             /* RTATime */
static int hf_atn_cpdlc_rTATolerance = -1;        /* RTATolerance */
static int hf_atn_cpdlc_runway_direction = -1;    /* RunwayDirection */
static int hf_atn_cpdlc_configuration = -1;       /* RunwayConfiguration */
static int hf_atn_cpdlc_runway = -1;              /* Runway */
static int hf_atn_cpdlc_rVR = -1;                 /* RVR */
static int hf_atn_cpdlc_rVRFeet = -1;             /* RVRFeet */
static int hf_atn_cpdlc_rVRMeters = -1;           /* RVRMeters */
static int hf_atn_cpdlc_speedIndicated = -1;      /* SpeedIndicated */
static int hf_atn_cpdlc_speedIndicatedMetric = -1;  /* SpeedIndicatedMetric */
static int hf_atn_cpdlc_speedTrue = -1;           /* SpeedTrue */
static int hf_atn_cpdlc_speedTrueMetric = -1;     /* SpeedTrueMetric */
static int hf_atn_cpdlc_speedGround = -1;         /* SpeedGround */
static int hf_atn_cpdlc_speedGroundMetric = -1;   /* SpeedGroundMetric */
static int hf_atn_cpdlc_speedMach = -1;           /* SpeedMach */
static int hf_atn_cpdlc_SpeedSpeed_item = -1;     /* Speed */
static int hf_atn_cpdlc_SpeedTypeSpeedTypeSpeedType_item = -1;  /* SpeedType */
static int hf_atn_cpdlc_speedTypes = -1;          /* SpeedTypeSpeedTypeSpeedType */
static int hf_atn_cpdlc_hours = -1;               /* TimeHours */
static int hf_atn_cpdlc_minutes = -1;             /* TimeMinutes */
static int hf_atn_cpdlc_timeDepartureAllocated = -1;  /* Time */
static int hf_atn_cpdlc_timeDepartureControlled = -1;  /* ControlledTime */
static int hf_atn_cpdlc_timeDepartureClearanceExpected = -1;  /* Time */
static int hf_atn_cpdlc_departureMinimumInterval = -1;  /* DepartureMinimumInterval */
static int hf_atn_cpdlc_tofrom = -1;              /* ToFrom */
static int hf_atn_cpdlc_hoursminutes = -1;        /* Time */
static int hf_atn_cpdlc_seconds = -1;             /* TimeSeconds */
static int hf_atn_cpdlc_unitName = -1;            /* UnitName */
static int hf_atn_cpdlc_timeposition = -1;        /* TimePosition */
static int hf_atn_cpdlc_levelspeed = -1;          /* LevelSpeed */
static int hf_atn_cpdlc_speedspeed = -1;          /* SpeedSpeed */
static int hf_atn_cpdlc_TimeTime_item = -1;       /* Time */
static int hf_atn_cpdlc_toFrom = -1;              /* ToFrom */
static int hf_atn_cpdlc_facilityName = -1;        /* FacilityName */
static int hf_atn_cpdlc_facilityFunction = -1;    /* FacilityFunction */
static int hf_atn_cpdlc_vertical_direction = -1;  /* VerticalDirection */
static int hf_atn_cpdlc_rate = -1;                /* VerticalRate */
static int hf_atn_cpdlc_verticalRateEnglish = -1;  /* VerticalRateEnglish */
static int hf_atn_cpdlc_verticalRateMetric = -1;  /* VerticalRateMetric */
static int hf_atn_cpdlc_winds_direction = -1;     /* WindDirection */
static int hf_atn_cpdlc_winds_speed = -1;         /* WindSpeed */
static int hf_atn_cpdlc_windSpeedEnglish = -1;    /* WindSpeedEnglish */
static int hf_atn_cpdlc_windSpeedMetric = -1;     /* WindSpeedMetric */

/*--- End of included file: packet-atn-cpdlc-hf.c ---*/
#line 97 "./asn1/atn-cpdlc/packet-atn-cpdlc-template.c"


/*--- Included file: packet-atn-cpdlc-ett.c ---*/
#line 1 "./asn1/atn-cpdlc/packet-atn-cpdlc-ett.c"
static gint ett_atn_cpdlc_GroundPDUs = -1;
static gint ett_atn_cpdlc_UplinkMessage = -1;
static gint ett_atn_cpdlc_AircraftPDUs = -1;
static gint ett_atn_cpdlc_StartDownMessage = -1;
static gint ett_atn_cpdlc_DownlinkMessage = -1;
static gint ett_atn_cpdlc_ProtectedGroundPDUs = -1;
static gint ett_atn_cpdlc_ProtectedUplinkMessage = -1;
static gint ett_atn_cpdlc_ATCForwardMessage = -1;
static gint ett_atn_cpdlc_ForwardHeader = -1;
static gint ett_atn_cpdlc_ForwardMessage = -1;
static gint ett_atn_cpdlc_ProtectedAircraftPDUs = -1;
static gint ett_atn_cpdlc_ProtectedStartDownMessage = -1;
static gint ett_atn_cpdlc_ProtectedDownlinkMessage = -1;
static gint ett_atn_cpdlc_ATCUplinkMessage = -1;
static gint ett_atn_cpdlc_ATCUplinkMessageData = -1;
static gint ett_atn_cpdlc_SEQUENCE_SIZE_1_5_OF_ATCUplinkMsgElementId = -1;
static gint ett_atn_cpdlc_T_atcuplinkmessagedata_constraineddata = -1;
static gint ett_atn_cpdlc_SEQUENCE_SIZE_1_2_OF_RouteClearance = -1;
static gint ett_atn_cpdlc_ATCDownlinkMessage = -1;
static gint ett_atn_cpdlc_ATCDownlinkMessageData = -1;
static gint ett_atn_cpdlc_SEQUENCE_SIZE_1_5_OF_ATCDownlinkMsgElementId = -1;
static gint ett_atn_cpdlc_T_atcdownlinkmessagedata_constraineddata = -1;
static gint ett_atn_cpdlc_ATCMessageHeader = -1;
static gint ett_atn_cpdlc_ATCUplinkMsgElementId = -1;
static gint ett_atn_cpdlc_ATCDownlinkMsgElementId = -1;
static gint ett_atn_cpdlc_Altimeter = -1;
static gint ett_atn_cpdlc_ATWAlongTrackWaypoint = -1;
static gint ett_atn_cpdlc_ATWLevel = -1;
static gint ett_atn_cpdlc_ATWLevelSequence = -1;
static gint ett_atn_cpdlc_ATWDistance = -1;
static gint ett_atn_cpdlc_Code = -1;
static gint ett_atn_cpdlc_ControlledTime = -1;
static gint ett_atn_cpdlc_Date = -1;
static gint ett_atn_cpdlc_DateTimeGroup = -1;
static gint ett_atn_cpdlc_Degrees = -1;
static gint ett_atn_cpdlc_DepartureClearance = -1;
static gint ett_atn_cpdlc_DirectionDegrees = -1;
static gint ett_atn_cpdlc_Distance = -1;
static gint ett_atn_cpdlc_DistanceSpecified = -1;
static gint ett_atn_cpdlc_DistanceSpecifiedDirection = -1;
static gint ett_atn_cpdlc_DistanceSpecifiedDirectionTime = -1;
static gint ett_atn_cpdlc_Facility = -1;
static gint ett_atn_cpdlc_FacilityDesignationAltimeter = -1;
static gint ett_atn_cpdlc_FacilityDesignationATISCode = -1;
static gint ett_atn_cpdlc_FixName = -1;
static gint ett_atn_cpdlc_FlightInformation = -1;
static gint ett_atn_cpdlc_Frequency = -1;
static gint ett_atn_cpdlc_FurtherInstructions = -1;
static gint ett_atn_cpdlc_Holdatwaypoint = -1;
static gint ett_atn_cpdlc_HoldClearance = -1;
static gint ett_atn_cpdlc_InterceptCourseFrom = -1;
static gint ett_atn_cpdlc_InterceptCourseFromSelection = -1;
static gint ett_atn_cpdlc_Latitude = -1;
static gint ett_atn_cpdlc_LatitudeDegreesMinutes = -1;
static gint ett_atn_cpdlc_LatitudeDegreesMinutesSeconds = -1;
static gint ett_atn_cpdlc_LatitudeLongitude = -1;
static gint ett_atn_cpdlc_LatitudeReportingPoints = -1;
static gint ett_atn_cpdlc_LatitudeType = -1;
static gint ett_atn_cpdlc_LatLonReportingPoints = -1;
static gint ett_atn_cpdlc_LegDistance = -1;
static gint ett_atn_cpdlc_LegType = -1;
static gint ett_atn_cpdlc_Level = -1;
static gint ett_atn_cpdlc_SEQUENCE_SIZE_2_OF_LevelType = -1;
static gint ett_atn_cpdlc_LevelLevel = -1;
static gint ett_atn_cpdlc_LevelPosition = -1;
static gint ett_atn_cpdlc_LevelProcedureName = -1;
static gint ett_atn_cpdlc_LevelsOfFlight = -1;
static gint ett_atn_cpdlc_LevelSpeed = -1;
static gint ett_atn_cpdlc_LevelSpeedSpeed = -1;
static gint ett_atn_cpdlc_LevelTime = -1;
static gint ett_atn_cpdlc_LevelType = -1;
static gint ett_atn_cpdlc_Longitude = -1;
static gint ett_atn_cpdlc_LongitudeDegreesMinutes = -1;
static gint ett_atn_cpdlc_LongitudeDegreesMinutesSeconds = -1;
static gint ett_atn_cpdlc_LongitudeReportingPoints = -1;
static gint ett_atn_cpdlc_LongitudeType = -1;
static gint ett_atn_cpdlc_Navaid = -1;
static gint ett_atn_cpdlc_PlaceBearing = -1;
static gint ett_atn_cpdlc_PlaceBearingDistance = -1;
static gint ett_atn_cpdlc_PlaceBearingPlaceBearing = -1;
static gint ett_atn_cpdlc_Position = -1;
static gint ett_atn_cpdlc_PositionDegrees = -1;
static gint ett_atn_cpdlc_PositionDistanceSpecifiedDirection = -1;
static gint ett_atn_cpdlc_PositionLevel = -1;
static gint ett_atn_cpdlc_PositionLevelLevel = -1;
static gint ett_atn_cpdlc_PositionLevelSpeed = -1;
static gint ett_atn_cpdlc_PositionPosition = -1;
static gint ett_atn_cpdlc_PositionProcedureName = -1;
static gint ett_atn_cpdlc_PositionReport = -1;
static gint ett_atn_cpdlc_PositionRouteClearanceIndex = -1;
static gint ett_atn_cpdlc_PositionSpeed = -1;
static gint ett_atn_cpdlc_PositionSpeedSpeed = -1;
static gint ett_atn_cpdlc_PositionTime = -1;
static gint ett_atn_cpdlc_PositionTimeLevel = -1;
static gint ett_atn_cpdlc_PositionTimeTime = -1;
static gint ett_atn_cpdlc_PositionUnitNameFrequency = -1;
static gint ett_atn_cpdlc_ProcedureName = -1;
static gint ett_atn_cpdlc_PublishedIdentifier = -1;
static gint ett_atn_cpdlc_RemainingFuelPersonsOnBoard = -1;
static gint ett_atn_cpdlc_ReportingPoints = -1;
static gint ett_atn_cpdlc_RouteAndLevels = -1;
static gint ett_atn_cpdlc_RouteClearance = -1;
static gint ett_atn_cpdlc_SEQUENCE_SIZE_1_128_OF_RouteInformation = -1;
static gint ett_atn_cpdlc_RouteInformation = -1;
static gint ett_atn_cpdlc_RouteInformationAdditional = -1;
static gint ett_atn_cpdlc_SEQUENCE_SIZE_1_8_OF_ATWAlongTrackWaypoint = -1;
static gint ett_atn_cpdlc_SEQUENCE_SIZE_1_4_OF_InterceptCourseFrom = -1;
static gint ett_atn_cpdlc_SEQUENCE_SIZE_1_8_OF_Holdatwaypoint = -1;
static gint ett_atn_cpdlc_SEQUENCE_SIZE_1_32_OF_WaypointSpeedLevel = -1;
static gint ett_atn_cpdlc_SEQUENCE_SIZE_1_32_OF_RTARequiredTimeArrival = -1;
static gint ett_atn_cpdlc_RTARequiredTimeArrival = -1;
static gint ett_atn_cpdlc_RTATime = -1;
static gint ett_atn_cpdlc_Runway = -1;
static gint ett_atn_cpdlc_RunwayRVR = -1;
static gint ett_atn_cpdlc_RVR = -1;
static gint ett_atn_cpdlc_Speed = -1;
static gint ett_atn_cpdlc_SpeedSpeed = -1;
static gint ett_atn_cpdlc_SpeedTime = -1;
static gint ett_atn_cpdlc_SpeedTypeSpeedTypeSpeedType = -1;
static gint ett_atn_cpdlc_SpeedTypeSpeedTypeSpeedTypeSpeed = -1;
static gint ett_atn_cpdlc_Time = -1;
static gint ett_atn_cpdlc_TimeLevel = -1;
static gint ett_atn_cpdlc_TimeDeparture = -1;
static gint ett_atn_cpdlc_TimeDistanceSpecifiedDirection = -1;
static gint ett_atn_cpdlc_TimeDistanceToFromPosition = -1;
static gint ett_atn_cpdlc_Timehhmmss = -1;
static gint ett_atn_cpdlc_TimeUnitNameFrequency = -1;
static gint ett_atn_cpdlc_TimePosition = -1;
static gint ett_atn_cpdlc_TimePositionLevel = -1;
static gint ett_atn_cpdlc_TimePositionLevelSpeed = -1;
static gint ett_atn_cpdlc_TimeSpeed = -1;
static gint ett_atn_cpdlc_TimeSpeedSpeed = -1;
static gint ett_atn_cpdlc_TimeTime = -1;
static gint ett_atn_cpdlc_TimeToFromPosition = -1;
static gint ett_atn_cpdlc_ToFromPosition = -1;
static gint ett_atn_cpdlc_UnitName = -1;
static gint ett_atn_cpdlc_UnitNameFrequency = -1;
static gint ett_atn_cpdlc_VerticalChange = -1;
static gint ett_atn_cpdlc_VerticalRate = -1;
static gint ett_atn_cpdlc_WaypointSpeedLevel = -1;
static gint ett_atn_cpdlc_Winds = -1;
static gint ett_atn_cpdlc_WindSpeed = -1;

/*--- End of included file: packet-atn-cpdlc-ett.c ---*/
#line 99 "./asn1/atn-cpdlc/packet-atn-cpdlc-template.c"
static gint ett_atn_cpdlc = -1;


/*--- Included file: packet-atn-cpdlc-fn.c ---*/
#line 1 "./asn1/atn-cpdlc/packet-atn-cpdlc-fn.c"

static const value_string atn_cpdlc_CPDLCUserAbortReason_vals[] = {
  {   0, "undefined" },
  {   1, "no-message-identification-numbers-available" },
  {   2, "duplicate-message-identification-numbers" },
  {   3, "no-longer-next-data-authority" },
  {   4, "current-data-authority-abort" },
  {   5, "commanded-termination" },
  {   6, "invalid-response" },
  { 0, NULL }
};


static int
dissect_atn_cpdlc_CPDLCUserAbortReason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string atn_cpdlc_CPDLCProviderAbortReason_vals[] = {
  {   0, "timer-expired" },
  {   1, "undefined-error" },
  {   2, "invalid-PDU" },
  {   3, "protocol-error" },
  {   4, "communication-service-error" },
  {   5, "communication-service-failure" },
  {   6, "invalid-QOS-parameter" },
  {   7, "expected-PDU-missing" },
  { 0, NULL }
};


static int
dissect_atn_cpdlc_CPDLCProviderAbortReason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_atn_cpdlc_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_atn_cpdlc_MsgIdentificationNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_MsgReferenceNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_Year(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1996U, 2095U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_Month(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 12U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_Day(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 31U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Date_sequence[] = {
  { &hf_atn_cpdlc_year      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Year },
  { &hf_atn_cpdlc_month     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Month },
  { &hf_atn_cpdlc_day       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Day },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_Date(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_Date, Date_sequence);

  return offset;
}



static int
dissect_atn_cpdlc_TimeHours(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 23U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_TimeMinutes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 59U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Time_sequence[] = {
  { &hf_atn_cpdlc_hours     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_TimeHours },
  { &hf_atn_cpdlc_minutes   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_TimeMinutes },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_Time(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_Time, Time_sequence);

  return offset;
}



static int
dissect_atn_cpdlc_TimeSeconds(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 59U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Timehhmmss_sequence[] = {
  { &hf_atn_cpdlc_hoursminutes, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Time },
  { &hf_atn_cpdlc_seconds   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_TimeSeconds },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_Timehhmmss(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_Timehhmmss, Timehhmmss_sequence);

  return offset;
}


static const per_sequence_t DateTimeGroup_sequence[] = {
  { &hf_atn_cpdlc_date      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Date },
  { &hf_atn_cpdlc_timehhmmss, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Timehhmmss },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_DateTimeGroup(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_DateTimeGroup, DateTimeGroup_sequence);

  return offset;
}


static const value_string atn_cpdlc_LogicalAck_vals[] = {
  {   0, "required" },
  {   1, "notRequired" },
  { 0, NULL }
};


static int
dissect_atn_cpdlc_LogicalAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t ATCMessageHeader_sequence[] = {
  { &hf_atn_cpdlc_messageIdNumber, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_MsgIdentificationNumber },
  { &hf_atn_cpdlc_messageRefNumber, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_MsgReferenceNumber },
  { &hf_atn_cpdlc_dateTime  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_DateTimeGroup },
  { &hf_atn_cpdlc_logicalAck, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_LogicalAck },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_ATCMessageHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_ATCMessageHeader, ATCMessageHeader_sequence);

  return offset;
}



static int
dissect_atn_cpdlc_LevelFeet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -60, 7000U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_LevelMeters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -30, 25000U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_LevelFlightLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            30U, 700U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_LevelFlightLevelMetric(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            100U, 2500U, NULL, FALSE);

  return offset;
}


static const value_string atn_cpdlc_LevelType_vals[] = {
  {   0, "levelFeet" },
  {   1, "levelMeters" },
  {   2, "levelFlightLevel" },
  {   3, "levelFlightLevelMetric" },
  { 0, NULL }
};

static const per_choice_t LevelType_choice[] = {
  {   0, &hf_atn_cpdlc_levelFeet , ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_LevelFeet },
  {   1, &hf_atn_cpdlc_levelMeters, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_LevelMeters },
  {   2, &hf_atn_cpdlc_levelFlightLevel, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_LevelFlightLevel },
  {   3, &hf_atn_cpdlc_levelFlightLevelMetric, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_LevelFlightLevelMetric },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_LevelType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_LevelType, LevelType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_2_OF_LevelType_sequence_of[1] = {
  { &hf_atn_cpdlc_blockLevel_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_LevelType },
};

static int
dissect_atn_cpdlc_SEQUENCE_SIZE_2_OF_LevelType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_atn_cpdlc_SEQUENCE_SIZE_2_OF_LevelType, SEQUENCE_SIZE_2_OF_LevelType_sequence_of,
                                                  2, 2, FALSE);

  return offset;
}


static const value_string atn_cpdlc_Level_vals[] = {
  {   0, "singleLevel" },
  {   1, "blockLevel" },
  { 0, NULL }
};

static const per_choice_t Level_choice[] = {
  {   0, &hf_atn_cpdlc_singleLevel, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_LevelType },
  {   1, &hf_atn_cpdlc_blockLevel, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_SEQUENCE_SIZE_2_OF_LevelType },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_Level(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_Level, Level_choice,
                                 NULL);

  return offset;
}



static int
dissect_atn_cpdlc_Fix(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,1, 5, FALSE, ia5alpha , 127, NULL);

  return offset;
}



static int
dissect_atn_cpdlc_LatitudeDegrees(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 90000U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_LatitudeWholeDegrees(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 89U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_MinutesLatLon(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 5999U, NULL, FALSE);

  return offset;
}


static const per_sequence_t LatitudeDegreesMinutes_sequence[] = {
  { &hf_atn_cpdlc_latitudeWholeDegrees, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_LatitudeWholeDegrees },
  { &hf_atn_cpdlc_minutesLatLon, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_MinutesLatLon },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_LatitudeDegreesMinutes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_LatitudeDegreesMinutes, LatitudeDegreesMinutes_sequence);

  return offset;
}



static int
dissect_atn_cpdlc_LatLonWholeMinutes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 59U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_SecondsLatLon(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 59U, NULL, FALSE);

  return offset;
}


static const per_sequence_t LatitudeDegreesMinutesSeconds_sequence[] = {
  { &hf_atn_cpdlc_latitudeWholeDegrees, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_LatitudeWholeDegrees },
  { &hf_atn_cpdlc_latlonWholeMinutes, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_LatLonWholeMinutes },
  { &hf_atn_cpdlc_secondsLatLon, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_SecondsLatLon },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_LatitudeDegreesMinutesSeconds(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_LatitudeDegreesMinutesSeconds, LatitudeDegreesMinutesSeconds_sequence);

  return offset;
}


static const value_string atn_cpdlc_LatitudeType_vals[] = {
  {   0, "latitudeDegrees" },
  {   1, "latitudeDegreesMinutes" },
  {   2, "latitudeDMS" },
  { 0, NULL }
};

static const per_choice_t LatitudeType_choice[] = {
  {   0, &hf_atn_cpdlc_latitudeDegrees, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_LatitudeDegrees },
  {   1, &hf_atn_cpdlc_latitudeDegreesMinutes, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_LatitudeDegreesMinutes },
  {   2, &hf_atn_cpdlc_latitudeDMS, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_LatitudeDegreesMinutesSeconds },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_LatitudeType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_LatitudeType, LatitudeType_choice,
                                 NULL);

  return offset;
}


static const value_string atn_cpdlc_LatitudeDirection_vals[] = {
  {   0, "north" },
  {   1, "south" },
  { 0, NULL }
};


static int
dissect_atn_cpdlc_LatitudeDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t Latitude_sequence[] = {
  { &hf_atn_cpdlc_latitudeType, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_LatitudeType },
  { &hf_atn_cpdlc_latitudeDirection, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_LatitudeDirection },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_Latitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_Latitude, Latitude_sequence);

  return offset;
}



static int
dissect_atn_cpdlc_LongitudeDegrees(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 180000U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_LongitudeWholeDegrees(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 179U, NULL, FALSE);

  return offset;
}


static const per_sequence_t LongitudeDegreesMinutes_sequence[] = {
  { &hf_atn_cpdlc_longitudeWholeDegrees, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_LongitudeWholeDegrees },
  { &hf_atn_cpdlc_minutesLatLon, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_MinutesLatLon },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_LongitudeDegreesMinutes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_LongitudeDegreesMinutes, LongitudeDegreesMinutes_sequence);

  return offset;
}


static const per_sequence_t LongitudeDegreesMinutesSeconds_sequence[] = {
  { &hf_atn_cpdlc_longitudeWholeDegrees, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_LongitudeWholeDegrees },
  { &hf_atn_cpdlc_latLonWholeMinutes, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_LatLonWholeMinutes },
  { &hf_atn_cpdlc_secondsLatLon, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_SecondsLatLon },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_LongitudeDegreesMinutesSeconds(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_LongitudeDegreesMinutesSeconds, LongitudeDegreesMinutesSeconds_sequence);

  return offset;
}


static const value_string atn_cpdlc_LongitudeType_vals[] = {
  {   0, "longitudeDegrees" },
  {   1, "longitudeDegreesMinutes" },
  {   2, "longitudeDMS" },
  { 0, NULL }
};

static const per_choice_t LongitudeType_choice[] = {
  {   0, &hf_atn_cpdlc_longitudeDegrees, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_LongitudeDegrees },
  {   1, &hf_atn_cpdlc_longitudeDegreesMinutes, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_LongitudeDegreesMinutes },
  {   2, &hf_atn_cpdlc_longitudeDMS, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_LongitudeDegreesMinutesSeconds },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_LongitudeType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_LongitudeType, LongitudeType_choice,
                                 NULL);

  return offset;
}


static const value_string atn_cpdlc_LongitudeDirection_vals[] = {
  {   0, "east" },
  {   1, "west" },
  { 0, NULL }
};


static int
dissect_atn_cpdlc_LongitudeDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t Longitude_sequence[] = {
  { &hf_atn_cpdlc_longitudeType, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_LongitudeType },
  { &hf_atn_cpdlc_longitudeDirection, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_LongitudeDirection },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_Longitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_Longitude, Longitude_sequence);

  return offset;
}


static const per_sequence_t LatitudeLongitude_sequence[] = {
  { &hf_atn_cpdlc_latitude  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Latitude },
  { &hf_atn_cpdlc_longitude , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Longitude },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_LatitudeLongitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_LatitudeLongitude, LatitudeLongitude_sequence);

  return offset;
}


static const per_sequence_t FixName_sequence[] = {
  { &hf_atn_cpdlc_fixname_name, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Fix },
  { &hf_atn_cpdlc_latlon    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_LatitudeLongitude },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_FixName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_FixName, FixName_sequence);

  return offset;
}



static int
dissect_atn_cpdlc_NavaidName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,1, 4, FALSE, ia5alpha , 127, NULL);

  return offset;
}


static const per_sequence_t Navaid_sequence[] = {
  { &hf_atn_cpdlc_navaid_name, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_NavaidName },
  { &hf_atn_cpdlc_latlon    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_LatitudeLongitude },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_Navaid(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_Navaid, Navaid_sequence);

  return offset;
}



static int
dissect_atn_cpdlc_Airport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,4, 4, FALSE, ia5alpha , 127, NULL);

  return offset;
}


static const value_string atn_cpdlc_PublishedIdentifier_vals[] = {
  {   0, "fixName" },
  {   1, "navaid" },
  { 0, NULL }
};

static const per_choice_t PublishedIdentifier_choice[] = {
  {   0, &hf_atn_cpdlc_fixName   , ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_FixName },
  {   1, &hf_atn_cpdlc_navaid    , ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_Navaid },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_PublishedIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_PublishedIdentifier, PublishedIdentifier_choice,
                                 NULL);

  return offset;
}



static int
dissect_atn_cpdlc_DegreesMagnetic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 360U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_DegreesTrue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 360U, NULL, FALSE);

  return offset;
}


static const value_string atn_cpdlc_Degrees_vals[] = {
  {   0, "degreesMagnetic" },
  {   1, "degreesTrue" },
  { 0, NULL }
};

static const per_choice_t Degrees_choice[] = {
  {   0, &hf_atn_cpdlc_degreesMagnetic, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_DegreesMagnetic },
  {   1, &hf_atn_cpdlc_degreesTrue, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_DegreesTrue },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_Degrees(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_Degrees, Degrees_choice,
                                 NULL);

  return offset;
}



static int
dissect_atn_cpdlc_DistanceNm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9999U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_DistanceKm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8000U, NULL, FALSE);

  return offset;
}


static const value_string atn_cpdlc_Distance_vals[] = {
  {   0, "distanceNm" },
  {   1, "distanceKm" },
  { 0, NULL }
};

static const per_choice_t Distance_choice[] = {
  {   0, &hf_atn_cpdlc_distanceNm, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_DistanceNm },
  {   1, &hf_atn_cpdlc_distanceKm, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_DistanceKm },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_Distance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_Distance, Distance_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t PlaceBearingDistance_sequence[] = {
  { &hf_atn_cpdlc_publishedIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_PublishedIdentifier },
  { &hf_atn_cpdlc_degrees   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Degrees },
  { &hf_atn_cpdlc_distance  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Distance },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_PlaceBearingDistance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_PlaceBearingDistance, PlaceBearingDistance_sequence);

  return offset;
}


static const value_string atn_cpdlc_Position_vals[] = {
  {   0, "fixName" },
  {   1, "navaid" },
  {   2, "airport" },
  {   3, "latitudeLongitude" },
  {   4, "placeBearingDistance" },
  { 0, NULL }
};

static const per_choice_t Position_choice[] = {
  {   0, &hf_atn_cpdlc_fixName   , ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_FixName },
  {   1, &hf_atn_cpdlc_navaid    , ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_Navaid },
  {   2, &hf_atn_cpdlc_airport   , ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_Airport },
  {   3, &hf_atn_cpdlc_latitudeLongitude, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_LatitudeLongitude },
  {   4, &hf_atn_cpdlc_placeBearingDistance, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_PlaceBearingDistance },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_Position(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_Position, Position_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t TimeLevel_sequence[] = {
  { &hf_atn_cpdlc_time      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Time },
  { &hf_atn_cpdlc_level     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Level },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_TimeLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_TimeLevel, TimeLevel_sequence);

  return offset;
}


static const per_sequence_t PositionLevel_sequence[] = {
  { &hf_atn_cpdlc_position  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Position },
  { &hf_atn_cpdlc_level     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Level },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_PositionLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_PositionLevel, PositionLevel_sequence);

  return offset;
}


static const per_sequence_t LevelTime_sequence[] = {
  { &hf_atn_cpdlc_level     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Level },
  { &hf_atn_cpdlc_time      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Time },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_LevelTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_LevelTime, LevelTime_sequence);

  return offset;
}


static const per_sequence_t LevelPosition_sequence[] = {
  { &hf_atn_cpdlc_level     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Level },
  { &hf_atn_cpdlc_position  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Position },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_LevelPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_LevelPosition, LevelPosition_sequence);

  return offset;
}


static const per_sequence_t LevelLevel_sequence_of[1] = {
  { &hf_atn_cpdlc_LevelLevel_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Level },
};

static int
dissect_atn_cpdlc_LevelLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_atn_cpdlc_LevelLevel, LevelLevel_sequence_of,
                                                  2, 2, FALSE);

  return offset;
}


static const per_sequence_t PositionLevelLevel_sequence[] = {
  { &hf_atn_cpdlc_position  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Position },
  { &hf_atn_cpdlc_levels    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_LevelLevel },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_PositionLevelLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_PositionLevelLevel, PositionLevelLevel_sequence);

  return offset;
}


static const per_sequence_t PositionTime_sequence[] = {
  { &hf_atn_cpdlc_position  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Position },
  { &hf_atn_cpdlc_time      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Time },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_PositionTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_PositionTime, PositionTime_sequence);

  return offset;
}


static const per_sequence_t TimeTime_sequence_of[1] = {
  { &hf_atn_cpdlc_TimeTime_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Time },
};

static int
dissect_atn_cpdlc_TimeTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_atn_cpdlc_TimeTime, TimeTime_sequence_of,
                                                  2, 2, FALSE);

  return offset;
}


static const per_sequence_t PositionTimeTime_sequence[] = {
  { &hf_atn_cpdlc_position  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Position },
  { &hf_atn_cpdlc_times     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_TimeTime },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_PositionTimeTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_PositionTimeTime, PositionTimeTime_sequence);

  return offset;
}



static int
dissect_atn_cpdlc_SpeedIndicated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 400U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_SpeedIndicatedMetric(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 800U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_SpeedTrue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2000U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_SpeedTrueMetric(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4000U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_SpeedGround(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -50, 2000U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_SpeedGroundMetric(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -100, 4000U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_SpeedMach(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            500U, 4000U, NULL, FALSE);

  return offset;
}


static const value_string atn_cpdlc_Speed_vals[] = {
  {   0, "speedIndicated" },
  {   1, "speedIndicatedMetric" },
  {   2, "speedTrue" },
  {   3, "speedTrueMetric" },
  {   4, "speedGround" },
  {   5, "speedGroundMetric" },
  {   6, "speedMach" },
  { 0, NULL }
};

static const per_choice_t Speed_choice[] = {
  {   0, &hf_atn_cpdlc_speedIndicated, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_SpeedIndicated },
  {   1, &hf_atn_cpdlc_speedIndicatedMetric, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_SpeedIndicatedMetric },
  {   2, &hf_atn_cpdlc_speedTrue , ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_SpeedTrue },
  {   3, &hf_atn_cpdlc_speedTrueMetric, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_SpeedTrueMetric },
  {   4, &hf_atn_cpdlc_speedGround, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_SpeedGround },
  {   5, &hf_atn_cpdlc_speedGroundMetric, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_SpeedGroundMetric },
  {   6, &hf_atn_cpdlc_speedMach , ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_SpeedMach },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_Speed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_Speed, Speed_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t PositionSpeed_sequence[] = {
  { &hf_atn_cpdlc_position  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Position },
  { &hf_atn_cpdlc_speed     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Speed },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_PositionSpeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_PositionSpeed, PositionSpeed_sequence);

  return offset;
}


static const per_sequence_t PositionTimeLevel_sequence[] = {
  { &hf_atn_cpdlc_positionTime, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_PositionTime },
  { &hf_atn_cpdlc_level     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Level },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_PositionTimeLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_PositionTimeLevel, PositionTimeLevel_sequence);

  return offset;
}


static const per_sequence_t PositionLevelSpeed_sequence[] = {
  { &hf_atn_cpdlc_positionlevel, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_PositionLevel },
  { &hf_atn_cpdlc_speed     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Speed },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_PositionLevelSpeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_PositionLevelSpeed, PositionLevelSpeed_sequence);

  return offset;
}


static const per_sequence_t TimePosition_sequence[] = {
  { &hf_atn_cpdlc_time      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Time },
  { &hf_atn_cpdlc_position  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Position },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_TimePosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_TimePosition, TimePosition_sequence);

  return offset;
}


static const per_sequence_t TimePositionLevel_sequence[] = {
  { &hf_atn_cpdlc_timeposition, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_TimePosition },
  { &hf_atn_cpdlc_level     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Level },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_TimePositionLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_TimePositionLevel, TimePositionLevel_sequence);

  return offset;
}


static const per_sequence_t SpeedSpeed_sequence_of[1] = {
  { &hf_atn_cpdlc_SpeedSpeed_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Speed },
};

static int
dissect_atn_cpdlc_SpeedSpeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_atn_cpdlc_SpeedSpeed, SpeedSpeed_sequence_of,
                                                  2, 2, FALSE);

  return offset;
}


static const per_sequence_t LevelSpeed_sequence[] = {
  { &hf_atn_cpdlc_level     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Level },
  { &hf_atn_cpdlc_levelspeed_speed, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_SpeedSpeed },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_LevelSpeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_LevelSpeed, LevelSpeed_sequence);

  return offset;
}


static const per_sequence_t TimePositionLevelSpeed_sequence[] = {
  { &hf_atn_cpdlc_timeposition, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_TimePosition },
  { &hf_atn_cpdlc_levelspeed, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_LevelSpeed },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_TimePositionLevelSpeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_TimePositionLevelSpeed, TimePositionLevelSpeed_sequence);

  return offset;
}



static int
dissect_atn_cpdlc_DistanceSpecifiedNm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 250U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_DistanceSpecifiedKm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 500U, NULL, FALSE);

  return offset;
}


static const value_string atn_cpdlc_DistanceSpecified_vals[] = {
  {   0, "distanceSpecifiedNm" },
  {   1, "distanceSpecifiedKm" },
  { 0, NULL }
};

static const per_choice_t DistanceSpecified_choice[] = {
  {   0, &hf_atn_cpdlc_distanceSpecifiedNm, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_DistanceSpecifiedNm },
  {   1, &hf_atn_cpdlc_distanceSpecifiedKm, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_DistanceSpecifiedKm },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_DistanceSpecified(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_DistanceSpecified, DistanceSpecified_choice,
                                 NULL);

  return offset;
}


static const value_string atn_cpdlc_Direction_vals[] = {
  {   0, "left" },
  {   1, "right" },
  {   2, "eitherSide" },
  {   3, "north" },
  {   4, "south" },
  {   5, "east" },
  {   6, "west" },
  {   7, "northEast" },
  {   8, "northWest" },
  {   9, "southEast" },
  {  10, "southWest" },
  { 0, NULL }
};


static int
dissect_atn_cpdlc_Direction(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     11, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t DistanceSpecifiedDirection_sequence[] = {
  { &hf_atn_cpdlc_distanceSpecified, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_DistanceSpecified },
  { &hf_atn_cpdlc_direction , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Direction },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_DistanceSpecifiedDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_DistanceSpecifiedDirection, DistanceSpecifiedDirection_sequence);

  return offset;
}


static const per_sequence_t PositionDistanceSpecifiedDirection_sequence[] = {
  { &hf_atn_cpdlc_position  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Position },
  { &hf_atn_cpdlc_distanceSpecifiedDirection, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_DistanceSpecifiedDirection },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_PositionDistanceSpecifiedDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_PositionDistanceSpecifiedDirection, PositionDistanceSpecifiedDirection_sequence);

  return offset;
}


static const per_sequence_t TimeDistanceSpecifiedDirection_sequence[] = {
  { &hf_atn_cpdlc_time      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Time },
  { &hf_atn_cpdlc_distanceSpecifiedDirection, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_DistanceSpecifiedDirection },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_TimeDistanceSpecifiedDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_TimeDistanceSpecifiedDirection, TimeDistanceSpecifiedDirection_sequence);

  return offset;
}



static int
dissect_atn_cpdlc_AircraftFlightIdentification(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,2, 8, FALSE, ia5alpha , 127, NULL);

  return offset;
}


static const per_sequence_t PlaceBearing_sequence[] = {
  { &hf_atn_cpdlc_publishedIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_PublishedIdentifier },
  { &hf_atn_cpdlc_degrees   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Degrees },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_PlaceBearing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_PlaceBearing, PlaceBearing_sequence);

  return offset;
}


static const per_sequence_t PlaceBearingPlaceBearing_sequence_of[1] = {
  { &hf_atn_cpdlc_PlaceBearingPlaceBearing_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_PlaceBearing },
};

static int
dissect_atn_cpdlc_PlaceBearingPlaceBearing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_atn_cpdlc_PlaceBearingPlaceBearing, PlaceBearingPlaceBearing_sequence_of,
                                                  2, 2, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_ATSRouteDesignator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,2, 7, FALSE, ia5alpha , 127, NULL);

  return offset;
}


static const value_string atn_cpdlc_RouteInformation_vals[] = {
  {   0, "publishedIdentifier" },
  {   1, "latitudeLongitude" },
  {   2, "placeBearingPlaceBearing" },
  {   3, "placeBearingDistance" },
  {   4, "aTSRouteDesignator" },
  { 0, NULL }
};

static const per_choice_t RouteInformation_choice[] = {
  {   0, &hf_atn_cpdlc_publishedIdentifier, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_PublishedIdentifier },
  {   1, &hf_atn_cpdlc_latitudeLongitude, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_LatitudeLongitude },
  {   2, &hf_atn_cpdlc_placeBearingPlaceBearing, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_PlaceBearingPlaceBearing },
  {   3, &hf_atn_cpdlc_placeBearingDistance, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_PlaceBearingDistance },
  {   4, &hf_atn_cpdlc_aTSRouteDesignator, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_ATSRouteDesignator },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_RouteInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_RouteInformation, RouteInformation_choice,
                                 NULL);

  return offset;
}


static const value_string atn_cpdlc_ProcedureType_vals[] = {
  {   0, "arrival" },
  {   1, "approach" },
  {   2, "departure" },
  { 0, NULL }
};


static int
dissect_atn_cpdlc_ProcedureType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_atn_cpdlc_Procedure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,1, 20, FALSE, ia5alpha , 127, NULL);

  return offset;
}



static int
dissect_atn_cpdlc_ProcedureTransition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,1, 5, FALSE, ia5alpha , 127, NULL);

  return offset;
}


static const per_sequence_t ProcedureName_sequence[] = {
  { &hf_atn_cpdlc_type      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_ProcedureType },
  { &hf_atn_cpdlc_procedure , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Procedure },
  { &hf_atn_cpdlc_transition, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_ProcedureTransition },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_ProcedureName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_ProcedureName, ProcedureName_sequence);

  return offset;
}


static const per_sequence_t LevelProcedureName_sequence[] = {
  { &hf_atn_cpdlc_level     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Level },
  { &hf_atn_cpdlc_procedureName, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_ProcedureName },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_LevelProcedureName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_LevelProcedureName, LevelProcedureName_sequence);

  return offset;
}


static const value_string atn_cpdlc_LevelsOfFlight_vals[] = {
  {   0, "level" },
  {   1, "procedureName" },
  {   2, "levelProcedureName" },
  { 0, NULL }
};

static const per_choice_t LevelsOfFlight_choice[] = {
  {   0, &hf_atn_cpdlc_level     , ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_Level },
  {   1, &hf_atn_cpdlc_procedureName, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_ProcedureName },
  {   2, &hf_atn_cpdlc_levelProcedureName, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_LevelProcedureName },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_LevelsOfFlight(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_LevelsOfFlight, LevelsOfFlight_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RouteAndLevels_sequence[] = {
  { &hf_atn_cpdlc_routeOfFlight, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_RouteInformation },
  { &hf_atn_cpdlc_levelsOfFlight, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_LevelsOfFlight },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_RouteAndLevels(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_RouteAndLevels, RouteAndLevels_sequence);

  return offset;
}


static const value_string atn_cpdlc_FlightInformation_vals[] = {
  {   0, "routeOfFlight" },
  {   1, "levelsOfFlight" },
  {   2, "routeAndLevels" },
  { 0, NULL }
};

static const per_choice_t FlightInformation_choice[] = {
  {   0, &hf_atn_cpdlc_routeOfFlight, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_RouteInformation },
  {   1, &hf_atn_cpdlc_levelsOfFlight, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_LevelsOfFlight },
  {   2, &hf_atn_cpdlc_routeAndLevels, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_RouteAndLevels },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_FlightInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_FlightInformation, FlightInformation_choice,
                                 NULL);

  return offset;
}



static int
dissect_atn_cpdlc_CodeOctalDigit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Code_sequence_of[1] = {
  { &hf_atn_cpdlc_Code_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_CodeOctalDigit },
};

static int
dissect_atn_cpdlc_Code(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_atn_cpdlc_Code, Code_sequence_of,
                                                  4, 4, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_FacilityDesignation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,4, 8, FALSE, ia5alpha , 127, NULL);

  return offset;
}



static int
dissect_atn_cpdlc_FacilityName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,3, 18, FALSE, ia5alpha , 127, NULL);

  return offset;
}


static const value_string atn_cpdlc_FacilityFunction_vals[] = {
  {   0, "center" },
  {   1, "approach" },
  {   2, "tower" },
  {   3, "final" },
  {   4, "groundControl" },
  {   5, "clearanceDelivery" },
  {   6, "departure" },
  {   7, "control" },
  {   8, "radio" },
  { 0, NULL }
};


static int
dissect_atn_cpdlc_FacilityFunction(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     9, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t UnitName_sequence[] = {
  { &hf_atn_cpdlc_facilityDesignation, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_FacilityDesignation },
  { &hf_atn_cpdlc_facilityName, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_FacilityName },
  { &hf_atn_cpdlc_facilityFunction, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_FacilityFunction },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_UnitName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_UnitName, UnitName_sequence);

  return offset;
}



static int
dissect_atn_cpdlc_Frequencyhf(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            2850U, 28000U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_Frequencyvhf(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            23600U, 27398U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_Frequencyuhf(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            9000U, 15999U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_Frequencysatchannel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_NumericString(tvb, offset, actx, tree, hf_index,
                                          12, 12, FALSE);

  return offset;
}


static const value_string atn_cpdlc_Frequency_vals[] = {
  {   0, "frequencyhf" },
  {   1, "frequencyvhf" },
  {   2, "frequencyuhf" },
  {   3, "frequencysatchannel" },
  { 0, NULL }
};

static const per_choice_t Frequency_choice[] = {
  {   0, &hf_atn_cpdlc_frequencyhf, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_Frequencyhf },
  {   1, &hf_atn_cpdlc_frequencyvhf, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_Frequencyvhf },
  {   2, &hf_atn_cpdlc_frequencyuhf, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_Frequencyuhf },
  {   3, &hf_atn_cpdlc_frequencysatchannel, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_Frequencysatchannel },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_Frequency(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_Frequency, Frequency_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UnitNameFrequency_sequence[] = {
  { &hf_atn_cpdlc_unitName  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_UnitName },
  { &hf_atn_cpdlc_frequency , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Frequency },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_UnitNameFrequency(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_UnitNameFrequency, UnitNameFrequency_sequence);

  return offset;
}


static const value_string atn_cpdlc_TimeTolerance_vals[] = {
  {   0, "at" },
  {   1, "atorafter" },
  {   2, "atorbefore" },
  { 0, NULL }
};


static int
dissect_atn_cpdlc_TimeTolerance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t ControlledTime_sequence[] = {
  { &hf_atn_cpdlc_time      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Time },
  { &hf_atn_cpdlc_timeTolerance, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_TimeTolerance },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_ControlledTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_ControlledTime, ControlledTime_sequence);

  return offset;
}



static int
dissect_atn_cpdlc_DepartureMinimumInterval(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 150U, NULL, FALSE);

  return offset;
}


static const per_sequence_t TimeDeparture_sequence[] = {
  { &hf_atn_cpdlc_timeDepartureAllocated, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Time },
  { &hf_atn_cpdlc_timeDepartureControlled, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_ControlledTime },
  { &hf_atn_cpdlc_timeDepartureClearanceExpected, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Time },
  { &hf_atn_cpdlc_departureMinimumInterval, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_DepartureMinimumInterval },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_TimeDeparture(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_TimeDeparture, TimeDeparture_sequence);

  return offset;
}



static int
dissect_atn_cpdlc_RunwayDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 36U, NULL, FALSE);

  return offset;
}


static const value_string atn_cpdlc_RunwayConfiguration_vals[] = {
  {   0, "left" },
  {   1, "right" },
  {   2, "center" },
  {   3, "none" },
  { 0, NULL }
};


static int
dissect_atn_cpdlc_RunwayConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t Runway_sequence[] = {
  { &hf_atn_cpdlc_runway_direction, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_RunwayDirection },
  { &hf_atn_cpdlc_configuration, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_RunwayConfiguration },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_Runway(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_Runway, Runway_sequence);

  return offset;
}



static int
dissect_atn_cpdlc_RevisionNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 16U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_ATISCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,1, 1, FALSE, ia5alpha , 127, NULL);

  return offset;
}


static const per_sequence_t FurtherInstructions_sequence[] = {
  { &hf_atn_cpdlc_code      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Code },
  { &hf_atn_cpdlc_frequencyDeparture, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_UnitNameFrequency },
  { &hf_atn_cpdlc_clearanceExpiryTime, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Time },
  { &hf_atn_cpdlc_airportDeparture, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Airport },
  { &hf_atn_cpdlc_airportDestination, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Airport },
  { &hf_atn_cpdlc_timeDeparture, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_TimeDeparture },
  { &hf_atn_cpdlc_runwayDeparture, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Runway },
  { &hf_atn_cpdlc_revisionNumber, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_RevisionNumber },
  { &hf_atn_cpdlc_aTISCode  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_ATISCode },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_FurtherInstructions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_FurtherInstructions, FurtherInstructions_sequence);

  return offset;
}


static const per_sequence_t DepartureClearance_sequence[] = {
  { &hf_atn_cpdlc_aircraftFlightIdentification, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_AircraftFlightIdentification },
  { &hf_atn_cpdlc_clearanceLimit, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Position },
  { &hf_atn_cpdlc_flightInformation, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_FlightInformation },
  { &hf_atn_cpdlc_furtherInstructions, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_FurtherInstructions },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_DepartureClearance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_DepartureClearance, DepartureClearance_sequence);

  return offset;
}


static const per_sequence_t PositionPosition_sequence_of[1] = {
  { &hf_atn_cpdlc_PositionPosition_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Position },
};

static int
dissect_atn_cpdlc_PositionPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_atn_cpdlc_PositionPosition, PositionPosition_sequence_of,
                                                  2, 2, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_RouteClearanceIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 2U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PositionRouteClearanceIndex_sequence[] = {
  { &hf_atn_cpdlc_position  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Position },
  { &hf_atn_cpdlc_routeClearanceIndex, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_RouteClearanceIndex },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_PositionRouteClearanceIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_PositionRouteClearanceIndex, PositionRouteClearanceIndex_sequence);

  return offset;
}


static const per_sequence_t PositionProcedureName_sequence[] = {
  { &hf_atn_cpdlc_position  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Position },
  { &hf_atn_cpdlc_procedureName, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_ProcedureName },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_PositionProcedureName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_PositionProcedureName, PositionProcedureName_sequence);

  return offset;
}



static int
dissect_atn_cpdlc_LegDistanceEnglish(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 50U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_LegDistanceMetric(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 128U, NULL, FALSE);

  return offset;
}


static const value_string atn_cpdlc_LegDistance_vals[] = {
  {   0, "legDistanceEnglish" },
  {   1, "legDistanceMetric" },
  { 0, NULL }
};

static const per_choice_t LegDistance_choice[] = {
  {   0, &hf_atn_cpdlc_legDistanceEnglish, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_LegDistanceEnglish },
  {   1, &hf_atn_cpdlc_legDistanceMetric, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_LegDistanceMetric },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_LegDistance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_LegDistance, LegDistance_choice,
                                 NULL);

  return offset;
}



static int
dissect_atn_cpdlc_LegTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 10U, NULL, FALSE);

  return offset;
}


static const value_string atn_cpdlc_LegType_vals[] = {
  {   0, "legDistance" },
  {   1, "legTime" },
  { 0, NULL }
};

static const per_choice_t LegType_choice[] = {
  {   0, &hf_atn_cpdlc_legDistance, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_LegDistance },
  {   1, &hf_atn_cpdlc_legTime   , ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_LegTime },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_LegType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_LegType, LegType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t HoldClearance_sequence[] = {
  { &hf_atn_cpdlc_position  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Position },
  { &hf_atn_cpdlc_level     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Level },
  { &hf_atn_cpdlc_degrees   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Degrees },
  { &hf_atn_cpdlc_direction , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Direction },
  { &hf_atn_cpdlc_legType   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_LegType },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_HoldClearance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_HoldClearance, HoldClearance_sequence);

  return offset;
}


static const per_sequence_t DirectionDegrees_sequence[] = {
  { &hf_atn_cpdlc_direction , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Direction },
  { &hf_atn_cpdlc_degrees   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Degrees },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_DirectionDegrees(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_DirectionDegrees, DirectionDegrees_sequence);

  return offset;
}


static const per_sequence_t PositionDegrees_sequence[] = {
  { &hf_atn_cpdlc_position  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Position },
  { &hf_atn_cpdlc_degrees   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Degrees },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_PositionDegrees(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_PositionDegrees, PositionDegrees_sequence);

  return offset;
}


static const per_sequence_t TimeSpeed_sequence[] = {
  { &hf_atn_cpdlc_time      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Time },
  { &hf_atn_cpdlc_speed     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Speed },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_TimeSpeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_TimeSpeed, TimeSpeed_sequence);

  return offset;
}


static const per_sequence_t TimeSpeedSpeed_sequence[] = {
  { &hf_atn_cpdlc_time      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Time },
  { &hf_atn_cpdlc_speedspeed, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_SpeedSpeed },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_TimeSpeedSpeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_TimeSpeedSpeed, TimeSpeedSpeed_sequence);

  return offset;
}


static const per_sequence_t PositionSpeedSpeed_sequence[] = {
  { &hf_atn_cpdlc_position  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Position },
  { &hf_atn_cpdlc_speeds    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_SpeedSpeed },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_PositionSpeedSpeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_PositionSpeedSpeed, PositionSpeedSpeed_sequence);

  return offset;
}


static const per_sequence_t LevelSpeedSpeed_sequence[] = {
  { &hf_atn_cpdlc_level     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Level },
  { &hf_atn_cpdlc_speeds    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_SpeedSpeed },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_LevelSpeedSpeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_LevelSpeedSpeed, LevelSpeedSpeed_sequence);

  return offset;
}


static const per_sequence_t PositionUnitNameFrequency_sequence[] = {
  { &hf_atn_cpdlc_position  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Position },
  { &hf_atn_cpdlc_unitname  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_UnitName },
  { &hf_atn_cpdlc_frequency , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Frequency },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_PositionUnitNameFrequency(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_PositionUnitNameFrequency, PositionUnitNameFrequency_sequence);

  return offset;
}


static const per_sequence_t TimeUnitNameFrequency_sequence[] = {
  { &hf_atn_cpdlc_time      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Time },
  { &hf_atn_cpdlc_unitName  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_UnitName },
  { &hf_atn_cpdlc_frequency , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Frequency },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_TimeUnitNameFrequency(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_TimeUnitNameFrequency, TimeUnitNameFrequency_sequence);

  return offset;
}


static const value_string atn_cpdlc_SpeedType_vals[] = {
  {   0, "noneSpecified" },
  {   1, "indicated" },
  {   2, "true" },
  {   3, "ground" },
  {   4, "mach" },
  {   5, "approach" },
  {   6, "cruise" },
  {   7, "minimum" },
  {   8, "maximum" },
  { 0, NULL }
};


static int
dissect_atn_cpdlc_SpeedType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     9, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SpeedTypeSpeedTypeSpeedType_sequence_of[1] = {
  { &hf_atn_cpdlc_SpeedTypeSpeedTypeSpeedType_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_SpeedType },
};

static int
dissect_atn_cpdlc_SpeedTypeSpeedTypeSpeedType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_atn_cpdlc_SpeedTypeSpeedTypeSpeedType, SpeedTypeSpeedTypeSpeedType_sequence_of,
                                                  3, 3, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_AltimeterEnglish(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            2200U, 3200U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_AltimeterMetric(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            7500U, 12500U, NULL, FALSE);

  return offset;
}


static const value_string atn_cpdlc_Altimeter_vals[] = {
  {   0, "altimeterEnglish" },
  {   1, "altimeterMetric" },
  { 0, NULL }
};

static const per_choice_t Altimeter_choice[] = {
  {   0, &hf_atn_cpdlc_altimeterEnglish, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_AltimeterEnglish },
  {   1, &hf_atn_cpdlc_altimeterMetric, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_AltimeterMetric },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_Altimeter(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_Altimeter, Altimeter_choice,
                                 NULL);

  return offset;
}


static const value_string atn_cpdlc_ErrorInformation_vals[] = {
  {   0, "unrecognizedMsgReferenceNumber" },
  {   1, "logicalAcknowledgmentNotAccepted" },
  {   2, "insufficientResources" },
  {   3, "invalidMessageElementCombination" },
  {   4, "invalidMessageElement" },
  { 0, NULL }
};


static int
dissect_atn_cpdlc_ErrorInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string atn_cpdlc_Facility_vals[] = {
  {   0, "noFacility" },
  {   1, "facilityDesignation" },
  { 0, NULL }
};

static const per_choice_t Facility_choice[] = {
  {   0, &hf_atn_cpdlc_noFacility, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_NULL },
  {   1, &hf_atn_cpdlc_facilityDesignation, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_FacilityDesignation },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_Facility(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_Facility, Facility_choice,
                                 NULL);

  return offset;
}


static const value_string atn_cpdlc_TrafficType_vals[] = {
  {   0, "noneSpecified" },
  {   1, "oppositeDirection" },
  {   2, "sameDirection" },
  {   3, "converging" },
  {   4, "crossing" },
  {   5, "diverging" },
  { 0, NULL }
};


static int
dissect_atn_cpdlc_TrafficType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_atn_cpdlc_FreeText(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,1, 256, FALSE, ia5alpha , 127, NULL);

  return offset;
}



static int
dissect_atn_cpdlc_VerticalRateEnglish(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3000U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_VerticalRateMetric(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1000U, NULL, FALSE);

  return offset;
}


static const value_string atn_cpdlc_VerticalRate_vals[] = {
  {   0, "verticalRateEnglish" },
  {   1, "verticalRateMetric" },
  { 0, NULL }
};

static const per_choice_t VerticalRate_choice[] = {
  {   0, &hf_atn_cpdlc_verticalRateEnglish, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_VerticalRateEnglish },
  {   1, &hf_atn_cpdlc_verticalRateMetric, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_VerticalRateMetric },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_VerticalRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_VerticalRate, VerticalRate_choice,
                                 NULL);

  return offset;
}


static const value_string atn_cpdlc_ToFrom_vals[] = {
  {   0, "to" },
  {   1, "from" },
  { 0, NULL }
};


static int
dissect_atn_cpdlc_ToFrom(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t ToFromPosition_sequence[] = {
  { &hf_atn_cpdlc_toFrom    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_ToFrom },
  { &hf_atn_cpdlc_position  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Position },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_ToFromPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_ToFromPosition, ToFromPosition_sequence);

  return offset;
}


static const per_sequence_t TimeToFromPosition_sequence[] = {
  { &hf_atn_cpdlc_time      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Time },
  { &hf_atn_cpdlc_tofrom    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_ToFrom },
  { &hf_atn_cpdlc_position  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Position },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_TimeToFromPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_TimeToFromPosition, TimeToFromPosition_sequence);

  return offset;
}


static const per_sequence_t FacilityDesignationATISCode_sequence[] = {
  { &hf_atn_cpdlc_facilityDesignation, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_FacilityDesignation },
  { &hf_atn_cpdlc_aTISCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_ATISCode },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_FacilityDesignationATISCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_FacilityDesignationATISCode, FacilityDesignationATISCode_sequence);

  return offset;
}


static const per_sequence_t FacilityDesignationAltimeter_sequence[] = {
  { &hf_atn_cpdlc_facilityDesignation, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_FacilityDesignation },
  { &hf_atn_cpdlc_altimeter , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Altimeter },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_FacilityDesignationAltimeter(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_FacilityDesignationAltimeter, FacilityDesignationAltimeter_sequence);

  return offset;
}



static int
dissect_atn_cpdlc_RVRFeet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 6100U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_RVRMeters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1500U, NULL, FALSE);

  return offset;
}


static const value_string atn_cpdlc_RVR_vals[] = {
  {   0, "rVRFeet" },
  {   1, "rVRMeters" },
  { 0, NULL }
};

static const per_choice_t RVR_choice[] = {
  {   0, &hf_atn_cpdlc_rVRFeet   , ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_RVRFeet },
  {   1, &hf_atn_cpdlc_rVRMeters , ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_RVRMeters },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_RVR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_RVR, RVR_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RunwayRVR_sequence[] = {
  { &hf_atn_cpdlc_runway    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Runway },
  { &hf_atn_cpdlc_rVR       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_RVR },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_RunwayRVR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_RunwayRVR, RunwayRVR_sequence);

  return offset;
}


static const value_string atn_cpdlc_ATCUplinkMsgElementId_vals[] = {
  {   0, "uM0NULL" },
  {   1, "uM1NULL" },
  {   2, "uM2NULL" },
  {   3, "uM3NULL" },
  {   4, "uM4NULL" },
  {   5, "uM5NULL" },
  {   6, "uM6Level" },
  {   7, "uM7Time" },
  {   8, "uM8Position" },
  {   9, "uM9Time" },
  {  10, "uM10Position" },
  {  11, "uM11Time" },
  {  12, "uM12Position" },
  {  13, "uM13TimeLevel" },
  {  14, "uM14PositionLevel" },
  {  15, "uM15TimeLevel" },
  {  16, "uM16PositionLevel" },
  {  17, "uM17TimeLevel" },
  {  18, "uM18PositionLevel" },
  {  19, "uM19Level" },
  {  20, "uM20Level" },
  {  21, "uM21TimeLevel" },
  {  22, "uM22PositionLevel" },
  {  23, "uM23Level" },
  {  24, "uM24TimeLevel" },
  {  25, "uM25PositionLevel" },
  {  26, "uM26LevelTime" },
  {  27, "uM27LevelPosition" },
  {  28, "uM28LevelTime" },
  {  29, "uM29LevelPosition" },
  {  30, "uM30LevelLevel" },
  {  31, "uM31LevelLevel" },
  {  32, "uM32LevelLevel" },
  {  33, "uM33NULL" },
  {  34, "uM34Level" },
  {  35, "uM35Level" },
  {  36, "uM36Level" },
  {  37, "uM37Level" },
  {  38, "uM38Level" },
  {  39, "uM39Level" },
  {  40, "uM40NULL" },
  {  41, "uM41NULL" },
  {  42, "uM42PositionLevel" },
  {  43, "uM43PositionLevel" },
  {  44, "uM44PositionLevel" },
  {  45, "uM45PositionLevel" },
  {  46, "uM46PositionLevel" },
  {  47, "uM47PositionLevel" },
  {  48, "uM48PositionLevel" },
  {  49, "uM49PositionLevel" },
  {  50, "uM50PositionLevelLevel" },
  {  51, "uM51PositionTime" },
  {  52, "uM52PositionTime" },
  {  53, "uM53PositionTime" },
  {  54, "uM54PositionTimeTime" },
  {  55, "uM55PositionSpeed" },
  {  56, "uM56PositionSpeed" },
  {  57, "uM57PositionSpeed" },
  {  58, "uM58PositionTimeLevel" },
  {  59, "uM59PositionTimeLevel" },
  {  60, "uM60PositionTimeLevel" },
  {  61, "uM61PositionLevelSpeed" },
  {  62, "uM62TimePositionLevel" },
  {  63, "uM63TimePositionLevelSpeed" },
  {  64, "uM64DistanceSpecifiedDirection" },
  {  65, "uM65PositionDistanceSpecifiedDirection" },
  {  66, "uM66TimeDistanceSpecifiedDirection" },
  {  67, "uM67NULL" },
  {  68, "uM68Position" },
  {  69, "uM69Time" },
  {  70, "uM70Position" },
  {  71, "uM71Time" },
  {  72, "uM72NULL" },
  {  73, "uM73DepartureClearance" },
  {  74, "uM74Position" },
  {  75, "uM75Position" },
  {  76, "uM76TimePosition" },
  {  77, "uM77PositionPosition" },
  {  78, "uM78LevelPosition" },
  {  79, "uM79PositionRouteClearance" },
  {  80, "uM80RouteClearance" },
  {  81, "uM81ProcedureName" },
  {  82, "uM82DistanceSpecifiedDirection" },
  {  83, "uM83PositionRouteClearance" },
  {  84, "uM84PositionProcedureName" },
  {  85, "uM85RouteClearance" },
  {  86, "uM86PositionRouteClearance" },
  {  87, "uM87Position" },
  {  88, "uM88PositionPosition" },
  {  89, "uM89TimePosition" },
  {  90, "uM90LevelPosition" },
  {  91, "uM91HoldClearance" },
  {  92, "uM92PositionLevel" },
  {  93, "uM93Time" },
  {  94, "uM94DirectionDegrees" },
  {  95, "uM95DirectionDegrees" },
  {  96, "uM96NULL" },
  {  97, "uM97PositionDegrees" },
  {  98, "uM98DirectionDegrees" },
  {  99, "uM99ProcedureName" },
  { 100, "uM100TimeSpeed" },
  { 101, "uM101PositionSpeed" },
  { 102, "uM102LevelSpeed" },
  { 103, "uM103TimeSpeedSpeed" },
  { 104, "uM104PositionSpeedSpeed" },
  { 105, "uM105LevelSpeedSpeed" },
  { 106, "uM106Speed" },
  { 107, "uM107NULL" },
  { 108, "uM108Speed" },
  { 109, "uM109Speed" },
  { 110, "uM110SpeedSpeed" },
  { 111, "uM111Speed" },
  { 112, "uM112Speed" },
  { 113, "uM113Speed" },
  { 114, "uM114Speed" },
  { 115, "uM115Speed" },
  { 116, "uM116NULL" },
  { 117, "uM117UnitNameFrequency" },
  { 118, "uM118PositionUnitNameFrequency" },
  { 119, "uM119TimeUnitNameFrequency" },
  { 120, "uM120UnitNameFrequency" },
  { 121, "uM121PositionUnitNameFrequency" },
  { 122, "uM122TimeUnitNameFrequency" },
  { 123, "uM123Code" },
  { 124, "uM124NULL" },
  { 125, "uM125NULL" },
  { 126, "uM126NULL" },
  { 127, "uM127NULL" },
  { 128, "uM128Level" },
  { 129, "uM129Level" },
  { 130, "uM130Position" },
  { 131, "uM131NULL" },
  { 132, "uM132NULL" },
  { 133, "uM133NULL" },
  { 134, "uM134SpeedTypeSpeedTypeSpeedType" },
  { 135, "uM135NULL" },
  { 136, "uM136NULL" },
  { 137, "uM137NULL" },
  { 138, "uM138NULL" },
  { 139, "uM139NULL" },
  { 140, "uM140NULL" },
  { 141, "uM141NULL" },
  { 142, "uM142NULL" },
  { 143, "uM143NULL" },
  { 144, "uM144NULL" },
  { 145, "uM145NULL" },
  { 146, "uM146NULL" },
  { 147, "uM147NULL" },
  { 148, "uM148Level" },
  { 149, "uM149LevelPosition" },
  { 150, "uM150LevelTime" },
  { 151, "uM151Speed" },
  { 152, "uM152DistanceSpecifiedDirection" },
  { 153, "uM153Altimeter" },
  { 154, "uM154NULL" },
  { 155, "uM155Position" },
  { 156, "uM156NULL" },
  { 157, "uM157Frequency" },
  { 158, "uM158AtisCode" },
  { 159, "uM159ErrorInformation" },
  { 160, "uM160Facility" },
  { 161, "uM161NULL" },
  { 162, "uM162NULL" },
  { 163, "uM163FacilityDesignation" },
  { 164, "uM164NULL" },
  { 165, "uM165NULL" },
  { 166, "uM166TrafficType" },
  { 167, "uM167NULL" },
  { 168, "uM168NULL" },
  { 169, "uM169FreeText" },
  { 170, "uM170FreeText" },
  { 171, "uM171VerticalRate" },
  { 172, "uM172VerticalRate" },
  { 173, "uM173VerticalRate" },
  { 174, "uM174VerticalRate" },
  { 175, "uM175Level" },
  { 176, "uM176NULL" },
  { 177, "uM177NULL" },
  { 178, "uM178NULL" },
  { 179, "uM179NULL" },
  { 180, "uM180LevelLevel" },
  { 181, "uM181ToFromPosition" },
  { 182, "uM182NULL" },
  { 183, "uM183FreeText" },
  { 184, "uM184TimeToFromPosition" },
  { 185, "uM185PositionLevel" },
  { 186, "uM186PositionLevel" },
  { 187, "uM187FreeText" },
  { 188, "uM188PositionSpeed" },
  { 189, "uM189Speed" },
  { 190, "uM190Degrees" },
  { 191, "uM191NULL" },
  { 192, "uM192LevelTime" },
  { 193, "uM193NULL" },
  { 194, "uM194FreeText" },
  { 195, "uM195FreeText" },
  { 196, "uM196FreeText" },
  { 197, "uM197FreeText" },
  { 198, "uM198FreeText" },
  { 199, "uM199FreeText" },
  { 200, "uM200NULL" },
  { 201, "uM201NULL" },
  { 202, "uM202NULL" },
  { 203, "uM203FreeText" },
  { 204, "uM204FreeText" },
  { 205, "uM205FreeText" },
  { 206, "uM206FreeText" },
  { 207, "uM207FreeText" },
  { 208, "uM208FreeText" },
  { 209, "uM209LevelPosition" },
  { 210, "uM210Position" },
  { 211, "uM211NULL" },
  { 212, "uM212FacilityDesignationATISCode" },
  { 213, "uM213FacilityDesignationAltimeter" },
  { 214, "uM214RunwayRVR" },
  { 215, "uM215DirectionDegrees" },
  { 216, "uM216NULL" },
  { 217, "uM217NULL" },
  { 218, "uM218NULL" },
  { 219, "uM219Level" },
  { 220, "uM220Level" },
  { 221, "uM221Degrees" },
  { 222, "uM222NULL" },
  { 223, "uM223NULL" },
  { 224, "uM224NULL" },
  { 225, "uM225NULL" },
  { 226, "uM226Time" },
  { 227, "uM227NULL" },
  { 228, "uM228Position" },
  { 229, "uM229NULL" },
  { 230, "uM230NULL" },
  { 231, "uM231NULL" },
  { 232, "uM232NULL" },
  { 233, "uM233NULL" },
  { 234, "uM234NULL" },
  { 235, "uM235NULL" },
  { 236, "uM236NULL" },
  { 237, "uM237NULL" },
  { 0, NULL }
};

static const per_choice_t ATCUplinkMsgElementId_choice[] = {
  {   0, &hf_atn_cpdlc_uM0NULL   , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {   1, &hf_atn_cpdlc_uM1NULL   , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {   2, &hf_atn_cpdlc_uM2NULL   , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {   3, &hf_atn_cpdlc_uM3NULL   , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {   4, &hf_atn_cpdlc_uM4NULL   , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {   5, &hf_atn_cpdlc_uM5NULL   , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {   6, &hf_atn_cpdlc_uM6Level  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  {   7, &hf_atn_cpdlc_uM7Time   , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Time },
  {   8, &hf_atn_cpdlc_uM8Position, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Position },
  {   9, &hf_atn_cpdlc_uM9Time   , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Time },
  {  10, &hf_atn_cpdlc_uM10Position, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Position },
  {  11, &hf_atn_cpdlc_uM11Time  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Time },
  {  12, &hf_atn_cpdlc_uM12Position, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Position },
  {  13, &hf_atn_cpdlc_uM13TimeLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_TimeLevel },
  {  14, &hf_atn_cpdlc_uM14PositionLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionLevel },
  {  15, &hf_atn_cpdlc_uM15TimeLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_TimeLevel },
  {  16, &hf_atn_cpdlc_uM16PositionLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionLevel },
  {  17, &hf_atn_cpdlc_uM17TimeLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_TimeLevel },
  {  18, &hf_atn_cpdlc_uM18PositionLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionLevel },
  {  19, &hf_atn_cpdlc_uM19Level , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  {  20, &hf_atn_cpdlc_uM20Level , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  {  21, &hf_atn_cpdlc_uM21TimeLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_TimeLevel },
  {  22, &hf_atn_cpdlc_uM22PositionLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionLevel },
  {  23, &hf_atn_cpdlc_uM23Level , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  {  24, &hf_atn_cpdlc_uM24TimeLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_TimeLevel },
  {  25, &hf_atn_cpdlc_uM25PositionLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionLevel },
  {  26, &hf_atn_cpdlc_uM26LevelTime, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_LevelTime },
  {  27, &hf_atn_cpdlc_uM27LevelPosition, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_LevelPosition },
  {  28, &hf_atn_cpdlc_uM28LevelTime, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_LevelTime },
  {  29, &hf_atn_cpdlc_uM29LevelPosition, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_LevelPosition },
  {  30, &hf_atn_cpdlc_uM30LevelLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_LevelLevel },
  {  31, &hf_atn_cpdlc_uM31LevelLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_LevelLevel },
  {  32, &hf_atn_cpdlc_uM32LevelLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_LevelLevel },
  {  33, &hf_atn_cpdlc_uM33NULL  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {  34, &hf_atn_cpdlc_uM34Level , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  {  35, &hf_atn_cpdlc_uM35Level , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  {  36, &hf_atn_cpdlc_uM36Level , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  {  37, &hf_atn_cpdlc_uM37Level , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  {  38, &hf_atn_cpdlc_uM38Level , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  {  39, &hf_atn_cpdlc_uM39Level , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  {  40, &hf_atn_cpdlc_uM40NULL  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {  41, &hf_atn_cpdlc_uM41NULL  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {  42, &hf_atn_cpdlc_uM42PositionLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionLevel },
  {  43, &hf_atn_cpdlc_uM43PositionLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionLevel },
  {  44, &hf_atn_cpdlc_uM44PositionLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionLevel },
  {  45, &hf_atn_cpdlc_uM45PositionLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionLevel },
  {  46, &hf_atn_cpdlc_uM46PositionLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionLevel },
  {  47, &hf_atn_cpdlc_uM47PositionLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionLevel },
  {  48, &hf_atn_cpdlc_uM48PositionLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionLevel },
  {  49, &hf_atn_cpdlc_uM49PositionLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionLevel },
  {  50, &hf_atn_cpdlc_uM50PositionLevelLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionLevelLevel },
  {  51, &hf_atn_cpdlc_uM51PositionTime, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionTime },
  {  52, &hf_atn_cpdlc_uM52PositionTime, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionTime },
  {  53, &hf_atn_cpdlc_uM53PositionTime, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionTime },
  {  54, &hf_atn_cpdlc_uM54PositionTimeTime, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionTimeTime },
  {  55, &hf_atn_cpdlc_uM55PositionSpeed, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionSpeed },
  {  56, &hf_atn_cpdlc_uM56PositionSpeed, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionSpeed },
  {  57, &hf_atn_cpdlc_uM57PositionSpeed, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionSpeed },
  {  58, &hf_atn_cpdlc_uM58PositionTimeLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionTimeLevel },
  {  59, &hf_atn_cpdlc_uM59PositionTimeLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionTimeLevel },
  {  60, &hf_atn_cpdlc_uM60PositionTimeLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionTimeLevel },
  {  61, &hf_atn_cpdlc_uM61PositionLevelSpeed, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionLevelSpeed },
  {  62, &hf_atn_cpdlc_uM62TimePositionLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_TimePositionLevel },
  {  63, &hf_atn_cpdlc_uM63TimePositionLevelSpeed, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_TimePositionLevelSpeed },
  {  64, &hf_atn_cpdlc_uM64DistanceSpecifiedDirection, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_DistanceSpecifiedDirection },
  {  65, &hf_atn_cpdlc_uM65PositionDistanceSpecifiedDirection, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionDistanceSpecifiedDirection },
  {  66, &hf_atn_cpdlc_uM66TimeDistanceSpecifiedDirection, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_TimeDistanceSpecifiedDirection },
  {  67, &hf_atn_cpdlc_uM67NULL  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {  68, &hf_atn_cpdlc_uM68Position, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Position },
  {  69, &hf_atn_cpdlc_uM69Time  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Time },
  {  70, &hf_atn_cpdlc_uM70Position, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Position },
  {  71, &hf_atn_cpdlc_uM71Time  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Time },
  {  72, &hf_atn_cpdlc_uM72NULL  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {  73, &hf_atn_cpdlc_uM73DepartureClearance, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_DepartureClearance },
  {  74, &hf_atn_cpdlc_uM74Position, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Position },
  {  75, &hf_atn_cpdlc_uM75Position, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Position },
  {  76, &hf_atn_cpdlc_uM76TimePosition, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_TimePosition },
  {  77, &hf_atn_cpdlc_uM77PositionPosition, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionPosition },
  {  78, &hf_atn_cpdlc_uM78LevelPosition, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_LevelPosition },
  {  79, &hf_atn_cpdlc_uM79PositionRouteClearance, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionRouteClearanceIndex },
  {  80, &hf_atn_cpdlc_uM80RouteClearance, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_RouteClearanceIndex },
  {  81, &hf_atn_cpdlc_uM81ProcedureName, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_ProcedureName },
  {  82, &hf_atn_cpdlc_uM82DistanceSpecifiedDirection, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_DistanceSpecifiedDirection },
  {  83, &hf_atn_cpdlc_uM83PositionRouteClearance, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionRouteClearanceIndex },
  {  84, &hf_atn_cpdlc_uM84PositionProcedureName, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionProcedureName },
  {  85, &hf_atn_cpdlc_uM85RouteClearance, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_RouteClearanceIndex },
  {  86, &hf_atn_cpdlc_uM86PositionRouteClearance, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionRouteClearanceIndex },
  {  87, &hf_atn_cpdlc_uM87Position, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Position },
  {  88, &hf_atn_cpdlc_uM88PositionPosition, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionPosition },
  {  89, &hf_atn_cpdlc_uM89TimePosition, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_TimePosition },
  {  90, &hf_atn_cpdlc_uM90LevelPosition, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_LevelPosition },
  {  91, &hf_atn_cpdlc_uM91HoldClearance, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_HoldClearance },
  {  92, &hf_atn_cpdlc_uM92PositionLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionLevel },
  {  93, &hf_atn_cpdlc_uM93Time  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Time },
  {  94, &hf_atn_cpdlc_uM94DirectionDegrees, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_DirectionDegrees },
  {  95, &hf_atn_cpdlc_uM95DirectionDegrees, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_DirectionDegrees },
  {  96, &hf_atn_cpdlc_uM96NULL  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {  97, &hf_atn_cpdlc_uM97PositionDegrees, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionDegrees },
  {  98, &hf_atn_cpdlc_uM98DirectionDegrees, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_DirectionDegrees },
  {  99, &hf_atn_cpdlc_uM99ProcedureName, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_ProcedureName },
  { 100, &hf_atn_cpdlc_uM100TimeSpeed, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_TimeSpeed },
  { 101, &hf_atn_cpdlc_uM101PositionSpeed, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionSpeed },
  { 102, &hf_atn_cpdlc_uM102LevelSpeed, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_LevelSpeed },
  { 103, &hf_atn_cpdlc_uM103TimeSpeedSpeed, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_TimeSpeedSpeed },
  { 104, &hf_atn_cpdlc_uM104PositionSpeedSpeed, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionSpeedSpeed },
  { 105, &hf_atn_cpdlc_uM105LevelSpeedSpeed, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_LevelSpeedSpeed },
  { 106, &hf_atn_cpdlc_uM106Speed, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Speed },
  { 107, &hf_atn_cpdlc_uM107NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 108, &hf_atn_cpdlc_uM108Speed, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Speed },
  { 109, &hf_atn_cpdlc_uM109Speed, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Speed },
  { 110, &hf_atn_cpdlc_uM110SpeedSpeed, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_SpeedSpeed },
  { 111, &hf_atn_cpdlc_uM111Speed, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Speed },
  { 112, &hf_atn_cpdlc_uM112Speed, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Speed },
  { 113, &hf_atn_cpdlc_uM113Speed, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Speed },
  { 114, &hf_atn_cpdlc_uM114Speed, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Speed },
  { 115, &hf_atn_cpdlc_uM115Speed, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Speed },
  { 116, &hf_atn_cpdlc_uM116NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 117, &hf_atn_cpdlc_uM117UnitNameFrequency, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_UnitNameFrequency },
  { 118, &hf_atn_cpdlc_uM118PositionUnitNameFrequency, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionUnitNameFrequency },
  { 119, &hf_atn_cpdlc_uM119TimeUnitNameFrequency, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_TimeUnitNameFrequency },
  { 120, &hf_atn_cpdlc_uM120UnitNameFrequency, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_UnitNameFrequency },
  { 121, &hf_atn_cpdlc_uM121PositionUnitNameFrequency, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionUnitNameFrequency },
  { 122, &hf_atn_cpdlc_uM122TimeUnitNameFrequency, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_TimeUnitNameFrequency },
  { 123, &hf_atn_cpdlc_uM123Code , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Code },
  { 124, &hf_atn_cpdlc_uM124NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 125, &hf_atn_cpdlc_uM125NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 126, &hf_atn_cpdlc_uM126NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 127, &hf_atn_cpdlc_uM127NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 128, &hf_atn_cpdlc_uM128Level, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  { 129, &hf_atn_cpdlc_uM129Level, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  { 130, &hf_atn_cpdlc_uM130Position, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Position },
  { 131, &hf_atn_cpdlc_uM131NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 132, &hf_atn_cpdlc_uM132NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 133, &hf_atn_cpdlc_uM133NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 134, &hf_atn_cpdlc_uM134SpeedTypeSpeedTypeSpeedType, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_SpeedTypeSpeedTypeSpeedType },
  { 135, &hf_atn_cpdlc_uM135NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 136, &hf_atn_cpdlc_uM136NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 137, &hf_atn_cpdlc_uM137NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 138, &hf_atn_cpdlc_uM138NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 139, &hf_atn_cpdlc_uM139NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 140, &hf_atn_cpdlc_uM140NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 141, &hf_atn_cpdlc_uM141NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 142, &hf_atn_cpdlc_uM142NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 143, &hf_atn_cpdlc_uM143NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 144, &hf_atn_cpdlc_uM144NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 145, &hf_atn_cpdlc_uM145NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 146, &hf_atn_cpdlc_uM146NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 147, &hf_atn_cpdlc_uM147NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 148, &hf_atn_cpdlc_uM148Level, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  { 149, &hf_atn_cpdlc_uM149LevelPosition, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_LevelPosition },
  { 150, &hf_atn_cpdlc_uM150LevelTime, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_LevelTime },
  { 151, &hf_atn_cpdlc_uM151Speed, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Speed },
  { 152, &hf_atn_cpdlc_uM152DistanceSpecifiedDirection, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_DistanceSpecifiedDirection },
  { 153, &hf_atn_cpdlc_uM153Altimeter, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Altimeter },
  { 154, &hf_atn_cpdlc_uM154NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 155, &hf_atn_cpdlc_uM155Position, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Position },
  { 156, &hf_atn_cpdlc_uM156NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 157, &hf_atn_cpdlc_uM157Frequency, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Frequency },
  { 158, &hf_atn_cpdlc_uM158AtisCode, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_ATISCode },
  { 159, &hf_atn_cpdlc_uM159ErrorInformation, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_ErrorInformation },
  { 160, &hf_atn_cpdlc_uM160Facility, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Facility },
  { 161, &hf_atn_cpdlc_uM161NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 162, &hf_atn_cpdlc_uM162NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 163, &hf_atn_cpdlc_uM163FacilityDesignation, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FacilityDesignation },
  { 164, &hf_atn_cpdlc_uM164NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 165, &hf_atn_cpdlc_uM165NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 166, &hf_atn_cpdlc_uM166TrafficType, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_TrafficType },
  { 167, &hf_atn_cpdlc_uM167NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 168, &hf_atn_cpdlc_uM168NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 169, &hf_atn_cpdlc_uM169FreeText, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FreeText },
  { 170, &hf_atn_cpdlc_uM170FreeText, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FreeText },
  { 171, &hf_atn_cpdlc_uM171VerticalRate, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_VerticalRate },
  { 172, &hf_atn_cpdlc_uM172VerticalRate, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_VerticalRate },
  { 173, &hf_atn_cpdlc_uM173VerticalRate, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_VerticalRate },
  { 174, &hf_atn_cpdlc_uM174VerticalRate, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_VerticalRate },
  { 175, &hf_atn_cpdlc_uM175Level, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  { 176, &hf_atn_cpdlc_uM176NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 177, &hf_atn_cpdlc_uM177NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 178, &hf_atn_cpdlc_uM178NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 179, &hf_atn_cpdlc_uM179NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 180, &hf_atn_cpdlc_uM180LevelLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_LevelLevel },
  { 181, &hf_atn_cpdlc_uM181ToFromPosition, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_ToFromPosition },
  { 182, &hf_atn_cpdlc_uM182NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 183, &hf_atn_cpdlc_uM183FreeText, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FreeText },
  { 184, &hf_atn_cpdlc_uM184TimeToFromPosition, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_TimeToFromPosition },
  { 185, &hf_atn_cpdlc_uM185PositionLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionLevel },
  { 186, &hf_atn_cpdlc_uM186PositionLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionLevel },
  { 187, &hf_atn_cpdlc_uM187FreeText, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FreeText },
  { 188, &hf_atn_cpdlc_uM188PositionSpeed, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionSpeed },
  { 189, &hf_atn_cpdlc_uM189Speed, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Speed },
  { 190, &hf_atn_cpdlc_uM190Degrees, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Degrees },
  { 191, &hf_atn_cpdlc_uM191NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 192, &hf_atn_cpdlc_uM192LevelTime, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_LevelTime },
  { 193, &hf_atn_cpdlc_uM193NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 194, &hf_atn_cpdlc_uM194FreeText, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FreeText },
  { 195, &hf_atn_cpdlc_uM195FreeText, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FreeText },
  { 196, &hf_atn_cpdlc_uM196FreeText, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FreeText },
  { 197, &hf_atn_cpdlc_uM197FreeText, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FreeText },
  { 198, &hf_atn_cpdlc_uM198FreeText, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FreeText },
  { 199, &hf_atn_cpdlc_uM199FreeText, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FreeText },
  { 200, &hf_atn_cpdlc_uM200NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 201, &hf_atn_cpdlc_uM201NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 202, &hf_atn_cpdlc_uM202NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 203, &hf_atn_cpdlc_uM203FreeText, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FreeText },
  { 204, &hf_atn_cpdlc_uM204FreeText, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FreeText },
  { 205, &hf_atn_cpdlc_uM205FreeText, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FreeText },
  { 206, &hf_atn_cpdlc_uM206FreeText, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FreeText },
  { 207, &hf_atn_cpdlc_uM207FreeText, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FreeText },
  { 208, &hf_atn_cpdlc_uM208FreeText, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FreeText },
  { 209, &hf_atn_cpdlc_uM209LevelPosition, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_LevelPosition },
  { 210, &hf_atn_cpdlc_uM210Position, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Position },
  { 211, &hf_atn_cpdlc_uM211NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 212, &hf_atn_cpdlc_uM212FacilityDesignationATISCode, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FacilityDesignationATISCode },
  { 213, &hf_atn_cpdlc_uM213FacilityDesignationAltimeter, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FacilityDesignationAltimeter },
  { 214, &hf_atn_cpdlc_uM214RunwayRVR, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_RunwayRVR },
  { 215, &hf_atn_cpdlc_uM215DirectionDegrees, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_DirectionDegrees },
  { 216, &hf_atn_cpdlc_uM216NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 217, &hf_atn_cpdlc_uM217NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 218, &hf_atn_cpdlc_uM218NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 219, &hf_atn_cpdlc_uM219Level, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  { 220, &hf_atn_cpdlc_uM220Level, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  { 221, &hf_atn_cpdlc_uM221Degrees, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Degrees },
  { 222, &hf_atn_cpdlc_uM222NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 223, &hf_atn_cpdlc_uM223NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 224, &hf_atn_cpdlc_uM224NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 225, &hf_atn_cpdlc_uM225NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 226, &hf_atn_cpdlc_uM226Time , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Time },
  { 227, &hf_atn_cpdlc_uM227NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 228, &hf_atn_cpdlc_uM228Position, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Position },
  { 229, &hf_atn_cpdlc_uM229NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 230, &hf_atn_cpdlc_uM230NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 231, &hf_atn_cpdlc_uM231NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 232, &hf_atn_cpdlc_uM232NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 233, &hf_atn_cpdlc_uM233NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 234, &hf_atn_cpdlc_uM234NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 235, &hf_atn_cpdlc_uM235NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 236, &hf_atn_cpdlc_uM236NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 237, &hf_atn_cpdlc_uM237NULL , ASN1_NOT_EXTENSION_ROOT, dissect_atn_cpdlc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_ATCUplinkMsgElementId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_ATCUplinkMsgElementId, ATCUplinkMsgElementId_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_5_OF_ATCUplinkMsgElementId_sequence_of[1] = {
  { &hf_atn_cpdlc_atcuplinkmessagedata_elementids_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_ATCUplinkMsgElementId },
};

static int
dissect_atn_cpdlc_SEQUENCE_SIZE_1_5_OF_ATCUplinkMsgElementId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_atn_cpdlc_SEQUENCE_SIZE_1_5_OF_ATCUplinkMsgElementId, SEQUENCE_SIZE_1_5_OF_ATCUplinkMsgElementId_sequence_of,
                                                  1, 5, FALSE);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_128_OF_RouteInformation_sequence_of[1] = {
  { &hf_atn_cpdlc_routeInformations_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_RouteInformation },
};

static int
dissect_atn_cpdlc_SEQUENCE_SIZE_1_128_OF_RouteInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_atn_cpdlc_SEQUENCE_SIZE_1_128_OF_RouteInformation, SEQUENCE_SIZE_1_128_OF_RouteInformation_sequence_of,
                                                  1, 128, FALSE);

  return offset;
}


static const value_string atn_cpdlc_ATWDistanceTolerance_vals[] = {
  {   0, "plus" },
  {   1, "minus" },
  { 0, NULL }
};


static int
dissect_atn_cpdlc_ATWDistanceTolerance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t ATWDistance_sequence[] = {
  { &hf_atn_cpdlc_atwDistanceTolerance, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_ATWDistanceTolerance },
  { &hf_atn_cpdlc_distance  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Distance },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_ATWDistance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_ATWDistance, ATWDistance_sequence);

  return offset;
}


static const value_string atn_cpdlc_ATWLevelTolerance_vals[] = {
  {   0, "at" },
  {   1, "atorabove" },
  {   2, "atorbelow" },
  { 0, NULL }
};


static int
dissect_atn_cpdlc_ATWLevelTolerance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t ATWLevel_sequence[] = {
  { &hf_atn_cpdlc_atw       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_ATWLevelTolerance },
  { &hf_atn_cpdlc_level     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Level },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_ATWLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_ATWLevel, ATWLevel_sequence);

  return offset;
}


static const per_sequence_t ATWLevelSequence_sequence_of[1] = {
  { &hf_atn_cpdlc_ATWLevelSequence_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_ATWLevel },
};

static int
dissect_atn_cpdlc_ATWLevelSequence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_atn_cpdlc_ATWLevelSequence, ATWLevelSequence_sequence_of,
                                                  1, 2, FALSE);

  return offset;
}


static const per_sequence_t ATWAlongTrackWaypoint_sequence[] = {
  { &hf_atn_cpdlc_position  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Position },
  { &hf_atn_cpdlc_aTWDistance, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_ATWDistance },
  { &hf_atn_cpdlc_speed     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Speed },
  { &hf_atn_cpdlc_aTWLevels , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_ATWLevelSequence },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_ATWAlongTrackWaypoint(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_ATWAlongTrackWaypoint, ATWAlongTrackWaypoint_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_8_OF_ATWAlongTrackWaypoint_sequence_of[1] = {
  { &hf_atn_cpdlc_aTWAlongTrackWaypoints_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_ATWAlongTrackWaypoint },
};

static int
dissect_atn_cpdlc_SEQUENCE_SIZE_1_8_OF_ATWAlongTrackWaypoint(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_atn_cpdlc_SEQUENCE_SIZE_1_8_OF_ATWAlongTrackWaypoint, SEQUENCE_SIZE_1_8_OF_ATWAlongTrackWaypoint_sequence_of,
                                                  1, 8, FALSE);

  return offset;
}


static const per_sequence_t LatitudeReportingPoints_sequence[] = {
  { &hf_atn_cpdlc_latitudeDirection, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_LatitudeDirection },
  { &hf_atn_cpdlc_latitudeDegrees, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_LatitudeDegrees },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_LatitudeReportingPoints(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_LatitudeReportingPoints, LatitudeReportingPoints_sequence);

  return offset;
}


static const per_sequence_t LongitudeReportingPoints_sequence[] = {
  { &hf_atn_cpdlc_longitudeDirection, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_LongitudeDirection },
  { &hf_atn_cpdlc_longitudeDegrees, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_LongitudeDegrees },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_LongitudeReportingPoints(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_LongitudeReportingPoints, LongitudeReportingPoints_sequence);

  return offset;
}


static const value_string atn_cpdlc_LatLonReportingPoints_vals[] = {
  {   0, "latitudeReportingPoints" },
  {   1, "longitudeReportingPoints" },
  { 0, NULL }
};

static const per_choice_t LatLonReportingPoints_choice[] = {
  {   0, &hf_atn_cpdlc_latitudeReportingPoints, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_LatitudeReportingPoints },
  {   1, &hf_atn_cpdlc_longitudeReportingPoints, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_LongitudeReportingPoints },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_LatLonReportingPoints(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_LatLonReportingPoints, LatLonReportingPoints_choice,
                                 NULL);

  return offset;
}



static int
dissect_atn_cpdlc_DegreeIncrement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 20U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ReportingPoints_sequence[] = {
  { &hf_atn_cpdlc_latLonReportingPoints, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_LatLonReportingPoints },
  { &hf_atn_cpdlc_degreeIncrement, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_DegreeIncrement },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_ReportingPoints(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_ReportingPoints, ReportingPoints_sequence);

  return offset;
}


static const value_string atn_cpdlc_InterceptCourseFromSelection_vals[] = {
  {   0, "publishedIdentifier" },
  {   1, "latitudeLongitude" },
  {   2, "placeBearingPlaceBearing" },
  {   3, "placeBearingDistance" },
  { 0, NULL }
};

static const per_choice_t InterceptCourseFromSelection_choice[] = {
  {   0, &hf_atn_cpdlc_publishedIdentifier, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_PublishedIdentifier },
  {   1, &hf_atn_cpdlc_latitudeLongitude, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_LatitudeLongitude },
  {   2, &hf_atn_cpdlc_placeBearingPlaceBearing, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_PlaceBearingPlaceBearing },
  {   3, &hf_atn_cpdlc_placeBearingDistance, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_PlaceBearingDistance },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_InterceptCourseFromSelection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_InterceptCourseFromSelection, InterceptCourseFromSelection_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t InterceptCourseFrom_sequence[] = {
  { &hf_atn_cpdlc_fromSelection, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_InterceptCourseFromSelection },
  { &hf_atn_cpdlc_degrees   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Degrees },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_InterceptCourseFrom(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_InterceptCourseFrom, InterceptCourseFrom_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_4_OF_InterceptCourseFrom_sequence_of[1] = {
  { &hf_atn_cpdlc_interceptCourseFroms_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_InterceptCourseFrom },
};

static int
dissect_atn_cpdlc_SEQUENCE_SIZE_1_4_OF_InterceptCourseFrom(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_atn_cpdlc_SEQUENCE_SIZE_1_4_OF_InterceptCourseFrom, SEQUENCE_SIZE_1_4_OF_InterceptCourseFrom_sequence_of,
                                                  1, 4, FALSE);

  return offset;
}


static const per_sequence_t Holdatwaypoint_sequence[] = {
  { &hf_atn_cpdlc_position  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Position },
  { &hf_atn_cpdlc_holdatwaypointspeedlow, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Speed },
  { &hf_atn_cpdlc_aTWlevel  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_ATWLevel },
  { &hf_atn_cpdlc_holdatwaypointspeedhigh, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Speed },
  { &hf_atn_cpdlc_direction , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Direction },
  { &hf_atn_cpdlc_degrees   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Degrees },
  { &hf_atn_cpdlc_eFCtime   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Time },
  { &hf_atn_cpdlc_legtype   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_LegType },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_Holdatwaypoint(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_Holdatwaypoint, Holdatwaypoint_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_8_OF_Holdatwaypoint_sequence_of[1] = {
  { &hf_atn_cpdlc_holdAtWaypoints_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Holdatwaypoint },
};

static int
dissect_atn_cpdlc_SEQUENCE_SIZE_1_8_OF_Holdatwaypoint(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_atn_cpdlc_SEQUENCE_SIZE_1_8_OF_Holdatwaypoint, SEQUENCE_SIZE_1_8_OF_Holdatwaypoint_sequence_of,
                                                  1, 8, FALSE);

  return offset;
}


static const per_sequence_t WaypointSpeedLevel_sequence[] = {
  { &hf_atn_cpdlc_position  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Position },
  { &hf_atn_cpdlc_speed     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Speed },
  { &hf_atn_cpdlc_aTWLevels , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_ATWLevelSequence },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_WaypointSpeedLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_WaypointSpeedLevel, WaypointSpeedLevel_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_32_OF_WaypointSpeedLevel_sequence_of[1] = {
  { &hf_atn_cpdlc_waypointSpeedLevels_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_WaypointSpeedLevel },
};

static int
dissect_atn_cpdlc_SEQUENCE_SIZE_1_32_OF_WaypointSpeedLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_atn_cpdlc_SEQUENCE_SIZE_1_32_OF_WaypointSpeedLevel, SEQUENCE_SIZE_1_32_OF_WaypointSpeedLevel_sequence_of,
                                                  1, 32, FALSE);

  return offset;
}


static const per_sequence_t RTATime_sequence[] = {
  { &hf_atn_cpdlc_time      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Time },
  { &hf_atn_cpdlc_timeTolerance, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_TimeTolerance },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_RTATime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_RTATime, RTATime_sequence);

  return offset;
}



static int
dissect_atn_cpdlc_RTATolerance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 150U, NULL, FALSE);

  return offset;
}


static const per_sequence_t RTARequiredTimeArrival_sequence[] = {
  { &hf_atn_cpdlc_position  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Position },
  { &hf_atn_cpdlc_rTATime   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_RTATime },
  { &hf_atn_cpdlc_rTATolerance, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_RTATolerance },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_RTARequiredTimeArrival(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_RTARequiredTimeArrival, RTARequiredTimeArrival_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_32_OF_RTARequiredTimeArrival_sequence_of[1] = {
  { &hf_atn_cpdlc_rTARequiredTimeArrivals_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_RTARequiredTimeArrival },
};

static int
dissect_atn_cpdlc_SEQUENCE_SIZE_1_32_OF_RTARequiredTimeArrival(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_atn_cpdlc_SEQUENCE_SIZE_1_32_OF_RTARequiredTimeArrival, SEQUENCE_SIZE_1_32_OF_RTARequiredTimeArrival_sequence_of,
                                                  1, 32, FALSE);

  return offset;
}


static const per_sequence_t RouteInformationAdditional_sequence[] = {
  { &hf_atn_cpdlc_aTWAlongTrackWaypoints, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_SEQUENCE_SIZE_1_8_OF_ATWAlongTrackWaypoint },
  { &hf_atn_cpdlc_reportingpoints, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_ReportingPoints },
  { &hf_atn_cpdlc_interceptCourseFroms, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_SEQUENCE_SIZE_1_4_OF_InterceptCourseFrom },
  { &hf_atn_cpdlc_holdAtWaypoints, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_SEQUENCE_SIZE_1_8_OF_Holdatwaypoint },
  { &hf_atn_cpdlc_waypointSpeedLevels, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_SEQUENCE_SIZE_1_32_OF_WaypointSpeedLevel },
  { &hf_atn_cpdlc_rTARequiredTimeArrivals, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_SEQUENCE_SIZE_1_32_OF_RTARequiredTimeArrival },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_RouteInformationAdditional(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_RouteInformationAdditional, RouteInformationAdditional_sequence);

  return offset;
}


static const per_sequence_t RouteClearance_sequence[] = {
  { &hf_atn_cpdlc_airportDeparture, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Airport },
  { &hf_atn_cpdlc_airportDestination, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Airport },
  { &hf_atn_cpdlc_runwayDeparture, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Runway },
  { &hf_atn_cpdlc_procedureDeparture, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_ProcedureName },
  { &hf_atn_cpdlc_runwayArrival, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Runway },
  { &hf_atn_cpdlc_procedureApproach, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_ProcedureName },
  { &hf_atn_cpdlc_procedureArrival, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_ProcedureName },
  { &hf_atn_cpdlc_routeInformations, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_SEQUENCE_SIZE_1_128_OF_RouteInformation },
  { &hf_atn_cpdlc_routeInformationAdditional, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_RouteInformationAdditional },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_RouteClearance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_RouteClearance, RouteClearance_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_2_OF_RouteClearance_sequence_of[1] = {
  { &hf_atn_cpdlc_routeClearanceData_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_RouteClearance },
};

static int
dissect_atn_cpdlc_SEQUENCE_SIZE_1_2_OF_RouteClearance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_atn_cpdlc_SEQUENCE_SIZE_1_2_OF_RouteClearance, SEQUENCE_SIZE_1_2_OF_RouteClearance_sequence_of,
                                                  1, 2, FALSE);

  return offset;
}


static const per_sequence_t T_atcuplinkmessagedata_constraineddata_sequence[] = {
  { &hf_atn_cpdlc_routeClearanceData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_cpdlc_SEQUENCE_SIZE_1_2_OF_RouteClearance },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_T_atcuplinkmessagedata_constraineddata(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_T_atcuplinkmessagedata_constraineddata, T_atcuplinkmessagedata_constraineddata_sequence);

  return offset;
}


static const per_sequence_t ATCUplinkMessageData_sequence[] = {
  { &hf_atn_cpdlc_atcuplinkmessagedata_elementids, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_SEQUENCE_SIZE_1_5_OF_ATCUplinkMsgElementId },
  { &hf_atn_cpdlc_atcuplinkmessagedata_constraineddata, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_T_atcuplinkmessagedata_constraineddata },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_ATCUplinkMessageData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_ATCUplinkMessageData, ATCUplinkMessageData_sequence);

  return offset;
}


static const per_sequence_t ATCUplinkMessage_sequence[] = {
  { &hf_atn_cpdlc_header    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_ATCMessageHeader },
  { &hf_atn_cpdlc_atcuplinkmessage_messagedata, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_ATCUplinkMessageData },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_ATCUplinkMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_ATCUplinkMessage, ATCUplinkMessage_sequence);

  return offset;
}


static const value_string atn_cpdlc_UplinkMessage_vals[] = {
  {   0, "noMessage" },
  {   1, "aTCUplinkMessage" },
  { 0, NULL }
};

static const per_choice_t UplinkMessage_choice[] = {
  {   0, &hf_atn_cpdlc_noMessage , ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_NULL },
  {   1, &hf_atn_cpdlc_aTCUplinkMessage, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_ATCUplinkMessage },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_UplinkMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_UplinkMessage, UplinkMessage_choice,
                                 NULL);

  return offset;
}



static int
dissect_atn_cpdlc_AircraftAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     24, 24, FALSE, NULL, NULL);

  return offset;
}


static const per_sequence_t ForwardHeader_sequence[] = {
  { &hf_atn_cpdlc_dateTime  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_DateTimeGroup },
  { &hf_atn_cpdlc_aircraftID, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_AircraftFlightIdentification },
  { &hf_atn_cpdlc_aircraftAddress, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_AircraftAddress },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_ForwardHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_ForwardHeader, ForwardHeader_sequence);

  return offset;
}



static int
dissect_atn_cpdlc_BIT_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     NO_BOUND, NO_BOUND, FALSE, NULL, NULL);

  return offset;
}


static const value_string atn_cpdlc_ForwardMessage_vals[] = {
  {   0, "upElementIDs" },
  {   1, "downElementIDs" },
  { 0, NULL }
};

static const per_choice_t ForwardMessage_choice[] = {
  {   0, &hf_atn_cpdlc_upElementIDs, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_BIT_STRING },
  {   1, &hf_atn_cpdlc_downElementIDs, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_BIT_STRING },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_ForwardMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_ForwardMessage, ForwardMessage_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ATCForwardMessage_sequence[] = {
  { &hf_atn_cpdlc_forwardHeader, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_ForwardHeader },
  { &hf_atn_cpdlc_forwardMessage, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_ForwardMessage },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_ATCForwardMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_ATCForwardMessage, ATCForwardMessage_sequence);

  return offset;
}


static const value_string atn_cpdlc_ATCForwardResponse_vals[] = {
  {   0, "success" },
  {   1, "service-not-supported" },
  {   2, "version-not-equal" },
  { 0, NULL }
};


static int
dissect_atn_cpdlc_ATCForwardResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string atn_cpdlc_GroundPDUs_vals[] = {
  {   0, "abortUser" },
  {   1, "abortProvider" },
  {   2, "startup" },
  {   3, "send" },
  {   4, "forward" },
  {   5, "forwardresponse" },
  { 0, NULL }
};

static const per_choice_t GroundPDUs_choice[] = {
  {   0, &hf_atn_cpdlc_abortUser , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_CPDLCUserAbortReason },
  {   1, &hf_atn_cpdlc_abortProvider, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_CPDLCProviderAbortReason },
  {   2, &hf_atn_cpdlc_startup   , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_UplinkMessage },
  {   3, &hf_atn_cpdlc_groundpdus_send, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_ATCUplinkMessage },
  {   4, &hf_atn_cpdlc_forward   , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_ATCForwardMessage },
  {   5, &hf_atn_cpdlc_forwardresponse, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_ATCForwardResponse },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_GroundPDUs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_GroundPDUs, GroundPDUs_choice,
                                 NULL);

  return offset;
}


static const value_string atn_cpdlc_Mode_vals[] = {
  {   0, "cpdlc" },
  {   1, "dsc" },
  { 0, NULL }
};


static int
dissect_atn_cpdlc_Mode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string atn_cpdlc_ClearanceType_vals[] = {
  {   0, "noneSpecified" },
  {   1, "approach" },
  {   2, "departure" },
  {   3, "further" },
  {   4, "start-up" },
  {   5, "pushback" },
  {   6, "taxi" },
  {   7, "take-off" },
  {   8, "landing" },
  {   9, "oceanic" },
  {  10, "en-route" },
  {  11, "downstream" },
  { 0, NULL }
};


static int
dissect_atn_cpdlc_ClearanceType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     12, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_atn_cpdlc_RemainingFuel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_atn_cpdlc_Time(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_atn_cpdlc_Temperature(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -100, 100U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_WindDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 360U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_WindSpeedEnglish(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cpdlc_WindSpeedMetric(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 511U, NULL, FALSE);

  return offset;
}


static const value_string atn_cpdlc_WindSpeed_vals[] = {
  {   0, "windSpeedEnglish" },
  {   1, "windSpeedMetric" },
  { 0, NULL }
};

static const per_choice_t WindSpeed_choice[] = {
  {   0, &hf_atn_cpdlc_windSpeedEnglish, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_WindSpeedEnglish },
  {   1, &hf_atn_cpdlc_windSpeedMetric, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_WindSpeedMetric },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_WindSpeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_WindSpeed, WindSpeed_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Winds_sequence[] = {
  { &hf_atn_cpdlc_winds_direction, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_WindDirection },
  { &hf_atn_cpdlc_winds_speed, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_WindSpeed },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_Winds(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_Winds, Winds_sequence);

  return offset;
}


static const value_string atn_cpdlc_Turbulence_vals[] = {
  {   0, "light" },
  {   1, "moderate" },
  {   2, "severe" },
  { 0, NULL }
};


static int
dissect_atn_cpdlc_Turbulence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string atn_cpdlc_Icing_vals[] = {
  {   0, "reserved" },
  {   1, "light" },
  {   2, "moderate" },
  {   3, "severe" },
  { 0, NULL }
};


static int
dissect_atn_cpdlc_Icing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string atn_cpdlc_VerticalDirection_vals[] = {
  {   0, "up" },
  {   1, "down" },
  { 0, NULL }
};


static int
dissect_atn_cpdlc_VerticalDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t VerticalChange_sequence[] = {
  { &hf_atn_cpdlc_vertical_direction, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_VerticalDirection },
  { &hf_atn_cpdlc_rate      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_VerticalRate },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_VerticalChange(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_VerticalChange, VerticalChange_sequence);

  return offset;
}



static int
dissect_atn_cpdlc_Humidity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PositionReport_sequence[] = {
  { &hf_atn_cpdlc_positioncurrent, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Position },
  { &hf_atn_cpdlc_timeatpositioncurrent, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Time },
  { &hf_atn_cpdlc_level     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Level },
  { &hf_atn_cpdlc_fixnext   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Position },
  { &hf_atn_cpdlc_timeetaatfixnext, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Time },
  { &hf_atn_cpdlc_fixnextplusone, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Position },
  { &hf_atn_cpdlc_timeetaatdestination, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Time },
  { &hf_atn_cpdlc_remainingFuel, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_RemainingFuel },
  { &hf_atn_cpdlc_temperature, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Temperature },
  { &hf_atn_cpdlc_winds     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Winds },
  { &hf_atn_cpdlc_turbulence, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Turbulence },
  { &hf_atn_cpdlc_icing     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Icing },
  { &hf_atn_cpdlc_speed     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Speed },
  { &hf_atn_cpdlc_speedground, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_SpeedGround },
  { &hf_atn_cpdlc_verticalChange, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_VerticalChange },
  { &hf_atn_cpdlc_trackAngle, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Degrees },
  { &hf_atn_cpdlc_heading   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Degrees },
  { &hf_atn_cpdlc_distance  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Distance },
  { &hf_atn_cpdlc_humidity  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Humidity },
  { &hf_atn_cpdlc_reportedWaypointPosition, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Position },
  { &hf_atn_cpdlc_reportedWaypointTime, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Time },
  { &hf_atn_cpdlc_reportedWaypointLevel, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Level },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_PositionReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_PositionReport, PositionReport_sequence);

  return offset;
}



static int
dissect_atn_cpdlc_PersonsOnBoard(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1024U, NULL, FALSE);

  return offset;
}


static const per_sequence_t RemainingFuelPersonsOnBoard_sequence[] = {
  { &hf_atn_cpdlc_remainingFuel, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_RemainingFuel },
  { &hf_atn_cpdlc_personsOnBoard, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_PersonsOnBoard },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_RemainingFuelPersonsOnBoard(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_RemainingFuelPersonsOnBoard, RemainingFuelPersonsOnBoard_sequence);

  return offset;
}



static int
dissect_atn_cpdlc_VersionNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}


static const per_sequence_t TimeDistanceToFromPosition_sequence[] = {
  { &hf_atn_cpdlc_time      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Time },
  { &hf_atn_cpdlc_distance  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Distance },
  { &hf_atn_cpdlc_tofrom    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_ToFrom },
  { &hf_atn_cpdlc_position  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Position },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_TimeDistanceToFromPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_TimeDistanceToFromPosition, TimeDistanceToFromPosition_sequence);

  return offset;
}


static const per_sequence_t SpeedTime_sequence[] = {
  { &hf_atn_cpdlc_speed     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Speed },
  { &hf_atn_cpdlc_time      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Time },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_SpeedTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_SpeedTime, SpeedTime_sequence);

  return offset;
}


static const per_sequence_t DistanceSpecifiedDirectionTime_sequence[] = {
  { &hf_atn_cpdlc_distanceSpecifiedDirection, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_DistanceSpecifiedDirection },
  { &hf_atn_cpdlc_time      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Time },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_DistanceSpecifiedDirectionTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_DistanceSpecifiedDirectionTime, DistanceSpecifiedDirectionTime_sequence);

  return offset;
}


static const per_sequence_t SpeedTypeSpeedTypeSpeedTypeSpeed_sequence[] = {
  { &hf_atn_cpdlc_speedTypes, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_SpeedTypeSpeedTypeSpeedType },
  { &hf_atn_cpdlc_speed     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_Speed },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_SpeedTypeSpeedTypeSpeedTypeSpeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_SpeedTypeSpeedTypeSpeedTypeSpeed, SpeedTypeSpeedTypeSpeedTypeSpeed_sequence);

  return offset;
}


static const value_string atn_cpdlc_ATCDownlinkMsgElementId_vals[] = {
  {   0, "dM0NULL" },
  {   1, "dM1NULL" },
  {   2, "dM2NULL" },
  {   3, "dM3NULL" },
  {   4, "dM4NULL" },
  {   5, "dM5NULL" },
  {   6, "dM6Level" },
  {   7, "dM7LevelLevel" },
  {   8, "dM8Level" },
  {   9, "dM9Level" },
  {  10, "dM10Level" },
  {  11, "dM11PositionLevel" },
  {  12, "dM12PositionLevel" },
  {  13, "dM13TimeLevel" },
  {  14, "dM14TimeLevel" },
  {  15, "dM15DistanceSpecifiedDirection" },
  {  16, "dM16PositionDistanceSpecifiedDirection" },
  {  17, "dM17TimeDistanceSpecifiedDirection" },
  {  18, "dM18Speed" },
  {  19, "dM19SpeedSpeed" },
  {  20, "dM20NULL" },
  {  21, "dM21Frequency" },
  {  22, "dM22Position" },
  {  23, "dM23ProcedureName" },
  {  24, "dM24RouteClearance" },
  {  25, "dM25ClearanceType" },
  {  26, "dM26PositionRouteClearance" },
  {  27, "dM27DistanceSpecifiedDirection" },
  {  28, "dM28Level" },
  {  29, "dM29Level" },
  {  30, "dM30Level" },
  {  31, "dM31Position" },
  {  32, "dM32Level" },
  {  33, "dM33Position" },
  {  34, "dM34Speed" },
  {  35, "dM35Degrees" },
  {  36, "dM36Degrees" },
  {  37, "dM37Level" },
  {  38, "dM38Level" },
  {  39, "dM39Speed" },
  {  40, "dM40RouteClearance" },
  {  41, "dM41NULL" },
  {  42, "dM42Position" },
  {  43, "dM43Time" },
  {  44, "dM44Position" },
  {  45, "dM45Position" },
  {  46, "dM46Time" },
  {  47, "dM47Code" },
  {  48, "dM48PositionReport" },
  {  49, "dM49Speed" },
  {  50, "dM50SpeedSpeed" },
  {  51, "dM51NULL" },
  {  52, "dM52NULL" },
  {  53, "dM53NULL" },
  {  54, "dM54Level" },
  {  55, "dM55NULL" },
  {  56, "dM56NULL" },
  {  57, "dM57RemainingFuelPersonsOnBoard" },
  {  58, "dM58NULL" },
  {  59, "dM59PositionRouteClearance" },
  {  60, "dM60DistanceSpecifiedDirection" },
  {  61, "dM61Level" },
  {  62, "dM62ErrorInformation" },
  {  63, "dM63NULL" },
  {  64, "dM64FacilityDesignation" },
  {  65, "dM65NULL" },
  {  66, "dM66NULL" },
  {  67, "dM67FreeText" },
  {  68, "dM68FreeText" },
  {  69, "dM69NULL" },
  {  70, "dM70Degrees" },
  {  71, "dM71Degrees" },
  {  72, "dM72Level" },
  {  73, "dM73Versionnumber" },
  {  74, "dM74NULL" },
  {  75, "dM75NULL" },
  {  76, "dM76LevelLevel" },
  {  77, "dM77LevelLevel" },
  {  78, "dM78TimeDistanceToFromPosition" },
  {  79, "dM79AtisCode" },
  {  80, "dM80DistanceSpecifiedDirection" },
  {  81, "dM81LevelTime" },
  {  82, "dM82Level" },
  {  83, "dM83SpeedTime" },
  {  84, "dM84Speed" },
  {  85, "dM85DistanceSpecifiedDirectionTime" },
  {  86, "dM86DistanceSpecifiedDirection" },
  {  87, "dM87Level" },
  {  88, "dM88Level" },
  {  89, "dM89UnitnameFrequency" },
  {  90, "dM90FreeText" },
  {  91, "dM91FreeText" },
  {  92, "dM92FreeText" },
  {  93, "dM93FreeText" },
  {  94, "dM94FreeText" },
  {  95, "dM95FreeText" },
  {  96, "dM96FreeText" },
  {  97, "dM97FreeText" },
  {  98, "dM98FreeText" },
  {  99, "dM99NULL" },
  { 100, "dM100NULL" },
  { 101, "dM101NULL" },
  { 102, "dM102NULL" },
  { 103, "dM103NULL" },
  { 104, "dM104PositionTime" },
  { 105, "dM105Airport" },
  { 106, "dM106Level" },
  { 107, "dM107NULL" },
  { 108, "dM108NULL" },
  { 109, "dM109Time" },
  { 110, "dM110Position" },
  { 111, "dM111TimePosition" },
  { 112, "dM112NULL" },
  { 113, "dM113SpeedTypeSpeedTypeSpeedTypeSpeed" },
  { 0, NULL }
};

static const per_choice_t ATCDownlinkMsgElementId_choice[] = {
  {   0, &hf_atn_cpdlc_dM0NULL   , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {   1, &hf_atn_cpdlc_dM1NULL   , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {   2, &hf_atn_cpdlc_dM2NULL   , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {   3, &hf_atn_cpdlc_dM3NULL   , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {   4, &hf_atn_cpdlc_dM4NULL   , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {   5, &hf_atn_cpdlc_dM5NULL   , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {   6, &hf_atn_cpdlc_dM6Level  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  {   7, &hf_atn_cpdlc_dM7LevelLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_LevelLevel },
  {   8, &hf_atn_cpdlc_dM8Level  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  {   9, &hf_atn_cpdlc_dM9Level  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  {  10, &hf_atn_cpdlc_dM10Level , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  {  11, &hf_atn_cpdlc_dM11PositionLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionLevel },
  {  12, &hf_atn_cpdlc_dM12PositionLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionLevel },
  {  13, &hf_atn_cpdlc_dM13TimeLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_TimeLevel },
  {  14, &hf_atn_cpdlc_dM14TimeLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_TimeLevel },
  {  15, &hf_atn_cpdlc_dM15DistanceSpecifiedDirection, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_DistanceSpecifiedDirection },
  {  16, &hf_atn_cpdlc_dM16PositionDistanceSpecifiedDirection, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionDistanceSpecifiedDirection },
  {  17, &hf_atn_cpdlc_dM17TimeDistanceSpecifiedDirection, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_TimeDistanceSpecifiedDirection },
  {  18, &hf_atn_cpdlc_dM18Speed , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Speed },
  {  19, &hf_atn_cpdlc_dM19SpeedSpeed, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_SpeedSpeed },
  {  20, &hf_atn_cpdlc_dM20NULL  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {  21, &hf_atn_cpdlc_dM21Frequency, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Frequency },
  {  22, &hf_atn_cpdlc_dM22Position, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Position },
  {  23, &hf_atn_cpdlc_dM23ProcedureName, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_ProcedureName },
  {  24, &hf_atn_cpdlc_dM24RouteClearance, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_RouteClearanceIndex },
  {  25, &hf_atn_cpdlc_dM25ClearanceType, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_ClearanceType },
  {  26, &hf_atn_cpdlc_dM26PositionRouteClearance, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionRouteClearanceIndex },
  {  27, &hf_atn_cpdlc_dM27DistanceSpecifiedDirection, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_DistanceSpecifiedDirection },
  {  28, &hf_atn_cpdlc_dM28Level , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  {  29, &hf_atn_cpdlc_dM29Level , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  {  30, &hf_atn_cpdlc_dM30Level , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  {  31, &hf_atn_cpdlc_dM31Position, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Position },
  {  32, &hf_atn_cpdlc_dM32Level , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  {  33, &hf_atn_cpdlc_dM33Position, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Position },
  {  34, &hf_atn_cpdlc_dM34Speed , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Speed },
  {  35, &hf_atn_cpdlc_dM35Degrees, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Degrees },
  {  36, &hf_atn_cpdlc_dM36Degrees, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Degrees },
  {  37, &hf_atn_cpdlc_dM37Level , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  {  38, &hf_atn_cpdlc_dM38Level , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  {  39, &hf_atn_cpdlc_dM39Speed , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Speed },
  {  40, &hf_atn_cpdlc_dM40RouteClearance, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_RouteClearanceIndex },
  {  41, &hf_atn_cpdlc_dM41NULL  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {  42, &hf_atn_cpdlc_dM42Position, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Position },
  {  43, &hf_atn_cpdlc_dM43Time  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Time },
  {  44, &hf_atn_cpdlc_dM44Position, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Position },
  {  45, &hf_atn_cpdlc_dM45Position, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Position },
  {  46, &hf_atn_cpdlc_dM46Time  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Time },
  {  47, &hf_atn_cpdlc_dM47Code  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Code },
  {  48, &hf_atn_cpdlc_dM48PositionReport, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionReport },
  {  49, &hf_atn_cpdlc_dM49Speed , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Speed },
  {  50, &hf_atn_cpdlc_dM50SpeedSpeed, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_SpeedSpeed },
  {  51, &hf_atn_cpdlc_dM51NULL  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {  52, &hf_atn_cpdlc_dM52NULL  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {  53, &hf_atn_cpdlc_dM53NULL  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {  54, &hf_atn_cpdlc_dM54Level , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  {  55, &hf_atn_cpdlc_dM55NULL  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {  56, &hf_atn_cpdlc_dM56NULL  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {  57, &hf_atn_cpdlc_dM57RemainingFuelPersonsOnBoard, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_RemainingFuelPersonsOnBoard },
  {  58, &hf_atn_cpdlc_dM58NULL  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {  59, &hf_atn_cpdlc_dM59PositionRouteClearance, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionRouteClearanceIndex },
  {  60, &hf_atn_cpdlc_dM60DistanceSpecifiedDirection, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_DistanceSpecifiedDirection },
  {  61, &hf_atn_cpdlc_dM61Level , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  {  62, &hf_atn_cpdlc_dM62ErrorInformation, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_ErrorInformation },
  {  63, &hf_atn_cpdlc_dM63NULL  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {  64, &hf_atn_cpdlc_dM64FacilityDesignation, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FacilityDesignation },
  {  65, &hf_atn_cpdlc_dM65NULL  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {  66, &hf_atn_cpdlc_dM66NULL  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {  67, &hf_atn_cpdlc_dM67FreeText, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FreeText },
  {  68, &hf_atn_cpdlc_dM68FreeText, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FreeText },
  {  69, &hf_atn_cpdlc_dM69NULL  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {  70, &hf_atn_cpdlc_dM70Degrees, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Degrees },
  {  71, &hf_atn_cpdlc_dM71Degrees, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Degrees },
  {  72, &hf_atn_cpdlc_dM72Level , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  {  73, &hf_atn_cpdlc_dM73Versionnumber, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_VersionNumber },
  {  74, &hf_atn_cpdlc_dM74NULL  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {  75, &hf_atn_cpdlc_dM75NULL  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  {  76, &hf_atn_cpdlc_dM76LevelLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_LevelLevel },
  {  77, &hf_atn_cpdlc_dM77LevelLevel, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_LevelLevel },
  {  78, &hf_atn_cpdlc_dM78TimeDistanceToFromPosition, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_TimeDistanceToFromPosition },
  {  79, &hf_atn_cpdlc_dM79AtisCode, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_ATISCode },
  {  80, &hf_atn_cpdlc_dM80DistanceSpecifiedDirection, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_DistanceSpecifiedDirection },
  {  81, &hf_atn_cpdlc_dM81LevelTime, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_LevelTime },
  {  82, &hf_atn_cpdlc_dM82Level , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  {  83, &hf_atn_cpdlc_dM83SpeedTime, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_SpeedTime },
  {  84, &hf_atn_cpdlc_dM84Speed , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Speed },
  {  85, &hf_atn_cpdlc_dM85DistanceSpecifiedDirectionTime, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_DistanceSpecifiedDirectionTime },
  {  86, &hf_atn_cpdlc_dM86DistanceSpecifiedDirection, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_DistanceSpecifiedDirection },
  {  87, &hf_atn_cpdlc_dM87Level , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  {  88, &hf_atn_cpdlc_dM88Level , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  {  89, &hf_atn_cpdlc_dM89UnitnameFrequency, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_UnitNameFrequency },
  {  90, &hf_atn_cpdlc_dM90FreeText, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FreeText },
  {  91, &hf_atn_cpdlc_dM91FreeText, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FreeText },
  {  92, &hf_atn_cpdlc_dM92FreeText, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FreeText },
  {  93, &hf_atn_cpdlc_dM93FreeText, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FreeText },
  {  94, &hf_atn_cpdlc_dM94FreeText, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FreeText },
  {  95, &hf_atn_cpdlc_dM95FreeText, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FreeText },
  {  96, &hf_atn_cpdlc_dM96FreeText, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FreeText },
  {  97, &hf_atn_cpdlc_dM97FreeText, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FreeText },
  {  98, &hf_atn_cpdlc_dM98FreeText, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_FreeText },
  {  99, &hf_atn_cpdlc_dM99NULL  , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 100, &hf_atn_cpdlc_dM100NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 101, &hf_atn_cpdlc_dM101NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 102, &hf_atn_cpdlc_dM102NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 103, &hf_atn_cpdlc_dM103NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 104, &hf_atn_cpdlc_dM104PositionTime, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PositionTime },
  { 105, &hf_atn_cpdlc_dM105Airport, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Airport },
  { 106, &hf_atn_cpdlc_dM106Level, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Level },
  { 107, &hf_atn_cpdlc_dM107NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 108, &hf_atn_cpdlc_dM108NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 109, &hf_atn_cpdlc_dM109Time , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Time },
  { 110, &hf_atn_cpdlc_dM110Position, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_Position },
  { 111, &hf_atn_cpdlc_dM111TimePosition, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_TimePosition },
  { 112, &hf_atn_cpdlc_dM112NULL , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_NULL },
  { 113, &hf_atn_cpdlc_dM113SpeedTypeSpeedTypeSpeedTypeSpeed, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_SpeedTypeSpeedTypeSpeedTypeSpeed },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_ATCDownlinkMsgElementId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_ATCDownlinkMsgElementId, ATCDownlinkMsgElementId_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_5_OF_ATCDownlinkMsgElementId_sequence_of[1] = {
  { &hf_atn_cpdlc_atcdownlinkmessagedata_elementids_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_ATCDownlinkMsgElementId },
};

static int
dissect_atn_cpdlc_SEQUENCE_SIZE_1_5_OF_ATCDownlinkMsgElementId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_atn_cpdlc_SEQUENCE_SIZE_1_5_OF_ATCDownlinkMsgElementId, SEQUENCE_SIZE_1_5_OF_ATCDownlinkMsgElementId_sequence_of,
                                                  1, 5, FALSE);

  return offset;
}


static const per_sequence_t T_atcdownlinkmessagedata_constraineddata_sequence[] = {
  { &hf_atn_cpdlc_routeClearanceData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_cpdlc_SEQUENCE_SIZE_1_2_OF_RouteClearance },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_T_atcdownlinkmessagedata_constraineddata(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_T_atcdownlinkmessagedata_constraineddata, T_atcdownlinkmessagedata_constraineddata_sequence);

  return offset;
}


static const per_sequence_t ATCDownlinkMessageData_sequence[] = {
  { &hf_atn_cpdlc_atcdownlinkmessagedata_elementids, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_SEQUENCE_SIZE_1_5_OF_ATCDownlinkMsgElementId },
  { &hf_atn_cpdlc_atcdownlinkmessagedata_constraineddata, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_T_atcdownlinkmessagedata_constraineddata },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_ATCDownlinkMessageData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_ATCDownlinkMessageData, ATCDownlinkMessageData_sequence);

  return offset;
}


static const per_sequence_t ATCDownlinkMessage_sequence[] = {
  { &hf_atn_cpdlc_header    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_ATCMessageHeader },
  { &hf_atn_cpdlc_atcdownlinkmessage_messagedata, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_ATCDownlinkMessageData },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_ATCDownlinkMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_ATCDownlinkMessage, ATCDownlinkMessage_sequence);

  return offset;
}


static const value_string atn_cpdlc_DownlinkMessage_vals[] = {
  {   0, "noMessage" },
  {   1, "aTCDownlinkMessage" },
  { 0, NULL }
};

static const per_choice_t DownlinkMessage_choice[] = {
  {   0, &hf_atn_cpdlc_noMessage , ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_NULL },
  {   1, &hf_atn_cpdlc_aTCDownlinkMessage, ASN1_NO_EXTENSIONS     , dissect_atn_cpdlc_ATCDownlinkMessage },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_DownlinkMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_DownlinkMessage, DownlinkMessage_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t StartDownMessage_sequence[] = {
  { &hf_atn_cpdlc_mode      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_Mode },
  { &hf_atn_cpdlc_startDownlinkMessage, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_DownlinkMessage },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_StartDownMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_StartDownMessage, StartDownMessage_sequence);

  return offset;
}


static const value_string atn_cpdlc_AircraftPDUs_vals[] = {
  {   0, "abortUser" },
  {   1, "abortProvider" },
  {   2, "startdown" },
  {   3, "send" },
  { 0, NULL }
};

static const per_choice_t AircraftPDUs_choice[] = {
  {   0, &hf_atn_cpdlc_abortUser , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_CPDLCUserAbortReason },
  {   1, &hf_atn_cpdlc_abortProvider, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_CPDLCProviderAbortReason },
  {   2, &hf_atn_cpdlc_startdown , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_StartDownMessage },
  {   3, &hf_atn_cpdlc_aircraftpdus_send, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_ATCDownlinkMessage },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_AircraftPDUs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_AircraftPDUs, AircraftPDUs_choice,
                                 NULL);

  return offset;
}


static const value_string atn_cpdlc_PMCPDLCUserAbortReason_vals[] = {
  {   0, "undefined" },
  {   1, "no-message-identification-numbers-available" },
  {   2, "duplicate-message-identification-numbers" },
  {   3, "no-longer-next-data-authority" },
  {   4, "current-data-authority-abort" },
  {   5, "commanded-termination" },
  {   6, "invalid-response" },
  {   7, "time-out-of-synchronisation" },
  {   8, "unknown-integrity-check" },
  {   9, "validation-failure" },
  {  10, "unable-to-decode-message" },
  {  11, "invalid-pdu" },
  {  12, "invalid-CPDLC-message" },
  { 0, NULL }
};


static int
dissect_atn_cpdlc_PMCPDLCUserAbortReason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     13, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string atn_cpdlc_PMCPDLCProviderAbortReason_vals[] = {
  {   0, "timer-expired" },
  {   1, "undefined-error" },
  {   2, "invalid-PDU" },
  {   3, "protocol-error" },
  {   4, "communication-service-error" },
  {   5, "communication-service-failure" },
  {   6, "invalid-QOS-parameter" },
  {   7, "expected-PDU-missing" },
  { 0, NULL }
};


static int
dissect_atn_cpdlc_PMCPDLCProviderAbortReason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_atn_cpdlc_AlgorithmIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    proto_tree *top_tree=NULL;

    offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, top_tree, NULL);


  return offset;
}



static int
dissect_atn_cpdlc_CPDLCMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    tvbuff_t *tvb_usr = NULL;

    offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index, NO_BOUND, NO_BOUND, FALSE, &tvb_usr, NULL);

    if (tvb_usr) {
      switch(check_heur_msg_type(actx->pinfo)){
          case dm:
              dissect_atn_cpdlc_ATCDownlinkMessage(tvb_new_subset_remaining(tvb_usr, 0), 0, actx, tree, hf_index);
              break;
          case um:
              dissect_atn_cpdlc_ATCUplinkMessage(tvb_new_subset_remaining(tvb_usr, 0), 0, actx , tree, hf_index);
              break;
          default:
              break;
      }
    }


  return offset;
}


static const per_sequence_t ProtectedUplinkMessage_sequence[] = {
  { &hf_atn_cpdlc_algorithmIdentifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_cpdlc_AlgorithmIdentifier },
  { &hf_atn_cpdlc_protectedMessage, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_cpdlc_CPDLCMessage },
  { &hf_atn_cpdlc_integrityCheck, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_BIT_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_ProtectedUplinkMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_ProtectedUplinkMessage, ProtectedUplinkMessage_sequence);

  return offset;
}


static const value_string atn_cpdlc_ProtectedGroundPDUs_vals[] = {
  {   0, "abortUser" },
  {   1, "abortProvider" },
  {   2, "startup" },
  {   3, "send" },
  {   4, "forward" },
  {   5, "forwardresponse" },
  { 0, NULL }
};

static const per_choice_t ProtectedGroundPDUs_choice[] = {
  {   0, &hf_atn_cpdlc_pmcpdlcuserabortreason, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PMCPDLCUserAbortReason },
  {   1, &hf_atn_cpdlc_pmcpdlcproviderabortreason, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PMCPDLCProviderAbortReason },
  {   2, &hf_atn_cpdlc_protecteduplinkmessage, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_ProtectedUplinkMessage },
  {   3, &hf_atn_cpdlc_protecteduplinkmessage, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_ProtectedUplinkMessage },
  {   4, &hf_atn_cpdlc_forward   , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_ATCForwardMessage },
  {   5, &hf_atn_cpdlc_forwardresponse, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_ATCForwardResponse },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_ProtectedGroundPDUs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_ProtectedGroundPDUs, ProtectedGroundPDUs_choice,
                                 NULL);

  return offset;
}


static const value_string atn_cpdlc_ProtectedMode_vals[] = {
  {   0, "cpdlc" },
  {   1, "dsc" },
  { 0, NULL }
};


static int
dissect_atn_cpdlc_ProtectedMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t ProtectedDownlinkMessage_sequence[] = {
  { &hf_atn_cpdlc_algorithmIdentifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_cpdlc_AlgorithmIdentifier },
  { &hf_atn_cpdlc_protectedMessage, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_cpdlc_CPDLCMessage },
  { &hf_atn_cpdlc_integrityCheck, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_BIT_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_ProtectedDownlinkMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_ProtectedDownlinkMessage, ProtectedDownlinkMessage_sequence);

  return offset;
}


static const per_sequence_t ProtectedStartDownMessage_sequence[] = {
  { &hf_atn_cpdlc_protectedmode, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cpdlc_ProtectedMode },
  { &hf_atn_cpdlc_protecteddownlinkmessage, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cpdlc_ProtectedDownlinkMessage },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cpdlc_ProtectedStartDownMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cpdlc_ProtectedStartDownMessage, ProtectedStartDownMessage_sequence);

  return offset;
}


static const value_string atn_cpdlc_ProtectedAircraftPDUs_vals[] = {
  {   0, "abortUser" },
  {   1, "abortProvider" },
  {   2, "startdown" },
  {   3, "send" },
  { 0, NULL }
};

static const per_choice_t ProtectedAircraftPDUs_choice[] = {
  {   0, &hf_atn_cpdlc_pmcpdlcuserabortreason, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PMCPDLCUserAbortReason },
  {   1, &hf_atn_cpdlc_pmcpdlcproviderabortreason, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_PMCPDLCProviderAbortReason },
  {   2, &hf_atn_cpdlc_protectedstartDownmessage, ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_ProtectedStartDownMessage },
  {   3, &hf_atn_cpdlc_send      , ASN1_EXTENSION_ROOT    , dissect_atn_cpdlc_ProtectedDownlinkMessage },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cpdlc_ProtectedAircraftPDUs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cpdlc_ProtectedAircraftPDUs, ProtectedAircraftPDUs_choice,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_GroundPDUs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_atn_cpdlc_GroundPDUs(tvb, offset, &asn1_ctx, tree, hf_atn_cpdlc_GroundPDUs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AircraftPDUs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_atn_cpdlc_AircraftPDUs(tvb, offset, &asn1_ctx, tree, hf_atn_cpdlc_AircraftPDUs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ProtectedGroundPDUs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_atn_cpdlc_ProtectedGroundPDUs(tvb, offset, &asn1_ctx, tree, hf_atn_cpdlc_ProtectedGroundPDUs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ProtectedAircraftPDUs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_atn_cpdlc_ProtectedAircraftPDUs(tvb, offset, &asn1_ctx, tree, hf_atn_cpdlc_ProtectedAircraftPDUs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-atn-cpdlc-fn.c ---*/
#line 102 "./asn1/atn-cpdlc/packet-atn-cpdlc-template.c"

/* Wireshark ID of CPDLC protocol */
static int proto_atn_cpdlc = -1;


static int
dissect_atn_cpdlc(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree,
    void *data _U_)
{
    /* note: */
    /* there are two co-existing applications of CPDLC: */
    /* "plain old" (ae-qualifier 2) and */
    /* "protected mode" (ae-qualifier 22) CPDLC. */
    /* "protected mode" was introduced to cope with a */
    /* safety issue in which a message would sent to the wrong aircraft. */

    /* note:*/
    /* The protection is an additional checksum and covers the message content, */
    /* the 24-bit address of the aircraft, the current flight id and */
    /* the current ground facility so that an aircraft would be able to reject */
    /* messages which are unexpected (i.e. messages to another flight or */
    /* messages from the wrong center). */

    /*note:*/
    /* although "plain old" CPDLC is more or less deprecated */
    /* many aircraft cannot perform  */
    /* "protected mode" for this largely depends on */
    /* upgraded avionics packages */

    /*note:*/
    /* The use of CPDLC is *optional* as the pilot  */
    /* may always use a voice radio channel to talk to the controller.*/

    proto_tree *atn_cpdlc_tree = NULL;
    atn_conversation_t *atn_cv = NULL;

    /* note: */
    /* we need the ae qualifier stored within the conversation */
    /* to decode "plain old cpdlc" or  */
    /* "protected mode cpdlc correctly " */

    /* DT: dstref present, srcref is always zero */
    if((pinfo->clnp_dstref) && (!pinfo->clnp_srcref)){
        atn_cv = find_atn_conversation(
            &pinfo->dst,
            pinfo->clnp_dstref,
            &pinfo->src );
    }
    /* CR: srcref present, dstref is always zero */
    if((!pinfo->clnp_dstref) && (pinfo->clnp_srcref)){
        atn_cv = find_atn_conversation(
            &pinfo->src,
            pinfo->clnp_srcref,
            &pinfo->dst );
    }
    /* CC: srcref and dstref present, always use src/srcref & dst */
    if((pinfo->clnp_dstref) && (pinfo->clnp_srcref)){
        atn_cv = find_atn_conversation(
            &pinfo->src,
            pinfo->clnp_srcref,
            &pinfo->dst );
    }

    if(!atn_cv){ /* atn conversation not found */
      return 0; }

    atn_cpdlc_tree = proto_tree_add_subtree(
        tree, tvb, 0, -1, ett_atn_cpdlc, NULL,
        ATN_CPDLC_PROTO );

    switch(atn_cv->ae_qualifier){
        case  pmcpdlc:
            if( check_heur_msg_type(pinfo) == um ) {
                /* uplink PDU's = Ground PDU's */
                dissect_ProtectedGroundPDUs_PDU(
                    tvb,
                    pinfo,
                    atn_cpdlc_tree, NULL);
            }else {  /* downlink PDU's = Aircraft PDU's */
                dissect_ProtectedAircraftPDUs_PDU(
                    tvb,
                    pinfo,
                  atn_cpdlc_tree, NULL);
            }
            break;
        case cpdlc:
            if( check_heur_msg_type(pinfo) == um ) {
                /* uplink PDU's = Ground PDU's */
                dissect_GroundPDUs_PDU(
                    tvb,
                    pinfo,
                    atn_cpdlc_tree, NULL);
            }else {  /* downlink PDU's = Aircraft PDU's */
                dissect_AircraftPDUs_PDU(
                    tvb,
                    pinfo,
                    atn_cpdlc_tree, NULL);
            }
            break;
        default:
            break;
    }
    return tvb_reported_length_remaining(tvb, 0);
}

static gboolean
dissect_atn_cpdlc_heur(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree,
    void *data _U_)
{
    atn_conversation_t *volatile atn_cv = NULL;
    volatile gboolean is_atn_cpdlc = FALSE;
    volatile gboolean is_pm = FALSE;
    int type;

    type = check_heur_msg_type(pinfo);

    switch(type){
      case um:
          TRY {
            dissect_ProtectedGroundPDUs_PDU(tvb, pinfo, NULL, NULL);
            is_atn_cpdlc = TRUE;
            is_pm = TRUE;}
          CATCH_ALL{
            is_atn_cpdlc = FALSE;
            is_pm = FALSE;}
          ENDTRY;
          if (is_atn_cpdlc) {
            break;
          }
          TRY {
            dissect_GroundPDUs_PDU(tvb, pinfo, NULL, NULL);
            is_pm = FALSE;
            is_atn_cpdlc = TRUE;}
          CATCH_ALL{
            is_atn_cpdlc = FALSE;
            is_pm = FALSE;}
          ENDTRY;
        break;
    case dm:
          TRY {
            dissect_ProtectedAircraftPDUs_PDU(tvb, pinfo, NULL, NULL);
            is_atn_cpdlc = TRUE;
            is_pm = TRUE;}
          CATCH_ALL {
            is_atn_cpdlc = FALSE;
            is_pm = FALSE; }
          ENDTRY;
          if (is_atn_cpdlc) {
            break;
          }
          TRY{
            dissect_AircraftPDUs_PDU(tvb, pinfo, NULL, NULL);
            is_atn_cpdlc = TRUE;
            is_pm = FALSE;}
          CATCH_ALL{
            is_atn_cpdlc = FALSE;
            is_pm = FALSE;}
          ENDTRY;
      break;
    default:
      break;
  }

  if(is_atn_cpdlc){
    /* note: */
    /* all subsequent PDU's belonging to this conversation */
    /* are considered CPDLC */
    /* if the first CPDLC PDU has been decoded successfully */
    /* (This is done in "atn-ulcs" by using "call_dissector_with_data()") */

    /* DT: dstref present, srcref is always zero */
    if((pinfo->clnp_dstref) && (!pinfo->clnp_srcref)){
        atn_cv = find_atn_conversation(&pinfo->dst,
                          pinfo->clnp_dstref,
                          &pinfo->src );
    }
    /* CR: srcref present, dstref is always zero */
    if((!pinfo->clnp_dstref) && (pinfo->clnp_srcref)){
        atn_cv = find_atn_conversation(&pinfo->src,
                          pinfo->clnp_srcref,
                          &pinfo->dst );
    }
    /* CC: srcref and dstref present, always use src/srcref & dst */
    if((pinfo->clnp_dstref) && (pinfo->clnp_srcref)){
        atn_cv = find_atn_conversation(&pinfo->src,
                          pinfo->clnp_srcref,
                          &pinfo->dst );
    }

    if(atn_cv){ /* atn conversation found */
      if(is_pm == TRUE) {
          atn_cv->ae_qualifier =  pmcpdlc; }
      else {
          atn_cv->ae_qualifier =  cpdlc; }
      dissect_atn_cpdlc(tvb, pinfo, tree, NULL);
    }
  }else { /* there should *always* be an atn conversation */
      is_atn_cpdlc = FALSE;
  }

  return is_atn_cpdlc;
}



void proto_register_atn_cpdlc (void)
{
    static hf_register_info hf_atn_cpdlc[] = {

/*--- Included file: packet-atn-cpdlc-hfarr.c ---*/
#line 1 "./asn1/atn-cpdlc/packet-atn-cpdlc-hfarr.c"
    { &hf_atn_cpdlc_GroundPDUs_PDU,
      { "GroundPDUs", "atn-cpdlc.GroundPDUs",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_GroundPDUs_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_AircraftPDUs_PDU,
      { "AircraftPDUs", "atn-cpdlc.AircraftPDUs",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_AircraftPDUs_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_ProtectedGroundPDUs_PDU,
      { "ProtectedGroundPDUs", "atn-cpdlc.ProtectedGroundPDUs",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_ProtectedGroundPDUs_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_ProtectedAircraftPDUs_PDU,
      { "ProtectedAircraftPDUs", "atn-cpdlc.ProtectedAircraftPDUs",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_ProtectedAircraftPDUs_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_abortUser,
      { "abortUser", "atn-cpdlc.abortUser",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_CPDLCUserAbortReason_vals), 0,
        "CPDLCUserAbortReason", HFILL }},
    { &hf_atn_cpdlc_abortProvider,
      { "abortProvider", "atn-cpdlc.abortProvider",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_CPDLCProviderAbortReason_vals), 0,
        "CPDLCProviderAbortReason", HFILL }},
    { &hf_atn_cpdlc_startup,
      { "startup", "atn-cpdlc.startup",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_UplinkMessage_vals), 0,
        "UplinkMessage", HFILL }},
    { &hf_atn_cpdlc_groundpdus_send,
      { "send", "atn-cpdlc.send_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ATCUplinkMessage", HFILL }},
    { &hf_atn_cpdlc_forward,
      { "forward", "atn-cpdlc.forward_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ATCForwardMessage", HFILL }},
    { &hf_atn_cpdlc_forwardresponse,
      { "forwardresponse", "atn-cpdlc.forwardresponse",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_ATCForwardResponse_vals), 0,
        "ATCForwardResponse", HFILL }},
    { &hf_atn_cpdlc_noMessage,
      { "noMessage", "atn-cpdlc.noMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_aTCUplinkMessage,
      { "aTCUplinkMessage", "atn-cpdlc.aTCUplinkMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_startdown,
      { "startdown", "atn-cpdlc.startdown_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "StartDownMessage", HFILL }},
    { &hf_atn_cpdlc_aircraftpdus_send,
      { "send", "atn-cpdlc.send_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ATCDownlinkMessage", HFILL }},
    { &hf_atn_cpdlc_mode,
      { "mode", "atn-cpdlc.mode",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Mode_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_startDownlinkMessage,
      { "startDownlinkMessage", "atn-cpdlc.startDownlinkMessage",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_DownlinkMessage_vals), 0,
        "DownlinkMessage", HFILL }},
    { &hf_atn_cpdlc_aTCDownlinkMessage,
      { "aTCDownlinkMessage", "atn-cpdlc.aTCDownlinkMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_pmcpdlcuserabortreason,
      { "abortUser", "atn-cpdlc.abortUser",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_PMCPDLCUserAbortReason_vals), 0,
        "PMCPDLCUserAbortReason", HFILL }},
    { &hf_atn_cpdlc_pmcpdlcproviderabortreason,
      { "abortProvider", "atn-cpdlc.abortProvider",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_PMCPDLCProviderAbortReason_vals), 0,
        "PMCPDLCProviderAbortReason", HFILL }},
    { &hf_atn_cpdlc_protecteduplinkmessage,
      { "startup", "atn-cpdlc.startup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtectedUplinkMessage", HFILL }},
    { &hf_atn_cpdlc_algorithmIdentifier,
      { "algorithmIdentifier", "atn-cpdlc.algorithmIdentifier",
        FT_REL_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_protectedMessage,
      { "protectedMessage", "atn-cpdlc.protectedMessage",
        FT_BYTES, BASE_NONE, NULL, 0,
        "CPDLCMessage", HFILL }},
    { &hf_atn_cpdlc_integrityCheck,
      { "integrityCheck", "atn-cpdlc.integrityCheck",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_atn_cpdlc_forwardHeader,
      { "forwardHeader", "atn-cpdlc.forwardHeader_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_forwardMessage,
      { "forwardMessage", "atn-cpdlc.forwardMessage",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_ForwardMessage_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dateTime,
      { "dateTime", "atn-cpdlc.dateTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DateTimeGroup", HFILL }},
    { &hf_atn_cpdlc_aircraftID,
      { "aircraftID", "atn-cpdlc.aircraftID",
        FT_STRING, BASE_NONE, NULL, 0,
        "AircraftFlightIdentification", HFILL }},
    { &hf_atn_cpdlc_aircraftAddress,
      { "aircraftAddress", "atn-cpdlc.aircraftAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_upElementIDs,
      { "upElementIDs", "atn-cpdlc.upElementIDs",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_atn_cpdlc_downElementIDs,
      { "downElementIDs", "atn-cpdlc.downElementIDs",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_atn_cpdlc_protectedstartDownmessage,
      { "startdown", "atn-cpdlc.startdown_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtectedStartDownMessage", HFILL }},
    { &hf_atn_cpdlc_send,
      { "send", "atn-cpdlc.send_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtectedDownlinkMessage", HFILL }},
    { &hf_atn_cpdlc_protectedmode,
      { "mode", "atn-cpdlc.mode",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_ProtectedMode_vals), 0,
        "ProtectedMode", HFILL }},
    { &hf_atn_cpdlc_protecteddownlinkmessage,
      { "startDownlinkMessage", "atn-cpdlc.startDownlinkMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtectedDownlinkMessage", HFILL }},
    { &hf_atn_cpdlc_header,
      { "header", "atn-cpdlc.header_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ATCMessageHeader", HFILL }},
    { &hf_atn_cpdlc_atcuplinkmessage_messagedata,
      { "messageData", "atn-cpdlc.messageData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ATCUplinkMessageData", HFILL }},
    { &hf_atn_cpdlc_atcuplinkmessagedata_elementids,
      { "elementIds", "atn-cpdlc.elementIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_5_OF_ATCUplinkMsgElementId", HFILL }},
    { &hf_atn_cpdlc_atcuplinkmessagedata_elementids_item,
      { "ATCUplinkMsgElementId", "atn-cpdlc.ATCUplinkMsgElementId",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_ATCUplinkMsgElementId_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_atcuplinkmessagedata_constraineddata,
      { "constrainedData", "atn-cpdlc.constrainedData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_atcuplinkmessagedata_constraineddata", HFILL }},
    { &hf_atn_cpdlc_routeClearanceData,
      { "routeClearanceData", "atn-cpdlc.routeClearanceData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_2_OF_RouteClearance", HFILL }},
    { &hf_atn_cpdlc_routeClearanceData_item,
      { "RouteClearance", "atn-cpdlc.RouteClearance_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_atcdownlinkmessage_messagedata,
      { "messageData", "atn-cpdlc.messageData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ATCDownlinkMessageData", HFILL }},
    { &hf_atn_cpdlc_atcdownlinkmessagedata_elementids,
      { "elementIds", "atn-cpdlc.elementIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_5_OF_ATCDownlinkMsgElementId", HFILL }},
    { &hf_atn_cpdlc_atcdownlinkmessagedata_elementids_item,
      { "ATCDownlinkMsgElementId", "atn-cpdlc.ATCDownlinkMsgElementId",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_ATCDownlinkMsgElementId_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_atcdownlinkmessagedata_constraineddata,
      { "constrainedData", "atn-cpdlc.constrainedData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_atcdownlinkmessagedata_constraineddata", HFILL }},
    { &hf_atn_cpdlc_messageIdNumber,
      { "messageIdNumber", "atn-cpdlc.messageIdNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MsgIdentificationNumber", HFILL }},
    { &hf_atn_cpdlc_messageRefNumber,
      { "messageRefNumber", "atn-cpdlc.messageRefNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MsgReferenceNumber", HFILL }},
    { &hf_atn_cpdlc_logicalAck,
      { "logicalAck", "atn-cpdlc.logicalAck",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_LogicalAck_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM0NULL,
      { "uM0NULL", "atn-cpdlc.uM0NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM1NULL,
      { "uM1NULL", "atn-cpdlc.uM1NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM2NULL,
      { "uM2NULL", "atn-cpdlc.uM2NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM3NULL,
      { "uM3NULL", "atn-cpdlc.uM3NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM4NULL,
      { "uM4NULL", "atn-cpdlc.uM4NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM5NULL,
      { "uM5NULL", "atn-cpdlc.uM5NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM6Level,
      { "uM6Level", "atn-cpdlc.uM6Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_uM7Time,
      { "uM7Time", "atn-cpdlc.uM7Time_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_atn_cpdlc_uM8Position,
      { "uM8Position", "atn-cpdlc.uM8Position",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Position_vals), 0,
        "Position", HFILL }},
    { &hf_atn_cpdlc_uM9Time,
      { "uM9Time", "atn-cpdlc.uM9Time_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_atn_cpdlc_uM10Position,
      { "uM10Position", "atn-cpdlc.uM10Position",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Position_vals), 0,
        "Position", HFILL }},
    { &hf_atn_cpdlc_uM11Time,
      { "uM11Time", "atn-cpdlc.uM11Time_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_atn_cpdlc_uM12Position,
      { "uM12Position", "atn-cpdlc.uM12Position",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Position_vals), 0,
        "Position", HFILL }},
    { &hf_atn_cpdlc_uM13TimeLevel,
      { "uM13TimeLevel", "atn-cpdlc.uM13TimeLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimeLevel", HFILL }},
    { &hf_atn_cpdlc_uM14PositionLevel,
      { "uM14PositionLevel", "atn-cpdlc.uM14PositionLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionLevel", HFILL }},
    { &hf_atn_cpdlc_uM15TimeLevel,
      { "uM15TimeLevel", "atn-cpdlc.uM15TimeLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimeLevel", HFILL }},
    { &hf_atn_cpdlc_uM16PositionLevel,
      { "uM16PositionLevel", "atn-cpdlc.uM16PositionLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionLevel", HFILL }},
    { &hf_atn_cpdlc_uM17TimeLevel,
      { "uM17TimeLevel", "atn-cpdlc.uM17TimeLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimeLevel", HFILL }},
    { &hf_atn_cpdlc_uM18PositionLevel,
      { "uM18PositionLevel", "atn-cpdlc.uM18PositionLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionLevel", HFILL }},
    { &hf_atn_cpdlc_uM19Level,
      { "uM19Level", "atn-cpdlc.uM19Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_uM20Level,
      { "uM20Level", "atn-cpdlc.uM20Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_uM21TimeLevel,
      { "uM21TimeLevel", "atn-cpdlc.uM21TimeLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimeLevel", HFILL }},
    { &hf_atn_cpdlc_uM22PositionLevel,
      { "uM22PositionLevel", "atn-cpdlc.uM22PositionLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionLevel", HFILL }},
    { &hf_atn_cpdlc_uM23Level,
      { "uM23Level", "atn-cpdlc.uM23Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_uM24TimeLevel,
      { "uM24TimeLevel", "atn-cpdlc.uM24TimeLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimeLevel", HFILL }},
    { &hf_atn_cpdlc_uM25PositionLevel,
      { "uM25PositionLevel", "atn-cpdlc.uM25PositionLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionLevel", HFILL }},
    { &hf_atn_cpdlc_uM26LevelTime,
      { "uM26LevelTime", "atn-cpdlc.uM26LevelTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LevelTime", HFILL }},
    { &hf_atn_cpdlc_uM27LevelPosition,
      { "uM27LevelPosition", "atn-cpdlc.uM27LevelPosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LevelPosition", HFILL }},
    { &hf_atn_cpdlc_uM28LevelTime,
      { "uM28LevelTime", "atn-cpdlc.uM28LevelTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LevelTime", HFILL }},
    { &hf_atn_cpdlc_uM29LevelPosition,
      { "uM29LevelPosition", "atn-cpdlc.uM29LevelPosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LevelPosition", HFILL }},
    { &hf_atn_cpdlc_uM30LevelLevel,
      { "uM30LevelLevel", "atn-cpdlc.uM30LevelLevel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LevelLevel", HFILL }},
    { &hf_atn_cpdlc_uM31LevelLevel,
      { "uM31LevelLevel", "atn-cpdlc.uM31LevelLevel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LevelLevel", HFILL }},
    { &hf_atn_cpdlc_uM32LevelLevel,
      { "uM32LevelLevel", "atn-cpdlc.uM32LevelLevel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LevelLevel", HFILL }},
    { &hf_atn_cpdlc_uM33NULL,
      { "uM33NULL", "atn-cpdlc.uM33NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM34Level,
      { "uM34Level", "atn-cpdlc.uM34Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_uM35Level,
      { "uM35Level", "atn-cpdlc.uM35Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_uM36Level,
      { "uM36Level", "atn-cpdlc.uM36Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_uM37Level,
      { "uM37Level", "atn-cpdlc.uM37Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_uM38Level,
      { "uM38Level", "atn-cpdlc.uM38Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_uM39Level,
      { "uM39Level", "atn-cpdlc.uM39Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_uM40NULL,
      { "uM40NULL", "atn-cpdlc.uM40NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM41NULL,
      { "uM41NULL", "atn-cpdlc.uM41NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM42PositionLevel,
      { "uM42PositionLevel", "atn-cpdlc.uM42PositionLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionLevel", HFILL }},
    { &hf_atn_cpdlc_uM43PositionLevel,
      { "uM43PositionLevel", "atn-cpdlc.uM43PositionLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionLevel", HFILL }},
    { &hf_atn_cpdlc_uM44PositionLevel,
      { "uM44PositionLevel", "atn-cpdlc.uM44PositionLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionLevel", HFILL }},
    { &hf_atn_cpdlc_uM45PositionLevel,
      { "uM45PositionLevel", "atn-cpdlc.uM45PositionLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionLevel", HFILL }},
    { &hf_atn_cpdlc_uM46PositionLevel,
      { "uM46PositionLevel", "atn-cpdlc.uM46PositionLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionLevel", HFILL }},
    { &hf_atn_cpdlc_uM47PositionLevel,
      { "uM47PositionLevel", "atn-cpdlc.uM47PositionLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionLevel", HFILL }},
    { &hf_atn_cpdlc_uM48PositionLevel,
      { "uM48PositionLevel", "atn-cpdlc.uM48PositionLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionLevel", HFILL }},
    { &hf_atn_cpdlc_uM49PositionLevel,
      { "uM49PositionLevel", "atn-cpdlc.uM49PositionLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionLevel", HFILL }},
    { &hf_atn_cpdlc_uM50PositionLevelLevel,
      { "uM50PositionLevelLevel", "atn-cpdlc.uM50PositionLevelLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionLevelLevel", HFILL }},
    { &hf_atn_cpdlc_uM51PositionTime,
      { "uM51PositionTime", "atn-cpdlc.uM51PositionTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionTime", HFILL }},
    { &hf_atn_cpdlc_uM52PositionTime,
      { "uM52PositionTime", "atn-cpdlc.uM52PositionTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionTime", HFILL }},
    { &hf_atn_cpdlc_uM53PositionTime,
      { "uM53PositionTime", "atn-cpdlc.uM53PositionTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionTime", HFILL }},
    { &hf_atn_cpdlc_uM54PositionTimeTime,
      { "uM54PositionTimeTime", "atn-cpdlc.uM54PositionTimeTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionTimeTime", HFILL }},
    { &hf_atn_cpdlc_uM55PositionSpeed,
      { "uM55PositionSpeed", "atn-cpdlc.uM55PositionSpeed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionSpeed", HFILL }},
    { &hf_atn_cpdlc_uM56PositionSpeed,
      { "uM56PositionSpeed", "atn-cpdlc.uM56PositionSpeed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionSpeed", HFILL }},
    { &hf_atn_cpdlc_uM57PositionSpeed,
      { "uM57PositionSpeed", "atn-cpdlc.uM57PositionSpeed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionSpeed", HFILL }},
    { &hf_atn_cpdlc_uM58PositionTimeLevel,
      { "uM58PositionTimeLevel", "atn-cpdlc.uM58PositionTimeLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionTimeLevel", HFILL }},
    { &hf_atn_cpdlc_uM59PositionTimeLevel,
      { "uM59PositionTimeLevel", "atn-cpdlc.uM59PositionTimeLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionTimeLevel", HFILL }},
    { &hf_atn_cpdlc_uM60PositionTimeLevel,
      { "uM60PositionTimeLevel", "atn-cpdlc.uM60PositionTimeLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionTimeLevel", HFILL }},
    { &hf_atn_cpdlc_uM61PositionLevelSpeed,
      { "uM61PositionLevelSpeed", "atn-cpdlc.uM61PositionLevelSpeed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionLevelSpeed", HFILL }},
    { &hf_atn_cpdlc_uM62TimePositionLevel,
      { "uM62TimePositionLevel", "atn-cpdlc.uM62TimePositionLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimePositionLevel", HFILL }},
    { &hf_atn_cpdlc_uM63TimePositionLevelSpeed,
      { "uM63TimePositionLevelSpeed", "atn-cpdlc.uM63TimePositionLevelSpeed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimePositionLevelSpeed", HFILL }},
    { &hf_atn_cpdlc_uM64DistanceSpecifiedDirection,
      { "uM64DistanceSpecifiedDirection", "atn-cpdlc.uM64DistanceSpecifiedDirection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DistanceSpecifiedDirection", HFILL }},
    { &hf_atn_cpdlc_uM65PositionDistanceSpecifiedDirection,
      { "uM65PositionDistanceSpecifiedDirection", "atn-cpdlc.uM65PositionDistanceSpecifiedDirection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionDistanceSpecifiedDirection", HFILL }},
    { &hf_atn_cpdlc_uM66TimeDistanceSpecifiedDirection,
      { "uM66TimeDistanceSpecifiedDirection", "atn-cpdlc.uM66TimeDistanceSpecifiedDirection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimeDistanceSpecifiedDirection", HFILL }},
    { &hf_atn_cpdlc_uM67NULL,
      { "uM67NULL", "atn-cpdlc.uM67NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM68Position,
      { "uM68Position", "atn-cpdlc.uM68Position",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Position_vals), 0,
        "Position", HFILL }},
    { &hf_atn_cpdlc_uM69Time,
      { "uM69Time", "atn-cpdlc.uM69Time_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_atn_cpdlc_uM70Position,
      { "uM70Position", "atn-cpdlc.uM70Position",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Position_vals), 0,
        "Position", HFILL }},
    { &hf_atn_cpdlc_uM71Time,
      { "uM71Time", "atn-cpdlc.uM71Time_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_atn_cpdlc_uM72NULL,
      { "uM72NULL", "atn-cpdlc.uM72NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM73DepartureClearance,
      { "uM73DepartureClearance", "atn-cpdlc.uM73DepartureClearance_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DepartureClearance", HFILL }},
    { &hf_atn_cpdlc_uM74Position,
      { "uM74Position", "atn-cpdlc.uM74Position",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Position_vals), 0,
        "Position", HFILL }},
    { &hf_atn_cpdlc_uM75Position,
      { "uM75Position", "atn-cpdlc.uM75Position",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Position_vals), 0,
        "Position", HFILL }},
    { &hf_atn_cpdlc_uM76TimePosition,
      { "uM76TimePosition", "atn-cpdlc.uM76TimePosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimePosition", HFILL }},
    { &hf_atn_cpdlc_uM77PositionPosition,
      { "uM77PositionPosition", "atn-cpdlc.uM77PositionPosition",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PositionPosition", HFILL }},
    { &hf_atn_cpdlc_uM78LevelPosition,
      { "uM78LevelPosition", "atn-cpdlc.uM78LevelPosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LevelPosition", HFILL }},
    { &hf_atn_cpdlc_uM79PositionRouteClearance,
      { "uM79PositionRouteClearance", "atn-cpdlc.uM79PositionRouteClearance_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionRouteClearanceIndex", HFILL }},
    { &hf_atn_cpdlc_uM80RouteClearance,
      { "uM80RouteClearance", "atn-cpdlc.uM80RouteClearance",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RouteClearanceIndex", HFILL }},
    { &hf_atn_cpdlc_uM81ProcedureName,
      { "uM81ProcedureName", "atn-cpdlc.uM81ProcedureName_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProcedureName", HFILL }},
    { &hf_atn_cpdlc_uM82DistanceSpecifiedDirection,
      { "uM82DistanceSpecifiedDirection", "atn-cpdlc.uM82DistanceSpecifiedDirection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DistanceSpecifiedDirection", HFILL }},
    { &hf_atn_cpdlc_uM83PositionRouteClearance,
      { "uM83PositionRouteClearance", "atn-cpdlc.uM83PositionRouteClearance_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionRouteClearanceIndex", HFILL }},
    { &hf_atn_cpdlc_uM84PositionProcedureName,
      { "uM84PositionProcedureName", "atn-cpdlc.uM84PositionProcedureName_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionProcedureName", HFILL }},
    { &hf_atn_cpdlc_uM85RouteClearance,
      { "uM85RouteClearance", "atn-cpdlc.uM85RouteClearance",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RouteClearanceIndex", HFILL }},
    { &hf_atn_cpdlc_uM86PositionRouteClearance,
      { "uM86PositionRouteClearance", "atn-cpdlc.uM86PositionRouteClearance_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionRouteClearanceIndex", HFILL }},
    { &hf_atn_cpdlc_uM87Position,
      { "uM87Position", "atn-cpdlc.uM87Position",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Position_vals), 0,
        "Position", HFILL }},
    { &hf_atn_cpdlc_uM88PositionPosition,
      { "uM88PositionPosition", "atn-cpdlc.uM88PositionPosition",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PositionPosition", HFILL }},
    { &hf_atn_cpdlc_uM89TimePosition,
      { "uM89TimePosition", "atn-cpdlc.uM89TimePosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimePosition", HFILL }},
    { &hf_atn_cpdlc_uM90LevelPosition,
      { "uM90LevelPosition", "atn-cpdlc.uM90LevelPosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LevelPosition", HFILL }},
    { &hf_atn_cpdlc_uM91HoldClearance,
      { "uM91HoldClearance", "atn-cpdlc.uM91HoldClearance_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "HoldClearance", HFILL }},
    { &hf_atn_cpdlc_uM92PositionLevel,
      { "uM92PositionLevel", "atn-cpdlc.uM92PositionLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionLevel", HFILL }},
    { &hf_atn_cpdlc_uM93Time,
      { "uM93Time", "atn-cpdlc.uM93Time_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_atn_cpdlc_uM94DirectionDegrees,
      { "uM94DirectionDegrees", "atn-cpdlc.uM94DirectionDegrees_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DirectionDegrees", HFILL }},
    { &hf_atn_cpdlc_uM95DirectionDegrees,
      { "uM95DirectionDegrees", "atn-cpdlc.uM95DirectionDegrees_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DirectionDegrees", HFILL }},
    { &hf_atn_cpdlc_uM96NULL,
      { "uM96NULL", "atn-cpdlc.uM96NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM97PositionDegrees,
      { "uM97PositionDegrees", "atn-cpdlc.uM97PositionDegrees_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionDegrees", HFILL }},
    { &hf_atn_cpdlc_uM98DirectionDegrees,
      { "uM98DirectionDegrees", "atn-cpdlc.uM98DirectionDegrees_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DirectionDegrees", HFILL }},
    { &hf_atn_cpdlc_uM99ProcedureName,
      { "uM99ProcedureName", "atn-cpdlc.uM99ProcedureName_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProcedureName", HFILL }},
    { &hf_atn_cpdlc_uM100TimeSpeed,
      { "uM100TimeSpeed", "atn-cpdlc.uM100TimeSpeed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimeSpeed", HFILL }},
    { &hf_atn_cpdlc_uM101PositionSpeed,
      { "uM101PositionSpeed", "atn-cpdlc.uM101PositionSpeed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionSpeed", HFILL }},
    { &hf_atn_cpdlc_uM102LevelSpeed,
      { "uM102LevelSpeed", "atn-cpdlc.uM102LevelSpeed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LevelSpeed", HFILL }},
    { &hf_atn_cpdlc_uM103TimeSpeedSpeed,
      { "uM103TimeSpeedSpeed", "atn-cpdlc.uM103TimeSpeedSpeed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimeSpeedSpeed", HFILL }},
    { &hf_atn_cpdlc_uM104PositionSpeedSpeed,
      { "uM104PositionSpeedSpeed", "atn-cpdlc.uM104PositionSpeedSpeed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionSpeedSpeed", HFILL }},
    { &hf_atn_cpdlc_uM105LevelSpeedSpeed,
      { "uM105LevelSpeedSpeed", "atn-cpdlc.uM105LevelSpeedSpeed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LevelSpeedSpeed", HFILL }},
    { &hf_atn_cpdlc_uM106Speed,
      { "uM106Speed", "atn-cpdlc.uM106Speed",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Speed_vals), 0,
        "Speed", HFILL }},
    { &hf_atn_cpdlc_uM107NULL,
      { "uM107NULL", "atn-cpdlc.uM107NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM108Speed,
      { "uM108Speed", "atn-cpdlc.uM108Speed",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Speed_vals), 0,
        "Speed", HFILL }},
    { &hf_atn_cpdlc_uM109Speed,
      { "uM109Speed", "atn-cpdlc.uM109Speed",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Speed_vals), 0,
        "Speed", HFILL }},
    { &hf_atn_cpdlc_uM110SpeedSpeed,
      { "uM110SpeedSpeed", "atn-cpdlc.uM110SpeedSpeed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SpeedSpeed", HFILL }},
    { &hf_atn_cpdlc_uM111Speed,
      { "uM111Speed", "atn-cpdlc.uM111Speed",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Speed_vals), 0,
        "Speed", HFILL }},
    { &hf_atn_cpdlc_uM112Speed,
      { "uM112Speed", "atn-cpdlc.uM112Speed",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Speed_vals), 0,
        "Speed", HFILL }},
    { &hf_atn_cpdlc_uM113Speed,
      { "uM113Speed", "atn-cpdlc.uM113Speed",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Speed_vals), 0,
        "Speed", HFILL }},
    { &hf_atn_cpdlc_uM114Speed,
      { "uM114Speed", "atn-cpdlc.uM114Speed",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Speed_vals), 0,
        "Speed", HFILL }},
    { &hf_atn_cpdlc_uM115Speed,
      { "uM115Speed", "atn-cpdlc.uM115Speed",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Speed_vals), 0,
        "Speed", HFILL }},
    { &hf_atn_cpdlc_uM116NULL,
      { "uM116NULL", "atn-cpdlc.uM116NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM117UnitNameFrequency,
      { "uM117UnitNameFrequency", "atn-cpdlc.uM117UnitNameFrequency_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnitNameFrequency", HFILL }},
    { &hf_atn_cpdlc_uM118PositionUnitNameFrequency,
      { "uM118PositionUnitNameFrequency", "atn-cpdlc.uM118PositionUnitNameFrequency_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionUnitNameFrequency", HFILL }},
    { &hf_atn_cpdlc_uM119TimeUnitNameFrequency,
      { "uM119TimeUnitNameFrequency", "atn-cpdlc.uM119TimeUnitNameFrequency_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimeUnitNameFrequency", HFILL }},
    { &hf_atn_cpdlc_uM120UnitNameFrequency,
      { "uM120UnitNameFrequency", "atn-cpdlc.uM120UnitNameFrequency_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnitNameFrequency", HFILL }},
    { &hf_atn_cpdlc_uM121PositionUnitNameFrequency,
      { "uM121PositionUnitNameFrequency", "atn-cpdlc.uM121PositionUnitNameFrequency_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionUnitNameFrequency", HFILL }},
    { &hf_atn_cpdlc_uM122TimeUnitNameFrequency,
      { "uM122TimeUnitNameFrequency", "atn-cpdlc.uM122TimeUnitNameFrequency_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimeUnitNameFrequency", HFILL }},
    { &hf_atn_cpdlc_uM123Code,
      { "uM123Code", "atn-cpdlc.uM123Code",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Code", HFILL }},
    { &hf_atn_cpdlc_uM124NULL,
      { "uM124NULL", "atn-cpdlc.uM124NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM125NULL,
      { "uM125NULL", "atn-cpdlc.uM125NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM126NULL,
      { "uM126NULL", "atn-cpdlc.uM126NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM127NULL,
      { "uM127NULL", "atn-cpdlc.uM127NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM128Level,
      { "uM128Level", "atn-cpdlc.uM128Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_uM129Level,
      { "uM129Level", "atn-cpdlc.uM129Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_uM130Position,
      { "uM130Position", "atn-cpdlc.uM130Position",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Position_vals), 0,
        "Position", HFILL }},
    { &hf_atn_cpdlc_uM131NULL,
      { "uM131NULL", "atn-cpdlc.uM131NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM132NULL,
      { "uM132NULL", "atn-cpdlc.uM132NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM133NULL,
      { "uM133NULL", "atn-cpdlc.uM133NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM134SpeedTypeSpeedTypeSpeedType,
      { "uM134SpeedTypeSpeedTypeSpeedType", "atn-cpdlc.uM134SpeedTypeSpeedTypeSpeedType",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SpeedTypeSpeedTypeSpeedType", HFILL }},
    { &hf_atn_cpdlc_uM135NULL,
      { "uM135NULL", "atn-cpdlc.uM135NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM136NULL,
      { "uM136NULL", "atn-cpdlc.uM136NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM137NULL,
      { "uM137NULL", "atn-cpdlc.uM137NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM138NULL,
      { "uM138NULL", "atn-cpdlc.uM138NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM139NULL,
      { "uM139NULL", "atn-cpdlc.uM139NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM140NULL,
      { "uM140NULL", "atn-cpdlc.uM140NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM141NULL,
      { "uM141NULL", "atn-cpdlc.uM141NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM142NULL,
      { "uM142NULL", "atn-cpdlc.uM142NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM143NULL,
      { "uM143NULL", "atn-cpdlc.uM143NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM144NULL,
      { "uM144NULL", "atn-cpdlc.uM144NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM145NULL,
      { "uM145NULL", "atn-cpdlc.uM145NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM146NULL,
      { "uM146NULL", "atn-cpdlc.uM146NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM147NULL,
      { "uM147NULL", "atn-cpdlc.uM147NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM148Level,
      { "uM148Level", "atn-cpdlc.uM148Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_uM149LevelPosition,
      { "uM149LevelPosition", "atn-cpdlc.uM149LevelPosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LevelPosition", HFILL }},
    { &hf_atn_cpdlc_uM150LevelTime,
      { "uM150LevelTime", "atn-cpdlc.uM150LevelTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LevelTime", HFILL }},
    { &hf_atn_cpdlc_uM151Speed,
      { "uM151Speed", "atn-cpdlc.uM151Speed",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Speed_vals), 0,
        "Speed", HFILL }},
    { &hf_atn_cpdlc_uM152DistanceSpecifiedDirection,
      { "uM152DistanceSpecifiedDirection", "atn-cpdlc.uM152DistanceSpecifiedDirection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DistanceSpecifiedDirection", HFILL }},
    { &hf_atn_cpdlc_uM153Altimeter,
      { "uM153Altimeter", "atn-cpdlc.uM153Altimeter",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Altimeter_vals), 0,
        "Altimeter", HFILL }},
    { &hf_atn_cpdlc_uM154NULL,
      { "uM154NULL", "atn-cpdlc.uM154NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM155Position,
      { "uM155Position", "atn-cpdlc.uM155Position",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Position_vals), 0,
        "Position", HFILL }},
    { &hf_atn_cpdlc_uM156NULL,
      { "uM156NULL", "atn-cpdlc.uM156NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM157Frequency,
      { "uM157Frequency", "atn-cpdlc.uM157Frequency",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Frequency_vals), 0,
        "Frequency", HFILL }},
    { &hf_atn_cpdlc_uM158AtisCode,
      { "uM158AtisCode", "atn-cpdlc.uM158AtisCode",
        FT_STRING, BASE_NONE, NULL, 0,
        "ATISCode", HFILL }},
    { &hf_atn_cpdlc_uM159ErrorInformation,
      { "uM159ErrorInformation", "atn-cpdlc.uM159ErrorInformation",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_ErrorInformation_vals), 0,
        "ErrorInformation", HFILL }},
    { &hf_atn_cpdlc_uM160Facility,
      { "uM160Facility", "atn-cpdlc.uM160Facility",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Facility_vals), 0,
        "Facility", HFILL }},
    { &hf_atn_cpdlc_uM161NULL,
      { "uM161NULL", "atn-cpdlc.uM161NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM162NULL,
      { "uM162NULL", "atn-cpdlc.uM162NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM163FacilityDesignation,
      { "uM163FacilityDesignation", "atn-cpdlc.uM163FacilityDesignation",
        FT_STRING, BASE_NONE, NULL, 0,
        "FacilityDesignation", HFILL }},
    { &hf_atn_cpdlc_uM164NULL,
      { "uM164NULL", "atn-cpdlc.uM164NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM165NULL,
      { "uM165NULL", "atn-cpdlc.uM165NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM166TrafficType,
      { "uM166TrafficType", "atn-cpdlc.uM166TrafficType",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_TrafficType_vals), 0,
        "TrafficType", HFILL }},
    { &hf_atn_cpdlc_uM167NULL,
      { "uM167NULL", "atn-cpdlc.uM167NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM168NULL,
      { "uM168NULL", "atn-cpdlc.uM168NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM169FreeText,
      { "uM169FreeText", "atn-cpdlc.uM169FreeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "FreeText", HFILL }},
    { &hf_atn_cpdlc_uM170FreeText,
      { "uM170FreeText", "atn-cpdlc.uM170FreeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "FreeText", HFILL }},
    { &hf_atn_cpdlc_uM171VerticalRate,
      { "uM171VerticalRate", "atn-cpdlc.uM171VerticalRate",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_VerticalRate_vals), 0,
        "VerticalRate", HFILL }},
    { &hf_atn_cpdlc_uM172VerticalRate,
      { "uM172VerticalRate", "atn-cpdlc.uM172VerticalRate",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_VerticalRate_vals), 0,
        "VerticalRate", HFILL }},
    { &hf_atn_cpdlc_uM173VerticalRate,
      { "uM173VerticalRate", "atn-cpdlc.uM173VerticalRate",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_VerticalRate_vals), 0,
        "VerticalRate", HFILL }},
    { &hf_atn_cpdlc_uM174VerticalRate,
      { "uM174VerticalRate", "atn-cpdlc.uM174VerticalRate",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_VerticalRate_vals), 0,
        "VerticalRate", HFILL }},
    { &hf_atn_cpdlc_uM175Level,
      { "uM175Level", "atn-cpdlc.uM175Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_uM176NULL,
      { "uM176NULL", "atn-cpdlc.uM176NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM177NULL,
      { "uM177NULL", "atn-cpdlc.uM177NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM178NULL,
      { "uM178NULL", "atn-cpdlc.uM178NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM179NULL,
      { "uM179NULL", "atn-cpdlc.uM179NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM180LevelLevel,
      { "uM180LevelLevel", "atn-cpdlc.uM180LevelLevel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LevelLevel", HFILL }},
    { &hf_atn_cpdlc_uM181ToFromPosition,
      { "uM181ToFromPosition", "atn-cpdlc.uM181ToFromPosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ToFromPosition", HFILL }},
    { &hf_atn_cpdlc_uM182NULL,
      { "uM182NULL", "atn-cpdlc.uM182NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM183FreeText,
      { "uM183FreeText", "atn-cpdlc.uM183FreeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "FreeText", HFILL }},
    { &hf_atn_cpdlc_uM184TimeToFromPosition,
      { "uM184TimeToFromPosition", "atn-cpdlc.uM184TimeToFromPosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimeToFromPosition", HFILL }},
    { &hf_atn_cpdlc_uM185PositionLevel,
      { "uM185PositionLevel", "atn-cpdlc.uM185PositionLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionLevel", HFILL }},
    { &hf_atn_cpdlc_uM186PositionLevel,
      { "uM186PositionLevel", "atn-cpdlc.uM186PositionLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionLevel", HFILL }},
    { &hf_atn_cpdlc_uM187FreeText,
      { "uM187FreeText", "atn-cpdlc.uM187FreeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "FreeText", HFILL }},
    { &hf_atn_cpdlc_uM188PositionSpeed,
      { "uM188PositionSpeed", "atn-cpdlc.uM188PositionSpeed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionSpeed", HFILL }},
    { &hf_atn_cpdlc_uM189Speed,
      { "uM189Speed", "atn-cpdlc.uM189Speed",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Speed_vals), 0,
        "Speed", HFILL }},
    { &hf_atn_cpdlc_uM190Degrees,
      { "uM190Degrees", "atn-cpdlc.uM190Degrees",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Degrees_vals), 0,
        "Degrees", HFILL }},
    { &hf_atn_cpdlc_uM191NULL,
      { "uM191NULL", "atn-cpdlc.uM191NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM192LevelTime,
      { "uM192LevelTime", "atn-cpdlc.uM192LevelTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LevelTime", HFILL }},
    { &hf_atn_cpdlc_uM193NULL,
      { "uM193NULL", "atn-cpdlc.uM193NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM194FreeText,
      { "uM194FreeText", "atn-cpdlc.uM194FreeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "FreeText", HFILL }},
    { &hf_atn_cpdlc_uM195FreeText,
      { "uM195FreeText", "atn-cpdlc.uM195FreeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "FreeText", HFILL }},
    { &hf_atn_cpdlc_uM196FreeText,
      { "uM196FreeText", "atn-cpdlc.uM196FreeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "FreeText", HFILL }},
    { &hf_atn_cpdlc_uM197FreeText,
      { "uM197FreeText", "atn-cpdlc.uM197FreeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "FreeText", HFILL }},
    { &hf_atn_cpdlc_uM198FreeText,
      { "uM198FreeText", "atn-cpdlc.uM198FreeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "FreeText", HFILL }},
    { &hf_atn_cpdlc_uM199FreeText,
      { "uM199FreeText", "atn-cpdlc.uM199FreeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "FreeText", HFILL }},
    { &hf_atn_cpdlc_uM200NULL,
      { "uM200NULL", "atn-cpdlc.uM200NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM201NULL,
      { "uM201NULL", "atn-cpdlc.uM201NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM202NULL,
      { "uM202NULL", "atn-cpdlc.uM202NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM203FreeText,
      { "uM203FreeText", "atn-cpdlc.uM203FreeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "FreeText", HFILL }},
    { &hf_atn_cpdlc_uM204FreeText,
      { "uM204FreeText", "atn-cpdlc.uM204FreeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "FreeText", HFILL }},
    { &hf_atn_cpdlc_uM205FreeText,
      { "uM205FreeText", "atn-cpdlc.uM205FreeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "FreeText", HFILL }},
    { &hf_atn_cpdlc_uM206FreeText,
      { "uM206FreeText", "atn-cpdlc.uM206FreeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "FreeText", HFILL }},
    { &hf_atn_cpdlc_uM207FreeText,
      { "uM207FreeText", "atn-cpdlc.uM207FreeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "FreeText", HFILL }},
    { &hf_atn_cpdlc_uM208FreeText,
      { "uM208FreeText", "atn-cpdlc.uM208FreeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "FreeText", HFILL }},
    { &hf_atn_cpdlc_uM209LevelPosition,
      { "uM209LevelPosition", "atn-cpdlc.uM209LevelPosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LevelPosition", HFILL }},
    { &hf_atn_cpdlc_uM210Position,
      { "uM210Position", "atn-cpdlc.uM210Position",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Position_vals), 0,
        "Position", HFILL }},
    { &hf_atn_cpdlc_uM211NULL,
      { "uM211NULL", "atn-cpdlc.uM211NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM212FacilityDesignationATISCode,
      { "uM212FacilityDesignationATISCode", "atn-cpdlc.uM212FacilityDesignationATISCode_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FacilityDesignationATISCode", HFILL }},
    { &hf_atn_cpdlc_uM213FacilityDesignationAltimeter,
      { "uM213FacilityDesignationAltimeter", "atn-cpdlc.uM213FacilityDesignationAltimeter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FacilityDesignationAltimeter", HFILL }},
    { &hf_atn_cpdlc_uM214RunwayRVR,
      { "uM214RunwayRVR", "atn-cpdlc.uM214RunwayRVR_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RunwayRVR", HFILL }},
    { &hf_atn_cpdlc_uM215DirectionDegrees,
      { "uM215DirectionDegrees", "atn-cpdlc.uM215DirectionDegrees_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DirectionDegrees", HFILL }},
    { &hf_atn_cpdlc_uM216NULL,
      { "uM216NULL", "atn-cpdlc.uM216NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM217NULL,
      { "uM217NULL", "atn-cpdlc.uM217NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM218NULL,
      { "uM218NULL", "atn-cpdlc.uM218NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM219Level,
      { "uM219Level", "atn-cpdlc.uM219Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_uM220Level,
      { "uM220Level", "atn-cpdlc.uM220Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_uM221Degrees,
      { "uM221Degrees", "atn-cpdlc.uM221Degrees",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Degrees_vals), 0,
        "Degrees", HFILL }},
    { &hf_atn_cpdlc_uM222NULL,
      { "uM222NULL", "atn-cpdlc.uM222NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM223NULL,
      { "uM223NULL", "atn-cpdlc.uM223NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM224NULL,
      { "uM224NULL", "atn-cpdlc.uM224NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM225NULL,
      { "uM225NULL", "atn-cpdlc.uM225NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM226Time,
      { "uM226Time", "atn-cpdlc.uM226Time_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_atn_cpdlc_uM227NULL,
      { "uM227NULL", "atn-cpdlc.uM227NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM228Position,
      { "uM228Position", "atn-cpdlc.uM228Position",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Position_vals), 0,
        "Position", HFILL }},
    { &hf_atn_cpdlc_uM229NULL,
      { "uM229NULL", "atn-cpdlc.uM229NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM230NULL,
      { "uM230NULL", "atn-cpdlc.uM230NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM231NULL,
      { "uM231NULL", "atn-cpdlc.uM231NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM232NULL,
      { "uM232NULL", "atn-cpdlc.uM232NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM233NULL,
      { "uM233NULL", "atn-cpdlc.uM233NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM234NULL,
      { "uM234NULL", "atn-cpdlc.uM234NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM235NULL,
      { "uM235NULL", "atn-cpdlc.uM235NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM236NULL,
      { "uM236NULL", "atn-cpdlc.uM236NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_uM237NULL,
      { "uM237NULL", "atn-cpdlc.uM237NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM0NULL,
      { "dM0NULL", "atn-cpdlc.dM0NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM1NULL,
      { "dM1NULL", "atn-cpdlc.dM1NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM2NULL,
      { "dM2NULL", "atn-cpdlc.dM2NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM3NULL,
      { "dM3NULL", "atn-cpdlc.dM3NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM4NULL,
      { "dM4NULL", "atn-cpdlc.dM4NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM5NULL,
      { "dM5NULL", "atn-cpdlc.dM5NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM6Level,
      { "dM6Level", "atn-cpdlc.dM6Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_dM7LevelLevel,
      { "dM7LevelLevel", "atn-cpdlc.dM7LevelLevel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LevelLevel", HFILL }},
    { &hf_atn_cpdlc_dM8Level,
      { "dM8Level", "atn-cpdlc.dM8Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_dM9Level,
      { "dM9Level", "atn-cpdlc.dM9Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_dM10Level,
      { "dM10Level", "atn-cpdlc.dM10Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_dM11PositionLevel,
      { "dM11PositionLevel", "atn-cpdlc.dM11PositionLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionLevel", HFILL }},
    { &hf_atn_cpdlc_dM12PositionLevel,
      { "dM12PositionLevel", "atn-cpdlc.dM12PositionLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionLevel", HFILL }},
    { &hf_atn_cpdlc_dM13TimeLevel,
      { "dM13TimeLevel", "atn-cpdlc.dM13TimeLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimeLevel", HFILL }},
    { &hf_atn_cpdlc_dM14TimeLevel,
      { "dM14TimeLevel", "atn-cpdlc.dM14TimeLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimeLevel", HFILL }},
    { &hf_atn_cpdlc_dM15DistanceSpecifiedDirection,
      { "dM15DistanceSpecifiedDirection", "atn-cpdlc.dM15DistanceSpecifiedDirection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DistanceSpecifiedDirection", HFILL }},
    { &hf_atn_cpdlc_dM16PositionDistanceSpecifiedDirection,
      { "dM16PositionDistanceSpecifiedDirection", "atn-cpdlc.dM16PositionDistanceSpecifiedDirection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionDistanceSpecifiedDirection", HFILL }},
    { &hf_atn_cpdlc_dM17TimeDistanceSpecifiedDirection,
      { "dM17TimeDistanceSpecifiedDirection", "atn-cpdlc.dM17TimeDistanceSpecifiedDirection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimeDistanceSpecifiedDirection", HFILL }},
    { &hf_atn_cpdlc_dM18Speed,
      { "dM18Speed", "atn-cpdlc.dM18Speed",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Speed_vals), 0,
        "Speed", HFILL }},
    { &hf_atn_cpdlc_dM19SpeedSpeed,
      { "dM19SpeedSpeed", "atn-cpdlc.dM19SpeedSpeed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SpeedSpeed", HFILL }},
    { &hf_atn_cpdlc_dM20NULL,
      { "dM20NULL", "atn-cpdlc.dM20NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM21Frequency,
      { "dM21Frequency", "atn-cpdlc.dM21Frequency",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Frequency_vals), 0,
        "Frequency", HFILL }},
    { &hf_atn_cpdlc_dM22Position,
      { "dM22Position", "atn-cpdlc.dM22Position",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Position_vals), 0,
        "Position", HFILL }},
    { &hf_atn_cpdlc_dM23ProcedureName,
      { "dM23ProcedureName", "atn-cpdlc.dM23ProcedureName_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProcedureName", HFILL }},
    { &hf_atn_cpdlc_dM24RouteClearance,
      { "dM24RouteClearance", "atn-cpdlc.dM24RouteClearance",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RouteClearanceIndex", HFILL }},
    { &hf_atn_cpdlc_dM25ClearanceType,
      { "dM25ClearanceType", "atn-cpdlc.dM25ClearanceType",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_ClearanceType_vals), 0,
        "ClearanceType", HFILL }},
    { &hf_atn_cpdlc_dM26PositionRouteClearance,
      { "dM26PositionRouteClearance", "atn-cpdlc.dM26PositionRouteClearance_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionRouteClearanceIndex", HFILL }},
    { &hf_atn_cpdlc_dM27DistanceSpecifiedDirection,
      { "dM27DistanceSpecifiedDirection", "atn-cpdlc.dM27DistanceSpecifiedDirection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DistanceSpecifiedDirection", HFILL }},
    { &hf_atn_cpdlc_dM28Level,
      { "dM28Level", "atn-cpdlc.dM28Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_dM29Level,
      { "dM29Level", "atn-cpdlc.dM29Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_dM30Level,
      { "dM30Level", "atn-cpdlc.dM30Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_dM31Position,
      { "dM31Position", "atn-cpdlc.dM31Position",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Position_vals), 0,
        "Position", HFILL }},
    { &hf_atn_cpdlc_dM32Level,
      { "dM32Level", "atn-cpdlc.dM32Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_dM33Position,
      { "dM33Position", "atn-cpdlc.dM33Position",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Position_vals), 0,
        "Position", HFILL }},
    { &hf_atn_cpdlc_dM34Speed,
      { "dM34Speed", "atn-cpdlc.dM34Speed",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Speed_vals), 0,
        "Speed", HFILL }},
    { &hf_atn_cpdlc_dM35Degrees,
      { "dM35Degrees", "atn-cpdlc.dM35Degrees",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Degrees_vals), 0,
        "Degrees", HFILL }},
    { &hf_atn_cpdlc_dM36Degrees,
      { "dM36Degrees", "atn-cpdlc.dM36Degrees",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Degrees_vals), 0,
        "Degrees", HFILL }},
    { &hf_atn_cpdlc_dM37Level,
      { "dM37Level", "atn-cpdlc.dM37Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_dM38Level,
      { "dM38Level", "atn-cpdlc.dM38Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_dM39Speed,
      { "dM39Speed", "atn-cpdlc.dM39Speed",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Speed_vals), 0,
        "Speed", HFILL }},
    { &hf_atn_cpdlc_dM40RouteClearance,
      { "dM40RouteClearance", "atn-cpdlc.dM40RouteClearance",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RouteClearanceIndex", HFILL }},
    { &hf_atn_cpdlc_dM41NULL,
      { "dM41NULL", "atn-cpdlc.dM41NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM42Position,
      { "dM42Position", "atn-cpdlc.dM42Position",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Position_vals), 0,
        "Position", HFILL }},
    { &hf_atn_cpdlc_dM43Time,
      { "dM43Time", "atn-cpdlc.dM43Time_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_atn_cpdlc_dM44Position,
      { "dM44Position", "atn-cpdlc.dM44Position",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Position_vals), 0,
        "Position", HFILL }},
    { &hf_atn_cpdlc_dM45Position,
      { "dM45Position", "atn-cpdlc.dM45Position",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Position_vals), 0,
        "Position", HFILL }},
    { &hf_atn_cpdlc_dM46Time,
      { "dM46Time", "atn-cpdlc.dM46Time_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_atn_cpdlc_dM47Code,
      { "dM47Code", "atn-cpdlc.dM47Code",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Code", HFILL }},
    { &hf_atn_cpdlc_dM48PositionReport,
      { "dM48PositionReport", "atn-cpdlc.dM48PositionReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionReport", HFILL }},
    { &hf_atn_cpdlc_dM49Speed,
      { "dM49Speed", "atn-cpdlc.dM49Speed",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Speed_vals), 0,
        "Speed", HFILL }},
    { &hf_atn_cpdlc_dM50SpeedSpeed,
      { "dM50SpeedSpeed", "atn-cpdlc.dM50SpeedSpeed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SpeedSpeed", HFILL }},
    { &hf_atn_cpdlc_dM51NULL,
      { "dM51NULL", "atn-cpdlc.dM51NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM52NULL,
      { "dM52NULL", "atn-cpdlc.dM52NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM53NULL,
      { "dM53NULL", "atn-cpdlc.dM53NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM54Level,
      { "dM54Level", "atn-cpdlc.dM54Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_dM55NULL,
      { "dM55NULL", "atn-cpdlc.dM55NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM56NULL,
      { "dM56NULL", "atn-cpdlc.dM56NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM57RemainingFuelPersonsOnBoard,
      { "dM57RemainingFuelPersonsOnBoard", "atn-cpdlc.dM57RemainingFuelPersonsOnBoard_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RemainingFuelPersonsOnBoard", HFILL }},
    { &hf_atn_cpdlc_dM58NULL,
      { "dM58NULL", "atn-cpdlc.dM58NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM59PositionRouteClearance,
      { "dM59PositionRouteClearance", "atn-cpdlc.dM59PositionRouteClearance_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionRouteClearanceIndex", HFILL }},
    { &hf_atn_cpdlc_dM60DistanceSpecifiedDirection,
      { "dM60DistanceSpecifiedDirection", "atn-cpdlc.dM60DistanceSpecifiedDirection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DistanceSpecifiedDirection", HFILL }},
    { &hf_atn_cpdlc_dM61Level,
      { "dM61Level", "atn-cpdlc.dM61Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_dM62ErrorInformation,
      { "dM62ErrorInformation", "atn-cpdlc.dM62ErrorInformation",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_ErrorInformation_vals), 0,
        "ErrorInformation", HFILL }},
    { &hf_atn_cpdlc_dM63NULL,
      { "dM63NULL", "atn-cpdlc.dM63NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM64FacilityDesignation,
      { "dM64FacilityDesignation", "atn-cpdlc.dM64FacilityDesignation",
        FT_STRING, BASE_NONE, NULL, 0,
        "FacilityDesignation", HFILL }},
    { &hf_atn_cpdlc_dM65NULL,
      { "dM65NULL", "atn-cpdlc.dM65NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM66NULL,
      { "dM66NULL", "atn-cpdlc.dM66NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM67FreeText,
      { "dM67FreeText", "atn-cpdlc.dM67FreeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "FreeText", HFILL }},
    { &hf_atn_cpdlc_dM68FreeText,
      { "dM68FreeText", "atn-cpdlc.dM68FreeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "FreeText", HFILL }},
    { &hf_atn_cpdlc_dM69NULL,
      { "dM69NULL", "atn-cpdlc.dM69NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM70Degrees,
      { "dM70Degrees", "atn-cpdlc.dM70Degrees",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Degrees_vals), 0,
        "Degrees", HFILL }},
    { &hf_atn_cpdlc_dM71Degrees,
      { "dM71Degrees", "atn-cpdlc.dM71Degrees",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Degrees_vals), 0,
        "Degrees", HFILL }},
    { &hf_atn_cpdlc_dM72Level,
      { "dM72Level", "atn-cpdlc.dM72Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_dM73Versionnumber,
      { "dM73Versionnumber", "atn-cpdlc.dM73Versionnumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "VersionNumber", HFILL }},
    { &hf_atn_cpdlc_dM74NULL,
      { "dM74NULL", "atn-cpdlc.dM74NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM75NULL,
      { "dM75NULL", "atn-cpdlc.dM75NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM76LevelLevel,
      { "dM76LevelLevel", "atn-cpdlc.dM76LevelLevel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LevelLevel", HFILL }},
    { &hf_atn_cpdlc_dM77LevelLevel,
      { "dM77LevelLevel", "atn-cpdlc.dM77LevelLevel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LevelLevel", HFILL }},
    { &hf_atn_cpdlc_dM78TimeDistanceToFromPosition,
      { "dM78TimeDistanceToFromPosition", "atn-cpdlc.dM78TimeDistanceToFromPosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimeDistanceToFromPosition", HFILL }},
    { &hf_atn_cpdlc_dM79AtisCode,
      { "dM79AtisCode", "atn-cpdlc.dM79AtisCode",
        FT_STRING, BASE_NONE, NULL, 0,
        "ATISCode", HFILL }},
    { &hf_atn_cpdlc_dM80DistanceSpecifiedDirection,
      { "dM80DistanceSpecifiedDirection", "atn-cpdlc.dM80DistanceSpecifiedDirection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DistanceSpecifiedDirection", HFILL }},
    { &hf_atn_cpdlc_dM81LevelTime,
      { "dM81LevelTime", "atn-cpdlc.dM81LevelTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LevelTime", HFILL }},
    { &hf_atn_cpdlc_dM82Level,
      { "dM82Level", "atn-cpdlc.dM82Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_dM83SpeedTime,
      { "dM83SpeedTime", "atn-cpdlc.dM83SpeedTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SpeedTime", HFILL }},
    { &hf_atn_cpdlc_dM84Speed,
      { "dM84Speed", "atn-cpdlc.dM84Speed",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Speed_vals), 0,
        "Speed", HFILL }},
    { &hf_atn_cpdlc_dM85DistanceSpecifiedDirectionTime,
      { "dM85DistanceSpecifiedDirectionTime", "atn-cpdlc.dM85DistanceSpecifiedDirectionTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DistanceSpecifiedDirectionTime", HFILL }},
    { &hf_atn_cpdlc_dM86DistanceSpecifiedDirection,
      { "dM86DistanceSpecifiedDirection", "atn-cpdlc.dM86DistanceSpecifiedDirection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DistanceSpecifiedDirection", HFILL }},
    { &hf_atn_cpdlc_dM87Level,
      { "dM87Level", "atn-cpdlc.dM87Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_dM88Level,
      { "dM88Level", "atn-cpdlc.dM88Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_dM89UnitnameFrequency,
      { "dM89UnitnameFrequency", "atn-cpdlc.dM89UnitnameFrequency_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnitNameFrequency", HFILL }},
    { &hf_atn_cpdlc_dM90FreeText,
      { "dM90FreeText", "atn-cpdlc.dM90FreeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "FreeText", HFILL }},
    { &hf_atn_cpdlc_dM91FreeText,
      { "dM91FreeText", "atn-cpdlc.dM91FreeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "FreeText", HFILL }},
    { &hf_atn_cpdlc_dM92FreeText,
      { "dM92FreeText", "atn-cpdlc.dM92FreeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "FreeText", HFILL }},
    { &hf_atn_cpdlc_dM93FreeText,
      { "dM93FreeText", "atn-cpdlc.dM93FreeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "FreeText", HFILL }},
    { &hf_atn_cpdlc_dM94FreeText,
      { "dM94FreeText", "atn-cpdlc.dM94FreeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "FreeText", HFILL }},
    { &hf_atn_cpdlc_dM95FreeText,
      { "dM95FreeText", "atn-cpdlc.dM95FreeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "FreeText", HFILL }},
    { &hf_atn_cpdlc_dM96FreeText,
      { "dM96FreeText", "atn-cpdlc.dM96FreeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "FreeText", HFILL }},
    { &hf_atn_cpdlc_dM97FreeText,
      { "dM97FreeText", "atn-cpdlc.dM97FreeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "FreeText", HFILL }},
    { &hf_atn_cpdlc_dM98FreeText,
      { "dM98FreeText", "atn-cpdlc.dM98FreeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "FreeText", HFILL }},
    { &hf_atn_cpdlc_dM99NULL,
      { "dM99NULL", "atn-cpdlc.dM99NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM100NULL,
      { "dM100NULL", "atn-cpdlc.dM100NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM101NULL,
      { "dM101NULL", "atn-cpdlc.dM101NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM102NULL,
      { "dM102NULL", "atn-cpdlc.dM102NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM103NULL,
      { "dM103NULL", "atn-cpdlc.dM103NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM104PositionTime,
      { "dM104PositionTime", "atn-cpdlc.dM104PositionTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionTime", HFILL }},
    { &hf_atn_cpdlc_dM105Airport,
      { "dM105Airport", "atn-cpdlc.dM105Airport",
        FT_STRING, BASE_NONE, NULL, 0,
        "Airport", HFILL }},
    { &hf_atn_cpdlc_dM106Level,
      { "dM106Level", "atn-cpdlc.dM106Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_dM107NULL,
      { "dM107NULL", "atn-cpdlc.dM107NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM108NULL,
      { "dM108NULL", "atn-cpdlc.dM108NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM109Time,
      { "dM109Time", "atn-cpdlc.dM109Time_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_atn_cpdlc_dM110Position,
      { "dM110Position", "atn-cpdlc.dM110Position",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Position_vals), 0,
        "Position", HFILL }},
    { &hf_atn_cpdlc_dM111TimePosition,
      { "dM111TimePosition", "atn-cpdlc.dM111TimePosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimePosition", HFILL }},
    { &hf_atn_cpdlc_dM112NULL,
      { "dM112NULL", "atn-cpdlc.dM112NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_dM113SpeedTypeSpeedTypeSpeedTypeSpeed,
      { "dM113SpeedTypeSpeedTypeSpeedTypeSpeed", "atn-cpdlc.dM113SpeedTypeSpeedTypeSpeedTypeSpeed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SpeedTypeSpeedTypeSpeedTypeSpeed", HFILL }},
    { &hf_atn_cpdlc_altimeterEnglish,
      { "altimeterEnglish", "atn-cpdlc.altimeterEnglish",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_altimeterMetric,
      { "altimeterMetric", "atn-cpdlc.altimeterMetric",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_position,
      { "position", "atn-cpdlc.position",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Position_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_aTWDistance,
      { "aTWDistance", "atn-cpdlc.aTWDistance_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_speed,
      { "speed", "atn-cpdlc.speed",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Speed_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_aTWLevels,
      { "aTWLevels", "atn-cpdlc.aTWLevels",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ATWLevelSequence", HFILL }},
    { &hf_atn_cpdlc_atw,
      { "atw", "atn-cpdlc.atw",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_ATWLevelTolerance_vals), 0,
        "ATWLevelTolerance", HFILL }},
    { &hf_atn_cpdlc_level,
      { "level", "atn-cpdlc.level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_ATWLevelSequence_item,
      { "ATWLevel", "atn-cpdlc.ATWLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_atwDistanceTolerance,
      { "atwDistanceTolerance", "atn-cpdlc.atwDistanceTolerance",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_ATWDistanceTolerance_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_distance,
      { "distance", "atn-cpdlc.distance",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Distance_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_Code_item,
      { "CodeOctalDigit", "atn-cpdlc.CodeOctalDigit",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_time,
      { "time", "atn-cpdlc.time_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_timeTolerance,
      { "timeTolerance", "atn-cpdlc.timeTolerance",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_TimeTolerance_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_year,
      { "year", "atn-cpdlc.year",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_month,
      { "month", "atn-cpdlc.month",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_day,
      { "day", "atn-cpdlc.day",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_date,
      { "date", "atn-cpdlc.date_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_timehhmmss,
      { "timehhmmss", "atn-cpdlc.timehhmmss_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_degreesMagnetic,
      { "degreesMagnetic", "atn-cpdlc.degreesMagnetic",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_degreesTrue,
      { "degreesTrue", "atn-cpdlc.degreesTrue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_aircraftFlightIdentification,
      { "aircraftFlightIdentification", "atn-cpdlc.aircraftFlightIdentification",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_clearanceLimit,
      { "clearanceLimit", "atn-cpdlc.clearanceLimit",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Position_vals), 0,
        "Position", HFILL }},
    { &hf_atn_cpdlc_flightInformation,
      { "flightInformation", "atn-cpdlc.flightInformation",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_FlightInformation_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_furtherInstructions,
      { "furtherInstructions", "atn-cpdlc.furtherInstructions_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_direction,
      { "direction", "atn-cpdlc.direction",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Direction_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_degrees,
      { "degrees", "atn-cpdlc.degrees",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Degrees_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_distanceNm,
      { "distanceNm", "atn-cpdlc.distanceNm",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_distanceKm,
      { "distanceKm", "atn-cpdlc.distanceKm",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_distanceSpecifiedNm,
      { "distanceSpecifiedNm", "atn-cpdlc.distanceSpecifiedNm",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_distanceSpecifiedKm,
      { "distanceSpecifiedKm", "atn-cpdlc.distanceSpecifiedKm",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_distanceSpecified,
      { "distanceSpecified", "atn-cpdlc.distanceSpecified",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_DistanceSpecified_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_distanceSpecifiedDirection,
      { "distanceSpecifiedDirection", "atn-cpdlc.distanceSpecifiedDirection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_noFacility,
      { "noFacility", "atn-cpdlc.noFacility_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_facilityDesignation,
      { "facilityDesignation", "atn-cpdlc.facilityDesignation",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_altimeter,
      { "altimeter", "atn-cpdlc.altimeter",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Altimeter_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_aTISCode,
      { "aTISCode", "atn-cpdlc.aTISCode",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_fixname_name,
      { "name", "atn-cpdlc.name",
        FT_STRING, BASE_NONE, NULL, 0,
        "Fix", HFILL }},
    { &hf_atn_cpdlc_latlon,
      { "latlon", "atn-cpdlc.latlon_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LatitudeLongitude", HFILL }},
    { &hf_atn_cpdlc_routeOfFlight,
      { "routeOfFlight", "atn-cpdlc.routeOfFlight",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_RouteInformation_vals), 0,
        "RouteInformation", HFILL }},
    { &hf_atn_cpdlc_levelsOfFlight,
      { "levelsOfFlight", "atn-cpdlc.levelsOfFlight",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_LevelsOfFlight_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_routeAndLevels,
      { "routeAndLevels", "atn-cpdlc.routeAndLevels_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_frequencyhf,
      { "frequencyhf", "atn-cpdlc.frequencyhf",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_frequencyvhf,
      { "frequencyvhf", "atn-cpdlc.frequencyvhf",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_frequencyuhf,
      { "frequencyuhf", "atn-cpdlc.frequencyuhf",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_frequencysatchannel,
      { "frequencysatchannel", "atn-cpdlc.frequencysatchannel",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_code,
      { "code", "atn-cpdlc.code",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_frequencyDeparture,
      { "frequencyDeparture", "atn-cpdlc.frequencyDeparture_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnitNameFrequency", HFILL }},
    { &hf_atn_cpdlc_clearanceExpiryTime,
      { "clearanceExpiryTime", "atn-cpdlc.clearanceExpiryTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_atn_cpdlc_airportDeparture,
      { "airportDeparture", "atn-cpdlc.airportDeparture",
        FT_STRING, BASE_NONE, NULL, 0,
        "Airport", HFILL }},
    { &hf_atn_cpdlc_airportDestination,
      { "airportDestination", "atn-cpdlc.airportDestination",
        FT_STRING, BASE_NONE, NULL, 0,
        "Airport", HFILL }},
    { &hf_atn_cpdlc_timeDeparture,
      { "timeDeparture", "atn-cpdlc.timeDeparture_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_runwayDeparture,
      { "runwayDeparture", "atn-cpdlc.runwayDeparture_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Runway", HFILL }},
    { &hf_atn_cpdlc_revisionNumber,
      { "revisionNumber", "atn-cpdlc.revisionNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_holdatwaypointspeedlow,
      { "holdatwaypointspeedlow", "atn-cpdlc.holdatwaypointspeedlow",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Speed_vals), 0,
        "Speed", HFILL }},
    { &hf_atn_cpdlc_aTWlevel,
      { "aTWlevel", "atn-cpdlc.aTWlevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_holdatwaypointspeedhigh,
      { "holdatwaypointspeedhigh", "atn-cpdlc.holdatwaypointspeedhigh",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Speed_vals), 0,
        "Speed", HFILL }},
    { &hf_atn_cpdlc_eFCtime,
      { "eFCtime", "atn-cpdlc.eFCtime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_atn_cpdlc_legtype,
      { "legtype", "atn-cpdlc.legtype",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_LegType_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_legType,
      { "legType", "atn-cpdlc.legType",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_LegType_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_fromSelection,
      { "fromSelection", "atn-cpdlc.fromSelection",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_InterceptCourseFromSelection_vals), 0,
        "InterceptCourseFromSelection", HFILL }},
    { &hf_atn_cpdlc_publishedIdentifier,
      { "publishedIdentifier", "atn-cpdlc.publishedIdentifier",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_PublishedIdentifier_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_latitudeLongitude,
      { "latitudeLongitude", "atn-cpdlc.latitudeLongitude_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_placeBearingPlaceBearing,
      { "placeBearingPlaceBearing", "atn-cpdlc.placeBearingPlaceBearing",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_placeBearingDistance,
      { "placeBearingDistance", "atn-cpdlc.placeBearingDistance_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_latitudeType,
      { "latitudeType", "atn-cpdlc.latitudeType",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_LatitudeType_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_latitudeDirection,
      { "latitudeDirection", "atn-cpdlc.latitudeDirection",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_LatitudeDirection_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_latitudeWholeDegrees,
      { "latitudeWholeDegrees", "atn-cpdlc.latitudeWholeDegrees",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_minutesLatLon,
      { "minutesLatLon", "atn-cpdlc.minutesLatLon",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_latlonWholeMinutes,
      { "latlonWholeMinutes", "atn-cpdlc.latlonWholeMinutes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_secondsLatLon,
      { "secondsLatLon", "atn-cpdlc.secondsLatLon",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_latitude,
      { "latitude", "atn-cpdlc.latitude_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_longitude,
      { "longitude", "atn-cpdlc.longitude_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_latitudeDegrees,
      { "latitudeDegrees", "atn-cpdlc.latitudeDegrees",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_latitudeDegreesMinutes,
      { "latitudeDegreesMinutes", "atn-cpdlc.latitudeDegreesMinutes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_latitudeDMS,
      { "latitudeDMS", "atn-cpdlc.latitudeDMS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LatitudeDegreesMinutesSeconds", HFILL }},
    { &hf_atn_cpdlc_latitudeReportingPoints,
      { "latitudeReportingPoints", "atn-cpdlc.latitudeReportingPoints_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_longitudeReportingPoints,
      { "longitudeReportingPoints", "atn-cpdlc.longitudeReportingPoints_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_legDistanceEnglish,
      { "legDistanceEnglish", "atn-cpdlc.legDistanceEnglish",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_legDistanceMetric,
      { "legDistanceMetric", "atn-cpdlc.legDistanceMetric",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_legDistance,
      { "legDistance", "atn-cpdlc.legDistance",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_LegDistance_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_legTime,
      { "legTime", "atn-cpdlc.legTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_singleLevel,
      { "singleLevel", "atn-cpdlc.singleLevel",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_LevelType_vals), 0,
        "LevelType", HFILL }},
    { &hf_atn_cpdlc_blockLevel,
      { "blockLevel", "atn-cpdlc.blockLevel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_2_OF_LevelType", HFILL }},
    { &hf_atn_cpdlc_blockLevel_item,
      { "LevelType", "atn-cpdlc.LevelType",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_LevelType_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_LevelLevel_item,
      { "Level", "atn-cpdlc.Level",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_procedureName,
      { "procedureName", "atn-cpdlc.procedureName_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_levelProcedureName,
      { "levelProcedureName", "atn-cpdlc.levelProcedureName_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_levelspeed_speed,
      { "speed", "atn-cpdlc.speed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SpeedSpeed", HFILL }},
    { &hf_atn_cpdlc_speeds,
      { "speeds", "atn-cpdlc.speeds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SpeedSpeed", HFILL }},
    { &hf_atn_cpdlc_levelFeet,
      { "levelFeet", "atn-cpdlc.levelFeet",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_levelMeters,
      { "levelMeters", "atn-cpdlc.levelMeters",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_levelFlightLevel,
      { "levelFlightLevel", "atn-cpdlc.levelFlightLevel",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_levelFlightLevelMetric,
      { "levelFlightLevelMetric", "atn-cpdlc.levelFlightLevelMetric",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_longitudeType,
      { "longitudeType", "atn-cpdlc.longitudeType",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_LongitudeType_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_longitudeDirection,
      { "longitudeDirection", "atn-cpdlc.longitudeDirection",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_LongitudeDirection_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_longitudeWholeDegrees,
      { "longitudeWholeDegrees", "atn-cpdlc.longitudeWholeDegrees",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_latLonWholeMinutes,
      { "latLonWholeMinutes", "atn-cpdlc.latLonWholeMinutes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_longitudeDegrees,
      { "longitudeDegrees", "atn-cpdlc.longitudeDegrees",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_longitudeDegreesMinutes,
      { "longitudeDegreesMinutes", "atn-cpdlc.longitudeDegreesMinutes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_longitudeDMS,
      { "longitudeDMS", "atn-cpdlc.longitudeDMS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LongitudeDegreesMinutesSeconds", HFILL }},
    { &hf_atn_cpdlc_navaid_name,
      { "name", "atn-cpdlc.name",
        FT_STRING, BASE_NONE, NULL, 0,
        "NavaidName", HFILL }},
    { &hf_atn_cpdlc_PlaceBearingPlaceBearing_item,
      { "PlaceBearing", "atn-cpdlc.PlaceBearing_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_fixName,
      { "fixName", "atn-cpdlc.fixName_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_navaid,
      { "navaid", "atn-cpdlc.navaid_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_airport,
      { "airport", "atn-cpdlc.airport",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_levels,
      { "levels", "atn-cpdlc.levels",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LevelLevel", HFILL }},
    { &hf_atn_cpdlc_positionlevel,
      { "positionlevel", "atn-cpdlc.positionlevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_PositionPosition_item,
      { "Position", "atn-cpdlc.Position",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Position_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_positioncurrent,
      { "positioncurrent", "atn-cpdlc.positioncurrent",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Position_vals), 0,
        "Position", HFILL }},
    { &hf_atn_cpdlc_timeatpositioncurrent,
      { "timeatpositioncurrent", "atn-cpdlc.timeatpositioncurrent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_atn_cpdlc_fixnext,
      { "fixnext", "atn-cpdlc.fixnext",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Position_vals), 0,
        "Position", HFILL }},
    { &hf_atn_cpdlc_timeetaatfixnext,
      { "timeetaatfixnext", "atn-cpdlc.timeetaatfixnext_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_atn_cpdlc_fixnextplusone,
      { "fixnextplusone", "atn-cpdlc.fixnextplusone",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Position_vals), 0,
        "Position", HFILL }},
    { &hf_atn_cpdlc_timeetaatdestination,
      { "timeetaatdestination", "atn-cpdlc.timeetaatdestination_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_atn_cpdlc_remainingFuel,
      { "remainingFuel", "atn-cpdlc.remainingFuel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_temperature,
      { "temperature", "atn-cpdlc.temperature",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_winds,
      { "winds", "atn-cpdlc.winds_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_turbulence,
      { "turbulence", "atn-cpdlc.turbulence",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Turbulence_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_icing,
      { "icing", "atn-cpdlc.icing",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Icing_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_speedground,
      { "speedground", "atn-cpdlc.speedground",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_verticalChange,
      { "verticalChange", "atn-cpdlc.verticalChange_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_trackAngle,
      { "trackAngle", "atn-cpdlc.trackAngle",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Degrees_vals), 0,
        "Degrees", HFILL }},
    { &hf_atn_cpdlc_heading,
      { "heading", "atn-cpdlc.heading",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Degrees_vals), 0,
        "Degrees", HFILL }},
    { &hf_atn_cpdlc_humidity,
      { "humidity", "atn-cpdlc.humidity",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_reportedWaypointPosition,
      { "reportedWaypointPosition", "atn-cpdlc.reportedWaypointPosition",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Position_vals), 0,
        "Position", HFILL }},
    { &hf_atn_cpdlc_reportedWaypointTime,
      { "reportedWaypointTime", "atn-cpdlc.reportedWaypointTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_atn_cpdlc_reportedWaypointLevel,
      { "reportedWaypointLevel", "atn-cpdlc.reportedWaypointLevel",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Level_vals), 0,
        "Level", HFILL }},
    { &hf_atn_cpdlc_routeClearanceIndex,
      { "routeClearanceIndex", "atn-cpdlc.routeClearanceIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_positionTime,
      { "positionTime", "atn-cpdlc.positionTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_times,
      { "times", "atn-cpdlc.times",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TimeTime", HFILL }},
    { &hf_atn_cpdlc_unitname,
      { "unitname", "atn-cpdlc.unitname_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_frequency,
      { "frequency", "atn-cpdlc.frequency",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Frequency_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_type,
      { "type", "atn-cpdlc.type",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_ProcedureType_vals), 0,
        "ProcedureType", HFILL }},
    { &hf_atn_cpdlc_procedure,
      { "procedure", "atn-cpdlc.procedure",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_transition,
      { "transition", "atn-cpdlc.transition",
        FT_STRING, BASE_NONE, NULL, 0,
        "ProcedureTransition", HFILL }},
    { &hf_atn_cpdlc_personsOnBoard,
      { "personsOnBoard", "atn-cpdlc.personsOnBoard",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_latLonReportingPoints,
      { "latLonReportingPoints", "atn-cpdlc.latLonReportingPoints",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_LatLonReportingPoints_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_degreeIncrement,
      { "degreeIncrement", "atn-cpdlc.degreeIncrement",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_procedureDeparture,
      { "procedureDeparture", "atn-cpdlc.procedureDeparture_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProcedureName", HFILL }},
    { &hf_atn_cpdlc_runwayArrival,
      { "runwayArrival", "atn-cpdlc.runwayArrival_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Runway", HFILL }},
    { &hf_atn_cpdlc_procedureApproach,
      { "procedureApproach", "atn-cpdlc.procedureApproach_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProcedureName", HFILL }},
    { &hf_atn_cpdlc_procedureArrival,
      { "procedureArrival", "atn-cpdlc.procedureArrival_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProcedureName", HFILL }},
    { &hf_atn_cpdlc_routeInformations,
      { "routeInformations", "atn-cpdlc.routeInformations",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_128_OF_RouteInformation", HFILL }},
    { &hf_atn_cpdlc_routeInformations_item,
      { "RouteInformation", "atn-cpdlc.RouteInformation",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_RouteInformation_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_routeInformationAdditional,
      { "routeInformationAdditional", "atn-cpdlc.routeInformationAdditional_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_aTSRouteDesignator,
      { "aTSRouteDesignator", "atn-cpdlc.aTSRouteDesignator",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_aTWAlongTrackWaypoints,
      { "aTWAlongTrackWaypoints", "atn-cpdlc.aTWAlongTrackWaypoints",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_8_OF_ATWAlongTrackWaypoint", HFILL }},
    { &hf_atn_cpdlc_aTWAlongTrackWaypoints_item,
      { "ATWAlongTrackWaypoint", "atn-cpdlc.ATWAlongTrackWaypoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_reportingpoints,
      { "reportingpoints", "atn-cpdlc.reportingpoints_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_interceptCourseFroms,
      { "interceptCourseFroms", "atn-cpdlc.interceptCourseFroms",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_4_OF_InterceptCourseFrom", HFILL }},
    { &hf_atn_cpdlc_interceptCourseFroms_item,
      { "InterceptCourseFrom", "atn-cpdlc.InterceptCourseFrom_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_holdAtWaypoints,
      { "holdAtWaypoints", "atn-cpdlc.holdAtWaypoints",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_8_OF_Holdatwaypoint", HFILL }},
    { &hf_atn_cpdlc_holdAtWaypoints_item,
      { "Holdatwaypoint", "atn-cpdlc.Holdatwaypoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_waypointSpeedLevels,
      { "waypointSpeedLevels", "atn-cpdlc.waypointSpeedLevels",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_32_OF_WaypointSpeedLevel", HFILL }},
    { &hf_atn_cpdlc_waypointSpeedLevels_item,
      { "WaypointSpeedLevel", "atn-cpdlc.WaypointSpeedLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_rTARequiredTimeArrivals,
      { "rTARequiredTimeArrivals", "atn-cpdlc.rTARequiredTimeArrivals",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_32_OF_RTARequiredTimeArrival", HFILL }},
    { &hf_atn_cpdlc_rTARequiredTimeArrivals_item,
      { "RTARequiredTimeArrival", "atn-cpdlc.RTARequiredTimeArrival_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_rTATime,
      { "rTATime", "atn-cpdlc.rTATime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_rTATolerance,
      { "rTATolerance", "atn-cpdlc.rTATolerance",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_runway_direction,
      { "direction", "atn-cpdlc.direction",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RunwayDirection", HFILL }},
    { &hf_atn_cpdlc_configuration,
      { "configuration", "atn-cpdlc.configuration",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_RunwayConfiguration_vals), 0,
        "RunwayConfiguration", HFILL }},
    { &hf_atn_cpdlc_runway,
      { "runway", "atn-cpdlc.runway_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_rVR,
      { "rVR", "atn-cpdlc.rVR",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_RVR_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_rVRFeet,
      { "rVRFeet", "atn-cpdlc.rVRFeet",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_rVRMeters,
      { "rVRMeters", "atn-cpdlc.rVRMeters",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_speedIndicated,
      { "speedIndicated", "atn-cpdlc.speedIndicated",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_speedIndicatedMetric,
      { "speedIndicatedMetric", "atn-cpdlc.speedIndicatedMetric",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_speedTrue,
      { "speedTrue", "atn-cpdlc.speedTrue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_speedTrueMetric,
      { "speedTrueMetric", "atn-cpdlc.speedTrueMetric",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_speedGround,
      { "speedGround", "atn-cpdlc.speedGround",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_speedGroundMetric,
      { "speedGroundMetric", "atn-cpdlc.speedGroundMetric",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_speedMach,
      { "speedMach", "atn-cpdlc.speedMach",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_SpeedSpeed_item,
      { "Speed", "atn-cpdlc.Speed",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_Speed_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_SpeedTypeSpeedTypeSpeedType_item,
      { "SpeedType", "atn-cpdlc.SpeedType",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_SpeedType_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_speedTypes,
      { "speedTypes", "atn-cpdlc.speedTypes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SpeedTypeSpeedTypeSpeedType", HFILL }},
    { &hf_atn_cpdlc_hours,
      { "hours", "atn-cpdlc.hours",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TimeHours", HFILL }},
    { &hf_atn_cpdlc_minutes,
      { "minutes", "atn-cpdlc.minutes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TimeMinutes", HFILL }},
    { &hf_atn_cpdlc_timeDepartureAllocated,
      { "timeDepartureAllocated", "atn-cpdlc.timeDepartureAllocated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_atn_cpdlc_timeDepartureControlled,
      { "timeDepartureControlled", "atn-cpdlc.timeDepartureControlled_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ControlledTime", HFILL }},
    { &hf_atn_cpdlc_timeDepartureClearanceExpected,
      { "timeDepartureClearanceExpected", "atn-cpdlc.timeDepartureClearanceExpected_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_atn_cpdlc_departureMinimumInterval,
      { "departureMinimumInterval", "atn-cpdlc.departureMinimumInterval",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_tofrom,
      { "tofrom", "atn-cpdlc.tofrom",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_ToFrom_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_hoursminutes,
      { "hoursminutes", "atn-cpdlc.hoursminutes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_atn_cpdlc_seconds,
      { "seconds", "atn-cpdlc.seconds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TimeSeconds", HFILL }},
    { &hf_atn_cpdlc_unitName,
      { "unitName", "atn-cpdlc.unitName_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_timeposition,
      { "timeposition", "atn-cpdlc.timeposition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_levelspeed,
      { "levelspeed", "atn-cpdlc.levelspeed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_speedspeed,
      { "speedspeed", "atn-cpdlc.speedspeed",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_TimeTime_item,
      { "Time", "atn-cpdlc.Time_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_toFrom,
      { "toFrom", "atn-cpdlc.toFrom",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_ToFrom_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_facilityName,
      { "facilityName", "atn-cpdlc.facilityName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_facilityFunction,
      { "facilityFunction", "atn-cpdlc.facilityFunction",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_FacilityFunction_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_vertical_direction,
      { "direction", "atn-cpdlc.direction",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_VerticalDirection_vals), 0,
        "VerticalDirection", HFILL }},
    { &hf_atn_cpdlc_rate,
      { "rate", "atn-cpdlc.rate",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_VerticalRate_vals), 0,
        "VerticalRate", HFILL }},
    { &hf_atn_cpdlc_verticalRateEnglish,
      { "verticalRateEnglish", "atn-cpdlc.verticalRateEnglish",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_verticalRateMetric,
      { "verticalRateMetric", "atn-cpdlc.verticalRateMetric",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_winds_direction,
      { "direction", "atn-cpdlc.direction",
        FT_UINT32, BASE_DEC, NULL, 0,
        "WindDirection", HFILL }},
    { &hf_atn_cpdlc_winds_speed,
      { "speed", "atn-cpdlc.speed",
        FT_UINT32, BASE_DEC, VALS(atn_cpdlc_WindSpeed_vals), 0,
        "WindSpeed", HFILL }},
    { &hf_atn_cpdlc_windSpeedEnglish,
      { "windSpeedEnglish", "atn-cpdlc.windSpeedEnglish",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cpdlc_windSpeedMetric,
      { "windSpeedMetric", "atn-cpdlc.windSpeedMetric",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},

/*--- End of included file: packet-atn-cpdlc-hfarr.c ---*/
#line 317 "./asn1/atn-cpdlc/packet-atn-cpdlc-template.c"
      };

    static gint *ett[] = {

/*--- Included file: packet-atn-cpdlc-ettarr.c ---*/
#line 1 "./asn1/atn-cpdlc/packet-atn-cpdlc-ettarr.c"
    &ett_atn_cpdlc_GroundPDUs,
    &ett_atn_cpdlc_UplinkMessage,
    &ett_atn_cpdlc_AircraftPDUs,
    &ett_atn_cpdlc_StartDownMessage,
    &ett_atn_cpdlc_DownlinkMessage,
    &ett_atn_cpdlc_ProtectedGroundPDUs,
    &ett_atn_cpdlc_ProtectedUplinkMessage,
    &ett_atn_cpdlc_ATCForwardMessage,
    &ett_atn_cpdlc_ForwardHeader,
    &ett_atn_cpdlc_ForwardMessage,
    &ett_atn_cpdlc_ProtectedAircraftPDUs,
    &ett_atn_cpdlc_ProtectedStartDownMessage,
    &ett_atn_cpdlc_ProtectedDownlinkMessage,
    &ett_atn_cpdlc_ATCUplinkMessage,
    &ett_atn_cpdlc_ATCUplinkMessageData,
    &ett_atn_cpdlc_SEQUENCE_SIZE_1_5_OF_ATCUplinkMsgElementId,
    &ett_atn_cpdlc_T_atcuplinkmessagedata_constraineddata,
    &ett_atn_cpdlc_SEQUENCE_SIZE_1_2_OF_RouteClearance,
    &ett_atn_cpdlc_ATCDownlinkMessage,
    &ett_atn_cpdlc_ATCDownlinkMessageData,
    &ett_atn_cpdlc_SEQUENCE_SIZE_1_5_OF_ATCDownlinkMsgElementId,
    &ett_atn_cpdlc_T_atcdownlinkmessagedata_constraineddata,
    &ett_atn_cpdlc_ATCMessageHeader,
    &ett_atn_cpdlc_ATCUplinkMsgElementId,
    &ett_atn_cpdlc_ATCDownlinkMsgElementId,
    &ett_atn_cpdlc_Altimeter,
    &ett_atn_cpdlc_ATWAlongTrackWaypoint,
    &ett_atn_cpdlc_ATWLevel,
    &ett_atn_cpdlc_ATWLevelSequence,
    &ett_atn_cpdlc_ATWDistance,
    &ett_atn_cpdlc_Code,
    &ett_atn_cpdlc_ControlledTime,
    &ett_atn_cpdlc_Date,
    &ett_atn_cpdlc_DateTimeGroup,
    &ett_atn_cpdlc_Degrees,
    &ett_atn_cpdlc_DepartureClearance,
    &ett_atn_cpdlc_DirectionDegrees,
    &ett_atn_cpdlc_Distance,
    &ett_atn_cpdlc_DistanceSpecified,
    &ett_atn_cpdlc_DistanceSpecifiedDirection,
    &ett_atn_cpdlc_DistanceSpecifiedDirectionTime,
    &ett_atn_cpdlc_Facility,
    &ett_atn_cpdlc_FacilityDesignationAltimeter,
    &ett_atn_cpdlc_FacilityDesignationATISCode,
    &ett_atn_cpdlc_FixName,
    &ett_atn_cpdlc_FlightInformation,
    &ett_atn_cpdlc_Frequency,
    &ett_atn_cpdlc_FurtherInstructions,
    &ett_atn_cpdlc_Holdatwaypoint,
    &ett_atn_cpdlc_HoldClearance,
    &ett_atn_cpdlc_InterceptCourseFrom,
    &ett_atn_cpdlc_InterceptCourseFromSelection,
    &ett_atn_cpdlc_Latitude,
    &ett_atn_cpdlc_LatitudeDegreesMinutes,
    &ett_atn_cpdlc_LatitudeDegreesMinutesSeconds,
    &ett_atn_cpdlc_LatitudeLongitude,
    &ett_atn_cpdlc_LatitudeReportingPoints,
    &ett_atn_cpdlc_LatitudeType,
    &ett_atn_cpdlc_LatLonReportingPoints,
    &ett_atn_cpdlc_LegDistance,
    &ett_atn_cpdlc_LegType,
    &ett_atn_cpdlc_Level,
    &ett_atn_cpdlc_SEQUENCE_SIZE_2_OF_LevelType,
    &ett_atn_cpdlc_LevelLevel,
    &ett_atn_cpdlc_LevelPosition,
    &ett_atn_cpdlc_LevelProcedureName,
    &ett_atn_cpdlc_LevelsOfFlight,
    &ett_atn_cpdlc_LevelSpeed,
    &ett_atn_cpdlc_LevelSpeedSpeed,
    &ett_atn_cpdlc_LevelTime,
    &ett_atn_cpdlc_LevelType,
    &ett_atn_cpdlc_Longitude,
    &ett_atn_cpdlc_LongitudeDegreesMinutes,
    &ett_atn_cpdlc_LongitudeDegreesMinutesSeconds,
    &ett_atn_cpdlc_LongitudeReportingPoints,
    &ett_atn_cpdlc_LongitudeType,
    &ett_atn_cpdlc_Navaid,
    &ett_atn_cpdlc_PlaceBearing,
    &ett_atn_cpdlc_PlaceBearingDistance,
    &ett_atn_cpdlc_PlaceBearingPlaceBearing,
    &ett_atn_cpdlc_Position,
    &ett_atn_cpdlc_PositionDegrees,
    &ett_atn_cpdlc_PositionDistanceSpecifiedDirection,
    &ett_atn_cpdlc_PositionLevel,
    &ett_atn_cpdlc_PositionLevelLevel,
    &ett_atn_cpdlc_PositionLevelSpeed,
    &ett_atn_cpdlc_PositionPosition,
    &ett_atn_cpdlc_PositionProcedureName,
    &ett_atn_cpdlc_PositionReport,
    &ett_atn_cpdlc_PositionRouteClearanceIndex,
    &ett_atn_cpdlc_PositionSpeed,
    &ett_atn_cpdlc_PositionSpeedSpeed,
    &ett_atn_cpdlc_PositionTime,
    &ett_atn_cpdlc_PositionTimeLevel,
    &ett_atn_cpdlc_PositionTimeTime,
    &ett_atn_cpdlc_PositionUnitNameFrequency,
    &ett_atn_cpdlc_ProcedureName,
    &ett_atn_cpdlc_PublishedIdentifier,
    &ett_atn_cpdlc_RemainingFuelPersonsOnBoard,
    &ett_atn_cpdlc_ReportingPoints,
    &ett_atn_cpdlc_RouteAndLevels,
    &ett_atn_cpdlc_RouteClearance,
    &ett_atn_cpdlc_SEQUENCE_SIZE_1_128_OF_RouteInformation,
    &ett_atn_cpdlc_RouteInformation,
    &ett_atn_cpdlc_RouteInformationAdditional,
    &ett_atn_cpdlc_SEQUENCE_SIZE_1_8_OF_ATWAlongTrackWaypoint,
    &ett_atn_cpdlc_SEQUENCE_SIZE_1_4_OF_InterceptCourseFrom,
    &ett_atn_cpdlc_SEQUENCE_SIZE_1_8_OF_Holdatwaypoint,
    &ett_atn_cpdlc_SEQUENCE_SIZE_1_32_OF_WaypointSpeedLevel,
    &ett_atn_cpdlc_SEQUENCE_SIZE_1_32_OF_RTARequiredTimeArrival,
    &ett_atn_cpdlc_RTARequiredTimeArrival,
    &ett_atn_cpdlc_RTATime,
    &ett_atn_cpdlc_Runway,
    &ett_atn_cpdlc_RunwayRVR,
    &ett_atn_cpdlc_RVR,
    &ett_atn_cpdlc_Speed,
    &ett_atn_cpdlc_SpeedSpeed,
    &ett_atn_cpdlc_SpeedTime,
    &ett_atn_cpdlc_SpeedTypeSpeedTypeSpeedType,
    &ett_atn_cpdlc_SpeedTypeSpeedTypeSpeedTypeSpeed,
    &ett_atn_cpdlc_Time,
    &ett_atn_cpdlc_TimeLevel,
    &ett_atn_cpdlc_TimeDeparture,
    &ett_atn_cpdlc_TimeDistanceSpecifiedDirection,
    &ett_atn_cpdlc_TimeDistanceToFromPosition,
    &ett_atn_cpdlc_Timehhmmss,
    &ett_atn_cpdlc_TimeUnitNameFrequency,
    &ett_atn_cpdlc_TimePosition,
    &ett_atn_cpdlc_TimePositionLevel,
    &ett_atn_cpdlc_TimePositionLevelSpeed,
    &ett_atn_cpdlc_TimeSpeed,
    &ett_atn_cpdlc_TimeSpeedSpeed,
    &ett_atn_cpdlc_TimeTime,
    &ett_atn_cpdlc_TimeToFromPosition,
    &ett_atn_cpdlc_ToFromPosition,
    &ett_atn_cpdlc_UnitName,
    &ett_atn_cpdlc_UnitNameFrequency,
    &ett_atn_cpdlc_VerticalChange,
    &ett_atn_cpdlc_VerticalRate,
    &ett_atn_cpdlc_WaypointSpeedLevel,
    &ett_atn_cpdlc_Winds,
    &ett_atn_cpdlc_WindSpeed,

/*--- End of included file: packet-atn-cpdlc-ettarr.c ---*/
#line 321 "./asn1/atn-cpdlc/packet-atn-cpdlc-template.c"
        &ett_atn_cpdlc
    };

    /* register CPDLC */
    proto_atn_cpdlc = proto_register_protocol(
        ATN_CPDLC_PROTO ,
        "ATN-CPDLC",
        "atn-cpdlc");

    proto_register_field_array(
        proto_atn_cpdlc,
        hf_atn_cpdlc,
        array_length(hf_atn_cpdlc));

    proto_register_subtree_array(
        ett,
        array_length(ett));

    register_dissector(
        "atn-cpdlc",
        dissect_atn_cpdlc,
        proto_atn_cpdlc);
}

void proto_reg_handoff_atn_cpdlc(void)
{
    /* add session dissector to atn dissector list dissector list*/
    heur_dissector_add(
        "atn-ulcs",
        dissect_atn_cpdlc_heur,
        "ATN-CPDLC over ATN-ULCS",
        "atn-cpdlc-ulcs",
        proto_atn_cpdlc, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
