/* packet-bacapp.c
 * Routines for BACnet (APDU) dissection
 * Copyright 2001, Hartmut Mueller <hartmut[AT]abmlinux.org>, FH Dortmund
 * Enhanced by Steve Karg, 2005, <skarg[AT]users.sourceforge.net>, Atlanta
 * Enhanced by Herbert Lischka, 2005, <lischka[AT]kieback-peter.de>, Berlin
 * Enhanced by Felix Kraemer, 2010, <sauter-cumulus[AT]de.sauter-bc.com>,
 * 	Sauter-Cumulus GmbH, Freiburg
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald[AT]wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer,v 1.23
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/reassemble.h>
#include <epan/expert.h>
#include <epan/stats_tree.h>
#include "packet-bacapp.h"

static int bacapp_tap = -1;

/* formerly bacapp.h  contains definitions and forward declarations */

#ifndef FAULT
#define FAULT 			proto_tree_add_text(subtree, tvb, offset, tvb_length(tvb) - offset, "something is going wrong here !!"); \
	offset = tvb_length(tvb);
#endif

/* BACnet PDU Types */
#define BACAPP_TYPE_CONFIRMED_SERVICE_REQUEST 0
#define BACAPP_TYPE_UNCONFIRMED_SERVICE_REQUEST 1
#define BACAPP_TYPE_SIMPLE_ACK 2
#define BACAPP_TYPE_COMPLEX_ACK 3
#define BACAPP_TYPE_SEGMENT_ACK 4
#define BACAPP_TYPE_ERROR 5
#define BACAPP_TYPE_REJECT 6
#define BACAPP_TYPE_ABORT 7
#define MAX_BACAPP_TYPE 8

#define BACAPP_SEGMENTED_REQUEST 0x08
#define BACAPP_MORE_SEGMENTS 0x04
#define BACAPP_SEGMENTED_RESPONSE 0x02
#define BACAPP_SEGMENT_NAK 0x02
#define BACAPP_SENT_BY 0x01


/**
 * dissect_bacapp ::= CHOICE {
 *  confirmed-request-PDU       [0] BACnet-Confirmed-Request-PDU,
 *  unconfirmed-request-PDU     [1] BACnet-Unconfirmed-Request-PDU,
 *  simpleACK-PDU               [2] BACnet-SimpleACK-PDU,
 *  complexACK-PDU              [3] BACnet-ComplexACK-PDU,
 *  segmentACK-PDU              [4] BACnet-SegmentACK-PDU,
 *  error-PDU                   [5] BACnet-Error-PDU,
 *  reject-PDU                  [6] BACnet-Reject-PDU,
 *  abort-PDU                   [7] BACnet-Abort-PDU
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 **/
static void
dissect_bacapp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/**
 * ConfirmedRequest-PDU ::= SEQUENCE {
 * 	pdu-type					[0] Unsigned (0..15), -- 0 for this PDU Type
 *  segmentedMessage			[1] BOOLEAN,
 *  moreFollows					[2] BOOLEAN,
 *  segmented-response-accepted	[3] BOOLEAN,
 *  reserved					[4] Unsigned (0..3), -- must be set zero
 *  max-segments-accepted		[5] Unsigned (0..7), -- as per 20.1.2.4
 *  max-APDU-length-accepted	[5] Unsigned (0..15), -- as per 20.1.2.5
 *  invokeID					[6] Unsigned (0..255),
 *  sequence-number				[7] Unsigned (0..255) OPTIONAL, -- only if segmented msg
 *  proposed-window-size		[8] Unsigned (0..127) OPTIONAL, -- only if segmented msg
 *  service-choice				[9] BACnetConfirmedServiceChoice,
 *  service-request				[10] BACnet-Confirmed-Service-Request OPTIONAL
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fConfirmedRequestPDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @param ack - indocates whether working on request or ack
 * @param svc - output variable to return service choice
 * @param tt  - output varable to return service choice item
 * @return modified offset
 */
static guint
fStartConfirmed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint8 ack,
				gint *svc, proto_item **tt);

/**
 * Unconfirmed-Request-PDU ::= SEQUENCE {
 * 	pdu-type		[0] Unsigned (0..15), -- 1 for this PDU type
 *  reserved		[1] Unsigned (0..15), -- must be set zero
 *  service-choice	[2] BACnetUnconfirmedServiceChoice,
 *  service-request	[3] BACnetUnconfirmedServiceRequest -- Context-specific tags 0..3 are NOT used in header encoding
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fUnconfirmedRequestPDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * SimpleACK-PDU ::= SEQUENCE {
 * 	pdu-type		[0] Unsigned (0..15), -- 2 for this PDU type
 *  reserved		[1] Unsigned (0..15), -- must be set zero
 *  invokeID		[2] Unsigned (0..255),
 *  service-ACK-choice	[3] BACnetUnconfirmedServiceChoice -- Context-specific tags 0..3 are NOT used in header encoding
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fSimpleAckPDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ComplexACK-PDU ::= SEQUENCE {
 * 	pdu-type				[0] Unsigned (0..15), -- 3 for this PDU Type
 *  segmentedMessage		[1] BOOLEAN,
 *  moreFollows				[2] BOOLEAN,
 *  reserved				[3] Unsigned (0..3), -- must be set zero
 *  invokeID				[4] Unsigned (0..255),
 *  sequence-number			[5] Unsigned (0..255) OPTIONAL, -- only if segmented msg
 *  proposed-window-size	[6] Unsigned (0..127) OPTIONAL, -- only if segmented msg
 *  service-ACK-choice 		[7] BACnetConfirmedServiceChoice,
 *  service-ACK				[8] BACnet-Confirmed-Service-Request  -- Context-specific tags 0..8 are NOT used in header encoding
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fComplexAckPDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * SegmentACK-PDU ::= SEQUENCE {
 * 	pdu-type				[0] Unsigned (0..15), -- 4 for this PDU Type
 *  reserved				[1] Unsigned (0..3), -- must be set zero
 *  negative-ACK			[2] BOOLEAN,
 *  server					[3] BOOLEAN,
 *  original-invokeID		[4] Unsigned (0..255),
 *  sequence-number			[5] Unsigned (0..255),
 *  actual-window-size		[6] Unsigned (0..127)
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fSegmentAckPDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * Error-PDU ::= SEQUENCE {
 * 	pdu-type				[0] Unsigned (0..15), -- 5 for this PDU Type
 *  reserved				[1] Unsigned (0..3), -- must be set zero
 *  original-invokeID		[2] Unsigned (0..255),
 *  error-choice			[3] BACnetConfirmedServiceChoice,
 *  error					[4] BACnet-Error
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fErrorPDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * Reject-PDU ::= SEQUENCE {
 * 	pdu-type				[0] Unsigned (0..15), -- 6 for this PDU Type
 *  reserved				[1] Unsigned (0..3), -- must be set zero
 *  original-invokeID		[2] Unsigned (0..255),
 *  reject-reason			[3] BACnetRejectReason
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fRejectPDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * Abort-PDU ::= SEQUENCE {
 * 	pdu-type				[0] Unsigned (0..15), -- 7 for this PDU Type
 *  reserved				[1] Unsigned (0..3), -- must be set zero
 *  server					[2] BOOLEAN,
 *  original-invokeID		[3] Unsigned (0..255),
 *  abort-reason			[4] BACnetAbortReason
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fAbortPDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * 20.2.4, adds the label with max 64Bit unsigned Integer Value to tree
 * @param tvb
 * @param tree
 * @param offset
 * @param label
 * @return modified offset
 */
static guint
fUnsignedTag (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label);

/**
 * 20.2.5, adds the label with max 64Bit signed Integer Value to tree
 * @param tvb
 * @param tree
 * @param offset
 * @param label
 * @return modified offset
 */
static guint
fSignedTag (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label);

/**
 * 20.2.8, adds the label with Octet String to tree; if lvt == 0 then lvt = restOfFrame
 * @param tvb
 * @param tree
 * @param offset
 * @param label
 * @param lvt length of String
 * @return modified offset
 */
static guint
fOctetString (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label, guint32 lvt);

/**
 * 20.2.12, adds the label with Date Value to tree
 * @param tvb
 * @param tree
 * @param offset
 * @param label
 * @return modified offset
 */
static guint
fDate    (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label);

/**
 * 20.2.13, adds the label with Time Value to tree
 * @param tvb
 * @param tree
 * @param offset
 * @param label
 * @return modified offset
 */
static guint
fTime (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label);

/**
 * 20.2.14, adds Object Identifier to tree
 * use BIG ENDIAN: Bits 31..22 Object Type, Bits 21..0 Instance Number
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fObjectIdentifier (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnet-Confirmed-Service-Request ::= CHOICE {
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @param service_choice
 * @return offset
 */
static guint
fConfirmedServiceRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, gint service_choice);

/**
 * BACnet-Confirmed-Service-ACK ::= CHOICE {
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @param service_choice
 * @return offset
 */
static guint
fConfirmedServiceAck (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, gint service_choice);

/**
 * AcknowledgeAlarm-Request ::= SEQUENCE {
 * 	acknowledgingProcessIdentifier	[0]	Unsigned32,
 * 	eventObjectIdentifier	[1] BACnetObjectIdentifer,
 * 	eventStateAcknowledge	[2] BACnetEventState,
 * 	timeStamp	[3] BACnetTimeStamp,
 * 	acknowledgementSource	[4] Character String,
 *  timeOfAcknowledgement	[5] BACnetTimeStamp
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fAcknowledgeAlarmRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ConfirmedCOVNotification-Request ::= SEQUENCE {
 * 	subscriberProcessIdentifier	[0]	Unsigned32,
 * 	initiatingDeviceIdentifier	[1] BACnetObjectIdentifer,
 * 	monitoredObjectIdentifier	[2] BACnetObjectIdentifer,
 * 	timeRemaining	[3] unsigned,
 * 	listOfValues	[4] SEQUENCE OF BACnetPropertyValues
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fConfirmedCOVNotificationRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ConfirmedEventNotification-Request ::= SEQUENCE {
 * 	ProcessIdentifier	[0]	Unsigned32,
 * 	initiatingDeviceIdentifier	[1] BACnetObjectIdentifer,
 * 	eventObjectIdentifier	[2] BACnetObjectIdentifer,
 * 	timeStamp	[3] BACnetTimeStamp,
 * 	notificationClass	[4] unsigned,
 * 	priority	[5] unsigned8,
 * 	eventType	[6] BACnetEventType,
 * 	messageText	[7] CharacterString OPTIONAL,
 * 	notifyType	[8] BACnetNotifyType,
 * 	ackRequired	[9] BOOLEAN OPTIONAL,
 * 	fromState	[10] BACnetEventState OPTIONAL,
 * 	toState	[11] BACnetEventState,
 * 	eventValues	[12] BACnetNotificationParameters OPTIONAL
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fConfirmedEventNotificationRequest (tvbuff_t *tvb, packet_info *pinfo,  proto_tree *tree, guint offset);

/**
 * GetAlarmSummary-ACK ::= SEQUENCE OF SEQUENCE {
 * 	objectIdentifier	BACnetObjectIdentifer,
 * 	alarmState	BACnetEventState,
 * 	acknowledgedTransitions	 BACnetEventTransitionBits
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fGetAlarmSummaryAck (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * GetEnrollmentSummary-Request ::= SEQUENCE {
 * 	acknowledgmentFilter	[0]	ENUMERATED {
 *      all (0),
 *      acked   (1),
 *      not-acked   (2)
 *      },
 * 	enrollmentFilter	[1] BACnetRecipientProcess OPTIONAL,
 * 	eventStateFilter	[2] ENUMERATED {
 *      offnormal   (0),
 *      fault   (1),
 *      normal  (2),
 *      all (3),
 *      active  (4)
 *      },
 * 	eventTypeFilter	[3] BACnetEventType OPTIONAL,
 * 	priorityFilter	[4] SEQUENCE {
 *      minPriority [0] Unsigned8,
 *      maxPriority [1] Unsigned8
 *      } OPTIONAL,
 *  notificationClassFilter	[5] Unsigned OPTIONAL
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fGetEnrollmentSummaryRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * GetEnrollmentSummary-ACK ::= SEQUENCE OF SEQUENCE {
 * 	objectIdentifier	BACnetObjectIdentifer,
 * 	eventType	BACnetEventType,
 * 	eventState	BACnetEventState,
 * 	priority    Unsigned8,
 *  notificationClass   Unsigned OPTIONAL
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fGetEnrollmentSummaryAck (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * GetEventInformation-Request ::= SEQUENCE {
 * 	lastReceivedObjectIdentifier	[0] BACnetObjectIdentifer
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fGetEventInformationRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * GetEventInformation-ACK ::= SEQUENCE {
 * 	listOfEventSummaries	[0] listOfEventSummaries,
 *  moreEvents  [1] BOOLEAN
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fGetEventInformationACK (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * LifeSafetyOperation-Request ::= SEQUENCE {
 * 	requestingProcessIdentifier	[0]	Unsigned32
 * 	requestingSource	[1] CharacterString
 * 	request	[2] BACnetLifeSafetyOperation
 * 	objectIdentifier	[3] BACnetObjectIdentifier OPTIONAL
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fLifeSafetyOperationRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label);

/**
 * SubscribeCOV-Request ::= SEQUENCE {
 * 	subscriberProcessIdentifier	[0]	Unsigned32
 * 	monitoredObjectIdentifier	[1] BACnetObjectIdentifier
 * 	issueConfirmedNotifications	[2] BOOLEAN OPTIONAL
 * 	lifetime	[3] Unsigned OPTIONAL
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @param label
 * @param src
 * @return modified offset
 */
static guint
fSubscribeCOVRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * SubscribeCOVProperty-Request ::= SEQUENCE {
 * 	subscriberProcessIdentifier	[0]	Unsigned32
 * 	monitoredObjectIdentifier	[1] BACnetObjectIdentifier
 * 	issueConfirmedNotifications	[2] BOOLEAN OPTIONAL
 * 	lifetime	[3] Unsigned OPTIONAL
 * 	monitoredPropertyIdentifier	[4] BACnetPropertyReference OPTIONAL
 * 	covIncrement	[5] Unsigned OPTIONAL
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fSubscribeCOVPropertyRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * AtomicReadFile-Request ::= SEQUENCE {
 * 	fileIdentifier	BACnetObjectIdentifier,
 *  accessMethod	CHOICE {
 *  	streamAccess	[0] SEQUENCE {
 *  		fileStartPosition	INTEGER,
 * 			requestedOctetCount	Unsigned
 * 			},
 * 		recordAccess	[1] SEQUENCE {
 * 			fileStartRecord	INTEGER,
 * 			requestedRecordCount	Unsigned
 * 			}
 * 		}
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fAtomicReadFileRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * AtomicWriteFile-ACK ::= SEQUENCE {
 * 	endOfFile	BOOLEAN,
 *  accessMethod	CHOICE {
 *  	streamAccess	[0] SEQUENCE {
 *  		fileStartPosition	INTEGER,
 * 			fileData	OCTET STRING
 * 			},
 * 		recordAccess	[1] SEQUENCE {
 * 			fileStartRecord	INTEGER,
 * 			returnedRecordCount	Unsigned,
 * 			fileRecordData	SEQUENCE OF OCTET STRING
 * 			}
 * 		}
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fAtomicReadFileAck (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * AtomicWriteFile-Request ::= SEQUENCE {
 * 	fileIdentifier	BACnetObjectIdentifier,
 *  accessMethod	CHOICE {
 *  	streamAccess	[0] SEQUENCE {
 *  		fileStartPosition	INTEGER,
 * 			fileData	OCTET STRING
 * 			},
 * 		recordAccess	[1] SEQUENCE {
 * 			fileStartRecord	INTEGER,
 * 			recordCount	Unsigned,
 * 			fileRecordData	SEQUENCE OF OCTET STRING
 * 			}
 * 		}
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fAtomicWriteFileRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * AtomicWriteFile-ACK ::= SEQUENCE {
 * 		fileStartPosition	[0] INTEGER,
 * 	   	fileStartRecord	[1] INTEGER,
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fAtomicWriteFileAck (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * AddListElement-Request ::= SEQUENCE {
 * 	objectIdentifier	[0] BACnetObjectIdentifier,
 *  propertyIdentifier  [1] BACnetPropertyIdentifier,
 *  propertyArrayIndex  [2] Unsigned OPTIONAL, -- used only with array datatype
 *  listOfElements  [3] ABSTRACT-SYNTAX.&Type
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fAddListElementRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * CreateObject-Request ::= SEQUENCE {
 * 	objectSpecifier	[0] ObjectSpecifier,
 *  listOfInitialValues	[1] SEQUENCE OF BACnetPropertyValue OPTIONAL
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fCreateObjectRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, guint offset);

/**
 * CreateObject-Request ::= BACnetObjectIdentifier
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fCreateObjectAck (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * DeleteObject-Request ::= SEQUENCE {
 * 	ObjectIdentifier	BACnetObjectIdentifer
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fDeleteObjectRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ReadProperty-Request ::= SEQUENCE {
 * 	objectIdentifier	[0]	BACnetObjectIdentifier,
 * 	propertyIdentifier	[1] BACnetPropertyIdentifier,
 * 	propertyArrayIndex	[2] Unsigned OPTIONAL, -- used only with array datatype
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fReadPropertyRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ReadProperty-ACK ::= SEQUENCE {
 * 	objectIdentifier	[0]	BACnetObjectIdentifier,
 * 	propertyIdentifier	[1] BACnetPropertyIdentifier,
 * 	propertyArrayIndex	[2] Unsigned OPTIONAL, -- used only with array datatype
 * 	propertyValue	[3] ABSTRACT-SYNTAX.&Type
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fReadPropertyAck (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ReadPropertyConditional-Request ::= SEQUENCE {
 * 	objectSelectionCriteria	[0] objectSelectionCriteria,
 * 	listOfPropertyReferences	[1] SEQUENCE OF BACnetPropertyReference OPTIONAL
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fReadPropertyConditionalRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, guint offset);

/**
 * ReadPropertyConditional-ACK ::= SEQUENCE {
 * 	listOfPReadAccessResults	SEQUENCE OF ReadAccessResult OPTIONAL
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fReadPropertyConditionalAck (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ReadPropertyMultiple-Request ::= SEQUENCE {
 *  listOfReadAccessSpecs	SEQUENCE OF ReadAccessSpecification
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return offset modified
 */
static guint
fReadPropertyMultipleRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, guint offset);

/**
 * ReadPropertyMultiple-Ack ::= SEQUENCE {
 *  listOfReadAccessResults	SEQUENCE OF ReadAccessResult
 * }
 * @param tvb
 * @parma pinfo
 * @param tree
 * @param offset
 * @return offset modified
 */
static guint
fReadPropertyMultipleAck (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ReadRange-Request ::= SEQUENCE {
 * 	objectIdentifier	[0] BACnetObjectIdentifier,
 *  propertyIdentifier	[1] BACnetPropertyIdentifier,
 *  propertyArrayIndex	[2] Unsigned OPTIONAL, -- used only with array datatype
 *  	range	CHOICE {
 * 		byPosition	[3] SEQUENCE {
 * 			referencedIndex Unsigned,
 * 			count INTEGER
 * 			},
 * 		byTime	[4] SEQUENCE {
 * 			referenceTime BACnetDateTime,
 * 			count INTEGER
 * 			},
 * 		timeRange	[5] SEQUENCE {
 * 			beginningTime BACnetDateTime,
 * 			endingTime BACnetDateTime
 * 			},
 * 		} OPTIONAL
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fReadRangeRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ReadRange-ACK ::= SEQUENCE {
 * 	objectIdentifier	[0] BACnetObjectIdentifier,
 *  propertyIdentifier	[1] BACnetPropertyIdentifier,
 *  propertyArrayIndex	[2] Unsigned OPTIONAL, -- used only with array datatype
 *  resultFlags	[3] BACnetResultFlags,
 *  itemCount	[4] Unsigned,
 *  itemData	[5] SEQUENCE OF ABSTRACT-SYNTAX.&Type
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fReadRangeAck (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * RemoveListElement-Request ::= SEQUENCE {
 * 	objectIdentifier	[0]	BACnetObjectIdentifier,
 * 	propertyIdentifier	[1] BACnetPropertyIdentifier,
 * 	propertyArrayIndex	[2] Unsigned OPTIONAL, -- used only with array datatype
 * 	listOfElements	[3] ABSTRACT-SYNTAX.&Type
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fRemoveListElementRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * WriteProperty-Request ::= SEQUENCE {
 * 	objectIdentifier	[0]	BACnetObjectIdentifier,
 * 	propertyIdentifier	[1] BACnetPropertyIdentifier,
 * 	propertyArrayIndex	[2] Unsigned OPTIONAL, -- used only with array datatype
 * 	propertyValue	[3] ABSTRACT-SYNTAX.&Type
 *  priority	[4] Unsigned8 (1..16) OPTIONAL --used only when property is commandable
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fWritePropertyRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * WritePropertyMultiple-Request ::= SEQUENCE {
 * 	listOfWriteAccessSpecifications	SEQUENCE OF WriteAccessSpecification
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fWritePropertyMultipleRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * DeviceCommunicationControl-Request ::= SEQUENCE {
 * 	timeDuration	[0] Unsigned16 OPTIONAL,
 *  enable-disable	[1] ENUMERATED {
 * 		enable (0),
 * 		disable (1)
 * 		},
 *  password	[2] CharacterString (SIZE(1..20)) OPTIONAL
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fDeviceCommunicationControlRequest(tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * ConfirmedPrivateTransfer-Request ::= SEQUENCE {
 * 	vendorID	[0]	Unsigned,
 * 	serviceNumber	[1] Unsigned,
 * 	serviceParameters	[2] ABSTRACT-SYNTAX.&Type OPTIONAL
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fConfirmedPrivateTransferRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ConfirmedPrivateTransfer-ACK ::= SEQUENCE {
 * 	vendorID	[0]	Unsigned,
 * 	serviceNumber	[1] Unsigned,
 * 	resultBlock	[2] ABSTRACT-SYNTAX.&Type OPTIONAL
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fConfirmedPrivateTransferAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ConfirmedTextMessage-Request ::=  SEQUENCE {
 *  textMessageSourceDevice [0] BACnetObjectIdentifier,
 *  messageClass [1] CHOICE {
 *      numeric [0] Unsigned,
 *      character [1] CharacterString
 *      } OPTIONAL,
 *  messagePriority [2] ENUMERATED {
 *      normal (0),
 *      urgent (1)
 *      },
 *  message [3] CharacterString
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fConfirmedTextMessageRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ReinitializeDevice-Request ::= SEQUENCE {
 *  reinitializedStateOfDevice	[0] ENUMERATED {
 * 		coldstart (0),
 * 		warmstart (1),
 * 		startbackup (2),
 * 		endbackup (3),
 * 		startrestore (4),
 * 		endrestore (5),
 * 		abortrestor (6)
 * 		},
 *  password	[1] CharacterString (SIZE(1..20)) OPTIONAL
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fReinitializeDeviceRequest(tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * VTOpen-Request ::= SEQUENCE {
 *  vtClass	BACnetVTClass,
 *  localVTSessionIdentifier	Unsigned8
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fVtOpenRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * VTOpen-ACK ::= SEQUENCE {
 *  remoteVTSessionIdentifier	Unsigned8
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fVtOpenAck (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * VTClose-Request ::= SEQUENCE {
 *  listOfRemoteVTSessionIdentifiers	SEQUENCE OF Unsigned8
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fVtCloseRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * VTData-Request ::= SEQUENCE {
 *  vtSessionIdentifier	Unsigned8,
 *  vtNewData	OCTET STRING,
 *  vtDataFlag	Unsigned (0..1)
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fVtDataRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * VTData-ACK ::= SEQUENCE {
 *  allNewDataAccepted	[0] BOOLEAN,
 *  acceptedOctetCount	[1] Unsigned OPTIONAL -- present only if allNewDataAccepted = FALSE
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fVtDataAck (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * Authenticate-Request ::= SEQUENCE {
 *  pseudoRandomNumber	[0] Unsigned32,
 *  excpectedInvokeID	[1] Unsigned8 OPTIONAL,
 *  operatorName	[2] CharacterString OPTIONAL,
 *  operatorPassword	[3] CharacterString (SIZE(1..20)) OPTIONAL,
 *  startEncypheredSession	[4] BOOLEAN OPTIONAL
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fAuthenticateRequest (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * Authenticate-ACK ::= SEQUENCE {
 *  modifiedRandomNumber	Unsigned32,
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fAuthenticateAck (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * RequestKey-Request ::= SEQUENCE {
 *  requestingDeviceIdentifier	BACnetObjectIdentifier,
 *  requestingDeviceAddress	BACnetAddress,
 *  remoteDeviceIdentifier	BACnetObjectIdentifier,
 *  remoteDeviceAddress	BACnetAddress
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fRequestKeyRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * Unconfirmed-Service-Request ::= CHOICE {
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @param service_choice
 * @return modified offset
 */
static guint
fUnconfirmedServiceRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, gint service_choice);

/**
 * UnconfirmedCOVNotification-Request ::= SEQUENCE {
 * 	subscriberProcessIdentifier	[0]	Unsigned32,
 * 	initiatingDeviceIdentifier	[1] BACnetObjectIdentifer,
 * 	monitoredObjectIdentifier	[2] BACnetObjectIdentifer,
 * 	timeRemaining	[3] unsigned,
 * 	listOfValues	[4] SEQUENCE OF BACnetPropertyValues
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fUnconfirmedCOVNotificationRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * UnconfirmedEventNotification-Request ::= SEQUENCE {
 * 	ProcessIdentifier	[0]	Unsigned32,
 * 	initiatingDeviceIdentifier	[1] BACnetObjectIdentifer,
 * 	eventObjectIdentifier	[2] BACnetObjectIdentifer,
 * 	timeStamp	[3] BACnetTimeStamp,
 * 	notificationClass	[4] unsigned,
 * 	priority	[5] unsigned8,
 * 	eventType	[6] BACnetEventType,
 * 	messageText	[7] CharacterString OPTIONAL,
 * 	notifyType	[8] BACnetNotifyType,
 * 	ackRequired	[9] BOOLEAN OPTIONAL,
 * 	fromState	[10] BACnetEventState OPTIONAL,
 * 	toState	[11] BACnetEventState,
 * 	eventValues	[12] BACnetNotificationParameters OPTIONAL
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fUnconfirmedEventNotificationRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * I-Am-Request ::= SEQUENCE {
 * 	aAmDeviceIdentifier	BACnetObjectIdentifier,
 *  maxAPDULengthAccepted	Unsigned,
 * 	segmentationSupported	BACnetSegmentation,
 * 	vendorID	Unsigned
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fIAmRequest  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);


/**
 * I-Have-Request ::= SEQUENCE {
 * 	deviceIdentifier	BACnetObjectIdentifier,
 *  objectIdentifier	BACnetObjectIdentifier,
 * 	objectName	CharacterString
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fIHaveRequest  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * UnconfirmedPrivateTransfer-Request ::= SEQUENCE {
 * 	vendorID	[0]	Unsigned,
 * 	serviceNumber	[1] Unsigned,
 * 	serviceParameters	[2] ABSTRACT-SYNTAX.&Type OPTIONAL
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fUnconfirmedPrivateTransferRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * UnconfirmedTextMessage-Request ::=  SEQUENCE {
 *  textMessageSourceDevice [0] BACnetObjectIdentifier,
 *  messageClass [1] CHOICE {
 *      numeric [0] Unsigned,
 *      character [1] CharacterString
 *      } OPTIONAL,
 *  messagePriority [2] ENUMERATED {
 *      normal (0),
 *      urgent (1)
 *      },
 *  message [3] CharacterString
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fUnconfirmedTextMessageRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * TimeSynchronization-Request ::=  SEQUENCE {
 *  BACnetDateTime
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fTimeSynchronizationRequest  (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * UTCTimeSynchronization-Request ::=  SEQUENCE {
 *  BACnetDateTime
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fUTCTimeSynchronizationRequest  (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * Who-Has-Request ::=  SEQUENCE {
 *  limits SEQUENCE {
 *      deviceInstanceRangeLowLimit [0] Unsigned (0..4194303),
 *      deviceInstanceRangeHighLimit [1] Unsigned (0..4194303)
 *      } OPTIONAL,
 *  object CHOICE {
 *      objectIdentifier [2] BACnetObjectIdentifier,
 *      objectName [3] CharacterString
 *      }
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fWhoHas (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * Who-Is-Request ::= SEQUENCE {
 * 	deviceInstanceRangeLowLimit	[0] Unsigned (0..4194303) OPTIONAL, -- must be used as a pair, see 16.9,
 * 	deviceInstanceRangeHighLimit	[0] Unsigned (0..4194303) OPTIONAL, -- must be used as a pair, see 16.9,
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fWhoIsRequest  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnet-Error ::= CHOICE {
 *  addListElement          [8] ChangeList-Error,
 *  removeListElement       [9] ChangeList-Error,
 *  writePropertyMultiple   [16] WritePropertyMultiple-Error,
 *  confirmedPrivatTransfer [18] ConfirmedPrivateTransfer-Error,
 *  vtClose                 [22] VTClose-Error,
 *  readRange               [26] ObjectAccessService-Error
 *                      [default] Error
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @param service
 * @return modified offset
 */
static guint
fBACnetError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint service);

/**
 * Dissect a BACnetError in a context tag
 *
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint fContextTaggedError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ChangeList-Error ::= SEQUENCE {
 *    errorType     [0] Error,
 *    firstFailedElementNumber  [1] Unsigned
 *    }
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fChangeListError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * CreateObject-Error ::= SEQUENCE {
 *    errorType     [0] Error,
 *    firstFailedElementNumber  [1] Unsigned
 *    }
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fCreateObjectError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ConfirmedPrivateTransfer-Error ::= SEQUENCE {
 *    errorType     [0] Error,
 *    vendorID      [1] Unsigned,
 *    serviceNumber [2] Unsigned,
 *    errorParameters   [3] ABSTRACT-SYNTAX.&Type OPTIONAL
 *    }
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fConfirmedPrivateTransferError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * WritePropertyMultiple-Error ::= SEQUENCE {
 *    errorType     [0] Error,
 *    firstFailedWriteAttempt  [1] Unsigned
 *    }
 * }
 * @param tvb
 * @pram pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fWritePropertyMultipleError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * VTClose-Error ::= SEQUENCE {
 *    errorType     [0] Error,
 *    listOfVTSessionIdentifiers  [1] SEQUENCE OF Unsigned8 OPTIONAL
 *    }
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fVTCloseError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnet Application Types chapter 20.2.1
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @param label
 * @return modified offset
 */
static guint
fApplicationTypes   (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label);

/**
 * BACnetActionCommand ::= SEQUENCE {
 *  deviceIdentifier    [0] BACnetObjectIdentifier OPTIONAL,
 *  objectIdentifier    [1] BACnetObjectIdentifier,
 *  propertyIdentifier  [2] BACnetPropertyIdentifier,
 *  propertyArrayIndex  [3] Unsigned OPTIONAL, -- used only with array datatype
 *  propertyValue       [4] ABSTRACT-SYNTAX.&Type,
 *  priority            [5] Unsigned (1..16) OPTIONAL, -- used only when property is commandable
 *  postDelay           [6] Unsigned OPTIONAL,
 *  quitOnFailure       [7] BOOLEAN,
 *  writeSuccessful     [8] BOOLEAN
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @param matching tag number
 * @return modified offset
 */
static guint
fActionCommand (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint8 tag_match);

/**
 * BACnetActionList ::= SEQUENCE {
 *  action  [0] SEQUENCE of BACnetActionCommand
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fActionList (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/** BACnetAddress ::= SEQUENCE {
 *  network-number  Unsigned16, -- A value 0 indicates the local network
 *  mac-address     OCTET STRING -- A string of length 0 indicates a broadcast
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fAddress (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * BACnetAddressBinding ::= SEQUENCE {
 * 	deviceObjectID  BACnetObjectIdentifier
 * 	deviceAddress   BacnetAddress
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fAddressBinding (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetCalendaryEntry ::= CHOICE {
 * 	date        [0] Date,
 * 	dateRange   [1] BACnetDateRange,
 *  weekNDay    [2] BacnetWeekNday
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fCalendaryEntry (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * BACnetClientCOV ::= CHOICE {
 * 	real-increment  REAL,
 * 	default-increment   NULL
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fClientCOV (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);


/**
 * BACnetDailySchedule ::= SEQUENCE {
 *  day-schedule    [0] SENQUENCE OF BACnetTimeValue
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fDailySchedule (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetWeeklySchedule ::= SEQUENCE {
 *  week-schedule    SENQUENCE SIZE (7) OF BACnetDailySchedule
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fWeeklySchedule (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetDateRange ::= SEQUENCE {
 *  StartDate   Date,
 *  EndDate     Date
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fDateRange (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * BACnetDateTime ::= SEQUENCE {
 *  date   Date,
 *  time   Time
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @param label
 * @return modified offset
 */
static guint
fDateTime (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label);

/**
 * BACnetDestination ::= SEQUENCE {
 *  validDays   BACnetDaysOfWeek,
 *  fromTime    Time,
 *  toTime      Time,
 *  recipient   BACnetRecipient,
 *  processIdentifier   Unsigned32,
 *  issueConfirmedNotifications BOOLEAN,
 *  transitions BACnetEventTransitionBits
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fDestination (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetDeviceObjectPropertyReference ::= SEQUENCE {
 *  objectIdentifier    [0] BACnetObjectIdentifier,
 *  propertyIdentifier  [1] BACnetPropertyIdentifier,
 *  propertyArrayIndex  [2] Unsigend OPTIONAL,
 *  deviceIdentifier    [3] BACnetObjectIdentifier OPTIONAL
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fDeviceObjectPropertyReference (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetDeviceObjectReference ::= SEQUENCE {
 *  deviceIdentifier    [0] BACnetObjectIdentifier OPTIONAL,
 *  objectIdentifier    [1] BACnetObjectIdentifier
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fDeviceObjectReference (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

#if 0
/**
 * BACnetEventParameter ::= CHOICE {
 * 	change-of-bitstring [0] SEQUENCE {
 *   	time-delay [0] Unsigned,
 *  	bitmask [1] BIT STRING,
 *   	list-of-bitstring-values [2] SEQUENCE OF BIT STRING
 *   	},
 *  change-of-state [1] SEQUENCE {
 *   	time-delay [0] Unsigned,
 *   	list-of-values [1] SEQUENCE OF BACnetPropertyStates
 *   	},
 *   change-of-value [2] SEQUENCE {
 *   	time-delay [0] Unsigned,
 *   	cov-criteria [1] CHOICE {
 *   		bitmask [0] BIT STRING,
 *   		referenced-property-increment [1] REAL
 *			}
 *		},
 *	command-failure [3] SEQUENCE {
 *		time-delay [0] Unsigned,
 *		feedback-property-reference [1] BACnetDeviceObjectPropertyReference
 *		},
 *	floating-limit [4] SEQUENCE {
 *		time-delay [0] Unsigned,
 *		setpoint-reference [1] BACnetDeviceObjectPropertyReference,
 *		low-diff-limit [2] REAL,
 *		high-diff-limit [3] REAL,
 *		deadband [4] REAL
 *		},
 *	out-of-range [5] SEQUENCE {
 *		time-delay [0] Unsigned,
 *		low-limit [1] REAL,
 *		high-limit [2] REAL,
 *		deadband [3] REAL
 *		},
 *	buffer-ready [7] SEQUENCE {
 *		notification-threshold [0] Unsigned,
 *		previous-notification-count [1] Unsigned32
 *		}
 *	change-of-life-safety [8] SEQUENCE {
 *		time-delay [0] Unsigned,
 *		list-of-life-safety-alarm-values [1] SEQUENCE OF BACnetLifeSafetyState,
 *		list-of-alarm-values [2] SEQUENCE OF BACnetLifeSafetyState,
 *		mode-property-reference [3] BACnetDeviceObjectPropertyReference
 *		}
 *	}
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fEventParameter (tvbuff_t *tvb, proto_tree *tree, guint offset);
#endif



/**
 * BACnetLogRecord ::= SEQUENCE {
 *	timestamp [0] BACnetDateTime,
 *	logDatum [1] CHOICE {
 *		log-status [0] BACnetLogStatus,
 *		boolean-value [1] BOOLEAN,
 *		real-value [2] REAL,
 *		enum-value [3] ENUMERATED, -- Optionally limited to 32 bits
 *		unsigned-value [4] Unsigned, -- Optionally limited to 32 bits
 *		signed-value [5] INTEGER, -- Optionally limited to 32 bits
 *		bitstring-value [6] BIT STRING,-- Optionally limited to 32 bits
 *		null-value [7] NULL,
 *		failure [8] Error,
 *		time-change [9] REAL,
 *		any-value [10] ABSTRACT-SYNTAX.&Type -- Optional
 *		}
 *	statusFlags [2] BACnetStatusFlags OPTIONAL
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fLogRecord (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);


/**
 * BACnetNotificationParameters ::= CHOICE {
 * 	change-of-bitstring	[0]	SEQUENCE {
 *      referenced-bitstring    [0] BIT STRING,
 *      status-flags    [1] BACnetStatusFlags
 *      },
 *  change-of-state [1]	SEQUENCE {
 *      new-state   [0] BACnetPropertyStatus,
 *      status-flags    [1] BACnetStatusFlags
 *      },
 *  change-of-value [2]	SEQUENCE {
 *      new-value   [0] CHOICE {
 *          changed-bits   [0] BIT STRING,
 *          changed-value    [1] REAL
 *          },
 *      status-flags    [1] BACnetStatusFlags
 *      },
 *  command-failure [3]	SEQUENCE {
 *      command-value   [0] ABSTRACT-SYNTAX.&Type, -- depends on ref property
 *      status-flags    [1] BACnetStatusFlags
 *      feedback-value    [2] ABSTRACT-SYNTAX.&Type -- depends on ref property
 *      },
 *  floating-limit [4]	SEQUENCE {
 *      reference-value   [0] REAL,
 *      status-flags    [1] BACnetStatusFlags
 *      setpoint-value   [2] REAL,
 *      error-limit   [3] REAL
 *      },
 *  out-of-range [5]	SEQUENCE {
 *      exceeding-value   [0] REAL,
 *      status-flags    [1] BACnetStatusFlags
 *      deadband   [2] REAL,
 *      exceeded-limit   [0] REAL
 *      },
 *  complex-event-type  [6] SEQUENCE OF BACnetPropertyValue,
 *  buffer-ready [7]	SEQUENCE {
 *      buffer-device   [0] BACnetObjectIdentifier,
 *      buffer-object    [1] BACnetObjectIdentifier
 *      previous-notification   [2] BACnetDateTime,
 *      current-notification   [3] BACnetDateTime
 *      },
 *  change-of-life-safety [8]	SEQUENCE {
 *      new-state   [0] BACnetLifeSafetyState,
 *      new-mode    [1] BACnetLifeSafetyState
 *      status-flags   [2] BACnetStatusFlags,
 *      operation-expected   [3] BACnetLifeSafetyOperation
 *      }
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fNotificationParameters (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetObjectPropertyReference ::= SEQUENCE {
 * 	objectIdentifier	[0] BACnetObjectIdentifier,
 * 	propertyIdentifier	[1] BACnetPropertyIdentifier,
 * 	propertyArrayIndex	[2] Unsigned OPTIONAL, -- used only with array datatype
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fBACnetObjectPropertyReference (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

#if 0
/**
 * BACnetObjectPropertyValue ::= SEQUENCE {
 *		objectIdentifier [0] BACnetObjectIdentifier,
 *		propertyIdentifier [1] BACnetPropertyIdentifier,
 *		propertyArrayIndex [2] Unsigned OPTIONAL, -- used only with array datatype
 *				-- if omitted with an array the entire array is referenced
 *		value [3] ABSTRACT-SYNTAX.&Type, --any datatype appropriate for the specified property
 *		priority [4] Unsigned (1..16) OPTIONAL
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fObjectPropertyValue (tvbuff_t *tvb, proto_tree *tree, guint offset);
#endif

/**
 * BACnetPriorityArray ::= SEQUENCE SIZE (16) OF BACnetPriorityValue
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fPriorityArray (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fPropertyReference (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint8 tagoffset, guint8 list);

/**
 * BACnetPropertyReference ::= SEQUENCE {
 * 	propertyIdentifier	[0] BACnetPropertyIdentifier,
 * 	propertyArrayIndex	[1] Unsigned OPTIONAL, -- used only with array datatype
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fBACnetPropertyReference (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint8 list);

/* static guint
fBACnetObjectPropertyReference (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset); */

static guint
fLOPR (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fRestartReason (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetPropertyValue ::= SEQUENCE {
 * 		PropertyIdentifier [0] BACnetPropertyIdentifier,
 * 		propertyArrayIndex [1] Unsigned OPTIONAL, -- used only with array datatypes
 * 				-- if omitted with an array the entire array is referenced
 * 		value [2] ABSTRACT-SYNTAX.&Type, -- any datatype appropriate for the specified property
 * 		priority [3] Unsigned (1..16) OPTIONAL -- used only when property is commandable
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fBACnetPropertyValue (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fPropertyValue (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint8 tagoffset);

/**
 * BACnet Application PDUs chapter 21
 * BACnetRecipient::= CHOICE {
 * 	device	[0] BACnetObjectIdentifier
 * 	address	[1] BACnetAddress
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fRecipient (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnet Application PDUs chapter 21
 * BACnetRecipientProcess::= SEQUENCE {
 * 	recipient	[0] BACnetRecipient
 * 	processID	[1] Unsigned32
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fRecipientProcess (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fCOVSubscription (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

#if 0
/**
 * BACnetSessionKey ::= SEQUENCE {
 * 	sessionKey	OCTET STRING (SIZE(8)), -- 56 bits for key, 8 bits for checksum
 * 	peerAddress	BACnetAddress
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 * @todo check if checksum is displayed correctly
 */
static guint
fSessionKey (tvbuff_t *tvb, proto_tree *tree, guint offset);
#endif

/**
 * BACnetSpecialEvent ::= SEQUENCE {
 * 	period		CHOICE {
 * 		calendarEntry		[0] BACnetCalendarEntry,
 * 		calendarRefernce	[1] BACnetObjectIdentifier
 * 		},
 * 		listOfTimeValues	[2] SEQUENCE OF BACnetTimeValue,
 * 		eventPriority		[3] Unsigned (1..16)
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fSpecialEvent (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetTimeStamp ::= CHOICE {
 * 	time			[0] Time,
 * 	sequenceNumber	[1] Unsigned (0..65535),
 * 	dateTime		[2] BACnetDateTime
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @param label
 * @return modified offset
 */
static guint
fTimeStamp (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label);

/**
 * BACnetTimeValue ::= SEQUENCE {
 * 	time	Time,
 * 	value	ABSTRACT-SYNTAX.&Type -- any primitive datatype, complex types cannot be decoded
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fTimeValue (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

#if 0
/**
 * BACnetVTSession ::= SEQUENCE {
 * 	local-vtSessionID	Unsigned8,
 * 	remote-vtSessionID	Unsigned8,
 * 	remote-vtAddress	BACnetAddress
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fVTSession (tvbuff_t *tvb, proto_tree *tree, guint offset);
#endif

/**
 * BACnetWeekNDay ::= OCTET STRING (SIZE (3))
 * -- first octet month (1..12) January = 1, X'FF' = any month
 * -- second octet weekOfMonth where: 1 = days numbered 1-7
 * -- 2 = days numbered 8-14
 * -- 3 = days numbered 15-21
 * -- 4 = days numbered 22-28
 * -- 5 = days numbered 29-31
 * -- 6 = last 7 days of this month
 * -- X'FF' = any week of this month
 * -- third octet dayOfWeek (1..7) where 1 = Monday
 * -- 7 = Sunday
 * -- X'FF' = any day of week
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fWeekNDay (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * ReadAccessResult ::= SEQUENCE {
 * 	objectIdentifier	[0] BACnetObjectIdentifier,
 * 	listOfResults	[1] SEQUENCE OF SEQUENCE {
 * 		propertyIdentifier	[2] BACnetPropertyIdentifier,
 * 		propertyArrayIndex	[3] Unsigned OPTIONAL, -- used only with array datatype if omitted with an array the entire array is referenced
 * 		readResult	CHOICE {
 * 			propertyValue	[4] ABSTRACT-SYNTAX.&Type,
 * 			propertyAccessError	[5] Error
 * 		}
 *  } OPTIONAL
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fReadAccessResult (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ReadAccessSpecification ::= SEQUENCE {
 * 	objectIdentifier	[0] BACnetObjectIdentifier,
 * 	listOfPropertyReferences	[1] SEQUENCE OF BACnetPropertyReference
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fReadAccessSpecification (tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, guint offset);

/**
 * WriteAccessSpecification ::= SEQUENCE {
 * 	objectIdentifier	[0] BACnetObjectIdentifier,
 * 	listOfProperty	[1] SEQUENCE OF BACnetPropertyValue
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fWriteAccessSpecification (tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, guint offset);


/********************************************************* Helper functions *******************************************/

/**
 * extracts the tag number from the tag header.
 * @param tvb "TestyVirtualBuffer"
 * @param offset in actual tvb
 * @return Tag Number corresponding to BACnet 20.2.1.2 Tag Number
 */
static guint
fTagNo (tvbuff_t *tvb, guint offset);

/**
 * splits Tag Header coresponding to 20.2.1 General Rules For BACnet Tags
 * @param tvb = "TestyVirtualBuffer"
 * @param offset = offset in actual tvb
 * @return tag_no BACnet 20.2.1.2 Tag Number
 * @return class_tag BACnet 20.2.1.1 Class
 * @return lvt BACnet 20.2.1.3 Length/Value/Type
 * @return offs = length of this header
 */

static guint
fTagHeader (tvbuff_t *tvb, guint offset, guint8 *tag_no, guint8* class_tag, guint32 *lvt);


/**
 * adds processID with max 32Bit unsigned Integer Value to tree
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fProcessId (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * adds timeSpan with max 32Bit unsigned Integer Value to tree
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fTimeSpan (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label);

/**
 * BACnet Application PDUs chapter 21
 * BACnetPropertyIdentifier::= ENUMERATED {
 * 	 @see bacapp_property_identifier
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @param tt returnvalue of this item
 * @return modified offset
 */
static guint
fPropertyIdentifier (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnet Application PDUs chapter 21
 * BACnetPropertyArrayIndex::= ENUMERATED {
 * 	 @see bacapp_property_array_index
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @param tt returnvalue of this item
 * @return modified offset
 */
static guint
fPropertyArrayIndex (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * listOfEventSummaries ::= SEQUENCE OF SEQUENCE {
 * 	objectIdentifier	[0] BACnetObjectIdentifier,
 *  eventState  [1] BACnetEventState,
 *  acknowledgedTransitions [2] BACnetEventTransitionBits,
 *  eventTimeStamps [3] SEQURNCE SIZE (3) OF BACnetTimeStamps,
 *  notifyType  [4] BACnetNotifyType,
 *  eventEnable [5] BACnetEventTransitionBits,
 *  eventPriorities [6] SEQUENCE SIZE (3) OF Unsigned
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
flistOfEventSummaries (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * SelectionCriteria ::= SEQUENCE {
 * 	propertyIdentifier	[0] BACnetPropertyIdentifier,
 * 	propertyArrayIndex	[1] Unsigned OPTIONAL, -- used only with array datatype
 *  relationSpecifier	[2] ENUMERATED { bacapp_relationSpecifier },
 *  comparisonValue	[3] ABSTRACT-SYNTAX.&Type
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fSelectionCriteria (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * objectSelectionCriteria ::= SEQUENCE {
 * 	selectionLogic	[0] ENUMERATED { bacapp_selectionLogic },
 * 	listOfSelectionCriteria	[1] SelectionCriteria
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fObjectSelectionCriteria (tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, guint offset);

/**
 * BACnet-Error ::= SEQUENCE {
 *    error-class ENUMERATED {},
 *    error-code  ENUMERATED {}
 *    }
 * }
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * Generic handler for context tagged values.  Mostly for handling
 * vendor-defined properties and services.
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 * @todo beautify this ugly construct
 */
static guint
fContextTaggedValue(tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label);

/**
 * realizes some ABSTRACT-SYNTAX.&Type
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @return modified offset
 * @todo beautify this ugly construct
 */
static guint
fAbstractSyntaxNType (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);


static guint
fBitStringTagVS (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label,
	const value_string *src);

/**
 * register_bacapp
 */
void
proto_register_bacapp(void);

/**
 * proto_reg_handoff_bacapp
 */
void
proto_reg_handoff_bacapp(void);

/**
 * converts XXX coded strings to UTF-8
 * else 'in' is copied to 'out'
 * @param in  -- pointer to string
 * @param inbytesleft
 * @param out -- pointer to string
 * @param outbytesleft
 * @param fromcoding
 * @return count of modified characters of returned string, -1 for errors
 */
static guint32
fConvertXXXtoUTF8(gchar *in, gsize *inbytesleft, gchar *out, gsize *outbytesleft, const gchar *fromcoding);

static void
uni_to_string(char * data, gsize str_length, char *dest_buf);

/* <<<< formerly bacapp.h */

/* some hashes for segmented messages */
static GHashTable *msg_fragment_table = NULL;
static GHashTable *msg_reassembled_table = NULL;

/* some necessary forward function prototypes */
static guint
fApplicationTypesEnumerated (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset,
	const gchar *label, const value_string *vs);

static const char *bacapp_unknown_service_str = "unknown service";
static const char *ASHRAE_Reserved_Fmt = "(%d) Reserved for Use by ASHRAE";
static const char *Vendor_Proprietary_Fmt = "(%d) Vendor Proprietary Value";

static const value_string
BACnetTypeName[] = {
	{0, "Confirmed-REQ"},
	{1, "Unconfirmed-REQ"},
	{2, "Simple-ACK"},
	{3, "Complex-ACK"},
	{4, "Segment-ACK"},
	{5, "Error"},
	{6, "Reject"},
	{7, "Abort"},
	{0, NULL }
};

static const true_false_string segments_follow = {
	"Segmented Request",
	"Unsegmented Request"
};

static const true_false_string more_follow = {
	"More Segments Follow",
	"No More Segments Follow"
};

static const true_false_string segmented_accept = {
	"Segmented Response accepted",
	"Segmented Response not accepted"
};

static const true_false_string
BACnetTagClass = {
	"Context Specific Tag",
	"Application Tag"
};

static const value_string
BACnetMaxSegmentsAccepted [] = {
	{0,"Unspecified"},
	{1,"2 segments"},
	{2,"4 segments"},
	{3,"8 segments"},
	{4,"16 segments"},
	{5,"32 segments"},
	{6,"64 segments"},
	{7,"Greater than 64 segments"},
	{0,NULL }
};

static const value_string
BACnetMaxAPDULengthAccepted [] = {
	{0,"Up to MinimumMessageSize (50 octets)"},
	{1,"Up to 128 octets"},
	{2,"Up to 206 octets (fits in a LonTalk frame)"},
	{3,"Up to 480 octets (fits in an ARCNET frame)"},
	{4,"Up to 1024 octets"},
	{5,"Up to 1476 octets (fits in an ISO 8802-3 frame)"},
	{6,"reserved by ASHRAE"},
	{7,"reserved by ASHRAE"},
	{8,"reserved by ASHRAE"},
	{9,"reserved by ASHRAE"},
	{10,"reserved by ASHRAE"},
	{11,"reserved by ASHRAE"},
	{12,"reserved by ASHRAE"},
	{13,"reserved by ASHRAE"},
	{14,"reserved by ASHRAE"},
	{15,"reserved by ASHRAE"},
	{0,NULL}
};

static const value_string
BACnetRejectReason [] = {
	{0,"other"},
	{1,"buffer-overflow"},
	{2,"inconsistent-parameters"},
	{3,"invalid-parameter-data-type"},
	{4,"invalid-tag"},
	{5,"missing-required-parameter"},
	{6,"parameter-out-of-range"},
	{7,"too-many-arguments"},
	{8,"undefined-enumeration"},
	{9,"unrecognized-service"},
	{0,NULL}
};

static const value_string
BACnetRestartReason [] = {
	{0,"unknown"},
	{1,"coldstart"},
	{2,"warmstart"},
	{3,"detected-power-lost"},
	{4,"detected-powered-off"},
	{5,"hardware-watchdog"},
	{6,"software-watchdog"},
	{7,"suspended"},
	{0,NULL}
};

static const value_string
BACnetApplicationTagNumber [] = {
	{0,"Null"},
	{1,"Boolean"},
	{2,"Unsigned Integer"},
	{3,"Signed Integer (2's complement notation)"},
	{4,"Real (ANSI/IEE-754 floating point)"},
	{5,"Double (ANSI/IEE-754 double precision floating point)"},
	{6,"Octet String"},
	{7,"Character String"},
	{8,"Bit String"},
	{9,"Enumerated"},
	{10,"Date"},
	{11,"Time"},
	{12,"BACnetObjectIdentifier"},
	{13,"reserved by ASHRAE"},
	{14,"reserved by ASHRAE"},
	{15,"reserved by ASHRAE"},
	{0,NULL}
};

static const value_string
BACnetAction [] = {
	{0,"direct"},
	{1,"reverse"},
	{0,NULL}
};

static const value_string
BACnetFileAccessMethod [] = {
	{0,"record-access"},
	{1,"stream-access"},
	{0,NULL}
};

/* For some reason, BACnet defines the choice parameter
   in the file read and write services backwards from the
   BACnetFileAccessMethod enumeration.
*/
static const value_string
BACnetFileAccessOption [] = {
	{0,"stream access"},
	{1,"record access"},
	{0,NULL}
};

static const value_string
BACnetFileStartOption [] = {
	{0, "File Start Position: "},
	{1, "File Start Record: "},
	{0, NULL}
};

static const value_string
BACnetFileRequestCount [] = {
	{0, "Requested Octet Count: "},
	{1, "Requested Record Count: "},
	{0, NULL}
};

static const value_string
BACnetFileWriteInfo [] = {
	{0, "File Data: "},
	{1, "Record Count: "},
	{0, NULL}
};

static const value_string
BACnetAbortReason [] = {
	{0,"other"},
	{1,"buffer-overflow"},
	{2,"invalid-apdu-in-this-state"},
	{3,"preempted-by-higher-priority-task"},
	{4,"segmentation-not-supported"},
	{0,NULL}
};

static const value_string
BACnetLifeSafetyMode [] = {
	{0,"off"},
	{1,"on"},
	{2,"test"},
	{3,"manned"},
	{4,"unmanned"},
	{5,"armed"},
	{6,"disarmed"},
	{7,"prearmed"},
	{8,"slow"},
	{9,"fast"},
	{10,"disconnected"},
	{11,"enabled"},
	{12,"disabled"},
	{13,"atomic-release-disabled"},
	{14,"default"},
	{0,NULL}
/* Enumerated values 0-255 are reserved for definition by ASHRAE.
   Enumerated values 256-65535 may be used by others subject to
   procedures and constraints described in Clause 23. */
};

static const value_string
BACnetLifeSafetyOperation [] = {
	{0,"none"},
	{1,"silence"},
	{2,"silence-audible"},
	{3,"silence-visual"},
	{4,"reset"},
	{5,"reset-alarm"},
	{6,"reset-fault"},
	{7,"unsilence"},
	{8,"unsilence-audible"},
	{9,"unsilence-visual"},
	{0,NULL}
/* Enumerated values 0-63 are reserved for definition by ASHRAE.
   Enumerated values 64-65535 may be used by others subject to
   procedures and constraints described in Clause 23. */
};

static const value_string
BACnetLimitEnable [] = {
	{0,"lowLimitEnable"},
	{1,"highLimitEnable"},
	{0,NULL}
};

static const value_string
BACnetLifeSafetyState [] = {
	{0,"quiet"},
	{1,"pre-alarm"},
	{2,"alarm"},
	{3,"fault"},
	{4,"fault-pre-alarm"},
	{5,"fault-alarm"},
	{6,"not-ready"},
	{7,"active"},
	{8,"tamper"},
	{9,"test-alarm"},
	{10,"test-active"},
	{11,"test-fault"},
	{12,"test-fault-alarm"},
	{13,"holdup"},
	{14,"duress"},
	{15,"tamper-alarm"},
	{16,"abnormal"},
	{17,"emergency-power"},
	{18,"delayed"},
	{19,"blocked"},
	{20,"local-alarm"},
	{21,"general-alarm"},
	{22,"supervisory"},
	{23,"test-supervisory"},
	{0,NULL}
/* Enumerated values 0-255 are reserved for definition by ASHRAE.
   Enumerated values 256-65535 may be used by others subject to
   procedures and constraints described in Clause 23. */
};

static const value_string
BACnetConfirmedServiceChoice [] = {
	{0,"acknowledgeAlarm"},
	{1,"confirmedCOVNotification"},
	{2,"confirmedEventNotification"},
	{3,"getAlarmSummary"},
	{4,"getEnrollmentSummary"},
	{5,"subscribeCOV"},
	{6,"atomicReadFile"},
	{7,"atomicWriteFile"},
	{8,"addListElement"},
	{9,"removeListElement"},
	{10,"createObject"},
	{11,"deleteObject"},
	{12,"readProperty"},
	{13,"readPropertyConditional"},
	{14,"readPropertyMultiple"},
	{15,"writeProperty"},
	{16,"writePropertyMultiple"},
	{17,"deviceCommunicationControl"},
	{18,"confirmedPrivateTransfer"},
	{19,"confirmedTextMessage"},
	{20,"reinitializeDevice"},
	{21,"vtOpen"},
	{22,"vtClose"},
	{23,"vtData"},
	{24,"authenticate"},
	{25,"requestKey"},
	{26,"readRange"},
	{27,"lifeSafetyOperation"},
	{28,"subscribeCOVProperty"},
	{29,"getEventInformation"},
	{30,"reserved by ASHRAE"},
	{0, NULL}
};

static const value_string
BACnetReliability [] = {
	{0,"no-fault-detected"},
	{1,"no-sensor"},
	{2,"over-range"},
	{3,"under-range"},
	{4,"open-loop"},
	{5,"shorted-loop"},
	{6,"no-output"},
	{7,"unreliable-other"},
	{8,"process-error"},
	{9,"multi-state-fault"},
	{10,"configuration-error"},
	/* enumeration value 11 is reserved for a future addendum */
	{12,"communication-failure"},
	{13,"member-fault"},
	{0,NULL}
};

static const value_string
BACnetUnconfirmedServiceChoice [] = {
	{0,"i-Am"},
	{1,"i-Have"},
	{2,"unconfirmedCOVNotification"},
	{3,"unconfirmedEventNotification"},
	{4,"unconfirmedPrivateTransfer"},
	{5,"unconfirmedTextMessage"},
	{6,"timeSynchronization"},
	{7,"who-Has"},
	{8,"who-Is"},
	{9,"utcTimeSynchonization"},
	{0,NULL}
};

static const value_string
BACnetUnconfirmedServiceRequest [] = {
	{0,"i-Am-Request"},
	{1,"i-Have-Request"},
	{2,"unconfirmedCOVNotification-Request"},
	{3,"unconfirmedEventNotification-Request"},
	{4,"unconfirmedPrivateTransfer-Request"},
	{5,"unconfirmedTextMessage-Request"},
	{6,"timeSynchronization-Request"},
	{7,"who-Has-Request"},
	{8,"who-Is-Request"},
	{9,"utcTimeSynchonization-Request"},
	{0,NULL}
};

static const value_string
BACnetObjectType [] = {
	{0,"analog-input"},
	{1,"analog-output"},
	{2,"analog-value"},
	{3,"binary-input"},
	{4,"binary-output"},
	{5,"binary-value"},
	{6,"calendar"},
	{7,"command"},
	{8,"device"},
	{9,"event-enrollment"},
	{10,"file"},
	{11,"group"},
	{12,"loop"},
	{13,"multi-state-input"},
	{14,"multi-state-output"},
	{15,"notification-class"},
	{16,"program"},
	{17,"schedule"},
	{18,"averaging"},
	{19,"multi-state-value"},
	{20,"trend-log"},
	{21,"life-safety-point"},
	{22,"life-safety-zone"},
	{23,"accumulator"},
	{24,"pulse-converter"},
	{25,"event-log"},
	{26,"global-group"},
	{27,"trend-log-multiple"},
	{28,"load-control"},
	{29,"structured-view"},
	{30,"access-door"},		/* 30-37 added with addanda 135-2008j */
	/* value 31 is unassigned */
	{32,"access-credential"},
	{33,"access-point"},
	{34,"access-rights"},
	{35,"access-user"},
	{36,"access-zone"},
	{37,"credential-data-input"},
	{38,"network-security"},
	{39,"bitstring-value"},		/* 39-50 added with addenda 135-2008w */
	{40,"characterstring-value"},
	{41,"date-pattern-value"},
	{42,"date-value"},
	{43,"datetime-pattern-value"},
	{44,"datetime-value"},
	{45,"integer-value"},
	{46,"large-analog-value"},
	{47,"octetstring-value"},
	{48,"positive-integer-value"},
	{49,"time-pattern-value"},
	{50,"time-value"},
	{0, NULL}
/* Enumerated values 0-127 are reserved for definition by ASHRAE.
   Enumerated values 128-1023 may be used by others subject to
   the procedures and constraints described in Clause 23. */
};

static const value_string
BACnetEngineeringUnits [] = {
	{0,"Sq Meters"},
	{1,"Sq Feet"},
	{2,"Milliamperes"},
	{3,"Amperes"},
	{4,"Ohms"},
	{5,"Volts"},
	{6,"Kilovolts"},
	{7,"Megavolts"},
	{8,"Volt Amperes"},
	{9,"Kilovolt Amperes"},
	{10,"Megavolt Amperes"},
	{11,"Volt Amperes Reactive"},
	{12,"Kilovolt Amperes Reactive"},
	{13,"Megavolt Amperes Reactive"},
	{14,"Degrees Phase"},
	{15,"Power Factor"},
	{16,"Joules"},
	{17,"Kilojoules"},
	{18,"Watt Hours"},
	{19,"Kilowatt Hours"},
	{20,"BTUs"},
	{21,"Therms"},
	{22,"Ton Hours"},
	{23,"Joules Per Kg Dry Air"},
	{24,"BTUs Per Pound Dry Air"},
	{25,"Cycles Per Hour"},
	{26,"Cycles Per Minute"},
	{27,"Hertz"},
	{28,"Grams Of Water Per Kilogram Dry Air"},
	{29,"Relative Humidity"},
	{30,"Millimeters"},
	{31,"Meters"},
	{32,"Inches"},
	{33,"Feed"},
	{34,"Watts Per Sq Foot"},
	{35,"Watts Per Sq meter"},
	{36,"Lumens"},
	{37,"Lux"},
	{38,"Foot Candles"},
	{39,"Kilograms"},
	{40,"Pounds Mass"},
	{41,"Tons"},
	{42,"Kgs per Second"},
	{43,"Kgs Per Minute"},
	{44,"Kgs Per Hour"},
	{45,"Pounds Mass Per Minute"},
	{46,"Pounds Mass Per Hour"},
	{47,"Watt"},
	{48,"Kilowatts"},
	{49,"Megawatts"},
	{50,"BTUs Per Hour"},
	{51,"Horsepower"},
	{52,"Tons Refrigeration"},
	{53,"Pascals"},
	{54,"Kilopascals"},
	{55,"Bars"},
	{56,"Pounds Force Per Square Inch"},
	{57,"Centimeters Of Water"},
	{58,"Inches Of Water"},
	{59,"Millimeters Of Mercury"},
	{60,"Centimeters Of Mercury"},
	{61,"Inches Of Mercury"},
	{62,"Degrees Celsius"},
	{63,"Degrees Kelvin"},
	{64,"Degrees Fahrenheit"},
	{65,"Degree Days Celsius"},
	{66,"Degree Days Fahrenheit"},
	{67,"Years"},
	{68,"Months"},
	{69,"Weeks"},
	{70,"Days"},
	{71,"Hours"},
	{72,"Minutes"},
	{73,"Seconds"},
	{74,"Meters Per Second"},
	{75,"Kilometers Per Hour"},
	{76,"Feed Per Second"},
	{77,"Feet Per Minute"},
	{78,"Miles Per Hour"},
	{79,"Cubic Feet"},
	{80,"Cubic Meters"},
	{81,"Imperial Gallons"},
	{82,"Liters"},
	{83,"US Gallons"},
	{84,"Cubic Feet Per Minute"},
	{85,"Cubic Meters Per Second"},
	{86,"Imperial Gallons Per Minute"},
	{87,"Liters Per Second"},
	{88,"Liters Per Minute"},
	{89,"US Gallons Per Minute"},
	{90,"Degrees Angular"},
	{91,"Degrees Celsius Per Hour"},
	{92,"Degrees Celsius Per Minute"},
	{93,"Degrees Fahrenheit Per Hour"},
	{94,"Degrees Fahrenheit Per Minute"},
	{95,"No Units"},
	{96,"Parts Per Million"},
	{97,"Parts Per Billion"},
	{98,"Percent"},
	{99,"Pecent Per Second"},
	{100,"Per Minute"},
	{101,"Per Second"},
	{102,"Psi Per Degree Fahrenheit"},
	{103,"Radians"},
	{104,"Revolutions Per Min"},
	{105,"Currency1"},
	{106,"Currency2"},
	{107,"Currency3"},
	{108,"Currency4"},
	{109,"Currency5"},
	{110,"Currency6"},
	{111,"Currency7"},
	{112,"Currency8"},
	{113,"Currency9"},
	{114,"Currency10"},
	{115,"Sq Inches"},
	{116,"Sq Centimeters"},
	{117,"BTUs Per Pound"},
	{118,"Centimeters"},
	{119,"Pounds Mass Per Second"},
	{120,"Delta Degrees Fahrenheit"},
	{121,"Delta Degrees Kelvin"},
	{122,"Kilohms"},
	{123,"Megohms"},
	{124,"Millivolts"},
	{125,"Kilojoules Per Kg"},
	{126,"Megajoules"},
	{127,"Joules Per Degree Kelvin"},
	{128,"Joules Per Kg Degree Kelvin"},
	{129,"Kilohertz"},
	{130,"Megahertz"},
	{131,"Per Hour"},
	{132,"Milliwatts"},
	{133,"Hectopascals"},
	{134,"Millibars"},
	{135,"Cubic Meters Per Hour"},
	{136,"Liters Per Hour"},
	{137,"KWatt Hours Per Square Meter"},
	{138,"KWatt Hours Per Square Foot"},
	{139,"Megajoules Per Square Meter"},
	{140,"Megajoules Per Square Foot"},
	{141,"Watts Per Sq Meter Degree Kelvin"},
	{142,"Cubic Feet Per Second"},
	{143,"Percent Obstruction Per Foot"},
	{144,"Percent Obstruction Per Meter"},
	{145,"milliohms"},
	{146,"megawatt-hours"},
	{147,"kilo-btus"},
	{148,"mega-btus"},
	{149,"kilojoules-per-kilogram-dry-air"},
	{150,"megajoules-per-kilogram-dry-air"},
	{151,"kilojoules-per-degree-Kelvin"},
	{152,"megajoules-per-degree-Kelvin"},
	{153,"newton"},
	{154,"grams-per-second"},
	{155,"grams-per-minute"},
	{156,"tons-per-hour"},
	{157,"kilo-btus-per-hour"},
	{158,"hundredths-seconds"},
	{159,"milliseconds"},
	{160,"newton-meters"},
	{161,"millimeters-per-second"},
	{162,"millimeters-per-minute"},
	{163,"meters-per-minute"},
	{164,"meters-per-hour"},
	{165,"cubic-meters-per-minute"},
	{166,"meters-per-second-per-second"},
	{167,"amperes-per-meter"},
	{168,"amperes-per-square-meter"},
	{169,"ampere-square-meters"},
	{170,"farads"},
	{171,"henrys"},
	{172,"ohm-meters"},
	{173,"siemens"},
	{174,"siemens-per-meter"},
	{175,"teslas"},
	{176,"volts-per-degree-Kelvin"},
	{177,"volts-per-meter"},
	{178,"webers"},
	{179,"candelas"},
	{180,"candelas-per-square-meter"},
	{181,"degrees-Kelvin-per-hour"},
	{182,"degrees-Kelvin-per-minute"},
	{183,"joule-seconds"},
	{184,"radians-per-second"},
	{185,"square-meters-per-Newton"},
	{186,"kilograms-per-cubic-meter"},
	{187,"newton-seconds"},
	{188,"newtons-per-meter"},
	{189,"watts-per-meter-per-degree-Kelvin"},
	{190,"micro-siemens"},
	{191,"cubic-feet-per-hour"},
	{192,"us-gallons-per-hour"},
	{193,"kilometers"},
	{194,"micrometers"},
	{195,"grams"},
	{196,"milligrams"},
	{197,"milliliters"},
	{198,"milliliters-per-second"},
	{199,"decibels"},
	{200,"decibels-millivolt"},
	{201,"decibels-volt"},
	{202,"millisiemens"},
	{203,"watt-hours-reactive"},
	{204,"kilowatt-hours-reactive"},
	{205,"megawatt-hours-reactive"},
	{206,"millimeters-of-water"},
	{207,"per-mille"},
	{208,"grams-per-gram"},
	{209,"kilograms-per-kilogram"},
	{210,"grams-per-kilogram"},
	{211,"milligrams-per-gram"},
	{212,"milligrams-per-kilogram"},
	{213,"grams-per-milliliter"},
	{214,"grams-per-liter"},
	{215,"milligrams-per-liter"},
	{216,"micrograms-per-liter"},
	{217,"grams-per-cubic-meter"},
	{218,"milligrams-per-cubic-meter"},
	{219,"micrograms-per-cubic-meter"},
	{220,"nanograms-per-cubic-meter"},
	{221,"grams-per-cubic-centimeter"},
	{222,"becquerels"},
	{223,"kilobecquerels"},
	{224,"megabecquerels"},
	{225,"gray"},
	{226,"milligray"},
	{227,"microgray"},
	{228,"sieverts"},
	{229,"millisieverts"},
	{230,"microsieverts"},
	{231,"microsieverts-per-hour"},
	{232,"decibels-a"},
	{233,"nephelometric-turbidity-unit"},
	{234,"pH"},
	{235,"grams-per-square-meter"},
	{236,"minutes-per-degree-kelvin"},
	{0,NULL}
/* Enumerated values 0-255 are reserved for definition by ASHRAE.
   Enumerated values 256-65535 may be used by others subject to
   the procedures and constraints described in Clause 23. */
};

static const value_string
BACnetErrorCode [] = {
	{0,"other"},
	{1,"authentication-failed"},
	{2,"configuration-in-progress"},
	{3,"device-busy"},
	{4,"dynamic-creation-not-supported"},
	{5,"file-access-denied"},
	{6,"incompatible-security-levels"},
	{7,"inconsistent-parameters"},
	{8,"inconsistent-selection-criterion"},
	{9,"invalid-data-type"},
	{10,"invalid-file-access-method"},
	{11,"invalid-file-start-position"},
	{12,"invalid-operator-name"},
	{13,"invalid-parameter-data-type"},
	{14,"invalid-time-stamp"},
	{15,"key-generation-error"},
	{16,"missing-required-parameter"},
	{17,"no-objects-of-specified-type"},
	{18,"no-space-for-object"},
	{19,"no-space-to-add-list-element"},
	{20,"no-space-to-write-property"},
	{21,"no-vt-sessions-available"},
	{22,"property-is-not-a-list"},
	{23,"object-deletion-not-permitted"},
	{24,"object-identifier-already-exists"},
	{25,"operational-problem"},
	{26,"password-failure"},
	{27,"read-access-denied"},
	{28,"security-not-supported"},
	{29,"service-request-denied"},
	{30,"timeout"},
	{31,"unknown-object"},
	{32,"unknown-property"},
	{33,"removed enumeration"},
	{34,"unknown-vt-class"},
	{35,"unknown-vt-session"},
	{36,"unsupported-object-type"},
	{37,"value-out-of-range"},
	{38,"vt-session-already-closed"},
	{39,"vt-session-termination-failure"},
	{40,"write-access-denied"},
	{41,"character-set-not-supported"},
	{42,"invalid-array-index"},
	{43,"cov-subscription-failed"},
	{44,"not-cov-property"},
	{45,"optional-functionality-not-supported"},
	{46,"invalid-configuration-data"},
	{47,"datatype-not-supported"},
	{48,"duplicate-name"},
	{49,"duplicate-object-id"},
	{50,"property-is-not-an-array"},
	{73,"invalid-event-state"},
	{74,"no-alarm-configured"},
	{75,"log-buffer-full"},
	{76,"logged-value-purged"},
	{77,"no-property-specified"},
	{78,"not-configured-for-triggered-logging"},
	{79,"unknown-subscription"},
	{80,"parameter-out-of-range"},
	{81,"list-element-not-found"},
	{82,"busy"},
	{83,"communication-disabled"},
	{84,"success"},
	{85,"access-denied"},
	{86,"bad-destination-address"},
	{87,"bad-destination-device-id"},
	{88,"bad-signature"},
	{89,"bad-source-address"},
	{90,"bad-timestamp"},
	{91,"cannot-use-key"},
	{92,"cannot-verify-message-id"},
	{93,"correct-key-revision"},
	{94,"destination-device-id-required"},
	{95,"duplicate-message"},
	{96,"encryption-not-configured"},
	{97,"encryption-required"},
	{98,"incorrect-key"},
	{99,"invalid-key-data"},
	{100,"key-update-in-progress"},
	{101,"malformed-message"},
	{102,"not-key-server"},
	{103,"security-not-configured"},
	{104,"source-security-required"},
	{105,"too-many-keys"},
	{106,"unknown-authentication-type"},
	{107,"unknown-key"},
	{108,"unknown-key-revision"},
	{109,"unknown-source-message"},
	{110,"not-router-to-dnet"},
	{111,"router-busy"},
	{112,"unknown-network-message"},
	{113,"message-too-long"},
	{114,"security-error"},
	{115,"addressing-error"},
	{116,"write-bdt-failed"},
	{117,"read-bdt-failed"},
	{118,"register-foreign-device-failed"},
	{119,"read-fdt-failed"},
	{120,"delete-fdt-entry-failed"},
	{121,"distribute-broadcast-failed"},
	{122,"unknown-file-size"},
	{123,"abort-apdu-too-long"},
	{124,"abort-application-exceeded-reply-time"},
	{125,"abort-out-of-resources"},
	{126,"abort-tsm-timeout"},
	{127,"abort-window-size-out-of-range"},
	{128,"file-full"},
	{129,"inconsistent-configuration"},
	{130,"inconsistent-object-type"},
	{131,"internal-error"},
	{132,"not-configured"},
	{133,"out-of-memory"},
	{134,"value-too-long"},
	{135,"abort-insufficient-security"},
	{136,"abort-security-error"},
	{0, NULL}
/* Enumerated values 0-255 are reserved for definition by ASHRAE.
   Enumerated values 256-65535 may be used by others subject to the
   procedures and constraints described in Clause 23. */
};

static const value_string
BACnetPropertyIdentifier [] = {
	{0,"acked-transition"},
	{1,"ack-required"},
	{2,"action"},
	{3,"action-text"},
	{4,"active-text"},
	{5,"active-vt-session"},
	{6,"alarm-value"},
	{7,"alarm-values"},
	{8,"all"},
	{9,"all-write-successful"},
	{10,"apdu-segment-timeout"},
	{11,"apdu-timeout"},
	{12,"application-software-version"},
	{13,"archive"},
	{14,"bias"},
	{15,"change-of-state-count"},
	{16,"change-of-state-time"},
	{17,"notification-class"},
	{18,"the property in this place was deleted"},
	{19,"controlled-variable-reference"},
	{20,"controlled-variable-units"},
	{21,"controlled-variable-value"},
	{22,"cov-increment"},
	{23,"datelist"},
	{24,"daylights-savings-status"},
	{25,"deadband"},
	{26,"derivative-constant"},
	{27,"derivative-constant-units"},
	{28,"description"},
	{29,"description-of-halt"},
	{30,"device-address-binding"},
	{31,"device-type"},
	{32,"effective-period"},
	{33,"elapsed-active-time"},
	{34,"error-limit"},
	{35,"event-enable"},
	{36,"event-state"},
	{37,"event-type"},
	{38,"exception-schedule"},
	{39,"fault-values"},
	{40,"feedback-value"},
	{41,"file-access-method"},
	{42,"file-size"},
	{43,"file-type"},
	{44,"firmware-revision"},
	{45,"high-limit"},
	{46,"inactive-text"},
	{47,"in-progress"},
	{48,"instance-of"},
	{49,"integral-constant"},
	{50,"integral-constant-units"},
	{51,"issue-confirmed-notifications"},
	{52,"limit-enable"},
	{53,"list-of-group-members"},
	{54,"list-of-object-property-references"},
	{55,"list-of-session-keys"},
	{56,"local-date"},
	{57,"local-time"},
	{58,"location"},
	{59,"low-limit"},
	{60,"manipulated-variable-reference"},
	{61,"maximum-output"},
	{62,"max-apdu-length-accepted"},
	{63,"max-info-frames"},
	{64,"max-master"},
	{65,"max-pres-value"},
	{66,"minimum-off-time"},
	{67,"minimum-on-time"},
	{68,"minimum-output"},
	{69,"min-pres-value"},
	{70,"model-name"},
	{71,"modification-date"},
	{72,"notify-type"},
	{73,"number-of-APDU-retries"},
	{74,"number-of-states"},
	{75,"object-identifier"},
	{76,"object-list"},
	{77,"object-name"},
	{78,"object-property-reference"},
	{79,"object-type"},
	{80,"optional"},
	{81,"out-of-service"},
	{82,"output-units"},
	{83,"event-parameters"},
	{84,"polarity"},
	{85,"present-value"},
	{86,"priority"},
	{87,"priority-array"},
	{88,"priority-for-writing"},
	{89,"process-identifier"},
	{90,"program-change"},
	{91,"program-location"},
	{92,"program-state"},
	{93,"proportional-constant"},
	{94,"proportional-constant-units"},
	{95,"protocol-conformance-class"},
	{96,"protocol-object-types-supported"},
	{97,"protocol-services-supported"},
	{98,"protocol-version"},
	{99,"read-only"},
	{100,"reason-for-halt"},
	{101,"recipient"},
	{102,"recipient-list"},
	{103,"reliability"},
	{104,"relinquish-default"},
	{105,"required"},
	{106,"resolution"},
	{107,"segmentation-supported"},
	{108,"setpoint"},
	{109,"setpoint-reference"},
	{110,"state-text"},
	{111,"status-flags"},
	{112,"system-status"},
	{113,"time-delay"},
	{114,"time-of-active-time-reset"},
	{115,"time-of-state-count-reset"},
	{116,"time-synchronization-recipients"},
	{117,"units"},
	{118,"update-interval"},
	{119,"utc-offset"},
	{120,"vendor-identifier"},
	{121,"vendor-name"},
	{122,"vt-class-supported"},
	{123,"weekly-schedule"},
	{124,"attempted-samples"},
	{125,"average-value"},
	{126,"buffer-size"},
	{127,"client-cov-increment"},
	{128,"cov-resubscription-interval"},
	{129,"current-notify-time"},
	{130,"event-time-stamp"},
	{131,"log-buffer"},
	{132,"log-device-object-property"},
	{133,"enable"}, /* per ANSI/ASHRAE 135-2004 addendum B */
	{134,"log-interval"},
	{135,"maximum-value"},
	{136,"minimum-value"},
	{137,"notification-threshold"},
	{138,"previous-notify-time"},
	{139,"protocol-revision"},
	{140,"records-since-notification"},
	{141,"record-count"},
	{142,"start-time"},
	{143,"stop-time"},
	{144,"stop-when-full"},
	{145,"total-record-count"},
	{146,"valid-samples"},
	{147,"window-interval"},
	{148,"window-samples"},
	{149,"maximum-value-time-stamp"},
	{150,"minimum-value-time-stamp"},
	{151,"variance-value"},
	{152,"active-cov-subscriptions"},
	{153,"backup-failure-timeout"},
	{154,"configuration-files"},
	{155,"database-revision"},
	{156,"direct-reading"},
	{157,"last-restore-time"},
	{158,"maintenance-required"},
	{159,"member-of"},
	{160,"mode"},
	{161,"operation-expected"},
	{162,"setting"},
	{163,"silenced"},
	{164,"tracking-value"},
	{165,"zone-members"},
	{166,"life-safety-alarm-values"},
	{167,"max-segments-accepted"},
	{168,"profile-name"},
	{169,"auto-slave-discovery"},
	{170,"manual-slave-address-binding"},
	{171,"slave-address-binding"},
	{172,"slave-proxy-enable"},
	{173,"last-notify-record"},		/* bug 4117 */
	{174,"schedule-default"},
	{175,"accepted-modes"},
	{176,"adjust-value"},
	{177,"count"},
	{178,"count-before-change"},
	{179,"count-change-time"},
	{180,"cov-period"},
	{181,"input-reference"},
	{182,"limit-monitoring-interval"},
	{183,"logging-device"},
	{184,"logging-record"},
	{185,"prescale"},
	{186,"pulse-rate"},
	{187,"scale"},
	{188,"scale-factor"},
	{189,"update-time"},
	{190,"value-before-change"},
	{191,"value-set"},
	{192,"value-change-time"},
	{193,"align-intervals"},
	{194,"group-member-names"},
	{195,"interval-offset"},
	{196,"last-restart-reason"},
	{197,"logging-type"},
	{198,"member-status-flags"},
	{199,"notification-period"},
	{200,"previous-notify-record"},
	{201,"requested-update-interval"},
	{202,"restart-notification-recipients"},
	{203,"time-of-device-restart"},
	{204,"time-synchronization-recipients"},
	{205,"trigger"},
	{206,"UTC-time-synchronization-recipients"},
	{207,"node-subtype"},
	{208,"node-type"},
	{209,"structured-object-list"},
	{210,"subordinate-annotations"},
	{211,"subordinate-list"},
	{212,"actual-shed-level"},
	{213,"duty-window"},
	{214,"expected-shed-level"},
	{215,"full-duty-baseline"},
	{216,"node-subtype"},
	{217,"node-type"},
	{218,"requested-shed-level"},
	{219,"shed-duration"},
	{220,"shed-level-descriptions"},
	{221,"shed-levels"},
	{222,"state-description"},
	/* enumeration values 223-225 are unassigned */
	{226,"door-alarm-state"},
	{227,"door-extended-pulse-time"},
	{228,"door-members"},
	{229,"door-open-too-long-time"},
	{230,"door-pulse-time"},
	{231,"door-status"},
	{232,"door-unlock-delay-time"},
	{233,"lock-status"},
	{234,"masked-alarm-values"},
	{235,"secured-status"},
	/* enumeration values 236-243 are unassigned */
	{244,"absentee-limit"},		/* added with addenda 135-2008j */
	{245,"access-alarm-events"},
	{246,"access-doors"},
	{247,"access-event"},
	{248,"access-event-authentication-factor"},
	{249,"access-event-credential"},
	{250,"access-event-time"},
	{251,"access-transaction-events"},
	{252,"accompaniment"},
	{253,"accompaniment-time"},
	{254,"activation-time"},
	{255,"active-authentication-policy"},
	{256,"assigned-access-rights"},
	{257,"authentication-factors"},
	{258,"authentication-policy-list"},
	{259,"authentication-policy-names"},
	{260,"authentication-status"},
	{261,"authorization-mode"},
	{262,"belongs-to"},
	{263,"credential-disable"},
	{264,"credential-status"},
	{265,"credentials"},
	{266,"credentials-in-zone"},
	{267,"days-remaining"},
	{268,"entry-points"},
	{269,"exit-points"},
	{270,"expiry-time"},
	{271,"extended-time-enable"},
	{272,"failed-attempt-events"},
	{273,"failed-attempts"},
	{274,"failed-attempts-time"},
	{275,"last-access-event"},
	{276,"last-access-point"},
	{277,"last-credential-added"},
	{278,"last-credential-added-time"},
	{279,"last-credential-removed"},
	{280,"last-credential-removed-time"},
	{281,"last-use-time"},
	{282,"lockout"},
	{283,"lockout-relinquish-time"},
	{284,"master-exemption"},
	{285,"max-failed-attempts"},
	{286,"members"},
	{287,"muster-point"},
	{288,"negative-access-rules"},
	{289,"number-of-authentication-policies"},
	{290,"occupancy-count"},
	{291,"occupancy-count-adjust"},
	{292,"occupancy-count-enable"},
	{293,"occupancy-exemption"},
	{294,"occupancy-lower-limit"},
	{295,"occupancy-lower-limit-enforced"},
	{296,"occupancy-state"},
	{297,"occupancy-upper-limit"},
	{298,"occupancy-upper-limit-enforced"},
	{299,"passback-exemption"},
	{300,"passback-mode"},
	{301,"passback-timeout"},
	{302,"positive-access-rules"},
	{303,"reason-for-disable"},
	{304,"supported-formats"},
	{305,"supported-format-classes"},
	{306,"threat-authority"},
	{307,"threat-level"},
	{308,"trace-flag"},
	{309,"transaction-notification-class"},
	{310,"user-external-identifier"},
	{311,"user-information-reference"},
	/* enumeration values 312-316 are unassigned */
	{317,"user-name"},
	{318,"user-type"},
	{319,"uses-remaining"},
	{320,"zone-from"},
	{321,"zone-to"},
	{322,"access-event-tag"},
	{323,"global-identifier"},
	/* enumeration values 324-325 reserved for future addenda */
	{326,"verification-time"},
	{327,"base-device-security-policy"},
	{328,"distribution-key-revision"},
	{329,"do-not-hide"},
	{330,"key-sets"},
	{331,"last-key-server"},
	{332,"network-access-security-policies"},
	{333,"packet-reorder-time"},
	{334,"security-pdu-timeout"},
	{335,"security-time-window"},
	{336,"supported-security-algorithms"},
	{337,"update-key-set-timeout"},
	{338,"backup-and-restore-state"},
	{339,"backup-preparation-time"},
	{340,"restore-completion-time"},
	{341,"restore-preparation-time"},
	{342,"bit-mask"},		/* addenda 135-2008w */
	{343,"bit-text"},
	{344,"is-utc"},
	{345,"group-members"},
	{346,"group-member-names"},
	{347,"member-status-flags"},
	{348,"requested-update-interval"},
	{349,"covu-period"},
	{350,"covu-recipients"},
	{351,"event-message-texts"},
	{0, NULL}
/* Enumerated values 0-511 are reserved for definition by ASHRAE.
   Enumerated values 512-4194303 may be used by others subject to
   the procedures and constraints described in Clause 23. */
};

static const value_string
BACnetBinaryPV [] = {
	{0,"inactive"},
	{1,"active"},
	{0,NULL}
};


#define ANSI_X34 0
#define IBM_MS_DBCS 1
#define JIS_C_6226 2
#define ISO_10646_UCS4 3
#define ISO_10646_UCS2 4
#define ISO_18859_1 5
static const value_string
BACnetCharacterSet [] = {
	{ANSI_X34,	"ANSI X3.4 / UTF-8 (since 2010)"},
	{IBM_MS_DBCS,	"IBM/Microsoft DBCS"},
	{JIS_C_6226,	"JIS C 6226"},
	{ISO_10646_UCS4, "ISO 10646(UCS-4)"},
	{ISO_10646_UCS2, "ISO 10646(UCS-2)"},
	{ISO_18859_1,	"ISO 18859-1"},
	{0,		NULL}
};

static const value_string
BACnetStatusFlags [] = {
	{0,"in-alarm"},
	{1,"fault"},
	{2,"overridden"},
	{3,"out-of-service"},
	{0,NULL}
};

static const value_string
BACnetMessagePriority [] = {
	{0,"normal"},
	{1,"urgent"},
	{0,NULL}
};

static const value_string
BACnetAcknowledgementFilter [] = {
	{0,"all"},
	{1,"acked"},
	{2,"not-acked"},
	{0,NULL}
};

static const value_string
BACnetResultFlags [] = {
	{0,"firstitem"},
	{1,"lastitem"},
	{2,"moreitems"},
	{0,NULL}
};

static const value_string
BACnetRelationSpecifier [] = {
	{0,"equal"},
	{1,"not-equal"},
	{2,"less-than"},
	{3,"greater-than"},
	{4,"less-than-or-equal"},
	{5,"greater-than-or-equal"},
	{0,NULL}
};

static const value_string
BACnetSelectionLogic [] = {
	{0,"and"},
	{1,"or"},
	{2,"all"},
	{0,NULL}
};

static const value_string
BACnetEventStateFilter [] = {
	{0,"offnormal"},
	{1,"fault"},
	{2,"normal"},
	{3,"all"},
	{4,"active"},
	{0,NULL}
};

static const value_string
BACnetEventTransitionBits [] = {
	{0,"to-offnormal"},
	{1,"to-fault"},
	{2,"to-normal"},
	{0,NULL}
};

static const value_string
BACnetSegmentation [] = {
	{0,"segmented-both"},
	{1,"segmented-transmit"},
	{2,"segmented-receive"},
	{3,"no-segmentation"},
	{0,NULL}
};

static const value_string
BACnetSilencedState [] = {
	{0,"unsilenced"},
	{1,"audible-silenced"},
	{2,"visible-silenced"},
	{3,"all-silenced"},
	{0,NULL}
};

static const value_string
BACnetDeviceStatus [] = {
	{0,"operational"},
	{1,"operational-read-only"},
	{2,"download-required"},
	{3,"download-in-progress"},
	{4,"non-operational"},
	{5,"backup-in-progress"},
	{0,NULL}
};

static const value_string
BACnetEnableDisable [] = {
	{0,"enable"},
	{1,"disable"},
	{2,"disable-initiation"},
	{0,NULL}
};

static const value_string
months [] = {
	{1,"January" },
	{2,"February" },
	{3,"March" },
	{4,"April" },
	{5,"May" },
	{6,"June" },
	{7,"July" },
	{8,"August" },
	{9,"September" },
	{10,"October" },
	{11,"November" },
	{12,"December" },
	{255,"any month" },
	{0,NULL }
};

static const value_string
weekofmonth [] = {
	{1,"days numbered 1-7" },
	{2,"days numbered 8-14" },
	{3,"days numbered 15-21" },
	{4,"days numbered 22-28" },
	{5,"days numbered 29-31" },
	{6,"last 7 days of this month" },
	{255,"any week of this month" },
	{0,NULL }
};

/* note: notification class object recipient-list uses
   different day-of-week enum */
static const value_string
day_of_week [] = {
	{1,"Monday" },
	{2,"Tuesday" },
	{3,"Wednesday" },
	{4,"Thursday" },
	{5,"Friday" },
	{6,"Saturday" },
	{7,"Sunday" },
	{255,"any day of week" },
	{0,NULL }
};

static const value_string
BACnetErrorClass [] = {
	{0,"device" },
	{1,"object" },
	{2,"property" },
	{3,"resources" },
	{4,"security" },
	{5,"services" },
	{6,"vt" },
	{0,NULL }
/* Enumerated values 0-63 are reserved for definition by ASHRAE.
   Enumerated values64-65535 may be used by others subject to
   the procedures and constraints described in Clause 23. */
};

static const value_string
BACnetVTClass [] = {
	{0,"default-terminal" },
	{1,"ansi-x3-64" },
	{2,"dec-vt52" },
	{3,"dec-vt100" },
	{4,"dec-vt200" },
	{5,"hp-700-94" },
	{6,"ibm-3130" },
	{0,NULL }
};

static const value_string
BACnetEventType [] = {
	{0,"change-of-bitstring" },
	{1,"change-of-state" },
	{2,"change-of-value" },
	{3,"command-failure" },
	{4,"floating-limit" },
	{5,"out-of-range" },
	{6,"complex-event-type" },
	{7,"buffer-ready" },
	{8,"change-of-life-safety" },
	{9,"extended" },
	{10,"buffer-ready" },
	{11,"unsigned-range" },
	{14,"double-out-of-range"},		/* added with addenda 135-2008w */
	{15,"signed-out-of-range"},
	{16,"unsigned-out-of-range"},
	{17,"change-of-characterstring"},
	{18,"change-of-status-flags"},
	{0,NULL }
/* Enumerated values 0-63 are reserved for definition by ASHRAE.
   Enumerated values 64-65535 may be used by others subject to
   the procedures and constraints described in Clause 23.
   It is expected that these enumerated values will correspond
   to the use of the complex-event-type CHOICE [6] of the
   BACnetNotificationParameters production. */
};

static const value_string
BACnetEventState [] = {
	{0,"normal" },
	{1,"fault" },
	{2,"offnormal" },
	{3,"high-limit" },
	{4,"low-limit" },
	{5,"life-safety-alarm" },
	{0,NULL }
/* Enumerated values 0-63 are reserved for definition by ASHRAE.
   Enumerated values 64-65535 may be used by others subject to
   the procedures and constraints described in Clause 23.  */
};

static const value_string
BACnetLogStatus [] = {
	{0,"log-disabled" },
	{1,"buffer-purged" },
	{0,NULL }
};

static const value_string
BACnetMaintenance [] = {
	{0,"none" },
	{1,"periodic-test" },
	{2,"need-service-operational" },
	{3,"need-service-inoperative" },
	{0,NULL }
};

static const value_string
BACnetNotifyType [] = {
	{0,"alarm" },
	{1,"event" },
	{2,"ack-notification" },
	{0,NULL }
};

static const value_string
BACnetServicesSupported [] = {
	{0,"acknowledgeAlarm"},
	{1,"confirmedCOVNotification"},
	{2,"confirmedEventNotification"},
	{3,"getAlarmSummary"},
	{4,"getEnrollmentSummary"},
	{5,"subscribeCOV"},
	{6,"atomicReadFile"},
	{7,"atomicWriteFile"},
	{8,"addListElement"},
	{9,"removeListElement"},
	{10,"createObject"},
	{11,"deleteObject"},
	{12,"readProperty"},
	{13,"readPropertyConditional"},
	{14,"readPropertyMultiple"},
	{15,"writeProperty"},
	{16,"writePropertyMultiple"},
	{17,"deviceCommunicationControl"},
	{18,"confirmedPrivateTransfer"},
	{19,"confirmedTextMessage"},
	{20,"reinitializeDevice"},
	{21,"vtOpen"},
	{22,"vtClose"},
	{23,"vtData"},
	{24,"authenticate"},
	{25,"requestKey"},
	{26,"i-Am"},
	{27,"i-Have"},
	{28,"unconfirmedCOVNotification"},
	{29,"unconfirmedEventNotification"},
	{30,"unconfirmedPrivateTransfer"},
	{31,"unconfirmedTextMessage"},
	{32,"timeSynchronization"},
	{33,"who-Has"},
	{34,"who-Is"},
	{35,"readRange"},
	{36,"utcTimeSynchronization"},
	{37,"lifeSafetyOperation"},
	{38,"subscribeCOVProperty"},
	{39,"getEventInformation"},
	{0, NULL}
};

static const value_string
BACnetPropertyStates [] = {
	{0,"boolean-value"},
	{1,"binary-value"},
	{2,"event-type"},
	{3,"polarity"},
	{4,"program-change"},
	{5,"program-state"},
	{6,"reason-for-halt"},
	{7,"reliability"},
	{8,"state"},
	{9,"system-status"},
	{10,"units"},
	{11,"unsigned-value"},
	{12,"life-safety-mode"},
	{13,"life-safety-state"},
	{14,"restart-reason"},
	{15,"door-alarm-state"},
	{16,"action"},
	{17,"door-secured-status"},
	{18,"door-status"},
	{19,"door-value"},
	{20,"file-access-method"},
	{21,"lock-status"},
	{22,"life-safety-operation"},
	{23,"maintenance"},
	{24,"node-type"},
	{25,"notify-type"},
	{26,"security-level"},
	{27,"shed-state"},
	{28,"silenced-state"},
	/* context tag 29 reserved for future addenda */
	{30,"access-event"},
	{31,"zone-occupancy-state"},
	{32,"access-credential-disable-reason"},
	{33,"access-credential-disable"},
	{34,"authentication-status"},
	{36,"backup-state"},
	{0,NULL}
/* Tag values 0-63 are reserved for definition by ASHRAE.
   Tag values of 64-254 may be used by others to accommodate
   vendor specific properties that have discrete or enumerated values,
   subject to the constraints described in Clause 23. */
};

static const value_string
BACnetProgramError [] = {
	{0,"normal"},
	{1,"load-failed"},
	{2,"internal"},
	{3,"program"},
	{4,"other"},
	{0,NULL}
/* Enumerated values 0-63 are reserved for definition by ASHRAE.
   Enumerated values 64-65535 may be used by others subject to
   the procedures and constraints described in Clause 23. */
};

static const value_string
BACnetProgramRequest [] = {
	{0,"ready"},
	{1,"load"},
	{2,"run"},
	{3,"halt"},
	{4,"restart"},
	{4,"unload"},
	{0,NULL}
};

static const value_string
BACnetProgramState [] = {
	{0,"idle"},
	{1,"loading"},
	{2,"running"},
	{3,"waiting"},
	{4,"halted"},
	{4,"unloading"},
	{0,NULL}
};

static const value_string
BACnetReinitializedStateOfDevice [] = {
	{0,"coldstart"},
	{1,"warmstart"},
	{2,"startbackup"},
	{3,"endbackup"},
	{4,"startrestore"},
	{5,"endrestore"},
	{6,"abortrestore"},
	{0,NULL}
};

static const value_string
BACnetPolarity [] = {
	{0,"normal"},
	{1,"reverse"},
	{0,NULL}
};

static const value_string
BACnetTagNames[] = {
	{ 5, "Extended Value" },
	{ 6, "Opening Tag" },
	{ 7, "Closing Tag" },
	{ 0, NULL }
};

static const value_string
BACnetReadRangeOptions[] = {
	{ 3, "range byPosition" },
	{ 4, "range byTime" },
	{ 5, "range timeRange" },
	{ 6, "range bySequenceNumber" },
	{ 7, "range byTime" },
	{ 0, NULL }
};

/* Present_Value for Load Control Object */
static const value_string
BACnetShedState[] = {
	{ 0, "shed-inactive" },
	{ 1, "shed-request-pending" },
	{ 2, "shed-compliant" },
	{ 3, "shed-non-compliant" },
	{ 0, NULL }
};

static const value_string
BACnetVendorIdentifiers [] = {
	{ 0, "ASHRAE" },
	{ 1, "NIST" },
	{ 2, "The Trane Company" },
	{ 3, "McQuay International" },
	{ 4, "PolarSoft" },
	{ 5, "Johnson Controls, Inc." },
	{ 6, "American Auto-Matrix" },
	{ 7, "Siemens Building Technologies, Ltd., Landis & Staefa Division Europe" },
	{ 8, "Delta Controls" },
	{ 9, "Siemens Building Technologies, Inc." },
	{ 10, "Tour Andover Controls Corporation" },
	{ 11, "TAC" },
	{ 12, "Orion Analysis Corporation" },
	{ 13, "Teletrol Systems Inc." },
	{ 14, "Cimetrics Technology" },
	{ 15, "Cornell University" },
	{ 16, "United Technologies Carrier" },
	{ 17, "Honeywell Inc." },
	{ 18, "Alerton / Honeywell" },
	{ 19, "TAC AB" },
	{ 20, "Hewlett-Packard Company" },
	{ 21, "Dorsette's Inc." },
	{ 22, "Cerberus AG" },
	{ 23, "York Controls Group" },
	{ 24, "Automated Logic Corporation" },
	{ 25, "CSI Control Systems International" },
	{ 26, "Phoenix Controls Corporation" },
	{ 27, "Innovex Technologies, Inc." },
	{ 28, "KMC Controls, Inc." },
	{ 29, "Xn Technologies, Inc." },
	{ 30, "Hyundai Information Technology Co., Ltd." },
	{ 31, "Tokimec Inc." },
	{ 32, "Simplex" },
	{ 33, "North Communications Limited" },
	{ 34, "Notifier" },
	{ 35, "Reliable Controls Corporation" },
	{ 36, "Tridium Inc." },
	{ 37, "Sierra Monitor Corp." },
	{ 38, "Silicon Energy" },
	{ 39, "Kieback & Peter GmbH & Co KG" },
	{ 40, "Anacon Systems, Inc." },
	{ 41, "Systems Controls & Instruments, LLC" },
	{ 42, "Lithonia Lighting" },
	{ 43, "Micropower Manufacturing" },
	{ 44, "Matrix Controls" },
	{ 45, "METALAIRE" },
	{ 46, "ESS Engineering" },
	{ 47, "Sphere Systems Pty Ltd." },
	{ 48, "Walker Technologies Corporation" },
	{ 49, "H I Solutions, Inc." },
	{ 50, "MBS GmbH" },
	{ 51, "SAMSON AG" },
	{ 52, "Badger Meter Inc." },
	{ 53, "DAIKIN Industries Ltd." },
	{ 54, "NARA Controls Inc." },
	{ 55, "Mammoth Inc." },
	{ 56, "Liebert Corporation" },
	{ 57, "SEMCO Incorporated" },
	{ 58, "Air Monitor Corporation" },
	{ 59, "TRIATEK, Inc." },
	{ 60, "NexLight" },
	{ 61, "Multistack" },
	{ 62, "TSI Incorporated" },
	{ 63, "Weather-Rite, Inc." },
	{ 64, "Dunham-Bush" },
	{ 65, "Reliance Electric" },
	{ 66, "LCS Inc." },
	{ 67, "Regulator Australia PTY Ltd." },
	{ 68, "Touch-Plate Lighting Controls" },
	{ 69, "Amann GmbH" },
	{ 70, "RLE Technologies" },
	{ 71, "Cardkey Systems" },
	{ 72, "SECOM Co., Ltd." },
	{ 73, "ABB Gebaudetechnik AG Bereich NetServ" },
	{ 74, "KNX Association cvba" },
	{ 75, "Institute of Electrical Installation Engineers of Japan (IEIEJ)" },
	{ 76, "Nohmi Bosai, Ltd." },
	{ 77, "Carel S.p.A." },
	{ 78, "AirSense Technology, Inc." },
	{ 79, "Hochiki Corporation" },
	{ 80, "Fr. Sauter AG" },
	{ 81, "Matsushita Electric Works, Ltd." },
	{ 82, "Mitsubishi Electric Corporation, Inazawa Works" },
	{ 83, "Mitsubishi Heavy Industries, Ltd." },
	{ 84, "ITT Bell & Gossett" },
	{ 85, "Yamatake Building Systems Co., Ltd." },
	{ 86, "The Watt Stopper, Inc." },
	{ 87, "Aichi Tokei Denki Co., Ltd." },
	{ 88, "Activation Technologies, LLC" },
	{ 89, "Saia-Burgess Controls, Ltd." },
	{ 90, "Hitachi, Ltd." },
	{ 91, "Novar Corp./Trend Control Systems Ltd." },
	{ 92, "Mitsubishi Electric Lighting Corporation" },
	{ 93, "Argus Control Systems, Ltd." },
	{ 94, "Kyuki Corporation" },
	{ 95, "Richards-Zeta Building Intelligence, Inc." },
	{ 96, "Scientech R&D, Inc." },
	{ 97, "VCI Controls, Inc." },
	{ 98, "Toshiba Corporation" },
	{ 99, "Mitsubishi Electric Corporation Air Conditioning & Refrigeration Systems Works" },
	{ 100, "Custom Mechanical Equipment, LLC" },
	{ 101, "ClimateMaster" },
	{ 102, "ICP Panel-Tec, Inc." },
	{ 103, "D-Tek Controls" },
	{ 104, "NEC Engineering, Ltd." },
	{ 105, "PRIVA BV" },
	{ 106, "Meidensha Corporation" },
	{ 107, "JCI Systems Integration Services" },
	{ 108, "Freedom Corporation" },
	{ 109, "Neuberger Gebaudeautomation GmbH" },
	{ 110, "Sitronix" },
	{ 111, "Leviton Manufacturing" },
	{ 112, "Fujitsu Limited" },
	{ 113, "Emerson Network Power" },
	{ 114, "S. A. Armstrong, Ltd." },
	{ 115, "Visonet AG" },
	{ 116, "M&M Systems, Inc." },
	{ 117, "Custom Software Engineering" },
	{ 118, "Nittan Company, Limited" },
	{ 119, "Elutions Inc. (Wizcon Systems SAS)" },
	{ 120, "Pacom Systems Pty., Ltd." },
	{ 121, "Unico, Inc." },
	{ 122, "Ebtron, Inc." },
	{ 123, "Scada Engine" },
	{ 124, "AC Technology Corporation" },
	{ 125, "Eagle Technology" },
	{ 126, "Data Aire, Inc." },
	{ 127, "ABB, Inc." },
	{ 128, "Transbit Sp. z o. o." },
	{ 129, "Toshiba Carrier Corporation" },
	{ 130, "Shenzhen Junzhi Hi-Tech Co., Ltd." },
	{ 131, "Tokai Soft" },
	{ 132, "Lumisys" },
	{ 133, "Veris Industries" },
	{ 134, "Centaurus Prime" },
	{ 135, "Sand Network Systems" },
	{ 136, "Regulvar, Inc." },
	{ 137, "Fastek International, Ltd." },
	{ 138, "PowerCold Comfort Air Solutions, Inc." },
	{ 139, "I Controls" },
	{ 140, "Viconics Electronics, Inc." },
	{ 141, "Yaskawa Electric America, Inc." },
	{ 142, "Plueth Regelsysteme" },
	{ 143, "Digitale Mess- und Steuersysteme AG" },
	{ 144, "Fujitsu General Limited" },
	{ 145, "Project Engineering S.r.l." },
	{ 146, "Sanyo Electric Co., Ltd." },
	{ 147, "Integrated Information Systems, Inc." },
	{ 148, "Temco Controls, Ltd." },
	{ 149, "Airtek Technologies, Inc." },
	{ 150, "Advantech Corporation" },
	{ 151, "Titan Products, Ltd." },
	{ 152, "Regel Partners" },
	{ 153, "National Environmental Product" },
	{ 154, "Unitec Corporation" },
	{ 155, "Kanden Engineering Company" },
	{ 156, "Messner Gebaudetechnik GmbH" },
	{ 157, "Integrated.CH" },
	{ 158, "EH Price Limited" },
	{ 159, "SE-Elektronic GmbH" },
	{ 160, "Rockwell Automation" },
	{ 161, "Enflex Corp." },
	{ 162, "ASI Controls" },
	{ 163, "SysMik GmbH Dresden" },
	{ 164, "HSC Regelungstechnik GmbH" },
	{ 165, "Smart Temp Australia Pty. Ltd." },
	{ 166, "PCI Lighting Control Systems" },
	{ 167, "Duksan Mecasys Co., Ltd." },
	{ 168, "Fuji IT Co., Ltd." },
	{ 169, "Vacon Plc" },
	{ 170, "Leader Controls" },
	{ 171, "Cylon Controls, Ltd." },
	{ 172, "Compas" },
	{ 173, "Mitsubishi Electric Building Techno-Service Co., Ltd." },
	{ 174, "Building Control Integrators" },
	{ 175, "ITG Worldwide (M) Sdn Bhd" },
	{ 176, "Lutron Electronics Co., Inc." },
	{ 177, "Cooper-Atkins Corporation" },
	{ 178, "LOYTEC Electronics GmbH" },
	{ 179, "ProLon" },
	{ 180, "Mega Controls Limited" },
	{ 181, "Micro Control Systems, Inc." },
	{ 182, "Kiyon, Inc." },
	{ 183, "Dust Networks" },
	{ 184, "Advanced Building Automation Systems" },
	{ 185, "Hermos AG" },
	{ 186, "CEZIM" },
	{ 187, "Softing" },
	{ 188, "Lynxspring" },
	{ 189, "Schneider Toshiba Inverter Europe" },
	{ 190, "Danfoss Drives A/S" },
	{ 191, "Eaton Corporation" },
	{ 192, "Matyca S.A." },
	{ 193, "Botech AB" },
	{ 194, "Noveo, Inc." },
	{ 195, "AMEV" },
	{ 196, "Yokogawa Electric Corporation" },
	{ 197, "GFR Gesellschaft fur Regelungstechnik" },
	{ 198, "Exact Logic" },
	{ 199, "Mass Electronics Pty Ltd dba Innotech Control Systems Australia" },
	{ 200, "Kandenko Co., Ltd." },
	{ 201, "DTF, Daten-Technik Fries" },
	{ 202, "Klimasoft, Ltd." },
	{ 203, "Toshiba Schneider Inverter Corporation" },
	{ 204, "Control Applications, Ltd." },
	{ 205, "KDT Systems Co., Ltd." },
	{ 206, "Onicon Incorporated" },
	{ 207, "Automation Displays, Inc." },
	{ 208, "Control Solutions, Inc." },
	{ 209, "Remsdaq Limited" },
	{ 210, "NTT Facilities, Inc." },
	{ 211, "VIPA GmbH" },
	{ 212, "TSC21 Association of Japan" },
	{ 213, "BBP Energie Ltee" },
	{ 214, "HRW Limited" },
	{ 215, "Lighting Control & Design, Inc." },
	{ 216, "Mercy Electronic and Electrical Industries" },
	{ 217, "Samsung SDS Co., Ltd" },
	{ 218, "Impact Facility Solutions, Inc." },
	{ 219, "Aircuity" },
	{ 220, "Control Techniques, Ltd." },
	{ 221, "Evolve Control Systems, LLC" },
	{ 222, "WAGO Kontakttechnik GmbH & Co. KG" },
	{ 223, "Cerus Industrial" },
	{ 224, "Chloride Power Protection Company" },
	{ 225, "Computrols, Inc." },
	{ 226, "Phoenix Contact GmbH & Co. KG" },
	{ 227, "Grundfos Management A/S" },
	{ 228, "Ridder Drive Systems" },
	{ 229, "Soft Device SDN BHD" },
	{ 230, "Integrated Control Technology Limited" },
	{ 231, "AIRxpert Systems, Inc." },
	{ 232, "Microtrol Limited" },
	{ 233, "Red Lion Controls" },
	{ 234, "Digital Electronics Corporation" },
	{ 235, "Ennovatis GmbH" },
	{ 236, "Serotonin Software Technologies, Inc." },
	{ 237, "LS Industrial Systems Co., Ltd." },
	{ 238, "Square D Company" },
	{ 239, "S Squared Innovations, Inc." },
	{ 240, "Aricent Ltd." },
	{ 241, "EtherMetrics, LLC" },
	{ 242, "Industrial Control Communications, Inc." },
	{ 243, "Paragon Controls, Inc." },
	{ 244, "A. O. Smith Corporation" },
	{ 245, "Contemporary Control Systems, Inc." },
	{ 246, "Intesis Software SL" },
	{ 247, "Ingenieurgesellschaft N. Hartleb mbH" },
	{ 248, "Heat-Timer Corporation" },
	{ 249, "Ingrasys Technology, Inc." },
	{ 250, "Costerm Building Automation" },
	{ 251, "Wilo AG" },
	{ 252, "Embedia Technologies Corp." },
	{ 253, "Technilog" },
	{ 254, "HR Controls Ltd. & Co. KG" },
	{ 255, "Lennox International, Inc." },
	{ 256, "RK-Tec Rauchklappen-Steuerungssysteme GmbH & Co. KG" },
	{ 257, "Thermomax, Ltd." },
	{ 258, "ELCON Electronic Control, Ltd." },
	{ 259, "Larmia Control AB" },
	{ 260, "BACnet Stack at SourceForge" },
	{ 261, "G4S Security Services A/S" },
	{ 262, "Sitek S.p.A." },
	{ 263, "Cristal Controles" },
	{ 264, "Regin AB" },
	{ 265, "Dimension Software, Inc. " },
	{ 266, "SynapSense Corporation" },
	{ 267, "Beijing Nantree Electronic Co., Ltd." },
	{ 268, "Camus Hydronics Ltd." },
	{ 269, "Kawasaki Heavy Industries, Ltd. " },
	{ 270, "Critical Environment Technologies" },
	{ 271, "ILSHIN IBS Co., Ltd." },
	{ 272, "ELESTA Energy Control AG" },
	{ 273, "KROPMAN Installatietechniek" },
	{ 274, "Baldor Electric Company" },
	{ 275, "INGA mbH" },
	{ 276, "GE Consumer & Industrial" },
	{ 277, "Functional Devices, Inc." },
	{ 278, "ESAC" },
	{ 279, "M-System Co., Ltd." },
	{ 280, "Yokota Co., Ltd." },
	{ 281, "Hitranse Technology Co., LTD" },
	{ 282, "Federspiel Controls" },
	{ 283, "Kele, Inc." },
	{ 284, "Opera Electronics, Inc." },
	{ 285, "Gentec" },
	{ 286, "Embedded Science Labs, LLC" },
	{ 287, "Parker Hannifin Corporation" },
	{ 288, "MaCaPS International Limited" },
	{ 289, "Link4 Corporation" },
	{ 290, "Romutec Steuer-u. Regelsysteme GmbH" },
	{ 291, "Pribusin, Inc." },
	{ 292, "Advantage Controls" },
	{ 293, "Critical Room Control" },
	{ 294, "LEGRAND" },
	{ 295, "Tongdy Control Technology Co., Ltd." },
	{ 296, "ISSARO Integrierte Systemtechnik" },
	{ 297, "Pro-Dev Industries" },
	{ 298, "DRI-STEEM" },
	{ 299, "Creative Electronic GmbH" },
	{ 300, "Swegon AB" },
	{ 301, "Jan Brachacek" },
	{ 302, "Hitachi Appliances, Inc." },
	{ 303, "Real Time Automation, Inc." },
	{ 304, "ITEC Hankyu-Hanshin Co." },
	{ 305, "Cyrus E&M Engineering Co., Ltd." },
	{ 306, "Racine Federated, Inc." },
	{ 307, "Verari Systems, Inc." },
	{ 308, "Elesta GmbH Building Automation" },
	{ 309, "Securiton" },
	{ 310, "OSlsoft, Inc." },
	{ 311, "Hanazeder Electronic GmbH" },
	{ 312, "Honeywell Security Deutschland, Novar GmbH" },
	{ 313, "Siemens Energy & Automation, Inc." },
	{ 314, "ETM Professional Control GmbH" },
	{ 315, "Meitav-tec, Ltd." },
	{ 316, "Janitza Electronics GmbH" },
	{ 317, "MKS Nordhausen" },
	{ 318, "De Gier Drive Systems B.V." },
	{ 319, "Cypress Envirosystems" },
	{ 320, "SMARTron s.r.o." },
	{ 321, "Verari Systems, Inc." },
	{ 322, "K-W Electronic Service, Inc." },
	{ 323, "ALFA-SMART Energy Management" },
	{ 324, "Telkonet, Inc." },
	{ 325, "Securiton GmbH" },
	{ 326, "Cemtrex, Inc." },
	{ 327, "Performance Technologies, Inc." },
	{ 328, "Xtralis (Aust) Pty Ltd" },
	{ 329, "TROX GmbH" },
	{ 330, "Beijing Hysine Technology Co., Ltd" },
	{ 331, "RCK Controls, Inc." },
	{ 332, "ACELIA" },
	{ 333, "Novar/Honeywell" },
	{ 334, "The S4 Group, Inc." },
	{ 335, "Schneider Electric" },
	{ 336, "LHA Systems" },
	{ 337, "GHM engineering Group, Inc." },
	{ 338, "Cllimalux S.A." },
	{ 339, "VAISALA Oyj" },
	{ 340, "COMPLEX (Beijing) Technology, Co., LTD." },
	{ 342, "POWERPEG NSI Limited" },
	{ 343, "BACnet Interoperability Testing Services, Inc." },
	{ 344, "Teco a.s." },
	{ 345, "Plexus Technology Limited"},
	{ 346, "Energy Focus, Inc."},
	{ 347, "Powersmiths International Corp."},
	{ 348, "Nichibei Co., Ltd."},
	{ 349, "HKC Technology Ltd."},
	{ 350, "Ovation Networks, Inc."},
	{ 351, "Setra Systems"},
	{ 352, "AVG Automation"},
	{ 353, "ZXC Ltd."},
	{ 354, "Byte Sphere"},
	{ 355, "Generiton Co., Ltd."},
	{ 356, "Holter Regelarmaturen GmbH & Co. KG"},
	{ 357, "Bedford Instruments, LLC"},
	{ 358, "Standair Inc."},
	{ 359, "WEG Automation - R&D"},
	{ 360, "Prolon Control Systems ApS"},
	{ 361, "Inneasoft"},
	{ 362, "ConneXSoft GmbH"},
	{ 363, "CEAG Notlichtsysteme GmbH"},
	{ 364, "Distech Controls Inc."},
	{ 365, "Industrial Technology Research Institute"},
	{ 366, "ICONICS, Inc."},
	{ 367, "IQ Controls s.c."},
	{ 368, "OJ Electronics A/S"},
	{ 369, "Rolbit Ltd."},
	{ 370, "Synapsys Solutions Ltd."},
	{ 371, "ACME Engineering Prod. Ltd."},
	{ 372, "Zener Electric Pty, Ltd."},
	{ 373, "Selectronix, Inc."},
	{ 374, "Gorbet & Banerjee, LLC."},
	{ 375, "IME"},
	{ 376, "Stephen H. Dawson Computer Service"},
	{ 377, "Accutrol, LLC"},
	{ 378, "Schneider Elektronik GmbH"},
	{ 379, "Alpha-Inno Tec GmbH"},
	{ 380, "ADMMicro, Inc."},
	{ 381, "Greystone Energy Systems, Inc."},
	{ 382, "CAP Technologie"},
	{ 383, "KeRo Systems"},
	{ 384, "Domat Control System s.r.o."},
	{ 385, "Efektronics Pty. Ltd."},
	{ 386, "Hekatron Vertriebs GmbH"},
	{ 387, "Securiton AG"},
	{ 388, "Carlo Gavazzi Controls SpA"},
	{ 389, "Chipkin Automation Systems"},
	{ 390, "Savant Systems, LLC"},
	{ 391, "Simmtronic Lighting Controls"},
	{ 392, "Abelko Innovation AB"},
	{ 393, "Seresco Technologies Inc."},
	{ 394, "IT Watchdogs"},
	{ 395, "Automation Assist Japan Corp."},
	{ 396, "Thermokon Sensortechnik GmbH"},
	{ 397, "EGauge Systems, LLC"},
	{ 398, "Quantum Automation (ASIA) PTE, Ltd."},
	{ 399, "Toshiba Lighting & Technology Corp."},
	{ 400, "SPIN Engenharia de Automação Ltda."},
	{ 401, "Logistics Systems & Software Services India PVT. Ltd."},
	{ 402, "Delta Controls Integration Products"},
	{ 403, "Focus Media"},
	{ 404, "LUMEnergi Inc."},
	{ 405, "Kara Systems"},
	{ 406, "RF Code, Inc."},
	{ 407, "Fatek Automation Corp."},
	{ 408, "JANDA Software Company, LLC"},
	{ 409, "Open System Solutions Limited"},
	{ 410, "Intelec Systems PTY Ltd."},
	{ 411, "Ecolodgix, LLC"},
	{ 412, "Douglas Lighting Controls"},
	{ 413, "iSAtech GmbH intelligente Sensoren Aktoren technologie"},
	{ 414, "AREAL"},
	{ 415, "Beckhoff Automation GmbH"},
	{ 416, "IPAS GmbH"},
	{ 417, "KE2 Therm Solutions"},
	{ 418, "Base2Products"},
	{ 419, "DTL Controls, LLC"},
	{ 420, "INNCOM International, Inc."},
	{ 421, "BTR Netcom GmbH"},
	{ 422, "Greentrol Automation, Inc"},
	{ 423, "BELIMO Automation AG"},
	{ 424, "Samsung Heavy Industries Co, Ltd"},
	{ 425, "Triacta Power Technologies, Inc."},
	{ 426, "Globestar Systems"},
	{ 427, "MLB Advanced Media, LP"},
	{ 428, "SWG Stuckmann Wirtschaftliche Gebäudesysteme GmbH"},
	{ 429, "SensorSwitch"},
	{ 430, "Multitek Power Limited"},
	{ 431, "Aquametro AG"},
	{ 432, "LG Electronics Inc."},
	{ 433, "Electronic Theatre Controls, Inc."},
	{ 434, "Mitsubishi Electric Corporation Nagoya Works"},
	{ 435, "Delta Electronics, Inc."},
	{ 436, "Elma Kurtalj, Ltd."},
	{ 437, "ADT Fire and Security Sp. A.o.o."},
	{ 438, "Nedap Security Management"},
	{ 439, "ESC Automation Inc."},
	{ 440, "DSP4YOU Ltd."},
	{ 441, "GE Sensing and Inspection Technologies"},
	{ 442, "Embedded Systems SIA"},
	{ 443, "BEFEGA GmbH"},
	{ 444, "Baseline Inc."},
	{ 445, "M2M Systems Integrators"},
	{ 446, "OEMCtrl"},
	{ 447, "Clarkson Controls Limited"},
	{ 448, "Rogerwell Control System Limited"},
	{ 449, "SCL Elements"},
	{ 450, "Hitachi Ltd."},
	{ 451, "Newron System SA"},
	{ 452, "BEVECO Gebouwautomatisering BV"},
	{ 453, "Streamside Solutions"},
	{ 454, "Yellowstone Soft"},
	{ 455, "Oztech Intelligent Systems Pty Ltd."},
	{ 456, "Novelan GmbH"},
	{ 457, "Flexim Americas Corporation"},
	{ 458, "ICP DAS Co., Ltd."},
	{ 459, "CARMA Industries Inc."},
	{ 460, "Log-One Ltd."},
	{ 461, "TECO Electric & Machinery Co., Ltd."},
	{ 462, "ConnectEx, Inc."},
	{ 463, "Turbo DDC Südwest"},
	{ 464, "Quatrosense Environmental Ltd."},
	{ 465, "Fifth Light Technology Ltd."},
	{ 466, "Scientific Solutions, Ltd."},
	{ 467, "Controller Area Network Solutions (M) Sdn Bhd"},
	{ 468, "RESOL - Elektronische Regelungen GmbH"},
	{ 469, "RPBUS LLC"},
	{ 470, "BRS Sistemas Eletronicos"},
	{ 471, "WindowMaster A/S"},
	{ 472, "Sunlux Technologies Ltd."},
	{ 473, "Measurlogic"},
	{ 474, "Frimat GmbH"},
	{ 475, "Spirax Sarco"},
	{ 476, "Luxtron"},
	{ 477, "Raypak Inc"},
	{ 478, "Air Monitor Corporation"},
	{ 479, "Regler Och Webbteknik Sverige (ROWS)"},
	{ 480, "Intelligent Lighting Controls Inc."},
	{ 481, "Sanyo Electric Industry Co., Ltd"},
	{ 482, "E-Mon Energy Monitoring Products"},
	{ 483, "Digital Control Systems"},
	{ 484, "ATI Airtest Technologies, Inc."},
	{ 485, "SCS SA"},
	{ 486, "HMS Industrial Networks AB"},
	{ 487, "Shenzhen Universal Intellisys Co Ltd"},
	{ 488, "EK Intellisys Sdn Bhd"},
	{ 489, "SysCom"},
	{ 490, "Firecom, Inc."},
	{ 491, "ESA Elektroschaltanlagen Grimma GmbH"},
	{ 492, "Kumahira Co Ltd"},
	{ 493, "Hotraco"},
	{ 494, "SABO Elektronik GmbH"},
	{ 495, "Equip'Trans"},
	{ 496, "TCS Basys Controls"},
	{ 497, "FlowCon International A/S"},
	{ 498, "ThyssenKrupp Elevator Americas"},
	{ 499, "Abatement Technologies"},
	{ 500, "Continental Control Systems, LLC"},
	{ 501, "WISAG Automatisierungstechnik GmbH & Co KG"},
	{ 502, "EasyIO"},
	{ 503, "EAP-Electric GmbH"},
	{ 504, "Hardmeier"},
	{ 505, "Mircom Group of Companies"},
	{ 506, "Quest Controls"},
	{ 507, "Mestek, Inc"},
	{ 508, "Pulse Energy"},
	{ 509, "Tachikawa Corporation"},
	{ 510, "University of Nebraska-Lincoln"},
	{ 511, "Redwood Systems"},
	{ 512, "PASStec Industrie-Elektronik GmbH"},
	{ 513, "NgEK, Inc."},
	{ 514, "FAW Electronics Ltd"},
	{ 515, "Jireh Energy Tech Co., Ltd."},
	{ 516, "Enlighted Inc."},
	{ 517, "El-Piast Sp. Z o.o"},
	{ 518, "NetxAutomation Software GmbH"},
	{ 519, "Invertek Drives"},
	{ 520, "Deutschmann Automation GmbH & Co. KG"},
	{ 521, "EMU Electronic AG"},
	{ 522, "Phaedrus Limited"},
	{ 523, "Sigmatek GmbH & Co KG"},
	{ 524, "Marlin Controls"},
	{ 525, "Circutor, SA"},
	{ 526, "UTC Fire & Security"},
	{ 527, "DENT Instruments, Inc."},
	{ 528, "FHP Manufacturing Company - Bosch Group"},
	{ 529, "GE Intelligent Platforms"},
	{ 530, "Inner Range Pty Ltd"},
	{ 531, "GLAS Energy Technology"},
	{ 532, "MSR-Electronic-GmbH"},
	{ 0, NULL }
};

static int proto_bacapp = -1;
static int hf_bacapp_type = -1;
static int hf_bacapp_pduflags = -1;
static int hf_bacapp_SEG = -1;
static int hf_bacapp_MOR = -1;
static int hf_bacapp_SA = -1;
static int hf_bacapp_response_segments = -1;
static int hf_bacapp_max_adpu_size = -1;
static int hf_bacapp_invoke_id = -1;
static int hf_bacapp_objectType = -1;
static int hf_bacapp_instanceNumber = -1;
static int hf_bacapp_sequence_number = -1;
static int hf_bacapp_window_size = -1;
static int hf_bacapp_service = -1;
static int hf_bacapp_NAK = -1;
static int hf_bacapp_SRV = -1;
static int hf_Device_Instance_Range_Low_Limit = -1;
static int hf_Device_Instance_Range_High_Limit = -1;
static int hf_BACnetRejectReason = -1;
static int hf_BACnetAbortReason = -1;
static int hf_BACnetApplicationTagNumber = -1;
static int hf_BACnetContextTagNumber = -1;
static int hf_BACnetExtendedTagNumber = -1;
static int hf_BACnetNamedTag = -1;
static int hf_BACnetTagClass = -1;
static int hf_BACnetCharacterSet = -1;
static int hf_bacapp_tag_lvt = -1;
static int hf_bacapp_tag_ProcessId = -1;
static int hf_bacapp_uservice = -1;
static int hf_BACnetPropertyIdentifier = -1;
static int hf_BACnetVendorIdentifier = -1;
static int hf_BACnetRestartReason = -1;
static int hf_bacapp_tag_IPV4 = -1;
static int hf_bacapp_tag_IPV6 = -1;
static int hf_bacapp_tag_PORT = -1;
/* some more variables for segmented messages */
static int hf_msg_fragments = -1;
static int hf_msg_fragment = -1;
static int hf_msg_fragment_overlap = -1;
static int hf_msg_fragment_overlap_conflicts = -1;
static int hf_msg_fragment_multiple_tails = -1;
static int hf_msg_fragment_too_long_fragment = -1;
static int hf_msg_fragment_error = -1;
static int hf_msg_fragment_count = -1;
static int hf_msg_reassembled_in = -1;
static int hf_msg_reassembled_length = -1;

static gint ett_msg_fragment = -1;
static gint ett_msg_fragments = -1;

static gint ett_bacapp = -1;
static gint ett_bacapp_control = -1;
static gint ett_bacapp_tag = -1;
static gint ett_bacapp_list = -1;
static gint ett_bacapp_value = -1;

static dissector_handle_t data_handle;
static gint32 propertyIdentifier = -1;
static gint32 propertyArrayIndex = -1;
static guint32 object_type = 4096;

static guint8 bacapp_flags = 0;
static guint8 bacapp_seq = 0;

/* Defined to allow vendor identifier registration of private transfer dissectors */
static dissector_table_t bacapp_dissector_table;


/* Stat: BACnet Packets sorted by IP */
bacapp_info_value_t bacinfo;

static const gchar* st_str_packets_by_ip = "BACnet Packets by IP";
static const gchar* st_str_packets_by_ip_dst = "By Destination";
static const gchar* st_str_packets_by_ip_src = "By Source";
static int st_node_packets_by_ip = -1;
static int st_node_packets_by_ip_dst = -1;
static int st_node_packets_by_ip_src = -1;

static void
bacapp_packet_stats_tree_init(stats_tree* st)
{
	st_node_packets_by_ip = stats_tree_create_pivot(st, st_str_packets_by_ip, 0);
	st_node_packets_by_ip_src = stats_tree_create_node(st, st_str_packets_by_ip_src, st_node_packets_by_ip, TRUE);
	st_node_packets_by_ip_dst = stats_tree_create_node(st, st_str_packets_by_ip_dst, st_node_packets_by_ip, TRUE);
}

static int
bacapp_stats_tree_packet(stats_tree* st, packet_info* pinfo, epan_dissect_t* edt _U_, const void* p)
{
	int packets_for_this_dst;
	int packets_for_this_src;
	int service_for_this_dst;
	int service_for_this_src;
	int src_for_this_dst;
	int dst_for_this_src;
	int objectid_for_this_dst;
	int objectid_for_this_src;
	int instanceid_for_this_dst;
	int instanceid_for_this_src;
	gchar *dststr;
	gchar *srcstr;
	const bacapp_info_value_t *binfo = p;

	srcstr = ep_strconcat("Src: ", address_to_str(&pinfo->src), NULL);
	dststr = ep_strconcat("Dst: ", address_to_str(&pinfo->dst), NULL);

	tick_stat_node(st, st_str_packets_by_ip, 0, TRUE);
	packets_for_this_dst = tick_stat_node(st, st_str_packets_by_ip_dst, st_node_packets_by_ip, TRUE);
	packets_for_this_src = tick_stat_node(st, st_str_packets_by_ip_src, st_node_packets_by_ip, TRUE);
	src_for_this_dst = tick_stat_node(st, dststr, packets_for_this_dst, TRUE);
	dst_for_this_src = tick_stat_node(st, srcstr, packets_for_this_src, TRUE);
	service_for_this_src = tick_stat_node(st, dststr, dst_for_this_src, TRUE);
	service_for_this_dst = tick_stat_node(st, srcstr, src_for_this_dst, TRUE);
	if (binfo->service_type) {
		objectid_for_this_dst = tick_stat_node(st, binfo->service_type, service_for_this_dst, TRUE);
		objectid_for_this_src = tick_stat_node(st, binfo->service_type, service_for_this_src, TRUE);
		if (binfo->object_ident) {
			instanceid_for_this_dst=tick_stat_node(st, binfo->object_ident, objectid_for_this_dst, TRUE);
			tick_stat_node(st, binfo->instance_ident, instanceid_for_this_dst, FALSE);
			instanceid_for_this_src=tick_stat_node(st, binfo->object_ident, objectid_for_this_src, TRUE);
			tick_stat_node(st, binfo->instance_ident, instanceid_for_this_src, FALSE);
		}
	}

	return 1;
}

/* Stat: BACnet Packets sorted by Service */
static const gchar* st_str_packets_by_service = "BACnet Packets by Service";
static int st_node_packets_by_service = -1;

static void
bacapp_service_stats_tree_init(stats_tree* st)
{
	st_node_packets_by_service = stats_tree_create_pivot(st, st_str_packets_by_service, 0);
}

static int
bacapp_stats_tree_service(stats_tree* st, packet_info* pinfo, epan_dissect_t* edt _U_, const void* p)
{
	int servicetype;
	int src,dst;
	int objectid;

	gchar *dststr;
	gchar *srcstr;
	const bacapp_info_value_t *binfo = p;

	srcstr = ep_strconcat("Src: ", address_to_str(&pinfo->src), NULL);
	dststr = ep_strconcat("Dst: ", address_to_str(&pinfo->dst), NULL);

	tick_stat_node(st, st_str_packets_by_service, 0, TRUE);
	if (binfo->service_type) {
		servicetype = tick_stat_node(st, binfo->service_type, st_node_packets_by_service, TRUE);
		src = tick_stat_node(st, srcstr, servicetype, TRUE);
		dst = tick_stat_node(st, dststr, src, TRUE);
		if (binfo->object_ident) {
			objectid = tick_stat_node(st, binfo->object_ident, dst, TRUE);
			tick_stat_node(st, binfo->instance_ident, objectid, FALSE);
		}
	}

	return 1;
}

/* Stat: BACnet Packets sorted by Object Type */
static const gchar* st_str_packets_by_objectid = "BACnet Packets by Object Type";
static int st_node_packets_by_objectid = -1;

static void
bacapp_objectid_stats_tree_init(stats_tree* st)
{
	st_node_packets_by_objectid = stats_tree_create_pivot(st, st_str_packets_by_objectid, 0);
}

static int
bacapp_stats_tree_objectid(stats_tree* st, packet_info* pinfo, epan_dissect_t* edt _U_, const void* p)
{
	int servicetype;
	int src,dst;
	int objectid;

	gchar *dststr;
	gchar *srcstr;
	const bacapp_info_value_t *binfo = p;

	srcstr = ep_strconcat("Src: ", address_to_str(&pinfo->src), NULL);
	dststr = ep_strconcat("Dst: ", address_to_str(&pinfo->dst), NULL);

	tick_stat_node(st, st_str_packets_by_objectid, 0, TRUE);
	if (binfo->object_ident) {
		objectid = tick_stat_node(st, binfo->object_ident, st_node_packets_by_objectid, TRUE);
		src = tick_stat_node(st, srcstr, objectid, TRUE);
		dst = tick_stat_node(st, dststr, src, TRUE);
		if (binfo->service_type) {
			servicetype = tick_stat_node(st, binfo->service_type, dst, TRUE);
			tick_stat_node(st, binfo->instance_ident, servicetype, FALSE);
		}
	}

	return 1;
}

/* Stat: BACnet Packets sorted by Instance No */
static const gchar* st_str_packets_by_instanceid = "BACnet Packets by Instance ID";
static int st_node_packets_by_instanceid = -1;

static void
bacapp_instanceid_stats_tree_init(stats_tree* st)
{
	st_node_packets_by_instanceid = stats_tree_create_pivot(st, st_str_packets_by_instanceid, 0);
}

static int
bacapp_stats_tree_instanceid(stats_tree* st, packet_info* pinfo, epan_dissect_t* edt _U_, const void* p)
{
	int servicetype;
	int src,dst;
	int instanceid;

	gchar *dststr;
	gchar *srcstr;
	const bacapp_info_value_t *binfo = p;

	srcstr = ep_strconcat("Src: ", address_to_str(&pinfo->src), NULL);
	dststr = ep_strconcat("Dst: ", address_to_str(&pinfo->dst), NULL);

	tick_stat_node(st, st_str_packets_by_instanceid, 0, TRUE);
	if (binfo->object_ident) {
		instanceid = tick_stat_node(st, binfo->instance_ident, st_node_packets_by_instanceid, TRUE);
		src = tick_stat_node(st, srcstr, instanceid, TRUE);
		dst = tick_stat_node(st, dststr, src, TRUE);
		if (binfo->service_type) {
			servicetype = tick_stat_node(st, binfo->service_type, dst, TRUE);
			tick_stat_node(st, binfo->object_ident, servicetype, FALSE);
		}
	}
	return 1;
}


/* register all BACnet Ststistic trees */
static void
register_bacapp_stat_trees(void)
{
	stats_tree_register("bacapp","bacapp_ip","BACnet/Packets sorted by IP", 0,
		bacapp_stats_tree_packet, bacapp_packet_stats_tree_init, NULL);
	stats_tree_register("bacapp","bacapp_service","BACnet/Packets sorted by Service", 0,
		bacapp_stats_tree_service, bacapp_service_stats_tree_init, NULL);
	stats_tree_register("bacapp","bacapp_objectid","BACnet/Packets sorted by Object Type", 0,
		bacapp_stats_tree_objectid, bacapp_objectid_stats_tree_init, NULL);
	stats_tree_register("bacapp","bacapp_instanceid","BACnet/Packets sorted by Instance ID", 0,
		bacapp_stats_tree_instanceid, bacapp_instanceid_stats_tree_init, NULL);
}

/* 'data' must be ep_ allocated */
static gint
updateBacnetInfoValue(gint whichval, gchar *data)
{
	if (whichval == BACINFO_SERVICE) {
		bacinfo.service_type = data;
		return 0;
	}
	if (whichval == BACINFO_INVOKEID) {
		bacinfo.invoke_id = data;
		return 0;
	}
	if (whichval == BACINFO_OBJECTID) {
		bacinfo.object_ident = data;
		return 0;
	}
	if (whichval == BACINFO_INSTANCEID) {
		bacinfo.instance_ident = data;
		return 0;
	}
	return -1;
}

static const fragment_items msg_frag_items = {
	/* Fragment subtrees */
	&ett_msg_fragment,
	&ett_msg_fragments,
	/* Fragment fields */
	&hf_msg_fragments,
	&hf_msg_fragment,
	&hf_msg_fragment_overlap,
	&hf_msg_fragment_overlap_conflicts,
	&hf_msg_fragment_multiple_tails,
	&hf_msg_fragment_too_long_fragment,
	&hf_msg_fragment_error,
	&hf_msg_fragment_count,
	/* Reassembled in field */
	&hf_msg_reassembled_in,
	/* Reassembled length field */
	&hf_msg_reassembled_length,
	/* Tag */
	"Message fragments"
};

/* if BACnet uses the reserved values, then patch the corresponding values here, maximum 16 values are defined */
static const guint MaxAPDUSize [] = { 50,128,206,480,1024,1476 };

#if 0
/* FIXME: fGetMaxAPDUSize is commented out, as it is not used. It was used to set variables which were not later used. */
static guint
fGetMaxAPDUSize(guint8 idx)
{
	/* only 16 values are defined, so use & 0x0f */
	/* check the size of the Array, deliver either the entry
	   or the first entry if idx is outside of the array (bug 3736 comment#7) */

	if ((idx & 0x0f) >= (gint)(sizeof(MaxAPDUSize)/sizeof(guint)))
		return MaxAPDUSize[0];
	else
		return MaxAPDUSize[idx & 0x0f];
}
#endif


/* Used when there are ranges of reserved and proprietary enumerations */
static const char*
val_to_split_str(guint32 val, guint32 split_val, const value_string *vs,
	const char *fmt, const char *split_fmt)
{
	if (val < split_val)
		return val_to_str(val, vs, fmt);
	else
		return val_to_str(val, vs, split_fmt);
}

/* from clause 20.2.1.3.2 Constructed Data */
/* returns true if the extended value is used */
static gboolean
tag_is_extended_value(guint8 tag)
{
	return (tag & 0x07) == 5;
}

static gboolean
tag_is_opening(guint8 tag)
{
	return (tag & 0x07) == 6;
}

static gboolean
tag_is_closing(guint8 tag)
{
	return (tag & 0x07) == 7;
}

/* from clause 20.2.1.1 Class
   class bit shall be one for context specific tags */
/* returns true if the tag is context specific */
static gboolean
tag_is_context_specific(guint8 tag)
{
	return (tag & 0x08) != 0;
}

static gboolean
tag_is_extended_tag_number(guint8 tag)
{
	return ((tag & 0xF0) == 0xF0);
}

static guint32
object_id_type(guint32 object_identifier)
{
	return ((object_identifier >> 22) & 0x3FF);
}

static guint32
object_id_instance(guint32 object_identifier)
{
	return (object_identifier & 0x3FFFFF);
}

static guint
fTagNo (tvbuff_t *tvb, guint offset)
{
	return (guint)(tvb_get_guint8(tvb, offset) >> 4);
}

static gboolean
fUnsigned32 (tvbuff_t *tvb, guint offset, guint32 lvt, guint32 *val)
{
	gboolean valid = TRUE;

	switch (lvt) {
		case 1:
			*val = tvb_get_guint8(tvb, offset);
			break;
		case 2:
			*val = tvb_get_ntohs(tvb, offset);
			break;
		case 3:
			*val = tvb_get_ntoh24(tvb, offset);
			break;
		case 4:
			*val = tvb_get_ntohl(tvb, offset);
			break;
		default:
			valid = FALSE;
			break;
	}

	return valid;
}

static gboolean
fUnsigned64 (tvbuff_t *tvb, guint offset, guint32 lvt, guint64 *val)
{
	gboolean valid = FALSE;
	gint64 value = 0;
	guint8 data, i;

	if (lvt && (lvt <= 8)) {
		valid = TRUE;
		data = tvb_get_guint8(tvb, offset);
		for (i = 0; i < lvt; i++) {
			data = tvb_get_guint8(tvb, offset+i);
			value = (value << 8) + data;
		}
		*val = value;
	}

	return valid;
}

/* BACnet Signed Value uses 2's complement notation, but with a twist:
   All signed integers shall be encoded in the smallest number of octets
   possible.  That is, the first octet of any multi-octet encoded value
   shall not be X'00' if the most significant bit (bit 7) of the second
   octet is 0, and the first octet shall not be X'FF' if the most
   significant bit of the second octet is 1. ASHRAE-135-2004-20.2.5 */
static gboolean
fSigned64 (tvbuff_t *tvb, guint offset, guint32 lvt, gint64 *val)
{
	gboolean valid = FALSE;
	gint64 value = 0;
	guint8 data;
	guint32 i;

	/* we can only handle 7 bytes for a 64-bit value due to signed-ness */
	if (lvt && (lvt <= 7)) {
		valid = TRUE;
		data = tvb_get_guint8(tvb, offset);
		if ((data & 0x80) != 0)
			value = (-1 << 8) | data;
		else
			value = data;
		for (i = 1; i < lvt; i++) {
			data = tvb_get_guint8(tvb, offset+i);
			value = (value << 8) + data;
		}
		*val = value;
	}

	return valid;
}

static guint
fTagHeaderTree (tvbuff_t *tvb, proto_tree *tree, guint offset,
	guint8 *tag_no, guint8* tag_info, guint32 *lvt)
{
	guint8 tag;
	guint8 value;
	guint tag_len = 1;
	guint lvt_len = 1; /* used for tree display of lvt */
	guint lvt_offset; /* used for tree display of lvt */
	proto_item *ti;
	proto_tree *subtree;

	lvt_offset = offset;
	tag = tvb_get_guint8(tvb, offset);
	*tag_info = 0;
	*lvt = tag & 0x07;
	/* To solve the problem of lvt values of 6/7 being indeterminate - it */
	/* can mean open/close tag or length of 6/7 after the length is */
	/* computed below - store whole tag info, not just context bit. */
	if (tag_is_context_specific(tag)) *tag_info = tag & 0x0F;
	*tag_no = tag >> 4;
	if (tag_is_extended_tag_number(tag)) {
		*tag_no = tvb_get_guint8(tvb, offset + tag_len++);
	}
	if (tag_is_extended_value(tag)) {       /* length is more than 4 Bytes */
		lvt_offset += tag_len;
		value = tvb_get_guint8(tvb, lvt_offset);
		tag_len++;
		if (value == 254) { /* length is encoded with 16 Bits */
			*lvt = tvb_get_ntohs(tvb, lvt_offset+1);
			tag_len += 2;
			lvt_len += 2;
		} else if (value == 255) { /* length is encoded with 32 Bits */
			*lvt = tvb_get_ntohl(tvb, lvt_offset+1);
			tag_len += 4;
			lvt_len += 4;
		} else
			*lvt = value;
	}

	if (tree) {
		if (tag_is_opening(tag))
			ti = proto_tree_add_text(tree, tvb, offset, tag_len, "{[%u]", *tag_no );
		else if (tag_is_closing(tag))
			ti = proto_tree_add_text(tree, tvb, offset, tag_len, "}[%u]", *tag_no );
		else if (tag_is_context_specific(tag)) {
			ti = proto_tree_add_text(tree, tvb, offset, tag_len,
				"Context Tag: %u, Length/Value/Type: %u",
				*tag_no, *lvt);
		} else
			ti = proto_tree_add_text(tree, tvb, offset, tag_len,
				"Application Tag: %s, Length/Value/Type: %u",
				val_to_str(*tag_no,
					BACnetApplicationTagNumber,
					ASHRAE_Reserved_Fmt),
					*lvt);

		subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
		/* details if needed */
		proto_tree_add_item(subtree, hf_BACnetTagClass, tvb, offset, 1, FALSE);
		if (tag_is_extended_tag_number(tag)) {
			proto_tree_add_uint_format(subtree,
					hf_BACnetContextTagNumber,
					tvb, offset, 1, tag,
					"Extended Tag Number");
			proto_tree_add_item(subtree,
				hf_BACnetExtendedTagNumber,
				tvb, offset + 1, 1, FALSE);
		} else {
			if (tag_is_context_specific(tag))
				proto_tree_add_item(subtree,
					hf_BACnetContextTagNumber,
					tvb, offset, 1, FALSE);
			else
				proto_tree_add_item(subtree,
					hf_BACnetApplicationTagNumber,
					tvb, offset, 1, FALSE);
		}
		if (tag_is_closing(tag) || tag_is_opening(tag))
			proto_tree_add_item(subtree,
				hf_BACnetNamedTag,
				tvb, offset, 1, FALSE);
		else if (tag_is_extended_value(tag)) {
			proto_tree_add_item(subtree,
				hf_BACnetNamedTag,
				tvb, offset, 1, FALSE);
			proto_tree_add_uint(subtree, hf_bacapp_tag_lvt,
				tvb, lvt_offset, lvt_len, *lvt);
		} else
			proto_tree_add_uint(subtree, hf_bacapp_tag_lvt,
				tvb, lvt_offset, lvt_len, *lvt);
	}

	return tag_len;
}

static guint
fTagHeader (tvbuff_t *tvb, guint offset, guint8 *tag_no, guint8* tag_info,
	guint32 *lvt)
{
	return fTagHeaderTree (tvb, NULL, offset, tag_no, tag_info, lvt);
}

static guint
fNullTag (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label)
{
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_item *ti;
	proto_tree *subtree;

	ti = proto_tree_add_text(tree, tvb, offset, 1, "%sNULL", label);
	subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
	fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);

	return offset + 1;
}

static guint
fBooleanTag (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label)
{
	guint8 tag_no, tag_info;
	guint32 lvt = 0;
	proto_item *ti;
	proto_tree *subtree;
	guint bool_len = 1;

	fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	if (tag_info && lvt == 1) {
		lvt = tvb_get_guint8(tvb, offset+1);
		++bool_len;
	}

	ti = proto_tree_add_text(tree, tvb, offset, bool_len,
		"%s%s", label, lvt == 0 ? "FALSE" : "TRUE");
	subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
	fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);

	return offset + bool_len;
}

static guint
fUnsignedTag (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label)
{
	guint64 val = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;
	guint tag_len;
	proto_item *ti;
	proto_tree *subtree;

	tag_len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	/* only support up to an 8 byte (64-bit) integer */
	if (fUnsigned64 (tvb, offset + tag_len, lvt, &val))
		ti = proto_tree_add_text(tree, tvb, offset, lvt+tag_len,
			"%s(Unsigned) %" G_GINT64_MODIFIER "u", label, val);
	else
		ti = proto_tree_add_text(tree, tvb, offset, lvt+tag_len,
			"%s - %u octets (Unsigned)", label, lvt);
	subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
	fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);

	return offset+tag_len+lvt;
}

static guint
fDevice_Instance (tvbuff_t *tvb, proto_tree *tree, guint offset, int hf)
{
	guint8 tag_no, tag_info;
	guint32 lvt;
	guint tag_len;
	proto_item *ti;
	proto_tree *subtree;

	tag_len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	ti = proto_tree_add_item(tree, hf, tvb, offset+tag_len, lvt, ENC_BIG_ENDIAN);
	subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
	fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);

	return offset+tag_len+lvt;
}

/* set split_val to zero when not needed */
static guint
fEnumeratedTagSplit (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label,
	const value_string *vs, guint32 split_val)
{
	guint32 val = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;
	guint tag_len;
	proto_item *ti;
	proto_tree *subtree;

	tag_len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	/* only support up to a 4 byte (32-bit) enumeration */
	if (fUnsigned32 (tvb, offset+tag_len, lvt, &val)) {
		if (vs)
			ti = proto_tree_add_text(tree, tvb, offset, lvt+tag_len,
				"%s %s", label, val_to_split_str(val, split_val, vs,
				ASHRAE_Reserved_Fmt,Vendor_Proprietary_Fmt));
		else
			ti =proto_tree_add_text(tree, tvb, offset, lvt+tag_len,
				"%s %u", label, val);
	} else {
		ti = proto_tree_add_text(tree, tvb, offset, lvt+tag_len,
			"%s - %u octets (enumeration)", label, lvt);
	}
	subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
	fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);

	return offset+tag_len+lvt;
}

static guint
fEnumeratedTag (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label,
		const value_string *vs)
{
	return fEnumeratedTagSplit (tvb, tree, offset, label, vs, 0);
}

static guint
fSignedTag (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label)
{
	gint64 val = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;
	guint tag_len;
	proto_item *ti;
	proto_tree *subtree;

	tag_len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	if (fSigned64 (tvb, offset + tag_len, lvt, &val))
		ti = proto_tree_add_text(tree, tvb, offset, lvt+tag_len,
			"%s(Signed) %" G_GINT64_MODIFIER "d", label, val);
	else
		ti = proto_tree_add_text(tree, tvb, offset, lvt+tag_len,
			"%s - %u octets (Signed)", label, lvt);
	subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
	fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);

	return offset+tag_len+lvt;
}

static guint
fRealTag (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label)
{
	guint8 tag_no, tag_info;
	guint32 lvt;
	guint tag_len;
	gfloat f_val;
	proto_item *ti;
	proto_tree *subtree;

	tag_len = fTagHeader(tvb, offset, &tag_no, &tag_info, &lvt);
	f_val = tvb_get_ntohieee_float(tvb, offset+tag_len);
	ti = proto_tree_add_text(tree, tvb, offset, 4+tag_len,
		"%s%f (Real)", label, f_val);
	subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
	fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);

	return offset+tag_len+4;
}

static guint
fDoubleTag (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label)
{
	guint8 tag_no, tag_info;
	guint32 lvt;
	guint tag_len;
	gdouble d_val;
	proto_item *ti;
	proto_tree *subtree;

	tag_len = fTagHeader(tvb, offset, &tag_no, &tag_info, &lvt);
	d_val = tvb_get_ntohieee_double(tvb, offset+tag_len);
	ti = proto_tree_add_text(tree, tvb, offset, 8+tag_len,
		"%s%f (Double)", label, d_val);
	subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
	fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);

	return offset+tag_len+8;
}

static guint
fProcessId (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint32 val = 0, lvt;
	guint8 tag_no, tag_info;
	proto_item *ti;
	proto_tree *subtree;
	guint tag_len;

	tag_len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	if (fUnsigned32 (tvb, offset+tag_len, lvt, &val))
		ti = proto_tree_add_uint(tree, hf_bacapp_tag_ProcessId,
			tvb, offset, lvt+tag_len, val);
	else
		ti = proto_tree_add_text(tree, tvb, offset, lvt+tag_len,
			"Process Identifier - %u octets (Signed)", lvt);
	subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
	fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
	offset += tag_len + lvt;

	return offset;
}

static guint
fTimeSpan (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label)
{
	guint32 val = 0, lvt;
	guint8 tag_no, tag_info;
	proto_item *ti;
	proto_tree *subtree;
	guint tag_len;

	tag_len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	if (fUnsigned32 (tvb, offset+tag_len, lvt, &val))
		ti = proto_tree_add_text(tree, tvb, offset, lvt+tag_len,
		"%s (hh.mm.ss): %d.%02d.%02d%s",
		label,
		(val / 3600), ((val % 3600) / 60), (val % 60),
		val == 0 ? " (indefinite)" : "");
	else
		ti = proto_tree_add_text(tree, tvb, offset, lvt+tag_len,
			"%s - %u octets (Signed)", label, lvt);
	subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
	fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);

	return offset+tag_len+lvt;
}

static guint
fWeekNDay (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint32 month, weekOfMonth, dayOfWeek;
	guint8 tag_no, tag_info;
	guint32 lvt;
	guint tag_len;
	proto_item *ti;
	proto_tree *subtree;

	tag_len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	month = tvb_get_guint8(tvb, offset+tag_len);
	weekOfMonth = tvb_get_guint8(tvb, offset+tag_len+1);
	dayOfWeek = tvb_get_guint8(tvb, offset+tag_len+2);
	ti = proto_tree_add_text(tree, tvb, offset, lvt+tag_len, "%s %s, %s",
				 val_to_str(month, months, "month (%d) not found"),
				 val_to_str(weekOfMonth, weekofmonth, "week of month (%d) not found"),
				 val_to_str(dayOfWeek, day_of_week, "day of week (%d) not found"));
	subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
	fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);

	return offset+tag_len+lvt;
}

static guint
fDate (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label)
{
	guint32 year, month, day, weekday;
	guint8 tag_no, tag_info;
	guint32 lvt;
	guint tag_len;
	proto_item *ti;
	proto_tree *subtree;

	tag_len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	year = tvb_get_guint8(tvb, offset+tag_len);
	month = tvb_get_guint8(tvb, offset+tag_len+1);
	day = tvb_get_guint8(tvb, offset+tag_len+2);
	weekday = tvb_get_guint8(tvb, offset+tag_len+3);
	if ((year == 255) && (day == 255) && (month == 255) && (weekday == 255)) {
		ti = proto_tree_add_text(tree, tvb, offset, lvt+tag_len,
			"%sany", label);
	}
	else if (year != 255) {
		year += 1900;
		ti = proto_tree_add_text(tree, tvb, offset, lvt+tag_len,
			"%s%s %d, %d, (Day of Week = %s)",
			label, val_to_str(month,
				months,
				"month (%d) not found"),
			day, year, val_to_str(weekday,
				day_of_week,
				"(%d) not found"));
	} else {
		ti = proto_tree_add_text(tree, tvb, offset, lvt+tag_len,
			"%s%s %d, any year, (Day of Week = %s)",
			label, val_to_str(month, months, "month (%d) not found"),
			day, val_to_str(weekday, day_of_week, "(%d) not found"));
	}
	subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
	fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);

	return offset+tag_len+lvt;
}

static guint
fTime (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label)
{
	guint32 hour, minute, second, msec, lvt;
	guint8 tag_no, tag_info;
	guint tag_len;
	proto_item *ti;
	proto_tree *subtree;

	tag_len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	hour = tvb_get_guint8(tvb, offset+tag_len);
	minute = tvb_get_guint8(tvb, offset+tag_len+1);
	second = tvb_get_guint8(tvb, offset+tag_len+2);
	msec = tvb_get_guint8(tvb, offset+tag_len+3);
	if ((hour == 255) && (minute == 255) && (second == 255) && (msec == 255))
		ti = proto_tree_add_text(tree, tvb, offset,
			lvt+tag_len, "%sany", label);
	else
		ti = proto_tree_add_text(tree, tvb, offset, lvt+tag_len,
			"%s%d:%02d:%02d.%d %s = %02d:%02d:%02d.%d",
			label,
			hour > 12 ? hour - 12 : hour,
			minute, second, msec,
			hour >= 12 ? "P.M." : "A.M.",
			hour, minute, second, msec);
	subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
	fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);

	return offset+tag_len+lvt;
}

static guint
fDateTime (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label)
{
	proto_tree *subtree = tree;
	proto_item *tt;

	if (label != NULL) {
		tt = proto_tree_add_text (subtree, tvb, offset, 1, "%s", label);
		subtree = proto_item_add_subtree(tt, ett_bacapp_value);
	}
	offset = fDate (tvb,subtree,offset,"Date: ");
	return fTime (tvb,subtree,offset,"Time: ");
}

static guint
fTimeValue (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {   /* closing Tag, but not for me */
			return offset;
		}
		offset = fTime    (tvb,tree,offset,"Time: ");
		offset = fApplicationTypes(tvb, pinfo, tree, offset, "Value: ");

		if (offset==lastoffset) break;    /* exit loop if nothing happens inside */
	}
	return offset;
}

static guint
fCalendaryEntry (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint8 tag_no, tag_info;
	guint32 lvt;

	switch (fTagNo(tvb, offset)) {
	case 0:	/* Date */
		offset = fDate    (tvb, tree, offset, "Date: ");
		break;
	case 1:	/* dateRange */
		offset += fTagHeaderTree(tvb, tree, offset, &tag_no, &tag_info, &lvt);
		offset = fDateRange (tvb, tree, offset);
		offset += fTagHeaderTree(tvb, tree, offset, &tag_no, &tag_info, &lvt);
		break;
	case 2:	/* BACnetWeekNDay */
		offset = fWeekNDay (tvb, tree, offset);
		break;
	default:
		return offset;
	}

	return offset;
}

static guint
fTimeStamp (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label)
{
	guint8 tag_no = 0, tag_info = 0;
	guint32 lvt = 0;

	if (tvb_reported_length_remaining(tvb, offset) > 0) {	/* don't loop, it's a CHOICE */
		switch (fTagNo(tvb, offset)) {
		case 0:	/* time */
			offset = fTime (tvb, tree, offset, label?label:"timestamp: ");
			break;
		case 1:	/* sequenceNumber */
			offset = fUnsignedTag (tvb, tree, offset,
				label?label:"sequence Number: ");
			break;
		case 2:	/* dateTime */
			offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
			offset = fDateTime (tvb, tree, offset, label?label:"timestamp: ");
			offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
			break;
		default:
			return offset;
		}
	}

	return offset;
}


static guint
fClientCOV (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	if (tvb_reported_length_remaining(tvb, offset) > 0) {
		offset = fApplicationTypes(tvb,pinfo,tree,offset, "increment: ");
	}
	return offset;
}

static const value_string
BACnetDaysOfWeek [] = {
	{0,"Monday" },
	{1,"Tuesday" },
	{2,"Wednesday" },
	{3,"Thursday" },
	{4,"Friday" },
	{5,"Saturday" },
	{6,"Sunday" },
	{0,NULL }
};

static guint
fDestination (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	if (tvb_reported_length_remaining(tvb, offset) > 0) {
		offset = fApplicationTypesEnumerated(tvb,pinfo,tree,offset,
			"valid Days: ", BACnetDaysOfWeek);
		offset = fTime (tvb,tree,offset,"from time: ");
		offset = fTime (tvb,tree,offset,"to time: ");
		offset = fRecipient (tvb,pinfo,tree,offset);
		offset = fProcessId (tvb,tree,offset);
		offset = fApplicationTypes (tvb,pinfo,tree,offset,
			"issue confirmed notifications: ");
		offset = fBitStringTagVS (tvb,tree,offset,
			"transitions: ", BACnetEventTransitionBits);
	}
	return offset;
}


static guint
fOctetString (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label, guint32 lvt)
{
	gchar *tmp;
	guint start = offset;
	guint8 tag_no, tag_info;
	proto_tree* subtree = tree;
	proto_item* ti = 0;

	offset += fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);

	if (lvt > 0) {
		tmp = tvb_bytes_to_str(tvb, offset, lvt);
		ti = proto_tree_add_text(tree, tvb, offset, lvt, "%s %s", label, tmp);
		offset += lvt;
	}

	if (ti)
		subtree = proto_item_add_subtree(ti, ett_bacapp_tag);

	fTagHeaderTree(tvb, subtree, start, &tag_no, &tag_info, &lvt);

	return offset;
}

static guint
fMacAddress (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label, guint32 lvt)
{
	gchar *tmp;
	guint start = offset;
	guint8 tag_no, tag_info;
	proto_tree* subtree = tree;
	proto_item* ti = 0;

	offset += fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);

	ti = proto_tree_add_text(tree, tvb, offset, 6, "%s", label); /* just add the label, with the tagHeader information in its subtree */

	if (lvt > 0) {
		if (lvt == 6) { /* we have 6 Byte IP Address with 4 Octets IPv4 and 2 Octets Port Information */

			guint32 ip = tvb_get_ipv4(tvb, offset);
			guint16 port =  tvb_get_ntohs(tvb, offset+4);

			proto_tree_add_ipv4(tree, hf_bacapp_tag_IPV4, tvb, offset, 4, ip);
			proto_tree_add_uint(tree, hf_bacapp_tag_PORT, tvb, offset+4, 2, port);

		} else {
			if (lvt == 18) { /* we have 18 Byte IP Address with 16 Octets IPv6 and 2 Octets Port Information */
			struct e_in6_addr addr;
			guint16 port =  tvb_get_ntohs(tvb, offset+16);
			tvb_get_ipv6(tvb, offset, &addr);

			proto_tree_add_ipv6(tree, hf_bacapp_tag_IPV6, tvb, offset, 16, (const guint8 *) &addr);
			proto_tree_add_uint(tree, hf_bacapp_tag_PORT, tvb, offset+16, 2, port);

			} else { /* we have 1 Byte MS/TP Address or anything else interpreted as an address */
				tmp = tvb_bytes_to_str(tvb, offset, lvt);
				ti = proto_tree_add_text(tree, tvb, offset, lvt, "%s", tmp);
			}
		}
		offset += lvt;
	}

	if (ti)
		subtree = proto_item_add_subtree(ti, ett_bacapp_tag);

	fTagHeaderTree(tvb, subtree, start, &tag_no, &tag_info, &lvt);

	return offset;
}

static guint
fAddress (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint8 tag_no, tag_info;
	guint32 lvt;
	guint offs;

	offset = fUnsignedTag (tvb, tree, offset, "network-number");
	offs = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	if (lvt == 0) {
		proto_tree_add_text(tree, tvb, offset, offs, "MAC-address: broadcast");
		offset += offs;
	} else
		offset = fMacAddress (tvb, tree, offset, "MAC-address: ", lvt);

	return offset;
}

static guint
fSessionKey (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	offset = fOctetString (tvb,tree,offset,"session key: ", 8);
	return fAddress (tvb,tree,offset);
}

static guint
fObjectIdentifier (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint8  tag_no, tag_info;
	guint32 lvt;
	guint tag_length;
	proto_item *ti;
	proto_tree *subtree;
	guint32 object_id;

	tag_length = fTagHeader(tvb, offset, &tag_no, &tag_info, &lvt);
	object_id = tvb_get_ntohl(tvb,offset+tag_length);
	object_type = object_id_type(object_id);
	ti = proto_tree_add_text(tree, tvb, offset, tag_length + 4,
		"ObjectIdentifier: %s, %u",
		val_to_split_str(object_type,
			128,
			BACnetObjectType,
			ASHRAE_Reserved_Fmt,
			Vendor_Proprietary_Fmt),
		object_id_instance(object_id));
	if (col_get_writable(pinfo->cinfo))
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s,%u ",
			val_to_split_str(object_type,
				128,
				BACnetObjectType,
				ASHRAE_Reserved_Fmt,
				Vendor_Proprietary_Fmt),
				object_id_instance(object_id));

	/* update BACnet Statistics */
	updateBacnetInfoValue(BACINFO_OBJECTID,
			      ep_strdup(val_to_split_str(object_type, 128,
					BACnetObjectType, ASHRAE_Reserved_Fmt,
					Vendor_Proprietary_Fmt)));
	updateBacnetInfoValue(BACINFO_INSTANCEID, ep_strdup_printf("Instance ID: %u",
			      object_id_instance(object_id)));

	/* here are the details of how we arrived at the above text */
	subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
	fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
	offset += tag_length;
	proto_tree_add_item(subtree, hf_bacapp_objectType, tvb, offset, 4, FALSE);
	proto_tree_add_item(subtree, hf_bacapp_instanceNumber, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;
}

static guint
fRecipient (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint8  tag_no, tag_info;
	guint32 lvt;

	fTagHeader(tvb, offset, &tag_no, &tag_info, &lvt);
	if (tag_no < 2) {
		if (tag_no == 0) { /* device */
			offset = fObjectIdentifier (tvb, pinfo, tree, offset);
		}
		else {	/* address */
			offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
			offset = fAddress (tvb, tree, offset);
			offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
		}
	}
	return offset;
}

static guint
fRecipientProcess (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8  tag_no, tag_info;
	guint32 lvt;
	proto_tree* orgtree = tree;
	proto_item* tt;
	proto_tree* subtree;

	/* beginning of new item - indent and label */
	tt = proto_tree_add_text(orgtree, tvb, offset, 1, "Recipient Process" );
	tree = proto_item_add_subtree(tt, ett_bacapp_value);

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;

		switch (fTagNo(tvb, offset)) {
		case 0:	/* recipient */
			offset += fTagHeaderTree(tvb, tree, offset, &tag_no, &tag_info, &lvt); /* show context open */
			tt = proto_tree_add_text(tree, tvb, offset, 1, "Recipient");	/* add tree label and indent */
			subtree = proto_item_add_subtree(tt, ett_bacapp_value);
			offset = fRecipient (tvb, pinfo, subtree, offset);
			offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);	/* show context close */
			break;
		case 1:	/* processId */
			offset = fProcessId (tvb, tree, offset);
			lastoffset = offset;
			break;
		default:
			break;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fCOVSubscription (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8  tag_no, tag_info;
	guint32 lvt;
	proto_tree* subtree;
	proto_item *tt;
	proto_tree* orgtree = tree;
	guint itemno = 1;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info) ) {
			return offset;
		}
		switch (tag_no) {

		case 0:	/* recipient */
				/* beginning of new item in list */
				tt = proto_tree_add_text(orgtree, tvb, offset, 1, "Subscription %d",itemno);	/* add tree label and indent */
				itemno = itemno + 1;
				tree = proto_item_add_subtree(tt, ett_bacapp_value);

				tt = proto_tree_add_text(tree, tvb, offset, 1, "Recipient");	/* add tree label and indent */
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt); /* show context open */
				offset = fRecipientProcess (tvb, pinfo, subtree, offset);
				offset += fTagHeaderTree (tvb, subtree, offset,	&tag_no, &tag_info, &lvt);	/* show context close */
				subtree = tree;	/* done with this level - return to previous tree */
			break;
		case 1: /* MonitoredPropertyReference */
				tt = proto_tree_add_text(tree, tvb, offset, 1, "Monitored Property Reference");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fBACnetObjectPropertyReference (tvb, pinfo, subtree, offset);
				offset += fTagHeaderTree (tvb, subtree, offset,	&tag_no, &tag_info, &lvt);
				subtree = tree;
			break;
		case 2: /* IssueConfirmedNotifications - boolean */
			offset = fBooleanTag (tvb, tree, offset, "Issue Confirmed Notifications: ");
			break;
		case 3:	/* TimeRemaining */
			offset = fUnsignedTag (tvb, tree, offset, "Time Remaining: ");
			break;
		case 4: /* COVIncrement */
			offset = fRealTag (tvb, tree, offset, "COV Increment: ");
			break;
		default:
			break;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fAddressBinding (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	offset = fObjectIdentifier (tvb, pinfo, tree, offset);
	return fAddress (tvb, tree, offset);
}

static guint
fActionCommand (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint8 tag_match)
{
	guint lastoffset = 0, len;
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_tree *subtree = tree;

	/* set the optional global properties to indicate not-used */
	propertyArrayIndex = -1;
	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info) ) {
			if (tag_no == tag_match) {
				return offset;
			}
			offset += len;
			subtree = tree;
			continue;
		}
		switch (tag_no) {

		case 0: /* deviceIdentifier */
			offset = fObjectIdentifier (tvb, pinfo, subtree, offset);
			break;
		case 1: /* objectIdentifier */
			offset = fObjectIdentifier (tvb, pinfo, subtree, offset);
			break;
		case 2: /* propertyIdentifier */
			offset = fPropertyIdentifier (tvb, pinfo, subtree, offset);
			break;
		case 3: /* propertyArrayIndex */
			offset = fPropertyArrayIndex (tvb, subtree, offset);
			break;
		case 4: /* propertyValue */
			offset = fPropertyValue (tvb, pinfo, subtree, offset, tag_info);
			break;
		case 5: /* priority */
			offset = fUnsignedTag (tvb,subtree,offset,"Priority: ");
			break;
		case 6: /* postDelay */
			offset = fUnsignedTag (tvb,subtree,offset,"Post Delay: ");
			break;
		case 7: /* quitOnFailure */
			offset = fBooleanTag(tvb, subtree, offset,
				"Quit On Failure: ");
			break;
		case 8: /* writeSuccessful */
			offset = fBooleanTag(tvb, subtree, offset,
				"Write Successful: ");
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

/* BACnetActionList ::= SEQUENCE{
      action [0] SEQUENCE OF BACnetActionCommand
      }
*/
static guint
fActionList (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0, len;
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *ti;

	while (tvb_reported_length_remaining(tvb, offset)) {
		lastoffset = offset;
		len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {
			offset += len;
			subtree = tree;
			continue;
		}
		if (tag_is_opening(tag_info)) {
			ti = proto_tree_add_text(tree, tvb, offset, 1, "Action List");
			subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
			offset += fTagHeaderTree (tvb, subtree, offset,
				&tag_no, &tag_info, &lvt);
		}
		switch (tag_no) {
			case 0: /* BACnetActionCommand */
				offset = fActionCommand (tvb, pinfo, subtree, offset, tag_no);
				break;
			default:
				break;
		}
		if (offset == lastoffset) break;    /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fPropertyIdentifier (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint8 tag_no, tag_info;
	guint32 lvt;
	guint tag_len;
	proto_item *ti;
	proto_tree *subtree;
	const gchar *label = "Property Identifier";

	propertyIdentifier = 0; /* global Variable */
	tag_len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	/* can we decode this value? */
	if (fUnsigned32 (tvb, offset+tag_len, lvt, (guint32 *)&propertyIdentifier)) {
		ti = proto_tree_add_text(tree, tvb, offset, lvt+tag_len,
			"%s: %s (%u)", label,
			val_to_split_str(propertyIdentifier, 512,
				BACnetPropertyIdentifier,
				ASHRAE_Reserved_Fmt,
				Vendor_Proprietary_Fmt), propertyIdentifier);
		if (col_get_writable(pinfo->cinfo))
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
				val_to_split_str(propertyIdentifier, 512,
					BACnetPropertyIdentifier,
					ASHRAE_Reserved_Fmt,
					Vendor_Proprietary_Fmt));
	} else {
		/* property identifiers cannot be larger than 22-bits */
		return offset;
	}
	subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
	fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
	proto_tree_add_item(subtree, hf_BACnetPropertyIdentifier, tvb,
		offset+tag_len, lvt, FALSE);

	return offset+tag_len+lvt;
}

static guint
fPropertyArrayIndex (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint8 tag_no, tag_info;
	guint32 lvt;
	guint tag_len;
	proto_item *ti;
	proto_tree *subtree;

	tag_len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	if (fUnsigned32 (tvb, offset + tag_len, lvt, (guint32 *)&propertyArrayIndex))
		ti = proto_tree_add_text(tree, tvb, offset, lvt+tag_len,
			"property Array Index (Unsigned) %u", propertyArrayIndex);
	else
		ti = proto_tree_add_text(tree, tvb, offset, lvt+tag_len,
			"property Array Index - %u octets (Unsigned)", lvt);
	subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
	fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);

	return offset+tag_len+lvt;
}

static guint
fCharacterString (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label)
{
	guint8 tag_no, tag_info, character_set;
	guint32 lvt, l;
	gsize inbytesleft, outbytesleft = 512;
	guint offs, extra = 1;
	guint8 *str_val;
	const char *coding;
	guint8 bf_arr[512], *out = &bf_arr[0];
	proto_item *ti;
	proto_tree *subtree;
	guint start = offset;

	if (tvb_reported_length_remaining(tvb, offset) > 0) {

		offs = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);

		character_set = tvb_get_guint8(tvb, offset+offs);
		/* Account for code page if DBCS */
		if (character_set == 1) {
		    extra = 3;
		}
		offset += (offs+extra);
		lvt -= (extra);

		do {
			inbytesleft = l = MIN(lvt, 255);
			/*
			 * XXX - are we guaranteed that these encoding
			 * names correspond, on *all* platforms with
			 * iconv(), to the encodings we want?
			 * If not (and perhaps even if so), we should
			 * perhaps have our own iconv() implementation,
			 * with a different name, so that we control the
			 * encodings it supports and the names of those
			 * encodings.
			 *
			 * We should also handle that in the general
			 * string handling code, rather than making it
			 * specific to the BACAPP dissector, as many
			 * other dissectors need to handle various
			 * character encodings.
			 */
			str_val = tvb_get_ephemeral_string(tvb, offset, l);
			/** this decoding may be not correct for multi-byte characters, Lka */
			switch (character_set) {
			case ANSI_X34:
				fConvertXXXtoUTF8(str_val, &inbytesleft, out, &outbytesleft, "ANSI_X3.4");
				coding = "ANSI X3.4";
				break;
			case IBM_MS_DBCS:
				out = str_val;
				coding = "IBM MS DBCS";
				break;
			case JIS_C_6226:
				out = str_val;
				coding = "JIS C 6226";
				break;
			case ISO_10646_UCS4:
				fConvertXXXtoUTF8(str_val, &inbytesleft, out, &outbytesleft, "UCS-4BE");
				coding = "ISO 10646 UCS-4";
				break;
			case ISO_10646_UCS2:
				fConvertXXXtoUTF8(str_val, &inbytesleft, out, &outbytesleft, "UCS-2BE");
				coding = "ISO 10646 UCS-2";
				break;
			case ISO_18859_1:
				fConvertXXXtoUTF8(str_val, &inbytesleft, out, &outbytesleft, "ISO8859-1");
				coding = "ISO 8859-1";
				break;
			default:
				out = str_val;
				coding = "unknown";
				break;
			}
			ti = proto_tree_add_text(tree, tvb, offset, l, "%s%s '%s'", label, coding, out);
			lvt-=l;
			offset+=l;
		} while (lvt > 0);

		subtree = proto_item_add_subtree(ti, ett_bacapp_tag);

		fTagHeaderTree (tvb, subtree, start, &tag_no, &tag_info, &lvt);
		proto_tree_add_item(subtree, hf_BACnetCharacterSet, tvb, start+offs, 1, FALSE);

		if (character_set == 1) {
		    proto_tree_add_text(subtree, tvb, start+offs+1, 2, "Code Page: %d", tvb_get_ntohs(tvb, start+offs+1));
		}
		/* XXX - put the string value here */
	}
	return offset;
}

static guint
fBitStringTagVS (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label,
	const value_string *src)
{
	guint8 tag_no, tag_info, tmp;
	gint j, unused, skip;
	guint start = offset;
	guint offs;
	guint32 lvt, i, numberOfBytes;
	guint8 bf_arr[256];
	proto_tree* subtree = tree;
	proto_item* ti = 0;

	offs = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	numberOfBytes = lvt-1; /* Ignore byte for unused bit count */
	offset+=offs;
	unused = tvb_get_guint8(tvb, offset); /* get the unused Bits */
	ti = proto_tree_add_text(tree, tvb, start, offs+lvt,
				"%s(Bit String)",
				label);
	if (ti) {
		subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
	}
	fTagHeaderTree(tvb, subtree, start, &tag_no, &tag_info, &lvt);
	proto_tree_add_text(subtree, tvb, offset, 1,
				"Unused bits: %u",
				unused);
	skip = 0;
	for (i = 0; i < numberOfBytes; i++) {
		tmp = tvb_get_guint8(tvb, (offset)+i+1);
		if (i == numberOfBytes-1) { skip = unused; }
		for (j = 0; j < 8-skip; j++) {
			if (src != NULL) {
				if (tmp & (1 << (7 - j)))
					proto_tree_add_text(subtree, tvb,
						offset+i+1, 1,
						"%s = TRUE",
						val_to_str((guint) (i*8 +j),
							src,
							ASHRAE_Reserved_Fmt));
				else
					proto_tree_add_text(subtree, tvb,
						offset+i+1, 1,
						"%s = FALSE",
						val_to_str((guint) (i*8 +j),
							src,
							ASHRAE_Reserved_Fmt));
			} else {
				bf_arr[MIN(255,(i*8)+j)] = tmp & (1 << (7 - j)) ? '1' : '0';
			}
		}
	}

	if (src == NULL) {
		bf_arr[MIN(255,numberOfBytes*8-unused)] = 0;
		proto_tree_add_text(subtree, tvb, offset, lvt, "B'%s'", bf_arr);
	}

	offset+=lvt;

	return offset;
}

static guint
fBitStringTag (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label)
{
	return fBitStringTagVS (tvb, tree, offset, label, NULL);
}

/* handles generic application types, as well as enumerated and enumerations
   with reserved and proprietarty ranges (split) */
static guint
fApplicationTypesEnumeratedSplit (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset,
	const gchar *label, const value_string *src, guint32 split_val)
{
	guint8 tag_no, tag_info;
	guint32 lvt;
	guint tag_len;

	if (tvb_reported_length_remaining(tvb, offset) > 0) {

		tag_len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (!tag_is_context_specific(tag_info)) {
			switch (tag_no) {
				case 0:	/** NULL 20.2.2 */
					offset = fNullTag(tvb, tree, offset, label);
					break;
				case 1:	/** BOOLEAN 20.2.3 */
					offset = fBooleanTag(tvb, tree, offset, label);
					break;
				case 2:	/** Unsigned Integer 20.2.4 */
					offset = fUnsignedTag(tvb, tree, offset, label);
					break;
				case 3:	/** Signed Integer 20.2.5 */
					offset = fSignedTag(tvb, tree, offset, label);
					break;
				case 4:	/** Real 20.2.6 */
					offset = fRealTag(tvb, tree, offset, label);
					break;
				case 5:	/** Double 20.2.7 */
					offset = fDoubleTag(tvb, tree, offset, label);
					break;
				case 6: /** Octet String 20.2.8 */
					offset = fOctetString (tvb, tree, offset, label, lvt);
					break;
				case 7: /** Character String 20.2.9 */
					offset = fCharacterString (tvb,tree,offset,label);
					break;
				case 8: /** Bit String 20.2.10 */
					offset = fBitStringTagVS (tvb, tree, offset, label, src);
					break;
				case 9: /** Enumerated 20.2.11 */
					offset = fEnumeratedTagSplit (tvb, tree, offset, label, src, split_val);
					break;
				case 10: /** Date 20.2.12 */
					offset = fDate (tvb, tree, offset, label);
					break;
				case 11: /** Time 20.2.13 */
					offset = fTime (tvb, tree, offset, label);
					break;
				case 12: /** BACnetObjectIdentifier 20.2.14 */
					offset = fObjectIdentifier (tvb, pinfo, tree, offset);
					break;
				case 13: /* reserved for ASHRAE */
				case 14:
				case 15:
					proto_tree_add_text(tree, tvb, offset, lvt+tag_len, "%s'reserved for ASHRAE'", label);
					offset+=lvt+tag_len;
					break;
				default:
					break;
			}

		}
	}
	return offset;
}

static guint
fShedLevel (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;

		switch (fTagNo(tvb,offset)) {
		case 0:	/* percent */
			offset = fUnsignedTag (tvb, tree, offset, "shed percent: ");
			break;
		case 1:	/* level */
			offset = fUnsignedTag (tvb, tree, offset, "shed level: ");
			break;
		case 2:	/* amount */
			offset = fRealTag(tvb, tree, offset, "shed amount: ");
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fApplicationTypesEnumerated (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset,
	const gchar *label, const value_string *vs)
{
	return fApplicationTypesEnumeratedSplit(tvb, pinfo, tree, offset, label, vs, 0);
}

static guint
fApplicationTypes (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset,
	const gchar *label)
{
	return fApplicationTypesEnumeratedSplit(tvb, pinfo, tree, offset, label, NULL, 0);
}

static guint
fContextTaggedValue(tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label)
{
	guint8 tag_no, tag_info;
	guint32 lvt;
	guint tag_len;
	proto_item *ti;
	proto_tree *subtree;
	gint tvb_len;

	(void)label;
	tag_len = fTagHeader(tvb, offset, &tag_no, &tag_info, &lvt);
	/* cap the the suggested length in case of bad data */
	tvb_len = tvb_reported_length_remaining(tvb, offset+tag_len);
	if ((tvb_len >= 0) && ((guint32)tvb_len < lvt)) {
		lvt = tvb_len;
	}
	ti = proto_tree_add_text(tree, tvb, offset+tag_len, lvt,
		"Context Value (as %u DATA octets)", lvt);

	subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
	fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);

	return offset + tag_len + lvt;
}

static guint
fAbstractSyntaxNType (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint8 tag_no, tag_info;
	guint32 lvt;
	guint lastoffset = 0, depth = 0;
	char ar[256];

	if (propertyIdentifier >= 0) {
		g_snprintf (ar, sizeof(ar), "%s: ",
			val_to_split_str(propertyIdentifier, 512,
				BACnetPropertyIdentifier,
				ASHRAE_Reserved_Fmt,
				Vendor_Proprietary_Fmt));
	} else {
		g_snprintf (ar, sizeof(ar), "Abstract Type: ");
	}
	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) { /* closing tag, but not for me */
			if (depth <= 0) return offset;
		}

		/* Application Tags */
		switch (propertyIdentifier) {
		case 2: /* action */
			/* loop object is application tagged,
				command object is context tagged */
			if (tag_is_context_specific(tag_info)) {
				/* BACnetActionList */
				offset = fActionList (tvb, pinfo, tree,offset);
			} else {
				/* BACnetAction */
				offset = fApplicationTypesEnumerated (tvb, pinfo, tree, offset, ar,
					BACnetAction);
			}
			break;
		case 30: /* BACnetAddressBinding */
			offset = fAddressBinding (tvb,pinfo,tree,offset);
			break;
		case 54: /* list of object property reference */
			offset = fLOPR (tvb, pinfo, tree,offset);
			break;
		case 55: /* list-of-session-keys */
			fSessionKey (tvb, tree, offset);
			break;
		case 79: /* object-type */
		case 96: /* protocol-object-types-supported */
			offset = fApplicationTypesEnumeratedSplit (tvb, pinfo, tree, offset, ar,
				BACnetObjectType, 128);
			break;
		case 97: /* Protocol-Services-Supported */
			offset = fApplicationTypesEnumerated (tvb, pinfo, tree, offset, ar,
				BACnetServicesSupported);
			break;
		case 102: /* recipient-list */
			offset = fDestination (tvb, pinfo, tree, offset);
			break;
		case 107: /* segmentation-supported */
			offset = fApplicationTypesEnumerated (tvb, pinfo, tree, offset, ar,
				BACnetSegmentation);
			break;
		case 111: /* Status-Flags */
			offset = fApplicationTypesEnumerated (tvb, pinfo, tree, offset, ar,
				BACnetStatusFlags);
			break;
		case 112: /* System-Status */
			offset = fApplicationTypesEnumerated (tvb, pinfo, tree, offset, ar,
				BACnetDeviceStatus);
			break;
		case 117: /* units */
			offset = fApplicationTypesEnumerated (tvb, pinfo, tree, offset, ar,
				BACnetEngineeringUnits);
			break;
		case 87:	/* priority-array -- accessed as a BACnetARRAY */
			if (propertyArrayIndex == 0) {
				/* BACnetARRAY index 0 refers to the length
				of the array, not the elements of the array */
				offset = fApplicationTypes (tvb, pinfo, tree, offset, ar);
			} else {
				offset = fPriorityArray (tvb, pinfo, tree, offset);
			}
			break;
		case 38:	/* exception-schedule */
			if (object_type < 128) {
				if (propertyArrayIndex == 0) {
					/* BACnetARRAY index 0 refers to the length
					of the array, not the elements of the array */
					offset = fApplicationTypes (tvb, pinfo, tree, offset, ar);
				} else {
					offset = fSpecialEvent (tvb,pinfo,tree,offset);
				}
			}
			break;
		case 19:  /* controlled-variable-reference */
		case 60:  /* manipulated-variable-reference */
		case 109: /* Setpoint-Reference */
		case 132: /* log-device-object-property */
			offset = fDeviceObjectPropertyReference (tvb, pinfo, tree, offset);
			break;
		case 123:	/* weekly-schedule -- accessed as a BACnetARRAY */
			if (object_type < 128) {
				if (propertyArrayIndex == 0) {
					/* BACnetARRAY index 0 refers to the length
					of the array, not the elements of the array */
					offset = fApplicationTypes (tvb, pinfo, tree, offset, ar);
				} else {
					offset = fWeeklySchedule (tvb, pinfo, tree, offset);
				}
			}
			break;
		case 127:	/* client COV increment */
			offset = fClientCOV (tvb, pinfo, tree, offset);
			break;
		case 131:  /* log-buffer */
			offset = fLogRecord (tvb, pinfo, tree, offset);
			break;
		case 159: /* member-of */
		case 165: /* zone-members */
			offset = fDeviceObjectReference (tvb, pinfo, tree, offset);
			break;
		case 196: /* last-restart-reason */
			offset = fRestartReason (tvb, pinfo, tree, offset);
			break;
		case 212: /* actual-shed-level */
		case 214: /* expected-shed-level */
		case 218: /* requested-shed-level */
			offset = fShedLevel (tvb, tree, offset);
			break;
		case 152: /* active-cov-subscriptions */
			offset = fCOVSubscription (tvb, pinfo, tree, offset);
			break;
		default:
			if (tag_info) {
				if (tag_is_opening(tag_info)) {
					++depth;
					offset += fTagHeaderTree(tvb, tree, offset, &tag_no, &tag_info, &lvt);
				} else if (tag_is_closing(tag_info)) {
					--depth;
					offset += fTagHeaderTree(tvb, tree, offset, &tag_no, &tag_info, &lvt);
				} else {
					offset = fContextTaggedValue(tvb, tree, offset, ar);
				}
			} else {
				offset = fApplicationTypes (tvb, pinfo, tree, offset, ar);
			}
			break;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;

}

static guint
fPropertyValue (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint8 tag_info)
{
	guint8 tag_no;
	guint32 lvt;

	if (tag_is_opening(tag_info)) {
		offset += fTagHeaderTree(tvb, tree, offset,
			&tag_no, &tag_info, &lvt);
		offset = fAbstractSyntaxNType (tvb, pinfo, tree, offset);
		if (tvb_length_remaining(tvb, offset) > 0) {
			offset += fTagHeaderTree(tvb, tree, offset,
				&tag_no, &tag_info, &lvt);
		}
	} else {
		proto_tree_add_text(tree, tvb, offset, tvb_length(tvb) - offset,
			"expected Opening Tag!"); \
		offset = tvb_length(tvb);
	}

	return offset;
}


static guint
fPropertyIdentifierValue (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint8 tagoffset)
{
	guint lastoffset = offset;
	guint8 tag_no, tag_info;
	guint32 lvt;

	offset = fPropertyReference(tvb, pinfo, tree, offset, tagoffset, 0);
	if (offset > lastoffset) {
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_no == tagoffset+2) {  /* Value - might not be present in ReadAccessResult */
			offset = fPropertyValue (tvb, pinfo, tree, offset, tag_info);
		}
	}
	return offset;
}

static guint
fBACnetPropertyValue (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		offset = fPropertyIdentifierValue(tvb, pinfo, tree, offset, 0);
		if (offset > lastoffset) {
			/* detect optional priority
			by looking to see if the next tag is context tag number 3 */
			fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
			if (tag_is_context_specific(tag_info) && (tag_no == 3))
				offset = fUnsignedTag (tvb,tree,offset,"Priority: ");
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fSubscribeCOVPropertyRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0, len;
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {
			offset += len;
			subtree = tree;
			continue;
		}

		switch (tag_no) {
		case 0:	/* ProcessId */
			offset = fUnsignedTag (tvb, tree, offset, "subscriber Process Id: ");
			break;
		case 1: /* monitored ObjectId */
			offset = fObjectIdentifier (tvb, pinfo, tree, offset);
			break;
		case 2: /* issueConfirmedNotifications */
			offset = fBooleanTag (tvb, tree, offset, "issue Confirmed Notifications: ");
			break;
		case 3:	/* life time */
			offset = fTimeSpan (tvb,tree,offset,"life time");
			break;
		case 4:	/* monitoredPropertyIdentifier */
			if (tag_is_opening(tag_info)) {
				tt = proto_tree_add_text(subtree, tvb, offset, 1, "monitoredPropertyIdentifier");
				if (tt) {
					subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				}
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fBACnetPropertyReference (tvb, pinfo, subtree, offset, 1);
				break;
			}
			FAULT;
			break;
		case 5:	/* covIncrement */
			offset = fRealTag (tvb, tree, offset, "COV Increment: ");
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fSubscribeCOVRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	return fSubscribeCOVPropertyRequest(tvb, pinfo, tree, offset);
}

static guint
fWhoHas (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;

		switch (fTagNo(tvb, offset)) {
		case 0: /* deviceInstanceLowLimit */
			offset = fUnsignedTag (tvb, tree, offset, "device Instance Low Limit: ");
			break;
		case 1: /* deviceInstanceHighLimit */
			offset = fUnsignedTag (tvb, tree, offset, "device Instance High Limit: ");
			break;
		case 2: /* BACnetObjectId */
			offset = fObjectIdentifier (tvb, pinfo, tree, offset);
			break;
		case 3: /* messageText */
			offset = fCharacterString (tvb,tree,offset, "Object Name: ");
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}


static guint
fDailySchedule (tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;

	fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	if (tag_is_opening(tag_info) && tag_no == 0) {
		offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt); /* opening context tag 0 */
		while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
			lastoffset = offset;
			fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
			if (tag_is_closing(tag_info)) {
				/* should be closing context tag 0 */
				offset += fTagHeaderTree (tvb, subtree, offset,	&tag_no, &tag_info, &lvt);
				return offset;
			}

			offset = fTimeValue (tvb, pinfo, subtree, offset);
			if (offset == lastoffset) break;    /* nothing happened, exit loop */
		}
	} else if (tag_no == 0 && lvt == 0) {
		/* not sure null (empty array element) is legal */
		offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
	}
	return offset;
}

static guint
fWeeklySchedule (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;
	guint i = 1; /* day of week array index */
	proto_tree *subtree = tree;
	proto_item *tt;

	if (propertyArrayIndex > 0) {
		/* BACnetARRAY index 0 refers to the length
		of the array, not the elements of the array.
		BACnetARRAY index -1 is our internal flag that
		the optional index was not used.
		BACnetARRAY refers to this as all elements of the array.
		If the optional index is specified for a BACnetARRAY,
		then that specific array element is referenced. */
		i = propertyArrayIndex;
	}
	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {
			return offset; /* outer encoding will print out closing tag */
		}
		tt = proto_tree_add_text(tree, tvb, offset, 0, "%s", val_to_str(i++, day_of_week, "day of week (%d) not found"));
		subtree = proto_item_add_subtree(tt, ett_bacapp_value);
		offset = fDailySchedule (tvb, pinfo, subtree, offset);
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}


static guint
fUTCTimeSynchronizationRequest  (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	if (tvb_reported_length_remaining(tvb, offset) <= 0)
		return offset;

	return fDateTime (tvb, tree, offset, "UTC-Time: ");
}

static guint
fTimeSynchronizationRequest  (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	if (tvb_reported_length_remaining(tvb, offset) <= 0)
		return offset;

	return fDateTime (tvb, tree, offset, NULL);
}

static guint
fDateRange  (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	if (tvb_reported_length_remaining(tvb, offset) <= 0)
		return offset;
	offset = fDate (tvb,tree,offset,"Start Date: ");
	return fDate (tvb, tree, offset, "End Date: ");
}

static guint
fVendorIdentifier (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint32 val = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;
	guint tag_len;
	proto_item *ti;
	proto_tree *subtree;
	const gchar *label = "Vendor ID";

	tag_len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	if (fUnsigned32 (tvb, offset + tag_len, lvt, &val))
		ti = proto_tree_add_text(tree, tvb, offset, lvt+tag_len,
			"%s: %s (%u)", label,
			val_to_str(val,BACnetVendorIdentifiers,"Unknown Vendor"), val);
	else
		ti = proto_tree_add_text(tree, tvb, offset, lvt+tag_len,
			"%s - %u octets (Unsigned)", label, lvt);
	subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
	fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);

	if ((lvt < 1) || (lvt > 2)) { /* vendorIDs >= 1  and <= 2 are supported */
		proto_item *expert_item;
		expert_item = proto_tree_add_text(tree, tvb, 0, lvt, "Wrong length indicated. Expected 1 or 2, got %u", lvt);
		expert_add_info_format(pinfo, expert_item, PI_MALFORMED, PI_ERROR, "Wrong length indicated. Expected 1 or 2, got %u", lvt);
		PROTO_ITEM_SET_GENERATED(expert_item);
		return offset+tag_len+lvt;
	}

	proto_tree_add_item(subtree, hf_BACnetVendorIdentifier, tvb,
		offset+tag_len, lvt, FALSE);

	return offset+tag_len+lvt;
}

static guint
fRestartReason (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint32 val = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;
	guint tag_len;
	proto_item *ti;
	proto_tree *subtree;
	const gchar *label = "Restart Reason";

	tag_len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	if (fUnsigned32 (tvb, offset + tag_len, lvt, &val))
		ti = proto_tree_add_text(tree, tvb, offset, lvt+tag_len,
			"%s: %s (%u)", label,
			val_to_str(val,BACnetRestartReason,"Unknown reason"), val);
	else
		ti = proto_tree_add_text(tree, tvb, offset, lvt+tag_len,
			"%s - %u octets (Unsigned)", label, lvt);
	subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
	fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);

	if (lvt != 1) {
		proto_item *expert_item;
		expert_item = proto_tree_add_text(tree, tvb, 0, lvt, "Wrong length indicated. Expected 1, got %u", lvt);
		expert_add_info_format(pinfo, expert_item, PI_MALFORMED, PI_ERROR, "Wrong length indicated. Expected 1, got %u", lvt);
		PROTO_ITEM_SET_GENERATED(expert_item);
		return offset+tag_len+lvt;
	}

	proto_tree_add_item(subtree, hf_BACnetRestartReason, tvb,
		offset+tag_len, lvt, FALSE);

	return offset+tag_len+lvt;
}

static guint
fConfirmedTextMessageRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		switch (fTagNo(tvb, offset)) {

		case 0:	/* textMessageSourceDevice */
			offset = fObjectIdentifier (tvb, pinfo, tree, offset);
			break;
		case 1: /* messageClass */
			switch (fTagNo(tvb, offset)) {
			case 0: /* numeric */
				offset = fUnsignedTag (tvb, tree, offset, "message Class: ");
				break;
			case 1: /* character */
				offset = fCharacterString (tvb, tree, offset, "message Class: ");
				break;
			}
			break;
		case 2: /* messagePriority */
			offset = fEnumeratedTag (tvb, tree, offset, "message Priority: ",
				BACnetMessagePriority);
			break;
		case 3: /* message */
			offset = fCharacterString (tvb, tree, offset, "message: ");
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fUnconfirmedTextMessageRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	return fConfirmedTextMessageRequest(tvb, pinfo, tree, offset);
}

static guint
fConfirmedPrivateTransferRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0, len;
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;
	tvbuff_t *next_tvb;
	guint vendor_identifier = 0;
	guint service_number = 0;

	lastoffset = offset;
	len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	fUnsigned32(tvb, offset+len, lvt, &vendor_identifier);
	if (col_get_writable(pinfo->cinfo))
		col_append_fstr(pinfo->cinfo, COL_INFO, "V=%u ", vendor_identifier);
	offset = fVendorIdentifier (tvb, pinfo, subtree, offset);

	next_tvb = tvb_new_subset_remaining(tvb,offset);
	if (dissector_try_uint(bacapp_dissector_table,
	    vendor_identifier, next_tvb, pinfo, tree)) {
		/* we parsed it so skip over length and we are done */
		offset += tvb_length(next_tvb);
		return offset;
	}

	/* Not handled by vendor dissector */

	/* exit loop if nothing happens inside */
	while (tvb_reported_length_remaining(tvb, offset)) {
		lastoffset = offset;
		len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {
			if (tag_no == 2) { /* Make sure it's the expected tag */
				offset += len;
				subtree = tree;
				continue;
			} else {
				break; /* End loop if incorrect closing tag */
			}
		}
		switch (tag_no) {

			/* vendorID is now parsed above */
		case 1: /* serviceNumber */
			fUnsigned32(tvb, offset+len, lvt, &service_number);
			if (col_get_writable(pinfo->cinfo))
				col_append_fstr(pinfo->cinfo, COL_INFO, "SN=%u ",	service_number);
			offset = fUnsignedTag (tvb, subtree, offset, "service Number: ");
			break;
		case 2: /*serviceParameters */
			if (tag_is_opening(tag_info)) {
				tt = proto_tree_add_text(subtree, tvb, offset, 1, "service Parameters");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				propertyIdentifier = -1;
				offset = fAbstractSyntaxNType (tvb, pinfo, subtree, offset);
				break;
			}
			FAULT;
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}

	return offset;
}

static guint
fUnconfirmedPrivateTransferRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	return fConfirmedPrivateTransferRequest(tvb, pinfo, tree, offset);
}

static guint
fConfirmedPrivateTransferAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	return fConfirmedPrivateTransferRequest(tvb, pinfo, tree, offset);
}

static guint
fLifeSafetyOperationRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	if (label != NULL) {
		tt = proto_tree_add_text (subtree, tvb, offset, 1, "%s", label);
		subtree = proto_item_add_subtree(tt, ett_bacapp_value);
	}

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);

		switch (tag_no) {
		case 0:	/* subscriberProcessId */
			offset = fUnsignedTag (tvb, subtree, offset, "requesting Process Id: ");
			break;
		case 1: /* requestingSource */
			offset = fCharacterString (tvb, tree, offset, "requesting Source: ");
			break;
		case 2: /* request */
			offset = fEnumeratedTagSplit (tvb, tree, offset,
				"request: ", BACnetLifeSafetyOperation, 64);
			break;
		case 3:	/* objectId */
			offset = fObjectIdentifier (tvb, pinfo, subtree, offset);
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fBACnetPropertyStates(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	switch (fTagNo(tvb, offset))
	{
	case 0:
		offset = fBooleanTag (tvb, tree, offset, "boolean-value: ");
		break;
	case 1:
		offset = fEnumeratedTagSplit (tvb, tree, offset,
			"binary-value: ", BACnetBinaryPV, 2);
		break;
	case 2:
		offset = fEnumeratedTagSplit (tvb, tree, offset,
			"event-type: ", BACnetEventType, 12);
		break;
	case 3:
		offset = fEnumeratedTagSplit (tvb, tree, offset,
			"polarity: ", BACnetPolarity, 2);
		break;
	case 4:
		offset = fEnumeratedTagSplit (tvb, tree, offset,
			"program-change: ", BACnetProgramRequest, 5);
		break;
	case 5:
		offset = fEnumeratedTagSplit (tvb, tree, offset,
			"program-state: ", BACnetProgramState, 5);
		break;
	case 6:
		offset = fEnumeratedTagSplit (tvb, tree, offset,
			"reason-for-halt: ", BACnetProgramError, 5);
		break;
	case 7:
		offset = fEnumeratedTagSplit (tvb, tree, offset,
			"reliability: ", BACnetReliability, 10);
		break;
	case 8:
		offset = fEnumeratedTagSplit (tvb, tree, offset,
			"state: ", BACnetEventState, 64);
		break;
	case 9:
		offset = fEnumeratedTagSplit (tvb, tree, offset,
			"system-status: ", BACnetDeviceStatus, 64);
		break;
	case 10:
		offset = fEnumeratedTagSplit (tvb, tree, offset,
			"units: ", BACnetEngineeringUnits, 2);
		break;
	case 11:
		offset = fUnsignedTag(tvb, tree, offset, "unsigned-value: ");
		break;
	case 12:
		offset = fEnumeratedTagSplit (tvb, tree, offset,
			"life-safety-mode: ", BACnetLifeSafetyMode, 64);
		break;
	case 13:
		offset = fEnumeratedTagSplit (tvb, tree, offset,
			"life-safety-state: ", BACnetLifeSafetyState, 64);
		break;
	default:
		break;
	}
	return offset;
}


/*
BACnetDeviceObjectPropertyValue ::= SEQUENCE {
      deviceIdentifier       [0]      BACnetObjectIdentifier,
      objectIdentifier       [1]      BACnetObjectIdentifier,
      propertyIdentifier     [2]      BACnetPropertyIdentifier,
      arrayIndex             [3]      Unsigned OPTIONAL,
      value                  [4]      ABSTRACT-SYNTAX.&Type
      }
*/
static guint
fDeviceObjectPropertyValue (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;

	while (tvb_reported_length_remaining(tvb, offset)) {
		lastoffset = offset;
		/* check the tag.  A closing tag means we are done */
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {
			return offset;
		}
		switch (tag_no) {
		case 0:	/* deviceIdentifier */
			offset = fObjectIdentifier (tvb, pinfo, tree, offset);
			break;
		case 1:	/* objectIdentifier */
			offset = fObjectIdentifier (tvb, pinfo, tree, offset);
			break;
		case 2: /* propertyIdentifier */
			offset = fPropertyIdentifier (tvb, pinfo, tree, offset);
			break;
		case 3:	/* arrayIndex - OPTIONAL */
			offset = fUnsignedTag (tvb, tree, offset,
				"arrayIndex: ");
			break;
		case 4: /* value */
			offset += fTagHeaderTree(tvb, tree, offset, &tag_no, &tag_info, &lvt);
			offset = fAbstractSyntaxNType (tvb, pinfo, tree, offset);
			offset += fTagHeaderTree(tvb, tree, offset, &tag_no, &tag_info, &lvt);
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}


/*
BACnetDeviceObjectPropertyReference ::= SEQUENCE {
      objectIdentifier       [0]      BACnetObjectIdentifier,
      propertyIdentifier     [1]      BACnetPropertyIdentifier,
      propertyArrayIndex     [2]      Unsigned OPTIONAL, -- used only with array datatype
                                                                -- if omitted with an array then
                                                                -- the entire array is referenced
      deviceIdentifier       [3]      BACnetObjectIdentifier OPTIONAL
      }
*/
static guint
fDeviceObjectPropertyReference (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;

	while (tvb_reported_length_remaining(tvb, offset)) {
		lastoffset = offset;
		/* check the tag.  A closing tag means we are done */
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {
			return offset;
		}
		switch (tag_no) {
		case 0:	/* objectIdentifier */
			offset = fObjectIdentifier (tvb, pinfo, tree, offset);
			break;
		case 1: /* propertyIdentifier */
			offset = fPropertyIdentifier (tvb, pinfo, tree, offset);
			break;
		case 2:	/* arrayIndex - OPTIONAL */
			offset = fUnsignedTag (tvb, tree, offset,
				"arrayIndex: ");
			break;
		case 3:	/* deviceIdentifier - OPTIONAL */
			offset = fObjectIdentifier (tvb, pinfo, tree, offset);
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fNotificationParameters (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = offset;
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	tt = proto_tree_add_text(subtree, tvb, offset, 0, "notification parameters (%d) %s",
		tag_no, val_to_str(tag_no, BACnetEventType, "invalid type"));
	subtree = proto_item_add_subtree(tt, ett_bacapp_value);
	/* Opening tag for parameter choice */
	offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);

	switch (tag_no) {
	case 0: /* change-of-bitstring */
		while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
			lastoffset = offset;
			switch (fTagNo(tvb, offset)) {
			case 0:
				offset = fBitStringTag (tvb, subtree, offset,
					"referenced-bitstring: ");
				break;
			case 1:
				offset = fBitStringTagVS (tvb, subtree, offset,
					"status-flags: ", BACnetStatusFlags);
	        	lastoffset = offset;
				break;
			default:
				break;
			}
			if (offset == lastoffset) break;     /* nothing happened, exit loop */
		}
		break;
	case 1: /* change-of-state */
		while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
			lastoffset = offset;
			switch (fTagNo(tvb, offset)) {
			case 0:
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fBACnetPropertyStates(tvb, subtree, offset);
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				break;
			case 1:
				offset = fBitStringTagVS (tvb, subtree, offset,
					"status-flags: ", BACnetStatusFlags);
	        	lastoffset = offset;
				break;
			default:
				break;
			}
			if (offset == lastoffset) break;     /* nothing happened, exit loop */
		}
		break;
	case 2: /* change-of-value */
		while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
			lastoffset = offset;
			switch (fTagNo(tvb, offset)) {
			case 0:
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				switch (fTagNo(tvb, offset)) {
				case 0:
					offset = fBitStringTag (tvb, subtree, offset,
						"changed-bits: ");
					break;
				case 1:
					offset = fRealTag (tvb, subtree, offset,
						"changed-value: ");
					break;
				default:
					break;
				}
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				break;
			case 1:
				offset = fBitStringTagVS (tvb, subtree, offset,
					"status-flags: ", BACnetStatusFlags);
	        	lastoffset = offset;
				break;
			default:
				break;
			}
			if (offset == lastoffset) break;     /* nothing happened, exit loop */
		}
		break;
	case 3: /* command-failure */
		while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
			lastoffset = offset;
			switch (fTagNo(tvb, offset)) {
			case 0: /* "command-value: " */
				/* from BACnet Table 13-3,
					Standard Object Property Values Returned in Notifications */
				propertyIdentifier = 85; /* PRESENT_VALUE */
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fAbstractSyntaxNType (tvb, pinfo, subtree, offset);
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				break;
			case 1:
				offset = fBitStringTagVS (tvb, subtree, offset,
					"status-flags: ", BACnetStatusFlags);
				break;
			case 2: /* "feedback-value: " */
				propertyIdentifier = 40; /* FEEDBACK_VALUE */
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fAbstractSyntaxNType (tvb, pinfo, subtree, offset);
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
	        	lastoffset = offset;
				break;
			default:
				break;
			}
			if (offset == lastoffset) break;     /* nothing happened, exit loop */
		}
		break;
	case 4: /* floating-limit */
		while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
			lastoffset = offset;
			switch (fTagNo(tvb, offset)) {
			case 0:
				offset = fRealTag (tvb, subtree, offset, "reference-value: ");
				break;
			case 1:
				offset = fBitStringTagVS (tvb, subtree, offset,
					"status-flags: ", BACnetStatusFlags);
				break;
			case 2:
				offset = fRealTag (tvb, subtree, offset, "setpoint-value: ");
				break;
			case 3:
				offset = fRealTag (tvb, subtree, offset, "error-limit: ");
	        	lastoffset = offset;
				break;
			default:
				break;
			}
			if (offset == lastoffset) break;     /* nothing happened, exit loop */
		}
		break;
	case 5: /* out-of-range */
		while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
			lastoffset = offset;
			switch (fTagNo(tvb, offset)) {
			case 0:
				offset = fRealTag (tvb, subtree, offset, "exceeding-value: ");
				break;
			case 1:
				offset = fBitStringTagVS (tvb, subtree, offset,
					"status-flags: ", BACnetStatusFlags);
				break;
			case 2:
				offset = fRealTag (tvb, subtree, offset, "deadband: ");
				break;
			case 3:
				offset = fRealTag (tvb, subtree, offset, "exceeded-limit: ");
	        	lastoffset = offset;
				break;
			default:
				break;
			}
			if (offset == lastoffset) break;     /* nothing happened, exit loop */
		}
	    break;
	case 6:
		while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
			lastoffset = offset;
			offset =fBACnetPropertyValue (tvb,pinfo,subtree,offset);
			if (offset == lastoffset) break;     /* nothing happened, exit loop */
		}
		break;
	case 7: /* buffer-ready */
		while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
			lastoffset = offset;
			switch (fTagNo(tvb, offset)) {
			case 0:
				offset = fObjectIdentifier (tvb, pinfo, subtree, offset); /* buffer-device */
				break;
			case 1:
				offset = fObjectIdentifier (tvb, pinfo, subtree, offset); /* buffer-object */
				break;
			case 2:
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fDateTime (tvb, subtree, offset, "previous-notification: ");
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				break;
			case 3:
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fDateTime (tvb, subtree, offset, "current-notification: ");
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
	        	lastoffset = offset;
				break;
			default:
				break;
			}
			if (offset == lastoffset) break;     /* nothing happened, exit loop */
		}
		break;
	case 8: /* change-of-life-safety */
		while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
			lastoffset = offset;
			switch (fTagNo(tvb, offset)) {
			case 0:
				offset = fEnumeratedTagSplit (tvb, subtree, offset,
					"new-state: ", BACnetLifeSafetyState, 256);
				break;
			case 1:
				offset = fEnumeratedTagSplit (tvb, subtree, offset,
					"new-mode: ", BACnetLifeSafetyMode, 256);
				break;
			case 2:
				offset = fBitStringTagVS (tvb, subtree, offset,
					"status-flags: ", BACnetStatusFlags);
				break;
			case 3:
				offset = fEnumeratedTagSplit (tvb, subtree, offset,
					"operation-expected: ", BACnetLifeSafetyOperation, 64);
	        	lastoffset = offset;
				break;
			default:
				break;
			}
			if (offset == lastoffset) break;     /* nothing happened, exit loop */
		}
		break;
	case 9: /* extended */
		while (tvb_reported_length_remaining(tvb, offset)) {
			lastoffset = offset;
			switch (fTagNo(tvb, offset)) {
			case 0:
				offset = fVendorIdentifier (tvb, pinfo, subtree, offset);
				break;
			case 1:
				offset = fUnsignedTag (tvb, subtree, offset,
					"extended-event-type: ");
				break;
			case 2: /* parameters */
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fApplicationTypes(tvb, pinfo, subtree, offset, "parameters: ");
				offset = fDeviceObjectPropertyValue(tvb, pinfo, subtree, offset);
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
	        	lastoffset = offset;
				break;
			default:
				break;
			}
			if (offset == lastoffset) break;     /* nothing happened, exit loop */
		}
		break;
	case 10: /* buffer ready */
		while (tvb_reported_length_remaining(tvb, offset)) {
			lastoffset = offset;
			switch (fTagNo(tvb, offset)) {
			case 0: /* buffer-property */
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fDeviceObjectPropertyReference (tvb, pinfo, subtree, offset);
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				break;
			case 1:
				offset = fUnsignedTag (tvb, subtree, offset,
					"previous-notification: ");
				break;
			case 2:
				offset = fUnsignedTag (tvb, subtree, offset,
					"current-notification: ");
	        	lastoffset = offset;
				break;
			default:
				break;
			}
			if (offset == lastoffset) break;     /* nothing happened, exit loop */
		}
		break;
	case 11: /* unsigned range */
		while (tvb_reported_length_remaining(tvb, offset)) {
			lastoffset = offset;
			switch (fTagNo(tvb, offset)) {
			case 0:
				offset = fUnsignedTag (tvb, subtree, offset,
					"exceeding-value: ");
				break;
			case 1:
				offset = fBitStringTagVS (tvb, subtree, offset,
					"status-flags: ", BACnetStatusFlags);
				break;
			case 2:
				offset = fUnsignedTag (tvb, subtree, offset,
					"exceeded-limit: ");
	        	lastoffset = offset;
				break;
			default:
				break;
			}
			if (offset == lastoffset) break;     /* nothing happened, exit loop */
		}
		break;
	default:
		break;
	}

	/* Closing tag for parameter choice */
	offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);

	return offset;
}

#if 0
static guint
fEventParameter (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0: /* change-of-bitstring */
			while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
				lastoffset = offset;
				switch (fTagNo(tvb, offset)) {
				case 0:
					offset = fTimeSpan (tvb, tree, offset, "Time Delay");
					break;
				case 1:
					offset = fBitStringTag (tvb, tree, offset, "bitmask: ");
					break;
				case 2: /* SEQUENCE OF BIT STRING */
					offset = fBitStringTagVS (tvb, tree, offset,
						"bitstring value: ", BACnetEventTransitionBits);
					break;
				default:
					return offset;
				}
			}
			break;
		case 1: /* change-of-state */
			while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
				lastoffset = offset;
				switch (fTagNo(tvb, offset)) {
				case 0:
					offset = fTimeSpan (tvb, tree, offset, "Time Delay");
					break;
				case 1: /* SEQUENCE OF BACnetPropertyStates */
					offset = fEnumeratedTagSplit (tvb, tree, offset,
						"value: ", BACnetPropertyStates, 64);
					break;
				default:
					return offset;
				}
			}
			break;
		case 2: /* change-of-value */
			while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
				lastoffset = offset;
				switch (fTagNo(tvb, offset)) {
				case 0:
					offset = fTimeSpan   (tvb, tree, offset, "Time Delay");
					break;
				case 1: /* don't loop it, it's a CHOICE */
					switch (fTagNo(tvb, offset)) {
					case 0:
						offset = fBitStringTag (tvb, tree, offset, "bitmask: ");
						break;
					case 1:
						offset = fRealTag (tvb, tree, offset,
							"referenced Property Increment: ");
						break;
					default:
						return offset;
					}
				default:
					return offset;
				}
			}
			break;
		case 3: /* command-failure */
			while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
				lastoffset = offset;
				switch (fTagNo(tvb, offset)) {
				case 0:
					offset = fTimeSpan   (tvb, tree, offset, "Time Delay");
					break;
				case 1:
					offset = fDeviceObjectPropertyReference (tvb,pinfo,tree,offset);
				default:
					return offset;
				}
			}
			break;
		case 4: /* floating-limit */
			while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
				lastoffset = offset;
				switch (fTagNo(tvb, offset)) {
				case 0:
					offset = fTimeSpan   (tvb, tree, offset, "Time Delay");
					break;
				case 1:
					offset = fDeviceObjectPropertyReference (tvb,pinfo,tree,offset);
					break;
				case 2:
					offset = fRealTag (tvb, tree, offset, "low diff limit: ");
					break;
				case 3:
					offset = fRealTag (tvb, tree, offset, "high diff limit: ");
					break;
				case 4:
					offset = fRealTag (tvb, tree, offset, "deadband: ");
					break;
				default:
					return offset;
				}
			}
			break;
		case 5: /* out-of-range */
			while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
				lastoffset = offset;
				switch (fTagNo(tvb, offset)) {
				case 0:
					offset = fTimeSpan (tvb, tree, offset, "Time Delay");
					break;
				case 1:
					offset = fRealTag (tvb, tree, offset, "low limit: ");
					break;
				case 2:
					offset = fRealTag (tvb, tree, offset, "high limit: ");
					break;
				case 3:
					offset = fRealTag (tvb, tree, offset, "deadband: ");
					break;
				default:
					return offset;
				}
			}
			break;
		case 6:
			offset = fBACnetPropertyValue (tvb,pinfo,tree,offset);
			break;
		case 7: /* buffer-ready */
			while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
				lastoffset = offset;
				switch (fTagNo(tvb, offset)) {
				case 0:
					offset = fUnsignedTag (tvb,tree,offset,"notification threshold");
					break;
				case 1:
					offset = fUnsignedTag (tvb,tree,offset,
						"previous notification count: ");
					break;
				default:
					return offset;
				}
			}
			break;
		case 8: /* change-of-life-safety */
			while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
				lastoffset = offset;
				switch (fTagNo(tvb, offset)) {
				case 0:
					offset = fTimeSpan (tvb, tree, offset, "Time Delay");
					break;
				case 1:
					offset = fEnumeratedTagSplit (tvb, tree, offset,
						"life safety alarm value: ", BACnetLifeSafetyState, 256);
					break;
				case 2:
					offset = fEnumeratedTagSplit (tvb, tree, offset,
						"alarm value: ", BACnetLifeSafetyState, 256);
					break;
				case 3:
					offset = fDeviceObjectPropertyReference (tvb, pinfo, tree, offset);
					break;
				default:
					return offset;
				}
			}
			break;
		default:
			return offset;
		}
	}
	return offset;
}
#endif

static guint
fLogRecord (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0: /* timestamp */
			offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
			offset = fDate (tvb,tree,offset,"Date: ");
			offset = fTime (tvb,tree,offset,"Time: ");
			offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
			break;
		case 1: /* logDatum: don't loop, it's a CHOICE */
			offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
			switch (fTagNo(tvb, offset)) {
			case 0:	/* logStatus */
				offset = fEnumeratedTag (tvb, tree, offset,
					"log status: ", BACnetLogStatus);
				break;
			case 1:
				offset = fBooleanTag (tvb, tree, offset, "boolean-value: ");
				break;
			case 2:
				offset = fRealTag (tvb, tree, offset, "real value: ");
				break;
			case 3:
				offset = fUnsignedTag (tvb, tree, offset, "enum value: ");
				break;
			case 4:
				offset = fUnsignedTag (tvb, tree, offset, "unsigned value: ");
				break;
			case 5:
				offset = fSignedTag (tvb, tree, offset, "signed value: ");
				break;
			case 6:
				offset = fBitStringTag (tvb, tree, offset, "bitstring value: ");
				break;
			case 7:
				offset = fNullTag(tvb, tree, offset, "null value: ");
				break;
			case 8:
				offset = fError (tvb, pinfo, tree, offset);
				break;
			case 9:
				offset = fRealTag (tvb, tree, offset, "time change: ");
				break;
			case 10:	/* any Value */
				offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
				offset = fAbstractSyntaxNType (tvb, pinfo, tree, offset);
				offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
				break;
			default:
				return offset;
			}
			offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
			break;
		case 2:
			offset = fEnumeratedTag (tvb, tree, offset,
				"Status Flags: ", BACnetStatusFlags);
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}


static guint
fConfirmedEventNotificationRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;

		switch (fTagNo(tvb,offset)) {
		case 0:	/* ProcessId */
			offset = fProcessId (tvb,tree,offset);
			break;
		case 1: /* initiating ObjectId */
			offset = fObjectIdentifier (tvb, pinfo, tree, offset);
			break;
		case 2: /* event ObjectId */
			offset = fObjectIdentifier (tvb, pinfo, tree, offset);
			break;
		case 3:	/* time stamp */
			offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
			offset = fTimeStamp (tvb, tree, offset, NULL);
			offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
			break;
		case 4:	/* notificationClass */
			offset = fUnsignedTag (tvb, tree, offset, "Notification Class: ");
			break;
		case 5:	/* Priority */
			offset = fUnsignedTag (tvb, tree, offset, "Priority: ");
			break;
		case 6:	/* EventType */
			offset = fEnumeratedTagSplit (tvb, tree, offset,
				"Event Type: ", BACnetEventType, 64);
			break;
		case 7: /* messageText */
			offset = fCharacterString (tvb, tree, offset, "message Text: ");
			break;
		case 8:	/* NotifyType */
			offset = fEnumeratedTag (tvb, tree, offset,
				"Notify Type: ", BACnetNotifyType);
			break;
		case 9: /* ackRequired */
			offset = fBooleanTag (tvb, tree, offset, "ack Required: ");
			break;
		case 10: /* fromState */
			offset = fEnumeratedTagSplit (tvb, tree, offset,
				"from State: ", BACnetEventState, 64);
			break;
		case 11: /* toState */
			offset = fEnumeratedTagSplit (tvb, tree, offset,
				"to State: ", BACnetEventState, 64);
			break;
		case 12: /* NotificationParameters */
			offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
			offset = fNotificationParameters (tvb, pinfo, tree, offset);
			offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
			break;
		default:
			break;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fUnconfirmedEventNotificationRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	return fConfirmedEventNotificationRequest (tvb, pinfo, tree, offset);
}

static guint
fConfirmedCOVNotificationRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0, len;
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {
			offset += len;
			subtree = tree;
			continue;
		}

		switch (tag_no) {
		case 0:	/* ProcessId */
			offset = fProcessId (tvb,tree,offset);
			break;
		case 1: /* initiating DeviceId */
			offset = fObjectIdentifier (tvb, pinfo, subtree, offset);
			break;
		case 2: /* monitored ObjectId */
			offset = fObjectIdentifier (tvb, pinfo, subtree, offset);
			break;
		case 3:	/* time remaining */
			offset = fTimeSpan (tvb, tree, offset, "Time remaining");
			break;
		case 4:	/* List of Values */
			if (tag_is_opening(tag_info)) {
				tt = proto_tree_add_text(subtree, tvb, offset, 1, "list of Values");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fBACnetPropertyValue (tvb, pinfo, subtree, offset);
				break;
			}
			FAULT;
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fUnconfirmedCOVNotificationRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	return fConfirmedCOVNotificationRequest (tvb, pinfo, tree, offset);
}

static guint
fAcknowledgeAlarmRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no = 0, tag_info = 0;
	guint32 lvt = 0;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0:	/* acknowledgingProcessId */
			offset = fUnsignedTag (tvb, tree, offset, "acknowledging Process Id: ");
			break;
		case 1: /* eventObjectId */
			offset = fObjectIdentifier (tvb, pinfo, tree, offset);
			break;
		case 2: /* eventStateAcknowledged */
			offset = fEnumeratedTagSplit (tvb, tree, offset,
				"event State Acknowledged: ", BACnetEventState, 64);
			break;
		case 3:	/* timeStamp */
			offset += fTagHeaderTree(tvb, tree, offset, &tag_no, &tag_info, &lvt);
			offset = fTimeStamp(tvb, tree, offset, NULL);
			offset += fTagHeaderTree(tvb, tree, offset, &tag_no, &tag_info, &lvt);
			break;
		case 4:	/* acknowledgementSource */
			offset = fCharacterString (tvb, tree, offset, "acknowledgement Source: ");
			break;
		case 5:	/* timeOfAcknowledgement */
			offset += fTagHeaderTree(tvb, tree, offset, &tag_no, &tag_info, &lvt);
			offset = fTimeStamp(tvb, tree, offset, "acknowledgement timestamp: ");
			offset += fTagHeaderTree(tvb, tree, offset, &tag_no, &tag_info, &lvt);
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fGetAlarmSummaryAck (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		offset = fApplicationTypes (tvb, pinfo, tree, offset, "Object Identifier: ");
		offset = fApplicationTypesEnumeratedSplit (tvb, pinfo, tree, offset,
			"alarm State: ", BACnetEventState, 64);
		offset = fApplicationTypesEnumerated (tvb, pinfo, tree, offset,
			"acknowledged Transitions: ", BACnetEventTransitionBits);
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return  offset;
}

static guint
fGetEnrollmentSummaryRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0:	/* acknowledgmentFilter */
			offset = fEnumeratedTag (tvb, tree, offset,
				"acknowledgment Filter: ", BACnetAcknowledgementFilter);
			break;
		case 1: /* eventObjectId - OPTIONAL */
			offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
			offset = fRecipientProcess (tvb, pinfo, tree, offset);
			offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
			break;
		case 2: /* eventStateFilter */
			offset = fEnumeratedTag (tvb, tree, offset,
				"event State Filter: ", BACnetEventStateFilter);
			break;
		case 3:	/* eventTypeFilter - OPTIONAL */
			offset = fEnumeratedTag (tvb, tree, offset,
				"event Type Filter: ", BACnetEventType);
			break;
		case 4:	/* priorityFilter */
			offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
			offset = fUnsignedTag (tvb, tree, offset, "min Priority: ");
			offset = fUnsignedTag (tvb, tree, offset, "max Priority: ");
			offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
			break;
		case 5:	/* notificationClassFilter - OPTIONAL */
			offset = fUnsignedTag (tvb, tree, offset, "notification Class Filter: ");
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fGetEnrollmentSummaryAck (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		offset = fApplicationTypes (tvb, pinfo, tree, offset, "Object Identifier: ");
		offset = fApplicationTypesEnumeratedSplit (tvb, pinfo, tree, offset,
			"event Type: ", BACnetEventType, 64);
		offset = fApplicationTypesEnumerated (tvb, pinfo, tree, offset,
			"event State: ", BACnetEventState);
		offset = fApplicationTypes (tvb, pinfo, tree, offset, "Priority: ");
		offset = fApplicationTypes (tvb, pinfo, tree, offset, "Notification Class: ");
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}

	return  offset;
}

static guint
fGetEventInformationRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	if (tvb_reported_length_remaining(tvb, offset) > 0) {
		if (fTagNo(tvb, offset) == 0) {
			offset = fObjectIdentifier (tvb, pinfo, tree, offset);
		}
	}
	return offset;
}

static guint
flistOfEventSummaries (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_tree* subtree = tree;
	proto_item* ti = 0;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		/* we are finished here if we spot a closing tag */
		if (tag_is_closing(tag_info)) {
			break;
		}
		switch (tag_no) {
		case 0:	/* ObjectId */
			offset = fObjectIdentifier (tvb, pinfo, tree, offset);
			break;
		case 1: /* eventState */
			offset = fEnumeratedTag (tvb, tree, offset,
				"event State: ", BACnetEventState);
			break;
		case 2: /* acknowledgedTransitions */
			offset = fBitStringTagVS (tvb, tree, offset,
				"acknowledged Transitions: ", BACnetEventTransitionBits);
			break;
		case 3: /* eventTimeStamps */
			ti = proto_tree_add_text(tree, tvb, offset, lvt, "eventTimeStamps");
			if (ti) {
				subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
			}
			offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
			offset = fTimeStamp (tvb, subtree, offset,"TO-OFFNORMAL timestamp: ");
			offset = fTimeStamp (tvb, subtree, offset,"TO-FAULT timestamp: ");
			offset = fTimeStamp (tvb, subtree, offset,"TO-NORMAL timestamp: ");
			offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
			break;
		case 4: /* notifyType */
			offset = fEnumeratedTag (tvb, tree, offset,
				"Notify Type: ", BACnetNotifyType);
			break;
		case 5: /* eventEnable */
			offset = fBitStringTagVS (tvb, tree, offset,
				"event Enable: ", BACnetEventTransitionBits);
			break;
		case 6: /* eventPriorities */
			ti = proto_tree_add_text(tree, tvb, offset, lvt, "eventPriorities");
			if (ti) {
				subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
			}
			offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
			offset = fUnsignedTag (tvb, subtree, offset, "TO-OFFNORMAL Priority: ");
			offset = fUnsignedTag (tvb, subtree, offset, "TO-FAULT Priority: ");
			offset = fUnsignedTag (tvb, subtree, offset, "TO-NORMAL Priority: ");
			offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fLOPR (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;

	col_set_writable(pinfo->cinfo, FALSE); /* don't set all infos into INFO column */
	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		/* we are finished here if we spot a closing tag */
		if (tag_is_closing(tag_info)) {
			break;
		}
		offset = fDeviceObjectPropertyReference(tvb, pinfo, tree, offset);
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fGetEventInformationACK (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0:	/* listOfEventSummaries */
			offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
			offset = flistOfEventSummaries (tvb, pinfo, tree, offset);
			offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
			break;
		case 1: /* moreEvents */
			offset = fBooleanTag (tvb, tree, offset, "more Events: ");
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fAddListElementRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0, len;
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	col_set_writable(pinfo->cinfo, FALSE); /* don't set all infos into INFO column */

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {
			offset += len;
			subtree = tree;
			continue;
		}

		switch (tag_no) {
		case 0:	/* ObjectId */
			offset = fBACnetObjectPropertyReference (tvb, pinfo, subtree, offset);
			break;
		case 3:	/* listOfElements */
			if (tag_is_opening(tag_info)) {
				tt = proto_tree_add_text(subtree, tvb, offset, 1, "listOfElements");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fAbstractSyntaxNType (tvb, pinfo, subtree, offset);
				break;
			}
			FAULT;
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fDeleteObjectRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	return fObjectIdentifier (tvb, pinfo, tree, offset);
}

static guint
fDeviceCommunicationControlRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;

		switch (fTagNo(tvb, offset)) {
		case 0:	/* timeDuration */
			offset = fUnsignedTag (tvb,tree,offset,"time Duration: ");
			break;
		case 1:	/* enable-disable */
			offset = fEnumeratedTag (tvb, tree, offset, "enable-disable: ",
				BACnetEnableDisable);
			break;
		case 2: /* password - OPTIONAL */
			offset = fCharacterString (tvb, tree, offset, "Password: ");
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fReinitializeDeviceRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;

		switch (fTagNo(tvb, offset)) {
		case 0:	/* reinitializedStateOfDevice */
			offset = fEnumeratedTag (tvb, tree, offset,
				"reinitialized State Of Device: ",
				BACnetReinitializedStateOfDevice);
			break;
		case 1: /* password - OPTIONAL */
			offset = fCharacterString (tvb, tree, offset, "Password: ");
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fVtOpenRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	offset = fApplicationTypesEnumerated (tvb, pinfo, tree, offset,
		"vtClass: ", BACnetVTClass);
	return fApplicationTypes (tvb, pinfo, tree,offset,"local VT Session ID: ");
}

static guint
fVtOpenAck (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	return fApplicationTypes (tvb, pinfo, tree,offset,"remote VT Session ID: ");
}

static guint
fVtCloseRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		offset= fApplicationTypes (tvb, pinfo, tree,offset,"remote VT Session ID: ");
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fVtDataRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	offset= fApplicationTypes (tvb, pinfo, tree,offset,"VT Session ID: ");
	offset = fApplicationTypes (tvb, pinfo, tree, offset, "VT New Data: ");
	return fApplicationTypes (tvb, pinfo, tree,offset,"VT Data Flag: ");;
}

static guint
fVtDataAck (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;

		switch (fTagNo(tvb,offset)) {
		case 0:	/* BOOLEAN */
			offset = fBooleanTag (tvb, tree, offset, "all New Data Accepted: ");
			break;
		case 1:	/* Unsigned OPTIONAL */
			offset = fUnsignedTag (tvb, tree, offset, "accepted Octet Count: ");
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fAuthenticateRequest (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;

		switch (fTagNo(tvb,offset)) {
		case 0:	/* Unsigned32 */
			offset = fUnsignedTag (tvb, tree, offset, "pseudo Random Number: ");
			break;
		case 1:	/* expected Invoke ID Unsigned8 OPTIONAL */
			proto_tree_add_item(tree, hf_bacapp_invoke_id, tvb, offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 2: /* Chararacter String OPTIONAL */
			offset = fCharacterString (tvb, tree, offset, "operator Name: ");
			break;
		case 3:	/* Chararacter String OPTIONAL */
			offset = fCharacterString (tvb, tree, offset, "operator Password: ");
			break;
		case 4: /* Boolean OPTIONAL */
			offset = fBooleanTag (tvb, tree, offset, "start Encyphered Session: ");
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fAuthenticateAck (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	return fApplicationTypes (tvb, pinfo, tree, offset, "modified Random Number: ");
}

static guint
fRequestKeyRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	offset = fObjectIdentifier (tvb, pinfo, tree, offset); /* Requesting Device Identifier */
	offset = fAddress (tvb, tree, offset);
	offset = fObjectIdentifier (tvb, pinfo, tree, offset); /* Remote Device Identifier */
	return fAddress (tvb, tree, offset);
}

static guint
fRemoveListElementRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	/* Same as AddListElement request after service choice */
	return fAddListElementRequest(tvb, pinfo, tree, offset);
}

static guint
fReadPropertyRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	return fBACnetObjectPropertyReference(tvb, pinfo, tree, offset);
}

static guint
fReadPropertyAck (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0, len;
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_tree *subtree = tree;

	/* set the optional global properties to indicate not-used */
	propertyArrayIndex = -1;
	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {
			offset += len;
			subtree = tree;
			continue;
		}
		switch (tag_no) {
		case 0:	/* objectIdentifier */
			offset = fObjectIdentifier (tvb, pinfo, subtree, offset);
			break;
		case 1:	/* propertyIdentifier */
			offset = fPropertyIdentifier (tvb, pinfo, subtree, offset);
			break;
		case 2: /* propertyArrayIndex */
			offset = fPropertyArrayIndex (tvb, subtree, offset);
			break;
		case 3:	/* propertyValue */
			offset = fPropertyValue (tvb, pinfo, subtree, offset, tag_info);
			break;
		default:
			break;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fWritePropertyRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_tree *subtree = tree;

	/* set the optional global properties to indicate not-used */
	propertyArrayIndex = -1;
	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		/* quit loop if we spot a closing tag */
		if (tag_is_closing(tag_info)) {
			subtree = tree;
			break;
		}

		switch (tag_no) {
		case 0:	/* objectIdentifier */
			offset = fObjectIdentifier (tvb, pinfo, subtree, offset);
			break;
		case 1:	/* propertyIdentifier */
			offset = fPropertyIdentifier (tvb, pinfo, subtree, offset);
			break;
		case 2: /* propertyArrayIndex */
			offset = fPropertyArrayIndex (tvb, subtree, offset);
			break;
		case 3:	/* propertyValue */
			offset = fPropertyValue (tvb, pinfo, subtree, offset, tag_info);
			break;
		case 4: /* Priority (only used for write) */
			offset = fUnsignedTag (tvb, subtree, offset, "Priority: ");
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fWriteAccessSpecification (tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, guint offset)
{
	guint lastoffset = 0, len;
	guint8 tag_no, tag_info;
	guint32 lvt;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		/* maybe a listOfwriteAccessSpecifications if we spot a closing tag */
		if (tag_is_closing(tag_info)) {
			offset += len;
			continue;
		}

		switch (tag_no) {
		case 0:	/* objectIdentifier */
			offset = fObjectIdentifier (tvb, pinfo, subtree, offset);
			break;
		case 1:	/* listOfPropertyValues */
			if (tag_is_opening(tag_info)) {
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fBACnetPropertyValue (tvb, pinfo, subtree, offset);
				break;
			}
			FAULT;
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fWritePropertyMultipleRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	if (offset >= tvb_reported_length(tvb))
		return offset;

	col_set_writable(pinfo->cinfo, FALSE); /* don't set all infos into INFO column */
	return fWriteAccessSpecification (tvb, pinfo, tree, offset);
}

static guint
fPropertyReference (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint8 tagoffset, guint8 list)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;

	/* set the optional global properties to indicate not-used */
	propertyArrayIndex = -1;
	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) { /* closing Tag, but not for me */
			return offset;
		} else if (tag_is_opening(tag_info)) { /* opening Tag, but not for me */
			return offset;
		}
		switch (tag_no-tagoffset) {
		case 0:	/* PropertyIdentifier */
			offset = fPropertyIdentifier (tvb, pinfo, tree, offset);
			break;
		case 1:	/* propertyArrayIndex */
			offset = fPropertyArrayIndex (tvb, tree, offset);
			if (list != 0) break; /* Continue decoding if this may be a list */
		default:
			lastoffset = offset; /* Set loop end condition */
			break;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fBACnetPropertyReference (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint8 list)
{
	col_set_writable(pinfo->cinfo, FALSE); /* don't set all infos into INFO column */
	return fPropertyReference(tvb, pinfo, tree, offset, 0, list);
}

static guint
fBACnetObjectPropertyReference (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;

		switch (fTagNo(tvb,offset)) {
		case 0:	/* ObjectIdentifier */
			offset = fObjectIdentifier (tvb, pinfo, tree, offset);
			break;
		case 1:	/* PropertyIdentifier and propertyArrayIndex */
			offset = fPropertyReference (tvb, pinfo, tree, offset, 1, 0);
			col_set_writable(pinfo->cinfo, FALSE); /* don't set all infos into INFO column */
		default:
			lastoffset = offset; /* Set loop end condition */
			break;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

#if 0
static guint
fObjectPropertyValue (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_tree* subtree = tree;
	proto_item* tt;

	while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {
			offset += fTagHeaderTree (tvb, subtree, offset,
				&tag_no, &tag_info, &lvt);
			continue;
		}
		switch (tag_no) {
		case 0:	/* ObjectIdentifier */
			offset = fObjectIdentifier (tvb, pinfo, subtree, offset);
			break;
		case 1:	/* PropertyIdentifier */
			offset = fPropertyIdentifier (tvb, pinfo, subtree, offset);
			break;
		case 2:	/* propertyArrayIndex */
			offset = fUnsignedTag (tvb, subtree, offset, "property Array Index: ");
			break;
		case 3:  /* Value */
			offset = fPropertyValue (tvb, subtree, offset, tag_info);
			break;
		case 4:  /* Priority */
			offset = fUnsignedTag (tvb, subtree, offset, "Priority: ");
			break;
		default:
			break;
		}
	}
	return offset;
}
#endif

static guint
fPriorityArray (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	char i = 1, ar[256];
	guint lastoffset = 0;

	if (propertyArrayIndex > 0) {
		/* BACnetARRAY index 0 refers to the length
		of the array, not the elements of the array.
		BACnetARRAY index -1 is our internal flag that
		the optional index was not used.
		BACnetARRAY refers to this as all elements of the array.
		If the optional index is specified for a BACnetARRAY,
		then that specific array element is referenced. */
		i = propertyArrayIndex;
	}
	while (tvb_reported_length_remaining(tvb, offset)) {
		/* exit loop if nothing happens inside */
		lastoffset = offset;
		g_snprintf (ar, sizeof(ar), "%s[%d]: ",
			val_to_split_str(87 , 512,
				BACnetPropertyIdentifier,
				ASHRAE_Reserved_Fmt,
				Vendor_Proprietary_Fmt),
			i++);
		/* DMR Should be fAbstractNSyntax, but that's where we came from! */
		offset = fApplicationTypes(tvb, pinfo, tree, offset, ar);
		/* there are only 16 priority array elements */
		if (i > 16) {
			break;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}

	return offset;
}

static guint
fDeviceObjectReference (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;

		switch (fTagNo(tvb,offset)) {
		case 0:	/* deviceIdentifier - OPTIONAL */
			offset = fObjectIdentifier (tvb, pinfo, tree, offset);
			break;
		case 1:	/* ObjectIdentifier */
			offset = fObjectIdentifier (tvb, pinfo, tree, offset);
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fSpecialEvent (tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, guint offset)
{
	guint8 tag_no, tag_info;
	guint32 lvt;
	guint lastoffset = 0, len;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		/* maybe a SEQUENCE of SpecialEvents if we spot a closing tag */
		if (tag_is_closing(tag_info)) {
			offset += len;
			continue;
		}

		switch (tag_no) {
		case 0:	/* calendaryEntry */
			if (tag_is_opening(tag_info)) {
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fCalendaryEntry (tvb, subtree, offset);
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
			}
			break;
		case 1:	/* calendarReference */
			offset = fObjectIdentifier (tvb, pinfo, subtree, offset);
			break;
		case 2:	/* list of BACnetTimeValue */
			if (tag_is_opening(tag_info)) {
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fTimeValue (tvb, pinfo, subtree, offset);
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				break;
			}
			FAULT;
			break;
		case 3:	/* eventPriority */
			offset = fUnsignedTag (tvb, subtree, offset, "event priority: ");
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fSelectionCriteria (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0, len;
	guint8 tag_no, tag_info;
	guint32 lvt;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		/* maybe a listOfSelectionCriteria if we spot a closing tag */
		if (tag_is_closing(tag_info)) {
			offset += len;
			continue;
		}

		switch (fTagNo(tvb,offset)) {
		case 0:	/* propertyIdentifier */
			offset = fPropertyIdentifier (tvb, pinfo, tree, offset);
			break;
		case 1:	/* propertyArrayIndex */
			offset = fPropertyArrayIndex (tvb, tree, offset);
			break;
		case 2: /* relationSpecifier */
			offset = fEnumeratedTag (tvb, tree, offset,
				"relation Specifier: ", BACnetRelationSpecifier);
			break;
		case 3: /* comparisonValue */
			offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
			offset = fAbstractSyntaxNType (tvb, pinfo, tree, offset);
			offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fObjectSelectionCriteria (tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		/* quit loop if we spot a closing tag */
		if (tag_is_closing(tag_info)) {
			break;
		}

		switch (tag_no) {
		case 0:	/* selectionLogic */
			offset = fEnumeratedTag (tvb, subtree, offset,
				"selection Logic: ", BACnetSelectionLogic);
			break;
		case 1:	/* listOfSelectionCriteria */
			if (tag_is_opening(tag_info)) {
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fSelectionCriteria (tvb, pinfo, subtree, offset);
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				break;
			}
			FAULT;
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}


static guint
fReadPropertyConditionalRequest(tvbuff_t *tvb, packet_info* pinfo, proto_tree *subtree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);

		if (tag_is_opening(tag_info) && tag_no < 2) {
			offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
			switch (tag_no) {
			case 0:	/* objectSelectionCriteria */
				offset = fObjectSelectionCriteria (tvb, pinfo, subtree, offset);
				break;
			case 1:	/* listOfPropertyReferences */
				offset = fBACnetPropertyReference (tvb, pinfo, subtree, offset, 1);
				break;
			default:
				return offset;
			}
			offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fReadAccessSpecification (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_item *tt;
	proto_tree *subtree = tree;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		switch (tag_no) {
		case 0:	/* objectIdentifier */
			offset = fObjectIdentifier (tvb, pinfo, subtree, offset);
			break;
		case 1:	/* listOfPropertyReferences */
			if (tag_is_opening(tag_info)) {
				tt = proto_tree_add_text(subtree, tvb, offset, 1, "listOfPropertyReferences");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fBACnetPropertyReference (tvb, pinfo, subtree, offset, 1);
			} else if (tag_is_closing(tag_info)) {
				offset += fTagHeaderTree (tvb, subtree, offset,
					&tag_no, &tag_info, &lvt);
				subtree = tree;
			} else {
				/* error condition: let caller handle */
				return offset;
			}
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fReadAccessResult (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0, len;
	guint8 tag_no;
	guint8 tag_info;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		/* maybe a listOfReadAccessResults if we spot a closing tag here */
		if (tag_is_closing(tag_info)) {
			offset += len;
			if ((tag_no == 4 || tag_no == 5) && (subtree != tree)) subtree = subtree->parent; /* Value and error have extra subtree */
			continue;
		}

		switch (tag_no) {
		case 0:	/* objectSpecifier */
			offset = fObjectIdentifier (tvb, pinfo, tree, offset);
			break;
		case 1:	/* list of Results */
			if (tag_is_opening(tag_info)) {
				tt = proto_tree_add_text(tree, tvb, offset, 1, "listOfResults");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				break;
			}
			FAULT;
			break;
		case 2:	/* propertyIdentifier */
			offset = fPropertyIdentifierValue(tvb, pinfo, subtree, offset, 2);
			break;
		case 5:	/* propertyAccessError */
			if (tag_is_opening(tag_info)) {
				tt = proto_tree_add_text(subtree, tvb, offset, 1, "propertyAccessError");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				/* Error Code follows */
				offset = fError(tvb, pinfo, subtree, offset);
				break;
			}
			FAULT;
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}


static guint
fReadPropertyConditionalAck (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	/* listOfReadAccessResults */
	return fReadAccessResult (tvb, pinfo, tree, offset);
}


static guint
fCreateObjectRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);

		if (tag_no < 2) {
			offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
			switch (tag_no) {
			case 0:	/* objectSpecifier */
				switch (fTagNo(tvb, offset)) { /* choice of objectType or objectIdentifier */
				case 0:	/* objectType */
					offset = fEnumeratedTagSplit (tvb, subtree, offset, "Object Type: ", BACnetObjectType, 128);
					break;
				case 1:	/* objectIdentifier */
					offset = fObjectIdentifier (tvb, pinfo, subtree, offset);
					break;
				default:
					break;
				}
				break;
			case 1:	/* propertyValue */
				if (tag_is_opening(tag_info)) {
					offset = fBACnetPropertyValue (tvb, pinfo, subtree, offset);
					break;
				}
				FAULT;
				break;
			default:
				break;
			}
			offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
		}
		if (offset == lastoffset) break;    /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fCreateObjectAck (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	return fObjectIdentifier (tvb, pinfo, tree, offset);
}

static guint
fReadRangeRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	offset = fBACnetObjectPropertyReference(tvb, pinfo, subtree, offset);

	if (tvb_reported_length_remaining(tvb, offset) > 0) {
		/* optional range choice */
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_opening(tag_info)) {
			tt = proto_tree_add_text(subtree, tvb, offset, 1, "%s", val_to_str(tag_no, BACnetReadRangeOptions, "unknown range option"));
			subtree = proto_item_add_subtree(tt, ett_bacapp_value);
			offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
			switch (tag_no) {
			case 3:	/* range byPosition */
			case 6: /* range bySequenceNumber, 2004 spec */
				offset = fApplicationTypes (tvb, pinfo, subtree, offset, "reference Index: ");
				offset = fApplicationTypes (tvb, pinfo, subtree, offset, "reference Count: ");
				break;
			case 4:	/* range byTime - deprecated in 2004 */
			case 7: /* 2004 spec */
				offset = fDateTime(tvb, subtree, offset, "reference Date/Time: ");
				offset = fApplicationTypes (tvb, pinfo, subtree, offset, "reference Count: ");
				break;
			case 5:	/* range timeRange - deprecated in 2004 */
				offset = fDateTime(tvb, subtree, offset, "beginning Time: ");
				offset = fDateTime(tvb, subtree, offset, "ending Time: ");
				break;
			default:
				break;
			}
			offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
		}
	}
	return offset;
}

static guint
fReadRangeAck (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	/* set the optional global properties to indicate not-used */
	propertyArrayIndex = -1;
	/* objectIdentifier, propertyIdentifier, and
	   OPTIONAL propertyArrayIndex */
	offset = fBACnetObjectPropertyReference(tvb, pinfo, subtree, offset);
	/* resultFlags => BACnetResultFlags ::= BIT STRING */
	offset = fBitStringTagVS (tvb, tree, offset,
		"resultFlags: ",
		BACnetResultFlags);
	/* itemCount */
	offset = fUnsignedTag (tvb, subtree, offset, "item Count: ");
	/* itemData */
	fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	if (tag_is_opening(tag_info)) {
		col_set_writable(pinfo->cinfo, FALSE); /* don't set all infos into INFO column */
		tt = proto_tree_add_text(subtree, tvb, offset, 1, "itemData");
		subtree = proto_item_add_subtree(tt, ett_bacapp_value);
		offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
		offset = fAbstractSyntaxNType (tvb, pinfo, subtree, offset);
		offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
	}
	/* firstSequenceNumber - OPTIONAL */
	if (tvb_reported_length_remaining(tvb, offset) > 0) {
		offset = fUnsignedTag (tvb, subtree, offset, "first Sequence Number: ");
	}

	return offset;
}

static guint
fAccessMethod(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint32 lvt;
	guint8 tag_no, tag_info;
	proto_item* tt;
	proto_tree* subtree = NULL;

	fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);

	if (tag_is_opening(tag_info)) {
		tt = proto_tree_add_text(tree, tvb, offset, 1, "%s", val_to_str(tag_no, BACnetFileAccessOption, "invalid access method"));
		subtree = proto_item_add_subtree(tt, ett_bacapp_value);
		offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
		offset = fApplicationTypes (tvb, pinfo, subtree, offset, val_to_str(tag_no, BACnetFileStartOption, "invalid option"));
		offset = fApplicationTypes (tvb, pinfo, subtree, offset, val_to_str(tag_no, BACnetFileWriteInfo, "unknown option"));

		if (tag_no == 1) {
			while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {
				/* exit loop if nothing happens inside */
				lastoffset = offset;
				offset = fApplicationTypes (tvb, pinfo, subtree, offset, "Record Data: ");
			}
		}

		if ((bacapp_flags & BACAPP_MORE_SEGMENTS) == 0) {
			/* More Flag is not set, so we can look for closing tag in this segment */
			fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
			if (tag_is_closing(tag_info)) {
				offset += fTagHeaderTree (tvb, subtree, offset,	&tag_no, &tag_info, &lvt);
			}
		}
	}
	return offset;
}

static guint
fAtomicReadFileRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	offset = fObjectIdentifier (tvb, pinfo, tree, offset);

	fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);

	if (tag_is_opening(tag_info)) {
		tt = proto_tree_add_text(subtree, tvb, offset, 1, "%s", val_to_str(tag_no, BACnetFileAccessOption, "unknown access method"));
		subtree = proto_item_add_subtree(tt, ett_bacapp_value);
		offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
		offset = fSignedTag (tvb, subtree, offset, val_to_str(tag_no, BACnetFileStartOption, "unknown option"));
		offset = fUnsignedTag (tvb, subtree, offset, val_to_str(tag_no, BACnetFileRequestCount, "unknown option"));
		offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
	}
	return offset;
}

static guint
fAtomicWriteFileRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{

	offset = fObjectIdentifier (tvb, pinfo, tree, offset); /* file Identifier */
	offset = fAccessMethod(tvb, pinfo, tree, offset);

	return offset;
}

static guint
fAtomicWriteFileAck (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint tag_no = fTagNo(tvb, offset);
	return fSignedTag (tvb, tree, offset, val_to_str(tag_no, BACnetFileStartOption, "unknown option"));
}

static guint
fAtomicReadFileAck (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	offset = fApplicationTypes (tvb, pinfo, tree, offset, "End Of File: ");
	offset = fAccessMethod(tvb,pinfo, tree, offset);

	return offset;
}

static guint
fReadPropertyMultipleRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, guint offset)
{
	col_set_writable(pinfo->cinfo, FALSE); /* don't set all infos into INFO column */
	return fReadAccessSpecification (tvb,pinfo,subtree,offset);
}

static guint
fReadPropertyMultipleAck (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	col_set_writable(pinfo->cinfo, FALSE); /* don't set all infos into INFO column */
	return fReadAccessResult (tvb,pinfo,tree,offset);
}

static guint
fConfirmedServiceRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, gint service_choice)
{
	if (tvb_reported_length_remaining(tvb,offset) <= 0)
		return offset;

	switch (service_choice) {
	case 0:	/* acknowledgeAlarm */
		offset = fAcknowledgeAlarmRequest (tvb, pinfo, tree, offset);
		break;
	case 1: /* confirmedCOVNotification */
		offset = fConfirmedCOVNotificationRequest (tvb, pinfo, tree, offset);
		break;
	case 2: /* confirmedEventNotification */
		offset = fConfirmedEventNotificationRequest (tvb, pinfo, tree, offset);
		break;
	case 3: /* confirmedGetAlarmSummary conveys no parameters */
		break;
	case 4: /* getEnrollmentSummaryRequest */
		offset = fGetEnrollmentSummaryRequest (tvb, pinfo, tree, offset);
		break;
	case 5: /* subscribeCOVRequest */
		offset = fSubscribeCOVRequest(tvb, pinfo, tree, offset);
		break;
	case 6: /* atomicReadFile-Request */
		offset = fAtomicReadFileRequest(tvb, pinfo, tree, offset);
		break;
	case 7: /* atomicWriteFile-Request */
		offset = fAtomicWriteFileRequest(tvb, pinfo, tree, offset);
		break;
	case 8: /* AddListElement-Request */
		offset = fAddListElementRequest(tvb, pinfo, tree, offset);
		break;
	case 9: /* removeListElement-Request */
		offset = fRemoveListElementRequest(tvb, pinfo, tree, offset);
		break;
	case 10: /* createObjectRequest */
		offset = fCreateObjectRequest(tvb, pinfo, tree, offset);
		break;
	case 11: /* deleteObject */
		offset = fDeleteObjectRequest(tvb, pinfo, tree, offset);
		break;
	case 12:
		offset = fReadPropertyRequest(tvb, pinfo, tree, offset);
		break;
	case 13:
		offset = fReadPropertyConditionalRequest(tvb, pinfo, tree, offset);
		break;
	case 14:
		offset = fReadPropertyMultipleRequest(tvb, pinfo, tree, offset);
		break;
	case 15:
		offset = fWritePropertyRequest(tvb, pinfo, tree, offset);
		break;
	case 16:
		offset = fWritePropertyMultipleRequest(tvb, pinfo, tree, offset);
		break;
	case 17:
		offset = fDeviceCommunicationControlRequest(tvb, tree, offset);
		break;
	case 18:
		offset = fConfirmedPrivateTransferRequest(tvb, pinfo, tree, offset);
		break;
	case 19:
		offset = fConfirmedTextMessageRequest(tvb, pinfo, tree, offset);
		break;
	case 20:
		offset = fReinitializeDeviceRequest(tvb, tree, offset);
		break;
	case 21:
		offset = fVtOpenRequest(tvb, pinfo, tree, offset);
		break;
	case 22:
		offset = fVtCloseRequest (tvb, pinfo, tree, offset);
		break;
	case 23:
		offset = fVtDataRequest (tvb, pinfo, tree, offset);
		break;
	case 24:
		offset = fAuthenticateRequest (tvb, tree, offset);
		break;
	case 25:
		offset = fRequestKeyRequest (tvb, pinfo, tree, offset);
		break;
	case 26:
		offset = fReadRangeRequest (tvb, pinfo, tree, offset);
		break;
	case 27:
		offset = fLifeSafetyOperationRequest(tvb, pinfo, tree, offset, NULL);
		break;
	case 28:
		offset = fSubscribeCOVPropertyRequest(tvb, pinfo, tree, offset);
		break;
	case 29:
		offset = fGetEventInformationRequest (tvb, pinfo, tree, offset);
		break;
	default:
		return offset;
	}
	return offset;
}

static guint
fConfirmedServiceAck (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, gint service_choice)
{
	if (tvb_reported_length_remaining(tvb,offset) <= 0)
		return offset;

	switch (service_choice) {
	case 3: /* confirmedEventNotificationAck */
		offset = fGetAlarmSummaryAck (tvb, pinfo, tree, offset);
		break;
	case 4: /* getEnrollmentSummaryAck */
		offset = fGetEnrollmentSummaryAck (tvb, pinfo, tree, offset);
		break;
	case 6: /* atomicReadFile */
		offset = fAtomicReadFileAck (tvb, pinfo, tree, offset);
		break;
	case 7: /* atomicReadFileAck */
		offset = fAtomicWriteFileAck (tvb, tree, offset);
		break;
	case 10: /* createObject */
		offset = fCreateObjectAck (tvb, pinfo, tree, offset);
		break;
	case 12:
		offset = fReadPropertyAck (tvb, pinfo, tree, offset);
		break;
	case 13:
		offset = fReadPropertyConditionalAck (tvb, pinfo, tree, offset);
		break;
	case 14:
		offset = fReadPropertyMultipleAck (tvb, pinfo, tree, offset);
		break;
	case 18:
		offset = fConfirmedPrivateTransferAck(tvb, pinfo, tree, offset);
		break;
	case 21:
		offset = fVtOpenAck (tvb, pinfo, tree, offset);
		break;
	case 23:
		offset = fVtDataAck (tvb, tree, offset);
		break;
	case 24:
		offset = fAuthenticateAck (tvb, pinfo, tree, offset);
		break;
	case 26:
		offset = fReadRangeAck (tvb, pinfo, tree, offset);
		break;
	case 29:
		offset = fGetEventInformationACK (tvb, pinfo, tree, offset);
		break;
	default:
		return offset;
	}
	return offset;
}

static guint
fIAmRequest  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	/* BACnetObjectIdentifier */
	offset = fApplicationTypes (tvb, pinfo, tree, offset, "BACnet Object Identifier: ");

	/* MaxAPDULengthAccepted */
	offset = fApplicationTypes (tvb, pinfo, tree, offset, "Maximum ADPU Length Accepted: ");

	/* segmentationSupported */
	offset = fApplicationTypesEnumerated (tvb, pinfo, tree, offset,
		"Segmentation Supported: ", BACnetSegmentation);

	/* vendor ID */
	return fVendorIdentifier (tvb, pinfo, tree, offset);
}

static guint
fIHaveRequest  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	/* BACnetDeviceIdentifier */
	offset = fApplicationTypes (tvb, pinfo, tree, offset, "Device Identifier: ");

	/* BACnetObjectIdentifier */
	offset = fApplicationTypes (tvb, pinfo, tree, offset, "Object Identifier: ");

	/* ObjectName */
	return fApplicationTypes (tvb, pinfo, tree, offset, "Object Name: ");

}

static guint
fWhoIsRequest  (tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint val;
	guint8 tag_len;

	guint8 tag_no, tag_info;
	guint32 lvt;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;

		tag_len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);

		switch (tag_no) {
		case 0:
			/* DeviceInstanceRangeLowLimit Optional */
			fUnsigned32(tvb, offset+tag_len, lvt, &val);
			if (col_get_writable(pinfo->cinfo))
				col_append_fstr(pinfo->cinfo, COL_INFO, "%d ", val);
			offset = fDevice_Instance (tvb, tree, offset,
				hf_Device_Instance_Range_Low_Limit);
			break;
		case 1:
			/* DeviceInstanceRangeHighLimit Optional but
				required if DeviceInstanceRangeLowLimit is there */
			fUnsigned32(tvb, offset+tag_len, lvt, &val);
			if (col_get_writable(pinfo->cinfo))
				col_append_fstr(pinfo->cinfo, COL_INFO, "%d ", val);
			offset = fDevice_Instance (tvb, tree, offset,
				hf_Device_Instance_Range_High_Limit);
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
 	return offset;
}

static guint
fUnconfirmedServiceRequest  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, gint service_choice)
{
	if (tvb_reported_length_remaining(tvb,offset) <= 0)
		return offset;

	switch (service_choice) {
	case 0:	/* I-Am-Request */
		offset = fIAmRequest  (tvb, pinfo, tree, offset);
		break;
	case 1: /* i-Have Request */
		offset = fIHaveRequest  (tvb, pinfo, tree, offset);
	break;
	case 2: /* unconfirmedCOVNotification */
		offset = fUnconfirmedCOVNotificationRequest (tvb, pinfo, tree, offset);
		break;
	case 3: /* unconfirmedEventNotification */
		offset = fUnconfirmedEventNotificationRequest (tvb, pinfo, tree, offset);
		break;
	case 4: /* unconfirmedPrivateTransfer */
		offset = fUnconfirmedPrivateTransferRequest(tvb, pinfo, tree, offset);
		break;
	case 5: /* unconfirmedTextMessage */
		offset = fUnconfirmedTextMessageRequest(tvb, pinfo, tree, offset);
		break;
	case 6: /* timeSynchronization */
		offset = fTimeSynchronizationRequest  (tvb, tree, offset);
		break;
	case 7: /* who-Has */
		offset = fWhoHas (tvb, pinfo, tree, offset);
		break;
	case 8: /* who-Is */
		offset = fWhoIsRequest  (tvb, pinfo, tree, offset);
		break;
	case 9: /* utcTimeSynchronization */
		offset = fUTCTimeSynchronizationRequest  (tvb, tree, offset);
		break;
	default:
		break;
	}
	return offset;
}

static guint
fStartConfirmed(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *bacapp_tree, guint offset, guint8 ack,
		gint *svc, proto_item **tt)
{
	proto_item *tc;
	proto_tree *bacapp_tree_control;
	gint tmp;
	guint extra = 2;

	bacapp_seq = 0;
	tmp = (gint) tvb_get_guint8(tvb, offset);
	bacapp_flags = tmp & 0x0f;

	if (ack == 0) {
		extra = 3;
	}
	*svc = (gint) tvb_get_guint8(tvb, offset+extra);
	if (bacapp_flags & 0x08)
		*svc = (gint) tvb_get_guint8(tvb, offset+extra+2);

	proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	tc = proto_tree_add_item(bacapp_tree, hf_bacapp_pduflags, tvb, offset, 1, ENC_BIG_ENDIAN);
	bacapp_tree_control = proto_item_add_subtree(tc, ett_bacapp_control);

	proto_tree_add_item(bacapp_tree_control, hf_bacapp_SEG, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(bacapp_tree_control, hf_bacapp_MOR, tvb, offset, 1, ENC_BIG_ENDIAN);
	if (ack == 0) { /* The following are for ConfirmedRequest, not Complex ack */
	    proto_tree_add_item(bacapp_tree_control, hf_bacapp_SA, tvb, offset++, 1, ENC_BIG_ENDIAN);
	    proto_tree_add_item(bacapp_tree, hf_bacapp_response_segments, tvb,
							offset, 1, ENC_BIG_ENDIAN);
	    proto_tree_add_item(bacapp_tree, hf_bacapp_max_adpu_size, tvb,
							offset, 1, ENC_BIG_ENDIAN);
	}
	offset++;
	proto_tree_add_item(bacapp_tree, hf_bacapp_invoke_id, tvb, offset++, 1, ENC_BIG_ENDIAN);
	if (bacapp_flags & 0x08) {
		bacapp_seq = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(bacapp_tree, hf_bacapp_sequence_number, tvb,
		    offset++, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(bacapp_tree, hf_bacapp_window_size, tvb,
		    offset++, 1, ENC_BIG_ENDIAN);
	}
	*tt = proto_tree_add_item(bacapp_tree, hf_bacapp_service, tvb,
				  offset++, 1, ENC_BIG_ENDIAN);
	return offset;
}

static guint
fContinueConfirmedRequestPDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *bacapp_tree, guint offset, gint svc)
{	/* BACnet-Confirmed-Request */
	/* ASHRAE 135-2001 20.1.2 */

	return fConfirmedServiceRequest (tvb, pinfo, bacapp_tree, offset, svc);
}

static guint
fConfirmedRequestPDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *bacapp_tree, guint offset)
{	/* BACnet-Confirmed-Request */
	/* ASHRAE 135-2001 20.1.2 */
	gint svc;
	proto_item *tt = 0;

	offset = fStartConfirmed(tvb, pinfo, bacapp_tree, offset, 0, &svc, &tt);
	return fContinueConfirmedRequestPDU(tvb, pinfo, bacapp_tree, offset, svc);
}

static guint
fUnconfirmedRequestPDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *bacapp_tree, guint offset)
{	/* BACnet-Unconfirmed-Request-PDU */
	/* ASHRAE 135-2001 20.1.3 */

	gint tmp;

	proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, offset++, 1, ENC_BIG_ENDIAN);

	tmp = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(bacapp_tree, hf_bacapp_uservice, tvb,
	    offset++, 1, ENC_BIG_ENDIAN);
	/* Service Request follows... Variable Encoding 20.2ff */
	return fUnconfirmedServiceRequest  (tvb, pinfo, bacapp_tree, offset, tmp);
}

static guint
fSimpleAckPDU(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *bacapp_tree, guint offset)
{	/* BACnet-Simple-Ack-PDU */
	/* ASHRAE 135-2001 20.1.4 */

	proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, offset++, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(bacapp_tree, hf_bacapp_invoke_id, tvb,
			    offset++, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(bacapp_tree, hf_bacapp_service, tvb,
			    offset++, 1, ENC_BIG_ENDIAN);

	return offset;
}

static guint
fContinueComplexAckPDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *bacapp_tree, guint offset, gint svc)
{	/* BACnet-Complex-Ack-PDU */
	/* ASHRAE 135-2001 20.1.5 */

	/* Service ACK follows... */
	return fConfirmedServiceAck (tvb, pinfo, bacapp_tree, offset, svc);
}

static guint
fComplexAckPDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *bacapp_tree, guint offset)
{	/* BACnet-Complex-Ack-PDU */
	/* ASHRAE 135-2001 20.1.5 */
	gint svc;
	proto_item *tt = 0;

	offset = fStartConfirmed(tvb, pinfo, bacapp_tree, offset, 1, &svc, &tt);
	return fContinueComplexAckPDU(tvb, pinfo, bacapp_tree, offset, svc);
}

static guint
fSegmentAckPDU(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *bacapp_tree, guint offset)
{	/* BACnet-SegmentAck-PDU */
	/* ASHRAE 135-2001 20.1.6 */

	proto_item *tc;
	proto_tree *bacapp_tree_control;

	tc = proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	bacapp_tree_control = proto_item_add_subtree(tc, ett_bacapp);

	proto_tree_add_item(bacapp_tree_control, hf_bacapp_NAK, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(bacapp_tree_control, hf_bacapp_SRV, tvb, offset++, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(bacapp_tree_control, hf_bacapp_invoke_id, tvb,
			    offset++, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(bacapp_tree_control, hf_bacapp_sequence_number, tvb,
			    offset++, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(bacapp_tree_control, hf_bacapp_window_size, tvb,
			    offset++, 1, ENC_BIG_ENDIAN);
	return offset;
}

static guint
fContextTaggedError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint8 tag_info = 0;
	guint8 parsed_tag = 0;
	guint32 lvt = 0;
	offset += fTagHeaderTree(tvb, tree, offset, &parsed_tag, &tag_info, &lvt);
	offset = fError(tvb, pinfo, tree, offset);
	return offset + fTagHeaderTree(tvb, tree, offset, &parsed_tag, &tag_info, &lvt);
}

static guint
fConfirmedPrivateTransferError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no = 0, tag_info = 0;
	guint32 lvt = 0;
	proto_tree *subtree = tree;
	proto_item *tt;

	guint vendor_identifier = 0;
	guint service_number = 0;
	guint8 tag_len = 0;

	while (tvb_reported_length_remaining(tvb, offset)) {
		/* exit loop if nothing happens inside */
		lastoffset = offset;
		tag_len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		switch (tag_no) {
		case 0:	/* errorType */
			offset = fContextTaggedError(tvb, pinfo, subtree, offset);
			break;
		case 1:	/* vendorID */
			fUnsigned32(tvb, offset+tag_len, lvt, &vendor_identifier);
			if (col_get_writable(pinfo->cinfo))
				col_append_fstr(pinfo->cinfo, COL_INFO, "V=%u ",	vendor_identifier);
			offset = fVendorIdentifier (tvb, pinfo, subtree, offset);
			break;
		case 2:	/* serviceNumber */
			fUnsigned32(tvb, offset+tag_len, lvt, &service_number);
			if (col_get_writable(pinfo->cinfo))
				col_append_fstr(pinfo->cinfo, COL_INFO, "SN=%u ",	service_number);
			offset = fUnsignedTag (tvb, subtree, offset, "service Number: ");
			break;
		case 3: /* errorParameters */
			if (tag_is_opening(tag_info)) {
				tt = proto_tree_add_text(subtree, tvb, offset, 1,
					"error Parameters");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				propertyIdentifier = -1;
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fAbstractSyntaxNType (tvb, pinfo, subtree, offset);
			} else if (tag_is_closing(tag_info)) {
				offset += fTagHeaderTree (tvb, subtree, offset,
					&tag_no, &tag_info, &lvt);
				subtree = tree;
			} else {
				/* error condition: let caller handle */
				return offset;
			}
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fCreateObjectError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0:	/* errorType */
			offset = fContextTaggedError(tvb, pinfo, tree, offset);
			break;
		case 1:	/* firstFailedElementNumber */
			offset = fUnsignedTag (tvb,tree,offset,"first failed element number: ");
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fChangeListError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	/* Identical to CreateObjectError */
	return fCreateObjectError(tvb, pinfo, tree, offset);
}

static guint
fVTCloseError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint8 tag_no = 0, tag_info = 0;
	guint32 lvt = 0;

	if (fTagNo(tvb, offset) == 0) {
		/* errorType */
		offset = fContextTaggedError(tvb, pinfo, tree,offset);
		if (fTagNo(tvb, offset) == 1) {
			/* listOfVTSessionIdentifiers [OPTIONAL] */
			offset += fTagHeaderTree(tvb, tree, offset, &tag_no, &tag_info, &lvt);
			offset = fVtCloseRequest (tvb, pinfo, tree, offset);
			offset += fTagHeaderTree(tvb, tree, offset, &tag_no, &tag_info, &lvt);
		}
	}
	/* should report bad packet if initial tag wasn't 0 */
	return offset;
}

static guint
fWritePropertyMultipleError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no = 0, tag_info = 0;
	guint32 lvt = 0;

	col_set_writable(pinfo->cinfo, FALSE); /* don't set all infos into INFO column */
	while (tvb_reported_length_remaining(tvb, offset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0:	/* errorType */
			offset = fContextTaggedError(tvb, pinfo, tree, offset);
			break;
		case 1:	/* firstFailedWriteAttempt */
			offset += fTagHeaderTree(tvb, tree, offset, &tag_no, &tag_info, &lvt);
			offset = fBACnetObjectPropertyReference(tvb, pinfo, tree, offset);
			offset += fTagHeaderTree(tvb, tree, offset, &tag_no, &tag_info, &lvt);
			break;
		default:
			return offset;
		}
		if (offset == lastoffset) break;     /* nothing happened, exit loop */
	}
	return offset;
}

static guint
fError (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
	offset = fApplicationTypesEnumeratedSplit (tvb, pinfo, tree, offset,
						   "error Class: ", BACnetErrorClass, 64);
	return fApplicationTypesEnumeratedSplit (tvb, pinfo, tree, offset,
						 "error Code: ", BACnetErrorCode, 256);
}

static guint
fBACnetError (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint service)
{
	switch (service) {
	case 8:  /* no break here !!!! */
	case 9:
		offset = fChangeListError (tvb, pinfo, tree, offset);
		break;
	case 10:
		offset = fCreateObjectError (tvb, pinfo, tree, offset);
		break;
	case 16:
		offset = fWritePropertyMultipleError (tvb, pinfo, tree, offset);
		break;
	case 18:
		offset = fConfirmedPrivateTransferError (tvb,pinfo,tree,offset);
		break;
	case 22:
		offset = fVTCloseError (tvb, pinfo, tree, offset);
		break;
	default:
		return fError (tvb, pinfo, tree, offset);
	}
	return offset;
}

static guint
fErrorPDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *bacapp_tree, guint offset)
{	/* BACnet-Error-PDU */
	/* ASHRAE 135-2001 20.1.7 */

	proto_item *tc;
	proto_tree *bacapp_tree_control;
	guint8 tmp;

	tc = proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, offset++, 1, ENC_BIG_ENDIAN);
	bacapp_tree_control = proto_item_add_subtree(tc, ett_bacapp);

	proto_tree_add_item(bacapp_tree_control, hf_bacapp_invoke_id, tvb,
			    offset++, 1, ENC_BIG_ENDIAN);
	tmp = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(bacapp_tree_control, hf_bacapp_service, tvb,
				 offset++, 1, ENC_BIG_ENDIAN);
	/* Error Handling follows... */
	return fBACnetError (tvb, pinfo, bacapp_tree, offset, tmp);
}

static guint
fRejectPDU(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *bacapp_tree, guint offset)
{	/* BACnet-Reject-PDU */
	/* ASHRAE 135-2001 20.1.8 */

	proto_item *tc;
	proto_tree *bacapp_tree_control;

	tc = proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, offset++, 1, ENC_BIG_ENDIAN);
	bacapp_tree_control = proto_item_add_subtree(tc, ett_bacapp);

	proto_tree_add_item(bacapp_tree_control, hf_bacapp_invoke_id, tvb,
			    offset++, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(bacapp_tree_control, hf_BACnetRejectReason, tvb,
			    offset++, 1, ENC_BIG_ENDIAN);
	return offset;
}

static guint
fAbortPDU(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *bacapp_tree, guint offset)
{	/* BACnet-Abort-PDU */
	/* ASHRAE 135-2001 20.1.9 */

	proto_item *tc;
	proto_tree *bacapp_tree_control;

	tc = proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	bacapp_tree_control = proto_item_add_subtree(tc, ett_bacapp);

	proto_tree_add_item(bacapp_tree_control, hf_bacapp_SRV, tvb, offset++, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(bacapp_tree_control, hf_bacapp_invoke_id, tvb,
			    offset++, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(bacapp_tree_control, hf_BACnetAbortReason, tvb,
			    offset++, 1, ENC_BIG_ENDIAN);
	return offset;
}

static guint
do_the_dissection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 flag, bacapp_type;
	guint offset = 0;

	flag = (gint) tvb_get_guint8(tvb, 0);
	bacapp_type = (flag >> 4) & 0x0f;

	if (tvb == NULL) {
		return 0;
	}

	/* ASHRAE 135-2001 20.1.1 */
	switch (bacapp_type) {
	case BACAPP_TYPE_CONFIRMED_SERVICE_REQUEST:	/* BACnet-Confirmed-Service-Request */
		offset = fConfirmedRequestPDU(tvb, pinfo, tree, offset);
		break;
	case BACAPP_TYPE_UNCONFIRMED_SERVICE_REQUEST:	/* BACnet-Unconfirmed-Request-PDU */
		offset = fUnconfirmedRequestPDU(tvb, pinfo, tree, offset);
		break;
	case BACAPP_TYPE_SIMPLE_ACK:	/* BACnet-Simple-Ack-PDU */
		offset = fSimpleAckPDU(tvb, pinfo, tree, offset);
		break;
	case BACAPP_TYPE_COMPLEX_ACK:	/* BACnet-Complex-Ack-PDU */
		offset = fComplexAckPDU(tvb, pinfo, tree, offset);
		break;
	case BACAPP_TYPE_SEGMENT_ACK:	/* BACnet-SegmentAck-PDU */
		offset = fSegmentAckPDU(tvb, pinfo, tree, offset);
		break;
	case BACAPP_TYPE_ERROR:	/* BACnet-Error-PDU */
		offset = fErrorPDU(tvb, pinfo, tree, offset);
		break;
	case BACAPP_TYPE_REJECT:	/* BACnet-Reject-PDU */
		offset = fRejectPDU(tvb, pinfo, tree, offset);
		break;
	case BACAPP_TYPE_ABORT:	/* BACnet-Abort-PDU */
		offset = fAbortPDU(tvb, pinfo, tree, offset);
		break;
	}
	return offset;
}

static void
dissect_bacapp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 flag, bacapp_type;
	guint save_fragmented = FALSE, data_offset = 0, /*bacapp_apdu_size,*/ fragment = FALSE;
	tvbuff_t* new_tvb = NULL;
	guint offset = 0;
	guint8 bacapp_seqno = 0;
	guint8 bacapp_service, bacapp_reason/*, bacapp_prop_win_size*/;
	guint8 bacapp_invoke_id = 0;
	proto_item *ti;
	proto_tree *bacapp_tree = NULL;

	gint svc = 0;
	proto_item *tt = 0;
	gint8 ack = 0;

	/* Strings for BACnet Statistics */
	const gchar errstr[]="ERROR: ";
	const gchar rejstr[]="REJECTED: ";
	const gchar abortstr[]="ABORTED: ";
	const gchar sackstr[]=" (SimpleAck)";
	const gchar cackstr[]=" (ComplexAck)";
	const gchar uconfsreqstr[]=" (Unconfirmed Service Request)";
	const gchar confsreqstr[]=" (Confirmed Service Request)";

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BACnet-APDU");
	col_clear (pinfo->cinfo, COL_INFO);

	flag = tvb_get_guint8(tvb, 0);
	bacapp_type = (flag >> 4) & 0x0f;

	/* show some descriptive text in the INFO column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "%-16s",
		val_to_str(bacapp_type, BACnetTypeName, "# unknown APDU #"));

	bacinfo.service_type = NULL;
	bacinfo.invoke_id = NULL;
	bacinfo.instance_ident = NULL;
	bacinfo.object_ident = NULL;

	switch (bacapp_type)
	{
		case BACAPP_TYPE_CONFIRMED_SERVICE_REQUEST:
			/* segmented messages have 2 additional bytes */
			if (flag & BACAPP_SEGMENTED_REQUEST) {
				fragment = TRUE;
				ack = 0;
				/* bacapp_apdu_size = fGetMaxAPDUSize(tvb_get_guint8(tvb, offset + 1)); */ /* has 16 values, reserved are 50 Bytes */
				bacapp_invoke_id = tvb_get_guint8(tvb, offset + 2);
				bacapp_seqno = tvb_get_guint8(tvb, offset + 3);
				/* bacapp_prop_win_size = tvb_get_guint8(tvb, offset + 4); */
				bacapp_service = tvb_get_guint8(tvb, offset + 5);
				data_offset = 6;
			} else {
				bacapp_invoke_id = tvb_get_guint8(tvb, offset + 2);
				bacapp_service = tvb_get_guint8(tvb, offset + 3);
			}
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s[%3u] ",
				val_to_str(bacapp_service,
					BACnetConfirmedServiceChoice,
					bacapp_unknown_service_str),bacapp_invoke_id);

			updateBacnetInfoValue(BACINFO_INVOKEID,
					      ep_strdup_printf("Invoke ID: %d", bacapp_invoke_id));

			updateBacnetInfoValue(BACINFO_SERVICE,
			    ep_strconcat(val_to_str(bacapp_service,
						    BACnetConfirmedServiceChoice,
						    bacapp_unknown_service_str),
					 confsreqstr, NULL));
			break;
		case BACAPP_TYPE_UNCONFIRMED_SERVICE_REQUEST:
			bacapp_service = tvb_get_guint8(tvb, offset + 1);
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
				val_to_str(bacapp_service,
					BACnetUnconfirmedServiceChoice,
					bacapp_unknown_service_str));

			updateBacnetInfoValue(BACINFO_SERVICE,
			    ep_strconcat(val_to_str(bacapp_service,
						    BACnetUnconfirmedServiceChoice,
						    bacapp_unknown_service_str),
					 uconfsreqstr, NULL));
			break;
		case BACAPP_TYPE_SIMPLE_ACK:
			bacapp_invoke_id = tvb_get_guint8(tvb, offset + 1);
			bacapp_service = tvb_get_guint8(tvb, offset + 2);
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s[%3u] ", /* "original-invokeID" replaced */
				val_to_str(bacapp_service,
					BACnetConfirmedServiceChoice,
					bacapp_unknown_service_str), bacapp_invoke_id);

			updateBacnetInfoValue(BACINFO_INVOKEID,
					      ep_strdup_printf("Invoke ID: %d", bacapp_invoke_id));

			updateBacnetInfoValue(BACINFO_SERVICE,
			    ep_strconcat(val_to_str(bacapp_service,
						    BACnetConfirmedServiceChoice,
						    bacapp_unknown_service_str),
					 sackstr, NULL));
			break;
		case BACAPP_TYPE_COMPLEX_ACK:
			/* segmented messages have 2 additional bytes */
			if (flag & BACAPP_SEGMENTED_REQUEST) {
				fragment = TRUE;
				ack = 1;
				/* bacapp_apdu_size = fGetMaxAPDUSize(0); */ /* has minimum of 50 Bytes */
				bacapp_invoke_id = tvb_get_guint8(tvb, offset + 1);
				bacapp_seqno = tvb_get_guint8(tvb, offset + 2);
				/* bacapp_prop_win_size = tvb_get_guint8(tvb, offset + 3); */
				bacapp_service = tvb_get_guint8(tvb, offset + 4);
				data_offset = 5;
			} else {
				bacapp_invoke_id = tvb_get_guint8(tvb, offset + 1);
				bacapp_service = tvb_get_guint8(tvb, offset + 2);
			}
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s[%3u] ", /* "original-invokeID" replaced */
				val_to_str(bacapp_service,
					BACnetConfirmedServiceChoice,
					bacapp_unknown_service_str), bacapp_invoke_id);

			updateBacnetInfoValue(BACINFO_INVOKEID,
					      ep_strdup_printf("Invoke ID: %d", bacapp_invoke_id));

			updateBacnetInfoValue(BACINFO_SERVICE,
			    ep_strconcat(val_to_str(bacapp_service,
			    			    BACnetConfirmedServiceChoice,
						    bacapp_unknown_service_str),
					 cackstr, NULL));
			break;
		case BACAPP_TYPE_SEGMENT_ACK:
			/* nothing more to add */
			break;
		case BACAPP_TYPE_ERROR:
			bacapp_invoke_id = tvb_get_guint8(tvb, offset + 1);
			bacapp_service = tvb_get_guint8(tvb, offset + 2);
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s[%3u] ", /* "original-invokeID" replaced */
				val_to_str(bacapp_service,
					BACnetConfirmedServiceChoice,
					bacapp_unknown_service_str), bacapp_invoke_id);

			updateBacnetInfoValue(BACINFO_INVOKEID,
					      ep_strdup_printf("Invoke ID: %d", bacapp_invoke_id));

			updateBacnetInfoValue(BACINFO_SERVICE,
			    ep_strconcat(errstr,
					 val_to_str(bacapp_service,
						    BACnetConfirmedServiceChoice,
						    bacapp_unknown_service_str),
					 NULL));
			break;
		case BACAPP_TYPE_REJECT:
			bacapp_invoke_id = tvb_get_guint8(tvb, offset + 1);
			bacapp_reason = tvb_get_guint8(tvb, offset + 2);
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s[%3u] ", /* "original-invokeID" replaced */
				val_to_split_str(bacapp_reason,
					64,
					BACnetRejectReason,
					ASHRAE_Reserved_Fmt,
					Vendor_Proprietary_Fmt), bacapp_invoke_id);

			updateBacnetInfoValue(BACINFO_INVOKEID,
					      ep_strdup_printf("Invoke ID: %d", bacapp_invoke_id));

			updateBacnetInfoValue(BACINFO_SERVICE,
				ep_strconcat(rejstr,
					     val_to_split_str(bacapp_reason, 64,
					     BACnetRejectReason,
					     ASHRAE_Reserved_Fmt,
					     Vendor_Proprietary_Fmt),
					     NULL));
			break;
		case BACAPP_TYPE_ABORT:
			bacapp_invoke_id = tvb_get_guint8(tvb, offset + 1);
			bacapp_reason = tvb_get_guint8(tvb, offset + 2);
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s[%3u] ", /* "original-invokeID" replaced */
				val_to_split_str(bacapp_reason,
					64,
					BACnetAbortReason,
					ASHRAE_Reserved_Fmt,
					Vendor_Proprietary_Fmt), bacapp_invoke_id);

			updateBacnetInfoValue(BACINFO_INVOKEID,
					      ep_strdup_printf("Invoke ID: %d", bacapp_invoke_id));

			updateBacnetInfoValue(BACINFO_SERVICE,
				ep_strconcat(abortstr,
					     val_to_split_str(bacapp_reason,
							      64,
							      BACnetAbortReason,
							      ASHRAE_Reserved_Fmt,
							      Vendor_Proprietary_Fmt),
					     NULL));
			break;
		/* UNKNOWN */
		default:
			/* nothing more to add */
			break;
	}

	save_fragmented = pinfo->fragmented;

	ti = proto_tree_add_item(tree, proto_bacapp, tvb, offset, -1, FALSE);
	bacapp_tree = proto_item_add_subtree(ti, ett_bacapp);

	if (!fragment)
		offset = do_the_dissection(tvb,pinfo,bacapp_tree);
	else
		fStartConfirmed(tvb, pinfo, bacapp_tree, offset, ack, &svc, &tt);
			/* not resetting the offset so the remaining can be done */

	if (fragment) { /* fragmented */
		fragment_data *frag_msg = NULL;

		new_tvb = NULL;
		pinfo->fragmented = TRUE;

		frag_msg = fragment_add_seq_check(tvb, data_offset, pinfo,
			bacapp_invoke_id, /* ID for fragments belonging together */
			msg_fragment_table, /* list of message fragments */
			msg_reassembled_table, /* list of reassembled messages */
			bacapp_seqno, /* fragment sequence number */
			tvb_reported_length_remaining(tvb, data_offset), /* fragment length - to the end */
			flag & BACAPP_MORE_SEGMENTS); /* Last fragment reached? */
		new_tvb = process_reassembled_data(tvb, data_offset, pinfo,
				"Reassembled BACapp", frag_msg, &msg_frag_items,
				NULL, tree);

		if (new_tvb) { /* Reassembled */
			col_append_str(pinfo->cinfo, COL_INFO,
				" (Message Reassembled)");
		} else { /* Not last packet of reassembled Short Message */
			col_append_fstr(pinfo->cinfo, COL_INFO,
			" (Message fragment %u)", bacapp_seqno);
		}
		if (new_tvb) { /* take it all */
			switch (bacapp_type)
			{
				case BACAPP_TYPE_CONFIRMED_SERVICE_REQUEST:
					fContinueConfirmedRequestPDU(new_tvb, pinfo, bacapp_tree, 0, svc);
				break;
				case BACAPP_TYPE_COMPLEX_ACK:
					fContinueComplexAckPDU(new_tvb, pinfo, bacapp_tree, 0, svc);
				break;
				default:
					/* do nothing */
				break;
			}
			/* } */
		}
	}

	pinfo->fragmented = save_fragmented;

	/* tapping */
	tap_queue_packet(bacapp_tap,pinfo,&bacinfo);
}

static void
bacapp_init_routine(void)
{
	fragment_table_init(&msg_fragment_table);
	reassembled_table_init(&msg_reassembled_table);
}

static guint32
fConvertXXXtoUTF8 (gchar *in, gsize *inbytesleft, gchar *out, gsize *outbytesleft, const gchar *fromcoding)
{
	guint32 i;
	GIConv icd;

	if ((icd = g_iconv_open ("UTF-8", fromcoding)) != (GIConv) -1) {
		i = (guint32) g_iconv (icd, &in, inbytesleft, &out, outbytesleft);
		/* g_iconv incremented 'out'; now ensure it's NULL terminated */
		out[0] = '\0';

		g_iconv_close (icd);
		return i;
	}

	uni_to_string(in,*inbytesleft,out);
	out[*inbytesleft] = '\0';
	*outbytesleft -= *inbytesleft;
	*inbytesleft = 0;

	return 0;
}

static void
uni_to_string(char * data, gsize str_length, char *dest_buf)
{
	gint i;
	guint16 c_char;
	gsize length_remaining = 0;

	length_remaining = str_length;
	dest_buf[0] = '\0';
	if(str_length == 0) {
		return;
	}
	for ( i = 0; i < (gint) str_length; i++ ) {
		c_char = data[i];
		if (c_char<0x20 || c_char>0x7e) {
			if (c_char != 0x00) {
				c_char = '.';
				dest_buf[i] = c_char & 0xff;
			} else {
				i--;
				str_length--;
			}
		} else {
			dest_buf[i] = c_char & 0xff;
		}
		length_remaining--;

		if(length_remaining==0) {
			dest_buf[i+1] = '\0';
			return;
		}
	}
	if (i < 0) {
		i = 0;
	}
	dest_buf[i] = '\0';
	return;
}

void
proto_register_bacapp(void)
{
	static hf_register_info hf[] = {
		{ &hf_bacapp_type,
			{ "APDU Type",           "bacapp.type",
			FT_UINT8, BASE_DEC, VALS(BACnetTypeName), 0xf0, NULL, HFILL }
		},
		{ &hf_bacapp_pduflags,
			{ "PDU Flags",			"bacapp.pduflags",
			FT_UINT8, BASE_HEX, NULL, 0x0f,	NULL, HFILL }
		},
		{ &hf_bacapp_SEG,
			{ "Segmented Request",           "bacapp.segmented_request",
			FT_BOOLEAN, 8, TFS(&segments_follow), 0x08, NULL, HFILL }
		},
		{ &hf_bacapp_MOR,
			{ "More Segments",           "bacapp.more_segments",
			FT_BOOLEAN, 8, TFS(&more_follow), 0x04, "More Segments Follow", HFILL }
		},
		{ &hf_bacapp_SA,
			{ "SA",           "bacapp.SA",
			FT_BOOLEAN, 8, TFS(&segmented_accept), 0x02, "Segmented Response accepted", HFILL }
		},
		{ &hf_bacapp_max_adpu_size,
			{ "Size of Maximum ADPU accepted",           "bacapp.max_adpu_size",
			FT_UINT8, BASE_DEC, VALS(BACnetMaxAPDULengthAccepted), 0x0f, NULL, HFILL }
		},
		{ &hf_bacapp_response_segments,
			{ "Max Response Segments accepted",           "bacapp.response_segments",
			FT_UINT8, BASE_DEC, VALS(BACnetMaxSegmentsAccepted), 0x70, NULL, HFILL }
		},
		{ &hf_bacapp_objectType,
			{ "Object Type",           "bacapp.objectType",
			FT_UINT32, BASE_DEC, VALS(BACnetObjectType), 0xffc00000, NULL, HFILL }
		},
		{ &hf_bacapp_instanceNumber,
			{ "Instance Number",           "bacapp.instance_number",
			FT_UINT32, BASE_DEC, NULL, 0x003fffff, NULL, HFILL }
		},
		{ &hf_BACnetPropertyIdentifier,
			{ "Property Identifier", "bacapp.property_identifier",
			FT_UINT32, BASE_DEC, VALS(BACnetPropertyIdentifier), 0, NULL, HFILL }
		},
		{ &hf_BACnetVendorIdentifier,
			{ "Vendor Identifier", "bacapp.vendor_identifier",
			FT_UINT16, BASE_DEC, VALS(BACnetVendorIdentifiers), 0, NULL, HFILL }
		},
		{ &hf_BACnetRestartReason,
			{ "Restart Reason", "bacapp.restart_reason",
			FT_UINT8, BASE_DEC, VALS(BACnetRestartReason), 0, NULL, HFILL }
		},
		{ &hf_bacapp_invoke_id,
			{ "Invoke ID",           "bacapp.invoke_id",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_bacapp_sequence_number,
			{ "Sequence Number",           "bacapp.sequence_number",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_bacapp_window_size,
			{ "Proposed Window Size",           "bacapp.window_size",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_bacapp_service,
			{ "Service Choice",           "bacapp.confirmed_service",
			FT_UINT8, BASE_DEC, VALS(BACnetConfirmedServiceChoice), 0x00, NULL, HFILL }
		},
		{ &hf_bacapp_uservice,
			{ "Unconfirmed Service Choice",           "bacapp.unconfirmed_service",
			FT_UINT8, BASE_DEC, VALS(BACnetUnconfirmedServiceChoice), 0x00, NULL, HFILL }
		},
		{ &hf_bacapp_NAK,
			{ "NAK",           "bacapp.NAK",
			FT_BOOLEAN, 8, NULL, 0x02, "negative ACK", HFILL }
		},
		{ &hf_bacapp_SRV,
			{ "SRV",           "bacapp.SRV",
			FT_BOOLEAN, 8, NULL, 0x01, "Server", HFILL }
		},
		{ &hf_Device_Instance_Range_Low_Limit,
			{ "Device Instance Range Low Limit", "bacapp.who_is.low_limit",
			FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_Device_Instance_Range_High_Limit,
			{ "Device Instance Range High Limit", "bacapp.who_is.high_limit",
			FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_BACnetRejectReason,
			{ "Reject Reason",           "bacapp.reject_reason",
			FT_UINT8, BASE_DEC, VALS(BACnetRejectReason), 0x00, NULL, HFILL }
		},
		{ &hf_BACnetAbortReason,
			{ "Abort Reason",           "bacapp.abort_reason",
			FT_UINT8, BASE_DEC, VALS(BACnetAbortReason), 0x00, NULL, HFILL }
		},
		{ &hf_BACnetApplicationTagNumber,
			{ "Application Tag Number",
			"bacapp.application_tag_number",
			FT_UINT8, BASE_DEC, VALS(BACnetApplicationTagNumber), 0xF0,
			NULL, HFILL }
		},
		{ &hf_BACnetContextTagNumber,
			{ "Context Tag Number",
			"bacapp.context_tag_number",
			FT_UINT8, BASE_DEC, NULL, 0xF0,
			NULL, HFILL }
		},
		{ &hf_BACnetExtendedTagNumber,
			{ "Extended Tag Number",
			"bacapp.extended_tag_number",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_BACnetNamedTag,
			{ "Named Tag",
			"bacapp.named_tag",
			FT_UINT8, BASE_DEC, VALS(BACnetTagNames), 0x07,
			NULL, HFILL }
		},
		{ &hf_BACnetCharacterSet,
			{ "String Character Set",
			"bacapp.string_character_set",
			FT_UINT8, BASE_DEC, VALS(BACnetCharacterSet),0,
			NULL, HFILL }
		},
		{ &hf_BACnetTagClass,
			{ "Tag Class",           "bacapp.tag_class",
			FT_BOOLEAN, 8, TFS(&BACnetTagClass), 0x08, NULL, HFILL }
		},
		{ &hf_bacapp_tag_lvt,
			{ "Length Value Type",
			"bacapp.LVT",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacapp_tag_ProcessId,
			{ "ProcessIdentifier",           "bacapp.processId",
			FT_UINT32, BASE_DEC, NULL, 0, "Process Identifier", HFILL }
		},
		{ &hf_bacapp_tag_IPV4,
			{ "IPV4",           "bacapp.IPV4",
			FT_IPv4, BASE_NONE, NULL, 0, "IP-Address", HFILL }
		},
		{ &hf_bacapp_tag_IPV6,
		{ "IPV6",           "bacapp.IPV6",
			FT_IPv6, BASE_NONE, NULL, 0, "IP-Address", HFILL }
		},
		{ &hf_bacapp_tag_PORT,
			{ "Port",           "bacapp.Port",
			FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{&hf_msg_fragments,
			{"Message fragments", "bacapp.fragments",
			FT_NONE, BASE_NONE, NULL, 0x00,	NULL, HFILL } },
		{&hf_msg_fragment,
			{"Message fragment", "bacapp.fragment",
			FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{&hf_msg_fragment_overlap,
			{"Message fragment overlap", "bacapp.fragment.overlap",
			FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{&hf_msg_fragment_overlap_conflicts,
			{"Message fragment overlapping with conflicting data",
			"bacapp.fragment.overlap.conflicts",
			FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{&hf_msg_fragment_multiple_tails,
			{"Message has multiple tail fragments",
			"bacapp.fragment.multiple_tails",
			FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{&hf_msg_fragment_too_long_fragment,
			{"Message fragment too long", "bacapp.fragment.too_long_fragment",
			FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{&hf_msg_fragment_error,
			{"Message defragmentation error", "bacapp.fragment.error",
			FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{&hf_msg_fragment_count,
			{"Message fragment count", "bacapp.fragment.count",
			FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
		{&hf_msg_reassembled_in,
			{"Reassembled in", "bacapp.reassembled.in",
			FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{&hf_msg_reassembled_length,
			{"Reassembled BACapp length", "bacapp.reassembled.length",
			FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } }
	};
	static gint *ett[] = {
		&ett_bacapp,
		&ett_bacapp_control,
		&ett_bacapp_tag,
		&ett_bacapp_list,
		&ett_bacapp_value,
		&ett_msg_fragment,
		&ett_msg_fragments

	};

	proto_bacapp = proto_register_protocol("Building Automation and Control Network APDU",
					       "BACapp", "bacapp");

	proto_register_field_array(proto_bacapp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("bacapp", dissect_bacapp, proto_bacapp);
	register_init_routine (&bacapp_init_routine);

	bacapp_dissector_table = register_dissector_table("bacapp.vendor_identifier",
							  "BACapp Vendor Identifier",
							  FT_UINT8, BASE_HEX);

	/* Register BACnet Statistic trees */
	register_bacapp_stat_trees();
	bacapp_tap = register_tap("bacapp"); /* BACnet statistics tap */
}

void
proto_reg_handoff_bacapp(void)
{
	data_handle = find_dissector("data");
}
