/* packet-bacapp.h
 * Routines for BACnet (APDU) dissection
 * Copyright 2004, Herbert Lischka <lischka@kieback-peter.de>, Berlin
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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

#ifndef __BACAPP_H__
#define __BACAPP_H__

#ifdef HAVE_CONFIG_H
# include "config.h"
#if HAVE_ICONV
#include <iconv.h>
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>

#ifndef min
#define min(a,b) (((a)<(b))?(a):(b))
#endif

#ifndef max
#define max(a,b) (((a)>(b))?(a):(b))
#endif

#ifndef FAULT
#define FAULT 			proto_tree_add_text(subtree, tvb, offset, tvb_length(tvb) - offset, "something is going wrong here !!"); \
			offset = tvb_length(tvb);
#endif

#ifndef false
#define false 0
#endif
#ifndef true
#define true 1
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
 */
void
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
fConfirmedRequestPDU(tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * @param tvb
 * @param tree
 * @param offset
 * @param ack - indocates whether working on request or ack
 * @param svc - output variable to return service choice
 * @param tt  - output varable to return service choice item
 * @return modified offset
 */
static guint
fStartConfirmed(tvbuff_t *tvb, proto_tree *tree, guint offset, guint8 ack,
				gint *svc, proto_item **tt);

/**
 * Unconfirmed-Request-PDU ::= SEQUENCE {
 * 	pdu-type		[0] Unsigned (0..15), -- 1 for this PDU type
 *  reserved		[1] Unsigned (0..15), -- must be set zero
 *  service-choice	[2] BACnetUnconfirmedServiceChoice,
 *  service-request	[3] BACnetUnconfirmedServiceRequest -- Context-specific tags 0..3 are NOT used in header encoding
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fUnconfirmedRequestPDU(tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * SimpleACK-PDU ::= SEQUENCE {
 * 	pdu-type		[0] Unsigned (0..15), -- 2 for this PDU type
 *  reserved		[1] Unsigned (0..15), -- must be set zero
 *  invokeID		[2] Unsigned (0..255),
 *  service-ACK-choice	[3] BACnetUnconfirmedServiceChoice -- Context-specific tags 0..3 are NOT used in header encoding
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fSimpleAckPDU(tvbuff_t *tvb, proto_tree *tree, guint offset);

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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fComplexAckPDU(tvbuff_t *tvb, proto_tree *tree, guint offset);

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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fSegmentAckPDU(tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * Error-PDU ::= SEQUENCE {
 * 	pdu-type				[0] Unsigned (0..15), -- 5 for this PDU Type
 *  reserved				[1] Unsigned (0..3), -- must be set zero
 *  original-invokeID		[2] Unsigned (0..255),
 *  error-choice			[3] BACnetConfirmedServiceChoice,
 *  error					[4] BACnet-Error
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fErrorPDU(tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * Reject-PDU ::= SEQUENCE {
 * 	pdu-type				[0] Unsigned (0..15), -- 6 for this PDU Type
 *  reserved				[1] Unsigned (0..3), -- must be set zero
 *  original-invokeID		[2] Unsigned (0..255),
 *  reject-reason			[3] BACnetRejectReason
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fRejectPDU(tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * Abort-PDU ::= SEQUENCE {
 * 	pdu-type				[0] Unsigned (0..15), -- 7 for this PDU Type
 *  reserved				[1] Unsigned (0..3), -- must be set zero
 *  server					[2] BOOLEAN,
 *  original-invokeID		[3] Unsigned (0..255),
 *  abort-reason			[4] BACnetAbortReason
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fAbortPDU(tvbuff_t *tvb, proto_tree *tree, guint offset);

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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fObjectIdentifier (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * BACnet-Confirmed-Service-Request ::= CHOICE {
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @param service_choice
 * @return offset
 */
static guint
fConfirmedServiceRequest (tvbuff_t *tvb, proto_tree *tree, guint offset, gint service_choice);

/**
 * BACnet-Confirmed-Service-ACK ::= CHOICE {
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @param service_choice
 * @return offset
 */
static guint
fConfirmedServiceAck (tvbuff_t *tvb, proto_tree *tree, guint offset, gint service_choice);

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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fAcknowledgeAlarmRequest (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * ConfirmedCOVNotification-Request ::= SEQUENCE {
 * 	subscriberProcessIdentifier	[0]	Unsigned32,
 * 	initiatingDeviceIdentifier	[1] BACnetObjectIdentifer,
 * 	monitoredObjectIdentifier	[2] BACnetObjectIdentifer,
 * 	timeRemaining	[3] unsigned,
 * 	listOfValues	[4] SEQUENCE OF BACnetPropertyValues
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fConfirmedCOVNotificationRequest (tvbuff_t *tvb, proto_tree *tree, guint offset);

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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fConfirmedEventNotificationRequest (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * GetAlarmSummary-ACK ::= SEQUENCE OF SEQUENCE {
 * 	objectIdentifier	BACnetObjectIdentifer,
 * 	alarmState	BACnetEventState,
 * 	acknowledgedTransitions	 BACnetEventTransitionBits
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fGetAlarmSummaryAck (tvbuff_t *tvb, proto_tree *tree, guint offset);

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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fGetEnrollmentSummaryRequest (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * GetEnrollmentSummary-ACK ::= SEQUENCE OF SEQUENCE {
 * 	objectIdentifier	BACnetObjectIdentifer,
 * 	eventType	BACnetEventType,
 * 	eventState	BACnetEventState,
 * 	priority    Unsigned8,
 *  notificationClass   Unsigned OPTIONAL
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fGetEnrollmentSummaryAck (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * GetEventInformation-Request ::= SEQUENCE {
 * 	lastReceivedObjectIdentifier	[0] BACnetObjectIdentifer
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fGetEventInformationRequest (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * GetEventInformation-ACK ::= SEQUENCE {
 * 	listOfEventSummaries	[0] listOfEventSummaries,
 *  moreEvents  [1] BOOLEAN
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fGetEventInformationACK (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * LifeSafetyOperation-Request ::= SEQUENCE {
 * 	requestingProcessIdentifier	[0]	Unsigned32
 * 	requestingSource	[1] CharacterString
 * 	request	[2] BACnetLifeSafetyOperation
 * 	objectIdentifier	[3] BACnetObjectIdentifier OPTIONAL
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fLifeSafetyOperationRequest(tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label);

/**
 * SubscribeCOV-Request ::= SEQUENCE {
 * 	subscriberProcessIdentifier	[0]	Unsigned32
 * 	monitoredObjectIdentifier	[1] BACnetObjectIdentifier
 * 	issueConfirmedNotifications	[2] BOOLEAN OPTIONAL
 * 	lifetime	[3] Unsigned OPTIONAL
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @param label
 * @param src
 * @return modified offset
 */
static guint
fSubscribeCOVRequest(tvbuff_t *tvb, proto_tree *tree, guint offset);

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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fSubscribeCOVPropertyRequest(tvbuff_t *tvb, proto_tree *tree, guint offset);

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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fAtomicReadFileRequest(tvbuff_t *tvb, proto_tree *tree, guint offset);

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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fAtomicReadFileAck (tvbuff_t *tvb, proto_tree *tree, guint offset);

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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fAtomicWriteFileRequest(tvbuff_t *tvb, proto_tree *tree, guint offset);

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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fAddListElementRequest(tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * CreateObject-Request ::= SEQUENCE {
 * 	objectSpecifier	[0] ObjectSpecifier,
 *  listOfInitialValues	[1] SEQUENCE OF BACnetPropertyValue OPTIONAL
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fCreateObjectRequest(tvbuff_t *tvb, proto_tree *subtree, guint offset);

/**
 * CreateObject-Request ::= BACnetObjectIdentifier
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fCreateObjectAck (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * DeleteObject-Request ::= SEQUENCE {
 * 	ObjectIdentifier	BACnetObjectIdentifer
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fDeleteObjectRequest(tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * ReadProperty-Request ::= SEQUENCE {
 * 	objectIdentifier	[0]	BACnetObjectIdentifier,
 * 	propertyIdentifier	[1] BACnetPropertyIdentifier,
 * 	propertyArrayIndex	[2] Unsigned OPTIONAL, -- used only with array datatype
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fReadPropertyRequest(tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * ReadProperty-ACK ::= SEQUENCE {
 * 	objectIdentifier	[0]	BACnetObjectIdentifier,
 * 	propertyIdentifier	[1] BACnetPropertyIdentifier,
 * 	propertyArrayIndex	[2] Unsigned OPTIONAL, -- used only with array datatype
 * 	propertyValue	[3] ABSTRACT-SYNTAX.&Type
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fReadPropertyAck (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * ReadPropertyConditional-Request ::= SEQUENCE {
 * 	objectSelectionCriteria	[0] objectSelectionCriteria,
 * 	listOfPropertyReferences	[1] SEQUENCE OF BACnetPropertyReference OPTIONAL
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fReadPropertyConditionalRequest(tvbuff_t *tvb, proto_tree *subtree, guint offset);

/**
 * ReadPropertyConditional-ACK ::= SEQUENCE {
 * 	listOfPReadAccessResults	SEQUENCE OF ReadAccessResult OPTIONAL
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fReadPropertyConditionalAck (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * ReadPropertyMultiple-Request ::= SEQUENCE {
 *  listOfReadAccessSpecs	SEQUENCE OF ReadAccessSpecification
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return offset modified
 */
static guint
fReadPropertyMultipleRequest(tvbuff_t *tvb, proto_tree *subtree, guint offset);

/**
 * ReadPropertyMultiple-Ack ::= SEQUENCE {
 *  listOfReadAccessResults	SEQUENCE OF ReadAccessResult
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return offset modified
 */
static guint
fReadPropertyMultipleAck (tvbuff_t *tvb, proto_tree *tree, guint offset);

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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fReadRangeRequest (tvbuff_t *tvb, proto_tree *tree, guint offset);

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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fReadRangeAck (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * RemoveListElement-Request ::= SEQUENCE {
 * 	objectIdentifier	[0]	BACnetObjectIdentifier,
 * 	propertyIdentifier	[1] BACnetPropertyIdentifier,
 * 	propertyArrayIndex	[2] Unsigned OPTIONAL, -- used only with array datatype
 * 	listOfElements	[3] ABSTRACT-SYNTAX.&Type
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fRemoveListElementRequest(tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * WriteProperty-Request ::= SEQUENCE {
 * 	objectIdentifier	[0]	BACnetObjectIdentifier,
 * 	propertyIdentifier	[1] BACnetPropertyIdentifier,
 * 	propertyArrayIndex	[2] Unsigned OPTIONAL, -- used only with array datatype
 * 	propertyValue	[3] ABSTRACT-SYNTAX.&Type
 *  priority	[4] Unsigned8 (1..16) OPTIONAL --used only when property is commandable
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fWritePropertyRequest(tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * WritePropertyMultiple-Request ::= SEQUENCE {
 * 	listOfWriteAccessSpecifications	SEQUENCE OF WriteAccessSpecification
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fWritePropertyMultipleRequest(tvbuff_t *tvb, proto_tree *tree, guint offset);

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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fConfirmedPrivateTransferRequest(tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * ConfirmedPrivateTransfer-ACK ::= SEQUENCE {
 * 	vendorID	[0]	Unsigned,
 * 	serviceNumber	[1] Unsigned,
 * 	resultBlock	[2] ABSTRACT-SYNTAX.&Type OPTIONAL
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fConfirmedPrivateTransferAck(tvbuff_t *tvb, proto_tree *tree, guint offset);

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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fConfirmedTextMessageRequest(tvbuff_t *tvb, proto_tree *tree, guint offset);

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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fVtOpenRequest(tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * VTOpen-ACK ::= SEQUENCE {
 *  remoteVTSessionIdentifier	Unsigned8
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fVtOpenAck (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * VTClose-Request ::= SEQUENCE {
 *  listOfRemoteVTSessionIdentifiers	SEQUENCE OF Unsigned8
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fVtCloseRequest (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * VTData-Request ::= SEQUENCE {
 *  vtSessionIdentifier	Unsigned8,
 *  vtNewData	OCTET STRING,
 *  vtDataFlag	Unsigned (0..1)
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fVtDataRequest (tvbuff_t *tvb, proto_tree *tree, guint offset);

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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fAuthenticateAck (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * RequestKey-Request ::= SEQUENCE {
 *  requestingDeviceIdentifier	BACnetObjectIdentifier,
 *  requestingDeviceAddress	BACnetAddress,
 *  remoteDeviceIdentifier	BACnetObjectIdentifier,
 *  remoteDeviceAddress	BACnetAddress
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fRequestKeyRequest (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * Unconfirmed-Service-Request ::= CHOICE {
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @param service_choice
 * @return modified offset
 */
static guint
fUnconfirmedServiceRequest (tvbuff_t *tvb, proto_tree *tree, guint offset, gint service_choice);

/**
 * UnconfirmedCOVNotification-Request ::= SEQUENCE {
 * 	subscriberProcessIdentifier	[0]	Unsigned32,
 * 	initiatingDeviceIdentifier	[1] BACnetObjectIdentifer,
 * 	monitoredObjectIdentifier	[2] BACnetObjectIdentifer,
 * 	timeRemaining	[3] unsigned,
 * 	listOfValues	[4] SEQUENCE OF BACnetPropertyValues
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fUnconfirmedCOVNotificationRequest (tvbuff_t *tvb, proto_tree *tree, guint offset);

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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fUnconfirmedEventNotificationRequest (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * I-Am-Request ::= SEQUENCE {
 * 	aAmDeviceIdentifier	BACnetObjectIdentifier,
 *  maxAPDULengthAccepted	Unsigned,
 * 	segmentationSupported	BACnetSegmentation,
 * 	vendorID	Unsigned
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fIAmRequest  (tvbuff_t *tvb, proto_tree *tree, guint offset);


/**
 * I-Have-Request ::= SEQUENCE {
 * 	deviceIdentifier	BACnetObjectIdentifier,
 *  objectIdentifier	BACnetObjectIdentifier,
 * 	objectName	CharacterString
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fIHaveRequest  (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * UnconfirmedPrivateTransfer-Request ::= SEQUENCE {
 * 	vendorID	[0]	Unsigned,
 * 	serviceNumber	[1] Unsigned,
 * 	serviceParameters	[2] ABSTRACT-SYNTAX.&Type OPTIONAL
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fUnconfirmedPrivateTransferRequest(tvbuff_t *tvb, proto_tree *tree, guint offset);

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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fUnconfirmedTextMessageRequest(tvbuff_t *tvb, proto_tree *tree, guint offset);

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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fWhoHas (tvbuff_t *tvb, proto_tree *tree, guint offset);

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
fWhoIsRequest  (tvbuff_t *tvb, proto_tree *tree, guint offset);

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
 * @param tree
 * @param offset
 * @param service
 * @return modified offset
 */
static guint
fBACnetError(tvbuff_t *tvb, proto_tree *tree, guint offset, guint service);

/**
 * Dissect a BACnetError in a context tag
 *
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint fContextTaggedError(tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * ChangeList-Error ::= SEQUENCE {
 *    errorType     [0] Error,
 *    firstFailedElementNumber  [1] Unsigned
 *    }
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fChangeListError(tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * CreateObject-Error ::= SEQUENCE {
 *    errorType     [0] Error,
 *    firstFailedElementNumber  [1] Unsigned
 *    }
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fCreateObjectError(tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * ConfirmedPrivateTransfer-Error ::= SEQUENCE {
 *    errorType     [0] Error,
 *    vendorID      [1] Unsigned,
 *    serviceNumber [2] Unsigned,
 *    errorParameters   [3] ABSTRACT-SYNTAX.&Type OPTIONAL
 *    }
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fConfirmedPrivateTransferError(tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * WritePropertyMultiple-Error ::= SEQUENCE {
 *    errorType     [0] Error,
 *    firstFailedWriteAttempt  [1] Unsigned
 *    }
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fWritePropertyMultipleError(tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * VTClose-Error ::= SEQUENCE {
 *    errorType     [0] Error,
 *    listOfVTSessionIdentifiers  [1] SEQUENCE OF Unsigned8 OPTIONAL
 *    }
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fVTCloseError(tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * BACnet Application Types chapter 20.2.1
 * @param tvb
 * @param tree
 * @param offset
 * @param label
 * @return modified offset
 */
static guint
fApplicationTypes   (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label);

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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fActionCommand (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * BACnetActionList ::= SEQUENCE {
 *  action  [0] SEQUENCE of BACnetActionCommand
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fActionList (tvbuff_t *tvb, proto_tree *tree, guint offset);

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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fAddressBinding (tvbuff_t *tvb, proto_tree *tree, guint offset);

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

#if 0
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
fClientCOV (tvbuff_t *tvb, proto_tree *tree, guint offset);
#endif

/**
 * BACnetDailySchedule ::= SEQUENCE {
 *  day-schedule    [0] SENQUENCE OF BACnetTimeValue
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fDailySchedule (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * BACnetWeeklySchedule ::= SEQUENCE {
 *  week-schedule    SENQUENCE SIZE (7) OF BACnetDailySchedule
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fWeeklySchedule (tvbuff_t *tvb, proto_tree *tree, guint offset);

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

#if 0
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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fDestination (tvbuff_t *tvb, proto_tree *tree, guint offset);
#endif

#if 0
/**
 * BACnetDeviceObjectPropertyReference ::= SEQUENCE {
 *  objectIdentifier    [0] BACnetObjectIdentifier,
 *  propertyIdentifier  [1] BACnetPropertyIdentifier,
 *  propertyArrayIndex  [2] Unsigend OPTIONAL,
 *  deviceIdentifier    [3] BACnetObjectIdentifier OPTIONAL
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fDeviceObjectPropertyReference (tvbuff_t *tvb, proto_tree *tree, guint offset);
#endif

/**
 * BACnetDeviceObjectReference ::= SEQUENCE {
 *  deviceIdentifier    [0] BACnetObjectIdentifier OPTIONAL,
 *  objectIdentifier    [1] BACnetObjectIdentifier
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fDeviceObjectReference (tvbuff_t *tvb, proto_tree *tree, guint offset);

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


#if 0
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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fLogRecord (tvbuff_t *tvb, proto_tree *tree, guint offset);
#endif

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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fNotificationParameters (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * BACnetObjectPropertyReference ::= SEQUENCE {
 * 	objectIdentifier	[0] BACnetObjectIdentifier,
 * 	propertyIdentifier	[1] BACnetPropertyIdentifier,
 * 	propertyArrayIndex	[2] Unsigned OPTIONAL, -- used only with array datatype
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fBACnetObjectPropertyReference (tvbuff_t *tvb, proto_tree *tree, guint offset);

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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fPriorityArray (tvbuff_t *tvb, proto_tree *tree, guint offset);

static guint
fPropertyReference (tvbuff_t *tvb, proto_tree *tree, guint offset, guint8 tagoffset, guint8 list);

/**
 * BACnetPropertyReference ::= SEQUENCE {
 * 	propertyIdentifier	[0] BACnetPropertyIdentifier,
 * 	propertyArrayIndex	[1] Unsigned OPTIONAL, -- used only with array datatype
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fBACnetPropertyReference (tvbuff_t *tvb, proto_tree *tree, guint offset, guint8 list);

static guint
fBACnetObjectPropertyReference (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * BACnetPropertyValue ::= SEQUENCE {
 * 		PropertyIdentifier [0] BACnetPropertyIdentifier,
 * 		propertyArrayIndex [1] Unsigned OPTIONAL, -- used only with array datatypes
 * 				-- if omitted with an array the entire array is referenced
 * 		value [2] ABSTRACT-SYNTAX.&Type, -- any datatype appropriate for the specified property
 * 		priority [3] Unsigned (1..16) OPTIONAL -- used only when property is commandable
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fBACnetPropertyValue (tvbuff_t *tvb, proto_tree *tree, guint offset);

static guint
fPropertyValue (tvbuff_t *tvb, proto_tree *tree, guint offset, guint8 tagoffset);

/**
 * BACnet Application PDUs chapter 21
 * BACnetRecipient::= CHOICE {
 * 	device	[0] BACnetObjectIdentifier
 * 	address	[1] BACnetAddress
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fRecipient (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * BACnet Application PDUs chapter 21
 * BACnetRecipientProcess::= SEQUENCE {
 * 	recipient	[0] BACnetRecipient
 * 	processID	[1] Unsigned32
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fRecipientProcess (tvbuff_t *tvb, proto_tree *tree, guint offset);

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

#if 0
/**
 * BACnetSetpointReference ::= SEQUENCE {
 * 	sessionKey	[0] BACnetObjectPropertyReference OPTIONAL
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fSetpointReference (tvbuff_t *tvb, proto_tree *tree, guint offset);
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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fSpecialEvent (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * BACnetTimeStamp ::= CHOICE {
 * 	time			[0] Time,
 * 	sequenceNumber	[1] Unsigned (0..65535),
 * 	dateTime		[2] BACnetDateTime
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fTimeStamp (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * BACnetTimeValue ::= SEQUENCE {
 * 	time	Time,
 * 	value	ABSTRACT-SYNTAX.&Type -- any primitive datatype, complex types cannot be decoded
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fTimeValue (tvbuff_t *tvb, proto_tree *tree, guint offset);

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
 * -- X’FF’ = any week of this month
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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fReadAccessResult (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * ReadAccessSpecification ::= SEQUENCE {
 * 	objectIdentifier	[0] BACnetObjectIdentifier,
 * 	listOfPropertyReferences	[1] SEQUENCE OF BACnetPropertyReference
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fReadAccessSpecification (tvbuff_t *tvb, proto_tree *subtree, guint offset);

/**
 * WriteAccessSpecification ::= SEQUENCE {
 * 	objectIdentifier	[0] BACnetObjectIdentifier,
 * 	listOfProperty	[1] SEQUENCE OF BACnetPropertyValue
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fWriteAccessSpecification (tvbuff_t *tvb, proto_tree *subtree, guint offset);


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
 * @param tree
 * @param offset
 * @param tt returnvalue of this item
 * @return modified offset
 */
static guint
fPropertyIdentifier (tvbuff_t *tvb, proto_tree *tree, guint offset);

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
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
flistOfEventSummaries (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * SelectionCriteria ::= SEQUENCE {
 * 	propertyIdentifier	[0] BACnetPropertyIdentifier,
 * 	propertyArrayIndex	[1] Unsigned OPTIONAL, -- used only with array datatype
 *  relationSpecifier	[2] ENUMERATED { bacapp_relationSpecifier },
 *  comparisonValue	[3] ABSTRACT-SYNTAX.&Type
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fSelectionCriteria (tvbuff_t *tvb, proto_tree *tree, guint offset);

/**
 * objectSelectionCriteria ::= SEQUENCE {
 * 	selectionLogic	[0] ENUMERATED { bacapp_selectionLogic },
 * 	listOfSelectionCriteria	[1] SelectionCriteria
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fObjectSelectionCriteria (tvbuff_t *tvb, proto_tree *subtree, guint offset);

/**
 * BACnet-Error ::= SEQUENCE {
 *    error-class ENUMERATED {},
 *    error-code  ENUMERATED {}
 *    }
 * }
 * @param tvb
 * @param tree
 * @param offset
 * @return modified offset
 */
static guint
fError(tvbuff_t *tvb, proto_tree *tree, guint offset);

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
 * @param tree
 * @param offset
 * @return modified offset
 * @todo beautify this ugly construct
 */
static guint
fAbstractSyntaxNType (tvbuff_t *tvb, proto_tree *tree, guint offset);

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
 * converts XXX coded strings to UTF-8 if iconv is allowed
 * else 'in' is copied to 'out'
 * @param in  -- pointer to string
 * @param inbytesleft
 * @param out -- pointer to string
 * @param outbytesleft
 * @param fromcoding
 * @return count of modified characters of returned string, -1 for errors
 */
guint32
fConvertXXXtoUTF8(const guint8 *in, size_t *inbytesleft,guint8 *out, size_t *outbytesleft, const gchar *fromcoding);

#endif /* __BACAPP_H__ */


