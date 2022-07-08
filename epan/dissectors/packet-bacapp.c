/* packet-bacapp.c
 * Routines for BACnet (APDU) dissection
 * Copyright 2001, Hartmut Mueller <hartmut[AT]abmlinux.org>, FH Dortmund
 * Enhanced by Steve Karg, 2005, <skarg[AT]users.sourceforge.net>, Atlanta
 * Enhanced by Herbert Lischka, 2005, <lischka[AT]kieback-peter.de>, Berlin
 * Enhanced by Felix Kraemer, 2010, <sauter-cumulus[AT]de.sauter-bc.com>,
 *  Sauter-Cumulus GmbH, Freiburg
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald[AT]wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/strutil.h>
#include <epan/reassemble.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/stats_tree.h>
#include "packet-bacapp.h"

static int bacapp_tap = -1;

/* formerly bacapp.h  contains definitions and forward declarations */

/* BACnet PDU Types */
#define BACAPP_TYPE_CONFIRMED_SERVICE_REQUEST                   0
#define BACAPP_TYPE_UNCONFIRMED_SERVICE_REQUEST                 1
#define BACAPP_TYPE_SIMPLE_ACK                                  2
#define BACAPP_TYPE_COMPLEX_ACK                                 3
#define BACAPP_TYPE_SEGMENT_ACK                                 4
#define BACAPP_TYPE_ERROR                                       5
#define BACAPP_TYPE_REJECT                                      6
#define BACAPP_TYPE_ABORT                                       7
#define MAX_BACAPP_TYPE                                         8

#define BACAPP_SEGMENTED_REQUEST 0x08
#define BACAPP_MORE_SEGMENTS 0x04
#define BACAPP_SEGMENTED_RESPONSE 0x02
#define BACAPP_SEGMENT_NAK 0x02
#define BACAPP_SENT_BY 0x01

#define BACAPP_MAX_RECURSION_DEPTH 100 // Arbitrary

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
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 **/

/**
 * ConfirmedRequest-PDU ::= SEQUENCE {
 *  pdu-type                    [0] Unsigned (0..15), -- 0 for this PDU Type
 *  segmentedMessage            [1] BOOLEAN,
 *  moreFollows                 [2] BOOLEAN,
 *  segmented-response-accepted [3] BOOLEAN,
 *  reserved                    [4] Unsigned (0..3), -- must be set zero
 *  max-segments-accepted       [5] Unsigned (0..7), -- as per 20.1.2.4
 *  max-APDU-length-accepted    [5] Unsigned (0..15), -- as per 20.1.2.5
 *  invokeID                    [6] Unsigned (0..255),
 *  sequence-number             [7] Unsigned (0..255) OPTIONAL, -- only if segmented msg
 *  proposed-window-size        [8] Unsigned (0..127) OPTIONAL, -- only if segmented msg
 *  service-choice              [9] BACnetConfirmedServiceChoice,
 *  service-request             [10] BACnet-Confirmed-Service-Request OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fConfirmedRequestPDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
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
 *  pdu-type        [0] Unsigned (0..15), -- 1 for this PDU type
 *  reserved        [1] Unsigned (0..15), -- must be set zero
 *  service-choice  [2] BACnetUnconfirmedServiceChoice,
 *  service-request [3] BACnetUnconfirmedServiceRequest -- Context-specific tags 0..3 are NOT used in header encoding
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fUnconfirmedRequestPDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * SimpleACK-PDU ::= SEQUENCE {
 *  pdu-type            [0] Unsigned (0..15), -- 2 for this PDU type
 *  reserved            [1] Unsigned (0..15), -- must be set zero
 *  invokeID            [2] Unsigned (0..255),
 *  service-ACK-choice  [3] BACnetUnconfirmedServiceChoice -- Context-specific tags 0..3 are NOT used in header encoding
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fSimpleAckPDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ComplexACK-PDU ::= SEQUENCE {
 *  pdu-type                [0] Unsigned (0..15), -- 3 for this PDU Type
 *  segmentedMessage        [1] BOOLEAN,
 *  moreFollows             [2] BOOLEAN,
 *  reserved                [3] Unsigned (0..3), -- must be set zero
 *  invokeID                [4] Unsigned (0..255),
 *  sequence-number         [5] Unsigned (0..255) OPTIONAL, -- only if segmented msg
 *  proposed-window-size    [6] Unsigned (0..127) OPTIONAL, -- only if segmented msg
 *  service-ACK-choice      [7] BACnetConfirmedServiceChoice,
 *  service-ACK             [8] BACnet-Confirmed-Service-Request  -- Context-specific tags 0..8 are NOT used in header encoding
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fComplexAckPDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * SegmentACK-PDU ::= SEQUENCE {
 *  pdu-type                [0] Unsigned (0..15), -- 4 for this PDU Type
 *  reserved                [1] Unsigned (0..3), -- must be set zero
 *  negative-ACK            [2] BOOLEAN,
 *  server                  [3] BOOLEAN,
 *  original-invokeID       [4] Unsigned (0..255),
 *  sequence-number         [5] Unsigned (0..255),
 *  actual-window-size      [6] Unsigned (0..127)
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fSegmentAckPDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * Error-PDU ::= SEQUENCE {
 *  pdu-type                [0] Unsigned (0..15), -- 5 for this PDU Type
 *  reserved                [1] Unsigned (0..3), -- must be set zero
 *  original-invokeID       [2] Unsigned (0..255),
 *  error-choice            [3] BACnetConfirmedServiceChoice,
 *  error                   [4] BACnet-Error
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fErrorPDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * Reject-PDU ::= SEQUENCE {
 *  pdu-type                [0] Unsigned (0..15), -- 6 for this PDU Type
 *  reserved                [1] Unsigned (0..3), -- must be set zero
 *  original-invokeID       [2] Unsigned (0..255),
 *  reject-reason           [3] BACnetRejectReason
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fRejectPDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * Abort-PDU ::= SEQUENCE {
 *  pdu-type                [0] Unsigned (0..15), -- 7 for this PDU Type
 *  reserved                [1] Unsigned (0..3), -- must be set zero
 *  server                  [2] BOOLEAN,
 *  original-invokeID       [3] Unsigned (0..255),
 *  abort-reason            [4] BACnetAbortReason
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fAbortPDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * 20.2.4, adds the label with max 64Bit unsigned Integer Value to tree
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @param label the label of this item
 * @return modified offset
 */
static guint
fUnsignedTag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label);

/**
 * 20.2.5, adds the label with max 64Bit signed Integer Value to tree
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @param label the label of this item
 * @return modified offset
 */
static guint
fSignedTag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label);

/**
 * 20.2.8, adds the label with Octet String to tree; if lvt == 0 then lvt = restOfFrame
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @param label the label of this item
 * @param lvt length of String
 * @return modified offset
 */
static guint
fOctetString(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label, guint32 lvt);

/**
 * 20.2.12, adds the label with Date Value to tree
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @param label the label of this item
 * @return modified offset
 */
static guint
fDate(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label);

/**
 * 20.2.13, adds the label with Time Value to tree
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @param label the label of this item
 * @return modified offset
 */
static guint
fTime(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label);

/**
 * 20.2.14, adds Object Identifier to tree
 * use BIG ENDIAN: Bits 31..22 Object Type, Bits 21..0 Instance Number
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @param label the label of this item
 * @return modified offset
 */
static guint
fObjectIdentifier(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label);

/**
 * BACnet-Confirmed-Service-Request ::= CHOICE {
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @param service_choice the service choice
 * @return offset
 */
static guint
fConfirmedServiceRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, gint service_choice);

/**
 * BACnet-Confirmed-Service-ACK ::= CHOICE {
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @param service_choice the service choice
 * @return offset
 */
static guint
fConfirmedServiceAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, gint service_choice);

/**
 * AcknowledgeAlarm-Request ::= SEQUENCE {
 *  acknowledgingProcessIdentifier [0] Unsigned32,
 *  eventObjectIdentifier          [1] BACnetObjectIdentifer,
 *  eventStateAcknowledge          [2] BACnetEventState,
 *  timeStamp                      [3] BACnetTimeStamp,
 *  acknowledgementSource          [4] Character String,
 *  timeOfAcknowledgement          [5] BACnetTimeStamp
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fAcknowledgeAlarmRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ConfirmedCOVNotification-Request ::= SEQUENCE {
 *  subscriberProcessIdentifier [0] Unsigned32,
 *  initiatingDeviceIdentifier  [1] BACnetObjectIdentifer,
 *  monitoredObjectIdentifier   [2] BACnetObjectIdentifer,
 *  timeRemaining               [3] unsigned,
 *  listOfValues                [4] SEQUENCE OF BACnetPropertyValues
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fConfirmedCOVNotificationRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ConfirmedEventNotification-Request ::= SEQUENCE {
 *  ProcessIdentifier           [0] Unsigned32,
 *  initiatingDeviceIdentifier  [1] BACnetObjectIdentifer,
 *  eventObjectIdentifier       [2] BACnetObjectIdentifer,
 *  timeStamp                   [3] BACnetTimeStamp,
 *  notificationClass           [4] unsigned,
 *  priority                    [5] unsigned8,
 *  eventType                   [6] BACnetEventType,
 *  messageText                 [7] CharacterString OPTIONAL,
 *  notifyType                  [8] BACnetNotifyType,
 *  ackRequired                 [9] BOOLEAN OPTIONAL,
 *  fromState                  [10] BACnetEventState OPTIONAL,
 *  toState                    [11] BACnetEventState,
 *  eventValues                [12] BACnetNotificationParameters OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fConfirmedEventNotificationRequest(tvbuff_t *tvb, packet_info *pinfo,  proto_tree *tree, guint offset);

/**
 * GetAlarmSummary-ACK ::= SEQUENCE OF SEQUENCE {
 *  objectIdentifier         BACnetObjectIdentifer,
 *  alarmState               BACnetEventState,
 *  acknowledgedTransitions  BACnetEventTransitionBits
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fGetAlarmSummaryAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * GetEnrollmentSummary-Request ::= SEQUENCE {
 *  acknowledgmentFilter    [0] ENUMERATED {
 *      all       (0),
 *      acked     (1),
 *      not-acked (2)
 *      },
 *  enrollmentFilter        [1] BACnetRecipientProcess OPTIONAL,
 *  eventStateFilter        [2] ENUMERATED {
 *      offnormal (0),
 *      fault     (1),
 *      normal    (2),
 *      all       (3),
 *      active    (4)
 *      },
 *  eventTypeFilter         [3] BACnetEventType OPTIONAL,
 *  priorityFilter          [4] SEQUENCE {
 *      minPriority [0] Unsigned8,
 *      maxPriority [1] Unsigned8
 *      } OPTIONAL,
 *  notificationClassFilter [5] Unsigned OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fGetEnrollmentSummaryRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * GetEnrollmentSummary-ACK ::= SEQUENCE OF SEQUENCE {
 *  objectIdentifier    BACnetObjectIdentifer,
 *  eventType           BACnetEventType,
 *  eventState          BACnetEventState,
 *  priority            Unsigned8,
 *  notificationClass   Unsigned OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fGetEnrollmentSummaryAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * GetEventInformation-Request ::= SEQUENCE {
 *  lastReceivedObjectIdentifier    [0] BACnetObjectIdentifer
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fGetEventInformationRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * GetEventInformation-ACK ::= SEQUENCE {
 *  listOfEventSummaries [0] listOfEventSummaries,
 *  moreEvents           [1] BOOLEAN
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fGetEventInformationACK(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * LifeSafetyOperation-Request ::= SEQUENCE {
 *  requestingProcessIdentifier [0] Unsigned32
 *  requestingSource            [1] CharacterString
 *  request                     [2] BACnetLifeSafetyOperation
 *  objectIdentifier            [3] BACnetObjectIdentifier OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fLifeSafetyOperationRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label);

/**
 * SubscribeCOV-Request ::= SEQUENCE {
 *  subscriberProcessIdentifier [0] Unsigned32
 *  monitoredObjectIdentifier   [1] BACnetObjectIdentifier
 *  issueConfirmedNotifications [2] BOOLEAN OPTIONAL
 *  lifetime                    [3] Unsigned OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fSubscribeCOVRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * SubscribeCOVProperty-Request ::= SEQUENCE {
 *  subscriberProcessIdentifier [0] Unsigned32
 *  monitoredObjectIdentifier   [1] BACnetObjectIdentifier
 *  issueConfirmedNotifications [2] BOOLEAN OPTIONAL
 *  lifetime                    [3] Unsigned OPTIONAL
 *  monitoredPropertyIdentifier [4] BACnetPropertyReference OPTIONAL
 *  covIncrement                [5] Unsigned OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fSubscribeCOVPropertyRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * AtomicReadFile-Request ::= SEQUENCE {
 *  fileIdentifier  BACnetObjectIdentifier,
 *  accessMethod    CHOICE {
 *      streamAccess    [0] SEQUENCE {
 *          fileStartPosition   INTEGER,
 *          requestedOctetCount Unsigned
 *          },
 *      recordAccess    [1] SEQUENCE {
 *          fileStartRecord      INTEGER,
 *          requestedRecordCount Unsigned
 *          }
 *      }
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fAtomicReadFileRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * AtomicWriteFile-ACK ::= SEQUENCE {
 *  endOfFile   BOOLEAN,
 *  accessMethod    CHOICE {
 *      streamAccess    [0] SEQUENCE {
 *          fileStartPosition   INTEGER,
 *          fileData            OCTET STRING
 *          },
 *      recordAccess    [1] SEQUENCE {
 *          fileStartRecord     INTEGER,
 *          returnedRecordCount Unsigned,
 *          fileRecordData      SEQUENCE OF OCTET STRING
 *          }
 *      }
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fAtomicReadFileAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * AtomicWriteFile-Request ::= SEQUENCE {
 *  fileIdentifier  BACnetObjectIdentifier,
 *  accessMethod    CHOICE {
 *      streamAccess    [0] SEQUENCE {
 *          fileStartPosition  INTEGER,
 *          fileData           OCTET STRING
 *          },
 *      recordAccess    [1] SEQUENCE {
 *          fileStartRecord    INTEGER,
 *          recordCount        Unsigned,
 *          fileRecordData     SEQUENCE OF OCTET STRING
 *          }
 *      }
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fAtomicWriteFileRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * AtomicWriteFile-ACK ::= SEQUENCE {
 *      fileStartPosition [0] INTEGER,
 *      fileStartRecord   [1] INTEGER,
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fAtomicWriteFileAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * AddListElement-Request ::= SEQUENCE {
 *  objectIdentifier   [0] BACnetObjectIdentifier,
 *  propertyIdentifier [1] BACnetPropertyIdentifier,
 *  propertyArrayIndex [2] Unsigned OPTIONAL, -- used only with array datatype
 *  listOfElements     [3] ABSTRACT-SYNTAX.&Type
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fAddListElementRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * CreateObject-Request ::= SEQUENCE {
 *  objectSpecifier     [0] ObjectSpecifier,
 *  listOfInitialValues [1] SEQUENCE OF BACnetPropertyValue OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param subtree the sub tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fCreateObjectRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, guint offset);

/**
 * CreateObject-Request ::= BACnetObjectIdentifier
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fCreateObjectAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * DeleteObject-Request ::= SEQUENCE {
 *  ObjectIdentifier    BACnetObjectIdentifer
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fDeleteObjectRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ReadProperty-Request ::= SEQUENCE {
 *  objectIdentifier    [0] BACnetObjectIdentifier,
 *  propertyIdentifier  [1] BACnetPropertyIdentifier,
 *  propertyArrayIndex  [2] Unsigned OPTIONAL, -- used only with array datatype
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fReadPropertyRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ReadProperty-ACK ::= SEQUENCE {
 *  objectIdentifier   [0] BACnetObjectIdentifier,
 *  propertyIdentifier [1] BACnetPropertyIdentifier,
 *  propertyArrayIndex [2] Unsigned OPTIONAL, -- used only with array datatype
 *  propertyValue      [3] ABSTRACT-SYNTAX.&Type
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fReadPropertyAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ReadPropertyConditional-Request ::= SEQUENCE {
 *  objectSelectionCriteria  [0] objectSelectionCriteria,
 *  listOfPropertyReferences [1] SEQUENCE OF BACnetPropertyReference OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param subtree the  sub tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fReadPropertyConditionalRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, guint offset);

/**
 * ReadPropertyConditional-ACK ::= SEQUENCE {
 *  listOfPReadAccessResults    SEQUENCE OF ReadAccessResult OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fReadPropertyConditionalAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ReadPropertyMultiple-Request ::= SEQUENCE {
 *  listOfReadAccessSpecs   SEQUENCE OF ReadAccessSpecification
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param subtree the sub tree to append this item to
 * @param offset the offset in the tvb
 * @return offset modified
 */
static guint
fReadPropertyMultipleRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, guint offset);

/**
 * ReadPropertyMultiple-Ack ::= SEQUENCE {
 *  listOfReadAccessResults SEQUENCE OF ReadAccessResult
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return offset modified
 */
static guint
fReadPropertyMultipleAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ReadRange-Request ::= SEQUENCE {
 *  objectIdentifier    [0] BACnetObjectIdentifier,
 *  propertyIdentifier  [1] BACnetPropertyIdentifier,
 *  propertyArrayIndex  [2] Unsigned OPTIONAL, -- used only with array datatype
 *  range   CHOICE {
 *      byPosition  [3] SEQUENCE {
 *          referencedIndex Unsigned,
 *          count INTEGER
 *          },
 *      byTime      [4] SEQUENCE {
 *          referenceTime BACnetDateTime,
 *          count INTEGER
 *          },
 *      timeRange   [5] SEQUENCE {
 *          beginningTime BACnetDateTime,
 *          endingTime BACnetDateTime
 *          },
 *      } OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fReadRangeRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ReadRange-ACK ::= SEQUENCE {
 *  objectIdentifier   [0] BACnetObjectIdentifier,
 *  propertyIdentifier [1] BACnetPropertyIdentifier,
 *  propertyArrayIndex [2] Unsigned OPTIONAL, -- used only with array datatype
 *  resultFlags        [3] BACnetResultFlags,
 *  itemCount          [4] Unsigned,
 *  itemData           [5] SEQUENCE OF ABSTRACT-SYNTAX.&Type
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fReadRangeAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * RemoveListElement-Request ::= SEQUENCE {
 *  objectIdentifier    [0] BACnetObjectIdentifier,
 *  propertyIdentifier  [1] BACnetPropertyIdentifier,
 *  propertyArrayIndex  [2] Unsigned OPTIONAL, -- used only with array datatype
 *  listOfElements  [3] ABSTRACT-SYNTAX.&Type
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fRemoveListElementRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * WriteProperty-Request ::= SEQUENCE {
 *  objectIdentifier   [0] BACnetObjectIdentifier,
 *  propertyIdentifier [1] BACnetPropertyIdentifier,
 *  propertyArrayIndex [2] Unsigned OPTIONAL, -- used only with array datatype
 *  propertyValue      [3] ABSTRACT-SYNTAX.&Type
 *  priority           [4] Unsigned8 (1..16) OPTIONAL --used only when property is commandable
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fWritePropertyRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * WritePropertyMultiple-Request ::= SEQUENCE {
 *  listOfWriteAccessSpecifications SEQUENCE OF WriteAccessSpecification
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fWritePropertyMultipleRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * DeviceCommunicationControl-Request ::= SEQUENCE {
 *  timeDuration    [0] Unsigned16 OPTIONAL,
 *  enable-disable  [1] ENUMERATED {
 *      enable  (0),
 *      disable (1)
 *      },
 *  password        [2] CharacterString (SIZE(1..20)) OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fDeviceCommunicationControlRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ConfirmedPrivateTransfer-Request ::= SEQUENCE {
 *  vendorID          [0] Unsigned,
 *  serviceNumber     [1] Unsigned,
 *  serviceParameters [2] ABSTRACT-SYNTAX.&Type OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fConfirmedPrivateTransferRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ConfirmedPrivateTransfer-ACK ::= SEQUENCE {
 *  vendorID      [0] Unsigned,
 *  serviceNumber [1] Unsigned,
 *  resultBlock   [2] ABSTRACT-SYNTAX.&Type OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fConfirmedPrivateTransferAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ConfirmedTextMessage-Request ::=  SEQUENCE {
 *  textMessageSourceDevice [0] BACnetObjectIdentifier,
 *  messageClass            [1] CHOICE {
 *      numeric   [0] Unsigned,
 *      character [1] CharacterString
 *      } OPTIONAL,
 *  messagePriority         [2] ENUMERATED {
 *      normal (0),
 *      urgent (1)
 *      },
 *  message [3] CharacterString
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fConfirmedTextMessageRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ReinitializeDevice-Request ::= SEQUENCE {
 *  reinitializedStateOfDevice  [0] ENUMERATED {
 *      coldstart    (0),
 *      warmstart    (1),
 *      startbackup  (2),
 *      endbackup    (3),
 *      startrestore (4),
 *      endrestore   (5),
 *      abortrestor  (6)
 *      },
 *  password                    [1] CharacterString (SIZE(1..20)) OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fReinitializeDeviceRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * VTOpen-Request ::= SEQUENCE {
 *  vtClass BACnetVTClass,
 *  localVTSessionIdentifier    Unsigned8
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fVtOpenRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * VTOpen-ACK ::= SEQUENCE {
 *  remoteVTSessionIdentifier   Unsigned8
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fVtOpenAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * VTClose-Request ::= SEQUENCE {
 *  listOfRemoteVTSessionIdentifiers    SEQUENCE OF Unsigned8
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fVtCloseRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * VTData-Request ::= SEQUENCE {
 *  vtSessionIdentifier Unsigned8,
 *  vtNewData           OCTET STRING,
 *  vtDataFlag          Unsigned (0..1)
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fVtDataRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * VTData-ACK ::= SEQUENCE {
 *  allNewDataAccepted  [0] BOOLEAN,
 *  acceptedOctetCount  [1] Unsigned OPTIONAL -- present only if allNewDataAccepted = FALSE
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fVtDataAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * Authenticate-Request ::= SEQUENCE {
 *  pseudoRandomNumber     [0] Unsigned32,
 *  excpectedInvokeID      [1] Unsigned8 OPTIONAL,
 *  operatorName           [2] CharacterString OPTIONAL,
 *  operatorPassword       [3] CharacterString (SIZE(1..20)) OPTIONAL,
 *  startEncypheredSession [4] BOOLEAN OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fAuthenticateRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * Authenticate-ACK ::= SEQUENCE {
 *  modifiedRandomNumber    Unsigned32,
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fAuthenticateAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * RequestKey-Request ::= SEQUENCE {
 *  requestingDeviceIdentifier BACnetObjectIdentifier,
 *  requestingDeviceAddress    BACnetAddress,
 *  remoteDeviceIdentifier     BACnetObjectIdentifier,
 *  remoteDeviceAddress        BACnetAddress
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fRequestKeyRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * Unconfirmed-Service-Request ::= CHOICE {
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @param service_choice the service choice
 * @return modified offset
 */
static guint
fUnconfirmedServiceRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, gint service_choice);

/**
 * UnconfirmedCOVNotification-Request ::= SEQUENCE {
 *  subscriberProcessIdentifier [0] Unsigned32,
 *  initiatingDeviceIdentifier  [1] BACnetObjectIdentifer,
 *  monitoredObjectIdentifier   [2] BACnetObjectIdentifer,
 *  timeRemaining               [3] unsigned,
 *  listOfValues                [4] SEQUENCE OF BACnetPropertyValues
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fUnconfirmedCOVNotificationRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * UnconfirmedEventNotification-Request ::= SEQUENCE {
 *  ProcessIdentifier           [0] Unsigned32,
 *  initiatingDeviceIdentifier  [1] BACnetObjectIdentifer,
 *  eventObjectIdentifier       [2] BACnetObjectIdentifer,
 *  timeStamp                   [3] BACnetTimeStamp,
 *  notificationClass           [4] unsigned,
 *  priority                    [5] unsigned8,
 *  eventType                   [6] BACnetEventType,
 *  messageText                 [7] CharacterString OPTIONAL,
 *  notifyType                  [8] BACnetNotifyType,
 *  ackRequired                 [9] BOOLEAN OPTIONAL,
 *  fromState                  [10] BACnetEventState OPTIONAL,
 *  toState                    [11] BACnetEventState,
 *  eventValues                [12] BACnetNotificationParameters OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fUnconfirmedEventNotificationRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * I-Am-Request ::= SEQUENCE {
 *  aAmDeviceIdentifier BACnetObjectIdentifier,
 *  maxAPDULengthAccepted   Unsigned,
 *  segmentationSupported   BACnetSegmentation,
 *  vendorID    Unsigned
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fIAmRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);


/**
 * I-Have-Request ::= SEQUENCE {
 *  deviceIdentifier  BACnetObjectIdentifier,
 *  objectIdentifier  BACnetObjectIdentifier,
 *  objectName        CharacterString
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fIHaveRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * UnconfirmedPrivateTransfer-Request ::= SEQUENCE {
 *  vendorID          [0] Unsigned,
 *  serviceNumber     [1] Unsigned,
 *  serviceParameters [2] ABSTRACT-SYNTAX.&Type OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fUnconfirmedPrivateTransferRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * UnconfirmedTextMessage-Request ::=  SEQUENCE {
 *  textMessageSourceDevice [0] BACnetObjectIdentifier,
 *  messageClass            [1] CHOICE {
 *      numeric   [0] Unsigned,
 *      character [1] CharacterString
 *      } OPTIONAL,
 *  messagePriority         [2] ENUMERATED {
 *      normal (0),
 *      urgent (1)
 *      },
 *  message                 [3] CharacterString
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fUnconfirmedTextMessageRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * TimeSynchronization-Request ::=  SEQUENCE {
 *  BACnetDateTime
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fTimeSynchronizationRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * UTCTimeSynchronization-Request ::=  SEQUENCE {
 *  BACnetDateTime
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fUTCTimeSynchronizationRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * Who-Has-Request ::=  SEQUENCE {
 *  limits SEQUENCE {
 *      deviceInstanceRangeLowLimit  [0] Unsigned (0..4194303),
 *      deviceInstanceRangeHighLimit [1] Unsigned (0..4194303)
 *      } OPTIONAL,
 *  object CHOICE {
 *      objectIdentifier             [2] BACnetObjectIdentifier,
 *      objectName                   [3] CharacterString
 *      }
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fWhoHas(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * Who-Is-Request ::= SEQUENCE {
 *  deviceInstanceRangeLowLimit  [0] Unsigned (0..4194303) OPTIONAL, -- must be used as a pair, see 16.9,
 *  deviceInstanceRangeHighLimit [0] Unsigned (0..4194303) OPTIONAL, -- must be used as a pair, see 16.9,
 * }
 * @param tvb the tv buffer of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fWhoIsRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnet-Error ::= CHOICE {
 *  addListElement           [8] ChangeList-Error,
 *  removeListElement        [9] ChangeList-Error,
 *  writePropertyMultiple   [16] WritePropertyMultiple-Error,
 *  confirmedPrivatTransfer [18] ConfirmedPrivateTransfer-Error,
 *  vtClose                 [22] VTClose-Error,
 *  readRange               [26] ObjectAccessService-Error
 *                          [default] Error
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @param service the service
 * @return modified offset
 */
static guint
fBACnetError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint service);

/**
 * Dissect a BACnetError in a context tag
 *
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint fContextTaggedError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ChangeList-Error ::= SEQUENCE {
 *    errorType                [0] Error,
 *    firstFailedElementNumber [1] Unsigned
 *    }
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fChangeListError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * CreateObject-Error ::= SEQUENCE {
 *    errorType                [0] Error,
 *    firstFailedElementNumber [1] Unsigned
 *    }
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fCreateObjectError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ConfirmedPrivateTransfer-Error ::= SEQUENCE {
 *    errorType       [0] Error,
 *    vendorID        [1] Unsigned,
 *    serviceNumber   [2] Unsigned,
 *    errorParameters [3] ABSTRACT-SYNTAX.&Type OPTIONAL
 *    }
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fConfirmedPrivateTransferError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * WritePropertyMultiple-Error ::= SEQUENCE {
 *    errorType               [0] Error,
 *    firstFailedWriteAttempt [1] Unsigned
 *    }
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fWritePropertyMultipleError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * VTClose-Error ::= SEQUENCE {
 *    errorType                  [0] Error,
 *    listOfVTSessionIdentifiers [1] SEQUENCE OF Unsigned8 OPTIONAL
 *    }
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fVTCloseError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnet Application Types chapter 20.2.1
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @param label the label of this item
 * @return modified offset
 */
static guint
fApplicationTypes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label);

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
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @param tag_match the tag number
 * @return modified offset
 */
static guint
fActionCommand(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint8 tag_match);

/**
 * BACnetActionList ::= SEQUENCE {
 *  action  [0] SEQUENCE of BACnetActionCommand
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fActionList(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/** BACnetAddress ::= SEQUENCE {
 *  network-number  Unsigned16, -- A value 0 indicates the local network
 *  mac-address     OCTET STRING -- A string of length 0 indicates a broadcast
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fAddress(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetAddressBinding ::= SEQUENCE {
 *  deviceObjectID  BACnetObjectIdentifier
 *  deviceAddress   BacnetAddress
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fAddressBinding(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetCalendarEntry ::= CHOICE {
 *  date        [0] Date,
 *  dateRange   [1] BACnetDateRange,
 *  weekNDay    [2] BacnetWeekNday
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fCalendarEntry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetClientCOV ::= CHOICE {
 *  real-increment  REAL,
 *  default-increment   NULL
 * }
 * @param tvb the tv buffer of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fClientCOV(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);


/**
 * BACnetDailySchedule ::= SEQUENCE {
 *  day-schedule    [0] SENQUENCE OF BACnetTimeValue
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fDailySchedule(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetHealth ::= SEQUENCE {
 *  timestamp                   [0] BACnetDateTime,
 *  result                      [1] Error,
 *  property                    [2] BACnetPropertiyIdentifier OPTIONAL,
 *  details                     [3] CharacterString OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fHealth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetSCFailedConnectionRequest ::= SEQUENCE {
 *  timestamp                   [0] BACnetDateTime,
 *  peer-address                [1] BACnetHostNPort,
 *  peer-vmac                   [2] OCTET STRING (SIZE(6))
 *  peer-uuid                   [3] OCTET STRING (SIZE(16))
 *  error                       [4] Error OPTIONAL
 *  error-details               [5] CharacterString OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fSCFailedConnectionRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetSCDirectConnection ::= SEQUENCE {
 *  uri                         [0] CharacterString
 *  connection-state            [1] BACnetSCConnectionState,
 *  connect-timestamp           [2] BACnetDateTime,
 *  disconnect-timestamp        [3] BACnetDateTime,
 *  peer-address                [4] BACnetHostNPort,
 *  peer-vmac                   [5] OCTET STRING (SIZE(6))
 *  peer-uuid                   [6] OCTET STRING (SIZE(16))
 *  error                       [7] Error OPTIONAL
 *  error-details               [8] CharacterString OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fSCDirectConnection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetSCHubConnection ::= SEQUENCE {
 *  connection-state            [0] BACnetSCConnectionState,
 *  connect-timestamp           [1] BACnetDateTime,
 *  disconnect-timestamp        [2] BACnetDateTime,
 *  error                       [3] Error OPTIONAL
 *  error-details               [4] CharacterString OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fSCHubConnection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetSCHubFunctionConnection ::= SEQUENCE {
 *  connection-state            [0] BACnetSCConnectionState,
 *  connect-timestamp           [1] BACnetDateTime,
 *  disconnect-timestamp        [2] BACnetDateTime,
 *  peer-address                [3] BACnetHostNPort,
 *  peer-vmac                   [4] OCTET STRING (SIZE(6))
 *  peer-uuid                   [5] OCTET STRING (SIZE(16))
 *  error                       [6] Error OPTIONAL
 *  error-details               [7] CharacterString OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fSCHubFunctionConnection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetWeeklySchedule ::= SEQUENCE {
 *  week-schedule    SENQUENCE SIZE (7) OF BACnetDailySchedule
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fWeeklySchedule(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetDateRange ::= SEQUENCE {
 *  StartDate   Date,
 *  EndDate     Date
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fDateRange(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetDateTime ::= SEQUENCE {
 *  date   Date,
 *  time   Time
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @param label the label of this item
 * @return modified offset
 */
static guint
fDateTime(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label);

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
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fDestination(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetDeviceObjectPropertyReference ::= SEQUENCE {
 *  objectIdentifier    [0] BACnetObjectIdentifier,
 *  propertyIdentifier  [1] BACnetPropertyIdentifier,
 *  propertyArrayIndex  [2] Unsigend OPTIONAL,
 *  deviceIdentifier    [3] BACnetObjectIdentifier OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fDeviceObjectPropertyReference(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetObjectPropertyReference ::= SEQUENCE {
 *  objectIdentifier    [0] BACnetObjectIdentifier,
 *  propertyIdentifier  [1] BACnetPropertyIdentifier,
 *  propertyArrayIndex  [2] Unsigend OPTIONAL,
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fObjectPropertyReference(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetDeviceObjectReference ::= SEQUENCE {
 *  deviceIdentifier    [0] BACnetObjectIdentifier OPTIONAL,
 *  objectIdentifier    [1] BACnetObjectIdentifier
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fDeviceObjectReference(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetEventParameter ::= CHOICE {
 *  change-of-bitstring             [0] SEQUENCE {
 *      time-delay                       [0] Unsigned,
 *      bitmask                          [1] BIT STRING,
 *      list-of-bitstring-values         [2] SEQUENCE OF BIT STRING
 *      },
 *  change-of-state                 [1] SEQUENCE {
 *      time-delay     [0] Unsigned,
 *      list-of-values [1] SEQUENCE OF BACnetPropertyStates
 *      },
 *  change-of-value                 [2] SEQUENCE {
 *      time-delay   [0] Unsigned,
 *      cov-criteria [1] CHOICE {
 *          bitmask                       [0] BIT STRING,
 *          referenced-property-increment [1] REAL
 *          }
 *      },
 *  command-failure                 [3] SEQUENCE {
 *      time-delay                       [0] Unsigned,
 *      feedback-property-reference      [1] BACnetDeviceObjectPropertyReference
 *      },
 *  floating-limit                  [4] SEQUENCE {
 *      time-delay                       [0] Unsigned,
 *      setpoint-reference               [1] BACnetDeviceObjectPropertyReference,
 *      low-diff-limit                   [2] REAL,
 *      high-diff-limit                  [3] REAL,
 *      deadband                         [4] REAL
 *      },
 *  out-of-range                    [5] SEQUENCE {
 *      time-delay                       [0] Unsigned,
 *      low-limit                        [1] REAL,
 *      high-limit                       [2] REAL,
 *      deadband                         [3] REAL
 *      },
 *  -- context tag 7 is deprecated
 *  change-of-life-safety           [8] SEQUENCE {
 *      time-delay                       [0] Unsigned,
 *      list-of-life-safety-alarm-values [1] SEQUENCE OF BACnetLifeSafetyState,
 *      list-of-alarm-values             [2] SEQUENCE OF BACnetLifeSafetyState,
 *      mode-property-reference          [3] BACnetDeviceObjectPropertyReference
 *      },
 *  extended                        [9] SEQUENCE {
 *      vendor-id                        [0] Unsigned16,
 *      extended-event-type              [1] Unsigned,
 *      parameters                       [2] SEQUENCE OF CHOICE {
 *          null        NULL,
 *          real        REAL,
 *          integer     Unsigned,
 *          boolean     BOOLEAN,
 *          double      Double,
 *          octet       OCTET STRING,
 *          bitstring   BIT STRING,
 *          enum        ENUMERATED,
 *          reference   [0] BACnetDeviceObjectPropertyReference
 *          }
 *      },
 *  buffer-ready                    [10] SEQUENCE {
 *      notification-threshold           [0] Unsigned,
 *      previous-notification-count      [1] Unsigned32
 *      },
 * unsigned-range                   [11] SEQUENCE {
 *      time-delay                       [0] Unsigned,
 *      low-limit                        [1] Unsigned,
 *      high-limit                       [2] Unsigned,
 *      }
 * -- context tag 12 is reserved for future addenda
 * access-event                     [13] SEQUENCE {
 *      list-of-access-events            [0] SEQUENCE OF BACnetAccessEvent,
 *      access-event-time-reference      [1] BACnetDeviceObjectPropertyReference
 *      }
 * double-out-of-range              [14] SEQUENCE {
 *      time-delay                       [0] Unsigned,
 *      low-limit                        [1] Double,
 *      high-limit                       [2] Double,
 *      deadband                         [3] Double
 *  }
 *  signed-out-of-range             [15] SEQUENCE {
 *      time-delay                       [0] Unsigned,
 *      low-limit                        [1] INTEGER,
 *      high-limit                       [2] INTEGER,
 *      deadband                         [3] Unsigned
 *  }
 *  unsigned-out-of-range           [16] SEQUENCE {
 *      time-delay                       [0] Unsigned,
 *      low-limit                        [1] Unsigned,
 *      high-limit                       [2] Unsigned,
 *      deadband                         [3] Unsigned
 *   }
 *  change-of-characterstring       [17] SEQUENCE {
 *      time-delay                       [0] Unsigned,
 *      list-of-alarm-values             [1] SEQUENCE OF CharacterString,
 *   }
 *  change-of-status-flags          [18] SEQUENCE {
 *      time-delay                       [0] Unsigned,
 *      selected-flags                   [1] BACnetStatusFlags
 *   }
 * }
 * @param tvb the tv buffer of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fEventParameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);



/**
 * BACnetLogRecord ::= SEQUENCE {
 *  timestamp   [0] BACnetDateTime,
 *  logDatum    [1] CHOICE {
 *      log-status      [0] BACnetLogStatus,
 *      boolean-value   [1] BOOLEAN,
 *      real-value      [2] REAL,
 *      enum-value      [3] ENUMERATED, -- Optionally limited to 32 bits
 *      unsigned-value  [4] Unsigned, -- Optionally limited to 32 bits
 *      signed-value    [5] INTEGER, -- Optionally limited to 32 bits
 *      bitstring-value [6] BIT STRING, -- Optionally limited to 32 bits
 *      null-value      [7] NULL,
 *      failure         [8] Error,
 *      time-change     [9] REAL,
 *      any-value       [10] ABSTRACT-SYNTAX.&Type -- Optional
 *      }
 *  statusFlags [2] BACnetStatusFlags OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fLogRecord(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetEventLogRecord ::= SEQUENCE {
 *  timestamp [0] BACnetDateTime,
 *  logDatum  [1] CHOICE {
 *      log-status   [0] BACnetLogStatus,
 *      notification [1] ConfirmedEventNotification-Request,
 *      time-change  [2] REAL,
 *      }
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fEventLogRecord(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fLogMultipleRecord(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetNotificationParameters ::= CHOICE {
 *  change-of-bitstring [0] SEQUENCE {
 *      referenced-bitstring [0] BIT STRING,
 *      status-flags         [1] BACnetStatusFlags
 *      },
 *  change-of-state [1] SEQUENCE {
 *      new-state            [0] BACnetPropertyStatus,
 *      status-flags         [1] BACnetStatusFlags
 *      },
 *  change-of-value [2] SEQUENCE {
 *      new-value            [0] CHOICE {
 *          changed-bits        [0] BIT STRING,
 *          changed-value       [1] REAL
 *          },
 *      status-flags         [1] BACnetStatusFlags
 *      },
 *  command-failure [3] SEQUENCE {
 *      command-value        [0] ABSTRACT-SYNTAX.&Type, -- depends on ref property
 *      status-flags         [1] BACnetStatusFlags
 *      feedback-value       [2] ABSTRACT-SYNTAX.&Type -- depends on ref property
 *      },
 *  floating-limit [4]  SEQUENCE {
 *      reference-value      [0] REAL,
 *      status-flags         [1] BACnetStatusFlags
 *      setpoint-value       [2] REAL,
 *      error-limit          [3] REAL
 *      },
 *  out-of-range [5]    SEQUENCE {
 *      exceeding-value      [0] REAL,
 *      status-flags         [1] BACnetStatusFlags
 *      deadband             [2] REAL,
 *      exceeded-limit       [3] REAL
 *      },
 *  complex-event-type  [6] SEQUENCE OF BACnetPropertyValue,
 * -- complex tag 7 is deprecated
 *  change-of-life-safety [8]   SEQUENCE {
 *      new-state            [0] BACnetLifeSafetyState,
 *      new-mode             [1] BACnetLifeSafetyState
 *      status-flags         [2] BACnetStatusFlags,
 *      operation-expected   [3] BACnetLifeSafetyOperation
 *      },
 *  extended [9]   SEQUENCE {
 *      vendor-id            [0] Unsigned16,
 *      extended-event-type  [1] Unsigned,
 *      parameters           [2] SEQUENCE OF CHOICE {
 *          null                NULL,
 *          real                REAL,
 *          integer             Unsigned,
 *          boolean             BOOLEAN,
 *          double              Double,
 *          octet               OCTET STRING,
 *          bitstring           BIT STRING,
 *          enum                ENUMERATED,
 *          propertyValue       [0] BACnetDeviceObjectPropertyValue
 *          }
 *      },
 *  buffer-ready [10]    SEQUENCE {
 *      buffer-property      [0] BACnetDeviceObjectPropertyReference,
 *      previous-notification[1] Unsigned32,
 *      current-notification [2] BACneUnsigned32tDateTime
 *      },
 *  unsigned-range [11]    SEQUENCE {
 *      exceeding-value      [0] Unsigned,
 *      status-flags         [1] BACnetStatusFlags,
 *      exceeded-limit       [2] Unsigned
 *      },
 * -- context tag 12 is reserved for future addenda
 *  access-event [13]    SEQUENCE {
 *      access-event          [0] BACnetAccessEvent,
 *      status-flags          [1] BACnetStatusFlags,
 *      access-event-tag      [2] Unsigned,
 *      access-event-time     [3] BACnetTimeStamp,
 *      access-credential     [4] BACnetDeviceObjectReference,
 *      authentication-factor [5] BACnetAuthenticationFactor OPTIONAL
 *      },
 *  double-out-of-range [14]    SEQUENCE {
 *      exceeding-value      [0] Double,
 *      status-flags         [1] BACnetStatusFlags
 *      deadband             [2] Double,
 *      exceeded-limit       [3] Double
 *      },
 *  signed-out-of-range [15]    SEQUENCE {
 *      exceeding-value      [0] INTEGER,
 *      status-flags         [1] BACnetStatusFlags
 *      deadband             [2] Unsigned,
 *      exceeded-limit       [3] INTEGER
 *      },
 *  unsigned-out-of-range [16]    SEQUENCE {
 *      exceeding-value      [0] Unsigned,
 *      status-flags         [1] BACnetStatusFlags
 *      deadband             [2] Unsigned,
 *      exceeded-limit       [3] Unsigned
 *      },
 *  change-of-characterstring [17]    SEQUENCE {
 *      changed-value        [0] CharacterString,
 *      status-flags         [1] BACnetStatusFlags
 *      alarm-value          [2] CharacterString
 *      },
 *  change-of-status-flags [18]    SEQUENCE {
 *      present-value        [0] ABSTRACT-SYNTAX.&Type OPTIONAL,
 *                              -- depends on referenced property
 *      referenced-flags     [1] BACnetStatusFlags
 *      },
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fNotificationParameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetObjectPropertyReference ::= SEQUENCE {
 *  objectIdentifier    [0] BACnetObjectIdentifier,
 *  propertyIdentifier  [1] BACnetPropertyIdentifier,
 *  propertyArrayIndex  [2] Unsigned OPTIONAL, -- used only with array datatype
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fBACnetObjectPropertyReference(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

#if 0
/**
 * BACnetObjectPropertyValue ::= SEQUENCE {
 *      objectIdentifier   [0] BACnetObjectIdentifier,
 *      propertyIdentifier [1] BACnetPropertyIdentifier,
 *      propertyArrayIndex [2] Unsigned OPTIONAL, -- used only with array datatype
 *                                                -- if omitted with an array the entire array is referenced
 *      value              [3] ABSTRACT-SYNTAX.&Type, --any datatype appropriate for the specified property
 *      priority           [4] Unsigned (1..16) OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fObjectPropertyValue(tvbuff_t *tvb, proto_tree *tree, guint offset);
#endif

/**
 * BACnetPriorityArray ::= SEQUENCE SIZE (16) OF BACnetPriorityValue
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fPriorityArray(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fPropertyReference(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint8 tagoffset, guint8 list);

/**
 * BACnetPropertyReference ::= SEQUENCE {
 *  propertyIdentifier  [0] BACnetPropertyIdentifier,
 *  propertyArrayIndex  [1] Unsigned OPTIONAL, -- used only with array datatype
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fBACnetPropertyReference(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint8 list);

static guint
fLOPR(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fRestartReason(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetPropertyValue ::= SEQUENCE {
 *      PropertyIdentifier [0] BACnetPropertyIdentifier,
 *      propertyArrayIndex [1] Unsigned OPTIONAL, -- used only with array datatypes
 *                                                -- if omitted with an array the entire array is referenced
 *      value              [2] ABSTRACT-SYNTAX.&Type, -- any datatype appropriate for the specified property
 *      priority           [3] Unsigned (1..16) OPTIONAL -- used only when property is commandable
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fBACnetPropertyValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fPropertyValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint8 tagoffset);

/**
 * BACnet Application PDUs chapter 21
 * BACnetRecipient::= CHOICE {
 *  device  [0] BACnetObjectIdentifier
 *  address [1] BACnetAddress
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fRecipient(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnet Application PDUs chapter 21
 * BACnetRecipientProcess::= SEQUENCE {
 *  recipient   [0] BACnetRecipient
 *  processID   [1] Unsigned32
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fRecipientProcess(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fCOVSubscription(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

#if 0
/**
 * BACnetSessionKey ::= SEQUENCE {
 *  sessionKey  OCTET STRING (SIZE(8)), -- 56 bits for key, 8 bits for checksum
 *  peerAddress BACnetAddress
 * }
 * @param tvb the tv buffer of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 * @todo check if checksum is displayed correctly
 */
static guint
fSessionKey(tvbuff_t *tvb, proto_tree *tree, guint offset);
#endif

/**
 * BACnetSpecialEvent ::= SEQUENCE {
 *  period      CHOICE {
 *      calendarEntry       [0] BACnetCalendarEntry,
 *      calendarRefernce    [1] BACnetObjectIdentifier
 *      },
 *      listOfTimeValues    [2] SEQUENCE OF BACnetTimeValue,
 *      eventPriority       [3] Unsigned (1..16)
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fSpecialEvent(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetTimeStamp ::= CHOICE {
 *  time            [0] Time,
 *  sequenceNumber  [1] Unsigned (0..65535),
 *  dateTime        [2] BACnetDateTime
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @param label the label of this item
 * @return modified offset
 */
static guint
fTimeStamp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label);

static guint
fEventTimeStamps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnetTimeValue ::= SEQUENCE {
 *  time    Time,
 *  value   ABSTRACT-SYNTAX.&Type -- any primitive datatype, complex types cannot be decoded
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fTimeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

#if 0
/**
 * BACnetVTSession ::= SEQUENCE {
 *  local-vtSessionID   Unsigned8,
 *  remote-vtSessionID  Unsigned8,
 *  remote-vtAddress    BACnetAddress
 * }
 * @param tvb the tv buffer of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fVTSession(tvbuff_t *tvb, proto_tree *tree, guint offset);
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
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fWeekNDay(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ReadAccessResult ::= SEQUENCE {
 *  objectIdentifier            [0] BACnetObjectIdentifier,
 *  listOfResults               [1] SEQUENCE OF SEQUENCE {
 *      propertyIdentifier      [2] BACnetPropertyIdentifier,
 *      propertyArrayIndex      [3] Unsigned OPTIONAL, -- used only with array datatype if omitted with an array the entire array is referenced
 *      readResult  CHOICE {
 *          propertyValue       [4] ABSTRACT-SYNTAX.&Type,
 *          propertyAccessError [5] Error
 *      }
 *  } OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fReadAccessResult(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * ReadAccessSpecification ::= SEQUENCE {
 *  objectIdentifier         [0] BACnetObjectIdentifier,
 *  listOfPropertyReferences [1] SEQUENCE OF BACnetPropertyReference
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param subtree the subtree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fReadAccessSpecification(tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, guint offset);

/**
 * WriteAccessSpecification ::= SEQUENCE {
 *  objectIdentifier [0] BACnetObjectIdentifier,
 *  listOfProperty   [1] SEQUENCE OF BACnetPropertyValue
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param subtree the sub tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fWriteAccessSpecification(tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, guint offset);


/********************************************************* Helper functions *******************************************/

/**
 * extracts the tag number from the tag header.
 * @param tvb the tv buffer of the current data "TestyVirtualBuffer"
 * @param offset the offset in the tvb in actual tvb
 * @return Tag Number corresponding to BACnet 20.2.1.2 Tag Number
 */
static guint
fTagNo(tvbuff_t *tvb, guint offset);

/**
 * splits Tag Header coresponding to 20.2.1 General Rules For BACnet Tags
 * @param tvb the tv buffer of the current data = "TestyVirtualBuffer"
 * @param pinfo the packet info of the current data = packet info
 * @param offset the offset in the tvb = offset in actual tvb
 * @return tag_no BACnet 20.2.1.2 Tag Number
 * @return class_tag BACnet 20.2.1.1 Class
 * @return lvt BACnet 20.2.1.3 Length/Value/Type
 * @return offs = length of this header
 */

static guint
fTagHeader(tvbuff_t *tvb, packet_info *pinfo, guint offset, guint8 *tag_no, guint8* class_tag, guint32 *lvt);


/**
 * adds processID with max 32Bit unsigned Integer Value to tree
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fProcessId(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * adds present value to the tree
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @param vs enum of string values when applicable
 * @param split_val enum index
 * @param type present value datatype enum
 * @return modified offset
 */
static guint
fPresentValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const value_string *vs, guint32 split_val, BacappPresentValueType type);

/**
 * adds event type to the tree
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fEventType(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * adds notify type to the tree
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fNotifyType(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * adds next_state with max 32Bit unsigned Integer Value to tree
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fToState(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * adds from_state with max 32Bit unsigned Integer Value to tree
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fFromState(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * adds object_name string value to tree
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fObjectName(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * wrapper function for fCharacterStringBase
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fCharacterString(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label);

/**
 * adds string value to tree
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @param present_val_dissect exposes string as present_value property
 * @param object_name_dissect exposes string as object_name property
 * @return modified offset
 */
static guint
fCharacterStringBase(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label,
                     gboolean present_val_dissect, gboolean object_name_dissect);

/**
 * adds timeSpan with max 32Bit unsigned Integer Value to tree
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fTimeSpan(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label);

/**
 * BACnet Application PDUs chapter 21
 * BACnetPropertyIdentifier::= ENUMERATED {
 *   @see bacapp_property_identifier
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fPropertyIdentifier(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * BACnet Application PDUs chapter 21
 * BACnetPropertyArrayIndex::= ENUMERATED {
 *   @see bacapp_property_array_index
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fPropertyArrayIndex(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * listOfEventSummaries ::= SEQUENCE OF SEQUENCE {
 *  objectIdentifier        [0] BACnetObjectIdentifier,
 *  eventState              [1] BACnetEventState,
 *  acknowledgedTransitions [2] BACnetEventTransitionBits,
 *  eventTimeStamps         [3] SEQURNCE SIZE (3) OF BACnetTimeStamps,
 *  notifyType              [4] BACnetNotifyType,
 *  eventEnable             [5] BACnetEventTransitionBits,
 *  eventPriorities         [6] SEQUENCE SIZE (3) OF Unsigned
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
flistOfEventSummaries(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * SelectionCriteria ::= SEQUENCE {
 *  propertyIdentifier [0] BACnetPropertyIdentifier,
 *  propertyArrayIndex [1] Unsigned OPTIONAL, -- used only with array datatype
 *  relationSpecifier  [2] ENUMERATED { bacapp_relationSpecifier },
 *  comparisonValue    [3] ABSTRACT-SYNTAX.&Type
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fSelectionCriteria(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * objectSelectionCriteria ::= SEQUENCE {
 *  selectionLogic          [0] ENUMERATED { bacapp_selectionLogic },
 *  listOfSelectionCriteria [1] SelectionCriteria
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param subtree the sub tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fObjectSelectionCriteria(tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, guint offset);

/**
 * BACnet-Error ::= SEQUENCE {
 *    error-class ENUMERATED {},
 *    error-code  ENUMERATED {}
 *    }
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * Adds error-code from BACnet-Error to the tree
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fErrorCode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * Adds error-class from BACnet-Error to the tree
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fErrorClass(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/**
 * Generic handler for context tagged values.  Mostly for handling
 * vendor-defined properties and services.
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 * @todo beautify this ugly construct
 */
static guint
fContextTaggedValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label);

/**
 * realizes some ABSTRACT-SYNTAX.&Type
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 * @todo beautify this ugly construct
 */
static guint
fAbstractSyntaxNType(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);


static guint
fBitStringTagVS(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label,
    const value_string *src);

static guint
fBitStringTagVSBase(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label,
    const value_string *src, gboolean present_val_dissect);

static guint
fFaultParameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fEventNotificationSubscription(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fLightingCommand(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *lable);

static guint
fColorCommand(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, guint offset, const gchar* lable);

static guint
fXyColor(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, guint offset, const gchar* lable);

static guint
fTimerStateChangeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fHostNPort(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *lable);

static guint
fBDTEntry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *lable);

static guint
fFDTEntry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *lable);

static guint
fRouterEntry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fVMACEntry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fValueSource(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fAssignedLandingCalls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fLandingCallStatus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fLandingDoorStatus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fCOVMultipleSubscription(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fNameValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fNameValueCollection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fAuthenticationFactor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fAuthenticationFactorFormat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fAuthenticationPolicy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fAccessRule(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fChannelValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label);

static guint
fPropertyAccessResult(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fNetworkSecurityPolicy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fSecurityKeySet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fAuditLogRecord(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fStageLimitValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

static guint
fObjectSelector(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);


/**
 * register_bacapp
 */
void
proto_register_bacapp(void);

/* <<<< formerly bacapp.h */

/* reassembly table for segmented messages */
static reassembly_table msg_reassembly_table;

/* some necessary forward function prototypes */
static guint
fApplicationTypesEnumerated(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset,
    const gchar *label, const value_string *vs);

static const char *bacapp_unknown_service_str = "unknown service";  /* Usage: no format specifiers */
static const char ASHRAE_Reserved_Fmt[] = "(%d) Reserved for Use by ASHRAE";
static const char Vendor_Proprietary_Fmt[] = "(%d) Vendor Proprietary Value";

static const value_string
BACnetTypeName[] = {
    { 0, "Confirmed-REQ"},
    { 1, "Unconfirmed-REQ"},
    { 2, "Simple-ACK"},
    { 3, "Complex-ACK"},
    { 4, "Segment-ACK"},
    { 5, "Error"},
    { 6, "Reject"},
    { 7, "Abort"},
    { 0, NULL }
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
    { 0,  "Unspecified"},
    { 1,  "2 segments"},
    { 2,  "4 segments"},
    { 3,  "8 segments"},
    { 4, "16 segments"},
    { 5, "32 segments"},
    { 6, "64 segments"},
    { 7, "Greater than 64 segments"},
    { 0, NULL }
};

static const value_string
BACnetMaxAPDULengthAccepted [] = {
    {  0, "Up to MinimumMessageSize (50 octets)"},
    {  1, "Up to 128 octets"},
    {  2, "Up to 206 octets (fits in a LonTalk frame)"},
    {  3, "Up to 480 octets (fits in an ARCNET frame)"},
    {  4, "Up to 1024 octets"},
    {  5, "Up to 1476 octets (fits in an ISO 8802-3 frame)"},
    {  6, "reserved by ASHRAE"},
    {  7, "reserved by ASHRAE"},
    {  8, "reserved by ASHRAE"},
    {  9, "reserved by ASHRAE"},
    { 10, "reserved by ASHRAE"},
    { 11, "reserved by ASHRAE"},
    { 12, "reserved by ASHRAE"},
    { 13, "reserved by ASHRAE"},
    { 14, "reserved by ASHRAE"},
    { 15, "reserved by ASHRAE"},
    { 0, NULL}
};

static const value_string
BACnetRejectReason [] = {
    { 0, "other"},
    { 1, "buffer-overflow"},
    { 2, "inconsistent-parameters"},
    { 3, "invalid-parameter-data-type"},
    { 4, "invalid-tag"},
    { 5, "missing-required-parameter"},
    { 6, "parameter-out-of-range"},
    { 7, "too-many-arguments"},
    { 8, "undefined-enumeration"},
    { 9, "unrecognized-service"},
    { 0, NULL}
};

static const value_string
BACnetRestartReason [] = {
    { 0, "unknown"},
    { 1, "coldstart"},
    { 2, "warmstart"},
    { 3, "detected-power-lost"},
    { 4, "detected-powered-off"},
    { 5, "hardware-watchdog"},
    { 6, "software-watchdog"},
    { 7, "suspended"},
    { 8, "activate-changes"},
    { 0, NULL}
};

static const value_string
BACnetApplicationTagNumber [] = {
    {  0, "Null"},
    {  1, "Boolean"},
    {  2, "Unsigned Integer"},
    {  3, "Signed Integer (2's complement notation)"},
    {  4, "Real (ANSI/IEE-754 floating point)"},
    {  5, "Double (ANSI/IEE-754 double precision floating point)"},
    {  6, "Octet String"},
    {  7, "Character String"},
    {  8, "Bit String"},
    {  9, "Enumerated"},
    { 10, "Date"},
    { 11, "Time"},
    { 12, "BACnetObjectIdentifier"},
    { 13, "reserved by ASHRAE"},
    { 14, "reserved by ASHRAE"},
    { 15, "reserved by ASHRAE"},
    { 0,  NULL}
};

static const value_string
BACnetAction [] = {
    { 0, "direct"},
    { 1, "reverse"},
    { 0, NULL}
};

static const value_string
BACnetAccessEvent [] = {
    {  0, "none"},
    {  1, "granted"},
    {  2, "muster"},
    {  3, "passback-detected"},
    {  4, "duress"},
    {  5, "trace"},
    {  6, "lockout-max-attempts"},
    {  7, "lockout-other"},
    {  8, "lockout-relinquished"},
    {  9, "lockout-by-higher-priority"},
    { 10, "out-of-service"},
    { 11, "out-of-service-relinquished"},
    { 12, "accompaniment-by"},
    { 13, "authentication-factor-read"},
    { 14, "authorization-delayed"},
    { 15, "verification-required"},
    /* Enumerated values 128-511 are used for events
     * which indicate that access has been denied. */
    { 128, "denied-deny-all"},
    { 129, "denied-unknown-credential"},
    { 130, "denied-authentication-unavailable"},
    { 131, "denied-authentication-factor-timeout"},
    { 132, "denied-incorrect-authentication-factor"},
    { 133, "denied-zone-no-access-rights"},
    { 134, "denied-point-no-access-rights"},
    { 135, "denied-no-access-rights"},
    { 136, "denied-out-of-time-range"},
    { 137, "denied-threat-level"},
    { 138, "denied-passback"},
    { 139, "denied-unexpected-location-usage"},
    { 140, "denied-max-attempts"},
    { 141, "denied-lower-occupancy-limit"},
    { 142, "denied-upper-occupancy-limit"},
    { 143, "denied-authentication-factor-lost"},
    { 144, "denied-authentication-factor-stolen"},
    { 145, "denied-authentication-factor-damaged"},
    { 146, "denied-authentication-factor-destroyed"},
    { 147, "denied-authentication-factor-disabled"},
    { 148, "denied-authentication-factor-error"},
    { 149, "denied-credential-unassigned"},
    { 150, "denied-credential-not-provisioned"},
    { 151, "denied-credential-not-yet-active"},
    { 152, "denied-credential-expired"},
    { 153, "denied-credential-manual-disable"},
    { 154, "denied-credential-lockout"},
    { 155, "denied-credential-max-days"},
    { 156, "denied-credential-max-uses"},
    { 157, "denied-credential-inactivity"},
    { 158, "denied-credential-disabled"},
    { 159, "denied-no-accompaniment"},
    { 160, "denied-incorrect-accompaniment"},
    { 161, "denied-lockout"},
    { 162, "denied-verification-failed"},
    { 163, "denied-verification-timeout"},
    { 164, "denied-other"},
    { 0,  NULL}
/* Enumerated values 0-512 are reserved for definition by ASHRAE.
   Enumerated values 512-65535 may be used by others subject to
   procedures and constraints described in Clause 23. */
};

static const value_string
BACnetAccessZoneOccupancyState[] = {
    { 0, "normal"},
    { 1, "below-lower-limit"},
    { 2, "at-lower-limit"},
    { 3, "at-upper-limit"},
    { 4, "above-upper-limit"},
    { 5, "disabled"},
    { 6, "not-supported"},
    { 0,  NULL}
};

static const value_string
BACnetAccessPassbackMode[] = {
    { 0, "passback-off" },
    { 1, "hard-passback" },
    { 2, "soft-passback" },
    { 0, NULL }
};

static const value_string
BACnetAccessCredentialDisableReason[] = {
    { 0, "disabled" },
    { 1, "disabled-needs-provisioning" },
    { 2, "disabled-unassigned" },
    { 3, "disabled-not-yet-active" },
    { 4, "disabled-expired" },
    { 5, "disabled-lockout" },
    { 6, "disabled-max-days" },
    { 7, "disabled-max-uses" },
    { 8, "disabled-inactivity" },
    { 9, "disabled-manual" },
    { 0, NULL }
};

static const value_string
BACnetAccessUserType[] = {
    { 0, "asset" },
    { 1, "group" },
    { 2, "person" },
    { 0, NULL }
};

static const value_string
BACnetWriteStatus[] = {
    { 0, "idle" },
    { 1, "in-progress" },
    { 2, "successful" },
    { 3, "failed" },
    { 0, NULL }
};

static const value_string
BACnetLightingTransition[] = {
    { 0, "none" },
    { 1, "fade" },
    { 2, "ramp" },
    { 0, NULL }
};

static const value_string
BACnetSecurityLevel[] = {
    { 0, "incapable" },
    { 1, "plain" },
    { 2, "signed" },
    { 3, "encrypted" },
    { 4, "signed-end-to-end" },
    { 5, "encrypted-end-to-end" },
    { 0, NULL }
};

static const value_string
BACnetAccessCredentialDisable[] = {
    { 0, "none" },
    { 1, "disable" },
    { 2, "disable-manual" },
    { 3, "disable-lockout" },
    { 0, NULL }
};

static const value_string
BACnetAuthenticationStatus[] = {
    { 0, "not-ready" },
    { 1, "ready" },
    { 2, "disabled" },
    { 3, "waiting-for-authentication-factor" },
    { 4, "waiting-for-accompaniment" },
    { 5, "waiting-for-verification" },
    { 6, "in-progress" },
    { 0, NULL }
};

static const value_string
BACnetAuthorizationMode[] = {
    { 0, "authorize" },
    { 1, "grant-active" },
    { 2, "deny-all" },
    { 3, "verification-required" },
    { 4, "authorization-delayed" },
    { 5, "none" },
    { 0, NULL }
};

static const value_string
BACnetAuthorizationExemption[] = {
    { 0, "passback" },
    { 1, "occupancy-check" },
    { 2, "access-rights" },
    { 3, "lockout" },
    { 4, "deny" },
    { 5, "verification" },
    { 6, "authorization-delay" },
    { 0, NULL }
};

static const value_string
BACnetLightingInProgress[] = {
    { 0, "idle" },
    { 1, "fade-active" },
    { 2, "ramp-active" },
    { 3, "not-controlled" },
    { 4, "other" },
    { 5, "trim-active" },
    { 0, NULL }
};

static const value_string
BACnetColorOperationInProgress[] = {
    { 0, "idle" },
    { 1, "fade-active" },
    { 2, "ramp-active" },
    { 3, "not-controlled" },
    { 4, "other" },
    { 0, NULL }
};

static const value_string
BACnetColorTransition[] = {
    { 0, "none" },
    { 1, "fade" },
    { 2, "ramp" },
    { 0, NULL }
};

static const value_string
BACnetBinaryLightingPV[] = {
    { 0, "off" },
    { 1, "on" },
    { 2, "warn" },
    { 3, "warn-off" },
    { 4, "warn-relinquish" },
    { 5, "stop" },
    { 0, NULL }
};

static const value_string
BACnetBackupState[] = {
    { 0, "idle"},
    { 1, "preparing-for-backup"},
    { 2, "preparing-for-restore"},
    { 3, "performing-a-backup"},
    { 4, "performing-a-restore"},
    { 5, "backup-failure"},
    { 6, "restore-failure"},
    { 0,  NULL}
};

static const value_string
BACnetAcknowledgedTransitions[] = {
    { 0, "to-offnormal" },
    { 1, "to-fault" },
    { 2, "to-normal" },
    { 0, NULL }
};

static const value_string
BACnetFileAccessMethod [] = {
    { 0, "record-access"},
    { 1, "stream-access"},
    { 0, NULL}
};

/* For some reason, BACnet defines the choice parameter
   in the file read and write services backwards from the
   BACnetFileAccessMethod enumeration.
*/
static const value_string
BACnetFileAccessOption [] = {
    { 0, "stream access"},
    { 1, "record access"},
    { 0, NULL}
};

static const value_string
BACnetFileStartOption [] = {
    { 0, "File Start Position: "},
    { 1, "File Start Record: "},
    { 0, NULL}
};

static const value_string
BACnetFileRequestCount [] = {
    { 0, "Requested Octet Count: "},
    { 1, "Requested Record Count: "},
    { 0, NULL}
};

static const value_string
BACnetFileWriteInfo [] = {
    { 0, "File Data: "},
    { 1, "Record Count: "},
    { 0, NULL}
};

static const value_string
BACnetAbortReason [] = {
    { 0, "other"},
    { 1, "buffer-overflow"},
    { 2, "invalid-apdu-in-this-state"},
    { 3, "preempted-by-higher-priority-task"},
    { 4, "segmentation-not-supported"},
    { 5, "security-error"},
    { 6, "insufficient-security"},
    { 7, "window-size-out-of-range"},
    { 8, "application-exceeded-reply-time"},
    { 9, "out-of-resources"},
    { 10, "tsm-timeout"},
    { 11, "apdu-too-long"},
    { 0, NULL}
};

static const value_string
BACnetIpMode [] = {
    { 0, "normal"},
    { 1, "foreign"},
    { 2, "bbmd"},
    { 0,  NULL}
};

static const value_string
BACnetNetworkPortCommand [] = {
    { 0, "idle"},
    { 1, "discard-changes"},
    { 2, "renew-fd-registration"},
    { 3, "restart-slave-discovery"},
    { 4, "renew-dhcp"},
    { 5, "restart-autonegotiation"},
    { 6, "disconnect"},
    { 7, "restart-port"},
    { 8, "generate-csr-file"},
    { 9, "validate-changes"},
    { 0,  NULL}
};

static const value_string
BACnetNetworkNumberQuality [] = {
    { 0, "unknown"},
    { 1, "learned"},
    { 2, "learned-configured"},
    { 3, "configured"},
    { 0,  NULL}
};

static const value_string
BACnetNetworkType [] = {
    { 0, "ethernet" },
    { 1, "arcnet" },
    { 2, "mstp" },
    { 3, "ptp" },
    { 4, "lontalk" },
    { 5, "bacnet-ipv4" },
    { 6, "zigbee" },
    { 7, "virtual" },
    { 8, "non-bacnet" },
    { 9, "bacnet-ipv6" },
    {10, "serial" },
    {11, "secure-connect" },
    { 0,  NULL}
};

static const value_string
BACnetSCConnectionState [] = {
    { 0, "not-connected" },
    { 1, "connected" },
    { 2, "disconnected-with-errors" },
    { 3, "failed-to-connect" },
    { 0,  NULL}
};

static const value_string
BACnetSCHubConnectorState [] = {
    { 0, "no-hub-connection" },
    { 1, "connected-to-primary" },
    { 2, "connected-to-failover" },
    { 0,  NULL}
};

static const value_string
BACnetLifeSafetyMode [] = {
    {  0, "off"},
    {  1, "on"},
    {  2, "test"},
    {  3, "manned"},
    {  4, "unmanned"},
    {  5, "armed"},
    {  6, "disarmed"},
    {  7, "prearmed"},
    {  8, "slow"},
    {  9, "fast"},
    { 10, "disconnected"},
    { 11, "enabled"},
    { 12, "disabled"},
    { 13, "atomic-release-disabled"},
    { 14, "default"},
    { 15, "activated-oeo-alarm"},
    { 16, "activated-oeo-evacuate"},
    { 17, "activated-oeo-phase1-recall"},
    { 18, "activated-oeo-unavailable"},
    { 19, "deactivated"},
    { 0,  NULL}
/* Enumerated values 0-255 are reserved for definition by ASHRAE.
   Enumerated values 256-65535 may be used by others subject to
   procedures and constraints described in Clause 23. */
};

static const value_string
BACnetLifeSafetyOperation [] = {
    { 0, "none"},
    { 1, "silence"},
    { 2, "silence-audible"},
    { 3, "silence-visual"},
    { 4, "reset"},
    { 5, "reset-alarm"},
    { 6, "reset-fault"},
    { 7, "unsilence"},
    { 8, "unsilence-audible"},
    { 9, "unsilence-visual"},
    { 0, NULL}
/* Enumerated values 0-63 are reserved for definition by ASHRAE.
   Enumerated values 64-65535 may be used by others subject to
   procedures and constraints described in Clause 23. */
};

static const value_string
BACnetLifeSafetyState [] = {
    {  0, "quiet"},
    {  1, "pre-alarm"},
    {  2, "alarm"},
    {  3, "fault"},
    {  4, "fault-pre-alarm"},
    {  5, "fault-alarm"},
    {  6, "not-ready"},
    {  7, "active"},
    {  8, "tamper"},
    {  9, "test-alarm"},
    { 10, "test-active"},
    { 11, "test-fault"},
    { 12, "test-fault-alarm"},
    { 13, "holdup"},
    { 14, "duress"},
    { 15, "tamper-alarm"},
    { 16, "abnormal"},
    { 17, "emergency-power"},
    { 18, "delayed"},
    { 19, "blocked"},
    { 20, "local-alarm"},
    { 21, "general-alarm"},
    { 22, "supervisory"},
    { 23, "test-supervisory"},
    { 24, "non-default-mode"},
    { 25, "oeo-unavailable"},
    { 26, "oeo-alarm"},
    { 27, "oeo-phase1-recall"},
    { 28, "oeo-evacuate"},
    { 29, "oeo-unaffected"},
    { 30, "test-oeo-unavailable"},
    { 31, "test-oeo-alarm"},
    { 32, "test-oeo-phase1-recall"},
    { 33, "test-oeo-evacuate"},
    { 34, "test-oeo-unaffected"},
    { 0,  NULL}
/* Enumerated values 0-255 are reserved for definition by ASHRAE.
   Enumerated values 256-65535 may be used by others subject to
   procedures and constraints described in Clause 23. */
};

static const value_string
BACnetLimitEnable[] = {
    { 0, "low-limit" },
    { 1, "high-limit" },
    { 0, NULL }
};

static const value_string
BACnetTimerState [] = {
    { 0, "idle"},
    { 1, "running"},
    { 2, "expired"},
    { 0, NULL}
};

static const value_string
BACnetTimerTransition [] = {
    { 0, "none"},
    { 1, "idle-to-running"},
    { 2, "running-to-idle"},
    { 3, "running-to-running"},
    { 4, "running-to-expired"},
    { 5, "forced-to-expired"},
    { 6, "expired-to-idle"},
    { 7, "expired-to-running"},
    { 0, NULL}
};

static const value_string
BACnetEscalatorFault [] = {
    { 0, "controller-fault"},
    { 1, "drive-and-motor-fault"},
    { 2, "mechanical-component-fault"},
    { 3, "overspeed-fault"},
    { 4, "power-supply-fault"},
    { 5, "safety-device-fault"},
    { 6, "controller-supply-fault"},
    { 7, "drive-temperature-exceeded"},
    { 8, "comb-plate-fault"},
    { 0, NULL}
};

static const value_string
BACnetEscalatorMode [] = {
    { 0, "unknown"},
    { 1, "stop"},
    { 2, "up"},
    { 3, "down"},
    { 4, "inspection"},
    { 5, "out-of-service"},
    { 0, NULL}
};

static const value_string
BACnetEscalatorOperationDirection [] = {
    { 0, "unknown"},
    { 1, "stopped"},
    { 2, "up-rated-speed"},
    { 3, "up-reduced-speed"},
    { 4, "down-rated-speed"},
    { 5, "down-reduced-speed"},
    { 0, NULL}
};

static const value_string
BACnetLiftCarDirection [] = {
    { 0, "unknown"},
    { 1, "none"},
    { 2, "stopped"},
    { 3, "up"},
    { 4, "down"},
    { 5, "up-and-down"},
    { 0, NULL}
};

static const value_string
BACnetLiftCarDoorCommand [] = {
    { 0, "none"},
    { 1, "open"},
    { 2, "close"},
    { 0, NULL}
};

static const value_string
BACnetLiftCarDriveStatus [] = {
    { 0, "unknown"},
    { 1, "stationary"},
    { 2, "braking"},
    { 3, "accelerate"},
    { 4, "decelerate"},
    { 5, "rated-speed"},
    { 6, "single-floor-jump"},
    { 7, "two-floor-jump"},
    { 8, "three-floor-jump"},
    { 9, "multi-floor-jump"},
    { 0, NULL}
};

static const value_string
BACnetLiftCarMode [] = {
    { 0, "unknown"},
    { 1, "normal"},
    { 2, "vip"},
    { 3, "homing"},
    { 4, "parking"},
    { 5, "attendant-control"},
    { 6, "firefighter-control"},
    { 7, "emergency-power"},
    { 8, "inspection"},
    { 9, "cabinet-recall"},
    { 10, "earthquake-operation"},
    { 11, "fire-operation"},
    { 12, "out-of-service"},
    { 13, "occupant-evacuation"},
    { 0, NULL}
};

static const value_string
BACnetLiftFault [] = {
    { 0, "controller-fault"},
    { 1, "drive-and-motor-fault"},
    { 2, "governor-and-safety-gear-fault"},
    { 3, "lift-shaft-device-fault"},
    { 4, "power-supply-fault"},
    { 5, "safety-interlock-fault"},
    { 6, "door-closing-fault"},
    { 7, "door-opening-fault"},
    { 8, "car-stopped-outside-landing-zone"},
    { 9, "call-button-stuck"},
    { 10, "start-failure"},
    { 11, "controller-supply-fault"},
    { 12, "self-test-failure"},
    { 13, "runtime-limit-exceeded"},
    { 14, "position-lost"},
    { 15, "drive-temperature-exceeded"},
    { 16, "load-measurement-fault"},
    { 0, NULL}
};

static const value_string
BACnetLiftGroupMode [] = {
    { 0, "unknown"},
    { 1, "normal"},
    { 2, "down-peak"},
    { 3, "two-way"},
    { 4, "four-way"},
    { 5, "emergency-power"},
    { 6, "up-peak"},
    { 0, NULL}
};

static const value_string
BACnetProtocolLevel [] = {
    { 0, "physical"},
    { 1, "protocol"},
    { 2, "bacnet-application"},
    { 3, "non-bacnet-application"},
    { 0, NULL}
};

static const value_string
BACnetRelationship [] = {
    { 0, "unknown"},
    { 1, "default"},
    { 2, "contains"},
    { 3, "contained-by"},
    { 4, "uses"},
    { 5, "used-by"},
    { 6, "commands"},
    { 7, "commanded-by"},
    { 8, "adjusts"},
    { 9, "adjusted-by"},
    { 10, "ingress"},
    { 11, "egress"},
    { 12, "supplies-air"},
    { 13, "receives-air"},
    { 14, "supplies-hot-air"},
    { 15, "receives-hot-air"},
    { 16, "supplies-cool-air"},
    { 17, "receives-cool-air"},
    { 18, "supplies-power"},
    { 19, "receives-power"},
    { 20, "supplies-gas"},
    { 21, "receives-gas"},
    { 22, "supplies-water"},
    { 23, "receives-water"},
    { 24, "supplies-hot-water"},
    { 25, "receives-hot-water"},
    { 26, "supplies-cool-water"},
    { 27, "receives-cool-water"},
    { 28, "supplies-steam"},
    { 29, "receives-steam"},
    { 0, NULL}
};

static const value_string
BACnetLightingOperation[] = {
    { 0, "none" },
    { 1, "fade-to" },
    { 2, "ramp-to" },
    { 3, "step-up" },
    { 4, "step-down" },
    { 5, "step-on" },
    { 6, "step-off" },
    { 7, "warn" },
    { 8, "warn-off" },
    { 9, "warn-relinquish" },
    { 10, "stop" },
    { 0, NULL }
};

static const value_string
BACnetColorOperation[] = {
    { 0, "none" },
    { 1, "fade-to-color" },
    { 2, "fade-to-cct" },
    { 3, "ramp-to-cct" },
    { 4, "step-up-cct" },
    { 5, "step-down-cct" },
    { 6, "stop" },
    { 0, NULL }
};

static const value_string
BACnetConfirmedServiceChoice[] = {
    {  0, "acknowledgeAlarm"},
    {  1, "confirmedCOVNotification"},
    {  2, "confirmedEventNotification"},
    {  3, "getAlarmSummary"},
    {  4, "getEnrollmentSummary"},
    {  5, "subscribeCOV"},
    {  6, "atomicReadFile"},
    {  7, "atomicWriteFile"},
    {  8, "addListElement"},
    {  9, "removeListElement"},
    { 10, "createObject"},
    { 11, "deleteObject"},
    { 12, "readProperty"},
    { 13, "readPropertyConditional"},
    { 14, "readPropertyMultiple"},
    { 15, "writeProperty"},
    { 16, "writePropertyMultiple"},
    { 17, "deviceCommunicationControl"},
    { 18, "confirmedPrivateTransfer"},
    { 19, "confirmedTextMessage"},
    { 20, "reinitializeDevice"},
    { 21, "vtOpen"},
    { 22, "vtClose"},
    { 23, "vtData"},
    { 24, "authenticate"},
    { 25, "requestKey"},
    { 26, "readRange"},
    { 27, "lifeSafetyOperation"},
    { 28, "subscribeCOVProperty"},
    { 29, "getEventInformation"},
    { 30, "subscribeCovPropertyMultiple"},
    { 31, "confirmedCovNotificationMultiple"},
    { 32, "confirmedAuditNotification"},
    { 33, "auditLogQuery"},
    { 0,  NULL}
};

static const value_string
BACnetReliability [] = {
    {  0, "no-fault-detected"},
    {  1, "no-sensor"},
    {  2, "over-range"},
    {  3, "under-range"},
    {  4, "open-loop"},
    {  5, "shorted-loop"},
    {  6, "no-output"},
    {  7, "unreliable-other"},
    {  8, "process-error"},
    {  9, "multi-state-fault"},
    { 10, "configuration-error"},
    { 11, "reserved for a future addendum"},
    { 12, "communication-failure"},
    { 13, "member-fault"},
    { 14, "monitored-object-fault" },
    { 15, "tripped"},
    { 16, "lamp-failure"},
    { 17, "activation-failure"},
    { 18, "renew-dhcp-failure"},
    { 19, "renew-fd-registration-failure"},
    { 20, "restart-auto-negotiation-failure"},
    { 21, "restart-failure"},
    { 22, "proprietary-command-failure"},
    { 23, "faults-listed"},
    { 24, "referenced-object-fault"},
    { 0,  NULL}
};

static const value_string
BACnetRouterStatus[] = {
    { 0, "available" },
    { 1, "busy" },
    { 2, "disconnected" },
    { 0, NULL }
};

static const value_string
BACnetUnconfirmedServiceChoice [] = {
    { 0, "i-Am"},
    { 1, "i-Have"},
    { 2, "unconfirmedCOVNotification"},
    { 3, "unconfirmedEventNotification"},
    { 4, "unconfirmedPrivateTransfer"},
    { 5, "unconfirmedTextMessage"},
    { 6, "timeSynchronization"},
    { 7, "who-Has"},
    { 8, "who-Is"},
    { 9, "utcTimeSynchronization"},
    { 10, "writeGroup"},
    { 11, "unconfirmedCovNotificationMultiple"},
    { 12, "unconfirmedAuditNotification"},
    { 13, "who-am-I" },
    { 14, "you-are" },
    { 0, NULL}
};

static const value_string
BACnetObjectType [] = {
    {  0, "analog-input"},
    {  1, "analog-output"},
    {  2, "analog-value"},
    {  3, "binary-input"},
    {  4, "binary-output"},
    {  5, "binary-value"},
    {  6, "calendar"},
    {  7, "command"},
    {  8, "device"},
    {  9, "event-enrollment"},
    { 10, "file"},
    { 11, "group"},
    { 12, "loop"},
    { 13, "multi-state-input"},
    { 14, "multi-state-output"},
    { 15, "notification-class"},
    { 16, "program"},
    { 17, "schedule"},
    { 18, "averaging"},
    { 19, "multi-state-value"},
    { 20, "trend-log"},
    { 21, "life-safety-point"},
    { 22, "life-safety-zone"},
    { 23, "accumulator"},
    { 24, "pulse-converter"},
    { 25, "event-log"},
    { 26, "global-group"},
    { 27, "trend-log-multiple"},
    { 28, "load-control"},
    { 29, "structured-view"},
    { 30, "access-door"},     /* 30-37 added with addanda 135-2008j */
    { 31, "timer"},
    { 32, "access-credential"},
    { 33, "access-point"},
    { 34, "access-rights"},
    { 35, "access-user"},
    { 36, "access-zone"},
    { 37, "credential-data-input"},
    { 38, "network-security"},
    { 39, "bitstring-value"},     /* 39-50 added with addenda 135-2008w */
    { 40, "characterstring-value"},
    { 41, "date-pattern-value"},
    { 42, "date-value"},
    { 43, "datetime-pattern-value"},
    { 44, "datetime-value"},
    { 45, "integer-value"},
    { 46, "large-analog-value"},
    { 47, "octetstring-value"},
    { 48, "positive-integer-value"},
    { 49, "time-pattern-value"},
    { 50, "time-value"},
    { 51, "notification-forwarder"},
    { 52, "alert-enrollment"},
    { 53, "channel"},
    { 54, "lighting-output"},
    { 55, "binary-lighting-output"},
    { 56, "network-port"},
    { 57, "elevator-group"},
    { 58, "escalator"},
    { 59, "lift"},
    { 60, "staging"},
    { 61, "audit-log"},
    { 62, "audit-reporter"},
    { 63, "color"},
    { 64, "color-temperature"},
    { 0,  NULL}
/* Enumerated values 0-127 are reserved for definition by ASHRAE.
   Enumerated values 128-1023 may be used by others subject to
   the procedures and constraints described in Clause 23. */
};

static const value_string
BACnetEngineeringUnits [] = {
    {   0, "Sq Meters"},
    {   1, "Sq Feet"},
    {   2, "Milliamperes"},
    {   3, "Amperes"},
    {   4, "Ohms"},
    {   5, "Volts"},
    {   6, "Kilovolts"},
    {   7, "Megavolts"},
    {   8, "Volt Amperes"},
    {   9, "Kilovolt Amperes"},
    {  10, "Megavolt Amperes"},
    {  11, "Volt Amperes Reactive"},
    {  12, "Kilovolt Amperes Reactive"},
    {  13, "Megavolt Amperes Reactive"},
    {  14, "Degrees Phase"},
    {  15, "Power Factor"},
    {  16, "Joules"},
    {  17, "Kilojoules"},
    {  18, "Watt Hours"},
    {  19, "Kilowatt Hours"},
    {  20, "BTUs"},
    {  21, "Therms"},
    {  22, "Ton Hours"},
    {  23, "Joules Per Kg Dry Air"},
    {  24, "BTUs Per Pound Dry Air"},
    {  25, "Cycles Per Hour"},
    {  26, "Cycles Per Minute"},
    {  27, "Hertz"},
    {  28, "Grams Of Water Per Kilogram Dry Air"},
    {  29, "Relative Humidity"},
    {  30, "Millimeters"},
    {  31, "Meters"},
    {  32, "Inches"},
    {  33, "Feed"},
    {  34, "Watts Per Sq Foot"},
    {  35, "Watts Per Sq meter"},
    {  36, "Lumens"},
    {  37, "Lux"},
    {  38, "Foot Candles"},
    {  39, "Kilograms"},
    {  40, "Pounds Mass"},
    {  41, "Tons"},
    {  42, "Kgs per Second"},
    {  43, "Kgs Per Minute"},
    {  44, "Kgs Per Hour"},
    {  45, "Pounds Mass Per Minute"},
    {  46, "Pounds Mass Per Hour"},
    {  47, "Watt"},
    {  48, "Kilowatts"},
    {  49, "Megawatts"},
    {  50, "BTUs Per Hour"},
    {  51, "Horsepower"},
    {  52, "Tons Refrigeration"},
    {  53, "Pascals"},
    {  54, "Kilopascals"},
    {  55, "Bars"},
    {  56, "Pounds Force Per Square Inch"},
    {  57, "Centimeters Of Water"},
    {  58, "Inches Of Water"},
    {  59, "Millimeters Of Mercury"},
    {  60, "Centimeters Of Mercury"},
    {  61, "Inches Of Mercury"},
    {  62, "Degrees Celsius"},
    {  63, "Degrees Kelvin"},
    {  64, "Degrees Fahrenheit"},
    {  65, "Degree Days Celsius"},
    {  66, "Degree Days Fahrenheit"},
    {  67, "Years"},
    {  68, "Months"},
    {  69, "Weeks"},
    {  70, "Days"},
    {  71, "Hours"},
    {  72, "Minutes"},
    {  73, "Seconds"},
    {  74, "Meters Per Second"},
    {  75, "Kilometers Per Hour"},
    {  76, "Feed Per Second"},
    {  77, "Feet Per Minute"},
    {  78, "Miles Per Hour"},
    {  79, "Cubic Feet"},
    {  80, "Cubic Meters"},
    {  81, "Imperial Gallons"},
    {  82, "Liters"},
    {  83, "US Gallons"},
    {  84, "Cubic Feet Per Minute"},
    {  85, "Cubic Meters Per Second"},
    {  86, "Imperial Gallons Per Minute"},
    {  87, "Liters Per Second"},
    {  88, "Liters Per Minute"},
    {  89, "US Gallons Per Minute"},
    {  90, "Degrees Angular"},
    {  91, "Degrees Celsius Per Hour"},
    {  92, "Degrees Celsius Per Minute"},
    {  93, "Degrees Fahrenheit Per Hour"},
    {  94, "Degrees Fahrenheit Per Minute"},
    {  95, "No Units"},
    {  96, "Parts Per Million"},
    {  97, "Parts Per Billion"},
    {  98, "Percent"},
    {  99, "Percent Per Second"},
    { 100, "Per Minute"},
    { 101, "Per Second"},
    { 102, "Psi Per Degree Fahrenheit"},
    { 103, "Radians"},
    { 104, "Revolutions Per Min"},
    { 105, "Currency1"},
    { 106, "Currency2"},
    { 107, "Currency3"},
    { 108, "Currency4"},
    { 109, "Currency5"},
    { 110, "Currency6"},
    { 111, "Currency7"},
    { 112, "Currency8"},
    { 113, "Currency9"},
    { 114, "Currency10"},
    { 115, "Sq Inches"},
    { 116, "Sq Centimeters"},
    { 117, "BTUs Per Pound"},
    { 118, "Centimeters"},
    { 119, "Pounds Mass Per Second"},
    { 120, "Delta Degrees Fahrenheit"},
    { 121, "Delta Degrees Kelvin"},
    { 122, "Kilohms"},
    { 123, "Megohms"},
    { 124, "Millivolts"},
    { 125, "Kilojoules Per Kg"},
    { 126, "Megajoules"},
    { 127, "Joules Per Degree Kelvin"},
    { 128, "Joules Per Kg Degree Kelvin"},
    { 129, "Kilohertz"},
    { 130, "Megahertz"},
    { 131, "Per Hour"},
    { 132, "Milliwatts"},
    { 133, "Hectopascals"},
    { 134, "Millibars"},
    { 135, "Cubic Meters Per Hour"},
    { 136, "Liters Per Hour"},
    { 137, "KWatt Hours Per Square Meter"},
    { 138, "KWatt Hours Per Square Foot"},
    { 139, "Megajoules Per Square Meter"},
    { 140, "Megajoules Per Square Foot"},
    { 141, "Watts Per Sq Meter Degree Kelvin"},
    { 142, "Cubic Feet Per Second"},
    { 143, "Percent Obstruction Per Foot"},
    { 144, "Percent Obstruction Per Meter"},
    { 145, "milliohms"},
    { 146, "megawatt-hours"},
    { 147, "kilo-btus"},
    { 148, "mega-btus"},
    { 149, "kilojoules-per-kilogram-dry-air"},
    { 150, "megajoules-per-kilogram-dry-air"},
    { 151, "kilojoules-per-degree-Kelvin"},
    { 152, "megajoules-per-degree-Kelvin"},
    { 153, "newton"},
    { 154, "grams-per-second"},
    { 155, "grams-per-minute"},
    { 156, "tons-per-hour"},
    { 157, "kilo-btus-per-hour"},
    { 158, "hundredths-seconds"},
    { 159, "milliseconds"},
    { 160, "newton-meters"},
    { 161, "millimeters-per-second"},
    { 162, "millimeters-per-minute"},
    { 163, "meters-per-minute"},
    { 164, "meters-per-hour"},
    { 165, "cubic-meters-per-minute"},
    { 166, "meters-per-second-per-second"},
    { 167, "amperes-per-meter"},
    { 168, "amperes-per-square-meter"},
    { 169, "ampere-square-meters"},
    { 170, "farads"},
    { 171, "henrys"},
    { 172, "ohm-meters"},
    { 173, "siemens"},
    { 174, "siemens-per-meter"},
    { 175, "teslas"},
    { 176, "volts-per-degree-Kelvin"},
    { 177, "volts-per-meter"},
    { 178, "webers"},
    { 179, "candelas"},
    { 180, "candelas-per-square-meter"},
    { 181, "degrees-Kelvin-per-hour"},
    { 182, "degrees-Kelvin-per-minute"},
    { 183, "joule-seconds"},
    { 184, "radians-per-second"},
    { 185, "square-meters-per-Newton"},
    { 186, "kilograms-per-cubic-meter"},
    { 187, "newton-seconds"},
    { 188, "newtons-per-meter"},
    { 189, "watts-per-meter-per-degree-Kelvin"},
    { 190, "micro-siemens"},
    { 191, "cubic-feet-per-hour"},
    { 192, "us-gallons-per-hour"},
    { 193, "kilometers"},
    { 194, "micrometers"},
    { 195, "grams"},
    { 196, "milligrams"},
    { 197, "milliliters"},
    { 198, "milliliters-per-second"},
    { 199, "decibels"},
    { 200, "decibels-millivolt"},
    { 201, "decibels-volt"},
    { 202, "millisiemens"},
    { 203, "watt-hours-reactive"},
    { 204, "kilowatt-hours-reactive"},
    { 205, "megawatt-hours-reactive"},
    { 206, "millimeters-of-water"},
    { 207, "per-mille"},
    { 208, "grams-per-gram"},
    { 209, "kilograms-per-kilogram"},
    { 210, "grams-per-kilogram"},
    { 211, "milligrams-per-gram"},
    { 212, "milligrams-per-kilogram"},
    { 213, "grams-per-milliliter"},
    { 214, "grams-per-liter"},
    { 215, "milligrams-per-liter"},
    { 216, "micrograms-per-liter"},
    { 217, "grams-per-cubic-meter"},
    { 218, "milligrams-per-cubic-meter"},
    { 219, "micrograms-per-cubic-meter"},
    { 220, "nanograms-per-cubic-meter"},
    { 221, "grams-per-cubic-centimeter"},
    { 222, "becquerels"},
    { 223, "kilobecquerels"},
    { 224, "megabecquerels"},
    { 225, "gray"},
    { 226, "milligray"},
    { 227, "microgray"},
    { 228, "sieverts"},
    { 229, "millisieverts"},
    { 230, "microsieverts"},
    { 231, "microsieverts-per-hour"},
    { 232, "decibels-a"},
    { 233, "nephelometric-turbidity-unit"},
    { 234, "pH"},
    { 235, "grams-per-square-meter"},
    { 236, "minutes-per-degree-kelvin"},
    { 237, "ohm-meter-squared-per-meter"},
    { 238, "ampere-seconds"},
    { 239, "volt-ampere-hours"},
    { 240, "kilovolt-ampere-hours"},
    { 241, "megavolt-ampere-hours"},
    { 242, "volt-ampere-hours-reactive"},
    { 243, "kilovolt-ampere-hours-reactive"},
    { 244, "megavolt-ampere-hours-reactive"},
    { 245, "volt-square-hours"},
    { 246, "ampere-square-hours"},
    { 247, "joule-per-hours"},
    { 248, "cubic-feet-per-day"},
    { 249, "cubic-meters-per-day"},
    { 250, "watt-hours-per-cubic-meter"},
    { 251, "joules-per-cubic-meter"},
    { 252, "mole-percent"},
    { 253, "pascal-seconds"},
    { 254, "million-standard-cubic-feet-per-minute"},
    { 255, "unassigned-unit-value-255"},
    { 47808, "standard-cubic-feet-per-day"},
    { 47809, "million-standard-cubic-feet-per-day"},
    { 47810, "thousand-cubic-feet-per-day"},
    { 47811, "thousand-standard-cubic-feet-per-day"},
    { 47812, "pounds-mass-per-day"},
    { 47813, "reserved-unit-47813"},
    { 47814, "millirems"},
    { 47815, "millirems-per-hour"},
    { 47816, "degrees-lovibond"},
    { 47817, "alcohol-by-volume"},
    { 47818, "international-bittering-units"},
    { 47819, "european-bitterness-units"},
    { 47820, "degrees-plato"},
    { 47821, "specific-gravity"},
    { 47822, "european-brewing-convention"},
    { 0,   NULL}
/* Enumerated values 0-255 are reserved for definition by ASHRAE.
   Enumerated values 256-65535 may be used by others subject to
   the procedures and constraints described in Clause 23. */
};

static const value_string
BACnetErrorCode [] = {
    {   0, "other"},
    {   1, "authentication-failed"},
    {   2, "configuration-in-progress"},
    {   3, "device-busy"},
    {   4, "dynamic-creation-not-supported"},
    {   5, "file-access-denied"},
    {   6, "incompatible-security-levels"},
    {   7, "inconsistent-parameters"},
    {   8, "inconsistent-selection-criterion"},
    {   9, "invalid-data-type"},
    {  10, "invalid-file-access-method"},
    {  11, "invalid-file-start-position"},
    {  12, "invalid-operator-name"},
    {  13, "invalid-parameter-data-type"},
    {  14, "invalid-time-stamp"},
    {  15, "key-generation-error"},
    {  16, "missing-required-parameter"},
    {  17, "no-objects-of-specified-type"},
    {  18, "no-space-for-object"},
    {  19, "no-space-to-add-list-element"},
    {  20, "no-space-to-write-property"},
    {  21, "no-vt-sessions-available"},
    {  22, "property-is-not-a-list"},
    {  23, "object-deletion-not-permitted"},
    {  24, "object-identifier-already-exists"},
    {  25, "operational-problem"},
    {  26, "password-failure"},
    {  27, "read-access-denied"},
    {  28, "security-not-supported"},
    {  29, "service-request-denied"},
    {  30, "timeout"},
    {  31, "unknown-object"},
    {  32, "unknown-property"},
    {  33, "removed enumeration"},
    {  34, "unknown-vt-class"},
    {  35, "unknown-vt-session"},
    {  36, "unsupported-object-type"},
    {  37, "value-out-of-range"},
    {  38, "vt-session-already-closed"},
    {  39, "vt-session-termination-failure"},
    {  40, "write-access-denied"},
    {  41, "character-set-not-supported"},
    {  42, "invalid-array-index"},
    {  43, "cov-subscription-failed"},
    {  44, "not-cov-property"},
    {  45, "optional-functionality-not-supported"},
    {  46, "invalid-configuration-data"},
    {  47, "datatype-not-supported"},
    {  48, "duplicate-name"},
    {  49, "duplicate-object-id"},
    {  50, "property-is-not-an-array"},
    {  51, "abort - buffer - overflow" },
    {  52, "abort - invalid - apdu - in - this - state" },
    {  53, "abort - preempted - by - higher - priority - task" },
    {  54, "abort - segmentation - not - supported" },
    {  55, "abort - proprietary" },
    {  56, "abort - other" },
    {  57, "reject - invalid - tag" },
    {  58, "reject - network - down" },
    {  59, "reject - buffer - overflow" },
    {  60, "reject - inconsistent - parameters" },
    {  61, "reject - invalid - parameter - data - type" },
    {  62, "reject - invalid - tag" },
    {  63, "reject - missing - required - parameter" },
    {  64, "reject - parameter - out - of - range" },
    {  65, "reject - too - many - arguments" },
    {  66, "reject - undefined - enumeration" },
    {  67, "reject - unrecognized - service" },
    {  68, "reject - proprietary" },
    {  69, "reject - other" },
    {  70, "unknown - device" },
    {  71, "unknown - route" },
    {  72, "value - not - initialized" },
    {  73, "invalid-event-state"},
    {  74, "no-alarm-configured"},
    {  75, "log-buffer-full"},
    {  76, "logged-value-purged"},
    {  77, "no-property-specified"},
    {  78, "not-configured-for-triggered-logging"},
    {  79, "unknown-subscription"},
    {  80, "parameter-out-of-range"},
    {  81, "list-element-not-found"},
    {  82, "busy"},
    {  83, "communication-disabled"},
    {  84, "success"},
    {  85, "access-denied"},
    {  86, "bad-destination-address"},
    {  87, "bad-destination-device-id"},
    {  88, "bad-signature"},
    {  89, "bad-source-address"},
    {  90, "bad-timestamp"},
    {  91, "cannot-use-key"},
    {  92, "cannot-verify-message-id"},
    {  93, "correct-key-revision"},
    {  94, "destination-device-id-required"},
    {  95, "duplicate-message"},
    {  96, "encryption-not-configured"},
    {  97, "encryption-required"},
    {  98, "incorrect-key"},
    {  99, "invalid-key-data"},
    { 100, "key-update-in-progress"},
    { 101, "malformed-message"},
    { 102, "not-key-server"},
    { 103, "security-not-configured"},
    { 104, "source-security-required"},
    { 105, "too-many-keys"},
    { 106, "unknown-authentication-type"},
    { 107, "unknown-key"},
    { 108, "unknown-key-revision"},
    { 109, "unknown-source-message"},
    { 110, "not-router-to-dnet"},
    { 111, "router-busy"},
    { 112, "unknown-network-message"},
    { 113, "message-too-long"},
    { 114, "security-error"},
    { 115, "addressing-error"},
    { 116, "write-bdt-failed"},
    { 117, "read-bdt-failed"},
    { 118, "register-foreign-device-failed"},
    { 119, "read-fdt-failed"},
    { 120, "delete-fdt-entry-failed"},
    { 121, "distribute-broadcast-failed"},
    { 122, "unknown-file-size"},
    { 123, "abort-apdu-too-long"},
    { 124, "abort-application-exceeded-reply-time"},
    { 125, "abort-out-of-resources"},
    { 126, "abort-tsm-timeout"},
    { 127, "abort-window-size-out-of-range"},
    { 128, "file-full"},
    { 129, "inconsistent-configuration"},
    { 130, "inconsistent-object-type"},
    { 131, "internal-error"},
    { 132, "not-configured"},
    { 133, "out-of-memory"},
    { 134, "value-too-long"},
    { 135, "abort-insufficient-security"},
    { 136, "abort-security-error"},
    { 137, "duplicate-entry"},
    { 138, "invalid-value-in-this-state"},
    { 139, "invalid-operation-in-this-state"},
    { 140, "list-item-not-numbered"},
    { 141, "list-item-not-timestamped"},
    { 142, "invalid-data-encoding"},
    { 143, "bvlc-function-unknown"},
    { 144, "bvlc-proprietary-function-unknown"},
    { 145, "header-encoding-error"},
    { 146, "header-not-understood"},
    { 147, "message-incomplete"},
    { 148, "not-a-bacnet-sc-hub"},
    { 149, "payload-expected"},
    { 150, "unexpected-data"},
    { 151, "node-duplicate-vmac"},
    { 152, "http-unexpected-response-code"},
    { 153, "http-no-upgrade"},
    { 154, "http-resource-not-local"},
    { 155, "http-proxy-authentication-failed"},
    { 156, "http-response-timeout"},
    { 157, "http-response-syntax-error"},
    { 158, "http-response-value-error"},
    { 159, "http-response-missing-header"},
    { 160, "http-websocket-header-error"},
    { 161, "http-upgrade-required"},
    { 162, "http-upgrade-error"},
    { 163, "http-temporary-unavailable"},
    { 164, "http-not-a-server"},
    { 165, "http-error"},
    { 166, "websocket-scheme-not-supported"},
    { 167, "websocket-unknown-control-message"},
    { 168, "websocket-close-error"},
    { 169, "websocket-closed-by-peer"},
    { 170, "websocket-endpoint-leaves"},
    { 171, "websocket-protocol-error"},
    { 172, "websocket-data-not-accepted"},
    { 173, "websocket-closed-abnormally"},
    { 174, "websocket-data-inconsistent"},
    { 175, "websocket-data-against-policy"},
    { 176, "websocket-frame-too-long"},
    { 177, "websocket-extension-missing"},
    { 178, "websocket-request-unavailable"},
    { 179, "websocket-error"},
    { 180, "tls-client-certificate-error"},
    { 181, "tls-server-certificate-error"},
    { 182, "tls-client-authentication-failed"},
    { 183, "tls-server-authentication-failed"},
    { 184, "tls-client-certificate-expired"},
    { 185, "tls-server-certificate-expired"},
    { 186, "tls-client-certificate-revoked"},
    { 187, "tls-server-certificate-revoked"},
    { 188, "tls-error"},
    { 189, "dns-unavailable"},
    { 190, "dns-name-resolution-failed"},
    { 191, "dns-resolver-failure"},
    { 192, "dns-error"},
    { 193, "tcp-connect-timeout"},
    { 194, "tcp-connection-refused"},
    { 195, "tcp-closed-by-local"},
    { 196, "tcp-closed-other"},
    { 197, "tcp-error"},
    { 198, "ip-address-not-reachable"},
    { 199, "ip-error"},
    { 0,   NULL}
/* Enumerated values 0-255 are reserved for definition by ASHRAE.
   Enumerated values 256-65535 may be used by others subject to the
   procedures and constraints described in Clause 23. */
};

static const value_string
BACnetPropertyIdentifier [] = {
    {   0, "acked-transition"},
    {   1, "ack-required"},
    {   2, "action"},
    {   3, "action-text"},
    {   4, "active-text"},
    {   5, "active-vt-session"},
    {   6, "alarm-value"},
    {   7, "alarm-values"},
    {   8, "all"},
    {   9, "all-writes-successful"},
    {  10, "apdu-segment-timeout"},
    {  11, "apdu-timeout"},
    {  12, "application-software-version"},
    {  13, "archive"},
    {  14, "bias"},
    {  15, "change-of-state-count"},
    {  16, "change-of-state-time"},
    {  17, "notification-class"},
    {  18, "the property in this place was deleted"},
    {  19, "controlled-variable-reference"},
    {  20, "controlled-variable-units"},
    {  21, "controlled-variable-value"},
    {  22, "cov-increment"},
    {  23, "datelist"},
    {  24, "daylights-savings-status"},
    {  25, "deadband"},
    {  26, "derivative-constant"},
    {  27, "derivative-constant-units"},
    {  28, "description"},
    {  29, "description-of-halt"},
    {  30, "device-address-binding"},
    {  31, "device-type"},
    {  32, "effective-period"},
    {  33, "elapsed-active-time"},
    {  34, "error-limit"},
    {  35, "event-enable"},
    {  36, "event-state"},
    {  37, "event-type"},
    {  38, "exception-schedule"},
    {  39, "fault-values"},
    {  40, "feedback-value"},
    {  41, "file-access-method"},
    {  42, "file-size"},
    {  43, "file-type"},
    {  44, "firmware-revision"},
    {  45, "high-limit"},
    {  46, "inactive-text"},
    {  47, "in-process"},
    {  48, "instance-of"},
    {  49, "integral-constant"},
    {  50, "integral-constant-units"},
    {  51, "issue-confirmed-notifications"},
    {  52, "limit-enable"},
    {  53, "list-of-group-members"},
    {  54, "list-of-object-property-references"},
    {  55, "list-of-session-keys"},
    {  56, "local-date"},
    {  57, "local-time"},
    {  58, "location"},
    {  59, "low-limit"},
    {  60, "manipulated-variable-reference"},
    {  61, "maximum-output"},
    {  62, "max-apdu-length-accepted"},
    {  63, "max-info-frames"},
    {  64, "max-master"},
    {  65, "max-pres-value"},
    {  66, "minimum-off-time"},
    {  67, "minimum-on-time"},
    {  68, "minimum-output"},
    {  69, "min-pres-value"},
    {  70, "model-name"},
    {  71, "modification-date"},
    {  72, "notify-type"},
    {  73, "number-of-APDU-retries"},
    {  74, "number-of-states"},
    {  75, "object-identifier"},
    {  76, "object-list"},
    {  77, "object-name"},
    {  78, "object-property-reference"},
    {  79, "object-type"},
    {  80, "optional"},
    {  81, "out-of-service"},
    {  82, "output-units"},
    {  83, "event-parameters"},
    {  84, "polarity"},
    {  85, "present-value"},
    {  86, "priority"},
    {  87, "priority-array"},
    {  88, "priority-for-writing"},
    {  89, "process-identifier"},
    {  90, "program-change"},
    {  91, "program-location"},
    {  92, "program-state"},
    {  93, "proportional-constant"},
    {  94, "proportional-constant-units"},
    {  95, "protocol-conformance-class"},
    {  96, "protocol-object-types-supported"},
    {  97, "protocol-services-supported"},
    {  98, "protocol-version"},
    {  99, "read-only"},
    { 100, "reason-for-halt"},
    { 101, "recipient"},
    { 102, "recipient-list"},
    { 103, "reliability"},
    { 104, "relinquish-default"},
    { 105, "required"},
    { 106, "resolution"},
    { 107, "segmentation-supported"},
    { 108, "setpoint"},
    { 109, "setpoint-reference"},
    { 110, "state-text"},
    { 111, "status-flags"},
    { 112, "system-status"},
    { 113, "time-delay"},
    { 114, "time-of-active-time-reset"},
    { 115, "time-of-state-count-reset"},
    { 116, "time-synchronization-recipients"},
    { 117, "units"},
    { 118, "update-interval"},
    { 119, "utc-offset"},
    { 120, "vendor-identifier"},
    { 121, "vendor-name"},
    { 122, "vt-class-supported"},
    { 123, "weekly-schedule"},
    { 124, "attempted-samples"},
    { 125, "average-value"},
    { 126, "buffer-size"},
    { 127, "client-cov-increment"},
    { 128, "cov-resubscription-interval"},
    { 129, "current-notify-time"},
    { 130, "event-time-stamp"},
    { 131, "log-buffer"},
    { 132, "log-device-object-property"},
    { 133, "enable"}, /* per ANSI/ASHRAE 135-2004 addendum B */
    { 134, "log-interval"},
    { 135, "maximum-value"},
    { 136, "minimum-value"},
    { 137, "notification-threshold"},
    { 138, "previous-notify-time"},
    { 139, "protocol-revision"},
    { 140, "records-since-notification"},
    { 141, "record-count"},
    { 142, "start-time"},
    { 143, "stop-time"},
    { 144, "stop-when-full"},
    { 145, "total-record-count"},
    { 146, "valid-samples"},
    { 147, "window-interval"},
    { 148, "window-samples"},
    { 149, "maximum-value-time-stamp"},
    { 150, "minimum-value-time-stamp"},
    { 151, "variance-value"},
    { 152, "active-cov-subscriptions"},
    { 153, "backup-failure-timeout"},
    { 154, "configuration-files"},
    { 155, "database-revision"},
    { 156, "direct-reading"},
    { 157, "last-restore-time"},
    { 158, "maintenance-required"},
    { 159, "member-of"},
    { 160, "mode"},
    { 161, "operation-expected"},
    { 162, "setting"},
    { 163, "silenced"},
    { 164, "tracking-value"},
    { 165, "zone-members"},
    { 166, "life-safety-alarm-values"},
    { 167, "max-segments-accepted"},
    { 168, "profile-name"},
    { 169, "auto-slave-discovery"},
    { 170, "manual-slave-address-binding"},
    { 171, "slave-address-binding"},
    { 172, "slave-proxy-enable"},
    { 173, "last-notify-record"},     /* bug 4117 */
    { 174, "schedule-default"},
    { 175, "accepted-modes"},
    { 176, "adjust-value"},
    { 177, "count"},
    { 178, "count-before-change"},
    { 179, "count-change-time"},
    { 180, "cov-period"},
    { 181, "input-reference"},
    { 182, "limit-monitoring-interval"},
    { 183, "logging-object"},
    { 184, "logging-record"},
    { 185, "prescale"},
    { 186, "pulse-rate"},
    { 187, "scale"},
    { 188, "scale-factor"},
    { 189, "update-time"},
    { 190, "value-before-change"},
    { 191, "value-set"},
    { 192, "value-change-time"},
    { 193, "align-intervals"},
    { 194, "group-member-names"},
    { 195, "interval-offset"},
    { 196, "last-restart-reason"},
    { 197, "logging-type"},
    { 198, "member-status-flags"},
    { 199, "notification-period"},
    { 200, "previous-notify-record"},
    { 201, "requested-update-interval"},
    { 202, "restart-notification-recipients"},
    { 203, "time-of-device-restart"},
    { 204, "time-synchronization-interval"},
    { 205, "trigger"},
    { 206, "UTC-time-synchronization-recipients"},
    { 207, "node-subtype"},
    { 208, "node-type"},
    { 209, "structured-object-list"},
    { 210, "subordinate-annotations"},
    { 211, "subordinate-list"},
    { 212, "actual-shed-level"},
    { 213, "duty-window"},
    { 214, "expected-shed-level"},
    { 215, "full-duty-baseline"},
    { 216, "node-subtype"},
    { 217, "node-type"},
    { 218, "requested-shed-level"},
    { 219, "shed-duration"},
    { 220, "shed-level-descriptions"},
    { 221, "shed-levels"},
    { 222, "state-description"},
    /* enumeration values 223-225 are unassigned */
    { 226, "door-alarm-state"},
    { 227, "door-extended-pulse-time"},
    { 228, "door-members"},
    { 229, "door-open-too-long-time"},
    { 230, "door-pulse-time"},
    { 231, "door-status"},
    { 232, "door-unlock-delay-time"},
    { 233, "lock-status"},
    { 234, "masked-alarm-values"},
    { 235, "secured-status"},
    /* enumeration values 236-243 are unassigned */
    { 244, "absentee-limit"},     /* added with addenda 135-2008j */
    { 245, "access-alarm-events"},
    { 246, "access-doors"},
    { 247, "access-event"},
    { 248, "access-event-authentication-factor"},
    { 249, "access-event-credential"},
    { 250, "access-event-time"},
    { 251, "access-transaction-events"},
    { 252, "accompaniment"},
    { 253, "accompaniment-time"},
    { 254, "activation-time"},
    { 255, "active-authentication-policy"},
    { 256, "assigned-access-rights"},
    { 257, "authentication-factors"},
    { 258, "authentication-policy-list"},
    { 259, "authentication-policy-names"},
    { 260, "authentication-status"},
    { 261, "authorization-mode"},
    { 262, "belongs-to"},
    { 263, "credential-disable"},
    { 264, "credential-status"},
    { 265, "credentials"},
    { 266, "credentials-in-zone"},
    { 267, "days-remaining"},
    { 268, "entry-points"},
    { 269, "exit-points"},
    { 270, "expiration-time"},
    { 271, "extended-time-enable"},
    { 272, "failed-attempt-events"},
    { 273, "failed-attempts"},
    { 274, "failed-attempts-time"},
    { 275, "last-access-event"},
    { 276, "last-access-point"},
    { 277, "last-credential-added"},
    { 278, "last-credential-added-time"},
    { 279, "last-credential-removed"},
    { 280, "last-credential-removed-time"},
    { 281, "last-use-time"},
    { 282, "lockout"},
    { 283, "lockout-relinquish-time"},
    { 284, "master-exemption"},
    { 285, "max-failed-attempts"},
    { 286, "members"},
    { 287, "muster-point"},
    { 288, "negative-access-rules"},
    { 289, "number-of-authentication-policies"},
    { 290, "occupancy-count"},
    { 291, "occupancy-count-adjust"},
    { 292, "occupancy-count-enable"},
    { 293, "occupancy-exemption"},
    { 294, "occupancy-lower-limit"},
    { 295, "occupancy-lower-limit-enforced"},
    { 296, "occupancy-state"},
    { 297, "occupancy-upper-limit"},
    { 298, "occupancy-upper-limit-enforced"},
    { 299, "passback-exemption"},
    { 300, "passback-mode"},
    { 301, "passback-timeout"},
    { 302, "positive-access-rules"},
    { 303, "reason-for-disable"},
    { 304, "supported-formats"},
    { 305, "supported-format-classes"},
    { 306, "threat-authority"},
    { 307, "threat-level"},
    { 308, "trace-flag"},
    { 309, "transaction-notification-class"},
    { 310, "user-external-identifier"},
    { 311, "user-information-reference"},
    /* enumeration values 312-316 are unassigned */
    { 317, "user-name"},
    { 318, "user-type"},
    { 319, "uses-remaining"},
    { 320, "zone-from"},
    { 321, "zone-to"},
    { 322, "access-event-tag"},
    { 323, "global-identifier"},
    /* enumeration values 324-325 reserved for future addenda */
    { 326, "verification-time"},
    { 327, "base-device-security-policy"},
    { 328, "distribution-key-revision"},
    { 329, "do-not-hide"},
    { 330, "key-sets"},
    { 331, "last-key-server"},
    { 332, "network-access-security-policies"},
    { 333, "packet-reorder-time"},
    { 334, "security-pdu-timeout"},
    { 335, "security-time-window"},
    { 336, "supported-security-algorithms"},
    { 337, "update-key-set-timeout"},
    { 338, "backup-and-restore-state"},
    { 339, "backup-preparation-time"},
    { 340, "restore-completion-time"},
    { 341, "restore-preparation-time"},
    { 342, "bit-mask"},       /* addenda 135-2008w */
    { 343, "bit-text"},
    { 344, "is-utc"},
    { 345, "group-members"},
    { 346, "group-member-names"},
    { 347, "member-status-flags"},
    { 348, "requested-update-interval"},
    { 349, "covu-period"},
    { 350, "covu-recipients"},
    { 351, "event-message-texts"},
    { 352, "event-message-texts-config"},
    { 353, "event-detection-enable"},
    { 354, "event-algorithm-inhibit"},
    { 355, "event-algorithm-inhibit-ref"},
    { 356, "time-delay-normal"},
    { 357, "reliability-evaluation-inhibit"},
    { 358, "fault-parameters"},
    { 359, "fault-type"},
    { 360, "local-forwarding-only"},
    { 361, "process-identifier-filter"},
    { 362, "subscribed-recipients"},
    { 363, "port-filter"},
    { 364, "authorization-exemptions"},
    { 365, "allow-group-delay-inhibit"},
    { 366, "channel-number"},
    { 367, "control-groups"},
    { 368, "execution-delay"},
    { 369, "last-priority"},
    { 370, "write-status"},
    { 371, "property-list"},
    { 372, "serial-number"},
    { 373, "blink-warn-enable"},
    { 374, "default-fade-time"},
    { 375, "default-ramp-rate"},
    { 376, "default-step-increment"},
    { 377, "egress-time"},
    { 378, "in-progress"},
    { 379, "instantaneous-power"},
    { 380, "lighting-command"},
    { 381, "lighting-command-default-priority"},
    { 382, "max-actual-value"},
    { 383, "min-actual-value"},
    { 384, "power"},
    { 385, "transition"},
    { 386, "egress-active"},
    { 387, "interface-value"},
    { 388, "fault-high-limit"},
    { 389, "fault-low-limit"},
    { 390, "low-diff-limit"},
    { 391, "strike-count"},
    { 392, "time-of-strike-count-reset"},
    { 393, "default-timeout"},
    { 394, "initial-timeout"},
    { 395, "last-state-change"},
    { 396, "state-change-values"},
    { 397, "timer-running"},
    { 398, "timer-state"},
    { 399, "apdu-length"},
    { 400, "bacnet-ip-address"},
    { 401, "bacnet-ip-default-gateway"},
    { 402, "bacnet-ip-dhcp-enable"},
    { 403, "bacnet-ip-dhcp-lease-time"},
    { 404, "bacnet-ip-dhcp-lease-time-remaining"},
    { 405, "bacnet-ip-dhcp-server"},
    { 406, "bacnet-ip-dns-server"},
    { 407, "bacnet-ip-global-address"},
    { 408, "bacnet-ip-mode"},
    { 409, "bacnet-ip-multicast-address"},
    { 410, "bacnet-ip-nat-traversal"},
    { 411, "bacnet-ip-subnet-mask"},
    { 412, "bacnet-ip-udp-port"},
    { 413, "bbmd-accept-fd-registrations"},
    { 414, "bbmd-broadcast-distribution-table"},
    { 415, "bbmd-foreign-device-table"},
    { 416, "changes-pending"},
    { 417, "command"},
    { 418, "fd-bbmd-address"},
    { 419, "fd-subscription-lifetime"},
    { 420, "link-speed"},
    { 421, "link-speeds"},
    { 422, "link-speed-autonegotiate"},
    { 423, "mac-address"},
    { 424, "network-interface-name"},
    { 425, "network-number"},
    { 426, "network-number-quality"},
    { 427, "network-type"},
    { 428, "routing-table"},
    { 429, "virtual-mac-address-table"},
    { 430, "command-time-array"},
    { 431, "current-command-priority"},
    { 432, "last-command-time"},
    { 433, "value-source"},
    { 434, "value-source-array"},
    { 435, "bacnet-ipv6-mode"},
    { 436, "ipv6-address"},
    { 437, "ipv6-prefix-length"},
    { 438, "bacnet-ipv6-udp-port"},
    { 439, "ipv6-default-gateway"},
    { 440, "bacnet-ipv6-multicast-address"},
    { 441, "ipv6-dns-server"},
    { 442, "ipv6-auto-addressing-enable"},
    { 443, "ipv6-dhcp-lease-time"},
    { 444, "ipv6-dhcp-lease-time-remaining"},
    { 445, "ipv6-dhcp-server"},
    { 446, "ipv6-zone-index"},
    { 447, "assigned-landing-calls"},
    { 448, "car-assigned-direction"},
    { 449, "car-door-command"},
    { 450, "car-door-status"},
    { 451, "car-door-text"},
    { 452, "car-door-zone"},
    { 453, "car-drive-status"},
    { 454, "car-load"},
    { 455, "car-load-units"},
    { 456, "car-mode"},
    { 457, "car-moving-direction"},
    { 458, "car-position"},
    { 459, "elevator-group"},
    { 460, "energy-meter"},
    { 461, "energy-meter-ref"},
    { 462, "escalator-mode"},
    { 463, "fault-signals"},
    { 464, "floor-text"},
    { 465, "group-id"},
    { 466, "enumeration value 466 is unassigned"},
    { 467, "group-mode"},
    { 468, "higher-deck"},
    { 469, "installation-id"},
    { 470, "landing-calls"},
    { 471, "landing-call-control"},
    { 472, "landing-door-status"},
    { 473, "lower-deck"},
    { 474, "machine-room-id"},
    { 475, "making-car-call"},
    { 476, "next-stopping-floor"},
    { 477, "operation-direction"},
    { 478, "passenger-alarm"},
    { 479, "power-mode"},
    { 480, "registered-car-call"},
    { 481, "active-cov-multiple-subscriptions"},
    { 482, "protocol-level"},
    { 483, "reference-port"},
    { 484, "deployed-profile-location"},
    { 485, "profile-location"},
    { 486, "tags"},
    { 487, "subordinate-node-types"},
    { 488, "subordinate-tags"},
    { 489, "subordinate-relationship"},
    { 490, "default-subordinate-relationship"},
    { 491, "represents"},
    { 492, "default-present-value"},
    { 493, "present-stage"},
    { 494, "stages"},
    { 495, "stage-names"},
    { 496, "target-references"},
    { 497, "audit-source-reporter"},
    { 498, "audit-level"},
    { 499, "audit-notification-recipient"},
    { 500, "audit-priority-filter"},
    { 501, "auditable-operations"},
    { 502, "delete-on-forward"},
    { 503, "maximum-send-delay"},
    { 504, "monitored-objects"},
    { 505, "send-now"},
    { 506, "floor-number"},
    { 507, "device-uuid"},
    { 508, "additional-reference-ports"},
    { 509, "certificate-signing-request-file"},
    { 510, "command-validation-result"},
    { 511, "issuer-certificate-files"},
    { 4194304, "max-bvlc-length-accepted"},
    { 4194305, "max-npdu-length-accepted"},
    { 4194306, "operational-certificate-file"},
    { 4194307, "current-health"},
    { 4194308, "sc-connect-wait-timeout"},
    { 4194309, "sc-direct-connect-accept-enable"},
    { 4194310, "sc-direct-connect-accept-uris"},
    { 4194311, "ssc-direct-connect-binding"},
    { 4194312, "sc-direct-connect-connection-status"},
    { 4194313, "sc-direct-connect-initiate-enable"},
    { 4194314, "sc-disconnect-wait-timeout"},
    { 4194315, "sc-failed-connection-request"},
    { 4194316, "sc-failover-hub-connection-status"},
    { 4194317, "sc-failover-hub-uri"},
    { 4194318, "sc-hub-connector-state"},
    { 4194319, "sc-hub-function-accept-uris"},
    { 4194320, "sc-hub-function-binding"},
    { 4194321, "sc-hub-function-connection-status"},
    { 4194322, "sc-hub-function-enable"},
    { 4194323, "sc-heartbeat-timeout"},
    { 4194324, "sc-primary-hub-connection-status"},
    { 4194325, "sc-primary-hub-uri"},
    { 4194326, "sc-maximum-reconnect-time"},
    { 4194327, "sc-minimum-reconnect-time"},
    { 4194328, "color-override"},
    { 4194329, "color-reference"},
    { 4194330, "default-color"},
    { 4194331, "default-color-temperature"},
    { 4194332, "override-color-reference"},
    { 4194334, "color-command"},
    { 4194335, "high_end_trim"},
    { 4194336, "low_end_trim"},
    { 4194337, "trim_fade_time"},
    { 0,   NULL}
/* Enumerated values 0-511 are reserved for definition by ASHRAE.
   Enumerated values 512-4194303 may be used by others subject to
   the procedures and constraints described in Clause 23. */
};

static const value_string
BACnetBinaryPV [] = {
    { 0, "inactive"},
    { 1, "active"},
    { 0, NULL}
};


#define ANSI_X3_4      0 /* ANSI X3.4, a/k/a "ASCII"; full UTF-8 since 2010 */
                         /* See, for example, ANSI/ASHRAE Addendum k to ANSI/ASHRAE Standard 135-2008 */
                         /* XXX - I've seen captures using this for ISO 8859-1 */
#define IBM_MS_DBCS    1 /* "IBM/Microsoft DBCS"; was there only one such DBCS? */
#define JIS_C_6226     2 /* JIS C 6226 */
#define ISO_10646_UCS4 3 /* ISO 10646 (UCS-4) - 4-byte Unicode */
#define ISO_10646_UCS2 4 /* ISO 10646 (UCS-2) - 2-byte Unicode Basic Multilingual Plane (not UTF-16, presumably) */
#define ISO_8859_1     5 /* ISO 8859-1 */
static const value_string
BACnetCharacterSet [] = {
    { ANSI_X3_4,      "ANSI X3.4 / UTF-8 (since 2010)"},
    { IBM_MS_DBCS,    "IBM/Microsoft DBCS"},
    { JIS_C_6226,     "JIS C 6226"},
    { ISO_10646_UCS4, "ISO 10646 (UCS-4)"},
    { ISO_10646_UCS2, "ISO 10646 (UCS-2)"},
    { ISO_8859_1,     "ISO 8859-1"},
    { 0,     NULL}
};

static const value_string
BACnetStatusFlags [] = {
    { 0, "in-alarm"},
    { 1, "fault"},
    { 2, "overridden"},
    { 3, "out-of-service"},
    { 0, NULL}
};

static const value_string
BACnetMessagePriority [] = {
    { 0, "normal"},
    { 1, "urgent"},
    { 0, NULL}
};

static const value_string
BACnetAcknowledgementFilter [] = {
    { 0, "all"},
    { 1, "acked"},
    { 2, "not-acked"},
    { 0, NULL}
};

static const value_string
BACnetResultFlags [] = {
    { 0, "firstitem"},
    { 1, "lastitem"},
    { 2, "moreitems"},
    { 0, NULL}
};

static const value_string
BACnetRelationSpecifier [] = {
    { 0, "equal"},
    { 1, "not-equal"},
    { 2, "less-than"},
    { 3, "greater-than"},
    { 4, "less-than-or-equal"},
    { 5, "greater-than-or-equal"},
    { 0, NULL}
};

static const value_string
BACnetSelectionLogic [] = {
    { 0, "and"},
    { 1, "or"},
    { 2, "all"},
    { 0, NULL}
};

static const value_string
BACnetEventStateFilter [] = {
    { 0, "offnormal"},
    { 1, "fault"},
    { 2, "normal"},
    { 3, "all"},
    { 4, "active"},
    { 0, NULL}
};

static const value_string
BACnetEventTransitionBits [] = {
    { 0, "to-offnormal"},
    { 1, "to-fault"},
    { 2, "to-normal"},
    { 0, NULL}
};

static const value_string
BACnetSegmentation [] = {
    { 0, "segmented-both"},
    { 1, "segmented-transmit"},
    { 2, "segmented-receive"},
    { 3, "no-segmentation"},
    { 0, NULL}
};

static const value_string
BACnetSilencedState [] = {
    { 0, "unsilenced"},
    { 1, "audible-silenced"},
    { 2, "visible-silenced"},
    { 3, "all-silenced"},
    { 0, NULL}
};

static const value_string
BACnetDeviceStatus [] = {
    { 0, "operational"},
    { 1, "operational-read-only"},
    { 2, "download-required"},
    { 3, "download-in-progress"},
    { 4, "non-operational"},
    { 5, "backup-in-progress"},
    { 0, NULL}
};

static const value_string
BACnetEnableDisable [] = {
    { 0, "enable"},
    { 1, "disable"},
    { 2, "disable-initiation"},
    { 0, NULL}
};

static const value_string
months [] = {
    {   1, "January" },
    {   2, "February" },
    {   3, "March" },
    {   4, "April" },
    {   5, "May" },
    {   6, "June" },
    {   7, "July" },
    {   8, "August" },
    {   9, "September" },
    {  10, "October" },
    {  11, "November" },
    {  12, "December" },
    {  13, "odd month" },
    {  14, "even month" },
    { 255, "any month" },
    { 0,   NULL }
};

static const value_string
weekofmonth [] = {
    {   1, "days numbered 1-7" },
    {   2, "days numbered 8-14" },
    {   3, "days numbered 15-21" },
    {   4, "days numbered 22-28" },
    {   5, "days numbered 29-31" },
    {   6, "last 7 days of this month" },
    {   7, "any of 7 days prior to last 7 days of this month" },
    {   8, "any of 7 days prior to last 14 days of this month" },
    {   9, "any of 7 days prior to last 21 days of this month" },
    { 255, "any week of this month" },
    { 0,   NULL }
};

/* note: notification class object recipient-list uses
   different day-of-week enum */
static const value_string
day_of_week [] = {
    {   1, "Monday" },
    {   2, "Tuesday" },
    {   3, "Wednesday" },
    {   4, "Thursday" },
    {   5, "Friday" },
    {   6, "Saturday" },
    {   7, "Sunday" },
    { 255, "any day of week" },
    { 0,   NULL }
};

static const value_string
BACnetErrorClass [] = {
    { 0, "device" },
    { 1, "object" },
    { 2, "property" },
    { 3, "resources" },
    { 4, "security" },
    { 5, "services" },
    { 6, "vt" },
    { 7, "communication" },
    { 0, NULL }
/* Enumerated values 0-63 are reserved for definition by ASHRAE.
   Enumerated values64-65535 may be used by others subject to
   the procedures and constraints described in Clause 23. */
};

static const value_string
BACnetVTClass [] = {
    { 0, "default-terminal" },
    { 1, "ansi-x3-64" },
    { 2, "dec-vt52" },
    { 3, "dec-vt100" },
    { 4, "dec-vt200" },
    { 5, "hp-700-94" },
    { 6, "ibm-3130" },
    { 0, NULL }
};

static const value_string
BACnetEventType [] = {
    {  0, "change-of-bitstring" },
    {  1, "change-of-state" },
    {  2, "change-of-value" },
    {  3, "command-failure" },
    {  4, "floating-limit" },
    {  5, "out-of-range" },
    {  6, "complex-event-type" },
    {  7, "(deprecated)buffer-ready" },
    {  8, "change-of-life-safety" },
    {  9, "extended" },
    { 10, "buffer-ready" },
    { 11, "unsigned-range" },
    { 13, "access-event" },
    { 14, "double-out-of-range"},     /* added with addenda 135-2008w */
    { 15, "signed-out-of-range"},
    { 16, "unsigned-out-of-range"},
    { 17, "change-of-characterstring"},
    { 18, "change-of-status-flags"},
    { 19, "change-of-reliability" },
    { 20, "none" },
    { 21, "change-of-discrete-value"},
    { 22, "change-of-timer"},
    { 0,  NULL }
/* Enumerated values 0-63 are reserved for definition by ASHRAE.
   Enumerated values 64-65535 may be used by others subject to
   the procedures and constraints described in Clause 23.
   It is expected that these enumerated values will correspond
   to the use of the complex-event-type CHOICE [6] of the
   BACnetNotificationParameters production. */
};

static const value_string
BACnetEventState [] = {
    { 0, "normal" },
    { 1, "fault" },
    { 2, "offnormal" },
    { 3, "high-limit" },
    { 4, "low-limit" },
    { 5, "life-safety-alarm" },
    { 0, NULL }
/* Enumerated values 0-63 are reserved for definition by ASHRAE.
   Enumerated values 64-65535 may be used by others subject to
   the procedures and constraints described in Clause 23.  */
};

static const value_string
BACnetLogStatus [] = {
    { 0, "log-disabled" },
    { 1, "buffer-purged" },
    { 2, "log-interrupted"},
    { 0, NULL }
};

static const value_string
BACnetMaintenance [] = {
    { 0, "none" },
    { 1, "periodic-test" },
    { 2, "need-service-operational" },
    { 3, "need-service-inoperative" },
    { 0, NULL }
};

static const value_string
BACnetNotifyType [] = {
    { 0, "alarm" },
    { 1, "event" },
    { 2, "ack-notification" },
    { 0, NULL }
};

static const value_string
BACnetServicesSupported [] = {
    {  0, "acknowledgeAlarm"},
    {  1, "confirmedCOVNotification"},
    {  2, "confirmedEventNotification"},
    {  3, "getAlarmSummary"},
    {  4, "getEnrollmentSummary"},
    {  5, "subscribeCOV"},
    {  6, "atomicReadFile"},
    {  7, "atomicWriteFile"},
    {  8, "addListElement"},
    {  9, "removeListElement"},
    { 10, "createObject"},
    { 11, "deleteObject"},
    { 12, "readProperty"},
    { 13, "readPropertyConditional"},
    { 14, "readPropertyMultiple"},
    { 15, "writeProperty"},
    { 16, "writePropertyMultiple"},
    { 17, "deviceCommunicationControl"},
    { 18, "confirmedPrivateTransfer"},
    { 19, "confirmedTextMessage"},
    { 20, "reinitializeDevice"},
    { 21, "vtOpen"},
    { 22, "vtClose"},
    { 23, "vtData"},
    { 24, "authenticate"},
    { 25, "requestKey"},
    { 26, "i-Am"},
    { 27, "i-Have"},
    { 28, "unconfirmedCOVNotification"},
    { 29, "unconfirmedEventNotification"},
    { 30, "unconfirmedPrivateTransfer"},
    { 31, "unconfirmedTextMessage"},
    { 32, "timeSynchronization"},
    { 33, "who-Has"},
    { 34, "who-Is"},
    { 35, "readRange"},
    { 36, "utcTimeSynchronization"},
    { 37, "lifeSafetyOperation"},
    { 38, "subscribeCOVProperty"},
    { 39, "getEventInformation"},
    { 40, "write-group"},
    { 41, "subscribe-cov-property-multiple"},
    { 42, "confirmed-cov-notification-multiple"},
    { 43, "unconfirmed-cov-notification-multiple"},
    { 44, "confirmed-audit-notification" },
    { 45, "audit-log-query" },
    { 46, "unconfirmed-audit-notification" },
    { 0,  NULL}
};

static const value_string
BACnetPropertyStates [] = {
    {  0, "boolean-value"},
    {  1, "binary-value"},
    {  2, "event-type"},
    {  3, "polarity"},
    {  4, "program-change"},
    {  5, "program-state"},
    {  6, "reason-for-halt"},
    {  7, "reliability"},
    {  8, "state"},
    {  9, "system-status"},
    { 10, "units"},
    { 11, "unsigned-value"},
    { 12, "life-safety-mode"},
    { 13, "life-safety-state"},
    { 14, "restart-reason"},
    { 15, "door-alarm-state"},
    { 16, "action"},
    { 17, "door-secured-status"},
    { 18, "door-status"},
    { 19, "door-value"},
    { 20, "file-access-method"},
    { 21, "lock-status"},
    { 22, "life-safety-operation"},
    { 23, "maintenance"},
    { 24, "node-type"},
    { 25, "notify-type"},
    { 26, "security-level"},
    { 27, "shed-state"},
    { 28, "silenced-state"},
    { 29, "unknown-29"},
    { 30, "access-event"},
    { 31, "zone-occupancy-state"},
    { 32, "access-credential-disable-reason"},
    { 33, "access-credential-disable"},
    { 34, "authentication-status"},
    { 35, "unknown-35"},
    { 36, "backup-state"},
    { 37, "write-status"},
    { 38, "lighting-in-progress"},
    { 39, "lighting-operation"},
    { 40, "lighting-transition"},
    { 41, "signed-value"},
    { 42, "unknown-42"},
    { 43, "timer-state"},
    { 44, "timer-transition"},
    { 45, "bacnet-ip-mode"},
    { 46, "network-port-command"},
    { 47, "network-type"},
    { 48, "network-number-quality"},
    { 49, "escalator-operation-direction"},
    { 50, "escalator-fault"},
    { 51, "escalator-mode"},
    { 52, "lift-car-direction"},
    { 53, "lift-car-door-command"},
    { 54, "lift-car-drive-status"},
    { 55, "lift-car-mode"},
    { 56, "lift-group-mode"},
    { 57, "lift-fault"},
    { 58, "protocol-level"},
    { 59, "audit-level"},
    { 60, "audit-operation"},
    { 63, "extended-value"},
    {256, "-- example-one"},
    {257, "-- example-two"},
    {258, "sc-connection-state"},
    {258, "sc-hub-connecto-state"},
    { 0, NULL}
/* Tag values 0-63 are reserved for definition by ASHRAE.
   Tag values of 64-254 may be used by others to accommodate
   vendor specific properties that have discrete or enumerated values,
   subject to the constraints described in Clause 23. */
};

static const value_string
BACnetProgramError [] = {
    { 0, "normal"},
    { 1, "load-failed"},
    { 2, "internal"},
    { 3, "program"},
    { 4, "other"},
    { 0, NULL}
/* Enumerated values 0-63 are reserved for definition by ASHRAE.
   Enumerated values 64-65535 may be used by others subject to
   the procedures and constraints described in Clause 23. */
};

static const value_string
BACnetProgramRequest [] = {
    { 0, "ready"},
    { 1, "load"},
    { 2, "run"},
    { 3, "halt"},
    { 4, "restart"},
    { 4, "unload"},
    { 0, NULL}
};

static const value_string
BACnetProgramState [] = {
    { 0, "idle"},
    { 1, "loading"},
    { 2, "running"},
    { 3, "waiting"},
    { 4, "halted"},
    { 4, "unloading"},
    { 0, NULL}
};

static const value_string
BACnetReinitializedStateOfDevice [] = {
    { 0, "coldstart"},
    { 1, "warmstart"},
    { 2, "start-backup"},
    { 3, "end-backup"},
    { 4, "start-restore"},
    { 5, "end-restore"},
    { 6, "abort-restore"},
    { 7, "activate-changes"},
    { 0, NULL}
};

static const value_string
BACnetPolarity [] = {
    { 0, "normal"},
    { 1, "reverse"},
    { 0, NULL}
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
BACnetFaultType[] = {
  { 0, "none" },
  { 1, "fault-characterstring" },
  { 2, "fault-extended" },
  { 3, "fault-life-safety" },
  { 4, "fault-state" },
  { 5, "fault-status-flags" },
  { 6, "fault-out-of-range" },
  { 7, "fault-listed" },
  { 0, NULL }
};

static const value_string
BACnetNodeType [] = {
    { 0, "unknown" },
    { 1, "system" },
    { 2, "network" },
    { 3, "device" },
    { 4, "organizational" },
    { 5, "area" },
    { 6, "equipment" },
    { 7, "point" },
    { 8, "collection" },
    { 9, "property" },
    { 10, "functional" },
    { 11, "other" },
    { 12, "subsystem" },
    { 13, "building" },
    { 14, "floor" },
    { 15, "section" },
    { 16, "module" },
    { 17, "tree" },
    { 18, "member" },
    { 19, "protocol" },
    { 20, "room" },
    { 21, "zone" },
    { 0, NULL }
};

static const value_string
BACnetLoggingType [] = {
    { 0, "polled" },
    { 1, "cov" },
    { 2, "triggered" },
    { 0, NULL }
};

static const value_string
BACnetDoorStatus [] = {
    { 0, "closed" },
    { 1, "opened" },
    { 2, "unknown" },
    { 3, "door-fault" },
    { 4, "unused" },
    { 5, "none" },
    { 6, "closing" },
    { 7, "opening" },
    { 8, "safety-locked" },
    { 9, "limited-opened" },
    { 0, NULL }
};

static const value_string
BACnetDoorValue[] = {
  { 0, "lock" },
  { 1, "unlock" },
  { 2, "pulse-unlock" },
  { 3, "extended-pulse-unlock" },
  { 0, NULL }
};

static const value_string
BACnetLockStatus [] = {
    { 0, "locked" },
    { 1, "unlocked" },
    { 2, "fault" },
    { 3, "unknown" },
    { 0, NULL }
};

static const value_string
BACnetDoorSecuredStatus [] = {
    { 0, "secured" },
    { 1, "unsecured" },
    { 2, "unknown" },
    { 0, NULL }
};

static const value_string
BACnetDoorAlarmState [] = {
    { 0, "normal" },
    { 1, "alarm" },
    { 2, "door-open-too-long" },
    { 3, "forced-open" },
    { 4, "tamper" },
    { 5, "door-fault" },
    { 6, "lock-down" },
    { 7, "free-access" },
    { 8, "egress-open" },
    { 0, NULL }
};

static const value_string
BACnetSecurityPolicy [] = {
    { 0, "plain-non-trusted"},
    { 1, "plain-trusted"},
    { 2, "signed-trusted"},
    { 3, "encrypted-trusted"},
    { 0, NULL }
};

static const value_string
BACnetAccumulatorStatus [] = {
    { 0, "normal" },
    { 1, "starting" },
    { 2, "recovered" },
    { 3, "abnormal" },
    { 4, "failed" },
    { 0, NULL }
};

static const value_string
BACnetAuditLevel [] = {
    { 0, "none" },
    { 1, "audit-all" },
    { 2, "audit-config" },
    { 3, "default" },
    { 0, NULL }
};

static const value_string
BACnetAuditPriorityFilter [] = {
    { 1, "manual-life-safety" },
    { 2, "automatic-life-safety" },
    { 3, "priority-3" },
    { 4, "priority-4" },
    { 5, "critical-equipment-controls" },
    { 6, "minimum-on-off" },
    { 7, "priority-7" },
    { 8, "manual-operator" },
    { 9, "priority-9" },
    { 10, "priority-10" },
    { 11, "priority-11" },
    { 12, "priority-12" },
    { 13, "priority-13" },
    { 14, "priority-14" },
    { 15, "priority-15" },
    { 16, "priority-16" },
    { 0, NULL }
};

static const value_string
BACnetAuditOperation [] = {
    { 0, "read" },
    { 1, "write" },
    { 2, "create" },
    { 3, "delete" },
    { 4, "life-safety" },
    { 5, "acknowledge-alarm" },
    { 6, "device-disable-comm" },
    { 7, "device-enable-comm" },
    { 8, "device-reset" },
    { 9, "device-backup" },
    { 10, "device-restore" },
    { 11, "subscription" },
    { 12, "notification" },
    { 13, "auditing-failure" },
    { 14, "network-changes" },
    { 15, "general" },
    { 0, NULL }
};

static const value_string
BACnetSuccessFilter [] = {
    { 0, "all" },
    { 1, "successes-only" },
    { 2, "failures-only" },
    { 0, NULL }
};


/* These values are (manually) transferred from
 * http://www.bacnet.org/VendorID/BACnet Vendor IDs.htm
 * Version: "As of January 12, 2022"
 */

static const value_string
BACnetVendorIdentifiers [] = {
    {    0, "ASHRAE" },
    {    1, "NIST" },
    {    2, "The Trane Company" },
    {    3, "McQuay International" },
    {    4, "PolarSoft" },
    {    5, "Johnson Controls, Inc." },
    {    6, "American Auto-Matrix" },
    {    7, "Siemens Schweiz AG (Formerly: Landis & Staefa Division Europe)" },
    {    8, "Delta Controls" },
    {    9, "Siemens Schweiz AG" },
    {   10, "Schneider Electric" },
    {   11, "TAC" },
    {   12, "Orion Analysis Corporation" },
    {   13, "Teletrol Systems Inc." },
    {   14, "Cimetrics Technology" },
    {   15, "Cornell University" },
    {   16, "United Technologies Carrier" },
    {   17, "Honeywell Inc." },
    {   18, "Alerton / Honeywell" },
    {   19, "TAC AB" },
    {   20, "Hewlett-Packard Company" },
    {   21, "Dorsette's Inc." },
    {   22, "Siemens Schweiz AG (Formerly: Cerberus AG)" },
    {   23, "York Controls Group" },
    {   24, "Automated Logic Corporation" },
    {   25, "CSI Control Systems International" },
    {   26, "Phoenix Controls Corporation" },
    {   27, "Innovex Technologies, Inc." },
    {   28, "KMC Controls, Inc." },
    {   29, "Xn Technologies, Inc." },
    {   30, "Hyundai Information Technology Co., Ltd." },
    {   31, "Tokimec Inc." },
    {   32, "Simplex" },
    {   33, "North Building Technologies Limited" },
    {   34, "Notifier" },
    {   35, "Reliable Controls Corporation" },
    {   36, "Tridium Inc." },
    {   37, "Sierra Monitor Corporation/FieldServer Technologies" },
    {   38, "Silicon Energy" },
    {   39, "Kieback & Peter GmbH & Co KG" },
    {   40, "Anacon Systems, Inc." },
    {   41, "Systems Controls & Instruments, LLC" },
    {   42, "Acuity Brands Lighting, Inc." },
    {   43, "Micropower Manufacturing" },
    {   44, "Matrix Controls" },
    {   45, "METALAIRE" },
    {   46, "ESS Engineering" },
    {   47, "Sphere Systems Pty Ltd." },
    {   48, "Walker Technologies Corporation" },
    {   49, "H I Solutions, Inc." },
    {   50, "MBS GmbH" },
    {   51, "SAMSON AG" },
    {   52, "Badger Meter Inc." },
    {   53, "DAIKIN Industries Ltd." },
    {   54, "NARA Controls Inc." },
    {   55, "Mammoth Inc." },
    {   56, "Liebert Corporation" },
    {   57, "SEMCO Incorporated" },
    {   58, "Air Monitor Corporation" },
    {   59, "TRIATEK, LLC" },
    {   60, "NexLight" },
    {   61, "Multistack" },
    {   62, "TSI Incorporated" },
    {   63, "Weather-Rite, Inc." },
    {   64, "Dunham-Bush" },
    {   65, "Reliance Electric" },
    {   66, "LCS Inc." },
    {   67, "Regulator Australia PTY Ltd." },
    {   68, "Touch-Plate Lighting Controls" },
    {   69, "Amann GmbH" },
    {   70, "RLE Technologies" },
    {   71, "Cardkey Systems" },
    {   72, "SECOM Co., Ltd." },
    {   73, "ABB Gebaeudetechnik AG Bereich NetServ" },
    {   74, "KNX Association cvba" },
    {   75, "Institute of Electrical Installation Engineers of Japan (IEIEJ)" },
    {   76, "Nohmi Bosai, Ltd." },
    {   77, "Carel S.p.A." },
    {   78, "UTC Fire & Security Espana, S.L." },
    {   79, "Hochiki Corporation" },
    {   80, "Fr. Sauter AG" },
    {   81, "Matsushita Electric Works, Ltd." },
    {   82, "Mitsubishi Electric Corporation, Inazawa Works" },
    {   83, "Mitsubishi Heavy Industries, Ltd." },
    {   84, "Xylem, Inc." },
    {   85, "Yamatake Building Systems Co., Ltd." },
    {   86, "The Watt Stopper, Inc." },
    {   87, "Aichi Tokei Denki Co., Ltd." },
    {   88, "Activation Technologies, LLC" },
    {   89, "Saia-Burgess Controls, Ltd." },
    {   90, "Hitachi, Ltd." },
    {   91, "Novar Corp./Trend Control Systems Ltd." },
    {   92, "Mitsubishi Electric Lighting Corporation" },
    {   93, "Argus Control Systems, Ltd." },
    {   94, "Kyuki Corporation" },
    {   95, "Richards-Zeta Building Intelligence, Inc." },
    {   96, "Scientech R&D, Inc." },
    {   97, "VCI Controls, Inc." },
    {   98, "Toshiba Corporation" },
    {   99, "Mitsubishi Electric Corporation Air Conditioning & Refrigeration Systems Works" },
    {  100, "Custom Mechanical Equipment, LLC" },
    {  101, "ClimateMaster" },
    {  102, "ICP Panel-Tec, Inc." },
    {  103, "D-Tek Controls" },
    {  104, "NEC Engineering, Ltd." },
    {  105, "PRIVA BV" },
    {  106, "Meidensha Corporation" },
    {  107, "JCI Systems Integration Services" },
    {  108, "Freedom Corporation" },
    {  109, "Neuberger Gebaeudeautomation GmbH" },
    {  110, "eZi Controls" },
    {  111, "Leviton Manufacturing" },
    {  112, "Fujitsu Limited" },
    {  113, "Emerson Network Power" },
    {  114, "S. A. Armstrong, Ltd." },
    {  115, "Visonet AG" },
    {  116, "M&M Systems, Inc." },
    {  117, "Custom Software Engineering" },
    {  118, "Nittan Company, Limited" },
    {  119, "Elutions Inc. (Wizcon Systems SAS)" },
    {  120, "Pacom Systems Pty., Ltd." },
    {  121, "Unico, Inc." },
    {  122, "Ebtron, Inc." },
    {  123, "Scada Engine" },
    {  124, "AC Technology Corporation" },
    {  125, "Eagle Technology" },
    {  126, "Data Aire, Inc." },
    {  127, "ABB, Inc." },
    {  128, "Transbit Sp. z o. o." },
    {  129, "Toshiba Carrier Corporation" },
    {  130, "Shenzhen Junzhi Hi-Tech Co., Ltd." },
    {  131, "Tokai Soft" },
    {  132, "Blue Ridge Technologies" },
    {  133, "Veris Industries" },
    {  134, "Centaurus Prime" },
    {  135, "Sand Network Systems" },
    {  136, "Regulvar, Inc." },
    {  137, "AFDtek Division of Fastek International Inc." },
    {  138, "PowerCold Comfort Air Solutions, Inc." },
    {  139, "I Controls" },
    {  140, "Viconics Electronics, Inc." },
    {  141, "Yaskawa America, Inc." },
    {  142, "DEOS control systems GmbH" },
    {  143, "Digitale Mess- und Steuersysteme AG" },
    {  144, "Fujitsu General Limited" },
    {  145, "Project Engineering S.r.l." },
    {  146, "Sanyo Electric Co., Ltd." },
    {  147, "Integrated Information Systems, Inc." },
    {  148, "Temco Controls, Ltd." },
    {  149, "Airtek International Inc." },
    {  150, "Advantech Corporation" },
    {  151, "Titan Products, Ltd." },
    {  152, "Regel Partners" },
    {  153, "National Environmental Product" },
    {  154, "Unitec Corporation" },
    {  155, "Kanden Engineering Company" },
    {  156, "Messner Gebaeudetechnik GmbH" },
    {  157, "Integrated.CH" },
    {  158, "Price Industries" },
    {  159, "SE-Elektronic GmbH" },
    {  160, "Rockwell Automation" },
    {  161, "Enflex Corp." },
    {  162, "ASI Controls" },
    {  163, "SysMik GmbH Dresden" },
    {  164, "HSC Regelungstechnik GmbH" },
    {  165, "Smart Temp Australia Pty.  Ltd." },
    {  166, "Cooper Controls" },
    {  167, "Duksan Mecasys Co., Ltd." },
    {  168, "Fuji IT Co., Ltd." },
    {  169, "Vacon Plc" },
    {  170, "Leader Controls" },
    {  171, "Cylon Controls, Ltd." },
    {  172, "Compas" },
    {  173, "Mitsubishi Electric Building Techno-Service Co., Ltd." },
    {  174, "Building Control Integrators" },
    {  175, "ITG Worldwide (M) Sdn Bhd" },
    {  176, "Lutron Electronics Co., Inc." },
    {  177, "Cooper-Atkins Corporation" },
    {  178, "LOYTEC Electronics GmbH" },
    {  179, "ProLon" },
    {  180, "Mega Controls Limited" },
    {  181, "Micro Control Systems, Inc." },
    {  182, "Kiyon, Inc." },
    {  183, "Dust Networks" },
    {  184, "Advanced Building Automation Systems" },
    {  185, "Hermos AG" },
    {  186, "CEZIM" },
    {  187, "Softing" },
    {  188, "Lynxspring, Inc." },
    {  189, "Schneider Toshiba Inverter Europe" },
    {  190, "Danfoss Drives A/S" },
    {  191, "Eaton Corporation" },
    {  192, "Matyca S.A." },
    {  193, "Botech AB" },
    {  194, "Noveo, Inc." },
    {  195, "AMEV" },
    {  196, "Yokogawa Electric Corporation" },
    {  197, "GFR Gesellschaft fuer Regelungstechnik" },
    {  198, "Exact Logic" },
    {  199, "Mass Electronics Pty Ltd dba Innotech Control Systems Australia" },
    {  200, "Kandenko Co., Ltd." },
    {  201, "DTF, Daten-Technik Fries" },
    {  202, "Klimasoft, Ltd." },
    {  203, "Toshiba Schneider Inverter Corporation" },
    {  204, "Control Applications, Ltd." },
    {  205, "KDT Systems Co., Ltd." },
    {  206, "Onicon Incorporated" },
    {  207, "Automation Displays, Inc." },
    {  208, "Control Solutions, Inc." },
    {  209, "Remsdaq Limited" },
    {  210, "NTT Facilities, Inc." },
    {  211, "VIPA GmbH" },
    {  212, "TSC21 Association of Japan" },
    {  213, "Strato Automation" },
    {  214, "HRW Limited" },
    {  215, "Lighting Control & Design, Inc." },
    {  216, "Mercy Electronic and Electrical Industries" },
    {  217, "Samsung SDS Co., Ltd" },
    {  218, "Impact Facility Solutions, Inc." },
    {  219, "Aircuity" },
    {  220, "Control Techniques, Ltd." },
    {  221, "OpenGeneral Pty., Ltd." },
    {  222, "WAGO Kontakttechnik GmbH & Co. KG" },
    {  223, "Cerus Industrial" },
    {  224, "Chloride Power Protection Company" },
    {  225, "Computrols, Inc." },
    {  226, "Phoenix Contact GmbH & Co. KG" },
    {  227, "Grundfos Management A/S" },
    {  228, "Ridder Drive Systems" },
    {  229, "Soft Device SDN BHD" },
    {  230, "Integrated Control Technology Limited" },
    {  231, "AIRxpert Systems, Inc." },
    {  232, "Microtrol Limited" },
    {  233, "Red Lion Controls" },
    {  234, "Digital Electronics Corporation" },
    {  235, "Ennovatis GmbH" },
    {  236, "Serotonin Software Technologies, Inc." },
    {  237, "LS Industrial Systems Co., Ltd." },
    {  238, "Square D Company" },
    {  239, "S Squared Innovations, Inc." },
    {  240, "Aricent Ltd." },
    {  241, "EtherMetrics, LLC" },
    {  242, "Industrial Control Communications, Inc." },
    {  243, "Paragon Controls, Inc." },
    {  244, "A. O. Smith Corporation" },
    {  245, "Contemporary Control Systems, Inc." },
    {  246, "Intesis Software SL" },
    {  247, "Ingenieurgesellschaft N. Hartleb mbH" },
    {  248, "Heat-Timer Corporation" },
    {  249, "Ingrasys Technology, Inc." },
    {  250, "Costerm Building Automation" },
    {  251, "WILO SE" },
    {  252, "Embedia Technologies Corp." },
    {  253, "Technilog" },
    {  254, "HR Controls Ltd. & Co. KG" },
    {  255, "Lennox International, Inc." },
    {  256, "RK-Tec Rauchklappen-Steuerungssysteme GmbH & Co. KG" },
    {  257, "Thermomax, Ltd." },
    {  258, "ELCON Electronic Control, Ltd." },
    {  259, "Larmia Control AB" },
    {  260, "BACnet Stack at SourceForge" },
    {  261, "G4S Security Services A/S" },
    {  262, "Exor International S.p.A." },
    {  263, "Cristal Controles" },
    {  264, "Regin AB" },
    {  265, "Dimension Software, Inc." },
    {  266, "SynapSense Corporation" },
    {  267, "Beijing Nantree Electronic Co., Ltd." },
    {  268, "Camus Hydronics Ltd." },
    {  269, "Kawasaki Heavy Industries, Ltd." },
    {  270, "Critical Environment Technologies" },
    {  271, "ILSHIN IBS Co., Ltd." },
    {  272, "ELESTA Energy Control AG" },
    {  273, "KROPMAN Installatietechniek" },
    {  274, "Baldor Electric Company" },
    {  275, "INGA mbH" },
    {  276, "GE Consumer & Industrial" },
    {  277, "Functional Devices, Inc." },
    {  278, "ESAC" },
    {  279, "M-System Co., Ltd." },
    {  280, "Yokota Co., Ltd." },
    {  281, "Hitranse Technology Co., LTD" },
    {  282, "Vigilent Corporation" },
    {  283, "Kele, Inc." },
    {  284, "Opera Electronics, Inc." },
    {  285, "Gentec" },
    {  286, "Embedded Science Labs, LLC" },
    {  287, "Parker Hannifin Corporation" },
    {  288, "MaCaPS International Limited" },
    {  289, "Link4 Corporation" },
    {  290, "Romutec Steuer-u. Regelsysteme GmbH" },
    {  291, "Pribusin, Inc." },
    {  292, "Advantage Controls" },
    {  293, "Critical Room Control" },
    {  294, "LEGRAND" },
    {  295, "Tongdy Control Technology Co., Ltd." },
    {  296, "ISSARO Integrierte Systemtechnik" },
    {  297, "Pro-Dev Industries" },
    {  298, "DRI-STEEM" },
    {  299, "Creative Electronic GmbH" },
    {  300, "Swegon AB" },
    {  301, "Jan Brachacek" },
    {  302, "Hitachi Appliances, Inc." },
    {  303, "Real Time Automation, Inc." },
    {  304, "ITEC Hankyu-Hanshin Co." },
    {  305, "Cyrus E&M Engineering Co., Ltd." },
    {  306, "Badger Meter" },
    {  307, "Cirrascale Corporation" },
    {  308, "Elesta GmbH Building Automation" },
    {  309, "Securiton" },
    {  310, "OSlsoft, Inc." },
    {  311, "Hanazeder Electronic GmbH" },
    {  312, "Honeywell Security Deutschland, Novar GmbH" },
    {  313, "Siemens Industry, Inc." },
    {  314, "ETM Professional Control GmbH" },
    {  315, "Meitav-tec, Ltd." },
    {  316, "Janitza Electronics GmbH" },
    {  317, "MKS Nordhausen" },
    {  318, "De Gier Drive Systems B.V." },
    {  319, "Cypress Envirosystems" },
    {  320, "SMARTron s.r.o." },
    {  321, "Verari Systems, Inc." },
    {  322, "K-W Electronic Service, Inc." },
    {  323, "ALFA-SMART Energy Management" },
    {  324, "Telkonet, Inc." },
    {  325, "Securiton GmbH" },
    {  326, "Cemtrex, Inc." },
    {  327, "Performance Technologies, Inc." },
    {  328, "Xtralis (Aust) Pty Ltd" },
    {  329, "TROX GmbH" },
    {  330, "Beijing Hysine Technology Co., Ltd" },
    {  331, "RCK Controls, Inc." },
    {  332, "Distech Controls SAS" },
    {  333, "Novar/Honeywell" },
    {  334, "The S4 Group, Inc." },
    {  335, "Schneider Electric" },
    {  336, "LHA Systems" },
    {  337, "GHM engineering Group, Inc." },
    {  338, "Cllimalux S.A." },
    {  339, "VAISALA Oyj" },
    {  340, "COMPLEX (Beijing) Technology, Co., LTD." },
    {  341, "SCADAmetrics" },
    {  342, "POWERPEG NSI Limited" },
    {  343, "BACnet Interoperability Testing Services, Inc." },
    {  344, "Teco a.s." },
    {  345, "Plexus Technology, Inc." },
    {  346, "Energy Focus, Inc." },
    {  347, "Powersmiths International Corp." },
    {  348, "Nichibei Co., Ltd." },
    {  349, "HKC Technology Ltd." },
    {  350, "Ovation Networks, Inc." },
    {  351, "Setra Systems" },
    {  352, "AVG Automation" },
    {  353, "ZXC Ltd." },
    {  354, "Byte Sphere" },
    {  355, "Generiton Co., Ltd." },
    {  356, "Holter Regelarmaturen GmbH & Co. KG" },
    {  357, "Bedford Instruments, LLC" },
    {  358, "Standair Inc." },
    {  359, "WEG Automation - R&D" },
    {  360, "Prolon Control Systems ApS" },
    {  361, "Inneasoft" },
    {  362, "ConneXSoft GmbH" },
    {  363, "CEAG Notlichtsysteme GmbH" },
    {  364, "Distech Controls Inc." },
    {  365, "Industrial Technology Research Institute" },
    {  366, "ICONICS, Inc." },
    {  367, "IQ Controls s.c." },
    {  368, "OJ Electronics A/S" },
    {  369, "Rolbit Ltd." },
    {  370, "Synapsys Solutions Ltd." },
    {  371, "ACME Engineering Prod. Ltd." },
    {  372, "Zener Electric Pty, Ltd." },
    {  373, "Selectronix, Inc." },
    {  374, "Gorbet & Banerjee, LLC." },
    {  375, "IME" },
    {  376, "Stephen H. Dawson Computer Service" },
    {  377, "Accutrol, LLC" },
    {  378, "Schneider Elektronik GmbH" },
    {  379, "Alpha-Inno Tec GmbH" },
    {  380, "ADMMicro, Inc." },
    {  381, "Greystone Energy Systems, Inc." },
    {  382, "CAP Technologie" },
    {  383, "KeRo Systems" },
    {  384, "Domat Control System s.r.o." },
    {  385, "Efektronics Pty. Ltd." },
    {  386, "Hekatron Vertriebs GmbH" },
    {  387, "Securiton AG" },
    {  388, "Carlo Gavazzi Controls SpA" },
    {  389, "Chipkin Automation Systems" },
    {  390, "Savant Systems, LLC" },
    {  391, "Simmtronic Lighting Controls" },
    {  392, "Abelko Innovation AB" },
    {  393, "Seresco Technologies Inc." },
    {  394, "IT Watchdogs" },
    {  395, "Automation Assist Japan Corp." },
    {  396, "Thermokon Sensortechnik GmbH" },
    {  397, "EGauge Systems, LLC" },
    {  398, "Quantum Automation (ASIA) PTE, Ltd." },
    {  399, "Toshiba Lighting & Technology Corp." },
    {  400, "SPIN Engenharia de Automacao Ltda." },
    {  401, "Logistics Systems & Software Services India PVT. Ltd." },
    {  402, "Delta Controls Integration Products" },
    {  403, "Focus Media" },
    {  404, "LUMEnergi Inc." },
    {  405, "Kara Systems" },
    {  406, "RF Code, Inc." },
    {  407, "Fatek Automation Corp." },
    {  408, "JANDA Software Company, LLC" },
    {  409, "Open System Solutions Limited" },
    {  410, "Intelec Systems PTY Ltd." },
    {  411, "Ecolodgix, LLC" },
    {  412, "Douglas Lighting Controls" },
    {  413, "iSAtech GmbH" },
    {  414, "AREAL" },
    {  415, "Beckhoff Automation GmbH" },
    {  416, "IPAS GmbH" },
    {  417, "KE2 Therm Solutions" },
    {  418, "Base2Products" },
    {  419, "DTL Controls, LLC" },
    {  420, "INNCOM International, Inc." },
    {  421, "BTR Netcom GmbH" },
    {  422, "Greentrol Automation, Inc" },
    {  423, "BELIMO Automation AG" },
    {  424, "Samsung Heavy Industries Co, Ltd" },
    {  425, "Triacta Power Technologies, Inc." },
    {  426, "Globestar Systems" },
    {  427, "MLB Advanced Media, LP" },
    {  428, "SWG Stuckmann Wirtschaftliche Gebaeudesysteme GmbH" },
    {  429, "SensorSwitch" },
    {  430, "Multitek Power Limited" },
    {  431, "Aquametro AG" },
    {  432, "LG Electronics Inc." },
    {  433, "Electronic Theatre Controls, Inc." },
    {  434, "Mitsubishi Electric Corporation Nagoya Works" },
    {  435, "Delta Electronics, Inc." },
    {  436, "Elma Kurtalj, Ltd." },
    {  437, "ADT Fire and Security Sp. A.o.o." },
    {  438, "Nedap Security Management" },
    {  439, "ESC Automation Inc." },
    {  440, "DSP4YOU Ltd." },
    {  441, "GE Sensing and Inspection Technologies" },
    {  442, "Embedded Systems SIA" },
    {  443, "BEFEGA GmbH" },
    {  444, "Baseline Inc." },
    {  445, "M2M Systems Integrators" },
    {  446, "OEMCtrl" },
    {  447, "Clarkson Controls Limited" },
    {  448, "Rogerwell Control System Limited" },
    {  449, "SCL Elements" },
    {  450, "Hitachi Ltd." },
    {  451, "Newron System SA" },
    {  452, "BEVECO Gebouwautomatisering BV" },
    {  453, "Streamside Solutions" },
    {  454, "Yellowstone Soft" },
    {  455, "Oztech Intelligent Systems Pty Ltd." },
    {  456, "Novelan GmbH" },
    {  457, "Flexim Americas Corporation" },
    {  458, "ICP DAS Co., Ltd." },
    {  459, "CARMA Industries Inc." },
    {  460, "Log-One Ltd." },
    {  461, "TECO Electric & Machinery Co., Ltd." },
    {  462, "ConnectEx, Inc." },
    {  463, "Turbo DDC Suedwest" },
    {  464, "Quatrosense Environmental Ltd." },
    {  465, "Fifth Light Technology Ltd." },
    {  466, "Scientific Solutions, Ltd." },
    {  467, "Controller Area Network Solutions (M) Sdn Bhd" },
    {  468, "RESOL - Elektronische Regelungen GmbH" },
    {  469, "RPBUS LLC" },
    {  470, "BRS Sistemas Eletronicos" },
    {  471, "WindowMaster A/S" },
    {  472, "Sunlux Technologies Ltd." },
    {  473, "Measurlogic" },
    {  474, "Frimat GmbH" },
    {  475, "Spirax Sarco" },
    {  476, "Luxtron" },
    {  477, "Raypak Inc" },
    {  478, "Air Monitor Corporation" },
    {  479, "Regler Och Webbteknik Sverige (ROWS)" },
    {  480, "Intelligent Lighting Controls Inc." },
    {  481, "Sanyo Electric Industry Co., Ltd" },
    {  482, "E-Mon Energy Monitoring Products" },
    {  483, "Digital Control Systems" },
    {  484, "ATI Airtest Technologies, Inc." },
    {  485, "SCS SA" },
    {  486, "HMS Industrial Networks AB" },
    {  487, "Shenzhen Universal Intellisys Co Ltd" },
    {  488, "EK Intellisys Sdn Bhd" },
    {  489, "SysCom" },
    {  490, "Firecom, Inc." },
    {  491, "ESA Elektroschaltanlagen Grimma GmbH" },
    {  492, "Kumahira Co Ltd" },
    {  493, "Hotraco" },
    {  494, "SABO Elektronik GmbH" },
    {  495, "Equip'Trans" },
    {  496, "TCS Basys Controls" },
    {  497, "FlowCon International A/S" },
    {  498, "ThyssenKrupp Elevator Americas" },
    {  499, "Abatement Technologies" },
    {  500, "Continental Control Systems, LLC" },
    {  501, "WISAG Automatisierungstechnik GmbH & Co KG" },
    {  502, "EasyIO" },
    {  503, "EAP-Electric GmbH" },
    {  504, "Hardmeier" },
    {  505, "Mircom Group of Companies" },
    {  506, "Quest Controls" },
    {  507, "Mestek, Inc" },
    {  508, "Pulse Energy" },
    {  509, "Tachikawa Corporation" },
    {  510, "University of Nebraska-Lincoln" },
    {  511, "Redwood Systems" },
    {  512, "PASStec Industrie-Elektronik GmbH" },
    {  513, "NgEK, Inc." },
    {  514, "t-mac Technologies" },
    {  515, "Jireh Energy Tech Co., Ltd." },
    {  516, "Enlighted Inc." },
    {  517, "El-Piast Sp. Z o.o" },
    {  518, "NetxAutomation Software GmbH" },
    {  519, "Invertek Drives" },
    {  520, "Deutschmann Automation GmbH & Co. KG" },
    {  521, "EMU Electronic AG" },
    {  522, "Phaedrus Limited" },
    {  523, "Sigmatek GmbH & Co KG" },
    {  524, "Marlin Controls" },
    {  525, "Circutor, SA" },
    {  526, "UTC Fire & Security" },
    {  527, "DENT Instruments, Inc." },
    {  528, "FHP Manufacturing Company - Bosch Group" },
    {  529, "GE Intelligent Platforms" },
    {  530, "Inner Range Pty Ltd" },
    {  531, "GLAS Energy Technology" },
    {  532, "MSR-Electronic-GmbH" },
    {  533, "Energy Control Systems, Inc." },
    {  534, "EMT Controls" },
    {  535, "Daintree Networks Inc." },
    {  536, "EURO ICC d.o.o" },
    {  537, "TE Connectivity Energy" },
    {  538, "GEZE GmbH" },
    {  539, "NEC Corporation" },
    {  540, "Ho Cheung International Company Limited" },
    {  541, "Sharp Manufacturing Systems Corporation" },
    {  542, "DOT CONTROLS a.s." },
    {  543, "BeaconMedaes" },
    {  544, "Midea Commercial Aircon" },
    {  545, "WattMaster Controls" },
    {  546, "Kamstrup A/S" },
    {  547, "CA Computer Automation GmbH" },
    {  548, "Laars Heating Systems Company" },
    {  549, "Hitachi Systems, Ltd." },
    {  550, "Fushan AKE Electronic Engineering Co., Ltd." },
    {  551, "Toshiba International Corporation" },
    {  552, "Starman Systems, LLC" },
    {  553, "Samsung Techwin Co., Ltd." },
    {  554, "ISAS-Integrated Switchgear and Systems P/L" },
    {  555, "reserved by ASHRAE" },
    {  556, "Obvius" },
    {  557, "Marek Guzik" },
    {  558, "Vortek Instruments, LLC" },
    {  559, "Universal Lighting Technologies" },
    {  560, "Myers Power Products, Inc." },
    {  561, "Vector Controls GmbH" },
    {  562, "Crestron Electronics, Inc." },
    {  563, "A&E Controls Limited" },
    {  564, "Projektomontaza A.D." },
    {  565, "Freeaire Refrigeration" },
    {  566, "Aqua Cooler Pty Limited" },
    {  567, "Basic Controls" },
    {  568, "GE Measurement and Control Solutions Advanced Sensors" },
    {  569, "EQUAL Networks" },
    {  570, "Millennial Net" },
    {  571, "APLI Ltd" },
    {  572, "Electro Industries/GaugeTech" },
    {  573, "SangMyung University" },
    {  574, "Coppertree Analytics, Inc." },
    {  575, "CoreNetiX GmbH" },
    {  576, "Acutherm" },
    {  577, "Dr. Riedel Automatisierungstechnik GmbH" },
    {  578, "Shina System Co., Ltd" },
    {  579, "Iqapertus" },
    {  580, "PSE Technology" },
    {  581, "BA Systems" },
    {  582, "BTICINO" },
    {  583, "Monico, Inc." },
    {  584, "iCue" },
    {  585, "tekmar Control Systems Ltd." },
    {  586, "Control Technology Corporation" },
    {  587, "GFAE GmbH" },
    {  588, "BeKa Software GmbH" },
    {  589, "Isoil Industria SpA" },
    {  590, "Home Systems Consulting SpA" },
    {  591, "Socomec" },
    {  592, "Everex Communications, Inc." },
    {  593, "Ceiec Electric Technology" },
    {  594, "Atrila GmbH" },
    {  595, "WingTechs" },
    {  596, "Shenzhen Mek Intellisys Pte Ltd." },
    {  597, "Nestfield Co., Ltd." },
    {  598, "Swissphone Telecom AG" },
    {  599, "PNTECH JSC" },
    {  600, "Horner APG, LLC" },
    {  601, "PVI Industries, LLC" },
    {  602, "Ela-compil" },
    {  603, "Pegasus Automation International LLC" },
    {  604, "Wight Electronic Services Ltd." },
    {  605, "Marcom" },
    {  606, "Exhausto A/S" },
    {  607, "Dwyer Instruments, Inc." },
    {  608, "Link GmbH" },
    {  609, "Oppermann Regelgerate GmbH" },
    {  610, "NuAire, Inc." },
    {  611, "Nortec Humidity, Inc." },
    {  612, "Bigwood Systems, Inc." },
    {  613, "Enbala Power Networks" },
    {  614, "Inter Energy Co., Ltd." },
    {  615, "ETC" },
    {  616, "COMELEC S.A.R.L" },
    {  617, "Pythia Technologies" },
    {  618, "TrendPoint Systems, Inc." },
    {  619, "AWEX" },
    {  620, "Eurevia" },
    {  621, "Kongsberg E-lon AS" },
    {  622, "FlaktWoods" },
    {  623, "E + E Elektronik GES M.B.H." },
    {  624, "ARC Informatique" },
    {  625, "SKIDATA AG" },
    {  626, "WSW Solutions" },
    {  627, "Trefon Electronic GmbH" },
    {  628, "Dongseo System" },
    {  629, "Kanontec Intelligence Technology Co., Ltd." },
    {  630, "EVCO S.p.A." },
    {  631, "Accuenergy (CANADA) Inc." },
    {  632, "SoftDEL" },
    {  633, "Orion Energy Systems, Inc." },
    {  634, "Roboticsware" },
    {  635, "DOMIQ Sp. z o.o." },
    {  636, "Solidyne" },
    {  637, "Elecsys Corporation" },
    {  638, "Conditionaire International Pty. Limited" },
    {  639, "Quebec, Inc." },
    {  640, "Homerun Holdings" },
    {  641, "Murata Americas" },
    {  642, "Comptek" },
    {  643, "Westco Systems, Inc." },
    {  644, "Advancis Software & Services GmbH" },
    {  645, "Intergrid, LLC" },
    {  646, "Markerr Controls, Inc." },
    {  647, "Toshiba Elevator and Building Systems Corporation" },
    {  648, "Spectrum Controls, Inc." },
    {  649, "Mkservice" },
    {  650, "Fox Thermal Instruments" },
    {  651, "SyxthSense Ltd" },
    {  652, "DUHA System S R.O." },
    {  653, "NIBE" },
    {  654, "Melink Corporation" },
    {  655, "Fritz-Haber-Institut" },
    {  656, "MTU Onsite Energy GmbH, Gas Power Systems" },
    {  657, "Omega Engineering, Inc." },
    {  658, "Avelon" },
    {  659, "Ywire Technologies, Inc." },
    {  660, "M.R. Engineering Co., Ltd." },
    {  661, "Lochinvar, LLC" },
    {  662, "Sontay Limited" },
    {  663, "GRUPA Slawomir Chelminski" },
    {  664, "Arch Meter Corporation" },
    {  665, "Senva, Inc." },
    {  666, "reserved by ASHRAE" },
    {  667, "FM-Tec" },
    {  668, "Systems Specialists, Inc." },
    {  669, "SenseAir" },
    {  670, "AB IndustrieTechnik Srl" },
    {  671, "Cortland Research, LLC" },
    {  672, "MediaView" },
    {  673, "VDA Elettronica" },
    {  674, "CSS, Inc." },
    {  675, "Tek-Air Systems, Inc." },
    {  676, "ICDT" },
    {  677, "The Armstrong Monitoring Corporation" },
    {  678, "DIXELL S.r.l" },
    {  679, "Lead System, Inc." },
    {  680, "ISM EuroCenter S.A." },
    {  681, "TDIS" },
    {  682, "Trade FIDES" },
    {  683, "Knuerr GmbH (Emerson Network Power)" },
    {  684, "Resource Data Management" },
    {  685, "Abies Technology, Inc." },
    {  686, "Amalva" },
    {  687, "MIRAE Electrical Mfg. Co., Ltd." },
    {  688, "HunterDouglas Architectural Projects Scandinavia ApS" },
    {  689, "RUNPAQ Group Co., Ltd" },
    {  690, "Unicard SA" },
    {  691, "IE Technologies" },
    {  692, "Ruskin Manufacturing" },
    {  693, "Calon Associates Limited" },
    {  694, "Contec Co., Ltd." },
    {  695, "iT GmbH" },
    {  696, "Autani Corporation" },
    {  697, "Christian Fortin" },
    {  698, "HDL" },
    {  699, "IPID Sp. Z.O.O Limited" },
    {  700, "Fuji Electric Co., Ltd" },
    {  701, "View, Inc." },
    {  702, "Samsung S1 Corporation" },
    {  703, "New Lift" },
    {  704, "VRT Systems" },
    {  705, "Motion Control Engineering, Inc." },
    {  706, "Weiss Klimatechnik GmbH" },
    {  707, "Elkon" },
    {  708, "Eliwell Controls S.r.l." },
    {  709, "Japan Computer Technos Corp" },
    {  710, "Rational Network ehf" },
    {  711, "Magnum Energy Solutions, LLC" },
    {  712, "MelRok" },
    {  713, "VAE Group" },
    {  714, "LGCNS" },
    {  715, "Berghof Automationstechnik GmbH" },
    {  716, "Quark Communications, Inc." },
    {  717, "Sontex" },
    {  718, "mivune AG" },
    {  719, "Panduit" },
    {  720, "Smart Controls, LLC" },
    {  721, "Compu-Aire, Inc." },
    {  722, "Sierra" },
    {  723, "ProtoSense Technologies" },
    {  724, "Eltrac Technologies Pvt Ltd" },
    {  725, "Bektas Invisible Controls GmbH" },
    {  726, "Entelec" },
    {  727, "INNEXIV" },
    {  728, "Covenant" },
    {  729, "Davitor AB" },
    {  730, "TongFang Technovator" },
    {  731, "Building Robotics, Inc." },
    {  732, "HSS-MSR UG" },
    {  733, "FramTack LLC" },
    {  734, "B. L. Acoustics, Ltd." },
    {  735, "Traxxon Rock Drills, Ltd" },
    {  736, "Franke" },
    {  737, "Wurm GmbH & Co" },
    {  738, "AddENERGIE" },
    {  739, "Mirle Automation Corporation" },
    {  740, "Ibis Networks" },
    {  741, "ID-KARTA s.r.o." },
    {  742, "Anaren, Inc." },
    {  743, "Span, Incorporated" },
    {  744, "Bosch Thermotechnology Corp" },
    {  745, "DRC Technology S.A." },
    {  746, "Shanghai Energy Building Technology Co, Ltd" },
    {  747, "Fraport AG" },
    {  748, "Flowgroup" },
    {  749, "Skytron Energy, GmbH" },
    {  750, "ALTEL Wicha, Golda Sp. J." },
    {  751, "Drupal" },
    {  752, "Axiomatic Technology, Ltd" },
    {  753, "Bohnke + Partner" },
    {  754, "Function 1" },
    {  755, "Optergy Pty, Ltd" },
    {  756, "LSI Virticus" },
    {  757, "Konzeptpark GmbH" },
    {  758, "Hubbell Building Automation, Inc." },
    {  759, "eCurv, Inc." },
    {  760, "Agnosys GmbH" },
    {  761, "Shanghai Sunfull Automation Co., LTD" },
    {  762, "Kurz Instruments, Inc." },
    {  763, "Cias Elettronica S.r.l." },
    {  764, "Multiaqua, Inc." },
    {  765, "BlueBox" },
    {  766, "Sensidyne" },
    {  767, "Viessmann Elektronik GmbH" },
    {  768, "ADFweb.com srl" },
    {  769, "Gaylord Industries" },
    {  770, "Majur Ltd." },
    {  771, "Shanghai Huilin Technology Co., Ltd." },
    {  772, "Exotronic" },
    {  773, "Safecontrol spol s.r.o." },
    {  774, "Amatis" },
    {  775, "Universal Electric Corporation" },
    {  776, "iBACnet" },
    {  777, "reserved by ASHRAE" },
    {  778, "Smartrise Engineering, Inc." },
    {  779, "Miratron, Inc." },
    {  780, "SmartEdge" },
    {  781, "Mitsubishi Electric Australia Pty Ltd" },
    {  782, "Triangle Research International Ptd Ltd" },
    {  783, "Produal Oy" },
    {  784, "Milestone Systems A/S" },
    {  785, "Trustbridge" },
    {  786, "Feedback Solutions" },
    {  787, "IES" },
    {  788, "GE Critical Power" },
    {  789, "Riptide IO" },
    {  790, "Messerschmitt Systems AG" },
    {  791, "Dezem Energy Controlling" },
    {  792, "MechoSystems" },
    {  793, "evon GmbH" },
    {  794, "CS Lab GmbH" },
    {  795, "8760 Enterprises, Inc." },
    {  796, "Touche Controls" },
    {  797, "Ontrol Teknik Malzeme San. ve Tic. A.S." },
    {  798, "Uni Control System Sp. Z o.o." },
    {  799, "Weihai Ploumeter Co., Ltd" },
    {  800, "Elcom International Pvt. Ltd" },
    {  801, "Philips Lighting" },
    {  802, "AutomationDirect" },
    {  803, "Paragon Robotics" },
    {  804, "SMT System & Modules Technology AG" },
    {  805, "OS Technology Service and Trading Co., LTD" },
    {  806, "CMR Controls Ltd" },
    {  807, "Innovari, Inc." },
    {  808, "ABB Control Products" },
    {  809, "Gesellschaft fur Gebaeudeautomation mbH" },
    {  810, "RODI Systems Corp." },
    {  811, "Nextek Power Systems" },
    {  812, "Creative Lighting" },
    {  813, "WaterFurnace International" },
    {  814, "Mercury Security" },
    {  815, "Hisense (Shandong) Air-Conditioning Co., Ltd." },
    {  816, "Layered Solutions, Inc." },
    {  817, "Leegood Automatic System, Inc." },
    {  818, "Shanghai Restar Technology Co., Ltd." },
    {  819, "Reimann Ingenieurbuero" },
    {  820, "LynTec" },
    {  821, "HTP" },
    {  822, "Elkor Technologies, Inc." },
    {  823, "Bentrol Pty Ltd" },
    {  824, "Team-Control Oy" },
    {  825, "NextDevice, LLC" },
    {  826, "GLOBAL CONTROL 5 Sp. z o.o." },
    {  827, "King I Electronics Co., Ltd" },
    {  828, "SAMDAV" },
    {  829, "Next Gen Industries Pvt. Ltd." },
    {  830, "Entic LLC" },
    {  831, "ETAP" },
    {  832, "Moralle Electronics Limited" },
    {  833, "Leicom AG" },
    {  834, "Watts Regulator Company" },
    {  835, "S.C. Orbtronics S.R.L." },
    {  836, "Gaussan Technologies" },
    {  837, "WEBfactory GmbH" },
    {  838, "Ocean Controls" },
    {  839, "Messana  Air-Ray Conditioning s.r.l." },
    {  840, "Hangzhou BATOWN Technology Co. Ltd." },
    {  841, "Reasonable Controls" },
    {  842, "Servisys, Inc." },
    {  843, "halstrup-walcher GmbH" },
    {  844, "SWG Automation Fuzhou Limited" },
    {  845, "KSB Aktiengesellschaft" },
    {  846, "Hybryd Sp. z o.o." },
    {  847, "Helvatron AG" },
    {  848, "Oderon Sp. Z.O.O." },
    {  849, "miko" },
    {  850, "Exodraft" },
    {  851, "Hochhuth GmbH" },
    {  852, "Integrated System Technologies Ltd." },
    {  853, "Shanghai Cellcons Controls Co., Ltd" },
    {  854, "Emme Controls, LLC" },
    {  855, "Field Diagnostic Services, Inc." },
    {  856, "Ges Teknik A.S." },
    {  857, "Global Power Products, Inc." },
    {  858, "Option NV" },
    {  859, "BV-Control AG" },
    {  860, "Sigren Engineering AG" },
    {  861, "Shanghai Jaltone Technology Co., Ltd." },
    {  862, "MaxLine Solutions Ltd" },
    {  863, "Kron Instrumentos Eletricos Ltda" },
    {  864, "Thermo Matrix" },
    {  865, "Infinite Automation Systems, Inc." },
    {  866, "Vantage" },
    {  867, "Elecon Measurements Pvt Ltd" },
    {  868, "TBA" },
    {  869, "Carnes Company" },
    {  870, "Harman Professional" },
    {  871, "Nenutec Asia Pacific Pte Ltd" },
    {  872, "Gia NV" },
    {  873, "Kepware Tehnologies" },
    {  874, "Temperature Electronics Ltd" },
    {  875, "Packet Power" },
    {  876, "Project Haystack Corporation" },
    {  877, "DEOS Controls Americas Inc." },
    {  878, "Senseware Inc" },
    {  879, "MST Systemtechnik AG" },
    {  880, "Lonix Ltd" },
    {  881, "GMC-I Messtechnik GmbH" },
    {  882, "Aviosys International Inc." },
    {  883, "Efficient Building Automation Corp." },
    {  884, "Accutron Instruments Inc." },
    {  885, "Vermont Energy Control Systems LLC" },
    {  886, "DCC Dynamics" },
    {  887, "Brueck Electronic GmbH" },
    {  888, "reserved by ASHRAE" },
    {  889, "NGBS Hungary Ltd." },
    {  890, "ILLUM Technology, LLC" },
    {  891, "Delta Controls Germany Limited" },
    {  892, "S+T Service & Technique S.A." },
    {  893, "SimpleSoft" },
    {  894, "Candi Controls, Inc." },
    {  895, "EZEN Solution Inc." },
    {  896, "Fujitec Co. Ltd." },
    {  897, "Terralux" },
    {  898, "Annicom" },
    {  899, "Bihl+Wiedemann GmbH" },
    {  900, "Daper, Inc." },
    {  901, "Schueco International KG" },
    {  902, "Otis Elevator Company" },
    {  903, "Fidelix Oy" },
    {  904, "RAM GmbH Mess- und Regeltechnik" },
    {  905, "WEMS" },
    {  906, "Ravel Electronics Pvt Ltd" },
    {  907, "OmniMagni" },
    {  908, "Echelon" },
    {  909, "Intellimeter Canada, Inc." },
    {  910, "Bithouse Oy" },
    {  912, "BuildPulse" },
    {  913, "Shenzhen 1000 Building Automation Co. Ltd" },
    {  914, "AED Engineering GmbH" },
    {  915, "Guentner GmbH & Co. KG" },
    {  916, "KNXlogic" },
    {  917, "CIM Environmental Group" },
    {  918, "Flow Control" },
    {  919, "Lumen Cache, Inc." },
    {  920, "Ecosystem" },
    {  921, "Potter Electric Signal Company, LLC" },
    {  922, "Tyco Fire & Security S.p.A." },
    {  923, "Watanabe Electric Industry Co., Ltd." },
    {  924, "Causam Energy" },
    {  925, "W-tec AG" },
    {  926, "IMI Hydronic Engineering International SA" },
    {  927, "ARIGO Software" },
    {  928, "MSA Safety" },
    {  929, "Smart Solucoes Ltda - MERCATO" },
    {  930, "PIATRA Engineering" },
    {  931, "ODIN Automation Systems, LLC" },
    {  932, "Belparts NV" },
    {  933, "UAB, SALDA" },
    {  934, "Alre-IT Regeltechnik GmbH" },
    {  935, "Ingenieurbuero H. Lertes GmbH & Co. KG" },
    {  936, "Breathing Buildings" },
    {  937, "eWON SA" },
    {  938, "Cav. Uff. Giacomo Cimberio S.p.A" },
    {  939, "PKE Electronics AG" },
    {  940, "Allen" },
    {  941, "Kastle Systems" },
    {  942, "Logical Electro-Mechanical (EM) Systems, Inc." },
    {  943, "ppKinetics Instruments, LLC" },
    {  944, "Cathexis Technologies" },
    {  945, "Sylop Limited" },
    {  946, "Brauns Control GmbH" },
    {  947, "Omron Corporation" },
    {  948, "Wildeboer Bauteile Gmbh" },
    {  949, "Shanghai Biens Technologies Ltd:" },
    {  950, "Beijing HZHY Technology Co., Ltd;" },
    {  951, "Building Clouds" },
    {  952, "The University of Sheffield-Department of Electronic and Electrical Engineering" },
    {  953, "Fabtronics Australia Pty Ltd" },
    {  954, "SLAT" },
    {  955, "Software Motor Corporation" },
    {  956, "Armstrong International Inc." },
    {  957, "Steril-Aire, Inc." },
    {  958, "Infinique" },
    {  959, "Arcom" },
    {  960, "Argo Performance, Ltd" },
    {  961, "Dialight" },
    {  962, "Ideal Technical Solutions" },
    {  963, "Neurobat AG" },
    {  964, "Neyer Software Consulting LLC" },
    {  965, "SCADA Technology Development Co., Ltd." },
    {  966, "Demand Logic Limited" },
    {  967, "GWA Group Limited" },
    {  968, "Occitaline" },
    {  969, "NAO Digital Co., Ltd." },
    {  970, "Shenzhen Chanslink Network Technology Co., Ltd." },
    {  971, "Samsung Electronics Co., Ltd." },
    {  972, "Mesa Laboratories, Inc." },
    {  973, "Fischer" },
    {  974, "OpSys Solutions Ltd." },
    {  975, "Advanced Devices Limited" },
    {  976, "Condair" },
    {  977, "INELCOM Ingenieria Electronica Comercial S.A." },
    {  978, "GridPoint, Inc." },
    {  979, "ADF Technologies Sdn Bhd" },
    {  980, "EPM, Inc." },
    {  981, "Lighting Controls Ltd." },
    {  982, "Perix Controls Ltd." },
    {  983, "AERCO International, Inc." },
    {  984, "KONE Inc." },
    {  985, "Ziehl - Abegg SE" },
    {  986, "Robot, S.A.Bernat Pons" },
    {  987, "Optigo Networks, Inc." },
    {  988, "Openmotics BVBA" },
    {  989, "Metropolitan Industries, Inc." },
    {  990, "Huawei Technologies Co., Ltd." },
    {  991, "OSRAM Sylvania, Inc." },
    {  992, "Vanti" },
    {  993, "Cree, Inc." },
    {  994, "Richmond Heights SDN BHD" },
    {  995, "Payne - Sparkman Lighting Management" },
    {  996, "Ashcroft" },
    {  997, "Jet Controls Corp" },
    {  998, "Zumtobel Lighting GmbH" },
    {  999, "reserved by ASHRAE" },
    { 1000, "Ekon GmbH" },
    { 1001, "Molex GmbH" },
    { 1002, "Maco Lighting Pty Ltd." },
    { 1003, "Axecon Corp." },
    { 1004, "Tensor plc" },
    { 1005, "Kaseman Environmental Control Equipment(Shanghai) Limited" },
    { 1006, "AB Axis Industries" },
    { 1007, "Netix Controls" },
    { 1008, "Eldridge Products, Inc." },
    { 1009, "Micronics" },
    { 1010, "Fortecho Solutions Ltd." },
    { 1011, "Sellers Manufacturing Company" },
    { 1012, "Rite - Hite Doors, Inc." },
    { 1013, "Violet Defense LLC" },
    { 1014, "Simna" },
    { 1015, "Multi - Energie Best Inc." },
    { 1016, "Mega System Technologies, Inc." },
    { 1017, "Rheem" },
    { 1018, "Ing.Punzenberger COPA - DATA GmbH" },
    { 1019, "MEC Electronics GmbH" },
    { 1020, "Taco Comfort Solutions" },
    { 1021, "Alexander Maier GmbH" },
    { 1022, "Ecorithm, Inc." },
    { 1023, "Accurro Ltd." },
    { 1024, "ROMTECK Australia Pty Ltd." },
    { 1025, "Splash Monitoring Limited" },
    { 1026, "Light Application" },
    { 1027, "Logical Building Automation" },
    { 1028, "Exilight Oy" },
    { 1029, "Hager Electro SAS" },
    { 1030, "KLIF Co. LTD." },
    { 1031, "HygroMatik" },
    { 1032, "Daniel Mousseau Programmation & Electronique" },
    { 1033, "Aerionics Inc." },
    { 1034, "M2S Electronique Ltee" },
    { 1035, "Automation Components, Inc." },
    { 1036, "Niobrara Research & Development Corporation" },
    { 1037, "Netcom Sicherheitstechnik GmbH" },
    { 1038, "Lumel S.A." },
    { 1039, "Great Plains Industries, Inc." },
    { 1040, "Domotica Labs S.R.L" },
    { 1041, "Energy Cloud, Inc." },
    { 1042, "Vomatec" },
    { 1043, "Demma Companies" },
    { 1044, "Valsena" },
    { 1045, "Comsys Buertsch AG" },
    { 1046, "bGrid" },
    { 1047, "MDJ Software Pty Ltd" },
    { 1048, "Dimonoff, Inc." },
    { 1049, "Edomo Systems" },
    { 1050, "Effektiv, LLC" },
    { 1051, "SteamOVap" },
    { 1052, "grandcentrix GmbH" },
    { 1053, "Weintek Labs, Inc." },
    { 1054, "Intefox GmbH" },
    { 1055, "Radius22 Automation Company" },
    { 1056, "Ringdale, Inc." },
    { 1057, "Iwaki America" },
    { 1058, "Bractlet" },
    { 1059, "STULZ Air Technology Systems, Inc." },
    { 1060, "Climate Ready Engineering" },
    { 1061, "Genea Energy Partners" },
    { 1062, "IoTall Chile" },
    { 1063, "IKS Co., Ltd." },
    { 1064, "Yodiwo AB" },
    { 1065, "TITAN electronic GmbH" },
    { 1066, "IDEC Corporation" },
    { 1067, "SIFRI SL" },
    { 1068, "Thermal Gas Systems Inc." },
    { 1069, "Building Automation Products, Inc" },
    { 1070, "Asset Mapping" },
    { 1071, "Smarteh Company" },
    { 1072, "Datapod Australia Pty Ltd." },
    { 1073, "Buildings Alive Pty Ltd" },
    { 1074, "Digital Elektronik" },
    { 1075, "Talent Automacao e Tecnologia Ltda" },
    { 1076, "Norposh Limited" },
    { 1077, "Merkur Funksysteme AG" },
    { 1078, "Faster CZ spol. S.r.o" },
    { 1079, "Eco-Adapt" },
    { 1080, "Energocentrum Plus, s.r.o" },
    { 1081, "amBX UK Ltd" },
    { 1082, "Western Reserve Controls, Inc." },
    { 1083, "LayerZero Power Systems, Inc." },
    { 1084, "CIC Jan Hrebec s.r.o." },
    { 1085, "Sigrov BV" },
    { 1086, "ISYS-Intelligent Systems" },
    { 1087, "Gas Detection (Australia) Pty Ltd" },
    { 1088, "Kinco Automation (Shanghai) Ltd." },
    { 1089, "Lars Energy, LLC" },
    { 1090, "Flamefast (UK) Ltd." },
    { 1091, "Royal Service Air Conditioning" },
    { 1092, "Ampio Sp. Z o.o." },
    { 1093, "Inovonics Wireless Corporation" },
    { 1094, "Nvent Thermal Management" },
    { 1095, "Sinowell Control System Ltd." },
    { 1096, "Moxa Inc." },
    { 1097, "Matrix iControl SDN BHD" },
    { 1098, "PurpleSwift" },
    { 1099, "OTIM Technologies" },
    { 1100, "FlowMate Limited" },
    { 1101, "Degree Controls, Inc." },
    { 1102, "Fei Xing (Shanghai) Software Technologies Co., Ltd." },
    { 1103, "Berg GmbH" },
    { 1104, "ARENZ.IT" },
    { 1105, "Edelstrom Electronic Devices & Designing LLC" },
    { 1106, "Drive Connect, LLC" },
    { 1107, "DevelopNow" },
    { 1108, "Poort" },
    { 1109, "VMEIL Information (Shanghai) Ltd." },
    { 1110, "Rayleigh Instruments" },
    { 1111, "Reserved for ASHRAE" },
    { 1112, "CODEYSYS Development" },
    { 1113, "Smartware Technologies Group, LLC" },
    { 1114, "Polar Bear Solutions" },
    { 1115, "Codra" },
    { 1116, "Pharos Architectural Controls Ltd" },
    { 1117, "EngiNear Ltd." },
    { 1118, "Ad Hoc Electronics" },
    { 1119, "Unified Microsystems" },
    { 1120, "Industrieelektronik Brandenburg GmbH" },
    { 1121, "Hartmann GmbH" },
    { 1122, "Piscada" },
    { 1123, "KMB systems, s.r.o." },
    { 1124, "PowerTech Engineering AS" },
    { 1125, "Telefonbau Arthur Schwabe GmbH & Co. KG" },
    { 1126, "Wuxi Fistwelove Technology Co., Ltd." },
    { 1127, "Prysm" },
    { 1128, "STEINEL GmbH" },
    { 1129, "Georg Fischer JRG AG" },
    { 1130, "Make Develop SL" },
    { 1131, "Monnit Corporation" },
    { 1132, "Mirror Life Corporation" },
    { 1133, "Secure Meters Limited" },
    { 1134, "PECO" },
    { 1135, "CCTECH, Inc." },
    { 1136, "LightFi Limited" },
    { 1137, "Nice Spa" },
    { 1138, "Fiber SenSys, Inc." },
    { 1139, "B&D Buchta und Degeorgi" },
    { 1140, "Ventacity Systems, Inc." },
    { 1141, "Hitachi-Johnson Controls Air Conditioning, Inc." },
    { 1142, "Sage Metering, Inc." },
    { 1143, "Andel Limited" },
    { 1144, "ECOSmart Technologies" },
    { 1145, "S.E.T. Air Conditioning Engineering Co., Limited" },
    { 1146, "Protec Fire Detection Spain SL" },
    { 1147, "AGRAMER UG" },
    { 1148, "Anylink Electronic GmbH" },
    { 1149, "Schindler, Ltd" },
    { 1150, "Jibreel Abdeen Est." },
    { 1151, "Fluidyne Control Systems Pvt. Ltd" },
    { 1152, "Prism Systems, Inc." },
    { 1153, "Enertiv" },
    { 1154, "Mirasoft GmbH & Co. KG" },
    { 1155, "DUALTECH IT" },
    { 1156, "Countlogic, LLC" },
    { 1157, "Kohler" },
    { 1158, "Chen Sen Controls Co., Ltd." },
    { 1159, "Greenheck" },
    { 1160, "Intwine Connect, LLC" },
    { 1161, "Karlborgs Elkontroll" },
    { 1162, "Datakom" },
    { 1163, "Hoga Control AS" },
    { 1164, "Cool Automation" },
    { 1165, "Inter Search Co., Ltd" },
    { 1166, "DABBEL-Automation Intelligence GmbH" },
    { 1167, "Gadgeon Engineering Smartness" },
    { 1168, "Coster Group S.r.l." },
    { 1169, "Walter Mueller AG" },
    { 1170, "Fluke" },
    { 1171, "Quintex Systems Ltd" },
    { 1172, "Senfficient SDN BHD" },
    { 1173, "Nube iO Operations Pty Ltd" },
    { 1174, "DAS Integrator Pte Ltd" },
    { 1175, "CREVIS Co., Ltd" },
    { 1176, "iSquared software inc." },
    { 1177, "KTG GmbH" },
    { 1178, "POK Group Oy" },
    { 1179, "Adiscom" },
    { 1180, "Incusense" },
    { 1181, "75F" },
    { 1182, "Anord Mardix, Inc." },
    { 1183, "HOSCH Gebäudeautomation" },
    { 1184, "BOSCH Software Innovations GmbH" },
    { 1185, "Royal Boon Edam International B.V." },
    { 1186, "Clack Corporation" },
    { 1187, "Unitex Controls LLC" },
    { 1188, "KTC Göteborg AB" },
    { 1189, "Interzon AB" },
    { 1190, "ISDE ING SL" },
    { 1191, "ABM automation building messaging GmbH" },
    { 1192, "Kentec Electronics Ltd" },
    { 1193, "Emerson Commercial and Residential Solutions" },
    { 1194, "Powerside" },
    { 1195, "SMC Group" },
    { 1196, "EOS Weather Instruments" },
    { 1197, "Zonex Systems" },
    { 1198, "Generex Systems Computervertriebsgesellschaft mbH" },
    { 1199, "Energy Wall LLC" },
    { 1200, "Thermofin" },
    { 1201, "SDATAWAY SA" },
    { 1202, "Biddle Air Systems Limited" },
    { 1203, "Kessler" },
    { 1204, "Thermoscreens" },
    { 1205, "Modio" },
    { 1206, "Newron Solutions" },
    { 1207, "Unitronics" },
    { 1208, "TRILUX GmbH & Co. KG" },
    { 1209, "Kollmorgen Steuerungstechnik GmbH" },
    { 1210, "Bosch Rexroth AG" },
    { 1211, "Alarko Carrier" },
    { 1212, "Verdigris Technologies" },
    { 1213, "Shanghai SIIC-Longchuang Smarter Energy Technology Co., Ltd." },
    { 1214, "Quinda Co." },
    { 1215, "GRUNER AG" },
    { 1216, "BACMOVE" },
    { 1217, "PSIDAC AB" },
    { 1218, "ISICON-Control Automation" },
    { 1219, "Big Ass Fans" },
    { 1220, "din" },
    { 1221, "Teldio" },
    { 1222, "MIKROKLIMA s.r.o." },
    { 1223, "Density" },
    { 1224, "ICONAG-Leittechnik GmbH" },
    { 1225, "Awair" },
    { 1226, "T&D Engineering, Ltd" },
    { 1227, "Sistemas Digitales" },
    { 1228, "Loxone Electronics GmbH" },
    { 1229, "ActronAir" },
    { 1230, "Inductive Automation" },
    { 1231, "Thor Engineering GmbH" },
    { 1232, "Berner International, LLC" },
    { 1233, "Potsdam Sensors LLC" },
    { 1234, "Kohler Mira Ltd" },
    { 1235, "Tecomon GmbH" },
    { 1236, "Two Dimensional Instruments, LLC" },
    { 1237, "LEFA Technologies Pte. Ltd" },
    { 1238, "EATON CEAG Notlichtsysteme GmbH" },
    { 1239, "Commbox Tecnologia" },
    { 1240, "IPVideo Corporation" },
    { 1241, "Bender GmbH & Co. KG" },
    { 1242, "Rhymebus Corporation" },
    { 1243, "Axon Systems Ltd" },
    { 1244, "Engineered Air" },
    { 1245, "Elipse Software Ltd" },
    { 1246, "Simatix Building Technologies Pvt. Ltd." },
    { 1247, "W.A. Benjamin Electric Co." },
    { 1248, "TROX Air Conditioning Components (Suzhou) Co. Ltd." },
    { 1249, "SC Medical Pty Ltd." },
    { 1250, "Elcanic A/S" },
    { 1251, "Obeo AS" },
    { 1252, "Tapa, Inc." },
    { 1253, "ASE Smart Energy, Inc." },
    { 1254, "Performance Services, Inc." },
    { 1255, "Veridify Security" },
    { 1256, "CD Innovation LTD" },
    { 1257, "Ben Peoples Industries, LLC" },
    { 1258, "UNICOMM Sp. z o.o" },
    { 1259, "Thing Technologies GmbH" },
    { 1260, "Beijing HaiLin Energy Saving Technology, Inc." },
    { 1261, "Digital Realty" },
    { 1262, "Agrowtek Inc." },
    { 1263, "DSP Innovation BV " },
    { 1264, "STV Electronic GmbH" },
    { 1265, "Elmeasure India Pvt Ltd." },
    { 1266, "Pineshore Energy LLC." },
    { 1267, "Brasch Environmental Technologies, LLC." },
    { 1268, "Lion Controls Co., LTD" },
    { 1269, "Sinux" },
    { 1270, "Avnet Inc." },
    { 1271, "Somfy Activites SA" },
    { 1272, "Amico" },
    { 1273, "SageGlass" },
    { 1274, "AuVerte" },
    { 1275, "Agile Connects Pvt. Ltd." },
    { 1276, "Locimation Pty Ltd." },
    { 1277, "Envio Systems GmbH" },
    { 1278, "Voytech Systems Limited" },
    { 1279, "Davidsmeyer und Paul GmbH" },
    { 1280, "Lusher Engineering Services" },
    { 1281, "CHNT Nanjing Techsel Intelligent Company LTD." },
    { 1282, "Threetronics Pty Ltd." },
    { 1283, "SkyFoundry, LLC." },
    { 1284, "HanilProTech" },
    { 1285, "Sensorscall" },
    { 1286, "Shanghai Jingpu Information Technology, Co., Ltd." },
    { 1287, "Lichtmanufaktur Berlin GmbH" },
    { 1288, "Eco Parking Technologies" },
    { 1289, "Envision Digital International Pte Ltd." },
    { 1290, "Antony Developpement Electronique" },
    { 1291, "i2systems" },
    { 1292, "Thureon International Limited" },
    { 1293, "Pulsafeeder" },
    { 1294, "MegaChips Corporation" },
    { 1295, "TES Controls" },
    { 1296, "Cermate" },
    { 1297, "Grand Valley State University" },
    { 1298, "Symcon Gmbh" },
    { 1299, "The Chicago Faucet Company" },
    { 1300, "Geberit AG" },
    { 1301, "Rex Controls" },
    { 1302, "IVMS GmbH" },
    { 1303, "MNPP Saturn Ltd." },
    { 1304, "Regal Beloit" },
    { 1305, "ACS-Air Conditioning Solutions" },
    { 1306, "GBX Technology, LLC" },
    { 1307, "Kaiterra" },
    { 1308, "ThinKuan loT Technology (Shanghai) Co., Ltd" },
    { 1309, "HoCoSto B.V." },
    { 1310, "Shenzhen AS-AI Technology Co., Ltd." },
    { 1311, "RPS S.p.a." },
    { 1312, "Delta Dore Ems" },
    { 1313, "IOTech Systems Limited" },
    { 1314, "i-AutoLogic Co., Ltd." },
    { 1315, "New Age Micro, LLC" },
    { 1316, "Guardian Glass" },
    { 1317, "Guangzhou Zhaoyu Information Technology" },
    { 1318, "ACE IoT Solutions LLC" },
    { 1319, "Poris Electronics Co., Ltd." },
    { 1320, "Terminus Technologies Group" },
    { 1321, "Intech 21, Inc." },
    { 1322, "Accurate Electronics" },
    { 1323, "Fluence Bioengineering" },
    { 1324, "Mun Hean Singapore Pte Ltd" },
    { 1325, "Katronic AG & Co. KG" },
    { 1326, "Suzhou XinAo Information Technology Co. Ltd" },
    { 1327, "Linktekk Technology, JSC." },
    { 1328, "Stirling Ultracold" },
    { 1329, "UV Partners, Inc." },
    { 1330, "ProMinent GmbH" },
    { 1331, "Multi-Tech Systems, Inc." },
    { 1332, "JUMO GmbH & Co. KG" },
    { 1333, "Qingdao Huarui Technology Co. Ltd." },
    { 1334, "Cairn Systemes" },
    { 1335, "NeuroLogic Research Corp." },
    { 1336, "Transition Technologies Advanced Solutions Sp. z o.o" },
    { 1337, "Xxter bv" },
    { 1338, "PassiveLogic" },
    { 1339, "EnSmart Controls" },
    { 1340, "Watts Heating and Hot Water Solutions, dba Lync" },
    { 1341, "Troposphaira Technologies LLP" },
    { 1342, "Network Thermostat" },
    { 1343, "Titanium Intelligent Solutions, LLC" },
    { 1344, "Numa Products, LLC" },
    { 1345, "WAREMA Renkhoff SE" },
    { 1346, "Frese A/S" },
    { 1347, "Mapped" },
    { 1348, "ELEKTRODESIGN ventilatory s.r.o" },
    { 1349, "AirCare Automation, Inc." },
    { 1350, "Antrum" },
    { 1351, "Bao Linh Connect Technology" },
    { 1352, "Virginia Controls, LLC" },
    { 1353, "Duosys SDN BHD" },
    { 1354, "Onsen SAS" },
    { 1355, "Vaughn Thermal Corporation" },
    { 1356, "Thermoplastic Engineering Ltd (TPE)" },
    { 1357, "Wirth Research Ltd." },
    { 1358, "SST Automation" },
    { 1359, "Shanghai Bencol Electronic Technology Co., Ltd" },
    { 1360, "AIWAA Systems Private Limited" },
    { 1361, "Enless Wireless" },
    { 1362, "Ozuno Engineering Pty Ltd" },
    { 1363, "Hubbell, The Electric Heater Company" },
    { 1364, "Industrial Turnaround Corporation (ITAC)" },
    {    0, NULL }
};
static value_string_ext BACnetVendorIdentifiers_ext = VALUE_STRING_EXT_INIT(BACnetVendorIdentifiers);

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
static int hf_bacapp_object_name = -1;
static int hf_bacapp_instanceNumber = -1;
static int hf_bacapp_sequence_number = -1;
static int hf_bacapp_window_size = -1;
static int hf_bacapp_service = -1;
static int hf_bacapp_NAK = -1;
static int hf_bacapp_SRV = -1;
static int hf_bacapp_notify_type = -1;
static int hf_bacapp_event_type = -1;
static int hf_bacapp_error_class = -1;
static int hf_bacapp_error_code = -1;
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
static int hf_BACnetCodePage = -1;
static int hf_bacapp_tag_lvt = -1;
static int hf_bacapp_tag_ProcessId = -1;
static int hf_bacapp_tag_to_state = -1;
static int hf_bacapp_tag_from_state = -1;
static int hf_bacapp_uservice = -1;
static int hf_BACnetPropertyIdentifier = -1;
static int hf_BACnetVendorIdentifier = -1;
static int hf_BACnetRestartReason = -1;
static int hf_bacapp_tag_IPV4 = -1;
static int hf_bacapp_tag_IPV6 = -1;
static int hf_bacapp_tag_PORT = -1;
static int hf_bacapp_tag_mac_address_broadcast = -1;
static int hf_bacapp_reserved_ashrea = -1;
static int hf_bacapp_unused_bits = -1;
static int hf_bacapp_bit = -1;
static int hf_bacapp_complete_bitstring = -1;

/* present value */
static int hf_bacapp_present_value_null = -1;
static int hf_bacapp_present_value_bool = -1;
static int hf_bacapp_present_value_unsigned = -1;
static int hf_bacapp_present_value_signed = -1;
static int hf_bacapp_present_value_real = -1;
static int hf_bacapp_present_value_double = -1;
static int hf_bacapp_present_value_octet_string = -1;
static int hf_bacapp_present_value_char_string = -1;
static int hf_bacapp_present_value_bit_string = -1;
static int hf_bacapp_present_value_enum_index = -1;

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

static expert_field ei_bacapp_bad_length = EI_INIT;
static expert_field ei_bacapp_bad_tag = EI_INIT;
static expert_field ei_bacapp_opening_tag = EI_INIT;
static expert_field ei_bacapp_max_recursion_depth_reached = EI_INIT;

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
    st_node_packets_by_ip_src = stats_tree_create_node(st, st_str_packets_by_ip_src, st_node_packets_by_ip, STAT_DT_INT, TRUE);
    st_node_packets_by_ip_dst = stats_tree_create_node(st, st_str_packets_by_ip_dst, st_node_packets_by_ip, STAT_DT_INT, TRUE);
}

static gchar *
bacapp_get_address_label(const char *tag, address *addr)
{
    gchar *addr_str, *label_str;

    addr_str = address_to_str(NULL, addr);
    label_str = wmem_strconcat(NULL, tag, addr_str, NULL);
    wmem_free(NULL, addr_str);
    return label_str;
}

static tap_packet_status
bacapp_stats_tree_packet(stats_tree* st, packet_info* pinfo, epan_dissect_t* edt _U_, const void* p, tap_flags_t flags _U_)
{
    int    packets_for_this_dst;
    int    packets_for_this_src;
    int    service_for_this_dst;
    int    service_for_this_src;
    int    src_for_this_dst;
    int    dst_for_this_src;
    int    objectid_for_this_dst;
    int    objectid_for_this_src;
    int    instanceid_for_this_dst;
    int    instanceid_for_this_src;
    gchar *dststr;
    gchar *srcstr;
    const bacapp_info_value_t *binfo = (const bacapp_info_value_t *)p;

    srcstr = bacapp_get_address_label("Src: ", &pinfo->src);
    dststr = bacapp_get_address_label("Dst: ", &pinfo->dst);

    tick_stat_node(st, st_str_packets_by_ip, 0, TRUE);
    packets_for_this_dst = tick_stat_node(st, st_str_packets_by_ip_dst, st_node_packets_by_ip, TRUE);
    packets_for_this_src = tick_stat_node(st, st_str_packets_by_ip_src, st_node_packets_by_ip, TRUE);
    src_for_this_dst     = tick_stat_node(st, dststr, packets_for_this_dst, TRUE);
    dst_for_this_src     = tick_stat_node(st, srcstr, packets_for_this_src, TRUE);
    service_for_this_src = tick_stat_node(st, dststr, dst_for_this_src, TRUE);
    service_for_this_dst = tick_stat_node(st, srcstr, src_for_this_dst, TRUE);
    if (binfo->service_type) {
        objectid_for_this_dst = tick_stat_node(st, binfo->service_type, service_for_this_dst, TRUE);
        objectid_for_this_src = tick_stat_node(st, binfo->service_type, service_for_this_src, TRUE);
        if (binfo->object_ident) {
            instanceid_for_this_dst = tick_stat_node(st, binfo->object_ident, objectid_for_this_dst, TRUE);
            tick_stat_node(st, binfo->instance_ident, instanceid_for_this_dst, FALSE);
            instanceid_for_this_src = tick_stat_node(st, binfo->object_ident, objectid_for_this_src, TRUE);
            tick_stat_node(st, binfo->instance_ident, instanceid_for_this_src, FALSE);
        }
    }

    wmem_free(NULL, srcstr);
    wmem_free(NULL, dststr);

    return TAP_PACKET_REDRAW;
}

/* Stat: BACnet Packets sorted by Service */
static const gchar* st_str_packets_by_service = "BACnet Packets by Service";
static int st_node_packets_by_service = -1;

static void
bacapp_service_stats_tree_init(stats_tree* st)
{
    st_node_packets_by_service = stats_tree_create_pivot(st, st_str_packets_by_service, 0);
}

static tap_packet_status
bacapp_stats_tree_service(stats_tree* st, packet_info* pinfo, epan_dissect_t* edt _U_, const void* p, tap_flags_t flags _U_)
{
    int    servicetype;
    int    src, dst;
    int    objectid;

    gchar *dststr;
    gchar *srcstr;

    const bacapp_info_value_t *binfo = (const bacapp_info_value_t *)p;

    srcstr = bacapp_get_address_label("Src: ", &pinfo->src);
    dststr = bacapp_get_address_label("Dst: ", &pinfo->dst);

    tick_stat_node(st, st_str_packets_by_service, 0, TRUE);
    if (binfo->service_type) {
        servicetype = tick_stat_node(st, binfo->service_type, st_node_packets_by_service, TRUE);
        src         = tick_stat_node(st, srcstr, servicetype, TRUE);
        dst         = tick_stat_node(st, dststr, src, TRUE);
        if (binfo->object_ident) {
            objectid = tick_stat_node(st, binfo->object_ident, dst, TRUE);
            tick_stat_node(st, binfo->instance_ident, objectid, FALSE);
        }
    }

    wmem_free(NULL, srcstr);
    wmem_free(NULL, dststr);

    return TAP_PACKET_REDRAW;
}

/* Stat: BACnet Packets sorted by Object Type */
static const gchar* st_str_packets_by_objectid = "BACnet Packets by Object Type";
static int st_node_packets_by_objectid = -1;

static void
bacapp_objectid_stats_tree_init(stats_tree* st)
{
    st_node_packets_by_objectid = stats_tree_create_pivot(st, st_str_packets_by_objectid, 0);
}

static tap_packet_status
bacapp_stats_tree_objectid(stats_tree* st, packet_info* pinfo, epan_dissect_t* edt _U_, const void* p, tap_flags_t flags _U_)
{
    int    servicetype;
    int    src, dst;
    int    objectid;

    gchar *dststr;
    gchar *srcstr;
    const bacapp_info_value_t *binfo = (const bacapp_info_value_t *)p;

    srcstr = bacapp_get_address_label("Src: ", &pinfo->src);
    dststr = bacapp_get_address_label("Dst: ", &pinfo->dst);

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

    wmem_free(NULL, srcstr);
    wmem_free(NULL, dststr);

    return TAP_PACKET_REDRAW;
}

/* Stat: BACnet Packets sorted by Instance No */
static const gchar* st_str_packets_by_instanceid  = "BACnet Packets by Instance ID";
static int          st_node_packets_by_instanceid = -1;

static void
bacapp_instanceid_stats_tree_init(stats_tree* st)
{
    st_node_packets_by_instanceid = stats_tree_create_pivot(st, st_str_packets_by_instanceid, 0);
}

static tap_packet_status
bacapp_stats_tree_instanceid(stats_tree* st, packet_info* pinfo, epan_dissect_t* edt _U_, const void* p, tap_flags_t flags _U_)
{
    int    servicetype;
    int    src, dst;
    int    instanceid;

    gchar *dststr;
    gchar *srcstr;
    const bacapp_info_value_t *binfo = (const bacapp_info_value_t *)p;

    srcstr = bacapp_get_address_label("Src: ", &pinfo->src);
    dststr = bacapp_get_address_label("Dst: ", &pinfo->dst);

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

    wmem_free(NULL, srcstr);
    wmem_free(NULL, dststr);

    return TAP_PACKET_REDRAW;
}


/* register all BACnet Ststistic trees */
static void
register_bacapp_stat_trees(void)
{
    stats_tree_register("bacapp", "bacapp_ip", "BACnet/Packets sorted by IP", 0,
        bacapp_stats_tree_packet, bacapp_packet_stats_tree_init, NULL);
    stats_tree_register("bacapp", "bacapp_service", "BACnet/Packets sorted by Service", 0,
        bacapp_stats_tree_service, bacapp_service_stats_tree_init, NULL);
    stats_tree_register("bacapp", "bacapp_objectid", "BACnet/Packets sorted by Object Type", 0,
        bacapp_stats_tree_objectid, bacapp_objectid_stats_tree_init, NULL);
    stats_tree_register("bacapp", "bacapp_instanceid", "BACnet/Packets sorted by Instance ID", 0,
        bacapp_stats_tree_instanceid, bacapp_instanceid_stats_tree_init, NULL);
}

/* 'data' must be allocated with wmem packet scope */
static gint
updateBacnetInfoValue(gint whichval, const gchar *data)
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
    /* Reassembled data field */
    NULL,
    /* Tag */
    "Message fragments"
};

#if 0
/* if BACnet uses the reserved values, then patch the corresponding values here, maximum 16 values are defined */
/* FIXME: fGetMaxAPDUSize is commented out, as it is not used. It was used to set variables which were not later used. */
static const guint MaxAPDUSize [] = { 50, 128, 206, 480, 1024, 1476 };

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

static const char*
val_to_split_str(guint32 val, guint32 split_val, const value_string *vs,
    const char *fmt, const char *split_fmt)
    G_GNUC_PRINTF(4, 0)
    G_GNUC_PRINTF(5, 0);

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
fTagNo(tvbuff_t *tvb, guint offset)
{
    return (guint)(tvb_get_guint8(tvb, offset) >> 4);
}

static gboolean
fUnsigned32(tvbuff_t *tvb, guint offset, guint32 lvt, guint32 *val)
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
fUnsigned64(tvbuff_t *tvb, guint offset, guint32 lvt, guint64 *val)
{
    gboolean valid = FALSE;
    gint64   value = 0;
    guint8   data, i;

    if (lvt && (lvt <= 8)) {
        valid = TRUE;
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
fSigned64(tvbuff_t *tvb, guint offset, guint32 lvt, gint64 *val)
{
    gboolean valid = FALSE;
    gint64   value = 0;
    guint8   data;
    guint32  i;

    /* we can only handle 7 bytes for a 64-bit value due to signed-ness */
    if (lvt && (lvt <= 7)) {
        valid = TRUE;
        data = tvb_get_guint8(tvb, offset);
        if ((data & 0x80) != 0)
            value = (~G_GUINT64_CONSTANT(0) << 8) | data;
        else
            value = data;
        for (i = 1; i < lvt; i++) {
            data = tvb_get_guint8(tvb, offset+i);
            value = ((guint64)value << 8) | data;
        }
        *val = value;
    }

    return valid;
}

static guint
fTagHeaderTree(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    guint offset, guint8 *tag_no, guint8* tag_info, guint32 *lvt)
{
    proto_item *ti = NULL;
    guint8      tag;
    guint8      value;
    guint       tag_len = 1;
    guint       lvt_len = 1;    /* used for tree display of lvt */
    guint       lvt_offset;     /* used for tree display of lvt */

    lvt_offset = offset;
    tag        = tvb_get_guint8(tvb, offset);
    *tag_info  = 0;
    *lvt       = tag & 0x07;

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
        proto_tree *subtree;
        if (tag_is_opening(tag)) {
            subtree = proto_tree_add_subtree_format(tree, tvb, offset, tag_len,
                    ett_bacapp_tag, &ti, "{[%u]", *tag_no );
        } else if (tag_is_closing(tag)) {
            subtree = proto_tree_add_subtree_format(tree, tvb, offset, tag_len,
                    ett_bacapp_tag, &ti, "}[%u]", *tag_no );
        } else if (tag_is_context_specific(tag)) {
            subtree = proto_tree_add_subtree_format(tree, tvb, offset, tag_len,
                    ett_bacapp_tag, &ti,
                    "Context Tag: %u, Length/Value/Type: %u", *tag_no, *lvt);
        } else {
            subtree = proto_tree_add_subtree_format(tree, tvb, offset, tag_len,
                    ett_bacapp_tag, &ti,
                    "Application Tag: %s, Length/Value/Type: %u",
                    val_to_str(*tag_no, BACnetApplicationTagNumber,
                        ASHRAE_Reserved_Fmt),
                    *lvt);
        }

        /* details if needed */
        proto_tree_add_item(subtree, hf_BACnetTagClass, tvb, offset, 1, ENC_BIG_ENDIAN);
        if (tag_is_extended_tag_number(tag)) {
            proto_tree_add_uint_format(subtree,
                                       hf_BACnetContextTagNumber,
                                       tvb, offset, 1, tag,
                                       "Extended Tag Number");
            proto_tree_add_item(subtree,
                                hf_BACnetExtendedTagNumber,
                                tvb, offset + 1, 1, ENC_BIG_ENDIAN);
        } else {
            if (tag_is_context_specific(tag))
                proto_tree_add_item(subtree,
                                    hf_BACnetContextTagNumber,
                                    tvb, offset, 1, ENC_BIG_ENDIAN);
            else
                proto_tree_add_item(subtree,
                                    hf_BACnetApplicationTagNumber,
                                    tvb, offset, 1, ENC_BIG_ENDIAN);
        }
        if (tag_is_closing(tag) || tag_is_opening(tag))
            proto_tree_add_item(subtree,
                                hf_BACnetNamedTag,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
        else if (tag_is_extended_value(tag)) {
            proto_tree_add_item(subtree,
                                hf_BACnetNamedTag,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_uint(subtree, hf_bacapp_tag_lvt,
                                tvb, lvt_offset, lvt_len, *lvt);
        } else
            proto_tree_add_uint(subtree, hf_bacapp_tag_lvt,
                                tvb, lvt_offset, lvt_len, *lvt);
    } /* if (tree) */

    if (*lvt > tvb_reported_length(tvb)) {
        expert_add_info_format(pinfo, ti, &ei_bacapp_bad_length,
                               "LVT length too long: %d > %d", *lvt,
                               tvb_reported_length(tvb));
        *lvt = 1;
    }

    return tag_len;
}

static guint
fTagHeader(tvbuff_t *tvb, packet_info *pinfo, guint offset, guint8 *tag_no, guint8* tag_info,
    guint32 *lvt)
{
    return fTagHeaderTree(tvb, pinfo, NULL, offset, tag_no, tag_info, lvt);
}

static guint
fNullTag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label)
{
    guint8      tag_no, tag_info;
    guint32     lvt;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree_format(tree, tvb, offset, 1, ett_bacapp_tag, NULL, "%sNULL", label);
    fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);

    return offset + 1;
}

static guint
fBooleanTag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label)
{
    guint8      tag_no, tag_info;
    guint32     lvt      = 0;
    proto_tree *subtree;
    guint       bool_len = 1;

    fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    if (tag_info && lvt == 1) {
        lvt = tvb_get_guint8(tvb, offset+1);
        ++bool_len;
    }

    subtree = proto_tree_add_subtree_format(tree, tvb, offset, bool_len,
                             ett_bacapp_tag, NULL, "%s%s", label, lvt == 0 ? "FALSE" : "TRUE");
    fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);

    return offset + bool_len;
}

static guint
fUnsignedTag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label)
{
    guint64     val = 0;
    guint8      tag_no, tag_info;
    guint32     lvt;
    guint       tag_len;
    proto_tree *subtree;

    tag_len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    /* only support up to an 8 byte (64-bit) integer */
    if (fUnsigned64(tvb, offset + tag_len, lvt, &val))
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
            ett_bacapp_tag, NULL, "%s(Unsigned) %" PRIu64, label, val);
    else
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
            ett_bacapp_tag, NULL, "%s - %u octets (Unsigned)", label, lvt);
    fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);

    return offset+tag_len+lvt;
}

static guint
fDevice_Instance(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, int hf)
{
    guint8      tag_no, tag_info;
    guint32     lvt, safe_lvt;
    guint       tag_len;
    proto_item *ti;
    proto_tree *subtree;

    tag_len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);

    if (lvt > 4)
        safe_lvt = 4;
    else
        safe_lvt = lvt;

    ti = proto_tree_add_item(tree, hf, tvb, offset+tag_len, safe_lvt, ENC_BIG_ENDIAN);

    if (lvt != safe_lvt)
        expert_add_info_format(pinfo, ti, &ei_bacapp_bad_length,
                "This field claims to be an impossible %u bytes, while the max is %u", lvt, safe_lvt);

    subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
    fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);

    return offset+tag_len+lvt;
}

/* set split_val to zero when not needed */
static guint
fEnumeratedTagSplit(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    guint offset, const gchar *label, const value_string *vs, guint32 split_val)
{
    guint32     val = 0;
    guint8      tag_no, tag_info;
    guint32     lvt;
    guint       tag_len;
    proto_tree *subtree;

    tag_len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    /* only support up to a 4 byte (32-bit) enumeration */
    if (fUnsigned32(tvb, offset+tag_len, lvt, &val)) {
        if (vs)
            subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
                ett_bacapp_tag, NULL, "%s %s (%u)", label, val_to_split_str(val, split_val, vs,
                ASHRAE_Reserved_Fmt, Vendor_Proprietary_Fmt), val);
        else
            subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
                ett_bacapp_tag, NULL, "%s %u", label, val);
    } else {
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
            ett_bacapp_tag, NULL, "%s - %u octets (enumeration)", label, lvt);
    }

    fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);

    return offset+tag_len+lvt;
}

static guint
fEnumeratedTag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        guint offset, const gchar *label, const value_string *vs)
{
    return fEnumeratedTagSplit(tvb, pinfo, tree, offset, label, vs, 0);
}

static guint
fSignedTag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label)
{
    gint64      val = 0;
    guint8      tag_no, tag_info;
    guint32     lvt;
    guint       tag_len;
    proto_tree *subtree;

    tag_len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    if (fSigned64(tvb, offset + tag_len, lvt, &val))
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
            ett_bacapp_tag, NULL, "%s(Signed) %" PRId64, label, val);
    else
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
            ett_bacapp_tag, NULL, "%s - %u octets (Signed)", label, lvt);
    fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);

    return offset+tag_len+lvt;
}

static guint
fRealTag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label)
{
    guint8      tag_no, tag_info;
    guint32     lvt;
    guint       tag_len;
    gfloat      f_val;
    proto_tree *subtree;

    tag_len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    f_val = tvb_get_ntohieee_float(tvb, offset+tag_len);
    subtree = proto_tree_add_subtree_format(tree, tvb, offset, 4+tag_len,
        ett_bacapp_tag, NULL, "%s%f (Real)", label, f_val);
    fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);

    return offset+tag_len+4;
}

static guint
fDoubleTag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label)
{
    guint8      tag_no, tag_info;
    guint32     lvt;
    guint       tag_len;
    gdouble     d_val;
    proto_tree  *subtree;

    tag_len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    d_val = tvb_get_ntohieee_double(tvb, offset+tag_len);
    subtree = proto_tree_add_subtree_format(tree, tvb, offset, 8+tag_len,
        ett_bacapp_tag, NULL, "%s%f (Double)", label, d_val);
    fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);

    return offset+tag_len+8;
}

static guint
fProcessId(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint32     val = 0, lvt;
    guint8      tag_no, tag_info;
    proto_item *ti;
    proto_tree *subtree;
    guint       tag_len;

    tag_len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    if (fUnsigned32(tvb, offset+tag_len, lvt, &val))
    {
        ti = proto_tree_add_uint(tree, hf_bacapp_tag_ProcessId,
            tvb, offset, lvt+tag_len, val);
        subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
    }
    else
    {
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
            ett_bacapp_tag, NULL, "Process Identifier - %u octets (Signed)", lvt);
    }
    fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
    offset += tag_len + lvt;

    return offset;
}

static guint
fPresentValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const value_string *vs, guint32 split_val, BacappPresentValueType type)
{
    // tag vars
    guint32     lvt;
    guint8      tag_no, tag_info;
    guint       tag_len;
    guint       curr_offset = offset;
    // tree vars
    proto_item *tree_item = NULL;
    proto_tree *subtree = NULL;
    // dissection vars
    guint       bool_len = 1;
    guint64     unsigned_val = 0;
    gint64      signed_val = 0;
    gfloat      float_val;
    gdouble     double_val;
    guint32     enum_index = 0;
    guint32     object_id;

    tag_len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    switch(type) {
        case BACAPP_PRESENT_VALUE_NULL:
            tree_item = proto_tree_add_string(tree, hf_bacapp_present_value_null, tvb, offset, lvt+tag_len, "NULL");
            curr_offset += 1;
            break;
        case BACAPP_PRESENT_VALUE_BOOL:
            if (tag_info && lvt == 1) {
                lvt = tvb_get_guint8(tvb, offset+1);
                bool_len++;
            }
            tree_item = proto_tree_add_boolean(tree, hf_bacapp_present_value_bool, tvb, offset, bool_len, lvt);
            curr_offset += bool_len;
            break;
        case BACAPP_PRESENT_VALUE_UNSIGNED:
            if (fUnsigned64(tvb, offset + tag_len, lvt, &unsigned_val))
                tree_item = proto_tree_add_uint64(tree, hf_bacapp_present_value_unsigned, tvb, offset, lvt+tag_len, unsigned_val);
            curr_offset += tag_len + lvt;
            break;
        case BACAPP_PRESENT_VALUE_SIGNED:
            if (fSigned64(tvb, offset + tag_len, lvt, &signed_val))
                tree_item = proto_tree_add_int64(tree, hf_bacapp_present_value_signed, tvb, offset, lvt+tag_len, signed_val);
            curr_offset += tag_len + lvt;
            break;
        case BACAPP_PRESENT_VALUE_REAL:
            float_val = tvb_get_ntohieee_float(tvb, offset+tag_len);
            double_val = (gdouble) float_val;
            tree_item = proto_tree_add_double(tree, hf_bacapp_present_value_real, tvb, offset, lvt+tag_len, double_val);
            curr_offset += tag_len + lvt;
            break;
        case BACAPP_PRESENT_VALUE_DOUBLE:
            double_val = tvb_get_ntohieee_double(tvb, offset+tag_len);
            tree_item = proto_tree_add_double(tree, hf_bacapp_present_value_double, tvb, offset, lvt+tag_len, double_val);
            curr_offset += tag_len + lvt;
            break;
        case BACAPP_PRESENT_VALUE_OCTET_STRING:
            if (lvt > 0)
                tree_item = proto_tree_add_item(tree, hf_bacapp_present_value_octet_string, tvb, offset, lvt+tag_len, ENC_NA);
            curr_offset += tag_len + lvt;
            break;
        case BACAPP_PRESENT_VALUE_CHARACTER_STRING:
            curr_offset = fCharacterStringBase(tvb, pinfo, tree, offset, NULL, TRUE, FALSE);
            break;
        case BACAPP_PRESENT_VALUE_BIT_STRING:
            curr_offset = fBitStringTagVSBase(tvb, pinfo, tree, offset, NULL, NULL, TRUE);
            break;
        case BACAPP_PRESENT_VALUE_ENUM:
            if (fUnsigned32(tvb, offset+tag_len, lvt, &enum_index)) {
                if (vs) {
                    subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len, ett_bacapp_tag, NULL,
                        "Present Value (enum value): %s",
                        val_to_split_str(enum_index,
                        split_val,
                        vs,
                        ASHRAE_Reserved_Fmt,
                        Vendor_Proprietary_Fmt));
                    proto_tree_add_uint(subtree, hf_bacapp_present_value_enum_index, tvb, offset, lvt+tag_len, enum_index);
                    fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                } else {
                    tree_item = proto_tree_add_uint(tree, hf_bacapp_present_value_enum_index, tvb, offset, lvt+tag_len, enum_index);
                }
            }
            curr_offset += tag_len + lvt;
            break;
        case BACAPP_PRESENT_VALUE_DATE:
            curr_offset = fDate(tvb, pinfo, tree, offset, "Date: ");
            break;
        case BACAPP_PRESENT_VALUE_TIME:
            curr_offset = fTime(tvb, pinfo, tree, offset, "Time: ");
            break;
        case BACAPP_PRESENT_VALUE_OBJECT_IDENTIFIER:
            object_id   = tvb_get_ntohl(tvb, offset+tag_len);
            object_type = object_id_type(object_id);
            subtree = proto_tree_add_subtree_format(tree, tvb, offset, tag_len + 4, ett_bacapp_tag, NULL,
                "Present Value (enum value): %s",
                val_to_split_str(object_type,
                128,
                BACnetObjectType,
                ASHRAE_Reserved_Fmt,
                Vendor_Proprietary_Fmt));
            proto_tree_add_uint(subtree, hf_bacapp_present_value_enum_index, tvb, offset, lvt+tag_len, object_type);
            fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            curr_offset += tag_len + lvt;
            break;
        default:
            curr_offset += tag_len + lvt;
            break;
    }

    if (tree_item != NULL && subtree == NULL) {
        subtree = proto_item_add_subtree(tree_item, ett_bacapp_value);
        fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
    }

    return curr_offset;
}

static guint
fEventType(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint32     val = 0, lvt;
    guint8      tag_no, tag_info;
    proto_item *ti;
    proto_tree *subtree;
    guint       tag_len;

    tag_len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    if (fUnsigned32(tvb, offset+tag_len, lvt, &val))
    {
        ti = proto_tree_add_uint(tree, hf_bacapp_event_type,
            tvb, offset, lvt+tag_len, val);
        subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
    }
    else
    {
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
            ett_bacapp_tag, NULL, "Event Type - %u octets (Signed)", lvt);
    }
    fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
    offset += tag_len + lvt;

    return offset;
}

static guint
fNotifyType(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint32     val = 0, lvt;
    guint8      tag_no, tag_info;
    proto_item *ti;
    proto_tree *subtree;
    guint       tag_len;

    tag_len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    if (fUnsigned32(tvb, offset+tag_len, lvt, &val))
    {
        ti = proto_tree_add_uint(tree, hf_bacapp_notify_type,
            tvb, offset, lvt+tag_len, val);
        subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
    }
    else
    {
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
            ett_bacapp_tag, NULL, "Notify Type - %u octets (Signed)", lvt);
    }
    fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
    offset += tag_len + lvt;

    return offset;
}

static guint
fToState(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint32     val = 0, lvt;
    guint8      tag_no, tag_info;
    proto_item *ti;
    proto_tree *subtree;
    guint       tag_len;

    tag_len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    if (fUnsigned32(tvb, offset+tag_len, lvt, &val))
    {
        ti = proto_tree_add_uint(tree, hf_bacapp_tag_to_state,
            tvb, offset, lvt+tag_len, val);
        subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
    }
    else
    {
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
            ett_bacapp_tag, NULL, "To State - %u octets (Signed)", lvt);
    }
    fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
    offset += tag_len + lvt;

    return offset;
}

static guint
fFromState(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint32     val = 0, lvt;
    guint8      tag_no, tag_info;
    proto_item *ti;
    proto_tree *subtree;
    guint       tag_len;

    tag_len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    if (fUnsigned32(tvb, offset+tag_len, lvt, &val))
    {
        ti = proto_tree_add_uint(tree, hf_bacapp_tag_from_state,
            tvb, offset, lvt+tag_len, val);
        subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
    }
    else
    {
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
            ett_bacapp_tag, NULL, "From State - %u octets (Signed)", lvt);
    }
    fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
    offset += tag_len + lvt;

    return offset;
}

static guint
fTimeSpan(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label)
{
    guint32     val = 0, lvt;
    guint8      tag_no, tag_info;
    proto_tree *subtree;
    guint       tag_len;

    tag_len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    if (fUnsigned32(tvb, offset+tag_len, lvt, &val))
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
            ett_bacapp_tag, NULL,
            "%s (hh.mm.ss): %d.%02d.%02d%s",
            label,
            (val / 3600), ((val % 3600) / 60), (val % 60),
            val == 0 ? " (indefinite)" : "");
    else
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
            ett_bacapp_tag, NULL,
            "%s - %u octets (Signed)", label, lvt);
    fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);

    return offset+tag_len+lvt;
}

static guint
fWeekNDay(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint32     month, weekOfMonth, dayOfWeek;
    guint8      tag_no, tag_info;
    guint32     lvt;
    guint       tag_len;
    proto_tree *subtree;

    tag_len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    month = tvb_get_guint8(tvb, offset+tag_len);
    weekOfMonth = tvb_get_guint8(tvb, offset+tag_len+1);
    dayOfWeek = tvb_get_guint8(tvb, offset+tag_len+2);
    subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
                 ett_bacapp_tag, NULL, "%s %s, %s",
                 val_to_str(month, months, "month (%d) not found"),
                 val_to_str(weekOfMonth, weekofmonth, "week of month (%d) not found"),
                 val_to_str(dayOfWeek, day_of_week, "day of week (%d) not found"));
    fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);

    return offset+tag_len+lvt;
}

static guint
fDate(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label)
{
    guint32     year, month, day, weekday;
    guint8      tag_no, tag_info;
    guint32     lvt;
    guint       tag_len;
    proto_tree *subtree;

    tag_len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    year    = tvb_get_guint8(tvb, offset+tag_len);
    month   = tvb_get_guint8(tvb, offset+tag_len+1);
    day     = tvb_get_guint8(tvb, offset+tag_len+2);
    weekday = tvb_get_guint8(tvb, offset+tag_len+3);
    if ((year == 255) && (day == 255) && (month == 255) && (weekday == 255)) {
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
            ett_bacapp_tag, NULL,
            "%sany", label);
    }
    else if (year != 255) {
        year += 1900;
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
            ett_bacapp_tag, NULL,
            "%s%s %d, %d, (Day of Week = %s)",
            label, val_to_str(month,
                months,
                "month (%d) not found"),
            day, year, val_to_str(weekday,
                day_of_week,
                "(%d) not found"));
    } else {
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
            ett_bacapp_tag, NULL,
            "%s%s %d, any year, (Day of Week = %s)",
            label, val_to_str(month, months, "month (%d) not found"),
            day, val_to_str(weekday, day_of_week, "(%d) not found"));
    }
    fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);

    return offset+tag_len+lvt;
}

static guint
fTime(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label)
{
    guint32     hour, minute, second, msec, lvt;
    guint8      tag_no, tag_info;
    guint       tag_len;
    proto_tree *subtree;

    tag_len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    hour    = tvb_get_guint8(tvb, offset+tag_len);
    minute  = tvb_get_guint8(tvb, offset+tag_len+1);
    second  = tvb_get_guint8(tvb, offset+tag_len+2);
    msec    = tvb_get_guint8(tvb, offset+tag_len+3);
    if ((hour == 255) && (minute == 255) && (second == 255) && (msec == 255))
        subtree = proto_tree_add_subtree_format(tree, tvb, offset,
            lvt+tag_len, ett_bacapp_tag, NULL,
            "%sany", label);
    else
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
            ett_bacapp_tag, NULL,
            "%s%d:%02d:%02d.%d %s = %02d:%02d:%02d.%d",
            label,
            hour > 12 ? hour - 12 : hour,
            minute, second, msec,
            hour >= 12 ? "P.M." : "A.M.",
            hour, minute, second, msec);
    fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);

    return offset+tag_len+lvt;
}

static guint
fDateTime(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label)
{
    proto_tree *subtree = tree;

    if (label != NULL) {
        subtree = proto_tree_add_subtree(subtree, tvb, offset, 10, ett_bacapp_value, NULL, label);
    }
    offset = fDate(tvb, pinfo, subtree, offset, "Date: ");
    return fTime(tvb, pinfo, subtree, offset, "Time: ");
}

static guint
fTimeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;
    guint8 tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {   /* closing Tag, but not for me */
            return offset;
        }
        offset = fTime(tvb, pinfo, tree, offset, "Time: ");
        offset = fApplicationTypes(tvb, pinfo, tree, offset, "Value: ");

        if (offset <= lastoffset) break;    /* exit loop if nothing happens inside */
    }
    return offset;
}

static guint
fCalendarEntry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8  tag_no, tag_info;
    guint32 lvt;

    switch (fTagNo(tvb, offset)) {
    case 0: /* Date */
        offset = fDate(tvb, pinfo, tree, offset, "Date: ");
        break;
    case 1: /* dateRange */
        offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
        offset  = fDateRange(tvb, pinfo, tree, offset);
        offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
        break;
    case 2: /* BACnetWeekNDay */
        offset = fWeekNDay(tvb, pinfo, tree, offset);
        break;
    default:
        return offset;
    }

    return offset;
}

static guint
fEventTimeStamps( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint32     lvt     = 0;
    proto_tree* subtree = tree;

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        subtree = proto_tree_add_subtree(tree, tvb, offset, lvt, ett_bacapp_tag, NULL, "eventTimeStamps");

        offset = fTimeStamp(tvb, pinfo, subtree, offset, "TO-OFFNORMAL timestamp: ");
        offset = fTimeStamp(tvb, pinfo, subtree, offset, "TO-FAULT timestamp: ");
        offset = fTimeStamp(tvb, pinfo, subtree, offset, "TO-NORMAL timestamp: ");
    }
    return offset;
}

static guint
fTimeStamp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label)
{
    guint8  tag_no = 0, tag_info = 0;
    guint32 lvt    = 0;

    if (tvb_reported_length_remaining(tvb, offset) > 0) {   /* don't loop, it's a CHOICE */
        switch (fTagNo(tvb, offset)) {
        case 0: /* time */
            offset = fTime(tvb, pinfo, tree, offset, label?label:"time: ");
            break;
        case 1: /* sequenceNumber */
            offset = fUnsignedTag(tvb, pinfo, tree, offset,
                label?label:"sequence number: ");
            break;
        case 2: /* dateTime */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset  = fDateTime(tvb, pinfo, tree, offset, label?label:"date time: ");
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        default:
            return offset;
        }
    }

    return offset;
}


static guint
fClientCOV(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        offset = fApplicationTypes(tvb, pinfo, tree, offset, "increment: ");
    }
    return offset;
}

static const value_string
BACnetDaysOfWeek [] = {
    { 0, "Monday" },
    { 1, "Tuesday" },
    { 2, "Wednesday" },
    { 3, "Thursday" },
    { 4, "Friday" },
    { 5, "Saturday" },
    { 6, "Sunday" },
    { 0, NULL }
};

static guint
fDestination(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset,
                                             "valid Days: ", BACnetDaysOfWeek);
        offset = fTime(tvb, pinfo, tree, offset, "from time: ");
        offset = fTime(tvb, pinfo, tree, offset, "to time: ");
        offset = fRecipient(tvb, pinfo, tree, offset);
        offset = fProcessId(tvb, pinfo, tree, offset);
        offset = fApplicationTypes(tvb, pinfo, tree, offset,
                                    "issue confirmed notifications: ");
        offset = fBitStringTagVS(tvb, pinfo, tree, offset,
                                  "transitions: ", BACnetEventTransitionBits);
    }
    return offset;
}


static guint
fOctetString(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label, guint32 lvt)
{
    gchar      *tmp;
    guint       start   = offset;
    guint8      tag_no, tag_info;
    proto_tree *subtree = tree;

    offset += fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);

    if (lvt > 0) {
        tmp = tvb_bytes_to_str(pinfo->pool, tvb, offset, lvt);
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt,
                    ett_bacapp_tag, NULL, "%s %s", label, tmp);
        offset += lvt;
    }

    fTagHeaderTree(tvb, pinfo, subtree, start, &tag_no, &tag_info, &lvt);

    return offset;
}

static guint
fMacAddress(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label, guint32 lvt)
{
    guint start = offset;
    guint8 tag_no, tag_info;
    proto_tree* subtree = tree;

    offset += fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);

    /* just add the label, with the tagHeader information in its subtree */
    subtree = proto_tree_add_subtree(tree, tvb, offset, lvt, ett_bacapp_tag, NULL, label);

    if (lvt == 6) { /* we have 6 Byte IP Address with 4 Octets IPv4 and 2 Octets Port Information */
        proto_tree_add_item(tree, hf_bacapp_tag_IPV4, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_bacapp_tag_PORT, tvb, offset+4, 2, ENC_BIG_ENDIAN);
    } else if (lvt == 18) { /* we have 18 Byte IP Address with 16 Octets IPv6 and 2 Octets Port Information */
        proto_tree_add_item(tree, hf_bacapp_tag_IPV6, tvb, offset, 16, ENC_NA);
        proto_tree_add_item(tree, hf_bacapp_tag_PORT, tvb, offset+16, 2, ENC_BIG_ENDIAN);
    } else { /* we have 1 Byte MS/TP Address or anything else interpreted as an address */
        subtree = proto_tree_add_subtree(tree, tvb, offset, lvt,
                ett_bacapp_tag, NULL, tvb_bytes_to_str(pinfo->pool, tvb, offset, lvt));
    }
    offset += lvt;

    fTagHeaderTree(tvb, pinfo, subtree, start, &tag_no, &tag_info, &lvt);

    return offset;
}

static guint
fAddress(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8  tag_no, tag_info;
    guint32 lvt;
    guint   offs;

    offset = fUnsignedTag(tvb, pinfo, tree, offset, "network-number");
    offs   = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    if (lvt == 0) {
        proto_tree_add_item(tree, hf_bacapp_tag_mac_address_broadcast, tvb, offset, offs, ENC_NA);
        offset += offs;
    } else
        offset  = fMacAddress(tvb, pinfo, tree, offset, "MAC-address: ", lvt);

    return offset;
}

static guint
fSessionKey(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    offset = fOctetString(tvb, pinfo, tree, offset, "session key: ", 8);
    return fAddress(tvb, pinfo, tree, offset);
}

static guint
fObjectIdentifier(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label)
{
    guint8      tag_no, tag_info;
    guint32     lvt;
    guint       tag_length;
    proto_tree *subtree;
    guint32     object_id;

    tag_length  = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    object_id   = tvb_get_ntohl(tvb, offset+tag_length);
    object_type = object_id_type(object_id);
    subtree = proto_tree_add_subtree_format(tree, tvb, offset, tag_length + 4,
            ett_bacapp_tag, NULL, "%s%s, %u", label,
            val_to_split_str(object_type,
                128,
                BACnetObjectType,
                ASHRAE_Reserved_Fmt,
                Vendor_Proprietary_Fmt),
            object_id_instance(object_id));

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s,%u ",
            val_to_split_str(object_type,
                128,
                BACnetObjectType,
                ASHRAE_Reserved_Fmt,
                Vendor_Proprietary_Fmt),
                object_id_instance(object_id));

    /* update BACnet Statistics */
    updateBacnetInfoValue(BACINFO_OBJECTID,
                  wmem_strdup(pinfo->pool,
                    val_to_split_str(object_type, 128,
                    BACnetObjectType, ASHRAE_Reserved_Fmt,
                    Vendor_Proprietary_Fmt)));
    updateBacnetInfoValue(BACINFO_INSTANCEID,
                  wmem_strdup_printf(pinfo->pool,
                    "Instance ID: %u",
                    object_id_instance(object_id)));

    /* here are the details of how we arrived at the above text */
    fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
    offset += tag_length;
    proto_tree_add_item(subtree, hf_bacapp_objectType, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_bacapp_instanceNumber, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

static guint
fObjectName(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    return fCharacterStringBase(tvb, pinfo, tree, offset, "Object Name", FALSE, TRUE);
}

static guint
fRecipient(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8  tag_no, tag_info;
    guint32 lvt;

    fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    if (tag_no < 2) {
        if (tag_no == 0) { /* device */
            offset = fObjectIdentifier(tvb, pinfo, tree, offset, "DeviceIdentifier: ");
        }
        else {  /* address */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset  = fAddress(tvb, pinfo, tree, offset);
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
        }
    }
    return offset;
}

static guint
fRecipientProcess(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       lastoffset = 0;
    guint8      tag_no, tag_info;
    guint32     lvt;
    proto_tree *orgtree    = tree;
    proto_tree *subtree;

    /* beginning of new item - indent and label */
    tree = proto_tree_add_subtree(orgtree, tvb, offset, 1, ett_bacapp_value, NULL, "Recipient Process" );

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;

        switch (fTagNo(tvb, offset)) {
        case 0: /* recipient */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt); /* show context open */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_bacapp_value, NULL, "Recipient");    /* add tree label and indent */
            offset  = fRecipient(tvb, pinfo, subtree, offset);
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt); /* show context close */
            break;
        case 1: /* processId */
            offset = fProcessId(tvb, pinfo, tree, offset);
            lastoffset = offset;
            break;
        default:
            break;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fCOVSubscription(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       lastoffset = 0;
    guint8      tag_no, tag_info;
    guint32     lvt;
    proto_tree *subtree;
    proto_tree *orgtree    = tree;
    guint       itemno     = 1;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info) ) {
            return offset;
        }
        switch (tag_no) {

        case 0: /* recipient */
            /* beginning of new item in list */
            tree = proto_tree_add_subtree_format(orgtree, tvb, offset, 1,
                ett_bacapp_value, NULL, "Subscription %d",itemno);    /* add tree label and indent */
            itemno = itemno + 1;

            subtree = proto_tree_add_subtree(tree, tvb, offset, 1,
                ett_bacapp_value, NULL, "Recipient");    /* add tree label and indent */
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt); /* show context open */
            offset  = fRecipientProcess(tvb, pinfo, subtree, offset);
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);  /* show context close */
            break;
        case 1: /* MonitoredPropertyReference */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 1,
                ett_bacapp_value, NULL, "Monitored Property Reference");
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            offset  = fBACnetObjectPropertyReference(tvb, pinfo, subtree, offset);
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 2: /* IssueConfirmedNotifications - boolean */
            offset = fBooleanTag(tvb, pinfo, tree, offset, "Issue Confirmed Notifications: ");
            break;
        case 3: /* TimeRemaining */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "Time Remaining: ");
            break;
        case 4: /* COVIncrement */
            offset = fRealTag(tvb, pinfo, tree, offset, "COV Increment: ");
            break;
        default:
            break;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fAddressBinding(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    offset = fObjectIdentifier(tvb, pinfo, tree, offset, "DeviceIdentifier: ");
    return fAddress(tvb, pinfo, tree, offset);
}

static guint
fActionCommand(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint8 tag_match)
{
    guint       lastoffset = 0, len;
    guint8      tag_no, tag_info;
    guint32     lvt;
    proto_tree *subtree    = tree;

    /* set the optional global properties to indicate not-used */
    propertyArrayIndex = -1;
    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
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
            offset = fObjectIdentifier(tvb, pinfo, subtree, offset, "DeviceIdentifier: ");
            break;
        case 1: /* objectIdentifier */
            offset = fObjectIdentifier(tvb, pinfo, subtree, offset, "ObjectIdentifier: ");
            break;
        case 2: /* propertyIdentifier */
            offset = fPropertyIdentifier(tvb, pinfo, subtree, offset);
            break;
        case 3: /* propertyArrayIndex */
            offset = fPropertyArrayIndex(tvb, pinfo, subtree, offset);
            break;
        case 4: /* propertyValue */
            offset = fPropertyValue(tvb, pinfo, subtree, offset, tag_info);
            break;
        case 5: /* priority */
            offset = fUnsignedTag(tvb, pinfo, subtree, offset, "Priority: ");
            break;
        case 6: /* postDelay */
            offset = fUnsignedTag(tvb, pinfo, subtree, offset, "Post Delay: ");
            break;
        case 7: /* quitOnFailure */
            offset = fBooleanTag(tvb, pinfo, subtree, offset,
                "Quit On Failure: ");
            break;
        case 8: /* writeSuccessful */
            offset = fBooleanTag(tvb, pinfo, subtree, offset,
                "Write Successful: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

/* BACnetActionList ::= SEQUENCE{
      action [0] SEQUENCE OF BACnetActionCommand
      }
*/
static guint
fActionList(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       lastoffset = 0, len;
    guint8      tag_no, tag_info;
    guint32     lvt;
    proto_tree *subtree    = tree;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        lastoffset = offset;
        len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            if ( tag_no != 0 ) /* don't eat the closing property tag, just return */
                return offset;
            /* print closing tag of action list too */
            fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            subtree = tree;
            offset += len;
            continue;
        }
        if (tag_is_opening(tag_info)) {
            subtree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_bacapp_tag, NULL, "Action List");
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset,
                &tag_no, &tag_info, &lvt);
        }
        switch (tag_no) {
        case 0: /* BACnetActionCommand */
            offset = fActionCommand(tvb, pinfo, subtree, offset, tag_no);
            break;
        default:
            break;
        }
        if (offset <= lastoffset) break;    /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fPropertyAccessResult(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
  guint       lastoffset = 0;
  guint8      tag_no, tag_info;
  guint32     lvt;
  guint32     save_object_type;
  guint32     save_inner_object_type;
  gint32      save_propertyIdentifier;

  /* save the external entry data because it might get overwritten here */
  save_object_type = object_type;
  save_propertyIdentifier = propertyIdentifier;

  /* inner object type might get overwritten by device id */
  save_inner_object_type = object_type;

  while (tvb_reported_length_remaining(tvb, offset) > 0) {
    lastoffset = offset;
    fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    if (tag_is_closing(tag_info)) {
        break;
    }

    switch (tag_no) {
    case 0: /* objectIdentifier */
        offset = fObjectIdentifier(tvb, pinfo, tree, offset, "ObjectIdentifier: ");
        /* save the local object type because device id might overwrite it */
        save_inner_object_type = object_type;
        break;
    case 1: /* propertyIdentifier */
        offset = fPropertyIdentifier(tvb, pinfo, tree, offset);
        break;
    case 2: /* propertyArrayIndex */
        offset = fPropertyArrayIndex(tvb, pinfo, tree, offset);
        break;
    case 3: /* deviceIdentifier */
        offset = fObjectIdentifier(tvb, pinfo, tree, offset, "DeviceIdentifier: ");
        /* restore the inner object type to decode the right property value */
        object_type = save_inner_object_type;
        break;
    case 4: /* propertyValue */
        offset = fPropertyValue(tvb, pinfo, tree, offset, tag_info);
        /* restore the external values for next loop */
        object_type = save_object_type;
        propertyIdentifier = save_propertyIdentifier;
        break;
    case 5: /* propertyAccessError */
        if (tag_is_opening(tag_info)) {
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset = fError(tvb, pinfo, tree, offset);
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
        }
        else {
            expert_add_info(pinfo, tree, &ei_bacapp_bad_tag);
        }
        /* restore the external values for next loop */
        object_type = save_object_type;
        propertyIdentifier = save_propertyIdentifier;
        break;
    default:
        break;
    }

    if (offset <= lastoffset) break;    /* nothing happened, exit loop */
  }

  /* restore the external values for next decoding */
  object_type = save_object_type;
  propertyIdentifier = save_propertyIdentifier;
  return offset;
}

static guint
fPropertyIdentifier(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8       tag_no, tag_info;
    guint32      lvt;
    guint        tag_len;
    proto_tree  *subtree;
    const gchar *label = "Property Identifier";

    propertyIdentifier = 0; /* global Variable */
    tag_len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    /* can we decode this value? */
    if (fUnsigned32(tvb, offset+tag_len, lvt, (guint32 *)&propertyIdentifier)) {
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
            ett_bacapp_tag, NULL,
            "%s: %s (%u)", label,
            val_to_split_str(propertyIdentifier, 512,
                BACnetPropertyIdentifier,
                ASHRAE_Reserved_Fmt,
                Vendor_Proprietary_Fmt), propertyIdentifier);
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
                val_to_split_str(propertyIdentifier, 512,
                    BACnetPropertyIdentifier,
                    ASHRAE_Reserved_Fmt,
                    Vendor_Proprietary_Fmt));
    } else {
        /* property identifiers cannot be larger than 22-bits */
        return offset;
    }

    fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
    proto_tree_add_item(subtree, hf_BACnetPropertyIdentifier, tvb,
        offset+tag_len, lvt, ENC_BIG_ENDIAN);

    return offset+tag_len+lvt;
}

static guint
fPropertyArrayIndex(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8      tag_no, tag_info;
    guint32     lvt;
    guint       tag_len;
    proto_tree *subtree;

    tag_len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    if (fUnsigned32(tvb, offset + tag_len, lvt, (guint32 *)&propertyArrayIndex))
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
            ett_bacapp_tag, NULL, "property Array Index (Unsigned) %u", propertyArrayIndex);
    else
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
            ett_bacapp_tag, NULL, "property Array Index - %u octets (Unsigned)", lvt);
    fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);

    return offset+tag_len+lvt;
}

static guint
fChannelValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label)
{
  guint8      tag_no, tag_info;
  guint32     lvt;

  if (tvb_reported_length_remaining(tvb, offset) > 0) {
      fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
      if (tag_is_opening(tag_info) && tag_no == 0) {
          offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
          offset = fLightingCommand(tvb, pinfo, tree, offset, "lighting-command: ");
          offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
      } else if (tag_is_opening(tag_info) && tag_no == 1) {
          offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
          offset = fXyColor(tvb, pinfo, tree, offset, "xy-color: ");
          offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
      } else if (tag_is_opening(tag_info) && tag_no == 2) {
          offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
          offset = fColorCommand(tvb, pinfo, tree, offset, "color-command: ");
          offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
      } else {
          if (tag_info) {
              offset = fContextTaggedValue(tvb, pinfo, tree, offset, label);
          } else {
              offset = fApplicationTypes(tvb, pinfo, tree, offset, label);
          }
      }
  }

  return offset;
}

static guint
fCharacterString(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label)
{
    return fCharacterStringBase(tvb, pinfo, tree, offset, label, FALSE, FALSE);
}

static guint
fCharacterStringBase(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label, gboolean present_val_dissect, gboolean object_name_dissect)
{
    guint8          tag_no, tag_info, character_set;
    guint32         lvt, l;
    guint           offs;
    const char     *coding;
    guint8         *out;
    proto_tree     *subtree;
    guint           start = offset;

    if (tvb_reported_length_remaining(tvb, offset) > 0) {

        offs = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        offset += offs;

        character_set = tvb_get_guint8(tvb, offset);
        offset++;
        lvt--;

        /* Account for code page if DBCS */
        if (character_set == IBM_MS_DBCS) {
            offset += 2;
            lvt -= 2;
        }

        do {
            l = MIN(lvt, 256);
            /*
             * XXX - are we guaranteed that these encoding
             * names correspond, on *all* platforms with
             * iconv(), to the encodings we want?
             *
             * Not necessarily. These specify "character sets" but
             * not the encodings. IBM/MS DBCS specifies that it uses
             * some IBM or MS double byte character set, but does not
             * specify the code page - there was a proposal to explicitly
             * add the code page, but that was apparently withdrawn in favor
             * of just deprecating using DBCS, as it never got past a draft
             * (One problem could be that IBM and MS code pages with the
             * same number are slightly different, and then there's non
             * IBM/MS unofficial ones that got used, sometimes conflicting
             * numbers.) Even if we assume that they certainly mean one
             * of the DBCS and not just any non ISO-8859-1 code page, there's
             * all four types of CJK to choose from. -
             * http://www.bacnet.org/Addenda/Add-135-2004k-PPR1-chair-approved.pdf
             * JIS C 6226 (now JIS X 0208)
             * http://www.bacnet.org/Addenda/Add-135-2008k.pdf
             * is a character set, which are supported by several different
             * encodings, the main types being ISO-2022-JP (JIS X 0202,
             * a 7 bit encoding), Shift-JIS (most common), and EUC-JP (UNIX).
             * It is unclear which encoding this refers to.
             *
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
            /** this decoding may be not correct for multi-byte characters, Lka */
            switch (character_set) {
            case ANSI_X3_4:
                out = tvb_get_string_enc(pinfo->pool, tvb, offset, l, ENC_UTF_8);
                coding = "UTF-8";
                break;
            case IBM_MS_DBCS:
                out = tvb_get_string_enc(pinfo->pool, tvb, offset, l, ENC_ASCII);
                coding = "IBM MS DBCS";
                break;
            case JIS_C_6226:
                out = tvb_get_string_enc(pinfo->pool, tvb, offset, l, ENC_ASCII);
                coding = "JIS C 6226";
                break;
            case ISO_10646_UCS4:
                out = tvb_get_string_enc(pinfo->pool, tvb, offset, l, ENC_UCS_4|ENC_BIG_ENDIAN);
                coding = "ISO 10646 UCS-4";
                break;
            case ISO_10646_UCS2:
                out = tvb_get_string_enc(pinfo->pool, tvb, offset, l, ENC_UCS_2|ENC_BIG_ENDIAN);
                coding = "ISO 10646 UCS-2";
                break;
            case ISO_8859_1:
                out = tvb_get_string_enc(pinfo->pool, tvb, offset, l, ENC_ISO_8859_1);
                coding = "ISO 8859-1";
                break;
            default:
                /* Assume this is some form of extended ASCII, with one-byte code points for ASCII characters */
                out = tvb_get_string_enc(pinfo->pool, tvb, offset, l, ENC_ASCII);
                coding = "unknown";
                break;
            }

            if (present_val_dissect) {
                subtree = proto_tree_add_subtree(tree, tvb, offset, l, ett_bacapp_tag, NULL, "present-value");
                proto_tree_add_string(subtree, hf_bacapp_present_value_char_string, tvb, offset, l, (const gchar*) out);
            } else if (object_name_dissect) {
                subtree = proto_tree_add_subtree(tree, tvb, offset, l, ett_bacapp_tag, NULL, label);
                proto_tree_add_string(subtree, hf_bacapp_object_name, tvb, offset, l, (const gchar*) out);
            } else {
                subtree = proto_tree_add_subtree_format(tree, tvb, offset, l, ett_bacapp_tag, NULL,
                                    "%s%s '%s'", label, coding, out);
            }

            lvt    -= l;
            offset += l;
        } while (lvt > 0);

        fTagHeaderTree(tvb, pinfo, subtree, start, &tag_no, &tag_info, &lvt);
        proto_tree_add_item(subtree, hf_BACnetCharacterSet, tvb, start+offs, 1, ENC_BIG_ENDIAN);

        if (character_set == IBM_MS_DBCS) {
            proto_tree_add_item(subtree, hf_BACnetCodePage, tvb, start+offs+1, 2, ENC_BIG_ENDIAN);
        }
        /* XXX - put the string value here */
    }
    return offset;
}

static guint
fBitStringTagVS(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label,
    const value_string *src)
{
    return fBitStringTagVSBase(tvb, pinfo, tree, offset, label, src, FALSE);
}

static guint
fBitStringTagVSBase(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label,
    const value_string *src, gboolean present_val_dissect)
{
    guint8          tag_no, tag_info, tmp;
    gint            j, unused, skip;
    guint           start = offset;
    guint           offs;
    guint32         lvt, i, numberOfBytes;
    guint8          bf_arr[256 + 1];
    proto_tree     *subtree = tree;

    offs = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    numberOfBytes = lvt-1; /* Ignore byte for unused bit count */
    offset += offs;
    unused  = tvb_get_guint8(tvb, offset); /* get the unused Bits */

    memset(bf_arr, 0, sizeof(bf_arr));
    skip = 0;
    for (i = 0; i < numberOfBytes; i++) {
        tmp = tvb_get_guint8(tvb, (offset)+i + 1);
        if (i == numberOfBytes - 1) { skip = unused; }
        for (j = 0; j < 8 - skip; j++) {
            bf_arr[MIN(255, (i * 8) + j)] = tmp & (1 << (7 - j)) ? 'T' : 'F';
        }
    }

    if (!present_val_dissect) {
        subtree = proto_tree_add_subtree_format(tree, tvb, start, offs+lvt,
                                    ett_bacapp_tag, NULL,
                                    "%s(Bit String) (%s)", label, bf_arr);
    } else {
        subtree = proto_tree_add_subtree(tree, tvb, offset, offs+lvt, ett_bacapp_tag, NULL, "present-value");
        proto_tree_add_string(subtree, hf_bacapp_present_value_bit_string, tvb, offset, offs+lvt, bf_arr);
    }

    fTagHeaderTree(tvb, pinfo, subtree, start, &tag_no, &tag_info, &lvt);
    proto_tree_add_item(subtree, hf_bacapp_unused_bits, tvb, offset, 1, ENC_NA);
    memset(bf_arr, 0, sizeof(bf_arr));
    skip = 0;
    for (i = 0; i < numberOfBytes; i++) {
        tmp = tvb_get_guint8(tvb, (offset)+i+1);
        if (i == numberOfBytes-1) { skip = unused; }
        for (j = 0; j < 8-skip; j++) {
            if (src != NULL) {
                proto_tree_add_boolean_format(subtree, hf_bacapp_bit, tvb, offset+i+1, 1,
                                            (tmp & (1 << (7 - j))), "%s = %s",
                                            val_to_str((guint) (i*8 +j), src, ASHRAE_Reserved_Fmt),
                                            (tmp & (1 << (7 - j))) ? "TRUE" : "FALSE");
            } else {
                bf_arr[MIN(255, (i*8)+j)] = tmp & (1 << (7 - j)) ? '1' : '0';
            }
        }
    }

    if (src == NULL) {
        bf_arr[MIN(255, numberOfBytes*8-unused)] = 0;
        proto_tree_add_bytes_format(subtree, hf_bacapp_complete_bitstring, tvb, offset, lvt, NULL, "B'%s'", bf_arr);
    }

    offset += lvt;

    return offset;
}

static guint
fBitStringTag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label)
{
    return fBitStringTagVS(tvb, pinfo, tree, offset, label, NULL);
}

/* handles generic application types, as well as enumerated and enumerations
   with reserved and proprietarty ranges (split) */
static guint
fApplicationTypesEnumeratedSplit(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset,
    const gchar *label, const value_string *src, guint32 split_val)
{
    guint8  tag_no, tag_info;
    guint32 lvt;
    guint   tag_len;

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        tag_len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (!tag_is_context_specific(tag_info)) {
            switch (tag_no) {
            case 0: /** NULL 20.2.2 */
                offset = fNullTag(tvb, pinfo, tree, offset, label);
                break;
            case 1: /** BOOLEAN 20.2.3 */
                offset = fBooleanTag(tvb, pinfo, tree, offset, label);
                break;
            case 2: /** Unsigned Integer 20.2.4 */
                offset = fUnsignedTag(tvb, pinfo, tree, offset, label);
                break;
            case 3: /** Signed Integer 20.2.5 */
                offset = fSignedTag(tvb, pinfo, tree, offset, label);
                break;
            case 4: /** Real 20.2.6 */
                offset = fRealTag(tvb, pinfo, tree, offset, label);
                break;
            case 5: /** Double 20.2.7 */
                offset = fDoubleTag(tvb, pinfo, tree, offset, label);
                break;
            case 6: /** Octet String 20.2.8 */
                offset = fOctetString(tvb, pinfo, tree, offset, label, lvt);
                break;
            case 7: /** Character String 20.2.9 */
                offset = fCharacterString(tvb, pinfo, tree, offset, label);
                break;
            case 8: /** Bit String 20.2.10 */
                offset = fBitStringTagVS(tvb, pinfo, tree, offset, label, src);
                break;
            case 9: /** Enumerated 20.2.11 */
                offset = fEnumeratedTagSplit(tvb, pinfo, tree, offset, label, src, split_val);
                break;
            case 10: /** Date 20.2.12 */
                offset = fDate(tvb, pinfo, tree, offset, label);
                break;
            case 11: /** Time 20.2.13 */
                offset = fTime(tvb, pinfo, tree, offset, label);
                break;
            case 12: /** BACnetObjectIdentifier 20.2.14 */
                offset = fObjectIdentifier(tvb, pinfo, tree, offset, "ObjectIdentifier: ");
                break;
            case 13: /* reserved for ASHRAE */
            case 14:
            case 15:
                proto_tree_add_bytes_format(tree, hf_bacapp_reserved_ashrea, tvb, offset, lvt+tag_len, NULL, "%s'reserved for ASHRAE'", label);
                offset += lvt + tag_len;
                break;
            default:
                break;
            }
        }
    }
    return offset;
}

static guint
fShedLevel(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;

        switch (fTagNo(tvb, offset)) {
        case 0: /* percent */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "shed percent: ");
            break;
        case 1: /* level */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "shed level: ");
            break;
        case 2: /* amount */
            offset = fRealTag(tvb, pinfo, tree, offset, "shed amount: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fApplicationTypesEnumerated(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset,
    const gchar *label, const value_string *vs)
{
    return fApplicationTypesEnumeratedSplit(tvb, pinfo, tree, offset, label, vs, 0);
}

static guint
fApplicationTypes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset,
    const gchar *label)
{
    return fApplicationTypesEnumeratedSplit(tvb, pinfo, tree, offset, label, NULL, 0);
}

static guint
fContextTaggedValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label)
{
    guint8      tag_no, tag_info;
    guint32     lvt;
    guint       tag_len;
    proto_tree *subtree;
    gint        tvb_len;

    (void)label;
    tag_len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    /* cap the the suggested length in case of bad data */
    tvb_len = tvb_reported_length_remaining(tvb, offset+tag_len);
    if ((tvb_len >= 0) && ((guint32)tvb_len < lvt)) {
        lvt = tvb_len;
    }
    subtree = proto_tree_add_subtree_format(tree, tvb, offset+tag_len, lvt,
        ett_bacapp_tag, NULL, "Context Value (as %u DATA octets)", lvt);

    fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);

    return offset + tag_len + lvt;
}
/*
BACnetPrescale ::= SEQUENCE {
    multiplier  [0] Unsigned,
moduloDivide    [1] Unsigned
}
*/
static guint
fPrescale(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8  tag_no, tag_info;
    guint32 lvt;
    guint   lastoffset = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info) ) {
            return offset;
            }
        switch (tag_no) {
        case 0: /* multiplier */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "Multiplier: ");
            break;
        case 1: /* moduloDivide */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "Modulo Divide: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;

}
/*
BACnetScale ::= CHOICE {
    floatScale  [0] REAL,
integerScale    [1] INTEGER
}
*/
static guint
fScale(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8  tag_no, tag_info;
    guint32 lvt;
    guint   lastoffset = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info) ) {
            return offset;
            }
        switch (tag_no) {
        case 0: /* floatScale */
            offset = fRealTag(tvb, pinfo, tree, offset, "Float Scale: ");
            break;
        case 1: /* integerScale */
            offset = fSignedTag(tvb, pinfo, tree, offset, "Integer Scale: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}
/*
BACnetAccumulatorRecord ::= SEQUENCE {
    timestamp       [0] BACnetDateTime,
    presentValue        [1] Unsigned,
    accumulatedValue    [2] Unsigned,
    accumulatortStatus  [3] ENUMERATED {
                    normal          (0),
                    starting        (1),
                    recovered       (2),
                    abnormal        (3),
                    failed          (4)
                    }
}
*/
static guint
fLoggingRecord(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8  tag_no, tag_info;
    guint32 lvt;
    guint   lastoffset = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info) ) {
            return offset;
            }
        switch (tag_no) {
        case 0: /* timestamp */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset  = fDateTime(tvb, pinfo, tree, offset, "Timestamp: ");
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 1: /* presentValue */
            offset = fPresentValue(tvb, pinfo, tree, offset, NULL, 0, BACAPP_PRESENT_VALUE_UNSIGNED);
            break;
        case 2: /* accumulatedValue */
            offset  = fUnsignedTag(tvb, pinfo, tree, offset, "Accumulated Value: ");
            break;
        case 3: /* accumulatorStatus */
            offset  = fEnumeratedTag(tvb, pinfo, tree, offset, "Accumulator Status: ", BACnetAccumulatorStatus);
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

/*
 SEQ OF Any enumeration (current usage is SEQ OF BACnetDoorAlarmState
*/
static guint
fSequenceOfEnums(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *label, const value_string *vs)
{
    guint8  tag_no, tag_info;
    guint32 lvt;
    guint   lastoffset = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info) ) {
            return offset;
            }
        offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, label, vs);
        if ( offset <= lastoffset ) break;
    }
    return offset;
}

/*
SEQ OF BACnetDeviceObjectReference (accessed as an array)
}
*/
static guint
fDoorMembers(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8  tag_no, tag_info;
    guint32 lvt;
    guint   lastoffset = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info) ) {
            return offset;
            }
        offset = fDeviceObjectReference(tvb, pinfo, tree, offset);
        if (offset <= lastoffset) break;
    }
    return offset;
}

/*
SEQ OF ReadAccessSpecification
*/
static guint
fListOfGroupMembers(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8  tag_no, tag_info;
    guint32 lvt;
    guint   lastoffset = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info) ) {
            return offset;
            }
        offset = fReadAccessSpecification(tvb, pinfo, tree, offset);
        if ( offset <= lastoffset ) break;
    }
    return offset;
}

static guint
fAbstractSyntaxNType(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8  tag_no, tag_info;
    guint32 lvt;
    guint   lastoffset = 0, depth = 0;
    char    ar[256];
    guint32 save_object_type;
    gboolean do_default_handling;

    if (propertyIdentifier >= 0) {
        snprintf(ar, sizeof(ar), "%s: ",
            val_to_split_str(propertyIdentifier, 512,
                BACnetPropertyIdentifier,
                ASHRAE_Reserved_Fmt,
                Vendor_Proprietary_Fmt));
    } else {
        snprintf(ar, sizeof(ar), "Abstract Type: ");
    }

    unsigned recursion_depth = p_get_proto_depth(pinfo, proto_bacapp);
    if (++recursion_depth >= BACAPP_MAX_RECURSION_DEPTH) {
        proto_tree_add_expert(tree, pinfo, &ei_bacapp_max_recursion_depth_reached, tvb, 0, 0);
        return offset;
    }
    p_set_proto_depth(pinfo, proto_bacapp, recursion_depth);

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) { /* closing tag, but not for me */
            if (depth <= 0) {
                goto cleanup;
            }
        }

        do_default_handling = FALSE;

        /* Application Tags */
        switch (propertyIdentifier) {
        case 0: /* acked-transitions */
        case 35: /* event-enable */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar,
            BACnetAcknowledgedTransitions);
            break;
        case 2: /* action */
                /* loop object is application tagged,
                    command object is context tagged */
                if (tag_is_context_specific(tag_info)) {
                    /* BACnetActionList */
                    offset = fActionList(tvb, pinfo, tree, offset);
                } else {
                    /* BACnetAction */
                    offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar,
                        BACnetAction);
                }
                break;
        case 7: /* alarm-values*/
            switch (object_type) {
            case 21: /* life-point */
            case 22: /* life-zone */
              offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetLifeSafetyState);
              break;
            case 30: /* access-door */
              offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetDoorAlarmState);
              break;
            case 31: /* timer */
              offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetTimerState);
              break;
            case 36: /* access-zone */
              offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetAccessZoneOccupancyState);
              break;
            case 39: /* bitstring-value */
            default:
              if (tag_info) {
                if (tag_is_opening(tag_info)) {
                  ++depth;
                  offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                }
                else if (tag_is_closing(tag_info)) {
                  --depth;
                  offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                }
                else {
                  offset = fContextTaggedValue(tvb, pinfo, tree, offset, ar);
                }
              }
              else {
                offset = fApplicationTypes(tvb, pinfo, tree, offset, ar);
              }
              break;
            }
            break;
        case 37: /* event-type */
            offset = fEventType(tvb, pinfo, tree, offset);
            break;
        case 39: /* fault-values */
            switch (object_type) {
            case 21: /* life-point */
            case 22: /* life-zone */
              offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetLifeSafetyState);
              break;
            case 30: /* access-door */
              offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetDoorAlarmState);
              break;
            case 31: /* timer */
              offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetTimerState);
              break;
            case 36: /* access-zone */
              offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetAccessZoneOccupancyState);
              break;
            case 39: /* bitstring-value */
            default:
              if (tag_info) {
                if (tag_is_opening(tag_info)) {
                  ++depth;
                  offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                }
                else if (tag_is_closing(tag_info)) {
                  --depth;
                  offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                }
                else {
                  offset = fContextTaggedValue(tvb, pinfo, tree, offset, ar);
                }
              }
              else {
                offset = fApplicationTypes(tvb, pinfo, tree, offset, ar);
              }
              break;
            }
            break;
        case 30: /* BACnetAddressBinding */
        case 331: /* last-key-server */
            offset = fAddressBinding(tvb, pinfo, tree, offset);
            break;
        case 52: /* limit-enable */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetLimitEnable);
            break;
        case 54: /* list of object property reference */
            offset = fLOPR(tvb, pinfo, tree, offset);
            break;
        case 55: /* list-of-session-keys */
            fSessionKey(tvb, pinfo, tree, offset);
            break;
        case 77: /* object-name */
            offset = fObjectName(tvb, pinfo, tree, offset);
            break;
        case 79: /* object-type */
        case 96: /* protocol-object-types-supported */
            offset = fApplicationTypesEnumeratedSplit(tvb, pinfo, tree, offset, ar,
                BACnetObjectType, 128);
            break;
        case 97: /* Protocol-Services-Supported */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar,
                BACnetServicesSupported);
            break;
        case 102: /* recipient-list */
            offset = fDestination(tvb, pinfo, tree, offset);
            break;
        case 107: /* segmentation-supported */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar,
                BACnetSegmentation);
            break;
        case 111: /* Status-Flags */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar,
                BACnetStatusFlags);
            break;
        case 112: /* System-Status */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar,
                BACnetDeviceStatus);
            break;
        case 117: /* units */
        case 455: /* car-load-units */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar,
                BACnetEngineeringUnits);
            break;
        case 87:    /* priority-array -- accessed as a BACnetARRAY */
            if (propertyArrayIndex == 0) {
                /* BACnetARRAY index 0 refers to the length
                of the array, not the elements of the array */
                offset = fApplicationTypes(tvb, pinfo, tree, offset, ar);
            } else {
                offset = fPriorityArray(tvb, pinfo, tree, offset);
            }
            break;
        case 38:    /* exception-schedule */
            if (object_type < 128) {
                if (propertyArrayIndex == 0) {
                    /* BACnetARRAY index 0 refers to the length
                    of the array, not the elements of the array */
                    offset = fApplicationTypes(tvb, pinfo, tree, offset, ar);
                } else {
                    offset = fSpecialEvent(tvb, pinfo, tree, offset);
                }
            }
            break;
        case 19:  /* controlled-variable-reference */
        case 60:  /* manipulated-variable-reference */
        case 78:  /* object-property-reference */
        case 181: /* input-reference */
        case 355: /* event-algorithm-inhibit-reference */
            offset = fObjectPropertyReference(tvb, pinfo, tree, offset);
            break;
        case 132: /* log-device-object-property */
            offset = fDeviceObjectPropertyReference(tvb, pinfo, tree, offset);
            break;
        case 109: /* Setpoint-Reference */
            /* setpoint-Reference is actually BACnetSetpointReference which is a SEQ of [0] */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset = fBACnetObjectPropertyReference(tvb, pinfo, tree, offset);
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 123:   /* weekly-schedule -- accessed as a BACnetARRAY */
            if (object_type < 128) {
                if (propertyArrayIndex == 0) {
                    /* BACnetARRAY index 0 refers to the length
                    of the array, not the elements of the array */
                    offset = fApplicationTypes(tvb, pinfo, tree, offset, ar);
                } else {
                    offset = fWeeklySchedule(tvb, pinfo, tree, offset);
                }
            }
            break;
        case 127:   /* client COV increment */
            offset = fClientCOV(tvb, pinfo, tree, offset);
            break;
        case 131:  /* log-buffer */
            if ( object_type == 61 )
                offset = fAuditLogRecord(tvb, pinfo, tree, offset);
            else if ( object_type == 25 )
                offset = fEventLogRecord(tvb, pinfo, tree, offset);
            else if ( object_type == 27 )
                offset = fLogMultipleRecord(tvb, pinfo, tree, offset);
            else
                offset = fLogRecord(tvb, pinfo, tree, offset);
            break;
        case 159: /* member-of */
        case 165: /* zone-members */
        case 211: /* subordinate-list */
        case 246: /* access-doors */
        case 249: /* access-event-credential */
        case 252: /* accompaniment */
        case 265: /* credentials */
        case 266: /* credentials-in-zone */
        case 277: /* last-credential-added */
        case 279: /* last-credential-removed */
        case 286: /* members */
        case 320: /* zone-from */
        case 321: /* zone-to */
        case 461: /* energy-meter-ref */
        case 491: /* represents */
            offset = fDeviceObjectReference(tvb, pinfo, tree, offset);
            break;
        case 196: /* last-restart-reason */
            offset = fRestartReason(tvb, pinfo, tree, offset);
            break;
        case 212: /* actual-shed-level */
        case 214: /* expected-shed-level */
        case 218: /* requested-shed-level */
            offset = fShedLevel(tvb, pinfo, tree, offset);
            break;
        case 152: /* active-cov-subscriptions */
            offset = fCOVSubscription(tvb, pinfo, tree, offset);
            break;
        case 23: /* date-list */
            offset = fCalendarEntry(tvb, pinfo, tree, offset);
            break;
        case 116: /* time-sychronization-recipients */
        case 206: /* utc-time-synchronization-recipients */
        case 202: /* restart-notification-recipients */
            offset = fRecipient(tvb, pinfo, tree, offset);
            break;
        case 83: /* event-parameters */
            offset = fEventParameter(tvb, pinfo, tree, offset);
            break;
        case 130: /* event-time-stamp */
            if (propertyArrayIndex == 0) {
                /* BACnetARRAY index 0 refers to the length
                of the array, not the elements of the array */
                offset = fApplicationTypes(tvb, pinfo, tree, offset, ar);
            } else {
                offset = fEventTimeStamps(tvb, pinfo, tree, offset);
            }
            break;
        case 197: /* logging-type */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetLoggingType);
            break;
        case 36: /* event-state */
            offset = fApplicationTypesEnumeratedSplit(tvb, pinfo, tree, offset, ar, BACnetEventState, 64);
            break;
        case 103: /* reliability */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetReliability);
            break;
        case 72: /* notify-type */
            offset = fNotifyType(tvb, pinfo, tree, offset);
            break;
        case 208: /* node-type */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetNodeType);
            break;
        case 231: /* door-status */
        case 450: /* car-door-status */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetDoorStatus);
            break;
        case 233: /* lock-status */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetLockStatus);
            break;
        case 235: /* secured-status */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetDoorSecuredStatus);
            break;
        case 158: /* maintenance-required */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetMaintenance);
            break;
        case 92: /* program-state */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetProgramState);
            break;
        case 90: /* program-change */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetProgramRequest);
            break;
        case 100: /* reason-for-halt */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetProgramError);
            break;
        case 157: /* last-restore-time */
            offset = fTimeStamp(tvb, pinfo, tree, offset, ar);
            break;
        case 160: /* mode */
        case 175: /* accepted-modes */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetLifeSafetyMode);
            break;
        case 163: /* silenced */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetSilencedState);
            break;
        case 161: /* operation-expected */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetLifeSafetyOperation);
            break;
        case 164: /* tracking-value */
            if (object_type == 21 || object_type == 22) /* life-safety-point/zone */
                offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetLifeSafetyState);
            else if (object_type == 63) /* color */
                offset = fXyColor(tvb, pinfo, tree, offset, ar);
            else if (object_type == 64) /* color-temperature */
                offset = fUnsignedTag(tvb, pinfo, tree, offset, ar);
            break;
        case 166: /* life-safety-alarm-values */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetLifeSafetyState);
            break;
        case 41: /* file-access-method */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetFileAccessMethod);
            break;
        case 185:  /* prescale */
            offset = fPrescale(tvb, pinfo, tree, offset);
            break;
        case 187:  /* scale */
            offset = fScale(tvb, pinfo, tree, offset);
            break;
        case 189: /* update-time */
            if (object_type == 37)
                offset = fTimeStamp(tvb, pinfo, tree, offset, ar);
            else
                offset = fDateTime(tvb, pinfo, tree, offset, ar);
            break;
        case 184: /* logging-record */
            offset = fLoggingRecord(tvb, pinfo, tree, offset);
            break;
        case 203: /* time-of-device-restart */
            offset = fTimeStamp(tvb, pinfo, tree, offset, ar);
            break;
        case 226: /* door-alarm-state */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetDoorAlarmState);
            break;
        case 228: /* door-members */
            offset = fDoorMembers(tvb, pinfo, tree, offset);
            break;
        case 234: /* masked-alarm-values */
            offset = fSequenceOfEnums(tvb, pinfo, tree, offset, ar, BACnetDoorAlarmState);
            break;
        case 248: /* access-event-authentication-factor */
            offset = fAuthenticationFactor(tvb, pinfo, tree, offset);
            break;
        case 261: /* authorization-mode */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetAuthorizationMode);
            break;
        case 53:  /* list-of-group-members */
            save_object_type = object_type;
            offset = fListOfGroupMembers(tvb, pinfo, tree, offset);
            object_type = save_object_type;
            break;
        case 296: /* occupancy-state */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetAccessZoneOccupancyState);
            break;
        case 300: /* passback-mode */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetAccessPassbackMode);
            break;
        case 303: /* reason-for-disable */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetAccessCredentialDisableReason);
            break;
        case 318: /* user-type */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetAccessUserType);
            break;
        case 330: /* key-sets */
            offset = fSecurityKeySet(tvb, pinfo, tree, offset);
            break;
        case 332: /* network-access-security-policies */
            offset = fNetworkSecurityPolicy(tvb, pinfo, tree, offset);
            break;
        case 338: /* backup-and-restore-state */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetBackupState);
            break;
        case 370: /* write-status */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetWriteStatus);
            break;
        case 385: /* transition */
            if (object_type == 54) /* lighting-output */
                offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetLightingTransition);
            else if (object_type == 63) /* color */
                offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetColorTransition);
            else if (object_type == 64) /* color-temperature */
                offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetColorTransition);
            break;
        case 288: /* negative-access-rules */
        case 302: /* positive-access-rules */
            offset = fAccessRule(tvb, pinfo, tree, offset);
            break;
        case 304: /* suppoprted-formats */
            offset = fAuthenticationFactorFormat(tvb, pinfo, tree, offset);
            break;
        case 327: /* base-device-security-policy */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetSecurityLevel);
            break;
        case 371: /* property-list */
            offset = fSequenceOfEnums(tvb, pinfo, tree, offset, ar, BACnetPropertyIdentifier);
            break;
        case 358: /* fault-parameters */
            offset = fFaultParameter(tvb, pinfo, tree, offset);
            break;
        case 359: /* fault type */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetFaultType);
            break;
        case 362: /* subscribed-recipients */
            offset = fEventNotificationSubscription(tvb, pinfo, tree, offset);
            break;
        case 364: /* authorization-exemptions */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetAuthorizationExemption);
            break;
        case 378: /* in-progress */
            if (object_type == 54) /* lighting-output */
                offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetLightingInProgress);
            else if (object_type == 63) /* color */
                offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetColorOperationInProgress);
            else if (object_type == 64) /* color-temperature */
                offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetColorOperationInProgress);
            break;
        case 380: /* lighting-command */
            offset = fLightingCommand(tvb, pinfo, tree, offset, ar);
            break;
        case 16:  /* change-of-state-time */
        case 71:  /* modification-date */
        case 114: /* time-of-active-time-reset */
        case 115: /* time-of-state-count-reset */
        case 142: /* start-time */
        case 143: /* stop-time */
        case 149: /* maximum-value-time-stamp */
        case 150: /* minimum-value-time-stamp */
        case 179: /* count-change-time */
        case 192: /* value-change-time */
        case 254: /* activation-time */
        case 270: /* expiration-time */
        case 278: /* last-credential-added-time */
        case 280: /* last-credential-removed-time */
        case 281: /* last-use-time */
        case 392: /* time-of-strike-count-reset */
            offset = fDateTime(tvb, pinfo, tree, offset, ar);
            break;
        case 258: /* authentication-policy-list */
            offset = fAuthenticationPolicy(tvb, pinfo, tree, offset);
            break;
        case 395: /* last-state-change */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetTimerTransition);
            break;
        case 396: /* state-change-values */
            offset = fTimerStateChangeValue(tvb, pinfo, tree, offset);
            break;
        case 398: /* timer-state */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetTimerState);
            break;
        case 407: /* bacnet-ip-global-address */
        case 418: /* fd-bbmd-address */
            offset = fHostNPort(tvb, pinfo, tree, offset, ar);
            break;
        case 408: /* bacnet-ip-mode */
        case 435: /* bacnet-ipv6-mode */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetIpMode);
            break;
        case 414: /* bmd-broadcast-distribution-table */
            offset = fBDTEntry(tvb, pinfo, tree, offset, ar);
            break;
        case 415: /* bbmd-foreign-device-table */
            offset = fFDTEntry(tvb, pinfo, tree, offset, ar);
            break;
        case 417: /* command */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetNetworkPortCommand);
            break;
        case 426: /* network-number-quality */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetNetworkNumberQuality);
            break;
        case 427: /* network-type */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetNetworkType);
            break;
        case 428: /* routing-table */
            offset = fRouterEntry(tvb, pinfo, tree, offset);
            break;
        case 429: /* virtual-mac-address-table */
            offset = fVMACEntry(tvb, pinfo, tree, offset);
            break;
        case 430: /* command-time-array */
            if (propertyArrayIndex == 0) {
                /* BACnetARRAY index 0 refers to the length
                of the array, not the elements of the array */
                offset = fApplicationTypes(tvb, pinfo, tree, offset, ar);
            } else {
                offset = fTimeStamp(tvb, pinfo, tree, offset, ar);
            }
            break;
        case 432: /* last-command-time */
            offset = fTimeStamp(tvb, pinfo, tree, offset, ar);
            break;
        case 433: /* value-source */
            offset = fValueSource(tvb, pinfo, tree, offset);
            break;
        case 434: /* value-source-array */
            if (propertyArrayIndex == 0) {
                /* BACnetARRAY index 0 refers to the length
                of the array, not the elements of the array */
                offset = fApplicationTypes(tvb, pinfo, tree, offset, ar);
            } else {
                offset = fValueSource(tvb, pinfo, tree, offset);
            }
            break;
        case 447: /* assigned-landing-calls */
            offset = fAssignedLandingCalls(tvb, pinfo, tree, offset);
            break;
        case 448: /* car-assigned-direction */
        case 457: /* car-moving-direction */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetLiftCarDirection);
            break;
        case 449: /* car-door-command */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetLiftCarDoorCommand);
            break;
        case 453: /* car-drive-status */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetLiftCarDriveStatus);
            break;
        case 456: /* car-mode */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetLiftCarMode);
            break;
        case 462: /* escalator-mode */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetEscalatorMode);
            break;
        case 463: /* fault-signals */
            if (propertyArrayIndex == 0) {
                /* BACnetARRAY index 0 refers to the length
                of the array, not the elements of the array */
                offset = fApplicationTypes(tvb, pinfo, tree, offset, ar);
            } else {
                if (object_type == 59) /* lift object */
                    offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetLiftFault);
                else
                    offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetEscalatorFault);
            }
            break;
        case 467: /* group-mode */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetLiftGroupMode);
            break;
        case 470: /* landing-calls */
            if (propertyArrayIndex == 0) {
                /* BACnetARRAY index 0 refers to the length
                of the array, not the elements of the array */
                offset = fApplicationTypes(tvb, pinfo, tree, offset, ar);
            } else {
                offset = fLandingCallStatus(tvb, pinfo, tree, offset);
            }
            break;
        case 471: /* landing-call-control */
            offset = fLandingCallStatus(tvb, pinfo, tree, offset);
            break;
        case 472: /* landing-door-status */
            if (propertyArrayIndex == 0) {
                /* BACnetARRAY index 0 refers to the length
                of the array, not the elements of the array */
                offset = fApplicationTypes(tvb, pinfo, tree, offset, ar);
            } else {
                offset = fLandingDoorStatus(tvb, pinfo, tree, offset);
            }
            break;
        case 477: /* "operation-direction */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetEscalatorOperationDirection);
            break;
        case 481: /* active-cov-multiple-subscriptions */
            if (propertyArrayIndex == 0) {
                /* BACnetARRAY index 0 refers to the length
                of the array, not the elements of the array */
                offset = fApplicationTypes(tvb, pinfo, tree, offset, ar);
            } else {
                offset = fCOVMultipleSubscription(tvb, pinfo, tree, offset);
            }
            break;
        case 482: /* protocol-level */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetProtocolLevel);
            break;
        case 486: /* tags */
            if (propertyArrayIndex == 0) {
                /* BACnetARRAY index 0 refers to the length
                of the array, not the elements of the array */
                offset = fApplicationTypes(tvb, pinfo, tree, offset, ar);
            } else {
                offset = fNameValue(tvb, pinfo, tree, offset);
            }
            break;
        case 487: /* subordinate-node-types */
            if (propertyArrayIndex == 0) {
                /* BACnetARRAY index 0 refers to the length
                of the array, not the elements of the array */
                offset = fApplicationTypes(tvb, pinfo, tree, offset, ar);
            } else {
                offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetNodeType);
            }
            break;
        case 488: /* subordinate-tags */
            if (propertyArrayIndex == 0) {
                /* BACnetARRAY index 0 refers to the length
                of the array, not the elements of the array */
                offset = fApplicationTypes(tvb, pinfo, tree, offset, ar);
            } else {
                offset = fNameValueCollection(tvb, pinfo, tree, offset);
            }
            break;
        case 489: /* subordinate-relationship */
            if (propertyArrayIndex == 0) {
                /* BACnetARRAY index 0 refers to the length
                of the array, not the elements of the array */
                offset = fApplicationTypes(tvb, pinfo, tree, offset, ar);
            } else {
                offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetRelationship);
            }
            break;
        case 490: /* default-subordinate-relationship */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetRelationship);
            break;
        case 494: /* stages */
            if (propertyArrayIndex == 0) {
                /* BACnetARRAY index 0 refers to the length
                of the array, not the elements of the array */
                offset = fApplicationTypes(tvb, pinfo, tree, offset, ar);
            } else {
                offset = fStageLimitValue(tvb, pinfo, tree, offset);
            }
            break;
        case 498: /* audit-level */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetAuditLevel);
            break;
        case 500: /* audit-priority-filter */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetAuditPriorityFilter);
            break;
        case 501: /* auditable-operations */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetAuditOperation);
            break;
        case 504: /* monitored-objects */
            if (propertyArrayIndex == 0) {
                /* BACnetARRAY index 0 refers to the length
                of the array, not the elements of the array */
                offset = fApplicationTypes(tvb, pinfo, tree, offset, ar);
            } else {
                offset = fObjectSelector(tvb, pinfo, tree, offset);
            }
            break;
        case 510:     /* command-validation-result */
        case 4194307: /* current-health */
            offset = fHealth(tvb, pinfo, tree, offset);
            break;
        case 4194312: /* sc-direct-connect-connection-status */
            offset = fSCDirectConnection(tvb, pinfo, tree, offset);
            break;
        case 4194315: /* sc-failed-connection-requests */
            offset = fSCFailedConnectionRequest(tvb, pinfo, tree, offset);
            break;
        case 4194316: /* sc-failover-hub-connection-status */
        case 4194324: /* sc-primary-hub-connection-status */
            offset = fSCHubConnection(tvb, pinfo, tree, offset);
            break;
        case 4194318: /* sc_hub_connector_state */
            offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset, ar, BACnetSCHubConnectorState);
            break;
        case 4194321: /* sc-hub-function-connection-status */
            offset = fSCHubFunctionConnection(tvb, pinfo, tree, offset);
            break;
        case 4194330: /* default-color */
            offset = fXyColor(tvb, pinfo, tree, offset, ar);
            break;
        case 4194334: /* color-command */
            offset = fColorCommand(tvb, pinfo, tree, offset, ar);
            break;

        case 85:  /* present-value */
            if ( object_type == 11 )    /* group object handling of present-value */
            {
                offset = fReadAccessResult(tvb, pinfo, tree, offset);
            }
            else if (object_type == 30)  /* access-door object */
            {
                offset = fPresentValue(tvb, pinfo, tree, offset, BACnetDoorValue, 0, BACAPP_PRESENT_VALUE_ENUM);
            }
            else if (object_type == 21)  /* life-point */
            {
                offset = fPresentValue(tvb, pinfo, tree, offset, BACnetLifeSafetyState, 0, BACAPP_PRESENT_VALUE_ENUM);
            }
            else if (object_type == 22)  /* life-zone */
            {
                offset = fPresentValue(tvb, pinfo, tree, offset, BACnetLifeSafetyState, 0, BACAPP_PRESENT_VALUE_ENUM);
            }
            else if (object_type == 53) /* channel object */
            {
                offset = fChannelValue(tvb, pinfo, tree, offset, ar);
            }
            else if (object_type == 37) /* credential-data-input */
            {
                offset = fAuthenticationFactor(tvb, pinfo, tree, offset);
            }
            else if (object_type == 26) /* global-group */
            {
                offset = fPropertyAccessResult(tvb, pinfo, tree, offset);
            }
            else if (object_type == 28) /* loac-control */
            {
                offset = fPresentValue(tvb, pinfo, tree, offset, BACnetShedState, 0, BACAPP_PRESENT_VALUE_ENUM);
            }
            else if (object_type == 43) /* date-time-pattern-value */
            {
                offset = fDateTime(tvb, pinfo, tree, offset, ar);
            }
            else if (object_type == 44) /* date-time-value */
            {
                offset = fDateTime(tvb, pinfo, tree, offset, ar);
            }
            else if (object_type == 63) /* color */
            {
                offset = fXyColor(tvb, pinfo, tree, offset, ar);
            }
            else
            {
                if (!tag_info) {
                    fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
                    // application tag number above 12 reserved for ASHRAE
                    if (!tag_is_context_specific(tag_info) && tag_no <= 12) {
                        offset = fPresentValue(tvb, pinfo, tree, offset, NULL, 0, (BacappPresentValueType) tag_no);
                    }
                } else {
                    do_default_handling = TRUE;
                }
            }
            break;
        default:
            do_default_handling = TRUE;
            break;
        }
        if (do_default_handling) {
            if (tag_info) {
                if (tag_is_opening(tag_info)) {
                    ++depth;
                    offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                } else if (tag_is_closing(tag_info)) {
                    --depth;
                    offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                } else {
                    offset  = fContextTaggedValue(tvb, pinfo, tree, offset, ar);
                }
            } else {
                offset = fApplicationTypes(tvb, pinfo, tree, offset, ar);
            }
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }

cleanup:
    recursion_depth = p_get_proto_depth(pinfo, proto_bacapp);
    p_set_proto_depth(pinfo, proto_bacapp, recursion_depth - 1);
    return offset;
}

static guint
fPropertyValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint8 tag_info)
{
    guint8  tag_no;
    guint32 lvt;

    if (tag_is_opening(tag_info)) {
        offset += fTagHeaderTree(tvb, pinfo, tree, offset,
                                 &tag_no, &tag_info, &lvt);
        offset  = fAbstractSyntaxNType(tvb, pinfo, tree, offset);
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            offset += fTagHeaderTree(tvb, pinfo, tree, offset,
                                     &tag_no, &tag_info, &lvt);
        }
    } else {
        proto_tree_add_expert(tree, pinfo, &ei_bacapp_opening_tag, tvb, offset, -1);
        offset = tvb_reported_length(tvb);
    }

    return offset;
}


static guint
fPropertyIdentifierValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint8 tagoffset)
{
    guint   lastoffset = offset;
    guint8  tag_no, tag_info;
    guint32 lvt;

    offset = fPropertyReference(tvb, pinfo, tree, offset, tagoffset, 0);
    if (offset > lastoffset) {
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_no == tagoffset+2) {  /* Value - might not be present in ReadAccessResult */
            offset = fPropertyValue(tvb, pinfo, tree, offset, tag_info);
        }
    }
    return offset;
}

static guint
fBACnetPropertyValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        offset = fPropertyIdentifierValue(tvb, pinfo, tree, offset, 0);
        if (offset > lastoffset) {
            /* detect optional priority
            by looking to see if the next tag is context tag number 3 */
            fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
            if (tag_is_context_specific(tag_info) && (tag_no == 3))
                offset = fUnsignedTag(tvb, pinfo, tree, offset, "Priority: ");
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fSubscribeCOVPropertyRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       lastoffset = 0, len;
    guint8      tag_no, tag_info;
    guint32     lvt;
    proto_tree *subtree = tree;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            offset += len;
            subtree = tree;
            continue;
        }

        switch (tag_no) {
        case 0: /* ProcessId */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "subscriber Process Id: ");
            break;
        case 1: /* monitored ObjectId */
            offset = fObjectIdentifier(tvb, pinfo, tree, offset, "ObjectIdentifier: ");
            break;
        case 2: /* issueConfirmedNotifications */
            offset = fBooleanTag(tvb, pinfo, tree, offset, "issue Confirmed Notifications: ");
            break;
        case 3: /* life time */
            offset = fTimeSpan(tvb, pinfo, tree, offset, "life time");
            break;
        case 4: /* monitoredPropertyIdentifier */
            if (tag_is_opening(tag_info)) {
                subtree = proto_tree_add_subtree(subtree, tvb, offset, 1, ett_bacapp_value, NULL, "monitoredPropertyIdentifier");
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset  = fBACnetPropertyReference(tvb, pinfo, subtree, offset, 1);
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            } else {
                expert_add_info(pinfo, subtree, &ei_bacapp_bad_tag);
            }
            break;
        case 5: /* covIncrement */
            offset = fRealTag(tvb, pinfo, tree, offset, "COV Increment: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fSubscribeCOVPropertyMultipleRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       lastoffset = 0, len;
    guint8      tag_no, tag_info;
    guint32     lvt;
    proto_tree *subtree = tree;
    proto_tree *subsubtree = tree;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            offset += len;
            subtree = tree;
            continue;
        }

        switch (tag_no) {
        case 0: /* ProcessId */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "subscriber Process Id: ");
            break;
        case 1: /* issueConfirmedNotifications */
            offset = fBooleanTag(tvb, pinfo, tree, offset, "issue Confirmed Notifications: ");
            break;
        case 2: /* life time */
            offset = fTimeSpan(tvb, pinfo, tree, offset, "life time");
            break;
        case 3: /* notification delay */
            offset = fTimeSpan(tvb, pinfo, tree, offset, "notification delay");
            break;
        case 4: /* list-of-cov-subscription-specifications */
            if (tag_is_opening(tag_info)) {
                subtree = proto_tree_add_subtree(subtree, tvb, offset, 1, ett_bacapp_value, NULL, "list-of-cov-subscription-specifications: ");
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);

                while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
                    lastoffset = offset;
                    len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
                    if (tag_is_closing(tag_info)) {
                        fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                        offset += len;
                        subtree = tree;
                        break;
                    }

                    switch (tag_no) {
                    case 0: /* monitored-object-identifier */
                        offset = fObjectIdentifier(tvb, pinfo, subtree, offset, "ObjectIdentifier: ");
                        break;
                    case 1: /* list-of-cov-references */
                      if (tag_is_opening(tag_info)) {
                          subsubtree = proto_tree_add_subtree(subtree, tvb, offset, 1, ett_bacapp_value, NULL, "list-of-cov-references: ");
                          offset += fTagHeaderTree(tvb, pinfo, subsubtree, offset, &tag_no, &tag_info, &lvt);

                          while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
                              lastoffset = offset;
                              len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
                              if (tag_is_closing(tag_info)) {
                                  fTagHeaderTree(tvb, pinfo, subsubtree, offset, &tag_no, &tag_info, &lvt);
                                  offset += len;
                                  break;
                              }

                              switch (tag_no) {
                              case 0: /* monitored-property */
                                  if (tag_is_opening(tag_info)) {
                                      offset += fTagHeaderTree(tvb, pinfo, subsubtree, offset, &tag_no, &tag_info, &lvt);
                                      offset = fBACnetPropertyReference(tvb, pinfo, subsubtree, offset, 1);
                                      offset += fTagHeaderTree(tvb, pinfo, subsubtree, offset, &tag_no, &tag_info, &lvt);
                                  }
                                  else {
                                      expert_add_info(pinfo, subsubtree, &ei_bacapp_bad_tag);
                                  }
                                  break;
                              case 1: /* cov-increment */
                                  offset = fRealTag(tvb, pinfo, subsubtree, offset, "COV Increment: ");
                                  break;
                              case 2: /* timestamped */
                                  offset = fBooleanTag(tvb, pinfo, subsubtree, offset, "timestamped: ");
                                  break;
                              default:
                                  return offset;
                            }
                            if (offset <= lastoffset) break;     /* nothing happened, exit loop */
                        }
                      }
                      else {
                          expert_add_info(pinfo, subsubtree, &ei_bacapp_bad_tag);
                      }
                      break;
                    default:
                      return offset;
                    }
                    if (offset <= lastoffset) break;     /* nothing happened, exit loop */
                }
            }
            else {
                expert_add_info(pinfo, subtree, &ei_bacapp_bad_tag);
            }
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fSubscribeCOVPropertyMultipleError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       lastoffset = 0, len;
    guint8      tag_no, tag_info;
    guint32     lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
            offset += len;
            break;
        }

        switch (tag_no) {
        case 0: /* normal error */
            if (tag_is_opening(tag_info)) {
                offset = fContextTaggedError(tvb, pinfo, tree, offset);
            }
            else {
                offset = fError(tvb, pinfo, tree, offset);
            }
            break;
        case 1: /* first-failed-subscription */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);

            while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
                lastoffset = offset;
                len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
                if (tag_is_closing(tag_info)) {
                    fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                    offset += len;
                    break;
                }

                switch (tag_no) {
                case 0: /* monitored-object-identifier */
                    offset = fObjectIdentifier(tvb, pinfo, tree, offset, "ObjectIdentifier: ");
                    break;
                case 1: /* monitored-property-reference */
                    if (tag_is_opening(tag_info)) {
                        offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                        offset = fBACnetPropertyReference(tvb, pinfo, tree, offset, 1);
                        offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                    }
                    else {
                        expert_add_info(pinfo, tree, &ei_bacapp_bad_tag);
                    }
                    break;
                case 2: /* error-type */
                    offset = fContextTaggedError(tvb, pinfo, tree, offset);
                    break;
                default:
                    return offset;
                }
                if (offset <= lastoffset) break;     /* nothing happened, exit loop */
            }
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fSubscribeCOVRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    return fSubscribeCOVPropertyRequest(tvb, pinfo, tree, offset);
}

static guint
fWhoHas(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;

        switch (fTagNo(tvb, offset)) {
        case 0: /* deviceInstanceLowLimit */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "device Instance Low Limit: ");
            break;
        case 1: /* deviceInstanceHighLimit */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "device Instance High Limit: ");
            break;
        case 2: /* BACnetObjectId */
            offset = fObjectIdentifier(tvb, pinfo, tree, offset, "ObjectIdentifier: ");
            break;
        case 3: /* ObjectName */
            offset = fObjectName(tvb, pinfo, tree, offset);
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}


static guint
fDailySchedule(tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    if (tag_is_opening(tag_info) && tag_no == 0) {
        offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt); /* opening context tag 0 */
        while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
            if (tag_is_closing(tag_info)) {
                /* should be closing context tag 0 */
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                return offset;
            }

            offset = fTimeValue(tvb, pinfo, subtree, offset);
            if (offset <= lastoffset) break;    /* nothing happened, exit loop */
        }
    } else if ((tag_no == 0) && (lvt == 0)) {
        /* not sure null (empty array element) is legal */
        offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
    }
    return offset;
}

/**
 * BACnetHealth ::= SEQUENCE {
 *  timestamp                   [0] BACnetDateTime,
 *  result                      [1] Error,
 *  property                    [2] BACnetPropertiyIdentifier OPTIONAL,
 *  details                     [3] CharacterString OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fHealth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        lastoffset = offset;
        /* check the tag.  A closing tag means we are done */
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            return offset;
        }
        switch (tag_no) {
        case 0: /* timestamp */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset = fDateTime(tvb, pinfo, tree, offset, "timestamp: ");
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 1: /* result */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset = fError(tvb, pinfo, tree, offset);
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 2: /* property - OPTIONAL*/
            offset = fPropertyIdentifier(tvb, pinfo, tree, offset);
            break;
        case 3: /* details - OPTIONAL */
            offset = fCharacterString(tvb, pinfo, tree, offset, "details: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

/**
 * BACnetSCDirectConnection ::= SEQUENCE {
 *  uri                         [0] CharacterString
 *  connection-state            [1] BACnetSCConnectionState,
 *  connect-timestamp           [2] BACnetDateTime,
 *  disconnect-timestamp        [3] BACnetDateTime,
 *  peer-address                [4] BACnetHostNPort,
 *  peer-vmac                   [5] OCTET STRING (SIZE(6))
 *  peer-uuid                   [6] OCTET STRING (SIZE(16))
 *  error                       [7] Error OPTIONAL
 *  error-details               [8] CharacterString OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fSCDirectConnection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        lastoffset = offset;
        /* check the tag.  A closing tag means we are done */
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            return offset;
        }
        switch (tag_no) {
        case 0: /* uri */
            offset = fCharacterString(tvb, pinfo, tree, offset, "uri: ");
            break;
        case 1: /* connection-state */
            offset = fEnumeratedTag(tvb, pinfo, tree, offset, "connection-state: ", BACnetSCConnectionState);
            break;
        case 2: /* connect-timestamp */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset = fDateTime(tvb, pinfo, tree, offset, "connet-timestamp: ");
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 3: /* disconnect-timestamp */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset = fDateTime(tvb, pinfo, tree, offset, "disconnect-timestamp: ");
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 4: /* peer-address */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset = fHostNPort(tvb, pinfo, tree, offset,"peer-address: ");
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 5: /* peer-vmac */
            offset = fOctetString(tvb, pinfo, tree, offset, "peer-vmac: ", lvt);
            break;
        case 6: /* peer-uuid */
            offset = fOctetString(tvb, pinfo, tree, offset, "peer-uuid: ", lvt);
            break;
        case 7: /* error */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset = fError(tvb, pinfo, tree, offset);
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 8: /* details - OPTIONAL */
            offset = fCharacterString(tvb, pinfo, tree, offset, "details: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

/**
 * BACnetSCFailedConnectionRequest ::= SEQUENCE {
 *  timestamp                   [0] BACnetDateTime,
 *  peer-address                [1] BACnetHostNPort,
 *  peer-vmac                   [2] OCTET STRING (SIZE(6))
 *  peer-uuid                   [3] OCTET STRING (SIZE(16))
 *  error                       [4] Error OPTIONAL
 *  error-details               [5] CharacterString OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fSCFailedConnectionRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        lastoffset = offset;
        /* check the tag.  A closing tag means we are done */
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            return offset;
        }
        switch (tag_no) {
        case 0: /* timestamp */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset = fDateTime(tvb, pinfo, tree, offset, "connet-timestamp: ");
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 1: /* peer-address */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset = fHostNPort(tvb, pinfo, tree, offset,"peer-address: ");
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 2: /* peer-vmac */
            offset = fOctetString(tvb, pinfo, tree, offset, "peer-vmac: ", lvt);
            break;
        case 3: /* peer-uuid */
            offset = fOctetString(tvb, pinfo, tree, offset, "peer-uuid: ", lvt);
            break;
        case 4: /* error */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset = fError(tvb, pinfo, tree, offset);
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 5: /* details - OPTIONAL */
            offset = fCharacterString(tvb, pinfo, tree, offset, "details: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

/**
 * BACnetSCHubConnection ::= SEQUENCE {
 *  connection-state            [0] BACnetSCConnectionState,
 *  connect-timestamp           [1] BACnetDateTime,
 *  disconnect-timestamp        [2] BACnetDateTime,
 *  error                       [3] Error OPTIONAL
 *  error-details               [4] CharacterString OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fSCHubConnection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        lastoffset = offset;
        /* check the tag.  A closing tag means we are done */
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            return offset;
        }
        switch (tag_no) {
        case 0: /* connection-state */
            offset = fEnumeratedTag(tvb, pinfo, tree, offset, "connection-state: ", BACnetSCConnectionState);
            break;
        case 1: /* connect-timestamp */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset = fDateTime(tvb, pinfo, tree, offset, "connet-timestamp: ");
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 2: /* disconnect-timestamp */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset = fDateTime(tvb, pinfo, tree, offset, "disconnect-timestamp: ");
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 3: /* error */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset = fError(tvb, pinfo, tree, offset);
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 4: /* details - OPTIONAL */
            offset = fCharacterString(tvb, pinfo, tree, offset, "details: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

/**
 * BACnetSCHubFunctionConnection ::= SEQUENCE {
 *  connection-state            [0] BACnetSCConnectionState,
 *  connect-timestamp           [1] BACnetDateTime,
 *  disconnect-timestamp        [2] BACnetDateTime,
 *  peer-address                [3] BACnetHostNPort,
 *  peer-vmac                   [4] OCTET STRING (SIZE(6))
 *  peer-uuid                   [5] OCTET STRING (SIZE(16))
 *  error                       [6] Error OPTIONAL
 *  error-details               [7] CharacterString OPTIONAL
 * }
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 * @return modified offset
 */
static guint
fSCHubFunctionConnection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        lastoffset = offset;
        /* check the tag.  A closing tag means we are done */
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            return offset;
        }
        switch (tag_no) {
        case 0: /* connection-state */
            offset = fEnumeratedTag(tvb, pinfo, tree, offset, "connection-state: ", BACnetSCConnectionState);
            break;
        case 1: /* connect-timestamp */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset = fDateTime(tvb, pinfo, tree, offset, "connet-timestamp: ");
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 2: /* disconnect-timestamp */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset = fDateTime(tvb, pinfo, tree, offset, "disconnect-timestamp: ");
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 3: /* peer-address */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset = fHostNPort(tvb, pinfo, tree, offset,"peer-address: ");
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 4: /* peer-vmac */
            offset = fOctetString(tvb, pinfo, tree, offset, "peer-vmac: ", lvt);
            break;
        case 5: /* peer-uuid */
            offset = fOctetString(tvb, pinfo, tree, offset, "peer-uuid: ", lvt);
            break;
        case 6: /* error */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset = fError(tvb, pinfo, tree, offset);
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 7: /* details - OPTIONAL */
            offset = fCharacterString(tvb, pinfo, tree, offset, "details: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fWeeklySchedule(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       lastoffset = 0;
    guint8      tag_no, tag_info;
    guint32     lvt;
    guint       i = 1; /* day of week array index */
    proto_tree *subtree = tree;

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
    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            return offset; /* outer encoding will print out closing tag */
        }
        subtree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_bacapp_value, NULL,
                                val_to_str(i++, day_of_week, "day of week (%d) not found"));
        offset = fDailySchedule(tvb, pinfo, subtree, offset);
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}


static guint
fUTCTimeSynchronizationRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    if (tvb_reported_length_remaining(tvb, offset) <= 0)
        return offset;

    return fDateTime(tvb, pinfo, tree, offset, "UTC-Time: ");
}

static guint
fTimeSynchronizationRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    if (tvb_reported_length_remaining(tvb, offset) <= 0)
        return offset;

    return fDateTime(tvb, pinfo, tree, offset, NULL);
}

static guint
fWriteGroupRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       lastoffset = 0, len;
    guint8      tag_no, tag_info;
    guint32     lvt;
    proto_tree *subtree = tree;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            offset += len;
            subtree = tree;
            continue;
        }

        switch (tag_no) {
        case 0: /* group-number */
            offset = fUnsignedTag(tvb, pinfo, subtree, offset, "Group number: ");
            break;
        case 1: /* write-priority */
            offset = fUnsignedTag(tvb, pinfo, subtree, offset, "Priority: ");
            break;
        case 2: /* change-list */
            if (tag_is_opening(tag_info)) {
                subtree = proto_tree_add_subtree(subtree, tvb, offset, 1, ett_bacapp_value, NULL, "change-list: ");
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);

                while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
                    lastoffset = offset;
                    len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
                    if (tag_is_closing(tag_info)) {
                        fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                        offset += len;
                        subtree = tree;
                        break;
                    }

                    switch (tag_no) {
                    case 0: /* channel */
                        if (tag_info && ! tag_is_opening(tag_info)) {
                            /* context tagged */
                            offset = fUnsignedTag(tvb, pinfo, subtree, offset, "Channel: ");
                        } else {
                            /* application tagged */
                            offset = fChannelValue(tvb, pinfo, subtree, offset, "Value: ");
                        }
                        break;
                    case 1: /* overriding-priority */
                        if (tag_info && ! tag_is_opening(tag_info)) {
                            /* context tagged */
                            offset = fUnsignedTag(tvb, pinfo, subtree, offset, "Overriding priority: ");
                        } else {
                            /* application tagged */
                            offset = fChannelValue(tvb, pinfo, subtree, offset, "Value: ");
                        }
                        break;
                    default: /* channel-value (application tagged, or opening/closing context-0 tagged) */
                        offset = fChannelValue(tvb, pinfo, subtree, offset, "Value: ");
                        break;
                    }
                    if (offset <= lastoffset) break;     /* nothing happened, exit loop */
                }
            }
            else {
                expert_add_info(pinfo, subtree, &ei_bacapp_bad_tag);
            }
            break;
        case 3: /* inhibit-delay */
            offset = fBooleanTag(tvb, pinfo, tree, offset, "Inhibit delay: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fDateRange(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    if (tvb_reported_length_remaining(tvb, offset) <= 0)
        return offset;
    offset = fDate(tvb, pinfo, tree, offset, "Start Date: ");
    return fDate(tvb, pinfo, tree, offset, "End Date: ");
}

static guint
fVendorIdentifier(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint32      val   = 0;
    guint8       tag_no, tag_info;
    guint32      lvt;
    guint        tag_len;
    proto_item  *ti;
    proto_tree  *subtree;
    const gchar *label = "Vendor ID";

    tag_len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    if (fUnsigned32(tvb, offset + tag_len, lvt, &val))
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
            ett_bacapp_tag, &ti, "%s: %s (%u)",
            label,
            val_to_str_ext_const(val, &BACnetVendorIdentifiers_ext, "Unknown Vendor"),
            val);
    else
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
            ett_bacapp_tag, &ti, "%s - %u octets (Unsigned)", label, lvt);
    fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);

    if ((lvt < 1) || (lvt > 2)) { /* vendorIDs >= 1  and <= 2 are supported */
        expert_add_info_format(pinfo, ti, &ei_bacapp_bad_length,
                                "Wrong length indicated. Expected 1 or 2, got %u", lvt);
        return offset+tag_len+lvt;
    }

    proto_tree_add_item(subtree, hf_BACnetVendorIdentifier, tvb,
        offset+tag_len, lvt, ENC_BIG_ENDIAN);

    return offset+tag_len+lvt;
}

static guint
fRestartReason(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint32      val   = 0;
    guint8       tag_no, tag_info;
    guint32      lvt;
    guint        tag_len;
    proto_item  *ti;
    proto_tree  *subtree;
    const gchar *label = "Restart Reason";

    tag_len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    if (fUnsigned32(tvb, offset + tag_len, lvt, &val))
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
            ett_bacapp_tag, &ti, "%s: %s (%u)", label,
            val_to_str_const(val, BACnetRestartReason, "Unknown reason"), val);
    else
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
            ett_bacapp_tag, &ti, "%s - %u octets (Unsigned)", label, lvt);
    fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);

    if (lvt != 1) {
        expert_add_info_format(pinfo, ti, &ei_bacapp_bad_length,
                                "Wrong length indicated. Expected 1, got %u", lvt);
        return offset+tag_len+lvt;
    }

    proto_tree_add_item(subtree, hf_BACnetRestartReason, tvb,
        offset+tag_len, lvt, ENC_BIG_ENDIAN);

    return offset+tag_len+lvt;
}

static guint
fConfirmedTextMessageRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8       tag_no, tag_info;
    guint32      lvt;
    guint        lastoffset = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        switch (fTagNo(tvb, offset)) {
        case 0: /* textMessageSourceDevice */
            offset = fObjectIdentifier(tvb, pinfo, tree, offset, "DeviceIdentifier: ");
            break;
        case 1: /* messageClass */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            switch (fTagNo(tvb, offset)) {
            case 0: /* numeric */
                offset = fUnsignedTag(tvb, pinfo, tree, offset, "message Class: ");
                break;
            case 1: /* character */
                offset = fCharacterString(tvb, pinfo, tree, offset, "message Class: ");
                break;
            }
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 2: /* messagePriority */
            offset = fEnumeratedTag(tvb, pinfo, tree, offset, "message Priority: ",
                BACnetMessagePriority);
            break;
        case 3: /* message */
            offset = fCharacterString(tvb, pinfo, tree, offset, "message: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
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
    guint       lastoffset, len;
    guint8      tag_no, tag_info;
    guint32     lvt;
    proto_tree *subtree = tree;
    tvbuff_t   *next_tvb;
    guint       vendor_identifier = 0;
    guint       service_number = 0;

    len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    fUnsigned32(tvb, offset+len, lvt, &vendor_identifier);
    col_append_fstr(pinfo->cinfo, COL_INFO, "V=%u ", vendor_identifier);
    offset = fVendorIdentifier(tvb, pinfo, subtree, offset);

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    if (dissector_try_uint(bacapp_dissector_table,
        vendor_identifier, next_tvb, pinfo, tree)) {
        /* we parsed it so skip over length and we are done */
        offset += tvb_reported_length(next_tvb);
        return offset;
    }

    /* Not handled by vendor dissector */

    /* exit loop if nothing happens inside */
    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        lastoffset = offset;
        len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
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
            col_append_fstr(pinfo->cinfo, COL_INFO, "SN=%u ",   service_number);
            offset = fUnsignedTag(tvb, pinfo, subtree, offset, "service Number: ");
            break;
        case 2: /*serviceParameters */
            if (tag_is_opening(tag_info)) {
                subtree = proto_tree_add_subtree(subtree, tvb, offset, 1,
                        ett_bacapp_value, NULL, "service Parameters");
                propertyIdentifier = -1;
                offset = fAbstractSyntaxNType(tvb, pinfo, subtree, offset);
            } else {
                expert_add_info(pinfo, subtree, &ei_bacapp_bad_tag);
            }
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
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
    guint       lastoffset = 0;
    guint8      tag_no, tag_info;
    guint32     lvt;
    proto_tree *subtree = tree;

    if (label != NULL) {
        subtree = proto_tree_add_subtree(subtree, tvb, offset, 1, ett_bacapp_value, NULL, label);
    }

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);

        switch (tag_no) {
        case 0: /* subscriberProcessId */
            offset = fUnsignedTag(tvb, pinfo, subtree, offset, "requesting Process Id: ");
            break;
        case 1: /* requestingSource */
            offset = fCharacterString(tvb, pinfo, tree, offset, "requesting Source: ");
            break;
        case 2: /* request */
            offset = fEnumeratedTagSplit(tvb, pinfo, tree, offset,
                "request: ", BACnetLifeSafetyOperation, 64);
            break;
        case 3: /* objectId */
            offset = fObjectIdentifier(tvb, pinfo, subtree, offset, "ObjectIdentifier: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

typedef struct _value_string_enum {
  guint8 tag_no;
  const value_string *valstr;
} value_string_enum;

static const value_string_enum
BACnetPropertyStatesEnums[] = {
    {   1, BACnetBinaryPV },
    {   2, BACnetEventType },
    {   3, BACnetPolarity },
    {   4, BACnetProgramRequest },
    {   5, BACnetProgramState },
    {   6, BACnetProgramError },
    {   7, BACnetReliability },
    {   8, BACnetEventState },
    {   9, BACnetDeviceStatus },
    {  10, BACnetEngineeringUnits },
    {  12, BACnetLifeSafetyMode },
    {  13, BACnetLifeSafetyState },
    {  14, BACnetRestartReason },
    {  15, BACnetDoorAlarmState },
    {  16, BACnetAction },
    {  17, BACnetDoorSecuredStatus },
    {  18, BACnetDoorStatus },
    {  19, BACnetDoorValue },
    {  20, BACnetFileAccessMethod },
    {  21, BACnetLockStatus },
    {  22, BACnetLifeSafetyOperation },
    {  23, BACnetMaintenance },
    {  24, BACnetNodeType },
    {  25, BACnetNotifyType },
    {  26, BACnetSecurityLevel },
    {  27, BACnetShedState },
    {  28, BACnetSilencedState },
    {  30, BACnetAccessEvent },
    {  31, BACnetAccessZoneOccupancyState },
    {  32, BACnetAccessCredentialDisableReason },
    {  33, BACnetAccessCredentialDisable },
    {  34, BACnetAuthenticationStatus },
    {  36, BACnetBackupState },
    {  37, BACnetWriteStatus },
    {  38, BACnetLightingInProgress },
    {  39, BACnetLightingOperation },
    {  40, BACnetLightingTransition },
    {  42, BACnetBinaryLightingPV },
    {  43, BACnetTimerState },
    {  44, BACnetTimerTransition },
    {  45, BACnetIpMode },
    {  46, BACnetNetworkPortCommand },
    {  47, BACnetNetworkType },
    {  48, BACnetNetworkNumberQuality },
    {  49, BACnetEscalatorOperationDirection },
    {  50, BACnetEscalatorFault },
    {  51, BACnetEscalatorMode },
    {  52, BACnetLiftCarDirection },
    {  53, BACnetLiftCarDoorCommand },
    {  54, BACnetLiftCarDriveStatus },
    {  55, BACnetLiftCarMode },
    {  56, BACnetLiftGroupMode },
    {  57, BACnetLiftFault },
    {  58, BACnetProtocolLevel }
};
#define BACnetPropertyStatesEnums_Size \
    (sizeof(BACnetPropertyStatesEnums) / sizeof(BACnetPropertyStatesEnums[0]))

static guint
fBACnetPropertyStates(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8       tag_no, tag_info;
    guint32      lvt;
    guint32      idx;
    const gchar* label;
    const value_string_enum* valstrenum;

    fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    label = wmem_strdup_printf(pinfo->pool, "%s: ",
                               val_to_str_const( tag_no, VALS(BACnetPropertyStates), "Unknown State" ));

    switch (tag_no) {
    case 0:
        offset = fBooleanTag(tvb, pinfo, tree, offset, label);
        break;
    case 11:
        offset = fUnsignedTag(tvb, pinfo, tree, offset, label);
        break;
    default:
        valstrenum = NULL;

        for (idx = 0; idx < BACnetPropertyStatesEnums_Size; idx++) {
            valstrenum = &BACnetPropertyStatesEnums[idx];
            if (valstrenum->tag_no == tag_no &&
                valstrenum->valstr != NULL) {
                break;
            }
            valstrenum = NULL;
        }

        if (valstrenum == NULL)
        {
            offset = fEnumeratedTag(tvb, pinfo, tree, offset, label, NULL);
            /* don't use Abstract type here because it is context tagged and therefore we don't know app type */
        }
        else
        {
            offset = fEnumeratedTagSplit(tvb, pinfo, tree, offset, label,
                    VALS(valstrenum->valstr), 64);
        }
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
fDeviceObjectPropertyValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        lastoffset = offset;
        /* check the tag.  A closing tag means we are done */
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            return offset;
        }
        switch (tag_no) {
        case 0: /* deviceIdentifier */
            offset = fObjectIdentifier(tvb, pinfo, tree, offset, "DeviceIdentifier: ");
            break;
        case 1: /* objectIdentifier */
            offset = fObjectIdentifier(tvb, pinfo, tree, offset, "ObjectIdentifier: ");
            break;
        case 2: /* propertyIdentifier */
            offset = fPropertyIdentifier(tvb, pinfo, tree, offset);
            break;
        case 3: /* arrayIndex - OPTIONAL */
            offset = fUnsignedTag(tvb, pinfo, tree, offset,
                "arrayIndex: ");
            break;
        case 4: /* value */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset  = fAbstractSyntaxNType(tvb, pinfo, tree, offset);
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
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
fObjectPropertyReference(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    return fDeviceObjectPropertyReference(tvb, pinfo, tree, offset);
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
fDeviceObjectPropertyReference(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        lastoffset = offset;
        /* check the tag.  A closing tag means we are done */
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            return offset;
        }
        switch (tag_no) {
        case 0: /* objectIdentifier */
            offset = fObjectIdentifier(tvb, pinfo, tree, offset, "ObjectIdentifier: ");
            break;
        case 1: /* propertyIdentifier */
            offset = fPropertyIdentifier(tvb, pinfo, tree, offset);
            break;
        case 2: /* arrayIndex - OPTIONAL */
            offset = fUnsignedTag(tvb, pinfo, tree, offset,
                "arrayIndex: ");
            break;
        case 3: /* deviceIdentifier - OPTIONAL */
            offset = fObjectIdentifier(tvb, pinfo, tree, offset, "DeviceIdentifier: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fNotificationParameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       lastoffset = offset;
    guint8      tag_no, tag_info;
    guint32     lvt;
    proto_tree *subtree = tree;
    proto_tree *pvtree;

    fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    subtree = proto_tree_add_subtree_format(subtree, tvb, offset, 0,
        ett_bacapp_value, NULL, "notification parameters (%d) %s",
        tag_no, val_to_str_const(tag_no, BACnetEventType, "invalid type"));
    /* Opening tag for parameter choice */
    offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);

    switch (tag_no) {
    case 0: /* change-of-bitstring */
        while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset = fBitStringTag(tvb, pinfo, subtree, offset,
                    "referenced-bitstring: ");
                break;
            case 1:
                offset = fBitStringTagVS(tvb, pinfo, subtree, offset,
                    "status-flags: ", BACnetStatusFlags);
                lastoffset = offset;
                break;
            default:
                break;
            }
            if (offset <= lastoffset) break;     /* nothing happened, exit loop */
        }
        break;
    case 1: /* change-of-state */
        while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset  = fBACnetPropertyStates(tvb, pinfo, subtree, offset);
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            case 1:
                offset = fBitStringTagVS(tvb, pinfo, subtree, offset,
                    "status-flags: ", BACnetStatusFlags);
                lastoffset = offset;
                break;
            default:
                break;
            }
            if (offset <= lastoffset) break;     /* nothing happened, exit loop */
        }
        break;
    case 2: /* change-of-value */
        while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                switch (fTagNo(tvb, offset)) {
                case 0:
                    offset = fBitStringTag(tvb, pinfo, subtree, offset,
                        "changed-bits: ");
                    break;
                case 1:
                    offset = fRealTag(tvb, pinfo, subtree, offset,
                        "changed-value: ");
                    break;
                default:
                    break;
                }
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            case 1:
                offset = fBitStringTagVS(tvb, pinfo, subtree, offset,
                    "status-flags: ", BACnetStatusFlags);
                lastoffset = offset;
                break;
            default:
                break;
            }
            if (offset <= lastoffset) break;     /* nothing happened, exit loop */
        }
        break;
    case 3: /* command-failure */
        while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0: /* "command-value: " */
                /* from BACnet Table 13-3,
                    Standard Object Property Values Returned in Notifications */
                propertyIdentifier = 85; /* PRESENT_VALUE */
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset  = fAbstractSyntaxNType(tvb, pinfo, subtree, offset);
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            case 1:
                offset = fBitStringTagVS(tvb, pinfo, subtree, offset,
                    "status-flags: ", BACnetStatusFlags);
                break;
            case 2: /* "feedback-value: " */
                propertyIdentifier = 40; /* FEEDBACK_VALUE */
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset  = fAbstractSyntaxNType(tvb, pinfo, subtree, offset);
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                lastoffset = offset;
                break;
            default:
                break;
            }
            if (offset <= lastoffset) break;     /* nothing happened, exit loop */
        }
        break;
    case 4: /* floating-limit */
        while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset = fRealTag(tvb, pinfo, subtree, offset, "reference-value: ");
                break;
            case 1:
                offset = fBitStringTagVS(tvb, pinfo, subtree, offset,
                    "status-flags: ", BACnetStatusFlags);
                break;
            case 2:
                offset = fRealTag(tvb, pinfo, subtree, offset, "setpoint-value: ");
                break;
            case 3:
                offset = fRealTag(tvb, pinfo, subtree, offset, "error-limit: ");
                lastoffset = offset;
                break;
            default:
                break;
            }
            if (offset <= lastoffset) break;     /* nothing happened, exit loop */
        }
        break;
    case 5: /* out-of-range */
        while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset = fRealTag(tvb, pinfo, subtree, offset, "exceeding-value: ");
                break;
            case 1:
                offset = fBitStringTagVS(tvb, pinfo, subtree, offset,
                    "status-flags: ", BACnetStatusFlags);
                break;
            case 2:
                offset = fRealTag(tvb, pinfo, subtree, offset, "deadband: ");
                break;
            case 3:
                offset = fRealTag(tvb, pinfo, subtree, offset, "exceeded-limit: ");
                lastoffset = offset;
                break;
            default:
                break;
            }
            if (offset <= lastoffset) break;     /* nothing happened, exit loop */
        }
        break;
    case 6:
        while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            offset =fBACnetPropertyValue(tvb, pinfo, subtree, offset);
            if (offset <= lastoffset) break;     /* nothing happened, exit loop */
        }
        break;
    case 7: /* deprecated (was 'buffer-ready', changed and moved to [10]) */
        while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset = fObjectIdentifier(tvb, pinfo, subtree, offset, "DeviceIdentifier: "); /* buffer-device */
                break;
            case 1:
                offset = fObjectIdentifier(tvb, pinfo, subtree, offset, "ObjectIdentifier: "); /* buffer-object */
                break;
            case 2:
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset  = fDateTime(tvb, pinfo, subtree, offset, "previous-notification: ");
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            case 3:
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset  = fDateTime(tvb, pinfo, subtree, offset, "current-notification: ");
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                lastoffset = offset;
                break;
            default:
                break;
            }
            if (offset <= lastoffset) break;     /* nothing happened, exit loop */
        }
        break;
    case 8: /* change-of-life-safety */
        while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset = fEnumeratedTagSplit(tvb, pinfo, subtree, offset,
                    "new-state: ", BACnetLifeSafetyState, 256);
                break;
            case 1:
                offset = fEnumeratedTagSplit(tvb, pinfo, subtree, offset,
                    "new-mode: ", BACnetLifeSafetyMode, 256);
                break;
            case 2:
                offset = fBitStringTagVS(tvb, pinfo, subtree, offset,
                    "status-flags: ", BACnetStatusFlags);
                break;
            case 3:
                offset = fEnumeratedTagSplit(tvb, pinfo, subtree, offset,
                    "operation-expected: ", BACnetLifeSafetyOperation, 64);
                lastoffset = offset;
                break;
            default:
                break;
            }
            if (offset <= lastoffset) break;     /* nothing happened, exit loop */
        }
        break;
    case 9: /* extended */
        while (tvb_reported_length_remaining(tvb, offset) > 0) {
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset = fVendorIdentifier(tvb, pinfo, subtree, offset);
                break;
            case 1:
                offset = fUnsignedTag(tvb, pinfo, subtree, offset, "extended-event-type: ");
                break;
            case 2: /* parameters */
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);

                while (tvb_reported_length_remaining(tvb, offset) > 0) {
                    const guint param_lastoffset = offset;
                    fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
                    if (tag_is_closing(tag_info))
                    {
                        break;
                    }

                    if (tag_is_opening(tag_info))
                    {
                        offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                        offset = fDeviceObjectPropertyValue(tvb, pinfo, subtree, offset);
                        offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                    }
                    else
                    {
                        offset = fApplicationTypes(tvb, pinfo, subtree, offset, "parameters: ");
                    }
                    if (offset <= param_lastoffset)
                        break;     /* nothing happened, exit loop */
                }

                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                lastoffset = offset;
                break;
            default:
                break;
            }
            if (offset <= lastoffset) break;     /* nothing happened, exit loop */
        }
        break;
    case 10: /* buffer ready */
        while (tvb_reported_length_remaining(tvb, offset) > 0) {
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0: /* buffer-property */
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset  = fDeviceObjectPropertyReference(tvb, pinfo, subtree, offset);
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            case 1:
                offset  = fUnsignedTag(tvb, pinfo, subtree, offset,
                    "previous-notification: ");
                break;
            case 2:
                offset = fUnsignedTag(tvb, pinfo, subtree, offset,
                    "current-notification: ");
                lastoffset = offset;
                break;
            default:
                break;
            }
            if (offset <= lastoffset) break;     /* nothing happened, exit loop */
        }
        break;
    case 11: /* unsigned range */
        while (tvb_reported_length_remaining(tvb, offset) > 0) {
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset = fUnsignedTag(tvb, pinfo, subtree, offset,
                    "exceeding-value: ");
                break;
            case 1:
                offset = fBitStringTagVS(tvb, pinfo, subtree, offset,
                    "status-flags: ", BACnetStatusFlags);
                break;
            case 2:
                offset = fUnsignedTag(tvb, pinfo, subtree, offset,
                    "exceeded-limit: ");
                lastoffset = offset;
                break;
            default:
                break;
            }
            if (offset <= lastoffset) break;     /* nothing happened, exit loop */
        }
        break;
        /* 12 reserved */
    case 13: /* access-event */
        while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset = fEnumeratedTagSplit(tvb, pinfo, subtree, offset,
                                              "access event: ", BACnetAccessEvent, 512);
                break;
            case 1:
                offset = fBitStringTagVS(tvb, pinfo, subtree, offset,
                    "status-flags: ", BACnetStatusFlags);
                break;
            case 2:
                offset = fUnsignedTag(tvb, pinfo, subtree, offset,
                    "access-event-tag: ");
                break;
            case 3:
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset  = fTimeStamp(tvb, pinfo, subtree, offset, "access-event-time: ");
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            case 4:
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset  = fDeviceObjectReference(tvb, pinfo, subtree, offset);
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            case 5: /* optional authentication-factor */
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset  = fAuthenticationFactor(tvb, pinfo, subtree, offset);
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                lastoffset = offset;
                break;
            default:
                break;
            }
            if (offset <= lastoffset) break;     /* nothing happened, exit loop */
        }
        break;
    case 14: /* double-out-of-range */
        while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset = fDoubleTag(tvb, pinfo, subtree, offset, "exceeding-value: ");
                break;
            case 1:
                offset = fBitStringTagVS(tvb, pinfo, subtree, offset,
                    "status-flags: ", BACnetStatusFlags);
                break;
            case 2:
                offset = fDoubleTag(tvb, pinfo, subtree, offset, "deadband: ");
                break;
            case 3:
                offset = fDoubleTag(tvb, pinfo, subtree, offset, "exceeded-limit: ");
                lastoffset = offset;
                break;
            default:
                break;
            }
            if (offset <= lastoffset) break;     /* nothing happened, exit loop */
        }
        break;
    case 15: /* signed-out-of-range */
        while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset = fSignedTag(tvb, pinfo, subtree, offset, "exceeding-value: ");
                break;
            case 1:
                offset = fBitStringTagVS(tvb, pinfo, subtree, offset,
                    "status-flags: ", BACnetStatusFlags);
                break;
            case 2:
                offset = fUnsignedTag(tvb, pinfo, subtree, offset, "deadband: ");
                break;
            case 3:
                offset = fSignedTag(tvb, pinfo, subtree, offset, "exceeded-limit: ");
                lastoffset = offset;
                break;
            default:
                break;
            }
            if (offset <= lastoffset) break;     /* nothing happened, exit loop */
        }
        break;
    case 16: /* unsigned-out-of-range */
        while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset = fUnsignedTag(tvb, pinfo, subtree, offset, "exceeding-value: ");
                break;
            case 1:
                offset = fBitStringTagVS(tvb, pinfo, subtree, offset,
                    "status-flags: ", BACnetStatusFlags);
                break;
            case 2:
                offset = fUnsignedTag(tvb, pinfo, subtree, offset, "deadband: ");
                break;
            case 3:
                offset = fUnsignedTag(tvb, pinfo, subtree, offset, "exceeded-limit: ");
                lastoffset = offset;
                break;
            default:
                break;
            }
            if (offset <= lastoffset) break;     /* nothing happened, exit loop */
        }
        break;
    case 17: /* change-of-characterstring */
        while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                 /* changed-value (CharacterString) */
                offset  = fCharacterString(tvb, pinfo, subtree, offset, "changed-value: ");
                break;
            case 1:
                offset = fBitStringTagVS(tvb, pinfo, subtree, offset,
                    "status-flags: ", BACnetStatusFlags);
                break;
            case 2:
                /* alarm-value (CharacterString) */
                offset  = fCharacterString(tvb, pinfo, subtree, offset, "alarm-value: ");
                lastoffset = offset;
                break;
            default:
                break;
            }
            if (offset <= lastoffset) break;     /* nothing happened, exit loop */
        }
        break;
    case 18: /* change-of-status-flags */
        while (tvb_reported_length_remaining(tvb, offset) > 0) {
            /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);

                fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
                if (tag_is_context_specific(tag_info)) {
                    propertyIdentifier = 85; /* suppose present-value here */
                    offset = fAbstractSyntaxNType(tvb, pinfo, subtree, offset);
                } else {
                    offset = fPresentValue(tvb, pinfo, tree, offset, BACnetStatusFlags, 0, BACAPP_PRESENT_VALUE_ENUM);
                }

                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            case 1:
                offset = fBitStringTagVS(tvb, pinfo, subtree, offset,
                    "referenced-flags: ", BACnetStatusFlags);
                lastoffset = offset;
                break;
            default:
                break;
            }
            if (offset <= lastoffset) break;     /* nothing happened, exit loop */
        }
        break;
    case 19: /* change-of-reliability */
        while (tvb_reported_length_remaining(tvb, offset) > 0) {
            /* exit loop if nothing happens inside */
            lastoffset = offset;

            switch (fTagNo(tvb, offset)) {
            case 0:
               offset = fEnumeratedTag(tvb, pinfo, subtree, offset, "reliability:", BACnetReliability);
               break;
            case 1:
               offset = fBitStringTagVS(tvb, pinfo, subtree, offset, "status-flags: ", BACnetStatusFlags);
               break;
            case 2: /* property-values */
               fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
               if (tag_is_closing(tag_info)) {
                  offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
               return offset;
               }
               pvtree = proto_tree_add_subtree(subtree, tvb, offset, 1, ett_bacapp_value, NULL, "property-values");
               offset += fTagHeaderTree(tvb, pinfo, pvtree, offset, &tag_no, &tag_info, &lvt);
               offset = fBACnetPropertyValue(tvb, pinfo, pvtree, offset);
               offset += fTagHeaderTree(tvb, pinfo, pvtree, offset, &tag_no, &tag_info, &lvt);
               break;
            default:
               break;
           }
           if (offset <= lastoffset)
               break;     /* nothing happened, exit loop */
        }
        break;
    case 20: /* context tag [20] is not used */
        break;
    case 21: /* change-of-discrete-value */
        while (tvb_reported_length_remaining(tvb, offset) > 0) {
            /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0: /* new-value */
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset  = fApplicationTypes(tvb, pinfo, subtree, offset, "new-value: ");
                offset  = fDeviceObjectPropertyValue(tvb, pinfo, subtree, offset);
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            case 1: /* status-flags */
                offset = fBitStringTagVS(tvb, pinfo, subtree, offset,
                    "status-flags: ", BACnetStatusFlags);
                break;
            default:
                break;
            }
            if (offset <= lastoffset) break;     /* nothing happened, exit loop */
        }
        break;
    case 22: /* change-of-timer */
        while (tvb_reported_length_remaining(tvb, offset) > 0) {
            /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0: /* new-state */
                offset = fEnumeratedTagSplit(tvb, pinfo, subtree, offset,
                    "new-state: ", BACnetTimerState, 256);
                break;
            case 1: /* status-flags */
                offset = fBitStringTagVS(tvb, pinfo, subtree, offset,
                    "status-flags: ", BACnetStatusFlags);
                break;
            case 2: /* update-time */
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset  = fDateTime(tvb, pinfo, subtree, offset, "update-time: ");
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            case 3: /* last-state-change (OPTIONAL) */
                offset = fEnumeratedTagSplit(tvb, pinfo, subtree, offset,
                    "new-state: ", BACnetTimerTransition, 256);
                break;
            case 4: /* initial-timeout (OPTIONAL) */
                offset  = fUnsignedTag(tvb, pinfo, subtree, offset, "initial-timeout: ");
                break;
            default:
                break;
            }
            if (offset <= lastoffset) break;     /* nothing happened, exit loop */
        }
        break;

        /* todo: add new parameters here ... */
    default:
        offset = fAbstractSyntaxNType(tvb, pinfo, subtree, offset);
        break;
    }

    /* Closing tag for parameter choice */
    offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);

    return offset;
}

static guint
fEventParameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       lastoffset = offset;
    guint8      tag_no, tag_info;
    guint32     lvt;
    proto_tree *subtree = tree;

    fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    subtree = proto_tree_add_subtree_format(subtree, tvb, offset, 0,
        ett_bacapp_value, NULL, "event parameters (%d) %s",
        tag_no, val_to_str_const(tag_no, BACnetEventType, "invalid type"));

    /* Opening tag for parameter choice */
    offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);

    switch (tag_no) {
    case 0: /* change-of-bitstring */
        while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
            if (tag_is_closing(tag_info)) {
                break;
            }
            switch (tag_no) {
            case 0:
                offset = fTimeSpan(tvb, pinfo, subtree, offset, "Time Delay");
                break;
            case 1:
                offset = fBitStringTag(tvb, pinfo, subtree, offset, "bitmask: ");
                break;
            case 2: /* SEQUENCE OF BIT STRING */
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
                    lastoffset = offset;
                    fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
                    if (tag_is_closing(tag_info)) {
                        break;
                    }
                    offset = fBitStringTag(tvb, pinfo, subtree, offset,
                                           "bitstring value: ");
                }
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            default:
                break;
            }
        }
        break;
    case 1: /* change-of-state */
        while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
            if (tag_is_closing(tag_info)) {
                break;
            }
            switch (tag_no) {
            case 0:
                offset = fTimeSpan(tvb, pinfo, subtree, offset, "Time Delay");
                break;
            case 1: /* SEQUENCE OF BACnetPropertyStates */
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
                    lastoffset = offset;
                    fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
                    if (tag_is_closing(tag_info)) {
                        break;
                    }
                    offset = fBACnetPropertyStates(tvb, pinfo, subtree, offset);
                }
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            default:
                break;
            }
        }
        break;
    case 2: /* change-of-value */
        while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset = fTimeSpan(tvb, pinfo, subtree, offset, "Time Delay");
                break;
            case 1: /* don't loop it, it's a CHOICE */
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                switch (fTagNo(tvb, offset)) {
                case 0:
                    offset = fBitStringTag(tvb, pinfo, subtree, offset, "bitmask: ");
                    break;
                case 1:
                    offset = fRealTag(tvb, pinfo, subtree, offset,
                                       "referenced Property Increment: ");
                    break;
                default:
                    break;
                }
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            default:
                break;
            }
        }
        break;
    case 3: /* command-failure */
        while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            tag_no = fTagNo(tvb, offset);
            switch (tag_no) {
            case 0:
                offset = fTimeSpan(tvb, pinfo, subtree, offset, "Time Delay");
                break;
            case 1:
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset  = fDeviceObjectPropertyReference(tvb, pinfo, subtree, offset);
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            default:
                break;
            }
        }
        break;
    case 4: /* floating-limit */
        while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
            if (tag_is_closing(tag_info)) {
                break;
            }
            switch (tag_no) {
            case 0:
                offset = fTimeSpan(tvb, pinfo, subtree, offset, "Time Delay");
                break;
            case 1:
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset  = fDeviceObjectPropertyReference(tvb, pinfo, subtree, offset);
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            case 2:
                offset  = fRealTag(tvb, pinfo, subtree, offset, "low diff limit: ");
                break;
            case 3:
                offset  = fRealTag(tvb, pinfo, subtree, offset, "high diff limit: ");
                break;
            case 4:
                offset  = fRealTag(tvb, pinfo, subtree, offset, "deadband: ");
                break;
            default:
                break;
            }
        }
        break;
    case 5: /* out-of-range */
        while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset = fTimeSpan(tvb, pinfo, subtree, offset, "Time Delay");
                break;
            case 1:
                offset = fRealTag(tvb, pinfo, subtree, offset, "low limit: ");
                break;
            case 2:
                offset = fRealTag(tvb, pinfo, subtree, offset, "high limit: ");
                break;
            case 3:
                offset = fRealTag(tvb, pinfo, subtree, offset, "deadband: ");
                break;
            default:
                break;
            }
        }
        break;
    case 6: /* complex-event-type */
        /* deprecated */
        offset = fBACnetPropertyValue (tvb, pinfo, tree, offset);
        break;
    case 7: /* buffer-ready */
        /* deprecated */
        while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset = fUnsignedTag(tvb, pinfo, tree, offset, "notification threshold");
                break;
            case 1:
                offset = fUnsignedTag(tvb, pinfo, tree, offset,
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
                offset = fTimeSpan(tvb, pinfo, subtree, offset, "Time Delay");
                break;
            case 1:
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
                    lastoffset = offset;
                    fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
                    if (tag_is_closing(tag_info)) {
                        break;
                    }
                    offset = fEnumeratedTagSplit(tvb, pinfo, subtree, offset,
                                                  "life safety alarm value: ", BACnetLifeSafetyState, 256);
                }
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            case 2:
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
                    lastoffset = offset;
                    fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
                    if (tag_is_closing(tag_info)) {
                        break;
                    }
                    offset = fEnumeratedTagSplit(tvb, pinfo, subtree, offset,
                                                  "alarm value: ", BACnetLifeSafetyState, 256);
                }
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            case 3:
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset  = fDeviceObjectPropertyReference(tvb, pinfo, subtree, offset);
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            default:
                break;
            }
        }
        break;
    case 9: /* extended */
        while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset = fVendorIdentifier(tvb, pinfo, tree, offset);
                break;
            case 1:
                offset = fUnsignedTag(tvb, pinfo, tree, offset, "extended-event-type: ");
                break;
            case 2: /* parameters */
                offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
                    lastoffset = offset;
                    fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
                    if (tag_is_closing(tag_info) && tag_no == 2) {
                        break;
                    }

                    if ( ! tag_is_context_specific(tag_info)) {
                        offset  = fApplicationTypes(tvb, pinfo, tree, offset, "parameters: ");
                    } else {
                        if (tag_no == 0) {
                            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                            offset  = fDeviceObjectPropertyReference(tvb, pinfo, tree, offset);
                            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                        } else {
                            offset = fAbstractSyntaxNType(tvb, pinfo, tree, offset);
                        }
                    }
                }
                offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                lastoffset = offset;
                break;
            default:
                break;
            }
            if (offset <= lastoffset) break;     /* nothing happened, exit loop */
        }
        break;
    case 10: /* buffer-ready */
        while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset = fUnsignedTag(tvb, pinfo, subtree, offset,
                                       "notification-threshold: ");
                break;
            case 1:
                offset = fUnsignedTag(tvb, pinfo, subtree, offset,
                                       "previous-notification-count: ");
                break;
            default:
                break;
            }
        }
        break;
    case 11: /* unsigned-range */
        while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset = fTimeSpan(tvb, pinfo, tree, offset, "Time Delay");
                break;
            case 1:
                offset = fUnsignedTag(tvb, pinfo, tree, offset,
                                       "low-limit: ");
                break;
            case 2:
                offset = fUnsignedTag(tvb, pinfo, tree, offset,
                                       "high-limit: ");
                break;
            default:
                break;
            }
        }
        break;
    case 13: /* access-event */
        while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                /* TODO: [0] SEQUENCE OF BACnetAccessEvent */
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
                    lastoffset = offset;
                    fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
                    if (tag_is_closing(tag_info)) {
                        break;
                    }
                    offset = fEnumeratedTagSplit(tvb, pinfo, subtree, offset,
                                                  "access event: ", BACnetAccessEvent, 512);
                }
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            case 1:
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset  = fDeviceObjectPropertyReference(tvb, pinfo, subtree, offset);
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            default:
                break;
            }
        }
        break;
    case 14: /* double-out-of-range */
        while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset = fTimeSpan(tvb, pinfo, subtree, offset, "Time Delay");
                break;
            case 1:
                offset = fDoubleTag(tvb, pinfo, subtree, offset, "low limit: ");
                break;
            case 2:
                offset = fDoubleTag(tvb, pinfo, subtree, offset, "high limit: ");
                break;
            case 3:
                offset = fDoubleTag(tvb, pinfo, subtree, offset, "deadband: ");
                break;
            default:
                break;
            }
        }
        break;
    case 15: /* signed-out-of-range */
        while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset = fTimeSpan(tvb, pinfo, subtree, offset, "Time Delay");
                break;
            case 1:
                offset = fSignedTag(tvb, pinfo, subtree, offset, "low limit: ");
                break;
            case 2:
                offset = fSignedTag(tvb, pinfo, subtree, offset, "high limit: ");
                break;
            case 3:
                offset = fUnsignedTag(tvb, pinfo, subtree, offset, "deadband: ");
                break;
            default:
                break;
            }
        }
        break;
    case 16: /* unsigned-out-of-range */
        while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset = fTimeSpan(tvb, pinfo, subtree, offset, "Time Delay");
                break;
            case 1:
                offset = fUnsignedTag(tvb, pinfo, subtree, offset, "low limit: ");
                break;
            case 2:
                offset = fUnsignedTag(tvb, pinfo, subtree, offset, "high limit: ");
                break;
            case 3:
                offset = fUnsignedTag(tvb, pinfo, subtree, offset, "deadband: ");
                break;
            default:
                break;
            }
        }
        break;
    case 17: /* change-of-characterstring */
        while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset = fTimeSpan(tvb, pinfo, subtree, offset, "Time Delay");
                break;
            case 1: /* SEQUENCE OF CharacterString */
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
                    lastoffset = offset;
                    fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
                    if (tag_is_closing(tag_info)) {
                        break;
                    }
                    offset  = fCharacterString(tvb, pinfo, tree, offset, "alarm value: ");
                }
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            default:
                break;
            }
        }
        break;
    case 18: /* change-of-status-flags */
        while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset = fTimeSpan(tvb, pinfo, subtree, offset, "Time Delay");
                break;
            case 1:
                offset = fBitStringTagVS(tvb, pinfo, subtree, offset,
                    "selected flags: ", BACnetStatusFlags);
                break;
            default:
                break;
            }
        }
        break;
    case 19: /* has been intentionally omitted. It parallels the change-of-reliability event type */
        break;
    case 20: /* none */
        /* no closing tag expected only context tag here */
        return offset;
    case 21: /* change-of-discrete-value */
        while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset = fTimeSpan(tvb, pinfo, subtree, offset, "Time Delay");
                break;
            default:
                break;
            }
        }
        break;
    case 22: /* change-of-timer */
        while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0: /* time-delay */
                offset = fTimeSpan(tvb, pinfo, subtree, offset, "Time Delay");
                break;
            case 1: /* alarm-values */
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
                    lastoffset = offset;
                    fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
                    if (tag_is_closing(tag_info)) {
                        break;
                    }
                offset = fEnumeratedTag(tvb, pinfo, subtree, offset,
                                                  "alarm value: ", BACnetTimerState);
                }
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            case 2: /* update-time-reference */
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset = fDeviceObjectPropertyReference(tvb, pinfo, subtree, offset);
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            default:
                break;
            }
        }
        break;
    /* todo: add new event-parameter cases here */
  default:
        break;
    }

    /* Closing tag for parameter choice */
    offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
    return offset;
}

static guint
fFaultParameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       lastoffset = offset;
    guint8      tag_no, tag_info;
    guint32     lvt;
    proto_tree *subtree = tree;

    fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    subtree = proto_tree_add_subtree_format(subtree, tvb, offset, 0,
      ett_bacapp_value, NULL, "fault parameters (%d) %s",
      tag_no, val_to_str_const(tag_no, BACnetFaultType, "invalid type"));

    /* Opening tag for parameter choice */
    offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);

    switch (tag_no) {
    case 0: /* none */
        /* no closing tag expected only context tag here */
        return offset;
    case 1: /* fault-characterstring */
        while ((tvb_reported_length_remaining(tvb, offset) > 0) && (offset>lastoffset)) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0: /* SEQUENCE OF CharacterString */
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                while ((tvb_reported_length_remaining(tvb, offset) > 0) && (offset>lastoffset)) {  /* exit loop if nothing happens inside */
                    lastoffset = offset;
                    fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
                    if (tag_is_closing(tag_info)) {
                        break;
                    }
                    offset = fCharacterString(tvb, pinfo, subtree, offset, "fault value: ");
                }
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            default:
                break;
            }
        }
        break;
    case 2: /* fault-extended */
        while ((tvb_reported_length_remaining(tvb, offset) > 0) && (offset>lastoffset)) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset = fVendorIdentifier(tvb, pinfo, subtree, offset);
                break;
            case 1:
                offset = fUnsignedTag(tvb, pinfo, subtree, offset, "extended-fault-type: ");
                break;
            case 2: /* parameters */
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset = fApplicationTypes(tvb, pinfo, subtree, offset, "parameters: ");
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                lastoffset = offset;
                break;
            default:
                break;
            }
        }
        break;
    case 3: /* fault-life-safety */
        while ((tvb_reported_length_remaining(tvb, offset) > 0) && (offset>lastoffset)) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                while ((tvb_reported_length_remaining(tvb, offset) > 0) && (offset>lastoffset)) {  /* exit loop if nothing happens inside */
                    lastoffset = offset;
                    fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
                    if (tag_is_closing(tag_info)) {
                        break;
                    }
                    offset = fEnumeratedTag(tvb, pinfo, subtree, offset,
                      "fault value: ", BACnetLifeSafetyState);
                }
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            case 1:
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset = fDeviceObjectPropertyReference(tvb, pinfo, subtree, offset);
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            default:
                break;
            }
        }
        break;
    case 4: /* fault-state */
        while ((tvb_reported_length_remaining(tvb, offset) > 0) && (offset>lastoffset)) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
            if (tag_is_closing(tag_info)) {
                break;
            }
            switch (tag_no) {
            case 0: /* SEQUENCE OF BACnetPropertyStates */
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                while ((tvb_reported_length_remaining(tvb, offset) > 0) && (offset>lastoffset)) {  /* exit loop if nothing happens inside */
                    lastoffset = offset;
                    fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
                    if (tag_is_closing(tag_info)) {
                        break;
                    }
                    offset = fBACnetPropertyStates(tvb, pinfo, subtree, offset);
                }
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            default:
                break;
            }
        }
        break;
    case 5: /* fault-status-flags */
        while ((tvb_reported_length_remaining(tvb, offset) > 0) && (offset>lastoffset)) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset = fDeviceObjectPropertyReference(tvb, pinfo, subtree, offset);
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            default:
                break;
            }
        }
        break;
    case 6: /* fault-out-of-range */
        while ((tvb_reported_length_remaining(tvb, offset) > 0) && (offset>lastoffset)) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
            if (tag_is_closing(tag_info)) {
                break;
            }
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset = fApplicationTypes(tvb, pinfo, subtree, offset, "min-normal-value: ");
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            case 1:
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset = fApplicationTypes(tvb, pinfo, subtree, offset, "max-normal-value: ");
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            default:
                break;
            }
        }
        break;
    case 7: /* fault-listed */
        while ((tvb_reported_length_remaining(tvb, offset) > 0) && (offset>lastoffset)) {  /* exit loop if nothing happens inside */
            lastoffset = offset;
            switch (fTagNo(tvb, offset)) {
            case 0:
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset = fDeviceObjectPropertyReference(tvb, pinfo, subtree, offset);
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            default:
                break;
          }
        }
      break;
    default:
      break;
    }

    /* Closing tag for parameter choice */
    offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
    return offset;
}

static guint
fEventNotificationSubscription(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       lastoffset = 0;
    guint8      tag_no, tag_info;
    guint32     lvt;
    proto_tree *subtree;
    guint       itemno = 1;

    while (tvb_reported_length_remaining(tvb, offset) > 0 && offset > lastoffset) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            return offset;
        }
        switch (tag_no) {
        case 0: /* recipient  */
            tree = proto_tree_add_subtree_format(tree, tvb, offset, 1,
              ett_bacapp_value, NULL, "Subscription %d", itemno);    /* add tree label and indent */
            itemno = itemno + 1;

            subtree = proto_tree_add_subtree(tree, tvb, offset, 1,
              ett_bacapp_value, NULL, "Recipient: ");    /* add tree label and indent */
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt); /* show context open */
            offset = fRecipient(tvb, pinfo, subtree, offset);
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);  /* show context close */
            break;
        case 1: /* process-identifier  */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "Process Identifier: ");
            break;
        case 2: /* issue-confirmed-notifications  */
            offset = fBooleanTag(tvb, pinfo, tree, offset, "Issue Confirmed Notifications: ");
            break;
        case 3: /* time-remaining  */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "Time Remaining: ");
            break;
        default:
            return offset;
        }
    }

    return offset;
}

static guint
fLightingCommand(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *lable)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;
    proto_tree *subtree = tree;

    subtree = proto_tree_add_subtree_format(subtree, tvb, offset, 0,
      ett_bacapp_value, NULL, "%s", lable);

    while (tvb_reported_length_remaining(tvb, offset) > 0 && offset > lastoffset) {
        lastoffset = offset;
        /* check the tag.  A closing tag means we are done */
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            return offset;
        }
        switch (tag_no) {
        case 0: /* operation */
            offset = fEnumeratedTag(tvb, pinfo, subtree, offset, "operation: ", BACnetLightingOperation);
            break;
        case 1: /* target-level */
            offset = fRealTag(tvb, pinfo, subtree, offset, "target-level: ");
            break;
        case 2: /* ramp-rate */
            offset = fRealTag(tvb, pinfo, subtree, offset, "ramp-rate: ");
            break;
        case 3: /* step-increment */
            offset = fRealTag(tvb, pinfo, subtree, offset, "step-increment: ");
            break;
        case 4: /* fade-time */
            offset = fUnsignedTag(tvb, pinfo, subtree, offset, "fade-time: ");
            break;
        case 5: /* priority */
            offset = fUnsignedTag(tvb, pinfo, subtree, offset, "priority: ");
            break;
        default:
            return offset;
        }
    }

    return offset;
}

static guint
fColorCommand(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, guint offset, const gchar* lable)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;
    proto_tree* subtree = tree;

    subtree = proto_tree_add_subtree_format(subtree, tvb, offset, 0,
        ett_bacapp_value, NULL, "%s", lable);

    while (tvb_reported_length_remaining(tvb, offset) > 0 && offset > lastoffset) {
        lastoffset = offset;
        /* check the tag.  A closing tag means we are done */
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            return offset;
        }
        switch (tag_no) {
        case 0: /* operation */
            offset = fEnumeratedTag(tvb, pinfo, subtree, offset, "operation: ", BACnetColorOperation);
            break;
        case 1: /* target-color */
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            offset = fXyColor(tvb, pinfo, subtree, offset, "xy-color: ");
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 2: /* target-color-temperature */
            offset = fUnsignedTag(tvb, pinfo, subtree, offset, "target-color-temperature: ");
            break;
        case 3: /* fade-time */
            offset = fUnsignedTag(tvb, pinfo, subtree, offset, "fade-time: ");
            break;
        case 4: /* ramp-rate */
            offset = fUnsignedTag(tvb, pinfo, subtree, offset, "ramp-rate: ");
            break;
        case 5: /* step-increment */
            offset = fUnsignedTag(tvb, pinfo, subtree, offset, "step-increment: ");
            break;
        default:
            return offset;
        }
    }

    return offset;
}

static guint
fXyColor(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, guint offset, const gchar* label)
{
    proto_tree* subtree = tree;

    if (label != NULL) {
        subtree = proto_tree_add_subtree(subtree, tvb, offset, 10, ett_bacapp_value, NULL, label);
    }
    offset = fRealTag(tvb, pinfo, subtree, offset, "x-coordinate: ");
    return fRealTag(tvb, pinfo, subtree, offset, "y-coordinate: ");
}

static guint
fTimerStateChangeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;
    guint ftag_offset;

    while (tvb_reported_length_remaining(tvb, offset) > 0 && offset > lastoffset) {
        lastoffset = offset;
        /* check the tag. A closing tag means we are done */
        ftag_offset = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            return offset;
        }
        if (tag_is_context_specific(tag_info)){
            switch (tag_no) {
            case 0: /* no-value */
                offset = fNullTag(tvb, pinfo, tree, offset, "no-value: ");
                break;
            case 1: /* constructed-value */
                offset += ftag_offset;
                offset = fAbstractSyntaxNType(tvb, pinfo, tree, offset);
                offset += fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
                break;
            case 2: /* date-time */
                offset += ftag_offset;
                offset = fDateTime(tvb, pinfo, tree, offset, "date-time: ");
                offset += fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
                break;
            case 3: /* lighting-command */
                offset += ftag_offset;
                offset = fLightingCommand(tvb, pinfo, tree, offset, "lighting-command: ");
                offset += fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
                break;
            default:
                return offset;
            }
        }
        else {
            offset = fApplicationTypes(tvb, pinfo, tree, offset, NULL);
        }
    }
    return offset;
}

static guint
fHostAddress(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8  tag_no, tag_info;
    guint32 lvt;

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        switch (tag_no) {
        case 0: /* none */
            offset = fNullTag(tvb, pinfo, tree, offset, "no-value: ");
            break;
        case 1: /* ip-address */
            offset = fOctetString(tvb, pinfo, tree, offset, "ip-address: ", lvt);
            break;
        case 2: /* internet name (see RFC 1123) */
            offset = fCharacterString(tvb, pinfo, tree, offset, "name: ");
            break;
        default:
            return offset;
        }
    }

    return offset;
}

static guint
fHostNPort(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *lable)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;
    proto_tree *subtree = tree;

    subtree = proto_tree_add_subtree_format(subtree, tvb, offset, 0,
        ett_bacapp_value, NULL, "%s", lable);

    while (tvb_reported_length_remaining(tvb, offset) > 0 && offset > lastoffset) {
        lastoffset = offset;
        /* check the tag.  A closing tag means we are done */
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            return offset;
        }
        switch (tag_no) {
        case 0: /* host */
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            offset = fHostAddress(tvb, pinfo, subtree, offset);
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 1: /* port */
            offset = fUnsignedTag(tvb, pinfo, subtree, offset, "port: ");
            break;
        default:
            return offset;
        }
    }

    return offset;
}

static guint
fBDTEntry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *lable)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;
    proto_tree *subtree = tree;

    subtree = proto_tree_add_subtree_format(subtree, tvb, offset, 0,
                ett_bacapp_value, NULL, "%s", lable);

    while (tvb_reported_length_remaining(tvb, offset) > 0 && offset > lastoffset) {
        lastoffset = offset;
        /* check the tag.  A closing tag means we are done */
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            return offset;
        }

        switch (tag_no) {
        case 0: /* bbmd-address */
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            offset = fHostNPort(tvb, pinfo, subtree, offset, "bbmd-address: ");
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 1: /* bbmd-mask */
            offset = fOctetString(tvb, pinfo, subtree, offset, "bbmd-mask: ", lvt);
            break;
        default:
            return offset;
        }
    }

    return offset;
}

static guint
fFDTEntry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const gchar *lable)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;
    proto_tree *subtree = tree;

    subtree = proto_tree_add_subtree_format(subtree, tvb, offset, 0,
                ett_bacapp_value, NULL, "%s", lable);

    while (tvb_reported_length_remaining(tvb, offset) > 0 && offset > lastoffset) {
        lastoffset = offset;
        /* check the tag.  A closing tag means we are done */
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            return offset;
        }

        switch (tag_no) {
        case 0: /* bacnetip-address */
            offset = fOctetString(tvb, pinfo, subtree, offset, "bacnetip-address: ", lvt);
            break;
        case 1: /* time-to-live */
            offset = fUnsignedTag(tvb, pinfo, subtree, offset, "time-to-live: ");
            break;
        case 2: /* remaining-time-to-live */
            offset = fUnsignedTag(tvb, pinfo, subtree, offset, "remaining-time-to-live: ");
            break;
        default:
            return offset;
        }
    }

  return offset;
}

static guint
fRouterEntry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        lastoffset = offset;
        /* check the tag.  A closing tag means we are done */
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            break;
        }
        switch (tag_no) {
        case 0: /* network number */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "network number: ");
            break;
        case 1: /* MAC address */
            offset = fOctetString(tvb, pinfo, tree, offset, "MAC address: ", lvt);
            break;
        case 2: /* status */
            offset = fEnumeratedTag(tvb, pinfo, tree, offset, "status: ", BACnetRouterStatus);
            break;
        case 3: /* performance index */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "performance index: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }

    return offset;
}

static guint
fVMACEntry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        lastoffset = offset;
        /* check the tag.  A closing tag means we are done */
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            break;
        }
        switch (tag_no) {
        case 0: /* virtual mac address */
            offset = fOctetString(tvb, pinfo, tree, offset, "virtual MAC address: ", lvt);
            break;
        case 1: /* native mac address */
            offset = fOctetString(tvb, pinfo, tree, offset, "native MAC address: ", lvt);
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
  }

  return offset;
}

static guint
fValueSource(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8  tag_no, tag_info;
    guint32 lvt;

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        switch (tag_no) {
        case 0: /* null */
            offset = fNullTag(tvb, pinfo, tree, offset, "no-value: ");
            break;
        case 1: /* object reference */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset = fDeviceObjectReference(tvb, pinfo, tree, offset);
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 2: /* address */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset = fAddress(tvb, pinfo, tree, offset);
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        default:
            return offset;
        }
    }

  return offset;
}

static guint
fAssignedLandingCalls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        lastoffset = offset;
        /* check the tag.  A closing tag means we are done */
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            break;
        }
        switch (tag_no) {
        case 0: /* floor number */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "floor number: ");
            break;
        case 1: /* direction */
            offset = fEnumeratedTag(tvb, pinfo, tree, offset, "direction: ", BACnetLiftCarDirection);
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }

    offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
    return offset;
}

static guint
fLandingCallStatus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        lastoffset = offset;
        /* check the tag.  A closing tag means we are done */
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            break;
        }
        switch (tag_no) {
        case 0: /* floor number */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "floor number: ");
            break;
        case 1: /* direction */
            offset = fEnumeratedTag(tvb, pinfo, tree, offset, "direction: ", BACnetLiftCarDirection);
            break;
        case 2: /* destination */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "destination: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }

    return offset;
}

static guint
fLandingDoorStatus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        lastoffset = offset;
        /* check the tag.  A closing tag means we are done */
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            break;
        }
        switch (tag_no) {
        case 0: /* floor number */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "floor number: ");
            break;
        case 1: /* door status */
            offset = fEnumeratedTag(tvb, pinfo, tree, offset, "door status: ", BACnetDoorStatus);
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }

    offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
    return offset;
}

static guint
fCOVMultipleSubscription(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        lastoffset = offset;
        /* check the tag.  A closing tag means we are done */
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            break;
        }
        switch (tag_no) {
        case 0: /* recipient */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset = fRecipientProcess(tvb, pinfo, tree, offset);
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 1: /* issue-confirmed-notifications */
            offset = fBooleanTag(tvb, pinfo, tree, offset, "issue confirmed notifications: ");
            break;
        case 2: /* time-remaining */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "time remaining: ");
            break;
        case 3: /* max-notification-delay */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "max notification delay: ");
            break;
        case 4: /* list-of-cov-subscription-specifications */
            while (tvb_reported_length_remaining(tvb, offset) > 0) {
                lastoffset = offset;
                /* check the tag.  A closing tag means we are done */
                fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
                if (tag_is_closing(tag_info)) {
                    break;
                }
                switch (tag_no) {
                case 0: /* monitored-object-identifier */
                    offset = fObjectIdentifier(tvb, pinfo, tree, offset, "ObjectIdentifier: ");
                    break;
                case 1: /* list-of-cov-references */
                    while (tvb_reported_length_remaining(tvb, offset) > 0) {
                    lastoffset = offset;
                    /* check the tag.  A closing tag means we are done */
                    fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
                    if (tag_is_closing(tag_info)) {
                        break;
                    }
                    switch (tag_no) {
                    case 0: /* monitored-property */
                        offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                        offset = fBACnetPropertyReference(tvb, pinfo, tree, offset, 0);
                        offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                        break;
                    case 1: /* cov-increment */
                        offset = fRealTag(tvb, pinfo, tree, offset, "cov-increment: ");
                        break;
                    case 2: /* timestamped */
                        offset = fBooleanTag(tvb, pinfo, tree, offset, "timestamped: ");
                        break;
                    default:
                        return offset;
                    }
                    if (offset <= lastoffset) break;     /* nothing happened, exit loop */
                    }
                    break;
                default:
                    return offset;
                }
                if (offset <= lastoffset) break;     /* nothing happened, exit loop */
            }
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }

    return offset;
}

static guint
fNameValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        lastoffset = offset;
        /* check the tag.  A closing tag means we are done */
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            break;
        }
        if (tag_is_context_specific(tag_info)) {
            switch (tag_no) {
            case 0: /* name */
            offset = fCharacterString(tvb, pinfo, tree, offset, "name: ");
            break;
            case 1: /* date+time value */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset = fDateTime(tvb, pinfo, tree, offset, "value: ");
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
            default: /* abstract syntax and type */
            /* DMR Should be fAbstractNSyntax, but that's where we came from! */
            offset = fApplicationTypes(tvb, pinfo, tree, offset, "value: ");
            break;
            }
        }
        else {
            /* DMR Should be fAbstractNSyntax, but that's where we came from! */
            offset = fApplicationTypes(tvb, pinfo, tree, offset, "value: ");
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fNameValueCollection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;
    proto_tree *subtree = tree;

    subtree = proto_tree_add_subtree_format(subtree, tvb, offset, 0,
            ett_bacapp_value, NULL, "%s", "name-value-collection: ");

    offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);

    while (tvb_reported_length_remaining(tvb, offset) > 0 && offset > lastoffset) {
        lastoffset = offset;
        /* check the tag.  A closing tag means we are done */
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            break;
        }

        offset = fNameValue(tvb, pinfo, subtree, offset);
    }

    offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
    return offset;
}

static guint
fObjectSelector(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            break;
        }

        switch (tag_no) {
        case 0: /* NULL */
            offset = fNullTag(tvb, pinfo, tree, offset, "NULL: ");
            break;
        case 9: /* object-type */
            offset = fEnumeratedTagSplit(tvb, pinfo, tree, offset, "object-type: ", BACnetObjectType, 256);
            break;
        case 12: /* object */
            offset = fObjectIdentifier(tvb, pinfo, tree, offset, "ObjectIdentifier: ");
            break;
        default:
            break;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fStageLimitValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    if (tvb_reported_length_remaining(tvb, offset) <= 0)
        return offset;
    offset = fRealTag(tvb, pinfo, tree, offset, "limit: ");
    if (tvb_reported_length_remaining(tvb, offset) <= 0)
        return offset;
    offset = fBitStringTag(tvb, pinfo, tree, offset, "values: ");
    if (tvb_reported_length_remaining(tvb, offset) <= 0)
        return offset;
    offset = fRealTag(tvb, pinfo, tree, offset, "deadband: ");
    return offset;
}

static guint
fLifeSafetyInfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            break;
        }

        switch (tag_no) {
        case 0: /* requesting-process-identifier */
            offset  = fUnsignedTag(tvb, pinfo, tree, offset, "requesting-process-identifier: ");
            break;
        case 1: /* request */
            offset  = fEnumeratedTagSplit(tvb, pinfo, tree, offset,
                "requested-operation: ", BACnetLifeSafetyOperation, 64);
            break;
        default:
            break;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fAcknowledgeAlarmInfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            break;
        }

        switch (tag_no) {
        case 0: /* event-state-acknowledged */
            offset  = fEnumeratedTagSplit(tvb, pinfo, tree, offset,
                "event-state-acknowledged: ", BACnetEventState, 64);
            break;
        case 1: /* timestamp */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt); /* show context open */
            offset  = fTimeStamp(tvb, pinfo, tree, offset, "source-timestamp: ");
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt); /* show context close */
            break;
        default:
            break;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fAuditNotificationInfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   len, lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;
    guint32 operation = 0;
    proto_tree *subtree = tree;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            break;
        }

        switch (tag_no) {
        case 0: /* source-timestamp */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt); /* show context open */
            offset  = fTimeStamp(tvb, pinfo, tree, offset, "source-timestamp: ");
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt); /* show context close */
            break;
        case 1: /* target-timestamp */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt); /* show context open */
            offset  = fTimeStamp(tvb, pinfo, tree, offset, "target-timestamp: ");
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt); /* show context close */
            break;
        case 2: /* source-device */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_bacapp_value, NULL, "source-device: ");
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt); /* show context open */
            offset = fRecipient(tvb, pinfo, subtree, offset);
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt); /* show context close */
            break;
        case 3: /* source-object */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_bacapp_value, NULL, "source-object: ");
            offset = fObjectIdentifier(tvb, pinfo, subtree, offset, "ObjectIdentifier: ");
            break;
        case 4: /* operation */
            fUnsigned32(tvb, offset, lvt, &operation);
            offset  = fEnumeratedTagSplit(tvb, pinfo, tree, offset,
                  "operation: ", BACnetAuditOperation, 64);
            break;
        case 5: /* source-comment */
            offset  = fCharacterString(tvb, pinfo, tree, offset, "source-comment: ");
            break;
        case 6: /* target-comment */
            offset  = fCharacterString(tvb, pinfo, tree, offset, "target-comment: ");
            break;
        case 7: /* invoke-id */
            offset  = fUnsignedTag(tvb, pinfo, tree, offset, "invoke-id: ");
            break;
        case 8: /* source-user-id */
            offset  = fUnsignedTag(tvb, pinfo, tree, offset, "source-user-id: ");
            break;
        case 9: /* source-user-role */
            offset  = fUnsignedTag(tvb, pinfo, tree, offset, "source-user-role: ");
            break;
        case 10: /* target-device */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_bacapp_value, NULL, "target-device: ");
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt); /* show context open */
            offset = fRecipient(tvb, pinfo, subtree, offset);
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt); /* show context close */
            break;
        case 11: /* target-object */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_bacapp_value, NULL, "target-object: ");
            offset = fObjectIdentifier(tvb, pinfo, subtree, offset, "ObjectIdentifier: ");
            break;
        case 12: /* target-property */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_bacapp_value, NULL, "target-property: ");
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt); /* show context open */
            offset = fPropertyReference(tvb, pinfo, subtree, offset, 0, 0);
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt); /* show context close */
            break;
        case 13: /* target-priority */
            offset  = fUnsignedTag(tvb, pinfo, tree, offset, "target-priority: ");
            break;
        case 14: /* target-value */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_bacapp_value, NULL, "target-value: ");
            if (operation == 4) {
                /* operation life safety */
                /* inspect next tag */
                fTagHeader(tvb, pinfo, offset + len, &tag_no, &tag_info, &lvt);
                if ( tag_no == 0 &&
                     ! tag_is_opening(tag_info) &&
                     tag_is_context_specific(tag_info) ) {
                    offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt); /* show context open */
                    offset = fLifeSafetyInfo(tvb, pinfo, subtree, offset);
                    offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt); /* show context close */
                } else {
                    /* abstract syntax and type */
                    offset = fPropertyValue(tvb, pinfo, subtree, offset, tag_info);
                }
            } else if ( operation == 5 ) {
                /* operation acknowledge alarm */
                /* inspect next tag */
                fTagHeader(tvb, pinfo, offset + len, &tag_no, &tag_info, &lvt);
                if ( tag_no == 0 &&
                     ! tag_is_opening(tag_info) &&
                     tag_is_context_specific(tag_info) ) {
                    offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt); /* show context open */
                    offset = fAcknowledgeAlarmInfo(tvb, pinfo, subtree, offset);
                    offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt); /* show context close */
                } else {
                    /* abstract syntax and type */
                    offset = fPropertyValue(tvb, pinfo, subtree, offset, tag_info);
                }
            } else {
                /* abstract syntax and type */
                offset = fPropertyValue(tvb, pinfo, subtree, offset, tag_info);
            }
            break;
        case 15: /* current-value */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_bacapp_value, NULL, "current-value: ");
            /* always abstract syntax and type */
            offset = fPropertyValue(tvb, pinfo, subtree, offset, tag_info);
            break;
        case 16: /* error-result */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_bacapp_value, NULL, "error-result: ");
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt); /* show context open */
            offset = fError(tvb, pinfo, subtree, offset);
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt); /* show context close */
            break;
        default:
            break;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fAuditLogRecord(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       lastoffset = 0;
    guint8      tag_no, tag_info;
    guint32     lvt;
    proto_tree *subtree = tree;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            break;
        }

        switch (tag_no) {
        case 0: /* timestamp */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset  = fDate(tvb, pinfo, tree, offset, "Date: ");
            offset  = fTime(tvb, pinfo, tree, offset, "Time: ");
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 1: /* logDatum: don't loop, it's a CHOICE */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            switch (fTagNo(tvb, offset)) {
            case 0: /* logStatus */    /* Changed this to BitString per BACnet Spec. */
                offset = fBitStringTagVS(tvb, pinfo, tree, offset, "log status:", BACnetLogStatus);
                break;
            case 1: /* notification */
                subtree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_bacapp_value, NULL, "notification: ");
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset  = fAuditNotificationInfo(tvb, pinfo, subtree, offset);
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            case 2: /* time-change */
                offset = fRealTag(tvb, pinfo, tree, offset, "time-change: ");
                break;
            default:
                return offset;
            }
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fEventLogRecord(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       lastoffset = 0;
    guint8      tag_no, tag_info;
    guint32     lvt;
    proto_tree *subtree = tree;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        switch (fTagNo(tvb, offset)) {
        case 0: /* timestamp */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset  = fDate(tvb, pinfo, tree, offset, "Date: ");
            offset  = fTime(tvb, pinfo, tree, offset, "Time: ");
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 1: /* logDatum: don't loop, it's a CHOICE */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            switch (fTagNo(tvb, offset)) {
            case 0: /* logStatus */    /* Changed this to BitString per BACnet Spec. */
                offset = fBitStringTagVS(tvb, pinfo, tree, offset, "log status:", BACnetLogStatus);
                break;
            case 1: /* notification */
                subtree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_bacapp_value, NULL, "notification: ");
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset  = fConfirmedEventNotificationRequest(tvb, pinfo, subtree, offset);
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                break;
            case 2: /* time-change */
                offset = fRealTag(tvb, pinfo, tree, offset, "time-change: ");
                break;
            default:
                return offset;
            }
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fLogRecord(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;
    gint32  save_propertyIdentifier;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        switch (fTagNo(tvb, offset)) {
        case 0: /* timestamp */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset  = fDate(tvb, pinfo, tree, offset, "Date: ");
            offset  = fTime(tvb, pinfo, tree, offset, "Time: ");
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 1: /* logDatum: don't loop, it's a CHOICE */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            switch (fTagNo(tvb, offset)) {
            case 0: /* logStatus */    /* Changed this to BitString per BACnet Spec. */
                offset = fBitStringTagVS(tvb, pinfo, tree, offset, "log status: ", BACnetLogStatus);
                break;
            case 1:
                offset = fBooleanTag(tvb, pinfo, tree, offset, "boolean-value: ");
                break;
            case 2:
                offset = fRealTag(tvb, pinfo, tree, offset, "real value: ");
                break;
            case 3:
                offset = fUnsignedTag(tvb, pinfo, tree, offset, "enum value: ");
                break;
            case 4:
                offset = fUnsignedTag(tvb, pinfo, tree, offset, "unsigned value: ");
                break;
            case 5:
                offset = fSignedTag(tvb, pinfo, tree, offset, "signed value: ");
                break;
            case 6:
                offset = fBitStringTag(tvb, pinfo, tree, offset, "bitstring value: ");
                break;
            case 7:
                offset = fNullTag(tvb, pinfo, tree, offset, "null value: ");
                break;
            case 8:
                offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                offset  = fError(tvb, pinfo, tree, offset);
                offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                break;
            case 9:
                offset = fRealTag(tvb, pinfo, tree, offset, "time change: ");
                break;
            case 10:    /* any Value */
                offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                /* this ASN-1 construction may contain also an property identifier, so
                   save the one we have got and restore it later and invalidate current
                   one to avoid misinterpretations */
                save_propertyIdentifier = propertyIdentifier;
                propertyIdentifier = -1;
                offset  = fAbstractSyntaxNType(tvb, pinfo, tree, offset);
                propertyIdentifier = save_propertyIdentifier;
                offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                break;
            default:
                return offset;
            }
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 2:
            /* Changed this to BitString per BACnet Spec. */
            offset = fBitStringTagVS(tvb, pinfo, tree, offset, "Status Flags: ", BACnetStatusFlags);
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fLogMultipleRecord(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;
    gint32  save_propertyIdentifier;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        switch (fTagNo(tvb, offset)) {
        case 0: /* timestamp */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset  = fDate(tvb, pinfo, tree, offset, "Date: ");
            offset  = fTime(tvb, pinfo, tree, offset, "Time: ");
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 1: /* logData: don't loop, it's a CHOICE */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            switch (fTagNo(tvb, offset)) {
            case 0: /* logStatus */    /* Changed this to BitString per BACnet Spec. */
                offset = fBitStringTagVS(tvb, pinfo, tree, offset, "log status: ", BACnetLogStatus);
                break;
            case 1: /* log-data: SEQUENCE OF CHOICE */
                offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                while ((tvb_reported_length_remaining(tvb, offset) > 0) && (offset != lastoffset)) {  /* exit loop if nothing happens inside */
                    lastoffset = offset;
                    fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
                    if (tag_is_closing(tag_info)) {
                        lastoffset = offset;
                        break;
                    }
                    switch (tag_no) {
                    case 0:
                        offset = fBooleanTag(tvb, pinfo, tree, offset, "boolean-value: ");
                        break;
                    case 1:
                        offset = fRealTag(tvb, pinfo, tree, offset, "real value: ");
                        break;
                    case 2:
                        offset = fUnsignedTag(tvb, pinfo, tree, offset, "enum value: ");
                        break;
                    case 3:
                        offset = fUnsignedTag(tvb, pinfo, tree, offset, "unsigned value: ");
                        break;
                    case 4:
                        offset = fSignedTag(tvb, pinfo, tree, offset, "signed value: ");
                        break;
                    case 5:
                        offset = fBitStringTag(tvb, pinfo, tree, offset, "bitstring value: ");
                        break;
                    case 6:
                        offset = fNullTag(tvb, pinfo, tree, offset, "null value: ");
                        break;
                    case 7:
                        offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                        offset  = fError(tvb, pinfo, tree, offset);
                        offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                        break;
                    case 8: /* any Value */
                        offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                        /* this ASN-1 construction may contain also an property identifier, so
                           save the one we have got and restore it later and invalidate current
                           one to avoid misinterpretations */
                        save_propertyIdentifier = propertyIdentifier;
                        propertyIdentifier = -1;
                        offset  = fAbstractSyntaxNType(tvb, pinfo, tree, offset);
                        propertyIdentifier = save_propertyIdentifier;
                        offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                        break;
                    default:
                        return offset;
                    }
                }
                offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                break;
            case 2:
                offset = fRealTag(tvb, pinfo, tree, offset, "time-change: ");
                break;
            default:
                return offset;
            }
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}


static guint
fConfirmedEventNotificationRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            break;
        }

        switch (tag_no) {
        case 0: /* ProcessId */
            offset  = fProcessId(tvb, pinfo, tree, offset);
            break;
        case 1: /* initiating ObjectId */
            offset  = fObjectIdentifier(tvb, pinfo, tree, offset, "ObjectIdentifier: ");
            break;
        case 2: /* event ObjectId */
            offset  = fObjectIdentifier(tvb, pinfo, tree, offset, "ObjectIdentifier: ");
            break;
        case 3: /* time stamp */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset  = fTimeStamp(tvb, pinfo, tree, offset, NULL);
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 4: /* notificationClass */
            offset  = fUnsignedTag(tvb, pinfo, tree, offset, "Notification Class: ");
            break;
        case 5: /* Priority */
            offset  = fUnsignedTag(tvb, pinfo, tree, offset, "Priority: ");
            break;
        case 6: /* EventType */
            offset = fEventType(tvb, pinfo, tree, offset);
            break;
        case 7: /* messageText */
            offset  = fCharacterString(tvb, pinfo, tree, offset, "message Text: ");
            break;
        case 8: /* NotifyType */
            offset = fNotifyType(tvb, pinfo, tree, offset);
            break;
        case 9: /* ackRequired */
            offset  = fBooleanTag(tvb, pinfo, tree, offset, "ack Required: ");
            break;
        case 10: /* fromState */
            offset = fFromState(tvb, pinfo, tree, offset);
            break;
        case 11: /* toState */
            offset = fToState(tvb, pinfo, tree, offset);
            break;
        case 12: /* NotificationParameters */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset  = fNotificationParameters(tvb, pinfo, tree, offset);
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        default:
            break;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fUnconfirmedEventNotificationRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    return fConfirmedEventNotificationRequest(tvb, pinfo, tree, offset);
}

static guint
fConfirmedCOVNotificationMultipleRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       lastoffset = 0, len;
    guint8      tag_no, tag_info;
    guint32     lvt;
    proto_tree *subtree = tree;
    proto_tree *subsubtree = tree;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            offset += len;
            subtree = tree;
            continue;
        }

        switch (tag_no) {
        case 0: /* ProcessId */
            offset = fProcessId(tvb, pinfo, tree, offset);
            break;
        case 1: /* initiating DeviceId */
            offset = fObjectIdentifier(tvb, pinfo, tree, offset, "DeviceIdentifier: ");
            break;
        case 2: /* time remaining */
            offset = fTimeSpan(tvb, pinfo, tree, offset, "Time remaining: ");
            break;
        case 3: /* timestamp */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset = fDateTime(tvb, pinfo, tree, offset, "Timestamp: ");
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 4: /* list-of-cov-notifications */
            if (tag_is_opening(tag_info)) {
                /* new subtree for list-of-cov-notifications */
                subtree = proto_tree_add_subtree(subtree, tvb, offset, 1, ett_bacapp_value, NULL, "list-of-cov-notifications: ");
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);

                while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
                    lastoffset = offset;
                    len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
                    if (tag_is_closing(tag_info)) {
                        /* end for list-of-cov-notifications */
                        fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                        offset += len;
                        subtree = tree;
                        break;
                    }

                    switch (tag_no) {
                    case 0: /* monitored-object-identifier */
                        offset = fObjectIdentifier(tvb, pinfo, subtree, offset, "ObjectIdentifier: ");
                        break;
                    case 1: /* list-of-values */
                        if (tag_is_opening(tag_info)) {
                            /* new subtree for list-of-values */
                            subsubtree = proto_tree_add_subtree(subtree, tvb, offset, 1, ett_bacapp_value, NULL, "list-of-values: ");
                            offset += fTagHeaderTree(tvb, pinfo, subsubtree, offset, &tag_no, &tag_info, &lvt);

                            while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
                            lastoffset = offset;
                            len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
                            if (tag_is_closing(tag_info)) {
                                /* end of list-of-values */
                                fTagHeaderTree(tvb, pinfo, subsubtree, offset, &tag_no, &tag_info, &lvt);
                                offset += len;
                                break;
                            }

                            switch (tag_no) {
                            case 0: /* PropertyIdentifier */
                                offset = fPropertyIdentifier(tvb, pinfo, subsubtree, offset);
                                break;
                            case 1: /* propertyArrayIndex */
                                offset = fPropertyArrayIndex(tvb, pinfo, subsubtree, offset);
                                break;
                            case 2: /* property-value */
                                offset = fPropertyValue(tvb, pinfo, subsubtree, offset, tag_info);
                                break;
                            case 3: /* time-of-change */
                                offset = fTime(tvb, pinfo, subsubtree, offset, "time of change: ");
                                break;
                            default:
                                /* wrong tag encoding */
                                return offset;
                            }
                            if (offset <= lastoffset) break;     /* nothing happened, exit loop */
                            }
                        }
                        else {
                            /* wrong tag encoding */
                            expert_add_info(pinfo, subsubtree, &ei_bacapp_bad_tag);
                        }
                        break;
                    default:
                        /* wrong tag encoding */
                        return offset;
                    }
                    if (offset <= lastoffset) break;     /* nothing happened, exit loop */
                }
            }
            else {
                /* wrong tag encoding */
                expert_add_info(pinfo, subtree, &ei_bacapp_bad_tag);
            }
            break;
        default:
            /* wrong tag encoding */
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fUnconfirmedCOVNotificationMultipleRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    return fConfirmedCOVNotificationMultipleRequest(tvb, pinfo, tree, offset);
}

static guint
fConfirmedCOVNotificationRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       lastoffset = 0, len;
    guint8      tag_no, tag_info;
    guint32     lvt;
    proto_tree *subtree = tree;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            offset += len;
            subtree = tree;
            continue;
        }

        switch (tag_no) {
        case 0: /* ProcessId */
            offset = fProcessId(tvb, pinfo, tree, offset);
            break;
        case 1: /* initiating DeviceId */
            offset = fObjectIdentifier(tvb, pinfo, subtree, offset, "DeviceIdentifier: ");
            break;
        case 2: /* monitored ObjectId */
            offset = fObjectIdentifier(tvb, pinfo, subtree, offset, "ObjectIdentifier: ");
            break;
        case 3: /* time remaining */
            offset = fTimeSpan(tvb, pinfo, tree, offset, "Time remaining: ");
            break;
        case 4: /* List of Values */
            if (tag_is_opening(tag_info)) {
            subtree = proto_tree_add_subtree(subtree, tvb, offset, 1, ett_bacapp_value, NULL, "list of Values: ");
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            offset = fBACnetPropertyValue(tvb, pinfo, subtree, offset);
            }
            else {
            expert_add_info(pinfo, subtree, &ei_bacapp_bad_tag);
            }
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fUnconfirmedCOVNotificationRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    return fConfirmedCOVNotificationRequest(tvb, pinfo, tree, offset);
}

static guint
fAcknowledgeAlarmRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no = 0, tag_info = 0;
    guint32 lvt = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        switch (fTagNo(tvb, offset)) {
        case 0: /* acknowledgingProcessId */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "acknowledging Process Id: ");
            break;
        case 1: /* eventObjectId */
            offset = fObjectIdentifier(tvb, pinfo, tree, offset, "ObjectIdentifier: ");
            break;
        case 2: /* eventStateAcknowledged */
            offset = fEnumeratedTagSplit(tvb, pinfo, tree, offset,
                "event State Acknowledged: ", BACnetEventState, 64);
            break;
        case 3: /* timeStamp */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset  = fTimeStamp(tvb, pinfo, tree, offset, NULL);
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 4: /* acknowledgementSource */
            offset  = fCharacterString(tvb, pinfo, tree, offset, "acknowledgement Source: ");
            break;
        case 5: /* timeOfAcknowledgement */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset  = fTimeStamp(tvb, pinfo, tree, offset, "acknowledgement timestamp: ");
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fGetAlarmSummaryAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        offset = fApplicationTypes(tvb, pinfo, tree, offset, "Object Identifier: ");
        offset = fApplicationTypesEnumeratedSplit(tvb, pinfo, tree, offset,
            "alarm State: ", BACnetEventState, 64);
        offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset,
            "acknowledged Transitions: ", BACnetEventTransitionBits);
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return  offset;
}

static guint
fGetEnrollmentSummaryRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        switch (fTagNo(tvb, offset)) {
        case 0: /* acknowledgmentFilter */
            offset = fEnumeratedTag(tvb, pinfo, tree, offset,
                "acknowledgment Filter: ", BACnetAcknowledgementFilter);
            break;
        case 1: /* eventObjectId - OPTIONAL */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset  = fRecipientProcess(tvb, pinfo, tree, offset);
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 2: /* eventStateFilter */
            offset  = fEnumeratedTag(tvb, pinfo, tree, offset,
                "event State Filter: ", BACnetEventStateFilter);
            break;
        case 3: /* eventTypeFilter - OPTIONAL */
            offset  = fEnumeratedTag(tvb, pinfo, tree, offset,
                "event Type Filter: ", BACnetEventType);
            break;
        case 4: /* priorityFilter */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset  = fUnsignedTag(tvb, pinfo, tree, offset, "min Priority: ");
            offset  = fUnsignedTag(tvb, pinfo, tree, offset, "max Priority: ");
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 5: /* notificationClassFilter - OPTIONAL */
            offset  = fUnsignedTag(tvb, pinfo, tree, offset, "notification Class Filter: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fGetEnrollmentSummaryAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        offset = fApplicationTypes(tvb, pinfo, tree, offset, "Object Identifier: ");
        offset = fApplicationTypesEnumeratedSplit(tvb, pinfo, tree, offset,
            "event Type: ", BACnetEventType, 64);
        offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset,
            "event State: ", BACnetEventState);
        offset = fApplicationTypes(tvb, pinfo, tree, offset, "Priority: ");
        if (tvb_reported_length_remaining(tvb, offset) > 0 && fTagNo(tvb, offset) == 2)  /* Notification Class - OPTIONAL */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "Notification Class: ");
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }

    return  offset;
}

static guint
fGetEventInformationRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        if (fTagNo(tvb, offset) == 0) {
            offset = fObjectIdentifier(tvb, pinfo, tree, offset, "ObjectIdentifier: ");
        }
    }
    return offset;
}

static guint
flistOfEventSummaries(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       lastoffset = 0;
    guint8      tag_no, tag_info;
    guint32     lvt;
    proto_tree* subtree = tree;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        /* we are finished here if we spot a closing tag */
        if (tag_is_closing(tag_info)) {
            break;
        }
        switch (tag_no) {
        case 0: /* ObjectId */
            offset = fObjectIdentifier(tvb, pinfo, tree, offset, "ObjectIdentifier: ");
            break;
        case 1: /* eventState */
            offset = fEnumeratedTag(tvb, pinfo, tree, offset,
                "event State: ", BACnetEventState);
            break;
        case 2: /* acknowledgedTransitions */
            offset = fBitStringTagVS(tvb, pinfo, tree, offset,
                "acknowledged Transitions: ", BACnetEventTransitionBits);
            break;
        case 3: /* eventTimeStamps */
            subtree = proto_tree_add_subtree(tree, tvb, offset, lvt, ett_bacapp_tag, NULL, "eventTimeStamps");
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            offset  = fTimeStamp(tvb, pinfo, subtree, offset, "TO-OFFNORMAL timestamp: ");
            offset  = fTimeStamp(tvb, pinfo, subtree, offset, "TO-FAULT timestamp: ");
            offset  = fTimeStamp(tvb, pinfo, subtree, offset, "TO-NORMAL timestamp: ");
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 4: /* notifyType */
            offset = fNotifyType(tvb, pinfo, tree, offset);
            break;
        case 5: /* eventEnable */
            offset  = fBitStringTagVS(tvb, pinfo, tree, offset,
                "event Enable: ", BACnetEventTransitionBits);
            break;
        case 6: /* eventPriorities */
            subtree = proto_tree_add_subtree(tree, tvb, offset, lvt, ett_bacapp_tag, NULL, "eventPriorities");
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            offset  = fUnsignedTag(tvb, pinfo, subtree, offset, "TO-OFFNORMAL Priority: ");
            offset  = fUnsignedTag(tvb, pinfo, subtree, offset, "TO-FAULT Priority: ");
            offset  = fUnsignedTag(tvb, pinfo, subtree, offset, "TO-NORMAL Priority: ");
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fLOPR(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    col_set_writable(pinfo->cinfo, COL_INFO, FALSE); /* don't set all infos into INFO column */
    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        /* we are finished here if we spot a closing tag */
        if (tag_is_closing(tag_info)) {
            break;
        }
        offset = fDeviceObjectPropertyReference(tvb, pinfo, tree, offset);
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fGetEventInformationACK(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        switch (fTagNo(tvb, offset)) {
        case 0: /* listOfEventSummaries */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset  = flistOfEventSummaries(tvb, pinfo, tree, offset);
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 1: /* moreEvents */
            offset  = fBooleanTag(tvb, pinfo, tree, offset, "more Events: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fAddListElementRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       lastoffset = 0, len;
    guint8      tag_no, tag_info;
    guint32     lvt;
    proto_tree *subtree    = tree;

    col_set_writable(pinfo->cinfo, COL_INFO, FALSE); /* don't set all infos into INFO column */

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            offset += len;
            subtree = tree;
            continue;
        }

        switch (tag_no) {
        case 0: /* ObjectId */
            offset = fBACnetObjectPropertyReference(tvb, pinfo, subtree, offset);
            break;
        case 3: /* listOfElements */
            if (tag_is_opening(tag_info)) {
                subtree = proto_tree_add_subtree(subtree, tvb, offset, 1, ett_bacapp_value, NULL, "listOfElements");
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset  = fAbstractSyntaxNType(tvb, pinfo, subtree, offset);
                fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            } else {
                expert_add_info(pinfo, subtree, &ei_bacapp_bad_tag);
            }
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fDeleteObjectRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    return fObjectIdentifier(tvb, pinfo, tree, offset, "ObjectIdentifier: ");
}

static guint
fDeviceCommunicationControlRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;

        switch (fTagNo(tvb, offset)) {
        case 0: /* timeDuration */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "time Duration: ");
            break;
        case 1: /* enable-disable */
            offset = fEnumeratedTag(tvb, pinfo, tree, offset, "enable-disable: ",
                BACnetEnableDisable);
            break;
        case 2: /* password - OPTIONAL */
            offset = fCharacterString(tvb, pinfo, tree, offset, "Password: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fReinitializeDeviceRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;

        switch (fTagNo(tvb, offset)) {
        case 0: /* reinitializedStateOfDevice */
            offset = fEnumeratedTag(tvb, pinfo, tree, offset,
                "reinitialized State Of Device: ",
                BACnetReinitializedStateOfDevice);
            break;
        case 1: /* password - OPTIONAL */
            offset = fCharacterString(tvb, pinfo, tree, offset, "Password: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fVtOpenRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset,
                                          "vtClass: ", BACnetVTClass);
    return fApplicationTypes(tvb, pinfo, tree, offset, "local VT Session ID: ");
}

static guint
fVtOpenAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    return fApplicationTypes(tvb, pinfo, tree, offset, "remote VT Session ID: ");
}

static guint
fVtCloseRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        offset= fApplicationTypes(tvb, pinfo, tree, offset, "remote VT Session ID: ");
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fVtDataRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    offset= fApplicationTypes(tvb, pinfo, tree, offset, "VT Session ID: ");
    offset = fApplicationTypes(tvb, pinfo, tree, offset, "VT New Data: ");
    return fApplicationTypes(tvb, pinfo, tree, offset, "VT Data Flag: ");
}

static guint
fVtDataAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;

        switch (fTagNo(tvb, offset)) {
        case 0: /* BOOLEAN */
            offset = fBooleanTag(tvb, pinfo, tree, offset, "all New Data Accepted: ");
            break;
        case 1: /* Unsigned OPTIONAL */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "accepted Octet Count: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fConfirmedAuditNotificationRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint   firstloop = 1;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        }

        if (tag_is_opening(tag_info) && firstloop) {
            firstloop = 0;
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
        }

        offset = fAuditNotificationInfo(tvb, pinfo, tree, offset);
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fUnconfirmedAuditNotificationRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    return fConfirmedAuditNotificationRequest(tvb, pinfo, tree, offset);
}

static guint
fAuditLogQueryByTargetParameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            break;
        }

        switch (tag_no) {
        case 0: /* target-device-identifier */
            offset = fObjectIdentifier(tvb, pinfo, tree, offset, "DeviceIdentifier: ");
            break;
        case 1: /* target-device-address */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset  = fAddress(tvb, pinfo, tree, offset);
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 2: /* target-object-identifier */
            offset = fObjectIdentifier(tvb, pinfo, tree, offset, "ObjectIdentifier: ");
            break;
        case 3: /* target-property-identifier */
            offset = fPropertyIdentifier(tvb, pinfo, tree, offset);
            break;
        case 4: /* target-property-array-index */
            offset = fPropertyArrayIndex(tvb, pinfo, tree, offset);
            break;
        case 5: /* target-priority */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "target-priority: ");
            break;
        case 6: /* target-operation */
            offset  = fBitStringTagVS(tvb, pinfo, tree, offset,
                  "target-operation: ", BACnetAuditOperation);
            break;
        case 7: /* successful-action */
            offset  = fEnumeratedTagSplit(tvb, pinfo, tree, offset,
                  "target-successful-action: ", BACnetSuccessFilter, 64);
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fAuditLogQueryBySourceParameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            break;
        }

        switch (tag_no) {
        case 0: /* source-device-identifier */
            offset = fObjectIdentifier(tvb, pinfo, tree, offset, "DeviceIdentifier: ");
            break;
        case 1: /* source-device-address */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset  = fAddress(tvb, pinfo, tree, offset);
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 2: /* source-object-identifier */
            offset = fObjectIdentifier(tvb, pinfo, tree, offset, "ObjectIdentifier: ");
            break;
        case 3: /* source-operation */
            offset  = fBitStringTagVS(tvb, pinfo, tree, offset,
                  "source-operation: ", BACnetAuditOperation);
            break;
        case 4: /* successful-action */
            offset  = fEnumeratedTagSplit(tvb, pinfo, tree, offset,
                  "source-successful-action: ", BACnetSuccessFilter, 64);
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fAuditLogQueryParameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;
    proto_tree *subtree = tree;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            break;
        }

        switch (tag_no) {
        case 0: /* query-by-target-parameters */
            subtree = proto_tree_add_subtree(subtree, tvb, offset, 1, ett_bacapp_value, NULL, "target-parameters: ");
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            offset  = fAuditLogQueryByTargetParameters(tvb, pinfo, subtree, offset);
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 1: /* query-by-source-parameters */
            subtree = proto_tree_add_subtree(subtree, tvb, offset, 1, ett_bacapp_value, NULL, "source-parameters: ");
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            offset  = fAuditLogQueryBySourceParameters(tvb, pinfo, subtree, offset);
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fAuditLogQueryRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;
    proto_tree *subtree = tree;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);

        switch (tag_no) {
        case 0: /* audit-log */
            offset = fObjectIdentifier(tvb, pinfo, tree, offset, "ObjectIdentifier: ");
            break;
        case 1: /* query-parameters */
            subtree = proto_tree_add_subtree(subtree, tvb, offset, 1, ett_bacapp_value, NULL, "query-parameters: ");
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            offset = fAuditLogQueryParameters(tvb, pinfo, subtree, offset);
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 2: /* start-at-sequence-number */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "start-at-sequence-number: ");
            break;
        case 3: /* requested-count */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "requested-count: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fAuditLogRecordResult(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;
    proto_tree *subtree = tree;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            break;
        }

        switch (tag_no) {
        case 0 : /* sequence-number */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "sequence-number: ");
            break;
        case 1: /* log-record */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_bacapp_value, NULL, "log-record: ");
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            offset = fAuditLogRecord(tvb, pinfo, subtree, offset);
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fAuditLogQueryAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;
    proto_tree *subtree = tree;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);

        switch (tag_no) {
        case 0: /* audit-log */
            offset = fObjectIdentifier(tvb, pinfo, tree, offset, "ObjectIdentifier: ");
            break;
        case 1: /* records */
            subtree = proto_tree_add_subtree(subtree, tvb, offset, 1, ett_bacapp_value, NULL, "records: ");
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            offset = fAuditLogRecordResult(tvb, pinfo, subtree, offset);
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 2: /* no-more-items */
            offset = fBooleanTag(tvb, pinfo, tree, offset, "no-more-items: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fWhoAmIRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        offset = fApplicationTypes(tvb, pinfo, tree, offset, "Vendor ID: ");
        offset = fApplicationTypes(tvb, pinfo, tree, offset, "Model name: ");
        offset = fApplicationTypes(tvb, pinfo, tree, offset, "Serial number: ");
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fYouAreRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        offset = fApplicationTypes(tvb, pinfo, tree, offset, "Vendor ID: ");
        offset = fApplicationTypes(tvb, pinfo, tree, offset, "Model name: ");
        offset = fApplicationTypes(tvb, pinfo, tree, offset, "Serial number: ");
        if(tvb_reported_length_remaining(tvb, offset) > 0) {
            offset = fApplicationTypes(tvb, pinfo, tree, offset, "Device Identifier: ");
        }
        if(tvb_reported_length_remaining(tvb, offset) > 0) {
            offset = fApplicationTypes(tvb, pinfo, tree, offset, "Device MAC address: ");
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fAuthenticateRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;

        switch (fTagNo(tvb, offset)) {
        case 0: /* Unsigned32 */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "pseudo Random Number: ");
            break;
        case 1: /* expected Invoke ID Unsigned8 OPTIONAL */
            proto_tree_add_item(tree, hf_bacapp_invoke_id, tvb, offset++, 1, ENC_BIG_ENDIAN);
            break;
        case 2: /* Chararacter String OPTIONAL */
            offset = fCharacterString(tvb, pinfo, tree, offset, "operator Name: ");
            break;
        case 3: /* Chararacter String OPTIONAL */
            offset = fCharacterString(tvb, pinfo, tree, offset, "operator Password: ");
            break;
        case 4: /* Boolean OPTIONAL */
            offset = fBooleanTag(tvb, pinfo, tree, offset, "start Encyphered Session: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fAuthenticateAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    return fApplicationTypes(tvb, pinfo, tree, offset, "modified Random Number: ");
}

static guint
fAuthenticationFactor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        /* quit loop if we spot a closing tag */
        if (tag_is_closing(tag_info)) {
            break;
        }

        switch (tag_no) {
        case 0: /* format-type */
            offset = fEnumeratedTag(tvb, pinfo, tree, offset, "formet-type: ", NULL);
            break;
        case 1: /* format-class */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "format-class: ");
            break;
        case 2: /* value */
            offset = fOctetString(tvb, pinfo, tree, offset, "value: ", lvt);
            break;
        default:
            break;
        }

        if (offset <= lastoffset) break;    /* nothing happened, exit loop */
    }

    return offset;
}

static guint
fAuthenticationFactorFormat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        /* quit loop if we spot a closing tag */
        if (tag_is_closing(tag_info)) {
            break;
        }

        switch (tag_no) {
        case 0: /* format-type */
            offset = fEnumeratedTag(tvb, pinfo, tree, offset, "formet-type: ", NULL);
            break;
        case 1: /* vendor-id */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "vendor-id: ");
            break;
        case 2: /* vendor-format */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "vendor-format: ");
            break;
        default:
            break;
        }

        if (offset <= lastoffset) break;    /* nothing happened, exit loop */
    }

    return offset;
}

static guint
fAuthenticationPolicy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        /* quit loop if we spot a closing tag */
        if (tag_is_closing(tag_info)) {
            break;
        }

        switch (tag_no) {
        case 0: /* policy */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
                lastoffset = offset;
                fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
                /* quit loop if we spot a closing tag */
                if (tag_is_closing(tag_info)) {
                    offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                    break;
                }

                switch (tag_no) {
                case 0: /* credential-data-input */
                    offset = fDeviceObjectReference(tvb, pinfo, tree, offset);
                    break;
                case 1: /* index */
                    offset = fUnsignedTag(tvb, pinfo, tree, offset, "index: ");
                    break;
                default:
                    break;
                }

                if (offset <= lastoffset) break;    /* nothing happened, exit loop */
            }
            break;
        case 1: /* order-enforced */
            offset = fBooleanTag(tvb, pinfo, tree, offset, "order-enforced: ");
            break;
        case 2: /* timeout */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "timeout: ");
            break;
        default:
            break;
        }

        if (offset <= lastoffset) break;    /* nothing happened, exit loop */
    }

    return offset;
}

static guint
fRequestKeyRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    offset = fObjectIdentifier(tvb, pinfo, tree, offset, "DeviceIdentifier: "); /* Requesting Device Identifier */
    offset = fAddress(tvb, pinfo, tree, offset);
    offset = fObjectIdentifier(tvb, pinfo, tree, offset, "DeviceIdentifier: "); /* Remote Device Identifier */
    return fAddress(tvb, pinfo, tree, offset);
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
fReadPropertyAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       lastoffset = 0, len;
    guint8      tag_no, tag_info;
    guint32     lvt;
    proto_tree *subtree = tree;

    /* set the optional global properties to indicate not-used */
    propertyArrayIndex = -1;
    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            offset += len;
            subtree = tree;
            continue;
        }
        switch (tag_no) {
        case 0: /* objectIdentifier */
            offset = fObjectIdentifier(tvb, pinfo, subtree, offset, "ObjectIdentifier: ");
            break;
        case 1: /* propertyIdentifier */
            offset = fPropertyIdentifier(tvb, pinfo, subtree, offset);
            break;
        case 2: /* propertyArrayIndex */
            offset = fPropertyArrayIndex(tvb, pinfo, subtree, offset);
            break;
        case 3: /* propertyValue */
            offset = fPropertyValue(tvb, pinfo, subtree, offset, tag_info);
            break;
        default:
            break;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fWritePropertyRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       lastoffset = 0;
    guint8      tag_no, tag_info;
    guint32     lvt;
    proto_tree *subtree = tree;

    /* set the optional global properties to indicate not-used */
    propertyArrayIndex = -1;
    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        /* quit loop if we spot a closing tag */
        if (tag_is_closing(tag_info)) {
            break;
        }

        switch (tag_no) {
        case 0: /* objectIdentifier */
            offset = fObjectIdentifier(tvb, pinfo, subtree, offset, "ObjectIdentifier: ");
            break;
        case 1: /* propertyIdentifier */
            offset = fPropertyIdentifier(tvb, pinfo, subtree, offset);
            break;
        case 2: /* propertyArrayIndex */
            offset = fPropertyArrayIndex(tvb, pinfo, subtree, offset);
            break;
        case 3: /* propertyValue */
            offset = fPropertyValue(tvb, pinfo, subtree, offset, tag_info);
            break;
        case 4: /* Priority (only used for write) */
            offset = fUnsignedTag(tvb, pinfo, subtree, offset, "Priority: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fWriteAccessSpecification(tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, guint offset)
{
    guint   lastoffset = 0, len;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        /* maybe a listOfwriteAccessSpecifications if we spot a closing tag */
        if (tag_is_closing(tag_info)) {
            offset += len;
            continue;
        }

        switch (tag_no) {
        case 0: /* objectIdentifier */
            offset = fObjectIdentifier(tvb, pinfo, subtree, offset, "ObjectIdentifier: ");
            break;
        case 1: /* listOfPropertyValues */
            if (tag_is_opening(tag_info)) {
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset  = fBACnetPropertyValue(tvb, pinfo, subtree, offset);
            } else {
                expert_add_info(pinfo, subtree, &ei_bacapp_bad_tag);
            }
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fWritePropertyMultipleRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    if (offset >= tvb_reported_length(tvb))
        return offset;

    col_set_writable(pinfo->cinfo, COL_INFO, FALSE); /* don't set all infos into INFO column */
    return fWriteAccessSpecification(tvb, pinfo, tree, offset);
}

static guint
fPropertyReference(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint8 tagoffset, guint8 list)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    /* set the optional global properties to indicate not-used */
    propertyArrayIndex = -1;
    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) { /* closing Tag, but not for me */
            return offset;
        } else if (tag_is_opening(tag_info)) { /* opening Tag, but not for me */
            return offset;
        }
        switch (tag_no-tagoffset) {
        case 0: /* PropertyIdentifier */
            offset = fPropertyIdentifier(tvb, pinfo, tree, offset);
            break;
        case 1: /* propertyArrayIndex */
            offset = fPropertyArrayIndex(tvb, pinfo, tree, offset);
            if (list != 0)
                break; /* Continue decoding if this may be a list */
            /* FALLTHROUGH */
        default:
            lastoffset = offset; /* Set loop end condition */
            break;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fBACnetPropertyReference(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint8 list)
{
    col_set_writable(pinfo->cinfo, COL_INFO, FALSE); /* don't set all infos into INFO column */
    return fPropertyReference(tvb, pinfo, tree, offset, 0, list);
}

static guint
fBACnetObjectPropertyReference(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;

        switch (fTagNo(tvb, offset)) {
        case 0: /* ObjectIdentifier */
            offset = fObjectIdentifier(tvb, pinfo, tree, offset, "ObjectIdentifier: ");
            break;
        case 1: /* PropertyIdentifier and propertyArrayIndex */
            offset = fPropertyReference(tvb, pinfo, tree, offset, 1, 0);
            col_set_writable(pinfo->cinfo, COL_INFO, FALSE); /* don't set all infos into INFO column */
            /* FALLTHROUGH */
        default:
            lastoffset = offset; /* Set loop end condition */
            break;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

#if 0
static guint
fObjectPropertyValue(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint       lastoffset = 0;
    guint8      tag_no, tag_info;
    guint32     lvt;
    proto_tree* subtree = tree;
    proto_item* tt;

    while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset,
                &tag_no, &tag_info, &lvt);
            continue;
        }
        switch (tag_no) {
        case 0: /* ObjectIdentifier */
            offset = fObjectIdentifier(tvb, pinfo, subtree, offset, "ObjectIdentifier: ");
            break;
        case 1: /* PropertyIdentifier */
            offset = fPropertyIdentifier(tvb, pinfo, subtree, offset);
            break;
        case 2: /* propertyArrayIndex */
            offset = fUnsignedTag(tvb, pinfo, subtree, offset, "property Array Index: ");
            break;
        case 3:  /* Value */
            offset = fPropertyValue(tvb, pinfo, subtree, offset, tag_info);
            break;
        case 4:  /* Priority */
            offset = fUnsignedTag(tvb, pinfo, subtree, offset, "Priority: ");
            break;
        default:
            break;
        }
    }
    return offset;
}
#endif

static guint
fPriorityArray(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    char  i = 1, ar[256];
    guint lastoffset = 0;
    guint8 tag_no;
    guint8 tag_info;
    guint32 lvt;

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
    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        /* exit loop if nothing happens inside */
        lastoffset = offset;
        snprintf(ar, sizeof(ar), "%s[%d]: ",
            val_to_split_str(87 , 512,
                BACnetPropertyIdentifier,
                ASHRAE_Reserved_Fmt,
                Vendor_Proprietary_Fmt),
            i++);
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if ( ! tag_is_context_specific(tag_info)) {
            /* DMR Should be fAbstractNSyntax, but that's where we came from! */
            offset = fApplicationTypes(tvb, pinfo, tree, offset, ar);
        } else {
            if (tag_is_opening(tag_info) && tag_no == 0) {
                offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                offset = fAbstractSyntaxNType(tvb, pinfo, tree, offset);
                offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            } else if (tag_is_opening(tag_info) && tag_no == 1) {
                offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                offset = fDate(tvb, pinfo, tree, offset, "Date: ");
                offset = fTime(tvb, pinfo, tree, offset, "Time: ");
                offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            } else if (tag_is_opening(tag_info) && tag_no == 2) {
                offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
                offset = fXyColor(tvb, pinfo, tree, offset, "xy-color: ");
                offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            } else {
                /* DMR Should be fAbstractNSyntax, but that's where we came from! */
                offset = fApplicationTypes(tvb, pinfo, tree, offset, ar);
            }
        }
        /* there are only 16 priority array elements */
        if (i > 16) {
            break;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }

    return offset;
}

static guint
fDeviceObjectReference(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8 tag_no, tag_info;
    guint32 lvt;
    guint lastoffset = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        /* quit loop if we spot an un-matched closing tag */
        if (tag_is_closing(tag_info)) {
            break;
        }
        switch (tag_no) {
        case 0: /* deviceIdentifier - OPTIONAL */
            offset = fObjectIdentifier(tvb, pinfo, tree, offset, "DeviceIdentifier: ");
            break;
        case 1: /* ObjectIdentifier */
            offset = fObjectIdentifier(tvb, pinfo, tree, offset, "ObjectIdentifier: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fSpecialEvent(tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, guint offset)
{
    guint8 tag_no, tag_info;
    guint32 lvt;
    guint lastoffset = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        /* quit loop if we spot an un-matched closing tag */
        if (tag_is_closing(tag_info)) {
            break;
        }
        switch (tag_no) {
        case 0: /* calendarEntry */
            if (tag_is_opening(tag_info)) {
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset  = fCalendarEntry(tvb, pinfo, subtree, offset);
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            }
            break;
        case 1: /* calendarReference */
            offset = fObjectIdentifier(tvb, pinfo, subtree, offset, "ObjectIdentifier: ");
            break;
        case 2: /* list of BACnetTimeValue */
            if (tag_is_opening(tag_info)) {
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset  = fTimeValue(tvb, pinfo, subtree, offset);
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            } else {
                expert_add_info(pinfo, subtree, &ei_bacapp_bad_tag);
            }
            break;
        case 3: /* eventPriority */
            offset = fUnsignedTag(tvb, pinfo, subtree, offset, "event priority: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fNetworkSecurityPolicy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_bacapp_tag, NULL, "network security policy");

    while (tvb_reported_length_remaining(tvb, offset) > 0 && offset > lastoffset) {
        lastoffset = offset;
        /* check the tag.  A closing tag means we are done */
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            return offset;
        }
        switch (tag_no) {
        case 0: /* port-id */
            offset = fUnsignedTag(tvb, pinfo, subtree, offset, "port-id: ");
            break;
        case 1: /* security-level */
            offset  = fEnumeratedTag(tvb, pinfo, subtree, offset,
                "security-level: ", BACnetSecurityPolicy);
            break;
        default:
            return offset;
        }
    }

    return offset;
}

static guint
fKeyIdentifier(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0 && offset > lastoffset) {
        lastoffset = offset;
        /* check the tag.  A closing tag means we are done */
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            return offset;
        }
        switch (tag_no) {
        case 0: /* algorithm */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "algorithm: ");
            break;
        case 1: /* key-id */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "key-id: ");
            break;
        default:
            return offset;
        }
    }

    return offset;
}

static guint
fSecurityKeySet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_bacapp_tag, NULL, "security keyset");

    while (tvb_reported_length_remaining(tvb, offset) > 0 && offset > lastoffset) {
        lastoffset = offset;
        /* check the tag.  A closing tag means we are done */
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_closing(tag_info)) {
            return offset;
        }
        switch (tag_no) {
        case 0: /* key-revision */
            offset = fUnsignedTag(tvb, pinfo, subtree, offset, "key-revision: ");
            break;
        case 1: /* activation-time */
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            offset = fDateTime(tvb, pinfo, subtree, offset, "activation-time: ");
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 2: /* expiration-time */
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            offset = fDateTime(tvb, pinfo, subtree, offset, "expiration-time: ");
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            break;
        case 3: /* key-ids */
            if (tag_is_opening(tag_info)) {
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset = fKeyIdentifier(tvb, pinfo, subtree, offset);
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            } else {
                expert_add_info(pinfo, subtree, &ei_bacapp_bad_tag);
            }
            break;
        default:
            return offset;
        }
    }

    return offset;
}

static guint
fSelectionCriteria(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        /* quit loop if we spot a closing tag */
        if (tag_is_closing(tag_info)) {
            break;
        }

        switch (fTagNo(tvb, offset)) {
        case 0: /* propertyIdentifier */
            offset  = fPropertyIdentifier(tvb, pinfo, tree, offset);
            break;
        case 1: /* propertyArrayIndex */
            offset  = fPropertyArrayIndex(tvb, pinfo, tree, offset);
            break;
        case 2: /* relationSpecifier */
            offset  = fEnumeratedTag(tvb, pinfo, tree, offset,
                "relation Specifier: ", BACnetRelationSpecifier);
            break;
        case 3: /* comparisonValue */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset  = fAbstractSyntaxNType(tvb, pinfo, tree, offset);
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fObjectSelectionCriteria(tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        /* quit loop if we spot a closing tag */
        if (tag_is_closing(tag_info)) {
            break;
        }

        switch (tag_no) {
        case 0: /* selectionLogic */
            offset = fEnumeratedTag(tvb, pinfo, subtree, offset,
                "selection Logic: ", BACnetSelectionLogic);
            break;
        case 1: /* listOfSelectionCriteria */
            if (tag_is_opening(tag_info)) {
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset  = fSelectionCriteria(tvb, pinfo, subtree, offset);
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            } else {
                expert_add_info(pinfo, subtree, &ei_bacapp_bad_tag);
            }
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}


static guint
fReadPropertyConditionalRequest(tvbuff_t *tvb, packet_info* pinfo, proto_tree *subtree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader (tvb, pinfo, offset, &tag_no, &tag_info, &lvt);

        if (tag_is_opening(tag_info) && tag_no < 2) {
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            switch (tag_no) {
            case 0: /* objectSelectionCriteria */
                offset = fObjectSelectionCriteria(tvb, pinfo, subtree, offset);
                break;
            case 1: /* listOfPropertyReferences */
                offset = fBACnetPropertyReference(tvb, pinfo, subtree, offset, 1);
                break;
            default:
                return offset;
            }
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fReadAccessSpecification(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       lastoffset = 0;
    guint8      tag_no, tag_info;
    guint32     lvt;
    proto_tree *subtree = tree;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        switch (tag_no) {
        case 0: /* objectIdentifier */
            offset = fObjectIdentifier(tvb, pinfo, subtree, offset, "ObjectIdentifier: ");
            break;
        case 1: /* listOfPropertyReferences */
            if (tag_is_opening(tag_info)) {
                subtree = proto_tree_add_subtree(subtree, tvb, offset, 1, ett_bacapp_value, NULL, "listOfPropertyReferences");
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset  = fBACnetPropertyReference(tvb, pinfo, subtree, offset, 1);
            } else if (tag_is_closing(tag_info)) {
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset,
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
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fReadAccessResult(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       lastoffset = 0, len;
    guint8      tag_no;
    guint8      tag_info;
    guint32     lvt;
    proto_tree *subtree = tree;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        /* maybe a listOfReadAccessResults if we spot a closing tag here */
        if (tag_is_closing(tag_info)) {
            offset += len;
            if ((tag_no == 4 || tag_no == 5) && (subtree != tree))
                subtree = subtree->parent; /* Value and error have extra subtree */

        if (tag_no == 1) {
            /* closing list of results for this objectSpecifier */
            fTagHeaderTree(tvb, pinfo, subtree, offset - len, &tag_no, &tag_info, &lvt);
            /* look if another objectSpecifier follows here */
            if (tvb_reported_length_remaining(tvb, offset) <= 0)
                return offset; /* nothing more to decode left */

            fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
            if (tag_no != 0 || tag_info != 12)
                return offset; /* no objectSpecifier */
            }

            continue;
        }

        switch (tag_no) {
        case 0: /* objectSpecifier */
            offset = fObjectIdentifier(tvb, pinfo, tree, offset, "ObjectIdentifier: ");
            break;
        case 1: /* list of Results */
            if (tag_is_opening(tag_info)) {
                subtree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_bacapp_value, NULL, "listOfResults");
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            } else {
                expert_add_info(pinfo, subtree, &ei_bacapp_bad_tag);
            }
            break;
        case 2: /* propertyIdentifier */
            offset = fPropertyIdentifierValue(tvb, pinfo, subtree, offset, 2);
            break;
        case 5: /* propertyAccessError */
            if (tag_is_opening(tag_info)) {
                subtree = proto_tree_add_subtree(subtree, tvb, offset, 1, ett_bacapp_value, NULL, "propertyAccessError");
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                /* Error Code follows */
                offset  = fError(tvb, pinfo, subtree, offset);
                fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            }
            else {
                expert_add_info(pinfo, subtree, &ei_bacapp_bad_tag);
            }
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}


static guint
fReadPropertyConditionalAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    /* listOfReadAccessResults */
    return fReadAccessResult(tvb, pinfo, tree, offset);
}


static guint
fCreateObjectRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);

        if (tag_no < 2) {
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            switch (tag_no) {
            case 0: /* objectSpecifier */
                switch (fTagNo(tvb, offset)) { /* choice of objectType or objectIdentifier */
                case 0: /* objectType */
                    offset = fEnumeratedTagSplit(tvb, pinfo, subtree, offset, "Object Type: ", BACnetObjectType, 128);
                    break;
                case 1: /* objectIdentifier */
                    offset = fObjectIdentifier(tvb, pinfo, subtree, offset, "ObjectIdentifier: ");
                    break;
                default:
                    break;
                }
                break;
            case 1: /* propertyValue */
                if (tag_is_opening(tag_info)) {
                    offset = fBACnetPropertyValue(tvb, pinfo, subtree, offset);
                } else {
                    expert_add_info(pinfo, subtree, &ei_bacapp_bad_tag);
                }
                break;
            default:
                break;
            }
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
        }
        if (offset <= lastoffset) break;    /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fCreateObjectAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    return fObjectIdentifier(tvb, pinfo, tree, offset, "ObjectIdentifier: ");
}

static guint
fReadRangeRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8      tag_no, tag_info;
    guint32     lvt;
    proto_tree *subtree = tree;

    offset = fBACnetObjectPropertyReference(tvb, pinfo, subtree, offset);

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        /* optional range choice */
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        if (tag_is_opening(tag_info)) {
            subtree = proto_tree_add_subtree(subtree, tvb, offset, 1, ett_bacapp_value, NULL,
                val_to_str_const(tag_no, BACnetReadRangeOptions, "unknown range option"));
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            switch (tag_no) {
            case 3: /* range byPosition */
            case 6: /* range bySequenceNumber, 2004 spec */
                offset = fApplicationTypes(tvb, pinfo, subtree, offset, "reference Index: ");
                offset = fApplicationTypes(tvb, pinfo, subtree, offset, "reference Count: ");
                break;
            case 4: /* range byTime - deprecated in 2004 */
            case 7: /* 2004 spec */
                offset = fDateTime(tvb, pinfo, subtree, offset, "reference Date/Time: ");
                offset = fApplicationTypes(tvb, pinfo, subtree, offset, "reference Count: ");
                break;
            case 5: /* range timeRange - deprecated in 2004 */
                offset = fDateTime(tvb, pinfo, subtree, offset, "beginning Time: ");
                offset = fDateTime(tvb, pinfo, subtree, offset, "ending Time: ");
                break;
            default:
                break;
            }
            offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
        }
    }
    return offset;
}

static guint
fReadRangeAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8      tag_no, tag_info;
    guint32     lvt;
    proto_tree *subtree = tree;

    /* set the optional global properties to indicate not-used */
    propertyArrayIndex = -1;
    /* objectIdentifier, propertyIdentifier, and
       OPTIONAL propertyArrayIndex */
    offset = fBACnetObjectPropertyReference(tvb, pinfo, subtree, offset);
    /* resultFlags => BACnetResultFlags ::= BIT STRING */
    offset = fBitStringTagVS(tvb, pinfo, tree, offset,
        "resultFlags: ",
        BACnetResultFlags);
    /* itemCount */
    offset = fUnsignedTag(tvb, pinfo, subtree, offset, "item Count: ");
    /* itemData */
    fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    if (tag_is_opening(tag_info)) {
        col_set_writable(pinfo->cinfo, COL_INFO, FALSE); /* don't set all infos into INFO column */
        subtree = proto_tree_add_subtree(subtree, tvb, offset, 1, ett_bacapp_value, NULL, "itemData");
        offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
        offset  = fAbstractSyntaxNType(tvb, pinfo, subtree, offset);
        offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
    }
    /* firstSequenceNumber - OPTIONAL */
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        offset  = fUnsignedTag(tvb, pinfo, subtree, offset, "first Sequence Number: ");
    }

    return offset;
}

static guint
fAccessMethod(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       lastoffset = 0;
    guint32     lvt;
    guint8      tag_no, tag_info;
    proto_tree* subtree = NULL;

    fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);

    if (tag_is_opening(tag_info)) {
        subtree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_bacapp_value, NULL,
            val_to_str_const(tag_no, BACnetFileAccessOption, "invalid access method"));
        offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
        offset  = fApplicationTypes(tvb, pinfo, subtree, offset, val_to_str_const(tag_no, BACnetFileStartOption, "invalid option"));
        offset  = fApplicationTypes(tvb, pinfo, subtree, offset, val_to_str_const(tag_no, BACnetFileWriteInfo, "unknown option"));

        if (tag_no == 1) {
            while ((tvb_reported_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {
                /* exit loop if nothing happens inside */
                lastoffset = offset;
                offset = fApplicationTypes(tvb, pinfo, subtree, offset, "Record Data: ");
            }
        }

        if ((bacapp_flags & BACAPP_MORE_SEGMENTS) == 0) {
            /* More Flag is not set, so we can look for closing tag in this segment */
            fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
            if (tag_is_closing(tag_info)) {
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
            }
        }
    }
    return offset;
}

static guint
fAccessRule(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        /* quit loop if we spot a closing tag */
        if (tag_is_closing(tag_info)) {
            break;
        }

        switch (tag_no) {
        case 0: /* time-range-specifier */
            offset = fEnumeratedTag(tvb, pinfo, tree, offset, "time-range-specifier: ", NULL);
            break;
        case 1: /* time-range */
            offset = fDeviceObjectPropertyReference(tvb, pinfo, tree, offset);
            break;
        case 2: /* location-specifier */
            offset = fEnumeratedTag(tvb, pinfo, tree, offset, "location-specifier: ", NULL);
            break;
        case 3: /* location */
            offset = fDeviceObjectReference(tvb, pinfo, tree, offset);
            break;
        case 4: /* enable */
            offset = fBooleanTag(tvb, pinfo, tree, offset, "enable: ");
            break;
        default:
            break;
        }

        if (offset <= lastoffset) break;    /* nothing happened, exit loop */
    }

    return offset;
}

static guint
fAtomicReadFileRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8      tag_no, tag_info;
    guint32     lvt;
    proto_tree *subtree = tree;

    offset = fObjectIdentifier(tvb, pinfo, tree, offset, "ObjectIdentifier: ");

    fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);

    if (tag_is_opening(tag_info)) {
        subtree = proto_tree_add_subtree(subtree, tvb, offset, 1, ett_bacapp_value, NULL,
                        val_to_str_const(tag_no, BACnetFileAccessOption, "unknown access method"));
        offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
        offset  = fSignedTag(tvb, pinfo, subtree, offset, val_to_str_const(tag_no, BACnetFileStartOption, "unknown option"));
        offset  = fUnsignedTag(tvb, pinfo, subtree, offset, val_to_str_const(tag_no, BACnetFileRequestCount, "unknown option"));
        offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
    }
    return offset;
}

static guint
fAtomicWriteFileRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{

    offset = fObjectIdentifier(tvb, pinfo, tree, offset, "ObjectIdentifier: "); /* file Identifier */
    offset = fAccessMethod(tvb, pinfo, tree, offset);

    return offset;
}

static guint
fAtomicWriteFileAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint tag_no = fTagNo(tvb, offset);
    return fSignedTag(tvb, pinfo, tree, offset, val_to_str_const(tag_no, BACnetFileStartOption, "unknown option"));
}

static guint
fAtomicReadFileAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    offset = fApplicationTypes(tvb, pinfo, tree, offset, "End Of File: ");
    offset = fAccessMethod(tvb, pinfo, tree, offset);

    return offset;
}

static guint
fReadPropertyMultipleRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, guint offset)
{
    col_set_writable(pinfo->cinfo, COL_INFO, FALSE); /* don't set all infos into INFO column */
    return fReadAccessSpecification(tvb, pinfo, subtree, offset);
}

static guint
fReadPropertyMultipleAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    col_set_writable(pinfo->cinfo, COL_INFO, FALSE); /* don't set all infos into INFO column */
    return fReadAccessResult(tvb, pinfo, tree, offset);
}

static guint
fConfirmedServiceRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, gint service_choice)
{
    if (tvb_reported_length_remaining(tvb, offset) <= 0)
        return offset;

    switch (service_choice) {
    case 0: /* acknowledgeAlarm */
        offset = fAcknowledgeAlarmRequest(tvb, pinfo, tree, offset);
        break;
    case 1: /* confirmedCOVNotification */
        offset = fConfirmedCOVNotificationRequest(tvb, pinfo, tree, offset);
        break;
    case 2: /* confirmedEventNotification */
        offset = fConfirmedEventNotificationRequest(tvb, pinfo, tree, offset);
        break;
    case 3: /* confirmedGetAlarmSummary conveys no parameters */
        break;
    case 4: /* getEnrollmentSummaryRequest */
        offset = fGetEnrollmentSummaryRequest(tvb, pinfo, tree, offset);
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
        offset = fDeviceCommunicationControlRequest(tvb, pinfo, tree, offset);
        break;
    case 18:
        offset = fConfirmedPrivateTransferRequest(tvb, pinfo, tree, offset);
        break;
    case 19:
        offset = fConfirmedTextMessageRequest(tvb, pinfo, tree, offset);
        break;
    case 20:
        offset = fReinitializeDeviceRequest(tvb, pinfo, tree, offset);
        break;
    case 21:
        offset = fVtOpenRequest(tvb, pinfo, tree, offset);
        break;
    case 22:
        offset = fVtCloseRequest(tvb, pinfo, tree, offset);
        break;
    case 23:
        offset = fVtDataRequest(tvb, pinfo, tree, offset);
        break;
    case 24:
        offset = fAuthenticateRequest(tvb, pinfo, tree, offset);
        break;
    case 25:
        offset = fRequestKeyRequest(tvb, pinfo, tree, offset);
        break;
    case 26:
        offset = fReadRangeRequest(tvb, pinfo, tree, offset);
        break;
    case 27:
        offset = fLifeSafetyOperationRequest(tvb, pinfo, tree, offset, NULL);
        break;
    case 28:
        offset = fSubscribeCOVPropertyRequest(tvb, pinfo, tree, offset);
        break;
    case 29:
        offset = fGetEventInformationRequest(tvb, pinfo, tree, offset);
        break;
    case 30:
        offset = fSubscribeCOVPropertyMultipleRequest(tvb, pinfo, tree, offset);
        break;
    case 31:
        offset = fConfirmedCOVNotificationMultipleRequest(tvb, pinfo, tree, offset);
        break;
    case 32:
        offset = fConfirmedAuditNotificationRequest(tvb, pinfo, tree, offset);
        break;
    case 33:
        offset = fAuditLogQueryRequest(tvb, pinfo, tree, offset);
        break;
    default:
        return offset;
    }
    return offset;
}

static guint
fConfirmedServiceAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, gint service_choice)
{
    if (tvb_reported_length_remaining(tvb, offset) <= 0)
        return offset;

    switch (service_choice) {
    case 3: /* confirmedEventNotificationAck */
        offset = fGetAlarmSummaryAck(tvb, pinfo, tree, offset);
        break;
    case 4: /* getEnrollmentSummaryAck */
        offset = fGetEnrollmentSummaryAck(tvb, pinfo, tree, offset);
        break;
    case 6: /* atomicReadFile */
        offset = fAtomicReadFileAck(tvb, pinfo, tree, offset);
        break;
    case 7: /* atomicReadFileAck */
        offset = fAtomicWriteFileAck(tvb, pinfo, tree, offset);
        break;
    case 10: /* createObject */
        offset = fCreateObjectAck(tvb, pinfo, tree, offset);
        break;
    case 12:
        offset = fReadPropertyAck(tvb, pinfo, tree, offset);
        break;
    case 13:
        offset = fReadPropertyConditionalAck(tvb, pinfo, tree, offset);
        break;
    case 14:
        offset = fReadPropertyMultipleAck(tvb, pinfo, tree, offset);
        break;
    case 18:
        offset = fConfirmedPrivateTransferAck(tvb, pinfo, tree, offset);
        break;
    case 21:
        offset = fVtOpenAck(tvb, pinfo, tree, offset);
        break;
    case 23:
        offset = fVtDataAck(tvb, pinfo, tree, offset);
        break;
    case 24:
        offset = fAuthenticateAck(tvb, pinfo, tree, offset);
        break;
    case 26:
        offset = fReadRangeAck(tvb, pinfo, tree, offset);
        break;
    case 29:
        offset = fGetEventInformationACK(tvb, pinfo, tree, offset);
        break;
    case 33:
        offset = fAuditLogQueryAck(tvb, pinfo, tree, offset);
        break;
    default:
        return offset;
    }
    return offset;
}

static guint
fIAmRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    /* BACnetObjectIdentifier */
    offset = fApplicationTypes(tvb, pinfo, tree, offset, "BACnet Object Identifier: ");

    /* MaxAPDULengthAccepted */
    offset = fApplicationTypes(tvb, pinfo, tree, offset, "Maximum ADPU Length Accepted: ");

    /* segmentationSupported */
    offset = fApplicationTypesEnumerated(tvb, pinfo, tree, offset,
        "Segmentation Supported: ", BACnetSegmentation);

    /* vendor ID */
    return fVendorIdentifier(tvb, pinfo, tree, offset);
}

static guint
fIHaveRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    /* BACnetDeviceIdentifier */
    offset = fApplicationTypes(tvb, pinfo, tree, offset, "Device Identifier: ");

    /* BACnetObjectIdentifier */
    offset = fApplicationTypes(tvb, pinfo, tree, offset, "Object Identifier: ");

    /* ObjectName */
    return fObjectName(tvb, pinfo, tree, offset);
}

static guint
fWhoIsRequest(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint   val;
    guint8  tag_len;

    guint8  tag_no, tag_info;
    guint32 lvt;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;

        tag_len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);

        switch (tag_no) {
        case 0:
            /* DeviceInstanceRangeLowLimit Optional */
            if (fUnsigned32(tvb, offset+tag_len, lvt, &val))
                col_append_fstr(pinfo->cinfo, COL_INFO, "%d ", val);
            offset = fDevice_Instance(tvb, pinfo, tree, offset,
                hf_Device_Instance_Range_Low_Limit);
            break;
        case 1:
            /* DeviceInstanceRangeHighLimit Optional but
                required if DeviceInstanceRangeLowLimit is there */
            if (fUnsigned32(tvb, offset+tag_len, lvt, &val))
                col_append_fstr(pinfo->cinfo, COL_INFO, "%d ", val);
            offset = fDevice_Instance(tvb, pinfo, tree, offset,
                hf_Device_Instance_Range_High_Limit);
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fUnconfirmedServiceRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, gint service_choice)
{
    if (tvb_reported_length_remaining(tvb, offset) <= 0)
        return offset;

    switch (service_choice) {
    case 0: /* I-Am-Request */
        offset = fIAmRequest(tvb, pinfo, tree, offset);
        break;
    case 1: /* i-Have Request */
        offset = fIHaveRequest(tvb, pinfo, tree, offset);
    break;
    case 2: /* unconfirmedCOVNotification */
        offset = fUnconfirmedCOVNotificationRequest(tvb, pinfo, tree, offset);
        break;
    case 3: /* unconfirmedEventNotification */
        offset = fUnconfirmedEventNotificationRequest(tvb, pinfo, tree, offset);
        break;
    case 4: /* unconfirmedPrivateTransfer */
        offset = fUnconfirmedPrivateTransferRequest(tvb, pinfo, tree, offset);
        break;
    case 5: /* unconfirmedTextMessage */
        offset = fUnconfirmedTextMessageRequest(tvb, pinfo, tree, offset);
        break;
    case 6: /* timeSynchronization */
        offset = fTimeSynchronizationRequest(tvb, pinfo, tree, offset);
        break;
    case 7: /* who-Has */
        offset = fWhoHas(tvb, pinfo, tree, offset);
        break;
    case 8: /* who-Is */
        offset = fWhoIsRequest(tvb, pinfo, tree, offset);
        break;
    case 9: /* utcTimeSynchronization */
        offset = fUTCTimeSynchronizationRequest(tvb, pinfo, tree, offset);
        break;
    case 10:
        offset = fWriteGroupRequest(tvb, pinfo, tree, offset);
        break;
    case 11:
        offset = fUnconfirmedCOVNotificationMultipleRequest(tvb, pinfo, tree, offset);
        break;
    case 12:
        offset = fUnconfirmedAuditNotificationRequest(tvb, pinfo, tree, offset);
        break;
    case 13:
        offset = fWhoAmIRequest(tvb, pinfo, tree, offset);
        break;
    case 14:
        offset = fYouAreRequest(tvb, pinfo, tree, offset);
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
    gint        tmp;
    guint       extra = 2;

    bacapp_seq = 0;
    tmp = tvb_get_gint8(tvb, offset);
    bacapp_flags = tmp & 0x0f;

    if (ack == 0) {
        extra = 3;
    }
    *svc = tvb_get_gint8(tvb, offset+extra);
    if (bacapp_flags & 0x08)
        *svc = tvb_get_gint8(tvb, offset+extra+2);

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
{   /* BACnet-Confirmed-Request */
    /* ASHRAE 135-2001 20.1.2 */

    return fConfirmedServiceRequest(tvb, pinfo, bacapp_tree, offset, svc);
}

static guint
fConfirmedRequestPDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *bacapp_tree, guint offset)
{   /* BACnet-Confirmed-Request */
    /* ASHRAE 135-2001 20.1.2 */
    gint        svc;
    proto_item *tt = 0;

    offset = fStartConfirmed(tvb, pinfo, bacapp_tree, offset, 0, &svc, &tt);
    return fContinueConfirmedRequestPDU(tvb, pinfo, bacapp_tree, offset, svc);
}

static guint
fUnconfirmedRequestPDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *bacapp_tree, guint offset)
{   /* BACnet-Unconfirmed-Request-PDU */
    /* ASHRAE 135-2001 20.1.3 */

    gint tmp;

    proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, offset++, 1, ENC_BIG_ENDIAN);

    tmp = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(bacapp_tree, hf_bacapp_uservice, tvb,
        offset++, 1, ENC_BIG_ENDIAN);
    /* Service Request follows... Variable Encoding 20.2ff */
    return fUnconfirmedServiceRequest(tvb, pinfo, bacapp_tree, offset, tmp);
}

static guint
fSimpleAckPDU(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *bacapp_tree, guint offset)
{   /* BACnet-Simple-Ack-PDU */
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
{   /* BACnet-Complex-Ack-PDU */
    /* ASHRAE 135-2001 20.1.5 */

    /* Service ACK follows... */
    return fConfirmedServiceAck(tvb, pinfo, bacapp_tree, offset, svc);
}

static guint
fComplexAckPDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *bacapp_tree, guint offset)
{   /* BACnet-Complex-Ack-PDU */
    /* ASHRAE 135-2001 20.1.5 */
    gint        svc;
    proto_item *tt = 0;

    offset = fStartConfirmed(tvb, pinfo, bacapp_tree, offset, 1, &svc, &tt);
    return fContinueComplexAckPDU(tvb, pinfo, bacapp_tree, offset, svc);
}

static guint
fSegmentAckPDU(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *bacapp_tree, guint offset)
{   /* BACnet-SegmentAck-PDU */
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
    guint8  tag_info   = 0;
    guint8  parsed_tag = 0;
    guint32 lvt        = 0;

    offset += fTagHeaderTree(tvb, pinfo, tree, offset, &parsed_tag, &tag_info, &lvt);
    offset  = fError(tvb, pinfo, tree, offset);
    return offset + fTagHeaderTree(tvb, pinfo, tree, offset, &parsed_tag, &tag_info, &lvt);
}

static guint
fConfirmedPrivateTransferError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint       lastoffset        = 0;
    guint8      tag_no            = 0, tag_info = 0;
    guint32     lvt               = 0;
    proto_tree *subtree           = tree;

    guint       vendor_identifier = 0;
    guint       service_number    = 0;
    guint8      tag_len           = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        /* exit loop if nothing happens inside */
        lastoffset = offset;
        tag_len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
        switch (tag_no) {
        case 0: /* errorType */
            offset = fContextTaggedError(tvb, pinfo, subtree, offset);
            break;
        case 1: /* vendorID */
            fUnsigned32(tvb, offset+tag_len, lvt, &vendor_identifier);
            col_append_fstr(pinfo->cinfo, COL_INFO, "V=%u ",    vendor_identifier);
            offset = fVendorIdentifier(tvb, pinfo, subtree, offset);
            break;
        case 2: /* serviceNumber */
            fUnsigned32(tvb, offset+tag_len, lvt, &service_number);
            col_append_fstr(pinfo->cinfo, COL_INFO, "SN=%u ",   service_number);
            offset = fUnsignedTag(tvb, pinfo, subtree, offset, "service Number: ");
            break;
        case 3: /* errorParameters */
            if (tag_is_opening(tag_info)) {
                subtree = proto_tree_add_subtree(subtree, tvb, offset, 1,
                    ett_bacapp_value, NULL, "error Parameters");
                propertyIdentifier = -1;
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
                offset  = fAbstractSyntaxNType(tvb, pinfo, subtree, offset);
            } else if (tag_is_closing(tag_info)) {
                offset += fTagHeaderTree(tvb, pinfo, subtree, offset,
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
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fCreateObjectError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        switch (fTagNo(tvb, offset)) {
        case 0: /* errorType */
            offset = fContextTaggedError(tvb, pinfo, tree, offset);
            break;
        case 1: /* firstFailedElementNumber */
            offset = fUnsignedTag(tvb, pinfo, tree, offset, "first failed element number: ");
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
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
    guint8  tag_no = 0, tag_info = 0;
    guint32 lvt = 0;

    if (fTagNo(tvb, offset) == 0) {
        /* errorType */
        offset = fContextTaggedError(tvb, pinfo, tree, offset);
        if (fTagNo(tvb, offset) == 1) {
            /* listOfVTSessionIdentifiers [OPTIONAL] */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset  = fVtCloseRequest(tvb, pinfo, tree, offset);
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
        }
    }
    /* should report bad packet if initial tag wasn't 0 */
    return offset;
}

static guint
fWritePropertyMultipleError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint   lastoffset = 0;
    guint8  tag_no     = 0, tag_info = 0;
    guint32 lvt        = 0;

    col_set_writable(pinfo->cinfo, COL_INFO, FALSE); /* don't set all infos into INFO column */
    while (tvb_reported_length_remaining(tvb, offset) > 0) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
        switch (fTagNo(tvb, offset)) {
        case 0: /* errorType */
            offset = fContextTaggedError(tvb, pinfo, tree, offset);
            break;
        case 1: /* firstFailedWriteAttempt */
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            offset  = fBACnetObjectPropertyReference(tvb, pinfo, tree, offset);
            offset += fTagHeaderTree(tvb, pinfo, tree, offset, &tag_no, &tag_info, &lvt);
            break;
        default:
            return offset;
        }
        if (offset <= lastoffset) break;     /* nothing happened, exit loop */
    }
    return offset;
}

static guint
fErrorClass(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint32     val = 0, lvt;
    guint8      tag_no, tag_info;
    proto_item *ti;
    proto_tree *subtree;
    guint       tag_len;

    tag_len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    if (fUnsigned32(tvb, offset+tag_len, lvt, &val))
    {
        ti = proto_tree_add_uint(tree, hf_bacapp_error_class,
            tvb, offset, lvt+tag_len, val);
        subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
    }
    else
    {
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
            ett_bacapp_tag, NULL, "Error Class - %u octets (Signed)", lvt);
    }
    fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
    offset += tag_len + lvt;

    return offset;
}

static guint
fErrorCode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint32     val = 0, lvt;
    guint8      tag_no, tag_info;
    proto_item *ti;
    proto_tree *subtree;
    guint       tag_len;

    tag_len = fTagHeader(tvb, pinfo, offset, &tag_no, &tag_info, &lvt);
    if (fUnsigned32(tvb, offset+tag_len, lvt, &val))
    {
        ti = proto_tree_add_uint(tree, hf_bacapp_error_code,
            tvb, offset, lvt+tag_len, val);
        subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
    }
    else
    {
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lvt+tag_len,
            ett_bacapp_tag, NULL, "Error Code - %u octets (Signed)", lvt);
    }
    fTagHeaderTree(tvb, pinfo, subtree, offset, &tag_no, &tag_info, &lvt);
    offset += tag_len + lvt;

    return offset;
}

static guint
fError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    offset = fErrorClass(tvb, pinfo, tree, offset);

    return fErrorCode(tvb, pinfo, tree, offset);
}

static guint
fBACnetError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint service)
{
    switch (service) {
    case 8:
        offset = fChangeListError(tvb, pinfo, tree, offset);
        break;
    case 9:
        offset = fChangeListError(tvb, pinfo, tree, offset);
        break;
    case 10:
        offset = fCreateObjectError(tvb, pinfo, tree, offset);
        break;
    case 16:
        offset = fWritePropertyMultipleError(tvb, pinfo, tree, offset);
        break;
    case 18:
        offset = fConfirmedPrivateTransferError(tvb, pinfo, tree, offset);
        break;
    case 22:
        offset = fVTCloseError(tvb, pinfo, tree, offset);
        break;
    case 30:
        offset = fSubscribeCOVPropertyMultipleError(tvb, pinfo, tree, offset);
        break;
    default:
        offset = fError(tvb, pinfo, tree, offset);
        break;
  }
    return offset;
}

static guint
fErrorPDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *bacapp_tree, guint offset)
{   /* BACnet-Error-PDU */
    /* ASHRAE 135-2001 20.1.7 */

    proto_item *tc;
    proto_tree *bacapp_tree_control;
    guint8      tmp;

    tc = proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, offset++, 1, ENC_BIG_ENDIAN);
    bacapp_tree_control = proto_item_add_subtree(tc, ett_bacapp);

    proto_tree_add_item(bacapp_tree_control, hf_bacapp_invoke_id, tvb,
                offset++, 1, ENC_BIG_ENDIAN);
    tmp = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(bacapp_tree_control, hf_bacapp_service, tvb,
                 offset++, 1, ENC_BIG_ENDIAN);
    /* Error Handling follows... */
    return fBACnetError(tvb, pinfo, bacapp_tree, offset, tmp);
}

static guint
fRejectPDU(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *bacapp_tree, guint offset)
{   /* BACnet-Reject-PDU */
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
{   /* BACnet-Abort-PDU */
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
    guint  offset = 0;

    flag = tvb_get_gint8(tvb, 0);
    bacapp_type = (flag >> 4) & 0x0f;

    if (tvb == NULL) {
        return 0;
    }

    /* ASHRAE 135-2001 20.1.1 */
    switch (bacapp_type) {
    case BACAPP_TYPE_CONFIRMED_SERVICE_REQUEST: /* BACnet-Confirmed-Service-Request */
        offset = fConfirmedRequestPDU(tvb, pinfo, tree, offset);
        break;
    case BACAPP_TYPE_UNCONFIRMED_SERVICE_REQUEST:   /* BACnet-Unconfirmed-Request-PDU */
        offset = fUnconfirmedRequestPDU(tvb, pinfo, tree, offset);
        break;
    case BACAPP_TYPE_SIMPLE_ACK:    /* BACnet-Simple-Ack-PDU */
        offset = fSimpleAckPDU(tvb, pinfo, tree, offset);
        break;
    case BACAPP_TYPE_COMPLEX_ACK:   /* BACnet-Complex-Ack-PDU */
        offset = fComplexAckPDU(tvb, pinfo, tree, offset);
        break;
    case BACAPP_TYPE_SEGMENT_ACK:   /* BACnet-SegmentAck-PDU */
        offset = fSegmentAckPDU(tvb, pinfo, tree, offset);
        break;
    case BACAPP_TYPE_ERROR: /* BACnet-Error-PDU */
        offset = fErrorPDU(tvb, pinfo, tree, offset);
        break;
    case BACAPP_TYPE_REJECT:    /* BACnet-Reject-PDU */
        offset = fRejectPDU(tvb, pinfo, tree, offset);
        break;
    case BACAPP_TYPE_ABORT: /* BACnet-Abort-PDU */
        offset = fAbortPDU(tvb, pinfo, tree, offset);
        break;
    }
    return offset;
}

static int
dissect_bacapp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    guint8      flag, bacapp_type;
    guint       save_fragmented  = FALSE, data_offset = 0, /*bacapp_apdu_size,*/ fragment = FALSE;
    tvbuff_t   *new_tvb          = NULL;
    guint       offset           = 0;
    guint8      bacapp_seqno     = 0;
    guint8      bacapp_service, bacapp_reason/*, bacapp_prop_win_size*/;
    guint8      bacapp_invoke_id = 0;
    proto_item *ti;
    proto_tree *bacapp_tree      = NULL;

    gint        svc = 0;
    proto_item *tt  = 0;
    gint8       ack = 0;

    /* Strings for BACnet Statistics */
    const gchar errstr[]       = "ERROR: ";
    const gchar rejstr[]       = "REJECTED: ";
    const gchar abortstr[]     = "ABORTED: ";
    const gchar sackstr[]      = " (SimpleAck)";
    const gchar cackstr[]      = " (ComplexAck)";
    const gchar uconfsreqstr[] = " (Unconfirmed Service Request)";
    const gchar confsreqstr[]  = " (Confirmed Service Request)";

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BACnet-APDU");
    col_clear(pinfo->cinfo, COL_INFO);

    flag = tvb_get_guint8(tvb, 0);
    bacapp_type = (flag >> 4) & 0x0f;

    /* show some descriptive text in the INFO column */
    col_add_fstr(pinfo->cinfo, COL_INFO, "%-16s",
        val_to_str_const(bacapp_type, BACnetTypeName, "# unknown APDU #"));

    bacinfo.service_type = NULL;
    bacinfo.invoke_id = NULL;
    bacinfo.instance_ident = NULL;
    bacinfo.object_ident = NULL;

    switch (bacapp_type) {
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
                        val_to_str_const(bacapp_service,
                                         BACnetConfirmedServiceChoice,
                                         bacapp_unknown_service_str),
                        bacapp_invoke_id);

        updateBacnetInfoValue(BACINFO_INVOKEID,
                              wmem_strdup_printf(pinfo->pool, "Invoke ID: %d", bacapp_invoke_id));

        updateBacnetInfoValue(BACINFO_SERVICE,
                              wmem_strconcat(pinfo->pool,
                                             val_to_str_const(bacapp_service,
                                                              BACnetConfirmedServiceChoice,
                                                              bacapp_unknown_service_str),
                                             confsreqstr, NULL));
        break;
    case BACAPP_TYPE_UNCONFIRMED_SERVICE_REQUEST:
        bacapp_service = tvb_get_guint8(tvb, offset + 1);
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
                        val_to_str_const(bacapp_service,
                                         BACnetUnconfirmedServiceChoice,
                                         bacapp_unknown_service_str));

        updateBacnetInfoValue(BACINFO_SERVICE,
                              wmem_strconcat(pinfo->pool,
                                             val_to_str_const(bacapp_service,
                                                              BACnetUnconfirmedServiceChoice,
                                                              bacapp_unknown_service_str),
                                             uconfsreqstr, NULL));
        break;
    case BACAPP_TYPE_SIMPLE_ACK:
        bacapp_invoke_id = tvb_get_guint8(tvb, offset + 1);
        bacapp_service = tvb_get_guint8(tvb, offset + 2);
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s[%3u] ", /* "original-invokeID" replaced */
                        val_to_str_const(bacapp_service,
                                         BACnetConfirmedServiceChoice,
                                         bacapp_unknown_service_str),
                        bacapp_invoke_id);

        updateBacnetInfoValue(BACINFO_INVOKEID,
                              wmem_strdup_printf(pinfo->pool,
                                                 "Invoke ID: %d", bacapp_invoke_id));

        updateBacnetInfoValue(BACINFO_SERVICE,
                              wmem_strconcat(pinfo->pool,
                                             val_to_str_const(bacapp_service,
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
                        val_to_str_const(bacapp_service,
                                         BACnetConfirmedServiceChoice,
                                         bacapp_unknown_service_str),
                        bacapp_invoke_id);

        updateBacnetInfoValue(BACINFO_INVOKEID,
                              wmem_strdup_printf(pinfo->pool, "Invoke ID: %d", bacapp_invoke_id));

        updateBacnetInfoValue(BACINFO_SERVICE,
                              wmem_strconcat(pinfo->pool,
                                             val_to_str_const(bacapp_service,
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
                        val_to_str_const(bacapp_service,
                                         BACnetConfirmedServiceChoice,
                                         bacapp_unknown_service_str),
                        bacapp_invoke_id);

        updateBacnetInfoValue(BACINFO_INVOKEID,
                              wmem_strdup_printf(pinfo->pool, "Invoke ID: %d", bacapp_invoke_id));

        updateBacnetInfoValue(BACINFO_SERVICE,
                              wmem_strconcat(pinfo->pool,
                                             errstr,
                                             val_to_str_const(bacapp_service,
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
                              wmem_strdup_printf(pinfo->pool, "Invoke ID: %d", bacapp_invoke_id));

        updateBacnetInfoValue(BACINFO_SERVICE,
                              wmem_strconcat(pinfo->pool, rejstr,
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
                              wmem_strdup_printf(pinfo->pool, "Invoke ID: %d", bacapp_invoke_id));

        updateBacnetInfoValue(BACINFO_SERVICE,
                              wmem_strconcat(pinfo->pool, abortstr,
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

    ti = proto_tree_add_item(tree, proto_bacapp, tvb, offset, -1, ENC_NA);
    bacapp_tree = proto_item_add_subtree(ti, ett_bacapp);

    if (!fragment)
        do_the_dissection(tvb, pinfo, bacapp_tree);
    else
        fStartConfirmed(tvb, pinfo, bacapp_tree, offset, ack, &svc, &tt);
            /* not resetting the offset so the remaining can be done */

    if (fragment) { /* fragmented */
        fragment_head *frag_msg;

        pinfo->fragmented = TRUE;

        frag_msg = fragment_add_seq_check(&msg_reassembly_table,
            tvb, data_offset,
            pinfo,
            bacapp_invoke_id,      /* ID for fragments belonging together */
            NULL,
            bacapp_seqno,          /* fragment sequence number */
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
            switch (bacapp_type) {
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
        }
    }

    pinfo->fragmented = save_fragmented;

    /* tapping */
    tap_queue_packet(bacapp_tap, pinfo, &bacinfo);
    return tvb_captured_length(tvb);
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
          { "PDU Flags",          "bacapp.pduflags",
            FT_UINT8, BASE_HEX, NULL, 0x0f, NULL, HFILL }
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
        { &hf_bacapp_object_name,
          { "Object Name",           "bacapp.object_name",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
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
            FT_UINT16, BASE_DEC|BASE_EXT_STRING, &BACnetVendorIdentifiers_ext, 0, NULL, HFILL }
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
        { &hf_bacapp_event_type,
          { "Event Type", "bacapp.event_type",
            FT_UINT32, BASE_DEC, VALS(BACnetEventType), 0, NULL, HFILL }
        },
        { &hf_bacapp_notify_type,
          { "Notify Type", "bacapp.notify_type",
            FT_UINT8, BASE_DEC, VALS(BACnetNotifyType), 0, NULL, HFILL }
        },
        { &hf_bacapp_error_class,
          { "Error Class", "bacapp.error_class",
            FT_UINT32, BASE_DEC, VALS(BACnetErrorClass), 0, NULL, HFILL }
        },
        { &hf_bacapp_error_code,
          { "Error Code", "bacapp.error_code",
            FT_UINT32, BASE_DEC, VALS(BACnetErrorCode), 0, NULL, HFILL }
        },
        { &hf_bacapp_present_value_null,
          { "Present Value (null)", "bacapp.present_value.null",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_bacapp_present_value_bool,
          { "Present Value (bool)", "bacapp.present_value.boolean",
            FT_BOOLEAN, 8, NULL, 0, NULL, HFILL }
        },
        { &hf_bacapp_present_value_unsigned,
          { "Present Value (uint)", "bacapp.present_value.uint",
            FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_bacapp_present_value_signed,
          { "Present Value (int)", "bacapp.present_value.int",
            FT_INT64, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_bacapp_present_value_real,
          { "Present Value (real)", "bacapp.present_value.real",
            FT_DOUBLE, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_bacapp_present_value_double,
          { "Present Value (double)", "bacapp.present_value.double",
            FT_DOUBLE, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_bacapp_present_value_octet_string,
          { "Present Value (octet string)", "bacapp.present_value.octet_string",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_bacapp_present_value_char_string,
          { "Present Value (char string)", "bacapp.present_value.char_string",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_bacapp_present_value_bit_string,
          { "Present Value (bit string)", "bacapp.present_value.bit_string",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_bacapp_present_value_enum_index,
          { "Present Value (enum index)", "bacapp.present_value.enum_index",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
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
            FT_UINT8, BASE_DEC, VALS(BACnetCharacterSet), 0,
            NULL, HFILL }
        },
        { &hf_BACnetCodePage,
          { "Code Page",
            "bacapp.code_page",
            FT_UINT16, BASE_DEC, NULL, 0,
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
        { &hf_bacapp_tag_to_state,
          { "To State", "bacapp.to_state",
            FT_UINT32, BASE_DEC, VALS(BACnetEventState), 0, NULL, HFILL }
        },
        { &hf_bacapp_tag_from_state,
          { "From State", "bacapp.from_state",
            FT_UINT32, BASE_DEC, VALS(BACnetEventState), 0, NULL, HFILL }
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
        { &hf_bacapp_tag_mac_address_broadcast,
          { "MAC-address: broadcast",           "bacapp.mac_address_broadcast",
            FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_bacapp_reserved_ashrea,
          { "reserved for ASHRAE",           "bacapp.reserved_ashrea",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_bacapp_unused_bits,
          { "Unused bits",           "bacapp.unused_bits",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_bacapp_bit,
          { "bit",           "bacapp.bit",
            FT_BOOLEAN, 8, NULL, 0, NULL, HFILL }
        },
        { &hf_bacapp_complete_bitstring,
          { "Complete bitstring",           "bacapp.complete_bitstring",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        {&hf_msg_fragments,
          { "Message fragments", "bacapp.fragments",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_msg_fragment,
          { "Message fragment", "bacapp.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_msg_fragment_overlap,
          { "Message fragment overlap", "bacapp.fragment.overlap",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_msg_fragment_overlap_conflicts,
          { "Message fragment overlapping with conflicting data",
            "bacapp.fragment.overlap.conflicts",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_msg_fragment_multiple_tails,
          { "Message has multiple tail fragments",
            "bacapp.fragment.multiple_tails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_msg_fragment_too_long_fragment,
          { "Message fragment too long", "bacapp.fragment.too_long_fragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_msg_fragment_error,
          { "Message defragmentation error", "bacapp.fragment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_msg_fragment_count,
          { "Message fragment count", "bacapp.fragment.count",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        {&hf_msg_reassembled_in,
          { "Reassembled in", "bacapp.reassembled.in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_msg_reassembled_length,
          { "Reassembled BACapp length", "bacapp.reassembled.length",
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

    static ei_register_info ei[] = {
        { &ei_bacapp_bad_length, { "bacapp.bad_length", PI_MALFORMED, PI_ERROR, "Wrong length indicated", EXPFILL }},
        { &ei_bacapp_bad_tag, { "bacapp.bad_tag", PI_MALFORMED, PI_ERROR, "Wrong tag found", EXPFILL }},
        { &ei_bacapp_opening_tag, { "bacapp.bad_opening_tag", PI_MALFORMED, PI_ERROR, "Expected Opening Tag!", EXPFILL }},
        { &ei_bacapp_max_recursion_depth_reached, { "bacapp.max_recursion_depth_reached",
            PI_PROTOCOL, PI_WARN, "Maximum allowed recursion depth reached. Dissection stopped.", EXPFILL }}
    };

    expert_module_t* expert_bacapp;

    proto_bacapp = proto_register_protocol("Building Automation and Control Network APDU",
                                           "BACapp", "bacapp");

    proto_register_field_array(proto_bacapp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_bacapp = expert_register_protocol(proto_bacapp);
    expert_register_field_array(expert_bacapp, ei, array_length(ei));
    register_dissector("bacapp", dissect_bacapp, proto_bacapp);

    reassembly_table_register(&msg_reassembly_table,
                          &addresses_reassembly_table_functions);

    bacapp_dissector_table = register_dissector_table("bacapp.vendor_identifier",
                                                      "BACapp Vendor Identifier", proto_bacapp,
                                                      FT_UINT8, BASE_HEX);

    /* Register BACnet Statistic trees */
    register_bacapp_stat_trees();
    bacapp_tap = register_tap("bacapp"); /* BACnet statistics tap */
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
