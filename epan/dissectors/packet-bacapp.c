/* packet-bacapp.c
 * Routines for BACnet (APDU) dissection
 * Copyright 2001, Hartmut Mueller <hartmut@abmlinux.org>, FH Dortmund
 * modified 2004, Herbert Lischka <lischka@kieback-peter.de>, Berlin
 *
 * $Id$
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

#ifdef HAVE_CONFIG_H
# include "config.h"
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

/*
 * XXX - this is an ASN.1-based protocol, so the dissector should perhaps
 * be generated from the ASN.1 specification.
 *
 * However, they seem to indicate in 20 "ENCODING BACnet PROTOCOL DATA
 * UNITS" in the BACnet spec that they're not using BER uniformly - the
 * fixed portion of each APDU is encoded implicitly rather than using
 * BER's explicit tagging - so that might not be possible.  If it's not,
 * it should probably still use the packet-ber.c routines.
 */

static const value_string bacapp_type_name[] = {
	{0, "Conf-Request "},
	{1, "Unconf-Request "},
	{2, "SimpleACK-PDU "},
	{3, "ComplexACK-PDU "},
	{4, "SegmentACK-PDU "},
	{5, "#### Error-PDU #### "},
	{6, "---- Reject-PDU ---- "},
	{7, "==== Abort-PDU ==== "},
	{0, NULL }
};

static const true_false_string segments_follow = {
	"Segmented Request",
	"Unsegemented Request"
};

static const true_false_string more_follow = {
	"More Segments Follow",
	"No More Segments Follow"
};

static const true_false_string segmented_accept = {
	"Segmented Response accepted",
	"Segmented Response not accepted"
};

static const true_false_string bacapp_tag_class = {
	"Context Specific Tag",
	"Application Tag"
};

static const value_string
bacapp_max_segments_accepted [] = {
	{0, "Unspecified"},
	{1,	"2 segments"},
	{2,	"4 segments"},
	{3,	"8 segments"},
	{4,	"16 segments"},
	{5,	"32 segments"},
	{6,	"64 segments"},
	{7,	"Greater than 64 segments"},
	{0, NULL }
};

static const value_string
bacapp_max_APDU_length_accepted [] = {
	{0,	"Up to MinimumMessageSize (50 octets)"},
	{1,	"Up to 128 octets"},
	{2,	"Up to 206 octets (fits in a LonTalk frame)"},
	{3,	"Up to 480 octets (fits in an ARCNET frame)"},
	{4,	"Up to 1024 octets"},
	{5,	"Up to 1476 octets"},
	{6,	"reserved by ASHRAE"},
	{7,	"reserved by ASHRAE"},
	{8,	"reserved by ASHRAE"},
	{9,	"reserved by ASHRAE"},
	{10, "reserved by ASHRAE"},
	{11, "reserved by ASHRAE"},
	{12, "reserved by ASHRAE"},
	{13, "reserved by ASHRAE"},
	{14, "reserved by ASHRAE"},
	{15, "reserved by ASHRAE"},
	{0,	NULL}
};

static const value_string
bacapp_reject_reason [] = {
	{0,	"other"},
	{1,	"buffer-overflow"},
	{2,	"inconsistent-parameters"},
	{3,	"invalid-parameter-data-type"},
	{4,	"invalid-tag"},
	{5,	"missing-required-parameter"},
	{6,	"parameter-out-of-range"},
	{7,	"too-many-arguments"},
	{8,	"undefined-enumeration"},
	{9,	"unrecognized-service"},
	{10, "reserved by ASHRAE"},
	{11, "reserved by ASHRAE"},
	{12, "reserved by ASHRAE"},
	{13, "reserved by ASHRAE"},
	{14, "reserved by ASHRAE"},
	{15, "reserved by ASHRAE"},
	{0,	NULL}
};

static const value_string
bacapp_tag_number [] = {
	{0,	"Null"},
	{1,	"Boolean"},
	{2,	"Unsigned Integer"},
	{3,	"Signed Integer (2's complement notation)"},
	{4,	"Real (ANSI/IEE-754 floating point)"},
	{5,	"Double (ANSI/IEE-754 double precision floating point)"},
	{6,	"Octet String"},
	{7,	"Character String"},
	{8,	"Bit String"},
	{9,	"Enumerated"},
	{10, "Date"},
	{11, "Time"},
	{12, "BACnetObjectIdentifier"},
	{13, "reserved by ASHRAE"},
	{14, "reserved by ASHRAE"},
	{15, "reserved by ASHRAE"},
	{0,	NULL}
};

static const value_string
bacapp_abort_reason [] = {
	{0,	"other"},
	{1,	"buffer-overflow"},
	{2,	"invalid-apdu-in-this-state"},
	{3,	"preempted-by-higher-priority-task"},
	{4,	"segmentation-not-supported"},
	{5, "reserved by ASHRAE"},
	{0,	NULL}
};

static const value_string
bacapp_confirmed_service_choice [] = {
	{0,	"acknowledgeAlarm"},
	{1,	"confirmedCOVNotification"},
	{2,	"confirmedEventNotification"},
	{3,	"getAlarmSummary"},
	{4,	"getEnrollmentSummary"},
	{5,	"subscribeCOV"},
	{6,	"atomicReadFile"},
	{7,	"atomicWriteFile"},
	{8,	"addListElement"},
	{9,	"removeListElement"},
	{10,"createObject"},
	{11,"deleteObject"},
	{12,"readProperty"},
	{13,"readPropertyConditional"},
	{14,"readPropertyMultiple"},
	{15,"writeProperty"},		/* 15 */
	{16,"writePropertyMultiple"},
	{17,"deviceCommunicationControl"},
	{18,"confirmedPrivateTransfer"},
	{19,"confirmedTextMessage"},
	{20,"reinitializeDevice"},
	{21,"vtOpen"},
	{22,"vtClose"},
	{23,"vtData"},
	{24,"authenticate"},
	{25,"requestKey"},	/* 25 */
	{26,"readRange"},
	{27,"lifeSafetyOperation"},
	{28,"subscribeCOVProperty"},
	{29,"getEventInformation"},
	{30,"reserved by ASHRAE"},
	{0, NULL}
};

static const value_string
BACnetUnconfirmedServiceChoice [] = {
	{0,	"i-Am"},
	{1,	"i-Have"},
	{2,	"unconfirmedCOVNotification"},
	{3,	"unconfirmedEventNotification"},
	{4,	"unconfirmedPrivateTransfer"},
	{5,	"unconfirmedTextMessage"},
	{6,	"timeSynchronization"},
	{7,	"who-Has"},
	{8,	"who-Is"},
	{9,	"utcTimeSynchonization"},
	{0, NULL}
};

static const value_string
BACnetUnconfirmedServiceRequest [] = {
	{0,	"i-Am-Request"},
	{1,	"i-Have-Request"},
	{2,	"unconfirmedCOVNotification-Request"},
	{3,	"unconfirmedEventNotification-Request"},
	{4,	"unconfirmedPrivateTransfer-Request"},
	{5,	"unconfirmedTextMessage-Request"},
	{6,	"timeSynchronization-Request"},
	{7,	"who-Has-Request"},
	{8,	"who-Is-Request"},
	{9,	"utcTimeSynchonization-Request"},
	{0, NULL}
};

static const value_string
bacapp_object_type [] = {
	{0,	"analog-input object"},
	{1,	"analog-output object"},
	{2,	"analog-value object"},
	{3,	"binary-input object"},
	{4,	"binary-output object"},
	{5,	"binary-value object"},
	{6,	"calendar object"},
	{7,	"command object"},
	{8,	"device object"},
	{9,	"event-enrollment object"},
	{10,"file object"},
	{11,"group object"},
	{12,"loop object"},
	{13,"multi-state-input object"},
	{14,"multi-state-output object"},
	{15,"notification-class object"},
	{16,"program object"},
	{17,"schedule object"},
	{18,"averaging object"},
	{19,"multi-state-value object"},
	{20,"trend-log object"},
	{21,"life-safety-point object"},
	{22,"life-safety-zone object"},
	{0, NULL}
};

static const value_string
bacapp_error_code [] = {
	{0,	"other"},
	{1,	"authentication-failed"},
	{2,	"character-set-not-supported"},
	{3,	"configuration-in-progress"},
	{4,	"device-busy"},
	{5,	"file-access-denied"},
	{6,	"incompatible-security-levels"},
	{7,	"inconsistent-parameters"},
	{8,	"inconsistent-selection-criterion"},
	{9,	"invalid-data-type"},
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
	{45,"optional-functionaltity-not-supported"},
	{46,"invalid-configuration-data"},
	{47,"reserved by ASHRAE"},
	{0, NULL}
};

static const value_string
bacapp_property_identifier [] = {
	{0,	"acked-transition"},
	{1,	"ack-required"},
	{2,	"action"},
	{3,	"action-text"},
	{4,	"active-text"},
	{5,	"active-vt-session"},
	{6,	"alarm-value"},
	{7,	"alarm-values"},
	{8,	"all"},
	{9,	"all-write-successfull"},
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
	{123,"weekly-svhedule"},
	{124,"attempted-samples"},
	{125,"average-value"},
	{126,"buffer-size"},
	{127,"client-cov-increment"},
	{128,"cov-resubscription-interval"},
	{129,"current-notify-time"},
	{130,"event-time-stamp"},
	{131,"log-buffer"},
	{132,"log-device-object-property"},
	{133,"log-enable"},
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
	{0, NULL}
};

static const value_string
bacapp_character_set [] = {
	{0, "   ANSI X3.4"},
	{1, "   IBM/Microsoft DBCS"},
	{2, "   JIS C 6226"},
	{3, "   ISO 10646(UCS-4)"},
	{4, "   ISO 10646(UCS-2)"},
	{5, "   ISO 18859-1"},
	{0, NULL}
};

static const value_string
bacapp_status_flags [] = {
	{0, "in-alarm"},
	{1, "fault"},
	{2, "overridden"},
	{3, "out-of-service"},
	{0, NULL}
};

static const value_string
bacapp_messagePriority [] = {
	{0, "normal"},
	{1, "urgent"},
	{0, NULL}
};

static const value_string
bacapp_AcknowledgementFilter [] = {
	{0, "and"},
	{1, "or"},
	{2, "all"},
	{0, NULL}
};

static const value_string
bacapp_resultFlags [] = {
	{0, "firstitem"},
	{1, "lastitem"},
	{2, "moreitems"},
	{0, NULL}
};

static const value_string
bacapp_relationSpecifier [] = {
	{0, "equal"},
	{1, "not-equal"},
	{2, "less-than"},
	{3, "greater-than"},
	{4, "less-than-or-equal"},
	{5, "greater-than-or-equal"},
	{0, NULL}
};

static const value_string
bacapp_selectionLogic [] = {
	{0, "normal"},
	{1, "urgent"},
	{0, NULL}
};

static const value_string
bacapp_eventStateFilter [] = {
	{0, "offnormal"},
	{1, "fault"},
	{2, "normal"},
	{3, "all"},
	{4, "active"},
	{0, NULL}
};

static const value_string
bacapp_EventTransitionBits [] = {
	{0, "to-offnormal"},
	{1, "to-fault"},
	{2, "to-normal"},
	{0, NULL}
};

static const value_string
bacapp_segmentation [] = {
	{0, "segmented-both"},
	{1, "segmented-transmit"},
	{2, "segmented-receive"},
	{3, "no-segmentation"},
	{0, NULL}
};

static const value_string
bacapp_deviceStatus [] = {
	{0, "operational"},
	{1, "operational-read-only"},
	{2, "download-required"},
	{3, "download-in-progress"},
	{4, "non-operational"},
	{5, "backup-in-progress"},
	{0, NULL}
};

static const value_string
bacapp_statusFlags [] = {
	{0, "in-alarm"},
	{1, "fault"},
	{2, "overridden"},
	{3, "out-of-service"},
	{0, NULL}
};

static const value_string
months [] = {
	{1, "January" },
	{2, "February" },
	{3, "March" },
	{4, "April" },
	{5, "May" },
	{6, "June" },
	{7, "July" },
	{8, "August" },
	{9, "September" },
	{10, "October" },
	{11, "November" },
	{12, "December" },
	{255, "unspecified" },
	{0, NULL }
};

static const value_string
days [] = {
	{1, "Monday" },
	{2, "Tuesday" },
	{3, "Wednesday" },
	{4, "Thursday" },
	{5, "Friday" },
	{6, "Saturday" },
	{7, "Sonday" },
	{255, "unspecified" },
	{0, NULL },
};

static const value_string
bacapp_errorClass [] = {
	{0, "device" },
	{1, "object" },
	{2, "property" },
	{3, "resources" },
	{4, "security" },
	{5, "services" },
	{6, "vt" },
	{0, NULL },
};

static const value_string
bacapp_EventType [] = {
	{0, "change-of-bitstring" },
	{1, "change-of-state" },
	{2, "change-of-value" },
	{3, "command-failure" },
	{4, "floating-limit" },
	{5, "out-of-range" },
	{6, "complex-event-type" },
	{7, "buffer-ready" },
	{8, "change-of-life-safety" },
	{0, NULL },
};

static const value_string
bacapp_EventState [] = {
	{0, "normal" },
	{1, "fault" },
	{2, "offnormal" },
	{3, "high-limit" },
	{4, "low-limit" },
	{5, "life-safety-alarm" },
	{0, NULL },
};

static const value_string
bacapp_NotifyType [] = {
	{0, "alarm" },
	{1, "event" },
	{2, "ack-notification" },
	{0, NULL },
};

static const value_string
bacapp_servicesSupported [] = {
	{0,	"acknowledgeAlarm"},
	{1,	"confirmedCOVNotification"},
	{2,	"confirmedEventNotification"},
	{3,	"getAlarmSummary"},
	{4,	"getEnrollmentSummary"},
	{5,	"subscribeCOV"},
	{6,	"atomicReadFile"},
	{7,	"atomicWriteFile"},
	{8,	"addListElement"},
	{9,	"removeListElement"},
	{10,"createObject"},
	{11,"deleteObject"},
	{12,"readProperty"},
	{13,"readPropertyConditional"},
	{14,"readPropertyMultiple"},
	{15,"writeProperty"},		/* 15 */
	{16,"writePropertyMultiple"},
	{17,"deviceCommunicationControl"},
	{18,"confirmedPrivateTransfer"},
	{19,"confirmedTextMessage"},
	{20,"reinitializeDevice"},
	{21,"vtOpen"},
	{22,"vtClose"},
	{23,"vtData"},
	{24,"authenticate"},
	{25,"requestKey"},	/* 25 */
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
	{40,"reserved by ASHRAE"},
	{0, NULL}
};

static const value_string
bacapp_PropertyStates [] = {
	{0,	"boolean-value"},
	{1,	"binary-value"},
	{2,	"event-type"},
	{3,	"polarity"},
	{4,	"program-change"},
	{5,	"program-state"},
	{6,	"reason-for-halt"},
	{7,	"reliability"},
	{8,	"state"},
	{9,	"system-status"},
	{10,"units"},
	{11,"unsigned-value"},
	{12,"life-safety-mode"},
	{13,"life-safety-state"},
	{0, NULL}
};

static int proto_bacapp = -1;
static int hf_bacapp_type = -1;
static int hf_bacapp_SEG = -1;
static int hf_bacapp_MOR = -1;
static int hf_bacapp_SA = -1;
static int hf_bacapp_response_segments = -1;
static int hf_bacapp_max_adpu_size = -1;
static int hf_bacapp_invoke_id = -1;
static int hf_bacapp_sequence_number = -1;
static int hf_bacapp_window_size = -1;
static int hf_bacapp_service = -1;
static int hf_bacapp_NAK = -1;
static int hf_bacapp_SRV = -1;
static int hf_bacapp_reject_reason = -1;
static int hf_bacapp_abort_reason = -1;
static int hf_bacapp_tag_number = -1;
static int hf_bacapp_tag_class = -1;
static int hf_bacapp_tag_lvt = -1;
static int hf_bacapp_tag_ProcessId = -1;
static int hf_bacapp_tag_initiatingObjectType = -1;
/* static int hf_bacapp_tag_initiatingObjectId = -1; */
static int hf_bacapp_vpart = -1;

/*
static int hf_bacapp_tag_null = -1;
static int hf_bacapp_tag_boolean = -1;
static int hf_bacapp_tag_uint8 = -1;
static int hf_bacapp_tag_uint16 = -1;
static int hf_bacapp_tag_uint32 = -1;
static int hf_bacapp_tag_uint64 = -1;
static int hf_bacapp_tag_sint8 = -1;
static int hf_bacapp_tag_sint16 = -1;
static int hf_bacapp_tag_sint32 = -1;
static int hf_bacapp_tag_sint64 = -1;
static int hf_bacapp_tag_real = -1;
static int hf_bacapp_tag_double = -1;
static int hf_bacapp_initiatingObject = -1;
static int hf_bacapp_monitoredObject = -1;
static int hf_bacapp_tag_timeRemaining = -1;
static int hf_bacapp_tag_string = -1;
static int hf_bacapp_tag_bytes = -1;
static int hf_bacapp_tag_character_set = -1;
*/
static int hf_bacapp_uservice = -1;


static gint ett_bacapp = -1;
static gint ett_bacapp_control = -1;
static gint ett_bacapp_tag = -1;

static dissector_handle_t data_handle;

static gint32 propertyIdentifier = -1;

static guint8 bacapp_flags = 0;
static guint8 bacapp_seq = 0;


int
fTagHeader (tvbuff_t *tvb, guint *offset, guint8 *tag_no, guint8* class_tag, guint64 *lvt)
{
	int tmp, retVal = 0;

	tmp = tvb_get_guint8(tvb, *offset);
	*class_tag = tmp & 0x08;
	*lvt = tmp & 0x07;
	*tag_no = tmp >> 4;
	if (*tag_no == 15) { /* B'1111' because of extended tagnumber */
		*tag_no = tvb_get_guint8(tvb, (*offset)+1);
		retVal++;
	}
	if (*lvt == 5) { /* length is more than 4 Bytes */
		*lvt = tvb_get_guint8(tvb, (*offset)+retVal+1);
		retVal++;
		if (*lvt == 254) { /* length is more than 253 Bytes */
			*lvt = tvb_get_guint8(tvb, (*offset)+retVal+1);
			retVal++;
			*lvt = (*lvt << 8) + tvb_get_guint8(tvb, (*offset)+retVal+1);
			retVal++;
		}
	}

	return retVal;
}

#define LABEL(lbl) (lbl==NULL ? (guint8 *) "   Value: " : lbl)


void
fUnsignedTag (tvbuff_t *tvb, proto_tree *tree, guint *offset, guint8 *label, guint64 lvt)
{
	guint8 tmp, i;
	guint64 val = 0;

	(*offset)++;
	for (i = 0; i < min((guint8) lvt,8); i++) {
		tmp = tvb_get_guint8(tvb, (*offset)+i);
		val = (val << 8) + tmp;
	}
	proto_tree_add_text(tree, tvb, *offset, min((guint8) lvt,8), "%s%" PRIu64, LABEL(label), val);
	(*offset)+=min((guint8) lvt,8);
}

void
fSignedTag (tvbuff_t *tvb, proto_tree *tree, guint *offset, guint8 *label, guint64 lvt)
{
	guint8 tmp, i;
	guint64 val = 0;

	(*offset)++;
	for (i = 0; i < min((guint8) lvt,8); i++) {
		tmp = tvb_get_guint8(tvb, (*offset)+i);
		val = (val << 8) + tmp;
	}
	proto_tree_add_text(tree, tvb, *offset, min((guint8) lvt,8), "%s%" PRIu64, LABEL(label), val);
	(*offset)+=min((guint8) lvt,8);
}

void
fDateTag (tvbuff_t *tvb, proto_tree *tree, guint *offset, guint8 *label, guint64 lvt)
{
	guint32 year, month, day, weekday;

	(*offset)++;
	year = tvb_get_guint8(tvb, (*offset)) + 1900;
	month = tvb_get_guint8(tvb, (*offset)+1);
	day = tvb_get_guint8(tvb, (*offset)+2);
	weekday = tvb_get_guint8(tvb, (*offset)+3);
	if ((year == 255) && (day == 255) && (month == 255) && (weekday == 255))
		proto_tree_add_text(tree, tvb, *offset, (guint8) lvt, "%sany", LABEL(label));
	else
		proto_tree_add_text(tree, tvb, *offset, (guint8) lvt, "%s%s %d, %d, (Day of Week = %s)", LABEL(label), match_strval(month, months), day, year, match_strval(weekday, days));
	(*offset)+=(guint8) lvt;
}

void
fTimeTag (tvbuff_t *tvb, proto_tree *tree, guint *offset, guint8 *label, guint64 lvt)
{
	guint32 year, month, day, weekday;

	(*offset)++;
	year = tvb_get_guint8(tvb, (*offset));
	month = tvb_get_guint8(tvb, (*offset)+1);
	day = tvb_get_guint8(tvb, (*offset)+2);
	weekday = tvb_get_guint8(tvb, (*offset)+3);
	if ((year == 255) && (day == 255) && (month == 255) && (weekday == 255))
		proto_tree_add_text(tree, tvb, *offset, (guint8) lvt, "%sany", LABEL(label));
	else
		proto_tree_add_text(tree, tvb, *offset, (guint8) lvt, "%s%d:%02d:%02d.%d %s = %02d:%02d:%02d.%d", LABEL(label), year > 12 ? year -12 : year, month, day, weekday, year > 12 ? "P.M." : "A.M.", year, month, day, weekday);
	(*offset)+=(guint8) lvt;
}

void
fOctetString (tvbuff_t *tvb, proto_tree *tree, guint *offset, guint8 *label, guint64 lvt)
{
	guint8 *str_val, len;

	if ((lvt == 0) || (lvt > tvb_reported_length(tvb)))
		lvt = tvb_reported_length(tvb) - *offset;

	proto_tree_add_text(tree, tvb, *offset, (int)lvt, "[displayed OctetString with %" PRIu64 " Bytes:] %s", lvt, LABEL(label));

	do {
		len = (guint8) min (lvt, 200);
		str_val = tvb_get_string(tvb, *offset, len);
		proto_tree_add_text(tree, tvb, *offset, len, "%s", str_val);
		g_free(str_val);
		lvt -= len;
		(*offset) += len;
	} while (lvt > 0);
}

void
fBACnetAddress (tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
	guint8 tag_no, class_tag;
	guint64 lvt;

	(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	fUnsignedTag (tvb, tree, offset, "network-number", lvt);
	(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
	if (lvt == 0)
		proto_tree_add_text(tree, tvb, *offset-1, 1, "mac-address: broadcast");
	else
		fOctetString (tvb, tree, offset, "mac-address: ", lvt);
}

void
fObjectIdentifier (tvbuff_t *tvb, proto_tree *tree, guint *offset, guint8 *label)
{
	guint8 offs, tag_no, class_tag;
	guint32 tmp, val = 0, type;
	guint64 lvt;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
	(*offset)+= offs + 1;

	val = tvb_get_guint8(tvb, (*offset));
	tmp = tvb_get_guint8(tvb, (*offset)+1);
	type = (val << 2) + (tmp >> 6);
	val = ((tmp & 0x03) << 16) + (tvb_get_guint8(tvb, (*offset)+2) << 8) + tvb_get_guint8(tvb, (*offset)+3);
	proto_tree_add_text(tree, tvb, *offset, 4,
		"%s%s, instance number %d", LABEL(label), val_to_str(type, bacapp_object_type, "(%d) reserved for ASHREA"), val);
	(*offset)+=4;
}

void
fRecipient (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 tag_no, class_tag;
	guint64 lvt;

	(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* device */
		fObjectIdentifier (tvb, tree, offset, "device: ");
		break;
	case 1:	/* address */
		fBACnetAddress (tvb, tree, offset);
		break;
	default:
		return;
		break;
	}
	fRecipient (tvb, pinfo, tree, offset);
}


void
fRecipientProcess (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 tag_no, class_tag;
	guint64 lvt;

	(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* recipient */
		fRecipient (tvb, pinfo, tree, offset);
		break;
	case 1:	/* processId */
		fUnsignedTag (tvb, tree, offset, "processId: ", lvt);
		break;
	default:
		return;
		break;
	}
	fRecipientProcess (tvb, pinfo, tree, offset);
}

void
fBACnetAddressBinding (tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
	guint8 tag_no, class_tag;
	guint64 lvt;

	(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	fObjectIdentifier (tvb, tree, offset, "deviceObjectId: ");
	(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
	fBACnetAddress (tvb, tree, offset);
}

int
fPropertyIdentifier (tvbuff_t *tvb, proto_tree *tree, guint *offset, guint8 *label)
{
	guint8 offs, tag_no, class_tag, tmp, i;
	guint64 lvt;
	guint val = 0;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
	(*offset) += offs + 1;

	for (i = 0; i < min((guint8) lvt,4); i++) {
		tmp = tvb_get_guint8(tvb, (*offset)+i);
		val = (val << 8) + tmp;
	}
	proto_tree_add_text(tree, tvb, *offset, min((guint8) lvt,4),
		"%s%s", LABEL(label),val_to_str(val, bacapp_property_identifier, "(%d) reserved for ASHREA"));
	(*offset)+=min((guint8) lvt,4);
	return val;
}

void
fApplicationTags (tvbuff_t *tvb, proto_tree *tree, guint *offset, guint8 *label, const value_string
 *src)
{
	guint8 offs, tag_no, class_tag, tmp, i, j, unused;
	guint64 val = 0, lvt;
	gfloat f_val = 0.0;
	gdouble d_val = 0.0;
	guint8 *str_val;
	guint8 bf_arr[256];

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	(*offset) += offs;	/* set offset according to enhancements.... */

	switch (tag_no) {
		case 0:	/* NULL */
			proto_tree_add_text(tree, tvb, (*offset)++, 1, "%sNULL", LABEL(label));
			break;
		case 1:	/* BOOLEAN */
			proto_tree_add_text(tree, tvb, (*offset)++, 1, "%s%s", LABEL(label), lvt == 0 ? "FALSE" : "TRUE");
			break;
		case 2:	/* Unsigned Integer */
			fUnsignedTag (tvb, tree, offset, label, lvt);
			break;
		case 3:	/* Signed Integer */
			fSignedTag (tvb, tree, offset, label, lvt);
			break;
		case 4:	/* Real */
			(*offset)++;
			f_val = tvb_get_ntohieee_float(tvb, *offset);
			proto_tree_add_text(tree, tvb, *offset, 4, "%s%f", LABEL(label), f_val);
			(*offset)+=4;
			break;
		case 5:	/* Double */
			(*offset)++;
			d_val = tvb_get_ntohieee_double(tvb, *offset);
			proto_tree_add_text(tree, tvb, *offset, 8, "%s%lf", LABEL(label), d_val);
			(*offset)+=8;
			break;
		case 6: /* Octet String */
			(*offset)++;
			proto_tree_add_text(tree, tvb, *offset-offs-1, offs+1, "%s (%d Characters)", LABEL(label), (int)lvt);
			fOctetString (tvb, tree, offset, label, lvt);
			break;
		case 7: /* Character String */
			(*offset)++;
			tmp = tvb_get_guint8(tvb, *offset);
			if (tmp == 3) {
				proto_tree_add_text (tree, tvb, *offset, 4, "   String Character Set: %s", val_to_str((guint) tmp, bacapp_character_set, "Reserved by ASHRAE"));
				(*offset)+=4;
				lvt-=4;
			}
			if (tmp == 4) {
				proto_tree_add_text (tree, tvb, *offset, 2, "   String Character Set: %s", val_to_str((guint) tmp, bacapp_character_set, "Reserved by ASHRAE"));
				(*offset)+=2;
				lvt-=2;
			}
			if ((tmp != 3) && (tmp != 4)) {
				proto_tree_add_text (tree, tvb, *offset, 1, "   String Character Set: %s", val_to_str((guint) tmp, bacapp_character_set, "Reserved by ASHRAE"));
				(*offset)++;
				lvt--;
			}
			do {
				guint8 l = (guint8) min(lvt, 255);
				str_val = tvb_get_string(tvb, *offset, l);
				/* this decoding is not correct for multi-byte characters, Lka */
				proto_tree_add_text(tree, tvb, *offset, l, "%s'%s'", LABEL(label), str_val);
				g_free(str_val);
				lvt -= l;
				(*offset) += l;
			} while (lvt > 0);
			break;
		case 8: /* Bit String */
			(*offset)++;
			unused = tvb_get_guint8(tvb, *offset); /* get the unused Bits */
			for (i = 0; i < (lvt-2); i++) {
				tmp = tvb_get_guint8(tvb, (*offset)+i+1);
				for (j = 0; j < 8; j++) {
					if (src != NULL) {
						if (tmp & (1 << (7 - j)))
							proto_tree_add_text(tree, tvb, (*offset)+i+1, 1, "%s%s = TRUE", LABEL(label), val_to_str((guint) (i*8 +j), src, "Reserved by ASHRAE"));
						else
							proto_tree_add_text(tree, tvb, (*offset)+i+1, 1, "%s%s = FALSE", LABEL(label), val_to_str((guint) (i*8 +j), src, "Reserved by ASHRAE"));

					} else {
						bf_arr[min(255,(i*8)+j)] = tmp & (1 << (7 - j)) ? '1' : '0';
					}
				}
			}
			tmp = tvb_get_guint8(tvb, (*offset)+(guint8)lvt-1);	/* jetzt das letzte Byte */
			if (src == NULL) {
				for (j = 0; j < (8 - unused); j++)
					bf_arr[min(255,((lvt-2)*8)+j)] = tmp & (1 << (7 - j)) ? '1' : '0';
				for (; j < 8; j++)
					bf_arr[min(255,((lvt-2)*8)+j)] = 'x';
				bf_arr[min(255,((lvt-2)*8)+j)] = '\0';
				proto_tree_add_text(tree, tvb, *offset, (guint8)lvt, "%sB'%s'", LABEL(label), bf_arr);
			} else {
				for (j = 0; j < (8 - unused); j++) {
					if (tmp & (1 << (7 - j)))
						proto_tree_add_text(tree, tvb, (*offset)+i+1, 1, "%s%s = TRUE", LABEL(label), val_to_str((guint) (i*8 +j), src, "Reserved by ASHRAE"));
					else
						proto_tree_add_text(tree, tvb, (*offset)+i+1, 1, "%s%s = FALSE", LABEL(label), val_to_str((guint) (i*8 +j), src, "Reserved by ASHRAE"));
				}
			}
			(*offset)+=(guint8)lvt;
			break;
		case 9: /* Enumerated */
			(*offset)++;
			for (i = 0; i < min((guint8) lvt,8); i++) {
				tmp = tvb_get_guint8(tvb, (*offset)+i);
				val = (val << 8) + tmp;
			}
			if (src != NULL)
				proto_tree_add_text(tree, tvb, *offset, (guint8)lvt, "%s%s", LABEL(label), val_to_str((guint) val, src, "Reserved by ASHRAE"));
			else
				proto_tree_add_text(tree, tvb, *offset, (guint8)lvt, "%s%" PRIu64, LABEL(label), val);

			(*offset)+=(guint8)lvt;
			break;
		case 10: /* Date */
			fDateTag (tvb, tree, offset, label, lvt);
			break;
		case 11: /* Time */
			fTimeTag (tvb, tree, offset, label, lvt);
			break;
		case 12: /* BACnetObjectIdentifier */
			fObjectIdentifier (tvb, tree, offset, LABEL(label));
			break;
		case 13: /* reserved for ASHRAE */
		case 14:
		case 15:
			(*offset)++;
			proto_tree_add_text(tree, tvb, *offset, (guint8)lvt, "%s'reserved for ASHRAE'", LABEL(label));
			(*offset)+=(guint8)lvt;
			break;
	}
}

void
fPropertyValue (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 offs, tag_no, class_tag;
	guint64 lvt;
	static int awaitingClosingTag = 0;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	if (((lvt == 7) && (offs == 0)) && !awaitingClosingTag) {  /* closing Tag */
		return;	/* but not for me */
	}

	if (class_tag) {
		switch (tag_no) {
		case 0:	/* PropertyIdentifier */
			propertyIdentifier = fPropertyIdentifier (tvb, tree, offset,  "   property Identifier: ");
			break;
		case 1:	/* propertyArrayIndex */
			fPropertyIdentifier (tvb, tree, offset, "propertyArrayIndex: ");
		break;
		case 2:  /* Value */
			(*offset) += offs + 1;	/* set offset according to enhancements.... */
			if ((lvt == 6) && (offs == 0)) {   /* opening Tag */
				awaitingClosingTag = 1;
				if (propertyIdentifier == 111) {	/* status-flags */
					fApplicationTags (tvb, tree, offset, "   propertyValue: ", bacapp_statusFlags);
				} else {
					fApplicationTags (tvb, tree, offset, NULL, NULL);
				}
			}
			if (((lvt == 7) && (offs == 0)))  /* closing Tag */
				awaitingClosingTag = 0; /* ignore corresponding closing Tag, just throw ist away */
			break;
		case 3:  /* Priority */
			(*offset) += offs;	/* set offset according to enhancements.... */
			fSignedTag (tvb, tree, offset, "   Priority: ", lvt);
		break;
		default:
			break;
		}
	} else {
		switch (propertyIdentifier)
		{
		case 97: /* Protocol-Services-Supported */
			fApplicationTags (tvb, tree, offset, "   propertyValue: ", bacapp_servicesSupported);
			break;
		case 111: /* Status-Flags */
			fApplicationTags (tvb, tree, offset, "   propertyValue: ", bacapp_statusFlags);
			break;
		case 76:  /* object-list */
			fApplicationTags (tvb, tree, offset, "   propertyValue: ", NULL);
			break;
		default:
			fApplicationTags (tvb, tree, offset, "   propertyValue: ", NULL);
			break;
		}
	}
	fPropertyValue (tvb, pinfo, tree, offset);
}

void
fSubscribeCOV (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 offs, tmp, tag_no, class_tag, i;
	guint64 lvt;
	guint32 val = 0;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* ProcessId */
		(*offset) += offs + 1;	/* set offset according to enhancements.... */
		for (i = 0; i < (guint8) min(lvt, 2); i++) {
			tmp = tvb_get_guint8(tvb, (*offset)+i);
			val = (val << 8) + tmp;
		}

		proto_tree_add_uint(tree, hf_bacapp_tag_ProcessId, tvb, *offset, (guint8)lvt, val);
		(*offset)+=(guint8)lvt;
		break;
	case 1: /* monitored ObjectId */
		fObjectIdentifier (tvb, tree, offset, "monitored ObjectId: ");
	break;
	case 2: /* issueConfirmedNotifications */
		fApplicationTags (tvb, tree, offset, "issueConfirmedNotifications: ", NULL);
		break;
	case 3:	/* life time */
		(*offset) += offs + 1;	/* set offset according to enhancements.... */
		for (i = 0; i < (guint8) min(lvt, 4); i++) {
			tmp = tvb_get_guint8(tvb, (*offset)+i);
			val = (val << 8) + tmp;
		}
		proto_tree_add_text(tree, tvb, *offset, (guint8)lvt, "life time (hh.mm.ss): %d.%02d.%02d%s", (int)(val / 3600), (int)((val % 3600) / 60), (int)(val % 60), val == 0 ? " (indefinite)" : "");
		(*offset)+=(guint8)lvt;
		return;
		break;
	default:
		return;
		break;
	}
	fSubscribeCOV (tvb, pinfo, tree, offset);
}

void
fWhoHas (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 offs, tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0: /* deviceInstanceLowLimit */
		fUnsignedTag (tvb, tree, offset, "deviceInstanceLowLimit: ", lvt);
		break;
	case 1: /* deviceInstanceHighLimit */
		fUnsignedTag (tvb, tree, offset, "deviceInstanceHighLimit: ", lvt);
		break;
	case 2: /* BACnetObjectId */
		fObjectIdentifier (tvb, tree, offset, "BACnetObjectId: ");
	break;
	case 3: /* messageText */
		fApplicationTags (tvb, tree, offset, "ObjectName: ", NULL);
		break;
	default:
		return;
	}
	fWhoHas (tvb, pinfo, tree, offset);
}

void
fUTCTimeSynchronization (tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
	guint8 tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	fDateTag (tvb, tree, offset, "Date: ", lvt);
	fTimeTag (tvb, tree, offset, "UTC-Time: ", lvt);
}

void
fTimeSynchronization (tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
	guint8 tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	fDateTag (tvb, tree, offset, "Date: ", lvt);
	fTimeTag (tvb, tree, offset, "Time: ", lvt);
}

void
fTextMessage (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* textMessageSourceDevice */
		fObjectIdentifier (tvb, tree, offset, "TextMessageSourceDevice: ");
		break;
	case 1: /* messageClass */
		(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		switch (tag_no) {
		case 0: /* numeric */
			fUnsignedTag (tvb, tree, offset, "   messageClass: ", lvt);
			break;
		case 1: /* character */
			fApplicationTags (tvb, tree, offset, "messageClass: ", NULL);
			break;
		}
		break;
	case 2: /* messagePriority */
		fApplicationTags (tvb, tree, offset, "ObjectName: ", bacapp_messagePriority);
		break;
	case 3: /* message */
		fApplicationTags (tvb, tree, offset, "message: ", NULL);
		break;
	}
	fTextMessage (tvb, pinfo, tree, offset);
}

void
fPrivateTransfer (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 offs, tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0: /* vendorID */
		fUnsignedTag (tvb, tree, offset, "   vendorID: ", lvt);
		break;
	case 1: /* serviceNumber */
		fUnsignedTag (tvb, tree, offset, "   serviceNumber: ", lvt);
		break;
	case 2: /*serviceParameters */
		if (!((lvt == 7) && (offs == 0))) {   /* not closing Tag */
			(*offset) += offs + 1;	/* set offset according to enhancements.... */
			proto_tree_add_text(tree, tvb, *offset, max(offs,1), "list of Values {");
			fPropertyValue (tvb, pinfo, tree, offset); /* use pointer, not value of offset !!!! */
		} else {
			proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
		}
		break;
	}
}

void
fNotificationParameters (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 offs, tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0: /* change-of-bitstring */
		fApplicationTags (tvb, tree, offset, "referenced-bitstring: ", NULL);
		fApplicationTags (tvb, tree, offset, "status-flags: ", bacapp_statusFlags);
		break;
	case 1: /* change-of-state */
		fApplicationTags (tvb, tree, offset, "new-state: ", bacapp_PropertyStates);
		fApplicationTags (tvb, tree, offset, "status-flags: ", bacapp_statusFlags);
		break;
	default:
		return;
	}
	fNotificationParameters (tvb, pinfo, tree, offset);
}

void
fEventNotification (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 offs, tmp, tag_no, class_tag, i;
	guint64 lvt;
	guint32 val = 0;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* ProcessId */
		(*offset) += offs + 1;	/* set offset according to enhancements.... */
		for (i = 0; i < min((guint8) lvt, 2); i++) {
			tmp = tvb_get_guint8(tvb, (*offset)+i);
			val = (val << 8) + tmp;
		}

		proto_tree_add_uint(tree, hf_bacapp_tag_ProcessId, tvb, *offset, (guint8)lvt, val);
		(*offset)+=(guint8)lvt;
		break;
	case 1: /* initiating ObjectId */
		fObjectIdentifier (tvb, tree, offset, "initiating DeviceId: ");
	break;
	case 2: /* event ObjectId */
		fObjectIdentifier (tvb, tree, offset, "event ObjectId: ");
	break;
	case 3:	/* time stamp */
		fApplicationTags (tvb, tree, offset, "Time Stamp: ", NULL);
		break;
	case 4:	/* notificationClass */
		fApplicationTags (tvb, tree, offset, "Notification Class: ", NULL);
		break;
	case 5:	/* Priority */
		fApplicationTags (tvb, tree, offset, "Priority: ", NULL);
		break;
	case 6:	/* EventType */
		fApplicationTags (tvb, tree, offset, "EventType: ", bacapp_EventType);
		break;
	case 7: /* messageText */
		fApplicationTags (tvb, tree, offset, "messageText: ", NULL);
		break;
	case 8:	/* NotifyType */
		fApplicationTags (tvb, tree, offset, "NotifyType: ", bacapp_NotifyType);
		break;
	case 9: /* ackRequired */
		fApplicationTags (tvb, tree, offset, "ackRequired: ", NULL);
		break;
	case 10: /* fromState */
		fApplicationTags (tvb, tree, offset, "fromState: ", bacapp_EventState);
		break;
	case 11: /* toState */
		fApplicationTags (tvb, tree, offset, "toState: ", bacapp_EventState);
		break;
	case 12: /* NotificationParameters */
		fNotificationParameters (tvb, pinfo, tree, offset);
		break;
	default:
		return;
		break;
	}
	fEventNotification (tvb, pinfo, tree, offset);
}

void
fCOVNotification (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 offs, tmp, tag_no, class_tag, i;
	guint64 lvt;
	guint32 val = 0;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* ProcessId */
		(*offset) += offs + 1;	/* set offset according to enhancements.... */
		for (i = 0; i < min((guint8) lvt, 2); i++) {
			tmp = tvb_get_guint8(tvb, (*offset)+i);
			val = (val << 8) + tmp;
		}

		proto_tree_add_uint(tree, hf_bacapp_tag_ProcessId, tvb, *offset, (guint8)lvt, val);
		(*offset)+=(guint8)lvt;
		break;
	case 1: /* initiating ObjectId */
		fObjectIdentifier (tvb, tree, offset, "initiating ObjectId: ");
	break;
	case 2: /* monitored ObjectId */
		fObjectIdentifier (tvb, tree, offset, "monitored ObjectId: ");
	break;
	case 3:	/* time remaining */
		(*offset) += offs + 1;	/* set offset according to enhancements.... */
		for (i = 0; i < min((guint8) lvt, 4); i++) {
			tmp = tvb_get_guint8(tvb, (*offset)+i);
			val = (val << 8) + tmp;
		}
		proto_tree_add_text(tree, tvb, *offset, (guint8)lvt, "time remaining (hh.mm.ss): %d.%02d.%02d%s", (int)(val / 3600), (int)((val % 3600) / 60), (int)(val % 60), val == 0 ? " (indefinite)" : "");
		(*offset)+=(guint8)lvt;
		break;
	case 4:	/* List of Values */
		if (!((lvt == 7) && (offs == 0))) {   /* not closing Tag */
			(*offset) += offs + 1;	/* set offset according to enhancements.... */
			proto_tree_add_text(tree, tvb, *offset, max(offs,1), "list of Values {");
			fPropertyValue (tvb, pinfo, tree, offset); /* use pointer, not value of offset !!!! */
		} else {
			proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
		}
		break;
	default:
		return;
		break;
	}
	fCOVNotification (tvb, pinfo, tree, offset);
}

void
fAckAlarm (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 offs, tmp, tag_no, class_tag, i;
	guint64 lvt;
	guint32 val = 0;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* acknowledgingProcessId */
		fUnsignedTag (tvb, tree, offset, "initiating ObjectId: ", lvt);
		break;
	case 1: /* initiating ObjectId */
		fObjectIdentifier (tvb, tree, offset, "initiating ObjectId: ");
	break;
	case 2: /* monitored ObjectId */
		fObjectIdentifier (tvb, tree, offset, "monitored ObjectId: ");
	break;
	case 3:	/* time remaining */
		(*offset) += offs + 1;	/* set offset according to enhancements.... */
		for (i = 0; i < min((guint8) lvt, 4); i++) {
			tmp = tvb_get_guint8(tvb, (*offset)+i);
			val = (val << 8) + tmp;
		}
		proto_tree_add_text(tree, tvb, *offset, (guint8)lvt, "time remaining (hh.mm.ss): %d.%02d.%02d%s", (int)(val / 3600), (int)((val % 3600) / 60), (int)(val % 60), val == 0 ? " (indefinite)" : "");
		(*offset)+=(guint8)lvt;
		break;
	case 4:	/* List of Values */
		if (!((lvt == 7) && (offs == 0))) {   /* not closing Tag */
			(*offset) += offs + 1;	/* set offset according to enhancements.... */
			proto_tree_add_text(tree, tvb, *offset, max(offs,1), "list of Values {");
			fPropertyValue (tvb, pinfo, tree, offset); /* use pointer, not value of offset !!!! */
		} else {
			proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
			return;
		}
		break;
	default:
		return;
		break;
	}
	fAckAlarm (tvb, pinfo, tree, offset);
}

void
fAckAlarmRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 tag_no, class_tag;
	guint64 lvt;

	(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* acknowledgingProcessId */
		fUnsignedTag (tvb, tree, offset, "acknowledgingProcessId: ", lvt);
		break;
	case 1: /* eventObjectId */
		fObjectIdentifier (tvb, tree, offset, "eventObjectId: ");
	break;
	case 2: /* eventStateAcknowledged */
		fApplicationTags (tvb, tree, offset, "eventStateAcknowledged: ", bacapp_EventState);
	break;
	case 3:	/* timeStamp */
		fTimeTag (tvb, tree, offset, "timeStamp: ", lvt);
		break;
	case 4:	/* acknowledgementSource */
		fApplicationTags (tvb, tree, offset, "acknowledgementSource: ", NULL);
		break;
	case 5:	/* timeOfAcknowledgement */
		fTimeTag (tvb, tree, offset, "timeOfAcknowledgement: ", lvt);
		break;
	default:
		return;
		break;
	}
	fAckAlarmRequest (tvb, pinfo, tree, offset);
}

void
fGetAlarmSummary (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	if ((*offset) >= tvb_reported_length(tvb))
		return;

	fObjectIdentifier (tvb, tree, offset, "objectIdentifier: ");
	fApplicationTags (tvb, tree, offset, "alarmState: ", bacapp_EventState);
	fApplicationTags (tvb, tree, offset, "acknowledgedTransitions: ", bacapp_EventTransitionBits);

	fGetAlarmSummary (tvb, pinfo, tree, offset);
}

void
fgetEnrollmentSummaryRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* acknowledgmentFilter */
		fApplicationTags (tvb, tree, offset, "acknowledgmentFilter: ", bacapp_AcknowledgementFilter);
		break;
	case 1: /* eventObjectId */
		fRecipientProcess (tvb, pinfo, tree, offset);
	break;
	case 2: /* eventStateFilter */
		fApplicationTags (tvb, tree, offset, "eventStateFilter: ", bacapp_eventStateFilter);
	break;
	case 3:	/* eventTypeFilter */
		fApplicationTags (tvb, tree, offset, "eventTypeFilter: ", bacapp_EventType);
		break;
	case 4:	/* priorityFilter */
		(*offset)++;
		fUnsignedTag (tvb, tree, offset, "minPriority: ", lvt);
		(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		fUnsignedTag (tvb, tree, offset, "maxPriority: ", lvt);
		break;
	case 5:	/* notificationClassFilter */
		fUnsignedTag (tvb, tree, offset, "notificationClassFilter: ", lvt);
		break;
	default:
		return;
		break;
	}
	fgetEnrollmentSummaryRequest (tvb, pinfo, tree, offset);
}

void
fgetEnrollmentSummaryAck (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	fObjectIdentifier (tvb, tree, offset, "ObjectId: ");
	fApplicationTags (tvb, tree, offset, "eventType: ", bacapp_EventType);
	fApplicationTags (tvb, tree, offset, "eventState: ", bacapp_eventStateFilter);
	(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
	fUnsignedTag (tvb, tree, offset, "Priority: ", lvt);
	(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
	fUnsignedTag (tvb, tree, offset, "notificationClass: ", lvt);

	fgetEnrollmentSummaryAck (tvb, pinfo, tree, offset);
}

void
fGetEventInformationRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* lastReceivedObjectId */
		fObjectIdentifier (tvb, tree, offset, "lastReceivedObjectId: ");
		break;
	default:
		return;
		break;
	}
	fGetEventInformationRequest (tvb, pinfo, tree, offset);
}

void
flistOfEventSummaries (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* ObjectId */
		fObjectIdentifier (tvb, tree, offset, "ObjectId: ");
		break;
	case 1: /* eventState */
		fApplicationTags (tvb, tree, offset, "eventState: ", bacapp_eventStateFilter);
		break;
	case 2: /* acknowledgedTransitions */
		fApplicationTags (tvb, tree, offset, "acknowledgedTransitions: ", bacapp_EventTransitionBits);
		break;
	case 3: /* eventTimeStamps */
		fTimeTag (tvb, tree, offset, "timeStamp: ", lvt);
		(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		fTimeTag (tvb, tree, offset, "timeStamp: ", lvt);
		(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		fTimeTag (tvb, tree, offset, "timeStamp: ", lvt);
		break;
	case 4: /* notifyType */
		fApplicationTags (tvb, tree, offset, "NotifyType: ", bacapp_NotifyType);
		break;
	case 5: /* eventEnable */
		fApplicationTags (tvb, tree, offset, "eventEnable: ", bacapp_EventTransitionBits);
		break;
	case 6: /* eventPriorities */
		fUnsignedTag (tvb, tree, offset, "eventPriority: ", lvt);
		(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		fUnsignedTag (tvb, tree, offset, "eventPriority: ", lvt);
		(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		fUnsignedTag (tvb, tree, offset, "eventPriority: ", lvt);
		break;
	default:
		return;
		break;
	}
	flistOfEventSummaries (tvb, pinfo, tree, offset);
}

void
fGetEventInformation (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* listOfEventSummaries */
		flistOfEventSummaries (tvb, pinfo, tree, offset);
		break;
	case 1: /* moreEvents */
		fApplicationTags (tvb, tree, offset, "moreEvents: ", NULL);
		break;
	default:
		return;
		break;
	}
	fGetEventInformationRequest (tvb, pinfo, tree, offset);
}

void
fAddListElement (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 offs, tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* ObjectId */
		fObjectIdentifier (tvb, tree, offset, "ObjectId: ");
		break;
	case 1:	/* propertyIdentifier */
		propertyIdentifier = fPropertyIdentifier (tvb, tree, offset, "property Identifier: ");
	break;
	case 2: /* propertyArrayIndex */
		(*offset)+= offs;
		fSignedTag (tvb, tree, offset, "propertyArrayIndex: ", lvt);
	break;
	case 3:	/* propertyValue */
		(*offset) += offs; /* set offset according to enhancements.... */
		if ((lvt == 6) && (offs == 0)) {   /* opening Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, max(offs,1), "list of Elements {");
			fPropertyValue (tvb, pinfo, tree, offset); /* use pointer, not value of offset !!!! */
		}
		if (((lvt == 7) && (offs == 0))) {   /* closing Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
			return;
		}
	break;
	default:
		return;
		break;
	}
	fAddListElement (tvb, pinfo, tree, offset);
}

void
fDeleteObject (tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
	fObjectIdentifier (tvb, tree, offset, "BACnetObjectIdentifier: ");
}

void
fWritePropertyMultiple (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	if ((*offset) >= tvb_reported_length(tvb))
		return;

	/* not yet implemented */
	*pinfo = *pinfo; /* just to eliminate warnings */
	*tree = *tree; /* just to eliminate warnings */

}

void
fDeviceCommunicationControl (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	if ((*offset) >= tvb_reported_length(tvb))
		return;

	/* not yet implemented */
	*pinfo = *pinfo; /* just to eliminate warnings */
	*tree = *tree; /* just to eliminate warnings */

}

void
fReinitializeDevice (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	if ((*offset) >= tvb_reported_length(tvb))
		return;

	/* not yet implemented */
	*pinfo = *pinfo; /* just to eliminate warnings */
	*tree = *tree; /* just to eliminate warnings */

}

void
fVtOpen (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	if ((*offset) >= tvb_reported_length(tvb))
		return;

	/* not yet implemented */
	*pinfo = *pinfo; /* just to eliminate warnings */
	*tree = *tree; /* just to eliminate warnings */

}

void
fVtClose (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	if ((*offset) >= tvb_reported_length(tvb))
		return;

	/* not yet implemented */
	*pinfo = *pinfo; /* just to eliminate warnings */
	*tree = *tree; /* just to eliminate warnings */

}

void
fVtData (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	if ((*offset) >= tvb_reported_length(tvb))
		return;

	/* not yet implemented */
	*pinfo = *pinfo; /* just to eliminate warnings */
	*tree = *tree; /* just to eliminate warnings */

}

void
fAuthenticate (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	if ((*offset) >= tvb_reported_length(tvb))
		return;

	/* not yet implemented */
	*pinfo = *pinfo; /* just to eliminate warnings */
	*tree = *tree; /* just to eliminate warnings */

}

void
fRequestKey (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	if ((*offset) >= tvb_reported_length(tvb))
		return;

	/* not yet implemented */
	*pinfo = *pinfo; /* just to eliminate warnings */
	*tree = *tree; /* just to eliminate warnings */

}

void
fLifeSafetyOperation (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	if ((*offset) >= tvb_reported_length(tvb))
		return;

	/* not yet implemented */
	*pinfo = *pinfo; /* just to eliminate warnings */
	*tree = *tree; /* just to eliminate warnings */

}

void
fSubscribeCOVProperty (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	if ((*offset) >= tvb_reported_length(tvb))
		return;

	/* not yet implemented */
	*pinfo = *pinfo; /* just to eliminate warnings */
	*tree = *tree; /* just to eliminate warnings */

}

void
fRemoveListElement (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	if ((*offset) >= tvb_reported_length(tvb))
		return;

	/* not yet implemented */
	*pinfo = *pinfo; /* just to eliminate warnings */
	*tree = *tree; /* just to eliminate warnings */

}

void
fReadWriteProperty (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 offs, tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* objectIdentifier */
		fObjectIdentifier (tvb, tree, offset, "BACnetObjectIdentifier: ");
	break;
	case 1:	/* propertyIdentifier */
		propertyIdentifier = fPropertyIdentifier (tvb, tree, offset, "property Identifier: ");
	break;
	case 2: /* propertyArrayIndex */
		(*offset)+= offs;
		fSignedTag (tvb, tree, offset, "propertyArrayIndex: ", lvt);
	break;
	case 3:	/* propertyValue */
		(*offset) += offs; /* set offset according to enhancements.... */
		if ((lvt == 6) && (offs == 0)) {   /* opening Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, max(offs,1), "list of Values {");
			fPropertyValue (tvb, pinfo, tree, offset); /* use pointer, not value of offset !!!! */
		}
		if (((lvt == 7) && (offs == 0))) {   /* closing Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
		/*	return;  */
		}
	break;
	case 4: /* Priority */
		(*offset)+= offs;
		fSignedTag (tvb, tree, offset, "Priority: ", lvt);
	break;
	default:
		proto_tree_add_text(tree, tvb, (*offset)++, 1, "unknown");
		return;
	}
	fReadWriteProperty (tvb, pinfo, tree, offset);
}


void
fPropertyReference (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 offs, tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	if (lvt == 7)	/* closing bracket */
		return;

	switch (tag_no) {
	case 0:	/* PropertyIdentifier */
		propertyIdentifier = fPropertyIdentifier (tvb, tree, offset, "property Identifier: ");
		break;
	case 1:	/* propertyArrayIndex */
		(*offset)+= offs;
		fUnsignedTag (tvb, tree, offset, "propertyArrayIndex: ", lvt);
	break;
	default:
		return;
	}
	fPropertyReference (tvb, pinfo, tree, offset);
}

void
fSelectionCriteria (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 offs, tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* selectionLogic */
		propertyIdentifier = fPropertyIdentifier (tvb, tree, offset, "property Identifier: ");
		break;
	case 1:	/* propertyArrayIndex */
		(*offset)+= offs;
		fUnsignedTag (tvb, tree, offset, "propertyArrayIndex: ", lvt);
		break;
	case 2: /* relationSpecifier */
		fApplicationTags (tvb, tree, offset, "relationSpecifier: ", bacapp_relationSpecifier);
		break;
	case 3: /* comparisonValue */
		fApplicationTags (tvb, tree, offset, "comparisonValue: ", NULL);
		break;
	default:
		return;
	}
	fSelectionCriteria (tvb, pinfo, tree, offset);
}

void
fObjectSelectionCriteria (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 offs, tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* selectionLogic */
		fApplicationTags (tvb, tree, offset, "selectionLogic: ", bacapp_selectionLogic);
		break;
	case 1:	/* listOfSelectionCriteria */
		(*offset) += offs; /* set offset according to enhancements.... */
		if ((lvt == 6) && (offs == 0)) {   /* opening Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, max(offs,1), "list of PropertyReferences {");
		}
		fSelectionCriteria (tvb, pinfo, tree, offset);

		if (((lvt == 7) && (offs == 0))) {   /* closing Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
			return;
		}
		break;
	default:
		return;
	}
	fObjectSelectionCriteria (tvb, pinfo, tree, offset);
}


void
fReadPropertyConditional (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 offs, tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* objectSelectionCriteria */
		fObjectSelectionCriteria (tvb, pinfo, tree, offset);
		break;
	case 1:	/* listOfPropertyReferences */
		(*offset) += offs; /* set offset according to enhancements.... */
		if ((lvt == 6) && (offs == 0)) {   /* opening Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, max(offs,1), "list of PropertyReferences {");
		}
		fPropertyReference (tvb, pinfo, tree, offset);

		if (((lvt == 7) && (offs == 0))) {   /* closing Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
			return;
		}
		break;
	default:
		return;
	}
	fReadPropertyConditional (tvb, pinfo, tree, offset);
}

void
fReadWriteMultipleProperty (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 offs, tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	/* not yet implemented */
	*pinfo = *pinfo; /* just to eliminate warnings */
	*tree = *tree; /* just to eliminate warnings */
}

void
fReadAccessSpecification (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 offs, tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* objectIdentifier */
		fObjectIdentifier (tvb, tree, offset, "BACnetObjectIdentifier: ");
		break;
	case 1:	/* listOfPropertyReferences */
		(*offset) += offs; /* set offset according to enhancements.... */
		if ((lvt == 6) && (offs == 0)) {   /* opening Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, max(offs,1), "list of PropertyReferences {");
		}
		fPropertyReference (tvb, pinfo, tree, offset);

		if (((lvt == 7) && (offs == 0))) {   /* closing Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
			return;
		}
		break;
	default:
		return;
	}
	fReadAccessSpecification (tvb, pinfo, tree, offset);
}

void
fWriteAccessSpecification (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 offs, tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* objectIdentifier */
		fObjectIdentifier (tvb, tree, offset, "BACnetObjectIdentifier: ");
		break;
	case 1:	/* listOfPropertyValues */
		(*offset) += offs; /* set offset according to enhancements.... */
		if ((lvt == 6) && (offs == 0)) {   /* opening Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, max(offs,1), "list of PropertyValues {");
		}
		fPropertyValue (tvb, pinfo, tree, offset);

		if (((lvt == 7) && (offs == 0))) {   /* closing Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
			return;
		}
		break;
	default:
		return;
	}
	fReadAccessSpecification (tvb, pinfo, tree, offset);
}

void
fReadAccessResult (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 offs, tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* objectIdentifier */
		fObjectIdentifier (tvb, tree, offset, "BACnetObjectIdentifier: ");
		break;
	case 1:	/* listOfResults */
		(*offset) += offs; /* set offset according to enhancements.... */
		if ((lvt == 6) && (offs == 0)) {   /* opening Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, max(offs,1), "list of Results {");
		}
		if (((lvt == 7) && (offs == 0))) {   /* closing Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
			return;
		}
		break;
	case 2:	/* propertyIdentifier */
		propertyIdentifier = fPropertyIdentifier (tvb, tree, offset, "property Identifier: ");
	break;
	case 3: /* propertyArrayIndex */
		(*offset)+= offs;
		fUnsignedTag (tvb, tree, offset, "propertyArrayIndex: ", lvt);
	break;
	case 4:	/* propertyValue */
		(*offset) += offs; /* set offset according to enhancements.... */
		if ((lvt == 6) && (offs == 0)) {   /* opening Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, max(offs,1), "list of Values {");
			fPropertyValue (tvb, pinfo, tree, offset); /* use pointer, not value of offset !!!! */
		}
		if (((lvt == 7) && (offs == 0))) {   /* closing Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
			return;
		}
	break;
	case 5:	/* propertyAccessError */
		(*offset) += offs; /* set offset according to enhancements.... */
		if ((lvt == 6) && (offs == 0)) {   /* opening Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, max(offs,1), "list of Errors {");
			/* Error Code follows */
			fApplicationTags (tvb, tree, offset, "   errorClass: ", bacapp_errorClass);
			fApplicationTags (tvb, tree, offset, "   errorCode: ", bacapp_error_code);
		}
		if (((lvt == 7) && (offs == 0))) {   /* closing Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
		}
	break;
	default:
		return;
	}
	fReadAccessResult (tvb, pinfo, tree, offset);
}


void
fReadPropertyConditionalAck (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 offs, tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	/* listOfReadAccessResults */
	fReadAccessResult (tvb, pinfo, tree, offset);
	fReadPropertyConditionalAck (tvb, pinfo, tree, offset);
}


void
fObjectSpecifier (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 offs, tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* objectType */
		proto_tree_add_item(tree, hf_bacapp_tag_initiatingObjectType, tvb, (*offset), 1, TRUE);
	break;
	case 1:	/* objectIdentifier */
		fObjectIdentifier (tvb, tree, offset, "BACnetObjectIdentifier: ");
	break;
	}
	fObjectSpecifier (tvb, pinfo, tree, offset);
}



void
fCreateObject (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 offs, tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* objectSpecifier */
		fObjectSpecifier (tvb, pinfo, tree, offset);
	break;
	case 1:	/* propertyValue */
		(*offset) += offs; /* set offset according to enhancements.... */
		if ((lvt == 6) && (offs == 0)) {   /* opening Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, max(offs,1), "list of Values {");
			fPropertyValue (tvb, pinfo, tree, offset); /* use pointer, not value of offset !!!! */
		}
		if (((lvt == 7) && (offs == 0))) {   /* closing Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
			return;
		}
	break;
	default:
		proto_tree_add_text(tree, tvb, (*offset)++, 1, "unknown");
		return;
	}
	fCreateObject (tvb, pinfo, tree, offset);
}

void
fCreateObjectAck (tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
	fObjectIdentifier (tvb, tree, offset, "BACnetObjectIdentifier: ");
}

void
fReadRangeRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 offs, tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* objectSpecifier */
		fObjectIdentifier (tvb, tree, offset, "BACnetObjectIdentifier: ");
		break;
	case 1:	/* propertyIdentifier */
		propertyIdentifier = fPropertyIdentifier (tvb, tree, offset, "property Identifier: ");
		break;
	case 2:	/* propertyArrayIndex Optional */
		fUnsignedTag (tvb, tree, offset, "PropertyArrayIndex: ", lvt);
		break;
	case 3:	/* range byPosition */
		(*offset) += offs; /* set offset according to enhancements.... */
		if ((lvt == 6) && (offs == 0)) {   /* opening Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, max(offs,1), "range byPosition: referenceIndex, count {");
			fPropertyValue (tvb, pinfo, tree, offset); /* use pointer, not value of offset !!!! */
		}
		if (((lvt == 7) && (offs == 0))) {   /* closing Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
			return;
		}
	break;
	case 4:	/* range byTime */
		(*offset) += offs; /* set offset according to enhancements.... */
		if ((lvt == 6) && (offs == 0)) {   /* opening Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, max(offs,1), "range byTime: referenceTime, count {");
			fPropertyValue (tvb, pinfo, tree, offset); /* use pointer, not value of offset !!!! */
		}
		if (((lvt == 7) && (offs == 0))) {   /* closing Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
			return;
		}
	break;
	case 5:	/* range timeRange */
		(*offset) += offs; /* set offset according to enhancements.... */
		if ((lvt == 6) && (offs == 0)) {   /* opening Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, max(offs,1), "TimeRange: beginningTime, endingTime {");
			fPropertyValue (tvb, pinfo, tree, offset); /* use pointer, not value of offset !!!! */
		}
		if (((lvt == 7) && (offs == 0))) {   /* closing Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
			return;
		}
	break;
	default:
		return;
	}
	fReadRangeRequest (tvb, pinfo, tree, offset);
}

void
fReadRangeAck (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 offs, tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* objectSpecifier */
		fObjectIdentifier (tvb, tree, offset, "BACnetObjectIdentifier: ");
		break;
	case 1:	/* propertyIdentifier */
		propertyIdentifier = fPropertyIdentifier (tvb, tree, offset, "property Identifier: ");
		break;
	case 2:	/* propertyArrayIndex Optional */
		fUnsignedTag (tvb, tree, offset, "PropertyArrayIndex: ", lvt);
		break;
	case 3:	/* resultFlags */
		fApplicationTags (tvb, tree, offset, "resultFlags: ", bacapp_resultFlags);
	break;
	case 4:	/* itemCount */
		fUnsignedTag (tvb, tree, offset, "itemCount: ", lvt);
	break;
	case 5:	/* itemData */
		(*offset) += offs; /* set offset according to enhancements.... */
		if ((lvt == 6) && (offs == 0)) {   /* opening Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, max(offs,1), "List Of Values {");
			fApplicationTags (tvb, tree, offset, "   Data: ", NULL);
		}
		if (((lvt == 7) && (offs == 0))) {   /* closing Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
			return;
		}
	break;
	default:
		return;
	}
	fReadRangeAck (tvb, pinfo, tree, offset);
}

void
fAtomicReadFileRequest (tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
	guint8 offs, tag_no, class_tag;
	guint64 lvt;

	fObjectIdentifier (tvb, tree, offset, "BACnetObjectIdentifier: ");

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* streamAccess */
		(*offset) += offs; /* set offset according to enhancements.... */
		if ((lvt == 6) && (offs == 0)) {   /* opening Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, max(offs,1), "streamAccess {");
		}
		(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		fSignedTag (tvb, tree, offset, "   FileStartPosition: ", lvt);
		(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		fUnsignedTag (tvb, tree, offset, "   requestetOctetCount: ", lvt);
		(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		if (((lvt == 7) && (offs == 0))) {   /* closing Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
		}
		break;
	case 1:	/* recordAccess */
		(*offset) += offs; /* set offset according to enhancements.... */
		if ((lvt == 6) && (offs == 0)) {   /* opening Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, max(offs,1), "recordAccess {");
		}
		(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		fSignedTag (tvb, tree, offset, "   FileStartRecord: ", lvt);
		(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		fUnsignedTag (tvb, tree, offset, "   requestetRecordCount: ", lvt);
		(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		if (((lvt == 7) && (offs == 0))) {   /* closing Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
		}
	break;
	default:
		return;
	}
}

void
fAtomicWriteFileRequest (tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
	guint8 offs, tag_no, class_tag;
	guint64 lvt;

	if ((bacapp_flags & 0x08) && (bacapp_seq != 0)) {	/* Segment of an Request */
		if (bacapp_flags & 0x04) { /* More Flag is set */
			fOctetString (tvb, tree, offset, "   fileData: ", 0);
		} else {
			fOctetString (tvb, tree, offset, "   fileData: ", tvb_reported_length(tvb) - *offset - 1);
			(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
			if (lvt == 7) {   /* closing Tag */
				proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
			}
		}
	} else {
		fObjectIdentifier (tvb, tree, offset, "fileIdentifier: ");

		offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

		switch (tag_no) {
		case 0:	/* streamAccess */
			(*offset) += offs; /* set offset according to enhancements.... */
			if ((lvt == 6) && (offs == 0)) {   /* opening Tag */
				proto_tree_add_text(tree, tvb, (*offset)++, max(offs,1), "streamAccess {");
			}
			(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
			fSignedTag (tvb, tree, offset, "   FileStartPosition: ", lvt);
			fApplicationTags (tvb, tree, offset, "   fileData: ", NULL);
			if (bacapp_flags && 0x04) { /* More Flag is set */
				break;
			}
			(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
			if (((lvt == 7) && (offs == 0))) {   /* closing Tag */
				proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
			}
			break;
		case 1:	/* recordAccess */
			(*offset) += offs; /* set offset according to enhancements.... */
			if ((lvt == 6) && (offs == 0)) {   /* opening Tag */
				proto_tree_add_text(tree, tvb, (*offset)++, max(offs,1), "streamAccess {");
			}
			(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
			fSignedTag (tvb, tree, offset, "  fileStartRecord: ", lvt);
			fUnsignedTag (tvb, tree, offset, "  RecordCount: ", lvt);
			fApplicationTags (tvb, tree, offset, "  Data: ", NULL);
			if (bacapp_flags && 0x04) { /* More Flag is set */
				break;
			}
			(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
			if (((lvt == 7) && (offs == 0))) {   /* closing Tag */
				proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
			}
		break;
		default:
			return;
		}
	}
}

void
fAtomicWriteFileAck (tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
	guint8 tag_no, class_tag;
	guint64 lvt;

	(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* streamAccess */
		fSignedTag (tvb, tree, offset, "   FileStartPosition: ", lvt);
		break;
	case 1:	/* recordAccess */
		fSignedTag (tvb, tree, offset, "  fileStartRecord: ", lvt);
	break;
	default:
		return;
	}
}

void
fAtomicReadFile (tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
	guint8 offs, tag_no, class_tag;
	guint64 lvt;

	if ((bacapp_flags & 0x08) && (bacapp_seq != 0)) {	/* Segment of an Request */
		if (bacapp_flags & 0x04) { /* More Flag is set */
			fOctetString (tvb, tree, offset, "   fileData: ", 0);
		} else {
			fOctetString (tvb, tree, offset, "   fileData: ", tvb_reported_length(tvb) - *offset - 1);
			(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
			if (lvt == 7) {   /* closing Tag */
				proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
			}
		}
	} else {
		fApplicationTags (tvb, tree, offset, "EndOfFile: ", NULL);

		offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

		switch (tag_no) {
		case 0:	/* streamAccess */
			(*offset) += offs; /* set offset according to enhancements.... */
			if ((lvt == 6) && (offs == 0)) {   /* opening Tag */
				proto_tree_add_text(tree, tvb, (*offset)++, max(offs,1), "streamAccess {");
			}
			(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
			fSignedTag (tvb, tree, offset, "   FileStartPosition: ", lvt);
			fApplicationTags (tvb, tree, offset, "   fileData: ", NULL);
			if (bacapp_flags && 0x04) { /* More Flag is set */
				break;
			}
			(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
			if (((lvt == 7) && (offs == 0))) {   /* closing Tag */
				proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
			}
			break;
		case 1:	/* recordAccess */
			(*offset) += offs; /* set offset according to enhancements.... */
			if ((lvt == 6) && (offs == 0)) {   /* opening Tag */
				proto_tree_add_text(tree, tvb, (*offset)++, max(offs,1), "streamAccess {");
			}
			(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
			fSignedTag (tvb, tree, offset, "  FileStartRecord: ", lvt);
			fUnsignedTag (tvb, tree, offset, "  returnedRecordCount: ", lvt);
			fApplicationTags (tvb, tree, offset, "  Data: ", NULL);
			if (bacapp_flags && 0x04) { /* More Flag is set */
				break;
			}
			(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
			if (((lvt == 7) && (offs == 0))) {   /* closing Tag */
				proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
			}
		break;
		default:
			return;
		}
	}
}

void
fReadPropertyMultipleRequest (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 offs, tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* objectSpecifier */
		fObjectIdentifier (tvb, tree, offset, "BACnetObjectIdentifier: ");
		break;
	case 1:	/* list of propertyReferences */
		(*offset) += offs; /* set offset according to enhancements.... */
		if ((lvt == 6) && (offs == 0)) {   /* opening Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, max(offs,1), "list of Values {");
			fPropertyReference (tvb, pinfo, tree, offset); /* use pointer, not value of offset !!!! */
		}
		if (((lvt == 7) && (offs == 0))) {   /* closing Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
		}
	break;
	default:
		return;
	}
	fReadPropertyMultipleRequest (tvb, pinfo, tree, offset);
}

void
fReadPropertyMultipleAck (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 offs, tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (tag_no) {
	case 0:	/* objectSpecifier */
		fObjectIdentifier (tvb, tree, offset, "BACnetObjectIdentifier: ");
		break;
	case 1:	/* list of Results */
		(*offset) += offs; /* set offset according to enhancements.... */
		if ((lvt == 6) && (offs == 0)) {   /* opening Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, max(offs,1), "list of Results {");
		}
		if (((lvt == 7) && (offs == 0))) {   /* closing Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
		}
	break;
	case 2:	/* propertyIdentifier */
		propertyIdentifier = fPropertyIdentifier (tvb, tree, offset, "property Identifier: ");
		break;
	case 3:	/* propertyArrayIndex Optional */
		fUnsignedTag (tvb, tree, offset, "PropertyArrayIndex: ", lvt);
		break;
	case 4:	/* propertyValue */
		(*offset) += offs; /* set offset according to enhancements.... */
		if ((lvt == 6) && (offs == 0)) {   /* opening Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, max(offs,1), "list of Values {");
			fPropertyValue (tvb, pinfo, tree, offset); /* use pointer, not value of offset !!!! */
		}
		if (((lvt == 7) && (offs == 0))) {   /* closing Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
		}
	break;
	case 5:	/* propertyAccessError */
		(*offset) += offs; /* set offset according to enhancements.... */
		if ((lvt == 6) && (offs == 0)) {   /* opening Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, max(offs,1), "list of Errors {");
			/* Error Code follows */
			fApplicationTags (tvb, tree, offset, "   errorClass: ", bacapp_errorClass);
			fApplicationTags (tvb, tree, offset, "   errorCode: ", bacapp_error_code);
		}
		if (((lvt == 7) && (offs == 0))) {   /* closing Tag */
			proto_tree_add_text(tree, tvb, (*offset)++, 1, "}");
		}
	break;
	default:
		return;
	}
	fReadPropertyMultipleAck (tvb, pinfo, tree, offset);
}

void
fTagRequests (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset, gint service_choice)
{
	guint8 offs, tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

#if 0
	if (class_tag)	{	/* Context Specific Tag detected */
#endif
		switch (service_choice) {
		case 0:	/* acknowledgeAlarm */
			fAckAlarmRequest (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 1: /* confirmedCOVNotification*/
			fCOVNotification (tvb, pinfo, tree, offset); /* offset changes his value on return */
		break;
		case 2: /* confirmedEventNotification*/
			fEventNotification (tvb, pinfo, tree, offset); /* offset changes his value on return */
		break;
		case 3: /* confirmedEventNotification*/
			fGetAlarmSummary (tvb, pinfo, tree, offset); /* offset changes his value on return */
		break;
		case 4: /* getEnrollmentSummaryRequest */
			fgetEnrollmentSummaryRequest (tvb, pinfo, tree, offset);
			break;
		case 5: /* subscribeCOVRequest */
			fSubscribeCOV (tvb, pinfo, tree, offset);
		break;
		case 6: /* atomicReadFile-Request */
			fAtomicReadFileRequest (tvb, tree, offset);
			break;
		case 7: /* atomicReadFile-Request */
			fAtomicWriteFileRequest (tvb, tree, offset);
			break;
		case 8: /* AddListElement-Request */
			fAddListElement (tvb, pinfo, tree, offset);
			break;
		case 9: /* removeListElement-Request */
			fRemoveListElement (tvb, pinfo, tree, offset);
			break;
		case 10: /* createObjectRequest */
			fCreateObject (tvb, pinfo, tree, offset);
		break;
		case 11: /* deleteObject */
			fDeleteObject (tvb, tree, offset);
		break;
		case 12:
			fReadWriteProperty (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 13:
			fReadPropertyConditional (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 14:
			fReadPropertyMultipleRequest (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 15:
			fReadWriteProperty (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 16:
			fReadWriteMultipleProperty (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 17:
			fDeviceCommunicationControl (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 18:
			fPrivateTransfer (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 19:
			fTextMessage (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 20:
			fReinitializeDevice (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 21:
			fVtOpen (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 22:
			fVtClose (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 23:
			fVtData (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 24:
			fAuthenticate (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 25:
			fRequestKey (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 26:
			fReadRangeRequest (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 27:
			fLifeSafetyOperation (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 28:
			fSubscribeCOVProperty (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 29:
			fGetEventInformationRequest (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		default:
			return;
		break;
		}
#if 0
	} else {	/* Application Specific Tags */
		fApplicationTags (tvb, tree, offset, NULL, NULL);
	}
#endif

 /*	fTagRequests (tvb, pinfo, tree, offset, service_choice); ### */
}

void
fTags (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset, gint service_choice)
{
	guint8 offs, tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

#if 0
	if (class_tag)	{	/* Context Specific Tag detected */
#endif
		switch (service_choice) {
		case 0:	/* acknowledgeAlarm */
			fAckAlarm (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 1: /* confirmedCOVNotification*/
			fCOVNotification (tvb, pinfo, tree, offset); /* offset changes his value on return */
		break;
		case 2: /* confirmedEventNotification*/
			fEventNotification (tvb, pinfo, tree, offset); /* offset changes his value on return */
		break;
		case 3: /* confirmedEventNotification*/
			fGetAlarmSummary (tvb, pinfo, tree, offset); /* offset changes his value on return */
		break;
		case 4: /* getEnrollmentSummaryAck */
			fgetEnrollmentSummaryAck (tvb, pinfo, tree, offset);
			break;
		case 5: /* subscribeCOV */
			fSubscribeCOV (tvb, pinfo, tree, offset);
		break;
		case 6: /* atomicReadFile */
			fAtomicReadFile (tvb, tree, offset);
			break;
		case 7: /* atomicReadFileAck */
			fAtomicWriteFileAck (tvb, tree, offset);
			break;
		case 8: /* AddListElement */
			fAddListElement (tvb, pinfo, tree, offset);
			break;
		case 9: /* removeListElement */
			fRemoveListElement (tvb, pinfo, tree, offset);
			break;
		case 10: /* createObject */
			fCreateObjectAck (tvb, tree, offset);
		break;
		case 11: /* deleteObject */
			fDeleteObject (tvb, tree, offset);
		break;
		case 12:
			fReadWriteProperty (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 13:
			fReadPropertyConditionalAck (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 14:
			fReadPropertyMultipleAck (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 15:
			fReadWriteProperty (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 16:
			fReadWriteMultipleProperty (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 17:
			fDeviceCommunicationControl (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 18:
			fPrivateTransfer (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 19:
			fTextMessage (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 20:
			fReinitializeDevice (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 21:
			fVtOpen (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 22:
			fVtClose (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 23:
			fVtData (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 24:
			fAuthenticate (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 25:
			fRequestKey (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 26:
			fReadRangeAck (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 27:
			fLifeSafetyOperation (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 28:
			fSubscribeCOVProperty (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		case 29:
			fGetEventInformation (tvb, pinfo, tree, offset); /* offset changes his value on return */
			break;
		default:
			return;
		break;
		}
#if 0
	} else {	/* Application Specific Tags */
		fApplicationTags (tvb, pinfo, tree, offset, NULL, NULL);
	}
#endif
}

void
fIAm (tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
	guint8 offs, tmp, tag_no, class_tag, i;
	guint64 lvt;
	guint32 val = 0;

	/* BACnetObjectIdentifier */
	fApplicationTags (tvb, tree, offset, "BACnetObjectIdentifier: ", NULL);

	/* MaxAPDULengthAccepted */
	fApplicationTags (tvb, tree, offset, "Maximum ADPU Length accepted: ", NULL);

	/* segmentationSupported */
	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		(*offset) += offs + 1;	/* set offset according to enhancements.... */
	for (i = 0; i < min((guint8) lvt, 4); i++) {
		tmp = tvb_get_guint8(tvb, (*offset)+i);
		val = (val << 8) + tmp;
	}
	proto_tree_add_text(tree, tvb, *offset, 1, "segmentationSupported: %s", match_strval(val, bacapp_segmentation));
	(*offset)+=(guint8)lvt;

	/* vendor ID */
	(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
	fUnsignedTag (tvb, tree, offset, "vendorID: ", lvt);

}

void
fIHave (tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
	/* BACnetDeviceIdentifier */
	fApplicationTags (tvb, tree, offset, "DeviceIdentifier: ", NULL);

	/* BACnetObjectIdentifier */
	fApplicationTags (tvb, tree, offset, "ObjectIdentifier: ", NULL);

	/* ObjectName */
	fApplicationTags (tvb, tree, offset, "ObjectName: ", NULL);

}

void
fWhoIs (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	guint8 tag_no, class_tag;
	guint64 lvt;

	if ((*offset) >= tvb_reported_length(tvb))
		return;

	(*offset) += fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);


	switch (tag_no) {
	case 0:	/* DeviceInstanceRangeLowLimit Optional */
		fUnsignedTag (tvb, tree, offset, "DeviceInstanceRangeLowLimit: ", lvt);
		break;
	case 1:	/* DeviceInstanceRangeHighLimit Optional but required if DeviceInstanceRangeLowLimit is there */
		fUnsignedTag (tvb, tree, offset, "DeviceInstanceRangeHighLimit: ", lvt);
		break;
	default:
		return;
		break;
	}
 	fWhoIs (tvb, pinfo, tree, offset);
}

void
fUnconfirmedTags (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset, gint service_choice)
{
	guint8 offs, tag_no, class_tag;
	guint64 lvt;

	if (*offset >= tvb_reported_length(tvb))
		return;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	switch (service_choice) {
	case 0:	/* I-Am-Request */
		fIAm (tvb, tree, offset); /* offset changes his value on return */
		break;
	case 1: /* i-Have Request */
		fIHave (tvb, tree, offset); /* offset changes his value on return */
	break;
	case 2: /* unconfirmedCOVNotification */
		fCOVNotification (tvb, pinfo, tree, offset); /* offset changes his value on return */
		break;
	case 3: /* unconfirmedEventNotification */
		fEventNotification (tvb, pinfo, tree, offset); /* offset changes his value on return */
		break;
	case 4: /* unconfirmedPrivateTransfer */
		fPrivateTransfer (tvb, pinfo, tree, offset); /* offset changes his value on return */
		break;
	case 5: /* unconfirmedTextMessage */
		fTextMessage (tvb, pinfo, tree, offset); /* offset changes his value on return */
		break;
	case 6: /* timeSynchronization */
		fTimeSynchronization (tvb, tree, offset); /* offset changes his value on return */
		break;
	case 7: /* who-Has */
		fWhoHas (tvb, pinfo, tree, offset); /* offset changes his value on return */
		break;
	case 8: /* who-Is */
		fWhoIs (tvb, pinfo, tree, offset); /* offset changes his value on return */
		break;
	case 9: /* utcTimeSynchronization */
		fUTCTimeSynchronization (tvb, tree, offset); /* offset changes his value on return */
		break;
	default:
		break;
	}
}

void
fConfirmedServiceRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{	/* BACnet-Confirmed-Request */
	/* ASHRAE 135-2001 20.1.2 */

	proto_item *tc, *tt, *ti;
	proto_tree *bacapp_tree, *bacapp_tree_control, *bacapp_tree_tag;
	gint tmp, bacapp_type, service_choice;

	tmp = (gint) tvb_get_guint8(tvb, (*offset));
	bacapp_type = (tmp >> 4) & 0x0f;
	bacapp_flags = tmp & 0x0f;

	service_choice = (gint) tvb_get_guint8(tvb, (*offset)+3);
	if (bacapp_flags & 0x08)
		service_choice = (gint) tvb_get_guint8(tvb, (*offset)+5);


	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_str(pinfo->cinfo, COL_INFO, val_to_str(service_choice, bacapp_confirmed_service_choice, "Reserved by ASHRAE"));

	if (tree) {

		ti = proto_tree_add_item(tree, proto_bacapp, tvb, (*offset), -1, FALSE);
		bacapp_tree = proto_item_add_subtree(ti, ett_bacapp);

		tc = proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, (*offset), 1, TRUE);
		bacapp_tree_control = proto_item_add_subtree(tc, ett_bacapp);

		proto_tree_add_item(bacapp_tree_control, hf_bacapp_SEG, tvb, (*offset), 1, TRUE);
		proto_tree_add_item(bacapp_tree_control, hf_bacapp_MOR, tvb, (*offset), 1, TRUE);
		proto_tree_add_item(bacapp_tree_control, hf_bacapp_SA, tvb, (*offset)++, 1, TRUE);
		proto_tree_add_item(bacapp_tree_control, hf_bacapp_response_segments, tvb,
			                (*offset), 1, TRUE);
		proto_tree_add_item(bacapp_tree_control, hf_bacapp_max_adpu_size, tvb,
							(*offset), 1, TRUE);
		(*offset) ++;
		proto_tree_add_item(bacapp_tree, hf_bacapp_invoke_id, tvb,	(*offset)++, 1, TRUE);
		if (bacapp_flags & 0x08) {
			bacapp_seq = tvb_get_guint8(tvb, (*offset));
			proto_tree_add_item(bacapp_tree_control, hf_bacapp_sequence_number, tvb,
				(*offset)++, 1, TRUE);
			proto_tree_add_item(bacapp_tree_control, hf_bacapp_window_size, tvb,
				(*offset)++, 1, TRUE);
		}
		tmp = tvb_get_guint8(tvb, (*offset));
		proto_tree_add_item(bacapp_tree, hf_bacapp_service, tvb,
			(*offset)++, 1, TRUE);
		tt = proto_tree_add_item(bacapp_tree, hf_bacapp_vpart, tvb,
			(*offset), 0, TRUE);
		/* Service Request follows... Variable Encoding 20.2ff */
		bacapp_tree_tag = proto_item_add_subtree(tt, ett_bacapp_tag);
		fTagRequests (tvb, pinfo, bacapp_tree_tag, offset, tmp); /* (*offset) changes his value on return */
	}
}

void
fUnconfirmedServiceRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{	/* BACnet-Unconfirmed-Request-PDU */
	/* ASHRAE 135-2001 20.1.3 */

	proto_item *tt, *ti;
	proto_tree *bacapp_tree_tag, *bacapp_tree;
	gint tmp;

	tmp = tvb_get_guint8(tvb, (*offset)+1);
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_str(pinfo->cinfo, COL_INFO, val_to_str(tmp, BACnetUnconfirmedServiceRequest, "Reserved by ASHRAE"));

	if (tree) {
		ti = proto_tree_add_item(tree, proto_bacapp, tvb, (*offset), -1, FALSE);
		bacapp_tree = proto_item_add_subtree(ti, ett_bacapp);

		proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, (*offset)++, 1, TRUE);

		tmp = tvb_get_guint8(tvb, (*offset));
		tt = proto_tree_add_item(bacapp_tree, hf_bacapp_uservice, tvb,
				(*offset)++, 1, TRUE);
		/* Service Request follows... Variable Encoding 20.2ff */
		bacapp_tree_tag = proto_item_add_subtree(tt, ett_bacapp_tag);
		fUnconfirmedTags (tvb, pinfo, bacapp_tree_tag, offset, tmp); /* (*offset) changes his value on return */
	}
}

void
fSimpleAcknowledge(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{	/* BACnet-Simple-Ack-PDU */
	/* ASHRAE 135-2001 20.1.4 */

	proto_item *tc, *ti;
	gint tmp;
	proto_tree *bacapp_tree;

	tmp = tvb_get_guint8(tvb, (*offset)+2);
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_str(pinfo->cinfo, COL_INFO, val_to_str(tmp, bacapp_confirmed_service_choice, "Reserved by ASHRAE"));

	if (tree) {
		ti = proto_tree_add_item(tree, proto_bacapp, tvb, (*offset), -1, FALSE);
		bacapp_tree = proto_item_add_subtree(ti, ett_bacapp);

		tc = proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, (*offset)++, 1, TRUE);

		proto_tree_add_item(bacapp_tree, hf_bacapp_invoke_id, tvb,
			(*offset)++, 1, TRUE);
		proto_tree_add_item(bacapp_tree, hf_bacapp_service, tvb,
			(*offset)++, 1, TRUE);
	}
}

void
fComplexAcknowledge(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{	/* BACnet-Complex-Ack-PDU */
	/* ASHRAE 135-2001 20.1.5 */

	proto_item *tc, *tt, *ti;
	proto_tree *bacapp_tree, *bacapp_tree_control, *bacapp_tree_tag;
	gint tmp, bacapp_type;

	tmp = (gint) tvb_get_guint8(tvb, (*offset));
	bacapp_type = (tmp >> 4) & 0x0f;
	bacapp_flags = tmp & 0x0f;

	tmp = tvb_get_guint8(tvb, (*offset)+2);
	if (bacapp_flags & 0x08)
		tmp = tvb_get_guint8(tvb, (*offset)+4);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_str(pinfo->cinfo, COL_INFO, val_to_str(tmp, bacapp_confirmed_service_choice, "Reserved by ASHRAE"));

	if (tree) {

		ti = proto_tree_add_item(tree, proto_bacapp, tvb, (*offset), -1, FALSE);
		bacapp_tree = proto_item_add_subtree(ti, ett_bacapp);

		tc = proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, (*offset), 1, TRUE);
		bacapp_tree_control = proto_item_add_subtree(tc, ett_bacapp);

		proto_tree_add_item(bacapp_tree, hf_bacapp_SEG, tvb, (*offset), 1, TRUE);
		proto_tree_add_item(bacapp_tree, hf_bacapp_MOR, tvb, (*offset)++, 1, TRUE);
		proto_tree_add_item(bacapp_tree, hf_bacapp_invoke_id, tvb,
			(*offset)++, 1, TRUE);
		if (bacapp_flags & 0x08) {
			bacapp_seq = tvb_get_guint8(tvb, (*offset));
			proto_tree_add_item(bacapp_tree, hf_bacapp_sequence_number, tvb,
				(*offset)++, 1, TRUE);
			proto_tree_add_item(bacapp_tree, hf_bacapp_window_size, tvb,
				(*offset)++, 1, TRUE);
		}
		tmp = tvb_get_guint8(tvb, (*offset));
		tt = proto_tree_add_item(bacapp_tree, hf_bacapp_service, tvb,
			(*offset)++, 1, TRUE);
		/* Service ACK follows... */
		bacapp_tree_tag = proto_item_add_subtree(tt, ett_bacapp_tag);
		fTags (tvb, pinfo, bacapp_tree_tag, offset, tmp); /* (*offset) changes his value on return */
	}
}


void
fSegmentedAcknowledge(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{	/* BACnet-SegmentAck-PDU */
	/* ASHRAE 135-2001 20.1.6 */

	proto_item *tc, *ti;
	proto_tree *bacapp_tree_control, *bacapp_tree;

	if (tree) {
		ti = proto_tree_add_item(tree, proto_bacapp, tvb, (*offset), -1, FALSE);
		bacapp_tree = proto_item_add_subtree(ti, ett_bacapp);

		tc = proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, (*offset), 1, TRUE);
		bacapp_tree_control = proto_item_add_subtree(tc, ett_bacapp);

		proto_tree_add_item(bacapp_tree, hf_bacapp_NAK, tvb, (*offset), 1, TRUE);
		proto_tree_add_item(bacapp_tree, hf_bacapp_SRV, tvb, (*offset)++, 1, TRUE);
		proto_tree_add_item(bacapp_tree, hf_bacapp_invoke_id, tvb,
			(*offset)++, 1, TRUE);
		proto_tree_add_item(bacapp_tree, hf_bacapp_sequence_number, tvb,
				(*offset)++, 1, TRUE);
		proto_tree_add_item(bacapp_tree, hf_bacapp_window_size, tvb,
				(*offset)++, 1, TRUE);
	}
}

void
fError(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{	/* BACnet-Error-PDU */
	/* ASHRAE 135-2001 20.1.7 */

	proto_item *tc, *ti;
	proto_tree *bacapp_tree_control, *bacapp_tree;

	if (tree) {
		ti = proto_tree_add_item(tree, proto_bacapp, tvb, (*offset), -1, FALSE);
		bacapp_tree = proto_item_add_subtree(ti, ett_bacapp);

		tc = proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, (*offset)++, 1, TRUE);
		bacapp_tree_control = proto_item_add_subtree(tc, ett_bacapp);

		proto_tree_add_item(bacapp_tree, hf_bacapp_invoke_id, tvb,
			(*offset)++, 1, TRUE);
		proto_tree_add_item(bacapp_tree, hf_bacapp_service, tvb,
			(*offset)++, 1, TRUE);
		/* Error Code follows */
		fApplicationTags (tvb, bacapp_tree, offset, "   errorClass: ", bacapp_errorClass);
		fApplicationTags (tvb, bacapp_tree, offset, "   errorCode: ", bacapp_error_code);

	}
}

void
fReject(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{	/* BACnet-Reject-PDU */
	/* ASHRAE 135-2001 20.1.8 */

	proto_item *tc, *ti;
	proto_tree *bacapp_tree_control, *bacapp_tree;

	if (tree) {
		ti = proto_tree_add_item(tree, proto_bacapp, tvb, (*offset), -1, FALSE);
		bacapp_tree = proto_item_add_subtree(ti, ett_bacapp);

		tc = proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, (*offset)++, 1, TRUE);
		bacapp_tree_control = proto_item_add_subtree(tc, ett_bacapp);

		proto_tree_add_item(bacapp_tree, hf_bacapp_invoke_id, tvb,
			(*offset)++, 1, TRUE);
		proto_tree_add_item(bacapp_tree, hf_bacapp_reject_reason, tvb,
			(*offset)++, 1, TRUE);
	}
}

void
dissect_bacapp_abort(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{	/* BACnet-Abort-PDU */
	/* ASHRAE 135-2001 20.1.9 */

	proto_item *tc, *ti;
	proto_tree *bacapp_tree_control, *bacapp_tree;

	if (tree) {
		ti = proto_tree_add_item(tree, proto_bacapp, tvb, (*offset), -1, FALSE);
		bacapp_tree = proto_item_add_subtree(ti, ett_bacapp);

		tc = proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, (*offset), 1, TRUE);
		bacapp_tree_control = proto_item_add_subtree(tc, ett_bacapp);

		proto_tree_add_item(bacapp_tree, hf_bacapp_SRV, tvb, (*offset)++, 1, TRUE);
		proto_tree_add_item(bacapp_tree, hf_bacapp_invoke_id, tvb,
			(*offset)++, 1, TRUE);
		proto_tree_add_item(bacapp_tree, hf_bacapp_abort_reason, tvb,
			(*offset)++, 1, TRUE);
	}
}

void
dissect_bacapp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint tmp, bacapp_type;
	tvbuff_t *next_tvb;
	guint offset = 0;

	tmp = (gint) tvb_get_guint8(tvb, 0);
	bacapp_type = (tmp >> 4) & 0x0f;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, val_to_str(bacapp_type, bacapp_type_name, "#### unknown APDU ##### "));

	/* ASHRAE 135-2001 20.1.1 */
	switch (bacapp_type) {
	case 0:	/* BACnet-Confirmed-Service-Request */
		fConfirmedServiceRequest(tvb, pinfo, tree, &offset);	/* offset will be modified */
		break;
	case 1:	/* BACnet-Unconfirmed-Request-PDU */
		fUnconfirmedServiceRequest(tvb, pinfo, tree, &offset);	/* offset will be modified */
		break;
	case 2:	/* BACnet-Simple-Ack-PDU */
		fSimpleAcknowledge(tvb, pinfo, tree, &offset);	/* offset will be modified */
		break;
	case 3:	/* BACnet-Complex-Ack-PDU */
		fComplexAcknowledge(tvb, pinfo, tree, &offset);	/* offset will be modified */
		break;
	case 4:	/* BACnet-SegmentAck-PDU */
		fSegmentedAcknowledge(tvb, tree, &offset);	/* offset will be modified */
		break;
	case 5:	/* BACnet-Error-PDU */
		fError(tvb, tree, &offset);	/* offset will be modified */
		break;
	case 6:	/* BACnet-Reject-PDU */
		fReject(tvb, tree, &offset);	/* offset will be modified */
		break;
	case 7:	/* BACnet-Abort-PDU */
		dissect_bacapp_abort(tvb, tree, &offset);	/* offset will be modified */
		break;
	}

	next_tvb = tvb_new_subset(tvb,offset,-1,-1);
	call_dissector(data_handle,next_tvb, pinfo, tree);
}

void
proto_register_bacapp(void)
{
	static hf_register_info hf[] = {
		{ &hf_bacapp_type,
			{ "APDU Type",           "bacapp.bacapp_type",
			FT_UINT8, BASE_DEC, VALS(bacapp_type_name), 0xf0, "APDU Type", HFILL }
		},
		{ &hf_bacapp_SEG,
			{ "SEG",           "bacapp.bacapp_type.SEG",
			FT_BOOLEAN, 8, TFS(&segments_follow), 0x08, "Segmented Requests", HFILL }
		},
		{ &hf_bacapp_MOR,
			{ "MOR",           "bacapp.bacapp_type.MOR",
			FT_BOOLEAN, 8, TFS(&more_follow), 0x04, "More Segments Follow", HFILL }
		},
		{ &hf_bacapp_SA,
			{ "SA",           "bacapp.bacapp_type.SA",
			FT_BOOLEAN, 8, TFS(&segmented_accept), 0x02, "Segmented Response accepted", HFILL }
		},
		{ &hf_bacapp_max_adpu_size,
			{ "Size of Maximum ADPU accepted",           "bacapp.bacapp_max_adpu_size",
			FT_UINT8, BASE_DEC, VALS(bacapp_max_APDU_length_accepted), 0x0f, "Size of Maximum ADPU accepted", HFILL }
		},
		{ &hf_bacapp_response_segments,
			{ "Max Response Segments accepted",           "bacapp.bacapp_response_segments",
			FT_UINT8, BASE_DEC, VALS(bacapp_max_segments_accepted), 0xe0, "Max Response Segments accepted", HFILL }
		},
		{ &hf_bacapp_invoke_id,
			{ "Invoke ID",           "bacapp.bacapp_invoke_id",
			FT_UINT8, BASE_HEX, NULL, 0, "Invoke ID", HFILL }
		},
		{ &hf_bacapp_sequence_number,
			{ "Sequence Number",           "bacapp.bacapp_sequence_number",
			FT_UINT8, BASE_DEC, NULL, 0, "Sequence Number", HFILL }
		},
		{ &hf_bacapp_window_size,
			{ "Proposed Window Size",           "bacapp.bacapp_window_size",
			FT_UINT8, BASE_DEC, NULL, 0, "Proposed Window Size", HFILL }
		},
		{ &hf_bacapp_service,
			{ "Service Choice",           "bacapp.bacapp_service",
			FT_UINT8, BASE_DEC, VALS(bacapp_confirmed_service_choice), 0x00, "Service Choice", HFILL }
		},
		{ &hf_bacapp_uservice,
			{ "Unconfirmed Service Choice",           "bacapp.bacapp_unconfirmed_service",
			FT_UINT8, BASE_DEC, VALS(BACnetUnconfirmedServiceChoice), 0x00, "Unconfirmed Service Choice", HFILL }
		},
		{ &hf_bacapp_NAK,
			{ "NAK",           "bacapp.bacapp_type.NAK",
			FT_BOOLEAN, 8, NULL, 0x02, "negativ ACK", HFILL }
		},
		{ &hf_bacapp_SRV,
			{ "SRV",           "bacapp.bacapp_type.SRV",
			FT_BOOLEAN, 8, NULL, 0x01, "Server", HFILL }
		},
		{ &hf_bacapp_reject_reason,
			{ "Reject Reason",           "bacapp.bacapp_reject_reason",
			FT_UINT8, BASE_DEC, VALS(bacapp_reject_reason), 0x00, "Reject Reason", HFILL }
		},
		{ &hf_bacapp_abort_reason,
			{ "Abort Reason",           "bacapp.bacapp_abort_reason",
			FT_UINT8, BASE_DEC, VALS(bacapp_abort_reason), 0x00, "Abort Reason", HFILL }
		},
		{ &hf_bacapp_vpart,
			{ "BACnet APDU variable part:",           "bacapp.variable_part",
			FT_NONE, 0, NULL, 00, "BACnet APDU varaiable part:", HFILL }
		},
		{ &hf_bacapp_tag_number,
			{ "Tag Number",           "bacapp.bacapp_tag.number",
			FT_UINT8, BASE_DEC, VALS(bacapp_tag_number), 0xF0, "Tag Number", HFILL }
		},
		{ &hf_bacapp_tag_class,
			{ "Class",           "bacapp.bacapp_tag.class",
			FT_BOOLEAN, 8, TFS(&bacapp_tag_class), 0x08, "Class", HFILL }
		},
		{ &hf_bacapp_tag_lvt,
			{ "Length Value Type",           "bacapp.bacapp_tag.lvt",
			FT_UINT8, BASE_DEC, NULL, 0x07, "Length Value Type", HFILL }
		},
/*		{ &hf_bacapp_initiatingObject,
			{ "initiating Object Identifier:",           "bacapp.initiatingObject",
			FT_NONE, 0, NULL, 0x00, "BACnet APDU InitiatingObject:", HFILL }
		},
		{ &hf_bacapp_monitoredObject,
			{ "monitored Object Identifier:",           "bacapp.monitoredObject",
			FT_NONE, 0, NULL, 0x00, "BACnet APDU MonitoredObject:", HFILL }
		},
*/		{ &hf_bacapp_tag_ProcessId,
			{ "subscriberProcessIdentifier",           "bacapp.bacapp_tag.ProcessId",
			FT_UINT32, BASE_DEC, NULL, 0, "subscriberProcessIdentifier", HFILL }
		},
		{ &hf_bacapp_tag_initiatingObjectType,
			{ "ObjectType",           "bacapp.bacapp_tag.ObjectType",
			FT_UINT16, BASE_DEC, VALS(bacapp_object_type), 0x00, "ObjectType", HFILL }
		},
/*		{ &hf_bacapp_tag_initiatingObjectId,
			{ "instance Number",           "bacapp.bacapp_tag.ObjectId",
			FT_UINT24, BASE_DEC, NULL, 0, "instance Number", HFILL }
		},
		{ &hf_bacapp_tag_null,
			{ "   Value -  NULL",           "bacapp.bacapp_tag.null",
			FT_UINT8, BASE_HEX, NULL, 0x07, "Application Tag NULL", HFILL }
		},
		{ &hf_bacapp_tag_boolean,
			{ "   Value - Boolean",           "bacapp.bacapp_tag.boolean",
			FT_BOOLEAN, 8, NULL, 0x07, "Application Tag Boolean", HFILL }
		},
		{ &hf_bacapp_tag_uint8,
			{ "   Value - Unsigned Integer",           "bacapp.bacapp_tag.uint8",
			FT_UINT8, BASE_DEC, NULL, 0, "Unsigned Integer", HFILL }
		},
		{ &hf_bacapp_tag_uint16,
			{ "   Value - Unsigned Integer",           "bacapp.bacapp_tag.uint16",
			FT_UINT16, BASE_DEC, NULL, 0, "Unsigned Integer", HFILL }
		},
		{ &hf_bacapp_tag_uint32,
			{ "   Value - Unsigned Integer",           "bacapp.bacapp_tag.uint32",
			FT_UINT32, BASE_DEC, NULL, 0, "Unsigned Integer", HFILL }
		},
		{ &hf_bacapp_tag_uint64,
			{ "   Value - Unsigned Integer",           "bacapp.bacapp_tag.uint64",
			FT_UINT64, BASE_DEC, NULL, 0, "Unsigned Integer", HFILL }
		},
		{ &hf_bacapp_tag_sint8,
			{ "   Value - Signed Integer",           "bacapp.bacapp_tag.sint8",
			FT_INT8, BASE_DEC, NULL, 0, "Signed Integer", HFILL }
		},
		{ &hf_bacapp_tag_sint16,
			{ "   Value - Signed Integer",           "bacapp.bacapp_tag.sint16",
			FT_INT16, BASE_DEC, NULL, 0, "Signed Integer", HFILL }
		},
		{ &hf_bacapp_tag_sint32,
			{ "   Value - Signed Integer",           "bacapp.bacapp_tag.sint32",
			FT_INT32, BASE_DEC, NULL, 0, "Signed Integer", HFILL }
		},
		{ &hf_bacapp_tag_sint64,
			{ "   Value - Signed Integer",           "bacapp.bacapp_tag.sint64",
			FT_INT64, BASE_DEC, NULL, 0, "Signed Integer", HFILL }
		},
		{ &hf_bacapp_tag_real,
			{ "   Value - REAL",           "bacapp.bacapp_tag.real",
			FT_FLOAT, BASE_DEC, NULL, 0, "Real (Floating Point)", HFILL }
		},
		{ &hf_bacapp_tag_double,
			{ "   Value - DOUBLE",           "bacapp.bacapp_tag.double",
			FT_DOUBLE, BASE_DEC, NULL, 0, "Double (Double Precision Floating Point)", HFILL }
		},
		{ &hf_bacapp_tag_timeRemaining,
			{ "time remaining (seconds)",           "bacapp.bacapp_tag.timeRemaining",
			FT_UINT64, BASE_DEC, NULL, 0, "time remaining (seconds)", HFILL }
		},
		{ &hf_bacapp_tag_string,
			{ "   Value - String",           "bacapp.bacapp_tag.string",
			FT_STRING, BASE_DEC, NULL, 0, "String", HFILL }
		},
		{ &hf_bacapp_tag_bytes,
			{ "   Value - Bytes",           "bacapp.bacapp_tag.bytes",
			FT_BYTES, BASE_DEC, NULL, 0, "Bytes", HFILL }
		},
		{ &hf_bacapp_tag_character_set,
			{ "   Value - String Character Set",           "bacapp.bacapp_tag.character_set",
			FT_UINT8, BASE_DEC, bacapp_character_set, 0, "Bytes", HFILL }
		},
		{ &hf_bacapp_error_code,
			{ "Error Code",           "bacapp.bacapp_code",
			FT_UINT8, BASE_DEC, VALS(bacapp_error_code), 0x00, "Error Code", HFILL }
		},
*/
	};
	static gint *ett[] = {
		&ett_bacapp,
		&ett_bacapp_control,
		&ett_bacapp_tag,
	};
	proto_bacapp = proto_register_protocol("Building Automation and Control Network APDU",
	    "BACapp", "bacapp");

	proto_register_field_array(proto_bacapp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("bacapp", dissect_bacapp, proto_bacapp);
}

void
proto_reg_handoff_bacapp(void)
{
	data_handle = find_dissector("data");
}
