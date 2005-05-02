/* packet-bacapp.c
 * Routines for BACnet (APDU) dissection
 * Copyright 2001, Hartmut Mueller <hartmut@abmlinux.org>, FH Dortmund
 * Enhanced by Steve Karg, 2005, <skarg@users.sourceforge.net>
 * Enhanced by Herbert Lischka, 2005, <lischka@kieback-peter.de>, Berlin
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include "packet-bacapp.h"


static const char *bacapp_unknown_service_str = "unknown service";

static const value_string
BACnetTypeName[] = {
	{0, "Confirmed-Request "},
	{1, "Unconfirmed-Request "},
	{2, "SimpleACK "},
	{3, "ComplexACK "},
	{4, "SegmentACK "},
	{5, "Error "},
	{6, "Reject "},
	{7, "Abort "},
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
	{5,"Up to 1476 octets (fits in Ethernet II frame)"},
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
	{10,"reserved by ASHRAE"},
	{11,"reserved by ASHRAE"},
	{12,"reserved by ASHRAE"},
	{13,"reserved by ASHRAE"},
	{14,"reserved by ASHRAE"},
	{15,"reserved by ASHRAE"},
	{0,NULL}
};

static const value_string
BACnetTagNumber [] = {
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

static const value_string
BACnetAbortReason [] = {
	{0,"other"},
	{1,"buffer-overflow"},
	{2,"invalid-apdu-in-this-state"},
	{3,"preempted-by-higher-priority-task"},
	{4,"segmentation-not-supported"},
	{5,"reserved by ASHRAE"},
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
	{11,"enabledt"},
	{12,"disabled"},
	{13,"atomic-release-disabled"},
	{14,"default"},
	{0,NULL}
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
	{7,"reserved by ASHRAE"},
	{0,NULL}
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
	{256,"not known"},
	{0,NULL}
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
	{0,"analog-input object"},
	{1,"analog-output object"},
	{2,"analog-value object"},
	{3,"binary-input object"},
	{4,"binary-output object"},
	{5,"binary-value object"},
	{6,"calendar object"},
	{7,"command object"},
	{8,"device object"},
	{9,"event-enrollment object"},
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
BACnetUnits [] = {
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
	{13,"Megavolt Amperes Ractive"},
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
	{28,"Gramms Of Water Per Kilogram Dry Air"},
	{29,"Relative Humidity"},
	{30,"Millimeters"},
	{31,"Meters"},
	{32,"Inches"},
	{33,"Feed"},
	{34,"Watts Per Sq Foot"},
	{35,"Watts Per Sq meter"},
	{36,"Lumens"},
	{37,"Lux"},
	{38,"Foot Candels"},
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
	{63,"Degress Kelvin"},
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
	{256,"Kelvin Per Minute"},
	{257,"Minute Per Kelvin"},
	{258,"Kelvin Per Hour"},
	{0,NULL}
};

static const value_string
BACnetErrorCode [] = {
	{0,"other"},
	{1,"authentication-failed"},
	{2,"character-set-not-supported"},
	{3,"configuration-in-progress"},
	{4,"device-busy"},
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
	{45,"optional-functionaltity-not-supported"},
	{46,"invalid-configuration-data"},
	{47,"reserved by ASHRAE"},
	{0, NULL}
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
	{9,"all-write-successfull"},
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
BACnetBinaryPV [] = {
	{0,"inactive"},
	{1,"active"},
	{0,NULL}
};


static const value_string
BACnetCharacterSet [] = {
	{0,"ANSI X3.4"},
	{1,"IBM/Microsoft DBCS"},
	{2,"JIS C 6226"},
	{3,"ISO 10646(UCS-4)"},
	{4,"ISO 10646(UCS-2)"},
	{5,"ISO 18859-1"},
	{0,NULL}
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
	{0,"and"},
	{1,"or"},
	{2,"all"},
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
	{0,"normal"},
	{1,"urgent"},
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

static const value_string
days [] = {
	{1,"Monday" },
	{2,"Tuesday" },
	{3,"Wednesday" },
	{4,"Thursday" },
	{5,"Friday" },
	{6,"Saturday" },
	{7,"Sunday" },
	{255,"any day of week" },
	{0,NULL },
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
	{0,NULL },
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
	{0,NULL },
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
	{0,NULL },
};

static const value_string
BACnetEventState [] = {
	{0,"normal" },
	{1,"fault" },
	{2,"offnormal" },
	{3,"high-limit" },
	{4,"low-limit" },
	{5,"life-safety-alarm" },
	{0,NULL },
};

static const value_string
BACnetLogStatus [] = {
	{0,"log-disabled" },
	{1,"buffer-purged" },
	{0,NULL },
};

static const value_string
BACnetMaintenance [] = {
	{0,"none" },
	{1,"periodic-test" },
	{2,"need-service-operational" },
	{3,"need-service-inoperative" },
	{0,NULL },
};

static const value_string
BACnetNotifyType [] = {
	{0,"alarm" },
	{1,"event" },
	{2,"ack-notification" },
	{0,NULL },
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
	{0,NULL}
};

static const value_string
BACnetProgramError [] = {
	{0,"normal"},
	{1,"load-failed"},
	{2,"internal"},
	{3,"program"},
	{4,"other"},
	{0,NULL}
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


static int proto_bacapp = -1;
static int hf_bacapp_type = -1;
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
static int hf_BACnetRejectReason = -1;
static int hf_BACnetAbortReason = -1;
static int hf_BACnetTagNumber = -1;
static int hf_BACnetTagClass = -1;
static int hf_bacapp_tag_lvt = -1;
static int hf_bacapp_tag_ProcessId = -1;
static int hf_bacapp_tag_initiatingObjectType = -1;
static int hf_bacapp_vpart = -1;

static int hf_bacapp_uservice = -1;


static gint ett_bacapp = -1;
static gint ett_bacapp_control = -1;
static gint ett_bacapp_tag = -1;
static gint ett_bacapp_list = -1;
static gint ett_bacapp_value = -1;

static dissector_handle_t data_handle;

static gint32 propertyIdentifier = -1;

static guint8 bacapp_flags = 0;
static guint8 bacapp_seq = 0;

static guint
fTagNo (tvbuff_t *tvb, guint offset)
{
	return (guint)(tvb_get_guint8(tvb, offset) >> 4);
}

static guint
fTagHeader (tvbuff_t *tvb, guint offset, guint8 *tag_no, guint8* class_tag, guint32 *lvt)
{
	guint8 tmp;
	guint offs = 1;

	tmp = tvb_get_guint8(tvb, offset);
	*class_tag = tmp & 0x08; /* 0 = Application Tag, 1 = Context Specific Tag */
	*lvt = tmp & 0x07;
	*tag_no = tmp >> 4;
	if (*tag_no == 15) { /* B'1111' because of extended tagnumber */
		*tag_no = tvb_get_guint8(tvb, offset + offs++);
	}
	if (*lvt == 5) {       /* length is more than 4 Bytes */
		*lvt = tvb_get_guint8(tvb, offset + offs++);
		if (*lvt == 254) { /* length is encoded with 16 Bits */
			*lvt = tvb_get_guint8(tvb, offset + offs++);
			*lvt = (*lvt << 8) + tvb_get_guint8(tvb, offset + offs++);
		} else {
            if (*lvt == 255) { /* length is encoded with 32 Bits */
			*lvt = tvb_get_guint8(tvb, offset + offs++);
			*lvt = (*lvt << 8) + tvb_get_guint8(tvb, offset + offs++);
			*lvt = (*lvt << 8) + tvb_get_guint8(tvb, offset + offs++);
			*lvt = (*lvt << 8) + tvb_get_guint8(tvb, offset + offs++);
            }
        }
	}

	return offs;
}

static guint
fUnsignedTag (tvbuff_t *tvb, proto_tree *tree, guint offset, guint8 *label)
{
	guint8 tmp;
	guint64 val = 0;
	guint8 tag_no, class_tag;
	guint32 lvt, i;
    guint offs;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
	for (i = 0; i < min(lvt,8); i++) {
		tmp = tvb_get_guint8(tvb, offset+offs+i);
		val = (val << 8) + tmp;
	}
	proto_tree_add_text(tree, tvb, offset, min(lvt,8)+offs, "%s(Unsigned) %" PRIu64, LABEL(label), val);
	return offset+offs+min(lvt,8);
}

static guint
fSignedTag (tvbuff_t *tvb, proto_tree *tree, guint offset, guint8 *label)
{
	guint8 tmp;
	guint64 val = 0;
	guint8 tag_no, class_tag;
	guint32 lvt, i;
    guint offs;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
	for (i = 0; i < min(lvt,8); i++) {
		tmp = tvb_get_guint8(tvb, offset+offs+i);
		val = (val << 8) + tmp;
	}
	proto_tree_add_text(tree, tvb, offset, min(lvt,8)+offs, "%s(Signed) %" PRId64, LABEL(label), (gint64) val);
	return offset+offs+min(lvt,8);
}

static guint
fProcessId (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint8 tmp;
	guint32 val = 0, lvt, i;
	guint8 tag_no, class_tag;
    guint offs;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	for (i = 0; i < min(lvt, 4); i++) {
			tmp = tvb_get_guint8(tvb, offset+offs+i);
			val = (val << 8) + tmp;
	}
	
	proto_tree_add_uint(tree, hf_bacapp_tag_ProcessId, tvb, offset, offs+i, val);
	return offset+offs+i;
}

static guint
fTimeSpan (tvbuff_t *tvb, proto_tree *tree, guint offset, guint8 *label)
{
	guint8 tmp;
	guint val = 0;
	guint32 lvt, i;
	guint8 tag_no, class_tag;
    guint offs;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	for (i = 0; i < min(lvt, 4); i++) {
		tmp = tvb_get_guint8(tvb, offset+offs+i);
		val = (val << 8) + tmp;
	}
	proto_tree_add_text(tree, tvb, offset, i+offs, "%s (hh.mm.ss): %d.%02d.%02d%s", LABEL(label), (val / 3600), ((val % 3600) / 60), (val % 60), val == 0 ? " (indefinite)" : "");
	return offset+offs+i;
}

static guint
fWeekNDay (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint32 month, weekOfMonth, dayOfWeek;
	guint8 tag_no, class_tag;
	guint32 lvt;
    guint offs;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
	month = tvb_get_guint8(tvb, offset+offs);
	weekOfMonth = tvb_get_guint8(tvb, offset+offs+1);
	dayOfWeek = tvb_get_guint8(tvb, offset+offs+2);
	proto_tree_add_text(tree, tvb, offset, lvt+offs, "%s %s, %s", 
                        val_to_str(month, months, "month (%d) not found"), 
                        val_to_str(weekOfMonth, weekofmonth, "week of month (%d) not found"), 
                        val_to_str(dayOfWeek, days, "day of week (%d) not found"));
	return offset+offs+lvt;
}

static guint
fDate    (tvbuff_t *tvb, proto_tree *tree, guint offset, guint8 *label)
{
	guint32 year, month, day, weekday;
	guint8 tag_no, class_tag;
	guint32 lvt;
    guint offs;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
	year = tvb_get_guint8(tvb, offset+offs) + 1900;
	month = tvb_get_guint8(tvb, offset+offs+1);
	day = tvb_get_guint8(tvb, offset+offs+2);
	weekday = tvb_get_guint8(tvb, offset+offs+3);
	if ((year == 255) && (day == 255) && (month == 255) && (weekday == 255))
		proto_tree_add_text(tree, tvb, offset, lvt+offs, "%sany", LABEL(label));
	else
		proto_tree_add_text(tree, tvb, offset, lvt+offs, "%s%s %d, %d, (Day of Week = %s)", 
                            LABEL(label), val_to_str(month, months, "month (%d) not found"), 
                            day, year, val_to_str(weekday, days, "(%d) not found"));
	return offset+offs+lvt;
}

static guint
fTime (tvbuff_t *tvb, proto_tree *tree, guint offset, guint8 *label)
{
	guint32 year, month, day, weekday, lvt;
	guint8 tag_no, class_tag;
	guint offs;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
	year = tvb_get_guint8(tvb, offset+offs);
	month = tvb_get_guint8(tvb, offset+offs+1);
	day = tvb_get_guint8(tvb, offset+offs+2);
	weekday = tvb_get_guint8(tvb, offset+offs+3);
	if ((year == 255) && (day == 255) && (month == 255) && (weekday == 255))
		proto_tree_add_text(tree, tvb, offset, lvt+offs, "%sany", LABEL(label));
	else
		proto_tree_add_text(tree, tvb, offset, lvt+offs, "%s%d:%02d:%02d.%d %s = %02d:%02d:%02d.%d", LABEL(label), year > 12 ? year -12 : year, month, day, weekday, year > 12 ? "P.M." : "A.M.", year, month, day, weekday);
	return offset+offs+lvt;
}

static guint
fDateTime (tvbuff_t *tvb, proto_tree *tree, guint offset, guint8 *label)
{
	proto_tree *subtree = tree;
	proto_item *tt;

	if (label != NULL) {
		tt = proto_tree_add_text (subtree, tvb, offset, 1, "%s", LABEL(label));
		subtree = proto_item_add_subtree(tt, ett_bacapp_value);
	}
	offset = fDate    (tvb,subtree,offset,"Date: ");
	return fTime (tvb,subtree,offset,"Time: ");
}

static guint
fTimeValue (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;
	guint8 tag_no, class_tag;
	guint32 lvt;                               

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
        if (((lvt == 7) && class_tag)) {   /* closing Tag, but not for me */
            return offset;
        }
		offset = fTime    (tvb,tree,offset,"Time: ");
		offset = fApplicationTypes (tvb,tree,offset, "Value: ", NULL);
	}
	return offset;
}

static guint
fCalendaryEntry (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
	
		switch (fTagNo(tvb, offset)) {
		case 0:	/* Date */
			offset = fDate    (tvb, tree, offset, "Date: ");
			break;
		case 1:	/* dateRange */
			offset = fDateRange (tvb, tree, offset);
			break;
		case 2:	/* BACnetWeekNDay */
			offset = fWeekNDay (tvb, tree, offset);
			break;
		default:
			return offset;
			break;
		}
	}
	return offset;
}

static guint
fTimeStamp (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	if (offset < tvb_reported_length(tvb)) {	/* don't loop, it's a CHOICE */
	
		switch (fTagNo(tvb, offset)) {
		case 0:	/* time */
			offset = fTime    (tvb, tree, offset, "timestamp: ");
			break;
		case 1:	/* sequenceNumber */
			offset = fUnsignedTag (tvb, tree, offset, "sequence Number: ");
			break;
		case 2:	/* dateTime */
			offset = fDateTime (tvb, tree, offset, "timestamp: ");
			break;
		default:
			return offset;
			break;
		}
	}
	return offset;
}

static guint
fSetpointReference (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
	
		switch (fTagNo(tvb, offset)) {
		case 0:	/* setpointReference */
			offset = fObjectPropertyReference (tvb,tree,offset);
			break;
		default:
			return offset;
			break;
		}
	}
	return offset;
}


static guint
fClientCOV (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	if (offset < tvb_reported_length(tvb)) {
        offset = fApplicationTypes (tvb,tree,offset, "increment: ",NULL);
    }
    return offset;
}

static guint
fDestination (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	if (offset < tvb_reported_length(tvb)) {
        offset = fApplicationTypes (tvb,tree,offset, "valid Days: ", days);
        offset = fTime (tvb,tree,offset,"from time: ");
        offset = fTime (tvb,tree,offset,"to time: ");
        offset = fRecipient (tvb,tree,offset);
        offset = fProcessId (tvb,tree,offset);
        offset = fApplicationTypes (tvb,tree,offset,"issue confirmed notifications: ", NULL);
        offset = fApplicationTypes (tvb,tree,offset,"transitions: ", BACnetEventTransitionBits);
    }
    return offset;
}

static guint
fOctetString (tvbuff_t *tvb, proto_tree *tree, guint offset, guint8 *label, guint32 lvt)
{
	guint8 *str_val;
    guint len;

	if ((lvt == 0) || ((lvt+offset) > tvb_length(tvb)))
		lvt = tvb_length(tvb) - offset;

	proto_tree_add_text(tree, tvb, offset, lvt, "[displayed OctetString with %d Bytes:] %s", lvt, LABEL(label));

	do {
		len = min (lvt, 200);
		str_val = tvb_get_string(tvb, offset, len);
		proto_tree_add_text(tree, tvb, offset, len, "%s", str_val);
		g_free(str_val);
		lvt -= len;
		offset += len;
	} while (lvt > 0);

	if (tvb_length(tvb) < tvb_reported_length(tvb)) {
		proto_tree_add_text(tree, tvb, offset, tvb_reported_length(tvb) - tvb_length(tvb), "[Frame is %d Bytes shorter than expected]", tvb_reported_length(tvb) - tvb_length(tvb));
		str_val = tvb_get_string(tvb, offset, 1);
		g_free(str_val);
	}
	return offset;
}

static guint
fAddress (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint8 tag_no, class_tag;
	guint32 lvt;
    guint offs;

	offset = fUnsignedTag (tvb, tree, offset, "network-number");
	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
	if (lvt == 0) {
		proto_tree_add_text(tree, tvb, offset, offs, "mac-address: broadcast");
		offset += offs;
	} else
		offset = fOctetString (tvb, tree, offset, "mac-address: ", lvt);
	return offset;
}

static guint
fSessionKey (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	offset = fOctetString (tvb,tree,offset,"session key: ", 8);
	return fAddress (tvb,tree,offset);
}

static guint
fObjectIdentifier (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint8  tag_no, class_tag;
	guint32 lvt;
	guint offs;

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	proto_tree_add_item(tree, hf_bacapp_objectType, tvb, offset+offs, 4, FALSE);
	proto_tree_add_item(tree, hf_bacapp_instanceNumber, tvb, offset+offs, 4, FALSE);

	return offset+offs+4;
}

static guint
fRecipient (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
	
		switch (fTagNo(tvb, offset)) {
		case 0:	/* device */
			offset = fObjectIdentifier (tvb, tree, offset);
			break;
		case 1:	/* address */
			offset = fAddress (tvb, tree, offset);
			break;
		default:
			return offset;
			break;
		}
	}
	return offset;
}

static guint
fRecipientProcess (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
	
		switch (fTagNo(tvb, offset)) {
		case 0:	/* recipient */
			offset = fRecipient (tvb, tree, offset);
			break;
		case 1:	/* processId */
			offset = fProcessId (tvb, tree, offset);
			break;
		default:
			return offset;
			break;
		}
	}
	return offset;
}

static guint
fAddressBinding (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	offset = fObjectIdentifier (tvb, tree, offset);
	return fAddress (tvb, tree, offset);
}

static guint
fActionCommand (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;
	guint8 tag_no, class_tag;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
        if (((lvt == 7) && class_tag)) {   /* closing Tag */
            subtree = tree;
            offset++;
            continue;
        }
		switch (tag_no) {
	
		case 0: /* deviceIdentifier */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 1: /* objectIdentifier */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
        case 2: /* propertyIdentifier */
            offset = fPropertyIdentifier (tvb,subtree,offset,&tt);
            subtree = proto_item_add_subtree(tt, ett_bacapp_value);
            break;
        case 3: /* propertyArrayIndex */
            offset = fUnsignedTag (tvb,subtree,offset,"Property Array Index: ");
            break;
		case 4: /* propertyValue */
			if (((lvt == 6) && class_tag)) { offset++;  /* opening Tag */
				offset = fAbstractSyntaxNType (tvb, subtree, offset);
				break;
			}
			FAULT;
			break;
        case 5: /* priority */
            offset = fUnsignedTag (tvb,subtree,offset,"Priority: ");
            break;
        case 6: /* quitOnFailure */
            offset = fApplicationTypes   (tvb,subtree,offset,"Quit On Failure: ",NULL);
            break;
        case 7: /* writeSuccessful */
            offset = fApplicationTypes   (tvb,subtree,offset,"Write Successful: ",NULL);
            break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fActionList (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	return fActionCommand (tvb,tree,offset);
}

static guint
fPropertyIdentifier (tvbuff_t *tvb, proto_tree *tree, guint offset, proto_item **tt)
{
	guint8 tag_no, class_tag, tmp;
	guint32 lvt, i;
    guint offs;
	propertyIdentifier = 0;	/* global Variable */

	offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	for (i = 0; i < min(lvt,4); i++) {
		tmp = tvb_get_guint8(tvb, offset+offs+i);
		propertyIdentifier = (propertyIdentifier << 8) + tmp;
	}
	*tt = proto_tree_add_text(tree, tvb, offset, min(lvt,4)+offs,
		"property Identifier: %s", val_to_str(propertyIdentifier, BACnetPropertyIdentifier, "(%d) reserved for ASHREA"));
	return offset+offs+min(lvt,4); 
}

static guint
fCharacterString (tvbuff_t *tvb, proto_tree *tree, guint offset, guint8 *label)
{
	guint8 tag_no, class_tag, tmp;
    guint32 lvt, outbytesleft = 512, inbytesleft, l;
    guint offs;
	guint8 *str_val;
	guint8 bf_arr[512], *out = &bf_arr[0];

	if (offset < tvb_reported_length(tvb)) {

		offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
	
		tmp = tvb_get_guint8(tvb, offset+offs);
		if (tmp == 3) {
			proto_tree_add_text (tree, tvb, offset, 4+offs, "String Character Set: %s", val_to_str((guint) tmp, BACnetCharacterSet, "Reserved by ASHRAE"));
			offset+=4+offs;
			lvt-=4;
		}
		if (tmp == 4) {
			proto_tree_add_text (tree, tvb, offset, 1+offs, "String Character Set: %s", val_to_str((guint) tmp, BACnetCharacterSet, "Reserved by ASHRAE"));
			offset+=1+offs;
			lvt-=1;
		}
		if ((tmp != 3) && (tmp != 4)) {
			proto_tree_add_text (tree, tvb, offset, offs, "String Character Set: %s", val_to_str((guint) tmp, BACnetCharacterSet, "Reserved by ASHRAE"));
			offset+=1+offs;
			lvt--;
		}
		do {
			l = inbytesleft = min(lvt, 255);
			str_val = tvb_get_string(tvb, offset, l);
			/** this decoding may be not correct for multi-byte characters, Lka */
			switch (tmp) {
			case 0x00:	/* ANSI_X3.4 */
				fConvertXXXtoUTF8(str_val, &inbytesleft, out, &outbytesleft, "ANSI_X3.4");
				break;
			case 1: /* IBM/MICROSOFT DBCS */
				out = str_val;
				break;
			case 2: /* JIS C 6226 */
				out = str_val;
				break;
			case 3:	/* UCS-4 */
				fConvertXXXtoUTF8(str_val, &inbytesleft, out, &outbytesleft, "UCS-4BE");
				break;
			case 4:	/* UCS-2 */
				fConvertXXXtoUTF8(str_val, &inbytesleft, out, &outbytesleft, "UCS-2BE");
				break;
			case 5:	/* ISO8859-1 */
				fConvertXXXtoUTF8(str_val, &inbytesleft, out, &outbytesleft, "ISO8859-1");
				break;
			default:
				out = str_val;
				break;
			}
			proto_tree_add_text(tree, tvb, offset, l, "%s'%s'", LABEL(label), out);
			g_free(str_val);
			lvt-=l;
			offset+=l;
		} while (lvt > 0);
	}
	return offset;
}

static guint
fApplicationTypes   (tvbuff_t *tvb, proto_tree *tree, guint offset, guint8 *label, const value_string *src)
{
	guint8 tag_no, class_tag, tmp;
	gint j, unused;
	guint64 val = 0;
    guint32 lvt, i;
    guint offs;
	gfloat f_val = 0.0;
	gdouble d_val = 0.0;
	guint8 bf_arr[256];

	if (offset < tvb_reported_length(tvb)) {

		offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
	
		switch (tag_no) {
			case 0:	/** NULL 20.2.2 */
				proto_tree_add_text(tree, tvb, offset++, 1, "%sNULL", LABEL(label));
				break;
			case 1:	/** BOOLEAN 20.2.3 */
				proto_tree_add_text(tree, tvb, offset++, 1, "%s%s", LABEL(label), lvt == 0 ? "FALSE" : "TRUE");
				break;
			case 2:	/** Unsigned Integer 20.2.4 */
				offset = fUnsignedTag (tvb, tree, offset, label);
				break;
			case 3:	/** Signed Integer 20.2.5 */
				offset = fSignedTag (tvb, tree, offset, label);
				break;
			case 4:	/** Real 20.2.6 */
				f_val = tvb_get_ntohieee_float(tvb, offset+offs);
				proto_tree_add_text(tree, tvb, offset, 4+offs, "%s%f (Real)", LABEL(label), f_val);
				offset +=4+offs;
				break;
			case 5:	/** Double 20.2.7 */
				d_val = tvb_get_ntohieee_double(tvb, offset+offs);
				proto_tree_add_text(tree, tvb, offset, 8+offs, "%s%lf (Double)", LABEL(label), d_val);
				offset+=8+offs;
				break;
			case 6: /** Octet String 20.2.8 */
				proto_tree_add_text(tree, tvb, offset, 1, "%s (%d Characters)", LABEL(label), lvt);
				offset = fOctetString (tvb, tree, offset+offs, label, lvt);
				break;
		case 7: /** Character String 20.2.9 */
				offset = fCharacterString (tvb,tree,offset,label);
				break;
			case 8: /** Bit String 20.2.10 */
				offset+=offs;
				unused = tvb_get_guint8(tvb, offset); /* get the unused Bits */
				for (i = 0; i < (lvt-2); i++) {
					tmp = tvb_get_guint8(tvb, (offset)+i+1);
					for (j = 0; j < 8; j++) {
						if (src != NULL) {
							if (tmp & (1 << (7 - j)))
								proto_tree_add_text(tree, tvb, offset+i+1, 1, "%s%s = TRUE", LABEL(label), val_to_str((guint) (i*8 +j), src, "Reserved by ASHRAE"));
							else
								proto_tree_add_text(tree, tvb, offset+i+1, 1, "%s%s = FALSE", LABEL(label), val_to_str((guint) (i*8 +j), src, "Reserved by ASHRAE"));
	
						} else {
							bf_arr[min(255,(i*8)+j)] = tmp & (1 << (7 - j)) ? '1' : '0';
						}
					}
				}
				tmp = tvb_get_guint8(tvb, offset+lvt-1);	/* now the last Byte */
				if (src == NULL) {
					for (j = 0; j < (8 - unused); j++)
						bf_arr[min(255,((lvt-2)*8)+j)] = tmp & (1 << (7 - j)) ? '1' : '0';
					for (; j < 8; j++)
						bf_arr[min(255,((lvt-2)*8)+j)] = 'x';
					bf_arr[min(255,((lvt-2)*8)+j)] = '\0';
					proto_tree_add_text(tree, tvb, offset, lvt, "%sB'%s'", LABEL(label), bf_arr);
				} else {
					for (j = 0; j < (int) (8 - unused); j++) {
						if (tmp & (1 << (7 - j)))
							proto_tree_add_text(tree, tvb, offset+i+1, 1, "%s%s = TRUE", LABEL(label), val_to_str((guint) (i*8 +j), src, "Reserved by ASHRAE"));
						else
							proto_tree_add_text(tree, tvb, offset+i+1, 1, "%s%s = FALSE", LABEL(label), val_to_str((guint) (i*8 +j), src, "Reserved by ASHRAE"));
					}
				}
				offset+=lvt;
				break;
			case 9: /** Enumerated 20.2.11 */
				for (i = 0; i < min(lvt,8); i++) {
					tmp = tvb_get_guint8(tvb, offset+offs+i);
					val = (val << 8) + tmp;
				}
				if (src != NULL)
					proto_tree_add_text(tree, tvb, offset, lvt+offs, "%s%s (%d)", LABEL(label), val_to_str((guint) val, src, "Reserved by ASHRAE"), (guint) val);
				else
					proto_tree_add_text(tree, tvb, offset, lvt+offs, "%s%" PRIu64, LABEL(label), val);
	
				offset+=lvt+offs;
				break;
			case 10: /** Date 20.2.12 */
				offset = fDate    (tvb, tree, offset, label);
				break;
			case 11: /** Time 20.2.13 */
				offset = fTime (tvb, tree, offset, label);
				break;
			case 12: /** BACnetObjectIdentifier 20.2.14 */
				offset = fObjectIdentifier (tvb, tree, offset);
				break;
			case 13: /* reserved for ASHRAE */
			case 14:
			case 15:
				proto_tree_add_text(tree, tvb, offset, lvt+offs, "%s'reserved for ASHRAE'", LABEL(label));
				offset+=lvt+offs;
				break;
			default:
				return offset;
				break;
		}
	}
	return offset;
}

static guint
fAbstractSyntaxNType (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint8 tag_no, class_tag;
	guint32 lvt;
	guint offs, lastoffset = 0;
	char ar[256];
	sprintf (ar, "%s: ", val_to_str(propertyIdentifier, BACnetPropertyIdentifier, "identifier (%d) not found"));

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		offs = fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		if (((lvt == 7) && class_tag)) { /* closing tag, but not for me */
			return offset;
		}
		/* Application Tags */
		switch (propertyIdentifier) {
		case 2: /* BACnetActionList */
			offset = fActionList (tvb,tree,offset);
			break;
		case 30: /* BACnetAddressBinding */
			offset = fAddressBinding (tvb,tree,offset);
			break;
		case 38:	/* exception-schedule */
			offset = fSpecialEvent (tvb,tree,offset);
			break;
		case 97: /* Protocol-Services-Supported */
			offset = fApplicationTypes   (tvb, tree, offset, ar, BACnetServicesSupported);
			break;
		case 111: /* Status-Flags */
		case 112: /* System-Status */
			offset = fApplicationTypes   (tvb, tree, offset, ar, BACnetStatusFlags);
			break;
		case 117: /* units */
			offset = fApplicationTypes   (tvb, tree, offset, ar, BACnetUnits);
			break;
		case 76:  /* object-list */
			offset = fApplicationTypes   (tvb, tree, offset, ar, NULL);
			break;
		case 87:	/* priority-array */
			offset = fPriorityArray  (tvb, tree, offset);
			break;
		case 123:	/* weekly-schedule */
			offset = fWeeklySchedule (tvb,tree,offset);
			break;
		default:
			offset = fApplicationTypes   (tvb, tree, offset, ar, NULL);
			break;
		}
	}
	return offset;

}

static guint
fPropertyValue (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;
	guint8 tag_no, class_tag;
	guint32 lvt;
    gboolean awaitingClosingTag = false;
	proto_tree *subtree = tree;
	proto_item *tt;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		if (class_tag) {
			if ((lvt == 7) && !awaitingClosingTag) {  /* closing Tag */
				return offset; /* but not for me */
			}
			if (lvt == 7) {   /* closing Tag for me */
				subtree = tree;
				offset++;
				awaitingClosingTag = false;
				continue;
			}
			switch (tag_no) {
			case 0:	/* PropertyIdentifier */
				offset = fPropertyIdentifier (tvb, subtree, offset,  &tt);
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				break;
			case 1:	/* propertyArrayIndex */
				offset = fUnsignedTag (tvb, subtree, offset, "property Array Index: ");
				break;
			case 2:  /* Value */
				if ((lvt == 6) && class_tag) { offset++;  /* opening Tag */
					awaitingClosingTag = true;
					offset = fAbstractSyntaxNType (tvb, subtree, offset);
					break;
				}
				FAULT;
				break;
			case 3:  /* Priority */
				offset = fSignedTag (tvb, subtree, offset, "Priority: ");
				break;
			default:
				return offset;
				break;
			}
		} else {
			offset = fAbstractSyntaxNType (tvb,tree,offset);
		}
	}
	return offset;
}

static guint
fSubscribeCOVRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
	
		switch (fTagNo(tvb,offset)) {
		case 0:	/* ProcessId */
			offset = fUnsignedTag (tvb, tree, offset, "subscriber Process Id: ");
			break;
		case 1: /* monitored ObjectId */
			offset = fObjectIdentifier (tvb, tree, offset);
		break;
		case 2: /* issueConfirmedNotifications */
			offset = fApplicationTypes   (tvb, tree, offset, "issue Confirmed Notifications: ", NULL);
			break;
		case 3:	/* life time */
			offset = fTimeSpan (tvb,tree,offset,"life time");
			break;
		default:
			return offset;
			break;
		}
	}
	return offset;
}

static guint
fCOVSubscription(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
	
		switch (fTagNo(tvb,offset)) {
		case 0:	/* Recipient */
			offset = fRecipientProcess (tvb, tree, offset);
			break;
		case 1: /* monitoredPropertyReference */
			offset = fPropertyReference (tvb, tree, offset);
		break;
		case 2: /* issueConfirmedNotifications */
			offset = fApplicationTypes   (tvb, tree, offset, "issue Confirmed Notifications: ", NULL);
			break;
        case 3:	/* time remaining */
            offset = fTimeSpan (tvb,tree,offset,"time remaining");
			break;
        case 4: /* COVIncrement */
            offset = fApplicationTypes(tvb,tree,offset,"COV Increment: ", NULL);
            break;
		default:
			return offset;
			break;
		}
	}
	return offset;
}

static guint
fWhoHas (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
	
		switch (fTagNo(tvb, offset)) {
		case 0: /* deviceInstanceLowLimit */
			offset = fUnsignedTag (tvb, tree, offset, "device Instance Low Limit: ");
			break;
		case 1: /* deviceInstanceHighLimit */
			offset = fUnsignedTag (tvb, tree, offset, "device Instance High Limit: ");
			break;
		case 2: /* BACnetObjectId */
			offset = fObjectIdentifier (tvb, tree, offset);
		break;
		case 3: /* messageText */
			offset = fCharacterString (tvb,tree,offset, "Object Name: ");
			break;
		default:
			return offset;
		}
	}
	return offset;
}


static guint
fDailySchedule (tvbuff_t *tvb, proto_tree *subtree, guint offset)
{
    guint lastoffset = 0;
	guint8 tag_no, class_tag;
	guint32 lvt;
	
	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		if (((lvt == 7) && class_tag)) {   /* closing Tag */
			offset++;
			return offset;
		}
		
		switch (tag_no) {
		case 0: /* day-schedule */
			if (((lvt == 6) && class_tag)) { offset++;  /* opening Tag */
				offset = fTimeValue (tvb, subtree, offset);
				break;
			}
			FAULT;
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fWeeklySchedule (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;
	guint8 tag_no, class_tag;
	guint32 lvt;
	guint i=1;
	proto_tree *subtree = tree;
	proto_item *tt;
	
	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		if (((lvt == 7) && class_tag)) {   /* closing Tag */
			offset++;
			return offset;
		}	
		tt = proto_tree_add_text(tree, tvb, offset, 0, val_to_str(i++, days, "day of week (%d) not found"));
		subtree = proto_item_add_subtree(tt, ett_bacapp_value);
		offset = fDailySchedule (tvb,subtree,offset);
	
	}
	return offset;
}


static guint
fUTCTimeSynchronizationRequest  (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	if (offset >= tvb_reported_length(tvb))
		return offset;
	
	return fDateTime (tvb, tree, offset, "UTC-Time: ");
}

static guint
fTimeSynchronizationRequest  (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	if (offset >= tvb_reported_length(tvb))
		return offset;

	return fDateTime (tvb, tree, offset, NULL);
}

static guint
fDateRange  (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	if (offset >= tvb_reported_length(tvb))
		return offset;
    offset = fDate (tvb,tree,offset,"Start Date: ");
	return fDate (tvb, tree, offset, "End Date: ");
}

static guint
fConfirmedTextMessageRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;	
		switch (fTagNo(tvb, offset)) {
		case 0:	/* textMessageSourceDevice */
			offset = fObjectIdentifier (tvb, tree, offset);
			break;
		case 1: /* messageClass */
			switch (fTagNo(tvb, offset)) {
			case 0: /* numeric */
				offset = fUnsignedTag (tvb, tree, offset, "message Class: ");
				break;
			case 1: /* character */
				offset = fApplicationTypes   (tvb, tree, offset, "message Class: ", NULL);
				break;
			}
			break;
		case 2: /* messagePriority */
			offset = fApplicationTypes   (tvb, tree, offset, "Object Name: ", BACnetMessagePriority);
			break;
		case 3: /* message */
			offset = fApplicationTypes   (tvb, tree, offset, "message: ", NULL);
			break;
		default:
			return offset;
			break;	
		}
	}
	return offset;
}

static guint
fUnconfirmedTextMessageRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;	
		switch (fTagNo(tvb, offset)) {
		case 0:	/* textMessageSourceDevice */
			offset = fObjectIdentifier (tvb, tree, offset);
			break;
		case 1: /* messageClass */
			switch (fTagNo(tvb, offset)) {
			case 0: /* numeric */
				offset = fUnsignedTag (tvb, tree, offset, "message Class: ");
				break;
			case 1: /* character */
				offset = fApplicationTypes   (tvb, tree, offset, "message Class: ", NULL);
				break;
			}
			break;
		case 2: /* messagePriority */
			offset = fApplicationTypes   (tvb, tree, offset, "Object Name: ", BACnetMessagePriority);
			break;
		case 3: /* message */
			offset = fApplicationTypes   (tvb, tree, offset, "message: ", NULL);
			break;
		default:
			return offset;
			break;	
		}
	}
	return offset;
}

static guint
fConfirmedPrivateTransferRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;
	guint8 tag_no, class_tag;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
        if (((lvt == 7) && class_tag)) {   /* closing Tag */
            subtree = tree;
            offset++;
            continue;
        }
		switch (tag_no) {
	
		case 0: /* vendorID */
			offset = fUnsignedTag (tvb, subtree, offset, "vendor ID: ");
			break;
		case 1: /* serviceNumber */
			offset = fUnsignedTag (tvb, subtree, offset, "service Number: ");
			break;
		case 2: /*serviceParameters */
			if (((lvt == 6) && class_tag)) { offset++;  /* opening Tag */
				tt = proto_tree_add_text(subtree, tvb, offset, 1, "service Parameters");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset = fAbstractSyntaxNType (tvb, subtree, offset);
				break;
			}
			FAULT;
			break;
		default:
			return offset;
		}
	}
	return offset;
}


static guint
fUnconfirmedPrivateTransferRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;
	guint8 tag_no, class_tag;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
        if (((lvt == 7) && class_tag)) {   /* closing Tag */
            subtree = tree;
            offset++;
            continue;
        }
		switch (tag_no) {
	
		case 0: /* vendorID */
			offset = fUnsignedTag (tvb, subtree, offset, "vendor ID: ");
			break;
		case 1: /* serviceNumber */
			offset = fUnsignedTag (tvb, subtree, offset, "service Number: ");
			break;
		case 2: /*serviceParameters */
			if (((lvt == 6) && class_tag)) { offset++;   /* opening Tag */
				tt = proto_tree_add_text(subtree, tvb, offset, 1, "service Parameters");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset = fAbstractSyntaxNType (tvb, subtree, offset);
				break;
			}
			FAULT;
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fConfirmedPrivateTransferAck(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;
	guint8 tag_no, class_tag;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
        if (((lvt == 7) && class_tag)) {   /* closing Tag */
            subtree = tree;
            offset++;
            continue;
        }
		switch (tag_no) {
	
		case 0: /* vendorID */
			offset = fUnsignedTag (tvb, subtree, offset, "vendor ID: ");
			break;
		case 1: /* serviceNumber */
			offset = fUnsignedTag (tvb, subtree, offset, "service Number: ");
			break;
		case 2: /*serviceParameters */
			if (((lvt == 6) && class_tag)) { offset++;   /* opening Tag */
				tt = proto_tree_add_text(subtree, tvb, offset, 1, "result Block");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset = fAbstractSyntaxNType (tvb, subtree, offset);
				break;
			}
			FAULT;
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fLifeSafetyOperationRequest(tvbuff_t *tvb, proto_tree *tree, guint offset, guint8 *label)
{
    guint lastoffset = 0;
	guint8 tag_no, class_tag;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	if (label != NULL) {
		tt = proto_tree_add_text (subtree, tvb, offset, 1, "%s", LABEL(label));
		subtree = proto_item_add_subtree(tt, ett_bacapp_value);
	}

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
	
		switch (tag_no) {
		case 0:	/* subscriberProcessId */
			offset = fUnsignedTag (tvb, subtree, offset, "requesting Process Id: ");
			break;
		case 1: /* requestingSource */
			offset = fApplicationTypes   (tvb, subtree, offset, "requesting Source: ", NULL);
			break;
		case 2: /* request */
			offset = fApplicationTypes   (tvb, subtree, offset, "request: ", BACnetLifeSafetyOperation);
			break;
		case 3:	/* objectId */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		default:
			return offset;
			break;
		}
	}
	return offset;
}

static guint
fNotificationParameters (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0: /* change-of-bitstring */
			while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
                lastoffset = offset;
				switch (fTagNo(tvb, offset)) {
				case 0:
					offset = fApplicationTypes   (tvb, tree, offset, "referenced-bitstring: ", NULL);
					break;
				case 1:
					offset = fApplicationTypes   (tvb, tree, offset, "status-flags: ", BACnetStatusFlags);
					break;
				default:
					return offset;
					break;
				}
			}
        break;
		case 1: /* change-of-state */
			while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
                lastoffset = offset;
				switch (fTagNo(tvb, offset)) {
				case 0:
					offset = fApplicationTypes   (tvb, tree, offset, "new-state: ", BACnetPropertyStates);
				case 1:
					offset = fApplicationTypes   (tvb, tree, offset, "status-flags: ", BACnetStatusFlags);
					break;
				default:
					return offset;
					break;
				}
			}
			break;
        case 2: /* change-of-value */
			while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
                lastoffset = offset;
				switch (fTagNo(tvb, offset)) {
				case 0: offset++;
					switch (fTagNo(tvb, offset)) {
					case 0:
						offset = fApplicationTypes   (tvb, tree, offset, "changed-bits: ", NULL);
					break;
					case 1:
						offset = fApplicationTypes   (tvb, tree, offset, "changed-value: ", NULL);
					break;
					default:
						return offset;
						break;
					}
					break;
				case 1:
					offset = fApplicationTypes   (tvb, tree, offset, "status-flags: ", BACnetStatusFlags);
				default:
					return offset;
					break;
				}
			}
		break;
        case 3: /* command-failure */
			while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
                lastoffset = offset;
				switch (fTagNo(tvb, offset)) {
				case 0: /* "command-value: " */
					offset = fAbstractSyntaxNType   (tvb, tree, offset);
					break;
				case 1:
					offset = fApplicationTypes   (tvb, tree, offset, "status-flags: ", BACnetStatusFlags);
				case 2: /* "feedback-value: " */
					offset = fAbstractSyntaxNType   (tvb, tree, offset);
				default:
					return offset;
					break;
				}
			}
        break;
        case 4: /* floating-limit */
			while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
                lastoffset = offset;
				switch (fTagNo(tvb, offset)) {
				case 0:
					offset = fApplicationTypes   (tvb, tree, offset, "reference-value: ", NULL);
					break;
				case 1:
					offset = fApplicationTypes   (tvb, tree, offset, "status-flags: ", BACnetStatusFlags);
					break;
				case 2:
					offset = fApplicationTypes   (tvb, tree, offset, "setpoint-value: ", NULL);
					break;
				case 3:
					offset = fApplicationTypes   (tvb, tree, offset, "error-limit: ", NULL);
				default:
					return offset;
					break;
				}
			}
			break;
        case 5: /* out-of-range */
			while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
                lastoffset = offset;
				switch (fTagNo(tvb, offset)) {
				case 0:
					offset = fApplicationTypes   (tvb, tree, offset, "exceeding-value: ", NULL);
					break;
				case 1:
					offset = fApplicationTypes   (tvb, tree, offset, "status-flags: ", BACnetStatusFlags);
					break;
				case 2:
					offset = fApplicationTypes   (tvb, tree, offset, "deadband: ", NULL);
					break;
				case 3:
					offset = fApplicationTypes   (tvb, tree, offset, "exceeded-limit: ", NULL);
				default:
					return offset;
					break;
				}
			}
        break;
		case 6:
			offset = fPropertyValue (tvb,tree,offset);
		break;
        case 7: /* buffer-ready */
			while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
                lastoffset = offset;
				switch (fTagNo(tvb, offset)) {
				case 0:
					offset = fObjectIdentifier (tvb, tree, offset); /* buffer-device */
					break;
				case 1:
					offset = fObjectIdentifier (tvb, tree, offset); /* buffer-object */
					break;
				case 2:
					offset = fDateTime (tvb, tree, offset, "previous-notification: ");
					break;
				case 3:
					offset = fDateTime (tvb, tree, offset, "current-notification: ");
				default:
					return offset;
					break;
				}
			}
        break;
        case 8: /* change-of-life-safety */
			while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
                lastoffset = offset;
				switch (fTagNo(tvb, offset)) {
				case 0:
					offset = fApplicationTypes   (tvb, tree, offset, "new-state: ", BACnetLifeSafetyState);
					break;
				case 1:
					offset = fApplicationTypes   (tvb, tree, offset, "new-mode: ", BACnetLifeSafetyState);
					break;
				case 2:
					offset = fApplicationTypes   (tvb, tree, offset, "status-flags: ", BACnetStatusFlags);
				case 3:
					offset = fLifeSafetyOperationRequest(tvb, tree, offset, "operation-expected: ");
				default:
					return offset;
					break;
				}
			}
        break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fEventParameters (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0: /* change-of-bitstring */
			while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
                lastoffset = offset;
				switch (fTagNo(tvb, offset)) {
				case 0:
					offset = fTimeSpan   (tvb, tree, offset, "Time Delay");
					break;
				case 1:
					offset = fApplicationTypes   (tvb, tree, offset, "bitmask: ", NULL);
					break;
				case 2:
					offset = fApplicationTypes   (tvb, tree, offset, "bitstring value: ", BACnetEventTransitionBits);
					break;
				default:
					return offset;
				}
			}
        break;
		case 1: /* change-of-state */
			while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
                lastoffset = offset;
				switch (fTagNo(tvb, offset)) {
				case 0:
					offset = fTimeSpan   (tvb, tree, offset, "Time Delay");
					break;
				case 1:
					offset = fApplicationTypes   (tvb, tree, offset, "value: ", BACnetStatusFlags);
					break;
				default:
					return offset;
				}
			}
			break;
        case 2: /* change-of-value */
			while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
                lastoffset = offset;
				switch (fTagNo(tvb, offset)) {
				case 0:
					offset = fTimeSpan   (tvb, tree, offset, "Time Delay");
					break;
				case 1: /* don't loop it, it's a CHOICE */
					switch (fTagNo(tvb, offset)) {
					case 0:
						offset = fApplicationTypes   (tvb, tree, offset, "bitmask: ", NULL);
					break;
					case 1:
						offset = fApplicationTypes   (tvb, tree, offset, "referenced Property Incremental: ", NULL);
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
			while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
                lastoffset = offset;
				switch (fTagNo(tvb, offset)) {
				case 0:
					offset = fTimeSpan   (tvb, tree, offset, "Time Delay");
					break;
				case 1:
					offset = fDeviceObjectPropertyReference (tvb,tree,offset);
				default:
					return offset;
				}
			}
        break;
        case 4: /* floating-limit */
			while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
                lastoffset = offset;
				switch (fTagNo(tvb, offset)) {
				case 0:
					offset = fTimeSpan   (tvb, tree, offset, "Time Delay");
					break;
				case 1:
					offset = fDeviceObjectPropertyReference (tvb,tree,offset);
					break;
				case 2:
					offset = fApplicationTypes   (tvb, tree, offset, "low diff limit: ", NULL);
					break;
				case 3:
					offset = fApplicationTypes   (tvb, tree, offset, "high diff limit: ", NULL);
					break;
				case 4:
					offset = fApplicationTypes   (tvb, tree, offset, "deadband: ", NULL);
					break;
				default:
					return offset;
				}
			}
			break;
        case 5: /* out-of-range */
			while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
                lastoffset = offset;
				switch (fTagNo(tvb, offset)) {
				case 0:
					offset = fTimeSpan   (tvb, tree, offset, "Time Delay");
					break;
				case 1:
					offset = fApplicationTypes   (tvb, tree, offset, "low limit: ", NULL);
					break;
				case 2:
					offset = fApplicationTypes   (tvb, tree, offset, "high limit: ", NULL);
					break;
				case 3:
					offset = fApplicationTypes   (tvb, tree, offset, "deadband: ", NULL);
					break;
				default:
					return offset;
				}
			}
        break;
		case 6:
			offset = fPropertyValue (tvb,tree,offset);
		break;
        case 7: /* buffer-ready */
			while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
                lastoffset = offset;
				switch (fTagNo(tvb, offset)) {
				case 0:
					offset = fUnsignedTag (tvb,tree,offset,"notification threshold");
					break;
				case 1:
					offset = fApplicationTypes   (tvb, tree, offset, "previous notification count: ", NULL);
					break;
				default:
					return offset;
				}
			}
        break;
        case 8: /* change-of-life-safety */
			while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
                lastoffset = offset;
				switch (fTagNo(tvb, offset)) {
				case 0:
					offset = fTimeSpan   (tvb, tree, offset, "Time Delay");
					break;
				case 1:
					offset = fApplicationTypes   (tvb, tree, offset, "life safety alarm value: ", BACnetLifeSafetyState);
					break;
				case 2:
					offset = fApplicationTypes   (tvb, tree, offset, "alarm value: ", BACnetLifeSafetyState);
					break;
				case 3:
					offset = fDeviceObjectPropertyReference (tvb, tree, offset);
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

static guint
fLogRecord (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0: /* timestamp */
			offset = fDateTime (tvb,tree,offset,NULL);
			break;
		case 1: /* logDatum: don't loop, it's a CHOICE */
			switch (fTagNo(tvb, offset)) {
			case 0:	/* logStatus */
				offset = fApplicationTypes   (tvb, tree, offset, "log status: ", BACnetLogStatus);
				break;
			case 1:
				offset = fApplicationTypes   (tvb, tree, offset, "boolean-value: ", NULL);
				break;
			case 2:
				offset = fApplicationTypes   (tvb, tree, offset, "real value: ", NULL);
				break;
			case 3:
				offset = fApplicationTypes   (tvb, tree, offset, "enum value: ", NULL);
				break;
			case 4:
				offset = fUnsignedTag   (tvb, tree, offset, "unsigned value: ");
				break;
			case 5:
				offset = fApplicationTypes   (tvb, tree, offset, "signed value: ", NULL);
				break;
			case 6:
				offset = fApplicationTypes   (tvb, tree, offset, "bitstring value: ", NULL);
				break;
			case 7:
				offset = fApplicationTypes   (tvb, tree, offset, "null value: ", NULL);
				break;
			case 8:
				offset = fError (tvb,tree,offset);
				break;
			case 9:
				offset = fApplicationTypes   (tvb, tree, offset, "time change: ", NULL);
				break;
			case 10:	/* any Value */
				offset = fAbstractSyntaxNType   (tvb, tree, offset);
				break;
			default:
				return offset;
			}
        break;
		case 2:
			offset = fApplicationTypes   (tvb, tree, offset, "status Flags: ", BACnetStatusFlags);
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fConfirmedEventNotificationRequest (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
	
		switch (fTagNo(tvb,offset)) {
		case 0:	/* ProcessId */
			offset = fProcessId (tvb,tree,offset);
			break;
		case 1: /* initiating ObjectId */
			offset = fObjectIdentifier (tvb, tree, offset);
			break;
		case 2: /* event ObjectId */
			offset = fObjectIdentifier (tvb, tree, offset);
			break;
		case 3:	/* time stamp */
			offset = fApplicationTypes   (tvb, tree, offset, "Time Stamp: ", NULL);
			break;
		case 4:	/* notificationClass */
			offset = fApplicationTypes   (tvb, tree, offset, "Notification Class: ", NULL);
			break;
		case 5:	/* Priority */
			offset = fApplicationTypes   (tvb, tree, offset, "Priority: ", NULL);
			break;
		case 6:	/* EventType */
			offset = fApplicationTypes   (tvb, tree, offset, "Event Type: ", BACnetEventType);
			break;
		case 7: /* messageText */
			offset = fApplicationTypes   (tvb, tree, offset, "message Text: ", NULL);
			break;
		case 8:	/* NotifyType */
			offset = fApplicationTypes   (tvb, tree, offset, "Notify Type: ", BACnetNotifyType);
			break;
		case 9: /* ackRequired */
			offset = fApplicationTypes   (tvb, tree, offset, "ack Required: ", NULL);
			break;
		case 10: /* fromState */
			offset = fApplicationTypes   (tvb, tree, offset, "from State: ", BACnetEventState);
			break;
		case 11: /* toState */
			offset = fApplicationTypes   (tvb, tree, offset, "to State: ", BACnetEventState);
			break;
		case 12: /* NotificationParameters */
			offset = fNotificationParameters (tvb, tree, offset);
			break;
		default:
			return offset;
			break;
		}
	}
	return offset;
}

static guint
fUnconfirmedEventNotificationRequest (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
	
		switch (fTagNo(tvb,offset)) {
		case 0:	/* ProcessId */
			offset = fProcessId (tvb,tree,offset);
			break;
		case 1: /* initiating ObjectId */
			offset = fObjectIdentifier (tvb, tree, offset);
			break;
		case 2: /* event ObjectId */
			offset = fObjectIdentifier (tvb, tree, offset);
			break;
		case 3:	/* time stamp */
			offset = fApplicationTypes   (tvb, tree, offset, "Time Stamp: ", NULL);
			break;
		case 4:	/* notificationClass */
			offset = fApplicationTypes   (tvb, tree, offset, "Notification Class: ", NULL);
			break;
		case 5:	/* Priority */
			offset = fApplicationTypes   (tvb, tree, offset, "Priority: ", NULL);
			break;
		case 6:	/* EventType */
			offset = fApplicationTypes   (tvb, tree, offset, "Event Type: ", BACnetEventType);
			break;
		case 7: /* messageText */
			offset = fApplicationTypes   (tvb, tree, offset, "message Text: ", NULL);
			break;
		case 8:	/* NotifyType */
			offset = fApplicationTypes   (tvb, tree, offset, "Notify Type: ", BACnetNotifyType);
			break;
		case 9: /* ackRequired */
			offset = fApplicationTypes   (tvb, tree, offset, "ack Required: ", NULL);
			break;
		case 10: /* fromState */
			offset = fApplicationTypes   (tvb, tree, offset, "from State: ", BACnetEventState);
			break;
		case 11: /* toState */
			offset = fApplicationTypes   (tvb, tree, offset, "to State: ", BACnetEventState);
			break;
		case 12: /* NotificationParameters */
			offset = fNotificationParameters (tvb, tree, offset);
			break;
		default:
			return offset;
			break;
		}
	}
	return offset;
}

static guint
fConfirmedCOVNotificationRequest (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;
	guint8 tag_no, class_tag;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		if (((lvt == 7) && class_tag)) {   /* closing Tag */
			subtree = tree;
			offset++;
			continue;
		}
	
		switch (tag_no) {
		case 0:	/* ProcessId */
			offset = fProcessId (tvb,tree,offset);
			break;
		case 1: /* initiating ObjectId */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 2: /* monitored ObjectId */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 3:	/* time remaining */
			offset = fTimeSpan (tvb, tree, offset, "Time remaining");
			break;
		case 4:	/* List of Values */
			if (((lvt == 6) && class_tag)) { offset++;   /* opening Tag */
				tt = proto_tree_add_text(subtree, tvb, offset, 1, "list of Values");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset = fPropertyValue (tvb, subtree, offset);
				break;
			}
			FAULT;
			break;
		default:
			return offset;
			break;
		}
	}
	return offset;
}

static guint
fUnconfirmedCOVNotificationRequest (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;
	guint8 tag_no, class_tag;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		if (((lvt == 7) && class_tag)) {   /* closing Tag */
			subtree = tree;
			offset++;
			continue;
		}
	
		switch (tag_no) {
		case 0:	/* subscriberProcessId */
			offset = fProcessId (tvb,tree,offset);
			break;
		case 1: /* initiating ObjectId */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 2: /* monitored ObjectId */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 3:	/* time remaining */
			offset = fTimeSpan (tvb, tree, offset, "Time remaining");
			break;
		case 4:	/* List of Values */
			if (((lvt == 6) && class_tag)) {  offset++;  /* opening Tag */
				tt = proto_tree_add_text(subtree, tvb, offset, 1, "list of Values");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset = fPropertyValue (tvb, subtree, offset);
				break;
			}
			FAULT;
			break;
		default:
			return offset;
			break;
		}
	}
	return offset;
}

static guint
fAcknowlegdeAlarmRequest (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0:	/* acknowledgingProcessId */
			offset = fUnsignedTag (tvb, tree, offset, "acknowledging Process Id: ");
			break;
		case 1: /* eventObjectId */
			offset = fObjectIdentifier (tvb, tree, offset);
			break;
		case 2: /* eventStateAcknowledged */
			fApplicationTypes   (tvb, tree, offset, "event State Acknowledged: ", BACnetEventState);
			break;
		case 3:	/* timeStamp */
			offset = fTime (tvb, tree, offset, "time Stamp: ");
			break;
		case 4:	/* acknowledgementSource */
			offset = fApplicationTypes   (tvb, tree, offset, "acknowledgement Source: ", NULL);
			break;
		case 5:	/* timeOfAcknowledgement */
			offset = fTime (tvb, tree, offset, "time Of Acknowledgement: ");
			break;
		default:
			return offset;
			break;
		}
	}
	return offset;
}

static guint
fGetAlarmSummaryAck (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		offset = fObjectIdentifier (tvb, tree, offset);
		offset = fApplicationTypes   (tvb, tree, offset, "alarm State: ", BACnetEventState);
		offset = fApplicationTypes   (tvb, tree, offset, "acknowledged Transitions: ", BACnetEventTransitionBits);
	}
	return  offset;
}

static guint
fGetEnrollmentSummaryRequest (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0:	/* acknowledgmentFilter */
			offset = fApplicationTypes   (tvb, tree, offset, "acknowledgment Filter: ", BACnetAcknowledgementFilter);
			break;
		case 1: /* eventObjectId */
			offset = fRecipientProcess (tvb, tree, offset);
			break;
		case 2: /* eventStateFilter */
			offset = fApplicationTypes   (tvb, tree, offset, "event State Filter: ", BACnetEventStateFilter);
			break;
		case 3:	/* eventTypeFilter */
			offset = fApplicationTypes   (tvb, tree, offset, "event Type Filter: ", BACnetEventType);
			break;
		case 4:	/* priorityFilter */
			offset = fUnsignedTag (tvb, tree, offset, "min Priority: ");
			offset = fUnsignedTag (tvb, tree, offset, "max Priority: ");
			break;
		case 5:	/* notificationClassFilter */
			offset = fUnsignedTag (tvb, tree, offset, "notification Class Filter: ");
			break;
		default:
			return offset;
			break;
		}
	}
	return offset;
}

static guint
fGetEnrollmentSummaryAck (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		offset = fObjectIdentifier (tvb, tree, offset);
		offset = fApplicationTypes   (tvb, tree, offset, "event Type: ", BACnetEventType);
		offset = fApplicationTypes   (tvb, tree, offset, "event State: ", BACnetEventStateFilter);
		offset = fUnsignedTag (tvb, tree, offset, "Priority: ");
		offset = fUnsignedTag (tvb, tree, offset, "notification Class: ");
	}

	return  offset;
}

static guint
fGetEventInformationRequest (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0:	/* lastReceivedObjectId */
			offset = fObjectIdentifier (tvb, tree, offset);
			break;
		default:
			return offset;
			break;
		}
	}
	return offset;
}

static guint
flistOfEventSummaries (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0:	/* ObjectId */
			offset = fObjectIdentifier (tvb, tree, offset);
			break;
		case 1: /* eventState */
			offset = fApplicationTypes   (tvb, tree, offset, "event State: ", BACnetEventStateFilter);
			break;
		case 2: /* acknowledgedTransitions */
			offset = fApplicationTypes   (tvb, tree, offset, "acknowledged Transitions: ", BACnetEventTransitionBits);
			break;
		case 3: /* eventTimeStamps */
			offset = fTime (tvb, tree, offset, "time Stamp: ");
			offset = fTime (tvb, tree, offset, "time Stamp: ");
			offset = fTime (tvb, tree, offset, "time Stamp: ");
			break;
		case 4: /* notifyType */
			offset = fApplicationTypes   (tvb, tree, offset, "Notify Type: ", BACnetNotifyType);
			break;
		case 5: /* eventEnable */
			offset = fApplicationTypes   (tvb, tree, offset, "event Enable: ", BACnetEventTransitionBits);
			break;
		case 6: /* eventPriorities */
			offset = fUnsignedTag (tvb, tree, offset, "event Priority: ");
			offset = fUnsignedTag (tvb, tree, offset, "event Priority: ");
			offset = fUnsignedTag (tvb, tree, offset, "event Priority: ");
			break;
		default:
			return offset;
			break;
		}
	}
	return offset;
}

static guint
fGetEventInformationACK (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0:	/* listOfEventSummaries */
			offset = flistOfEventSummaries (tvb, tree, offset);
			break;
		case 1: /* moreEvents */
			offset = fApplicationTypes   (tvb, tree, offset, "more Events: ", NULL);
			break;
		default:
			return offset;
			break;
		}
	}
	return offset;
}

static guint
fAddListElementRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;
	guint8 tag_no, class_tag;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		if (((lvt == 7) && class_tag)) {   /* closing Tag */
			subtree = tree;
			offset++;
			continue;
		}
	
		switch (tag_no) {
		case 0:	/* ObjectId */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 1:	/* propertyIdentifier */
			offset = fPropertyIdentifier (tvb, subtree, offset, &tt);
			subtree = proto_item_add_subtree(tt, ett_bacapp_value);
			break;
		case 2: /* propertyArrayIndex */
			offset = fSignedTag (tvb, subtree, offset, "property Array Index: ");
			break;
		case 3:	/* listOfElements */
			if ((lvt == 6) && class_tag) { offset++;  /* opening Tag */
				offset = fAbstractSyntaxNType (tvb, subtree, offset);
				break;
			}
			FAULT;
			break;
		default:
			return offset;
			break;
		}
	}
	return offset;
}

static guint
fDeleteObjectRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	return fObjectIdentifier (tvb, tree, offset);
}

static guint
fDeviceCommunicationControlRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
	
		switch (fTagNo(tvb, offset)) {
		case 0:	/* timeDuration */
			offset = fUnsignedTag (tvb,tree,offset,"time Duration: ");
			break;
		case 1:	/* enable-disable */
			offset = fApplicationTypes   (tvb, tree, offset, "enable-disable: ", BACnetEnableDisable);
			break;
		case 2: /* password */
			offset = fApplicationTypes   (tvb, tree, offset, "Password: ", NULL);
			break;
		default:
			return offset;
			break;
		}
	}
	return offset;
}

static guint
fReinitializeDeviceRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
	
		switch (fTagNo(tvb, offset)) {
		case 0:	/* reinitializedStateOfDevice */
			offset = fApplicationTypes   (tvb, tree, offset, "reinitialized State Of Device: ", BACnetReinitializedStateOfDevice);
			break;
		case 1: /* password */
			offset = fApplicationTypes   (tvb, tree, offset, "Password: ", NULL);
			break;
		default:
			return offset;
			break;
		}
	}
	return offset;
}

static guint
fVtOpenRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	if (offset >= tvb_reported_length(tvb))
		return offset;
	offset = fApplicationTypes   (tvb, tree, offset, "vtClass: ", BACnetVTClass);
	return fUnsignedTag (tvb,tree,offset,"local VT Session ID: ");
}

static guint
fVtOpenAck (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	if (offset >= tvb_reported_length(tvb))
		return offset;
	return offset= fUnsignedTag (tvb,tree,offset,"remote VT Session ID: ");
}

static guint
fVtCloseRequest (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		offset= fUnsignedTag (tvb,tree,offset,"remote VT Session ID: ");
	}
	return offset;
}

static guint
fVtDataRequest (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	if (offset >= tvb_reported_length(tvb))
		return offset;
	offset= fUnsignedTag (tvb,tree,offset,"VT Session ID: ");
	offset = fApplicationTypes   (tvb, tree, offset, "VT New Data: ", NULL);
	return fUnsignedTag (tvb,tree,offset,"VT Data Flag: ");;
}

static guint
fVtDataAck (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
	
		switch (fTagNo(tvb,offset)) {
		case 0:	/* BOOLEAN */
			offset = fApplicationTypes   (tvb, tree, offset, "all New Data Accepted: ", NULL);
			break;
		case 1:	/* Unsigned OPTIONAL */
			offset = fUnsignedTag (tvb, tree, offset, "accepted Octet Count: ");
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fAuthenticateRequest (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
	
		switch (fTagNo(tvb,offset)) {
		case 0:	/* Unsigned32 */
			offset = fUnsignedTag (tvb, tree, offset, "pseudo Random Number: ");
			break;
		case 1:	/* expected Invoke ID Unsigned8 OPTIONAL */
			proto_tree_add_item(tree, hf_bacapp_invoke_id, tvb, offset++, 1, TRUE);
			break;
		case 2: /* Chararacter String OPTIONAL */
			offset = fApplicationTypes (tvb, tree, offset, "operator Name: ", NULL);
			break;
		case 3:	/* Chararacter String OPTIONAL */
			offset = fApplicationTypes   (tvb, tree, offset, "operator Password: ", NULL);
			break;
		case 4: /* Boolean OPTIONAL */
			offset = fApplicationTypes   (tvb, tree, offset, "start Encyphered Session: ", NULL);
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fAuthenticateAck (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	return fUnsignedTag (tvb, tree, offset, "modified Random Number: ");
}

static guint
fRequestKeyRequest (tvbuff_t *tvb, proto_tree *tree, guint offset)
{

	offset = fObjectIdentifier (tvb, tree, offset); /* Requesting Device Identifier */
	offset = fAddress (tvb, tree, offset);
	offset = fObjectIdentifier (tvb, tree, offset); /* Remote Device Identifier */
	return fAddress (tvb, tree, offset);
}

static guint
fSubscribeCOVPropertyRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
	
		switch (fTagNo(tvb,offset)) {
		case 0:	/* subscriberProcessId */
			offset = fUnsignedTag (tvb, tree, offset, "subscriber Process Id: ");
			break;
		case 1: /* monitored ObjectId */
			offset = fObjectIdentifier (tvb, tree, offset);
		break;
		case 2: /* issueConfirmedNotifications */
			offset = fApplicationTypes   (tvb, tree, offset, "issue Confirmed Notifications: ", NULL);
			break;
		case 3:	/* life time */
			offset = fTimeSpan (tvb,tree,offset,"life time");
			break;
		case 4: /* monitoredPropertyIdentifier */
			offset = fApplicationTypes   (tvb, tree, offset, "monitored Property Id: ", NULL);
			break;
		case 5: /* covIncrement */
			offset = fUnsignedTag (tvb, tree, offset, "cov Increment: ");
			break;
		default:
			return offset;
			break;
		}
	}
	return offset;
}

static guint
fRemoveListElementRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	guint8 tag_no, class_tag;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		if (((lvt == 7) && class_tag)) {   /* closing Tag */
			subtree = tree;
			offset++;
			continue;
		}
	
		switch (tag_no) {
		case 0:	/* ObjectId */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 1:	/* propertyIdentifier */
			offset = fPropertyIdentifier (tvb, subtree, offset, &tt);
			subtree = proto_item_add_subtree(tt, ett_bacapp_value);
			break;
		case 2: /* propertyArrayIndex */
			offset = fSignedTag (tvb, subtree, offset, "property Array Index: ");
			break;
		case 3:	/* listOfElements */
			if ((lvt == 6) && class_tag) { offset++;  /* opening Tag */
				offset = fAbstractSyntaxNType (tvb, subtree, offset);
				break;
			}
			FAULT;
			break;
		default:
			return offset;
			break;
		}
	}
	return offset;
}

static guint
fReadPropertyRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;
	proto_tree *subtree = tree;
    proto_item *tt;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		switch (fTagNo(tvb,offset)) {
		case 0:	/* objectIdentifier */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 1:	/* propertyIdentifier */
			offset = fPropertyIdentifier (tvb, subtree, offset, &tt);
			break;
		case 2: /* propertyArrayIndex */
			offset = fSignedTag (tvb, subtree, offset, "property Array Index: ");
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fReadPropertyAck (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;
	guint8 tag_no, class_tag;
	guint32 lvt;
	proto_tree *subtree = tree;
    proto_item *tt;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		if (((lvt == 7) && class_tag)) { 
			subtree = tree;
			offset++;
			continue;
		}
	
		switch (tag_no) {
		case 0:	/* objectIdentifier */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 1:	/* propertyIdentifier */
			offset = fPropertyIdentifier (tvb, subtree, offset, &tt);
			subtree = proto_item_add_subtree(tt, ett_bacapp_value);
			break;
		case 2: /* propertyArrayIndex */
			offset = fSignedTag (tvb, subtree, offset, "property Array Index: ");
			break;
		case 3:	/* propertyValue */
			if ((lvt == 6) && class_tag) {   offset++;
				offset = fAbstractSyntaxNType (tvb, subtree, offset);
			/*	offset = fPropertyValue (tvb,subtree,offset); */
				break;
			}
			FAULT;
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fWritePropertyRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;
	guint8 tag_no, class_tag;
	guint32 lvt;
	proto_tree *subtree = tree;
    proto_item *tt;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		if (((lvt == 7) && class_tag)) { 
			subtree = tree;
			offset++;
			continue;
		}
	
		switch (tag_no) {
		case 0:	/* objectIdentifier */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 1:	/* propertyIdentifier */
			offset = fPropertyIdentifier (tvb, subtree, offset, &tt);
			break;
		case 2: /* propertyArrayIndex */
			offset = fSignedTag (tvb, subtree, offset, "property Array Index: ");
			break;
		case 3:	/* propertyValue */
			if ((lvt == 6) && class_tag) {   offset++;
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset = fAbstractSyntaxNType (tvb, subtree, offset);
				break;
			}
			FAULT;
			break;
		case 4: /* Priority (only used for write) */
			offset = fSignedTag (tvb, subtree, offset, "Priority: ");
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fWriteAccessSpecification (tvbuff_t *tvb, proto_tree *subtree, guint offset)
{
    guint lastoffset = 0;
	guint8 tag_no, class_tag;
	guint32 lvt;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		if ((lvt == 7) && class_tag) {   /* closing Tag */
			offset++;
			continue;
		}
	
		switch (tag_no) {
		case 0:	/* objectIdentifier */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 1:	/* listOfPropertyValues */
			if ((lvt == 6) && class_tag) { offset++;  /* opening Tag */
				offset = fPropertyValue (tvb, subtree, offset);
				break;
			}
			FAULT;
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fWritePropertyMultipleRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	if (offset >= tvb_reported_length(tvb))
		return offset;

	return fWriteAccessSpecification (tvb, tree, offset);
}

static guint
fPropertyReference (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;
	guint8 tag_no, class_tag;
	guint32 lvt;
	proto_tree* subtree = tree;
	proto_item* tt;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		if ((lvt == 7) && class_tag) {   /* closing Tag, but not for me */
			return offset;
		}
		switch (tag_no) {
		case 0:	/* PropertyIdentifier */
			offset = fPropertyIdentifier (tvb, tree, offset, &tt);
			subtree = proto_item_add_subtree(tt, ett_bacapp_value);
			break;
		case 1:	/* propertyArrayIndex */
			offset = fUnsignedTag (tvb, subtree, offset, "property Array Index: ");
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fObjectPropertyReference (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;
	proto_tree* subtree = tree;
	proto_item* tt;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		
        switch (fTagNo(tvb,offset)) {
		case 0:	/* ObjectIdentifier */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 1:	/* PropertyIdentifier */
			offset = fPropertyIdentifier (tvb, tree, offset, &tt);
			subtree = proto_item_add_subtree(tt, ett_bacapp_value);
			break;
		case 2:	/* propertyArrayIndex */
			offset = fUnsignedTag (tvb, subtree, offset, "property Array Index: ");
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fObjectPropertyValue (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;
	guint8 tag_no, class_tag;
	guint32 lvt;
	proto_tree* subtree = tree;
	proto_item* tt;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		if ((lvt == 7) && class_tag) {   /* closing Tag */
            offset++; /* check it again, Lka */
			continue;
		}
		switch (tag_no) {
		case 0:	/* ObjectIdentifier */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 1:	/* PropertyIdentifier */
			offset = fPropertyIdentifier (tvb, tree, offset, &tt);
			subtree = proto_item_add_subtree(tt, ett_bacapp_value);
			break;
		case 2:	/* propertyArrayIndex */
			offset = fUnsignedTag (tvb, subtree, offset, "property Array Index: ");
			break;
		case 3:  /* Value */
			if ((lvt == 6) && class_tag) { offset++;  /* opening Tag */
				offset = fAbstractSyntaxNType   (tvb, subtree, offset);
				break;
			}
			FAULT;
			break;
		case 4:  /* Priority */
			offset = fSignedTag (tvb, subtree, offset, "Priority: ");
			break;
		default:
			return offset;
		}
	}
	return offset;
}


static guint
fDeviceObjectPropertyReference (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;
	proto_tree* subtree = tree;
	proto_item* tt;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		
        switch (fTagNo(tvb,offset)) {
		case 0:	/* ObjectIdentifier */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 1:	/* PropertyIdentifier */
			offset = fPropertyIdentifier (tvb, tree, offset, &tt);
			subtree = proto_item_add_subtree(tt, ett_bacapp_value);
			break;
		case 2:	/* propertyArrayIndex */
			offset = fUnsignedTag (tvb, subtree, offset, "property Array Index: ");
			break;
		case 3:	/* deviceIdentifier */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fPriorityArray (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint8 i, ar[256];

	if (offset >= tvb_reported_length(tvb))
		return offset;
	
	for (i = 1; i <= 16; i++) {
		
		sprintf (ar, "%s[%d]: ", val_to_str(propertyIdentifier, BACnetPropertyIdentifier, "identifier (%d) not found"), i);
		offset = fApplicationTypes   (tvb, tree, offset, ar, BACnetBinaryPV);
	}
	return offset;
}

static guint
fDeviceObjectReference (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		
        switch (fTagNo(tvb,offset)) {
		case 0:	/* deviceIdentifier */
			offset = fObjectIdentifier (tvb, tree, offset);
			break;
		case 1:	/* ObjectIdentifier */
			offset = fObjectIdentifier (tvb, tree, offset);
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fSpecialEvent (tvbuff_t *tvb, proto_tree *subtree, guint offset)
{
	guint8 tag_no, class_tag;
	guint32 lvt;
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		if ((lvt == 7) && class_tag) {   /* closing Tag */
			offset++;
			continue;
		}
        
		switch (fTagNo(tvb,offset)) {
		case 0:	/* calendaryEntry */
			offset = fCalendaryEntry (tvb, subtree, offset);
			break;
		case 1:	/* calendarReference */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 2:	/* calendarReference */
			if ((lvt == 6) && class_tag) {  offset++; /* opening Tag */
				offset = fTimeValue (tvb, subtree, offset);
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
	}
	return offset;
}

static guint
fSelectionCriteria (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;
	proto_tree *subtree = tree;
	proto_item *tt;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		
		switch (fTagNo(tvb,offset)) {
		case 0:	/* propertyIdentifier */
			offset = fPropertyIdentifier (tvb, tree, offset, &tt);
			subtree = proto_item_add_subtree(tt, ett_bacapp_value);
			break;
		case 1:	/* propertyArrayIndex */
			offset = fUnsignedTag (tvb, subtree, offset, "property Array Index: ");
			break;
		case 2: /* relationSpecifier */
			offset = fApplicationTypes   (tvb, subtree, offset, "relation Specifier: ", BACnetRelationSpecifier);
			break;
		case 3: /* comparisonValue */
			offset = fAbstractSyntaxNType   (tvb, subtree, offset);
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fObjectSelectionCriteria (tvbuff_t *tvb, proto_tree *subtree, guint offset)
{
    guint lastoffset = 0;
	guint8 tag_no, class_tag;
	guint32 lvt;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		if ((lvt == 7) && class_tag) {   /* closing Tag */
			offset++;
			continue;
		}
	
		switch (tag_no) {
		case 0:	/* selectionLogic */
			offset = fApplicationTypes   (tvb, subtree, offset, "selection Logic: ", BACnetSelectionLogic);
			break;
		case 1:	/* listOfSelectionCriteria */
			if ((lvt == 6) && class_tag) {  offset++; /* opening Tag */
				offset = fSelectionCriteria (tvb, subtree, offset);
				break;
			}
			FAULT;
			break;
		default:
			return offset;
		}
	}
	return offset;
}


static guint
fReadPropertyConditionalRequest(tvbuff_t *tvb, proto_tree *subtree, guint offset)
{
    guint lastoffset = 0;
	guint8 tag_no, class_tag;
	guint32 lvt;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		if ((lvt == 7) && class_tag) {   /* closing Tag */
			offset++;
			continue;
		}
	
		switch (tag_no) {
		case 0:	/* objectSelectionCriteria */
			offset = fObjectSelectionCriteria (tvb, subtree, offset);
			break;
		case 1:	/* listOfPropertyReferences */
			if ((lvt == 6) && class_tag) {  offset++; /* opening Tag */
				offset = fPropertyReference (tvb, subtree, offset);
				break;
			}
			FAULT;
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fReadAccessSpecification (tvbuff_t *tvb, proto_tree *subtree, guint offset)
{
    guint lastoffset = 0;
	guint8 tag_no, class_tag;
	guint32 lvt;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		if ((lvt == 7) && class_tag) {   /* closing Tag */
			offset++;
			continue;
		}
	
		switch (tag_no) {
		case 0:	/* objectIdentifier */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 1:	/* listOfPropertyReferences */
			if ((lvt == 6) && class_tag) { offset++;  /* opening Tag */
				offset = fPropertyReference (tvb, subtree, offset);
				break;
			}
			FAULT;
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fReadAccessResult (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;
	guint8 tag_no;
	guint8 class_tag;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		if ((lvt == 7) && class_tag) {   /* closing Tag */
			subtree = tree;
			offset++;
			continue;
		}
	
		switch (tag_no) {
		case 0:	/* objectSpecifier */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 1:	/* list of Results */
			if ((lvt == 6) && class_tag) { offset++;  /* opening Tag */
				break;
			}
			FAULT;
			break;
		case 2:	/* propertyIdentifier */
			offset = fPropertyIdentifier (tvb, subtree, offset, &tt);
			subtree = proto_item_add_subtree(tt, ett_bacapp_list);
			break;
		case 3:	/* propertyArrayIndex Optional */
			offset = fUnsignedTag (tvb, subtree, offset, "Property Array Index: ");
			break;
		case 4:	/* propertyValue */
			if ((lvt == 6) && class_tag) {  offset++; /* opening Tag */
				offset = fAbstractSyntaxNType (tvb, subtree, offset);
				break;
			}
			FAULT;
			break;
		case 5:	/* propertyAccessError */
			if ((lvt == 6) && class_tag) {  offset++; /* opening Tag */
				/* Error Code follows */
				offset = fApplicationTypes   (tvb, subtree, offset, "error Class: ", BACnetErrorClass);
				offset = fApplicationTypes   (tvb, subtree, offset, "error Code: ", BACnetErrorCode);
				break;
			}
			FAULT;
			break;
		default:
			return offset;
		}
	}
	return offset;
}


static guint
fReadPropertyConditionalAck (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	/* listOfReadAccessResults */
	return fReadAccessResult (tvb, tree, offset);
}


static guint
fObjectSpecifier (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0:	/* objectType */
			proto_tree_add_item(tree, hf_bacapp_tag_initiatingObjectType, tvb, offset++, 1, TRUE);
			break;
		case 1:	/* objectIdentifier */
			offset = fObjectIdentifier (tvb, tree, offset);
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fCreateObjectRequest(tvbuff_t *tvb, proto_tree *subtree, guint offset)
{
    guint lastoffset = 0;
	guint8 tag_no, class_tag;
	guint32 lvt;

	while ((offset < tvb_reported_length(tvb)) && (offset > lastoffset)) {  /* exit loop if nothing happens inside */
        lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		if ((lvt == 7) && class_tag) {   /* closing Tag */
			offset++;
			continue;
		}
	
		switch (tag_no) {
		case 0:	/* objectSpecifier */
			offset = fObjectSpecifier (tvb, subtree, offset);
			break;
		case 1:	/* propertyValue */
			if ((lvt == 6) && class_tag) { offset++;  /* opening Tag */
				offset = fPropertyValue (tvb, subtree, offset);
				break;
			}
			FAULT;
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fCreateObjectAck (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	return fObjectIdentifier (tvb, tree, offset);
}

static guint
fReadRangeRequest (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;
	guint8 tag_no, class_tag;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		if ((lvt == 7) && class_tag) {   /* closing Tag */
			subtree = tree;
			offset++;
			continue;
		}
	
		switch (tag_no) {
		case 0:	/* objectSpecifier */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 1:	/* propertyIdentifier */
			offset = fPropertyIdentifier (tvb, subtree, offset, &tt);
			subtree = proto_item_add_subtree(tt, ett_bacapp_value);
			break;
		case 2:	/* propertyArrayIndex Optional */
			offset = fUnsignedTag (tvb, subtree, offset, "Property Array Index: ");
			break;
		case 3:	/* range byPosition */
			if ((lvt == 6) && class_tag) { offset++;  /* opening Tag */
				offset = fApplicationTypes   (tvb, subtree, offset, "reference Index: ", NULL);
				offset = fApplicationTypes   (tvb, subtree, offset, "reference Count: ", NULL);
				break;
			}
			FAULT;
			break;
		case 4:	/* range byTime */
			if ((lvt == 6) && class_tag) { offset++;  /* opening Tag */
				offset = fApplicationTypes   (tvb, subtree, offset, "reference Time: ", NULL);
				offset = fApplicationTypes   (tvb, subtree, offset, "reference Count: ", NULL);
				break;
			}
			FAULT;
			break;
		case 5:	/* range timeRange */
			if ((lvt == 6) && class_tag) { offset++;  /* opening Tag */
				offset = fApplicationTypes   (tvb, subtree, offset, "beginning Time: ", NULL);
				offset = fApplicationTypes   (tvb, subtree, offset, "ending Time: ", NULL);
				break;
			}
			FAULT;
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fReadRangeAck (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;
	guint8 tag_no, class_tag;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		if ((lvt == 7) && class_tag) {   /* closing Tag */
			subtree = tree;
			offset++;
			continue;
		}
	
		switch (tag_no) {
		case 0:	/* objectSpecifier */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 1:	/* propertyIdentifier */
			offset = fPropertyIdentifier (tvb, subtree, offset, &tt);
			subtree = proto_item_add_subtree(tt, ett_bacapp_value);
			break;
		case 2:	/* propertyArrayIndex Optional */
			offset = fUnsignedTag (tvb, subtree, offset, "Property Array Index: ");
			break;
		case 3:	/* resultFlags */
			offset = fApplicationTypes   (tvb, subtree, offset, "result Flags: ", BACnetResultFlags);
			break;
		case 4:	/* itemCount */
			offset = fUnsignedTag (tvb, subtree, offset, "item Count: ");
			break;
		case 5:	/* itemData */
			if ((lvt == 6) && class_tag) {  offset++; /* opening Tag */
				offset = fAbstractSyntaxNType   (tvb, subtree, offset);
				break;
			}
			FAULT;
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fAtomicReadFileRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;
	guint8 tag_no, class_tag;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	offset = fObjectIdentifier (tvb, tree, offset);

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
		if ((lvt == 7) && class_tag) {   /* closing Tag */
			offset++;
			subtree = tree;
			continue;
		}

		switch (tag_no) {
		case 0:	/* streamAccess */
			if ((lvt == 6) && class_tag) {   /* opening Tag */
				tt = proto_tree_add_text(subtree, tvb, offset++, 1, "stream Access");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset = fSignedTag (tvb, subtree, offset, "File Start Position: ");
				offset = fUnsignedTag (tvb, subtree, offset, "requestet Octet Count: ");
				break;
			}
			FAULT;
			break;
		case 1:	/* recordAccess */
			if ((lvt == 6) && class_tag) {   /* opening Tag */
				tt = proto_tree_add_text(subtree, tvb, offset++, 1, "record Access");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset = fSignedTag (tvb, subtree, offset, "File Start Record: ");
				offset = fUnsignedTag (tvb, subtree, offset, "requestet Record Count: ");
				break;
			}
			FAULT;
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fAtomicWriteFileRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint8 tag_no, class_tag;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	if ((bacapp_flags & 0x08) && (bacapp_seq != 0)) {	/* Segment of an Request */
		if (bacapp_flags & 0x04) { /* More Flag is set */
			offset = fOctetString (tvb, tree, offset, "file Data: ", 0);
		} else {
			offset = fOctetString (tvb, tree, offset, "file Data: ", tvb_reported_length(tvb) - offset - 1);
			fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
			if ((lvt == 7) && class_tag) {   /* closing Tag */
				offset++;
			}
		}
	} else {
		offset = fObjectIdentifier (tvb, tree, offset); /* file Identifier */

		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

		switch (tag_no) {
		case 0:	/* streamAccess */
			if ((lvt == 6) && class_tag) {   /* opening Tag */
				tt = proto_tree_add_text(tree, tvb, offset++, 1, "stream Access");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset = fSignedTag (tvb, subtree, offset, "File Start Position: ");
				offset = fApplicationTypes   (tvb, subtree, offset, "file Data: ", NULL);
			}
			if (bacapp_flags && 0x04) { /* More Flag is set */
				break;
			}
			fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
			if (((lvt == 7) && class_tag)) {   /* closing Tag */
				offset++;
				subtree = tree;
			}
			break;
		case 1:	/* recordAccess */
			if ((lvt == 6) && class_tag) {   /* opening Tag */
				tt = proto_tree_add_text(tree, tvb, offset++, 1, "stream Access");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset = fSignedTag (tvb, subtree, offset, "file Start Record: ");
				offset = fUnsignedTag (tvb, subtree, offset, "Record Count: ");
				offset = fApplicationTypes   (tvb, subtree, offset, "file Data: ", NULL);
			}
			if (bacapp_flags && 0x04) { /* More Flag is set */
				break;
			}
			fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
			if (((lvt == 7) && class_tag)) {   /* closing Tag */
				offset++;
				subtree = tree;
			}
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fAtomicWriteFileAck (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	switch (fTagNo(tvb, offset)) {
	case 0:	/* streamAccess */
		offset = fSignedTag (tvb, tree, offset, "File Start Position: ");
		break;
	case 1:	/* recordAccess */
		offset = fSignedTag (tvb, tree, offset, "File Start Record: ");
		break;
	default:
		return offset;
	}
	return offset;
}

static guint
fAtomicReadFileAck (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint8 tag_no, class_tag;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

	if ((bacapp_flags & 0x08) && (bacapp_seq != 0)) {	/* Segment of an Request */
		if (bacapp_flags & 0x04) { /* More Flag is set */
			offset = fOctetString (tvb, tree, offset, "File Data: ", 0);
		} else {
			offset = fOctetString (tvb, tree, offset, "File Data: ", tvb_reported_length(tvb)-offset-1);
			fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
			if ((lvt == 7) && class_tag) {   /* closing Tag */
				offset++;
			}
		}
	} else {
		offset = fApplicationTypes   (tvb, subtree, offset, "End Of File: ", NULL);

		fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);

		switch (tag_no) {
		case 0:	/* streamAccess */
			if ((lvt == 6) && class_tag) {   /* opening Tag */
				tt = proto_tree_add_text(tree, tvb, offset++, 1, "stream Access");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset = fSignedTag (tvb, subtree, offset, "File Start Position: ");
				offset = fApplicationTypes   (tvb, subtree, offset, "file Data: ", NULL);
			}
			if (bacapp_flags && 0x04) { /* More Flag is set */
				break;
			}
			fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
			if ((lvt == 7) && class_tag) {   /* closing Tag */
				offset++;
				subtree = tree;
			}
			break;
		case 1:	/* recordAccess */
			if ((lvt == 6) && class_tag) {   /* opening Tag */
				proto_tree_add_text(tree, tvb, offset++, 1, "stream Access {");
				offset = fSignedTag (tvb, subtree, offset, "File Start Record: ");
				offset = fUnsignedTag (tvb, subtree, offset, "returned Record Count: ");
				offset = fApplicationTypes   (tvb, subtree, offset, "Data: ", NULL);
			}
			if (bacapp_flags && 0x04) { /* More Flag is set */
				break;
			}
			fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
			if ((lvt == 7) && class_tag) {   /* closing Tag */
				offset++;
				subtree = tree;
			}
		break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fReadPropertyMultipleRequest(tvbuff_t *tvb, proto_tree *subtree, guint offset)
{
	return fReadAccessSpecification (tvb,subtree,offset);
}

static guint
fReadPropertyMultipleAck (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	return fReadAccessResult (tvb,tree,offset);
}

static guint
fConfirmedServiceRequest (tvbuff_t *tvb, proto_tree *tree, guint offset, gint service_choice)
{
	if (offset >= tvb_reported_length(tvb))
		return offset;

	switch (service_choice) {
	case 0:	/* acknowledgeAlarm */
		offset = fAcknowlegdeAlarmRequest (tvb, tree, offset);
		break;
	case 1: /* confirmedCOVNotification */
		offset = fConfirmedCOVNotificationRequest (tvb, tree, offset);
		break;
	case 2: /* confirmedEventNotification */
		offset = fConfirmedEventNotificationRequest (tvb, tree, offset);
		break;
	case 3: /* confirmedGetAlarmSummary conveys no parameters */
		break;
	case 4: /* getEnrollmentSummaryRequest */
		offset = fGetEnrollmentSummaryRequest (tvb, tree, offset);
		break;
	case 5: /* subscribeCOVRequest */
		offset = fSubscribeCOVRequest(tvb, tree, offset);
		break;
	case 6: /* atomicReadFile-Request */
		offset = fAtomicReadFileRequest(tvb, tree, offset);
		break;
	case 7: /* atomicWriteFile-Request */
		offset = fAtomicWriteFileRequest(tvb, tree, offset);
		break;
	case 8: /* AddListElement-Request */
		offset = fAddListElementRequest(tvb, tree, offset);
		break;
	case 9: /* removeListElement-Request */
		offset = fRemoveListElementRequest(tvb, tree, offset);
		break;
	case 10: /* createObjectRequest */
		offset = fCreateObjectRequest(tvb, tree, offset);
		break;
	case 11: /* deleteObject */
		offset = fDeleteObjectRequest(tvb, tree, offset);
		break;
	case 12:
		offset = fReadPropertyRequest(tvb, tree, offset);
		break;
	case 13:
		offset = fReadPropertyConditionalRequest(tvb, tree, offset);
		break;
	case 14:
		offset = fReadPropertyMultipleRequest(tvb, tree, offset);
		break;
	case 15:
		offset = fWritePropertyRequest(tvb, tree, offset);
		break;
	case 16:
		offset = fWritePropertyMultipleRequest(tvb, tree, offset);
		break;
	case 17:
		offset = fDeviceCommunicationControlRequest(tvb, tree, offset);
		break;
	case 18:
		offset = fConfirmedPrivateTransferRequest(tvb, tree, offset);
		break;
	case 19:
		offset = fConfirmedTextMessageRequest(tvb, tree, offset);
		break;
	case 20:
		offset = fReinitializeDeviceRequest(tvb, tree, offset);
		break;
	case 21:
		offset = fVtOpenRequest(tvb, tree, offset);
		break;
	case 22:
		offset = fVtCloseRequest (tvb, tree, offset);
		break;
	case 23:
		offset = fVtDataRequest (tvb, tree, offset);
		break;
	case 24:
		offset = fAuthenticateRequest (tvb, tree, offset);
		break;
	case 25:
		offset = fRequestKeyRequest (tvb, tree, offset);
		break;
	case 26:
		offset = fReadRangeRequest (tvb, tree, offset);
		break;
	case 27:
		offset = fLifeSafetyOperationRequest(tvb, tree, offset, NULL);
		break;
	case 28:
		offset = fSubscribeCOVPropertyRequest(tvb, tree, offset);
		break;
	case 29:
		offset = fGetEventInformationRequest (tvb, tree, offset);
		break;
	default:
		return offset;
		break;
	}
	return offset;
}

static guint
fConfirmedServiceAck (tvbuff_t *tvb, proto_tree *tree, guint offset, gint service_choice)
{
	if (offset >= tvb_reported_length(tvb))
		return offset;

	switch (service_choice) {
	case 3: /* confirmedEventNotificationAck */
		offset = fGetAlarmSummaryAck (tvb, tree, offset);
		break;
	case 4: /* getEnrollmentSummaryAck */
		offset = fGetEnrollmentSummaryAck (tvb, tree, offset);
		break;
	case 6: /* atomicReadFile */
		offset = fAtomicReadFileAck (tvb, tree, offset);
		break;
	case 7: /* atomicReadFileAck */
		offset = fAtomicWriteFileAck (tvb, tree, offset);
		break;
	case 10: /* createObject */
		offset = fCreateObjectAck (tvb, tree, offset);
		break;
	case 12:
		offset = fReadPropertyAck (tvb, tree, offset);
		break;
	case 13:
		offset = fReadPropertyConditionalAck (tvb, tree, offset);
		break;
	case 14:
		offset = fReadPropertyMultipleAck (tvb, tree, offset);
		break;
	case 18:
		offset = fConfirmedPrivateTransferAck(tvb, tree, offset);
		break;
	case 21:
		offset = fVtOpenAck (tvb, tree, offset);
		break;
	case 23:
		offset = fVtDataAck (tvb, tree, offset);
		break;
	case 24:
		offset = fAuthenticateAck (tvb, tree, offset);
		break;
	case 26:
		offset = fReadRangeAck (tvb, tree, offset);
		break;
	case 29:
		offset = fGetEventInformationACK (tvb, tree, offset);
		break;
	default:
		return offset;
	}
	return offset;
}

static guint
fIAmRequest  (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint8 tmp, tag_no, class_tag;
	guint32 lvt, val = 0, i;

	/* BACnetObjectIdentifier */
	offset = fApplicationTypes   (tvb, tree, offset, "BACnet Object Identifier: ", NULL);

	/* MaxAPDULengthAccepted */
	offset = fApplicationTypes   (tvb, tree, offset, "Maximum ADPU Length accepted: ", NULL);

	/* segmentationSupported */
	fTagHeader (tvb, offset, &tag_no, &class_tag, &lvt);
	offset++;	/* set offset according to enhancements.... */
	for (i = 0; i < min(lvt, 4); i++) {
		tmp = tvb_get_guint8(tvb, offset+i);
		val = (val << 8) + tmp;
	}
	proto_tree_add_text(tree, tvb, offset, 1, "segmentation Supported: %s", val_to_str(val, BACnetSegmentation, "segmentation (%d) not found"));
	offset+=lvt;

	/* vendor ID */
	return fUnsignedTag (tvb, tree, offset, "vendor ID: ");
}

static guint
fIHaveRequest  (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	/* BACnetDeviceIdentifier */
	offset = fApplicationTypes   (tvb, tree, offset, "Device Identifier: ", NULL);

	/* BACnetObjectIdentifier */
	offset = fApplicationTypes   (tvb, tree, offset, "Object Identifier: ", NULL);

	/* ObjectName */
	return fApplicationTypes   (tvb, tree, offset, "Object Name: ", NULL);

}

static guint
fWhoIsRequest  (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0:	/* DeviceInstanceRangeLowLimit Optional */
			offset = fUnsignedTag (tvb, tree, offset, "Device Instance Range Low Limit: ");
			break;
		case 1:	/* DeviceInstanceRangeHighLimit Optional but required if DeviceInstanceRangeLowLimit is there */
			offset = fUnsignedTag (tvb, tree, offset, "Device Instance Range High Limit: ");
			break;
		default:
			return offset;
			break;
		}
	}
 	return offset;
}

static guint
fUnconfirmedServiceRequest  (tvbuff_t *tvb, proto_tree *tree, guint offset, gint service_choice)
{
	if (offset >= tvb_reported_length(tvb))
		return offset;
	
	switch (service_choice) {
	case 0:	/* I-Am-Request */
		offset = fIAmRequest  (tvb, tree, offset);
		break;
	case 1: /* i-Have Request */
		offset = fIHaveRequest  (tvb, tree, offset);
	break;
	case 2: /* unconfirmedCOVNotification */
		offset = fUnconfirmedCOVNotificationRequest (tvb, tree, offset);
		break;
	case 3: /* unconfirmedEventNotification */
		offset = fUnconfirmedEventNotificationRequest (tvb, tree, offset);
		break;
	case 4: /* unconfirmedPrivateTransfer */
		offset = fUnconfirmedPrivateTransferRequest(tvb, tree, offset);
		break;
	case 5: /* unconfirmedTextMessage */
		offset = fUnconfirmedTextMessageRequest(tvb, tree, offset);
		break;
	case 6: /* timeSynchronization */
		offset = fTimeSynchronizationRequest  (tvb, tree, offset);
		break;
	case 7: /* who-Has */
		offset = fWhoHas (tvb, tree, offset);
		break;
	case 8: /* who-Is */
		offset = fWhoIsRequest  (tvb, tree, offset);
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
fConfirmedRequestPDU(tvbuff_t *tvb, proto_tree *tree, guint offset)
{	/* BACnet-Confirmed-Request */
	/* ASHRAE 135-2001 20.1.2 */

	proto_item *tc, *tt, *ti;
	proto_tree *bacapp_tree, *bacapp_tree_control, *bacapp_tree_tag;
	gint tmp, bacapp_type, service_choice;

	tmp = (gint) tvb_get_guint8(tvb, offset);
	bacapp_type = (tmp >> 4) & 0x0f;
	bacapp_flags = tmp & 0x0f;

	service_choice = (gint) tvb_get_guint8(tvb, offset+3);
	if (bacapp_flags & 0x08)
		service_choice = (gint) tvb_get_guint8(tvb, offset+5);

    ti = proto_tree_add_item(tree, proto_bacapp, tvb, offset, -1, FALSE);
    bacapp_tree = proto_item_add_subtree(ti, ett_bacapp);

    tc = proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, offset, 1, TRUE);
    bacapp_tree_control = proto_item_add_subtree(tc, ett_bacapp);

    proto_tree_add_item(bacapp_tree_control, hf_bacapp_SEG, tvb, offset, 1, TRUE);
    proto_tree_add_item(bacapp_tree_control, hf_bacapp_MOR, tvb, offset, 1, TRUE);
    proto_tree_add_item(bacapp_tree_control, hf_bacapp_SA, tvb, offset++, 1, TRUE);
    proto_tree_add_item(bacapp_tree_control, hf_bacapp_response_segments, tvb,
                        offset, 1, TRUE);
    proto_tree_add_item(bacapp_tree_control, hf_bacapp_max_adpu_size, tvb,
                        offset, 1, TRUE);
    offset++;
    proto_tree_add_item(bacapp_tree, hf_bacapp_invoke_id, tvb, offset++, 1, TRUE);
    if (bacapp_flags & 0x08) {
        bacapp_seq = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(bacapp_tree_control, hf_bacapp_sequence_number, tvb,
            offset++, 1, TRUE);
        proto_tree_add_item(bacapp_tree_control, hf_bacapp_window_size, tvb,
            offset++, 1, TRUE);
    }
    tmp = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(bacapp_tree, hf_bacapp_service, tvb,
        offset++, 1, TRUE);
    tt = proto_tree_add_item(bacapp_tree, hf_bacapp_vpart, tvb,
        offset, 0, TRUE);
    /* Service Request follows... Variable Encoding 20.2ff */
    bacapp_tree_tag = proto_item_add_subtree(tt, ett_bacapp_tag);
    return fConfirmedServiceRequest (tvb, bacapp_tree_tag, offset, tmp);
}

static guint
fUnconfirmedRequestPDU(tvbuff_t *tvb, proto_tree *tree, guint offset)
{	/* BACnet-Unconfirmed-Request-PDU */
	/* ASHRAE 135-2001 20.1.3 */

	proto_item *tt, *ti;
	proto_tree *bacapp_tree_tag, *bacapp_tree;
	gint tmp;

	tmp = tvb_get_guint8(tvb, offset+1);

    ti = proto_tree_add_item(tree, proto_bacapp, tvb, offset, -1, FALSE);
    bacapp_tree = proto_item_add_subtree(ti, ett_bacapp);

    proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, offset++, 1, TRUE);

    tmp = tvb_get_guint8(tvb, offset);
    tt = proto_tree_add_item(bacapp_tree, hf_bacapp_uservice, tvb,
            offset++, 1, TRUE);
    /* Service Request follows... Variable Encoding 20.2ff */
    bacapp_tree_tag = proto_item_add_subtree(tt, ett_bacapp_tag);
    return fUnconfirmedServiceRequest  (tvb, bacapp_tree_tag, offset, tmp);
}

static guint
fSimpleAckPDU(tvbuff_t *tvb, proto_tree *tree, guint offset)
{	/* BACnet-Simple-Ack-PDU */
	/* ASHRAE 135-2001 20.1.4 */

	proto_item *tc, *ti;
	gint tmp;
	proto_tree *bacapp_tree;

	tmp = tvb_get_guint8(tvb, offset+2);

    ti = proto_tree_add_item(tree, proto_bacapp, tvb, offset, -1, FALSE);
    bacapp_tree = proto_item_add_subtree(ti, ett_bacapp);

    tc = proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, offset++, 1, TRUE);

    proto_tree_add_item(bacapp_tree, hf_bacapp_invoke_id, tvb,
        offset++, 1, TRUE);
    proto_tree_add_item(bacapp_tree, hf_bacapp_service, tvb,
        offset++, 1, TRUE);
	return offset;
}

static guint
fComplexAckPDU(tvbuff_t *tvb, proto_tree *tree, guint offset)
{	/* BACnet-Complex-Ack-PDU */
	/* ASHRAE 135-2001 20.1.5 */

	proto_item *tc, *tt, *ti;
	proto_tree *bacapp_tree, *bacapp_tree_control, *bacapp_tree_tag;
	gint tmp, bacapp_type;

	tmp = (gint) tvb_get_guint8(tvb, offset);
	bacapp_type = (tmp >> 4) & 0x0f;
	bacapp_flags = tmp & 0x0f;

	tmp = tvb_get_guint8(tvb, offset+2);
	if (bacapp_flags & 0x08)
		tmp = tvb_get_guint8(tvb, offset+4);

    ti = proto_tree_add_item(tree, proto_bacapp, tvb, offset, -1, FALSE);
    bacapp_tree = proto_item_add_subtree(ti, ett_bacapp);

    tc = proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, offset, 1, TRUE);
    bacapp_tree_control = proto_item_add_subtree(tc, ett_bacapp);

    proto_tree_add_item(bacapp_tree, hf_bacapp_SEG, tvb, offset, 1, TRUE);
    proto_tree_add_item(bacapp_tree, hf_bacapp_MOR, tvb, offset++, 1, TRUE);
    proto_tree_add_item(bacapp_tree, hf_bacapp_invoke_id, tvb,
        offset++, 1, TRUE);
    if (bacapp_flags & 0x08) {
        bacapp_seq = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(bacapp_tree, hf_bacapp_sequence_number, tvb,
            offset++, 1, TRUE);
        proto_tree_add_item(bacapp_tree, hf_bacapp_window_size, tvb,
            offset++, 1, TRUE);
    }
    tmp = tvb_get_guint8(tvb, offset);
    tt = proto_tree_add_item(bacapp_tree, hf_bacapp_service, tvb,
        offset++, 1, TRUE);
    /* Service ACK follows... */
    bacapp_tree_tag = proto_item_add_subtree(tt, ett_bacapp_tag);
    return fConfirmedServiceAck (tvb, bacapp_tree_tag, offset, tmp);
}


static guint
fSegmentAckPDU(tvbuff_t *tvb, proto_tree *tree, guint offset)
{	/* BACnet-SegmentAck-PDU */
	/* ASHRAE 135-2001 20.1.6 */

	proto_item *tc, *ti;
	proto_tree *bacapp_tree_control, *bacapp_tree;

    ti = proto_tree_add_item(tree, proto_bacapp, tvb, offset, -1, FALSE);
    bacapp_tree = proto_item_add_subtree(ti, ett_bacapp);

    tc = proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, offset, 1, TRUE);
    bacapp_tree_control = proto_item_add_subtree(tc, ett_bacapp);

    proto_tree_add_item(bacapp_tree, hf_bacapp_NAK, tvb, offset, 1, TRUE);
    proto_tree_add_item(bacapp_tree, hf_bacapp_SRV, tvb, offset++, 1, TRUE);
    proto_tree_add_item(bacapp_tree, hf_bacapp_invoke_id, tvb,
        offset++, 1, TRUE);
    proto_tree_add_item(bacapp_tree, hf_bacapp_sequence_number, tvb,
            offset++, 1, TRUE);
    proto_tree_add_item(bacapp_tree, hf_bacapp_window_size, tvb,
            offset++, 1, TRUE);
	return offset;
}

static guint
fConfirmedPrivateTransferError(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0:	/* errorType */
			offset = fError (tvb,tree,offset);
			break;
		case 1:	/* vendorID */
			offset = fUnsignedTag (tvb,tree,offset,"vendor ID: ");
			break;
		case 2:	/* serviceNumber */
			offset = fUnsignedTag (tvb,tree,offset,"service Number: ");
			break;
        case 3: /* errorParameters */
            offset = fAbstractSyntaxNType   (tvb, tree, offset);
            break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fCreateObjectError(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0:	/* errorType */
			offset = fError (tvb,tree,offset);
			break;
		case 1:	/* firstFailedElementNumber */
			offset = fUnsignedTag (tvb,tree,offset,"first failed element number: ");
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fChangeListError(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0:	/* errorType */
			offset = fError (tvb,tree,offset);
			break;
		case 1:	/* firstFailedElementNumber */
			offset = fUnsignedTag (tvb,tree,offset,"first failed element number: ");
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fVTSession(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	if (offset < tvb_reported_length(tvb)) {	/* don't loop */
		offset = fUnsignedTag (tvb,tree,offset, "local-VTSessionID: ");
		offset = fUnsignedTag (tvb,tree,offset, "remote-VTSessionID: ");
		offset = fAddress (tvb,tree,offset);
	}
	return offset;
}

static guint
fVTCloseError(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0:	/* errorType */
			offset = fError (tvb,tree,offset);
			break;
		case 1:	/* listOfVTSessionIdentifiers */
			offset = fUnsignedTag (tvb,tree,offset,"VT SessionID: ");
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fWritePropertyMultipleError(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint lastoffset = 0;

	while ((offset < tvb_reported_length(tvb))&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */ 
        lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0:	/* errorType */
			offset = fError (tvb,tree,offset);
			break;
		case 1:	/* firstFailedWriteAttempt */
			offset = fUnsignedTag (tvb,tree,offset,"first failed write attempt: ");
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint
fError (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    offset = fApplicationTypes   (tvb, tree, offset, "error Class: ", BACnetErrorClass);
    return fApplicationTypes   (tvb, tree, offset, "error Code: ", BACnetErrorCode);
}

static guint
fBACnetError (tvbuff_t *tvb, proto_tree *tree, guint offset, guint service)
{
    switch (service) {
    case 8:  /* no break here !!!! */
    case 9:
        offset = fChangeListError (tvb, tree, offset);
        break;
    case 10:
        offset = fCreateObjectError (tvb,tree,offset);
        break;
    case 16:
        offset = fWritePropertyMultipleError (tvb,tree,offset);
        break;
    case 18:
        offset = fConfirmedPrivateTransferError (tvb,tree,offset);
    case 22:
        offset = fVTCloseError (tvb,tree,offset);
    default:
        return fError (tvb, tree, offset);
        break;
    }
    return offset;
}

static guint
fErrorPDU(tvbuff_t *tvb, proto_tree *tree, guint offset)
{	/* BACnet-Error-PDU */
	/* ASHRAE 135-2001 20.1.7 */

	proto_item *tc, *ti, *tt;
	proto_tree *bacapp_tree_control, *bacapp_tree, *bacapp_tree_tag;
    guint8 tmp;

    ti = proto_tree_add_item(tree, proto_bacapp, tvb, offset, -1, FALSE);
    bacapp_tree = proto_item_add_subtree(ti, ett_bacapp);

    tc = proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, offset++, 1, TRUE);
    bacapp_tree_control = proto_item_add_subtree(tc, ett_bacapp);

    proto_tree_add_item(bacapp_tree, hf_bacapp_invoke_id, tvb,
        offset++, 1, TRUE);
    tmp = tvb_get_guint8(tvb, offset);
    tt = proto_tree_add_item(bacapp_tree, hf_bacapp_service, tvb,
        offset++, 1, TRUE);
    /* Error Handling follows... */
    bacapp_tree_tag = proto_item_add_subtree(tt, ett_bacapp_tag);
    return fBACnetError (tvb, bacapp_tree_tag, offset, tmp);
}

static guint
fRejectPDU(tvbuff_t *tvb, proto_tree *tree, guint offset)
{	/* BACnet-Reject-PDU */
	/* ASHRAE 135-2001 20.1.8 */

	proto_item *tc, *ti;
	proto_tree *bacapp_tree_control, *bacapp_tree;

    ti = proto_tree_add_item(tree, proto_bacapp, tvb, offset, -1, FALSE);
    bacapp_tree = proto_item_add_subtree(ti, ett_bacapp);

    tc = proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, offset++, 1, TRUE);
    bacapp_tree_control = proto_item_add_subtree(tc, ett_bacapp);

    proto_tree_add_item(bacapp_tree, hf_bacapp_invoke_id, tvb,
        offset++, 1, TRUE);
    proto_tree_add_item(bacapp_tree, hf_BACnetRejectReason, tvb,
        offset++, 1, TRUE);
	return offset;
}

static guint
fAbortPDU(tvbuff_t *tvb, proto_tree *tree, guint offset)
{	/* BACnet-Abort-PDU */
	/* ASHRAE 135-2001 20.1.9 */

	proto_item *tc, *ti;
	proto_tree *bacapp_tree_control, *bacapp_tree;

    ti = proto_tree_add_item(tree, proto_bacapp, tvb, offset, -1, FALSE);
    bacapp_tree = proto_item_add_subtree(ti, ett_bacapp);

    tc = proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, offset, 1, TRUE);
    bacapp_tree_control = proto_item_add_subtree(tc, ett_bacapp);

    proto_tree_add_item(bacapp_tree, hf_bacapp_SRV, tvb, offset++, 1, TRUE);
    proto_tree_add_item(bacapp_tree, hf_bacapp_invoke_id, tvb,
        offset++, 1, TRUE);
    proto_tree_add_item(bacapp_tree, hf_BACnetAbortReason, tvb,
        offset++, 1, TRUE);
	return offset;
}

void
dissect_bacapp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint8 tmp, bacapp_type;
	tvbuff_t *next_tvb;
	guint offset = 0;
    guint8 bacapp_service, bacapp_reason;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "BACnet-APDU");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_str(pinfo->cinfo, COL_INFO, "BACnet APDU ");
	
    tmp = (gint) tvb_get_guint8(tvb, 0);
	bacapp_type = (tmp >> 4) & 0x0f;

	/* show some descriptive text in the INFO column */
	if (check_col(pinfo->cinfo, COL_INFO))
	{
		col_clear(pinfo->cinfo, COL_INFO);
		col_add_str(pinfo->cinfo, COL_INFO,
			val_to_str(bacapp_type, BACnetTypeName, "#### unknown APDU ##### "));
		switch (bacapp_type)
		{
			case BACAPP_TYPE_CONFIRMED_SERVICE_REQUEST:
				/* segmented messages have 2 additional bytes */
				if (tmp & BACAPP_SEGMENTED_REQUEST)
					bacapp_service = tvb_get_guint8(tvb, offset + 5);
				else
					bacapp_service = tvb_get_guint8(tvb, offset + 3);
				col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
					val_to_str(bacapp_service, 
						BACnetConfirmedServiceChoice,
						bacapp_unknown_service_str));
				break;
			case BACAPP_TYPE_UNCONFIRMED_SERVICE_REQUEST:
				bacapp_service = tvb_get_guint8(tvb, offset + 1);
				col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
					val_to_str(bacapp_service, 
						BACnetUnconfirmedServiceChoice,
						bacapp_unknown_service_str));
				break;
			case BACAPP_TYPE_SIMPLE_ACK:
				bacapp_service = tvb_get_guint8(tvb, offset + 2);
				col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
					val_to_str(bacapp_service, 
						BACnetConfirmedServiceChoice,
						bacapp_unknown_service_str));
				break;
			case BACAPP_TYPE_COMPLEX_ACK:
				/* segmented messages have 2 additional bytes */
				if (tmp & BACAPP_SEGMENTED_REQUEST)
					bacapp_service = tvb_get_guint8(tvb, offset + 4);
				else
					bacapp_service = tvb_get_guint8(tvb, offset + 2);
				col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
					val_to_str(bacapp_service, 
						BACnetConfirmedServiceChoice,
						bacapp_unknown_service_str));
				break;
			case BACAPP_TYPE_SEGMENT_ACK:
				/* nothing more to add */
				break;
			case BACAPP_TYPE_ERROR:
				bacapp_service = tvb_get_guint8(tvb, offset + 2);
				col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
					val_to_str(bacapp_service, 
						BACnetConfirmedServiceChoice,
						bacapp_unknown_service_str));
				break;
			case BACAPP_TYPE_REJECT:
				bacapp_reason = tvb_get_guint8(tvb, offset + 2);
				col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", 
                    val_to_str(bacapp_reason, 
						BACnetRejectReason,
						bacapp_unknown_service_str));
				break;
			case BACAPP_TYPE_ABORT:
				bacapp_reason = tvb_get_guint8(tvb, offset + 2);
				col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
					val_to_str(bacapp_reason, 
						BACnetAbortReason,
						bacapp_unknown_service_str));
				break;
			/* UNKNOWN */
			default:
				/* nothing more to add */
				break;
		}
	}
   
    if (tree) {
    	/* ASHRAE 135-2001 20.1.1 */
    	switch (bacapp_type) {
    	case BACAPP_TYPE_CONFIRMED_SERVICE_REQUEST:	/* BACnet-Confirmed-Service-Request */
    		offset = fConfirmedRequestPDU(tvb, tree, offset);
    		break;
    	case BACAPP_TYPE_UNCONFIRMED_SERVICE_REQUEST:	/* BACnet-Unconfirmed-Request-PDU */
    		offset = fUnconfirmedRequestPDU(tvb, tree, offset);
    		break;
    	case BACAPP_TYPE_SIMPLE_ACK:	/* BACnet-Simple-Ack-PDU */
    		offset = fSimpleAckPDU(tvb, tree, offset);
    		break;
    	case BACAPP_TYPE_COMPLEX_ACK:	/* BACnet-Complex-Ack-PDU */
    		offset = fComplexAckPDU(tvb, tree, offset);
    		break;
    	case BACAPP_TYPE_SEGMENT_ACK:	/* BACnet-SegmentAck-PDU */
    		offset = fSegmentAckPDU(tvb, tree, offset);
    		break;
    	case BACAPP_TYPE_ERROR:	/* BACnet-Error-PDU */
    		offset = fErrorPDU(tvb, tree, offset);
    		break;
    	case BACAPP_TYPE_REJECT:	/* BACnet-Reject-PDU */
    		offset = fRejectPDU(tvb, tree, offset);
    		break;
    	case BACAPP_TYPE_ABORT:	/* BACnet-Abort-PDU */
    		offset = fAbortPDU(tvb, tree, offset);
    		break;
    	}
    }

	next_tvb = tvb_new_subset(tvb,offset,-1,tvb_reported_length(tvb) - offset);
	call_dissector(data_handle,next_tvb, pinfo, tree);
}

void
proto_register_bacapp(void)
{
	static hf_register_info hf[] = {
		{ &hf_bacapp_type,
			{ "APDU Type",           "bacapp.type",
			FT_UINT8, BASE_DEC, VALS(BACnetTypeName), 0xf0, "APDU Type", HFILL }
		},
		{ &hf_bacapp_SEG,
			{ "Segmented Request",           "bacapp.segmented_request",
			FT_BOOLEAN, 8, TFS(&segments_follow), 0x08, "Segmented Request", HFILL }
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
			FT_UINT8, BASE_DEC, VALS(BACnetMaxAPDULengthAccepted), 0x0f, "Size of Maximum ADPU accepted", HFILL }
		},
		{ &hf_bacapp_response_segments,
			{ "Max Response Segments accepted",           "bacapp.response_segments",
			FT_UINT8, BASE_DEC, VALS(BACnetMaxSegmentsAccepted), 0xe0, "Max Response Segments accepted", HFILL }
		},
		{ &hf_bacapp_objectType,
			{ "Object Type",           "bacapp.objectType",
			FT_UINT32, BASE_DEC, VALS(BACnetObjectType), 0xffc00000, "Object Type", HFILL }
		},
		{ &hf_bacapp_instanceNumber,
			{ "Instance Number",           "bacapp.instance_number",
			FT_UINT32, BASE_DEC, NULL, 0x003fffff, "Instance Number", HFILL }
		},
		{ &hf_bacapp_invoke_id,
			{ "Invoke ID",           "bacapp.invoke_id",
			FT_UINT8, BASE_HEX, NULL, 0, "Invoke ID", HFILL }
		},
		{ &hf_bacapp_sequence_number,
			{ "Sequence Number",           "bacapp.sequence_number",
			FT_UINT8, BASE_DEC, NULL, 0, "Sequence Number", HFILL }
		},
		{ &hf_bacapp_window_size,
			{ "Proposed Window Size",           "bacapp.window_size",
			FT_UINT8, BASE_DEC, NULL, 0, "Proposed Window Size", HFILL }
		},
		{ &hf_bacapp_service,
			{ "Service Choice",           "bacapp.confirmed_service",
			FT_UINT8, BASE_DEC, VALS(BACnetConfirmedServiceChoice), 0x00, "Service Choice", HFILL }
		},
		{ &hf_bacapp_uservice,
			{ "Unconfirmed Service Choice",           "bacapp.unconfirmed_service",
			FT_UINT8, BASE_DEC, VALS(BACnetUnconfirmedServiceChoice), 0x00, "Unconfirmed Service Choice", HFILL }
		},
		{ &hf_bacapp_NAK,
			{ "NAK",           "bacapp.NAK",
			FT_BOOLEAN, 8, NULL, 0x02, "negativ ACK", HFILL }
		},
		{ &hf_bacapp_SRV,
			{ "SRV",           "bacapp.SRV",
			FT_BOOLEAN, 8, NULL, 0x01, "Server", HFILL }
		},
		{ &hf_BACnetRejectReason,
			{ "Reject Reason",           "bacapp.reject_reason",
			FT_UINT8, BASE_DEC, VALS(BACnetRejectReason), 0x00, "Reject Reason", HFILL }
		},
		{ &hf_BACnetAbortReason,
			{ "Abort Reason",           "bacapp.abort_reason",
			FT_UINT8, BASE_DEC, VALS(BACnetAbortReason), 0x00, "Abort Reason", HFILL }
		},
		{ &hf_bacapp_vpart,
			{ "BACnet APDU variable part:",           "bacapp.variable_part",
			FT_NONE, 0, NULL, 00, "BACnet APDU varaiable part", HFILL }
		},
		{ &hf_BACnetTagNumber,
			{ "Tag Number",           "bacapp.tag_number",
			FT_UINT8, BASE_DEC, VALS(BACnetTagNumber), 0xF0, "Tag Number", HFILL }
		},
		{ &hf_BACnetTagClass,
			{ "Class",           "bacapp.class",
			FT_BOOLEAN, 8, TFS(&BACnetTagClass), 0x08, "Class", HFILL }
		},
		{ &hf_bacapp_tag_lvt,
			{ "Length Value Type",           "bacapp.LVT",
			FT_UINT8, BASE_DEC, NULL, 0x07, "Length Value Type", HFILL }
		},
		{ &hf_bacapp_tag_ProcessId,
			{ "ProcessIdentifier",           "bacapp.processId",
			FT_UINT32, BASE_DEC, NULL, 0, "Process Identifier", HFILL }
		},
		{ &hf_bacapp_tag_initiatingObjectType,
			{ "ObjectType",           "bacapp.objectType",
			FT_UINT16, BASE_DEC, VALS(BACnetObjectType), 0x00, "Object Type", HFILL }
		},
	};
	static gint *ett[] = {
		&ett_bacapp,
		&ett_bacapp_control,
		&ett_bacapp_tag,
		&ett_bacapp_list,
		&ett_bacapp_value,
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

guint32
fConvertXXXtoUTF8 (guint8 *in, guint32 *inbytesleft, guint8 *out, guint32 *outbytesleft, guint8 *fromcoding)
{  /* I don't want to let in and out be modified */
#ifdef HAVE_CONFIG_H
#if HAVE_ICONV_H
	guint32 i; 
    iconv_t icd;
	guint8 *inp = in, *outp = out;
	guint8 **inpp = &inp, **outpp = &outp;
     
    if ((icd = iconv_open ("UTF-8", fromcoding)) != (iconv_t) -1) {

        i = iconv (icd, (char**) inpp, inbytesleft, (char**) outpp, outbytesleft);
		*outpp[0] = '\0';
        iconv_close (icd);
        return i;
    }

#endif
#endif

    memcpy (out, in, *inbytesleft);
    out[*inbytesleft] = '\0';
	*outbytesleft -= *inbytesleft;
    *inbytesleft = 0;

    return 0;
}

