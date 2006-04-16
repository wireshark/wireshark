/* packet-bacapp.c
 * Routines for BACnet (APDU) dissection
 * Copyright 2001, Hartmut Mueller <hartmut@abmlinux.org>, FH Dortmund
 * Enhanced by Steve Karg, 2005, <skarg@users.sourceforge.net>, Atlanta
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

/* some necessary forward function prototypes */
static guint
fApplicationTypesEnumerated (tvbuff_t *tvb, proto_tree *tree, guint offset, 
	const gchar *label, const value_string *vs);

static const char *bacapp_unknown_service_str = "unknown service";
static const char *ASHRAE_Reserved_Fmt = "(%d) Reserved for Use by ASHRAE";
static const char *Vendor_Proprietary_Fmt = "(%d) Vendor Proprietary Value";

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
	{23,"accumulator object"},
	{24,"pulse-converter object"},
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
	{0,NULL}
/* Enumerated values 0-255 are reserved for definition by ASHRAE. 
   Enumerated values 256-65535 may be used by others subject to 
   the procedures and constraints described in Clause 23. */
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
	{47,"datatype-not-supported"},
	{48,"duplicate-name"},
	{49,"duplicate-object-id"},
	{50,"property-is-not-an-array"},
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
	{169,"auto-slave-discovery"},
	{170,"manual-slave-address-binding"},
	{171,"slave-address-binding"},
	{172,"slave-proxy-enable"},
	{173,"last-notify-time"},
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
	{9,"extended" },
	{10,"buffer-ready" },
	{11,"unsigned-range" },
	{0,NULL },
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
	{0,NULL },
/* Enumerated values 0-63 are reserved for definition by ASHRAE. 
   Enumerated values 64-65535 may be used by others subject to 
   the procedures and constraints described in Clause 23.  */
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
static int hf_BACnetRejectReason = -1;
static int hf_BACnetAbortReason = -1;
static int hf_BACnetApplicationTagNumber = -1;
static int hf_BACnetContextTagNumber = -1;
static int hf_BACnetExtendedTagNumber = -1;
static int hf_BACnetNamedTag = -1;
static int hf_BACnetTagClass = -1;
static int hf_BACnetCharacterSet = -1;
static int hf_bacapp_tag = -1;
static int hf_bacapp_tag_lvt = -1;
static int hf_bacapp_tag_value8 = -1;
static int hf_bacapp_tag_value16 = -1;
static int hf_bacapp_tag_value32 = -1;
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
static guint32 object_type = 4096;

static guint8 bacapp_flags = 0;
static guint8 bacapp_seq = 0;

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
static gboolean tag_is_extended_value(guint8 tag)
{
	return (tag & 0x07) == 5;
}

static gboolean tag_is_opening(guint8 tag)
{
	return (tag & 0x07) == 6;
}

static gboolean tag_is_closing(guint8 tag)
{
	return (tag & 0x07) == 7;
}

/* from clause 20.2.1.1 Class
   class bit shall be one for context specific tags */
/* returns true if the tag is context specific */
static gboolean tag_is_context_specific(guint8 tag)
{
	return (tag & 0x08) != 0;
}

static gboolean tag_is_extended_tag_number(guint8 tag)
{
	return ((tag & 0xF0) == 0xF0);
}

static guint32 object_id_type(guint32 object_identifier)
{
	return ((object_identifier >> 22) & 0x3FF);
}

static guint32 object_id_instance(guint32 object_identifier)
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

/* BACnet Signed Value uses 2's compliment notation, but with a twist:
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
	guint8 data, i;

	/* we can only handle 7 bytes for a 64-bit value due to signed-ness */
	if (lvt && (lvt <= 7)) {
		valid = TRUE;
		data = tvb_get_guint8(tvb, offset);
		if ((data & 0x80) != 0)
			value = (-1 << 8) | data;
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
	if (tree)
	{
		if (tag_is_closing(tag) || tag_is_opening(tag))
			ti = proto_tree_add_text(tree, tvb, offset, tag_len,
				"%s: %u", match_strval(
					tag & 0x07, BACnetTagNames),
				*tag_no);
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
	guint tag_len;
	proto_item *ti;
	proto_tree *subtree;
	guint bool_len = 1;

	tag_len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	if (tag_info && lvt == 1)
	{
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
			"%s(Unsigned) %" PRIu64, label, val);
	else
		ti = proto_tree_add_text(tree, tvb, offset, lvt+tag_len,
			"%s - %u octets (Unsigned)", label, lvt);
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
			"%s(Signed) %" PRId64, label, val);
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
	gfloat f_val = 0.0;
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
	gdouble d_val = 0.0;
	proto_item *ti;
	proto_tree *subtree;
	
	tag_len = fTagHeader(tvb, offset, &tag_no, &tag_info, &lvt);
	d_val = tvb_get_ntohieee_double(tvb, offset+tag_len);
	ti = proto_tree_add_text(tree, tvb, offset, 8+tag_len,
		"%s%lf (Double)", label, d_val);
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
	
	return offset+tag_len+lvt;
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
                        val_to_str(dayOfWeek, days, "day of week (%d) not found"));
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
	if ((year == 255) && (day == 255) && (month == 255) && (weekday == 255))
	{
		ti = proto_tree_add_text(tree, tvb, offset, lvt+tag_len,
			"%sany", label);
	}
	else if (year != 255)
	{
		year += 1900;
		ti = proto_tree_add_text(tree, tvb, offset, lvt+tag_len,
			"%s%s %d, %d, (Day of Week = %s)",
			label, val_to_str(month,
				months,
				"month (%d) not found"),
			day, year, val_to_str(weekday,
				days,
				"(%d) not found"));
	}
	else
	{
		ti = proto_tree_add_text(tree, tvb, offset, lvt+tag_len,
			"%s%s %d, any year, (Day of Week = %s)",
			label, val_to_str(month, months, "month (%d) not found"),
			day, val_to_str(weekday, days, "(%d) not found"));
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
			hour > 12 ? "P.M." : "A.M.",
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
fTimeValue (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;                               

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {   /* closing Tag, but not for me */
			return offset;
		}
		offset = fTime    (tvb,tree,offset,"Time: ");
		offset = fApplicationTypes(tvb, tree, offset, "Value: ");
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
		break;
	}

	return offset;
}

static guint
fTimeStamp (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint8 tag_no = 0, tag_info = 0;
	guint32 lvt = 0;

	if (tvb_length_remaining(tvb, offset) > 0) {	/* don't loop, it's a CHOICE */
		switch (fTagNo(tvb, offset)) {
		case 0:	/* time */
			offset = fTime (tvb, tree, offset, "timestamp: ");
			break;
		case 1:	/* sequenceNumber */
			offset = fUnsignedTag (tvb, tree, offset, "sequence Number: ");
			break;
		case 2:	/* dateTime */
			offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
			offset = fDateTime (tvb, tree, offset, "timestamp: ");
			offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
			break;
		default:
			return offset;
			break;
		}
	}
	return offset;
}

#if 0
static guint
fSetpointReference (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
	
		switch (fTagNo(tvb, offset)) {
		case 0:	/* setpointReference */
			offset = fBACnetObjectPropertyReference (tvb,tree,offset);
			break;
		default:
			return offset;
			break;
		}
	}
	return offset;
}
#endif

#if 0
static guint
fClientCOV (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	if (tvb_length_remaining(tvb, offset) > 0) {
        offset = fApplicationTypes(tvb,tree,offset, "increment: ");
    }
    return offset;
}

static guint
fDestination (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	if (tvb_length_remaining(tvb, offset) > 0) {
		offset = fApplicationTypesEnumerated(tvb,tree,offset, 
			"valid Days: ", days);
		offset = fTime (tvb,tree,offset,"from time: ");
		offset = fTime (tvb,tree,offset,"to time: ");
		offset = fRecipient (tvb,tree,offset);
		offset = fProcessId (tvb,tree,offset);
		offset = fApplicationTypes (tvb,tree,offset,
			"issue confirmed notifications: ");
		offset = fApplicationTypesEnumerated (tvb,tree,offset,
			"transitions: ", BACnetEventTransitionBits);
	}
	return offset;
}

#endif

static guint
fOctetString (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label, guint32 lvt)
{
	gchar *tmp;
    guint start = offset;
	guint8 tag_no, tag_info;
    proto_tree* subtree = tree;
    proto_item* ti = 0;

	offset += fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);

	if (lvt > 0)
    {
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
fAddress (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint8 tag_no, tag_info;
	guint32 lvt;
    guint offs;

	offset = fUnsignedTag (tvb, tree, offset, "network-number");
	offs = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	if (lvt == 0) {
		proto_tree_add_text(tree, tvb, offset, offs, "mac-address: broadcast");
		offset += offs;
	} else
		offset = fOctetString (tvb, tree, offset, "mac-address: ", lvt);
	return offset;
}

#if 0
static guint
fSessionKey (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	offset = fOctetString (tvb,tree,offset,"session key: ", 8);
	return fAddress (tvb,tree,offset);
}
#endif

static guint
fObjectIdentifier (tvbuff_t *tvb, proto_tree *tree, guint offset)
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
fRecipient (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
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

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
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
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {  
			offset += fTagHeaderTree (tvb, subtree, offset,
				&tag_no, &tag_info, &lvt);
			subtree = tree;
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
			offset = fPropertyIdentifier (tvb, subtree, offset);
			break;
		case 3: /* propertyArrayIndex */
			offset = fUnsignedTag (tvb,subtree,offset,"Property Array Index: ");
			break;
		case 4: /* propertyValue */
			if (tag_is_opening(tag_info)) {
				tt = proto_tree_add_text(subtree, tvb, offset, 1, "propertyValue");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fAbstractSyntaxNType (tvb, subtree, offset);
				break;
			}
			FAULT;
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
	}
	return offset;
}

static guint
fActionList (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	return fActionCommand (tvb,tree,offset);
}

static guint
fPropertyIdentifier (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint8 tag_no, tag_info;
	guint32 lvt;
	guint tag_len;
	proto_item *ti;
	proto_tree *subtree;

	propertyIdentifier = 0; /* global Variable */
	tag_len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	if (fUnsigned32 (tvb, offset+tag_len, lvt, (guint32 *)&propertyIdentifier))
		ti = proto_tree_add_text(tree, tvb, offset, lvt+tag_len,
			"property Identifier: %s",
			val_to_split_str(propertyIdentifier, 512,
				BACnetPropertyIdentifier,
				ASHRAE_Reserved_Fmt,
				Vendor_Proprietary_Fmt));
	else
		ti = proto_tree_add_text(tree, tvb, offset, lvt+tag_len,
		"Property Identifier - %u octets", lvt);
	subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
	fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);

	return offset+tag_len+lvt;
}

static guint
fCharacterString (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label)
{
	guint8 tag_no, tag_info, character_set;
	guint32 lvt, l;
	size_t inbytesleft, outbytesleft = 512;
	guint offs, extra = 1;
	guint8 *str_val;
	guint8 bf_arr[512], *out = &bf_arr[0];
	proto_item *ti;
	proto_tree *subtree;
    guint start = offset;

	if (tvb_length_remaining(tvb, offset) > 0) {

		offs = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	
		character_set = tvb_get_guint8(tvb, offset+offs);
        /* Account for code page if DBCS */
        if (character_set == 1)
        {
            extra = 3;
        }
        offset += (offs+extra);
        lvt -= (extra);

		do {
			l = inbytesleft = min(lvt, 255);
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
			ti = proto_tree_add_text(tree, tvb, offset, l, "%s'%s'", label, out);
			lvt-=l;
			offset+=l;
		} while (lvt > 0);

		subtree = proto_item_add_subtree(ti, ett_bacapp_tag);

        fTagHeaderTree (tvb, subtree, start, &tag_no, &tag_info, &lvt);
		proto_tree_add_item(subtree, hf_BACnetCharacterSet, tvb, start+offs, 1, FALSE);
        if (character_set == 1)
        {
            proto_tree_add_text(subtree, tvb, start+offs+1, 2, "Code Page: %d", tvb_get_ntohs(tvb, start+offs+1));
        }
	}
	return offset;
}

static guint
fBitStringTagVS (tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label,
	const value_string *src)
{
	guint8 tag_no, tag_info, tmp;
	gint j, unused, skip;
	guint offs;
	guint32 lvt, i, numberOfBytes;
	guint8 bf_arr[256];
	
	offs = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	numberOfBytes = lvt-1; /* Ignore byte for unused bit count */
	offset+=offs;
	unused = tvb_get_guint8(tvb, offset); /* get the unused Bits */
	skip = 0;
	for (i = 0; i < numberOfBytes; i++) {
		tmp = tvb_get_guint8(tvb, (offset)+i+1);
		if (i == numberOfBytes-1) { skip = unused; }
		for (j = 0; j < 8-skip; j++) {
			if (src != NULL) {
				if (tmp & (1 << (7 - j)))
					proto_tree_add_text(tree, tvb,
						offset+i+1, 1,
						"%s%s = TRUE",
						label,
						val_to_str((guint) (i*8 +j),
							src,
							ASHRAE_Reserved_Fmt));
				else
					proto_tree_add_text(tree, tvb,
						offset+i+1, 1,
						"%s%s = FALSE",
						label,
						val_to_str((guint) (i*8 +j),
							src,
							ASHRAE_Reserved_Fmt));

			} else {
				bf_arr[min(255,(i*8)+j)] = tmp & (1 << (7 - j)) ? '1' : '0';
			}
		}
	}

	if (src == NULL)
	{
		bf_arr[min(255,numberOfBytes*8-unused)] = 0;
		proto_tree_add_text(tree, tvb, offset, lvt, "%sB'%s'", label, bf_arr);
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
fApplicationTypesEnumeratedSplit (tvbuff_t *tvb, proto_tree *tree, guint offset, 
	const gchar *label, const value_string *src, guint32 split_val)
{
	guint8 tag_no, tag_info;
	guint32 lvt;
	guint tag_len;

	if (tvb_length_remaining(tvb, offset) > 0) {

		tag_len = fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	
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
				offset = fObjectIdentifier (tvb, tree, offset);
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
	return offset;
}

static guint
fApplicationTypesEnumerated (tvbuff_t *tvb, proto_tree *tree, guint offset, 
	const gchar *label, const value_string *vs)
{
  return fApplicationTypesEnumeratedSplit(tvb, tree, offset, label, vs, 0);
}

static guint
fApplicationTypes (tvbuff_t *tvb, proto_tree *tree, guint offset, 
	const gchar *label)
{
  return fApplicationTypesEnumeratedSplit(tvb, tree, offset, label, NULL, 0);
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
	tvb_len = tvb_length_remaining(tvb, offset+tag_len);
	if ((tvb_len >= 0) && ((guint32)tvb_len < lvt))
	{
		lvt = tvb_len;
	}
	ti = proto_tree_add_text(tree, tvb, offset+tag_len, lvt,
		"Context Value (as %u DATA octets)", lvt);

	subtree = proto_item_add_subtree(ti, ett_bacapp_tag);
	fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
	
	return offset + tag_len + lvt;
}

static guint
fAbstractSyntaxNType (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint8 tag_no, tag_info;
	guint32 lvt;
	guint lastoffset = 0, depth = 0;
	char ar[256];
	
	if (propertyIdentifier >= 0)
	{
		g_snprintf (ar, sizeof(ar), "%s: ",
			val_to_split_str(propertyIdentifier, 512,
				BACnetPropertyIdentifier,
				ASHRAE_Reserved_Fmt,
				Vendor_Proprietary_Fmt));
	}
	else
	{
		g_snprintf (ar, sizeof(ar), "Abstract Type: ");
	}
	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) { /* closing tag, but not for me */
			if (depth <= 0) return offset;
		}

		/* Application Tags */
		switch (propertyIdentifier) {
		case 2: /* BACnetActionList */
			offset = fActionList (tvb,tree,offset);
			break;
		case 30: /* BACnetAddressBinding */
			offset = fAddressBinding (tvb,tree,offset);
			break;
		case 79: /* object-type */
		case 96: /* protocol-object-types-supported */
			offset = fApplicationTypesEnumeratedSplit (tvb, tree, offset, ar, 
				BACnetObjectType, 128);
			break;
		case 97: /* Protocol-Services-Supported */
			offset = fApplicationTypesEnumerated (tvb, tree, offset, ar, 
				BACnetServicesSupported);
			break;
		case 107: /* segmentation-supported */
			offset = fApplicationTypesEnumerated (tvb, tree, offset, ar, 
				BACnetSegmentation);
			break;
		case 111: /* Status-Flags */
			offset = fApplicationTypesEnumerated (tvb, tree, offset, ar, 
				BACnetStatusFlags);
			break;
		case 112: /* System-Status */
			offset = fApplicationTypesEnumerated (tvb, tree, offset, ar, 
				BACnetDeviceStatus);
			break;
		case 117: /* units */
			offset = fApplicationTypesEnumerated (tvb, tree, offset, ar, 
				BACnetEngineeringUnits);
			break;
		case 87:	/* priority-array */
			offset = fPriorityArray (tvb, tree, offset);
			break;
		case 38:	/* exception-schedule */
			if (object_type < 128)
			{
				offset = fSpecialEvent (tvb,tree,offset);
				break;
			}
		case 123:	/* weekly-schedule */
			if (object_type < 128)
			{
				offset = fWeeklySchedule (tvb,tree,offset);
				break;
			}
		default:
			if (tag_info)
			{
				if (tag_is_opening(tag_info))
				{
					++depth;
					offset += fTagHeaderTree(tvb, tree, offset, &tag_no, &tag_info, &lvt);
				}
				else if (tag_is_closing(tag_info))
				{
					--depth;
					offset += fTagHeaderTree(tvb, tree, offset, &tag_no, &tag_info, &lvt);
				}
				else
				{
					offset = fContextTaggedValue(tvb, tree, offset, ar);
				}
			}
			else
			{
				offset = fApplicationTypes (tvb, tree, offset, ar);
			}
			break;
		}
	}
	return offset;

}

static guint
fPropertyValue (tvbuff_t *tvb, proto_tree *tree, guint offset, guint8 tagoffset)
{
	guint lastoffset = offset;
	proto_item *tt;
	proto_tree *subtree;
	guint8 tag_no, tag_info;
	guint32 lvt;
	
	offset = fPropertyReference(tvb, tree, offset, tagoffset, 0);
	if (offset > lastoffset)
	{
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_no == tagoffset+2) {  /* Value - might not be present in ReadAccessResult */
			if (tag_is_opening(tag_info)) {
				tt = proto_tree_add_text(tree, tvb, offset, 1, "propertyValue");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fAbstractSyntaxNType (tvb, subtree, offset);
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
			}
		}
	}
	return offset;
}

static guint
fBACnetPropertyValue (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		offset = fPropertyValue(tvb, tree, offset, 0);
		if (offset > lastoffset)
		{
			/* detect optional priority
			by looking to see if the next tag is context tag number 3 */
			fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
			if (tag_is_context_specific(tag_info) && (tag_no == 3))
				offset = fUnsignedTag (tvb,tree,offset,"Priority: ");
		}
	}
	return offset;
}

static guint
fSubscribeCOVPropertyRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
	
		switch (fTagNo(tvb,offset)) {
		case 0:	/* ProcessId */
			offset = fUnsignedTag (tvb, tree, offset, "subscriber Process Id: ");
			break;
		case 1: /* monitored ObjectId */
			offset = fObjectIdentifier (tvb, tree, offset);
			break;
		case 2: /* issueConfirmedNotifications */
			offset = fBooleanTag (tvb, tree, offset, "issue Confirmed Notifications: ");
			break;
		case 3:	/* life time */
			offset = fTimeSpan (tvb,tree,offset,"life time");
			break;
		case 4:	/* monitoredPropertyIdentifier */
			offset = fBACnetPropertyReference (tvb, tree, offset, 0);
			break;
		case 5:	/* covIncrement */
			offset = fRealTag (tvb, tree, offset, "COV Increment: ");
			break;
		default:
			return offset;
			break;
		}
	}
	return offset;
}

static guint
fSubscribeCOVRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	return fSubscribeCOVPropertyRequest(tvb, tree, offset);
}

static guint
fWhoHas (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
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
	guint8 tag_no, tag_info;
	guint32 lvt;
	
	fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	if (tag_is_opening(tag_info) && tag_no == 0)
	{
		offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt); /* opening context tag 0 */
		while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
			lastoffset = offset;
			fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
			if (tag_is_closing(tag_info)) {
				/* should be closing context tag 0 */
				offset += fTagHeaderTree (tvb, subtree, offset,	&tag_no, &tag_info, &lvt);
				return offset;
			}
			
			offset = fTimeValue (tvb, subtree, offset);
		}
	}
	else if (tag_no == 0 && lvt == 0)
	{
		/* not sure null (empty array element) is legal */
		offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
	}
	return offset;
}

static guint
fWeeklySchedule (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;
	guint i=1;
	proto_tree *subtree = tree;
	proto_item *tt;
	
	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {
			return offset; /* outer encoding will print out closing tag */
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
	if (tvb_length_remaining(tvb, offset) <= 0)
		return offset;
	
	return fDateTime (tvb, tree, offset, "UTC-Time: ");
}

static guint
fTimeSynchronizationRequest  (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	if (tvb_length_remaining(tvb, offset) <= 0)
		return offset;

	return fDateTime (tvb, tree, offset, NULL);
}

static guint
fDateRange  (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	if (tvb_length_remaining(tvb, offset) <= 0)
		return offset;
    offset = fDate (tvb,tree,offset,"Start Date: ");
	return fDate (tvb, tree, offset, "End Date: ");
}

static guint
fConfirmedTextMessageRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
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
			break;	
		}
	}
	return offset;
}

static guint
fUnconfirmedTextMessageRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	return fConfirmedTextMessageRequest(tvb, tree, offset);
}

static guint
fConfirmedPrivateTransferRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	/* exit loop if nothing happens inside */ 
	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {
			if (tag_no == 2) /* Make sure it's the expected tag */
			{
				offset += fTagHeaderTree (tvb, subtree, offset,
					&tag_no, &tag_info, &lvt);
				subtree = tree;
				continue;
			}
			else
			{
				break; /* End loop if incorrect closing tag */
			}
		}
		switch (tag_no) {

		case 0: /* vendorID */
			offset = fUnsignedTag (tvb, subtree, offset, "vendor ID: ");
			break;
		case 1: /* serviceNumber */
			offset = fUnsignedTag (tvb, subtree, offset, "service Number: ");
			break;
		case 2: /*serviceParameters */
			if (tag_is_opening(tag_info)) {
				tt = proto_tree_add_text(subtree, tvb, offset, 1, "service Parameters");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				propertyIdentifier = -1;
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
	return fConfirmedPrivateTransferRequest(tvb, tree, offset);
}

static guint
fConfirmedPrivateTransferAck(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	return fConfirmedPrivateTransferRequest(tvb, tree, offset);
}

static guint
fLifeSafetyOperationRequest(tvbuff_t *tvb, proto_tree *tree, guint offset, const gchar *label)
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

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
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
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		default:
			return offset;
			break;
		}
	}
	return offset;
}

static guint fBACnetPropertyStates(tvbuff_t *tvb, proto_tree *tree, guint offset)
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

static guint
fNotificationParameters (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = offset;
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	tt = proto_tree_add_text(subtree, tvb, offset, 0, "notification parameters");
	subtree = proto_item_add_subtree(tt, ett_bacapp_value);
	/* Opeing tag for parameter choice */
	offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);

	switch (tag_no) {
	case 0: /* change-of-bitstring */
		while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
        	lastoffset = offset;
			switch (fTagNo(tvb, offset)) {
			case 0:
				offset = fBitStringTag (tvb, subtree, offset, 
					"referenced-bitstring: ");
				break;
			case 1:
				offset = fEnumeratedTag (tvb, subtree, offset, 
					"status-flags: ", BACnetStatusFlags);
				break;
			default:
				return offset;
				break;
			}
		}
		break;
	case 1: /* change-of-state */
		while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
        	lastoffset = offset;
			switch (fTagNo(tvb, offset)) {
			case 0:
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fBACnetPropertyStates(tvb, subtree, offset);
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
			case 1:
				offset = fEnumeratedTag (tvb, subtree, offset, 
					"status-flags: ", BACnetStatusFlags);
	        	lastoffset = offset;
				break;
			default:
				break;
			}
		}
		break;
    case 2: /* change-of-value */
		while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
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
				offset = fEnumeratedTag (tvb, subtree, offset, 
					"status-flags: ", BACnetStatusFlags);
				break;
			default:
				break;
			}
		}
		break;
    case 3: /* command-failure */
		while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
        	lastoffset = offset;
			switch (fTagNo(tvb, offset)) {
			case 0: /* "command-value: " */
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fAbstractSyntaxNType (tvb, subtree, offset);
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				break;
			case 1:
				offset = fEnumeratedTag (tvb, subtree, offset, 
					"status-flags: ", BACnetStatusFlags);
			case 2: /* "feedback-value: " */
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fAbstractSyntaxNType (tvb, subtree, offset);
				offset += fTagHeaderTree(tvb, subtree, offset, &tag_no, &tag_info, &lvt);
			default:
				break;
			}
		}
		break;
    case 4: /* floating-limit */
		while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
        	lastoffset = offset;
			switch (fTagNo(tvb, offset)) {
			case 0:
				offset = fRealTag (tvb, subtree, offset, "reference-value: ");
				break;
			case 1:
				offset = fEnumeratedTag (tvb, subtree, offset, 
					"status-flags: ", BACnetStatusFlags);
				break;
			case 2:
				offset = fRealTag (tvb, subtree, offset, "setpoint-value: ");
				break;
			case 3:
				offset = fRealTag (tvb, subtree, offset, "error-limit: ");
			default:
				break;
			}
		}
		break;
    case 5: /* out-of-range */
		while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
        	lastoffset = offset;
			switch (fTagNo(tvb, offset)) {
			case 0:
				offset = fRealTag (tvb, subtree, offset, "exceeding-value: ");
				break;
			case 1:
				offset = fEnumeratedTag (tvb, subtree, offset, 
					"status-flags: ", BACnetStatusFlags);
				break;
			case 2:
				offset = fRealTag (tvb, subtree, offset, "deadband: ");
				break;
			case 3:
				offset = fRealTag (tvb, subtree, offset, "exceeded-limit: ");
			default:
				break;
			}
		}
	    break;
	case 6:
		while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
	       	lastoffset = offset;
			offset =fBACnetPropertyValue (tvb,subtree,offset);
		}
		break;
	case 7: /* buffer-ready */
		while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
        	lastoffset = offset;
			switch (fTagNo(tvb, offset)) {
			case 0:
				offset = fObjectIdentifier (tvb, subtree, offset); /* buffer-device */
				break;
			case 1:
				offset = fObjectIdentifier (tvb, subtree, offset); /* buffer-object */
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
			default:
				break;
			}
		}
		break;
    case 8: /* change-of-life-safety */
		while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
        	lastoffset = offset;
			switch (fTagNo(tvb, offset)) {
			case 0:
				offset = fEnumeratedTagSplit (tvb, subtree, offset, 
					"new-state: ", BACnetLifeSafetyState, 256);
				break;
			case 1:
				offset = fEnumeratedTagSplit (tvb, subtree, offset, 
					"new-mode: ", BACnetLifeSafetyState, 256);
				break;
			case 2:
				offset = fEnumeratedTag (tvb, subtree, offset, 
					"status-flags: ", BACnetStatusFlags);
			case 3:
				offset = fEnumeratedTagSplit (tvb, subtree, offset, 
					"operation-expected: ", BACnetLifeSafetyOperation, 64);
			default:
				return offset;
				break;
			}
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

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0: /* change-of-bitstring */
			while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
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
			while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
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
			while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
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
			while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
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
			while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
        		lastoffset = offset;
				switch (fTagNo(tvb, offset)) {
				case 0:
					offset = fTimeSpan   (tvb, tree, offset, "Time Delay");
					break;
				case 1:
					offset = fDeviceObjectPropertyReference (tvb,tree,offset);
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
			while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
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
			offset = fBACnetPropertyValue (tvb,tree,offset);
			break;
		case 7: /* buffer-ready */
			while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
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
			while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
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

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0: /* timestamp */
			offset = fDateTime (tvb,tree,offset,NULL);
			break;
		case 1: /* logDatum: don't loop, it's a CHOICE */
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
				offset = fError (tvb,tree,offset);
				break;
			case 9:
				offset = fRealTag (tvb, tree, offset, "time change: ");
				break;
			case 10:	/* any Value */
				offset = fAbstractSyntaxNType (tvb, tree, offset);
				break;
			default:
				return offset;
			}
        break;
		case 2:
			offset = fEnumeratedTag (tvb, tree, offset, 
				"status Flags: ", BACnetStatusFlags);
			break;
		default:
			return offset;
		}
	}
	return offset;
}
#endif

static guint
fConfirmedEventNotificationRequest (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
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
			offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
			offset = fTimeStamp (tvb, tree, offset);
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
			offset = fNotificationParameters (tvb, tree, offset);
			offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
			break;
		default:
			break;
		}
	}
	return offset;
}

static guint
fUnconfirmedEventNotificationRequest (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	return fConfirmedEventNotificationRequest (tvb, tree, offset);
}

static guint
fConfirmedCOVNotificationRequest (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {   
			offset += fTagHeaderTree (tvb, subtree, offset,
				&tag_no, &tag_info, &lvt);
			subtree = tree;
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
			if (tag_is_opening(tag_info)) {
				tt = proto_tree_add_text(subtree, tvb, offset, 1, "list of Values");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fBACnetPropertyValue (tvb, subtree, offset);
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
	return fConfirmedCOVNotificationRequest (tvb, tree, offset);
}

static guint
fAcknowledgeAlarmRequest (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no = 0, tag_info = 0;
	guint32 lvt = 0;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0:	/* acknowledgingProcessId */
			offset = fUnsignedTag (tvb, tree, offset, "acknowledging Process Id: ");
			break;
		case 1: /* eventObjectId */
			offset = fObjectIdentifier (tvb, tree, offset);
			break;
		case 2: /* eventStateAcknowledged */
			offset = fEnumeratedTagSplit (tvb, tree, offset, 
				"event State Acknowledged: ", BACnetEventState, 64);
			break;
		case 3:	/* timeStamp */
			offset += fTagHeaderTree(tvb, tree, offset, &tag_no, &tag_info, &lvt);
			offset = fTimeStamp(tvb, tree, offset);
			offset += fTagHeaderTree(tvb, tree, offset, &tag_no, &tag_info, &lvt);
			break;
		case 4:	/* acknowledgementSource */
			offset = fCharacterString (tvb, tree, offset, "acknowledgement Source: ");
			break;
		case 5:	/* timeOfAcknowledgement */
			offset += fTagHeaderTree(tvb, tree, offset, &tag_no, &tag_info, &lvt);
			offset = fTimeStamp(tvb, tree, offset);
			offset += fTagHeaderTree(tvb, tree, offset, &tag_no, &tag_info, &lvt);
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

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		offset = fApplicationTypes (tvb, tree, offset, "Object Identifier: ");
		offset = fApplicationTypesEnumeratedSplit (tvb, tree, offset, 
			"alarm State: ", BACnetEventState, 64);
		offset = fApplicationTypesEnumerated (tvb, tree, offset, 
			"acknowledged Transitions: ", BACnetEventTransitionBits);
	}
	return  offset;
}

static guint
fGetEnrollmentSummaryRequest (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0:	/* acknowledgmentFilter */
			offset = fEnumeratedTag (tvb, tree, offset, 
				"acknowledgment Filter: ", BACnetAcknowledgementFilter);
			break;
		case 1: /* eventObjectId */
			offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
			offset = fRecipientProcess (tvb, tree, offset);
			break;
		case 2: /* eventStateFilter */
			offset = fEnumeratedTag (tvb, tree, offset, 
				"event State Filter: ", BACnetEventStateFilter);
			break;
		case 3:	/* eventTypeFilter */
			offset = fEnumeratedTag (tvb, tree, offset, 
				"event Type Filter: ", BACnetEventType);
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

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		offset = fApplicationTypes (tvb, tree, offset, "Object Identifier: ");
		offset = fApplicationTypesEnumeratedSplit (tvb, tree, offset, 
			"event Type: ", BACnetEventType, 64);
		offset = fApplicationTypesEnumerated (tvb, tree, offset, 
			"event State: ", BACnetEventStateFilter);
		offset = fApplicationTypes (tvb, tree, offset, "Priority: ");
		offset = fApplicationTypes (tvb, tree, offset, "Notification Class: ");
	}

	return  offset;
}

static guint
fGetEventInformationRequest (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
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

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0:	/* ObjectId */
			offset = fObjectIdentifier (tvb, tree, offset);
			break;
		case 1: /* eventState */
			offset = fEnumeratedTag (tvb, tree, offset, 
				"event State: ", BACnetEventStateFilter);
			break;
		case 2: /* acknowledgedTransitions */
			offset = fEnumeratedTag (tvb, tree, offset, 
				"acknowledged Transitions: ", BACnetEventTransitionBits);
			break;
		case 3: /* eventTimeStamps */
			offset = fTime (tvb, tree, offset, "time Stamp: ");
			offset = fTime (tvb, tree, offset, "time Stamp: ");
			offset = fTime (tvb, tree, offset, "time Stamp: ");
			break;
		case 4: /* notifyType */
			offset = fEnumeratedTag (tvb, tree, offset, 
				"Notify Type: ", BACnetNotifyType);
			break;
		case 5: /* eventEnable */
			offset = fEnumeratedTag (tvb, tree, offset, 
				"event Enable: ", BACnetEventTransitionBits);
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
	guint8 tag_no, tag_info;
	guint32 lvt;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0:	/* listOfEventSummaries */
			offset += fTagHeaderTree (tvb, tree, offset, &tag_no, &tag_info, &lvt);
			offset = flistOfEventSummaries (tvb, tree, offset);
			break;
		case 1: /* moreEvents */
			offset = fBooleanTag (tvb, tree, offset, "more Events: ");
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
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {
			offset += fTagHeaderTree (tvb, subtree, offset,
				&tag_no, &tag_info, &lvt);
			subtree = tree;
			continue;
		}
	
		switch (tag_no) {
		case 0:	/* ObjectId */
			offset = fBACnetObjectPropertyReference (tvb, subtree, offset);
			break;
		case 3:	/* listOfElements */
			if (tag_is_opening(tag_info)) {
				tt = proto_tree_add_text(subtree, tvb, offset, 1, "listOfElements");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
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

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
	
		switch (fTagNo(tvb, offset)) {
		case 0:	/* timeDuration */
			offset = fUnsignedTag (tvb,tree,offset,"time Duration: ");
			break;
		case 1:	/* enable-disable */
			offset = fEnumeratedTag (tvb, tree, offset, "enable-disable: ",
				BACnetEnableDisable);
			break;
		case 2: /* password */
			offset = fCharacterString (tvb, tree, offset, "Password: ");
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

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
	
		switch (fTagNo(tvb, offset)) {
		case 0:	/* reinitializedStateOfDevice */
			offset = fEnumeratedTag (tvb, tree, offset, 
				"reinitialized State Of Device: ", 
				BACnetReinitializedStateOfDevice);
			break;
		case 1: /* password */
			offset = fCharacterString (tvb, tree, offset, "Password: ");
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
	offset = fApplicationTypesEnumerated (tvb, tree, offset, 
		"vtClass: ", BACnetVTClass);
	return fApplicationTypes (tvb,tree,offset,"local VT Session ID: ");
}

static guint
fVtOpenAck (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	return fApplicationTypes (tvb,tree,offset,"remote VT Session ID: ");
}

static guint
fVtCloseRequest (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		offset= fApplicationTypes (tvb,tree,offset,"remote VT Session ID: ");
	}
	return offset;
}

static guint
fVtDataRequest (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	offset= fApplicationTypes (tvb,tree,offset,"VT Session ID: ");
	offset = fApplicationTypes (tvb, tree, offset, "VT New Data: ");
	return fApplicationTypes (tvb,tree,offset,"VT Data Flag: ");;
}

static guint
fVtDataAck (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
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
	}
	return offset;
}

static guint
fAuthenticateRequest (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
	
		switch (fTagNo(tvb,offset)) {
		case 0:	/* Unsigned32 */
			offset = fUnsignedTag (tvb, tree, offset, "pseudo Random Number: ");
			break;
		case 1:	/* expected Invoke ID Unsigned8 OPTIONAL */
			proto_tree_add_item(tree, hf_bacapp_invoke_id, tvb, offset++, 1, TRUE);
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
	}
	return offset;
}

static guint
fAuthenticateAck (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	return fApplicationTypes (tvb, tree, offset, "modified Random Number: ");
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
fRemoveListElementRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	/* Same as AddListElement request after service choice */
	return fAddListElementRequest(tvb, tree, offset);
}

static guint
fReadPropertyRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	return fBACnetObjectPropertyReference(tvb, tree, offset);
}

static guint
fReadPropertyAck (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_tree *subtree = tree;
    proto_item *tt;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {
			offset += fTagHeaderTree (tvb, subtree, offset,
				&tag_no, &tag_info, &lvt);
			subtree = tree;
			continue;
		}
		switch (tag_no) {
		case 0:	/* objectIdentifier */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 1:	/* propertyIdentifier */
			offset = fPropertyIdentifier (tvb, subtree, offset);
			break;
		case 2: /* propertyArrayIndex */
			offset = fSignedTag (tvb, subtree, offset, "property Array Index: ");
			break;
		case 3:	/* propertyValue */
			if (tag_is_opening(tag_info)) {
				tt = proto_tree_add_text(subtree, tvb, offset, 1, "propertyValue");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fAbstractSyntaxNType (tvb, subtree, offset);
				break;
			}
			FAULT;
			break;
		default:
			break;
		}
	}
	return offset;
}

static guint
fWritePropertyRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_tree *subtree = tree;
    proto_item *tt;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {
			offset += fTagHeaderTree (tvb, subtree, offset,
				&tag_no, &tag_info, &lvt);
			subtree = tree;
			continue;
		}
	
		switch (tag_no) {
		case 0:	/* objectIdentifier */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 1:	/* propertyIdentifier */
			offset = fPropertyIdentifier (tvb, subtree, offset);
			break;
		case 2: /* propertyArrayIndex */
			offset = fSignedTag (tvb, subtree, offset, "property Array Index: ");
			break;
		case 3:	/* propertyValue */
			if (tag_is_opening(tag_info)) {
				tt = proto_tree_add_text(subtree, tvb, offset, 1, "propertyValue");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
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
	guint8 tag_no, tag_info;
	guint32 lvt;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {   
			offset += fTagHeaderTree (tvb, subtree, offset,
				&tag_no, &tag_info, &lvt);
			continue;
		}
	
		switch (tag_no) {
		case 0:	/* objectIdentifier */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 1:	/* listOfPropertyValues */
			if (tag_is_opening(tag_info)) {
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fBACnetPropertyValue (tvb, subtree, offset);
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
fPropertyReference (tvbuff_t *tvb, proto_tree *tree, guint offset, guint8 tagoffset, guint8 list)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) { /* closing Tag, but not for me */
			return offset;
		}
		switch (tag_no-tagoffset) {
		case 0:	/* PropertyIdentifier */
			offset = fPropertyIdentifier (tvb, tree, offset);
			break;
		case 1:	/* propertyArrayIndex */
			offset = fUnsignedTag (tvb, tree, offset, "property Array Index: ");
			if (list != 0) break; /* Continue decoding if this may be a list */
		default:
			lastoffset = offset; /* Set loop end condition */
			break;
		}
	}
	return offset;
}

static guint
fBACnetPropertyReference (tvbuff_t *tvb, proto_tree *tree, guint offset, guint8 list)
{
	return fPropertyReference(tvb, tree, offset, 0, list);
}

static guint
fBACnetObjectPropertyReference (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		
		switch (fTagNo(tvb,offset)) {
		case 0:	/* ObjectIdentifier */
			offset = fObjectIdentifier (tvb, tree, offset);
			break;
		case 1:	/* PropertyIdentifier and propertyArrayIndex */
			offset = fPropertyReference (tvb, tree, offset, 1, 0);
		default:
			lastoffset = offset; /* Set loop end condition */
			break;
		}
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

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {
			offset += fTagHeaderTree (tvb, subtree, offset,
				&tag_no, &tag_info, &lvt);
			continue;
		}
		switch (tag_no) {
		case 0:	/* ObjectIdentifier */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 1:	/* PropertyIdentifier */
			offset = fPropertyIdentifier (tvb, subtree, offset);
			break;
		case 2:	/* propertyArrayIndex */
			offset = fUnsignedTag (tvb, subtree, offset, "property Array Index: ");
			break;
		case 3:  /* Value */
			if (tag_is_opening(tag_info)) {
				tt = proto_tree_add_text(subtree, tvb, offset, 1, "propertyValue");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fAbstractSyntaxNType   (tvb, subtree, offset);
				break;
			}
			FAULT;
			break;
		case 4:  /* Priority */
			offset = fSignedTag (tvb, subtree, offset, "Priority: ");
			break;
		default:
			break;
		}
	}
	return offset;
}
#endif

#if 0
static guint
fDeviceObjectPropertyReference (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		
		switch (fTagNo(tvb,offset)) {
		case 0:	/* ObjectIdentifier */
			offset = fBACnetObjectPropertyReference (tvb, tree, offset);
			break;
		case 3:	/* deviceIdentifier */
			offset = fObjectIdentifier (tvb, tree, offset);
			break;
		default:
			return offset;
		}
	}
	return offset;
}
#endif

static guint
fPriorityArray (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	char i, ar[256];

	if (offset >= tvb_reported_length(tvb))
		return offset;
	
	for (i = 1; i <= 16; i++) {
		g_snprintf (ar, sizeof(ar), "%s[%d]: ",
			val_to_split_str(87 , 512,
				BACnetPropertyIdentifier,
				ASHRAE_Reserved_Fmt,
				Vendor_Proprietary_Fmt),
			i);
		/* DMR Replace with fAbstractNSyntax */
		offset = fApplicationTypes(tvb, tree, offset, ar);
	}
	return offset;
}

#if 0
static guint
fDeviceObjectReference (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
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
#endif

static guint
fSpecialEvent (tvbuff_t *tvb, proto_tree *subtree, guint offset)
{
	guint8 tag_no, tag_info;
	guint32 lvt;
	guint lastoffset = 0;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {   
			continue;
		}
        
		switch (tag_no) {
		case 0:	/* calendaryEntry */
            if (tag_is_opening(tag_info))
            {
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
    			offset = fCalendaryEntry (tvb, subtree, offset);
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
            }
			break;
		case 1:	/* calendarReference */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 2:	/* list of BACnetTimeValue */
			if (tag_is_opening(tag_info)) {
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fTimeValue (tvb, subtree, offset);
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
	}
	return offset;
}

static guint
fSelectionCriteria (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		
		switch (fTagNo(tvb,offset)) {
		case 0:	/* propertyIdentifier */
			offset = fPropertyIdentifier (tvb, tree, offset);
			break;
		case 1:	/* propertyArrayIndex */
			offset = fUnsignedTag (tvb, tree, offset, "property Array Index: ");
			break;
		case 2: /* relationSpecifier */
			offset = fEnumeratedTag (tvb, tree, offset, 
				"relation Specifier: ", BACnetRelationSpecifier);
			break;
		case 3: /* comparisonValue */
			offset = fAbstractSyntaxNType   (tvb, tree, offset);
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
	guint8 tag_no, tag_info;
	guint32 lvt;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {  
			offset += fTagHeaderTree (tvb, subtree, offset,
				&tag_no, &tag_info, &lvt);
			continue;
		}
	
		switch (tag_no) {
		case 0:	/* selectionLogic */
			offset = fEnumeratedTag (tvb, subtree, offset, 
				"selection Logic: ", BACnetSelectionLogic);
			break;
		case 1:	/* listOfSelectionCriteria */
			if (tag_is_opening(tag_info)) {
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
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
	guint8 tag_no, tag_info;
	guint32 lvt;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {   
			offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
			continue;
		}
	
		switch (tag_no) {
		case 0:	/* objectSelectionCriteria */
			offset = fObjectSelectionCriteria (tvb, subtree, offset);
			break;
		case 1:	/* listOfPropertyReferences */
			if (tag_is_opening(tag_info)) {
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fBACnetPropertyReference (tvb, subtree, offset, 1);
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
	guint8 tag_no, tag_info;
	guint32 lvt;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {   
			offset += fTagHeaderTree (tvb, subtree, offset, &tag_no,
				&tag_info, &lvt);
			continue;
		}
	
		switch (tag_no) {
		case 0:	/* objectIdentifier */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 1:	/* listOfPropertyReferences */
			if (tag_is_opening(tag_info)) {
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fBACnetPropertyReference (tvb, subtree, offset, 1);
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
	guint8 tag_info;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {   
			offset += fTagHeaderTree (tvb, subtree, offset,
				&tag_no, &tag_info, &lvt);
			if (tag_no == 4 || tag_no == 5) subtree = tree; /* Value and error have extra subtree */
			continue;
		}
	
		switch (tag_no) {
		case 0:	/* objectSpecifier */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 1:	/* list of Results */
			if (tag_is_opening(tag_info)) {
				tt = proto_tree_add_text(subtree, tvb, offset, 1, "listOfResults");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				break;
			}
			FAULT;
			break;
		case 2:	/* propertyIdentifier */
			offset = fPropertyValue(tvb, subtree, offset, 2);
			break;
		case 5:	/* propertyAccessError */
			if (tag_is_opening(tag_info)) {
				tt = proto_tree_add_text(subtree, tvb, offset, 1, "propertyAccessError");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				/* Error Code follows */
				offset = fError(tvb, subtree, offset);
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

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
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
	guint8 tag_no, tag_info;
	guint32 lvt;

	while ((tvb_length_remaining(tvb, offset) > 0) && (offset > lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {   
			offset += fTagHeaderTree (tvb, subtree, offset,
				&tag_no, &tag_info, &lvt);
			continue;
		}
	
		switch (tag_no) {
		case 0:	/* objectSpecifier */
			offset = fObjectSpecifier (tvb, subtree, offset);
			break;
		case 1:	/* propertyValue */
			if (tag_is_opening(tag_info)) {
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fBACnetPropertyValue (tvb, subtree, offset);
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
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {  
			offset += fTagHeaderTree (tvb, subtree, offset,
				&tag_no, &tag_info, &lvt);
			subtree = tree;
			continue;
		}
	
		switch (tag_no) {
		case 0:	/* objectSpecifier */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 1:	/* propertyIdentifier */
			offset = fPropertyIdentifier (tvb, subtree, offset);
			break;
		case 2:	/* propertyArrayIndex Optional */
			offset = fUnsignedTag (tvb, subtree, offset, "Property Array Index: ");
			break;
		case 3:	/* range byPosition */
			if (tag_is_opening(tag_info)) {
				tt = proto_tree_add_text(subtree, tvb, offset, 1, "range byPosition");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fApplicationTypes (tvb, subtree, offset, "reference Index: ");
				offset = fApplicationTypes (tvb, subtree, offset, "reference Count: ");
				break;
			}
			FAULT;
			break;
		case 4:	/* range byTime */
        case 7: /* 2004 spec */
			if (tag_is_opening(tag_info)) {
				tt = proto_tree_add_text(subtree, tvb, offset, 1, "range byTime");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fDateTime(tvb, subtree, offset, "reference Date/Time: ");
				offset = fApplicationTypes (tvb, subtree, offset, "reference Count: ");
				break;
			}
			FAULT;
			break;
		case 5:	/* range timeRange */
			if (tag_is_opening(tag_info)) {
				tt = proto_tree_add_text(subtree, tvb, offset, 1, "range timeRange");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fApplicationTypes (tvb, subtree, offset, "beginning Time: ");
				offset = fApplicationTypes (tvb, subtree, offset, "ending Time: ");
				break;
			}
			FAULT;
			break;
        case 6: /* range bySequenceNumber, 2004 spec */
            if (tag_is_opening(tag_info)) {
				tt = proto_tree_add_text(subtree, tvb, offset, 1, "range bySequenceNumber");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fApplicationTypes (tvb, subtree, offset, "referenceIndex: ");
				offset = fApplicationTypes (tvb, subtree, offset, "reference Count: ");
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
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {
			offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
			subtree = tree;
			continue;
		}
	
		switch (tag_no) {
		case 0:	/* objectSpecifier */
			offset = fObjectIdentifier (tvb, subtree, offset);
			break;
		case 1:	/* propertyIdentifier */
			offset = fPropertyIdentifier (tvb, subtree, offset);
			break;
		case 2:	/* propertyArrayIndex Optional */
			offset = fUnsignedTag (tvb, subtree, offset, "Property Array Index: ");
			break;
		case 3:	/* resultFlags */
			offset = fEnumeratedTag (tvb, tree, offset, 
				"result Flags: ", BACnetResultFlags);
			break;
		case 4:	/* itemCount */
			offset = fUnsignedTag (tvb, subtree, offset, "item Count: ");
			break;
		case 5:	/* itemData */
			if (tag_is_opening(tag_info)) {
				tt = proto_tree_add_text(subtree, tvb, offset, 1, "itemData");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fAbstractSyntaxNType   (tvb, subtree, offset);
				break;
			}
			FAULT;
			break;
		case 6:	/* firstSequenceNumber */
			offset = fUnsignedTag (tvb, subtree, offset, "first Sequence Number: ");
			break;
		default:
			return offset;
		}
	}
	return offset;
}

static guint fAccessMethod(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint32 lvt;
	guint8 tag_no, tag_info;
	proto_item* tt;
	proto_tree* subtree = NULL;

	fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);

	switch (tag_no) {
	case 0:	/* streamAccess */
		if (tag_is_opening(tag_info)) {  
			tt = proto_tree_add_text(tree, tvb, offset, 1, "stream Access");
			subtree = proto_item_add_subtree(tt, ett_bacapp_value);
			offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
			offset = fApplicationTypes (tvb, subtree, offset, "File Start Position: ");
			offset = fApplicationTypes (tvb, subtree, offset, "file Data: ");
		}
		if (bacapp_flags & 0x04) { /* More Flag is set */
			break;
		}
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {
			offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
		}
		break;
	case 1:	/* recordAccess */
		if (tag_is_opening(tag_info)) {
			tt = proto_tree_add_text(tree, tvb, offset, 1, "record Access");
			subtree = proto_item_add_subtree(tt, ett_bacapp_value);
			offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
			offset = fApplicationTypes (tvb, subtree, offset, "File Start Record: ");
			offset = fApplicationTypes (tvb, subtree, offset, "Record Count: ");
			offset = fApplicationTypes (tvb, subtree, offset, "Data: ");
		}
		if (bacapp_flags & 0x04) { /* More Flag is set */
			break;
		}
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) {
			offset += fTagHeaderTree (tvb, subtree, offset,	&tag_no, &tag_info, &lvt);
		}
		break;
	default:
		break;
	}
	
	return offset;
}

static guint
fAtomicReadFileRequest(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_tree *subtree = tree;
	proto_item *tt;

	offset = fObjectIdentifier (tvb, tree, offset);

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
		if (tag_is_closing(tag_info)) { 
			offset += fTagHeaderTree (tvb, subtree, offset,
				&tag_no, &tag_info, &lvt);
			subtree = tree;
			continue;
		}

		switch (tag_no) {
		case 0:	/* streamAccess */
			if (tag_is_opening(tag_info)) {
				tt = proto_tree_add_text(subtree, tvb, offset, 1, "stream Access");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fSignedTag (tvb, subtree, offset, "File Start Position: ");
				offset = fUnsignedTag (tvb, subtree, offset, "requested Octet Count: ");
				break;
			}
			FAULT;
			break;
		case 1:	/* recordAccess */
			if (tag_is_opening(tag_info)) {
				tt = proto_tree_add_text(subtree, tvb, offset, 1, "record Access");
				subtree = proto_item_add_subtree(tt, ett_bacapp_value);
				offset += fTagHeaderTree (tvb, subtree, offset, &tag_no, &tag_info, &lvt);
				offset = fSignedTag (tvb, subtree, offset, "File Start Record: ");
				offset = fUnsignedTag (tvb, subtree, offset, "requested Record Count: ");
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

	offset = fObjectIdentifier (tvb, tree, offset); /* file Identifier */
    offset = fAccessMethod(tvb, tree, offset);

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
	guint8 tag_no, tag_info;
	guint32 lvt;
	proto_tree *subtree = tree;

	fTagHeader (tvb, offset, &tag_no, &tag_info, &lvt);
	offset = fApplicationTypes (tvb, subtree, offset, "End Of File: ");
    offset = fAccessMethod(tvb, tree, offset);

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
	if (tvb_length_remaining(tvb,offset) <= 0)
		return offset;

	switch (service_choice) {
	case 0:	/* acknowledgeAlarm */
		offset = fAcknowledgeAlarmRequest (tvb, tree, offset);
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
	if (tvb_length_remaining(tvb,offset) <= 0)
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
	/* BACnetObjectIdentifier */
	offset = fApplicationTypes (tvb, tree, offset, "BACnet Object Identifier: ");

	/* MaxAPDULengthAccepted */
	offset = fApplicationTypes (tvb, tree, offset, "Maximum ADPU Length Accepted: ");

	/* segmentationSupported */
	offset = fApplicationTypesEnumerated (tvb, tree, offset, 
		"Segmentation Supported: ", BACnetSegmentation);

	/* vendor ID */
	return fUnsignedTag (tvb, tree, offset, "Vendor ID: ");
}

static guint
fIHaveRequest  (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	/* BACnetDeviceIdentifier */
	offset = fApplicationTypes (tvb, tree, offset, "Device Identifier: ");

	/* BACnetObjectIdentifier */
	offset = fApplicationTypes (tvb, tree, offset, "Object Identifier: ");

	/* ObjectName */
	return fApplicationTypes (tvb, tree, offset, "Object Name: ");

}

static guint
fWhoIsRequest  (tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
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
	if (tvb_length_remaining(tvb,offset) <= 0)
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
fStartConfirmed(tvbuff_t *tvb, proto_tree *bacapp_tree, guint offset, guint8 ack,
				gint *svc, proto_item **tt)
{
	proto_item *tc;
	proto_tree *bacapp_tree_control;
	gint tmp, bacapp_type;
	guint extra = 2;

	bacapp_seq = 0;
	tmp = (gint) tvb_get_guint8(tvb, offset);
	bacapp_type = (tmp >> 4) & 0x0f;
	bacapp_flags = tmp & 0x0f;

	if (ack == 0) {
		extra = 3;
	}
	*svc = (gint) tvb_get_guint8(tvb, offset+extra);
	if (bacapp_flags & 0x08)
		*svc = (gint) tvb_get_guint8(tvb, offset+extra+2);

    proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, offset, 1, TRUE);
	tc = proto_tree_add_item(bacapp_tree, hf_bacapp_pduflags, tvb, offset, 1, TRUE);
	bacapp_tree_control = proto_item_add_subtree(tc, ett_bacapp_control);

    proto_tree_add_item(bacapp_tree_control, hf_bacapp_SEG, tvb, offset, 1, TRUE);
    proto_tree_add_item(bacapp_tree_control, hf_bacapp_MOR, tvb, offset, 1, TRUE);
	if (ack == 0) /* The following are for ConfirmedRequest, not Complex ack */
	{
	    proto_tree_add_item(bacapp_tree_control, hf_bacapp_SA, tvb, offset++, 1, TRUE);
		proto_tree_add_item(bacapp_tree, hf_bacapp_response_segments, tvb,
							offset, 1, TRUE);
		proto_tree_add_item(bacapp_tree, hf_bacapp_max_adpu_size, tvb,
							offset, 1, TRUE);
	}
    offset++;
    proto_tree_add_item(bacapp_tree, hf_bacapp_invoke_id, tvb, offset++, 1, TRUE);
    if (bacapp_flags & 0x08) {
        bacapp_seq = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(bacapp_tree_control, hf_bacapp_sequence_number, tvb,
            offset++, 1, TRUE);
        proto_tree_add_item(bacapp_tree_control, hf_bacapp_window_size, tvb,
            offset++, 1, TRUE);
    }
    *tt = proto_tree_add_item(bacapp_tree, hf_bacapp_service, tvb,
        offset++, 1, TRUE);
	return offset;
}

static guint
fConfirmedRequestPDU(tvbuff_t *tvb, proto_tree *bacapp_tree, guint offset)
{	/* BACnet-Confirmed-Request */
	/* ASHRAE 135-2001 20.1.2 */
	gint svc;
	proto_item *tt = 0;

	offset = fStartConfirmed(tvb, bacapp_tree, offset, 0, &svc, &tt);
	if (bacapp_seq > 0) /* Can't handle continuation segments, so just treat as data */
	{
		proto_tree_add_text(bacapp_tree, tvb, offset, 0, "(continuation)");
		return offset;
	}
	else
	{
		/* Service Request follows... Variable Encoding 20.2ff */
		return fConfirmedServiceRequest (tvb, bacapp_tree, offset, svc);
	}
}

static guint
fUnconfirmedRequestPDU(tvbuff_t *tvb, proto_tree *bacapp_tree, guint offset)
{	/* BACnet-Unconfirmed-Request-PDU */
	/* ASHRAE 135-2001 20.1.3 */

	gint tmp;

    proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, offset++, 1, TRUE);

    tmp = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(bacapp_tree, hf_bacapp_uservice, tvb,
            offset++, 1, TRUE);
    /* Service Request follows... Variable Encoding 20.2ff */
    return fUnconfirmedServiceRequest  (tvb, bacapp_tree, offset, tmp);
}

static guint
fSimpleAckPDU(tvbuff_t *tvb, proto_tree *bacapp_tree, guint offset)
{	/* BACnet-Simple-Ack-PDU */
	/* ASHRAE 135-2001 20.1.4 */

	proto_item *tc;

	tc = proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, offset++, 1, TRUE);

    proto_tree_add_item(bacapp_tree, hf_bacapp_invoke_id, tvb,
        offset++, 1, TRUE);
    proto_tree_add_item(bacapp_tree, hf_bacapp_service, tvb,
        offset++, 1, TRUE);
	return offset;
}

static guint
fComplexAckPDU(tvbuff_t *tvb, proto_tree *bacapp_tree, guint offset)
{	/* BACnet-Complex-Ack-PDU */
	/* ASHRAE 135-2001 20.1.5 */
	gint svc;
	proto_item *tt = 0;

	offset = fStartConfirmed(tvb, bacapp_tree, offset, 1, &svc, &tt);

	if (bacapp_seq > 0) /* Can't handle continuation segments, so just treat as data */
	{
		proto_tree_add_text(bacapp_tree, tvb, offset, 0, "(continuation)");
		return offset;
	}
	else
	{
	    /* Service ACK follows... */
		return fConfirmedServiceAck (tvb, bacapp_tree, offset, svc);
	}
}


static guint
fSegmentAckPDU(tvbuff_t *tvb, proto_tree *bacapp_tree, guint offset)
{	/* BACnet-SegmentAck-PDU */
	/* ASHRAE 135-2001 20.1.6 */

	proto_item *tc;
	proto_tree *bacapp_tree_control;

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

static guint fContextTaggedError(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint8 tag_info = 0;
    guint8 parsed_tag = 0;
    guint32 lvt = 0;
    offset += fTagHeaderTree(tvb, tree, offset, &parsed_tag, &tag_info, &lvt);
    offset = fError(tvb, tree, offset);
    return offset + fTagHeaderTree(tvb, tree, offset, &parsed_tag, &tag_info, &lvt);
}

static guint
fConfirmedPrivateTransferError(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0:	/* errorType */
			offset = fContextTaggedError(tvb,tree,offset);
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

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0:	/* errorType */
			offset = fContextTaggedError(tvb,tree,offset);
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

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0:	/* errorType */
			offset = fContextTaggedError(tvb,tree,offset);
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

#if 0
static guint
fVTSession(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	if (tvb_length_remaining(tvb, offset) > 0) {	/* don't loop */
		offset = fUnsignedTag (tvb,tree,offset, "local-VTSessionID: ");
		offset = fUnsignedTag (tvb,tree,offset, "remote-VTSessionID: ");
		offset = fAddress (tvb,tree,offset);
	}
	return offset;
}
#endif

static guint
fVTCloseError(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
	guint lastoffset = 0;

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0:	/* errorType */
			offset = fContextTaggedError(tvb,tree,offset);
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

	while ((tvb_length_remaining(tvb, offset) > 0)&&(offset>lastoffset)) {  /* exit loop if nothing happens inside */
		lastoffset = offset;
		switch (fTagNo(tvb, offset)) {
		case 0:	/* errorType */
			offset = fContextTaggedError(tvb,tree,offset);
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
    offset = fApplicationTypesEnumeratedSplit (tvb, tree, offset, 
        "error Class: ", BACnetErrorClass, 64);
    return fApplicationTypesEnumeratedSplit (tvb, tree, offset, 
        "error Code: ", BACnetErrorCode, 256);
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
fErrorPDU(tvbuff_t *tvb, proto_tree *bacapp_tree, guint offset)
{	/* BACnet-Error-PDU */
	/* ASHRAE 135-2001 20.1.7 */

	proto_item *tc, *tt;
	proto_tree *bacapp_tree_control;
    guint8 tmp;

    tc = proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, offset++, 1, TRUE);
    bacapp_tree_control = proto_item_add_subtree(tc, ett_bacapp);

    proto_tree_add_item(bacapp_tree, hf_bacapp_invoke_id, tvb,
        offset++, 1, TRUE);
    tmp = tvb_get_guint8(tvb, offset);
    tt = proto_tree_add_item(bacapp_tree, hf_bacapp_service, tvb,
        offset++, 1, TRUE);
    /* Error Handling follows... */
    return fBACnetError (tvb, bacapp_tree, offset, tmp);
}

static guint
fRejectPDU(tvbuff_t *tvb, proto_tree *bacapp_tree, guint offset)
{	/* BACnet-Reject-PDU */
	/* ASHRAE 135-2001 20.1.8 */

	proto_item *tc;
	proto_tree *bacapp_tree_control;

    tc = proto_tree_add_item(bacapp_tree, hf_bacapp_type, tvb, offset++, 1, TRUE);
    bacapp_tree_control = proto_item_add_subtree(tc, ett_bacapp);

    proto_tree_add_item(bacapp_tree, hf_bacapp_invoke_id, tvb,
        offset++, 1, TRUE);
    proto_tree_add_item(bacapp_tree, hf_BACnetRejectReason, tvb,
        offset++, 1, TRUE);
	return offset;
}

static guint
fAbortPDU(tvbuff_t *tvb, proto_tree *bacapp_tree, guint offset)
{	/* BACnet-Abort-PDU */
	/* ASHRAE 135-2001 20.1.9 */

	proto_item *tc;
	proto_tree *bacapp_tree_control;

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
	proto_item *ti;
	proto_tree *bacapp_tree;

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
					val_to_split_str(bacapp_reason,
						64,
						BACnetRejectReason,
						ASHRAE_Reserved_Fmt,
						Vendor_Proprietary_Fmt));
				break;
			case BACAPP_TYPE_ABORT:
				bacapp_reason = tvb_get_guint8(tvb, offset + 2);
				col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
					val_to_split_str(bacapp_reason,
						64,
						BACnetAbortReason,
						ASHRAE_Reserved_Fmt,
						Vendor_Proprietary_Fmt));
				break;
			/* UNKNOWN */
			default:
				/* nothing more to add */
				break;
		}
	}
   
    if (tree) {
		ti = proto_tree_add_item(tree, proto_bacapp, tvb, offset, -1, FALSE);
		bacapp_tree = proto_item_add_subtree(ti, ett_bacapp);

		/* ASHRAE 135-2001 20.1.1 */
    	switch (bacapp_type) {
    	case BACAPP_TYPE_CONFIRMED_SERVICE_REQUEST:	/* BACnet-Confirmed-Service-Request */
    		offset = fConfirmedRequestPDU(tvb, bacapp_tree, offset);
    		break;
    	case BACAPP_TYPE_UNCONFIRMED_SERVICE_REQUEST:	/* BACnet-Unconfirmed-Request-PDU */
    		offset = fUnconfirmedRequestPDU(tvb, bacapp_tree, offset);
    		break;
    	case BACAPP_TYPE_SIMPLE_ACK:	/* BACnet-Simple-Ack-PDU */
    		offset = fSimpleAckPDU(tvb, bacapp_tree, offset);
    		break;
    	case BACAPP_TYPE_COMPLEX_ACK:	/* BACnet-Complex-Ack-PDU */
    		offset = fComplexAckPDU(tvb, bacapp_tree, offset);
    		break;
    	case BACAPP_TYPE_SEGMENT_ACK:	/* BACnet-SegmentAck-PDU */
    		offset = fSegmentAckPDU(tvb, bacapp_tree, offset);
    		break;
    	case BACAPP_TYPE_ERROR:	/* BACnet-Error-PDU */
    		offset = fErrorPDU(tvb, bacapp_tree, offset);
    		break;
    	case BACAPP_TYPE_REJECT:	/* BACnet-Reject-PDU */
    		offset = fRejectPDU(tvb, bacapp_tree, offset);
    		break;
    	case BACAPP_TYPE_ABORT:	/* BACnet-Abort-PDU */
    		offset = fAbortPDU(tvb, bacapp_tree, offset);
    		break;
    	}
    }

	next_tvb = tvb_new_subset(tvb,offset,-1,tvb_length_remaining(tvb,offset));
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
		{ &hf_bacapp_pduflags,
			{ "PDU Flags",			"bacapp.pduflags",
			FT_UINT8, BASE_HEX, NULL, 0x0f,	"PDU Flags", HFILL }
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
			FT_UINT8, BASE_DEC, VALS(BACnetMaxSegmentsAccepted), 0x70, "Max Response Segments accepted", HFILL }
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
			FT_UINT8, BASE_DEC, NULL, 0, "Invoke ID", HFILL }
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
			FT_NONE, 0, NULL, 0, "BACnet APDU variable part", HFILL }
		},
		{ &hf_bacapp_tag,
			{ "BACnet Tag",
			"bacapp.tag",
			FT_BYTES, BASE_HEX, NULL, 0,
			"BACnet Tag", HFILL }
		},
		{ &hf_BACnetApplicationTagNumber,
			{ "Application Tag Number",
			"bacapp.application_tag_number",
			FT_UINT8, BASE_DEC, VALS(&BACnetApplicationTagNumber), 0xF0,
			"Application Tag Number", HFILL }
		},
		{ &hf_BACnetContextTagNumber,
			{ "Context Tag Number",
			"bacapp.context_tag_number",
			FT_UINT8, BASE_DEC, NULL, 0xF0,
			"Context Tag Number", HFILL }
		},
		{ &hf_BACnetExtendedTagNumber,
			{ "Extended Tag Number",
			"bacapp.extended_tag_number",
			FT_UINT8, BASE_DEC, NULL, 0,
			"Extended Tag Number", HFILL }
		},
		{ &hf_BACnetNamedTag,
			{ "Named Tag",
			"bacapp.named_tag",
			FT_UINT8, BASE_DEC, VALS(&BACnetTagNames), 0x07,
			"Named Tag", HFILL }
		},
		{ &hf_BACnetCharacterSet,
			{ "String Character Set",
			"bacapp.string_character_set",
			FT_UINT8, BASE_DEC, VALS(&BACnetCharacterSet),0,
			"String Character Set", HFILL }
		},
		{ &hf_BACnetTagClass,
			{ "Tag Class",           "bacapp.tag_class",
			FT_BOOLEAN, 8, TFS(&BACnetTagClass), 0x08, "Tag Class", HFILL }
		},
		{ &hf_bacapp_tag_lvt,
			{ "Length Value Type",
			"bacapp.LVT",
			FT_UINT8, BASE_DEC, NULL, 0,
			"Length Value Type", HFILL }
		},
		{ &hf_bacapp_tag_value8,
			{ "Tag Value",
			"bacapp.tag_value8",
			FT_UINT8, BASE_DEC, NULL, 0,
			"Tag Value", HFILL }
		},
		{ &hf_bacapp_tag_value16,
			{ "Tag Value 16-bit",
			"bacapp.tag_value16",
			FT_UINT16, BASE_DEC, NULL, 0,
			"Tag Value 16-bit", HFILL }
		},
		{ &hf_bacapp_tag_value32,
			{ "Tag Value 32-bit",
			"bacapp.tag_value32",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Tag Value 32-bit", HFILL }
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
fConvertXXXtoUTF8 (const guint8 *in, size_t *inbytesleft, guint8 *out, size_t *outbytesleft, const gchar *fromcoding)
{  /* I don't want to let in and out be modified */
#ifdef HAVE_CONFIG_H
#if HAVE_ICONV_H
	guint32 i; 
	iconv_t icd;
	const guint8 *inp = in;
	guint8 *outp = out;
	const guint8 **inpp = &inp;
	guint8 **outpp = &outp;
     
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

