/* packet-rdm.c
 * RDM (Remote Device Management) packet disassembly.
 *
 * $Id$
 *
 * This dissector is written by
 * 
 *  Erwin Rol <erwin@erwinrol.com>
 *  Copyright 2003, 2011, 2012 Erwin Rol
 *
 *  Shaun Jackman <sjackman@gmail.com>
 *  Copyright 2006 Pathway Connectivity
 *
 *  Wireshark - Network traffic analyzer
 *  Gerald Combs <gerald@wireshark.org>
 *  Copyright 1999 Gerald Combs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor
 * Boston, MA  02110-1301, USA.
 */
/*
 * ANSI E1.20-2006, Entertainment Technology
 * Remote Device Management over USITT DMX512, describes a method of
 * bi-directional communications over a USITT DMX512/1990 data link
 * between an entertainment lighting controller and one or more
 * remotely controlled lighting devices. The protocol also is intended
 * to work with the ANSI E1.11-2004 control protocol. It allows
 * discovery of devices on a DMX512/E1.11 network and the remote
 * setting of DMX starting addresses, as well as status and fault
 * reporting back to the control console.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>

#define RDM_SC_RDM				0xCC
#define RDM_SC_SUB_MESSAGE			0x01

#define RDM_CC_DISCOVERY_COMMAND		0x10
#define RDM_CC_DISCOVERY_COMMAND_RESPONSE	0x11
#define RDM_CC_GET_COMMAND			0x20
#define RDM_CC_GET_COMMAND_RESPONSE		0x21
#define RDM_CC_SET_COMMAND			0x30
#define RDM_CC_SET_COMMAND_RESPONSE		0x31

static const value_string rdm_cc_vals[] = {
	{ RDM_CC_DISCOVERY_COMMAND,		"Discovery Command" },
	{ RDM_CC_DISCOVERY_COMMAND_RESPONSE,	"Discovery Command Response" },
	{ RDM_CC_GET_COMMAND,			"Get Command" },
	{ RDM_CC_GET_COMMAND_RESPONSE,		"Get Command Response" },
	{ RDM_CC_SET_COMMAND,			"Set Command" },
	{ RDM_CC_SET_COMMAND_RESPONSE,		"Set Command Response" },
	{ 0, NULL },
};

#define RDM_RESPONSE_TYPE_ACK			0x00
#define RDM_RESPONSE_TYPE_ACK_TIMER		0x01
#define RDM_RESPONSE_TYPE_NACK_REASON		0x02
#define RDM_RESPONSE_TYPE_ACK_OVERFLOW		0x03

static const value_string rdm_rt_vals[] = {
	{ RDM_RESPONSE_TYPE_ACK,		"Ack" },
	{ RDM_RESPONSE_TYPE_ACK_TIMER,		"Ack Timer" },
	{ RDM_RESPONSE_TYPE_NACK_REASON,	"Nack Reason" },
	{ RDM_RESPONSE_TYPE_ACK_OVERFLOW,	"Ack Overflow" },
	{ 0, NULL },
};

#define RDM_PARAM_ID_DISC_UNIQUE_BRANCH		0x0001
#define RDM_PARAM_ID_DISC_MUTE			0x0002
#define RDM_PARAM_ID_DISC_UN_MUTE		0x0003
#define RDM_PARAM_ID_PROXIED_DEVICES		0x0010
#define RDM_PARAM_ID_PROXIED_DEVICE_COUNT	0x0011
#define RDM_PARAM_ID_COMMS_STATUS		0x0015
#define RDM_PARAM_ID_QUEUED_MESSAGE		0x0020
#define RDM_PARAM_ID_STATUS_MESSAGES		0x0030
#define RDM_PARAM_ID_STATUS_ID_DESCRIPTION	0x0031
#define RDM_PARAM_ID_CLEAR_STATUS_ID		0x0032
#define RDM_PARAM_ID_SUB_DEVICE_STATUS_REPORT_THRESHOLD 0x0033
#define RDM_PARAM_ID_SUPPORTED_PARAMETERS	0x0050
#define RDM_PARAM_ID_PARAMETER_DESCRIPTION	0x0051
#define RDM_PARAM_ID_DEVICE_INFO		0x0060
#define RDM_PARAM_ID_PRODUCT_DETAIL_ID_LIST	0x0070
#define RDM_PARAM_ID_DEVICE_MODEL_DESCRIPTION	0x0080
#define RDM_PARAM_ID_MANUFACTURER_LABEL		0x0081
#define RDM_PARAM_ID_DEVICE_LABEL		0x0082
#define RDM_PARAM_ID_FACTORY_DEFAULTS		0x0090
#define RDM_PARAM_ID_LANGUAGE_CAPABILITIES	0x00A0
#define RDM_PARAM_ID_LANGUAGE			0x00B0
#define RDM_PARAM_ID_SOFTWARE_VERSION_LABEL	0x00C0
#define RDM_PARAM_ID_BOOT_SOFTWARE_VERSION_ID	0x00C1
#define RDM_PARAM_ID_BOOT_SOFTWARE_VERSION_LABEL 0x00C2
#define RDM_PARAM_ID_DMX_PERSONALITY		0x00E0
#define RDM_PARAM_ID_DMX_PERSONALITY_DESCRIPTION 0x00E1
#define RDM_PARAM_ID_DMX_START_ADDRESS		0x00F0
#define RDM_PARAM_ID_SLOT_INFO			0x0120
#define RDM_PARAM_ID_SLOT_DESCRIPTION		0x0121
#define RDM_PARAM_ID_DEFAULT_SLOT_VALUE		0x0122
#define RDM_PARAM_ID_SENSOR_DEFINITION		0x0200
#define RDM_PARAM_ID_SENSOR_VALUE		0x0201
#define RDM_PARAM_ID_RECORD_SENSORS		0x0202
#define RDM_PARAM_ID_DEVICE_HOURS 		0x0400
#define RDM_PARAM_ID_LAMP_HOURS 		0x0401
#define RDM_PARAM_ID_LAMP_STRIKES 		0x0402
#define RDM_PARAM_ID_LAMP_STATE 		0x0403
#define RDM_PARAM_ID_LAMP_ON_MODE 		0x0404
#define RDM_PARAM_ID_DEVICE_POWER_CYCLES 	0x0405
#define RDM_PARAM_ID_DISPLAY_INVERT		0x0500 
#define RDM_PARAM_ID_DISPLAY_LEVEL 		0x0501
#define RDM_PARAM_ID_PAN_INVERT 		0x0600
#define RDM_PARAM_ID_TILT_INVERT 		0x0601
#define RDM_PARAM_ID_PAN_TILT_SWAP 		0x0602
#define RDM_PARAM_ID_REAL_TIME_CLOCK 		0x0603
#define RDM_PARAM_ID_IDENTIFY_DEVICE 		0x1000
#define RDM_PARAM_ID_RESET_DEVICE 		0x1001
#define RDM_PARAM_ID_POWER_STATE 		0x1010
#define RDM_PARAM_ID_PERFORM_SELFTEST 		0x1020
#define RDM_PARAM_ID_SELF_TEST_DESCRIPTION 	0x1021
#define RDM_PARAM_ID_CAPTURE_PRESET 		0x1030
#define RDM_PARAM_ID_PRESET_PLAYBACK 		0x1031

static const value_string rdm_param_id_vals[] = {
	{ RDM_PARAM_ID_DISC_UNIQUE_BRANCH,	"DISC_UNIQUE_BRANCH" },
	{ RDM_PARAM_ID_DISC_MUTE,		"DISC_MUTE" },
	{ RDM_PARAM_ID_DISC_UN_MUTE,		"DISC_UN_MUTE" },
	{ RDM_PARAM_ID_PROXIED_DEVICES,		"PROXIED_DEVICES" },
	{ RDM_PARAM_ID_PROXIED_DEVICE_COUNT,	"PROXIED_DEVICE_COUNT" },
	{ RDM_PARAM_ID_COMMS_STATUS,		"COMMS_STATUS" },
	{ RDM_PARAM_ID_QUEUED_MESSAGE,		"QUEUED_MESSAGE" },
	{ RDM_PARAM_ID_STATUS_MESSAGES,		"STATUS_MESSAGES" },
	{ RDM_PARAM_ID_STATUS_ID_DESCRIPTION,	"STATUS_ID_DESCRIPTION" },
	{ RDM_PARAM_ID_CLEAR_STATUS_ID,		"CLEAR_STATUS_ID" },
	{ RDM_PARAM_ID_SUB_DEVICE_STATUS_REPORT_THRESHOLD, "DEVICE_STATUS_REPORT_THRESHOLD" },
	{ RDM_PARAM_ID_SUPPORTED_PARAMETERS,	"SUPPORTED_PARAMETERS" },
	{ RDM_PARAM_ID_PARAMETER_DESCRIPTION,	"PARAMETER_DESCRIPTION" },
	{ RDM_PARAM_ID_DEVICE_INFO,		"DEVICE_INFO" },
	{ RDM_PARAM_ID_PRODUCT_DETAIL_ID_LIST,	"PRODUCT_DETAIL_ID_LIST" },
	{ RDM_PARAM_ID_DEVICE_MODEL_DESCRIPTION, "DEVICE_MODEL_DESCRIPTION" },
	{ RDM_PARAM_ID_MANUFACTURER_LABEL,	"MANUFACTURER_LABEL" },
	{ RDM_PARAM_ID_DEVICE_LABEL,		"DEVICE_LABEL" },
	{ RDM_PARAM_ID_FACTORY_DEFAULTS,	"FACTORY_DEFAULTS" },
	{ RDM_PARAM_ID_LANGUAGE_CAPABILITIES,	"LANGUAGE_CAPABILITIES" },
	{ RDM_PARAM_ID_LANGUAGE,		"LANGUAGE" },
	{ RDM_PARAM_ID_SOFTWARE_VERSION_LABEL,	"SOFTWARE_VERSION_LABEL" },
	{ RDM_PARAM_ID_BOOT_SOFTWARE_VERSION_ID, "BOOT_SOFTWARE_VERSION_ID" },
	{ RDM_PARAM_ID_BOOT_SOFTWARE_VERSION_LABEL, "BOOT_SOFTWARE_VERSION_LABEL" },
	{ RDM_PARAM_ID_DMX_PERSONALITY,		"DMX_PERSONALITY" },
	{ RDM_PARAM_ID_DMX_PERSONALITY_DESCRIPTION, "DMX_PERSONALITY_DESCRIPTION" },
	{ RDM_PARAM_ID_DMX_START_ADDRESS,	"DMX_START_ADDRESS" },
	{ RDM_PARAM_ID_SLOT_INFO,		"SLOT_INFO" },
	{ RDM_PARAM_ID_SLOT_DESCRIPTION,	"SLOT_DESCRIPTION" },
	{ RDM_PARAM_ID_DEFAULT_SLOT_VALUE,	"DEFAULT_SLOT_VALUE" },
	{ RDM_PARAM_ID_SENSOR_DEFINITION,	"SENSOR_DEFINITION" },
	{ RDM_PARAM_ID_SENSOR_VALUE,		"SENSOR_VALUE" },
	{ RDM_PARAM_ID_RECORD_SENSORS,		"RECORD_SENSORS" },
	{ RDM_PARAM_ID_DEVICE_HOURS,		"DEVICE_HOURS" },
	{ RDM_PARAM_ID_LAMP_HOURS,		"LAMP_HOURS" },
	{ RDM_PARAM_ID_LAMP_STRIKES,		"LAMP_STRIKES" },
	{ RDM_PARAM_ID_LAMP_STATE,		"LAMP_STATE" },
	{ RDM_PARAM_ID_LAMP_ON_MODE,		"LAMP_ON_MODE" },
	{ RDM_PARAM_ID_DEVICE_POWER_CYCLES,	"DEVICE_POWER_CYCLES" },
	{ RDM_PARAM_ID_DISPLAY_INVERT,		"DISPLAY_INVERT" },
	{ RDM_PARAM_ID_DISPLAY_LEVEL,		"DISPLAY_LEVEL" },
	{ RDM_PARAM_ID_PAN_INVERT,		"PAN_INVERT" },
	{ RDM_PARAM_ID_TILT_INVERT,		"TILT_INVERT" },
	{ RDM_PARAM_ID_PAN_TILT_SWAP,		"PAN_TILT_SWAP" },
	{ RDM_PARAM_ID_REAL_TIME_CLOCK,		"REAL_TIME_CLOCK" },
	{ RDM_PARAM_ID_IDENTIFY_DEVICE,		"IDENTIFY_DEVICE" },
	{ RDM_PARAM_ID_RESET_DEVICE,		"RESET_DEVICE" },
	{ RDM_PARAM_ID_POWER_STATE,		"POWER_STATE" },
	{ RDM_PARAM_ID_PERFORM_SELFTEST,	"PERFORM_SELFTEST" },
	{ RDM_PARAM_ID_SELF_TEST_DESCRIPTION,	"SELF_TEST_DESCRIPTION" },
	{ RDM_PARAM_ID_CAPTURE_PRESET,		"CAPTURE_PRESET" },
	{ RDM_PARAM_ID_PRESET_PLAYBACK,		"PRESET_PLAYBACK" },
	{ 0, NULL },
};


#define RDM_STATUS_NONE				0x00
#define RMD_STATUS_GET_LAST_MESSAGE		0x01
#define RDM_STATUS_ADVISORY			0x02
#define RDM_STATUS_WARNING			0x03
#define RDM_STATUS_ERROR			0x04

static const value_string rdm_status_vals[] = {
	{ RDM_STATUS_NONE,		"None" },
	{ RMD_STATUS_GET_LAST_MESSAGE,	"Get Last Message" },
	{ RDM_STATUS_ADVISORY,		"Advisory" },
	{ RDM_STATUS_WARNING,		"Warning" },
	{ RDM_STATUS_ERROR,		"Error" },
	{ 0, NULL },
};

#define RDM_PREFIX_NONE		0x00
#define RDM_PREFIX_DECI		0x01
#define RDM_PREFIX_CENTI	0x02
#define RDM_PREFIX_MILLI	0x03
#define RDM_PREFIX_MICRO	0x04
#define RDM_PREFIX_NANO		0x05
#define RDM_PREFIX_PICO		0x06
#define RDM_PREFIX_FEMPTO	0x07
#define RDM_PREFIX_ATTO		0x08
#define RDM_PREFIX_ZEPTO	0x09
#define RDM_PREFIX_YOCTO	0x0A
#define RDM_PREFIX_DECA		0x11
#define RDM_PREFIX_HECTO	0x12
#define RDM_PREFIX_KILO		0x13
#define RDM_PREFIX_MEGA		0x14
#define RDM_PREFIX_GIGA		0x15
#define RDM_PREFIX_TERRA	0x16
#define RDM_PREFIX_PETA		0x17
#define RDM_PREFIX_EXA		0x18
#define RDM_PREFIX_ZETTA	0x19
#define RDM_PREFIX_YOTTA	0x1A

static const value_string rdm_prefix_vals[] = {
	{ RDM_PREFIX_NONE,	"NONE (x1)" },
	{ RDM_PREFIX_DECI,	"deci (x10^-1)" },
	{ RDM_PREFIX_CENTI,	"centi (x10^-2)" },
	{ RDM_PREFIX_MILLI,	"milli (x10^-3)" },
	{ RDM_PREFIX_MICRO,	"micro (x10^-6)" },
	{ RDM_PREFIX_NANO,	"nano (x10^-9)" },
	{ RDM_PREFIX_PICO,	"pico (x10^-12)" },
	{ RDM_PREFIX_FEMPTO,	"fempto (x10^-15)" },
	{ RDM_PREFIX_ATTO,	"atto (x10^-18)" },
	{ RDM_PREFIX_ZEPTO,	"zepto (x10^-21)" },
	{ RDM_PREFIX_YOCTO,	"yocto (x10^-24)" },
	{ RDM_PREFIX_DECA,	"deca (x10^1)" },
	{ RDM_PREFIX_HECTO,	"hecto (x10^2)" },
	{ RDM_PREFIX_KILO,	"kilo (x10^3)" },
	{ RDM_PREFIX_MEGA,	"mega (x10^6)" },
	{ RDM_PREFIX_GIGA,	"giga (x10^9)" },
	{ RDM_PREFIX_TERRA,	"terra (x10^12)" },
	{ RDM_PREFIX_PETA,	"peta (x10^15)" },
	{ RDM_PREFIX_EXA,	"exa (x10^18)" },
	{ RDM_PREFIX_ZETTA,	"zetta (x10^21)" },
	{ RDM_PREFIX_YOTTA,	"yotta (x10^24)" },
	{ 0, NULL },
};

#define RDM_UNITS_NONE			0x00
#define RDM_UNITS_CENTIGRADE		0x01
#define RDM_UNITS_VOLTS_DC		0x02
#define RDM_UNITS_VOLTS_AC_PEAK		0x03
#define RDM_UNITS_VOLTS_AC_RMS		0x04
#define RDM_UNITS_AMPERE_DC		0x05
#define RDM_UNITS_AMPERE_AC_PEAK	0x06
#define RDM_UNITS_AMPERE_AC_RMS		0x07
#define RDM_UNITS_HERTZ			0x08
#define RDM_UNITS_OHM			0x09
#define RDM_UNITS_WATT			0x0A
#define RDM_UNITS_KILOGRAM		0x0B
#define RDM_UNITS_METERS		0x0C
#define RDM_UNITS_METERS_SQUARED	0x0D
#define RDM_UNITS_METERS_CUBED		0x0E
#define RDM_UNITS_KILOGRAMMES_PER_METER_CUBED 0x0F
#define RDM_UNITS_METERS_PER_SECOND	0x10
#define RDM_UNITS_METERS_PER_SECOND_SQUARED 0x11
#define RDM_UNITS_NEWTON		0x12
#define RDM_UNITS_JOULE			0x13
#define RDM_UNITS_PASCAL		0x14
#define RDM_UNITS_SECOND		0x15
#define RDM_UNITS_DEGREE		0x16
#define RDM_UNITS_STERADIAN		0x17
#define RDM_UNITS_CANDELA		0x18
#define RDM_UNITS_LUMEN			0x19
#define RDM_UNITS_LUX			0x1A
#define RDM_UNITS_IRE			0x1B
#define RDM_UNITS_BYTE			0x1C

static const value_string rdm_unit_vals[] = {
	{ RDM_UNITS_NONE,		"NONE" },
	{ RDM_UNITS_CENTIGRADE,		"Centigrade" },
	{ RDM_UNITS_VOLTS_DC,		"Volts DC" },
	{ RDM_UNITS_VOLTS_AC_PEAK,	"Volts AC Peak" },
	{ RDM_UNITS_VOLTS_AC_RMS,	"Volts AC RMS" },
	{ RDM_UNITS_AMPERE_DC,		"Ampere DC" },
	{ RDM_UNITS_AMPERE_AC_PEAK,	"Ampere AC Peak" },
	{ RDM_UNITS_AMPERE_AC_RMS,	"Ampere AC RMS" },
	{ RDM_UNITS_HERTZ,		"Hertz" },
	{ RDM_UNITS_OHM,		"Ohm" },
	{ RDM_UNITS_WATT,		"Watt" },
	{ RDM_UNITS_KILOGRAM,		"Kilogram" },
	{ RDM_UNITS_METERS,		"Meters" },
	{ RDM_UNITS_METERS_SQUARED,	"Meters Squared" },
	{ RDM_UNITS_METERS_CUBED,	"Meters Cubed" },
	{ RDM_UNITS_KILOGRAMMES_PER_METER_CUBED, "Kilogrammes per Meter Cubed" },
	{ RDM_UNITS_METERS_PER_SECOND,	"Meters per Second" },
	{ RDM_UNITS_METERS_PER_SECOND_SQUARED, "Meters per Second Squared" },
	{ RDM_UNITS_NEWTON,		"Newton" },
	{ RDM_UNITS_JOULE,		"Joule" },
	{ RDM_UNITS_PASCAL,		"Pascal" },
	{ RDM_UNITS_SECOND,		"Second" },
	{ RDM_UNITS_DEGREE,		"Degree" },
	{ RDM_UNITS_STERADIAN,		"Steradian" },
	{ RDM_UNITS_CANDELA,		"Candela" },
	{ RDM_UNITS_LUMEN,		"Lumen" },
	{ RDM_UNITS_LUX,		"Lux" },
	{ RDM_UNITS_IRE,		"Ire" },
	{ RDM_UNITS_BYTE,		"Byte" },
	{ 0, NULL },
};

#define RDM_SENS_TEMPERATURE	0x00
#define RDM_SENS_VOLTAGE	0x01
#define RDM_SENS_CURRENT	0x02
#define RDM_SENS_FREQUENCY	0x03
#define RDM_SENS_RESISTANCE	0x04
#define RDM_SENS_POWER		0x05
#define RDM_SENS_MASS		0x06
#define RDM_SENS_LENGTH		0x07
#define RDM_SENS_AREA		0x08
#define RDM_SENS_VOLUME		0x09
#define RDM_SENS_DENSITY	0x0A
#define RDM_SENS_VELOCITY	0x0B
#define RDM_SENS_ACCELERATION	0x0C
#define RDM_SENS_FORCE		0x0D
#define RDM_SENS_ENERGY		0x0E
#define RDM_SENS_PRESSURE	0x0F
#define RDM_SENS_TIME		0x10
#define RDM_SENS_ANGLE		0x11
#define RDM_SENS_POSITION_X	0x12
#define RDM_SENS_POSITION_Y	0x13 
#define RDM_SENS_POSITION_Z	0x14 
#define RDM_SENS_ANGULAR_VELOCITY	0x15 
#define RDM_SENS_LUMINOUS_INTENSITY	0x16 
#define RDM_SENS_LUMINOUS_FLUX	0x17 
#define RDM_SENS_ILLUMINANCE	0x18 
#define RDM_SENS_CHROMINANCE_RED	0x19 
#define RDM_SENS_CHROMINANCE_GREEN	0x1A 
#define RDM_SENS_CHROMINANCE_BLUE	0x1B 
#define RDM_SENS_CONTACTS	0x1C
#define RDM_SENS_MEMORY		0x1D
#define RDM_SENS_ITEMS		0x1E
#define RDM_SENS_HUMIDITY	0x1F 
#define RDM_SENS_COUNTER_16BIT	0x20 
#define RDM_SENS_OTHER		0x7F 

static const value_string rdm_sensor_type_vals[] = {
	{ RDM_SENS_TEMPERATURE,		"Temperature" },
	{ RDM_SENS_VOLTAGE,		"Voltage" },
	{ RDM_SENS_CURRENT,		"Current" },
	{ RDM_SENS_FREQUENCY,		"Frequency" },
	{ RDM_SENS_RESISTANCE,		"Resistance" },
	{ RDM_SENS_POWER,		"Power" },
	{ RDM_SENS_MASS,		"Mass" },
	{ RDM_SENS_LENGTH,		"Lenght" },
	{ RDM_SENS_AREA,		"Area" },
	{ RDM_SENS_VOLUME,		"Volume" },
	{ RDM_SENS_DENSITY,		"Density" },
	{ RDM_SENS_VELOCITY,		"Velocity" },
	{ RDM_SENS_ACCELERATION,	"Acceleration" },
	{ RDM_SENS_FORCE,		"Force" },
	{ RDM_SENS_ENERGY,		"Energy" },
	{ RDM_SENS_PRESSURE,		"Pressure" },
	{ RDM_SENS_TIME,		"Time" },
	{ RDM_SENS_ANGLE,		"Angle" },
	{ RDM_SENS_POSITION_X,		"Position X" },
	{ RDM_SENS_POSITION_Y,		"Position Y" },
	{ RDM_SENS_POSITION_Z,		"Position Z" },
	{ RDM_SENS_ANGULAR_VELOCITY,	"Angular Velocity" },
	{ RDM_SENS_LUMINOUS_INTENSITY,	"Luminous Intensity" },
	{ RDM_SENS_LUMINOUS_FLUX,	"Luminous Flux" },
	{ RDM_SENS_ILLUMINANCE,		"Illuminance" },
	{ RDM_SENS_CHROMINANCE_RED,	"Chrominance Red" },
	{ RDM_SENS_CHROMINANCE_GREEN,	"Chrominance Green" },
	{ RDM_SENS_CHROMINANCE_BLUE,	"Chrominance Blue" },
	{ RDM_SENS_CONTACTS,		"Contacts" },
	{ RDM_SENS_MEMORY,		"Memory" },
	{ RDM_SENS_ITEMS,		"Items" },
	{ RDM_SENS_HUMIDITY,		"Humidity" },
	{ RDM_SENS_COUNTER_16BIT,	"Counter 16bit" },
	{ RDM_SENS_OTHER,		"Other" },
	{ 0, NULL} ,
};

#define RDM_PRODUCT_CATEGORY_NOT_DECLARED		0x0000
#define RDM_PRODUCT_CATEGORY_FIXTURE			0x0100
#define RDM_PRODUCT_CATEGORY_FIXTURE_FIXED		0x0101
#define RDM_PRODUCT_CATEGORY_FIXTURE_MOVING_YOKE	0x0102 
#define RDM_PRODUCT_CATEGORY_FIXTURE_MOVING_MIRROR	0x0103 
#define RDM_PRODUCT_CATEGORY_FIXTURE_OTHER		0x01FF
#define RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY		0x0200
#define RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY_COLOR	0x0201
#define RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY_YOKE	0x0202
#define RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY_MIRROR	0x0203
#define RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY_EFFECT	0x0204
#define RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY_BEAM	0x0205
#define RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY_OTHER	0x02FF 
#define RDM_PRODUCT_CATEGORY_PROJECTOR			0x0300
#define RDM_PRODUCT_CATEGORY_PROJECTOR_FIXED		0x0301
#define RDM_PRODUCT_CATEGORY_PROJECTOR_MOVING_YOKE	0x0302 
#define RDM_PRODUCT_CATEGORY_PROJECTOR_MOVING_MIRROR	0x0303 
#define RDM_PRODUCT_CATEGORY_PROJECTOR_OTHER		0x03FF 
#define RDM_PRODUCT_CATEGORY_ATMOSPHERIC		0x0400
#define RDM_PRODUCT_CATEGORY_ATMOSPHERIC_EFFECT		0x0401
#define RDM_PRODUCT_CATEGORY_ATMOSPHERIC_PYRO		0x0402
#define RDM_PRODUCT_CATEGORY_ATMOSPHERIC_OTHER		0x04FF
#define RDM_PRODUCT_CATEGORY_DIMMER			0x0500  
#define RDM_PRODUCT_CATEGORY_DIMMER_AC_INCANDESCENT	0x0501 
#define RDM_PRODUCT_CATEGORY_DIMMER_AC_FLUORESCENT	0x0502 
#define RDM_PRODUCT_CATEGORY_DIMMER_AC_COLDCATHODE	0x0503 
#define RDM_PRODUCT_CATEGORY_DIMMER_AC_NONDIM		0x0504 
#define RDM_PRODUCT_CATEGORY_DIMMER_AC_ELV		0x0505 
#define RDM_PRODUCT_CATEGORY_DIMMER_AC_OTHER		0x0506 
#define RDM_PRODUCT_CATEGORY_DIMMER_DC_LEVEL		0x0507
#define RDM_PRODUCT_CATEGORY_DIMMER_DC_PWM		0x0508
#define RDM_PRODUCT_CATEGORY_DIMMER_CS_LED		0x0509
#define RDM_PRODUCT_CATEGORY_DIMMER_OTHER		0x05FF 
#define RDM_PRODUCT_CATEGORY_POWER			0x0600
#define RDM_PRODUCT_CATEGORY_POWER_CONTROL		0x0601 
#define RDM_PRODUCT_CATEGORY_POWER_SOURCE		0x0602
#define RDM_PRODUCT_CATEGORY_POWER_OTHER		0x06FF
#define RDM_PRODUCT_CATEGORY_SCENIC			0x0700
#define RDM_PRODUCT_CATEGORY_SCENIC_DRIVE		0x0701
#define RDM_PRODUCT_CATEGORY_SCENIC_OTHER		0x07FF 
#define RDM_PRODUCT_CATEGORY_DATA			0x0800
#define RDM_PRODUCT_CATEGORY_DATA_DISTRIBUTION		0x0801
#define RDM_PRODUCT_CATEGORY_DATA_CONVERSION		0x0802
#define RDM_PRODUCT_CATEGORY_DATA_OTHER			0x08FF 
#define RDM_PRODUCT_CATEGORY_AV				0x0900
#define RDM_PRODUCT_CATEGORY_AV_AUDIO			0x0901
#define RDM_PRODUCT_CATEGORY_AV_VIDEO			0x0902
#define RDM_PRODUCT_CATEGORY_AV_OTHER			0x09FF 
#define RDM_PRODUCT_CATEGORY_MONITOR			0x0A00
#define RDM_PRODUCT_CATEGORY_MONITOR_ACLINEPOWER	0x0A01
#define RDM_PRODUCT_CATEGORY_MONITOR_DCPOWER		0x0A02 
#define RDM_PRODUCT_CATEGORY_MONITOR_ENVIRONMENTAL	0x0A03
#define RDM_PRODUCT_CATEGORY_MONITOR_OTHER		0x0AFF 
#define RDM_PRODUCT_CATEGORY_CONTROL			0x7000 
#define RDM_PRODUCT_CATEGORY_CONTROL_CONTROLLER		0x7001 
#define RDM_PRODUCT_CATEGORY_CONTROL_BACKUPDEVICE	0x7002 
#define RDM_PRODUCT_CATEGORY_CONTROL_OTHER		0x70FF 
#define RDM_PRODUCT_CATEGORY_TEST			0x7100 
#define RDM_PRODUCT_CATEGORY_TEST_EQUIPMENT		0x7101 
#define RDM_PRODUCT_CATEGORY_TEST_EQUIPMENT_OTHER	0x71FF 
#define RDM_PRODUCT_CATEGORY_OTHER			0x7FFF 

static const value_string rdm_product_cat_vals[] = {
	{ RDM_PRODUCT_CATEGORY_NOT_DECLARED,		"Not Declared" },
	{ RDM_PRODUCT_CATEGORY_FIXTURE,			"Fixture" },
	{ RDM_PRODUCT_CATEGORY_FIXTURE_FIXED,		"Fixture Fixed" },
	{ RDM_PRODUCT_CATEGORY_FIXTURE_MOVING_YOKE,	"Fixture Moving Yoke" },
	{ RDM_PRODUCT_CATEGORY_FIXTURE_MOVING_MIRROR,	"Fixture Moving Mirror" },
	{ RDM_PRODUCT_CATEGORY_FIXTURE_OTHER,		"Fixture Other" },
	{ RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY,	"Fixture Accessory" },
	{ RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY_COLOR,	"Fixture Accessory Color" },
	{ RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY_YOKE,	"Fixture Accessory Yoke" },
	{ RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY_MIRROR,"Fixture Accessory Mirror" },
	{ RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY_EFFECT,"Fixture Accessory Effect" },
	{ RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY_BEAM,	"Fixture Accessory Beam" },
	{ RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY_OTHER,	"Fixture Accessory Other" },
	{ RDM_PRODUCT_CATEGORY_PROJECTOR,		"Projector" },
	{ RDM_PRODUCT_CATEGORY_PROJECTOR_FIXED,		"Projector Fixed" },
	{ RDM_PRODUCT_CATEGORY_PROJECTOR_MOVING_YOKE,	"Projector Moving Yoke" },
	{ RDM_PRODUCT_CATEGORY_PROJECTOR_MOVING_MIRROR,	"Projector Moving Mirror" },
	{ RDM_PRODUCT_CATEGORY_PROJECTOR_OTHER,		"Projector Other" },
	{ RDM_PRODUCT_CATEGORY_ATMOSPHERIC,		"Atmospheric" },
	{ RDM_PRODUCT_CATEGORY_ATMOSPHERIC_EFFECT,	"Atmospheric Effect" },
	{ RDM_PRODUCT_CATEGORY_ATMOSPHERIC_PYRO,	"Atmospheric Pyro" },
	{ RDM_PRODUCT_CATEGORY_ATMOSPHERIC_OTHER,	"Atmospheric Other" },
	{ RDM_PRODUCT_CATEGORY_DIMMER,			"Dimmer" },
	{ RDM_PRODUCT_CATEGORY_DIMMER_AC_INCANDESCENT,	"Dimmer AC Incandescent" },
	{ RDM_PRODUCT_CATEGORY_DIMMER_AC_FLUORESCENT,	"Dimmer AC Fluorescent" },
	{ RDM_PRODUCT_CATEGORY_DIMMER_AC_COLDCATHODE,	"Dimmer AC Coldcathode" },
	{ RDM_PRODUCT_CATEGORY_DIMMER_AC_NONDIM,	"Dimmer AC Nondim" },
	{ RDM_PRODUCT_CATEGORY_DIMMER_AC_ELV,		"Dimmer AC ELV" },
	{ RDM_PRODUCT_CATEGORY_DIMMER_AC_OTHER,		"Dimmer AC Other" },
	{ RDM_PRODUCT_CATEGORY_DIMMER_DC_LEVEL,		"Dimmer DC Level" },
	{ RDM_PRODUCT_CATEGORY_DIMMER_DC_PWM,		"Dimmer DC PWM" },
	{ RDM_PRODUCT_CATEGORY_DIMMER_CS_LED,		"Dimmer CS LED" },
	{ RDM_PRODUCT_CATEGORY_DIMMER_OTHER,		"Dimmer Other" },
	{ RDM_PRODUCT_CATEGORY_POWER,			"Power" },
	{ RDM_PRODUCT_CATEGORY_POWER_CONTROL,		"Power Control" },
	{ RDM_PRODUCT_CATEGORY_POWER_SOURCE,		"Power Source" },
	{ RDM_PRODUCT_CATEGORY_POWER_OTHER,		"Power Other" },
	{ RDM_PRODUCT_CATEGORY_SCENIC,			"Scenic" },
	{ RDM_PRODUCT_CATEGORY_SCENIC_DRIVE,		"Scenic Drive" },
	{ RDM_PRODUCT_CATEGORY_SCENIC_OTHER,		"Scenic Other" },
	{ RDM_PRODUCT_CATEGORY_DATA,			"Data" },
	{ RDM_PRODUCT_CATEGORY_DATA_DISTRIBUTION,	"Data Distribution" },
	{ RDM_PRODUCT_CATEGORY_DATA_CONVERSION,		"Data Conversion" },
	{ RDM_PRODUCT_CATEGORY_DATA_OTHER,		"Data Other" },
	{ RDM_PRODUCT_CATEGORY_AV,			"AV" },
	{ RDM_PRODUCT_CATEGORY_AV_AUDIO,		"AV Audio" },
	{ RDM_PRODUCT_CATEGORY_AV_VIDEO,		"AV Video" },
	{ RDM_PRODUCT_CATEGORY_AV_OTHER,		"AV Other" },
	{ RDM_PRODUCT_CATEGORY_MONITOR,			"Monitor" },
	{ RDM_PRODUCT_CATEGORY_MONITOR_ACLINEPOWER,	"Monitor AC Line Power" },
	{ RDM_PRODUCT_CATEGORY_MONITOR_DCPOWER,		"Monitor DC Power" },
	{ RDM_PRODUCT_CATEGORY_MONITOR_ENVIRONMENTAL,	"Monitor Environmental" },
	{ RDM_PRODUCT_CATEGORY_MONITOR_OTHER,		"Monitor Other" },
	{ RDM_PRODUCT_CATEGORY_CONTROL,			"Control" },
	{ RDM_PRODUCT_CATEGORY_CONTROL_CONTROLLER,	"Control Controller" },
	{ RDM_PRODUCT_CATEGORY_CONTROL_BACKUPDEVICE,	"Control Backup Device" },
	{ RDM_PRODUCT_CATEGORY_CONTROL_OTHER,		"Control Other" },
	{ RDM_PRODUCT_CATEGORY_TEST,			"Test" },
	{ RDM_PRODUCT_CATEGORY_TEST_EQUIPMENT,		"Test Equipment" },
	{ RDM_PRODUCT_CATEGORY_TEST_EQUIPMENT_OTHER,	"Test Equipment Other" },
	{ RDM_PRODUCT_CATEGORY_OTHER,			"Other" },
	{ 0, NULL },
};

static int proto_rdm = -1;

static int hf_rdm_sub_start_code = -1;
static int hf_rdm_message_length = -1;
static int hf_rdm_dest_uid = -1;
static int hf_rdm_src_uid = -1;
static int hf_rdm_transaction_number = -1;
static int hf_rdm_port_id = -1;
static int hf_rdm_response_type = -1;
static int hf_rdm_message_count = -1;
static int hf_rdm_sub_device = -1;
static int hf_rdm_mdb = -1;
static int hf_rdm_command_class = -1;
static int hf_rdm_parameter_id = -1;
static int hf_rdm_parameter_data_length = -1;
static int hf_rdm_parameter_data = -1;
static int hf_rdm_parameter_data_raw = -1;
static int hf_rdm_intron = -1;
static int hf_rdm_checksum = -1;
static int hf_rdm_checksum_good = -1;
static int hf_rdm_checksum_bad = -1;
static int hf_rdm_trailer = -1;

static int hf_rdm_pd_device_label = -1;

static int hf_rdm_pd_manu_label = -1;

static int hf_rdm_pd_dmx_start_address = -1;

static int hf_rdm_pd_queued_message_status = -1;

static int hf_rdm_pd_sensor_nr = -1;
static int hf_rdm_pd_sensor_type = -1;
static int hf_rdm_pd_sensor_unit = -1;
static int hf_rdm_pd_sensor_prefix = -1;
static int hf_rdm_pd_sensor_value_pres = -1;
static int hf_rdm_pd_sensor_value_low = -1;
static int hf_rdm_pd_sensor_value_high = -1;
static int hf_rdm_pd_sensor_value_rec = -1;

static int hf_rdm_pd_sensor_range_min_value = -1;
static int hf_rdm_pd_sensor_range_max_value = -1;
static int hf_rdm_pd_sensor_normal_min_value = -1;
static int hf_rdm_pd_sensor_normal_max_value = -1;
static int hf_rdm_pd_sensor_recorded_value_support = -1;
static int hf_rdm_pd_sensor_description = -1;

static int hf_rdm_pd_device_hours = -1;
static int hf_rdm_pd_lamp_hours = -1;
static int hf_rdm_pd_lamp_strikes = -1;


static int hf_rdm_pd_proto_vers = -1;
static int hf_rdm_pd_device_model_id = -1;
static int hf_rdm_pd_product_cat = -1;
static int hf_rdm_pd_software_vers_id = -1;
static int hf_rdm_pd_dmx_footprint = -1;
static int hf_rdm_pd_dmx_pers_current = -1;
static int hf_rdm_pd_dmx_pers_total = -1;
static int hf_rdm_pd_sub_device_count = -1;
static int hf_rdm_pd_sensor_count = -1;

static int hf_rdm_pd_device_model_description = -1;

static int hf_rdm_pd_disc_unique_branch_lb_uid = -1;
static int hf_rdm_pd_disc_unique_branch_ub_uid = -1;
static int hf_rdm_pd_disc_mute_control_field = -1;
static int hf_rdm_pd_disc_mute_binding_uid = -1;
static int hf_rdm_pd_disc_unmute_control_field = -1;
static int hf_rdm_pd_disc_unmute_binding_uid = -1;
static int hf_rdm_pd_proxied_devices_uid = -1;
static int hf_rdm_pd_proxied_device_count = -1;
static int hf_rdm_pd_proxied_device_list_change = -1;
static int hf_rdm_pd_real_time_clock_year = -1;
static int hf_rdm_pd_real_time_clock_month = -1;
static int hf_rdm_pd_real_time_clock_day = -1;
static int hf_rdm_pd_real_time_clock_hour = -1;
static int hf_rdm_pd_real_time_clock_minute = -1;
static int hf_rdm_pd_real_time_clock_second = -1;
static int hf_rdm_pd_lamp_state = -1;
static int hf_rdm_pd_lamp_on_mode = -1;
static int hf_rdm_pd_device_power_cycles = -1;
static int hf_rdm_pd_display_invert = -1;
static int hf_rdm_pd_display_level = -1;
static int hf_rdm_pd_pan_invert = -1;
static int hf_rdm_pd_tilt_invert = -1;
static int hf_rdm_pd_tilt_swap = -1;
static int hf_rdm_pd_selftest_nr = -1;
static int hf_rdm_pd_selftest_state = -1;
static int hf_rdm_pd_selftest_description = -1;
static int hf_rdm_pd_language_code = -1;
static int hf_rdm_pd_identify_device = -1;
static int hf_rdm_pd_identify_device_state = -1;
static int hf_rdm_pd_reset_device = -1;
static int hf_rdm_pd_power_state = -1;
static int hf_rdm_pd_capture_preset_scene_nr = -1;
static int hf_rdm_pd_capture_preset_up_fade_time = -1;
static int hf_rdm_pd_capture_preset_down_fade_time = -1;
static int hf_rdm_pd_capture_preset_wait_time = -1;
static int hf_rdm_pd_preset_playback_mode = -1;
static int hf_rdm_pd_preset_playback_level = -1;
static int hf_rdm_pd_parameter_id = -1;
static int hf_rdm_pd_parameter_pdl_size = -1;
static int hf_rdm_pd_parameter_data_type = -1;
static int hf_rdm_pd_parameter_cmd_class = -1;
static int hf_rdm_pd_parameter_type = -1;
static int hf_rdm_pd_parameter_unit = -1;
static int hf_rdm_pd_parameter_prefix = -1;
static int hf_rdm_pd_parameter_min_value = -1;
static int hf_rdm_pd_parameter_max_value = -1;
static int hf_rdm_pd_parameter_default_value = -1;
static int hf_rdm_pd_parameter_description = -1;
static int hf_rdm_pd_software_version_label = -1;
static int hf_rdm_pd_boot_software_version_id = -1;
static int hf_rdm_pd_boot_software_version_label = -1;
static int hf_rdm_pd_comms_status_short_msg = -1;
static int hf_rdm_pd_comms_status_len_mismatch = -1;
static int hf_rdm_pd_comms_status_csum_fail = -1;
static int hf_rdm_pd_status_messages_type = -1;
static int hf_rdm_pd_status_messages_sub_device_id = -1;
static int hf_rdm_pd_status_messages_id = -1;
static int hf_rdm_pd_status_messages_data_value_1 = -1;
static int hf_rdm_pd_status_messages_data_value_2 = -1;
static int hf_rdm_pd_status_id = -1;
static int hf_rdm_pd_status_id_description = -1;
static int hf_rdm_pd_sub_device_status_report_threshold_status_type = -1;
static int hf_rdm_pd_product_detail_id_list = -1;
static int hf_rdm_pd_factory_defaults = -1;
static int hf_rdm_pd_dmx_pers_nr = -1;
static int hf_rdm_pd_dmx_pers_count = -1;
static int hf_rdm_pd_dmx_pers_description = -1;
static int hf_rdm_pd_dmx_pers_slots = -1;
static int hf_rdm_pd_dmx_pers_text = -1;
static int hf_rdm_pd_slot_offset = -1;
static int hf_rdm_pd_slot_type = -1;
static int hf_rdm_pd_slot_label_id = -1;
static int hf_rdm_pd_slot_nr = -1;
static int hf_rdm_pd_slot_description = -1;
static int hf_rdm_pd_slot_value = -1;
static int hf_rdm_pd_rec_value_support = -1;


static int ett_rdm = -1;

static guint16
rdm_checksum(tvbuff_t *tvb, unsigned length)
{
	guint16 sum = RDM_SC_RDM;
	unsigned i;
	for (i = 0; i < length; i++)
		sum += tvb_get_guint8(tvb, i);
	return sum;
}

static guint
dissect_rdm_pd_queued_message(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_GET_COMMAND:
		proto_tree_add_item(tree, hf_rdm_pd_queued_message_status, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset++;
		break;
	}

	return offset;
}

static guint
dissect_rdm_pd_dmx_start_address(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_SET_COMMAND:
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_dmx_start_address, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset+=2;
		break;
	}

	return offset;
}

static guint
dissect_rdm_pd_device_info(tvbuff_t *tvb _U_, guint offset, proto_tree *tree _U_, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_proto_vers, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset+=2;

		proto_tree_add_item(tree, hf_rdm_pd_device_model_id, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset+=2;

		proto_tree_add_item(tree, hf_rdm_pd_product_cat, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset+=2;

		proto_tree_add_item(tree, hf_rdm_pd_software_vers_id, tvb,
			offset, 4, ENC_BIG_ENDIAN);
		offset+=4;

		proto_tree_add_item(tree, hf_rdm_pd_dmx_footprint, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset+=2;

		proto_tree_add_item(tree, hf_rdm_pd_dmx_pers_current, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(tree, hf_rdm_pd_dmx_pers_total, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(tree, hf_rdm_pd_dmx_start_address, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset+=2;

		proto_tree_add_item(tree, hf_rdm_pd_sub_device_count, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset+=2;

		proto_tree_add_item(tree, hf_rdm_pd_sensor_count, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset++;

		break;
	}

	return offset;
}

			
static guint
dissect_rdm_pd_device_model_description(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len)
{
	switch(cc) {
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_device_model_description, tvb,
			offset, len, ENC_BIG_ENDIAN);
		offset+=len;
		break;
	}

	return offset;
}

			
static guint
dissect_rdm_pd_device_label(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len)
{
	switch(cc) {
	case RDM_CC_SET_COMMAND:
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_device_label, tvb,
			offset, len, ENC_BIG_ENDIAN);
		offset+=len;
		break;
	}

	return offset;
}

			
static guint
dissect_rdm_pd_device_hours(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_SET_COMMAND:
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_device_hours, tvb,
			offset, 4, ENC_BIG_ENDIAN);
		offset+=4;
		break;
	}

	return offset;
}

			
static guint
dissect_rdm_pd_lamp_hours(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_SET_COMMAND:
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_lamp_hours, tvb,
			offset, 4, ENC_BIG_ENDIAN);
		offset+=4;
		break;
	}

	return offset;
}

			
static guint
dissect_rdm_pd_lamp_strikes(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_SET_COMMAND:
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_lamp_strikes, tvb,
			offset, 4, ENC_BIG_ENDIAN);
		offset+=4;
		break;
	}

	return offset;
}

			
static guint
dissect_rdm_pd_sensor_definition(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len)
{
	switch(cc) {
	case RDM_CC_GET_COMMAND:
		proto_tree_add_item(tree, hf_rdm_pd_sensor_nr, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset++;
		break;

	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_sensor_nr, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(tree, hf_rdm_pd_sensor_type, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(tree, hf_rdm_pd_sensor_unit, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(tree, hf_rdm_pd_sensor_prefix, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(tree, hf_rdm_pd_sensor_range_min_value, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset+=2;

		proto_tree_add_item(tree, hf_rdm_pd_sensor_range_max_value, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset+=2;

		proto_tree_add_item(tree, hf_rdm_pd_sensor_normal_min_value, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset+=2;

		proto_tree_add_item(tree, hf_rdm_pd_sensor_normal_max_value, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset+=2;

		proto_tree_add_item(tree, hf_rdm_pd_sensor_recorded_value_support, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(tree, hf_rdm_pd_sensor_description, tvb,
			offset, len - 13, ENC_BIG_ENDIAN);
		offset += (len - 13);
		break;
	}

	return offset;
}

static guint
dissect_rdm_pd_sensor_value(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len)
{
	switch(cc) {
	case RDM_CC_GET_COMMAND:
	case RDM_CC_SET_COMMAND:
		proto_tree_add_item(tree, hf_rdm_pd_sensor_nr, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset++;
		break;

	case RDM_CC_GET_COMMAND_RESPONSE:
	case RDM_CC_SET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_sensor_nr, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(tree, hf_rdm_pd_sensor_value_pres, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset+=2;

		if (len == 7 || len == 9) {
			proto_tree_add_item(tree, hf_rdm_pd_sensor_value_low, tvb,
				offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			proto_tree_add_item(tree, hf_rdm_pd_sensor_value_high, tvb,
				offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
		}
	
		if (len == 5 || len == 9) {
			proto_tree_add_item(tree, hf_rdm_pd_sensor_value_rec, tvb,
				offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
		}

		break;
	}

	return offset;
}
			
static guint
dissect_rdm_pd_manufacturer_label(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len)
{
	switch(cc) {
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_manu_label, tvb,
			offset, len, ENC_BIG_ENDIAN);
		offset+=len;
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_disc_unique_branch(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_DISCOVERY_COMMAND:
		proto_tree_add_item(tree, hf_rdm_pd_disc_unique_branch_lb_uid, tvb,
			offset, 6, ENC_NA);
		offset += 6;
		
		proto_tree_add_item(tree, hf_rdm_pd_disc_unique_branch_ub_uid, tvb,
			offset, 6, ENC_NA);
		offset += 6;		
		break;
	}

	return offset;
}

static guint
dissect_rdm_pd_disc_mute(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len)
{
	switch(cc) {		
	case RDM_CC_DISCOVERY_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_disc_mute_control_field, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;		
		if (len > 2) {
			proto_tree_add_item(tree, hf_rdm_pd_disc_mute_binding_uid, tvb,
				offset, 6, ENC_NA);
			offset += 6;
		}
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_disc_un_mute(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len)
{
	switch(cc) {
	case RDM_CC_DISCOVERY_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_disc_unmute_control_field, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;		
		if (len > 2) {
			proto_tree_add_item(tree, hf_rdm_pd_disc_unmute_binding_uid, tvb,
				offset, 6, ENC_NA);
			offset += 6;
		}
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_proxied_devices(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len)
{
	switch(cc) {
	case RDM_CC_GET_COMMAND_RESPONSE:
		while (len >= 6) {
			proto_tree_add_item(tree, hf_rdm_pd_proxied_devices_uid, tvb,
				offset, 6, ENC_NA);
			offset += 6;
			len -= 6;
		}
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_proxied_device_count(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_proxied_device_count, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;		
		proto_tree_add_item(tree, hf_rdm_pd_proxied_device_list_change, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_comms_status(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_comms_status_short_msg, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;		
		proto_tree_add_item(tree, hf_rdm_pd_comms_status_len_mismatch, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;		
		proto_tree_add_item(tree, hf_rdm_pd_comms_status_csum_fail, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_status_messages(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len)
{
	switch(cc) {
	case RDM_CC_GET_COMMAND:
		proto_tree_add_item(tree, hf_rdm_pd_status_messages_type, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;			
		break;
		
	case RDM_CC_GET_COMMAND_RESPONSE:
		while (len >= 9) {
			proto_tree_add_item(tree, hf_rdm_pd_status_messages_sub_device_id, tvb,
				offset, 2, ENC_BIG_ENDIAN);
			offset += 2;			
			len -= 2;
			proto_tree_add_item(tree, hf_rdm_pd_status_messages_type, tvb,
				offset, 1, ENC_BIG_ENDIAN);
			offset += 1;			
			len -= 1;
			proto_tree_add_item(tree, hf_rdm_pd_status_messages_id, tvb,
				offset, 2, ENC_BIG_ENDIAN);
			offset += 2;			
			len -= 2;
			proto_tree_add_item(tree, hf_rdm_pd_status_messages_data_value_1, tvb,
				offset, 2, ENC_BIG_ENDIAN);
			offset += 2;			
			len -= 2;
			proto_tree_add_item(tree, hf_rdm_pd_status_messages_data_value_2, tvb,
				offset, 2, ENC_BIG_ENDIAN);
			offset += 2;			
			len -= 2;
		}
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_status_id_description(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len)
{
	switch(cc) {
	case RDM_CC_GET_COMMAND:
		proto_tree_add_item(tree, hf_rdm_pd_status_id, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		break;
		
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_status_id_description, tvb,
			offset, len, ENC_BIG_ENDIAN);
		offset += len;
		break;
	}

	return offset;
}

static guint
dissect_rdm_pd_clear_status_id(tvbuff_t *tvb _U_, guint offset, proto_tree *tree _U_, guint8 cc _U_, guint8 len _U_)
{
	return offset;
}

static guint
dissect_rdm_pd_sub_device_status_report_threshold(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_SET_COMMAND:
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_sub_device_status_report_threshold_status_type, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		break;
	}

	return offset;
}

static guint
dissect_rdm_pd_supported_parameters(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len)
{
	switch(cc) {
	case RDM_CC_GET_COMMAND_RESPONSE:
		while (len >= 2) {
			proto_tree_add_item(tree, hf_rdm_pd_parameter_id, tvb,
				offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			len -= 2;
		}
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_parameter_description(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len)
{
	switch(cc) {
	case RDM_CC_GET_COMMAND:
		proto_tree_add_item(tree, hf_rdm_pd_parameter_id, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		break;
		
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_parameter_id, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, hf_rdm_pd_parameter_pdl_size, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(tree, hf_rdm_pd_parameter_data_type, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(tree, hf_rdm_pd_parameter_cmd_class, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(tree, hf_rdm_pd_parameter_type, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(tree, hf_rdm_pd_parameter_unit, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(tree, hf_rdm_pd_parameter_prefix, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(tree, hf_rdm_pd_parameter_min_value, tvb,
			offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_rdm_pd_parameter_max_value, tvb,
			offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_rdm_pd_parameter_default_value, tvb,
			offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_rdm_pd_parameter_description, tvb,
			offset, len - 0x14, ENC_BIG_ENDIAN);
		offset += (len - 0x14);		
		break;
	}

	return offset;
}

static guint
dissect_rdm_pd_product_detail_id_list(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len)
{
	switch(cc) {
	case RDM_CC_GET_COMMAND_RESPONSE:
		while (len >= 2) {
			proto_tree_add_item(tree, hf_rdm_pd_product_detail_id_list, tvb,
				offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			len -= 2;
		}
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_factory_defaults(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_factory_defaults, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_language_capabilities(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len)
{
	switch(cc) {
	case RDM_CC_GET_COMMAND_RESPONSE:
		while (len >= 2) {
			proto_tree_add_item(tree, hf_rdm_pd_language_code, tvb,
				offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			len -= 2;
		}
		break;
	}

	return offset;
}

static guint
dissect_rdm_pd_language(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_SET_COMMAND:
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_language_code, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		break;
	}

	return offset;
}

static guint
dissect_rdm_pd_software_version_label(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len)
{
	switch(cc) {
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_software_version_label, tvb,
			offset, len, ENC_BIG_ENDIAN);
		offset += len;
	
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_boot_software_version_id(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_boot_software_version_id, tvb,
			offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_boot_software_version_label(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len)
{
	switch(cc) {
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_boot_software_version_label, tvb,
			offset, len, ENC_BIG_ENDIAN);
		offset += len;
	
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_dmx_personality(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_SET_COMMAND:
		proto_tree_add_item(tree, hf_rdm_pd_dmx_pers_nr, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		break;
		
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_dmx_pers_current, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(tree, hf_rdm_pd_dmx_pers_count, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_dmx_personality_description(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len)
{
	switch(cc) {
	case RDM_CC_GET_COMMAND:
		proto_tree_add_item(tree, hf_rdm_pd_dmx_pers_description, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		break;
		
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_dmx_pers_description, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(tree, hf_rdm_pd_dmx_pers_slots, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(tree, hf_rdm_pd_dmx_pers_text, tvb,
			offset, (len - 3), ENC_BIG_ENDIAN);
		offset += (len - 3);
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_slot_info(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len)
{
	switch(cc) {
	case RDM_CC_GET_COMMAND_RESPONSE:
		while (len >= 5) {
			proto_tree_add_item(tree, hf_rdm_pd_slot_offset, tvb,
				offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			len -= 2;
			proto_tree_add_item(tree, hf_rdm_pd_slot_type, tvb,
				offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			len -= 1;
			proto_tree_add_item(tree, hf_rdm_pd_slot_label_id, tvb,
				offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			len -= 2;
		}
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_slot_description(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len)
{
	switch(cc) {
	case RDM_CC_GET_COMMAND:
		proto_tree_add_item(tree, hf_rdm_pd_slot_nr, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		break;
		
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_slot_nr, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, hf_rdm_pd_slot_description, tvb,
			offset, (len - 2), ENC_BIG_ENDIAN);
		offset += (len - 2);
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_slot_value(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len)
{
	switch(cc) {
	case RDM_CC_GET_COMMAND_RESPONSE:
		while (len >= 3) {
			proto_tree_add_item(tree, hf_rdm_pd_slot_offset, tvb,
				offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			len -= 2;
			proto_tree_add_item(tree, hf_rdm_pd_slot_value, tvb,
				offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			len -= 1;
		}
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_record_sensors(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len)
{
	switch(cc) {
	case RDM_CC_GET_COMMAND:
		proto_tree_add_item(tree, hf_rdm_pd_sensor_nr, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;	
		break;
		
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_sensor_nr, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;	
		proto_tree_add_item(tree, hf_rdm_pd_sensor_type, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;	
		proto_tree_add_item(tree, hf_rdm_pd_sensor_unit, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;	
		proto_tree_add_item(tree, hf_rdm_pd_sensor_prefix, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;	
		proto_tree_add_item(tree, hf_rdm_pd_sensor_range_min_value, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;	
		proto_tree_add_item(tree, hf_rdm_pd_sensor_range_max_value, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;	
		proto_tree_add_item(tree, hf_rdm_pd_sensor_normal_min_value, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;	
		proto_tree_add_item(tree, hf_rdm_pd_sensor_normal_max_value, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;	
		proto_tree_add_item(tree, hf_rdm_pd_rec_value_support, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;	
		proto_tree_add_item(tree, hf_rdm_pd_sensor_description, tvb,
			offset, (len - 13), ENC_BIG_ENDIAN);
		offset += (len - 13);	
	
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_lamp_state(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_SET_COMMAND:
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_lamp_state, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_lamp_on_mode(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_SET_COMMAND:
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_lamp_on_mode, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_device_power_cycles(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_SET_COMMAND:
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_device_power_cycles, tvb,
			offset, 4, ENC_BIG_ENDIAN);
		offset +=4;
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_display_invert(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_SET_COMMAND:
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_display_invert, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_display_level(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_SET_COMMAND:
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_display_level, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_pan_invert(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_SET_COMMAND:
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_pan_invert, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_tilt_invert(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_SET_COMMAND:
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_tilt_invert, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_pan_tilt_swap(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_SET_COMMAND:
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_tilt_swap, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_real_time_clock(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_SET_COMMAND:
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_real_time_clock_year, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, hf_rdm_pd_real_time_clock_month, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(tree, hf_rdm_pd_real_time_clock_day, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(tree, hf_rdm_pd_real_time_clock_hour, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(tree, hf_rdm_pd_real_time_clock_minute, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(tree, hf_rdm_pd_real_time_clock_second, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_identify_device(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_SET_COMMAND:
		proto_tree_add_item(tree, hf_rdm_pd_identify_device, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		break;
		
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_identify_device_state, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_reset_device(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_SET_COMMAND:
		proto_tree_add_item(tree, hf_rdm_pd_reset_device, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;	
		break;
	}

	return offset;
}

static guint
dissect_rdm_pd_power_state(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_SET_COMMAND:
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_power_state, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;		
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_perform_selftest(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_SET_COMMAND:
		proto_tree_add_item(tree, hf_rdm_pd_selftest_nr, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;		
		break;
		
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_selftest_state, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;		
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_self_test_description(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len)
{
	switch(cc) {
	case RDM_CC_GET_COMMAND:
		proto_tree_add_item(tree, hf_rdm_pd_selftest_nr, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;		
		break;
		
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_selftest_nr, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;		
		proto_tree_add_item(tree, hf_rdm_pd_selftest_description, tvb,
			offset, (len - 1), ENC_BIG_ENDIAN);
		offset += (len - 1);		
		break;	
	}

	return offset;
}

static guint
dissect_rdm_pd_capture_preset(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_SET_COMMAND:
		proto_tree_add_item(tree, hf_rdm_pd_capture_preset_scene_nr, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, hf_rdm_pd_capture_preset_up_fade_time, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, hf_rdm_pd_capture_preset_down_fade_time, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, hf_rdm_pd_capture_preset_wait_time, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		
		break;
	}

	return offset;
}

static guint
dissect_rdm_pd_preset_playback(tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 cc, guint8 len _U_)
{
	switch(cc) {
	case RDM_CC_SET_COMMAND:
	case RDM_CC_GET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_pd_preset_playback_mode, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, hf_rdm_pd_preset_playback_level, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;	
		break;	
	}

	return offset;
}

static guint
dissect_rdm_mdb(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
	guint8 cc;
	guint16 param_id;
	guint8 parameter_data_length;
	proto_tree *hi,*si, *mdb_tree;

	cc = tvb_get_guint8(tvb, offset + 4);

	switch (cc) {
	case RDM_CC_DISCOVERY_COMMAND:
	case RDM_CC_GET_COMMAND:
	case RDM_CC_SET_COMMAND:
		proto_tree_add_item(tree, hf_rdm_port_id, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset++;
		break;

	case RDM_CC_DISCOVERY_COMMAND_RESPONSE:
	case RDM_CC_GET_COMMAND_RESPONSE:
	case RDM_CC_SET_COMMAND_RESPONSE:
		proto_tree_add_item(tree, hf_rdm_response_type, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset++;
		break;
	}

	proto_tree_add_item(tree, hf_rdm_message_count, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(tree, hf_rdm_sub_device, tvb,
			offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	hi = proto_tree_add_item(tree, hf_rdm_mdb, tvb,
			offset, -1, ENC_BIG_ENDIAN);
	mdb_tree = proto_item_add_subtree(hi,ett_rdm);


	proto_tree_add_item(mdb_tree, hf_rdm_command_class, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	offset++;

	param_id = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(mdb_tree, hf_rdm_parameter_id, tvb,
			offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	parameter_data_length = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(mdb_tree, hf_rdm_parameter_data_length, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_item_set_len( mdb_tree,  parameter_data_length + 4);

	if (parameter_data_length > 0) {
		hi = proto_tree_add_item(mdb_tree, hf_rdm_parameter_data, tvb,
				offset, parameter_data_length, ENC_BIG_ENDIAN);
		si = proto_item_add_subtree(hi,ett_rdm);

		switch(param_id) {
		case RDM_PARAM_ID_SENSOR_VALUE:
			offset = dissect_rdm_pd_sensor_value(tvb, offset, si, cc, parameter_data_length);
			break;

		case RDM_PARAM_ID_QUEUED_MESSAGE:
			offset = dissect_rdm_pd_queued_message(tvb, offset, si, cc, parameter_data_length);
			break;

		case RDM_PARAM_ID_DMX_START_ADDRESS:
			offset = dissect_rdm_pd_dmx_start_address(tvb, offset, si, cc, parameter_data_length);
			break;

		case RDM_PARAM_ID_DEVICE_INFO:
			offset = dissect_rdm_pd_device_info(tvb, offset, si, cc, parameter_data_length);
			break;

		case RDM_PARAM_ID_DEVICE_MODEL_DESCRIPTION:
			offset = dissect_rdm_pd_device_model_description(tvb, offset, si, cc, parameter_data_length);
			break;

		case RDM_PARAM_ID_DEVICE_LABEL:
			offset = dissect_rdm_pd_device_label(tvb, offset, si, cc, parameter_data_length);
			break;

		case RDM_PARAM_ID_DEVICE_HOURS:
			offset = dissect_rdm_pd_device_hours(tvb, offset, si, cc, parameter_data_length);
			break;

		case RDM_PARAM_ID_LAMP_HOURS:
			offset = dissect_rdm_pd_lamp_hours(tvb, offset, si, cc, parameter_data_length);
			break;

		case RDM_PARAM_ID_LAMP_STRIKES:
			offset = dissect_rdm_pd_lamp_strikes(tvb, offset, si, cc, parameter_data_length);
			break;

		case RDM_PARAM_ID_SENSOR_DEFINITION:
			offset = dissect_rdm_pd_sensor_definition(tvb, offset, si, cc, parameter_data_length);
			break;

		case RDM_PARAM_ID_MANUFACTURER_LABEL:
			offset = dissect_rdm_pd_manufacturer_label(tvb, offset, si, cc, parameter_data_length);
			break;

		case RDM_PARAM_ID_DISC_UNIQUE_BRANCH:
			offset = dissect_rdm_pd_disc_unique_branch(tvb, offset, si, cc, parameter_data_length);
			break;
		
		case RDM_PARAM_ID_DISC_MUTE:
			offset = dissect_rdm_pd_disc_mute(tvb, offset, si, cc, parameter_data_length);
			break;

		case RDM_PARAM_ID_DISC_UN_MUTE:
			offset = dissect_rdm_pd_disc_un_mute(tvb, offset, si, cc, parameter_data_length);
			break;

		case RDM_PARAM_ID_PROXIED_DEVICES:
			offset = dissect_rdm_pd_proxied_devices(tvb, offset, si, cc, parameter_data_length);
			break;

		case RDM_PARAM_ID_PROXIED_DEVICE_COUNT:
			offset = dissect_rdm_pd_proxied_device_count(tvb, offset, si, cc, parameter_data_length);
			break;
			
		case RDM_PARAM_ID_COMMS_STATUS:
			offset = dissect_rdm_pd_comms_status(tvb, offset, si, cc, parameter_data_length);
			break;

		case RDM_PARAM_ID_STATUS_MESSAGES:
			offset = dissect_rdm_pd_status_messages(tvb, offset, si, cc, parameter_data_length);
			break;

		case RDM_PARAM_ID_STATUS_ID_DESCRIPTION:
			offset = dissect_rdm_pd_status_id_description(tvb, offset, si, cc, parameter_data_length);
			break;

		case RDM_PARAM_ID_CLEAR_STATUS_ID:
			offset = dissect_rdm_pd_clear_status_id(tvb, offset, si, cc, parameter_data_length);
			break;

		case RDM_PARAM_ID_SUB_DEVICE_STATUS_REPORT_THRESHOLD:
			offset = dissect_rdm_pd_sub_device_status_report_threshold(tvb, offset, si, cc, parameter_data_length);
			break;

		case RDM_PARAM_ID_SUPPORTED_PARAMETERS:
			offset = dissect_rdm_pd_supported_parameters(tvb, offset, si, cc, parameter_data_length);
			break;

		case RDM_PARAM_ID_PARAMETER_DESCRIPTION:
			offset = dissect_rdm_pd_parameter_description(tvb, offset, si, cc, parameter_data_length);
			break;

		case RDM_PARAM_ID_PRODUCT_DETAIL_ID_LIST:
			offset = dissect_rdm_pd_product_detail_id_list(tvb, offset, si, cc, parameter_data_length);
			break;

		case RDM_PARAM_ID_FACTORY_DEFAULTS:
			offset = dissect_rdm_pd_factory_defaults(tvb, offset, si, cc, parameter_data_length);
			break;

		case RDM_PARAM_ID_LANGUAGE_CAPABILITIES:
			offset = dissect_rdm_pd_language_capabilities(tvb, offset, si, cc, parameter_data_length);
			break;

		case RDM_PARAM_ID_LANGUAGE:
			offset = dissect_rdm_pd_language(tvb, offset, si, cc, parameter_data_length);
			break;

		case RDM_PARAM_ID_SOFTWARE_VERSION_LABEL:
			offset = dissect_rdm_pd_software_version_label(tvb, offset, si, cc, parameter_data_length);
			break;
		
		case RDM_PARAM_ID_BOOT_SOFTWARE_VERSION_ID:
			offset = dissect_rdm_pd_boot_software_version_id(tvb, offset, si, cc, parameter_data_length);
			break;
				
		case RDM_PARAM_ID_BOOT_SOFTWARE_VERSION_LABEL:
			offset = dissect_rdm_pd_boot_software_version_label(tvb, offset, si, cc, parameter_data_length);
			break;
		
		case RDM_PARAM_ID_DMX_PERSONALITY:
			offset = dissect_rdm_pd_dmx_personality(tvb, offset, si, cc, parameter_data_length);
			break;
		
		case RDM_PARAM_ID_DMX_PERSONALITY_DESCRIPTION:
			offset = dissect_rdm_pd_dmx_personality_description(tvb, offset, si, cc, parameter_data_length);
			break;
		
		case RDM_PARAM_ID_SLOT_INFO:
			offset = dissect_rdm_pd_slot_info(tvb, offset, si, cc, parameter_data_length);
			break;
		
		case RDM_PARAM_ID_SLOT_DESCRIPTION:
			offset = dissect_rdm_pd_slot_description(tvb, offset, si, cc, parameter_data_length);
			break;
		
		case RDM_PARAM_ID_DEFAULT_SLOT_VALUE:
			offset = dissect_rdm_pd_slot_value(tvb, offset, si, cc, parameter_data_length);
			break;
		
		case RDM_PARAM_ID_RECORD_SENSORS:
			offset = dissect_rdm_pd_record_sensors(tvb, offset, si, cc, parameter_data_length);
			break;
		
		case RDM_PARAM_ID_LAMP_STATE:
			offset = dissect_rdm_pd_lamp_state(tvb, offset, si, cc, parameter_data_length);
			break;

		case RDM_PARAM_ID_LAMP_ON_MODE:
			offset = dissect_rdm_pd_lamp_on_mode(tvb, offset, si, cc, parameter_data_length);
			break;
	
		case RDM_PARAM_ID_DEVICE_POWER_CYCLES:
			offset = dissect_rdm_pd_device_power_cycles(tvb, offset, si, cc, parameter_data_length);
			break;
		
		case RDM_PARAM_ID_DISPLAY_INVERT:
			offset = dissect_rdm_pd_display_invert(tvb, offset, si, cc, parameter_data_length);
			break;
		
		case RDM_PARAM_ID_DISPLAY_LEVEL:
			offset = dissect_rdm_pd_display_level(tvb, offset, si, cc, parameter_data_length);
			break;
		
		case RDM_PARAM_ID_PAN_INVERT:
			offset = dissect_rdm_pd_pan_invert(tvb, offset, si, cc, parameter_data_length);
			break;
		
		case RDM_PARAM_ID_TILT_INVERT:
			offset = dissect_rdm_pd_tilt_invert(tvb, offset, si, cc, parameter_data_length);
			break;
		
		case RDM_PARAM_ID_PAN_TILT_SWAP:
			offset = dissect_rdm_pd_pan_tilt_swap(tvb, offset, si, cc, parameter_data_length);
			break;
		
		case RDM_PARAM_ID_REAL_TIME_CLOCK:
			offset = dissect_rdm_pd_real_time_clock(tvb, offset, si, cc, parameter_data_length);
			break;
		
		case RDM_PARAM_ID_IDENTIFY_DEVICE:
			offset = dissect_rdm_pd_identify_device(tvb, offset, si, cc, parameter_data_length);
			break;
		
		case RDM_PARAM_ID_RESET_DEVICE:
			offset = dissect_rdm_pd_reset_device(tvb, offset, si, cc, parameter_data_length);
			break;
		
		case RDM_PARAM_ID_POWER_STATE:
			offset = dissect_rdm_pd_power_state(tvb, offset, si, cc, parameter_data_length);
			break;
		
		case RDM_PARAM_ID_PERFORM_SELFTEST:
			offset = dissect_rdm_pd_perform_selftest(tvb, offset, si, cc, parameter_data_length);
			break;
		
		case RDM_PARAM_ID_SELF_TEST_DESCRIPTION:
			offset = dissect_rdm_pd_self_test_description(tvb, offset, si, cc, parameter_data_length);
			break;
		
		case RDM_PARAM_ID_CAPTURE_PRESET:
			offset = dissect_rdm_pd_capture_preset(tvb, offset, si, cc, parameter_data_length);
			break;
		
		case RDM_PARAM_ID_PRESET_PLAYBACK:
			offset = dissect_rdm_pd_preset_playback(tvb, offset, si, cc, parameter_data_length);
			break;
		
		default:
			proto_tree_add_item(si, hf_rdm_parameter_data_raw, tvb,
				offset, parameter_data_length, ENC_NA);
			offset += parameter_data_length;
			break;
		}
	}
	
	return offset;
}

static void
dissect_rdm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RDM");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree != NULL) {
		gint padding_size;
		guint16 man_id;
		guint32 dev_id;
		unsigned message_length, checksum, checksum_shouldbe, offset = 0;
		proto_item *item;
		proto_tree *checksum_tree;

		proto_tree *ti = proto_tree_add_item(tree, proto_rdm, tvb,
				offset, -1, ENC_NA);
		proto_tree *rdm_tree = proto_item_add_subtree(ti, ett_rdm);

		proto_tree_add_item(rdm_tree, hf_rdm_sub_start_code, tvb,
				offset, 1, ENC_BIG_ENDIAN);
		offset++;

		message_length = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(rdm_tree, hf_rdm_message_length, tvb,
				offset, 1, ENC_BIG_ENDIAN);
		offset++;

		man_id = tvb_get_ntohs(tvb, offset);
		dev_id = tvb_get_ntohl(tvb, offset + 2);
		proto_item_append_text(ti, ", Dst UID: %04x:%08x", man_id, dev_id);
		proto_tree_add_item(rdm_tree, hf_rdm_dest_uid, tvb,
				offset, 6, ENC_NA);
		offset += 6;


		man_id = tvb_get_ntohs(tvb, offset);
		dev_id = tvb_get_ntohl(tvb, offset + 2);
		proto_item_append_text(ti, ", Src UID: %04x:%08x", man_id, dev_id);
		proto_tree_add_item(rdm_tree, hf_rdm_src_uid, tvb,
				offset, 6, ENC_NA);
		offset += 6;

		proto_tree_add_item(rdm_tree, hf_rdm_transaction_number, tvb,
				offset, 1, ENC_BIG_ENDIAN);
		offset++;

		offset = dissect_rdm_mdb(tvb, offset, rdm_tree);

		padding_size = offset - (message_length - 1);
		if (padding_size > 0) {
			proto_tree_add_item(rdm_tree, hf_rdm_intron, tvb,
					offset, padding_size, ENC_NA);
			offset += padding_size;
		}

		checksum_shouldbe = rdm_checksum(tvb, offset);
		checksum = tvb_get_ntohs(tvb, offset);
		item = proto_tree_add_item(rdm_tree, hf_rdm_checksum, tvb,
				offset, 2, ENC_BIG_ENDIAN);
		if (checksum == checksum_shouldbe) {
			proto_item_append_text(item, " [correct]");

			checksum_tree = proto_item_add_subtree(item, ett_rdm);
			item = proto_tree_add_boolean(checksum_tree, hf_rdm_checksum_good, tvb,
						offset, 2, TRUE);
			PROTO_ITEM_SET_GENERATED(item);
			item = proto_tree_add_boolean(checksum_tree, hf_rdm_checksum_bad, tvb,
						offset, 2, FALSE);
			PROTO_ITEM_SET_GENERATED(item);
		} else {
			proto_item_append_text(item, " [incorrect, should be 0x%04x]", checksum_shouldbe);

			checksum_tree = proto_item_add_subtree(item, ett_rdm);
			item = proto_tree_add_boolean(checksum_tree, hf_rdm_checksum_good, tvb,
						offset, 2, FALSE);
			PROTO_ITEM_SET_GENERATED(item);
			item = proto_tree_add_boolean(checksum_tree, hf_rdm_checksum_bad, tvb,
						offset, 2, TRUE);
			PROTO_ITEM_SET_GENERATED(item);
		}

		offset += 2;

		if (offset < tvb_length(tvb))
			proto_tree_add_item(rdm_tree, hf_rdm_trailer, tvb,
					offset, -1, ENC_NA);
	}
}

void
proto_register_rdm(void)
{
	static hf_register_info hf[] = {
		{ &hf_rdm_sub_start_code,
			{ "Sub-start code", "rdm.ssc",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_message_length,
			{ "Message length", "rdm.len",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_dest_uid,
			{ "Destination UID", "rdm.dst",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_src_uid,
			{ "Source UID", "rdm.src",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_transaction_number,
			{ "Transaction number", "rdm.tn",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_port_id,
			{ "Port ID", "rdm.port_id",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_response_type,
			{ "Response type", "rdm.rt",
				FT_UINT8, BASE_HEX, VALS(rdm_rt_vals), 0x0,
				NULL, HFILL }},

		{ &hf_rdm_message_count,
			{ "Message count", "rdm.mc",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_sub_device,
			{ "Sub-device", "rdm.sd",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_mdb,
			{ "Message Data Block", "rdm.mdb",
				FT_NONE, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_command_class,
			{ "Command class", "rdm.cc",
				FT_UINT8, BASE_HEX, VALS(rdm_cc_vals), 0x0,
				NULL, HFILL }},

		{ &hf_rdm_parameter_id,
			{ "Parameter ID", "rdm.pid",
				FT_UINT16, BASE_HEX, VALS(rdm_param_id_vals), 0x0,
				NULL, HFILL }},

		{ &hf_rdm_parameter_data_length,
			{ "Parameter data length", "rdm.pdl",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_parameter_data,
			{ "Parameter data", "rdm.pd",
				FT_NONE, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_parameter_data_raw,
			{ "Raw Data", "rdm.pd.raw",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_intron,
			{ "Intron", "rdm.intron",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_checksum,
			{ "Checksum", "rdm.checksum",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_checksum_good,
			{ "Good Checksum", "rdm.checksum_good", 
				FT_BOOLEAN, BASE_NONE, NULL, 0x0,
				"True: checksum matches packet content; False: doesn't match content", HFILL }},

		{ &hf_rdm_checksum_bad,
			{ "Bad Checksum", "rdm.checksum_bad", 
				FT_BOOLEAN, BASE_NONE, NULL, 0x0,
				"True: checksum doesn't match packet content; False: matches content", HFILL }},

		{ &hf_rdm_trailer,
			{ "Trailer", "rdm.trailer",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_queued_message_status,
			{ "Status", "rdm.pd.queued_message.status",
				FT_UINT8, BASE_HEX, VALS(rdm_status_vals), 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_sensor_nr,
			{ "Sensor Nr.", "rdm.pd.sensor.nr",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_sensor_value_pres,
			{ "Sensor Present Value", "rdm.pd.sensor.value.present",
				FT_INT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_sensor_value_low,
			{ "Sensor Lowest Value", "rdm.pd.sensor.value.lowest",
				FT_INT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_sensor_value_high,
			{ "Sensor Highest Value", "rdm.pd.sensor.value.highest",
				FT_INT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_sensor_value_rec,
			{ "Sensor Recorded Value", "rdm.pd.sensor.value.recorded",
				FT_INT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_sensor_range_min_value,
			{ "Sensor Range Min. Value", "rdm.pd.sensor.range.min_value",
				FT_INT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_sensor_range_max_value,
			{ "Sensor Range Max. Value", "rdm.pd.sensor.range.max_value",
				FT_INT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_sensor_normal_min_value,
			{ "Sensor Normal Min. Value", "rdm.pd.sensor.normal.min_value",
				FT_INT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_sensor_normal_max_value,
			{ "Sensor Normal Max. Value", "rdm.pd.sensor.normal.max_value",
				FT_INT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_sensor_recorded_value_support,
			{ "Sensor Recorded Value Support", "rdm.pd.sensor.recorded_value_support",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_sensor_type,
			{ "Sensor Type", "rdm.pd.sensor_type",
				FT_UINT8, BASE_HEX, VALS(rdm_sensor_type_vals), 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_sensor_unit,
			{ "Sensor Unit", "rdm.pd.sensor_unit",
				FT_UINT8, BASE_HEX, VALS(rdm_unit_vals), 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_sensor_prefix,
			{ "Sensor Prefix", "rdm.pd.sensor_prefix",
				FT_UINT8, BASE_HEX, VALS(rdm_prefix_vals), 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_sensor_description,
			{ "Sensor Description", "rdm.pd.sensor.description",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_manu_label,
			{ "Manufacturur Label", "rdm.pd.manu_label",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},


		{ &hf_rdm_pd_device_label,
			{ "Device Label", "rdm.pd.device_label",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_dmx_start_address,
			{ "DMX Start Address", "rdm.pd.dmx_start_address",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_device_hours,
			{ "Device Hours", "rdm.pd.device_hours",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_lamp_hours,
			{ "Lamp Hours", "rdm.pd.lamp_hours",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_lamp_strikes,
			{ "Lamp Strikes", "rdm.pd.lamp_strikes",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_proto_vers,
			{ "RDM Protocol Version", "rdm.pd.proto_vers",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_device_model_id,
			{ "Device Model ID", "rdm.pd.device_model_id",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_product_cat,
			{ "Product Category", "rdm.pd.product_cat",
				FT_UINT16, BASE_HEX, VALS(rdm_product_cat_vals), 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_software_vers_id,
			{ "Software Version ID", "rdm.pd.software_version_id",
				FT_UINT32, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_dmx_footprint,
			{ "DMX Footprint", "rdm.pd.dmx_footprint",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_dmx_pers_current,
			{ "Current DMX Personallity", "rdm.pd.dmx_pers_current",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_dmx_pers_total,
			{ "Total nr. DMX Personallities", "rdm.pd.dmx_pers_total",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_sub_device_count,
			{ "Sub-Device Count", "rdm.pd.sub_device_count",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_sensor_count,
			{ "Sensor Count", "rdm.pd.sensor_count",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_device_model_description,
			{ "Device Model Description", "rdm.pd.device_model_description",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_disc_unique_branch_lb_uid,
			{ "Lower Bound UID", "rdm.pd.disc_unique_branch.lb_uid",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_disc_unique_branch_ub_uid,
			{ "Upper Bound UID", "rdm.pd.disc_unique_branch.ub_uid",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_disc_mute_control_field,
			{ "Control Field", "rdm.pd.disc_mute.control_field",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_disc_mute_binding_uid,
			{ "Binding UID", "rdm.pd.disc_mute.binding_uid",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_disc_unmute_control_field,
			{ "Control Field", "rdm.pd.disc_unmute.control_field",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_disc_unmute_binding_uid,
			{ "Binding UID", "rdm.pd.disc_unmute.binding_uid",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_proxied_devices_uid,
			{ "UID", "rdm.pd.proxied_devices.uid",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_proxied_device_count,
			{ "Device Count", "rdm.pd.device_count",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_proxied_device_list_change,
			{ "List Change", "rdm.pd.list_change",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_real_time_clock_year,
			{ "Year", "rdm.pd.real_time_clock.year",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_real_time_clock_month,
			{ "Month", "rdm.pd.real_time_clock.month",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_real_time_clock_day,
			{ "Day", "rdm.pd.real_time_clock.day",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_real_time_clock_hour,
			{ "Hour", "rdm.pd.real_time_clock.hour",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_real_time_clock_minute,
			{ "Minute", "rdm.pd.real_time_clock.minute",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_real_time_clock_second,
			{ "Second", "rdm.pd.real_time_clock.second",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_lamp_state,
			{ "Lamp State", "rdm.pd.lamp_state",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_lamp_on_mode,
			{ "Lamp On Mode", "rdm.pd.lamp_on_mode",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_device_power_cycles,
			{ "Device Power Cycles", "rdm.pd.device_power_cycles",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_display_invert,
			{ "Display Invert", "rdm.pd.display_invert",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_display_level,
			{ "Display Level", "rdm.pd.display_level",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_pan_invert,
			{ "Pan Invert", "rdm.pd.pan_invert",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_tilt_invert,
			{ "Tilt Invert", "rdm.pd.tilt_invert",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_tilt_swap,
			{ "Tilt Swap", "rdm.pd.tilt_swap",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_selftest_nr,
			{ "Selftest Nr.", "rdm.pd.selftest.nr",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_selftest_state,
			{ "Selftest State", "rdm.pd.selftest.state",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_selftest_description,
			{ "Selftest Description", "rdm.pd.selftest.description",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_language_code,
			{ "Language Code", "rdm.pd.language_code",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_identify_device,
			{ "Identify Device", "rdm.pd.identify_device",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_identify_device_state,
			{ "Identify Device State", "rdm.pd.identify_device.state",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_reset_device,
			{ "Reset Device", "rdm.pd.reset_device",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_power_state,
			{ "Power State", "rdm.pd.power_state",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_capture_preset_scene_nr,
			{ "Scene Nr.", "rdm.pd.capture_preset.scene_nr",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_capture_preset_up_fade_time,
			{ "Up Fade Time", "rdm.pd.capture_preset.up_fade_time",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_capture_preset_down_fade_time,
			{ "Down Fade Time", "rdm.pd.capture_preset.down_fade_time",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_capture_preset_wait_time,
			{ "Wait Time", "rdm.pd.capture_preset.wait_time",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_preset_playback_mode,
			{ "Mode", "rdm.pd.preset_playback.mode",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_preset_playback_level,
			{ "Level", "rdm.pd.preset_playback.level",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_parameter_id,
			{ "ID", "rdm.pd.parameter.id",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_parameter_pdl_size,
			{ "PDL Size", "rdm.pd.parameter.pdl_size",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_parameter_data_type,
			{ "Data Type", "rdm.pd.parameter.data_type",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_parameter_cmd_class,
			{ "Command Class", "rdm.pd.parameter.cmd_class",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_parameter_type,
			{ "Type", "rdm.pd.parameter.type",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_parameter_unit,
			{ "Unit", "rdm.pd.parameter.unit",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_parameter_prefix,
			{ "Prefix", "rdm.pd.parameter.prefix",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_parameter_min_value,
			{ "Min. Value", "rdm.pd.parameter.min_value",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_parameter_max_value,
			{ "Max. Value", "rdm.pd.parameter.max_value",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_parameter_default_value,
			{ "Delauft Value", "rdm.pd.parameter.default_value",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_parameter_description,
			{ "Description", "rdm.pd.parameter.description",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_software_version_label,
			{ "Version Label", "rdm.pd.software_version.label",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_boot_software_version_id,
			{ "Version ID", "rdm.pd.boot_software_version.id",
				FT_UINT32, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_boot_software_version_label,
			{ "Version Label", "rdm.pd.boot_software_version.label",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_comms_status_short_msg,
			{ "Short Msg", "rdm.pd.comms_status.short_msg",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_comms_status_len_mismatch,
			{ "Len Mismatch", "rdm.pd.comms_status.len_mismatch",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_comms_status_csum_fail,
			{ "Checksum Fail", "rdm.pd.comms_status.csum_fail",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_status_messages_type,
			{ "Type", "rdm.pd.status_messages.type",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_status_messages_sub_device_id,
			{ "Sub. Device ID", "rdm.pd.status_messages.sub_devices_id",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_status_messages_id,
			{ "ID", "rdm.pd.status_messages.id",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_status_messages_data_value_1,
			{ "Data Value 1", "rdm.pd.status_messages.data_value_1",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_status_messages_data_value_2,
			{ "Data Value 2", "rdm.pd.status_messages.data_value_2",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_status_id,
			{ "ID", "rdm.pd.status_id",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_status_id_description,
			{ "Description", "rdm.pd.status_id.description",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_sub_device_status_report_threshold_status_type,
			{ "Status Type", "rdm.pd.sub_device_status_report_threshold.status_type",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_product_detail_id_list,
			{ "Sensor Count", "rdm.pd.product_detail_id_list",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_factory_defaults,
			{ "Factory Defaults", "rdm.pd.factory_defaults",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_dmx_pers_nr,
			{ "DMX Pers. Nr.", "rdm.pd.dmx_pers.nr",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_dmx_pers_count,
			{ "DMX Pers. Count", "rdm.pd.dmx_pers.count",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_dmx_pers_description,
			{ "DMX Pers. Description", "rdm.pd.dmx_pers.description",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_dmx_pers_slots,
			{ "DMX Pers. Slots", "rdm.pd.dmx_pers.slots",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_dmx_pers_text,
			{ "DMX Pers. Text", "rdm.pd.dmx_pers.text",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_slot_offset,
			{ "Slot Offset", "rdm.pd.slot_offset",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_slot_type,
			{ "Slot Type", "rdm.pd.slot_type",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_slot_label_id,
			{ "Slot Label ID", "rdm.pd.slot_label_id",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_slot_nr,
			{ "Slot Nr.", "rdm.pd.slot_nr",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_slot_description,
			{ "Slot Description", "rdm.pd.slot_description",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_slot_value,
			{ "Slot Value", "rdm.pd.slot_value",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_pd_rec_value_support,
			{ "Rec. Value Support", "rdm.pd.rec_value_support",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_rdm
	};

	proto_rdm = proto_register_protocol("Remote Device Management",
			"RDM", "rdm");
	proto_register_field_array(proto_rdm, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("rdm", dissect_rdm, proto_rdm);
}

void
proto_reg_handoff_rdm(void)
{
}
