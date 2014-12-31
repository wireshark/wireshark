/* packet-bluetooth.c
 * Routines for the Bluetooth
 *
 * Copyright 2014, Michal Labedzki for Tieto Corporation
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

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation_table.h>
#include <wiretap/wtap.h>

#include "packet-bluetooth.h"

int proto_bluetooth = -1;
static int proto_ubertooth = -1;

static int hf_bluetooth_src = -1;
static int hf_bluetooth_dst = -1;
static int hf_bluetooth_addr = -1;
static int hf_bluetooth_str_src = -1;
static int hf_bluetooth_str_dst = -1;
static int hf_bluetooth_str_addr = -1;

static gint ett_bluetooth = -1;

static dissector_handle_t bluetooth_handle;
static dissector_handle_t btle_handle;
static dissector_handle_t data_handle;

static dissector_table_t bluetooth_table;

static wmem_tree_t *chandle_sessions        = NULL;
static wmem_tree_t *chandle_to_bdaddr       = NULL;
static wmem_tree_t *chandle_to_mode         = NULL;
static wmem_tree_t *bdaddr_to_name          = NULL;
static wmem_tree_t *bdaddr_to_role          = NULL;
static wmem_tree_t *localhost_name          = NULL;
static wmem_tree_t *localhost_bdaddr        = NULL;

static int bluetooth_tap = -1;

static const value_string bluetooth_uuid_vals[] = {
    /* Protocol Identifiers - https://www.bluetooth.org/en-us/specification/assigned-numbers/service-discovery */
    { 0x0001,   "SDP" },
    { 0x0002,   "UDP" },
    { 0x0003,   "RFCOMM" },
    { 0x0004,   "TCP" },
    { 0x0005,   "TCS-BIN" },
    { 0x0006,   "TCS-AT" },
    { 0x0007,   "ATT" },
    { 0x0008,   "OBEX" },
    { 0x0009,   "IP" },
    { 0x000A,   "FTP" },
    { 0x000C,   "HTTP" },
    { 0x000E,   "WSP" },
    { 0x000F,   "BNEP" },
    { 0x0010,   "UPNP" },
    { 0x0011,   "HIDP" },
    { 0x0012,   "Hardcopy Control Channel" },
    { 0x0014,   "Hardcopy Data Channel" },
    { 0x0016,   "Hardcopy Notification" },
    { 0x0017,   "AVCTP" },
    { 0x0019,   "AVDTP" },
    { 0x001B,   "CMPT" },
    { 0x001D,   "UDI C-Plane" }, /* unofficial */
    { 0x001E,   "MCAP Control Channel" },
    { 0x001F,   "MCAP Data Channel" },
    { 0x0100,   "L2CAP" },
    /* Traditional Services - https://www.bluetooth.org/en-us/specification/assigned-numbers/service-discovery */
    { 0x1000,   "Service Discovery Server Service Class ID" },
    { 0x1001,   "Browse Group Descriptor Service Class ID" },
    { 0x1002,   "Public Browse Group" },
    { 0x1101,   "Serial Port" },
    { 0x1102,   "LAN Access Using PPP" },
    { 0x1103,   "Dialup Networking" },
    { 0x1104,   "IrMC Sync" },
    { 0x1105,   "OBEX Object Push" },
    { 0x1106,   "OBEX File Transfer" },
    { 0x1107,   "IrMC Sync Command" },
    { 0x1108,   "Headset" },
    { 0x1109,   "Cordless Telephony" },
    { 0x110A,   "Audio Source" },
    { 0x110B,   "Audio Sink" },
    { 0x110C,   "A/V Remote Control Target" },
    { 0x110D,   "Advanced Audio Distribution" },
    { 0x110E,   "A/V Remote Control" },
    { 0x110F,   "A/V Remote Control Controller" },
    { 0x1110,   "Intercom" },
    { 0x1111,   "Fax" },
    { 0x1112,   "Headset Audio Gateway" },
    { 0x1113,   "WAP" },
    { 0x1114,   "WAP Client" },
    { 0x1115,   "PANU" },
    { 0x1116,   "NAP" },
    { 0x1117,   "GN" },
    { 0x1118,   "Direct Printing" },
    { 0x1119,   "Reference Printing" },
    { 0x111A,   "Imaging" },
    { 0x111B,   "Imaging Responder" },
    { 0x111C,   "Imaging Automatic Archive" },
    { 0x111D,   "Imaging Referenced Objects" },
    { 0x111E,   "Handsfree" },
    { 0x111F,   "Handsfree Audio Gateway" },
    { 0x1120,   "Direct Printing Reference Objects Service" },
    { 0x1121,   "Reflected UI" },
    { 0x1122,   "Basic Printing" },
    { 0x1123,   "Printing Status" },
    { 0x1124,   "Human Interface Device Service" },
    { 0x1125,   "Hardcopy Cable Replacement" },
    { 0x1126,   "HCR Print" },
    { 0x1127,   "HCR Scan" },
    { 0x1128,   "Common ISDN Access" },
    { 0x1129,   "Video Conferencing GW" },
    { 0x112A,   "UDI MT" },
    { 0x112B,   "UDI TA" },
    { 0x112C,   "Audio/Video" },
    { 0x112D,   "SIM Access" },
    { 0x112E,   "Phonebook Access Client" },
    { 0x112F,   "Phonebook Access Server" },
    { 0x1130,   "Phonebook Access Profile" },
    { 0x1131,   "Headset HS" },
    { 0x1132,   "Message Access Server" },
    { 0x1133,   "Message Notification Server" },
    { 0x1134,   "Message Access Profile" },
    { 0x1135,   "Global Navigation Satellite System" },
    { 0x1136,   "Global Navigation Satellite System Server" },
    { 0x1137,   "3D Display" },
    { 0x1138,   "3D Glasses" },
    { 0x1139,   "3D Synchronization Profile" },
    { 0x113A,   "Multi-Profile" },
    { 0x113B,   "Multi-Profile SC" },
    { 0x1200,   "PnP Information" },
    { 0x1201,   "Generic Networking" },
    { 0x1202,   "Generic File Transfer" },
    { 0x1203,   "Generic Audio" },
    { 0x1204,   "Generic Telephony" },
    { 0x1205,   "UPNP Service" },
    { 0x1206,   "UPNP IP Service" },
    { 0x1300,   "ESDP UPNP_IP PAN" },
    { 0x1301,   "ESDP UPNP IP LAP" },
    { 0x1302,   "ESDP UPNP L2CAP" },
    { 0x1303,   "Video Source" },
    { 0x1304,   "Video Sink" },
    { 0x1305,   "Video Distribution" },
    { 0x1400,   "Health Device Profile" },
    { 0x1401,   "Health Device Source" },
    { 0x1402,   "Health Device Sink" },
    /* LE Services -  https://developer.bluetooth.org/gatt/services/Pages/ServicesHome.aspx */
    { 0x1800,   "Generic Access Profile" },
    { 0x1801,   "Generic Attribute Profile" },
    { 0x1802,   "Immediate Alert" },
    { 0x1803,   "Link Loss" },
    { 0x1804,   "Tx Power" },
    { 0x1805,   "Current Time Service" },
    { 0x1806,   "Reference Time Update Service" },
    { 0x1807,   "Next DST Change Service" },
    { 0x1808,   "Glucose" },
    { 0x1809,   "Health Thermometer" },
    { 0x180A,   "Device Information" },
    { 0x180D,   "Heart Rate" },
    { 0x180E,   "Phone Alert Status Service" },
    { 0x180F,   "Battery Service" },
    { 0x1810,   "Blood Pressure" },
    { 0x1811,   "Alert Notification Service" },
    { 0x1812,   "Human Interface Device" },
    { 0x1813,   "Scan Parameters" },
    { 0x1814,   "Running Speed and Cadence" },
    { 0x1816,   "Cycling Speed and Cadence" },
    { 0x1818,   "Cycling Power" },
    { 0x1819,   "Location and Navigation" },
    /* Units - http://developer.bluetooth.org/gatt/declarations/Pages/DeclarationsHome.aspx */
    { 0x2700,   "unitless" },
    { 0x2701,   "length (metre)" },
    { 0x2702,   "mass (kilogram)" },
    { 0x2703,   "time (second)" },
    { 0x2704,   "electric current (ampere)" },
    { 0x2705,   "thermodynamic temperature (kelvin)" },
    { 0x2706,   "amount of substance (mole)" },
    { 0x2707,   "luminous intensity (candela)" },
    { 0x2710,   "area (square metres)" },
    { 0x2711,   "volume (cubic metres)" },
    { 0x2712,   "velocity (metres per second)" },
    { 0x2713,   "acceleration (metres per second squared)" },
    { 0x2714,   "wavenumber (reciprocal metre)" },
    { 0x2715,   "density (kilogram per cubic metre)" },
    { 0x2716,   "surface density (kilogram per square metre)" },
    { 0x2717,   "specific volume (cubic metre per kilogram)" },
    { 0x2718,   "current density (ampere per square metre)" },
    { 0x2719,   "magnetic field strength (ampere per metre)" },
    { 0x271A,   "amount concentration (mole per cubic metre)" },
    { 0x271B,   "mass concentration (kilogram per cubic metre)" },
    { 0x271C,   "luminance (candela per square metre)" },
    { 0x271D,   "refractive index" },
    { 0x271E,   "relative permeability" },
    { 0x2720,   "plane angle (radian)" },
    { 0x2721,   "solid angle (steradian)" },
    { 0x2722,   "frequency (hertz)" },
    { 0x2723,   "force (newton)" },
    { 0x2724,   "pressure (pascal)" },
    { 0x2725,   "energy (joule)" },
    { 0x2726,   "power (watt)" },
    { 0x2727,   "electric charge (coulomb)" },
    { 0x2728,   "electric potential difference (volt)" },
    { 0x2729,   "capacitance (farad)" },
    { 0x272A,   "electric resistance (ohm)" },
    { 0x272B,   "electric conductance (siemens)" },
    { 0x272C,   "magnetic flex (weber)" },
    { 0x272D,   "magnetic flex density (tesla)" },
    { 0x272E,   "inductance (henry)" },
    { 0x272F,   "Celsius temperature (degree Celsius)" },
    { 0x2730,   "luminous flux (lumen)" },
    { 0x2731,   "illuminance (lux)" },
    { 0x2732,   "activity referred to a radionuclide (becquerel)" },
    { 0x2733,   "absorbed dose (gray)" },
    { 0x2734,   "dose equivalent (sievert)" },
    { 0x2735,   "catalytic activity (katal)" },
    { 0x2740,   "dynamic viscosity (pascal second)" },
    { 0x2741,   "moment of force (newton metre)" },
    { 0x2742,   "surface tension (newton per metre)" },
    { 0x2743,   "angular velocity (radian per second)" },
    { 0x2744,   "angular acceleration (radian per second squared)" },
    { 0x2745,   "heat flux density (watt per square metre)" },
    { 0x2746,   "heat capacity (joule per kelvin)" },
    { 0x2747,   "specific heat capacity (joule per kilogram kelvin)" },
    { 0x2748,   "specific energy (joule per kilogram)" },
    { 0x2749,   "thermal conductivity (watt per metre kelvin)" },
    { 0x274A,   "energy density (joule per cubic metre)" },
    { 0x274B,   "electric field strength (volt per metre)" },
    { 0x274C,   "electric charge density (coulomb per cubic metre)" },
    { 0x274D,   "surface charge density (coulomb per square metre)" },
    { 0x274E,   "electric flux density (coulomb per square metre)" },
    { 0x274F,   "permittivity (farad per metre)" },
    { 0x2750,   "permeability (henry per metre)" },
    { 0x2751,   "molar energy (joule per mole)" },
    { 0x2752,   "molar entropy (joule per mole kelvin)" },
    { 0x2753,   "exposure (coulomb per kilogram)" },
    { 0x2754,   "absorbed dose rate (gray per second)" },
    { 0x2755,   "radiant intensity (watt per steradian)" },
    { 0x2756,   "radiance (watt per square metre steradian)" },
    { 0x2757,   "catalytic activity concentration (katal per cubic metre)" },
    { 0x2760,   "time (minute)" },
    { 0x2761,   "time (hour)" },
    { 0x2762,   "time (day)" },
    { 0x2763,   "plane angle (degree)" },
    { 0x2764,   "plane angle (minute)" },
    { 0x2765,   "plane angle (second)" },
    { 0x2766,   "area (hectare)" },
    { 0x2767,   "volume (litre)" },
    { 0x2768,   "mass (tonne)" },
    { 0x2780,   "pressure (bar)" },
    { 0x2781,   "pressure (millimetre of mercury)" },
    { 0x2782,   "length (angstrom)" },
    { 0x2783,   "length (nautical mile)" },
    { 0x2784,   "area (barn)" },
    { 0x2785,   "velocity (knot)" },
    { 0x2786,   "logarithmic radio quantity (neper)" },
    { 0x2787,   "logarithmic radio quantity (bel)" },
    { 0x27A0,   "length (yard)" },
    { 0x27A1,   "length (parsec)" },
    { 0x27A2,   "length (inch)" },
    { 0x27A3,   "length (foot)" },
    { 0x27A4,   "length (mile)" },
    { 0x27A5,   "pressure (pound-force per square inch)" },
    { 0x27A6,   "velocity (kilometre per hour)" },
    { 0x27A7,   "velocity (mile per hour)" },
    { 0x27A8,   "angular velocity (revolution per minute)" },
    { 0x27A9,   "energy (gram calorie)" },
    { 0x27AA,   "energy (kilogram calorie)" },
    { 0x27AB,   "energy (kilowatt hour)" },
    { 0x27AC,   "thermodynamic temperature (degree Fahrenheit)" },
    { 0x27AD,   "percentage" },
    { 0x27AE,   "per mille" },
    { 0x27AF,   "period (beats per minute)" },
    { 0x27B0,   "electric charge (ampere hours)" },
    { 0x27B1,   "mass density (milligram per decilitre)" },
    { 0x27B2,   "mass density (millimole per litre)" },
    { 0x27B3,   "time (year)" },
    { 0x27B4,   "time (month)" },
    { 0x27B5,   "concentration (count per cubic metre)" },
    { 0x27B6,   "irradiance (watt per square metre)" },
    { 0x27B7,   "milliliter (per kilogram per minute)" },
    { 0x27B8,   "mass (pound)" },
    /* Declarations - http://developer.bluetooth.org/gatt/declarations/Pages/DeclarationsHome.aspx */
    { 0x2800,   "GATT Primary Service Declaration" },
    { 0x2801,   "GATT Secondary Service Declaration" },
    { 0x2802,   "GATT Include Declaration" },
    { 0x2803,   "GATT Characteristic Declaration" },
    /* Descriptors - http://developer.bluetooth.org/gatt/descriptors/Pages/DescriptorsHomePage.aspx */
    { 0x2900,   "Characteristic Extended Properties" },
    { 0x2901,   "Characteristic User Description" },
    { 0x2902,   "Client Characteristic Configuration" },
    { 0x2903,   "Server Characteristic Configuration" },
    { 0x2904,   "Characteristic Presentation Format" },
    { 0x2905,   "Characteristic Aggregate Format" },
    { 0x2906,   "Valid Range" },
    { 0x2907,   "External Report Reference" },
    { 0x2908,   "Report Reference" },
    /* Characteristics - http://developer.bluetooth.org/gatt/characteristics/Pages/CharacteristicsHome.aspx */
    { 0x2A00,   "Device Name" },
    { 0x2A01,   "Appearance" },
    { 0x2A02,   "Peripheral Privacy Flag" },
    { 0x2A03,   "Reconnection Address" },
    { 0x2A04,   "Peripheral Preferred Connection Parameters" },
    { 0x2A05,   "Service Changed" },
    { 0x2A06,   "Alert Level" },
    { 0x2A07,   "Tx Power Level" },
    { 0x2A08,   "Date Time" },
    { 0x2A09,   "Day of Week" },
    { 0x2A0A,   "Day Date Time" },
    { 0x2A0C,   "Exact Time 256" },
    { 0x2A0D,   "DST Offset" },
    { 0x2A0E,   "Time Zone" },
    { 0x2A0F,   "Local Time Information" },
    { 0x2A11,   "Time with DST" },
    { 0x2A12,   "Time Accuracy" },
    { 0x2A13,   "Time Source" },
    { 0x2A14,   "Reference Time Information" },
    { 0x2A16,   "Time Update Control Point" },
    { 0x2A17,   "Time Update State" },
    { 0x2A18,   "Glucose Measurement" },
    { 0x2A19,   "Battery Level" },
    { 0x2A1C,   "Temperature Measurement" },
    { 0x2A1D,   "Temperature Type" },
    { 0x2A1E,   "Intermediate Temperature" },
    { 0x2A21,   "Measurement Interval" },
    { 0x2A22,   "Boot Keyboard Input Report" },
    { 0x2A23,   "System ID" },
    { 0x2A24,   "Model Number String" },
    { 0x2A25,   "Serial Number String" },
    { 0x2A26,   "Firmware Revision String" },
    { 0x2A27,   "Hardware Revision String" },
    { 0x2A28,   "Software Revision String" },
    { 0x2A29,   "Manufacturer Name String" },
    { 0x2A2A,   "IEEE 11073-20601 Regulatory Certification Data List" },
    { 0x2A2B,   "Current Time" },
    { 0x2A31,   "Scan Refresh" },
    { 0x2A32,   "Boot Keyboard Output Report" },
    { 0x2A33,   "Boot Mouse Input Report" },
    { 0x2A34,   "Glucose Measurement Context" },
    { 0x2A35,   "Blood Pressure Measurement" },
    { 0x2A36,   "Intermediate Cuff Pressure" },
    { 0x2A37,   "Heart Rate Measurement" },
    { 0x2A38,   "Body Sensor Location" },
    { 0x2A39,   "Heart Rate Control Point" },
    { 0x2A3F,   "Alert Status" },
    { 0x2A40,   "Ringer Control Point" },
    { 0x2A41,   "Ringer Setting" },
    { 0x2A42,   "Alert Category ID Bit Mask" },
    { 0x2A43,   "Alert Category ID" },
    { 0x2A44,   "Alert Notification Control Point" },
    { 0x2A45,   "Unread Alert Status" },
    { 0x2A46,   "New Alert" },
    { 0x2A47,   "Supported New Alert Category" },
    { 0x2A48,   "Supported Unread Alert Category" },
    { 0x2A49,   "Blood Pressure Feature" },
    { 0x2A4A,   "HID Information" },
    { 0x2A4B,   "Report Map" },
    { 0x2A4C,   "HID Control Point" },
    { 0x2A4D,   "Report" },
    { 0x2A4E,   "Protocol Mode" },
    { 0x2A4F,   "Scan Interval Window" },
    { 0x2A50,   "PnP ID" },
    { 0x2A51,   "Glucose Feature" },
    { 0x2A52,   "Record Access Control Point" },
    { 0x2A53,   "RSC Measurement" },
    { 0x2A54,   "RSC Feature" },
    { 0x2A55,   "SC Control Point" },
    { 0x2A5B,   "CSC Measurement" },
    { 0x2A5C,   "CSC Feature" },
    { 0x2A5D,   "Sensor Location" },
    { 0x2A63,   "Cycling Power Measurement" },
    { 0x2A64,   "Cycling Power Vector" },
    { 0x2A65,   "Cycling Power Feature" },
    { 0x2A66,   "Cycling Power Control Point" },
    { 0x2A67,   "Location and Speed" },
    { 0x2A68,   "Navigation" },
    { 0x2A69,   "Position Quality" },
    { 0x2A6A,   "LN Feature" },
    { 0x2A6B,   "LN Control Point" },
    /*  16-bit UUID for Members - https://www.bluetooth.org/en-us/Pages/LoginRestrictedAll/16-bit-UUIDs-member.aspx */
    { 0xFEEE,   "Company UUID #2: Polar Electro Oy"}, /* Allocated 06-Mar-14 */
    { 0xFEEF,   "Company UUID #1: Polar Electro Oy"}, /* Allocated 06-Mar-14 */
    { 0xFEF0,   "Company UUID: Intel"}, /* Allocated 06-Mar-14 */
    { 0xFEF1,   "Company UUID #2: CSR"}, /* Allocated 13-Feb-14 */
    { 0xFEF2,   "Company UUID #1: CSR"}, /* Allocated 13-Feb-14 */
    { 0xFEF3,   "Company UUID #2: Google"}, /* Allocated 13-Feb-14 */
    { 0xFEF4,   "Company UUID #1: Google"}, /* Allocated 13-Feb-14 */
    { 0xFEF5,   "Company UUID: Dialog Semiconductor GmbH"}, /* Allocated 13-Feb-14 */
    { 0xFEF6,   "Company UUID: Wicentric, Inc."}, /* Allocated 13-Feb-14 */
    { 0xFEF7,   "Company UUID #2: Aplix Corporation"}, /* Allocated 13-Feb-14 */
    { 0xFEF8,   "Company UUID #1: Aplix Corporation"}, /* Allocated 13-Feb-14 */
    { 0xFEF9,   "Company UUID #2: PayPal, Inc."}, /* Allocated 13-Jan-14 */
    { 0xFEFA,   "Company UUID #1: PayPal, Inc."}, /* Allocated 13-Jan-14 */
    { 0xFEFB,   "Company UUID: Stollmann E+V GmbH"}, /* Allocated 06-Jan-14 */
    { 0xFEFC,   "Company UUID #2: Qualcomm Retail Solutions, Inc."}, /* Allocated 20-Dec-13 */
    { 0xFEFD,   "Company UUID #1: Qualcomm Retail Solutions, Inc."}, /* Allocated 20-Dec-13 */
    { 0xFEFE,   "Company UUID: GN ReSound A/S"}, /* Allocated 17-Dec-13 */
    { 0xFEFF,   "Company UUID: GN Netcom"}, /* Allocated 12-Dec-13 */
    /* SDO Uuids - https://www.bluetooth.org/en-us/specification/assigned-numbers/sdo-16-bit-uuids */
    { 0xFFFE,   "Alliance for Wireless Power" },
    { 0, NULL }
};
value_string_ext bluetooth_uuid_vals_ext = VALUE_STRING_EXT_INIT(bluetooth_uuid_vals);


/* Taken from https://www.bluetooth.org/technical/assignednumbers/identifiers.htm */
static const value_string bluetooth_company_id_vals[] = {
    {0x0000, "Ericsson Technology Licensing"},
    {0x0001, "Nokia Mobile Phones"},
    {0x0002, "Intel Corp."},
    {0x0003, "IBM Corp."},
    {0x0004, "Toshiba Corp."},
    {0x0005, "3Com"},
    {0x0006, "Microsoft"},
    {0x0007, "Lucent"},
    {0x0008, "Motorola"},
    {0x0009, "Infineon Technologies AG"},
    {0x000A, "Cambridge Silicon Radio"},
    {0x000B, "Silicon Wave"},
    {0x000C, "Digianswer A/S"},
    {0x000D, "Texas Instruments Inc."},
    {0x000E, "Ceva, Inc. (formerly Parthus Technologies, Inc.)"},
    {0x000F, "Broadcom Corporation"},
    {0x0010, "Mitel Semiconductor"},
    {0x0011, "Widcomm, Inc."},
    {0x0012, "Zeevo, Inc."},
    {0x0013, "Atmel Corporation"},
    {0x0014, "Mitsubishi Electric Corporation"},
    {0x0015, "RTX Telecom A/S"},
    {0x0016, "KC Technology Inc."},
    {0x0017, "Newlogic"},
    {0x0018, "Transilica, Inc."},
    {0x0019, "Rohde & Schwarz GmbH & Co. KG"},
    {0x001A, "TTPCom Limited"},
    {0x001B, "Signia Technologies, Inc."},
    {0x001C, "Conexant Systems Inc."},
    {0x001D, "Qualcomm"},
    {0x001E, "Inventel"},
    {0x001F, "AVM Berlin"},
    {0x0020, "BandSpeed, Inc."},
    {0x0021, "Mansella Ltd"},
    {0x0022, "NEC Corporation"},
    {0x0023, "WavePlus Technology Co., Ltd."},
    {0x0024, "Alcatel"},
    {0x0025, "Philips Semiconductors"},
    {0x0026, "C Technologies"},
    {0x0027, "Open Interface"},
    {0x0028, "R F Micro Devices"},
    {0x0029, "Hitachi Ltd"},
    {0x002A, "Symbol Technologies, Inc."},
    {0x002B, "Tenovis"},
    {0x002C, "Macronix International Co. Ltd."},
    {0x002D, "GCT Semiconductor"},
    {0x002E, "Norwood Systems"},
    {0x002F, "MewTel Technology Inc."},
    {0x0030, "ST Microelectronics"},
    {0x0031, "Synopsys"},
    {0x0032, "Red-M (Communications) Ltd"},
    {0x0033, "Commil Ltd"},
    {0x0034, "Computer Access Technology Corporation (CATC)"},
    {0x0035, "Eclipse (HQ Espana) S.L."},
    {0x0036, "Renesas Technology Corp."},
    {0x0037, "Mobilian Corporation"},
    {0x0038, "Terax"},
    {0x0039, "Integrated System Solution Corp."},
    {0x003A, "Matsushita Electric Industrial Co., Ltd."},
    {0x003B, "Gennum Corporation"},
    {0x003C, "Research In Motion"},
    {0x003D, "IPextreme, Inc."},
    {0x003E, "Systems and Chips, Inc"},
    {0x003F, "Bluetooth SIG, Inc"},
    {0x0040, "Seiko Epson Corporation"},
    {0x0041, "Integrated Silicon Solution Taiwan, Inc."},
    {0x0042, "CONWISE Technology Corporation Ltd"},
    {0x0043, "PARROT SA"},
    {0x0044, "Socket Mobile"},
    {0x0045, "Atheros Communications, Inc."},
    {0x0046, "MediaTek, Inc."},
    {0x0047, "Bluegiga"},
    {0x0048, "Marvell Technology Group Ltd."},
    {0x0049, "3DSP Corporation"},
    {0x004A, "Accel Semiconductor Ltd."},
    {0x004B, "Continental Automotive Systems"},
    {0x004C, "Apple, Inc."},
    {0x004D, "Staccato Communications, Inc."},
    {0x004E, "Avago Technologies"},
    {0x004F, "APT Licensing Ltd."},
    {0x0050, "SiRF Technology, Inc."},
    {0x0051, "Tzero Technologies, Inc."},
    {0x0052, "J&M Corporation"},
    {0x0053, "Free2move AB"},
    {0x0054, "3DiJoy Corporation"},
    {0x0055, "Plantronics, Inc."},
    {0x0056, "Sony Ericsson Mobile Communications"},
    {0x0057, "Harman International Industries, Inc."},
    {0x0058, "Vizio, Inc."},
    {0x0059, "Nordic Semiconductor ASA"},
    {0x005A, "EM Microelectronic-Marin SA"},
    {0x005B, "Ralink Technology Corporation"},
    {0x005C, "Belkin International, Inc."},
    {0x005D, "Realtek Semiconductor Corporation"},
    {0x005E, "Stonestreet One, LLC"},
    {0x005F, "Wicentric, Inc."},
    {0x0060, "RivieraWaves S.A.S"},
    {0x0061, "RDA Microelectronics"},
    {0x0062, "Gibson Guitars"},
    {0x0063, "MiCommand Inc."},
    {0x0064, "Band XI International, LLC"},
    {0x0065, "Hewlett-Packard Company"},
    {0x0066, "9Solutions Oy"},
    {0x0067, "GN Netcom A/S"},
    {0x0068, "General Motors"},
    {0x0069, "A&D Engineering, Inc."},
    {0x006A, "MindTree Ltd."},
    {0x006B, "Polar Electro OY"},
    {0x006C, "Beautiful Enterprise Co., Ltd."},
    {0x006D, "BriarTek, Inc."},
    {0x006E, "Summit Data Communications, Inc."},
    {0x006F, "Sound ID"},
    {0x0070, "Monster, LLC"},
    {0x0071, "connectBlue AB"},
    {0x0072, "ShangHai Super Smart Electronics Co. Ltd."},
    {0x0073, "Group Sense Ltd."},
    {0x0074, "Zomm, LLC"},
    {0x0075, "Samsung Electronics Co. Ltd."},
    {0x0076, "Creative Technology Ltd."},
    {0x0077, "Laird Technologies"},
    {0x0078, "Nike, Inc."},
    {0x0079, "lesswire AG"},
    {0x007A, "MStar Semiconductor, Inc."},
    {0x007B, "Hanlynn Technologies"},
    {0x007C, "A & R Cambridge"},
    {0x007D, "Seers Technology Co. Ltd."},
    {0x007E, "Sports Tracking Technologies Ltd."},
    {0x007F, "Autonet Mobile"},
    {0x0080, "DeLorme Publishing Company, Inc."},
    {0x0081, "WuXi Vimicro"},
    {0x0082, "Sennheiser Communications A/S"},
    {0x0083, "TimeKeeping Systems, Inc."},
    {0x0084, "Ludus Helsinki Ltd."},
    {0x0085, "BlueRadios, Inc."},
    {0x0086, "equinux AG"},
    {0x0087, "Garmin International, Inc."},
    {0x0088, "Ecotest"},
    {0x0089, "GN ReSound A/S"},
    {0x008A, "Jawbone"},
    {0x008B, "Topcon Positioning Systems, LLC"},
    {0x008C, "Qualcomm Labs, Inc."},
    {0x008D, "Zscan Software"},
    {0x008E, "Quintic Corp."},
    {0x008F, "Stollmann E+V GmbH"},
    {0x0090, "Funai Electric Co., Ltd."},
    {0x0091, "Advanced PANMOBIL systems GmbH & Co. KG"},
    {0x0092, "ThinkOptics, Inc."},
    {0x0093, "Universal Electronics, Inc."},
    {0x0094, "Airoha Technology Corp."},
    {0x0095, "NEC Lighting, Ltd."},
    {0x0096, "ODM Technology, Inc."},
    {0x0097, "Bluetrek Technologies Limited"},
    {0x0098, "zero1.tv GmbH"},
    {0x0099, "i.Tech Dynamic Global Distribution Ltd."},
    {0x009A, "Alpwise"},
    {0x009B, "Jiangsu Toppower Automotive Electronics Co., Ltd."},
    {0x009C, "Colorfy, Inc."},
    {0x009D, "Geoforce Inc."},
    {0x009E, "Bose Corporation"},
    {0x009F, "Suunto Oy"},
    {0x00A0, "Kensington Computer Products Group"},
    {0x00A1, "SR-Medizinelektronik"},
    {0x00A2, "Vertu Corporation Limited"},
    {0x00A3, "Meta Watch Ltd."},
    {0x00A4, "LINAK A/S"},
    {0x00A5, "OTL Dynamics LLC"},
    {0x00A6, "Panda Ocean Inc."},
    {0x00A7, "Visteon Corporation"},
    {0x00A8, "ARP Devices Limited"},
    {0x00A9, "Magneti Marelli S.p.A."},
    {0x00AA, "CAEN RFID srl"},
    {0x00AB, "Ingenieur-Systemgruppe Zahn GmbH"},
    {0x00AC, "Green Throttle Games"},
    {0x00AD, "Peter Systemtechnik GmbH"},
    {0x00AE, "Omegawave Oy"},
    {0x00AF, "Cinetix"},
    {0x00B0, "Passif Semiconductor Corp"},
    {0x00B1, "Saris Cycling Group, Inc"},
    {0x00B2, "Bekey A/S"},
    {0x00B3, "Clarinox Technologies Pty. Ltd."},
    {0x00B4, "BDE Technology Co., Ltd."},
    {0x00B5, "Swirl Networks"},
    {0x00B6, "Meso international"},
    {0x00B7, "TreLab Ltd"},
    {0x00B8, "Qualcomm Innovation Center, Inc. (QuIC)"},
    {0x00B9, "Johnson Controls, Inc."},
    {0x00BA, "Starkey Laboratories Inc."},
    {0x00BB, "S-Power Electronics Limited"},
    {0xFFFF, "For use in internal and interoperability tests."},
    {0, NULL }
};
value_string_ext bluetooth_company_id_vals_ext = VALUE_STRING_EXT_INIT(bluetooth_company_id_vals);

guint32 max_disconnect_in_frame = G_MAXUINT32;


void proto_register_bluetooth(void);
void proto_reg_handoff_bluetooth(void);


gint
dissect_bd_addr(gint hf_bd_addr, proto_tree *tree, tvbuff_t *tvb, gint offset, guint8 *bdaddr)
{
    guint8 bd_addr[6];

    bd_addr[5] = tvb_get_guint8(tvb, offset);
    bd_addr[4] = tvb_get_guint8(tvb, offset + 1);
    bd_addr[3] = tvb_get_guint8(tvb, offset + 2);
    bd_addr[2] = tvb_get_guint8(tvb, offset + 3);
    bd_addr[1] = tvb_get_guint8(tvb, offset + 4);
    bd_addr[0] = tvb_get_guint8(tvb, offset + 5);

    proto_tree_add_ether(tree, hf_bd_addr, tvb, offset, 6, bd_addr);
    offset += 6;

    if (bdaddr)
        memcpy(bdaddr, bd_addr, 6);

    return offset;
}


static const char* bluetooth_conv_get_filter_type(conv_item_t* conv _U_, conv_filter_type_e filter)
{
    if (filter == CONV_FT_SRC_ADDRESS)
        return "bluetooth.src";

    if (filter == CONV_FT_DST_ADDRESS)
        return "bluetooth.dst";

    if (filter == CONV_FT_ANY_ADDRESS)
        return "bluetooth.addr";

    return CONV_FILTER_INVALID;
}

static ct_dissector_info_t bluetooth_ct_dissector_info = {&bluetooth_conv_get_filter_type};


static const char* bluetooth_get_filter_type(hostlist_talker_t* host _U_, conv_filter_type_e filter)
{
    if (filter == CONV_FT_ANY_ADDRESS)
        return "bluetooth.addr";

    return CONV_FILTER_INVALID;
}

static hostlist_dissector_info_t  bluetooth_dissector_info = {&bluetooth_get_filter_type};


static int
bluetooth_conversation_packet(void *pct, packet_info *pinfo,
        epan_dissect_t *edt _U_, const void *vip _U_)
{
    conv_hash_t *hash = (conv_hash_t*) pct;
    add_conversation_table_data(hash, &pinfo->dl_src, &pinfo->dl_dst, 0, 0, 1,
            pinfo->fd->pkt_len, &pinfo->rel_ts, &pinfo->fd->abs_ts,
            &bluetooth_ct_dissector_info, PT_NONE);

    return 1;
}


static int
bluetooth_hostlist_packet(void *pit, packet_info *pinfo,
        epan_dissect_t *edt _U_, const void *vip _U_)
{
    conv_hash_t *hash = (conv_hash_t*) pit;

    add_hostlist_table_data(hash, &pinfo->dl_src, 0, TRUE,  1, pinfo->fd->pkt_len, &bluetooth_dissector_info, PT_NONE);
    add_hostlist_table_data(hash, &pinfo->dl_dst, 0, FALSE, 1, pinfo->fd->pkt_len, &bluetooth_dissector_info, PT_NONE);

    return 1;
}

static conversation_t *
get_conversation(packet_info *pinfo,
                     address *src_addr, address *dst_addr,
                     guint32 src_endpoint, guint32 dst_endpoint)
{
    conversation_t *conversation;

    conversation = find_conversation(pinfo->fd->num,
                               src_addr, dst_addr,
                               pinfo->ptype,
                               src_endpoint, dst_endpoint, 0);
    if (conversation) {
        return conversation;
    }

    conversation = conversation_new(pinfo->fd->num,
                           src_addr, dst_addr,
                           pinfo->ptype,
                           src_endpoint, dst_endpoint, 0);
    return conversation;
}


static gint
dissect_bluetooth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item        *main_item;
    proto_tree        *main_tree;
    proto_item        *sub_item;
    bluetooth_data_t  *bluetooth_data;
    address           *src;
    address           *dst;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Bluetooth");
    switch (pinfo->p2p_dir) {

    case P2P_DIR_SENT:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Sent ");
        break;

    case P2P_DIR_RECV:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Rcvd ");
        break;

    case P2P_DIR_UNKNOWN:
        break;

    default:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction %d ",
                pinfo->p2p_dir);
        break;
    }

    pinfo->ptype = PT_BLUETOOTH;
    get_conversation(pinfo, &pinfo->dl_src, &pinfo->dl_dst, pinfo->srcport, pinfo->destport);

    main_item = proto_tree_add_item(tree, proto_bluetooth, tvb, 0, tvb_length(tvb), ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_bluetooth);

    bluetooth_data = (bluetooth_data_t *) wmem_new(wmem_packet_scope(), bluetooth_data_t);
    if (pinfo->phdr->presence_flags & WTAP_HAS_INTERFACE_ID)
        bluetooth_data->interface_id = pinfo->phdr->interface_id;
    else
        bluetooth_data->interface_id = HCI_INTERFACE_DEFAULT;
    bluetooth_data->adapter_id = HCI_ADAPTER_DEFAULT;
    bluetooth_data->adapter_disconnect_in_frame  = &max_disconnect_in_frame;
    bluetooth_data->chandle_sessions             = chandle_sessions;
    bluetooth_data->chandle_to_bdaddr            = chandle_to_bdaddr;
    bluetooth_data->chandle_to_mode              = chandle_to_mode;
    bluetooth_data->bdaddr_to_name               = bdaddr_to_name;
    bluetooth_data->bdaddr_to_role               = bdaddr_to_role;
    bluetooth_data->localhost_bdaddr             = localhost_bdaddr;
    bluetooth_data->localhost_name               = localhost_name;

    bluetooth_data->previous_protocol_data.data = data;

    if (have_tap_listener(bluetooth_tap)) {
        bluetooth_tap_data_t  *bluetooth_tap_data;

        bluetooth_tap_data                = wmem_new(wmem_packet_scope(), bluetooth_tap_data_t);
        bluetooth_tap_data->interface_id  = bluetooth_data->interface_id;
        bluetooth_tap_data->adapter_id    = bluetooth_data->adapter_id;

        tap_queue_packet(bluetooth_tap, pinfo, bluetooth_tap_data);
    }

    src = (address *) p_get_proto_data(wmem_file_scope(), pinfo, proto_bluetooth, BLUETOOTH_DATA_SRC);
    dst = (address *) p_get_proto_data(wmem_file_scope(), pinfo, proto_bluetooth, BLUETOOTH_DATA_DST);

    if (src && src->type == AT_STRINGZ) {
        sub_item = proto_tree_add_string(main_tree, hf_bluetooth_str_addr, tvb, 0, 0, (const char *) src->data);
        PROTO_ITEM_SET_HIDDEN(sub_item);

        sub_item = proto_tree_add_string(main_tree, hf_bluetooth_str_src, tvb, 0, 0, (const char *) src->data);
        PROTO_ITEM_SET_GENERATED(sub_item);
    } else if (src && src->type == AT_ETHER) {
        sub_item = proto_tree_add_ether(main_tree, hf_bluetooth_addr, tvb, 0, 0, (const guint8 *) src->data);
        PROTO_ITEM_SET_HIDDEN(sub_item);

        sub_item = proto_tree_add_ether(main_tree, hf_bluetooth_src, tvb, 0, 0, (const guint8 *) src->data);
        PROTO_ITEM_SET_GENERATED(sub_item);
    }

    if (dst && dst->type == AT_STRINGZ) {
        sub_item = proto_tree_add_string(main_tree, hf_bluetooth_str_addr, tvb, 0, 0, (const char *) dst->data);
        PROTO_ITEM_SET_HIDDEN(sub_item);

        sub_item = proto_tree_add_string(main_tree, hf_bluetooth_str_dst, tvb, 0, 0, (const char *) dst->data);
        PROTO_ITEM_SET_GENERATED(sub_item);
    } else if (dst && dst->type == AT_ETHER) {
        sub_item = proto_tree_add_ether(main_tree, hf_bluetooth_addr, tvb, 0, 0, (const guint8 *) dst->data);
        PROTO_ITEM_SET_HIDDEN(sub_item);

        sub_item = proto_tree_add_ether(main_tree, hf_bluetooth_dst, tvb, 0, 0, (const guint8 *) dst->data);
        PROTO_ITEM_SET_GENERATED(sub_item);
    }

    if (proto_ubertooth == (gint) GPOINTER_TO_UINT(wmem_list_frame_data(
                wmem_list_frame_prev(wmem_list_tail(pinfo->layers))))) {
        call_dissector(btle_handle, tvb, pinfo, tree);
    } else if (!dissector_try_uint_new(bluetooth_table, pinfo->phdr->pkt_encap, tvb, pinfo, tree, TRUE, bluetooth_data)) {
        call_dissector(data_handle, tvb, pinfo, tree);
    }

    return tvb_length(tvb);
}

void
proto_register_bluetooth(void)
{
    static hf_register_info hf[] = {
        { &hf_bluetooth_src,
            { "Source",                              "bluetooth.src",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bluetooth_dst,
            { "Destination",                         "bluetooth.dst",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bluetooth_addr,
            { "Source or Destination",               "bluetooth.addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bluetooth_str_src,
            { "Source",                              "bluetooth.src",
            FT_STRING, STR_ASCII, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bluetooth_str_dst,
            { "Destination",                         "bluetooth.dst",
            FT_STRING, STR_ASCII, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bluetooth_str_addr,
            { "Source or Destination",               "bluetooth.addr",
            FT_STRING, STR_ASCII, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_bluetooth,
    };

    proto_bluetooth = proto_register_protocol("Bluetooth",
            "Bluetooth", "bluetooth");

    bluetooth_handle = new_register_dissector("bluetooth", dissect_bluetooth, proto_bluetooth);

    proto_register_field_array(proto_bluetooth, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    bluetooth_table = register_dissector_table("bluetooth.encap",
            "Bluetooth Encapsulation", FT_UINT32, BASE_HEX);

    chandle_sessions         = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    chandle_to_bdaddr        = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    chandle_to_mode          = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    bdaddr_to_name           = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    bdaddr_to_role           = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    localhost_bdaddr         = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    localhost_name           = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    bluetooth_tap = register_tap("bluetooth");

    register_conversation_table(proto_bluetooth, TRUE, bluetooth_conversation_packet, bluetooth_hostlist_packet);
}

void
proto_reg_handoff_bluetooth(void)
{
    proto_ubertooth = proto_get_id_by_filter_name("ubertooth");
    btle_handle = find_dissector("btle");
    data_handle = find_dissector("data");

    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_HCI,           bluetooth_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_H4,            bluetooth_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR,  bluetooth_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR, bluetooth_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_PACKETLOGGER,            bluetooth_handle);

    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_LE_LL,           bluetooth_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_LE_LL_WITH_PHDR, bluetooth_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_BREDR_BB,        bluetooth_handle);

    dissector_add_uint("usb.product", (0x0a5c << 16) | 0x21e8, bluetooth_handle);
    dissector_add_uint("usb.product", (0x1131 << 16) | 0x1001, bluetooth_handle);
    dissector_add_uint("usb.product", (0x050d << 16) | 0x0081, bluetooth_handle);
    dissector_add_uint("usb.product", (0x0a5c << 16) | 0x2198, bluetooth_handle);
    dissector_add_uint("usb.product", (0x0a5c << 16) | 0x21e8, bluetooth_handle);
    dissector_add_uint("usb.product", (0x04bf << 16) | 0x0320, bluetooth_handle);
    dissector_add_uint("usb.product", (0x13d3 << 16) | 0x3375, bluetooth_handle);

    dissector_add_uint("usb.protocol", 0xE00101, bluetooth_handle);
    dissector_add_uint("usb.protocol", 0xE00104, bluetooth_handle);

    dissector_add_for_decode_as("usb.device", bluetooth_handle);
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
