/* packet-bluetooth.c
 * Routines for the Bluetooth
 *
 * Copyright 2014, Michal Labedzki for Tieto Corporation
 *
 * Dissector for Bluetooth High Speed over wireless
 * Copyright 2012 intel Corp.
 * Written by Andrei Emeltchenko at intel dot com
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

#include <string.h>
#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/conversation_table.h>
#include <epan/decode_as.h>
#include <epan/proto_data.h>
#include <wiretap/wtap.h>
#include "packet-llc.h"
#include <epan/oui.h>

#include "packet-bluetooth.h"

int proto_bluetooth = -1;

static int hf_bluetooth_src = -1;
static int hf_bluetooth_dst = -1;
static int hf_bluetooth_addr = -1;
static int hf_bluetooth_src_str = -1;
static int hf_bluetooth_dst_str = -1;
static int hf_bluetooth_addr_str = -1;

static int hf_llc_bluetooth_pid = -1;

static gint ett_bluetooth = -1;

static dissector_handle_t btle_handle;
static dissector_handle_t hci_usb_handle;

static dissector_table_t bluetooth_table;
static dissector_table_t hci_vendor_table;
dissector_table_t        bluetooth_uuid_table;

static wmem_tree_t *chandle_sessions        = NULL;
static wmem_tree_t *chandle_to_bdaddr       = NULL;
static wmem_tree_t *chandle_to_mode         = NULL;
static wmem_tree_t *bdaddr_to_name          = NULL;
static wmem_tree_t *bdaddr_to_role          = NULL;
static wmem_tree_t *localhost_name          = NULL;
static wmem_tree_t *localhost_bdaddr        = NULL;
static wmem_tree_t *hci_vendors             = NULL;

wmem_tree_t *bluetooth_uuids = NULL;

static int bluetooth_tap = -1;
int bluetooth_device_tap = -1;
int bluetooth_hci_summary_tap = -1;

const value_string bluetooth_uuid_vals[] = {
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
    { 0x1115,   "PAN PANU" },
    { 0x1116,   "PAN NAP" },
    { 0x1117,   "PAN GN" },
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
    { 0x113C,   "Calendar, Task and Notes Access Service" },
    { 0x113D,   "Calendar, Task and Notes Notification Service" },
    { 0x113E,   "Calendar, Task and Notes Profile" },
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
    { 0x1815,   "Automation IO" },
    { 0x1816,   "Cycling Speed and Cadence" },
    { 0x1818,   "Cycling Power" },
    { 0x1819,   "Location and Navigation" },
    { 0x181A,   "Environmental Sensing" },
    { 0x181B,   "Body Composition" },
    { 0x181C,   "User Data" },
    { 0x181D,   "Weight Scale" },
    { 0x181E,   "Bond Management" },
    { 0x181F,   "Continuous Glucose Monitoring" },
    { 0x1820,   "Internet Protocol Support" },
    { 0x1821,   "Indoor Positioning" },
    { 0x1822,   "Pulse Oximeter" },
    { 0x1823,   "HTTP Proxy" },
    { 0x1824,   "Transport Discovery" },
    { 0x1825,   "Object Transfer" },
    /* Units - https://developer.bluetooth.org/gatt/units/Pages/default.aspx */
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
    /* Declarations - https://developer.bluetooth.org/gatt/declarations/Pages/DeclarationsHome.aspx */
    { 0x2800,   "GATT Primary Service Declaration" },
    { 0x2801,   "GATT Secondary Service Declaration" },
    { 0x2802,   "GATT Include Declaration" },
    { 0x2803,   "GATT Characteristic Declaration" },
    /* Descriptors - https://developer.bluetooth.org/gatt/descriptors/Pages/DescriptorsHomePage.aspx */
    { 0x2900,   "Characteristic Extended Properties" },
    { 0x2901,   "Characteristic User Description" },
    { 0x2902,   "Client Characteristic Configuration" },
    { 0x2903,   "Server Characteristic Configuration" },
    { 0x2904,   "Characteristic Presentation Format" },
    { 0x2905,   "Characteristic Aggregate Format" },
    { 0x2906,   "Valid Range" },
    { 0x2907,   "External Report Reference" },
    { 0x2908,   "Report Reference" },
    { 0x2909,   "Number of Digitals" },
    { 0x290A,   "Value Trigger Setting" },
    { 0x290B,   "Environmental Sensing Configuration" },
    { 0x290C,   "Environmental Sensing Measurement" },
    { 0x290D,   "Environmental Sensing Trigger Setting" },
    { 0x290E,   "Time Trigger Setting" },
    /* Characteristics - https://developer.bluetooth.org/gatt/characteristics/Pages/CharacteristicsHome.aspx */
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
    { 0x2A2C,   "Magnetic Declination" },
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
    { 0x2A56,   "Digital" },
    { 0x2A58,   "Analog" },
    { 0x2A5A,   "Aggregate" },
    { 0x2A5B,   "CSC Measurement" },
    { 0x2A5C,   "CSC Feature" },
    { 0x2A5D,   "Sensor Location" },
    { 0x2A5E,   "PLX Spot-Check Measurement" },
    { 0x2A5F,   "PLX Continuous Measurement" },
    { 0x2A60,   "PLX Features" },
    { 0x2A63,   "Cycling Power Measurement" },
    { 0x2A64,   "Cycling Power Vector" },
    { 0x2A65,   "Cycling Power Feature" },
    { 0x2A66,   "Cycling Power Control Point" },
    { 0x2A67,   "Location and Speed" },
    { 0x2A68,   "Navigation" },
    { 0x2A69,   "Position Quality" },
    { 0x2A6A,   "LN Feature" },
    { 0x2A6B,   "LN Control Point" },
    { 0x2A6C,   "Elevation" },
    { 0x2A6D,   "Pressure" },
    { 0x2A6E,   "Temperature" },
    { 0x2A6F,   "Humidity" },
    { 0x2A70,   "True Wind Speed" },
    { 0x2A71,   "True Wind Direction" },
    { 0x2A72,   "Apparent Wind Speed" },
    { 0x2A73,   "Apparent Wind Direction" },
    { 0x2A74,   "Gust Factor" },
    { 0x2A75,   "Pollen Concentration" },
    { 0x2A76,   "UV Index" },
    { 0x2A77,   "Irradiance" },
    { 0x2A78,   "Rainfall" },
    { 0x2A79,   "Wind Chill" },
    { 0x2A7A,   "Heat Index" },
    { 0x2A7B,   "Dew Point" },
    { 0x2A7D,   "Descriptor Value Changed" },
    { 0x2A7E,   "Aerobic Heart Rate Lower Limit" },
    { 0x2A7F,   "Aerobic Threshold" },
    { 0x2A80,   "Age" },
    { 0x2A81,   "Anaerobic Heart Rate Lower Limit" },
    { 0x2A82,   "Anaerobic Heart Rate Upper Limit" },
    { 0x2A83,   "Anaerobic Threshold" },
    { 0x2A84,   "Aerobic Heart Rate Upper Limit" },
    { 0x2A85,   "Date of Birth" },
    { 0x2A86,   "Date of Threshold Assessment" },
    { 0x2A87,   "Email Address" },
    { 0x2A88,   "Fat Burn Heart Rate Lower Limit" },
    { 0x2A89,   "Fat Burn Heart Rate Upper Limit" },
    { 0x2A8A,   "First Name" },
    { 0x2A8B,   "Five Zone Heart Rate Limits" },
    { 0x2A8C,   "Gender" },
    { 0x2A8D,   "Heart Rate Max" },
    { 0x2A8E,   "Height" },
    { 0x2A8F,   "Hip Circumference" },
    { 0x2A90,   "Last Name" },
    { 0x2A91,   "Maximum Recommended Heart Rate" },
    { 0x2A92,   "Resting Heart Rate" },
    { 0x2A93,   "Sport Type for Aerobic and Anaerobic Thresholds" },
    { 0x2A94,   "Three Zone Heart Rate Limits" },
    { 0x2A95,   "Two Zone Heart Rate Limit" },
    { 0x2A96,   "VO2 Max" },
    { 0x2A97,   "Waist Circumference" },
    { 0x2A98,   "Weight" },
    { 0x2A99,   "Database Change Increment" },
    { 0x2A9A,   "User Index" },
    { 0x2A9B,   "Body Composition Feature" },
    { 0x2A9C,   "Body Composition Measurement" },
    { 0x2A9D,   "Weight Measurement" },
    { 0x2A9E,   "Weight Scale Feature" },
    { 0x2A9F,   "User Control Point" },
    { 0x2AA0,   "Magnetic Flux Density - 2D" },
    { 0x2AA1,   "Magnetic Flux Density - 3D" },
    { 0x2AA2,   "Language" },
    { 0x2AA3,   "Barometric Pressure Trend" },
    { 0x2AA4,   "Bond Management Control Point" },
    { 0x2AA5,   "Bond Management Feature" },
    { 0x2AA6,   "Central Address Resolution" },
    { 0x2AA7,   "CGM Measurement" },
    { 0x2AA8,   "CGM Feature" },
    { 0x2AA9,   "CGM Status" },
    { 0x2AAA,   "CGM Session Start Time" },
    { 0x2AAB,   "CGM Session Run Time" },
    { 0x2AAC,   "CGM Specific Ops Control Point" },
    { 0x2AAD,   "Indoor Positioning Configuration" },
    { 0x2AAE,   "Latitude" },
    { 0x2AAF,   "Longitude" },
    { 0x2AB0,   "Local North Coordinate" },
    { 0x2AB1,   "Local East Coordinate" },
    { 0x2AB2,   "Floor Number" },
    { 0x2AB3,   "Altitude" },
    { 0x2AB4,   "Uncertainty" },
    { 0x2AB5,   "Location Name" },
    { 0x2AB6,   "URI" },
    { 0x2AB7,   "HTTP Headers" },
    { 0x2AB8,   "HTTP Status Code" },
    { 0x2AB9,   "HTTP Entity Body" },
    { 0x2ABA,   "HTTP Control Point" },
    { 0x2ABB,   "HTTPS Security" },
    { 0x2ABC,   "TDS Control Point" },
    { 0x2ABD,   "OTS Feature" },
    { 0x2ABE,   "Object Name" },
    { 0x2ABF,   "Object Type" },
    { 0x2AC0,   "Object Size" },
    { 0x2AC1,   "Object First-Created" },
    { 0x2AC2,   "Object Last-Modified" },
    { 0x2AC3,   "Object ID" },
    { 0x2AC4,   "Object Properties" },
    { 0x2AC5,   "Object Action Control Point" },
    { 0x2AC6,   "Object List Control Point" },
    { 0x2AC7,   "Object List Filter" },
    { 0x2AC8,   "Object Changed" },
    /*  16-bit UUID for Members - https://www.bluetooth.org/en-us/Pages/LoginRestrictedAll/16-bit-UUIDs-member.aspx */
    { 0xFE5C,   "million hunters GmbH" },
    { 0xFE5D,   "Grundfos A/S" },
    { 0xFE5E,   "Plastc Corporation" },
    { 0xFE5F,   "Eyefi, Inc." },
    { 0xFE60,   "Lierda Science & Technology Group Co., Ltd." },
    { 0xFE61,   "Logitech International SA" },
    { 0xFE62,   "Indagem Tech LLC" },
    { 0xFE63,   "Connected Yard, Inc." },
    { 0xFE64,   "Siemens AG" },
    { 0xFE65,   "CHIPOLO d.o.o." },
    { 0xFE66,   "Intel Corporation" },
    { 0xFE67,   "Lab Sensor Solutions" },
    { 0xFE68,   "Qualcomm Life Inc" },
    { 0xFE69,   "Qualcomm Life Inc" },
    { 0xFE6A,   "Kontakt Micro-Location Sp. z o.o." },
    { 0xFE6B,   "TASER International, Inc." },
    { 0xFE6C,   "TASER International, Inc." },
    { 0xFE6D,   "The University of Tokyo" },
    { 0xFE6E,   "The University of Tokyo" },
    { 0xFE6F,   "LINE Corporation" },
    { 0xFE70,   "Beijing Jingdong Century Trading Co., Ltd." },
    { 0xFE71,   "Plume Design Inc" },
    { 0xFE72,   "St. Jude Medical, Inc." },
    { 0xFE73,   "St. Jude Medical, Inc." },
    { 0xFE74,   "unwire" },
    { 0xFE75,   "TangoMe" },
    { 0xFE76,   "TangoMe" },
    { 0xFE77,   "Hewlett-Packard Company" },
    { 0xFE78,   "Hewlett-Packard Company" },
    { 0xFE79,   "Zebra Technologies" },
    { 0xFE7A,   "Bragi GmbH" },
    { 0xFE7B,   "Orion Labs, Inc." },
    { 0xFE7C,   "Telit Wireless Solutions (Formerly Stollmann E+V GmbH)" },
    { 0xFE7D,   "Aterica Health Inc." },
    { 0xFE7E,   "Awear Solutions Ltd" },
    { 0xFE7F,   "Doppler Lab" },
    { 0xFE80,   "Doppler Lab" },
    { 0xFE81,   "Medtronic Inc." },
    { 0xFE82,   "Medtronic Inc." },
    { 0xFE83,   "Blue Bite" },
    { 0xFE84,   "RF Digital Corp" },
    { 0xFE85,   "RF Digital Corp" },
    { 0xFE86,   "HUAWEI Technologies Co., Ltd." },
    { 0xFE87,   "Qingdao Yeelink Information Technology Co., Ltd." },
    { 0xFE88,   "SALTO SYSTEMS S.L." },
    { 0xFE89,   "B&O Play A/S" },
    { 0xFE8A,   "Apple, Inc." },
    { 0xFE8B,   "Apple, Inc." },
    { 0xFE8C,   "TRON Forum" },
    { 0xFE8D,   "Interaxon Inc." },
    { 0xFE8E,   "ARM Ltd" },
    { 0xFE8F,   "CSR" },
    { 0xFE90,   "JUMA" },
    { 0xFE91,   "Shanghai Imilab Technology Co.,Ltd" },
    { 0xFE92,   "Jarden Safety & Security" },
    { 0xFE93,   "OttoQ Inc." },
    { 0xFE94,   "OttoQ Inc." },
    { 0xFE95,   "Xiaomi Inc." },
    { 0xFE96,   "Tesla Motor Inc." },
    { 0xFE97,   "Tesla Motor Inc." },
    { 0xFE98,   "Currant, Inc." },
    { 0xFE99,   "Currant, Inc." },
    { 0xFE9A,   "Estimote" },
    { 0xFE9B,   "Samsara Networks, Inc" },
    { 0xFE9C,   "GSI Laboratories, Inc." },
    { 0xFE9D,   "Mobiquity Networks Inc" },
    { 0xFE9E,   "Dialog Semiconductor B.V." },
    { 0xFE9F,   "Google" },
    { 0xFEA0,   "Google" },
    { 0xFEA1,   "Intrepid Control Systems, Inc." },
    { 0xFEA2,   "Intrepid Control Systems, Inc." },
    { 0xFEA3,   "ITT Industries" },
    { 0xFEA4,   "Paxton Access Ltd" },
    { 0xFEA5,   "GoPro, Inc." },
    { 0xFEA6,   "GoPro, Inc." },
    { 0xFEA7,   "UTC Fire and Security" },
    { 0xFEA8,   "Savant Systems LLC" },
    { 0xFEA9,   "Savant Systems LLC" },
    { 0xFEAA,   "Google" },
    { 0xFEAB,   "Nokia Corporation" },
    { 0xFEAC,   "Nokia Corporation" },
    { 0xFEAD,   "Nokia Corporation" },
    { 0xFEAE,   "Nokia Corporation" },
    { 0xFEAF,   "Nest Labs Inc." },
    { 0xFEB0,   "Nest Labs Inc." },
    { 0xFEB1,   "Electronics Tomorrow Limited" },
    { 0xFEB2,   "Microsoft Corporation" },
    { 0xFEB3,   "Taobao" },
    { 0xFEB4,   "WiSilica Inc." },
    { 0xFEB5,   "WiSilica Inc." },
    { 0xFEB6,   "Vencer Co, Ltd" },
    { 0xFEB7,   "Facebook, Inc." },
    { 0xFEB8,   "Facebook, Inc." },
    { 0xFEB9,   "LG Electronics" },
    { 0xFEBA,   "Tencent Holdings Limited" },
    { 0xFEBB,   "adafruit industries" },
    { 0xFEBC,   "Dexcom, Inc." },
    { 0xFEBD,   "Clover Network, Inc." },
    { 0xFEBE,   "Bose Corporation" },
    { 0xFEBF,   "Nod, Inc." },
    { 0xFEC0,   "KDDI Corporation" },
    { 0xFEC1,   "KDDI Corporation" },
    { 0xFEC2,   "Blue Spark Technologies, Inc." },
    { 0xFEC3,   "360fly, Inc." },
    { 0xFEC4,   "PLUS Location Systems" },
    { 0xFEC5,   "Realtek Semiconductor Corp." },
    { 0xFEC6,   "Kocomojo, LLC" },
    { 0xFEC7,   "Apple, Inc." },
    { 0xFEC8,   "Apple, Inc." },
    { 0xFEC9,   "Apple, Inc." },
    { 0xFECA,   "Apple, Inc." },
    { 0xFECB,   "Apple, Inc." },
    { 0xFECC,   "Apple, Inc." },
    { 0xFECD,   "Apple, Inc." },
    { 0xFECE,   "Apple, Inc." },
    { 0xFECF,   "Apple, Inc." },
    { 0xFED0,   "Apple, Inc." },
    { 0xFED1,   "Apple, Inc." },
    { 0xFED2,   "Apple, Inc." },
    { 0xFED3,   "Apple, Inc." },
    { 0xFED4,   "Apple, Inc." },
    { 0xFED5,   "Plantronics Inc." },
    { 0xFED6,   "Broadcom Corporation" },
    { 0xFED7,   "Broadcom Corporation" },
    { 0xFED8,   "Google" },
    { 0xFED9,   "Pebble Technology Corporation" },
    { 0xFEDA,   "ISSC Technologies Corporation" },
    { 0xFEDB,   "Perka, Inc." },
    { 0xFEDC,   "Jawbone" },
    { 0xFEDD,   "Jawbone" },
    { 0xFEDE,   "Coin, Inc." },
    { 0xFEDF,   "Design SHIFT" },
    { 0xFEE0,   "Anhui Huami Information Technology Co." },
    { 0xFEE1,   "Anhui Huami Information Technology Co." },
    { 0xFEE2,   "Anki, Inc." },
    { 0xFEE3,   "Anki, Inc." },
    { 0xFEE4,   "Nordic Semiconductor ASA" },
    { 0xFEE5,   "Nordic Semiconductor ASA" },
    { 0xFEE6,   "Seed Labs, Inc." },
    { 0xFEE7,   "Tencent Holdings Limited" },
    { 0xFEE8,   "Quintic Corp." },
    { 0xFEE9,   "Quintic Corp." },
    { 0xFEEA,   "Swirl Networks, Inc." },
    { 0xFEEB,   "Swirl Networks, Inc." },
    { 0xFEEC,   "Tile, Inc." },
    { 0xFEED,   "Tile, Inc." },
    { 0xFEEE,   "Polar Electro Oy" },
    { 0xFEEF,   "Polar Electro Oy" },
    { 0xFEF0,   "Intel" },
    { 0xFEF1,   "CSR" },
    { 0xFEF2,   "CSR" },
    { 0xFEF3,   "Google" },
    { 0xFEF4,   "Google" },
    { 0xFEF5,   "Dialog Semiconductor GmbH" },
    { 0xFEF6,   "Wicentric, Inc." },
    { 0xFEF7,   "Aplix Corporation" },
    { 0xFEF8,   "Aplix Corporation" },
    { 0xFEF9,   "PayPal, Inc." },
    { 0xFEFA,   "PayPal, Inc." },
    { 0xFEFB,   "Telit Wireless Solutions (Formerly Stollmann E+V GmbH)" },
    { 0xFEFC,   "Gimbal, Inc." },
    { 0xFEFD,   "Gimbal, Inc." },
    { 0xFEFE,   "GN ReSound A/S" },
    { 0xFEFF,   "GN Netcom" },


    /* SDO Uuids - https://www.bluetooth.org/en-us/specification/assigned-numbers/sdo-16-bit-uuids */
    { 0xFFFD,   "Fast IDentity Online Alliance - Universal Second Factor Authenticator Service" },
    { 0xFFFE,   "Alliance for Wireless Power - Wireless Power Transfer Service" },
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
    {0x0011, "Widcomm, Inc"},
    {0x0012, "Zeevo, Inc."},
    {0x0013, "Atmel Corporation"},
    {0x0014, "Mitsubishi Electric Corporation"},
    {0x0015, "RTX Telecom A/S"},
    {0x0016, "KC Technology Inc."},
    {0x0017, "NewLogic"},
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
    {0x0025, "NXP Semiconductors (formerly Philips Semiconductors)"},
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
    {0x0031, "Synopsis"},
    {0x0032, "Red-M (Communications) Ltd"},
    {0x0033, "Commil Ltd"},
    {0x0034, "Computer Access Technology Corporation (CATC)"},
    {0x0035, "Eclipse (HQ Espana) S.L."},
    {0x0036, "Renesas Electronics Corporation"},
    {0x0037, "Mobilian Corporation"},
    {0x0038, "Terax"},
    {0x0039, "Integrated System Solution Corp."},
    {0x003A, "Matsushita Electric Industrial Co., Ltd."},
    {0x003B, "Gennum Corporation"},
    {0x003C, "BlackBerry Limited (formerly Research In Motion)"},
    {0x003D, "IPextreme, Inc."},
    {0x003E, "Systems and Chips, Inc."},
    {0x003F, "Bluetooth SIG, Inc."},
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
    {0x0050, "SiRF Technology"},
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
    {0x007D, "Seers Technology Co. Ltd"},
    {0x007E, "Sports Tracking Technologies Ltd."},
    {0x007F, "Autonet Mobile"},
    {0x0080, "DeLorme Publishing Company, Inc."},
    {0x0081, "WuXi Vimicro"},
    {0x0082, "Sennheiser Communications A/S"},
    {0x0083, "TimeKeeping Systems, Inc."},
    {0x0084, "Ludus Helsinki Ltd."},
    {0x0085, "BlueRadios, Inc."},
    {0x0086, "equinox AG"},
    {0x0087, "Garmin International, Inc."},
    {0x0088, "Ecotest"},
    {0x0089, "GN ReSound A/S"},
    {0x008A, "Jawbone"},
    {0x008B, "Topcorn Positioning Systems, LLC"},
    {0x008C, "Gimbal Inc. (formerly Qualcomm Labs, Inc. and Qualcomm Retail Solutions, Inc.)"},
    {0x008D, "Zscan Software"},
    {0x008E, "Quintic Corp."},
    {0x008F, "Telit Wireless Solutions GmbH (Formerly Stollman E+V GmbH)"},
    {0x0090, "Funai Electric Co., Ltd."},
    {0x0091, "Advanced PANMOBIL Systems GmbH & Co. KG"},
    {0x0092, "ThinkOptics, Inc."},
    {0x0093, "Universal Electronics, Inc."},
    {0x0094, "Airoha Technology Corp."},
    {0x0095, "NEC Lighting, Ltd."},
    {0x0096, "ODM Technology, Inc."},
    {0x0097, "ConnecteDevice Ltd."},
    {0x0098, "zer01.tv GmbH"},
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
    {0x00A9, "Magneti Marelli S.p.A"},
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
    {0x00BC, "Ace Sensor Inc"},
    {0x00BD, "Aplix Corporation"},
    {0x00BE, "AAMP of America"},
    {0x00BF, "Stalmart Technology Limited"},
    {0x00C0, "AMICCOM Electronics Corporation"},
    {0x00C1, "Shenzhen Excelsecu Data Technology Co.,Ltd"},
    {0x00C2, "Geneq Inc."},
    {0x00C3, "adidas AG"},
    {0x00C4, "LG Electronics"},
    {0x00C5, "Onset Computer Corporation"},
    {0x00C6, "Selfly BV"},
    {0x00C7, "Quuppa Oy."},
    {0x00C8, "GeLo Inc"},
    {0x00C9, "Evluma"},
    {0x00CA, "MC10"},
    {0x00CB, "Binauric SE"},
    {0x00CC, "Beats Electronics"},
    {0x00CD, "Microchip Technology Inc."},
    {0x00CE, "Elgato Systems GmbH"},
    {0x00CF, "ARCHOS SA"},
    {0x00D0, "Dexcom, Inc."},
    {0x00D1, "Polar Electro Europe B.V."},
    {0x00D2, "Dialog Semiconductor B.V."},
    {0x00D3, "Taixingbang Technology (HK) Co,. LTD."},
    {0x00D4, "Kawantech"},
    {0x00D5, "Austco Communication Systems"},
    {0x00D6, "Timex Group USA, Inc."},
    {0x00D7, "Qualcomm Technologies, Inc."},
    {0x00D8, "Qualcomm Connected Experiences, Inc."},
    {0x00D9, "Voyetra Turtle Beach"},
    {0x00DA, "txtr GmbH"},
    {0x00DB, "Biosentronics"},
    {0x00DC, "Procter & Gamble"},
    {0x00DD, "Hosiden Corporation"},
    {0x00DE, "Muzik LLC"},
    {0x00DF, "Misfit Wearables Corp"},
    {0x00E0, "Google"},
    {0x00E1, "Danlers Ltd"},
    {0x00E2, "Semilink Inc"},
    {0x00E3, "inMusic Brands, Inc"},
    {0x00E4, "L.S. Research Inc."},
    {0x00E5, "Eden Software Consultants Ltd."},
    {0x00E6, "Freshtemp"},
    {0x00E7, "KS Technologies"},
    {0x00E8, "ACTS Technologies"},
    {0x00E9, "Vtrack Systems"},
    {0x00EA, "Nielsen-Kellerman Company"},
    {0x00EB, "Server Technology, Inc."},
    {0x00EC, "BioResearch Associates"},
    {0x00ED, "Jolly Logic, LLC"},
    {0x00EE, "Above Average Outcomes, Inc."},
    {0x00EF, "Bitsplitters GmbH"},
    {0x00F0, "PayPal, Inc."},
    {0x00F1, "Witron Technology Limited"},
    {0x00F2, "Aether Things Inc. (formerly Morse Project Inc.)"},
    {0x00F3, "Kent Displays Inc."},
    {0x00F4, "Nautilus Inc."},
    {0x00F5, "Smartifier Oy"},
    {0x00F6, "Elcometer Limited"},
    {0x00F7, "VSN Technologies Inc."},
    {0x00F8, "AceUni Corp., Ltd."},
    {0x00F9, "StickNFind"},
    {0x00FA, "Crystal Code AB"},
    {0x00FB, "KOUKAAM a.s."},
    {0x00FC, "Delphi Corporation"},
    {0x00FD, "ValenceTech Limited"},
    {0x00FE, "Reserved"},
    {0x00FF, "Typo Products, LLC"},
    {0x0100, "TomTom International BV"},
    {0x0101, "Fugoo, Inc"},
    {0x0102, "Keiser Corporation"},
    {0x0103, "Bang & Olufsen A/S"},
    {0x0104, "PLUS Locations Systems Pty Ltd"},
    {0x0105, "Ubiquitous Computing Technology Corporation"},
    {0x0106, "Innovative Yachtter Solutions"},
    {0x0107, "William Demant Holding A/S"},
    {0x0108, "Chicony Electronics Co., Ltd."},
    {0x0109, "Atus BV"},
    {0x010A, "Codegate Ltd."},
    {0x010B, "ERi, Inc."},
    {0x010C, "Transducers Direct, LLC"},
    {0x010D, "Fujitsu Ten Limited"},
    {0x010E, "Audi AG"},
    {0x010F, "HiSilicon Technologies Co., Ltd."},
    {0x0110, "Nippon Seiki Co., Ltd."},
    {0x0111, "Steelseries ApS"},
    {0x0112, "Visybl Inc."},
    {0x0113, "Openbrain Technologies, Co., Ltd."},
    {0x0114, "Xensr"},
    {0x0115, "e.solutions"},
    {0x0116, "1OAK Technologies"},
    {0x0117, "Wimoto Technologies Inc"},
    {0x0118, "Radius Networks, Inc."},
    {0x0119, "Wize Technology Co., Ltd."},
    {0x011A, "Qualcomm Labs, Inc."},
    {0x011B, "Aruba Networks"},
    {0x011C, "Baidu"},
    {0x011D, "Arendi AG"},
    {0x011E, "Skoda Auto a.s."},
    {0x011F, "Volkswagon AG"},
    {0x0120, "Porsche AG"},
    {0x0121, "Sino Wealth Electronic Ltd."},
    {0x0122, "AirTurn, Inc."},
    {0x0123, "Kinsa, Inc."},
    {0x0124, "HID Global"},
    {0x0125, "SEAT es"},
    {0x0126, "Promethean Ltd."},
    {0x0127, "Salutica Allied Solutions"},
    {0x0128, "GPSI Group Pty Ltd"},
    {0x0129, "Nimble Devices Oy"},
    {0x012A, "Changzhou Yongse Infotech Co., Ltd"},
    {0x012B, "SportIQ"},
    {0x012C, "TEMEC Instruments B.V."},
    {0x012D, "Sony Corporation"},
    {0x012E, "ASSA ABLOY"},
    {0x012F, "Clarion Co., Ltd."},
    {0x0130, "Warehouse Innovations"},
    {0x0131, "Cypress Semiconductor Corporation"},
    {0x0132, "MADS Inc"},
    {0x0133, "Blue Maestro Limited"},
    {0x0134, "Resolution Products, Inc."},
    {0x0135, "Airewear LLC"},
    {0x0136, "Seed Labs, Inc. (formerly ETC sp. z.o.o.)"},
    {0x0137, "Prestigio Plaza Ltd."},
    {0x0138, "NTEO Inc."},
    {0x0139, "Focus Systems Corporation"},
    {0x013A, "Tencent Holdings Limited"},
    {0x013B, "Allegion"},
    {0x013C, "Murata Manufacuring Co., Ltd."},
    {0x013E, "Nod, Inc."},
    {0x013F, "B&B Manufacturing Company"},
    {0x0140, "Alpine Electronics (China) Co., Ltd"},
    {0x0141, "FedEx Services"},
    {0x0142, "Grape Systems Inc."},
    {0x0143, "Bkon Connect"},
    {0x0144, "Lintech GmbH"},
    {0x0145, "Novatel Wireless"},
    {0x0146, "Ciright"},
    {0x0147, "Mighty Cast, Inc."},
    {0x0148, "Ambimat Electronics"},
    {0x0149, "Perytons Ltd."},
    {0x014A, "Tivoli Audio, LLC"},
    {0x014B, "Master Lock"},
    {0x014C, "Mesh-Net Ltd"},
    {0x014D, "Huizhou Desay SV Automotive CO., LTD."},
    {0x014E, "Tangerine, Inc."},
    {0x014F, "B&W Group Ltd."},
    {0x0150, "Pioneer Corporation"},
    {0x0151, "OnBeep"},
    {0x0152, "Vernier Software & Technology"},
    {0x0153, "ROL Ergo"},
    {0x0154, "Pebble Technology"},
    {0x0155, "NETATMO"},
    {0x0156, "Accumulate AB"},
    {0x0157, "Anhui Huami Information Technology Co., Ltd."},
    {0x0158, "Inmite s.r.o."},
    {0x0159, "ChefSteps, Inc."},
    {0x015A, "micas AG"},
    {0x015B, "Biomedical Research Ltd."},
    {0x015C, "Pitius Tec S.L."},
    {0x015D, "Estimote, Inc."},
    {0x015E, "Unikey Technologies, Inc."},
    {0x015F, "Timer Cap Co."},
    {0x0160, "AwoX"},
    {0x0161, "yikes"},
    {0x0162, "MADSGlobal NZ Ltd."},
    {0x0163, "PCH International"},
    {0x0164, "Qingdao Yeelink Information Technology Co., Ltd."},
    {0x0165, "Milwaukee Tool (formerly Milwaukee Electric Tools)"},
    {0x0166, "MISHIK Pte Ltd"},
    {0x0167, "Bayer HealthCare"},
    {0x0168, "Spicebox LLC"},
    {0x0169, "emberlight"},
    {0x016A, "Cooper-Atkins Corporation"},
    {0x016B, "Qblinks"},
    {0x016C, "MYSPHERA"},
    {0x016D, "LifeScan Inc"},
    {0x016E, "Volantic AB"},
    {0x016F, "Podo Labs, Inc"},
    {0x0170, "F. Hoffmann-La Roche AG"},
    {0x0171, "Amazon Fulfillment Service"},
    {0x0172, "Connovate Technology Private Limited"},
    {0x0173, "Kocomojo, LLC"},
    {0x0174, "Everykey LLC"},
    {0x0175, "Dynamic Controls"},
    {0x0176, "SentriLock"},
    {0x0177, "I-SYST inc."},
    {0x0178, "CASIO COMPUTER CO., LTD."},
    {0x0179, "LAPIS Semiconductor Co., Ltd."},
    {0x017A, "Telemonitor, Inc."},
    {0x017B, "taskit GmbH"},
    {0x017C, "Daimler AG"},
    {0x017D, "BatAndCat"},
    {0x017E, "BluDotz Ltd"},
    {0x017F, "XTel ApS"},
    {0x0180, "Gigaset Communications GmbH"},
    {0x0181, "Gecko Health Innovations, Inc."},
    {0x0182, "HOP Ubiquitous"},
    {0x0183, "To Be Assigned"},
    {0x0184, "Nectar"},
    {0x0185, "bel'apps LLC"},
    {0x0186, "CORE Lighting Ltd"},
    {0x0187, "Seraphim Sense Ltd"},
    {0x0188, "Unico RBC"},
    {0x0189, "Physical Enterprises Inc."},
    {0x018A, "Able Trend Technology Limited"},
    {0x018B, "Konica Minolta, Inc."},
    {0x018C, "Wilo SE"},
    {0x018D, "Extron Design Services"},
    {0x018E, "Fitbit, Inc."},
    {0x018F, "Fireflies Systems"},
    {0x0190, "Intelletto Technologies Inc."},
    {0x0191, "FDK CORPORATION"},
    {0x0192, "Cloudleaf, Inc"},
    {0x0193, "Maveric Automation LLC"},
    {0x0194, "Acoustic Stream Corporation"},
    {0x0195, "Zuli"},
    {0x0196, "Paxton Access Ltd"},
    {0x0197, "WiSilica Inc"},
    {0x0198, "Vengit Limited"},
    {0x0199, "SALTO SYSTEMS S.L."},
    {0x019A, "TRON Forum (formerly T-Engine Forum)"},
    {0x019B, "CUBETECH s.r.o."},
    {0x019C, "Cokiya Incorporated"},
    {0x019D, "CVS Health"},
    {0x019E, "Ceruus"},
    {0x019F, "Strainstall Ltd"},
    {0x01A0, "Channel Enterprises (HK) Ltd."},
    {0x01A1, "FIAMM"},
    {0x01A2, "GIGALANE.CO.,LTD"},
    {0x01A3, "EROAD"},
    {0x01A4, "Mine Safety Appliances"},
    {0x01A5, "Icon Health and Fitness"},
    {0x01A6, "Asandoo GmbH"},
    {0x01A7, "ENERGOUS CORPORATION"},
    {0x01A8, "Taobao"},
    {0x01A9, "Canon Inc."},
    {0x01AA, "Geophysical Technology Inc."},
    {0x01AB, "Facebook, Inc."},
    {0x01AC, "Nipro Diagnostics, Inc."},
    {0x01AD, "FlightSafety International"},
    {0x01AE, "Earlens Corporation"},
    {0x01AF, "Sunrise Micro Devices, Inc."},
    {0x01B0, "Star Micronics Co., Ltd."},
    {0x01B1, "Netizens Sp. z o.o."},
    {0x01B2, "Nymi Inc."},
    {0x01B3, "Nytec, Inc."},
    {0x01B4, "Trineo Sp. z o.o."},
    {0x01B5, "Nest Labs Inc."},
    {0x01B6, "LM Technologies Ltd"},
    {0x01B7, "General Electric Company"},
    {0x01B8, "i+D3 S.L."},
    {0x01B9, "HANA Micron"},
    {0x01BA, "Stages Cycling LLC"},
    {0x01BB, "Cochlear Bone Anchored Solutions AB"},
    {0x01BC, "SenionLab AB"},
    {0x01BD, "Syszone Co., Ltd"},
    {0x01BE, "Pulsate Mobile Ltd."},
    {0x01BF, "Hong Kong HunterSun Electronic Limited"},
    {0x01C0, "pironex GmbH"},
    {0x01C1, "BRADATECH Corp."},
    {0x01C2, "Transenergooil AG"},
    {0x01C3, "Bunch"},
    {0x01C4, "DME Microelectronics"},
    {0x01C5, "Bitcraze AB"},
    {0x01C6, "HASWARE Inc."},
    {0x01C7, "Abiogenix Inc."},
    {0x01C8, "Poly-Control ApS"},
    {0x01C9, "Avi-on"},
    {0x01CA, "Laerdal Medical AS"},
    {0x01CB, "Fetch My Pet"},
    {0x01CC, "Sam Labs Ltd."},
    {0x01CD, "Chengdu Synwing Technology Ltd"},
    {0x01CE, "HOUWA SYSTEM DESIGN, k.k."},
    {0x01CF, "BSH"},
    {0x01D0, "Primus Inter Pares Ltd"},
    {0x01D1, "August"},
    {0x01D2, "Gill Electronics"},
    {0x01D3, "Sky Wave Design"},
    {0x01D4, "Newlab S.r.l."},
    {0x01D5, "ELAD srl"},
    {0x01D6, "G-wearables inc."},
    {0x01D7, "Squadrone Systems Inc."},
    {0x01D8, "Code Corporation"},
    {0x01D9, "Savant Systems LLC"},
    {0x01DA, "Logitech International SA"},
    {0x01DB, "Innblue Consulting"},
    {0x01DC, "iParking Ltd."},
    {0x01DD, "Koninklijke Philips Electronics N.V."},
    {0x01DE, "Minelab Electronics Pty Limited"},
    {0x01DF, "Bison Group Ltd."},
    {0x01E0, "Widex A/S"},
    {0x01E1, "Jolla Ltd"},
    {0x01E2, "Lectronix, Inc."},
    {0x01E3, "Caterpillar Inc"},
    {0x01E4, "Freedom Innovations"},
    {0x01E5, "Dynamic Devices Ltd"},
    {0x01E6, "Technology Solutions (UK) Ltd"},
    {0x01E7, "IPS Group Inc."},
    {0x01E8, "STIR"},
    {0x01E9, "Sano, Inc"},
    {0x01EA, "Advanced Application Design, Inc."},
    {0x01EB, "AutoMap LLC"},
    {0x01EC, "Spreadtrum Communications Shanghai Ltd"},
    {0x01ED, "CuteCircuit LTD"},
    {0x01EE, "Valeo Service"},
    {0x01EF, "Fullpower Technologies, Inc."},
    {0x01F0, "KloudNation"},
    {0x01F1, "Zebra Technologies Corporation"},
    {0x01F2, "Itron, Inc."},
    {0x01F3, "The University of Tokyo"},
    {0x01F4, "UTC Fire and Security"},
    {0x01F5, "Cool Webthings Limited"},
    {0x01F6, "DJO Global"},
    {0x01F7, "Gelliner Limited"},
    {0x01F8, "Anyka (Guangzhou) Microelectronics Technology Co, LTD"},
    {0x01F9, "Medtronic, Inc."},
    {0x01FA, "Gozio, Inc."},
    {0x01FB, "Form Lifting, LLC"},
    {0x01FC, "Wahoo Fitness, LLC"},
    {0x01FD, "Kontakt Micro-Location Sp. z o.o."},
    {0x01FE, "Radio System Corporation"},
    {0x01FF, "Freescale Semiconductor, Inc."},
    {0x0200, "Verifone Systems PTe Ltd. Taiwan Branch"},
    {0x0201, "AR Timing"},
    {0x0202, "Rigado LLC"},
    {0x0203, "Kemppi Oy"},
    {0x0204, "Tapcentive Inc."},
    {0x0205, "Smartbotics Inc."},
    {0x0206, "Otter Products, LLC"},
    {0x0207, "STEMP Inc."},
    {0x0208, "LumiGeek LLC"},
    {0x0209, "InvisionHeart Inc."},
    {0x020A, "Macnica Inc. "},
    {0x020B, "Jaguar Land Rover Limited"},
    {0x020C, "CoroWare Technologies, Inc"},
    {0x020D, "Simplo Technology Co., LTD"},
    {0x020E, "Omron Healthcare Co., LTD"},
    {0x020F, "Comodule GMBH"},
    {0x0210, "ikeGPS"},
    {0x0211, "Telink Semiconductor Co. Ltd"},
    {0x0212, "Interplan Co., Ltd"},
    {0x0213, "Wyler AG"},
    {0x0214, "IK Multimedia Production srl"},
    {0x0215, "Lukoton Experience Oy"},
    {0x0216, "MTI Ltd"},
    {0x0217, "Tech4home, Lda"},
    {0x0218, "Hiotech AB"},
    {0x0219, "DOTT Limited"},
    {0x021A, "Blue Speck Labs, LLC"},
    {0x021B, "Cisco Systems Inc"},
    {0x021C, "Mobicomm Inc"},
    {0x021D, "Edamic"},
    {0x021E, "Goodnet Ltd"},
    {0x021F, "Luster Leaf Products Inc"},
    {0x0220, "Manus Machina BV"},
    {0x0221, "Mobiquity Networks Inc"},
    {0x0222, "Praxis Dynamics"},
    {0x0223, "Philip Morris Products S.A."},
    {0x0224, "Comarch SA"},
    {0x0225, "Nestle Nespresso S.A."},
    {0x0226, "Merlinia A/S"},
    {0x0227, "LifeBEAM Technologies"},
    {0x0228, "Twocanoes Labs, LLC"},
    {0x0229, "Muoverti Limited"},
    {0X022A, "Stamer Musikanlagen GMBH"},
    {0x022B, "Tesla Motors"},
    {0x022C, "Pharynks Corporation"},
    {0x022D, "Lupine"},
    {0x022E, "Siemens AG"},
    {0x022F, "Huami (Shanghai) Culture Communication CO., LTD"},
    {0x0230, "Foster Electric Company, Ltd"},
    {0x0231, "ETA SA"},
    {0x0232, "x-Senso Solutions Kft"},
    {0x0233, "Shenzhen SuLong Communication Ltd"},
    {0x0234, "FengFan (BeiJing) Technology Co, Ltd"},
    {0x0235, "Qrio Inc"},
    {0x0236, "Pitpatpet Ltd"},
    {0x0237, "MSHeli s.r.l."},
    {0x0238, "Trakm8 Ltd"},
    {0x0239, "JIN CO, Ltd"},
    {0x023A, "Alatech Technology"},
    {0x023B, "Beijing CarePulse Electronic Technology Co, Ltd"},
    {0x023C, "Awarepoint"},
    {0x023D, "ViCentra B.V."},
    {0x023E, "Raven Industries"},
    {0x023F, "WaveWare Technologies"},
    {0x0240, "Argenox Technologies"},
    {0x0241, "Bragi GmbH"},
    {0x0242, "16Lab Inc"},
    {0x0243, "Masimo Corp"},
    {0x0244, "Iotera Inc."},
    {0x0245, "Endress+Hauser"},
    {0x0246, "ACKme Networks, Inc."},
    {0x0247, "FiftyThree Inc."},
    {0x0248, "Parker Hannifin Corp"},
    {0x0249, "Transcranial Ltd"},
    {0x024A, "Uwatec AG"},
    {0x024B, "Orlan LLC"},
    {0x024C, "Blue Clover Devices"},
    {0x024D, "M-Way Solutions GmbH"},
    {0x024E, "Microtronics Engineering GmbH"},
    {0x024F, "Schneider Schreibgerate GmbH"},
    {0x0250, "Sapphire Circuits LLC"},
    {0x0251, "Lumo Bodytech Inc."},
    {0x0252, "UKC Technosolution"},
    {0x0253, "Xicato Inc."},
    {0x0254, "Playbrush"},
    {0x0255, "Dai Nippon Printing Co., Ltd."},
    {0x0256, "G24 Power Limited"},
    {0x0257, "AdBabble Local Commerce Inc."},
    {0x0258, "Devialet SA"},
    {0x0259, "ALTYOR"},
    {0x025A, "University of Applied Sciences Valais/Haute Ecole Valaisanne"},
    {0x025B, "Five Interactive, LLC dba Zendo"},
    {0x025C, "NetEase (Hangzhou) Network co.Ltd."},
    {0x025D, "Lexmark International Inc."},
    {0x025E, "Fluke Corporation"},
    {0x025F, "Yardarm Technologies"},
    {0x0260, "SensaRx"},
    {0x0261, "SECVRE GmbH"},
    {0x0262, "Glacial Ridge Technologies"},
    {0x0263, "Identiv, Inc."},
    {0x0264, "DDS, Inc."},
    {0x0265, "SMK Corporation"},
    {0x0266, "Schawbel Technologies LLC"},
    {0x0267, "XMI Systems SA"},
    {0x0268, "Cerevo"},
    {0x0269, "Torrox GmbH & Co KG"},
    {0x026A, "Gemalto"},
    {0x026B, "DEKA Research & Development Corp."},
    {0x026C, "Domster Tadeusz Szydlowski"},
    {0x026D, "Technogym SPA"},
    {0x026E, "FLEURBAEY BVBA"},
    {0x026F, "Aptcode Solutions"},
    {0x0270, "LSI ADL Technology"},
    {0x0271, "Animas Corp"},
    {0x0272, "Alps Electric Co., Ltd."},
    {0x0273, "OCEASOFT"},
    {0x0274, "Motsai Research"},
    {0x0275, "Geotab"},
    {0x0276, "E.G.O. Elektro-Geratebau GmbH"},
    {0x0277, "bewhere inc"},
    {0x0278, "Johnson Outdoors Inc"},
    {0x0279, "steute Schaltgerate GmbH & Co. KG"},
    {0x027A, "Ekomini inc."},
    {0x027B, "DEFA AS"},
    {0x027C, "Aseptika Ltd"},
    {0x027D, "HUAWEI Technologies Co., Ltd."},
    {0x027E, "HabitAware, LLC"},
    {0x027F, "ruwido austria gmbh"},
    {0x0280, "ITEC corporation"},
    {0x0281, "StoneL"},
    {0x0282, "Sonova AG"},
    {0x0283, "Maven Machines, Inc."},
    {0x0284, "Synapse Electronics"},
    {0x0285, "Standard Innovation Inc."},
    {0x0286, "RF Code, Inc."},
    {0x0287, "Wally Ventures S.L."},
    {0x0288, "Willowbank Electronics Ltd"},
    {0x0289, "SK Telecom"},
    {0x028A, "Jetro AS"},
    {0x028B, "Code Gears LTD"},
    {0x028C, "NANOLINK APS"},
    {0x028D, "IF, LLC"},
    {0x028E, "RF Digital Corp"},
    {0x028F, "Church & Dwight Co., Inc"},
    {0x0290, "Multibit Oy"},
    {0x0291, "CliniCloud Inc"},
    {0x0292, "SwiftSensors"},
    {0x0293, "Blue Bite"},
    {0x0294, "ELIAS GmbH"},
    {0x0295, "Sivantos GmbH"},
    {0x0296, "Petzl"},
    {0x0297, "storm power ltd"},
    {0x0298, "EISST Ltd"},
    {0x0299, "Inexess Technology Simma KG"},
    {0x029A, "Currant, Inc."},
    {0x029B, "C2 Development, Inc."},
    {0x029C, "Blue Sky Scientific, LLC"},
    {0x029D, "ALOTTAZS LABS, LLC"},
    {0x029E, "Kupson spol. s r.o."},
    {0x029F, "Areus Engineering GmbH"},
    {0x02A0, "Impossible Camera GmbH"},
    {0x02A1, "InventureTrack Systems"},
    {0x02A2, "LockedUp"},
    {0x02A3, "Itude"},
    {0x02A4, "Pacific Lock Company"},
    {0x02A5, "Tendyron Corporation"},
    {0x02A6, "Robert Bosch GmbH"},
    {0x02A7, "Illuxtron international B.V."},
    {0x02A8, "miSport Ltd."},
    {0x02A9, "Chargelib"},
    {0x02AA, "Doppler Lab"},
    {0x02AB, "BBPOS Limited"},
    {0x02AC, "RTB Elektronik GmbH & Co. KG"},
    {0x02AD, "Rx Networks, Inc."},
    {0x02AE, "WeatherFlow, Inc."},
    {0x02AF, "Technicolor USA Inc."},
    {0x02B0, "Bestechnic(Shanghai),Ltd"},
    {0x02B1, "Raden Inc"},
    {0x02B2, "JouZen Oy"},
    {0x02B3, "CLABER S.P.A."},
    {0x02B4, "Hyginex, Inc."},
    {0x02B5, "HANSHIN ELECTRIC RAILWAY CO.,LTD."},
    {0x02B6, "Schneider Electric"},
    {0x02B7, "Oort Technologies LLC"},
    {0x02B8, "Chrono Therapeutics"},
    {0x02B9, "Rinnai Corporation"},
    {0x02BA, "Swissprime Technologies AG"},
    {0x02BB, "Koha.,Co.Ltd"},
    {0x02BC, "Genevac Ltd"},
    {0x02BD, "Chemtronics"},
    {0x02BE, "Seguro Technology Sp. z o.o."},
    {0x02BF, "Redbird Flight Simulations"},
    {0x02C0, "Dash Robotics"},
    {0x02C1, "LINE Corporation"},
    {0x02C2, "Guillemot Corporation"},
    {0x02C3, "Techtronic Power Tools Technology Limited"},
    {0x02C4, "Wilson Sporting Goods"},
    {0x02C5, "Lenovo (Singapore) Pte Ltd."},
    {0x02C6, "Ayatan Sensors"},
    {0x02C7, "Electronics Tomorrow Limited"},
    {0x02C8, "VASCO Data Security International, Inc."},
    {0x02C9, "PayRange Inc."},
    {0x02CA, "ABOV Semiconductor"},
    {0x02CB, "AINA-Wireless Inc."},
    {0x02CC, "Eijkelkamp Soil & Water"},
    {0x02CD, "BMA ergonomics b.v."},
    {0x02CE, "Teva Branded Pharmaceutical Products R&D, Inc."},
    {0x02CF, "Anima"},
    {0x02D0, "3M"},
    {0x02D1, "Empatica Srl"},
    {0x02D2, "Afero, Inc."},
    {0x02D3, "Powercast Corporation"},
    {0x02D4, "Secuyou ApS"},
    {0x02D5, "OMRON Corporation"},
    {0x02D6, "Send Solutions"},
    {0x02D7, "NIPPON SYSTEMWARE CO.,LTD."},
    {0x02D8, "Neosfar"},
    {0x02D9, "Fliegl Agrartechnik GmbH"},
    {0x02DA, "Gilvader"},
    {0x02DB, "Digi International Inc (R)"},
    {0x02DC, "DeWalch Technologies, Inc."},
    {0x02DD, "Flint Rehabilitation Devices, LLC"},
    {0x02DE, "Samsung SDS Co., Ltd."},
    {0x02DF, "Blur Product Development"},
    {0x02E0, "University of Michigan"},
    {0x02E1, "Victron Energy BV"},
    {0x02E2, "NTT docomo"},
    {0x02E3, "Carmanah Technologies Corp."},
    {0x02E4, "Bytestorm Ltd."},
    {0x02E5, "Espressif Incorporated"},
    {0x02E6, "Unwire"},
    {0x02E7, "Connected Yard, Inc."},
    {0x02E8, "American Music Environments"},
    {0x02E9, "Sensogram Technologies, Inc."},
    {0x02EA, "Fujitsu Limited"},
    {0x02EB, "Ardic Technology"},
    {0x02EC, "Delta Systems, Inc"},
    {0x02ED, "HTC Corporation"},
    {0x02EE, "Citizen Holdings Co., Ltd."},
    {0x02EF, "SMART-INNOVATION.inc"},
    {0x02F0, "Blackrat Software"},
    {0x02F1, "The Idea Cave, LLC"},
    {0x02F2, "GoPro, Inc."},
    {0x02F3, "AuthAir, Inc"},
    {0x02F4, "Vensi, Inc."},
    {0x02F5, "Indagem Tech LLC"},
    {0x02F6, "Intemo Technologies"},
    {0x02F7, "DreamVisions co., Ltd."},
    {0x02F8, "Runteq Oy Ltd"},
    {0x02F9, "IMAGINATION TECHNOLOGIES LTD"},
    {0x02FA, "CoSTAR Technologies"},
    {0x02FB, "Clarius Mobile Health Corp."},
    {0x02FC, "Shanghai Frequen Microelectronics Co., Ltd."},
    {0x02FD, "Uwanna, Inc."},
    {0x02FE, "Lierda Science & Technology Group Co., Ltd."},
    {0x02FF, "Silicon Laboratories"},
    {0x0300, "World Moto Inc."},
    {0x0301, "Giatec Scientific Inc."},
    {0x0302, "Loop Devices, Inc"},
    {0x0303, "IACA electronique"},
    {0x0304, "Martians Inc"},
    {0x0305, "Swipp ApS"},
    {0x0306, "Life Laboratory Inc."},
    {0x0307, "FUJI INDUSTRIAL CO.,LTD."},
    {0x0308, "Surefire, LLC"},
    {0x0309, "Dolby Labs"},
    {0x030A, "Ellisys"},
    {0x030B, "Magnitude Lighting Converters"},
    {0x030C, "Hilti AG"},
    {0x030D, "Devdata S.r.l."},
    {0x030E, "Deviceworx"},
    {0x030F, "Shortcut Labs"},
    {0x0310, "SGL Italia S.r.l."},
    {0x0311, "PEEQ DATA"},
    {0x0312, "Ducere Technologies Pvt Ltd"},
    {0x0313, "DiveNav, Inc."},
    {0x0314, "RIIG AI Sp. z o.o."},
    {0x0315, "Thermo Fisher Scientific"},
    {0x0316, "AG Measurematics Pvt. Ltd."},
    {0x0317, "CHUO Electronics CO., LTD."},
    {0x0318, "Aspenta International"},
    {0x0319, "Eugster Frismag AG"},
    {0x031A, "Amber wireless GmbH"},
    {0x031B, "HQ Inc"},
    {0x031C, "Lab Sensor Solutions"},
    {0x031D, "Enterlab ApS"},
    {0x031E, "Eyefi, Inc."},
    {0x031F, "MetaSystem S.p.A"},
    {0x0320, "SONO ELECTRONICS. CO., LTD"},
    {0x0321, "Jewelbots"},
    {0x0322, "Compumedics Limited"},
    {0x0323, "Rotor Bike Components"},
    {0x0324, "Astro, Inc."},
    {0x0325, "Amotus Solutions"},
    {0x0326, "Healthwear Technologies (Changzhou)Ltd"},
    {0x0327, "Essex Electronics"},
    {0x0328, "Grundfos A/S"},
    {0x0329, "Eargo, Inc."},
    {0x032A, "Electronic Design Lab"},
    {0x032B, "ESYLUX"},
    {0x032C, "NIPPON SMT.CO.,Ltd"},
    {0x032D, "BM innovations GmbH"},
    {0x032E, "indoormap"},
    {0x032F, "OttoQ Inc"},
    {0x0330, "North Pole Engineering"},
    {0x0331, "3flares Technologies Inc."},
    {0x0332, "Electrocompaniet A.S."},
    {0x0333, "Mul-T-Lock"},
    {0x0334, "Corentium AS"},
    {0x0335, "Enlighted Inc"},
    {0x0336, "GISTIC"},
    {0x0337, "AJP2 Holdings, LLC"},
    {0x0338, "COBI GmbH"},
    {0x0339, "Blue Sky Scientific, LLC"},
    {0x033A, "Appception, Inc."},
    {0x033B, "Courtney Thorne Limited"},
    {0x033C, "Virtuosys"},
    {0x033D, "TPV Technology Limited"},
    {0x033E, "Monitra SA"},
    {0x033F, "Automation Components, Inc."},
    {0x0340, "Letsense s.r.l."},
    {0x0341, "Etesian Technologies LLC"},
    {0x0342, "GERTEC BRASIL LTDA."},
    {0x0343, "Drekker Development Pty. Ltd."},
    {0x0344, "Whirl Inc"},
    {0x0345, "Locus Positioning"},
    {0x0346, "Acuity Brands Lighting, Inc"},
    {0x0347, "Prevent Biometrics"},
    {0x0348, "Arioneo"},
    {0x0349, "VersaMe"},
    {0x034A, "Vaddio"},
    {0x034B, "Libratone A/S"},
    {0x034C, "HM Electronics, Inc."},
    {0x034D, "TASER International, Inc."},
    {0x034E, "Safe Trust Inc."},
    {0x034F, "Heartland Payment Systems"},
    {0x0350, "Bitstrata Systems Inc."},
    {0x0351, "Pieps GmbH"},
    {0x0352, "iRiding(Xiamen)Technology Co.,Ltd."},
    {0x0353, "Alpha Audiotronics, Inc."},
    {0x0354, "TOPPAN FORMS CO.,LTD."},
    {0x0355, "Sigma Designs, Inc."},
    {0x0356, "Spectrum Brands, Inc."},
    {0x0357, "Polymap Wireless"},
    {0x0358, "MagniWare Ltd."},
    {0x0359, "Novotec Medical GmbH"},
    {0x035A, "Medicom Innovation Partner a/s"},
    {0x035B, "Matrix Inc."},
    {0x035C, "Eaton Corporation"},
    {0x035D, "KYS"},
    {0x035E, "Naya Health, Inc."},
    {0x035F, "Acromag"},
    {0x0360, "Insulet Corporation"},
    {0x0361, "Wellinks Inc."},
    {0x0362, "ON Semiconductor"},
    {0x0363, "FREELAP SA"},
    {0x0364, "Favero Electronics Srl"},
    {0x0365, "BioMech Sensor LLC"},
    {0x0366, "BOLTT Sports technologies Private limited"},
    {0x0367, "Saphe International"},
    {0x0368, "Metormote AB"},
    {0x0369, "littleBits"},
    {0x036A, "SetPoint Medical"},
    {0x036B, "BRControls Products BV"},
    {0x036C, "Zipcar"},
    {0x036D, "AirBolt Pty Ltd"},
    {0x036E, "KeepTruckin Inc"},
    {0xFFFF, "For use in internal and interoperability tests."},
    {0, NULL }
};
value_string_ext bluetooth_company_id_vals_ext = VALUE_STRING_EXT_INIT(bluetooth_company_id_vals);

const value_string bluetooth_address_type_vals[] = {
    { 0x00,  "Public" },
    { 0x01,  "Random" },
    { 0, NULL }
};

/*
 * BLUETOOTH SPECIFICATION Version 4.0 [Vol 5] defines that
 * before transmission, the PAL shall remove the HCI header,
 * add LLC and SNAP headers and insert an 802.11 MAC header.
 * Protocol identifier are described in Table 5.2.
 */

#define AMP_U_L2CAP		0x0001
#define AMP_C_ACTIVITY_REPORT	0x0002
#define AMP_C_SECURITY_FRAME	0x0003
#define AMP_C_LINK_SUP_REQUEST	0x0004
#define AMP_C_LINK_SUP_REPLY	0x0005

static const value_string bluetooth_pid_vals[] = {
	{ AMP_U_L2CAP,			"AMP_U L2CAP ACL data" },
	{ AMP_C_ACTIVITY_REPORT,	"AMP-C Activity Report" },
	{ AMP_C_SECURITY_FRAME,		"AMP-C Security frames" },
	{ AMP_C_LINK_SUP_REQUEST,	"AMP-C Link supervision request" },
	{ AMP_C_LINK_SUP_REPLY,		"AMP-C Link supervision reply" },
	{ 0,	NULL }
};

guint32 max_disconnect_in_frame = G_MAXUINT32;


void proto_register_bluetooth(void);
void proto_reg_handoff_bluetooth(void);

static void bluetooth_uuid_prompt(packet_info *pinfo, gchar* result)
{
    gchar *value_data;

    value_data = (gchar *) p_get_proto_data(pinfo->pool, pinfo, proto_bluetooth, PROTO_DATA_BLUETOOTH_SERVICE_UUID);
    if (value_data)
        g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "BT Service UUID %s as", (gchar *) value_data);
    else
        g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Unknown BT Service UUID");
}

static gpointer bluetooth_uuid_value(packet_info *pinfo)
{
    gchar *value_data;

    value_data = (gchar *) p_get_proto_data(pinfo->pool, pinfo, proto_bluetooth, PROTO_DATA_BLUETOOTH_SERVICE_UUID);

    if (value_data)
        return (gpointer) value_data;

    return NULL;
}

gint
dissect_bd_addr(gint hf_bd_addr, packet_info *pinfo, proto_tree *tree,
        tvbuff_t *tvb, gint offset, gboolean is_local_bd_addr,
        guint32 interface_id, guint32 adapter_id, guint8 *bdaddr)
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

    if (have_tap_listener(bluetooth_device_tap)) {
        bluetooth_device_tap_t  *tap_device;

        tap_device = wmem_new(wmem_packet_scope(), bluetooth_device_tap_t);
        tap_device->interface_id = interface_id;
        tap_device->adapter_id   = adapter_id;
        memcpy(tap_device->bd_addr, bd_addr, 6);
        tap_device->has_bd_addr = TRUE;
        tap_device->is_local = is_local_bd_addr;
        tap_device->type = BLUETOOTH_DEVICE_BD_ADDR;
        tap_queue_packet(bluetooth_device_tap, pinfo, tap_device);
    }

    if (bdaddr)
        memcpy(bdaddr, bd_addr, 6);

    return offset;
}


void
save_local_device_name_from_eir_ad(tvbuff_t *tvb, gint offset, packet_info *pinfo,
        guint8 size, bluetooth_data_t *bluetooth_data)
{
    gint                    i = 0;
    guint8                  length;
    wmem_tree_key_t         key[4];
    guint32                 k_interface_id;
    guint32                 k_adapter_id;
    guint32                 k_frame_number;
    gchar                   *name;
    localhost_name_entry_t  *localhost_name_entry;

    if (!(!pinfo->fd->flags.visited && bluetooth_data)) return;

    while (i < size) {
        length = tvb_get_guint8(tvb, offset + i);
        if (length == 0) break;

        switch(tvb_get_guint8(tvb, offset + i + 1)) {
        case 0x08: /* Device Name, shortened */
        case 0x09: /* Device Name, full */
            name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset + i + 2, length - 1, ENC_ASCII);

            k_interface_id = bluetooth_data->interface_id;
            k_adapter_id = bluetooth_data->adapter_id;
            k_frame_number = pinfo->num;

            key[0].length = 1;
            key[0].key    = &k_interface_id;
            key[1].length = 1;
            key[1].key    = &k_adapter_id;
            key[2].length = 1;
            key[2].key    = &k_frame_number;
            key[3].length = 0;
            key[3].key    = NULL;

            localhost_name_entry = (localhost_name_entry_t *) wmem_new(wmem_file_scope(), localhost_name_entry_t);
            localhost_name_entry->interface_id = k_interface_id;
            localhost_name_entry->adapter_id = k_adapter_id;
            localhost_name_entry->name = wmem_strdup(wmem_file_scope(), name);

            wmem_tree_insert32_array(bluetooth_data->localhost_name, key, localhost_name_entry);

            break;
        }

        i += length + 1;
    }
}


static const char* bluetooth_conv_get_filter_type(conv_item_t* conv, conv_filter_type_e filter)
{
    if (filter == CONV_FT_SRC_ADDRESS) {
        if (conv->src_address.type == AT_ETHER)
            return "bluetooth.src";
        else if (conv->src_address.type == AT_STRINGZ)
            return "bluetooth.src_str";
    }

    if (filter == CONV_FT_DST_ADDRESS) {
        if (conv->dst_address.type == AT_ETHER)
            return "bluetooth.dst";
        else if (conv->dst_address.type == AT_STRINGZ)
            return "bluetooth.dst_str";
    }

    if (filter == CONV_FT_ANY_ADDRESS) {
        if (conv->src_address.type == AT_ETHER && conv->dst_address.type == AT_ETHER)
            return "bluetooth.addr";
        else if (conv->src_address.type == AT_STRINGZ && conv->dst_address.type == AT_STRINGZ)
            return "bluetooth.addr_str";
    }

    return CONV_FILTER_INVALID;
}

static ct_dissector_info_t bluetooth_ct_dissector_info = {&bluetooth_conv_get_filter_type};


static const char* bluetooth_get_filter_type(hostlist_talker_t* host, conv_filter_type_e filter)
{
    if (filter == CONV_FT_ANY_ADDRESS) {
        if (host->myaddress.type == AT_ETHER)
            return "bluetooth.addr";
        else if (host->myaddress.type == AT_STRINGZ)
            return "bluetooth.addr_str";
    }

    return CONV_FILTER_INVALID;
}

static hostlist_dissector_info_t  bluetooth_dissector_info = {&bluetooth_get_filter_type};


static int
bluetooth_conversation_packet(void *pct, packet_info *pinfo,
        epan_dissect_t *edt _U_, const void *vip _U_)
{
    conv_hash_t *hash = (conv_hash_t*) pct;
    add_conversation_table_data(hash, &pinfo->dl_src, &pinfo->dl_dst, 0, 0, 1,
            pinfo->fd->pkt_len, &pinfo->rel_ts, &pinfo->abs_ts,
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

    conversation = find_conversation(pinfo->num,
                               src_addr, dst_addr,
                               pinfo->ptype,
                               src_endpoint, dst_endpoint, 0);
    if (conversation) {
        return conversation;
    }

    conversation = conversation_new(pinfo->num,
                           src_addr, dst_addr,
                           pinfo->ptype,
                           src_endpoint, dst_endpoint, 0);
    return conversation;
}

bluetooth_uuid_t
get_uuid(tvbuff_t *tvb, gint offset, gint size)
{
    bluetooth_uuid_t  uuid;

    memset(&uuid, 0, sizeof(uuid));

    if (size != 2 && size != 16) {
        return uuid;
    }

    uuid.size = size;
    if (size == 2) {
        uuid.data[0] = tvb_get_guint8(tvb, offset + 1);
        uuid.data[1] = tvb_get_guint8(tvb, offset);
    } else if (size == 16) {
        uuid.data[0] = tvb_get_guint8(tvb, offset + 15);
        uuid.data[1] = tvb_get_guint8(tvb, offset + 14);
        uuid.data[2] = tvb_get_guint8(tvb, offset + 13);
        uuid.data[3] = tvb_get_guint8(tvb, offset + 12);
        uuid.data[4] = tvb_get_guint8(tvb, offset + 11);
        uuid.data[5] = tvb_get_guint8(tvb, offset + 10);
        uuid.data[6] = tvb_get_guint8(tvb, offset + 9);
        uuid.data[7] = tvb_get_guint8(tvb, offset + 8);
        uuid.data[8] = tvb_get_guint8(tvb, offset + 7);
        uuid.data[9] = tvb_get_guint8(tvb, offset + 6);
        uuid.data[10] = tvb_get_guint8(tvb, offset + 5);
        uuid.data[11] = tvb_get_guint8(tvb, offset + 4);
        uuid.data[12] = tvb_get_guint8(tvb, offset + 3);
        uuid.data[13] = tvb_get_guint8(tvb, offset + 2);
        uuid.data[14] = tvb_get_guint8(tvb, offset + 1);
        uuid.data[15] = tvb_get_guint8(tvb, offset);
    }

    if (size == 2) {
        uuid.bt_uuid = uuid.data[1] | uuid.data[0] << 8;
    } else {
        if (uuid.data[0] == 0x00 && uuid.data[1] == 0x00 &&
                uuid.data[4]  == 0x00 && uuid.data[5]  == 0x00 && uuid.data[6]  == 0x10 &&
                uuid.data[7]  == 0x00 && uuid.data[8]  == 0x80 && uuid.data[9]  == 0x00 &&
                uuid.data[10] == 0x00 && uuid.data[11] == 0x80 && uuid.data[12] == 0x5F &&
                uuid.data[13] == 0x9B && uuid.data[14] == 0x34 && uuid.data[15] == 0xFB)
        uuid.bt_uuid = uuid.data[2] | uuid.data[3] << 8;
    }

    return uuid;
}

const gchar *
print_numeric_uuid(bluetooth_uuid_t *uuid)
{
    if (!(uuid && uuid->size > 0))
        return NULL;

    if (uuid->size != 16) {
        return bytes_to_str(wmem_packet_scope(), uuid->data, uuid->size);
    } else {
        gchar *text;

        text = (gchar *) wmem_alloc(wmem_packet_scope(), 38);
        bytes_to_hexstr(&text[0], uuid->data, 4);
        text[8] = '-';
        bytes_to_hexstr(&text[9], uuid->data + 4, 2);
        text[13] = '-';
        bytes_to_hexstr(&text[14], uuid->data + 4 + 2 * 1, 2);
        text[18] = '-';
        bytes_to_hexstr(&text[19], uuid->data + 4 + 2 * 2, 2);
        text[23] = '-';
        bytes_to_hexstr(&text[24], uuid->data + 4 + 2 * 3, 6);
        text[36] = '\0';

        return text;
    }

    return NULL;
}

const gchar *
print_uuid(bluetooth_uuid_t *uuid)
{
    const gchar *description;

    if (uuid->bt_uuid) {
        const gchar *name;

        /*
         * Known UUID?
         */
        name = try_val_to_str_ext(uuid->bt_uuid, &bluetooth_uuid_vals_ext);
        if (name != NULL) {
            /*
             * Yes.  This string is part of the value_string_ext table,
             * so we don't have to make a copy.
             */
            return name;
        }

        /*
         * No - fall through to try looking it up.
         */
    }

    description = print_numeric_uuid(uuid);

    if (description) {
        description = (const gchar *) wmem_tree_lookup_string(bluetooth_uuids, description, 0);
        if (description)
            return description;
    }

    return "Unknown";
}

static bluetooth_data_t *
dissect_bluetooth_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
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

    default:
        col_set_str(pinfo->cinfo, COL_INFO, "UnknownDirection ");
        break;
    }

    pinfo->ptype = PT_BLUETOOTH;
    get_conversation(pinfo, &pinfo->dl_src, &pinfo->dl_dst, pinfo->srcport, pinfo->destport);

    main_item = proto_tree_add_item(tree, proto_bluetooth, tvb, 0, tvb_captured_length(tvb), ENC_NA);
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
    bluetooth_data->hci_vendors                  = hci_vendors;

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
        sub_item = proto_tree_add_string(main_tree, hf_bluetooth_addr_str, tvb, 0, 0, (const char *) src->data);
        PROTO_ITEM_SET_HIDDEN(sub_item);

        sub_item = proto_tree_add_string(main_tree, hf_bluetooth_src_str, tvb, 0, 0, (const char *) src->data);
        PROTO_ITEM_SET_GENERATED(sub_item);
    } else if (src && src->type == AT_ETHER) {
        sub_item = proto_tree_add_ether(main_tree, hf_bluetooth_addr, tvb, 0, 0, (const guint8 *) src->data);
        PROTO_ITEM_SET_HIDDEN(sub_item);

        sub_item = proto_tree_add_ether(main_tree, hf_bluetooth_src, tvb, 0, 0, (const guint8 *) src->data);
        PROTO_ITEM_SET_GENERATED(sub_item);
    }

    if (dst && dst->type == AT_STRINGZ) {
        sub_item = proto_tree_add_string(main_tree, hf_bluetooth_addr_str, tvb, 0, 0, (const char *) dst->data);
        PROTO_ITEM_SET_HIDDEN(sub_item);

        sub_item = proto_tree_add_string(main_tree, hf_bluetooth_dst_str, tvb, 0, 0, (const char *) dst->data);
        PROTO_ITEM_SET_GENERATED(sub_item);
    } else if (dst && dst->type == AT_ETHER) {
        sub_item = proto_tree_add_ether(main_tree, hf_bluetooth_addr, tvb, 0, 0, (const guint8 *) dst->data);
        PROTO_ITEM_SET_HIDDEN(sub_item);

        sub_item = proto_tree_add_ether(main_tree, hf_bluetooth_dst, tvb, 0, 0, (const guint8 *) dst->data);
        PROTO_ITEM_SET_GENERATED(sub_item);
    }

    return bluetooth_data;
}

/*
 * Register this in the wtap_encap dissector table.
 * It's called for WTAP_ENCAP_BLUETOOTH_H4, WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR,
 * WTAP_ENCAP_PACKETLOGGER. WTAP_ENCAP_BLUETOOTH_LE_LL,
 * WTAP_ENCAP_BLUETOOTH_LE_LL_WITH_PHDR, and WTAP_ENCAP_BLUETOOTH_BREDR_BB.
 *
 * It does work common to all Bluetooth encapsulations, and then calls
 * the dissector registered in the bluetooth.encap table to handle the
 * metadata header in the packet.
 */
static gint
dissect_bluetooth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    bluetooth_data_t  *bluetooth_data;

    bluetooth_data = dissect_bluetooth_common(tvb, pinfo, tree);

    /*
     * There is no pseudo-header, or there's just a p2p pseudo-header.
     */
    bluetooth_data->previous_protocol_data_type = BT_PD_NONE;
    bluetooth_data->previous_protocol_data.none = NULL;

    if (!dissector_try_uint_new(bluetooth_table, pinfo->phdr->pkt_encap, tvb, pinfo, tree, TRUE, bluetooth_data)) {
        call_data_dissector(tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}


/*
 * Register this in the wtap_encap dissector table.
 * It's called for WTAP_ENCAP_BLUETOOTH_HCI.
 *
 * It does work common to all Bluetooth encapsulations, and then calls
 * the dissector registered in the bluetooth.encap table to handle the
 * metadata header in the packet.
 */
static gint
dissect_bluetooth_bthci(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    bluetooth_data_t  *bluetooth_data;

    bluetooth_data = dissect_bluetooth_common(tvb, pinfo, tree);

    /*
     * data points to a struct bthci_phdr.
     */
    bluetooth_data->previous_protocol_data_type = BT_PD_BTHCI;
    bluetooth_data->previous_protocol_data.bthci = (struct bthci_phdr *)data;

    if (!dissector_try_uint_new(bluetooth_table, pinfo->phdr->pkt_encap, tvb, pinfo, tree, TRUE, bluetooth_data)) {
        call_data_dissector(tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}

/*
 * Register this in the wtap_encap dissector table.
 * It's called for WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR.
 *
 * It does work common to all Bluetooth encapsulations, and then calls
 * the dissector registered in the bluetooth.encap table to handle the
 * metadata header in the packet.
 */
static gint
dissect_bluetooth_btmon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    bluetooth_data_t  *bluetooth_data;

    bluetooth_data = dissect_bluetooth_common(tvb, pinfo, tree);

    /*
     * data points to a struct btmon_phdr.
     */
    bluetooth_data->previous_protocol_data_type = BT_PD_BTMON;
    bluetooth_data->previous_protocol_data.btmon = (struct btmon_phdr *)data;

    if (!dissector_try_uint_new(bluetooth_table, pinfo->phdr->pkt_encap, tvb, pinfo, tree, TRUE, bluetooth_data)) {
        call_data_dissector(tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}

/*
 * Register this in various USB dissector tables.
 */
static gint
dissect_bluetooth_usb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    bluetooth_data_t  *bluetooth_data;

    bluetooth_data = dissect_bluetooth_common(tvb, pinfo, tree);

    /*
     * data points to a usb_conv_info_t.
     */
    bluetooth_data->previous_protocol_data_type = BT_PD_USB_CONV_INFO;
    bluetooth_data->previous_protocol_data.usb_conv_info = (usb_conv_info_t *)data;

    return call_dissector_with_data(hci_usb_handle, tvb, pinfo, tree, bluetooth_data);
}

/*
 * Register this by name; it's called from the Ubertooth dissector.
 */
static gint
dissect_bluetooth_ubertooth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    bluetooth_data_t  *bluetooth_data;

    bluetooth_data = dissect_bluetooth_common(tvb, pinfo, tree);

    /*
     * data points to a ubertooth_data_t.
     */
    bluetooth_data->previous_protocol_data_type = BT_PD_UBERTOOTH_DATA;
    bluetooth_data->previous_protocol_data.ubertooth_data = (ubertooth_data_t *)data;

    call_dissector(btle_handle, tvb, pinfo, tree);

    return tvb_captured_length(tvb);
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
        { &hf_bluetooth_src_str,
            { "Source",                              "bluetooth.src_str",
            FT_STRING, STR_ASCII, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bluetooth_dst_str,
            { "Destination",                         "bluetooth.dst_str",
            FT_STRING, STR_ASCII, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bluetooth_addr_str,
            { "Source or Destination",               "bluetooth.addr_str",
            FT_STRING, STR_ASCII, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static hf_register_info oui_hf[] = {
        { &hf_llc_bluetooth_pid,
            { "PID",	"llc.bluetooth_pid",
            FT_UINT16, BASE_HEX, VALS(bluetooth_pid_vals), 0x0,
            "Protocol ID", HFILL }
        }
    };

    static gint *ett[] = {
        &ett_bluetooth,
    };

    /* Decode As handling */
    static build_valid_func bluetooth_uuid_da_build_value[1] = {bluetooth_uuid_value};
    static decode_as_value_t bluetooth_uuid_da_values = {bluetooth_uuid_prompt, 1, bluetooth_uuid_da_build_value};
    static decode_as_t bluetooth_uuid_da = {"bluetooth", "BT Service UUID", "bluetooth.uuid", 1, 0, &bluetooth_uuid_da_values, NULL, NULL,
            decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};


    proto_bluetooth = proto_register_protocol("Bluetooth",
            "Bluetooth", "bluetooth");

    register_dissector("bluetooth_ubertooth", dissect_bluetooth_ubertooth, proto_bluetooth);

    proto_register_field_array(proto_bluetooth, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    bluetooth_table = register_dissector_table("bluetooth.encap",
            "Bluetooth Encapsulation", proto_bluetooth, FT_UINT32, BASE_HEX);

    chandle_sessions         = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    chandle_to_bdaddr        = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    chandle_to_mode          = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    bdaddr_to_name           = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    bdaddr_to_role           = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    localhost_bdaddr         = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    localhost_name           = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    hci_vendors              = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    hci_vendor_table = register_dissector_table("bluetooth.vendor", "HCI Vendor", proto_bluetooth, FT_UINT16, BASE_HEX);
    bluetooth_uuids          = wmem_tree_new(wmem_epan_scope());

    bluetooth_tap = register_tap("bluetooth");
    bluetooth_device_tap = register_tap("bluetooth.device");
    bluetooth_hci_summary_tap = register_tap("bluetooth.hci_summary");

    bluetooth_uuid_table = register_dissector_table("bluetooth.uuid", "BT Service UUID", proto_bluetooth, FT_STRING, BASE_NONE);
	llc_add_oui(OUI_BLUETOOTH, "llc.bluetooth_pid", "LLC Bluetooth OUI PID", oui_hf, proto_bluetooth);

    register_conversation_table(proto_bluetooth, TRUE, bluetooth_conversation_packet, bluetooth_hostlist_packet);

    register_decode_as(&bluetooth_uuid_da);
}

void
proto_reg_handoff_bluetooth(void)
{
    dissector_handle_t bluetooth_handle = create_dissector_handle(dissect_bluetooth, proto_bluetooth);
    dissector_handle_t bluetooth_bthci_handle = create_dissector_handle(dissect_bluetooth_bthci, proto_bluetooth);
    dissector_handle_t bluetooth_btmon_handle = create_dissector_handle(dissect_bluetooth_btmon, proto_bluetooth);
    dissector_handle_t bluetooth_usb_handle = create_dissector_handle(dissect_bluetooth_usb, proto_bluetooth);
	dissector_handle_t eapol_handle;
	dissector_handle_t btl2cap_handle;

    btle_handle = find_dissector_add_dependency("btle", proto_bluetooth);
    hci_usb_handle = find_dissector_add_dependency("hci_usb", proto_bluetooth);

    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_HCI,           bluetooth_bthci_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_H4,            bluetooth_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR,  bluetooth_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR, bluetooth_btmon_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_PACKETLOGGER,            bluetooth_handle);

    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_LE_LL,           bluetooth_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_LE_LL_WITH_PHDR, bluetooth_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_BREDR_BB,        bluetooth_handle);

    dissector_add_uint("usb.product", (0x0a5c << 16) | 0x21e8, bluetooth_usb_handle);
    dissector_add_uint("usb.product", (0x1131 << 16) | 0x1001, bluetooth_usb_handle);
    dissector_add_uint("usb.product", (0x050d << 16) | 0x0081, bluetooth_usb_handle);
    dissector_add_uint("usb.product", (0x0a5c << 16) | 0x2198, bluetooth_usb_handle);
    dissector_add_uint("usb.product", (0x0a5c << 16) | 0x21e8, bluetooth_usb_handle);
    dissector_add_uint("usb.product", (0x04bf << 16) | 0x0320, bluetooth_usb_handle);
    dissector_add_uint("usb.product", (0x13d3 << 16) | 0x3375, bluetooth_usb_handle);

    dissector_add_uint("usb.protocol", 0xE00101, bluetooth_usb_handle);
    dissector_add_uint("usb.protocol", 0xE00104, bluetooth_usb_handle);

    dissector_add_for_decode_as("usb.device", bluetooth_usb_handle);

    wmem_tree_insert_string(bluetooth_uuids, "00000001-0000-1000-8000-0002EE000002", "SyncML Server", 0);
    wmem_tree_insert_string(bluetooth_uuids, "00000002-0000-1000-8000-0002EE000002", "SyncML Client", 0);

	eapol_handle = find_dissector("eapol");
	btl2cap_handle = find_dissector("btl2cap");

	dissector_add_uint("llc.bluetooth_pid", AMP_C_SECURITY_FRAME, eapol_handle);
	dissector_add_uint("llc.bluetooth_pid", AMP_U_L2CAP, btl2cap_handle);

/* TODO: Add UUID128 verion of UUID16; UUID32? UUID16? */
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
