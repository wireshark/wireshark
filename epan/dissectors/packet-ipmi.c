/* packet-ipmi.c
 * Routines for IPMI-over-LAN packet dissection
 *
 * Duncan Laurie <duncan@sun.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-rmcp.c
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 *
 * See the IPMI spec at
 *
 *	http://www.intel.com/design/servers/ipmi/
 *
 * IPMI LAN Message Request
 *  ipmi.session.authtype
 *  ipmi.session.sequence
 *  ipmi.session.id
 * [ipmi.session.authcode]
 *  ipmi.msg.len
 *  ipmi.msg.rsaddr
 *  ipmi.msg.netfn << 2 | ipmi.msg.rslun
 *  ipmi.msg.csum1
 *  ipmi.msg.rqaddr
 *  ipmi.msg.seq << 2 | ipmi.msg.rqlun
 *  ipmi.msg.cmd
 *  ipmi.msg.DATA
 *  ipmi.msg.csum2
 *
 * IPMI LAN Message Response
 *  ipmi.session.authtype
 *  ipmi.session.sequence
 *  ipmi.session.id
 * [ipmi.session.authcode]
 *  ipmi.msg.len
 *  ipmi.msg.rqaddr
 *  ipmi.msg.netfn << 2 | ipmi.msg.rqlun
 *  ipmi.msg.csum1
 *  ipmi.msg.rsaddr
 *  ipmi.msg.seq << 2 | ipmi.msg.rslun
 *  ipmi.msg.cmd
 *  ipmi.msg.ccode
 *  ipmi.msg.DATA
 *  ipmi.msg.csum2
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#define RMCP_CLASS_IPMI 0x07

static dissector_handle_t data_handle;
static int proto_ipmi = -1;

static gint ett_ipmi = -1;
static gint ett_ipmi_session = -1;
static gint ett_ipmi_msg_nlfield = -1;
static gint ett_ipmi_msg_slfield = -1;

/********* Sensor/Event, NetFN = 0x04 *********/

/* Platform Event Message, added by lane */
static gint ett_cmd_PEM_EventDirAndEventType = -1;
static gint ett_cmd_PEM_EventData1_threshold = -1;
static gint ett_cmd_PEM_EventData1_discrete = -1;
static gint ett_cmd_PEM_EventData2_discrete = -1;
static gint ett_cmd_PEM_EventData1_OEM = -1;
static gint ett_cmd_PEM_EventData2_OEM = -1;
/* Get Device SDR Info, added by lane */
static gint ett_cmd_GetDeviceSDRInfo_Flag = -1; /* add subtree for Flag */
/* Get Sensor Reading, added by lane */
static gint ett_cmd_GetSensorReading_ResponseDataByte2 = -1;
static gint ett_cmd_GetSensorReading_ResponseDataByte3 = -1;
static gint ett_cmd_GetSensorReading_ResponseDataByte3_threshold = -1;
static gint ett_cmd_GetSensorReading_ResponseDataByte4 = -1;
/* Set Sensor Thresholds, added by lane */
static gint ett_cmd_SetSensorThresholds_ControlByte = -1;
/* Get Sensor Thresholds, added by lane */
static gint ett_cmd_GetSensorThresholds_ControlByte = -1;

/********* APP, NetFN = 0x06 *********/

/* Get Device ID, added by lane */
static gint ett_cmd_GetDeviceID_data_dr = -1;    /* add subtree for Device Revision field  */
static gint ett_cmd_GetDeviceID_data_fr = -1;     /* add subtree for firmware Revision field  */
static gint ett_cmd_GetDeviceID_data_ads = -1;  /* add subtree for Additional Device Support */


/********* Storage, NetFN = 0x0a *********/

static gint ett_Get_Channel_Auth_Cap_anonymouslogin = -1;
/* Get FRU Inventory Area Info, added by lane */
static gint ett_cmd_GetFRUInventoryAreaInfo_data_ResponseDataByte4 = -1;    /* add subtree for ResponseDataByte4 */
/* Get SEL Info, added by lane */
static gint ett_cmd_GetSELInfo_data_OperationSupport = -1;    /* add subtree for Operation Support */
/* Clear SEL, added by lane */
static gint ett_cmd_ClearSEL_data_ErasureProgress = -1;    /* add subtree for Erasure Progress */

/********* PICMG, NetFN = 0x2c *********/

/* Get FRU Led Properties, added by lane */
static gint  ett_cmd_GetFRULedProperties_data_LedProperties = -1; /* add subtree for Get FRU Led Properties */
/* Get Led Color Capabilities, added by lane */
static gint ett_cmd_GetLedColorCapabilities_data_LEDColorCapabilities = -1; /* add subtree for LED Color Capabilities */
static gint ett_cmd_GetLedColorCapabilities_data_DefaultLEDColorLocalControl = -1; /* add subtree for Default LED Color in Local Control State */
static gint ett_cmd_GetLedColorCapabilities_data_DefaultLEDColorOverride = -1; /* add subtree for Get Default LED Color  in Override State */
/* Set FRU Led State, added by lane */
static gint ett_cmd_SetFRULedState_data_Color = -1; /* add subtree for Color when illuminated */
/* Get FRU Led State, added by lane */
static gint ett_cmd_GetFRULedState_data_LEDState = -1;   /* add subtree for LED State*/
static gint ett_cmd_GetFRULedState_data_LocalControlColor = -1;  /* add subtree for Local Control Color*/
static gint ett_cmd_GetFRULedState_data_OverrideStateColor = -1;  /* add subtree for Override State Color*/
/* Set FRU Activation Policy, added by lane */
static gint ett_cmd_SetFRUActivationPolicy_data_FRUActivationPolicyMaskBit = -1; 
static gint ett_cmd_SetFRUActivationPolicy_data_FRUActivationPolicySetBit = -1; 
/* Get FRU Activation Policy, added by lane */
static gint ett_cmd_GetFRUActivationPolicy_data_FRUActivationPolicy = -1; 
/* Get Power Level, added by lane */
static gint ett_cmd_GetPowerLevel_data_Properties = -1; /* add subtree for Properties */


/***************************************************************************************************/


/* IPMI session header */
static int hf_ipmi_session_id = -1;
static int hf_ipmi_session_authtype = -1;
static int hf_ipmi_payloadtype = -1;
static int hf_ipmi_payloadtype_auth = -1;
static int hf_ipmi_payloadtype_enc = -1;
static int hf_ipmi_oem_iana = -1;
static int hf_ipmi_oem_payload_id = -1;
static int hf_ipmi_session_sequence = -1;
static int hf_ipmi_session_authcode = -1;

/* IPMI message header */
static int hf_ipmi_msg_len = -1;
static int hf_ipmi_conf_hdr = -1;
static int hf_ipmi_msg_rsaddr = -1;
static int hf_ipmi_msg_nlfield = -1;
static int hf_ipmi_msg_netfn = -1;
static int hf_ipmi_msg_rqlun = -1;
static int hf_ipmi_msg_csum1 = -1;
static int hf_ipmi_msg_rqaddr = -1;
static int hf_ipmi_msg_slfield = -1;
static int hf_ipmi_msg_seq = -1;
static int hf_ipmi_msg_rslun = -1;
static int hf_ipmi_msg_cmd = -1;
static int hf_ipmi_msg_ccode = -1;
static int hf_ipmi_msg_csum2 = -1;

/********* Sensor/Event, NetFN = 0x04 **********/

/* Platform Event Message, added by lane */
static int hf_PEM_datafield_EvMRev = -1; 
static int hf_PEM_datafield_SensorType = -1; 
static int hf_PEM_datafield_SensorNumber = -1; 
static int hf_PEM_datafield_EventDirAndEventType_EventDir = -1; 
static int hf_PEM_datafield_EventDirAndEventType_EventType = -1; 

static int hf_PEM_datafield_EventData1_threshold_76 = -1; 
static int hf_PEM_datafield_EventData1_threshold_54 = -1; 
static int hf_PEM_datafield_EventData1_threshold_30 = -1; 
static int hf_PEM_datafield_EventData2_threshold = -1; 
static int hf_PEM_datafield_EventData3_threshold = -1; 

static int hf_PEM_datafield_EventData1_discrete_76 = -1; 
static int hf_PEM_datafield_EventData1_discrete_54 = -1; 
static int hf_PEM_datafield_EventData1_discrete_30 = -1; 
static int hf_PEM_datafield_EventData2_discrete_74 = -1; 
static int hf_PEM_datafield_EventData2_discrete_30 = -1; 
static int hf_PEM_datafield_EventData3_discrete = -1; 

static int hf_PEM_datafield_EventData1_OEM_76 = -1; 
static int hf_PEM_datafield_EventData1_OEM_54 = -1; 
static int hf_PEM_datafield_EventData1_OEM_30 = -1; 
static int hf_PEM_datafield_EventData2_OEM_74 = -1; 
static int hf_PEM_datafield_EventData2_OEM_30 = -1; 
static int hf_PEM_datafield_EventData3_OEM = -1; 

static int hf_PEM_datafield_HotSwapEvent_CurrentState = -1; 
static int hf_PEM_datafield_HotSwapEvent_StateChangeCause = -1;
static int hf_PEM_datafield_HotSwapEvent_PreviousState = -1;
static int hf_PEM_datafield_HotSwapEvent_FRUDeviceID = -1;

/* Get Device SDR Info, added by lane */
static int hf_GetDeviceSDRInfo_datafield_SensorNumber = -1;
static int hf_GetDeviceSDRInfo_datafield_Flag = -1;
static int hf_GetDeviceSDRInfo_datafield_Flag_Dynamicpopulation = -1;
static int hf_GetDeviceSDRInfo_datafield_Flag_Reserved = -1;
static int hf_GetDeviceSDRInfo_datafield_Flag_DeviceLUNs3 = -1;
static int hf_GetDeviceSDRInfo_datafield_Flag_DeviceLUNs2 = -1;
static int hf_GetDeviceSDRInfo_datafield_Flag_DeviceLUNs1 = -1;
static int hf_GetDeviceSDRInfo_datafield_Flag_DeviceLUNs0 = -1;
static int hf_GetDeviceSDRInfo_datafield_SensorPopulationChangeIndicator = -1;
/* Get Device SDR, added by lane */
static int hf_GetDeviceSDR_datafield_NextRecordID = -1;
static int hf_GetDeviceSDR_datafield_ReservationID = -1;
static int hf_GetDeviceSDR_datafield_RecordID = -1;
static int hf_GetDeviceSDR_datafield_OffsetIntoRecord = -1; 
static int hf_GetDeviceSDR_datafield_BytesToRead = -1;
/* Reserve Device SDR Repository, added by lane */
static int hf_ReserveDeviceSDRRepository_datafield_ReservationID = -1;
/* Set Sensor Hysteresis, added by lane */
static int hf_SetSensorHysteresis_datafield_SensorNumber = -1;
static int hf_SetSensorHysteresis_datafield_ReservedForHysteresisMask = -1;
static int hf_SetSensorHysteresis_datafield_PositivegoingThresholdHysteresisValue = -1;
static int hf_SetSensorHysteresis_datafield_NegativegoingThresholdHysteresisValue = -1;
/* Get Sensor Hysteresis, added by lane */
static int hf_GetSensorHysteresis_datafield_SensorNumber = -1;
static int hf_GetSensorHysteresis_datafield_ReservedForHysteresisMask = -1;
static int hf_GetSensorHysteresis_datafield_PositivegoingThresholdHysteresisValue = -1;
static int hf_GetSensorHysteresis_datafield_NegativegoingThresholdHysteresisValue = -1;
/* Set Sensor Thresholds, added by lane */
static int hf_SetSensorThresholds_datafield_SensorNumber = -1;
static int hf_SetSensorThresholds_datafield_ControlByte_Bit76 = -1;
static int hf_SetSensorThresholds_datafield_ControlByte_Bit5 = -1;
static int hf_SetSensorThresholds_datafield_ControlByte_Bit4 = -1;
static int hf_SetSensorThresholds_datafield_ControlByte_Bit3 = -1;
static int hf_SetSensorThresholds_datafield_ControlByte_Bit2 = -1;
static int hf_SetSensorThresholds_datafield_ControlByte_Bit1 = -1;
static int hf_SetSensorThresholds_datafield_ControlByte_Bit0 = -1;
static int hf_SetSensorThresholds_datafield_LowerNonCriticalThreshold = -1;
static int hf_SetSensorThresholds_datafield_LowerCriticalThreshold = -1;
static int hf_SetSensorThresholds_datafield_LowerNonRecoverableThreshold = -1;
static int hf_SetSensorThresholds_datafield_UpperNonCriticalThreshold = -1;
static int hf_SetSensorThresholds_datafield_UpperCriticalThreshold = -1;
static int hf_SetSensorThresholds_datafield_UpperNonRecoverableThreshold = -1;
/* Get Sensor Thresholds, added by lane */
static int hf_GetSensorThresholds_datafield_SensorNumber = -1;
static int hf_GetSensorThresholds_datafield_ControlByte_Bit76 = -1;
static int hf_GetSensorThresholds_datafield_ControlByte_Bit5 = -1;
static int hf_GetSensorThresholds_datafield_ControlByte_Bit4 = -1;
static int hf_GetSensorThresholds_datafield_ControlByte_Bit3 = -1;
static int hf_GetSensorThresholds_datafield_ControlByte_Bit2 = -1;
static int hf_GetSensorThresholds_datafield_ControlByte_Bit1 = -1;
static int hf_GetSensorThresholds_datafield_ControlByte_Bit0 = -1;
static int hf_GetSensorThresholds_datafield_LowerNonCriticalThreshold = -1;
static int hf_GetSensorThresholds_datafield_LowerCriticalThreshold = -1;
static int hf_GetSensorThresholds_datafield_LowerNonRecoverableThreshold = -1;
static int hf_GetSensorThresholds_datafield_UpperNonCriticalThreshold = -1;
static int hf_GetSensorThresholds_datafield_UpperCriticalThreshold = -1;
static int hf_GetSensorThresholds_datafield_UpperNonRecoverableThreshold = -1;
/* Get Sensor Reading, added by lane */
static int hf_GetSensorReading_datafield_SensorNumber = -1;
static int hf_GetSensorReading_datafield_Sensorreading = -1;
static int hf_GetSensorReading_datafield_ResponseDataByte2_Bit7 = -1;
static int hf_GetSensorReading_datafield_ResponseDataByte2_Bit6 = -1;
static int hf_GetSensorReading_datafield_ResponseDataByte2_Bit5 = -1;
static int hf_GetSensorReading_datafield_ResponseDataByte2_Bit40 = -1;
static int hf_GetSensorReading_datafield_ResponseDataByte3_Bit7 = -1;
static int hf_GetSensorReading_datafield_ResponseDataByte3_Bit6 = -1;
static int hf_GetSensorReading_datafield_ResponseDataByte3_Bit5 = -1;
static int hf_GetSensorReading_datafield_ResponseDataByte3_Bit4 = -1;
static int hf_GetSensorReading_datafield_ResponseDataByte3_Bit3 = -1;
static int hf_GetSensorReading_datafield_ResponseDataByte3_Bit2 = -1;
static int hf_GetSensorReading_datafield_ResponseDataByte3_Bit1 = -1;
static int hf_GetSensorReading_datafield_ResponseDataByte3_Bit0 = -1;
static int hf_GetSensorReading_datafield_ResponseDataByte4_Bit7 = -1;
static int hf_GetSensorReading_datafield_ResponseDataByte4_Bit6 = -1;
static int hf_GetSensorReading_datafield_ResponseDataByte4_Bit5 = -1;
static int hf_GetSensorReading_datafield_ResponseDataByte4_Bit4 = -1;
static int hf_GetSensorReading_datafield_ResponseDataByte4_Bit3 = -1;
static int hf_GetSensorReading_datafield_ResponseDataByte4_Bit2 = -1;
static int hf_GetSensorReading_datafield_ResponseDataByte4_Bit1 = -1;
static int hf_GetSensorReading_datafield_ResponseDataByte4_Bit0 = -1;
static int hf_GetSensorReading_datafield_ResponseDataByte3_Bit76_threshold = -1;
static int hf_GetSensorReading_datafield_ResponseDataByte3_Bit5_threshold = -1;
static int hf_GetSensorReading_datafield_ResponseDataByte3_Bit4_threshold = -1;
static int hf_GetSensorReading_datafield_ResponseDataByte3_Bit3_threshold = -1;
static int hf_GetSensorReading_datafield_ResponseDataByte3_Bit2_threshold = -1;
static int hf_GetSensorReading_datafield_ResponseDataByte3_Bit1_threshold = -1;
static int hf_GetSensorReading_datafield_ResponseDataByte3_Bit0_threshold = -1;

/********* App, NetFN = 0x06 *********/

/* Get Device ID, added by lane */
static int hf_GetDeviceID_datafield_DeviceID = -1;
static int hf_GetDeviceID_datafield_DeviceSDR = -1;
static int hf_GetDeviceID_datafield_DeviceRevision = -1;
static int hf_GetDeviceID_datafield_DeviceAvailable = -1;
static int hf_GetDeviceID_datafield_MajorFirmwareRevision = -1;
static int hf_GetDeviceID_datafield_MinorFirmwareRevision = -1;
static int hf_GetDeviceID_datafield_IPMIRevision = -1;
static int hf_GetDeviceID_datafield_ADS_Chasis = -1;
static int hf_GetDeviceID_datafield_ADS_Bridge = -1;
static int hf_GetDeviceID_datafield_ADS_IPMBEventGenerator = -1;
static int hf_GetDeviceID_datafield_ADS_IPMBEventReceiver = -1;
static int hf_GetDeviceID_datafield_ADS_FRUInventoryDevice = -1;
static int hf_GetDeviceID_datafield_ADS_SELDevice = -1;
static int hf_GetDeviceID_datafield_ADS_SDRRepositoryDevice = -1;
static int hf_GetDeviceID_datafield_ADS_SensorDevice = -1;
static int hf_GetDeviceID_datafield_ManufactureID = -1;
static int hf_GetDeviceID_datafield_ProductID = -1;
static int hf_GetDeviceID_datafield_AFRI = -1;

static int hf_Get_Channel_Auth_Cap_channel_number = -1;
static int hf_Get_Channel_Auth_Cap_datafield_comp_info = -1;
static int hf_Get_Channel_Auth_Cap_datafield_channel_number = -1;
static int hf_Get_Channel_Auth_Cap_datafield_max_priv_lev = -1;
static int hf_Get_Channel_Auth_Cap_comp_info = -1;
static int hf_Get_Channel_Auth_Cap_Auth_types_b5 = -1;
static int hf_Get_Channel_Auth_Cap_Auth_types_b4 = -1;
static int hf_Get_Channel_Auth_Cap_Auth_types_b2 = -1;
static int hf_Get_Channel_Auth_Cap_Auth_types_b1 = -1;
static int hf_Get_Channel_Auth_Cap_Auth_types_b0 = -1;
static int hf_Get_Channel_Auth_Cap_Auth_KG_status = -1;
static int hf_Get_Channel_Auth_Cap_per_mess_auth_status = -1;
static int hf_Get_Channel_Auth_Cap_user_level_auth_status = -1;
static int hf_Get_Channel_Auth_Cap_anonymouslogin_status_b2 = -1;
static int hf_Get_Channel_Auth_Cap_anonymouslogin_status_b1 = -1;
static int hf_Get_Channel_Auth_Cap_anonymouslogin_status_b0 = -1;
static int hf_Get_Channel_Auth_Cap_ext_cap_b1 = -1;
static int hf_Get_Channel_Auth_Cap_ext_cap_b0 = -1;
static int hf_Get_Channel_Auth_OEM_ID = -1;
static int hf_Get_Channel_Auth_OEM_AUX = -1;

/********* Storage, NetFN = 0x0a *********/

/* Get FRU Inventory Area Info, added by lane */
static int hf_GetFRUInventoryAreaInfo_datafield_FRUDeviceID = -1;
static int hf_GetFRUInventoryAreaInfo_datafield_FRUInventoryAreaSize = -1;
static int hf_GetFRUInventoryAreaInfo_datafield_ResponseDataByte4_Bit71 = -1;
static int hf_GetFRUInventoryAreaInfo_datafield_ResponseDataByte4_Bit0 = -1;
/* Get SEL Info, added by lane */
static int hf_GetSELInfo_datafield_SELVersion = -1;
static int hf_GetSELInfo_datafield_Entries = -1;
static int hf_GetSELInfo_datafield_FreeSpace = -1;
static int hf_GetSELInfo_datafield_AdditionTimestamp = -1;
static int hf_GetSELInfo_datafield_EraseTimestamp = -1;
static int hf_GetSELInfo_datafield_OperationSupport_Bit7 = -1;
static int hf_GetSELInfo_datafield_OperationSupport_Reserved = -1;
static int hf_GetSELInfo_datafield_OperationSupport_Bit3 = -1;
static int hf_GetSELInfo_datafield_OperationSupport_Bit2 = -1;
static int hf_GetSELInfo_datafield_OperationSupport_Bit1 = -1;
static int hf_GetSELInfo_datafield_OperationSupport_Bit0 = -1;
/* Reserve SEL, added by lane */
static int hf_ReserveSEL_datafield_ReservationID  = -1;
/* Get SEL Entry, added by lane */
static int hf_GetSELEntry_datafield_ReservationID = -1;
static int hf_GetSELEntry_datafield_SELRecordID = -1;
static int hf_GetSELEntry_datafield_OffsetIntoRecord = -1;
static int hf_GetSELEntry_datafield_BytesToRead = -1;
static int hf_GetSELEntry_datafield_NextSELRecordID = -1;
/* Clear SEL, added by lane */
static int hf_ClearSEL_datafield_ReservationID = -1;
static int hf_ClearSEL_datafield_Byte3 = -1;
static int hf_ClearSEL_datafield_Byte4 = -1;
static int hf_ClearSEL_datafield_Byte5 = -1;
static int hf_ClearSEL_datafield_Byte6 = -1;
static int hf_ClearSEL_datafield_ErasureProgress_Reserved = -1;
static int hf_ClearSEL_datafield_ErasureProgress_EraProg = -1;


/********* PICMG, NetFN = 0X2c *********/

/* Get PICMG Properties, added by lane */
static int hf_GetPICMGProperties_datafield_PICMGIdentifier = -1;
static int hf_GetPICMGProperties_datafield_PICMGExtensionVersion = -1;
static int hf_GetPICMGProperties_datafield_MaxFRUDeviceID = -1;
static int hf_GetPICMGProperties_datafield_FRUDeviceIDforIPMController = -1;
/* FRU Control, added by lane */
static int hf_FRUControl_datafield_PICMGIdentifier = -1;
static int hf_FRUControl_datafield_FRUDeviceID = -1;
static int hf_FRUControl_datafield_FRUControlOption = -1;
/* Get FRU Led Properties, added by lane */
static int hf_GetFRULedProperties_datafield_PICMGIdentifier = -1;
static int hf_GetFRULedProperties_datafield_FRUDeviceID = -1;
static int hf_GetFRULedProperties_datafield_LedProperties_Reserved = -1;
static int hf_GetFRULedProperties_datafield_LedProperties_LED3 = -1;
static int hf_GetFRULedProperties_datafield_LedProperties_LED2 = -1;
static int hf_GetFRULedProperties_datafield_LedProperties_LED1 = -1;
static int hf_GetFRULedProperties_datafield_LedProperties_BlueLED = -1;
static int hf_GetFRULedProperties_datafield_ApplicationSpecificLEDCount = -1;
/* Get Led Color Capabilities, added by lane */
static int hf_GetLedColorCapabilities_datafield_PICMGIdentifier = -1;
static int hf_GetLedColorCapabilities_datafield_FRUDeviceID = -1;
static int hf_GetLedColorCapabilities_datafield_LEDID = -1;
static int hf_GetLedColorCapabilities_datafield_LEDColorCapabilities_Reserved_7 = -1;
static int hf_GetLedColorCapabilities_datafield_LEDColorCapabilities_WHITE = -1;
static int hf_GetLedColorCapabilities_datafield_LEDColorCapabilities_ORANGE = -1;
static int hf_GetLedColorCapabilities_datafield_LEDColorCapabilities_AMBER = -1;
static int hf_GetLedColorCapabilities_datafield_LEDColorCapabilities_GREEN = -1;
static int hf_GetLedColorCapabilities_datafield_LEDColorCapabilities_RED = -1;
static int hf_GetLedColorCapabilities_datafield_LEDColorCapabilities_BLUE = -1;
static int hf_GetLedColorCapabilities_datafield_LEDColorCapabilities_Reserved_0 = -1;
static int hf_GetLedColorCapabilities_datafield_DefaultLEDColorLocalControl_Reserved_74 = -1;
static int hf_GetLedColorCapabilities_datafield_DefaultLEDColorLocalControl_Color = -1;
static int hf_GetLedColorCapabilities_datafield_DefaultLEDColorOverride_Reserved_74 = -1;
static int hf_GetLedColorCapabilities_datafield_DefaultLEDColorOverride_Color = -1;
/* Set FRU Led State, added by lane */
static int hf_SetFRULedState_datafield_PICMGIdentifier = -1;
static int hf_SetFRULedState_datafield_FRUDeviceID = -1;
static int hf_SetFRULedState_datafield_LEDID = -1;
static int hf_SetFRULedState_datafield_LEDFunction = -1;
static int hf_SetFRULedState_datafield_Offduration = -1;
static int hf_SetFRULedState_datafield_Onduration = -1;
static int hf_SetFRULedState_datafield_Color_Reserved = -1;
static int hf_SetFRULedState_datafield_Color_ColorVal = -1;
/* Get FRU Led State, added by lane */
static int hf_GetFRULedState_datafield_PICMGIdentifier = -1;
static int hf_GetFRULedState_datafield_FRUDeviceID = -1;
static int hf_GetFRULedState_datafield_LEDID = -1;
static int hf_GetFRULedState_datafield_LEDState_Reserved = -1;
static int hf_GetFRULedState_datafield_LEDState_Bit2 = -1;
static int hf_GetFRULedState_datafield_LEDState_Bit1 = -1;
static int hf_GetFRULedState_datafield_LEDState_Bit0 = -1;
static int hf_GetFRULedState_datafield_LocalControlLEDFunction = -1;
static int hf_GetFRULedState_datafield_LocalControlOffduration = -1;
static int hf_GetFRULedState_datafield_LocalControlOnduration = -1;
static int hf_GetFRULedState_datafield_LocalControlColor_Reserved = -1;
static int hf_GetFRULedState_datafield_LocalControlColor_ColorVal = -1;
static int hf_GetFRULedState_datafield_OverrideStateLEDFunction = -1;
static int hf_GetFRULedState_datafield_OverrideStateOffduration = -1;
static int hf_GetFRULedState_datafield_OverrideStateOnduration = -1;
static int hf_GetFRULedState_datafield_OverrideStateColor_Reserved = -1;
static int hf_GetFRULedState_datafield_OverrideStateColor_ColorVal = -1;
static int hf_GetFRULedState_datafield_LampTestDuration = -1;
/* Set FRU Activation Policy, added by lane */
static int hf_SetFRUActivationPolicy_datafield_PICMGIdentifier = -1;
static int hf_SetFRUActivationPolicy_datafield_FRUDeviceID = -1;
static int hf_SetFRUActivationPolicy_datafield_FRUActivationPolicyMaskBit_Bit72 = -1;
static int hf_SetFRUActivationPolicy_datafield_FRUActivationPolicyMaskBit_Bit1 = -1;
static int hf_SetFRUActivationPolicy_datafield_FRUActivationPolicyMaskBit_Bit0 = -1;
static int hf_SetFRUActivationPolicy_datafield_FRUActivationPolicySetBit_Bit72 = -1;
static int hf_SetFRUActivationPolicy_datafield_FRUActivationPolicySetBit_Bit1 = -1;
static int hf_SetFRUActivationPolicy_datafield_FRUActivationPolicySetBit_Bit0 = -1;
static int hf_SetFRUActivationPolicy_datafield_FRUActivationPolicySetBit_Bit1_ignored  = -1;
static int hf_SetFRUActivationPolicy_datafield_FRUActivationPolicySetBit_Bit0_ignored  = -1;
/* Get FRU Activation Policy, added by lane */
static int hf_GetFRUActivationPolicy_datafield_PICMGIdentifier = -1;
static int hf_GetFRUActivationPolicy_datafield_FRUDeviceID = -1;
static int hf_GetFRUActivationPolicy_datafield_FRUActivationPolicy_Bit72 = -1;
static int hf_GetFRUActivationPolicy_datafield_FRUActivationPolicy_Bit1 = -1;
static int hf_GetFRUActivationPolicy_datafield_FRUActivationPolicy_Bit0 = -1;
/* Set FRU Activation, added by lane */
static int hf_SetFRUActivation_datafield_PICMGIdentifier = -1;
static int hf_SetFRUActivation_datafield_FRUDeviceID = -1;
static int hf_SetFRUActivation_datafield_FRUActivationDeactivation = -1;
/* Get Device Locator Record ID, added by lane */
static int hf_GetDeviceLocatorRecordID_datafield_PICMGIdentifier = -1;
static int hf_GetDeviceLocatorRecordID_datafield_FRUDeviceID = -1;
static int hf_GetDeviceLocatorRecordID_datafield_RecordID = -1;
/* Set Power Level, added by lane */
static int hf_SetPowerLevel_datafield_PICMGIdentifier = -1;
static int hf_SetPowerLevel_datafield_FRUDeviceID = -1;
static int hf_SetPowerLevel_datafield_PowerLevel = -1;
static int hf_SetPowerLevel_datafield_SetPresentLevelsToDesiredLevels = -1;
/* Get Power Level, added by lane */
static int hf_GetPowerLevel_datafield_PICMGIdentifier = -1;
static int hf_GetPowerLevel_datafield_FRUDeviceID = -1;
static int hf_GetPowerLevel_datafield_PowerType = -1;
static int hf_GetPowerLevel_datafield_Properties = -1;
static int hf_GetPowerLevel_datafield_Properties_DynamicPowerCon = -1;
static int hf_GetPowerLevel_datafield_Properties_Reserved = -1;
static int hf_GetPowerLevel_datafield_Properties_PowerLevel = -1;
static int hf_GetPowerLevel_datafield_DelayToStablePower = -1;
static int hf_GetPowerLevel_datafield_PowerMultiplier = -1;
static int hf_GetPowerLevel_datafield_PowerDraw = -1;
/* Set Fan Level, added by lane */
static int hf_SetFanLevel_datafield_PICMGIdentifier = -1;
static int hf_SetFanLevel_datafield_FRUDeviceID = -1;
static int hf_SetFanLevel_datafield_FanLevel = -1;
/* Get Fan Level, added by lane */
static int hf_GetFanLevel_datafield_PICMGIdentifier = -1;
static int hf_GetFanLevel_datafield_FRUDeviceID = -1;
static int hf_GetFanLevel_datafield_OverrideFanLevel = -1;
static int hf_GetFanLevel_datafield_LocalControlFanLevel = -1;



/***********************************************************************/

static const value_string ipmi_netfn_vals[] = {
	{ 0x00,	"Chassis Request" },
	{ 0x01,	"Chassis Response" },
	{ 0x02,	"Bridge Request" },
	{ 0x03,	"Bridge Response" },
	{ 0x04,	"Sensor/Event Request" },
	{ 0x05,	"Sensor/Event Response" },
	{ 0x06,	"Application Request" },
	{ 0x07,	"Application Response" },
	{ 0x08,	"Firmware Request" },
	{ 0x09,	"Frimware Response" },
	{ 0x0a,	"Storage Request" },
	{ 0x0b,	"Storage Response" },
	{ 0x0c,	"Transport Request" },
	{ 0x0d,	"Transport Response" },
	{ 0x2c,	"PICMG Request" },       /* lane */
	{ 0x2d,	"PICMG Response" },    /* lane */
	{ 0x30,	"OEM Request" },
	{ 0x31,	"OEM Response" },
	{ 0x00,	NULL },
};

#define IPMI_AUTH_NONE		0x00
#define IPMI_AUTH_MD2		0x01
#define IPMI_AUTH_MD5		0x02
#define IPMI_AUTH_PASSWORD	0x04
#define IPMI_AUTH_OEM		0x05
#define IPMI_AUTH_RMCPP		0x06

static const value_string ipmi_authtype_vals[] = {
	{ IPMI_AUTH_NONE,	"NONE" },
	{ IPMI_AUTH_MD2,	"MD2" },
	{ IPMI_AUTH_MD5,	"MD5" },
	{ IPMI_AUTH_PASSWORD,	"PASSWORD" },
	{ IPMI_AUTH_OEM,	"OEM" },
	{ IPMI_AUTH_RMCPP,	"RMCPP"},
	{ 0x00,	NULL }
};

#define IPMI_IPMI_MESSAGE	0
#define IPMI_OEM_EXPLICIT	2

static const value_string ipmi_payload_vals[] = {
	{ IPMI_IPMI_MESSAGE,	"IPMI Message" },
	{ 0x01,	"SOL (serial over LAN)" },
	{ IPMI_OEM_EXPLICIT,	"OEM Explicit" },
	/* Session Setup Payload Types */
	{ 0x10,	"RMCP+ Open Session Request" },
	{ 0x11,	"RMCP+ Open Session Response" },
	{ 0x12,	"RAKP Message 1" },
	{ 0x13,	"RAKP Message 2" },
	{ 0x14,	"RAKP Message 3" },
	{ 0x15,	"RAKP Message 4" },
	/* OEM Payload Type Handles */
	{ 0x20,	"Handle values for OEM payloads OEM0" },
	{ 0x21,	"Handle values for OEM payloads OEM1" },
	{ 0x22,	"Handle values for OEM payloads OEM2" },
	{ 0x23,	"Handle values for OEM payloads OEM3" },
	{ 0x24,	"Handle values for OEM payloads OEM4" },
	{ 0x25,	"Handle values for OEM payloads OEM5" },
	{ 0x26,	"Handle values for OEM payloads OEM6" },
	{ 0x27,	"Handle values for OEM payloads OEM7" },
	{ 0x00,	NULL }
};

static const true_false_string ipmi_payload_aut_val  = {
  "Payload is authenticated",
  "Payload is unauthenticated"
};

static const true_false_string ipmi_payload_enc_val  = {
  "Payload is encrypted",
  "Payload is unencrypted"
};

static const value_string ipmi_ccode_vals[] = {
	{ 0x00, "Command completed normally" },
	/* added by lane */
	{ 0x81, "cannot execute command, SEL erase in progress" },
	/***************/
	{ 0xc0, "Node busy" },
	{ 0xc1, "Unrecognized or unsupported command" },
	{ 0xc2, "Command invalid for given LUN" },
	{ 0xc3, "Timeout while processing command" },
	{ 0xc4, "Out of space" },
	{ 0xc5, "Reservation cancelled or invalid reservation ID" },
	{ 0xc6, "Request data truncated" },
	{ 0xc7, "Request data length invalid" },
	{ 0xc8, "Request data field length limit exceeded" },
	{ 0xc9, "Parameter out of range" },
	{ 0xca, "Cannot return number of requested data bytes" },
	{ 0xcb, "Requested sensor, data, or record not present" },
	{ 0xcc, "Invalid data field in request" },
	{ 0xcd, "Command illegal for specified sensor or record type" },
	{ 0xce, "Command response could not be provided" },
	{ 0xcf, "Cannot execute duplicated request" },
	{ 0xd0, "SDR repository in update mode" },
	{ 0xd1, "Device in firmware update mode" },
	{ 0xd2, "BMC initialization or initialization agent running" },
	{ 0xd3, "Destination unavailable" },
	{ 0xd4, "Insufficient privilege level" },
	{ 0xd5, "Command or param not supported in present state" },
	{ 0xff, "Unspecified error" },
	{ 0x00, NULL },
};

static const value_string ipmi_addr_vals[] = {
	{ 0x20, "BMC Slave Address" },
	{ 0x81,	"Remote Console Software 1" },
	{ 0x83,	"Remote Console Software 2" },
	{ 0x85,	"Remote Console Software 3" },
	{ 0x87,	"Remote Console Software 4" },
	{ 0x89,	"Remote Console Software 5" },
	{ 0x8b,	"Remote Console Software 6" },
	{ 0x8d,	"Remote Console Software 7" },
	{ 0x00,	NULL },
};

/* Table 13-19, Confidentiality Algorithm Numbers */
static const value_string ipmi_conf_vals[] ={
	{ 0x00,	"none" },
	{ 0x01,	"AES-CBC-128" },
	{ 0x02,	"xRC4-128" },
	{ 0x03,	"xRC4-40" },
	{ 0x30,	"OEM" },
	{ 0x31,	"OEM" },
	{ 0x32,	"OEM" },
	{ 0x33,	"OEM" },
	{ 0x34,	"OEM" },
	{ 0x35,	"OEM" },
	{ 0x36,	"OEM" },
	{ 0x37,	"OEM" },
	{ 0x38,	"OEM" },
	{ 0x39,	"OEM" },
	{ 0x3a,	"OEM" },
	{ 0x3b,	"OEM" },
	{ 0x3c,	"OEM" },
	{ 0x3d,	"OEM" },
	{ 0x3e,	"OEM" },
	{ 0x3f,	"OEM" },
	{ 0x00,	NULL },
};

static const value_string ipmi_chassis_cmd_vals[] = {
	/* Chassis Device Commands */
	{ 0x00,	"Get Chassis Capabilities" },
	{ 0x01,	"Get Chassis Status" },
	{ 0x02,	"Chassis Control" },
	{ 0x03,	"Chassis Reset" },
	{ 0x04,	"Chassis Identify" },
	{ 0x05,	"Set Chassis Capabilities" },
	{ 0x06,	"Set Power Restore Policy" },
	{ 0x07,	"Get System Restart Cause" },
	{ 0x08,	"Set System Boot Options" },
	{ 0x09,	"Get System Boot Options" },
	{ 0x0f,	"Get POH Counter" },
	{ 0x00,	NULL },
};

static const value_string ipmi_bridge_cmd_vals[] = {
	/* ICMB Bridge Management Commands */
	{ 0x00,	"Get Bridge State" },
	{ 0x01,	"Set Bridge State" },
	{ 0x02,	"Get ICMB Address" },
	{ 0x03,	"Set ICMB Address" },
	{ 0x04,	"Set Bridge ProxyAddress" },
	{ 0x05,	"Get Bridge Statistics" },
	{ 0x06,	"Get ICMB Capabilities" },
	{ 0x08,	"Clear Bridge Statistics" },
	{ 0x09,	"Get Bridge Proxy Address" },
	{ 0x0a,	"Get ICMB Connector Info" },
	{ 0x0b,	"Get ICMB Connection ID" },
	{ 0x0c,	"Send ICMB Connection ID" },
	/* ICMB Discovery Commands */
	{ 0x10,	"Prepare For Discovery" },
	{ 0x11,	"Get Addresses" },
	{ 0x12,	"Set Discovered" },
	{ 0x13,	"Get Chassis Device ID" },
	{ 0x14,	"Set Chassis Device ID" },
	/* ICMB Bridging Commands */
	{ 0x20,	"Bridge Request" },
	{ 0x21,	"Bridge Message" },
	/* ICMB Event Commands */
	{ 0x30,	"Get Event Count" },
	{ 0x31,	"Set Event Destination" },
	{ 0x32,	"Set Event Reception State" },
	{ 0x33,	"Send ICMB Event Message" },
	{ 0x34,	"Get Event Destination" },
	{ 0x35,	"Get Event Reception State" },
	{ 0x00,	NULL },
};

static const value_string ipmi_se_cmd_vals[] = {
	/* Event Commands */
	{ 0x00,	"Set Event Receiver" },
	{ 0x01,	"Get Event Receiver" },
	{ 0x02,	"Platform Event Message" },
	/* PEF and Alerting Commands */
	{ 0x10,	"Get PEF Capabilities" },
	{ 0x11,	"Arm PEF Postpone Timer" },
	{ 0x12,	"Set PEF Config Params" },
	{ 0x13,	"Get PEF Config Params" },
	{ 0x14,	"Set Last Processed Event ID" },
	{ 0x15,	"Get Last Processed Event ID" },
	{ 0x16,	"Alert Immediate" },
	{ 0x17,	"PET Acknowledge" },
	/* Sensor Device Commands */
	{ 0x20,	"Get Device SDR Info" },
	{ 0x21,	"Get Device SDR" },
	{ 0x22,	"Reserve Device SDR Repository" },
	{ 0x23,	"Get Sensor Reading Factors" },
	{ 0x24,	"Set Sensor Hysteresis" },
	{ 0x25,	"Get Sensor Hysteresis" },
	{ 0x26,	"Set Sensor Threshold" },
	{ 0x27,	"Get Sensor Threshold" },
	{ 0x28,	"Set Sensor Event Enable" },
	{ 0x29,	"Get Sensor Event Enable" },
	{ 0x2a,	"Re-arm Sensor Events" },
	{ 0x2b,	"Get Sensor Event Status" },
	{ 0x2d,	"Get Sensor Reading" },
	{ 0x2e,	"Set Sensor Type" },
	{ 0x2f,	"Get Sensor Type" },
	{ 0x00,	NULL },
};

static const value_string ipmi_storage_cmd_vals[] = {
	/* FRU Device Commands */
	{ 0x10,	"Get FRU Inventory Area Info" },
	{ 0x11,	"Read FRU Data" },
	{ 0x12,	"Write FRU Data" },
	/* SDR Device Commands */
	{ 0x20,	"Get SDR Repository Info" },
	{ 0x21,	"Get SDR Repository Allocation Info" },
	{ 0x22,	"Reserve SDR Repository" },
	{ 0x23,	"Get SDR" },
	{ 0x24,	"Add SDR" },
	{ 0x25,	"Partial Add SDR" },
	{ 0x26,	"Delete SDR" },
	{ 0x27,	"Clear SDR Repository" },
	{ 0x28,	"Get SDR Repository Time" },
	{ 0x29,	"Set SDR Repository Time" },
	{ 0x2a,	"Enter SDR Repository Update Mode" },
	{ 0x2b,	"Exit SDR Repository Update Mode" },
	{ 0x2c,	"Run Initialization Agent" },
	/* SEL Device Commands */
	{ 0x40,	"Get SEL Info" },
	{ 0x41,	"Get SEL Allocation Info" },
	{ 0x42,	"Reserve SEL" },
	{ 0x43,	"Get SEL Entry" },
	{ 0x44,	"Add SEL Entry" },
	{ 0x45,	"Partial Add SEL Entry" },
	{ 0x46,	"Delete SEL Entry" },
	{ 0x47,	"Clear SEL" },
	{ 0x48,	"Get SEL Time" },
	{ 0x49,	"Set SEL Time" },
	{ 0x5a,	"Get Auxillary Log Status" },
	{ 0x5b,	"Set Auxillary Log Status" },
	{ 0x00,	NULL },
};

static const value_string ipmi_transport_cmd_vals[] = {
	/* LAN Device Commands */
	{ 0x01,	"Set LAN Config Param" },
	{ 0x02,	"Get LAN Config Param" },
	{ 0x03,	"Suspend BMC ARPs" },
	{ 0x04,	"Get IP/UDP/RMCP Statistics" },
	/* Serial/Modem Device Commands */
	{ 0x10,	"Set Serial/Modem Config" },
	{ 0x11,	"Get Serial/Modem Config" },
	{ 0x12,	"Get Serial/Modem Mux" },
	{ 0x13,	"Get TAP Response Codes" },
	{ 0x14,	"Set PPP UDP Proxy Transmit Data" },
	{ 0x15,	"Get PPP UDP Proxy Transmit Data" },
	{ 0x16,	"Send PPP UDP Proxy Packet" },
	{ 0x17,	"Get PPP UDP Proxy Data" },
	{ 0x18,	"Serial/Modem Connection Active" },
	{ 0x19,	"Callback" },
	{ 0x1a,	"Set User Callback Options" },
	{ 0x1b,	"Get User Callback Options" },
	{ 0x00,	NULL },
};

static const value_string ipmi_app_cmd_vals[] = {
	/* Device "Global" Commands */
	{ 0x01,	"Get Device ID" },
	{ 0x02,	"Cold Reset" },
	{ 0x03,	"Warm Reset" },
	{ 0x04,	"Get Self Test Results" },
	{ 0x05,	"Manufacturing Test On" },
	{ 0x06,	"Set ACPI Power State" },
	{ 0x07,	"Get ACPI Power State" },
	{ 0x08,	"Get Device GUID" },
	/* BMC Watchdog Timer Commands */
	{ 0x22,	"Reset Watchdog Timer" },
	{ 0x24,	"Set Watchdog Timer" },
	{ 0x25,	"Get Watchdog Timer" },
	/* BMC Device and Messaging Commands */
	{ 0x2e,	"Set BMC Global Enables" },
	{ 0x2f,	"Get BMC Global Enables" },
	{ 0x30,	"Clear Message Flags" },
	{ 0x31,	"Get Message Flags" },
	{ 0x32,	"Enable Message Channel Receive" },
	{ 0x33,	"Get Message" },
	{ 0x34,	"Send Message" },
	{ 0x35,	"Read Event Message Buffer" },
	{ 0x36,	"Get BT Interface Capabilities" },
	{ 0x37,	"Get System GUID" },
	{ 0x38,	"Get Channel Auth Capabilities" },
	{ 0x39,	"Get Session Challenge" },
	{ 0x3a,	"Activate Session" },
	{ 0x3b,	"Set Session Privilege Level" },
	{ 0x3c,	"Close Session" },
	{ 0x3d,	"Get Session Info" },
	{ 0x3e,	"unassigned" },
	{ 0x3f,	"Get AuthCode" },
	{ 0x40,	"Set Channel Access" },
	{ 0x41,	"Get Channel Access" },
	{ 0x42,	"Get Channel Info" },
	{ 0x43,	"Set User Access" },
	{ 0x44,	"Get User Access" },
	{ 0x45,	"Set User Name" },
	{ 0x46,	"Get User Name" },
	{ 0x47,	"Set User Password" },
	{ 0x52,	"Master Write-Read" },
	{ 0x00,	NULL },
};

/* ipmi_picmg_cmd_vals[] array added by lane  */
static const value_string ipmi_picmg_cmd_vals[] = {	
	{ 0x00,	"Get PICMG Properties" },
	{ 0x01,	"Get Address Info" },
	{ 0x02,	"Get Shelf Address Info" },
	{ 0x03,	"Set Shelf Address Info" },
	{ 0x04,	"FRU Control" },
	{ 0x05,	"Get FRU LED Properties" },
	{ 0x06,	"Get LED Color Capabilities" },
	{ 0x07,	"Set FRU LED State" },
	{ 0x08,	"Get FRU LED State" },
	{ 0x09,	"Set IPMB State" },
	{ 0x0a,	"Set FRU Activation Policy" },
	{ 0x0b,	"Get FRU Activation Policy" },
	{ 0x0c,	"Set FRU Activation" },
	{ 0x0d,	"Get Device Locator Record Id" },
	{ 0x0e,	"Set Port State" },
	{ 0x0f,	"Get Port State" },
	{ 0x10,	"Compute Power Properties" },
	{ 0x11,	"Set Power Level" },
	{ 0x12,	"Get Power Level" },
	{ 0x13,	"Renegotiate Power" },
	{ 0x14,	"Get Fan Speed Properties" },
	{ 0x15,	"Set Fan Level" },
	{ 0x16,	"Get Fan Level" },
	{ 0x17,	"Bused Resource" },
	{ 0x18,	"Get IPMB Link Info" },	
	{ 0x00,	NULL },
};

/***********************************************************************/

/********* Sensor/Event, NetFN = 0x04 *********/

/* Platform Event Message, added by lane */
static const value_string cmd_PEM_EvMRev_vals[] = {
	{ 0x03,	"IPMI V1.0" },
	{ 0x04,	"IPMI V1.5" },
	{ 0x00,	NULL },
};

static const value_string cmd_PEM_SensorType_vals[] = {
	{ 0x00,	"Reserved" },
	{ 0x01,	"Temperature" },
	{ 0x02,	"Voltage" },
	{ 0x03,	"Current" },
	{ 0x04,	"Fan" },
	{ 0x05,	"Physical Security (Chassis Intrusion)" },
	{ 0x06,	"Platform Security Violation Attempt" },
	{ 0x07,	"Processor" },
	{ 0x08,	"Power Supply" },
	{ 0x09,	"Power Unit" },
	{ 0x0a,	"Cooling Device" },
	{ 0x0b,	"Other Units-based Sensor (per units given in SDR)" },
	{ 0x0c,	"Memory" },
	{ 0x0d,	"Drive Slot (Bay)" },
	{ 0x0e,	"POST Memory Resize" },
	{ 0x0f,	"System Firmware Progress (formerly POST Error)" },
	{ 0x10,	"Event Logging Disabled" },
	{ 0x11,	"Watchdog 1" },
	{ 0x12,	"System Event" },
	{ 0x13,	"Critical Interrupt" },
	{ 0x14,	"Button" },
	{ 0x15,	"Module / Board" },
	{ 0x16,	"Microcontroller / Coprocessor" },
	{ 0x17,	"Add-in Card" },
	{ 0x18,	"Chassis" },
	{ 0x19,	"Chip Set" },
	{ 0x1a,	"Other FRU" },
	{ 0x1b,	"Cable / Interconnect" },
	{ 0x1c,	"Terminator" },
	{ 0x1d,	"System Boot Initiated" },
	{ 0x1e,	"Boot Error" },
	{ 0x1f,	"OS Boot" },
	{ 0x20,	"OS Critical Stop" },
	{ 0x21,	"Slot /Connector" },
	{ 0x22,	"System ACPI Power State" },
	{ 0x23,	"Watchdog 2" },
	{ 0x24,	"Platform Alert" },
	{ 0x25,	"Entity Presence" },
	{ 0x26,	"Monitor ASIC / IC" },
	{ 0x27,	"LAN" },
	{ 0x28,	"Management Subsystem Health" },
	{ 0x29,	"Battery" },
	{ 0xf0,	"Hot Swap Event" },
	{ 0x00,	NULL },
};

static const value_string cmd_PEM_EventDir_vals[] = {
	{ 0x00,	"Assertion Event" },
	{ 0x01,	"Deassertion Event" },
	{ 0x00,	NULL },
};

static const value_string cmd_PEM_EventData1_threshold_76_vals[] = {
	{ 0x00,	"unspecified byte 2" },
	{ 0x01,	"trigger reading in byte 2" },
	{ 0x02,	"OEM code in byte 2" },
	{ 0x03,	"sensor-specific event extension code in byte 2" },
	{ 0x00,	NULL },
};

static const value_string cmd_PEM_EventData1_threshold_54_vals[] = {
	{ 0x00,	"unspecified byte 3" },
	{ 0x01,	"trigger reading in byte 3" },
	{ 0x02,	"OEM code in byte 3" },
	{ 0x03,	"sensor-specific event extension code in byte 3" },
	{ 0x00,	NULL },
};

static const value_string cmd_PEM_EventData1_discrete_76_vals[] = {
	{ 0x00,	"unspecified byte 2" },
	{ 0x01,	"previous state and/or severity in byte 2" },
	{ 0x02,	"OEM code in byte 2" },
	{ 0x03,	"sensor-specific event extension code in byte 3" },
	{ 0x00,	NULL },
};

static const value_string cmd_PEM_EventData1_discrete_54_vals[] = {
	{ 0x00,	"unspecified byte 3" },
	{ 0x01,	"reserved" },
	{ 0x02,	"OEM code in byte 3" },
	{ 0x03,	"sensor-specific event extension code in byte 3" },
	{ 0x00,	NULL },
};

static const value_string cmd_PEM_EventData1_OEM_76_vals[] = {
	{ 0x00,	"unspecified byte 2" },
	{ 0x01,	"previous state and/or severity in byte 2" },
	{ 0x02,	"OEM code in byte 2" },
	{ 0x03,	"sensor-specific event extension code in byte 3" },
	{ 0x00,	NULL },
};

static const value_string cmd_PEM_EventData1_OEM_54_vals[] = {
	{ 0x00,	"unspecified byte 3" },
	{ 0x01,	"reserved" },
	{ 0x02,	"OEM code in byte 3" },
	{ 0x03,	"sensor-specific event extension code in byte 3" },
	{ 0x00,	NULL },
};

static const value_string cmd_PEM_HotSwapEvent_StateChangeCause_vals[] = {
	{ 0x00,	"Normal State Change" },
	{ 0x01,	"Change Commanded by Shelf Manager with Set FRU Activation" },
	{ 0x02,	"State Change due to operator Changing a Handle Switch" },
	{ 0x03,	"State Change due to FRU programmatic action" },
	{ 0x04,	"Communication Lost or Regained" },
	{ 0x05,	"Communication Lost or Regained-locally detected" },
	{ 0x06,	"Suprise State Change due to extraction" },
	{ 0x07,	"State Change due to provided information" },
	{ 0x08,	"Invalid Hardware Address Detected" },
	{ 0x09,	"UnexpectedDeactivation" },
	{ 0x0a,	"Reserved" },
	{ 0x0b,	"Reserved" },
	{ 0x0c,	"Reserved" },
	{ 0x0d,	"Reserved" },
	{ 0x0e,	"Reserved" },
	{ 0x0f,	"State Change, Cause Unknow" },
	{ 0x00,	NULL },
};

static const value_string cmd_PEM_HotSwapEvent_state_vals[] = {
	{ 0x00,	"M0 - FRU Not Installed" },
	{ 0x01,	"M1 - FRU Inactive" },
	{ 0x02,	"M2 - FRU Activation Request" },
	{ 0x03,	"M3 - FRU Activation In Progress" },
	{ 0x04,	"M4 - FRU Active" },
	{ 0x05,	"M5 - FRU Deactivation Request" },
	{ 0x06,	"M6 - FRU Deactivation In Progress" },
	{ 0x07,	"M7 - FRU Communication Lost" },
	{ 0x08,	"Reserved" },
	{ 0x09,	"Reserved" },
	{ 0x0a,	"Reserved" },
	{ 0x0b,	"Reserved" },
	{ 0x0c,	"Reserved" },
	{ 0x0d,	"Reserved" },
	{ 0x0e,	"Reserved" },
	{ 0x0f,	"Reserved" },
	{ 0x00,	NULL },
};

/* Get Device SDR Info, added by lane */
static const value_string cmd_GetDeviceSDRInfo_data_Flag_Dynamicpopulation_vals[] = {
	{ 0x00,	"static sensor population" },
	{ 0x01,	"dynamic sensor population" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetDeviceSDRInfo_data_Flag_DeviceLUNs_vals[] = {
	{ 0x00,	"has no sensors" },
	{ 0x01,	"has sensors" },
	{ 0x00,	NULL },
};

/* Get Device SDR, added by lane */
static const value_string cmd_GetDeviceSDR_data_BytesToRead_vals[] = {
	{ 0xff,	"Read entire record" },
	{ 0x00,	NULL },
};

/* Set Sensor Thresholds, added by lane */
static const value_string cmd_SetSensorThresholds_data_ControlByte_Bit_vals[] = {
	{ 0x00,	"Ignored" },
	{ 0x01,	"Set" },
	{ 0x00,	NULL },
};

/* Get Sensor Thresholds, added by lane */
static const value_string cmd_GetSensorThresholds_data_ControlByte_Bit_vals[] = {
	{ 0x00,	"Ignored" },
	{ 0x01,	"Readable" },
	{ 0x00,	NULL },
};

/* Get Sensor Reading, added by lane */
static const value_string cmd_GetSensorReading_data_ResponseDataByte2_Bit7_vals[] = {
	{ 0x00,	"All Event Messages disabled from this sensor" },
	{ 0x01,	"All Event Messages enabled from this sensor" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetSensorReading_data_ResponseDataByte2_Bit6_vals[] = {
	{ 0x00,	"sensor scanning disabled" },
	{ 0x01,	"sensor scanning enabled" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetSensorReading_data_ResponseDataByte2_Bit5_vals[] = {
	{ 0x00,	"update sensor status completed" },
	{ 0x01,	"initial update in progress" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetSensorReading_data_ResponseDataByte3_Bit7_vals[] = {
	{ 0x00,	"state 7 has not been asserted" },
	{ 0x01,	"state 7 asserted" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetSensorReading_data_ResponseDataByte3_Bit6_vals[] = {
	{ 0x00,	"state 6 has not been asserted" },
	{ 0x01,	"state 6 asserted" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetSensorReading_data_ResponseDataByte3_Bit5_vals[] = {
	{ 0x00,	"state 5 has not been asserted" },
	{ 0x01,	"state 5 asserted" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetSensorReading_data_ResponseDataByte3_Bit4_vals[] = {
	{ 0x00,	"state 4 has not been asserted" },
	{ 0x01,	"state 4 asserted" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetSensorReading_data_ResponseDataByte3_Bit3_vals[] = {
	{ 0x00,	"state 3 has not been asserted" },
	{ 0x01,	"state 3 asserted" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetSensorReading_data_ResponseDataByte3_Bit2_vals[] = {
	{ 0x00,	"state 2 has not been asserted" },
	{ 0x01,	"state 2 asserted" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetSensorReading_data_ResponseDataByte3_Bit1_vals[] = {
	{ 0x00,	"state 1 has not been asserted" },
	{ 0x01,	"state 1 asserted" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetSensorReading_data_ResponseDataByte3_Bit0_vals[] = {
	{ 0x00,	"state 0 has not been asserted" },
	{ 0x01,	"state 0 asserted" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetSensorReading_data_ResponseDataByte4_Bit7_vals[] = {
	{ 0x00,	"Reserved, Shall returned as 1b" },
	{ 0x01,	"Reserved, Returned as 1b" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetSensorReading_data_ResponseDataByte4_Bit6_vals[] = {
	{ 0x00,	"state 14 has not been asserted" },
	{ 0x01,	"state 14 asserted" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetSensorReading_data_ResponseDataByte4_Bit5_vals[] = {
	{ 0x00,	"state 13 has not been asserted" },
	{ 0x01,	"state 13 asserted" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetSensorReading_data_ResponseDataByte4_Bit4_vals[] = {
	{ 0x00,	"state 12 has not been asserted" },
	{ 0x01,	"state 12 asserted" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetSensorReading_data_ResponseDataByte4_Bit3_vals[] = {
	{ 0x00,	"state 11 has not been asserted" },
	{ 0x01,	"state 11 asserted" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetSensorReading_data_ResponseDataByte4_Bit2_vals[] = {
	{ 0x00,	"state 10 has not been asserted" },
	{ 0x01,	"state 10 asserted" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetSensorReading_data_ResponseDataByte4_Bit1_vals[] = {
	{ 0x00,	"state 9 has not been asserted" },
	{ 0x01,	"state 9 asserted" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetSensorReading_data_ResponseDataByte4_Bit0_vals[] = {
	{ 0x00,	"state 8 has not been asserted" },
	{ 0x01,	"state 8 asserted" },
	{ 0x00,	NULL },
};


static const value_string cmd_GetSensorReading_data_ResponseDataByte3_Bit5_threshold_vals[] = {
	{ 0x00,	"unknown" },
	{ 0x01,	"at or above upper non-recoverable threshold" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetSensorReading_data_ResponseDataByte3_Bit4_threshold_vals[] = {
	{ 0x00,	"unknown" },
	{ 0x01,	"at or above upper critical threshold" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetSensorReading_data_ResponseDataByte3_Bit3_threshold_vals[] = {
	{ 0x00,	"unknown" },
	{ 0x01,	"at or above upper non-critical threshold" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetSensorReading_data_ResponseDataByte3_Bit2_threshold_vals[] = {
	{ 0x00,	"unknown" },
	{ 0x01,	"at or below lower non-recoverable threshold" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetSensorReading_data_ResponseDataByte3_Bit1_threshold_vals[] = {
	{ 0x00,	"unknown" },
	{ 0x01,	"at or below lower critical threshold" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetSensorReading_data_ResponseDataByte3_Bit0_threshold_vals[] = {
	{ 0x00,	"unknown" },
	{ 0x01,	"at or below lower non-critical threshold" },
	{ 0x00,	NULL },
};


/********* APP, NetFN = 0x06 *********/

/* Get Device ID data, added by lane*/
static const value_string cmd_GetDeviceID_data_DeviceSDR_vals[] = {
	{ 0x00,	"Device provides device SDR" },
	{ 0x01,	"Device does not provide device SDR" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetDeviceID_Data_DeviceRevision_vals[] = {
	{ 0x00,	"0" },
	{ 0x01,	"1" },
	{ 0x02,	"2" },
	{ 0x03,	"3" },
	{ 0x04,	"4" },
	{ 0x05,	"5" },
	{ 0x06,	"6" },
	{ 0x07,	"7" },
	{ 0x08,	"8" },
	{ 0x09,	"9" },
	{ 0x0a,	"10" },
	{ 0x0b,	"11" },
	{ 0x0c,	"12" },
	{ 0x0d,	"13" },
	{ 0x0e,	"14" },      
	{ 0x0f,	"15" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetDeviceID_data_DeviceAvailable_vals[] = {
	{ 0x00,	"normal operation" },
	{ 0x01,	"device firmware" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetDeviceID_Data_IPMIRevision_vals[] = {
	{ 0x01,	"V1.0" },
	{ 0x11,	"V1.1" },
	{ 0x21,	"V1.2" },
	{ 0x31,	"V1.3" },
	{ 0x41,	"V1.4" },
	{ 0x51,	"V1.5" },
	{ 0x61,	"V1.6" },
	{ 0x71,	"V1.7" },
	{ 0x81,	"V1.8" },
	{ 0x91,	"V1.9" },
	{ 0x02,	"V2.0" },
	{ 0x12,	"V2.1" },
	{ 0x22,	"V2.2" },
	{ 0x32,	"V2.3" },
	{ 0x42,	"V2.4" },      
	{ 0x52,	"V2.5" },
	{ 0x62,	"V2.6" },
	{ 0x72,	"V2.7" },
	{ 0x82,	"V2.8" },
	{ 0x92,	"V2.9" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetDeviceID_data_ADS_vals[] = {
	{ 0x00,	"No" },
	{ 0x01,	"Yes" },
	{ 0x00,	NULL },
};


/********* Storage, NetFN = 0x0a *********/

/* Get FRU Inventory Area Info, added by lane */
static const value_string cmd_GetFRUInventoryAreaInfo_Data_ResponseDataByte4_Bit0_vals[] = {
	{ 0x00,	"By bytes" },
	{ 0x01,	"By words" },
	{ 0x00,	NULL },
};

/* Get SEL Info, added by lane */
static const value_string cmd_GetSELInfo_Data_SELVersion_vals[] = {
	{ 0x01,	"V1.0" },
	{ 0x11,	"V1.1" },
	{ 0x21,	"V1.2" },
	{ 0x31,	"V1.3" },
	{ 0x41,	"V1.4" },
	{ 0x51,	"V1.5" },
	{ 0x61,	"V1.6" },
	{ 0x71,	"V1.7" },
	{ 0x81,	"V1.8" },
	{ 0x91,	"V1.9" },
	{ 0x02,	"V2.0" },
	{ 0x12,	"V2.1" },
	{ 0x22,	"V2.2" },
	{ 0x32,	"V2.3" },
	{ 0x42,	"V2.4" },      
	{ 0x52,	"V2.5" },
	{ 0x62,	"V2.6" },
	{ 0x72,	"V2.7" },
	{ 0x82,	"V2.8" },
	{ 0x92,	"V2.9" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetSELInfo_Data_OperationSupport_Bit7_vals[] = {
	{ 0x00,	"Ok" },
	{ 0x01,	"Events have been dropped due to lack of space in the SEL" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetSELInfo_Data_OperationSupport_Bit3to0_vals[] = {
	{ 0x00,	"Don't Support" },
	{ 0x01,	"Support" },
	{ 0x00,	NULL },
};

/* Clear SEL, added by lane */
static const value_string cmd_ClearSEL_Data_Byte6_vals[] = {
	{ 0x00,	"get erasure status" },
	{ 0xaa,	"initiate erase" },
	{ 0x00,	NULL },
};

static const value_string cmd_ClearSEL_Data_ErasureProgress_EraProg_vals[] = {
	{ 0x00,	"erasure in progress" },
	{ 0x01,	"erase completed" },
	{ 0x00,	NULL },
};



/********* PICMG, NetFN = 0X2c *********/

/* Get PICMG Properties data, added by lane */
static const value_string cmd_GetPICMGProperties_data_PICMGExtensionVersion_vals[] = {
	{ 0x12,	"V2.1" },
	{ 0x00,	NULL },
};

/* FRU Control, added by lane */
static const value_string cmd_FRUControl_data_FRUControlOption_vals[] = {
	{ 0x00,	"Cold Reset" },
	{ 0x01,	"Warm Reset" },
	{ 0x02,	"Graceful Reboot" },
	{ 0x03,	"Issue Diagnostic Interrupt" },
	{ 0x04,	"Reserved" },
	{ 0xff,	"Reserved" },
	{ 0x00,	NULL },
};

/* Get FRU Led Properties, added by lane */
static const value_string cmd_GetFRULedProperties_data_LedProperties_LED3_vals[] = {
	{ 0x00,	"FRU can't control LED3" },
	{ 0x01,	"FRU can control LED3" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetFRULedProperties_data_LedProperties_LED2_vals[] = {
	{ 0x00,	"FRU can't control LED2" },
	{ 0x01,	"FRU can control LED2" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetFRULedProperties_data_LedProperties_LED1_vals[] = {
	{ 0x00,	"FRU can't control LED1" },
	{ 0x01,	"FRU can control LED1" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetFRULedProperties_data_LedProperties_BLUELED_vals[] = {
	{ 0x00,	"FRU can't control Blue LED" },
	{ 0x01,	"FRU can control Blue LED" },
	{ 0x00,	NULL },
};

/* Get Led Color Capabilities, added by lane */
static const value_string cmd_GetLedColorCapabilities_data_LEDColorCapabilities_vals[] = {
	{ 0x00,	"Don't Support" },
	{ 0x01,	"Support" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetLedColorCapabilities_data_DefaultLEDColor_vals[] = {
	{ 0x00,	"Reserved" },
	{ 0x01,	"BLUE" },
	{ 0x02,	"RED" },
	{ 0x03,	"GREEN" },
	{ 0x04,	"AMBER" },
	{ 0x05,	"ORANGE" },
	{ 0x06,	"WHITE" },
	{ 0x07,	"Reserved" },
	{ 0x08,	"Reserved" },
	{ 0x09,	"Reserved" },
	{ 0x0a,	"Reserved" },
	{ 0x0b,	"Reserved" },
	{ 0x0c,	"Reserved" },
	{ 0x0d,	"Reserved" },
	{ 0x0e,	"Reserved" },
	{ 0x0f,	"Reserved" },
	{ 0x00,	NULL },
};

/* Set FRU Activation data, added by lane */
static const value_string cmd_SetFRUActivation_data_FRUActivationDeactivation_vals[] = {
	{ 0x00,	"Deactivate FRU" },
	{ 0x01,	"Activate FRU" },
	{ 0x00,	NULL },
};

/* Set FRU Led State, added by lane */
static const value_string cmd_SetFRULedState_data_LEDID_vals[] = {
	{ 0x00,	"BLUE LED (Bottom of Board)" },
	{ 0x01,	"LED1 Topmost" },
	{ 0x02,	"LED2 Second from top" },
	{ 0x03,	"LED3 Third from top" },
	{ 0xff,	"Lamp Test" },
	{ 0x00,	NULL },
};

static const value_string cmd_SetFRULedState_data_LEDFunction_vals[] = {
	{ 0x00,	"LED off override" },
	{ 0x01,	"LED BLINKING override" },
	/* ... */
	{ 0xfa,	"LED BLINKING override" },
	{ 0xfb,	"LAMP TEST state" },
	{ 0xfc,	"LED state restored to Local Control state" },
	{ 0xfd,	"Reserved" },
	{ 0xfe,	"Reserved" },
	{ 0xff,	"LED on override" },
	{ 0x00,	NULL },
};

static const value_string cmd_SetFRULedState_data_Color_ColorVal_vals[] = {
	{ 0x00,	"Reserved" },
	{ 0x01,	"Use BLUE" },
	{ 0x02,	"Use RED" },
	{ 0x03,	"Use GREEN" },
	{ 0x04,	"Use AMBER" },
	{ 0x05,	"Use ORANGE" },
	{ 0x06,	"Use WHITE" },
	{ 0x07,	"Reserved" },
	{ 0x08,	"Reserved" },
	{ 0x09,	"Reserved" },
	{ 0x0a,	"Reserved" },
	{ 0x0b,	"Reserved" },
	{ 0x0c,	"Reserved" },
	{ 0x0d,	"Reserved" },
	{ 0x0e,	"Do not Change" },
	{ 0x0f,	"Use default color" },
	{ 0x00,	NULL },
};

/* Get FRU Led State, added by lane */
static const value_string cmd_GetFRULedState_data_LEDID_vals[] = {
	{ 0x00,	"BLUE LED (Bottom of Board)" },
	{ 0x01,	"LED1 Topmost" },
	{ 0x02,	"LED2 Second from top" },
	{ 0x03,	"LED3 Third from top" },
	{ 0xff,	"Lamp Test" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetFRULedState_data_LEDState_Bit21_vals[] = {
	{ 0x00,	"Disabled" },
	{ 0x01,	"Enabled" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetFRULedState_data_LEDState_Bit0_vals[] = {
	{ 0x00,	"No" },
	{ 0x01,	"Yes" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetFRULedState_data_LocalControlLEDFunction_vals[] = {
	{ 0x00,	"LED is off" },
	{ 0x01,	"LED is BLINKING" },
	/* ... */
	{ 0xfa,	"LED is BLINKING" },
	{ 0xfb,	"Reserved" },
	{ 0xfc,	"Reserved" },
	{ 0xfd,	"Reserved" },
	{ 0xfe,	"Reserved" },
	{ 0xff,	"LED is on " },
	{ 0x00,	NULL },
};

static const value_string cmd_GetFRULedState_data_ColorVal_vals[] = {
	{ 0x00,	"Reserved" },
	{ 0x01,	"Use BLUE" },
	{ 0x02,	"Use RED" },
	{ 0x03,	"Use GREEN" },
	{ 0x04,	"Use AMBER" },
	{ 0x05,	"Use ORANGE" },
	{ 0x06,	"Use WHITE" },
	{ 0x07,	"Reserved" },
	{ 0x08,	"Reserved" },
	{ 0x09,	"Reserved" },
	{ 0x0a,	"Reserved" },
	{ 0x0b,	"Reserved" },
	{ 0x0c,	"Reserved" },
	{ 0x0d,	"Reserved" },
	{ 0x0e,	"Reserved" },
	{ 0x0f,	"Reserved" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetFRULedState_data_OverrideStateLEDFunction_vals[] = {
	{ 0x00,	"LED Override State is off" },
	{ 0x01,	"LED Override State is BLINKING" },
	/* ... */
	{ 0xfa,	"LED Override State is BLINKING" },
	{ 0xfb,	"Reserved" },
	{ 0xfc,	"Reserved" },
	{ 0xfd,	"Reserved" },
	{ 0xfe,	"Reserved" },
	{ 0xff,	"LED Override State is on " },
	{ 0x00,	NULL },
};

/* Set FRU Activation Policy, added by lane */
static const value_string cmd_SetFRUActivationPolicy_data_PFRUActivationPolicyMaskBit_Bit1_vals[] = {
	{ 0x00,	"Bit 1 in Byte 4 of command will be ignored" },
	{ 0x01,	"Bit 1 in Byte 4 of command will affect the Deactivation-Locked bit" },
	{ 0x00,	NULL },
};

static const value_string cmd_SetFRUActivationPolicy_data_PFRUActivationPolicyMaskBit_Bit0_vals[] = {
	{ 0x00,	"Bit 0 in Byte 4 of command will be ignored" },
	{ 0x01,	"Bit 0 in Byte 4 of command will affect the Locked bit" },
	{ 0x00,	NULL },
};

static const value_string cmd_SetFRUActivationPolicy_data_PFRUActivationPolicySetBit_Bit1_vals[] = {
	{ 0x00,	"FRU can transition from M4 to M5" },
	{ 0x01,	"FRU can not transition from M4 to M5" },
	{ 0x00,	NULL },
};

static const value_string cmd_SetFRUActivationPolicy_data_PFRUActivationPolicySetBit_Bit0_vals[] = {
	{ 0x00,	"FRU can transition from M1 to M2" },
	{ 0x01,	"FRU can not transition from M1 to M2" },
	{ 0x00,	NULL },
};

static const value_string cmd_SetFRUActivationPolicy_data_PFRUActivationPolicySetBit_Bit1_ignored_vals[] = {
	{ 0x00,	"ignored, because Bit 1 of Byte 3 = 0" },
	{ 0x01,	"ignored, because Bit 1 of Byte 3 = 0" },
	{ 0x00,	NULL },
};

static const value_string cmd_SetFRUActivationPolicy_data_PFRUActivationPolicySetBit_Bit0_ignored_vals[] = {
	{ 0x00,	"ignored, because Bit 0 of Byte 3 = 0" },
	{ 0x01,	"ignored, because Bit 0 of Byte 3 = 0" },
	{ 0x00,	NULL },
};

/* Get FRU Activation Policy, added by lane */
static const value_string cmd_GetFRUActivationPolicy_data_FRUActivationPolicy_Bit1_vals[] = {
	{ 0x00,	"FRU is not Deactivation-Locked" },
	{ 0x01,	"FRU is Deactivation-Locked" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetFRUActivationPolicy_data_FRUActivationPolicy_Bit0_vals[] = {
	{ 0x00,	"FRU is not Locked" },
	{ 0x01,	"FRU is Locked" },
	{ 0x00,	NULL },
};

/* Set Power Level data, added by lane */
static const value_string cmd_SetPowerLevel_data_PowerLevel_vals[] = {
	{ 0x00,	"Power Off" },
	{ 0x01,	"Select the power level" },
	{ 0x02,	"Select the power level" },
	{ 0x03,	"Select the power level" },
	{ 0x04,	"Select the power level" },
	{ 0x05,	"Select the power level" },
	{ 0x06,	"Select the power level" },
	{ 0x07,	"Select the power level" },
	{ 0x08,	"Select the power level" },
	{ 0x09,	"Select the power level" },
	{ 0x0a,	"Select the power level" },
	{ 0x0b,	"Select the power level" },
	{ 0x0c,	"Select the power level" },
	{ 0x0d,	"Select the power level" },
	{ 0x0e,	"Select the power level" },
	{ 0x0f,	"Select the power level" },
	{ 0x10,	"Select the power level" },
	{ 0x11,	"Select the power level" },
	{ 0x12,	"Select the power level" },
	{ 0x13,	"Select the power level" },
	{ 0x14,	"Select the power level" },
	{ 0xff,	"Do not change current power level" },
	{ 0x00,	NULL },
};

static const value_string cmd_SetPowerLevel_data_SetPresentLevelsToDesiredLevels_vals[] = {
	{ 0x00,	"Do not change present power level" },
	{ 0x01,	"Copy Present Levels To Desired Levels" },
	{ 0x00,	NULL },
};

/* Get Power Level data, added by lane */
static const value_string cmd_GetPowerLevel_data_PowerType_vals[] = {
	{ 0x00,	"Steady state power draw levels" },
	{ 0x01,	"Desired steady state draw levels" },
	{ 0x02,	"Early power draw levels" },
	{ 0x03,	"Desired early levels" },
	{ 0x00,	NULL },
};

static const value_string cmd_GetPowerLevel_data_Properties_DynamicPowerCon_vals[] = {
	{ 0x00,	"FRU doesn't support dynamic reconfiguration of power" },
	{ 0x01,	"FRU support dynamic reconfiguration of power" },
	{ 0x00,	NULL },
};

/* Set Fan Level, added by lane */
static const value_string cmd_SetFanLevel_data_FanLevel_vals[] = {
	{ 0xfe,	"Emergency Shut Down" },
	{ 0xff,	"Local Control" },
	{ 0x00,	NULL },
};

/* Get Fan Level, added by lane */
static const value_string cmd_GetFanLevel_data_OverrideFanLevel_vals[] = {
	{ 0xfe,	"Fan has been placed in ' Emergency Shut Down ' by the Shelf Manager" },
	{ 0xff,	"Fan operating in Local Control mode" },
	{ 0x00,	NULL },
};


/*****************************************************************************************/


/* ipmi command dissector struct , added by lane */

typedef struct _ipmi_cmd_dissect{
  guint8  netfn;
  guint8  cmd;
  void   (*dissectfunc)(proto_tree *, proto_tree *, packet_info *, tvbuff_t *, gint *, guint8, guint8, guint8);  
} ipmi_cmd_dissect;



/* Sensor/Event  NetFN (0x04) */

static void
dissect_cmd_PlatformEventMessage(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo, tvbuff_t *tvb,
								gint *poffset, guint8 len, guint8 response, guint8 auth_offset)
{

	tvbuff_t		*next_tvb;
	proto_tree	*field_tree = NULL;
	proto_item	*tf = NULL;
	guint8 		SensorType, EventDirAndEventType, EventType, EventData1, EventData2;

	if(response) {

		return;		
	}
	else {

		/* EvMRev */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_PEM_datafield_EvMRev,
			    					tvb, (*poffset)++, 1, TRUE);
			len--;
		}

		/* Sensor Type */
		SensorType = tvb_get_guint8(tvb, auth_offset + 17) ;
		
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_PEM_datafield_SensorType,
			    					tvb, (*poffset)++, 1, TRUE);
			len--;
		}
		
		/* Sensor Number */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_PEM_datafield_SensorNumber,
			    					tvb, (*poffset)++, 1, TRUE);
			len--;
		}
	
		/* Event Dir & Event Type*/
		EventDirAndEventType = tvb_get_guint8(tvb, auth_offset + 19) ;
		EventType = EventDirAndEventType&0x7f;
		
		if (tree) {
			
				tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 		"EventDir&EventType: %s0x%02x", " ", EventDirAndEventType);
				field_tree = proto_item_add_subtree(tf, ett_cmd_PEM_EventDirAndEventType);

				proto_tree_add_item(field_tree, hf_PEM_datafield_EventDirAndEventType_EventDir,
				    					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_PEM_datafield_EventDirAndEventType_EventType,
				   					tvb, *poffset, 1, TRUE);
				(*poffset)++;
				len--;				
			}
		
		
		/* EventData 1~3 */
		switch(SensorType) {

			case 0xf0:              /* Hot Swap Event */
				/* unspecial */
				if(0x00==EventType) {


				}
				
				/* threshold  */
				if(0x01==EventType) {
					/* EventData 1*/
					EventData1 = tvb_get_guint8(tvb, auth_offset + 20) ;
					if (tree) {
						tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 			"EventData 1: %s0x%02x", " ", EventData1);

						field_tree = proto_item_add_subtree(tf, ett_cmd_PEM_EventData1_threshold);

						proto_tree_add_item(field_tree, hf_PEM_datafield_EventData1_threshold_76,
				    					tvb, *poffset, 1, TRUE);
						proto_tree_add_item(field_tree, hf_PEM_datafield_EventData1_threshold_54,
				   					tvb, *poffset, 1, TRUE);
						proto_tree_add_item(field_tree, hf_PEM_datafield_EventData1_threshold_30,
				   					tvb, *poffset, 1, TRUE);
				
						(*poffset)++;
						len--;
					}
					
					/* EventData 2*/
					if (tree&&(len!=0)) {
						proto_tree_add_item(field_tree, hf_PEM_datafield_EventData2_threshold,
				    					tvb, (*poffset)++, 1, TRUE);
						len--;
					}
					
					/* EventData 3*/
					if (tree&&(len!=0)) {
						proto_tree_add_item(ipmi_tree, hf_PEM_datafield_EventData3_threshold,
			    						tvb, (*poffset)++, 1, TRUE);
					}

				}

	
				/* discrete */
				if(((EventType>=0x02)&&(EventType<=0x0b))||(0x6f==EventType)) {
					/* EventData 1*/
					if (tree) {
						EventData1 = tvb_get_guint8(tvb, auth_offset + 20) ;
						tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 			"EventData 1: %s0x%02x", " ", EventData1);

						field_tree = proto_item_add_subtree(tf, ett_cmd_PEM_EventData1_discrete);

						proto_tree_add_item(field_tree, hf_PEM_datafield_EventData1_discrete_76,
				    					tvb, *poffset, 1, TRUE);
						proto_tree_add_item(field_tree, hf_PEM_datafield_EventData1_discrete_54,
				   					tvb, *poffset, 1, TRUE);
						proto_tree_add_item(field_tree, hf_PEM_datafield_HotSwapEvent_CurrentState,
				   					tvb, *poffset, 1, TRUE);
				
						(*poffset)++;
						len--;
					}
					
					/* EventData 2*/
					if (tree&&(len!=0)) {
						EventData2 = tvb_get_guint8(tvb, auth_offset + 21) ;
						tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 			"EventData 2: %s0x%02x", " ", EventData2);

						field_tree = proto_item_add_subtree(tf, ett_cmd_PEM_EventData2_discrete);

						proto_tree_add_item(field_tree, hf_PEM_datafield_HotSwapEvent_StateChangeCause,
				    					tvb, *poffset, 1, TRUE);
						proto_tree_add_item(field_tree, hf_PEM_datafield_HotSwapEvent_PreviousState,
				   					tvb, *poffset, 1, TRUE);
				
						(*poffset)++;
						len--;
					}
					
					/* EventData 3*/
					if (tree&&(len!=0)) {
						proto_tree_add_item(ipmi_tree, hf_PEM_datafield_HotSwapEvent_FRUDeviceID,
			    						tvb, (*poffset)++, 1, TRUE);
					}

				}
				
				/* OEM */
				if((EventType>=0x70)&&(EventType<=0x7f)) {
					/* EventData 1*/
					if (tree) {
						EventData1 = tvb_get_guint8(tvb, auth_offset + 20) ;
						tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 			"EventData 1: %s0x%02x", " ", EventData1);

						field_tree = proto_item_add_subtree(tf, ett_cmd_PEM_EventData1_OEM);

						proto_tree_add_item(field_tree, hf_PEM_datafield_EventData1_OEM_76,
				    					tvb, *poffset, 1, TRUE);
						proto_tree_add_item(field_tree, hf_PEM_datafield_EventData1_OEM_54,
				   					tvb, *poffset, 1, TRUE);
						proto_tree_add_item(field_tree, hf_PEM_datafield_EventData1_OEM_30,
				   					tvb, *poffset, 1, TRUE);
				
						(*poffset)++;
						len--;
					}
					/* EventData 2*/
					if (tree&&(len!=0)) {
						EventData2 = tvb_get_guint8(tvb, auth_offset + 21) ;
						tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 			"EventData 2: %s0x%02x", " ", EventData2);

						field_tree = proto_item_add_subtree(tf, ett_cmd_PEM_EventData2_OEM);

						proto_tree_add_item(field_tree, hf_PEM_datafield_EventData2_OEM_74,
				    					tvb, *poffset, 1, TRUE);
						proto_tree_add_item(field_tree, hf_PEM_datafield_EventData2_OEM_30,
				   					tvb, *poffset, 1, TRUE);
				
						(*poffset)++;
						len--;
					}
					/* EventData 3*/
					if (tree&&(len!=0)) {
						proto_tree_add_item(ipmi_tree, hf_PEM_datafield_EventData3_OEM,
			    						tvb, (*poffset)++, 1, TRUE);
					}

				}
				break;


			default:
				if (tree) {
					next_tvb = tvb_new_subset(tvb, *poffset, len, len);
					call_dissector(data_handle, next_tvb, pinfo, tree);
					*poffset += len;
				}
				break;
		}
		
	}

}


static void
dissect_cmd_GetDeviceSDR(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo, tvbuff_t *tvb,
								gint *poffset, guint8 len, guint8 response, guint8 auth_offset _U_)
{
	tvbuff_t	*next_tvb;

	if(response) {

		/* Record ID for next record */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_GetDeviceSDR_datafield_NextRecordID,
			    					tvb, *poffset, 1, TRUE);
			(*poffset)+=2;
			len-=2;
		}
		/* Requested bytes from record */
		if (tree) {
			next_tvb = tvb_new_subset(tvb, *poffset, len, len);
			call_dissector(data_handle, next_tvb, pinfo, tree);
			*poffset += len;
		}
		
	}
	else {

		/* Reservation ID */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_GetDeviceSDR_datafield_ReservationID,
			    					tvb, *poffset, 1, TRUE);
		(*poffset)+=2;
		}
		/* Record ID of record to Get */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_GetDeviceSDR_datafield_RecordID,
			    					tvb, *poffset, 1, TRUE);
		(*poffset)+=2;
		}
		/* Offset into record */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_GetDeviceSDR_datafield_OffsetIntoRecord,
			    					tvb, (*poffset)++, 1, TRUE);
		}
		/* Bytes to read */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_GetDeviceSDR_datafield_BytesToRead,
			    					tvb, (*poffset)++, 1, TRUE);
		}

	}

}


static void
dissect_cmd_Get_Device_SDR_Info(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo _U_, tvbuff_t *tvb,
								gint *poffset, guint8 len _U_, guint8 response, guint8 auth_offset)
{

	proto_tree	*field_tree = NULL;
	proto_item	*tf = NULL;
	guint8		flag;
	
	if(response) {

		flag = tvb_get_guint8(tvb, auth_offset + 18) ;
		
		/* Number of the Sensors in device*/
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_GetDeviceSDRInfo_datafield_SensorNumber,
			    					tvb, (*poffset)++, 1, TRUE);
		}
		/* Flag */
		if (tree) {
			
				tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 		"Flag: %s0x%02x", " ", flag);

				field_tree = proto_item_add_subtree(tf, ett_cmd_GetDeviceSDRInfo_Flag);

				proto_tree_add_item(field_tree, hf_GetDeviceSDRInfo_datafield_Flag_Dynamicpopulation,
				    					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetDeviceSDRInfo_datafield_Flag_Reserved,
				   					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetDeviceSDRInfo_datafield_Flag_DeviceLUNs3,
				    					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetDeviceSDRInfo_datafield_Flag_DeviceLUNs2,
				    					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetDeviceSDRInfo_datafield_Flag_DeviceLUNs1,
				    					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetDeviceSDRInfo_datafield_Flag_DeviceLUNs0,
				    					tvb, *poffset, 1, TRUE);
				(*poffset)++;
				
			}
		/* Sensor Population Change Indicator */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_GetDeviceSDRInfo_datafield_SensorPopulationChangeIndicator,
			    					tvb, *poffset, 1, TRUE);
			(*poffset)+=4;
		}
		
	}
	else
		return;

}

static void
dissect_cmd_Reserve_Device_SDR_Repository(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo _U_, tvbuff_t *tvb,
								gint *poffset, guint8 len _U_, guint8 response, guint8 auth_offset _U_)
{

	if(response) {

		/* Reservation ID */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_ReserveDeviceSDRRepository_datafield_ReservationID ,
			    					tvb, *poffset, 1, TRUE);
			(*poffset)+=2;
		}

	}
	else
		return;

}

static void
dissect_cmd_Set_Sensor_Hysteresis(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo _U_, tvbuff_t *tvb,
								gint *poffset, guint8 len _U_, guint8 response, guint8 auth_offset _U_)
{

	if(response) {
		return;
	}
	else {
		/* sensor number */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_SetSensorHysteresis_datafield_SensorNumber,
			    					tvb, (*poffset)++, 1, TRUE);
		}
		/* reserved for future 'hysteresis mask' definition. */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_SetSensorHysteresis_datafield_ReservedForHysteresisMask,
			    					tvb, (*poffset)++, 1, TRUE);
		}
		/* Positive-going Threshold Hysteresis Value */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_SetSensorHysteresis_datafield_PositivegoingThresholdHysteresisValue,
			    					tvb, (*poffset)++, 1, TRUE);
		}
		/* Negative-going Threshold Hysteresis Value */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_SetSensorHysteresis_datafield_NegativegoingThresholdHysteresisValue,
			    					tvb, (*poffset)++, 1, TRUE);
		}
	}

}

static void
dissect_cmd_Get_Sensor_Hysteresis(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo _U_, tvbuff_t *tvb,
								gint *poffset, guint8 len _U_, guint8 response, guint8 auth_offset _U_)
{

	if(response) {
		/* Positive-going Threshold Hysteresis Value */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_GetSensorHysteresis_datafield_PositivegoingThresholdHysteresisValue,
			    					tvb, (*poffset)++, 1, TRUE);
		}
		/* Negative-going Threshold Hysteresis Value */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_GetSensorHysteresis_datafield_NegativegoingThresholdHysteresisValue,
			    					tvb, (*poffset)++, 1, TRUE);
		}
	}
	else {
		/* sensor number */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_GetSensorHysteresis_datafield_SensorNumber,
			    					tvb, (*poffset)++, 1, TRUE);
		}
		/* reserved for future 'hysteresis mask' definition. */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_GetSensorHysteresis_datafield_ReservedForHysteresisMask,
			    					tvb, (*poffset)++, 1, TRUE);
		}
	}

}

static void
dissect_cmd_Set_Sensor_Thresholds(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo _U_, tvbuff_t *tvb,
								gint *poffset, guint8 len _U_, guint8 response, guint8 auth_offset)
{

	proto_tree	*field_tree = NULL;
	proto_item	*tf = NULL;
	guint8		ControlByte;

	if(response) {
		return;
	}
	else {
		/* sensor number */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_SetSensorThresholds_datafield_SensorNumber,
			    					tvb, (*poffset)++, 1, TRUE);
			/* Control Byte */
			ControlByte = tvb_get_guint8(tvb, auth_offset + 17) ;
			tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 		"Control Byte: %s0x%02x", " ", ControlByte);
			field_tree = proto_item_add_subtree(tf, ett_cmd_SetSensorThresholds_ControlByte);

			proto_tree_add_item(field_tree, hf_SetSensorThresholds_datafield_ControlByte_Bit76,
				    					tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_SetSensorThresholds_datafield_ControlByte_Bit5,
				   					tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_SetSensorThresholds_datafield_ControlByte_Bit4,
				    					tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_SetSensorThresholds_datafield_ControlByte_Bit3,
				    					tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_SetSensorThresholds_datafield_ControlByte_Bit2,
				    					tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_SetSensorThresholds_datafield_ControlByte_Bit1,
				    					tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_SetSensorThresholds_datafield_ControlByte_Bit0,
				    					tvb, *poffset, 1, TRUE);
			(*poffset)++;

			/* lower non-critical threshold */
			if(ControlByte&0x01) 
				proto_tree_add_item(ipmi_tree, hf_SetSensorThresholds_datafield_LowerNonCriticalThreshold,
									tvb, (*poffset)++, 1, TRUE);

			/* lower critical threshold */
			if(ControlByte&0x02) 
				proto_tree_add_item(ipmi_tree, hf_SetSensorThresholds_datafield_LowerCriticalThreshold,
									tvb, (*poffset)++, 1, TRUE);

			/* lower non-recoverable threshold */
			if(ControlByte&0x04) 
				proto_tree_add_item(ipmi_tree, hf_SetSensorThresholds_datafield_LowerNonRecoverableThreshold,
									tvb, (*poffset)++, 1, TRUE);

			/* upper non-critical threshold */
			if(ControlByte&0x08) 
				proto_tree_add_item(ipmi_tree, hf_SetSensorThresholds_datafield_UpperNonCriticalThreshold,
									tvb, (*poffset)++, 1, TRUE);

			/* upper critical threshold value */
			if(ControlByte&0x10) 
				proto_tree_add_item(ipmi_tree, hf_SetSensorThresholds_datafield_UpperCriticalThreshold,
									tvb, (*poffset)++, 1, TRUE);

			/* upper non-recoverable threshold value */
			if(ControlByte&0x20) 
				proto_tree_add_item(ipmi_tree, hf_SetSensorThresholds_datafield_UpperNonRecoverableThreshold,
									tvb, (*poffset)++, 1, TRUE);
		}

	}

}

static void
dissect_cmd_Get_Sensor_Thresholds(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo _U_, tvbuff_t *tvb,
								gint *poffset, guint8 len _U_, guint8 response, guint8 auth_offset)
{

	proto_tree	*field_tree = NULL;
	proto_item	*tf = NULL;
	guint8		ControlByte;

	if(response) {
		/* Control Byte */
		if (tree) {
			ControlByte = tvb_get_guint8(tvb, auth_offset + 17) ;
			tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 		"Control Byte: %s0x%02x", " ", ControlByte);
			field_tree = proto_item_add_subtree(tf, ett_cmd_GetSensorThresholds_ControlByte);

			proto_tree_add_item(field_tree, hf_GetSensorThresholds_datafield_ControlByte_Bit76,
				    					tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_GetSensorThresholds_datafield_ControlByte_Bit5,
				   					tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_GetSensorThresholds_datafield_ControlByte_Bit4,
				    					tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_GetSensorThresholds_datafield_ControlByte_Bit3,
				    					tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_GetSensorThresholds_datafield_ControlByte_Bit2,
				    					tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_GetSensorThresholds_datafield_ControlByte_Bit1,
				    					tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_GetSensorThresholds_datafield_ControlByte_Bit0,
				    					tvb, *poffset, 1, TRUE);
			(*poffset)++;

			/* lower non-critical threshold */
			if(ControlByte&0x01) 
				proto_tree_add_item(ipmi_tree, hf_GetSensorThresholds_datafield_LowerNonCriticalThreshold,
									tvb, (*poffset)++, 1, TRUE);

			/* lower critical threshold */
			if(ControlByte&0x02) 
				proto_tree_add_item(ipmi_tree, hf_GetSensorThresholds_datafield_LowerCriticalThreshold,
									tvb, (*poffset)++, 1, TRUE);

			/* lower non-recoverable threshold */
			if(ControlByte&0x04) 
				proto_tree_add_item(ipmi_tree, hf_GetSensorThresholds_datafield_LowerNonRecoverableThreshold,
									tvb, (*poffset)++, 1, TRUE);

			/* upper non-critical threshold */
			if(ControlByte&0x08) 
				proto_tree_add_item(ipmi_tree, hf_GetSensorThresholds_datafield_UpperNonCriticalThreshold,
									tvb, (*poffset)++, 1, TRUE);

			/* upper critical threshold value */
			if(ControlByte&0x10) 
				proto_tree_add_item(ipmi_tree, hf_GetSensorThresholds_datafield_UpperCriticalThreshold,
									tvb, (*poffset)++, 1, TRUE);

			/* upper non-recoverable threshold value */
			if(ControlByte&0x20) 
				proto_tree_add_item(ipmi_tree, hf_GetSensorThresholds_datafield_UpperNonRecoverableThreshold,
									tvb, (*poffset)++, 1, TRUE);
		}

	}
	else {
		/* sensor number */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_GetSensorThresholds_datafield_SensorNumber,
			    					tvb, (*poffset)++, 1, TRUE);
		}
	}

}

static void
dissect_cmd_Get_Sensor_Reading(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo _U_, tvbuff_t *tvb,
								gint *poffset, guint8 len, guint8 response, guint8 auth_offset)
{

	proto_tree	*field_tree = NULL;
	proto_item	*tf = NULL;
	guint8		Response_Data_Byte2, Response_Data_Byte3, Response_Data_Byte4;
	
	if(response) {

		/* Sensor reading*/
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_GetSensorReading_datafield_Sensorreading,
			    					tvb, (*poffset)++, 1, TRUE);
		}
		/* Response Data Byte2 */
		if (tree) {
			
				Response_Data_Byte2 = tvb_get_guint8(tvb, auth_offset + 18) ;
				
				tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 		"Response Data Byte 2: %s0x%02x", " ", Response_Data_Byte2);

				field_tree = proto_item_add_subtree(tf, ett_cmd_GetSensorReading_ResponseDataByte2);

				proto_tree_add_item(field_tree, hf_GetSensorReading_datafield_ResponseDataByte2_Bit7,
				    					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetSensorReading_datafield_ResponseDataByte2_Bit6,
				   					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetSensorReading_datafield_ResponseDataByte2_Bit5,
				    					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetSensorReading_datafield_ResponseDataByte2_Bit40,
				    					tvb, *poffset, 1, TRUE);
				(*poffset)++;
				
		}
		
		if(len==4) {
				/* Response Data Byte3 (For discrete reading sensors) */
				if (tree) {
			
					Response_Data_Byte3 = tvb_get_guint8(tvb, auth_offset + 19) ;
				
					tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 		"Response Data Byte 3: %s0x%02x", " ", Response_Data_Byte3);

					field_tree = proto_item_add_subtree(tf, ett_cmd_GetSensorReading_ResponseDataByte3);

					proto_tree_add_item(field_tree, hf_GetSensorReading_datafield_ResponseDataByte3_Bit7,
				    					tvb, *poffset, 1, TRUE);
					proto_tree_add_item(field_tree, hf_GetSensorReading_datafield_ResponseDataByte3_Bit6,
				   					tvb, *poffset, 1, TRUE);
					proto_tree_add_item(field_tree, hf_GetSensorReading_datafield_ResponseDataByte3_Bit5,
				    					tvb, *poffset, 1, TRUE);
					proto_tree_add_item(field_tree, hf_GetSensorReading_datafield_ResponseDataByte3_Bit4,
				    					tvb, *poffset, 1, TRUE);
					proto_tree_add_item(field_tree, hf_GetSensorReading_datafield_ResponseDataByte3_Bit3,
				   					tvb, *poffset, 1, TRUE);
					proto_tree_add_item(field_tree, hf_GetSensorReading_datafield_ResponseDataByte3_Bit2,
				    					tvb, *poffset, 1, TRUE);
					proto_tree_add_item(field_tree, hf_GetSensorReading_datafield_ResponseDataByte3_Bit1,
				    					tvb, *poffset, 1, TRUE);
					proto_tree_add_item(field_tree, hf_GetSensorReading_datafield_ResponseDataByte3_Bit0,
				    					tvb, *poffset, 1, TRUE);
					(*poffset)++;
				
				}
				/* Response Data Byte4 (For discrete reading sensors) */
				if (tree) {
			
					Response_Data_Byte4 = tvb_get_guint8(tvb, auth_offset + 20) ;
				
					tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 		"Response Data Byte 4: %s0x%02x", " ", Response_Data_Byte4);

					field_tree = proto_item_add_subtree(tf, ett_cmd_GetSensorReading_ResponseDataByte4);

					proto_tree_add_item(field_tree, hf_GetSensorReading_datafield_ResponseDataByte4_Bit7,
				    					tvb, *poffset, 1, TRUE);
					proto_tree_add_item(field_tree, hf_GetSensorReading_datafield_ResponseDataByte4_Bit6,
				   					tvb, *poffset, 1, TRUE);
					proto_tree_add_item(field_tree, hf_GetSensorReading_datafield_ResponseDataByte4_Bit5,
				    					tvb, *poffset, 1, TRUE);
					proto_tree_add_item(field_tree, hf_GetSensorReading_datafield_ResponseDataByte4_Bit4,
				    					tvb, *poffset, 1, TRUE);
					proto_tree_add_item(field_tree, hf_GetSensorReading_datafield_ResponseDataByte4_Bit3,
				   					tvb, *poffset, 1, TRUE);
					proto_tree_add_item(field_tree, hf_GetSensorReading_datafield_ResponseDataByte4_Bit2,
				    					tvb, *poffset, 1, TRUE);
					proto_tree_add_item(field_tree, hf_GetSensorReading_datafield_ResponseDataByte4_Bit1,
				    					tvb, *poffset, 1, TRUE);
					proto_tree_add_item(field_tree, hf_GetSensorReading_datafield_ResponseDataByte4_Bit0,
				    					tvb, *poffset, 1, TRUE);
					(*poffset)++;
				
				}
		}
		else {
				/* Response Data Byte3 (For threshold-based sensors) */
				if (tree) {
			
					Response_Data_Byte3 = tvb_get_guint8(tvb, auth_offset + 19) ;
				
					tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 		"Present threshold comparison status: %s0x%02x", " ", Response_Data_Byte3);

					field_tree = proto_item_add_subtree(tf, ett_cmd_GetSensorReading_ResponseDataByte3_threshold);

					proto_tree_add_item(field_tree, hf_GetSensorReading_datafield_ResponseDataByte3_Bit76_threshold,
				    					tvb, *poffset, 1, TRUE);
					proto_tree_add_item(field_tree, hf_GetSensorReading_datafield_ResponseDataByte3_Bit5_threshold,
				    					tvb, *poffset, 1, TRUE);
					proto_tree_add_item(field_tree, hf_GetSensorReading_datafield_ResponseDataByte3_Bit4_threshold,
				    					tvb, *poffset, 1, TRUE);
					proto_tree_add_item(field_tree, hf_GetSensorReading_datafield_ResponseDataByte3_Bit3_threshold,
				   					tvb, *poffset, 1, TRUE);
					proto_tree_add_item(field_tree, hf_GetSensorReading_datafield_ResponseDataByte3_Bit2_threshold,
				    					tvb, *poffset, 1, TRUE);
					proto_tree_add_item(field_tree, hf_GetSensorReading_datafield_ResponseDataByte3_Bit1_threshold,
				    					tvb, *poffset, 1, TRUE);
					proto_tree_add_item(field_tree, hf_GetSensorReading_datafield_ResponseDataByte3_Bit0_threshold,
				    					tvb, *poffset, 1, TRUE);
					(*poffset)++;
				
				}
		}
		
	}
	else {
		/* Sensor Number */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_GetSensorReading_datafield_SensorNumber,
			    					tvb, (*poffset)++, 1, TRUE);
		}
	}
	

}



/* App NetFN (0x06) */

static void
dissect_cmd_Get_Device_ID(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo _U_, tvbuff_t *tvb,
								gint *poffset, guint8 len, guint8 response, guint8 auth_offset)
{

	proto_tree	*field_tree = NULL;
	proto_item	*tf = NULL;
	guint8		device_revision, firmware_revision1, additional_device_support;
	guint32		ManufactureID; 
	guint16		ProductID; 			
	

	if(response) {

		device_revision = tvb_get_guint8(tvb, auth_offset + 18) ;
		firmware_revision1 = tvb_get_guint8(tvb, auth_offset + 19) ;
		additional_device_support = tvb_get_guint8(tvb, auth_offset + 22) ;
		ManufactureID = tvb_get_ntoh24(tvb, auth_offset + 23);
		ProductID = tvb_get_ntohs(tvb, auth_offset + 26);
		

		/* Device ID */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_GetDeviceID_datafield_DeviceID,
			    					tvb, (*poffset)++, 1, TRUE);
		}
		
		
		/* DeviceSDR/DeviceRevision */
		if (tree) {
			
			tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 "Device SDR/Device Revision: %s (0x%02x)", val_to_str(device_revision>>7,
					 cmd_GetDeviceID_data_DeviceSDR_vals, "Unknown (0x%02x)"), device_revision>>7);

			field_tree = proto_item_add_subtree(tf, ett_cmd_GetDeviceID_data_dr);

			proto_tree_add_item(field_tree, hf_GetDeviceID_datafield_DeviceSDR,
				    tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_GetDeviceID_datafield_DeviceRevision,
				    tvb, *poffset, 1, TRUE);
			proto_item_append_text(tf, ", DeviceRevision (0x%02x)", device_revision&0x0f);
			(*poffset)++;
		}

		/* Device available/Major Firmware Revision */
		if (tree) {
			
			tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 "Device available/Major Firmware Revision: %s (0x%02x)", val_to_str(firmware_revision1>>7,
					 cmd_GetDeviceID_data_DeviceAvailable_vals, "Unknown (0x%02x)"), firmware_revision1>>7);

			field_tree = proto_item_add_subtree(tf, ett_cmd_GetDeviceID_data_fr);

			proto_tree_add_item(field_tree, hf_GetDeviceID_datafield_DeviceAvailable,
				    tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_GetDeviceID_datafield_MajorFirmwareRevision,
				    tvb, *poffset, 1, TRUE);
			proto_item_append_text(tf, ", MajorFirmwareRevision 0x%02x", device_revision&0x7f);
			(*poffset)++;
		}

		/* Minor Firmware Revision */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_GetDeviceID_datafield_MinorFirmwareRevision,
			    					tvb, (*poffset)++, 1, TRUE);
		}
		
		/* IPMI Revision */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_GetDeviceID_datafield_IPMIRevision,
			    					tvb, (*poffset)++, 1, TRUE);
		}

		/* Additional Device Support */
		if (tree) {
			
			tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 "Additional Device Support: %s0x%02x", " ", additional_device_support);

			field_tree = proto_item_add_subtree(tf, ett_cmd_GetDeviceID_data_ads);

			proto_tree_add_item(field_tree, hf_GetDeviceID_datafield_ADS_Chasis,
				    tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_GetDeviceID_datafield_ADS_Bridge,
				    tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_GetDeviceID_datafield_ADS_IPMBEventGenerator,
				    tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_GetDeviceID_datafield_ADS_IPMBEventReceiver,
				    tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_GetDeviceID_datafield_ADS_FRUInventoryDevice,
				    tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_GetDeviceID_datafield_ADS_SELDevice,
				    tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_GetDeviceID_datafield_ADS_SDRRepositoryDevice,
				    tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_GetDeviceID_datafield_ADS_SensorDevice,
				    tvb, *poffset, 1, TRUE);
			
			(*poffset)++;
		}

		/* Manufacture ID */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_GetDeviceID_datafield_ManufactureID,
			    					tvb, *poffset, 3, TRUE);
			(*poffset)+=3;
		}

		/* Product ID */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_GetDeviceID_datafield_ProductID,
			    					tvb, *poffset, 2, TRUE);
			(*poffset)+=2;
		}

		/* Auxiliary Firmware Revision Infomation */
		if ((15==len)&&tree) {
			proto_tree_add_item(ipmi_tree, hf_GetDeviceID_datafield_AFRI,
			    					tvb, *poffset, 4, TRUE);
			(*poffset)+=4;
		}		

	}
	else
		return;

}

static const true_false_string ipmi_Auth_Cap_comp_val  = {
  "IPMI v2.0+ extended capabilities available",
  "IPMI v1.5 support only"
};

static const true_false_string ipmi_Authentication_Type_Support_val  = {
  "Supported",
  "Authentication type not available for use"
};

static const true_false_string ipmi_Auth_Cap_datafield_comp_val  = {
  "Get IPMI v2.0+ extended data",
  "Backward compatible with IPMI v1.5"
};

static const true_false_string ipmi_Authentication_Type_KG_status_val  = {
  "KG is set to non-zero value",
  "KG is set to default (all 0s)"
};

static const true_false_string ipmi_Authentication_Type_per_mess_auth_status_val  = {
  "Per-message Authentication is disabled",
  "Per-message Authentication is enabled"
};

static const true_false_string ipmi_Authentication_Type_user_level_auth_status_val  = {
  "User Level Authentication is disabled",
  "User Level Authentication is enabled"
};



static const value_string GetChannelAuthCap_channelno_vals[] = {
	{ 0x0,	"0" },
	{ 0x1,	"1" },
	{ 0x2,	"2" },
	{ 0x3,	"3" },
	{ 0x4,	"4" },
	{ 0x5,	"5" },
	{ 0x6,	"6" },
	{ 0x7,	"7" },
	{ 0x8,	"8" },
	{ 0x9,	"9" },
	{ 0xa,	"10" },
	{ 0xb,	"11" },
	{ 0xe,	"Retrieve information for channel this request was issued on" },
	{ 0xf,	"15" },
	{ 0x0,	NULL },
};

static const value_string GetChannelAuthCap_max_priv_lev_vals[] = {
	{ 0x0,	"Reserved" },
	{ 0x1,	"Callback level" },
	{ 0x2,	"User level" },
	{ 0x3,	"Operator level" },
	{ 0x4,	"Administrator level" },
	{ 0x5,	"OEM Proprietary level" },
	{ 0x0,	NULL },
};
/* 22-15, Get Channel Authentication Capabilities Command */
static void
dissect_cmd_Get_Channel_Auth_Capabilities(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo _U_, tvbuff_t *tvb,
								gint *poffset, guint8 len, guint8 response, guint8 auth_offset)
{
	proto_tree	*field_tree = NULL;
	proto_item	*tf = NULL;

	if(response) {
		if (tree) {
			/* Byte 2 Channel Number */
			proto_tree_add_item(ipmi_tree, hf_Get_Channel_Auth_Cap_channel_number,
			    					tvb, (*poffset), 1, TRUE);
			(*poffset)++;
			/* Byte 3 - 4 Authentication Type Support */
			proto_tree_add_item(ipmi_tree, hf_Get_Channel_Auth_Cap_comp_info,
			    					tvb, (*poffset), 1, TRUE);
			proto_tree_add_item(ipmi_tree, hf_Get_Channel_Auth_Cap_Auth_types_b5,
			    					tvb, (*poffset), 1, TRUE);
			proto_tree_add_item(ipmi_tree, hf_Get_Channel_Auth_Cap_Auth_types_b4,
			    					tvb, (*poffset), 1, TRUE);
			proto_tree_add_item(ipmi_tree, hf_Get_Channel_Auth_Cap_Auth_types_b2,
			    					tvb, (*poffset), 1, TRUE);
			proto_tree_add_item(ipmi_tree, hf_Get_Channel_Auth_Cap_Auth_types_b1,
			    					tvb, (*poffset), 1, TRUE);
			proto_tree_add_item(ipmi_tree, hf_Get_Channel_Auth_Cap_Auth_types_b0,
			    					tvb, (*poffset), 1, TRUE);
			(*poffset)++;
			proto_tree_add_item(ipmi_tree, hf_Get_Channel_Auth_Cap_Auth_KG_status,
			    					tvb, (*poffset), 1, TRUE);
			/* [4] - Per-message Authentication status */
			proto_tree_add_item(ipmi_tree, hf_Get_Channel_Auth_Cap_per_mess_auth_status,
			    					tvb, (*poffset), 1, TRUE);
			proto_tree_add_item(ipmi_tree, hf_Get_Channel_Auth_Cap_user_level_auth_status,
			    					tvb, (*poffset), 1, TRUE);
			/* [2:0] - Anonymous Login status */
			tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,"Anonymous Login status");
			field_tree = proto_item_add_subtree(tf, ett_Get_Channel_Auth_Cap_anonymouslogin);

			proto_tree_add_item(field_tree, hf_Get_Channel_Auth_Cap_anonymouslogin_status_b2,
			    					tvb, (*poffset), 1, TRUE);
			proto_tree_add_item(field_tree, hf_Get_Channel_Auth_Cap_anonymouslogin_status_b1,
			    					tvb, (*poffset), 1, TRUE);
			proto_tree_add_item(field_tree, hf_Get_Channel_Auth_Cap_anonymouslogin_status_b0,
			    					tvb, (*poffset), 1, TRUE);
			(*poffset)++;
			/* For IPMI v2.0+: - Extended Capabilities */
			proto_tree_add_item(ipmi_tree, hf_Get_Channel_Auth_Cap_ext_cap_b1,
			    					tvb, (*poffset), 1, TRUE);
			proto_tree_add_item(ipmi_tree, hf_Get_Channel_Auth_Cap_ext_cap_b0,
			    					tvb, (*poffset), 1, TRUE);
			(*poffset)++;
			proto_tree_add_item(ipmi_tree, hf_Get_Channel_Auth_OEM_ID,
			    					tvb, (*poffset), 3, TRUE);
			(*poffset)+=3;
			proto_tree_add_item(ipmi_tree, hf_Get_Channel_Auth_OEM_AUX,
			    					tvb, (*poffset), 1, TRUE);
		}
	}else{
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_Get_Channel_Auth_Cap_datafield_comp_info,
			    					tvb, (*poffset), 1, TRUE);
			proto_tree_add_item(ipmi_tree, hf_Get_Channel_Auth_Cap_datafield_channel_number,
			    					tvb, (*poffset), 1, TRUE);
			(*poffset)++;
			/* Requested Maximum Privilege Level */
			proto_tree_add_item(ipmi_tree, hf_Get_Channel_Auth_Cap_datafield_max_priv_lev,
			    					tvb, (*poffset), 1, TRUE);
		}
	}
}
/* Storage NetFN (0x0a) */
static void
dissect_cmd_Get_FRU_Inventory_Area_Info(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo _U_, tvbuff_t *tvb,
								gint *poffset, guint8 len _U_, guint8 response, guint8 auth_offset)
{

	proto_tree	*field_tree = NULL;
	proto_item	*tf = NULL;
	guint8		Response_Data_Byte4;
	
	if(response) {

		/* FRU Inventory area size in bytes */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_GetFRUInventoryAreaInfo_datafield_FRUInventoryAreaSize,
			    					tvb, (*poffset), 2, TRUE);
			(*poffset)+=2;
		}
		/* Response Data Byte4 */
		if (tree) {
			
			Response_Data_Byte4 =  tvb_get_guint8(tvb, auth_offset + 19) ;
			
			tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 "Device is accessed by bytes or words: %s0x%02x", " ", Response_Data_Byte4);

			field_tree = proto_item_add_subtree(tf, ett_cmd_GetFRUInventoryAreaInfo_data_ResponseDataByte4);

			proto_tree_add_item(field_tree, hf_GetFRUInventoryAreaInfo_datafield_ResponseDataByte4_Bit71,
				    tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_GetFRUInventoryAreaInfo_datafield_ResponseDataByte4_Bit0,
				    tvb, *poffset, 1, TRUE);
			(*poffset)++;
		}
		
	}
	else {
		
		/* FRU Device ID */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_GetFRUInventoryAreaInfo_datafield_FRUDeviceID,
			    					tvb, (*poffset)++, 1, TRUE);
		}
		
	}
	
}

static void
dissect_cmd_Get_SEL_Info(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo _U_, tvbuff_t *tvb,
								gint *poffset, guint8 len _U_, guint8 response, guint8 auth_offset)
{

	proto_tree	*field_tree = NULL;
	proto_item	*tf = NULL;
	guint8		Operation_Support;
	
	if(response) {

		/* SEL Version */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_GetSELInfo_datafield_SELVersion,
			    					tvb, (*poffset)++, 1, TRUE);
		}
		
		
		/* number of log entries in SEL */
		if (tree) {
			
			proto_tree_add_item(ipmi_tree, hf_GetSELInfo_datafield_Entries,
				    tvb, *poffset, 2, TRUE);
			(*poffset)+=2;
		}

		/* Free Space in bytes */
		if (tree) {
			
			proto_tree_add_item(ipmi_tree, hf_GetSELInfo_datafield_FreeSpace,
				    tvb, *poffset, 2, TRUE);
			(*poffset)+=2;
		}


		/* Most recent addition timestamp */
		if (tree) {
			
			proto_tree_add_item(ipmi_tree, hf_GetSELInfo_datafield_AdditionTimestamp,
				    tvb, *poffset, 4, TRUE);
			(*poffset)+=4;
		
		}

		/* Most recent addition timestamp */
		if (tree) {
			
			proto_tree_add_item(ipmi_tree, hf_GetSELInfo_datafield_EraseTimestamp,
				    tvb, *poffset, 4, TRUE);
			(*poffset)+=4;
		
		}
		
		/* Operation Support */
		if (tree) {
			
			Operation_Support =  tvb_get_guint8(tvb, auth_offset + 30) ;
			
			tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 "Operation Support: %s0x%02x", " ", Operation_Support);

			field_tree = proto_item_add_subtree(tf, ett_cmd_GetSELInfo_data_OperationSupport);

			proto_tree_add_item(field_tree, hf_GetSELInfo_datafield_OperationSupport_Bit7,
				    tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_GetSELInfo_datafield_OperationSupport_Reserved,
				    tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_GetSELInfo_datafield_OperationSupport_Bit3,
				    tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_GetSELInfo_datafield_OperationSupport_Bit2,
				    tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_GetSELInfo_datafield_OperationSupport_Bit1,
				    tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_GetSELInfo_datafield_OperationSupport_Bit0,
				    tvb, *poffset, 1, TRUE);
			(*poffset)++;
		}
		
	}
	else
		return;

}

static void
dissect_cmd_Reserve_SEL(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo _U_, tvbuff_t *tvb,
								gint *poffset, guint8 len _U_, guint8 response, guint8 auth_offset _U_)
{
	
	if(response) {

		/* Reservation ID */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_ReserveSEL_datafield_ReservationID,
				    tvb, *poffset, 2, TRUE);
			(*poffset)+=2;
		}

	}
	else
		return;

}

static void
dissect_cmd_Get_SEL_Entry(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo, tvbuff_t *tvb,
								gint *poffset, guint8 len, guint8 response, guint8 auth_offset _U_)
{

	tvbuff_t		*next_tvb;
	
	if(response) {

		/* Next SEL Record ID */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_GetSELEntry_datafield_NextSELRecordID,
			    					tvb, (*poffset), 2, TRUE);
			(*poffset)+=2;
			len-=2;
		}
		/* Record Data */
		if (tree) {
			next_tvb = tvb_new_subset(tvb, *poffset, len, len);
			call_dissector(data_handle, next_tvb, pinfo, tree);
			*poffset += len;
		}
		
	}
	else {
		
		/* Reservation ID */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_GetSELEntry_datafield_ReservationID,
				    tvb, *poffset, 2, TRUE);
			(*poffset)+=2;
		}
		/* SEL Record ID */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_GetSELEntry_datafield_SELRecordID,
				    tvb, *poffset, 2, TRUE);
			(*poffset)+=2;
		}
		/* Offset into record */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_GetSELEntry_datafield_OffsetIntoRecord,
				    tvb, (*poffset)++, 1, TRUE);
		}
		/* Bytes to read */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_GetSELEntry_datafield_BytesToRead,
				    tvb, (*poffset)++, 1, TRUE);
		}

	}

}

static void
dissect_cmd_Clear_SEL(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo _U_, tvbuff_t *tvb,
								gint *poffset, guint8 len _U_, guint8 response, guint8 auth_offset)
{

	proto_tree	*field_tree = NULL;
	proto_item	*tf = NULL;
	guint8		erasure_progress;
	
	if(response) {

		/* Erasure progress */
		if (tree) {
			
			erasure_progress =  tvb_get_guint8(tvb, auth_offset + 17) ;
			
			tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 "Erasure progress: %s0x%02x", " ", erasure_progress);

			field_tree = proto_item_add_subtree(tf, ett_cmd_ClearSEL_data_ErasureProgress);

			proto_tree_add_item(field_tree, hf_ClearSEL_datafield_ErasureProgress_Reserved,
				    tvb, *poffset, 1, TRUE);
			proto_tree_add_item(field_tree, hf_ClearSEL_datafield_ErasureProgress_EraProg,
				    tvb, *poffset, 1, TRUE);
			(*poffset)++;
		}
		
	}
	else {
		
		/* Reservation ID */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_ClearSEL_datafield_ReservationID,
				    tvb, *poffset, 2, TRUE);
			(*poffset)+=2;
		}
		/* 'C' (43h) */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_ClearSEL_datafield_Byte3,
				    tvb, (*poffset)++, 1, TRUE);
		}
		/* 'L' (4Ch) */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_ClearSEL_datafield_Byte4,
				    tvb, (*poffset)++, 1, TRUE);
		}
		/* 'R' (52h) */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_ClearSEL_datafield_Byte5,
				    tvb, (*poffset)++, 1, TRUE);
		}
		/* Data Byte 6 */
		if (tree) {
			proto_tree_add_item(ipmi_tree, hf_ClearSEL_datafield_Byte6,
				    tvb, (*poffset)++, 1, TRUE);
		}

	}
}


/* Picmg NetFN (0x2c) */

static void
dissect_cmd_Get_PICMG_Properties(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo _U_, tvbuff_t *tvb,
								gint *poffset, guint8 len _U_, guint8 response, guint8 auth_offset _U_)
{
		/*proto_tree	*field_tree = NULL;
		proto_item	*tf = NULL;
		guint8		picmg_identifier,  PICMGExtensionVersion, MaxFRUDeviceID, FRUDeviceIDforIPMController;*/
			
		if(response) {

			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetPICMGProperties_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			/* PICMG Extension Version */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetPICMGProperties_datafield_PICMGExtensionVersion,
			    						tvb, (*poffset)++, 1, TRUE);
			}
			/*Max FRU Device ID*/
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetPICMGProperties_datafield_MaxFRUDeviceID,
			    						tvb, (*poffset)++, 1, TRUE);
			}	
			/*FRU Device ID for IPM Controller*/
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetPICMGProperties_datafield_FRUDeviceIDforIPMController,
			    						tvb, (*poffset)++, 1, TRUE);
			}	
		}
		else {
			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetPICMGProperties_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}
		}


}

static void
dissect_cmd_FRU_Control(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo _U_, tvbuff_t *tvb,
							gint *poffset, guint8 len _U_, guint8 response, guint8 auth_offset _U_)
{

		if(response) {

			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_FRUControl_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}

		}
		else {
			
			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_FRUControl_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			/* FRU Device ID */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_FRUControl_datafield_FRUDeviceID,
			    						tvb, (*poffset)++, 1, TRUE);
			}
			/* FRU Control Option*/
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_FRUControl_datafield_FRUControlOption,
			    						tvb, (*poffset)++, 1, TRUE);
			}

		}

}

static void
dissect_cmd_Get_FRU_Led_Properties(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo _U_, tvbuff_t *tvb,
							gint *poffset, guint8 len _U_, guint8 response, guint8 auth_offset)
{
		proto_tree	*field_tree = NULL;
		proto_item	*tf = NULL;
		guint8		LedProperties;
		
		if(response) {

			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetFRULedProperties_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			/* General Status LED Properties */
			if (tree) {
			
				LedProperties = tvb_get_guint8(tvb, auth_offset + 18) ;
				
				tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 		"General Status LED Properties: %s0x%02x", " ", LedProperties);

				field_tree = proto_item_add_subtree(tf, ett_cmd_GetFRULedProperties_data_LedProperties);

				proto_tree_add_item(field_tree, hf_GetFRULedProperties_datafield_LedProperties_Reserved,
				    					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetFRULedProperties_datafield_LedProperties_LED3,
				    					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetFRULedProperties_datafield_LedProperties_LED2,
				   					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetFRULedProperties_datafield_LedProperties_LED1,
				    					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetFRULedProperties_datafield_LedProperties_BlueLED,
				    					tvb, *poffset, 1, TRUE);
				(*poffset)++;
				
			}
			/* Application Specific LED Count */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetFRULedProperties_datafield_ApplicationSpecificLEDCount,
			    						tvb, (*poffset)++, 1, TRUE);
			}

		}
		else {
			
			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetFRULedProperties_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			/* FRU Device ID */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetFRULedProperties_datafield_FRUDeviceID,
			    						tvb, (*poffset)++, 1, TRUE);
			}
			
		}

}

static void 
dissect_cmd_Get_Led_Color_Capabilities(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo _U_, tvbuff_t *tvb,
							gint *poffset, guint8 len _U_, guint8 response, guint8 auth_offset)
{

		proto_tree	*field_tree = NULL;
		proto_item	*tf = NULL;
		guint8		LEDColorCapabilities, DefaultLEDColorLocalControl, DefaultLEDColorOverride;
		
		if(response) {

			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetLedColorCapabilities_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			/* LED Color Capabilities */
			if (tree) {
			
				LEDColorCapabilities = tvb_get_guint8(tvb, auth_offset + 18) ;
				
				tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 		"LED Color Capabilities: %s0x%02x", " ", LEDColorCapabilities);

				field_tree = proto_item_add_subtree(tf, ett_cmd_GetLedColorCapabilities_data_LEDColorCapabilities);

				proto_tree_add_item(field_tree, hf_GetLedColorCapabilities_datafield_LEDColorCapabilities_Reserved_7,
				    					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetLedColorCapabilities_datafield_LEDColorCapabilities_WHITE,
				    					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetLedColorCapabilities_datafield_LEDColorCapabilities_ORANGE,
				   					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetLedColorCapabilities_datafield_LEDColorCapabilities_AMBER,
				    					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetLedColorCapabilities_datafield_LEDColorCapabilities_GREEN,
				    					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetLedColorCapabilities_datafield_LEDColorCapabilities_RED,
				    					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetLedColorCapabilities_datafield_LEDColorCapabilities_BLUE,
				    					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetLedColorCapabilities_datafield_LEDColorCapabilities_Reserved_0,
				    					tvb, *poffset, 1, TRUE);
				(*poffset)++;
				
			}
			/* Default LED Color in Local Control State*/
			if (tree) {
				
				DefaultLEDColorLocalControl = tvb_get_guint8(tvb, auth_offset + 19) ;
				
				tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 		"Default LED Color in Local Control State: %s0x%02x", " ", DefaultLEDColorLocalControl);

				field_tree = proto_item_add_subtree(tf, ett_cmd_GetLedColorCapabilities_data_DefaultLEDColorLocalControl);

				proto_tree_add_item(field_tree, hf_GetLedColorCapabilities_datafield_DefaultLEDColorLocalControl_Reserved_74,
				    					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetLedColorCapabilities_datafield_DefaultLEDColorLocalControl_Color,
				    					tvb, *poffset, 1, TRUE);
				(*poffset)++;
			}
			/* Default LED Color in Override State */
			if (tree) {
				
				DefaultLEDColorOverride = tvb_get_guint8(tvb, auth_offset + 20) ;
				
				tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 		"Default LED Color in Override State: %s0x%02x", " ", DefaultLEDColorOverride);

				field_tree = proto_item_add_subtree(tf, ett_cmd_GetLedColorCapabilities_data_DefaultLEDColorOverride);

				proto_tree_add_item(field_tree, hf_GetLedColorCapabilities_datafield_DefaultLEDColorOverride_Reserved_74,
				    					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetLedColorCapabilities_datafield_DefaultLEDColorOverride_Color,
				    					tvb, *poffset, 1, TRUE);
				(*poffset)++;
			}

		}
		else {
			
			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetLedColorCapabilities_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			/* FRU Device ID */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetLedColorCapabilities_datafield_FRUDeviceID,
			    						tvb, (*poffset)++, 1, TRUE);
			}
			/* LED ID */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetLedColorCapabilities_datafield_LEDID,
			    						tvb, (*poffset)++, 1, TRUE);
			}
			
			
		}

}

static void 
dissect_cmd_Set_FRU_Led_State(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo _U_, tvbuff_t *tvb,
								gint *poffset, guint8 len _U_, guint8 response, guint8 auth_offset)
{
		proto_tree	*field_tree = NULL;
		proto_item	*tf = NULL;
		guint8		Color;

		
		if(response) {

			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_SetFRULedState_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			
		}
		else {

			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_SetFRULedState_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			/* FRU Device ID */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_SetFRULedState_datafield_FRUDeviceID,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			/* LED ID */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_SetFRULedState_datafield_LEDID,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			/* LED Function */
			if (tree) {
				guint8 LEDFunction = tvb_get_guint8(tvb, *poffset);
				if ((LEDFunction < 0x01) || (LEDFunction > 0xfa)) {
					proto_tree_add_item(ipmi_tree, hf_SetFRULedState_datafield_LEDFunction,
									tvb, (*poffset)++, 1, TRUE);
				} else {
					proto_tree_add_uint_format(ipmi_tree, hf_SetFRULedState_datafield_Offduration,
									tvb, (*poffset)++, 1, LEDFunction,
									"Off-duration: %u ms (0x%02x)", LEDFunction * 10, LEDFunction);
				}
			}
			/*On-duration */
			if (tree) {
				guint8 duration = tvb_get_guint8(tvb, *poffset);
				proto_tree_add_uint_format(ipmi_tree, hf_SetFRULedState_datafield_Onduration, 
									tvb, (*poffset)++, 1, duration,
									"On-duration: %u ms (0x%02x)", duration * 10, duration);
			}
			/* Color when illuminated */
			if (tree) {

				Color = tvb_get_guint8(tvb, auth_offset + 21) ;
			
				tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 		"Color when illuminated: %s0x%02x", " ", Color);

				field_tree = proto_item_add_subtree(tf, ett_cmd_SetFRULedState_data_Color);

				proto_tree_add_item(field_tree, hf_SetFRULedState_datafield_Color_Reserved,
				    					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_SetFRULedState_datafield_Color_ColorVal,
				   					tvb, *poffset, 1, TRUE);
				(*poffset)++;
				
			}
			
		}

}

static void 
dissect_cmd_Get_FRU_Led_State(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo _U_, tvbuff_t *tvb,
								gint *poffset, guint8 len _U_, guint8 response, guint8 auth_offset)
{
		proto_tree	*field_tree = NULL;
		proto_item	*tf = NULL;
		guint8		led_state, Color;

		
		if(response) {

			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetFRULedState_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			/* LED state */
			if (tree) {

				led_state = tvb_get_guint8(tvb, auth_offset + 18) ;
			
				tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 		"LED State: %s0x%02x", " ", led_state);

				field_tree = proto_item_add_subtree(tf, ett_cmd_GetFRULedState_data_LEDState);

				proto_tree_add_item(field_tree, hf_GetFRULedState_datafield_LEDState_Reserved,
				    					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetFRULedState_datafield_LEDState_Bit2,
				   					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetFRULedState_datafield_LEDState_Bit1,
				   					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetFRULedState_datafield_LEDState_Bit0,
				   					tvb, *poffset, 1, TRUE);
				(*poffset)++;
			}
			/* Local Control LED Function */
			if (tree) {
				guint8 LEDFunction = tvb_get_guint8(tvb, *poffset);
				if ((LEDFunction < 0x01) || (LEDFunction > 0xfa)) {
					proto_tree_add_item(ipmi_tree, hf_GetFRULedState_datafield_LocalControlLEDFunction,
									tvb, (*poffset)++, 1, TRUE);
				} else {
					proto_tree_add_uint_format(ipmi_tree, hf_GetFRULedState_datafield_LocalControlOffduration,
									tvb, (*poffset)++, 1, LEDFunction,
									"Local Control Off-duration: %u ms (0x%02x)", LEDFunction * 10, LEDFunction);
				}
			}
			/* Local Control On-duration */
			if (tree) {
				guint8 duration = tvb_get_guint8(tvb, *poffset);
				proto_tree_add_uint_format(ipmi_tree, hf_GetFRULedState_datafield_LocalControlOnduration,
									tvb, (*poffset)++, 1, duration,
									"Local Control On-duration: %u ms (0x%02x)", duration * 10, duration);
			}
			/* Local Control Color */
			if (tree) {

				Color = tvb_get_guint8(tvb, auth_offset + 21) ;
			
				tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 		"Local Control Color: %s0x%02x", " ", Color);

				field_tree = proto_item_add_subtree(tf, ett_cmd_GetFRULedState_data_LocalControlColor);

				proto_tree_add_item(field_tree, hf_GetFRULedState_datafield_LocalControlColor_Reserved,
				    					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetFRULedState_datafield_LocalControlColor_ColorVal,
				   					tvb, *poffset, 1, TRUE);
				(*poffset)++;
				
			}
			/* Override State LED Function */
			if (tree) {
				guint8 LEDFunction = tvb_get_guint8(tvb, *poffset);
				if ((LEDFunction < 0x01) || (LEDFunction > 0xfa)) {
					proto_tree_add_item(ipmi_tree, hf_GetFRULedState_datafield_OverrideStateLEDFunction,
		    							tvb, (*poffset)++, 1, TRUE);
				} else {
					proto_tree_add_uint_format(ipmi_tree, hf_GetFRULedState_datafield_OverrideStateOffduration,
									tvb, (*poffset)++, 1, LEDFunction,
									"Override State Off-duration: %u ms (0x%02x)", LEDFunction * 10, LEDFunction);
				}
			}
			/* Override State On-duration */
			if (tree) {
				guint8 duration = tvb_get_guint8(tvb, *poffset);
				proto_tree_add_uint_format(ipmi_tree, hf_GetFRULedState_datafield_OverrideStateOnduration,
									tvb, (*poffset)++, 1, duration,
									"Override State On-duration: %u ms (0x%02x)", duration * 10, duration);
			}
			/* Override State Color */
			if (tree) {
				
				Color = tvb_get_guint8(tvb, auth_offset + 24) ;
			
				tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 		"Override State Color: %s0x%02x", " ", Color);

				field_tree = proto_item_add_subtree(tf, ett_cmd_GetFRULedState_data_OverrideStateColor);

				proto_tree_add_item(field_tree, hf_GetFRULedState_datafield_OverrideStateColor_Reserved,
				    					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetFRULedState_datafield_OverrideStateColor_ColorVal,
				   					tvb, *poffset, 1, TRUE);
				(*poffset)++;
			}
			/* Lamp Test Duration */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetFRULedState_datafield_LampTestDuration,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			
		}
		else {

			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetFRULedState_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			/* FRU Device ID */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetFRULedState_datafield_FRUDeviceID,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			/* LED ID */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetFRULedState_datafield_LEDID,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			
		}

}

static void
dissect_cmd_Set_FRU_Activation_Policy(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo _U_, tvbuff_t *tvb,
								gint *poffset, guint8 len _U_, guint8 response, guint8 auth_offset)
{
		proto_tree	*field_tree = NULL;
		proto_item	*tf = NULL;
		guint8		FRUActivationPolicyMaskBit, MaskBit1, MaskBit0, FRUActivationPolicySetBit;
		
		if(response) {

			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_SetFRUActivationPolicy_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			
		}
		else {

			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_SetFRUActivationPolicy_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			/* FRU Device ID */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_SetFRUActivationPolicy_datafield_FRUDeviceID,
			    						tvb, (*poffset)++, 1, TRUE);
			}
			/* FRU Activation Policy Mask Bit */
			FRUActivationPolicyMaskBit = tvb_get_guint8(tvb, auth_offset + 18) ;
			if (tree) {
				tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 		"FRU Activation Policy Mask Bit : %s0x%02x", " ", FRUActivationPolicyMaskBit);

				field_tree = proto_item_add_subtree(tf, ett_cmd_SetFRUActivationPolicy_data_FRUActivationPolicyMaskBit);

				proto_tree_add_item(field_tree, hf_SetFRUActivationPolicy_datafield_FRUActivationPolicyMaskBit_Bit72,
				    					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_SetFRUActivationPolicy_datafield_FRUActivationPolicyMaskBit_Bit1,
				   					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_SetFRUActivationPolicy_datafield_FRUActivationPolicyMaskBit_Bit0,
				    					tvb, *poffset, 1, TRUE);
				(*poffset)++;
			}
			/* FRU Activation Policy Set Bit */
			MaskBit1 = FRUActivationPolicyMaskBit & 0x02;
			MaskBit0 = FRUActivationPolicyMaskBit & 0x01;
			
			if(MaskBit1&&MaskBit0) {

				if (tree) {
					FRUActivationPolicySetBit = tvb_get_guint8(tvb, auth_offset + 19) ;
					tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 		"FRU Activation Policy Set Bit : %s0x%02x", " ", FRUActivationPolicySetBit);

					field_tree = proto_item_add_subtree(tf, ett_cmd_SetFRUActivationPolicy_data_FRUActivationPolicySetBit);

					proto_tree_add_item(field_tree, hf_SetFRUActivationPolicy_datafield_FRUActivationPolicySetBit_Bit72,
				    					tvb, *poffset, 1, TRUE);
					proto_tree_add_item(field_tree, hf_SetFRUActivationPolicy_datafield_FRUActivationPolicySetBit_Bit1,
				   					tvb, *poffset, 1, TRUE);
					proto_tree_add_item(field_tree, hf_SetFRUActivationPolicy_datafield_FRUActivationPolicySetBit_Bit0,
				    					tvb, *poffset, 1, TRUE);
					(*poffset)++;
				}
				
			}
			else if(MaskBit1) {
				
					if (tree) {
						FRUActivationPolicySetBit = tvb_get_guint8(tvb, auth_offset + 19) ;
						tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 		"FRU Activation Policy Set Bit : %s0x%02x", " ", FRUActivationPolicySetBit);

						field_tree = proto_item_add_subtree(tf, ett_cmd_SetFRUActivationPolicy_data_FRUActivationPolicySetBit);

						proto_tree_add_item(field_tree, hf_SetFRUActivationPolicy_datafield_FRUActivationPolicySetBit_Bit72,
				    					tvb, *poffset, 1, TRUE);
						proto_tree_add_item(field_tree, hf_SetFRUActivationPolicy_datafield_FRUActivationPolicySetBit_Bit1,
				   					tvb, *poffset, 1, TRUE);
						proto_tree_add_item(field_tree, hf_SetFRUActivationPolicy_datafield_FRUActivationPolicySetBit_Bit0_ignored,
				    					tvb, *poffset, 1, TRUE);
						(*poffset)++;
					}
					
				}
			else if(MaskBit0) {

					if (tree) {
						FRUActivationPolicySetBit = tvb_get_guint8(tvb, auth_offset + 19) ;
						tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 		"FRU Activation Policy Set Bit : %s0x%02x", " ", FRUActivationPolicySetBit);

						field_tree = proto_item_add_subtree(tf, ett_cmd_SetFRUActivationPolicy_data_FRUActivationPolicySetBit);

						proto_tree_add_item(field_tree, hf_SetFRUActivationPolicy_datafield_FRUActivationPolicySetBit_Bit72,
				    					tvb, *poffset, 1, TRUE);
						proto_tree_add_item(field_tree, hf_SetFRUActivationPolicy_datafield_FRUActivationPolicySetBit_Bit1_ignored,
				   					tvb, *poffset, 1, TRUE);
						proto_tree_add_item(field_tree, hf_SetFRUActivationPolicy_datafield_FRUActivationPolicySetBit_Bit0,
				    					tvb, *poffset, 1, TRUE);
						(*poffset)++;
					}
				}
			else {
				
				if (tree) {
						FRUActivationPolicySetBit = tvb_get_guint8(tvb, auth_offset + 19) ;
						tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 		"FRU Activation Policy Set Bit : %s0x%02x", " ", FRUActivationPolicySetBit);

						field_tree = proto_item_add_subtree(tf, ett_cmd_SetFRUActivationPolicy_data_FRUActivationPolicySetBit);

						proto_tree_add_item(field_tree, hf_SetFRUActivationPolicy_datafield_FRUActivationPolicySetBit_Bit72,
				    					tvb, *poffset, 1, TRUE);
						proto_tree_add_item(field_tree, hf_SetFRUActivationPolicy_datafield_FRUActivationPolicySetBit_Bit1_ignored,
				   					tvb, *poffset, 1, TRUE);
						proto_tree_add_item(field_tree, hf_SetFRUActivationPolicy_datafield_FRUActivationPolicySetBit_Bit0_ignored,
				    					tvb, *poffset, 1, TRUE);
						(*poffset)++;
					}
				
			}
				
			
		}

}

static void
dissect_cmd_Get_FRU_Activation_Policy(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo _U_, tvbuff_t *tvb,
								gint *poffset, guint8 len _U_, guint8 response, guint8 auth_offset)
{

		proto_tree	*field_tree = NULL;
		proto_item	*tf = NULL;
		guint8		FRUActivationPolicy;
		
		if(response) {

			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetFRUActivationPolicy_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			/* FRU Activation Policy Mask Bit */
			if (tree) {
				FRUActivationPolicy = tvb_get_guint8(tvb, auth_offset + 18) ;
				tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 		"FRU Activation Policy : %s0x%02x", " ", FRUActivationPolicy);

				field_tree = proto_item_add_subtree(tf, ett_cmd_GetFRUActivationPolicy_data_FRUActivationPolicy);

				proto_tree_add_item(field_tree, hf_GetFRUActivationPolicy_datafield_FRUActivationPolicy_Bit72,
				    					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetFRUActivationPolicy_datafield_FRUActivationPolicy_Bit1,
				   					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetFRUActivationPolicy_datafield_FRUActivationPolicy_Bit0,
				    					tvb, *poffset, 1, TRUE);
				(*poffset)++;
			}
			
		}
		else {

			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetFRUActivationPolicy_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			/* FRU Device ID */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetFRUActivationPolicy_datafield_FRUDeviceID,
			    						tvb, (*poffset)++, 1, TRUE);
			}
			
		}


}

static void
dissect_cmd_Set_FRU_Activation(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo _U_, tvbuff_t *tvb,
								gint *poffset, guint8 len _U_, guint8 response, guint8 auth_offset _U_)
{

		if(response) {

			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_SetFRUActivation_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			
		}
		else {

			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_SetFRUActivation_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			/* FRU Device ID */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_SetFRUActivation_datafield_FRUDeviceID,
			    						tvb, (*poffset)++, 1, TRUE);
			}
			/*FRU Activation/Deactivation*/
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_SetFRUActivation_datafield_FRUActivationDeactivation,
			    						tvb, (*poffset)++, 1, TRUE);
			}	
			
		}

}

static void
dissect_cmd_Get_Device_Locator_Record_ID(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo _U_, tvbuff_t *tvb,
								gint *poffset, guint8 len _U_, guint8 response, guint8 auth_offset _U_)
{
				
		if(response) {

			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetDeviceLocatorRecordID_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			/* Record ID */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetDeviceLocatorRecordID_datafield_RecordID,
			    						tvb, *poffset, 2, TRUE);
				(*poffset)+=2;
			}
			
		}
		else {

			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetDeviceLocatorRecordID_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			 /* FRU Device ID */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetDeviceLocatorRecordID_datafield_FRUDeviceID,
			    						tvb, (*poffset)++, 1, TRUE);
			}
		
		}

}

static void
dissect_cmd_Set_Power_Level(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo _U_, tvbuff_t *tvb,
								gint *poffset, guint8 len _U_, guint8 response, guint8 auth_offset _U_)
{
		if(response) {

			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_SetPowerLevel_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}

		}
		else {
			
			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_SetPowerLevel_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			/* FRU Device ID */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_SetPowerLevel_datafield_FRUDeviceID,
			    						tvb, (*poffset)++, 1, TRUE);
			}
			/* Power Level*/
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_SetPowerLevel_datafield_PowerLevel,
			    						tvb, (*poffset)++, 1, TRUE);
			}
			/* Set Present Levels to Desired Levels */
			if (tree) {
					proto_tree_add_item(ipmi_tree, hf_SetPowerLevel_datafield_SetPresentLevelsToDesiredLevels,
			    						tvb, (*poffset)++, 1, TRUE);
				}	
						
		}

}

static void
dissect_cmd_Get_Power_Level(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo _U_, tvbuff_t *tvb,
								gint *poffset, guint8 len, guint8 response, guint8 auth_offset)
{
		proto_tree	*field_tree = NULL;
		proto_item	*tf = NULL;
		guint8		Properties, j;

		
		if(response) {

			Properties = tvb_get_guint8(tvb, auth_offset + 18) ;
			
			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetPowerLevel_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			/* Properties */
			if (tree) {
			
				tf = proto_tree_add_text(ipmi_tree, tvb, *poffset, 1,
					 		"Properties: %s0x%02x", " ", Properties);

				field_tree = proto_item_add_subtree(tf, ett_cmd_GetPowerLevel_data_Properties);

				proto_tree_add_item(field_tree, hf_GetPowerLevel_datafield_Properties_DynamicPowerCon,
				    					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetPowerLevel_datafield_Properties_Reserved,
				   					tvb, *poffset, 1, TRUE);
				proto_tree_add_item(field_tree, hf_GetPowerLevel_datafield_Properties_PowerLevel,
				    					tvb, *poffset, 1, TRUE);
				(*poffset)++;
				
			}
			/*Delay To Stable Power*/
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetPowerLevel_datafield_DelayToStablePower,
			    						tvb, (*poffset)++, 1, TRUE);
			}
			/*Power Multiplier*/
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetPowerLevel_datafield_PowerMultiplier,
			    						tvb, (*poffset)++, 1, TRUE);
			}
			/*Power Draw*/
			for(j=0; j<len-4; j++) {
			
				if (tree) {
					proto_tree_add_item(ipmi_tree, hf_GetPowerLevel_datafield_PowerDraw,
			    						tvb, (*poffset)++, 1, TRUE);
				}	
			}
					
		}
		else {

			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetPowerLevel_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			/* FRU Device ID */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetPowerLevel_datafield_FRUDeviceID,
			    						tvb, (*poffset)++, 1, TRUE);
			}
			/* Power Type */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetPowerLevel_datafield_PowerType,
			    						tvb, (*poffset)++, 1, TRUE);
			}
			
		}

}

static void
dissect_cmd_Set_Fan_Level(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo _U_, tvbuff_t *tvb,
								gint *poffset, guint8 len _U_, guint8 response, guint8 auth_offset _U_)
{
		if(response) {

			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_SetFanLevel_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}

		}
		else {
			
			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_SetFanLevel_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			/* FRU Device ID */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_SetFanLevel_datafield_FRUDeviceID,
			    						tvb, (*poffset)++, 1, TRUE);
			}
			/* Fan Level */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_SetFanLevel_datafield_FanLevel,
			    						tvb, (*poffset)++, 1, TRUE);
			}
						
		}

}

static void
dissect_cmd_Get_Fan_Level(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo _U_, tvbuff_t *tvb,
								gint *poffset, guint8 len, guint8 response, guint8 auth_offset _U_)
{
				
		if(response) {

			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetFanLevel_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			 
			/* Override Fan Level */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetFanLevel_datafield_OverrideFanLevel,
			    						tvb, (*poffset)++, 1, TRUE);
			}
			if(3==len) {
			/* Local Control Fan Level */
				if (tree) {
					proto_tree_add_item(ipmi_tree, hf_GetFanLevel_datafield_LocalControlFanLevel,
			    						tvb, (*poffset)++, 1, TRUE);
				}
			}
				
		}
		else {

			/* PICMG Identifier */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetFanLevel_datafield_PICMGIdentifier,
		    							tvb, (*poffset)++, 1, TRUE);
			}
			/* FRU Device ID */
			if (tree) {
				proto_tree_add_item(ipmi_tree, hf_GetFanLevel_datafield_FRUDeviceID,
			    						tvb, (*poffset)++, 1, TRUE);
			}
			
		}

}



/******************************************lane**********************************************/

static void dissect_ipmi_data(proto_tree *, proto_tree *, packet_info *, tvbuff_t *, gint *,
						guint8, guint8, guint8, guint8,guint8);


static const ipmi_cmd_dissect ipmi_cmd_array[] = {
	
	/* Chassis netfn (0x00) */
	{ 0x00,	0x00,	NULL},
	{ 0x00,	0x01,	NULL},
	{ 0x00,	0x02,	NULL},
	{ 0x00,	0x03,	NULL},
	{ 0x00,	0x04,	NULL},
	{ 0x00,	0x05,	NULL},
	{ 0x00,	0x06,	NULL},
	{ 0x00,	0x07,	NULL},
	{ 0x00,	0x08,	NULL},
	{ 0x00,	0x09,	NULL},
	{ 0x00,	0x0f,	NULL},
	/* Bridge netfn (0x02) */
	{ 0x02,	0x00,	NULL},
	{ 0x02,	0x01,	NULL},
	{ 0x02,	0x02,	NULL},
	{ 0x02,	0x03,	NULL},
	{ 0x02,	0x04,	NULL},
	{ 0x02,	0x05,	NULL},
	{ 0x02,	0x06,	NULL},
	{ 0x02,	0x07,	NULL},
	{ 0x02,	0x08,	NULL},
	{ 0x02,	0x09,	NULL},
	{ 0x02,	0x0a,	NULL},
	{ 0x02,	0x0b,	NULL},
	{ 0x02,	0x0c,	NULL},
	{ 0x02,	0x10,	NULL},
	{ 0x02,	0x11,	NULL},
	{ 0x02,	0x12,	NULL},
	{ 0x02,	0x13,	NULL},
	{ 0x02,	0x14,	NULL},
	{ 0x02,	0x20,	NULL},
	{ 0x02,	0x21,	NULL},
	{ 0x02,	0x30,	NULL},
	{ 0x02,	0x31,	NULL},
	{ 0x02,	0x32,	NULL},
	{ 0x02,	0x33,	NULL},
	{ 0x02,	0x34,	NULL},
	{ 0x02,	0x35,	NULL},
	{ 0x02,	0xff,	NULL},
	/* Sensor/Event netfn (0x04) */
	{ 0x04,	0x00,	NULL},
	{ 0x04,	0x01,	NULL},
	{ 0x04,	0x02,	dissect_cmd_PlatformEventMessage},
	{ 0x04,	0x10,	NULL},
	{ 0x04,	0x11,	NULL},
	{ 0x04,	0x12,	NULL},
	{ 0x04,	0x13,	NULL},
	{ 0x04,	0x14,	NULL},
	{ 0x04,	0x15,	NULL},
	{ 0x04,	0x16,	NULL},
	{ 0x04,	0x17,	NULL},
	{ 0x04,	0x20,	dissect_cmd_Get_Device_SDR_Info},
	{ 0x04,	0x21,	dissect_cmd_GetDeviceSDR},
	{ 0x04,	0x22,	dissect_cmd_Reserve_Device_SDR_Repository},
	{ 0x04,	0x23,	NULL},
	{ 0x04,	0x24,	dissect_cmd_Set_Sensor_Hysteresis},
	{ 0x04,	0x25,	dissect_cmd_Get_Sensor_Hysteresis},
	{ 0x04,	0x26,	dissect_cmd_Set_Sensor_Thresholds},
	{ 0x04,	0x27,	dissect_cmd_Get_Sensor_Thresholds},
	{ 0x04,	0x28,	NULL},
	{ 0x04,	0x29,	NULL},
	{ 0x04,	0x2a,	NULL},
	{ 0x04,	0x2b,	NULL},
	{ 0x04,	0x2d,	dissect_cmd_Get_Sensor_Reading},
	{ 0x04,	0x2e,	NULL},
	{ 0x04,	0x2f,	NULL},
	/* App netfn (0x06) */
	{ 0x06,	0x01,	dissect_cmd_Get_Device_ID},
	/* { 0x06,	0x01,	NULL}, */
	{ 0x06,	0x02,	NULL},
	{ 0x06,	0x03,	NULL},
	{ 0x06,	0x04,	NULL},
	{ 0x06,	0x05,	NULL},
	{ 0x06,	0x06,	NULL},
	{ 0x06,	0x07,	NULL},
	{ 0x06,	0x08,	NULL},
	{ 0x06,	0x22,	NULL},
	{ 0x06,	0x24,	NULL},
	{ 0x06,	0x25,	NULL},
	{ 0x06,	0x2e,	NULL},
	{ 0x06,	0x2f,	NULL},
	{ 0x06,	0x30,	NULL},
	{ 0x06,	0x31,	NULL},
	{ 0x06,	0x32,	NULL},
	{ 0x06,	0x33,	NULL},
	{ 0x06,	0x34,	NULL},
	{ 0x06,	0x35,	NULL},
	{ 0x06,	0x36,	NULL},
	{ 0x06,	0x37,	NULL},
	{ 0x06,	0x38,	dissect_cmd_Get_Channel_Auth_Capabilities},
	{ 0x06,	0x39,	NULL},
	{ 0x06,	0x3a,	NULL},
	{ 0x06,	0x3b,	NULL},
	{ 0x06,	0x3c,	NULL},
	{ 0x06,	0x3d,	NULL},
	{ 0x06,	0x3f,	NULL},
	{ 0x06,	0x40,	NULL},
	{ 0x06,	0x41,	NULL},
	{ 0x06,	0x42,	NULL},
	{ 0x06,	0x43,	NULL},
	{ 0x06,	0x44,	NULL},
	{ 0x06,	0x45,	NULL},
	{ 0x06,	0x46,	NULL},
	{ 0x06,	0x47,	NULL},
	{ 0x06,	0x52,	NULL},
	/*Storage netfn (0x0a)  */
	{ 0x0a,	0x10,	dissect_cmd_Get_FRU_Inventory_Area_Info},
	{ 0x0a,	0x11,	NULL},
	{ 0x0a,	0x12,	NULL},
	{ 0x0a,	0x20,	NULL},
	{ 0x0a,	0x21,	NULL},
	{ 0x0a,	0x22,	NULL},
	{ 0x0a,	0x23,	NULL},
	{ 0x0a,	0x24,	NULL},
	{ 0x0a,	0x25,	NULL},
	{ 0x0a,	0x26,	NULL},
	{ 0x0a,	0x27,	NULL},
	{ 0x0a,	0x28,	NULL},
	{ 0x0a,	0x29,	NULL},
	{ 0x0a,	0x2a,	NULL},
	{ 0x0a,	0x2b,	NULL},
	{ 0x0a,	0x2d,	NULL},
	{ 0x0a,	0x2c,	NULL},
	{ 0x0a,	0x40,	dissect_cmd_Get_SEL_Info},
	{ 0x0a,	0x41,	NULL},
	{ 0x0a,	0x42,	dissect_cmd_Reserve_SEL},
	{ 0x0a,	0x43,	dissect_cmd_Get_SEL_Entry},
	{ 0x0a,	0x44,	NULL},
	{ 0x0a,	0x45,	NULL},
	{ 0x0a,	0x46,	NULL},
	{ 0x0a,	0x47,	dissect_cmd_Clear_SEL},
	{ 0x0a,	0x48,	NULL},
	{ 0x0a,	0x49,	NULL},
	{ 0x0a,	0x5a,	NULL},
	{ 0x0a,	0x5b,	NULL},
	/* PICMG netfn (0x2c) */
	{0x2c,	0x00,	dissect_cmd_Get_PICMG_Properties},
	{0x2c,	0x01,	NULL},
	{0x2c,	0x02,	NULL},
	{0x2c,	0x03,	NULL},
	{0x2c,	0x04,	dissect_cmd_FRU_Control},
	{0x2c,	0x05,	dissect_cmd_Get_FRU_Led_Properties},
	{0x2c,	0x06,	dissect_cmd_Get_Led_Color_Capabilities},
	{0x2c,	0x07,	dissect_cmd_Set_FRU_Led_State},
	{0x2c,	0x08,	dissect_cmd_Get_FRU_Led_State},
	{0x2c,	0x09,	NULL},
	{0x2c,	0x0a,	dissect_cmd_Set_FRU_Activation_Policy},
	{0x2c,	0x0b,	dissect_cmd_Get_FRU_Activation_Policy},
	{0x2c,	0x0c,	dissect_cmd_Set_FRU_Activation},
	{0x2c,	0x0d,	dissect_cmd_Get_Device_Locator_Record_ID},
	{0x2c,	0x0e,	NULL},
	{0x2c,	0x0f,	NULL},
	{0x2c,	0x10,	NULL},
	{0x2c,	0x11,	dissect_cmd_Set_Power_Level},
	{0x2c,	0x12,	dissect_cmd_Get_Power_Level},
	{0x2c,	0x13,	NULL},
	{0x2c,	0x14,	NULL},
	{0x2c,	0x15,	dissect_cmd_Set_Fan_Level},
	{0x2c,	0x16,	dissect_cmd_Get_Fan_Level},
	{0x2c,	0x17,	NULL},
	{0x2c,	0x18,	NULL},		
};

#define NUM_OF_CMD_ARRAY (sizeof(ipmi_cmd_array)/sizeof(ipmi_cmd_dissect))

/***************************************************/

static const char *
get_netfn_cmd_text(guint8 netfn, guint8 cmd)
{
	switch (netfn) {
	case 0x00:
	case 0x01:
		return val_to_str(cmd, ipmi_chassis_cmd_vals, "Unknown (0x%02x)");
	case 0x02:
	case 0x03:
		return val_to_str(cmd, ipmi_bridge_cmd_vals, "Unknown (0x%02x)");
	case 0x04:
	case 0x05:
		return val_to_str(cmd, ipmi_se_cmd_vals, "Unknown (0x%02x)");
	case 0x06:
	case 0x07:
		return val_to_str(cmd, ipmi_app_cmd_vals, "Unknown (0x%02x)");
	case 0x0a:
	case 0x0b:
		return val_to_str(cmd, ipmi_storage_cmd_vals, "Unknown (0x%02x)");
	case 0x0c:
	case 0x0d:
		return val_to_str(cmd, ipmi_transport_cmd_vals, "Unknown (0x%02x)");
	case 0x2c: /* added by lane */
	case 0x2d:
		return val_to_str(cmd, ipmi_picmg_cmd_vals, "Unknown (0x%02x)");
	default:
		return (netfn & 1) ? "Unknown Response" : "Unknown Request";
	}
}

static void
dissect_ipmi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*ipmi_tree = NULL, *field_tree = NULL;
	proto_item	*ti = NULL, *tf;
	gint			offset = 0;
	gint			auth_offset = 0;
	/* tvbuff_t	*next_tvb; */  /* modified by lane */
	guint32		session_id;
	/*payloadtype for RMCPP*/
	guint8		authtype, payloadtype = 0, netfn, cmd, ccode, len, response;
	gboolean	payloadtype_auth, payloadtype_enc = 0;

	/* session authtype, 0=no authcode present */
	authtype = tvb_get_guint8(tvb, 0);



	/* EventData 1~3 */
	switch(authtype) {

		case IPMI_AUTH_RMCPP:
			/* RMCPP
			 *  ipmi.session.authtype 	=6
			 *	Payload Type			+1
			 *  ipmi.session.id
			 *  ipmi.session.sequence
			 * [OEM IANA]				+?
			 * [OEM Payload ID]			+?
			 *  ipmi.msg.len			+1
 			 */
			auth_offset = 2;

			break;
		case IPMI_AUTH_NONE:
			auth_offset = 0;
			break;
		default:
			auth_offset = 16;
		}


/*
	2.0:	IPMI v2.0 RMCP+ Session ID	4
	BOTH:	Session Sequence Number		4
	1.5:	IPMI v1.5 Session ID		4
*/

	/* session ID */
	if (authtype == IPMI_AUTH_RMCPP) {
		/* -1 for 2 byte length field when RMCPP */
		session_id = tvb_get_letohl(tvb, auth_offset + 9 - 1);
	} else {
		session_id = tvb_get_letohl(tvb, auth_offset + 5);
	}

	/* network function code */
	netfn = tvb_get_guint8(tvb, auth_offset + 11) >> 2;

	/* bit 0 of netfn: even=request odd=response */
	response =  netfn & 1;

	/* command */
	cmd = tvb_get_guint8(tvb, auth_offset + 15);

	/* completion code */
	ccode = response ? tvb_get_guint8(tvb, auth_offset + 16) : 0;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		if (authtype == IPMI_AUTH_RMCPP) {
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "RMCPP");
		} else {
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPMI");
		}
	}
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);
	if (authtype != IPMI_AUTH_RMCPP) {
		if (check_col(pinfo->cinfo, COL_INFO)) {
			if (ccode)
				col_add_fstr(pinfo->cinfo, COL_INFO, "%s, %s: %s",
				     get_netfn_cmd_text(netfn, cmd),
				     val_to_str(netfn, ipmi_netfn_vals,	"Unknown (0x%02x)"),
				     val_to_str(ccode, ipmi_ccode_vals,	"Unknown (0x%02x)"));
			else
				col_add_fstr(pinfo->cinfo, COL_INFO, "%s, %s",
				     get_netfn_cmd_text(netfn, cmd),
				     val_to_str(netfn, ipmi_netfn_vals,	"Unknown (0x%02x)"));
		}
	}

	if (tree) {
		ti = proto_tree_add_protocol_format(tree, proto_ipmi,
			    tvb, offset, auth_offset + 16,
			    "Intelligent Platform Management Interface, "
			    "NetFn: %s (0x%02x), Cmd: %s (0x%02x)",
			    val_to_str(netfn, ipmi_netfn_vals, "Unknown (0x%02x)"),
			    netfn, get_netfn_cmd_text(netfn, cmd), cmd);
		ipmi_tree = proto_item_add_subtree(ti, ett_ipmi);
	}
	
/*
	2.0:	IPMI v2.0 RMCP+ Session ID	4
	BOTH:	Session Sequence Number		4
	1.5:	IPMI v1.5 Session ID		4
*/


	/* ipmi session field */

	if (authtype == IPMI_AUTH_RMCPP) {

		/*5 - 1 :subtract extra byte from 2 byte length correction*/
		tf = proto_tree_add_text(ipmi_tree, tvb, offset,
				 auth_offset + 5 - 1,
				 "Session: ID 0x%08x (%d bytes)",
				 session_id, auth_offset + 5 - 1);
		field_tree = proto_item_add_subtree(tf, ett_ipmi_session);
		proto_tree_add_item(field_tree, hf_ipmi_session_authtype,
				tvb, offset++, 1, TRUE);

		/*payloadtype */
		payloadtype = tvb_get_guint8(tvb,offset);
		payloadtype_auth = (payloadtype >> 6) & 1;
		payloadtype_enc = (payloadtype >> 7);
		payloadtype = payloadtype & 0x3f;
		proto_tree_add_item(field_tree, hf_ipmi_payloadtype,
				tvb, offset, 1, TRUE);
		/* Bit [6] - 0b = payload is unauthenticated (no AuthCode field)
		 *			 1b = payload is authenticated (AuthCode field is present)
		 * Bit [7] - 0b = payload is unencrypted
		 *			 1b = payload is encrypted
		 */
		proto_tree_add_item(field_tree, hf_ipmi_payloadtype_auth,
				tvb, offset, 1, TRUE);
		proto_tree_add_item(field_tree, hf_ipmi_payloadtype_enc,
				tvb, offset, 1, TRUE);
		offset++;
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
				val_to_str(payloadtype, ipmi_payload_vals,	"Unknown (0x%02x)"));
		}
	 
		if ( payloadtype == IPMI_OEM_EXPLICIT){
			proto_tree_add_item(field_tree, hf_ipmi_oem_iana,
				tvb, offset, 4, TRUE);
			offset = offset+4;
			proto_tree_add_item(field_tree, hf_ipmi_oem_payload_id,
					tvb, offset, 2, TRUE);
			offset = offset+2;
		}
		proto_tree_add_item(field_tree, hf_ipmi_session_id,
				tvb, offset, 4, TRUE);
		offset += 4;

		proto_tree_add_item(field_tree, hf_ipmi_session_sequence,
				tvb, offset, 4, TRUE);
		offset += 4;
	} else {
		tf = proto_tree_add_text(ipmi_tree, tvb, offset,
					 auth_offset + 9,
				 "Session: ID 0x%08x (%d bytes)",
					 session_id, auth_offset + 9);
		field_tree = proto_item_add_subtree(tf, ett_ipmi_session);
		proto_tree_add_item(field_tree, hf_ipmi_session_authtype,
			    tvb, offset++, 1, TRUE);
		proto_tree_add_item(field_tree, hf_ipmi_session_sequence,
			    tvb, offset, 4, TRUE);
		offset += 4;
		proto_tree_add_item(field_tree, hf_ipmi_session_id,
			    tvb, offset, 4, TRUE);
		offset += 4;
		if (authtype != IPMI_AUTH_NONE) {
			proto_tree_add_item(field_tree, hf_ipmi_session_authcode,
				    tvb, offset, 16, TRUE);
			offset += 16;
		}
	}

	/* message length */
	if (tree) {

		if(authtype == IPMI_AUTH_RMCPP) {
			proto_tree_add_item(ipmi_tree, hf_ipmi_msg_len,
					tvb, offset, 2, TRUE);
					offset+=2;
					/*
			proto_tree_add_item(ipmi_tree, hf_ipmi_conf_hdr,
					tvb, offset, 1, TRUE);
					offset++;
					*/
		} else {
			proto_tree_add_item(ipmi_tree, hf_ipmi_msg_len,
					tvb, offset, 1, TRUE);
					offset++;
		}
	}
	if ((authtype == IPMI_AUTH_RMCPP)) {
		switch (payloadtype){
		case IPMI_IPMI_MESSAGE:
			if (payloadtype_enc){
				return;
			}
			break;
		default:
			return;
		
		}

	}

	/* r[sq]addr */
	if (tree) {
		proto_tree_add_item(ipmi_tree,
			    response ? hf_ipmi_msg_rqaddr : hf_ipmi_msg_rsaddr,
			    tvb, offset++, 1, TRUE);
	}

	/* netfn/lun */
	if (tree) {
		guint8 lun;

		tf = proto_tree_add_text(ipmi_tree, tvb, offset, 1,
			 "NetFn/LUN: %s (0x%02x)", val_to_str(netfn,
			 ipmi_netfn_vals, "Unknown (0x%02x)"),
			 netfn);

		field_tree = proto_item_add_subtree(tf, ett_ipmi_msg_nlfield);

		proto_tree_add_item(field_tree, hf_ipmi_msg_netfn,
				    tvb, offset, 1, TRUE);
		proto_tree_add_item(field_tree,
				    response ? hf_ipmi_msg_rqlun : hf_ipmi_msg_rslun,
				    tvb, offset, 1, TRUE);
		lun = tvb_get_guint8(tvb, offset) & 3;
		proto_item_append_text(tf, ", LUN 0x%02x", lun);
		offset += 1;
	}

	/* checksum */
	if (tree) {
		proto_tree_add_item(ipmi_tree, hf_ipmi_msg_csum1,
				    tvb, offset++, 1, TRUE);
	}

	/* r[sq]addr */
	if (tree) {
		proto_tree_add_item(ipmi_tree,
				    response ? hf_ipmi_msg_rsaddr : hf_ipmi_msg_rqaddr,
				    tvb, offset++, 1, TRUE);
	}

	/* seq/lun */
	if (tree) {
		guint8 lun;

		tf = proto_tree_add_item(ipmi_tree, hf_ipmi_msg_slfield,
					 tvb, offset, 1, TRUE);
		field_tree = proto_item_add_subtree(tf, ett_ipmi_msg_slfield);

		proto_tree_add_item(field_tree, hf_ipmi_msg_seq,
				    tvb, offset, 1, TRUE);
		proto_tree_add_item(field_tree,
				    response ? hf_ipmi_msg_rslun : hf_ipmi_msg_rqlun,
				    tvb, offset, 1, TRUE);
		lun = tvb_get_guint8(tvb, offset) & 3;
		proto_item_append_text(tf, ", LUN 0x%02x", lun);
		offset += 1;
	}
	

	/* command */
	if (tree) {
		proto_tree_add_text(ipmi_tree, tvb, offset++, 1,
				    "Command: %s (0x%02x)",
				    get_netfn_cmd_text(netfn, cmd), cmd);
	}
	

	/* completion code */
	if (tree && response) {
		proto_tree_add_item(ipmi_tree, hf_ipmi_msg_ccode,
				    tvb, offset++, 1, TRUE);
	}
	

	/* If ccode is non zero and there is only one more byte remaining in
	 * the packet this probably means that the response has been truncated
	 * and the single remaining byte is just the checksum field.
	 */
	if(ccode && response && tvb_reported_length_remaining(tvb, offset)==1){
		proto_tree_add_text(ipmi_tree, tvb, offset, 0, "[Truncated response]");

		/* checksum */
		proto_tree_add_item(ipmi_tree, hf_ipmi_msg_csum2,
				    tvb, offset++, 1, TRUE);
		return;
	}

	/* determine data length */
	len = tvb_get_guint8(tvb,  auth_offset + 9) - 6 - (response ? 1 : 0) -1;
	/*TODO: fix for 2 byte length with RMCPP*/

	/* rem by lane */
	/*
	next_tvb = tvb_new_subset(tvb, offset, len, len);
	call_dissector(data_handle, next_tvb, pinfo, tree);
	offset += len;
	*/

	/* dissect the data block, added by lane */
	dissect_ipmi_data(tree, ipmi_tree, pinfo, tvb, &offset, len, netfn, cmd, response, auth_offset);
	

	/* checksum 2 */
	if (tree) {
		proto_tree_add_item(ipmi_tree, hf_ipmi_msg_csum2,
				    tvb, offset++, 1, TRUE);
	}
}

void
proto_register_ipmi(void)
{
	static hf_register_info hf_session[] = {
		{ &hf_ipmi_session_authtype, {
			"Authentication Type", "ipmi.session.authtype",
			FT_UINT8, BASE_HEX, VALS(ipmi_authtype_vals), 0,
			"IPMI Authentication Type", HFILL }},
		{ &hf_ipmi_payloadtype,{
			"Payload Type", "ipmi.session.payloadtype",
			FT_UINT8, BASE_HEX, VALS(ipmi_payload_vals), 0x3f,
			"IPMI Payload Type", HFILL }},
		{ &hf_ipmi_payloadtype_auth,{
			"Authenticated","ipmi.session.payloadtype.auth",
			FT_BOOLEAN,8,  TFS(&ipmi_payload_aut_val), 0x40,          
			"IPMI Payload Type authenticated", HFILL }},
		{ &hf_ipmi_payloadtype_enc,{
			"Encryption","ipmi.session.payloadtype.enc",
			FT_BOOLEAN,8,  TFS(&ipmi_payload_enc_val), 0x80,          
			"IPMI Payload Type encryption", HFILL }},
		{ &hf_ipmi_oem_iana,{
			"OEM IANA", "ipmi.session.oem.iana",
			FT_BYTES, BASE_HEX, NULL, 0,
			"IPMI OEM IANA", HFILL }},
		{ &hf_ipmi_oem_payload_id,{
			"OEM Payload ID", "ipmi.session.oem.payloadid",
			FT_BYTES, BASE_HEX, NULL, 0,
			"IPMI OEM Payload ID", HFILL }},
		{ &hf_ipmi_session_sequence, {
			"Session Sequence Number", "ipmi.session.sequence",
			FT_UINT32, BASE_HEX, NULL, 0,
			"IPMI Session Sequence Number", HFILL }},
		{ &hf_ipmi_session_id, {
			"Session ID", "ipmi.session.id",
			FT_UINT32, BASE_HEX, NULL, 0,
			"IPMI Session ID", HFILL }},
		{ &hf_ipmi_session_authcode, {
			"Authentication Code", "ipmi.session.authcode",
			FT_BYTES, BASE_HEX, NULL, 0,
			"IPMI Message Authentication Code", HFILL }},
	};
	static hf_register_info hf_msg[] = {
		{ &hf_ipmi_msg_len, {
			"Message Length", "ipmi.msg.len",
			FT_UINT8, BASE_DEC, NULL, 0,
			"IPMI Message Length", HFILL }},
		{ &hf_ipmi_conf_hdr, {
			"Confidentiality Header", "ipmi.msg.confhdr",
			FT_UINT8, BASE_DEC, VALS(ipmi_conf_vals), 0x3f,
			"IPMI Confidentiality Header", HFILL }},
		{ &hf_ipmi_msg_rsaddr, {
			"Response Address", "ipmi.msg.rsaddr",
			FT_UINT8, BASE_HEX, VALS(ipmi_addr_vals), 0,
			"Responder's Slave Address", HFILL }},
		{ &hf_ipmi_msg_csum1, {
			"Checksum 1", "ipmi.msg.csum1",
			FT_UINT8, BASE_HEX, NULL, 0,
			"2s Complement Checksum", HFILL }},
		{ &hf_ipmi_msg_rqaddr, {
			"Request Address", "ipmi.msg.rqaddr",
			FT_UINT8, BASE_HEX, VALS(ipmi_addr_vals), 0,
			"Requester's Address (SA or SWID)", HFILL }},
		{ &hf_ipmi_msg_cmd, {
			"Command", "ipmi.msg.cmd",
			FT_UINT8, BASE_HEX, NULL, 0,
			"IPMI Command Byte", HFILL }},
		{ &hf_ipmi_msg_ccode, {
			"Completion Code", "ipmi.msg.ccode",
			FT_UINT8, BASE_HEX, VALS(ipmi_ccode_vals), 0,
			"Completion Code for Request", HFILL }},
		{ &hf_ipmi_msg_csum2, {
			"Checksum 2", "ipmi.msg.csum2",
			FT_UINT8, BASE_HEX, NULL, 0,
			"2s Complement Checksum", HFILL }},
	};
	static hf_register_info hf_msg_field[] = {
		{ &hf_ipmi_msg_nlfield, {
			"NetFn/LUN", "ipmi.msg.nlfield",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Network Function and LUN field", HFILL }},
		{ &hf_ipmi_msg_netfn, {
			"NetFn", "ipmi.msg.nlfield.netfn",
			FT_UINT8, BASE_HEX, VALS(ipmi_netfn_vals), 0xfc,
			"Network Function Code", HFILL }},
		{ &hf_ipmi_msg_rqlun, {
			"Request LUN", "ipmi.msg.nlfield.rqlun",
			FT_UINT8, BASE_HEX, NULL, 0x03,
			"Requester's Logical Unit Number", HFILL }},
		{ &hf_ipmi_msg_slfield, {
			"Seq/LUN", "ipmi.msg.slfield",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Sequence and LUN field", HFILL }},
		{ &hf_ipmi_msg_seq, {
			"Sequence", "ipmi.msg.slfield.seq",
			FT_UINT8, BASE_HEX, NULL, 0xfc,
			"Sequence Number (requester)", HFILL }},
		{ &hf_ipmi_msg_rslun, {
			"Response LUN", "ipmi.msg.slfield.rslun",
			FT_UINT8, BASE_HEX, NULL, 0x03,
			"Responder's Logical Unit Number", HFILL }},
	};

/********* Sensor/Event, NetFN = 0x04 **********/

	/*  Data field of Platform Event Message command, added by lane */
	static hf_register_info hf_PEM_datafield[] = {
		{ &hf_PEM_datafield_EvMRev, {
			"Event Message Revision", "PEM.datafield.EvMRev",
			FT_UINT8, BASE_HEX, VALS(cmd_PEM_EvMRev_vals), 0,
			"Event Message Revision", HFILL }},
		{ &hf_PEM_datafield_SensorType, {
			"Sensor Type", "PEM.datafield.SensorType",
			FT_UINT8, BASE_HEX, VALS(cmd_PEM_SensorType_vals), 0,
			"Sensor Type", HFILL }},
		{ &hf_PEM_datafield_SensorNumber, {
			"Sensor #", "PEM.datafield.SensorNumber",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Sensor Number", HFILL }},
		{ &hf_PEM_datafield_EventDirAndEventType_EventDir, {
			"Event Direction", "PEM.datafield.EventDirAndEventType.EventDir",
			FT_UINT8, BASE_HEX, VALS(cmd_PEM_EventDir_vals), 0x80,
			"Event Direction", HFILL }},
		{ &hf_PEM_datafield_EventDirAndEventType_EventType, {
			"Event Type", "PEM.datafield.EventType",
			FT_UINT8, BASE_HEX, NULL, 0x7f,
			"Event Type", HFILL }},
		/* threshold */
		{ &hf_PEM_datafield_EventData1_threshold_76, {
			"[7,6] ", "PEM.datafield.EventData1_threshold_76",
			FT_UINT8, BASE_HEX, VALS(cmd_PEM_EventData1_threshold_76_vals), 0xc0,
			"byte 2 in the event data", HFILL }},
		{ &hf_PEM_datafield_EventData1_threshold_54, {
			"[5,4] ", "PEM.datafield.EventData1_threshold_54",
			FT_UINT8, BASE_HEX, VALS(cmd_PEM_EventData1_threshold_54_vals), 0x30,
			"byte 3 in the event data", HFILL }},
		{ &hf_PEM_datafield_EventData1_threshold_30, {
			"Offset from Event/Reading Code for threshold event", "PEM.datafield.EventData1_threshold_30",
			FT_UINT8, BASE_HEX, NULL, 0x0f,
			"Offset from Event/Reading Code for threshold event", HFILL }},
		{ &hf_PEM_datafield_EventData2_threshold, {
			"reading that triggered event", "PEM.datafield.EventData2_threshold",
			FT_UINT8, BASE_HEX, NULL, 0,
			"reading that triggered event", HFILL }},
		{ &hf_PEM_datafield_EventData3_threshold, {
			"threshold value that triggered event", "PEM.datafield.EventData3_threshold",
			FT_UINT8, BASE_HEX, NULL, 0,
			"threshold value that triggered event", HFILL }},	
		/* discrete */
		{ &hf_PEM_datafield_EventData1_discrete_76, {
			"[7,6] ", "PEM.datafield.EventData1_discrete_76",
			FT_UINT8, BASE_HEX, VALS(cmd_PEM_EventData1_discrete_76_vals), 0xc0,
			"byte 2 in the event data", HFILL }},
		{ &hf_PEM_datafield_EventData1_discrete_54, {
			"[5,4] ", "PEM.datafield.EventData1_discrete_54",
			FT_UINT8, BASE_HEX, VALS(cmd_PEM_EventData1_discrete_54_vals), 0x30,
			"byte 3 in the event data", HFILL }},
		{ &hf_PEM_datafield_EventData1_discrete_30, {
			"Offset from Event/Reading Code for threshold event", "PEM.datafield.EventData1_discrete_30",
			FT_UINT8, BASE_HEX, NULL, 0x0f,
			"Offset from Event/Reading Code for threshold event", HFILL }},
		{ &hf_PEM_datafield_EventData2_discrete_74, {
			"Optional offset from 'Severity' Event/Reading Code(0x0f if unspecified)", "PEM.datafield.EventData2_discrete_74",
			FT_UINT8, BASE_HEX, NULL, 0xf0,
			"Optional offset from 'Severity' Event/Reading Code(0x0f if unspecified)", HFILL }},
		{ &hf_PEM_datafield_EventData2_discrete_30, {
			"Optional offset from Event/Reading Type Code for previous discrete event state (0x0f if unspecified)", "PEM.datafield.EventData2_discrete_30",
			FT_UINT8, BASE_HEX, NULL, 0x0f,
			"Optional offset from Event/Reading Type Code for previous discrete event state (0x0f if unspecified)", HFILL }},
		{ &hf_PEM_datafield_EventData3_discrete, {
			"Optional OEM code", "PEM.datafield.EventData3_discrete",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Optional OEM code", HFILL }},
		/* OEM */
		{ &hf_PEM_datafield_EventData1_OEM_76, {
			"[7,6] ", "PEM.datafield.EventData1_OEM_76",
			FT_UINT8, BASE_HEX, VALS(cmd_PEM_EventData1_OEM_76_vals), 0xc0,
			"byte 2 in the event data", HFILL }},
		{ &hf_PEM_datafield_EventData1_OEM_54, {
			"[5,4] ", "PEM.datafield.EventData1_OEM_54",
			FT_UINT8, BASE_HEX, VALS(cmd_PEM_EventData1_OEM_54_vals), 0x30,
			"byte 3 in the event data", HFILL }},
		{ &hf_PEM_datafield_EventData1_OEM_30, {
			"Offset from Event/Reading Type Code", "PEM.datafield.EventData1_OEM_30",
			FT_UINT8, BASE_HEX, NULL, 0x0f,
			"Offset from Event/Reading Type Code", HFILL }},
		{ &hf_PEM_datafield_EventData2_OEM_74, {
			"Optional OEM code bits or offset from 'Severity' Event/Reading Type Code(0x0f if unspecified)", "PEM.datafield.EventData2_OEM_74",
			FT_UINT8, BASE_HEX, NULL, 0xf0,
			"Optional OEM code bits or offset from 'Severity' Event/Reading Type Code(0x0f if unspecified)", HFILL }},
		{ &hf_PEM_datafield_EventData2_OEM_30, {
			"Optional OEM code or offset from Event/Reading Type Code for previous event state(0x0f if unspecified)", "PEM.datafield.EventData2_OEM_30",
			FT_UINT8, BASE_HEX, NULL, 0x0f,
			"Optional OEM code or offset from Event/Reading Type Code for previous event state(0x0f if unspecified)", HFILL }},
		{ &hf_PEM_datafield_EventData3_OEM, {
			"Optional OEM code", "PEM.datafield.EventData3_discrete",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Optional OEM code", HFILL }},
		/* Hot Swap Event  dedicated */
		{ &hf_PEM_datafield_HotSwapEvent_CurrentState, {
			"Current State", "PEM.datafield.HotSwapEvent_CurrentState",
			FT_UINT8, BASE_HEX, VALS(cmd_PEM_HotSwapEvent_state_vals), 0x0f,
			"Current State", HFILL }},
		{ &hf_PEM_datafield_HotSwapEvent_StateChangeCause, {
			"Cause of State Change", "PEM.datafield.HotSwapEvent_EventData2_74",
			FT_UINT8, BASE_HEX, VALS(cmd_PEM_HotSwapEvent_StateChangeCause_vals), 0xf0,
			"Cause of State Change", HFILL }},
		{ &hf_PEM_datafield_HotSwapEvent_PreviousState, {
			"Previous State", "PEM.datafield.HotSwapEvent_HotSwapEvent_PreviousState",
			FT_UINT8, BASE_HEX, VALS(cmd_PEM_HotSwapEvent_state_vals), 0x0f,
			"Previous State", HFILL }},
		{ &hf_PEM_datafield_HotSwapEvent_FRUDeviceID, {
			"FRU Device ID", "PEM.datafield.HotSwapEvent_FRUDeviceID",
			FT_UINT8, BASE_HEX, NULL, 0,
			"FRU Device ID", HFILL }},
	};

	/* Data field of Get Device SDR Info command, added by lane */
	static hf_register_info hf_GetDeviceSDRInfo_datafield[] = {
		{ &hf_GetDeviceSDRInfo_datafield_SensorNumber, {
			"Number of the Sensors in device", "GetDeviceSDRInfo.datafield.PICMGIdentifier",
			FT_UINT8, BASE_DEC, NULL, 0,
			"Number of the Sensors in device", HFILL }},
		{ &hf_GetDeviceSDRInfo_datafield_Flag, {
			"Flag", "GetDeviceSDRInfo.datafield.Flag",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Flag", HFILL }},
		{ &hf_GetDeviceSDRInfo_datafield_Flag_Dynamicpopulation, {
			"Dynamic population", "GetDeviceSDRInfo.datafield.Flag.Dynamicpopulation",
			FT_UINT8, BASE_HEX, VALS(cmd_GetDeviceSDRInfo_data_Flag_Dynamicpopulation_vals), 0x80,
			"Dynamic population", HFILL }},
		{ &hf_GetDeviceSDRInfo_datafield_Flag_Reserved, {
			"Reserved", "GetDeviceSDRInfo.datafield.Flag.Reserved",
			FT_UINT8, BASE_HEX, NULL, 0x70,
			"Reserved", HFILL }},
		{ &hf_GetDeviceSDRInfo_datafield_Flag_DeviceLUNs3, {
			"Device LUN 3", "GetDeviceSDRInfo.datafield.Flag.DeviceLUN3",
			FT_UINT8, BASE_HEX, VALS(cmd_GetDeviceSDRInfo_data_Flag_DeviceLUNs_vals), 0x08,
			"Device LUN 3", HFILL }},
		{ &hf_GetDeviceSDRInfo_datafield_Flag_DeviceLUNs2, {
			"Device LUN 2", "GetDeviceSDRInfo.datafield.Flag.DeviceLUNs2",
			FT_UINT8, BASE_HEX, VALS(cmd_GetDeviceSDRInfo_data_Flag_DeviceLUNs_vals), 0x04,
			"Device LUN 2", HFILL }},
		{ &hf_GetDeviceSDRInfo_datafield_Flag_DeviceLUNs1, {
			"Device LUN 1", "GetDeviceSDRInfo.datafield.Flag.DeviceLUNs1",
			FT_UINT8, BASE_HEX, VALS(cmd_GetDeviceSDRInfo_data_Flag_DeviceLUNs_vals), 0x02,
			"Device LUN 1", HFILL }},
		{ &hf_GetDeviceSDRInfo_datafield_Flag_DeviceLUNs0, {
			"Device LUN 0", "GetDeviceSDRInfo.datafield.Flag.DeviceLUNs0",
			FT_UINT8, BASE_HEX, VALS(cmd_GetDeviceSDRInfo_data_Flag_DeviceLUNs_vals), 0x01,
			"Device LUN 0", HFILL }},
		{ &hf_GetDeviceSDRInfo_datafield_SensorPopulationChangeIndicator, {
			"SensorPopulation Change Indicator ", "GetDeviceSDRInfo.datafield.SensorPopulationChangeIndicator",
			FT_UINT32, BASE_HEX, NULL, 0,
			"Sensor Population Change Indicator", HFILL }},
	};

	/*  Data field of Reserve Device SDR Repository command, added by lane */
	static hf_register_info hf_ReserveDeviceSDRRepository_datafield[] = {
		{ &hf_ReserveDeviceSDRRepository_datafield_ReservationID, {
			"Reservation ID", "ReserveDeviceSDRRepository.datafield.ReservationID",
			FT_UINT16, BASE_HEX, NULL, 0,
			"Reservation ID", HFILL }},
	};

	/*  Data field of Get Device SDR command, added by lane */
	static hf_register_info hf_GetDeviceSDR_datafield[] = {
		{ &hf_GetDeviceSDR_datafield_ReservationID, {
			"Reservation ID", "GetDeviceSDR.datafield.ReservationID",
			FT_UINT16, BASE_HEX, NULL, 0,
			"Reservation ID", HFILL }},
		{ &hf_GetDeviceSDR_datafield_RecordID, {
			"Record ID of record to Get", "GetDeviceSDR.datafield.RecordID",
			FT_UINT16, BASE_HEX, NULL, 0,
			"Record ID of record to Get", HFILL }},
		{ &hf_GetDeviceSDR_datafield_OffsetIntoRecord, {
			"Offset into record", "GetDeviceSDR.datafield.OffsetIntoRecord",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Offset into record", HFILL }},
		{ &hf_GetDeviceSDR_datafield_BytesToRead, {
			"Bytes to read (number)", "GetDeviceSDR.datafield.BytesToRead",
			FT_UINT8, BASE_HEX, VALS(cmd_GetDeviceSDR_data_BytesToRead_vals), 0,
			"Bytes to read", HFILL }},
		{ &hf_GetDeviceSDR_datafield_NextRecordID, {
			"Record ID for next record", "GetDeviceSDR.datafield.ReservationID",
			FT_UINT16, BASE_HEX, NULL, 0,
			"Record ID for next record", HFILL }},		
	};

	/* Data field of Set Sensor Hysteresis command, added by lane */
	static hf_register_info hf_SetSensorHysteresis_datafield[] = {
		{ &hf_SetSensorHysteresis_datafield_SensorNumber, {
			"Sensor Number", "SetSensorHysteresis.datafield.SensorNumber",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Sensor Number", HFILL }},
		{ &hf_SetSensorHysteresis_datafield_ReservedForHysteresisMask, {
			"Reserved for future ' Hysteresis Mask ' definition", "SetSensorHysteresis.datafield.ReservedForHysteresisMask",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Reserved For Hysteresis Mask", HFILL }},
		{ &hf_SetSensorHysteresis_datafield_PositivegoingThresholdHysteresisValue, {
			"Positive-going Threshold Hysteresis Value", "SetSensorHysteresis.datafield.PositivegoingThresholdHysteresisValue",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Positive-going Threshold Hysteresis Value", HFILL }},
		{ &hf_SetSensorHysteresis_datafield_NegativegoingThresholdHysteresisValue, {
			"Negative-going Threshold Hysteresis Value", "SetSensorHysteresis.datafield.NegativegoingThresholdHysteresisValue",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Negative-going Threshold Hysteresis Value", HFILL }},
	};

	/* Data field of Get Sensor Hysteresis command, added by lane */
	static hf_register_info hf_GetSensorHysteresis_datafield[] = {
		{ &hf_GetSensorHysteresis_datafield_SensorNumber, {
			"Sensor Number", "GetSensorHysteresis.datafield.SensorNumber",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Sensor Number", HFILL }},
		{ &hf_GetSensorHysteresis_datafield_ReservedForHysteresisMask, {
			"Reserved for future ' Hysteresis Mask ' definition", "GetSensorHysteresis.datafield.ReservedForHysteresisMask",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Reserved For Hysteresis Mask", HFILL }},
		{ &hf_GetSensorHysteresis_datafield_PositivegoingThresholdHysteresisValue, {
			"Positive-going Threshold Hysteresis Value", "GetSensorHysteresis.datafield.PositivegoingThresholdHysteresisValue",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Positive-going Threshold Hysteresis Value", HFILL }},
		{ &hf_GetSensorHysteresis_datafield_NegativegoingThresholdHysteresisValue, {
			"Negative-going Threshold Hysteresis Value", "GetSensorHysteresis.datafield.NegativegoingThresholdHysteresisValue",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Negative-going Threshold Hysteresis Value", HFILL }},
	};

	/*  Data field of Set Sensor Thresholds command, added by lane */
	static hf_register_info hf_SetSensorThresholds_datafield[] = {
		{ &hf_SetSensorThresholds_datafield_SensorNumber, {
			"Sensor Number", "SetSensorThresholds.datafield.SensorNumber",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Sensor Number", HFILL }},
		{ &hf_SetSensorThresholds_datafield_ControlByte_Bit76, {
			"Bit 7...6 Reserved", "SetSensorThresholds.datafield.ControlByte.Bit76",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Bit 7...6 Reserved", HFILL }},
		{ &hf_SetSensorThresholds_datafield_ControlByte_Bit5, {
			"upper non-recoverable threshold", "SetSensorThresholds.datafield.ControlByte.Bit5",
			FT_UINT8, BASE_HEX, VALS(cmd_SetSensorThresholds_data_ControlByte_Bit_vals), 0x20,
			"upper non-recoverable threshold", HFILL }},
		{ &hf_SetSensorThresholds_datafield_ControlByte_Bit4, {
			"upper critical threshold", "SetSensorThresholds.datafield.ControlByte.Bit4",
			FT_UINT8, BASE_HEX, VALS(cmd_SetSensorThresholds_data_ControlByte_Bit_vals), 0x10,
			"upper critical threshold", HFILL }},
		{ &hf_SetSensorThresholds_datafield_ControlByte_Bit3, {
			"upper non-critical threshold", "SetSensorThresholds.datafield.ControlByte.Bit3",
			FT_UINT8, BASE_HEX, VALS(cmd_SetSensorThresholds_data_ControlByte_Bit_vals), 0x08,
			"upper non-critical threshold", HFILL }},
		{ &hf_SetSensorThresholds_datafield_ControlByte_Bit2, {
			"lower non-recoverable threshold", "SetSensorThresholds.datafield.ControlByte.Bit2",
			FT_UINT8, BASE_HEX, VALS(cmd_SetSensorThresholds_data_ControlByte_Bit_vals), 0x04,
			"lower non-recoverable threshold", HFILL }},
		{ &hf_SetSensorThresholds_datafield_ControlByte_Bit1, {
			"lower critical threshold", "SetSensorThresholds.datafield.ControlByte.Bit1",
			FT_UINT8, BASE_HEX, VALS(cmd_SetSensorThresholds_data_ControlByte_Bit_vals), 0x02,
			"lower critical threshold", HFILL }},
		{ &hf_SetSensorThresholds_datafield_ControlByte_Bit0, {
			"lower non-critical threshold", "SetSensorThresholds.datafield.ControlByte.Bit0",
			FT_UINT8, BASE_HEX, VALS(cmd_SetSensorThresholds_data_ControlByte_Bit_vals), 0x01,
			"lower non-critical threshold", HFILL }},
		{ &hf_SetSensorThresholds_datafield_LowerNonCriticalThreshold, {
			"lower non-critical threshold", "SetSensorThresholds.datafield.LowerNonCriticalThreshold",
			FT_UINT8, BASE_HEX, NULL, 0,
			"lower non-critical threshold", HFILL }},
		{ &hf_SetSensorThresholds_datafield_LowerCriticalThreshold, {
			"lower critical threshold", "SetSensorThresholds.datafield.LowerCriticalThreshold",
			FT_UINT8, BASE_HEX, NULL, 0,
			"lower critical threshold", HFILL }},
		{ &hf_SetSensorThresholds_datafield_LowerNonRecoverableThreshold, {
			"lower non-recoverable threshold", "SetSensorThresholds.datafield.LowerNonRecoverableThreshold",
			FT_UINT8, BASE_HEX, NULL, 0,
			"lower non-recoverable threshold", HFILL }},
		{ &hf_SetSensorThresholds_datafield_UpperNonCriticalThreshold, {
			"upper non-critical threshold", "SetSensorThresholds.datafield.UpperNonCriticalThreshold",
			FT_UINT8, BASE_HEX, NULL, 0,
			"upper non-critical threshold", HFILL }},
		{ &hf_SetSensorThresholds_datafield_UpperCriticalThreshold, {
			"upper critical threshold", "SetSensorThresholds.datafield.UpperCriticalThreshold",
			FT_UINT8, BASE_HEX, NULL, 0,
			"upper critical threshold", HFILL }},
		{ &hf_SetSensorThresholds_datafield_UpperNonRecoverableThreshold, {
			"upper non-recoverable threshold", "SetSensorThresholds.datafield.UpperNonRecoverableThreshold",
			FT_UINT8, BASE_HEX, NULL, 0,
			"upper non-recoverable threshold", HFILL }},
	};

	/*  Data field of Get Sensor Thresholds command, added by lane */
	static hf_register_info hf_GetSensorThresholds_datafield[] = {
		{ &hf_GetSensorThresholds_datafield_SensorNumber, {
			"Sensor Number", "GetSensorThresholds.datafield.SensorNumber",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Sensor Number", HFILL }},
		{ &hf_GetSensorThresholds_datafield_ControlByte_Bit76, {
			"Bit 7...6 Reserved", "GetSensorThresholds.datafield.ControlByte.Bit76",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Bit 7...6 Reserved", HFILL }},
		{ &hf_GetSensorThresholds_datafield_ControlByte_Bit5, {
			"upper non-recoverable threshold", "GetSensorThresholds.datafield.ControlByte.Bit5",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorThresholds_data_ControlByte_Bit_vals), 0x20,
			"upper non-recoverable threshold", HFILL }},
		{ &hf_GetSensorThresholds_datafield_ControlByte_Bit4, {
			"upper critical threshold", "GetSensorThresholds.datafield.ControlByte.Bit4",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorThresholds_data_ControlByte_Bit_vals), 0x10,
			"upper critical threshold", HFILL }},
		{ &hf_GetSensorThresholds_datafield_ControlByte_Bit3, {
			"upper non-critical threshold", "GetSensorThresholds.datafield.ControlByte.Bit3",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorThresholds_data_ControlByte_Bit_vals), 0x08,
			"upper non-critical threshold", HFILL }},
		{ &hf_GetSensorThresholds_datafield_ControlByte_Bit2, {
			"lower non-recoverable threshold", "GetSensorThresholds.datafield.ControlByte.Bit2",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorThresholds_data_ControlByte_Bit_vals), 0x04,
			"lower non-recoverable threshold", HFILL }},
		{ &hf_GetSensorThresholds_datafield_ControlByte_Bit1, {
			"lower critical threshold", "GetSensorThresholds.datafield.ControlByte.Bit1",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorThresholds_data_ControlByte_Bit_vals), 0x02,
			"lower critical threshold", HFILL }},
		{ &hf_GetSensorThresholds_datafield_ControlByte_Bit0, {
			"lower non-critical threshold", "GetSensorThresholds.datafield.ControlByte.Bit0",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorThresholds_data_ControlByte_Bit_vals), 0x01,
			"lower non-critical threshold", HFILL }},
		{ &hf_GetSensorThresholds_datafield_LowerNonCriticalThreshold, {
			"lower non-critical threshold", "GetSensorThresholds.datafield.LowerNonCriticalThreshold",
			FT_UINT8, BASE_HEX, NULL, 0,
			"lower non-critical threshold", HFILL }},
		{ &hf_GetSensorThresholds_datafield_LowerCriticalThreshold, {
			"lower critical threshold", "GetSensorThresholds.datafield.LowerCriticalThreshold",
			FT_UINT8, BASE_HEX, NULL, 0,
			"lower critical threshold", HFILL }},
		{ &hf_GetSensorThresholds_datafield_LowerNonRecoverableThreshold, {
			"lower non-recoverable threshold", "GetSensorThresholds.datafield.LowerNonRecoverableThreshold",
			FT_UINT8, BASE_HEX, NULL, 0,
			"lower non-recoverable threshold", HFILL }},
		{ &hf_GetSensorThresholds_datafield_UpperNonCriticalThreshold, {
			"upper non-critical threshold", "GetSensorThresholds.datafield.UpperNonCriticalThreshold",
			FT_UINT8, BASE_HEX, NULL, 0,
			"upper non-critical threshold", HFILL }},
		{ &hf_GetSensorThresholds_datafield_UpperCriticalThreshold, {
			"upper critical threshold", "GetSensorThresholds.datafield.UpperCriticalThreshold",
			FT_UINT8, BASE_HEX, NULL, 0,
			"upper critical threshold", HFILL }},
		{ &hf_GetSensorThresholds_datafield_UpperNonRecoverableThreshold, {
			"upper non-recoverable threshold", "GetSensorThresholds.datafield.UpperNonRecoverableThreshold",
			FT_UINT8, BASE_HEX, NULL, 0,
			"upper non-recoverable threshold", HFILL }},
	};
	
	/*  Data field of Get Sensor Reading command, added by lane */
	static hf_register_info hf_GetSensorReading_datafield[] = {
		{ &hf_GetSensorReading_datafield_SensorNumber, {
			"Sensor Number", "GetSensorReading.datafield.SensorNumber",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Sensor Number", HFILL }},
		{ &hf_GetSensorReading_datafield_Sensorreading, {
			"Sensor Reading", "GetSensorReading.datafield.Sensorreading",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Sensor Reading", HFILL }},
		{ &hf_GetSensorReading_datafield_ResponseDataByte2_Bit7, {
			"Bit 7", "GetSensorReading.datafield.ResponseDataByte2.Bit7",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorReading_data_ResponseDataByte2_Bit7_vals), 0x80,
			"Bit 7", HFILL }},
		{ &hf_GetSensorReading_datafield_ResponseDataByte2_Bit6, {
			"Bit 6", "GetSensorReading.datafield.ResponseDataByte2.Bit6",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorReading_data_ResponseDataByte2_Bit6_vals), 0x40,
			"Bit 6", HFILL }},
		{ &hf_GetSensorReading_datafield_ResponseDataByte2_Bit5, {
			"Bit 5", "GetSensorReading.datafield.ResponseDataByte2.Bit5",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorReading_data_ResponseDataByte2_Bit5_vals), 0x20,
			"Bit 5", HFILL }},
		{ &hf_GetSensorReading_datafield_ResponseDataByte2_Bit40, {
			"Bit 4...0 Reserved", "GetSensorReading.datafield.ResponseDataByte2.Bit5",
			FT_UINT8, BASE_HEX, NULL, 0x1f,
			"Bit 4...0 Reserved", HFILL }},
		{ &hf_GetSensorReading_datafield_ResponseDataByte3_Bit7, {
			"Bit 7", "GetSensorReading.datafield.ResponseDataByte3.Bit7",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorReading_data_ResponseDataByte3_Bit7_vals), 0x80,
			"Bit 7", HFILL }},
		{ &hf_GetSensorReading_datafield_ResponseDataByte3_Bit6, {
			"Bit 6", "GetSensorReading.datafield.ResponseDataByte3.Bit6",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorReading_data_ResponseDataByte3_Bit6_vals), 0x40,
			"Bit 6", HFILL }},
		{ &hf_GetSensorReading_datafield_ResponseDataByte3_Bit5, {
			"Bit 5", "GetSensorReading.datafield.ResponseDataByte3.Bit5",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorReading_data_ResponseDataByte3_Bit5_vals), 0x20,
			"Bit 5", HFILL }},
		{ &hf_GetSensorReading_datafield_ResponseDataByte3_Bit4, {
			"Bit 4", "GetSensorReading.datafield.ResponseDataByte3.Bit4",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorReading_data_ResponseDataByte3_Bit4_vals), 0x10,
			"Bit 4", HFILL }},
		{ &hf_GetSensorReading_datafield_ResponseDataByte3_Bit3, {
			"Bit 3", "GetSensorReading.datafield.ResponseDataByte3.Bit3",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorReading_data_ResponseDataByte3_Bit3_vals), 0x08,
			"Bit 3", HFILL }},
		{ &hf_GetSensorReading_datafield_ResponseDataByte3_Bit2, {
			"Bit 2", "GetSensorReading.datafield.ResponseDataByte3.Bit2",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorReading_data_ResponseDataByte3_Bit2_vals), 0x04,
			"Bit 2", HFILL }},
		{ &hf_GetSensorReading_datafield_ResponseDataByte3_Bit1, {
			"Bit 1", "GetSensorReading.datafield.ResponseDataByte3.Bit1",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorReading_data_ResponseDataByte3_Bit1_vals), 0x02,
			"Bit 1", HFILL }},
		{ &hf_GetSensorReading_datafield_ResponseDataByte3_Bit0, {
			"Bit 0", "GetSensorReading.datafield.ResponseDataByte3.Bit0",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorReading_data_ResponseDataByte3_Bit0_vals), 0x01,
			"Bit 0", HFILL }},
		{ &hf_GetSensorReading_datafield_ResponseDataByte4_Bit7, {
			"Bit 7", "GetSensorReading.datafield.ResponseDataByte4.Bit7",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorReading_data_ResponseDataByte4_Bit7_vals), 0x80,
			"Bit 7", HFILL }},
		{ &hf_GetSensorReading_datafield_ResponseDataByte4_Bit6, {
			"Bit 6", "GetSensorReading.datafield.ResponseDataByte4.Bit6",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorReading_data_ResponseDataByte4_Bit6_vals), 0x40,
			"Bit 6", HFILL }},
		{ &hf_GetSensorReading_datafield_ResponseDataByte4_Bit5, {
			"Bit 5", "GetSensorReading.datafield.ResponseDataByte4.Bit5",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorReading_data_ResponseDataByte4_Bit5_vals), 0x20,
			"Bit 5", HFILL }},
		{ &hf_GetSensorReading_datafield_ResponseDataByte4_Bit4, {
			"Bit 4", "GetSensorReading.datafield.ResponseDataByte4.Bit4",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorReading_data_ResponseDataByte4_Bit4_vals), 0x10,
			"Bit 4", HFILL }},
		{ &hf_GetSensorReading_datafield_ResponseDataByte4_Bit3, {
			"Bit 3", "GetSensorReading.datafield.ResponseDataByte3.Bit3",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorReading_data_ResponseDataByte4_Bit3_vals), 0x08,
			"Bit 3", HFILL }},
		{ &hf_GetSensorReading_datafield_ResponseDataByte4_Bit2, {
			"Bit 2", "GetSensorReading.datafield.ResponseDataByte4.Bit2",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorReading_data_ResponseDataByte4_Bit2_vals), 0x04,
			"Bit 2", HFILL }},
		{ &hf_GetSensorReading_datafield_ResponseDataByte4_Bit1, {
			"Bit 1", "GetSensorReading.datafield.ResponseDataByte4.Bit1",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorReading_data_ResponseDataByte4_Bit1_vals), 0x02,
			"Bit 1", HFILL }},
		{ &hf_GetSensorReading_datafield_ResponseDataByte4_Bit0, {
			"Bit 0", "GetSensorReading.datafield.ResponseDataByte4.Bit0",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorReading_data_ResponseDataByte4_Bit0_vals), 0x01,
			"Bit 0", HFILL }},
		{ &hf_GetSensorReading_datafield_ResponseDataByte3_Bit76_threshold, {
			"Bit 7...6 Reserved", "GetSensorReading.datafield.ResponseDataByte3.Bit76_threshold",
			FT_UINT8, BASE_HEX, NULL, 0xc0,
			"Bit 7...6 Reserved", HFILL }},
		{ &hf_GetSensorReading_datafield_ResponseDataByte3_Bit5_threshold, {
			"Bit 5", "GetSensorReading.datafield.ResponseDataByte3.Bit5_threshold",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorReading_data_ResponseDataByte3_Bit5_threshold_vals), 0x20,
			"Bit 5", HFILL }},
		{ &hf_GetSensorReading_datafield_ResponseDataByte3_Bit4_threshold, {
			"Bit 4", "GetSensorReading.datafield.ResponseDataByte3.Bit4_threshold",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorReading_data_ResponseDataByte3_Bit4_threshold_vals), 0x10,
			"Bit 4", HFILL }},
		{ &hf_GetSensorReading_datafield_ResponseDataByte3_Bit3_threshold, {
			"Bit 3", "GetSensorReading.datafield.ResponseDataByte3.Bit3_threshold",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorReading_data_ResponseDataByte3_Bit3_threshold_vals), 0x08,
			"Bit 3", HFILL }},
		{ &hf_GetSensorReading_datafield_ResponseDataByte3_Bit2_threshold, {
			"Bit 2", "GetSensorReading.datafield.ResponseDataByte3.Bit2_threshold",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorReading_data_ResponseDataByte3_Bit2_threshold_vals), 0x04,
			"Bit 2", HFILL }},
		{ &hf_GetSensorReading_datafield_ResponseDataByte3_Bit1_threshold, {
			"Bit 1", "GetSensorReading.datafield.ResponseDataByte3.Bit1_threshold",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorReading_data_ResponseDataByte3_Bit1_threshold_vals), 0x02,
			"Bit 1", HFILL }},
		{ &hf_GetSensorReading_datafield_ResponseDataByte3_Bit0_threshold, {
			"Bit 0", "GetSensorReading.datafield.ResponseDataByte3.Bit0_threshold",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSensorReading_data_ResponseDataByte3_Bit0_threshold_vals), 0x01,
			"Bit 0", HFILL }},
};

/********* APP, NetFN = 0x06 *********/

	/* Data field of Get Device ID command, added by lane */
	static hf_register_info hf_GetDeviceID_datafield[] = {
		{ &hf_GetDeviceID_datafield_DeviceID, {
			"Device ID", "GetDeviceID.datafield.DeviceID",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Device ID field", HFILL }},
		{ &hf_GetDeviceID_datafield_DeviceSDR, {
			"Device SDR", "GetDeviceID.datafield.DeviceSDR",
			FT_UINT8, BASE_HEX, VALS(cmd_GetDeviceID_data_DeviceSDR_vals), 0x80,
			"Device SDR ", HFILL }},
		{ &hf_GetDeviceID_datafield_DeviceRevision, {
			"Device Revision", "GetDeviceID.datafield.DeviceRevision",
			FT_UINT8, BASE_HEX, VALS(cmd_GetDeviceID_Data_DeviceRevision_vals), 0x0f,
			"Device Revision binary code", HFILL }},
		{ &hf_GetDeviceID_datafield_DeviceAvailable, {
			"Device Available", "GetDeviceID.datafield.DeviceAvailable",
			FT_UINT8, BASE_HEX, VALS(cmd_GetDeviceID_data_DeviceAvailable_vals), 0x80,
			"Device Available", HFILL }},
		{ &hf_GetDeviceID_datafield_MajorFirmwareRevision, {
			"Major Firmware Revision", "GetDeviceID.datafield.MajorFirmwareRevision",
			FT_UINT8, BASE_DEC, NULL, 0x7f,
			"Major Firmware Revision", HFILL }},
		{ &hf_GetDeviceID_datafield_MinorFirmwareRevision, {
			"Minor Firmware Revision", "GetDeviceID.datafield.MinorFirmwareRevision",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Minor Firmware Revision", HFILL }},	
		{ &hf_GetDeviceID_datafield_IPMIRevision, {
			"IPMI Revision", "GetDeviceID.datafield.IPMIRevision",
			FT_UINT8, BASE_HEX, VALS(cmd_GetDeviceID_Data_IPMIRevision_vals), 0,
			"IPMI Revision", HFILL }},
		{ &hf_GetDeviceID_datafield_ADS_Chasis, {
			"Chasis Device", "GetDeviceID.datafield.Chasis",
			FT_UINT8, BASE_HEX, VALS(cmd_GetDeviceID_data_ADS_vals), 0x80,
			"Chasis Device", HFILL }},
		{ &hf_GetDeviceID_datafield_ADS_Bridge, {
			"Bridge Device", "GetDeviceID.datafield.Bridge",
			FT_UINT8, BASE_HEX, VALS(cmd_GetDeviceID_data_ADS_vals), 0x40,
			"Bridge Device", HFILL }},
		{ &hf_GetDeviceID_datafield_ADS_IPMBEventGenerator, {
			"IPMB Event Generator", "GetDeviceID.datafield.IPMBEventGenerator",
			FT_UINT8, BASE_HEX, VALS(cmd_GetDeviceID_data_ADS_vals), 0x20,
			"IPMB Event Generator", HFILL }},
		{ &hf_GetDeviceID_datafield_ADS_IPMBEventReceiver, {
			"IPMB Event Receiver", "GetDeviceID.datafield.IPMBEventReceiver",
			FT_UINT8, BASE_HEX, VALS(cmd_GetDeviceID_data_ADS_vals), 0x10,
			"IPMB Event Receiver", HFILL }},
		{ &hf_GetDeviceID_datafield_ADS_FRUInventoryDevice, {
			"FRU Inventory Device", "GetDeviceID.datafield.FRUInventoryDevice",
			FT_UINT8, BASE_HEX, VALS(cmd_GetDeviceID_data_ADS_vals), 0x08,
			"FRU Inventory Device", HFILL }},
		{ &hf_GetDeviceID_datafield_ADS_SELDevice, {
			"SEL Device", "GetDeviceID.datafield.SELDevice",
			FT_UINT8, BASE_HEX, VALS(cmd_GetDeviceID_data_ADS_vals), 0x04,
			"SEL Device", HFILL }},
		{ &hf_GetDeviceID_datafield_ADS_SDRRepositoryDevice, {
			"SDR Repository Device", "GetDeviceID.datafield.SDRRepositoryDevice",
			FT_UINT8, BASE_HEX, VALS(cmd_GetDeviceID_data_ADS_vals), 0x02,
			"SDR Repository Device", HFILL }},
		{ &hf_GetDeviceID_datafield_ADS_SensorDevice, {
			"Sensor Device", "GetDeviceID.datafield.SensorDevice",
			FT_UINT8, BASE_HEX, VALS(cmd_GetDeviceID_data_ADS_vals), 0x01,
			"Sensor Device", HFILL }},
		{ &hf_GetDeviceID_datafield_ManufactureID, {
			"Manufacture ID", "GetDeviceID.datafield.ManufactureID",
			FT_UINT24, BASE_HEX, NULL, 0,
			"Manufacture ID", HFILL }},
		{ &hf_GetDeviceID_datafield_ProductID, {
			"Product ID", "GetDeviceID.datafield.ProductID",
			FT_UINT16, BASE_HEX, NULL, 0,
			"Product ID", HFILL }},	
		{ &hf_GetDeviceID_datafield_AFRI, {
			"Auxiliary Firmware Revision Infomation", "GetDeviceID.datafield.AuxiliaryFirmwareRevisionInfomation",
			FT_UINT32, BASE_HEX, NULL, 0,
			"Auxiliary Firmware Revision Infomation", HFILL }},
	};
	/* Data field of Get Channel Authentication Capabilities command */
	static hf_register_info hf_Get_Ch_Auth_Cap_datafield[] = {
		{ &hf_Get_Channel_Auth_Cap_channel_number, {
			"Channel number", "GetChannelAuthCap.resp.channelno",
			FT_UINT8, BASE_DEC, NULL, 0,
			"Channel number", HFILL }},
		{ &hf_Get_Channel_Auth_Cap_comp_info, {
			"Compabillity information", "GetChannelAuthCap.resp.Auth_Cap_comp_info",
			FT_BOOLEAN,8,  TFS(&ipmi_Auth_Cap_comp_val), 0x80,          
			"Compabillity information", HFILL }},
		{ &hf_Get_Channel_Auth_Cap_Auth_types_b5, {
			"OEM proprietary (per OEM identified by the IANA OEM ID in the RMCP Ping Response)", "GetChannelAuthCap.resp.auth_types_b4",
			FT_BOOLEAN,8, TFS(&ipmi_Authentication_Type_Support_val), 0x20,
			"OEM proprietary (per OEM identified by the IANA OEM ID in the RMCP Ping Response)", HFILL }},
		{ &hf_Get_Channel_Auth_Cap_Auth_types_b4, {
			"Straight password / key", "GetChannelAuthCap.resp.auth_types_b4",
			FT_BOOLEAN,8, TFS(&ipmi_Authentication_Type_Support_val), 0x10,
			"Straight password / key", HFILL }},
		{ &hf_Get_Channel_Auth_Cap_Auth_types_b2, {
			"MD5", "GetChannelAuthCap.resp.auth_types_b2",
			FT_BOOLEAN,8, TFS(&ipmi_Authentication_Type_Support_val), 0x04,
			"MD5", HFILL }},
		{ &hf_Get_Channel_Auth_Cap_Auth_types_b1, {
			"MD2", "GetChannelAuthCap.resp.auth_types_b1",
			FT_BOOLEAN,8, TFS(&ipmi_Authentication_Type_Support_val), 0x02,
			"MD2", HFILL }},
		{ &hf_Get_Channel_Auth_Cap_Auth_types_b0, {
			"None", "GetChannelAuthCap.resp.auth_types_b0",
			FT_BOOLEAN,8, TFS(&ipmi_Authentication_Type_Support_val), 0x01,
			"None", HFILL }},
		{ &hf_Get_Channel_Auth_Cap_Auth_KG_status, {
			"KG status", "GetChannelAuthCap.resp.auth_types_b0",
			FT_BOOLEAN,8, TFS(&ipmi_Authentication_Type_KG_status_val), 0x20,
			"KG status (two-key login status)", HFILL }},
		{ &hf_Get_Channel_Auth_Cap_per_mess_auth_status, {
			"Per-message Authentication is enabled", "GetChannelAuthCap.resp.per_mess_auth_status",
			FT_BOOLEAN,8, TFS(&ipmi_Authentication_Type_per_mess_auth_status_val), 0x10,
			"Per-message Authentication is enabled", HFILL }},
		{ &hf_Get_Channel_Auth_Cap_user_level_auth_status, {
			"User Level Authentication status", "GetChannelAuthCap.resp.user_level_auth_status",
			FT_BOOLEAN,8, TFS(&ipmi_Authentication_Type_user_level_auth_status_val), 0x08,
			"User Level Authentication status", HFILL }},
		{ &hf_Get_Channel_Auth_Cap_anonymouslogin_status_b2, {
			"Non-null usernames enabled", "GetChannelAuthCap.resp.anonymouslogin_status_b2",
			FT_BOOLEAN,8, NULL, 0x04,
			"Non-null usernames enabled", HFILL }},
		{ &hf_Get_Channel_Auth_Cap_anonymouslogin_status_b1, {
			"Null usernames enabled", "GetChannelAuthCap.resp.anonymouslogin_status_b1",
			FT_BOOLEAN,8, NULL, 0x02,
			"Null usernames enabled", HFILL }},
		{ &hf_Get_Channel_Auth_Cap_anonymouslogin_status_b0, {
			"Anonymous Login enabled", "GetChannelAuthCap.resp.anonymouslogin_status_b0",
			FT_BOOLEAN,8, NULL, 0x01,
			"Anonymous Login enabled", HFILL }},
		{ &hf_Get_Channel_Auth_Cap_ext_cap_b1, {
			"Channel supports IPMI v2.0 connections", "GetChannelAuthCap.resp.ext_cap_b1",
			FT_BOOLEAN,8, NULL, 0x02,
			"Channel supports IPMI v2.0 connections", HFILL }},
		{ &hf_Get_Channel_Auth_Cap_ext_cap_b0, {
			"Channel supports IPMI v1.5 connections", "GetChannelAuthCap.resp.ext_cap_b0",
			FT_BOOLEAN,8, NULL, 0x01,
			"Channel supports IPMI v1.5 connections", HFILL }},
		{ &hf_Get_Channel_Auth_OEM_ID, {
			"OEM ID", "GetChannelAuthCap.resp.oemid",
			FT_UINT24, BASE_HEX, NULL, 0,
			"OEM ID", HFILL }},
		{ &hf_Get_Channel_Auth_OEM_AUX, {
			"OEM auxiliary data", "GetChannelAuthCap.resp.oemaux",
			FT_UINT8, BASE_HEX, NULL, 0,
			"OEM auxiliary data.", HFILL }},

		{ &hf_Get_Channel_Auth_Cap_datafield_comp_info, {
			"Compabillity information", "GetChannelAuthCap.datafield.compinfo",
			FT_BOOLEAN,8,  TFS(&ipmi_Auth_Cap_datafield_comp_val), 0x80,          
			"Compabillity information", HFILL }},
		{ &hf_Get_Channel_Auth_Cap_datafield_channel_number, {
			"Channel number", "GetChannelAuthCap.datafield.channelno",
			FT_UINT8, BASE_DEC, VALS(GetChannelAuthCap_channelno_vals), 0xf,
			"Channel number", HFILL }},
		{ &hf_Get_Channel_Auth_Cap_datafield_max_priv_lev, {
			"Requested Maximum Privilege Level", "GetChannelAuthCap.datafield.max_priv_lev",
			FT_UINT8, BASE_DEC, VALS(GetChannelAuthCap_max_priv_lev_vals), 0xf,
			"Requested Maximum Privilege Level", HFILL }},
	};

/********* Storage, NetFN = 0x0a *********/

	/* Data field of Get FRU Inventory Area Info, added by lane */
	static hf_register_info hf_GetFRUInventoryAreaInfo_datafield[] = {
		{ &hf_GetFRUInventoryAreaInfo_datafield_FRUDeviceID, {
			"FRU Device ID", "GetFRUInventoryAreaInfo.datafield.ReservationID",
			FT_UINT8, BASE_HEX, NULL, 0,
			"FRU Device ID", HFILL }},
		{ &hf_GetFRUInventoryAreaInfo_datafield_FRUInventoryAreaSize, {
			"FRU Inventory area size in bytes", "GetFRUInventoryAreaInfo.datafield.FRUInventoryAreaSize",
			FT_UINT16, BASE_HEX, NULL, 0,
			"FRU Inventory area size in bytes", HFILL }},
		{ &hf_GetFRUInventoryAreaInfo_datafield_ResponseDataByte4_Bit71, {
			"Reserved", "GetFRUInventoryAreaInfo.datafield.ResponseDataByte4.Bit71",
			FT_UINT8, BASE_HEX, NULL, 0xfe,
			"Reserved", HFILL }},
		{ &hf_GetFRUInventoryAreaInfo_datafield_ResponseDataByte4_Bit0, {
			"Device is accessed by bytes or words ?", "GetFRUInventoryAreaInfo.datafield.ResponseDataByte4.Bit0",
			FT_UINT8, BASE_HEX, VALS(cmd_GetFRUInventoryAreaInfo_Data_ResponseDataByte4_Bit0_vals), 0x01,
			"Device is accessed by bytes or words ?", HFILL }},
	};
	
	/* Data field of Get SEL Info command, added by lane */
	static hf_register_info hf_GetSELInfo_datafield[] = {
		{ &hf_GetSELInfo_datafield_SELVersion, {
			"SEL Version", "GetSELInfo.datafield.SELVersion",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSELInfo_Data_SELVersion_vals), 0,
			"SEL Version", HFILL }},
		{ &hf_GetSELInfo_datafield_Entries, {
			"Number of log entries in SEL", "GetSELInfo.datafield.Entries",
			FT_UINT16, BASE_HEX, NULL, 0,
			"Number of log entries in SEL", HFILL }},
		{ &hf_GetSELInfo_datafield_FreeSpace, {
			"Free Space in bytes", "GetSELInfo.datafield.FreeSpace",
			FT_UINT16, BASE_HEX, NULL, 0,
			"Free Space in bytes", HFILL }},
		{ &hf_GetSELInfo_datafield_AdditionTimestamp, {
			"Most recent addition timestamp", "GetSELInfo.datafield.AdditionTimestamp",
			FT_UINT32, BASE_HEX, NULL, 0,
			"Most recent addition timestamp", HFILL }},
		{ &hf_GetSELInfo_datafield_EraseTimestamp, {
			"Most recent erase timestamp", "GetSELInfo.datafield.EraseTimestamp",
			FT_UINT32, BASE_HEX, NULL, 0,
			"Most recent erase timestamp", HFILL }},
		{ &hf_GetSELInfo_datafield_OperationSupport_Bit7, {
			"Overflow Flag", "GetSELInfo.datafield.OperationSupport.Bit7",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSELInfo_Data_OperationSupport_Bit7_vals), 0x80,
			"Overflow Flag", HFILL }},	
		{ &hf_GetSELInfo_datafield_OperationSupport_Reserved, {
			"Reserved", "GetSELInfo.datafield.OperationSupport.Reserved",
			FT_UINT8, BASE_HEX, NULL, 0x70,
			"Reserved", HFILL }},
		{ &hf_GetSELInfo_datafield_OperationSupport_Bit3, {
			"Delete SEL command supported ?", "GetSELInfo.datafield.OperationSupport.Bit3",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSELInfo_Data_OperationSupport_Bit3to0_vals), 0x08,
			"Delete SEL command supported ?", HFILL }},
		{ &hf_GetSELInfo_datafield_OperationSupport_Bit2, {
			"Partial Add SEL Entry command supported ?", "GetSELInfo.datafield.OperationSupport.Bit2",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSELInfo_Data_OperationSupport_Bit3to0_vals), 0x04,
			"Partial Add SEL Entry command supported ?", HFILL }},
		{ &hf_GetSELInfo_datafield_OperationSupport_Bit1, {
			"Reserve SEL command supported ?", "GetSELInfo.datafield.OperationSupport.Bit1",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSELInfo_Data_OperationSupport_Bit3to0_vals), 0x02,
			"Reserve SEL command supported ?", HFILL }},
		{ &hf_GetSELInfo_datafield_OperationSupport_Bit0, {
			"Get SEL Allocation Information command supported ?", "GetSELInfo.datafield.OperationSupport.Bit0",
			FT_UINT8, BASE_HEX, VALS(cmd_GetSELInfo_Data_OperationSupport_Bit3to0_vals), 0x01,
			"Get SEL Allocation Information command supported ?", HFILL }},
	};

	/* Data field of Reserve SEL command, added by lane */
	static hf_register_info hf_ReserveSEL_datafield[] = {
		{ &hf_ReserveSEL_datafield_ReservationID, {
			"Reservation ID", "GetSELInfo.datafield.ReservationID",
			FT_UINT16, BASE_HEX, NULL, 0,
			"Reservation ID", HFILL }},
	};

	/* Data field of Get SEL Entry command, added by lane */
	static hf_register_info hf_GetSELEntry_datafield[] = {
		{ &hf_GetSELEntry_datafield_ReservationID, {
			"Reservation ID", "GetSELEntry.datafield.ReservationID",
			FT_UINT16, BASE_HEX, NULL, 0,
			"Reservation ID", HFILL }},
		{ &hf_GetSELEntry_datafield_SELRecordID, {
			"SEL Record ID", "GetSELEntry.datafield.SELRecordID",
			FT_UINT16, BASE_HEX, NULL, 0,
			"SEL Record ID", HFILL }},
		{ &hf_GetSELEntry_datafield_OffsetIntoRecord, {
			"Offset into record", "GetSELEntry.datafield.OffsetIntoRecord",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Offset into record", HFILL }},
		{ &hf_GetSELEntry_datafield_BytesToRead, {
			"Bytes to read", "GetSELEntry.datafield.BytesToRead",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Bytes to read", HFILL }},
		{ &hf_GetSELEntry_datafield_NextSELRecordID, {
			"Next SEL Record ID", "GetSELEntry.datafield.NextSELRecordID",
			FT_UINT16, BASE_HEX, NULL, 0,
			"Next SEL Record ID", HFILL }},
	};

	/* Data field of Clear SEL command, added by lane */
	static hf_register_info hf_ClearSEL_datafield[] = {
		{ &hf_ClearSEL_datafield_ReservationID, {
			"Reservation ID", "ClearSEL.datafield.ReservationID",
			FT_UINT16, BASE_HEX, NULL, 0,
			"Reservation ID", HFILL }},
		{ &hf_ClearSEL_datafield_Byte3, {
			"'C' (0x43)", "ClearSEL.datafield.SELRecordID",
			FT_UINT8, BASE_HEX, NULL, 0,
			"'C' (0x43)", HFILL }},
		{ &hf_ClearSEL_datafield_Byte4, {
			"'L' (0x4C)", "ClearSEL.datafield.OffsetIntoRecord",
			FT_UINT8, BASE_HEX, NULL, 0,
			"'L' (0x4C)", HFILL }},
		{ &hf_ClearSEL_datafield_Byte5, {
			"'R' (0x52)", "ClearSEL.datafield.BytesToRead",
			FT_UINT8, BASE_HEX, NULL, 0,
			"'R' (0x52)", HFILL }},
		{ &hf_ClearSEL_datafield_Byte6, {
			"Action for Clear SEL", "ClearSEL.datafield.NextSELRecordID",
			FT_UINT8, BASE_HEX, VALS(cmd_ClearSEL_Data_Byte6_vals), 0,
			"Action for Clear SEL", HFILL }},
		{ &hf_ClearSEL_datafield_ErasureProgress_Reserved, {
			"Reserved", "ClearSEL.datafield.ErasureProgress.Reserved",
			FT_UINT8, BASE_HEX, NULL, 0xf0,
			"Reserved", HFILL }},
		{ &hf_ClearSEL_datafield_ErasureProgress_EraProg, {
			"Erasure Progress", "ClearSEL.datafield.ErasureProgress.EraProg",
			FT_UINT8, BASE_HEX, VALS(cmd_ClearSEL_Data_ErasureProgress_EraProg_vals), 0x0f,
			"Erasure Progress", HFILL }},
	};
	

/********* PICMG, NetFN = 0x2c *********/

	/* Data field of Get PICMG Properties command, added by lane */
	static hf_register_info hf_GetPICMGProperties_datafield[] = {
		{ &hf_GetPICMGProperties_datafield_PICMGIdentifier, {
			"PICMG Identifier", "GetPICMGProperties.datafield.PICMGIdentifier",
			FT_UINT8, BASE_HEX, NULL, 0,
			"PICMG Identifier", HFILL }},
		{ &hf_GetPICMGProperties_datafield_PICMGExtensionVersion, {
			"PICMG Extension Version", "GetPICMGProperties.datafield.PICMGExtensionVersion",
			FT_UINT8, BASE_HEX, VALS(cmd_GetPICMGProperties_data_PICMGExtensionVersion_vals), 0,
			"PICMG Extension Version", HFILL }},
		{ &hf_GetPICMGProperties_datafield_MaxFRUDeviceID, {
			"Max FRU Device ID", "GetPICMGProperties.datafield.MaxFRUDeviceID",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Max FRU Device ID", HFILL }},
		{ &hf_GetPICMGProperties_datafield_FRUDeviceIDforIPMController, {
			"FRU Device ID for IPM Controller", "GetPICMGProperties.datafield.FRUDeviceIDforIPMController",
			FT_UINT8, BASE_HEX, NULL, 0,
			"FRU Device ID for IPM Controller", HFILL }},		
	};

	/* Data field of FRU Control command, added by lane */
	static hf_register_info hf_FRUControl_datafield[] = {
		{ &hf_FRUControl_datafield_PICMGIdentifier, {
			"PICMG Identifier", "FRUControl.datafield.PICMGIdentifier",
			FT_UINT8, BASE_HEX, NULL, 0,
			"PICMG Identifier", HFILL }},
		{ &hf_FRUControl_datafield_FRUDeviceID, {
			"FRU Device ID", "FRUControl.datafield.FRUDeviceID",
			FT_UINT8, BASE_HEX, NULL, 0,
			"FRU Device ID", HFILL }},
		{ &hf_FRUControl_datafield_FRUControlOption, {
			"FRU Control Option", "FRUControl.datafield.FRUControlOption",
			FT_UINT8, BASE_HEX, VALS(cmd_FRUControl_data_FRUControlOption_vals), 0,
			"FRU Control Option", HFILL }},
	};

	/* Data field of Get FRU Led Properties command, added by lane */
	static hf_register_info hf_GetFRULedProperties_datafield[] = {
		{ &hf_GetFRULedProperties_datafield_PICMGIdentifier, {
			"PICMG Identifier", "GetFRULedProperties.datafield.PICMGIdentifier",
			FT_UINT8, BASE_HEX, NULL, 0,
			"PICMG Identifier", HFILL }},
		{ &hf_GetFRULedProperties_datafield_FRUDeviceID, {
			"FRU Device ID", "GetFRULedProperties.datafield.FRUDeviceID",
			FT_UINT8, BASE_HEX, NULL, 0,
			"FRU Device ID", HFILL }},
		{ &hf_GetFRULedProperties_datafield_LedProperties_Reserved, {
			"Reserved", "GetFRULedProperties.datafield.LedProperties.Reserved",
			FT_UINT8, BASE_HEX, NULL, 0xf0,
			"Reserved", HFILL }},
		{ &hf_GetFRULedProperties_datafield_LedProperties_LED3, {
			"LED3", "GetFRULedProperties.datafield.LedProperties.LED3",
			FT_UINT8, BASE_HEX, VALS(cmd_GetFRULedProperties_data_LedProperties_LED3_vals), 0x08,
			"LED3", HFILL }},
		{ &hf_GetFRULedProperties_datafield_LedProperties_LED2, {
			"LED2", "GetFRULedProperties.datafield.LedProperties.LED2",
			FT_UINT8, BASE_HEX, VALS(cmd_GetFRULedProperties_data_LedProperties_LED2_vals), 0x04,
			"LED2", HFILL }},
		{ &hf_GetFRULedProperties_datafield_LedProperties_LED1, {
			"LED1", "GetFRULedProperties.datafield.LedProperties.LED1",
			FT_UINT8, BASE_HEX, VALS(cmd_GetFRULedProperties_data_LedProperties_LED1_vals), 0x02,
			"LED1", HFILL }},
		{ &hf_GetFRULedProperties_datafield_LedProperties_BlueLED, {
			"BlueLED", "GetFRULedProperties.datafield.LedProperties.BlueLED",
			FT_UINT8, BASE_HEX, VALS(cmd_GetFRULedProperties_data_LedProperties_BLUELED_vals), 0x01,
			"BlueLED", HFILL }},
		{ &hf_GetFRULedProperties_datafield_ApplicationSpecificLEDCount, {
			"Application Specific LED Count", "GetFRULedProperties.datafield.ApplicationSpecificLEDCount",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Application Specific LED Count", HFILL }},
	};

	/* Data field of Get Led Color Capabilities command, added by lane */
	static hf_register_info hf_GetLedColorCapabilities_datafield[] = {
		{ &hf_GetLedColorCapabilities_datafield_PICMGIdentifier, {
			"PICMG Identifier", "GetLedColorCapabilities.datafield.PICMGIdentifier",
			FT_UINT8, BASE_HEX, NULL, 0,
			"PICMG Identifier", HFILL }},
		{ &hf_GetLedColorCapabilities_datafield_FRUDeviceID, {
			"FRU Device ID", "GetLedColorCapabilities.datafield.FRUDeviceID",
			FT_UINT8, BASE_HEX, NULL, 0,
			"FRU Device ID", HFILL }},
		{ &hf_GetLedColorCapabilities_datafield_LEDID, {
			"LED ID", "GetLedColorCapabilities.datafield.LEDID",
			FT_UINT8, BASE_HEX, NULL, 0,
			"LED ID", HFILL }},
		/* LED Color Capabilities */	
		{ &hf_GetLedColorCapabilities_datafield_LEDColorCapabilities_Reserved_7, {
			"Reserved", "GetLedColorCapabilities.datafield.LEDColorCapabilities.Reserved.bit7",
			FT_UINT8, BASE_HEX, NULL, 0x80,
			"Reserved", HFILL }},
		{ &hf_GetLedColorCapabilities_datafield_LEDColorCapabilities_WHITE, {
			"LED Support WHITE ?", "GetLedColorCapabilities.datafield.LEDColorCapabilities.WHITE",
			FT_UINT8, BASE_HEX, VALS(cmd_GetLedColorCapabilities_data_LEDColorCapabilities_vals), 0x40,
			"LED Support WHITE ?", HFILL }},
		{ &hf_GetLedColorCapabilities_datafield_LEDColorCapabilities_ORANGE, {
			"LED Support ORANGE ?", "GetLedColorCapabilities.datafield.LEDColorCapabilities.ORANGE",
			FT_UINT8, BASE_HEX, VALS(cmd_GetLedColorCapabilities_data_LEDColorCapabilities_vals), 0x20,
			"LED Support ORANGE ?", HFILL }},
		{ &hf_GetLedColorCapabilities_datafield_LEDColorCapabilities_AMBER, {
			"LED Support AMBER ?", "GetLedColorCapabilities.datafield.LEDColorCapabilities.AMBER",
			FT_UINT8, BASE_HEX, VALS(cmd_GetLedColorCapabilities_data_LEDColorCapabilities_vals), 0x10,
			"LED Support AMBER ?", HFILL }},
		{ &hf_GetLedColorCapabilities_datafield_LEDColorCapabilities_GREEN, {
			"LED Support GREEN ?", "GetLedColorCapabilities.datafield.LEDColorCapabilities.GREEN",
			FT_UINT8, BASE_HEX, VALS(cmd_GetLedColorCapabilities_data_LEDColorCapabilities_vals), 0x08,
			"LED Support GREEN ?", HFILL }},
		{ &hf_GetLedColorCapabilities_datafield_LEDColorCapabilities_RED, {
			"LED Support RED ?", "GetLedColorCapabilities.datafield.LEDColorCapabilities.RED",
			FT_UINT8, BASE_HEX, VALS(cmd_GetLedColorCapabilities_data_LEDColorCapabilities_vals), 0x04,
			"LED Support RED ?", HFILL }},
		{ &hf_GetLedColorCapabilities_datafield_LEDColorCapabilities_BLUE, {
			"LED Support BLUE ?", "GetLedColorCapabilities.datafield.LEDColorCapabilities.BLUE",
			FT_UINT8, BASE_HEX, VALS(cmd_GetLedColorCapabilities_data_LEDColorCapabilities_vals), 0x02,
			"LED Support BLUE ?", HFILL }},
		{ &hf_GetLedColorCapabilities_datafield_LEDColorCapabilities_Reserved_0, {
			"Reserved", "GetLedColorCapabilities.datafield.LEDColorCapabilities.Reserved.bit0",
			FT_UINT8, BASE_HEX, NULL, 0x01,
			"Reserved", HFILL }},
		/* Default LED Color in Local Control State*/	
		{ &hf_GetLedColorCapabilities_datafield_DefaultLEDColorLocalControl_Reserved_74, {
			"Reserved", "GetLedColorCapabilities.datafield.DefaultLEDColorLocalControl.Reserved.bit7-4",
			FT_UINT8, BASE_HEX, NULL, 0xf0,
			"Reserved", HFILL }},
		{ &hf_GetLedColorCapabilities_datafield_DefaultLEDColorLocalControl_Color, {
			"Default LED Color (Local Control State)", "GetLedColorCapabilities.datafield.DefaultLEDColorLocalControl.Color",
			FT_UINT8, BASE_HEX, VALS(cmd_GetLedColorCapabilities_data_DefaultLEDColor_vals), 0x0f,
			"Default LED Color (Local Control State)", HFILL }},
		/* Default LED Color in Override State */	
		{ &hf_GetLedColorCapabilities_datafield_DefaultLEDColorOverride_Reserved_74, {
			"Reserved", "GetLedColorCapabilities.datafield.DefaultLEDColorOverride.Reserved.bit7-4",
			FT_UINT8, BASE_HEX, NULL, 0xf0,
			"Reserved", HFILL }},
		{ &hf_GetLedColorCapabilities_datafield_DefaultLEDColorOverride_Color, {
			"Default LED Color (Override State)", "GetLedColorCapabilities.datafield.DefaultLEDColorOverride.Color",
			FT_UINT8, BASE_HEX, VALS(cmd_GetLedColorCapabilities_data_DefaultLEDColor_vals), 0x0f,
			"Default LED Color (Override State)", HFILL }},				
	};

	/* Data field of Set FRU Led State, added by lane */
	static hf_register_info hf_SetFRULedState_datafield[] = {
		{ &hf_SetFRULedState_datafield_PICMGIdentifier, {
			"PICMG Identifier", "SetFRULedState.datafield.PICMGIdentifier",
			FT_UINT8, BASE_HEX, NULL, 0,
			"PICMG Identifier", HFILL }},
		{ &hf_SetFRULedState_datafield_FRUDeviceID, {
			"FRU Device ID", "SetFRULedState.datafield.FRUDeviceID",
			FT_UINT8, BASE_HEX, NULL, 0,
			"FRU Device ID", HFILL }},
		{ &hf_SetFRULedState_datafield_LEDID, {
			"LED ID", "SetFRULedState.datafield.LEDID",
			FT_UINT8, BASE_HEX, VALS(cmd_SetFRULedState_data_LEDID_vals), 0,
			"LED ID", HFILL }},
		{ &hf_SetFRULedState_datafield_LEDFunction, {
			"LED Function", "SetFRULedState.datafield.LEDFunction",
			FT_UINT8, BASE_HEX, VALS(cmd_SetFRULedState_data_LEDFunction_vals), 0,
			"LED Function", HFILL }},
		{ &hf_SetFRULedState_datafield_Offduration, {
			"Off-duration", "SetFRULedState.datafield.Offduration",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Off-duration", HFILL }},
		{ &hf_SetFRULedState_datafield_Onduration, {
			"On-duration", "SetFRULedState.datafield.Onduration",
			FT_UINT8, BASE_HEX, NULL, 0,
			"On-duration", HFILL }},
		{ &hf_SetFRULedState_datafield_Color_Reserved, {
			"Bit 7...4 Reserved", "SetFRULedState.datafield.Color.Reserved",
			FT_UINT8, BASE_HEX, NULL, 0xf0,
			"Bit 7...4 Reserved", HFILL }},	
		{ &hf_SetFRULedState_datafield_Color_ColorVal, {
			"Color", "SetFRULedState.datafield.Color.ColorVal",
			FT_UINT8, BASE_HEX, VALS(cmd_SetFRULedState_data_Color_ColorVal_vals), 0x0f,
			"Color", HFILL }},
	};

	/* Data field of Get FRU Led State, added by lane */
	static hf_register_info hf_GetFRULedState_datafield[] = {
		{ &hf_GetFRULedState_datafield_PICMGIdentifier, {
			"PICMG Identifier", "GetFRULedState.datafield.PICMGIdentifier",
			FT_UINT8, BASE_HEX, NULL, 0,
			"PICMG Identifier", HFILL }},
		{ &hf_GetFRULedState_datafield_FRUDeviceID, {
			"FRU Device ID", "GetFRULedState.datafield.FRUDeviceID",
			FT_UINT8, BASE_HEX, NULL, 0,
			"FRU Device ID", HFILL }},
		{ &hf_GetFRULedState_datafield_LEDID, {
			"LED ID", "GetFRULedState.datafield.LEDID",
			FT_UINT8, BASE_HEX, VALS(cmd_GetFRULedState_data_LEDID_vals), 0,
			"LED ID", HFILL }},
		{ &hf_GetFRULedState_datafield_LEDState_Reserved, {
			"Bit 7...3 Reserved", "GetFRULedState.datafield.LEDFunction",
			FT_UINT8, BASE_HEX, NULL, 0xf8,
			"Bit 7...3 Reserved", HFILL }},
		{ &hf_GetFRULedState_datafield_LEDState_Bit2, {
			"Lamp Test", "GetFRULedState.datafield.LEDState.Bit2",
			FT_UINT8, BASE_HEX, VALS(cmd_GetFRULedState_data_LEDState_Bit21_vals), 0x04,
			"Lamp Test", HFILL }},
		{ &hf_GetFRULedState_datafield_LEDState_Bit1, {
			"Override State", "GetFRULedState.datafield.LEDState.Bit1",
			FT_UINT8, BASE_HEX, VALS(cmd_GetFRULedState_data_LEDState_Bit21_vals), 0x02,
			"Override State", HFILL }},	
		{ &hf_GetFRULedState_datafield_LEDState_Bit0, {
			"IPM Controller has a Local Control State ?", "GetFRULedState.datafield.LEDState.Bit0",
			FT_UINT8, BASE_HEX, VALS(cmd_GetFRULedState_data_LEDState_Bit0_vals), 0x01,
			"IPM Controller has a Local Control State ?", HFILL }},
		{ &hf_GetFRULedState_datafield_LocalControlLEDFunction, {
			"Local Control LED Function", "GetFRULedState.datafield.LocalControlLEDFunction",
			FT_UINT8, BASE_HEX, VALS(cmd_GetFRULedState_data_LocalControlLEDFunction_vals), 0,
			"Local Control LED Function", HFILL }},
		{ &hf_GetFRULedState_datafield_LocalControlOffduration, {
			"Local Control Off-duration", "GetFRULedState.datafield.LocalControlOffduration",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Local Control Off-duration", HFILL }},
		{ &hf_GetFRULedState_datafield_LocalControlOnduration, {
			"Local Control On-duration", "GetFRULedState.datafield.LocalControlOnduration",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Local Control On-duration", HFILL }},
		{ &hf_GetFRULedState_datafield_LocalControlColor_Reserved, {
			"Bit 7...4 Reserved", "GetFRULedState.datafield.LocalControlColor.Reserved",
			FT_UINT8, BASE_HEX, NULL, 0xf0,
			"Bit 7...4 Reserved", HFILL }},	
		{ &hf_GetFRULedState_datafield_LocalControlColor_ColorVal, {
			"Color", "GetFRULedState.datafield.LocalControlColor.ColorVal",
			FT_UINT8, BASE_HEX, VALS(cmd_GetFRULedState_data_ColorVal_vals), 0x0f,
			"Color", HFILL }},
		{ &hf_GetFRULedState_datafield_OverrideStateLEDFunction, {
			"Override State LED Function", "GetFRULedState.datafield.OverrideStateLEDFunction",
			FT_UINT8, BASE_HEX, VALS(cmd_GetFRULedState_data_OverrideStateLEDFunction_vals), 0,
			"Override State LED Function", HFILL }},
		{ &hf_GetFRULedState_datafield_OverrideStateOffduration, {
			"Override State Off-duration", "GetFRULedState.datafield.OverrideStateOffduration",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Override State Off-duration", HFILL }},
		{ &hf_GetFRULedState_datafield_OverrideStateOnduration, {
			"Override State On-duration", "GetFRULedState.datafield.OverrideStateOnduration",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Override State On-duration", HFILL }},
		{ &hf_GetFRULedState_datafield_OverrideStateColor_Reserved, {
			"Bit 7...4 Reserved", "GetFRULedState.datafield.OverrideStateColor.Reserved",
			FT_UINT8, BASE_HEX, NULL, 0xf0,
			"Bit 7...4 Reserved", HFILL }},	
		{ &hf_GetFRULedState_datafield_OverrideStateColor_ColorVal, {
			"Color", "GetFRULedState.datafield.OverrideStateColor.ColorVal",
			FT_UINT8, BASE_HEX, VALS(cmd_GetFRULedState_data_ColorVal_vals), 0x0f,
			"Color", HFILL }},
		{ &hf_GetFRULedState_datafield_LampTestDuration, {
			"Lamp Test Duration", "GetFRULedState.datafield.LampTestDuration",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Lamp Test Duration", HFILL }},
	};

	/* Data field of Set FRU Activation command, added by lane */
	static hf_register_info hf_SetFRUActivation_datafield[] = {
		{ &hf_SetFRUActivation_datafield_PICMGIdentifier, {
			"PICMG Identifier", "SetFRUActivation.datafield.PICMGIdentifier",
			FT_UINT8, BASE_HEX, NULL, 0,
			"PICMG Identifier", HFILL }},
		{ &hf_SetFRUActivation_datafield_FRUDeviceID, {
			"FRU Device ID", "SetFRUActivation.datafield.FRUDeviceID",
			FT_UINT8, BASE_HEX, NULL, 0,
			"FRU Device ID", HFILL }},
		{ &hf_SetFRUActivation_datafield_FRUActivationDeactivation, {
			"FRU Activation/Deactivation", "SetFRUActivation.datafield.FRUActivationDeactivation",
			FT_UINT8, BASE_HEX, VALS(cmd_SetFRUActivation_data_FRUActivationDeactivation_vals), 0,
			"FRU Activation/Deactivation", HFILL }},		
	};

	/* Data field of Set FRU Activation Policy command, added by lane */
	static hf_register_info hf_SetFRUActivationPolicy_datafield[] = {
		{ &hf_SetFRUActivationPolicy_datafield_PICMGIdentifier, {
			"PICMG Identifier", "SetFRUActivationPolicy.datafield.PICMGIdentifier",
			FT_UINT8, BASE_HEX, NULL, 0,
			"PICMG Identifier", HFILL }},
		{ &hf_SetFRUActivationPolicy_datafield_FRUDeviceID, {
			"FRU Device ID", "SetFRUActivationPolicy.datafield.FRUDeviceID",
			FT_UINT8, BASE_HEX, NULL, 0,
			"FRU Device ID", HFILL }},
		{ &hf_SetFRUActivationPolicy_datafield_FRUActivationPolicyMaskBit_Bit72, {
			"Bit 7...2 Reserverd", "SetFRUActivationPolicy.datafield.FRUActivationPolicyMaskBit.Bit72",
			FT_UINT8, BASE_HEX, NULL, 0xfc,
			"Bit 7...2 Reserverd", HFILL }},
		{ &hf_SetFRUActivationPolicy_datafield_FRUActivationPolicyMaskBit_Bit1, {
			"Bit 1", "SetFRUActivationPolicy.datafield.FRUActivationPolicyMaskBit.Bit1",
			FT_UINT8, BASE_HEX, VALS(cmd_SetFRUActivationPolicy_data_PFRUActivationPolicyMaskBit_Bit1_vals), 0x02,
			"Bit 1", HFILL }},
		{ &hf_SetFRUActivationPolicy_datafield_FRUActivationPolicyMaskBit_Bit0, {
			"Bit 0", "SetFRUActivationPolicy.datafield.FRUActivationPolicyMaskBit.Bit0",
			FT_UINT8, BASE_HEX, VALS(cmd_SetFRUActivationPolicy_data_PFRUActivationPolicyMaskBit_Bit0_vals), 0x01,
			"Bit 0", HFILL }},
		{ &hf_SetFRUActivationPolicy_datafield_FRUActivationPolicySetBit_Bit72, {
			"Bit 7...2 Reserverd", "SetFRUActivationPolicy.datafield.FRUActivationPolicySetBit.Bit72",
			FT_UINT8, BASE_HEX, NULL, 0xfc,
			"Bit 7...2 Reserverd", HFILL }},
		{ &hf_SetFRUActivationPolicy_datafield_FRUActivationPolicySetBit_Bit1, {
			"Set or Clear Deactivation-Locked", "SetFRUActivationPolicy.datafield.FRUActivationPolicySetBit.Bit1",
			FT_UINT8, BASE_HEX, VALS(cmd_SetFRUActivationPolicy_data_PFRUActivationPolicySetBit_Bit1_vals), 0x02,
			"Set or Clear Deactivation-Locked", HFILL }},
		{ &hf_SetFRUActivationPolicy_datafield_FRUActivationPolicySetBit_Bit0, {
			"Set or Clear Locked", "SetFRUActivationPolicy.datafield.FRUActivationPolicySetBit.Bit0",
			FT_UINT8, BASE_HEX, VALS(cmd_SetFRUActivationPolicy_data_PFRUActivationPolicySetBit_Bit0_vals), 0x01,
			"Set or Clear Locked", HFILL }},
		{ &hf_SetFRUActivationPolicy_datafield_FRUActivationPolicySetBit_Bit1_ignored, {
			"Set or Clear Deactivation-Locked", "SetFRUActivationPolicy.datafield.FRUActivationPolicySetBit.Bit1_ignored",
			FT_UINT8, BASE_HEX, VALS(cmd_SetFRUActivationPolicy_data_PFRUActivationPolicySetBit_Bit1_ignored_vals), 0x02,
			"Set or Clear Deactivation-Locked", HFILL }},
		{ &hf_SetFRUActivationPolicy_datafield_FRUActivationPolicySetBit_Bit0_ignored, {
			"Set or Clear Locked", "SetFRUActivationPolicy.datafield.FRUActivationPolicySetBit.Bit0_ignored",
			FT_UINT8, BASE_HEX, VALS(cmd_SetFRUActivationPolicy_data_PFRUActivationPolicySetBit_Bit0_ignored_vals), 0x01,
			"Set or Clear Locked", HFILL }},	
	};

	/* Data field of Get FRU Activation Policy command, added by lane */
	static hf_register_info hf_GetFRUActivationPolicy_datafield[] = {
		{ &hf_GetFRUActivationPolicy_datafield_PICMGIdentifier, {
			"PICMG Identifier", "GetFRUActivationPolicy.datafield.PICMGIdentifier",
			FT_UINT8, BASE_HEX, NULL, 0,
			"PICMG Identifier", HFILL }},
		{ &hf_GetFRUActivationPolicy_datafield_FRUDeviceID, {
			"FRU Device ID", "GetFRUActivationPolicy.datafield.FRUDeviceID",
			FT_UINT8, BASE_HEX, NULL, 0,
			"FRU Device ID", HFILL }},
		{ &hf_GetFRUActivationPolicy_datafield_FRUActivationPolicy_Bit72, {
			"Bit 7...2 Reserverd", "GetFRUActivationPolicy.datafield.FRUActivationPolicy.Bit72",
			FT_UINT8, BASE_HEX, NULL, 0xfc,
			"Bit 7...2 Reserverd", HFILL }},
		{ &hf_GetFRUActivationPolicy_datafield_FRUActivationPolicy_Bit1, {
			"Deactivation-Locked Bit", "GetFRUActivationPolicy.datafield.FRUActivationPolicy.Bit1",
			FT_UINT8, BASE_HEX, VALS(cmd_GetFRUActivationPolicy_data_FRUActivationPolicy_Bit1_vals), 0x02,
			"Deactivation-Locked Bit", HFILL }},
		{ &hf_GetFRUActivationPolicy_datafield_FRUActivationPolicy_Bit0, {
			"Locked Bit", "GetFRUActivationPolicy.datafield.FRUActivationPolicy.Bit0",
			FT_UINT8, BASE_HEX, VALS(cmd_GetFRUActivationPolicy_data_FRUActivationPolicy_Bit0_vals), 0x01,
			"Locked Bit", HFILL }},
	};
	
	/* Data field of Get Device Locator Record ID, added by lane */
	static hf_register_info hf_GetDeviceLocatorRecordID_datafield[] = {
		{ &hf_GetDeviceLocatorRecordID_datafield_PICMGIdentifier, {
			"PICMG Identifier", "GetDeviceLocatorRecordID.datafield.PICMGIdentifier",
			FT_UINT8, BASE_HEX, NULL, 0,
			"PICMG Identifier", HFILL }},
		{ &hf_GetDeviceLocatorRecordID_datafield_FRUDeviceID, {
			"FRU Device ID", "GetDeviceLocatorRecordID.datafield.FRUDeviceID",
			FT_UINT8, BASE_HEX, NULL, 0,
			"FRU Device ID", HFILL }},
		{ &hf_GetDeviceLocatorRecordID_datafield_RecordID, {
			"Record ID", "GetDeviceLocatorRecordID.datafield.RecordID",
			FT_UINT16, BASE_HEX, NULL, 0,
			"Record ID", HFILL }},
	};

	/* Data field of Set Power Level command, added by lane */
	static hf_register_info hf_SetPowerLevel_datafield[] = {
		{ &hf_SetPowerLevel_datafield_PICMGIdentifier, {
			"PICMG Identifier", "SetPowerLevel.datafield.PICMGIdentifier",
			FT_UINT8, BASE_HEX, NULL, 0,
			"PICMG Identifier", HFILL }},
		{ &hf_SetPowerLevel_datafield_FRUDeviceID, {
			"FRU Device ID", "SetPowerLevel.datafield.FRUDeviceID",
			FT_UINT8, BASE_HEX, NULL, 0,
			"FRU Device ID", HFILL }},
		{ &hf_SetPowerLevel_datafield_PowerLevel, {
			"Power Level", "SetPowerLevel.datafield.PowerLevel",
			FT_UINT8, BASE_HEX, VALS(cmd_SetPowerLevel_data_PowerLevel_vals), 0,
			"Power Level", HFILL }},
		{ &hf_SetPowerLevel_datafield_SetPresentLevelsToDesiredLevels, {
			"Set Present Levels to Desired Levels", "SetPowerLevel.datafield.SetPresentLevelsToDesiredLevels",
			FT_UINT8, BASE_HEX, VALS(cmd_SetPowerLevel_data_SetPresentLevelsToDesiredLevels_vals), 0,
			"Set Present Levels to Desired Levels", HFILL }},		
	};

	/* Data field of Get Power Level command, added by lane */
	static hf_register_info hf_GetPowerLevel_datafield[] = {
		{ &hf_GetPowerLevel_datafield_PICMGIdentifier, {
			"PICMG Identifier", "GetPowerLevel.datafield.PICMGIdentifier",
			FT_UINT8, BASE_HEX, NULL, 0,
			"PICMG Identifier", HFILL }},
		{ &hf_GetPowerLevel_datafield_FRUDeviceID, {
			"FRU Device ID", "GetPowerLevel.datafield.FRUDeviceID",
			FT_UINT8, BASE_HEX, NULL, 0,
			"FRU Device ID", HFILL }},
		{ &hf_GetPowerLevel_datafield_PowerType, {
			"Power Type", "GetPowerLevel.datafield.PowerType",
			FT_UINT8, BASE_HEX, VALS(cmd_GetPowerLevel_data_PowerType_vals), 0,
			"Power Type", HFILL }},
		{ &hf_GetPowerLevel_datafield_Properties, {
			"Properties", "GetPowerLevel.datafield.Properties",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Properties", HFILL }},
		{ &hf_GetPowerLevel_datafield_Properties_DynamicPowerCon, {
			"Dynamic Power Configuration", "GetPowerLevel.datafield.Properties.DynamicPowerCon",
			FT_UINT8, BASE_HEX, VALS(cmd_GetPowerLevel_data_Properties_DynamicPowerCon_vals), 0x80,
			"Dynamic Power Configuration", HFILL }},
		{ &hf_GetPowerLevel_datafield_Properties_Reserved, {
			"Reserved", "GetPowerLevel.datafield.Properties.Reserved",
			FT_UINT8, BASE_HEX, NULL, 0x60,
			"Reserved", HFILL }},
		{ &hf_GetPowerLevel_datafield_Properties_PowerLevel, {
			"Power Level", "GetPowerLevel.datafield.Properties.PowerLevel",
			FT_UINT8, BASE_HEX, NULL, 0x1f,
			"Power Level", HFILL }},
		{ &hf_GetPowerLevel_datafield_DelayToStablePower, {
			"Delay To Stable Power", "GetPowerLevel.datafield.DelayToStablePower",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Delay To Stable Power", HFILL }},
		{ &hf_GetPowerLevel_datafield_PowerMultiplier, {
			"Power Multiplier", "GetPowerLevel.datafield.PowerMultiplier",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Power Multiplier", HFILL }},
		{ &hf_GetPowerLevel_datafield_PowerDraw, {
			"Power Draw", "GetPowerLevel.datafield.PowerDraw",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Power Draw", HFILL }},
	};

/* Data field of Set Fan Level command, added by lane */
	static hf_register_info hf_SetFanLevel_datafield[] = {
		{ &hf_SetFanLevel_datafield_PICMGIdentifier, {
			"PICMG Identifier", "SetFanLevel.datafield.PICMGIdentifier",
			FT_UINT8, BASE_HEX, NULL, 0,
			"PICMG Identifier", HFILL }},
		{ &hf_SetFanLevel_datafield_FRUDeviceID, {
			"FRU Device ID", "SetFanLevel.datafield.FRUDeviceID",
			FT_UINT8, BASE_HEX, NULL, 0,
			"FRU Device ID", HFILL }},
		{ &hf_SetFanLevel_datafield_FanLevel, {
			"Fan Level", "SetFanLevel.datafield.FanLevel",
			FT_UINT8, BASE_HEX, VALS(cmd_SetFanLevel_data_FanLevel_vals), 0,
			"Fan Level", HFILL }},
	};

/* Data field of Get Fan Level command, added by lane */
	static hf_register_info hf_GetFanLevel_datafield[] = {
		{ &hf_GetFanLevel_datafield_PICMGIdentifier, {
			"PICMG Identifier", "GetFanLevel.datafield.PICMGIdentifier",
			FT_UINT8, BASE_HEX, NULL, 0,
			"PICMG Identifier", HFILL }},
		{ &hf_GetFanLevel_datafield_FRUDeviceID, {
			"FRU Device ID", "GetFanLevel.datafield.FRUDeviceID",
			FT_UINT8, BASE_HEX, NULL, 0,
			"FRU Device ID", HFILL }},
		{ &hf_GetFanLevel_datafield_OverrideFanLevel, {
			"Override Fan Level", "GetFanLevel.datafield.OverrideFanLevel",
			FT_UINT8, BASE_HEX, VALS(cmd_GetFanLevel_data_OverrideFanLevel_vals), 0,
			"Override Fan Level", HFILL }},
		{ &hf_GetFanLevel_datafield_LocalControlFanLevel, {
			"Local Control Fan Level", "GetFanLevel.datafield.LocalControlFanLevel",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Local Control Fan Level", HFILL }},
	};



/***************************************************************************************************/

static gint *ett[] = {
		&ett_ipmi,
		&ett_ipmi_session,
		&ett_ipmi_msg_nlfield,
		&ett_ipmi_msg_slfield,

		/********* Sensor/Event, NetFN = 0x04 *********/
		/* Platform Event Message, added by lane */
		&ett_cmd_PEM_EventDirAndEventType,
		&ett_cmd_PEM_EventData1_threshold,
		&ett_cmd_PEM_EventData1_discrete,
		&ett_cmd_PEM_EventData2_discrete,
		&ett_cmd_PEM_EventData1_OEM,
		&ett_cmd_PEM_EventData2_OEM,
		/* Get Device SDR Info, added by lane*/
		&ett_cmd_GetDeviceSDRInfo_Flag,
		/* Set Sensor Thresholds, added by lane */
		&ett_cmd_SetSensorThresholds_ControlByte,
		/* Get Sensor Thresholds, added by lane */
		&ett_cmd_GetSensorThresholds_ControlByte,
		/* Get Sensor Reading, added by lane */
		&ett_cmd_GetSensorReading_ResponseDataByte2,
		&ett_cmd_GetSensorReading_ResponseDataByte3,
		&ett_cmd_GetSensorReading_ResponseDataByte3_threshold,
		&ett_cmd_GetSensorReading_ResponseDataByte4,
		
		/********* APP, NetFN = 0x06 *********/
		/*Get Device ID, added by lane */
		&ett_cmd_GetDeviceID_data_dr,
		&ett_cmd_GetDeviceID_data_fr,
		&ett_cmd_GetDeviceID_data_ads,
		
		/********* Storage, NetFN = 0x0a *********/
		&ett_Get_Channel_Auth_Cap_anonymouslogin,
		/* Get FRU Inventory Area Info, added by lane */
		&ett_cmd_GetFRUInventoryAreaInfo_data_ResponseDataByte4,
		/* Get SEL Info, added by lane */
		&ett_cmd_GetSELInfo_data_OperationSupport,
		/* Clear SEL, added by lane */
		&ett_cmd_ClearSEL_data_ErasureProgress,

		/********* PICMG, NetFN = 0X2c *********/
		/* Get FRU Led Propertiesl, added by lane*/
		&ett_cmd_GetFRULedProperties_data_LedProperties,
		/* Get Led Color Capabilities , added by lane */
		&ett_cmd_GetLedColorCapabilities_data_LEDColorCapabilities,
		&ett_cmd_GetLedColorCapabilities_data_DefaultLEDColorLocalControl,
		&ett_cmd_GetLedColorCapabilities_data_DefaultLEDColorOverride,
		/* Set FRU Led State, added by lane */
		&ett_cmd_SetFRULedState_data_Color,
		/* Get FRU Led State, added by lane */
		&ett_cmd_GetFRULedState_data_LEDState,
		&ett_cmd_GetFRULedState_data_LocalControlColor,
		&ett_cmd_GetFRULedState_data_OverrideStateColor,
		/* Set FRU Activation Policy, added by lane */
		&ett_cmd_SetFRUActivationPolicy_data_FRUActivationPolicyMaskBit,
		&ett_cmd_SetFRUActivationPolicy_data_FRUActivationPolicySetBit,
		/* Get FRU Activation Policy, added by lane */
		&ett_cmd_GetFRUActivationPolicy_data_FRUActivationPolicy,
		/* Get Power Level, added by lane*/
		&ett_cmd_GetPowerLevel_data_Properties,
		
	};

	proto_ipmi = proto_register_protocol(
		"Intelligent Platform Management Interface", "IPMI", "ipmi");

	proto_register_field_array(proto_ipmi, hf_session,
			   array_length(hf_session));
	proto_register_field_array(proto_ipmi, hf_msg,
			   array_length(hf_msg));
	proto_register_field_array(proto_ipmi, hf_msg_field,
			   array_length(hf_msg_field));

	/********* Sensor/Event, NetFN = 0x04 *********/
	
	/* Platform Event Message, added by lane */
	proto_register_field_array(proto_ipmi, hf_PEM_datafield,
			   array_length(hf_PEM_datafield));
	/* Get Device SDR Info, added by lane*/
	proto_register_field_array(proto_ipmi, hf_GetDeviceSDRInfo_datafield,
			   array_length(hf_GetDeviceSDRInfo_datafield));
	/* Get Device SDR, added by lane*/
	proto_register_field_array(proto_ipmi, hf_GetDeviceSDR_datafield,
			   array_length(hf_GetDeviceSDR_datafield));
	/* Reserve Device SDR Repository, added by lane */
	proto_register_field_array(proto_ipmi, hf_ReserveDeviceSDRRepository_datafield,
			   array_length(hf_ReserveDeviceSDRRepository_datafield));
	/* Set Sensor Hysteresis, added by lane */
	proto_register_field_array(proto_ipmi, hf_SetSensorHysteresis_datafield,
			   array_length(hf_SetSensorHysteresis_datafield));
	/* Get Sensor Hysteresis, added by lane */
	proto_register_field_array(proto_ipmi, hf_GetSensorHysteresis_datafield,
			   array_length(hf_GetSensorHysteresis_datafield));
	/* Set Sensor Thresholds, added by lane */
	proto_register_field_array(proto_ipmi, hf_SetSensorThresholds_datafield,
			   array_length(hf_SetSensorThresholds_datafield));
	/* Get Sensor Thresholds, added by lane */
	proto_register_field_array(proto_ipmi, hf_GetSensorThresholds_datafield,
			   array_length(hf_GetSensorThresholds_datafield));
	/* Get Sensor Reading, added by lane */
	proto_register_field_array(proto_ipmi, hf_GetSensorReading_datafield,
			   array_length(hf_GetSensorReading_datafield));

	/********* APP, NetFN = 0x06 *********/
	
	/*Get Device ID, added by lane */
	proto_register_field_array(proto_ipmi, hf_GetDeviceID_datafield,
			   array_length(hf_GetDeviceID_datafield));
	
	/* Get Channel Authentication Capabilities */
	proto_register_field_array(proto_ipmi, hf_Get_Ch_Auth_Cap_datafield,
			   array_length(hf_Get_Ch_Auth_Cap_datafield));
	
	/********* Storage, NetFN = 0x0a *********/

	/* Get FRU Inventory Area Info, added by lane */
	proto_register_field_array(proto_ipmi, hf_GetFRUInventoryAreaInfo_datafield,
			   array_length(hf_GetFRUInventoryAreaInfo_datafield));
	/* Get SEL Info, added by lane */
	proto_register_field_array(proto_ipmi, hf_GetSELInfo_datafield,
			   array_length(hf_GetSELInfo_datafield));
	/* Reserve SEL, added by lane */
	proto_register_field_array(proto_ipmi, hf_ReserveSEL_datafield,
			   array_length(hf_ReserveSEL_datafield));
	/* Get SEL Entry, added by lane */
	proto_register_field_array(proto_ipmi, hf_GetSELEntry_datafield,
			   array_length(hf_GetSELEntry_datafield));
	/* Get SEL Entry, added by lane */
	proto_register_field_array(proto_ipmi, hf_ClearSEL_datafield,
			   array_length(hf_ClearSEL_datafield));

	/********* PICMG, NetFN = 0X2c *********/
	
	/*Get PICMG Properties, added by lane */
	proto_register_field_array(proto_ipmi, hf_GetPICMGProperties_datafield,
			   array_length(hf_GetPICMGProperties_datafield));
	/*FRU Control, added by lane */
	proto_register_field_array(proto_ipmi, hf_FRUControl_datafield,
			   array_length(hf_FRUControl_datafield));
	/* Get FRU Led Properties, added by lane*/
	proto_register_field_array(proto_ipmi, hf_GetFRULedProperties_datafield,
			   array_length(hf_GetFRULedProperties_datafield));
	/* Get Led Color Capabilities ,, added by lane*/
	proto_register_field_array(proto_ipmi, hf_GetLedColorCapabilities_datafield,
			   array_length(hf_GetLedColorCapabilities_datafield));
	/* Set FRU Led State, added by lane */
	proto_register_field_array(proto_ipmi, hf_SetFRULedState_datafield,
			   array_length(hf_SetFRULedState_datafield));
	/* Get FRU Led State, added by lane */
	proto_register_field_array(proto_ipmi, hf_GetFRULedState_datafield,
			   array_length(hf_GetFRULedState_datafield));
	/* Set FRU Activation Policy, added by lane */
	proto_register_field_array(proto_ipmi, hf_SetFRUActivationPolicy_datafield,
			   array_length(hf_SetFRUActivationPolicy_datafield));
	/* Get FRU Activation Policy, added by lane */
	proto_register_field_array(proto_ipmi, hf_GetFRUActivationPolicy_datafield,
			   array_length(hf_GetFRUActivationPolicy_datafield));
	/* Set FRU Activation, added by lane */
	proto_register_field_array(proto_ipmi, hf_SetFRUActivation_datafield,
			   array_length(hf_SetFRUActivation_datafield));
	/* Get Device Locator Record ID, added by lane */
	proto_register_field_array(proto_ipmi, hf_GetDeviceLocatorRecordID_datafield,
			   array_length(hf_GetDeviceLocatorRecordID_datafield));
	/* Set Power Level, added by lane */
	proto_register_field_array(proto_ipmi, hf_SetPowerLevel_datafield,
			   array_length(hf_SetPowerLevel_datafield));
	/* Get Power Level, added by lane */
	proto_register_field_array(proto_ipmi, hf_GetPowerLevel_datafield,
			   array_length(hf_GetPowerLevel_datafield));
	/* Set Fan Level, added by lane */
	proto_register_field_array(proto_ipmi, hf_SetFanLevel_datafield,
			   array_length(hf_SetFanLevel_datafield));
	/* Get Fan Level, added by lane */
	proto_register_field_array(proto_ipmi, hf_GetFanLevel_datafield,
			   array_length(hf_GetFanLevel_datafield));
	
/****************************************************************************/

	proto_register_subtree_array(ett, array_length(ett));
	
}

void
proto_reg_handoff_ipmi(void)
{
	dissector_handle_t ipmi_handle;

	data_handle = find_dissector("data");

	ipmi_handle = create_dissector_handle(dissect_ipmi, proto_ipmi);
	dissector_add("rmcp.class", RMCP_CLASS_IPMI, ipmi_handle);
}

typedef  void (*P_FUN)(proto_tree *tree, proto_tree *ipmi_tree, packet_info *pinfo, tvbuff_t *tvb, gint *poffset, guint8 len, guint8 response, guint8 auth_offset);

/* added hereinafter by lane */ 
void
dissect_ipmi_data(proto_tree *tree, proto_tree *ipmi_tree,	packet_info *pinfo,
					tvbuff_t *tvb, gint *poffset, guint8 len, guint8 netfn, guint8 cmd, 
					guint8 response, guint8 auth_offset)
{
	tvbuff_t	*next_tvb;
	guint i;
	
	for (i = 0; i < NUM_OF_CMD_ARRAY; i++)	{
		if(((netfn&0xfe)==ipmi_cmd_array[i].netfn) && (cmd==ipmi_cmd_array[i].cmd))	{
			if(ipmi_cmd_array[i].dissectfunc) {
				/*( (P_FUN)ipmi_cmd_array[i].dissectfunc )(tree, ipmi_tree, pinfo, tvb, poffset, len, response, authtype);*/
				( (P_FUN)ipmi_cmd_array[i].dissectfunc )(tree, ipmi_tree, pinfo, tvb, poffset, len, response, auth_offset);
				return;
			}
			else  {
				next_tvb = tvb_new_subset(tvb, *poffset, len, len);
				call_dissector(data_handle, next_tvb, pinfo, tree);
				*poffset += len;
				return;
			}
	       }
	}
	next_tvb = tvb_new_subset(tvb, *poffset, len, len);
	call_dissector(data_handle, next_tvb, pinfo, tree);
	(*poffset) += len;
	return;

}

/************************************************************************************/



