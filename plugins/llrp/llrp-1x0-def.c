/* EPCglobal Low-Level Reader Protocol Packet Dissector
 *
 * Copyright 2008, Intermec Technologies Corp. <matt.poduska@intermec.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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

#include <stdio.h> /* for NULL */
#include "llrpparsetypes.h" 
#include "llrpparseinc.h" 
/*lint -e786 -e766*/


/* ----------------------------------------------------------------------------- */
/* Enumerations (42 total) */
    
t_llrp_enumeration_item llrp_enum_list_AirProtocols[] = {
        
    { "Unspecified", 0 },
    { "EPCGlobalClass1Gen2", 1 },
};
t_llrp_enumeration llrp_enum_AirProtocols = {
    llrp_enum_list_AirProtocols, 2
};
    
t_llrp_enumeration_item llrp_enum_list_GetReaderCapabilitiesRequestedData[] = {
        
    { "All", 0 },
    { "General_Device_Capabilities", 1 },
    { "LLRP_Capabilities", 2 },
    { "Regulatory_Capabilities", 3 },
    { "LLRP_Air_Protocol_Capabilities", 4 },
};
t_llrp_enumeration llrp_enum_GetReaderCapabilitiesRequestedData = {
    llrp_enum_list_GetReaderCapabilitiesRequestedData, 5
};
    
t_llrp_enumeration_item llrp_enum_list_CommunicationsStandard[] = {
        
    { "Unspecified", 0 },
    { "US_FCC_Part_15", 1 },
    { "ETSI_302_208", 2 },
    { "ETSI_300_220", 3 },
    { "Australia_LIPD_1W", 4 },
    { "Australia_LIPD_4W", 5 },
    { "Japan_ARIB_STD_T89", 6 },
    { "Hong_Kong_OFTA_1049", 7 },
    { "Taiwan_DGT_LP0002", 8 },
    { "Korea_MIC_Article_5_2", 9 },
};
t_llrp_enumeration llrp_enum_CommunicationsStandard = {
    llrp_enum_list_CommunicationsStandard, 10
};
    
t_llrp_enumeration_item llrp_enum_list_ROSpecState[] = {
        
    { "Disabled", 0 },
    { "Inactive", 1 },
    { "Active", 2 },
};
t_llrp_enumeration llrp_enum_ROSpecState = {
    llrp_enum_list_ROSpecState, 3
};
    
t_llrp_enumeration_item llrp_enum_list_ROSpecStartTriggerType[] = {
        
    { "Null", 0 },
    { "Immediate", 1 },
    { "Periodic", 2 },
    { "GPI", 3 },
};
t_llrp_enumeration llrp_enum_ROSpecStartTriggerType = {
    llrp_enum_list_ROSpecStartTriggerType, 4
};
    
t_llrp_enumeration_item llrp_enum_list_ROSpecStopTriggerType[] = {
        
    { "Null", 0 },
    { "Duration", 1 },
    { "GPI_With_Timeout", 2 },
};
t_llrp_enumeration llrp_enum_ROSpecStopTriggerType = {
    llrp_enum_list_ROSpecStopTriggerType, 3
};
    
t_llrp_enumeration_item llrp_enum_list_AISpecStopTriggerType[] = {
        
    { "Null", 0 },
    { "Duration", 1 },
    { "GPI_With_Timeout", 2 },
    { "Tag_Observation", 3 },
};
t_llrp_enumeration llrp_enum_AISpecStopTriggerType = {
    llrp_enum_list_AISpecStopTriggerType, 4
};
    
t_llrp_enumeration_item llrp_enum_list_TagObservationTriggerType[] = {
        
    { "Upon_Seeing_N_Tags_Or_Timeout", 0 },
    { "Upon_Seeing_No_More_New_Tags_For_Tms_Or_Timeout", 1 },
    { "N_Attempts_To_See_All_Tags_In_FOV_Or_Timeout", 2 },
};
t_llrp_enumeration llrp_enum_TagObservationTriggerType = {
    llrp_enum_list_TagObservationTriggerType, 3
};
    
t_llrp_enumeration_item llrp_enum_list_RFSurveySpecStopTriggerType[] = {
        
    { "Null", 0 },
    { "Duration", 1 },
    { "N_Iterations_Through_Frequency_Range", 2 },
};
t_llrp_enumeration llrp_enum_RFSurveySpecStopTriggerType = {
    llrp_enum_list_RFSurveySpecStopTriggerType, 3
};
    
t_llrp_enumeration_item llrp_enum_list_AccessSpecState[] = {
        
    { "Disabled", 0 },
    { "Active", 1 },
};
t_llrp_enumeration llrp_enum_AccessSpecState = {
    llrp_enum_list_AccessSpecState, 2
};
    
t_llrp_enumeration_item llrp_enum_list_AccessSpecStopTriggerType[] = {
        
    { "Null", 0 },
    { "Operation_Count", 1 },
};
t_llrp_enumeration llrp_enum_AccessSpecStopTriggerType = {
    llrp_enum_list_AccessSpecStopTriggerType, 2
};
    
t_llrp_enumeration_item llrp_enum_list_GetReaderConfigRequestedData[] = {
        
    { "All", 0 },
    { "Identification", 1 },
    { "AntennaProperties", 2 },
    { "AntennaConfiguration", 3 },
    { "ROReportSpec", 4 },
    { "ReaderEventNotificationSpec", 5 },
    { "AccessReportSpec", 6 },
    { "LLRPConfigurationStateValue", 7 },
    { "KeepaliveSpec", 8 },
    { "GPIPortCurrentState", 9 },
    { "GPOWriteData", 10 },
    { "EventsAndReports", 11 },
};
t_llrp_enumeration llrp_enum_GetReaderConfigRequestedData = {
    llrp_enum_list_GetReaderConfigRequestedData, 12
};
    
t_llrp_enumeration_item llrp_enum_list_IdentificationType[] = {
        
    { "MAC_Address", 0 },
    { "EPC", 1 },
};
t_llrp_enumeration llrp_enum_IdentificationType = {
    llrp_enum_list_IdentificationType, 2
};
    
t_llrp_enumeration_item llrp_enum_list_KeepaliveTriggerType[] = {
        
    { "Null", 0 },
    { "Periodic", 1 },
};
t_llrp_enumeration llrp_enum_KeepaliveTriggerType = {
    llrp_enum_list_KeepaliveTriggerType, 2
};
    
t_llrp_enumeration_item llrp_enum_list_GPIPortState[] = {
        
    { "Low", 0 },
    { "High", 1 },
    { "Unknown", 2 },
};
t_llrp_enumeration llrp_enum_GPIPortState = {
    llrp_enum_list_GPIPortState, 3
};
    
t_llrp_enumeration_item llrp_enum_list_ROReportTriggerType[] = {
        
    { "None", 0 },
    { "Upon_N_Tags_Or_End_Of_AISpec", 1 },
    { "Upon_N_Tags_Or_End_Of_ROSpec", 2 },
};
t_llrp_enumeration llrp_enum_ROReportTriggerType = {
    llrp_enum_list_ROReportTriggerType, 3
};
    
t_llrp_enumeration_item llrp_enum_list_AccessReportTriggerType[] = {
        
    { "Whenever_ROReport_Is_Generated", 0 },
    { "End_Of_AccessSpec", 1 },
};
t_llrp_enumeration llrp_enum_AccessReportTriggerType = {
    llrp_enum_list_AccessReportTriggerType, 2
};
    
t_llrp_enumeration_item llrp_enum_list_NotificationEventType[] = {
        
    { "Upon_Hopping_To_Next_Channel", 0 },
    { "GPI_Event", 1 },
    { "ROSpec_Event", 2 },
    { "Report_Buffer_Fill_Warning", 3 },
    { "Reader_Exception_Event", 4 },
    { "RFSurvey_Event", 5 },
    { "AISpec_Event", 6 },
    { "AISpec_Event_With_Details", 7 },
    { "Antenna_Event", 8 },
};
t_llrp_enumeration llrp_enum_NotificationEventType = {
    llrp_enum_list_NotificationEventType, 9
};
    
t_llrp_enumeration_item llrp_enum_list_ROSpecEventType[] = {
        
    { "Start_Of_ROSpec", 0 },
    { "End_Of_ROSpec", 1 },
    { "Preemption_Of_ROSpec", 2 },
};
t_llrp_enumeration llrp_enum_ROSpecEventType = {
    llrp_enum_list_ROSpecEventType, 3
};
    
t_llrp_enumeration_item llrp_enum_list_RFSurveyEventType[] = {
        
    { "Start_Of_RFSurvey", 0 },
    { "End_Of_RFSurvey", 1 },
};
t_llrp_enumeration llrp_enum_RFSurveyEventType = {
    llrp_enum_list_RFSurveyEventType, 2
};
    
t_llrp_enumeration_item llrp_enum_list_AISpecEventType[] = {
        
    { "End_Of_AISpec", 0 },
};
t_llrp_enumeration llrp_enum_AISpecEventType = {
    llrp_enum_list_AISpecEventType, 1
};
    
t_llrp_enumeration_item llrp_enum_list_AntennaEventType[] = {
        
    { "Antenna_Disconnected", 0 },
    { "Antenna_Connected", 1 },
};
t_llrp_enumeration llrp_enum_AntennaEventType = {
    llrp_enum_list_AntennaEventType, 2
};
    
t_llrp_enumeration_item llrp_enum_list_ConnectionAttemptStatusType[] = {
        
    { "Success", 0 },
    { "Failed_A_Reader_Initiated_Connection_Already_Exists", 1 },
    { "Failed_A_Client_Initiated_Connection_Already_Exists", 2 },
    { "Failed_Reason_Other_Than_A_Connection_Already_Exists", 3 },
    { "Another_Connection_Attempted", 4 },
};
t_llrp_enumeration llrp_enum_ConnectionAttemptStatusType = {
    llrp_enum_list_ConnectionAttemptStatusType, 5
};
    
t_llrp_enumeration_item llrp_enum_list_StatusCode[] = {
        
    { "M_Success", 0 },
    { "M_ParameterError", 1 },
    { "M_FieldError", 2 },
    { "M_UnexpectedParameter", 3 },
    { "M_MissingParameter", 4 },
    { "M_DuplicateParameter", 5 },
    { "M_OverflowParameter", 6 },
    { "M_OverflowField", 7 },
    { "M_UnknownParameter", 8 },
    { "M_UnknownField", 9 },
    { "M_UnsupportedMessage", 10 },
    { "M_UnsupportedVersion", 11 },
    { "M_UnsupportedParameter", 12 },
    { "P_ParameterError", 13 },
    { "P_FieldError", 14 },
    { "P_UnexpectedParameter", 15 },
    { "P_MissingParameter", 16 },
    { "P_DuplicateParameter", 17 },
    { "P_OverflowParameter", 18 },
    { "P_OverflowField", 19 },
    { "P_UnknownParameter", 20 },
    { "P_UnknownField", 21 },
    { "P_UnsupportedParameter", 22 },
    { "A_Invalid", 23 },
    { "A_OutOfRange", 24 },
    { "R_DeviceError", 25 },
};
t_llrp_enumeration llrp_enum_StatusCode = {
    llrp_enum_list_StatusCode, 26
};
    
t_llrp_enumeration_item llrp_enum_list_C1G2DRValue[] = {
        
    { "DRV_8", 0 },
    { "DRV_64_3", 1 },
};
t_llrp_enumeration llrp_enum_C1G2DRValue = {
    llrp_enum_list_C1G2DRValue, 2
};
    
t_llrp_enumeration_item llrp_enum_list_C1G2MValue[] = {
        
    { "MV_FM0", 0 },
    { "MV_2", 1 },
    { "MV_4", 2 },
    { "MV_8", 3 },
};
t_llrp_enumeration llrp_enum_C1G2MValue = {
    llrp_enum_list_C1G2MValue, 4
};
    
t_llrp_enumeration_item llrp_enum_list_C1G2ForwardLinkModulation[] = {
        
    { "PR_ASK", 0 },
    { "SSB_ASK", 1 },
    { "DSB_ASK", 2 },
};
t_llrp_enumeration llrp_enum_C1G2ForwardLinkModulation = {
    llrp_enum_list_C1G2ForwardLinkModulation, 3
};
    
t_llrp_enumeration_item llrp_enum_list_C1G2SpectralMaskIndicator[] = {
        
    { "Unknown", 0 },
    { "SI", 1 },
    { "MI", 2 },
    { "DI", 3 },
};
t_llrp_enumeration llrp_enum_C1G2SpectralMaskIndicator = {
    llrp_enum_list_C1G2SpectralMaskIndicator, 4
};
    
t_llrp_enumeration_item llrp_enum_list_C1G2TruncateAction[] = {
        
    { "Unspecified", 0 },
    { "Do_Not_Truncate", 1 },
    { "Truncate", 2 },
};
t_llrp_enumeration llrp_enum_C1G2TruncateAction = {
    llrp_enum_list_C1G2TruncateAction, 3
};
    
t_llrp_enumeration_item llrp_enum_list_C1G2StateAwareTarget[] = {
        
    { "SL", 0 },
    { "Inventoried_State_For_Session_S0", 1 },
    { "Inventoried_State_For_Session_S1", 2 },
    { "Inventoried_State_For_Session_S2", 3 },
    { "Inventoried_State_For_Session_S3", 4 },
};
t_llrp_enumeration llrp_enum_C1G2StateAwareTarget = {
    llrp_enum_list_C1G2StateAwareTarget, 5
};
    
t_llrp_enumeration_item llrp_enum_list_C1G2StateAwareAction[] = {
        
    { "AssertSLOrA_DeassertSLOrB", 0 },
    { "AssertSLOrA_Noop", 1 },
    { "Noop_DeassertSLOrB", 2 },
    { "NegateSLOrABBA_Noop", 3 },
    { "DeassertSLOrB_AssertSLOrA", 4 },
    { "DeassertSLOrB_Noop", 5 },
    { "Noop_AssertSLOrA", 6 },
    { "Noop_NegateSLOrABBA", 7 },
};
t_llrp_enumeration llrp_enum_C1G2StateAwareAction = {
    llrp_enum_list_C1G2StateAwareAction, 8
};
    
t_llrp_enumeration_item llrp_enum_list_C1G2StateUnawareAction[] = {
        
    { "Select_Unselect", 0 },
    { "Select_DoNothing", 1 },
    { "DoNothing_Unselect", 2 },
    { "Unselect_DoNothing", 3 },
    { "Unselect_Select", 4 },
    { "DoNothing_Select", 5 },
};
t_llrp_enumeration llrp_enum_C1G2StateUnawareAction = {
    llrp_enum_list_C1G2StateUnawareAction, 6
};
    
t_llrp_enumeration_item llrp_enum_list_C1G2TagInventoryStateAwareI[] = {
        
    { "State_A", 0 },
    { "State_B", 1 },
};
t_llrp_enumeration llrp_enum_C1G2TagInventoryStateAwareI = {
    llrp_enum_list_C1G2TagInventoryStateAwareI, 2
};
    
t_llrp_enumeration_item llrp_enum_list_C1G2TagInventoryStateAwareS[] = {
        
    { "SL", 0 },
    { "Not_SL", 1 },
};
t_llrp_enumeration llrp_enum_C1G2TagInventoryStateAwareS = {
    llrp_enum_list_C1G2TagInventoryStateAwareS, 2
};
    
t_llrp_enumeration_item llrp_enum_list_C1G2LockPrivilege[] = {
        
    { "Read_Write", 0 },
    { "Perma_Lock", 1 },
    { "Perma_Unlock", 2 },
    { "Unlock", 3 },
};
t_llrp_enumeration llrp_enum_C1G2LockPrivilege = {
    llrp_enum_list_C1G2LockPrivilege, 4
};
    
t_llrp_enumeration_item llrp_enum_list_C1G2LockDataField[] = {
        
    { "Kill_Password", 0 },
    { "Access_Password", 1 },
    { "EPC_Memory", 2 },
    { "TID_Memory", 3 },
    { "User_Memory", 4 },
};
t_llrp_enumeration llrp_enum_C1G2LockDataField = {
    llrp_enum_list_C1G2LockDataField, 5
};
    
t_llrp_enumeration_item llrp_enum_list_C1G2ReadResultType[] = {
        
    { "Success", 0 },
    { "Nonspecific_Tag_Error", 1 },
    { "No_Response_From_Tag", 2 },
    { "Nonspecific_Reader_Error", 3 },
};
t_llrp_enumeration llrp_enum_C1G2ReadResultType = {
    llrp_enum_list_C1G2ReadResultType, 4
};
    
t_llrp_enumeration_item llrp_enum_list_C1G2WriteResultType[] = {
        
    { "Success", 0 },
    { "Tag_Memory_Overrun_Error", 1 },
    { "Tag_Memory_Locked_Error", 2 },
    { "Insufficient_Power", 3 },
    { "Nonspecific_Tag_Error", 4 },
    { "No_Response_From_Tag", 5 },
    { "Nonspecific_Reader_Error", 6 },
};
t_llrp_enumeration llrp_enum_C1G2WriteResultType = {
    llrp_enum_list_C1G2WriteResultType, 7
};
    
t_llrp_enumeration_item llrp_enum_list_C1G2KillResultType[] = {
        
    { "Success", 0 },
    { "Zero_Kill_Password_Error", 1 },
    { "Insufficient_Power", 2 },
    { "Nonspecific_Tag_Error", 3 },
    { "No_Response_From_Tag", 4 },
    { "Nonspecific_Reader_Error", 5 },
};
t_llrp_enumeration llrp_enum_C1G2KillResultType = {
    llrp_enum_list_C1G2KillResultType, 6
};
    
t_llrp_enumeration_item llrp_enum_list_C1G2LockResultType[] = {
        
    { "Success", 0 },
    { "Insufficient_Power", 1 },
    { "Nonspecific_Tag_Error", 2 },
    { "No_Response_From_Tag", 3 },
    { "Nonspecific_Reader_Error", 4 },
};
t_llrp_enumeration llrp_enum_C1G2LockResultType = {
    llrp_enum_list_C1G2LockResultType, 5
};
    
t_llrp_enumeration_item llrp_enum_list_C1G2BlockEraseResultType[] = {
        
    { "Success", 0 },
    { "Tag_Memory_Overrun_Error", 1 },
    { "Tag_Memory_Locked_Error", 2 },
    { "Insufficient_Power", 3 },
    { "Nonspecific_Tag_Error", 4 },
    { "No_Response_From_Tag", 5 },
    { "Nonspecific_Reader_Error", 6 },
};
t_llrp_enumeration llrp_enum_C1G2BlockEraseResultType = {
    llrp_enum_list_C1G2BlockEraseResultType, 7
};
    
t_llrp_enumeration_item llrp_enum_list_C1G2BlockWriteResultType[] = {
        
    { "Success", 0 },
    { "Tag_Memory_Overrun_Error", 1 },
    { "Tag_Memory_Locked_Error", 2 },
    { "Insufficient_Power", 3 },
    { "Nonspecific_Tag_Error", 4 },
    { "No_Response_From_Tag", 5 },
    { "Nonspecific_Reader_Error", 6 },
};
t_llrp_enumeration llrp_enum_C1G2BlockWriteResultType = {
    llrp_enum_list_C1G2BlockWriteResultType, 7
};
    

/* ----------------------------------------------------------------------------- */
/* Choice Definitions (unordered lists of parameters)                            */

    
/* Choice: SpecParameter */
t_llrp_compound_item *llrp_choice_items_SpecParameter[] = {
        
    &llrp_param_AISpec,
    &llrp_param_RFSurveySpec,
    &llrp_param_Custom,
};
t_llrp_compound_item llrp_choice_SpecParameter = { 
    "SpecParameter", LLRP_ITEM_CHOICE, 0, 3, llrp_choice_items_SpecParameter
};
    
/* Choice: AccessCommandOpSpec */
t_llrp_compound_item *llrp_choice_items_AccessCommandOpSpec[] = {
        
    &llrp_param_C1G2Read,
    &llrp_param_C1G2Write,
    &llrp_param_C1G2Kill,
    &llrp_param_C1G2Lock,
    &llrp_param_C1G2BlockErase,
    &llrp_param_C1G2BlockWrite,
};
t_llrp_compound_item llrp_choice_AccessCommandOpSpec = { 
    "AccessCommandOpSpec", LLRP_ITEM_CHOICE, 0, 6, llrp_choice_items_AccessCommandOpSpec
};
    
/* Choice: AccessCommandOpSpecResult */
t_llrp_compound_item *llrp_choice_items_AccessCommandOpSpecResult[] = {
        
    &llrp_param_C1G2ReadOpSpecResult,
    &llrp_param_C1G2WriteOpSpecResult,
    &llrp_param_C1G2KillOpSpecResult,
    &llrp_param_C1G2LockOpSpecResult,
    &llrp_param_C1G2BlockEraseOpSpecResult,
    &llrp_param_C1G2BlockWriteOpSpecResult,
};
t_llrp_compound_item llrp_choice_AccessCommandOpSpecResult = { 
    "AccessCommandOpSpecResult", LLRP_ITEM_CHOICE, 0, 6, llrp_choice_items_AccessCommandOpSpecResult
};
    
/* Choice: EPCParameter */
t_llrp_compound_item *llrp_choice_items_EPCParameter[] = {
        
    &llrp_param_EPCData,
    &llrp_param_EPC_96,
};
t_llrp_compound_item llrp_choice_EPCParameter = { 
    "EPCParameter", LLRP_ITEM_CHOICE, 0, 2, llrp_choice_items_EPCParameter
};
    
/* Choice: Timestamp */
t_llrp_compound_item *llrp_choice_items_Timestamp[] = {
        
    &llrp_param_UTCTimestamp,
    &llrp_param_Uptime,
};
t_llrp_compound_item llrp_choice_Timestamp = { 
    "Timestamp", LLRP_ITEM_CHOICE, 0, 2, llrp_choice_items_Timestamp
};
    
/* Choice: AirProtocolLLRPCapabilities */
t_llrp_compound_item *llrp_choice_items_AirProtocolLLRPCapabilities[] = {
        
    &llrp_param_C1G2LLRPCapabilities,
};
t_llrp_compound_item llrp_choice_AirProtocolLLRPCapabilities = { 
    "AirProtocolLLRPCapabilities", LLRP_ITEM_CHOICE, 0, 1, llrp_choice_items_AirProtocolLLRPCapabilities
};
    
/* Choice: AirProtocolUHFRFModeTable */
t_llrp_compound_item *llrp_choice_items_AirProtocolUHFRFModeTable[] = {
        
    &llrp_param_C1G2UHFRFModeTable,
};
t_llrp_compound_item llrp_choice_AirProtocolUHFRFModeTable = { 
    "AirProtocolUHFRFModeTable", LLRP_ITEM_CHOICE, 0, 1, llrp_choice_items_AirProtocolUHFRFModeTable
};
    
/* Choice: AirProtocolInventoryCommandSettings */
t_llrp_compound_item *llrp_choice_items_AirProtocolInventoryCommandSettings[] = {
        
    &llrp_param_C1G2InventoryCommand,
};
t_llrp_compound_item llrp_choice_AirProtocolInventoryCommandSettings = { 
    "AirProtocolInventoryCommandSettings", LLRP_ITEM_CHOICE, 0, 1, llrp_choice_items_AirProtocolInventoryCommandSettings
};
    
/* Choice: AirProtocolTagSpec */
t_llrp_compound_item *llrp_choice_items_AirProtocolTagSpec[] = {
        
    &llrp_param_C1G2TagSpec,
};
t_llrp_compound_item llrp_choice_AirProtocolTagSpec = { 
    "AirProtocolTagSpec", LLRP_ITEM_CHOICE, 0, 1, llrp_choice_items_AirProtocolTagSpec
};
    
/* Choice: AirProtocolEPCMemorySelector */
t_llrp_compound_item *llrp_choice_items_AirProtocolEPCMemorySelector[] = {
        
    &llrp_param_C1G2EPCMemorySelector,
};
t_llrp_compound_item llrp_choice_AirProtocolEPCMemorySelector = { 
    "AirProtocolEPCMemorySelector", LLRP_ITEM_CHOICE, 0, 1, llrp_choice_items_AirProtocolEPCMemorySelector
};
    
/* Choice: AirProtocolTagData */
t_llrp_compound_item *llrp_choice_items_AirProtocolTagData[] = {
        
    &llrp_param_C1G2_PC,
    &llrp_param_C1G2_CRC,
};
t_llrp_compound_item llrp_choice_AirProtocolTagData = { 
    "AirProtocolTagData", LLRP_ITEM_CHOICE, 0, 2, llrp_choice_items_AirProtocolTagData
};
    
/* Choice: AirProtocolSingulationDetails */
t_llrp_compound_item *llrp_choice_items_AirProtocolSingulationDetails[] = {
        
    &llrp_param_C1G2SingulationDetails,
};
t_llrp_compound_item llrp_choice_AirProtocolSingulationDetails = { 
    "AirProtocolSingulationDetails", LLRP_ITEM_CHOICE, 0, 1, llrp_choice_items_AirProtocolSingulationDetails
};
    
/* ----------------------------------------------------------------------------- */
/* Choice List (12 total)                                  */

t_llrp_compound_item *llrp_v1_0_choice_list[] = {
  
    &llrp_choice_SpecParameter,
    &llrp_choice_AccessCommandOpSpec,
    &llrp_choice_AccessCommandOpSpecResult,
    &llrp_choice_EPCParameter,
    &llrp_choice_Timestamp,
    &llrp_choice_AirProtocolLLRPCapabilities,
    &llrp_choice_AirProtocolUHFRFModeTable,
    &llrp_choice_AirProtocolInventoryCommandSettings,
    &llrp_choice_AirProtocolTagSpec,
    &llrp_choice_AirProtocolEPCMemorySelector,
    &llrp_choice_AirProtocolTagData,
    &llrp_choice_AirProtocolSingulationDetails,
};
  
/* ----------------------------------------------------------------------------- */
/* Parameter Definitions (108 total) */
    
/* Parameter: UTCTimestamp */
      
t_llrp_item llrp_param_items_UTCTimestamp[] = {
      
    { "Microseconds", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u64, 
      NULL },

};
      
t_llrp_compound_item llrp_param_UTCTimestamp = {
    "UTCTimestamp", LLRP_ITEM_PARAMETER, 128, 1,
      llrp_param_items_UTCTimestamp
};
    
/* Parameter: Uptime */
      
t_llrp_item llrp_param_items_Uptime[] = {
      
    { "Microseconds", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u64, 
      NULL },

};
      
t_llrp_compound_item llrp_param_Uptime = {
    "Uptime", LLRP_ITEM_PARAMETER, 129, 1,
      llrp_param_items_Uptime
};
    
/* Parameter: Custom */
      
t_llrp_item llrp_param_items_Custom[] = {
      
    { "VendorIdentifier", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "ParameterSubtype", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "Data", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_bytesToEnd, 
      NULL },

};
      
t_llrp_compound_item llrp_param_Custom = {
    "Custom", LLRP_ITEM_PARAMETER, 1023, 3,
      llrp_param_items_Custom
};
    
/* Parameter: GeneralDeviceCapabilities */
      
t_llrp_item llrp_param_items_GeneralDeviceCapabilities[] = {
      
    { "MaxNumberOfAntennaSupported", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "CanSetAntennaProperties", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "HasUTCClockCapability", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 14, 0, LLRP_FIELDTYPE_NONE, NULL },

    { "DeviceManufacturerName", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "ModelName", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "ReaderFirmwareVersion", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_utf8v, 
      NULL },

    { "ReceiveSensitivityTableEntry", LLRP_ITEM_PARAMETER, 1, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_ReceiveSensitivityTableEntry },

    { "PerAntennaReceiveSensitivityRange", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_PerAntennaReceiveSensitivityRange },

    { "GPIOCapabilities", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_GPIOCapabilities },

    { "PerAntennaAirProtocol", LLRP_ITEM_PARAMETER, 1, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_PerAntennaAirProtocol },

};
      
t_llrp_compound_item llrp_param_GeneralDeviceCapabilities = {
    "GeneralDeviceCapabilities", LLRP_ITEM_PARAMETER, 137, 11,
      llrp_param_items_GeneralDeviceCapabilities
};
    
/* Parameter: ReceiveSensitivityTableEntry */
      
t_llrp_item llrp_param_items_ReceiveSensitivityTableEntry[] = {
      
    { "Index", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "ReceiveSensitivityValue", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_s16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_ReceiveSensitivityTableEntry = {
    "ReceiveSensitivityTableEntry", LLRP_ITEM_PARAMETER, 139, 2,
      llrp_param_items_ReceiveSensitivityTableEntry
};
    
/* Parameter: PerAntennaReceiveSensitivityRange */
      
t_llrp_item llrp_param_items_PerAntennaReceiveSensitivityRange[] = {
      
    { "AntennaID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "ReceiveSensitivityIndexMin", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "ReceiveSensitivityIndexMax", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_PerAntennaReceiveSensitivityRange = {
    "PerAntennaReceiveSensitivityRange", LLRP_ITEM_PARAMETER, 149, 3,
      llrp_param_items_PerAntennaReceiveSensitivityRange
};
    
/* Parameter: PerAntennaAirProtocol */
      
t_llrp_item llrp_param_items_PerAntennaAirProtocol[] = {
      
    { "AntennaID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "ProtocolID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8v, 
      &llrp_enum_AirProtocols },

};
      
t_llrp_compound_item llrp_param_PerAntennaAirProtocol = {
    "PerAntennaAirProtocol", LLRP_ITEM_PARAMETER, 140, 2,
      llrp_param_items_PerAntennaAirProtocol
};
    
/* Parameter: GPIOCapabilities */
      
t_llrp_item llrp_param_items_GPIOCapabilities[] = {
      
    { "NumGPIs", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "NumGPOs", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_GPIOCapabilities = {
    "GPIOCapabilities", LLRP_ITEM_PARAMETER, 141, 2,
      llrp_param_items_GPIOCapabilities
};
    
/* Parameter: LLRPCapabilities */
      
t_llrp_item llrp_param_items_LLRPCapabilities[] = {
      
    { "CanDoRFSurvey", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "CanReportBufferFillWarning", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "SupportsClientRequestOpSpec", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "CanDoTagInventoryStateAwareSingulation", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "SupportsEventAndReportHolding", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 3, 0, LLRP_FIELDTYPE_NONE, NULL },

    { "MaxNumPriorityLevelsSupported", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      NULL },

    { "ClientRequestOpSpecTimeout", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "MaxNumROSpecs", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "MaxNumSpecsPerROSpec", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "MaxNumInventoryParameterSpecsPerAISpec", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "MaxNumAccessSpecs", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "MaxNumOpSpecsPerAccessSpec", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

};
      
t_llrp_compound_item llrp_param_LLRPCapabilities = {
    "LLRPCapabilities", LLRP_ITEM_PARAMETER, 142, 13,
      llrp_param_items_LLRPCapabilities
};
    
/* Parameter: RegulatoryCapabilities */
      
t_llrp_item llrp_param_items_RegulatoryCapabilities[] = {
      
    { "CountryCode", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "CommunicationsStandard", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      &llrp_enum_CommunicationsStandard },

    { "UHFBandCapabilities", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_UHFBandCapabilities },

    { "Custom", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_Custom },

};
      
t_llrp_compound_item llrp_param_RegulatoryCapabilities = {
    "RegulatoryCapabilities", LLRP_ITEM_PARAMETER, 143, 4,
      llrp_param_items_RegulatoryCapabilities
};
    
/* Parameter: UHFBandCapabilities */
      
t_llrp_item llrp_param_items_UHFBandCapabilities[] = {
      
    { "TransmitPowerLevelTableEntry", LLRP_ITEM_PARAMETER, 1, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_TransmitPowerLevelTableEntry },

    { "FrequencyInformation", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_FrequencyInformation },

    { "AirProtocolUHFRFModeTable", LLRP_ITEM_CHOICE, 1, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_choice_AirProtocolUHFRFModeTable },

};
      
t_llrp_compound_item llrp_param_UHFBandCapabilities = {
    "UHFBandCapabilities", LLRP_ITEM_PARAMETER, 144, 3,
      llrp_param_items_UHFBandCapabilities
};
    
/* Parameter: TransmitPowerLevelTableEntry */
      
t_llrp_item llrp_param_items_TransmitPowerLevelTableEntry[] = {
      
    { "Index", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "TransmitPowerValue", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_s16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_TransmitPowerLevelTableEntry = {
    "TransmitPowerLevelTableEntry", LLRP_ITEM_PARAMETER, 145, 2,
      llrp_param_items_TransmitPowerLevelTableEntry
};
    
/* Parameter: FrequencyInformation */
      
t_llrp_item llrp_param_items_FrequencyInformation[] = {
      
    { "Hopping", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 7, 0, LLRP_FIELDTYPE_NONE, NULL },

    { "FrequencyHopTable", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_FrequencyHopTable },

    { "FixedFrequencyTable", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_FixedFrequencyTable },

};
      
t_llrp_compound_item llrp_param_FrequencyInformation = {
    "FrequencyInformation", LLRP_ITEM_PARAMETER, 146, 4,
      llrp_param_items_FrequencyInformation
};
    
/* Parameter: FrequencyHopTable */
      
t_llrp_item llrp_param_items_FrequencyHopTable[] = {
      
    { "HopTableID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 8, 0, LLRP_FIELDTYPE_NONE, NULL },

    { "Frequency", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32v, 
      NULL },

};
      
t_llrp_compound_item llrp_param_FrequencyHopTable = {
    "FrequencyHopTable", LLRP_ITEM_PARAMETER, 147, 3,
      llrp_param_items_FrequencyHopTable
};
    
/* Parameter: FixedFrequencyTable */
      
t_llrp_item llrp_param_items_FixedFrequencyTable[] = {
      
    { "Frequency", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32v, 
      NULL },

};
      
t_llrp_compound_item llrp_param_FixedFrequencyTable = {
    "FixedFrequencyTable", LLRP_ITEM_PARAMETER, 148, 1,
      llrp_param_items_FixedFrequencyTable
};
    
/* Parameter: ROSpec */
      
t_llrp_item llrp_param_items_ROSpec[] = {
      
    { "ROSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "Priority", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      NULL },

    { "CurrentState", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_ROSpecState },

    { "ROBoundarySpec", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_ROBoundarySpec },

    { "SpecParameter", LLRP_ITEM_CHOICE, 1, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_choice_SpecParameter },

    { "ROReportSpec", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_ROReportSpec },

};
      
t_llrp_compound_item llrp_param_ROSpec = {
    "ROSpec", LLRP_ITEM_PARAMETER, 177, 6,
      llrp_param_items_ROSpec
};
    
/* Parameter: ROBoundarySpec */
      
t_llrp_item llrp_param_items_ROBoundarySpec[] = {
      
    { "ROSpecStartTrigger", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_ROSpecStartTrigger },

    { "ROSpecStopTrigger", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_ROSpecStopTrigger },

};
      
t_llrp_compound_item llrp_param_ROBoundarySpec = {
    "ROBoundarySpec", LLRP_ITEM_PARAMETER, 178, 2,
      llrp_param_items_ROBoundarySpec
};
    
/* Parameter: ROSpecStartTrigger */
      
t_llrp_item llrp_param_items_ROSpecStartTrigger[] = {
      
    { "ROSpecStartTriggerType", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_ROSpecStartTriggerType },

    { "PeriodicTriggerValue", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_PeriodicTriggerValue },

    { "GPITriggerValue", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_GPITriggerValue },

};
      
t_llrp_compound_item llrp_param_ROSpecStartTrigger = {
    "ROSpecStartTrigger", LLRP_ITEM_PARAMETER, 179, 3,
      llrp_param_items_ROSpecStartTrigger
};
    
/* Parameter: PeriodicTriggerValue */
      
t_llrp_item llrp_param_items_PeriodicTriggerValue[] = {
      
    { "Offset", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "Period", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "UTCTimestamp", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_UTCTimestamp },

};
      
t_llrp_compound_item llrp_param_PeriodicTriggerValue = {
    "PeriodicTriggerValue", LLRP_ITEM_PARAMETER, 180, 3,
      llrp_param_items_PeriodicTriggerValue
};
    
/* Parameter: GPITriggerValue */
      
t_llrp_item llrp_param_items_GPITriggerValue[] = {
      
    { "GPIPortNum", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "GPIEvent", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 7, 0, LLRP_FIELDTYPE_NONE, NULL },

    { "Timeout", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

};
      
t_llrp_compound_item llrp_param_GPITriggerValue = {
    "GPITriggerValue", LLRP_ITEM_PARAMETER, 181, 4,
      llrp_param_items_GPITriggerValue
};
    
/* Parameter: ROSpecStopTrigger */
      
t_llrp_item llrp_param_items_ROSpecStopTrigger[] = {
      
    { "ROSpecStopTriggerType", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_ROSpecStopTriggerType },

    { "DurationTriggerValue", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "GPITriggerValue", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_GPITriggerValue },

};
      
t_llrp_compound_item llrp_param_ROSpecStopTrigger = {
    "ROSpecStopTrigger", LLRP_ITEM_PARAMETER, 182, 3,
      llrp_param_items_ROSpecStopTrigger
};
    
/* Parameter: AISpec */
      
t_llrp_item llrp_param_items_AISpec[] = {
      
    { "AntennaIDs", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16v, 
      NULL },

    { "AISpecStopTrigger", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_AISpecStopTrigger },

    { "InventoryParameterSpec", LLRP_ITEM_PARAMETER, 1, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_InventoryParameterSpec },

    { "Custom", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_Custom },

};
      
t_llrp_compound_item llrp_param_AISpec = {
    "AISpec", LLRP_ITEM_PARAMETER, 183, 4,
      llrp_param_items_AISpec
};
    
/* Parameter: AISpecStopTrigger */
      
t_llrp_item llrp_param_items_AISpecStopTrigger[] = {
      
    { "AISpecStopTriggerType", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_AISpecStopTriggerType },

    { "DurationTrigger", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "GPITriggerValue", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_GPITriggerValue },

    { "TagObservationTrigger", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_TagObservationTrigger },

};
      
t_llrp_compound_item llrp_param_AISpecStopTrigger = {
    "AISpecStopTrigger", LLRP_ITEM_PARAMETER, 184, 4,
      llrp_param_items_AISpecStopTrigger
};
    
/* Parameter: TagObservationTrigger */
      
t_llrp_item llrp_param_items_TagObservationTrigger[] = {
      
    { "TriggerType", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_TagObservationTriggerType },

    { "", LLRP_ITEM_RESERVED, 8, 0, LLRP_FIELDTYPE_NONE, NULL },

    { "NumberOfTags", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "NumberOfAttempts", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "T", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "Timeout", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

};
      
t_llrp_compound_item llrp_param_TagObservationTrigger = {
    "TagObservationTrigger", LLRP_ITEM_PARAMETER, 185, 6,
      llrp_param_items_TagObservationTrigger
};
    
/* Parameter: InventoryParameterSpec */
      
t_llrp_item llrp_param_items_InventoryParameterSpec[] = {
      
    { "InventoryParameterSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "ProtocolID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_AirProtocols },

    { "AntennaConfiguration", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_AntennaConfiguration },

    { "Custom", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_Custom },

};
      
t_llrp_compound_item llrp_param_InventoryParameterSpec = {
    "InventoryParameterSpec", LLRP_ITEM_PARAMETER, 186, 4,
      llrp_param_items_InventoryParameterSpec
};
    
/* Parameter: RFSurveySpec */
      
t_llrp_item llrp_param_items_RFSurveySpec[] = {
      
    { "AntennaID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "StartFrequency", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "EndFrequency", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "RFSurveySpecStopTrigger", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_RFSurveySpecStopTrigger },

    { "Custom", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_Custom },

};
      
t_llrp_compound_item llrp_param_RFSurveySpec = {
    "RFSurveySpec", LLRP_ITEM_PARAMETER, 187, 5,
      llrp_param_items_RFSurveySpec
};
    
/* Parameter: RFSurveySpecStopTrigger */
      
t_llrp_item llrp_param_items_RFSurveySpecStopTrigger[] = {
      
    { "StopTriggerType", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_RFSurveySpecStopTriggerType },

    { "DurationPeriod", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "N", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

};
      
t_llrp_compound_item llrp_param_RFSurveySpecStopTrigger = {
    "RFSurveySpecStopTrigger", LLRP_ITEM_PARAMETER, 188, 3,
      llrp_param_items_RFSurveySpecStopTrigger
};
    
/* Parameter: AccessSpec */
      
t_llrp_item llrp_param_items_AccessSpec[] = {
      
    { "AccessSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "AntennaID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "ProtocolID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_AirProtocols },

    { "CurrentState", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      &llrp_enum_AccessSpecState },

    { "", LLRP_ITEM_RESERVED, 7, 0, LLRP_FIELDTYPE_NONE, NULL },

    { "ROSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "AccessSpecStopTrigger", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_AccessSpecStopTrigger },

    { "AccessCommand", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_AccessCommand },

    { "AccessReportSpec", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_AccessReportSpec },

    { "Custom", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_Custom },

};
      
t_llrp_compound_item llrp_param_AccessSpec = {
    "AccessSpec", LLRP_ITEM_PARAMETER, 207, 10,
      llrp_param_items_AccessSpec
};
    
/* Parameter: AccessSpecStopTrigger */
      
t_llrp_item llrp_param_items_AccessSpecStopTrigger[] = {
      
    { "AccessSpecStopTrigger", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_AccessSpecStopTriggerType },

    { "OperationCountValue", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_AccessSpecStopTrigger = {
    "AccessSpecStopTrigger", LLRP_ITEM_PARAMETER, 208, 2,
      llrp_param_items_AccessSpecStopTrigger
};
    
/* Parameter: AccessCommand */
      
t_llrp_item llrp_param_items_AccessCommand[] = {
      
    { "AirProtocolTagSpec", LLRP_ITEM_CHOICE, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_choice_AirProtocolTagSpec },

    { "AccessCommandOpSpec", LLRP_ITEM_CHOICE, 1, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_choice_AccessCommandOpSpec },

    { "Custom", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_Custom },

};
      
t_llrp_compound_item llrp_param_AccessCommand = {
    "AccessCommand", LLRP_ITEM_PARAMETER, 209, 3,
      llrp_param_items_AccessCommand
};
    
/* Parameter: LLRPConfigurationStateValue */
      
t_llrp_item llrp_param_items_LLRPConfigurationStateValue[] = {
      
    { "LLRPConfigurationStateValue", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

};
      
t_llrp_compound_item llrp_param_LLRPConfigurationStateValue = {
    "LLRPConfigurationStateValue", LLRP_ITEM_PARAMETER, 217, 1,
      llrp_param_items_LLRPConfigurationStateValue
};
    
/* Parameter: Identification */
      
t_llrp_item llrp_param_items_Identification[] = {
      
    { "IDType", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_IdentificationType },

    { "ReaderID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8v, 
      NULL },

};
      
t_llrp_compound_item llrp_param_Identification = {
    "Identification", LLRP_ITEM_PARAMETER, 218, 2,
      llrp_param_items_Identification
};
    
/* Parameter: GPOWriteData */
      
t_llrp_item llrp_param_items_GPOWriteData[] = {
      
    { "GPOPortNumber", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "GPOData", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 7, 0, LLRP_FIELDTYPE_NONE, NULL },

};
      
t_llrp_compound_item llrp_param_GPOWriteData = {
    "GPOWriteData", LLRP_ITEM_PARAMETER, 219, 3,
      llrp_param_items_GPOWriteData
};
    
/* Parameter: KeepaliveSpec */
      
t_llrp_item llrp_param_items_KeepaliveSpec[] = {
      
    { "KeepaliveTriggerType", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_KeepaliveTriggerType },

    { "PeriodicTriggerValue", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

};
      
t_llrp_compound_item llrp_param_KeepaliveSpec = {
    "KeepaliveSpec", LLRP_ITEM_PARAMETER, 220, 2,
      llrp_param_items_KeepaliveSpec
};
    
/* Parameter: AntennaProperties */
      
t_llrp_item llrp_param_items_AntennaProperties[] = {
      
    { "AntennaConnected", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 7, 0, LLRP_FIELDTYPE_NONE, NULL },

    { "AntennaID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "AntennaGain", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_s16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_AntennaProperties = {
    "AntennaProperties", LLRP_ITEM_PARAMETER, 221, 4,
      llrp_param_items_AntennaProperties
};
    
/* Parameter: AntennaConfiguration */
      
t_llrp_item llrp_param_items_AntennaConfiguration[] = {
      
    { "AntennaID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "RFReceiver", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_RFReceiver },

    { "RFTransmitter", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_RFTransmitter },

    { "AirProtocolInventoryCommandSettings", LLRP_ITEM_CHOICE, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_choice_AirProtocolInventoryCommandSettings },

};
      
t_llrp_compound_item llrp_param_AntennaConfiguration = {
    "AntennaConfiguration", LLRP_ITEM_PARAMETER, 222, 4,
      llrp_param_items_AntennaConfiguration
};
    
/* Parameter: RFReceiver */
      
t_llrp_item llrp_param_items_RFReceiver[] = {
      
    { "ReceiverSensitivity", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_RFReceiver = {
    "RFReceiver", LLRP_ITEM_PARAMETER, 223, 1,
      llrp_param_items_RFReceiver
};
    
/* Parameter: RFTransmitter */
      
t_llrp_item llrp_param_items_RFTransmitter[] = {
      
    { "HopTableID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "ChannelIndex", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "TransmitPower", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_RFTransmitter = {
    "RFTransmitter", LLRP_ITEM_PARAMETER, 224, 3,
      llrp_param_items_RFTransmitter
};
    
/* Parameter: GPIPortCurrentState */
      
t_llrp_item llrp_param_items_GPIPortCurrentState[] = {
      
    { "GPIPortNum", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "Config", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 7, 0, LLRP_FIELDTYPE_NONE, NULL },

    { "State", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_GPIPortState },

};
      
t_llrp_compound_item llrp_param_GPIPortCurrentState = {
    "GPIPortCurrentState", LLRP_ITEM_PARAMETER, 225, 4,
      llrp_param_items_GPIPortCurrentState
};
    
/* Parameter: EventsAndReports */
      
t_llrp_item llrp_param_items_EventsAndReports[] = {
      
    { "HoldEventsAndReportsUponReconnect", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 7, 0, LLRP_FIELDTYPE_NONE, NULL },

};
      
t_llrp_compound_item llrp_param_EventsAndReports = {
    "EventsAndReports", LLRP_ITEM_PARAMETER, 226, 2,
      llrp_param_items_EventsAndReports
};
    
/* Parameter: ROReportSpec */
      
t_llrp_item llrp_param_items_ROReportSpec[] = {
      
    { "ROReportTrigger", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_ROReportTriggerType },

    { "N", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "TagReportContentSelector", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_TagReportContentSelector },

    { "Custom", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_Custom },

};
      
t_llrp_compound_item llrp_param_ROReportSpec = {
    "ROReportSpec", LLRP_ITEM_PARAMETER, 237, 4,
      llrp_param_items_ROReportSpec
};
    
/* Parameter: TagReportContentSelector */
      
t_llrp_item llrp_param_items_TagReportContentSelector[] = {
      
    { "EnableROSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "EnableSpecIndex", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "EnableInventoryParameterSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "EnableAntennaID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "EnableChannelIndex", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "EnablePeakRSSI", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "EnableFirstSeenTimestamp", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "EnableLastSeenTimestamp", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "EnableTagSeenCount", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "EnableAccessSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 6, 0, LLRP_FIELDTYPE_NONE, NULL },

    { "AirProtocolEPCMemorySelector", LLRP_ITEM_CHOICE, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_choice_AirProtocolEPCMemorySelector },

};
      
t_llrp_compound_item llrp_param_TagReportContentSelector = {
    "TagReportContentSelector", LLRP_ITEM_PARAMETER, 238, 12,
      llrp_param_items_TagReportContentSelector
};
    
/* Parameter: AccessReportSpec */
      
t_llrp_item llrp_param_items_AccessReportSpec[] = {
      
    { "AccessReportTrigger", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_AccessReportTriggerType },

};
      
t_llrp_compound_item llrp_param_AccessReportSpec = {
    "AccessReportSpec", LLRP_ITEM_PARAMETER, 239, 1,
      llrp_param_items_AccessReportSpec
};
    
/* Parameter: TagReportData */
      
t_llrp_item llrp_param_items_TagReportData[] = {
      
    { "EPCParameter", LLRP_ITEM_CHOICE, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_choice_EPCParameter },

    { "ROSpecID", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_ROSpecID },

    { "SpecIndex", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_SpecIndex },

    { "InventoryParameterSpecID", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_InventoryParameterSpecID },

    { "AntennaID", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_AntennaID },

    { "PeakRSSI", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_PeakRSSI },

    { "ChannelIndex", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_ChannelIndex },

    { "FirstSeenTimestampUTC", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_FirstSeenTimestampUTC },

    { "FirstSeenTimestampUptime", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_FirstSeenTimestampUptime },

    { "LastSeenTimestampUTC", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_LastSeenTimestampUTC },

    { "LastSeenTimestampUptime", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_LastSeenTimestampUptime },

    { "TagSeenCount", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_TagSeenCount },

    { "AirProtocolTagData", LLRP_ITEM_CHOICE, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_choice_AirProtocolTagData },

    { "AccessSpecID", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_AccessSpecID },

    { "AccessCommandOpSpecResult", LLRP_ITEM_CHOICE, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_choice_AccessCommandOpSpecResult },

    { "Custom", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_Custom },

};
      
t_llrp_compound_item llrp_param_TagReportData = {
    "TagReportData", LLRP_ITEM_PARAMETER, 240, 16,
      llrp_param_items_TagReportData
};
    
/* Parameter: EPCData */
      
t_llrp_item llrp_param_items_EPCData[] = {
      
    { "EPC", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1v, 
      NULL },

};
      
t_llrp_compound_item llrp_param_EPCData = {
    "EPCData", LLRP_ITEM_PARAMETER, 241, 1,
      llrp_param_items_EPCData
};
    
/* Parameter: EPC_96 */
      
t_llrp_item llrp_param_items_EPC_96[] = {
      
    { "EPC", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u96, 
      NULL },

};
      
t_llrp_compound_item llrp_param_EPC_96 = {
    "EPC_96", LLRP_ITEM_PARAMETER, 13, 1,
      llrp_param_items_EPC_96
};
    
/* Parameter: ROSpecID */
      
t_llrp_item llrp_param_items_ROSpecID[] = {
      
    { "ROSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

};
      
t_llrp_compound_item llrp_param_ROSpecID = {
    "ROSpecID", LLRP_ITEM_PARAMETER, 9, 1,
      llrp_param_items_ROSpecID
};
    
/* Parameter: SpecIndex */
      
t_llrp_item llrp_param_items_SpecIndex[] = {
      
    { "SpecIndex", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_SpecIndex = {
    "SpecIndex", LLRP_ITEM_PARAMETER, 14, 1,
      llrp_param_items_SpecIndex
};
    
/* Parameter: InventoryParameterSpecID */
      
t_llrp_item llrp_param_items_InventoryParameterSpecID[] = {
      
    { "InventoryParameterSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_InventoryParameterSpecID = {
    "InventoryParameterSpecID", LLRP_ITEM_PARAMETER, 10, 1,
      llrp_param_items_InventoryParameterSpecID
};
    
/* Parameter: AntennaID */
      
t_llrp_item llrp_param_items_AntennaID[] = {
      
    { "AntennaID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_AntennaID = {
    "AntennaID", LLRP_ITEM_PARAMETER, 1, 1,
      llrp_param_items_AntennaID
};
    
/* Parameter: PeakRSSI */
      
t_llrp_item llrp_param_items_PeakRSSI[] = {
      
    { "PeakRSSI", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_s8, 
      NULL },

};
      
t_llrp_compound_item llrp_param_PeakRSSI = {
    "PeakRSSI", LLRP_ITEM_PARAMETER, 6, 1,
      llrp_param_items_PeakRSSI
};
    
/* Parameter: ChannelIndex */
      
t_llrp_item llrp_param_items_ChannelIndex[] = {
      
    { "ChannelIndex", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_ChannelIndex = {
    "ChannelIndex", LLRP_ITEM_PARAMETER, 7, 1,
      llrp_param_items_ChannelIndex
};
    
/* Parameter: FirstSeenTimestampUTC */
      
t_llrp_item llrp_param_items_FirstSeenTimestampUTC[] = {
      
    { "Microseconds", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u64, 
      NULL },

};
      
t_llrp_compound_item llrp_param_FirstSeenTimestampUTC = {
    "FirstSeenTimestampUTC", LLRP_ITEM_PARAMETER, 2, 1,
      llrp_param_items_FirstSeenTimestampUTC
};
    
/* Parameter: FirstSeenTimestampUptime */
      
t_llrp_item llrp_param_items_FirstSeenTimestampUptime[] = {
      
    { "Microseconds", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u64, 
      NULL },

};
      
t_llrp_compound_item llrp_param_FirstSeenTimestampUptime = {
    "FirstSeenTimestampUptime", LLRP_ITEM_PARAMETER, 3, 1,
      llrp_param_items_FirstSeenTimestampUptime
};
    
/* Parameter: LastSeenTimestampUTC */
      
t_llrp_item llrp_param_items_LastSeenTimestampUTC[] = {
      
    { "Microseconds", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u64, 
      NULL },

};
      
t_llrp_compound_item llrp_param_LastSeenTimestampUTC = {
    "LastSeenTimestampUTC", LLRP_ITEM_PARAMETER, 4, 1,
      llrp_param_items_LastSeenTimestampUTC
};
    
/* Parameter: LastSeenTimestampUptime */
      
t_llrp_item llrp_param_items_LastSeenTimestampUptime[] = {
      
    { "Microseconds", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u64, 
      NULL },

};
      
t_llrp_compound_item llrp_param_LastSeenTimestampUptime = {
    "LastSeenTimestampUptime", LLRP_ITEM_PARAMETER, 5, 1,
      llrp_param_items_LastSeenTimestampUptime
};
    
/* Parameter: TagSeenCount */
      
t_llrp_item llrp_param_items_TagSeenCount[] = {
      
    { "TagCount", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_TagSeenCount = {
    "TagSeenCount", LLRP_ITEM_PARAMETER, 8, 1,
      llrp_param_items_TagSeenCount
};
    
/* Parameter: AccessSpecID */
      
t_llrp_item llrp_param_items_AccessSpecID[] = {
      
    { "AccessSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

};
      
t_llrp_compound_item llrp_param_AccessSpecID = {
    "AccessSpecID", LLRP_ITEM_PARAMETER, 16, 1,
      llrp_param_items_AccessSpecID
};
    
/* Parameter: RFSurveyReportData */
      
t_llrp_item llrp_param_items_RFSurveyReportData[] = {
      
    { "ROSpecID", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_ROSpecID },

    { "SpecIndex", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_SpecIndex },

    { "FrequencyRSSILevelEntry", LLRP_ITEM_PARAMETER, 1, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_FrequencyRSSILevelEntry },

    { "Custom", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_Custom },

};
      
t_llrp_compound_item llrp_param_RFSurveyReportData = {
    "RFSurveyReportData", LLRP_ITEM_PARAMETER, 242, 4,
      llrp_param_items_RFSurveyReportData
};
    
/* Parameter: FrequencyRSSILevelEntry */
      
t_llrp_item llrp_param_items_FrequencyRSSILevelEntry[] = {
      
    { "Frequency", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "Bandwidth", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "AverageRSSI", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_s8, 
      NULL },

    { "PeakRSSI", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_s8, 
      NULL },

    { "Timestamp", LLRP_ITEM_CHOICE, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_choice_Timestamp },

};
      
t_llrp_compound_item llrp_param_FrequencyRSSILevelEntry = {
    "FrequencyRSSILevelEntry", LLRP_ITEM_PARAMETER, 243, 5,
      llrp_param_items_FrequencyRSSILevelEntry
};
    
/* Parameter: ReaderEventNotificationSpec */
      
t_llrp_item llrp_param_items_ReaderEventNotificationSpec[] = {
      
    { "EventNotificationState", LLRP_ITEM_PARAMETER, 1, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_EventNotificationState },

};
      
t_llrp_compound_item llrp_param_ReaderEventNotificationSpec = {
    "ReaderEventNotificationSpec", LLRP_ITEM_PARAMETER, 244, 1,
      llrp_param_items_ReaderEventNotificationSpec
};
    
/* Parameter: EventNotificationState */
      
t_llrp_item llrp_param_items_EventNotificationState[] = {
      
    { "EventType", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      &llrp_enum_NotificationEventType },

    { "NotificationState", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 7, 0, LLRP_FIELDTYPE_NONE, NULL },

};
      
t_llrp_compound_item llrp_param_EventNotificationState = {
    "EventNotificationState", LLRP_ITEM_PARAMETER, 245, 3,
      llrp_param_items_EventNotificationState
};
    
/* Parameter: ReaderEventNotificationData */
      
t_llrp_item llrp_param_items_ReaderEventNotificationData[] = {
      
    { "Timestamp", LLRP_ITEM_CHOICE, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_choice_Timestamp },

    { "HoppingEvent", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_HoppingEvent },

    { "GPIEvent", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_GPIEvent },

    { "ROSpecEvent", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_ROSpecEvent },

    { "ReportBufferLevelWarningEvent", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_ReportBufferLevelWarningEvent },

    { "ReportBufferOverflowErrorEvent", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_ReportBufferOverflowErrorEvent },

    { "ReaderExceptionEvent", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_ReaderExceptionEvent },

    { "RFSurveyEvent", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_RFSurveyEvent },

    { "AISpecEvent", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_AISpecEvent },

    { "AntennaEvent", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_AntennaEvent },

    { "ConnectionAttemptEvent", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_ConnectionAttemptEvent },

    { "ConnectionCloseEvent", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_ConnectionCloseEvent },

    { "Custom", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_Custom },

};
      
t_llrp_compound_item llrp_param_ReaderEventNotificationData = {
    "ReaderEventNotificationData", LLRP_ITEM_PARAMETER, 246, 13,
      llrp_param_items_ReaderEventNotificationData
};
    
/* Parameter: HoppingEvent */
      
t_llrp_item llrp_param_items_HoppingEvent[] = {
      
    { "HopTableID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "NextChannelIndex", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_HoppingEvent = {
    "HoppingEvent", LLRP_ITEM_PARAMETER, 247, 2,
      llrp_param_items_HoppingEvent
};
    
/* Parameter: GPIEvent */
      
t_llrp_item llrp_param_items_GPIEvent[] = {
      
    { "GPIPortNumber", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "GPIEvent", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 7, 0, LLRP_FIELDTYPE_NONE, NULL },

};
      
t_llrp_compound_item llrp_param_GPIEvent = {
    "GPIEvent", LLRP_ITEM_PARAMETER, 248, 3,
      llrp_param_items_GPIEvent
};
    
/* Parameter: ROSpecEvent */
      
t_llrp_item llrp_param_items_ROSpecEvent[] = {
      
    { "EventType", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_ROSpecEventType },

    { "ROSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "PreemptingROSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

};
      
t_llrp_compound_item llrp_param_ROSpecEvent = {
    "ROSpecEvent", LLRP_ITEM_PARAMETER, 249, 3,
      llrp_param_items_ROSpecEvent
};
    
/* Parameter: ReportBufferLevelWarningEvent */
      
t_llrp_item llrp_param_items_ReportBufferLevelWarningEvent[] = {
      
    { "ReportBufferPercentageFull", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      NULL },

};
      
t_llrp_compound_item llrp_param_ReportBufferLevelWarningEvent = {
    "ReportBufferLevelWarningEvent", LLRP_ITEM_PARAMETER, 250, 1,
      llrp_param_items_ReportBufferLevelWarningEvent
};
    
/* Parameter: ReportBufferOverflowErrorEvent */
      
t_llrp_compound_item llrp_param_ReportBufferOverflowErrorEvent = {
    "ReportBufferOverflowErrorEvent", LLRP_ITEM_PARAMETER, 251, 0,
      NULL
};
    
/* Parameter: ReaderExceptionEvent */
      
t_llrp_item llrp_param_items_ReaderExceptionEvent[] = {
      
    { "Message", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_utf8v, 
      NULL },

    { "ROSpecID", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_ROSpecID },

    { "SpecIndex", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_SpecIndex },

    { "InventoryParameterSpecID", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_InventoryParameterSpecID },

    { "AntennaID", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_AntennaID },

    { "AccessSpecID", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_AccessSpecID },

    { "OpSpecID", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_OpSpecID },

    { "Custom", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_Custom },

};
      
t_llrp_compound_item llrp_param_ReaderExceptionEvent = {
    "ReaderExceptionEvent", LLRP_ITEM_PARAMETER, 252, 8,
      llrp_param_items_ReaderExceptionEvent
};
    
/* Parameter: OpSpecID */
      
t_llrp_item llrp_param_items_OpSpecID[] = {
      
    { "OpSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_OpSpecID = {
    "OpSpecID", LLRP_ITEM_PARAMETER, 17, 1,
      llrp_param_items_OpSpecID
};
    
/* Parameter: RFSurveyEvent */
      
t_llrp_item llrp_param_items_RFSurveyEvent[] = {
      
    { "EventType", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_RFSurveyEventType },

    { "ROSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "SpecIndex", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_RFSurveyEvent = {
    "RFSurveyEvent", LLRP_ITEM_PARAMETER, 253, 3,
      llrp_param_items_RFSurveyEvent
};
    
/* Parameter: AISpecEvent */
      
t_llrp_item llrp_param_items_AISpecEvent[] = {
      
    { "EventType", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_AISpecEventType },

    { "ROSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "SpecIndex", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "AirProtocolSingulationDetails", LLRP_ITEM_CHOICE, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_choice_AirProtocolSingulationDetails },

};
      
t_llrp_compound_item llrp_param_AISpecEvent = {
    "AISpecEvent", LLRP_ITEM_PARAMETER, 254, 4,
      llrp_param_items_AISpecEvent
};
    
/* Parameter: AntennaEvent */
      
t_llrp_item llrp_param_items_AntennaEvent[] = {
      
    { "EventType", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_AntennaEventType },

    { "AntennaID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_AntennaEvent = {
    "AntennaEvent", LLRP_ITEM_PARAMETER, 255, 2,
      llrp_param_items_AntennaEvent
};
    
/* Parameter: ConnectionAttemptEvent */
      
t_llrp_item llrp_param_items_ConnectionAttemptEvent[] = {
      
    { "Status", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      &llrp_enum_ConnectionAttemptStatusType },

};
      
t_llrp_compound_item llrp_param_ConnectionAttemptEvent = {
    "ConnectionAttemptEvent", LLRP_ITEM_PARAMETER, 256, 1,
      llrp_param_items_ConnectionAttemptEvent
};
    
/* Parameter: ConnectionCloseEvent */
      
t_llrp_compound_item llrp_param_ConnectionCloseEvent = {
    "ConnectionCloseEvent", LLRP_ITEM_PARAMETER, 257, 0,
      NULL
};
    
/* Parameter: LLRPStatus */
      
t_llrp_item llrp_param_items_LLRPStatus[] = {
      
    { "StatusCode", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      &llrp_enum_StatusCode },

    { "ErrorDescription", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_utf8v, 
      NULL },

    { "FieldError", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_FieldError },

    { "ParameterError", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_ParameterError },

};
      
t_llrp_compound_item llrp_param_LLRPStatus = {
    "LLRPStatus", LLRP_ITEM_PARAMETER, 287, 4,
      llrp_param_items_LLRPStatus
};
    
/* Parameter: FieldError */
      
t_llrp_item llrp_param_items_FieldError[] = {
      
    { "FieldNum", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "ErrorCode", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      &llrp_enum_StatusCode },

};
      
t_llrp_compound_item llrp_param_FieldError = {
    "FieldError", LLRP_ITEM_PARAMETER, 288, 2,
      llrp_param_items_FieldError
};
    
/* Parameter: ParameterError */
      
t_llrp_item llrp_param_items_ParameterError[] = {
      
    { "ParameterType", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "ErrorCode", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      &llrp_enum_StatusCode },

    { "FieldError", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_FieldError },

    { "ParameterError", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_ParameterError },

};
      
t_llrp_compound_item llrp_param_ParameterError = {
    "ParameterError", LLRP_ITEM_PARAMETER, 289, 4,
      llrp_param_items_ParameterError
};
    
/* Parameter: C1G2LLRPCapabilities */
      
t_llrp_item llrp_param_items_C1G2LLRPCapabilities[] = {
      
    { "CanSupportBlockErase", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "CanSupportBlockWrite", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 6, 0, LLRP_FIELDTYPE_NONE, NULL },

    { "MaxNumSelectFiltersPerQuery", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_C1G2LLRPCapabilities = {
    "C1G2LLRPCapabilities", LLRP_ITEM_PARAMETER, 327, 4,
      llrp_param_items_C1G2LLRPCapabilities
};
    
/* Parameter: C1G2UHFRFModeTable */
      
t_llrp_item llrp_param_items_C1G2UHFRFModeTable[] = {
      
    { "C1G2UHFRFModeTableEntry", LLRP_ITEM_PARAMETER, 1, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_C1G2UHFRFModeTableEntry },

};
      
t_llrp_compound_item llrp_param_C1G2UHFRFModeTable = {
    "C1G2UHFRFModeTable", LLRP_ITEM_PARAMETER, 328, 1,
      llrp_param_items_C1G2UHFRFModeTable
};
    
/* Parameter: C1G2UHFRFModeTableEntry */
      
t_llrp_item llrp_param_items_C1G2UHFRFModeTableEntry[] = {
      
    { "ModeIdentifier", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "DRValue", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      &llrp_enum_C1G2DRValue },

    { "EPCHAGTCConformance", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 6, 0, LLRP_FIELDTYPE_NONE, NULL },

    { "MValue", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_C1G2MValue },

    { "ForwardLinkModulation", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_C1G2ForwardLinkModulation },

    { "SpectralMaskIndicator", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_C1G2SpectralMaskIndicator },

    { "BDRValue", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "PIEValue", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "MinTariValue", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "MaxTariValue", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "StepTariValue", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

};
      
t_llrp_compound_item llrp_param_C1G2UHFRFModeTableEntry = {
    "C1G2UHFRFModeTableEntry", LLRP_ITEM_PARAMETER, 329, 12,
      llrp_param_items_C1G2UHFRFModeTableEntry
};
    
/* Parameter: C1G2InventoryCommand */
      
t_llrp_item llrp_param_items_C1G2InventoryCommand[] = {
      
    { "TagInventoryStateAware", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 7, 0, LLRP_FIELDTYPE_NONE, NULL },

    { "C1G2Filter", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_C1G2Filter },

    { "C1G2RFControl", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_C1G2RFControl },

    { "C1G2SingulationControl", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_C1G2SingulationControl },

    { "Custom", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_Custom },

};
      
t_llrp_compound_item llrp_param_C1G2InventoryCommand = {
    "C1G2InventoryCommand", LLRP_ITEM_PARAMETER, 330, 6,
      llrp_param_items_C1G2InventoryCommand
};
    
/* Parameter: C1G2Filter */
      
t_llrp_item llrp_param_items_C1G2Filter[] = {
      
    { "T", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u2, 
      &llrp_enum_C1G2TruncateAction },

    { "", LLRP_ITEM_RESERVED, 6, 0, LLRP_FIELDTYPE_NONE, NULL },

    { "C1G2TagInventoryMask", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_C1G2TagInventoryMask },

    { "C1G2TagInventoryStateAwareFilterAction", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_C1G2TagInventoryStateAwareFilterAction },

    { "C1G2TagInventoryStateUnawareFilterAction", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_C1G2TagInventoryStateUnawareFilterAction },

};
      
t_llrp_compound_item llrp_param_C1G2Filter = {
    "C1G2Filter", LLRP_ITEM_PARAMETER, 331, 5,
      llrp_param_items_C1G2Filter
};
    
/* Parameter: C1G2TagInventoryMask */
      
t_llrp_item llrp_param_items_C1G2TagInventoryMask[] = {
      
    { "MB", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u2, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 6, 0, LLRP_FIELDTYPE_NONE, NULL },

    { "Pointer", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "TagMask", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1v, 
      NULL },

};
      
t_llrp_compound_item llrp_param_C1G2TagInventoryMask = {
    "C1G2TagInventoryMask", LLRP_ITEM_PARAMETER, 332, 4,
      llrp_param_items_C1G2TagInventoryMask
};
    
/* Parameter: C1G2TagInventoryStateAwareFilterAction */
      
t_llrp_item llrp_param_items_C1G2TagInventoryStateAwareFilterAction[] = {
      
    { "Target", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_C1G2StateAwareTarget },

    { "Action", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_C1G2StateAwareAction },

};
      
t_llrp_compound_item llrp_param_C1G2TagInventoryStateAwareFilterAction = {
    "C1G2TagInventoryStateAwareFilterAction", LLRP_ITEM_PARAMETER, 333, 2,
      llrp_param_items_C1G2TagInventoryStateAwareFilterAction
};
    
/* Parameter: C1G2TagInventoryStateUnawareFilterAction */
      
t_llrp_item llrp_param_items_C1G2TagInventoryStateUnawareFilterAction[] = {
      
    { "Action", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_C1G2StateUnawareAction },

};
      
t_llrp_compound_item llrp_param_C1G2TagInventoryStateUnawareFilterAction = {
    "C1G2TagInventoryStateUnawareFilterAction", LLRP_ITEM_PARAMETER, 334, 1,
      llrp_param_items_C1G2TagInventoryStateUnawareFilterAction
};
    
/* Parameter: C1G2RFControl */
      
t_llrp_item llrp_param_items_C1G2RFControl[] = {
      
    { "ModeIndex", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "Tari", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_C1G2RFControl = {
    "C1G2RFControl", LLRP_ITEM_PARAMETER, 335, 2,
      llrp_param_items_C1G2RFControl
};
    
/* Parameter: C1G2SingulationControl */
      
t_llrp_item llrp_param_items_C1G2SingulationControl[] = {
      
    { "Session", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u2, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 6, 0, LLRP_FIELDTYPE_NONE, NULL },

    { "TagPopulation", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "TagTransitTime", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "C1G2TagInventoryStateAwareSingulationAction", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_C1G2TagInventoryStateAwareSingulationAction },

};
      
t_llrp_compound_item llrp_param_C1G2SingulationControl = {
    "C1G2SingulationControl", LLRP_ITEM_PARAMETER, 336, 5,
      llrp_param_items_C1G2SingulationControl
};
    
/* Parameter: C1G2TagInventoryStateAwareSingulationAction */
      
t_llrp_item llrp_param_items_C1G2TagInventoryStateAwareSingulationAction[] = {
      
    { "I", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      &llrp_enum_C1G2TagInventoryStateAwareI },

    { "S", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      &llrp_enum_C1G2TagInventoryStateAwareS },

    { "", LLRP_ITEM_RESERVED, 6, 0, LLRP_FIELDTYPE_NONE, NULL },

};
      
t_llrp_compound_item llrp_param_C1G2TagInventoryStateAwareSingulationAction = {
    "C1G2TagInventoryStateAwareSingulationAction", LLRP_ITEM_PARAMETER, 337, 3,
      llrp_param_items_C1G2TagInventoryStateAwareSingulationAction
};
    
/* Parameter: C1G2TagSpec */
      
t_llrp_item llrp_param_items_C1G2TagSpec[] = {
      
    { "C1G2TargetTag", LLRP_ITEM_PARAMETER, 1, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_C1G2TargetTag },

};
      
t_llrp_compound_item llrp_param_C1G2TagSpec = {
    "C1G2TagSpec", LLRP_ITEM_PARAMETER, 338, 1,
      llrp_param_items_C1G2TagSpec
};
    
/* Parameter: C1G2TargetTag */
      
t_llrp_item llrp_param_items_C1G2TargetTag[] = {
      
    { "MB", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u2, 
      NULL },

    { "Match", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 5, 0, LLRP_FIELDTYPE_NONE, NULL },

    { "Pointer", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "TagMask", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1v, 
      NULL },

    { "TagData", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1v, 
      NULL },

};
      
t_llrp_compound_item llrp_param_C1G2TargetTag = {
    "C1G2TargetTag", LLRP_ITEM_PARAMETER, 339, 6,
      llrp_param_items_C1G2TargetTag
};
    
/* Parameter: C1G2Read */
      
t_llrp_item llrp_param_items_C1G2Read[] = {
      
    { "OpSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "AccessPassword", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "MB", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u2, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 6, 0, LLRP_FIELDTYPE_NONE, NULL },

    { "WordPointer", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "WordCount", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_C1G2Read = {
    "C1G2Read", LLRP_ITEM_PARAMETER, 341, 6,
      llrp_param_items_C1G2Read
};
    
/* Parameter: C1G2Write */
      
t_llrp_item llrp_param_items_C1G2Write[] = {
      
    { "OpSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "AccessPassword", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "MB", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u2, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 6, 0, LLRP_FIELDTYPE_NONE, NULL },

    { "WordPointer", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "WriteData", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16v, 
      NULL },

};
      
t_llrp_compound_item llrp_param_C1G2Write = {
    "C1G2Write", LLRP_ITEM_PARAMETER, 342, 6,
      llrp_param_items_C1G2Write
};
    
/* Parameter: C1G2Kill */
      
t_llrp_item llrp_param_items_C1G2Kill[] = {
      
    { "OpSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "KillPassword", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

};
      
t_llrp_compound_item llrp_param_C1G2Kill = {
    "C1G2Kill", LLRP_ITEM_PARAMETER, 343, 2,
      llrp_param_items_C1G2Kill
};
    
/* Parameter: C1G2Lock */
      
t_llrp_item llrp_param_items_C1G2Lock[] = {
      
    { "OpSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "AccessPassword", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "C1G2LockPayload", LLRP_ITEM_PARAMETER, 1, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_C1G2LockPayload },

};
      
t_llrp_compound_item llrp_param_C1G2Lock = {
    "C1G2Lock", LLRP_ITEM_PARAMETER, 344, 3,
      llrp_param_items_C1G2Lock
};
    
/* Parameter: C1G2LockPayload */
      
t_llrp_item llrp_param_items_C1G2LockPayload[] = {
      
    { "Privilege", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_C1G2LockPrivilege },

    { "DataField", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_C1G2LockDataField },

};
      
t_llrp_compound_item llrp_param_C1G2LockPayload = {
    "C1G2LockPayload", LLRP_ITEM_PARAMETER, 345, 2,
      llrp_param_items_C1G2LockPayload
};
    
/* Parameter: C1G2BlockErase */
      
t_llrp_item llrp_param_items_C1G2BlockErase[] = {
      
    { "OpSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "AccessPassword", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "MB", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u2, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 6, 0, LLRP_FIELDTYPE_NONE, NULL },

    { "WordPointer", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "WordCount", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_C1G2BlockErase = {
    "C1G2BlockErase", LLRP_ITEM_PARAMETER, 346, 6,
      llrp_param_items_C1G2BlockErase
};
    
/* Parameter: C1G2BlockWrite */
      
t_llrp_item llrp_param_items_C1G2BlockWrite[] = {
      
    { "OpSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "AccessPassword", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "MB", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u2, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 6, 0, LLRP_FIELDTYPE_NONE, NULL },

    { "WordPointer", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "WriteData", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16v, 
      NULL },

};
      
t_llrp_compound_item llrp_param_C1G2BlockWrite = {
    "C1G2BlockWrite", LLRP_ITEM_PARAMETER, 347, 6,
      llrp_param_items_C1G2BlockWrite
};
    
/* Parameter: C1G2EPCMemorySelector */
      
t_llrp_item llrp_param_items_C1G2EPCMemorySelector[] = {
      
    { "EnableCRC", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "EnablePCBits", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 6, 0, LLRP_FIELDTYPE_NONE, NULL },

};
      
t_llrp_compound_item llrp_param_C1G2EPCMemorySelector = {
    "C1G2EPCMemorySelector", LLRP_ITEM_PARAMETER, 348, 3,
      llrp_param_items_C1G2EPCMemorySelector
};
    
/* Parameter: C1G2_PC */
      
t_llrp_item llrp_param_items_C1G2_PC[] = {
      
    { "PC_Bits", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_C1G2_PC = {
    "C1G2_PC", LLRP_ITEM_PARAMETER, 12, 1,
      llrp_param_items_C1G2_PC
};
    
/* Parameter: C1G2_CRC */
      
t_llrp_item llrp_param_items_C1G2_CRC[] = {
      
    { "CRC", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_C1G2_CRC = {
    "C1G2_CRC", LLRP_ITEM_PARAMETER, 11, 1,
      llrp_param_items_C1G2_CRC
};
    
/* Parameter: C1G2SingulationDetails */
      
t_llrp_item llrp_param_items_C1G2SingulationDetails[] = {
      
    { "NumCollisionSlots", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "NumEmptySlots", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_C1G2SingulationDetails = {
    "C1G2SingulationDetails", LLRP_ITEM_PARAMETER, 18, 2,
      llrp_param_items_C1G2SingulationDetails
};
    
/* Parameter: C1G2ReadOpSpecResult */
      
t_llrp_item llrp_param_items_C1G2ReadOpSpecResult[] = {
      
    { "Result", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_C1G2ReadResultType },

    { "OpSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "ReadData", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16v, 
      NULL },

};
      
t_llrp_compound_item llrp_param_C1G2ReadOpSpecResult = {
    "C1G2ReadOpSpecResult", LLRP_ITEM_PARAMETER, 349, 3,
      llrp_param_items_C1G2ReadOpSpecResult
};
    
/* Parameter: C1G2WriteOpSpecResult */
      
t_llrp_item llrp_param_items_C1G2WriteOpSpecResult[] = {
      
    { "Result", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_C1G2WriteResultType },

    { "OpSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "NumWordsWritten", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_C1G2WriteOpSpecResult = {
    "C1G2WriteOpSpecResult", LLRP_ITEM_PARAMETER, 350, 3,
      llrp_param_items_C1G2WriteOpSpecResult
};
    
/* Parameter: C1G2KillOpSpecResult */
      
t_llrp_item llrp_param_items_C1G2KillOpSpecResult[] = {
      
    { "Result", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_C1G2KillResultType },

    { "OpSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_C1G2KillOpSpecResult = {
    "C1G2KillOpSpecResult", LLRP_ITEM_PARAMETER, 351, 2,
      llrp_param_items_C1G2KillOpSpecResult
};
    
/* Parameter: C1G2LockOpSpecResult */
      
t_llrp_item llrp_param_items_C1G2LockOpSpecResult[] = {
      
    { "Result", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_C1G2LockResultType },

    { "OpSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_C1G2LockOpSpecResult = {
    "C1G2LockOpSpecResult", LLRP_ITEM_PARAMETER, 352, 2,
      llrp_param_items_C1G2LockOpSpecResult
};
    
/* Parameter: C1G2BlockEraseOpSpecResult */
      
t_llrp_item llrp_param_items_C1G2BlockEraseOpSpecResult[] = {
      
    { "Result", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_C1G2BlockEraseResultType },

    { "OpSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_C1G2BlockEraseOpSpecResult = {
    "C1G2BlockEraseOpSpecResult", LLRP_ITEM_PARAMETER, 353, 2,
      llrp_param_items_C1G2BlockEraseOpSpecResult
};
    
/* Parameter: C1G2BlockWriteOpSpecResult */
      
t_llrp_item llrp_param_items_C1G2BlockWriteOpSpecResult[] = {
      
    { "Result", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_C1G2BlockWriteResultType },

    { "OpSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "NumWordsWritten", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_param_C1G2BlockWriteOpSpecResult = {
    "C1G2BlockWriteOpSpecResult", LLRP_ITEM_PARAMETER, 354, 3,
      llrp_param_items_C1G2BlockWriteOpSpecResult
};
    
/* ----------------------------------------------------------------------------- */
/* Parameter List (108 total) */

t_llrp_standard_map_item llrp_v1_0_parameter_list[] = {
  
    { 1, &llrp_param_AntennaID,
        
    },
  
    { 2, &llrp_param_FirstSeenTimestampUTC,
        
    },
  
    { 3, &llrp_param_FirstSeenTimestampUptime,
        
    },
  
    { 4, &llrp_param_LastSeenTimestampUTC,
        
    },
  
    { 5, &llrp_param_LastSeenTimestampUptime,
        
    },
  
    { 6, &llrp_param_PeakRSSI,
        
    },
  
    { 7, &llrp_param_ChannelIndex,
        
    },
  
    { 8, &llrp_param_TagSeenCount,
        
    },
  
    { 9, &llrp_param_ROSpecID,
        
    },
  
    { 10, &llrp_param_InventoryParameterSpecID,
        
    },
  
    { 11, &llrp_param_C1G2_CRC,
        
    },
  
    { 12, &llrp_param_C1G2_PC,
        
    },
  
    { 13, &llrp_param_EPC_96,
        
    },
  
    { 14, &llrp_param_SpecIndex,
        
    },
  
    { 16, &llrp_param_AccessSpecID,
        
    },
  
    { 17, &llrp_param_OpSpecID,
        
    },
  
    { 18, &llrp_param_C1G2SingulationDetails,
        
    },
  
    { 128, &llrp_param_UTCTimestamp,
        
    },
  
    { 129, &llrp_param_Uptime,
        
    },
  
    { 137, &llrp_param_GeneralDeviceCapabilities,
        
    },
  
    { 139, &llrp_param_ReceiveSensitivityTableEntry,
        
    },
  
    { 140, &llrp_param_PerAntennaAirProtocol,
        
    },
  
    { 141, &llrp_param_GPIOCapabilities,
        
    },
  
    { 142, &llrp_param_LLRPCapabilities,
        
    },
  
    { 143, &llrp_param_RegulatoryCapabilities,
        
    },
  
    { 144, &llrp_param_UHFBandCapabilities,
        
    },
  
    { 145, &llrp_param_TransmitPowerLevelTableEntry,
        
    },
  
    { 146, &llrp_param_FrequencyInformation,
        
    },
  
    { 147, &llrp_param_FrequencyHopTable,
        
    },
  
    { 148, &llrp_param_FixedFrequencyTable,
        
    },
  
    { 149, &llrp_param_PerAntennaReceiveSensitivityRange,
        
    },
  
    { 177, &llrp_param_ROSpec,
        
    },
  
    { 178, &llrp_param_ROBoundarySpec,
        
    },
  
    { 179, &llrp_param_ROSpecStartTrigger,
        
    },
  
    { 180, &llrp_param_PeriodicTriggerValue,
        
    },
  
    { 181, &llrp_param_GPITriggerValue,
        
    },
  
    { 182, &llrp_param_ROSpecStopTrigger,
        
    },
  
    { 183, &llrp_param_AISpec,
        
    },
  
    { 184, &llrp_param_AISpecStopTrigger,
        
    },
  
    { 185, &llrp_param_TagObservationTrigger,
        
    },
  
    { 186, &llrp_param_InventoryParameterSpec,
        
    },
  
    { 187, &llrp_param_RFSurveySpec,
        
    },
  
    { 188, &llrp_param_RFSurveySpecStopTrigger,
        
    },
  
    { 207, &llrp_param_AccessSpec,
        
    },
  
    { 208, &llrp_param_AccessSpecStopTrigger,
        
    },
  
    { 209, &llrp_param_AccessCommand,
        
    },
  
    { 217, &llrp_param_LLRPConfigurationStateValue,
        
    },
  
    { 218, &llrp_param_Identification,
        
    },
  
    { 219, &llrp_param_GPOWriteData,
        
    },
  
    { 220, &llrp_param_KeepaliveSpec,
        
    },
  
    { 221, &llrp_param_AntennaProperties,
        
    },
  
    { 222, &llrp_param_AntennaConfiguration,
        
    },
  
    { 223, &llrp_param_RFReceiver,
        
    },
  
    { 224, &llrp_param_RFTransmitter,
        
    },
  
    { 225, &llrp_param_GPIPortCurrentState,
        
    },
  
    { 226, &llrp_param_EventsAndReports,
        
    },
  
    { 237, &llrp_param_ROReportSpec,
        
    },
  
    { 238, &llrp_param_TagReportContentSelector,
        
    },
  
    { 239, &llrp_param_AccessReportSpec,
        
    },
  
    { 240, &llrp_param_TagReportData,
        
    },
  
    { 241, &llrp_param_EPCData,
        
    },
  
    { 242, &llrp_param_RFSurveyReportData,
        
    },
  
    { 243, &llrp_param_FrequencyRSSILevelEntry,
        
    },
  
    { 244, &llrp_param_ReaderEventNotificationSpec,
        
    },
  
    { 245, &llrp_param_EventNotificationState,
        
    },
  
    { 246, &llrp_param_ReaderEventNotificationData,
        
    },
  
    { 247, &llrp_param_HoppingEvent,
        
    },
  
    { 248, &llrp_param_GPIEvent,
        
    },
  
    { 249, &llrp_param_ROSpecEvent,
        
    },
  
    { 250, &llrp_param_ReportBufferLevelWarningEvent,
        
    },
  
    { 251, &llrp_param_ReportBufferOverflowErrorEvent,
        
    },
  
    { 252, &llrp_param_ReaderExceptionEvent,
        
    },
  
    { 253, &llrp_param_RFSurveyEvent,
        
    },
  
    { 254, &llrp_param_AISpecEvent,
        
    },
  
    { 255, &llrp_param_AntennaEvent,
        
    },
  
    { 256, &llrp_param_ConnectionAttemptEvent,
        
    },
  
    { 257, &llrp_param_ConnectionCloseEvent,
        
    },
  
    { 287, &llrp_param_LLRPStatus,
        
    },
  
    { 288, &llrp_param_FieldError,
        
    },
  
    { 289, &llrp_param_ParameterError,
        
    },
  
    { 327, &llrp_param_C1G2LLRPCapabilities,
        
    },
  
    { 328, &llrp_param_C1G2UHFRFModeTable,
        
    },
  
    { 329, &llrp_param_C1G2UHFRFModeTableEntry,
        
    },
  
    { 330, &llrp_param_C1G2InventoryCommand,
        
    },
  
    { 331, &llrp_param_C1G2Filter,
        
    },
  
    { 332, &llrp_param_C1G2TagInventoryMask,
        
    },
  
    { 333, &llrp_param_C1G2TagInventoryStateAwareFilterAction,
        
    },
  
    { 334, &llrp_param_C1G2TagInventoryStateUnawareFilterAction,
        
    },
  
    { 335, &llrp_param_C1G2RFControl,
        
    },
  
    { 336, &llrp_param_C1G2SingulationControl,
        
    },
  
    { 337, &llrp_param_C1G2TagInventoryStateAwareSingulationAction,
        
    },
  
    { 338, &llrp_param_C1G2TagSpec,
        
    },
  
    { 339, &llrp_param_C1G2TargetTag,
        
    },
  
    { 341, &llrp_param_C1G2Read,
        
    },
  
    { 342, &llrp_param_C1G2Write,
        
    },
  
    { 343, &llrp_param_C1G2Kill,
        
    },
  
    { 344, &llrp_param_C1G2Lock,
        
    },
  
    { 345, &llrp_param_C1G2LockPayload,
        
    },
  
    { 346, &llrp_param_C1G2BlockErase,
        
    },
  
    { 347, &llrp_param_C1G2BlockWrite,
        
    },
  
    { 348, &llrp_param_C1G2EPCMemorySelector,
        
    },
  
    { 349, &llrp_param_C1G2ReadOpSpecResult,
        
    },
  
    { 350, &llrp_param_C1G2WriteOpSpecResult,
        
    },
  
    { 351, &llrp_param_C1G2KillOpSpecResult,
        
    },
  
    { 352, &llrp_param_C1G2LockOpSpecResult,
        
    },
  
    { 353, &llrp_param_C1G2BlockEraseOpSpecResult,
        
    },
  
    { 354, &llrp_param_C1G2BlockWriteOpSpecResult,
        
    },
  
    { 1023, &llrp_param_Custom,
        
    },
  
};
  

/* ----------------------------------------------------------------------------- */
/* Message Definitions (40 total) */
    
/* Message: CUSTOM_MESSAGE */
t_llrp_item llrp_message_items_CUSTOM_MESSAGE[] = {
      
    { "VendorIdentifier", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "MessageSubtype", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      NULL },

    { "Data", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_bytesToEnd, 
      NULL },

};
      
t_llrp_compound_item llrp_message_CUSTOM_MESSAGE = {
    "CUSTOM_MESSAGE", LLRP_ITEM_MESSAGE, 1023, 3,
      llrp_message_items_CUSTOM_MESSAGE
};
    
/* Message: GET_READER_CAPABILITIES */
t_llrp_item llrp_message_items_GET_READER_CAPABILITIES[] = {
      
    { "RequestedData", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_GetReaderCapabilitiesRequestedData },

    { "Custom", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_Custom },

};
      
t_llrp_compound_item llrp_message_GET_READER_CAPABILITIES = {
    "GET_READER_CAPABILITIES", LLRP_ITEM_MESSAGE, 1, 2,
      llrp_message_items_GET_READER_CAPABILITIES
};
    
/* Message: GET_READER_CAPABILITIES_RESPONSE */
t_llrp_item llrp_message_items_GET_READER_CAPABILITIES_RESPONSE[] = {
      
    { "LLRPStatus", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_LLRPStatus },

    { "GeneralDeviceCapabilities", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_GeneralDeviceCapabilities },

    { "LLRPCapabilities", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_LLRPCapabilities },

    { "RegulatoryCapabilities", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_RegulatoryCapabilities },

    { "AirProtocolLLRPCapabilities", LLRP_ITEM_CHOICE, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_choice_AirProtocolLLRPCapabilities },

    { "Custom", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_Custom },

};
      
t_llrp_compound_item llrp_message_GET_READER_CAPABILITIES_RESPONSE = {
    "GET_READER_CAPABILITIES_RESPONSE", LLRP_ITEM_MESSAGE, 11, 6,
      llrp_message_items_GET_READER_CAPABILITIES_RESPONSE
};
    
/* Message: ADD_ROSPEC */
t_llrp_item llrp_message_items_ADD_ROSPEC[] = {
      
    { "ROSpec", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_ROSpec },

};
      
t_llrp_compound_item llrp_message_ADD_ROSPEC = {
    "ADD_ROSPEC", LLRP_ITEM_MESSAGE, 20, 1,
      llrp_message_items_ADD_ROSPEC
};
    
/* Message: ADD_ROSPEC_RESPONSE */
t_llrp_item llrp_message_items_ADD_ROSPEC_RESPONSE[] = {
      
    { "LLRPStatus", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_LLRPStatus },

};
      
t_llrp_compound_item llrp_message_ADD_ROSPEC_RESPONSE = {
    "ADD_ROSPEC_RESPONSE", LLRP_ITEM_MESSAGE, 30, 1,
      llrp_message_items_ADD_ROSPEC_RESPONSE
};
    
/* Message: DELETE_ROSPEC */
t_llrp_item llrp_message_items_DELETE_ROSPEC[] = {
      
    { "ROSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

};
      
t_llrp_compound_item llrp_message_DELETE_ROSPEC = {
    "DELETE_ROSPEC", LLRP_ITEM_MESSAGE, 21, 1,
      llrp_message_items_DELETE_ROSPEC
};
    
/* Message: DELETE_ROSPEC_RESPONSE */
t_llrp_item llrp_message_items_DELETE_ROSPEC_RESPONSE[] = {
      
    { "LLRPStatus", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_LLRPStatus },

};
      
t_llrp_compound_item llrp_message_DELETE_ROSPEC_RESPONSE = {
    "DELETE_ROSPEC_RESPONSE", LLRP_ITEM_MESSAGE, 31, 1,
      llrp_message_items_DELETE_ROSPEC_RESPONSE
};
    
/* Message: START_ROSPEC */
t_llrp_item llrp_message_items_START_ROSPEC[] = {
      
    { "ROSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

};
      
t_llrp_compound_item llrp_message_START_ROSPEC = {
    "START_ROSPEC", LLRP_ITEM_MESSAGE, 22, 1,
      llrp_message_items_START_ROSPEC
};
    
/* Message: START_ROSPEC_RESPONSE */
t_llrp_item llrp_message_items_START_ROSPEC_RESPONSE[] = {
      
    { "LLRPStatus", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_LLRPStatus },

};
      
t_llrp_compound_item llrp_message_START_ROSPEC_RESPONSE = {
    "START_ROSPEC_RESPONSE", LLRP_ITEM_MESSAGE, 32, 1,
      llrp_message_items_START_ROSPEC_RESPONSE
};
    
/* Message: STOP_ROSPEC */
t_llrp_item llrp_message_items_STOP_ROSPEC[] = {
      
    { "ROSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

};
      
t_llrp_compound_item llrp_message_STOP_ROSPEC = {
    "STOP_ROSPEC", LLRP_ITEM_MESSAGE, 23, 1,
      llrp_message_items_STOP_ROSPEC
};
    
/* Message: STOP_ROSPEC_RESPONSE */
t_llrp_item llrp_message_items_STOP_ROSPEC_RESPONSE[] = {
      
    { "LLRPStatus", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_LLRPStatus },

};
      
t_llrp_compound_item llrp_message_STOP_ROSPEC_RESPONSE = {
    "STOP_ROSPEC_RESPONSE", LLRP_ITEM_MESSAGE, 33, 1,
      llrp_message_items_STOP_ROSPEC_RESPONSE
};
    
/* Message: ENABLE_ROSPEC */
t_llrp_item llrp_message_items_ENABLE_ROSPEC[] = {
      
    { "ROSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

};
      
t_llrp_compound_item llrp_message_ENABLE_ROSPEC = {
    "ENABLE_ROSPEC", LLRP_ITEM_MESSAGE, 24, 1,
      llrp_message_items_ENABLE_ROSPEC
};
    
/* Message: ENABLE_ROSPEC_RESPONSE */
t_llrp_item llrp_message_items_ENABLE_ROSPEC_RESPONSE[] = {
      
    { "LLRPStatus", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_LLRPStatus },

};
      
t_llrp_compound_item llrp_message_ENABLE_ROSPEC_RESPONSE = {
    "ENABLE_ROSPEC_RESPONSE", LLRP_ITEM_MESSAGE, 34, 1,
      llrp_message_items_ENABLE_ROSPEC_RESPONSE
};
    
/* Message: DISABLE_ROSPEC */
t_llrp_item llrp_message_items_DISABLE_ROSPEC[] = {
      
    { "ROSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

};
      
t_llrp_compound_item llrp_message_DISABLE_ROSPEC = {
    "DISABLE_ROSPEC", LLRP_ITEM_MESSAGE, 25, 1,
      llrp_message_items_DISABLE_ROSPEC
};
    
/* Message: DISABLE_ROSPEC_RESPONSE */
t_llrp_item llrp_message_items_DISABLE_ROSPEC_RESPONSE[] = {
      
    { "LLRPStatus", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_LLRPStatus },

};
      
t_llrp_compound_item llrp_message_DISABLE_ROSPEC_RESPONSE = {
    "DISABLE_ROSPEC_RESPONSE", LLRP_ITEM_MESSAGE, 35, 1,
      llrp_message_items_DISABLE_ROSPEC_RESPONSE
};
    
t_llrp_compound_item llrp_message_GET_ROSPECS = {
    "GET_ROSPECS", LLRP_ITEM_MESSAGE, 26, 0,
      NULL
};
    
/* Message: GET_ROSPECS_RESPONSE */
t_llrp_item llrp_message_items_GET_ROSPECS_RESPONSE[] = {
      
    { "LLRPStatus", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_LLRPStatus },

    { "ROSpec", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_ROSpec },

};
      
t_llrp_compound_item llrp_message_GET_ROSPECS_RESPONSE = {
    "GET_ROSPECS_RESPONSE", LLRP_ITEM_MESSAGE, 36, 2,
      llrp_message_items_GET_ROSPECS_RESPONSE
};
    
/* Message: ADD_ACCESSSPEC */
t_llrp_item llrp_message_items_ADD_ACCESSSPEC[] = {
      
    { "AccessSpec", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_AccessSpec },

};
      
t_llrp_compound_item llrp_message_ADD_ACCESSSPEC = {
    "ADD_ACCESSSPEC", LLRP_ITEM_MESSAGE, 40, 1,
      llrp_message_items_ADD_ACCESSSPEC
};
    
/* Message: ADD_ACCESSSPEC_RESPONSE */
t_llrp_item llrp_message_items_ADD_ACCESSSPEC_RESPONSE[] = {
      
    { "LLRPStatus", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_LLRPStatus },

};
      
t_llrp_compound_item llrp_message_ADD_ACCESSSPEC_RESPONSE = {
    "ADD_ACCESSSPEC_RESPONSE", LLRP_ITEM_MESSAGE, 50, 1,
      llrp_message_items_ADD_ACCESSSPEC_RESPONSE
};
    
/* Message: DELETE_ACCESSSPEC */
t_llrp_item llrp_message_items_DELETE_ACCESSSPEC[] = {
      
    { "AccessSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

};
      
t_llrp_compound_item llrp_message_DELETE_ACCESSSPEC = {
    "DELETE_ACCESSSPEC", LLRP_ITEM_MESSAGE, 41, 1,
      llrp_message_items_DELETE_ACCESSSPEC
};
    
/* Message: DELETE_ACCESSSPEC_RESPONSE */
t_llrp_item llrp_message_items_DELETE_ACCESSSPEC_RESPONSE[] = {
      
    { "LLRPStatus", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_LLRPStatus },

};
      
t_llrp_compound_item llrp_message_DELETE_ACCESSSPEC_RESPONSE = {
    "DELETE_ACCESSSPEC_RESPONSE", LLRP_ITEM_MESSAGE, 51, 1,
      llrp_message_items_DELETE_ACCESSSPEC_RESPONSE
};
    
/* Message: ENABLE_ACCESSSPEC */
t_llrp_item llrp_message_items_ENABLE_ACCESSSPEC[] = {
      
    { "AccessSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

};
      
t_llrp_compound_item llrp_message_ENABLE_ACCESSSPEC = {
    "ENABLE_ACCESSSPEC", LLRP_ITEM_MESSAGE, 42, 1,
      llrp_message_items_ENABLE_ACCESSSPEC
};
    
/* Message: ENABLE_ACCESSSPEC_RESPONSE */
t_llrp_item llrp_message_items_ENABLE_ACCESSSPEC_RESPONSE[] = {
      
    { "LLRPStatus", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_LLRPStatus },

};
      
t_llrp_compound_item llrp_message_ENABLE_ACCESSSPEC_RESPONSE = {
    "ENABLE_ACCESSSPEC_RESPONSE", LLRP_ITEM_MESSAGE, 52, 1,
      llrp_message_items_ENABLE_ACCESSSPEC_RESPONSE
};
    
/* Message: DISABLE_ACCESSSPEC */
t_llrp_item llrp_message_items_DISABLE_ACCESSSPEC[] = {
      
    { "AccessSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

};
      
t_llrp_compound_item llrp_message_DISABLE_ACCESSSPEC = {
    "DISABLE_ACCESSSPEC", LLRP_ITEM_MESSAGE, 43, 1,
      llrp_message_items_DISABLE_ACCESSSPEC
};
    
/* Message: DISABLE_ACCESSSPEC_RESPONSE */
t_llrp_item llrp_message_items_DISABLE_ACCESSSPEC_RESPONSE[] = {
      
    { "LLRPStatus", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_LLRPStatus },

};
      
t_llrp_compound_item llrp_message_DISABLE_ACCESSSPEC_RESPONSE = {
    "DISABLE_ACCESSSPEC_RESPONSE", LLRP_ITEM_MESSAGE, 53, 1,
      llrp_message_items_DISABLE_ACCESSSPEC_RESPONSE
};
    
t_llrp_compound_item llrp_message_GET_ACCESSSPECS = {
    "GET_ACCESSSPECS", LLRP_ITEM_MESSAGE, 44, 0,
      NULL
};
    
/* Message: GET_ACCESSSPECS_RESPONSE */
t_llrp_item llrp_message_items_GET_ACCESSSPECS_RESPONSE[] = {
      
    { "LLRPStatus", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_LLRPStatus },

    { "AccessSpec", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_AccessSpec },

};
      
t_llrp_compound_item llrp_message_GET_ACCESSSPECS_RESPONSE = {
    "GET_ACCESSSPECS_RESPONSE", LLRP_ITEM_MESSAGE, 54, 2,
      llrp_message_items_GET_ACCESSSPECS_RESPONSE
};
    
/* Message: GET_READER_CONFIG */
t_llrp_item llrp_message_items_GET_READER_CONFIG[] = {
      
    { "AntennaID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "RequestedData", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_GetReaderConfigRequestedData },

    { "GPIPortNum", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "GPOPortNum", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "Custom", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_Custom },

};
      
t_llrp_compound_item llrp_message_GET_READER_CONFIG = {
    "GET_READER_CONFIG", LLRP_ITEM_MESSAGE, 2, 5,
      llrp_message_items_GET_READER_CONFIG
};
    
/* Message: GET_READER_CONFIG_RESPONSE */
t_llrp_item llrp_message_items_GET_READER_CONFIG_RESPONSE[] = {
      
    { "LLRPStatus", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_LLRPStatus },

    { "Identification", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_Identification },

    { "AntennaProperties", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_AntennaProperties },

    { "AntennaConfiguration", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_AntennaConfiguration },

    { "ReaderEventNotificationSpec", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_ReaderEventNotificationSpec },

    { "ROReportSpec", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_ROReportSpec },

    { "AccessReportSpec", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_AccessReportSpec },

    { "LLRPConfigurationStateValue", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_LLRPConfigurationStateValue },

    { "KeepaliveSpec", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_KeepaliveSpec },

    { "GPIPortCurrentState", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_GPIPortCurrentState },

    { "GPOWriteData", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_GPOWriteData },

    { "EventsAndReports", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_EventsAndReports },

    { "Custom", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_Custom },

};
      
t_llrp_compound_item llrp_message_GET_READER_CONFIG_RESPONSE = {
    "GET_READER_CONFIG_RESPONSE", LLRP_ITEM_MESSAGE, 12, 13,
      llrp_message_items_GET_READER_CONFIG_RESPONSE
};
    
/* Message: SET_READER_CONFIG */
t_llrp_item llrp_message_items_SET_READER_CONFIG[] = {
      
    { "ResetToFactoryDefault", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 7, 0, LLRP_FIELDTYPE_NONE, NULL },

    { "ReaderEventNotificationSpec", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_ReaderEventNotificationSpec },

    { "AntennaProperties", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_AntennaProperties },

    { "AntennaConfiguration", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_AntennaConfiguration },

    { "ROReportSpec", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_ROReportSpec },

    { "AccessReportSpec", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_AccessReportSpec },

    { "KeepaliveSpec", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_KeepaliveSpec },

    { "GPOWriteData", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_GPOWriteData },

    { "GPIPortCurrentState", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_GPIPortCurrentState },

    { "EventsAndReports", LLRP_ITEM_PARAMETER, 0, 1, LLRP_FIELDTYPE_NONE, &llrp_param_EventsAndReports },

    { "Custom", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_Custom },

};
      
t_llrp_compound_item llrp_message_SET_READER_CONFIG = {
    "SET_READER_CONFIG", LLRP_ITEM_MESSAGE, 3, 12,
      llrp_message_items_SET_READER_CONFIG
};
    
/* Message: SET_READER_CONFIG_RESPONSE */
t_llrp_item llrp_message_items_SET_READER_CONFIG_RESPONSE[] = {
      
    { "LLRPStatus", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_LLRPStatus },

};
      
t_llrp_compound_item llrp_message_SET_READER_CONFIG_RESPONSE = {
    "SET_READER_CONFIG_RESPONSE", LLRP_ITEM_MESSAGE, 13, 1,
      llrp_message_items_SET_READER_CONFIG_RESPONSE
};
    
t_llrp_compound_item llrp_message_CLOSE_CONNECTION = {
    "CLOSE_CONNECTION", LLRP_ITEM_MESSAGE, 14, 0,
      NULL
};
    
/* Message: CLOSE_CONNECTION_RESPONSE */
t_llrp_item llrp_message_items_CLOSE_CONNECTION_RESPONSE[] = {
      
    { "LLRPStatus", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_LLRPStatus },

};
      
t_llrp_compound_item llrp_message_CLOSE_CONNECTION_RESPONSE = {
    "CLOSE_CONNECTION_RESPONSE", LLRP_ITEM_MESSAGE, 4, 1,
      llrp_message_items_CLOSE_CONNECTION_RESPONSE
};
    
t_llrp_compound_item llrp_message_GET_REPORT = {
    "GET_REPORT", LLRP_ITEM_MESSAGE, 60, 0,
      NULL
};
    
/* Message: RO_ACCESS_REPORT */
t_llrp_item llrp_message_items_RO_ACCESS_REPORT[] = {
      
    { "TagReportData", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_TagReportData },

    { "RFSurveyReportData", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_RFSurveyReportData },

    { "Custom", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_Custom },

};
      
t_llrp_compound_item llrp_message_RO_ACCESS_REPORT = {
    "RO_ACCESS_REPORT", LLRP_ITEM_MESSAGE, 61, 3,
      llrp_message_items_RO_ACCESS_REPORT
};
    
t_llrp_compound_item llrp_message_KEEPALIVE = {
    "KEEPALIVE", LLRP_ITEM_MESSAGE, 62, 0,
      NULL
};
    
t_llrp_compound_item llrp_message_KEEPALIVE_ACK = {
    "KEEPALIVE_ACK", LLRP_ITEM_MESSAGE, 72, 0,
      NULL
};
    
/* Message: READER_EVENT_NOTIFICATION */
t_llrp_item llrp_message_items_READER_EVENT_NOTIFICATION[] = {
      
    { "ReaderEventNotificationData", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_ReaderEventNotificationData },

};
      
t_llrp_compound_item llrp_message_READER_EVENT_NOTIFICATION = {
    "READER_EVENT_NOTIFICATION", LLRP_ITEM_MESSAGE, 63, 1,
      llrp_message_items_READER_EVENT_NOTIFICATION
};
    
t_llrp_compound_item llrp_message_ENABLE_EVENTS_AND_REPORTS = {
    "ENABLE_EVENTS_AND_REPORTS", LLRP_ITEM_MESSAGE, 64, 0,
      NULL
};
    
/* Message: ERROR_MESSAGE */
t_llrp_item llrp_message_items_ERROR_MESSAGE[] = {
      
    { "LLRPStatus", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_LLRPStatus },

};
      
t_llrp_compound_item llrp_message_ERROR_MESSAGE = {
    "ERROR_MESSAGE", LLRP_ITEM_MESSAGE, 100, 1,
      llrp_message_items_ERROR_MESSAGE
};
    
/* ----------------------------------------------------------------------------- */
/* Message List (40 total) */

t_llrp_standard_map_item llrp_v1_0_message_list[] = {
  
    { 1, &llrp_message_GET_READER_CAPABILITIES,
        
    },
  
    { 2, &llrp_message_GET_READER_CONFIG,
        
    },
  
    { 3, &llrp_message_SET_READER_CONFIG,
        
    },
  
    { 4, &llrp_message_CLOSE_CONNECTION_RESPONSE,
        
    },
  
    { 11, &llrp_message_GET_READER_CAPABILITIES_RESPONSE,
        
    },
  
    { 12, &llrp_message_GET_READER_CONFIG_RESPONSE,
        
    },
  
    { 13, &llrp_message_SET_READER_CONFIG_RESPONSE,
        
    },
  
    { 14, &llrp_message_CLOSE_CONNECTION,
        
    },
  
    { 20, &llrp_message_ADD_ROSPEC,
        
    },
  
    { 21, &llrp_message_DELETE_ROSPEC,
        
    },
  
    { 22, &llrp_message_START_ROSPEC,
        
    },
  
    { 23, &llrp_message_STOP_ROSPEC,
        
    },
  
    { 24, &llrp_message_ENABLE_ROSPEC,
        
    },
  
    { 25, &llrp_message_DISABLE_ROSPEC,
        
    },
  
    { 26, &llrp_message_GET_ROSPECS,
        
    },
  
    { 30, &llrp_message_ADD_ROSPEC_RESPONSE,
        
    },
  
    { 31, &llrp_message_DELETE_ROSPEC_RESPONSE,
        
    },
  
    { 32, &llrp_message_START_ROSPEC_RESPONSE,
        
    },
  
    { 33, &llrp_message_STOP_ROSPEC_RESPONSE,
        
    },
  
    { 34, &llrp_message_ENABLE_ROSPEC_RESPONSE,
        
    },
  
    { 35, &llrp_message_DISABLE_ROSPEC_RESPONSE,
        
    },
  
    { 36, &llrp_message_GET_ROSPECS_RESPONSE,
        
    },
  
    { 40, &llrp_message_ADD_ACCESSSPEC,
        
    },
  
    { 41, &llrp_message_DELETE_ACCESSSPEC,
        
    },
  
    { 42, &llrp_message_ENABLE_ACCESSSPEC,
        
    },
  
    { 43, &llrp_message_DISABLE_ACCESSSPEC,
        
    },
  
    { 44, &llrp_message_GET_ACCESSSPECS,
        
    },
  
    { 50, &llrp_message_ADD_ACCESSSPEC_RESPONSE,
        
    },
  
    { 51, &llrp_message_DELETE_ACCESSSPEC_RESPONSE,
        
    },
  
    { 52, &llrp_message_ENABLE_ACCESSSPEC_RESPONSE,
        
    },
  
    { 53, &llrp_message_DISABLE_ACCESSSPEC_RESPONSE,
        
    },
  
    { 54, &llrp_message_GET_ACCESSSPECS_RESPONSE,
        
    },
  
    { 60, &llrp_message_GET_REPORT,
        
    },
  
    { 61, &llrp_message_RO_ACCESS_REPORT,
        
    },
  
    { 62, &llrp_message_KEEPALIVE,
        
    },
  
    { 63, &llrp_message_READER_EVENT_NOTIFICATION,
        
    },
  
    { 64, &llrp_message_ENABLE_EVENTS_AND_REPORTS,
        
    },
  
    { 72, &llrp_message_KEEPALIVE_ACK,
        
    },
  
    { 100, &llrp_message_ERROR_MESSAGE,
        
    },
  
    { 1023, &llrp_message_CUSTOM_MESSAGE,
        
    },
  
};
  
/* ----------------------------------------------------------------------------- */
/* Validator: v1_0 */
t_llrp_parse_validator llrp_v1_0_parse_validator = {
    "v1_0",
    llrp_v1_0_parameter_list, 108,
    NULL, 0,
    llrp_v1_0_message_list, 40,
    NULL, 0,
};


/*end*/
