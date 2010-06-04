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
/* Enumerations (3 total) */
    
t_llrp_enumeration_item llrp_enum_list_IntermecEngineCodeEnumeration[] = {
        
    { "Success", 0 },
    { "Insufficient_Tag_Power", 1 },
    { "NAK", 2 },
    { "Read_Error", 3 },
    { "Write_Error", 4 },
    { "Lock_Error", 5 },
    { "Unlock_Error", 6 },
    { "Query_Lock_Error", 7 },
    { "Kill_Error", 8 },
    { "Illegal_Command", 9 },
    { "Address_Range_Check_Error", 10 },
    { "Nonspecific_Error", 11 },
    { "Privilege_Error", 12 },
    { "Memory_Lock_Error", 13 },
    { "Blocked", 14 },
    { "Duty_Cycle", 15 },
    { "No_Response", 16 },
    { "CRC_Error", 17 },
    { "Collision", 18 },
    { "Memory_Overrun_Error", 19 },
    { "Erase_Error", 20 },
    { "NXP_Alarm_Error", 21 },
};
t_llrp_enumeration llrp_enum_IntermecEngineCodeEnumeration = {
    llrp_enum_list_IntermecEngineCodeEnumeration, 22
};
    
t_llrp_enumeration_item llrp_enum_list_IntermecNXPReadProtectResultType[] = {
        
    { "Success", 0 },
    { "Tag_Memory_Locked_Error", 1 },
    { "Insufficient_Power", 2 },
    { "Nonspecific_Tag_Error", 3 },
    { "No_Response_From_Tag", 4 },
    { "Nonspecific_Reader_Error", 5 },
};
t_llrp_enumeration llrp_enum_IntermecNXPReadProtectResultType = {
    llrp_enum_list_IntermecNXPReadProtectResultType, 6
};
    
t_llrp_enumeration_item llrp_enum_list_IntermecNXPEASResultType[] = {
        
    { "Success", 0 },
    { "Tag_Memory_Locked_Error", 1 },
    { "Insufficient_Power", 2 },
    { "Nonspecific_Tag_Error", 3 },
    { "No_Response_From_Tag", 4 },
    { "Nonspecific_Reader_Error", 5 },
};
t_llrp_enumeration llrp_enum_IntermecNXPEASResultType = {
    llrp_enum_list_IntermecNXPEASResultType, 6
};
    
/* ----------------------------------------------------------------------------- */
/* Parameter Definitions (36 total) */
    
/* Parameter: IntermecResetStartEvent */
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecResetStartEvent = {
    "IntermecResetStartEvent", LLRP_ITEM_PARAMETER, 16, 0,
      NULL
};
    
/* Parameter: IntermecResetCompleteEvent */
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecResetCompleteEvent = {
    "IntermecResetCompleteEvent", LLRP_ITEM_PARAMETER, 19, 0,
      NULL
};
    
/* Parameter: IntermecLowLevelLogEvent */
      
t_llrp_item llrp_custparam_items_IntermecLowLevelLogEvent[] = {
      
    { "PlatformVersion", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_utf8v, 
      NULL },

    { "SoftwareVersion", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_utf8v, 
      NULL },

    { "Region", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_utf8v, 
      NULL },

    { "BuildDate", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_utf8v, 
      NULL },

    { "BuildTime", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_utf8v, 
      NULL },

    { "BuildOwner", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_utf8v, 
      NULL },

    { "BuildBaseline", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_utf8v, 
      NULL },

    { "LogData", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_bytesToEnd, 
      NULL },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecLowLevelLogEvent = {
    "IntermecLowLevelLogEvent", LLRP_ITEM_PARAMETER, 18, 8,
      llrp_custparam_items_IntermecLowLevelLogEvent
};
    
/* Parameter: IntermecROSpecLoopEvent */
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecROSpecLoopEvent = {
    "IntermecROSpecLoopEvent", LLRP_ITEM_PARAMETER, 21, 0,
      NULL
};
    
/* Parameter: IntermecNXPEASAlarmEndEvent */
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecNXPEASAlarmEndEvent = {
    "IntermecNXPEASAlarmEndEvent", LLRP_ITEM_PARAMETER, 29, 0,
      NULL
};
    
/* Parameter: IntermecNXPEASAlarmResult */
      
t_llrp_item llrp_custparam_items_IntermecNXPEASAlarmResult[] = {
      
    { "AlarmSeenCount", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "FirstSeenTimestampUTC", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_FirstSeenTimestampUTC },

    { "LastSeenTimestampUTC", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_LastSeenTimestampUTC },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecNXPEASAlarmResult = {
    "IntermecNXPEASAlarmResult", LLRP_ITEM_PARAMETER, 30, 3,
      llrp_custparam_items_IntermecNXPEASAlarmResult
};
    
/* Parameter: IntermecEnableROSpecLoop */
      
t_llrp_item llrp_custparam_items_IntermecEnableROSpecLoop[] = {
      
    { "EnableSpecLooping", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 7, 0, LLRP_FIELDTYPE_NONE, NULL },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecEnableROSpecLoop = {
    "IntermecEnableROSpecLoop", LLRP_ITEM_PARAMETER, 5, 2,
      llrp_custparam_items_IntermecEnableROSpecLoop
};
    
/* Parameter: IntermecEnableLowLevelLogging */
      
t_llrp_item llrp_custparam_items_IntermecEnableLowLevelLogging[] = {
      
    { "EnableLowLevelLogging", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 7, 0, LLRP_FIELDTYPE_NONE, NULL },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecEnableLowLevelLogging = {
    "IntermecEnableLowLevelLogging", LLRP_ITEM_PARAMETER, 17, 2,
      llrp_custparam_items_IntermecEnableLowLevelLogging
};
    
/* Parameter: IntermecNXPEASAlarm */
      
t_llrp_item llrp_custparam_items_IntermecNXPEASAlarm[] = {
      
    { "AntennaIDs", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16v, 
      NULL },

    { "AntennaConfiguration", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_AntennaConfiguration },

    { "AISpecStopTrigger", LLRP_ITEM_PARAMETER, 1, 0, LLRP_FIELDTYPE_NONE, &llrp_param_AISpecStopTrigger },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecNXPEASAlarm = {
    "IntermecNXPEASAlarm", LLRP_ITEM_PARAMETER, 27, 3,
      llrp_custparam_items_IntermecNXPEASAlarm
};
    
/* Parameter: IntermecAISpecStopTrigger */
      
t_llrp_item llrp_custparam_items_IntermecAISpecStopTrigger[] = {
      
    { "Custom", LLRP_ITEM_PARAMETER, 1, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_Custom },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecAISpecStopTrigger = {
    "IntermecAISpecStopTrigger", LLRP_ITEM_PARAMETER, 28, 1,
      llrp_custparam_items_IntermecAISpecStopTrigger
};
    
/* Parameter: IntermecAISpecStopTriggerMinimumTries */
      
t_llrp_item llrp_custparam_items_IntermecAISpecStopTriggerMinimumTries[] = {
      
    { "MinimumTries", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "Custom", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_Custom },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecAISpecStopTriggerMinimumTries = {
    "IntermecAISpecStopTriggerMinimumTries", LLRP_ITEM_PARAMETER, 31, 2,
      llrp_custparam_items_IntermecAISpecStopTriggerMinimumTries
};
    
/* Parameter: IntermecAISpecStopTriggerMinimumTimeout */
      
t_llrp_item llrp_custparam_items_IntermecAISpecStopTriggerMinimumTimeout[] = {
      
    { "MinimumTimeout", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "Custom", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_Custom },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecAISpecStopTriggerMinimumTimeout = {
    "IntermecAISpecStopTriggerMinimumTimeout", LLRP_ITEM_PARAMETER, 32, 2,
      llrp_custparam_items_IntermecAISpecStopTriggerMinimumTimeout
};
    
/* Parameter: IntermecCollectExtraTagSingulationDetails */
      
t_llrp_item llrp_custparam_items_IntermecCollectExtraTagSingulationDetails[] = {
      
    { "EnableRNSI", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "EnableHighResolutionRSSI", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "EnablePhaseAngle", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 5, 0, LLRP_FIELDTYPE_NONE, NULL },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecCollectExtraTagSingulationDetails = {
    "IntermecCollectExtraTagSingulationDetails", LLRP_ITEM_PARAMETER, 1, 4,
      llrp_custparam_items_IntermecCollectExtraTagSingulationDetails
};
    
/* Parameter: IntermecEnableABToggle */
      
t_llrp_item llrp_custparam_items_IntermecEnableABToggle[] = {
      
    { "EnableABToggle", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 7, 0, LLRP_FIELDTYPE_NONE, NULL },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecEnableABToggle = {
    "IntermecEnableABToggle", LLRP_ITEM_PARAMETER, 7, 2,
      llrp_custparam_items_IntermecEnableABToggle
};
    
/* Parameter: IntermecNXPReadProtect */
      
t_llrp_item llrp_custparam_items_IntermecNXPReadProtect[] = {
      
    { "OpSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "AccessPassword", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "EnableReadProtect", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 7, 0, LLRP_FIELDTYPE_NONE, NULL },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecNXPReadProtect = {
    "IntermecNXPReadProtect", LLRP_ITEM_PARAMETER, 23, 4,
      llrp_custparam_items_IntermecNXPReadProtect
};
    
/* Parameter: IntermecNXPEAS */
      
t_llrp_item llrp_custparam_items_IntermecNXPEAS[] = {
      
    { "OpSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "AccessPassword", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "EnableEAS", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 7, 0, LLRP_FIELDTYPE_NONE, NULL },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecNXPEAS = {
    "IntermecNXPEAS", LLRP_ITEM_PARAMETER, 24, 4,
      llrp_custparam_items_IntermecNXPEAS
};
    
/* Parameter: IntermecEnableReportCoalescence */
      
t_llrp_item llrp_custparam_items_IntermecEnableReportCoalescence[] = {
      
    { "EnableCoalescence", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 7, 0, LLRP_FIELDTYPE_NONE, NULL },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecEnableReportCoalescence = {
    "IntermecEnableReportCoalescence", LLRP_ITEM_PARAMETER, 33, 2,
      llrp_custparam_items_IntermecEnableReportCoalescence
};
    
/* Parameter: IntermecNXPReadProtectOpSpecResult */
      
t_llrp_item llrp_custparam_items_IntermecNXPReadProtectOpSpecResult[] = {
      
    { "Result", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_IntermecNXPReadProtectResultType },

    { "OpSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecNXPReadProtectOpSpecResult = {
    "IntermecNXPReadProtectOpSpecResult", LLRP_ITEM_PARAMETER, 25, 2,
      llrp_custparam_items_IntermecNXPReadProtectOpSpecResult
};
    
/* Parameter: IntermecNXPEASOpSpecResult */
      
t_llrp_item llrp_custparam_items_IntermecNXPEASOpSpecResult[] = {
      
    { "Result", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      &llrp_enum_IntermecNXPEASResultType },

    { "OpSpecID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecNXPEASOpSpecResult = {
    "IntermecNXPEASOpSpecResult", LLRP_ITEM_PARAMETER, 26, 2,
      llrp_custparam_items_IntermecNXPEASOpSpecResult
};
    
/* Parameter: IntermecEnableTagInZone */
      
t_llrp_item llrp_custparam_items_IntermecEnableTagInZone[] = {
      
    { "Enable", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 7, 0, LLRP_FIELDTYPE_NONE, NULL },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecEnableTagInZone = {
    "IntermecEnableTagInZone", LLRP_ITEM_PARAMETER, 3, 2,
      llrp_custparam_items_IntermecEnableTagInZone
};
    
/* Parameter: IntermecEnableTagInPortal */
      
t_llrp_item llrp_custparam_items_IntermecEnableTagInPortal[] = {
      
    { "Enable", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 7, 0, LLRP_FIELDTYPE_NONE, NULL },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecEnableTagInPortal = {
    "IntermecEnableTagInPortal", LLRP_ITEM_PARAMETER, 35, 2,
      llrp_custparam_items_IntermecEnableTagInPortal
};
    
/* Parameter: IntermecEnableTagMoving */
      
t_llrp_item llrp_custparam_items_IntermecEnableTagMoving[] = {
      
    { "Enable", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 7, 0, LLRP_FIELDTYPE_NONE, NULL },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecEnableTagMoving = {
    "IntermecEnableTagMoving", LLRP_ITEM_PARAMETER, 10, 2,
      llrp_custparam_items_IntermecEnableTagMoving
};
    
/* Parameter: IntermecEnableTagNear */
      
t_llrp_item llrp_custparam_items_IntermecEnableTagNear[] = {
      
    { "Enable", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 7, 0, LLRP_FIELDTYPE_NONE, NULL },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecEnableTagNear = {
    "IntermecEnableTagNear", LLRP_ITEM_PARAMETER, 11, 2,
      llrp_custparam_items_IntermecEnableTagNear
};
    
/* Parameter: IntermecEnableTagSpeed */
      
t_llrp_item llrp_custparam_items_IntermecEnableTagSpeed[] = {
      
    { "Enable", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 7, 0, LLRP_FIELDTYPE_NONE, NULL },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecEnableTagSpeed = {
    "IntermecEnableTagSpeed", LLRP_ITEM_PARAMETER, 14, 2,
      llrp_custparam_items_IntermecEnableTagSpeed
};
    
/* Parameter: IntermecEnableTagDistance */
      
t_llrp_item llrp_custparam_items_IntermecEnableTagDistance[] = {
      
    { "Enable", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1, 
      NULL },

    { "", LLRP_ITEM_RESERVED, 7, 0, LLRP_FIELDTYPE_NONE, NULL },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecEnableTagDistance = {
    "IntermecEnableTagDistance", LLRP_ITEM_PARAMETER, 20, 2,
      llrp_custparam_items_IntermecEnableTagDistance
};
    
/* Parameter: IntermecTagReportData */
      
t_llrp_item llrp_custparam_items_IntermecTagReportData[] = {
      
    { "ID", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u1v, 
      NULL },

    { "TagSeenCount", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

    { "UTCTimestampMicroseconds", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u64, 
      NULL },

    { "Custom", LLRP_ITEM_PARAMETER, 0, LLRP_REPEAT_INDEFINITELY, LLRP_FIELDTYPE_NONE, &llrp_param_Custom },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecTagReportData = {
    "IntermecTagReportData", LLRP_ITEM_PARAMETER, 2, 4,
      llrp_custparam_items_IntermecTagReportData
};
    
/* Parameter: IntermecAccessResult */
      
t_llrp_item llrp_custparam_items_IntermecAccessResult[] = {
      
    { "Result", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      &llrp_enum_IntermecEngineCodeEnumeration },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecAccessResult = {
    "IntermecAccessResult", LLRP_ITEM_PARAMETER, 0, 1,
      llrp_custparam_items_IntermecAccessResult
};
    
/* Parameter: IntermecRNSI */
      
t_llrp_item llrp_custparam_items_IntermecRNSI[] = {
      
    { "RNSI", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "LowLevelTimestamp", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecRNSI = {
    "IntermecRNSI", LLRP_ITEM_PARAMETER, 4, 2,
      llrp_custparam_items_IntermecRNSI
};
    
/* Parameter: IntermecPhaseAngle */
      
t_llrp_item llrp_custparam_items_IntermecPhaseAngle[] = {
      
    { "PhaseAngle", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_s16, 
      NULL },

    { "LowLevelTimestamp", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecPhaseAngle = {
    "IntermecPhaseAngle", LLRP_ITEM_PARAMETER, 6, 2,
      llrp_custparam_items_IntermecPhaseAngle
};
    
/* Parameter: IntermecHighResolutionRSSI */
      
t_llrp_item llrp_custparam_items_IntermecHighResolutionRSSI[] = {
      
    { "HighResolutionRSSI", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

    { "LowLevelTimestamp", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u32, 
      NULL },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecHighResolutionRSSI = {
    "IntermecHighResolutionRSSI", LLRP_ITEM_PARAMETER, 8, 2,
      llrp_custparam_items_IntermecHighResolutionRSSI
};
    
/* Parameter: IntermecTagInZone */
      
t_llrp_item llrp_custparam_items_IntermecTagInZone[] = {
      
    { "InZoneConfidence", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      NULL },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecTagInZone = {
    "IntermecTagInZone", LLRP_ITEM_PARAMETER, 9, 1,
      llrp_custparam_items_IntermecTagInZone
};
    
/* Parameter: IntermecTagInPortal */
      
t_llrp_item llrp_custparam_items_IntermecTagInPortal[] = {
      
    { "InPortalConfidence", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      NULL },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecTagInPortal = {
    "IntermecTagInPortal", LLRP_ITEM_PARAMETER, 34, 1,
      llrp_custparam_items_IntermecTagInPortal
};
    
/* Parameter: IntermecTagMoving */
      
t_llrp_item llrp_custparam_items_IntermecTagMoving[] = {
      
    { "MovingConfidence", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      NULL },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecTagMoving = {
    "IntermecTagMoving", LLRP_ITEM_PARAMETER, 12, 1,
      llrp_custparam_items_IntermecTagMoving
};
    
/* Parameter: IntermecTagNear */
      
t_llrp_item llrp_custparam_items_IntermecTagNear[] = {
      
    { "NearnessFactor", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u8, 
      NULL },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecTagNear = {
    "IntermecTagNear", LLRP_ITEM_PARAMETER, 13, 1,
      llrp_custparam_items_IntermecTagNear
};
    
/* Parameter: IntermecTagSpeed */
      
t_llrp_item llrp_custparam_items_IntermecTagSpeed[] = {
      
    { "Speed", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecTagSpeed = {
    "IntermecTagSpeed", LLRP_ITEM_PARAMETER, 15, 1,
      llrp_custparam_items_IntermecTagSpeed
};
    
/* Parameter: IntermecTagDistance */
      
t_llrp_item llrp_custparam_items_IntermecTagDistance[] = {
      
    { "Distance", LLRP_ITEM_FIELD, 0, 0, LLRP_FIELDTYPE_u16, 
      NULL },

};
      
t_llrp_compound_item llrp_custparam_Intermec_IntermecTagDistance = {
    "IntermecTagDistance", LLRP_ITEM_PARAMETER, 22, 1,
      llrp_custparam_items_IntermecTagDistance
};
    
/* ----------------------------------------------------------------------------- */
/* Custom Parameter List (36 total) */

t_llrp_custom_map_item llrp_llrp_Intermec_custom_parameter_list[] = {
    
    { 1963,
      0, &llrp_custparam_Intermec_IntermecAccessResult,
        
    },
    
    { 1963,
      1, &llrp_custparam_Intermec_IntermecCollectExtraTagSingulationDetails,
        
    },
    
    { 1963,
      2, &llrp_custparam_Intermec_IntermecTagReportData,
        
    },
    
    { 1963,
      3, &llrp_custparam_Intermec_IntermecEnableTagInZone,
        
    },
    
    { 1963,
      4, &llrp_custparam_Intermec_IntermecRNSI,
        
    },
    
    { 1963,
      5, &llrp_custparam_Intermec_IntermecEnableROSpecLoop,
        
    },
    
    { 1963,
      6, &llrp_custparam_Intermec_IntermecPhaseAngle,
        
    },
    
    { 1963,
      7, &llrp_custparam_Intermec_IntermecEnableABToggle,
        
    },
    
    { 1963,
      8, &llrp_custparam_Intermec_IntermecHighResolutionRSSI,
        
    },
    
    { 1963,
      9, &llrp_custparam_Intermec_IntermecTagInZone,
        
    },
    
    { 1963,
      10, &llrp_custparam_Intermec_IntermecEnableTagMoving,
        
    },
    
    { 1963,
      11, &llrp_custparam_Intermec_IntermecEnableTagNear,
        
    },
    
    { 1963,
      12, &llrp_custparam_Intermec_IntermecTagMoving,
        
    },
    
    { 1963,
      13, &llrp_custparam_Intermec_IntermecTagNear,
        
    },
    
    { 1963,
      14, &llrp_custparam_Intermec_IntermecEnableTagSpeed,
        
    },
    
    { 1963,
      15, &llrp_custparam_Intermec_IntermecTagSpeed,
        
    },
    
    { 1963,
      16, &llrp_custparam_Intermec_IntermecResetStartEvent,
        
    },
    
    { 1963,
      17, &llrp_custparam_Intermec_IntermecEnableLowLevelLogging,
        
    },
    
    { 1963,
      18, &llrp_custparam_Intermec_IntermecLowLevelLogEvent,
        
    },
    
    { 1963,
      19, &llrp_custparam_Intermec_IntermecResetCompleteEvent,
        
    },
    
    { 1963,
      20, &llrp_custparam_Intermec_IntermecEnableTagDistance,
        
    },
    
    { 1963,
      21, &llrp_custparam_Intermec_IntermecROSpecLoopEvent,
        
    },
    
    { 1963,
      22, &llrp_custparam_Intermec_IntermecTagDistance,
        
    },
    
    { 1963,
      23, &llrp_custparam_Intermec_IntermecNXPReadProtect,
        
    },
    
    { 1963,
      24, &llrp_custparam_Intermec_IntermecNXPEAS,
        
    },
    
    { 1963,
      25, &llrp_custparam_Intermec_IntermecNXPReadProtectOpSpecResult,
        
    },
    
    { 1963,
      26, &llrp_custparam_Intermec_IntermecNXPEASOpSpecResult,
        
    },
    
    { 1963,
      27, &llrp_custparam_Intermec_IntermecNXPEASAlarm,
        
    },
    
    { 1963,
      28, &llrp_custparam_Intermec_IntermecAISpecStopTrigger,
        
    },
    
    { 1963,
      29, &llrp_custparam_Intermec_IntermecNXPEASAlarmEndEvent,
        
    },
    
    { 1963,
      30, &llrp_custparam_Intermec_IntermecNXPEASAlarmResult,
        
    },
    
    { 1963,
      31, &llrp_custparam_Intermec_IntermecAISpecStopTriggerMinimumTries,
        
    },
    
    { 1963,
      32, &llrp_custparam_Intermec_IntermecAISpecStopTriggerMinimumTimeout,
        
    },
    
    { 1963,
      33, &llrp_custparam_Intermec_IntermecEnableReportCoalescence,
        
    },
    
    { 1963,
      34, &llrp_custparam_Intermec_IntermecTagInPortal,
        
    },
    
    { 1963,
      35, &llrp_custparam_Intermec_IntermecEnableTagInPortal,
        
    },
    
};
  
/* ----------------------------------------------------------------------------- */
/* Validator: llrp_Intermec */
t_llrp_parse_validator llrp_llrp_Intermec_parse_validator = {
    "llrp_Intermec",
    NULL, 0,
    llrp_llrp_Intermec_custom_parameter_list, 36,
    NULL, 0,
    NULL, 0,
};


/*end*/
