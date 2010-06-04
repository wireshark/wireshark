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

#ifndef _LLRP_GENERATED_llrp_Intermec_H
#define _LLRP_GENERATED_llrp_Intermec_H

#include "llrpparsetypes.h" 

#ifdef __cplusplus
extern "C" {
#endif

extern t_llrp_parse_validator llrp_llrp_Intermec_parse_validator;

#ifdef __cplusplus
}
#endif



/* ----------------------------------------------------------------------------- */
/* Custom Parameter Forward Declarations (36 total) */
    
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecResetStartEvent;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecResetCompleteEvent;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecLowLevelLogEvent;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecROSpecLoopEvent;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecNXPEASAlarmEndEvent;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecNXPEASAlarmResult;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecEnableROSpecLoop;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecEnableLowLevelLogging;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecNXPEASAlarm;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecAISpecStopTrigger;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecAISpecStopTriggerMinimumTries;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecAISpecStopTriggerMinimumTimeout;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecCollectExtraTagSingulationDetails;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecEnableABToggle;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecNXPReadProtect;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecNXPEAS;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecEnableReportCoalescence;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecNXPReadProtectOpSpecResult;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecNXPEASOpSpecResult;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecEnableTagInZone;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecEnableTagInPortal;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecEnableTagMoving;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecEnableTagNear;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecEnableTagSpeed;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecEnableTagDistance;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecTagReportData;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecAccessResult;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecRNSI;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecPhaseAngle;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecHighResolutionRSSI;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecTagInZone;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecTagInPortal;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecTagMoving;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecTagNear;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecTagSpeed;
extern t_llrp_compound_item llrp_custparam_Intermec_IntermecTagDistance;

/* Enumerations */
  
#define LLRP_ENUM_llrp_Intermec_IntermecEngineCodeEnumeration_Success  0
#define LLRP_ENUM_llrp_Intermec_IntermecEngineCodeEnumeration_Insufficient_Tag_Power  1
#define LLRP_ENUM_llrp_Intermec_IntermecEngineCodeEnumeration_NAK  3
#define LLRP_ENUM_llrp_Intermec_IntermecEngineCodeEnumeration_Read_Error  4
#define LLRP_ENUM_llrp_Intermec_IntermecEngineCodeEnumeration_Write_Error  5
#define LLRP_ENUM_llrp_Intermec_IntermecEngineCodeEnumeration_Lock_Error  7
#define LLRP_ENUM_llrp_Intermec_IntermecEngineCodeEnumeration_Unlock_Error  9
#define LLRP_ENUM_llrp_Intermec_IntermecEngineCodeEnumeration_Query_Lock_Error  10
#define LLRP_ENUM_llrp_Intermec_IntermecEngineCodeEnumeration_Kill_Error  12
#define LLRP_ENUM_llrp_Intermec_IntermecEngineCodeEnumeration_Illegal_Command  14
#define LLRP_ENUM_llrp_Intermec_IntermecEngineCodeEnumeration_Address_Range_Check_Error  15
#define LLRP_ENUM_llrp_Intermec_IntermecEngineCodeEnumeration_Nonspecific_Error  16
#define LLRP_ENUM_llrp_Intermec_IntermecEngineCodeEnumeration_Privilege_Error  17
#define LLRP_ENUM_llrp_Intermec_IntermecEngineCodeEnumeration_Memory_Lock_Error  18
#define LLRP_ENUM_llrp_Intermec_IntermecEngineCodeEnumeration_Blocked  19
#define LLRP_ENUM_llrp_Intermec_IntermecEngineCodeEnumeration_Duty_Cycle  20
#define LLRP_ENUM_llrp_Intermec_IntermecEngineCodeEnumeration_No_Response  22
#define LLRP_ENUM_llrp_Intermec_IntermecEngineCodeEnumeration_CRC_Error  23
#define LLRP_ENUM_llrp_Intermec_IntermecEngineCodeEnumeration_Collision  24
#define LLRP_ENUM_llrp_Intermec_IntermecEngineCodeEnumeration_Memory_Overrun_Error  25
#define LLRP_ENUM_llrp_Intermec_IntermecEngineCodeEnumeration_Erase_Error  26
#define LLRP_ENUM_llrp_Intermec_IntermecEngineCodeEnumeration_NXP_Alarm_Error  27
#define LLRP_ENUM_llrp_Intermec_IntermecNXPReadProtectResultType_Success  0
#define LLRP_ENUM_llrp_Intermec_IntermecNXPReadProtectResultType_Tag_Memory_Locked_Error  1
#define LLRP_ENUM_llrp_Intermec_IntermecNXPReadProtectResultType_Insufficient_Power  2
#define LLRP_ENUM_llrp_Intermec_IntermecNXPReadProtectResultType_Nonspecific_Tag_Error  3
#define LLRP_ENUM_llrp_Intermec_IntermecNXPReadProtectResultType_No_Response_From_Tag  4
#define LLRP_ENUM_llrp_Intermec_IntermecNXPReadProtectResultType_Nonspecific_Reader_Error  5
#define LLRP_ENUM_llrp_Intermec_IntermecNXPEASResultType_Success  0
#define LLRP_ENUM_llrp_Intermec_IntermecNXPEASResultType_Tag_Memory_Locked_Error  1
#define LLRP_ENUM_llrp_Intermec_IntermecNXPEASResultType_Insufficient_Power  2
#define LLRP_ENUM_llrp_Intermec_IntermecNXPEASResultType_Nonspecific_Tag_Error  3
#define LLRP_ENUM_llrp_Intermec_IntermecNXPEASResultType_No_Response_From_Tag  4
#define LLRP_ENUM_llrp_Intermec_IntermecNXPEASResultType_Nonspecific_Reader_Error  5

/* Parameters */
  

/* Custom Parameters */
  
#define LLRP_PARM_llrp_Intermec_IntermecAccessResult  0
#define LLRP_PARM_llrp_Intermec_IntermecCollectExtraTagSingulationDetails  1
#define LLRP_PARM_llrp_Intermec_IntermecTagReportData  2
#define LLRP_PARM_llrp_Intermec_IntermecEnableTagInZone  3
#define LLRP_PARM_llrp_Intermec_IntermecRNSI  4
#define LLRP_PARM_llrp_Intermec_IntermecEnableROSpecLoop  5
#define LLRP_PARM_llrp_Intermec_IntermecPhaseAngle  6
#define LLRP_PARM_llrp_Intermec_IntermecEnableABToggle  7
#define LLRP_PARM_llrp_Intermec_IntermecHighResolutionRSSI  8
#define LLRP_PARM_llrp_Intermec_IntermecTagInZone  9
#define LLRP_PARM_llrp_Intermec_IntermecEnableTagMoving  10
#define LLRP_PARM_llrp_Intermec_IntermecEnableTagNear  11
#define LLRP_PARM_llrp_Intermec_IntermecTagMoving  12
#define LLRP_PARM_llrp_Intermec_IntermecTagNear  13
#define LLRP_PARM_llrp_Intermec_IntermecEnableTagSpeed  14
#define LLRP_PARM_llrp_Intermec_IntermecTagSpeed  15
#define LLRP_PARM_llrp_Intermec_IntermecResetStartEvent  16
#define LLRP_PARM_llrp_Intermec_IntermecEnableLowLevelLogging  17
#define LLRP_PARM_llrp_Intermec_IntermecLowLevelLogEvent  18
#define LLRP_PARM_llrp_Intermec_IntermecResetCompleteEvent  19
#define LLRP_PARM_llrp_Intermec_IntermecEnableTagDistance  20
#define LLRP_PARM_llrp_Intermec_IntermecROSpecLoopEvent  21
#define LLRP_PARM_llrp_Intermec_IntermecTagDistance  22
#define LLRP_PARM_llrp_Intermec_IntermecNXPReadProtect  23
#define LLRP_PARM_llrp_Intermec_IntermecNXPEAS  24
#define LLRP_PARM_llrp_Intermec_IntermecNXPReadProtectOpSpecResult  25
#define LLRP_PARM_llrp_Intermec_IntermecNXPEASOpSpecResult  26
#define LLRP_PARM_llrp_Intermec_IntermecNXPEASAlarm  27
#define LLRP_PARM_llrp_Intermec_IntermecAISpecStopTrigger  28
#define LLRP_PARM_llrp_Intermec_IntermecNXPEASAlarmEndEvent  29
#define LLRP_PARM_llrp_Intermec_IntermecNXPEASAlarmResult  30
#define LLRP_PARM_llrp_Intermec_IntermecAISpecStopTriggerMinimumTries  31
#define LLRP_PARM_llrp_Intermec_IntermecAISpecStopTriggerMinimumTimeout  32
#define LLRP_PARM_llrp_Intermec_IntermecEnableReportCoalescence  33
#define LLRP_PARM_llrp_Intermec_IntermecTagInPortal  34
#define LLRP_PARM_llrp_Intermec_IntermecEnableTagInPortal  35

/* Messages */
  

/* Custom Messages */
  

#endif /* _LLRP_GENERATED_llrp_Intermec_H */

