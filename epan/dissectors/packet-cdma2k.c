/*
 * packet-cdma2k.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref CDMA2K: 3GPP2 C.S0005-E v3.0
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

void proto_reg_handoff_cdma2k(void);
void proto_register_cdma2k(void);

/* cdma2k Handle for the dissection */
static dissector_handle_t cdma2k_handle;

/* Function handlers for each message/information fields */
static void cdma2k_message_decode(proto_item *item,tvbuff_t *tvb, proto_tree *tree, guint *offset, proto_tree *mainTree, guint16 *noerror, packet_info *pinfo);
static void cdma2k_message_REGISTRATION(proto_item *item,  tvbuff_t *tvb,  proto_tree *tree,  guint *offset,  guint16 oneXPrev);
static void cdma2k_message_ORDER_IND(proto_item *item, tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void cdma2k_message_DATA_BURST_IND(proto_item *item, tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void cdma2k_message_ORIGINATION(proto_item *item, tvbuff_t *tvb, proto_tree *tree, guint *offset, guint16 authIncl, guint16 oneXPrev);
static void cdma2k_message_PAGE_RESPONSE(proto_item *item, tvbuff_t *tvb, proto_tree *tree, guint *offset, guint16 authIncl, guint16 oneXPrev);
static void cdma2k_message_AUTH_CHALL_RSP(proto_item *item, tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void cdma2k_message_ORDER_CMD(proto_item *item, tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void cdma2k_message_DATA_BURST_CMD(proto_item *item, tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void cdma2k_message_AUTH_CHALL_REQ(proto_item *item, tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void cdma2k_message_GEN_PAGE_REQ(proto_item *item, tvbuff_t *tvb, proto_tree *tree, guint *offset, guint16 l3PduLen);

static void cdma2k_message_ADDR_FIELDS(proto_item *item, tvbuff_t *tvb, proto_tree *tree, guint16 *l_offset,  guint16 headerRecLen);
static void cdma2k_message_AUTH_FIELDS(proto_item *item, tvbuff_t *tvb, proto_tree *tree, guint16 *l_offset,  guint16 headerRecLen);
static void cdma2k_message_IMSI_CLASS_SUBFIELDS(proto_item *item, tvbuff_t *tvb, proto_tree *tree, guint16 *l_offset);
static void cdma2k_message_ALERT_WITH_INFO(proto_item *item,tvbuff_t *tvb,proto_tree *tree,guint *offset);
static void cdma2k_message_HANDOFF_DIR(proto_item *item,tvbuff_t *tvb,proto_tree *tree,guint *offset, guint16 msgType);
static void cdma2k_message_ACTIVE_SET_RECORD_FIELDS(proto_item *item,tvbuff_t *tvb,proto_tree *subtree,guint16 *l_offset, guint16 chInd,guint16 schIncl);


/*Initialize all the header parameters that are to be displayed*/

int proto_cdma2k = -1;
static int hf_cdma2k_msghdr = -1;

/* Tlac Parameters */
static int hf_cdma2k_tlac_Record = -1;
static int hf_cdma2k_tlac_Header = -1;
static int hf_cdma2k_tlac_Channel = -1;
static int hf_cdma2k_tlac_1x_Protocol_Revision = -1;
static int hf_cdma2k_tlac_msgType = -1;
static int hf_cdma2k_tlac_Header_Record = -1;
static int hf_cdma2k_tlac_Header_Records_Count = -1;
static int hf_cdma2k_tlac_Header_Record_Type = -1;
static int hf_cdma2k_tlac_Header_Record_Length = -1;
static int hf_cdma2k_tlac_Header_Record_Values = -1;
static int hf_cdma2k_tlac_Header_Record_Reserved = -1;
static int hf_cdma2k_tlac_Pdu = -1;
static int hf_cdma2k_tlac_Pdu_Length = -1;

/* Addressing Fileds */
static int hf_cdma2k_tlac_Header_Record_MsId_Type = -1;
static int hf_cdma2k_tlac_Header_Record_Ext_MsId_Type = -1;
static int hf_cdma2k_tlac_Header_Record_MsId_Length = -1;
static int hf_cdma2k_tlac_Header_Record_Imsi_M_S1 = -1;
static int hf_cdma2k_tlac_Header_Record_Imsi_M_S1_sec_3_dig = -1;
static int hf_cdma2k_tlac_Header_Record_Imsi_M_S1_thousand_dig = -1;
static int hf_cdma2k_tlac_Header_Record_Imsi_M_S1_last_3_dig = -1;
static int hf_cdma2k_tlac_Header_Record_Imsi_M_S2 = -1;
static int hf_cdma2k_tlac_Header_Record_Esn = -1;
static int hf_cdma2k_tlac_Header_Record_Imsi_Class = -1;
static int hf_cdma2k_tlac_Header_Record_Imsi_Class0_Type = -1;
static int hf_cdma2k_tlac_Header_Record_Imsi_Class1_Type = -1;
static int hf_cdma2k_tlac_Header_Record_Imsi_S2 = -1;
static int hf_cdma2k_tlac_Header_Record_Imsi_S1 = -1;
static int hf_cdma2k_tlac_Header_Record_Imsi_11_12 = -1;
static int hf_cdma2k_tlac_Header_Record_MCC = -1;
static int hf_cdma2k_tlac_Header_Record_Imsi_Addr_Num = -1;
static int hf_cdma2k_tlac_Header_Record_Ext_MsId_MeId = -1;
static int hf_cdma2k_tlac_Header_Record_Tmsi_Code_Addr = -1;
static int hf_cdma2k_tlac_Header_Record_Tmsi_Zone = -1;

/* Authentication Fields */
static int hf_cdma2k_tlac_Header_Record_Mac_Incl = -1;
static int hf_cdma2k_tlac_Header_Record_Auth_Incl = -1;
static int hf_cdma2k_tlac_Header_Record_Authr = -1;
static int hf_cdma2k_tlac_Header_Record_Randc = -1;
static int hf_cdma2k_tlac_Header_Record_Count = -1;
static int hf_cdma2k_tlac_Header_Record_Sdu_KeyId = -1;
static int hf_cdma2k_tlac_Header_Record_Sdu_Algo = -1;
static int hf_cdma2k_tlac_Header_Record_Sdu_Sseq = -1;
static int hf_cdma2k_tlac_Header_Record_Sdu_Sseqh = -1;
static int hf_cdma2k_tlac_Header_Record_Sdu_Sseq_Or_Sseqh = -1;

/* Msg Types */
static int hf_cdma2k_RegMsg = -1;
static int hf_cdma2k_OrderIndMsg = -1;
static int hf_cdma2k_DataBurstIndMsg = -1;
static int hf_cdma2k_OrigMsg = -1;
static int hf_cdma2k_PageRspMsg = -1;
static int hf_cdma2k_AuthChallRspMsg = -1;
static int hf_cdma2k_DataBurstCmdMsg = -1;
static int hf_cdma2k_AuthChallReqMsg = -1;
static int hf_cdma2k_GenPageReqMsg = -1;
static int hf_cdma2k_AlertWithInfoMsg = -1;
static int hf_cdma2k_UhdmMsg = -1;
static int hf_cdma2k_MeIdUhdmMsg = -1;
static int hf_cdma2k_ext_scm_ind = -1;

/* Registration Msg Parms */
static int hf_cdma2k_Reg_Type = -1;
static int hf_cdma2k_Slot_Cycle_Index = -1;
static int hf_cdma2k_Mob_P_Rev = -1;
static int hf_cdma2k_Ext_Scm = -1;
static int hf_cdma2k_Sloted_Mode = -1;
static int hf_cdma2k_Mob_Term = -1;
static int hf_cdma2k_Return_Cause = -1;
static int hf_cdma2k_Qpch_Supported = -1;
static int hf_cdma2k_Enhanced_Rc = -1;
static int hf_cdma2k_Uzid_Incl = -1;
static int hf_cdma2k_Uzid = -1;
static int hf_cdma2k_GeoLoc_Incl = -1;
static int hf_cdma2k_GeoLoc_Type = -1;

/* Order Ind Msg Parms */
static int hf_cdma2k_Order_Ind = -1;
static int hf_cdma2k_Randbs = -1;
static int hf_cdma2k_Rejected_Type = -1;
static int hf_cdma2k_Rejected_Order = -1;
static int hf_cdma2k_Rejected_Ordq = -1;
static int hf_cdma2k_Rejected_Parm_Id = -1;
static int hf_cdma2k_Rejected_Record = -1;
static int hf_cdma2k_Tag = -1;

static int hf_cdma2k_Rsc_Mode_Ind = -1;
static int hf_cdma2k_Rsci = -1;
static int hf_cdma2k_Rsc_End_Time_Unit = -1;
static int hf_cdma2k_Rsc_End_Time_Value = -1;

/* Order Cmd Msg Parms */
static int hf_cdma2k_Order_Cmd = -1;
static int hf_cdma2k_Authbs = -1;
static int hf_cdma2k_Roam_Ind = -1;
static int hf_cdma2k_C_Sig_Encrypt_Mode = -1;
static int hf_cdma2k_Enc_Key_Size = -1;
static int hf_cdma2k_Msg_Int_Info_Incl = -1;
static int hf_cdma2k_Change_Keys = -1;
static int hf_cdma2k_Use_Uak = -1;

static int hf_cdma2k_Retry_Type = -1;
static int hf_cdma2k_Retry_Delay = -1;
static int hf_cdma2k_Reject_Reason = -1;
static int hf_cdma2k_Rejected_Msg_Type = -1;
static int hf_cdma2k_Rejected_Msg_Seq = -1;

/* BCMC Order type */
static int hf_cdma2k_All_Bcmc_Flows_Ind = -1;
static int hf_cdma2k_Clear_All_Retry_Delay = -1;
static int hf_cdma2k_All_Bcmc_Reason = -1;
static int hf_cdma2k_All_Bcmc_Retry_Delay = -1;
static int hf_cdma2k_Num_Bcmc_Programs = -1;
static int hf_cdma2k_Bcmc_Program_Id_Len = -1;
static int hf_cdma2k_Bcmc_Program_Id = -1;
static int hf_cdma2k_Bcmc_Flow_Discriminator_Len = -1;
static int hf_cdma2k_Num_Flow_Discriminator = -1;
static int hf_cdma2k_Bcmc_Flow_Discriminator = -1;
static int hf_cdma2k_Same_As_Previous_Bcmc_Flow = -1;
static int hf_cdma2k_Bcmc_Reason = -1;
static int hf_cdma2k_Bcmc_Retry_Delay = -1;

static int hf_cdma2k_Rsc_Mode_Supported = -1;
static int hf_cdma2k_Max_Rsc_End_Time_Unit = -1;
static int hf_cdma2k_Max_Rsc_End_Time_Value = -1;
static int hf_cdma2k_Req_Rsci = -1;
static int hf_cdma2k_Ignore_Qpch = -1;
static int hf_cdma2k_Rer_Mode_Incl = -1;
static int hf_cdma2k_Rer_Mode_Enabled = -1;
static int hf_cdma2k_Rer_Max_Num_Msg_Idx = -1;
static int hf_cdma2k_Rer_Time = -1;
static int hf_cdma2k_Rer_Time_Unit = -1;
static int hf_cdma2k_Max_Rer_Pilot_List_Size = -1;
static int hf_cdma2k_Tkz_Mode_Incl = -1;
static int hf_cdma2k_Tkz_Mode_Enabled = -1;
static int hf_cdma2k_Tkz_Max_Num_Msg_Idx = -1;
static int hf_cdma2k_Tkz_Update_Prd = -1;
static int hf_cdma2k_Tkz_List_Len = -1;
static int hf_cdma2k_Tkz_Timer = -1;

/* Service Status Order */
static int hf_cdma2k_Sr_Id_Bitmap = -1;
static int hf_cdma2k_Service_Status = -1;

/* Location Service Order */
static int hf_cdma2k_Regulatory_Ind_Incl = -1;
static int hf_cdma2k_Regulatory_Ind = -1;
/* Order Msg Parms */
static int hf_cdma2k_Add_Record_Len = -1;
static int hf_cdma2k_Order_Specific_Fields = -1;
static int hf_cdma2k_Ordq = -1;
static int hf_cdma2k_Con_Ref = -1;

/* Data Burst Msg Parms */
static int hf_cdma2k_Msg_Number = -1;
static int hf_cdma2k_Burst_Type = -1;
static int hf_cdma2k_Num_Msgs = -1;
static int hf_cdma2k_Num_Fields = -1;
static int hf_cdma2k_Chari_Data = -1;
static int hf_cdma2k_Msg_Identifier = -1;
static int hf_cdma2k_Parm_Id = -1;
static int hf_cdma2k_Parm_Length = -1;
static int hf_cdma2k_Parm_Value = -1;

/* Origination and Page Response Msg Parms */
static int hf_cdma2k_Request_Mode = -1;
static int hf_cdma2k_Special_Service = -1;
static int hf_cdma2k_pm = -1;
static int hf_cdma2k_digit_mode = -1;
static int hf_cdma2k_More_Fields = -1;
static int hf_cdma2k_Nar_An_Cap = -1;
static int hf_cdma2k_Paca_Reorig = -1;
static int hf_cdma2k_More_Records = -1;
static int hf_cdma2k_encryption_supported = -1;
static int hf_cdma2k_Paca_Supported = -1;
static int hf_cdma2k_num_alt_so = -1;
static int hf_cdma2k_DRS = -1;
static int hf_cdma2k_SR_ID = -1;
static int hf_cdma2k_Otd_Supported = -1;
static int hf_cdma2k_For_Rc_Pref = -1;
static int hf_cdma2k_Rev_Rc_Pref = -1;
static int hf_cdma2k_Fch_Supported = -1;
static int hf_cdma2k_Fch_capability_type_specific_Fields = -1;
static int hf_cdma2k_Fch_Frame_Size = -1;
static int hf_cdma2k_For_Fch_Len = -1;
static int hf_cdma2k_For_Fch_Rc_Map = -1;
static int hf_cdma2k_Rev_Fch_Len = -1;
static int hf_cdma2k_Rev_Fch_Rc_Map = -1;
static int hf_cdma2k_Dcch_capability_type_specific_Fields = -1;
static int hf_cdma2k_Dcch_Frame_Size = -1;
static int hf_cdma2k_For_Dcch_Len = -1;
static int hf_cdma2k_For_Dcch_Rc_Map = -1;
static int hf_cdma2k_Rev_Dcch_Len = -1;
static int hf_cdma2k_Rev_Dcch_Rc_Map = -1;
static int hf_cdma2k_Rev_Fch_Gating_Req = -1;
static int hf_cdma2k_Orig_Reason = -1;
static int hf_cdma2k_Orig_Count = -1;
static int hf_cdma2k_Sts_Supported = -1;
static int hf_cdma2k_ThreeXCchSupported = -1;
static int hf_cdma2k_Wll_Incl = -1;
static int hf_cdma2k_Wll_Device_Type = -1;
static int hf_cdma2k_Global_Emergency_Call = -1;
static int hf_cdma2k_Ms_Init_Pos_Loc_Ind = -1;
static int hf_cdma2k_Qos_Parms_Incl = -1;
static int hf_cdma2k_Qos_Parms_Length = -1;
static int hf_cdma2k_Qos_Parms = -1;
static int hf_cdma2k_Enc_Info_Incl = -1;
static int hf_cdma2k_Sig_Encrypt_Supp = -1;
static int hf_cdma2k_DSig_Encrypt_Req = -1;
static int hf_cdma2k_CSig_Encrypt_Req = -1;
static int hf_cdma2k_New_Sseq_H = -1;
static int hf_cdma2k_New_Sseq_H_Sig = -1;
static int hf_cdma2k_Ui_Encrypt_Req = -1;
static int hf_cdma2k_Prev_Sid_Incl = -1;
static int hf_cdma2k_Prev_Sid = -1;
static int hf_cdma2k_Prev_Nid_Incl = -1;
static int hf_cdma2k_Prev_Nid = -1;
static int hf_cdma2k_Prev_Pzid_Incl = -1;
static int hf_cdma2k_Prev_Pzid = -1;
static int hf_cdma2k_So_Bitmap_Ind = -1;
static int hf_cdma2k_So_Group_Num = -1;
static int hf_cdma2k_So_Bitmap = -1;
static int hf_cdma2k_Alt_So = -1;
static int hf_cdma2k_Dcch_Supported = -1;
static int hf_cdma2k_Hook_Status = -1;

/* Auth Chall Rsp Msg Parms */
static int hf_cdma2k_Authu = -1;

/* Auth Chall Req Msg Parms */
static int hf_cdma2k_Randu = -1;
static int hf_cdma2k_Gen_Cmea_Key = -1;

/* Gen Page Req Msg Parms */
static int hf_cdma2k_service_option = -1;

/* Handoff Dir Msg Parms */
static int hf_cdma2k_Use_Time = -1;
static int hf_cdma2k_Action_Time = -1;
static int hf_cdma2k_Hdm_Seq = -1;
static int hf_cdma2k_Parms_Incl = -1;
static int hf_cdma2k_P_Rev = -1;
static int hf_cdma2k_Serv_Neg_Type = -1;
static int hf_cdma2k_Search_Incl = -1;
static int hf_cdma2k_Pilot_Search = -1;
static int hf_cdma2k_Srch_Win_A = -1;
static int hf_cdma2k_Srch_Win_N = -1;
static int hf_cdma2k_Srch_Win_R = -1;
static int hf_cdma2k_T_Add = -1;
static int hf_cdma2k_T_Drop = -1;
static int hf_cdma2k_T_Comp = -1;
static int hf_cdma2k_T_Tdrop = -1;
static int hf_cdma2k_Soft_Slope = -1;
static int hf_cdma2k_Add_Intercept = -1;
static int hf_cdma2k_Drop_Intercept = -1;
static int hf_cdma2k_Extra_Parms_Incl = -1;
static int hf_cdma2k_Extra_Parms = -1;
static int hf_cdma2k_Packet_Zone_Id = -1;
static int hf_cdma2k_Frame_Offset = -1;
static int hf_cdma2k_Private_Lcm = -1;
static int hf_cdma2k_Reset_L2 = -1;
static int hf_cdma2k_Reset_Fpc = -1;
static int hf_cdma2k_Encrypt_Mode = -1;
static int hf_cdma2k_Nom_Pwr_Ext = -1;
static int hf_cdma2k_Nom_Pwr = -1;
static int hf_cdma2k_Rlgain_Traffic_Pilot = -1;
static int hf_cdma2k_Default_Rlag = -1;
static int hf_cdma2k_Num_Preamble = -1;
static int hf_cdma2k_Band_Class = -1;
static int hf_cdma2k_Cdma_Freq = -1;
static int hf_cdma2k_Return_If_Handoff_Fail = -1;
static int hf_cdma2k_Complete_Search = -1;
static int hf_cdma2k_Periodic_Search = -1;
static int hf_cdma2k_Scr_Incl = -1;
static int hf_cdma2k_Scr = -1;
static int hf_cdma2k_Serv_Con_Seq = -1;
static int hf_cdma2k_Record_Type = -1;
static int hf_cdma2k_Record_Len = -1;
static int hf_cdma2k_Type_Specific_Fields = -1;
static int hf_cdma2k_Nnscr_Incl = -1;
static int hf_cdma2k_Nnscr = -1;
static int hf_cdma2k_Use_Pwr_Cntl_Step = -1;
static int hf_cdma2k_Pwr_Cntl_Step = -1;
static int hf_cdma2k_Clear_Retry_Delay = -1;
static int hf_cdma2k_Sch_Incl = -1;
static int hf_cdma2k_Sch = -1;
static int hf_cdma2k_Num_For_Assign = -1;
static int hf_cdma2k_Record_For_Assign = -1;
static int hf_cdma2k_Sch_Id = -1;
static int hf_cdma2k_Sch_Duration = -1;
static int hf_cdma2k_Sch_Start_Time_Incl = -1;
static int hf_cdma2k_Sch_Start_Time = -1;
static int hf_cdma2k_Sccl_Index = -1;
static int hf_cdma2k_Num_Rev_Assign = -1;
static int hf_cdma2k_Record_Rev_Assign = -1;
static int hf_cdma2k_Sch_Num_Bits_Idx = -1;
static int hf_cdma2k_Fpc_Subchain_Gain = -1;
static int hf_cdma2k_Use_Pc_Time = -1;
static int hf_cdma2k_Pc_Action_Time = -1;
static int hf_cdma2k_Ch_Ind = -1;
static int hf_cdma2k_Active_Set_Rec_Len = -1;
static int hf_cdma2k_Active_Set_Rec_Fields = -1;
static int hf_cdma2k_Rev_Fch_Gating_Mode = -1;
static int hf_cdma2k_Rev_Pwr_Cntl_Delay_Incl = -1;
static int hf_cdma2k_Rev_Pwr_Cntl_Delay = -1;
static int hf_cdma2k_D_Sig_Encrypt_Mode = -1;
static int hf_cdma2k_3xfl_1xrl_Incl = -1;
static int hf_cdma2k_1xrl_Freq_Offset = -1;
static int hf_cdma2k_Sync_Id_Incl = -1;
static int hf_cdma2k_Sync_Id_Len = -1;
static int hf_cdma2k_Sync_Id = -1;
static int hf_cdma2k_Cc_Info_Incl = -1;
static int hf_cdma2k_Num_Calls_Assign = -1;
static int hf_cdma2k_Record_Calls_Assign = -1;
static int hf_cdma2k_Response_Ind = -1;
static int hf_cdma2k_Bypass_Alert_Answer = -1;
static int hf_cdma2k_Cs_Supported = -1;
static int hf_cdma2k_Chm_Supported = -1;
static int hf_cdma2k_Cdma_Off_Time_Rep_Sup_Ind = -1;
static int hf_cdma2k_Cdma_Off_Time_Rep_Threshold_Unit = -1;
static int hf_cdma2k_Cdma_Off_Time_Rep_Threshold = -1;
static int hf_cdma2k_Release_To_Idle_Ind = -1;
static int hf_cdma2k_Msg_Integrity_Sup = -1;
static int hf_cdma2k_Gen_2g_Key = -1;
static int hf_cdma2k_Register_In_Idle = -1;
static int hf_cdma2k_Plcm_Type_Incl = -1;
static int hf_cdma2k_Plcm_Type = -1;
static int hf_cdma2k_Plcm_39 = -1;
static int hf_cdma2k_T_Tdrop_Range_Incl = -1;
static int hf_cdma2k_T_Tdrop_Range = -1;
static int hf_cdma2k_For_Pdch_Supported = -1;
static int hf_cdma2k_Pdch_Chm_Supported = -1;
static int hf_cdma2k_Pilot_Info_Req_Supported = -1;
static int hf_cdma2k_Enc_Supported = -1;
static int hf_cdma2k_Sig_Encrypt_Sup = -1;
static int hf_cdma2k_Ui_Encrypt_Sup = -1;
static int hf_cdma2k_Use_Sync_Id = -1;
static int hf_cdma2k_Sid_Incl = -1;
static int hf_cdma2k_Sid = -1;
static int hf_cdma2k_Nid_Incl = -1;
static int hf_cdma2k_Nid = -1;
static int hf_cdma2k_Sdb_Supported = -1;
static int hf_cdma2k_Mob_Qos = -1;
static int hf_cdma2k_Ms_Init_Pos_Loc_Sup_Ind = -1;
static int hf_cdma2k_Rev_Pdch_Supported = -1;
static int hf_cdma2k_Pz_Hyst_Enabled = -1;
static int hf_cdma2k_Pz_Hyst_Info_Incl = -1;
static int hf_cdma2k_Pz_Hyst_List_Len = -1;
static int hf_cdma2k_Pz_Hyst_Act_Timer = -1;
static int hf_cdma2k_Pz_Hyst_Timer_Mul = -1;
static int hf_cdma2k_Pz_Hyst_Timer_Exp = -1;
static int hf_cdma2k_Bcmc_On_Traffic_Sup = -1;
static int hf_cdma2k_Auto_Re_Traffic_Allowed_Ind = -1;
static int hf_cdma2k_Sch_Bcmc_Ind = -1;
static int hf_cdma2k_Add_Plcm_For_Sch_Incl = -1;
static int hf_cdma2k_Add_Plcm_For_Sch_Type = -1;
static int hf_cdma2k_Add_Plcm_For_Sch_35 = -1;
static int hf_cdma2k_Record_Sch_Bcmc = -1;
static int hf_cdma2k_Use_Add_Plcm_For_Sch = -1;
static int hf_cdma2k_Fsch_Outercode_Incl = -1;
static int hf_cdma2k_Fsch_Outercode_Rate = -1;
static int hf_cdma2k_Fsch_Outercode_Offset = -1;
static int hf_cdma2k_Max_Add_Serv_Instance = -1;
static int hf_cdma2k_Use_Ch_Cfg_Rrm = -1;
static int hf_cdma2k_Tx_Pwr_Limit_Incl = -1;
static int hf_cdma2k_Tx_Pwr_Limit_Default = -1;
static int hf_cdma2k_Tx_Pwr_Limit = -1;

/* Active Set Record Fields of Handoff Direction Message*/
static int hf_cdma2k_Num_For_Sch = -1;
static int hf_cdma2k_Record_For_Sch = -1;
static int hf_cdma2k_Num_Rev_Sch = -1;
static int hf_cdma2k_Record_Rev_Sch = -1;
static int hf_cdma2k_Walsh_Id = -1;
static int hf_cdma2k_Num_Pilots = -1;
static int hf_cdma2k_Srch_Offset_Incl = -1;
static int hf_cdma2k_Record_Pilots = -1;
static int hf_cdma2k_Pilot_Pn = -1;
static int hf_cdma2k_Srch_Offset = -1;
static int hf_cdma2k_Add_Pilot_Rec_Incl = -1;
static int hf_cdma2k_Pilot_Rec_Type = -1;
static int hf_cdma2k_Pwr_Comb_Ind = -1;
static int hf_cdma2k_Code_Chan_Fch = -1;
static int hf_cdma2k_Qof_Mask_Id_Fch = -1;
static int hf_cdma2k_Num_Sch = -1;
static int hf_cdma2k_Record_Sch = -1;
static int hf_cdma2k_Pilot_Incl = -1;
static int hf_cdma2k_Code_Chan_Sch = -1;
static int hf_cdma2k_Qof_Mask_Id_Sch = -1;
static int hf_cdma2k_3xFch_Info_Incl = -1;
static int hf_cdma2k_3xFch_Low_Incl = -1;
static int hf_cdma2k_Qof_Mask_Id_Fch_Low = -1;
static int hf_cdma2k_Code_Chan_Fch_Low = -1;
static int hf_cdma2k_3xFch_High_Incl = -1;
static int hf_cdma2k_Qof_Mask_Id_Fch_High = -1;
static int hf_cdma2k_Code_Chan_Fch_High = -1;
static int hf_cdma2k_3xSch_Info_Incl = -1;
static int hf_cdma2k_3xSch_Low_Incl = -1;
static int hf_cdma2k_Qof_Mask_Id_Sch_Low = -1;
static int hf_cdma2k_Code_Chan_Sch_Low = -1;
static int hf_cdma2k_3xSch_High_Incl = -1;
static int hf_cdma2k_Qof_Mask_Id_Sch_High = -1;
static int hf_cdma2k_Code_Chan_Sch_High = -1;
static int hf_cdma2k_Ccsh_Included = -1;
static int hf_cdma2k_Use_Ccsh_Encoder_Time = -1;
static int hf_cdma2k_Ccsh_Encoder_Action_Time = -1;
static int hf_cdma2k_Ccsh_Encoder_Type = -1;
static int hf_cdma2k_Code_Chan_Dcch = -1;
static int hf_cdma2k_Qof_Mask_Id_Dcch = -1;
static int hf_cdma2k_3xDcch_Info_Incl = -1;
static int hf_cdma2k_3xDcch_Low_Incl = -1;
static int hf_cdma2k_Qof_Mask_Id_Dcch_Low = -1;
static int hf_cdma2k_Code_Chan_Dcch_Low = -1;
static int hf_cdma2k_3xDcch_High_Incl = -1;
static int hf_cdma2k_Qof_Mask_Id_Dcch_High = -1;
static int hf_cdma2k_Code_Chan_Dcch_High = -1;
static int hf_cdma2k_Fundicated_Bcmc_Ind = -1;
static int hf_cdma2k_For_Cpcch_Walsh = -1;
static int hf_cdma2k_For_Cpcsch = -1;
static int hf_cdma2k_Rev_Fch_Assigned = -1;
static int hf_cdma2k_Add_Plcm_For_Fch_Incl = -1;
static int hf_cdma2k_Add_Plcm_For_Fch_Type = -1;
static int hf_cdma2k_Add_Plcm_For_Fch_39 = -1;
static int hf_cdma2k_For_Cpcch_Info_Incl = -1;

/* Alert With Info Msg Parms */

static int hf_cdma2k_Info_Rec = -1;
static int hf_cdma2k_Chari = -1;
static int hf_cdma2k_Number_Type = -1;
static int hf_cdma2k_Number_Plan = -1;
static int hf_cdma2k_Pres_Indicator = -1;
static int hf_cdma2k_Scr_Indicator = -1;
static int hf_cdma2k_Signal_Type = -1;
static int hf_cdma2k_Alert_Pitch = -1;
static int hf_cdma2k_Signal = -1;
static int hf_cdma2k_Msg_Count = -1;
static int hf_cdma2k_Extension_Bit = -1;
static int hf_cdma2k_Subaddress_Type = -1;
static int hf_cdma2k_Odd_Even_Ind = -1;
static int hf_cdma2k_Redirection_Reason = -1;
static int hf_cdma2k_Pulse_Freq = -1;
static int hf_cdma2k_Pulse_On_Time = -1;
static int hf_cdma2k_Pulse_Off_Time = -1;
static int hf_cdma2k_Pulse_Count = -1;
static int hf_cdma2k_Cadence_Count = -1;
static int hf_cdma2k_Num_Grps = -1;
static int hf_cdma2k_Amplitude = -1;
static int hf_cdma2k_Freq = -1;
static int hf_cdma2k_On_Time = -1;
static int hf_cdma2k_Off_Time = -1;
static int hf_cdma2k_Repeat = -1;
static int hf_cdma2k_Delay = -1;
static int hf_cdma2k_Cadence_Type = -1;
static int hf_cdma2k_Polarity_Incl = -1;
static int hf_cdma2k_Toggle_Mode = -1;
static int hf_cdma2k_Reverse_Polarity = -1;
static int hf_cdma2k_Pwr_Denial_Time = -1;
static int hf_cdma2k_Call_Waiting_Ind = -1;

static int hf_cdma2k_Reserved = -1;

static int hf_cdma2k_Cmea = -1;
static int hf_cdma2k_Ecmea = -1;
static int hf_cdma2k_Rea = -1;

static int hf_cdma2k_scm_dual_mode = -1;
static int hf_cdma2k_scm_slotted_class = -1;
static int hf_cdma2k_scm_meid_sup = -1;
static int hf_cdma2k_scm_25mhz_bw = -1;
static int hf_cdma2k_scm_trans = -1;
static int hf_cdma2k_scm_pow_class = -1;

static expert_field ei_cdma2k_error = EI_INIT;

/* Toggle sub-tree items */
static gint ett_cdma2k_msghdr = -1;
static gint ett_cdma2k_subtree = -1;
static gint ett_cdma2k_subtree1 = -1;
static gint ett_cdma2k_subtree2 = -1;
static guint ett_cdma2k_m_s1 = -1;
static guint ett_cdma2000_scm = -1;

#define CDMA2KRegIndMsg       0x01
#define CDMA2KOrderIndMsg     0x02
#define CDMA2KDataBurstIndMsg 0x03
#define CDMA2KOrigIndMsg      0x04
#define CDMA2KPageResponseMsg 0x05
#define CDMA2KAuthChallRspMsg 0x06
#define CDMA2KOrderCmdMsg     0x07
#define CDMA2KDataBurstCmdMsg 0x09
#define CDMA2KAuthChallReqMsg 0x0A
#define CDMA2KGenPageReqMsg   0x11

#define CDMA2KAlertWithInfoMsg                   0x03
#define CDMA2KUniversalHandoffDirectionMsg       0x22
#define CDMA2KMeIdUniversalHandoffDirectionMsg   0x35

/* CDMA2K Msg Types */
static const value_string Cdma2k_Message_types[] = {
    { 0x01, "CDMA2KRegIndMsg" },
    { 0x02, "CDMA2KOrderIndMsg"},
    { 0x03, "CDMA2KDataBurstIndMsg"},
    { 0x04, "CDMA2KOrigIndMsg"},
    { 0x05, "CDMA2KPageResponseMsg"},
    { 0x06, "CDMA2KAuthChallRspMsg"},
    { 0x07, "CDMA2KOrderCmdMsg"},
    { 0x09, "CDMA2KDataBurstCmdMsg"},
    { 0x0A, "CDMA2KAuthChallReqMsg"},
    { 0x11, "CDMA2KGenPageReqMsg"},
    { 0, NULL },
};

#if 0
Currently not used ??
/* CDMA2K Msg Types specific to dedicated channel*/
static const value_string Cdma2k_Dcsh_Message_types[] = {
    { 0x03, "CDMA2KAlertWithInfoMsg" },
    { 0x22, "CDMA2KUniversalHandoffDirectionMsg"},
    { 0x35, "CDMA2KMeIdUniversalHandoffDirectionMsg"},
    { 0, NULL },
};
#endif

/* TLAC Channel Types */
static const value_string Channel_Types[] = {
    { 0, "CSCH_LOGICAL_CHANNEL" },
    { 1, "DSCH_LOGICAL_CHANNEL" },
    { 0, NULL },
};


/* TLAC Header Record Types */
static const value_string Header_Record_Types[] = {
    { 0, "ADDRESSING_SUBLAYER_RECORD_TYPE" },
    { 1, "AUTH_INTEGRITY_SUBLAYER_RECORD_TYPE" },
    { 0, NULL },
};


/* MsId Types */
static const value_string MsId_Address_Types[] = {
    { 0, "IMSI_S_ESN_MSID" },
    { 1, "ESN_MSID" },
    { 2, "IMSI_MSID" },
    { 3, "IMSI_ESN_MSID" },
    { 4, "EXTENDED_MSID" },
    { 5, "TMSI_MSID" },
    { 6, "MAX_MSID_ADD" },
    { 0, NULL },
};


/* Extended MsId Types */
static const value_string Ext_MsId_Address_Types[] = {
    { 0, "EXTENDED_MSID_MEID" },
    { 1, "EXTENDED_MSID_IMSI_MEID" },
    { 2, "EXTENDED_MSID_IMSI_ESN_MEID" },
    { 3, "MAX_EXTENDED_MSID_ADDRESS_TYPE" },
    { 0, NULL },
};


/* Imsi Class */
static const value_string Imsi_Class[] = {
    { 0, "IMSI_CLASS_0_TYPE" },
    { 1, "IMSI_CLASS_1_TYPE" },
    { 0, NULL },
};


/* Imsi Class0 Types */
static const value_string Imsi_Class0_Types[] = {
    { 0, "IMSI_CLASS_0_IMSI_S" },
    { 1, "IMSI_CLASS_0_IMSI_S_IMSI_11_12" },
    { 2, "IMSI_CLASS_0_IMSI_S_MCC" },
    { 3, "IMSI_CLASS_0_IMSI_S_IMSI_11_12_MCC" },
    { 0, NULL },
};


/* Imsi Class1 Types */
static const value_string Imsi_Class1_Types[] = {
    { 0, "IMSI_CLASS_1_IMSI_S_IMSI_11_12" },
    { 1, "IMSI_CLASS_1_IMSI_S_IMSI_11_12_MCC" },
    { 0, NULL },
};


/* CDMA2K Reg Types */
static const value_string Reg_Types[] = {
    { 0, "TIMER_BASED" },
    { 1, "POWER_UP" },
    { 2, "ZONE_BASED" },
    { 3, "POWER_DOWN" },
    { 4, "PARAMETER_CHANGE" },
    { 5, "ORDERED" },
    { 6, "DISTANCE_BASED" },
    { 7, "USERZONE_BASED" },
    { 8, "ENCRYPTION_RESYNC_REQUIRED" },
    { 9, "BCMC_REGISTRATION" },
    { 0, NULL },
};


/* CDMA2K DB Chari Msg Identifier Types */
static const value_string Chari_Identifier_Types[] = {
    { 0, "SMDPP_637" },
    { 1, "SMDBRD_637" },
    { 2, "SMSACK_637" },
    { 0, NULL },
};


/* CDMA2K DB Chari Parameter Types */
static const value_string Chari_Parm_Types[] = {
    { 0, "TELE_SERVICE_637" },
    { 1, "BROADCAST_SERVICE_637" },
    { 2, "ORIGINATION_ADDRESS_637" },
    { 3, "ORIGINATION_SUBADDRESS_637" },
    { 4, "DESTINATION_ADDRESS_637" },
    { 5, "DESTINATION_SUBADDRESS_637" },
    { 6, "BEARER_REPLY_637" },
    { 7, "CAUSE_CODE_637" },
    { 8, "BEARER_DATA_637" },
    { 0, NULL },
};


/* CDMA2K Page Req Service Option Types */
static const value_string Page_Req_Service_Option_Types[] = {
    { 0x0000, "INVALID" },
    { 1, "Basic Variable Rate Voice Service (8 kbps)" },
    { 2, "Mobile Station Loopback (8 kbps)" },
    { 3, "Enhanced Variable Rate Voice Service (8 kbps)" },
    { 4, "Asynchronous Data Service (9.6 kbps)" },
    { 5, "Group 3 Facsimile (9.6 kbps)" },
    { 6, "Short Message Services (Rate Set 1)" },
    { 7, "Packet Data Service: Internet or ISO Protocol Stack (9.6 kbps)" },
    { 8, "Packet Data Service: CDPD Protocol Stack (9.6 kbps)" },
    { 9, "Mobile Station Loopback (13 kbps)" },
    {10, "None STU-III Transparent Service" },
    {11, "None STU-III Non-Transparent Service" },
    {12, "Asynchronous Data Service (14.4 or 9.6 kbps)" },
    {13, "Group 3 Facsimile (14.4 or 9.6 kbps)" },
    {14, "Short Message Services (Rate Set 2)" },
    {15, "Packet Data Service: Internet or ISO Protocol Stack (14.4 kbps)" },
    {16, "Packet Data Service: CDPD Protocol Stack (14.4 kbps)" },
    {17, "High Rate Voice Service (13 kbps)" },
    {18, "Over-the-Air Parameter Administration (Rate Set 1)" },
    {19, "Over-the-Air Parameter Administration (Rate Set 2)" },
    {20, "Group 3 Analog Facsimile (Rate Set 1)" },
    {21, "Group 3 Analog Facsimile (Rate Set 2) " },
    {22, "High Speed Packet Data Service: Internet or ISO Protocol Stack (RS1 forward, RS1 reverse)" },
    {23, "High Speed Packet Data Service: Internet or ISO Protocol Stack (RS1 forward, RS2 reverse)" },

    // page 3-3 (19)
    {24, "High Speed Packet Data Service: Internet or ISO Protocol Stack (RS2 forward, RS1 reverse)" },
    {25, "High Speed Packet Data Service: Internet or ISO Protocol Stack (RS2 forward, RS2 reverse)" },
    {26, "High Speed Packet Data Service: CDPD Protocol Stack (RS1 forward, RS1 reverse)" },
    {27, "High Speed Packet Data Service: CDPD Protocol Stack (RS1 forward, RS2 reverse)" },
    {28, "High Speed Packet Data Service: CDPD Protocol Stack (RS2 forward, RS1 reverse)" },
    {29, "High Speed Packet Data Service: CDPD Protocol Stack (RS2 forward, RS2 reverse)" },
    {30, "Supplemental Channel Loopback Test for Rate Set 1" },
    {31, "Supplemental Channel Loopback Test for Rate Set 2" },
    {32, "Test Data Service Option (TDSO)" },
    {33, "cdma2000 High Speed Packet Data Service, Internet or ISO Protocol Stack" },
    {34, "cdma2000 High Speed Packet Data Service, CDPD Protocol Stack" },
    {35, "Location Services, Rate Set 1 (9.6 kbps)" },
    {36, "Location Services, Rate Set 2 (14.4 kbps)" },
    {37, "ISDN Interworking Service (64 kbps)" },
    {38, "GSM Voice" },
    {39, "GSM Circuit Data" },
    {40, "GSM Packet Data" },
    {41, "GSM Short Message Service" },
    //42 - 53 None Reserved for MC-MAP standard service options" },
    {54, "Markov Service Option (MSO)" },
    {55, "Loopback Service Option (LSO)" },
    {56, "Selectable Mode Vocoder" },

    // page 3-4 (20)
    {57, "32 kbps Circuit Video Conferencing" },
    {58, "64 kbps Circuit Video Conferencing" },
    {59, "HRPD Packet Data Service" },
    {60, "Link Layer Assisted Robust Header Compression (LLA ROHC) - Header Removal" },
    {61, "Link Layer Assisted Robust Header Compression (LLA ROHC) - Header Compression" },
    {62, "Source-Controlled Variable-Rate Multimode Wideband Speech Codec (VMR-WB) Rate Set 2" },
    {63, "Source-Controlled Variable-Rate Multimode Wideband Speech Codec (VMR-WB) Rate Set 1" },
    {64, "HRPD auxiliary Packet Data Service instance" },
    {65, "cdma2000/GPRS Inter-working" },
    {66, "cdma2000 High Speed Packet Data Service,Internet or ISO Protocol Stack" },
    {67, "HRPD Packet Data IP Service where Higher Layer Protocol is IP or ROHC" },
    {68, "Enhanced Variable Rate Voice Service (EVRC-B)" },
    {69, "HRPD Packet Data Service, which when used in paging over the 1x air interface, a page response is required" },
    {70, "Enhanced Variable Rate Voice Service (EVRC-WB)" },
    {71, "HRPD Packet Data Service for altPPP" },
    {72, "HRPD auxiliary Packet Data IP Service with PDN multiplexing header" },

    // page 3-5 (21)
    {73, "Enhanced Variable Rate Voice Service (EVRC-NW:EVRC-WB with NB capacity operating points and DTX)" },
    {74, "Flexible Markov Service Option" },
    {75, "Enhanced Loopback Service Option" },
    //76 - 4099 None Reserved for standard service options.
    {4100, "Asynchronous Data Service, Revision 1 (9.6 or 14.4 kbps)" },
    {4101, "Group 3 Facsimile, Revision 1 (9.6 or 14.4 kbps)" },
    //4102 None Reserved for standard service options.
   {4103, "Packet Data Service: Internet or ISO Protocol Stack, Revision 1 (9.6 or 14.4 kbps)" },
   {4104, "Packet Data Service: CDPD Protocol Stack, Revision 1 (9.6 or 14.4 kbps)" },


   // page 3-6 (22)
   {32760, "Identifies service reference identifier 0" },
   {32761, "Identifies service reference identifier 1" },
   {32762, "Identifies service reference identifier 2" },
   {32763, "Identifies service reference identifier 3" },
   {32764, "Identifies service reference identifier 4" },
   {32765, "Identifies service reference identifier 5" },
   {32766, "Identifies service reference identifier 6" },
   {32767, "Identifies service reference identifier 7" },
    { 0x8000, "QCOMM_13KVOICE" },
    { 0x8001, "QCOMM_IS96VOICE" },
    { 0x8003, "QCOMM_DATA_SERVICES" },
    { 0x8008, "QCOMM_TDSO" },
    { 0x801d, "QCOMM_OFF_HOOK" },
    { 0x801e, "QCOMM_96MARKOV" },
    { 0x801f, "QCOMM_144MARKOV" },
    { 0, NULL },

};


/* CDMA2K Order Ind Types */
static const value_string Order_Ind_Cause_Types[] = {
    { 2,  "BASE_STATION_CHALLENGE" },
    { 3,  "SSD_UPDATE" },
    { 5,  "PARAMETER_UPDATE_CONFIRMATION" },
    { 11, "REQUEST_ANALOG_SERVICE" },
    { 16, "MOBILE_STATION_ACKNOWLEDGEMENT" },
    { 19, "SERVICE_OPTION_REQUEST" },
    { 20, "SERVICE_OPTION_RESPONSE" },
    { 21, "RELEASE" },
    { 23, "LONG_CODE_TRANSITION" },
    { 24, "CONNECT" },
    { 25, "CONTINUOUS_DTMF_TONE" },
    { 29, "SERVICE_OPTION_CONTROL" },
    { 30, "LOCAL_CONTROL_RESPONSE" },
    { 31, "MOBILE_STATION_REJECT" },
    { 33, "SECURITY_MODE_COMPLETION" },
    { 34, "FAST_CALL_SETUP" },
    { 0, NULL },
};


/* CDMA2K Order Cmd Types */
static const value_string Order_Cmd_Cause_Types[] = {
    { 1,  "ABBREVIATED_ALERT" },
    { 2,  "BASE_STATION_CHALLENGE" },
    { 3,  "MESSAGE_ENCRYPTION_MODE" },
    { 4,  "REORDER" },
    { 5,  "PARAMETER_UPDATE" },
    { 6,  "AUDIT" },
    { 9,  "INTERCEPT" },
    { 10, "MAINTENANCE" },
    { 16, "BASE_STATION_ACKNOWLEDGEMENT" },
    { 17, "PILOT_MEASUREMENT_REQUEST" },
    { 18, "LOCK_OR_MAINTENANCE_REQUIRED" },
    { 19, "SERVICE_OPTION_REQUEST" },
    { 20, "SERVICE_OPTION_RESPONSE" },
    { 21, "RELEASE" },
    { 22, "OUTER_LOOP_REPORT_REQUEST" },
    { 23, "LONG_CODE_TRANSITION" },
    { 24, "CONNECT" },
    { 25, "CONTINUOUS_DTMF_TONE" },
    { 26, "STATUS_REQUEST" },
    { 27, "REGISTRATION" },
    { 29, "SERVICE_OPTION_CONTROL" },
    { 30, "LOCAL_CONTROL" },
    { 31, "SLOTTED_MODE" },
    { 32, "RETRY" },
    { 33, "BASE_STATION_REJECT" },
    { 34, "TRANSIT_TO_IDLE" },
    { 35, "BCMC" },
    { 36, "FAST_CALL_SETUP" },
    { 37, "SERVICE_STATUS" },
    { 38, "LOCATION_SERVICES" },
    { 0, NULL },
};

#if 0
Currently not used ???
/* CDMA2K Rejected PDU Type types for the Mobile Station Reject Order*/
static const value_string Rejected_Pdu_Types[] = {
    { 0, "20 ms Regular Message" },
    { 1, "5 ms Mini Message" },
    { 2, "Reserved" },
    { 3, "Reserved" },
    { 0, NULL },
};
#endif

/* CDMA2K RSCI types for the Release Order*/
static const value_string RSCI_Types[] = {
    { 7, "Non Slotted" },
    { 4, "0.08ms  - 1 slot" },
    { 3, "0.16s   - 2 slots" },
    { 2, "0.32s   - 4 slots" },
    { 1, "0.64s   - 8 slots" },
    { 0, "1.28s   - 16 slots" },
    { 9, "2.56s   - 32 slots" },
    { 10, "5.12s   - 64 slots" },
    { 11, "10.24s  - 128 slots" },
    { 12, "20.48s  - 256 slots" },
    { 13, "40.96s  - 512 slots" },
    { 14, "81.92s  - 1024 slots" },
    { 0, NULL },
};

/* CDMA2K RSC_END_TIME_UNIT types for the Release Order*/
static const value_string Rsc_End_Time_Unit_Types[] = {
    { 0, "unit is 4 seconds" },
    { 1, "unit is 20 seconds" },
    { 2, "unit is 100 seconds" },
    { 3, "Reserved" },
    { 0, NULL },
};

/* CDMA2K Retry Type types for the Retry Order*/
static const value_string Retry_Types[] = {
    { 0, "Clear All" },
    { 1, "Origination" },
    { 2, "Resource Request" },
    { 3, "Supplemenal Channel Req" },
    { 4, "Short Data Burst" },
    { 5, "Orig & Short Data Burst" },
    { 6, "Reserved" },
    { 7, "Reserved" },
    { 0, NULL },
};

/* CDMA2K Reject Reason types for the Base Station Reject Order*/
static const value_string Reject_Reason_Types[] = {
    { 0, "MACI Field is Missing" },
    { 1, "MACI Field is present but invalid" },
    { 2, "Security Sequence Number is Invalid" },
    { 3, "Base Station Failed to Decrypt the Encrypted Msg" },
    { 4, "Reserved" },
    { 5, "Reserved" },
    { 6, "Reserved" },
    { 7, "Reserved" },
    { 0, NULL },
};

/* CDMA2K C_SIG_ENCRYPT_MODE types for the Registration Accepted Order*/
static const value_string C_Sig_Encrypt_Mode_Types[] = {
    { 0, "Common Channel Signaling Encryption Disabled" },
    { 1, "Enhanced Cellular Msg Encryption Algo Enabled" },
    { 2, "Rijndael Encryption Algo Enabled" },
    { 3, "Reserved" },
    { 4, "Reserved" },
    { 5, "Reserved" },
    { 6, "Reserved" },
    { 7, "Reserved" },
    { 0, NULL },
};

/* CDMA2K All BCMC Reason types for the BCMC Order*/
static const value_string All_Bcmc_Reason_Types[] = {
    { 0, "BCMC_FLOW_ID not Available" },
    { 1, "BCMC_FLOW_ID not Transmitted" },
    { 2, "BCMC_FLOW_ID available in IDLE state" },
    { 3, "BCMC Registration Accepted" },
    { 4, "Authorization Failure" },
    { 5, "Retry Later" },
    { 6, "Reserved" },
    { 7, "Reserved" },
    { 0, NULL },
};

/* CDMA2K All BCMC Retry Delay types for the BCMC Order*/
static const value_string All_Bcmc_Retry_Delay_Types[] = {
    { 0, "Retry Delay Interval" },
    { 1, "Retry Delay Interval" },
    { 2, "Retry Delay Interval" },
    { 3, "Retry Delay Interval" },
    { 4, "Retry Delay Interval" },
    { 5, "Retry Delay Interval" },
    { 6, "Retry Delay Interval" },
    { 7, "Unit For Retry Delay" },
    { 0, NULL },
};

/* CDMA2K Max RSC End Time Unit types for the Fast Call Setup Order*/
static const value_string Max_rsc_End_Time_unit_Types[] = {
    { 0, "Unit is 4 seconds" },
    { 1, "Unit is 20 seconds" },
    { 2, "Unit is 100 seconds" },
    { 3, "Reserved" },
    { 0, NULL },
};

/* CDMA2K Service Status types for the Service Status Order*/
static const value_string Service_Status_Types[] = {
    { 0, "Service Request Accepted" },
    { 1, "Service Request Rejected" },
    { 0, NULL },

};


/* CDMA2K Message Encryption Modes */
static const value_string Encrypt_Mode_Types[] = {
    { 0, "Encryption Disabled" },
    { 1, "Basic Encryption Of Call Control Messages" },
    { 2, "Enhanced Encryption Of Call Control Messages" },
    { 3, "Extended Encryption Of Call Control Messages" },
    { 0, NULL },
};


/* CDMA2K Information Record Types */
static const value_string Info_Rec_Types[] = {
    { 1, "Display" },
    { 2, "Called Party Number" },
    { 3, "Calling Party Number" },
    { 4, "Connected Number" },
    { 5, "Signal" },
    { 6, "Message Waiting" },
    { 7, "Service Configuration" },
    { 8, "Called Party Subaddress" },
    { 9, "Calling Party Subaddress" },
    { 10, "Connected Subaddress" },
    { 11, "Redirecting Number" },
    { 12, "Redirecting Subaddress" },
    { 13, "Meter Pulses" },
    { 14, "Parametric Alerting" },
    { 15, "Line Control" },
    { 16, "Extended Display" },
    { 19, "Non Negotiable Service Configuration" },
    { 20, "Multiple Character Extended Display" },
    { 21, "Call Waiting Indicator" },
    { 22, "Extended Multiple Character Extended Display" },
    { 254, "Extended Record Type_International" },
    { 0, NULL },

};


/* CDMA2K Encryption Key Size */
static const value_string Enc_Key_Types[] = {
    { 0, "Reserved" },
    { 1, "64 Bits" },
    { 2, "128 Bits" },
    { 3, "Reserved" },
    { 4, "Reserved" },
    { 5, "Reserved" },
    { 6, "Reserved" },
    { 7, "Reserved" },
    { 0, NULL },
};


/* CDMA2K 1x Reverse Link Frequency Offset */
static const value_string rl_Freq_Offset_Types[] = {
    { 0, "Reverse Link On Lowest SR3 Frequency" },
    { 1, "Reverse Link On Center SR3 Frequency" },
    { 2, "Reverse Link On Highest SR3 Frequency" },
    { 3, "Reserved" },
    { 0, NULL },
};


/* CDMA2K Pilot Record Types */
static const value_string Pilot_Rec_Types[] = {
    { 0, "1x Common Pilot With Transmit Diversity" },
    { 1, "1x Auxiliary Pilot" },
    { 2, "1x Auxiliary Pilot With Transmit Diversity" },
    { 3, "3x Common Pilot" },
    { 4, "3x Auxiliary Pilot" },
    { 5, "Reserved" },
    { 6, "Reserved" },
    { 7, "Reserved" },
    { 0, NULL },
};


/* CDMA2K PLCM Types */
static const value_string Plcm_Types[] = {
    { 0, "ESN Derived" },
    { 1, "BS Assigned" },
    { 2, "IMSI_M Derived" },
    { 3, "IMSI_T Derived" },
    { 4, "MEID Derived" },
    { 0, NULL },
};


/* CDMA2K Number Types */
static const value_string Number_Types[] = {
    { 0, "Unknown" },
    { 1, "International Number" },
    { 2, "National Number" },
    { 3, "Network Specific Number" },
    { 4, "Subscriber Number" },
    { 5, "Reserved" },
    { 6, "Abbreviated Number" },
    { 7, "Reserved For Extension" },
    { 0, NULL },
};


/* CDMA2K Numbering Plan Types */
static const value_string Number_Plan_Types[] = {
    { 0, "Unknown" },
    { 1, "ISDN/Telephony Numbering Plan" },
    { 2, "Reserved" },
    { 3, "Data Numbering Plan" },
    { 4, "Telex Numbering Plan" },
    { 5, "Reserved" },
    { 6, "Reserved" },
    { 7, "Reserved" },
    { 8, "Reserved" },
    { 9, "Private Numbering Plan" },
    { 10, "Reserved" },
    { 11, "Reserved" },
    { 12, "Reserved" },
    { 13, "Reserved" },
    { 14, "Reserved" },
    { 15, "Reserved For Extension" },
    { 0, NULL },
};


/* CDMA2K Presentation Indicator Types */
static const value_string Pres_Ind_Types[] = {
    { 0, "Presentation Allowed" },
    { 1, "Presentation Restricted" },
    { 2, "Number Not Available" },
    { 3, "Reserved" },
    { 0, NULL },
};


/* CDMA2K Screening Indicator Types */
static const value_string Scr_Ind_Types[] = {
    { 0, "User Provided, Not Screened" },
    { 1, "User Provided, Verified And Passed" },
    { 2, "User Provided, Verified And Failed" },
    { 3, "Network Provided" },
    { 0, NULL },
};


/* CDMA2K Signal Types */
static const value_string Signal_Types[] = {
    { 0, "Tone Signal" },
    { 1, "ISDN Alerting" },
    { 2, "IS-54B Alerting" },
    { 3, "Reserved" },
    { 0, NULL },
};


/* CDMA2K Odd Even Indicator */
static const value_string Odd_Even_Ind_Types[] = {
    { 0, "Even Number Of Address Signals" },
    { 1, "Odd Number Of Address Signals" },
    { 0, NULL },
};


/* CDMA2K Redirection Reasons */
static const value_string Redir_Reason_Types[] = {
    { 0, "Unknown" },
    { 1, "Call Forwarding / Called DTE Busy" },
    { 2, "Call Forwarding No Reply" },
    { 3, "Reserved" },
    { 4, "Reserved" },
    { 5, "Reserved" },
    { 6, "Reserved" },
    { 7, "Reserved" },
    { 8, "Reserved" },
    { 9, "Called DTE Out Of Order" },
    { 10, "Call Forwarding By The Called DTE" },
    { 11, "Reserved" },
    { 12, "Reserved" },
    { 13, "Reserved" },
    { 14, "Reserved" },
    { 15, "Call Forwarding Unconditional / Systematic Call Redirection" },
    { 0, NULL },
};


/* CDMA2K Cadence Types */
static const value_string Cadence_Types[] = {
    { 0, "Not Specified" },
    { 1, "Acoustic Earpiece / Similar Device" },
    { 2, "Device Other Than Acoustic Earpiece / Similar Device(Ex : Ringer)" },
    { 3, "Reserved" },
    { 0, NULL },
};

static const value_string l3dpu_ORM_PRM_req_mode_values[] = {
    { /* 000 */ 0x00, "Reserved" },
    { /* 001 */ 0x01, "CDMA only" },
    { /* 010 */ 0x02, "Reserved (Previously: Wide analog only)" },
    { /* 011 */ 0x03, "Reserved (Previously: Either wide analog or CDMA only)" },
    { /* 100 */ 0x04, "Reserved (Previously: Narrow analog only)" },
    { /* 101 */ 0x05, "Reserved (Previously: Either narrow analog or CDMA only)" },
    { /* 110 */ 0x06, "Reserved (Previously: Either narrow analog or wide analog only)" },
    { /* 111 */ 0x07, "Reserved (Previously: Narrow analog or wide analog or CDMA)" },

    {0x00, NULL }
};

// Table 2.7.1.3.2.4-5. Encryption Algorithms Supported , page 858 (2-738)
static const value_string l3dpu_ORM_encryption_algo_values[] = {
    {/*0000*/ 0x00, "Basic encryption supported" },
    {/*0001*/ 0x01, "Basic and Enhanced encryption supported" },
    {0x00, NULL }
};

static const value_string l3dpu_ORM_ch_ind_values[] = {
    {/*00*/ 0x00, "Refer to EXT_CH_IND" },
    {/*01*/ 0x01, "Fundamental Channel" },
    {/*10*/ 0x02, "Dedicated Control Channel" },
    {/*11*/ 0x03, "Fundamental Channel and Dedicated Control Channel" },
    {0x00, NULL }
};

/* Decoder for all the information elements of CDMA2K Message Type */
static void cdma2k_message_decode(proto_item *item _U_, tvbuff_t *tvb,proto_tree *tree, guint *offset, proto_tree *mainTree _U_, guint16 *noerror _U_ , packet_info *pinfo _U_)
{
    guint16 channel = -1, msgtype = -1, headerRecCnt = -1, headerRecLen = -1, l_offset = -1;
    guint16 headerRecType = -1, inc = -1, count = -1, l3PduLen = -1, authIncl = -1, oneXPrev = -1;
    proto_item *item1 = NULL;
    proto_tree *subtree = NULL, *subtree1 = NULL, *subtree2 = NULL, *subtree3 = NULL;

    item1 = proto_tree_add_item(tree,hf_cdma2k_tlac_Header, tvb, *offset,1, ENC_NA);
    subtree = proto_item_add_subtree(item1, ett_cdma2k_subtree);

    proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Channel, tvb, *offset*8,1, ENC_BIG_ENDIAN);
    channel = tvb_get_bits8(tvb,*offset*8,1);
    proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_1x_Protocol_Revision, tvb, *offset*8 + 1,8, ENC_BIG_ENDIAN);
    oneXPrev = tvb_get_bits8(tvb,*offset*8 + 1,8);
    *offset+=1;

    if (channel == 0)
    {
        /*get LSB 6 bits for MsgType if r-csch*/
        proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_msgType, tvb, *offset*8 + 3,6, ENC_BIG_ENDIAN);
        msgtype = tvb_get_bits8(tvb,*offset*8 + 3,6);
        *offset+=1;
    }
    else
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_msgType, tvb, *offset*8 + 1,8, ENC_BIG_ENDIAN);
        msgtype = tvb_get_bits8(tvb,*offset*8 + 1,8);
        *offset+=1;
    }

    proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Records_Count, tvb, *offset*8 + 1,4, ENC_BIG_ENDIAN);
    headerRecCnt = tvb_get_bits8(tvb,*offset*8 + 1,4);
    l_offset = *offset*8 + 5;

    item1 = proto_tree_add_item(subtree, hf_cdma2k_tlac_Header_Record, tvb, *offset,1, ENC_NA);
    subtree1 = proto_item_add_subtree(item1, ett_cdma2k_subtree1);

    for(count = 1; count <= headerRecCnt; count++)
    {
        item1 = proto_tree_add_item(subtree1, hf_cdma2k_tlac_Header_Record, tvb, l_offset/8,1, ENC_NA);
        proto_item_append_text(item1," : [%02x]",count);
        subtree2 = proto_item_add_subtree(item1, ett_cdma2k_subtree2);
        proto_tree_add_bits_item(subtree2,hf_cdma2k_tlac_Header_Record_Type, tvb, l_offset, 4, ENC_BIG_ENDIAN);
        headerRecType = tvb_get_bits8(tvb,l_offset, 4);
        l_offset+=4;

        if(headerRecType == 0)
        {
            proto_tree_add_bits_item(subtree2,hf_cdma2k_tlac_Header_Record_Length, tvb, l_offset, 8, ENC_BIG_ENDIAN);
            headerRecLen = tvb_get_bits8(tvb,l_offset, 8);
            l_offset+=8;
            item1 = proto_tree_add_item(subtree2, hf_cdma2k_tlac_Header_Record_Values, tvb, (l_offset/8),headerRecLen+1 , ENC_NA);
            subtree3 = proto_item_add_subtree(item1, ett_cdma2k_subtree2);
            cdma2k_message_ADDR_FIELDS(item1, tvb, subtree3, &l_offset,  headerRecLen);
        }
        else if(headerRecType == 1)
        {
            authIncl = 1;
            proto_tree_add_bits_item(subtree2,hf_cdma2k_tlac_Header_Record_Length, tvb, l_offset, 8, ENC_BIG_ENDIAN);
            headerRecLen = tvb_get_bits8(tvb,l_offset, 8);
            l_offset+=8;
            item1 = proto_tree_add_item(subtree2, hf_cdma2k_tlac_Header_Record_Values, tvb, (l_offset/8), headerRecLen+1, ENC_NA);
            subtree3 = proto_item_add_subtree(item1, ett_cdma2k_subtree2);
            cdma2k_message_AUTH_FIELDS(item1, tvb, subtree3, &l_offset,  headerRecLen);
        }
        else
        {
            proto_tree_add_bits_item(subtree2,hf_cdma2k_tlac_Header_Record_Length, tvb, l_offset, 8, ENC_BIG_ENDIAN);
            headerRecLen = tvb_get_bits8(tvb,l_offset, 8);
            l_offset+=8;
            item1 = proto_tree_add_item(subtree2, hf_cdma2k_tlac_Header_Record_Values, tvb, (l_offset/8), headerRecLen+1, ENC_NA);

            for (inc = 0; inc < (headerRecLen*8); )
            {
                proto_item_append_text(item1," 0x%02x ",tvb_get_bits8(tvb,l_offset, 8));
                l_offset+=8;
                inc+=8;
            }
        }
    }

    if(l_offset%8 == 0)
    {
        *offset = (l_offset/8);
    }
    else
    {
        proto_tree_add_bits_item(subtree1, hf_cdma2k_tlac_Header_Record_Reserved, tvb, l_offset, (8-(l_offset%8)), ENC_BIG_ENDIAN);
        *offset = (l_offset/8) + 1;
    }

    item1 = proto_tree_add_item(subtree1, hf_cdma2k_tlac_Pdu, tvb, *offset,-1, ENC_NA);
    subtree2 = proto_item_add_subtree(item1, ett_cdma2k_subtree2);
    proto_tree_add_item(subtree2,hf_cdma2k_tlac_Pdu_Length, tvb, *offset,2, ENC_BIG_ENDIAN);
    l3PduLen = tvb_get_bits16(tvb,*offset*8,16, ENC_BIG_ENDIAN);
    *offset+=2;

    if(channel == 0)
    {
        switch(msgtype)
        {
            case CDMA2KRegIndMsg:
                { cdma2k_message_REGISTRATION(item1, tvb, subtree2, offset, oneXPrev); break;}

            case CDMA2KOrderIndMsg:
                { cdma2k_message_ORDER_IND(item1, tvb, subtree2,offset); break;}

            case CDMA2KDataBurstIndMsg:
                { cdma2k_message_DATA_BURST_IND(item1, tvb, subtree2,offset); break;}

            case CDMA2KOrigIndMsg:
                { cdma2k_message_ORIGINATION(item1, tvb, subtree2,offset,authIncl,oneXPrev); break;}

            case CDMA2KPageResponseMsg:
                { cdma2k_message_PAGE_RESPONSE(item1, tvb, subtree2,offset,authIncl,oneXPrev); break;}

            case CDMA2KAuthChallRspMsg:
                { cdma2k_message_AUTH_CHALL_RSP(item1, tvb, subtree2,offset); break;}

            case CDMA2KOrderCmdMsg:
                { cdma2k_message_ORDER_CMD(item1, tvb, subtree2,offset); break;}

            case CDMA2KDataBurstCmdMsg:
                { cdma2k_message_DATA_BURST_CMD(item1, tvb, subtree2,offset); break;}

            case CDMA2KAuthChallReqMsg:
                { cdma2k_message_AUTH_CHALL_REQ(item1, tvb, subtree2,offset); break;}

             case CDMA2KGenPageReqMsg:
                { cdma2k_message_GEN_PAGE_REQ(item1, tvb, subtree2,offset,l3PduLen); break;}

            default:
                { *noerror = 0; break; }
        }
    }
    else
    {
        switch(msgtype)
        {
            case CDMA2KAlertWithInfoMsg:
                { cdma2k_message_ALERT_WITH_INFO(item1, tvb, subtree2,offset); break;}

            case CDMA2KUniversalHandoffDirectionMsg:
            case CDMA2KMeIdUniversalHandoffDirectionMsg:
                { cdma2k_message_HANDOFF_DIR(item1, tvb, subtree2,offset,msgtype); break;}

            default:
                { *noerror = 0; break; }
        }
    }

}

/* 3GPP2 C.S0005-E v3.0 Table 2.3.3-1. Station Class Mark */

/* SCM Fields values */
static const value_string l3dpu_SCM_field_values7[] = {
    { 0x00, "Other bands" },
    { 0x01, "Band Classes 1,4,14" },
    { 0x00, NULL }
};

static const value_string l3dpu_SCM_field_values6[] = {
    { 0x00, "CDMA Only" },
    { 0x01, "?" },
    { 0x00, NULL }
};

static const value_string l3dpu_SCM_field_values5[] = {
    { 0x00, "Non-Slotted" },
    { 0x01, "Slotted" },
    { 0x00, NULL }
};

static const value_string l3dpu_SCM_field_values4[] = {
    { 0x00, "MEID not configured" },
    { 0x01, "MEID configured" },
    { 0x00, NULL }
};


static const value_string l3dpu_SCM_field_values2[] = {
    { 0x00, "Continuous" },
    { 0x01, "Discontinuous" },
    { 0x00, NULL }
};

static void
dissect_cdma2000_scm(tvbuff_t* tvb, proto_tree* tree, guint bit_offset)
{
    proto_tree *sub_tree = proto_tree_add_subtree(tree, tvb, bit_offset >> 3, 2, ett_cdma2000_scm, NULL, "SCM - Station Class Mark");

    /* Extended SCM Indicator bit 7 */
    proto_tree_add_bits_item(sub_tree, hf_cdma2k_ext_scm_ind, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    /* Dual Mode Bit 6 */
    proto_tree_add_bits_item(sub_tree, hf_cdma2k_scm_dual_mode, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    /* Slotted Class Bit 5*/
    proto_tree_add_bits_item(sub_tree, hf_cdma2k_scm_slotted_class, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    /* MEID support indicator bit 4 */
    proto_tree_add_bits_item(sub_tree, hf_cdma2k_scm_meid_sup, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    /* 25 MHz Bandwidth Bit 3 */
    proto_tree_add_bits_item(sub_tree, hf_cdma2k_scm_25mhz_bw, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    /* Transmission Bit 2 */
    proto_tree_add_bits_item(sub_tree, hf_cdma2k_scm_trans, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    /* Power Class for Band Class 0 Analog Operation Bit 1 - 0 */
    proto_tree_add_bits_item(sub_tree, hf_cdma2k_scm_pow_class, tvb, bit_offset, 2, ENC_BIG_ENDIAN);

}

static void cdma2k_message_REGISTRATION(proto_item *item, tvbuff_t *tvb, proto_tree *tree, guint *offset, guint16 oneXPrev)
{
    guint16 mob_P_Rev_Value = -1, mob_P_Rev_Rx = -1;
    guint16 uzid_Incl = -1, geoLoc_Incl = -1, l_offset = -1;
    proto_tree *subtree = NULL;

    /*iws_Mob_P_Rev_In_Use = 7;*/

    item = proto_tree_add_item(tree,hf_cdma2k_RegMsg, tvb, *offset,-1, ENC_NA);
    subtree = proto_item_add_subtree(item, ett_cdma2k_subtree1);
    proto_tree_add_bits_item(subtree, hf_cdma2k_Reg_Type, tvb, *offset*8,4, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(subtree, hf_cdma2k_Slot_Cycle_Index, tvb, *offset*8 + 4,3, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(subtree, hf_cdma2k_Mob_P_Rev, tvb, *offset*8 + 7,8, ENC_BIG_ENDIAN);
    mob_P_Rev_Rx = tvb_get_bits8(tvb,*offset*8 + 7,8);
    *offset+=1;

    mob_P_Rev_Value = ((oneXPrev >= mob_P_Rev_Rx)? mob_P_Rev_Rx : oneXPrev);

    if(mob_P_Rev_Value == 1)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_Ext_Scm, tvb, *offset*8 + 7,1, ENC_BIG_ENDIAN);
        *offset+=1;
        /* Jump Over the one bit Reserved Field*/
        proto_tree_add_bits_item(subtree, hf_cdma2k_Reserved, tvb, *offset*8,1, ENC_BIG_ENDIAN);
        proto_tree_add_bits_item(subtree, hf_cdma2k_Sloted_Mode, tvb, *offset*8 + 1,1, ENC_BIG_ENDIAN);
         /*Jump Over the five bit Reserved Field*/
        proto_tree_add_bits_item(subtree, hf_cdma2k_Reserved, tvb, *offset*8 + 2,5, ENC_BIG_ENDIAN);
    }
    else
    {
        dissect_cdma2000_scm(tvb, subtree, *offset * 8 + 7);
        *offset+=1;
    }

    proto_tree_add_bits_item(subtree, hf_cdma2k_Mob_Term, tvb, *offset*8 + 7,1, ENC_BIG_ENDIAN);
    *offset+=1;
    l_offset = *offset*8;

    if(mob_P_Rev_Value > 3)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_Return_Cause, tvb, *offset*8,4, ENC_BIG_ENDIAN);
        l_offset+=4;
    }

    if(mob_P_Rev_Value >= 6)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_Qpch_Supported, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;
        proto_tree_add_bits_item(subtree, hf_cdma2k_Enhanced_Rc, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;
        proto_tree_add_bits_item(subtree, hf_cdma2k_Uzid_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        uzid_Incl = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;

        if(uzid_Incl != 0)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Uzid, tvb, l_offset, 16, ENC_BIG_ENDIAN);
            l_offset+=16;
        }
    }

    if(mob_P_Rev_Value >= 7)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_GeoLoc_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        geoLoc_Incl = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;

        if(geoLoc_Incl != 0)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_GeoLoc_Type, tvb, l_offset, 3, ENC_BIG_ENDIAN);
            l_offset+=3;
        }
    }

    if(l_offset%8 == 0)
        *offset = (l_offset/8);
    else
        *offset = (l_offset/8) + 1;
}


/* Decode Order Indication Message Parameters */
static void cdma2k_message_ORDER_IND(proto_item *item,tvbuff_t *tvb,proto_tree *tree,guint *offset)
{
    guint16 addRecLen = -1, ordq = -1, rejectedtype = -1;
    guint16  l_offset = -1, rsc_mode_ind = -1, ordertype = -1;
    proto_tree *subtree = NULL, *subtree1 = NULL;

    item = proto_tree_add_item(tree,hf_cdma2k_OrderIndMsg, tvb, *offset, -1, ENC_NA);
    subtree = proto_item_add_subtree(item, ett_cdma2k_subtree1);
    proto_tree_add_bits_item(subtree, hf_cdma2k_Order_Ind, tvb, *offset*8,6, ENC_BIG_ENDIAN);
    ordertype = tvb_get_bits8(tvb,*offset*8, 6);
    proto_tree_add_bits_item(subtree, hf_cdma2k_Add_Record_Len, tvb, *offset*8 + 6,3, ENC_BIG_ENDIAN);
    addRecLen = tvb_get_bits8(tvb,*offset*8 + 6,3);
    *offset+=1;
    l_offset = *offset*8+1;

    if(addRecLen > 0)
    {
        item = proto_tree_add_item(subtree, hf_cdma2k_Order_Specific_Fields, tvb, *offset,-1, ENC_NA);
        subtree1 = proto_item_add_subtree(item, ett_cdma2k_subtree2);

        switch(ordertype)
            {
            case 2:
            {
                proto_item_append_text(item, " : BASE STATION CHALLENGE Order ");

                        proto_tree_add_bits_item(subtree1, hf_cdma2k_Ordq, tvb, l_offset, 8, ENC_BIG_ENDIAN);
                l_offset+=8;

                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Randbs, tvb, l_offset, 32, ENC_BIG_ENDIAN);
                l_offset+=32;
                break;
            }

            case 4:
            {
                proto_item_append_text(item, " : REORDER Order ");

                        proto_tree_add_bits_item(subtree1, hf_cdma2k_Ordq, tvb, l_offset, 8, ENC_BIG_ENDIAN);
                l_offset+=8;

                break;
            }

            case 19:
            {
                proto_item_append_text(item, " : SERVICE OPTION REQUEST Order ");

                proto_tree_add_bits_item(subtree1, hf_cdma2k_Ordq, tvb, l_offset, 8, ENC_BIG_ENDIAN);
                l_offset+=8;
                proto_tree_add_bits_item(subtree1, hf_cdma2k_service_option, tvb, l_offset, 16, ENC_BIG_ENDIAN);
                l_offset+=16;
                break;
            }
            case 20:
            {
                proto_item_append_text(item, " : SERVICE OPTION RESPONSE Order ");

                proto_tree_add_bits_item(subtree1, hf_cdma2k_Ordq, tvb, l_offset,  8, ENC_BIG_ENDIAN);
                l_offset+=8;
                proto_tree_add_bits_item(subtree1, hf_cdma2k_service_option, tvb, l_offset,  16, ENC_BIG_ENDIAN);
                l_offset+=16;
                break;
            }
            case 31:
            {
                proto_item_append_text(item, " : MOBILE STATION REJECT Order ");

                proto_tree_add_bits_item(subtree1, hf_cdma2k_Ordq, tvb, l_offset,  8, ENC_BIG_ENDIAN);
                ordq = tvb_get_bits8(tvb,*offset*8+1,8);
                l_offset+=8;

                proto_tree_add_bits_item(subtree1, hf_cdma2k_Rejected_Type, tvb, l_offset, 8, ENC_BIG_ENDIAN);
                rejectedtype = tvb_get_bits8(tvb,*offset*8+1,8);
                l_offset+=8;

                if ((rejectedtype == 7) || (rejectedtype == 1)) /* 7= access, 1= reverse traffic */
                {
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Reserved, tvb, l_offset, 2, ENC_BIG_ENDIAN);
                    l_offset+=2;
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Rejected_Order, tvb, l_offset, 6, ENC_BIG_ENDIAN);
                    l_offset+=6;/* 4 byte , 1 bit */
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Rejected_Ordq, tvb, l_offset, 8, ENC_BIG_ENDIAN);
                    l_offset+=8;/* 5 byte , 1 bit */
                }

                if (rejectedtype == 12) /* for both access & reverse traffic */
                {
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Rejected_Parm_Id, tvb, l_offset, 16, ENC_BIG_ENDIAN);
                    l_offset+=16;/* 7 byte , 1 bit */
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Rejected_Record, tvb, l_offset, 8, ENC_BIG_ENDIAN);
                    l_offset+=8;/* 8 byte , 1 bit */
                }

                if ((ordq == 16) || (ordq == 17) || (ordq == 18) || (ordq == 19))
                {
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Con_Ref, tvb, l_offset, 8, ENC_BIG_ENDIAN);
                    l_offset+=8;
                }
                if (ordq == 19)
                {
                     proto_tree_add_bits_item(subtree1, hf_cdma2k_Tag, tvb, l_offset, 4, ENC_BIG_ENDIAN);
                    l_offset+=4;
                }

                if(l_offset%8 != 0)
                {
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Reserved, tvb, l_offset, (8-(l_offset%8)), ENC_BIG_ENDIAN);
                }
                break;
            }

            case 21:
            {
                proto_item_append_text(item, " : RELEASE Order ");

                proto_tree_add_bits_item(subtree1, hf_cdma2k_Ordq, tvb, *offset*8+1,8, ENC_BIG_ENDIAN);
                ordq = tvb_get_bits8(tvb,*offset*8+1,8);
                l_offset+=8;

                if (ordq == 3)
                {
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Rsc_Mode_Ind , tvb, l_offset, 1, ENC_BIG_ENDIAN);
                    rsc_mode_ind = tvb_get_bits8(tvb,*offset*8+1,1);
                    l_offset+=1;
                    if (rsc_mode_ind == 1)
                    {
                        proto_tree_add_bits_item(subtree1, hf_cdma2k_Rsci, tvb, l_offset, 4, ENC_BIG_ENDIAN);
                        l_offset+=4;
                        proto_tree_add_bits_item(subtree1, hf_cdma2k_Rsc_End_Time_Unit, tvb, l_offset, 2, ENC_BIG_ENDIAN);
                        l_offset+=2;
                        proto_tree_add_bits_item(subtree1, hf_cdma2k_Rsc_End_Time_Value, tvb, l_offset, 4, ENC_BIG_ENDIAN);
                        l_offset+=4;

                    }
                }
                break;
            }

            case 34:
            {
                proto_item_append_text(item, " : FAST CALL SETUP Order ");

                proto_tree_add_bits_item(subtree1, hf_cdma2k_Ordq, tvb, *offset*8+1,8, ENC_BIG_ENDIAN);
                l_offset+=8;

                proto_tree_add_bits_item(subtree1, hf_cdma2k_Rsc_Mode_Ind , tvb, l_offset, 1, ENC_BIG_ENDIAN);
                rsc_mode_ind = tvb_get_bits8(tvb,*offset*8+1,1);
                l_offset+=1;

                if (rsc_mode_ind == 1)
                {
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Rsci, tvb, l_offset, 4, ENC_BIG_ENDIAN);
                    l_offset+=4;
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Rsc_End_Time_Unit, tvb, l_offset, 2, ENC_BIG_ENDIAN);
                    l_offset+=2;
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Rsc_End_Time_Value, tvb, l_offset, 4, ENC_BIG_ENDIAN);
                    l_offset+=4;
                }
                break;
            }

            default:
            {
                proto_item_append_text(item, " : Invalid / Unsupported Order Type Received");
                break;
            }
        }
    }
    if(l_offset%8 == 0)
        *offset = (l_offset/8);
    else
        *offset = (l_offset/8) + 1;
}

/* Decode Order Command Message Parameters */
static void cdma2k_message_ORDER_CMD(proto_item *item,tvbuff_t *tvb,proto_tree *tree,guint *offset)
{
    guint16 addRecLen = -1, ordq = -1, csig = -1;
    guint16 l_offset = -1, MsgIntInfoIncl = -1, retrytype = -1, allbcmcflowind = -1, clearallretrydelay = -1;
    guint16 numbcmcprograms = -1, bcmc_program_id = -1;
    guint16 bcmcflowdiscriminatorlen = -1, regulatoryindincl = -1;
    guint16 rsc_mode_supported = -1, rer_mode_incl = -1, rer_mode_enabled = -1, tkz_mode_incl = -1;
    guint16 sameaspreviousbcmcflow = -1, ordertype = -1, clearretrydelay = -1, rer_time = -1;
    guint16 rsc_mode_ind = -1;
    proto_tree *subtree = NULL, *subtree1 = NULL;

    subtree = proto_tree_add_subtree(tree, tvb, *offset, -1, ett_cdma2k_subtree1, NULL, "Order Command Message");

    proto_tree_add_item(subtree, hf_cdma2k_Order_Cmd, tvb, *offset,1, ENC_BIG_ENDIAN);
    ordertype = tvb_get_guint8(tvb,*offset) >> 2;

    proto_tree_add_bits_item(subtree, hf_cdma2k_Add_Record_Len, tvb, *offset*8 + 6,3, ENC_BIG_ENDIAN);
    addRecLen = tvb_get_bits8(tvb,*offset*8 + 6,3);
    *offset+=1;
    l_offset = *offset*8+1;

    if(addRecLen > 0)
    {
        item = proto_tree_add_item(subtree, hf_cdma2k_Order_Specific_Fields, tvb, *offset,-1, ENC_NA);
        subtree1 = proto_item_add_subtree(item, ett_cdma2k_subtree2);

    switch(ordertype)
    {
        case 2:
        {
            proto_item_append_text(item, " : BASE STATION CHALLENGE CONFIRMATION Order ");

            proto_tree_add_bits_item(subtree1, hf_cdma2k_Ordq, tvb, l_offset, 8, ENC_BIG_ENDIAN);
            l_offset+=8;

                        proto_tree_add_bits_item(subtree1, hf_cdma2k_Authbs, tvb, l_offset, 18, ENC_BIG_ENDIAN);
            l_offset+=18;

            proto_tree_add_bits_item(subtree1, hf_cdma2k_Reserved, tvb, l_offset, 6, ENC_BIG_ENDIAN);
            l_offset+=6;
            break;
        }

        case 4:
        {
            proto_item_append_text(item, " : REORDER Order ");

                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Ordq, tvb, l_offset, 8, ENC_BIG_ENDIAN);
            l_offset+=8;

            break;
        }

        case 21:
        {
            proto_item_append_text(item, " : RELEASE Order ");

            proto_tree_add_bits_item(subtree1, hf_cdma2k_Ordq, tvb, *offset*8+1,8, ENC_BIG_ENDIAN);
            ordq = tvb_get_bits8(tvb,*offset*8+1,8);
            l_offset+=8;

            if (ordq == 3)
            {
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Rsc_Mode_Ind , tvb, l_offset, 1, ENC_BIG_ENDIAN);
                rsc_mode_ind = tvb_get_bits8(tvb,*offset*8+1,1);
                l_offset+=1;
                if (rsc_mode_ind == 1)
                {
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Rsci, tvb, l_offset, 4, ENC_BIG_ENDIAN);
                    l_offset+=4;
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Rsc_End_Time_Unit, tvb, l_offset, 2, ENC_BIG_ENDIAN);
                    l_offset+=2;
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Rsc_End_Time_Value, tvb, l_offset, 4, ENC_BIG_ENDIAN);
                    l_offset+=4;
                }
            }
            break;
        }

        case 27:
        {
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Ordq, tvb, l_offset, 8, ENC_BIG_ENDIAN);
            ordq = tvb_get_bits8(tvb,l_offset, 8);
            l_offset+=8;

            /*
             * 3GPP2 C.S0005-F v2.0 Table 3.7.4-1. Order and Order Qualification Codes Used on the f-csch and the f-dsch
             */
            switch(ordq){
            case 0: /* Registration Accepted Order (ROAM_INDI not included; see 3.7.4.5) */
                proto_item_append_text(item, " : Registration Accepted Order ");
                break;
            case 1: /* Registration Request Order */
                proto_item_append_text(item, " : Registration Request Order ");
                break;
            case 2: /* Registration Rejected Order */
                proto_item_append_text(item, " : Registration Rejected Order ");
                break;
            case 4: /* Registration Rejected Order (delete TMSI) */
                proto_item_append_text(item, " : Registration Rejected Order (delete TMSI) ");
                break;
            case 5: /* Registration Accepted Order (ROAM_INDI included but the signaling encryption related fields are not included; see 3.7.4.5) */
                proto_item_append_text(item, " : Registration Accepted Order ");
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Roam_Ind, tvb, l_offset, 8, ENC_BIG_ENDIAN);
                l_offset+=8;
                break;
            case 7: /* Registration Accepted Order (ROAM_INDI and the signaling encryption related fields are included; see 3.7.4.5) */
                proto_item_append_text(item, " : Registration Accepted Order ");
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Roam_Ind, tvb, l_offset, 8, ENC_BIG_ENDIAN);
                l_offset+=8;

                proto_tree_add_bits_item(subtree1, hf_cdma2k_C_Sig_Encrypt_Mode, tvb, l_offset, 3, ENC_BIG_ENDIAN);
                csig = tvb_get_bits8(tvb,l_offset, 3);
                l_offset+=8;

                proto_tree_add_bits_item(subtree1, hf_cdma2k_Msg_Int_Info_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
                MsgIntInfoIncl = tvb_get_bits8(tvb,l_offset, 1);
                l_offset+=1;
                break;
            default:
                break;
            }


            if ((csig == 1) || (csig == 2))
            {
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Enc_Key_Size, tvb, l_offset, 3, ENC_BIG_ENDIAN);
                l_offset+=3;
            }

            if (MsgIntInfoIncl == 1)
            {
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Change_Keys, tvb, l_offset, 1, ENC_BIG_ENDIAN);
                l_offset+=1;

                proto_tree_add_bits_item(subtree1, hf_cdma2k_Use_Uak, tvb, l_offset, 1, ENC_BIG_ENDIAN);
                l_offset+=1;
            }

            if(l_offset%8 != 0)
            {
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Reserved, tvb, l_offset, (8-(l_offset%8)), ENC_BIG_ENDIAN);
            }
            break;
        }

        case 32:
        {
            proto_item_append_text(item, " : RETRY Order ");

            proto_tree_add_bits_item(subtree1, hf_cdma2k_Ordq, tvb, l_offset, 8, ENC_BIG_ENDIAN);
            l_offset+=8;

            proto_tree_add_bits_item(subtree1, hf_cdma2k_Retry_Type, tvb, l_offset, 3, ENC_BIG_ENDIAN);
            retrytype = tvb_get_bits8(tvb,l_offset, 3);
            l_offset+=3;

            if (retrytype != 0)
            {
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Retry_Delay, tvb, l_offset, 8, ENC_BIG_ENDIAN);
                l_offset+=8;
            }

            proto_tree_add_bits_item(subtree1, hf_cdma2k_Reserved, tvb, l_offset, 5, ENC_BIG_ENDIAN);
            l_offset+=5;
            break;
        }
        case 33:
        {
            proto_item_append_text(item, " : BASE STATION REJECT Order ");

            proto_tree_add_bits_item(subtree1, hf_cdma2k_Ordq, tvb, l_offset, 8, ENC_BIG_ENDIAN);
            l_offset+=8;

            proto_tree_add_bits_item(subtree1, hf_cdma2k_Reject_Reason, tvb, l_offset, 4, ENC_BIG_ENDIAN);
            l_offset+=4;

            proto_tree_add_bits_item(subtree1, hf_cdma2k_Rejected_Msg_Type, tvb, l_offset, 8, ENC_BIG_ENDIAN);
            l_offset+=8;

            proto_tree_add_bits_item(subtree1, hf_cdma2k_Rejected_Msg_Seq, tvb, l_offset, 3, ENC_BIG_ENDIAN);
            l_offset+=3;
            break;
        }

        case 35:
        {
            proto_item_append_text(item, " : BCMC Order ");

            proto_tree_add_bits_item(subtree1, hf_cdma2k_Ordq, tvb, l_offset, 8, ENC_BIG_ENDIAN);
            l_offset+=8;

            proto_tree_add_bits_item(subtree1, hf_cdma2k_All_Bcmc_Flows_Ind, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            allbcmcflowind = tvb_get_bits8(tvb,l_offset, 1);
            l_offset+=1;

            if (allbcmcflowind == 1)
            {
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Clear_All_Retry_Delay, tvb, l_offset, 1, ENC_BIG_ENDIAN);
                clearallretrydelay = tvb_get_bits8(tvb,l_offset, 1);
                l_offset+=1;
            }

            if ((allbcmcflowind == 1) || (clearallretrydelay == 0))
            {
                proto_tree_add_bits_item(subtree1, hf_cdma2k_All_Bcmc_Reason, tvb, l_offset, 4, ENC_BIG_ENDIAN);
                l_offset+=4;
            }

            proto_tree_add_bits_item(subtree1, hf_cdma2k_All_Bcmc_Retry_Delay, tvb, l_offset, 8, ENC_BIG_ENDIAN);
            l_offset+=8;

            if (allbcmcflowind == 0)
            {
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Num_Bcmc_Programs, tvb, l_offset, 6, ENC_BIG_ENDIAN);
                numbcmcprograms = tvb_get_bits8(tvb,l_offset, 8);
                l_offset+=6;
            }

            if (numbcmcprograms != 0)
            {

                proto_tree_add_bits_item(subtree1, hf_cdma2k_Bcmc_Program_Id_Len, tvb, l_offset, 5, ENC_BIG_ENDIAN);
                bcmc_program_id = tvb_get_bits8(tvb,l_offset, 5);
                l_offset+=5;

                proto_tree_add_bits_item(subtree1, hf_cdma2k_Bcmc_Program_Id, tvb, l_offset, bcmc_program_id+1, ENC_BIG_ENDIAN);
                l_offset+=bcmc_program_id+1;

                proto_tree_add_bits_item(subtree1, hf_cdma2k_Bcmc_Flow_Discriminator_Len, tvb, l_offset, 3, ENC_BIG_ENDIAN);
                bcmcflowdiscriminatorlen = tvb_get_bits8(tvb,l_offset, 3);/* Extract  Bcmc_Flow_Discriminator_Len */
                l_offset+=3;

                if (bcmcflowdiscriminatorlen != 0)
                {
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Num_Flow_Discriminator, tvb, l_offset, bcmcflowdiscriminatorlen, ENC_BIG_ENDIAN);
                    l_offset+=bcmcflowdiscriminatorlen;
                }

                proto_tree_add_bits_item(subtree1, hf_cdma2k_Bcmc_Flow_Discriminator, tvb, l_offset, bcmcflowdiscriminatorlen, ENC_BIG_ENDIAN);
                l_offset+=bcmcflowdiscriminatorlen;

                proto_tree_add_bits_item(subtree1, hf_cdma2k_Same_As_Previous_Bcmc_Flow, tvb, l_offset, 1, ENC_BIG_ENDIAN);
                sameaspreviousbcmcflow = tvb_get_bits8(tvb,l_offset, 1);
                l_offset+=1;

                if (sameaspreviousbcmcflow == 0)
                {
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Clear_Retry_Delay, tvb, l_offset, 1, ENC_BIG_ENDIAN);
                    clearretrydelay = tvb_get_bits8(tvb,l_offset, 1);
                    l_offset+=1;
                }

                if ((sameaspreviousbcmcflow == 0) || (clearretrydelay == 0))
                {
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Bcmc_Reason, tvb, l_offset, 4, ENC_BIG_ENDIAN);
                    l_offset+=4;
                }

                proto_tree_add_bits_item(subtree1, hf_cdma2k_Bcmc_Retry_Delay, tvb, l_offset, 8, ENC_BIG_ENDIAN);
                l_offset+=8;
            }
            break;
        }

        case 36:
        {
            proto_item_append_text(item, " : FAST CALL SETUP Order ");

            proto_tree_add_bits_item(subtree1, hf_cdma2k_Ordq, tvb, l_offset, 8, ENC_BIG_ENDIAN);
            ordq = tvb_get_bits8(tvb, l_offset, 1);
            l_offset += 8;

            proto_tree_add_bits_item(subtree1, hf_cdma2k_Rsc_Mode_Supported, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            rsc_mode_supported = tvb_get_bits8(tvb, l_offset, 1);
            l_offset += 1;

            if (rsc_mode_supported == 1)
            {
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Max_Rsc_End_Time_Unit, tvb, l_offset, 2, ENC_BIG_ENDIAN);
                l_offset += 2;

                proto_tree_add_bits_item(subtree1, hf_cdma2k_Max_Rsc_End_Time_Value, tvb, l_offset, 4, ENC_BIG_ENDIAN);
                l_offset += 4;

                proto_tree_add_bits_item(subtree1, hf_cdma2k_Ignore_Qpch, tvb, l_offset, 1, ENC_BIG_ENDIAN);
                l_offset += 1;


            }

            if ((ordq == 0) && (rsc_mode_supported == 1))
            {
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Req_Rsci, tvb, l_offset, 4, ENC_BIG_ENDIAN);
                l_offset += 4;
            }

            proto_tree_add_bits_item(subtree1, hf_cdma2k_Rer_Mode_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            rer_mode_incl = tvb_get_bits8(tvb, l_offset, 1);
            l_offset += 1;

            if (rer_mode_incl == 1)
            {
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Rer_Mode_Enabled, tvb, l_offset, 1, ENC_BIG_ENDIAN);
                rer_mode_enabled = tvb_get_bits8(tvb, l_offset, 1);
                l_offset += 1;
            }

            proto_tree_add_bits_item(subtree1, hf_cdma2k_Rer_Max_Num_Msg_Idx, tvb, l_offset, 3, ENC_BIG_ENDIAN);
            l_offset += 3;

            proto_tree_add_bits_item(subtree1, hf_cdma2k_Rer_Time, tvb, l_offset, 3, ENC_BIG_ENDIAN);
            rer_time = tvb_get_bits8(tvb, l_offset, 3);
            l_offset += 3;

            if ((rer_time != 7) && (rer_mode_enabled == 1))
            {
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Rer_Time_Unit, tvb, l_offset, 2, ENC_BIG_ENDIAN);
                l_offset += 2;
            }

            proto_tree_add_bits_item(subtree1, hf_cdma2k_Max_Rer_Pilot_List_Size, tvb, l_offset, 3, ENC_BIG_ENDIAN);
            l_offset += 3;

            proto_tree_add_bits_item(subtree1, hf_cdma2k_Tkz_Mode_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            tkz_mode_incl = tvb_get_bits8(tvb, l_offset, 1);
            l_offset += 1;

            if (tkz_mode_incl == 1)
            {
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Tkz_Mode_Enabled, tvb, l_offset, 1, ENC_BIG_ENDIAN);
                l_offset += 1;
            }

            proto_tree_add_bits_item(subtree1, hf_cdma2k_Tkz_Max_Num_Msg_Idx, tvb, l_offset, 3, ENC_BIG_ENDIAN);
            l_offset += 3;

            proto_tree_add_bits_item(subtree1, hf_cdma2k_Tkz_Update_Prd, tvb, l_offset, 4, ENC_BIG_ENDIAN);
            l_offset += 4;

            proto_tree_add_bits_item(subtree1, hf_cdma2k_Tkz_List_Len, tvb, l_offset, 4, ENC_BIG_ENDIAN);
            l_offset += 4;

            proto_tree_add_bits_item(subtree1, hf_cdma2k_Tkz_Timer, tvb, l_offset, 8, ENC_BIG_ENDIAN);
            l_offset += 8;
        }
        break;
        case 37:
        {
            proto_item_append_text(item, " : SERVICE STATUS Order ");

            proto_tree_add_bits_item(subtree1, hf_cdma2k_Ordq, tvb, l_offset, 8, ENC_BIG_ENDIAN);
            l_offset+=8;

            proto_tree_add_bits_item(subtree1, hf_cdma2k_Sr_Id_Bitmap, tvb, l_offset, 6, ENC_BIG_ENDIAN);
            l_offset+=6;

            proto_tree_add_bits_item(subtree1, hf_cdma2k_Service_Status, tvb, l_offset, 3, ENC_BIG_ENDIAN);
            l_offset+=3;

            if(l_offset%8 != 0)
            {
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Reserved, tvb, l_offset, (8-(l_offset%8)), ENC_BIG_ENDIAN);
            }
            break;

        }

        case 38:
        {
            proto_item_append_text(item, " : LOCATION SERVICES Order ");

            proto_tree_add_bits_item(subtree1, hf_cdma2k_Ordq, tvb, l_offset, 8, ENC_BIG_ENDIAN);
            l_offset+=8;

            proto_tree_add_bits_item(subtree1, hf_cdma2k_Regulatory_Ind_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            regulatoryindincl = tvb_get_bits8(tvb,l_offset, 1);
            l_offset+=1;

            if (regulatoryindincl == 1)
            {
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Regulatory_Ind, tvb, l_offset, 2, ENC_BIG_ENDIAN);
                l_offset+=2;
            }
            break;
        }

        default:
        {
            proto_item_append_text(item, " : Invalid / Unsupported Order Type");
            break;
        }
    }
    }
    if(l_offset%8 == 0)
        *offset = (l_offset/8);
    else
        *offset = (l_offset/8) + 1;
}


/* Helper function to decode Data Burst Indication Message Parameters */
static void cdma2k_message_DATA_BURST_IND(proto_item *item,tvbuff_t *tvb,proto_tree *tree,guint *offset)
{
    guint16 numOfFields = -1, parmLen = -1;
    guint16 inc = -1, cnt = -1, disp_cnt = -1;
    proto_tree *subtree = NULL, *subtree1 = NULL, *subtree2 = NULL;
    cnt = 1;

    item = proto_tree_add_item(tree,hf_cdma2k_DataBurstIndMsg, tvb, *offset,-1, ENC_NA);
    subtree = proto_item_add_subtree(item, ett_cdma2k_subtree1);
    proto_tree_add_item(subtree, hf_cdma2k_Msg_Number, tvb, *offset,1, ENC_BIG_ENDIAN);
    *offset+=1;
    proto_tree_add_bits_item(subtree, hf_cdma2k_Burst_Type, tvb, *offset*8,6, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(subtree, hf_cdma2k_Num_Msgs, tvb, *offset*8 + 6,8, ENC_BIG_ENDIAN);
    *offset+=1;
    proto_tree_add_bits_item(subtree, hf_cdma2k_Num_Fields, tvb, *offset*8 + 6,8, ENC_BIG_ENDIAN);
    numOfFields = tvb_get_bits8(tvb,*offset*8 + 6,8);
    *offset+=1;

    item = proto_tree_add_item(subtree, hf_cdma2k_Chari_Data, tvb, *offset,-1, ENC_NA);
    subtree1 = proto_item_add_subtree(item, ett_cdma2k_subtree2);
    proto_tree_add_bits_item(subtree1, hf_cdma2k_Msg_Identifier, tvb, *offset*8 + 6,8, ENC_BIG_ENDIAN);
    *offset+=1;
    numOfFields-=1;

    while(numOfFields > 0)
    {
        item = proto_tree_add_bits_item(subtree1, hf_cdma2k_Parm_Id, tvb, *offset*8 + 6,8, ENC_BIG_ENDIAN);
        subtree2 = proto_item_add_subtree(item, ett_cdma2k_subtree2);
        *offset+=1;
        numOfFields-=1;
        proto_tree_add_bits_item(subtree2,hf_cdma2k_Parm_Length, tvb, *offset*8 + 6,8, ENC_BIG_ENDIAN);
        parmLen = tvb_get_bits8(tvb,*offset*8 + 6,8);
        *offset+=1;
        numOfFields-=1;

        if (cnt*32 < parmLen)
        {
                    disp_cnt = 32;
                }
                else
                {
                    disp_cnt = parmLen+1;
                }

        item = proto_tree_add_item(subtree2,hf_cdma2k_Parm_Value, tvb, *offset,disp_cnt, ENC_NA);

        for (inc = 0; inc < parmLen; inc++)
        {
            proto_item_append_text(item," 0x%02x ",tvb_get_bits8(tvb,*offset*8 + 6,8));
            *offset+=1;

            if(inc%8 == 7)
            proto_item_append_text(item,"\n");

            if(inc%32 == 31)
            {
                    if (cnt*32 < parmLen)
                        {
                            disp_cnt = 32;
                        }
                        else
                        {
                            disp_cnt = (parmLen - cnt*32);
                        }

                item = proto_tree_add_item(subtree2,hf_cdma2k_Parm_Value, tvb, *offset,disp_cnt, ENC_NA);
                proto_item_append_text(item,"cont..." );
                            cnt+=1;
            }
        }
        numOfFields-=parmLen;
    }
    *offset+=1;
}

static void cdma2k_message_ORIGINATION(proto_item *item,tvbuff_t *tvb,proto_tree *tree,guint *offset,guint16 authIncl,guint16 oneXPrev)
{
    guint16 prevInUse = -1, mob_P_Rev_Rx = -1, Prev_Nid_Incl = -1;
    guint16 Sync_Id_Len = -1, Prev_Pzid_Incl= -1, For_FchLen = -1,Rev_FchLen = -1;
    guint16 uzid_Incl = -1, GeoLoc_Incl = -1, l_offset = -1, numOfFields = -1, Map_Length = -1, Qos_Parms_Incl= -1;
    guint16 specialService = -1, Wll_Incl = -1,Global_Emergency_call = -1,Sync_Id_Incl = -1,Prev_Sid_Incl = -1;
    guint16 DigitMode = -1, Num_Alt_So = -1, Qos_Parms_Length = -1, Enc_Info_Incl = -1;
    guint16 digitSize = -1, So_Bitmap_Ind = -1, Dcch_supported = -1;
    guint16 Fch_supported = -1, Rev_DcchLen = -1, rea = -1, ecmea = -1, For_DcchLen = -1;

    proto_tree *subtree = NULL,*subtree1 = NULL, *subtree4 = NULL,*subtree3 = NULL;
    proto_item *item1 = NULL, *item2 = NULL, *item4 = NULL;

    /*iws_Mob_P_Rev_In_Use = 7;*/

    l_offset = *offset*8;

    item = proto_tree_add_item(tree,hf_cdma2k_OrigMsg, tvb, l_offset/8,-1, ENC_NA);
    subtree   = proto_item_add_subtree(item, ett_cdma2k_subtree1);
    proto_tree_add_bits_item(subtree, hf_cdma2k_Mob_Term, tvb, l_offset, 1, ENC_BIG_ENDIAN);
    l_offset +=1;
    proto_tree_add_bits_item(subtree, hf_cdma2k_Slot_Cycle_Index, tvb, l_offset, 3, ENC_BIG_ENDIAN);
    l_offset +=3;
    proto_tree_add_bits_item(subtree, hf_cdma2k_Mob_P_Rev, tvb, l_offset, 8, ENC_BIG_ENDIAN);
    mob_P_Rev_Rx = tvb_get_bits8(tvb,l_offset, 8);
    l_offset +=8;

    prevInUse = ((oneXPrev >= mob_P_Rev_Rx) ? mob_P_Rev_Rx : oneXPrev);

    if(prevInUse == 1)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_Ext_Scm, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset +=1;
         /*Jump Over the one bit Reserved Field*/
        proto_tree_add_bits_item(subtree, hf_cdma2k_Reserved, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset +=1;
        proto_tree_add_bits_item(subtree, hf_cdma2k_Sloted_Mode, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset +=1;
         /*Jump Over the five bit Reserved Field*/
        proto_tree_add_bits_item(subtree, hf_cdma2k_Reserved, tvb, l_offset, 5, ENC_BIG_ENDIAN);
        l_offset +=5;
    }
    else
    {
        dissect_cdma2000_scm(tvb, subtree, l_offset);
        l_offset +=8;
    }

    proto_tree_add_bits_item(subtree, hf_cdma2k_Request_Mode, tvb, l_offset, 3, ENC_BIG_ENDIAN);
    l_offset +=3;
    proto_tree_add_bits_item(subtree, hf_cdma2k_Special_Service, tvb, l_offset, 1, ENC_BIG_ENDIAN);
    specialService = tvb_get_bits8(tvb,l_offset, 1);
    l_offset +=1;

    if (specialService == 1)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_service_option, tvb, l_offset, 16, ENC_BIG_ENDIAN);
        l_offset +=16;
    }

    proto_tree_add_bits_item(subtree, hf_cdma2k_pm, tvb, l_offset, 1, ENC_BIG_ENDIAN);
    l_offset +=1;
    proto_tree_add_bits_item(subtree, hf_cdma2k_digit_mode, tvb, l_offset, 1, ENC_BIG_ENDIAN);
    DigitMode = tvb_get_bits8(tvb,l_offset, 1);
    l_offset +=1;

    if (DigitMode == 1)
    {
/*    if(mob_P_Rev_Rx > 8)
        { */
            proto_tree_add_bits_item(subtree, hf_cdma2k_Number_Type, tvb, l_offset, 3, ENC_BIG_ENDIAN);
            l_offset +=3;
/*      } */
        proto_tree_add_bits_item(subtree, hf_cdma2k_Number_Plan, tvb, l_offset, 4, ENC_BIG_ENDIAN);
        l_offset +=4;
    }

    proto_tree_add_bits_item(subtree, hf_cdma2k_More_Fields, tvb, l_offset, 1, ENC_BIG_ENDIAN);
    l_offset += 1;
    proto_tree_add_bits_item(subtree, hf_cdma2k_Num_Fields, tvb, l_offset, 8, ENC_BIG_ENDIAN);
    numOfFields = tvb_get_bits8(tvb,l_offset, 8);
    l_offset += 8;

    if(numOfFields > 0)
    {
        item2 = proto_tree_add_item(subtree, hf_cdma2k_Chari_Data, tvb, (l_offset/8),1, ENC_NA);
        proto_item_append_text(item2," - Dialed Digits :");
        while(numOfFields > 0)
        {
            if(DigitMode == 1)
            {
                digitSize = 8;
                proto_item_append_text(item2," 0x%02x",tvb_get_bits8(tvb,l_offset, digitSize));
                l_offset+=digitSize;
            }
            else if(DigitMode == 0)
            {
                digitSize = 4;
                proto_item_append_text(item2," 0x%x",tvb_get_bits8(tvb,l_offset, digitSize));
                l_offset+=digitSize;
            }
            numOfFields-=1;
        }
    }
    proto_tree_add_bits_item(subtree, hf_cdma2k_Nar_An_Cap, tvb, l_offset, 1, ENC_BIG_ENDIAN);
    l_offset += 1;
    proto_tree_add_bits_item(subtree, hf_cdma2k_Paca_Reorig, tvb, l_offset, 1, ENC_BIG_ENDIAN);
    l_offset += 1;
    proto_tree_add_bits_item(subtree, hf_cdma2k_Return_Cause, tvb, l_offset, 4, ENC_BIG_ENDIAN);
    l_offset += 4;
    proto_tree_add_bits_item(subtree, hf_cdma2k_More_Records, tvb, l_offset, 1, ENC_BIG_ENDIAN);
    l_offset += 1;

    if (prevInUse < 7 && authIncl == 1)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_encryption_supported, tvb, l_offset, 4, ENC_BIG_ENDIAN);
        l_offset += 4;
    }
    proto_tree_add_bits_item(subtree, hf_cdma2k_Paca_Supported, tvb, l_offset, 1, ENC_BIG_ENDIAN);
    l_offset += 1;
    proto_tree_add_bits_item(subtree, hf_cdma2k_num_alt_so, tvb, l_offset, 3, ENC_BIG_ENDIAN);
    Num_Alt_So = tvb_get_bits8(tvb,l_offset, 3);
    l_offset += 3;
    while (Num_Alt_So > 0)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_Alt_So, tvb, l_offset, 16, ENC_BIG_ENDIAN);
        l_offset+=16;
        Num_Alt_So--;
    }
    if (prevInUse >= 6)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_DRS, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset +=1;
        proto_tree_add_bits_item(subtree, hf_cdma2k_Uzid_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        uzid_Incl = tvb_get_bits8(tvb,l_offset, 1);
        l_offset +=1;
        if (uzid_Incl == 1)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Uzid, tvb, l_offset, 16, ENC_BIG_ENDIAN);
            l_offset+=16;
        }
        proto_tree_add_bits_item(subtree, hf_cdma2k_Ch_Ind, tvb, l_offset, 2, ENC_BIG_ENDIAN);
        l_offset+=2;
        proto_tree_add_bits_item(subtree, hf_cdma2k_SR_ID, tvb, l_offset, 3, ENC_BIG_ENDIAN);
        l_offset+=3;
        proto_tree_add_bits_item(subtree, hf_cdma2k_Otd_Supported, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset +=1;
        proto_tree_add_bits_item(subtree, hf_cdma2k_Qpch_Supported, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset +=1;
        proto_tree_add_bits_item(subtree, hf_cdma2k_Enhanced_Rc, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset +=1;
        proto_tree_add_bits_item(subtree, hf_cdma2k_For_Rc_Pref, tvb, l_offset, 5, ENC_BIG_ENDIAN);
        l_offset +=5;
        proto_tree_add_bits_item(subtree, hf_cdma2k_Rev_Rc_Pref, tvb, l_offset, 5, ENC_BIG_ENDIAN);
        l_offset +=5;
        proto_tree_add_bits_item(subtree, hf_cdma2k_Fch_Supported, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        Fch_supported = tvb_get_bits8(tvb,l_offset, 1);
        l_offset +=1;
        if(Fch_supported == 1)
        {
            item4 = proto_tree_add_item(subtree, hf_cdma2k_Fch_capability_type_specific_Fields, tvb, (l_offset/8),1, ENC_NA);
            subtree4 = proto_item_add_subtree(item4, ett_cdma2k_subtree2);
            proto_tree_add_bits_item(subtree4,hf_cdma2k_Fch_Frame_Size, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            l_offset +=1;
            proto_tree_add_bits_item(subtree4,hf_cdma2k_For_Fch_Len, tvb, l_offset, 3, ENC_BIG_ENDIAN);
            For_FchLen = tvb_get_bits8(tvb,l_offset, 3);
            l_offset+=3;
            Map_Length = 3*For_FchLen ;
            if(Map_Length > 0)
            {
                proto_tree_add_bits_item(subtree4,hf_cdma2k_For_Fch_Rc_Map, tvb, l_offset, Map_Length, ENC_BIG_ENDIAN);
                l_offset+= Map_Length;
            }
            proto_tree_add_bits_item(subtree4,hf_cdma2k_Rev_Fch_Len, tvb, l_offset, 3, ENC_BIG_ENDIAN);
            Rev_FchLen = tvb_get_bits8(tvb,l_offset, 3);
            l_offset+=3;
            Map_Length = 3*Rev_FchLen ;
            if(Map_Length > 0)
            {
                proto_tree_add_bits_item(subtree4,hf_cdma2k_Rev_Fch_Rc_Map, tvb, l_offset, Map_Length, ENC_BIG_ENDIAN);
                l_offset+= Map_Length;
            }
        }
        proto_tree_add_bits_item(subtree, hf_cdma2k_Dcch_Supported, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        Dcch_supported = tvb_get_bits8(tvb,l_offset, 1);
        l_offset +=1;

        if(Dcch_supported == 1)
        {
            item4 = proto_tree_add_item(subtree, hf_cdma2k_Dcch_capability_type_specific_Fields, tvb, (l_offset/8),1, ENC_NA);
            subtree3 = proto_item_add_subtree(item4, ett_cdma2k_subtree2);
            proto_tree_add_bits_item(subtree3,hf_cdma2k_Dcch_Frame_Size, tvb, l_offset, 2, ENC_BIG_ENDIAN);
            l_offset +=2;
            proto_tree_add_bits_item(subtree3,hf_cdma2k_For_Dcch_Len, tvb, l_offset, 3, ENC_BIG_ENDIAN);
            For_DcchLen = tvb_get_bits8(tvb,l_offset, 3);
            l_offset+=3;
            Map_Length = 3*For_DcchLen ;
            if(Map_Length > 0)
            {
                proto_tree_add_bits_item(subtree3,hf_cdma2k_For_Dcch_Rc_Map, tvb, l_offset, Map_Length, ENC_BIG_ENDIAN);
                l_offset+= Map_Length;
            }
            proto_tree_add_bits_item(subtree3,hf_cdma2k_Rev_Dcch_Len, tvb, l_offset, 3, ENC_BIG_ENDIAN);
            Rev_DcchLen = tvb_get_bits8(tvb,l_offset, 3);
            l_offset+=3;
            Map_Length = 3*Rev_DcchLen ;
            if(Map_Length > 0)
            {
                proto_tree_add_bits_item(subtree3,hf_cdma2k_Rev_Dcch_Rc_Map, tvb, l_offset, Map_Length, ENC_BIG_ENDIAN);
                l_offset+= Map_Length;
            }
        }

        proto_tree_add_bits_item(subtree, hf_cdma2k_GeoLoc_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        GeoLoc_Incl = tvb_get_bits8(tvb,l_offset, 1);
        l_offset += 1;
        if(GeoLoc_Incl == 1)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_GeoLoc_Type, tvb, l_offset, 3, ENC_BIG_ENDIAN);
            l_offset += 3;
        }

        proto_tree_add_bits_item(subtree, hf_cdma2k_Rev_Fch_Gating_Req, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset += 1;
        if(prevInUse >= 7)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Orig_Reason, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            l_offset += 1;
            proto_tree_add_bits_item(subtree, hf_cdma2k_Orig_Count, tvb, l_offset, 2, ENC_BIG_ENDIAN);
                        l_offset += 2;
            proto_tree_add_bits_item(subtree, hf_cdma2k_Sts_Supported, tvb, l_offset, 1, ENC_BIG_ENDIAN);
                        l_offset += 1;
            proto_tree_add_bits_item(subtree, hf_cdma2k_ThreeXCchSupported, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            l_offset += 1;
            proto_tree_add_bits_item(subtree, hf_cdma2k_Wll_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            Wll_Incl = tvb_get_bits8(tvb,l_offset, 1);
                        l_offset += 1;
            if(Wll_Incl == 1)
            {
                proto_tree_add_bits_item(subtree, hf_cdma2k_Wll_Device_Type, tvb, l_offset, 3, ENC_BIG_ENDIAN);
                l_offset += 3;

            }
            proto_tree_add_bits_item(subtree, hf_cdma2k_Global_Emergency_Call, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            Global_Emergency_call = tvb_get_bits8(tvb,l_offset, 1);
            l_offset += 1;
            if(Global_Emergency_call == 1)
            {
                proto_tree_add_bits_item(subtree, hf_cdma2k_Ms_Init_Pos_Loc_Ind, tvb, l_offset, 1, ENC_BIG_ENDIAN);
                l_offset += 1;
            }
            proto_tree_add_bits_item(subtree, hf_cdma2k_Qos_Parms_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            Qos_Parms_Incl = tvb_get_bits8(tvb,l_offset, 1);
            l_offset += 1;
            if(Qos_Parms_Incl != 0)
            {
                proto_tree_add_bits_item(subtree, hf_cdma2k_Qos_Parms_Length, tvb, l_offset, 5, ENC_BIG_ENDIAN);
                Qos_Parms_Length = tvb_get_bits8(tvb,l_offset, 5);
                l_offset += 5;
                while (Qos_Parms_Length > 0)
                {
                    item4 = proto_tree_add_item(subtree1, hf_cdma2k_Qos_Parms, tvb, (l_offset/8),8, ENC_BIG_ENDIAN);
                    subtree1 = proto_item_add_subtree(item4, ett_cdma2k_subtree2);
                    proto_item_append_text(item4," 0x%02x",tvb_get_bits8(tvb,l_offset, 8));
                    l_offset+=8;
                    Qos_Parms_Length -=1;
                }
            }
            proto_tree_add_bits_item(subtree, hf_cdma2k_Enc_Info_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            Enc_Info_Incl = tvb_get_bits8(tvb,l_offset, 1);
            l_offset+=1;
            if(Enc_Info_Incl != 0)
            {
                item2 = proto_tree_add_item(subtree, hf_cdma2k_Sig_Encrypt_Supp, tvb, (l_offset/8),1, ENC_NA);
                subtree1 = proto_item_add_subtree(item2,ett_cdma2k_subtree2);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Cmea, tvb, l_offset, 1, ENC_BIG_ENDIAN);
                l_offset+=1;
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Ecmea, tvb, l_offset, 1, ENC_BIG_ENDIAN);
                ecmea = tvb_get_bits8(tvb,l_offset, 1);
                l_offset+=1;
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Rea, tvb, l_offset, 1, ENC_BIG_ENDIAN);
                rea = tvb_get_bits8(tvb,l_offset, 1);
                l_offset+=1;
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Reserved, tvb, l_offset, 5, ENC_BIG_ENDIAN);
                l_offset+=5;
                proto_tree_add_bits_item(subtree, hf_cdma2k_DSig_Encrypt_Req, tvb, l_offset, 1, ENC_BIG_ENDIAN);
                l_offset+=1;
                proto_tree_add_bits_item(subtree, hf_cdma2k_CSig_Encrypt_Req, tvb, l_offset, 1, ENC_BIG_ENDIAN);
                l_offset+=1;
                if(ecmea == 1 || rea == 1)
                {
                    proto_tree_add_bits_item(subtree, hf_cdma2k_New_Sseq_H, tvb, l_offset, 24, ENC_BIG_ENDIAN);
                    l_offset+=24;
                    proto_tree_add_bits_item(subtree, hf_cdma2k_New_Sseq_H_Sig, tvb, l_offset, 8, ENC_BIG_ENDIAN);
                    l_offset+=8;
                }

                proto_tree_add_bits_item(subtree, hf_cdma2k_Ui_Encrypt_Req, tvb, l_offset, 1, ENC_BIG_ENDIAN);
                l_offset+=1;
                proto_tree_add_bits_item(subtree, hf_cdma2k_Ui_Encrypt_Sup, tvb, l_offset, 8, ENC_BIG_ENDIAN);
                        l_offset+=8;
            }
            proto_tree_add_bits_item(subtree, hf_cdma2k_Sync_Id_Incl, tvb, l_offset, 1, ENC_NA);
            Sync_Id_Incl = tvb_get_bits8(tvb,l_offset, 1);
            l_offset +=1;
            if(Sync_Id_Incl != 0)
            {
                proto_tree_add_bits_item(subtree, hf_cdma2k_Sync_Id_Len, tvb, l_offset, 4, ENC_BIG_ENDIAN);
                Sync_Id_Len = tvb_get_bits8(tvb,l_offset, 4);
                l_offset +=4;
                while (Sync_Id_Len > 0)
                {
                    item1 = proto_tree_add_item(subtree1, hf_cdma2k_Sync_Id, tvb, (l_offset/8),Sync_Id_Len, ENC_NA);
                    /*subtree1 = proto_item_add_subtree(item1, ett_cdma2k_subtree2);*/
                    proto_item_append_text(item1," 0x%02x",tvb_get_bits8(tvb,l_offset, 8));
                    l_offset+=8;
                    Sync_Id_Len -=1;
                }
            }
            proto_tree_add_bits_item(subtree, hf_cdma2k_Prev_Sid_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            Prev_Sid_Incl = tvb_get_bits8(tvb,l_offset, 1);
            l_offset+=1;
            if (Prev_Sid_Incl != 0)
            {
                proto_tree_add_bits_item(subtree, hf_cdma2k_Prev_Sid, tvb, l_offset, 15, ENC_BIG_ENDIAN);
                l_offset+=15;
            }
            proto_tree_add_bits_item(subtree, hf_cdma2k_Prev_Nid_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
                        Prev_Nid_Incl = tvb_get_bits8(tvb,l_offset, 1);
                        l_offset+=1;
            if (Prev_Nid_Incl != 0)
            {
                proto_tree_add_bits_item(subtree, hf_cdma2k_Prev_Nid, tvb, l_offset, 16, ENC_BIG_ENDIAN);
                                l_offset+=16;
            }
            proto_tree_add_bits_item(subtree, hf_cdma2k_Prev_Pzid_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
                        Prev_Pzid_Incl = tvb_get_bits8(tvb,l_offset, 1);
                        l_offset+=1;
            if (Prev_Pzid_Incl != 0)
                        {
                                proto_tree_add_bits_item(subtree, hf_cdma2k_Prev_Pzid, tvb, l_offset, 8, ENC_BIG_ENDIAN);
                                l_offset+=8;
                        }
            proto_tree_add_bits_item(subtree, hf_cdma2k_So_Bitmap_Ind, tvb, l_offset, 2, ENC_BIG_ENDIAN);
            So_Bitmap_Ind = tvb_get_bits8(tvb,l_offset, 2);
            l_offset+=2;
            if (So_Bitmap_Ind > 0)
            {
                proto_tree_add_bits_item(subtree, hf_cdma2k_So_Group_Num, tvb, l_offset, 5, ENC_BIG_ENDIAN);
                l_offset+=5;
                proto_tree_add_bits_item(subtree, hf_cdma2k_So_Bitmap, tvb, l_offset, 4*So_Bitmap_Ind, ENC_BIG_ENDIAN);
                l_offset+=4*So_Bitmap_Ind;
            }
        }
    }

         /*Currently IWS Stack supports only till Mobile Protocol Revision Value 7*/
/*  if (mob_P_Rev_Rx >= 8)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_SDB_Desired, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;
        proto_tree_add_bits_item(subtree, hf_cdma2k_Alt_Band_Class_Sup, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;
    }
    if (mob_P_Rev_Rx >= 9)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_Msg_Int_Info_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        msg_Int_Info_Incl = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;
        if (msg_Int_Info_Incl == 1)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Sig_Integrity_Sup_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            sigIntegritySupIncl = tvb_get_bits8(tvb,l_offset, 1);
            l_offset+=1;
            if(sigIntegritySupIncl ==1)
            {
                proto_tree_add_bits_item(subtree, hf_cdma2k_Sig_Integrity_Sup, tvb, l_offset, 8, ENC_BIG_ENDIAN);
                l_offset+=8;
                proto_tree_add_bits_item(subtree, hf_cdma2k_Sig_Integrity_Req, tvb, l_offset, 3, ENC_BIG_ENDIAN);
                l_offset+=3;
            }
            proto_tree_add_bits_item(subtree, hf_cdma2k_New_Key_Id, tvb, l_offset, 2, ENC_BIG_ENDIAN);
            l_offset+=2;
            proto_tree_add_bits_item(subtree, hf_cdma2k_New_Sseq_H_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            newSseqHIncl = tvb_get_bits8(tvb,l_offset, 1);
            l_offset+=1;
            if (newSseqHIncl == 1)
            {
                proto_tree_add_bits_item(subtree, hf_cdma2k_New_Sseq_H, tvb, l_offset, 24, ENC_BIG_ENDIAN);
                l_offset+=24;
                proto_tree_add_bits_item(subtree, hf_cdma2k_New_Sseq_H_Sig, tvb, l_offset, 8, ENC_BIG_ENDIAN);
                l_offset+=8;
            }
        }
        proto_tree_add_bits_item(subtree, hf_cdma2k_For_Pdch_Supported, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        forPdchSupported = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;
        if(forPdchSupported == 1)
        {
            item2 = proto_tree_add_item(subtree, hf_cdma2k_Type_Specific_Fields, tvb, (l_offset/8),1, ENC_NA);
            subtree1 = proto_item_add_subtree(item2,ett_cdma2k_subtree2);
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Ack_Delay, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            l_offset+=1;
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Num_Arq_Chan, tvb, l_offset, 2, ENC_BIG_ENDIAN);
            l_offset+=2;
            proto_tree_add_bits_item(subtree1, hf_cdma2k_For_Pdch_Len, tvb, l_offset, 2, ENC_BIG_ENDIAN);
            forPdchLen = tvb_get_bits8(tvb,l_offset, 2);
            l_offset+=2;
            proto_tree_add_bits_item(subtree1, hf_cdma2k_For_Pdch_Rc_Map, tvb, l_offset, 3*(forPdchLen+1), ENC_BIG_ENDIAN);
            l_offset+=3*(forPdchLen+1);
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Ch_Config_Sup_Map_Len, tvb, l_offset, 2, ENC_BIG_ENDIAN);
            chConfigSupMapLen = tvb_get_bits8(tvb,l_offset, 2);
            l_offset+=2;
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Ch_Config_Sup_Map, tvb, l_offset, 3*(chConfigSupMapLen + 1), ENC_BIG_ENDIAN);
            l_offset+=3*(chConfigSupMapLen + 1);
        }
    }
    if(chInd == 0)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_Ext_Ch_Ind, tvb, l_offset, 5, ENC_BIG_ENDIAN);
        l_offset+=5;
    }*/

    if(l_offset%8 == 0)
        *offset = (l_offset/8);
    else
        *offset = (l_offset/8) + 1;
}


/* Helper function to decode Authentication Challenge Response Message Parameters */
static void cdma2k_message_AUTH_CHALL_RSP(proto_item *item,tvbuff_t *tvb,proto_tree *tree,guint *offset)
{
    proto_tree *subtree = NULL;
    item = proto_tree_add_item(tree,hf_cdma2k_AuthChallRspMsg, tvb, *offset,-1, ENC_NA);
    subtree = proto_item_add_subtree(item, ett_cdma2k_subtree1);
    proto_tree_add_bits_item(subtree, hf_cdma2k_Authu, tvb, *offset*8,18, ENC_BIG_ENDIAN);
    *offset+=3;
}


/* Helper function to decode Data Burst Command Message Parameters */
static void cdma2k_message_DATA_BURST_CMD(proto_item *item,tvbuff_t *tvb,proto_tree *tree,guint *offset)
{
    guint16 numOfFields = -1, parmLen = -1;
    guint16 inc = -1, cnt = -1, disp_cnt = -1;
    proto_tree *subtree = NULL, *subtree1 = NULL, *subtree2 = NULL;
    cnt = 1;

    item = proto_tree_add_item(tree,hf_cdma2k_DataBurstCmdMsg, tvb, *offset,-1, ENC_NA);
    subtree = proto_item_add_subtree(item, ett_cdma2k_subtree1);
    proto_tree_add_item(subtree, hf_cdma2k_Msg_Number, tvb, *offset,1, ENC_BIG_ENDIAN);
    *offset+=1;
    proto_tree_add_bits_item(subtree, hf_cdma2k_Burst_Type, tvb, *offset*8,6, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(subtree, hf_cdma2k_Num_Msgs, tvb, *offset*8 + 6,8, ENC_BIG_ENDIAN);
    *offset+=1;
    proto_tree_add_bits_item(subtree, hf_cdma2k_Num_Fields, tvb, *offset*8 + 6,8, ENC_BIG_ENDIAN);
    numOfFields = tvb_get_bits8(tvb,*offset*8 + 6,8);
    *offset+=1;

    item = proto_tree_add_item(subtree, hf_cdma2k_Chari_Data, tvb, *offset,-1, ENC_NA);
    subtree1 = proto_item_add_subtree(item, ett_cdma2k_subtree2);
    proto_tree_add_bits_item(subtree1, hf_cdma2k_Msg_Identifier, tvb, *offset*8 + 6,8, ENC_BIG_ENDIAN);
    *offset+=1;
    numOfFields-=1;

    while(numOfFields > 0)
    {
        item = proto_tree_add_bits_item(subtree1, hf_cdma2k_Parm_Id, tvb, *offset*8 + 6,8, ENC_BIG_ENDIAN);
        subtree2 = proto_item_add_subtree(item, ett_cdma2k_subtree2);
        *offset+=1;
        numOfFields-=1;
        proto_tree_add_bits_item(subtree2,hf_cdma2k_Parm_Length, tvb, *offset*8 + 6,8, ENC_BIG_ENDIAN);
        parmLen = tvb_get_bits8(tvb,*offset*8 + 6,8);
        *offset+=1;
        numOfFields-=1;

            if (cnt*32 < parmLen)
                {
                    disp_cnt = 32;
                }
                else
                {
                    disp_cnt = parmLen+1;
                }
        item = proto_tree_add_item(subtree2,hf_cdma2k_Parm_Value, tvb, *offset,disp_cnt, ENC_NA);

        for (inc = 0; inc < parmLen; inc++)
        {
            proto_item_append_text(item," 0x%02x ",tvb_get_bits8(tvb,*offset*8 + 6,8));
            *offset+=1;


            if(inc%8 == 7)
            proto_item_append_text(item,"\n");

            if(inc%32 == 31)
            {
                    if (cnt*32 < parmLen)
                        {
                            disp_cnt = 32;
                        }
                        else
                        {
                            disp_cnt = (parmLen - cnt*32);
                        }

                item = proto_tree_add_item(subtree2,hf_cdma2k_Parm_Value, tvb, *offset,disp_cnt, ENC_NA);
                proto_item_append_text(item,"cont..." );
                            cnt+=1;
            }
        }
        numOfFields-=parmLen;
    }
    *offset+=1;
}


/* Helper function to decode Authentication Challenge Request Message Parameters */
static void cdma2k_message_AUTH_CHALL_REQ(proto_item *item,tvbuff_t *tvb,proto_tree *tree,guint *offset)
{
    proto_tree *subtree = NULL;
    item = proto_tree_add_item(tree,hf_cdma2k_AuthChallReqMsg, tvb, *offset,-1, ENC_NA);
    subtree = proto_item_add_subtree(item, ett_cdma2k_subtree1);
    proto_tree_add_bits_item(subtree, hf_cdma2k_Randu, tvb, *offset*8,24, ENC_BIG_ENDIAN);
    *offset+=3;
    proto_tree_add_item(subtree, hf_cdma2k_Gen_Cmea_Key, tvb, *offset,1, ENC_BIG_ENDIAN);
    *offset+=1;
}


/* Helper function to decode General Page Request Message Parameters */
static void cdma2k_message_GEN_PAGE_REQ(proto_item *item,tvbuff_t *tvb,proto_tree *tree,guint *offset,guint16 l3PduLen)
{
    proto_tree *subtree = NULL;
    item = proto_tree_add_item(tree,hf_cdma2k_GenPageReqMsg, tvb, *offset,-1, ENC_NA);
    subtree = proto_item_add_subtree(item, ett_cdma2k_subtree1);

    if (l3PduLen)
    {
        proto_tree_add_item(subtree, hf_cdma2k_service_option, tvb, *offset,2, ENC_BIG_ENDIAN);
        *offset+=2;
    }
}


/* Helper Function to decode Page Response Message Parameters */
static void cdma2k_message_PAGE_RESPONSE(proto_item *item, tvbuff_t *tvb,proto_tree *tree,guint *offset,guint16 authIncl,guint16 oneXPrev)
{
    guint16 fchSupported = -1, dcchSupported = -1,numAltSo = -1, soBitmapInd = -1;
    guint16 forFchLen = -1, revFchLen = -1, forDcchLen = -1, revDcchLen = -1 , syncIdLen =-1;
    guint16 uzidIncl = -1, wllIncl = -1, encInfoIncl = -1, syncIdIncl = -1;
    guint16 l_offset = -1, rea = -1, ecmea = -1;
    guint16 prevInUse = -1, mob_P_Rev_Rx = -1;

    proto_tree *subtree = NULL, *subtree1 = NULL;
    proto_item *item1 = NULL;

    /*iws_Mob_P_Rev_In_Use = 7;*/

    item = proto_tree_add_item(tree,hf_cdma2k_PageRspMsg, tvb, *offset,-1, ENC_NA);
    subtree = proto_item_add_subtree(item, ett_cdma2k_subtree1);
    proto_tree_add_bits_item(subtree, hf_cdma2k_Mob_Term, tvb, *offset*8,1, ENC_BIG_ENDIAN);
    l_offset = *offset*8 + 1;
    proto_tree_add_bits_item(subtree, hf_cdma2k_Slot_Cycle_Index, tvb, l_offset, 3, ENC_BIG_ENDIAN);
    l_offset+= 3;
    proto_tree_add_bits_item(subtree, hf_cdma2k_Mob_P_Rev, tvb, l_offset, 8, ENC_BIG_ENDIAN);
    mob_P_Rev_Rx = tvb_get_bits8(tvb,l_offset, 8);
    l_offset+= 8;

    prevInUse = ((oneXPrev >= mob_P_Rev_Rx) ? mob_P_Rev_Rx : oneXPrev);

    dissect_cdma2000_scm(tvb, subtree, l_offset);
    l_offset+=8;

    proto_tree_add_bits_item(subtree, hf_cdma2k_Request_Mode, tvb, l_offset, 3, ENC_BIG_ENDIAN);
    l_offset+=3;

    proto_tree_add_bits_item(subtree, hf_cdma2k_service_option , tvb, l_offset, 16, ENC_BIG_ENDIAN);
    l_offset+=16;

    proto_tree_add_bits_item(subtree, hf_cdma2k_pm, tvb, l_offset,  1, ENC_BIG_ENDIAN);
    l_offset+=1;

    proto_tree_add_bits_item(subtree, hf_cdma2k_Nar_An_Cap, tvb, l_offset, 1, ENC_BIG_ENDIAN);
    l_offset+=1;

    if(prevInUse < 7 && authIncl == 1)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_encryption_supported, tvb, l_offset, 4, ENC_BIG_ENDIAN);
        l_offset+=4;
    }

    proto_tree_add_bits_item(subtree, hf_cdma2k_num_alt_so, tvb, l_offset, 3, ENC_BIG_ENDIAN);
    numAltSo = tvb_get_bits8(tvb,l_offset, 3);
    l_offset+=3;

    while(numAltSo > 0)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_Alt_So, tvb, l_offset, 16, ENC_BIG_ENDIAN);
        l_offset+=16;
        numAltSo--;
    }

    if(prevInUse >= 6)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_Uzid_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        uzidIncl = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;
        if(uzidIncl == 1)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Uzid, tvb, l_offset, 16, ENC_BIG_ENDIAN);
            l_offset+=16;
        }
        proto_tree_add_bits_item(subtree, hf_cdma2k_Ch_Ind, tvb, l_offset, 2, ENC_BIG_ENDIAN);
        l_offset+=2;
        proto_tree_add_bits_item(subtree, hf_cdma2k_Otd_Supported, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;
        proto_tree_add_bits_item(subtree, hf_cdma2k_Qpch_Supported, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;
        proto_tree_add_bits_item(subtree, hf_cdma2k_Enhanced_Rc, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;
        proto_tree_add_bits_item(subtree, hf_cdma2k_For_Rc_Pref, tvb, l_offset, 5, ENC_BIG_ENDIAN);
        l_offset+=5;
        proto_tree_add_bits_item(subtree, hf_cdma2k_Rev_Rc_Pref, tvb, l_offset, 5, ENC_BIG_ENDIAN);
        l_offset+=5;
        proto_tree_add_bits_item(subtree, hf_cdma2k_Fch_Supported, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        fchSupported = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;
        if(fchSupported == 1)
        {
            item1 = proto_tree_add_item(subtree, hf_cdma2k_Type_Specific_Fields, tvb, (l_offset/8),1, ENC_NA);
            proto_item_append_text(item1, "Fch Records");
            subtree1 = proto_item_add_subtree(item1,ett_cdma2k_subtree2);
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Fch_Frame_Size, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            l_offset+=1;
            proto_tree_add_bits_item(subtree1, hf_cdma2k_For_Fch_Len, tvb, l_offset, 3, ENC_BIG_ENDIAN);
            forFchLen = tvb_get_bits8(tvb,l_offset, 3);
            l_offset+=3;
            if(forFchLen > 0)
            {
                proto_tree_add_bits_item(subtree1, hf_cdma2k_For_Fch_Rc_Map, tvb, l_offset, 3*forFchLen, ENC_BIG_ENDIAN);
                l_offset+=3*forFchLen;
            }
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Rev_Fch_Len, tvb, l_offset, 3, ENC_BIG_ENDIAN);
            revFchLen = tvb_get_bits8(tvb,l_offset, 3);
            l_offset+=3;
            if(revFchLen > 0)
            {
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Rev_Fch_Rc_Map, tvb, l_offset, 3*revFchLen , ENC_BIG_ENDIAN);
                l_offset+=3*revFchLen;
            }
        }
        proto_tree_add_bits_item(subtree, hf_cdma2k_Dcch_Supported, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        dcchSupported = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;
        if(dcchSupported == 1)
        {
            item1 = proto_tree_add_item(subtree, hf_cdma2k_Type_Specific_Fields, tvb, (l_offset/8),1, ENC_NA);
            proto_item_append_text(item1, "Dcch Records");
            subtree1 = proto_item_add_subtree(item1,ett_cdma2k_subtree2);
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Dcch_Frame_Size, tvb, l_offset, 2, ENC_BIG_ENDIAN);
            l_offset+=2;
            proto_tree_add_bits_item(subtree1, hf_cdma2k_For_Dcch_Len, tvb, l_offset, 3, ENC_BIG_ENDIAN);
            forDcchLen = tvb_get_bits8(tvb,l_offset, 3);
            l_offset+=3;
            if(forDcchLen > 0)
            {
                proto_tree_add_bits_item(subtree1, hf_cdma2k_For_Dcch_Rc_Map, tvb, l_offset, 3*forDcchLen, ENC_BIG_ENDIAN);
                l_offset+=3*forDcchLen;
            }
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Rev_Dcch_Len, tvb, l_offset, 3, ENC_BIG_ENDIAN);
            revDcchLen = tvb_get_bits8(tvb,l_offset, 3);
            l_offset+=3;
            if (revDcchLen > 0)
            {
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Rev_Dcch_Rc_Map, tvb, l_offset, 3*revDcchLen, ENC_BIG_ENDIAN);
                l_offset+=3*revDcchLen;
            }
        }
        proto_tree_add_bits_item(subtree, hf_cdma2k_Rev_Fch_Gating_Req, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;
    }
    if(prevInUse >= 7)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_Sts_Supported, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;
        proto_tree_add_bits_item(subtree, hf_cdma2k_ThreeXCchSupported , tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;
        proto_tree_add_bits_item(subtree, hf_cdma2k_Wll_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        wllIncl = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;
        if (wllIncl == 1)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Wll_Device_Type, tvb, l_offset, 3, ENC_BIG_ENDIAN);
            l_offset+=3;
            proto_tree_add_bits_item(subtree, hf_cdma2k_Hook_Status, tvb, l_offset, 4, ENC_BIG_ENDIAN);
            l_offset+=4;
        }
        proto_tree_add_bits_item(subtree, hf_cdma2k_Enc_Info_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        encInfoIncl = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;
        if(encInfoIncl == 1)
        {
            item1 = proto_tree_add_item(subtree, hf_cdma2k_Sig_Encrypt_Supp, tvb, (l_offset/8),1, ENC_NA);
            subtree1 = proto_item_add_subtree(item1,ett_cdma2k_subtree2);
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Cmea, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            l_offset+=1;
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Ecmea, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            ecmea = tvb_get_bits8(tvb,l_offset, 1);
            l_offset+=1;
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Rea, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            rea = tvb_get_bits8(tvb,l_offset, 1);
            l_offset+=1;
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Reserved, tvb, l_offset, 5, ENC_BIG_ENDIAN);
            l_offset+=5;
            proto_tree_add_bits_item(subtree, hf_cdma2k_DSig_Encrypt_Req, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            l_offset+=1;
            proto_tree_add_bits_item(subtree, hf_cdma2k_CSig_Encrypt_Req, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            l_offset+=1;
            if(ecmea == 1 || rea == 1)
            {
                proto_tree_add_bits_item(subtree, hf_cdma2k_New_Sseq_H, tvb, l_offset, 24, ENC_BIG_ENDIAN);
                l_offset+=24;
                proto_tree_add_bits_item(subtree, hf_cdma2k_New_Sseq_H_Sig, tvb, l_offset, 8, ENC_BIG_ENDIAN);
                l_offset+=8;
            }
            proto_tree_add_bits_item(subtree, hf_cdma2k_Ui_Encrypt_Req, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            l_offset+=1;
            proto_tree_add_bits_item(subtree, hf_cdma2k_Ui_Encrypt_Sup, tvb, l_offset, 8, ENC_BIG_ENDIAN);
            l_offset+=8;
        }
        proto_tree_add_bits_item(subtree, hf_cdma2k_Sync_Id_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        syncIdIncl = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;
        if(syncIdIncl == 1)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Sync_Id_Len, tvb, l_offset, 4, ENC_BIG_ENDIAN);
            syncIdLen = tvb_get_bits8(tvb,l_offset, 4);
            l_offset+=4;
            item1 = proto_tree_add_item(subtree, hf_cdma2k_Sync_Id, tvb, l_offset/8,syncIdLen, ENC_NA);
            while(syncIdLen > 0)
            {
                proto_item_append_text(item1, " %02x",tvb_get_bits8(tvb,l_offset, 8));
                l_offset+=8;
                syncIdLen--;
            }
        }
        proto_tree_add_bits_item(subtree, hf_cdma2k_So_Bitmap_Ind, tvb, l_offset, 2, ENC_BIG_ENDIAN);
        soBitmapInd = tvb_get_bits8(tvb,l_offset, 2);
        l_offset+=2;
        if(soBitmapInd != 0)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_So_Group_Num, tvb, l_offset, 5, ENC_BIG_ENDIAN);
            l_offset+=5;
            proto_tree_add_bits_item(subtree, hf_cdma2k_So_Bitmap, tvb, l_offset, 4*soBitmapInd, ENC_BIG_ENDIAN);
            l_offset+=4*soBitmapInd;
        }
    }

        /* Currently IWS Stack supports only till Mobile Protocol Revision Value 7 */
/*if(mob_P_Rev_Rx >= 8)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_Alt_Band_Class_Sup, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;
    }
    if(mob_P_Rev_Rx >= 9)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_Msg_Int_Info_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        msgIntInfoIncl = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;
        if(msgIntInfoIncl == 1)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Sig_Integrity_Sup_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            sigIntegritySupIncl = tvb_get_bits8(tvb,l_offset, 1);
            l_offset+=1;
            if(sigIntegritySupIncl ==1)
            {
                proto_tree_add_bits_item(subtree, hf_cdma2k_Sig_Integrity_Sup, tvb, l_offset, 8, ENC_BIG_ENDIAN);
                l_offset+=8;
                proto_tree_add_bits_item(subtree, hf_cdma2k_Alt_Sig_Integrity_Req, tvb, l_offset, 3, ENC_BIG_ENDIAN);
                l_offset+=3;
            }
            proto_tree_add_bits_item(subtree, hf_cdma2k_New_Key_Id, tvb, l_offset, 2, ENC_BIG_ENDIAN);
            l_offset+=2;
            proto_tree_add_bits_item(subtree, hf_cdma2k_New_Sseq_H_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            newSseqHIncl = tvb_get_bits8(tvb,l_offset, 1);
            l_offset+=1;
            if(newSseqHIncl == 1)
            {
                proto_tree_add_bits_item(subtree, hf_cdma2k_New_Sseq_H, tvb, l_offset, 24, ENC_BIG_ENDIAN);
                l_offset+=24;
                proto_tree_add_bits_item(subtree, hf_cdma2k_New_Sseq_H_Sig, tvb, l_offset, 8, ENC_BIG_ENDIAN);
                l_offset+=8;
            }

        }
        proto_tree_add_bits_item(subtree, hf_cdma2k_For_Pdch_Supported, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        forPdchSupported = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;
        if(forPdchSupported == 1)
        {
            item1 = proto_tree_add_item(subtree, hf_cdma2k_Type_Specific_Fields, tvb, (l_offset/8),1, ENC_NA);
            subtree1 = proto_item_add_subtree(item1,ett_cdma2k_subtree2);
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Ack_Delay, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            l_offset+=1;
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Num_Arq_Chan, tvb, l_offset, 2, ENC_BIG_ENDIAN);
            l_offset+=2;
            proto_tree_add_bits_item(subtree1, hf_cdma2k_For_Pdch_Len, tvb, l_offset, 2, ENC_BIG_ENDIAN);
            forPdchLen = tvb_get_bits8(tvb,l_offset, 2);
            l_offset+=2;
            proto_tree_add_bits_item(subtree1, hf_cdma2k_For_Pdch_Rc_Map, tvb, l_offset, 3*(forPdchLen+1), ENC_BIG_ENDIAN);
            l_offset+=3*(forFchLen+1);
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Ch_Config_Sup_Map_Len, tvb, l_offset, 2, ENC_BIG_ENDIAN);
            chConfigSupMapLen = tvb_get_bits8(tvb,l_offset, 2);
            l_offset+=2;
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Ch_Config_Sup_Map, tvb, l_offset, 3*(chConfigSupMapLen + 1), ENC_BIG_ENDIAN);
            l_offset+=3*(chConfigSupMapLen + 1);
        }
    }
    if(chInd == 0)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_Ext_Ch_Ind, tvb, l_offset, 5, ENC_BIG_ENDIAN);
        l_offset+=5;
    }
    if(mob_P_Rev_Rx >= 11)
    {
        if(slotCycleIndex != 0)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Sign_Slot_Cycle_Index, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            l_offset+=1;
        }
        proto_tree_add_bits_item(subtree, hf_cdma2k_Bcmc_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        bcmcIncl = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;
        if(bcmcIncl !=0)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Bcmc_Pref_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            l_offset+=1;
            proto_tree_add_bits_item(subtree, hf_cdma2k_Fundicated_Bcmc_Supported, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            fundicatedBcmcSupported = tvb_get_bits8(tvb,l_offset, 1);
            l_offset+=1;
            if(fundicatedBcmcSupported == 1)
            {
                item1 = proto_tree_add_item(subtree, hf_cdma2k_Type_Specific_Fields, tvb, (l_offset/8),1, ENC_NA);
                subtree1 = proto_item_add_subtree(item1,ett_cdma2k_subtree2);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Fundicated_Bcmc_Ch_Sup_Map_Len, tvb, l_offset, 2, ENC_BIG_ENDIAN);
                fundicatedBcmcChSupMapLen = tvb_get_bits8(tvb,l_offset, 2);
                l_offset+=2;
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Fundicated_Bcmc_Ch_Sup_Map, tvb, l_offset, 3*(fundicatedBcmcChSupMapLen + 1), ENC_BIG_ENDIAN);
                l_offset+=3*(fundicatedBcmcChSupMapLen + 1);
            }
            proto_tree_add_bits_item(subtree, hf_cdma2k_Auth_Signature_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            authSignatureIncl = tvb_get_bits8(tvb,l_offset, 1);
            l_offset+=1;
            if(authSignatureIncl !=0)
            {
                proto_tree_add_bits_item(subtree, hf_cdma2k_Time_Stamp_Short_Length, tvb, l_offset, 8, ENC_BIG_ENDIAN);
                l_offset+=8;
                proto_tree_add_bits_item(subtree, hf_cdma2k_Time_Stamp_Short, tvb, l_offset, 8, ENC_BIG_ENDIAN);
                l_offset+=8;/ * Length needs to be check  * /
                proto_tree_add_bits_item(subtree, hf_cdma2k_Num_Bcmc_Programs, tvb, l_offset, 8, ENC_BIG_ENDIAN);
                l_offset+=8;
            }
        }
    }*/
    if(l_offset%8 == 0)
        *offset = (l_offset/8);
    else
        *offset = (l_offset/8) + 1;
}


/* Helper function to decode Handoff Direction Message Parameters */
static void cdma2k_message_HANDOFF_DIR(proto_item *item,tvbuff_t *tvb,proto_tree *tree,guint *offset, guint16 msgType)
{
    guint16 useTime = -1, parmsIncl = -1, searchIncl = -1, extraParmsIncl = -1;
    guint16 l_offset = -1, returnIfHandoffFail = -1, scrIncl = -1, nnscrIncl = -1;
    guint16 recLen= -1, pwrCntlStepIncl = -1, schIncl = -1, startTimeIncl = -1;
    guint16 loop = -1, usePcTime = -1, chInd = -1, gatMode = -1, pwrCntlDelayIncl = -1;
    guint16 encryptMode = -1, linkIncl = -1, pRev = -1, syncIdIncl = -1, syncIdLen = -1;
    guint16 ccInfoIncl = -1, noCallAssign = -1, resInd = -1, cdmaRepSup = -1, plcmIncl = -1;
    guint16 plcmType = -1, dropTRangeIncl = -1, fwdPDChSup = -1, encIncl = -1, sidIncl = -1;
    guint16 nidIncl = -1, csSup = -1, pacZoneId = -1, pzHysEnabled = -1, pzHysInfoIncl = -1;
    guint16 bcmcTchSup = -1, numForAssign = -1, schBcmc = -1, addPlcmSchIncl = -1;
    guint16 addPlcmSchType = -1, fSchOuterCodeIncl = -1, txPwrIncl = -1, txPwrDflt = -1;
    proto_tree *subtree = NULL, *subtree1 = NULL, *subtree2 = NULL;
    proto_item *item1 = NULL, *item2 = NULL, *item3 = NULL;

    if(msgType == 34)
    {
        item = proto_tree_add_item(tree,hf_cdma2k_UhdmMsg, tvb, *offset,-1, ENC_NA);
    }
    else
    {
        item = proto_tree_add_item(tree,hf_cdma2k_MeIdUhdmMsg, tvb, *offset,-1, ENC_NA);
    }
    subtree = proto_item_add_subtree(item, ett_cdma2k_subtree1);

    proto_tree_add_bits_item(subtree, hf_cdma2k_Use_Time, tvb, *offset*8,1, ENC_BIG_ENDIAN);
    useTime = tvb_get_bits8(tvb,*offset*8,1);
    l_offset = *offset*8 + 1;
    if(useTime == 1)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_Action_Time, tvb, l_offset, 6, ENC_BIG_ENDIAN);
        l_offset+= 6;
    }
    proto_tree_add_bits_item(subtree, hf_cdma2k_Hdm_Seq, tvb, l_offset, 2, ENC_BIG_ENDIAN);
    l_offset+=2;

    proto_tree_add_bits_item(subtree, hf_cdma2k_Parms_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
    parmsIncl = tvb_get_bits8(tvb,l_offset, 1);
    l_offset+=1;
    if(parmsIncl == 1)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_P_Rev, tvb, l_offset, 8, ENC_BIG_ENDIAN);
        pRev = tvb_get_bits8(tvb,l_offset, 8);
        l_offset+=8;
        proto_tree_add_bits_item(subtree, hf_cdma2k_Serv_Neg_Type, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;
    }

    proto_tree_add_bits_item(subtree, hf_cdma2k_Search_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
    searchIncl = tvb_get_bits8(tvb,l_offset, 1);
    l_offset+=1;
    if(searchIncl == 1)
    {
        item1 = proto_tree_add_item(subtree, hf_cdma2k_Pilot_Search, tvb, (l_offset/8),7, ENC_NA);
        subtree1 = proto_item_add_subtree(item1, ett_cdma2k_subtree2);
        proto_tree_add_bits_item(subtree1, hf_cdma2k_Srch_Win_A, tvb, l_offset, 4, ENC_BIG_ENDIAN);
        l_offset+=4;
        proto_tree_add_bits_item(subtree1, hf_cdma2k_Srch_Win_N, tvb, l_offset, 4, ENC_BIG_ENDIAN);
        l_offset+=4;
        proto_tree_add_bits_item(subtree1, hf_cdma2k_Srch_Win_R, tvb, l_offset, 4, ENC_BIG_ENDIAN);
        l_offset+=4;
        proto_tree_add_bits_item(subtree1, hf_cdma2k_T_Add, tvb, l_offset, 6, ENC_BIG_ENDIAN);
        l_offset+=6;
        proto_tree_add_bits_item(subtree1, hf_cdma2k_T_Drop, tvb, l_offset, 6, ENC_BIG_ENDIAN);
        l_offset+=6;
        proto_tree_add_bits_item(subtree1, hf_cdma2k_T_Comp, tvb, l_offset, 4, ENC_BIG_ENDIAN);
        l_offset+=4;
        proto_tree_add_bits_item(subtree1, hf_cdma2k_T_Tdrop, tvb, l_offset, 4, ENC_BIG_ENDIAN);
        l_offset+=4;
        proto_tree_add_bits_item(subtree1, hf_cdma2k_Soft_Slope, tvb, l_offset, 6, ENC_BIG_ENDIAN);
        l_offset+=6;
        proto_tree_add_bits_item(subtree1, hf_cdma2k_Add_Intercept, tvb, l_offset, 6, ENC_BIG_ENDIAN);
        l_offset+=6;
        proto_tree_add_bits_item(subtree1, hf_cdma2k_Drop_Intercept, tvb, l_offset, 6, ENC_BIG_ENDIAN);
        l_offset+=6;
    }

    proto_tree_add_bits_item(subtree, hf_cdma2k_Extra_Parms_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
    extraParmsIncl = tvb_get_bits8(tvb,l_offset, 1);
    l_offset+=1;
    if(extraParmsIncl == 1)
    {
        item1 = proto_tree_add_item(subtree, hf_cdma2k_Extra_Parms, tvb, (l_offset/8),1, ENC_NA);
        subtree1 = proto_item_add_subtree(item1, ett_cdma2k_subtree2);
        proto_tree_add_bits_item(subtree1, hf_cdma2k_Packet_Zone_Id, tvb, l_offset, 8, ENC_BIG_ENDIAN);
        pacZoneId = tvb_get_bits8(tvb,l_offset, 8);
        l_offset+=8;
        proto_tree_add_bits_item(subtree1, hf_cdma2k_Frame_Offset, tvb, l_offset, 4, ENC_BIG_ENDIAN);
        l_offset+=4;
        proto_tree_add_bits_item(subtree1, hf_cdma2k_Private_Lcm, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;
        proto_tree_add_bits_item(subtree1, hf_cdma2k_Reset_L2, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;
        proto_tree_add_bits_item(subtree1, hf_cdma2k_Reset_Fpc, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;
        proto_tree_add_bits_item(subtree1, hf_cdma2k_Encrypt_Mode, tvb, l_offset, 2, ENC_BIG_ENDIAN);
        encryptMode = tvb_get_bits8(tvb,l_offset, 2);
        l_offset+=2;
        proto_tree_add_bits_item(subtree1, hf_cdma2k_Nom_Pwr_Ext, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;
        proto_tree_add_bits_item(subtree1, hf_cdma2k_Nom_Pwr, tvb, l_offset, 4, ENC_BIG_ENDIAN);
        l_offset+=4;
        proto_tree_add_bits_item(subtree1, hf_cdma2k_Rlgain_Traffic_Pilot, tvb, l_offset, 6, ENC_BIG_ENDIAN);
        l_offset+=6;
        proto_tree_add_bits_item(subtree1, hf_cdma2k_Default_Rlag, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;
        proto_tree_add_bits_item(subtree1, hf_cdma2k_Num_Preamble, tvb, l_offset, 3, ENC_BIG_ENDIAN);
        l_offset+=3;
        proto_tree_add_bits_item(subtree1, hf_cdma2k_Band_Class, tvb, l_offset, 5, ENC_BIG_ENDIAN);
        l_offset+=5;
        proto_tree_add_bits_item(subtree1, hf_cdma2k_Cdma_Freq, tvb, l_offset, 11, ENC_BIG_ENDIAN);
        l_offset+=11;

        proto_tree_add_bits_item(subtree1, hf_cdma2k_Return_If_Handoff_Fail, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        returnIfHandoffFail = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;
        if(returnIfHandoffFail == 1)
        {
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Complete_Search, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            l_offset+=1;
        }
        proto_tree_add_bits_item(subtree1, hf_cdma2k_Periodic_Search, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;
        proto_tree_add_bits_item(subtree1, hf_cdma2k_Scr_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        scrIncl = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;

        if(scrIncl == 1)
        {
            item2 = proto_tree_add_item(subtree1, hf_cdma2k_Scr, tvb, (l_offset/8),1, ENC_NA);
            subtree2 = proto_item_add_subtree(item2, ett_cdma2k_subtree2);
            proto_tree_add_bits_item(subtree2,hf_cdma2k_Serv_Con_Seq, tvb, l_offset, 3, ENC_BIG_ENDIAN);
            l_offset+=3;
            proto_tree_add_bits_item(subtree2,hf_cdma2k_Record_Type, tvb, l_offset, 8, ENC_BIG_ENDIAN);
            l_offset+=8;
            proto_tree_add_bits_item(subtree2,hf_cdma2k_Record_Len, tvb, l_offset, 8, ENC_BIG_ENDIAN);
            recLen = tvb_get_bits8(tvb,l_offset, 8);
            l_offset+=8;
            item3 = proto_tree_add_item(subtree2,hf_cdma2k_Type_Specific_Fields, tvb, (l_offset/8),recLen+1, ENC_NA);
            while(recLen>0)
            {
                proto_item_append_text(item3," 0x%02x",tvb_get_bits8(tvb,l_offset, 8));
                l_offset+=8;
                recLen-=1;
            }
        } /* scrIncl */

        proto_tree_add_bits_item(subtree1, hf_cdma2k_Nnscr_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        nnscrIncl = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;

        if(nnscrIncl == 1)
        {
            item2 = proto_tree_add_item(subtree1, hf_cdma2k_Nnscr, tvb, (l_offset/8),1, ENC_NA);
            subtree2 = proto_item_add_subtree(item2, ett_cdma2k_subtree2);
            proto_tree_add_bits_item(subtree2,hf_cdma2k_Record_Type, tvb, l_offset, 8, ENC_BIG_ENDIAN);
            l_offset+=8;
            proto_tree_add_bits_item(subtree2,hf_cdma2k_Record_Len, tvb, l_offset, 8, ENC_BIG_ENDIAN);
            recLen = tvb_get_bits8(tvb,l_offset, 8);
            l_offset+=8;
            item3 = proto_tree_add_item(subtree2,hf_cdma2k_Type_Specific_Fields, tvb, (l_offset/8),recLen, ENC_NA);
            while(recLen>0)
            {
                proto_item_append_text(item3," 0x%02x",tvb_get_bits8(tvb,l_offset, 8));
                l_offset+=8;
                recLen-=1;
            }
        } /* nnscrIncl */
    } /* extraParmsIncl */

    proto_tree_add_bits_item(subtree, hf_cdma2k_Use_Pwr_Cntl_Step, tvb, l_offset, 1, ENC_BIG_ENDIAN);
    pwrCntlStepIncl = tvb_get_bits8(tvb,l_offset, 1);
    l_offset+=1;
    if(pwrCntlStepIncl == 1)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_Pwr_Cntl_Step, tvb, l_offset, 3, ENC_BIG_ENDIAN);
        l_offset+=3;
    }
    proto_tree_add_bits_item(subtree, hf_cdma2k_Clear_Retry_Delay, tvb, l_offset, 1, ENC_BIG_ENDIAN);
    l_offset+=1;
    proto_tree_add_bits_item(subtree, hf_cdma2k_Sch_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
    schIncl = tvb_get_bits8(tvb,l_offset, 1);
    l_offset+=1;

    if(schIncl == 1)
    {
        item1 = proto_tree_add_item(subtree, hf_cdma2k_Sch, tvb, (l_offset/8),7, ENC_NA);
        subtree1 = proto_item_add_subtree(item1, ett_cdma2k_subtree1);
        proto_tree_add_bits_item(subtree1, hf_cdma2k_Num_For_Assign, tvb, l_offset, 2, ENC_BIG_ENDIAN);
        recLen = tvb_get_bits8(tvb,l_offset, 2);
        numForAssign = recLen;
        l_offset+=2;

        for(loop = 1; loop <= recLen; loop++)
        {
            item2 = proto_tree_add_item(subtree1, hf_cdma2k_Record_For_Assign, tvb, (l_offset/8),3, ENC_NA);
            proto_item_append_text(item2, " : [%02d]",loop);
            subtree2 = proto_item_add_subtree(item2, ett_cdma2k_subtree2);
            proto_tree_add_bits_item(subtree2,hf_cdma2k_Sch_Id, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            l_offset+=1;
            proto_tree_add_bits_item(subtree2,hf_cdma2k_Sch_Duration, tvb, l_offset, 4, ENC_BIG_ENDIAN);
            l_offset+=4;
            proto_tree_add_bits_item(subtree2,hf_cdma2k_Sch_Start_Time_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            startTimeIncl = tvb_get_bits8(tvb,l_offset, 1);
            l_offset+=1;
            if(startTimeIncl == 1)
            {
                proto_tree_add_bits_item(subtree2,hf_cdma2k_Sch_Start_Time, tvb, l_offset, 5, ENC_BIG_ENDIAN);
                l_offset+=5;
            }
            proto_tree_add_bits_item(subtree2,hf_cdma2k_Sccl_Index, tvb, l_offset, 4, ENC_BIG_ENDIAN);
            l_offset+=4;
        }

        proto_tree_add_bits_item(subtree1, hf_cdma2k_Num_Rev_Assign, tvb, l_offset, 2, ENC_BIG_ENDIAN);
        recLen = tvb_get_bits8(tvb,l_offset, 2);
        l_offset+=2;

        for(loop = 1; loop <= recLen; loop++)
        {
            item2 = proto_tree_add_item(subtree1, hf_cdma2k_Record_Rev_Assign, tvb, (l_offset/8),3, ENC_NA);
            proto_item_append_text(item2, " : [%02d]",loop);
            subtree2 = proto_item_add_subtree(item2, ett_cdma2k_subtree2);
            proto_tree_add_bits_item(subtree2,hf_cdma2k_Sch_Id, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            l_offset+=1;
            proto_tree_add_bits_item(subtree2,hf_cdma2k_Sch_Duration, tvb, l_offset, 4, ENC_BIG_ENDIAN);
            l_offset+=4;
            proto_tree_add_bits_item(subtree2,hf_cdma2k_Sch_Start_Time_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            startTimeIncl = tvb_get_bits8(tvb,l_offset, 1);
            l_offset+=1;
            if(startTimeIncl == 1)
            {
                proto_tree_add_bits_item(subtree2,hf_cdma2k_Sch_Start_Time, tvb, l_offset, 5, ENC_BIG_ENDIAN);
                l_offset+=5;
            }
            proto_tree_add_bits_item(subtree2,hf_cdma2k_Sch_Num_Bits_Idx, tvb, l_offset, 4, ENC_BIG_ENDIAN);
            l_offset+=4;
        }
    } /* schIncl */

    proto_tree_add_bits_item(subtree, hf_cdma2k_Fpc_Subchain_Gain, tvb, l_offset, 5, ENC_BIG_ENDIAN);
    l_offset+=5;
    proto_tree_add_bits_item(subtree, hf_cdma2k_Use_Pc_Time, tvb, l_offset, 1, ENC_BIG_ENDIAN);
    usePcTime = tvb_get_bits8(tvb,l_offset, 1);
    l_offset+=1;
    if(usePcTime == 1)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_Pc_Action_Time, tvb, l_offset, 6, ENC_BIG_ENDIAN);
        l_offset+=6;
    }
    proto_tree_add_bits_item(subtree, hf_cdma2k_Ch_Ind, tvb, l_offset, 3, ENC_BIG_ENDIAN);
    chInd = tvb_get_bits8(tvb,l_offset, 3);
    l_offset+=3;
    proto_tree_add_bits_item(subtree, hf_cdma2k_Active_Set_Rec_Len, tvb, l_offset, 8, ENC_BIG_ENDIAN);
    recLen = tvb_get_bits8(tvb,l_offset, 8);
    l_offset+=8;

    if((recLen > 0) && (chInd != 0))
    {
        item1 = proto_tree_add_item(subtree, hf_cdma2k_Active_Set_Rec_Fields, tvb, (l_offset/8),recLen, ENC_NA);
        subtree1 = proto_item_add_subtree(item1, ett_cdma2k_subtree1);
        cdma2k_message_ACTIVE_SET_RECORD_FIELDS(item1, tvb, subtree1, &l_offset,  chInd, schIncl);
    }
    else
    {
        l_offset+=recLen*8;
    }

    if((chInd != 2) && (chInd != 6))
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_Rev_Fch_Gating_Mode, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        gatMode = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;
    }
    if(gatMode == 1)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_Rev_Pwr_Cntl_Delay_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        pwrCntlDelayIncl = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;
        if(pwrCntlDelayIncl == 1)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Rev_Pwr_Cntl_Delay, tvb, l_offset, 2, ENC_BIG_ENDIAN);
            l_offset+=2;
        }
    }
    if(encryptMode == 2 || encryptMode == 3)
    {
        if(encryptMode == 3)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_D_Sig_Encrypt_Mode, tvb, l_offset, 3, ENC_BIG_ENDIAN);
            l_offset+=3;
        }
        proto_tree_add_bits_item(subtree, hf_cdma2k_Enc_Key_Size, tvb, l_offset, 3, ENC_BIG_ENDIAN);
        l_offset+=3;
    }
    proto_tree_add_bits_item(subtree, hf_cdma2k_3xfl_1xrl_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
    linkIncl = tvb_get_bits8(tvb,l_offset, 1);
    l_offset+=1;
    if(linkIncl == 1)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_1xrl_Freq_Offset, tvb, l_offset, 2, ENC_BIG_ENDIAN);
        l_offset+=2;
    }
    if(scrIncl == 1 || nnscrIncl == 1 || pRev >= 11)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_Sync_Id_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        syncIdIncl = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;
        if(syncIdIncl == 1)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Sync_Id_Len, tvb, l_offset, 4, ENC_BIG_ENDIAN);
            syncIdLen = tvb_get_bits8(tvb,l_offset, 4);
            l_offset+=4;
            item1 = proto_tree_add_item(subtree, hf_cdma2k_Sync_Id, tvb, l_offset/8,syncIdLen, ENC_NA);
            while(syncIdLen > 0)
            {
                proto_item_append_text(item1, " %02x",tvb_get_bits8(tvb,l_offset, 8));
                l_offset+=8;
                syncIdLen--;
            }
        }
    }
    proto_tree_add_bits_item(subtree, hf_cdma2k_Cc_Info_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
    ccInfoIncl = tvb_get_bits8(tvb,l_offset, 1);
    l_offset+=1;
    if(ccInfoIncl == 1)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_Num_Calls_Assign, tvb, l_offset, 8, ENC_BIG_ENDIAN);
        noCallAssign = tvb_get_bits8(tvb,l_offset, 8);
        l_offset+=8;
        for(loop = 1; loop <= noCallAssign; loop++)
        {
            item1 = proto_tree_add_item(subtree, hf_cdma2k_Record_Calls_Assign, tvb, l_offset/8,noCallAssign*2, ENC_NA);
            proto_item_append_text(item1, " : [%02d]",loop);
            subtree1 = proto_item_add_subtree(item1, ett_cdma2k_subtree1);
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Con_Ref, tvb, l_offset, 8, ENC_BIG_ENDIAN);
            l_offset+=8;
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Response_Ind, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            resInd = tvb_get_bits8(tvb,l_offset, 1);
            l_offset+=1;
            if(resInd == 1)
            {
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Tag, tvb, l_offset, 4, ENC_BIG_ENDIAN);
                l_offset+=4;
            }
            else
            {
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Bypass_Alert_Answer, tvb, l_offset, 1, ENC_BIG_ENDIAN);
                l_offset+=1;
            }
        }
    }

    proto_tree_add_bits_item(subtree, hf_cdma2k_Cs_Supported, tvb, l_offset, 1, ENC_BIG_ENDIAN);
    csSup = tvb_get_bits8(tvb,l_offset, 1);
    l_offset+=1;

    if(msgType == 53)
    {
        if(pRev == 6)
        {
            if(encryptMode == 2 && scrIncl ==1)
            {
                proto_tree_add_bits_item(subtree, hf_cdma2k_Reserved, tvb, l_offset, 13, ENC_BIG_ENDIAN);
                l_offset+=13;
            }
            else if(encryptMode == 2 && scrIncl !=1 && nnscrIncl == 1)
            {
                proto_tree_add_bits_item(subtree, hf_cdma2k_Reserved, tvb, l_offset, 12, ENC_BIG_ENDIAN);
                l_offset+=12;
            }
            else if(encryptMode == 2 && scrIncl !=1 && nnscrIncl != 1)
            {
                proto_tree_add_bits_item(subtree, hf_cdma2k_Reserved, tvb, l_offset, 11, ENC_BIG_ENDIAN);
                l_offset+=11;
            }
            else if(encryptMode != 2 && scrIncl ==1)
            {
                proto_tree_add_bits_item(subtree, hf_cdma2k_Reserved, tvb, l_offset, 10, ENC_BIG_ENDIAN);
                l_offset+=10;
            }
            else if(encryptMode != 2 && scrIncl !=1 && nnscrIncl == 1)
            {
                proto_tree_add_bits_item(subtree, hf_cdma2k_Reserved, tvb, l_offset, 9, ENC_BIG_ENDIAN);
                l_offset+=9;
            }
            else if(encryptMode != 2 && scrIncl !=1 && nnscrIncl != 1)
            {
                proto_tree_add_bits_item(subtree, hf_cdma2k_Reserved, tvb, l_offset, 8, ENC_BIG_ENDIAN);
                l_offset+=8;
            }
        }
        else if(pRev == 7 || pRev == 8)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Reserved, tvb, l_offset, 6, ENC_BIG_ENDIAN);
            l_offset+=6;
        }

        proto_tree_add_bits_item(subtree, hf_cdma2k_Plcm_Type_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        plcmIncl = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;
        if(plcmIncl == 1)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Plcm_Type, tvb, l_offset, 4, ENC_BIG_ENDIAN);
            plcmType = tvb_get_bits8(tvb,l_offset, 4);
            l_offset+=4;
            if(plcmType == 1)
            {
                proto_tree_add_bits_item(subtree, hf_cdma2k_Plcm_39, tvb, l_offset, 39, ENC_BIG_ENDIAN);
                l_offset+=39;
            }
        }
    }

    if(pRev > 7 && msgType == 34)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_Chm_Supported, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;
        proto_tree_add_bits_item(subtree, hf_cdma2k_Cdma_Off_Time_Rep_Sup_Ind, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        cdmaRepSup = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;
        if(cdmaRepSup == 1)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Cdma_Off_Time_Rep_Threshold_Unit, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            l_offset+=1;
            proto_tree_add_bits_item(subtree, hf_cdma2k_Cdma_Off_Time_Rep_Threshold, tvb, l_offset, 3, ENC_BIG_ENDIAN);
            l_offset+=3;
        }
        proto_tree_add_bits_item(subtree, hf_cdma2k_Release_To_Idle_Ind, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;
        proto_tree_add_bits_item(subtree, hf_cdma2k_Msg_Integrity_Sup, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;
        proto_tree_add_bits_item(subtree, hf_cdma2k_Gen_2g_Key, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;
        proto_tree_add_bits_item(subtree, hf_cdma2k_Register_In_Idle, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;

        proto_tree_add_bits_item(subtree, hf_cdma2k_Plcm_Type_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        plcmIncl = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;
        if(plcmIncl == 1)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Plcm_Type, tvb, l_offset, 4, ENC_BIG_ENDIAN);
            l_offset+=4;
            proto_tree_add_bits_item(subtree, hf_cdma2k_Plcm_39, tvb, l_offset, 39, ENC_BIG_ENDIAN);
            l_offset+=39;
        }
        if(searchIncl == 1)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_T_Tdrop_Range_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            dropTRangeIncl = tvb_get_bits8(tvb,l_offset, 1);
            l_offset+=1;
            if(dropTRangeIncl == 1)
            {
                proto_tree_add_bits_item(subtree, hf_cdma2k_T_Tdrop_Range, tvb, l_offset, 4, ENC_BIG_ENDIAN);
                l_offset+=4;
            }
        }
        proto_tree_add_bits_item(subtree, hf_cdma2k_For_Pdch_Supported, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        fwdPDChSup = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;
        if(fwdPDChSup == 1)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Pdch_Chm_Supported, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            l_offset+=1;
        }
        proto_tree_add_bits_item(subtree, hf_cdma2k_Pilot_Info_Req_Supported, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;
        proto_tree_add_bits_item(subtree, hf_cdma2k_Enc_Supported, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        encIncl = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;
        if(encIncl == 1)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Sig_Encrypt_Sup, tvb, l_offset, 8, ENC_BIG_ENDIAN);
            l_offset+=8;
            proto_tree_add_bits_item(subtree, hf_cdma2k_Ui_Encrypt_Sup, tvb, l_offset, 8, ENC_BIG_ENDIAN);
            l_offset+=8;
        }
        proto_tree_add_bits_item(subtree, hf_cdma2k_Use_Sync_Id, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;
        proto_tree_add_bits_item(subtree, hf_cdma2k_Sid_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        sidIncl = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;
        if(sidIncl == 1)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Sid, tvb, l_offset, 15, ENC_BIG_ENDIAN);
            l_offset+=15;
        }
        proto_tree_add_bits_item(subtree, hf_cdma2k_Nid_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        nidIncl = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;
        if(nidIncl == 1)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Nid, tvb, l_offset, 16, ENC_BIG_ENDIAN);
            l_offset+=16;
        }

        proto_tree_add_bits_item(subtree, hf_cdma2k_Sdb_Supported, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;
        if(csSup== 1)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Mob_Qos, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            l_offset+=1;
        }
        proto_tree_add_bits_item(subtree, hf_cdma2k_Ms_Init_Pos_Loc_Sup_Ind, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;
    }

    if(pRev > 9 && msgType == 34)
    {
        if(fwdPDChSup == 1)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Rev_Pdch_Supported, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            l_offset+=1;
        }
        if(pacZoneId != 0)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Pz_Hyst_Enabled, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            pzHysEnabled = tvb_get_bits8(tvb,l_offset, 1);
            l_offset+=1;
            if(pzHysEnabled == 1)
            {
                proto_tree_add_bits_item(subtree, hf_cdma2k_Pz_Hyst_Info_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
                pzHysInfoIncl = tvb_get_bits8(tvb,l_offset, 1);
                l_offset+=1;
                if(pzHysInfoIncl == 1)
                {
                    proto_tree_add_bits_item(subtree, hf_cdma2k_Pz_Hyst_List_Len, tvb, l_offset, 4, ENC_BIG_ENDIAN);
                    l_offset+=4;
                    proto_tree_add_bits_item(subtree, hf_cdma2k_Pz_Hyst_Act_Timer, tvb, l_offset, 8, ENC_BIG_ENDIAN);
                    l_offset+=8;
                    proto_tree_add_bits_item(subtree, hf_cdma2k_Pz_Hyst_Timer_Mul, tvb, l_offset, 3, ENC_BIG_ENDIAN);
                    l_offset+=3;
                    proto_tree_add_bits_item(subtree, hf_cdma2k_Pz_Hyst_Timer_Exp, tvb, l_offset, 5, ENC_BIG_ENDIAN);
                    l_offset+=5;
                }
            }
        }
        proto_tree_add_bits_item(subtree, hf_cdma2k_Bcmc_On_Traffic_Sup, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        bcmcTchSup = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;
        if(bcmcTchSup == 1)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Auto_Re_Traffic_Allowed_Ind, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            l_offset+=1;
        }
        if(bcmcTchSup == 1 || numForAssign == 1)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Sch_Bcmc_Ind, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            schBcmc = tvb_get_bits8(tvb,l_offset, 1);
            l_offset+=1;
        }
        if(schBcmc == 1)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Add_Plcm_For_Sch_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            addPlcmSchIncl = tvb_get_bits8(tvb,l_offset, 1);
            l_offset+=1;
            if(addPlcmSchIncl == 1)
            {
                proto_tree_add_bits_item(subtree, hf_cdma2k_Add_Plcm_For_Sch_Type, tvb, l_offset, 1, ENC_BIG_ENDIAN);
                addPlcmSchType = tvb_get_bits8(tvb,l_offset, 1);
                l_offset+=1;
                if(addPlcmSchType == 1)
                {
                    proto_tree_add_bits_item(subtree, hf_cdma2k_Add_Plcm_For_Sch_35, tvb, l_offset, 35, ENC_BIG_ENDIAN);
                    l_offset+=35;
                }
            }
            for(loop =1; loop <= numForAssign; loop++)
            {
                item1 = proto_tree_add_item(subtree, hf_cdma2k_Record_Sch_Bcmc, tvb, l_offset/8,numForAssign*2, ENC_NA);
                proto_item_append_text(item1, " : [%02d]",loop);
                subtree1 = proto_item_add_subtree(item1, ett_cdma2k_subtree1);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Use_Add_Plcm_For_Sch, tvb, l_offset, 1, ENC_BIG_ENDIAN);
                l_offset+=1;
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Fsch_Outercode_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
                fSchOuterCodeIncl = tvb_get_bits8(tvb,l_offset, 1);
                l_offset+=1;
                if(fSchOuterCodeIncl == 1)
                {
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Fsch_Outercode_Rate, tvb, l_offset, 3, ENC_BIG_ENDIAN);
                    l_offset+=3;
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Fsch_Outercode_Offset, tvb, l_offset, 6, ENC_BIG_ENDIAN);
                    l_offset+=6;
                }
            }
        }
        if(csSup== 1)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Max_Add_Serv_Instance, tvb, l_offset, 3, ENC_BIG_ENDIAN);
            l_offset+=3;
        }
        proto_tree_add_bits_item(subtree, hf_cdma2k_Use_Ch_Cfg_Rrm, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        l_offset+=1;
        proto_tree_add_bits_item(subtree, hf_cdma2k_Tx_Pwr_Limit_Incl, tvb, l_offset, 1, ENC_BIG_ENDIAN);
        txPwrIncl = tvb_get_bits8(tvb,l_offset, 1);
        l_offset+=1;
        if(txPwrIncl == 1)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Tx_Pwr_Limit_Default, tvb, l_offset, 1, ENC_BIG_ENDIAN);
            txPwrDflt = tvb_get_bits8(tvb,l_offset, 1);
            l_offset+=1;
            if(txPwrDflt == 0)
            {
                proto_tree_add_bits_item(subtree, hf_cdma2k_Tx_Pwr_Limit, tvb, l_offset, 6, ENC_BIG_ENDIAN);
                l_offset+=6;
            }
        }
    }

    if(l_offset%8 == 0)
    {
        *offset = (l_offset/8);
    }
    else
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_Reserved, tvb, l_offset, (8-(l_offset%8)), ENC_BIG_ENDIAN);
        *offset = (l_offset/8) + 1;
    }
}


/* Helper function to decode Alert With Info Message Parameters */
static void cdma2k_message_ALERT_WITH_INFO(proto_item *item,tvbuff_t *tvb,proto_tree *tree,guint *offset)
{
    guint16 recType = -1, recLen = -1, extBit = -1, numGrps = -1;
    guint16 polIncl = -1, inc = -1;
    proto_tree *subtree = NULL, *subtree1 = NULL;
    proto_item *item1 = NULL, *item2 = NULL;

    item = proto_tree_add_item(tree,hf_cdma2k_AlertWithInfoMsg, tvb, *offset,-1, ENC_NA);
    subtree = proto_item_add_subtree(item, ett_cdma2k_subtree1);

    inc = 1;
    while(tvb_captured_length_remaining(tvb,*offset) != 0 )
    {
        item1 = proto_tree_add_item(subtree, hf_cdma2k_Info_Rec, tvb, *offset,1, ENC_NA);
        proto_item_append_text(item1," : [%02d]", inc);
        inc++;
        subtree1 = proto_item_add_subtree(item1, ett_cdma2k_subtree1);
        proto_tree_add_item(subtree1, hf_cdma2k_Record_Type, tvb, *offset,1, ENC_BIG_ENDIAN);
        recType = tvb_get_bits8(tvb,*offset*8,8);
        *offset+=1;
        proto_tree_add_item(subtree1, hf_cdma2k_Record_Len, tvb, *offset,1, ENC_BIG_ENDIAN);
        recLen = tvb_get_bits8(tvb,*offset*8,8);
        *offset+=1;
        item1 = proto_tree_add_item(subtree1, hf_cdma2k_Type_Specific_Fields, tvb, *offset,recLen, ENC_NA);

        switch(recType)
        {
            case 1:
            {
                proto_item_append_text(item1," DISPLAY");
                subtree1 = proto_item_add_subtree(item1, ett_cdma2k_subtree1);
                item2 = proto_tree_add_item(subtree1, hf_cdma2k_Chari, tvb, *offset,recLen, ENC_NA);
                proto_item_append_text(item2, " - ASCII Values Of Characters : ");
                while(recLen > 0)
                {
                    proto_item_append_text(item2, "%02x ",tvb_get_bits8(tvb,*offset*8,8));
                    *offset+=1;
                    recLen-=1;
                }
                break;
            }

            case 2:
            {
                proto_item_append_text(item1," CALLED PARTY NUMBER");
                subtree1 = proto_item_add_subtree(item1, ett_cdma2k_subtree1);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Number_Type, tvb, *offset*8,3, ENC_BIG_ENDIAN);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Number_Plan, tvb, *offset*8+3,4, ENC_BIG_ENDIAN);
                item2 = proto_tree_add_item(subtree1, hf_cdma2k_Chari, tvb, *offset,recLen, ENC_NA);
                proto_item_append_text(item2, " - ASCII Values Of Called Party Number : ");
                while(recLen > 1)
                {
                    proto_item_append_text(item2, "%02x ",tvb_get_bits8(tvb,*offset*8+7,8));
                    *offset+=1;
                    recLen-=1;
                }
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Reserved, tvb, *offset*8+7,1, ENC_BIG_ENDIAN);
                *offset+=1;
                break;
            }

            case 3:
            {
                proto_item_append_text(item1," CALLING PARTY NUMBER");
                subtree1 = proto_item_add_subtree(item1, ett_cdma2k_subtree1);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Number_Type, tvb, *offset*8,3, ENC_BIG_ENDIAN);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Number_Plan, tvb, *offset*8+3,4, ENC_BIG_ENDIAN);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Pres_Indicator, tvb, *offset*8+7,2, ENC_BIG_ENDIAN);
                *offset+=1;
                recLen-=1;
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Scr_Indicator, tvb, *offset*8+1,2, ENC_BIG_ENDIAN);
                item2 = proto_tree_add_item(subtree1, hf_cdma2k_Chari, tvb, *offset,recLen, ENC_NA);
                proto_item_append_text(item2, " - ASCII Values Of Calling Party Number : ");
                while(recLen > 1)
                {
                    proto_item_append_text(item2, "%02x ",tvb_get_bits8(tvb,*offset*8+3,8));
                    *offset+=1;
                    recLen-=1;
                }
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Reserved, tvb, *offset*8+3,5, ENC_BIG_ENDIAN);
                *offset+=1;
                break;
            }

            case 5:
            {
                proto_item_append_text(item1," SIGNAL");
                subtree1 = proto_item_add_subtree(item1, ett_cdma2k_subtree1);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Signal_Type, tvb, *offset*8,2, ENC_BIG_ENDIAN);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Alert_Pitch, tvb, *offset*8+2,2, ENC_BIG_ENDIAN);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Signal, tvb, *offset*8+4,6, ENC_BIG_ENDIAN);
                *offset+=1;
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Reserved, tvb, *offset*8+2,6, ENC_BIG_ENDIAN);
                *offset+=1;
                break;
            }

            case 6:
            {
                proto_item_append_text(item1," MESSAGE WAITING");
                subtree1 = proto_item_add_subtree(item1, ett_cdma2k_subtree1);
                proto_tree_add_item(subtree1, hf_cdma2k_Msg_Count, tvb, *offset,1, ENC_BIG_ENDIAN);
                *offset+=1;
                break;
            }

            case 8:
            {
                proto_item_append_text(item1," CALLED PARTY SUBADDRESS");
                subtree1 = proto_item_add_subtree(item1, ett_cdma2k_subtree1);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Extension_Bit, tvb, *offset*8,1, ENC_BIG_ENDIAN);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Subaddress_Type, tvb, *offset*8+1,3, ENC_BIG_ENDIAN);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Odd_Even_Ind, tvb, *offset*8+4,1, ENC_BIG_ENDIAN);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Reserved, tvb, *offset*8+5,3, ENC_BIG_ENDIAN);
                *offset+=1;
                recLen-=1;
                item2 = proto_tree_add_item(subtree1, hf_cdma2k_Chari, tvb, *offset,recLen-1, ENC_NA);
                proto_item_append_text(item2, " - ASCII Values Of Called Party Subaddress : ");
                while(recLen > 1)
                {
                    proto_item_append_text(item2, "%02x ",tvb_get_bits8(tvb,*offset*8,8));
                    *offset+=1;
                    recLen-=1;
                }
                break;
            }

            case 9:
            {
                proto_item_append_text(item1," CALLING PARTY SUBADDRESS");
                subtree1 = proto_item_add_subtree(item1, ett_cdma2k_subtree1);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Extension_Bit, tvb, *offset*8,1, ENC_BIG_ENDIAN);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Subaddress_Type, tvb, *offset*8+1,3, ENC_BIG_ENDIAN);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Odd_Even_Ind, tvb, *offset*8+4,1, ENC_BIG_ENDIAN);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Reserved, tvb, *offset*8+5,3, ENC_BIG_ENDIAN);
                *offset+=1;
                recLen-=1;
                item2 = proto_tree_add_item(subtree1, hf_cdma2k_Chari, tvb, *offset,recLen-1, ENC_NA);
                proto_item_append_text(item2, " - ASCII Values Of Calling Party Subaddress : ");
                while(recLen > 1)
                {
                    proto_item_append_text(item2, "%02x ",tvb_get_bits8(tvb,*offset*8,8));
                    *offset+=1;
                    recLen-=1;
                }
                break;
            }

            case 11:
            {
                proto_item_append_text(item1," REDIRECTING NUMBER");
                subtree1 = proto_item_add_subtree(item1, ett_cdma2k_subtree1);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Extension_Bit, tvb, *offset*8,1, ENC_BIG_ENDIAN);
                extBit = tvb_get_bits8(tvb,*offset*8,1);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Number_Type, tvb, *offset*8+1,3, ENC_BIG_ENDIAN);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Number_Plan, tvb, *offset*8+4,4, ENC_BIG_ENDIAN);
                *offset+=1;
                recLen-=1;
                if(extBit == 0)
                {
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Extension_Bit, tvb, *offset*8,1, ENC_BIG_ENDIAN);
                    extBit = tvb_get_bits8(tvb,*offset*8,1);
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Pres_Indicator, tvb, *offset*8+1,2, ENC_BIG_ENDIAN);
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Reserved, tvb, *offset*8+3,3, ENC_BIG_ENDIAN);
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Scr_Indicator, tvb, *offset*8+6,2, ENC_BIG_ENDIAN);
                    *offset+=1;
                    recLen-=1;
                }
                if(extBit == 0)
                {
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Extension_Bit, tvb, *offset*8,1, ENC_BIG_ENDIAN);
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Reserved, tvb, *offset*8+1,3, ENC_BIG_ENDIAN);
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Redirection_Reason, tvb, *offset*8+4,4, ENC_BIG_ENDIAN);
                    *offset+=1;
                    recLen-=1;
                }
                item2 = proto_tree_add_item(subtree1, hf_cdma2k_Chari, tvb, *offset,recLen-1, ENC_NA);
                proto_item_append_text(item2, " - ASCII Values Of Redirecting Number : ");
                while(recLen > 1)
                {
                    proto_item_append_text(item2, "%02x ",tvb_get_bits8(tvb,*offset*8,8));
                    *offset+=1;
                    recLen-=1;
                }
                break;
            }

            case 12:
            {
                proto_item_append_text(item1," REDIRECTING SUBADDRESS");
                subtree1 = proto_item_add_subtree(item1, ett_cdma2k_subtree1);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Extension_Bit, tvb, *offset*8,1, ENC_BIG_ENDIAN);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Subaddress_Type, tvb, *offset*8+1,3, ENC_BIG_ENDIAN);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Odd_Even_Ind, tvb, *offset*8+4,1, ENC_BIG_ENDIAN);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Reserved, tvb, *offset*8+5,3, ENC_BIG_ENDIAN);
                *offset+=1;
                recLen-=1;
                item2 = proto_tree_add_item(subtree1, hf_cdma2k_Chari, tvb, *offset,recLen-1, ENC_NA);
                proto_item_append_text(item2, " - ASCII Values Of Redirecting Subaddress : ");
                while(recLen > 1)
                {
                    proto_item_append_text(item2, "%02x ",tvb_get_bits8(tvb,*offset*8,8));
                    *offset+=1;
                    recLen-=1;
                }
                break;
            }

            case 13:
            {
                proto_item_append_text(item1," METER PULSES");
                subtree1 = proto_item_add_subtree(item1, ett_cdma2k_subtree1);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Pulse_Freq, tvb, *offset*8,11, ENC_BIG_ENDIAN);
                *offset+=1;
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Pulse_On_Time, tvb, *offset*8+3,8, ENC_BIG_ENDIAN);
                *offset+=1;
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Pulse_Off_Time, tvb, *offset*8+3,8, ENC_BIG_ENDIAN);
                *offset+=1;
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Pulse_Count, tvb, *offset*8+3,4, ENC_BIG_ENDIAN);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Reserved, tvb, *offset*8+7,1, ENC_BIG_ENDIAN);
                *offset+=1;
                break;
            }

            case 14:
            {
                proto_item_append_text(item1," PARAMETRIC ALERTING");
                subtree1 = proto_item_add_subtree(item1, ett_cdma2k_subtree1);
                proto_tree_add_item(subtree1, hf_cdma2k_Cadence_Count, tvb, *offset,1, ENC_BIG_ENDIAN);
                *offset+=1;
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Num_Grps, tvb, *offset*8,4, ENC_BIG_ENDIAN);
                numGrps = tvb_get_bits8(tvb,*offset*8,4);
                while(numGrps > 0)
                {
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Amplitude, tvb, *offset*8+4,8, ENC_BIG_ENDIAN);
                    *offset+=1;
                    item2 = proto_tree_add_item(subtree1, hf_cdma2k_Freq, tvb, *offset,2, ENC_NA);
                    proto_item_append_text(item2, " [01] : %02d", tvb_get_bits8(tvb,*offset*8+4,10));
                    *offset+=1;
                    item2 = proto_tree_add_item(subtree1, hf_cdma2k_Freq, tvb, *offset,2, ENC_NA);
                    proto_item_append_text(item2, " [02] : %02d", tvb_get_bits8(tvb,*offset*8+6,10));
                    *offset+=2;
                    proto_tree_add_item(subtree1, hf_cdma2k_On_Time, tvb, *offset,1, ENC_BIG_ENDIAN);
                    *offset+=1;
                    proto_tree_add_item(subtree1, hf_cdma2k_Off_Time, tvb, *offset,1, ENC_BIG_ENDIAN);
                    *offset+=1;
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Repeat, tvb, *offset*8,4, ENC_BIG_ENDIAN);
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Delay, tvb, *offset*8+4,8, ENC_BIG_ENDIAN);
                    *offset+=1;
                    numGrps-=1;
                }
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Cadence_Type, tvb, *offset*8+4,2, ENC_BIG_ENDIAN);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Reserved, tvb, *offset*8+6,2, ENC_BIG_ENDIAN);
                *offset+=1;
                break;
            }

            case 15:
            {
                proto_item_append_text(item1," LINE CONTROL");
                subtree1 = proto_item_add_subtree(item1, ett_cdma2k_subtree1);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Polarity_Incl, tvb, *offset*8,1, ENC_BIG_ENDIAN);
                polIncl = tvb_get_bits8(tvb,*offset*8,1);
                if(polIncl == 1)
                {
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Toggle_Mode, tvb, *offset*8+1,1, ENC_BIG_ENDIAN);
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Reverse_Polarity, tvb, *offset*8+2,1, ENC_BIG_ENDIAN);
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Pwr_Denial_Time, tvb, *offset*8+3,8, ENC_BIG_ENDIAN);
                    *offset+=1;
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Reserved, tvb, *offset*8+3,5, ENC_BIG_ENDIAN);
                    *offset+=1;
                }
                else
                {
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Pwr_Denial_Time, tvb, *offset*8+1,8, ENC_BIG_ENDIAN);
                    *offset+=1;
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Reserved, tvb, *offset*8+1,7, ENC_BIG_ENDIAN);
                    *offset+=1;
                }
                break;
            }

            case 21:
            {
                proto_item_append_text(item1," CALL WAITING INDICATOR");
                subtree1 = proto_item_add_subtree(item1, ett_cdma2k_subtree1);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Call_Waiting_Ind, tvb, *offset*8,1, ENC_BIG_ENDIAN);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Reserved, tvb, *offset*8+1,7, ENC_BIG_ENDIAN);
                *offset+=1;
                break;
            }

            default:
            {
                proto_item_append_text(item1," Invalid / Unsupported Record Type in Alert With Info Message");
                break;
            }
        } /* Switch */
    } /* while */
}


/* Helper function to decode Active Set Record Field Parameters */
static void cdma2k_message_ACTIVE_SET_RECORD_FIELDS(proto_item *item _U_, tvbuff_t *tvb, proto_tree *subtree, guint16 *l_offset, guint16 chInd, guint16 schIncl)
{
    guint16 loop = -1, numForSch = -1, numRevSch = -1, pilotCnt = -1, srchOffsetIncl = -1;
    guint16 pilotInfoIncl = -1, recLen = -1, schCnt = -1, fchInfoIncl = -1, fchLowIncl = -1;
    guint16 fchHighIncl = -1, schInfoIncl = -1, schLowIncl = -1, ccshIncl = -1, ccshEncIncl = -1;
    guint16 pilotIncl = -1, schHighIncl = -1, dcchInfoIncl = -1, dcchLowIncl = -1, dcchHighIncl = -1;
    guint16 bcmcFunIncl = -1, addPlcmFchIncl = -1, cpcchInfoIncl = -1, addPlcmFchType = -1;
    proto_tree *subtree1 = NULL, *subtree2 = NULL;
    proto_item *item1 = NULL, *item2 = NULL;

    if(schIncl != 0)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_Num_For_Sch, tvb, *l_offset, 5, ENC_BIG_ENDIAN);
        numForSch = tvb_get_bits8(tvb,*l_offset, 5);
        *l_offset+=5;
        if(numForSch != 0)
        {
            for(loop = 1; loop <= numForSch; loop++)
            {
                item1 = proto_tree_add_item(subtree, hf_cdma2k_Record_For_Sch, tvb, *l_offset/8,numForSch*2, ENC_NA);
                proto_item_append_text(item1," : [%d]", loop);
                subtree1 = proto_item_add_subtree(item1,ett_cdma2k_subtree2);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Sch_Id, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
                *l_offset+=1;
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Sccl_Index, tvb, *l_offset, 4, ENC_BIG_ENDIAN);
                *l_offset+=4;
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Sch_Num_Bits_Idx, tvb, *l_offset, 4, ENC_BIG_ENDIAN);
                *l_offset+=4;
            }
        }
        proto_tree_add_bits_item(subtree, hf_cdma2k_Num_Rev_Sch, tvb, *l_offset, 5, ENC_BIG_ENDIAN);
        numRevSch = tvb_get_bits8(tvb,*l_offset, 5);
        *l_offset+=5;
        if(numRevSch != 0)
        {
            for(loop = 1; loop <= numRevSch; loop++)
            {
                item1 = proto_tree_add_item(subtree, hf_cdma2k_Record_Rev_Sch, tvb, *l_offset/8,numRevSch*1, ENC_NA);
                proto_item_append_text(item1," : [%d]", loop);
                subtree1 = proto_item_add_subtree(item1,ett_cdma2k_subtree2);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Sch_Id, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
                *l_offset+=1;
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Walsh_Id, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
                *l_offset+=1;
                proto_tree_add_bits_item(subtree1, hf_cdma2k_Sch_Num_Bits_Idx, tvb, *l_offset, 4, ENC_BIG_ENDIAN);
                *l_offset+=4;
            }
        }
    } /* schIncl */

    proto_tree_add_bits_item(subtree, hf_cdma2k_Num_Pilots, tvb, *l_offset, 3, ENC_BIG_ENDIAN);
    pilotCnt = tvb_get_bits8(tvb,*l_offset, 3);
    *l_offset+=3;
    proto_tree_add_bits_item(subtree, hf_cdma2k_Srch_Offset_Incl, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
    srchOffsetIncl = tvb_get_bits8(tvb,*l_offset, 1);
    *l_offset+=1;
    for(loop = 1; loop <= pilotCnt; loop++)
    {
        item1 = proto_tree_add_item(subtree, hf_cdma2k_Record_Pilots, tvb, *l_offset/8,1, ENC_NA);
        proto_item_append_text(item1," : [%d]", loop);
        subtree1 = proto_item_add_subtree(item1,ett_cdma2k_subtree2);
        proto_tree_add_bits_item(subtree1, hf_cdma2k_Pilot_Pn, tvb, *l_offset, 9, ENC_BIG_ENDIAN);
        *l_offset+=9;
        if(srchOffsetIncl == 1)
        {
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Srch_Offset, tvb, *l_offset, 3, ENC_BIG_ENDIAN);
            *l_offset+=3;
        }
        proto_tree_add_bits_item(subtree1, hf_cdma2k_Add_Pilot_Rec_Incl, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
        pilotInfoIncl = tvb_get_bits8(tvb,*l_offset, 1);
        *l_offset+=1;
        if(pilotInfoIncl == 1)
        {
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Pilot_Rec_Type, tvb, *l_offset, 3, ENC_BIG_ENDIAN);
            *l_offset+=3;
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Record_Len, tvb, *l_offset, 3, ENC_BIG_ENDIAN);
            recLen = tvb_get_bits8(tvb,*l_offset, 3);
            *l_offset+=3;
            item2 = proto_tree_add_item(subtree1, hf_cdma2k_Type_Specific_Fields, tvb, (*l_offset/8),recLen+1, ENC_NA);
            while(recLen > 0)
            {
                proto_item_append_text(item2," 0x%02x",tvb_get_bits8(tvb,*l_offset, 8));
                *l_offset+=8;
                recLen-=1;
            }
        }
        proto_tree_add_bits_item(subtree1, hf_cdma2k_Pwr_Comb_Ind, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
        *l_offset+=1;
        if(chInd == 5 || chInd == 7)
        {
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Code_Chan_Fch, tvb, *l_offset, 11, ENC_BIG_ENDIAN);
            *l_offset+=11;
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Qof_Mask_Id_Fch, tvb, *l_offset, 2, ENC_BIG_ENDIAN);
            *l_offset+=2;
        }
        if(chInd == 2 || chInd == 6 || chInd == 7)
        {
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Code_Chan_Dcch, tvb, *l_offset, 11, ENC_BIG_ENDIAN);
            *l_offset+=11;
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Qof_Mask_Id_Dcch, tvb, *l_offset, 2, ENC_BIG_ENDIAN);
            *l_offset+=2;
        }

        if(schIncl != 0)
        {
            proto_tree_add_bits_item(subtree1, hf_cdma2k_Num_Sch, tvb, *l_offset, 5, ENC_BIG_ENDIAN);
            schCnt = tvb_get_bits8(tvb,*l_offset, 5);
            *l_offset+=5;
            for(loop = 1; loop <= schCnt; loop++)
            {
                item2 = proto_tree_add_item(subtree1, hf_cdma2k_Record_Sch, tvb, *l_offset/8,-1, ENC_NA);
                proto_item_append_text(item2," : [%d]", loop);
                subtree2 = proto_item_add_subtree(item2,ett_cdma2k_subtree2);
                proto_tree_add_bits_item(subtree2,hf_cdma2k_Sch_Id, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
                *l_offset+=1;
                proto_tree_add_bits_item(subtree2,hf_cdma2k_Sccl_Index, tvb, *l_offset, 4, ENC_BIG_ENDIAN);
                *l_offset+=4;
                proto_tree_add_bits_item(subtree2,hf_cdma2k_Pilot_Incl, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
                pilotIncl = tvb_get_bits8(tvb,*l_offset, 1);
                *l_offset+=1;
                if(pilotIncl == 1)
                {
                    proto_tree_add_bits_item(subtree2,hf_cdma2k_Code_Chan_Sch, tvb, *l_offset, 11, ENC_BIG_ENDIAN);
                    *l_offset+=11;
                    proto_tree_add_bits_item(subtree2,hf_cdma2k_Qof_Mask_Id_Sch, tvb, *l_offset, 2, ENC_BIG_ENDIAN);
                    *l_offset+=2;
                }
            }
        } /* schIncl  */
    } /* loop  */

    if(chInd == 5 || chInd == 7)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_3xFch_Info_Incl, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
        fchInfoIncl = tvb_get_bits8(tvb,*l_offset, 1);
        *l_offset+=1;
    }
    if(chInd == 2 || chInd == 6 || chInd == 7)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_3xDcch_Info_Incl, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
        dcchInfoIncl = tvb_get_bits8(tvb,*l_offset, 1);
        *l_offset+=1;
    }
    if((fchInfoIncl == 1) || (dcchInfoIncl == 1))
    {
        for(loop = 1; loop <= pilotCnt; loop++)
        {
            item1 = proto_tree_add_item(subtree, hf_cdma2k_Record_Pilots, tvb, *l_offset/8,-1, ENC_NA);
            proto_item_append_text(item1," : [%d]", loop);
            subtree1 = proto_item_add_subtree(item1,ett_cdma2k_subtree2);
            if(fchInfoIncl == 1)
            {
                proto_tree_add_bits_item(subtree1, hf_cdma2k_3xFch_Low_Incl, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
                fchLowIncl = tvb_get_bits8(tvb,*l_offset, 1);
                *l_offset+=1;
                if(fchLowIncl == 1)
                {
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Qof_Mask_Id_Fch_Low, tvb, *l_offset, 2, ENC_BIG_ENDIAN);
                    *l_offset+=2;
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Code_Chan_Fch_Low, tvb, *l_offset, 11, ENC_BIG_ENDIAN);
                    *l_offset+=11;
                }
                proto_tree_add_bits_item(subtree1, hf_cdma2k_3xFch_High_Incl, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
                fchHighIncl = tvb_get_bits8(tvb,*l_offset, 1);
                *l_offset+=1;
                if(fchHighIncl == 1)
                {
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Qof_Mask_Id_Fch_High, tvb, *l_offset, 2, ENC_BIG_ENDIAN);
                    *l_offset+=2;
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Code_Chan_Fch_High, tvb, *l_offset, 11, ENC_BIG_ENDIAN);
                    *l_offset+=11;
                }
            }
            if(dcchInfoIncl == 1)
            {
                proto_tree_add_bits_item(subtree1, hf_cdma2k_3xDcch_Low_Incl, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
                dcchLowIncl = tvb_get_bits8(tvb,*l_offset, 1);
                *l_offset+=1;
                if(dcchLowIncl == 1)
                {
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Qof_Mask_Id_Dcch_Low, tvb, *l_offset, 2, ENC_BIG_ENDIAN);
                    *l_offset+=2;
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Code_Chan_Dcch_Low, tvb, *l_offset, 11, ENC_BIG_ENDIAN);
                    *l_offset+=11;
                }
                proto_tree_add_bits_item(subtree1, hf_cdma2k_3xDcch_High_Incl, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
                dcchHighIncl = tvb_get_bits8(tvb,*l_offset, 1);
                *l_offset+=1;
                if(dcchHighIncl == 1)
                {
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Qof_Mask_Id_Dcch_High, tvb, *l_offset, 2, ENC_BIG_ENDIAN);
                    *l_offset+=2;
                    proto_tree_add_bits_item(subtree1, hf_cdma2k_Code_Chan_Dcch_High, tvb, *l_offset, 11, ENC_BIG_ENDIAN);
                    *l_offset+=11;
                }
            }
            if(schIncl != 0)
            {
                proto_tree_add_bits_item(subtree1, hf_cdma2k_3xSch_Info_Incl, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
                schInfoIncl = tvb_get_bits8(tvb,*l_offset, 1);
                *l_offset+=1;
                if(schInfoIncl == 1)
                {
                    for(loop = 1; loop <= schCnt; loop++)
                    {
                        item2 = proto_tree_add_item(subtree1, hf_cdma2k_Record_Sch, tvb, *l_offset/8,-1, ENC_NA);
                        proto_item_append_text(item2," : [%d]", loop);
                        subtree2 = proto_item_add_subtree(item2,ett_cdma2k_subtree2);
                        proto_tree_add_bits_item(subtree2,hf_cdma2k_Sch_Id, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
                        *l_offset+=1;
                        proto_tree_add_bits_item(subtree2,hf_cdma2k_3xSch_Low_Incl, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
                        schLowIncl = tvb_get_bits8(tvb,*l_offset, 1);
                        *l_offset+=1;
                        if(schLowIncl == 1)
                        {
                            proto_tree_add_bits_item(subtree2,hf_cdma2k_Qof_Mask_Id_Sch_Low, tvb, *l_offset, 2, ENC_BIG_ENDIAN);
                            *l_offset+=2;
                            proto_tree_add_bits_item(subtree2,hf_cdma2k_Code_Chan_Sch_Low, tvb, *l_offset, 11, ENC_BIG_ENDIAN);
                            *l_offset+=11;
                        }
                        proto_tree_add_bits_item(subtree2,hf_cdma2k_3xSch_High_Incl, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
                        schHighIncl = tvb_get_bits8(tvb,*l_offset, 1);
                        *l_offset+=1;
                        if(schHighIncl == 1)
                        {
                            proto_tree_add_bits_item(subtree2,hf_cdma2k_Qof_Mask_Id_Sch_High, tvb, *l_offset, 2, ENC_BIG_ENDIAN);
                            *l_offset+=2;
                            proto_tree_add_bits_item(subtree2,hf_cdma2k_Code_Chan_Sch_High, tvb, *l_offset, 11, ENC_BIG_ENDIAN);
                            *l_offset+=11;
                        }
                    } /* Sch loop */
                } /* schInfoIncl */
            } /* schIncl */
        } /* Pilot loop */
    } /* FchInfoIncl */

    proto_tree_add_bits_item(subtree, hf_cdma2k_Ccsh_Included, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
    ccshIncl = tvb_get_bits8(tvb,*l_offset, 1);
    *l_offset+=1;
    if(ccshIncl  == 1)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_Use_Ccsh_Encoder_Time, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
        ccshEncIncl = tvb_get_bits8(tvb,*l_offset, 1);
        *l_offset+=1;
        if(ccshEncIncl  == 1)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Ccsh_Encoder_Action_Time, tvb, *l_offset, 6, ENC_BIG_ENDIAN);
            *l_offset+=6;
        }
        for(loop = 1; loop <= pilotCnt; loop++)
        {
            item1 = proto_tree_add_item(subtree, hf_cdma2k_Record_Pilots, tvb, *l_offset/8,-1, ENC_NA);
            proto_item_append_text(item1," : [%d]", loop);
            subtree1 = proto_item_add_subtree(item1,ett_cdma2k_subtree2);
            for(loop = 1; loop <= schCnt; loop++)
            {
                item2 = proto_tree_add_item(subtree1, hf_cdma2k_Record_Sch, tvb, *l_offset/8,-1, ENC_NA);
                proto_item_append_text(item2," : [%d]", loop);
                subtree2 = proto_item_add_subtree(item2,ett_cdma2k_subtree2);
                proto_tree_add_bits_item(subtree2,hf_cdma2k_Ccsh_Encoder_Type, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
                *l_offset+=1;
            }
        }
    }

    if(chInd == 2 || chInd == 6 || chInd == 7)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_Fundicated_Bcmc_Ind, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
        bcmcFunIncl = tvb_get_bits8(tvb,*l_offset, 1);
        *l_offset+=1;
        if(chInd == 7 && bcmcFunIncl == 1)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_Rev_Fch_Assigned, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
            *l_offset+=1;
            proto_tree_add_bits_item(subtree, hf_cdma2k_Add_Plcm_For_Fch_Incl, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
            addPlcmFchIncl = tvb_get_bits8(tvb,*l_offset, 1);
            *l_offset+=1;
            if(addPlcmFchIncl == 1)
            {
                proto_tree_add_bits_item(subtree, hf_cdma2k_Add_Plcm_For_Fch_Type, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
                addPlcmFchType = tvb_get_bits8(tvb,*l_offset, 1);
                *l_offset+=1;
                if(addPlcmFchType == 1)
                {
                    proto_tree_add_bits_item(subtree, hf_cdma2k_Add_Plcm_For_Fch_39, tvb, *l_offset, 39, ENC_BIG_ENDIAN);
                    *l_offset+=39;
                }
            }
            proto_tree_add_bits_item(subtree, hf_cdma2k_For_Cpcch_Info_Incl, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
            cpcchInfoIncl = tvb_get_bits8(tvb,*l_offset, 1);
            *l_offset+=1;
        }

        if(((chInd == 2 || chInd == 6) && (bcmcFunIncl == 1)) || ((chInd == 7) && (cpcchInfoIncl == 1)))
        {
            for(loop = 1; loop <= pilotCnt; loop++)
            {
                item1 = proto_tree_add_item(subtree, hf_cdma2k_Record_Pilots, tvb, *l_offset/8,-1, ENC_NA);
                proto_item_append_text(item1," : [%d]", loop);
                subtree1 = proto_item_add_subtree(item1,ett_cdma2k_subtree2);
                proto_tree_add_bits_item(subtree1, hf_cdma2k_For_Cpcch_Walsh, tvb, *l_offset, 7, ENC_BIG_ENDIAN);
                *l_offset+=7;
                proto_tree_add_bits_item(subtree1, hf_cdma2k_For_Cpcsch, tvb, *l_offset, 5, ENC_BIG_ENDIAN);
                *l_offset+=5;
            }
        }
    }

    if(*l_offset%8 != 0)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_Reserved, tvb, *l_offset, (8-(*l_offset%8)), ENC_BIG_ENDIAN);
    }
}


/* Helper function to decode Authentication Field Parameters */
static void cdma2k_message_AUTH_FIELDS(proto_item *item,tvbuff_t *tvb,proto_tree *subtree,guint16 *l_offset, guint16 headerRecLen)
{
    guint16 macIncl = -1, authIncl = -1, sduSseqOrSseqh = -1, endOffset = -1;
    endOffset = *l_offset + (headerRecLen*8);

    proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Mac_Incl, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
    macIncl = tvb_get_bits8(tvb,*l_offset, 1);
    *l_offset+=1;
    proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Auth_Incl, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
    authIncl = tvb_get_bits8(tvb,*l_offset, 1);
    *l_offset+=1;

    if(authIncl == 1)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Authr, tvb, *l_offset, 18, ENC_BIG_ENDIAN);
        *l_offset+=18;
        proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Randc, tvb, *l_offset, 8, ENC_BIG_ENDIAN);
        *l_offset+=8;
        proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Count, tvb, *l_offset, 6, ENC_BIG_ENDIAN);
        *l_offset+=6;
    }

    if(macIncl == 1)
    {
        if(authIncl == 0)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Randc, tvb, *l_offset, 8, ENC_BIG_ENDIAN);
            *l_offset+=8;
        }

        proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Sdu_KeyId, tvb, *l_offset, 2, ENC_BIG_ENDIAN);
        *l_offset+=2;
        proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Sdu_Algo, tvb, *l_offset, 3, ENC_BIG_ENDIAN);
        *l_offset+=3;
        proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Sdu_Sseq_Or_Sseqh, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
        sduSseqOrSseqh = tvb_get_bits8(tvb,*l_offset, 1);
        *l_offset+=1;

        if(sduSseqOrSseqh == 0)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Sdu_Sseq, tvb, *l_offset, 8, ENC_BIG_ENDIAN);
            *l_offset+=8;
        }
        else
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Sdu_Sseqh, tvb, *l_offset, 24, ENC_BIG_ENDIAN);
            *l_offset+=24;
        }
    }

    /*Skip bits till Header Record Length*/
    if(*l_offset < endOffset)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Reserved, tvb, *l_offset, (endOffset-*l_offset), ENC_BIG_ENDIAN);
        *l_offset+=(endOffset-*l_offset);
    }
    else if(*l_offset > endOffset)
    {
        proto_item_append_text(item," : Offset corruption in Authentication Fields");
    }
}


/* Helper function to decode Addressing Field Parameters */
static void cdma2k_message_ADDR_FIELDS(proto_item *item,tvbuff_t *tvb,proto_tree *tree,guint16 *l_offset, guint16 headerRecLen)
{
    proto_item* ti;
    proto_tree *sub_tree;
    guint16 msIdType = -1, extMsIdType = -1, msIdLen = -1, endOffset = -1;

    endOffset = *l_offset + (headerRecLen*8);
    proto_tree_add_bits_item(tree, hf_cdma2k_tlac_Header_Record_MsId_Type, tvb, *l_offset, 3, ENC_BIG_ENDIAN);
    msIdType = tvb_get_bits8(tvb,*l_offset, 3);
    *l_offset+=3;

    if(msIdType == 4)
    {
        proto_tree_add_bits_item(tree, hf_cdma2k_tlac_Header_Record_Ext_MsId_Type, tvb, *l_offset, 3, ENC_BIG_ENDIAN);
        extMsIdType = tvb_get_bits8(tvb,*l_offset, 3);
        *l_offset+=3;
    }

    proto_tree_add_bits_item(tree, hf_cdma2k_tlac_Header_Record_MsId_Length, tvb, *l_offset, 4, ENC_BIG_ENDIAN);
    msIdLen = tvb_get_bits8(tvb,*l_offset, 4);
    *l_offset+=4;

    switch(msIdType)
    {
        case 0:
            ti = proto_tree_add_bits_item(tree, hf_cdma2k_tlac_Header_Record_Imsi_M_S1, tvb, *l_offset, 24, ENC_BIG_ENDIAN);
            sub_tree = proto_item_add_subtree(ti, ett_cdma2k_m_s1);
            proto_tree_add_bits_item(sub_tree, hf_cdma2k_tlac_Header_Record_Imsi_M_S1_sec_3_dig, tvb, *l_offset, 10, ENC_BIG_ENDIAN);
            *l_offset += 10;
            proto_tree_add_bits_item(sub_tree, hf_cdma2k_tlac_Header_Record_Imsi_M_S1_thousand_dig, tvb, *l_offset, 4, ENC_BIG_ENDIAN);
            *l_offset+=4;
            proto_tree_add_bits_item(sub_tree, hf_cdma2k_tlac_Header_Record_Imsi_M_S1_last_3_dig, tvb, *l_offset, 10, ENC_BIG_ENDIAN);
            *l_offset += 10;
            proto_tree_add_bits_item(tree, hf_cdma2k_tlac_Header_Record_Imsi_M_S2, tvb, *l_offset, 10, ENC_BIG_ENDIAN);
            *l_offset+=10;
            proto_tree_add_bits_item(tree, hf_cdma2k_tlac_Header_Record_Esn, tvb, *l_offset, 32, ENC_BIG_ENDIAN);
            *l_offset+=32;
            proto_tree_add_bits_item(tree, hf_cdma2k_tlac_Header_Record_Reserved, tvb, *l_offset, 6, ENC_BIG_ENDIAN);
            *l_offset+=6;
            break;

        case 1:
            proto_tree_add_bits_item(tree, hf_cdma2k_tlac_Header_Record_Esn, tvb, *l_offset, 32, ENC_BIG_ENDIAN);
            *l_offset+=32;
            break;

        case 2:
            cdma2k_message_IMSI_CLASS_SUBFIELDS(item, tvb, tree,l_offset);
            break;

        case 3:
            proto_tree_add_bits_item(tree, hf_cdma2k_tlac_Header_Record_Esn, tvb, *l_offset, 32, ENC_BIG_ENDIAN);
            *l_offset+=32;
            cdma2k_message_IMSI_CLASS_SUBFIELDS(item, tvb, tree,l_offset);
            break;

        case 4:
            switch (extMsIdType)
            {
                case 0:
                    proto_tree_add_bits_item(tree, hf_cdma2k_tlac_Header_Record_Ext_MsId_MeId, tvb, *l_offset, 56, ENC_BIG_ENDIAN);
                    *l_offset+=56;
                    break;

                case 1:
                    proto_tree_add_bits_item(tree, hf_cdma2k_tlac_Header_Record_Ext_MsId_MeId, tvb, *l_offset, 56, ENC_BIG_ENDIAN);
                    *l_offset+=56;
                    cdma2k_message_IMSI_CLASS_SUBFIELDS(item, tvb, tree,l_offset);
                    break;

                case 2:
                    proto_tree_add_bits_item(tree, hf_cdma2k_tlac_Header_Record_Esn, tvb, *l_offset, 32, ENC_BIG_ENDIAN);
                    *l_offset+=32;
                    proto_tree_add_bits_item(tree, hf_cdma2k_tlac_Header_Record_Ext_MsId_MeId, tvb, *l_offset, 56, ENC_BIG_ENDIAN);
                    *l_offset+=56;
                    cdma2k_message_IMSI_CLASS_SUBFIELDS(item, tvb, tree,l_offset);
                    break;

                default:
                    proto_item_append_text(item," : Invalid extMsIdType in Addressing Fields");
                    break;
            }
            break;

        case 5:
            if(msIdLen > 4)
            {
                proto_tree_add_bits_item(tree, hf_cdma2k_tlac_Header_Record_Tmsi_Zone, tvb, *l_offset, (msIdLen-4)*8, ENC_BIG_ENDIAN);
                *l_offset+=((msIdLen-4)*8);
                proto_tree_add_bits_item(tree, hf_cdma2k_tlac_Header_Record_Tmsi_Code_Addr, tvb, *l_offset, 32, ENC_BIG_ENDIAN);
                *l_offset+=32;
            }
            else
            {
                proto_tree_add_bits_item(tree, hf_cdma2k_tlac_Header_Record_Tmsi_Code_Addr, tvb, *l_offset, msIdLen*8, ENC_BIG_ENDIAN);
                *l_offset+=(msIdLen*8);
            }
            break;

        default:
            proto_item_append_text(item," : Invalid msIdType in Addressing Fields");
            break;
    }

    /*Skip bits till Header Record Length*/
    if(*l_offset < endOffset)
    {
        proto_tree_add_bits_item(tree, hf_cdma2k_tlac_Header_Record_Reserved, tvb, *l_offset, (endOffset-*l_offset), ENC_BIG_ENDIAN);
        *l_offset+=(endOffset-*l_offset);
    }
    else if(*l_offset > endOffset)
    {
        proto_item_append_text(item," : Offset corruption in Addressing Fields");
    }
}

/* Helper function to decode Imsi Class and SubField Parameters */
static void cdma2k_message_IMSI_CLASS_SUBFIELDS(proto_item *item,tvbuff_t *tvb, proto_tree *subtree, guint16 *l_offset)
{
    guint16 imsi_class = -1, classType = -1;

    proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Imsi_Class, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
    imsi_class = tvb_get_bits8(tvb,*l_offset, 1);
    *l_offset+=1;

    if(imsi_class == 0)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Imsi_Class0_Type, tvb, *l_offset, 2, ENC_BIG_ENDIAN);
        classType = tvb_get_bits8(tvb,*l_offset, 2);
        *l_offset+=2;

        switch (classType)
            {
                case 0:
                    proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Reserved, tvb, *l_offset, 3, ENC_BIG_ENDIAN);
                    *l_offset+=3;
                    proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Imsi_S2, tvb, *l_offset, 10, ENC_BIG_ENDIAN);
                    *l_offset+=10;
                    proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Imsi_S1, tvb, *l_offset, 24, ENC_BIG_ENDIAN);
                    *l_offset+=24;
                    break;

                case 1:
                    proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Reserved, tvb, *l_offset, 4, ENC_BIG_ENDIAN);
                    *l_offset+=4;
                    proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Imsi_11_12, tvb, *l_offset, 7, ENC_BIG_ENDIAN);
                    *l_offset+=7;
                    proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Imsi_S2, tvb, *l_offset, 10, ENC_BIG_ENDIAN);
                    *l_offset+=10;
                    proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Imsi_S1, tvb, *l_offset, 24, ENC_BIG_ENDIAN);
                    *l_offset+=24;
                    break;

                case 2:
                    proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Reserved, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
                    *l_offset+=1;
                    proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_MCC, tvb, *l_offset, 10, ENC_BIG_ENDIAN);
                    *l_offset+=10;
                    proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Imsi_S2, tvb, *l_offset, 10, ENC_BIG_ENDIAN);
                    *l_offset+=10;
                    proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Imsi_S1, tvb, *l_offset, 24, ENC_BIG_ENDIAN);
                    *l_offset+=24;
                    break;

                case 3:
                    proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Reserved, tvb, *l_offset, 2, ENC_BIG_ENDIAN);
                    *l_offset+=2;
                    proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_MCC, tvb, *l_offset, 10, ENC_BIG_ENDIAN);
                    *l_offset+=10;
                    proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Imsi_11_12, tvb, *l_offset, 7, ENC_BIG_ENDIAN);
                    *l_offset+=7;
                    proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Imsi_S2, tvb, *l_offset, 10, ENC_BIG_ENDIAN);
                    *l_offset+=10;
                    proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Imsi_S1, tvb, *l_offset, 24, ENC_BIG_ENDIAN);
                    *l_offset+=24;
                    break;

                default:
                    proto_item_append_text(item," : Invalid Class0 Type in Addressing Fields");
                    break;
            }
    }
    else if(imsi_class == 1)
    {
        proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Imsi_Class1_Type, tvb, *l_offset, 1, ENC_BIG_ENDIAN);
        classType = tvb_get_bits8(tvb,*l_offset, 1);
        *l_offset+=1;

        if(classType == 0)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Reserved, tvb, *l_offset, 2, ENC_BIG_ENDIAN);
            *l_offset+=2;
            proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Imsi_Addr_Num, tvb, *l_offset, 3, ENC_BIG_ENDIAN);
            *l_offset+=3;
            proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Imsi_11_12, tvb, *l_offset, 7, ENC_BIG_ENDIAN);
            *l_offset+=7;
            proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Imsi_S2, tvb, *l_offset, 10, ENC_BIG_ENDIAN);
            *l_offset+=10;
            proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Imsi_S1, tvb, *l_offset, 24, ENC_BIG_ENDIAN);
            *l_offset+=24;
        }
        else if(classType == 1)
        {
            proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Imsi_Addr_Num, tvb, *l_offset, 3, ENC_BIG_ENDIAN);
            *l_offset+=3;
            proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_MCC, tvb, *l_offset, 10, ENC_BIG_ENDIAN);
            *l_offset+=10;
            proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Imsi_11_12, tvb, *l_offset, 7, ENC_BIG_ENDIAN);
            *l_offset+=7;
            proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Imsi_S2, tvb, *l_offset, 10, ENC_BIG_ENDIAN);
            *l_offset+=10;
            proto_tree_add_bits_item(subtree, hf_cdma2k_tlac_Header_Record_Imsi_S1, tvb, *l_offset, 24, ENC_BIG_ENDIAN);
            *l_offset+=24;
        }
        else
        {
            proto_item_append_text(item," : Invalid Class1 Type in Addressing Fields");
        }
    }
    else
    {
        proto_item_append_text(item," : Invalid Class in Addressing Fields");
    }
}


/*Method called when the dissection starts.....Starting point*/
static int
dissect_cdma2k(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

    /* Initialization*/
    proto_tree *cdma2k_msghdr_tree_start = NULL;

    proto_item *item = NULL;

    guint32 offset = 0;
    guint16 noerror = 1;

    /*Add the protocol name to display*/
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CDMA2K");
    col_add_fstr(pinfo->cinfo, COL_INFO, "[CDMA2K]");

    item = proto_tree_add_item(tree, hf_cdma2k_msghdr, tvb, 0, -1, ENC_NA);
    cdma2k_msghdr_tree_start =  proto_item_add_subtree(item, ett_cdma2k_msghdr);

    item = proto_tree_add_item(cdma2k_msghdr_tree_start, hf_cdma2k_tlac_Record, tvb, offset, 1, ENC_NA );

    if (tree)
    {
        while(tvb_captured_length_remaining(tvb, offset) != 0 && noerror == 1)
            cdma2k_message_decode(item, tvb, cdma2k_msghdr_tree_start, &offset, tree, &noerror, pinfo);

        if(noerror == 0)
        {
            expert_add_info(pinfo, item, &ei_cdma2k_error);
        }

    }
    return tvb_reported_length(tvb);
}


/*Register cdma2k */
void proto_register_cdma2k(void)
{
    static hf_register_info hf[] = {
            { &hf_cdma2k_tlac_Record,
            { "TLAC Header Record and L3PDU", "cdma2k.tlacRecord", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header,
            { "TLAC Header", "cdma2k.tlacHeader", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Channel,
            { "Channel Type", "cdma2k.tlacChannel", FT_UINT8, BASE_HEX_DEC, VALS(Channel_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_1x_Protocol_Revision,
            { "1x Protocol Revision", "cdma2k.tlac1xProtocolRevision", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_msgType,
            { "CDMA2K Message Type", "cdma2k.MsgType", FT_UINT8, BASE_HEX_DEC, VALS(Cdma2k_Message_types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record,
            { "TLAC Header Record", "cdma2k.tlacHeaderRecord", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Records_Count,
            { "Header Record Count", "cdma2k.tlacHeaderRecordCount", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Type ,
            { "Header Record Type", "cdma2k.tlacHeaderRecordType", FT_UINT8, BASE_HEX_DEC, VALS(Header_Record_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Length,
            { "Header Record Length", "cdma2k.tlacHeaderRecordLength", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Values,
            { "Header Record Data :", "cdma2k.tlacHeaderRecordData", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Reserved,
            { "Reserved", "cdma2k.tlacHeaderRecordReservedData", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_MsId_Type,
            { "MsId Type", "cdma2k.tlacHeaderRecordMsIdType", FT_UINT8, BASE_HEX_DEC, VALS(MsId_Address_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Ext_MsId_Type,
            { "Ext MsId Type", "cdma2k.tlacHeaderRecordExtMsIdType", FT_UINT8, BASE_HEX_DEC, VALS(Ext_MsId_Address_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_MsId_Length,
            { "MsId Length", "cdma2k.tlacHeaderRecordMsIdLength", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Imsi_M_S1,
            { "Imsi M S1", "cdma2k.tlacHeaderRecordImsiMS1", FT_UINT24, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Imsi_M_S1_sec_3_dig,
            { "Second 3 digits", "cdma2k.tlacHeaderRecordImsiMS1sec_3_dig", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Imsi_M_S1_thousand_dig,
            { "Thousands Digit", "cdma2k.tlacHeaderRecordImsiMS1thousand_dig", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Imsi_M_S1_last_3_dig,
            { "Last 3 digits", "cdma2k.tlacHeaderRecordImsiMS1last_3_dig", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Imsi_M_S2,
            { "Imsi M S2", "cdma2k.tlacHeaderRecordImsiMS2", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Esn,
            { "Esn", "cdma2k.tlacHeaderRecordEsn", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Imsi_Class,
            { "Imsi Class", "cdma2k.tlacHeaderRecordImsiClass", FT_UINT8, BASE_HEX_DEC, VALS(Imsi_Class), 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Imsi_Class0_Type,
            { "Imsi Class Type", "cdma2k.tlacHeaderRecordImsiClass0Type", FT_UINT8, BASE_HEX_DEC, VALS(Imsi_Class0_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Imsi_Class1_Type,
            { "Imsi Class Type", "cdma2k.tlacHeaderRecordImsiClass1Type", FT_UINT8, BASE_HEX_DEC, VALS(Imsi_Class1_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Imsi_S2,
            { "Imsi S2", "cdma2k.tlacHeaderRecordImsiS2", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Imsi_S1,
            { "Imsi S1", "cdma2k.tlacHeaderRecordImsiS1", FT_UINT24, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Imsi_11_12,
            { "Imsi 11 12", "cdma2k.tlacHeaderRecordImsi1112", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_MCC,
            { "Mcc", "cdma2k.tlacHeaderRecordMcc", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Imsi_Addr_Num,
            { "Imsi Addr Num", "cdma2k.tlacHeaderRecordImsiAddrNum", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Ext_MsId_MeId,
            { "Ext MsId MeId", "cdma2k.tlacHeaderRecordExtMsIdMeId", FT_UINT64, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Tmsi_Code_Addr,
            { "Tmsi Code Addr", "cdma2k.tlacHeaderRecordTmsiCodeAddr", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Tmsi_Zone,
            { "Tmsi Zone", "cdma2k.tlacHeaderRecordTmsiZone", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Mac_Incl,
            { "Maci Incl", "cdma2k.tlacHeaderRecordMacIncl", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Auth_Incl,
            { "Auth Incl", "cdma2k.tlacHeaderRecordAuthIncl", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Authr,
            { "Authr", "cdma2k.tlacHeaderRecordAuthr", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Randc,
            { "Randc", "cdma2k.tlacHeaderRecordRandc", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Count,
            { "Count", "cdma2k.tlacHeaderRecordCount", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Sdu_KeyId,
            { "Sdu Key Id", "cdma2k.tlacHeaderRecordSduKeyId", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Sdu_Algo,
            { "Sdu Integrity Algo", "cdma2k.tlacHeaderRecordSduAlgo", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Sdu_Sseq,
            { "Sdu Sseq", "cdma2k.tlacHeaderRecordSduSseq", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Sdu_Sseqh,
            { "Sdu Sseqh", "cdma2k.tlacHeaderRecordSduSseqh", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Header_Record_Sdu_Sseq_Or_Sseqh,
            { "Sdu Sseq Or Sseqh", "cdma2k.tlacHeaderRecordSduSseqOrSseqh", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Pdu,
            { "1x LAYER3 PDU", "cdma2k.tlacPdu", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_tlac_Pdu_Length,
            { "1x LAYER3 PDU Length", "cdma2k.tlacPduLength", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_RegMsg,
            { "Registration Message", "cdma2k.RegMsg", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_OrderIndMsg,
            { "Order Indication Message", "cdma2k.OrderIndMsg", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_DataBurstIndMsg,
            { "Data Burst Indication Message", "cdma2k.DataBurstIndMsg", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_OrigMsg,
            { "Origination Message", "cdma2k.OrigMsg", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_PageRspMsg,
            { "Page Response Message", "cdma2k.PageRspMsg", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_AuthChallRspMsg,
            { "Authentication Challenge Response Message", "cdma2k.AuthChallRspMsg", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_DataBurstCmdMsg,
            { "Data Burst Command Message", "cdma2k.DataBurstCmdMsg", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_AuthChallReqMsg,
            { "Authentication Challenge Request Message", "cdma2k.AuthChallReqMsg", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_GenPageReqMsg,
            { "Page Request Message", "cdma2k.GenPageReqMsg", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_msghdr,
            { "CDMA2000 Application Protocol", "cdma2k.msghdr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Reg_Type,
            { "Reg Type", "cdma2k.Reg_Type", FT_UINT8, BASE_HEX_DEC, VALS(Reg_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Slot_Cycle_Index,
            { "Slot Cycle Index", "cdma2k.Slot_Cycle_Index", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Mob_P_Rev,
            { "MobPRev Value", "cdma2k.Mob_P_Rev", FT_UINT8, BASE_HEX_DEC,NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Ext_Scm,
            { "Ext Scm", "cdma2k.Ext_Scm", FT_UINT8, BASE_HEX_DEC,NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Sloted_Mode,
            { "Slotted Mode", "cdma2k.Slotted_Mode", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Mob_Term,
            { "Mob Term", "cdma2k.Mob_Term", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Return_Cause,
            { "Return Cause", "cdma2k.Return_Cause", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Qpch_Supported,
            { "Qpch Supported", "cdma2k.pch_Supported", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Enhanced_Rc,
            { "Enhanced Rc", "cdma2k.Enhanced_Rc", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Uzid_Incl,
            { "Uzid Incl", "cdma2k.Uzid_Incl", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Uzid,
            { "Uzid", "cdma2k.Uzid", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_GeoLoc_Incl,
            { "GeoLoc Incl", "cdma2k.GeoLoc_Incl", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_GeoLoc_Type,
            { "GeoLoc Type", "cdma2k.GeoLoc_Type", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Order_Ind,
            { "Order Value", "cdma2k.Order_Ind", FT_UINT8, BASE_HEX_DEC, VALS(Order_Ind_Cause_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Order_Cmd,
            { "Order Value", "cdma2k.Order_Cmd", FT_UINT8, BASE_HEX_DEC, VALS(Order_Cmd_Cause_Types), 0xfc, NULL, HFILL } },
            { &hf_cdma2k_Add_Record_Len,
            { "Add Record Len", "cdma2k.Add_Record_Len", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Order_Specific_Fields,
            { "Order Specific Fields", "cdma2k.Order_Specific_Fields", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Ordq,
            { "Order Qualification", "cdma2k.Ordq", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Randbs,
            { "Random Chall Data", "cdma2k.Randbs", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Rejected_Type,
            { "Rejected Message Type", "cdma2k.Rejected_Type", FT_UINT8, BASE_HEX_DEC, VALS(Cdma2k_Message_types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Rejected_Order,
            { "Order of Rejected Message", "cdma2k.Rejected_Order", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Rejected_Ordq,
            { "Order Qualification of Rejected Message", "cdma2k.Rejected_Ordq", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Rejected_Parm_Id,
            { "Rejected Parameter", "cdma2k.Rejected_Parm_Id", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Rejected_Record,
            { "Rejected Record Type", "cdma2k.Rejected_Record", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Tag,
            { "Transaction Identifier", "cdma2k.Tag", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Rsc_Mode_Ind,
            { "Reduced Slot Cycle Mode Indication", "cdma2k.Rsc_Mode_Ind", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Rsci,
            { "Reduced Slot Cycle Mode Index", "cdma2k.Rsci", FT_UINT8, BASE_HEX_DEC, VALS(RSCI_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Rsc_End_Time_Unit,
            { "Reduced Slot Cycle Mode End Time Unit", "cdma2k.Rsc_End_Time_Unit", FT_UINT8, BASE_HEX_DEC, VALS(Rsc_End_Time_Unit_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Rsc_End_Time_Value,
            { "Reduced Slot Cycle Mode End Time Value", "cdma2k.Rsc_End_Time_Value", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Con_Ref,
            { "Connection Reference", "cdma2k.Con_Ref", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Authbs,
            { "Authbs", "cdma2k.Authbs", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Roam_Ind,
            { "Roam Indicator", "cdma2k.Roam_Ind", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_C_Sig_Encrypt_Mode,
            { "Encrypt Mode", "cdma2k.C_Sig_Encrypt_Mode", FT_UINT8, BASE_HEX_DEC, VALS(C_Sig_Encrypt_Mode_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Enc_Key_Size,
            { "Enc Key Size", "cdma2k.Enc_Key_Size", FT_UINT8, BASE_HEX_DEC, VALS(Enc_Key_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Msg_Int_Info_Incl,
            { "Msg Int Info Incl", "cdma2k.Msg_Int_Info_Incl", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Change_Keys,
            { "Change Keys", "cdma2k.Change_Keys", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Use_Uak,
            { "Use Uak", "cdma2k.Use_Uak", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Retry_Type,
            { "Retry Type", "cdma2k.Retry_Type", FT_UINT8, BASE_HEX_DEC, VALS(Retry_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Retry_Delay,
            { "Retry Delay", "cdma2k.Retry_Delay", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Reject_Reason,
            { "Reject Reason", "cdma2k.Reject_Reason", FT_UINT8, BASE_HEX_DEC, VALS(Reject_Reason_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Rejected_Msg_Type,
            { "Rejected Message Type", "cdma2k.Rejected_Msg_Type", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Rejected_Msg_Seq,
            { "Rejected Message Sequence", "cdma2k.Rejected_Msg_Seq", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_All_Bcmc_Flows_Ind,
            { "All BCMC Flows Indication", "cdma2k.All_Bcmc_Flows_Ind", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Clear_All_Retry_Delay,
            { "Clear All Retry Delay", "cdma2k.Clear_All_Retry_Delay", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_All_Bcmc_Reason,
            { "All BCMC Reason", "cdma2k.All_Bcmc_Reason", FT_UINT8, BASE_HEX_DEC, VALS(All_Bcmc_Reason_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_All_Bcmc_Retry_Delay,
            { "All BCMC Retry Delay", "cdma2k.All_Bcmc_Retry_Delay", FT_UINT8, BASE_HEX_DEC, VALS(All_Bcmc_Retry_Delay_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Num_Bcmc_Programs,
            { "Number of BCMC Programs", "cdma2k.Num_Bcmc_Programs", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Bcmc_Program_Id_Len,
            { "BCMC Program ID Length", "cdma2k.Bcmc_Program_Id_Len", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Bcmc_Program_Id,
            { "BCMC Program ID", "cdma2k.Bcmc_Program_Id", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Bcmc_Flow_Discriminator_Len,
            { "BCMC Flow Discriminator Length", "cdma2k.Bcmc_Flow_Discriminator_Len", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Num_Flow_Discriminator,
            { "Number of Flow Discriminator", "cdma2k.Num_Flow_Discriminator", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Bcmc_Flow_Discriminator ,
            { "BCMC Flow Discriminator", "cdma2k.Bcmc_Flow_Discriminator", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Same_As_Previous_Bcmc_Flow,
            { "Same As Previous BCMC Flow", "cdma2k.Same_As_Previous_Bcmc_Flow", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Bcmc_Reason,
            { "BCMC Reason", "cdma2k.Bcmc_Reason", FT_UINT8, BASE_HEX_DEC, VALS(All_Bcmc_Reason_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Bcmc_Retry_Delay,
            { "BCMC Retry Delay", "cdma2k.Bcmc_Retry_Delay", FT_UINT8, BASE_HEX_DEC, VALS(All_Bcmc_Retry_Delay_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Rsc_Mode_Supported,
            { "Reduced Slot Cycle Mode Supported", "cdma2k.Rsc_Mode_Supported", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Max_Rsc_End_Time_Unit,
            { "Maximum RSC End Time Unit", "cdma2k.Max_Rsc_End_Time_Unit", FT_UINT8, BASE_HEX_DEC, VALS(Max_rsc_End_Time_unit_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Max_Rsc_End_Time_Value,
            { "maximum RSC End Time Value", "cdma2k.Max_Rsc_End_Time_Value", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Req_Rsci,
            { "Requested Reduced Slot Cycle index", "cdma2k.Req_Rsci", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Ignore_Qpch,
            { "Ignore QPCH Indicators", "cdma2k.Ignore_Qpch", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Rer_Mode_Incl,
            { "Radio Environment Reporting Mode Indicator", "cdma2k.Rer_Mode_Incl", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Rer_Mode_Enabled,
            { "Radio Environment Reporting Mode Enabled", "cdma2k.Rer_Mode_Enabled", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Rer_Max_Num_Msg_Idx,
            { "RER Maximum Message Index", "cdma2k.Rer_Max_Num_Msg_Idx", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Rer_Time,
            { "Radio Environment Reporting Time", "cdma2k.Rer_Time", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Rer_Time_Unit,
            { "Radio Environment Reporting Time Unit", "cdma2k.Rer_Time_Unit", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Max_Rer_Pilot_List_Size,
            { "Maximum RER pilot List Size", "cdma2k.Max_Rer_Pilot_List_Size", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Tkz_Mode_Incl,
            { "Tracking Zone Mode Indication", "cdma2k.Tkz_Mode_Incl", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Tkz_Mode_Enabled,
            { "Tracking Zone Mode Enabled", "cdma2k.Tkz_Mode_Enabled", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Tkz_Max_Num_Msg_Idx,
            { "Tracking Zone Maximum Message Index", "cdma2k.Tkz_Max_Num_Msg_Idx", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Tkz_Update_Prd,
            { "Tracking Zone Update Period", "cdma2k.Tkz_Update_Prd", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Tkz_List_Len,
            { "Tracking Zone List Length", "cdma2k.Tkz_List_Len", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Tkz_Timer,
            { "Tracking Zone Timer", "cdma2k.Tkz_Timer", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Sr_Id_Bitmap,
            { "Service Reference Identifier Bitmap", "cdma2k.Sr_Id_Bitmap", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Service_Status,
            { "Service Status", "cdma2k.Service_Status", FT_UINT8, BASE_HEX_DEC, VALS(Service_Status_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Regulatory_Ind_Incl,
            { "Regulatory Indicator Included", "cdma2k.Regulatory_Ind_Incl", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Regulatory_Ind,
            { "Regulatory Indication", "cdma2k.Regulatory_Ind", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Msg_Number,
            { "Msg Number", "cdma2k.Msg_Number", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Burst_Type,
            { "Burst Type", "cdma2k.Burst_Type", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Num_Msgs,
            { "Num Msgs", "cdma2k.Num_Msgs", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Num_Fields,
            { "Num Fields", "cdma2k.Num_Fields", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Chari_Data,
            { "Chari Data", "cdma2k.Chari_Data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Msg_Identifier,
            { "Msg Identifier", "cdma2k.Msg_Identifier", FT_UINT8, BASE_HEX_DEC, VALS(Chari_Identifier_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Parm_Id,
            { "Parm Id", "cdma2k.Parm_Id", FT_UINT8, BASE_HEX_DEC, VALS(Chari_Parm_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Parm_Length,
            { "Parm Length", "cdma2k.Parm_Length", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Parm_Value,
            { "Parm Data", "cdma2k.Parm_Value", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Authu,
            { "Authu", "cdma2k.Authu", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Randu,
            { "Randu", "cdma2k.Randu", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Gen_Cmea_Key,
            { "Gen Cmea Key", "cdma2k.Gen_Cmea_Key", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_service_option,
            { "Service Option", "cdma2k.service_option", FT_UINT32, BASE_HEX_DEC, VALS(Page_Req_Service_Option_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Use_Time,
            { "Use Time", "cdma2k.Use_Time", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Action_Time,
            { "Action Time", "cdma2k.Action_Time", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Hdm_Seq,
            { "Sequence Number", "cdma2k.Hdm_Seq", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Parms_Incl,
            { "Parameters Incl", "cdma2k.Parms_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_P_Rev,
            { "Protocol Revision", "cdma2k.P_Rev", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Serv_Neg_Type,
            { "Service Negotiation", "cdma2k.Serv_Neg_Type", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Search_Incl,
            { "Pilot Search Incl", "cdma2k.Search_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Pilot_Search,
            { "Pilot Search Parameters", "cdma2k.Search", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Srch_Win_A,
            { "Search Window size for Active Set", "cdma2k.Srch_Win_A", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Srch_Win_N,
            { "Search Window size for Neighbour Set", "cdma2k.Srch_Win_N", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Srch_Win_R,
            { "Search Window size for Remaining Set", "cdma2k.Srch_Win_R", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_T_Add,
            { "Pilot Detection Threshold", "cdma2k.T_Add", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_T_Drop,
            { "Pilot Drop Threshold", "cdma2k.T_Drop", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_T_Comp,
            { "Active vs Candidate Set Comp Threshold", "cdma2k.T_Comp", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_T_Tdrop,
            { "Drop Timer Value", "cdma2k.T_Tdrop", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Soft_Slope,
            { "Soft Slope", "cdma2k.Soft_Slope", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Add_Intercept,
            { "Add Pilot Intercept", "cdma2k.Add_Intercept", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Drop_Intercept,
            { "Drop Pilot Intercept", "cdma2k.Drop_Intercept", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Extra_Parms_Incl,
            { "Extra Parms Incl", "cdma2k.Extra_Parms_incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Extra_Parms,
            { "Extra Parameters", "cdma2k.Extra_Parms", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Packet_Zone_Id,
            { "Packet Zone Identifier", "cdma2k.Packet_Zone_Id", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Frame_Offset,
            { "Frame Offset", "cdma2k.Frame_Offset", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Private_Lcm,
            { "Private LCM", "cdma2k.Private_Lcm", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Reset_L2,
            { "Reset L2 Ack", "cdma2k.Reset_L2", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Reset_Fpc,
            { "Reset Fch Power Cntrl Cntrs", "cdma2k.Reset_Fpc", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Encrypt_Mode,
            { "Msg Encryption Mode", "cdma2k.Encrypt_Mode", FT_UINT8, BASE_HEX_DEC, VALS(Encrypt_Mode_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Nom_Pwr_Ext,
            { "Ext Nominal Transmit Power", "cdma2k.Nom_Pwr_Ext", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Nom_Pwr,
            { "Nominal Transmit Power Offset", "cdma2k.Nom_Pwr", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Rlgain_Traffic_Pilot,
            { "Rlgain Of Traffic Pilot", "cdma2k.Rlgain_Traffic_Pilot", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Default_Rlag,
            { "Reverse Link Attr Gain", "cdma2k.Default_Rlag", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Num_Preamble,
            { "Traffic Channel Preamble", "cdma2k.Num_Preamble", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Band_Class,
            { "Band Class", "cdma2k.Band_Class", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Cdma_Freq,
            { "Frequency Assignment", "cdma2k.Cdma_Freq", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Return_If_Handoff_Fail,
            { "Return On Failure", "cdma2k.Return_If_Handoff_Fail", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Complete_Search,
            { "Complete Search", "cdma2k.Complete_Search", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Periodic_Search,
            { "Periodic Search", "cdma2k.Periodic_Search", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Scr_Incl,
            { "Scr Incl", "cdma2k.Scr_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Scr,
            { "Service Config Records", "cdma2k.Scr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Serv_Con_Seq,
            { "Service Connect Sequence Number", "cdma2k.Serv_Con_Seq", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Record_Type,
            { "Information Record Type", "cdma2k.Record_Type", FT_UINT8, BASE_HEX_DEC, VALS(Info_Rec_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Record_Len,
            { "Information Record Length", "cdma2k.Record_Len", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Type_Specific_Fields,
            { "Type Specific Fields :", "cdma2k.Type_Specific_Fields", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Nnscr_Incl,
            { "Nnscr Incl", "cdma2k.Nnscr_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Nnscr,
            { "Non-Negotiable Service Config Records", "cdma2k.Nnscr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Use_Pwr_Cntl_Step,
            { "Power Control Step Size Incl", "cdma2k.Use_Pwr_Cntl_Step", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Pwr_Cntl_Step,
            { "Power Control Step Size", "cdma2k.Pwr_Cntl_Step", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Clear_Retry_Delay,
            { "Clear Retry Delay Indicator", "cdma2k.Clear_Retry_Delay", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Sch_Incl,
            { "Supplemented Channel Parms Incl", "cdma2k.Sch_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Sch,
            { "Supplemental Channel Parameters", "cdma2k.Sch", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Num_For_Assign,
            { "Forward Channels Assigned", "cdma2k.Num_For_Assign", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Record_For_Assign,
            { "Forward Channel Records", "cdma2k.Record_For_Assign", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Sch_Id,
            { "Channel Identifier", "cdma2k.Sch_Id", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Sch_Duration,
            { "Channel Assignment Duration", "cdma2k.Sch_Duration", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Sch_Start_Time_Incl,
            { "Start Time Incl", "cdma2k.Sch_Start_Time_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Sch_Start_Time,
            { "Start Time", "cdma2k.Sch_Start_Time", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Sccl_Index,
            { "Channel Code List Index", "cdma2k.Sccl_Index", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Num_Rev_Assign,
            { "Reverse Channels Assigned", "cdma2k.Num_Rev_Assign", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Record_Rev_Assign,
            { "Reverse Channel Records", "cdma2k.Record_Rev_Assign", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Sch_Num_Bits_Idx,
            { "Bits Per Frame Index", "cdma2k.Sch_Num_Bits_Idx", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Fpc_Subchain_Gain,
            { "Fwd Pwr Cntl Subchannel Rel Gain", "cdma2k.Fpc_Subchain_Gain", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Use_Pc_Time,
            { "Pwr Cntl Action Time Incl", "cdma2k.Use_Pc_Time", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Pc_Action_Time,
            { "Pwr Cntl Action Time", "cdma2k.Pc_Action_Time", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Ch_Ind,
            { "Channel Indicator", "cdma2k.Ch_Ind", FT_UINT8, BASE_HEX_DEC, VALS(l3dpu_ORM_ch_ind_values), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Active_Set_Rec_Len,
            { "Active Set Rec Length", "cdma2k.Active_Set_Rec_Len", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Active_Set_Rec_Fields,
            { "Active Set Rec Fields", "cdma2k.Active_Set_Rec_Fields", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Rev_Fch_Gating_Mode,
            { "Rev Gating Mode Indicator", "cdma2k.Rev_Fch_Gating_Mode", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Rev_Pwr_Cntl_Delay_Incl,
            { "Rev Pwr Cntl Delay Incl", "cdma2k.Rev_Pwr_Cntl_Delay_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Rev_Pwr_Cntl_Delay,
            { "Rev Pwr Cntl Delay", "cdma2k.Rev_Pwr_Cntl_Delay", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_D_Sig_Encrypt_Mode,
            { "Dedicated Chan Encryption Mode Ind", "cdma2k.D_Sig_Encrypt_Mode", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_3xfl_1xrl_Incl,
            { "3x Fwd & 1x Rev Link Incl", "cdma2k.3xfl_1xrl_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_1xrl_Freq_Offset,
            { "1x Rev Link Freq Offset", "cdma2k.1xrl_Freq_Offset", FT_UINT8, BASE_HEX_DEC, VALS(rl_Freq_Offset_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Sync_Id_Incl,
            { "Sync Identifier Incl", "cdma2k.Sync_Id_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Sync_Id_Len,
            { "Sync Identifier Len", "cdma2k.Sync_Id_Len", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Sync_Id,
            { "Sync Identifier :", "cdma2k.Sync_Id", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Cc_Info_Incl,
            { "Call Cntl Info Incl", "cdma2k.Cc_Info_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Num_Calls_Assign,
            { "Number Of Call Assignments", "cdma2k.Num_Calls_Assign", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Record_Calls_Assign,
            { "Call Assignment Records", "cdma2k.Record_Calls_Assign", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Response_Ind,
            { "Response Indicator", "cdma2k.Response_Ind", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Bypass_Alert_Answer,
            { "Bypass Alert Answer", "cdma2k.Bypass_Alert_Answer", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Cs_Supported,
            { "Concurrent Services Supported", "cdma2k.Cs_Supported", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Chm_Supported,
            { "Control Hold Mode Supported", "cdma2k.Chm_Supported", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Cdma_Off_Time_Rep_Sup_Ind,
            { "CDMA Off Time Report Supported", "cdma2k.Cdma_Off_Time_Rep_Sup_Ind", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Cdma_Off_Time_Rep_Threshold_Unit,
            { "Threshold Unit", "cdma2k.Cdma_Off_Time_Rep_Threshold_Unit", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Cdma_Off_Time_Rep_Threshold,
            { "Threshold", "cdma2k.Cdma_Off_Time_Rep_Threshold", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Release_To_Idle_Ind,
            { "Release To Idle Allowed", "cdma2k.Release_To_Idle_Ind", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Msg_Integrity_Sup,
            { "Msg Integrity Supported", "cdma2k.Msg_Integrity_Sup", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Gen_2g_Key,
            { "Generate 2G Encryption Key", "cdma2k.Gen_2g_Key", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Register_In_Idle,
            { "Register In Idle State", "cdma2k.Register_In_Idle", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Plcm_Type_Incl,
            { "PLCM Type Incl", "cdma2k.Plcm_Type_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Plcm_Type,
            { "PLCM Type", "cdma2k.Plcm_Type", FT_UINT8, BASE_HEX_DEC, VALS(Plcm_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Plcm_39,
            { "PLCM 39", "cdma2k.Plcm_39", FT_UINT64, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_T_Tdrop_Range_Incl,
            { "Drop Timer Range Incl", "cdma2k.T_Tdrop_Range_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_T_Tdrop_Range,
            { "Drop Timer Range", "cdma2k.T_Tdrop_Range", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_For_Pdch_Supported,
            { "For Packet Data Channel Supported", "cdma2k.For_Pdch_Supported", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Pdch_Chm_Supported,
            { "PDCh Cntl Mode Supported", "cdma2k.Pdch_Chm_Supported", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Pilot_Info_Req_Supported,
            { "Pilot Info Req Supported", "cdma2k.Pilot_Info_Req_Supported", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Enc_Supported,
            { "Encryption Fields Incl", "cdma2k.Enc_Supported", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Sig_Encrypt_Sup,
            { "Signalling Encryption Supported", "cdma2k.Sig_Encrypt_Sup", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Ui_Encrypt_Sup,
            { "User Info Encryption Supported", "cdma2k.Ui_Encrypt_Sup", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Use_Sync_Id,
            { "Sync Id Supported", "cdma2k.Use_Sync_Id", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Sid_Incl,
            { "System Identification Incl", "cdma2k.Sid_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Sid,
            { "System Identification", "cdma2k.Sid", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Nid_Incl,
            { "Network Identification Incl", "cdma2k.Nid_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Nid,
            { "Network Identification", "cdma2k.Nid", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Sdb_Supported,
            { "Short Data Burst Indicator", "cdma2k.Sdb_Supported", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Mob_Qos,
            { "MS QoS Parm Req", "cdma2k.Mob_Qos", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Ms_Init_Pos_Loc_Sup_Ind,
            { "MS Pos Loc Supported", "cdma2k.Ms_Init_Pos_Loc_Sup_Ind", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Rev_Pdch_Supported,
            { "Rev Packet Data Channel Supported", "cdma2k.Rev_Pdch_Supported", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Pz_Hyst_Enabled,
            { "Packet Zone Hysteresis Enabled", "cdma2k.Pz_Hyst_Enabled", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Pz_Hyst_Info_Incl,
            { "Packet Zone Hysteresis Info Incl", "cdma2k.Pz_Hyst_Info_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Pz_Hyst_List_Len,
            { "Packet Zone Hysteresis List Length", "cdma2k.Pz_Hyst_List_Len", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Pz_Hyst_Act_Timer,
            { "Packet Zone Hysteresis Act Timer", "cdma2k.Pz_Hyst_Act_Timer", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Pz_Hyst_Timer_Mul,
            { "Packet Zone Hysteresis Timer Multiplier", "cdma2k.Pz_Hyst_Timer_Mul", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Pz_Hyst_Timer_Exp,
            { "Packet Zone Hysteresis Timer Exponent", "cdma2k.Pz_Hyst_Timer_Exp", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Bcmc_On_Traffic_Sup,
            { "BCMC On Tch Supported", "cdma2k.Bcmc_On_Traffic_Sup", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Auto_Re_Traffic_Allowed_Ind,
            { "BCMC Req On Tch Allowed", "cdma2k.Auto_Re_Traffic_Allowed_Ind", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Sch_Bcmc_Ind,
            { "BCMC On Sch Indicator", "cdma2k.Sch_Bcmc_Ind", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Add_Plcm_For_Sch_Incl,
            { "For Sch Additional PLCM Incl", "cdma2k.Add_Plcm_For_Sch_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Add_Plcm_For_Sch_Type,
            { "For Sch Additional PLCM Type", "cdma2k.Add_Plcm_For_Sch_Type", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Add_Plcm_For_Sch_35,
            { "For Sch Additional PLCM", "cdma2k.Add_Plcm_For_Sch_35", FT_UINT64, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Record_Sch_Bcmc,
            { "Sch BCMC Records", "cdma2k.Record_Sch_Bcmc", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Use_Add_Plcm_For_Sch,
            { "Use For Sch Additional PLCM", "cdma2k.Use_Add_Plcm_For_Sch", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Fsch_Outercode_Incl,
            { "For Sch Outer Code Incl", "cdma2k.Fsch_Outercode_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Fsch_Outercode_Rate,
            { "For Sch Outer Code Rate", "cdma2k.Fsch_Outercode_Rate", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Fsch_Outercode_Offset,
            { "For Sch Outer Code Offset", "cdma2k.Fsch_Outercode_Offset", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Max_Add_Serv_Instance,
            { "Max Additional Service Identifiers", "cdma2k.Max_Add_Serv_Instance", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Use_Ch_Cfg_Rrm,
            { "Channel Config Req Allowed", "cdma2k.Use_Ch_Cfg_Rrm", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Tx_Pwr_Limit_Incl,
            { "Tx Pwr Limit Incl", "cdma2k.Tx_Pwr_Limit_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Tx_Pwr_Limit_Default,
            { "Tx Pwr Limit Default", "cdma2k.Tx_Pwr_Limit_Default", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Tx_Pwr_Limit,
            { "Tx Pwr Limit", "cdma2k.Tx_Pwr_Limit", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Num_For_Sch,
            { "Forward Sch Record Count", "cdma2k.Num_For_Sch", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Record_For_Sch,
            { "Forward Supplemental Channel Record", "cdma2k.Record_For_Sch", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Num_Rev_Sch,
            { "Reverse Sch Record Count", "cdma2k.Num_Rev_Sch", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Record_Rev_Sch,
            { "Reverse Supplemental Channel Record", "cdma2k.Record_Rev_Sch", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Walsh_Id,
            { "Walsh Cover Identifier", "cdma2k.Walsh_Id", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Num_Pilots,
            { "Pilot Count", "cdma2k.Num_Pilots", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Srch_Offset_Incl,
            { "Search Window Offset Incl", "cdma2k.Srch_Offset_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Record_Pilots,
            { "Pilot Record", "cdma2k.Record_Pilots", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Pilot_Pn,
            { "PN Sequence Offset Idx", "cdma2k.Pilot_Pn", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Srch_Offset,
            { "Search Window Offset", "cdma2k.Srch_Offset", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Add_Pilot_Rec_Incl,
            { "Add Pilot Info Incl", "cdma2k.Add_Pilot_Rec_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Pilot_Rec_Type,
            { "Pilot Rec Type", "cdma2k.Pilot_Rec_Type", FT_UINT8, BASE_HEX_DEC, VALS(Pilot_Rec_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Pwr_Comb_Ind,
            { "Power Cntl Indicator", "cdma2k.Pwr_Comb_Ind", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Code_Chan_Fch,
            { "CodeCh On Fundamental Channel", "cdma2k.Code_Chan_Fch", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Qof_Mask_Id_Fch,
            { "Qof Idx On Fundamental Channel", "cdma2k.Qof_Mask_Id_Fch", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Num_Sch,
            { "Supplemental Channel Record Cnt", "cdma2k.Num_Sch", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Record_Sch,
            { "Supplemental Channel Records", "cdma2k.Record_Sch", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Pilot_Incl,
            { "Pilot Incl", "cdma2k.Pilot_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Code_Chan_Sch,
            { "Code Channel", "cdma2k.Code_Chan_Sch", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Qof_Mask_Id_Sch,
            { "Qof Index", "cdma2k.Qof_Mask_Id_Sch", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_3xFch_Info_Incl,
            { "3xFundamentalCh Info Incl", "cdma2k.3xFch_Info_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_3xFch_Low_Incl,
            { "Fundamental CodeCh On Low Freq Incl", "cdma2k.3xFch_Low_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Qof_Mask_Id_Fch_Low,
            { "Qof Idx", "cdma2k.Qof_Mask_Id_Fch_Low", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Code_Chan_Fch_Low,
            { "Code Channel", "cdma2k.Code_Chan_Fch_Low", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_3xFch_High_Incl,
            { "Fundamental CodeCh On High Freq Incl", "cdma2k.3xFch_High_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Qof_Mask_Id_Fch_High,
            { "Qof Idx", "cdma2k.Qof_Mask_Id_Fch_High", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Code_Chan_Fch_High,
            { "Code Channel", "cdma2k.Code_Chan_Fch_High", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_3xSch_Info_Incl,
            { "3x SCh Info Incl", "cdma2k.3xSch_Info_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_3xSch_Low_Incl,
            { "Sch On Low Freq Incl", "cdma2k.3xSch_Low_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Qof_Mask_Id_Sch_Low,
            { "Qof Index", "cdma2k.Qof_Mask_Id_Sch_Low", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Code_Chan_Sch_Low,
            { "Code Channel", "cdma2k.Code_Chan_Sch_Low", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_3xSch_High_Incl,
            { "Sch On High Freq Incl", "cdma2k.3xSch_High_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Qof_Mask_Id_Sch_High,
            { "Qof Index", "cdma2k.Qof_Mask_Id_Sch_High", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Code_Chan_Sch_High,
            { "Code Channel", "cdma2k.Code_Chan_Sch_High", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Ccsh_Included,
            { "Ccsh Incl", "cdma2k.Ccsh_Included", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Use_Ccsh_Encoder_Time,
            { "Ccsh Encoder Indicator", "cdma2k.Use_Ccsh_Encoder_Time", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Ccsh_Encoder_Action_Time,
            { "Ccsh Encoder Action Time", "cdma2k.Ccsh_Encoder_Action_Time", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Ccsh_Encoder_Type,
            { "Ccsh Encoder Type", "cdma2k.Ccsh_Encoder_Type", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Code_Chan_Dcch,
            { "CodeCh On Dedicated Channel", "cdma2k.Code_Chan_Dcch", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Qof_Mask_Id_Dcch,
            { "Qof Idx On Dedicated Channel", "cdma2k.Qof_Mask_Id_Dcch", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_3xDcch_Info_Incl,
            { "3xDedicatedCh Info Incl", "cdma2k.3xDcch_Info_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_3xDcch_Low_Incl,
            { "Dedicated CodeCh On Low Freq Incl", "cdma2k.3xDcch_Low_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Qof_Mask_Id_Dcch_Low,
            { "Qof Idx", "cdma2k.Qof_Mask_Id_Dcch_Low", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Code_Chan_Dcch_Low,
            { "Code Channel", "cdma2k.Code_Chan_Dcch_Low", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_3xDcch_High_Incl,
            { "Dedicated CodeCh On High Freq Incl", "cdma2k.3xDcch_High_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Qof_Mask_Id_Dcch_High,
            { "Qof Idx", "cdma2k.Qof_Mask_Id_Dcch_High", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Code_Chan_Dcch_High,
            { "Code Channel", "cdma2k.Code_Chan_Dcch_High", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Fundicated_Bcmc_Ind,
            { "BCMC On FundicatedCh Indicator", "cdma2k.Fundicated_Bcmc_Ind", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_For_Cpcch_Walsh,
            { "Forward Cpcch Walsh Code", "cdma2k.For_Cpcch_Walsh", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_For_Cpcsch,
            { "Forward Cpcsch", "cdma2k.For_Cpcsch", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Rev_Fch_Assigned,
            { "Rev FCh Channel Assigned", "cdma2k.Rev_Fch_Assigned", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Add_Plcm_For_Fch_Incl,
            { "Add PLCM For Forward Fch Incl", "cdma2k.Add_Plcm_For_Fch_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Add_Plcm_For_Fch_Type,
            { "Add PLCM For Forward Fch Type", "cdma2k.Add_Plcm_For_Fch_Type", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Add_Plcm_For_Fch_39,
            { "Add PLCM For Forward Fch", "cdma2k.Add_Plcm_For_Fch_39", FT_UINT64, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_For_Cpcch_Info_Incl,
            { "Cpcch Info Incl", "cdma2k.For_Cpcch_Info_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Info_Rec,
            { "Information Records", "cdma2k.Info_Rec", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Chari,
            { "Chari", "cdma2k.Chari", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Number_Type,
            { "Number Type", "cdma2k.Number_Type", FT_UINT8, BASE_HEX_DEC, VALS(Number_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Number_Plan,
            { "Number Plan", "cdma2k.Number_Plan", FT_UINT8, BASE_HEX_DEC, VALS(Number_Plan_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Pres_Indicator,
            { "Presentation Indicator", "cdma2k.Pres_Indicator", FT_UINT8, BASE_HEX_DEC, VALS(Pres_Ind_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Scr_Indicator,
            { "Screening Indicator", "cdma2k.Scr_Indicator", FT_UINT8, BASE_HEX_DEC, VALS(Scr_Ind_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Signal_Type,
            { "Signal Type", "cdma2k.Signal_Type", FT_UINT8, BASE_HEX_DEC, VALS(Signal_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Alert_Pitch,
            { "Alert Pitch", "cdma2k.Alert_Pitch", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Signal,
            { "Signal", "cdma2k.Signal", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Msg_Count,
            { "Msg Count", "cdma2k.Msg_Count", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Extension_Bit,
            { "Extension Bit", "cdma2k.Extension_Bit", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Subaddress_Type,
            { "Subaddress Type", "cdma2k.Subaddress_Type", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Odd_Even_Ind,
            { "Odd/Even Indicator", "cdma2k.Odd_Even_Ind", FT_UINT8, BASE_HEX_DEC, VALS(Odd_Even_Ind_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Redirection_Reason,
            { "Redirection Reason", "cdma2k.Redirection_Reason", FT_UINT8, BASE_HEX_DEC, VALS(Redir_Reason_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Pulse_Freq,
            { "Pulse Frequency", "cdma2k.Pulse_Freq", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Pulse_On_Time,
            { "Pulse On Time", "cdma2k.Pulse_On_Time", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Pulse_Off_Time,
            { "Pulse Off Time", "cdma2k.Pulse_Off_Time", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Pulse_Count,
            { "Pulse Count", "cdma2k.Pulse_Count", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Cadence_Count,
            { "Cadence Count", "cdma2k.Cadence_Count", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Num_Grps,
            { "Num Of Groups", "cdma2k.Num_Grps", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Amplitude,
            { "Amplitude", "cdma2k.Amplitude", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Freq,
            { "Tone Frequency", "cdma2k.Freq", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_On_Time,
            { "On Time", "cdma2k.On_Time", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Off_Time,
            { "Off Time", "cdma2k.Off_Time", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Repeat,
            { "Repeat", "cdma2k.Repeat", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Delay,
            { "Delay", "cdma2k.Delay", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Cadence_Type,
            { "Cadence Type", "cdma2k.Cadence_Type", FT_UINT8, BASE_HEX_DEC, VALS(Cadence_Types), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Polarity_Incl,
            { "Polarity Incl", "cdma2k.Polarity_Incl", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Toggle_Mode,
            { "Toggle Mode", "cdma2k.Toggle_Mode", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Reverse_Polarity,
            { "Reverse Polarity", "cdma2k.Reverse_Polarity", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Pwr_Denial_Time,
            { "Power Denial Time", "cdma2k.Pwr_Denial_Time", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Call_Waiting_Ind,
            { "Call Waiting Ind", "cdma2k.Call_Waiting_Ind", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Request_Mode,
            { "Request Mode", "cdma2k.Request_Mode", FT_UINT8, BASE_DEC, VALS(l3dpu_ORM_PRM_req_mode_values), 0x0, NULL, HFILL } },
            { &hf_cdma2k_Special_Service,
            { "Special Service", "cdma2k.Special_Service", FT_BOOLEAN, 8, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_pm,
            { "Privacy Mode", "cdma2k.PM", FT_BOOLEAN, 8, NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_digit_mode,
            { "Digit Mode", "cdma2k.Digit_Mode", FT_BOOLEAN, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_More_Fields,
            { "More Fields", "cdma2k.More_Fields", FT_BOOLEAN, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_Nar_An_Cap,
            { "NAR AN CAP", "cdma2k.Nar_An_Cap", FT_BOOLEAN, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_Paca_Reorig,
            { "PACA REORIG", "cdma2k.Paca_Reorig", FT_BOOLEAN, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_More_Records,
            { "More Records", "cdma2k.More_Records", FT_BOOLEAN, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_encryption_supported,
            { "Encryption Supported", "cdma2k.Encryption_Supported", FT_UINT8, BASE_DEC, VALS(l3dpu_ORM_encryption_algo_values), 0x0, NULL, HFILL } },
            {  &hf_cdma2k_Paca_Supported,
            { "Paca Supported", "cdma2k.Paca_Supported", FT_BOOLEAN, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_num_alt_so,
            { "NUM ALT SO", "cdma2k.NUM_ALT_SO", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_Alt_So,
            { "Alt So", "cdma2k.Alt_So", FT_UINT16, BASE_HEX_DEC, VALS(Page_Req_Service_Option_Types), 0x0, NULL, HFILL } },
            {  &hf_cdma2k_DRS,
            { "Data ready to send", "cdma2k.DRS", FT_BOOLEAN, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_SR_ID,
            { "SR ID", "cdma2k.SR_ID", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_Otd_Supported,
            { "OTD Supported", "cdma2k.OTD_Supported", FT_BOOLEAN, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_For_Rc_Pref,
            { "Forward Rc Pref", "cdma2k.For_Rc_Pref", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_Rev_Rc_Pref,
            { "Reverse Rc Pref", "cdma2k.Rev_Rc_Pref", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_Fch_Supported,
            { "Fch Supported","cdma2k.Fch_Supported", FT_BOOLEAN, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_Fch_capability_type_specific_Fields,
            { "Fch capability type specific Fields","cdma2k.Fch_cap_type_specific_Fields", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_Fch_Frame_Size,
            { "Frame Size", "cdma2k.Fch_Frame_Size", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_For_Fch_Len,
            { "Forward Fch Len", "cdma2k.For_Fch_Len", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_For_Fch_Rc_Map,
            { "Forward Fch Rc Map", "cdma2k.For_Fch_Rc_Map", FT_UINT8, BASE_HEX_DEC , NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_Rev_Fch_Len,
            { "Reverse Fch Len", "cdma2k.Rev_Fch_Len", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_Rev_Fch_Rc_Map,
            { "Reverse Fch Rc Map", "cdma2k.Rev_Fch_Rc_Map", FT_UINT8, BASE_HEX_DEC , NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_Dcch_capability_type_specific_Fields,
            { "Dcch cap type specific Fields","cdma2k.Dcch_cap_type_specific_Fields", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_Dcch_Supported,
            { "Dcch Supported","cdma2k.Dcch_Supported", FT_BOOLEAN, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_Dcch_Frame_Size,
            { "Frame Size", "cdma2k.Dcch_Frame_Size", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_For_Dcch_Len,
            { "Forward Dcch Len", "cdma2k.For_Dcch_Len", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_For_Dcch_Rc_Map,
            { "Forward Dcch Rc Map", "cdma2k.For_Dcch_Rc_Map", FT_UINT8, BASE_HEX_DEC , NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_Rev_Dcch_Len,
            { "Reverse Dcch Len", "cdma2k.Rev_Dcch_Len", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_cdma2k_Rev_Dcch_Rc_Map,
            { "Reverse Dcch Rc Map", "cdma2k.Rev_Dcch_Rc_Map", FT_UINT8, BASE_HEX_DEC , NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_Rev_Fch_Gating_Req,
            { "RevFch GatingReq","cdma2k.Rev_Fch_GatingReq", FT_BOOLEAN, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_Orig_Reason,
                { "Orig Reason","cdma2k.Orig_Reason", FT_BOOLEAN, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_Orig_Count,
            { "Orig Count", "cdma2k.Orig_Count", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
            {  &hf_cdma2k_Sts_Supported,
        { "Sts Supported","cdma2k.Sts_Supported", FT_BOOLEAN, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_ThreeXCchSupported,
        { "ThreeXCch Supported","cdma2k.ThreeXCch_Supported", FT_BOOLEAN, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_Wll_Incl,
        { "Wll Incl","cdma2k.Wll_Incl", FT_BOOLEAN, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_Wll_Device_Type,
        { "Wll Device Type", "cdma2k.Wll_Device_Type", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_Global_Emergency_Call,
                { "Global Emergency Call","cdma2k.Global_Emergency_Call", FT_BOOLEAN, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_Ms_Init_Pos_Loc_Ind,
        { "Ms Init Pos Loc Ind","cdma2k.Ms_Init_Pos_Loc_Ind", FT_BOOLEAN, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_Qos_Parms_Incl,
        { "Qos Parms Incl","cdma2k.Qos_Parms_Incl", FT_BOOLEAN, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_Qos_Parms_Length,
        { "Qos Parms Length", "cdma2k.Qos_Parms_Length", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_Qos_Parms,
        { "Qos Parms", "cdma2k.Qos_Parms", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_Enc_Info_Incl,
        { "Enc Info Incl","cdma2k.EncInfo_Incl", FT_BOOLEAN, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_Sig_Encrypt_Supp,
        { "Sig Encrypt Supported", "cdma2k.Sig_Encrypt_Supp", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_DSig_Encrypt_Req,
        { "DSig Encrypt Req","cdma2k.DSig_Encrypt_Req", FT_BOOLEAN, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_CSig_Encrypt_Req,
        { "CSig Encrypt Req","cdma2k.CSig_Encrypt_Req", FT_BOOLEAN, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_New_Sseq_H,
                { "New SseqH", "cdma2k.New_Sseq_H", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_New_Sseq_H_Sig,
                { "New SseqH Sig", "cdma2k.New_Sseq_H_Sig", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_Ui_Encrypt_Req,
        { "Ui Encrypt Req","cdma2k.Ui_Encrypt_Req", FT_BOOLEAN, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_Prev_Sid_Incl,
        { "Prev Sid Incl","cdma2k.Prev_Sid_Incl", FT_BOOLEAN, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_Prev_Sid,
        { "Prev Sid", "cdma2k.Prev_Sid", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_Prev_Nid_Incl,
        { "Prev Nid_Incl","cdma2k.Prev_Nid_Incl", FT_BOOLEAN, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_Prev_Nid,
        { "Prev Nid", "cdma2k.Prev_Nid", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_Prev_Pzid_Incl,
        { "Prev Pzid Incl","cdma2k.Prev_Pzid_Incl", FT_BOOLEAN, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_Prev_Pzid,
        { "Prev Pzid", "cdma2k.Prev_Pzid", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_So_Bitmap_Ind,
        { "So Bitmap Ind", "cdma2k.So_Bitmap_Ind", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_So_Group_Num,
        { "So Group Num", "cdma2k.So_Group_Num", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_So_Bitmap,
                { "So Bitmap", "cdma2k.So_Bitmap", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_Cmea,
                { "Cell Msg Encry Alg", "cdma2k.Cmea", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_Ecmea,
                { "Enhanced Cell Msg Encry Alg", "cdma2k.Ecmea", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_Rea,
                { "Rijndael Encry Alg", "cdma2k.Rea", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_cdma2k_Reserved,
            { "Reserved", "cdma2k.Reserved", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },

        {  &hf_cdma2k_AlertWithInfoMsg,
            { "Alert With Info Msg", "cdma2k.AlertWithInfoMsg", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_Hook_Status,
            { "Hook_Status", "cdma2k.Hook_Status", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_MeIdUhdmMsg,
            { "MeIdUhdmMsg", "cdma2k.MeIdUhdmMsg", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        {  &hf_cdma2k_UhdmMsg,
            { "UhdmMsg", "cdma2k.UhdmMsg", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_cdma2k_ext_scm_ind,
            { "Extended SCM Indicator", "cdma2k.ext_scm_ind", FT_UINT8, BASE_DEC, VALS(l3dpu_SCM_field_values7), 0x0, NULL, HFILL } },
        { &hf_cdma2k_scm_dual_mode,
            { "Dual Mode", "cdma2k.scm.dual_mode", FT_UINT8, BASE_DEC, VALS(l3dpu_SCM_field_values6), 0x0, NULL, HFILL } },
        { &hf_cdma2k_scm_slotted_class,
            { "Slotted Class", "cdma2k.scm.slotted_class", FT_UINT8, BASE_DEC, VALS(l3dpu_SCM_field_values5), 0x0, NULL, HFILL } },
        { &hf_cdma2k_scm_meid_sup,
            { "MEID support indicator", "cdma2k.scm.meid_sup", FT_UINT8, BASE_DEC, VALS(l3dpu_SCM_field_values4), 0x0, NULL, HFILL } },
        { &hf_cdma2k_scm_25mhz_bw,
            { "25 MHz Bandwidth", "cdma2k.scm.25mhz_bw", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cdma2k_scm_trans,
            { "Transmission", "cdma2k.scm.trans", FT_UINT8, BASE_DEC, VALS(l3dpu_SCM_field_values2), 0x0, NULL, HFILL } },
        { &hf_cdma2k_scm_pow_class,
            { "Power Class for Band Class 0 Analog Operation", "cdma2k.scm.pow_class", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    };

    static gint *ett[] = {
        &ett_cdma2k_msghdr,
            &ett_cdma2k_subtree,
            &ett_cdma2k_subtree1,
            &ett_cdma2k_subtree2,
            &ett_cdma2k_m_s1,
            &ett_cdma2000_scm
    };

    static ei_register_info ei[] = {
        { &ei_cdma2k_error, { "cdma2k.error", PI_PROTOCOL, PI_ERROR, "Violation of protocol specs (e.g. invalid information element)", EXPFILL }},
    };

    expert_module_t* expert_cdma2k;

    proto_cdma2k = proto_register_protocol (
        "CDMA2K",        /* name */
        "CDMA2K",        /* short name */
        "cdma2k"         /* abbrev */
    );

    register_dissector("cdma2k", dissect_cdma2k, proto_cdma2k);

    proto_register_field_array(proto_cdma2k, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_cdma2k = expert_register_protocol(proto_cdma2k);
    expert_register_field_array(expert_cdma2k, ei, array_length(ei));

}


void proto_reg_handoff_cdma2k(void)
{
    static int once = 1;

    if(once == 1){
        cdma2k_handle = create_dissector_handle(dissect_cdma2k, proto_cdma2k);
        once = 0;
    }
}
/*
* Editor modelines
*
* Local Variables:
* c-basic-offset: 4
* tab-width: 8
* indent-tabs-mode: nil
* End:
*
* ex: set shiftwidth=4 tabstop=8 expandtab:
* :indentSize=4:tabSize=8:noTabs=true:
*/
