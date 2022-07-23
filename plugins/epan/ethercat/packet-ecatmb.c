/* packet-ecatmb.c
 * Routines for EtherCAT packet disassembly
 *
 * Copyright (c) 2007 by Beckhoff Automation GmbH
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Include files */

#include "config.h"

#include <string.h>

#include <epan/packet.h>
#include <epan/expert.h>

#include "packet-ecatmb.h"

#define BIT2BYTE(x) ((x+7)/8)
#define ENDOF(p) ((p)+1) /* pointer to end of *p */

void proto_register_ecat_mailbox(void);
void proto_reg_handoff_ecat_mailbox(void);

static dissector_handle_t eth_handle;
static dissector_handle_t ams_handle;
static dissector_handle_t ecat_mailbox_handle;

/* Define the EtherCAT mailbox proto */
int proto_ecat_mailbox  = -1;

static int ett_ecat_mailbox = -1;
static int ett_ecat_mailbox_eoe = -1;
static int ett_ecat_mailbox_eoe_init = -1;
static int ett_ecat_mailbox_eoe_macfilter = -1;
static int ett_ecat_mailbox_eoe_macfilter_filter = -1;
static int ett_ecat_mailbox_eoe_macfilter_filtermask = -1;
static int ett_ecat_mailbox_coe = -1;
static int ett_ecat_mailbox_sdo = -1;
static int ett_ecat_mailbox_coe_sdoccs = -1;
static int ett_ecat_mailbox_coe_sdoscs = -1;
static int ett_ecat_mailbox_foe = -1;
static int ett_ecat_mailbox_foe_efw = -1;
static int ett_ecat_mailbox_soeflag = -1;
static int ett_ecat_mailbox_soe = -1;
static int ett_ecat_mailbox_fraghead = -1;
static int ett_ecat_mailbox_header = -1;

static int hf_ecat_mailboxlength = -1;
static int hf_ecat_mailboxaddress = -1;
static int hf_ecat_mailboxpriority = -1;
static int hf_ecat_mailboxtype = -1;
static int hf_ecat_mailboxcounter = -1;
static int hf_ecat_mailbox_eoe = -1;
static int hf_ecat_mailbox_eoe_fraghead = -1;
static int hf_ecat_mailbox_eoe_type = -1;
static int hf_ecat_mailbox_eoe_fragno = -1;
static int hf_ecat_mailbox_eoe_offset = -1;
static int hf_ecat_mailbox_eoe_frame = -1;
static int hf_ecat_mailbox_eoe_last = -1;
static int hf_ecat_mailbox_eoe_timestampreq = -1;
static int hf_ecat_mailbox_eoe_timestampapp = -1;
static int hf_ecat_mailbox_eoe_fragment = -1;
static int hf_ecat_mailbox_eoe_init = -1;
static int hf_ecat_mailbox_eoe_init_contains_macaddr = -1;
static int hf_ecat_mailbox_eoe_init_contains_ipaddr = -1;
static int hf_ecat_mailbox_eoe_init_contains_subnetmask = -1;
static int hf_ecat_mailbox_eoe_init_contains_defaultgateway = -1;
static int hf_ecat_mailbox_eoe_init_contains_dnsserver = -1;
static int hf_ecat_mailbox_eoe_init_contains_dnsname = -1;
static int hf_ecat_mailbox_eoe_init_append_timestamp = -1;
static int hf_ecat_mailbox_eoe_init_macaddr = -1;
static int hf_ecat_mailbox_eoe_init_ipaddr = -1;
static int hf_ecat_mailbox_eoe_init_subnetmask = -1;
static int hf_ecat_mailbox_eoe_init_defaultgateway = -1;
static int hf_ecat_mailbox_eoe_init_dnsserver = -1;
static int hf_ecat_mailbox_eoe_init_dnsname = -1;
static int hf_ecat_mailbox_eoe_macfilter = -1;
static int hf_ecat_mailbox_eoe_macfilter_macfiltercount = -1;
static int hf_ecat_mailbox_eoe_macfilter_maskcount = -1;
static int hf_ecat_mailbox_eoe_macfilter_nobroadcasts = -1;
static int hf_ecat_mailbox_eoe_macfilter_filter;
static int hf_ecat_mailbox_eoe_macfilter_filters[16] = {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};
static int hf_ecat_mailbox_eoe_macfilter_filtermask = -1;
static int hf_ecat_mailbox_eoe_macfilter_filtermasks[4] = {-1,-1,-1,-1};
static int hf_ecat_mailbox_eoe_timestamp = -1;
static int hf_ecat_mailbox_coe = -1;
static int hf_ecat_mailbox_coe_number = -1;
static int hf_ecat_mailbox_coe_type = -1;
static int hf_ecat_mailbox_coe_sdoreq = -1;
static int hf_ecat_mailbox_coe_sdoccsid = -1;
static int hf_ecat_mailbox_coe_sdoccsid_sizeind = -1;
static int hf_ecat_mailbox_coe_sdoccsid_expedited = -1;
static int hf_ecat_mailbox_coe_sdoccsid_size0= -1;
static int hf_ecat_mailbox_coe_sdoccsid_size1= -1;
static int hf_ecat_mailbox_coe_sdoccsid_complete = -1;
static int hf_ecat_mailbox_coe_sdoccsds = -1;
static int hf_ecat_mailbox_coe_sdoccsds_lastseg = -1;
static int hf_ecat_mailbox_coe_sdoccsds_size = -1;
static int hf_ecat_mailbox_coe_sdoccsds_toggle = -1;
static int hf_ecat_mailbox_coe_sdoccsus = -1;
static int hf_ecat_mailbox_coe_sdoccsus_toggle = -1;
static int hf_ecat_mailbox_coe_sdoccsiu = -1;
/* static int hf_ecat_mailbox_coe_sdoccsiu_complete = -1; */
static int hf_ecat_mailbox_coe_sdoidx = -1;
static int hf_ecat_mailbox_coe_sdoabortcode = -1;
static int hf_ecat_mailbox_coe_sdosub = -1;
static int hf_ecat_mailbox_coe_sdodata = -1;
static int hf_ecat_mailbox_coe_sdodata1 = -1;
static int hf_ecat_mailbox_coe_sdodata2 = -1;
static int hf_ecat_mailbox_coe_sdoldata = -1;
static int hf_ecat_mailbox_coe_sdolength = -1;
/* static int hf_ecat_mailbox_coe_sdoerror = -1; */
static int hf_ecat_mailbox_coe_sdores = -1;
static int hf_ecat_mailbox_coe_sdoscsds = -1;
static int hf_ecat_mailbox_coe_sdoscsds_toggle = -1;
static int hf_ecat_mailbox_coe_sdoscsiu = -1;
static int hf_ecat_mailbox_coe_sdoscsiu_sizeind = -1;
static int hf_ecat_mailbox_coe_sdoscsiu_expedited = -1;
static int hf_ecat_mailbox_coe_sdoscsiu_size0 = -1;
static int hf_ecat_mailbox_coe_sdoscsiu_size1 = -1;
static int hf_ecat_mailbox_coe_sdoscsiu_complete = -1;
static int hf_ecat_mailbox_coe_sdoscsus = -1;
static int hf_ecat_mailbox_coe_sdoscsus_lastseg = -1;
static int hf_ecat_mailbox_coe_sdoscsus_bytes = -1;
static int hf_ecat_mailbox_coe_sdoscsus_toggle = -1;
static int hf_ecat_mailbox_coe_sdoinfoopcode = -1;
static int hf_ecat_mailbox_coe_sdoinfofrag = -1;
static int hf_ecat_mailbox_coe_sdoinfolisttype = -1;
static int hf_ecat_mailbox_coe_sdoinfolist = -1;
static int hf_ecat_mailbox_coe_sdoinfoindex = -1;
static int hf_ecat_mailbox_coe_sdoinfosubindex = -1;
static int hf_ecat_mailbox_coe_sdoinfovalueinfo = -1;
static int hf_ecat_mailbox_coe_sdoinfoerrorcode = -1;
static int hf_ecat_mailbox_coe_sdoinfodatatype = -1;
static int hf_ecat_mailbox_coe_sdoinfomaxsub = -1;
static int hf_ecat_mailbox_coe_sdoinfoobjcode = -1;
static int hf_ecat_mailbox_coe_sdoinfoname = -1;
static int hf_ecat_mailbox_coe_sdoinfobitlen = -1;
static int hf_ecat_mailbox_coe_sdoinfoobjaccess = -1;
static int hf_ecat_mailbox_coe_sdoinfounittype = -1;
static int hf_ecat_mailbox_coe_sdoinfodefaultvalue = -1;
static int hf_ecat_mailbox_coe_sdoinfominvalue = -1;
static int hf_ecat_mailbox_coe_sdoinfomaxvalue = -1;
static int hf_ecat_mailboxdata = -1;
static int hf_ecat_mailbox_foe = -1;
static int hf_ecat_mailbox_foe_opmode = -1;
static int hf_ecat_mailbox_foe_filelength = -1;
static int hf_ecat_mailbox_foe_filename = -1;
static int hf_ecat_mailbox_foe_packetno = -1;
static int hf_ecat_mailbox_foe_errcode = -1;
static int hf_ecat_mailbox_foe_errtext = -1;
static int hf_ecat_mailbox_foe_busydone = -1;
static int hf_ecat_mailbox_foe_busyentire = -1;
static int hf_ecat_mailbox_foe_data = -1;
static int hf_ecat_mailbox_foe_efw = -1;
static int hf_ecat_mailbox_foe_efw_cmd = -1;
static int hf_ecat_mailbox_foe_efw_size = -1;
static int hf_ecat_mailbox_foe_efw_addresslw = -1;
static int hf_ecat_mailbox_foe_efw_addresshw = -1;
static int hf_ecat_mailbox_foe_efw_data = -1;
static int hf_ecat_mailbox_soe = -1;
static int hf_ecat_mailbox_soe_header = -1;

static int hf_ecat_mailbox_soe_header_opcode = -1;
static int hf_ecat_mailbox_soe_header_incomplete = -1;
static int hf_ecat_mailbox_soe_header_error = -1;
static int hf_ecat_mailbox_soe_header_driveno = -1;
static int hf_ecat_mailbox_soe_header_datastate = -1;
static int hf_ecat_mailbox_soe_header_name = -1;
static int hf_ecat_mailbox_soe_header_attribute = -1;
static int hf_ecat_mailbox_soe_header_unit = -1;
static int hf_ecat_mailbox_soe_header_min = -1;
static int hf_ecat_mailbox_soe_header_max = -1;
static int hf_ecat_mailbox_soe_header_value = -1;
static int hf_ecat_mailbox_soe_header_reserved = -1;
static int hf_ecat_mailbox_soe_idn = -1;
static int hf_ecat_mailbox_soe_data = -1;
static int hf_ecat_mailbox_soe_frag = -1;
static int hf_ecat_mailbox_soe_error = -1;

static expert_field ei_ecat_mailbox_error       = EI_INIT;
static expert_field ei_ecat_mailbox_coe_error   = EI_INIT;
static expert_field ei_ecat_mailbox_eoe_error   = EI_INIT;
static expert_field ei_ecat_mailbox_soe_error   = EI_INIT;
static expert_field ei_ecat_mailbox_foe_error   = EI_INIT;


static const value_string EcMBoxType[] =
{
   {   0, "Invalid", },
   {   1, "AoE (Vendor specific; Beckhoff ADS over EtherCAT)", },
   {   2, "EoE (Ethernet over EtherCAT)", },
   {   3, "CoE (CANopen over EtherCAT)", },
   {   4, "FoE (File access over EtherCAT)", },
   {   5, "SoE (Servo profile over EtherCAT)", },
   {  15, "VoE (Vendor specific over EtherCAT)"},
   {   0x80+1, "AoE - Err", },
   {   0x80+2, "EoE - Err", },
   {   0x80+3, "CoE - Err", },
   {   0x80+4, "FoE - Err", },
   {   0x80+5, "SoE - Err", },
   {   0, NULL }
};

static const value_string FoEOpMode[] =
{
   {   1, "RRQ", },
   {   2, "WRQ", },
   {   3, "DATA", },
   {   4, "ACK", },
   {   5, "ERROR", },
   {   6, "BUSY", },
   {   0,  NULL }
};

static const value_string FoEEfwCmd[] =
{
   {   1, "Memory Transfer", },
   {   2, "Write Code", },
   {   3, "Check device id", },
   {   4, "Checksum", },
   {   5, "Write code checksum", },
   {   6, "Set device id", },
   {   8, "Set code id", },
   {   9, "NOP", },
   {  10, "Checksum checksum", },
   {  11, "boot checksum", },
   { 0, NULL }
};

static const value_string SoeOpcode[] =
{
   {   0, "unused" },
   {   1, "readReq" },
   {   2, "readRes"},
   {   3, "writeReq"},
   {   4, "writeRes" },
   {   5, "notification" },
   {   6, "emergency"},
   {   0, NULL }
};

static const value_string EoEType[] =
{
   {   EOE_TYPE_FRAME_FRAG, "Fragment" },
   {   EOE_TYPE_TIMESTAMP_RES, "TimeStamp" },
   {   EOE_TYPE_INIT_REQ, "Init Req"},
   {   EOE_TYPE_INIT_RES, "Init Res"},
   {   EOE_TYPE_MACFILTER_REQ, "MAC Req" },
   {   EOE_TYPE_MACFILTER_RES, "MAC Res" },
   {   0, NULL }
};

static const value_string CANopenType[] =
{
   {   ETHERCAT_COE_TYPE_EMERGENCY, "EMERGENCY" },
   {   ETHERCAT_COE_TYPE_SDOREQ, "SDO Req" },
   {   ETHERCAT_COE_TYPE_SDORES, "SDO Res"},
   {   ETHERCAT_COE_TYPE_TXPDO, "TxPDO"},
   {   ETHERCAT_COE_TYPE_RXPDO, "RxPDO" },
   {   ETHERCAT_COE_TYPE_TXPDO_RTR, "TxPDO_RTR" },
   {   ETHERCAT_COE_TYPE_RXPDO_RTR, "RxPDO_RTR" },
   {   ETHERCAT_COE_TYPE_SDOINFO, "SDO Information" },
   {   0, NULL }
};

static const value_string CANopenSdoInfo[] =
{
   {   ECAT_COE_INFO_OPCODE_LIST_Q, "List Req" },
   {   ECAT_COE_INFO_OPCODE_LIST_S, "List Res" },
   {   ECAT_COE_INFO_OPCODE_OBJ_Q, "Obj Req"},
   {   ECAT_COE_INFO_OPCODE_OBJ_S, "Obj Res"},
   {   ECAT_COE_INFO_OPCODE_ENTRY_Q, "Entry Req" },
   {   ECAT_COE_INFO_OPCODE_ENTRY_S, "Entry Res" },
   {   ECAT_COE_INFO_OPCODE_ERROR_S, "Error Res" },
   {   0, NULL }
};

static const true_false_string tfs_complete =
{
   "Complete", "Legacy"
};

void init_mbx_header(PETHERCAT_MBOX_HEADER pMbox, tvbuff_t *tvb, gint offset)
{
   pMbox->Length = tvb_get_letohs(tvb, offset); offset+=2;
   pMbox->Address = tvb_get_letohs(tvb, offset); offset+=2;
   pMbox->aControlUnion.Control = tvb_get_letohs(tvb, offset);
}

static void init_eoe_header(PETHERCAT_EOE_HEADER pEoE, tvbuff_t *tvb, gint offset)
{
   pEoE->anEoeHeaderInfoUnion.Info = tvb_get_letohs(tvb, offset); offset+=2;
   pEoE->anEoeHeaderDataUnion.Result = tvb_get_letohs(tvb, offset);
}

static void init_foe_header(PETHERCAT_FOE_HEADER pFoE, tvbuff_t *tvb, gint offset)
{
   pFoE->OpMode = tvb_get_guint8(tvb, offset++);
   pFoE->Reserved1 = tvb_get_guint8(tvb, offset++);
   pFoE->aFoeHeaderDataUnion.FileLength = tvb_get_letohl(tvb, offset);
}

static void init_soe_header(PETHERCAT_SOE_HEADER pSoE, tvbuff_t *tvb, gint offset)
{
   pSoE->anSoeHeaderControlUnion.v2.Control = tvb_get_guint8(tvb, offset++);
   pSoE->anSoeHeaderControlUnion.v2.Element = tvb_get_guint8(tvb, offset++);
   pSoE->anSoeHeaderDataUnion.FragmentsLeft = tvb_get_letohs(tvb, offset);
}

static void init_coe_header(PETHERCAT_COE_HEADER pCoE, tvbuff_t *tvb, gint offset)
{
   pCoE->header = tvb_get_letohs(tvb, offset);
}

static void init_sdo_header(PETHERCAT_SDO_HEADER pSdo, tvbuff_t *tvb, gint offset)
{
   pSdo->anSdoHeaderUnion.CS = tvb_get_guint8(tvb, offset++);
   pSdo->Index = tvb_get_letohs(tvb, offset);offset+=2;
   pSdo->SubIndex = tvb_get_guint8(tvb, offset++);
   pSdo->Data = tvb_get_letohl(tvb, offset);
}

static void init_sdo_info_header(PETHERCAT_SDO_INFO_HEADER pInfo, tvbuff_t *tvb, gint offset)
{
   pInfo->anSdoControlUnion.Control = tvb_get_guint8(tvb, offset++);
   pInfo->Reserved = tvb_get_guint8(tvb, offset);
   pInfo->FragmentsLeft = 2;
}

static void CANopenSdoReqFormatter(PETHERCAT_SDO_HEADER pSdo, char *szText, gint nMax)
{
   switch ( pSdo->anSdoHeaderUnion.Idq.Ccs )
   {
   case SDO_CCS_INITIATE_DOWNLOAD:
      snprintf ( szText, nMax, "SDO Req : 'Initiate Download' (%d) Idx=0x%x Sub=%d", pSdo->anSdoHeaderUnion.Idq.Ccs, pSdo->Index,  pSdo->SubIndex);
      break;
   case SDO_CCS_INITIATE_UPLOAD:
      snprintf ( szText, nMax, "SDO Req : 'Initiate Upload' (%d) Idx=0x%x Sub=%d", pSdo->anSdoHeaderUnion.Idq.Ccs, pSdo->Index,  pSdo->SubIndex);
      break;
   case SDO_CCS_DOWNLOAD_SEGMENT:
      snprintf ( szText, nMax, "SDO Req : 'Download Segment' (%d)", pSdo->anSdoHeaderUnion.Idq.Ccs);
      break;
   case SDO_CCS_UPLOAD_SEGMENT:
      snprintf ( szText, nMax, "SDO Req : 'Upload Segment' (%d)", pSdo->anSdoHeaderUnion.Idq.Ccs);
      break;
   case SDO_CCS_ABORT_TRANSFER:
      snprintf ( szText, nMax, "SDO Req : 'Abort Transfer' (%d)", pSdo->anSdoHeaderUnion.Idq.Ccs);
      break;
   default:
      snprintf ( szText, nMax, "SDO Req : Ccs %d", pSdo->anSdoHeaderUnion.Idq.Ccs);
   }
}

static void FoeFormatter(tvbuff_t *tvb, gint offset, char *szText, gint nMax, guint foe_length)
{
   ETHERCAT_FOE_HEADER foe;
   char tmp[50];
   memset(tmp, 0, sizeof(tmp));

   init_foe_header(&foe, tvb, offset);

   switch ( foe.OpMode )
   {
   case ECAT_FOE_OPMODE_RRQ:
   case ECAT_FOE_OPMODE_WRQ:
   case ECAT_FOE_OPMODE_ERR:
      if ( foe_length > ETHERCAT_FOE_HEADER_LEN )
         tvb_memcpy(tvb, tmp, offset+ETHERCAT_FOE_HEADER_LEN, MIN(foe_length-ETHERCAT_FOE_HEADER_LEN, sizeof(tmp)-1));
      break;
   }

   switch ( foe.OpMode )
   {
   case ECAT_FOE_OPMODE_RRQ:
      snprintf ( szText, nMax, "FoE RRQ (%d) : '%s'", foe.aFoeHeaderDataUnion.FileLength, tmp);
      break;
   case ECAT_FOE_OPMODE_WRQ:
      snprintf ( szText, nMax, "FoE WRQ (%d) : '%s'", foe.aFoeHeaderDataUnion.FileLength, tmp);
      break;
   case ECAT_FOE_OPMODE_DATA:
      snprintf ( szText, nMax, "FoE DATA (%d) : %d Bytes", foe.aFoeHeaderDataUnion.v.PacketNo, foe_length-ETHERCAT_FOE_HEADER_LEN);
      break;
   case ECAT_FOE_OPMODE_ACK:
      snprintf ( szText, nMax, "FoE ACK (%d)", foe.aFoeHeaderDataUnion.v.PacketNo);
      break;
   case ECAT_FOE_OPMODE_ERR:
      snprintf ( szText, nMax, "FoE ERR (%d) : '%s'", foe.aFoeHeaderDataUnion.ErrorCode, tmp);
      break;
   case ECAT_FOE_OPMODE_BUSY:
      if ( foe.aFoeHeaderDataUnion.v2.Entire > 0 )
         snprintf ( szText, nMax, "FoE BUSY (%d%%)", ((guint32)foe.aFoeHeaderDataUnion.v2.Done*100)/foe.aFoeHeaderDataUnion.v2.Entire);
      else
         snprintf ( szText, nMax, "FoE BUSY (%d/%d)", foe.aFoeHeaderDataUnion.v2.Done, foe.aFoeHeaderDataUnion.v2.Entire);
      break;
   default:
      snprintf ( szText, nMax, "FoE Unknown");
   }
}

static void SoEIdToString( char* txt, guint16 id, int nMax)
{
   if ( id & 0x8000 )
      snprintf(txt, nMax, "P-%d-%04d", (id>>12) & 0x0007, id & 0x0FFF );
   else
      snprintf(txt, nMax, "S-%d-%04d", id>>12, id & 0x0FFF );
}

static void SoeFormatter(tvbuff_t *tvb, gint offset, char *szText, gint nMax, guint soe_length)
{
   ETHERCAT_SOE_HEADER soe;
   char tmp[50];
   char elm[50];
   memset(tmp, 0, sizeof(tmp));

   init_soe_header(&soe, tvb, offset);
   offset+=ETHERCAT_SOE_HEADER_LEN;

   if ( !soe.anSoeHeaderControlUnion.v.Error )
   {
      if ( !soe.anSoeHeaderControlUnion.v.InComplete )
      {
         SoEIdToString(tmp, soe.anSoeHeaderDataUnion.IDN, sizeof(tmp)-1);
         elm[0] = '\0';
         if ( soe.anSoeHeaderControlUnion.v.DataState )
            (void) g_strlcat(elm, "D", 50);
         if ( soe.anSoeHeaderControlUnion.v.Name )
            (void) g_strlcat(elm, "N", 50);
         if ( soe.anSoeHeaderControlUnion.v.Attribute )
            (void) g_strlcat(elm, "A", 50);
         if ( soe.anSoeHeaderControlUnion.v.Unit )
            (void) g_strlcat(elm, "U", 50);
         if ( soe.anSoeHeaderControlUnion.v.Min )
            (void) g_strlcat(elm, "I", 50);
         if ( soe.anSoeHeaderControlUnion.v.Max )
            (void) g_strlcat(elm, "X", 50);
         if ( soe.anSoeHeaderControlUnion.v.Value )
            (void) g_strlcat(elm, "V", 50);
         switch ( soe.anSoeHeaderControlUnion.v.OpCode )
         {
         case ECAT_SOE_OPCODE_RRQ:
            snprintf ( szText, nMax, "SoE: RRQ (%s, '%s')", tmp, elm);
            break;
         case ECAT_SOE_OPCODE_RRS:
            snprintf ( szText, nMax, "SoE: RRS (%s, '%s') : %u Bytes", tmp, elm, (guint)(soe_length-ETHERCAT_SOE_HEADER_LEN));
            break;
         case ECAT_SOE_OPCODE_WRS:
            snprintf ( szText, nMax, "SoE: WRS (%s, '%s')", tmp, elm);
            break;
         case ECAT_SOE_OPCODE_WRQ:
            snprintf ( szText, nMax, "SoE: WRQ (%s, '%s') : %u Bytes", tmp, elm, (guint)(soe_length-ETHERCAT_SOE_HEADER_LEN));
            break;
         case ECAT_SOE_OPCODE_NFC:
            snprintf ( szText, nMax, "SoE: NFC (%s, '%s') : %u Bytes", tmp, elm, (guint)(soe_length-ETHERCAT_SOE_HEADER_LEN));
            break;
         case 6:
            snprintf ( szText, nMax, "SoE: EMGCY");
            break;
         default:
            snprintf ( szText, nMax, "SoE:");
         }
      }
      else
         snprintf ( szText, nMax, "SoE: FragmentsLeft %d", soe.anSoeHeaderDataUnion.FragmentsLeft);
   }
   else
      snprintf ( szText, nMax, "SoE: Error %04x", tvb_get_letohs(tvb, offset));
}

/* ethercat mailbox */
static void dissect_ecat_coe(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree)
{
   proto_tree *ecat_coe_tree = NULL, *ecat_sdo_tree, *ecat_coe_sdoccs_tree, *ecat_coe_sdoscs_tree;

   proto_item *anItem = NULL, *aparent = NULL;
   char szText[200];
   int nMax = sizeof(szText)-1;

   guint coe_length = tvb_reported_length(tvb)-offset;
   guint16 len;

   if( tree )
   {
      anItem = proto_tree_add_bytes_format(tree, hf_ecat_mailbox_coe, tvb, offset, coe_length, NULL, "CoE");
      aparent = proto_item_get_parent(anItem);
      proto_item_append_text(aparent,":CoE ");
   }

   col_append_str(pinfo->cinfo, COL_INFO, "CoE ");

   if( coe_length >= ETHERCAT_COE_HEADER_LEN )
   {
      ETHERCAT_COE_HEADER coe;
      init_coe_header(&coe, tvb, offset);
      if( tree )
      {
         ecat_coe_tree = proto_item_add_subtree(anItem, ett_ecat_mailbox_coe);

         proto_tree_add_uint(ecat_coe_tree, hf_ecat_mailbox_coe_number, tvb, offset, ETHERCAT_COE_HEADER_LEN, coe.v.Number);
         proto_tree_add_uint(ecat_coe_tree, hf_ecat_mailbox_coe_type, tvb, offset, ETHERCAT_COE_HEADER_LEN, coe.v.Type);
      }

      offset += ETHERCAT_COE_HEADER_LEN;

      switch (coe.v.Type)
      {
      case ETHERCAT_COE_TYPE_SDOREQ:
         {
            ETHERCAT_SDO_HEADER sdo;

            if( coe_length < ETHERCAT_COE_HEADER_LEN + ETHERCAT_SDO_HEADER_LEN )
            {
               col_append_str(pinfo->cinfo, COL_INFO, "Sdo Req - invalid length");
               expert_add_info_format(pinfo, ecat_coe_tree, &ei_ecat_mailbox_coe_error, "Sdo Req - invalid length");
               break;
            }

            init_sdo_header(&sdo, tvb, offset);

            CANopenSdoReqFormatter(&sdo, szText, nMax);
             col_append_str(pinfo->cinfo, COL_INFO, szText);

            if( tree )
            {
               proto_item_append_text(aparent, "%s", szText);

               anItem = proto_tree_add_uint(ecat_coe_tree, hf_ecat_mailbox_coe_sdoreq, tvb, offset, 1, sdo.anSdoHeaderUnion.Idq.Ccs);
               proto_item_set_text(anItem, "%s", szText);
               ecat_sdo_tree = proto_item_add_subtree(anItem, ett_ecat_mailbox_sdo);

               switch ( sdo.anSdoHeaderUnion.Idq.Ccs )
               {
               case SDO_CCS_INITIATE_DOWNLOAD:
                  anItem = proto_tree_add_item(ecat_sdo_tree, hf_ecat_mailbox_coe_sdoccsid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                  ecat_coe_sdoccs_tree = proto_item_add_subtree(anItem, ett_ecat_mailbox_coe_sdoccs);
                  proto_tree_add_item(ecat_coe_sdoccs_tree, hf_ecat_mailbox_coe_sdoccsid_sizeind, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                  proto_tree_add_item(ecat_coe_sdoccs_tree, hf_ecat_mailbox_coe_sdoccsid_expedited, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                  proto_tree_add_item(ecat_coe_sdoccs_tree, hf_ecat_mailbox_coe_sdoccsid_size0, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                  proto_tree_add_item(ecat_coe_sdoccs_tree, hf_ecat_mailbox_coe_sdoccsid_size1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                  proto_tree_add_item(ecat_coe_sdoccs_tree, hf_ecat_mailbox_coe_sdoccsid_complete, tvb, offset, 1, ENC_LITTLE_ENDIAN);

                  proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoidx, tvb, offset+1, 2, ENC_LITTLE_ENDIAN);
                  proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdosub, tvb, offset+3, 1, ENC_LITTLE_ENDIAN);
                  if ( sdo.anSdoHeaderUnion.Idq.SizeInd && !sdo.anSdoHeaderUnion.Idq.Expedited )
                  {
                     len = coe_length - ETHERCAT_COE_HEADER_LEN - ETHERCAT_SDO_HEADER_LEN;
                     proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdolength, tvb, offset+4, 4, ENC_LITTLE_ENDIAN);
                     offset+=ETHERCAT_SDO_HEADER_LEN;
                     if ( len > 0 )
                        proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoldata, tvb, offset, len, ENC_NA);
                  }
                  else
                  {
                     if ( sdo.anSdoHeaderUnion.Idq.Size == 3 )
                        proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdodata1, tvb, offset+4, 1, ENC_LITTLE_ENDIAN);
                     else if ( sdo.anSdoHeaderUnion.Idq.Size == 2 )
                        proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdodata2, tvb, offset+4, 2, ENC_LITTLE_ENDIAN);
                     else
                        proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdodata, tvb, offset+4, 4, ENC_LITTLE_ENDIAN);
                  }
                  break;
               case SDO_CCS_INITIATE_UPLOAD:
                  anItem = proto_tree_add_item(ecat_sdo_tree, hf_ecat_mailbox_coe_sdoccsiu, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                  ecat_coe_sdoccs_tree = proto_item_add_subtree(anItem, ett_ecat_mailbox_coe_sdoccs);
                  proto_tree_add_item(ecat_coe_sdoccs_tree, hf_ecat_mailbox_coe_sdoccsid_complete, tvb, offset, 1, ENC_LITTLE_ENDIAN);

                  proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoidx, tvb, offset+1, 2, ENC_LITTLE_ENDIAN);
                  proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdosub, tvb, offset+3, 1, ENC_LITTLE_ENDIAN);

                  break;
               case SDO_CCS_DOWNLOAD_SEGMENT:
                  anItem = proto_tree_add_item(ecat_sdo_tree, hf_ecat_mailbox_coe_sdoccsds, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                  ecat_coe_sdoccs_tree = proto_item_add_subtree(anItem, ett_ecat_mailbox_coe_sdoccs);
                  proto_tree_add_item(ecat_coe_sdoccs_tree, hf_ecat_mailbox_coe_sdoccsds_lastseg, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                  proto_tree_add_item(ecat_coe_sdoccs_tree, hf_ecat_mailbox_coe_sdoccsds_size, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                  proto_tree_add_item(ecat_coe_sdoccs_tree, hf_ecat_mailbox_coe_sdoccsds_toggle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                  offset+=1;

                  if ( coe_length-offset > 0 )
                  {
                     anItem = proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoldata, tvb, offset, coe_length-offset, ENC_NA);
                     proto_item_append_text(anItem, "(len = %d)", coe_length-offset);
                  }
                  break;
               case SDO_CCS_UPLOAD_SEGMENT:
                  anItem = proto_tree_add_item(ecat_sdo_tree, hf_ecat_mailbox_coe_sdoccsus, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                  ecat_coe_sdoccs_tree = proto_item_add_subtree(anItem, ett_ecat_mailbox_coe_sdoccs);
                  proto_tree_add_item(ecat_coe_sdoccs_tree, hf_ecat_mailbox_coe_sdoccsus_toggle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                  break;
               case SDO_CCS_ABORT_TRANSFER:
                  proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoabortcode, tvb, offset+4, 4, ENC_LITTLE_ENDIAN);
                  break;
               }
            }
         }
         break;

      case ETHERCAT_COE_TYPE_SDORES:
         {
            ETHERCAT_SDO_HEADER sdo;
            if( coe_length < ETHERCAT_COE_HEADER_LEN + ETHERCAT_SDO_HEADER_LEN )
            {
               col_append_str(pinfo->cinfo, COL_INFO, "Sdo Res - invalid length");
               expert_add_info_format(pinfo, ecat_coe_tree, &ei_ecat_mailbox_coe_error, "Sdo Res - invalid length");
               break;
            }

            init_sdo_header(&sdo, tvb, offset);

            col_append_fstr(pinfo->cinfo, COL_INFO, "SDO Res: Scs %d", sdo.anSdoHeaderUnion.Ids.Scs);
            if( tree )
            {
               proto_tree_add_uint_format_value(ecat_coe_tree, hf_ecat_mailbox_coe_sdores, tvb, offset, 1, sdo.anSdoHeaderUnion.Ids.Scs,
                                            "Scs %d", sdo.anSdoHeaderUnion.Ids.Scs);
               ecat_sdo_tree = proto_item_add_subtree(anItem, ett_ecat_mailbox_sdo);

               switch ( sdo.anSdoHeaderUnion.Ids.Scs )
               {
               case SDO_SCS_INITIATE_DOWNLOAD:
                  proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoidx, tvb, offset+1, 2, ENC_LITTLE_ENDIAN);
                  proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdosub, tvb, offset+3, 1, ENC_LITTLE_ENDIAN);
                  break;
               case SDO_SCS_INITIATE_UPLOAD:
                  anItem = proto_tree_add_item(ecat_sdo_tree, hf_ecat_mailbox_coe_sdoscsiu, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                  ecat_coe_sdoscs_tree = proto_item_add_subtree(anItem, ett_ecat_mailbox_coe_sdoscs);
                  proto_tree_add_item(ecat_coe_sdoscs_tree, hf_ecat_mailbox_coe_sdoscsiu_sizeind, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                  proto_tree_add_item(ecat_coe_sdoscs_tree, hf_ecat_mailbox_coe_sdoscsiu_expedited, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                  proto_tree_add_item(ecat_coe_sdoscs_tree, hf_ecat_mailbox_coe_sdoscsiu_size0, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                  proto_tree_add_item(ecat_coe_sdoscs_tree, hf_ecat_mailbox_coe_sdoscsiu_size1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                  proto_tree_add_item(ecat_coe_sdoscs_tree, hf_ecat_mailbox_coe_sdoscsiu_complete, tvb, offset, 1, ENC_LITTLE_ENDIAN);

                  proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoidx, tvb, offset+1, 2, ENC_LITTLE_ENDIAN);
                  proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdosub, tvb, offset+3, 1, ENC_LITTLE_ENDIAN);
                  if ( sdo.anSdoHeaderUnion.Ius.SizeInd && !sdo.anSdoHeaderUnion.Ius.Expedited )
                  {
                     len = coe_length - ETHERCAT_COE_HEADER_LEN - ETHERCAT_SDO_HEADER_LEN;
                     proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdolength, tvb, offset+4, 4, ENC_LITTLE_ENDIAN);
                     offset+=ETHERCAT_SDO_HEADER_LEN;
                     if ( len > 0 )
                        proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoldata, tvb, offset, len, ENC_NA);
                  }
                  else if ( sdo.anSdoHeaderUnion.Ius.SizeInd && sdo.anSdoHeaderUnion.Ius.Expedited && sdo.anSdoHeaderUnion.Ius.Size == 3 )
                     proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdodata1, tvb, offset+4, 1, ENC_LITTLE_ENDIAN);
                  else if ( sdo.anSdoHeaderUnion.Ius.SizeInd && sdo.anSdoHeaderUnion.Ius.Expedited && sdo.anSdoHeaderUnion.Ius.Size == 2 )
                     proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdodata2, tvb, offset+4, 2, ENC_LITTLE_ENDIAN);
                  else
                     proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdodata, tvb, offset+4, 4, ENC_LITTLE_ENDIAN);
                  break;
               case SDO_SCS_DOWNLOAD_SEGMENT:
                  anItem = proto_tree_add_item(ecat_sdo_tree, hf_ecat_mailbox_coe_sdoscsds, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                  ecat_coe_sdoscs_tree = proto_item_add_subtree(anItem, ett_ecat_mailbox_coe_sdoscs);
                  proto_tree_add_item(ecat_coe_sdoscs_tree, hf_ecat_mailbox_coe_sdoscsds_toggle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                  break;
               case SDO_SCS_UPLOAD_SEGMENT:
                  anItem = proto_tree_add_item(ecat_sdo_tree, hf_ecat_mailbox_coe_sdoscsus, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                  ecat_coe_sdoscs_tree = proto_item_add_subtree(anItem, ett_ecat_mailbox_coe_sdoscs);
                  proto_tree_add_item(ecat_coe_sdoscs_tree, hf_ecat_mailbox_coe_sdoscsus_lastseg, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                  proto_tree_add_item(ecat_coe_sdoscs_tree, hf_ecat_mailbox_coe_sdoscsus_bytes, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                  proto_tree_add_item(ecat_coe_sdoscs_tree, hf_ecat_mailbox_coe_sdoscsus_toggle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                  offset+=1;

                  if ( coe_length-offset> 0 )
                  {
                     anItem = proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoldata, tvb, offset, coe_length-offset, ENC_NA);
                     proto_item_append_text(anItem, "(len = %d)", coe_length-offset);
                  }
                  break;
               }
            }
         }
         break;

      case ETHERCAT_COE_TYPE_SDOINFO:
         {
            ETHERCAT_SDO_INFO_HEADER info;

            if( coe_length < ETHERCAT_COE_HEADER_LEN + ETHERCAT_SDO_INFO_LISTREQ_LEN )
            {
               col_append_str(pinfo->cinfo, COL_INFO, "Sdo Info - invalid length");
               expert_add_info_format(pinfo, ecat_coe_tree, &ei_ecat_mailbox_coe_error, "Sdo Info - invalid length");
               break;
            }

            memset(&info, 0x0, sizeof(info));
            init_sdo_info_header(&info, tvb, offset);

            col_append_str(pinfo->cinfo, COL_INFO, val_to_str(info.anSdoControlUnion.v.OpCode & 0x7F, CANopenSdoInfo, "%d (Unknown)"));
            if ( info.anSdoControlUnion.v.InComplete )
                col_append_str(pinfo->cinfo, COL_INFO, " - More Follows");

            if( tree )
            {
               proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoinfoopcode, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
               offset++; /*Reserved*/

               proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoinfofrag, tvb, offset, 2, ENC_LITTLE_ENDIAN);
               offset+=2;

               switch ( info.anSdoControlUnion.v.OpCode )
               {
               case ECAT_COE_INFO_OPCODE_LIST_Q:
                  {
                     proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoinfolisttype, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                  }
                  break;
               case ECAT_COE_INFO_OPCODE_LIST_S:
                  {
                     proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoinfolisttype, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                     offset+=2;

                     proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoinfolist, tvb, offset, coe_length-offset, ENC_NA);
                  }
                  break;
               case ECAT_COE_INFO_OPCODE_OBJ_Q:
                  proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoinfoindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                  break;
               case ECAT_COE_INFO_OPCODE_OBJ_S:
                  {
                     proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoinfoindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                     offset+=2;

                     proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoinfodatatype, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                     offset+=2;

                     proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoinfomaxsub, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
                     proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoinfoobjcode, tvb, offset++, 1, ENC_LITTLE_ENDIAN);

                     proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoinfoname, tvb, offset, coe_length-offset, ENC_ASCII|ENC_NA);
                  }
                  break;
               case ECAT_COE_INFO_OPCODE_ENTRY_Q:
                  {
                     proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoinfoindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                     offset+=2;

                     proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoinfosubindex, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
                     proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoinfovalueinfo, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                  }
                  break;
               case ECAT_COE_INFO_OPCODE_ENTRY_S:
                  {
                     guint16 objlen;

                     proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoinfoindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                     offset+=2;

                     proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoinfosubindex, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
                     proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoinfovalueinfo, tvb, offset++, 1, ENC_LITTLE_ENDIAN);

                     proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoinfodatatype, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                     offset+=2;

                     proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoinfobitlen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                     offset+=2;

                     proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoinfoobjaccess, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                     offset+=2;

                     if ( (info.anSdoInfoUnion.Entry.ValueInfo & 0x08) != 0 )
                     {
                        proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoinfounittype, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        offset+=2;
                     }
                     if ( (info.anSdoInfoUnion.Entry.ValueInfo & 0x10) != 0 )
                     {
                        objlen = BIT2BYTE(info.anSdoInfoUnion.Entry.Res.BitLen);
                        proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoinfodefaultvalue, tvb, offset, objlen, ENC_NA);
                        offset+=objlen;
                     }
                     if ( (info.anSdoInfoUnion.Entry.ValueInfo & 0x20) != 0 )
                     {
                        objlen = BIT2BYTE(info.anSdoInfoUnion.Entry.Res.BitLen);
                        proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoinfominvalue, tvb, offset, objlen, ENC_NA);
                        offset+=objlen;
                     }
                     if ( (info.anSdoInfoUnion.Entry.ValueInfo & 0x40) != 0 )
                     {
                        objlen = BIT2BYTE(info.anSdoInfoUnion.Entry.Res.BitLen);
                        proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoinfomaxvalue, tvb, offset, objlen, ENC_NA);
                        offset+=objlen;
                     }
                     proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoinfoname, tvb, offset, coe_length-offset, ENC_ASCII|ENC_NA);
                  }
                  break;
               case ECAT_COE_INFO_OPCODE_ERROR_S:
                  {
                     proto_tree_add_item(ecat_coe_tree, hf_ecat_mailbox_coe_sdoinfoerrorcode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                  }
                  break;
               }
            }
         }
         break;
      }
   }
   else
   {
      col_append_str(pinfo->cinfo, COL_INFO, "- invalid length");
      expert_add_info(pinfo, tree, &ei_ecat_mailbox_coe_error);
   }
}

static void dissect_ecat_soe(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree)
{
   proto_tree *ecat_soeflag_tree, *ecat_soe_tree;

   proto_item *anItem = NULL ,*aparent = NULL;
   char szText[200];
   int nMax = sizeof(szText)-1;

   guint soe_length = tvb_reported_length(tvb)-offset;

   if( tree )
   {
      anItem = proto_tree_add_item(tree, hf_ecat_mailbox_soe, tvb, offset, soe_length, ENC_NA);

      aparent = proto_item_get_parent(anItem);
      proto_item_append_text(aparent,":SoE ");
   }

   if( soe_length >= ETHERCAT_SOE_HEADER_LEN )
   {
      SoeFormatter(tvb, offset, szText, nMax, soe_length);
      col_append_str(pinfo->cinfo, COL_INFO, szText);

      if( tree )
      {
         ETHERCAT_SOE_HEADER soe;
         init_soe_header(&soe, tvb, offset);

         proto_item_append_text(aparent, "%s", szText);
         proto_item_set_text(anItem, "%s", szText);

         ecat_soe_tree = proto_item_add_subtree(anItem, ett_ecat_mailbox_soe);
         anItem = proto_tree_add_item(ecat_soe_tree, hf_ecat_mailbox_soe_header, tvb, offset , 2, ENC_LITTLE_ENDIAN);

         ecat_soeflag_tree = proto_item_add_subtree(anItem, ett_ecat_mailbox_soeflag);
         proto_tree_add_item(ecat_soeflag_tree, hf_ecat_mailbox_soe_header_opcode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(ecat_soeflag_tree, hf_ecat_mailbox_soe_header_incomplete, tvb, offset, 2, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(ecat_soeflag_tree, hf_ecat_mailbox_soe_header_error, tvb, offset, 2, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(ecat_soeflag_tree, hf_ecat_mailbox_soe_header_driveno, tvb, offset, 2, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(ecat_soeflag_tree, hf_ecat_mailbox_soe_header_datastate, tvb, offset, 2, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(ecat_soeflag_tree, hf_ecat_mailbox_soe_header_name, tvb, offset, 2, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(ecat_soeflag_tree, hf_ecat_mailbox_soe_header_attribute, tvb, offset, 2, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(ecat_soeflag_tree, hf_ecat_mailbox_soe_header_unit, tvb, offset, 2, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(ecat_soeflag_tree, hf_ecat_mailbox_soe_header_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(ecat_soeflag_tree, hf_ecat_mailbox_soe_header_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(ecat_soeflag_tree, hf_ecat_mailbox_soe_header_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(ecat_soeflag_tree, hf_ecat_mailbox_soe_header_reserved, tvb, offset, 2, ENC_LITTLE_ENDIAN);
         offset+=2;

         if ( !soe.anSoeHeaderControlUnion.v.Error )
         {
            if ( !soe.anSoeHeaderControlUnion.v.InComplete )
            {
               switch (soe.anSoeHeaderControlUnion.v.OpCode)
               {
               case ECAT_SOE_OPCODE_RRQ:
               case ECAT_SOE_OPCODE_WRS:
                  proto_tree_add_item(ecat_soe_tree, hf_ecat_mailbox_soe_idn, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                  break;
               case ECAT_SOE_OPCODE_RRS:
               case ECAT_SOE_OPCODE_WRQ:
               case ECAT_SOE_OPCODE_NFC:
                  proto_tree_add_item(ecat_soe_tree, hf_ecat_mailbox_soe_idn, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                  offset+=2;
                  proto_tree_add_item(tree, hf_ecat_mailbox_soe_data, tvb, offset, soe_length-offset, ENC_NA);
                  break;
               }
            }
            else
            {
               proto_tree_add_item(ecat_soe_tree, hf_ecat_mailbox_soe_frag, tvb, offset, 2, ENC_LITTLE_ENDIAN);
               offset+=2;

               proto_tree_add_item(tree, hf_ecat_mailbox_soe_data, tvb, offset, soe_length-offset, ENC_NA);
            }
         }
         else
         {
            proto_tree_add_item(ecat_soe_tree, hf_ecat_mailbox_soe_idn, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_ecat_mailbox_soe_error, tvb, offset, 2, ENC_LITTLE_ENDIAN);
         }
      }
   }
   else
   {
      col_append_str(pinfo->cinfo, COL_INFO, "SoE - invalid length");
      expert_add_info(pinfo, tree, &ei_ecat_mailbox_soe_error);
   }
}

static void dissect_ecat_eoe(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree)
{
   proto_tree *ecat_eoe_tree = 0, *ecat_fraghead_tree, *ecat_eoe_init_tree, *ecat_eoe_macfilter_tree,
      *ecat_eoe_macfilter_filter_tree;
   tvbuff_t *next_tvb;
   proto_item *anItem = NULL, *aparent = NULL;
   int nCnt;

   guint eoe_length = tvb_reported_length(tvb)-offset;

   if( tree )
   {
      anItem = proto_tree_add_bytes_format(tree, hf_ecat_mailbox_eoe, tvb, offset, eoe_length, NULL, "EoE Fragment");

      aparent = proto_item_get_parent(anItem);
      proto_item_append_text(aparent,":EoE ");
   }

   if( eoe_length >= ETHERCAT_EOE_HEADER_LEN )
   {
      ETHERCAT_EOE_HEADER eoe;
      init_eoe_header(&eoe, tvb, offset);
      if ( eoe.anEoeHeaderInfoUnion.v.Type == EOE_TYPE_FRAME_FRAG )
          col_append_fstr(pinfo->cinfo, COL_INFO, "EoE-Frag %d", eoe.anEoeHeaderDataUnion.v.Fragment);
      else
          col_append_str(pinfo->cinfo, COL_INFO, "EoE");

      { /* Do the following even 'if (tree == NULL)' since a call_dissector() is done */
         ecat_eoe_tree = proto_item_add_subtree(anItem, ett_ecat_mailbox_eoe);

         anItem = proto_tree_add_item(ecat_eoe_tree, hf_ecat_mailbox_eoe_fraghead, tvb, offset, 4, ENC_NA);
         ecat_fraghead_tree = proto_item_add_subtree(anItem, ett_ecat_mailbox_fraghead);

         proto_tree_add_uint(ecat_fraghead_tree, hf_ecat_mailbox_eoe_type, tvb, offset, 4, eoe.anEoeHeaderInfoUnion.v.Type);

         switch ( eoe.anEoeHeaderInfoUnion.v.Type )
         {
         case EOE_TYPE_FRAME_FRAG:
            proto_tree_add_uint(ecat_fraghead_tree, hf_ecat_mailbox_eoe_fragno, tvb, offset, 4, eoe.anEoeHeaderDataUnion.v.Fragment);

            if (eoe.anEoeHeaderDataUnion.v.Fragment == 0)
            {
                proto_tree_add_uint_format(ecat_fraghead_tree, hf_ecat_mailbox_eoe_offset, tvb, offset, 4, 32*eoe.anEoeHeaderDataUnion.v.OffsetBuffer,
                    "BufferSize: %d", 32*eoe.anEoeHeaderDataUnion.v.OffsetBuffer);
            }
            else
            {
                proto_tree_add_uint(ecat_fraghead_tree, hf_ecat_mailbox_eoe_offset, tvb, offset, 4, 32*eoe.anEoeHeaderDataUnion.v.OffsetBuffer);
            }

            proto_tree_add_uint(ecat_fraghead_tree, hf_ecat_mailbox_eoe_frame, tvb, offset, 4, eoe.anEoeHeaderDataUnion.v.FrameNo);

            proto_tree_add_uint(ecat_fraghead_tree, hf_ecat_mailbox_eoe_last, tvb, offset, 4, eoe.anEoeHeaderInfoUnion.v.LastFragment);

            if ( eoe.anEoeHeaderInfoUnion.v.TimeStampRequested )
            {
               proto_tree_add_uint(ecat_fraghead_tree, hf_ecat_mailbox_eoe_timestampreq, tvb, offset, 4, eoe.anEoeHeaderInfoUnion.v.TimeStampRequested);
            }

            if ( eoe.anEoeHeaderInfoUnion.v.TimeStampAppended )
            {
               proto_tree_add_uint(ecat_fraghead_tree, hf_ecat_mailbox_eoe_timestampapp, tvb, offset, 4, eoe.anEoeHeaderInfoUnion.v.TimeStampAppended);
            }

            offset+=ETHERCAT_EOE_HEADER_LEN;
            proto_tree_add_item(ecat_eoe_tree, hf_ecat_mailbox_eoe_fragment, tvb, offset, eoe_length-offset, ENC_NA);

            if ( eoe.anEoeHeaderDataUnion.v.Fragment == 0 )
            {
               next_tvb = tvb_new_subset_length(tvb, offset, eoe_length-offset);
               call_dissector( eth_handle, next_tvb, pinfo, ecat_eoe_tree);
            }

            if ( eoe.anEoeHeaderInfoUnion.v.TimeStampAppended )
            {
               proto_tree_add_item(ecat_eoe_tree, hf_ecat_mailbox_eoe_timestamp, tvb, eoe_length-ETHERCAT_EOE_TIMESTAMP_LEN, ETHERCAT_EOE_TIMESTAMP_LEN, ENC_LITTLE_ENDIAN);
            }
            break;

         case EOE_TYPE_TIMESTAMP_RES:
            proto_tree_add_item(ecat_eoe_tree, hf_ecat_mailbox_eoe_timestamp, tvb, offset+ETHERCAT_EOE_HEADER_LEN, ETHERCAT_EOE_TIMESTAMP_LEN, ENC_LITTLE_ENDIAN);
            break;

         case EOE_TYPE_INIT_REQ:
            offset+=ETHERCAT_EOE_HEADER_LEN;
            anItem = proto_tree_add_item(ecat_fraghead_tree, hf_ecat_mailbox_eoe_init, tvb, offset, MIN(eoe_length-offset,ETHERCAT_EOE_INIT_LEN), ENC_NA);
            if( eoe_length-offset >= ETHERCAT_EOE_INIT_LEN )
            {
               ecat_eoe_init_tree = proto_item_add_subtree(anItem, ett_ecat_mailbox_eoe_init);

               proto_tree_add_item(ecat_eoe_init_tree, hf_ecat_mailbox_eoe_init_contains_macaddr, tvb, offset, 4, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(ecat_eoe_init_tree, hf_ecat_mailbox_eoe_init_contains_ipaddr, tvb, offset, 4, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(ecat_eoe_init_tree, hf_ecat_mailbox_eoe_init_contains_subnetmask, tvb, offset, 4, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(ecat_eoe_init_tree, hf_ecat_mailbox_eoe_init_contains_defaultgateway, tvb, offset, 4, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(ecat_eoe_init_tree, hf_ecat_mailbox_eoe_init_contains_dnsserver, tvb, offset, 4, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(ecat_eoe_init_tree, hf_ecat_mailbox_eoe_init_contains_dnsname, tvb, offset, 4, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(ecat_eoe_init_tree, hf_ecat_mailbox_eoe_init_append_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
               offset+=4;

               proto_tree_add_item(ecat_eoe_init_tree, hf_ecat_mailbox_eoe_init_macaddr, tvb, offset, ETHERNET_ADDRESS_LEN, ENC_NA);
               offset+=ETHERNET_ADDRESS_LEN;

               proto_tree_add_item(ecat_eoe_init_tree, hf_ecat_mailbox_eoe_init_ipaddr, tvb, offset, 4, ENC_LITTLE_ENDIAN);
               offset+=4;

               proto_tree_add_item(ecat_eoe_init_tree, hf_ecat_mailbox_eoe_init_subnetmask, tvb, offset, 4, ENC_LITTLE_ENDIAN);
               offset+=4;

               proto_tree_add_item(ecat_eoe_init_tree, hf_ecat_mailbox_eoe_init_defaultgateway, tvb, offset, 4, ENC_LITTLE_ENDIAN);
               offset+=4;

               proto_tree_add_item(ecat_eoe_init_tree, hf_ecat_mailbox_eoe_init_dnsserver, tvb, offset, 4, ENC_LITTLE_ENDIAN);
               offset+=4;

               proto_tree_add_item(ecat_eoe_init_tree, hf_ecat_mailbox_eoe_init_dnsname, tvb, offset, 32, ENC_ASCII|ENC_NA);
            }
            else
            {
               proto_item_append_text(anItem, " - Invalid length!");
               expert_add_info(pinfo, anItem, &ei_ecat_mailbox_eoe_error);
            }
            break;

         case EOE_TYPE_MACFILTER_REQ:
            {
               EoeMacFilterOptionsUnion options;
               offset+=ETHERCAT_EOE_HEADER_LEN;
               anItem = proto_tree_add_item(ecat_fraghead_tree, hf_ecat_mailbox_eoe_macfilter, tvb, offset, MIN(eoe_length-offset, ETHERCAT_EOE_MACFILTER_LEN), ENC_NA);
               if( eoe_length-offset >= ETHERCAT_EOE_MACFILTER_LEN )
               {
                  proto_tree *ecat_eoe_macfilter_filtermask_tree;

                  ecat_eoe_macfilter_tree = proto_item_add_subtree(anItem, ett_ecat_mailbox_eoe_macfilter);

                  /* XXX: Is the field containing EoeMacFilterOptionsUnion 4 bytes or 2 bytes ? */
                  /*      sizeof EoeMacFilterOptionsUnion = 2 bytes but the code below  */
                  /*      originally used a field width of 4 bytes.                     */
                  /*      Given the size of the union, the code below was changed to    */
                  /*       use a field width of 2 bytes.                                */
                  /*      The hf[] entries were also changed to match the union struct  */
                  proto_tree_add_item(ecat_eoe_macfilter_tree, hf_ecat_mailbox_eoe_macfilter_macfiltercount, tvb, offset, /*4*/ 2, ENC_LITTLE_ENDIAN);
                  proto_tree_add_item(ecat_eoe_macfilter_tree, hf_ecat_mailbox_eoe_macfilter_maskcount, tvb, offset, /*4*/ 2, ENC_LITTLE_ENDIAN);
                  proto_tree_add_item(ecat_eoe_macfilter_tree, hf_ecat_mailbox_eoe_macfilter_nobroadcasts, tvb, offset, /*4*/ 2, ENC_LITTLE_ENDIAN);
                  options.Options = tvb_get_letohs(tvb, offset);
                  offset+=/*4*/ 2;

                  anItem = proto_tree_add_item(ecat_eoe_macfilter_tree, hf_ecat_mailbox_eoe_macfilter_filter, tvb, offset, 16*ETHERNET_ADDRESS_LEN, ENC_NA);
                  ecat_eoe_macfilter_filter_tree = proto_item_add_subtree(anItem, ett_ecat_mailbox_eoe_macfilter_filter);
                  for( nCnt=0; nCnt<options.v.MacFilterCount; nCnt++)
                     proto_tree_add_item(ecat_eoe_macfilter_filter_tree, hf_ecat_mailbox_eoe_macfilter_filters[nCnt], tvb, offset+nCnt*ETHERNET_ADDRESS_LEN, ETHERNET_ADDRESS_LEN, ENC_NA);
                  offset+=16*ETHERNET_ADDRESS_LEN;

                  anItem = proto_tree_add_item(ecat_eoe_macfilter_tree, hf_ecat_mailbox_eoe_macfilter_filtermask, tvb, offset, 4*4, ENC_NA);
                  ecat_eoe_macfilter_filtermask_tree = proto_item_add_subtree(anItem, ett_ecat_mailbox_eoe_macfilter_filtermask);
                  for( nCnt=0; nCnt<options.v.MacFilterMaskCount; nCnt++)
                     proto_tree_add_item(ecat_eoe_macfilter_filtermask_tree, hf_ecat_mailbox_eoe_macfilter_filtermasks[nCnt], tvb, offset+nCnt*4, 4, ENC_NA);
               }
               else
               {
                  proto_item_append_text(anItem, " - Invalid length!");
                  expert_add_info(pinfo, anItem, &ei_ecat_mailbox_eoe_error);
               }
            }
            break;

         case EOE_TYPE_INIT_RES:
         case EOE_TYPE_MACFILTER_RES:
            break;
         }
      }

      col_prepend_fstr(pinfo->cinfo, COL_INFO, "EoE(");

      col_prepend_fstr(pinfo->cinfo, COL_PROTOCOL, "EoE-");
   }
   else
   {
      expert_add_info(pinfo, tree, &ei_ecat_mailbox_eoe_error);
      col_append_str(pinfo->cinfo, COL_INFO, "EoE - invalid length!");
   }
}

static void dissect_ecat_foe(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree)
{
   proto_tree *ecat_foe_tree,*ecat_foe_efw_tree;

   proto_item *anItem= NULL,*aparent = NULL;
   char szText[200];
   int nMax = sizeof(szText)-1;

   guint foe_length = tvb_reported_length(tvb)-offset;

   if( tree )
   {
      anItem = proto_tree_add_bytes_format(tree, hf_ecat_mailbox_foe, tvb, offset, foe_length, NULL, "Foe");

      aparent = proto_item_get_parent(anItem);
      proto_item_append_text(aparent,": FoE");
   }

   if( foe_length >= ETHERCAT_FOE_HEADER_LEN )
   {
      FoeFormatter(tvb, offset, szText, nMax, foe_length);
      col_append_str(pinfo->cinfo, COL_INFO, szText);

      if( tree )
      {
         ETHERCAT_FOE_HEADER foe;
         init_foe_header(&foe, tvb, offset);

         ecat_foe_tree = proto_item_add_subtree(anItem, ett_ecat_mailbox_foe);
         proto_tree_add_item(ecat_foe_tree, hf_ecat_mailbox_foe_opmode, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
         offset++; /*Reserved1;*/

         switch (foe.OpMode)
         {
         case ECAT_FOE_OPMODE_RRQ:
         case ECAT_FOE_OPMODE_WRQ:
            proto_tree_add_item(ecat_foe_tree, hf_ecat_mailbox_foe_filelength, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;

            proto_tree_add_item(ecat_foe_tree, hf_ecat_mailbox_foe_filename, tvb, offset, foe_length-offset, ENC_ASCII|ENC_NA);
            break;

         case ECAT_FOE_OPMODE_DATA:
            {
               proto_tree_add_item(ecat_foe_tree, hf_ecat_mailbox_foe_packetno, tvb, offset, 2, ENC_LITTLE_ENDIAN);
               offset+=4; /*+2 for Reserved2*/

               if( foe_length-offset >= sizeof(TEFWUPDATE_HEADER) )
               {
                  anItem = proto_tree_add_item(ecat_foe_tree, hf_ecat_mailbox_foe_efw, tvb, offset, foe_length-offset, ENC_NA);
                  ecat_foe_efw_tree = proto_item_add_subtree(anItem, ett_ecat_mailbox_foe_efw);
                  proto_tree_add_item(ecat_foe_efw_tree, hf_ecat_mailbox_foe_efw_cmd, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                  offset+=2;

                  proto_tree_add_item(ecat_foe_efw_tree, hf_ecat_mailbox_foe_efw_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                  offset+=2;

                  proto_tree_add_item(ecat_foe_efw_tree, hf_ecat_mailbox_foe_efw_addresslw, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                  offset+=2;

                  proto_tree_add_item(ecat_foe_efw_tree, hf_ecat_mailbox_foe_efw_addresshw, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                  offset+=2;

                  proto_tree_add_item(ecat_foe_efw_tree, hf_ecat_mailbox_foe_efw_data, tvb, offset, foe_length-offset, ENC_NA);
               }
               else
               {
                  proto_tree_add_item(ecat_foe_tree, hf_ecat_mailbox_foe_data, tvb, offset, foe_length-offset, ENC_NA);
               }
            }
            break;

         case ECAT_FOE_OPMODE_ACK:
            proto_tree_add_item(ecat_foe_tree, hf_ecat_mailbox_foe_packetno, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;

         case ECAT_FOE_OPMODE_ERR:
            proto_tree_add_item(ecat_foe_tree, hf_ecat_mailbox_foe_errcode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;

            proto_tree_add_item(ecat_foe_tree, hf_ecat_mailbox_foe_errtext, tvb, offset, foe_length-offset, ENC_ASCII|ENC_NA);
            break;

         case ECAT_FOE_OPMODE_BUSY:
            proto_tree_add_item(ecat_foe_tree, hf_ecat_mailbox_foe_busydone, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;

            proto_tree_add_item(ecat_foe_tree, hf_ecat_mailbox_foe_busyentire, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
         }
      }
   }
   else
   {
      col_append_str(pinfo->cinfo, COL_INFO, "FoE - invalid length");
      expert_add_info(pinfo, tree, &ei_ecat_mailbox_foe_error);
   }
}

static int dissect_ecat_mailbox(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
   proto_tree *ecat_mailbox_tree = NULL;
   proto_tree *ecat_mailbox_header_tree = NULL;
   tvbuff_t *next_tvb;
   proto_item *anItem;
   gint offset = 0;

   gint mailbox_length = tvb_reported_length(tvb);

   if( mailbox_length >= ETHERCAT_MBOX_HEADER_LEN )
   {
      ETHERCAT_MBOX_HEADER hdr;

      init_mbx_header(&hdr, tvb, offset);

      col_append_str(pinfo->cinfo, COL_INFO, " Mbx(");

      /* Create the mailbox sub tree */
      anItem = proto_tree_add_item(tree, proto_ecat_mailbox, tvb, 0, ETHERCAT_MBOX_HEADER_LEN+hdr.Length, ENC_NA);
      ecat_mailbox_tree = proto_item_add_subtree(anItem, ett_ecat_mailbox);

      /* Create a mailbox header subtree */
      ecat_mailbox_header_tree = proto_tree_add_subtree(ecat_mailbox_tree, tvb, offset, ETHERCAT_MBOX_HEADER_LEN, ett_ecat_mailbox_header, NULL, "Header");

      /* Add length information to the mailbox header */
      proto_tree_add_item(ecat_mailbox_header_tree, hf_ecat_mailboxlength, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      offset+=2;

      /* Add address information to the mailbox header */
      proto_tree_add_item(ecat_mailbox_header_tree, hf_ecat_mailboxaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      offset+=2;

      /* Add priority information to the mailbox header */
      proto_tree_add_item(ecat_mailbox_header_tree, hf_ecat_mailboxpriority, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      offset+=1;

      /* Add type information to the mailbox header */
      proto_tree_add_uint(ecat_mailbox_header_tree, hf_ecat_mailboxtype, tvb, offset, 1, hdr.aControlUnion.v.Type);

      /* Add counter information to the mailbox header */
      proto_tree_add_uint(ecat_mailbox_header_tree, hf_ecat_mailboxcounter, tvb, offset, 1, hdr.aControlUnion.v.Counter);
      offset++;

      if( mailbox_length >= ETHERCAT_MBOX_HEADER_LEN + hdr.Length )
      {
         next_tvb = tvb_new_subset_length (tvb, offset, hdr.Length);
         switch ( hdr.aControlUnion.v.Type )
         {
         case ETHERCAT_MBOX_TYPE_ADS:
            call_dissector(ams_handle, next_tvb, pinfo, ecat_mailbox_tree);
            break;

         case ETHERCAT_MBOX_TYPE_EOE:
            dissect_ecat_eoe(next_tvb, 0, pinfo, ecat_mailbox_tree);
            break;

         case ETHERCAT_MBOX_TYPE_COE:
            dissect_ecat_coe(next_tvb, 0, pinfo, ecat_mailbox_tree);
            break;

         case ETHERCAT_MBOX_TYPE_FOE:
            dissect_ecat_foe(next_tvb, 0, pinfo, ecat_mailbox_tree);
            break;

         case ETHERCAT_MBOX_TYPE_SOE:
            dissect_ecat_soe(next_tvb, 0, pinfo, ecat_mailbox_tree);
            break;

         default:
            proto_tree_add_item(ecat_mailbox_tree, hf_ecat_mailboxdata, tvb, offset, hdr.Length, ENC_NA);
         }
      }
      else
      {
         anItem =proto_tree_add_item(ecat_mailbox_tree, hf_ecat_mailboxdata, tvb, offset, mailbox_length-ETHERCAT_MBOX_HEADER_LEN, ENC_NA);
         expert_add_info_format(pinfo, anItem, &ei_ecat_mailbox_error,"Incorrect Mailbox data length(Expected:%d Actual:%d)", hdr.Length, mailbox_length-ETHERCAT_MBOX_HEADER_LEN);
      }
      col_append_str(pinfo->cinfo, COL_INFO, ")");
   }
   return tvb_captured_length(tvb);
}

void proto_register_ecat_mailbox(void)
{
   static const true_false_string flags_set_truth =
   {
      "Set",
      "Not set"
   };

   static hf_register_info hf[] =
   {
      { &hf_ecat_mailboxlength,
      { "Length", "ecat_mailbox.length",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailboxaddress,
      { "Address", "ecat_mailbox.address",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailboxpriority,
      { "Priority", "ecat_mailbox.priority",
      FT_UINT8, BASE_DEC, NULL, 0x03,
      NULL, HFILL }
      },
      { &hf_ecat_mailboxtype,
      { "Type", "ecat_mailbox.type",
      FT_UINT8, BASE_DEC, VALS(EcMBoxType), 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailboxcounter,
      { "Counter", "ecat_mailbox.counter",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe,
      { "EoE Fragment", "ecat_mailbox.eoe",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_fraghead,
      { "Header", "ecat_mailbox.eoe.fraghead",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_type,
      { "Type", "ecat_mailbox.eoe.type",
      FT_UINT32, BASE_DEC, VALS(EoEType), 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_fragno,
      { "FragNo", "ecat_mailbox.eoe.fragno",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_offset,
      { "Offset", "ecat_mailbox.eoe.offset",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
      },
      { &hf_ecat_mailbox_eoe_frame,
      { "FrameNo", "ecat_mailbox.eoe.frame",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_last,
      { "Last Fragment", "ecat_mailbox.eoe.last",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_timestampapp,
      { "Time Stamp Appended", "ecat_mailbox.eoe.timestampapp",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_timestampreq,
      { "Time Stamp Requested", "ecat_mailbox.eoe.timestampreq",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_fragment,
      { "EoE Frag Data", "ecat_mailbox.eoe.fragment",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init,
      { "Init", "ecat_mailbox.eoe.init",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init_contains_macaddr,
      { "MacAddr", "ecat_mailbox.eoe.init.contains_macaddr",
      FT_BOOLEAN, 32, TFS(&flags_set_truth), 0x00000001, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init_contains_ipaddr,
      { "IpAddr", "ecat_mailbox.eoe.init.contains_ipaddr",
      FT_BOOLEAN, 32, TFS(&flags_set_truth), 0x00000002, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init_contains_subnetmask,
      { "SubnetMask", "ecat_mailbox.eoe.init.contains_subnetmask",
      FT_BOOLEAN, 32, TFS(&flags_set_truth), 0x00000004, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init_contains_defaultgateway,
      { "DefaultGateway", "ecat_mailbox.eoe.init.contains_defaultgateway",
      FT_BOOLEAN, 32, TFS(&flags_set_truth), 0x00000008, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init_contains_dnsserver,
      { "DnsServer", "ecat_mailbox.eoe.init.contains_dnsserver",
      FT_BOOLEAN, 32, TFS(&flags_set_truth), 0x00000010, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init_contains_dnsname,
      { "DnsName", "ecat_mailbox.eoe.init.contains_dnsname",
      FT_BOOLEAN, 32, TFS(&flags_set_truth), 0x00000020, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init_append_timestamp,
      { "AppendTimeStamp", "ecat_mailbox.eoe.init.append_timestamp",
      FT_BOOLEAN, 32, TFS(&flags_set_truth), 0x00010000, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init_macaddr,
      { "Mac Addr", "ecat_mailbox.eoe.init.macaddr",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init_ipaddr,
      { "Ip Addr", "ecat_mailbox.eoe.init.ipaddr",
      FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init_subnetmask,
      { "Subnet Mask", "ecat_mailbox.eoe.init.subnetmask",
      FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init_defaultgateway,
      { "Default Gateway", "ecat_mailbox.eoe.init.defaultgateway",
      FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init_dnsserver,
      { "Dns Server", "ecat_mailbox.eoe.init.dnsserver",
      FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init_dnsname,
      { "Dns Name", "ecat_mailbox.eoe.init.dnsname",
      FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter,
      { "Mac Filter", "ecat_mailbox.eoe.macfilter",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },

      /* XXX: The following 3 fields may not be specified correctly */
      /*      See related comment above                             */
      { &hf_ecat_mailbox_eoe_macfilter_macfiltercount,
      { "Mac Filter Count", "ecat_mailbox.eoe.macfilter.macfiltercount",
        FT_UINT16, BASE_DEC, NULL, 0xF000, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_maskcount,
      { "Mac Filter Mask Count", "ecat_mailbox.eoe.macfilter.maskcount",
        FT_UINT16, BASE_DEC, NULL, 0x0C00, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_nobroadcasts,
      { "No Broadcasts", "ecat_mailbox.eoe.macfilter.nobroadcasts",
      FT_BOOLEAN, 16,  TFS(&flags_set_truth), 0x0100, NULL, HFILL }
      },
      /* ... */

      { &hf_ecat_mailbox_eoe_macfilter_filter,
      { "Filter", "ecat_mailbox.eoe.macfilter.filter",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[0],
      { "Filter 0", "ecat_mailbox.eoe.macfilter.filter0",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[1],
      { "Filter 1", "ecat_mailbox.eoe.macfilter.filter1",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[2],
      { "Filter 2", "ecat_mailbox.eoe.macfilter.filter2",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[3],
      { "Filter 3", "ecat_mailbox.eoe.macfilter.filter3",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[4],
      { "Filter 4", "ecat_mailbox.eoe.macfilter.filter4",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[5],
      { "Filter 5", "ecat_mailbox.eoe.macfilter.filter5",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[6],
      { "Filter 6", "ecat_mailbox.eoe.macfilter.filter6",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[7],
      { "Filter 7", "ecat_mailbox.eoe.macfilter.filter7",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[8],
      { "Filter 8", "ecat_mailbox.eoe.macfilter.filter8",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[9],
      { "Filter 9", "ecat_mailbox.eoe.macfilter.filter9",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[10],
      { "Filter 10", "ecat_mailbox.eoe.macfilter.filter10",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[11],
      { "Filter 11", "ecat_mailbox.eoe.macfilter.filter11",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[12],
      { "Filter 12", "ecat_mailbox.eoe.macfilter.filter12",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[13],
      { "Filter 13", "ecat_mailbox.eoe.macfilter.filter13",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[14],
      { "Filter 14", "ecat_mailbox.eoe.macfilter.filter14",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[15],
      { "Filter 15", "ecat_mailbox.eoe.macfilter.filter15",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filtermask,
      { "Filter Mask", "ecat_mailbox.eoe.macfilter.filtermask",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filtermasks[0],
      { "Mask 0", "ecat_mailbox.eoe.macfilter.filtermask0",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filtermasks[1],
      { "Mask 1", "ecat_mailbox.eoe.macfilter.filtermask1",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filtermasks[2],
      { "Mask 2", "ecat_mailbox.eoe.macfilter.filtermask2",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filtermasks[3],
      { "Mask 3", "ecat_mailbox.eoe.macfilter.filtermask3",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_timestamp,
      { "Time Stamp", "ecat_mailbox.eoe.timestamp",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe,
      { "CoE", "ecat_mailbox.coe",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_number,
      { "Number", "ecat_mailbox.coe.number",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_type,
      { "Type", "ecat_mailbox.coe.type",
      FT_UINT16, BASE_DEC, VALS(CANopenType), 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoreq,
      { "SDO Req", "ecat_mailbox.coe.sdoreq",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoccsid,
      { "Initiate Download", "ecat_mailbox.coe.sdoccsid",
      FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoccsid_sizeind,
      { "Size Ind.", "ecat_mailbox.coe.sdoccsid.sizeind",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x01,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoccsid_expedited,
      { "Expedited", "ecat_mailbox.coe.sdoccsid.expedited",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x02,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoccsid_size0,
      { "Bytes", "ecat_mailbox.coe.sdoccsid.size0",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x04,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoccsid_size1,
      { "Bytes", "ecat_mailbox.coe.sdoccsid.size1",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x08,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoccsid_complete,
      { "Access", "ecat_mailbox.coe.sdoccsid.complete",
      FT_BOOLEAN, 8, TFS(&tfs_complete), 0x10,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoccsds,
      { "Download Segment", "ecat_mailbox.coe.sdoccsds",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoccsds_lastseg,
      { "Last Segment", "ecat_mailbox.coe.sdoccsds.lastseg",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x01,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoccsds_size,
      { "Size", "ecat_mailbox.coe.sdoccsds.size",
      FT_UINT8, BASE_DEC, NULL, 0x0E,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoccsds_toggle,
      { "Toggle Bit", "ecat_mailbox.coe.sdoccsds.toggle",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x10,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoccsiu,
      { "Init Upload", "ecat_mailbox.coe.sdoccsiu",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
#if 0
      { &hf_ecat_mailbox_coe_sdoccsiu_complete,
      { "Toggle Bit", "ecat_mailbox.coe.sdoccsiu.complete",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x10,
      NULL, HFILL }
      },
#endif
      { &hf_ecat_mailbox_coe_sdoccsus,
      { "Upload Segment", "ecat_mailbox.coe.sdoccsus",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoccsus_toggle,
      { "Toggle Bit", "ecat_mailbox.coe.sdoccsus_toggle",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x10,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoidx,
      { "Index", "ecat_mailbox.coe.sdoidx",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoabortcode,
      { "Abort code", "ecat_mailbox.coe.abortcode",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdosub,
      { "SubIndex", "ecat_mailbox.coe.sdosub",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdodata,
      { "Data", "ecat_mailbox.coe.sdodata",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdodata1,
      { "Data", "ecat_mailbox.coe.sdodata",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdodata2,
      { "Data", "ecat_mailbox.coe.sdodata",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoldata,
      { "Data", "ecat_mailbox.coe.dsoldata",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdolength,
      { "Length", "ecat_mailbox.coe.sdolength",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
#if 0
      { &hf_ecat_mailbox_coe_sdoerror,
      { "SDO Error", "ecat_mailbox.coe.sdoerror",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
#endif
      { &hf_ecat_mailbox_coe_sdores,
      { "SDO Res", "ecat_mailbox.coe.sdores",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoscsiu,
      { "Initiate Upload Response", "ecat_mailbox.coe.sdoscsiu",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoscsiu_sizeind,
      { "Size Ind.", "ecat_mailbox.coe.sdoscsiu_sizeind",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x01,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoscsiu_expedited,
      { "Expedited", "ecat_mailbox.coe.sdoscsiu_expedited",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x02,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoscsiu_size0,
      { "Bytes", "ecat_mailbox.coe.sdoscsiu_size0",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x04,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoscsiu_size1,
      { "Bytes", "ecat_mailbox.coe.sdoscsiu_size1",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x08,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoscsiu_complete,
      { "Access", "ecat_mailbox.coe.sdoscsiu_complete",
      FT_BOOLEAN, 8, TFS(&tfs_complete), 0x10,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoscsds,
      { "Download Segment Response", "ecat_mailbox.coe.sdoscsds",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoscsds_toggle,
      { "Toggle Bit", "ecat_mailbox.coe.sdoscsds_toggle",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x10,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoscsus,
      { "Upload Segment", "ecat_mailbox.coe.sdoscsus",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoscsus_lastseg,
      { "Last Segment", "ecat_mailbox.coe.sdoscsus_lastseg",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x01,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoscsus_bytes,
      { "Bytes", "ecat_mailbox.coe.sdoscsus_bytes",
      FT_UINT8, BASE_DEC, NULL, 0x0E,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoscsus_toggle,
      { "Toggle Bit", "ecat_mailbox.coe.sdoscsus_toggle",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x10,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoinfoopcode,
      { "Info OpCode", "ecat_mailbox.coe.sdoinfoopcode",
      FT_UINT8, BASE_DEC, VALS(CANopenSdoInfo), 0x0,
      NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfofrag,
      { "Info Frag Left", "ecat_mailbox.coe.sdoinfofrag",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfolisttype,
      { "Info List Type", "ecat_mailbox.coe.sdoinfolisttype",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfolist,
      { "Info List", "ecat_mailbox.coe.sdoinfolist",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfoindex,
      { "Info Obj Index", "ecat_mailbox.coe.sdoinfoindex",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfosubindex,
      { "Info Obj SubIdx", "ecat_mailbox.coe.sdoinfosubindex",
      FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfovalueinfo,
      { "Info Obj ValueInfo", "ecat_mailbox.coe.sdoinfovalueinfo",
      FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfoerrorcode,
      { "Info Error Code", "ecat_mailbox.coe.sdoinfoerrorcode",
      FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfodatatype,
      { "Info Data Type", "ecat_mailbox.coe.sdoinfodatatype",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfomaxsub,
      { "Info Max SubIdx", "ecat_mailbox.coe.sdoinfomaxsub",
      FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfoobjcode,
      { "Info Obj Code", "ecat_mailbox.coe.sdoinfoobjcode",
      FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfoname,
      { "Info Name", "ecat_mailbox.coe.sdoinfoname",
      FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfobitlen,
      { "Info Bit Len", "ecat_mailbox.coe.sdoinfobitlen",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfoobjaccess,
      { "Info Obj Access", "ecat_mailbox.coe.sdoinfoobjaccess",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfounittype,
      { "Info Data Type", "ecat_mailbox.coe.sdoinfounittype",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfodefaultvalue,
      { "Info Default Val", "ecat_mailbox.coe.sdoinfodefaultvalue",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfominvalue,
      { "Info Min Val", "ecat_mailbox.coe.sdoinfominvalue",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfomaxvalue,
      { "Info Max Val", "ecat_mailbox.coe.sdoinfomaxvalue",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailboxdata,
      { "MB Data", "ecat_mailbox.data",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe,
      { "Foe", "ecat_mailbox.foe",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_opmode,
      { "Foe OpMode", "ecat_mailbox.foe_opmode",
      FT_UINT8, BASE_HEX, VALS(FoEOpMode), 0x0, "Op modes", HFILL }
      },
      { &hf_ecat_mailbox_foe_filelength,
      { "Foe FileLength", "ecat_mailbox.foe_filelength",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_filename,
      { "Foe FileName", "ecat_mailbox.foe_filename",
      FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_packetno,
      { "Foe PacketNo", "ecat_mailbox.foe_packetno",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_errcode,
      { "Foe ErrorCode", "ecat_mailbox.foe_errcode",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_errtext,
      { "Foe ErrorString", "ecat_mailbox.foe_errtext",
      FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_busydone,
      { "Foe BusyDone", "ecat_mailbox.foe_busydone",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_busyentire,
      { "Foe BusyEntire", "ecat_mailbox.foe_busyentire",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_data,
      { "Foe Data", "ecat_mailbox.foe_busydata",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_efw,
      { "Firmware", "ecat_mailbox.foe.efw",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_efw_cmd,
      { "Cmd", "ecat_mailbox.foe.efw.cmd",
      FT_UINT16, BASE_HEX, VALS(FoEEfwCmd), 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_efw_size,
      { "Size", "ecat_mailbox.foe.efw.size",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_efw_addresslw,
      { "AddressLW", "ecat_mailbox.foe.efw.addresslw",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_efw_addresshw,
      { "AddressHW", "ecat_mailbox.foe.efw.addresshw",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_efw_data,
      { "Data", "ecat_mailbox.foe.efw.data",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe,
      { "Soe", "ecat_mailbox.soe",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_header,
      { "Soe Header", "ecat_mailbox.soe_header",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_header_opcode,
      { "SoE OpCode", "ecat_mailbox.soe_opcode",
      FT_UINT16, BASE_DEC, VALS(SoeOpcode), 0x0007, NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_header_incomplete,
      { "More Follows...", "ecat_mailbox.soe_header_incomplete",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), 0x0008, NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_header_error,
      { "Error", "ecat_mailbox.soe_header_error",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), 0x0010,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_header_driveno,
      { "Drive No", "ecat_mailbox.soe_header_driveno",
      FT_UINT16, BASE_DEC, NULL, 0x00e0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_header_datastate,
      { "Datastate", "ecat_mailbox.soe_header_datastate",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), 0x0100,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_header_name,
      { "Name", "ecat_mailbox.soe_header_name",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), 0x0200,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_header_attribute,
      { "Attribute", "ecat_mailbox.soe_header_attribute",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), 0x0400,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_header_unit,
      { "Unit", "ecat_mailbox.soe_header_unit",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), 0x0800,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_header_min,
      { "Min", "ecat_mailbox.soe_header_min",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), 0x1000,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_header_max,
      { "Max", "ecat_mailbox.soe_header_max",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), 0x2000,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_header_value,
      { "Value", "ecat_mailbox.soe_header_value",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), 0x4000,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_header_reserved,
      { "Reserved", "ecat_mailbox.soe_header_reserved",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), 0x8000,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_idn,
      { "SoE IDN", "ecat_mailbox.soe_idn",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_data,
      { "SoE Data", "ecat_mailbox.soe_data",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_frag,
      { "SoE FragLeft", "ecat_mailbox.soe_frag",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_error,
      { "SoE Error", "ecat_mailbox.soe_error",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
      }
   };

   static gint *ett[] =
   {
      &ett_ecat_mailbox,
      &ett_ecat_mailbox_eoe,
      &ett_ecat_mailbox_eoe_init,
      &ett_ecat_mailbox_eoe_macfilter,
      &ett_ecat_mailbox_eoe_macfilter_filter,
      &ett_ecat_mailbox_eoe_macfilter_filtermask,
      &ett_ecat_mailbox_coe,
      &ett_ecat_mailbox_sdo,
      &ett_ecat_mailbox_coe_sdoccs,
      &ett_ecat_mailbox_coe_sdoscs,
      &ett_ecat_mailbox_foe,
      &ett_ecat_mailbox_foe_efw,
      &ett_ecat_mailbox_soeflag,
      &ett_ecat_mailbox_soe,
      &ett_ecat_mailbox_fraghead,
      &ett_ecat_mailbox_header
   };

   static ei_register_info ei[] =
   {
      { &ei_ecat_mailbox_error, { "ecat_mailbox.invalid", PI_MALFORMED, PI_ERROR, "Malformed mailbox data", EXPFILL } },
      { &ei_ecat_mailbox_coe_error, { "ecat_mailbox.coe.invalid", PI_MALFORMED, PI_ERROR, "Malformed CoE data", EXPFILL } },
      { &ei_ecat_mailbox_foe_error, { "ecat_mailbox.foe.invalid", PI_MALFORMED, PI_ERROR, "Malformed FoE data", EXPFILL } },
      { &ei_ecat_mailbox_soe_error, { "ecat_mailbox.soe.invalid", PI_MALFORMED, PI_ERROR, "Malformed SoE data", EXPFILL } },
      { &ei_ecat_mailbox_eoe_error, { "ecat_mailbox.eoe.invalid", PI_MALFORMED, PI_ERROR, "Malformed EoE data", EXPFILL } },
   };

   expert_module_t *expert_module;

   proto_ecat_mailbox = proto_register_protocol("EtherCAT Mailbox Protocol",
      "ECAT_MAILBOX", "ecat_mailbox");

   expert_module = expert_register_protocol(proto_ecat_mailbox);
   expert_register_field_array(expert_module, ei, array_length(ei));

   proto_register_field_array(proto_ecat_mailbox, hf,array_length(hf));
   proto_register_subtree_array(ett, array_length(ett));

   ecat_mailbox_handle = register_dissector("ecat_mailbox", dissect_ecat_mailbox, proto_ecat_mailbox);
}

void proto_reg_handoff_ecat_mailbox(void)
{
   /* Register this dissector as a sub dissector to E88A4 based on ether type. */
   dissector_add_uint("ecatf.type", 5, ecat_mailbox_handle);

   eth_handle = find_dissector_add_dependency("eth_withoutfcs", proto_ecat_mailbox);
   ams_handle = find_dissector_add_dependency("ams", proto_ecat_mailbox);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 3
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=3 tabstop=8 expandtab:
 * :indentSize=3:tabSize=8:noTabs=true:
 */
