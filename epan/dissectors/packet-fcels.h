/* packet-fcels.h
 * Fibre Channel Extended Link Services Definitions (ddutt@cisco.com)
 * Copyright 2001, Dinesh G Dutt <ddutt@cisco.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __PACKET_FCELS_H_
#define __PACKET_FCELS_H_

#define FC_ELS_LSRJT         0x01
#define FC_ELS_ACC           0x02  
#define FC_ELS_PLOGI         0x03
#define FC_ELS_FLOGI	     0x04
#define FC_ELS_LOGOUT        0x05
#define FC_ELS_ABTX          0x06
#define FC_ELS_RSI           0x0A
#define FC_ELS_TEST          0x11
#define FC_ELS_RRQ           0x12
#define FC_ELS_PRLI          0x20
#define FC_ELS_PRLO          0x21
#define FC_ELS_TPRLO         0x24
#define FC_ELS_PDISC         0x50
#define FC_ELS_FDISC         0x51
#define FC_ELS_ADISC         0x52
#define FC_ELS_FARP_REQ      0x54
#define FC_ELS_FARP_RPLY     0x55
#define FC_ELS_RPS           0x56
#define FC_ELS_RPL           0x57
#define FC_ELS_FAN           0x60
#define FC_ELS_RSCN          0x61
#define FC_ELS_SCR           0x62
#define FC_ELS_RNFT          0x63
#define FC_ELS_LINIT         0x70
#define FC_ELS_LSTS          0x72
#define FC_ELS_RNID          0x78
#define FC_ELS_RLIR          0x79
#define FC_ELS_LIRR          0x7A
#define FC_ELS_SRL           0x7B
#define FC_ELS_RPSC          0x7D
#define FC_ELS_AUTH          0x90
#define FC_ELS_CBIND         0xE0
#define FC_ELS_UNBIND        0xE4

static const value_string fc_els_proto_val[] = {
    {FC_ELS_LSRJT        , "LS_RJT"},
    {FC_ELS_ACC          , "ACC"},
    {FC_ELS_PLOGI        , "PLOGI"},
    {FC_ELS_FLOGI        , "FLOGI"},
    {FC_ELS_LOGOUT       , "LOGO"},
    {FC_ELS_ABTX         , "ABTX"},
    {FC_ELS_RSI          , "RSI"},
    {FC_ELS_TEST         , "TEST"},
    {FC_ELS_RRQ          , "RRQ"},
    {FC_ELS_PRLI         , "PRLI"},
    {FC_ELS_PRLO         , "PRLO"},
    {FC_ELS_TPRLO        , "TPRLO"},
    {FC_ELS_PDISC        , "PDISC"},
    {FC_ELS_FDISC        , "FDISC"},
    {FC_ELS_ADISC        , "ADISC"},
    {FC_ELS_FARP_REQ     , "FARP-REQ"},
    {FC_ELS_FARP_RPLY    , "FARP-REPLY"},
    {FC_ELS_RPS          , "RPS"},
    {FC_ELS_RPL          , "RPL"},
    {FC_ELS_FAN          , "FAN"},
    {FC_ELS_RSCN         , "RSCN"},
    {FC_ELS_SCR          , "SCR"},
    {FC_ELS_RNFT         , "RNFT"},
    {FC_ELS_LINIT        , "LINIT"},
    {FC_ELS_LSTS         , "LSTS"},
    {FC_ELS_RNID         , "RNID"},
    {FC_ELS_RLIR         , "RLIR"},
    {FC_ELS_LIRR         , "LIRR"},
    {FC_ELS_SRL          , "SRL"},
    {FC_ELS_RPSC         , "RPSC"},
    {FC_ELS_AUTH         , "AUTH"},
    {FC_ELS_CBIND        , "CBIND"},
    {FC_ELS_UNBIND       , "UNBIND"},
    {0, NULL},
};

/* Reject Reason Codes */
#define FC_ELS_RJT_INVCMDCODE   0x01
#define FC_ELS_RJT_LOGERR       0x03
#define FC_ELS_RJT_LOGBSY       0x05
#define FC_ELS_RJT_PROTERR      0x07
#define FC_ELS_RJT_GENFAIL      0x09
#define FC_ELS_RJT_CMDNOTSUPP   0x0B
#define FC_ELS_RJT_GENFAIL2     0x0D
#define FC_ELS_RJT_CMDINPROG    0x0E
#define FC_ELS_RJT_VENDOR       0xFF

static const value_string fc_els_rjt_val[] = {
    {FC_ELS_RJT_INVCMDCODE, "Invalid Cmd Code"},
    {FC_ELS_RJT_LOGERR    , "Logical Error"},
    {FC_ELS_RJT_LOGBSY    , "Logical Busy"},
    {FC_ELS_RJT_PROTERR   , "Protocol Error"},
    {FC_ELS_RJT_GENFAIL   , "Unable to Perform Cmd"},
    {FC_ELS_RJT_CMDNOTSUPP, "Command Not Supported"},
    {FC_ELS_RJT_GENFAIL2  , "Unable to Perform Cmd"},
    {FC_ELS_RJT_CMDINPROG , "Command in Progress Already"},
    {FC_ELS_RJT_VENDOR    , "Vendor Unique Error"},
    {0, NULL},
};

#define FC_ELS_RJT_DET_NODET             0x00
#define FC_ELS_RJT_DET_SVCPARM_OPT       0x01
#define FC_ELS_RJT_DET_SVCPARM_INITCTL   0x03
#define FC_ELS_RJT_DET_SVCPARM_RCPTCTL   0x05
#define FC_ELS_RJT_DET_SVCPARM_RCVSZE    0x07
#define FC_ELS_RJT_DET_SVCPARM_CSEQ      0x09
#define FC_ELS_RJT_DET_SVCPARM_CREDIT    0x0B
#define FC_ELS_RJT_DET_INV_PFNAME        0x0D
#define FC_ELS_RJT_DET_INV_NFNAME        0x0E
#define FC_ELS_RJT_DET_INV_CMNSVCPARM    0x0F
#define FC_ELS_RJT_DET_INV_ASSOCHDR      0x11
#define FC_ELS_RJT_DET_ASSOCHDR_REQD     0x13
#define FC_ELS_RJT_DET_INV_OSID          0x15
#define FC_ELS_RJT_DET_EXCHG_COMBO       0x17
#define FC_ELS_RJT_DET_CMDINPROG         0x19
#define FC_ELS_RJT_DET_PLOGI_REQ         0x1E
#define FC_ELS_RJT_DET_INV_NPID          0x1F
#define FC_ELS_RJT_DET_INV_SEQID         0x21
#define FC_ELS_RJT_DET_INV_EXCHG         0x23
#define FC_ELS_RJT_DET_INACTIVE_EXCHG    0x25
#define FC_ELS_RJT_DET_RQUAL_REQD        0x27
#define FC_ELS_RJT_DET_OORSRC            0x29
#define FC_ELS_RJT_DET_SUPPLYFAIL        0x2A
#define FC_ELS_RJT_DET_REQNOTSUPP        0x2C
#define FC_ELS_RJT_DET_INV_PLEN          0x2D
#define FC_ELS_RJT_DET_INV_ALIASID       0x30
#define FC_ELS_RJT_DET_OORSRC_ALIASID    0x31
#define FC_ELS_RJT_DET_INACTIVE_ALIASID  0x32
#define FC_ELS_RJT_DET_DEACT_ALIAS_FAIL1 0x33
#define FC_ELS_RJT_DET_DEACT_ALIAS_FAIL2 0x34
#define FC_ELS_RJT_DET_SVCPARM_CONFLICT  0x35
#define FC_ELS_RJT_DET_INV_ALIASTOK      0x36 
#define FC_ELS_RJT_DET_UNSUPP_ALIASTOK   0x37
#define FC_ELS_RJT_DET_GRPFORM_FAIL      0x38
#define FC_ELS_RJT_DET_QOSPARM_ERR       0x40
#define FC_ELS_RJT_DET_INV_VCID          0x41
#define FC_ELS_RJT_DET_OORSRC_C4         0x42
#define FC_ELS_RJT_DET_INV_PNNAME        0x44
#define FC_ELS_RJT_DET_AUTH_REQD         0x48

static const value_string fc_els_rjt_det_val[] = {
    {FC_ELS_RJT_DET_NODET            , "No further details"},
    {FC_ELS_RJT_DET_SVCPARM_OPT      , "Svc Param - Options Error"},
    {FC_ELS_RJT_DET_SVCPARM_INITCTL  , "Svc Param - Initiator Ctl Error"},
    {FC_ELS_RJT_DET_SVCPARM_RCPTCTL  , "Svc Param - Recipient Ctl Error"},
    {FC_ELS_RJT_DET_SVCPARM_RCVSZE   , "Svc Param - Recv Size Error"},
    {FC_ELS_RJT_DET_SVCPARM_CSEQ     , "Svc Param - Concurrent Seq Error"},
    {FC_ELS_RJT_DET_SVCPARM_CREDIT   , "Svc Param - Credit Error"},
    {FC_ELS_RJT_DET_INV_PFNAME       , "Invalid N_/F_Port Name"},
    {FC_ELS_RJT_DET_INV_NFNAME       , "Invalid Node/Fabric Name"},
    {FC_ELS_RJT_DET_INV_CMNSVCPARM   , "Invalid Common Svc Param"},
    {FC_ELS_RJT_DET_INV_ASSOCHDR     , "Invalid Association Header"},
    {FC_ELS_RJT_DET_ASSOCHDR_REQD    , "Association Header Reqd"},
    {FC_ELS_RJT_DET_INV_OSID         , "Invalid Orig S_ID"},
    {FC_ELS_RJT_DET_EXCHG_COMBO      , "Invalid OXID-RXID Combo"},
    {FC_ELS_RJT_DET_CMDINPROG        , "Cmd Already in Progress"},
    {FC_ELS_RJT_DET_PLOGI_REQ        , "N_Port Login Required"},
    {FC_ELS_RJT_DET_INV_NPID         , "Invalid N_Port Id"},
    {FC_ELS_RJT_DET_INV_SEQID        , "Invalid SeqID"},
    {FC_ELS_RJT_DET_INV_EXCHG        , "Attempt to Abort Invalid Exchg"},
    {FC_ELS_RJT_DET_INACTIVE_EXCHG   , "Attempt to Abort Inactive Exchg"},
    {FC_ELS_RJT_DET_RQUAL_REQD       , "Resource Qualifier Required"},
    {FC_ELS_RJT_DET_OORSRC           , "Insufficient Resources for Login"},
    {FC_ELS_RJT_DET_SUPPLYFAIL       , "Unable to Supply Req Data"},
    {FC_ELS_RJT_DET_REQNOTSUPP       , "Command Not Supported"},
    {FC_ELS_RJT_DET_INV_PLEN         , "Invalid Payload Length"},
    {FC_ELS_RJT_DET_INV_ALIASID      , "No Alias IDs available"},
    {FC_ELS_RJT_DET_OORSRC_ALIASID   , "Alias_ID Cannot be Activated (Out of Rsrc)"},
    {FC_ELS_RJT_DET_INACTIVE_ALIASID , "Alias_ID Cannot be Activated (Inv AID)"},
    {FC_ELS_RJT_DET_DEACT_ALIAS_FAIL1, "Alias_ID Cannot be Deactivated"},
    {FC_ELS_RJT_DET_DEACT_ALIAS_FAIL2, "Alias_ID Cannot be Deactivated"},
    {FC_ELS_RJT_DET_SVCPARM_CONFLICT , "Svc Parameter Conflict"},
    {FC_ELS_RJT_DET_INV_ALIASTOK     , "Invalid Alias Token"},
    {FC_ELS_RJT_DET_UNSUPP_ALIASTOK  , "Unsupported Alias Token"},
    {FC_ELS_RJT_DET_GRPFORM_FAIL     , "Alias Grp Cannot be Formed"},
    {FC_ELS_RJT_DET_QOSPARM_ERR      , "QoS Param Error"},
    {FC_ELS_RJT_DET_INV_VCID         , "VC_ID Not Found"},
    {FC_ELS_RJT_DET_OORSRC_C4        , "No Resources to Support Class 4 Conn"},
    {FC_ELS_RJT_DET_INV_PNNAME       , "Invalid Port/Node Name"},
    {FC_ELS_RJT_DET_AUTH_REQD        , "Authentication Required"},
    {0, NULL},
};

static const value_string fc_els_flacompliance_val[] = {
    {1, "FC-FLA Level 1"},
    {2, "FC-FLA Level 2"},
    {0, NULL},
};

static const value_string fc_els_loopstate_val[] = {
    {1, "Online"},
    {2, "Loop Failure"},
    {3, "Initialization Failure"},
    {4, "Initializing"},
    {0, NULL},
};

static const value_string fc_els_scr_reg_val[] = {
    {1, "Fabric Detected Regn"},
    {2, "N_Port Detected Regn"},
    {3, "Full Regn"},
    {255, "Clear All Regn"},
    {0, NULL},
};

static const value_string fc_els_farp_respaction_val[] = {
    {0, "No Action"},
    {1, "Login Using Requesting Port ID"},
    {2, "Respond with FARP-REPLY"},
    {3, "Login & send FARP-REPLY"},
    {0, NULL},
};

static const value_string fc_els_portstatus_val[] = {
    {0x20, "Point-to-Point Connection | No Fabric"},
    {0x10, "AL Connection | No Fabric"},
    {0x28, "Point-to-Point Connection | Fabric Detected"},
    {0x2C, "Point-to-Point Connection | Fabric Detected | Loss of Signal"},
    {0x24, "Point-to-Point Connection | Loss of Signal"},
    {0x18, "AL Connection | Fabric Detected"},
    {0x14, "AL Connection | Loss of Signal"},
    {0x1C, "AL Connection | Fabric Detected | Loss of Signal"},
    {0x04, "Loss of Signal"},
    {0x02, "Loss of Synchronization"},
    {0x01, "Link Reset Protocol in Progress"},
    {0, NULL},
};

static const value_string fc_els_portspeed_val[] = {
    {0x8000, "1 Gb"},
    {0x4000, "2 Gb"},
    {0x2000, "4 Gb"},
    {0x1000, "10 Gb"},
    {0x0002, "Unknown"},
    {0x0001, "Speed Not Estd."},
    {0, NULL}
};

static const value_string fc_els_lirr_regfunc_val[] = {
    {0x1, "Set Reg: Conditionally Receive"},
    {0x2, "Set Reg: Always Receive"},
    {0xFF, "Clear Reg"},
    {0, NULL},
};

static const value_string fc_els_rscn_evqual_val[] = {
    {0x00, "Event is not specified"},
    {0x01, "Changed Name Server Object"},
    {0x02, "Changed Port Attribute"},
    {0x03, "Changed Service Object"},
    {0x04, "Changed Switch Config"},
    {0, NULL},
};

static const value_string fc_els_rscn_addrfmt_val[] = {
    {0, "Port Addr (single N/L Port or service)"},
    {1, "Area Addr Group (area of E/L/N Port addresses)"},
    {2, "Domain Addr Group"},
    {3, "Fabric Addr Group"},
    {0, NULL},
};

static const value_string fc_els_nodeid_val[] = {
    {0x00, "Common Identification Data Only"},
    {0x05, "IP Specific Data"},
    {0x08, "FCP-Specific Data"},
    {0x20, "FC_CT Specific Data"},
    {0x22, "SW_ILS Specific Data"},
    {0x23, "AL Specific Data"},
    {0x24, "SNMP Specific Data"},
    {0xDF, "Common ID Data + General Topology Discovery Format"},
    {0, NULL},
};

static const value_string fc_els_rnid_asstype_val[] = {
    {0x0, "Reserved"},
    {0x1, "Unknown"},
    {0x2, "Other"},
    {0x3, "Hub"},
    {0x4, "Switch"},
    {0x5, "Gateway"},
    {0x6, "Converter"},
    {0x7, "HBA"},
    {0x9, "Storage Device"},
    {0xA, "Host"},
    {0xB, "Storage Subsystem"},
    {0xE, "Storage Access Device"},
    {0x11, "NAS Device"},
    {0, NULL},
};

static const value_string fc_els_rnid_mgmt_val[] = {
    {0, "IP/UDP/SNMP"},
    {1, "IP/TCP/Telnet"},
    {2, "IP/TCP/HTTP"},
    {3, "IP/TCP/HTTPS"},
    {0, NULL},
};

static const value_string fc_els_rnid_ipvers_val[] = {
    {0, "None"},
    {1, "IPv4"},
    {2, "IPv6"},
    {0, NULL},
};

#endif
