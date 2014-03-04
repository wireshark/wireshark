/* packet-fcdns.h
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

#ifndef __PACKET_FCDNS_H_
#define __PACKET_FCDNS_H_

/* Opcode definitions */
#define FCDNS_GA_NXT   0x0100
#define FCDNS_GID_A    0x0101
#define FCDNS_GPN_ID   0x0112
#define FCDNS_GNN_ID   0x0113
#define FCDNS_GCS_ID   0x0114
#define FCDNS_GFT_ID   0x0117
#define FCDNS_GSPN_ID  0x0118
#define FCDNS_GPT_ID   0x011A
#define FCDNS_GIPP_ID  0x011B
#define FCDNS_GFPN_ID  0x011C
#define FCDNS_GHA_ID   0x011D
#define FCDNS_GFD_ID   0x011E
#define FCDNS_GFF_ID   0x011F
#define FCDNS_GID_PN   0x0121
#define FCDNS_GIPP_PN  0x012B
#define FCDNS_GID_NN   0x0131
#define FCDNS_GPN_NN   0x0132
#define FCDNS_GIP_NN   0x0135
#define FCDNS_GIPA_NN  0x0136
#define FCDNS_GSNN_NN  0x0139
#define FCDNS_GNN_IP   0x0153
#define FCDNS_GIPA_IP  0x0156
#define FCDNS_GID_FT   0x0171
#define FCDNS_GPN_FT   0x0172
#define FCDNS_GNN_FT   0x0173
#define FCDNS_GID_PT   0x01A1
#define FCDNS_GID_IPP  0x01B1
#define FCDNS_GPN_IPP  0x01B2
#define FCDNS_GID_FF   0x01F1
#define FCDNS_RPN_ID   0x0212
#define FCDNS_RNN_ID   0x0213
#define FCDNS_RCS_ID   0x0214
#define FCDNS_RFT_ID   0x0217
#define FCDNS_RSPN_ID  0x0218
#define FCDNS_RPT_ID   0x021A
#define FCDNS_RIPP_ID  0x021B
#define FCDNS_RHA_ID   0x021D
#define FCDNS_RFD_ID   0x021E
#define FCDNS_RFF_ID   0x021F
#define FCDNS_RIP_NN   0x0235
#define FCDNS_RSNN_NN  0x0239
#define FCDNS_DA_ID    0x0300
/* dNS messages defined by FC-SW2 */
#define FCDNS_RA       0x0
#define FCDNS_GE_ID    0x0410
#define FCDNS_GE_PN    0x0420
#define FCDNS_GE_NN    0x0430
#define FCDNS_GE_IP    0x0450
#define FCDNS_GE_FT    0x0470
#define FCDNS_GE_PT    0x04A0
#define FCDNS_GE_ZM    0x04B0
#define FCDNS_GE_ZN    0x04C0
#define FCDNS_GE_IPP   0x04D0
#define FCDNS_GE_FF    0x04E0

static const value_string fc_dns_opcode_val[] = {
    {FCDNS_GA_NXT, "GA_NXT"  },
    {FCDNS_GID_A,  "GID_A"   },
    {FCDNS_GPN_ID, "GPN_ID"  },
    {FCDNS_GNN_ID, "GNN_ID"  },
    {FCDNS_GCS_ID, "GCS_ID"  },
    {FCDNS_GFT_ID, "GFT_ID"  },
    {FCDNS_GSPN_ID, "GSPN_ID" },
    {FCDNS_GPT_ID, "GPT_ID"  },
    {FCDNS_GIPP_ID, "GIPP_ID" },
    {FCDNS_GFPN_ID, "GFPN_ID" },
    {FCDNS_GHA_ID, "GHA_ID"  },
    {FCDNS_GFD_ID, "GFD_ID"  },
    {FCDNS_GFF_ID, "GFF_ID"  },
    {FCDNS_GID_PN, "GID_PN"  },
    {FCDNS_GIPP_PN, "GIPP_PN" },
    {FCDNS_GID_NN, "GID_NN"  },
    {FCDNS_GPN_NN, "GPN_NN"  },
    {FCDNS_GIP_NN, "GIP_NN"  },
    {FCDNS_GIPA_NN, "GIPA_NN" },
    {FCDNS_GSNN_NN, "GSNN_NN" },
    {FCDNS_GNN_IP, "GNN_IP"  },
    {FCDNS_GIPA_IP, "GIPA_IP" },
    {FCDNS_GID_FT, "GID_FT"  },
    {FCDNS_GPN_FT, "GPN_FT"  },
    {FCDNS_GNN_FT, "GNN_FT"  },
    {FCDNS_GID_PT, "GID_PT"  },
    {FCDNS_GID_IPP, "GID_IPP" },
    {FCDNS_GPN_IPP, "GPN_IPP" },
    {FCDNS_GID_FF, "GID_FF"  },
    {FCDNS_RPN_ID, "RPN_ID"  },
    {FCDNS_RNN_ID, "RNN_ID"  },
    {FCDNS_RCS_ID, "RCS_ID"  },
    {FCDNS_RFT_ID, "RFT_ID"  },
    {FCDNS_RSPN_ID, "RSPN_ID" },
    {FCDNS_RPT_ID, "RPT_ID"  },
    {FCDNS_RIPP_ID, "RIPP_ID" },
    {FCDNS_RHA_ID, "RHA_ID"  },
    {FCDNS_RFD_ID, "RFD_ID"  },
    {FCDNS_RFF_ID, "RFF_ID"  },
    {FCDNS_RIP_NN, "RIP_NN"  },
    {FCDNS_RSNN_NN, "RSNN_NN"},
    {FCDNS_DA_ID, "DA_ID"},
    {FCDNS_GE_ID, "GE_ID"},
    {FCDNS_GE_PN, "GE_PN"},
    {FCDNS_GE_NN, "GE_NN"},
    {FCDNS_GE_IP, "GE_IP"},
    {FCDNS_GE_FT, "GE_FT"},
    {FCDNS_GE_PT, "GE_PT"},
    {FCDNS_GE_ZM, "GE_ZM"},
    {FCDNS_GE_ZN, "GE_ZN"},
    {FCDNS_GE_IPP, "GE_IPP"},
    {FCDNS_GE_FF, "GE_FF"},
    {FCCT_MSG_ACC, "MSG_ACC"},
    {FCCT_MSG_RJT, "MSG_RJT"},
    {0, NULL},
};

/* Port type definitions */
#define FCDNS_PTYPE_UNDEF    0x00
#define FCDNS_PTYPE_NPORT    0x01
#define FCDNS_PTYPE_NLPORT   0x02
#define FCDNS_PTYPE_FNLPORT  0x03
#define FCDNS_PTYPE_NXPORT   0x7F
#define FCDNS_PTYPE_FPORT    0x81
#define FCDNS_PTYPE_FLPORT   0x82
#define FCDNS_PTYPE_EPORT    0x84
#define FCDNS_PTYPE_BPORT    0x85

static const value_string fc_dns_port_type_val [] = {
    {FCDNS_PTYPE_UNDEF   , "Undefined Port Type"},
    {FCDNS_PTYPE_NPORT   , "N_Port"},
    {FCDNS_PTYPE_NLPORT  , "NL_Port"},
    {FCDNS_PTYPE_FNLPORT , "F/NL_Port"},
    {FCDNS_PTYPE_NXPORT  , "Nx_Port"},
    {FCDNS_PTYPE_FPORT   , "F_Port"},
    {FCDNS_PTYPE_FLPORT  , "FL_Port"},
    {FCDNS_PTYPE_EPORT   , "E_Port"},
    {FCDNS_PTYPE_BPORT   , "B_Port"},
    {0, NULL},
};

/* Reject Detailed Reason code definitions for dNS */
#define FCDNS_RJT_NOREASON          0x00
#define FCDNS_RJT_PIDNOTREG         0x01
#define FCDNS_RJT_PNAMENOTREG       0x02
#define FCDNS_RJT_NNAMENOTREG       0x03
#define FCDNS_RJT_CLASSNOTREG       0x04
#define FCDNS_RJT_IPNNOTREG         0x05
#define FCDNS_RJT_IPANOTREG         0x06
#define FCDNS_RJT_FC4NOTREG         0x07
#define FCDNS_RJT_SPNAMENOTREG      0x08
#define FCDNS_RJT_SNNAMENOTREG      0x09
#define FCDNS_RJT_PTYPENOTREG       0x0A
#define FCDNS_RJT_IPPNOTREG         0x0B
#define FCDNS_RJT_FPNAMENOTREG      0x0C
#define FCDNS_RJT_HRDADDNOTREG      0x0D
#define FCDNS_RJT_FC4DESNOTREG      0x0E
#define FCDNS_RJT_FC4FEANOTREG      0x0F
#define FCDNS_RJT_ACCRJT            0x10
#define FCDNS_RJT_PTYPEFMT          0x11
#define FCDNS_RJT_DBEMPTY           0x12
#define FCDNS_RJT_NOOBJSCOPE        0x13
#define FCDNS_RJT_AUTHRZN_EXCEPTION 0xF0
#define FCDNS_RJT_AUTH_EXCEPTION    0xF1
#define FCDNS_RJT_DB_FULL           0xF2
#define FCDNS_RJT_DB_EMPTY          0xF3

static const value_string fc_dns_rjt_det_code_val [] = {
    {FCDNS_RJT_NOREASON    , "No Additional Info"},
    {FCDNS_RJT_PIDNOTREG   , "PortID Not Regd."},
    {FCDNS_RJT_PNAMENOTREG , "PortName Not Regd."},
    {FCDNS_RJT_NNAMENOTREG , "NodeName Not Regd."},
    {FCDNS_RJT_CLASSNOTREG , "Class Not Regd."},
    {FCDNS_RJT_IPNNOTREG   , "IP Addr (Node) Not Regd."},
    {FCDNS_RJT_IPANOTREG   , "IPA Not Regd."},
    {FCDNS_RJT_FC4NOTREG   , "FC4 TYPEs Not Regd."},
    {FCDNS_RJT_SPNAMENOTREG, "Symbolic PortName Not Regd."},
    {FCDNS_RJT_SNNAMENOTREG, "Symbolic NodeName Not Regd."},
    {FCDNS_RJT_PTYPENOTREG , "PortType Not Regd."},
    {FCDNS_RJT_IPPNOTREG   , "IP Addr (Port) Not Regd."},
    {FCDNS_RJT_FPNAMENOTREG, "Fabric Port Name Not Regd."},
    {FCDNS_RJT_HRDADDNOTREG, "Hard Addr Not Regd."},
    {FCDNS_RJT_FC4DESNOTREG, "FC4 Descriptors Not Regd."},
    {FCDNS_RJT_FC4FEANOTREG, "FC4 Features Not Regd."},
    {FCDNS_RJT_ACCRJT      , "Access Denied"},
    {FCDNS_RJT_PTYPEFMT    , "Unacceptable PortId"},
    {FCDNS_RJT_DBEMPTY     , "Database Empty"},
    {FCDNS_RJT_NOOBJSCOPE  , "No Objects Regd. in Scope"},
    {FCDNS_RJT_AUTHRZN_EXCEPTION, "Authorization Exception"},
    {FCDNS_RJT_AUTH_EXCEPTION, "Authentication Exception"},
    {FCDNS_RJT_DB_FULL, "Database Full"},
    {FCDNS_RJT_DB_EMPTY, "Database Empty"},
    {0, NULL},
};

/* Actual servers serving the directory service type identified by subtype */
#define FCDNS_GSSUBTYPE_DNS  0x02
#define FCDNS_GSSUBTYPE_IP   0x03

static const value_string fc_dns_subtype_val[] = {
    {FCDNS_GSSUBTYPE_DNS, "dNS"},
    {FCDNS_GSSUBTYPE_IP,  "IP"},
    {0, NULL},
};

#endif
