/* packet-fcfcs.h
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

#ifndef __PACKET_FCFCS_H_
#define __PACKET_FCFCS_H_

#define FCFCS_GTIN       0x100
#define FCFCS_GIEL       0x101
#define FCFCS_GIET       0x111
#define FCFCS_GDID       0x112
#define FCFCS_GMID       0x113
#define FCFCS_GFN        0x114
#define FCFCS_GIELN      0x115
#define FCFCS_GMAL       0x116
#define FCFCS_GIEIL      0x117
#define FCFCS_GPL        0x118
#define FCFCS_GPT        0x121
#define FCFCS_GPPN       0x122
#define FCFCS_GAPNL      0x124
#define FCFCS_GPS        0x126
#define FCFCS_GATIN      0x128
#define FCFCS_GPLNL      0x191
#define FCFCS_GPLT       0x192
#define FCFCS_GPLML      0x193
#define FCFCS_GNPL       0x1A1
#define FCFCS_GPNL       0x1A2
#define FCFCS_GNID       0x1B1
#define FCFCS_RIELN      0x215
#define FCFCS_RPL        0x280
#define FCFCS_RPLN       0x291
#define FCFCS_RPLT       0x292
#define FCFCS_RPLM       0x293   
#define FCFCS_DPL        0x380
#define FCFCS_DPLN       0x391
#define FCFCS_DPLML      0x393
#define FCFCS_GCAP       0xe020

/* Used in protocol detail window */
static const value_string fc_fcs_opcode_val[] = {
    {FCCT_MSG_ACC, "MSG_ACC"},
    {FCCT_MSG_RJT, "MSG_RJT"},
    {FCFCS_GTIN, "Get Topology Info"},
    {FCFCS_GIEL, "Get Interconnect Element List"},
    {FCFCS_GIET, "Get Interconnect Element Type"},
    {FCFCS_GDID, "Get Interconnect Element Domain ID"},
    {FCFCS_GMID, "Get Interconnect Element Mgmt ID"},
    {FCFCS_GFN, "Get Interconnect Element Fabric Name"},
    {FCFCS_GIELN, "Get Interconnect Element Logical Name"},
    {FCFCS_GMAL, "Get Interconnect Element Mgmt Addr List"},
    {FCFCS_GIEIL, "Get Interconnect Element Info List"},
    {FCFCS_GPL, "Get Port List"},
    {FCFCS_GPT, "Get Port Type"},
    {FCFCS_GPPN, "Get Physical Port Number"},
    {FCFCS_GAPNL, "Get Physical Port Name List"},
    {FCFCS_GPS, "Get Port State"},
    {FCFCS_GATIN, "Get Attached Topology Info"},
    {FCFCS_GPLNL, "Get Platform Node Name List"},
    {FCFCS_GPLT, "Get Platform Type"},
    {FCFCS_GPLML, "Get Platform Mgmt Addr List"},
    {FCFCS_GNPL, "Get Platform Node Name List"},
    {FCFCS_GPNL, "Get Platform Name List"},
    {FCFCS_GNID, "Get Node Identification Data"},
    {FCFCS_RIELN, "Register Interconnect Element Logical Name"},
    {FCFCS_RPL, "Register Platform"},
    {FCFCS_RPLN, "Register Platform Node Name"},
    {FCFCS_RPLT, "Register Platform Type"},
    {FCFCS_RPLM, "Register Platform Mgmt. Address"},
    {FCFCS_DPL, "Deregister Platform"},
    {FCFCS_DPLN, "Deregister Platform Node Name"},
    {FCFCS_DPLML, "Deregister Platform Mgmt. Address List"},
    {FCFCS_GCAP, "Get Capabilities"},
    {0, NULL},
};

/* Used in protocol summary window */
static const value_string fc_fcs_opcode_abbrev_val[] = {
    {FCCT_MSG_ACC, "MSG_ACC"},
    {FCCT_MSG_RJT, "MSG_RJT"},
    {FCFCS_GTIN, "GTIN"},
    {FCFCS_GIEL, "GIEL"},
    {FCFCS_GIET, "GIET"},
    {FCFCS_GDID, "GDID"},
    {FCFCS_GMID, "GMID"},
    {FCFCS_GFN, "GFN"},
    {FCFCS_GIELN, "GIELN"},
    {FCFCS_GMAL, "GMAL"},
    {FCFCS_GIEIL, "GIEIL"},
    {FCFCS_GPL, "GPL"},
    {FCFCS_GPT, "GPT"},
    {FCFCS_GPPN, "GPPN"},
    {FCFCS_GAPNL, "GAPNL"},
    {FCFCS_GPS, "GPS"},
    {FCFCS_GATIN, "GATIN"},
    {FCFCS_GPLNL, "GPLNL"},
    {FCFCS_GPLT, "GPLT"},
    {FCFCS_GPLML, "GPLML"},
    {FCFCS_GNPL, "GNPL"},
    {FCFCS_GPNL, "GPNL"},
    {FCFCS_GNID, "GNID"},
    {FCFCS_RIELN, "RIELN"},
    {FCFCS_RPL, "RPL"},
    {FCFCS_RPLN, "RPLN"},
    {FCFCS_RPLT, "RPLT"},
    {FCFCS_RPLM, "RPLM"},
    {FCFCS_DPL, "DPL"},
    {FCFCS_DPLN, "DPLN"},
    {FCFCS_DPLML, "DPLML"},
    {FCFCS_GCAP,  "GCAP"},
    {0, NULL},
};

static const value_string fc_fcs_ietype_val[] = {
    {0, "Unknown"},
    {1, "Switch"},
    {2, "Hub"},
    {3, "Bridge"},
    {0, NULL},
};

/* Port type definitions, same as in dNS (fcdns.h) */
#define FCFCS_PTYPE_UNDEF    0x00
#define FCFCS_PTYPE_NPORT    0x01
#define FCFCS_PTYPE_NLPORT   0x02
#define FCFCS_PTYPE_FNLPORT  0x03
#define FCFCS_PTYPE_NXPORT   0x7F
#define FCFCS_PTYPE_FPORT    0x81
#define FCFCS_PTYPE_FLPORT   0x82
#define FCFCS_PTYPE_EPORT    0x84
#define FCFCS_PTYPE_BPORT    0x85

static const value_string fc_fcs_port_type_val[] = {
    {FCFCS_PTYPE_UNDEF   , "Undefined Port Type"},
    {FCFCS_PTYPE_NPORT   , "N_Port"},
    {FCFCS_PTYPE_NLPORT  , "NL_Port"},
    {FCFCS_PTYPE_FNLPORT , "F/NL_Port"},
    {FCFCS_PTYPE_NXPORT  , "Nx_Port"},
    {FCFCS_PTYPE_FPORT   , "F_Port"},
    {FCFCS_PTYPE_FLPORT  , "FL_Port"},
    {FCFCS_PTYPE_EPORT   , "E_Port"},
    {FCFCS_PTYPE_BPORT   , "B_Port"},
    {0, NULL},
};

static const value_string fc_fcs_port_txtype_val[] = {
    {1, "Unknown"},
    {2, "Long Wave Laser"},
    {3, "Short Wave Laser"},
    {4, "Long Wave Laser Cost Reduced"},
    {5, "Electrical"},
    {0, NULL},
};

static const value_string fc_fcs_port_modtype_val[] = {
    {1, "Unknown"},
    {2, "Other"},
    {3, "GBIC"},
    {4, "Embedded"},
    {5, "GLM"},
    {6, "GBIC with Serial ID"},
    {7, "GBIC without Serial ID"},
    {8, "SFP with Serial ID"},
    {9, "SFP without Serial ID"},
    {0, NULL},
};

static const value_string fc_fcs_port_state_val[] = {
    {0, "Unknown"},
    {1, "Online"},
    {2, "Offline"},
    {3, "Testing"},
    {4, "Fault"},
    {0, NULL},
};

static const value_string fc_fcs_plat_type_val[] = {
    {1, "Unknown"},
    {2, "Other"},
    {5, "Gateway"},
    {6, "Converter"},
    {7, "HBA"},
    {8, "Software Proxy Agent"},
    {9, "Storage Device"},
    {10, "Host Computer"},
    {11, "Storage Subsystem"},
    {12, "Module"},
    {13, "Software Driver"},
    {14, "Storage Access Device"},
    {0, NULL},
};

static const value_string fc_fcs_rjt_code_val[] = {
    {0x00, "No Additional Explanation"},
    {0x01, "Invalid Name_Identifier for Interconnect Element or Port"},
    {0x10, "Interconnect Element List Not Available"},
    {0x11, "Interconnect Element Type Not Available"},
    {0x12, "Domain ID Not Available"},
    {0x13, "Mgmt. ID Not Available"},
    {0x14, "Fabric Name Not Available"},
    {0x15, "Interconnect Element Logical Name Not Available"},
    {0x16, "Mgmt. Address Not Available"},
    {0x17, "Interconnect Element Information List Not Available"},
    {0x30, "Port List Not Available"},
    {0x31, "Port Type Not Available"},
    {0x32, "Physical Port Number Not Available"},
    {0x34, "Attached Port Name List Not Available"},
    {0x36, "Port State Not Available"},
    {0x50, "Unable to Register Interconnect Element Logical Name"},
    {0x60, "Platform Name Does Not Exist"},
    {0x61, "Platform Name Already Exists"},
    {0x62, "Platform Node Name Does Not Exist"},
    {0x63, "Platform Node Name Already Exists"},
    {0, NULL},
};

static const true_false_string fc_fcs_portflags_tfs = {
    "RTIN ELS Supported",
    "RTIN ELS Not Supported",
};

static const value_string fc_fcs_fcsmask_val[] = {
    {1, "Basic Configuration Service"},
    {2, "Platform Configuration Service"},
    {3, "Basic+Platform Configuration Service"},
    {4, "Topology Discovery Configuration Service"},
    {5, "Basic+Topology Discovery Configuration Service"},
    {6, "Platform+Topology Discovery Configuration Service"},
    {7, "Basic+Platform+Topology Discovery Configuration Service"},
    {0, NULL},
};

static const value_string fc_fcs_unsmask_val[] = {
    {1, "Basic Unzoned Name Service"},
    {0, NULL},
};

#endif
