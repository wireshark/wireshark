/* packet-fcfzs.h
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

#ifndef __PACKET_FCFZS_H_
#define __PACKET_FCFZS_H_

/* Opcode definitions */
#define FC_FZS_GZC         0x100
#define FC_FZS_GEST        0x111
#define FC_FZS_GZSN        0x112
#define FC_FZS_GZD         0x113
#define FC_FZS_GZM         0x114
#define FC_FZS_GAZS        0x115
#define FC_FZS_GZS         0x116
#define FC_FZS_ADZS        0x200
#define FC_FZS_AZSD        0x201
#define FC_FZS_AZS         0x202
#define FC_FZS_DZS         0x203
#define FC_FZS_AZM         0x204
#define FC_FZS_AZD         0x205
#define FC_FZS_RZM         0x300
#define FC_FZS_RZD         0x301
#define FC_FZS_RZS         0x302

static const value_string fc_fzs_opcode_val[] = {
    {FC_FZS_GZC   , "Get Capabilities"},
    {FC_FZS_GEST  , "Get Enforcement State"},
    {FC_FZS_GZSN  , "Get Zone Set List"},
    {FC_FZS_GZD   , "Get Zone List"},
    {FC_FZS_GZM   , "Get Zone Member List"},
    {FC_FZS_GAZS  , "Get Active Zone Set"},
    {FC_FZS_GZS   , "Get Zone Set"},
    {FC_FZS_ADZS  , "Add Zone Set"},
    {FC_FZS_AZSD  , "Activate Zone Set Direct"},
    {FC_FZS_AZS   , "Activate Zone Set"},
    {FC_FZS_DZS   , "Deactivate Zone Set"},
    {FC_FZS_AZM   , "Add Zone Members"},
    {FC_FZS_AZD   , "Add Zone"},
    {FC_FZS_RZM   , "Remove Zone Members"},
    {FC_FZS_RZD   , "Remove Zone"},
    {FC_FZS_RZS   , "Remove Zone Set"},
    {FCCT_MSG_ACC , "MSG_ACC"},
    {FCCT_MSG_RJT , "MSG_RJT"},
    {0, NULL},
};

/* Reason code explanantions */
#define FC_FZS_RJT_NODETAIL                0x0
#define FC_FZS_RJT_ZONENOTSUPPORTED        0x1
#define FC_FZS_RJT_ZSNUNKNOWN              0x10
#define FC_FZS_RJT_NZSACTIVE               0x11
#define FC_FZS_RJT_ZONEUNKNOWN             0x12
#define FC_FZS_RJT_ZONESTATEUNKNOWN        0x13
#define FC_FZS_RJT_INVLDPLEN               0x14
#define FC_FZS_RJT_ZSTOOLARGE              0x15
#define FC_FZS_RJT_DZSFAIL                 0x16
#define FC_FZS_RJT_NOTSUPPORTED            0x17
#define FC_FZS_RJT_CAPNOTSUPPORTED         0x18
#define FC_FZS_RJT_ZMIDTYPEUNKNOWN         0x19
#define FC_FZS_RJT_INVLDZSDEF              0x1A

static const value_string fc_fzs_rjt_code_val[] = {
    {FC_FZS_RJT_NODETAIL         , "No Additional Explanantion"},
    {FC_FZS_RJT_ZONENOTSUPPORTED , "Zones Not Supported"},
    {FC_FZS_RJT_ZSNUNKNOWN       , "Zone Set Name Unknown"},
    {FC_FZS_RJT_NZSACTIVE        , "No Zone Set Active"},
    {FC_FZS_RJT_ZONEUNKNOWN      , "Zone Name Unknown"},
    {FC_FZS_RJT_ZONESTATEUNKNOWN , "Zone State Unknown"},
    {FC_FZS_RJT_INVLDPLEN        , "Incorrect Payload Length"},
    {FC_FZS_RJT_ZSTOOLARGE       , "Zone Set to be Activated Too Large"},
    {FC_FZS_RJT_DZSFAIL          , "Deactive Zone Set Failed"},
    {FC_FZS_RJT_NOTSUPPORTED     , "Request Not Supported"},
    {FC_FZS_RJT_CAPNOTSUPPORTED  , "Capability Not Supported"},
    {FC_FZS_RJT_ZMIDTYPEUNKNOWN  , "Zone Member Identifier Type Not Supported"},
    {FC_FZS_RJT_INVLDZSDEF       , "Invalid Zone Set Definition"},
    {0, NULL},
};

/* Zone Member Identifier Types */

#define FC_FZS_ZONEMBR_PWWN           1
#define FC_FZS_ZONEMBR_DP             2
#define FC_FZS_ZONEMBR_FCID           3
#define FC_FZS_ZONEMBR_NWWN           4
#define FC_FZS_ZONEMBR_PWWN_LUN       0xE1
#define FC_FZS_ZONEMBR_DP_LUN         0xE2
#define FC_FZS_ZONEMBR_FCID_LUN       0xE3

static const value_string fc_fzs_zonembr_type_val[] = {
    {0, "Reserved"},
    {FC_FZS_ZONEMBR_PWWN,           "N_Port WWN"},
    {FC_FZS_ZONEMBR_DP,             "Domain/Physical Port (0x00ddpppp)"},
    {FC_FZS_ZONEMBR_FCID,           "FC Address"},
    {FC_FZS_ZONEMBR_NWWN,           "Node WWN"},
    {FC_FZS_ZONEMBR_PWWN_LUN,       "N_Port WWN+LUN"},
    {FC_FZS_ZONEMBR_DP_LUN,         "Domain/Physical Port+LUN"},
    {FC_FZS_ZONEMBR_FCID_LUN,       "FC Address+LUN"},
    {0, NULL},
};

#endif
