/* packet-fcp.h
 * Fibre Channel SCSI (FCP) Protocol definitions 
 * Copyright 2001 Dinesh G Dutt (ddutt@cisco.com)
 *
 * $Id: packet-fcp.h,v 1.1 2002/12/08 02:32:17 gerald Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifndef __PACKET_FCP_H_
#define __PACKET_FCP_H_

/* Information Categories based on lower 4 bits of R_CTL */
#define FCP_IU_DATA              0x1
#define FCP_IU_CONFIRM           0x3
#define FCP_IU_XFER_RDY          0x5
#define FCP_IU_CMD               0x6
#define FCP_IU_RSP               0x7

static const value_string fcp_iu_val[] = {
    {FCP_IU_DATA      , "FCP_DATA"},
    {FCP_IU_CONFIRM   , "Confirm"},
    {FCP_IU_XFER_RDY  , "XFER_RDY"},
    {FCP_IU_CMD       , "FCP_CMND"},
    {FCP_IU_RSP       , "FCP_RSP"},
    {0, NULL},
};

/* Task Attribute Values */
static const value_string fcp_task_attr_val[] = {
    {0, "Simple"},
    {1, "Head of Queue"},
    {2, "Ordered"},
    {4, "ACA"},
    {5, "Untagged"},
    {0, NULL},
};

/* RSP Code Definitions (from FCP_RSP_INFO) */
static const value_string fcp_rsp_code_val[] = {
    {0, "Task Management Function Complete"},
    {1, "FCP_DATA length Different from FCP_BURST_LEN"},
    {2, "FCP_CMND Fields Invalid"},
    {3, "FCP_DATA Parameter Mismatch With FCP_DATA_RO"},
    {4, "Task Management Function Rejected"},
    {5, "Task Management Function Failed"},
    {0, NULL},
};

#define FCP_DEF_CMND_LEN         32 /* by default cmnd is 32 bytes */
#define FCP_DEF_RSP_LEN          24 /* default FCP_RSP len */

#endif
