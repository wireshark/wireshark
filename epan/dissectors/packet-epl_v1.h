/* packet-epl_v1.h
 * Routines for "ETHERNET Powerlink 1.0" dissection
 * (ETHERNET Powerlink Powerlink WhitePaper V0006-B)
 *
 * Copyright (c) 2006: Zurich University of Applied Sciences Winterthur (ZHW)
 *                     Institute of Embedded Systems (InES)
 *                     http://ines.zhwin.ch
 *
 *                     - Dominic Bechaz <bdo@zhwin.ch>
 *                     - David Buechi <bhd@zhwin.ch>
 *
 *
 * $Id$
 *
 * A dissector for:
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __PACKET_EPL_V1_H__
#define __PACKET_EPL_V1_H__


/*Ethertype definition for EPL_V1 */
#define ETHERTYPE_EPL_V1  0x3E3F

/* Offsets of fields within an EPL_V1 packet. */
#define EPL_V1_SERVICE_OFFSET                     0   /* same offset for all message types*/
#define EPL_V1_DEST_OFFSET                        1   /* same offset for all message types*/
#define EPL_V1_SRC_OFFSET                         2   /* same offset for all message types*/

#define EPL_V1_SOC_C2_OFFSET                      3
#define EPL_V1_SOC_PF_OFFSET                      3
#define EPL_V1_SOC_NET_COMMAND_OFFSET             4
#define EPL_V1_SOC_NET_TIME_OFFSET                6
#define EPL_V1_SOC_POWERLINK_CYCLE_TIME_OFFSET   10
#define EPL_V1_SOC_NET_COMMAND_PARAMETER_OFFSET  14

#define EPL_V1_PREQ_C2_OFFSET                     3
/* "Powerlink Multimanager Konzept V1.1" protocol extension*/
#define PMM_KONZEPT_V1_1_PREQ_YA                    3
#define PMM_KONZEPT_V1_1_PREQ_SC                    3
/* end "Powerlink Multimanager Konzept V1.1" protocol extension*/
#define EPL_V1_PREQ_RD_OFFSET                     3
#define EPL_V1_PREQ_RD_OFFSET                     3
#define EPL_V1_PREQ_POLL_SIZE_OUT_OFFSET          4
#define EPL_V1_PREQ_OUT_DATA_OFFSET              10

#define EPL_V1_PRES_C2_OFFSET                     3
#define EPL_V1_PRES_EX_OFFSET                     3
#define EPL_V1_PRES_RS_OFFSET                     3
#define EPL_V1_PRES_WA_OFFSET                     3
#define EPL_V1_PRES_ER_OFFSET                     3
#define EPL_V1_PRES_RD_OFFSET                     3
#define EPL_V1_PRES_POLL_SIZE_IN_OFFSET           4
#define EPL_V1_PRES_IN_DATA_OFFSET               10

#define EPL_V1_EOC_NET_COMMAND_OFFSET             4
#define EPL_V1_EOC_NET_COMMAND_PARAMETER_OFFSET  14

#define EPL_V1_AINV_CHANNEL_OFFSET                3

#define EPL_V1_ASND_CHANNEL_OFFSET                3
#define EPL_V1_ASND_SIZE_OFFSET                   4
#define EPL_V1_ASND_DATA_OFFSET                   6
#define EPL_V1_ASND_NODE_ID_OFFSET                6
#define EPL_V1_ASND_HARDWARE_REVISION_OFFSET     10
#define EPL_V1_ASND_FIRMWARE_VERSION_OFFSET      14
#define EPL_V1_ASND_DEVICE_VARIANT_OFFSET        18
#define EPL_V1_ASND_POLL_IN_SIZE_OFFSET          22
#define EPL_V1_ASND_POLL_OUT_SIZE_OFFSET         26

/* EPL_V1 message types */
#define EPL_V1_SOC    0x01
#define EPL_V1_EOC    0x02
#define EPL_V1_PREQ   0x03
#define EPL_V1_PRES   0x04
#define EPL_V1_AINV   0x05
#define EPL_V1_ASND   0x06

static const value_string service_vals[] = {
	{EPL_V1_SOC,  "Start of Cyclic (SoC)"   },
	{EPL_V1_EOC,  "End of Cyclic (EoC)"     },
	{EPL_V1_PREQ, "Poll Request (PReq)"     },
	{EPL_V1_PRES, "Poll Response (PRes)"    },
	{EPL_V1_AINV, "Acyclic Invite (AInv)"   },
	{EPL_V1_ASND, "Acyclic Send (ASnd)"     },
	{0,NULL}
};

/* Channel values for EPL_V1 message type "AInv" */
#define EPL_V1_AINV_IDENT         1
#define EPL_V1_AINV_GENERIC     255

static const value_string ainv_channel_number_vals[] = {
	{EPL_V1_AINV_IDENT,     "Ident"             },
	{EPL_V1_AINV_GENERIC,   "Generic Channel"   },
	{0,NULL}
};

/* Channel values for EPL_V1 message type "ASnd" */
#define EPL_V1_ASND_IDENT         1
#define EPL_V1_ASND_GENERIC     255

static const value_string asnd_channel_number_vals[] = {
	{EPL_V1_ASND_IDENT,     "Ident"             },
	{EPL_V1_ASND_GENERIC,   "Generic Channel"   },
	{0,NULL}
};

/* Net Command values for EPL_V1 message type "SoC" */
#define EPL_V1_SOC_NET_COMMAND_IDLE   0
#define EPL_V1_SOC_NET_COMMAND_ACTIVE 1

static const value_string soc_net_command_vals[] = {
	{EPL_V1_SOC_NET_COMMAND_IDLE,   "Net Command Idle"  },
	{EPL_V1_SOC_NET_COMMAND_ACTIVE, "Net Command Active"},
	{0,NULL}
};

/* Net Command values for EPL_V1 message type "EoC" */
#define EPL_V1_EOC_NET_COMMAND_IDLE   0
#define EPL_V1_EOC_NET_COMMAND_ACTIVE 1

static const value_string eoc_net_command_vals[] = {
	{EPL_V1_EOC_NET_COMMAND_IDLE,   "Net Command Idle"  },
	{EPL_V1_EOC_NET_COMMAND_ACTIVE, "Net Command Active"},
	{0,NULL}
};

#endif /* __PACKET_EPL_V1_H__ */
