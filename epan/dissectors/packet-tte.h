/* packet-tte.h
 * Header for Time Triggered Ethernet dissection
 *
 * Author: Valentin Ecker
 * Author: Benjamin Roch, benjamin.roch [AT] tttech.com
 *
 * TTTech Computertechnik AG, Austria.
 * http://www.tttech.com/solutions/ttethernet/
 *
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifndef _PACKET_TTE_H_
#define _PACKET_TTE_H_

/* in bytes, at least MAC dest/source and EthernetType must be there
   to look for TTE */
#define TTE_HEADER_LENGTH               14

#define TTE_MAC_LENGTH                  6   /* in bytes */
#define TTE_MACDEST_CF_LENGTH           4   /* in bytes */
#define TTE_MACDEST_CTID_LENGTH         2   /* in bytes */

#define TTE_ETHERTYPE_LENGTH            2   /* in bytes */

#define TTE_PCF_LENGTH                  28  /* in bytes */
#define TTE_PCF_IC_LENGTH               4   /* in bytes */
#define TTE_PCF_MN_LENGTH               4   /* in bytes */
#define TTE_PCF_RES0_LENGTH             4   /* in bytes */
#define TTE_PCF_SP_LENGTH               1   /* in bytes */
#define TTE_PCF_SD_LENGTH               1   /* in bytes */
#define TTE_PCF_TYPE_LENGTH             1   /* in bytes ( actually 4 bits  ) */
#define TTE_PCF_RES1_LENGTH             5   /* in bytes ( actually 44 bits ) */
#define TTE_PCF_TC_LENGTH               8   /* in bytes */


#endif /* _PACKET_TTE_H_ */

