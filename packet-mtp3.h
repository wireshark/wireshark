/* packet-mtp3.h
 *
 * $Id: packet-mtp3.h,v 1.3 2003/04/10 18:52:11 guy Exp $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

typedef enum {
  ITU_STANDARD  = 1,
  ANSI_STANDARD = 2,
  CHINESE_ITU_STANDARD = 3
} Standard_Type;

extern Standard_Type mtp3_standard;

#define ITU_PC_LENGTH     2
#define ITU_PC_MASK       0x3FFF

#define ANSI_PC_LENGTH    3
#define ANSI_NCM_LENGTH   1
#define ANSI_MEMBER_OFFSET 0
#define ANSI_CLUSTER_OFFSET 1
#define ANSI_NETWORK_OFFSET 2
#define ANSI_NETWORK_MASK 0x0000FF
#define ANSI_CLUSTER_MASK 0x00FF00
#define ANSI_MEMBER_MASK  0xFF0000
#define ANSI_PC_STRING_LENGTH 16
