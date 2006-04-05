/* packet-mtp3.h
 *
 * $Id$
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
  CHINESE_ITU_STANDARD = 3,
  JAPAN_STANDARD = 4
} Standard_Type;

extern gint mtp3_standard;

typedef enum {
  MTP3_ADDR_FMT_DEC		= 1,
  MTP3_ADDR_FMT_HEX		= 2,
  MTP3_ADDR_FMT_NI_DEC	= 3,
  MTP3_ADDR_FMT_NI_HEX	= 4,
  MTP3_ADDR_FMT_DASHED	= 5
} mtp3_net_addr_fmt_e;

typedef struct _mtp3_addr_pc_t {
  mtp3_net_addr_fmt_e	type;
  guint32		pc;
  guint8		ni;
} mtp3_addr_pc_t;

typedef struct _mtp3_tap_rec_t {
  mtp3_addr_pc_t	addr_opc;
  mtp3_addr_pc_t	addr_dpc;
  guint8		si_code;
  guint16		size;
} mtp3_tap_rec_t;

#define ITU_PC_LENGTH     2
#define ITU_PC_MASK       0x3FFF

#define ANSI_PC_LENGTH    3
#define ANSI_NCM_LENGTH   1
#define ANSI_MEMBER_OFFSET 0
#define ANSI_CLUSTER_OFFSET 1
#define ANSI_NETWORK_OFFSET 2
#define ANSI_PC_MASK      0xFFFFFF
#define ANSI_NETWORK_MASK 0x0000FF
#define ANSI_CLUSTER_MASK 0x00FF00
#define ANSI_MEMBER_MASK  0xFF0000
#define ANSI_PC_STRING_LENGTH 16

#define JAPAN_PC_LENGTH   2
#define JAPAN_PC_MASK     0xffff

extern void     mtp3_addr_to_str_buf(const guint8 *data, gchar *buf, int buf_len);
extern void     mtp3_pc_to_str_buf(const guint32 pc, gchar *buf, int buf_len);
extern gchar*   mtp3_pc_to_str(const guint32 pc);
extern gboolean mtp3_pc_structured(void);
extern guint32  mtp3_pc_hash(const guint8* data);

/*
 * the following allows TAP code access to the messages
 * without having to duplicate it. With MSVC and a 
 * libethereal.dll, we need a special declaration.
 */
ETH_VAR_IMPORT const value_string mtp3_service_indicator_code_short_vals[];

/*
 * I only want to gather stats for non-spare SI codes
 */
#define	MTP3_NUM_SI_CODE	9
