/* packet-s5066sis.h
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

#ifndef __PACKET_S5066SIS_H__
#define __PACKET_S5066SIS_H__

/* S5066 Client Application IDs */
#define S5066_CLIENT_BFTP				0x1002
#define S5066_CLIENT_FRAP				0x100B
#define S5066_CLIENT_FRAP_V2				0x100C
#define S5066_CLIENT_S4406_ANNEX_E_TMI_1_P_MUL		0x2000
#define S5066_CLIENT_S4406_ANNEX_E_TMI_2		0x2001
#define S5066_CLIENT_S4406_ANNEX_E_TMI_3		0x2002
#define S5066_CLIENT_S4406_ANNEX_E_TMI_4_DMP		0x2003 /* TMI-4 is updated with DMP spec. */
#define S5066_CLIENT_S4406_ANNEX_E_TMI_5_ACP_127	0x2004

#endif /* PACKET_S5066SIS_H */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
