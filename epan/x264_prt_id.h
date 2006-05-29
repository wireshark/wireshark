/* x264_prt_id.h
 * Definitions of X.264/ISO 11570 transport protocol IDs
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

#ifndef __X264_PRT_ID_H__
#define __X264_PRT_ID_H__

/* X.264 / ISO 11570 transport protocol ID values. */

#define	PRT_ID_ISO_8073			0x01	/* X.224/ISO 8073 COTP */
#define PRT_ID_ISO_8602			0x02	/* X.234/ISO 8602 CLTP */
#define PRT_ID_ISO_10736_ISO_8073	0x03	/* X.274/ISO 10736 + X.224/ISO 8073 */
#define PRT_ID_ISO_10736_ISO_8602	0x04	/* X.274/ISO 10736 + X.234/ISO 8602 */

#endif
