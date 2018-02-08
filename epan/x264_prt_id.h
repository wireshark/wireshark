/* x264_prt_id.h
 * Definitions of X.264/ISO 11570 transport protocol IDs
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __X264_PRT_ID_H__
#define __X264_PRT_ID_H__

/* X.264 / ISO 11570 transport protocol ID values. */

#define	PRT_ID_ISO_8073			0x01	/* X.224/ISO 8073 COTP */
#define PRT_ID_ISO_8602			0x02	/* X.234/ISO 8602 CLTP */
#define PRT_ID_ISO_10736_ISO_8073	0x03	/* X.274/ISO 10736 + X.224/ISO 8073 */
#define PRT_ID_ISO_10736_ISO_8602	0x04	/* X.274/ISO 10736 + X.234/ISO 8602 */

#endif
