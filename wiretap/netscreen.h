/* netscreen.h
 *
 * Juniper NetScreen snoop output parser
 * Created by re-using a lot of code from cosine.c
 * Copyright (c) 2007 by Sake Blok <sake@euronet.nl>
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __W_NETSCREEN_H__
#define __W_NETSCREEN_H__

#include <glib.h>
#include "wtap.h"

/* Magic text to check for NetScreen snoop output */
#define NETSCREEN_HDR_MAGIC_STR1	"(i) len="
#define NETSCREEN_HDR_MAGIC_STR2	"(o) len="

/* Magic text for start of packet */
#define NETSCREEN_REC_MAGIC_STR1	NETSCREEN_HDR_MAGIC_STR1
#define NETSCREEN_REC_MAGIC_STR2	NETSCREEN_HDR_MAGIC_STR2

#define NETSCREEN_LINE_LENGTH		128
#define NETSCREEN_HEADER_LINES_TO_CHECK	32
#define NETSCREEN_MAX_INFOLINES		8
#define NETSCREEN_SPACES_ON_INFO_LINE	14
#define NETSCREEN_MAX_INT_NAME_LENGTH	16

#define NETSCREEN_INGRESS		FALSE
#define NETSCREEN_EGRESS		TRUE

wtap_open_return_val netscreen_open(wtap *wth, int *err, gchar **err_info);

#endif
