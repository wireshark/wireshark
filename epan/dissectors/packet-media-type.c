/* packet-media-type.c
 * Manage the media_type dissector table
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_media_type(void);
void event_register_media_type(void);


static void
common_register_media_type(void)
{
	/*
	 * Dissectors can register themselves in this table.
	 * It's just "media_type", not "http.content_type", because
	 * it's an Internet media type, used by other protocols as well.
	 *
	 * RFC 6838, 4.2 Naming Requirements:
	 * "Both top-level type and subtype names are case-insensitive."
	 */
	 register_dissector_table("media_type", "Internet media type",
	     -1 /* no protocol */, FT_STRING, STRING_CASE_INSENSITIVE);
}

void
proto_register_media_type(void)
{
    common_register_media_type();
}

void
event_register_media_type(void)
{
    common_register_media_type();
}
