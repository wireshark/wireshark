/* hello.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <epan/packet.h>
#include <ws_attributes.h>

#ifndef VERSION
#define VERSION "0.0.0"
#endif

#define DLL_PUBLIC __attribute__((__visibility__("default")))

DLL_PUBLIC const gchar plugin_version[] = VERSION;
DLL_PUBLIC const gchar plugin_release[] = VERSION_RELEASE;

DLL_PUBLIC void plugin_register(void);

DLL_PUBLIC void plugin_reg_handoff(void);


static int proto_hello = -1;
static dissector_handle_t handle_hello;

static int
dissect_hello(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_protocol_format(tree, proto_hello, tvb, 0, -1, "This is Hello version %s, a Wireshark postdissector plugin prototype", plugin_version);
    return tvb_captured_length(tvb);
}

void plugin_register(void)
{
    proto_hello = proto_register_protocol("Wireshark Hello Plugin", "Hello", "hello");
    handle_hello = create_dissector_handle(dissect_hello, proto_hello);
    register_postdissector(handle_hello);
}

void plugin_reg_handoff(void)
{
    /* empty */
}
