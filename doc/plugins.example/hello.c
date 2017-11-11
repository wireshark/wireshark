/* hello.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
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
