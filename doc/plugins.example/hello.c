/* hello.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define WS_BUILD_DLL
#include <wireshark.h>
#include <wsutil/plugins.h>
#include <epan/packet.h>
#include <epan/proto.h>

#ifndef VERSION
#define VERSION "0.0.0"
#endif

WS_DLL_PUBLIC_DEF const char plugin_version[] = VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);
WS_DLL_PUBLIC uint32_t plugin_describe(void);

static int proto_hello;
static dissector_handle_t handle_hello;

static int
dissect_hello(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_protocol_format(tree, proto_hello, tvb, 0, -1, "This is Hello version %s, a Wireshark postdissector plugin prototype", plugin_version);
    return tvb_captured_length(tvb);
}

static void
proto_register_hello(void)
{
    proto_hello = proto_register_protocol("Wireshark Hello Plugin", "Hello WS", "hello_ws");
    handle_hello = create_dissector_handle(dissect_hello, proto_hello);
    register_postdissector(handle_hello);
}

static void
proto_reg_handoff_hello(void)
{
    /* empty */
}

void
plugin_register(void)
{
    static proto_plugin plug;

    plug.register_protoinfo = proto_register_hello;
    plug.register_handoff = proto_reg_handoff_hello; /* or NULL */
    proto_register_plugin(&plug);
}

uint32_t
plugin_describe(void)
{
    return WS_PLUGIN_DESC_DISSECTOR;
}
