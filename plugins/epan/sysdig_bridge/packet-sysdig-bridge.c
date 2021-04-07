/* packet-sysdig-bridge.c
 *
 * By Loris Degioanni
 * Copyright (C) 2021 Sysdig, Inc.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-sysdig-bridge.h"

#define FOO_PORT 1234
#define FOO_PORT1 1235

static int proto_foo = -1;
static int proto_foo1 = -1;

void
proto_register_foo(void)
{
    proto_foo = proto_register_protocol (
        "FOO Protocol", /* name       */
        "FOO",      /* short name */
        "foo"       /* abbrev     */
        );

    proto_foo1 = proto_register_protocol (
        "FOO1 Protocol", /* name       */
        "FOO1",      /* short name */
        "foo1"       /* abbrev     */
        );
}

static int
dissect_foo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FOO");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    return tvb_captured_length(tvb);
}

static int
dissect_foo1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FOO1");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    return tvb_captured_length(tvb);
}

void
proto_reg_handoff_foo(void)
{
    static dissector_handle_t foo_handle;
    foo_handle = create_dissector_handle(dissect_foo, proto_foo);
    dissector_add_uint("udp.port", FOO_PORT, foo_handle);

    static dissector_handle_t foo_handle1;
    foo_handle1 = create_dissector_handle(dissect_foo1, proto_foo1);
    dissector_add_uint("udp.port", FOO_PORT1, foo_handle1);
}
