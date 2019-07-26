/* packet-juniper.h
 * Routines for Juniper Networks, Inc. packet disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _PACKET_JUNIPER_H
#define _PACKET_JUNIPER_H

/* values < 200 are JUNOS internal proto values
 * found in frames containing no link-layer header */
enum {
  JUNIPER_PROTO_UNKNOWN = 0,
  JUNIPER_PROTO_IP = 2,
  JUNIPER_PROTO_MPLS_IP = 3,
  JUNIPER_PROTO_IP_MPLS = 4,
  JUNIPER_PROTO_MPLS = 5,
  JUNIPER_PROTO_IP6 = 6,
  JUNIPER_PROTO_MPLS_IP6 = 7,
  JUNIPER_PROTO_IP6_MPLS = 8,
  JUNIPER_PROTO_CLNP = 10,
  JUNIPER_PROTO_CLNP_MPLS = 32,
  JUNIPER_PROTO_MPLS_CLNP = 33,
  JUNIPER_PROTO_PPP = 200,
  JUNIPER_PROTO_ISO = 201,
  JUNIPER_PROTO_LLC = 202,
  JUNIPER_PROTO_LLC_SNAP = 203,
  JUNIPER_PROTO_ETHER = 204,
  JUNIPER_PROTO_OAM = 205,
  JUNIPER_PROTO_Q933 = 206,
  JUNIPER_PROTO_FRELAY = 207,
  JUNIPER_PROTO_CHDLC = 208
};

#endif /* _PACKET_JUNIPER_H */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
