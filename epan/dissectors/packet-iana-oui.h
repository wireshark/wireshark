/* packet-iana-oui.h
 * SNAP PIDs for the IANA's OUI 00:00:5e
 * See
 *
 *     http://www.iana.org/assignments/ethernet-numbers
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define IANA_PID_MARS_DATA_SHORT        0x0001  /* RFC 2022 */
#define IANA_PID_NHRP_RESERVED          0x0002  /* RFC 2332 */
#define IANA_PID_MARS_NHRP_CONTROL      0x0003  /* RFC 2022, RFC 2332 */
#define IANA_PID_MARS_DATA_LONG         0x0004  /* RFC 2022 */
#define IANA_PID_SCSP                   0x0005  /* RFC 2334 */
#define IANA_PID_VRID                   0x0006
#define IANA_PID_L2TP                   0x0007  /* RFC 3070 */
#define IANA_PID_VPN_ID                 0x0008  /* RFC 2684 */
#define IANA_PID_MSDP_GRE_PROTO_TYPE    0x0009

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
