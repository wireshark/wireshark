/* packet-geneve.h
 * Routines for Geneve - Generic Network Virtualization Encapsulation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef __PACKET_GENEVE_H__
#define __PACKET_GENEVE_H__

/* This is used by custom dissectors and should be in the "install" target */
/* PUBLIC_HEADER */

typedef struct geneve_option
{
    uint16_t    opt_class;
    uint8_t     opt_type;
    uint8_t     opt_len;
    char        *critical;
    uint8_t     flags;
} geneve_option_t;

#endif /* __PACKET_GENEVE_H__ */

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
