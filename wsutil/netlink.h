/* netlink.h
 * netlink-related definitions shared between libwireshark and other parts
 *
 * Copyright 2018, Martin Kaiser
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _WS_NETLINK_H
#define _WS_NETLINK_H

#include "config.h"

#if defined(HAVE_LIBNL)

/*
 * Pull in the include files where the kernel's nla_for_each_nested is defined.
 * This is to make sure that the kernel's definition will not overwrite our
 * version if msg.h or attr.h are included again explicitly after this file.
 */
DIAG_OFF_PEDANTIC
#include <netlink/msg.h>
DIAG_ON_PEDANTIC
#include <netlink/attr.h>

/*
 * And now for a steaming heap of suck.
 *
 * The nla_for_each_nested() macro defined by at least some versions of the
 * Linux kernel's headers doesn't do the casting required when compiling
 * with a C++ compiler or with -Wc++-compat, so we get warnings, and those
 * warnings are fatal when we compile this file.
 *
 * So we replace it with our own version, which does the requisite cast.
 */

/**
 * nla_for_each_nested - iterate over nested attributes
 * @pos: loop counter, set to current attribute
 * @nla: attribute containing the nested attributes
 * @rem: initialized to len, holds bytes currently remaining in stream
 */
#undef nla_for_each_nested
#define nla_for_each_nested(pos, nla, rem) \
    nla_for_each_attr(pos, (struct nlattr *)nla_data(nla), nla_len(nla), rem)

#endif /* HAVE_LIBNL */

#endif /* _WS_NETLINK_H */

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
