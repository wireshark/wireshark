/* sparkle_bridge.h
 *
 * C wrapper for the Sparkle API
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

// XXX We could alternatively do this via C++:
// https://github.com/sparkle-project/Sparkle/issues/1137


#ifndef SPARKLE_BRIDGE_H
#define SPARKLE_BRIDGE_H

#include <stdbool.h>

void sparkle_software_update_init(const char *url, bool enabled, int interval);

void sparkle_software_update_check(void);

void sparkle_software_update_cleanup(void);

#endif // SPARKLE_BRIDGE_H

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
