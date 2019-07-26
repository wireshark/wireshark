/* dissectors.h
 * Definitions for protocol registration
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TAP_REGISTER_H__
#define __TAP_REGISTER_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <glib.h>

typedef struct _tap_reg {
    const char *cb_name;
    void (*cb_func)(void);
} tap_reg_t;

extern tap_reg_t tap_reg_listener[];

extern const gulong tap_reg_listener_count;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TAP_REGISTER_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
