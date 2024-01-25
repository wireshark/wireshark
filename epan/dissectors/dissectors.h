/* dissectors.h
 * Definitions for protocol registration
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __DISSECTOR_REGISTER_H__
#define __DISSECTOR_REGISTER_H__

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _dissector_reg {
    const char *cb_name;
    void (*cb_func)(void);
} dissector_reg_t;

extern dissector_reg_t const dissector_reg_proto[];
extern dissector_reg_t const dissector_reg_handoff[];

extern const gulong dissector_reg_proto_count;
extern const gulong dissector_reg_handoff_count;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __DISSECTOR_REGISTER_H__ */

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
