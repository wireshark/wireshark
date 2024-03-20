/** @file
 *
 * Definitions for wiretap module registration
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WTAP_MODULES_H__
#define __WTAP_MODULES_H__

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Entry in the table of built-in wiretap modules to register.
 */
typedef struct _wtap_module_reg {
    const char *cb_name;
    void (*cb_func)(void);
} wtap_module_reg_t;

extern wtap_module_reg_t const wtap_module_reg[];

extern const unsigned wtap_module_count;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WTAP_MODULES_H__ */

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
