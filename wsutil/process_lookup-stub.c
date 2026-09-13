/* process_lookup-stub.c
 * Look up the processes that have a network socket open: platforms without a backend
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "process_lookup_int.h"

static void *
stub_open(char **err_msg)
{
    *err_msg = g_strdup("Looking up the processes that own sockets is not supported on this platform");
    return NULL;
}

static void
stub_close(void *state _U_)
{
}

static bool
stub_refresh(void *state _U_, ws_process_lookup_add_socket_func add _U_,
             void *ctx _U_, char **err_msg)
{
    *err_msg = g_strdup("Looking up the processes that own sockets is not supported on this platform");
    return false;
}

static bool
stub_describe(void *state _U_, uint32_t pid _U_, ws_process_info_t *info _U_)
{
    return false;
}

const ws_process_lookup_backend_t ws_process_lookup_backend = {
    false,
    stub_open,
    stub_close,
    stub_refresh,
    stub_describe,
};

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
