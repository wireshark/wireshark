/* register.c
 * Definitions for protocol registration
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include "register.h"
#include "ws_attributes.h"

#include <glib.h>
#include "epan/dissectors/dissectors.h"

static const char *cur_cb_name = NULL;
//static GMutex register_cb_mtx;
static GAsyncQueue *register_cb_done_q;

#define CB_WAIT_TIME (150 * 1000) // microseconds

static void set_cb_name(const char *proto) {
    // g_mutex_lock(register_cb_mtx);
    cur_cb_name = proto;
    // g_mutex_unlock(register_cb_mtx);
}

static void *
register_all_protocols_worker(void *arg _U_)
{
    for (gulong i = 0; i < dissector_reg_proto_count; i++) {
        set_cb_name(dissector_reg_proto[i].cb_name);
        dissector_reg_proto[i].cb_func();
    }

    g_async_queue_push(register_cb_done_q, GINT_TO_POINTER(TRUE));
    return NULL;
}

void
register_all_protocols(register_cb cb, gpointer cb_data)
{
    const char *cb_name;
    register_cb_done_q = g_async_queue_new();
    gboolean called_back = FALSE;

#if GLIB_CHECK_VERSION(2,31,0)
    g_thread_new("register_all_protocols_worker", &register_all_protocols_worker, NULL);
#else
    g_thread_create(&register_all_protocols_worker, TRUE, FALSE, NULL);
#endif
    while (!g_async_queue_timeout_pop(register_cb_done_q, CB_WAIT_TIME)) {
        // g_mutex_lock(register_cb_mtx);
        cb_name = cur_cb_name;
        // g_mutex_unlock(register_cb_mtx);
        if (cb && cb_name) {
            cb(RA_REGISTER, cb_name, cb_data);
            called_back = TRUE;
        }
    }
    if (cb && !called_back) {
            cb(RA_REGISTER, "Registration finished", cb_data);
    }
}

static void *
register_all_protocol_handoffs_worker(void *arg _U_)
{
    for (gulong i = 0; i < dissector_reg_handoff_count; i++) {
        set_cb_name(dissector_reg_handoff[i].cb_name);
        dissector_reg_handoff[i].cb_func();
    }

    g_async_queue_push(register_cb_done_q, GINT_TO_POINTER(TRUE));
    return NULL;
}

void
register_all_protocol_handoffs(register_cb cb, gpointer cb_data)
{
    cur_cb_name = NULL;
    const char *cb_name;
    gboolean called_back = FALSE;

#if GLIB_CHECK_VERSION(2,31,0)
    g_thread_new("register_all_protocol_handoffs_worker", &register_all_protocol_handoffs_worker, NULL);
#else
    g_thread_create(&register_all_protocol_handoffs_worker, TRUE, FALSE, NULL);
#endif
    while (!g_async_queue_timeout_pop(register_cb_done_q, CB_WAIT_TIME)) {
        // g_mutex_lock(register_cb_mtx);
        cb_name = cur_cb_name;
        // g_mutex_unlock(register_cb_mtx);
        if (cb && cb_name) {
            cb(RA_HANDOFF, cb_name, cb_data);
            called_back = TRUE;
        }
    }
    if (cb && !called_back) {
            cb(RA_HANDOFF, "Registration finished", cb_data);
    }

    g_async_queue_unref(register_cb_done_q);
}

gulong register_count(void)
{
    return dissector_reg_proto_count + dissector_reg_handoff_count;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
