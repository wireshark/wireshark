/* wmem_user_cb.h
 * Definitions for the Wireshark Memory Manager User Callbacks
 * Copyright 2012, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __WMEM_USER_CB_H__
#define __WMEM_USER_CB_H__

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @addtogroup wmem
 *  @{
 *    @defgroup wmem-user-cb User Callbacks
 *
 *    User callbacks.
 *
 *    @{
 */

/** The events that can trigger a callback. */
typedef enum _wmem_cb_event_t {
    WMEM_CB_FREE_EVENT,    /**< wmem_free_all() */
    WMEM_CB_DESTROY_EVENT  /**< wmem_destroy_allocator() */
} wmem_cb_event_t;

/** Function signature for registered user callbacks.
 *
 * allocator The allocator that triggered this callback.
 * event     The event type that triggered this callback.
 * user_data Whatever user_data was originally passed to the call to
 *                  wmem_register_cleanup_callback().
 * @return          FALSE to unregister the callback, TRUE otherwise.
 */
typedef gboolean (*wmem_user_cb_t) (wmem_allocator_t*, wmem_cb_event_t, void*);

/** Register a callback function with the given allocator pool.
 *
 * @param allocator The allocator with which to register the callback.
 * @param callback  The function to be called as the callback.
 * @param user_data An arbitrary data pointer that is passed to the callback as
 *                  a way to specify extra parameters or store extra data. Note
 *                  that this pointer is not freed when a callback is finished,
 *                  you have to do that yourself in the callback, or just
 *                  allocate it in the appropriate wmem pool.
 * @return          ID of this callback that can be passed back to
 *                  wmem_unregister_callback().
 */
WS_DLL_PUBLIC
guint
wmem_register_callback(wmem_allocator_t *allocator, wmem_user_cb_t callback,
        void *user_data);

/** Unregister the callback function with the given ID.
 *
 * @param allocator The allocator from which to unregister the callback.
 * @param id        The callback id as returned from wmem_register_callback().
 */
WS_DLL_PUBLIC
void
wmem_unregister_callback(wmem_allocator_t *allocator, guint id);

/**   @}
 *  @} */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_USER_CB_H__ */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
