/* main_statusbar.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __MAIN_STATUSBAR_H__
#define __MAIN_STATUSBAR_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

void profile_bar_update(void);
void packets_bar_update(void);
void status_expert_update(void);

/** Update the capture comment icon in the statusbar, depending on the
 *  current capture comment (XXX - it's only available for GTK at the moment)
 */
void status_capture_comment_update(void);

/** Push a formatted message referring to the currently-selected field
 * onto the statusbar.
 *
 * @param msg_format The format string for the message
 */
void statusbar_push_field_msg(const gchar *msg_format, ...)
    G_GNUC_PRINTF(1, 2);

/** Pop a message referring to the currently-selected field off the statusbar.
 */
void statusbar_pop_field_msg(void);

/** Push a formatted message referring to the current filter onto the
 * statusbar.
 *
 * @param msg_format The format string for the message
 */
void statusbar_push_filter_msg(const gchar *msg_format, ...)
    G_GNUC_PRINTF(1, 2);

/** Pop a message referring to the current filter off the statusbar.
 */
void statusbar_pop_filter_msg(void);

/** Push a formatted temporary message onto the statusbar. The message
 * is automatically removed at a later interval.
 *
 * @param msg_format The format string for the message
 */
void statusbar_push_temporary_msg(const gchar *msg_format, ...)
    G_GNUC_PRINTF(1, 2);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MAIN_STATUSBAR_H__ */

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
