/** @file
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

/**
 * @brief Update the profile display in the statusbar.
 */
void profile_bar_update(void);

/**
 * @brief Update the packet count display in the statusbar.
 */
void packets_bar_update(void);

/**
 * @brief Update the expert status in the statusbar.
 */
void status_expert_update(void);


/**
 * @brief Update the capture comment icon in the statusbar, depending on the
 *  current capture comment (XXX - it's only available for GTK at the moment)
 */
void status_capture_comment_update(void);

/**
 * @brief Push a formatted message referring to the currently-selected
 * field onto the statusbar.
 *
 * @param msg_format The format string for the message.
 * @param ...        Arguments for the format string.
 */
void statusbar_push_field_msg(const char *msg_format, ...)
    G_GNUC_PRINTF(1, 2);

/**
 * @brief Pop a message referring to the currently-selected field off
 * the statusbar.
 */
void statusbar_pop_field_msg(void);

/**
 * @brief Push a formatted message referring to the current filter onto
 * the statusbar.
 *
 * @param msg_format The format string for the message.
 * @param ...        Arguments for the format string.
 */
void statusbar_push_filter_msg(const char *msg_format, ...)
    G_GNUC_PRINTF(1, 2);

/**
 * @brief Pop a message referring to the current filter off the statusbar.
 */
void statusbar_pop_filter_msg(void);

/**
 * @brief Push a formatted temporary message onto the statusbar. The message
 * is automatically removed at a later interval.
 *
 * @param msg_format The format string for the message
 */
void statusbar_push_temporary_msg(const char *msg_format, ...)
    G_GNUC_PRINTF(1, 2);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MAIN_STATUSBAR_H__ */
