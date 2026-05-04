/** @file
 *
 * Registration tap hooks for Strato
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include <epan/conversation_table.h>

/**
 * @brief Initialize user I/O tracking for conversations.
 *
 * @param ct Pointer to conversation tracking structure.
 * @param filter Filter string for conversations.
 */
extern void init_iousers(struct register_ct* ct, const char *filter);

/**
 * @brief Initialize endpoint tracking for conversations.
 *
 * @param ct Pointer to conversation tracking structure.
 * @param filter Filter string for conversations.
 */
extern void init_endpoints(struct register_ct* ct, const char *filter);

/**
 * @brief Registers SRT tables for conversation tracking.
 *
 * @param key Pointer to the key for the table.
 * @param value Pointer to the value for the table.
 * @param userdata Pointer to user data.
 * @return bool indicating success or failure.
 */
extern bool register_srt_tables(const void *key, void *value, void *userdata);

/**
 * @brief Registers RTD tables for conversation tracking.
 *
 * @param key Pointer to the key for the table.
 * @param value Pointer to the value for the table.
 * @param userdata Pointer to user data.
 * @return bool indicating success or failure.
 */
extern bool register_rtd_tables(const void *key, void *value, void *userdata);

/**
 * @brief Registers simple statistic tables for conversation tracking.
 *
 * @param key Pointer to the key for the table.
 * @param value Pointer to the value for the table.
 * @param userdata Pointer to user data.
 * @return bool indicating success or failure.
 */
extern bool register_simple_stat_tables(const void *key, void *value, void *userdata);

/**
 * @brief Initializes funnel operations for conversation tracking.
 */
extern void initialize_funnel_ops(void);

/**
 * @brief Dumps all text windows for conversation tracking.
 */
extern void funnel_dump_all_text_windows(void);
