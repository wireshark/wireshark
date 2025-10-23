/** @file
 *
 * Routines to print various "standard" failure messages used in multiple
 * places.
 *
 * This is a "simple" version that does not link with libwiretap and interpret
 * the WTAP_ERR_ or WTAP_FILE_TYPE_SUBTYPE_ values that are parameters to the
 * capture file routines (cfile_*). It is for use in dumpcap, which does not
 * link with libwiretap or libui. The libwiretap-related routines should not
 * be called from dumpcap, but a rudimentary implementation is provided since
 * wsutil/report_message expects them.
 *
 * Console programs that do link against libwiretap should include
 * ui/failure_message.h instead.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __FAILURE_MESSAGE_SIMPLE_H__
#define __FAILURE_MESSAGE_SIMPLE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Registers routines with the report_message mechanism.
 *
 * This function initializes the failure message reporting system
 * using the provided program name for user-friendly output.
 *
 * @param friendly_program_name A human-readable name of the program
 *                              to include in failure messages.
 */
extern void init_report_failure_message_simple(const char *friendly_program_name);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FAILURE_MESSAGE_SIMPLE_H__ */
