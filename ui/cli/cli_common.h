/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CLI_COMMON_H__
#define __CLI_COMMON_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Dump profile information to the console.
 * @param app_env_var_prefix The prefix for application environment variables.
 * @param filter The filter for selecting profiles to dump.
 * @return True if the operation was successful, false otherwise.
 */
extern bool profiles_dump(const char* app_env_var_prefix, const char* filter);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CLI_COMMON_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
