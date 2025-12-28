/** @file
 *
 * Declarations of routines to report version information for Wireshark
 * programs
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WS_VERSION_INFO_H__
#define __WS_VERSION_INFO_H__

#include <glib.h>
#include <wsutil/feature_list.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Initialize version and build information for the application.
 * Initialize information about the program for various purposes, including
 * reporting the version and build information for the program, putting
 * that information into crash dumps if possible, and giving the program
 * name and version information into capture files written by the program
 * if possible.
 *
 * @param appname A string that appears at the beginning of the information;
 * it should be the application name.
 *
 * @param appflavor Optional additional string for the "parent" program.
 * If NULL, "(Wireshark)" will be added.
 *
 * @param version_func Required callback to get version information.
 *
 * @param gather_compile Optional callback (if non-null) called to add build-time
 * information.
 *
 * @param gather_runtime Optional callback (if non-null) called to add
 * run-time information; this is required in order to, for example,
 * put the libcap information into the string, as we currently
 * don't use libcap in TShark.
 */
WS_DLL_PUBLIC
void ws_init_version_info(const char *appname,
		const char* appflavor,
		get_version_func version_func,
		gather_feature_func gather_compile,
		gather_feature_func gather_runtime);

/**
 * @brief Retrieve the application name and version string.
 *
 * Returns a string containing the application name (as set by
 * `ws_init_version_info()`) followed by the application version.
 * Useful for display in logs, diagnostics, or user-facing interfaces.
 *
 * @return  A constant string with the application name and version.
 */
WS_DLL_PUBLIC
const char *get_appname_and_version(void);

/**
 * @brief Collect PCRE2 compile-time feature information.
 *
 * Populates the given `feature_list` with details about the PCRE2 library's
 * compile-time capabilities, such as Unicode support, JIT availability, and
 * other configuration flags.
 *
 * @param l  Feature list to populate with PCRE2 compile information.
 */
WS_DLL_PUBLIC
void
gather_pcre2_compile_info(feature_list l);

/**
 * @brief Collect XXH3/XXHash compile-time feature information.
 *
 * Populates the provided `feature_list` with details about the XXHash library's
 * compile-time capabilities, such as algorithm variants, platform optimizations,
 * and available hashing modes.
 *
 * @param l  Feature list to populate with XXHash compile information.
 */
WS_DLL_PUBLIC
void
gather_xxhash_compile_info(feature_list l);

/**
 * @brief Collect zlib compile-time feature information.
 *
 * Populates the provided `feature_list` with details about the zlib library's
 * compile-time configuration, such as version, compression capabilities, and
 * optional features like GZIP or raw deflate support.
 *
 * @param l  Feature list to populate with zlib compile information.
 */
WS_DLL_PUBLIC
void
gather_zlib_compile_info(feature_list l);

/**
 * @brief Collect zlib-ng compile-time feature information.
 *
 * Populates the provided `feature_list` with details about the zlib-ng library's
 * compile-time configuration, such as enabled compression strategies, API compatibility
 * modes, and platform-specific optimizations.
 *
 * @param l  Feature list to populate with zlib-ng compile information.
 */
WS_DLL_PUBLIC
void
gather_zlib_ng_compile_info(feature_list l);

/**
 * @brief Retrieve compile-time version information for various libraries.
 *
 * Constructs and returns a `GString` containing compile-time version details
 * for linked libraries. If `gather_compile` is non-NULL, it is invoked to
 * append additional build-time information to the string.
 *
 * @param gather_compile  Optional callback to add extra compile-time features.
 * @return                A newly allocated `GString` with version info.
 */
WS_DLL_PUBLIC
GString *get_compiled_version_info(gather_feature_func gather_compile);

/**
 * @brief Collect PCRE2 runtime feature information.
 *
 * Populates the given `feature_list` with details about the PCRE2 library's
 * runtime capabilities, such as available features, runtime configuration,
 * and support for specific modes or extensions.
 *
 * @param l  Feature list to populate with PCRE2 runtime information.
 */
WS_DLL_PUBLIC
void
gather_pcre2_runtime_info(feature_list l);

/**
 * @brief Collect XXHash runtime feature information.
 *
 * Populates the given `feature_list` with details about the XXHash library's
 * runtime capabilities, such as supported hashing algorithms, performance
 * optimizations, and platform-specific features available at runtime.
 *
 * @param l  Feature list to populate with XXHash runtime information.
 */
WS_DLL_PUBLIC
void
gather_xxhash_runtime_info(feature_list l);

/**
 * @brief Collect zlib runtime feature information.
 *
 * Populates the given `feature_list` with details about the zlib library's
 * runtime capabilities, such as the loaded version, available compression
 * features, and any platform-specific runtime behaviors.
 *
 * @param l  Feature list to populate with zlib runtime information.
 */
WS_DLL_PUBLIC
void
gather_zlib_runtime_info(feature_list l);

/**
 * @brief Retrieve runtime version information for libraries and the operating system.
 *
 * Constructs and returns a `GString` containing runtime version details for various
 * linked libraries and the host OS. If `gather_runtime` is non-NULL, it is invoked
 * to append additional runtime-specific information, such as libcap details, which
 * may not be included by default (e.g., in TShark).
 *
 * @param gather_runtime  Optional callback to add extra runtime features.
 * @return                A newly allocated `GString` with runtime version info.
 */
WS_DLL_PUBLIC
GString *get_runtime_version_info(gather_feature_func gather_runtime);

/**
 * @brief Retrieve the Wireshark version number as integers.
 *
 * Populates the provided pointers with the major, minor, and micro
 * components of the Wireshark version number.
 *
 * @param major  Pointer to receive the major version number.
 * @param minor  Pointer to receive the minor version number.
 * @param micro  Pointer to receive the micro version number.
 */
WS_DLL_PUBLIC
void get_ws_version_number(int *major, int *minor, int *micro);

/**
 * @brief Display the program name and version to standard output.
 *
 * Prints the application name and version number, typically used in response
 * to command-line options requesting version information (e.g., `--version`).
 */
WS_DLL_PUBLIC
void show_version(void);

/**
 * @brief Display help header with program name, version, and description.
 *
 * Prints the application name and version number, followed by a user-supplied
 * description string and a standard message directing users to a URL for
 * additional information. Typically used in response to command-line help
 * options (e.g., `--help`).
 *
 * @param description  A brief description of the program or its functionality.
 */
WS_DLL_PUBLIC
void show_help_header(const char *description);

/**
 * @brief Retrieve the copyright information string.
 *
 * Returns a constant string containing copyright details for the application,
 * including ownership and licensing terms. This may be displayed in version
 * dialogs, help messages, or about boxes.
 *
 * @return  A constant string with copyright information.
 */
WS_DLL_PUBLIC
const char *get_copyright_info(void);

/**
 * @brief Retrieve the application's license information string.
 *
 * Returns a constant string describing the licensing terms under which
 * the application is distributed. This may include references to open-source
 * licenses such as GPL, MIT, or others, and is suitable for display in
 * help messages, about dialogs, or documentation.
 *
 * @return  A constant string with license information.
 */
WS_DLL_PUBLIC
const char *get_license_info(void);

/**
 * @brief Retrieve a short summary of the application's license information.
 *
 * Returns a concise string describing the application's licensing terms,
 * suitable for brief displays such as command-line output or about dialogs.
 *
 * @return  A constant string with abbreviated license information.
 */
WS_DLL_PUBLIC
const char *get_license_info_short(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WS_VERSION_INFO_H__ */
