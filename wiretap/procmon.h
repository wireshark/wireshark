/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PROCMON_H__
#define __PROCMON_H__

#include "wtap.h"

/**
 * @brief Describes a single loaded module (DLL or executable image) within a monitored process.
 */
typedef struct procmon_module_t {
    nstime_t    timestamp;     /**< Timestamp at which this module was loaded into the process. */
    uint64_t    base_address;  /**< Base virtual address at which this module is mapped in the process address space. */
    uint32_t    size;          /**< Size in bytes of the mapped module image. */
    const char *image_path;    /**< Full file system path to the module image on disk. */
    const char *version;       /**< Version string from the module's version resource; NULL if unavailable. */
    const char *company;       /**< Company name from the module's version resource; NULL if unavailable. */
    const char *description;   /**< File description from the module's version resource; NULL if unavailable. */
} procmon_module_t;

/**
 * @brief Describes a single process observed by Process Monitor, including its identity, security context, and loaded modules.
 */
typedef struct procmon_process_t {
    nstime_t          start_time;            /**< Timestamp at which this process was created. */
    nstime_t          end_time;              /**< Timestamp at which this process exited; zero if still running. */
    uint64_t          authentication_id;     /**< Windows authentication ID (LUID) of the logon session under which this process runs. */
    uint32_t          process_id;            /**< Process identifier (PID) assigned by the operating system. */
    uint32_t          parent_process_id;     /**< PID of the parent process that spawned this process. */
    uint32_t          parent_process_index;  /**< Index into the process table of the parent process entry. */
    uint32_t          session_number;        /**< Windows Terminal Services session number in which this process runs. */
    const char       *integrity;             /**< Integrity level of the process (e.g. "Low", "Medium", "High", "System"). */
    const char       *user_name;             /**< User account name under which this process is running. */
    const char       *process_name;          /**< Base name of the process executable (e.g. "notepad.exe"). */
    const char       *image_path;            /**< Full file system path to the process executable image. */
    const char       *command_line;          /**< Full command line string used to launch this process. */
    const char       *company;               /**< Company name from the executable's version resource; NULL if unavailable. */
    const char       *version;               /**< Version string from the executable's version resource; NULL if unavailable. */
    const char       *description;           /**< File description from the executable's version resource; NULL if unavailable. */
    procmon_module_t *modules;               /**< Array of modules loaded into this process; contains @p num_modules entries. */
    uint32_t          num_modules;           /**< Number of entries in the @p modules array. */
    bool              is_virtualized : 1;    /**< True if this process is running under UAC virtualization. */
    bool              is_64_bit      : 1;    /**< True if this is a 64-bit process; false if it is a 32-bit (WOW64) process. */
} procmon_process_t;

/**
 * @brief Opens a procmon file and initializes the wtap structure.
 *
 * @param wth Pointer to the wtap structure that will be initialized.
 * @param err Pointer to an integer where any error code will be stored.
 * @param err_info Pointer to a char pointer where any error information will be stored.
 * @return wtap_open_return_val The result of opening the file.
 */
wtap_open_return_val procmon_open(wtap *wth, int *err, char **err_info);

#endif
