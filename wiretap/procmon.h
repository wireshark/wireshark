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

typedef struct procmon_module_t {
    nstime_t timestamp;
    uint64_t base_address;
    uint32_t size;
    const char *image_path;
    const char *version;
    const char *company;
    const char *description;
} procmon_module_t;

typedef struct procmon_process_t {
    nstime_t start_time;
    nstime_t end_time;
    uint64_t authentication_id;
    uint32_t process_id;
    uint32_t parent_process_id;
    uint32_t parent_process_index;
    uint32_t session_number;
    const char *integrity;
    const char *user_name;
    const char *process_name;
    const char *image_path;
    const char *command_line;
    const char *company;
    const char *version;
    const char *description;
    procmon_module_t *modules;
    uint32_t num_modules;
    bool is_virtualized : 1;
    bool is_64_bit      : 1;
} procmon_process_t;

wtap_open_return_val procmon_open(wtap *wth, int *err, char **err_info);

#endif
