/* stratoshark_flavor.c
 * Application flavor routines for Stratoshark
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "vcs_version.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_WSUTIL

#include <app/application_flavor.h>
#include <wsutil/path_config.h>


const char *application_flavor_name_proper(void)
{
    return "Stratoshark";
}

const char *application_flavor_name_lower(void)
{
    return "stratoshark";
}

const char* application_configuration_environment_prefix(void)
{
    return "STRATOSHARK";
}

const char* application_extcap_dir(void)
{
    return STRATOSHARK_EXTCAP_DIR;
}

const char*
application_get_vcs_version_info(void)
{
#ifdef STRATOSHARK_VCS_VERSION
    return STRATOSHARK_VERSION " (" STRATOSHARK_VCS_VERSION ")";
#else
    return STRATOSHARK_VERSION;
#endif
}

const char*
application_get_vcs_version_info_short(void)
{
#ifdef STRATOSHARK_VCS_VERSION
    return STRATOSHARK_VCS_VERSION;
#else
    return VERSION;
#endif
}

void application_file_extensions(const struct file_extension_info** file_extensions, unsigned* num_extensions)
{
    static const struct file_extension_info stratoshark_file_type_extensions_base[] = {
            { "Stratoshark/... - scap", true, "scap"},
            { "JSON Log", true, "json;jsonl;log" },
            {"MS Procmon", true, "pml"},
    };

    *file_extensions = stratoshark_file_type_extensions_base;
    *num_extensions = array_length(stratoshark_file_type_extensions_base);
}

const char** application_columns(void)
{
    static const char* col_fmt_logs[] = {
        "No.",              "%m",
        "Time",             "%t",
        "Event name",       "%Cus:sysdig.event_name:0:R",
        "Proc Name",        "%Cus:proc.name:0:R",
        "PID",              "%Cus:proc.pid:0:R",
        "TID",              "%Cus:thread.tid:0:R",
        "FD",               "%Cus:fd.num:0:R",
        "FD Name",          "%Cus:fd.name:0:R",
        "Container Name",   "%Cus:container.name:0:R",
        "Arguments",        "%Cus:evt.args:0:R",
        "Info",             "%i"
    };

    return col_fmt_logs;
}

unsigned application_num_columns(void)
{
    return 11;
}

bool application_flavor_is_wireshark(void)
{
    return false;
}

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
