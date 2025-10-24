/* application_flavor.c
 * Application flavor routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_WSUTIL

#include "application_flavor.h"
#include "path_config.h"

static enum application_flavor_e application_flavor = APPLICATION_FLAVOR_WIRESHARK;

void set_application_flavor(enum application_flavor_e flavor)
{
    application_flavor = flavor;
}

const char *application_flavor_name_proper(void) {
    switch (application_flavor) {
    case APPLICATION_FLAVOR_WIRESHARK:
        return "Wireshark";
    case APPLICATION_FLAVOR_STRATOSHARK:
        return "Stratoshark";
    default:
        ws_assert_not_reached();
    }
}

const char *application_flavor_name_lower(void) {
    switch (application_flavor) {
    case APPLICATION_FLAVOR_WIRESHARK:
        return "wireshark";
    case APPLICATION_FLAVOR_STRATOSHARK:
        return "stratoshark";
    default:
        ws_assert_not_reached();
    }
}

char* application_configuration_environment_variable(const char* suffix)
{
    switch (application_flavor) {
    case APPLICATION_FLAVOR_WIRESHARK:
        return g_strdup_printf("WIRESHARK_%s", suffix);
    case APPLICATION_FLAVOR_STRATOSHARK:
        return g_strdup_printf("STRATOSHARK_%s", suffix);
    default:
        ws_assert_not_reached();
    }
}

char* application_extcap_dir(const char* install_prefix)
{
    if (g_path_is_absolute(EXTCAP_DIR))
        return g_strdup(application_flavor == APPLICATION_FLAVOR_WIRESHARK ? EXTCAP_DIR : STRATOSHARK_EXTCAP_DIR);

    return g_build_filename(install_prefix,
        application_flavor == APPLICATION_FLAVOR_WIRESHARK ? EXTCAP_DIR : STRATOSHARK_EXTCAP_DIR, (char*)NULL);
}

bool application_flavor_is_wireshark(void)
{
    return (application_flavor == APPLICATION_FLAVOR_WIRESHARK);
}

bool application_flavor_is_stratoshark(void)
{
    return (application_flavor == APPLICATION_FLAVOR_STRATOSHARK);
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
