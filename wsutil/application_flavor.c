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

static enum application_flavor_e application_flavor = APPLICATION_FLAVOR_WIRESHARK;

void set_application_flavor(enum application_flavor_e flavor)
{
    application_flavor = flavor;
}

enum application_flavor_e get_application_flavor(void)
{
    return application_flavor;
}

const char *application_flavor_name_proper(void) {
    switch (get_application_flavor()) {
    case APPLICATION_FLAVOR_WIRESHARK:
        return "Wireshark";
    case APPLICATION_FLAVOR_STRATOSHARK:
        return "Stratoshark";
    default:
        ws_assert_not_reached();
    }
}

const char *application_flavor_name_lower(void) {
    switch (get_application_flavor()) {
    case APPLICATION_FLAVOR_WIRESHARK:
        return "wireshark";
    case APPLICATION_FLAVOR_STRATOSHARK:
        return "stratoshark";
    default:
        ws_assert_not_reached();
    }
}

enum application_flavor_e application_name_to_flavor(const char *name)
{
    if (g_ascii_strcasecmp(name, "stratoshark") == 0) {
        return APPLICATION_FLAVOR_STRATOSHARK;
    }
    return APPLICATION_FLAVOR_WIRESHARK;
}

bool application_flavor_is_wireshark(void)
{
    return get_application_flavor() == APPLICATION_FLAVOR_WIRESHARK;
}

bool application_flavor_is_stratoshark(void)
{
    return get_application_flavor() == APPLICATION_FLAVOR_STRATOSHARK;
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
