/*
 * tap-credentials.c
 * Copyright 2019 Dario Lombardo <lomato@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet_info.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>

#include <ui/cmdarg_err.h>
#include <ui/tap-credentials.h>

void register_tap_listener_credentials(void);

wmem_array_t* credentials = NULL;

static tap_credential_t* tap_credential_clone(tap_credential_t* auth)
{
    tap_credential_t* clone = wmem_new0(NULL, tap_credential_t);
    clone->num = auth->num;
    clone->username_num = auth->username_num;
    clone->password_hf_id = auth->password_hf_id;
    if (auth->username)
        clone->username = wmem_strdup(NULL, auth->username);
    clone->proto = auth->proto;
    if (auth->info)
        clone->info = wmem_strdup(NULL, auth->info);
    return clone;
}

static tap_packet_status credentials_packet(void *p _U_, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *pri, tap_flags_t flags _U_)
{
    tap_credential_t* clone = tap_credential_clone((tap_credential_t*)pri);
    wmem_array_append(credentials, (void*)clone, 1);
    return TAP_PACKET_REDRAW;
}

static void credentials_reset(void* p)
{
    if (!p)
        return;
    tap_credential_t* auth = (tap_credential_t*)p;
    wmem_free(NULL, auth->username);
    wmem_free(NULL, auth->info);
    wmem_free(NULL, auth);
}

static void credentials_draw(void *p _U_)
{
    printf("===================================================================\n");
    printf("%-10s %-16s %-16s %-16s\n", "Packet", "Protocol", "Username", "Info");
    printf("------     --------         --------         --------\n");
    for (guint i = 0; i < wmem_array_get_count(credentials); i++) {
        tap_credential_t* auth = (tap_credential_t*)wmem_array_index(credentials, i);
        printf("%-10u %-16s %-16s %-16s\n", auth->num, auth->proto, auth->username, auth->info ? auth->info : "");
    }
    printf("===================================================================\n");
}

static void credentials_init(const char *opt_arg _U_, void *userdata _U_)
{
    GString* error_string;

    error_string = register_tap_listener("credentials", NULL, NULL, TL_REQUIRES_NOTHING,
        credentials_reset, credentials_packet, credentials_draw, NULL);

    if (error_string) {
        /* error, we failed to attach to the tap. clean up */
        cmdarg_err("Couldn't register credentials tap: %s", error_string->str);
        g_string_free(error_string, TRUE);
        exit(1);
    }

    credentials = wmem_array_new(wmem_epan_scope(), sizeof(tap_credential_t));
}

static stat_tap_ui credentials_ui = {
    REGISTER_TOOLS_GROUP_UNSORTED,
    "Username and passwords",
    "credentials",
    credentials_init,
    0,
    NULL
};

void
register_tap_listener_credentials(void)
{
    register_stat_tap_ui(&credentials_ui, NULL);
}

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
