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

#include <wsutil/cmdarg_err.h>
#include <ui/tap-credentials.h>

void register_tap_listener_credentials(void);

typedef struct credentials_tapdata_s {
    wmem_array_t* credentials;
} credentials_tapdata_t;

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

static void tap_credential_free(tap_credential_t *auth)
{
    wmem_free(NULL, auth->username);
    wmem_free(NULL, auth->info);
}

static void tap_credentials_free_all(credentials_tapdata_t *c)
{
    if (c->credentials == NULL)
        return;

    for (unsigned i = 0; i < wmem_array_get_count(c->credentials); i++) {
        tap_credential_t* auth = (tap_credential_t*)wmem_array_index(c->credentials, i);
        tap_credential_free(auth);
    }
    wmem_destroy_array(c->credentials);
    c->credentials = NULL;
}

static void credentials_finish(void *p)
{
    credentials_tapdata_t *c = (credentials_tapdata_t *)p;
    tap_credentials_free_all(c);
    g_free(c);
}

static void credentials_reset(void* p)
{
    credentials_tapdata_t *c = (credentials_tapdata_t *)p;
    tap_credentials_free_all(c);
    c->credentials = wmem_array_new(wmem_epan_scope(), sizeof(tap_credential_t));
}

static tap_packet_status credentials_packet(void *p, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *pri, tap_flags_t flags _U_)
{
    credentials_tapdata_t *c = (credentials_tapdata_t *)p;
    tap_credential_t* clone = tap_credential_clone((tap_credential_t*)pri);
    wmem_array_append(c->credentials, (void*)clone, 1);
    /* wmem_array_append() takes a copy of the data, so we need to free our clone.
     * But not its copies of the strings; tap_credential_free() frees those.
     */
    wmem_free(NULL, clone);

    return TAP_PACKET_REDRAW;
}

static void credentials_draw(void *p)
{
    credentials_tapdata_t *c = (credentials_tapdata_t *)p;
    printf("===================================================================\n");
    printf("%-10s %-16s %-16s %-16s\n", "Packet", "Protocol", "Username", "Info");
    printf("------     --------         --------         --------\n");
    for (unsigned i = 0; i < wmem_array_get_count(c->credentials); i++) {
        tap_credential_t* auth = (tap_credential_t*)wmem_array_index(c->credentials, i);
        printf("%-10u %-16s %-16s %-16s\n", auth->num, auth->proto, auth->username, auth->info ? auth->info : "");
    }
    printf("===================================================================\n");
}

static bool credentials_init(const char *opt_arg _U_, void *userdata _U_)
{
    GString* error_string;
    credentials_tapdata_t *c = g_new0(credentials_tapdata_t, 1);

    error_string = register_tap_listener("credentials", c, NULL, TL_REQUIRES_NOTHING,
        credentials_reset, credentials_packet, credentials_draw, credentials_finish);

    if (error_string) {
        /* error, we failed to attach to the tap. clean up */
        cmdarg_err("Couldn't register credentials tap: %s", error_string->str);
        credentials_finish((void *)c);
        g_string_free(error_string, TRUE);
        return false;
    }

    c->credentials = wmem_array_new(wmem_epan_scope(), sizeof(tap_credential_t));
    return true;
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
