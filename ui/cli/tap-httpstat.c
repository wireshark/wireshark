/* tap-httpstat.c
 * tap-httpstat   2003 Jean-Michel FAYARD
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
#include <epan/value_string.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/dissectors/packet-http.h>

#include <wsutil/wslog.h>

#include <ui/cmdarg_err.h>

void register_tap_listener_httpstat(void);

/* used to keep track of the statictics for an entire program interface */
typedef struct _http_stats_t {
	char 		*filter;
	GHashTable	*hash_responses;
	GHashTable	*hash_requests;
} httpstat_t;

/* used to keep track of the stats for a specific response code
 * for example it can be { 3, 404, "Not Found" ,...}
 * which means we captured 3 reply http/1.1 404 Not Found */
typedef struct _http_response_code_t {
	guint32 	 packets;		/* 3 */
	guint	 	 response_code;		/* 404 */
	const gchar	*name;			/* Not Found */
	httpstat_t	*sp;
} http_response_code_t;

/* used to keep track of the stats for a specific request string */
typedef struct _http_request_methode_t {
	gchar		*response;	/* eg. : GET */
	guint32		 packets;
	httpstat_t	*sp;
} http_request_methode_t;


/* insert some entries */
static void
http_init_hash(httpstat_t *sp)
{
	int i;

	sp->hash_responses = g_hash_table_new(g_direct_hash, g_direct_equal);

	for (i=0; vals_http_status_code[i].strptr; i++)
	{
		http_response_code_t *sc = g_new (http_response_code_t, 1);
		sc->packets = 0;
		sc->response_code = vals_http_status_code[i].value;
		sc->name = vals_http_status_code[i].strptr;
		sc->sp = sp;
		g_hash_table_insert(sc->sp->hash_responses, GUINT_TO_POINTER(vals_http_status_code[i].value), sc);
	}
	sp->hash_requests = g_hash_table_new(g_str_hash, g_str_equal);
}
static void
http_draw_hash_requests(gchar *key _U_, http_request_methode_t *data, gchar *format)
{
	if (data->packets == 0)
		return;
	printf(format, data->response, data->packets);
}

static void
http_draw_hash_responses(gint * key _U_, http_response_code_t *data, char *format)
{
	if (data == NULL) {
		ws_warning("No data available, key=%d\n", *key);
		exit(EXIT_FAILURE);
	}
	if (data->packets == 0)
		return;
	/* "     %3d %-35s %9d packets", */
	/* The maximum existing response code length is 32 characters */
	printf(format, data->response_code, data->name, data->packets);
}

/* NOT USED at this moment */
/*
static void
http_free_hash(gpointer key, gpointer value, gpointer user_data _U_)
{
	g_free(key);
	g_free(value);
}
*/
static void
http_reset_hash_responses(gchar *key _U_, http_response_code_t *data, gpointer ptr _U_)
{
	data->packets = 0;
}
static void
http_reset_hash_requests(gchar *key _U_, http_request_methode_t *data, gpointer ptr _U_)
{
	data->packets = 0;
}

static void
httpstat_reset(void *psp)
{
	httpstat_t *sp = (httpstat_t *)psp;

	g_hash_table_foreach(sp->hash_responses, (GHFunc)http_reset_hash_responses, NULL);
	g_hash_table_foreach(sp->hash_requests, (GHFunc)http_reset_hash_requests, NULL);

}

static tap_packet_status
httpstat_packet(void *psp, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *pri, tap_flags_t flags _U_)
{
	const http_info_value_t *value = (const http_info_value_t *)pri;
	httpstat_t *sp = (httpstat_t *)psp;

	/* We are only interested in reply packets with a status code */
	/* Request or reply packets ? */
	if (value->response_code != 0) {
		http_response_code_t *sc;
		guint key = value->response_code;

		sc = (http_response_code_t *)g_hash_table_lookup(
				sp->hash_responses,
				GUINT_TO_POINTER(key));
		if (sc == NULL) {
			/* non standard status code ; we classify it as others
			 * in the relevant category (Informational,Success,Redirection,Client Error,Server Error)
			 */
			int i = value->response_code;
			if ((i < 100) || (i >= 600)) {
				return TAP_PACKET_DONT_REDRAW;
			}
			else if (i < 200) {
				key = 199;	/* Hopefully, this status code will never be used */
			}
			else if (i < 300) {
				key = 299;
			}
			else if (i < 400) {
				key = 399;
			}
			else if (i < 500) {
				key = 499;
			}
			else{
				key = 599;
			}
			sc = (http_response_code_t *)g_hash_table_lookup(
				sp->hash_responses,
				GUINT_TO_POINTER(key));
			if (sc == NULL)
				return TAP_PACKET_DONT_REDRAW;
		}
		sc->packets++;
	}
	else if (value->request_method) {
		http_request_methode_t *sc;

		sc = (http_request_methode_t *)g_hash_table_lookup(
				sp->hash_requests,
				value->request_method);
		if (sc == NULL) {
			sc = g_new(http_request_methode_t, 1);
			sc->response = g_strdup(value->request_method);
			sc->packets = 1;
			sc->sp = sp;
			g_hash_table_insert(sp->hash_requests, sc->response, sc);
		} else {
			sc->packets++;
		}
	} else {
		return TAP_PACKET_DONT_REDRAW;
	}
	return TAP_PACKET_REDRAW;
}


static void
httpstat_draw(void *psp)
{
	httpstat_t *sp = (httpstat_t *)psp;
	printf("\n");
	printf("===================================================================\n");
	if (! sp->filter || ! sp->filter[0])
		printf("HTTP Statistics\n");
	else
		printf("HTTP Statistics with filter %s\n", sp->filter);

	printf("* HTTP Response Status Codes                Packets\n");
	g_hash_table_foreach(sp->hash_responses, (GHFunc)http_draw_hash_responses,
			     (gpointer)"  %3d %-35s %9d\n");
	printf("* HTTP Request Methods                      Packets\n");
	g_hash_table_foreach(sp->hash_requests,  (GHFunc)http_draw_hash_requests,
			     (gpointer)"  %-39s %9d \n");
	printf("===================================================================\n");
}



/* When called, this function will create a new instance of httpstat.
 */
static void
httpstat_init(const char *opt_arg, void *userdata _U_)
{
	httpstat_t *sp;
	const char *filter = NULL;
	GString	*error_string;

	if (!strncmp (opt_arg, "http,stat,", 10)) {
		filter = opt_arg+10;
	} else {
		filter = NULL;
	}

	sp = g_new(httpstat_t, 1);
	sp->filter = g_strdup(filter);
	/*g_hash_table_foreach(http_status, (GHFunc)http_reset_hash_responses, NULL);*/


	error_string = register_tap_listener(
			"http",
			sp,
			filter,
			0,
			httpstat_reset,
			httpstat_packet,
			httpstat_draw,
			NULL);
	if (error_string) {
		/* error, we failed to attach to the tap. clean up */
		g_free(sp->filter);
		g_free(sp);
		cmdarg_err("Couldn't register http,stat tap: %s",
			 error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}

	http_init_hash(sp);
}

static stat_tap_ui httpstat_ui = {
	REGISTER_STAT_GROUP_GENERIC,
	NULL,
	"http,stat",
	httpstat_init,
	0,
	NULL
};

void
register_tap_listener_httpstat(void)
{
	register_stat_tap_ui(&httpstat_ui, NULL);
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
