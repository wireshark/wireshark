/* tap-rtspstat.c
 * tap-rtspstat   March 2011
 *
 * Stephane GORSE (Orange Labs / France Telecom)
 * Copied from Jean-Michel FAYARD's works (HTTP)
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
#include <epan/dissectors/packet-rtsp.h>

#include <wsutil/wslog.h>

#include <ui/cmdarg_err.h>

void register_tap_listener_rtspstat(void);

/* used to keep track of the statictics for an entire program interface */
typedef struct _rtsp_stats_t {
	char 		*filter;
	GHashTable	*hash_responses;
	GHashTable	*hash_requests;
} rtspstat_t;

/* used to keep track of the stats for a specific response code
 * for example it can be { 3, 404, "Not Found" ,...}
 * which means we captured 3 reply rtsp/1.1 404 Not Found */
typedef struct _rtsp_response_code_t {
	guint32 	 packets;		/* 3 */
	guint	 	 response_code;	/* 404 */
	const gchar	*name;			/* Not Found */
	rtspstat_t	*sp;
} rtsp_response_code_t;

/* used to keep track of the stats for a specific request string */
typedef struct _rtsp_request_methode_t {
	gchar		*response;	/* eg. : SETUP */
	guint32		 packets;
	rtspstat_t	*sp;
} rtsp_request_methode_t;


/* insert some entries */
static void
rtsp_init_hash( rtspstat_t *sp)
{
	int i;

	sp->hash_responses = g_hash_table_new(g_direct_hash, g_direct_equal);

	for (i=0 ; rtsp_status_code_vals[i].strptr ; i++ )
	{
		rtsp_response_code_t *sc = g_new (rtsp_response_code_t, 1);
		sc->packets = 0;
		sc->response_code = rtsp_status_code_vals[i].value;
		sc->name = rtsp_status_code_vals[i].strptr;
		sc->sp = sp;
		g_hash_table_insert( sc->sp->hash_responses, GINT_TO_POINTER(rtsp_status_code_vals[i].value), sc);
	}
	sp->hash_requests = g_hash_table_new( g_str_hash, g_str_equal);
}
static void
rtsp_draw_hash_requests( gchar *key _U_ , rtsp_request_methode_t *data, gchar * format)
{
	if (data->packets == 0)
		return;
	printf( format, data->response, data->packets);
}

static void
rtsp_draw_hash_responses( gpointer* key _U_ , rtsp_response_code_t *data, char * format)
{
	if (data == NULL) {
		ws_warning("No data available, key=%d\n", GPOINTER_TO_INT(key));
		exit(EXIT_FAILURE);
	}
	if (data->packets == 0)
		return;
	/* "     RTSP %3d %-35s %9d packets", */
	printf(format,  data->response_code, data->name, data->packets );
}



/* NOT USED at this moment */
/*
static void
rtsp_free_hash( gpointer key, gpointer value, gpointer user_data _U_ )
{
	g_free(key);
	g_free(value);
}
*/
static void
rtsp_reset_hash_responses(gchar *key _U_ , rtsp_response_code_t *data, gpointer ptr _U_ )
{
	data->packets = 0;
}
static void
rtsp_reset_hash_requests(gchar *key _U_ , rtsp_request_methode_t *data, gpointer ptr _U_ )
{
	data->packets = 0;
}

static void
rtspstat_reset(void *psp  )
{
	rtspstat_t *sp = (rtspstat_t *)psp;

	g_hash_table_foreach( sp->hash_responses, (GHFunc)rtsp_reset_hash_responses, NULL);
	g_hash_table_foreach( sp->hash_requests, (GHFunc)rtsp_reset_hash_requests, NULL);

}

static tap_packet_status
rtspstat_packet(void *psp , packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *pri, tap_flags_t flags _U_)
{
	const rtsp_info_value_t *value = (const rtsp_info_value_t *)pri;
	rtspstat_t *sp = (rtspstat_t *) psp;

	/* We are only interested in reply packets with a status code */
	/* Request or reply packets ? */
	if (value->response_code != 0) {
		rtsp_response_code_t *sc;

		sc =  (rtsp_response_code_t *)g_hash_table_lookup(
				sp->hash_responses,
				GINT_TO_POINTER(value->response_code));
		if (sc == NULL) {
			gint key;
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
			else {
				key = 599;
			}
			sc =  (rtsp_response_code_t *)g_hash_table_lookup(
				sp->hash_responses,
				GINT_TO_POINTER(key));
			if (sc == NULL)
				return TAP_PACKET_DONT_REDRAW;
		}
		sc->packets++;
	}
	else if (value->request_method) {
		rtsp_request_methode_t *sc;

		sc =  (rtsp_request_methode_t *)g_hash_table_lookup(
				sp->hash_requests,
				value->request_method);
		if (sc == NULL) {
			sc = g_new(rtsp_request_methode_t, 1);
			sc->response = g_strdup( value->request_method );
			sc->packets = 1;
			sc->sp = sp;
			g_hash_table_insert( sp->hash_requests, sc->response, sc);
		} else {
			sc->packets++;
		}
	} else {
		return TAP_PACKET_DONT_REDRAW;
	}
	return TAP_PACKET_REDRAW;
}


static void
rtspstat_draw(void *psp  )
{
	rtspstat_t *sp = (rtspstat_t *)psp;
	printf("\n");
	printf("===================================================================\n");
	if (!sp->filter || !sp->filter[0])
		printf("RTSP Statistics\n");
	else
		printf("RTSP Statistics with filter %s\n", sp->filter);

	printf("* RTSP Response Status Codes                Packets\n");
	g_hash_table_foreach( sp->hash_responses, (GHFunc)rtsp_draw_hash_responses,
		(gpointer)"  %3d %-35s %9d\n");
	printf("* RTSP Request Methods                      Packets\n");
	g_hash_table_foreach( sp->hash_requests,  (GHFunc)rtsp_draw_hash_requests,
		(gpointer)"  %-39s %9d\n");
	printf("===================================================================\n");
}



/* When called, this function will create a new instance of rtspstat.
 */
static void
rtspstat_init(const char *opt_arg, void *userdata _U_)
{
	rtspstat_t *sp;
	const char *filter = NULL;
	GString	*error_string;

	if (!strncmp (opt_arg, "rtsp,stat,", 10)) {
		filter = opt_arg+10;
	} else {
		filter = NULL;
	}

	sp = g_new(rtspstat_t, 1);
	sp->filter = g_strdup(filter);
	/*g_hash_table_foreach( rtsp_status, (GHFunc)rtsp_reset_hash_responses, NULL);*/


	error_string = register_tap_listener(
			"rtsp",
			sp,
			filter,
			0,
			rtspstat_reset,
			rtspstat_packet,
			rtspstat_draw,
			NULL);
	if (error_string) {
		/* error, we failed to attach to the tap. clean up */
		g_free(sp->filter);
		g_free(sp);
		cmdarg_err("Couldn't register rtsp,stat tap: %s",
				error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}

	rtsp_init_hash(sp);
}

static stat_tap_ui rtspstat_ui = {
	REGISTER_STAT_GROUP_GENERIC,
	NULL,
	"rtsp,stat",
	rtspstat_init,
	0,
	NULL
};

void
register_tap_listener_rtspstat(void)
{
	register_stat_tap_ui(&rtspstat_ui, NULL);
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
