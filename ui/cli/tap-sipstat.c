/* tap_sipstat.c
 * sip message counter for wireshark
 *
 * Copied from ui/gtk/sip_stat.c and tap-httpstat.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "epan/packet_info.h"
#include <epan/tap.h>
#include <epan/stat_cmd_args.h>
#include "epan/value_string.h"
#include <epan/dissectors/packet-sip.h>

void register_tap_listener_sipstat(void);

/* used to keep track of the statictics for an entire program interface */
typedef struct _sip_stats_t {
	char		*filter;
	guint32		packets;        /* number of sip packets, including continuations */
	guint32		resent_packets;
	guint32		average_setup_time;
	guint32		max_setup_time;
	guint32		min_setup_time;
	guint32		no_of_completed_calls;
	guint64		total_setup_time;
	GHashTable	*hash_responses;
	GHashTable	*hash_requests;
} sipstat_t;

/* used to keep track of the stats for a specific response code
 * for example it can be { 3, 404, "Not Found" ,...}
 * which means we captured 3 reply sip/1.1 404 Not Found */
typedef struct _sip_response_code_t {
	guint32	 packets;		/* 3 */
	guint		 response_code;		/* 404 */
	const gchar	*name;			/* Not Found */
	sipstat_t	*sp;
} sip_response_code_t;

/* used to keep track of the stats for a specific request string */
typedef struct _sip_request_method_t {
	gchar		*response;	/* eg. : INVITE */
	guint32		 packets;
	sipstat_t	*sp;
} sip_request_method_t;

/* TODO: extra codes to be added from SIP extensions? */
static const value_string vals_status_code[] = {
    { 100, "Trying"},
    { 180, "Ringing"},
    { 181, "Call Is Being Forwarded"},
    { 182, "Queued"},
    { 183, "Session Progress"},
    { 199, "Informational - Others" },

    { 200, "OK"},
    { 202, "Accepted"},
    { 204, "No Notification"},
    { 299, "Success - Others"},	/* used to keep track of other Success packets */

    { 300, "Multiple Choices"},
    { 301, "Moved Permanently"},
    { 302, "Moved Temporarily"},
    { 305, "Use Proxy"},
    { 380, "Alternative Service"},
    { 399, "Redirection - Others"},

    { 400, "Bad Request"},
    { 401, "Unauthorized"},
    { 402, "Payment Required"},
    { 403, "Forbidden"},
    { 404, "Not Found"},
    { 405, "Method Not Allowed"},
    { 406, "Not Acceptable"},
    { 407, "Proxy Authentication Required"},
    { 408, "Request Timeout"},
    { 410, "Gone"},
    { 412, "Conditional Request Failed"},
    { 413, "Request Entity Too Large"},
    { 414, "Request-URI Too Long"},
    { 415, "Unsupported Media Type"},
    { 416, "Unsupported URI Scheme"},
    { 420, "Bad Extension"},
    { 421, "Extension Required"},
    { 422, "Session Timer Too Small"},
    { 423, "Interval Too Brief"},
    { 428, "Use Identity Header"},
    { 429, "Provide Referrer Identity"},
    { 430, "Flow Failed"},
    { 433, "Anonymity Disallowed"},
    { 436, "Bad Identity-Info"},
    { 437, "Unsupported Certificate"},
    { 438, "Invalid Identity Header"},
    { 439, "First Hop Lacks Outbound Support"},
    { 440, "Max-Breadth Exceeded"},
    { 470, "Consent Needed"},
    { 480, "Temporarily Unavailable"},
    { 481, "Call/Transaction Does Not Exist"},
    { 482, "Loop Detected"},
    { 483, "Too Many Hops"},
    { 484, "Address Incomplete"},
    { 485, "Ambiguous"},
    { 486, "Busy Here"},
    { 487, "Request Terminated"},
    { 488, "Not Acceptable Here"},
    { 489, "Bad Event"},
    { 491, "Request Pending"},
    { 493, "Undecipherable"},
    { 494, "Security Agreement Required"},
    { 499, "Client Error - Others"},

    { 500, "Server Internal Error"},
    { 501, "Not Implemented"},
    { 502, "Bad Gateway"},
    { 503, "Service Unavailable"},
    { 504, "Server Time-out"},
    { 505, "Version Not Supported"},
    { 513, "Message Too Large"},
    { 599, "Server Error - Others"},

    { 600, "Busy Everywhere"},
    { 603, "Decline"},
    { 604, "Does Not Exist Anywhere"},
    { 606, "Not Acceptable"},
    { 699, "Global Failure - Others"},

    { 0,	NULL}
};

/* Create tables for responses and requests */
static void
sip_init_hash(sipstat_t *sp)
{
    int i;

    /* Create responses table */
    sp->hash_responses = g_hash_table_new(g_int_hash, g_int_equal);

    /* Add all response codes */
    for (i=0 ; vals_status_code[i].strptr ; i++)
    {
        gint *key = g_new (gint,1);
        sip_response_code_t *sc = g_new (sip_response_code_t,1);
        *key = vals_status_code[i].value;
        sc->packets=0;
        sc->response_code =  *key;
        sc->name=vals_status_code[i].strptr;
        sc->sp = sp;
        g_hash_table_insert(sc->sp->hash_responses, key, sc);
    }

    /* Create empty requests table */
    sp->hash_requests = g_hash_table_new(g_str_hash, g_str_equal);
}

static void
sip_draw_hash_requests( gchar *key _U_ , sip_request_method_t *data, gchar * format)
{
	if (data->packets==0)
		return;
	printf( format, data->response, data->packets);
}

static void
sip_draw_hash_responses( gint * key _U_ , sip_response_code_t *data, char * format)
{
	if (data==NULL) {
		g_warning("C'est quoi ce borderl key=%d\n", *key);
		exit(EXIT_FAILURE);
	}
	if (data->packets==0)
		return;
	printf(format,  data->response_code, data->name, data->packets );
}

/* NOT USED at this moment */
/*
static void
sip_free_hash( gpointer key, gpointer value, gpointer user_data _U_ )
{
	g_free(key);
	g_free(value);
}
*/

static void
sip_reset_hash_responses(gchar *key _U_ , sip_response_code_t *data, gpointer ptr _U_ )
{
	data->packets = 0;
}
static void
sip_reset_hash_requests(gchar *key _U_ , sip_request_method_t *data, gpointer ptr _U_ )
{
	data->packets = 0;
}

static void
sipstat_reset(void *psp  )
{
	sipstat_t *sp=(sipstat_t *)psp;
	if (sp) {
		sp->packets = 0;
		sp->resent_packets = 0;
		sp->average_setup_time = 0;
		sp->max_setup_time = 0;
		sp->min_setup_time = 0;
		sp->no_of_completed_calls = 0;
		sp->total_setup_time = 0;

		g_hash_table_foreach( sp->hash_responses, (GHFunc)sip_reset_hash_responses, NULL);
		g_hash_table_foreach( sp->hash_requests, (GHFunc)sip_reset_hash_requests, NULL);
	}
}


/* Main entry point to SIP tap */
static int
sipstat_packet(void *psp, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *pri)
{
    const sip_info_value_t *value=(const sip_info_value_t *)pri;
    sipstat_t *sp = (sipstat_t *)psp;

    /* Total number of packets, including continuation packets */
    sp->packets++;

	/* Calculate average setup time */
	if (value->setup_time){
		sp->no_of_completed_calls++;
		/* Check if it's the first value */
		if ( sp->total_setup_time == 0 ){
			sp->average_setup_time = value->setup_time;
			sp->total_setup_time = value->setup_time;
			sp->max_setup_time = value->setup_time;
			sp->min_setup_time = value->setup_time;
		}else{
			sp->total_setup_time = sp->total_setup_time + value->setup_time;
			if (sp->max_setup_time < value->setup_time){
				sp->max_setup_time = value->setup_time;
			}
			if (sp->min_setup_time > value->setup_time){
				sp->min_setup_time = value->setup_time;
			}
			/* Calculate average */
			sp->average_setup_time = (guint32)(sp->total_setup_time / sp->no_of_completed_calls);
		}
	}

    /* Update resent count if flag set */
    if (value->resend)
    {
        sp->resent_packets++;
    }


    /* Looking at both requests and responses */
    if (value->response_code != 0)
    {
        /* Responses */
        guint *key = g_new(guint,1);
        sip_response_code_t *sc;

        /* Look up response code in hash table */
        *key = value->response_code;
        sc = (sip_response_code_t *)g_hash_table_lookup(sp->hash_responses, key);
        if (sc==NULL)
        {
            /* Non-standard status code ; we classify it as others
             * in the relevant category
             * (Informational,Success,Redirection,Client Error,Server Error,Global Failure)
             */
            int i = value->response_code;
            if ((i<100) || (i>=700))
            {
                /* Forget about crazy values */
                return 0;
            }
            else if (i<200)
            {
                *key=199;	/* Hopefully, this status code will never be used */
            }
            else if (i<300)
            {
                *key=299;
            }
            else if (i<400)
            {
                *key=399;
            }
            else if (i<500)
            {
                *key=499;
            }
            else if (i<600)
            {
                *key=599;
            }
            else
            {
                *key = 699;
            }

            /* Now look up this fallback code to get its text description */
            sc = (sip_response_code_t *)g_hash_table_lookup(sp->hash_responses, key);
            if (sc==NULL)
            {
                return 0;
            }
        }
        sc->packets++;
    }
    else if (value->request_method)
    {
        /* Requests */
        sip_request_method_t *sc;

        /* Look up the request method in the table */
        sc = (sip_request_method_t *)g_hash_table_lookup(sp->hash_requests, value->request_method);
        if (sc == NULL)
        {
            /* First of this type. Create structure and initialise */
            sc=g_new(sip_request_method_t,1);
            sc->response = g_strdup(value->request_method);
            sc->packets = 1;
            sc->sp = sp;
            /* Insert it into request table */
            g_hash_table_insert(sp->hash_requests, sc->response, sc);
        }
        else
        {
            /* Already existed, just update count for that method */
            sc->packets++;
        }
        /* g_free(value->request_method); */
    }
    else
    {
        /* No request method set. Just ignore */
        return 0;
    }

    return 1;
}

static void
sipstat_draw(void *psp  )
{
	sipstat_t *sp=(sipstat_t *)psp;
	printf("\n");
	printf("===================================================================\n");
	if (sp->filter == NULL)
		printf("SIP Statistics\n");
	else
		printf("SIP Statistics with filter %s\n", sp->filter);

	printf("\nNumber of SIP messages: %d", sp->packets);
	printf("\nNumber of resent SIP messages: %d\n", sp->resent_packets);
	printf(	"\n* SIP Status Codes in reply packets\n");
	g_hash_table_foreach( sp->hash_responses, (GHFunc)sip_draw_hash_responses,
		(gpointer)"  SIP %3d %-15s : %5d Packets\n");
	printf("\n* List of SIP Request methods\n");
	g_hash_table_foreach( sp->hash_requests,  (GHFunc)sip_draw_hash_requests,
		(gpointer)"  %-15s : %5d Packets\n");
	printf(	"\n* Average setup time %d ms\n Min %d ms\n Max %d ms\n", sp->average_setup_time, sp->min_setup_time, sp->max_setup_time);
	printf("===================================================================\n");
}

static void
sipstat_init(const char *opt_arg, void* userdata _U_)
{
	sipstat_t *sp;
	const char *filter=NULL;
	GString	*error_string;

	if (strncmp (opt_arg, "sip,stat,", 9) == 0){
		filter=opt_arg+9;
	} else {
		filter=NULL;
	}

	sp = g_new0(sipstat_t,1);
	if(filter){
		sp->filter=g_strdup(filter);
	} else {
		sp->filter=NULL;
	}
	/*g_hash_table_foreach( sip_status, (GHFunc)sip_reset_hash_responses, NULL);*/


	error_string = register_tap_listener(
			"sip",
			sp,
			filter,
			0,
			sipstat_reset,
			sipstat_packet,
			sipstat_draw);
	if (error_string){
		/* error, we failed to attach to the tap. clean up */
		g_free(sp->filter);
		g_free(sp);
		fprintf (stderr, "tshark: Couldn't register sip,stat tap: %s\n",
				error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}

	sp->packets = 0;
	sp->resent_packets = 0;
	sip_init_hash(sp);
}

void
register_tap_listener_sipstat(void)
{
	register_stat_cmd_arg("sip,stat", sipstat_init,NULL);
}
