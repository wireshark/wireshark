/* tap-httpstat.c
 * tap-httpstat   2003 Jean-Michel FAYARD
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#include "epan/packet_info.h"
#include "epan/value_string.h"
#include <epan/tap.h>
#include <epan/stat_cmd_args.h>
#include "register.h"
#include <epan/dissectors/packet-http.h>

	
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


static const value_string vals_status_code[] = {
	{ 100, "Continue" },
	{ 101, "Switching Protocols" },
	{ 199, "Informational - Others" },

	{ 200, "OK"},
	{ 201, "Created"},
	{ 202, "Accepted"},
	{ 203, "Non-authoritative Information"},
	{ 204, "No Content"},
	{ 205, "Reset Content"},
	{ 206, "Partial Content"},
	{ 299, "Success - Others"},	/* used to keep track of others Success packets */

	{ 300, "Multiple Choices"},
	{ 301, "Moved Permanently"},
	{ 302, "Moved Temporarily"},
	{ 303, "See Other"},
        { 304, "Not Modified"},
        { 305, "Use Proxy"},
	{ 399, "Redirection - Others"},

        { 400, "Bad Request"},
        { 401, "Unauthorized"},
        { 402, "Payment Required"},
        { 403, "Forbidden"},
        { 404, "Not Found"},
        { 405, "Method Not Allowed"},
        { 406, "Not Acceptable"},
        { 407, "Proxy Authentication Required"},
        { 408, "Request Time-out"},
        { 409, "Conflict"},
        { 410, "Gone"},
        { 411, "Length Required"},
        { 412, "Precondition Failed"},
        { 413, "Request Entity Too Large"},
        { 414, "Request-URI Too Large"},
        { 415, "Unsupported Media Type"},
	{ 499, "Client Error - Others"},
	
        { 500, "Internal Server Error"},
        { 501, "Not Implemented"},
        { 502, "Bad Gateway"},
        { 503, "Service Unavailable"},
        { 504, "Gateway Time-out"},
        { 505, "HTTP Version not supported"},
	{ 599, "Server Error - Others"},

	{ 0, 	NULL}
} ;

/* insert some entries */
static void
http_init_hash( httpstat_t *sp)
{
	int i;

	sp->hash_responses = g_hash_table_new( g_int_hash, g_int_equal);		
			
	for (i=0 ; vals_status_code[i].strptr ; i++ )
	{
		gint *key = g_malloc (sizeof(gint));
		http_response_code_t *sc = g_malloc (sizeof(http_response_code_t));
		*key = vals_status_code[i].value;
		sc->packets=0;
		sc->response_code =  *key;
		sc->name=vals_status_code[i].strptr;
		sc->sp = sp;
		g_hash_table_insert( sc->sp->hash_responses, key, sc);
	}
	sp->hash_requests = g_hash_table_new( g_str_hash, g_str_equal);
}
static void
http_draw_hash_requests( gchar *key _U_ , http_request_methode_t *data, gchar * format)
{
	if (data->packets==0)
		return;
	printf( format, data->response, data->packets); 		
}

static void
http_draw_hash_responses( gint * key _U_ , http_response_code_t *data, char * format)
{
	if (data==NULL) {
		g_warning("No data available, key=%d\n", *key);
		exit(EXIT_FAILURE);
	}
	if (data->packets==0)
		return;
	/* "     HTTP %3d %-35s %9d packets", */
	printf(format,  data->response_code, data->name, data->packets );
}
		

		
/* NOT USED at this moment */
/*
static void
http_free_hash( gpointer key, gpointer value, gpointer user_data _U_ )
{
	g_free(key);
	g_free(value);
}
*/
static void
http_reset_hash_responses(gchar *key _U_ , http_response_code_t *data, gpointer ptr _U_ ) 
{	
	data->packets = 0;
}
static void
http_reset_hash_requests(gchar *key _U_ , http_request_methode_t *data, gpointer ptr _U_ ) 
{	
	data->packets = 0;
}

static void
httpstat_reset(void *psp  )
{
	httpstat_t *sp=psp;

	g_hash_table_foreach( sp->hash_responses, (GHFunc)http_reset_hash_responses, NULL);
	g_hash_table_foreach( sp->hash_requests, (GHFunc)http_reset_hash_requests, NULL);

}

static int
httpstat_packet(void *psp , packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *pri)
{
	const http_info_value_t *value=pri;
	httpstat_t *sp=(httpstat_t *) psp;

	/* We are only interested in reply packets with a status code */
	/* Request or reply packets ? */
	if (value->response_code!=0) {
		guint *key=g_malloc( sizeof(guint) );
		http_response_code_t *sc;
		
		*key=value->response_code;
		sc =  g_hash_table_lookup( 
				sp->hash_responses, 
				key);
		if (sc==NULL){
			/* non standard status code ; we classify it as others
			 * in the relevant category (Informational,Success,Redirection,Client Error,Server Error)
			 */
			int i = value->response_code;
			if ((i<100) || (i>=600)) {
				return 0;
			}
			else if (i<200){
				*key=199;	/* Hopefully, this status code will never be used */
			}
			else if (i<300){
				*key=299;
			}
			else if (i<400){
				*key=399;
			}
			else if (i<500){
				*key=499;
			}
			else{
				*key=599;
			}
			sc =  g_hash_table_lookup( 
				sp->hash_responses, 
				key);
			if (sc==NULL)
				return 0;
		}
		sc->packets++;
	} 
	else if (value->request_method){
		http_request_methode_t *sc;

		sc =  g_hash_table_lookup( 
				sp->hash_requests, 
				value->request_method);
		if (sc==NULL){
			sc=g_malloc( sizeof(http_request_methode_t) );
			sc->response=g_strdup( value->request_method );
			sc->packets=1;
			sc->sp = sp;
			g_hash_table_insert( sp->hash_requests, sc->response, sc);
		} else {
			sc->packets++;
		}
	} else {
		return 0;
	}
	return 1;
}


static void
httpstat_draw(void *psp  )
{
	httpstat_t *sp=psp;
	printf("\n");
	printf("===================================================================\n");
	if (! sp->filter[0])
		printf("HTTP Statistics\n");
	else
		printf("HTTP Statistics with filter %s\n", sp->filter);

	printf(	"* HTTP Status Codes in reply packets\n");
	g_hash_table_foreach( sp->hash_responses, (GHFunc)http_draw_hash_responses, 
		"    HTTP %3d %s\n");
	printf("* List of HTTP Request methods\n");
	g_hash_table_foreach( sp->hash_requests,  (GHFunc)http_draw_hash_requests, 
		"    %9s %d \n");
	printf("===================================================================\n");
}



/* When called, this function will create a new instance of gtk_httpstat.
 */
static void
gtk_httpstat_init(const char *optarg,void* userdata _U_)
{
	httpstat_t *sp;
	const char *filter=NULL;
	GString	*error_string;
	
	if (!strncmp (optarg, "http,stat,", 10)){
		filter=optarg+10;
	} else {
		filter=NULL;
	}
	
	sp = g_malloc( sizeof(httpstat_t) );
	if(filter){
		sp->filter=g_malloc(strlen(filter)+1);
		strcpy(sp->filter,filter);
	} else {
		sp->filter=NULL;
	}
	/*g_hash_table_foreach( http_status, (GHFunc)http_reset_hash_responses, NULL);*/


	error_string = register_tap_listener( 
			"http",
			sp,
			filter,
			httpstat_reset,
			httpstat_packet,
			httpstat_draw);
	if (error_string){
		/* error, we failed to attach to the tap. clean up */
		g_free(sp->filter);
		g_free(sp);
		fprintf (stderr, "tshark: Couldn't register http,stat tap: %s\n",
				error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}

	http_init_hash(sp);
}

void
register_tap_listener_gtkhttpstat(void)
{
	register_stat_cmd_arg("http,stat,", gtk_httpstat_init,NULL);
}
