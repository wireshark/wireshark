/* tap-wspstat.c
 * wspstat   2003 Jean-Michel FAYARD
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* This module provides WSP  statistics to tshark.
 * It is only used by tshark and not wireshark
 *
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet_info.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/value_string.h>
#include <epan/dissectors/packet-wsp.h>

#include <ui/cmdarg_err.h>

void register_tap_listener_wspstat(void);

/* used to keep track of the stats for a specific PDU type*/
typedef struct _wsp_pdu_t {
	const gchar 	*type;
	guint32		 packets;
} wsp_pdu_t;
/* used to keep track of SRT statistics */
typedef struct _wsp_status_code_t {
	const gchar	*name;
	guint32		 packets;
} wsp_status_code_t;
/* used to keep track of the statictics for an entire program interface */
typedef struct _wsp_stats_t {
	char 		*filter;
	wsp_pdu_t 	*pdu_stats;
	guint32	num_pdus;
	GHashTable	*hash;
} wspstat_t;

static void
wsp_reset_hash(gchar *key _U_ , wsp_status_code_t *data, gpointer ptr _U_)
{
	data->packets = 0;
}
static void
wsp_print_statuscode(gpointer key, wsp_status_code_t *data, char *format)
{
	if (data && (data->packets != 0))
		printf(format, GPOINTER_TO_INT(key), data->packets , data->name);
}
static void
wsp_free_hash_table( gpointer key, gpointer value, gpointer user_data _U_ )
{
	g_free(key);
	g_free(value);
}
static void
wspstat_reset(void *psp)
{
	wspstat_t *sp = (wspstat_t *)psp;
	guint32 i;

	for (i=1; i<=sp->num_pdus; i++)
	{
		sp->pdu_stats[i].packets = 0;
	}
	g_hash_table_foreach( sp->hash, (GHFunc)wsp_reset_hash, NULL);
}


/* This callback is invoked whenever the tap system has seen a packet
 * we might be interested in.
 * The function is to be used to only update internal state information
 * in the *tapdata structure, and if there were state changes which requires
 * the window to be redrawn, return 1 and (*draw) will be called sometime
 * later.
 *
 * We didn't apply a filter when we registered so we will be called for
 * ALL packets and not just the ones we are collecting stats for.
 *
 */
static gint
pdut2index(gint pdut)
{
	if (pdut <= 0x09)
		return pdut;
	if (pdut >= 0x40) {
		if (pdut <= 0x44) {
			return pdut - 54;
		} else if (pdut == 0x60 || pdut == 0x61) {
			return pdut - 81;
		}
	}
	return 0;
}
static gint
index2pdut(gint pdut)
{
	if (pdut <= 0x09)
		return pdut;
	if (pdut <= 14)
		return pdut + 54;
	if (pdut <= 16)
		return pdut + 81;
	return 0;
}
static tap_packet_status
wspstat_packet(void *psp, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *pri, tap_flags_t flags _U_)
{
	wspstat_t *sp = (wspstat_t *)psp;
	const wsp_info_value_t *value = (const wsp_info_value_t *)pri;
	gint idx = pdut2index(value->pdut);
	tap_packet_status retour = TAP_PACKET_DONT_REDRAW;

	if (value->status_code != 0) {
		wsp_status_code_t *sc;
		sc = (wsp_status_code_t *)g_hash_table_lookup(
				sp->hash,
				GINT_TO_POINTER(value->status_code));
		if (!sc) {
			sc = g_new(wsp_status_code_t, 1);
			sc -> packets = 1;
			sc -> name = NULL;
			g_hash_table_insert(
				sp->hash,
				GINT_TO_POINTER(value->status_code),
				sc);
		} else {
			sc->packets++;
		}
		retour = TAP_PACKET_REDRAW;
	}



	if (idx != 0) {
		sp->pdu_stats[idx].packets++;
		retour = TAP_PACKET_REDRAW;
	}
	return retour;
}


/* This callback is used when tshark wants us to draw/update our
 * data to the output device. Since this is tshark only output is
 * stdout.
 * TShark will only call this callback once, which is when tshark has
 * finished reading all packets and exists.
 * If used with wireshark this may be called any time, perhaps once every 3
 * seconds or so.
 * This function may even be called in parallell with (*reset) or (*draw)
 * so make sure there are no races. The data in the rpcstat_t can thus change
 * beneath us. Beware.
 */
static void
wspstat_draw(void *psp)
{
	wspstat_t *sp = (wspstat_t *)psp;
	guint32 i;

	printf("\n");
	printf("===================================================================\n");
	printf("WSP Statistics:\n");
	printf("%-23s %9s || %-23s %9s\n", "PDU Type", "Packets", "PDU Type", "Packets");
	for (i=1; i <= ((sp->num_pdus+1)/2); i++)
	{
		guint32 ii = i+sp->num_pdus/2;
		printf("%-23s %9u", sp->pdu_stats[i ].type, sp->pdu_stats[i ].packets);
		printf(" || ");
		if (ii< (sp->num_pdus) )
			printf("%-23s %9u\n", sp->pdu_stats[ii].type, sp->pdu_stats[ii].packets);
		else
			printf("\n");
		}
	printf("\nStatus code in reply packets\n");
	printf(		"Status Code    Packets  Description\n");
	g_hash_table_foreach( sp->hash, (GHFunc) wsp_print_statuscode,
			(gpointer)"       0x%02X  %9d  %s\n" ) ;
	printf("===================================================================\n");
}

/* When called, this function will create a new instance of wspstat.
 * program and version are whick onc-rpc program/version we want to
 * collect statistics for.
 * This function is called from tshark when it parses the -z wsp, arguments
 * and it creates a new instance to store statistics in and registers this
 * new instance for the wsp tap.
 */
static void
wspstat_init(const char *opt_arg, void *userdata _U_)
{
	wspstat_t          *sp;
	const char         *filter = NULL;
	guint32             i;
	GString	           *error_string;
	wsp_status_code_t  *sc;
	const value_string *wsp_vals_status_p;

	if (!strncmp (opt_arg, "wsp,stat,", 9)) {
		filter = opt_arg+9;
	} else {
		filter = NULL;
	}


	sp = g_new(wspstat_t, 1);
	sp->hash = g_hash_table_new(g_direct_hash, g_direct_equal);
	wsp_vals_status_p = VALUE_STRING_EXT_VS_P(&wsp_vals_status_ext);
	for (i=0; wsp_vals_status_p[i].strptr; i++ )
	{
		gint *key;
		sc = g_new(wsp_status_code_t, 1);
		key = g_new(gint, 1);
		sc->packets = 0;
		sc->name = wsp_vals_status_p[i].strptr;
		*key = wsp_vals_status_p[i].value;
		g_hash_table_insert(
				sp->hash,
				key,
				sc);
	}
	sp->num_pdus = 16;
	sp->pdu_stats = g_new(wsp_pdu_t, (sp->num_pdus+1));
	sp->filter = g_strdup(filter);

	for (i=0; i<sp->num_pdus; i++)
	{
		sp->pdu_stats[i].packets = 0;
		sp->pdu_stats[i].type = try_val_to_str_ext( index2pdut( i ), &wsp_vals_pdu_type_ext) ;
	}

	error_string = register_tap_listener(
			"wsp",
			sp,
			filter,
			0,
			wspstat_reset,
			wspstat_packet,
			wspstat_draw,
			NULL);
	if (error_string) {
		/* error, we failed to attach to the tap. clean up */
		g_free(sp->pdu_stats);
		g_free(sp->filter);
		g_hash_table_foreach( sp->hash, (GHFunc) wsp_free_hash_table, NULL ) ;
		g_hash_table_destroy( sp->hash );
		g_free(sp);
		cmdarg_err("Couldn't register wsp,stat tap: %s",
				error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}

static stat_tap_ui wspstat_ui = {
	REGISTER_STAT_GROUP_GENERIC,
	NULL,
	"wsp,stat",
	wspstat_init,
	0,
	NULL
};

void
register_tap_listener_wspstat(void)
{
	register_stat_tap_ui(&wspstat_ui, NULL);
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
