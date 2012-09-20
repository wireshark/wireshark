/* stat_cmd_args.c
 * Routines to register "-z" command-line argument handlers for stats
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdio.h>

#include <string.h>

#include <glib.h>

#include <epan/stat_cmd_args.h>

/* structure to keep track of what stats have registered command-line
   arguments.
 */
typedef struct _stat_cmd_arg {
	const char *cmd;
	void (*func)(const char *arg, void* userdata);
    void* userdata;
} stat_cmd_arg;

static GSList *stat_cmd_arg_list=NULL;

/* structure to keep track of what stats have been specified on the
   command line.
 */
typedef struct {
	stat_cmd_arg *sca;
	char *arg;
} stat_requested;
static GSList *stats_requested = NULL;

/* **********************************************************************
 * Function called from stat to register the stat's command-line argument
 * and initialization routine
 * ********************************************************************** */
static gint
sort_by_name(gconstpointer a, gconstpointer b)
{
	return strcmp(((const stat_cmd_arg *)a)->cmd,
	    ((const stat_cmd_arg *)b)->cmd);
}
void
register_stat_cmd_arg(const char *cmd, void (*func)(const char*, void*),void* userdata)
{
	stat_cmd_arg *newsca;

	newsca=g_malloc(sizeof(stat_cmd_arg));
	newsca->cmd=cmd;
	newsca->func=func;
	newsca->userdata=userdata;
	stat_cmd_arg_list=g_slist_insert_sorted(stat_cmd_arg_list, newsca,
	    sort_by_name);
}

/* **********************************************************************
 * Function called for a stat command-line argument
 * ********************************************************************** */
gboolean
process_stat_cmd_arg(char *optstr)
{
	GSList *entry;
	stat_cmd_arg *sca;
	stat_requested *tr;

	for(entry=stat_cmd_arg_list;entry;entry=g_slist_next(entry)){
		sca=entry->data;
		if(!strncmp(sca->cmd,optstr,strlen(sca->cmd))){
			tr=g_malloc(sizeof (stat_requested));
			tr->sca = sca;
			tr->arg=g_strdup(optstr);
			stats_requested=g_slist_append(stats_requested, tr);
			return TRUE;
		}
	}
	return FALSE;
}

/* **********************************************************************
 * Function to list all possible tap command-line arguments
 * ********************************************************************** */
void
list_stat_cmd_args(void)
{
	GSList *entry;
	stat_cmd_arg *sca;

	for(entry=stat_cmd_arg_list;entry;entry=g_slist_next(entry)){
		sca=entry->data;
		fprintf(stderr,"     %s\n",sca->cmd);
	}
}

/* **********************************************************************
 * Function to process stats requested with command-line arguments
 * ********************************************************************** */
void
start_requested_stats(void)
{
	stat_requested *sr;

	while(stats_requested){
		sr=stats_requested->data;
		(*sr->sca->func)(sr->arg,sr->sca->userdata);
		g_free(sr->arg);
		g_free(sr);
		stats_requested=g_slist_remove(stats_requested, sr);
	}
}
