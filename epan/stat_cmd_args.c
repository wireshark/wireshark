/* stat_cmd_args.c
 * Routines to register "-z" command-line argument handlers for stats
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include <glib.h>

#include <epan/stat_cmd_args.h>

/* structure to keep track of what stats have registered command-line
   arguments.
 */
typedef struct _stat_cmd_arg {
	struct _stat_cmd_arg *next;
	const char *cmd;
	void (*func)(const char *arg);
} stat_cmd_arg;
static stat_cmd_arg *stat_cmd_arg_list=NULL;

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
void
register_stat_cmd_arg(const char *cmd, void (*func)(const char *arg))
{
	stat_cmd_arg *newsca;

	newsca=g_malloc(sizeof(stat_cmd_arg));
	newsca->next=stat_cmd_arg_list;
	stat_cmd_arg_list=newsca;
	newsca->cmd=cmd;
	newsca->func=func;
}

/* **********************************************************************
 * Function called for a stat command-line argument
 * ********************************************************************** */
gboolean
process_stat_cmd_arg(char *optarg)
{
	stat_cmd_arg *sca;
	stat_requested *tr;

	for(sca=stat_cmd_arg_list;sca;sca=sca->next){
		if(!strncmp(sca->cmd,optarg,strlen(sca->cmd))){
			tr=g_malloc(sizeof (stat_requested));
			tr->sca = sca;
			tr->arg=g_strdup(optarg);
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
	stat_cmd_arg *sca;

	for(sca=stat_cmd_arg_list;sca;sca=sca->next){
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
		(*sr->sca->func)(sr->arg);
		g_free(sr->arg);
		g_free(sr);
		stats_requested=g_slist_remove(stats_requested, sr);
	}
}
