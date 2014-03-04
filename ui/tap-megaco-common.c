/* megaco_stat.c
 * megaco-statistics for Wireshark
 * Copyright 2003 Lars Roland
 * Copyright 2008 Ericsson AB
 * By Balint Reczey <balint.reczey@ericsson.com>
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

#include <string.h>

#include <epan/packet_info.h>
#include <epan/epan.h>
#include <epan/value_string.h>
#include <epan/tap.h>
#include "epan/gcp.h"

#include "epan/timestats.h"
#include "file.h"
#include "globals.h"
#include "stat_menu.h"

#include "tap-megaco-common.h"

static gboolean
megacostat_is_duplicate_reply(const gcp_cmd_t* cmd)
{
	switch (cmd->type) {

        GCP_CMD_REPLY_CASE
		{
			gcp_cmd_msg_t *cmd_msg;
			/* cycle through commands to find same command in the transaction */
			for (cmd_msg = cmd->trx->cmds;
			     (cmd_msg != NULL) && (cmd_msg->cmd->msg->framenum != cmd->msg->framenum);
			     cmd_msg = cmd_msg->next) {
				if (cmd_msg->cmd->type == cmd->type)
					return TRUE;
			}

			return FALSE;
		}
		break;
	default:
		return FALSE;
		break;
	}


}

static gboolean
megacostat_had_request(const gcp_cmd_t* cmd)
{
	switch (cmd->type) {

        GCP_CMD_REPLY_CASE
		{
			gcp_cmd_msg_t *cmd_msg;
			/* cycle through commands to find a request in the transaction */
			for (cmd_msg = cmd->trx->cmds;
			     (cmd_msg != NULL) && (cmd_msg->cmd->msg->framenum != cmd->msg->framenum);
			     cmd_msg = cmd_msg->next) {

				switch (cmd_msg->cmd->type) {

        			GCP_CMD_REQ_CASE
					return TRUE;
					break;
				default:
					return FALSE;
					break;
				}
			}

			return FALSE;
		}
		break;
	default:
		return FALSE;
		break;
	}
}

int
megacostat_packet(void *pms, packet_info *pinfo, epan_dissect_t *edt _U_, const void *pmi)
{
	megacostat_t *ms=(megacostat_t *)pms;
	const gcp_cmd_t *mi=(const gcp_cmd_t*)pmi;
	nstime_t delta;
	int ret = 0;

	switch (mi->type) {

        GCP_CMD_REQ_CASE
		if(!mi->trx->initial) {
			/* Track Context is probably disabled, we cannot
			 * measure service response time */
			return 0;
		}

		else if(mi->trx->initial->framenum != mi->msg->framenum){
			/* Duplicate is ignored */
			ms->req_dup_num++;
		}
		else {
			ms->open_req_num++;
		}
		break;

        GCP_CMD_REPLY_CASE
		if(megacostat_is_duplicate_reply(mi)){
			/* Duplicate is ignored */
			ms->rsp_dup_num++;
		}
		else if (!megacostat_had_request(mi)) {
			/* no request was seen */
			ms->disc_rsp_num++;
		}
		else {
			ms->open_req_num--;
			/* calculate time delta between request and response */
			nstime_delta(&delta, &pinfo->fd->abs_ts, &mi->trx->initial->time);

			switch(mi->type) {

			case GCP_CMD_ADD_REPLY:
				time_stat_update(&(ms->rtd[0]),&delta, pinfo);
				break;
			case GCP_CMD_MOVE_REPLY:
				time_stat_update(&(ms->rtd[1]),&delta, pinfo);
				break;
			case GCP_CMD_MOD_REPLY:
				time_stat_update(&(ms->rtd[2]),&delta, pinfo);
				break;
			case GCP_CMD_SUB_REPLY:
				time_stat_update(&(ms->rtd[3]),&delta, pinfo);
				break;
			case GCP_CMD_AUDITCAP_REPLY:
				time_stat_update(&(ms->rtd[4]),&delta, pinfo);
				break;
			case GCP_CMD_AUDITVAL_REPLY:
				time_stat_update(&(ms->rtd[5]),&delta, pinfo);
				break;
			case GCP_CMD_NOTIFY_REPLY:
				time_stat_update(&(ms->rtd[6]),&delta, pinfo);
				break;
			case GCP_CMD_SVCCHG_REPLY:
				time_stat_update(&(ms->rtd[7]),&delta, pinfo);
				break;
			case GCP_CMD_TOPOLOGY_REPLY:
				time_stat_update(&(ms->rtd[8]),&delta, pinfo);
				break;
			case GCP_CMD_REPLY:
				time_stat_update(&(ms->rtd[9]),&delta, pinfo);
				break;
			default:
				time_stat_update(&(ms->rtd[11]),&delta, pinfo);
			}
			time_stat_update(&(ms->rtd[10]),&delta, pinfo);

			ret = 1;
		}
		break;

	default:
		break;
	}

	return ret;
}

