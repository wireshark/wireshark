/* tap-rtd.c
 *
 * Based on tap-srt.c
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
#include <epan/packet.h>
#include <epan/rtd_table.h>
#include <epan/timestamp.h>
#include <epan/stat_tap_ui.h>
#include <ui/cli/tshark-tap.h>

typedef struct _rtd_t {
	const char *type;
	const char *filter;
	const value_string* vs_type;
	rtd_data_t rtd;
} rtd_t;

static void
rtd_draw(void *arg)
{
	rtd_data_t* rtd_data = (rtd_data_t*)arg;
	rtd_t* rtd = (rtd_t*)rtd_data->user_data;
	gchar* tmp_str;
	guint i, j;

	/* printing results */
	printf("\n");
	printf("=====================================================================================================\n");
	printf("%s Response Time Delay (RTD) Statistics:\n", rtd->type);
	printf("Filter for statistics: %s\n", rtd->filter ? rtd->filter : "");
	if (rtd_data->stat_table.num_rtds == 1)
	{
		printf("Duplicate requests: %u\n", rtd_data->stat_table.time_stats[0].req_dup_num);
		printf("Duplicate responses: %u\n", rtd_data->stat_table.time_stats[0].rsp_dup_num);
		printf("Open requests: %u\n", rtd_data->stat_table.time_stats[0].open_req_num);
		printf("Discarded responses: %u\n", rtd_data->stat_table.time_stats[0].disc_rsp_num);
		printf("Type    | Messages   |    Min RTD    |    Max RTD    |    Avg RTD    | Min in Frame | Max in Frame |\n");
		for (i=0; i<rtd_data->stat_table.time_stats[0].num_timestat; i++) {
			if (rtd_data->stat_table.time_stats[0].rtd[i].num) {
				tmp_str = val_to_str_wmem(NULL, i, rtd->vs_type, "Other (%d)");
				printf("%s | %7u    | %8.2f msec | %8.2f msec | %8.2f msec |  %10u  |  %10u  |\n",
						tmp_str, rtd_data->stat_table.time_stats[0].rtd[i].num,
						nstime_to_msec(&(rtd_data->stat_table.time_stats[0].rtd[i].min)), nstime_to_msec(&(rtd_data->stat_table.time_stats[0].rtd[i].max)),
						get_average(&(rtd_data->stat_table.time_stats[0].rtd[i].tot), rtd_data->stat_table.time_stats[0].rtd[i].num),
						rtd_data->stat_table.time_stats[0].rtd[i].min_num, rtd_data->stat_table.time_stats[0].rtd[i].max_num
				);
				wmem_free(NULL, tmp_str);
			}
		}
	}
	else
	{
		printf("Type    | Messages   |    Min RTD    |    Max RTD    |    Avg RTD    | Min in Frame | Max in Frame | Open Requests | Discarded responses | Duplicate requests | Duplicate responses\n");
		for (i=0; i<rtd_data->stat_table.num_rtds; i++) {
			for (j=0; j<rtd_data->stat_table.time_stats[i].num_timestat; j++) {
				if (rtd_data->stat_table.time_stats[i].rtd[j].num) {
					tmp_str = val_to_str_wmem(NULL, i, rtd->vs_type, "Other (%d)");
					printf("%s | %7u    | %8.2f msec | %8.2f msec | %8.2f msec |  %10u  |  %10u  |  %10u  |  %10u  | %4u (%4.2f%%) | %4u (%4.2f%%)  |\n",
							tmp_str, rtd_data->stat_table.time_stats[i].rtd[j].num,
							nstime_to_msec(&(rtd_data->stat_table.time_stats[i].rtd[j].min)), nstime_to_msec(&(rtd_data->stat_table.time_stats[i].rtd[j].max)),
							get_average(&(rtd_data->stat_table.time_stats[i].rtd[j].tot), rtd_data->stat_table.time_stats[i].rtd[j].num),
							rtd_data->stat_table.time_stats[i].rtd[j].min_num, rtd_data->stat_table.time_stats[i].rtd[j].max_num,
							rtd_data->stat_table.time_stats[i].open_req_num, rtd_data->stat_table.time_stats[i].disc_rsp_num,
							rtd_data->stat_table.time_stats[i].req_dup_num,
							rtd_data->stat_table.time_stats[i].rtd[j].num?((double)rtd_data->stat_table.time_stats[i].req_dup_num*100)/(double)rtd_data->stat_table.time_stats[i].rtd[j].num:0,
							rtd_data->stat_table.time_stats[i].rsp_dup_num,
							rtd_data->stat_table.time_stats[i].rtd[j].num?((double)rtd_data->stat_table.time_stats[i].rsp_dup_num*100)/(double)rtd_data->stat_table.time_stats[i].rtd[j].num:0
					);
					wmem_free(NULL, tmp_str);
				}
			}
		}
	}
	printf("=====================================================================================================\n");
}

static void
init_rtd_tables(register_rtd_t* rtd, const char *filter)
{
	GString *error_string;
	rtd_t* ui;

	ui = g_new0(rtd_t, 1);
	ui->type = proto_get_protocol_short_name(find_protocol_by_id(get_rtd_proto_id(rtd)));
	ui->filter = g_strdup(filter);
	ui->vs_type = get_rtd_value_string(rtd);
	ui->rtd.user_data = ui;

	rtd_table_dissector_init(rtd, &ui->rtd.stat_table, NULL, NULL);

	error_string = register_tap_listener(get_rtd_tap_listener_name(rtd), &ui->rtd, filter, 0, NULL, get_rtd_packet_func(rtd), rtd_draw);
	if (error_string) {
		free_rtd_table(&ui->rtd.stat_table, NULL, NULL);
		fprintf(stderr, "tshark: Couldn't register srt tap: %s\n", error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}

static void
dissector_rtd_init(const char *opt_arg, void* userdata)
{
	register_rtd_t *rtd = (register_rtd_t*)userdata;
	const char *filter=NULL;
	char* err = NULL;

	rtd_table_get_filter(rtd, opt_arg, &filter, &err);
	if (err != NULL)
	{
		fprintf(stderr, "tshark: %s\n", err);
		g_free(err);
		exit(1);
	}

	init_rtd_tables(rtd, filter);
}

/* Set GUI fields for register_rtd list */
void
register_rtd_tables(gpointer data, gpointer user_data _U_)
{
	register_rtd_t *rtd = (register_rtd_t*)data;
	stat_tap_ui ui_info;

	ui_info.group = REGISTER_STAT_GROUP_RESPONSE_TIME;
	ui_info.title = NULL;   /* construct this from the protocol info? */
	ui_info.cli_string = rtd_table_get_tap_string(rtd);
	ui_info.tap_init_cb = dissector_rtd_init;
	ui_info.nparams = 0;
	ui_info.params = NULL;
	register_stat_tap_ui(&ui_info, rtd);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
