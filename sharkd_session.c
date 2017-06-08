/* sharkd_session.c
 *
 * Copyright (C) 2016 Jakub Zawadzki
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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include <wsutil/wsjsmn.h>
#include <wsutil/ws_printf.h>

#include <file.h>
#include <epan/exceptions.h>
#include <epan/color_filters.h>
#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/uat-int.h>
#include <wiretap/wtap.h>

#include <epan/column.h>

#include <ui/ssl_key_export.h>

#include <epan/stats_tree_priv.h>
#include <epan/stat_tap_ui.h>
#include <epan/conversation_table.h>
#include <epan/expert.h>
#include <epan/export_object.h>
#include <epan/follow.h>
#include <epan/rtd_table.h>
#include <epan/srt_table.h>

#include <epan/dissectors/packet-h225.h>
#include <epan/rtp_pt.h>
#include <ui/voip_calls.h>
#include <ui/rtp_stream.h>
#include <ui/tap-rtp-common.h>
#include <epan/to_str.h>

#include <epan/addr_resolv.h>
#include <epan/dissectors/packet-rtp.h>
#include <ui/rtp_media.h>
#ifdef HAVE_SPEEXDSP
#include <speex/speex_resampler.h>
#else
#include <codecs/speex/speex_resampler.h>
#endif /* HAVE_SPEEXDSP */

#ifdef HAVE_GEOIP
# include <GeoIP.h>
# include <epan/geoip_db.h>
# include <wsutil/pint.h>
#endif

#include <wsutil/glib-compat.h>
#include <wsutil/strtoi.h>

#include "sharkd.h"

static void
json_unescape_str(char *input)
{
	char *output = input;

	while (*input)
	{
		char ch = *input++;

		if (ch == '\\')
		{
			/* TODO, add more escaping rules */
			ch = *input++;
		}

		*output = ch;
		output++;
	}

	*output = '\0';
}

static const char *
json_find_attr(const char *buf, const jsmntok_t *tokens, int count, const char *attr)
{
	int i;

	for (i = 0; i < count; i += 2)
	{
		const char *tok_attr  = &buf[tokens[i + 0].start];
		const char *tok_value = &buf[tokens[i + 1].start];

		if (!strcmp(tok_attr, attr))
			return tok_value;
	}

	return NULL;
}

static void
json_puts_string(const char *str)
{
	int i;

	if (str == NULL)
		str = "";

	putchar('"');
	for (i = 0; str[i]; i++)
	{
		switch (str[i])
		{
			case '\\':
			case '"':
				putchar('\\');
				putchar(str[i]);
				break;

			case '\n':
				putchar('\\');
				putchar('n');
				break;

			default:
				putchar(str[i]);
				break;
		}
	}

	putchar('"');
}

static void
json_print_base64_step(const guint8 *data, int *state1, int *state2)
{
	gchar buf[(1 / 3 + 1) * 4 + 4 + 1];
	gsize wrote;

	if (data)
		wrote = g_base64_encode_step(data, 1, FALSE, buf, state1, state2);
	else
		wrote = g_base64_encode_close(FALSE, buf, state1, state2);

	if (wrote > 0)
	{
		buf[wrote] = '\0';
		printf("%s", buf);
	}
}

static void
json_print_base64(const guint8 *data, size_t len)
{
	size_t i;
	int base64_state1 = 0;
	int base64_state2 = 0;

	putchar('"');

	for (i = 0; i < len; i++)
		json_print_base64_step(&data[i], &base64_state1, &base64_state2);

	json_print_base64_step(NULL, &base64_state1, &base64_state2);

	putchar('"');
}

struct filter_item
{
	struct filter_item *next;

	char *filter;
	guint8 *filtered;
};

static struct filter_item *filter_list = NULL;

static const guint8 *
sharkd_session_filter_data(const char *filter)
{
	struct filter_item *l;

	for (l = filter_list; l; l = l->next)
	{
		if (!strcmp(l->filter, filter))
			return l->filtered;
	}

	{
		guint8 *filtered = NULL;

		int ret = sharkd_filter(filter, &filtered);

		if (ret == -1)
			return NULL;

		l = (struct filter_item *) g_malloc(sizeof(struct filter_item));
		l->filter = g_strdup(filter);
		l->filtered = filtered;

		l->next = filter_list;
		filter_list = l;

		return filtered;
	}
}

struct sharkd_rtp_match
{
	guint32 addr_src, addr_dst;
	address src_addr;
	address dst_addr;
	guint16 src_port;
	guint16 dst_port;
	guint32 ssrc;
};

static gboolean
sharkd_rtp_match_init(struct sharkd_rtp_match *req, const char *init_str)
{
	gboolean ret = FALSE;
	char **arr;

	arr = g_strsplit(init_str, "_", 7); /* pass larger value, so we'll catch incorrect input :) */
	if (g_strv_length(arr) != 5)
		goto fail;

	/* TODO, for now only IPv4 */
	if (!get_host_ipaddr(arr[0], &req->addr_src))
		goto fail;

	if (!ws_strtou16(arr[1], NULL, &req->src_port))
		goto fail;

	if (!get_host_ipaddr(arr[2], &req->addr_dst))
		goto fail;

	if (!ws_strtou16(arr[3], NULL, &req->dst_port))
		goto fail;

	if (!ws_hexstrtou32(arr[4], NULL, &req->ssrc))
		goto fail;

	set_address(&req->src_addr, AT_IPv4, 4, &req->addr_src);
	set_address(&req->dst_addr, AT_IPv4, 4, &req->addr_dst);
	ret = TRUE;

fail:
	g_strfreev(arr);
	return ret;
}

static gboolean
sharkd_rtp_match_check(const struct sharkd_rtp_match *req, const packet_info *pinfo, const struct _rtp_info *rtp_info)
{
	if (rtp_info->info_sync_src == req->ssrc &&
		pinfo->srcport == req->src_port &&
		pinfo->destport == req->dst_port &&
		addresses_equal(&pinfo->src, &req->src_addr) &&
		addresses_equal(&pinfo->dst, &req->dst_addr))
	{
		return TRUE;
	}

	return FALSE;
}

static gboolean
sharkd_session_process_info_nstat_cb(const void *key, void *value, void *userdata)
{
	stat_tap_table_ui *new_stat_tap = (stat_tap_table_ui *) value;
	int *pi = (int *) userdata;

	printf("%s{", (*pi) ? "," : "");
		printf("\"name\":\"%s\"", new_stat_tap->title);
		printf(",\"tap\":\"nstat:%s\"", (const char *) key);
	printf("}");

	*pi = *pi + 1;
	return FALSE;
}

static gboolean
sharkd_session_process_info_conv_cb(const void* key, void* value, void* userdata)
{
	struct register_ct *table = (struct register_ct *) value;
	int *pi = (int *) userdata;

	const char *label = (const char*)key;

	if (get_conversation_packet_func(table))
	{
		printf("%s{", (*pi) ? "," : "");
			printf("\"name\":\"Conversation List/%s\"", label);
			printf(",\"tap\":\"conv:%s\"", label);
		printf("}");

		*pi = *pi + 1;
	}

	if (get_hostlist_packet_func(table))
	{
		printf("%s{", (*pi) ? "," : "");
			printf("\"name\":\"Endpoint/%s\"", label);
			printf(",\"tap\":\"endpt:%s\"", label);
		printf("}");

		*pi = *pi + 1;
	}
	return FALSE;
}

static gboolean
sharkd_export_object_visit_cb(const void *key _U_, void *value, void *user_data)
{
	register_eo_t *eo = (register_eo_t*)value;
	int *pi = (int *) user_data;

	const int proto_id = get_eo_proto_id(eo);
	const char *filter = proto_get_protocol_filter_name(proto_id);
	const char *label  = proto_get_protocol_short_name(find_protocol_by_id(proto_id));

	printf("%s{", (*pi) ? "," : "");
		printf("\"name\":\"Export Object/%s\"", label);
		printf(",\"tap\":\"eo:%s\"", filter);
	printf("}");

	*pi = *pi + 1;
	return FALSE;
}

static gboolean
sharkd_srt_visit_cb(const void *key _U_, void *value, void *user_data)
{
	register_srt_t *srt = (register_srt_t *) value;
	int *pi = (int *) user_data;

	const int proto_id = get_srt_proto_id(srt);
	const char *filter = proto_get_protocol_filter_name(proto_id);
	const char *label  = proto_get_protocol_short_name(find_protocol_by_id(proto_id));

	printf("%s{", (*pi) ? "," : "");
		printf("\"name\":\"Service Response Time/%s\"", label);
		printf(",\"tap\":\"srt:%s\"", filter);
	printf("}");

	*pi = *pi + 1;
	return FALSE;
}

static gboolean
sharkd_rtd_visit_cb(const void *key _U_, void *value, void *user_data)
{
	register_rtd_t *rtd = (register_rtd_t *) value;
	int *pi = (int *) user_data;

	const int proto_id = get_rtd_proto_id(rtd);
	const char *filter = proto_get_protocol_filter_name(proto_id);
	const char *label  = proto_get_protocol_short_name(find_protocol_by_id(proto_id));

	printf("%s{", (*pi) ? "," : "");
		printf("\"name\":\"Response Time Delay/%s\"", label);
		printf(",\"tap\":\"rtd:%s\"", filter);
	printf("}");

	*pi = *pi + 1;
	return FALSE;
}

static gboolean
sharkd_follower_visit_cb(const void *key _U_, void *value, void *user_data)
{
	register_follow_t *follower = (register_follow_t*) value;
	int *pi = (int *) user_data;

	const int proto_id = get_follow_proto_id(follower);
	const char *label  = proto_get_protocol_short_name(find_protocol_by_id(proto_id));
	const char *filter = label; /* correct: get_follow_by_name() is registered by short name */

	printf("%s{", (*pi) ? "," : "");
		printf("\"name\":\"Follow/%s\"", label);
		printf(",\"tap\":\"follow:%s\"", filter);
	printf("}");

	*pi = *pi + 1;
	return FALSE;
}

/**
 * sharkd_session_process_info()
 *
 * Process info request
 *
 * Output object with attributes:
 *   (m) columns - available column formats, array of object with attributes:
 *                  'name'   - column name
 *                  'format' - column format-name
 *
 *   (m) stats   - available statistics, array of object with attributes:
 *                  'name' - statistic name
 *                  'tap'  - sharkd tap-name for statistic
 *
 *   (m) convs   - available conversation list, array of object with attributes:
 *                  'name' - conversation name
 *                  'tap'  - sharkd tap-name for conversation
 *
 *   (m) eo      - available export object list, array of object with attributes:
 *                  'name' - export object name
 *                  'tap'  - sharkd tap-name for eo
 *
 *   (m) srt     - available service response time list, array of object with attributes:
 *                  'name' - service response time name
 *                  'tap'  - sharkd tap-name for srt
 *
 *   (m) rtd     - available response time delay list, array of object with attributes:
 *                  'name' - response time delay name
 *                  'tap'  - sharkd tap-name for rtd
 *
 *   (m) taps - available taps, array of object with attributes:
 *                  'name' - tap name
 *                  'tap'  - sharkd tap-name
 *
 *   (m) follow - available followers, array of object with attributes:
 *                  'name' - tap name
 *                  'tap'  - sharkd tap-name
 *
 *   (m) ftypes   - conversation table for FT_ number to string
 */
static void
sharkd_session_process_info(void)
{
	int i;

	printf("{\"columns\":[");
	for (i = 0; i < NUM_COL_FMTS; i++)
	{
		const char *col_format = col_format_to_string(i);
		const char *col_descr  = col_format_desc(i);

		printf("%s{", (i) ? "," : "");
			printf("\"name\":\"%s\"", col_descr);
			printf(",\"format\":\"%s\"", col_format);
		printf("}");
	}
	printf("]");

	printf(",\"stats\":[");
	{
		GList *cfg_list = stats_tree_get_cfg_list();
		GList *l;
		const char *sepa = "";

		for (l = cfg_list; l; l = l->next)
		{
			stats_tree_cfg *cfg = (stats_tree_cfg *) l->data;

			printf("%s{", sepa);
				printf("\"name\":\"%s\"", cfg->name);
				printf(",\"tap\":\"stat:%s\"", cfg->abbr);
			printf("}");
			sepa = ",";
		}

		g_list_free(cfg_list);
	}
	printf("]");

	printf(",\"ftypes\":[");
	for (i = 0; i < FT_NUM_TYPES; i++)
	{
		if (i)
			printf(",");
		json_puts_string(ftype_name((ftenum_t) i));
	}
	printf("]");

	printf(",\"version\":");
	json_puts_string(sharkd_version());

	printf(",\"nstat\":[");
	i = 0;
	new_stat_tap_iterate_tables(sharkd_session_process_info_nstat_cb, &i);
	printf("]");

	printf(",\"convs\":[");
	i = 0;
	conversation_table_iterate_tables(sharkd_session_process_info_conv_cb, &i);
	printf("]");

	printf(",\"taps\":[");
	{
		printf("{\"name\":\"%s\",\"tap\":\"%s\"}", "RTP streams", "rtp-streams");
		printf(",{\"name\":\"%s\",\"tap\":\"%s\"}", "Expert Information", "expert");
	}
	printf("]");

	printf(",\"eo\":[");
	i = 0;
	eo_iterate_tables(sharkd_export_object_visit_cb, &i);
	printf("]");

	printf(",\"srt\":[");
	i = 0;
	srt_table_iterate_tables(sharkd_srt_visit_cb, &i);
	printf("]");

	printf(",\"rtd\":[");
	i = 0;
	rtd_table_iterate_tables(sharkd_rtd_visit_cb, &i);
	printf("]");

	printf(",\"follow\":[");
	i = 0;
	follow_iterate_followers(sharkd_follower_visit_cb, &i);
	printf("]");

	printf("}\n");
}

/**
 * sharkd_session_process_load()
 *
 * Process load request
 *
 * Input:
 *   (m) file - file to be loaded
 *
 * Output object with attributes:
 *   (m) err - error code
 */
static void
sharkd_session_process_load(const char *buf, const jsmntok_t *tokens, int count)
{
	const char *tok_file = json_find_attr(buf, tokens, count, "file");
	int err = 0;

	fprintf(stderr, "load: filename=%s\n", tok_file);

	if (!tok_file)
		return;

	if (sharkd_cf_open(tok_file, WTAP_TYPE_AUTO, FALSE, &err) != CF_OK)
	{
		printf("{\"err\":%d}\n", err);
		return;
	}

	TRY
	{
		err = sharkd_load_cap_file();
	}
	CATCH(OutOfMemoryError)
	{
		fprintf(stderr, "load: OutOfMemoryError\n");
		err = ENOMEM;
	}
	ENDTRY;

	printf("{\"err\":%d}\n", err);
}

/**
 * sharkd_session_process_status()
 *
 * Process status request
 *
 * Output object with attributes:
 *   (m) frames   - count of currently loaded frames
 *   (m) duration - time difference between time of first frame, and last loaded frame
 *   (o) filename - capture filename
 *   (o) filesize - capture filesize
 */
static void
sharkd_session_process_status(void)
{
	printf("{\"frames\":%u", cfile.count);

	printf(",\"duration\":%.9f", nstime_to_sec(&cfile.elapsed_time));

	if (cfile.filename)
	{
		char *name = g_path_get_basename(cfile.filename);

		printf(",\"filename\":");
		json_puts_string(name);
		g_free(name);
	}

	if (cfile.wth)
	{
		gint64 file_size = wtap_file_size(cfile.wth, NULL);

		if (file_size > 0)
			printf(",\"filesize\":%" G_GINT64_FORMAT, file_size);
	}

	printf("}\n");
}

struct sharkd_analyse_data
{
	GHashTable *protocols_set;
	nstime_t *first_time;
	nstime_t *last_time;
};

static void
sharkd_session_process_analyse_cb(packet_info *pi, proto_tree *tree, struct epan_column_info *cinfo, const GSList *data_src, void *data)
{
	struct sharkd_analyse_data *analyser = (struct sharkd_analyse_data *) data;
	frame_data *fdata = pi->fd;

	(void) tree;
	(void) cinfo;
	(void) data_src;

	if (analyser->first_time == NULL || nstime_cmp(&fdata->abs_ts, analyser->first_time) < 0)
		analyser->first_time = &fdata->abs_ts;

	if (analyser->last_time == NULL || nstime_cmp(&fdata->abs_ts, analyser->last_time) > 0)
		analyser->last_time = &fdata->abs_ts;

	if (pi->layers)
	{
		wmem_list_frame_t *frame;

		for (frame = wmem_list_head(pi->layers); frame; frame = wmem_list_frame_next(frame))
		{
			int proto_id = GPOINTER_TO_UINT(wmem_list_frame_data(frame));

			if (!g_hash_table_lookup_extended(analyser->protocols_set, GUINT_TO_POINTER(proto_id), NULL, NULL))
			{
				g_hash_table_insert(analyser->protocols_set, GUINT_TO_POINTER(proto_id), GUINT_TO_POINTER(proto_id));

				if (g_hash_table_size(analyser->protocols_set) != 1)
					printf(",");
				json_puts_string(proto_get_protocol_filter_name(proto_id));
			}
		}
	}

}

/**
 * sharkd_session_process_status()
 *
 * Process analyse request
 *
 * Output object with attributes:
 *   (m) frames  - count of currently loaded frames
 *   (m) protocols - protocol list
 *   (m) first     - earliest frame time
 *   (m) last      - latest frame time
 */
static void
sharkd_session_process_analyse(void)
{
	unsigned int framenum;
	struct sharkd_analyse_data analyser;

	analyser.first_time = NULL;
	analyser.last_time  = NULL;
	analyser.protocols_set = g_hash_table_new(NULL /* g_direct_hash() */, NULL /* g_direct_equal */);

	printf("{\"frames\":%u", cfile.count);

	printf(",\"protocols\":[");
	for (framenum = 1; framenum <= cfile.count; framenum++)
		sharkd_dissect_request(framenum, &sharkd_session_process_analyse_cb, 0, 0, 0, &analyser);
	printf("]");

	if (analyser.first_time)
		printf(",\"first\":%.9f", nstime_to_sec(analyser.first_time));

	if (analyser.last_time)
		printf(",\"last\":%.9f", nstime_to_sec(analyser.last_time));

	printf("}\n");

	g_hash_table_destroy(analyser.protocols_set);
}

/**
 * sharkd_session_process_frames()
 *
 * Process frames request
 *
 * Input:
 *   (o) filter - filter to be used
 *   (o) skip=N   - skip N frames
 *   (o) limit=N  - show only N frames
 *
 * Output array of frames with attributes:
 *   (m) c   - array of column data
 *   (m) num - frame number
 *   (m) i   - if frame is ignored
 *   (m) m   - if frame is marked
 *   (m) bg  - color filter - background color in hex
 *   (m) fg  - color filter - foreground color in hex
 */
static void
sharkd_session_process_frames(const char *buf, const jsmntok_t *tokens, int count)
{
	const char *tok_filter = json_find_attr(buf, tokens, count, "filter");
	const char *tok_skip   = json_find_attr(buf, tokens, count, "skip");
	const char *tok_limit  = json_find_attr(buf, tokens, count, "limit");

	const guint8 *filter_data = NULL;

	const char *frame_sepa = "";
	int col;

	guint32 framenum;
	guint32 skip;
	guint32 limit;

	column_info *cinfo = &cfile.cinfo;

	if (tok_filter)
	{
		filter_data = sharkd_session_filter_data(tok_filter);
		if (!filter_data)
			return;
	}

	skip = 0;
	if (tok_skip)
	{
		if (!ws_strtou32(tok_skip, NULL, &skip))
			return;
	}

	limit = 0;
	if (tok_limit)
	{
		if (!ws_strtou32(tok_limit, NULL, &limit))
			return;
	}

	printf("[");
	for (framenum = 1; framenum <= cfile.count; framenum++)
	{
		frame_data *fdata = frame_data_sequence_find(cfile.frames, framenum);

		if (filter_data && !(filter_data[framenum / 8] & (1 << (framenum % 8))))
			continue;

		if (skip)
		{
			skip--;
			continue;
		}

		sharkd_dissect_columns(framenum, cinfo, (fdata->color_filter == NULL));

		printf("%s{\"c\":[", frame_sepa);
		for (col = 0; col < cinfo->num_cols; ++col)
		{
			const col_item_t *col_item = &cinfo->columns[col];

			if (col)
				printf(",");

			json_puts_string(col_item->col_data);
		}
		printf("],\"num\":%u", framenum);

		if (fdata->flags.ignored)
			printf(",\"i\":true");

		if (fdata->flags.marked)
			printf(",\"m\":true");

		if (fdata->color_filter)
		{
			printf(",\"bg\":\"%x\"", color_t_to_rgb(&fdata->color_filter->bg_color));
			printf(",\"fg\":\"%x\"", color_t_to_rgb(&fdata->color_filter->fg_color));
		}

		printf("}");
		frame_sepa = ",";

		if (limit && --limit == 0)
			break;
	}
	printf("]\n");

	if (cinfo != &cfile.cinfo)
		col_cleanup(cinfo);
}

static void
sharkd_session_process_tap_stats_node_cb(const stat_node *n)
{
	stat_node *node;
	const char *sepa = "";

	printf("[");
	for (node = n->children; node; node = node->next)
	{
		/* code based on stats_tree_get_values_from_node() */
		printf("%s{\"name\":\"%s\"", sepa, node->name);
		printf(",\"count\":%d", node->counter);
		if (node->counter && ((node->st_flags & ST_FLG_AVERAGE) || node->rng))
		{
			printf(",\"avg\":%.2f", ((float)node->total) / node->counter);
			printf(",\"min\":%d", node->minvalue);
			printf(",\"max\":%d", node->maxvalue);
		}

		if (node->st->elapsed)
			printf(",\"rate\":%.4f",((float)node->counter) / node->st->elapsed);

		if (node->parent && node->parent->counter)
			printf(",\"perc\":%.2f", (node->counter * 100.0) / node->parent->counter);
		else if (node->parent == &(node->st->root))
			printf(",\"perc\":100");

		if (prefs.st_enable_burstinfo && node->max_burst)
		{
			if (prefs.st_burst_showcount)
				printf(",\"burstcount\":%d", node->max_burst);
			else
				printf(",\"burstrate\":%.4f", ((double)node->max_burst) / prefs.st_burst_windowlen);

			printf(",\"bursttime\":%.3f", ((double)node->burst_time / 1000.0));
		}

		if (node->children)
		{
			printf(",\"sub\":");
			sharkd_session_process_tap_stats_node_cb(node);
		}
		printf("}");
		sepa = ",";
	}
	printf("]");
}

/**
 * sharkd_session_process_tap_stats_cb()
 *
 * Output stats tap:
 *
 *   (m) tap        - tap name
 *   (m) type:stats - tap output type
 *   (m) name       - stat name
 *   (m) stats      - array of object with attributes:
 *                  (m) name       - stat item name
 *                  (m) count      - stat item counter
 *                  (o) avg        - stat item averange value
 *                  (o) min        - stat item min value
 *                  (o) max        - stat item max value
 *                  (o) rate       - stat item rate value (ms)
 *                  (o) perc       - stat item percentage
 *                  (o) burstrate  - stat item burst rate
 *                  (o) burstcount - stat item burst count
 *                  (o) burstttme  - stat item burst start
 *                  (o) sub        - array of object with attributes like in stats node.
 */
static void
sharkd_session_process_tap_stats_cb(void *psp)
{
	stats_tree *st = (stats_tree *) psp;

	printf("{\"tap\":\"stats:%s\",\"type\":\"stats\"", st->cfg->abbr);

	printf(",\"name\":\"%s\",\"stats\":", st->cfg->name);
	sharkd_session_process_tap_stats_node_cb(&st->root);
	printf("},");
}

static void
sharkd_session_free_tap_stats_cb(void *psp)
{
	stats_tree *st = (stats_tree *) psp;

	stats_tree_free(st);
}

struct sharkd_expert_tap
{
	GSList *details;
	GStringChunk *text;
};

/**
 * sharkd_session_process_tap_expert_cb()
 *
 * Output expert tap:
 *
 *   (m) tap         - tap name
 *   (m) type:expert - tap output type
 *   (m) details     - array of object with attributes:
 *                  (m) f - frame number, which generated expert information
 *                  (o) s - severity
 *                  (o) g - group
 *                  (m) m - expert message
 *                  (o) p - protocol
 */
static void
sharkd_session_process_tap_expert_cb(void *tapdata)
{
	struct sharkd_expert_tap *etd = (struct sharkd_expert_tap *) tapdata;
	GSList *list;
	const char *sepa = "";

	printf("{\"tap\":\"%s\",\"type\":\"%s\"", "expert", "expert");

	printf(",\"details\":[");
	for (list = etd->details; list; list = list->next)
	{
		expert_info_t *ei = (expert_info_t *) list->data;
		const char *tmp;

		printf("%s{", sepa);

		printf("\"f\":%u,", ei->packet_num);

		tmp = try_val_to_str(ei->severity, expert_severity_vals);
		if (tmp)
			printf("\"s\":\"%s\",", tmp);

		tmp = try_val_to_str(ei->group, expert_group_vals);
		if (tmp)
			printf("\"g\":\"%s\",", tmp);

		printf("\"m\":");
		json_puts_string(ei->summary);
		printf(",");

		if (ei->protocol)
		{
			printf("\"p\":");
			json_puts_string(ei->protocol);
		}

		printf("}");
		sepa = ",";
	}
	printf("]");

	printf("},");
}

static gboolean
sharkd_session_packet_tap_expert_cb(void *tapdata, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *pointer)
{
	struct sharkd_expert_tap *etd = (struct sharkd_expert_tap *) tapdata;
	expert_info_t *ei             = (expert_info_t *) pointer;

	ei = (expert_info_t *) g_memdup(ei, sizeof(*ei));
	ei->protocol = g_string_chunk_insert_const(etd->text, ei->protocol);
	ei->summary  = g_string_chunk_insert_const(etd->text, ei->summary);

	etd->details = g_slist_prepend(etd->details, ei);

	return TRUE;
}

static void
sharkd_session_free_tap_expert_cb(void *tapdata)
{
	struct sharkd_expert_tap *etd = (struct sharkd_expert_tap *) tapdata;

	g_slist_free_full(etd->details, g_free);
	g_string_chunk_free(etd->text);
	g_free(etd);
}

struct sharkd_conv_tap_data
{
	const char *type;
	conv_hash_t hash;
	gboolean resolve_name;
	gboolean resolve_port;
};

static int
sharkd_session_geoip_addr(address *addr, const char *suffix)
{
	int with_geoip = 0;

	(void) addr;
	(void) suffix;

#ifdef HAVE_GEOIP
	if (addr->type == AT_IPv4)
	{
		guint32 ip = pntoh32(addr->data);

		guint num_dbs = geoip_db_num_dbs();
		guint dbnum;

		for (dbnum = 0; dbnum < num_dbs; dbnum++)
		{
			const char *geoip_key = NULL;
			char *geoip_val;

			int db_type = geoip_db_type(dbnum);

			switch (db_type)
			{
				case GEOIP_COUNTRY_EDITION:
					geoip_key = "geoip_country";
					break;

				case GEOIP_CITY_EDITION_REV0:
				case GEOIP_CITY_EDITION_REV1:
					geoip_key = "geoip_city";
					break;

				case GEOIP_ORG_EDITION:
					geoip_key = "geoip_org";
					break;

				case GEOIP_ISP_EDITION:
					geoip_key = "geoip_isp";
					break;

				case GEOIP_ASNUM_EDITION:
					geoip_key = "geoip_as";
					break;

				case WS_LAT_FAKE_EDITION:
					geoip_key = "geoip_lat";
					break;

				case WS_LON_FAKE_EDITION:
					geoip_key = "geoip_lon";
					break;
			}

			if (geoip_key && (geoip_val = geoip_db_lookup_ipv4(dbnum, ip, NULL)))
			{
				printf(",\"%s%s\":", geoip_key, suffix);
				json_puts_string(geoip_val);
				with_geoip = 1;
			}
		}
	}
#ifdef HAVE_GEOIP_V6
	if (addr->type == AT_IPv6)
	{
		const struct e_in6_addr *ip6 = (const struct e_in6_addr *) addr->data;

		guint num_dbs = geoip_db_num_dbs();
		guint dbnum;

		for (dbnum = 0; dbnum < num_dbs; dbnum++)
		{
			const char *geoip_key = NULL;
			char *geoip_val;

			int db_type = geoip_db_type(dbnum);

			switch (db_type)
			{
				case GEOIP_COUNTRY_EDITION_V6:
					geoip_key = "geoip_country";
					break;
#if NUM_DB_TYPES > 31
				case GEOIP_CITY_EDITION_REV0_V6:
				case GEOIP_CITY_EDITION_REV1_V6:
					geoip_key = "geoip_city";
					break;

				case GEOIP_ORG_EDITION_V6:
					geoip_key = "geoip_org";
					break;

				case GEOIP_ISP_EDITION_V6:
					geoip_key = "geoip_isp";
					break;

				case GEOIP_ASNUM_EDITION_V6:
					geoip_key = "geoip_as";
					break;
#endif /* DB_NUM_TYPES */
				case WS_LAT_FAKE_EDITION:
					geoip_key = "geoip_lat";
					break;

				case WS_LON_FAKE_EDITION:
					geoip_key = "geoip_lon";
					break;
			}

			if (geoip_key && (geoip_val = geoip_db_lookup_ipv6(dbnum, *ip6, NULL)))
			{
				printf(",\"%s%s\":", geoip_key, suffix);
				json_puts_string(geoip_val);
				with_geoip = 1;
			}
		}
	}
#endif /* HAVE_GEOIP_V6 */
#endif /* HAVE_GEOIP */

	return with_geoip;
}

struct sharkd_analyse_rtp_items
{
	guint32 frame_num;
	guint32 sequence_num;

	double delta;
	double jitter;
	double skew;
	double bandwidth;
	gboolean marker;

	double arrive_offset;

	/* from tap_rtp_stat_t */
	guint32 flags;
	guint16 pt;
};

struct sharkd_analyse_rtp
{
	const char *tap_name;
	struct sharkd_rtp_match rtp;

	GSList *packets;
	double start_time;
	tap_rtp_stat_t statinfo;
};

static void
sharkd_session_process_tap_rtp_free_cb(void *tapdata)
{
	struct sharkd_analyse_rtp *rtp_req = (struct sharkd_analyse_rtp *) tapdata;

	g_slist_free_full(rtp_req->packets, g_free);
	g_free(rtp_req);
}

static gboolean
sharkd_session_packet_tap_rtp_analyse_cb(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *pointer)
{
	struct sharkd_analyse_rtp *rtp_req = (struct sharkd_analyse_rtp *) tapdata;
	const struct _rtp_info *rtpinfo = (const struct _rtp_info *) pointer;

	if (sharkd_rtp_match_check(&rtp_req->rtp, pinfo, rtpinfo))
	{
		tap_rtp_stat_t *statinfo = &(rtp_req->statinfo);
		struct sharkd_analyse_rtp_items *item;

		rtp_packet_analyse(statinfo, pinfo, rtpinfo);

		item = (struct sharkd_analyse_rtp_items *) g_malloc(sizeof(struct sharkd_analyse_rtp_items));

		if (!rtp_req->packets)
			rtp_req->start_time = nstime_to_sec(&pinfo->abs_ts);

		item->frame_num    = pinfo->num;
		item->sequence_num = rtpinfo->info_seq_num;
		item->delta        = (statinfo->flags & STAT_FLAG_FIRST) ? 0.0 : statinfo->delta;
		item->jitter       = (statinfo->flags & STAT_FLAG_FIRST) ? 0.0 : statinfo->jitter;
		item->skew         = (statinfo->flags & STAT_FLAG_FIRST) ? 0.0 : statinfo->skew;
		item->bandwidth    = statinfo->bandwidth;
		item->marker       = rtpinfo->info_marker_set ? TRUE : FALSE;
		item->arrive_offset= nstime_to_sec(&pinfo->abs_ts) - rtp_req->start_time;

		item->flags = statinfo->flags;
		item->pt    = statinfo->pt;

		/* XXX, O(n) optimize */
		rtp_req->packets = g_slist_append(rtp_req->packets, item);
	}

	return TRUE;
}

/**
 * sharkd_session_process_tap_rtp_analyse_cb()
 *
 * Output rtp analyse tap:
 *   (m) tap   - tap name
 *   (m) type  - tap output type
 *   (m) ssrc         - RTP SSRC
 *   (m) max_delta    - Max delta (ms)
 *   (m) max_delta_nr - Max delta packet #
 *   (m) max_jitter   - Max jitter (ms)
 *   (m) mean_jitter  - Mean jitter (ms)
 *   (m) max_skew     - Max skew (ms)
 *   (m) total_nr     - Total number of RTP packets
 *   (m) seq_err      - Number of sequence errors
 *   (m) duration     - Duration (ms)
 *   (m) items      - array of object with attributes:
 *                  (m) f    - frame number
 *                  (m) o    - arrive offset
 *                  (m) sn   - sequence number
 *                  (m) d    - delta
 *                  (m) j    - jitter
 *                  (m) sk   - skew
 *                  (m) bw   - bandwidth
 *                  (o) s    - status string
 *                  (o) t    - status type
 *                  (o) mark - rtp mark
 */
static void
sharkd_session_process_tap_rtp_analyse_cb(void *tapdata)
{
	const int RTP_TYPE_CN       = 1;
	const int RTP_TYPE_ERROR    = 2;
	const int RTP_TYPE_WARN     = 3;
	const int RTP_TYPE_PT_EVENT = 4;

	const struct sharkd_analyse_rtp *rtp_req = (struct sharkd_analyse_rtp *) tapdata;
	const tap_rtp_stat_t *statinfo = &rtp_req->statinfo;

	const char *sepa = "";
	GSList *l;

	printf("{\"tap\":\"%s\",\"type\":\"rtp-analyse\"", rtp_req->tap_name);

	printf(",\"ssrc\":%u", rtp_req->rtp.ssrc);

	printf(",\"max_delta\":%f", statinfo->max_delta);
	printf(",\"max_delta_nr\":%u", statinfo->max_nr);
	printf(",\"max_jitter\":%f", statinfo->max_jitter);
	printf(",\"mean_jitter\":%f", statinfo->mean_jitter);
	printf(",\"max_skew\":%f", statinfo->max_skew);
	printf(",\"total_nr\":%u", statinfo->total_nr);
	printf(",\"seq_err\":%u", statinfo->sequence);
	printf(",\"duration\":%f", statinfo->time - statinfo->start_time);

	printf(",\"items\":[");
	for (l = rtp_req->packets; l; l = l->next)
	{
		struct sharkd_analyse_rtp_items *item = (struct sharkd_analyse_rtp_items *) l->data;

		printf("%s{", sepa);

		printf("\"f\":%u", item->frame_num);
		printf(",\"o\":%.9f", item->arrive_offset);
		printf(",\"sn\":%u", item->sequence_num);
		printf(",\"d\":%.2f", item->delta);
		printf(",\"j\":%.2f", item->jitter);
		printf(",\"sk\":%.2f", item->skew);
		printf(",\"bw\":%.2f", item->bandwidth);

		if (item->pt == PT_CN)
			printf(",\"s\":\"%s\",\"t\":%d", "Comfort noise (PT=13, RFC 3389)", RTP_TYPE_CN);
		else if (item->pt == PT_CN_OLD)
			printf(",\"s\":\"%s\",\"t\":%d", "Comfort noise (PT=19, reserved)", RTP_TYPE_CN);
		else if (item->flags & STAT_FLAG_WRONG_SEQ)
			printf(",\"s\":\"%s\",\"t\":%d", "Wrong sequence number", RTP_TYPE_ERROR);
		else if (item->flags & STAT_FLAG_DUP_PKT)
			printf(",\"s\":\"%s\",\"t\":%d", "Suspected duplicate (MAC address) only delta time calculated", RTP_TYPE_WARN);
		else if (item->flags & STAT_FLAG_REG_PT_CHANGE)
			printf(",\"s\":\"Payload changed to PT=%u%s\",\"t\":%d",
				item->pt,
				(item->flags & STAT_FLAG_PT_T_EVENT) ? " telephone/event" : "",
				RTP_TYPE_WARN);
		else if (item->flags & STAT_FLAG_WRONG_TIMESTAMP)
			printf(",\"s\":\"%s\",\"t\":%d", "Incorrect timestamp", RTP_TYPE_WARN);
		else if ((item->flags & STAT_FLAG_PT_CHANGE)
			&&  !(item->flags & STAT_FLAG_FIRST)
			&&  !(item->flags & STAT_FLAG_PT_CN)
			&&  (item->flags & STAT_FLAG_FOLLOW_PT_CN)
			&&  !(item->flags & STAT_FLAG_MARKER))
		{
			printf(",\"s\":\"%s\",\"t\":%d", "Marker missing?", RTP_TYPE_WARN);
		}
		else if (item->flags & STAT_FLAG_PT_T_EVENT)
			printf(",\"s\":\"PT=%u telephone/event\",\"t\":%d", item->pt, RTP_TYPE_PT_EVENT);
		else if (item->flags & STAT_FLAG_MARKER)
			printf(",\"t\":%d", RTP_TYPE_WARN);

		if (item->marker)
			printf(",\"mark\":1");

		printf("}");
		sepa = ",";
	}
	printf("]");

	printf("},");
}

/**
 * sharkd_session_process_tap_conv_cb()
 *
 * Output conv tap:
 *   (m) tap        - tap name
 *   (m) type       - tap output type
 *   (m) proto      - protocol short name
 *   (o) filter     - filter string
 *
 *   (o) convs      - array of object with attributes:
 *                  (m) saddr - source address
 *                  (m) daddr - destination address
 *                  (o) sport - source port
 *                  (o) dport - destination port
 *                  (m) txf   - TX frame count
 *                  (m) txb   - TX bytes
 *                  (m) rxf   - RX frame count
 *                  (m) rxb   - RX bytes
 *                  (m) start - (relative) first packet time
 *                  (m) stop  - (relative) last packet time
 *
 *   (o) hosts      - array of object with attributes:
 *                  (m) host - host address
 *                  (o) port - host port
 *                  (m) txf  - TX frame count
 *                  (m) txb  - TX bytes
 *                  (m) rxf  - RX frame count
 *                  (m) rxb  - RX bytes
 */
static void
sharkd_session_process_tap_conv_cb(void *arg)
{
	conv_hash_t *hash = (conv_hash_t *) arg;
	const struct sharkd_conv_tap_data *iu = (struct sharkd_conv_tap_data *) hash->user_data;
	const char *proto;
	int proto_with_port;
	guint i;

	int with_geoip = 0;

	if (!strncmp(iu->type, "conv:", 5))
	{
		printf("{\"tap\":\"%s\",\"type\":\"conv\"", iu->type);
		printf(",\"convs\":[");
		proto = iu->type + 5;
	}
	else if (!strncmp(iu->type, "endpt:", 6))
	{
		printf("{\"tap\":\"%s\",\"type\":\"host\"", iu->type);
		printf(",\"hosts\":[");
		proto = iu->type + 6;
	}
	else
	{
		printf("{\"tap\":\"%s\",\"type\":\"err\"", iu->type);
		proto = "";
	}

	proto_with_port = (!strcmp(proto, "TCP") || !strcmp(proto, "UDP") || !strcmp(proto, "SCTP"));

	if (iu->hash.conv_array != NULL && !strncmp(iu->type, "conv:", 5))
	{
		for (i = 0; i < iu->hash.conv_array->len; i++)
		{
			conv_item_t *iui = &g_array_index(iu->hash.conv_array, conv_item_t, i);
			char *src_addr, *dst_addr;
			char *src_port, *dst_port;
			char *filter_str;

			printf("%s{", i ? "," : "");

			printf("\"saddr\":\"%s\"",  (src_addr = get_conversation_address(NULL, &iui->src_address, iu->resolve_name)));
			printf(",\"daddr\":\"%s\"", (dst_addr = get_conversation_address(NULL, &iui->dst_address, iu->resolve_name)));

			if (proto_with_port)
			{
				printf(",\"sport\":\"%s\"", (src_port = get_conversation_port(NULL, iui->src_port, iui->ptype, iu->resolve_port)));
				printf(",\"dport\":\"%s\"", (dst_port = get_conversation_port(NULL, iui->dst_port, iui->ptype, iu->resolve_port)));

				wmem_free(NULL, src_port);
				wmem_free(NULL, dst_port);
			}

			printf(",\"rxf\":%" G_GUINT64_FORMAT, iui->rx_frames);
			printf(",\"rxb\":%" G_GUINT64_FORMAT, iui->rx_bytes);

			printf(",\"txf\":%" G_GUINT64_FORMAT, iui->tx_frames);
			printf(",\"txb\":%" G_GUINT64_FORMAT, iui->tx_bytes);

			printf(",\"start\":%.9f", nstime_to_sec(&iui->start_time));
			printf(",\"stop\":%.9f", nstime_to_sec(&iui->stop_time));

			filter_str = get_conversation_filter(iui, CONV_DIR_A_TO_FROM_B);
			if (filter_str)
			{
				printf(",\"filter\":\"%s\"", filter_str);
				g_free(filter_str);
			}

			wmem_free(NULL, src_addr);
			wmem_free(NULL, dst_addr);

			if (sharkd_session_geoip_addr(&(iui->src_address), "1"))
				with_geoip = 1;
			if (sharkd_session_geoip_addr(&(iui->dst_address), "2"))
				with_geoip = 1;

			printf("}");
		}
	}
	else if (iu->hash.conv_array != NULL && !strncmp(iu->type, "endpt:", 6))
	{
		for (i = 0; i < iu->hash.conv_array->len; i++)
		{
			hostlist_talker_t *host = &g_array_index(iu->hash.conv_array, hostlist_talker_t, i);
			char *host_str, *port_str;
			char *filter_str;

			printf("%s{", i ? "," : "");

			printf("\"host\":\"%s\"", (host_str = get_conversation_address(NULL, &host->myaddress, iu->resolve_name)));

			if (proto_with_port)
			{
				printf(",\"port\":\"%s\"", (port_str = get_conversation_port(NULL, host->port, host->ptype, iu->resolve_port)));

				wmem_free(NULL, port_str);
			}

			printf(",\"rxf\":%" G_GUINT64_FORMAT, host->rx_frames);
			printf(",\"rxb\":%" G_GUINT64_FORMAT, host->rx_bytes);

			printf(",\"txf\":%" G_GUINT64_FORMAT, host->tx_frames);
			printf(",\"txb\":%" G_GUINT64_FORMAT, host->tx_bytes);

			filter_str = get_hostlist_filter(host);
			if (filter_str)
			{
				printf(",\"filter\":\"%s\"", filter_str);
				g_free(filter_str);
			}

			wmem_free(NULL, host_str);

			if (sharkd_session_geoip_addr(&(host->myaddress), ""))
				with_geoip = 1;
			printf("}");
		}
	}

	printf("],\"proto\":\"%s\",\"geoip\":%s},", proto, with_geoip ? "true" : "false");
}

static void
sharkd_session_free_tap_conv_cb(void *arg)
{
	conv_hash_t *hash = (conv_hash_t *) arg;
	struct sharkd_conv_tap_data *iu = (struct sharkd_conv_tap_data *) hash->user_data;

	if (!strncmp(iu->type, "conv:", 5))
	{
		reset_conversation_table_data(hash);
	}
	else if (!strncmp(iu->type, "endpt:", 6))
	{
		reset_hostlist_table_data(hash);
	}

	g_free(iu);
}

/**
 * sharkd_session_process_tap_nstat_cb()
 *
 * Output nstat tap:
 *   (m) tap        - tap name
 *   (m) type       - tap output type
 *   (m) fields: array of objects with attributes:
 *                  (m) c - name
 *
 *   (m) tables: array of object with attributes:
 *                  (m) t - table title
 *                  (m) i - array of items
 */
static void
sharkd_session_process_tap_nstat_cb(void *arg)
{
	new_stat_data_t *stat_data = (new_stat_data_t *) arg;
	guint i, j, k;

	printf("{\"tap\":\"nstat:%s\",\"type\":\"nstat\"", stat_data->stat_tap_data->cli_string);

	printf(",\"fields\":[");
	for (i = 0; i < stat_data->stat_tap_data->nfields; i++)
	{
		stat_tap_table_item *field = &(stat_data->stat_tap_data->fields[i]);

		if (i)
			printf(",");

		printf("{");

		printf("\"c\":");
		json_puts_string(field->column_name);

		printf("}");
	}
	printf("]");

	printf(",\"tables\":[");
	for (i = 0; i < stat_data->stat_tap_data->tables->len; i++)
	{
		stat_tap_table *table = g_array_index(stat_data->stat_tap_data->tables, stat_tap_table *, i);
		const char *sepa = "";

		if (i)
			printf(",");

		printf("{");

		printf("\"t\":");
		printf("\"%s\"", table->title);

		printf(",\"i\":[");
		for (j = 0; j < table->num_elements; j++)
		{
			stat_tap_table_item_type *field_data;

			field_data = new_stat_tap_get_field_data(table, j, 0);
			if (field_data == NULL || field_data->type == TABLE_ITEM_NONE) /* Nothing for us here */
				continue;

			printf("%s[", sepa);
			for (k = 0; k < table->num_fields; k++)
			{
				field_data = new_stat_tap_get_field_data(table, j, k);

				if (k)
					printf(",");

				switch (field_data->type)
				{
					case TABLE_ITEM_UINT:
						printf("%u", field_data->value.uint_value);
						break;

					case TABLE_ITEM_INT:
						printf("%d", field_data->value.uint_value);
						break;

					case TABLE_ITEM_STRING:
						json_puts_string(field_data->value.string_value);
						break;

					case TABLE_ITEM_FLOAT:
						printf("%f", field_data->value.float_value);
						break;

					case TABLE_ITEM_ENUM:
						printf("%d", field_data->value.enum_value);
						break;

					case TABLE_ITEM_NONE:
						printf("null");
						break;
				}
			}

			printf("]");
			sepa = ",";
		}
		printf("]");
		printf("}");
	}

	printf("]},");
}

static void
sharkd_session_free_tap_nstat_cb(void *arg)
{
	new_stat_data_t *stat_data = (new_stat_data_t *) arg;

	free_stat_tables(stat_data->stat_tap_data, NULL, NULL);
}

/**
 * sharkd_session_process_tap_rtd_cb()
 *
 * Output rtd tap:
 *   (m) tap        - tap name
 *   (m) type       - tap output type
 *   (m) stats - statistics rows - array object with attributes:
 *                  (m) type - statistic name
 *                  (m) num - number of messages
 *                  (m) min - minimum SRT time
 *                  (m) max - maximum SRT time
 *                  (m) tot - total SRT time
 *                  (m) min_frame - minimal SRT
 *                  (m) max_frame - maximum SRT
 *                  (o) open_req - Open Requests
 *                  (o) disc_rsp - Discarded Responses
 *                  (o) req_dup  - Duplicated Requests
 *                  (o) rsp_dup  - Duplicated Responses
 *   (o) open_req   - Open Requests
 *   (o) disc_rsp   - Discarded Responses
 *   (o) req_dup    - Duplicated Requests
 *   (o) rsp_dup    - Duplicated Responses
 */
static void
sharkd_session_process_tap_rtd_cb(void *arg)
{
	rtd_data_t *rtd_data = (rtd_data_t *) arg;
	register_rtd_t *rtd  = (register_rtd_t *) rtd_data->user_data;

	guint i, j;

	const char *filter = proto_get_protocol_filter_name(get_rtd_proto_id(rtd));

	/* XXX, some dissectors are having single table and multiple timestats (mgcp, megaco),
	 *      some multiple table and single timestat (radius, h225)
	 *      and it seems that value_string is used one for timestamp-ID, other one for table-ID
	 *      I wonder how it will gonna work with multiple timestats and multiple timestat...
	 * (for usage grep for: register_rtd_table)
	 */
	const value_string *vs = get_rtd_value_string(rtd);
	const char *sepa = "";

	printf("{\"tap\":\"rtd:%s\",\"type\":\"rtd\"", filter);

	if (rtd_data->stat_table.num_rtds == 1)
	{
		const rtd_timestat *ms = &rtd_data->stat_table.time_stats[0];

		printf(",\"open_req\":%u", ms->open_req_num);
		printf(",\"disc_rsp\":%u", ms->disc_rsp_num);
		printf(",\"req_dup\":%u", ms->req_dup_num);
		printf(",\"rsp_dup\":%u", ms->rsp_dup_num);
	}

	printf(",\"stats\":[");
	for (i = 0; i < rtd_data->stat_table.num_rtds; i++)
	{
		const rtd_timestat *ms = &rtd_data->stat_table.time_stats[i];

		for (j = 0; j < ms->num_timestat; j++)
		{
			const char *type_str;

			if (ms->rtd[j].num == 0)
				continue;

			printf("%s{", sepa);

			if (rtd_data->stat_table.num_rtds == 1)
				type_str = val_to_str_const(j, vs, "Other"); /* 1 table - description per row */
			else
				type_str = val_to_str_const(i, vs, "Other"); /* multiple table - description per table */
			printf("\"type\":");
			json_puts_string(type_str);

			printf(",\"num\":%u", ms->rtd[j].num);
			printf(",\"min\":%.9f", nstime_to_sec(&(ms->rtd[j].min)));
			printf(",\"max\":%.9f", nstime_to_sec(&(ms->rtd[j].max)));
			printf(",\"tot\":%.9f", nstime_to_sec(&(ms->rtd[j].tot)));
			printf(",\"min_frame\":%u", ms->rtd[j].min_num);
			printf(",\"max_frame\":%u", ms->rtd[j].max_num);

			if (rtd_data->stat_table.num_rtds != 1)
			{
				/* like in tshark, display it on every row */
				printf(",\"open_req\":%u", ms->open_req_num);
				printf(",\"disc_rsp\":%u", ms->disc_rsp_num);
				printf(",\"req_dup\":%u", ms->req_dup_num);
				printf(",\"rsp_dup\":%u", ms->rsp_dup_num);
			}

			printf("}");
			sepa = ",";
		}
	}
	printf("]},");
}

static void
sharkd_session_free_tap_rtd_cb(void *arg)
{
	rtd_data_t *rtd_data = (rtd_data_t *) arg;

	free_rtd_table(&rtd_data->stat_table, NULL, NULL);
	g_free(rtd_data);
}

/**
 * sharkd_session_process_tap_srt_cb()
 *
 * Output srt tap:
 *   (m) tap        - tap name
 *   (m) type       - tap output type
 *
 *   (m) tables - array of object with attributes:
 *                  (m) n - table name
 *                  (m) f - table filter
 *                  (o) c - table column name
 *                  (m) r - table rows - array object with attributes:
 *                            (m) n   - row name
 *                            (m) idx - procedure index
 *                            (m) num - number of events
 *                            (m) min - minimum SRT time
 *                            (m) max - maximum SRT time
 *                            (m) tot - total SRT time
 */
static void
sharkd_session_process_tap_srt_cb(void *arg)
{
	srt_data_t *srt_data = (srt_data_t *) arg;
	register_srt_t *srt = (register_srt_t *) srt_data->user_data;

	const char *filter = proto_get_protocol_filter_name(get_srt_proto_id(srt));

	guint i;

	printf("{\"tap\":\"srt:%s\",\"type\":\"srt\"", filter);

	printf(",\"tables\":[");
	for (i = 0; i < srt_data->srt_array->len; i++)
	{
		/* SRT table */
		srt_stat_table *rst = g_array_index(srt_data->srt_array, srt_stat_table *, i);
		const char *sepa = "";

		int j;

		if (i)
			printf(",");
		printf("{");

		printf("\"n\":");
		if (rst->name)
			json_puts_string(rst->name);
		else if (rst->short_name)
			json_puts_string(rst->short_name);
		else
			printf("\"table%u\"", i);

		if (rst->filter_string)
		{
			printf(",\"f\":");
			json_puts_string(rst->filter_string);
		}

		if (rst->proc_column_name)
		{
			printf(",\"c\":");
			json_puts_string(rst->proc_column_name);
		}

		printf(",\"r\":[");
		for (j = 0; j < rst->num_procs; j++)
		{
			/* SRT row */
			srt_procedure_t *proc = &rst->procedures[j];

			if (proc->stats.num == 0)
				continue;

			printf("%s{", sepa);

			printf("\"n\":");
			json_puts_string(proc->procedure);

			if (rst->filter_string)
				printf(",\"idx\":%d", proc->proc_index);

			printf(",\"num\":%u", proc->stats.num);

			printf(",\"min\":%.9f", nstime_to_sec(&proc->stats.min));
			printf(",\"max\":%.9f", nstime_to_sec(&proc->stats.max));
			printf(",\"tot\":%.9f", nstime_to_sec(&proc->stats.tot));

			printf("}");
			sepa = ",";
		}
		printf("]}");
	}

	printf("]},");
}

static void
sharkd_session_free_tap_srt_cb(void *arg)
{
	srt_data_t *srt_data = (srt_data_t *) arg;
	register_srt_t *srt = (register_srt_t *) srt_data->user_data;

	free_srt_table(srt, srt_data->srt_array, NULL, NULL);
	g_array_free(srt_data->srt_array, TRUE);
	g_free(srt_data);
}

struct sharkd_export_object_list
{
	struct sharkd_export_object_list *next;

	char *type;
	const char *proto;
	GSList *entries;
};

static struct sharkd_export_object_list *sharkd_eo_list;

/**
 * sharkd_session_process_tap_eo_cb()
 *
 * Output eo tap:
 *   (m) tap        - tap name
 *   (m) type       - tap output type
 *   (m) proto      - protocol short name
 *   (m) objects    - array of object with attributes:
 *                  (m) pkt - packet number
 *                  (o) hostname - hostname
 *                  (o) type - content type
 *                  (o) filename - filename
 *                  (m) len - object length
 */
static void
sharkd_session_process_tap_eo_cb(void *tapdata)
{
	export_object_list_t *tap_object = (export_object_list_t *) tapdata;
	struct sharkd_export_object_list *object_list = (struct sharkd_export_object_list*) tap_object->gui_data;
	GSList *slist;
	int i = 0;

	printf("{\"tap\":\"%s\",\"type\":\"eo\"", object_list->type);
	printf(",\"proto\":\"%s\"", object_list->proto);
	printf(",\"objects\":[");

	for (slist = object_list->entries; slist; slist = slist->next)
	{
		const export_object_entry_t *eo_entry = (export_object_entry_t *) slist->data;

		printf("%s{", i ? "," : "");

		printf("\"pkt\":%u", eo_entry->pkt_num);

		if (eo_entry->hostname)
		{
			printf(",\"hostname\":");
			json_puts_string(eo_entry->hostname);
		}

		if (eo_entry->content_type)
		{
			printf(",\"type\":");
			json_puts_string(eo_entry->content_type);
		}

		if (eo_entry->filename)
		{
			printf(",\"filename\":");
			json_puts_string(eo_entry->filename);
		}

		printf(",\"_download\":\"%s_%d\"", object_list->type, i);

		printf(",\"len\":%" G_GINT64_FORMAT, eo_entry->payload_len);

		printf("}");

		i++;
	}

	printf("]},");
}

static void
sharkd_eo_object_list_add_entry(void *gui_data, export_object_entry_t *entry)
{
	struct sharkd_export_object_list *object_list = (struct sharkd_export_object_list *) gui_data;

	object_list->entries = g_slist_append(object_list->entries, entry);
}

static export_object_entry_t *
sharkd_eo_object_list_get_entry(void *gui_data, int row)
{
	struct sharkd_export_object_list *object_list = (struct sharkd_export_object_list *) gui_data;

	return (export_object_entry_t *) g_slist_nth_data(object_list->entries, row);
}

/**
 * sharkd_session_process_tap_rtp_cb()
 *
 * Output RTP streams tap:
 *   (m) tap        - tap name
 *   (m) type       - tap output type
 *   (m) streams    - array of object with attributes:
 *                  (m) ssrc        - RTP synchronization source identifier
 *                  (m) payload     - stream payload
 *                  (m) saddr       - source address
 *                  (m) sport       - source port
 *                  (m) daddr       - destination address
 *                  (m) dport       - destination port
 *                  (m) pkts        - packets count
 *                  (m) max_delta   - max delta (ms)
 *                  (m) max_jitter  - max jitter (ms)
 *                  (m) mean_jitter - mean jitter (ms)
 *                  (m) expectednr  -
 *                  (m) totalnr     -
 *                  (m) problem     - if analyser found the problem
 *                  (m) ipver       - address IP version (4 or 6)
 */
static void
sharkd_session_process_tap_rtp_cb(void *arg)
{
	rtpstream_tapinfo_t *rtp_tapinfo = (rtpstream_tapinfo_t *) arg;

	GList *listx;
	const char *sepa = "";

	printf("{\"tap\":\"%s\",\"type\":\"%s\"", "rtp-streams", "rtp-streams");

	printf(",\"streams\":[");
	for (listx = g_list_first(rtp_tapinfo->strinfo_list); listx; listx = listx->next)
	{
		rtp_stream_info_t *streaminfo = (rtp_stream_info_t *) listx->data;

		char *src_addr, *dst_addr;
		char *payload;
		guint32 expected;

		src_addr = address_to_display(NULL, &(streaminfo->src_addr));
		dst_addr = address_to_display(NULL, &(streaminfo->dest_addr));

		if (streaminfo->payload_type_name != NULL)
			payload = wmem_strdup(NULL, streaminfo->payload_type_name);
		else
			payload = val_to_str_ext_wmem(NULL, streaminfo->payload_type, &rtp_payload_type_short_vals_ext, "Unknown (%u)");

		printf("%s{\"ssrc\":%u", sepa, streaminfo->ssrc);
		printf(",\"payload\":\"%s\"", payload);

		printf(",\"saddr\":\"%s\"", src_addr);
		printf(",\"sport\":%u", streaminfo->src_port);

		printf(",\"daddr\":\"%s\"", dst_addr);
		printf(",\"dport\":%u", streaminfo->dest_port);

		printf(",\"pkts\":%u", streaminfo->packet_count);

		printf(",\"max_delta\":%f", streaminfo->rtp_stats.max_delta);
		printf(",\"max_jitter\":%f", streaminfo->rtp_stats.max_jitter);
		printf(",\"mean_jitter\":%f", streaminfo->rtp_stats.mean_jitter);

		expected = (streaminfo->rtp_stats.stop_seq_nr + streaminfo->rtp_stats.cycles * 65536) - streaminfo->rtp_stats.start_seq_nr + 1;
		printf(",\"expectednr\":%u", expected);
		printf(",\"totalnr\":%u", streaminfo->rtp_stats.total_nr);

		printf(",\"problem\":%s", streaminfo->problem ? "true" : "false");

		/* for filter */
		printf(",\"ipver\":%d", (streaminfo->src_addr.type == AT_IPv6) ? 6 : 4);

		wmem_free(NULL, src_addr);
		wmem_free(NULL, dst_addr);
		wmem_free(NULL, payload);

		printf("}");
		sepa = ",";
	}
	printf("]},");
}

/**
 * sharkd_session_process_tap()
 *
 * Process tap request
 *
 * Input:
 *   (m) tap0         - First tap request
 *   (o) tap1...tap15 - Other tap requests
 *
 * Output object with attributes:
 *   (m) taps  - array of object with attributes:
 *                  (m) tap  - tap name
 *                  (m) type - tap output type
 *                  ...
 *                  for type:stats see sharkd_session_process_tap_stats_cb()
 *                  for type:nstat see sharkd_session_process_tap_nstat_cb()
 *                  for type:conv see sharkd_session_process_tap_conv_cb()
 *                  for type:host see sharkd_session_process_tap_conv_cb()
 *                  for type:rtp-streams see sharkd_session_process_tap_rtp_cb()
 *                  for type:rtp-analyse see sharkd_session_process_tap_rtp_analyse_cb()
 *                  for type:eo see sharkd_session_process_tap_eo_cb()
 *                  for type:expert see sharkd_session_process_tap_expert_cb()
 *                  for type:rtd see sharkd_session_process_tap_rtd_cb()
 *                  for type:srt see sharkd_session_process_tap_srt_cb()
 *
 *   (m) err   - error code
 */
static void
sharkd_session_process_tap(char *buf, const jsmntok_t *tokens, int count)
{
	void *taps_data[16];
	GFreeFunc taps_free[16];
	int taps_count = 0;
	int i;

	rtpstream_tapinfo_t rtp_tapinfo =
		{NULL, NULL, NULL, NULL, 0, NULL, 0, TAP_ANALYSE, NULL, NULL, NULL, FALSE};

	for (i = 0; i < 16; i++)
	{
		char tapbuf[32];
		const char *tok_tap;

		void *tap_data = NULL;
		GFreeFunc tap_free = NULL;
		const char *tap_filter = "";
		GString *tap_error = NULL;

		ws_snprintf(tapbuf, sizeof(tapbuf), "tap%d", i);
		tok_tap = json_find_attr(buf, tokens, count, tapbuf);
		if (!tok_tap)
			break;

		if (!strncmp(tok_tap, "stat:", 5))
		{
			stats_tree_cfg *cfg = stats_tree_get_cfg_by_abbr(tok_tap + 5);
			stats_tree *st;

			if (!cfg)
			{
				fprintf(stderr, "sharkd_session_process_tap() stat %s not found\n", tok_tap + 5);
				continue;
			}

			st = stats_tree_new(cfg, NULL, tap_filter);

			tap_error = register_tap_listener(st->cfg->tapname, st, st->filter, st->cfg->flags, stats_tree_reset, stats_tree_packet, sharkd_session_process_tap_stats_cb);

			if (!tap_error && cfg->init)
				cfg->init(st);

			tap_data = st;
			tap_free = sharkd_session_free_tap_stats_cb;
		}
		else if (!strcmp(tok_tap, "expert"))
		{
			struct sharkd_expert_tap *expert_tap;

			expert_tap = g_new0(struct sharkd_expert_tap, 1);
			expert_tap->text = g_string_chunk_new(100);

			tap_error = register_tap_listener("expert", expert_tap, NULL, 0, NULL, sharkd_session_packet_tap_expert_cb, sharkd_session_process_tap_expert_cb);

			tap_data = expert_tap;
			tap_free = sharkd_session_free_tap_expert_cb;
		}
		else if (!strncmp(tok_tap, "conv:", 5) || !strncmp(tok_tap, "endpt:", 6))
		{
			struct register_ct *ct = NULL;
			const char *ct_tapname;
			struct sharkd_conv_tap_data *ct_data;
			tap_packet_cb tap_func = NULL;

			if (!strncmp(tok_tap, "conv:", 5))
			{
				ct = get_conversation_by_proto_id(proto_get_id_by_short_name(tok_tap + 5));

				if (!ct || !(tap_func = get_conversation_packet_func(ct)))
				{
					fprintf(stderr, "sharkd_session_process_tap() conv %s not found\n", tok_tap + 5);
					continue;
				}
			}
			else if (!strncmp(tok_tap, "endpt:", 6))
			{
				ct = get_conversation_by_proto_id(proto_get_id_by_short_name(tok_tap + 6));

				if (!ct || !(tap_func = get_hostlist_packet_func(ct)))
				{
					fprintf(stderr, "sharkd_session_process_tap() endpt %s not found\n", tok_tap + 6);
					continue;
				}
			}
			else
			{
				fprintf(stderr, "sharkd_session_process_tap() conv/endpt(?): %s not found\n", tok_tap);
				continue;
			}

			ct_tapname = proto_get_protocol_filter_name(get_conversation_proto_id(ct));

			ct_data = (struct sharkd_conv_tap_data *) g_malloc0(sizeof(struct sharkd_conv_tap_data));
			ct_data->type = tok_tap;
			ct_data->hash.user_data = ct_data;

			/* XXX: make configurable */
			ct_data->resolve_name = TRUE;
			ct_data->resolve_port = TRUE;

			tap_error = register_tap_listener(ct_tapname, &ct_data->hash, tap_filter, 0, NULL, tap_func, sharkd_session_process_tap_conv_cb);

			tap_data = &ct_data->hash;
			tap_free = sharkd_session_free_tap_conv_cb;
		}
		else if (!strncmp(tok_tap, "nstat:", 6))
		{
			stat_tap_table_ui *stat_tap = new_stat_tap_by_name(tok_tap + 6);
			new_stat_data_t *stat_data;

			if (!stat_tap)
			{
				fprintf(stderr, "sharkd_session_process_tap() nstat=%s not found\n", tok_tap + 6);
				continue;
			}

			stat_tap->stat_tap_init_cb(stat_tap, NULL, NULL);

			stat_data = g_new0(new_stat_data_t, 1);
			stat_data->stat_tap_data = stat_tap;
			stat_data->user_data = NULL;

			tap_error = register_tap_listener(stat_tap->tap_name, stat_data, tap_filter, 0, NULL, stat_tap->packet_func, sharkd_session_process_tap_nstat_cb);

			tap_data = stat_data;
			tap_free = sharkd_session_free_tap_nstat_cb;
		}
		else if (!strncmp(tok_tap, "rtd:", 4))
		{
			register_rtd_t *rtd = get_rtd_table_by_name(tok_tap + 4);
			rtd_data_t *rtd_data;
			char *err;

			if (!rtd)
			{
				fprintf(stderr, "sharkd_session_process_tap() rtd=%s not found\n", tok_tap + 4);
				continue;
			}

			rtd_table_get_filter(rtd, "", &tap_filter, &err);
			if (err != NULL)
			{
				fprintf(stderr, "sharkd_session_process_tap() rtd=%s err=%s\n", tok_tap + 4, err);
				g_free(err);
				continue;
			}

			rtd_data = g_new0(rtd_data_t, 1);
			rtd_data->user_data = rtd;
			rtd_table_dissector_init(rtd, &rtd_data->stat_table, NULL, NULL);

			tap_error = register_tap_listener(get_rtd_tap_listener_name(rtd), rtd_data, tap_filter, 0, NULL, get_rtd_packet_func(rtd), sharkd_session_process_tap_rtd_cb);

			tap_data = rtd_data;
			tap_free = sharkd_session_free_tap_rtd_cb;
		}
		else if (!strncmp(tok_tap, "srt:", 4))
		{
			register_srt_t *srt = get_srt_table_by_name(tok_tap + 4);
			srt_data_t *srt_data;
			char *err;

			if (!srt)
			{
				fprintf(stderr, "sharkd_session_process_tap() srt=%s not found\n", tok_tap + 4);
				continue;
			}

			srt_table_get_filter(srt, "", &tap_filter, &err);
			if (err != NULL)
			{
				fprintf(stderr, "sharkd_session_process_tap() srt=%s err=%s\n", tok_tap + 4, err);
				g_free(err);
				continue;
			}

			srt_data = g_new0(srt_data_t, 1);
			srt_data->srt_array = g_array_new(FALSE, TRUE, sizeof(srt_stat_table *));
			srt_data->user_data = srt;
			srt_table_dissector_init(srt, srt_data->srt_array, NULL, NULL);

			tap_error = register_tap_listener(get_srt_tap_listener_name(srt), srt_data, tap_filter, 0, NULL, get_srt_packet_func(srt), sharkd_session_process_tap_srt_cb);

			tap_data = srt_data;
			tap_free = sharkd_session_free_tap_srt_cb;
		}
		else if (!strncmp(tok_tap, "eo:", 3))
		{
			register_eo_t *eo = get_eo_by_name(tok_tap + 3);
			export_object_list_t *eo_object;
			struct sharkd_export_object_list *object_list;

			if (!eo)
			{
				fprintf(stderr, "sharkd_session_process_tap() eo=%s not found\n", tok_tap + 3);
				continue;
			}

			for (object_list = sharkd_eo_list; object_list; object_list = object_list->next)
			{
				if (!strcmp(object_list->type, tok_tap))
				{
					g_slist_free_full(object_list->entries, (GDestroyNotify) eo_free_entry);
					object_list->entries = NULL;
					break;
				}
			}

			if (!object_list)
			{
				object_list = g_new(struct sharkd_export_object_list, 1);
				object_list->type = g_strdup(tok_tap);
				object_list->proto = proto_get_protocol_short_name(find_protocol_by_id(get_eo_proto_id(eo)));
				object_list->entries = NULL;
				object_list->next = sharkd_eo_list;
				sharkd_eo_list = object_list;
			}

			eo_object  = g_new0(export_object_list_t, 1);
			eo_object->add_entry = sharkd_eo_object_list_add_entry;
			eo_object->get_entry = sharkd_eo_object_list_get_entry;
			eo_object->gui_data = (void *) object_list;

			tap_error = register_tap_listener(get_eo_tap_listener_name(eo), eo_object, NULL, 0, NULL, get_eo_packet_func(eo), sharkd_session_process_tap_eo_cb);

			tap_data = eo_object;
			tap_free = g_free; /* need to free only eo_object, object_list need to be kept for potential download */
		}
		else if (!strcmp(tok_tap, "rtp-streams"))
		{
			tap_error = register_tap_listener("rtp", &rtp_tapinfo, tap_filter, 0, rtpstream_reset_cb, rtpstream_packet, sharkd_session_process_tap_rtp_cb);

			tap_data = &rtp_tapinfo;
			tap_free = rtpstream_reset_cb;
		}
		else if (!strncmp(tok_tap, "rtp-analyse:", 12))
		{
			struct sharkd_analyse_rtp *rtp_req;

			rtp_req = (struct sharkd_analyse_rtp *) g_malloc0(sizeof(*rtp_req));
			if (!sharkd_rtp_match_init(&rtp_req->rtp, tok_tap + 12))
			{
				g_free(rtp_req);
				continue;
			}

			rtp_req->tap_name = tok_tap;
			rtp_req->statinfo.first_packet = TRUE;
			rtp_req->statinfo.reg_pt = PT_UNDEFINED;

			tap_error = register_tap_listener("rtp", rtp_req, tap_filter, 0, NULL, sharkd_session_packet_tap_rtp_analyse_cb, sharkd_session_process_tap_rtp_analyse_cb);

			tap_data = rtp_req;
			tap_free = sharkd_session_process_tap_rtp_free_cb;
		}
		else
		{
			fprintf(stderr, "sharkd_session_process_tap() %s not recognized\n", tok_tap);
			continue;
		}

		if (tap_error)
		{
			fprintf(stderr, "sharkd_session_process_tap() name=%s error=%s", tok_tap, tap_error->str);
			g_string_free(tap_error, TRUE);
			if (tap_free)
				tap_free(tap_data);
			continue;
		}

		taps_data[taps_count] = tap_data;
		taps_free[taps_count] = tap_free;
		taps_count++;
	}

	fprintf(stderr, "sharkd_session_process_tap() count=%d\n", taps_count);
	if (taps_count == 0)
		return;

	printf("{\"taps\":[");
	sharkd_retap();
	printf("null],\"err\":0}\n");

	for (i = 0; i < taps_count; i++)
	{
		if (taps_data[i])
			remove_tap_listener(taps_data[i]);

		if (taps_free[i])
			taps_free[i](taps_data[i]);
	}
}

/**
 * sharkd_session_process_follow()
 *
 * Process follow request
 *
 * Input:
 *   (m) follow  - follow protocol request (e.g. HTTP)
 *   (m) filter  - filter request (e.g. tcp.stream == 1)
 *
 * Output object with attributes:
 *
 *   (m) err    - error code
 *   (m) shost  - server host
 *   (m) sport  - server port
 *   (m) sbytes - server send bytes count
 *   (m) chost  - client host
 *   (m) cport  - client port
 *   (m) cbytes - client send bytes count
 *   (o) payloads - array of object with attributes:
 *                  (o) s - set if server sent, else client
 *                  (m) n - packet number
 *                  (m) d - data base64 encoded
 */
static void
sharkd_session_process_follow(char *buf, const jsmntok_t *tokens, int count)
{
	const char *tok_follow = json_find_attr(buf, tokens, count, "follow");
	const char *tok_filter = json_find_attr(buf, tokens, count, "filter");

	register_follow_t *follower;
	GString *tap_error;

	follow_info_t *follow_info;
	const char *host;
	char *port;

	if (!tok_follow || !tok_filter)
		return;

	follower = get_follow_by_name(tok_follow);
	if (!follower)
	{
		fprintf(stderr, "sharkd_session_process_follow() follower=%s not found\n", tok_follow);
		return;
	}

	/* follow_reset_stream ? */
	follow_info = g_new0(follow_info_t, 1);
	/* gui_data, filter_out_filter not set, but not used by dissector */

	tap_error = register_tap_listener(get_follow_tap_string(follower), follow_info, tok_filter, 0, NULL, get_follow_tap_handler(follower), NULL);
	if (tap_error)
	{
		fprintf(stderr, "sharkd_session_process_follow() name=%s error=%s", tok_follow, tap_error->str);
		g_string_free(tap_error, TRUE);
		g_free(follow_info);
		return;
	}

	sharkd_retap();

	printf("{");

	printf("\"err\":0");

	/* Server information: hostname, port, bytes sent */
	host = address_to_name(&follow_info->server_ip);
	printf(",\"shost\":");
	json_puts_string(host);

	port = get_follow_port_to_display(follower)(NULL, follow_info->server_port);
	printf(",\"sport\":");
	json_puts_string(port);
	wmem_free(NULL, port);

	printf(",\"sbytes\":%u", follow_info->bytes_written[0]);

	/* Client information: hostname, port, bytes sent */
	host = address_to_name(&follow_info->client_ip);
	printf(",\"chost\":");
	json_puts_string(host);

	port = get_follow_port_to_display(follower)(NULL, follow_info->client_port);
	printf(",\"cport\":");
	json_puts_string(port);
	wmem_free(NULL, port);

	printf(",\"cbytes\":%u", follow_info->bytes_written[1]);

	if (follow_info->payload)
	{
		follow_record_t *follow_record;
		GList *cur;
		const char *sepa = "";

		printf(",\"payloads\":[");

		for (cur = follow_info->payload; cur; cur = g_list_next(cur))
		{
			follow_record = (follow_record_t *) cur->data;

			printf("%s{", sepa);

			printf("\"n\":%u", follow_record->packet_num);

			printf(",\"d\":");
			json_print_base64(follow_record->data->data, follow_record->data->len);

			if (follow_record->is_server)
				printf(",\"s\":%d", 1);

			printf("}");
			sepa = ",";
		}

		printf("]");
	}

	printf("}\n");

	remove_tap_listener(follow_info);
	follow_info_free(follow_info);
}

static void
sharkd_session_process_frame_cb_tree(proto_tree *tree, tvbuff_t **tvbs)
{
	proto_node *node;
	const char *sepa = "";

	printf("[");
	for (node = tree->first_child; node; node = node->next)
	{
		field_info *finfo = PNODE_FINFO(node);

		if (!finfo)
			continue;

		/* XXX, for now always skip hidden */
		if (FI_GET_FLAG(finfo, FI_HIDDEN))
			continue;

		printf("%s{", sepa);

		printf("\"l\":");
		if (!finfo->rep)
		{
			char label_str[ITEM_LABEL_LENGTH];

			label_str[0] = '\0';
			proto_item_fill_label(finfo, label_str);
			json_puts_string(label_str);
		}
		else
		{
			json_puts_string(finfo->rep->representation);
		}

		if (finfo->ds_tvb && tvbs && tvbs[0] != finfo->ds_tvb)
		{
			int idx;

			for (idx = 1; tvbs[idx]; idx++)
			{
				if (tvbs[idx] == finfo->ds_tvb)
				{
					printf(",\"ds\":%d", idx);
					break;
				}
			}
		}

		if (finfo->start >= 0 && finfo->length > 0)
			printf(",\"h\":[%d,%d]", finfo->start, finfo->length);

		if (finfo->appendix_start >= 0 && finfo->appendix_length > 0)
			printf(",\"i\":[%d,%d]", finfo->appendix_start, finfo->appendix_length);


		if (finfo->hfinfo)
		{
			if (finfo->hfinfo->type == FT_PROTOCOL)
			{
				printf(",\"t\":\"proto\"");
			}
			else if (finfo->hfinfo->type == FT_FRAMENUM)
			{
				printf(",\"t\":\"framenum\",\"fnum\":%u", finfo->value.value.uinteger);
			}
			else if (FI_GET_FLAG(finfo, FI_URL) && IS_FT_STRING(finfo->hfinfo->type))
			{
				char *url = fvalue_to_string_repr(NULL, &finfo->value, FTREPR_DISPLAY, finfo->hfinfo->display);

				printf(",\"t\":\"url\",\"url\":");
				json_puts_string(url);
				wmem_free(NULL, url);
			}
		}

		if (FI_GET_FLAG(finfo, PI_SEVERITY_MASK))
		{
			const char *severity = try_val_to_str(FI_GET_FLAG(finfo, PI_SEVERITY_MASK), expert_severity_vals);

			g_assert(severity != NULL);

			printf(",\"s\":\"%s\"", severity);
		}

		if (((proto_tree *) node)->first_child) {
			if (finfo->tree_type != -1)
				printf(",\"e\":%d", finfo->tree_type);
			printf(",\"n\":");
			sharkd_session_process_frame_cb_tree((proto_tree *) node, tvbs);
		}

		printf("}");
		sepa = ",";
	}
	printf("]");
}

static gboolean
sharkd_follower_visit_layers_cb(const void *key _U_, void *value, void *user_data)
{
	register_follow_t *follower = (register_follow_t *) value;
	packet_info *pi = (packet_info *) user_data;

	const int proto_id = get_follow_proto_id(follower);

	guint32 ignore_stream;

	if (proto_is_frame_protocol(pi->layers, proto_get_protocol_filter_name(proto_id)))
	{
		const char *layer_proto = proto_get_protocol_short_name(find_protocol_by_id(proto_id));
		char *follow_filter;

		follow_filter = get_follow_conv_func(follower)(pi, &ignore_stream);

		printf(",[\"%s\",", layer_proto);
		json_puts_string(follow_filter);
		printf("]");

		g_free(follow_filter);
	}

	return FALSE;
}

static void
sharkd_session_process_frame_cb(packet_info *pi, proto_tree *tree, struct epan_column_info *cinfo, const GSList *data_src, void *data)
{
	(void) pi;
	(void) data;

	printf("{");

	printf("\"err\":0");

	if (tree)
	{
		tvbuff_t **tvbs = NULL;

		printf(",\"tree\":");

		/* arrayize data src, to speedup searching for ds_tvb index */
		if (data_src && data_src->next /* only needed if there are more than one data source */)
		{
			guint count = g_slist_length((GSList *) data_src);
			guint i;

			tvbs = (tvbuff_t **) g_malloc((count + 1) * sizeof(*tvbs));

			for (i = 0; i < count; i++)
			{
				struct data_source *src = (struct data_source *) g_slist_nth_data((GSList *) data_src, i);

				tvbs[i] = get_data_source_tvb(src);
			}

			tvbs[count] = NULL;
		}

		sharkd_session_process_frame_cb_tree(tree, tvbs);

		g_free(tvbs);
	}

	if (cinfo)
	{
		int col;

		printf(",\"col\":[");
		for (col = 0; col < cinfo->num_cols; ++col)
		{
			const col_item_t *col_item = &cinfo->columns[col];

			printf("%s\"%s\"", (col) ? "," : "", col_item->col_data);
		}
		printf("]");
	}

	if (data_src)
	{
		struct data_source *src = (struct data_source *)data_src->data;
		const char *ds_sepa = NULL;

		tvbuff_t *tvb;
		guint length;

		tvb = get_data_source_tvb(src);
		length = tvb_captured_length(tvb);

		printf(",\"bytes\":");
		if (length != 0)
		{
			const guchar *cp = tvb_get_ptr(tvb, 0, length);

			/* XXX pi.fd->flags.encoding */
			json_print_base64(cp, length);
		}
		else
		{
			json_print_base64("", 0);
		}

		data_src = data_src->next;
		if (data_src)
		{
			printf(",\"ds\":[");
			ds_sepa = "";
		}

		while (data_src)
		{
			src = (struct data_source *)data_src->data;

			{
				char *src_name = get_data_source_name(src);

				printf("%s{\"name\":", ds_sepa);
				json_puts_string(src_name);
				wmem_free(NULL, src_name);
			}

			tvb = get_data_source_tvb(src);
			length = tvb_captured_length(tvb);

			printf(",\"bytes\":");
			if (length != 0)
			{
				const guchar *cp = tvb_get_ptr(tvb, 0, length);

				/* XXX pi.fd->flags.encoding */
				json_print_base64(cp, length);
			}
			else
			{
				json_print_base64("", 0);
			}

			printf("}");
			ds_sepa = ",";

			data_src = data_src->next;
		}

		/* close ds, only if was opened */
		if (ds_sepa != NULL)
			printf("]");
	}

	printf(",\"fol\":[0");
	follow_iterate_followers(sharkd_follower_visit_layers_cb, pi);
	printf("]");

	printf("}\n");
}

/**
 * sharkd_session_process_intervals()
 *
 * Process intervals request - generate basic capture file statistics per requested interval.
 *
 * Input:
 *   (o) interval - interval time in ms, if not specified: 1000ms
 *   (o) filter   - filter for generating interval request
 *
 * Output object with attributes:
 *   (m) intervals - array of intervals, with indexes:
 *             [0] - index of interval,
 *             [1] - number of frames during interval,
 *             [2] - number of bytes during interval.
 *
 *   (m) last   - last interval number.
 *   (m) frames - total number of frames
 *   (m) bytes  - total number of bytes
 *
 * NOTE: If frames are not in order, there might be items with same interval index, or even negative one.
 */
static void
sharkd_session_process_intervals(char *buf, const jsmntok_t *tokens, int count)
{
	const char *tok_interval = json_find_attr(buf, tokens, count, "interval");
	const char *tok_filter = json_find_attr(buf, tokens, count, "filter");

	const guint8 *filter_data = NULL;

	struct
	{
		unsigned int frames;
		guint64 bytes;
	} st, st_total;

	nstime_t *start_ts = NULL;

	guint32 interval_ms = 1000; /* default: one per second */

	const char *sepa = "";
	unsigned int framenum;
	gint64 idx;
	gint64 max_idx = 0;

	if (tok_interval) {
		if (!ws_strtou32(tok_interval, NULL, &interval_ms) || interval_ms == 0) {
			fprintf(stderr, "Invalid interval parameter: %s.\n", tok_interval);
			return;
		}
	}

	if (tok_filter)
	{
		filter_data = sharkd_session_filter_data(tok_filter);
		if (!filter_data)
			return;
	}

	st_total.frames = 0;
	st_total.bytes  = 0;

	st.frames = 0;
	st.bytes  = 0;

	idx = 0;

	printf("{\"intervals\":[");

	for (framenum = 1; framenum <= cfile.count; framenum++)
	{
		frame_data *fdata = frame_data_sequence_find(cfile.frames, framenum);
		gint64 msec_rel;
		gint64 new_idx;

		if (start_ts == NULL)
			start_ts = &fdata->abs_ts;

		if (filter_data && !(filter_data[framenum / 8] & (1 << (framenum % 8))))
			continue;

		msec_rel = (fdata->abs_ts.secs - start_ts->secs) * (gint64) 1000 + (fdata->abs_ts.nsecs - start_ts->nsecs) / 1000000;
		new_idx  = msec_rel / interval_ms;

		if (idx != new_idx)
		{
			if (st.frames != 0)
			{
				printf("%s[%" G_GINT64_FORMAT ",%u,%" G_GUINT64_FORMAT "]", sepa, idx, st.frames, st.bytes);
				sepa = ",";
			}

			idx = new_idx;
			if (idx > max_idx)
				max_idx = idx;

			st.frames = 0;
			st.bytes  = 0;
		}

		st.frames += 1;
		st.bytes  += fdata->pkt_len;

		st_total.frames += 1;
		st_total.bytes  += fdata->pkt_len;
	}

	if (st.frames != 0)
	{
		printf("%s[%" G_GINT64_FORMAT ",%u,%" G_GUINT64_FORMAT "]", sepa, idx, st.frames, st.bytes);
		/* sepa = ","; */
	}

	printf("],\"last\":%" G_GINT64_FORMAT ",\"frames\":%u,\"bytes\":%" G_GUINT64_FORMAT "}\n", max_idx, st_total.frames, st_total.bytes);
}

/**
 * sharkd_session_process_frame()
 *
 * Process frame request
 *
 * Input:
 *   (m) frame - requested frame number
 *   (o) proto - set if output frame tree
 *   (o) columns - set if output frame columns
 *   (o) bytes - set if output frame bytes
 *
 * Output object with attributes:
 *   (m) err   - 0 if succeed
 *   (o) tree  - array of frame nodes with attributes:
 *                  l - label
 *                  t: 'proto', 'framenum', 'url' - type of node
 *                  s - severity
 *                  e - subtree ett index
 *                  n - array of subtree nodes
 *                  h - two item array: (item start, item length)
 *                  i - two item array: (appendix start, appendix length)
 *                  p - [RESERVED] two item array: (protocol start, protocol length)
 *                  ds- data src index
 *                  url  - only for t:'url', url
 *                  fnum - only for t:'framenum', frame number
 *
 *   (o) col   - array of column data
 *   (o) bytes - base64 of frame bytes
 *   (o) ds    - array of other data srcs
 *   (o) fol   - array of follow filters:
 *                  [0] - protocol
 *                  [1] - filter string
 */
static void
sharkd_session_process_frame(char *buf, const jsmntok_t *tokens, int count)
{
	const char *tok_frame = json_find_attr(buf, tokens, count, "frame");
	int tok_proto   = (json_find_attr(buf, tokens, count, "proto") != NULL);
	int tok_bytes   = (json_find_attr(buf, tokens, count, "bytes") != NULL);
	int tok_columns = (json_find_attr(buf, tokens, count, "columns") != NULL);

	guint32 framenum;

	if (!tok_frame || !ws_strtou32(tok_frame, NULL, &framenum) || framenum == 0)
		return;

	sharkd_dissect_request(framenum, &sharkd_session_process_frame_cb, tok_bytes, tok_columns, tok_proto, NULL);
}

/**
 * sharkd_session_process_check()
 *
 * Process check request.
 *
 * Input:
 *   (o) filter - filter to be checked
 *
 * Output object with attributes:
 *   (m) err - always 0
 *   (o) filter - 'ok', 'warn' or error message
 */
static int
sharkd_session_process_check(char *buf, const jsmntok_t *tokens, int count)
{
	const char *tok_filter = json_find_attr(buf, tokens, count, "filter");

	printf("{\"err\":0");
	if (tok_filter != NULL)
	{
		char *err_msg = NULL;
		dfilter_t *dfp;

		if (dfilter_compile(tok_filter, &dfp, &err_msg))
		{
			const char *s = "ok";

			if (dfilter_deprecated_tokens(dfp))
				s = "warn";

			printf(",\"filter\":\"%s\"", s);
			dfilter_free(dfp);
		}
		else
		{
			printf(",\"filter\":");
			json_puts_string(err_msg);
			g_free(err_msg);
		}
	}

	printf("}\n");
	return 0;
}

struct sharkd_session_process_complete_pref_data
{
	const char *module;
	const char *pref;
	const char *sepa;
};

static guint
sharkd_session_process_complete_pref_cb(module_t *module, gpointer d)
{
	struct sharkd_session_process_complete_pref_data *data = (struct sharkd_session_process_complete_pref_data *) d;

	if (strncmp(data->pref, module->name, strlen(data->pref)) != 0)
		return 0;

	printf("%s{\"f\":\"%s\",\"d\":\"%s\"}", data->sepa, module->name, module->title);
	data->sepa = ",";

	return 0;
}

static guint
sharkd_session_process_complete_pref_option_cb(pref_t *pref, gpointer d)
{
	struct sharkd_session_process_complete_pref_data *data = (struct sharkd_session_process_complete_pref_data *) d;
	const char *pref_name = prefs_get_name(pref);
	const char *pref_title = prefs_get_title(pref);

	if (strncmp(data->pref, pref_name, strlen(data->pref)) != 0)
		return 0;

	printf("%s{\"f\":\"%s.%s\",\"d\":\"%s\"}", data->sepa, data->module, pref_name, pref_title);
	data->sepa = ",";

	return 0; /* continue */
}

/**
 * sharkd_session_process_complete()
 *
 * Process complete request
 *
 * Input:
 *   (o) field - field to be completed
 *   (o) pref  - preference to be completed
 *
 * Output object with attributes:
 *   (m) err - always 0
 *   (o) field - array of object with attributes:
 *                  (m) f - field text
 *                  (o) t - field type (FT_ number)
 *                  (o) n - field name
 *   (o) pref  - array of object with attributes:
 *                  (m) f - pref name
 *                  (o) d - pref description
 */
static int
sharkd_session_process_complete(char *buf, const jsmntok_t *tokens, int count)
{
	const char *tok_field = json_find_attr(buf, tokens, count, "field");
	const char *tok_pref  = json_find_attr(buf, tokens, count, "pref");

	printf("{\"err\":0");
	if (tok_field != NULL && tok_field[0])
	{
		const size_t filter_length = strlen(tok_field);
		const int filter_with_dot = !!strchr(tok_field, '.');

		void *proto_cookie;
		void *field_cookie;
		int proto_id;
		const char *sepa = "";

		printf(",\"field\":[");

		for (proto_id = proto_get_first_protocol(&proto_cookie); proto_id != -1; proto_id = proto_get_next_protocol(&proto_cookie))
		{
			protocol_t *protocol = find_protocol_by_id(proto_id);
			const char *protocol_filter;
			const char *protocol_name;
			header_field_info *hfinfo;

			if (!proto_is_protocol_enabled(protocol))
				continue;

			protocol_name   = proto_get_protocol_long_name(protocol);
			protocol_filter = proto_get_protocol_filter_name(proto_id);

			if (strlen(protocol_filter) >= filter_length && !g_ascii_strncasecmp(tok_field, protocol_filter, filter_length))
			{
				printf("%s{", sepa);
				{
					printf("\"f\":");
					json_puts_string(protocol_filter);
					printf(",\"t\":%d", FT_PROTOCOL);
					printf(",\"n\":");
					json_puts_string(protocol_name);
				}
				printf("}");
				sepa = ",";
			}

			if (!filter_with_dot)
				continue;

			for (hfinfo = proto_get_first_protocol_field(proto_id, &field_cookie); hfinfo != NULL; hfinfo = proto_get_next_protocol_field(proto_id, &field_cookie))
			{
				if (hfinfo->same_name_prev_id != -1) /* ignore duplicate names */
					continue;

				if (strlen(hfinfo->abbrev) >= filter_length && !g_ascii_strncasecmp(tok_field, hfinfo->abbrev, filter_length))
				{
					printf("%s{", sepa);
					{
						printf("\"f\":");
						json_puts_string(hfinfo->abbrev);

						/* XXX, skip displaying name, if there are multiple (to not confuse user) */
						if (hfinfo->same_name_next == NULL)
						{
							printf(",\"t\":%d", hfinfo->type);
							printf(",\"n\":");
							json_puts_string(hfinfo->name);
						}
					}
					printf("}");
					sepa = ",";
				}
			}
		}

		printf("]");
	}

	if (tok_pref != NULL && tok_pref[0])
	{
		struct sharkd_session_process_complete_pref_data data;
		char *dot_sepa;

		data.module = tok_pref;
		data.pref = tok_pref;
		data.sepa = "";

		printf(",\"pref\":[");

		if ((dot_sepa = strchr(tok_pref, '.')))
		{
			module_t *pref_mod;

			*dot_sepa = '\0'; /* XXX, C abuse: discarding-const */
			data.pref = dot_sepa + 1;

			pref_mod = prefs_find_module(data.module);
			if (pref_mod)
				prefs_pref_foreach(pref_mod, sharkd_session_process_complete_pref_option_cb, &data);

			*dot_sepa = '.';
		}
		else
		{
			prefs_modules_foreach(sharkd_session_process_complete_pref_cb, &data);
		}

		printf("]");
	}


	printf("}\n");
	return 0;
}

/**
 * sharkd_session_process_setconf()
 *
 * Process setconf request
 *
 * Input:
 *   (m) name  - preference name
 *   (m) value - preference value
 *
 * Output object with attributes:
 *   (m) err   - error code: 0 succeed
 */
static void
sharkd_session_process_setconf(char *buf, const jsmntok_t *tokens, int count)
{
	const char *tok_name = json_find_attr(buf, tokens, count, "name");
	const char *tok_value = json_find_attr(buf, tokens, count, "value");
	char pref[4096];
	char *errmsg = NULL;

	prefs_set_pref_e ret;

	if (!tok_name || tok_name[0] == '\0' || !tok_value)
		return;

	ws_snprintf(pref, sizeof(pref), "%s:%s", tok_name, tok_value);

	ret = prefs_set_pref(pref, &errmsg);
	printf("{\"err\":%d", ret);
	if (errmsg) {
		/* Add error message for some syntax errors. */
		printf(",\"errmsg\":");
		json_puts_string(errmsg);
	}
	printf("}\n");
	g_free(errmsg);
}

struct sharkd_session_process_dumpconf_data
{
	module_t *module;
	const char *sepa;
};

static guint
sharkd_session_process_dumpconf_cb(pref_t *pref, gpointer d)
{
	struct sharkd_session_process_dumpconf_data *data = (struct sharkd_session_process_dumpconf_data *) d;
	const char *pref_name = prefs_get_name(pref);

	printf("%s\"%s.%s\":{", data->sepa, data->module->name, pref_name);

	switch (prefs_get_type(pref))
	{
		case PREF_UINT:
		case PREF_DECODE_AS_UINT:
			printf("\"u\":%u", prefs_get_uint_value_real(pref, pref_current));
			if (prefs_get_uint_base(pref) != 10)
				printf(",\"ub\":%u", prefs_get_uint_base(pref));
			break;

		case PREF_BOOL:
			printf("\"b\":%s", prefs_get_bool_value(pref, pref_current) ? "1" : "0");
			break;

		case PREF_STRING:
			printf("\"s\":");
			json_puts_string(prefs_get_string_value(pref, pref_current));
			break;

		case PREF_ENUM:
		{
			const enum_val_t *enums;
			const char *enum_sepa = "";

			printf("\"e\":[");
			for (enums = prefs_get_enumvals(pref); enums->name; enums++)
			{
				printf("%s{\"v\":%d", enum_sepa, enums->value);

				if (enums->value == prefs_get_enum_value(pref, pref_current))
					printf(",\"s\":1");

				printf(",\"d\":");
				json_puts_string(enums->description);

				printf("}");
				enum_sepa = ",";
			}
			printf("]");
			break;
		}

		case PREF_RANGE:
		case PREF_DECODE_AS_RANGE:
		{
			char *range_str = range_convert_range(NULL, prefs_get_range_value_real(pref, pref_current));
			printf("\"r\":\"%s\"", range_str);
			wmem_free(NULL, range_str);
			break;
		}

		case PREF_UAT:
		{
			uat_t *uat = prefs_get_uat_value(pref);
			guint idx;

			printf("\"t\":[");
			for (idx = 0; idx < uat->raw_data->len; idx++)
			{
				void *rec = UAT_INDEX_PTR(uat, idx);
				guint colnum;

				if (idx)
					printf(",");

				printf("[");
				for (colnum = 0; colnum < uat->ncols; colnum++)
				{
					char *str = uat_fld_tostr(rec, &(uat->fields[colnum]));

					if (colnum)
						printf(",");

					json_puts_string(str);
					g_free(str);
				}

				printf("]");
			}

			printf("]");
			break;
		}

		case PREF_COLOR:
		case PREF_CUSTOM:
		case PREF_STATIC_TEXT:
		case PREF_OBSOLETE:
			/* TODO */
			break;
	}

#if 0
	printf(",\"t\":");
	json_puts_string(prefs_get_title(pref));
#endif

	printf("}");
	data->sepa = ",";

	return 0; /* continue */
}

static guint
sharkd_session_process_dumpconf_mod_cb(module_t *module, gpointer d)
{
	struct sharkd_session_process_dumpconf_data *data = (struct sharkd_session_process_dumpconf_data *) d;

	data->module = module;
	prefs_pref_foreach(module, sharkd_session_process_dumpconf_cb, data);

	return 0;
}

/**
 * sharkd_session_process_dumpconf()
 *
 * Process dumpconf request
 *
 * Input:
 *   (o) pref - module, or preference, NULL for all
 *
 * Output object with attributes:
 *   (o) prefs   - object with module preferences
 *                  (m) [KEY] - preference name
 *                  (o) u - preference value (only for PREF_UINT)
 *                  (o) ub - preference value suggested base for display (only for PREF_UINT) and if different than 10
 *                  (o) b - preference value (only for PREF_BOOL) (1 true, 0 false)
 *                  (o) s - preference value (only for PREF_STRING)
 *                  (o) e - preference possible values (only for PREF_ENUM)
 *                  (o) r - preference value (only for PREF_RANGE)
 *                  (o) t - preference value (only for PREF_UAT)
 */
static void
sharkd_session_process_dumpconf(char *buf, const jsmntok_t *tokens, int count)
{
	const char *tok_pref = json_find_attr(buf, tokens, count, "pref");
	module_t *pref_mod;
	char *dot_sepa;

	if (!tok_pref)
	{
		struct sharkd_session_process_dumpconf_data data;

		data.module = NULL;
		data.sepa = "";

		printf("{\"prefs\":{");
		prefs_modules_foreach(sharkd_session_process_dumpconf_mod_cb, &data);
		printf("}}\n");
		return;
	}

	if ((dot_sepa = strchr(tok_pref, '.')))
	{
		pref_t *pref = NULL;

		*dot_sepa = '\0'; /* XXX, C abuse: discarding-const */
		pref_mod = prefs_find_module(tok_pref);
		if (pref_mod)
			pref = prefs_find_preference(pref_mod, dot_sepa + 1);
		*dot_sepa = '.';

		if (pref)
		{
			struct sharkd_session_process_dumpconf_data data;

			data.module = pref_mod;
			data.sepa = "";

			printf("{\"prefs\":{");
			sharkd_session_process_dumpconf_cb(pref, &data);
			printf("}}\n");
		}

		return;
	}

	pref_mod = prefs_find_module(tok_pref);
	if (pref_mod)
	{
		struct sharkd_session_process_dumpconf_data data;

		data.module = pref_mod;
		data.sepa = "";

		printf("{\"prefs\":{");
		prefs_pref_foreach(pref_mod, sharkd_session_process_dumpconf_cb, &data);
		printf("}}\n");
    }
}

struct sharkd_download_rtp
{
	struct sharkd_rtp_match rtp;
	GSList *packets;
	double start_time;
};

static void
sharkd_rtp_download_free_items(void *ptr)
{
	rtp_packet_t *rtp_packet = (rtp_packet_t *) ptr;

	g_free(rtp_packet->info);
	g_free(rtp_packet->payload_data);
	g_free(rtp_packet);
}

static void
sharkd_rtp_download_decode(struct sharkd_download_rtp *req)
{
	/* based on RtpAudioStream::decode() 6e29d874f8b5e6ebc59f661a0bb0dab8e56f122a */
	/* TODO, for now only without silence (timing_mode_ = Uninterrupted) */

	static const int sample_bytes_ = sizeof(SAMPLE) / sizeof(char);

	guint32 audio_out_rate_ = 0;
	struct _GHashTable *decoders_hash_ = rtp_decoder_hash_table_new();
	struct SpeexResamplerState_ *audio_resampler_ = NULL;

	gsize resample_buff_len = 0x1000;
	SAMPLE *resample_buff = (SAMPLE *) g_malloc(resample_buff_len);
	spx_uint32_t cur_in_rate = 0;
	char *write_buff = NULL;
	gint64 write_bytes = 0;
	unsigned channels = 0;
	unsigned sample_rate = 0;

	int i;
	int base64_state1 = 0;
	int base64_state2 = 0;

	GSList *l;

	for (l = req->packets; l; l = l->next)
	{
		rtp_packet_t *rtp_packet = (rtp_packet_t *) l->data;

		SAMPLE *decode_buff = NULL;
		size_t decoded_bytes;

		decoded_bytes = decode_rtp_packet(rtp_packet, &decode_buff, decoders_hash_, &channels, &sample_rate);
		if (decoded_bytes == 0 || sample_rate == 0)
		{
			/* We didn't decode anything. Clean up and prep for the next packet. */
			g_free(decode_buff);
			continue;
		}

		if (audio_out_rate_ == 0)
		{
			guint32 tmp32;
			guint16 tmp16;
			char wav_hdr[44];

			/* First non-zero wins */
			audio_out_rate_ = sample_rate;

			RTP_STREAM_DEBUG("Audio sample rate is %u", audio_out_rate_);

			/* write WAVE header */
			memset(&wav_hdr, 0, sizeof(wav_hdr));
			memcpy(&wav_hdr[0], "RIFF", 4);
			memcpy(&wav_hdr[4], "\xFF\xFF\xFF\xFF", 4); /* XXX, unknown */
			memcpy(&wav_hdr[8], "WAVE", 4);

			memcpy(&wav_hdr[12], "fmt ", 4);
			memcpy(&wav_hdr[16], "\x10\x00\x00\x00", 4); /* PCM */
			memcpy(&wav_hdr[20], "\x01\x00", 2);         /* PCM */
			/* # channels */
			tmp16 = channels;
			memcpy(&wav_hdr[22], &tmp16, 2);
			/* sample rate */
			tmp32 = sample_rate;
			memcpy(&wav_hdr[24], &tmp32, 4);
			/* byte rate */
			tmp32 = sample_rate * channels * sample_bytes_;
			memcpy(&wav_hdr[28], &tmp32, 4);
			/* block align */
			tmp16 = channels * sample_bytes_;
			memcpy(&wav_hdr[32], &tmp16, 2);
			/* bits per sample */
			tmp16 = 8 * sample_bytes_;
			memcpy(&wav_hdr[34], &tmp16, 2);

			memcpy(&wav_hdr[36], "data", 4);
			memcpy(&wav_hdr[40], "\xFF\xFF\xFF\xFF", 4); /* XXX, unknown */

			for (i = 0; i < (int) sizeof(wav_hdr); i++)
				json_print_base64_step(&wav_hdr[i], &base64_state1, &base64_state2);
		}

		// Write samples to our file.
		write_buff = (char *) decode_buff;
		write_bytes = decoded_bytes;

		if (audio_out_rate_ != sample_rate)
		{
			spx_uint32_t in_len, out_len;

			/* Resample the audio to match our previous output rate. */
			if (!audio_resampler_)
			{
				audio_resampler_ = speex_resampler_init(1, sample_rate, audio_out_rate_, 10, NULL);
				speex_resampler_skip_zeros(audio_resampler_);
				RTP_STREAM_DEBUG("Started resampling from %u to (out) %u Hz.", sample_rate, audio_out_rate_);
			}
			else
			{
				spx_uint32_t audio_out_rate;
				speex_resampler_get_rate(audio_resampler_, &cur_in_rate, &audio_out_rate);

				if (sample_rate != cur_in_rate)
				{
					speex_resampler_set_rate(audio_resampler_, sample_rate, audio_out_rate);
					RTP_STREAM_DEBUG("Changed input rate from %u to %u Hz. Out is %u.", cur_in_rate, sample_rate, audio_out_rate_);
				}
			}
			in_len = (spx_uint32_t)rtp_packet->info->info_payload_len;
			out_len = (audio_out_rate_ * (spx_uint32_t)rtp_packet->info->info_payload_len / sample_rate) + (audio_out_rate_ % sample_rate != 0);
			if (out_len * sample_bytes_ > resample_buff_len)
			{
				while ((out_len * sample_bytes_ > resample_buff_len))
					resample_buff_len *= 2;
				resample_buff = (SAMPLE *) g_realloc(resample_buff, resample_buff_len);
			}

			speex_resampler_process_int(audio_resampler_, 0, decode_buff, &in_len, resample_buff, &out_len);
			write_buff = (char *) resample_buff;
			write_bytes = out_len * sample_bytes_;
		}

		/* Write the decoded, possibly-resampled audio */
		for (i = 0; i < write_bytes; i++)
			json_print_base64_step(&write_buff[i], &base64_state1, &base64_state2);

		g_free(decode_buff);
	}

	json_print_base64_step(NULL, &base64_state1, &base64_state2);

	g_free(resample_buff);
	g_hash_table_destroy(decoders_hash_);
}

static gboolean
sharkd_session_packet_download_tap_rtp_cb(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *data)
{
	const struct _rtp_info *rtp_info = (const struct _rtp_info *) data;
	struct sharkd_download_rtp *req_rtp = (struct sharkd_download_rtp *) tapdata;

	/* do not consider RTP packets without a setup frame */
	if (rtp_info->info_setup_frame_num == 0)
		return FALSE;

	if (sharkd_rtp_match_check(&req_rtp->rtp, pinfo, rtp_info))
	{
		rtp_packet_t *rtp_packet;

		rtp_packet = g_new0(rtp_packet_t, 1);
		rtp_packet->info = (struct _rtp_info *) g_memdup(rtp_info, sizeof(struct _rtp_info));

		if (rtp_info->info_all_data_present && rtp_info->info_payload_len != 0)
			rtp_packet->payload_data = (guint8 *) g_memdup(&(rtp_info->info_data[rtp_info->info_payload_offset]), rtp_info->info_payload_len);

		if (!req_rtp->packets)
			req_rtp->start_time = nstime_to_sec(&pinfo->abs_ts);

		rtp_packet->frame_num = pinfo->num;
		rtp_packet->arrive_offset = nstime_to_sec(&pinfo->abs_ts) - req_rtp->start_time;

		/* XXX, O(n) optimize */
		req_rtp->packets = g_slist_append(req_rtp->packets, rtp_packet);
	}

	return FALSE;
}

/**
 * sharkd_session_process_download()
 *
 * Process download request
 *
 * Input:
 *   (m) token  - token to download
 *
 * Output object with attributes:
 *   (o) file - suggested name of file
 *   (o) mime - suggested content type
 *   (o) data - payload base64 encoded
 */
static void
sharkd_session_process_download(char *buf, const jsmntok_t *tokens, int count)
{
	const char *tok_token      = json_find_attr(buf, tokens, count, "token");

	if (!tok_token)
		return;

	if (!strncmp(tok_token, "eo:", 3))
	{
		struct sharkd_export_object_list *object_list;
		const export_object_entry_t *eo_entry = NULL;

		for (object_list = sharkd_eo_list; object_list; object_list = object_list->next)
		{
			size_t eo_type_len = strlen(object_list->type);

			if (!strncmp(tok_token, object_list->type, eo_type_len) && tok_token[eo_type_len] == '_')
			{
				int row;

				if (sscanf(&tok_token[eo_type_len + 1], "%d", &row) != 1)
					break;

				eo_entry = (export_object_entry_t *) g_slist_nth_data(object_list->entries, row);
				break;
			}
		}

		if (eo_entry)
		{
			const char *mime     = (eo_entry->content_type) ? eo_entry->content_type : "application/octet-stream";
			const char *filename = (eo_entry->filename) ? eo_entry->filename : tok_token;

			printf("{\"file\":");
			json_puts_string(filename);
			printf(",\"mime\":");
			json_puts_string(mime);
			printf(",\"data\":");
			json_print_base64(eo_entry->payload_data, (int) eo_entry->payload_len); /* XXX, export object will be truncated if >= 2^31 */
			printf("}\n");
		}
	}
	else if (!strcmp(tok_token, "ssl-secrets"))
	{
		char *str = ssl_export_sessions();

		if (str)
		{
			const char *mime     = "text/plain";
			const char *filename = "keylog.txt";

			printf("{\"file\":");
			json_puts_string(filename);
			printf(",\"mime\":");
			json_puts_string(mime);
			printf(",\"data\":");
			json_print_base64(str, strlen(str));
			printf("}\n");
		}
		g_free(str);
	}
	else if (!strncmp(tok_token, "rtp:", 4))
	{
		struct sharkd_download_rtp rtp_req;
		GString *tap_error;

		memset(&rtp_req, 0, sizeof(rtp_req));
		if (!sharkd_rtp_match_init(&rtp_req.rtp, tok_token + 4))
		{
			fprintf(stderr, "sharkd_session_process_download() rtp tokenizing error %s\n", tok_token);
			return;
		}

		tap_error = register_tap_listener("rtp", &rtp_req, NULL, 0, NULL, sharkd_session_packet_download_tap_rtp_cb, NULL);
		if (tap_error)
		{
			fprintf(stderr, "sharkd_session_process_download() rtp error=%s", tap_error->str);
			g_string_free(tap_error, TRUE);
			return;
		}

		sharkd_retap();
		remove_tap_listener(&rtp_req);

		if (rtp_req.packets)
		{
			const char *mime     = "audio/x-wav";
			const char *filename = tok_token;

			printf("{\"file\":");
			json_puts_string(filename);
			printf(",\"mime\":");
			json_puts_string(mime);

			printf(",\"data\":");
			putchar('"');
			sharkd_rtp_download_decode(&rtp_req);
			putchar('"');

			printf("}\n");

			g_slist_free_full(rtp_req.packets, sharkd_rtp_download_free_items);
		}
	}
}

static void
sharkd_session_process(char *buf, const jsmntok_t *tokens, int count)
{
	int i;

	/* sanity check, and split strings */
	if (count < 1 || tokens[0].type != JSMN_OBJECT)
	{
		fprintf(stderr, "sanity check(1): [0] not object\n");
		return;
	}

	/* don't need [0] token */
	tokens++;
	count--;

	if (count & 1)
	{
		fprintf(stderr, "sanity check(2): %d not even\n", count);
		return;
	}

	for (i = 0; i < count; i += 2)
	{
		if (tokens[i].type != JSMN_STRING)
		{
			fprintf(stderr, "sanity check(3): [%d] not string\n", i);
			return;
		}

		buf[tokens[i + 0].end] = '\0';
		buf[tokens[i + 1].end] = '\0';

		json_unescape_str(&buf[tokens[i + 0].start]);
		json_unescape_str(&buf[tokens[i + 1].start]);
	}

	{
		const char *tok_req = json_find_attr(buf, tokens, count, "req");

		if (!tok_req)
		{
			fprintf(stderr, "sanity check(4): no \"req\".\n");
			return;
		}

		if (!strcmp(tok_req, "load"))
			sharkd_session_process_load(buf, tokens, count);
		else if (!strcmp(tok_req, "status"))
			sharkd_session_process_status();
		else if (!strcmp(tok_req, "analyse"))
			sharkd_session_process_analyse();
		else if (!strcmp(tok_req, "info"))
			sharkd_session_process_info();
		else if (!strcmp(tok_req, "check"))
			sharkd_session_process_check(buf, tokens, count);
		else if (!strcmp(tok_req, "complete"))
			sharkd_session_process_complete(buf, tokens, count);
		else if (!strcmp(tok_req, "frames"))
			sharkd_session_process_frames(buf, tokens, count);
		else if (!strcmp(tok_req, "tap"))
			sharkd_session_process_tap(buf, tokens, count);
		else if (!strcmp(tok_req, "follow"))
			sharkd_session_process_follow(buf, tokens, count);
		else if (!strcmp(tok_req, "intervals"))
			sharkd_session_process_intervals(buf, tokens, count);
		else if (!strcmp(tok_req, "frame"))
			sharkd_session_process_frame(buf, tokens, count);
		else if (!strcmp(tok_req, "setconf"))
			sharkd_session_process_setconf(buf, tokens, count);
		else if (!strcmp(tok_req, "dumpconf"))
			sharkd_session_process_dumpconf(buf, tokens, count);
		else if (!strcmp(tok_req, "download"))
			sharkd_session_process_download(buf, tokens, count);
		else if (!strcmp(tok_req, "bye"))
			exit(0);
		else
			fprintf(stderr, "::: req = %s\n", tok_req);

		/* reply for every command are 0+ lines of JSON reply (outputed above), finished by empty new line */
		printf("\n");

		/*
		 * We do an explicit fflush after every line, because
		 * we want output to be written to the socket as soon
		 * as the line is complete.
		 *
		 * The stream is fully-buffered by default, so it's
		 * only flushed when the buffer fills or the FILE *
		 * is closed.  On UN*X, we could set it to be line
		 * buffered, but the MSVC standard I/O routines don't
		 * support line buffering - they only support *byte*
		 * buffering, doing a write for every byte written,
		 * which is too inefficient, and full buffering,
		 * which is what you get if you request line buffering.
		 */
		fflush(stdout);
	}
}

int
sharkd_session_main(void)
{
	char buf[2 * 1024];
	jsmntok_t *tokens = NULL;
	int tokens_max = -1;

	fprintf(stderr, "Hello in child.\n");

	while (fgets(buf, sizeof(buf), stdin))
	{
		/* every command is line seperated JSON */
		int ret;

		ret = wsjsmn_parse(buf, NULL, 0);
		if (ret < 0)
		{
			fprintf(stderr, "invalid JSON -> closing\n");
			return 1;
		}

		/* fprintf(stderr, "JSON: %d tokens\n", ret); */
		ret += 1;

		if (tokens == NULL || tokens_max < ret)
		{
			tokens_max = ret;
			tokens = (jsmntok_t *) g_realloc(tokens, sizeof(jsmntok_t) * tokens_max);
		}

		memset(tokens, 0, ret * sizeof(jsmntok_t));

		ret = wsjsmn_parse(buf, tokens, ret);
		if (ret < 0)
		{
			fprintf(stderr, "invalid JSON(2) -> closing\n");
			return 2;
		}

		sharkd_session_process(buf, tokens, ret);
	}

	g_free(tokens);

	return 0;
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
