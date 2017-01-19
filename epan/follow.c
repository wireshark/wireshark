/* follow.c
 *
 * Copyright 1998 Mike Hall <mlh@io.com>
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
 *
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include "follow.h"
#include <epan/tap.h>

struct register_follow {
    int proto_id;              /* protocol id (0-indexed) */
    const char* tap_listen_str;      /* string used in register_tap_listener */
    follow_conv_filter_func conv_filter;  /* generate "conversation" filter to follow */
    follow_index_filter_func index_filter; /* generate stream/index filter to follow */
    follow_address_filter_func address_filter; /* generate address filter to follow */
    follow_port_to_display_func port_to_display; /* port to name resolution for follow type */
    follow_tap_func tap_handler; /* tap listener handler */
};

static GSList *registered_followers = NULL;

static gint
insert_sorted_by_name(gconstpointer aparam, gconstpointer bparam)
{
    const register_follow_t *a = (const register_follow_t *)aparam;
    const register_follow_t *b = (const register_follow_t *)bparam;

    return g_ascii_strcasecmp(proto_get_protocol_short_name(find_protocol_by_id(a->proto_id)), proto_get_protocol_short_name(find_protocol_by_id(b->proto_id)));
}

void register_follow_stream(const int proto_id, const char* tap_listener,
                            follow_conv_filter_func conv_filter, follow_index_filter_func index_filter, follow_address_filter_func address_filter,
                            follow_port_to_display_func port_to_display, follow_tap_func tap_handler)
{
  register_follow_t *follower;
  DISSECTOR_ASSERT(tap_listener);
  DISSECTOR_ASSERT(conv_filter);
  DISSECTOR_ASSERT(index_filter);
  DISSECTOR_ASSERT(address_filter);
  DISSECTOR_ASSERT(port_to_display);
  DISSECTOR_ASSERT(tap_handler);

  follower = g_new(register_follow_t,1);

  follower->proto_id       = proto_id;
  follower->tap_listen_str = tap_listener;
  follower->conv_filter    = conv_filter;
  follower->index_filter   = index_filter;
  follower->address_filter = address_filter;
  follower->port_to_display = port_to_display;
  follower->tap_handler    = tap_handler;

  registered_followers = g_slist_insert_sorted(registered_followers, follower, insert_sorted_by_name);
}

int get_follow_proto_id(register_follow_t* follower)
{
  if (follower == NULL)
    return -1;

  return follower->proto_id;
}

const char* get_follow_tap_string(register_follow_t* follower)
{
  if (follower == NULL)
    return "";

  return follower->tap_listen_str;
}

follow_conv_filter_func get_follow_conv_func(register_follow_t* follower)
{
  return follower->conv_filter;
}

follow_index_filter_func get_follow_index_func(register_follow_t* follower)
{
  return follower->index_filter;
}

follow_address_filter_func get_follow_address_func(register_follow_t* follower)
{
  return follower->address_filter;
}

follow_port_to_display_func get_follow_port_to_display(register_follow_t* follower)
{
  return follower->port_to_display;
}

follow_tap_func get_follow_tap_handler(register_follow_t* follower)
{
  return follower->tap_handler;
}


static gint
find_matching_follower(gconstpointer arg1, gconstpointer arg2)
{
  register_follow_t *follower = (register_follow_t *)arg1;
  const gchar          *name   = (const gchar *)arg2;

  return strcmp(proto_get_protocol_short_name(find_protocol_by_id(follower->proto_id)), name);
}

register_follow_t* get_follow_by_name(const char* proto_short_name)
{
  GSList *found_follower;

  found_follower = g_slist_find_custom(registered_followers,
                    (gpointer)proto_short_name, find_matching_follower);

  if (found_follower)
    return (register_follow_t*)found_follower->data;

  return NULL;
}

void follow_iterate_followers(GFunc func, gpointer user_data)
{
    g_slist_foreach(registered_followers, func, user_data);
}

gchar* follow_get_stat_tap_string(register_follow_t* follower)
{
    GString *cmd_str = g_string_new("follow,");
    g_string_append(cmd_str, proto_get_protocol_filter_name(follower->proto_id));
    return g_string_free(cmd_str, FALSE);
}

/* here we are going to try and reconstruct the data portion of a TCP
   session. We will try and handle duplicates, TCP fragments, and out
   of order packets in a smart way. */
void
follow_reset_stream(follow_info_t* info)
{
    info->bytes_written[0] = info->bytes_written[1] = 0;
    info->client_port = 0;
    info->server_port = 0;
    info->client_ip.type = FT_NONE;
    info->client_ip.len = 0;
    info->server_ip.type = FT_NONE;
    info->server_ip.len = 0;
    info->fragments[0] = info->fragments[1] = NULL;
    info->seq[0] = info->seq[1] = 0;
}

void
follow_info_free(follow_info_t* follow_info)
{
    GList *cur;
    follow_record_t *follow_record;

    for(cur = follow_info->payload; cur; cur = g_list_next(cur)) {
        if(cur->data) {
            follow_record = (follow_record_t *)cur->data;
            if(follow_record->data)
                g_byte_array_free(follow_record->data, TRUE);

            g_free(follow_record);
        }
    }
    g_list_free(follow_info->payload);

    //Only TCP stream uses fragments
    for (cur = follow_info->fragments[0]; cur; cur = g_list_next(cur)) {
        follow_record = (follow_record_t *)cur->data;
        if(follow_record->data) {
            g_byte_array_free(follow_record->data, TRUE);
        }
        g_free(follow_record);
    }
    for (cur = follow_info->fragments[1]; cur; cur = g_list_next(cur)) {
        follow_record = (follow_record_t *)cur->data;
        if(follow_record->data) {
            g_byte_array_free(follow_record->data, TRUE);
        }
        g_free(follow_record);
    }

    free_address(&follow_info->client_ip);
    free_address(&follow_info->server_ip);
    g_free(follow_info->filter_out_filter);
    g_free(follow_info);
}

gboolean
follow_tvb_tap_listener(void *tapdata, packet_info *pinfo,
                      epan_dissect_t *edt _U_, const void *data)
{
    follow_record_t *follow_record;
    follow_info_t *follow_info = (follow_info_t *)tapdata;
    tvbuff_t *next_tvb = (tvbuff_t *)data;

    follow_record = g_new(follow_record_t,1);

    follow_record->data = g_byte_array_sized_new(tvb_captured_length(next_tvb));
    follow_record->data = g_byte_array_append(follow_record->data,
                                              tvb_get_ptr(next_tvb, 0, -1),
                                              tvb_captured_length(next_tvb));
    follow_record->packet_num = pinfo->fd->num;

    if (follow_info->client_port == 0) {
        follow_info->client_port = pinfo->srcport;
        copy_address(&follow_info->client_ip, &pinfo->src);
        follow_info->server_port = pinfo->destport;
        copy_address(&follow_info->server_ip, &pinfo->dst);
    }

    if (addresses_equal(&follow_info->client_ip, &pinfo->src) && follow_info->client_port == pinfo->srcport)
        follow_record->is_server = FALSE;
    else
        follow_record->is_server = TRUE;

    /* update stream counter */
    follow_info->bytes_written[follow_record->is_server] += follow_record->data->len;

    follow_info->payload = g_list_append(follow_info->payload, follow_record);
    return FALSE;
}

static void
clear_follower(gpointer p, gpointer user_data _U_)
{
    g_free(p);
}

void
follow_cleanup(void)
{
    g_slist_foreach(registered_followers, clear_follower, NULL);
    g_slist_free(registered_followers);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
