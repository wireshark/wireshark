/* follow.c
 *
 * Copyright 1998 Mike Hall <mlh@io.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
    tap_packet_cb tap_handler; /* tap listener handler */
};

static wmem_tree_t *registered_followers = NULL;

void register_follow_stream(const int proto_id, const char* tap_listener,
                            follow_conv_filter_func conv_filter, follow_index_filter_func index_filter, follow_address_filter_func address_filter,
                            follow_port_to_display_func port_to_display, tap_packet_cb tap_handler)
{
  register_follow_t *follower;
  DISSECTOR_ASSERT(tap_listener);
  DISSECTOR_ASSERT(conv_filter);
  DISSECTOR_ASSERT(index_filter);
  DISSECTOR_ASSERT(address_filter);
  DISSECTOR_ASSERT(port_to_display);
  DISSECTOR_ASSERT(tap_handler);

  follower = wmem_new(wmem_epan_scope(), register_follow_t);

  follower->proto_id       = proto_id;
  follower->tap_listen_str = tap_listener;
  follower->conv_filter    = conv_filter;
  follower->index_filter   = index_filter;
  follower->address_filter = address_filter;
  follower->port_to_display = port_to_display;
  follower->tap_handler    = tap_handler;

  if (registered_followers == NULL)
    registered_followers = wmem_tree_new(wmem_epan_scope());

  wmem_tree_insert_string(registered_followers, proto_get_protocol_short_name(find_protocol_by_id(proto_id)), follower, 0);
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

tap_packet_cb get_follow_tap_handler(register_follow_t* follower)
{
  return follower->tap_handler;
}


register_follow_t* get_follow_by_name(const char* proto_short_name)
{
  return (register_follow_t*)wmem_tree_lookup_string(registered_followers, proto_short_name, 0);
}

void follow_iterate_followers(wmem_foreach_func func, gpointer user_data)
{
    wmem_tree_foreach(registered_followers, func, user_data);
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
    info->substream_id = SUBSTREAM_UNUSED;
}

void
follow_info_free(follow_info_t* follow_info)
{
    GList *cur;
    follow_record_t *follow_record;

    for (cur = follow_info->payload; cur; cur = g_list_next(cur)) {
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

tap_packet_status
follow_tvb_tap_listener(void *tapdata, packet_info *pinfo,
                      epan_dissect_t *edt _U_, const void *data, tap_flags_t flags _U_)
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
    follow_record->abs_ts = pinfo->fd->abs_ts;

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

    follow_info->payload = g_list_prepend(follow_info->payload, follow_record);
    return TAP_PACKET_DONT_REDRAW;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
