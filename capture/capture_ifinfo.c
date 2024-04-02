/* capture_ifinfo.c
 * Routines for getting interface information from dumpcap
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_CAPTURE

#ifdef HAVE_LIBPCAP

#include <wireshark.h>

#include <stdlib.h>
#include <stdio.h>

#include "capture_opts.h"

#include "capture/capture_session.h"
#include "capture/capture_sync.h"
#include "extcap.h"

#include <capture/capture-pcap-util.h>
#include <capture/capture-pcap-util-int.h>
#include <capture/capture_ifinfo.h>
#include <wsutil/inet_addr.h>
#include <wsutil/wsjson.h>

#ifdef HAVE_PCAP_REMOTE
static GList *remote_interface_list;

GList * append_remote_list(GList *iflist)
{
    GSList *list;
    GList *rlist;
    if_addr_t *if_addr, *temp_addr;
    if_info_t *if_info, *temp;

    for (rlist = g_list_nth(remote_interface_list, 0); rlist != NULL; rlist = g_list_next(rlist)) {
        if_info = (if_info_t *)rlist->data;
        temp = g_new0(if_info_t, 1);
        temp->name = g_strdup(if_info->name);
        temp->friendly_name = g_strdup(if_info->friendly_name);
        temp->vendor_description = g_strdup(if_info->vendor_description);
        for (list = g_slist_nth(if_info->addrs, 0); list != NULL; list = g_slist_next(list)) {
            temp_addr = g_new0(if_addr_t, 1);
            if_addr = (if_addr_t *)list->data;
            if (if_addr) {
                temp_addr->ifat_type = if_addr->ifat_type;
                if (temp_addr->ifat_type == IF_AT_IPv4) {
                    temp_addr->addr.ip4_addr = if_addr->addr.ip4_addr;
                } else {
                    memcpy(temp_addr->addr.ip6_addr, if_addr->addr.ip6_addr, sizeof(if_addr->addr));
                }
            } else {
                g_free(temp_addr);
                temp_addr = NULL;
            }
            if (temp_addr) {
                temp->addrs = g_slist_append(temp->addrs, temp_addr);
            }
        }
        temp->loopback = if_info->loopback;
        iflist = g_list_append(iflist, temp);
   }
   return iflist;
}
#endif

static if_capabilities_t *
deserialize_if_capability(char* data, jsmntok_t *inf_tok)
{
    if_capabilities_t *caps;
    GList             *linktype_list = NULL, *timestamp_list = NULL;
    GList             *linktype_rfmon_list = NULL;
    int                err, i;
    char              *val_s;
    double             val_d;
    jsmntok_t         *array_tok, *cur_tok;

    /*
     * Allocate the interface capabilities structure.
     */
    caps = (if_capabilities_t *)g_malloc0(sizeof *caps);

    if (inf_tok == NULL || !json_get_double(data, inf_tok, "status", &val_d)) {
        ws_info("Capture Interface Capabilities failed with invalid JSON.");
        caps->primary_msg = g_strdup("Dumpcap returned bad JSON");
        return caps;
    }

    err = (int)val_d;
    if (err != 0) {
        caps->primary_msg = json_get_string(data, inf_tok, "primary_msg");
        if (caps->primary_msg) {
            caps->primary_msg = g_strdup(caps->primary_msg);
            caps->secondary_msg = get_pcap_failure_secondary_error_message(err, caps->primary_msg);
        } else {
            caps->primary_msg = g_strdup("Failed with no message");
        }
        ws_info("Capture Interface Capabilities failed. Error %d, %s",
              err, caps->primary_msg ? caps->primary_msg : "no message");
        return caps;
    }

    bool rfmon;
    if (!json_get_boolean(data, inf_tok, "rfmon", &rfmon)) {
        ws_message("Capture Interface Capabilities returned bad information.");
        ws_message("Didn't return monitor-mode cap");
        caps->primary_msg = g_strdup("Dumpcap didn't return monitor-mode capability");
        return caps;
    }

    caps->can_set_rfmon = rfmon;

    /*
     * The following are link-layer types.
     */
    array_tok = json_get_array(data, inf_tok, "data_link_types");
    if (!array_tok) {
        ws_info("Capture Interface Capabilities returned bad data_link information.");
        caps->primary_msg = g_strdup("Dumpcap didn't return data link types capability");
        return caps;
    }
    for (i = 0; i < json_get_array_len(array_tok); i++) {
        cur_tok = json_get_array_index(array_tok, i);

        if (!json_get_double(data, cur_tok, "dlt", &val_d)) {
            continue;
        }

        data_link_info_t *data_link_info;
        data_link_info = g_new(data_link_info_t,1);

        data_link_info->dlt = (int)val_d;
        val_s = json_get_string(data, cur_tok, "name");
        data_link_info->name = val_s ? g_strdup(val_s) : NULL;
        val_s = json_get_string(data, cur_tok, "description");
        if (!val_s || strcmp(val_s, "(not supported)") == 0) {
            data_link_info->description = NULL;
        } else {
            data_link_info->description = g_strdup(val_s);
        }
        linktype_list = g_list_append(linktype_list, data_link_info);
    }

    if (rfmon) {
        array_tok = json_get_array(data, inf_tok, "data_link_types_rfmon");

        if (!array_tok) {
            ws_info("Capture Interface Capabilities returned bad data_link information for monitor mode.");
            caps->primary_msg = g_strdup("Dumpcap claimed that interface supported monitor mode, but didn't return data link types when in monitor mode");
            caps->can_set_rfmon = false;
        } else for (i = 0; i < json_get_array_len(array_tok); i++) {
            cur_tok = json_get_array_index(array_tok, i);

            if (!json_get_double(data, cur_tok, "dlt", &val_d)) {
                continue;
            }

            data_link_info_t *data_link_info;
            data_link_info = g_new(data_link_info_t,1);

            data_link_info->dlt = (int)val_d;
            val_s = json_get_string(data, cur_tok, "name");
            data_link_info->name = val_s ? g_strdup(val_s) : NULL;
            val_s = json_get_string(data, cur_tok, "description");
            if (!val_s || strcmp(val_s, "(not supported)") == 0) {
                data_link_info->description = NULL;
            } else {
                data_link_info->description = g_strdup(val_s);
            }
            linktype_rfmon_list = g_list_append(linktype_rfmon_list, data_link_info);
        }
    }

    array_tok = json_get_array(data, inf_tok, "timestamp_types");
    if (array_tok) {
        for (i = 0; i < json_get_array_len(array_tok); i++) {
            cur_tok = json_get_array_index(array_tok, i);

            timestamp_info_t *timestamp_info;
            timestamp_info = g_new(timestamp_info_t,1);
            val_s = json_get_string(data, cur_tok, "name");
            timestamp_info->name = val_s ? g_strdup(val_s) : NULL;
            val_s = json_get_string(data, cur_tok, "description");
            timestamp_info->description = val_s ? g_strdup(val_s) : NULL;

            timestamp_list = g_list_append(timestamp_list, timestamp_info);
        }
    }

    caps->data_link_types = linktype_list;
    /* Should be NULL if rfmon unsupported. */
    caps->data_link_types_rfmon = linktype_rfmon_list;
    /* Might be NULL. Not all systems report timestamp types */
    caps->timestamp_types = timestamp_list;

    return caps;
}

GList *
deserialize_interface_list(char *data, int *err, char **err_str)
{
    int        i, j;
    char      *name, *addr;
    char      *val_s;
    double     val_d;
    bool       loopback;
    if_info_t *if_info;
    interface_type type;
    if_addr_t *if_addr;
    jsmntok_t *tokens, *if_tok, *addrs_tok, *cur_tok;
    GList     *if_list = NULL;

    if (data == NULL) {
        ws_info("Passed NULL capture interface list");
        *err = CANT_GET_INTERFACE_LIST;
        return if_list;
    }

    int num_tokens = json_parse(data, NULL, 0);
    if (num_tokens <= 0) {
        ws_info("Capture Interface List failed with invalid JSON.");
        if (err_str) {
            *err_str = g_strdup("Dumpcap returned bad JSON.");
        }
        g_free(data);
        *err = CANT_GET_INTERFACE_LIST;
        return NULL;
    }

    tokens = wmem_alloc_array(NULL, jsmntok_t, num_tokens);
    if (json_parse(data, tokens, num_tokens) <= 0) {
        ws_info("Capture Interface List failed with invalid JSON.");
        if (err_str) {
            *err_str = g_strdup("Dumpcap returned bad JSON.");
        }
        wmem_free(NULL, tokens);
        g_free(data);
        *err = CANT_GET_INTERFACE_LIST;
        return NULL;
    }

    for (i = 0; i < json_get_array_len(tokens); i++) {
        if_tok = json_get_array_index(tokens, i);
        if (if_tok && if_tok->type == JSMN_OBJECT) {
            if_tok++; // Key
            name = g_strndup(&data[if_tok->start], if_tok->end - if_tok->start);
            if (!json_decode_string_inplace(name)) {
                g_free(name);
                continue;
            }
            if_tok++;

            if (!json_get_double(data, if_tok, "type", &val_d)) {
                g_free(name);
                continue;
            }
            type = (interface_type)val_d;

            if (!json_get_boolean(data, if_tok, "loopback", &loopback)) {
                g_free(name);
                continue;
            }

            if_info = g_new0(if_info_t,1);
            if_info->name = name;
            val_s = json_get_string(data, if_tok, "friendly_name");
            if_info->friendly_name = g_strdup(val_s);
            val_s = json_get_string(data, if_tok, "vendor_description");
            if_info->vendor_description = g_strdup(val_s);
            if_info->type = type;

            addrs_tok = json_get_array(data, if_tok, "addrs");
            for (cur_tok = addrs_tok + 1, j = 0; j < json_get_array_len(addrs_tok); cur_tok++, j++) {
                addr = g_strndup(&data[cur_tok->start], cur_tok->end - cur_tok->start);
                if (json_decode_string_inplace(addr)) {
                    if_addr = g_new0(if_addr_t, 1);
                    if (ws_inet_pton4(addr, &if_addr->addr.ip4_addr)) {
                        if_addr->ifat_type = IF_AT_IPv4;
                    } else if (ws_inet_pton6(addr, (ws_in6_addr *)&if_addr->addr.ip6_addr)) {
                        if_addr->ifat_type = IF_AT_IPv6;
                    } else {
                        g_free(if_addr);
                        if_addr = NULL;
                    }
                    if (if_addr) {
                        if_info->addrs = g_slist_append(if_info->addrs, if_addr);
                    }
                }
                g_free(addr);
            }

            if_info->loopback = loopback;

            val_s = json_get_string(data, if_tok, "extcap");
            /* if_info->extcap is never NULL, unlike the friendly name
             * and vendor description. (see if_info_new)
             */
            if_info->extcap = val_s ? g_strdup(val_s) : "";

            cur_tok = json_get_object(data, if_tok, "caps");
            if (cur_tok) {
                if_info->caps = deserialize_if_capability(data, cur_tok);
            }

            if_list = g_list_append(if_list, if_info);
        }
    }

    wmem_free(NULL, tokens);
    g_free(data);

    return if_list;
}

/**
 * Fetch the interface list from a child process (dumpcap).
 *
 * @return A GList containing if_info_t structs if successful, NULL (with err and possibly err_str set) otherwise.
 *
 */
GList *
capture_interface_list(int *err, char **err_str, void (*update_cb)(void))
{
    int        ret;
    GList     *if_list = NULL;
    char      *data, *primary_msg, *secondary_msg;

    *err = 0;
    if (err_str) {
        *err_str = NULL;
    }

    /* Try to get the local interface list */
    ret = sync_interface_list_open(&data, &primary_msg, &secondary_msg, update_cb);
    if (ret != 0) {
        ws_info("sync_interface_list_open() failed. %s (%s)",
                  primary_msg ? primary_msg : "no message",
                  secondary_msg ? secondary_msg : "no secondary message");
        if (err_str) {
            *err_str = primary_msg;
        } else {
            g_free(primary_msg);
        }
        g_free(secondary_msg);
        *err = CANT_GET_INTERFACE_LIST;

        /*
         * Add the extcap interfaces that can exist; they may exist
         * even if no native interfaces have been found.
         */
        ws_debug("Loading External Capture Interface List ...");
        if_list = append_extcap_interface_list(if_list);
        return if_list;
    }

    if_list = deserialize_interface_list(data, err, err_str);

#ifdef HAVE_PCAP_REMOTE
    /* Add the remote interface list */
    if (remote_interface_list && g_list_length(remote_interface_list) > 0) {
        if_list = append_remote_list(if_list);
    }
#endif

    /* Add the extcap interfaces after the native and remote interfaces */
    ws_debug("Loading External Capture Interface List ...");
    if_list = append_extcap_interface_list(if_list);

    return if_list;
}

if_capabilities_t *
capture_get_if_capabilities(const char *ifname, bool monitor_mode,
                            const char *auth_string,
                            char **err_primary_msg, char **err_secondary_msg,
                            void (*update_cb)(void))
{
    if_capabilities_t *caps;
    int                 err;
    char               *data, *primary_msg, *secondary_msg;
    jsmntok_t          *tokens, *inf_tok;

    /* see if the interface is from extcap */
    caps = extcap_get_if_dlts(ifname, err_primary_msg);
    if (caps != NULL) {
        /* return if the extcap interface generated an error */
        if (caps->primary_msg) {
            free_if_capabilities(caps);
            caps = NULL;
        }
        return caps;
    }

    /* Try to get our interface list */
    err = sync_if_capabilities_open(ifname, monitor_mode, auth_string, &data,
                                    &primary_msg, &secondary_msg, update_cb);
    if (err != 0) {
        ws_info("Capture Interface Capabilities failed. Error %d, %s",
              err, primary_msg ? primary_msg : "no message");
        if (err_primary_msg)
            *err_primary_msg = primary_msg;
        else
            g_free(primary_msg);
        if (err_secondary_msg)
            *err_secondary_msg = secondary_msg;
        else
            g_free(secondary_msg);
        return NULL;
    }

    int num_tokens = json_parse(data, NULL, 0);
    if (num_tokens <= 0) {
        ws_info("Capture Interface Capabilities failed with invalid JSON.");
        if (err_primary_msg) {
            *err_primary_msg = g_strdup("Dumpcap returned bad JSON.");
        }
        g_free(data);
        return NULL;
    }

    tokens = wmem_alloc_array(NULL, jsmntok_t, num_tokens);
    if (json_parse(data, tokens, num_tokens) <= 0) {
        ws_info("Capture Interface Capabilities returned no information.");
        if (err_primary_msg) {
            *err_primary_msg = g_strdup("Dumpcap returned no interface capability information");
        }
        wmem_free(NULL, tokens);
        g_free(data);
        return NULL;
    }

    inf_tok = json_get_array_index(tokens, 0);
    if (inf_tok && inf_tok->type == JSMN_OBJECT) {
        inf_tok++; // Key
        char *ifname2 = g_strndup(&data[inf_tok->start], inf_tok->end - inf_tok->start);
        if (json_decode_string_inplace(ifname2) && g_strcmp0(ifname2, ifname) == 0) {
            inf_tok++;
            caps = deserialize_if_capability(data, inf_tok);
            if (caps->primary_msg) {
                if (err_primary_msg) {
                    *err_primary_msg = caps->primary_msg;
                    caps->primary_msg = NULL;
                }
                if (caps->secondary_msg && err_secondary_msg) {
                    *err_secondary_msg = g_strdup(caps->secondary_msg);
                }
                free_if_capabilities(caps);
                caps = NULL;
            }
        } else if (err_primary_msg) {
            *err_primary_msg = g_strdup("Dumpcap returned bad JSON.");
        }
        g_free(ifname2);
    } else if (err_primary_msg) {
        *err_primary_msg = g_strdup("Dumpcap returned bad JSON.");
    }

    wmem_free(NULL, tokens);
    g_free(data);

    return caps;
}

static void
free_if_capabilities_cb(void *data)
{
    if (data != NULL) {
        free_if_capabilities((if_capabilities_t*)data);
    }
}

GHashTable*
capture_get_if_list_capabilities(GList *if_cap_queries,
                            char **err_primary_msg, char **err_secondary_msg,
                            void (*update_cb)(void))
{
    if_cap_query_t    *query;
    if_capabilities_t *caps;
    GHashTable        *caps_hash;
    GList             *local_queries = NULL;
    int                err, i;
    char              *data, *primary_msg, *secondary_msg;
    jsmntok_t         *tokens, *inf_tok;

    caps_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, free_if_capabilities_cb);
    for (GList *li = if_cap_queries; li != NULL; li = g_list_next(li)) {

        query = (if_cap_query_t *)li->data;
        /* see if the interface is from extcap */
        caps = extcap_get_if_dlts(query->name, NULL);
        /* if the extcap interface generated an error, it was from extcap */
        if (caps != NULL) {
            g_hash_table_replace(caps_hash, g_strdup(query->name), caps);
        } else {
            local_queries = g_list_prepend(local_queries, query);
        }
    }

    if (local_queries == NULL)
        return caps_hash;

    local_queries = g_list_reverse(local_queries);

    /* Try to get our interface list */
    err = sync_if_list_capabilities_open(local_queries, &data,
                                    &primary_msg, &secondary_msg, update_cb);
    g_list_free(local_queries);
    if (err != 0) {
        ws_info("Capture Interface Capabilities failed. Error %d, %s",
              err, primary_msg ? primary_msg : "no message");
        if (err_primary_msg)
            *err_primary_msg = primary_msg;
        else
            g_free(primary_msg);
        if (err_secondary_msg)
            *err_secondary_msg = secondary_msg;
        else
            g_free(secondary_msg);
        return caps_hash;
    }

    int num_tokens = json_parse(data, NULL, 0);
    if (num_tokens <= 0) {
        ws_info("Capture Interface Capabilities failed with invalid JSON.");
        g_free(data);
        return caps_hash;
    }

    tokens = wmem_alloc_array(NULL, jsmntok_t, num_tokens);
    if (json_parse(data, tokens, num_tokens) <= 0) {
        ws_info("Capture Interface Capabilities returned no information.");
        if (err_primary_msg) {
            *err_primary_msg = g_strdup("Dumpcap returned no interface capability information");
        }
        wmem_free(NULL, tokens);
        g_free(data);
        return caps_hash;
    }

    char *ifname;
    for (i = 0; i < json_get_array_len(tokens); i++) {
        inf_tok = json_get_array_index(tokens, i);
        if (inf_tok && inf_tok->type == JSMN_OBJECT) {
            inf_tok++; // Key
            ifname = g_strndup(&data[inf_tok->start], inf_tok->end - inf_tok->start);
            if (!json_decode_string_inplace(ifname)) {
                g_free(ifname);
                continue;
            }
            inf_tok++;
            caps = deserialize_if_capability(data, inf_tok);
            g_hash_table_replace(caps_hash, ifname, caps);
        }
    }

    wmem_free(NULL, tokens);
    g_free(data);

    return caps_hash;
}

#ifdef HAVE_PCAP_REMOTE
void add_interface_to_remote_list(if_info_t *if_info)
{
    GSList *list;
    if_addr_t *if_addr, *temp_addr;

    if_info_t *temp = g_new0(if_info_t, 1);
    temp->name = g_strdup(if_info->name);
    temp->friendly_name = g_strdup(if_info->friendly_name);
    temp->vendor_description = g_strdup(if_info->vendor_description);
    for (list = g_slist_nth(if_info->addrs, 0); list != NULL; list = g_slist_next(list)) {
        temp_addr = g_new0(if_addr_t, 1);
        if_addr = (if_addr_t *)list->data;
        if (if_addr) {
            temp_addr->ifat_type = if_addr->ifat_type;
            if (temp_addr->ifat_type == IF_AT_IPv4) {
                temp_addr->addr.ip4_addr = if_addr->addr.ip4_addr;
            } else {
                memcpy(temp_addr->addr.ip6_addr, if_addr->addr.ip6_addr, sizeof(if_addr->addr));
            }
        } else {
            g_free(temp_addr);
            temp_addr = NULL;
        }
        if (temp_addr) {
            temp->addrs = g_slist_append(temp->addrs, temp_addr);
        }
    }
    temp->loopback = if_info->loopback;
    remote_interface_list = g_list_append(remote_interface_list, temp);
}
#endif
#endif /* HAVE_LIBPCAP */
