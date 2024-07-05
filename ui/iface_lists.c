/* iface_lists.c
 * Code to manage the global list of interfaces and to update widgets/windows
 * displaying items from those lists
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#ifdef HAVE_LIBPCAP

#include <string.h>

#include <glib.h>

#include <epan/prefs.h>
#include <epan/to_str.h>
#include <wsutil/wslog.h>

#include "ui/capture_ui_utils.h"
#include "ui/capture_globals.h"
#include "ui/iface_lists.h"

/*
 * Try to populate the given device with options (like capture filter) from
 * the capture options that are in use for an existing capture interface.
 * Returns true if the interface is selected for capture and false otherwise.
 */
static bool
fill_from_ifaces (interface_t *device)
{
    interface_options *interface_opts;
    unsigned i;

    for (i = 0; i < global_capture_opts.ifaces->len; i++) {
        interface_opts = &g_array_index(global_capture_opts.ifaces, interface_options, i);
        if (strcmp(interface_opts->name, device->name) != 0) {
            continue;
        }

#if defined(HAVE_PCAP_CREATE)
        device->buffer = interface_opts->buffer_size;
        device->monitor_mode_enabled = interface_opts->monitor_mode;
#endif
        device->pmode = interface_opts->promisc_mode;
        device->has_snaplen = interface_opts->has_snaplen;
        device->snaplen = interface_opts->snaplen;
        g_free(device->cfilter);
        device->cfilter = g_strdup(interface_opts->cfilter);
        device->timestamp_type = g_strdup(interface_opts->timestamp_type);
        if (interface_opts->linktype != -1) {
            device->active_dlt = interface_opts->linktype;
        }
        return true;
    }
    return false;
}

static char *
get_iface_display_name(const char *description, const if_info_t *if_info)
{
    /* Do we have a user-supplied description? */
    if (description && description[0]) {
        /*
         * Yes - show both the user-supplied description and a name for the
         * interface.
         */
#ifdef _WIN32
        /*
         * On Windows, if we have a friendly name, just show it
         * rather than the name, as the name is a string made out
         * of the device GUID, and not at all friendly.
         */
        char *if_string = if_info->friendly_name ? if_info->friendly_name : if_info->name;
        return ws_strdup_printf("%s: %s", description, if_string);
#else
        /*
         * On UN*X, show the interface name; it's short and somewhat
         * friendly, and many UN*X users are used to interface names,
         * so we should show it.
         */
        return ws_strdup_printf("%s: %s", description, if_info->name);
#endif
    }

    if (if_info->friendly_name) {
        /* We have a friendly name from the OS. */
#ifdef _WIN32
        /*
         * On Windows, if we have a friendly name, just show it,
         * don't show the name, as that's a string made out of
         * the device GUID, and not at all friendly.
         */
        return ws_strdup_printf("%s", if_info->friendly_name);
#else
        /*
         * On UN*X, if we have a friendly name, show it along
         * with the interface name; the interface name is short
         * and somewhat friendly, and many UN*X users are used
         * to interface names, so we should show it.
         */
        return ws_strdup_printf("%s: %s", if_info->friendly_name, if_info->name);
#endif
    }

    if (if_info->vendor_description) {
        /* We have a device description from libpcap. */
        return ws_strdup_printf("%s: %s", if_info->vendor_description, if_info->name);
    }

    /* No additional descriptions found. */
    return g_strdup(if_info->name);
}

/*
 * Fetch the list of local interfaces with capture_interface_list()
 * and set the list of "all interfaces" in *capture_opts to include
 * those interfaces.
 */
void
scan_local_interfaces(void (*update_cb)(void))
{
    scan_local_interfaces_filtered((GList *)0, update_cb);
}

/*
 * Fetch the list of local interfaces with capture_interface_list()
 * and set the list of "all interfaces" in *capture_opts to include
 * those interfaces.
 */
void
scan_local_interfaces_filtered(GList * allowed_types, void (*update_cb)(void))
{
    GList             *if_entry, *lt_entry, *if_list;
    if_info_t         *if_info;
    char              *descr;
    if_capabilities_t *caps=NULL;
    bool              monitor_mode;
    GSList            *curr_addr;
    int               ips = 0, i;
    unsigned          count = 0, j;
    if_addr_t         *addr;
    link_row          *link = NULL;
    data_link_info_t  *data_link_info;
    interface_t       device;
    GString           *ip_str = NULL;
    interface_options *interface_opts;
    bool              found = false;
    static bool       running = false;

    if (running) {
        /* scan_local_interfaces internally calls update_cb to process UI events
           to avoid stuck UI while running possibly slow operations. A side effect
           of this is that new interface changes can be detected before completing
           the last one.
           This return avoids recursive scan_local_interfaces operation. */
        return;
    }
    running = true;

    /* Retrieve list of interface information (if_info_t) into if_list. */
    g_free(global_capture_opts.ifaces_err_info);
    if_list = global_capture_opts.get_iface_list(&global_capture_opts.ifaces_err,
                                     &global_capture_opts.ifaces_err_info);

    /*
     * For each discovered interface name, look up its list of capabilities.
     * (if it supports monitor mode, supported DLTs, assigned IP addresses).
     * Do this all at once to reduce the number of spawned privileged dumpcap
     * processes.
     * It might be even better to get this information when getting the list,
     * but some devices can support different DLTs depending on whether
     * monitor mode is enabled, and we have to look up the monitor mode pref.
     */
    GList *if_cap_queries = NULL;
    if_cap_query_t *if_cap_query;
    GHashTable *capability_hash;
    for (if_entry = if_list; if_entry != NULL; if_entry = g_list_next(if_entry)) {
        if_info = (if_info_t *)if_entry->data;
        if (strstr(if_info->name, "rpcap:")) {
            continue;
        }
        /* Filter out all interfaces which are not allowed to be scanned */
        if (allowed_types != NULL)
        {
            if(g_list_find(allowed_types, GUINT_TO_POINTER((unsigned) if_info->type)) == NULL) {
                continue;
            }
        }
        if (if_info->caps != NULL) {
            continue;
        }
        if_cap_query = g_new(if_cap_query_t, 1);
        if_cap_query->name = if_info->name;
        if_cap_query->monitor_mode = prefs_capture_device_monitor_mode(if_info->name);
        if_cap_query->auth_username = NULL;
        if_cap_query->auth_password = NULL;
        if_cap_queries = g_list_prepend(if_cap_queries, if_cap_query);
    }
    if_cap_queries = g_list_reverse(if_cap_queries);
    capability_hash = capture_get_if_list_capabilities(if_cap_queries, NULL, NULL, update_cb);
    /* The if_info->name are not copied, so we can just free the
     * if_cap_query_t's and not their members. */
    g_list_free_full(if_cap_queries, g_free);

    /*
     * From the existing list of known interfaces, remove devices that we
     * expected to re-discover on scanning but did not (i.e., local devices,
     * but not pipes, stdin, and remote devices.)
     */
    if (global_capture_opts.all_ifaces->len > 0) {
        for (i = (int)global_capture_opts.all_ifaces->len-1; i >= 0; i--) {
            device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            if (device.local && device.if_info.type != IF_PIPE && device.if_info.type != IF_STDIN) {

                found = false;
                for (if_entry = if_list; if_entry != NULL; if_entry = g_list_next(if_entry)) {
                    if_info = (if_info_t *)if_entry->data;

                    if (strcmp(device.name, if_info->name) == 0) {
                        found = true;
                        break;
                    }
                }

                if (found) {
                    continue;
                }

                global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
                if (device.selected) {
                    global_capture_opts.num_selected--;
                }
                capture_opts_free_interface_t(&device);
            }
        }
    }

    /*
     * For each discovered interface name, look for it in the list of
     * devices. If not found, create a new device and add extra
     * information (including the capabilities we retrieved above).
     * If found, make sure that the information copied from if_info
     * is still valid.
     */
    count = 0;
    for (if_entry = if_list; if_entry != NULL; if_entry = g_list_next(if_entry)) {
        if_info = (if_info_t *)if_entry->data;
        ips = 0;
        if (strstr(if_info->name, "rpcap:")) {
            continue;
        }
        /* Filter out all interfaces which are not allowed to be scanned */
        if (allowed_types != NULL)
        {
            if(g_list_find(allowed_types, GUINT_TO_POINTER((unsigned) if_info->type)) == NULL) {
                continue;
            }
        }

        found = false;
        for (i = 0; i < (int)global_capture_opts.all_ifaces->len; i++) {
            device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            if (strcmp(device.name, if_info->name) == 0) {
                found = true;
                /* Remove it because we'll reinsert it below (in the proper
                 * index order, if that matters. Does it?)
                 */
                global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
                break;
            }
        }

        if (!found) {
            /* New device. Create a new one and set all the defaults. */
            memset(&device, 0, sizeof(device));
            device.name = g_strdup(if_info->name);
            device.hidden = false;
            if (prefs_is_capture_device_hidden(if_info->name)) {
                device.hidden = true;
            }
            device.selected = false;

#ifdef HAVE_PCAP_REMOTE
            device.remote_opts.src_type = CAPTURE_IFLOCAL;
            device.remote_opts.remote_host_opts.remote_host = g_strdup(global_capture_opts.default_options.remote_host);
            device.remote_opts.remote_host_opts.remote_port = g_strdup(global_capture_opts.default_options.remote_port);
            device.remote_opts.remote_host_opts.auth_type = global_capture_opts.default_options.auth_type;
            device.remote_opts.remote_host_opts.auth_username = g_strdup(global_capture_opts.default_options.auth_username);
            device.remote_opts.remote_host_opts.auth_password = g_strdup(global_capture_opts.default_options.auth_password);
            device.remote_opts.remote_host_opts.datatx_udp = global_capture_opts.default_options.datatx_udp;
            device.remote_opts.remote_host_opts.nocap_rpcap = global_capture_opts.default_options.nocap_rpcap;
            device.remote_opts.remote_host_opts.nocap_local = global_capture_opts.default_options.nocap_local;
#endif
#ifdef HAVE_PCAP_SETSAMPLING
            device.remote_opts.sampling_method = global_capture_opts.default_options.sampling_method;
            device.remote_opts.sampling_param  = global_capture_opts.default_options.sampling_param;
#endif

            device.local = true;
            device.last_packets = 0;
            if (!capture_dev_user_pmode_find(if_info->name, &device.pmode)) {
                device.pmode = global_capture_opts.default_options.promisc_mode;
            }
            if (!capture_dev_user_snaplen_find(if_info->name, &device.has_snaplen,
                                               &device.snaplen)) {
                device.has_snaplen = global_capture_opts.default_options.has_snaplen;
                device.snaplen = global_capture_opts.default_options.snaplen;
            }
            device.cfilter      = g_strdup(global_capture_opts.default_options.cfilter);
            device.timestamp_type = g_strdup(global_capture_opts.default_options.timestamp_type);
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
            if ((device.buffer = capture_dev_user_buffersize_find(if_info->name)) == -1) {
                device.buffer = global_capture_opts.default_options.buffer_size;
            }
#endif

            /* Extcap devices start with no cached args */
            device.external_cap_args_settings = NULL;

            monitor_mode = prefs_capture_device_monitor_mode(if_info->name);
            device.active_dlt = -1;
        } else {
            /* We can divide device_t members into three categories:
             * 1. Those that don't depend on if_info and the capabilities.
             * Keep those the same.
             * 2. Those that need to match the retrieved information.
             * Free those and set them below.
             * 3. Those that an option chosen from a set of options determined
             * from the capabilities. We have to check if the chosen values of
             * monitor mode enabled and active dlt are still supported.
             * There could be a knock on effect on the capture filter, as if
             * your previously chosen link-layer type isn't supported then
             * your capture filter might not be either, which will result in
             * it being marked invalid instead of being cleared. */
            /* XXX: We have duplicate copies of the name and we have
             * the addresses and links from the if_info transformed into new
             * types, but perhaps that transformation should be done when
             * creating the if_info and if_capabilities.
             */
            g_free(device.display_name);
            g_free(device.addresses);
            g_list_free_full(device.links, capture_opts_free_link_row);
            g_free(device.if_info.name);
            g_free(device.if_info.friendly_name);
            g_free(device.if_info.vendor_description);
            g_slist_free_full(device.if_info.addrs, g_free);
            g_free(device.if_info.extcap);
            if (device.if_info.caps) {
                free_if_capabilities(device.if_info.caps);
            }
            monitor_mode = device.monitor_mode_enabled;
        }

        descr = capture_dev_user_descr_find(if_info->name);
        device.display_name = get_iface_display_name(descr, if_info);
        g_free(descr);
        ip_str = g_string_new("");
        for (; (curr_addr = g_slist_nth(if_info->addrs, ips)) != NULL; ips++) {
            if (ips != 0) {
                g_string_append(ip_str, "\n");
            }
            addr = (if_addr_t *)curr_addr->data;
            if (addr) {
                address addr_str;
                char* temp_addr_str = NULL;
                switch (addr->ifat_type) {
                    case IF_AT_IPv4:
                        set_address(&addr_str, AT_IPv4, 4, &addr->addr.ip4_addr);
                        temp_addr_str = address_to_str(NULL, &addr_str);
                        g_string_append(ip_str, temp_addr_str);
                        break;
                    case IF_AT_IPv6:
                        set_address(&addr_str, AT_IPv6, 16, addr->addr.ip6_addr);
                        temp_addr_str = address_to_str(NULL, &addr_str);
                        g_string_append(ip_str, temp_addr_str);
                        break;
                    default:
                        /* In case we add non-IP addresses */
                        break;
                }
                wmem_free(NULL, temp_addr_str);
            }
        }
        device.addresses = g_strdup(ip_str->str);
        g_string_free(ip_str, TRUE);

        device.links = NULL;
        caps = if_info->caps;
        if (caps == NULL) {
            caps = g_hash_table_lookup(capability_hash, if_info->name);
        }
        if (caps != NULL && !caps->primary_msg) {
            GList *lt_list = caps->data_link_types;
#if defined(HAVE_PCAP_CREATE)
            device.monitor_mode_enabled = monitor_mode && caps->can_set_rfmon;
            device.monitor_mode_supported = caps->can_set_rfmon;
            if (device.monitor_mode_enabled) {
                lt_list = caps->data_link_types_rfmon;
            }
#endif
            /*
             * Process the list of link-layer header types.
             */
            bool found_active_dlt = false;
            for (lt_entry = lt_list; lt_entry != NULL; lt_entry = g_list_next(lt_entry)) {
                data_link_info = (data_link_info_t *)lt_entry->data;
                link = g_new(link_row, 1);
                if (data_link_info->description != NULL) {
                    link->dlt = data_link_info->dlt;
                    link->name = g_strdup(data_link_info->description);
                } else {
                    link->dlt = -1;
                    link->name = ws_strdup_printf("%s (not supported)", data_link_info->name);
                }
                if (link->dlt != -1 && link->dlt == device.active_dlt) {
                    found_active_dlt = true;
                }
                device.links = g_list_append(device.links, link);
            }

            /*
             * Set the active DLT for the device appropriately.
             */
            if (!found_active_dlt) {
                set_active_dlt(&device, global_capture_opts.default_options.linktype);
            }
        } else {
#if defined(HAVE_PCAP_CREATE)
            device.monitor_mode_enabled = false;
            device.monitor_mode_supported = false;
#endif
            device.active_dlt = -1;
        }

        device.no_addresses = ips;

        /* Copy interface options for active capture devices.
         * XXX: Not clear if we still need to do this, since we're not
         * destroying the old devices. */
        bool selected = fill_from_ifaces(&device);
        /* Restore device selection (for next capture). */
        if (!device.selected && selected) {
            device.selected = true;
            global_capture_opts.num_selected++;
        }

        /* We shallow copy if_info and then adding to the GArray shallow
         * copies it again, so free the if_info_t itself but not its members.
         * Then set the GList element data to NULL so that we don't free
         * it or its members when freeing the interface list. (This seems a
         * little easier than removing the link from the list while iterating.)
         */
        device.if_info = *if_info;
        if_entry->data = NULL;
        g_free(if_info);
        if (global_capture_opts.all_ifaces->len <= count) {
            g_array_append_val(global_capture_opts.all_ifaces, device);
            count = global_capture_opts.all_ifaces->len;
        } else {
            g_array_insert_val(global_capture_opts.all_ifaces, count, device);
        }
        count++;
    }
    g_hash_table_destroy(capability_hash);
    free_interface_list(if_list);

    /*
     * Pipes and stdin are not really discoverable interfaces, so re-add them to
     * the list of all interfaces (all_ifaces).
     */
    for (j = 0; j < global_capture_opts.ifaces->len; j++) {
        interface_opts = &g_array_index(global_capture_opts.ifaces, interface_options, j);

        found = false;
        for (i = 0; i < (int)global_capture_opts.all_ifaces->len; i++) {
            device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);

            /* Filter out all interfaces, which are not allowed to be scanned */
            if (allowed_types != NULL && g_list_find(allowed_types, GINT_TO_POINTER(interface_opts->if_type)) == NULL) {
                continue;
            }

            if (strcmp(device.name, interface_opts->name) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {  /* new interface, maybe a pipe */
            memset(&device, 0, sizeof(device));
            device.name         = g_strdup(interface_opts->name);
            device.display_name = interface_opts->descr ?
                ws_strdup_printf("%s: %s", device.name, interface_opts->descr) :
                g_strdup(device.name);
            device.hidden       = false;
            device.selected     = true;
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
            device.buffer = interface_opts->buffer_size;
#endif
#if defined(HAVE_PCAP_CREATE)
            device.monitor_mode_enabled = interface_opts->monitor_mode;
            device.monitor_mode_supported = false;
#endif
            device.pmode = interface_opts->promisc_mode;
            device.has_snaplen = interface_opts->has_snaplen;
            device.snaplen = interface_opts->snaplen;
            device.cfilter = g_strdup(interface_opts->cfilter);
            device.timestamp_type = g_strdup(interface_opts->timestamp_type);
            device.active_dlt = interface_opts->linktype;
            device.addresses    = NULL;
            device.no_addresses = 0;
            device.last_packets = 0;
            device.links        = NULL;
            device.local        = true;
            device.if_info.name = g_strdup(interface_opts->name);
            device.if_info.type = interface_opts->if_type;
            device.if_info.friendly_name = NULL;
            device.if_info.vendor_description = g_strdup(interface_opts->hardware);
            device.if_info.addrs = NULL;
            device.if_info.loopback = false;
            device.if_info.extcap = g_strdup(interface_opts->extcap);

            g_array_append_val(global_capture_opts.all_ifaces, device);
            global_capture_opts.num_selected++;
        }
    }

    running = false;
}

/*
 * Get the global interface list.  Generate it if we haven't done so
 * already.  This can be quite time consuming the first time, so
 * record how long it takes in the info log.
 */
void
fill_in_local_interfaces(void(*update_cb)(void))
{
    fill_in_local_interfaces_filtered((GList *)0, update_cb);
}

/*
 * Get the global interface list.  Generate it if we haven't done so
 * already.  This can be quite time consuming the first time, so
 * record how long it takes in the info log.
 */
void
fill_in_local_interfaces_filtered(GList * filter_list, void(*update_cb)(void))
{
    int64_t start_time;
    double elapsed;
    static bool initialized = false;

    /* record the time we started, so we can log total time later */
    start_time = g_get_monotonic_time();

    if (!initialized) {
        /* do the actual work */
        scan_local_interfaces_filtered(filter_list, update_cb);
        initialized = true;
    }
    /* log how long it took */
    elapsed = (g_get_monotonic_time() - start_time) / 1e6;

    ws_log(LOG_DOMAIN_MAIN, LOG_LEVEL_INFO, "Finished getting the global interface list, taking %.3fs", elapsed);
}

void
hide_interface(char* new_hide)
{
    char        *tok;
    unsigned    i;
    interface_t *device;
    bool        found = false;
    GList       *hidden_devices = NULL, *entry;
    if (new_hide != NULL) {
        for (tok = strtok (new_hide, ","); tok; tok = strtok(NULL, ",")) {
            hidden_devices = g_list_append(hidden_devices, tok);
        }
    }
    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        found = false;
        for (entry = hidden_devices; entry != NULL; entry = g_list_next(entry)) {
            if (strcmp((char *)entry->data, device->name)==0) {
                device->hidden = true;
                if (device->selected) {
                    device->selected = false;
                    global_capture_opts.num_selected--;
                }
                found = true;
                break;
            }
        }
        if (!found) {
            device->hidden = false;
        }
    }
    g_list_free(hidden_devices);
    g_free(new_hide);
}

void
update_local_interfaces(void)
{
    interface_t *device;
    char *descr;
    unsigned i;

    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        device->if_info.type = capture_dev_user_linktype_find(device->name);
        g_free(device->display_name);
        descr = capture_dev_user_descr_find(device->name);
        device->display_name = get_iface_display_name(descr, &device->if_info);
        g_free (descr);
        device->hidden = prefs_is_capture_device_hidden(device->name);
        fill_from_ifaces(device);
    }
}
#endif /* HAVE_LIBPCAP */
