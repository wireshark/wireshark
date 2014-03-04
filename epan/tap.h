/* tap.h
 * packet tap interface   2002 Ronnie Sahlberg
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

#ifndef __TAP_H__
#define __TAP_H__

#include <epan/epan.h>
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef void (*tap_reset_cb)(void *tapdata);
typedef gboolean (*tap_packet_cb)(void *tapdata, packet_info *pinfo, epan_dissect_t *edt, const void *data);
typedef void (*tap_draw_cb)(void *tapdata);

/**
 * Flags to indicate what a tap listener's packet routine requires.
 */
#define TL_REQUIRES_NOTHING	0x00000000	/**< nothing */
#define TL_REQUIRES_PROTO_TREE	0x00000001	/**< full protocol tree */
#define TL_REQUIRES_COLUMNS	0x00000002	/**< columns */
/** Flags to indicate what the tap listener does */
#define TL_IS_DISSECTOR_HELPER	0x00000004	/**< tap helps a dissector do work
						 ** but does not, itself, require dissection */

#ifdef HAVE_PLUGINS
/** Register tap plugin type with the plugin system.
    Called by epan_register_plugin_types(); do not call it yourself. */
extern void register_tap_plugin_type(void);
#endif

/*
 * For all tap plugins, call their register routines.
 * Must be called after init_plugins(), and must be called only once in
 * a program.
 *
 * XXX - should probably be handled by epan_init(), as the tap mechanism
 * is part of libwireshark.
 */
WS_DLL_PUBLIC void register_all_plugin_tap_listeners(void);

extern void tap_init(void);

/** This function registers that a dissector has the packet tap ability
 *  available.  The name parameter is the name of this tap and extensions can
 *  use open_tap(char *name,... to specify that it wants to receive packets/
 *  events from this tap.
 *
 *  This function is only to be called once, when the dissector initializes.
 *
 *  The return value from this call is later used as a parameter to the
 *  tap_packet(unsigned int *tap_id,...
 *  call so that the tap subsystem knows to which tap point this tapped
 *  packet is associated.
 */
WS_DLL_PUBLIC int register_tap(const char *name);

/* Gets a GList of the tap names */
WS_DLL_PUBLIC GList* get_tap_names(void);

/** This function will return the tap_id for the specific protocol tap
 *  or 0 if no such tap was found.
 */
WS_DLL_PUBLIC int find_tap_id(const char *name);

/** Everytime the dissector has finished dissecting a packet (and all
 *  subdissectors have returned) and if the dissector has been made "tappable"
 *  it will push some data to everyone tapping this layer by a call
 *  to tap_queue_packet().
 *  The first parameter is the tap_id returned by the register_tap()
 *  call for this dissector (so the tap system can keep track of who it came
 *  from and who is listening to it)
 *  The second is the packet_info structure which many tap readers will find
 *  interesting.
 *  The third argument is specific to each tap point or NULL if no additional
 *  data is available to this tap.  A tap point in say IP will probably want to
 *  push the IP header structure here. Same thing for TCP and ONCRPC.
 *
 *  The pinfo and the specific pointer are what is supplied to every listener
 *  in the read_callback() call made to every one currently listening to this
 *  tap.
 *
 *  The tap reader is responsible to know how to parse any structure pointed
 *  to by the tap specific data pointer.
 */
WS_DLL_PUBLIC void tap_queue_packet(int tap_id, packet_info *pinfo, const void *tap_specific_data);

/** Functions used by file.c to drive the tap subsystem */
WS_DLL_PUBLIC void tap_build_interesting(epan_dissect_t *edt);

/** This function is used to delete/initialize the tap queue and prime an
 *  epan_dissect_t with all the filters for tap listeners.
 *  To free the tap queue, we just prepend the used queue to the free queue.
 */
extern void tap_queue_init(epan_dissect_t *edt);

/** this function is called after a packet has been fully dissected to push the tapped
 *  data to all extensions that has callbacks registered.
 */

extern void tap_push_tapped_queue(epan_dissect_t *edt);

/** This function is called after a packet has been fully dissected to push the tapped
 *  data to all extensions that has callbacks registered.
 */

WS_DLL_PUBLIC void reset_tap_listeners(void);

/** This function is called when we need to redraw all tap listeners, for example
 * when we open/start a new capture or if we need to rescan the packet list.
 * It should be called from a low priority thread say once every 3 seconds
 *
 * If draw_all is true, redraw all aplications regardless if they have
 * changed or not.
 */
WS_DLL_PUBLIC void draw_tap_listeners(gboolean draw_all);

/** this function attaches the tap_listener to the named tap.
 * function returns :
 *     NULL: ok.
 * non-NULL: error, return value points to GString containing error
 *           message.
 * @param tapname    The name of the tap we want to listen to.
 * @param tapdata    is the instance identifier. The tap system uses the value of this
 *                   pointer to distinguish between different instances of a tap.
 *                   Just make sure that it is unique by letting it be the pointer to a struct
 *                   holding all state variables. If you want to allow multiple concurrent
 *                   instances, just put ALL state variables inside a struct allocated by
 *                   g_malloc() and use that pointer.
 * @param fstring    is a pointer to a filter string.
 *                   If this is NULL, then the tap system will provide ALL packets passing the
 *                   tapped protocol to your listener.
 *                   If you specify a filter string here the tap system will first try
 *                   to apply this string to the packet and then only pass those packets that
 *                   matched the filter to your listener.
 *                   The syntax for the filter string is identical to normal display filters.
 *
 *                   NOTE: Specifying filter strings will have a significant performance impact
 *                   on your application and Wireshark. If possible it is MUCH better to take
 *                   unfiltered data and just filter it yourself in the packet-callback than
 *                   to specify a filter string.
 *                   ONLY use a filter string if no other option exist.
 *
 * @param flags      is a set of flags for the tap listener.  The flags that can be set are:
 *
 *                      TL_REQUIRES_PROTO_TREE
 *
 *                   	set if your tap listener "packet" routine requires a protocol
 *                   	tree to be built.  It will require a protocol tree to be
 *                   	built if either
 *
 *                   		1) it looks at the protocol tree in edt->tree
 *
 *                   	or
 *
 *                   		2) the tap-specific data passed to it is constructed only if
 *                   		   the protocol tree is being built.
 *
 *                      TL_REQUIRES_COLUMNS
 *
 *                   	set if your tap listener "packet" routine requires the column
 *                   	strings to be constructed.
 *
 *                       If no flags are needed, use TL_REQUIRES_NOTHING.
 *
 * @param tap_reset  void (*reset)(void *tapdata)
 *                   This callback is called whenever Wireshark wants to inform your
 *                   listener that it is about to start [re]reading a capture file or a new capture
 *                   from an interface and that your application should reset any state it has
 *                   in the *tapdata instance.
 * @param tap_packet gboolean (*packet)(void *tapdata, packet_info *pinfo, epan_dissect_t *edt, const void *data)
 *                   This callback is used whenever a new packet has arrived at the tap and that
 *                   it has passed the filter (if there were a filter).
 *                   The *data structure type is specific to each tap.
 *                   This function returns an gboolean and it should return
 *                    TRUE, if the data in the packet caused state to be updated
 *                          (and thus a redraw of the window would later be required)
 *                    FALSE, if we don't need to redraw the window.
 *                   NOTE: that (*packet) should be as fast and efficient as possible. Use this
 *                   function ONLY to store data for later and do the CPU-intensive processing
 *                   or GUI updates down in (*draw) instead.
 * @param tap_draw   void (*draw)(void *tapdata)
 *                   This callback is used when Wireshark wants your application to redraw its
 *                   output. It will usually not be called unless your application has received
 *                   new data through the (*packet) callback.
 *                   On some ports of Wireshark (gtk2) (*draw) will be called asynchronously
 *                   from a separate thread up to once every 2-3 seconds.
 *                   On other ports it might only be called once when the capture is finished
 *                   or the file has been [re]read completely.
 */

WS_DLL_PUBLIC GString *register_tap_listener(const char *tapname, void *tapdata,
    const char *fstring, guint flags, tap_reset_cb tap_reset,
    tap_packet_cb tap_packet, tap_draw_cb tap_draw);

/** This function sets a new dfilter to a tap listener */
WS_DLL_PUBLIC GString *set_tap_dfilter(void *tapdata, const char *fstring);

/** this function removes a tap listener */
WS_DLL_PUBLIC void remove_tap_listener(void *tapdata);

/**
 * Return TRUE if we have one or more tap listeners that require dissection,
 * FALSE otherwise.
 */
WS_DLL_PUBLIC gboolean tap_listeners_require_dissection(void);

/** Returns TRUE there is an active tap listener for the specified tap id. */
WS_DLL_PUBLIC gboolean have_tap_listener(int tap_id);

/** Return TRUE if we have any tap listeners with filters, FALSE otherwise. */
WS_DLL_PUBLIC gboolean have_filtering_tap_listeners(void);

/**
 * Get the union of all the flags for all the tap listeners; that gives
 * an indication of whether the protocol tree, or the columns, are
 * required by any taps.
 */
WS_DLL_PUBLIC guint union_of_tap_listener_flags(void);

/** This function can be used by a dissector to fetch any tapped data before
 * returning.
 * This can be useful if one wants to extract the data inside dissector  BEFORE
 * it exists as an alternative to the callbacks that are all called AFTER the
 * dissection has completed.
 *
 * Example: SMB2 uses this mechanism to extract the data tapped from NTLMSSP
 * containing the account and domain names before exiting.
 * Note that the SMB2 tap listener specifies all three callbacks as NULL.
 *
 * Beware: when using this mechanism to extract the tapped data you can not
 * use "filters" and should specify the "filter" as NULL when registering
 * the tap listener.
 */
WS_DLL_PUBLIC const void *fetch_tapped_data(int tap_id, int idx);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TAP_H__ */
