/** @file
 * packet tap interface   2002 Ronnie Sahlberg
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <epan/epan.h>
#include <epan/packet_info.h>
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Status returned by the per-packet callback.
 */
typedef enum {
	TAP_PACKET_DONT_REDRAW,	/**< Packet processing succeeded, no need to redraw */
	TAP_PACKET_REDRAW,	/**< Packet processing succeeded, must redraw */
	TAP_PACKET_FAILED	/**< Packet processing failed, stop calling this tap */
} tap_packet_status;

typedef unsigned tap_flags_t;

typedef void (*tap_reset_cb)(void *tapdata);
typedef tap_packet_status (*tap_packet_cb)(void *tapdata, packet_info *pinfo, epan_dissect_t *edt, const void *data, tap_flags_t flags);
typedef void (*tap_draw_cb)(void *tapdata);
typedef void (*tap_finish_cb)(void *tapdata);

/**
 * Flags to indicate what a tap listener's packet routine requires.
 */
#define TL_REQUIRES_NOTHING         0x00000000	    /**< nothing */
#define TL_REQUIRES_PROTO_TREE      0x00000001	    /**< non-NULL protocol tree */
#define TL_REQUIRES_COLUMNS         0x00000002	    /**< columns */
#define TL_REQUIRES_ERROR_PACKETS   0x00000004	    /**< include packet even if pinfo->flags.in_error_pkt is set */
#define TL_REQUIRES_PROTOCOLS       0x00000020	    /**< don't fake protocols */

/** TL_REQUIRES_PROTO_TREE does not generate the full protocol tree;
 * any fields not referenced (e.g., in a filter) will still be "faked."
 * Note that if the tap does have a filter, it doesn't need
 * TL_REQUIRES_PROTO_TREE because filtering implies needing a tree.
 * It is for ensuring anything normally skipped with a NULL tree won't be,
 * which may include constructing data to pass to the tap. To make all
 * fields visible (which impacts performance), epan_set_always_visible()
 * can be used at the same time as registering the tap.
 * XXX - There should probably be a flag to set the tree visible.
 */

/** Flags to indicate what the tap listener does */
#define TL_IS_DISSECTOR_HELPER      0x00000008	    /**< tap helps a dissector do work
						                             ** but does not, itself, require dissection */

/** Flags to indicate what the packet cb should do */
#define TL_IGNORE_DISPLAY_FILTER    0x00000010      /**< use packet, even if it would be filtered out */
#define TL_DISPLAY_FILTER_IGNORED   0x00100000      /**< flag for the conversation handler */
#define TL_LIMIT_TO_DISPLAY_FILTER  0x00000040      /**< limit to the main display filter, and retap if it changes. */

/** Flags to indicate how the IP aggregation should behave during the statistics cb */
#define TL_IP_AGGREGATION_NULL      0x00000100      /**< default analysis, no aggregation at all */
#define TL_IP_AGGREGATION_ORI       0x00000200      /**< replace with subnets when possible, and keep original data */
#define TL_IP_AGGREGATION_RESERVED  0x00000400      /**< reserved */

/**
 * @brief Describes a tap plugin, providing a callback to register its tap listener with the tap framework.
 */
typedef struct {
    void (*register_tap_listener)(void); /**< Callback invoked during startup to register this plugin's tap listener. */
} tap_plugin;

/** Register tap plugin with the plugin system. */

/**
 * @brief Registers a packet tap plugin.
 *
 * Registers a new packet tap plugin with Wireshark.
 *
 * @param plug Pointer to the tap_plugin structure containing plugin information.
 */
WS_DLL_PUBLIC void tap_register_plugin(const tap_plugin *plug);

/**
 * @brief Describes a single built-in tap registration entry, pairing a tap name with its registration callback.
 */
typedef struct _tap_reg {
    const char* cb_name;    /**< Name identifying the tap registration entry, used for lookup and display. */
    void (*cb_func)(void);  /**< Callback invoked during startup to register this built-in tap. */
} tap_reg_t;

/**
 * @brief For all taps, call their register routines.
 * Must be called after plugins_init(), if plugins are supported,
 * and must be called only once in a program.
 * @param tap_reg_listeners Array of tap_reg_t structures for built-in taps, terminated by an entry with cb_func == NULL.
 */
extern void register_all_tap_listeners(tap_reg_t const *tap_reg_listeners);

/**
 * @brief Initializes the tap system.
 *
 * This function initializes the tap system and should be called once when the dissector is initialized.
 */
extern void tap_init(void);

/**
 * @brief Registers a tap with the given name.
 *
 * This function registers that a dissector has the packet tap ability
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
 * @param name The name of the tap to register.
 * @return The ID of the registered tap, or 0 on failure.
 */
WS_DLL_PUBLIC int register_tap(const char *name);

/**
 * @brief Returns a list of tap names.
 *
 * This function returns a GList containing the names of all available taps.
 *
 * @return A GList of tap names, or NULL if no taps are available.
 */
WS_DLL_PUBLIC GList* get_tap_names(void);

/**
 * @brief Finds the ID of a tap by its name.
 *
 * This function will return the tap_id for the specific protocol tap
 *  or 0 if no such tap was found.
 *
 * @param name The name of the tap to find.
 * @return The tap_id of the tap with the given name, or 0 if not found.
 */
WS_DLL_PUBLIC int find_tap_id(const char *name);

/** Every time the dissector has finished dissecting a packet (and all
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
 *
 * @param tap_id The ID of the tap to which this packet belongs.
 * @param pinfo Pointer to the packet information structure for the current packet.
 * @param tap_specific_data Pointer to tap-specific data, or NULL if not applicable.
 */
WS_DLL_PUBLIC void tap_queue_packet(int tap_id, packet_info *pinfo, const void *tap_specific_data);

/** Functions used by file.c to drive the tap subsystem */

/**
 * @brief Build a list of all interesting hf_fields for tap listeners.
 *
 * Loop over all tap listeners and build the list of all interesting hf_fields.
 *
 * @param edt The epan_dissect_t structure containing the dissection data.
 */
WS_DLL_PUBLIC void tap_build_interesting(epan_dissect_t *edt);

/** This function is used to delete/initialize the tap queue and prime an
 *  epan_dissect_t with all the filters for tap listeners.
 *  To free the tap queue, we just prepend the used queue to the free queue.
 *
 * @param edt The epan_dissect_t structure to prime with tap listener filters.
 */
extern void tap_queue_init(epan_dissect_t *edt);

/** this function is called after a packet has been fully dissected to push the tapped
 *  data to all extensions that has callbacks registered.
 * @param edt The epan_dissect_t structure containing the dissection data for the current packet.
 */
extern void tap_push_tapped_queue(epan_dissect_t *edt);

/**
 * @brief Resets all tap listeners.
 *
 * This function is called after a packet has been fully dissected to push the tapped
 *  data to all extensions that has callbacks registered.
 */
WS_DLL_PUBLIC void reset_tap_listeners(void);

/**
 * @brief Draws all tap listeners.
 *
 * This function is called when we need to redraw all tap listeners, for example
 * when we open/start a new capture or if we need to rescan the packet list.
 * It should be called from a low priority thread say once every 3 seconds
 *
 * If draw_all is true, redraw all applications regardless if they have
 * changed or not.
 *
 * @param draw_all If true, redraw all tap listeners regardless of their state; if false, only redraw those that need it.
 */
WS_DLL_PUBLIC void draw_tap_listeners(bool draw_all);

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
 * @param tap_packet tap_packet_status (*packet)(void *tapdata, packet_info *pinfo, epan_dissect_t *edt, const void *data)
 *                   This callback is used whenever a new packet has arrived at the tap and that
 *                   it has passed the filter (if there were a filter).
 *                   The *data structure type is specific to each tap.
 *                   This function returns an bool and it should return
 *                    true, if the data in the packet caused state to be updated
 *                          (and thus a redraw of the window would later be required)
 *                    false, if we don't need to redraw the window.
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
 * @param tap_finish void (*finish)(void *tapdata)
 *                   This callback is called when your listener is removed.
 */
WS_DLL_PUBLIC GString *register_tap_listener(const char *tapname, void *tapdata,
    const char *fstring, unsigned flags, tap_reset_cb tap_reset,
    tap_packet_cb tap_packet, tap_draw_cb tap_draw,
    tap_finish_cb tap_finish) G_GNUC_WARN_UNUSED_RESULT;

/**
 * @brief Set a display filter for a tap listener.
 *
 * This function sets a display filter for a tap listener using the provided filter string.
 *
 * @param tapdata Pointer to the tap data structure.
 * @param fstring The display filter string.
 * @return A GString containing an error message if the filter is invalid, or NULL on success.
 */
WS_DLL_PUBLIC GString *set_tap_dfilter(void *tapdata, const char *fstring);

/**
 * @brief Recompiles dfilter for all registered tap listeners
 *
 * This function iterates through all registered tap listeners and recompiles their dfilters.
 * If a listener's filter string is invalid, it sets up a dfilter that matches no packets.
 */
WS_DLL_PUBLIC void tap_listeners_dfilter_recompile(void);

/**
 * @brief Removes a tap listener from the queue.
 *
 * @param tapdata Pointer to the tap data associated with the listener to be removed.
 */
WS_DLL_PUBLIC void remove_tap_listener(void *tapdata);

/**
 * @brief Set flags for a tap listener.
 *
 * This function sets the flags for a tap listener identified by the provided tapdata pointer.
 * It returns NULL if the operation is successful, or an error message if it fails.
 *
 * @param tapdata Pointer to the tap data structure.
 * @param flags Flags to be set for the tap listener.
 * @return NULL on success, error message on failure.
 */
WS_DLL_PUBLIC GString *set_tap_flags(void *tapdata, unsigned flags);

/**
 * @brief Check if any tap listeners require dissection.
 *
 * @return true if any tap listeners require dissection, false otherwise.
 */
WS_DLL_PUBLIC bool tap_listeners_require_dissection(void);

/**
 * @brief Check if any tap listeners require column information.
 *
 * @return true if any tap listeners require column information, false otherwise.
 */
WS_DLL_PUBLIC bool tap_listeners_require_columns(void);

/**
 * @brief Check if there is a tap listener with the given ID.
 *
 * @param tap_id The ID of the tap listener to check for.
 * @return true if a tap listener with the given ID exists, false otherwise.
 */
WS_DLL_PUBLIC bool have_tap_listener(int tap_id);

/**
 * @brief Check if there are any tap listeners that require filtering.
 *
 * @return true if there is at least one tap listener with a filter, false otherwise.
 */
WS_DLL_PUBLIC bool have_filtering_tap_listeners(void);

/**
 * @brief If any tap listeners have a filter with references to the currently
 * selected frame in the GUI (edt->tree), update them.
 *
 * @param edt The epan_dissect_t structure containing the dissection data for the current packet.
 */
WS_DLL_PUBLIC void tap_listeners_load_field_references(epan_dissect_t *edt);

/**
 * @brief Get the union of all the flags for all the tap listeners; that gives
 * an indication of whether the protocol tree, or the columns, are
 * required by any taps.
 *
 * @return The union of all the flags for all the tap listeners.
 */
WS_DLL_PUBLIC unsigned union_of_tap_listener_flags(void);

/**
 * @brief Fetch tapped data before returning.
 *
 * This function can be used by a dissector to fetch any tapped data before
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
 *
 * @param tap_id The ID of the tap to fetch data from.
 * @param idx The index of the tapped data to fetch.
 * @return A pointer to the tapped data, or NULL if not found or if tapping is not active.
 */
WS_DLL_PUBLIC const void *fetch_tapped_data(int tap_id, int idx);

/**
 * @brief Clean internal structures
 */
extern void tap_cleanup(void);

/**
 * @brief Loads the main filter in the tapping system for taps that limit their
 * results to the main display filter. Does not take ownership of the filter,
 * which must still be freed in the main program.
 *
 * @param dfcode The main display filter to load into the tapping system.
 */
WS_DLL_PUBLIC void tap_load_main_filter(struct epan_dfilter *dfcode);

#ifdef __cplusplus
}
#endif /* __cplusplus */
