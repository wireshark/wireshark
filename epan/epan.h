/** @file
 *
 * Wireshark Protocol Analyzer Library
 *
 * Copyright (c) 2001 by Gerald Combs <gerald@wireshark.org>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __EPAN_H__
#define __EPAN_H__

#include <wsutil/feature_list.h>
#include <epan/tvbuff.h>
#include <epan/prefs.h>
#include <epan/frame_data.h>
#include <epan/register.h>
#include <wiretap/wtap_opttypes.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Controls whether Wireshark should abort on a dissector bug.
 *
 * This global variable reflects the value of the corresponding environment variable,
 * allowing Wireshark to avoid repeatedly querying the environment.
 * If set to true, Wireshark will abort when a dissector bug is detected.
 */
extern bool wireshark_abort_on_dissector_bug;

/**
 * @brief Controls whether Wireshark should abort when too many items are added to a tree.
 *
 * This global variable reflects the value of the corresponding environment variable,
 * allowing Wireshark to avoid repeatedly querying the environment.
 * If set to true, Wireshark will abort when the protocol tree exceeds a safety threshold.
 */
extern bool wireshark_abort_on_too_many_items;

/**
 * @brief Report a dissector bug (and optionally abort).
 *
 * @param format  printf-like format string.
 * @param ...     printf-like parameters.
 */
WS_DLL_PUBLIC void ws_dissector_bug(const char *format, ...)
    G_GNUC_PRINTF(1,2);

/**
 * @brief Report a dissector OOPS (and optionally abort).
 *
 * @param _fmt  printf-like format string literal.
 * @param ...   printf-like parameters.
 */
#define ws_dissector_oops(_fmt, ...) ws_dissector_bug("OOPS: " _fmt, __VA_ARGS__)

/**
 * @brief Opaque type representing a single packet dissection context.
 *
 * Used to manage state and results during the dissection of an individual packet.
 * Typically created with @ref epan_dissect_new and freed with @ref epan_dissect_free.
 */
typedef struct epan_dissect epan_dissect_t;

struct epan_dfilter;
struct epan_column_info;

/**
 * Opaque structure provided when an epan_t is created; it contains
 * information needed to allow the user of libwireshark to provide
 * time stamps, comments, and other information outside the packet
 * data itself.
 */
struct packet_provider_data;

/**
 * @brief Structure containing pointers to functions supplied by the user of libwireshark.
 *
 * Each function pointer corresponds to a callback that provides specific
 * information about packets, interfaces, or processes during packet processing.
 */
struct packet_provider_funcs {
    /**
     * @brief Get the timestamp of a specific frame.
     *
     * @param prov Packet provider context.
     * @param frame_num Frame number to query.
     * @return Pointer to the timestamp, or NULL if unavailable.
     */
    const nstime_t *(*get_frame_ts)(struct packet_provider_data *prov, uint32_t frame_num);

    /**
     * @brief Get the start timestamp of the capture session.
     *
     * @param prov Packet provider context.
     * @return Pointer to the start timestamp, or NULL if unavailable.
     */
    const nstime_t *(*get_start_ts)(struct packet_provider_data *prov);

    /**
     * @brief Get the end timestamp of the capture session.
     *
     * @param prov Packet provider context.
     * @return Pointer to the end timestamp, or NULL if unavailable.
     */
    const nstime_t *(*get_end_ts)(struct packet_provider_data *prov);

    /**
     * @brief Get the name of a capture interface.
     *
     * @param prov Packet provider context.
     * @param interface_id Interface identifier.
     * @param section_number Capture section number.
     * @return Interface name string, or NULL if unavailable.
     */
    const char *(*get_interface_name)(struct packet_provider_data *prov, uint32_t interface_id, unsigned section_number);

    /**
     * @brief Get the description of a capture interface.
     *
     * @param prov Packet provider context.
     * @param interface_id Interface identifier.
     * @param section_number Capture section number.
     * @return Interface description string, or NULL if unavailable.
     */
    const char *(*get_interface_description)(struct packet_provider_data *prov, uint32_t interface_id, unsigned section_number);

    /**
     * @brief Get a modified WTAP block for a given frame.
     *
     * @param prov Packet provider context.
     * @param fd Frame metadata.
     * @return Modified WTAP block, or NULL if unchanged.
     */
    wtap_block_t (*get_modified_block)(struct packet_provider_data *prov, const frame_data *fd);

    /**
     * @brief Get the process ID associated with a packet.
     *
     * @param prov Packet provider context.
     * @param process_info_id Process info identifier.
     * @param section_number Capture section number.
     * @return Process ID, or -1 if unavailable.
     */
    int32_t (*get_process_id)(struct packet_provider_data *prov, uint32_t process_info_id, unsigned section_number);

    /**
     * @brief Get the name of the process associated with a packet.
     *
     * @param prov Packet provider context.
     * @param process_info_id Process info identifier.
     * @param section_number Capture section number.
     * @return Process name string, or NULL if unavailable.
     */
    const char *(*get_process_name)(struct packet_provider_data *prov, uint32_t process_info_id, unsigned section_number);

    /**
     * @brief Get the UUID of the process associated with a packet.
     *
     * @param prov Packet provider context.
     * @param process_info_id Process info identifier.
     * @param section_number Capture section number.
     * @param uuid_size Output parameter for the size of the UUID.
     * @return Pointer to the UUID byte array, or NULL if unavailable.
     */
    const uint8_t *(*get_process_uuid)(struct packet_provider_data *prov, uint32_t process_info_id, unsigned section_number, size_t *uuid_size);
};

/**
	@section Epan The Enhanced Packet ANalyzer

	XXX

	@b Sections:
*/
/*
Ref 1
Epan
Enhanced Packet ANalyzer, aka the packet analyzing engine. Source code can be found in the epan directory.

Protocol-Tree - Keep data of the capture file protocol information.

Dissectors - The various protocol dissectors in epan/dissectors.

Plugins - Some of the protocol dissectors are implemented as plugins. Source code can be found at plugins.

Display-Filters - the display filter engine at epan/dfilter

*/

/**
 * @brief Information about the application that wants to use epan.
 */
typedef struct {
	const char* env_var_prefix;		/**< The prefix for the application environment variable used to get the configuration directories. */
	const char** col_fmt;			/**< Array of columns and their formats */
	int num_cols;				/**< Number of columns in the list above */
	register_entity_func register_func;	/**< Callback to register entities for the dissection engine */
	register_entity_func handoff_func;	/**< Callback to handoff function for entities in the dissection engine */
	struct _tap_reg const* tap_reg_listeners;	/**< List of tap registration routines to register built-in tap listeners */
} epan_app_data_t;

/**
 * @brief Initialize the entire epan module.
 *
 * This function must be called only once in a program to set up the module.
 *
 * @param cb           A callback function used for registration.
 * @param client_data  Pointer to client-specific data passed to the callback.
 * @param load_plugins Whether to load plugins during initialization.
 *
 * @return true if initialization succeeds, false otherwise.
 */
WS_DLL_PUBLIC
bool epan_init(register_cb cb, void *client_data, bool load_plugins, epan_app_data_t* app_data);

/**
 * @brief Load all settings from the current profile that affect epan.
 *
 * @return Pointer to the loaded preferences structure.
 */
WS_DLL_PUBLIC
e_prefs *epan_load_settings(void);

/**
 * @brief Clean up the entire epan module.
 *
 * This function should be called only once in a program, typically during shutdown,
 * to release resources and perform all necessary cleanup.
 */
WS_DLL_PUBLIC
void epan_cleanup(void);


/**
 * @struct epan_plugin
 * @brief Plugin interface for EPAN modules.
 *
 * Defines the lifecycle and registration hooks for EPAN plugins. Each function
 * pointer corresponds to a specific initialization or registration phase.
 */
typedef struct {
    /**
     * @brief Called before `proto_init()`.
     */
    void (*init)(void);

    /**
     * @brief Called at the end of `epan_init()`.
     */
    void (*post_init)(void);

    /**
     * @brief Called before each dissection begins.
     */
    void (*dissect_init)(epan_dissect_t *);

    /**
     * @brief Called after each dissection completes.
     */
    void (*dissect_cleanup)(epan_dissect_t *);

    /**
     * @brief Called during EPAN shutdown.
     */
    void (*cleanup)(void);

    /**
     * @brief Register all protocols with the core.
     *
     * @param cb Callback used for registration.
     * @param user_data Optional user data passed to the callback.
     */
    void (*register_all_protocols)(register_cb cb, void *user_data);

    /**
     * @brief Register all protocol handoffs.
     *
     * @param cb Callback used for registration.
     * @param user_data Optional user data passed to the callback.
     */
    void (*register_all_handoffs)(register_cb cb, void *user_data);

    /**
     * @brief Register all tap listeners.
     */
    void (*register_all_tap_listeners)(void);
} epan_plugin;

/**
 * @brief Register an epan plugin with the dissection engine.
 *
 * This function registers a plugin that provides dissectors, taps, or other
 * protocol-related functionality. It should be called during plugin initialization,
 * typically from the plugin's entry point (e.g., plugin_register()).
 *
 * Registered plugins are integrated into the epan framework and can contribute
 * to packet analysis during dissection.
 *
 * @param plugin Pointer to the epan_plugin structure containing plugin metadata and hooks.
 */
WS_DLL_PUBLIC void epan_register_plugin(const epan_plugin *plugin);

/**
 * @brief Check plugin support status for libwireshark components.
 *
 * @return
 *   - 0 if plugins can be loaded for all of libwireshark (tap, dissector, epan).
 *   - 1 if plugins are not supported by the platform.
 *   - -1 if plugins were disabled in the build configuration.
 */
WS_DLL_PUBLIC int epan_plugins_supported(void);

/**
 * @brief Initialize the table of conversations.
 *
 * Conversations are identified by their endpoints and are used for protocols such as IP, TCP, and UDP,
 * where packets contain endpoint information but don't contain a single value indicating
 * which flow the packet belongs to.
 */
void epan_conversation_init(void);


typedef struct epan_session epan_t;
/**
 * @brief Represents a dissection session state.
 *
 * A client creates one `epan_t` for an entire dissection session.
 * This single `epan_t` instance analyzes the entire sequence of packets sequentially,
 * corresponding to a single packet trace file.
 *
 * `epan_t` exists because some protocols require knowledge of previous packets
 * to decode certain packets correctly. This inter-packet "state" is maintained within `epan_t`.
 */
typedef struct epan_session epan_t;

/**
 * @brief Create a new epan dissection session.
 *
 * This function allocates and initializes an `epan_t` session object,
 * which maintains state across multiple packet dissections.
 * It requires a packet provider and its associated function table to supply
 * runtime data such as timestamps, interface metadata, and process info.
 *
 * @param prov  Pointer to the packet provider data.
 * @param funcs Pointer to the packet provider function table.
 *
 * @return A pointer to the newly created epan session object.
 */
WS_DLL_PUBLIC epan_t *epan_new(struct packet_provider_data *prov,
    const struct packet_provider_funcs *funcs);

/**
 * @brief Retrieve a modified capture block associated with a specific frame.
 *
 * This function returns a `wtap_block_t` that reflects any modifications
 * made to the original capture block for the given frame. These modifications
 * may include metadata updates or annotations applied during dissection.
 *
 * @param session  The epan session context.
 * @param fd       Pointer to the frame data for which the modified block is requested.
 *
 * @return The modified capture block, or NULL if no modifications exist.
 */
WS_DLL_PUBLIC wtap_block_t epan_get_modified_block(const epan_t *session, const frame_data *fd);

/**
 * @brief Retrieve the name of a network interface.
 *
 * This function queries the epan session for the name of a specific interface,
 * identified by its interface ID and section number. Interface names are typically
 * derived from capture metadata and may reflect physical or logical device labels.
 *
 * @param session        The epan session context.
 * @param interface_id   The interface's identifier.
 * @param section_number The section number within the capture file.
 *
 * @return A pointer to a string containing the interface name, or NULL if not available.
 *
 * @see epan_get_interface_description()
 */
WS_DLL_PUBLIC const char *epan_get_interface_name(const epan_t *session, uint32_t interface_id, unsigned section_number);

/**
 * @brief Retrieve the description of a network interface.
 *
 * This function queries the epan session for a textual description of a specific interface,
 * identified by its interface ID and section number. Descriptions may include hardware details,
 * driver info, or capture context metadata.
 *
 * @param session        The epan session context.
 * @param interface_id   The interface's identifier.
 * @param section_number The section number within the capture file.
 *
 * @return A pointer to a string containing the interface description, or NULL if not available.
 * @see epan_get_interface_name()
 */
WS_DLL_PUBLIC const char *epan_get_interface_description(const epan_t *session, uint32_t interface_id, unsigned section_number);

/**
 * @brief Retrieve the process ID associated with a given process info record.
 *
 * This function queries the epan session for the process ID corresponding to
 * the specified process information ID and section number. Process metadata
 * may be extracted from capture blocks or external annotations.
 *
 * @param session          The epan session context.
 * @param process_info_id  The identifier for the process information.
 * @param section_number   The section number within the capture file.
 *
 * @return The process ID (int32_t), or -1 if not available.
 *
 * @see epan_get_process_name()
 * @see epan_get_process_uuid()
 */
WS_DLL_PUBLIC int32_t epan_get_process_id(const epan_t *session, uint32_t process_info_id, unsigned section_number);

/**
 * @brief Retrieve the name of a process associated with a given process info record.
 *
 * This function queries the epan session for the name of a process identified by
 * the specified process information ID and section number. Process names may be
 * extracted from capture metadata or annotations.
 *
 * @param session          The epan session context.
 * @param process_info_id  The identifier for the process information.
 * @param section_number   The section number within the capture file.
 *
 * @return A pointer to a string containing the process name, or NULL if not available.
 *
 * @see epan_get_process_id()
 * @see epan_get_process_uuid()
 */
WS_DLL_PUBLIC const char *epan_get_process_name(const epan_t *session, uint32_t process_info_id, unsigned section_number);

/**
 * @brief Retrieve the UUID of a process associated with a given process info record.
 *
 * This function queries the epan session for the UUID of a process identified by
 * the specified process information ID and section number. The UUID is returned
 * as a pointer to a byte array, and its size is stored in the provided output parameter.
 *
 * @param session          The epan session context.
 * @param process_info_id  The identifier for the process information.
 * @param section_number   The section number within the capture file.
 * @param uuid_size        Output parameter that receives the size of the UUID in bytes.
 *
 * @return A pointer to the UUID byte array, or NULL if not available.
 *
 * @see epan_get_process_id()
 * @see epan_get_process_name()
 */
WS_DLL_PUBLIC const uint8_t *epan_get_process_uuid(const epan_t *session, uint32_t process_info_id, unsigned section_number, size_t *uuid_size);

/**
 * @brief Retrieve the timestamp of a specific frame.
 *
 * This function queries the epan session for the timestamp associated with
 * the given frame number.
 *
 * @param session    The epan session context.
 * @param frame_num  The frame number to query.
 *
 * @return A pointer to the timestamp (`nstime_t`) of the specified frame,
 *         or NULL if unavailable.
 */
const nstime_t *epan_get_frame_ts(const epan_t *session, uint32_t frame_num);

/**
 * @brief Retrieve the start timestamp of the capture session.
 *
 * This function returns the timestamp marking the beginning of the capture,
 * as recorded in the associated epan session.
 *
 * @param session  The epan session context.
 *
 * @return A pointer to the start timestamp (`nstime_t`), or NULL if unavailable.
 */
const nstime_t *epan_get_start_ts(const epan_t *session);

/**
 * @brief Free an epan dissection session.
 *
 * This function releases all resources associated with the given `epan_t` session.
 * It should be called once the session is no longer needed, typically after all
 * packet dissections are complete.
 *
 * @param session  Pointer to the epan session to be freed.
 */
WS_DLL_PUBLIC void epan_free(epan_t *session);

/**
 * @brief Retrieve the epan library's version as a string.
 *
 * This function returns a static string representing the version of the
 * libwireshark dissection engine (epan). For example, "4.7.0".
 *
 * @return A pointer to a constant string containing the epan version.
 *
 * @see epan_get_version_number()
 */
WS_DLL_PUBLIC const char* epan_get_version(void);

/**
 * @brief Retrieve the version number of the epan library.
 *
 * This function provides the major, minor, and micro components of the
 * libwireshark dissection engine (epan) version. It is useful for programmatic
 * version checks, compatibility validation, or display formatting.
 *
 * @param major  Pointer to an integer to receive the major version.
 * @param minor  Pointer to an integer to receive the minor version.
 * @param micro  Pointer to an integer to receive the micro (patch) version.
 *
 * @see epan_get_version()
 */
WS_DLL_PUBLIC void epan_get_version_number(int *major, int *minor, int *micro);

/**
 * @brief Retrieve the environment prefix string used by epan.
 *
 * This provides a "local copy" of the environment prefix used by the application
 * when epan is initialized and aids in encapsulation.
 *
 * @return A pointer to a constant string containing the environment prefix.
 */
WS_DLL_PUBLIC const char* epan_get_environment_prefix(void);

/**
 * @brief Set or unset the tree to always be visible when epan_dissect_init() is called.
 *
 * This state change persists until explicitly cleared, rather than being applied per function call.
 * It is currently used when Lua scripts request all fields to be generated.
 *
 * By default, the tree only becomes visible if epan_dissect_init() enables it, usually when a packet is selected.
 * Setting this forces the tree to always be visible, although it will still not be created if
 * create_proto_tree is false in the epan_dissect_init() call.
 *
 * Clearing this setting reverts the visibility decision back to epan_dissect_init() and proto_tree_visible.
 *
 * @param force  If true, the tree is always visible; if false, visibility follows default behavior.
 */
WS_DLL_PUBLIC
void epan_set_always_visible(bool force);

/**
 * @brief Initialize an existing single packet dissection.
 *
 * @param edt               The dissection context to initialize.
 * @param session           The epan session associated with the dissection.
 * @param create_proto_tree Whether to create a protocol tree for the dissection.
 * @param proto_tree_visible Whether the protocol tree should be visible after initialization.
 */
WS_DLL_PUBLIC
void
epan_dissect_init(epan_dissect_t *edt, epan_t *session, const bool create_proto_tree, const bool proto_tree_visible);

/**
 * @brief Create a new single packet dissection.
 *
 * The returned dissection should be freed using @ref epan_dissect_free()
 * after packet dissection is completed.
 *
 * @param session           The epan session to associate with the dissection.
 * @param create_proto_tree Whether to create a protocol tree for this dissection.
 * @param proto_tree_visible Whether the protocol tree should be visible.
 *
 * @return A pointer to the newly allocated epan_dissect_t.
 */
WS_DLL_PUBLIC
epan_dissect_t*
epan_dissect_new(epan_t *session, const bool create_proto_tree, const bool proto_tree_visible);

/**
 * @brief Reset a dissection context for reuse.
 *
 * This function clears the internal state of an existing `epan_dissect_t` object,
 * allowing it to be reused for dissecting another packet without reallocating
 * the entire structure. It preserves configuration flags such as protocol tree visibility.
 *
 * @param edt  The dissection context to reset.
 */
WS_DLL_PUBLIC
void
epan_dissect_reset(epan_dissect_t *edt);

/**
 * @brief Indicate whether protocols should be faked during dissection.
 *
 * @param edt             The dissection context.
 * @param fake_protocols  If true, protocols are faked; if false, they are not.
 */
WS_DLL_PUBLIC
void
epan_dissect_fake_protocols(epan_dissect_t *edt, const bool fake_protocols);

/**
 * @brief Run a single packet dissection.
 *
 * This function performs protocol dissection on a single packet using the provided
 * dissection context. It populates protocol trees, updates column information,
 * and applies decoding logic based on the capture file format and packet metadata.
 *
 * @param edt               The dissection context to use.
 * @param file_type_subtype The subtype of the capture file format (e.g., WTAP_FILE_PCAP).
 * @param rec               Pointer to the raw packet record (`wtap_rec`) containing metadata.
 * @param fd                Pointer to the frame data for the packet.
 * @param cinfo             Pointer to the column info structure to be updated during dissection.
 */
WS_DLL_PUBLIC
void
epan_dissect_run(epan_dissect_t *edt, int file_type_subtype,
        wtap_rec *rec, frame_data *fd, struct epan_column_info *cinfo);

/**
 * @brief Run a single packet dissection and invoke tap listeners.
 *
 * This function performs protocol dissection on a single packet using the provided
 * dissection context, similar to @ref epan_dissect_run, but additionally triggers
 * any registered tap listeners. Tap listeners are used to extract and process
 * protocol-specific data during dissection (e.g., for statistics or UI updates).
 *
 * @param edt               The dissection context to use.
 * @param file_type_subtype The subtype of the capture file format (e.g., WTAP_FILE_PCAP).
 * @param rec               Pointer to the raw packet record (`wtap_rec`) containing metadata.
 * @param fd                Pointer to the frame data for the packet.
 * @param cinfo             Pointer to the column info structure to be updated during dissection.
 *
 * @see epan_dissect_run()
 */
WS_DLL_PUBLIC
void
epan_dissect_run_with_taps(epan_dissect_t *edt, int file_type_subtype,
        wtap_rec *rec, frame_data *fd, struct epan_column_info *cinfo);

/**
 * @brief Run a dissection of file-based packet data.
 *
 * This function performs protocol dissection on a packet sourced from a capture file,
 * using the provided dissection context. Unlike live capture dissection, this assumes
 * the packet is static and fully recorded. It populates protocol trees and updates
 * column information accordingly.
 *
 * @param edt   The dissection context to use.
 * @param rec   Pointer to the raw packet record (`wtap_rec`) containing metadata.
 * @param fd    Pointer to the frame data for the packet.
 * @param cinfo Pointer to the column info structure to be updated during dissection.
 *
 * @see epan_dissect_file_run_with_taps()
 */
WS_DLL_PUBLIC
void
epan_dissect_file_run(epan_dissect_t *edt, wtap_rec *rec,
        frame_data *fd, struct epan_column_info *cinfo);

/**
 * @brief Run a dissection of file-based packet data and invoke tap listeners.
 *
 * This function performs protocol dissection on a packet sourced from a capture file,
 * using the provided dissection context. Unlike live capture dissection, this assumes
 * the packet is static and fully recorded. In addition to populating protocol trees and
 * updating column information, it triggers any registered tap listeners to extract
 * protocol-specific data during dissection.
 *
 * @param edt   The dissection context to use.
 * @param rec   Pointer to the raw packet record (`wtap_rec`) containing metadata.
 * @param fd    Pointer to the frame data for the packet.
 * @param cinfo Pointer to the column info structure to be updated during dissection.
 *
 * @see epan_dissect_file_run()
 */
WS_DLL_PUBLIC
void
epan_dissect_file_run_with_taps(epan_dissect_t *edt, wtap_rec *rec,
        frame_data *fd, struct epan_column_info *cinfo);

/**
 * @brief Prime a dissection context's protocol tree using a display filter.
 *
 * This function prepares the `epan_dissect_t` context by preloading protocol and field
 * definitions referenced in the given display filter. This ensures that the protocol tree
 * includes all necessary elements for evaluation, even if they wouldn't normally be generated
 * during dissection.
 *
 * This is typically used to guarantee that all fields required by a filter expression
 * are available for matching or display.
 *
 * @param edt     The dissection context to prime.
 * @param dfcode  The compiled display filter to use for priming.
 *
 * @see epan_dissect_prime_with_dfilter_print
 */
WS_DLL_PUBLIC
void
epan_dissect_prime_with_dfilter(epan_dissect_t *edt, const struct epan_dfilter *dfcode);

/**
 * @brief Prime a dissection context's protocol tree using a display filter, marking fields for print output.
 *
 * This function prepares the `epan_dissect_t` context by preloading protocol and field definitions
 * referenced in the given display filter, and marks those fields for inclusion in print-style output.
 * This ensures that all relevant fields are available and flagged for textual rendering, even if they
 * wouldn't normally be generated during dissection.
 *
 * @param edt     The dissection context to prime.
 * @param dfcode  The compiled display filter to use for priming and print marking.
 *
 * @see epan_dissect_prime_with_dfilter()
 */
WS_DLL_PUBLIC
void
epan_dissect_prime_with_dfilter_print(epan_dissect_t *edt, const struct epan_dfilter *dfcode);

/**
 * @brief Prime a dissection context's protocol tree with a specific field or protocol.
 *
 * This function prepares the `epan_dissect_t` context by preloading the protocol or field
 * identified by the given header field ID (`hfid`). This ensures that the corresponding
 * dissector logic and tree nodes are initialized and available during dissection,
 * even if they wouldn't normally be triggered by the packet content alone.
 *
 * @param edt   The dissection context to prime.
 * @param hfid  The header field ID of the protocol or field to preload.
 *
 * @see epan_dissect_prime_with_dfilter()
 */
WS_DLL_PUBLIC
void
epan_dissect_prime_with_hfid(epan_dissect_t *edt, int hfid);

/**
 * @brief Prime a dissection context's protocol tree with a set of fields or protocols.
 *
 * This function prepares the `epan_dissect_t` context by preloading all protocol and field
 * definitions referenced by the header field IDs (`hfids`) in the provided `GArray`. This ensures
 * that the corresponding dissector logic and tree nodes are initialized and available during
 * dissection, even if they wouldn't normally be triggered by the packet content alone.
 *
 * @param edt    The dissection context to prime.
 * @param hfids  A `GArray` of integers representing header field IDs to preload.
 *
 * @see epan_dissect_prime_with_hfid()
 */
WS_DLL_PUBLIC
void
epan_dissect_prime_with_hfid_array(epan_dissect_t *edt, GArray *hfids);

/**
 * @brief Populate packet list columns with dissection output.
 *
 * This function fills in the column data for a packet after dissection,
 * using the provided `epan_dissect_t` context. It can populate both
 * column expressions (e.g., protocol fields) and frame data–derived columns
 * (e.g., packet number, timestamp).
 *
 * @param edt               The dissection context containing parsed packet data.
 * @param fill_col_exprs    If true, populate columns based on display filter expressions.
 * @param fill_fd_colums    If true, populate columns based on frame metadata.
 */
WS_DLL_PUBLIC
void
epan_dissect_fill_in_columns(epan_dissect_t *edt, const bool fill_col_exprs, const bool fill_fd_colums);

/**
 * @brief Check whether a dissected packet contains a specific named field.
 *
 * This function inspects the protocol tree within the given dissection context
 * to determine whether a field with the specified name was generated during dissection.
 * Field names should match those registered via the protocol registrar (e.g., "ip.src").
 *
 * @param edt         The dissection context to query.
 * @param field_name  The name of the field to check (e.g., "tcp.port").
 *
 * @return True if the field is present in the dissected packet; false otherwise.
 *
 * @see proto_registrar_get_byname()
 * @see epan_dissect_run()
 */
WS_DLL_PUBLIC
bool
epan_dissect_packet_contains_field(epan_dissect_t* edt,
                                   const char *field_name);

/**
 * @brief Release resources associated with a packet dissection context.
 *
 * This function cleans up internal allocations and temporary data structures
 * attached to the given `epan_dissect_t` context.
 *
 * @note This does **not** free the `epan_dissect_t` pointer itself—use
 * `epan_dissect_free()` for full teardown.
 *
 * @param edt  The dissection context to clean up.
 *
 * @see epan_dissect_free()
 */
WS_DLL_PUBLIC
void
epan_dissect_cleanup(epan_dissect_t* edt);

/**
 * @brief Free a single packet dissection context.
 *
 * This function releases all memory and resources associated with the given
 * @ref epan_dissect_t object.
 *
 * @param edt The dissection context to free.
 *
 * @see epan_dissect_cleanup()
 */
WS_DLL_PUBLIC
void
epan_dissect_free(epan_dissect_t* edt);

/**
 * @brief Set the value of a custom column based on specified fields and expression.
 *
 * This function evaluates a custom column expression against the current dissection context
 * and populates the output buffer with the resulting string. It supports selecting specific
 * field occurrences and optionally includes detailed formatting.
 *
 * @param edt             The dissection context to evaluate against.
 * @param ids             A list of header field IDs (@ref hf_register_info) used in the expression.
 * @param occurrence      The occurrence index of the field to extract (e.g., 0 for first match).
 * @param display_details If true, include detailed formatting (e.g., label/value pairs).
 * @param result          Output buffer to receive the formatted column string.
 * @param expr            The custom column expression to evaluate.
 * @param size            The size of the output buffer.
 *
 * @return A pointer to the result buffer, or NULL if evaluation failed.
 */
const char *
epan_custom_set(epan_dissect_t *edt, GSList *ids, int occurrence, bool display_details,
                char *result, char *expr, const int size);

/**
 * @brief Get compile-time information for libraries used by libwireshark.
 *
 * @param l  The feature list object to store the compile-time information.
 */
WS_DLL_PUBLIC
void
epan_gather_compile_info(feature_list l);

/**
 * @brief Get runtime information for libraries used by libwireshark.
 *
 * @param l  The feature list object to store the runtime information.
 */
WS_DLL_PUBLIC
void
epan_gather_runtime_info(feature_list l);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __EPAN_H__ */
