/** @file
 *
 * Definitions for routines to get information about capture interfaces
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CAPTURE_IFINFO_H__
#define __CAPTURE_IFINFO_H__

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Represents the type of a capture interface, with explicit integer
 *        values that are exposed in the preferences gui.interfaces_hidden_types string.
 */
typedef enum {
    IF_WIRED    = 0,  /**< Standard wired (Ethernet) interface */
    IF_AIRPCAP  = 1,  /**< AirPcap wireless capture device */
    IF_PIPE     = 2,  /**< Named pipe interface */
    IF_STDIN    = 3,  /**< Standard input (stdin) interface */
    IF_BLUETOOTH = 4, /**< Bluetooth interface */
    IF_WIRELESS = 5,  /**< Generic wireless (Wi-Fi) interface */
    IF_DIALUP   = 6,  /**< Dial-up (PPP/modem) interface */
    IF_USB      = 7,  /**< USB capture interface */
    IF_EXTCAP   = 8,  /**< External capture (extcap) interface */
    IF_VIRTUAL  = 9,  /**< Virtual interface */
    IF_LOOPBACK = 10, /**< Loopback interface */
    IF_TUNNEL   = 11, /**< Tunnel interface */
} interface_type;

/**
 * @brief Describes the capabilities of a single capture interface.
 *
 * Returned by get_if_capabilities() and capture_if_capabilities();
 * must be released with free_if_capabilities().
 */
typedef struct {
    bool   can_set_rfmon;           /**< True if the interface can be placed into 802.11 monitor mode */
    GList *data_link_types;         /**< Available data link types (::data_link_info_t) in normal mode */
    GList *data_link_types_rfmon;   /**< Available data link types (::data_link_info_t) when in monitor mode */
    GList *timestamp_types;         /**< Available timestamp sources (::timestamp_info_t) for this interface */
    int    status;                  /**< Status code indicating the result of the capabilities query */
    char       *primary_msg;        /**< If non-NULL, the capabilities query failed; this string describes why */
    const char *secondary_msg;      /**< Optional supplementary detail message accompanying @p primary_msg */
} if_capabilities_t;


/**
 * @brief Describes a single network interface returned by get_interface_list().
 */
typedef struct {
    char  *name;                 /**< System interface name (e.g. "eth0", "en0") */
    char  *friendly_name;        /**< Human-readable OS-assigned name (e.g. "Local Area Connection"); NULL if unavailable */
    char  *vendor_description;   /**< Vendor description from pcap_findalldevs() (e.g. "Realtek PCIe GBE Family Controller", Windows only); NULL if unavailable */
    GSList           *addrs;     /**< List of ::if_addr_t address entries assigned to this interface */
    interface_type    type;      /**< Interface type (wired, wireless, pipe, extcap, etc.) */
    bool              loopback;  /**< True if this is a loopback interface */
    char             *extcap;    /**< Extcap argument string used to invoke the extcap interface; NULL for native interfaces */
    if_capabilities_t *caps;     /**< Cached interface capabilities, or NULL if not yet queried */
} if_info_t;

/**
 * @brief Enumeration of supported interface address types.
 *
 * Used to indicate whether an address is IPv4 or IPv6.
 */
typedef enum {
	IF_AT_IPv4, /**< IPv4 address (4 bytes). */
	IF_AT_IPv6  /**< IPv6 address (16 bytes). */
} if_address_type;

/**
 * @brief Represents an IP address in an interface address list.
 *
 * This structure holds either an IPv4 or IPv6 address, along with a type indicator.
 * It is typically used to store addresses associated with network interfaces.
 */
typedef struct {
	if_address_type ifat_type; /**< Type of address (IPv4 or IPv6). */
	union {
		uint32_t ip4_addr;     /**< IPv4 address in network byte order. */
		uint8_t ip6_addr[16];  /**< IPv6 address in network byte order. */
	} addr;
} if_addr_t;

/**
 * @brief Deserialize a serialized interface list into a GList.
 *
 * @param data     Serialized input buffer containing the interface list.
 * @param err      Pointer to an integer set to an error code on failure.
 * @param err_str  Pointer to a string set to a descriptive error message on failure.
 *
 * @return A GList of deserialized interface entries, or NULL on error.
 */
extern GList *deserialize_interface_list(char *data, int *err, char **err_str);

/**
 * @brief Get the list of capture interfaces.
 *
 * This function retrieves the list of available capture interfaces, including local,
 * remote, and extcap interfaces. It uses dumpcap to fetch local interfaces and appends
 * remote and extcap interfaces to the list.
 *
 * @param app_name The name of the application requesting the interface list.
 * @param err Pointer to an integer that will receive an error code if an error occurs.
 * @param err_str Pointer to a string that will receive an error message if an error occurs.
 * @param update_cb Callback function to update the UI during the process.
 * @return A GList containing if_info_t structs if successful, or NULL on failure.
 */
extern GList *capture_interface_list(const char* app_name, int *err, char **err_str, void (*update_cb)(void));

/* Error values from "get_interface_list()/capture_interface_list()". */
#define	CANT_GET_INTERFACE_LIST	1	/* error getting list */
#define	DONT_HAVE_PCAP		2	/* couldn't load WinPcap/Npcap */

/**
 * @brief Free an interface list.
 *
 * @param if_list The interface list to free.
 */
void free_interface_list(GList *if_list);

/**
 * @brief Deep copy an interface list
 * @param if_list The interface list to copy.
 * @return A new GList containing copies of the interface information.
 */
GList * interface_list_copy(GList *if_list);

/**
 * @brief Get an if_info_t for a particular interface.
 * @param name The name of the interface to retrieve information for.
 * @return An allocated if_info_t structure containing information about the interface, or NULL if the interface is not found or an error occurs.
 * @note May require privilege, so should only be used by dumpcap.
 */
extern if_info_t *if_info_get(const char *name);

/**
 * @brief Free an if_info_t.
 * @param if_info The if_info_t structure to free.
 */
void if_info_free(if_info_t *if_info);

/**
 * @brief Deep copy an if_info_t.
 * @param if_info The if_info_t structure to copy.
 * @return A new if_info_t structure containing a copy of the original information.
 */
if_info_t *if_info_copy(const if_info_t *if_info);

/**
 * @brief Deep copy an if_addr_t.
 * @param if_addr The if_addr_t structure to copy.
 * @return A new if_addr_t structure containing a copy of the original information.
 */
if_addr_t *if_addr_copy(const if_addr_t *if_addr);

/**
 * @brief Parameters passed to the interface capabilities query functions.
 */
typedef struct {
    const char *name;             /**< System interface name to query (e.g. "eth0") */
    bool        monitor_mode;     /**< True if capabilities should be queried for 802.11 monitor mode */
    const char *auth_username;    /**< Username for remote capture authentication, or NULL if not required */
    const char *auth_password;    /**< Password for remote capture authentication, or NULL if not required */
} if_cap_query_t;

/**
 * @brief Describes a single data link type available on a capture interface.
 */
typedef struct {
    int   dlt;         /**< libpcap DLT_ value identifying the link type (e.g. DLT_EN10MB = 1) */
    char *name;        /**< Short DLT name string (e.g. "EN10MB" or "DLT 1") */
    char *description; /**< Human-readable description from Wiretap (e.g. "Ethernet"); NULL if unknown */
} data_link_info_t;

/**
 * @brief Describes a single timestamp source available on a capture interface.
 */
typedef struct {
    char *name;        /**< Short internal timestamp type name from libpcap (e.g. "adapter_unsynced") */
    char *description; /**< Human-readable description from libpcap (e.g. "Adapter, not synced with system time") */
} timestamp_info_t;

/**
 * Fetch the linktype list for the specified interface from a child process.
 */
extern if_capabilities_t *
capture_get_if_capabilities(const char* app_name, const char *devname, bool monitor_mode,
                            const char *auth_string,
                            char **err_primary_msg, char **err_secondary_msg,
                            void (*update_cb)(void));

/**
 * Fetch the linktype list for the specified interface from a child process.
 */
extern GHashTable *
capture_get_if_list_capabilities(const char* app_name, GList *if_cap_queries,
                            char **err_primary_msg, char **err_secondary_msg,
                            void (*update_cb)(void));

/**
 * @brief Frees the memory allocated for interface capabilities.
 *
 * @param caps Pointer to the if_capabilities_t structure to be freed.
 */
void free_if_capabilities(if_capabilities_t *caps);

#ifdef HAVE_PCAP_REMOTE
void add_interface_to_remote_list(if_info_t *if_info);

GList* append_remote_list(GList *iflist);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CAPTURE_IFINFO_H__ */
