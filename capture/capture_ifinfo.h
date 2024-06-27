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

/*
 * Explicitly set the interface_type enum values as these values are exposed
 * in the preferences gui.interfaces_hidden_types string.
 */
typedef enum {
	IF_WIRED	= 0,
	IF_AIRPCAP	= 1,
	IF_PIPE		= 2,
	IF_STDIN	= 3,
	IF_BLUETOOTH	= 4,
	IF_WIRELESS	= 5,
	IF_DIALUP	= 6,
	IF_USB		= 7,
	IF_EXTCAP	= 8,
	IF_VIRTUAL	= 9
} interface_type;

/*
 * "get_if_capabilities()" and "capture_if_capabilities()" return a pointer
 * to an allocated instance of this structure.  "free_if_capabilities()"
 * frees the returned instance.
 */
typedef struct {
	bool	can_set_rfmon;	/* true if can be put into monitor mode */
	GList		*data_link_types;	/* GList of data_link_info_t's */
	GList		*data_link_types_rfmon; /* GList of data_link_info_t's */
	GList		*timestamp_types;   /* GList of timestamp_info_t's */
	int status;
	char *primary_msg;   /* If non-NULL, the query failed, and a message explaining why */
	const char *secondary_msg; /* An optional supplementary message */
} if_capabilities_t;

/*
 * The list of interfaces returned by "get_interface_list()" is
 * a list of these structures.
 */
typedef struct {
	char	*name;          /* e.g. "eth0" */
	char	*friendly_name; /* from OS, e.g. "Local Area Connection", or
				   NULL if not available */
	char	*vendor_description;
				/* vendor description from pcap_findalldevs(),
				   e.g. "Realtek PCIe GBE Family Controller",
				   or NULL if not available */
	GSList  *addrs;         /* containing address values of if_addr_t */
	interface_type type;    /* type of interface */
	bool loopback;      /* true if loopback, false otherwise */
	char	*extcap;		/* extcap arguments, which present the data to call the extcap interface */
	if_capabilities_t *caps;
} if_info_t;

/*
 * An address in the "addrs" list.
 */
typedef enum {
	IF_AT_IPv4,
	IF_AT_IPv6
} if_address_type;

typedef struct {
	if_address_type ifat_type;
	union {
		uint32_t ip4_addr;   /*  4 byte IP V4 address, or */
		uint8_t ip6_addr[16];/* 16 byte IP V6 address */
	} addr;
} if_addr_t;

extern GList *deserialize_interface_list(char *data, int *err, char **err_str);

/**
 * Return the list of interfaces.
 *
 * Local interfaces are fetched by running dumpcap.
 * The remote and extcap interfaces are appended to the list after that.
 */
extern GList *capture_interface_list(int *err, char **err_str, void (*update_cb)(void));

/* Error values from "get_interface_list()/capture_interface_list()". */
#define	CANT_GET_INTERFACE_LIST	1	/* error getting list */
#define	DONT_HAVE_PCAP		2	/* couldn't load WinPcap/Npcap */

void free_interface_list(GList *if_list);

/**
 * Deep copy an interface list
 */
GList * interface_list_copy(GList *if_list);

/**
 * Get an if_info_t for a particular interface.
 * (May require privilege, so should only be used by dumpcap.)
 */
extern if_info_t *if_info_get(const char *name);

/**
 * Free an if_info_t.
 */
void if_info_free(if_info_t *if_info);

/**
 * Deep copy an if_info_t.
 */
if_info_t *if_info_copy(const if_info_t *if_info);

/**
 * Deep copy an if_addr_t.
 */
if_addr_t *if_addr_copy(const if_addr_t *if_addr);

typedef struct {
        const char *name;
        bool monitor_mode;
        const char *auth_username;
        const char *auth_password;
} if_cap_query_t;

/*
 * Information about data link types.
 */
typedef struct {
	int	dlt;            /* e.g. DLT_EN10MB (which is 1) */
	char	*name;          /* e.g. "EN10MB" or "DLT 1" */
	char	*description;   /* descriptive name from wiretap e.g. "Ethernet", NULL if unknown */
} data_link_info_t;

/*
 * Information about timestamp types.
 */
typedef struct {
	char	*name;          /* e.g. "adapter_unsynced" */
	char	*description;   /* description from libpcap e.g. "Adapter, not synced with system time" */
} timestamp_info_t;

/**
 * Fetch the linktype list for the specified interface from a child process.
 */
extern if_capabilities_t *
capture_get_if_capabilities(const char *devname, bool monitor_mode,
                            const char *auth_string,
                            char **err_primary_msg, char **err_secondary_msg,
                            void (*update_cb)(void));

/**
 * Fetch the linktype list for the specified interface from a child process.
 */
extern GHashTable *
capture_get_if_list_capabilities(GList *if_cap_queries,
                            char **err_primary_msg, char **err_secondary_msg,
                            void (*update_cb)(void));

void free_if_capabilities(if_capabilities_t *caps);

#ifdef HAVE_PCAP_REMOTE
void add_interface_to_remote_list(if_info_t *if_info);

GList* append_remote_list(GList *iflist);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CAPTURE_IFINFO_H__ */
