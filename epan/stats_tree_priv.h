/** @file
 * implementor's API for stats_tree
 * 2005, Luis E. G. Ontanon
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include "stats_tree.h"
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define INDENT_MAX 32
#define NUM_BUF_SIZE 32

/** implementations should define this to contain its own node related data
 * as well as some operations on it */
typedef struct _st_node_pres st_node_pres;

/** implementations should define this to contain its own dynamic tree related data
* as well as some operations on it */
typedef struct _tree_pres tree_pres;

/** implementations should define this to contain its own static tree related data
* as well as some operations on it */
typedef struct _tree_cfg_pres tree_cfg_pres;


typedef struct _stat_node stat_node;
typedef struct _stats_tree_cfg stats_tree_cfg;

/**
 * @brief Represents an inclusive integer range with a lower and upper bound.
 */
typedef struct _range_pair {
    int floor; /**< Inclusive lower bound of the range. */
    int ceil;  /**< Inclusive upper bound of the range. */
} range_pair_t;

typedef struct _burst_bucket burst_bucket;
/**
 * @brief Represents a single time bucket in a burst analysis sliding window, linked into a doubly-linked list.
 */
struct _burst_bucket {
    burst_bucket* next;        /**< Pointer to the next bucket in the list, or NULL if this is the last. */
    burst_bucket* prev;        /**< Pointer to the previous bucket in the list, or NULL if this is the first. */
    int           count;       /**< Number of packets or events that fall within this bucket's time interval. */
    double        bucket_no;   /**< Sequential index identifying this bucket's position in the burst window. */
    double        start_time;  /**< Start time of this bucket's interval in seconds. */
};

/**
 * @brief Represents a node in a hierarchical statistics tree.
 *
 * Each node tracks statistical data such as counters, totals, min/max values,
 * and burst rates. Nodes may have children and siblings, forming a tree structure
 * used for organizing and displaying protocol or performance statistics.
 */
struct _stat_node {
	char* name;                     /**< Name of the statistic node. */
	int id;                         /**< Unique identifier for the node. */
	stat_node_datatype datatype;    /**< Type of data tracked (e.g., integer, float). */

	/** Counter value maintained by the node. */
	int counter;

	/** Total of all submitted values, used for computing averages. */
	union {
		int64_t int_total;          /**< Total for integer values. */
		double float_total;         /**< Total for floating-point values. */
	} total;

	/** Minimum value observed. */
	union {
		int int_min;                /**< Minimum integer value. */
		float float_min;            /**< Minimum float value. */
	} minvalue;

	/** Maximum value observed. */
	union {
		int int_max;                /**< Maximum integer value. */
		float float_max;            /**< Maximum float value. */
	} maxvalue;

	int st_flags;                   /**< Flags controlling node behavior or display. */

	/** Burst rate tracking fields. */
	int bcount;                     /**< Burst count. */
	burst_bucket *bh;               /**< Head of burst bucket list. */
	burst_bucket *bt;               /**< Tail of burst bucket list. */
	int max_burst;                  /**< Maximum burst count observed. */
	double burst_time;              /**< Time span of the burst. */

	GHashTable *hash;               /**< Child nodes indexed by name. */

	stats_tree *st;                 /**< Pointer to the owning statistics tree. */

	/** Tree relationships. */
	stat_node *parent;              /**< Pointer to parent node. */
	stat_node *children;            /**< Pointer to first child node. */
	stat_node *next;                /**< Pointer to next sibling node. */

	range_pair_t *rng;              /**< Optional range constraint for value filtering. */

	st_node_pres *pr;               /**< Presentation metadata for display formatting. */
};

/**
 * @brief Represents a live statistics tree instance, holding runtime state for accumulating and displaying tap statistics.
 */
struct _stats_tree {
    stats_tree_cfg* cfg;          /**< Pointer to the class configuration from which this tree instance was created. */

    char*           filter;       /**< Optional display filter string applied to limit which packets are counted. */

    /* times */
    double          start;        /**< Timestamp (in seconds) at which statistics collection began. */
    double          elapsed;      /**< Total elapsed time (in seconds) since collection started. */
    double          now;          /**< Timestamp (in seconds) of the most recently processed packet. */

    int             st_flags;     /**< Runtime flags controlling tree behavior (e.g. sorting options). */
    int             num_columns;  /**< Number of columns in the statistics tree display. */
    char*           display_name; /**< Human-readable name shown in the statistics tree window title. */

    GHashTable*     names;        /**< Hash table mapping parent node name strings to their stat_node pointers for fast lookup. */
    GPtrArray*      parents;      /**< Array of parent stat_node pointers for accelerated parent node resolution. */

    tree_pres*      pr;           /**< Opaque presentation handle defined by the GUI implementation for rendering the tree. */

    stat_node       root;         /**< The root node of the statistics tree from which all other nodes descend. */
};

/**
 * @brief Defines the static configuration and callbacks for a statistics tree type, shared across all instances of that tree.
 */
struct _stats_tree_cfg {
    char*                   abbr;               /**< Short abbreviated identifier used internally to register and look up the tree. */
    char*                   path;               /**< Menu path string determining where the tree appears in the Statistics menu. */
    char*                   title;              /**< Human-readable title displayed in the statistics window. */
    char*                   tapname;            /**< Name of the tap this statistics tree registers a listener on. */
    char*                   first_column_name;  /**< Label for the first (name) column in the statistics tree display. */
    register_stat_group_t   stat_group;         /**< Statistics menu group under which this tree is registered. */

    bool                    plugin;             /**< True if this statistics tree was registered by a plugin. */

    /** dissector defined callbacks */
    stat_tree_packet_cb     packet;             /**< Per-packet callback invoked by the tap for each matching packet. */
    stat_tree_init_cb       init;               /**< Callback invoked to initialize the tree before a capture or retap. */
    stat_tree_cleanup_cb    cleanup;            /**< Callback invoked to clean up tree resources after collection ends. */

    unsigned                flags;              /**< Tap listener flags controlling delivery behavior of the per-packet callback. */

    /*
     * node presentation callbacks
     */
    void (*setup_node_pr)(stat_node*);          /**< Callback invoked last during node creation to initialize node presentation state. */

    /*
     * tree presentation callbacks
     */
    tree_cfg_pres*          pr;                 /**< Opaque presentation configuration handle used by the GUI implementation. */

    tree_pres* (*new_tree_pr)(stats_tree*);     /**< Callback that allocates and returns a new presentation handle for a tree instance. */
    void (*free_tree_pr)(stats_tree*);          /**< Callback that releases the presentation handle of a tree instance. */

    unsigned                st_flags;           /**< Default stats tree flags (e.g. sorting behavior) applied to newly created tree instances. */
};

/* guess what, this is it! */
/**
 * @brief Registers callback functions for presenting statistics tree.
 *
 * @param registry_iterator Callback to iterate over the registry.
 * @param setup_node_pr Callback to set up a node in the statistics tree.
 * @param free_tree_pr Callback to free the statistics tree.
 * @param data User-defined data passed to callbacks.
 */
WS_DLL_PUBLIC void stats_tree_presentation(void (*registry_iterator)(void *,void *,void *),
				    void (*setup_node_pr)(stat_node*),
				    void (*free_tree_pr)(stats_tree*),
				    void *data);

/**
 * @brief Creates a new statistics tree.
 *
 * Initializes a new statistics tree with the given configuration and filter.
 *
 * @param cfg Pointer to the statistics tree configuration.
 * @param pr Pointer to the tree presentation structure.
 * @param filter The filter string for the statistics tree.
 * @return Pointer to the newly created statistics tree.
 */
WS_DLL_PUBLIC stats_tree *stats_tree_new(stats_tree_cfg *cfg, tree_pres *pr, const char *filter);

/**
 * @brief Process a packet for statistics tree.
 *
 * callback for taps
 *
 * @param p Pointer to the stats_tree structure.
 * @param pinfo Pointer to the packet_info structure.
 * @param edt Pointer to the epan_dissect_t structure.
 * @param pri Pointer to additional private data.
 * @param flags Flags indicating processing options.
 * @return tap_packet_status Status of packet processing.
 */
WS_DLL_PUBLIC tap_packet_status stats_tree_packet(void *p, packet_info *pinfo, epan_dissect_t *edt, const void *pri, tap_flags_t flags);

/**
 * @brief Resets a statistics tree.
 *
 * callback for reset
 *
 * @param p_st Pointer to the statistics tree structure to be reset.
 */
WS_DLL_PUBLIC void stats_tree_reset(void *p_st);

/**
 * @brief Reinitializes a statistics tree.
 *
 * callback for clear
 *
 * @param p_st Pointer to the statistics tree structure.
 */
WS_DLL_PUBLIC void stats_tree_reinit(void *p_st);

/* callback for destroy */
/**
 * @brief Frees a stats_tree structure.
 *
 * @param st Pointer to the stats_tree structure to be freed.
 */
WS_DLL_PUBLIC void stats_tree_free(stats_tree *st);

/**
 * @brief Retrieves an abbreviation from a given option argument.
 *
 * given an ws_optarg splits the abbr part
   and returns a newly allocated buffer containing it
 *
 * @param ws_optarg The option argument string to process.
 * @return A dynamically allocated string containing the abbreviation, or NULL if no comma is found.
 */
WS_DLL_PUBLIC char *stats_tree_get_abbr(const char *ws_optarg);

/**
 * @brief Retrieves configuration for a statistics tree by its abbreviation.
 *
 * obtains a stats tree from the registry given its abbr
 *
 * @param abbr The abbreviation of the statistics tree configuration to retrieve.
 * @return Pointer to the statistics tree configuration if found, NULL otherwise.
 */
WS_DLL_PUBLIC stats_tree_cfg *stats_tree_get_cfg_by_abbr(const char *abbr);

/**
 * @brief Retrieves a list of configuration items for statistics trees.
 *
 * obtains a stats tree list from the registry
 * caller should free returned list with  g_list_free()
 *
 * @return A GList containing pointers to stats_tree_cfg structures.
 */
WS_DLL_PUBLIC GList *stats_tree_get_cfg_list(void);

/**
 * @brief Calculate the maximum name length of a branch in the statistics tree.
 *
 * Used to calculate the size of the indentation and the longest string
 *
 * @param node The current node in the statistics tree.
 * @param indent The current indentation level.
 * @return The maximum name length of the branch.
 */
WS_DLL_PUBLIC unsigned stats_tree_branch_max_namelen(const stat_node *node, unsigned indent);

/**
 * @brief Convert a statistics tree node to a string.
 *
 * a text representation of a node,
 * if buffer is NULL returns a newly allocated string
 *
 * @param node The statistics tree node to convert.
 * @param buffer The buffer to store the resulting string, or NULL to allocate a new one.
 * @param len The length of the buffer if provided.
 * @return A pointer to the resulting string.
 */
WS_DLL_PUBLIC char *stats_tree_node_to_str(const stat_node *node,
					char *buffer, unsigned len);

/**
 * @brief Get the display name for a statistics tree node.
 *
 * Get the display name for the stats_tree (or node name) based on the
 * st_sort_showfullname preference. If not set remove everything before
 * last unescaped backslash. Caller must free the result *
 * @param fullname The full name of the statistics tree node.
 * @return A dynamically allocated string containing the display name.
 */
WS_DLL_PUBLIC char* stats_tree_get_displayname (const char* fullname);

/**
 * @brief Get the default sort column for a statistics tree.
 *
 * Returns the column number of the default column to sort on
 *
 * @param st Pointer to the statistics tree structure.
 * @return The index of the default sort column.
 */
WS_DLL_PUBLIC int stats_tree_get_default_sort_col (stats_tree *st);

/**
 * @brief Check if the default sort order for a stats tree is descending.
 *
 * Returns the default sort order to use
 *
 * @param st Pointer to the stats_tree structure.
 * @return true if the default sort order is descending, false otherwise.
 */
WS_DLL_PUBLIC bool stats_tree_is_default_sort_DESC (stats_tree *st);

/**
 * @brief Get the column name for a given index in the stats tree configuration.
 *
 * Returns the column name for a given column index
 *
 * @param st_config Pointer to the stats tree configuration structure.
 * @param col_index Index of the column for which to retrieve the name.
 * @return const char* The name of the column, or a default name if the index is invalid.
 */
WS_DLL_PUBLIC const char* stats_tree_get_column_name (stats_tree_cfg *st_config, int col_index);

/**
 * @brief Get the size of a column in the statistics tree.
 *
 * Returns the maximum number of characters in the value of a column
 *
 * @param col_index The index of the column to get the size for.
 * @return The size of the specified column, or 0 if the column is invalid.
 */
WS_DLL_PUBLIC int stats_tree_get_column_size (int col_index);

/**
 * @brief Retrieves values from a statistics tree node.
 *
 * returns the formatted column values for the current node
 * as array of char*. Caller must free entries and free array
 *
 * @param node Pointer to the stat_node structure containing the data.
 * @return Array of strings representing the values for different columns.
 */
WS_DLL_PUBLIC char** stats_tree_get_values_from_node (const stat_node* node);

/**
 * @brief Compare two stat_node elements for sorting.
 *
 * Compare two nodes for sort, based on sort_column
 *
 * @param a Pointer to the first stat_node element.
 * @param b Pointer to the second stat_node element.
 * @param sort_column The column index to sort by.
 * @param sort_descending Whether to sort in descending order.
 * @return An integer less than, equal to, or greater than zero if a is found,
 *         respectively, to be less than, to match, or be greater than b.
 */
WS_DLL_PUBLIC int stats_tree_sort_compare (const stat_node *a,
					const stat_node *b,
					int sort_column,
					bool sort_descending);

/**
 * @brief Compare two stat_node pointers for sorting purposes.
 *
 * Wrapper for stats_tree_sort_compare() function that can be called from array sort.
 * Compares two stat_node pointers based on the sort column and order specified in user_data.
 *
 * @param a Pointer to the first stat_node to compare.
 * @param b Pointer to the second stat_node to compare.
 * @param user_data Pointer to a sortinfo structure containing the sort column and order.
 * @return An integer less than, equal to, or greater than zero if the first argument is considered
 *         to be respectively less than, equal to, or greater than the second.
 */
WS_DLL_PUBLIC int stat_node_array_sortcmp (const void *a,
					const void *b,
					void *user_data);

/**
 * @brief Formats a stats tree as a string based on the specified format type.
 *
 * Copy stats_tree into GString. format determines output format
 *
 * @param st Pointer to the stats_tree structure.
 * @param format_type The desired output format (e.g., YAML, XML, CSV).
 * @param sort_column The column index to use for sorting.
 * @param sort_descending Whether to sort in descending order.
 * @return A GString containing the formatted stats tree or NULL on failure.
 */
WS_DLL_PUBLIC GString* stats_tree_format_as_str(const stats_tree* st,
					st_format_type format_type,
					int sort_column,
					bool sort_descending);

/**
 * @brief Formats a node in the statistics tree as a string.
 *
 * Helper function to add note to formatted stats_tree
 *
 * @param node The node to format.
 * @param s The GString where the formatted output will be appended.
 * @param format_type The type of format to use (e.g., YAML).
 * @param indent The number of spaces for indentation.
 * @param path The path to the node.
 * @param maxnamelen The maximum length of column names.
 * @param sort_column The column to sort by.
 * @param sort_descending Whether to sort in descending order.
 */
WS_DLL_PUBLIC void stats_tree_format_node_as_str(const stat_node *node,
					GString *s,
					st_format_type format_type,
					unsigned indent,
					const char *path,
					int maxnamelen,
					int sort_column,
					bool sort_descending);

#ifdef __cplusplus
}
#endif /* __cplusplus */
