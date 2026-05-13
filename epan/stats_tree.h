/** @file
 * A counter tree API for Wireshark dissectors
 * 2005, Luis E. G. Ontanon
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
#include <epan/tap.h>
#include <epan/stat_groups.h>
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define STAT_TREE_ROOT "root"
#define STATS_TREE_MENU_SEPARATOR "//"

/* stats_tree specific flags. When registering, these are used together
 * with the TL_ flags defined in tap.h, so make sure they don't overlap!
 * (Yes, that applies even to the flags that apply to nodes instead of
 * the entire tree, and should not be passed in stats_tree_register.
 * XXX - Why? These flags should be reworked at some point.)
 */

/* Flags on child nodes for internal use only */
#define ST_FLG_AVERAGE      0x10000000  /* Calculate averages for nodes, rather than totals */
#define ST_FLG_ROOTCHILD    0x20000000  /* This node is a direct child of the root node */

/* Flags set on child nodes via stat_node_set_flags */
#define ST_FLG_DEF_NOEXPAND 0x01000000  /* This node should not be expanded by default */
#define ST_FLG_SORT_TOP     0x00400000  /* When sorting always keep these lines on of list */

/* Flags for the entire stat_tree, set via stats_tree_register[_plugin] */
#define ST_FLG_SORT_DESC    0x00800000  /* When sorting, sort descending instead of ascending */
#define ST_FLG_SRTCOL_MASK  0x000F0000  /* Mask for sort column ID */
#define ST_FLG_SRTCOL_SHIFT 16          /* Number of bits to shift masked result */

#define ST_FLG_MASK         (ST_FLG_AVERAGE|ST_FLG_ROOTCHILD|ST_FLG_DEF_NOEXPAND| \
                             ST_FLG_SORT_TOP|ST_FLG_SORT_DESC|ST_FLG_SRTCOL_MASK)

#define ST_SORT_COL_NAME      1         /* Sort nodes by node names */
#define ST_SORT_COL_COUNT     2         /* Sort nodes by node count */
#define ST_SORT_COL_AVG       3         /* Sort nodes by node average */
#define ST_SORT_COL_MIN       4         /* Sort nodes by minimum node value */
#define ST_SORT_COL_MAX       5         /* Sort nodes by maximum node value */
#define ST_SORT_COL_BURSTRATE 6         /* Sort nodes by burst rate */

/* obscure information regarding the stats_tree */
typedef struct _stats_tree stats_tree;

/* tap packet callback for stats_tree */
typedef tap_packet_status (*stat_tree_packet_cb)(stats_tree*,
                                                 packet_info *,
                                                 epan_dissect_t *,
                                                 const void *,
                                                 tap_flags_t flags);

/* stats_tree initialization callback */
typedef void  (*stat_tree_init_cb)(stats_tree *);

/* stats_tree cleanup callback */
typedef void  (*stat_tree_cleanup_cb)(stats_tree *);

typedef enum _stat_node_datatype {
    STAT_DT_INT,
    STAT_DT_FLOAT
} stat_node_datatype;

typedef struct _stats_tree_cfg stats_tree_cfg;

/** Initialize the stats tree system.
 */
extern void stats_tree_init(void);

/**
 * Registers a new stats tree with default group REGISTER_STAT_GROUP_UNSORTED.
 * @param abbr tree abbr (used for tshark -z option)
 * @param path tree display name in GUI menu and window (use "//" for submenus)
 * @param flags tap listener flags for per-packet callback
 * @param packet per packet callback
 * @param init tree initialization callback
 * @param cleanup cleanup callback
 * @return A stats tree configuration pointer.
 */
WS_DLL_PUBLIC stats_tree_cfg *stats_tree_register(const char *tapname,
                                       const char *abbr,
                                       const char *path,
                                       unsigned flags,
                                       stat_tree_packet_cb packet,
                                       stat_tree_init_cb init,
                                       stat_tree_cleanup_cb cleanup);

/**
 * Registers a new stats tree with default group REGISTER_STAT_GROUP_UNSORTED from a plugin.
 * @param abbr tree abbr (used for tshark -z option)
 * @param path tree display name in GUI menu and window (use "//" for submenus)
 * @param flags tap listener flags for per-packet callback
 * @param packet per packet callback
 * @param init tree initialization callback
 * @param cleanup cleanup callback
 * @return A stats tree configuration pointer.
 */
WS_DLL_PUBLIC stats_tree_cfg *stats_tree_register_plugin(const char *tapname,
                                              const char *abbr,
                                              const char *path,
                                              unsigned flags,
                                              stat_tree_packet_cb packet,
                                              stat_tree_init_cb init,
                                              stat_tree_cleanup_cb cleanup);

/**
 * Set the menu statistics group for a stats tree.
 * @param stat_group A menu group.
 */
WS_DLL_PUBLIC void stats_tree_set_group(stats_tree_cfg *st_config, register_stat_group_t stat_group);

/**
 * Set the name a stats tree's first column.
 * Default is "Topic / Item".
 * @param column_name The new column name.
 */
WS_DLL_PUBLIC void stats_tree_set_first_column_name(stats_tree_cfg *st_config, const char *column_name);


/**
 * @brief Retrieves the parent ID of a node in the stats tree by its name.
 *
 * @param st The stats_tree to search within.
 * @param parent_name The name of the parent node. NULL for the root node.
 * @return int The ID of the parent node, or 0 if not found (root).
 */
WS_DLL_PUBLIC int stats_tree_parent_id_by_name(stats_tree *st, const char *parent_name);

/**
 * @brief Creates a node in the tree (to be used in the in init_cb)
 *
 * @param st Pointer to the statistics tree structure.
 * @param name Name of the new node.
 * @param parent_id ID of the parent node. (NULL for root)
 * @param datatype Data type of the node.
 * @param with_children true if this node will have "dynamically created" children.
 * @return ID of the created node, or 0 on failure.
 */
WS_DLL_PUBLIC int stats_tree_create_node(stats_tree *st,
                                         const char *name,
                                         int parent_id,
                                         stat_node_datatype datatype,
                                         bool with_children);

/**
 * @brief Creates a node in the statistics tree using its parent's tree name.
 *
 * @param st Pointer to the statistics tree.
 * @param name Name of the node.
 * @return int ID of the created node, or 0 if creation failed.
 */
WS_DLL_PUBLIC int stats_tree_create_node_by_pname(stats_tree *st,
                                                  const char *name,
                                                  const char *parent_name,
                                                  stat_node_datatype datatype,
                                                  bool with_children);

/**
 * @brief Creates a node in the stats tree that will contain a ranges list.
 *
 * creates a node in the tree, that will contain a ranges list.
 *  example:
 *  stats_tree_create_range_node(st,name,parent,
 *  "-99","100-199","200-299","300-399","400-", NULL);
 *
 * @param st Pointer to the stats tree.
 * @param name Name of the new node.
 * @param parent_id ID of the parent node.
 * @return int ID of the created range node.
 */
WS_DLL_PUBLIC int stats_tree_create_range_node(stats_tree *st,
                                               const char *name,
                                               int parent_id,
                                               ...);

 /**
  * @brief Creates a range node in the statistics tree with string ranges.
  *
  * @param st Pointer to the statistics tree.
  * @param name Name of the new range node.
  * @param parent_id ID of the parent node.
  * @param num_str_ranges Number of string ranges.
  * @param str_ranges Array of string ranges.
  * @return int ID of the created range node.
  */
WS_DLL_PUBLIC int stats_tree_create_range_node_string(stats_tree *st,
                                                      const char *name,
                                                      int parent_id,
                                                      int num_str_ranges,
                                                      char** str_ranges);

/**
 * @brief Increases by one the ranged node and the sub node to whose range the value belongs.
 *
 * @param st The statistics tree.
 * @param name The name of the range node.
 * @param parent_name The name of the parent node.
 * @return int The ID of the range node.
 */
WS_DLL_PUBLIC int stats_tree_range_node_with_pname(stats_tree *st,
                                                   const char *name,
                                                   const char *parent_name,
                                                   ...);

/* increases by one the ranged node and the sub node to whose range the value belongs */
/**
 * @brief Increment a statistic in a stats tree within a specified range.
 *
 * @param st Pointer to the stats tree.
 * @param name Name of the statistic node.
 * @param parent_id ID of the parent node.
 * @param value_in_range Value indicating if the statistic is within its range.
 * @return int The updated value of the statistic node.
 */
WS_DLL_PUBLIC int stats_tree_tick_range(stats_tree *st,
                                        const char *name,
                                        int parent_id,
                                        int value_in_range);

#define stats_tree_tick_range_by_pname(st,name,parent_name,value_in_range) \
    stats_tree_tick_range((st),(name),stats_tree_parent_id_by_name((st),(parent_name),(value_in_range)))

/**
 * @brief Creates a new pivot node in the statistics tree.
 *
 * @param st Pointer to the statistics tree.
 * @param name Name of the new pivot node.
 * @param parent_id ID of the parent node.
 * @return int ID of the newly created pivot node, or 0 if creation failed.
 */
WS_DLL_PUBLIC int stats_tree_create_pivot(stats_tree *st,
                                          const char *name,
                                          int parent_id);

/**
 * @brief Creates a pivot node in the statistics tree by name.
 *
 * @param st Pointer to the statistics tree.
 * @param name Name of the pivot node to create.
 * @param parent_name Name of the parent node for the pivot node.
 * @return int ID of the created pivot node, or 0 if creation fails.
 */
WS_DLL_PUBLIC int stats_tree_create_pivot_by_pname(stats_tree *st,
                                                   const char *name,
                                                   const char *parent_name);

/**
 * @brief Ticks a pivot node in the statistics tree.
 *
 * Increments the counter of the specified pivot node and updates related statistics.
 *
 * @param st Pointer to the stats_tree structure.
 * @param pivot_id ID of the pivot node to tick.
 * @param pivot_value Value associated with the pivot node.
 * @return The pivot_id on success, or an error code on failure.
 */
WS_DLL_PUBLIC int stats_tree_tick_pivot(stats_tree *st,
                                        int pivot_id,
                                        const char *pivot_value);

/**
 * @brief Cleans up the statistics tree registry.
 *
 * This function destroys the GHashTable that holds the registry of statistics tree nodes.
 */
extern void stats_tree_cleanup(void);


/*
 * manipulates the value of the node whose name is given
 * if the node does not exist yet it's created (with counter=1)
 * using parent_name as parent node (NULL for root).
 * with_children=true to indicate that the created node will be a parent
 */
typedef enum _manip_node_mode {
    MN_INCREASE,
    MN_SET,
    MN_AVERAGE,
    MN_AVERAGE_NOTICK,
    MN_SET_FLAGS,
    MN_CLEAR_FLAGS
} manip_node_mode;

/**
 * @brief Manipulates a node in a statistics tree by increasing its integer value.
 *
 * @param mode The manipulation mode (e.g., increase or set).
 * @param st The statistics tree to manipulate.
 * @param name The name of the node to manipulate.
 * @param parent_id The ID of the parent node.
 * @param with_children Indicates if children should be included.
 * @param value The integer value to add to the node's counter.
 * @return The result of the manipulation (0 on success, non-zero on failure).
 */
WS_DLL_PUBLIC int stats_tree_manip_node_int(manip_node_mode mode,
                                        stats_tree *st,
                                        const char *name,
                                        int parent_id,
                                        bool with_children,
                                        int value);

/**
 * @brief Manipulates a node in the statistics tree with a float value.
 *
 * @param mode The operation mode (e.g., increase, average).
 * @param st Pointer to the statistics tree.
 * @param name Name of the node.
 * @param parent_id ID of the parent node.
 * @param with_children Flag indicating if children should be included.
 * @param value Float value to manipulate the node with.
 * @return int Result of the operation.
*/
WS_DLL_PUBLIC int stats_tree_manip_node_float(manip_node_mode mode,
                                        stats_tree *st,
                                        const char *name,
                                        int parent_id,
                                        bool with_children,
                                        float value);

#define increase_stat_node(st,name,parent_id,with_children,value)       \
    (stats_tree_manip_node_int(MN_INCREASE,(st),(name),(parent_id),(with_children),(value)))

#define tick_stat_node(st,name,parent_id,with_children)                 \
    (stats_tree_manip_node_int(MN_INCREASE,(st),(name),(parent_id),(with_children),1))

#define set_stat_node(st,name,parent_id,with_children,value)            \
    (stats_tree_manip_node_int(MN_SET,(st),(name),(parent_id),(with_children),value))

#define zero_stat_node(st,name,parent_id,with_children)                 \
    (stats_tree_manip_node_int(MN_SET,(st),(name),(parent_id),(with_children),0))

/*
 * Add value to average calculation WITHOUT ticking node. Node MUST be ticked separately!
 *
 * Intention is to allow code to separately tick node (backward compatibility for plugin)
 * and set value to use for averages. Older versions without average support will then at
 * least show a count instead of 0.
 */
#define avg_stat_node_add_value_notick(st,name,parent_id,with_children,value) \
    (stats_tree_manip_node_int(MN_AVERAGE_NOTICK,(st),(name),(parent_id),(with_children),value))

/* Tick node and add a new value to the average calculation for this stats node. */
#define avg_stat_node_add_value_int(st,name,parent_id,with_children,value)  \
    (stats_tree_manip_node_int(MN_AVERAGE,(st),(name),(parent_id),(with_children),value))

#define avg_stat_node_add_value_float(st,name,parent_id,with_children,value)  \
    (stats_tree_manip_node_float(MN_AVERAGE,(st),(name),(parent_id),(with_children),value))

/* Set flags for this node. Node created if it does not yet exist. */
#define stat_node_set_flags(st,name,parent_id,with_children,flags)      \
    (stats_tree_manip_node_int(MN_SET_FLAGS,(st),(name),(parent_id),(with_children),flags))

/* Clear flags for this node. Node created if it does not yet exist. */
#define stat_node_clear_flags(st,name,parent_id,with_children,flags)    \
    (stats_tree_manip_node_int(MN_CLEAR_FLAGS,(st),(name),(parent_id),(with_children),flags))

#ifdef __cplusplus
}
#endif /* __cplusplus */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
