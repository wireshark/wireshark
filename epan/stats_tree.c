/* stats_tree.c
 * API for a counter tree for Wireshark
 * 2004, Luis E. G. Ontanon
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

 /* stats_tree modifications by Deon van der Westhuysen, November 2013
  * support for
  *  - sorting by column,
  *  - calculation of average values
  *  - calculation of burst rate
  *  - export to text, CSV or XML file
  */

#include "config.h"

#include <glib.h>

#include <stdlib.h>

#include <epan/stats_tree_priv.h>
#include <epan/prefs.h>
#include <math.h>
#include <string.h>

#include "strutil.h"
#include "stats_tree.h"

enum _stat_tree_columns {
    COL_NAME,
    COL_COUNT,
    COL_AVERAGE,
    COL_MIN,
    COL_MAX,
    COL_RATE,
    COL_PERCENT,
    COL_BURSTRATE,
    COL_BURSTTIME,
    N_COLUMNS
};

/* used to contain the registered stat trees */
static GHashTable *registry = NULL;

/* a text representation of a node
if buffer is NULL returns a newly allocated string */
extern gchar*
stats_tree_node_to_str(const stat_node *node, gchar *buffer, guint len)
{
    if (buffer) {
        g_snprintf(buffer,len,"%s: %i",node->name, node->counter);
        return buffer;
    } else {
        return g_strdup_printf("%s: %i",node->name, node->counter);
    }
}

extern guint
stats_tree_branch_max_namelen(const stat_node *node, guint indent)
{
    stat_node *child;
    guint maxlen = 0;
    guint len;

    indent = indent > INDENT_MAX ? INDENT_MAX : indent;

    if (node->children) {
        for (child = node->children; child; child = child->next ) {
            len = stats_tree_branch_max_namelen(child,indent+1);
            maxlen = len > maxlen ? len : maxlen;
        }
    }

    if (node->st_flags&ST_FLG_ROOTCHILD) {
        gchar *display_name= stats_tree_get_displayname(node->name);
        len = (guint) strlen(display_name) + indent;
        g_free(display_name);
    }
    else {
    len = (guint) strlen(node->name) + indent;
    }
    maxlen = len > maxlen ? len : maxlen;

    return maxlen;
}

/* frees the resources allocated by a stat_tree node */
static void
free_stat_node(stat_node *node)
{
    stat_node *child;
    stat_node *next;
    burst_bucket *bucket;

    if (node->children) {
    for (child = node->children; child; child = next ) {
        /* child->next will be gone after free_stat_node, so cache it here */
        next = child->next;
        free_stat_node(child);
    }
    }

    if (node->hash) g_hash_table_destroy(node->hash);

    while (node->bh) {
        bucket = node->bh;
        node->bh = bucket->next;
        g_free(bucket);
    }

    g_free(node->rng);
    g_free(node->name);
    g_free(node);
}

/* destroys the whole tree instance */
extern void
stats_tree_free(stats_tree *st)
{
    stat_node *child;
    stat_node *next;

    if (!st) return;

    g_free(st->filter);
    g_hash_table_destroy(st->names);
    g_ptr_array_free(st->parents,TRUE);
    g_free(st->display_name);

    for (child = st->root.children; child; child = next ) {
        /* child->next will be gone after free_stat_node, so cache it here */
        next = child->next;
        free_stat_node(child);
    }

    if (st->cfg->free_tree_pr)
        st->cfg->free_tree_pr(st);

    if (st->cfg->cleanup)
        st->cfg->cleanup(st);

    g_free(st);
}


/* reset a node to its original state */
static void
reset_stat_node(stat_node *node)
{
    stat_node *child;
    burst_bucket *bucket;

    node->counter = 0;
    node->total = 0;
    node->minvalue = G_MAXINT;
    node->maxvalue = G_MININT;
    node->st_flags = 0;

    while (node->bh) {
        bucket = node->bh;
        node->bh = bucket->next;
        g_free(bucket);
    }
    node->bh = (burst_bucket*)g_malloc0(sizeof(burst_bucket));
    node->bt = node->bh;
    node->bcount = 0;
    node->max_burst = 0;
    node->burst_time = -1.0;

    if (node->children) {
        for (child = node->children; child; child = child->next )
            reset_stat_node(child);
    }
}

/* reset the whole stats_tree */
extern void
stats_tree_reset(void *p)
{
    stats_tree *st = (stats_tree *)p;

    st->start = -1.0;
    st->elapsed = 0.0;
    st->now = - 1.0;

    reset_stat_node(&st->root);
}

extern void
stats_tree_reinit(void *p)
{
    stats_tree *st = (stats_tree *)p;
    stat_node *child;
    stat_node *next;

    for (child = st->root.children; child; child = next) {
        /* child->next will be gone after free_stat_node, so cache it here */
        next = child->next;
        free_stat_node(child);
    }

    st->root.children = NULL;
    st->root.counter = 0;
    st->root.total = 0;
    st->root.minvalue = G_MAXINT;
    st->root.maxvalue = G_MININT;
    st->root.st_flags = 0;

    st->root.bh = (burst_bucket*)g_malloc0(sizeof(burst_bucket));
    st->root.bt = st->root.bh;
    st->root.bcount = 0;
    st->root.max_burst = 0;
    st->root.burst_time = -1.0;

    /* No more stat_nodes left in tree - clean out hash, array */
    g_hash_table_remove_all(st->names);
    if (st->parents->len>1) {
        g_ptr_array_remove_range(st->parents, 1, st->parents->len-1);
    }

    /* Do not update st_flags for the tree (sorting) - leave as was */
    st->num_columns = N_COLUMNS;
    g_free(st->display_name);
    st->display_name= stats_tree_get_displayname(st->cfg->name);

    if (st->cfg->init) {
        st->cfg->init(st);
    }
}

/* register a new stats_tree */
extern void
stats_tree_register_with_group(const char *tapname, const char *abbr, const char *name,
            guint flags,
            stat_tree_packet_cb packet, stat_tree_init_cb init,
            stat_tree_cleanup_cb cleanup, register_stat_group_t stat_group)
{
    stats_tree_cfg *cfg = (stats_tree_cfg *)g_malloc0( sizeof(stats_tree_cfg) );

    /* at the very least the abbrev and the packet function should be given */
    g_assert( tapname && abbr && packet );

    cfg->tapname = g_strdup(tapname);
    cfg->abbr = g_strdup(abbr);
    cfg->name = name ? g_strdup(name) : g_strdup(abbr);
    cfg->stat_group = stat_group;

    cfg->packet = packet;
    cfg->init = init;
    cfg->cleanup = cleanup;

    cfg->flags = flags&~ST_FLG_MASK;
    cfg->st_flags = flags&ST_FLG_MASK;

    if (!registry) registry = g_hash_table_new(g_str_hash,g_str_equal);

    g_hash_table_insert(registry,cfg->abbr,cfg);
}

/* register a new stats_tree with default group REGISTER_STAT_GROUP_UNSORTED */
extern void
stats_tree_register(const char *tapname, const char *abbr, const char *name,
            guint flags,
            stat_tree_packet_cb packet, stat_tree_init_cb init,
            stat_tree_cleanup_cb cleanup)
{
    stats_tree_register_with_group(tapname, abbr, name,
            flags,
            packet, init,
            cleanup, REGISTER_STAT_GROUP_UNSORTED);
}

/* register a new stat_tree with default group REGISTER_STAT_GROUP_UNSORTED from a plugin */
extern void
stats_tree_register_plugin(const char *tapname, const char *abbr, const char *name,
            guint flags,
            stat_tree_packet_cb packet, stat_tree_init_cb init,
            stat_tree_cleanup_cb cleanup)
{
    stats_tree_cfg *cfg;

    stats_tree_register(tapname, abbr, name,
            flags,
            packet, init,
            cleanup);
    cfg = stats_tree_get_cfg_by_abbr(abbr);
    cfg->plugin = TRUE;
}

extern stats_tree*
stats_tree_new(stats_tree_cfg *cfg, tree_pres *pr, const char *filter)
{
    stats_tree *st = (stats_tree *)g_malloc0(sizeof(stats_tree));

    st->cfg = cfg;
    st->pr = pr;

    st->names = g_hash_table_new(g_str_hash,g_str_equal);
    st->parents = g_ptr_array_new();
    st->filter = g_strdup(filter);

    st->start = -1.0;
    st->elapsed = 0.0;

    st->root.minvalue = G_MAXINT;
    st->root.maxvalue = G_MININT;

    st->root.bh = (burst_bucket*)g_malloc0(sizeof(burst_bucket));
    st->root.bt = st->root.bh;
    st->root.burst_time = -1.0;

    st->root.name = stats_tree_get_displayname(cfg->name);
    st->root.st = st;

    st->st_flags = st->cfg->st_flags;

    if (!(st->st_flags&ST_FLG_SRTCOL_MASK)) {
        /* No default sort specified - use preferences */
        st->st_flags |= prefs.st_sort_defcolflag<<ST_FLG_SRTCOL_SHIFT;
        if (prefs.st_sort_defdescending) {
            st->st_flags |= ST_FLG_SORT_DESC;
        }
    }
    st->num_columns = N_COLUMNS;
    st->display_name= stats_tree_get_displayname(st->cfg->name);

    g_ptr_array_add(st->parents,&st->root);

    return st;
}

/* will be the tap packet cb */
extern int
stats_tree_packet(void *p, packet_info *pinfo, epan_dissect_t *edt, const void *pri)
{
    stats_tree *st = (stats_tree *)p;

    st->now = nstime_to_msec(&pinfo->rel_ts);
    if (st->start < 0.0) st->start = st->now;

    st->elapsed = st->now - st->start;

    if (st->cfg->packet)
        return st->cfg->packet(st,pinfo,edt,pri);
    else
        return 0;
}

extern stats_tree_cfg*
stats_tree_get_cfg_by_abbr(const char *abbr)
{
    if (!abbr) return NULL;
    return (stats_tree_cfg *)g_hash_table_lookup(registry,abbr);
}

static gint
compare_stat_menu_item(gconstpointer stat_a, gconstpointer stat_b)
{
    const stats_tree_cfg* stat_cfg_a = (const stats_tree_cfg*)stat_a;
    const stats_tree_cfg* stat_cfg_b = (const stats_tree_cfg*)stat_b;

    return strcmp(stat_cfg_a->name, stat_cfg_b->name);
}

extern GList*
stats_tree_get_cfg_list(void)
{
    GList* registry_list = g_hash_table_get_values(registry);
    /* Now sort the list so they can show up in the
       menu alphabetically */
    return g_list_sort(registry_list, compare_stat_menu_item);

}

struct _stats_tree_pres_cbs {
    void (*setup_node_pr)(stat_node*);
    void (*free_tree_pr)(stats_tree*);
};

static void
setup_tree_presentation(gpointer k _U_, gpointer v, gpointer p)
{
    stats_tree_cfg *cfg = (stats_tree_cfg *)v;
    struct _stats_tree_pres_cbs *d = (struct _stats_tree_pres_cbs *)p;

    cfg->in_use = FALSE;
    cfg->setup_node_pr = d->setup_node_pr;
    cfg->free_tree_pr = d->free_tree_pr;

}

extern void
stats_tree_presentation(void (*registry_iterator)(gpointer,gpointer,gpointer),
            void (*setup_node_pr)(stat_node*),
            void (*free_tree_pr)(stats_tree*),
            void *data)
{
    static struct _stats_tree_pres_cbs d;

    d.setup_node_pr = setup_node_pr;
    d.free_tree_pr = free_tree_pr;

    if (registry) g_hash_table_foreach(registry,setup_tree_presentation,&d);

    if (registry_iterator && registry)
        g_hash_table_foreach(registry,registry_iterator,data);

}


/* creates a stat_tree node
*    name: the name of the stats_tree node
*    parent_name: the name of the ALREADY REGISTERED parent
*    with_hash: whether or not it should keep a hash with its children names
*    as_named_node: whether or not it has to be registered in the root namespace
*/
static stat_node*
new_stat_node(stats_tree *st, const gchar *name, int parent_id,
          gboolean with_hash, gboolean as_parent_node)
{

    stat_node *node = (stat_node *)g_malloc0(sizeof(stat_node));
    stat_node *last_chld = NULL;

    node->minvalue = G_MAXINT;
    node->maxvalue = G_MININT;
    node->st_flags = parent_id?0:ST_FLG_ROOTCHILD;

    node->bh = (burst_bucket*)g_malloc0(sizeof(burst_bucket));
    node->bt = node->bh;
    node->burst_time = -1.0;

    node->name = g_strdup(name);
    node->st = (stats_tree*) st;
    node->hash = with_hash ? g_hash_table_new(g_str_hash,g_str_equal) : NULL;

    if (as_parent_node) {
        g_hash_table_insert(st->names,
                            node->name,
                            node);

        g_ptr_array_add(st->parents,node);

        node->id = st->parents->len - 1;
    } else {
        node->id = -1;
    }

    if (parent_id >= 0 && parent_id < (int) st->parents->len ) {
        node->parent = (stat_node *)g_ptr_array_index(st->parents,parent_id);
    } else {
        /* ??? should we set the parent to be root ??? */
        g_assert_not_reached();
    }

    if (node->parent->children) {
        /* insert as last child */

        for (last_chld = node->parent->children;
             last_chld->next;
             last_chld = last_chld->next ) ;

        last_chld->next = node;

    } else {
        /* insert as first child */
        node->parent->children = node;
    }

    if(node->parent->hash) {
        g_hash_table_insert(node->parent->hash,node->name,node);
    }

    if (st->cfg->setup_node_pr) {
        st->cfg->setup_node_pr(node);
    } else {
        node->pr = NULL;
    }

    return node;
}
/***/

extern int
stats_tree_create_node(stats_tree *st, const gchar *name, int parent_id, gboolean with_hash)
{
    stat_node *node = new_stat_node(st,name,parent_id,with_hash,TRUE);

    if (node)
        return node->id;
    else
        return 0;
}

/* XXX: should this be a macro? */
extern int
stats_tree_create_node_by_pname(stats_tree *st, const gchar *name,
                const gchar *parent_name, gboolean with_children)
{
    return stats_tree_create_node(st,name,stats_tree_parent_id_by_name(st,parent_name),with_children);
}

/* Internal function to update the burst calculation data - add entry to bucket */
static void
update_burst_calc(stat_node *node, gint value)
{
    double current_bucket;
    double burstwin;

    burst_bucket *bn;

    if (!prefs.st_enable_burstinfo) {
        return;
    }

    /* NB thebucket list should always contain at least one node - even if it is */
    /* the dummy created at init time. Head and tail should never be NULL!       */
    current_bucket= floor(node->st->now/prefs.st_burst_resolution);
    burstwin= prefs.st_burst_windowlen/prefs.st_burst_resolution;
    if (current_bucket>node->bt->bucket_no) {
        /* Must add a new bucket at the burst list tail */
        bn = (burst_bucket*)g_malloc0(sizeof(burst_bucket));
        bn->count = value;
        bn->bucket_no = current_bucket;
        bn->start_time = node->st->now;
        bn->prev = node->bt;
        node->bt->next = bn;
        node->bt = bn;
        /* And add value to the current burst count for node */
        node->bcount += value;
        /* Check if bucket list head is now too old and must be removed */
        while (current_bucket>=(node->bh->bucket_no+burstwin)) {
            /* off with its head! */
            bn = node->bh;
            node->bh = bn->next;
            node->bh->prev = NULL;
            node->bcount -= bn->count;
            g_free(bn);
        }
    }
    else if (current_bucket<node->bh->bucket_no) {
        /* Packet must be added at head of burst list - check if not too old */
        if ((current_bucket+burstwin)>node->bt->bucket_no) {
            /* packet still within the window */
            bn = (burst_bucket*)g_malloc0(sizeof(burst_bucket));
            bn->count = value;
            bn->bucket_no = current_bucket;
            bn->start_time = node->st->now;
            bn->next = node->bh;
            node->bh->prev = bn;
            node->bh = bn;
            /* And add value to the current burst count for node */
            node->bcount += value;
        }
    }
    else
    {
        /* Somewhere in the middle... */
        burst_bucket *search = node->bt;
        while (current_bucket<search->bucket_no) {
            search = search->prev;
        }
        if (current_bucket==search->bucket_no) {
            /* found existing bucket, increase value */
            search->count += value;
            if (search->start_time>node->st->now) {
                search->start_time = node->st->now;
            }
        }
        else {
            /* must add a new bucket after bn. */
            bn = (burst_bucket*)g_malloc0(sizeof(burst_bucket));
            bn->count = value;
            bn->bucket_no = current_bucket;
            bn->start_time = node->st->now;
            bn->prev = search;
            bn->next = search->next;
            search->next = bn;
            bn->next->prev = bn;
        }
        node->bcount += value;
    }
    if (node->bcount>node->max_burst) {
        /* new record burst */
        node->max_burst = node->bcount;
        node->burst_time = node->bh->start_time;
    }
}

/*
 * Increases by delta the counter of the node whose name is given
 * if the node does not exist yet it's created (with counter=1)
 * using parent_name as parent node.
 * with_hash=TRUE to indicate that the created node will have a parent
 */
extern int
stats_tree_manip_node(manip_node_mode mode, stats_tree *st, const char *name,
              int parent_id, gboolean with_hash, gint value)
{
    stat_node *node = NULL;
    stat_node *parent = NULL;

    g_assert( parent_id >= 0 && parent_id < (int) st->parents->len );

    parent = (stat_node *)g_ptr_array_index(st->parents,parent_id);

    if( parent->hash ) {
        node = (stat_node *)g_hash_table_lookup(parent->hash,name);
    } else {
        node = (stat_node *)g_hash_table_lookup(st->names,name);
    }

    if ( node == NULL )
        node = new_stat_node(st,name,parent_id,with_hash,with_hash);

    switch (mode) {
        case MN_INCREASE:
            node->counter += value;
            update_burst_calc(node, value);
            break;
        case MN_SET: node->counter = value; break;
        case MN_AVERAGE:
            node->counter++;
            update_burst_calc(node, 1);
            /* fall through to average code */
        case MN_AVERAGE_NOTICK:
            node->total += value;
            if (node->minvalue > value) {
                node->minvalue = value;
            }
            if (node->maxvalue < value) {
                node->maxvalue = value;
            }
            node->st_flags |= ST_FLG_AVERAGE;
            break;
        case MN_SET_FLAGS:
            node->st_flags |= value;
            break;
        case MN_CLEAR_FLAGS:
            node->st_flags &= ~value;
            break;
    }

    if (node)
        return node->id;
    else
        return -1;
}


extern char*
stats_tree_get_abbr(const char *opt_arg)
{
    guint i;

    /* XXX: this fails when tshark is given any options
       after the -z */
    g_assert(opt_arg != NULL);

    for (i=0; opt_arg[i] && opt_arg[i] != ','; i++);

    if (opt_arg[i] == ',') {
        return g_strndup(opt_arg,i);
    } else {
        return NULL;
    }
}


/*
 * This function accepts an input string which should define a long integer range.
 * The normal result is a struct containing the floor and ceil value of this
 * range.
 *
 * It is allowed to define a range string in the following ways :
 *
 * "0-10" -> { 0, 10 }
 * "-0" -> { G_MININT, 0 }
 * "0-" -> { 0, G_MAXINT }
 * "-" -> { G_MININT, G_MAXINT }
 *
 * Note that this function is robust to buggy input string. If in some cases it
 * returns NULL, it but may also return a pair with undefined values.
 *
 */
static range_pair_t*
get_range(char *rngstr)
{
    gchar **split;
    range_pair_t *rng;

    split = g_strsplit((gchar*)rngstr,"-",2);

    /* empty string */
    if (split[0] == NULL) {
        g_strfreev(split);
        return NULL;
    }

    rng = (range_pair_t *)g_malloc(sizeof(range_pair_t));

    if (split[1] == NULL) {
        /* means we have a non empty string with no delimiter
         * so it must be a single number */
        rng->floor = (gint)strtol(split[0],NULL,10);
        rng->ceil = rng->floor;
    } else {
      /* string == "X-?" */
        if (*(split[0]) != '\0') {
            rng->floor = (gint)strtol(split[0],NULL,10);
        } else {
            /* string == "-?" */
            rng->floor = G_MININT;
        }

        /* string != "?-" */
        if (*(split[1]) != '\0') {
            rng->ceil  = (gint)strtol(split[1],NULL,10);
        } else {
            /* string == "?-" */
            rng->ceil = G_MAXINT;
        }
    }
    g_strfreev(split);

    return rng;
}


extern int
stats_tree_create_range_node(stats_tree *st, const gchar *name, int parent_id, ...)
{
    va_list list;
    gchar *curr_range;
    stat_node *rng_root = new_stat_node(st, name, parent_id, FALSE, TRUE);
    stat_node *range_node = NULL;

    va_start( list, parent_id );
    while (( curr_range = va_arg(list, gchar*) )) {
        range_node = new_stat_node(st, curr_range, rng_root->id, FALSE, FALSE);
        range_node->rng = get_range(curr_range);
    }
    va_end( list );

    return rng_root->id;
}

extern int
stats_tree_create_range_node_string(stats_tree *st, const gchar *name,
                    int parent_id, int num_str_ranges,
                    gchar** str_ranges)
{
    int i;
    stat_node *rng_root = new_stat_node(st, name, parent_id, FALSE, TRUE);
    stat_node *range_node = NULL;

    for (i = 0; i < num_str_ranges; i++) {
        range_node = new_stat_node(st, str_ranges[i], rng_root->id, FALSE, FALSE);
        range_node->rng = get_range(str_ranges[i]);
    }

    return rng_root->id;
}

/****/
extern int
stats_tree_parent_id_by_name(stats_tree *st, const gchar *parent_name)
{
    stat_node *node = (stat_node *)g_hash_table_lookup(st->names,parent_name);

    if (node)
        return node->id;
    else
        return 0; /* XXX: this is the root shoud we return -1 instead?*/
}


extern int
stats_tree_range_node_with_pname(stats_tree *st, const gchar *name,
                 const gchar *parent_name, ...)
{
    va_list list;
    gchar *curr_range;
    stat_node *range_node = NULL;
    int parent_id = stats_tree_parent_id_by_name(st,parent_name);
    stat_node *rng_root = new_stat_node(st, name, parent_id, FALSE, TRUE);

    va_start( list, parent_name );
    while (( curr_range = va_arg(list, gchar*) )) {
        range_node = new_stat_node(st, curr_range, rng_root->id, FALSE, FALSE);
        range_node->rng = get_range(curr_range);
    }
    va_end( list );

    return rng_root->id;
}


extern int
stats_tree_tick_range(stats_tree *st, const gchar *name, int parent_id,
              int value_in_range)
{

    stat_node *node = NULL;
    stat_node *parent = NULL;
    stat_node *child = NULL;
    gint stat_floor, stat_ceil;

    if (parent_id >= 0 && parent_id < (int) st->parents->len) {
        parent = (stat_node *)g_ptr_array_index(st->parents,parent_id);
    } else {
        g_assert_not_reached();
    }

    if( parent->hash ) {
        node = (stat_node *)g_hash_table_lookup(parent->hash,name);
    } else {
        node = (stat_node *)g_hash_table_lookup(st->names,name);
    }

    if ( node == NULL )
        g_assert_not_reached();

    /* update stats for container node. counter should already be ticked so we only update total and min/max */
    node->total += value_in_range;
    if (node->minvalue > value_in_range) {
        node->minvalue = value_in_range;
    }
    if (node->maxvalue < value_in_range) {
        node->maxvalue = value_in_range;
    }
    node->st_flags |= ST_FLG_AVERAGE;

    for ( child = node->children; child; child = child->next) {
        stat_floor =  child->rng->floor;
        stat_ceil = child->rng->ceil;

        if ( value_in_range >= stat_floor && value_in_range <= stat_ceil ) {
            child->counter++;
            child->total += value_in_range;
            if (child->minvalue > value_in_range) {
                child->minvalue = value_in_range;
            }
            if (child->maxvalue < value_in_range) {
                child->maxvalue = value_in_range;
            }
            child->st_flags |= ST_FLG_AVERAGE;
            update_burst_calc(child, 1);
            return node->id;
        }
    }

    return node->id;
}

extern int
stats_tree_create_pivot(stats_tree *st, const gchar *name, int parent_id)
{
    stat_node *node = new_stat_node(st,name,parent_id,TRUE,TRUE);

    if (node)
        return node->id;
    else
        return 0;
}

extern int
stats_tree_create_pivot_by_pname(stats_tree *st, const gchar *name,
                 const gchar *parent_name)
{
    int parent_id = stats_tree_parent_id_by_name(st,parent_name);
    stat_node *node;

    node = new_stat_node(st,name,parent_id,TRUE,TRUE);

    if (node)
        return node->id;
    else
        return 0;
}

extern int
stats_tree_tick_pivot(stats_tree *st, int pivot_id, const gchar *pivot_value)
{
    stat_node *parent = (stat_node *)g_ptr_array_index(st->parents,pivot_id);

    parent->counter++;
    update_burst_calc(parent, 1);
    stats_tree_manip_node( MN_INCREASE, st, pivot_value, pivot_id, FALSE, 1);

    return pivot_id;
}

extern gchar*
stats_tree_get_displayname (gchar* fullname)
{
    gchar *buf = g_strdup(fullname);
    gchar *sep;

    if (prefs.st_sort_showfullname) {
        return buf; /* unmodifed */
    }

    sep = buf;
    while ((sep = strchr(sep,'/')) != NULL) {
        if (*(++sep)=='/') {  /* escapeded slash - two slash characters after each other */
            memmove(sep,sep+1,strlen(sep));
        }
        else {
            /* we got a new path separator */
            memmove(buf,sep,strlen(sep)+1);
            sep = buf;
        }
    }

    return buf;
}

extern gint
stats_tree_get_default_sort_col (stats_tree *st)
{
    switch ((st->st_flags&ST_FLG_SRTCOL_MASK)>>ST_FLG_SRTCOL_SHIFT) {
        case ST_SORT_COL_NAME:
            return COL_NAME;
        case ST_SORT_COL_COUNT:
            return COL_COUNT;
        case ST_SORT_COL_AVG:
            return COL_AVERAGE;
        case ST_SORT_COL_MIN:
            return COL_MIN;
        case ST_SORT_COL_MAX:
            return COL_MAX;
        case ST_SORT_COL_BURSTRATE:
            return COL_BURSTRATE;
    }
    return COL_COUNT;   /* nothing specific set */
}

extern gboolean
stats_tree_is_default_sort_DESC (stats_tree *st)
{
    return st->st_flags&ST_FLG_SORT_DESC;
}

extern const gchar*
stats_tree_get_column_name (gint col_index)
{
    switch (col_index) {
        case COL_NAME:
            return "Topic / Item";
        case COL_COUNT:
            return "Count";
        case COL_AVERAGE:
            return "Average";
        case COL_MIN:
            return "Min val";
        case COL_MAX:
            return "Max val";
        case COL_RATE:
            return "Rate (ms)";
        case COL_PERCENT:
            return "Percent";
        case COL_BURSTRATE:
            return prefs.st_burst_showcount?"Burst count":"Burst rate";
        case COL_BURSTTIME:
            return "Burst start";
        default:
            return "(Unknown)";
    }
}

extern gint
stats_tree_get_column_size (gint col_index)
{
    if (col_index==COL_NAME) {
        return 36;      /* but caller should really call stats_tree_branch_max_namelen() */
    }
    if (col_index<N_COLUMNS) {
        return 12;      /* all numerical values are this size */
    }
    return 0;           /* invalid column */
}

extern gchar**
stats_tree_get_values_from_node (const stat_node* node)
{
    gchar **values = (gchar**) g_malloc0(sizeof(gchar*)*(node->st->num_columns));

    values[COL_NAME]= (node->st_flags&ST_FLG_ROOTCHILD)?stats_tree_get_displayname(node->name):g_strdup(node->name);
    values[COL_COUNT]= g_strdup_printf("%u",node->counter);
    values[COL_AVERAGE]= ((node->st_flags&ST_FLG_AVERAGE)||node->rng)?
                (node->counter?g_strdup_printf("%.2f",((float)node->total)/node->counter):g_strdup("-")):
                g_strdup("");
    values[COL_MIN]= ((node->st_flags&ST_FLG_AVERAGE)||node->rng)?
                (node->counter?g_strdup_printf("%u",node->minvalue):g_strdup("-")):
                g_strdup("");
    values[COL_MAX]= ((node->st_flags&ST_FLG_AVERAGE)||node->rng)?
                (node->counter?g_strdup_printf("%u",node->maxvalue):g_strdup("-")):
                g_strdup("");
    values[COL_RATE]= (node->st->elapsed)?g_strdup_printf("%.4f",((float)node->counter)/node->st->elapsed):g_strdup("");
    values[COL_PERCENT]= ((node->parent)&&(node->parent->counter))?
                g_strdup_printf("%.2f%%",(node->counter*100.0)/node->parent->counter):
                (node->parent==&(node->st->root)?g_strdup("100%"):g_strdup(""));
    if (node->st->num_columns>COL_BURSTTIME) {
        values[COL_BURSTRATE]= (!prefs.st_enable_burstinfo)?g_strdup(""):
                (node->max_burst?(prefs.st_burst_showcount?
                                g_strdup_printf("%d",node->max_burst):
                                g_strdup_printf("%.4f",((double)node->max_burst)/prefs.st_burst_windowlen)):
                g_strdup("-"));
        values[COL_BURSTTIME]= (!prefs.st_enable_burstinfo)?g_strdup(""):
                (node->max_burst?g_strdup_printf("%.3f",((double)node->burst_time/1000.0)):g_strdup("-"));
    }
    return values;
}

extern gint
stats_tree_sort_compare (const stat_node *a, const stat_node *b, gint sort_column,
                    gboolean sort_descending)
{
    int result = 0;
    float avg_a, avg_b;

    if  (prefs.st_sort_rng_nameonly&&(a->rng&&b->rng)) {
        /* always sort ranges by range name */
        result = a->rng->floor - b->rng->floor;
        if (sort_descending&&(!prefs.st_sort_rng_fixorder)) {
            result= -result;
        }
        return result;
    }

    switch (sort_column) {
        case COL_NAME:
            if  (a->rng&&b->rng) {
                result = a->rng->floor - b->rng->floor;
            }
            else if (prefs.st_sort_casesensitve) {
                result = strcmp(a->name,b->name);
            }
            else {
                result = g_ascii_strcasecmp(a->name,b->name);
            }
            break;

        case COL_RATE:
        case COL_PERCENT:
        case COL_COUNT:
            result = a->counter - b->counter;
            break;

        case COL_AVERAGE:
            if (a->counter) {
                result= 1;      /* assume a>b */
                if (b->counter) {
                    avg_a= ((float)a->total)/a->counter;
                    avg_b= ((float)b->total)/b->counter;
                    result= (avg_a>avg_b)?1:((avg_a<avg_b)?-1:0);
                }
            }
            else {
                result= -1;     /* let b>a */
            }
            break;

        case COL_MIN:
            result = a->minvalue - b->minvalue;
            break;

        case COL_MAX:
            result = a->maxvalue - b->maxvalue;
            break;

        case COL_BURSTRATE:
            result = a->max_burst - b->max_burst;
            break;

        case COL_BURSTTIME:
            result = (a->burst_time>b->burst_time)?1:((a->burst_time<b->burst_time)?-1:0);
            break;

        default:
            /* no sort comparison found for column - must update this switch statement */
            g_assert_not_reached();
    }

    /* break tie between items with same primary search result */
    if (!result) {
        if (sort_column==COL_NAME) {
            result = a->counter - b->counter;
        }
        else {
            if  (a->rng&&b->rng) {
                result = a->rng->floor - b->rng->floor;
            }
            else if (prefs.st_sort_casesensitve) {
                result = strcmp(a->name,b->name);
            }
            else {
                result = g_ascii_strcasecmp(a->name,b->name);
            }
        }
    }

    /* take into account sort order */
    if (sort_descending) {
        result= -result;
    }

    if ((a->st_flags&ST_FLG_SORT_TOP)!=(b->st_flags&ST_FLG_SORT_TOP)) {
        /* different sort groups top vs non-top */
        result= (a->st_flags&ST_FLG_SORT_TOP)?-1:1;
    }
    return result;
}

extern GString*
stats_tree_format_as_str(const stats_tree* st, st_format_type format_type,
                    gint sort_column, gboolean sort_descending)
{
    int maxnamelen= stats_tree_branch_max_namelen(&st->root,0);
    stat_node *child;
    GString *s;
    int count;
    gchar *separator = NULL;

    switch(format_type) {
        case ST_FORMAT_YAML:
            s = g_string_new("---\n");
            break;
        case ST_FORMAT_XML:
            s = g_string_new("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
            break;
        case ST_FORMAT_CSV:
            s = g_string_new("\"level\",\"parent\",");
            for (count = 0; count<st->num_columns; count++) {
                g_string_append_printf(s,"\"%s\",",stats_tree_get_column_name(count));
            }
            g_string_append (s,"\n");
            break;
        case ST_FORMAT_PLAIN:
        {
            char fmt[16];
            int sep_length;

            sep_length= maxnamelen;
            for (count = 1; count<st->num_columns; count++) {
                sep_length += stats_tree_get_column_size(count)+2;
            }
            separator = (gchar *)g_malloc(sep_length+1);
            memset (separator, '=', sep_length);
            separator[sep_length] = 0;

            s = g_string_new("\n");
            g_string_append(s,separator);
            g_string_append_printf(s,"\n%s:\n",st->cfg->name);
            g_snprintf (fmt,(gulong)sizeof(fmt),"%%-%us",maxnamelen);
            g_string_append_printf(s,fmt,stats_tree_get_column_name(0));
            for (count = 1; count<st->num_columns; count++) {
                g_snprintf (fmt,(gulong)sizeof(fmt)," %%-%us",stats_tree_get_column_size(count)+1);
                g_string_append_printf(s,fmt,stats_tree_get_column_name(count));
            }
            memset (separator, '-', sep_length);
            g_string_append_printf(s,"\n%s\n",separator);
            break;
        }
        default:
            return g_string_new("unknown format for stats_tree\n");
    }

    for (child = st->root.children; child; child = child->next ) {
        stats_tree_format_node_as_str(child,s,format_type,0,"",maxnamelen,sort_column,sort_descending);

    }

    if (format_type==ST_FORMAT_PLAIN) {
        g_string_append_printf(s,"\n%s\n",separator);
        g_free(separator);
    }

    return s;
}

typedef struct {
    gint sort_column;
    gboolean sort_descending;
}   sortinfo;

/* Function to compare elements for child array sort. a and b are children, user_data
points to a st_flags value */
extern gint
stat_node_array_sortcmp (gconstpointer a, gconstpointer b, gpointer user_data)
{
    /* user_data is *guint value to st_flags */
    return stats_tree_sort_compare (*(const stat_node*const*)a,*(const stat_node*const*)b,
                    ((sortinfo*)user_data)->sort_column,((sortinfo*)user_data)->sort_descending);
}

static gchar*
clean_for_xml_tag (gchar *str)
{
    gchar *s = str;
    while ((s=strpbrk(s,"!\"#$%%&'()*+,/;<=>?@[\\]^`{|}~ ")) != NULL) {
        *(s++) = '-';
    }
    return str;
}

/** helper funcation to add note to formatted stats_tree */
WS_DLL_PUBLIC void stats_tree_format_node_as_str(const stat_node *node,
                         GString *s,
                         st_format_type format_type,
                         guint indent,
                         const gchar *path,
                         gint maxnamelen,
                         gint sort_column,
                         gboolean sort_descending)
{
    int count;
    int num_columns= node->st->num_columns;
    gchar **values= stats_tree_get_values_from_node(node);
    stat_node *child;
    sortinfo si;
    gchar *full_path;
    char fmt[16] = "%s%s%s";

    switch(format_type) {
        case ST_FORMAT_YAML:
            if (indent) {
                g_snprintf(fmt, (gulong)sizeof(fmt), "%%%ds%%s%%s", indent*4-2);
            }
            g_string_append_printf(s, fmt, "", indent?"- ":"", "Description");
            g_string_append_printf(s, ": \"%s\"\n", values[0]);

            for (count = 1; count<num_columns; count++) {
                if (*values[count]) {
                    g_string_append_printf(s, fmt, "", indent?"  ":"",
                                            stats_tree_get_column_name(count));
                    g_string_append_printf(s, ": %s\n", values[count]);
                }
            }
            if (node->children) {
                g_string_append_printf(s, fmt, "", indent?"  ":"", "Items:\n");
            }
            break;
        case ST_FORMAT_XML:
        {
            char *itemname = xml_escape(values[0]);
            g_string_append_printf(s,"<stat-node name=\"%s\"%s>\n",itemname,
                    node->rng?" isrange=\"true\"":"");
            g_free(itemname);
            for (count = 1; count<num_columns; count++) {
                gchar *colname= g_strdup(stats_tree_get_column_name(count));
                g_string_append_printf(s,"<%s>",clean_for_xml_tag(colname));
                g_string_append_printf(s,"%s</%s>\n",values[count],colname);
                g_free(colname);
            }
            break;
        }
        case ST_FORMAT_CSV:
            g_string_append_printf(s,"%d,\"%s\",\"%s\"",indent,path,values[0]);
            for (count = 1; count<num_columns; count++) {
                g_string_append_printf(s,",%s",values[count]);
            }
            g_string_append (s,"\n");
            break;
        case ST_FORMAT_PLAIN:
            g_snprintf (fmt,(gulong)sizeof(fmt),"%%%ds%%-%us",indent,maxnamelen-indent);
            g_string_append_printf(s,fmt,"",values[0]);
            for (count = 1; count<num_columns; count++) {
                g_snprintf (fmt,(gulong)sizeof(fmt)," %%-%us",stats_tree_get_column_size(count)+1);
                g_string_append_printf(s,fmt,values[count]);
            }
            g_string_append (s,"\n");
            break;
    }

    indent++;
    indent = indent > INDENT_MAX ? INDENT_MAX : indent;
    full_path= g_strdup_printf ("%s/%s",path,values[0]);

    for (count = 0; count<num_columns; count++) {
        g_free(values[count]);
    }
    g_free(values);

    if (node->children) {
        GArray *Children= g_array_new(FALSE,FALSE,sizeof(child));
        for (child = node->children; child; child = child->next ) {
            g_array_append_val(Children,child);
        }
        si.sort_column = sort_column;
        si.sort_descending = sort_descending;
        g_array_sort_with_data(Children,stat_node_array_sortcmp,&si);
        for (count = 0; count<((int)Children->len); count++) {
            stats_tree_format_node_as_str(g_array_index(Children,stat_node*,count), s, format_type,
                    indent, full_path, maxnamelen, sort_column, sort_descending);
        }
        g_array_free(Children,FALSE);
    }
    g_free(full_path);

    if (format_type==ST_FORMAT_XML) {
        g_string_append(s,"</stat-node>\n");
    }
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
