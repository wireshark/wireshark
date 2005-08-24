/* stats_tree.c
 * API for a counter tree for ethereal
 * 2004, Luis E. G. Ontanon
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/stats_tree_priv.h>
#include <string.h>

#include "stats_tree.h"

/*
TODO: 
   - sort out the sorting issue
 
 */

/* used to contain the registered stat trees */
static GHashTable* registry = NULL;

/* writes into the buffers pointed by value, rate and percent
   the string representations of a node*/
extern void stats_tree_get_strs_from_node(const stat_node* node, guint8* value, guint8* rate, guint8* percent) {
	float f;
	
	if (value) g_snprintf(value,NUM_BUF_SIZE,"%u",node->counter);
	
	if (rate) {
		*rate = '\0';
		if (node->st->elapsed > 0.0) {
			f = ((float)node->counter) / (float)node->st->elapsed;
			g_snprintf(rate,NUM_BUF_SIZE,"%f",f);
		}
	}
	
	if (percent) {
		*percent = '\0';
		if (node->parent->counter > 0) {
			f = (float)(((float)node->counter * 100.0) / node->parent->counter);
			g_snprintf(percent,NUM_BUF_SIZE,"%.2f%%",f);
		}
	}
}


/* a text representation of a node
if buffer is NULL returns a newly allocated string */
extern guint8* stats_tree_node_to_str(const stat_node* node,
								guint8* buffer, guint len) {
	if (buffer) {
		g_snprintf(buffer,len,"%s: %i",node->name, node->counter);
		return buffer;
	} else {
		return g_strdup_printf("%s: %i",node->name, node->counter);
	}
}

extern guint stats_tree_branch_max_namelen(const stat_node* node, guint indent) {
	stat_node* child;
	guint maxlen = 0;
	guint len;
	
	indent = indent > INDENT_MAX ? INDENT_MAX : indent;

	if (node->children) {
		for (child = node->children; child; child = child->next ) {
			len = stats_tree_branch_max_namelen(child,indent+1); 
			maxlen = len > maxlen ? len : maxlen;
		}
	}
	
	len = strlen(node->name) + indent;
	maxlen = len > maxlen ? len : maxlen;
	
	return maxlen;
}

static gchar* format;

/* populates the given GString with a tree representation of a branch given by node,
using indent spaces as initial indentation */
extern void stats_tree_branch_to_str(const stat_node* node, GString* s, guint indent) {
	stat_node* child;
	static gchar indentation[INDENT_MAX+1];
	static gchar value[NUM_BUF_SIZE];
	static gchar rate[NUM_BUF_SIZE];
	static gchar percent[NUM_BUF_SIZE];
	
	guint i = 0;
	
	if (indent == 0) {
		format = g_strdup_printf(" %%s%%-%us%%12s   %%12s    %%12s\n",stats_tree_branch_max_namelen(node,0));
	}
	
	stats_tree_get_strs_from_node(node, value, rate, percent);
	
	indent = indent > INDENT_MAX ? INDENT_MAX : indent;
	
	/* fill indentation with indent spaces */
	if (indent > 0) {
		while(i<indent)
			indentation[i++] = ' ';
	}
	
	indentation[i++] = '\0';
	
	g_string_sprintfa(s,format,
					  indentation,node->name,value,rate,percent);
		
	if (node->children) {
		for (child = node->children; child; child = child->next ) {
			stats_tree_branch_to_str(child,s,indent+1);
		}
	}
	
	if (indent == 0) {
		g_free(format);
	}
}


/* frees the resources allocated by a stat_tree node */
static void free_stat_node( stat_node* node ) {
	stat_node* child;
    stat_node* next;
	
	if (node->children) {
        for (child = node->children; child; child = next ) {
            /* child->next will be gone after free_stat_node, so cache it here */
            next = child->next;
			free_stat_node(child);
        }
	}
	
	if(node->st->cfg->free_node_pr) node->st->cfg->free_node_pr(node);
	
	if (node->hash) g_hash_table_destroy(node->hash);

	if (node->rng) g_free(node->rng);
	
	if (node->name) g_free(node->name);
	
	g_free(node);
}

/* destroys the whole tree instance */
extern void stats_tree_free(stats_tree* st) {
	stat_node* child;
	stat_node* next;
	
	g_free(st->filter);
	g_hash_table_destroy(st->names);
	g_ptr_array_free(st->parents,FALSE);
	
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
static void reset_stat_node(stat_node* node) {
	stat_node* child;
	
	if (node->children) {
		for (child = node->children; child; child = child->next ) 
			reset_stat_node(child);
	}
	
	node->counter = 0;
	
	if(node->st->cfg->reset_node) {
		node->st->cfg->reset_node(node);
	}
	
}

/* reset the whole stats_tree */
extern void stats_tree_reset(void* p) {
	stats_tree* st = p;
	reset_stat_node(&st->root);
	
	if (st->cfg->reset_tree) {
		st->cfg->reset_tree(st);
	}
}

extern void stats_tree_reinit(void* p) {
	stats_tree* st = p;
	stat_node* child;
	stat_node* next;
	
	for (child = st->root.children; child; child = next) {
        /* child->next will be gone after free_stat_node, so cache it here */
        next = child->next;
		free_stat_node(child);
	}
	
	st->root.children = NULL;
	st->root.counter = 0;
	
	if (st->cfg->init) {
		st->cfg->init(st);
	}
}

/* register a new stats_tree */
extern void stats_tree_register(const guint8* tapname,
								const guint8* abbr, 
								const guint8* name,
								stat_tree_packet_cb packet,
								stat_tree_init_cb init,
								stat_tree_cleanup_cb cleanup) {
	
	stats_tree_cfg* cfg = g_malloc( sizeof(stats_tree_cfg) );

	/* at the very least the abbrev and the packet function should be given */ 
	g_assert( tapname && abbr && packet );

	cfg->tapname = g_strdup(tapname);
	cfg->abbr = g_strdup(abbr);
	cfg->name = name ? g_strdup(name) : g_strdup(abbr);
	
	cfg->packet = packet;
	cfg->init = init;
	cfg->cleanup = cleanup;
	
	/* these have to be filled in by implementations */
	cfg->setup_node_pr = NULL;
	cfg->new_tree_pr = NULL;
	cfg->free_node_pr = NULL;
	cfg->free_tree_pr = NULL;
	cfg->draw_node = NULL;
	cfg->draw_tree = NULL;
	cfg->reset_node = NULL;
	cfg->reset_tree = NULL;

	if (!registry) registry = g_hash_table_new(g_str_hash,g_str_equal);

	g_hash_table_insert(registry,cfg->abbr,cfg);
	
}

extern stats_tree* stats_tree_new(stats_tree_cfg* cfg, tree_pres* pr,char* filter) {
	stats_tree* st = g_malloc(sizeof(stats_tree));

	st->cfg = cfg;
	st->pr = pr;

	st->names = g_hash_table_new(g_str_hash,g_str_equal);
	st->parents = g_ptr_array_new();
	st->filter = g_strdup(filter);
	
	st->start = -1.0;
	st->elapsed = 0.0;
	st->highest_seen = 0;
	
	st->root.counter = 0;
	st->root.name = g_strdup(cfg->name);
	st->root.st = st;
	st->root.parent = NULL;
	st->root.children = NULL;
	st->root.next = NULL;
	st->root.hash = NULL;
	st->root.pr = NULL;
	
	g_ptr_array_add(st->parents,&st->root);
	
	return st;
}	

/* will be the tap packet cb */
extern int stats_tree_packet(void* p, packet_info* pinfo, epan_dissect_t *edt, const void *pri) {
	stats_tree* st = p;
	double now;
	
	if (st->highest_seen >= pinfo->fd->num) return 0;
	
	st->highest_seen = pinfo->fd->num;

	now = nstime_to_msec(&pinfo->fd->rel_ts);
	
	if (st->start < 0.0) st->start = now;
	
	st->elapsed = now - st->start;
	
	if (st->cfg->packet)
		return st->cfg->packet(st,pinfo,edt,pri);
	else
		return 0;
}

static GHashTable* stat_tree_registry(void) {
	return registry;
}

extern stats_tree_cfg* stats_tree_get_cfg_by_abbr(guint8* abbr) {
	return g_hash_table_lookup(registry,abbr);
}


struct _stats_tree_pres_cbs {
	void (*setup_node_pr)(stat_node*);
	void (*free_node_pr)(stat_node*);
	void (*draw_node)(stat_node*);
	void (*reset_node)(stat_node*);
	tree_pres* (*new_tree_pr)(stats_tree*);
	void (*free_tree_pr)(stats_tree*);
	void (*draw_tree)(stats_tree*);
	void (*reset_tree)(stats_tree*);
};

static void setup_tree_presentation(gpointer k _U_, gpointer v, gpointer p) {
	stats_tree_cfg* cfg = v;
	struct _stats_tree_pres_cbs *d = p;
	
	cfg->setup_node_pr = d->setup_node_pr;
	cfg->new_tree_pr = d->new_tree_pr;
	cfg->free_node_pr = d->free_node_pr;
	cfg->free_tree_pr = d->free_tree_pr;
	cfg->draw_node = d->draw_node;
	cfg->draw_tree = d->draw_tree;
	cfg->reset_node = d->reset_node;
	cfg->reset_tree = d->reset_tree;
	
}

extern void stats_tree_presentation(void (*registry_iterator)(gpointer,gpointer,gpointer),
									void (*setup_node_pr)(stat_node*),
									void (*free_node_pr)(stat_node*),
									void (*draw_node)(stat_node*),
									void (*reset_node)(stat_node*),
									tree_pres* (*new_tree_pr)(stats_tree*),
									void (*free_tree_pr)(stats_tree*),
									void (*draw_tree)(stats_tree*),
									void (*reset_tree)(stats_tree*),
									void* data) {
	static struct _stats_tree_pres_cbs d;
	
	d.setup_node_pr = setup_node_pr;
	d.new_tree_pr = new_tree_pr;
	d.free_node_pr = free_node_pr;
	d.free_tree_pr = free_tree_pr;
	d.draw_node = draw_node;
	d.draw_tree = draw_tree;
	d.reset_node = reset_node;
	d.reset_tree = reset_tree;
	
	if (registry) g_hash_table_foreach(registry,setup_tree_presentation,&d);
	
	if (registry_iterator && registry)
		g_hash_table_foreach(registry,registry_iterator,data);
	
}


/* creates a stat_tree node
*    name: the name of the stats_tree node
*    parent_name: the name of the ALREADY REGISTERED parent
*    with_hash: whether or not it should keep a hash with it's children names
*    as_named_node: whether or not it has to be registered in the root namespace
*/
static stat_node*  new_stat_node(stats_tree* st,
								 const gchar* name,
								 int parent_id,
								 gboolean with_hash,
								 gboolean as_parent_node) {
	
	stat_node *node = g_malloc (sizeof(stat_node));
	stat_node* last_chld = NULL;
	
	node->counter = 0;
	node->name = g_strdup(name);
	node->children = NULL;
	node->next = NULL;
	node->st = (stats_tree*) st;
	node->hash = with_hash ? g_hash_table_new(g_str_hash,g_str_equal) : NULL;
	node->parent = NULL;
	node->rng  =  NULL;

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
		node->parent = g_ptr_array_index(st->parents,parent_id);
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

extern int stats_tree_create_node(stats_tree* st, const gchar* name, int parent_id, gboolean with_hash) {
	stat_node* node = new_stat_node(st,name,parent_id,with_hash,TRUE);
	
	if (node) 
		return node->id;
	else
		return 0;
}

/* XXX: should this be a macro? */
extern int stats_tree_create_node_by_pname(stats_tree* st,
										   const gchar* name,
										   const gchar* parent_name,
										   gboolean with_children) {
	return stats_tree_create_node(st,name,stats_tree_parent_id_by_name(st,parent_name),with_children);
}



/*
 * Increases by delta the counter of the node whose name is given
 * if the node does not exist yet it's created (with counter=1)
 * using parent_name as parent node.
 * with_hash=TRUE to indicate that the created node will have a parent
 */
extern int stats_tree_manip_node(manip_node_mode mode, stats_tree* st, const guint8* name, int parent_id, gboolean with_hash, gint value) {
	stat_node* node = NULL;
	stat_node* parent = NULL;
	
	g_assert( parent_id >= 0 && parent_id < (int) st->parents->len );
	
	parent = g_ptr_array_index(st->parents,parent_id);
	
	if( parent->hash ) {
		node = g_hash_table_lookup(parent->hash,name);
	} else {
		node = g_hash_table_lookup(st->names,name);
	}
	
	if ( node == NULL ) 
		node = new_stat_node(st,name,parent_id,with_hash,with_hash);
	
	switch (mode) {
		case MN_INCREASE: node->counter += value; break;
		case MN_SET: node->counter = value; break;
	}
	
	if (node) 
		return node->id;
	else
		return -1;
}


extern guint8* stats_tree_get_abbr(const guint8* optarg) {
	guint i;

	/* XXX: this fails when tethereal is given any options
	   after the -z */
	g_assert(optarg != NULL);
	
	for (i=0; optarg[i] && optarg[i] != ','; i++);
	
	if (optarg[i] == ',') {
		return g_strndup(optarg,i);
	} else {
		return NULL;
	}
}


static range_pair_t* get_range(guint8* rngstr) {
	gchar** split;
	range_pair_t* rng = g_malloc(sizeof(range_pair_t));
	
	split =  g_strsplit(rngstr,"-",2);

	rng->floor = strtol(split[0],NULL,10);
	rng->ceil  = strtol(split[1],NULL,10);
	
	if (rng->ceil == 0) rng->ceil = G_MAXINT;
	if (rng->floor == 0) rng->floor = G_MININT;

	g_strfreev(split);
	
	return rng;
}


extern int stats_tree_create_range_node(stats_tree* st,
								const gchar* name,
								int parent_id,
								...) {
	va_list list;
	guint8* curr_range;
	stat_node* rng_root = new_stat_node(st, name, parent_id, FALSE, TRUE);
	stat_node* range_node = NULL;
	
	va_start( list, parent_id );
	while (( curr_range = va_arg(list, guint8*) )) {
		range_node = new_stat_node(st, curr_range, rng_root->id, FALSE, FALSE);
		range_node->rng = get_range(curr_range);
	}
	va_end( list );

	return rng_root->id;
}

/****/
extern int stats_tree_parent_id_by_name(stats_tree* st, const gchar* parent_name) {
	stat_node* node = g_hash_table_lookup(st->names,parent_name);
	
	if (node)
		return node->id;
	else
		return 0; /* XXX: this is the root shoud we return -1 instead?*/
}


extern int stats_tree_range_node_with_pname(stats_tree* st,
											  const gchar* name,
											  const gchar* parent_name,
											  ...) {
	va_list list;
	guint8* curr_range;
	stat_node* range_node = NULL;
	int parent_id = stats_tree_parent_id_by_name(st,parent_name);
	stat_node* rng_root = new_stat_node(st, name, parent_id, FALSE, TRUE);

	va_start( list, parent_name );
	while (( curr_range = va_arg(list, guint8*) )) {
		range_node = new_stat_node(st, curr_range, rng_root->id, FALSE, FALSE);
		range_node->rng = get_range(curr_range);
	}
	va_end( list );
	
	return rng_root->id;
}	


extern int stats_tree_tick_range(stats_tree* st,
						 const gchar* name,
						 int parent_id,
						 int value_in_range) {
	
	stat_node* node = NULL;
	stat_node* parent = NULL;
	stat_node* child = NULL;
	gint floor, ceil;
	
	if (parent_id >= 0 && parent_id < (int) st->parents->len) {
		parent = g_ptr_array_index(st->parents,parent_id);
	} else {
		g_assert_not_reached();
	}
	
	if( parent->hash ) {
		node = g_hash_table_lookup(parent->hash,name);
	} else {
		node = g_hash_table_lookup(st->names,name);
	}
	
	if ( node == NULL ) 
		return node->id;
	
	for ( child = node->children; child; child = child->next) {
		floor =  child->rng->floor;
		ceil = child->rng->ceil;
		
		if ( value_in_range >= floor && value_in_range <= ceil ) {
			child->counter++;
			return node->id;
		}
	}
	
	return node->id;
}

extern int stats_tree_create_pivot(stats_tree* st,
							 const gchar* name,
							 int parent_id) {
	stat_node* node = new_stat_node(st,name,parent_id,TRUE,TRUE);
	
	if (node) 
		return node->id;
	else
		return 0;
}

extern int stats_tree_create_pivot_by_pname(stats_tree* st,
							 const gchar* name,
							 const gchar* parent_name) {
	int parent_id = stats_tree_parent_id_by_name(st,parent_name);
	stat_node* node;
	
	node = new_stat_node(st,name,parent_id,TRUE,TRUE);
	
	if (node) 
		return node->id;
	else
		return 0;
}

extern int stats_tree_tick_pivot(stats_tree* st,
					  int pivot_id,
					  const gchar* pivot_value) {
	
	stat_node* parent = g_ptr_array_index(st->parents,pivot_id);
	
	parent->counter++;
	stats_tree_manip_node( MN_INCREASE, st, pivot_value, pivot_id, FALSE, 1);
	
	return pivot_id;
}

