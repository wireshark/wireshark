/* stats_tree_priv.h
 * implementor's API for stats_tree
 * 2005, Luis E. G. Ontanon
 *
 * $Id: $
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

#ifndef __STATS_TREE_PRIV_H
#define  __STATS_TREE_PRIV_H

#include "stats_tree.h"

#define INDENT_MAX 32
#define NUM_BUF_SIZE 32

/* implementations should define this to contain its own node related data
 * as well as some operations on it */
typedef struct _st_node_pres st_node_pres;

/* implementations should define this to contain its own tree related data
* as well as some operations on it */
typedef struct _tree_pres tree_pres;

typedef struct _stat_node stat_node;


typedef struct _range_pair {
	gint floor;
	gint ceil;
} range_pair_t;

struct _stat_node {
	gchar*			name;
	int				id;
	
	/* the counter it keeps */
	gint			counter;

	/* children nodes by name */
	GHashTable*		hash;
	
	/* the owner of this node */
	stats_tree*		st;
	
	/* relatives */
	stat_node*	parent;
	stat_node*	children;
	stat_node*	next;

	/* used to check if value is within range */
	range_pair_t* rng;
	
	/* node presentation data */
	st_node_pres* pr;
} ;

struct _stats_tree {
	guint8*			abbr;
	guint8*			name;
	
	/* is this realy needed? */
	char*			filter;
	
	/* times */
	float			start;
	float			elapsed;
		

	   /* used to lookup named parents:
		*    key: parent node name
		*  value: parent node
		*/
	GHashTable*			names;
	
	   /* used for quicker lookups of parent nodes */
	GPtrArray*			parents;
	
	/* every tree in nature has one */
	stat_node	root;
	
	/* dissector defined callbacks */
	stat_tree_packet_cb packet;
	stat_tree_init_cb init;

	/**** tree representation
	 * 	to be defined (if needed) by the implementations
	 */
	tree_pres* pr;
	
	/*  node presentation callbacks
	 */
		
	/* last to be called at node creation */
	void (*setup_node_pr)(stat_node*);
	
	/* last to be called at node destruction */
	void (*free_node_pr)(stat_node*);
	
	/* to be called for every node in the tree */
	void (*draw_node)(stat_node*);
	void (*reset_node)(stat_node*);
	
	/* tree presentation callbacks */
	
	tree_pres* (*new_tree_pr)(stats_tree*);
	void (*free_tree_pr)(stats_tree*);
	void (*draw_tree)(stats_tree*);
	void (*reset_tree)(stats_tree*);
};

/* guess what, this is it! */
extern void stats_tree_presentation(void (*registry_iterator)(gpointer,gpointer,gpointer),
									void (*setup_node_pr)(stat_node*),
									void (*free_node_pr)(stat_node*),
									void (*draw_node)(stat_node*),
									void (*reset_node)(stat_node*),
									tree_pres* (*new_tree_pr)(stats_tree*),
									void (*free_tree_pr)(stats_tree*),
									void (*draw_tree)(stats_tree*),
									void (*reset_tree)(stats_tree*),
									void* data);

/* callback for taps */
extern int  stats_tree_packet(void*, packet_info*, epan_dissect_t*, const void *);

/* callback for reset */
extern void reset_stats_tree(void*);

/* callback for destoy */
extern void free_stats_tree(stats_tree* st);

/* given an optarg splits the abbr part
   and returns a newly allocated buffer containing it */
extern guint8* get_st_abbr(const guint8* optarg);

/* obtains a stats tree from the registry given its abbr */
extern stats_tree* get_stats_tree_by_abbr(guint8* abbr);

/* extracts node data as strings from a stat_node into
   the buffers given by value, rate and precent
   if NULL they are ignored */
extern void get_strings_from_node(const stat_node* node,
								  guint8* value,
								  guint8* rate,
								  guint8* percent);

/* populates the given GString with a tree representation of a branch given by node,
   using indent spaces as indentation */
extern void stat_branch_to_str(const stat_node* node,
							   GString* s,
							   guint indent);

/* a text representation of a node,
   if buffer is NULL returns a newly allocated string */
extern guint8* stat_node_to_str(const stat_node* node,
								guint8* buffer, guint len);

/* destroys the stats_tree */
extern void free_stats_tree(stats_tree* st);

#endif /* __STATS_TREE_PRIV_H */
