
#ifndef PROTO_HIER_STATS_H
#define PROTO_HIER_STATS_H

#include "proto.h"

typedef struct {
	header_field_info	*hfinfo;
	guint			num_pkts_total;
	guint			num_pkts_last;
	guint			num_bytes_total;
	guint			num_bytes_last;
} ph_stats_node_t;


typedef struct {
	guint	tot_packets;
	guint	tot_bytes;
	GNode	*stats_tree;
} ph_stats_t;


ph_stats_t* ph_stats_new(void);

void ph_stats_free(ph_stats_t *ps);

#endif
