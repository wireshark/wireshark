/* frame_data_sequence.h
 * Implements a sequence of frame_data structures
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __FRAME_DATA_SEQUENCE_H__
#define __FRAME_DATA_SEQUENCE_H__

/*
 * We store the frame_data structures in a radix tree, with 1024
 * elements per level.  The leaf nodes are arrays of 1024 frame_data
 * structures; the nodes above them are arrays of 1024 pointers to
 * the nodes below them.  The capture_file structure has a pointer
 * to the root node.
 *
 * As frame numbers are 32 bits, and as 1024 is 2^10, that gives us
 * up to 4 levels of tree.
 */
#define LOG2_NODES_PER_LEVEL	10
#define NODES_PER_LEVEL		(1<<LOG2_NODES_PER_LEVEL)

typedef struct {
  guint32      count;           /* Total number of frames */
  void        *ptree_root;      /* Pointer to the root node */
} frame_data_sequence;

extern frame_data_sequence *new_frame_data_sequence(void);

extern frame_data *frame_data_sequence_add(frame_data_sequence *fds,
    frame_data *fdata);

/*
 * Find the frame_data for the specified frame number.
 */
extern frame_data *frame_data_sequence_find(frame_data_sequence *fds,
    guint32 num);

/*
 * Free a frame_data_sequence and all the frame_data structures in it.
 */
extern void free_frame_data_sequence(frame_data_sequence *fds);

#endif /* frame_data_sequence.h */
