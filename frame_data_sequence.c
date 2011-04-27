/* frame_data_sequence.c
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>

#include "frame_data_sequence.h"

frame_data_sequence *
new_frame_data_sequence(void)
{
	frame_data_sequence *fds;

	fds = g_malloc(sizeof *fds);
	fds->count = 0;
	fds->ptree_root = NULL;
	return fds;
}

/*
 * For a given frame number, calculate the indices into a level 3
 * node, a level 2 node, a level 1 node, and a leaf node.
 */
#define LEVEL_3_INDEX(framenum) \
	((framenum) >> (3*LOG2_NODES_PER_LEVEL))
#define LEVEL_2_INDEX(framenum) \
	(((framenum) >> (2*LOG2_NODES_PER_LEVEL)) & (NODES_PER_LEVEL - 1))
#define LEVEL_1_INDEX(framenum) \
	(((framenum) >> (1*LOG2_NODES_PER_LEVEL)) & (NODES_PER_LEVEL - 1))
#define LEAF_INDEX(framenum) \
	(((framenum) >> (0*LOG2_NODES_PER_LEVEL)) & (NODES_PER_LEVEL - 1))

/*
 * Add a new frame_data structure to a frame_data_sequence.
 */
frame_data *
frame_data_sequence_add(frame_data_sequence *fds, frame_data *fdata)
{
  frame_data *leaf;
  frame_data **level1;
  frame_data ***level2;
  frame_data ****level3;
  frame_data *node;

  /*
   * The current value of fds->count is the index value for the new frame,
   * because the index value for a frame is the frame number - 1, and
   * if we currently have fds->count frames, the the frame number of
   * the last frame in the collection is fds->count, so its index value
   * is fds->count - 1.
   */
  if (fds->count == 0) {
    /* The tree is empty; allocate the first leaf node, which will be
       the root node. */
    leaf = g_malloc((sizeof *leaf)*NODES_PER_LEVEL);
    node = &leaf[0];
    fds->ptree_root = leaf;
  } else if (fds->count < NODES_PER_LEVEL) {
    /* It's a 1-level tree, and is going to stay that way for now. */
    leaf = fds->ptree_root;
    node = &leaf[fds->count];
  } else if (fds->count == NODES_PER_LEVEL) {
    /* It's a 1-level tree that will turn into a 2-level tree. */
    level1 = g_malloc((sizeof *level1)*NODES_PER_LEVEL);
    memset(level1, 0, (sizeof *level1)*NODES_PER_LEVEL);
    level1[0] = fds->ptree_root;
    leaf = g_malloc((sizeof *leaf)*NODES_PER_LEVEL);
    level1[1] = leaf;
    node = &leaf[0];
    fds->ptree_root = level1;
  } else if (fds->count < NODES_PER_LEVEL*NODES_PER_LEVEL) {
    /* It's a 2-level tree, and is going to stay that way for now. */
    level1 = fds->ptree_root;
    leaf = level1[fds->count >> LOG2_NODES_PER_LEVEL];
    if (leaf == NULL) {
      leaf = g_malloc((sizeof *leaf)*NODES_PER_LEVEL);
      level1[fds->count >> LOG2_NODES_PER_LEVEL] = leaf;
    }
    node = &leaf[LEAF_INDEX(fds->count)];
  } else if (fds->count == NODES_PER_LEVEL*NODES_PER_LEVEL) {
    /* It's a 2-level tree that will turn into a 3-level tree */
    level2 = g_malloc((sizeof *level2)*NODES_PER_LEVEL);
    memset(level2, 0, (sizeof *level2)*NODES_PER_LEVEL);
    level2[0] = fds->ptree_root;
    level1 = g_malloc((sizeof *level1)*NODES_PER_LEVEL);
    memset(level1, 0, (sizeof *level1)*NODES_PER_LEVEL);
    level2[1] = level1;
    leaf = g_malloc((sizeof *leaf)*NODES_PER_LEVEL);
    level1[0] = leaf;
    node = &leaf[0];
    fds->ptree_root = level2;
  } else if (fds->count < NODES_PER_LEVEL*NODES_PER_LEVEL*NODES_PER_LEVEL) {
    /* It's a 3-level tree, and is going to stay that way for now. */
    level2 = fds->ptree_root;
    level1 = level2[fds->count >> (LOG2_NODES_PER_LEVEL+LOG2_NODES_PER_LEVEL)];
    if (level1 == NULL) {
      level1 = g_malloc((sizeof *level1)*NODES_PER_LEVEL);
      memset(level1, 0, (sizeof *level1)*NODES_PER_LEVEL);
      level2[fds->count >> (LOG2_NODES_PER_LEVEL+LOG2_NODES_PER_LEVEL)] = level1;
    }
    leaf = level1[LEVEL_1_INDEX(fds->count)];
    if (leaf == NULL) {
      leaf = g_malloc((sizeof *leaf)*NODES_PER_LEVEL);
      level1[LEVEL_1_INDEX(fds->count)] = leaf;
    }
    node = &leaf[LEAF_INDEX(fds->count)];
  } else if (fds->count == NODES_PER_LEVEL*NODES_PER_LEVEL*NODES_PER_LEVEL) {
    /* It's a 3-level tree that will turn into a 4-level tree */
    level3 = g_malloc((sizeof *level3)*NODES_PER_LEVEL);
    memset(level3, 0, (sizeof *level3)*NODES_PER_LEVEL);
    level3[0] = fds->ptree_root;
    level2 = g_malloc((sizeof *level2)*NODES_PER_LEVEL);
    memset(level2, 0, (sizeof *level2)*NODES_PER_LEVEL);
    level3[1] = level2;
    level1 = g_malloc((sizeof *level1)*NODES_PER_LEVEL);
    memset(level1, 0, (sizeof *level1)*NODES_PER_LEVEL);
    level2[0] = level1;
    leaf = g_malloc((sizeof *leaf)*NODES_PER_LEVEL);
    level1[0] = leaf;
    node = &leaf[0];
    fds->ptree_root = level3;
  } else {
    /* fds->count is 2^32-1 at most, and NODES_PER_LEVEL^4
       2^(LOG2_NODES_PER_LEVEL*4), and LOG2_NODES_PER_LEVEL is 10,
       so fds->count is always less < NODES_PER_LEVEL^4.

       XXX - we should fail if fds->count is 2^31-1, or should
       make the frame numbers 64-bit and just let users run
       themselves out of address space or swap space. :-) */
    /* It's a 4-level tree, and is going to stay that way forever. */
    level3 = fds->ptree_root;
    level2 = level3[LEVEL_3_INDEX(fds->count)];
    if (level2 == NULL) {
      level2 = g_malloc((sizeof *level2)*NODES_PER_LEVEL);
      memset(level2, 0, (sizeof *level2)*NODES_PER_LEVEL);
      level3[LEVEL_3_INDEX(fds->count)] = level2;
    }
    level1 = level2[LEVEL_2_INDEX(fds->count)];
    if (level1 == NULL) {
      level1 = g_malloc((sizeof *level1)*NODES_PER_LEVEL);
      memset(level1, 0, (sizeof *level1)*NODES_PER_LEVEL);
      level2[LEVEL_2_INDEX(fds->count)] = level1;
    }
    leaf = level1[LEVEL_1_INDEX(fds->count)];
    if (leaf == NULL) {
      leaf = g_malloc((sizeof *leaf)*NODES_PER_LEVEL);
      level1[LEVEL_1_INDEX(fds->count)] = leaf;
    }
    node = &leaf[LEAF_INDEX(fds->count)];
  }
  *node = *fdata;
  fds->count++;
  return node;
}

/*
 * Find the frame_data for the specified frame number.
 */
frame_data *
frame_data_sequence_find(frame_data_sequence *fds, guint32 num)
{
  frame_data *leaf;
  frame_data **level1;
  frame_data ***level2;
  frame_data ****level3;

  if (num == 0) {
    /* There is no frame number 0 */
    return NULL;
  }

  /* Convert it into an index number. */
  num--;
  if (num >= fds->count) {
    /* There aren't that many frames. */
    return NULL;
  }

  if (fds->count <= NODES_PER_LEVEL) {
    /* It's a 1-level tree. */
    leaf = fds->ptree_root;
    return &leaf[num];
  }
  if (fds->count <= NODES_PER_LEVEL*NODES_PER_LEVEL) {
    /* It's a 2-level tree. */
    level1 = fds->ptree_root;
    leaf = level1[num >> LOG2_NODES_PER_LEVEL];
    return &leaf[LEAF_INDEX(num)];
  }
  if (fds->count <= NODES_PER_LEVEL*NODES_PER_LEVEL*NODES_PER_LEVEL) {
    /* It's a 3-level tree. */
    level2 = fds->ptree_root;
    level1 = level2[num >> (LOG2_NODES_PER_LEVEL+LOG2_NODES_PER_LEVEL)];
    leaf = level1[(num >> LOG2_NODES_PER_LEVEL) & (NODES_PER_LEVEL - 1)];
    return &leaf[LEAF_INDEX(num)];
  }
  /* fds->count is 2^32-1 at most, and NODES_PER_LEVEL^4
     2^(LOG2_NODES_PER_LEVEL*4), and LOG2_NODES_PER_LEVEL is 10,
     so fds->count is always less < NODES_PER_LEVEL^4. */
  /* It's a 4-level tree, and is going to stay that way forever. */
  level3 = fds->ptree_root;
  level2 = level3[num >> (LOG2_NODES_PER_LEVEL+LOG2_NODES_PER_LEVEL+LOG2_NODES_PER_LEVEL)];
  level1 = level2[(num >> (LOG2_NODES_PER_LEVEL+LOG2_NODES_PER_LEVEL)) & (NODES_PER_LEVEL - 1)];
  leaf = level1[(num >> LOG2_NODES_PER_LEVEL) & (NODES_PER_LEVEL - 1)];
  return &leaf[LEAF_INDEX(num)];
}

/*
 * Free a frame_data_sequence and all the frame_data structures in it.
 */
void
free_frame_data_sequence(frame_data_sequence *fds)
{
  frame_data **level1;
  frame_data ***level2;
  frame_data ****level3;
  guint i, j, k;

  if (fds->count == 0) {
    /* Nothing to free. */
    return;
  }
  if (fds->count <= NODES_PER_LEVEL) {
    /* It's a 1-level tree. */
    g_free(fds->ptree_root);
  } else if (fds->count <= NODES_PER_LEVEL*NODES_PER_LEVEL) {
    /* It's a 2-level tree. */
    level1 = fds->ptree_root;
    for (i = 0; i < NODES_PER_LEVEL && level1[i] != NULL; i++)
      g_free(level1[i]);
    g_free(level1);
  } else if (fds->count <= NODES_PER_LEVEL*NODES_PER_LEVEL*NODES_PER_LEVEL) {
    /* It's a 3-level tree. */
    level2 = fds->ptree_root;
    for (i = 0; i < NODES_PER_LEVEL && level2[i] != NULL; i++) {
      level1 = level2[i];
      for (j = 0; j < NODES_PER_LEVEL && level1[i] != NULL; j++)
        g_free(level1[j]);
      g_free(level1);
    }
    g_free(level2);
    return;
  } else {
    /* fds->count is 2^32-1 at most, and NODES_PER_LEVEL^4
       2^(LOG2_NODES_PER_LEVEL*4), and LOG2_NODES_PER_LEVEL is 10,
       so fds->count is always less < NODES_PER_LEVEL^4. */
    /* It's a 4-level tree, and is going to stay that way forever. */
    level3 = fds->ptree_root;
    for (i = 0; i < NODES_PER_LEVEL && level3[i] != NULL; i++) {
      level2 = level3[i];
      for (j = 0; j < NODES_PER_LEVEL && level2[i] != NULL; j++) {
        level1 = level2[j];
        for (k = 0; k < NODES_PER_LEVEL && level1[k] != NULL; k++)
          g_free(level1[k]);
      }
      g_free(level2);
    }
    g_free(level3);
  }
  g_free(fds);
}
