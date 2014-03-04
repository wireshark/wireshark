/* frame_data_sequence.c
 * Implements a sequence of frame_data structures
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

#include "config.h"

#include <glib.h>

#include <epan/packet.h>

#include "frame_data_sequence.h"

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

struct _frame_data_sequence {
  guint32      count;           /* Total number of frames */
  void        *ptree_root;      /* Pointer to the root node */
};

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

frame_data_sequence *
new_frame_data_sequence(void)
{
	frame_data_sequence *fds;

	fds = (frame_data_sequence *)g_malloc(sizeof *fds);
	fds->count = 0;
	fds->ptree_root = NULL;
	return fds;
}

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
    leaf = (frame_data *)g_malloc((sizeof *leaf)*NODES_PER_LEVEL);
    node = &leaf[0];
    fds->ptree_root = leaf;
  } else if (fds->count < NODES_PER_LEVEL) {
    /* It's a 1-level tree, and is going to stay that way for now. */
    leaf = (frame_data *)fds->ptree_root;
    node = &leaf[fds->count];
  } else if (fds->count == NODES_PER_LEVEL) {
    /* It's a 1-level tree that will turn into a 2-level tree. */
    level1 = (frame_data **)g_malloc0((sizeof *level1)*NODES_PER_LEVEL);
    level1[0] = (frame_data *)fds->ptree_root;
    leaf = (frame_data *)g_malloc((sizeof *leaf)*NODES_PER_LEVEL);
    level1[1] = leaf;
    node = &leaf[0];
    fds->ptree_root = level1;
  } else if (fds->count < NODES_PER_LEVEL*NODES_PER_LEVEL) {
    /* It's a 2-level tree, and is going to stay that way for now. */
    level1 = (frame_data **)fds->ptree_root;
    leaf = level1[fds->count >> LOG2_NODES_PER_LEVEL];
    if (leaf == NULL) {
      leaf = (frame_data *)g_malloc((sizeof *leaf)*NODES_PER_LEVEL);
      level1[fds->count >> LOG2_NODES_PER_LEVEL] = leaf;
    }
    node = &leaf[LEAF_INDEX(fds->count)];
  } else if (fds->count == NODES_PER_LEVEL*NODES_PER_LEVEL) {
    /* It's a 2-level tree that will turn into a 3-level tree */
    level2 = (frame_data ***)g_malloc0((sizeof *level2)*NODES_PER_LEVEL);
    level2[0] = (frame_data **)fds->ptree_root;
    level1 = (frame_data **)g_malloc0((sizeof *level1)*NODES_PER_LEVEL);
    level2[1] = level1;
    leaf = (frame_data *)g_malloc((sizeof *leaf)*NODES_PER_LEVEL);
    level1[0] = leaf;
    node = &leaf[0];
    fds->ptree_root = level2;
  } else if (fds->count < NODES_PER_LEVEL*NODES_PER_LEVEL*NODES_PER_LEVEL) {
    /* It's a 3-level tree, and is going to stay that way for now. */
    level2 = (frame_data ***)fds->ptree_root;
    level1 = level2[fds->count >> (LOG2_NODES_PER_LEVEL+LOG2_NODES_PER_LEVEL)];
    if (level1 == NULL) {
      level1 = (frame_data **)g_malloc0((sizeof *level1)*NODES_PER_LEVEL);
      level2[fds->count >> (LOG2_NODES_PER_LEVEL+LOG2_NODES_PER_LEVEL)] = level1;
    }
    leaf = level1[LEVEL_1_INDEX(fds->count)];
    if (leaf == NULL) {
      leaf = (frame_data *)g_malloc((sizeof *leaf)*NODES_PER_LEVEL);
      level1[LEVEL_1_INDEX(fds->count)] = leaf;
    }
    node = &leaf[LEAF_INDEX(fds->count)];
  } else if (fds->count == NODES_PER_LEVEL*NODES_PER_LEVEL*NODES_PER_LEVEL) {
    /* It's a 3-level tree that will turn into a 4-level tree */
    level3 = (frame_data ****)g_malloc0((sizeof *level3)*NODES_PER_LEVEL);
    level3[0] = (frame_data ***)fds->ptree_root;
    level2 = (frame_data ***)g_malloc0((sizeof *level2)*NODES_PER_LEVEL);
    level3[1] = level2;
    level1 = (frame_data **)g_malloc0((sizeof *level1)*NODES_PER_LEVEL);
    level2[0] = level1;
    leaf = (frame_data *)g_malloc((sizeof *leaf)*NODES_PER_LEVEL);
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
    level3 = (frame_data ****)fds->ptree_root;
    level2 = level3[LEVEL_3_INDEX(fds->count)];
    if (level2 == NULL) {
      level2 = (frame_data ***)g_malloc0((sizeof *level2)*NODES_PER_LEVEL);
      level3[LEVEL_3_INDEX(fds->count)] = level2;
    }
    level1 = level2[LEVEL_2_INDEX(fds->count)];
    if (level1 == NULL) {
      level1 = (frame_data **)g_malloc0((sizeof *level1)*NODES_PER_LEVEL);
      level2[LEVEL_2_INDEX(fds->count)] = level1;
    }
    leaf = level1[LEVEL_1_INDEX(fds->count)];
    if (leaf == NULL) {
      leaf = (frame_data *)g_malloc((sizeof *leaf)*NODES_PER_LEVEL);
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
    leaf = (frame_data *)fds->ptree_root;
    return &leaf[num];
  }
  if (fds->count <= NODES_PER_LEVEL*NODES_PER_LEVEL) {
    /* It's a 2-level tree. */
    level1 = (frame_data **)fds->ptree_root;
    leaf = level1[num >> LOG2_NODES_PER_LEVEL];
    return &leaf[LEAF_INDEX(num)];
  }
  if (fds->count <= NODES_PER_LEVEL*NODES_PER_LEVEL*NODES_PER_LEVEL) {
    /* It's a 3-level tree. */
    level2 = (frame_data ***)fds->ptree_root;
    level1 = level2[num >> (LOG2_NODES_PER_LEVEL+LOG2_NODES_PER_LEVEL)];
    leaf = level1[(num >> LOG2_NODES_PER_LEVEL) & (NODES_PER_LEVEL - 1)];
    return &leaf[LEAF_INDEX(num)];
  }
  /* fds->count is 2^32-1 at most, and NODES_PER_LEVEL^4
     2^(LOG2_NODES_PER_LEVEL*4), and LOG2_NODES_PER_LEVEL is 10,
     so fds->count is always less < NODES_PER_LEVEL^4. */
  /* It's a 4-level tree, and is going to stay that way forever. */
  level3 = (frame_data ****)fds->ptree_root;
  level2 = level3[num >> (LOG2_NODES_PER_LEVEL+LOG2_NODES_PER_LEVEL+LOG2_NODES_PER_LEVEL)];
  level1 = level2[(num >> (LOG2_NODES_PER_LEVEL+LOG2_NODES_PER_LEVEL)) & (NODES_PER_LEVEL - 1)];
  leaf = level1[(num >> LOG2_NODES_PER_LEVEL) & (NODES_PER_LEVEL - 1)];
  return &leaf[LEAF_INDEX(num)];
}

/* recursively frees a frame_data radix level */
static void
free_frame_data_array(void *array, guint count, guint level, gboolean last)
{
  guint i, level_count;

  if (last) {
    /* if we are the last in our given parent's row, we may not have
     * exactly a full row, so do the bit twiddling to figure out exactly
     * how many fields we have */
    level_count = (count >> ((level - 1) * LOG2_NODES_PER_LEVEL)) &
                  (NODES_PER_LEVEL - 1);
    /* the above calculation rounds down, so make sure we count correctly
     * if count is not an even multiple of NODES_PER_LEVEL */
    if (count & ((1 << ((level - 1) * LOG2_NODES_PER_LEVEL)) - 1)) {
      level_count++;
    }
  }
  else {
    /* if we're not the last in our parent, then we're guaranteed to have
     * a full array */
    level_count = NODES_PER_LEVEL;
  }


  if (level > 1) {
    /* recurse on every sub-array, passing on our own 'last' value
     * specially to our last child */
    frame_data **real_array = (frame_data **) array;

    for (i=0; i < level_count-1; i++) {
      free_frame_data_array(real_array[i], count, level-1, FALSE);
    }

    free_frame_data_array(real_array[level_count-1], count, level-1, last);
  }
  else if (level == 1) {
    /* bottom level, so just clean up all the frame data */
    frame_data *real_array = (frame_data *) array;

    for (i=0; i < level_count; i++) {
      frame_data_destroy(&real_array[i]);
    }
  }

  /* free the array itself */
  g_free(array);
}

/*
 * Free a frame_data_sequence and all the frame_data structures in it.
 */
void
free_frame_data_sequence(frame_data_sequence *fds)
{
  guint32 count  = fds->count;
  guint   levels = 0;

  /* calculate how many levels we have */
  while (count) {
    levels++;
    count >>= LOG2_NODES_PER_LEVEL;
  }

  /* call the recursive free function */
  if (levels > 0) {
    free_frame_data_array(fds->ptree_root, fds->count, levels, TRUE);
  }

  /* free the header struct */
  g_free(fds);
}

void
find_and_mark_frame_depended_upon(gpointer data, gpointer user_data)
{
  frame_data   *dependent_fd;
  guint32       dependent_frame = GPOINTER_TO_UINT(data);
  frame_data_sequence *frames   = (frame_data_sequence *)user_data;

  if (dependent_frame && frames) {
    dependent_fd = frame_data_sequence_find(frames, dependent_frame);
    dependent_fd->flags.dependent_of_displayed = 1;
  }
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
