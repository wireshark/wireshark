/* GTK - The GIMP Toolkit
 * Copyright (C) 1995-1997 Peter Mattis, Spencer Kimball, Josh MacDonald
 * Copyright (C) 1997-1998 Jay Painter <jpaint@serv.net><jpaint@gimp.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/*
 * Modified by the GTK+ Team and others 1997-1999.  See the AUTHORS
 * file for a list of people on the GTK+ Team.  See the ChangeLog
 * files for a list of changes.  These files are distributed with
 * GTK+ at ftp://ftp.gtk.org/pub/gtk/.
 */

#ifndef __ETH_CLIST_H__
#define __ETH_CLIST_H__

#include <gdk/gdk.h>
#include <gtk/gtksignal.h>
#include <gtk/gtkalignment.h>
#include <gtk/gtklabel.h>
#include <gtk/gtkbutton.h>
#include <gtk/gtkhscrollbar.h>
#include <gtk/gtkvscrollbar.h>
#include <gtk/gtkenums.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* clist flags */
enum {
  ETH_CLIST_IN_DRAG             = 1 <<  0,
  ETH_CLIST_ROW_HEIGHT_SET      = 1 <<  1,
  ETH_CLIST_SHOW_TITLES         = 1 <<  2,
  ETH_CLIST_CHILD_HAS_FOCUS     = 1 <<  3,
  ETH_CLIST_ADD_MODE            = 1 <<  4,
  ETH_CLIST_AUTO_SORT           = 1 <<  5,
  ETH_CLIST_AUTO_RESIZE_BLOCKED = 1 <<  6,
  ETH_CLIST_REORDERABLE         = 1 <<  7,
  ETH_CLIST_USE_DRAG_ICONS      = 1 <<  8,
  ETH_CLIST_DRAW_DRAG_LINE      = 1 <<  9,
  ETH_CLIST_DRAW_DRAG_RECT      = 1 << 10
};

/* cell types */
typedef enum
{
  ETH_CELL_EMPTY,
  ETH_CELL_TEXT,
  ETH_CELL_PIXMAP,
  ETH_CELL_PIXTEXT,
  ETH_CELL_WIDGET
} EthCellType;

typedef enum
{
  ETH_CLIST_DRAG_NONE,
  ETH_CLIST_DRAG_BEFORE,
  ETH_CLIST_DRAG_INTO,
  ETH_CLIST_DRAG_AFTER
} EthCListDragPos;

typedef enum
{
  ETH_BUTTON_IGNORED = 0,
  ETH_BUTTON_SELECTS = 1 << 0,
  ETH_BUTTON_DRAGS   = 1 << 1,
  ETH_BUTTON_EXPANDS = 1 << 2
} EthButtonAction;

#define ETH_TYPE_CLIST            (eth_clist_get_type ())
#define ETH_CLIST(obj)            (GTK_CHECK_CAST ((obj), ETH_TYPE_CLIST, EthCList))
#define ETH_CLIST_CLASS(klass)    (GTK_CHECK_CLASS_CAST ((klass), ETH_TYPE_CLIST, EthCListClass))
#define ETH_IS_CLIST(obj)         (GTK_CHECK_TYPE ((obj), ETH_TYPE_CLIST))
#define ETH_IS_CLIST_CLASS(klass) (GTK_CHECK_CLASS_TYPE ((klass), ETH_TYPE_CLIST))

#define ETH_CLIST_FLAGS(clist)             (ETH_CLIST (clist)->flags)
#define ETH_CLIST_SET_FLAG(clist,flag)     (ETH_CLIST_FLAGS (clist) |= (ETH_ ## flag))
#define ETH_CLIST_UNSET_FLAG(clist,flag)   (ETH_CLIST_FLAGS (clist) &= ~(ETH_ ## flag))

#define ETH_CLIST_IN_DRAG(clist)           (ETH_CLIST_FLAGS (clist) & ETH_CLIST_IN_DRAG)
#define ETH_CLIST_ROW_HEIGHT_SET(clist)    (ETH_CLIST_FLAGS (clist) & ETH_CLIST_ROW_HEIGHT_SET)
#define ETH_CLIST_SHOW_TITLES(clist)       (ETH_CLIST_FLAGS (clist) & ETH_CLIST_SHOW_TITLES)
#define ETH_CLIST_CHILD_HAS_FOCUS(clist)   (ETH_CLIST_FLAGS (clist) & ETH_CLIST_CHILD_HAS_FOCUS)
#define ETH_CLIST_ADD_MODE(clist)          (ETH_CLIST_FLAGS (clist) & ETH_CLIST_ADD_MODE)
#define ETH_CLIST_AUTO_SORT(clist)         (ETH_CLIST_FLAGS (clist) & ETH_CLIST_AUTO_SORT)
#define ETH_CLIST_AUTO_RESIZE_BLOCKED(clist) (ETH_CLIST_FLAGS (clist) & ETH_CLIST_AUTO_RESIZE_BLOCKED)
#define ETH_CLIST_REORDERABLE(clist)       (ETH_CLIST_FLAGS (clist) & ETH_CLIST_REORDERABLE)
#define ETH_CLIST_USE_DRAG_ICONS(clist)    (ETH_CLIST_FLAGS (clist) & ETH_CLIST_USE_DRAG_ICONS)
#define ETH_CLIST_DRAW_DRAG_LINE(clist)    (ETH_CLIST_FLAGS (clist) & ETH_CLIST_DRAW_DRAG_LINE)
#define ETH_CLIST_DRAW_DRAG_RECT(clist)    (ETH_CLIST_FLAGS (clist) & ETH_CLIST_DRAW_DRAG_RECT)

#define ETH_CLIST_ROW(_glist_) ((EthCListRow *)((_glist_)->data))

/* pointer casting for cells */
#define ETH_CELL_TEXT(cell)     (((EthCellText *) &(cell)))
#define ETH_CELL_PIXMAP(cell)   (((EthCellPixmap *) &(cell)))
#define ETH_CELL_PIXTEXT(cell)  (((EthCellPixText *) &(cell)))
#define ETH_CELL_WIDGET(cell)   (((EthCellWidget *) &(cell)))

typedef struct _EthCList EthCList;
typedef struct _EthCListClass EthCListClass;
typedef struct _EthCListColumn EthCListColumn;
typedef struct _EthCListRow EthCListRow;

typedef struct _EthCell EthCell;
typedef struct _EthCellText EthCellText;
typedef struct _EthCellPixmap EthCellPixmap;
typedef struct _EthCellPixText EthCellPixText;
typedef struct _EthCellWidget EthCellWidget;

typedef gint (*EthCListCompareFunc) (EthCList     *clist,
				     gconstpointer ptr1,
				     gconstpointer ptr2);

typedef struct _EthCListCellInfo EthCListCellInfo;
typedef struct _EthCListDestInfo EthCListDestInfo;

struct _EthCListCellInfo
{
  gint row;
  gint column;
};

struct _EthCListDestInfo
{
  EthCListCellInfo cell;
  EthCListDragPos  insert_pos;
};

struct _EthCList
{
  GtkContainer container;

  guint16 flags;

  /* mem chunks */
  GMemChunk *row_mem_chunk;
  GMemChunk *cell_mem_chunk;

  guint freeze_count;

  /* allocation rectangle after the conatiner_border_width
   * and the width of the shadow border */
  GdkRectangle internal_allocation;

  /* rows */
  gint rows;
  gint row_center_offset;
  gint row_height;
  GList *row_list;
  GList *row_list_end;

  /* columns */
  gint columns;
  GdkRectangle column_title_area;
  GdkWindow *title_window;

  /* dynamicly allocated array of column structures */
  EthCListColumn *column;

  /* the scrolling window and its height and width to
   * make things a little speedier */
  GdkWindow *clist_window;
  gint clist_window_width;
  gint clist_window_height;

  /* offsets for scrolling */
  gint hoffset;
  gint voffset;

  /* border shadow style */
  GtkShadowType shadow_type;

  /* the list's selection mode (gtkenums.h) */
  GtkSelectionMode selection_mode;

  /* list of selected rows */
  GList *selection;
  GList *selection_end;

  GList *undo_selection;
  GList *undo_unselection;
  gint undo_anchor;

  /* mouse buttons */
  guint8 button_actions[5];

  guint8 drag_button;

  /* dnd */
  EthCListCellInfo click_cell;

  /* scroll adjustments */
  GtkAdjustment *hadjustment;
  GtkAdjustment *vadjustment;

  /* xor GC for the vertical drag line */
  GdkGC *xor_gc;

  /* gc for drawing unselected cells */
  GdkGC *fg_gc;
  GdkGC *bg_gc;

  /* cursor used to indicate dragging */
  GdkCursor *cursor_drag;

  /* the current x-pixel location of the xor-drag line */
  gint x_drag;

  /* focus handling */
  gint focus_row;

  /* dragging the selection */
  gint anchor;
  GtkStateType anchor_state;
  gint drag_pos;
  gint htimer;
  gint vtimer;

  GtkSortType sort_type;
  EthCListCompareFunc compare;
  gint sort_column;
};

struct _EthCListClass
{
  GtkContainerClass parent_class;

  void  (*set_scroll_adjustments) (EthCList       *clist,
				   GtkAdjustment  *hadjustment,
				   GtkAdjustment  *vadjustment);
  void   (*refresh)             (EthCList       *clist);
  void   (*select_row)          (EthCList       *clist,
				 gint            row,
				 gint            column,
				 GdkEvent       *event);
  void   (*unselect_row)        (EthCList       *clist,
				 gint            row,
				 gint            column,
				 GdkEvent       *event);
  void   (*row_move)            (EthCList       *clist,
				 gint            source_row,
				 gint            dest_row);
  void   (*click_column)        (EthCList       *clist,
				 gint            column);
  void   (*resize_column)       (EthCList       *clist,
				 gint            column,
                                 gint            width);
  void   (*toggle_focus_row)    (EthCList       *clist);
  void   (*select_all)          (EthCList       *clist);
  void   (*unselect_all)        (EthCList       *clist);
  void   (*undo_selection)      (EthCList       *clist);
  void   (*start_selection)     (EthCList       *clist);
  void   (*end_selection)       (EthCList       *clist);
  void   (*extend_selection)    (EthCList       *clist,
				 GtkScrollType   scroll_type,
				 gfloat          position,
				 gboolean        auto_start_selection);
  void   (*scroll_horizontal)   (EthCList       *clist,
				 GtkScrollType   scroll_type,
				 gfloat          position);
  void   (*scroll_vertical)     (EthCList       *clist,
				 GtkScrollType   scroll_type,
				 gfloat          position);
  void   (*toggle_add_mode)     (EthCList       *clist);
  void   (*abort_column_resize) (EthCList       *clist);
  void   (*resync_selection)    (EthCList       *clist,
				 GdkEvent       *event);
  GList* (*selection_find)      (EthCList       *clist,
				 gint            row_number,
				 GList          *row_list_element);
  void   (*draw_row)            (EthCList       *clist,
				 GdkRectangle   *area,
				 gint            row,
				 EthCListRow    *clist_row);
  void   (*draw_drag_highlight) (EthCList        *clist,
				 EthCListRow     *target_row,
				 gint             target_row_number,
				 EthCListDragPos  drag_pos);
  void   (*clear)               (EthCList       *clist);
  void   (*fake_unselect_all)   (EthCList       *clist,
				 gint            row);
  void   (*sort_list)           (EthCList       *clist);
  gint   (*insert_row)          (EthCList       *clist,
				 gint            row,
				 gchar          *text[]);
  void   (*remove_row)          (EthCList       *clist,
				 gint            row);
  void   (*set_cell_contents)   (EthCList       *clist,
				 EthCListRow    *clist_row,
				 gint            column,
				 EthCellType     type,
				 const gchar    *text,
				 guint8          spacing,
				 GdkPixmap      *pixmap,
				 GdkBitmap      *mask);
  void   (*cell_size_request)   (EthCList       *clist,
				 EthCListRow    *clist_row,
				 gint            column,
				 GtkRequisition *requisition);

};

struct _EthCListColumn
{
  gchar *title;
  GdkRectangle area;

  GtkWidget *button;
  GdkWindow *window;

  gint width;
  gint min_width;
  gint max_width;
  GtkJustification justification;

  guint visible        : 1;
  guint width_set      : 1;
  guint resizeable     : 1;
  guint auto_resize    : 1;
  guint button_passive : 1;
};

struct _EthCListRow
{
  EthCell *cell;
  GtkStateType state;

  GdkColor foreground;
  GdkColor background;

  GtkStyle *style;

  gpointer data;
  GtkDestroyNotify destroy;

  guint fg_set     : 1;
  guint bg_set     : 1;
  guint selectable : 1;
};

/* Cell Structures */
struct _EthCellText
{
  EthCellType type;

  gint16 vertical;
  gint16 horizontal;

  GtkStyle *style;

  gchar *text;
};

struct _EthCellPixmap
{
  EthCellType type;

  gint16 vertical;
  gint16 horizontal;

  GtkStyle *style;

  GdkPixmap *pixmap;
  GdkBitmap *mask;
};

struct _EthCellPixText
{
  EthCellType type;

  gint16 vertical;
  gint16 horizontal;

  GtkStyle *style;

  gchar *text;
  guint8 spacing;
  GdkPixmap *pixmap;
  GdkBitmap *mask;
};

struct _EthCellWidget
{
  EthCellType type;

  gint16 vertical;
  gint16 horizontal;

  GtkStyle *style;

  GtkWidget *widget;
};

struct _EthCell
{
  EthCellType type;

  gint16 vertical;
  gint16 horizontal;

  GtkStyle *style;

  union {
    gchar *text;

    struct {
      GdkPixmap *pixmap;
      GdkBitmap *mask;
    } pm;

    struct {
      gchar *text;
      guint8 spacing;
      GdkPixmap *pixmap;
      GdkBitmap *mask;
    } pt;

    GtkWidget *widget;
  } u;
};

GtkType eth_clist_get_type (void);

/* constructors useful for gtk-- wrappers */
void eth_clist_construct (EthCList *clist,
			  gint      columns,
			  gchar    *titles[]);

/* create a new EthCList */
GtkWidget* eth_clist_new             (gint   columns);
GtkWidget* eth_clist_new_with_titles (gint   columns,
				      gchar *titles[]);

/* set adjustments of clist */
void eth_clist_set_hadjustment (EthCList      *clist,
				GtkAdjustment *adjustment);
void eth_clist_set_vadjustment (EthCList      *clist,
				GtkAdjustment *adjustment);

/* get adjustments of clist */
GtkAdjustment* eth_clist_get_hadjustment (EthCList *clist);
GtkAdjustment* eth_clist_get_vadjustment (EthCList *clist);

/* set the border style of the clist */
void eth_clist_set_shadow_type (EthCList      *clist,
				GtkShadowType  type);

/* set the clist's selection mode */
void eth_clist_set_selection_mode (EthCList         *clist,
				   GtkSelectionMode  mode);

/* enable clists reorder ability */
void eth_clist_set_reorderable (EthCList *clist,
				gboolean  reorderable);
void eth_clist_set_use_drag_icons (EthCList *clist,
				   gboolean  use_icons);
void eth_clist_set_button_actions (EthCList *clist,
				   guint     button,
				   guint8    button_actions);

/* freeze all visual updates of the list, and then thaw the list after
 * you have made a number of changes and the updates wil occure in a
 * more efficent mannor than if you made them on a unfrozen list
 */
void eth_clist_freeze (EthCList *clist);
void eth_clist_thaw   (EthCList *clist);

/* show and hide the column title buttons */
void eth_clist_column_titles_show (EthCList *clist);
void eth_clist_column_titles_hide (EthCList *clist);

/* set the column title to be a active title (responds to button presses,
 * prelights, and grabs keyboard focus), or passive where it acts as just
 * a title
 */
void eth_clist_column_title_active   (EthCList *clist,
				      gint      column);
void eth_clist_column_title_passive  (EthCList *clist,
				      gint      column);
void eth_clist_column_titles_active  (EthCList *clist);
void eth_clist_column_titles_passive (EthCList *clist);

/* set the title in the column title button */
void eth_clist_set_column_title (EthCList    *clist,
				 gint         column,
				 const gchar *title);

/* returns the title of column. Returns NULL if title is not set */
gchar * eth_clist_get_column_title (EthCList *clist,
				    gint      column);

/* set a widget instead of a title for the column title button */
void eth_clist_set_column_widget (EthCList  *clist,
				  gint       column,
				  GtkWidget *widget);

/* returns the column widget */
GtkWidget * eth_clist_get_column_widget (EthCList *clist,
					 gint      column);

/* set the justification on a column */
void eth_clist_set_column_justification (EthCList         *clist,
					 gint              column,
					 GtkJustification  justification);

/* set visibility of a column */
void eth_clist_set_column_visibility (EthCList *clist,
				      gint      column,
				      gboolean  visible);

/* enable/disable column resize operations by mouse */
void eth_clist_set_column_resizeable (EthCList *clist,
				      gint      column,
				      gboolean  resizeable);

/* resize column automatically to its optimal width */
void eth_clist_set_column_auto_resize (EthCList *clist,
				       gint      column,
				       gboolean  auto_resize);

gint eth_clist_columns_autosize (EthCList *clist);

/* return the optimal column width, i.e. maximum of all cell widths */
gint eth_clist_optimal_column_width (EthCList *clist,
				     gint      column);

/* set the pixel width of a column; this is a necessary step in
 * creating a CList because otherwise the column width is chozen from
 * the width of the column title, which will never be right
 */
void eth_clist_set_column_width (EthCList *clist,
				 gint      column,
				 gint      width);

/* set column minimum/maximum width. min/max_width < 0 => no restriction */
void eth_clist_set_column_min_width (EthCList *clist,
				     gint      column,
				     gint      min_width);
void eth_clist_set_column_max_width (EthCList *clist,
				     gint      column,
				     gint      max_width);

/* change the height of the rows, the default (height=0) is
 * the hight of the current font.
 */
void eth_clist_set_row_height (EthCList *clist,
			       guint     height);

/* scroll the viewing area of the list to the given column and row;
 * row_align and col_align are between 0-1 representing the location the
 * row should appear on the screnn, 0.0 being top or left, 1.0 being
 * bottom or right; if row or column is -1 then then there is no change
 */
void eth_clist_moveto (EthCList *clist,
		       gint      row,
		       gint      column,
		       gfloat    row_align,
		       gfloat    col_align);

/* returns whether the row is visible */
GtkVisibility eth_clist_row_is_visible (EthCList *clist,
					gint      row);

/* returns the cell type */
EthCellType eth_clist_get_cell_type (EthCList *clist,
				     gint      row,
				     gint      column);

/* sets a given cell's text, replacing its current contents */
void eth_clist_set_text (EthCList    *clist,
			 gint         row,
			 gint         column,
			 const gchar *text);

/* for the "get" functions, any of the return pointer can be
 * NULL if you are not interested
 */
gint eth_clist_get_text (EthCList  *clist,
			 gint       row,
			 gint       column,
			 gchar    **text);

/* sets a given cell's pixmap, replacing its current contents */
void eth_clist_set_pixmap (EthCList  *clist,
			   gint       row,
			   gint       column,
			   GdkPixmap *pixmap,
			   GdkBitmap *mask);

gint eth_clist_get_pixmap (EthCList   *clist,
			   gint        row,
			   gint        column,
			   GdkPixmap **pixmap,
			   GdkBitmap **mask);

/* sets a given cell's pixmap and text, replacing its current contents */
void eth_clist_set_pixtext (EthCList    *clist,
			    gint         row,
			    gint         column,
			    const gchar *text,
			    guint8       spacing,
			    GdkPixmap   *pixmap,
			    GdkBitmap   *mask);

gint eth_clist_get_pixtext (EthCList   *clist,
			    gint        row,
			    gint        column,
			    gchar     **text,
			    guint8     *spacing,
			    GdkPixmap **pixmap,
			    GdkBitmap **mask);

/* sets the foreground color of a row, the color must already
 * be allocated
 */
void eth_clist_set_foreground (EthCList *clist,
			       gint      row,
			       GdkColor *color);

/* sets the background color of a row, the color must already
 * be allocated
 */
void eth_clist_set_background (EthCList *clist,
			       gint      row,
			       GdkColor *color);

/* set / get cell styles */
void eth_clist_set_cell_style (EthCList *clist,
			       gint      row,
			       gint      column,
			       GtkStyle *style);

GtkStyle *eth_clist_get_cell_style (EthCList *clist,
				    gint      row,
				    gint      column);

void eth_clist_set_row_style (EthCList *clist,
			      gint      row,
			      GtkStyle *style);

GtkStyle *eth_clist_get_row_style (EthCList *clist,
				   gint      row);

/* this sets a horizontal and vertical shift for drawing
 * the contents of a cell; it can be positive or negitive;
 * this is particulary useful for indenting items in a column
 */
void eth_clist_set_shift (EthCList *clist,
			  gint      row,
			  gint      column,
			  gint      vertical,
			  gint      horizontal);

/* set/get selectable flag of a single row */
void eth_clist_set_selectable (EthCList *clist,
			       gint      row,
			       gboolean  selectable);
gboolean eth_clist_get_selectable (EthCList *clist,
				   gint      row);

/* prepend/append returns the index of the row you just added,
 * making it easier to append and modify a row
 */
gint eth_clist_prepend (EthCList    *clist,
		        gchar       *text[]);
gint eth_clist_append  (EthCList    *clist,
			gchar       *text[]);

/* inserts a row at index row and returns the row where it was
 * actually inserted (may be different from "row" in auto_sort mode)
 */
gint eth_clist_insert (EthCList    *clist,
		       gint         row,
		       gchar       *text[]);

/* removes row at index row */
void eth_clist_remove (EthCList *clist,
		       gint      row);

/* sets a arbitrary data pointer for a given row */
void eth_clist_set_row_data (EthCList *clist,
			     gint      row,
			     gpointer  data);

/* sets a data pointer for a given row with destroy notification */
void eth_clist_set_row_data_full (EthCList         *clist,
			          gint              row,
			          gpointer          data,
				  GtkDestroyNotify  destroy);

/* returns the data set for a row */
gpointer eth_clist_get_row_data (EthCList *clist,
				 gint      row);

/* givin a data pointer, find the first (and hopefully only!)
 * row that points to that data, or -1 if none do
 */
gint eth_clist_find_row_from_data (EthCList *clist,
				   gpointer  data);

/* force selection of a row */
void eth_clist_select_row (EthCList *clist,
			   gint      row,
			   gint      column);

/* force unselection of a row */
void eth_clist_unselect_row (EthCList *clist,
			     gint      row,
			     gint      column);

/* undo the last select/unselect operation */
void eth_clist_undo_selection (EthCList *clist);

/* clear the entire list -- this is much faster than removing
 * each item with eth_clist_remove
 */
void eth_clist_clear (EthCList *clist);

/* return the row column corresponding to the x and y coordinates,
 * the returned values are only valid if the x and y coordinates
 * are respectively to a window == clist->clist_window
 */
gint eth_clist_get_selection_info (EthCList *clist,
			     	   gint      x,
			     	   gint      y,
			     	   gint     *row,
			     	   gint     *column);

/* in multiple or extended mode, select all rows */
void eth_clist_select_all (EthCList *clist);

/* in all modes except browse mode, deselect all rows */
void eth_clist_unselect_all (EthCList *clist);

/* swap the position of two rows */
void eth_clist_swap_rows (EthCList *clist,
			  gint      row1,
			  gint      row2);

/* move row from source_row position to dest_row position */
void eth_clist_row_move (EthCList *clist,
			 gint      source_row,
			 gint      dest_row);

/* sets a compare function different to the default */
void eth_clist_set_compare_func (EthCList            *clist,
				 EthCListCompareFunc  cmp_func);

/* the column to sort by */
void eth_clist_set_sort_column (EthCList *clist,
				gint      column);

/* how to sort : ascending or descending */
void eth_clist_set_sort_type (EthCList    *clist,
			      GtkSortType  sort_type);

/* sort the list with the current compare function */
void eth_clist_sort (EthCList *clist);

/* Automatically sort upon insertion */
void eth_clist_set_auto_sort (EthCList *clist,
			      gboolean  auto_sort);


#ifdef __cplusplus
}
#endif				/* __cplusplus */

#endif				/* __ETH_CLIST_H__ */
