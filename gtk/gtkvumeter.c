/***************************************************************************
 *            gtkvumeter.c
 *
 * $Id$
 *
 *
 *  Fri Jan 10 20:06:23 2003
 *  Copyright  2003  Todd Goyen
 *  wettoad@knighthoodofbuh.org
 *
 *  Mon May 01 04:04:00 2006
 *  Copyright  2006  Ulf Lamping
 *  ulf.lamping@web.de
 *
 *  Source code is LGPL'd,
 *  but may be distributed under any other open source license
 ****************************************************************************/

#if defined(GDK_DISABLE_DEPRECATED)
# undef GDK_DISABLE_DEPRECATED
#endif

#include <math.h>
#include <gtk/gtk.h>
#include "gtk/gtkvumeter.h"

#include "gtk/old-gtk-compat.h"

#define MIN_DYNAMIC_SIDE    40

#define SMALL_PITCH_LINE    2
#define LARGE_PITCH_LINE    4

#define SPARE_LEFT          1
#define SPARE_RIGHT         1
#define SPARE_TOP           1
#define SPARE_BOTTOM        1


static void gtk_vumeter_init (GtkVUMeter *vumeter);
static void gtk_vumeter_class_init (GtkVUMeterClass *class);
static void gtk_vumeter_destroy (GtkObject *object);
static void gtk_vumeter_realize (GtkWidget *widget);
static void gtk_vumeter_size_calculate (GtkWidget *widget, GtkRequisition *requisition);
static void gtk_vumeter_size_request (GtkWidget *widget, GtkRequisition *requisition);
static void gtk_vumeter_size_allocate (GtkWidget *widget, GtkAllocation *allocation);
static gboolean gtk_vumeter_expose (GtkWidget *widget, GdkEventExpose *event);
static void gtk_vumeter_free_colors (GtkVUMeter *vumeter);
static void gtk_vumeter_setup_colors (GtkVUMeter *vumeter);
static gint gtk_vumeter_sound_level_to_draw_level (GtkVUMeter *vumeter, gint sound_level);
static gboolean gtk_vumeter_redraw_timeout (gpointer data);
static void gtk_vumeter_setup_scale_items(GtkVUMeter *vumeter, GList *scale_items);

static GtkWidgetClass *parent_class = NULL;

GType gtk_vumeter_get_type (void)
{
    static GType vumeter_type = 0;

    if (!vumeter_type) {
        static const GTypeInfo vumeter_info = {
            sizeof (GtkVUMeterClass),
            NULL, NULL,
            (GClassInitFunc) gtk_vumeter_class_init, NULL, NULL,
            sizeof (GtkVUMeter), 0, (GInstanceInitFunc) gtk_vumeter_init,
            NULL
        };
        vumeter_type = g_type_register_static (GTK_TYPE_WIDGET, "GtkVUMeter", &vumeter_info, 0);
    }

    return vumeter_type;
}

/**
 * gtk_vumeter_new:
 *
 * Creates a new VUMeter widget.
 */
GtkWidget* gtk_vumeter_new (void)
{
    GtkVUMeter *vumeter;

    vumeter = GTK_VUMETER (g_object_new (GTK_TYPE_VUMETER, NULL));

    return GTK_WIDGET (vumeter);
}

static void gtk_vumeter_init (GtkVUMeter *vumeter)
{
    vumeter->vertical = TRUE;
    vumeter->scale_inverted = FALSE;
    vumeter->thickness = 30;
    vumeter->reduced_thickness = 0;
    vumeter->scaling = GTK_VUMETER_SCALING_LINEAR;
    vumeter->scale_items = NULL;
    vumeter->scale_pitch_holes = 0;

    vumeter->padding_left = 1;
    vumeter->padding_right = 1;
    vumeter->padding_top = 1;
    vumeter->padding_bottom = 1;

    vumeter->colormap = NULL;
    vumeter->colors = 0;
    vumeter->f_gc = NULL;
    vumeter->b_gc = NULL;
    vumeter->f_colors = NULL;
    vumeter->b_colors = NULL;
    vumeter->f_brightness = 65535;
    vumeter->b_brightness = 49151;
    vumeter->yellow_level = 16383;
    vumeter->colors_inverted = FALSE;

    vumeter->level = 0;
    vumeter->level_min = 0;
    vumeter->level_max = 32767;

    vumeter->peak = FALSE;
    vumeter->peak_level = 0;
    vumeter->peak_timeout = 0;
    vumeter->peak_hold_factor = 0;
    vumeter->peak_hold = 0;
    vumeter->peak_falloff_mode = GTK_VUMETER_PEAK_FALLOFF_MEDIUM;
    vumeter->peak_falloff_rate = 3278;
}

static void gtk_vumeter_class_init (GtkVUMeterClass *class)
{
    GtkObjectClass *object_class;
    GtkWidgetClass *widget_class;

    object_class = (GtkObjectClass*) class;
    widget_class = (GtkWidgetClass*) class;
    parent_class = g_type_class_ref (gtk_widget_get_type ());

    object_class->destroy = gtk_vumeter_destroy;

    widget_class->realize = gtk_vumeter_realize;
    widget_class->expose_event = gtk_vumeter_expose;
    widget_class->size_request = gtk_vumeter_size_request;
    widget_class->size_allocate = gtk_vumeter_size_allocate;
}

static void gtk_vumeter_destroy (GtkObject *object)
{
    GtkVUMeter *vumeter = GTK_VUMETER (object);

    if(vumeter->peak_timeout) {
        g_source_remove(vumeter->peak_timeout);
    }

    gtk_vumeter_free_colors (vumeter);

    GTK_OBJECT_CLASS (parent_class)->destroy (object);
}

static void gtk_vumeter_realize (GtkWidget *widget)
{
    GtkVUMeter *vumeter;
    GdkWindowAttr attributes;
    gint attributes_mask;
    GtkAllocation widget_alloc;

    g_return_if_fail (widget != NULL);
    g_return_if_fail (GTK_IS_VUMETER (widget));

#if GTK_CHECK_VERSION(2,20,0)
    gtk_widget_set_realized(widget, TRUE);
#else
    GTK_WIDGET_SET_FLAGS (widget, GTK_REALIZED);
#endif
    vumeter = GTK_VUMETER (widget);

#if GTK_CHECK_VERSION(2,18,0)
    gtk_widget_get_allocation(widget, &widget_alloc);
#else
    widget_alloc = widget->allocation;
#endif

    attributes.x = widget_alloc.x;
    attributes.y = widget_alloc.y;
    attributes.width = widget_alloc.width;
    attributes.height = widget_alloc.height;
    attributes.wclass = GDK_INPUT_OUTPUT;
    attributes.window_type = GDK_WINDOW_CHILD;
    attributes.event_mask = gtk_widget_get_events (widget) | GDK_EXPOSURE_MASK;
    attributes.visual = gtk_widget_get_visual (widget);
    attributes.colormap = gtk_widget_get_colormap (widget);
    attributes_mask = GDK_WA_X | GDK_WA_Y | GDK_WA_VISUAL | GDK_WA_COLORMAP;
#if GTK_CHECK_VERSION(2,18,0)
    gtk_widget_set_window(widget, gdk_window_new(gtk_widget_get_parent_window(widget), &attributes, attributes_mask));
#else
    widget->window = gdk_window_new (widget->parent->window, &attributes, attributes_mask);
#endif

    gtk_widget_set_style(widget, gtk_style_attach(gtk_widget_get_style(widget), gtk_widget_get_window(widget)));

    gdk_window_set_user_data (gtk_widget_get_window(widget), widget);
    gtk_style_set_background (gtk_widget_get_style(widget), gtk_widget_get_window(widget),  GTK_STATE_NORMAL);

    /* colors */
    vumeter->colormap = gdk_colormap_get_system ();
    gtk_vumeter_setup_colors (vumeter);
}

static void gtk_vumeter_size_calculate (GtkWidget *widget, GtkRequisition *requisition)
{
    GtkVUMeter *vumeter;
    gint max_x = 0;
    gint max_y = 0;
    gint layout_width;
    gint layout_height;
    gint pitches = 0;
    GList * current;

    g_return_if_fail (GTK_IS_VUMETER (widget));
    g_return_if_fail (requisition != NULL);

    vumeter = GTK_VUMETER (widget);

    if(vumeter->scale_items != NULL) {
        /* iterate through scale items to get the highest scale item */
        for (current = vumeter->scale_items; current != NULL; current = g_list_next(current)) {
            GtkVUMeterScaleItem * item = current->data;

            pitches++;

            if(item->label) {
                PangoLayout * layout = gtk_widget_create_pango_layout (widget, item->label);
                pango_layout_get_pixel_size(layout, &layout_width, &layout_height);
                /* XXX - memleak */
            } else {
                layout_width = 0;
                layout_height = 0;
            }

            if (vumeter->vertical == TRUE) {
                max_x = MAX(max_x, item->large ? LARGE_PITCH_LINE : SMALL_PITCH_LINE);
                max_y = MAX(max_y, 1);
                if(item->label) {
                    max_x = MAX(max_x, LARGE_PITCH_LINE+3+layout_width);
                    max_y = MAX(max_y, layout_height);
                }
            } else {
                max_x = MAX(max_x, 1);
                max_y = MAX(max_y, item->large ? LARGE_PITCH_LINE : SMALL_PITCH_LINE);
                if(item->label) {
                    max_x = MAX(max_x, layout_width);
                    max_y = MAX(max_y, LARGE_PITCH_LINE+/*3+*/layout_height-2);
                }
            }
        }
    }

    pitches = MAX((vumeter->scale_pitch_holes+1)*pitches-1, MIN_DYNAMIC_SIDE);

    if (vumeter->vertical == TRUE) {
        vumeter->padding_left = SPARE_LEFT;
        vumeter->padding_right = SPARE_RIGHT + max_x;
        vumeter->padding_top = SPARE_TOP + max_y / 2;
        vumeter->padding_bottom = SPARE_BOTTOM + max_y / 2;
        requisition->width = vumeter->padding_left + vumeter->thickness + vumeter->padding_right;
        requisition->height = vumeter->padding_top + pitches + vumeter->padding_bottom;
    } else {
        vumeter->padding_left = SPARE_LEFT + max_x / 2;
        vumeter->padding_right = SPARE_RIGHT + max_x / 2;
        vumeter->padding_top = SPARE_TOP;
        vumeter->padding_bottom = SPARE_BOTTOM + max_y;
        requisition->width = vumeter->padding_left + pitches + vumeter->padding_right;
        requisition->height = vumeter->padding_top + vumeter->thickness + vumeter->padding_bottom;
    }
}

static void gtk_vumeter_size_request (GtkWidget *widget, GtkRequisition *requisition)
{
    gtk_vumeter_size_calculate(widget, requisition);
}

static void gtk_vumeter_size_allocate (GtkWidget *widget, GtkAllocation *allocation)
{
    GtkVUMeter *vumeter;
    GtkRequisition requisition;

    g_return_if_fail (GTK_IS_VUMETER (widget));
    g_return_if_fail (allocation != NULL);

#if GTK_CHECK_VERSION(2,18,0)
    gtk_widget_set_allocation(widget, allocation);
#else
    widget->allocation = *allocation;
#endif
    vumeter = GTK_VUMETER (widget);

    gtk_vumeter_size_calculate(widget, &requisition);

    if (gtk_widget_get_realized(widget)) {
        gdk_window_move_resize (gtk_widget_get_window(widget), allocation->x, allocation->y,
			MAX (allocation->width, requisition.width),
            MAX (allocation->height, requisition.height));

        /* Fix the colours */
        gtk_vumeter_setup_colors (vumeter);
    }
}

static gboolean gtk_vumeter_expose (GtkWidget *widget, GdkEventExpose *event)
{
    GtkVUMeter *vumeter;
    gint index, level, peak_level = 0;
    gint width, height;
    gint w, h, inc;
    GList * current;
    GtkAllocation widget_alloc;
    GdkWindow *widget_window = gtk_widget_get_window(widget);

    g_return_val_if_fail (GTK_IS_VUMETER (widget), FALSE);
    g_return_val_if_fail (event != NULL, FALSE);

    vumeter = GTK_VUMETER (widget);

    level = gtk_vumeter_sound_level_to_draw_level (vumeter, vumeter->level);
    if (vumeter->peak == TRUE) {
        peak_level = gtk_vumeter_sound_level_to_draw_level (vumeter, vumeter->peak_level);
    }

#if GTK_CHECK_VERSION(2,18,0)
    gtk_widget_get_allocation(widget, &widget_alloc);
#else
    widget_alloc = widget->allocation;
#endif

    /* the dimentions of the bar (leaving some space for the scale) */
    width = widget_alloc.width - vumeter->padding_left - vumeter->padding_right;
    height = widget_alloc.height - vumeter->padding_top - vumeter->padding_bottom;

    /* clear widget and draw border */
    gtk_paint_box (gtk_widget_get_style(widget), widget_window, GTK_STATE_NORMAL, GTK_SHADOW_IN,
        NULL, widget, "trough", 0, 0, widget_alloc.width, widget_alloc.height);

#if 0
    /* clear bar only */
    gtk_paint_box (widget->style, widget_window, GTK_STATE_NORMAL, GTK_SHADOW_NONE,
        NULL, widget, "trough", vumeter->padding_left, vumeter->padding_top, width+1, height+1);
#endif

    if (vumeter->vertical == TRUE) {
        if (vumeter->scale_inverted == TRUE) {
            h = height + vumeter->padding_top;
            inc = -1;
        } else {
            h = vumeter->padding_top;
            inc = 1;
        }

        /* draw scale */
        if(vumeter->scale_items != NULL) {
            /* iterate through scale items */
            for (current = vumeter->scale_items; current != NULL; current = g_list_next(current)) {
                GtkVUMeterScaleItem * item = current->data;
                int scale_level = gtk_vumeter_sound_level_to_draw_level (vumeter, item->level);

                /* XXX - use a fixed color for the scale? */
                gdk_draw_line (widget_window, vumeter->b_gc[scale_level],
                    vumeter->padding_left+width, h + inc*scale_level,
                    vumeter->padding_left+width+(item->large==TRUE ? LARGE_PITCH_LINE : SMALL_PITCH_LINE)-1, h + inc*scale_level);

                if(item->label) {
                    int layout_width;
                    int layout_height;
                    PangoLayout * layout = gtk_widget_create_pango_layout (widget, item->label);
                    pango_layout_get_pixel_size(layout, &layout_width, &layout_height);
                    gdk_draw_layout(widget_window,
                                             vumeter->b_gc[scale_level],
                                             vumeter->padding_left+width+vumeter->padding_right-1-layout_width,
                                             h + inc*scale_level - layout_height/2 - 1,
                                             layout);
                }
            }
        }

        /* draw background gradient */
        for (index = 0; index < level; index++, h += inc) {
            gdk_draw_line (widget_window, vumeter->b_gc[index],
                vumeter->padding_left+vumeter->reduced_thickness, h,
                vumeter->padding_left+width-1-vumeter->reduced_thickness, h);
        }
        /* draw foreground gradient */
        for (index = level; index < height; index++, h += inc) {
            gdk_draw_line (widget_window, vumeter->f_gc[index],
                vumeter->padding_left,h,
                vumeter->padding_left+width-1, h);
        }
        /* Draw the peak */
        if (vumeter->peak == TRUE) {
            /* Reset w */
            index = MAX (peak_level - 1, 0);
            for (; index < MIN (peak_level + 1, height - 2); index++) {
                h = vumeter->scale_inverted == TRUE ? height +vumeter->padding_top - (index + 2) : vumeter->padding_top + index + 1;
                gdk_draw_line (widget_window, vumeter->f_gc[index], vumeter->padding_left, h, vumeter->padding_left+width-1, h);
            }
        }
    } else { /* Horizontal */
        /* the start point of the bar */
        if (vumeter->scale_inverted == TRUE) {
            w = width-1 + vumeter->padding_left;
            inc = -1;
        } else {
            w = vumeter->padding_left;
            inc = 1;
        }

        /* draw scale */
        if(vumeter->scale_items != NULL) {
            /* iterate through scale items */
            for (current = vumeter->scale_items; current != NULL; current = g_list_next(current)) {
                GtkVUMeterScaleItem * item = current->data;
                int scale_level = gtk_vumeter_sound_level_to_draw_level (vumeter, item->level);

                /* XXX - use a fixed color for the scale? */
                gdk_draw_line (widget_window, vumeter->b_gc[scale_level],
                    w + inc*scale_level, vumeter->padding_top+height,
                    w + inc*scale_level, vumeter->padding_top+height+(item->large==TRUE ? LARGE_PITCH_LINE : SMALL_PITCH_LINE)-1);

                if(item->label) {
                    int layout_width;
                    int layout_height;
                    PangoLayout * layout = gtk_widget_create_pango_layout (widget, item->label);
                    pango_layout_get_pixel_size(layout, &layout_width, &layout_height);
                    gdk_draw_layout(widget_window, vumeter->b_gc[scale_level],
                                             w + inc*scale_level - layout_width/2,
                                             height + vumeter->padding_top + 3,
                                             layout);
                }
            }
        }

        /* draw background gradient */
        for (index = 0; index < level; index++, w += inc) {
            gdk_draw_line (widget_window, vumeter->b_gc[index],
                w, vumeter->padding_top+vumeter->reduced_thickness,
                w, vumeter->padding_top+height-1-vumeter->reduced_thickness);
        }
        /* draw foreground gradient */
        for (index = level; index < width; index++, w+= inc) {
            gdk_draw_line (widget_window, vumeter->f_gc[index],
                w, vumeter->padding_top,
                w, vumeter->padding_top+height-1);
        }

        /* Draw the peak */
        if (vumeter->peak == TRUE) {
            /* Reset w */
            index = MAX (peak_level - 1, 0);
            w = vumeter->scale_inverted == TRUE ? width + vumeter->padding_left - (index + 1) : vumeter->padding_left + index + 1;
            for (; index <= MIN (peak_level, width - 2); index++, w+= inc) {
                gdk_draw_line (widget_window, vumeter->f_gc[index], w, vumeter->padding_top, w, vumeter->padding_top+height-1);
            }
        }
    }

    return TRUE;
}

static void gtk_vumeter_free_colors (GtkVUMeter *vumeter)
{
    gint index;

    if (vumeter->colors == 0) { return; }

    /* Free old gc's */
    if (vumeter->f_gc && vumeter->b_gc) {
        for (index = 0; index < vumeter->colors; index++) {
            if (vumeter->f_gc[index]) {
                g_object_unref (G_OBJECT(vumeter->f_gc[index]));
            }
            if (vumeter->b_gc[index]) {
                g_object_unref (G_OBJECT(vumeter->b_gc[index]));
            }
        }
        g_free(vumeter->f_gc);
        g_free(vumeter->b_gc);
        vumeter->f_gc = NULL;
        vumeter->b_gc = NULL;
    }

    /* Free old Colors */
    if (vumeter->f_colors) {
        gdk_colormap_free_colors (vumeter->colormap, vumeter->f_colors, vumeter->colors);
        g_free (vumeter->f_colors);
        vumeter->f_colors = NULL;
    }
    if (vumeter->b_colors) {
        gdk_colormap_free_colors (vumeter->colormap, vumeter->b_colors, vumeter->colors);
        g_free (vumeter->b_colors);
        vumeter->b_colors = NULL;
    }
}

static void gtk_vumeter_setup_colors (GtkVUMeter *vumeter)
{
    gint index;
    gint f_step, b_step;
    gint first, second;
    gint max = 0, min = 0, log_max = 0;
    GtkAllocation vumeter_alloc;

    g_return_if_fail (vumeter->colormap != NULL);

    gtk_vumeter_free_colors (vumeter);

#if GTK_CHECK_VERSION(2,18,0)
    gtk_widget_get_allocation(GTK_WIDGET(vumeter), &vumeter_alloc);
#else
    vumeter_alloc = GTK_WIDGET(vumeter)->allocation;
#endif

    /* Set new size */
    if (vumeter->vertical == TRUE) {
        vumeter->colors = MAX(vumeter_alloc.height - vumeter->padding_top - vumeter->padding_bottom, 0);
    } else {
        vumeter->colors = MAX(vumeter_alloc.width - vumeter->padding_left - vumeter->padding_right, 0);
    }

    /* allocate new memory */
    vumeter->f_colors = g_malloc (vumeter->colors * sizeof(GdkColor));
    vumeter->b_colors = g_malloc (vumeter->colors * sizeof(GdkColor));
    vumeter->f_gc = g_malloc (vumeter->colors * sizeof(GdkGC *));
    vumeter->b_gc = g_malloc (vumeter->colors * sizeof(GdkGC *));

    /* Initialize stuff */
    if (vumeter->scaling == GTK_VUMETER_SCALING_LINEAR) {
        first = 1+gtk_vumeter_sound_level_to_draw_level (vumeter, vumeter->yellow_level);
        second = vumeter->colors;
    } else {
        max = vumeter->level_max;
        min = vumeter->level_min;
        log_max = (gint) (- 20.0 * log10(1.0/(max - min + 1.0)));
        first = (gint)((gdouble)vumeter->colors * 6.0 / log_max);
        second = (gint)((gdouble)vumeter->colors * 18.0 / log_max);
    }

    if(vumeter->colors_inverted) {
        vumeter->f_colors[0].red = 0;
        vumeter->f_colors[0].green = vumeter->f_brightness;
        vumeter->f_colors[0].blue = 0;

        vumeter->b_colors[0].red = 0;
        vumeter->b_colors[0].green = vumeter->b_brightness;
        vumeter->b_colors[0].blue = 0;

        /* Allocate from Green to Yellow */
        f_step = vumeter->f_brightness / (first - 1);
        b_step = vumeter->b_brightness / (first - 1);
        for (index = 1; index < first; index++) {
            /* foreground */
            vumeter->f_colors[index].red = vumeter->f_colors[index - 1].red + f_step;
            vumeter->f_colors[index].green = vumeter->f_brightness;
            vumeter->f_colors[index].blue = 0;
            /* background */
            vumeter->b_colors[index].red = vumeter->b_colors[index - 1].red + b_step;
            vumeter->b_colors[index].green = vumeter->b_brightness;
            vumeter->b_colors[index].blue = 0;
        }
        /* Allocate from Yellow to Red */
        if(second != first) {
            f_step = vumeter->f_brightness / (second - first);
            b_step = vumeter->b_brightness / (second - first);
            for (index = first; index < second; index++) {
                /* foreground */
                vumeter->f_colors[index].red = vumeter->f_colors[index - 1].red;
                vumeter->f_colors[index].green = vumeter->f_colors[index - 1].green - f_step;
                vumeter->f_colors[index].blue = 0;
                /* background */
                vumeter->b_colors[index].red = vumeter->b_colors[index - 1].red;
                vumeter->b_colors[index].green = vumeter->b_colors[index - 1].green - b_step;
                vumeter->b_colors[index].blue = 0;
            }
        }
    } else {
        vumeter->f_colors[0].red = vumeter->f_brightness;
        vumeter->f_colors[0].green = 0;
        vumeter->f_colors[0].blue = 0;

        vumeter->b_colors[0].red = vumeter->b_brightness;
        vumeter->b_colors[0].green = 0;
        vumeter->b_colors[0].blue = 0;

        /* Allocate from Red to Yellow */
        f_step = vumeter->f_brightness / MAX(first - 1, 1);
        b_step = vumeter->b_brightness / MAX(first - 1, 1);
        for (index = 1; index < first; index++) {
            /* foreground */
            vumeter->f_colors[index].red = vumeter->f_brightness;
            vumeter->f_colors[index].green = vumeter->f_colors[index - 1].green + f_step;
            vumeter->f_colors[index].blue = 0;
            /* background */
            vumeter->b_colors[index].red = vumeter->b_brightness;
            vumeter->b_colors[index].green = vumeter->b_colors[index - 1].green + b_step;
            vumeter->b_colors[index].blue = 0;
        }
        /* Allocate from Yellow to Green */
        f_step = vumeter->f_brightness / MAX(second - first, 1);
        b_step = vumeter->b_brightness / MAX(second - first, 1);
        for (index = first; index < second; index++) {
            /* foreground */
            vumeter->f_colors[index].red = vumeter->f_colors[index - 1].red - f_step;
            vumeter->f_colors[index].green = vumeter->f_colors[index - 1].green;
            vumeter->f_colors[index].blue = 0;
            /* background */
            vumeter->b_colors[index].red = vumeter->b_colors[index - 1].red - b_step;
            vumeter->b_colors[index].green = vumeter->b_colors[index - 1].green;
            vumeter->b_colors[index].blue = 0;
        }
        if (vumeter->scaling == GTK_VUMETER_SCALING_LOG && (vumeter->colors - second) > 0) {
            /* Allocate from Green to Dark Green */
            f_step = vumeter->f_brightness / 2 / (vumeter->colors - second);
            b_step = vumeter->b_brightness / 2 / (vumeter->colors - second);
            for (index = second; index < vumeter->colors; index++) {
                /* foreground */
                vumeter->f_colors[index].red = 0;
                vumeter->f_colors[index].green = vumeter->f_colors[index - 1].green - f_step;
                vumeter->f_colors[index].blue = 0;
                /* background */
                vumeter->b_colors[index].red = 0;
                vumeter->b_colors[index].green = vumeter->b_colors[index - 1].green - b_step;
                vumeter->b_colors[index].blue = 0;
            }
        }
    } /* colors_inverted */

    /* Allocate the Colours */
    for (index = 0; index < vumeter->colors; index++) {
        /* foreground */
        gdk_colormap_alloc_color (vumeter->colormap, &vumeter->f_colors[index], FALSE, TRUE);
        vumeter->f_gc[index] = gdk_gc_new(gtk_widget_get_window(GTK_WIDGET(vumeter)));
        gdk_gc_set_foreground(vumeter->f_gc[index], &vumeter->f_colors[index]);
        /* background */
        gdk_colormap_alloc_color (vumeter->colormap, &vumeter->b_colors[index], FALSE, TRUE);
        vumeter->b_gc[index] = gdk_gc_new(gtk_widget_get_window(GTK_WIDGET(vumeter)));
        gdk_gc_set_foreground(vumeter->b_gc[index], &vumeter->b_colors[index]);
    }
}

static gint gtk_vumeter_sound_level_to_draw_level (GtkVUMeter *vumeter, gint sound_level)
{
    gdouble draw_level;
    gdouble level, min, max, height;
    gdouble log_level, log_max;

    level = (gdouble)sound_level;
    min = (gdouble)vumeter->level_min;
    max = (gdouble)vumeter->level_max;
    height = (gdouble)vumeter->colors;

    if (vumeter->scaling == GTK_VUMETER_SCALING_LINEAR) {
        draw_level = (1.0 - (level - min)/(max - min)) * (height - 1.0);
        /* to avoid rounding problems */
        draw_level += 0.001;
    } else {
        log_level = log10((level - min + 1)/(max - min + 1));
        log_max = log10(1/(max - min + 1));
        draw_level = log_level/log_max * (height - 1.0);
    }

    return ((gint)draw_level);
}

static gboolean gtk_vumeter_redraw_timeout (gpointer data)
{
    GtkVUMeter *vumeter = data;
    /* Immediately return if need be */
    if (!gtk_widget_get_realized (GTK_WIDGET(vumeter))) { return TRUE; }
    if (vumeter->peak == FALSE) { return TRUE; }
    if (vumeter->peak_level == vumeter->level) { return TRUE; }

    if(vumeter->peak_hold != 0) {
        vumeter->peak_hold--;
        return TRUE;
    }

    /* Drop the peak_level by rate */
    vumeter->peak_level -= vumeter->peak_falloff_rate;
    vumeter->peak_level = MAX (vumeter->peak_level, vumeter->level);

    gtk_widget_queue_draw (GTK_WIDGET(vumeter));

    return TRUE;
}

static GList *gtk_vumeter_clone_scale_items(GList *scale_items)
{
    GList * new_list = NULL;


    for ( ; scale_items != NULL; scale_items = g_list_next(scale_items)) {
        GtkVUMeterScaleItem * item = scale_items->data;
        GtkVUMeterScaleItem * new_item;

        new_item = g_malloc(sizeof(GtkVUMeterScaleItem));
        new_item->level = item->level;
        new_item->large = item->large;
        new_item->label = g_strdup(item->label);
        new_list = g_list_append(new_list, new_item);
    }

    return new_list;
}

static void gtk_vumeter_setup_scale_items(GtkVUMeter *vumeter, GList *scale_items)
{
    GList * new_list = NULL;
    GList * new_list_item = NULL;

    /* clone the whole list */
    new_list = gtk_vumeter_clone_scale_items(scale_items);

    /* clamp the levels */
    for (new_list_item = new_list; new_list_item != NULL; new_list_item = g_list_next(new_list_item)) {
        GtkVUMeterScaleItem * item = new_list_item->data;

        item->level = CLAMP(item->level, vumeter->level_min, vumeter->level_max);
    }

    gtk_vumeter_free_scale_items(vumeter->scale_items);
    vumeter->scale_items = new_list;
}

void gtk_vumeter_free_scale_items(GList *scale_items)
{
    GList * current;

    if(scale_items == NULL) return;

    for (current = scale_items; current != NULL; current = g_list_next(current)) {
        GtkVUMeterScaleItem * item = current->data;

        g_free((void *) item->label);
        g_free(item);
    }

    g_list_free(scale_items);
}

/**
 * gtk_vumeter_set_orientation:
 * @param vumeter the vumeter widget
 * @param orientation the direction in which the graph is going for increasing values
 */
void gtk_vumeter_set_orientation (GtkVUMeter *vumeter, GtkVUMeterOrientation orientation)
{
    g_return_if_fail (GTK_IS_VUMETER (vumeter));

    if(orientation == GTK_VUMETER_BOTTOM_TO_TOP || orientation == GTK_VUMETER_TOP_TO_BOTTOM) {
        vumeter->vertical = TRUE;
    } else {
        vumeter->vertical = FALSE;
    }

    if(orientation == GTK_VUMETER_LEFT_TO_RIGHT || orientation == GTK_VUMETER_BOTTOM_TO_TOP) {
        vumeter->scale_inverted = TRUE;
    } else {
        vumeter->scale_inverted = FALSE;
    }

    if (gtk_widget_get_realized (GTK_WIDGET(vumeter))) {
        gtk_widget_queue_draw (GTK_WIDGET (vumeter));
    }
}

/**
 * gtk_vumeter_get_orientation:
 * @param vumeter the vumeter widget
 * @return the direction in which the graph is going for increasing values
 */
GtkVUMeterOrientation gtk_vumeter_get_orientation (GtkVUMeter *vumeter)
{
    if(!GTK_IS_VUMETER (vumeter)) {
        return GTK_VUMETER_BOTTOM_TO_TOP;
    }

    /* XXX - might be faster using a lookup table */
    if(vumeter->vertical == TRUE && vumeter->scale_inverted == TRUE) {
        return GTK_VUMETER_BOTTOM_TO_TOP;
    }

    if(vumeter->vertical == TRUE && vumeter->scale_inverted == FALSE) {
        return GTK_VUMETER_TOP_TO_BOTTOM;
    }

    if(vumeter->vertical == FALSE && vumeter->scale_inverted == TRUE) {
        return GTK_VUMETER_LEFT_TO_RIGHT;
    }

    if(vumeter->vertical == FALSE && vumeter->scale_inverted == FALSE) {
        return GTK_VUMETER_LEFT_TO_RIGHT;
    }

    g_assert_not_reached();
    return GTK_VUMETER_BOTTOM_TO_TOP;
}

/**
 * gtk_vumeter_set_thickness:
 * @param vumeter the vumeter widget
 * @param thickness gtkvumeter's minimum graph thickness in pixels (default:30)
 *
 * Allows the user program to change the dimension of the vumeter.
 * For a vertical meter, this is the width.
 * Likewise for a horizontal meter, this is the height.
 */
void gtk_vumeter_set_thickness (GtkVUMeter *vumeter, gint thickness)
{
    g_return_if_fail (GTK_IS_VUMETER (vumeter));

    if (vumeter->thickness != thickness) {
        vumeter->thickness = thickness;
        vumeter->reduced_thickness = MIN(vumeter->reduced_thickness, vumeter->thickness);
        gtk_widget_queue_resize (GTK_WIDGET (vumeter));
    }
}

/**
 * gtk_vumeter_get_thickness:
 * @param vumeter the vumeter widget
 * @return gtkvumeter's minimum graph thickness in pixels (default:30)
 *
 * For a vertical meter, this is the width.
 * Likewise for a horizontal meter, this is the height.
 */
gint gtk_vumeter_get_thickness (GtkVUMeter *vumeter)
{
    if(!GTK_IS_VUMETER (vumeter)) {
        return 0;
    } else {
        return vumeter->thickness;
    }
}

/**
 * gtk_vumeter_set_thickness_reduction:
 * @param vumeter the vumeter widget
 * @param reduced_thickness pixels to reduce the "none active" part of the graph (default:0)
 *
 * Allows the user program to reduce the thickness of the "background" part of the vumeter graph.
 * This can be useful to distinguish the border between the foreground and background graph.
 */
void gtk_vumeter_set_thickness_reduction (GtkVUMeter *vumeter, gint reduced_thickness)
{
    g_return_if_fail (GTK_IS_VUMETER (vumeter));

    if (vumeter->reduced_thickness != reduced_thickness) {
        vumeter->reduced_thickness = reduced_thickness;
        vumeter->reduced_thickness = CLAMP(vumeter->reduced_thickness, 0, vumeter->thickness/2);
        gtk_widget_queue_resize (GTK_WIDGET (vumeter));
    }
}

/**
 * gtk_vumeter_get_thickness_reduction:
 * @param vumeter the vumeter widget
 * @return pixels to reduce the "none active" part of the graph (default:0)
 *
 * The reduced thickness of the "background" part of the vumeter graph.
 */
gint gtk_vumeter_get_thickness_reduction (GtkVUMeter *vumeter)
{
    if(!GTK_IS_VUMETER (vumeter)) {
        return 0;
    } else {
        return vumeter->reduced_thickness;
    }
}

/**
 * gtk_vumeter_set_min_max:
 * @param vumeter the vumeter widget
 * @param min the new minimum level shown (default: 0)
 * @param max the new maximum level shown (default: 32768)
 *
 * Sets the minimum and maximum of the VU Meters scale.
 * It will increment max by one if min == max.
 * And finally it will clamp the relevant levels into the min, max range.
 * Either value can be NULL, to keep the current value.
 *
 * Don't forget to call %gtk_vumeter_set_yellow_level() if required!
 *
 * WARNING: negative values for min or max will currently not work!!!
 */
void gtk_vumeter_set_min_max (GtkVUMeter *vumeter, gint *min, gint *max)
{
    gint mi, ma;

    g_return_if_fail (GTK_IS_VUMETER (vumeter));

    /* Allow min or max to be NULL */
    mi = (min != NULL) ? *min : vumeter->level_min;
    ma = (max != NULL) ? *max : vumeter->level_max;

    /* Ensure that max > min */
    vumeter->level_max = MAX(ma, mi);
    vumeter->level_min = MIN(mi, ma);
    if (vumeter->level_max == vumeter->level_min) {
        /* Increment max so we have a range */
	    vumeter->level_max++;
    }
    /* Clamp the levels to the new range */
    vumeter->level = CLAMP (vumeter->level, vumeter->level_min, vumeter->level_max);
    vumeter->peak_level = CLAMP (vumeter->peak_level, vumeter->level, vumeter->level_max);
    vumeter->yellow_level = CLAMP (vumeter->yellow_level, vumeter->level_min, vumeter->level_max);

    gtk_widget_queue_draw (GTK_WIDGET(vumeter));
}

/**
 * gtk_vumeter_get_min_max:
 * @param vumeter the vumeter widget
 * @param min the new minimum level shown (default: 0)
 * @param max the new maximum level shown (default: 32768)
 *
 * The minimum and maximum of the VU Meters scale.
 */
void gtk_vumeter_get_min_max (GtkVUMeter *vumeter, gint *min, gint *max)
{
    if(!GTK_IS_VUMETER (vumeter)) {
        *min = 0;
        *max = 0;
    } else {
        *min = vumeter->level_min;
        *max = vumeter->level_max;
    }
}

/**
 * gtk_vumeter_set_level:
 * @param vumeter the vumeter widget
 * @param level the new level shown (default: 0)
 *
 * Sets new level value for the vumeter.
 * The level is clamped to the min max range.
 * The peak_level will be increased to level if needed.
 */
void gtk_vumeter_set_level (GtkVUMeter *vumeter, gint level)
{
    g_return_if_fail (GTK_IS_VUMETER (vumeter));

    if (vumeter->level != level) {
        vumeter->level = CLAMP (level, vumeter->level_min, vumeter->level_max);
        if(vumeter->level > vumeter->peak_level) {
            vumeter->peak_hold = vumeter->peak_hold_factor;
            vumeter->peak_level = vumeter->level;
        }
        gtk_widget_queue_draw (GTK_WIDGET(vumeter));
    }
}

/**
 * gtk_vumeter_get_level:
 * @param vumeter the vumeter widget
 * @return the level shown (default: 0)
 *
 * Gets the level value of the vumeter.
 */
gint gtk_vumeter_get_level (GtkVUMeter *vumeter)
{
    if(!GTK_IS_VUMETER (vumeter)) {
        return 0;
    } else {
        return vumeter->level;
    }
}

/**
 * gtk_vumeter_set_scaling:
 * @param vumeter the vumeter widget
 * @param scaling the scaling mode either GTK_VUMETER_SCALING_LINEAR or GTK_VUMETER_SCALING_LOG
 *
 * Sets the scaling mode of the VU Meter.
 * It is either log or linear and defaults to linear.
 * No matter which scale you set the input should always be linear, gtkVUMeter
 * does the log calculation/display.
 */
void gtk_vumeter_set_scaling (GtkVUMeter *vumeter, GtkVUMeterScaling scaling)
{
    g_return_if_fail (GTK_IS_VUMETER (vumeter));

    if (scaling != vumeter->scaling) {
        vumeter->scaling = CLAMP (scaling, GTK_VUMETER_SCALING_LINEAR, GTK_VUMETER_SCALING_LOG);
        if (gtk_widget_get_realized (GTK_WIDGET(vumeter))) {
            gtk_vumeter_setup_colors (vumeter);
            gtk_widget_queue_draw (GTK_WIDGET (vumeter));
        }
    }
}

/**
 * gtk_vumeter_get_scaling:
 * @param vumeter the vumeter widget
 * @return the scaling mode either GTK_VUMETER_SCALING_LINEAR or GTK_VUMETER_SCALING_LOG
 *
 * Gets the scaling mode of the VU Meter.
 * It is either log or linear and defaults to linear.
 */
GtkVUMeterScaling gtk_vumeter_get_scaling (GtkVUMeter *vumeter)
{
    if(!GTK_IS_VUMETER (vumeter)) {
        return 0;
    } else {
        return vumeter->scaling;
    }
}

/**
 * gtk_vumeter_set_scale_items:
 * @param vumeter the vumeter widget
 * @param scale_items a GList of the pitch lines and labels (default:NULL)
 *
 * Set the scale pitch lines and labels.
 * Must be NULL or a GList containing filled %GtkVUMeterScaleItem items.
 * Function will make a deep copy of the GList and it's items,
 * so the given GList and it's items can be safely thrown away after the call.
 * A side effect: This also sets the minimum size of the widget.
 */
void gtk_vumeter_set_scale_items(GtkVUMeter *vumeter, GList *scale_items)
{
    g_return_if_fail (GTK_IS_VUMETER (vumeter));

    gtk_vumeter_setup_scale_items(vumeter, scale_items);

    if (gtk_widget_get_realized(GTK_WIDGET(vumeter))) {
        gtk_widget_queue_draw (GTK_WIDGET (vumeter));
    }
}

/**
 * gtk_vumeter_get_scale_items:
 * @param vumeter the vumeter widget
 * @return a GList of the pitch lines and labels (default:NULL)
 *
 * Get the scale pitch lines and labels, a GList containing %GtkVUMeterScaleItem items.
 * The returned GList must be freed with gtk_vumeter_free_scale_items() by the user!!!
 */
GList *gtk_vumeter_get_scale_items(GtkVUMeter *vumeter)
{
    if(!GTK_IS_VUMETER (vumeter)) {
        return NULL;
    } else {
        return gtk_vumeter_clone_scale_items(vumeter->scale_items);
    }
}

/**
 * gtk_vumeter_set_scale_hole_size:
 * @param vumeter the vumeter widget
 * @param hole_size  (default:0)
 *
 * Set the size of the "holes" between the pitch lines.
 * A side effect: This also sets the minimum size of the widget.
 */
void gtk_vumeter_set_scale_hole_size (GtkVUMeter *vumeter, gint hole_size)
{
    g_return_if_fail (GTK_IS_VUMETER (vumeter));

    if (vumeter->scale_pitch_holes != hole_size) {
        vumeter->scale_pitch_holes = hole_size;
        gtk_widget_queue_resize (GTK_WIDGET (vumeter));
    }
}

/**
 * gtk_vumeter_get_scale_hole_size:
 * @param vumeter the vumeter widget
 * @return  (default:0)
 *
 * Get the size of the "holes" between the pitch lines.
 */
gint gtk_vumeter_get_scale_hole_size (GtkVUMeter *vumeter)
{
    if(!GTK_IS_VUMETER (vumeter)) {
        return 0;
    } else {
        return vumeter->scale_pitch_holes;
    }
}

/**
 * gtk_vumeter_set_peak:
 * @param vumeter the vumeter widget
 * @param peak whether or not the peak indicator is drawn
 * @param redraw_rate the rate (in milliseconds) at which the peak indicator is redrawn
 *
 * Enables/Disables the peak meachanism and sets the redraw timeout to redraw_rate milliseconds.
 * The redraw operation is intelligent in that the widget is only redrawn
 * if the peak_level != level and peak == %TRUE.
 *
 * Hint: A good redraw_rate is 200ms (default: 0ms -> off)
 */
void gtk_vumeter_set_peak (GtkVUMeter *vumeter, gboolean peak, guint redraw_rate)
{
    g_return_if_fail (GTK_IS_VUMETER (vumeter));

    if (vumeter->peak != peak) {
        vumeter->peak = peak;
        gtk_widget_queue_draw (GTK_WIDGET (vumeter));
    }

    vumeter->peak_redraw_rate = redraw_rate;

    if(vumeter->peak_timeout) {
        g_source_remove(vumeter->peak_timeout);
    }

    if(redraw_rate != 0 && vumeter->peak) {
        vumeter->peak_timeout = g_timeout_add (redraw_rate, gtk_vumeter_redraw_timeout, vumeter);
    }
}

/**
 * gtk_vumeter_get_peak:
 * @param vumeter the vumeter widget
 * @param peak whether or not the peak indicator is drawn
 * @param redraw_rate the rate (in milliseconds) at which the peak indicator is redrawn
 *
 */
void gtk_vumeter_get_peak (GtkVUMeter *vumeter, gboolean *peak, guint *redraw_rate)
{
    if(!GTK_IS_VUMETER (vumeter)) {
        *peak = 0;
        *redraw_rate = 0;
    } else {
        *peak = vumeter->peak;
        *redraw_rate = vumeter->peak_redraw_rate;
    }
}

/**
 * gtk_vumeter_set_peak_hold_factor:
 * @param vumeter the vumeter widget
 * @param hold_factor number of redraw_rates to wait until peak indicator is decayed (default:0 -> off)
 *
 * Holds the peak indicator for a limited time at it's highest position.
 * The actual rate is dependent on the redraw_rate given to %gtk_vumeter_set_peak().
 *
 * Hint: For a VU meter, a good hold_factor is 7 with a redraw_rate of 200ms.
 */
void gtk_vumeter_set_peak_hold_factor (GtkVUMeter *vumeter, gint hold_factor)
{
    g_return_if_fail (GTK_IS_VUMETER (vumeter));

    if (vumeter->peak_hold_factor != hold_factor) {
        vumeter->peak_hold_factor = hold_factor;
    }
}

/**
 * gtk_vumeter_get_peak_hold_factor:
 * @param vumeter the vumeter widget
 * @return number of redraw_rates to wait until peak indicator is decayed (default:0 -> off)
 */
gint gtk_vumeter_get_peak_hold_factor (GtkVUMeter *vumeter)
{
    if(!GTK_IS_VUMETER (vumeter)) {
        return 0;
    } else {
        return vumeter->peak_hold_factor;
    }
}

/**
 * gtk_vumeter_set_peak_falloff:
 * @param vumeter the vumeter widget
 * @param peak_falloff controls the speed to the peak decay
 * @param user_rate pixels to reduce the peak level at each redraw_rate in GTK_VUMETER_PEAK_FALLOFF_USER mode, otherwise ignored
 *
 * Set the numbers of pixel reduced from the peak indicator each redraw_rate (after the hold period is over).
 * The peak_falloff will be around: SLOW:5%, MEDIUM:10%, FAST:20%, USER:user_rate
 * of the current range, reduced from peak at each redraw_rate (%gtk_vumeter_set_peak()).
 *
 * Hint: a user_rate of 0 can be used to hold the peak indicator at the highest position ever.
 */
void gtk_vumeter_set_peak_falloff (GtkVUMeter *vumeter, GtkVUMeterPeakFalloff peak_falloff, guint user_rate)
{
    gint range;
    g_return_if_fail (GTK_IS_VUMETER (vumeter));

    vumeter->peak_falloff_mode = CLAMP(peak_falloff, GTK_VUMETER_PEAK_FALLOFF_SLOW, GTK_VUMETER_PEAK_FALLOFF_USER);
    range = vumeter->level_max - vumeter->level_min;

    switch (peak_falloff) {
        case GTK_VUMETER_PEAK_FALLOFF_SLOW:
            vumeter->peak_falloff_rate = range/20;
            break;
        default:
        case GTK_VUMETER_PEAK_FALLOFF_MEDIUM:
            vumeter->peak_falloff_rate = range/10;
            break;
        case GTK_VUMETER_PEAK_FALLOFF_FAST:
            vumeter->peak_falloff_rate = range/5;
            break;
        case GTK_VUMETER_PEAK_FALLOFF_USER:
            vumeter->peak_falloff_rate = (gint)user_rate;
            break;
    }
}

/**
 * gtk_vumeter_get_peak_falloff:
 * @param vumeter the vumeter widget
 * @param peak_falloff controls the speed to the peak decay
 * @param user_rate pixels to lower the peak level each redraw_rate (value valid in every peak_falloff mode)
 */
void gtk_vumeter_get_peak_falloff (GtkVUMeter *vumeter, GtkVUMeterPeakFalloff *peak_falloff, guint *user_rate)
{
    if(!GTK_IS_VUMETER (vumeter)) {
        *peak_falloff = 0;
        *user_rate = 0;
    } else {
        *peak_falloff = vumeter->peak_falloff_mode;
        *user_rate = vumeter->peak_falloff_rate;
    }
}

/**
 * gtk_vumeter_set_colors_inverted:
 * @param vumeter the vumeter widget
 * @param inverted whether or not the colors are inverted (default:%FALSE)
 *
 * Usually the graph will be colored with: 0:green, half:yellow, full:red.
 * This is used to display signals that won't "work correct" above a maximum level
 * (e.g. audio signals may distort if their amplitude is too high).
 *
 * The inverted colors will be: 0:red, half:yellow, full:green.
 * This is used to display signals that need a minimum level to work correct
 * (e.g. a received antenna signal must have a minimum amplitude to "work correct").
 */
void gtk_vumeter_set_colors_inverted (GtkVUMeter *vumeter, gboolean inverted)
{
    g_return_if_fail (GTK_IS_VUMETER (vumeter));

    vumeter->colors_inverted = inverted;
     if (gtk_widget_get_realized(GTK_WIDGET(vumeter))) {
        gtk_vumeter_setup_colors (vumeter);
        gtk_widget_queue_draw (GTK_WIDGET (vumeter));
    }
}

/**
 * gtk_vumeter_get_colors_inverted:
 * @param vumeter the vumeter widget
 * @return whether or not the colors are inverted (default:%FALSE)
 */
gboolean gtk_vumeter_get_colors_inverted (GtkVUMeter *vumeter)
{
    if(!GTK_IS_VUMETER (vumeter)) {
        return 0;
    } else {
        return vumeter->colors_inverted;
    }
}

/**
 * gtk_vumeter_set_yellow_level:
 * @param vumeter the vumeter widget
 * @param yellow_level set the position of the yellow area (default:16383)
 *
 * Will be clamped between min and max.
 */
void gtk_vumeter_set_yellow_level (GtkVUMeter *vumeter, gint yellow_level)
{
    g_return_if_fail (GTK_IS_VUMETER (vumeter));

    vumeter->yellow_level = CLAMP (yellow_level, vumeter->level_min, vumeter->level_max);
    if (gtk_widget_get_realized(GTK_WIDGET(vumeter))) {
        gtk_vumeter_setup_colors (vumeter);
        gtk_widget_queue_draw (GTK_WIDGET (vumeter));
    }
}

/**
 * gtk_vumeter_get_yellow_level:
 * @param vumeter the vumeter widget
 * @return get the position of the yellow area (default:16383)
 */
gint gtk_vumeter_get_yellow_level (GtkVUMeter *vumeter)
{
    if(!GTK_IS_VUMETER (vumeter)) {
        return 0;
    } else {
        return vumeter->yellow_level;
    }
}

/**
 * gtk_vumeter_set_brightness:
 * @param vumeter the vumeter widget
 * @param foreground set the brightness of the graphs foreground (default:65535)
 * @param background set the brightness of the graphs background (default:49151)
 *
 * Hint: don't turn the brightness too low, otherwise you'll only see a black bar :-)
 */
void gtk_vumeter_set_brightness (GtkVUMeter *vumeter, gint foreground, gint background)
{
    vumeter->f_brightness = CLAMP(foreground, 0, 65535);
    vumeter->b_brightness = CLAMP(background, 0, vumeter->f_brightness);
    if (gtk_widget_get_realized(GTK_WIDGET(vumeter))) {
        gtk_vumeter_setup_colors (vumeter);
        gtk_widget_queue_draw (GTK_WIDGET (vumeter));
    }
}

/**
 * gtk_vumeter_get_brightness:
 * @param vumeter the vumeter widget
 * @param foreground get the brightness of the graphs foreground (default:65535)
 * @param background get the brightness of the graphs background (default:49151)
 */
void gtk_vumeter_get_brightness (GtkVUMeter *vumeter, gint *foreground, gint *background)
{
    if(!GTK_IS_VUMETER (vumeter)) {
        *foreground = 0;
        *background = 0;
    } else {
        *foreground = vumeter->f_brightness;
        *background = vumeter->b_brightness;
    }
}

