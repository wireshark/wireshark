/***************************************************************************
 *            gtkvumeter.h
 *
 *  Fri Jan 10 20:06:41 2003
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

#ifndef __GTKVUMETER_H__
#define __GTKVUMETER_H__

#include <gtk/gtk.h>


#define GTK_TYPE_VUMETER                (gtk_vumeter_get_type ())
#define GTK_VUMETER(obj)                (GTK_CHECK_CAST ((obj), GTK_TYPE_VUMETER, GtkVUMeter))
#define GTK_VUMETER_CLASS(klass)        (GTK_CHECK_CLASS_CAST ((klass), GTK_TYPE_VUMETER GtkVUMeterClass))
#define GTK_IS_VUMETER(obj)             (GTK_CHECK_TYPE ((obj), GTK_TYPE_VUMETER))
#define GTK_IS_VUMETER_CLASS(klass)     (GTK_CHECK_CLASS_TYPE ((klass), GTK_TYPE_VUMETER))
#define GTK_VUMETER_GET_CLASS(obj)      (GTK_CHECK_GET_CLASS ((obj), GTK_TYPE_VUMETER, GtkVUMeterClass))

typedef struct _GtkVUMeter      GtkVUMeter;
typedef struct _GtkVUMeterClass GtkVUMeterClass;

typedef enum {
    GTK_VUMETER_PEAK_FALLOFF_SLOW,
    GTK_VUMETER_PEAK_FALLOFF_MEDIUM,
    GTK_VUMETER_PEAK_FALLOFF_FAST,
    GTK_VUMETER_PEAK_FALLOFF_USER
} GtkVUMeterPeakFalloff;

typedef enum {
    GTK_VUMETER_SCALING_LINEAR,
    GTK_VUMETER_SCALING_LOG
} GtkVUMeterScaling;

typedef enum
{
  GTK_VUMETER_LEFT_TO_RIGHT,
  GTK_VUMETER_RIGHT_TO_LEFT,
  GTK_VUMETER_BOTTOM_TO_TOP,
  GTK_VUMETER_TOP_TO_BOTTOM
} GtkVUMeterOrientation;

struct _GtkVUMeter {
    GtkWidget   widget;

    /* geometry */
    gboolean    vertical;
    gboolean    scale_inverted;
    gint        thickness;
    gint        reduced_thickness;
    gint        padding_left;
    gint        padding_right;
    gint        padding_top;
    gint        padding_bottom;

    /* signal level */
    gint        level;
    gint        level_min;
    gint        level_max;
    GtkVUMeterScaling scaling;

    /* the scale */
    GList       *scale_items;
    gint        scale_pitch_holes;

    /* peak indicator */
    gboolean    peak;
    gint        peak_level;
    gint        peak_redraw_rate;
    guint       peak_timeout;
    gint        peak_hold_factor;
    gint        peak_hold;
    GtkVUMeterPeakFalloff peak_falloff_mode;
    gint        peak_falloff_rate;

    /* colors */
    GdkColormap *colormap;
    gint        colors;
    GdkGC       **f_gc;
    GdkGC       **b_gc;
    GdkColor    *f_colors;
    GdkColor    *b_colors;
    gint        f_brightness;
    gint        b_brightness;
    gboolean    colors_inverted;
    gint        yellow_level;
};

struct _GtkVUMeterClass {
    GtkWidgetClass  parent_class;
};

typedef struct _GtkVUMeterScaleItem {
    gint        level;  /* level where to show the item (clamped: level_min/level_max) */
    gboolean    large;  /* TRUE for a large, FALSE for a small pitch line */
    const gchar *label; /* the label or NULL */
} GtkVUMeterScaleItem;

GtkType    gtk_vumeter_get_type (void) G_GNUC_CONST;

GtkWidget *gtk_vumeter_new (void);
void gtk_vumeter_set_orientation(GtkVUMeter *vumeter, GtkVUMeterOrientation orientation);
GtkVUMeterOrientation gtk_vumeter_get_orientation(GtkVUMeter *vumeter);
void gtk_vumeter_set_thickness (GtkVUMeter *vumeter, gint size);
gint gtk_vumeter_get_thickness (GtkVUMeter *vumeter);
void gtk_vumeter_set_thickness_reduction (GtkVUMeter *vumeter, gint size);
gint gtk_vumeter_get_thickness_reduction (GtkVUMeter *vumeter);

void gtk_vumeter_set_min_max (GtkVUMeter *vumeter, gint *min, gint *max);
void gtk_vumeter_get_min_max (GtkVUMeter *vumeter, gint *min, gint *max);
void gtk_vumeter_set_level (GtkVUMeter *vumeter, gint level);
gint gtk_vumeter_get_level (GtkVUMeter *vumeter);
void gtk_vumeter_set_scaling (GtkVUMeter *vumeter, GtkVUMeterScaling scale);
GtkVUMeterScaling gtk_vumeter_get_scaling (GtkVUMeter *vumeter);

void gtk_vumeter_set_scale_items (GtkVUMeter *vumeter, GList *scale_items);
GList *gtk_vumeter_get_scale_items (GtkVUMeter *vumeter);
void gtk_vumeter_free_scale_items(GList *scale_items);
void gtk_vumeter_set_scale_hole_size (GtkVUMeter *vumeter, gint hole_size);
gint gtk_vumeter_get_scale_hole_size (GtkVUMeter *vumeter);

void gtk_vumeter_set_peak (GtkVUMeter *vumeter, gboolean peak, guint redraw_rate);
void gtk_vumeter_get_peak (GtkVUMeter *vumeter, gboolean *peak, guint *redraw_rate);
void gtk_vumeter_set_peak_hold_factor (GtkVUMeter *vumeter, gint hold_factor);
gint gtk_vumeter_get_peak_hold_factor (GtkVUMeter *vumeter);
void gtk_vumeter_set_peak_falloff (GtkVUMeter *vumeter, GtkVUMeterPeakFalloff peak_falloff, guint user_rate);
void gtk_vumeter_get_peak_falloff (GtkVUMeter *vumeter, GtkVUMeterPeakFalloff *peak_falloff, guint *user_rate);

void gtk_vumeter_set_colors_inverted (GtkVUMeter *vumeter, gboolean inverted);
gboolean gtk_vumeter_get_colors_inverted (GtkVUMeter *vumeter);
void gtk_vumeter_set_yellow_level (GtkVUMeter *vumeter, gint yellow_level);
gint gtk_vumeter_get_yellow_level (GtkVUMeter *vumeter);
void gtk_vumeter_set_brightness (GtkVUMeter *vumeter, gint foreground, gint background);
void gtk_vumeter_get_brightness (GtkVUMeter *vumeter, gint *foreground, gint *background);


#endif /* __GTKVUMETER_H__ */
