#ifndef __BYTES_VIEW_H__
#define __BYTES_VIEW_H__

#define BYTES_VIEW_TYPE (bytes_view_get_type())
#define BYTES_VIEW(object)	    (G_TYPE_CHECK_INSTANCE_CAST((object), BYTES_VIEW_TYPE, BytesView))

typedef struct _BytesView BytesView;

GType bytes_view_get_type(void);

GtkWidget *bytes_view_new(void);
void bytes_view_set_font(BytesView *bv, PangoFontDescription *font);

void bytes_view_set_data(BytesView *bv, const guint8 *data, int len);
void bytes_view_set_encoding(BytesView *bv, int enc);
void bytes_view_set_format(BytesView *bv, int format);
void bytes_view_set_highlight_style(BytesView *bv, gboolean bold);

void bytes_view_set_highlight(BytesView *bv, int start, int end, guint32 mask, int maskle);
void bytes_view_set_highlight_appendix(BytesView *bv, int start, int end);

void bytes_view_refresh(BytesView *bv);
int bytes_view_byte_from_xy(BytesView *bv, int x, int y);
void bytes_view_scroll_to_byte(BytesView *bv, int byte);

#endif /* __BYTES_VIEW_H__ */
