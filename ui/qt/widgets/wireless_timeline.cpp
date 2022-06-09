/* wireless_timeline.cpp
 * GUI to show an 802.11 wireless timeline of packets
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copyright 2012 Parc Inc and Samsung Electronics
 * Copyright 2015, 2016 & 2017 Cisco Inc
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "wireless_timeline.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/packet_info.h>
#include <epan/column-utils.h>
#include <epan/tap.h>

#include <cmath>

#include "globals.h"
#include <epan/dissectors/packet-ieee80211-radio.h>

#include <epan/color_filters.h>
#include "frame_tvbuff.h"

#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include "main_application.h"
#include <wsutil/report_message.h>
#include <wsutil/utf8_entities.h>

#ifdef Q_OS_WIN
#include "wsutil/file_util.h"
#include <QSysInfo>
#endif

#include <QPaintEvent>
#include <QPainter>
#include <QGraphicsScene>
#include <QToolTip>

#include "packet_list.h"
#include <ui/qt/models/packet_list_model.h>

/* we start rendering this number of microseconds left of the left edge - to ensure
 * NAV lines are drawn correctly, and that small errors in time order don't prevent some
 * frames from being rendered.
 * These errors in time order can come from generators that record PHY rate incorrectly
 * in some circumstances.
 */
#define RENDER_EARLY 40000


const float fraction = 0.8F;
const float base = 0.1F;
class pcolor : public QColor
{
public:
    inline pcolor(float red, float green, float blue) : QColor(
            (int) (255*(red * fraction + base)),
            (int) (255*(green * fraction + base)),
            (int) (255*(blue * fraction + base))) { }
};

static void reset_rgb(float rgb[TIMELINE_HEIGHT][3])
{
    int i;
    for (i = 0; i < TIMELINE_HEIGHT; i++)
        rgb[i][0] = rgb[i][1] = rgb[i][2] = 1.0;
}

static void render_pixels(QPainter &p, gint x, gint width, float rgb[TIMELINE_HEIGHT][3], float ratio)
{
    int previous = 0, i;
    for (i = 1; i <= TIMELINE_HEIGHT; i++) {
        if (i != TIMELINE_HEIGHT &&
                rgb[previous][0] == rgb[i][0] &&
                rgb[previous][1] == rgb[i][1] &&
                rgb[previous][2] == rgb[i][2])
            continue;
        if (rgb[previous][0] != 1.0 || rgb[previous][1] != 1.0 || rgb[previous][2] != 1.0) {
          p.fillRect(QRectF(x/ratio, previous, width/ratio, i-previous), pcolor(rgb[previous][0],rgb[previous][1],rgb[previous][2]));
        }
        previous = i;
    }
    reset_rgb(rgb);
}

static void render_rectangle(QPainter &p, gint x, gint width, guint height, int dfilter, float r, float g, float b, float ratio)
{
    p.fillRect(QRectF(x/ratio, TIMELINE_HEIGHT/2-height, width/ratio, dfilter ? height * 2 : height), pcolor(r,g,b));
}

static void accumulate_rgb(float rgb[TIMELINE_HEIGHT][3], int height, int dfilter, float width, float red, float green, float blue)
{
    int i;
    for (i = TIMELINE_HEIGHT/2-height; i < (TIMELINE_HEIGHT/2 + (dfilter ? height : 0)); i++) {
        rgb[i][0] = rgb[i][0] - width + width * red;
        rgb[i][1] = rgb[i][1] - width + width * green;
        rgb[i][2] = rgb[i][2] - width + width * blue;
    }
}


void WirelessTimeline::mousePressEvent(QMouseEvent *event)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 0 ,0)
    start_x = last_x = event->position().x();
#else
    start_x = last_x = event->localPos().x();
#endif
}


void WirelessTimeline::mouseMoveEvent(QMouseEvent *event)
{
    if (event->buttons() == Qt::NoButton)
        return;

#if QT_VERSION >= QT_VERSION_CHECK(6, 0 ,0)
    qreal offset = event->position().x() - last_x;
    last_x = event->position().x();
#else
    qreal offset = event->localPos().x() - last_x;
    last_x = event->localPos().x();
#endif

    qreal shift = ((qreal) (end_tsf - start_tsf))/width() * offset;
    start_tsf -= shift;
    end_tsf -= shift;
    clip_tsf();

    // TODO: scroll by moving pixels and redraw only exposed area
    // render(p, ...)
    // then update full widget only on release.
    update();
}


void WirelessTimeline::mouseReleaseEvent(QMouseEvent *event)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 0 ,0)
    QPointF localPos = event->position();
#else
    QPointF localPos = event->localPos();
#endif
    qreal offset = localPos.x() - start_x;

    /* if this was a drag, ignore it */
    if (std::abs(offset) > 3)
        return;

    /* this was a click */
    guint num = find_packet(localPos.x());
    if (num == 0)
        return;

    frame_data *fdata = frame_data_sequence_find(cfile.provider.frames, num);
    if (!fdata->passed_dfilter && fdata->prev_dis_num > 0)
        num = fdata->prev_dis_num;

    cf_goto_frame(&cfile, num);
}


void WirelessTimeline::clip_tsf()
{
    // did we go past the start of the file?
    if (((gint64) start_tsf) < ((gint64) first->start_tsf)) {
        // align the start of the file at the left edge
        guint64 shift = first->start_tsf - start_tsf;
        start_tsf += shift;
        end_tsf += shift;
    }
    if (end_tsf > last->end_tsf) {
        guint64 shift = end_tsf - last->end_tsf;
        start_tsf -= shift;
        end_tsf -= shift;
    }
}


void WirelessTimeline::selectedFrameChanged(QList<int>)
{
    if (isHidden())
        return;

    if (cfile.current_frame) {
        struct wlan_radio *wr = get_wlan_radio(cfile.current_frame->num);

        guint left_margin = 0.9 * start_tsf + 0.1 * end_tsf;
        guint right_margin = 0.1 * start_tsf + 0.9 * end_tsf;
        guint64 half_window = (end_tsf - start_tsf)/2;

        if (wr) {
            // are we to the left of the left margin?
            if (wr->start_tsf < left_margin) {
                // scroll the left edge back to the left margin
                guint64 offset = left_margin - wr->start_tsf;
                if (offset < half_window) {
                    // small movement; keep packet to margin
                    start_tsf -= offset;
                    end_tsf -= offset;
                } else {
                    // large movement; move packet to center of window
                    guint64 center = (wr->start_tsf + wr->end_tsf)/2;
                    start_tsf = center - half_window;
                    end_tsf = center + half_window;
                }
            } else if (wr->end_tsf > right_margin) {
                guint64 offset = wr->end_tsf - right_margin;
                if (offset < half_window) {
                    start_tsf += offset;
                    end_tsf += offset;
                } else {
                    guint64 center = (wr->start_tsf + wr->end_tsf)/2;
                    start_tsf = center - half_window;
                    end_tsf = center + half_window;
                }
            }
            clip_tsf();

            update();
        }
    }
}


/* given an x position find which packet that corresponds to.
 * if it's inter frame space the subsequent packet is returned */
guint
WirelessTimeline::find_packet(qreal x_position)
{
    guint64 x_time = start_tsf + (x_position/width() * (end_tsf - start_tsf));

    return find_packet_tsf(x_time);
}

void WirelessTimeline::captureFileReadStarted(capture_file *cf)
{
    capfile = cf;
    hide();
    // TODO: hide or grey the toolbar controls
}

void WirelessTimeline::captureFileReadFinished()
{
    /* All frames must be included in packet list */
    if (cfile.count == 0 || g_hash_table_size(radio_packet_list) != cfile.count)
        return;

    /* check that all frames have start and end tsf time and are reasonable time order.
     * packet timing reference seems to be off a little on some generators, which
     * causes frequent IFS values in the range 0 to -30. Some generators emit excessive
     * data when an FCS error happens, and this results in the duration calculation for
     * the error frame being excessively long. This can cause larger negative IFS values
     * (-30 to -1000) for the subsequent frame. Ignore these cases, as they don't seem
     * to impact the GUI too badly. If the TSF reference point is set wrong (TSF at
     * start of frame when it is at the end) then larger negative offsets are often
     * seen. Don't display the timeline in these cases.
     */
    /* TODO: update GUI to handle captures with occasional frames missing TSF data */
    /* TODO: indicate error message to the user */
    for (guint32 n = 1; n < cfile.count; n++) {
        struct wlan_radio *w = get_wlan_radio(n);
        if (w->start_tsf == 0 || w->end_tsf == 0) {
            QString err = tr("Packet number %1 does not include TSF timestamp, not showing timeline.").arg(n);
            mainApp->pushStatus(MainApplication::TemporaryStatus, err);
            return;
        }
        if (w->ifs < -RENDER_EARLY) {
            QString err = tr("Packet number %u has large negative jump in TSF, not showing timeline. Perhaps TSF reference point is set wrong?").arg(n);
            mainApp->pushStatus(MainApplication::TemporaryStatus, err);
            return;
        }
    }

    first = get_wlan_radio(1);
    last = get_wlan_radio(cfile.count);

    start_tsf = first->start_tsf;
    end_tsf = last->end_tsf;

    /* TODO: only reset the zoom level if the file is changed, not on redissection */
    zoom_level = 0;

    show();
    selectedFrameChanged(QList<int>());
    // TODO: show or ungrey the toolbar controls
    update();
}

void WirelessTimeline::appInitialized()
{
    connect(mainApp->mainWindow(), SIGNAL(framesSelected(QList<int>)), this, SLOT(selectedFrameChanged(QList<int>)));

    GString *error_string;
    error_string = register_tap_listener("wlan_radio_timeline", this, NULL, TL_REQUIRES_NOTHING, tap_timeline_reset, tap_timeline_packet, NULL/*tap_draw_cb tap_draw*/, NULL);
    if (error_string) {
        report_failure("Wireless Timeline - tap registration failed: %s", error_string->str);
        g_string_free(error_string, TRUE);
    }
}

void WirelessTimeline::resizeEvent(QResizeEvent*)
{
    // TODO adjust scrollbar
}


// Calculate the x position on the GUI from the timestamp
int WirelessTimeline::position(guint64 tsf, float ratio)
{
    int position = -100;

    if (tsf != G_MAXUINT64) {
        position = ((double) tsf - start_tsf)*width()*ratio/(end_tsf-start_tsf);
    }
    return position;
}


WirelessTimeline::WirelessTimeline(QWidget *parent) : QWidget(parent)
{
    setHidden(true);
    zoom_level = 1.0;
    setFixedHeight(TIMELINE_HEIGHT);
    first_packet = 1;
    setMouseTracking(true);
    start_x = 0;
    last_x = 0;
    packet_list = NULL;
    start_tsf = 0;
    end_tsf = 0;
    first = NULL;
    last = NULL;
    capfile = NULL;

    radio_packet_list = g_hash_table_new(g_direct_hash, g_direct_equal);
    connect(mainApp, SIGNAL(appInitialized()), this, SLOT(appInitialized()));
}

WirelessTimeline::~WirelessTimeline()
{
    if (radio_packet_list != NULL)
    {
        g_hash_table_destroy(radio_packet_list);
    }
}

void WirelessTimeline::setPacketList(PacketList *packet_list)
{
    this->packet_list = packet_list;
}

void WirelessTimeline::tap_timeline_reset(void* tapdata)
{
    WirelessTimeline* timeline = (WirelessTimeline*)tapdata;

    if (timeline->radio_packet_list != NULL)
    {
        g_hash_table_destroy(timeline->radio_packet_list);
    }
    timeline->hide();

    timeline->radio_packet_list = g_hash_table_new(g_direct_hash, g_direct_equal);
}

tap_packet_status WirelessTimeline::tap_timeline_packet(void *tapdata, packet_info* pinfo, epan_dissect_t* edt _U_, const void *data, tap_flags_t)
{
    WirelessTimeline* timeline = (WirelessTimeline*)tapdata;
    const struct wlan_radio *wlan_radio_info = (const struct wlan_radio *)data;

    /* Save the radio information in our own (GUI) hashtable */
    g_hash_table_insert(timeline->radio_packet_list, GUINT_TO_POINTER(pinfo->num), (gpointer)wlan_radio_info);
    return TAP_PACKET_DONT_REDRAW;
}

struct wlan_radio* WirelessTimeline::get_wlan_radio(guint32 packet_num)
{
    return (struct wlan_radio*)g_hash_table_lookup(radio_packet_list, GUINT_TO_POINTER(packet_num));
}

void WirelessTimeline::doToolTip(struct wlan_radio *wr, QPoint pos, int x)
{
    if (x < position(wr->start_tsf, 1.0)) {
        QToolTip::showText(pos, QString("Inter frame space %1 " UTF8_MICRO_SIGN "s").arg(wr->ifs));
    } else {
        QToolTip::showText(pos, QString("Total duration %1 " UTF8_MICRO_SIGN "s\nNAV %2 " UTF8_MICRO_SIGN "s")
                           .arg(wr->end_tsf-wr->start_tsf).arg(wr->nav));
    }
}


bool WirelessTimeline::event(QEvent *event)
{
    if (event->type() == QEvent::ToolTip) {
        QHelpEvent *helpEvent = static_cast<QHelpEvent *>(event);
        guint packet = find_packet(helpEvent->pos().x());
        if (packet) {
            doToolTip(get_wlan_radio(packet), helpEvent->globalPos(), helpEvent->x());
        } else {
            QToolTip::hideText();
            event->ignore();
        }
        return true;
    }
    return QWidget::event(event);
}


void WirelessTimeline::wheelEvent(QWheelEvent *event)
{
    // "Most mouse types work in steps of 15 degrees, in which case the delta
    // value is a multiple of 120; i.e., 120 units * 1/8 = 15 degrees"
    double steps = event->angleDelta().y() / 120.0;
    if (steps != 0.0) {
        zoom_level += steps;
        if (zoom_level < 0) zoom_level = 0;
        if (zoom_level > TIMELINE_MAX_ZOOM) zoom_level = TIMELINE_MAX_ZOOM;
#if QT_VERSION >= QT_VERSION_CHECK(5, 15, 0)
        zoom(event->position().x() / width());
#else
        zoom(event->posF().x() / width());
#endif
    }
}


void WirelessTimeline::bgColorizationProgress(int first, int last)
{
    if (isHidden()) return;

    struct wlan_radio *first_wr = get_wlan_radio(first);

    struct wlan_radio *last_wr = get_wlan_radio(last-1);

    int x = position(first_wr->start_tsf, 1);
    int x_end = position(last_wr->end_tsf, 1);

    update(x, 0, x_end-x+1, height());
}


// zoom at relative position 0.0 <= x_fraction <= 1.0.
void WirelessTimeline::zoom(double x_fraction)
{
    /* adjust the zoom around the selected packet */
    guint64 file_range = last->end_tsf - first->start_tsf;
    guint64 center = start_tsf + x_fraction * (end_tsf - start_tsf);
    guint64 span = pow(file_range, 1.0 - zoom_level / TIMELINE_MAX_ZOOM);
    start_tsf = center - span * x_fraction;
    end_tsf = center + span * (1.0 - x_fraction);
    clip_tsf();
    update();
}

int WirelessTimeline::find_packet_tsf(guint64 tsf)
{
    if (cfile.count < 1)
        return 0;

    if (cfile.count < 2)
        return 1;

    guint32 min_count = 1;
    guint32 max_count = cfile.count-1;

    guint64 min_tsf = get_wlan_radio(min_count)->end_tsf;
    guint64 max_tsf = get_wlan_radio(max_count)->end_tsf;

    for (;;) {
        if (tsf >= max_tsf)
            return max_count+1;

        if (tsf < min_tsf)
            return min_count;

        guint32 middle = (min_count + max_count)/2;
        if (middle == min_count)
            return middle+1;

        guint64 middle_tsf = get_wlan_radio(middle)->end_tsf;

        if (tsf >= middle_tsf) {
            min_count = middle;
            min_tsf = middle_tsf;
        } else {
            max_count = middle;
            max_tsf = middle_tsf;
        }
    };
}

void
WirelessTimeline::paintEvent(QPaintEvent *qpe)
{
    QPainter p(this);

    // painting is done in device pixels in the x axis, get the ratio here
    float ratio = p.device()->devicePixelRatio();

    unsigned int packet;
    double zoom;
    int last_x=-1;
    int left = qpe->rect().left()*ratio;
    int right = qpe->rect().right()*ratio;
    float rgb[TIMELINE_HEIGHT][3];
    reset_rgb(rgb);

    zoom = ((double) width())/(end_tsf - start_tsf) * ratio;

    /* background is light grey */
    p.fillRect(0, 0, width(), TIMELINE_HEIGHT, QColor(240,240,240));

    /* background of packets visible in packet_list is white */
    int top = packet_list->indexAt(QPoint(0,0)).row();
    int bottom = packet_list->indexAt(QPoint(0,packet_list->viewport()->height())).row();

    frame_data * topData = packet_list->getFDataForRow(top);
    frame_data * botData = packet_list->getFDataForRow(bottom);
    if (! topData || ! botData)
        return;

    int x1 = top == -1 ? 0 : position(get_wlan_radio(topData->num)->start_tsf, ratio);
    int x2 = bottom == -1 ? width() : position(get_wlan_radio(botData->num)->end_tsf, ratio);
    p.fillRect(QRectF(x1/ratio, 0, (x2-x1+1)/ratio, TIMELINE_HEIGHT), Qt::white);

    /* background of current packet is blue */
    if (cfile.current_frame) {
        struct wlan_radio *wr = get_wlan_radio(cfile.current_frame->num);
        if (wr) {
            x1 = position(wr->start_tsf, ratio);
            x2 = position(wr->end_tsf, ratio);
            p.fillRect(QRectF(x1/ratio, 0, (x2-x1+1)/ratio, TIMELINE_HEIGHT), Qt::blue);
        }
    }

    QGraphicsScene qs;
    for (packet = find_packet_tsf(start_tsf + left/zoom - RENDER_EARLY); packet <= cfile.count; packet++) {
        frame_data *fdata = frame_data_sequence_find(cfile.provider.frames, packet);
        struct wlan_radio *ri = get_wlan_radio(fdata->num);
        float x, width, red, green, blue;

        if (ri == NULL) continue;

        gint8 rssi = ri->aggregate ? ri->aggregate->rssi : ri->rssi;
        guint height = (rssi+100)/2;
        gint end_nav;

        /* leave a margin above the packets so the selected packet can be seen */
        if (height > TIMELINE_HEIGHT/2-6)
            height = TIMELINE_HEIGHT/2-6;

        /* ensure shortest packets are clearly visible */
        if (height < 2)
            height = 2;

        /* skip frames we don't have start and end data for */
        /* TODO: show something, so it's clear a frame is missing */
        if (ri->start_tsf == 0 || ri->end_tsf == 0)
            continue;

        x = ((gint64) (ri->start_tsf - start_tsf))*zoom;
        /* is there a previous anti-aliased pixel to output */
        if (last_x >= 0 && ((int) x) != last_x) {
            /* write it out now */
            render_pixels(p, last_x, 1, rgb, ratio);
            last_x = -1;
        }

        /* does this packet start past the right edge of the window? */
        if (x >= right) {
            break;
        }

        width = (ri->end_tsf - ri->start_tsf)*zoom;
        if (width < 0) {
            continue;
        }

        /* is this packet completely to the left of the displayed area? */
        // TODO clip NAV line properly if we are displaying it
        if ((x + width) < left)
            continue;

        /* remember the first displayed packet */
        if (first_packet < 0)
            first_packet = packet;

        if (fdata->color_filter) {
            const color_t *c = &((const color_filter_t *) fdata->color_filter)->fg_color;
            red = c->red / 65535.0;
            green = c->green / 65535.0;
            blue = c->blue / 65535.0;
        } else {
            red = green = blue = 0.0;
        }

        /* record NAV field at higher magnifications */
        end_nav = x + width + ri->nav*zoom;
        if (zoom >= 0.01 && ri->nav && end_nav > 0) {
            gint y = 2*(packet % (TIMELINE_HEIGHT/2));
            qs.addLine(QLineF((x+width)/ratio, y, end_nav/ratio, y), QPen(pcolor(red,green,blue)));
        }

        /* does this rectangle fit within one pixel? */
        if (((int) x) == ((int) (x+width))) {
            /* accumulate it for later rendering together
             * with all other sub pixels that fall within this
             * pixel */
            last_x = x;
            accumulate_rgb(rgb, height, fdata->passed_dfilter, width, red, green, blue);
        } else {
            /* it spans more than 1 pixel.
             * first accumulate the part that does fit */
            float partial = ((int) x) + 1 - x;
            accumulate_rgb(rgb, height, fdata->passed_dfilter, partial, red, green, blue);
            /* and render it */
            render_pixels(p, (int) x, 1, rgb, ratio);
            last_x = -1;
            x += partial;
            width -= partial;
            /* are there any whole pixels of width left to draw? */
            if (width > 1.0) {
                render_rectangle(p, x, width, height, fdata->passed_dfilter, red, green, blue, ratio);
                x += (int) width;
                width -= (int) width;
            }
            /* is there a partial pixel left */
            if (width > 0.0) {
                last_x = x;
                accumulate_rgb(rgb, height, fdata->passed_dfilter, width, red, green, blue);
            }
        }
    }

    // draw the NAV lines last, so they appear on top of the packets
    qs.render(&p, rect(), rect());
}
