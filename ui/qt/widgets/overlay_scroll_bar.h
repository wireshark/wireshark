/* overlay_scroll_bar.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __OVERLAY_SCROLL_BAR_H__
#define __OVERLAY_SCROLL_BAR_H__

#include <QScrollBar>
#include <QProxyStyle>

class OverlayScrollBar : public QScrollBar
{
    Q_OBJECT

public:
    OverlayScrollBar(Qt::Orientation orientation, QWidget * parent = 0);
    virtual ~OverlayScrollBar();

    virtual QSize sizeHint() const;

    /** Set the "near" overlay image.
     * @param overlay_image An image containing a 1:1 mapping of nearby
     *        packet colors to raster lines. It should be sized in device
     *        pixels.
     * @param packet_count Number of packets.
     * @param start_pos The first packet number represented by the image.
     *        -1 means no packet is selected.
     * @param end_pos The last packet number represented by the image. -1
     *        means no packet is selected.
     * @param positions The positions of the selected packets within the
     *        image.
     */
    void setNearOverlayImage(QImage &overlay_image, int packet_count = -1, int start_pos = -1, int end_pos = -1, QList<int> positions = QList<int>());

    /** Set the "far" overlay image.
     * @param mp_image An image showing the position of marked, ignored,
     *        and reference time packets over the entire packet list. It
     *        should be sized in device pixels.
     */
    void setMarkedPacketImage(QImage &mp_image);


    /** The "groove" area of the child scrollbar.
     */
    QRect grooveRect();

public slots:
    void setChildRange(int min, int max) { child_sb_.setRange(min, max); }

protected:
    virtual void resizeEvent(QResizeEvent * event);
    virtual void paintEvent(QPaintEvent * event);
    virtual bool eventFilter(QObject *watched, QEvent *event);
    virtual void mousePressEvent(QMouseEvent *) { /* No-op */ }
    virtual void mouseReleaseEvent(QMouseEvent * event);

private:
    QProxyStyle* style_;
    QProxyStyle* child_style_;
    QScrollBar child_sb_;
    QImage packet_map_img_;
    QImage marked_packet_img_;
    int packet_map_width_;
    int marked_packet_width_;
    int packet_count_;
    int start_pos_;
    int end_pos_;
    QList<int> positions_;

};

#endif // __OVERLAY_SCROLL_BAR_H__

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
