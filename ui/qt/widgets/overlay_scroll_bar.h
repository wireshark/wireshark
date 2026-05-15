/** @file
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

class QProxyStyle;

/**
 * @brief A custom scroll bar with overlay images for packet representation.
 */
class OverlayScrollBar : public QScrollBar
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new OverlayScrollBar.
     * @param orientation The scroll bar orientation.
     * @param parent The parent widget, defaults to 0.
     */
    OverlayScrollBar(Qt::Orientation orientation, QWidget * parent = 0);

    /**
     * @brief Destroys the OverlayScrollBar.
     */
    virtual ~OverlayScrollBar();

    /**
     * @brief Returns the recommended size for the scroll bar.
     * @return The size hint as a QSize.
     */
    virtual QSize sizeHint() const;

    /**
     * @brief Retrieves the current slider position.
     * @return The slider position.
     */
    virtual int sliderPosition();

    /**
     * @brief Set the "near" overlay image.
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
     * @param rowHeight The row height to be used for displaying the mark
     */
    void setNearOverlayImage(QImage &overlay_image, int packet_count = -1, int start_pos = -1, int end_pos = -1, QList<int> positions = QList<int>(), int rowHeight = 1);

    /**
     * @brief Set the "far" overlay image.
     * @param mp_image An image showing the position of marked, ignored,
     *        and reference time packets over the entire packet list. It
     *        should be sized in device pixels.
     */
    void setMarkedPacketImage(QImage &mp_image);

    /**
     * @brief Retrieves the "groove" area of the child scrollbar.
     * @return The rectangle defining the groove area.
     */
    QRect grooveRect();

public slots:
    /**
     * @brief Sets the range of the child scroll bar.
     * @param min The minimum value.
     * @param max The maximum value.
     */
    void setChildRange(int min, int max) { child_sb_.setRange(min, max); }

protected:
    /**
     * @brief Handles resize events.
     * @param event The resize event.
     */
    virtual void resizeEvent(QResizeEvent * event);

    /**
     * @brief Handles paint events.
     * @param event The paint event.
     */
    virtual void paintEvent(QPaintEvent * event);

    /**
     * @brief Filters events for watched objects.
     * @param watched The watched object.
     * @param event The event to filter.
     * @return True if the event was filtered, false otherwise.
     */
    virtual bool eventFilter(QObject *watched, QEvent *event);

    /**
     * @brief Handles mouse press events (no-op).
     */
    virtual void mousePressEvent(QMouseEvent *) { /* No-op */ }

    /**
     * @brief Handles mouse release events.
     * @param event The mouse release event.
     */
    virtual void mouseReleaseEvent(QMouseEvent * event);

private:
    /** The main proxy style for the scrollbar. */
    QProxyStyle* style_;

    /** The proxy style for the child scrollbar. */
    QProxyStyle* child_style_;

    /** The child scrollbar widget. */
    QScrollBar child_sb_;

    /** Image representing the packet map. */
    QImage packet_map_img_;

    /** Image representing marked packets. */
    QImage marked_packet_img_;

    /** Width of the packet map image. */
    int packet_map_width_;

    /** Width of the marked packet image. */
    int marked_packet_width_;

    /** Total number of packets. */
    int packet_count_;

    /** Starting position for the overlay image. */
    int start_pos_;

    /** Ending position for the overlay image. */
    int end_pos_;

    /** List of positions for selected packets. */
    QList<int> positions_;

    /** Height of a single row. */
    int row_height_;

#if QT_VERSION >= QT_VERSION_CHECK(6, 1, 0)
    /**
     * @brief Updates the style of the child scrollbar.
     */
    void updateChildStyle();
#endif
};

#endif // __OVERLAY_SCROLL_BAR_H__
