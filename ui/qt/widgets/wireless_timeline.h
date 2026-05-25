/** @file
 *
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

#include <QScrollArea>

#ifndef WIRELESSTIMELINE_H
#define WIRELESSTIMELINE_H

#include <stdio.h>

#include <config.h>

#include "file.h"

#include "ui/ws_ui_util.h"

#include <epan/prefs.h>
//#include <epan/plugin_if.h>
#include <epan/tap.h>
#include <epan/timestamp.h>

#include <epan/dissectors/packet-ieee80211-radio.h>

#include <QScrollArea>

#include <epan/cfile.h>

/* pixels height for rendered timeline */
#define TIMELINE_HEIGHT 64

/* Maximum zoom levels for the timeline */
#define TIMELINE_MAX_ZOOM 25.0

class WirelessTimeline;
class PacketList;

/**
 * @brief Widget that renders a time-domain timeline of 802.11 wireless frames,
 *        enabling navigation, selection, zooming, and per-packet radio metadata
 *        visualisation for a captured WLAN session.
 */
class WirelessTimeline : public QWidget
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the WirelessTimeline widget.
     * @param parent Parent widget; must not be @c nullptr.
     */
    explicit WirelessTimeline(QWidget *parent);

    /**
     * @brief Destroys the timeline widget and frees associated tap and radio data.
     */
    ~WirelessTimeline();

    /**
     * @brief Associates the packet list view used for frame selection and navigation.
     * @param packet_list Pointer to the main PacketList widget.
     */
    void setPacketList(PacketList *packet_list);

    /**
     * @brief Registers the wireless timeline tap and prepares for incoming packet data.
     * @param cf The capture file being read.
     */
    void captureFileReadStarted(capture_file *cf);

    /**
     * @brief Finalises timeline state after all packets have been read and triggers
     *        an initial repaint.
     */
    void captureFileReadFinished();

protected:
    /**
     * @brief Recalculates layout parameters when the widget is resized.
     * @param event The resize event containing old and new sizes.
     */
    void resizeEvent(QResizeEvent *event) override;

    /**
     * @brief Renders the wireless timeline, colouring each pixel column according
     *        to the radio properties of the frame occupying that time slot.
     * @param event The paint event describing the region to update.
     */
    void paintEvent(QPaintEvent *event) override;

    /**
     * @brief Begins a pan or selection drag operation on button press.
     * @param event The mouse press event.
     */
    void mousePressEvent(QMouseEvent *event) override;

    /**
     * @brief Pans the visible time range while the mouse button is held and moved.
     * @param event The mouse move event.
     */
    void mouseMoveEvent(QMouseEvent *event) override;

    /**
     * @brief Finalises a pan or selection drag on button release.
     * @param event The mouse release event.
     */
    void mouseReleaseEvent(QMouseEvent *event) override;

    /**
     * @brief Handles tooltip requests and other non-standard events.
     * @param event The event to process.
     * @return @c true if the event was handled; @c false otherwise.
     */
    bool event(QEvent *event) override;

    /**
     * @brief Zooms the visible time range in or out in response to the scroll wheel.
     * @param event The wheel event.
     */
    void wheelEvent(QWheelEvent *event) override;

public slots:
    /**
     * @brief Triggers a partial repaint after background colourisation completes for
     *        the given packet range.
     * @param first Index of the first packet whose colourisation changed.
     * @param last  Index of the last packet whose colourisation changed.
     */
    void bgColorizationProgress(int first, int last);

    /**
     * @brief Called once the application has finished initialising; registers the
     *        wireless tap and performs any deferred setup.
     */
    void appInitialized();

protected:
    /**
     * @brief Tap reset callback; clears all accumulated radio packet data.
     * @param tapdata Pointer to the WirelessTimeline instance acting as tap data.
     */
    static void tap_timeline_reset(void *tapdata);

    /**
     * @brief Tap packet callback; extracts and stores wlan_radio metadata for each frame.
     * @param tapdata Pointer to the WirelessTimeline instance acting as tap data.
     * @param pinfo   Packet info for the current frame.
     * @param edt     Epan dissect tree for the current frame.
     * @param data    Protocol-specific tap data (wlan_radio struct).
     * @param flags   Tap flags for this packet.
     * @return TAP_PACKET_REDRAW if the display should be updated; TAP_PACKET_DONT_REDRAW otherwise.
     */
    static tap_packet_status tap_timeline_packet(void *tapdata, packet_info *pinfo,
                                                  epan_dissect_t *edt, const void *data,
                                                  tap_flags_t flags);

    /**
     * @brief Looks up the wlan_radio record for a given packet number.
     * @param packet_num One-based packet number to look up.
     * @return Pointer to the wlan_radio structure, or @c nullptr if not found.
     */
    struct wlan_radio *get_wlan_radio(uint32_t packet_num);

    /**
     * @brief Clamps start_tsf and end_tsf to the valid range of the capture file.
     */
    void clip_tsf();

    /**
     * @brief Converts a TSF timestamp to an x pixel position within the widget.
     * @param tsf   TSF timestamp value to convert.
     * @param ratio Pixels-per-microsecond scaling ratio for the current zoom level.
     * @return Pixel x coordinate corresponding to @p tsf.
     */
    int position(uint64_t tsf, float ratio);

    /**
     * @brief Finds the packet whose TSF timestamp is closest to the given value.
     * @param tsf TSF timestamp to search for.
     * @return One-based packet number of the nearest matching packet.
     */
    int find_packet_tsf(uint64_t tsf);

    /**
     * @brief Builds and displays a tooltip for a specific frame at the given position.
     * @param wr  wlan_radio data for the frame under the cursor.
     * @param pos Global screen position for the tooltip.
     * @param x   Widget-local x coordinate of the cursor.
     */
    void doToolTip(struct wlan_radio *wr, QPoint pos, int x);

    /**
     * @brief Zooms the visible time range, keeping the given x fraction stationary.
     * @param x_fraction Normalised [0, 1] horizontal position that should remain fixed
     *                   during the zoom.
     */
    void zoom(double x_fraction);

    double zoom_level;    /**< Current zoom level; higher values show a narrower time range. */
    qreal  start_x;       /**< Widget-local x coordinate where the current drag started. */
    qreal  last_x;        /**< Widget-local x coordinate of the last drag mouse position. */

    PacketList *packet_list; /**< Associated packet list widget used for frame selection. */

    /**
     * @brief Returns the packet number of the frame at the given x pixel coordinate.
     * @param x Widget-local x coordinate to query.
     * @return One-based packet number of the frame at @p x, or 0 if none.
     */
    unsigned find_packet(qreal x);

    float rgb[TIMELINE_HEIGHT][3]; /**< Per-row RGB colour buffer used to render the timeline. */

    uint64_t start_tsf;    /**< TSF timestamp of the left edge of the visible time range. */
    uint64_t end_tsf;      /**< TSF timestamp of the right edge of the visible time range. */
    int first_packet;      /**< One-based index of the first packet visible in the current view. */

    struct wlan_radio *first; /**< wlan_radio record for the earliest frame in the capture. */
    struct wlan_radio *last;  /**< wlan_radio record for the latest frame in the capture. */

    capture_file *capfile;    /**< The currently open capture file. */

    GHashTable *radio_packet_list; /**< Hash table mapping packet numbers to wlan_radio records. */

protected slots:
    /**
     * @brief Scrolls the timeline to keep the selected frames visible and triggers a repaint.
     * @param frames List of selected frame numbers.
     */
    void selectedFrameChanged(QList<int> frames);
};

#endif // WIRELESS_TIMELINE_H
