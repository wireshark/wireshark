/* overlay_scroll_bar.h
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

#ifndef __OVERLAY_SCROLL_BAR_H__
#define __OVERLAY_SCROLL_BAR_H__

#include <QScrollBar>

class OverlayScrollBar : public QScrollBar
{
    Q_OBJECT

public:
    OverlayScrollBar(Qt::Orientation orientation, QWidget * parent = 0);

    virtual QSize sizeHint() const;

    /** Set the "near" overlay image.
     * @param overlay_image An image containing a 1:1 mapping of nearby
     *        packet colors to raster lines.
     * @param selected_pos The position of the selected packet within the
     *        image. -1 means no packet is selected.
     */
    void setNearOverlayImage(QImage &overlay_image, int selected_pos = -1);

    /** Set the "far" overlay image.
     * @param overlay_image An image showing the position of marked, ignored,
     *        and reference time packets over the entire packet list.
     */
    void setFarOverlayImage(QImage &overlay_image);
    QRect grooveRect();

protected:
    virtual void paintEvent(QPaintEvent * event);

private:
    QImage near_overlay_;
    QImage far_overlay_;
    int selected_pos_;
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
