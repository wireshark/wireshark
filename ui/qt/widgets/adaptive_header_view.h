/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ADAPTIVE_HEADERVIEW_H_
#define ADAPTIVE_HEADERVIEW_H_

#include <QHeaderView>

class QEvent;

/**
 * @brief QHeaderView subclass that adapts its size based on the font.
 *
 * This class ensures that the header height is updated when the font changes,
 * providing a consistent appearance even when the font is zoomable.
 *
 * The font is still set through the parent (PacketList in the case of the packet list header),
 * so that it is shared with the rest of the UI. This class simply ensures that the header height
 * is updated when the font changes, by overriding sizeHint and responding to font change events.
 *
 * We could instead register directly with FontManager and update the size hint when the font
 * changes, but that would require a bigger redesign.
 */
class AdaptiveHeaderView : public QHeaderView
{
    Q_OBJECT
public:

    /**
     * @brief Constructs an AdaptiveHeaderView.
     * @param orientation The orientation of the header.
     * @param parent The parent widget.
     */
    AdaptiveHeaderView(Qt::Orientation orientation, QWidget *parent = nullptr);


    /**
     * @brief Overriding sizeHint to provide proper heights when font changes
     *
     * Starting with 5.x the regular font is zoomable and therefore the header can
     * change its height. This override ensures that the header height is updated
     * when the font changes.
     *
     * @return QSize the size of the header view
     */
    virtual QSize sizeHint() const override;

protected:

    virtual void changeEvent(QEvent *event) override;
};

#endif /* ADAPTIVE_HEADERVIEW_H_ */