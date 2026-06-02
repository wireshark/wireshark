/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QToolButton>

/**
 * @brief A tool button that displays a stock icon.
 */
class StockIconToolButton : public QToolButton
{
public:
    /**
     * @brief Constructs a new StockIconToolButton object.
     * @param parent The parent widget.
     * @param icon_name The name of the themed icon to display.
     */
    explicit StockIconToolButton(QWidget * parent = 0, QString icon_name = QString());

    /**
     * @brief Sets the themed icon by name. The base resource
     * name must exist in the ":/svg_icons/" resource path.
     * @param icon_name The name of the themed icon.
     */
    void setIconByName(QString icon_name = QString());

protected:
    /**
     * @brief Handles generic events for the tool button.
     * @param event The event object.
     * @return True if the event was handled, false otherwise.
     */
    virtual bool event(QEvent *event) override;

private:
    /** @brief The base icon object. */
    QIcon base_icon_;

    /** @brief The name of the currently set icon. */
    QString icon_name_;
};
