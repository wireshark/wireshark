/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef STOCKICONTOOLBUTTON_H
#define STOCKICONTOOLBUTTON_H

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
     * @param stock_icon_name The name of the stock icon to display.
     */
    explicit StockIconToolButton(QWidget * parent = 0, QString stock_icon_name = QString());

    /**
     * @brief Sets the icon mode.
     * @param mode The QIcon mode to set.
     */
    void setIconMode(QIcon::Mode mode = QIcon::Normal);

    /**
     * @brief Sets the stock icon by name.
     * @param icon_name The name of the stock icon.
     */
    void setStockIcon(QString icon_name = QString());

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

#endif // STOCKICONTOOLBUTTON_H
