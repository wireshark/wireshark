/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PREFERENCES_PAGE_BUTTONS_H
#define PREFERENCES_PAGE_BUTTONS_H

#include <QAbstractButton>
#include <QList>


/**
 * @brief Interface for a Preferences dialog page with buttons of its own.
 *
 * The dialog puts the buttons in its button bar and shows them only
 * while the page is the current page.
 */
class PreferencesPageButtons
{
public:
    virtual ~PreferencesPageButtons() = default;

    /**
     * @brief The buttons this page shows in the dialog's button bar.
     * @return The buttons, or an empty list when the page has none.
     */
    const QList<QAbstractButton *> &pageButtons() const { return page_buttons_; }

protected:
    /**
     * @brief Adds a button for the dialog's button bar.
     *
     * The button is hidden; the dialog shows it while the page is current.
     */
    void addPageButton(QAbstractButton *button)
    {
        button->hide();
        page_buttons_ << button;
    }

private:
    QList<QAbstractButton *> page_buttons_;
};

#endif // PREFERENCES_PAGE_BUTTONS_H
