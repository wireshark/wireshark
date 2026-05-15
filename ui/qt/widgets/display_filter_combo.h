/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DISPLAY_FILTER_COMBO_H
#define DISPLAY_FILTER_COMBO_H

#include <QComboBox>
#include <QList>

/**
 * @brief A combo box widget tailored for entering, evaluating, and storing display filters.
 */
class DisplayFilterCombo : public QComboBox
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new DisplayFilterCombo widget.
     * @param parent The parent widget, defaults to 0.
     */
    explicit DisplayFilterCombo(QWidget *parent = 0);

    /**
     * @brief Adds a display filter to the list of recently used captures.
     * @param filter The filter string to add.
     * @return True if the filter was successfully added, false otherwise.
     */
    bool addRecentCapture(const char *filter);

    /**
     * @brief Writes the list of recent display filters to a given file handle.
     * @param rf Pointer to the open file where recent filters will be written.
     */
    void writeRecent(FILE *rf);

    /**
     * @brief Updates the widget's style sheet based on its current syntax validation state.
     */
    void updateStyleSheet();

protected:
    /**
     * @brief Handles the insertion of rows into the combo box's model.
     * @param first The starting row index.
     * @param last The ending row index.
     */
    void rowsInserted(const QModelIndex&, int first, int last);

    /**
     * @brief Handles general events directed to the combo box.
     * @param event The event to be handled.
     * @return True if the event was handled successfully, false otherwise.
     */
    virtual bool event(QEvent *event);

private:

public slots:
    /**
     * @brief Validates the syntax of the currently entered display filter.
     * @return True if the filter syntax is valid, false otherwise.
     */
    bool checkDisplayFilter();

    /**
     * @brief Applies the currently entered display filter.
     */
    void applyDisplayFilter();

    /**
     * @brief Sets the text of the display filter input.
     * @param filter The display filter string to set.
     */
    void setDisplayFilter(QString filter);

private slots:
    /**
     * @brief Updates the maximum count of items allowed in the recent filter list.
     */
    void updateMaxCount();

    /**
     * @brief Slot triggered when a filter is applied elsewhere, ensuring the combo box stays synced.
     * @param filter The applied filter string.
     * @param force True to force the update even if conditions might otherwise skip it.
     */
    void filterApplied(QString filter, bool force);
};

#endif // DISPLAY_FILTER_COMBO_H
