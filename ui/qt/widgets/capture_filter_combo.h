/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CAPTURE_FILTER_COMBO_H
#define CAPTURE_FILTER_COMBO_H

#include <ui/qt/widgets/capture_filter_edit.h>

#include <QComboBox>
#include <QList>

/**
 * @brief A combo box widget for entering and selecting capture filters, providing a history of recently used filters.
 */
class CaptureFilterCombo : public QComboBox
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new CaptureFilterCombo widget.
     * @param parent The parent widget, defaults to 0.
     * @param plain If true, creates a plain combo box without extended editing features; defaults to false.
     */
    explicit CaptureFilterCombo(QWidget *parent = 0, bool plain = false);

    /**
     * @brief Adds a filter to the list of recently used capture filters.
     * @param filter The capture filter string to add.
     * @return True if the filter was successfully added, false otherwise.
     */
    bool addRecentCapture(const char *filter);

    /**
     * @brief Writes the recent capture filters to the provided file.
     * @param rf Pointer to the open file to write the recent filters to.
     */
    void writeRecent(FILE *rf);

    /**
     * @brief Sets the conflict state of the capture filter edit widget.
     * @param conflict True to indicate a conflict state, false otherwise (defaults to false).
     */
    void setConflict(bool conflict = false) { cf_edit_->setConflict(conflict); }

signals:
    /**
     * @brief Signal emitted when the available network interfaces change.
     */
    void interfacesChanged();

    /**
     * @brief Signal emitted when the validity of the current capture filter syntax changes.
     * @param valid True if the current filter syntax is valid, false otherwise.
     */
    void captureFilterSyntaxChanged(bool valid);

    /**
     * @brief Signal emitted to request starting a packet capture.
     */
    void startCapture();

protected:
    /**
     * @brief Handles general events directed to the combo box.
     * @param event The event to be handled.
     * @return True if the event was handled successfully, false otherwise.
     */
    virtual bool event(QEvent *event);

private:
    /**
     * @brief Updates the widget's style sheet based on its current state.
     */
    void updateStyleSheet();

    /** Pointer to the underlying capture filter line edit widget. */
    CaptureFilterEdit *cf_edit_;

private slots:
    /**
     * @brief Slot triggered to save the current filter and rebuild the list of recent filters.
     */
    void saveAndRebuildFilterList();

    /**
     * @brief Slot triggered to reconstruct the drop-down list of recent filters.
     */
    void rebuildFilterList();
};

#endif // CAPTURE_FILTER_COMBO_H
