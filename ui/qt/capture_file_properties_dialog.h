/** @file
 *
 * GSoC 2013 - QtShark
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CAPTURE_FILE_PROPERTIES_DIALOG_H
#define CAPTURE_FILE_PROPERTIES_DIALOG_H

#include <config.h>

#include <string.h>
#include <time.h>

#include <epan/strutil.h>
#include <wiretap/wtap.h>

#include "file.h"

#ifdef HAVE_LIBPCAP
    #include "ui/capture.h"
    #include "ui/capture_globals.h"
#endif

#include "wireshark_dialog.h"

#include <QClipboard>

namespace Ui {
class CaptureFilePropertiesDialog;
}

class QAbstractButton;

/**
 * @brief A dialog for displaying and modifying properties and statistics of a capture file.
 */
class CaptureFilePropertiesDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new CaptureFilePropertiesDialog.
     * @param parent The parent widget.
     * @param capture_file The capture file whose properties are to be displayed.
     */
    explicit CaptureFilePropertiesDialog(QWidget &parent, CaptureFile& capture_file);

    /**
     * @brief Destroys the CaptureFilePropertiesDialog.
     */
    virtual ~CaptureFilePropertiesDialog();

protected:
    /**
     * @brief Retrieves the start text string for the dialog.
     * @return The start text string.
     */
    virtual QString getStartTextString() const;

    /**
     * @brief Retrieves the string representing the first item.
     * @return The first item string.
     */
    virtual QString getFirstItemString() const;

    /**
     * @brief Retrieves the string representing the last item.
     * @return The last item string.
     */
    virtual QString getLastItemString() const;

    /**
     * @brief Retrieves the end text string for the dialog.
     * @return The end text string.
     */
    virtual QString getEndTextString() const;

    /**
     * @brief Retrieves the string indicating dropped items.
     * @return The dropped item string.
     */
    virtual QString getDroppedItemString() const;

    /**
     * @brief Retrieves the string displaying the item size limit.
     * @return The item size limit string.
     */
    virtual QString getItemSizeLimitString() const;

    /**
     * @brief Retrieves the title string for the row.
     * @return The row title string.
     */
    virtual QString getRowTitleString() const;

    /**
     * @brief Retrieves the string displaying the average item size.
     * @return The average item size string.
     */
    virtual QString getAvgItemSizeString() const;

    /**
     * @brief Retrieves the string associated with the item comment.
     * @return The item comment string.
     */
    virtual QString getItemCommentString() const;

    /**
     * @brief Retrieves the string showing who created the file or capture.
     * @return The creator string.
     */
    virtual QString getCreatedByString() const;

signals:
    /**
     * @brief Signal emitted when a capture comment has been changed.
     */
    void captureCommentChanged();

protected slots:
    /**
     * @brief Handles state change events for the dialog.
     * @param event The event to handle.
     */
    void changeEvent(QEvent* event);

private:
    /** Pointer to the generated UI elements. */
    Ui::CaptureFilePropertiesDialog *ui;

    /**
     * @brief Converts the capture summary properties to an HTML formatted string.
     * @return The HTML formatted summary string.
     */
    QString summaryToHtml();

    /**
     * @brief Fills the dialog with details extracted from the capture file.
     */
    void fillDetails();

private slots:
    /**
     * @brief Slot triggered to update the state of the dialog's widgets.
     */
    void updateWidgets();

    /**
     * @brief Slot triggered to add a capture comment.
     */
    void addCaptureComment();

    /**
     * @brief Slot triggered when the help button is requested from the button box.
     */
    void on_buttonBox_helpRequested();

    /**
     * @brief Slot triggered when a button in the button box is clicked.
     * @param button The abstract button that was clicked.
     */
    void on_buttonBox_clicked(QAbstractButton *button);

    /**
     * @brief Slot triggered when the dialog is rejected (e.g., Cancel is clicked).
     */
    void on_buttonBox_rejected();
};

#endif
