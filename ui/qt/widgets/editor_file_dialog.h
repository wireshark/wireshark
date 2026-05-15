/** @file
 *
 * File dialog that can be used as an "inline editor" in a table
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef EDITOR_FILE_DIALOG_H_
#define EDITOR_FILE_DIALOG_H_

#include <QModelIndex>
#include <QLineEdit>
#include <QFileDialog>
#include <QPushButton>

/**
 * @brief A QLineEdit combined with a file dialog button, designed for use as a table cell editor.
 */
class EditorFileDialog : public QLineEdit
{
    Q_OBJECT
public:
    /**
     * @brief Determines whether the dialog selects files or directories.
     */
    enum FileMode {
        ExistingFile, /**< Mode for selecting an existing file. */
        Directory     /**< Mode for selecting a directory. */
    };

    /**
     * @brief Constructs a new EditorFileDialog.
     * @param index The model index of the table cell being edited.
     * @param mode The selection mode (file or directory).
     * @param parent The parent widget, defaults to 0.
     * @param caption The title of the file dialog, defaults to empty.
     * @param directory The initial directory to open, defaults to empty.
     * @param filter The file filter string, defaults to empty.
     */
    explicit EditorFileDialog(const QModelIndex& index, enum FileMode mode, QWidget* parent = 0, const QString & caption = QString(), const QString & directory = QString(), const QString & filter = QString());

    /**
     * @brief Sets or unsets a QFileDialog option.
     * @param option The option to configure.
     * @param on True to enable the option, false to disable (defaults to true).
     */
    void setOption(QFileDialog::Option option, bool on = true);

    /**
     * @brief Handles focus in events.
     * @param event The focus event.
     */
    virtual void focusInEvent(QFocusEvent *event);

    /**
     * @brief Handles focus out events.
     * @param event The focus event.
     */
    virtual void focusOutEvent(QFocusEvent *event);

    /**
     * @brief Event filter to monitor specific events on the widget or its children.
     * @param obj The object receiving the event.
     * @param event The event being filtered.
     * @return True if the event was filtered out, false otherwise.
     */
    virtual bool eventFilter(QObject *obj, QEvent *event);

signals:
    /**
     * @brief Signal emitted to accept the edit and update the model.
     * @param index The model index of the cell that was edited.
     */
    void acceptEdit(const QModelIndex& index);

private slots:
    /**
     * @brief Slot triggered to open the file dialog and apply the selected filename.
     */
    void applyFilename();

protected:
    /**
     * @brief Handles resize events to adjust the layout of the line edit and button.
     */
    void resizeEvent(QResizeEvent *);

    /** Pointer to the button that triggers the file dialog. */
    QPushButton* file_dialog_button_;

    /** The saved model index of the table cell being edited. */
    const QModelIndex index_;

    /** The configured file selection mode. */
    enum FileMode mode_;

    /** The title caption of the file dialog. */
    QString caption_;

    /** The initial directory for the file dialog. */
    QString directory_;

    /** The file filter string for the file dialog. */
    QString filter_;

    /** The configured options for the file dialog. */
    QFileDialog::Options options_;
};

#endif /* EDITOR_FILE_DIALOG_H_ */
