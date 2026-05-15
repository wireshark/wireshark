/* path_chooser_delegate.cpp
 * Delegate to select a file path for a treeview entry
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PATH_SELECTOR_EDIT_H
#define PATH_SELECTOR_EDIT_H

#include <QWidget>
#include <QString>
#include <QLineEdit>
#include <QToolButton>

/**
 * @brief A widget for selecting a file or directory path.
 */
class PathSelectionEdit : public QWidget
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a PathSelectionEdit with specific parameters.
     * @param title The title for the browse dialog.
     * @param path The initial path.
     * @param selectFile True to select a file, false to select a directory.
     * @param parent The parent widget.
     */
    PathSelectionEdit(QString title, QString path, bool selectFile, QWidget *parent = 0);

    /**
     * @brief Constructs a default PathSelectionEdit.
     * @param parent The parent widget.
     */
    PathSelectionEdit(QWidget *parent = 0);

    /**
     * @brief Gets the currently selected path.
     * @return The current path string.
     */
    QString path() const;

public slots:
    /**
     * @brief Sets a new path programmatically.
     * @param newPath The new path to set.
     */
    void setPath(QString newPath = QString());

signals:
    /**
     * @brief Signal emitted when the path changes.
     * @param newPath The newly selected path.
     */
    void pathChanged(QString newPath);

protected slots:
    /**
     * @brief Opens a dialog to browse for a path.
     */
    void browseForPath();

private:
    QString _title; /**< The title for the browse dialog. */
    QString _path; /**< The currently selected path. */
    bool _selectFile; /**< Flag indicating whether to select a file (true) or directory (false). */

    QLineEdit * _edit; /**< The line edit displaying the path. */
    QToolButton * _button; /**< The button used to open the browse dialog. */
};
#endif // PATH_SELECTOR_EDIT_H
