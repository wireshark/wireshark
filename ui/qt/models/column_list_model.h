/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef COLUMN_LIST_MODELS_H
#define COLUMN_LIST_MODELS_H

#include <QAbstractListModel>
#include <QSortFilterProxyModel>
#include <QStyledItemDelegate>
#include <QSortFilterProxyModel>
#include <QMimeData>

/**
 * @brief Proxy model for filtering and sorting the packet list column models.
 */
class ColumnProxyModel : public QSortFilterProxyModel
{
public:
    /**
     * @brief Constructs a new ColumnProxyModel.
     * @param parent The parent QObject, defaults to Q_NULLPTR.
     */
    ColumnProxyModel(QObject *parent = Q_NULLPTR);

    /**
     * @brief Sets whether to show only the displayed columns.
     * @param set True to show only displayed columns, false otherwise.
     */
    void setShowDisplayedOnly(bool set);

protected:
    /**
     * @brief Determines whether a specific row is accepted by the filter.
     * @param source_row The row index in the source model.
     * @param source_parent The parent model index in the source model.
     * @return True if the row is accepted, false otherwise.
     */
    virtual bool filterAcceptsRow(int source_row, const QModelIndex &source_parent) const override;

private:
    /** Flag indicating if only displayed columns should be shown. */
    bool showDisplayedOnly_;
};

/**
 * @brief A delegate for rendering and editing column types and properties in a view.
 */
class ColumnTypeDelegate : public QStyledItemDelegate
{
public:
    /**
     * @brief Constructs a new ColumnTypeDelegate.
     * @param parent The parent QObject, defaults to Q_NULLPTR.
     */
    ColumnTypeDelegate(QObject * parent = Q_NULLPTR);

    /**
     * @brief Retrieves the display description for a given display format character.
     * @param display The format character.
     * @return The descriptive string.
     */
    static QString displayDesc(char display);

    /**
     * @brief Retrieves the alignment description for a given alignment character.
     * @param xalign The alignment character.
     * @return The descriptive alignment string.
     */
    static QString alignDesc(char xalign);

    /**
     * @brief Creates an editor widget for a given index.
     * @param parent The parent widget.
     * @param option The style options for the view item.
     * @param index The model index being edited.
     * @return A pointer to the created editor widget.
     */
    QWidget * createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                           const QModelIndex &index) const override;

    /**
     * @brief Sets the data for the editor from the model.
     * @param editor The editor widget.
     * @param index The model index containing the data.
     */
    void setEditorData(QWidget *editor, const QModelIndex &index) const override;

    /**
     * @brief Sets the data in the model from the editor.
     * @param editor The editor widget containing the modified data.
     * @param model The abstract item model to update.
     * @param index The model index being updated.
     */
    void setModelData(QWidget *editor, QAbstractItemModel *model,
                      const QModelIndex &index) const override;

    /**
     * @brief Updates the geometry of the editor widget based on available space.
     * @param editor The editor widget.
     * @param option The style options detailing available space.
     * @param index The model index being edited.
     */
    void updateEditorGeometry(QWidget *editor, const QStyleOptionViewItem &option,
                              const QModelIndex &index) const override;
};

/**
 * @brief A table model for managing the list of packet list columns.
 */
class ColumnListModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new ColumnListModel.
     * @param parent The parent QObject, defaults to Q_NULLPTR.
     */
    ColumnListModel(QObject * parent = Q_NULLPTR);

    /**
     * @brief Enumeration of column identifiers in the column list model.
     */
    enum {
        COL_DISPLAYED,  /**< Column showing whether the column is currently displayed. */
        COL_TITLE,      /**< Column showing the column title. */
        COL_TYPE,       /**< Column showing the column type. */
        COL_FIELDS,     /**< Column showing the field names used in the column. */
        COL_OCCURRENCE, /**< Column showing the occurrence index of the field. */
        COL_DISPLAY,    /**< Column showing the display format mapping. */
        COL_WIDTH,      /**< Column showing the width property. */
        COL_XALIGN      /**< Column showing the alignment property. */
    };

    /**
     * @brief Enumeration of custom roles used in the column list model.
     */
    enum {
        OriginalType = Qt::UserRole, /**< Role for the original, unmodified column type. */
        DisplayedState               /**< Role for querying the internal displayed state. */
    };

    /**
     * @brief Checks whether the display options are enabled for the given index.
     * @param index The model index.
     * @param displayStrings Output boolean indicating if display strings are supported.
     * @param displayDetails Output boolean indicating if display details are supported.
     * @return True if display options are enabled, false otherwise.
     */
    static bool displayEnabled(const QModelIndex &index, bool &displayStrings, bool &displayDetails);

    /**
     * @brief Saves the current column list to the global configuration.
     */
    void saveColumns();

    /**
     * @brief Adds a new default entry to the end of the column list.
     */
    void addEntry();

    /**
     * @brief Deletes a specific entry from the column list.
     * @param row The row index to delete.
     */
    void deleteEntry(int row);

    /**
     * @brief Resets the column list to the default configuration.
     */
    void reset();

    /**
     * @brief Retrieves header data for the table model.
     * @param section The column or row section.
     * @param orientation The orientation of the header.
     * @param role The requested data role.
     * @return The header data.
     */
    virtual QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    /**
     * @brief Retrieves data from the model.
     * @param index The model index.
     * @param role The requested data role.
     * @return The data associated with the index and role.
     */
    virtual QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    /**
     * @brief Retrieves the number of rows in the model.
     * @param parent The parent model index.
     * @return The number of rows.
     */
    virtual int rowCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Retrieves the number of columns in the model.
     * @param parent The parent model index.
     * @return The number of columns.
     */
    virtual int columnCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Retrieves the item flags for a given index.
     * @param index The model index.
     * @return The valid item flags for the index.
     */
    virtual Qt::ItemFlags flags(const QModelIndex &index) const override;

    /**
     * @brief Retrieves the supported MIME types for drag and drop operations.
     * @return A list of supported MIME type strings.
     */
    virtual QStringList mimeTypes() const override;

    /**
     * @brief Generates MIME data for the specified list of indexes.
     * @param indexes The list of indexes to generate data for.
     * @return A pointer to the generated QMimeData.
     */
    virtual QMimeData *mimeData(const QModelIndexList &indexes) const override;

    /**
     * @brief Specifies the supported drag and drop actions.
     * @return The supported drop actions.
     */
    virtual Qt::DropActions supportedDropActions() const override;

    /**
     * @brief Checks if MIME data can be dropped at a specific location.
     * @param data The MIME data being dropped.
     * @param action The drop action.
     * @param row The target row for the drop.
     * @param column The target column for the drop.
     * @param parent The target parent model index.
     * @return True if the drop is allowed, false otherwise.
     */
    virtual bool canDropMimeData(const QMimeData *data, Qt::DropAction action, int row, int column, const QModelIndex &parent) const override;

    /**
     * @brief Handles dropped MIME data to rearrange rows.
     * @param data The MIME data dropped.
     * @param action The drop action.
     * @param row The target row.
     * @param column The target column.
     * @param parent The target parent index.
     * @return True if the drop was successfully processed, false otherwise.
     */
    virtual bool dropMimeData(const QMimeData *data, Qt::DropAction action, int row, int column, const QModelIndex &parent) override;

    /**
     * @brief Sets data in the model for the given index and role.
     * @param index The model index to update.
     * @param value The value to set.
     * @param role The data role being set.
     * @return True if the data was successfully updated, false otherwise.
     */
    virtual bool setData(const QModelIndex &index, const QVariant &value, int role = Qt::EditRole) override;

private:
    /**
     * @brief Retrieves the title for a specific header section.
     * @param section The column section.
     * @return The header title string.
     */
    QString headerTitle(int section) const;

    /**
     * @brief Populates the model with the initial set of columns from the configuration.
     */
    void populate();
};

#endif // COLUMN_LIST_MODELS_H
