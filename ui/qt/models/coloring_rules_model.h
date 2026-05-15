/** @file
 *
 * Data model for coloring rules.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef COLORING_RULES_MODEL_H
#define COLORING_RULES_MODEL_H

#include <config.h>

#include <epan/color_filters.h>

#include <ui/qt/models/tree_model_helpers.h>

#include <QList>
#include <QColor>
#include <QAbstractTableModel>
#include <QSortFilterProxyModel>

/**
 * @brief Represents a single coloring rule item in a tree model.
 */
class ColoringRuleItem : public ModelHelperTreeItem<ColoringRuleItem>
{
public:
    /**
     * @brief Constructs a new ColoringRuleItem.
     * @param disabled True if the rule is disabled.
     * @param name The name of the rule.
     * @param filter The filter string for the rule.
     * @param foreground The foreground color.
     * @param background The background color.
     * @param parent The parent rule item.
     */
    ColoringRuleItem(bool disabled, QString name, QString filter, QColor foreground, QColor background, ColoringRuleItem* parent);

    /**
     * @brief Destroys the ColoringRuleItem.
     */
    virtual ~ColoringRuleItem();

    /**
     * @brief Constructs a new ColoringRuleItem from a core color filter structure.
     * @param colorf Pointer to the core color filter.
     * @param parent The parent rule item.
     */
    ColoringRuleItem(color_filter_t *colorf, ColoringRuleItem* parent);

    /**
     * @brief Copy constructor for ColoringRuleItem.
     * @param item The item to copy.
     */
    ColoringRuleItem(const ColoringRuleItem& item);

    /** @brief Indicates if the rule is currently disabled. */
    bool disabled_;

    /** @brief The display name of the rule. */
    QString name_;

    /** @brief The display filter string associated with the rule. */
    QString filter_;

    /** @brief The foreground color applied by the rule. */
    QColor foreground_;

    /** @brief The background color applied by the rule. */
    QColor background_;

    /**
     * @brief Assignment operator for ColoringRuleItem.
     * @param rhs The item to assign from.
     * @return A reference to this item.
     */
    ColoringRuleItem& operator=(ColoringRuleItem& rhs);

};

/**
 * @brief A model managing the coloring rules for packet display.
 */
class ColoringRulesModel : public QAbstractItemModel
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new ColoringRulesModel.
     * @param defaultForeground The default foreground color.
     * @param defaultBackground The default background color.
     * @param parent The parent QObject.
     */
    ColoringRulesModel(QColor defaultForeground, QColor defaultBackground, QObject *parent);

    /**
     * @brief Destroys the ColoringRulesModel.
     */
    virtual ~ColoringRulesModel();

    /**
     * @brief Defines the columns used in the coloring rules model.
     */
    enum ColoringRulesColumn {
        colName = 0,            /**< The name column. */
        colFilter,              /**< The filter string column. */
        colColoringRulesMax     /**< The maximum number of columns. */
    };

    /**
     * @brief Adds a new color rule from a core color filter.
     * @param colorf Pointer to the core color filter structure.
     */
    void addColor(color_filter_t* colorf);

    /**
     * @brief Adds a new color rule with specified properties.
     * @param disabled True if the rule is disabled.
     * @param filter The filter string for the rule.
     * @param foreground The foreground color.
     * @param background The background color.
     */
    void addColor(bool disabled, QString filter, QColor foreground, QColor background);

    /**
     * @brief Imports coloring rules from a specified file.
     * @param filename The name of the file to import.
     * @param err Output string for error messages.
     * @return True if the import was successful, false otherwise.
     */
    bool importColors(QString filename, QString& err);

    /**
     * @brief Exports the current coloring rules to a file.
     * @param filename The name of the file to export to.
     * @param err Output string for error messages.
     * @return True if the export was successful, false otherwise.
     */
    bool exportColors(QString filename, QString& err);

    /**
     * @brief Writes the coloring rules to the internal configuration.
     * @param err Output string for error messages.
     * @return True if writing was successful, false otherwise.
     */
    bool writeColors(QString& err);

    /**
     * @brief Retrieves the item flags for a given index.
     * @param index The model index to query.
     * @return The item flags for the specified index.
     */
    Qt::ItemFlags flags(const QModelIndex &index) const;

    /**
     * @brief Retrieves data from the model for the given index and role.
     * @param index The model index to retrieve data for.
     * @param role The role for which data is requested.
     * @return The data associated with the index and role.
     */
    QVariant data(const QModelIndex &index, int role) const;

    /**
     * @brief Sets data in the model for the given index and role.
     * @param index The model index to update.
     * @param value The value to set.
     * @param role The role for which data is being set (defaults to Qt::EditRole).
     * @return True if the data was successfully set, false otherwise.
     */
    bool setData(const QModelIndex &index, const QVariant &value, int role = Qt::EditRole);

    /**
     * @brief Retrieves header data for the given section, orientation, and role.
     * @param section The column or row section.
     * @param orientation The orientation of the header.
     * @param role The role for which data is requested (defaults to Qt::DisplayRole).
     * @return The header data for the specified parameters.
     */
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const;

    /**
     * @brief Generates an index for the specified row and column.
     * @param row The row number.
     * @param column The column number.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return The generated model index.
     */
    QModelIndex index(int row, int column,
                      const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Retrieves the parent index of the specified index.
     * @param indexItem The child model index.
     * @return The parent model index.
     */
    QModelIndex parent(const QModelIndex &indexItem) const;

    //Drag & drop functionality
    /**
     * @brief Specifies the supported drag and drop actions.
     * @return The supported drop actions.
     */
    Qt::DropActions supportedDropActions() const;

    /**
     * @brief Retrieves the list of supported MIME types for drag and drop operations.
     * @return A list of supported MIME type strings.
     */
    QStringList mimeTypes() const;

    /**
     * @brief Generates MIME data for the specified list of indexes.
     * @param indexes The list of indexes to generate data for.
     * @return A pointer to the generated QMimeData.
     */
    QMimeData* mimeData(const QModelIndexList &indexes) const;

    /**
     * @brief Handles dropped MIME data.
     * @param data The MIME data being dropped.
     * @param action The drop action being performed.
     * @param row The target row for the drop.
     * @param column The target column for the drop.
     * @param parent The target parent index.
     * @return True if the drop was successful, false otherwise.
     */
    bool dropMimeData(const QMimeData *data, Qt::DropAction action, int row, int column, const QModelIndex &parent);

    /**
     * @brief Returns the number of rows under the given parent.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return The number of rows in the model.
     */
    int rowCount(const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Returns the number of columns under the given parent.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return The number of columns in the model.
     */
    int columnCount(const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Inserts rows into the model.
     * @param row The starting row index for insertion.
     * @param count The number of rows to insert.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return True if the insertion was successful, false otherwise.
     */
    bool insertRows(int row, int count, const QModelIndex &parent = QModelIndex());

    /**
     * @brief Removes rows from the model.
     * @param row The starting row index for removal.
     * @param count The number of rows to remove.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return True if the removal was successful, false otherwise.
     */
    bool removeRows(int row, int count, const QModelIndex &parent = QModelIndex());

    /**
     * @brief Copies a row from one index to another.
     * @param dst_row The destination row index.
     * @param src_row The source row index.
     * @return True if the copy was successful, false otherwise.
     */
    bool copyRow(int dst_row, int src_row);

private:
    /**
     * @brief Populates the model with the current coloring rules.
     */
    void populate();

    /**
     * @brief Creates a GSList of color filters.
     * @return A pointer to the created GSList structure.
     */
    struct _GSList *createColorFilterList();

    /** @brief Pointer to the root item of the coloring rules tree. */
    ColoringRuleItem* root_;

    //Save off the conversation colors, do not include in dialog
    /** @brief Saved list of conversation colors (excluded from dialog). */
    struct _GSList *conversation_colors_;

    /** @brief The default foreground color for rules. */
    QColor defaultForeground_;

    /** @brief The default background color for rules. */
    QColor defaultBackground_;

    /** @brief List of rows currently involved in a drag-and-drop operation. */
    QList<int> dragDropRows_;
};

#endif // COLORING_RULES_MODEL_H
