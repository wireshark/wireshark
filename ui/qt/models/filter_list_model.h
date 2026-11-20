/** @file
 *
 * Model for all filter types
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FILTER_LIST_MODEL_h
#define FILTER_LIST_MODEL_h

#include <config.h>

#include <ui/qt/models/inherited_rules_model.h>

#include <QList>
#include <QStringList>

/**
 * @brief A filter or macro in a FilterListModel.
 */
class FilterListItem : public ModelHelperTreeItem<FilterListItem>
{
public:
    /**
     * @brief Constructs a new FilterListItem.
     * @param name The name of the filter.
     * @param filter The expression of the filter.
     * @param parent The parent item.
     * @param source_profile The parent profile the filter is inherited from, empty for an own filter.
     */
    FilterListItem(const QString &name, const QString &filter, FilterListItem *parent,
                   const QString &source_profile = QString());

    /**
     * @brief Copy constructor for FilterListItem.
     * @param item The item to copy.
     */
    FilterListItem(const FilterListItem &item);

    /** @brief The name of the filter. */
    QString name_;

    /** @brief The expression of the filter. */
    QString filter_;

    /** @brief The parent profile the filter is inherited from, empty for an own filter. */
    QString source_profile_;

    /** @brief Whether the filter comes from a parent profile; such a filter is read-only. @return true if inherited. */
    bool isInherited() const { return !source_profile_.isEmpty(); }
};

/**
 * @brief A list model for managing capture filters, display filters, and display macros.
 *
 * The profile's own filters come first, then the filters inherited from the
 * parent profiles, as the inherit mode of the file selects. A filter is
 * identified by its name and its expression, a macro by its name only.
 */
class FilterListModel : public InheritedRulesModel<FilterListItem>
{
    Q_OBJECT

public:
    /**
     * @brief Defines the type of filter list.
     */
    enum FilterListType {
        Display,       /**< A list of display filters. */
        Capture,       /**< A list of capture filters. */
        DisplayMacro,  /**< A list of display macros. */
    };

    /**
     * @brief Constructs a new FilterListModel with a specific type.
     * @param type The type of filter list (defaults to FilterListModel::Display).
     * @param parent The parent QObject, defaults to Q_NULLPTR.
     */
    explicit FilterListModel(FilterListType type = FilterListModel::Display, QObject * parent = Q_NULLPTR);

    /**
     * @brief Constructs a new FilterListModel.
     * @param parent The parent QObject, defaults to Q_NULLPTR.
     */
    explicit FilterListModel(QObject * parent = Q_NULLPTR);

    ~FilterListModel() override;

    /**
     * @brief Enumerates the columns for the filter list model.
     */
    enum {
        ColumnName,       /**< The filter name column. */
        ColumnExpression  /**< The filter expression column. */
    };

    /**
     * @brief Represents a single filter entry with a name and an expression.
     */
    struct FilterListValue {
        QString name;       /**< The name of the filter. */
        QString expression; /**< The filter expression string. */

        /**
         * @brief Constructs a new FilterListValue.
         * @param n The name of the filter.
         * @param e The expression of the filter.
         */
        FilterListValue(QString n, QString e) : name(n), expression(e) {}
    };

    /**
     * @brief The configuration file name of a filter list type.
     * @param type The type.
     * @return The file name, e.g. "dfilters".
     */
    static const char *fileName(FilterListType type);

    /**
     * @brief Reads the filters of a file.
     * @param path The file.
     * @param ok Set to false if the file can't be read, may be NULL.
     * @return The filters, in the order of the file.
     */
    static QList<FilterListValue> readFile(const QString &path, bool *ok = nullptr);

    /**
     * @brief Sets the filter type for this model.
     * @param type The filter list type to set.
     */
    void setFilterType(FilterListModel::FilterListType type);

    /**
     * @brief Retrieves the current filter type of the model.
     * @return The filter list type.
     */
    FilterListModel::FilterListType filterType() const;

    /**
     * @brief Finds a filter by its name.
     * @param name The name to search for.
     * @return The model index of the found filter, or an invalid index if not found.
     */
    QModelIndex findByName(QString name);

    /**
     * @brief Finds a filter by its expression.
     * @param expression The expression to search for.
     * @return The model index of the found filter, or an invalid index if not found.
     */
    QModelIndex findByExpression(QString expression);

    /**
     * @brief Adds a new filter after the profile's own filters.
     *
     * Nothing is added while only the parent's filters are used.
     * @param name The name of the new filter.
     * @param expression The expression string of the new filter.
     * @return The model index of the newly added filter, or an invalid index.
     */
    QModelIndex addFilter(QString name, QString expression);

    /**
     * @brief Removes a filter at the specified index; inherited filters are not removed.
     * @param idx The model index of the filter to remove.
     */
    void removeFilter(QModelIndex idx);

    /**
     * @brief Adds the filters of a file, e.g. of another profile, to the profile's own filters.
     * @param path The file.
     * @param err Set to an error message on failure.
     * @return true on success.
     */
    bool importFile(const QString &path, QString &err);

    /**
     * @brief Saves the profile's own filters to persistent storage.
     *
     * The inherited filters are not saved. A file without filters is
     * written only if the file had filters, or the filters replace the global
     * filters, so a profile without a file keeps using the inherited filters.
     */
    void saveList();

    /**
     * @brief Returns the number of columns under a given parent.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return The number of columns.
     */
    virtual int columnCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Retrieves data from the model for a given index and role.
     * @param index The model index.
     * @param role The data role requested (defaults to Qt::DisplayRole).
     * @return The data associated with the index and role.
     */
    virtual QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    /**
     * @brief Sets data in the model for a given index and role.
     * @param index The model index to update.
     * @param value The value to set.
     * @param role The role being edited.
     * @return True if successful, false otherwise.
     */
    virtual bool setData(const QModelIndex &index, const QVariant &value, int role) override;

    /**
     * @brief Retrieves the header data for a specific section and role.
     * @param section The column or row section.
     * @param orientation The orientation of the header.
     * @param role The data role requested (defaults to Qt::DisplayRole).
     * @return The header data.
     */
    virtual QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    /**
     * @brief Retrieves the item flags for a given index.
     * @param index The model index.
     * @return The item flags.
     */
    virtual Qt::ItemFlags flags(const QModelIndex &index) const override;

    /**
     * @brief Removes the profile's own filters; inherited filters are not removed.
     * @param row The first row.
     * @param count The number of rows.
     * @param parent The parent model index.
     * @return True if rows were removed.
     */
    virtual bool removeRows(int row, int count, const QModelIndex &parent = QModelIndex()) override;

    /**
     * @brief Retrieves the drop actions supported by the model.
     * @return The supported drop actions.
     */
    virtual Qt::DropActions supportedDropActions() const override;

protected:
    QList<FilterListItem *> readInherited(profile_inherit_e mode) override;
    void leavingInheritMode(profile_inherit_e mode) override;
    QList<FilterListItem *> readOwnRows() override;
    void enteredInheritMode(profile_inherit_e mode) override;

private:

    /** The current type of the filter list. */
    FilterListModel::FilterListType type_;

    /** The global filters, while not shown. */
    QList<FilterListItem *> default_rules_;

    /** Set if the own filters are the global filters, used without a file. */
    bool own_from_globals_;

    /** Set if the profile has a file of its own. */
    bool own_file_exists_;

    /**
     * @brief Reads the profile's own filters into the model, which must be empty.
     */
    void loadOwn();

    /**
     * @brief Reloads the filter list from persistent storage.
     */
    void reload();

    /**
     * @brief The path the own filters are written to.
     * @return The path.
     */
    QString ownFilePath() const;

    /**
     * @brief The global filters, e.g. used by a profile without a file.
     * @return New items.
     */
    QList<FilterListItem *> readGlobals() const;
};

#endif // FILTER_LIST_MODEL_h
