/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SUPPORTED_PROTOCOLS_MODEL_H
#define SUPPORTED_PROTOCOLS_MODEL_H

#include <config.h>

#include <ui/qt/models/tree_model_helpers.h>

#include <epan/proto.h>

#include <QSortFilterProxyModel>

/**
 * @brief Tree item representing a single protocol or protocol field in the
 *        Supported Protocols tree, storing its name, filter expression,
 *        field type, and description.
 */
class SupportedProtocolsItem : public ModelHelperTreeItem<SupportedProtocolsItem>
{
public:
    /**
     * @brief Constructs a supported-protocols tree item.
     * @param proto  Pointer to the protocol_t descriptor; @c nullptr for field items.
     * @param name   Display name of the protocol or field.
     * @param filter Filter expression string (e.g. "tcp", "tcp.port").
     * @param ftype  Field type enum value (e.g. FT_UINT16, FT_STRING).
     * @param descr  Human-readable description of the protocol or field.
     * @param parent Parent item in the tree; @c nullptr for root-level items.
     */
    SupportedProtocolsItem(protocol_t *proto, const char *name, const char *filter,
                            ftenum_t ftype, const char *descr,
                            SupportedProtocolsItem *parent);

    /**
     * @brief Destroys the item and all of its child items.
     */
    virtual ~SupportedProtocolsItem();

    /**
     * @brief Returns the protocol descriptor associated with this item.
     * @return Pointer to the protocol_t, or @c nullptr for field-only items.
     */
    protocol_t *protocol() const { return proto_; }

    /**
     * @brief Returns the display name of the protocol or field.
     * @return Name string.
     */
    QString name() const { return name_; }

    /**
     * @brief Returns the field type of this item.
     * @return ftenum_t value (e.g. FT_UINT16, FT_NONE for protocols).
     */
    ftenum_t type() const { return ftype_; }

    /**
     * @brief Returns the filter expression string for this protocol or field.
     * @return Filter string (e.g. "tcp.port").
     */
    QString filter() const { return filter_; }

    /**
     * @brief Returns the human-readable description of this protocol or field.
     * @return Description string.
     */
    QString description() const { return descr_; }

private:
    protocol_t *proto_; /**< Protocol descriptor; @c nullptr for pure field items. */
    QString     name_;   /**< Display name of the protocol or field. */
    QString     filter_; /**< Filter expression string. */
    ftenum_t    ftype_;  /**< Field type enum value. */
    QString     descr_;  /**< Human-readable description. */
};


/**
 * @brief Tree model that exposes all registered Wireshark protocols and their
 *        fields, organised as a parent–child hierarchy suitable for display in
 *        the Supported Protocols dialog.
 */
class SupportedProtocolsModel : public QAbstractItemModel
{
    Q_OBJECT

public:
    /**
     * @brief Constructs an empty model; call populate() to load protocol data.
     * @param parent Optional parent QObject.
     */
    explicit SupportedProtocolsModel(QObject *parent = Q_NULLPTR);

    /**
     * @brief Destroys the model and all tree items.
     */
    virtual ~SupportedProtocolsModel();

    /**
     * @brief Column indices for the supported-protocols tree view.
     */
    enum SupportedProtocolsColumn {
        colName        = 0, /**< Protocol or field name. */
        colFilter,          /**< Filter expression string. */
        colType,            /**< Field type as a human-readable string. */
        colDescription,     /**< Description of the protocol or field. */
        colLast             /**< Sentinel value; total number of columns. */
    };

    /**
     * @brief Returns the total number of protocol fields loaded by populate().
     * @return Field count across all protocols.
     */
    int fieldCount() { return field_count_; }

    /**
     * @brief Returns the model index for the item at @p row and @p column under @p parent.
     * @param row    Row within the parent item.
     * @param column Column index.
     * @param parent Parent model index; invalid index for top-level items.
     * @return Model index for the requested item.
     */
    QModelIndex index(int row, int column,
                      const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Returns the parent index of the item at @p index.
     * @param index Child model index.
     * @return Parent model index, or an invalid index for top-level items.
     */
    QModelIndex parent(const QModelIndex &index) const;

    /**
     * @brief Returns data for the given model index and role.
     * @param index Model index of the cell to query.
     * @param role  Qt item data role.
     * @return The requested data, or an invalid QVariant if not applicable.
     */
    QVariant data(const QModelIndex &index, int role) const;

    /**
     * @brief Returns column header labels for the supported-protocols table.
     * @param section     Column index.
     * @param orientation Qt::Horizontal for column headers.
     * @param role        Qt item data role.
     * @return Header label string, or an invalid QVariant if not applicable.
     */
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const;

    /**
     * @brief Returns the number of child rows under @p parent.
     * @param parent Parent model index; invalid index for the root.
     * @return Number of child items.
     */
    int rowCount(const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Returns the number of columns in the model.
     * @param parent Unused.
     * @return Number of columns (colLast).
     */
    int columnCount(const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Populates the model by iterating all registered protocols and their
     *        fields; must be called before the model is used in a view.
     */
    void populate();

private:
    SupportedProtocolsItem *root_;  /**< Invisible root item that owns all top-level protocol items. */
    int                     field_count_; /**< Total number of protocol fields loaded. */
};


/**
 * @brief Sort/filter proxy model for SupportedProtocolsModel that performs
 *        case-insensitive substring filtering across name, filter, type, and
 *        description columns, and provides natural sorting for each column.
 */
class SupportedProtocolsProxyModel : public QSortFilterProxyModel
{
public:
    /**
     * @brief Constructs the proxy model.
     * @param parent Optional parent QObject.
     */
    explicit SupportedProtocolsProxyModel(QObject *parent = Q_NULLPTR);

    /**
     * @brief Determines whether the source row should be visible given the current filter.
     * @param sourceRow    Row index in the source model.
     * @param sourceParent Parent index in the source model.
     * @return @c true if the row or any of its descendants match the filter.
     */
    virtual bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const;

    /**
     * @brief Sets the text filter used to match protocols and fields.
     *        An empty string shows all items.
     * @param filter Case-insensitive substring to match against item data.
     */
    void setFilter(const QString &filter);

protected:
    /**
     * @brief Compares two source rows for sorting using the active sort column.
     * @param source_left  Index of the left-hand item in the source model.
     * @param source_right Index of the right-hand item in the source model.
     * @return @c true if @p source_left should sort before @p source_right.
     */
    bool lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const;

    /**
     * @brief Tests whether a single SupportedProtocolsItem matches the current filter.
     * @param item The item to test.
     * @return @c true if any of the item's visible fields contain the filter string.
     */
    bool filterAcceptItem(SupportedProtocolsItem &item) const;

private:
    QString filter_; /**< Current case-insensitive substring filter. */
};

#endif // SUPPORTED_PROTOCOLS_MODEL_H
