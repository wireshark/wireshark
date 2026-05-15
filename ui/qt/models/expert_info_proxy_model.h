/** @file
 *
 * Data model for Expert Info tap data.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef EXPERT_INFO_PROXY_MODEL_H
#define EXPERT_INFO_PROXY_MODEL_H

#include <config.h>

#include <QSortFilterProxyModel>

class ExpertPacketItem;

/**
 * @brief A proxy model used for sorting and filtering expert information data.
 */
class ExpertInfoProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new ExpertInfoProxyModel.
     * @param parent The parent QObject, defaults to 0.
     */
    ExpertInfoProxyModel(QObject *parent = 0);

    /**
     * @brief Defines the mode for displaying and evaluating severities.
     */
    enum SeverityMode {
        Group,  /**< Mode for evaluating severity at the group level. */
        Packet  /**< Mode for evaluating severity at the individual packet level. */
    };

    /**
     * @brief Enumerates the columns exposed by the proxy model.
     */
    enum ExpertProxyColumn {
        colProxySeverity = 0, /**< Severity column. */
        colProxySummary,      /**< Summary text column. */
        colProxyGroup,        /**< Group ID column. */
        colProxyProtocol,     /**< Protocol string column. */
        colProxyCount,        /**< Event count column. */
        colProxyLast          /**< End of proxy columns marker. */
    };

    /**
     * @brief Retrieves data from the proxy model for a given index and role.
     * @param index The proxy model index.
     * @param role The data role requested.
     * @return The data associated with the index and role.
     */
    QVariant data(const QModelIndex &index, int role) const;

    /**
     * @brief Retrieves the header data for a specific section and role.
     * @param section The column or row section.
     * @param orientation The orientation of the header.
     * @param role The data role requested (defaults to Qt::DisplayRole).
     * @return The header data.
     */
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const;

    /**
     * @brief Returns the number of columns under a given parent.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return The number of columns.
     */
    int columnCount(const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Checks if a given parent index has any child elements.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return True if the parent has children, false otherwise.
     */
    bool hasChildren(const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Determines whether a row from the source model should be displayed.
     * @param sourceRow The row in the source model.
     * @param sourceParent The parent index in the source model.
     * @return True if the row is accepted, false otherwise.
     */
    virtual bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const;

    //GUI helpers

    /**
     * @brief Sets the severity mode for the proxy model.
     * @param mode The severity mode to apply.
     */
    void setSeverityMode(enum SeverityMode mode);

    /**
     * @brief Sets whether a specific severity level should be hidden or shown.
     * @param severity The severity level identifier.
     * @param hide True to hide the severity, false to show it.
     */
    void setSeverityFilter(int severity, bool hide);

    /**
     * @brief Sets the text filter used to filter items by their summary.
     * @param filter The filter text or regular expression.
     */
    void setSummaryFilter(const QString &filter);

protected:
    /**
     * @brief Compares two source indices to determine their sort order.
     * @param source_left The first source index.
     * @param source_right The second source index.
     * @return True if the left item should appear before the right item.
     */
    bool lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const;

    /**
     * @brief Checks if an individual expert packet item matches the current filter criteria.
     * @param item The expert packet item to check.
     * @return True if the item is accepted, false otherwise.
     */
    bool filterAcceptItem(ExpertPacketItem& item) const;

    /** The current severity evaluation mode. */
    enum SeverityMode severityMode_;

    /** A list of severity levels that are currently hidden. */
    QList<int> hidden_severities_;

    /** The current text filter applied to summaries. */
    QString textFilter_;

};

#endif // EXPERT_INFO_PROXY_MODEL_H
