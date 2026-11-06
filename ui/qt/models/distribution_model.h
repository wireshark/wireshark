/** @file
 *
 * Data model for the Distribution dialog: counts the value combinations of
 * up to four fields over the packets of a tap.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DISTRIBUTION_MODEL_H
#define DISTRIBUTION_MODEL_H

#include <config.h>

#include <vector>

#include <QAbstractTableModel>
#include <QHash>
#include <QList>
#include <QString>
#include <QStringList>
#include <QVariant>

#include <epan/proto.h>

/**
 * @brief One field counted by DistributionModel.
 */
struct DistributionField
{
    /**
     * @brief How the values of a field sort.
     */
    enum SortKind {
        SortSigned,     /**< Signed integers. */
        SortUnsigned,   /**< Unsigned integers, booleans, frame numbers, IPX networks. */
        SortIPv4,       /**< IPv4 addresses, by address. */
        SortIPv6,       /**< IPv6 addresses, by address bytes. */
        SortDouble,     /**< Floating point values and times. */
        SortString      /**< Everything else, by display string. */
    };

    QString name;           /**< Field abbreviation, used in filters. */
    QList<int> hf_indices;  /**< All homonyms of the field. */
    SortKind kind = SortString; /**< Sort kind shared by all homonyms. */
};

/**
 * @brief Table model of the distinct value combinations of the counted fields.
 *
 * Rows are appended while packets are added and become visible only when
 * publish() is called, so a view keeps its selection, scroll position and
 * sort while the counts update. Columns are one per field, then Count and
 * Percent. Without fields the model has the three columns Value, Count and
 * Percent and no rows.
 */
class DistributionModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    /** @brief The sort kind of a field, see DistributionField::SortKind. */
    using SortKind = DistributionField::SortKind;

    /** @brief The maximum number of fields that can be counted together. */
    static constexpr int maxFields = 4;

    /** @brief Item data role holding the typed sort key of a cell. */
    enum { SortRole = Qt::UserRole + 1 };

    /**
     * @brief Constructs an empty model without fields.
     * @param parent The parent object.
     */
    explicit DistributionModel(QObject *parent = nullptr);

    /**
     * @brief Tells whether the values of a field can be counted.
     * @param hfinfo The field.
     * @return True unless the field is a protocol or a label without value.
     */
    static bool supportsField(const header_field_info *hfinfo);

    /**
     * @brief Returns how the values of a field type sort.
     * @param type The field type.
     * @return The sort kind of that type.
     */
    static SortKind sortKind(enum ftenum type);

    /**
     * @brief Resolves field names into counted fields.
     *
     * The names are expected to have passed the field list checks of
     * FieldFilterEdit (known names or aliases, none empty, at most
     * maxFields). This only checks what is specific to counting. An alias
     * is stored under the abbreviation of its field.
     * @param names The field names.
     * @param fields Receives the resolved fields.
     * @return An empty string on success, else a message for the first
     * field that cannot be counted.
     */
    static QString parseFields(const QStringList &names, QList<DistributionField> &fields);

    /**
     * @brief Sets the counted fields and removes all rows.
     * @param fields The fields, as returned by parseFields().
     */
    void setFields(const QList<DistributionField> &fields);

    /**
     * @brief Removes all rows and counts, keeps the fields.
     */
    void clear();

    /**
     * @brief Counts the field values of one packet.
     *
     * Every combination of the distinct values of the fields is one
     * observation. New rows are not visible before publish().
     * @param tree The protocol tree of the packet.
     * @return True when the packet contains every field, false when it was
     * skipped.
     */
    bool addPacket(proto_tree *tree);

    /**
     * @brief Makes the rows and counts added since the last call visible.
     *
     * Always emits summaryChanged(), also when nothing changed.
     */
    void publish();

    /**
     * @brief Shows resolved labels instead of the raw values.
     * @param resolve True to show the resolved labels.
     */
    void setResolveValues(bool resolve);

    /**
     * @brief Tells whether fields were set.
     * @return True when setFields() was called with at least one field.
     */
    bool hasFields() const { return !fields_.isEmpty(); }

    /**
     * @brief Tells whether there is a result to describe.
     * @return True after publish() since the last setFields() or clear().
     */
    bool hasResult() const { return has_result_; }

    /**
     * @brief Returns the column of the counts.
     * @return The Count column.
     */
    int countColumn() const;

    /**
     * @brief Returns the column of the percentages.
     * @return The Percent column.
     */
    int percentColumn() const;

    /**
     * @brief Returns the display filter matching a row.
     * @param row The row.
     * @return The filter, one comparison per field joined by "&&".
     */
    QString filterExpression(int row) const;

    /**
     * @brief Returns the data of a row for copying and saving.
     * @param row The row.
     * @return The shown field texts, the count as qulonglong and the
     * percentage as double.
     */
    QList<QVariant> rowData(int row) const;

    /**
     * @brief Returns the count of a row.
     * @param row The row.
     * @return The number of observations of the row, 0 for a row that is not published.
     */
    quint64 count(int row) const;

    /**
     * @brief Returns the rows with the highest counts.
     * @param n The maximum number of rows.
     * @return The published rows, by decreasing count.
     */
    QList<int> topRows(int n) const;

    /**
     * @brief Returns a short name of a row.
     * @param row The row.
     * @return The shown field texts joined by ", ".
     */
    QString rowLabel(int row) const;

    /**
     * @brief Returns the names of the counted fields.
     * @return The field abbreviations.
     */
    QStringList fieldNames() const;

    /**
     * @brief Returns the number of published distinct value combinations.
     * @return The number of rows.
     */
    int distinctValues() const { return published_; }

    /**
     * @brief Returns the number of counted packets at the last publish().
     * @return The packet count.
     */
    quint64 packets() const { return published_packets_; }

    /**
     * @brief Returns the number of observations at the last publish().
     * @return The observation count.
     */
    quint64 observations() const { return published_observations_; }

    /**
     * @brief Returns the normalized Shannon entropy at the last publish().
     * @return The entropy between 0 and 1.
     */
    double entropy() const { return entropy_; }

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const override;

signals:
    /**
     * @brief Emitted when the summary values or hasResult() changed.
     */
    void summaryChanged();

private:
    /** @brief One distinct value combination. */
    struct Row {
        QStringList dfilter;    /**< Values as display filter literals, the key. */
        QStringList display;    /**< Values as display strings. */
        QStringList label;      /**< Resolved labels, empty where equal to display. */
        QList<QVariant> sort;   /**< Typed sort keys, one per field. */
        quint64 count;          /**< Number of observations. */
    };

    QString shownText(const Row &row, int field) const;
    double percent(const Row &row) const;
    void resetCounts();

    QList<DistributionField> fields_;
    std::vector<Row> rows_;
    QHash<QStringList, int> index_;
    int published_;
    quint64 packets_;
    quint64 observations_;
    quint64 published_packets_;
    quint64 published_observations_;
    double entropy_;
    bool has_result_;
    bool resolve_values_;
};

#endif // DISTRIBUTION_MODEL_H
