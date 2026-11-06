/* distribution_model.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "distribution_model.h"

#include <algorithm>
#include <cmath>

#include <QByteArray>

#include <epan/ftypes/ftypes.h>
#include <wsutil/inet_cidr.h>
#include <wsutil/wmem/wmem.h>

/* Normalized Shannon */
static double normalized_shannon(const quint64 *freq, size_t n_symbols, quint64 total) {

    /* ensure we have enough data or there's not much sense to compute */
    if (total == 0 || n_symbols < 2) {
        return 0.0;
    }

    double H = 0.0;
    for (size_t i = 0; i < n_symbols; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / (double)total;
        H -= p * log2(p);
    }

    return H / log2((double)n_symbols);
}

/*
 * The typed sort key of a value. Conversions that are not supported by the
 * value's type fall back to the display string, so a column always sorts.
 */
static QVariant sort_key(DistributionModel::SortKind kind, field_info *fi, const QString &display)
{
    switch (kind) {
    case DistributionField::SortSigned:
    {
        int64_t v;
        if (fvalue_to_sinteger64(fi->value, &v) == FT_OK) {
            return QVariant::fromValue<qlonglong>(v);
        }
        break;
    }
    case DistributionField::SortUnsigned:
    {
        uint64_t v;
        if (fvalue_to_uinteger64(fi->value, &v) == FT_OK) {
            return QVariant::fromValue<qulonglong>(v);
        }
        break;
    }
    case DistributionField::SortIPv4:
        /* fvalue_get_ipv4() asserts on other types */
        if (fvalue_type_ftenum(fi->value) == FT_IPv4) {
            return QVariant::fromValue<quint32>(fvalue_get_ipv4(fi->value)->addr);
        }
        break;
    case DistributionField::SortIPv6:
        if (fvalue_type_ftenum(fi->value) == FT_IPv6) {
            const ipv6_addr_and_prefix *ipv6 = fvalue_get_ipv6(fi->value);
            return QByteArray(reinterpret_cast<const char *>(ipv6->addr.bytes), sizeof(ipv6->addr.bytes));
        }
        break;
    case DistributionField::SortDouble:
    {
        double v;
        if (fvalue_to_double(fi->value, &v) == FT_OK) {
            return v;
        }
        break;
    }
    case DistributionField::SortString:
        break;
    }
    return display;
}

DistributionModel::DistributionModel(QObject *parent) :
    QAbstractTableModel(parent),
    published_(0),
    packets_(0),
    observations_(0),
    published_packets_(0),
    published_observations_(0),
    entropy_(0.0),
    has_result_(false),
    resolve_values_(false)
{
}

bool DistributionModel::supportsField(const header_field_info *hfinfo)
{
    return hfinfo && hfinfo->type != FT_NONE && hfinfo->type != FT_PROTOCOL;
}

DistributionModel::SortKind DistributionModel::sortKind(enum ftenum type)
{
    if (FT_IS_INT(type)) {
        return DistributionField::SortSigned;
    }
    /* FT_IS_UINT includes FT_CHAR and FT_FRAMENUM. FT_BOOLEAN and FT_IPXNET
     * are not in it but convert to unsigned 64-bit integers as well. */
    if (FT_IS_UINT(type) || type == FT_BOOLEAN || type == FT_IPXNET) {
        return DistributionField::SortUnsigned;
    }
    if (FT_IS_FLOATING(type) || type == FT_ABSOLUTE_TIME || type == FT_RELATIVE_TIME) {
        return DistributionField::SortDouble;
    }
    switch (type) {
    case FT_IPv4:
        return DistributionField::SortIPv4;
    case FT_IPv6:
        return DistributionField::SortIPv6;
    default:
        return DistributionField::SortString;
    }
}

QString DistributionModel::parseFields(const QStringList &names, QList<DistributionField> &fields)
{
    fields.clear();

    for (const QString &name : names) {
        const QByteArray name_utf8 = name.toUtf8();
        const header_field_info *hfinfo = proto_registrar_get_byname(name_utf8.constData());
        if (!hfinfo) {
            hfinfo = proto_registrar_get_byalias(name_utf8.constData());
        }
        if (!hfinfo) {
            fields.clear();
            return tr("\"%1\" cannot be counted.").arg(name);
        }

        if (hfinfo->type == FT_PROTOCOL) {
            fields.clear();
            void *cookie = NULL;
            const header_field_info *example = proto_get_first_protocol_field(hfinfo->id, &cookie);
            if (example) {
                return tr("\"%1\" is a protocol and has no values to count. Enter one of its fields, for example %2.")
                        .arg(name, example->abbrev);
            }
            return tr("\"%1\" is a protocol and has no values to count.").arg(name);
        }
        if (hfinfo->type == FT_NONE) {
            fields.clear();
            return tr("\"%1\" is a label without a value and cannot be counted.").arg(name);
        }

        /* Rewind (shouldn't be necessary but let's avoid unexpected-hard-to-debug situations.) */
        while (hfinfo->same_name_prev_id != -1) {
            hfinfo = proto_registrar_get_nth(hfinfo->same_name_prev_id);
        }

        DistributionField field;
        field.name = QString::fromUtf8(hfinfo->abbrev);
        field.kind = sortKind(hfinfo->type);

        /* All homonyms are counted together, so they must all be countable
         * and sort the same way, otherwise none of them is kept.
         * tcp.options.mptcp.reserved.flag is one of them, for example. */
        for (const header_field_info *h = hfinfo; h; h = h->same_name_next) {
            if (!supportsField(h) || sortKind(h->type) != field.kind) {
                fields.clear();
                return tr("\"%1\" has variants of different types and cannot be counted.").arg(name);
            }
            field.hf_indices.append(h->id);
        }

        fields.append(field);
    }
    return QString();
}

void DistributionModel::setFields(const QList<DistributionField> &fields)
{
    beginResetModel();
    fields_ = fields;
    resetCounts();
    endResetModel();
    emit summaryChanged();
}

void DistributionModel::clear()
{
    beginResetModel();
    resetCounts();
    endResetModel();
    emit summaryChanged();
}

void DistributionModel::resetCounts()
{
    rows_.clear();
    index_.clear();
    published_ = 0;
    packets_ = 0;
    observations_ = 0;
    published_packets_ = 0;
    published_observations_ = 0;
    entropy_ = 0.0;
    has_result_ = false;
}

bool DistributionModel::addPacket(proto_tree *tree)
{
    const int field_count = static_cast<int>(fields_.size());
    if (field_count == 0) {
        return false;
    }

    /* Find the distinct values of every field in this packet: the display
     * filter literal identifies a value, the field_info is kept to build a
     * new row from it. */
    QList<QStringList> found(field_count);
    QList<QList<field_info *>> found_infos(field_count);
    for (int i = 0; i < field_count; i++) {

        /* all homonyms of this field (typically ip.addr doesn't come alone) */
        for (int hf : fields_[i].hf_indices) {
            GPtrArray *gp = proto_get_finfo_ptr_array(tree, hf);
            if (!gp) continue;

            /* all occurrences of this hf */
            for (unsigned j = 0; j < gp->len; j++) {
                field_info *fi = (field_info *) g_ptr_array_index(gp, j);
                char *repr = fvalue_to_string_repr(NULL, fi->value, FTREPR_DFILTER, fi->hfinfo->display);
                if (!repr) continue;
                const QString value = QString::fromUtf8(repr);
                wmem_free(NULL, repr);
                if (!found[i].contains(value)) {
                    found[i].append(value);
                    found_infos[i].append(fi);
                }
            }
        }
        /* while unexpected (filter built over '&&'), ignore packets not containing the field */
        if (found[i].isEmpty()) return false;
    }

    /* Every combination of the values found is one observation. */
    QList<int> idx(field_count, 0);
    QStringList key;
    for (;;) {
        key.clear();
        for (int i = 0; i < field_count; i++) {
            key.append(found[i][idx[i]]);
        }

        auto it = index_.constFind(key);
        if (it != index_.constEnd()) {
            rows_[it.value()].count++;
        } else {
            Row row;
            row.dfilter = key;
            for (int i = 0; i < field_count; i++) {
                field_info *fi = found_infos[i][idx[i]];

                QString display;
                char *repr = fvalue_to_string_repr(NULL, fi->value, FTREPR_DISPLAY, fi->hfinfo->display);
                if (repr) {
                    display = QString::fromUtf8(repr);
                    wmem_free(NULL, repr);
                } else {
                    display = key[i];
                }

                char label_str[ITEM_LABEL_LENGTH];
                label_str[0] = '\0';
                proto_item_fill_display_label(fi, label_str, ITEM_LABEL_LENGTH);
                const QString label = QString::fromUtf8(label_str);

                row.display.append(display);
                row.label.append(label == display ? QString() : label);
                row.sort.append(sort_key(fields_[i].kind, fi, display));
            }
            row.count = 1;
            index_.insert(key, static_cast<int>(rows_.size()));
            rows_.push_back(row);
        }
        observations_++;

        int k = field_count - 1;
        while (k >= 0 && ++idx[k] == found[k].size()) { idx[k] = 0; k--; }
        if (k < 0) break;
    }

    packets_++;
    return true;
}

void DistributionModel::publish()
{
    const int old_published = published_;
    const int total = static_cast<int>(rows_.size());

    if (total > old_published) {
        beginInsertRows(QModelIndex(), old_published, total - 1);
        published_ = total;
        endInsertRows();
    }

    /* The counts and percentages of the rows already shown change only when
     * packets were added. */
    if (published_packets_ != packets_ && old_published > 0) {
        emit dataChanged(index(0, countColumn()), index(old_published - 1, percentColumn()));
    }
    published_packets_ = packets_;
    published_observations_ = observations_;

    std::vector<quint64> freq;
    freq.reserve(rows_.size());
    for (const Row &row : rows_) {
        freq.push_back(row.count);
    }
    entropy_ = normalized_shannon(freq.data(), freq.size(), observations_);

    has_result_ = true;
    emit summaryChanged();
}

void DistributionModel::setResolveValues(bool resolve)
{
    if (resolve == resolve_values_) {
        return;
    }
    resolve_values_ = resolve;
    if (published_ > 0 && !fields_.isEmpty()) {
        emit dataChanged(index(0, 0), index(published_ - 1, countColumn() - 1));
    }
}

int DistributionModel::countColumn() const
{
    return columnCount() - 2;
}

int DistributionModel::percentColumn() const
{
    return columnCount() - 1;
}

QString DistributionModel::shownText(const Row &row, int field) const
{
    if (resolve_values_ && !row.label[field].isEmpty()) {
        return row.label[field];
    }
    return row.display[field];
}

QString DistributionModel::filterExpression(int row) const
{
    if (row < 0 || row >= published_) {
        return QString();
    }

    /* The keys are display filter literals already (strings come quoted
     * and escaped), so they are used as they are. */
    const Row &r = rows_[row];
    QStringList terms;
    for (int i = 0; i < fields_.size(); i++) {
        terms << QStringLiteral("%1 == %2").arg(fields_[i].name, r.dfilter[i]);
    }
    return terms.join(QStringLiteral(" && "));
}

QList<QVariant> DistributionModel::rowData(int row) const
{
    QList<QVariant> data;
    if (row < 0 || row >= published_) {
        return data;
    }

    const Row &r = rows_[row];
    for (int i = 0; i < fields_.size(); i++) {
        data << shownText(r, i);
    }
    data << QVariant::fromValue<qulonglong>(r.count);
    data << percent(r);
    return data;
}

quint64 DistributionModel::count(int row) const
{
    if (row < 0 || row >= published_) {
        return 0;
    }
    return rows_[row].count;
}

double DistributionModel::percent(const Row &row) const
{
    return packets_ ? row.count * 100.0 / packets_ : 0.0;
}

QList<int> DistributionModel::topRows(int n) const
{
    QList<int> rows;
    rows.reserve(published_);
    for (int i = 0; i < published_; i++) {
        rows << i;
    }

    const int top = qBound(0, n, static_cast<int>(rows.size()));
    std::partial_sort(rows.begin(), rows.begin() + top, rows.end(),
                      [this](int a, int b) { return rows_[a].count > rows_[b].count; });
    rows.resize(top);
    return rows;
}

QString DistributionModel::rowLabel(int row) const
{
    if (row < 0 || row >= published_) {
        return QString();
    }

    const Row &r = rows_[row];
    QStringList texts;
    for (int i = 0; i < fields_.size(); i++) {
        texts << shownText(r, i);
    }
    return texts.join(QStringLiteral(", "));
}

QStringList DistributionModel::fieldNames() const
{
    QStringList names;
    for (const DistributionField &field : fields_) {
        names << field.name;
    }
    return names;
}

int DistributionModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : published_;
}

int DistributionModel::columnCount(const QModelIndex &parent) const
{
    if (parent.isValid()) {
        return 0;
    }
    /* Without fields a single Value column stands for them. */
    return fields_.isEmpty() ? 3 : static_cast<int>(fields_.size()) + 2;
}

QVariant DistributionModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= published_ || fields_.isEmpty()) {
        return QVariant();
    }

    const Row &r = rows_[index.row()];
    const int col = index.column();

    switch (role) {
    case Qt::DisplayRole:
        if (col < countColumn()) {
            return shownText(r, col);
        }
        if (col == countColumn()) {
            return QVariant::fromValue<qulonglong>(r.count);
        }
        /* PercentBarDelegate paints only when the text is empty. */
        return QVariant();
    case Qt::UserRole:
        if (col == percentColumn()) {
            return percent(r);
        }
        break;
    case Qt::ToolTipRole:
        return filterExpression(index.row());
    case Qt::TextAlignmentRole:
        if (col == countColumn()) {
            return static_cast<int>(Qt::AlignRight | Qt::AlignVCenter);
        }
        break;
    case SortRole:
        if (col < countColumn()) {
            return r.sort[col];
        }
        if (col == countColumn()) {
            return QVariant::fromValue<qulonglong>(r.count);
        }
        return percent(r);
    default:
        break;
    }
    return QVariant();
}

QVariant DistributionModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
        return QVariant();
    }

    if (section == countColumn()) {
        return tr("Count");
    }
    if (section == percentColumn()) {
        return tr("Percent");
    }
    if (fields_.isEmpty()) {
        return section == 0 ? tr("Value") : QVariant();
    }
    if (section >= 0 && section < fields_.size()) {
        return fields_[section].name;
    }
    return QVariant();
}
