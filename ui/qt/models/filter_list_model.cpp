/* filter_list_model.cpp
 * Model for all filter types
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <wsutil/filesystem.h>

#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/wireshark_mime_data.h>
#include <ui/qt/models/filter_list_model.h>
#include <ui/qt/models/profile_model.h>

#include <QFile>
#include <QTextStream>
#include <QRegularExpression>
#include <QDir>
#include <QMimeData>

/*
 * Capture filter file name.
 */
#define CFILTER_FILE_NAME     "cfilters"

/*
 * Display filter file name.
 */
#define DFILTER_FILE_NAME     "dfilters"

/*
 * Display filter macros file name.
 */
#define DMACROS_FILE_NAME     "dmacros"

FilterListModel::FilterListModel(QObject * parent) :
    QAbstractListModel(parent),
    type_(FilterListModel::Display)
{
    reload();
}

FilterListModel::FilterListModel(FilterListModel::FilterListType type, QObject * parent) :
    QAbstractListModel(parent),
    type_(type)
{
    reload();
}

void FilterListModel::reload()
{
    storage.clear();

    const char *cfile;

    switch (type_) {
        case FilterListModel::Capture: cfile = CFILTER_FILE_NAME; break;
        case FilterListModel::Display: cfile = DFILTER_FILE_NAME; break;
        case FilterListModel::DisplayMacro: cfile = DMACROS_FILE_NAME; break;
        default: ws_assert_not_reached();
    }

    /* Try personal config file first */
    QString fileName = gchar_free_to_qstring(get_persconffile_path(cfile, true));
    if (fileName.length() <= 0 || ! QFileInfo::exists(fileName))
        fileName = gchar_free_to_qstring(get_datafile_path(cfile));
    if (fileName.length() <= 0 || ! QFileInfo::exists(fileName))
        return;

    QFile file(fileName);
    /* Still can use the model, just have to start from an empty set */
    if (! file.open(QIODevice::ReadOnly | QIODevice::Text))
        return;

    QTextStream in(&file);
    QRegularExpression rx("\\s*\\\"\\s*(.*?)\\s*\\\"\\s(.*)");
    while (!in.atEnd())
    {
        QString data = in.readLine().trimmed();
        /* Filter out lines that do not contain content:
        *  - Starting with # is a comment
        *  - Does not start with a quoted string
        */
        if (data.startsWith("#") || ! data.trimmed().startsWith("\""))
            continue;

        QStringList content = data.split(QChar('\n'));
        foreach (QString line, content)
        {
            QRegularExpressionMatch match = rx.match(line);
            if (match.hasMatch()) {
                addFilter(match.captured(1).trimmed(), match.captured(2).trimmed());
            }
        }
    }
}

void FilterListModel::setFilterType(FilterListModel::FilterListType type)
{
    type_ = type;
    reload();
}

FilterListModel::FilterListType FilterListModel::filterType() const
{
    return type_;
}

int FilterListModel::rowCount(const QModelIndex &/* parent */) const
{
    return static_cast<int>(storage.count());
}

int FilterListModel::columnCount(const QModelIndex &/* parent */) const
{
    return 2;
}

QVariant FilterListModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (section >= columnCount() || section < 0 || orientation != Qt::Horizontal)
        return QVariant();

    if (role == Qt::DisplayRole)
    {
        switch (section) {
            case ColumnName:
                if (type_ == DisplayMacro)
                    return tr("Macro Name");
                else
                    return tr("Filter Name");
                break;
            case ColumnExpression:
                if (type_ == DisplayMacro)
                    return tr("Macro Expression");
                else
                    return tr("Filter Expression");
                break;
        }
    }

    return QVariant();
}

QVariant FilterListModel::data(const QModelIndex &index, int role) const
{
    if (! index.isValid() || index.row() >= rowCount())
        return QVariant();

    QStringList row = storage.at(index.row()).split("\n");
    if (role == Qt::DisplayRole)
        return row.at(index.column());

    return QVariant();
}

bool FilterListModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if (! index.isValid() || index.row() >= rowCount() || role != Qt::EditRole)
        return false;

    QStringList row = storage.at(index.row()).split("\n");
    if (row.count() <= index.column())
        return false;

    if (index.column() == FilterListModel::ColumnName && value.toString().contains("\""))
        return false;

    row[index.column()] = value.toString();
    storage[index.row()] = row.join("\n");

    return true;
}

Qt::ItemFlags FilterListModel::flags(const QModelIndex &index) const
{
    Qt::ItemFlags fl = QAbstractListModel::flags(index);
    fl |= Qt::ItemIsDropEnabled;

    if (! index.isValid() || index.row() >= rowCount())
        return fl;

    fl |= Qt::ItemIsEditable | Qt::ItemIsDragEnabled;

    return fl;
}
QModelIndex FilterListModel::addFilter(QString name, QString expression)
{
    if (name.length() == 0 || expression.length() == 0)
        return QModelIndex();

    beginInsertRows(QModelIndex(), rowCount(), rowCount());
    storage << QString("%1\n%2").arg(name).arg(expression);
    endInsertRows();

    return index(rowCount() - 1, 0);
}

QModelIndex FilterListModel::findByName(QString name)
{
    if (name.length() == 0)
        return QModelIndex();

    for (int cnt = 0; cnt < rowCount(); cnt++)
    {
        if (storage.at(cnt).startsWith(QString("%1\n").arg(name)))
            return index(cnt, 0);
    }

    return QModelIndex();
}

QModelIndex FilterListModel::findByExpression(QString expression)
{
    if (expression.length() == 0)
        return QModelIndex();

    for (int cnt = 0; cnt < rowCount(); cnt++)
    {
        if (storage.at(cnt).endsWith(QString("\n%1").arg(expression)))
            return index(cnt, 0);
    }

    return QModelIndex();
}

void FilterListModel::removeFilter(QModelIndex idx)
{
    if (! idx.isValid() || idx.row() >= rowCount())
        return;

    beginRemoveRows(QModelIndex(), idx.row(), idx.row());
    storage.removeAt(idx.row());
    endRemoveRows();
}

void FilterListModel::saveList()
{
    const char *cfile;
    QString filename;

    switch (type_) {
        case Capture: cfile = CFILTER_FILE_NAME; break;
        case Display: cfile = DFILTER_FILE_NAME; break;
        case DisplayMacro: cfile = DMACROS_FILE_NAME; break;
        default: ws_assert_not_reached();
    }

    filename = QString("%1%2%3").arg(ProfileModel::activeProfilePath()).arg("/").arg(cfile);
    QFile file(filename);

    if (! file.open(QIODevice::WriteOnly | QIODevice::Text))
        return;

    QTextStream out(&file);
    for (int row = 0; row < rowCount(); row++)
    {
        QString line = QString("\"%1\"").arg(index(row, ColumnName).data().toString().trimmed());
        line.append(QString(" %1").arg(index(row, ColumnExpression).data().toString()));

#if QT_VERSION >= QT_VERSION_CHECK(5, 14, 0)
        out << line << Qt::endl;
#else
        out << line << endl;
#endif
    }

    file.close();
}

Qt::DropActions FilterListModel::supportedDropActions() const
{
    return Qt::MoveAction;
}

QStringList FilterListModel::mimeTypes() const
{
    return QStringList() << WiresharkMimeData::FilterListMimeType;
}

QMimeData *FilterListModel::mimeData(const QModelIndexList &indexes) const
{
    QMimeData *mimeData = new QMimeData();
    QStringList rows;

    foreach (const QModelIndex &index, indexes)
    {
        if (! rows.contains(QString::number(index.row())))
            rows << QString::number(index.row());
    }

    mimeData->setData(WiresharkMimeData::FilterListMimeType, rows.join(",").toUtf8());
    return mimeData;
}

bool FilterListModel::dropMimeData(const QMimeData *data, Qt::DropAction action, int row, int /* column */, const QModelIndex & parent)
{
    if (action != Qt::MoveAction)
        return true;

    if (! data->hasFormat(WiresharkMimeData::FilterListMimeType))
        return true;

    QStringList rows = QString(data->data(WiresharkMimeData::FilterListMimeType)).split(",");

    int insertRow = parent.isValid() ? parent.row() : row;

    /* for now, only single rows can be selected */
    if (rows.count() > 0)
    {
        bool ok = false;
        int strow = rows[0].toInt(&ok);
        if (ok)
        {
            int storeTo = insertRow;
            if (storeTo < 0 || storeTo >= storage.count())
            {
                storeTo = static_cast<int>(storage.count()) - 1;
            }

            beginResetModel();
            storage.move(strow, storeTo);
            endResetModel();
        }
    }

    return true;
}
