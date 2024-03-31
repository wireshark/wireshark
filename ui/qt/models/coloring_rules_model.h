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

class ColoringRuleItem : public ModelHelperTreeItem<ColoringRuleItem>
{
public:
    ColoringRuleItem(bool disabled, QString name, QString filter, QColor foreground, QColor background, ColoringRuleItem* parent);
    virtual ~ColoringRuleItem();

    ColoringRuleItem(color_filter_t *colorf, ColoringRuleItem* parent);
    ColoringRuleItem(const ColoringRuleItem& item);

    bool disabled_;
    QString name_;
    QString filter_;
    QColor foreground_;
    QColor background_;

    ColoringRuleItem& operator=(ColoringRuleItem& rhs);

};

class ColoringRulesModel : public QAbstractItemModel
{
    Q_OBJECT

public:
    ColoringRulesModel(QColor defaultForeground, QColor defaultBackground, QObject *parent);
    virtual ~ColoringRulesModel();

    enum ColoringRulesColumn {
        colName = 0,
        colFilter,
        colColoringRulesMax
    };

    void addColor(color_filter_t* colorf);
    void addColor(bool disabled, QString filter, QColor foreground, QColor background);
    bool importColors(QString filename, QString& err);
    bool exportColors(QString filename, QString& err);
    bool writeColors(QString& err);

    Qt::ItemFlags flags(const QModelIndex &index) const;
    QVariant data(const QModelIndex &index, int role) const;
    bool setData(const QModelIndex &index, const QVariant &value, int role = Qt::EditRole);
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const;
    QModelIndex index(int row, int column,
                      const QModelIndex & = QModelIndex()) const;
    QModelIndex parent(const QModelIndex &) const;

    //Drag & drop functionality
    Qt::DropActions supportedDropActions() const;
    QStringList mimeTypes() const;
    QMimeData* mimeData(const QModelIndexList &indexes) const;
    bool dropMimeData(const QMimeData *data, Qt::DropAction action, int row, int column, const QModelIndex &parent);

    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;

    bool insertRows(int row, int count, const QModelIndex &parent = QModelIndex());
    bool removeRows(int row, int count, const QModelIndex &parent = QModelIndex());
    bool copyRow(int dst_row, int src_row);

private:
    void populate();
    struct _GSList *createColorFilterList();

    ColoringRuleItem* root_;
    //Save off the conversation colors, do not include in dialog
    struct _GSList *conversation_colors_;

    QColor defaultForeground_;
    QColor defaultBackground_;

    QList<int> dragDropRows_;
};

#endif // COLORING_RULES_MODEL_H
