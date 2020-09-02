/* filter_expression_toolbar.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/drag_drop_toolbar.h>

#include <glib.h>

#include <QMenu>

#ifndef FILTER_EXPRESSION_TOOLBAR_H
#define FILTER_EXPRESSION_TOOLBAR_H

class FilterExpressionToolBar : public DragDropToolBar
{
    Q_OBJECT
public:
    explicit FilterExpressionToolBar(QWidget * parent = Q_NULLPTR);

protected:
    virtual bool event(QEvent *event) override;
    virtual bool eventFilter(QObject *obj, QEvent *ev) override;

    virtual WiresharkMimeData * createMimeData(QString name, int position) override;

public slots:
    void filterExpressionsChanged();

signals:
    void filterSelected(QString, bool);
    void filterPreferences();
    void filterEdit(int uatIndex);

protected slots:
    void onCustomMenuHandler(const QPoint &pos);
    void onActionMoved(QAction * action, int oldPos, int newPos);
    void onFilterDropped(QString description, QString filter);

private slots:
    void removeFilter();
    void disableFilter();
    void editFilter();
    void filterClicked();
    void toolBarShowPreferences();

    void closeMenu(QAction *);

private:
    void updateStyleSheet();
    int uatRowIndexForFilter(QString label, QString expression);

    void customMenu(FilterExpressionToolBar * target, QAction * filterAction, const QPoint& pos);

    static gboolean filter_expression_add_action(const void *key, void *value, void *user_data);
    static QMenu * findParentMenu(const QStringList tree, void *fed_data, QMenu *parent = Q_NULLPTR);
};

#endif //FILTER_EXPRESSION_TOOLBAR_H

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
