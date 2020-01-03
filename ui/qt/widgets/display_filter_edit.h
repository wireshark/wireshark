/* display_filter_edit.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DISPLAYFILTEREDIT_H
#define DISPLAYFILTEREDIT_H

#include <QDrag>
#include <QActionGroup>

#include <ui/qt/widgets/syntax_line_edit.h>

class QEvent;
class StockIconToolButton;

typedef enum {
    DisplayFilterToApply,
    DisplayFilterToEnter,
    ReadFilterToApply
} DisplayFilterEditType;

class DisplayFilterEdit : public SyntaxLineEdit
{
    Q_OBJECT
public:
    explicit DisplayFilterEdit(QWidget *parent = 0, DisplayFilterEditType type = DisplayFilterToEnter);

protected:
    void paintEvent(QPaintEvent *evt);
    void resizeEvent(QResizeEvent *);
    void keyPressEvent(QKeyEvent *event) { completionKeyPressEvent(event); }
    void focusInEvent(QFocusEvent *event) { completionFocusInEvent(event); }
    void focusOutEvent(QFocusEvent *event);

    virtual void dragEnterEvent(QDragEnterEvent *event);
    virtual void dragMoveEvent(QDragMoveEvent *event);
    virtual void dropEvent(QDropEvent *event);
    virtual void contextMenuEvent(QContextMenuEvent *menu);

public slots:
    bool checkFilter();
    void updateBookmarkMenu();
    void applyDisplayFilter();
    void displayFilterSuccess(bool success);

private slots:
    void checkFilter(const QString &filter_text);
    void clearFilter();
    void changeEvent(QEvent* event);

    void displayFilterExpression();

    void saveFilter();
    void removeFilter();
    void showFilters();
    void showExpressionPrefs();
    void applyOrPrepareFilter();

    void triggerAlignementAction();

    void connectToMainWindow();

private:
    DisplayFilterEditType type_;
    QString placeholder_text_;
    QAction *save_action_;
    QAction *remove_action_;
    QActionGroup * actions_;
    StockIconToolButton *bookmark_button_;
    StockIconToolButton *clear_button_;
    StockIconToolButton *apply_button_;
    bool leftAlignActions_;
    QString last_applied_;

    void setDefaultPlaceholderText();
    void buildCompletionList(const QString& field_word);

    void createFilterTextDropMenu(QDropEvent *event, bool prepare, QString filterText = QString());

    void alignActionButtons();
    void updateClearButton();

signals:
    void pushFilterSyntaxStatus(const QString&);
    void popFilterSyntaxStatus();
    void filterPackets(QString new_filter, bool force);
    void showPreferencesDialog(QString pane_name);

};

#endif // DISPLAYFILTEREDIT_H

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
