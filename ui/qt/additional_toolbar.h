/* additional_toolbar.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef UI_QT_ADDITIONAL_TOOLBAR_H_
#define UI_QT_ADDITIONAL_TOOLBAR_H_

#include <epan/plugin_if.h>

#include <QToolBar>
#include <QWidgetAction>

/* Class for all display widgets.
 *
 * Inherits QWidgetAction, otherwise the extension popup might not work for the toolbar
 */
class AdditionalToolbarWidgetAction: public QWidgetAction
{
    Q_OBJECT

public:

    AdditionalToolbarWidgetAction(QObject * parent = 0);
    AdditionalToolbarWidgetAction(ext_toolbar_t * item, QObject * parent = 0);
    AdditionalToolbarWidgetAction(const AdditionalToolbarWidgetAction & copy_object);
    ~AdditionalToolbarWidgetAction();

protected:
    virtual QWidget * createWidget(QWidget * parent);

    static const char * propertyName;

private:

    ext_toolbar_t * toolbar_item;

    QWidget * createButton(ext_toolbar_t * item, QWidget * parent);
    QWidget * createBoolean(ext_toolbar_t * item, QWidget * parent);
    QWidget * createTextEditor(ext_toolbar_t * item, QWidget * parent);
    QWidget * createSelector(ext_toolbar_t * item, QWidget * parent);

    QWidget * createLabelFrame(ext_toolbar_t * item, QWidget * parent);

    ext_toolbar_t * extractToolbarItemFromObject(QObject *);

private slots:
    void onButtonClicked();
    void onCheckBoxChecked(int);
    void sendTextToCallback();
    void onSelectionInWidgetChanged(int idx);

    void captureActive(int);
};

class AdditionalToolBar: public QToolBar
{
    Q_OBJECT

public:
    AdditionalToolBar(ext_toolbar_t * toolbar, QWidget * parent = 0);
    virtual ~AdditionalToolBar();

    static AdditionalToolBar * create(QWidget * parent, ext_toolbar_t * toolbar);

    QString menuName();

private:
    ext_toolbar_t * toolbar;
};

#endif /* UI_QT_ADDITIONAL_TOOLBAR_H_ */

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
