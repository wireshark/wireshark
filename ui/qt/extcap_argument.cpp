/* extcap_argument.cpp
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

#include <extcap_argument.h>

#include <QObject>
#include <QWidget>
#include <QLabel>
#include <QLineEdit>
#include <QIntValidator>
#include <QDoubleValidator>
#include <QCheckBox>
#include <QButtonGroup>
#include <QBoxLayout>
#include <QRadioButton>
#include <QComboBox>
#include <QPushButton>
#include <QMargins>
#include <QVariant>
#include <QAbstractItemModel>
#include <QStringList>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QItemSelectionModel>
#include <QTreeView>

#include <extcap_parser.h>
#include <extcap_argument_file.h>

class ExtArgMultiSelect : public ExtcapArgument
{
public:
    ExtArgMultiSelect(extcap_arg * argument) :
        ExtcapArgument(argument), treeView(0), viewModel(0) {};

    virtual QList<QStandardItem *> valueWalker(ExtcapValueList list, QStringList &defaults)
    {
        ExtcapValueList::iterator iter = list.begin();
        QList<QStandardItem *> items;

        while ( iter != list.end() )
        {
            QStandardItem * item = new QStandardItem((*iter).value());
            if ( (*iter).enabled() == false )
            {
                item->setSelectable(false);
            }
            else
                item->setSelectable(true);

            item->setData((*iter).call(), Qt::UserRole);
            if ((*iter).isDefault())
                defaults << (*iter).call();

            item->setEditable(false);
            QList<QStandardItem *> childs = valueWalker((*iter).children(), defaults);
            if ( childs.length() > 0 )
                item->appendRows(childs);

            items << item;
            ++iter;
        }

        return items;
    }

    void selectItemsWalker(QStandardItem * item, QStringList defaults)
    {
        QModelIndexList results;
        QModelIndex index;

        if ( item->hasChildren() )
        {
            for (int row = 0; row < item->rowCount(); row++)
            {
                QStandardItem * child = item->child(row);
                if ( child != 0 )
                {
                    selectItemsWalker(child, defaults);
                }
            }
        }

        QString data = item->data(Qt::UserRole).toString();

        if ( defaults.contains(data) )
        {
            treeView->selectionModel()->select(item->index(), QItemSelectionModel::Select);
            index = item->index();
            while ( index.isValid() )
            {
                treeView->setExpanded(index, true);
                index = index.parent();
            }
        }
    }

    virtual QWidget * createEditor(QWidget * parent)
    {
        QStringList defaults;

        QList<QStandardItem *> items = valueWalker(values, defaults);
        if (items.length() == 0)
            return new QWidget();

        if ( _default != 0 )
             defaults = _default->toString().split(",", QString::SkipEmptyParts);

        viewModel = new QStandardItemModel();
        QList<QStandardItem *>::const_iterator iter = items.constBegin();
        while ( iter != items.constEnd() )
        {
            ((QStandardItemModel *)viewModel)->appendRow((*iter));
            ++iter;
        }

        treeView = new QTreeView(parent);
        treeView->setModel(viewModel);

        /* Shows at minimum 6 entries at most desktops */
        treeView->setMinimumHeight(100);
        treeView->setHeaderHidden(true);
        treeView->setSelectionMode(QAbstractItemView::ExtendedSelection);
        treeView->setEditTriggers(QAbstractItemView::NoEditTriggers);

        for (int row = 0; row < viewModel->rowCount(); row++ )
            selectItemsWalker(((QStandardItemModel*)viewModel)->item(row), defaults);

        return treeView;
    }

    virtual QString value()
    {
        if ( viewModel == 0 )
            return QString();

        QStringList result;
        QModelIndexList selected = treeView->selectionModel()->selectedIndexes();

        if ( selected.size() <= 0 )
            return QString();

        QModelIndexList::const_iterator iter = selected.constBegin();
        while ( iter != selected.constEnd() )
        {
            QModelIndex index = (QModelIndex)(*iter);

            result << viewModel->data(index, Qt::UserRole).toString();

            ++iter;
        }

        return result.join(QString(","));
    }

    virtual QString defaultValue()
    {
        if ( _argument != 0 && _argument->default_complex != 0)
        {
            gchar * str = extcap_get_complex_as_string(_argument->default_complex);
            if ( str != 0 )
                return QString(str);
        }

        return QString();
    }

private:
    QTreeView * treeView;
    QAbstractItemModel * viewModel;
};

class ExtArgSelector : public ExtcapArgument
{
public:
    ExtArgSelector(extcap_arg * argument) :
        ExtcapArgument(argument), boxSelection(0) {};

    virtual QWidget * createEditor(QWidget * parent)
    {
        int counter = 0;
        int selected = -1;

        boxSelection = new QComboBox(parent);

        if ( values.length() > 0 )
        {
            ExtcapValueList::const_iterator iter = values.constBegin();

            while ( iter != values.constEnd() )
            {
                boxSelection->addItem((*iter).value(), (*iter).call());
                if ( (*iter).isDefault() )
                    selected = counter;

                counter++;
                ++iter;
            }

            if ( selected > -1 && selected < boxSelection->count() )
                boxSelection->setCurrentIndex(selected);
        }

        return boxSelection;
    }

    virtual QString value()
    {
        if ( boxSelection == 0 )
            return QString();

#if QT_VERSION >= QT_VERSION_CHECK(5, 2, 0)
        QVariant data = boxSelection->currentData();
#else
        QVariant data = boxSelection->itemData(boxSelection->currentIndex());
#endif

        return data.toString();
    }

private:
    QComboBox * boxSelection;
};

class ExtArgRadio : public ExtcapArgument
{
public:
    ExtArgRadio(extcap_arg * argument) :
        ExtcapArgument(argument), selectorGroup(0), callStrings(0)
    {
    };

    virtual QWidget * createEditor(QWidget * parent)
    {

        int count = 0;
        bool anyChecked = false;

        selectorGroup = new QButtonGroup(parent);
        QWidget * radioButtons = new QWidget;
        QVBoxLayout * vrLayout = new QVBoxLayout();
        QMargins margins = vrLayout->contentsMargins();
        vrLayout->setContentsMargins(0, 0, 0, margins.bottom());
        if ( callStrings != 0 )
            delete callStrings;

        callStrings = new QList<QString>();

        if ( values.length() > 0  )
        {
            ExtcapValueList::const_iterator iter = values.constBegin();

            while ( iter != values.constEnd() )
           {
                QRadioButton * radio = new QRadioButton((*iter).value());
                QString callString = (*iter).call();
                callStrings->append(callString);

                if ( _default != NULL && (*iter).isDefault() )
                {
                    radio->setChecked(true);
                    anyChecked = true;
                }
                else if (_default != NULL)
                {
                    if ( callString.compare(_default->toString()) == 0 )
                    {
                        radio->setChecked(true);
                        anyChecked = true;
                    }
                }
                selectorGroup->addButton(radio, count);

                vrLayout->addWidget(radio);
                count++;

                ++iter;
            }
        }

        /* No default was provided, and not saved value exists */
        if ( anyChecked == false && count > 0 )
            ((QRadioButton*)(selectorGroup->button(0)))->setChecked(true);

        radioButtons->setLayout(vrLayout);

        return radioButtons;
    }

    virtual QString value()
    {
        int idx = 0;
        if ( selectorGroup == 0 || callStrings == 0 )
            return QString();

        idx = selectorGroup->checkedId();
        if ( idx > -1 && callStrings->length() > idx )
            return callStrings->takeAt(idx);

        return QString();
    }

private:
    QButtonGroup * selectorGroup;
    QList<QString> * callStrings;
};

class ExtArgBool : public ExtcapArgument
{
public:
    ExtArgBool(extcap_arg * argument) :
        ExtcapArgument(argument), boolBox(0) {};

    virtual QWidget * createLabel(QWidget * parent)
    {
        return new QWidget(parent);
    }

    virtual QWidget * createEditor(QWidget * parent)
    {
        boolBox = new QCheckBox(QString().fromUtf8(_argument->display), parent);
        if ( _argument->tooltip != NULL )
            boolBox->setToolTip(QString().fromUtf8(_argument->tooltip));

        if ( _argument->default_complex != NULL )
            if ( extcap_complex_get_bool(_argument->default_complex) == (gboolean)TRUE )
                boolBox->setCheckState(Qt::Checked);

        if ( _default != NULL )
        {
            if ( _default->toString().compare("true") )
                boolBox->setCheckState(Qt::Checked);
        }

        return boolBox;
    }

    virtual QString call()
    {
        if ( boolBox == NULL )
            return QString("");

        if ( _argument->arg_type == EXTCAP_ARG_BOOLEAN )
            return ExtcapArgument::call();

        return QString(boolBox->checkState() == Qt::Checked ? _argument->call : "");
    }

    virtual QString value()
    {
        if ( boolBox == NULL || _argument->arg_type == EXTCAP_ARG_BOOLFLAG )
            return QString();
        return QString(boolBox->checkState() == Qt::Checked ? "true" : "false");
    }

    virtual QString defaultValue()
    {
        if ( _argument != 0 && _argument->default_complex != NULL )
            if ( extcap_complex_get_bool(_argument->default_complex) == (gboolean)TRUE )
                return QString("true");

        return QString("false");
    }

private:
    QCheckBox * boolBox;
};

class ExtArgText : public ExtcapArgument
{
public:
    ExtArgText(extcap_arg * argument) :
        ExtcapArgument(argument), textBox(0)
    {
        _default = new QVariant(QString(""));
    };

    virtual QWidget * createEditor(QWidget * parent)
    {
        textBox = new QLineEdit(_default->toString(), parent);

        textBox->setText(defaultValue());

        if ( _argument->tooltip != NULL )
            textBox->setToolTip(QString().fromUtf8(_argument->tooltip));

        return textBox;
    }

    virtual QString value()
    {
        if ( textBox == 0 )
            return QString();

        return textBox->text();
    }

    virtual QString defaultValue()
    {
        if ( _argument != 0 && _argument->default_complex != 0)
        {
            gchar * str = extcap_get_complex_as_string(_argument->default_complex);
            if ( str != 0 )
                return QString(str);
        }

        return QString();
    }

protected:
    QLineEdit * textBox;
};

class ExtArgNumber : public ExtArgText
{
public:
    ExtArgNumber(extcap_arg * argument) :
        ExtArgText(argument) {};

    virtual QWidget * createEditor(QWidget * parent)
    {
        textBox = (QLineEdit *)ExtArgText::createEditor(parent);

        if ( _argument->arg_type == EXTCAP_ARG_INTEGER || _argument->arg_type == EXTCAP_ARG_UNSIGNED )
        {
            QIntValidator * textValidator = new QIntValidator(parent);
            if ( _argument->range_start != NULL )
                textValidator->setBottom(extcap_complex_get_int(_argument->range_start));

            if ( _argument->arg_type == EXTCAP_ARG_UNSIGNED && textValidator->bottom() < 0 )
                textValidator->setBottom(0);

            if ( _argument->range_end != NULL )
                textValidator->setTop(extcap_complex_get_int(_argument->range_end));
            textBox->setValidator(textValidator);
        }
        else if ( _argument->arg_type == EXTCAP_ARG_DOUBLE )
        {
            QDoubleValidator * textValidator = new QDoubleValidator(parent);
            if ( _argument->range_start != NULL )
                textValidator->setBottom(extcap_complex_get_double(_argument->range_start));
            if ( _argument->range_end != NULL )
                textValidator->setTop(extcap_complex_get_double(_argument->range_end));

            textBox->setValidator(textValidator);
        }

        textBox->setText(defaultValue());

        return textBox;
    };

    virtual QString defaultValue()
    {
        QString result;

        if ( _argument != 0 && _argument->default_complex != NULL )
        {
            if ( _argument->arg_type == EXTCAP_ARG_DOUBLE )
                result = QString::number(extcap_complex_get_double(_argument->default_complex));
            else if ( _argument->arg_type == EXTCAP_ARG_INTEGER )
                result = QString::number(extcap_complex_get_int(_argument->default_complex));
            else if ( _argument->arg_type == EXTCAP_ARG_UNSIGNED )
                result = QString::number(extcap_complex_get_uint(_argument->default_complex));
            else if ( _argument->arg_type == EXTCAP_ARG_LONG )
                result = QString::number(extcap_complex_get_long(_argument->default_complex));
            else
                result = QString();
        }

        return result;
    }
};

ExtcapValue::~ExtcapValue() {}

void ExtcapValue::setChildren(ExtcapValueList children)
{
    ExtcapValueList::iterator iter = children.begin();
    while ( iter != children.end() )
    {
        (*iter)._depth = _depth + 1;
        ++iter;
    }

    _children.append(children);
}

ExtcapArgument::ExtcapArgument(extcap_arg * argument, QObject *parent) :
        QObject(parent), _argument(argument), _default(0)
{
    if ( _argument->values != 0 )
    {
        ExtcapValueList elements = loadValues(QString(""));
        if ( elements.length() > 0 )
            values.append(elements);
    }
}

ExtcapValueList ExtcapArgument::loadValues(QString parent)
{
    if (_argument->values == 0 )
        return ExtcapValueList();

    GList * walker = 0;
    extcap_value * v;
    ExtcapValueList elements;

    for (walker = g_list_first((GList *)(_argument->values)); walker != NULL ; walker = walker->next)
    {
        v = (extcap_value *) walker->data;
        if (v == NULL || v->display == NULL || v->call == NULL )
            break;

        QString valParent(v->parent == 0 ? "" : QString().fromUtf8(v->parent));

        if ( parent.compare(valParent) == 0 )
        {

            QString display = QString().fromUtf8(v->display);
            QString call = QString().fromUtf8(v->call);

            ExtcapValue element = ExtcapValue(display, call,
                            v->enabled == (gboolean)TRUE, v->is_default == (gboolean)TRUE);

            element.setChildren(this->loadValues(call));
            elements.append(element);
        }
    }

    return elements;
}

ExtcapArgument::~ExtcapArgument() {
    // TODO Auto-generated destructor stub
}

QWidget * ExtcapArgument::createLabel(QWidget * parent)
{
    if ( _argument == 0 || _argument->display == 0 )
        return 0;

    QString text = QString().fromUtf8(_argument->display);

    QLabel * label = new QLabel(text, parent);
    if ( _argument->tooltip != 0 )
        label->setToolTip(QString().fromUtf8(_argument->tooltip));

    return label;
}

QWidget * ExtcapArgument::createEditor(QWidget *)
{
    return 0;
}

QString ExtcapArgument::call()
{
    return QString(_argument->call);
}

QString ExtcapArgument::value()
{
    return QString();
}

QString ExtcapArgument::defaultValue()
{
    return QString();
}

void ExtcapArgument::setDefault(GHashTable * defaultsList)
{
    if ( defaultsList != NULL && g_hash_table_size(defaultsList) > 0 )
    {
        GList * keys = g_hash_table_get_keys(defaultsList);
        while ( keys != NULL )
        {
            if ( call().compare(QString().fromUtf8((gchar *)keys->data)) == 0 )
            {
                gpointer data = g_hash_table_lookup(defaultsList, keys->data);
                QString dataStr = QString().fromUtf8((gchar *)data);
                /* We assume an empty value but set entry must be a boolflag */
                if ( dataStr.length() == 0 )
                    dataStr = "true";
                _default = new QVariant(dataStr);
                break;
            }
            keys = keys->next;
        }
    }
}

ExtcapArgument * ExtcapArgument::create(extcap_arg * argument, GHashTable * device_defaults)
{
    if ( argument == 0 || argument->display == 0 )
        return 0;

    ExtcapArgument * result = 0;

    if ( argument->arg_type == EXTCAP_ARG_STRING )
        result = new ExtArgText(argument);
    else if ( argument->arg_type == EXTCAP_ARG_INTEGER || argument->arg_type == EXTCAP_ARG_LONG ||
            argument->arg_type == EXTCAP_ARG_UNSIGNED || argument->arg_type == EXTCAP_ARG_DOUBLE )
        result = new ExtArgNumber(argument);
    else if ( argument->arg_type == EXTCAP_ARG_BOOLEAN || argument->arg_type == EXTCAP_ARG_BOOLFLAG )
        result = new ExtArgBool(argument);
    else if ( argument->arg_type == EXTCAP_ARG_SELECTOR )
        result = new ExtArgSelector(argument);
    else if ( argument->arg_type == EXTCAP_ARG_RADIO )
        result = new ExtArgRadio(argument);
    else if ( argument->arg_type == EXTCAP_ARG_FILESELECT )
        result = new ExtcapArgumentFileSelection(argument);
    else if ( argument->arg_type == EXTCAP_ARG_MULTICHECK )
        result = new ExtArgMultiSelect(argument);
    else
    {
        /* For everything else, we just print the label */
        result = new ExtcapArgument(argument);
    }

    result->setDefault(device_defaults);

    return result;
}

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
