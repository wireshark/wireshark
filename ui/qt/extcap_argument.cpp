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
#include <extcap_argument_multiselect.h>

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

        connect ( boxSelection, SIGNAL(currentIndexChanged(int)), SLOT(onIntChanged(int)) );

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

                connect(radio, SIGNAL(clicked(bool)), SLOT(onBoolChanged(bool)));
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

        connect (boolBox, SIGNAL(stateChanged(int)), SLOT(onIntChanged(int)));

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

        connect(textBox , SIGNAL(textChanged(QString)), SLOT(onStringChanged(QString)));

        return textBox;
    }

    virtual QString value()
    {
        if ( textBox == 0 )
            return QString();

        return textBox->text();
    }

    virtual bool isValid()
    {
        if ( isRequired() && value().length() == 0 )
            return false;

        return true;
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
        textBox->disconnect(SIGNAL(textChanged(QString)));

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

        connect(textBox, SIGNAL(textChanged(QString)), SLOT(onStringChanged(QString)));

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


bool ExtcapArgument::isValid()
{
    return value().length() > 0;
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

bool ExtcapArgument::isRequired()
{
    if ( _argument != NULL )
        return _argument->is_required;

    return FALSE;
}

bool ExtcapArgument::fileExists()
{
    if ( _argument != NULL )
        return _argument->fileexists;

    return FALSE;
}

bool ExtcapArgument::isDefault()
{
    if ( value().compare(defaultValue()) == 0 )
        return true;

    return false;
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

/* The following is a necessity, because Q_Object does not do well with multiple inheritances */
void ExtcapArgument::onStringChanged(QString)
{
    emit valueChanged();
}

void ExtcapArgument::onIntChanged(int)
{
    if ( isValid() )
        emit valueChanged();
}

void ExtcapArgument::onBoolChanged(bool)
{
    emit valueChanged();
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
