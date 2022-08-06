/* extcap_argument.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <extcap_argument.h>

#include <QObject>
#include <QWidget>
#include <QLabel>
#include <QLineEdit>
#include <QDateTimeEdit>
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
#include <QRegularExpression>

#include <glib.h>

#include <extcap.h>
#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <wsutil/wslog.h>
#include <ui/qt/utils/color_utils.h>

#include <extcap_parser.h>
#include <extcap_argument_file.h>
#include <extcap_argument_multiselect.h>

#include <ui/qt/extcap_options_dialog.h>

ExtArgTimestamp::ExtArgTimestamp(extcap_arg * argument, QObject * parent) :
    ExtcapArgument(argument, parent), tsBox(0) {}

QWidget * ExtArgTimestamp::createEditor(QWidget * parent)
{
    QString text = defaultValue();

    if (_argument->pref_valptr && strlen(*_argument->pref_valptr))
    {
        QString storeValue(*_argument->pref_valptr);
        text = storeValue.trimmed();
    }

    ts = QDateTime::fromSecsSinceEpoch(text.toInt());
    tsBox = new QDateTimeEdit(ts, parent);
    tsBox->setDisplayFormat(QLocale::system().dateTimeFormat());
    tsBox->setCalendarPopup(true);
    tsBox->setAutoFillBackground(true);

    if (_argument->tooltip != NULL)
        tsBox->setToolTip(QString().fromUtf8(_argument->tooltip));

    connect(tsBox, SIGNAL(dateTimeChanged(QDateTime)), SLOT(onDateTimeChanged(QDateTime)));

    return tsBox;
}

void ExtArgTimestamp::onDateTimeChanged(QDateTime t)
{
    ts = t;
    emit valueChanged();
}

QString ExtArgTimestamp::defaultValue()
{
    return QString::number(QDateTime::currentDateTime().toSecsSinceEpoch());
}

bool ExtArgTimestamp::isValid()
{
    bool valid = true;

    if (value().length() == 0 && isRequired())
        valid = false;

    return valid;
}

QString ExtArgTimestamp::value()
{
    return QString::number(ts.toSecsSinceEpoch());
}

QString ExtArgTimestamp::prefValue()
{
    return value();
}

bool ExtArgTimestamp::isSetDefaultValueSupported()
{
    return TRUE;
}

void ExtArgTimestamp::setDefaultValue()
{
    QDateTime t;

    t = QDateTime::fromSecsSinceEpoch(defaultValue().toInt());
    tsBox->setDateTime(t);
}



ExtArgSelector::ExtArgSelector(extcap_arg * argument, QObject * parent) :
        ExtcapArgument(argument, parent), boxSelection(0) {}

QWidget * ExtArgSelector::createEditor(QWidget * parent)
{
    QWidget * editor = new QWidget(parent);
    QHBoxLayout * layout = new QHBoxLayout();
    QMargins margins = layout->contentsMargins();
    layout->setContentsMargins(0, margins.top(), 0, margins.bottom());

    boxSelection = new QComboBox(parent);
    boxSelection->setToolTip(QString().fromUtf8(_argument->tooltip));
    layout->addWidget(boxSelection);

    if (values.length() > 0)
    {
        ExtcapValueList::const_iterator iter = values.constBegin();

        while (iter != values.constEnd())
        {
            boxSelection->addItem((*iter).value(), (*iter).call());
            ++iter;
        }
    }

    setDefaultValue();

    if (reload())
    {
        QString btnText(tr("Reload data"));
        if (_argument->placeholder)
            btnText = QString(_argument->placeholder);

        QPushButton * reloadButton = new QPushButton(btnText, editor);
        layout->addWidget(reloadButton);
        reloadButton->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Preferred);
        boxSelection->setSizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::Preferred);

        connect(reloadButton, SIGNAL(clicked()), this, SLOT(onReloadTriggered()));
    }

    connect (boxSelection, SIGNAL(currentIndexChanged(int)), SLOT(onIntChanged(int)));

    editor->setLayout(layout);

    return editor;
}

void ExtArgSelector::onReloadTriggered()
{
    int counter = 0;
    int selected = -1;

    QString call = boxSelection->currentData().toString();
    const char *prefval = (_argument->pref_valptr && strlen(*_argument->pref_valptr)) ? *_argument->pref_valptr : NULL;
    QString stored(prefval ? prefval : "");
    if (call != stored)
        stored = call;

    if (reloadValues() && values.length() > 0)
    {
        boxSelection->clear();

        ExtcapValueList::const_iterator iter = values.constBegin();

        while (iter != values.constEnd())
        {
            boxSelection->addItem((*iter).value(), (*iter).call());

            if (stored.compare((*iter).call()) == 0)
                selected = counter;
            else if ((*iter).isDefault() && selected == -1)
                selected = counter;

            counter++;
            ++iter;
        }

        if (selected > -1 && selected < boxSelection->count())
            boxSelection->setCurrentIndex(selected);
    }
}

bool ExtArgSelector::isValid()
{
    bool valid = true;

    if (value().length() == 0 && isRequired())
        valid = false;

    if (boxSelection)
    {
        QString lblInvalidColor = ColorUtils::fromColorT(prefs.gui_text_invalid).name();
        QString cmbBoxStyle("QComboBox { background-color: %1; } ");
        boxSelection->setStyleSheet(cmbBoxStyle.arg(valid ? QString("") : lblInvalidColor));
    }

    return valid;
}

QString ExtArgSelector::value()
{
    if (boxSelection == 0)
        return QString();

    QVariant data = boxSelection->currentData();

    return data.toString();
}

bool ExtArgSelector::isSetDefaultValueSupported()
{
    return TRUE;
}

void ExtArgSelector::setDefaultValue()
{
    int counter = 0;
    int selected = -1;

    const char *prefval = (_argument->pref_valptr && strlen(*_argument->pref_valptr)) ? *_argument->pref_valptr : NULL;
    QString stored(prefval ? prefval : "");

    if (values.length() > 0)
    {
        ExtcapValueList::const_iterator iter = values.constBegin();

        while (iter != values.constEnd())
        {
            if (!prefval && (*iter).isDefault())
                selected = counter;
            else if (prefval && stored.compare((*iter).call()) == 0)
                selected = counter;

            counter++;
            ++iter;
        }

        if (selected > -1 && selected < boxSelection->count())
            boxSelection->setCurrentIndex(selected);
    }

}



ExtArgRadio::ExtArgRadio(extcap_arg * argument, QObject * parent) :
        ExtcapArgument(argument, parent), selectorGroup(0), callStrings(0) {}

QWidget * ExtArgRadio::createEditor(QWidget * parent)
{
    int count = 0;

    selectorGroup = new QButtonGroup(parent);
    QWidget * radioButtons = new QWidget;
    QVBoxLayout * vrLayout = new QVBoxLayout();
    QMargins margins = vrLayout->contentsMargins();
    vrLayout->setContentsMargins(0, 0, 0, margins.bottom());
    if (callStrings != 0)
        delete callStrings;

    callStrings = new QList<QString>();

    if (values.length() > 0)
    {
        ExtcapValueList::const_iterator iter = values.constBegin();

        while (iter != values.constEnd())
        {
            QRadioButton * radio = new QRadioButton((*iter).value());
            QString callString = (*iter).call();
            callStrings->append(callString);

            connect(radio, SIGNAL(clicked(bool)), SLOT(onBoolChanged(bool)));
            selectorGroup->addButton(radio, count);

            vrLayout->addWidget(radio);
            count++;

            ++iter;
        }
    }

    setDefaultValue();

    radioButtons->setLayout(vrLayout);

    return radioButtons;
}

QString ExtArgRadio::value()
{
    int idx = 0;
    if (selectorGroup == 0 || callStrings == 0)
        return QString();

    idx = selectorGroup->checkedId();
    if (idx > -1 && callStrings->length() > idx)
        return callStrings->at(idx);

    return QString();
}

bool ExtArgRadio::isValid()
{
    bool valid = true;
    int idx = 0;

    if (isRequired())
    {
        if (selectorGroup == 0 || callStrings == 0)
            valid = false;
        else
        {
            idx = selectorGroup->checkedId();
            if (idx == -1 || callStrings->length() <= idx)
                valid = false;
        }
    }

    /* If nothing is selected, but a selection is required, the only thing that
     * can be marked is the label */
    QString lblInvalidColor = ColorUtils::fromColorT(prefs.gui_text_invalid).name();
    _label->setStyleSheet (label_style.arg(valid ? QString("") : lblInvalidColor));

    return valid;
}

bool ExtArgRadio::isSetDefaultValueSupported()
{
    return TRUE;
}

void ExtArgRadio::setDefaultValue()
{
    int counter = 0;
    int selected = 0;

    const char *prefval = (_argument->pref_valptr && strlen(*_argument->pref_valptr)) ? *_argument->pref_valptr : NULL;
    QString stored(prefval ? prefval : "");

    if (values.length() > 0)
    {
        ExtcapValueList::const_iterator iter = values.constBegin();

        while (iter != values.constEnd())
        {
            if (!prefval && (*iter).isDefault())
                selected = counter;
            else if (prefval && stored.compare((*iter).call()) == 0)
                selected = counter;

            counter++;
            ++iter;
        }

        ((QRadioButton*)(selectorGroup->button(selected)))->setChecked(true);
    }
}



ExtArgBool::ExtArgBool(extcap_arg * argument, QObject * parent) :
        ExtcapArgument(argument, parent), boolBox(0) {}

QWidget * ExtArgBool::createLabel(QWidget * parent)
{
    return new QWidget(parent);
}

QWidget * ExtArgBool::createEditor(QWidget * parent)
{
    bool state = defaultBool();

    boolBox = new QCheckBox(QString().fromUtf8(_argument->display), parent);
    if (_argument->tooltip != NULL)
        boolBox->setToolTip(QString().fromUtf8(_argument->tooltip));

    const char *prefval = (_argument->pref_valptr && strlen(*_argument->pref_valptr)) ? *_argument->pref_valptr : NULL;
    if (prefval)
    {
        QRegularExpression regexp(EXTCAP_BOOLEAN_REGEX);
        QRegularExpressionMatch match = regexp.match(QString(prefval[0]));
        bool savedstate = match.hasMatch();
        if (savedstate != state)
            state = savedstate;
    }

    boolBox->setCheckState(state ? Qt::Checked : Qt::Unchecked);

    connect (boolBox, SIGNAL(stateChanged(int)), SLOT(onIntChanged(int)));

    return boolBox;
}

QString ExtArgBool::call()
{
    if (boolBox == NULL)
        return QString("");

    if (_argument->arg_type == EXTCAP_ARG_BOOLEAN)
        return ExtcapArgument::call();

    return QString(boolBox->checkState() == Qt::Checked ? _argument->call : "");
}

QString ExtArgBool::value()
{
    if (boolBox == NULL || _argument->arg_type == EXTCAP_ARG_BOOLFLAG)
        return QString();
    return QString(boolBox->checkState() == Qt::Checked ? "true" : "false");
}

QString ExtArgBool::prefValue()
{
    if (boolBox == NULL)
        return QString("false");
    return QString(boolBox->checkState() == Qt::Checked ? "true" : "false");
}

bool ExtArgBool::isValid()
{
    /* A bool is allways valid, but the base function checks on string length,
     * which will fail with boolflags */
    return true;
}

bool ExtArgBool::defaultBool()
{
    bool result = false;

    if (_argument)
    {
        if (extcap_complex_get_bool(_argument->default_complex) == (gboolean)TRUE)
            result = true;
    }

    return result;
}

QString ExtArgBool::defaultValue()
{
    return defaultBool() ? QString("true") : QString("false");
}

bool ExtArgBool::isSetDefaultValueSupported()
{
    return TRUE;
}

void ExtArgBool::setDefaultValue()
{
    boolBox->setCheckState(defaultBool() ? Qt::Checked : Qt::Unchecked);
}



ExtArgText::ExtArgText(extcap_arg * argument, QObject * parent) :
    ExtcapArgument(argument, parent), textBox(0)
{
}

QWidget * ExtArgText::createEditor(QWidget * parent)
{
    QString text = defaultValue();

    /* Prefs can contain empty string. We accept it. */
    if (_argument->pref_valptr && (*_argument->pref_valptr))
    {
        QString storeValue(*_argument->pref_valptr);
        text = storeValue.trimmed();
    }

    textBox = new QLineEdit(text, parent);

    if (_argument->tooltip != NULL)
        textBox->setToolTip(QString().fromUtf8(_argument->tooltip));

    if (_argument->placeholder != NULL)
        textBox->setPlaceholderText(QString().fromUtf8(_argument->placeholder));

    if (_argument->arg_type == EXTCAP_ARG_PASSWORD)
        textBox->setEchoMode(QLineEdit::PasswordEchoOnEdit);

    connect(textBox , SIGNAL(textChanged(QString)), SLOT(onStringChanged(QString)));

    return textBox;
}

QString ExtArgText::value()
{
    if (textBox == 0)
        return QString();

    return textBox->text();
}

bool ExtArgText::isValid()
{
    bool valid = true;

    if (isRequired() && value().length() == 0)
        valid = false;

    /* Does the validator, if any, consider the value valid?
     *
     * If it considers it an "intermediate" value, rather than an "invalid"
     * value, the user will be able to transfer the input focus to another
     * widget, and, as long as all widgets have values for which isValid()
     * is true, they wil be able to click the "Start" button.
     *
     * For QIntValidator(), used for integral fields with minimum and
     * maximum values, a value that's larger than the maximum but has
     * the same number of digits as the maximum is "intermediate" rather
     * than "invalid", so the user will be able to cause that value to
     * be passed to the extcap module; see bug 16510.
     *
     * So we explicitly call the hasAcceptableInput() method on the
     * text box; that returns false if the value is not "valid", and
     * that includes "intermediate" values.
     *
     * This way, 1) non-colorblind users are informed that the value
     * is invalid by the text box background being red (perhaps the
     * user isn't fully colorblind, or perhaps the background is a
     * noticeably different grayscale), and 2) the user won't be able
     * to start the capture until they fix the problem.
     *
     * XXX - it might be nice to have some way of indicating to the
     * user what the problem is with the value - alert box?  Tooltip? */
    if (!textBox->hasAcceptableInput())
        valid = false;

    /* validation should only be checked if there is a value. if the argument
     * must be present (isRequired) the check above will handle that */
    if (valid && _argument->regexp != NULL && value().length() > 0)
    {
        QString regexp = QString().fromUtf8(_argument->regexp);
        if (regexp.length() > 0)
        {
            QRegularExpression expr(regexp, QRegularExpression::UseUnicodePropertiesOption);
            if (! expr.isValid() || ! expr.match(value()).hasMatch())
                valid = false;
        }
    }

    QString lblInvalidColor = ColorUtils::fromColorT(prefs.gui_text_invalid).name();
    QString txtStyle("QLineEdit { background-color: %1; } ");
    textBox->setStyleSheet(txtStyle.arg(valid ? QString("") : lblInvalidColor));

    return valid;
}

bool ExtArgText::isSetDefaultValueSupported()
{
    return TRUE;
}

void ExtArgText::setDefaultValue()
{
    textBox->setText(defaultValue());
}



ExtArgNumber::ExtArgNumber(extcap_arg * argument, QObject * parent) :
        ExtArgText(argument, parent) {}

QWidget * ExtArgNumber::createEditor(QWidget * parent)
{
    QString text = defaultValue();

    if (_argument->pref_valptr && strlen(*_argument->pref_valptr))
    {
        QString storeValue(*_argument->pref_valptr);
        text = storeValue;
    }

    textBox = (QLineEdit *)ExtArgText::createEditor(parent);
    textBox->disconnect(SIGNAL(textChanged(QString)));

    if (_argument->arg_type == EXTCAP_ARG_INTEGER || _argument->arg_type == EXTCAP_ARG_UNSIGNED)
    {
        QIntValidator * textValidator = new QIntValidator(parent);
        if (_argument->range_start != NULL)
        {
            int val = 0;
            if (_argument->arg_type == EXTCAP_ARG_INTEGER)
                val = extcap_complex_get_int(_argument->range_start);
            else if (_argument->arg_type == EXTCAP_ARG_UNSIGNED)
            {
                guint tmp = extcap_complex_get_uint(_argument->range_start);
                if (tmp > G_MAXINT)
                {
                    ws_log(LOG_DOMAIN_CAPTURE, LOG_LEVEL_DEBUG, "Defined value for range_start of %s exceeds valid integer range", _argument->call);
                    val = G_MAXINT;
                }
                else
                    val = (gint)tmp;
            }

            textValidator->setBottom(val);
        }
        if (_argument->arg_type == EXTCAP_ARG_UNSIGNED && textValidator->bottom() < 0)
        {
            ws_log(LOG_DOMAIN_CAPTURE, LOG_LEVEL_DEBUG, "%s sets negative bottom range for unsigned value, setting to 0", _argument->call);
            textValidator->setBottom(0);
        }

        if (_argument->range_end != NULL)
        {
            int val = 0;
            if (_argument->arg_type == EXTCAP_ARG_INTEGER)
                val = extcap_complex_get_int(_argument->range_end);
            else if (_argument->arg_type == EXTCAP_ARG_UNSIGNED)
            {
                guint tmp = extcap_complex_get_uint(_argument->range_end);
                if (tmp > G_MAXINT)
                {
                    ws_log(LOG_DOMAIN_CAPTURE, LOG_LEVEL_DEBUG, "Defined value for range_end of %s exceeds valid integer range", _argument->call);
                    val = G_MAXINT;
                }
                else
                    val = (gint)tmp;
            }

            textValidator->setTop(val);
        }
        textBox->setValidator(textValidator);
    }
    else if (_argument->arg_type == EXTCAP_ARG_DOUBLE)
    {
        QDoubleValidator * textValidator = new QDoubleValidator(parent);
        if (_argument->range_start != NULL)
            textValidator->setBottom(extcap_complex_get_double(_argument->range_start));
        if (_argument->range_end != NULL)
            textValidator->setTop(extcap_complex_get_double(_argument->range_end));

        textBox->setValidator(textValidator);
    }

    textBox->setText(text.trimmed());

    connect(textBox, SIGNAL(textChanged(QString)), SLOT(onStringChanged(QString)));

    return textBox;
}

QString ExtArgNumber::defaultValue()
{
    QString result;

    if (_argument != 0)
    {
        if (_argument->arg_type == EXTCAP_ARG_DOUBLE)
            result = QString::number(extcap_complex_get_double(_argument->default_complex));
        else if (_argument->arg_type == EXTCAP_ARG_INTEGER)
            result = QString::number(extcap_complex_get_int(_argument->default_complex));
        else if (_argument->arg_type == EXTCAP_ARG_UNSIGNED)
            result = QString::number(extcap_complex_get_uint(_argument->default_complex));
        else if (_argument->arg_type == EXTCAP_ARG_LONG)
            result = QString::number(extcap_complex_get_long(_argument->default_complex));
        else
        {
            QString defValue = ExtcapArgument::defaultValue();
            result = defValue.length() > 0 ? defValue : QString();
        }
    }

    return result;
}

ExtcapValue::~ExtcapValue() {}

void ExtcapValue::setChildren(ExtcapValueList children)
{
    ExtcapValueList::iterator iter = children.begin();
    while (iter != children.end())
    {
        (*iter)._depth = _depth + 1;
        ++iter;
    }

    _children.append(children);
}

ExtcapArgument::ExtcapArgument(QObject *parent) :
        QObject(parent), _argument(0), _label(0), _number(0),
        label_style(QString("QLabel { color: %1; }"))
{
}

ExtcapArgument::ExtcapArgument(extcap_arg * argument, QObject *parent) :
        QObject(parent), _argument(argument), _label(0),
        label_style(QString("QLabel { color: %1; }"))
{
    _number = argument->arg_num;

    if (_argument->values != 0)
    {
        ExtcapValueList elements = loadValues(QString(""));
        if (elements.length() > 0)
            values.append(elements);
    }
}

ExtcapArgument::ExtcapArgument(const ExtcapArgument &obj) :
        QObject(obj.parent()), _argument(obj._argument), _label(0),
        label_style(QString("QLabel { color: %1; }"))
{
    _number = obj._argument->arg_num;

    if (_argument->values != 0)
    {
        ExtcapValueList elements = loadValues(QString(""));
        if (elements.length() > 0)
            values.append(elements);
    }
}

ExtcapValueList ExtcapArgument::loadValues(QString parent)
{
    if (_argument == 0 || _argument->values == 0)
        return ExtcapValueList();

    GList * walker = 0;
    extcap_value * v;
    ExtcapValueList elements;

    for (walker = g_list_first((GList *)(_argument->values)); walker != NULL ; walker = walker->next)
    {
        v = (extcap_value *) walker->data;
        if (v == NULL || v->display == NULL || v->call == NULL)
            break;

        QString valParent = QString().fromUtf8(v->parent);

        if (parent.compare(valParent) == 0)
        {

            QString display = QString().fromUtf8(v->display);
            QString call = QString().fromUtf8(v->call);

            ExtcapValue element = ExtcapValue(display, call,
                            v->enabled == (gboolean)TRUE, v->is_default == (gboolean)TRUE);

            if (!call.isEmpty())
                element.setChildren(this->loadValues(call));

            elements.append(element);
        }
    }

    return elements;
}

bool ExtcapArgument::reloadValues()
{
    if (! qobject_cast<ExtcapOptionsDialog*> (parent()) )
        return false;

    ExtcapOptionsDialog * dialog = qobject_cast<ExtcapOptionsDialog*>(parent());
    ExtcapValueList list = dialog->loadValuesFor(_argument->arg_num, _argument->call);

    if (list.size() > 0)
    {
        values.clear();
        values << list;

        return true;
    }

    return false;
}

ExtcapArgument::~ExtcapArgument() {
}

QWidget * ExtcapArgument::createLabel(QWidget * parent)
{
    if (_argument == 0 || _argument->display == 0)
        return 0;

    QString lblInvalidColor = ColorUtils::fromColorT(prefs.gui_text_invalid).name();

    QString text = QString().fromUtf8(_argument->display);

    if (_label == 0)
        _label = new QLabel(text, parent);
    else
        _label->setText(text);

    _label->setProperty("isRequired", QString(isRequired() ? "true" : "false"));

    _label->setStyleSheet (label_style.arg(QString("")));

    if (_argument->tooltip != 0)
        _label->setToolTip(QString().fromUtf8(_argument->tooltip));

    return (QWidget *)_label;
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

QString ExtcapArgument::prefValue()
{
    return value();
}

void ExtcapArgument::resetValue()
{
    if (_argument->pref_valptr) {
        g_free(*_argument->pref_valptr);
        *_argument->pref_valptr = g_strdup("");
    }
}

bool ExtcapArgument::isValid()
{
    /* Unrequired arguments are always valid, except if validity checks fail,
     * which must be checked in an derived class, not here */
    if (! isRequired())
        return true;

    return value().length() > 0;
}

QString ExtcapArgument::defaultValue()
{
    if (_argument != 0 && _argument->default_complex != 0)
    {
        gchar * str = extcap_get_complex_as_string(_argument->default_complex);
        if (str != 0)
            return QString(str);
    }
    return QString();
}

QString ExtcapArgument::group() const
{
    if (_argument != 0 && _argument->group != 0)
        return QString(_argument->group);

    return QString();
}

int ExtcapArgument::argNr() const
{
    return _number;
}

QString ExtcapArgument::prefKey(const QString & device_name)
{
    struct preference * pref = NULL;

    if (_argument == 0 || ! _argument->save)
        return QString();

    pref = extcap_pref_for_argument(device_name.toStdString().c_str(), _argument);
    if (pref != NULL)
        return QString(prefs_get_name(pref));

    return QString();
}

bool ExtcapArgument::isRequired()
{
    if (_argument != NULL)
        return _argument->is_required;

    return FALSE;
}

bool ExtcapArgument::reload()
{
    if (_argument != NULL)
        return _argument->reload;

    return false;
}

bool ExtcapArgument::fileExists()
{
    if (_argument != NULL)
        return _argument->fileexists;

    return FALSE;
}

bool ExtcapArgument::isDefault()
{
    if (value().compare(defaultValue()) == 0)
        return true;

    return false;
}

ExtcapArgument * ExtcapArgument::create(extcap_arg * argument, QObject *parent)
{
    if (argument == 0 || argument->display == 0)
        return 0;

    ExtcapArgument * result = 0;

    if (argument->arg_type == EXTCAP_ARG_STRING || argument->arg_type == EXTCAP_ARG_PASSWORD)
        result = new ExtArgText(argument, parent);
    else if (argument->arg_type == EXTCAP_ARG_INTEGER || argument->arg_type == EXTCAP_ARG_LONG ||
            argument->arg_type == EXTCAP_ARG_UNSIGNED || argument->arg_type == EXTCAP_ARG_DOUBLE)
        result = new ExtArgNumber(argument, parent);
    else if (argument->arg_type == EXTCAP_ARG_BOOLEAN || argument->arg_type == EXTCAP_ARG_BOOLFLAG)
        result = new ExtArgBool(argument, parent);
    else if (argument->arg_type == EXTCAP_ARG_SELECTOR)
        result = new ExtArgSelector(argument, parent);
    else if (argument->arg_type == EXTCAP_ARG_RADIO)
        result = new ExtArgRadio(argument, parent);
    else if (argument->arg_type == EXTCAP_ARG_FILESELECT)
        result = new ExtcapArgumentFileSelection(argument, parent);
    else if (argument->arg_type == EXTCAP_ARG_MULTICHECK)
        result = new ExtArgMultiSelect(argument, parent);
    else if (argument->arg_type == EXTCAP_ARG_TIMESTAMP)
        result = new ExtArgTimestamp(argument, parent);
    else
    {
        /* For everything else, we just print the label */
        result = new ExtcapArgument(argument, parent);
    }

    return result;
}

/* The following is a necessity, because Q_Object does not do well with multiple inheritances */
void ExtcapArgument::onStringChanged(QString)
{
    emit valueChanged();
}

void ExtcapArgument::onIntChanged(int)
{
    if (isValid())
        emit valueChanged();
}

void ExtcapArgument::onBoolChanged(bool)
{
    emit valueChanged();
}

bool ExtcapArgument::isSetDefaultValueSupported()
{
    return FALSE;
}

void ExtcapArgument::setDefaultValue()
{
}

