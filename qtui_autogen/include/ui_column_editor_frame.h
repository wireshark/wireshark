/********************************************************************************
** Form generated from reading UI file 'column_editor_frame.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_COLUMN_EDITOR_FRAME_H
#define UI_COLUMN_EDITOR_FRAME_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QSpacerItem>
#include "accordion_frame.h"
#include "widgets/field_filter_edit.h"
#include "widgets/syntax_line_edit.h"

QT_BEGIN_NAMESPACE

class Ui_ColumnEditorFrame
{
public:
    QHBoxLayout *horizontalLayout;
    QLabel *label;
    QLineEdit *titleLineEdit;
    QSpacerItem *horizontalSpacer_2;
    QLabel *label_2;
    QComboBox *typeComboBox;
    QSpacerItem *horizontalSpacer_3;
    QLabel *label_3;
    FieldFilterEdit *fieldsNameLineEdit;
    QSpacerItem *horizontalSpacer_4;
    QLabel *label_4;
    SyntaxLineEdit *occurrenceLineEdit;
    QSpacerItem *horizontalSpacer;
    QDialogButtonBox *buttonBox;

    void setupUi(AccordionFrame *ColumnEditorFrame)
    {
        if (ColumnEditorFrame->objectName().isEmpty())
            ColumnEditorFrame->setObjectName(QString::fromUtf8("ColumnEditorFrame"));
        ColumnEditorFrame->resize(1018, 34);
        ColumnEditorFrame->setFrameShape(QFrame::NoFrame);
        ColumnEditorFrame->setFrameShadow(QFrame::Plain);
        horizontalLayout = new QHBoxLayout(ColumnEditorFrame);
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        horizontalLayout->setContentsMargins(-1, 0, -1, 0);
        label = new QLabel(ColumnEditorFrame);
        label->setObjectName(QString::fromUtf8("label"));

        horizontalLayout->addWidget(label);

        titleLineEdit = new QLineEdit(ColumnEditorFrame);
        titleLineEdit->setObjectName(QString::fromUtf8("titleLineEdit"));

        horizontalLayout->addWidget(titleLineEdit);

        horizontalSpacer_2 = new QSpacerItem(20, 5, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_2);

        label_2 = new QLabel(ColumnEditorFrame);
        label_2->setObjectName(QString::fromUtf8("label_2"));

        horizontalLayout->addWidget(label_2);

        typeComboBox = new QComboBox(ColumnEditorFrame);
        typeComboBox->setObjectName(QString::fromUtf8("typeComboBox"));

        horizontalLayout->addWidget(typeComboBox);

        horizontalSpacer_3 = new QSpacerItem(20, 5, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_3);

        label_3 = new QLabel(ColumnEditorFrame);
        label_3->setObjectName(QString::fromUtf8("label_3"));

        horizontalLayout->addWidget(label_3);

        fieldsNameLineEdit = new FieldFilterEdit(ColumnEditorFrame);
        fieldsNameLineEdit->setObjectName(QString::fromUtf8("fieldsNameLineEdit"));

        horizontalLayout->addWidget(fieldsNameLineEdit);

        horizontalSpacer_4 = new QSpacerItem(20, 5, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_4);

        label_4 = new QLabel(ColumnEditorFrame);
        label_4->setObjectName(QString::fromUtf8("label_4"));

        horizontalLayout->addWidget(label_4);

        occurrenceLineEdit = new SyntaxLineEdit(ColumnEditorFrame);
        occurrenceLineEdit->setObjectName(QString::fromUtf8("occurrenceLineEdit"));

        horizontalLayout->addWidget(occurrenceLineEdit);

        horizontalSpacer = new QSpacerItem(20, 5, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);

        buttonBox = new QDialogButtonBox(ColumnEditorFrame);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setMaximumSize(QSize(16777215, 27));
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Ok);

        horizontalLayout->addWidget(buttonBox);

        horizontalLayout->setStretch(1, 1);
        horizontalLayout->setStretch(7, 2);

        retranslateUi(ColumnEditorFrame);

        QMetaObject::connectSlotsByName(ColumnEditorFrame);
    } // setupUi

    void retranslateUi(AccordionFrame *ColumnEditorFrame)
    {
        ColumnEditorFrame->setWindowTitle(QApplication::translate("ColumnEditorFrame", "Frame", nullptr));
        label->setText(QApplication::translate("ColumnEditorFrame", "Title:", nullptr));
        label_2->setText(QApplication::translate("ColumnEditorFrame", "Type:", nullptr));
        label_3->setText(QApplication::translate("ColumnEditorFrame", "Fields:", nullptr));
        label_4->setText(QApplication::translate("ColumnEditorFrame", "Occurrence:", nullptr));
    } // retranslateUi

};

namespace Ui {
    class ColumnEditorFrame: public Ui_ColumnEditorFrame {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_COLUMN_EDITOR_FRAME_H
