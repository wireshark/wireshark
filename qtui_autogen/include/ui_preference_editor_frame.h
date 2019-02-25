/********************************************************************************
** Form generated from reading UI file 'preference_editor_frame.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_PREFERENCE_EDITOR_FRAME_H
#define UI_PREFERENCE_EDITOR_FRAME_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QToolButton>
#include "accordion_frame.h"
#include "widgets/syntax_line_edit.h"

QT_BEGIN_NAMESPACE

class Ui_PreferenceEditorFrame
{
public:
    QHBoxLayout *horizontalLayout;
    QToolButton *modulePreferencesToolButton;
    QSpacerItem *horizontalSpacer_2;
    QLabel *preferenceTitleLabel;
    SyntaxLineEdit *preferenceLineEdit;
    QSpacerItem *horizontalSpacer;
    QDialogButtonBox *buttonBox;

    void setupUi(AccordionFrame *PreferenceEditorFrame)
    {
        if (PreferenceEditorFrame->objectName().isEmpty())
            PreferenceEditorFrame->setObjectName(QString::fromUtf8("PreferenceEditorFrame"));
        PreferenceEditorFrame->resize(458, 34);
        PreferenceEditorFrame->setFrameShape(QFrame::NoFrame);
        PreferenceEditorFrame->setFrameShadow(QFrame::Plain);
        horizontalLayout = new QHBoxLayout(PreferenceEditorFrame);
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        horizontalLayout->setContentsMargins(-1, 0, -1, 0);
        modulePreferencesToolButton = new QToolButton(PreferenceEditorFrame);
        modulePreferencesToolButton->setObjectName(QString::fromUtf8("modulePreferencesToolButton"));

        horizontalLayout->addWidget(modulePreferencesToolButton);

        horizontalSpacer_2 = new QSpacerItem(81, 5, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_2);

        preferenceTitleLabel = new QLabel(PreferenceEditorFrame);
        preferenceTitleLabel->setObjectName(QString::fromUtf8("preferenceTitleLabel"));

        horizontalLayout->addWidget(preferenceTitleLabel);

        preferenceLineEdit = new SyntaxLineEdit(PreferenceEditorFrame);
        preferenceLineEdit->setObjectName(QString::fromUtf8("preferenceLineEdit"));
        QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        sizePolicy.setHorizontalStretch(1);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(preferenceLineEdit->sizePolicy().hasHeightForWidth());
        preferenceLineEdit->setSizePolicy(sizePolicy);

        horizontalLayout->addWidget(preferenceLineEdit);

        horizontalSpacer = new QSpacerItem(20, 13, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);

        buttonBox = new QDialogButtonBox(PreferenceEditorFrame);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setMaximumSize(QSize(16777215, 27));
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Ok);

        horizontalLayout->addWidget(buttonBox);

        horizontalLayout->setStretch(1, 1);

        retranslateUi(PreferenceEditorFrame);

        QMetaObject::connectSlotsByName(PreferenceEditorFrame);
    } // setupUi

    void retranslateUi(AccordionFrame *PreferenceEditorFrame)
    {
        PreferenceEditorFrame->setWindowTitle(QApplication::translate("PreferenceEditorFrame", "Frame", nullptr));
        modulePreferencesToolButton->setText(QApplication::translate("PreferenceEditorFrame", "\342\200\246", nullptr));
        preferenceTitleLabel->setText(QApplication::translate("PreferenceEditorFrame", "a preference", nullptr));
    } // retranslateUi

};

namespace Ui {
    class PreferenceEditorFrame: public Ui_PreferenceEditorFrame {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_PREFERENCE_EDITOR_FRAME_H
