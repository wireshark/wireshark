#
# - Find Asciidoctor
# Sets:
#  ASCIIDOCTOR_EXECUTABLE
#

INCLUDE(FindChocolatey)

FIND_PROGRAM(ASCIIDOCTOR_EXECUTABLE
    NAMES
        asciidoctorj
        asciidoctor.bat
        asciidoctor
        asciidoctor.ruby2.1
        # XXX Add Asciidoctor.js releases (asciidoctor-linux,
        # asciidoctor-macos, asciidoctor-win) if that ever becomes an option.
    PATHS
        /bin
        /usr/bin
        /usr/local/bin
        ${CHOCOLATEY_BIN_PATH}
    DOC "Path to Asciidoctor or AsciidoctorJ"
)

if(ASCIIDOCTOR_EXECUTABLE)
    # As of 2.2.0 the AsciidctorJ wrapper script sets -Xmn128m -Xms256m -Xmx256m.
    # This isn't enough for the User's Guide.
    set(_asciidoctorj_opts "-Xmn256m -Xms512m -Xmx2048m $ENV{ASCIIDOCTORJ_OPTS}")
    execute_process( COMMAND ${ASCIIDOCTOR_EXECUTABLE} --version OUTPUT_VARIABLE _ad_full_version )
    separate_arguments(_ad_full_version)
    list(GET _ad_full_version 1 ASCIIDOCTOR_VERSION)

    function(set_asciidoctor_target_properties _target)
        set_target_properties(${_target} PROPERTIES
            FOLDER "Documentation"
            EXCLUDE_FROM_DEFAULT_BUILD True
        )
    endfunction(set_asciidoctor_target_properties)

    set (_asciidoctor_common_args
        # Doesn't work with AsciidoctorJ?
        # --failure-level=WARN
        # --trace
        --quiet
        --attribute build_dir=${CMAKE_CURRENT_BINARY_DIR}
        --require ${CMAKE_SOURCE_DIR}/docbook/asciidoctor-macros/ws_utils.rb
        --require ${CMAKE_SOURCE_DIR}/docbook/asciidoctor-macros/commaize-block.rb
        --require ${CMAKE_SOURCE_DIR}/docbook/asciidoctor-macros/cveidlink-inline-macro.rb
        --require ${CMAKE_SOURCE_DIR}/docbook/asciidoctor-macros/manarg-block.rb
        --require ${CMAKE_SOURCE_DIR}/docbook/asciidoctor-macros/wsbuglink-inline-macro.rb
        --require ${CMAKE_SOURCE_DIR}/docbook/asciidoctor-macros/wssalink-inline-macro.rb
    )

    set(_asciidoctor_common_command
        ${CMAKE_COMMAND} -E env TZ=UTC
        ${ASCIIDOCTOR_EXECUTABLE}
        ${_asciidoctor_common_args}
    )

    set(_asciidoctor_docbook_common_command
        ${CMAKE_COMMAND} -E env TZ=UTC ASCIIDOCTORJ_OPTS=${_asciidoctorj_opts}
        ${ASCIIDOCTOR_EXECUTABLE}
        ${_asciidoctor_common_args}
    )

    MACRO( ASCIIDOCTOR2DOCBOOK _asciidocsource )
        GET_FILENAME_COMPONENT( _source_base_name ${_asciidocsource} NAME_WE )
        set( _output_xml ${_source_base_name}.xml )

        add_custom_command(
            OUTPUT
                ${_output_xml}
            COMMAND ${_asciidoctor_docbook_common_command}
                --backend docbook
                --out-file ${_output_xml}
                ${CMAKE_CURRENT_SOURCE_DIR}/${_asciidocsource}
            DEPENDS
                ${CMAKE_SOURCE_DIR}/docbook/attributes.adoc
                ${CMAKE_CURRENT_SOURCE_DIR}/${_asciidocsource}
                ${ARGN}
        )
        if(CMAKE_GENERATOR MATCHES "Visual Studio")
            add_custom_command(
                OUTPUT
                    ${_output_xml}-stamp
                COMMAND ${CMAKE_COMMAND} -E touch ${_output_xml}-stamp
                DEPENDS ${_output_xml}
            )
            add_custom_target(generate_${_output_xml} DEPENDS ${_output_xml}-stamp)
        else()
            add_custom_target(generate_${_output_xml} DEPENDS ${_output_xml})
        endif()
        set_asciidoctor_target_properties(generate_${_output_xml})
        unset(_output_xml)
    ENDMACRO()

    # Single page only, for the release notes and man pages.
    MACRO( ASCIIDOCTOR2HTML _asciidocsource )
        GET_FILENAME_COMPONENT( _source_base_name ${_asciidocsource} NAME_WE )
        set( _output_html ${_source_base_name}.html )

        ADD_CUSTOM_COMMAND(
            OUTPUT
                ${_output_html}
            COMMAND ${_asciidoctor_common_command}
                --backend html
                --out-file ${_output_html}
                ${CMAKE_CURRENT_SOURCE_DIR}/${_asciidocsource}
            DEPENDS
                ${CMAKE_SOURCE_DIR}/docbook/attributes.adoc
                ${CMAKE_CURRENT_SOURCE_DIR}/${_asciidocsource}
                ${ARGN}
        )
        add_custom_target(generate_${_output_html} DEPENDS ${_output_html})
        set_asciidoctor_target_properties(generate_${_output_html})
        unset(_output_html)
    ENDMACRO()

    MACRO( ASCIIDOCTOR2TXT _asciidocsource )
        GET_FILENAME_COMPONENT( _source_base_name ${_asciidocsource} NAME_WE )
        set( _output_html ${_source_base_name}.html )
        set( _output_txt ${_source_base_name}.txt )

        ADD_CUSTOM_COMMAND(
            OUTPUT
                ${_output_txt}
            COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tools/html2text.py
                ${_output_html}
                > ${_output_txt}
            DEPENDS
                ${MAN_INCLUDES}
                ${CMAKE_SOURCE_DIR}/docbook/attributes.adoc
                ${CMAKE_CURRENT_SOURCE_DIR}/${_asciidocsource}
                ${_output_html}
                ${ARGN}
        )
        unset(_output_html)
        unset(_output_txt)
    ENDMACRO()

    # Generate one or more ROFF man pages
    MACRO(ASCIIDOCTOR2ROFFMAN _man_section)
        set(_input_adoc)
        set(_output_man)
        foreach(_src_file ${ARGN})
            list(APPEND _input_adoc ${_src_file})
            GET_FILENAME_COMPONENT(_source_base_name ${_src_file} NAME_WE )
            list(APPEND _output_man ${_source_base_name}.${_man_section} )
        endforeach()

        ADD_CUSTOM_COMMAND(
            OUTPUT
                ${_output_man}
            COMMAND ${_asciidoctor_common_command}
                --backend manpage
                --destination-dir ${CMAKE_CURRENT_BINARY_DIR}
                ${_input_adoc}
            DEPENDS
                ${MAN_INCLUDES}
                ${CMAKE_SOURCE_DIR}/docbook/attributes.adoc
                ${_input_adoc}
        )
        unset(_src_file)
        unset(_input_adoc)
        unset(_output_man)
    ENDMACRO()

    # Generate one or more HTML man pages
    MACRO(ASCIIDOCTOR2HTMLMAN)
        set(_input_adoc)
        set(_output_man)
        foreach(_src_file ${ARGN})
            list(APPEND _input_adoc ${_src_file})
            GET_FILENAME_COMPONENT(_source_base_name ${_src_file} NAME_WE )
            list(APPEND _output_man ${_source_base_name}.html )
        endforeach()

        ADD_CUSTOM_COMMAND(
            OUTPUT
                ${_output_man}
            COMMAND ${_asciidoctor_common_command}
                --backend html
                --destination-dir ${CMAKE_CURRENT_BINARY_DIR}
                ${_input_adoc}
            DEPENDS
                ${MAN_INCLUDES}
                ${CMAKE_SOURCE_DIR}/docbook/attributes.adoc
                ${_input_adoc}
        )
        unset(_src_file)
        unset(_input_adoc)
        unset(_output_man)
    ENDMACRO()

    # news: release-notes.txt
    #         ${CMAKE_COMMAND} -E copy_if_different release-notes.txt ../NEWS

    FIND_PROGRAM(ASCIIDOCTOR_PDF_EXECUTABLE
        NAMES
            asciidoctorj
            asciidoctor-pdf
        PATHS
            /bin
            /usr/bin
            /usr/local/bin
            ${CHOCOLATEY_BIN_PATH}
        DOC "Path to Asciidoctor PDF or AsciidoctorJ"
    )

    if(ASCIIDOCTOR_PDF_EXECUTABLE)

        set(_asciidoctor_pdf_common_command
            ${CMAKE_COMMAND} -E env TZ=UTC "ASCIIDOCTORJ_OPTS=${_asciidoctorj_opts}"
            ${ASCIIDOCTOR_PDF_EXECUTABLE}
            --require asciidoctor-pdf
            --backend pdf
            ${_asciidoctor_common_args}
        )

        MACRO( ASCIIDOCTOR2PDF _title _asciidocsource )
            GET_FILENAME_COMPONENT( _source_base_name ${_asciidocsource} NAME_WE )
            set(_generate_pdf "generate_${_source_base_name}_pdf")
            set(_output_pdf "${_title}.pdf")

            ADD_CUSTOM_COMMAND(
            OUTPUT
                    ${_output_pdf}
            COMMAND ${_asciidoctor_pdf_common_command}
                    --out-file "${_output_pdf}"
                    ${CMAKE_CURRENT_SOURCE_DIR}/${_asciidocsource}
            DEPENDS
                    ${CMAKE_SOURCE_DIR}/docbook/attributes.adoc
                    ${CMAKE_CURRENT_SOURCE_DIR}/${_asciidocsource}
                    ${ARGN}
            VERBATIM
            )
            add_custom_target(${_generate_pdf} DEPENDS ${_output_pdf})
            set_asciidoctor_target_properties(${_generate_pdf})
            unset(_generate_pdf)
            unset(_output_pdf)
        ENDMACRO()

    else(ASCIIDOCTOR_PDF_EXECUTABLE)

        MACRO( ASCIIDOCTOR2PDF _asciidocsource )
        ENDMACRO()

    endif(ASCIIDOCTOR_PDF_EXECUTABLE)

    FIND_PROGRAM(ASCIIDOCTOR_EPUB_EXECUTABLE
        NAMES
            asciidoctorj
            asciidoctor-epub3
        PATHS
            /bin
            /usr/bin
            /usr/local/bin
            ${CHOCOLATEY_BIN_PATH}
        DOC "Path to Asciidoctor EPUB3 or AsciidoctorJ"
    )

    if(ASCIIDOCTOR_EPUB_EXECUTABLE)

        set(_asciidoctor_epub_common_command
            ${CMAKE_COMMAND} -E env TZ=UTC "ASCIIDOCTORJ_OPTS=${_asciidoctorj_opts}"
            ${ASCIIDOCTOR_EPUB_EXECUTABLE}
            --backend epub3
            ${_asciidoctor_common_args}
        )

        MACRO(ASCIIDOCTOR2EPUB _title _asciidocsource)
            GET_FILENAME_COMPONENT(_source_base_name ${_asciidocsource} NAME_WE)
            set(_generate_epub "generate_${_source_base_name}_epub")
            set(_output_epub "${_title}.epub")

            ADD_CUSTOM_COMMAND(
            OUTPUT
                    ${_output_epub}
            COMMAND ${_asciidoctor_epub_common_command}
                    --out-file "${_output_epub}"
                    ${CMAKE_CURRENT_SOURCE_DIR}/${_asciidocsource}
            DEPENDS
                    ${CMAKE_SOURCE_DIR}/docbook/attributes.adoc
                    ${CMAKE_CURRENT_SOURCE_DIR}/${_asciidocsource}
                    ${ARGN}
            VERBATIM
            )
            add_custom_target(${_generate_epub} DEPENDS ${_output_epub})
            set_asciidoctor_target_properties(${_generate_epub})
            unset(_generate_epub)
            unset(_output_epub)
        ENDMACRO()

    else(ASCIIDOCTOR_EPUB_EXECUTABLE)

        MACRO(ASCIIDOCTOR2EPUB _asciidocsource)
        ENDMACRO()

    endif(ASCIIDOCTOR_EPUB_EXECUTABLE)

endif(ASCIIDOCTOR_EXECUTABLE)

include( FindPackageHandleStandardArgs )
find_package_handle_standard_args( Asciidoctor
    REQUIRED_VARS ASCIIDOCTOR_EXECUTABLE
    VERSION_VAR ASCIIDOCTOR_VERSION
    )

mark_as_advanced( ASCIIDOCTOR_EXECUTABLE )
