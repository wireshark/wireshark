# Try to find Python and set PYTHON_EXECUTABLE on Windows prior to
# calling FindPythonInterp in order to keep us from using Cygwin's Python.
# http://public.kitware.com/Bug/view.php?id=13818

if(WIN32)
    # First check the HKLM and HKCU "App Paths" keys.
    if(NOT PYTHON_EXECUTABLE)
        get_filename_component(PYTHON_EXECUTABLE
            "[HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\Python.exe]"
        )
    endif()
    if(NOT PYTHON_EXECUTABLE)
        get_filename_component(PYTHON_EXECUTABLE
            "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\Python.exe]"
        )
    endif()
    if(NOT PYTHON_EXECUTABLE)
        foreach(_major_version 3 2)
            foreach(_minor_version 7 6 5 4 3 2 1)
                find_program(PYTHON_EXECUTABLE
                    python.exe
                    PATHS [HKEY_LOCAL_MACHINE\\SOFTWARE\\Python\\PythonCore\\${_major_version}.${_minor_version}\\InstallPath]
                    NO_DEFAULT_PATH
                )
                if (PYTHON_EXECUTABLE)
                    break()
                endif()
            endforeach()
        endforeach()
    endif()
endif(WIN32)