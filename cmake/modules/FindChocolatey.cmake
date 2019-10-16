# FindChocolatey
# ----------
#
# This module looks for Chocolatey

if(WIN32)
    if(ENV{ChocolateyInstall})
        set(_chocolateyinstall_bin "$ENV{ChocolateyInstall}/bin")
    endif()

    find_path(CHOCOLATEY_BIN_PATH
        choco.exe
        PATHS
            ${_chocolateyinstall_bin}
            "$ENV{ProgramData}/chocolatey/bin"
            C:/Chocolatey/bin
        DOC "Chocolatey binary path"
        NO_DEFAULT_PATH
    )

    mark_as_advanced(CHOCOLATEY_BIN_PATH)
endif()
