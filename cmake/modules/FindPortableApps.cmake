#
# - Find PortableApps
# Find the PortableApps LauncherGenerator and Installer commands
#
#  PORTABLEAPPS_LAUNCHER_GENERATOR_EXECUTABLE - path to the PortableApps.comLauncherGenerator utility.
#  PORTABLEAPPS_INSTALLER_EXECUTABLE - path to the PortableApps.comInstaller utility.

# Find PortableApps.comLauncherGenerator
find_program(PORTABLEAPPS_LAUNCHER_GENERATOR_EXECUTABLE PortableApps.comLauncherGenerator
	PATH
		"C:/PortableApps/PortableApps.comLauncher"
		"$ENV{USERPROFILE}/PortableApps/PortableApps.comLauncher"
	DOC "Path to the PortableApps.comLauncherGenerator utility."
)

# Find PortableApps.comInstaller
find_program(PORTABLEAPPS_INSTALLER_EXECUTABLE PortableApps.comInstaller
	PATH
		"C:/PortableApps/PortableApps.comInstaller"
		"$ENV{USERPROFILE}/PortableApps/PortableApps.comInstaller"
	DOC "Path to the PortableApps.comInstaller utility."
)

# Assume that FindNSIS has taken care of this for us.
# set(CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS_SKIP TRUE)
# include(InstallRequiredSystemLibraries)
