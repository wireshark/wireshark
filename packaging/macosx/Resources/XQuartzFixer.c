#include <unistd.h>

/*
 * Very simple program, which is run with root privileges.
 * All it does is attempt to symlink /usr/X11 to /opt/X11, in order
 * to fix an XQuartz installation that's been damaged by an OS X
 * installer on an OS upgrade (the Yosemite installer does that).
 */
static const char opt_x11[] = "/opt/X11";
static const char usr_x11[] = "/usr/X11";

int
main(void)
{
	(void) symlink(opt_x11, usr_x11);
	return 0;
}
