/* Created by rdps.c. Do not edit! */

#include <stdio.h>

#include <ps.h>

/* Created by rdps.c. Do not edit! */
void print_ps_preamble(FILE *fd) {
	fprintf(fd, "%%!\n");
	fprintf(fd, "%%!PS-Adobe-2.0\n");
	fprintf(fd, "%%\n");
	fprintf(fd, "%% Ethereal - Network traffic analyzer\n");
	fprintf(fd, "%% By Gerald Combs <gerald@zing.org>\n");
	fprintf(fd, "%% Copyright 1998 Gerald Combs\n");
	fprintf(fd, "%%\n");
	fprintf(fd, "%%%%Creator: Ethereal\n");
	fprintf(fd, "%%%%Title: ethereal.ps\n");
	fprintf(fd, "%%%%DocumentFonts: Helvetica Courier\n");
	fprintf(fd, "%%%%EndComments\n");
	fprintf(fd, "%%!\n");
	fprintf(fd, "\n");
	fprintf(fd, "%% Get the Imagable Area of the page\n");
	fprintf(fd, "clippath pathbbox\n");
	fprintf(fd, "\n");
	fprintf(fd, "%% Set vmax to the vertical size of the page,\n");
	fprintf(fd, "%% hmax to the horizontal size of the page.\n");
	fprintf(fd, "/vmax exch def\n");
	fprintf(fd, "/hmax exch def\n");
	fprintf(fd, "pop pop		%% junk\n");
	fprintf(fd, "\n");
	fprintf(fd, "%% 1-inch margins\n");
	fprintf(fd, "/lmargin 72 def\n");
	fprintf(fd, "/tmargin vmax 72 sub def\n");
	fprintf(fd, "/bmargin 72 def\n");
	fprintf(fd, "\n");
	fprintf(fd, "%% Counters\n");
	fprintf(fd, "/vpos vmax 70 sub def\n");
	fprintf(fd, "\n");
	fprintf(fd, "/putline {\n");
	fprintf(fd, "	exch 10 mul lmargin add		%% X\n");
	fprintf(fd, "	vpos 						%% Y\n");
	fprintf(fd, "	moveto\n");
	fprintf(fd, "	show\n");
	fprintf(fd, "\n");
	fprintf(fd, "	/vpos vpos 10 sub def\n");
	fprintf(fd, "\n");
	fprintf(fd, "	vpos bmargin le 			%% is vpos <= bottom margin?\n");
	fprintf(fd, "	{showpage\n");
	fprintf(fd, "		/vpos tmargin def}\n");
	fprintf(fd, "	if							%% then formfeed and start at top\n");
	fprintf(fd, "} def\n");
	fprintf(fd, "\n");
	fprintf(fd, "/hexdump {\n");
	fprintf(fd, "	lmargin						%% X\n");
	fprintf(fd, "	vpos 						%% Y\n");
	fprintf(fd, "	moveto\n");
	fprintf(fd, "	show\n");
	fprintf(fd, "\n");
	fprintf(fd, "	/vpos vpos 10 sub def\n");
	fprintf(fd, "\n");
	fprintf(fd, "	vpos bmargin le 			%% is vpos <= bottom margin?\n");
	fprintf(fd, "	{showpage\n");
	fprintf(fd, "		/vpos tmargin def}\n");
	fprintf(fd, "	if							%% then formfeed and start at top\n");
	fprintf(fd, "} def\n");
	fprintf(fd, "\n");
	fprintf(fd, "%% Set the font to 10 point\n");
	fprintf(fd, "/Helvetica findfont 10 scalefont setfont\n");
	fprintf(fd, "\n");
	fprintf(fd, "%% Display our output lines.\n");
}


/* Created by rdps.c. Do not edit! */
void print_ps_hex(FILE *fd) {
	fprintf(fd, "%% Set the font to 10 point\n");
	fprintf(fd, "/Courier findfont 10 scalefont setfont\n");
	fprintf(fd, "() hexdump\n");
}


/* Created by rdps.c. Do not edit! */
void print_ps_finale(FILE *fd) {
	fprintf(fd, "showpage\n");
}


