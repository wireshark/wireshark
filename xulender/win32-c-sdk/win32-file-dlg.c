#include <windows.h>
#include <commdlg.h>
#include <stdlib.h>

#include "win32-file-dlg.h"

BOOL win32_open_file (HWND h_wnd, LPSTR file_name, int len) {
	static OPENFILENAME ofn;

	memset(&ofn, 0, sizeof(ofn));

	/* XXX - Check for version and set OPENFILENAME_SIZE_VERSION_400
           where appropriate */
	// ofn.lStructSize = sizeof(ofn);
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = h_wnd;
	ofn.hInstance = (HINSTANCE) GetWindowLong(h_wnd, GWL_HINSTANCE);
	ofn.lpstrFilter = "Ethereal capture files (*.pcap)\0" "*.pcap\0"
			"All Files (*.*)\0" "*.*\0"
			"\0";
	ofn.nFilterIndex = 2;
	ofn.lpstrCustomFilter = NULL;
	ofn.nMaxCustFilter = 0;
	ofn.lpstrFile = file_name;
	ofn.nMaxFile = len;
	ofn.lpstrFileTitle = NULL;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = NULL;
	ofn.lpstrTitle = "Select a capture file";
	ofn.Flags = OFN_ENABLESIZING | OFN_ENABLETEMPLATE | OFN_EXPLORER |
		OFN_FILEMUSTEXIST;
	ofn.lpstrDefExt = "pcap";
	ofn.lpTemplateName = "ETHEREAL_OPENFILENAME_TEMPLATE";

	return (GetOpenFileName(&ofn));
}

