#!/usr/bin/env python
#
# faq.py
#
# Routines to assemble a FAQ list for the Wireshark web site.
# Questions and answer content can be found below. Section and
# question numbers will be automatically generated.
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import sys
import string

class faq_section:
	def __init__(self, name, secnum):
		self.name = name
		self.secnum = secnum
		self.qa = []
		self.subsecs = []

	def add_qa(self, question, answer, tag):
		q_num = len(self.qa) + 1
		q_id = "%s.%d" % (self.get_num_string(), q_num)
		self.qa.append( (q_id, question, answer, tag) )

	def get_all_qa(self):
		return self.qa

	def add_subsec(self, subsec):
		self.subsecs.append(subsec)

	def get_all_subsecs(self):
		return self.subsecs

	def get_num_string(self):
		return "%d" % (self.secnum)

	def get_name(self):
		return self.name

	def get_num_name(self):
		return "%s. %s" % (self.get_num_string(), self.name)

	def get_header_level(self):
		return 3

	def print_index(self):
		print(("<a href=#sec%s><h%d>%s:</h%d></a>\n" % (self.get_num_string(), self.get_header_level(), self.get_num_name(), self.get_header_level())))
		for qa in self.qa:
			id = qa[0]
			question = qa[1]
			print('<p class="faq_q">')
			print(('<a class="faq_qnum" href=#q%s>%s %s</a>\n' % (id, id, question)))
			print('</p>')
		for subsec in self.subsecs:
			subsec.print_index()

	def print_contents(self):
		# Table header
		print(("""
  <h%d id="sec%s">%s</h%d>
""" % (self.get_header_level(), self.get_num_string(), self.get_num_name(), self.get_header_level())))

		# Questions and Answers
		for qa in self.qa:
			id = qa[0]
			question = qa[1]
			answer = qa[2]
			tag = qa[3]

			print('<p class="faq_q">')
			if tag is not None:
				print(('<span id=%s></span>' % (tag)))
			print(('<a href=#q%s class="faq_qnum" id=q%s>Q %s: %s</a>' % (id, id, id, question)))
			print('</p>')

			print('<p class="faq_a">')
			print('<span class="faq_anum">A:</span>\n')
			print(answer)
			print('</p>')

		# Subsections
		for subsec in self.subsecs:
			subsec.print_contents()

		# Table footer
		print("")

class faq_subsection(faq_section):
	def __init__(self, name, secnum, subsecnum):
		self.name = name
		self.secnum = secnum
		self.subsecnum = subsecnum
		self.qa = []
		self.subsecs = []

	def get_num_string(self):
		return "%d.%d" % (self.secnum, self.subsecnum)

	def get_header_level(self):
		return 2

class faq_subsubsection(faq_section):
	def __init__(self, name, secnum, subsecnum, subsubsecnum):
		self.name = name
		self.secnum = secnum
		self.subsecnum = subsecnum
		self.subsubsecnum = subsubsecnum
		self.qa = []
		self.subsecs = []

	def get_num_string(self):
		return "%d.%d.%d" % (self.secnum, self.subsecnum, self.subsubsecnum)

	def get_header_level(self):
		return 2

sec_num = 0
subsec_num = 0
subsubsec_num = 0
sections = []
current_section = None
parent_section = None
grandparent_section = None
current_question = None
current_tag = None

# Make a URL of itself
def selflink(text):
	return "<a href=\"%s\">%s</a>" % (text, text)

# Add a section
def section(name):
	global sec_num
	global subsec_num
	global subsubsec_num
	global current_section
	global grandparent_section
	assert not current_question
	sec_num = sec_num + 1
	subsec_num = 0
	subsubsec_num = 0
	sec = faq_section(name, sec_num)
	sections.append(sec)
	current_section = sec
	grandparent_section = sec

# Add a subsection
def subsection(name):
	global subsec_num
	global subsubsec_num
	global current_section
	global parent_section
	global grandparent_section
	assert not current_question
	subsec_num = subsec_num + 1
	subsubsec_num = 0
	sec = faq_subsection(name, sec_num, subsec_num)
	grandparent_section.add_subsec(sec)
	current_section = sec
	parent_section = sec

# Add a subsubsection
def subsubsection(name):
	global subsubsec_num
	global current_section
	global parent_section
	assert not current_question
	subsubsec_num = subsubsec_num + 1
	sec = faq_subsubsection(name, sec_num, subsec_num, subsubsec_num)
	parent_section.add_subsec(sec)
	current_section = sec

# Add a question
def question(text, tag=None):
	global current_question
	global current_tag
	assert current_section
	assert not current_question
	assert not current_tag
	current_question = text
	current_tag = tag

# Add an answer
def answer(text):
	global current_question
	global current_tag
	assert current_section
	assert current_question
	current_section.add_qa(current_question, text, current_tag)
	current_question = None
	current_tag = None


# Create the index
def create_index():
	print("""
  <h1 id="index">Index</h1>
""")
	for sec in sections:
		sec.print_index()

	print("""
""")


# Print result
def create_output(header='', footer=''):

	print(header)
	create_index()

	for sec in sections:
		sec.print_contents()

	print(footer)

def main():
	header = '''\
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Wireshark Frequently Asked Questions</title>
</head>
<body>
'''
	footer = '''\
</body>
</html>
'''

	if len(sys.argv) > 1 and sys.argv[1] == '-b': # Only print the document body
		header = ''
		footer = ''

	create_output(header, footer)

#################################################################
section("General Questions")
#################################################################

question("What is Wireshark?")
answer("""
Wireshark&#174; is a network protocol analyzer. It lets you capture and
interactively browse the traffic running on a computer network.  It has
a rich and powerful feature set and is world's most popular tool of its
kind. It runs on most computing platforms including Windows, OS X,
Linux, and UNIX. Network professionals, security experts, developers,
and educators around the world use it regularly. It is freely available
as open source, and is released under the GNU General Public License
version 2.

<br>

It is developed and maintained by a global team of protocol experts, and
it is an example of a
<a href="https://en.wikipedia.org/wiki/Disruptive_technology">disruptive
technology</a>.

<br>

Wireshark used to be known as Ethereal&#174;.  See the next question
for details about the name change.  If you're still using Ethereal, it
is strongly recommended that you upgrade to Wireshark as Ethereal is
unsupported and has known security vulnerabilities.

<br>

For more information, please see the
<a href="https://www.wireshark.org/about.html">About Wireshark</a>
page.
""")


question("What's up with the name change?  Is Wireshark a fork?")
answer("""
In May of 2006, Gerald Combs (the original author of Ethereal)
went to work for CACE Technologies (best known for WinPcap).
Unfortunately, he had to leave the Ethereal trademarks behind.

<br>

This left the project in an awkward position.  The only reasonable way
to ensure the continued success of the project was to change the name.
This is how Wireshark was born.

<br>

Wireshark is almost (but not quite) a fork. Normally a "fork" of an open source
project results in two names, web sites, development teams, support
infrastructures, etc. This is the case with Wireshark except for one notable
exception -- every member of the core development team is now working on
Wireshark. There has been no active development on Ethereal since the name
change. Several parts of the Ethereal web site (such as the mailing lists,
source code repository, and build farm) have gone offline.

<br>

More information on the name change can be found here:
</p>
<ul class="item_list">

  <li><a href="http://www.prweb.com/releases/2006/6/prweb396098.htm">Original press release</a>
  <li><a href="http://archive09.linux.com/articles/54968">NewsForge article</a>
  <li>Many other articles in <a href="https://www.wireshark.org/bibliography.html">our bibliography</a>
</ul>
<p>
""")


question("Where can I get help?")
answer("""
Community support is available on the
<a href="https://ask.wireshark.org/">Q&amp;A site</a> and on the
wireshark-users mailing list.  Subscription information and archives for
all of Wireshark's mailing lists can be found at %s.  An IRC channel
dedicated to Wireshark can be found at %s.

<br>

Self-paced and instructor-led training is available at <a
href="http://www.wiresharktraining.com">Wireshark University</a>.
Wireshark University also offers certification via the Wireshark
Certified Network Analyst program.

""" % (selflink("https://www.wireshark.org/mailman/listinfo"),
       selflink("irc://irc.freenode.net/wireshark")
       ))


question("What kind of shark is Wireshark?")
answer("""
<i>carcharodon photoshopia</i>.
""")


question("How is Wireshark pronounced, spelled and capitalized?")
answer("""
Wireshark is pronounced as the word <i>wire</i> followed immediately by
the word <i>shark</i>.  Exact pronunciation and emphasis may vary
depending on your locale (e.g. Arkansas).

<br>

It's spelled with a capital <i>W</i>, followed by a lower-case
<i>ireshark</i>.  It is not a CamelCase word, i.e., <i>WireShark</i>
is incorrect.
""")


question("How much does Wireshark cost?", "but_thats_not_all")
answer("""
Wireshark is "free software"; you can download it without paying any
license fee.  The version of Wireshark you download isn't a "demo"
version, with limitations not present in a "full" version; it
<em>is</em> the full version.

<br>

The license under which Wireshark is issued is <a
href="https://www.gnu.org/licenses/gpl-2.0.html">the GNU General Public
License version 2</a>.  See <a
href="https://www.gnu.org/licenses/old-licenses/gpl-2.0-faq.html">the GNU
GPL FAQ</a> for some more information.
""")

question("But I just paid someone on eBay for a copy of Wireshark! Did I get ripped off?")
answer("""
That depends. Did they provide any sort of value-added product or service, such
as installation support, installation media, training, trace file analysis, or
funky-colored shark-themed socks? Probably not.

<br>

Wireshark is <a href="https://www.wireshark.org/download.html">available for
anyone to download, absolutely free, at any time</a>. Paying for a copy implies
that you should get something for your money.
""")

question("Can I use Wireshark commercially?")
answer("""
Yes, if, for example, you mean "I work for a commercial organization;
can I use Wireshark to capture and analyze network traffic in our
company's networks or in our customer's networks?"

<br>

If you mean "Can I use Wireshark as part of my commercial product?", see
<a href="#derived_work_gpl">the next entry in the FAQ</a>.
""")


question("Can I use Wireshark as part of my commercial product?",
"derived_work_gpl")

answer("""
As noted, Wireshark is licensed under <a
href="https://www.gnu.org/licenses/gpl-2.0.html">the GNU General Public
License, version 2</a>. The GPL imposes conditions on your use of GPL'ed
code in your own products; you cannot, for example, make a "derived
work" from Wireshark, by making modifications to it, and then sell the
resulting derived work and not allow recipients to give away the
resulting work. You must also make the changes you've made to the
Wireshark source available to all recipients of your modified version;
those changes must also be licensed under the terms of the GPL. See the
<a href="https://www.gnu.org/licenses/old-licenses/gpl-2.0-faq.html">GPL
FAQ</a> for more details; in particular, note the answer to <a
href="https://www.gnu.org/licenses/old-licenses/gpl-2.0-faq.html#GPLCommercially">the
question about modifying a GPLed program and selling it
commercially</a>, and <a
href="https://www.gnu.org/licenses/old-licenses/gpl-2.0-faq.html#LinkingWithGPL">the
question about linking GPLed code with other code to make a proprietary
program</a>.

<br>

You can combine a GPLed program such as Wireshark and a commercial
program as long as they communicate "at arm's length", as per <a
href="https://www.gnu.org/licenses/old-licenses/gpl-2.0-faq.html#GPLInProprietarySystem">this
item in the GPL FAQ</a>.

<br>

We recommend keeping Wireshark and your product completely separate,
communicating over sockets or pipes. If you're loading any part of
Wireshark as a DLL, you're probably doing it wrong.
""")

question("What protocols are currently supported?")
answer("""
There are currently hundreds of supported
protocols and media.  Details can be found in the
<a
href="https://www.wireshark.org/docs/man-pages/wireshark.html">wireshark(1)</a>
man page.
""")


question("Are there any plans to support {your favorite protocol}?")
answer("""
Support for particular protocols is added to Wireshark as a result of
people contributing that support; no formal plans for adding support for
particular protocols in particular future releases exist.
""")


question("""Can Wireshark read capture files from {your favorite network
analyzer}?""")

answer("""
Support for particular capture file formats is added to Wireshark as a result
of people contributing that support; no formal plans for adding support for
particular capture file formats in particular future releases exist.

<br>

If a network analyzer writes out files in a format already supported by
Wireshark (e.g., in libpcap format), Wireshark may already be able to read
them, unless the analyzer has added its own proprietary extensions to
that format.

<br>

If a network analyzer writes out files in its own format, or has added
proprietary extensions to another format, in order to make Wireshark read
captures from that network analyzer, we would either have to have a
specification for the file format, or the extensions, sufficient to give
us enough information to read the parts of the file relevant to
Wireshark, or would need at least one capture file in that format
<strong>AND</strong> a detailed textual analysis of the packets in that
capture file (showing packet time stamps, packet lengths, and the
top-level packet header) in order to reverse-engineer the file
format.

<br>

Note that there is no guarantee that we will be able to reverse-engineer
a capture file format.
""")


question("What devices can Wireshark use to capture packets?")
answer("""
Wireshark can read live data from Ethernet, Token-Ring, FDDI, serial (PPP
and SLIP) (if the OS on which it's running allows Wireshark to do so),
802.11 wireless LAN (if the OS on which it's running allows Wireshark to
do so), ATM connections (if the OS on which it's running allows Wireshark
to do so), and the "any" device supported on Linux by recent versions of
libpcap.

<br>

See <a href="https://wiki.wireshark.org/CaptureSetup/NetworkMedia">the list of
supported capture media on various OSes</a> for details (several items
in there say "Unknown", which doesn't mean "Wireshark can't capture on
them", it means "we don't know whether it can capture on them"; we
expect that it will be able to capture on many of them, but we haven't
tried it ourselves - if you try one of those types and it works, please
update the wiki page accordingly.

<br>

It can also read a variety of capture file formats, including:

</p>
<ul>

<li> AG Group/WildPackets/Savvius EtherPeek/TokenPeek/AiroPeek/EtherHelp/Packet Grabber captures
<li> AIX's iptrace captures
<li> Accellent's 5Views LAN agent output
<li> Cinco Networks NetXRay captures
<li> Cisco Secure Intrusion Detection System IPLog output
<li> CoSine L2 debug output
<li> DBS Etherwatch VMS text output
<li> Endace Measurement Systems' ERF format captures
<li> EyeSDN USB S0 traces
<li> HP-UX nettl captures
<li> ISDN4BSD project i4btrace captures
<li> Linux Bluez Bluetooth stack hcidump -w traces
<li> Lucent/Ascend router debug output
<li> Microsoft Network Monitor captures
<li> Network Associates Windows-based Sniffer captures
<li> Network General/Network Associates DOS-based Sniffer (compressed or uncompressed) captures
<li> Network Instruments Observer version 9 captures
<li> Novell LANalyzer captures
<li> RADCOM's WAN/LAN analyzer captures
<li> Shomiti/Finisar Surveyor captures
<li> Toshiba's ISDN routers dump output
<li> VMS TCPIPtrace/TCPtrace/UCX$TRACE output
<li> Visual Networks' Visual UpTime traffic capture
<li> libpcap, tcpdump and various other tools using tcpdump's capture format
<li> snoop and atmsnoop output

</ul>

<p>
so that it can read traces from various network types, as captured by
other applications or equipment, even if it cannot itself capture on
those network types.
""")

question("""
Does Wireshark work on Windows Vista or Windows Server 2008?
""")

answer("""
Yes, but if you want to capture packets as a normal user, you must make sure
npf.sys is loaded. Wireshark's installer enables this by default. This is not a
concern if you run Wireshark as Administrator, but this is discouraged. See the
<a
href="https://wiki.wireshark.org/CaptureSetup/CapturePrivileges#windows">CapturePrivileges</a>
page on the wiki for more details.
""")


#################################################################
section("Installing Wireshark")
#################################################################


question("""I installed the Wireshark RPM (or other package); why did
it install TShark but not Wireshark?""")

answer("""
Many distributions have separate Wireshark packages, one for non-GUI
components such as TShark, editcap, dumpcap, etc. and one for the GUI.
If this is the case on your system, there's probably a separate package
named <code>wireshark-gnome</code> or <code>wireshark-gtk+</code>.  Find it and
install it.
""")


#################################################################
section("Building Wireshark")
#################################################################


question("""I have libpcap installed; why did the configure script not
find pcap.h or bpf.h?""")

answer("""
Are you sure pcap.h and bpf.h are installed?  The official distribution
of libpcap only installs the libpcap.a library file when "make install"
is run.  To install pcap.h and bpf.h, you must run "make install-incl".
If you're running Debian or Redhat, make sure you have the "libpcap-dev"
or "libpcap-devel" packages installed.

<br>

It's also possible that pcap.h and bpf.h have been installed in a strange
location.  If this is the case, you may have to tweak aclocal.m4.
""")


question("""
Why do I get the error

<em>dftest_DEPENDENCIES was already defined in condition TRUE,
which implies condition HAVE_PLUGINS_TRUE</em>

when I try to build Wireshark from SVN or a SVN snapshot?
""")

answer("""
You probably have automake 1.5 installed on your machine (the command
<kbd>automake --version</kbd> will report the version of automake on
your machine).  There is a bug in that version of automake that causes
this problem; upgrade to a later version of automake (1.6 or later).
""")

question("""
Why does the linker fail with a number of "Output line too long." messages
followed by linker errors when I try to build Wireshark?
""")

answer("""
The version of the <code>sed</code> command on your system is incapable of
handling very long lines.  On Solaris, for example,
<code>/usr/bin/sed</code> has a line length limit too low to allow
<code>libtool</code> to work; <code>/usr/xpg4/bin/sed</code> can handle it, as
can GNU <code>sed</code> if you have it installed.

<br>

On Solaris, changing your command search path to search
<code>/usr/xpg4/bin</code> before <code>/usr/bin</code> should make the problem
go away; on any platform on which you have this problem, installing GNU
<code>sed</code> and changing your command path to search the directory in
which it is installed before searching the directory with the version of
<code>sed</code> that came with the OS should make the problem go away.
""")

question("""
When I try to build Wireshark on Solaris, why does the link fail
complaining that <code>plugin_list</code> is undefined?
""")

answer("""
This appears to be due to a problem with some versions of the GTK+ and
GLib packages from www.sunfreeware.org; un-install those packages, and
try getting the 1.2.10 versions from that site, or the versions from <a
href="http://www.thewrittenword.com">The Written Word</a>, or the
versions from Sun's GNOME distribution, or the versions from the
supplemental software CD that comes with the Solaris media kit, or build
them from source from <a href="http://www.gtk.org/">the GTK Web
site</a>.  Then re-run the configuration script, and try rebuilding
Wireshark.  (If you get the 1.2.10 versions from www.sunfreeware.org, and
the problem persists, un-install them and try installing one of the
other versions mentioned.)
""")

question("""
When I try to build Wireshark on Windows, why does the build fail because
of conflicts between <code>winsock.h</code> and <code>winsock2.h</code>?
""")

answer("""
As of Wireshark 0.9.5, you must install WinPcap 2.3 or later, and the
corresponding version of the developer's pack, in order to be able to
compile Wireshark; it will not compile with older versions of the
developer's pack.  The symptoms of this failure are conflicts between
definitions in <code>winsock.h</code> and in <code>winsock2.h</code>; Wireshark
uses <code>winsock2.h</code>, but pre-2.3 versions of the WinPcap
developer's packet use <code>winsock.h</code>.  (2.3 uses
<code>winsock2.h</code>, so if Wireshark were to use <code>winsock.h</code>, it
would not be able to build with current versions of the WinPcap
developer's pack.)

<br>

Note that the installed version of the developer's pack should be the
same version as the version of WinPcap you have installed.
""")

#################################################################
section("Starting Wireshark")
#################################################################


question("""Why does Wireshark crash with a Bus Error when I try to run
it on Solaris 8?""")

answer("""
Some versions of the GTK+ library from www.sunfreeware.org appear to be
buggy, causing Wireshark to drop core with a Bus Error.  Un-install those
packages, and try getting the 1.2.10 version from that site, or the
version from <a href="http://www.thewrittenword.com">The Written
Word</a>, or the version from Sun's GNOME distribution, or the version
from the supplemental software CD that comes with the Solaris media kit,
or build it from source from <a href="http://www.gtk.org/">the GTK Web
site</a>.  Update the GLib library to the 1.2.10 version, from the same
source, as well.  (If you get the 1.2.10 versions from
www.sunfreeware.org, and the problem persists, un-install them and try
installing one of the other versions mentioned.)

<br>

Similar problems may exist with older versions of GTK+ for earlier
versions of Solaris.
""")

question("""When I try to run Wireshark, why does it complain about
<code>sprint_realloc_objid</code> being undefined?""")

answer("""
Wireshark can only be linked with version 4.2.2 or later of UCD SNMP.
Your version of Wireshark was dynamically linked with such a version of
UCD SNMP; however, you have an older version of UCD SNMP installed,
which means that when Wireshark is run, it tries to link to the older
version, and fails.  You will have to replace that version of UCD SNMP
with version 4.2.2 or a later version.
""")

question("""
I've installed Wireshark from Fink on OS X; why is it very slow to
start up?
""")

answer("""
When an application is installed on OS X, prior to 10.4, it is usually
"prebound" to speed up launching the application.  (That's what the
"Optimizing" phase of installation is.)

<br>

Fink normally performs prebinding automatically when you install a
package. However, in some rare cases, for whatever reason the prebinding
caches get corrupt, and then not only does prebinding fail, but startup
actually becomes much slower, because the system tries in vain to
perform prebinding "on the fly" as you launch the application. This
fails, causing sometimes huge delays.

<br>

To fix the prebinding caches, run the command
</p>

<pre>
	sudo /sw/var/lib/fink/prebound/update-package-prebinding.pl -f
</pre>
<p>
""")

#################################################################
section("Crashes and other fatal errors")
#################################################################


question("""
I have an XXX network card on my machine; if I try to capture on it, why
does my machine crash or reset itself?
""")

answer("""
This is almost certainly a problem with one or more of:
</p>

<ul>
<li>the operating system you're using;
<li>the device driver for the interface you're using;
<li>the libpcap/WinPcap library and, if this is Windows, the WinPcap
device driver;
</ul>

<p>
so:
</p>

<ul>
<li>if you are using Windows, see <a
href="https://www.winpcap.org/contact.htm">the WinPcap support
page</a> - check the "Submitting bugs" section;
<li>if you are using some Linux distribution, some version of BSD, or
some other UNIX-flavored OS, you should report the problem to the
company or organization that produces the OS (in the case of a Linux
distribution, report the problem to whoever produces the distribution).
</ul>
<p>
""")

question("""
Why does my machine crash or reset itself when I select "Start" from the
"Capture" menu or select "Preferences" from the "Edit" menu?
""")

answer("""
Both of those operations cause Wireshark to try to build a list of the
interfaces that it can open; it does so by getting a list of interfaces
and trying to open them.  There is probably an OS, driver, or, for
Windows, WinPcap bug that causes the system to crash when this happens;
see the previous question.
""")

#################################################################
section("Capturing packets")
#################################################################


question("""When I use Wireshark to capture packets, why do I see only
packets to and from my machine, or not see all the traffic I'm expecting
to see from or to the machine I'm trying to monitor?""", "promiscsniff")

answer("""
This might be because the interface on which you're capturing is plugged
into an Ethernet or Token Ring switch; on a switched network, unicast
traffic between two ports will not necessarily appear on other ports -
only broadcast and multicast traffic will be sent to all ports.

<br>

Note that even if your machine is plugged into a hub, the "hub" may be
a switched hub, in which case you're still on a switched network.

<br>

Note also that on the Linksys Web site, they say that their
auto-sensing hubs "broadcast the 10Mb packets to the port that operate
at 10Mb only and broadcast the 100Mb packets to the ports that operate
at 100Mb only", which would indicate that if you sniff on a 10Mb port,
you will not see traffic coming sent to a 100Mb port, and <i>vice
versa</i>.  This problem has also been reported for Netgear dual-speed
hubs, and may exist for other "auto-sensing" or "dual-speed" hubs.

<br>

Some switches have the ability to replicate all traffic on all ports to
a single port so that you can plug your analyzer into that single port to
sniff all traffic.  You would have to check the documentation for the
switch to see if this is possible and, if so, to see how to do this.
See <a href="https://wiki.wireshark.org/SwitchReference">the switch
reference page</a> on <a href="https://wiki.wireshark.org/">the Wireshark
Wiki</a> for information on some switches.  (Note that it's a Wiki, so
you can update or fix that information, or add additional information on
those switches or information on new switches, yourself.)

<br>

Note also that many firewall/NAT boxes have a switch built into them;
this includes many of the "cable/DSL router" boxes.  If you have a box
of that sort, that has a switch with some number of Ethernet ports into
which you plug machines on your network, and another Ethernet port used
to connect to a cable or DSL modem, you can, at least, sniff traffic
between the machines on your network and the Internet by plugging
the Ethernet port on the router going to the modem, the Ethernet port on
the modem, and the machine on which you're running Wireshark into a hub
(make sure it's not a switching hub, and that, if it's a dual-speed hub,
all three of those ports are running at the same speed.

<br>

If your machine is <em>not</em> plugged into a switched network or a
dual-speed hub, or it is plugged into a switched network but the port is
set up to have all traffic replicated to it, the problem might be that
the network interface on which you're capturing doesn't support
"promiscuous" mode, or because your OS can't put the interface into
promiscuous mode.  Normally, network interfaces supply to the host only:
</p>

<ul>
<li>packets sent to one of that host's link-layer addresses;
<li>broadcast packets;
<li>multicast packets sent to a multicast address that the host has
		         configured the interface to accept.
</ul>

<p>
Most network interfaces can also be put in "promiscuous" mode, in which
they supply to the host all network packets they see.  Wireshark will try
to put the interface on which it's capturing into promiscuous mode
unless the "Capture packets in promiscuous mode" option is turned off in
the "Capture Options" dialog box, and TShark will try to put the
interface on which it's capturing into promiscuous mode unless the
<code>-p</code> option was specified.  However, some network interfaces
don't support promiscuous mode, and some OSes might not allow interfaces
to be put into promiscuous mode.

<br>

If the interface is not running in promiscuous mode, it won't see any
traffic that isn't intended to be seen by your machine.  It
<strong>will</strong> see broadcast packets, and multicast packets sent
to a multicast MAC address the interface is set up to receive.

<br>

You should ask the vendor of your network interface whether it supports
promiscuous mode.  If it does, you should ask whoever supplied the
driver for the interface (the vendor, or the supplier of the OS you're
running on your machine) whether it supports promiscuous mode with that
network interface.

<br>

In the case of token ring interfaces, the drivers for some of them, on
Windows, may require you to enable promiscuous mode in order to capture
in promiscuous mode.  See <a
href="https://wiki.wireshark.org/CaptureSetup/TokenRing">the Wireshark
Wiki item on Token Ring capturing</a> for details.

<br>

In the case of wireless LAN interfaces, it appears that, when those
interfaces are promiscuously sniffing, they're running in a
significantly different mode from the mode that they run in when they're
just acting as network interfaces (to the extent that it would be a
significant effort for those drivers to support for promiscuously
sniffing <em>and</em> acting as regular network interfaces at the same
time), so it may be that Windows drivers for those interfaces don't
support promiscuous mode.
""")

question("""When I capture with Wireshark, why can't I see any TCP
packets other than packets to and from my machine, even though another
analyzer on the network sees those packets?""")

answer("""
You're probably not seeing <em>any</em> packets other than unicast
packets to or from your machine, and broadcast and multicast packets; a
switch will normally send to a port only unicast traffic sent to the MAC
address for the interface on that port, and broadcast and multicast
traffic - it won't send to that port unicast traffic sent to a MAC
address for some other interface - and a network interface not in
promiscuous mode will receive only unicast traffic sent to the MAC
address for that interface, broadcast traffic, and multicast traffic
sent to a multicast MAC address the interface is set up to receive.

<br>

TCP doesn't use broadcast or multicast, so you will only see your own
TCP traffic, but UDP services may use broadcast or multicast so you'll
see some UDP traffic - however, this is not a problem with TCP traffic,
it's a problem with unicast traffic, as you also won't see all UDP
traffic between other machines.

<br>

I.e., this is probably <a href="#promiscsniff">the same question
as this earlier one</a>; see the response to that question.
""")

question("""Why am I only seeing ARP packets when I try to capture
traffic?""")

answer("""
You're probably on a switched network, and running Wireshark on a machine
that's not sending traffic to the switch and not being sent any traffic
from other machines on the switch.  ARP packets are often broadcast
packets, which are sent to all switch ports.

<br>

I.e., this is probably <a href="#promiscsniff">the same question
as this earlier one</a>; see the response to that question.
""")

question("""
Why am I not seeing any traffic when I try to capture traffic?""")

answer("""
Is the machine running Wireshark sending out any traffic on the network
interface on which you're capturing, or receiving any traffic on that
network, or is there any broadcast traffic on the network or multicast
traffic to a multicast group to which the machine running Wireshark
belongs?

<br>

If not, this may just be a problem with promiscuous sniffing, either due
to running on a switched network or a dual-speed hub, or due to problems
with the interface not supporting promiscuous mode; see the response to
<a href="#promiscsniff">this earlier question</a>.

<br>

Otherwise, on Windows, see the response to <a href="#capprobwin">this
question</a> and, on a UNIX-flavored OS, see the response to <a
href="#capprobunix">this question</a>.
""")

question("""
Can Wireshark capture on (my T1/E1 line, SS7 links, etc.)?
""")

answer("""
Wireshark can only capture on devices supported by libpcap/WinPcap.  On
most OSes, only devices that can act as network interfaces of the type
that support IP are supported as capture devices for libpcap/WinPcap,
although the device doesn't necessarily have to be running as an IP
interface in order to support traffic capture.

<br>

On Linux and FreeBSD, libpcap 0.8 and later support the API for <a
href="http://www.endace.com/products.htm">Endace Measurement Systems'
DAG cards</a>, so that a system with one of those cards, and its driver
and libraries, installed can capture traffic with those cards with
libpcap-based applications.  You would either have to have a version of
Wireshark built with that version of libpcap, or a dynamically-linked
version of Wireshark and a shared libpcap library with DAG support, in
order to do so with Wireshark.  You should ask Endace whether that could
be used to capture traffic on, for example, your T1/E1 link.

<br>

See <a href="https://wiki.wireshark.org/CaptureSetup/SS7">the SS7 capture
setup page</a> on <a href="https://wiki.wireshark.org/">the Wireshark
Wiki</a> for current information on capturing SS7 traffic on TDM
links.
""")

question("""How do I put an interface into promiscuous mode?""")

answer("""
By not disabling promiscuous mode when running Wireshark or TShark.

<br>

Note, however, that:
</p>
<ul>
<li>the form of promiscuous mode that libpcap (the library that
programs such as tcpdump, Wireshark, etc.  use to do packet capture)
turns on will <strong>not</strong> necessarily be shown if you run
<code>ifconfig</code> on the interface on a UNIX system;
<li>some network interfaces might not support promiscuous mode, and some
drivers might not allow promiscuous mode to be turned on - see <a
href="#promiscsniff">this earlier question</a> for more information on
that;
<li>the fact that you're not seeing any traffic, or are only seeing
broadcast traffic, or aren't seeing any non-broadcast traffic other than
traffic to or from the machine running Wireshark, does not mean that
promiscuous mode isn't on - see <a href="#promiscsniff">this earlier
question</a> for more information on that.
</ul>

<p>
I.e., this is probably <a href="#promiscsniff">the same question
as this earlier one</a>; see the response to that question.
""")

question("""
I can set a display filter just fine; why don't capture filters work?
""")

answer("""
Capture filters currently use a different syntax than display filters.  Here's
the corresponding section from the
<a
href="https://www.wireshark.org/docs/man-pages/wireshark.html">wireshark(1)</a>
man page:

<br>

"Display filters in Wireshark are very powerful; more fields are filterable
in Wireshark than in other protocol analyzers, and the syntax you can
use to create your filters is richer. As Wireshark progresses, expect
more and more protocol fields to be allowed in display filters.

<br>

Packet capturing is performed with the pcap library. The capture filter
syntax follows the rules of the pcap library. This syntax is different
from the display filter syntax."

<br>

The capture filter syntax used by libpcap can be found in the
<a href="http://www.tcpdump.org/tcpdump_man.html">tcpdump(8)</a>
man page.
""")


question("""I'm entering valid capture filters; why do I still get
"parse error" errors?""")

answer("""
There is a bug in some versions of libpcap/WinPcap that cause it to
report parse errors even for valid expressions if a previous filter
expression was invalid and got a parse error.

<br>

Try exiting and restarting Wireshark; if you are using a version of
libpcap/WinPcap with this bug, this will "erase" its memory of the
previous parse error.  If the capture filter that got the "parse error"
now works, the earlier error with that filter was probably due to this
bug.

<br>

The bug was fixed in libpcap 0.6; 0.4[.x] and 0.5[.x] versions of
libpcap have this bug, but 0.6[.x] and later versions don't.

<br>

Versions of WinPcap prior to 2.3 are based on pre-0.6 versions of
libpcap, and have this bug; WinPcap 2.3 is based on libpcap 0.6.2, and
doesn't have this bug.

<br>

If you are running Wireshark on a UNIX-flavored platform, run "wireshark
-v", or select "About Wireshark..." from the "Help" menu in Wireshark, to
see what version of libpcap it's using.  If it's not 0.6 or later, you
will need either to upgrade your OS to get a later version of libpcap,
or will need to build and install a later version of libpcap from <a
href="http://www.tcpdump.org/">the tcpdump.org Web site</a> and then
recompile Wireshark from source with that later version of libpcap.

<br>

If you are running Wireshark on Windows with a pre-2.3 version of
WinPcap, you will need to un-install WinPcap and then download and
install WinPcap 2.3.
""")

question("""
How can I capture packets with CRC errors?
""")

answer("""
Wireshark can capture only the packets that the packet capture library -
libpcap on UNIX-flavored OSes, and the WinPcap port to Windows of libpcap
on Windows - can capture, and libpcap/WinPcap can capture only the
packets that the OS's raw packet capture mechanism (or the WinPcap
driver, and the underlying OS networking code and network interface
drivers, on Windows) will allow it to capture.

<br>

Unless the OS always supplies packets with errors such as invalid CRCs
to the raw packet capture mechanism, or can be configured to do so,
invalid CRCs to the raw packet capture mechanism, Wireshark - and other
programs that capture raw packets, such as tcpdump - cannot capture
those packets.  You will have to determine whether your OS needs to be
so configured and, if so, can be so configured, configure it if
necessary and possible, and make whatever changes to libpcap and the
packet capture program you're using are necessary, if any, to support
capturing those packets.

<br>

Most OSes probably do <strong>not</strong> support capturing packets
with invalid CRCs on Ethernet, and probably do not support it on most
other link-layer types.  Some drivers on some OSes do support it, such
as some Ethernet drivers on FreeBSD; in those OSes, you might always get
those packets, or you might only get them if you capture in promiscuous
mode (you'd have to determine which is the case).

<br>

Note that libpcap does not currently supply to programs that use it an
indication of whether the packet's CRC was invalid (because the drivers
themselves do not supply that information to the raw packet capture
mechanism); therefore, Wireshark will not indicate which packets had CRC
errors unless the FCS was captured (see the next question) and you're
using Wireshark 0.9.15 and later, in which case Wireshark will check the
CRC and indicate whether it's correct or not.
""")

question("""
How can I capture entire frames, including the FCS?
""")

answer("""
Wireshark can only capture data that the packet capture library -
libpcap on UNIX-flavored OSes, and the WinPcap port to Windows of
libpcap on Windows - can capture, and libpcap/WinPcap can capture only
the data that the OS's raw packet capture mechanism (or the WinPcap
driver, and the underlying OS networking code and network interface
drivers, on Windows) will allow it to capture.

<br>

For any particular link-layer network type, unless the OS supplies the
FCS of a frame as part of the frame, or can be configured to do so,
Wireshark - and other programs that capture raw packets, such as tcpdump
- cannot capture the FCS of a frame.  You will have to determine whether
your OS needs to be so configured and, if so, can be so configured,
configure it if necessary and possible, and make whatever changes to
libpcap and the packet capture program you're using are necessary, if
any, to support capturing the FCS of a frame.

<br>

Most OSes do <strong>not</strong> support capturing the FCS of a frame
on Ethernet, and probably do not support it on most other link-layer
types.  Some drivres on some OSes do support it, such as some (all?)
Ethernet drivers on NetBSD and possibly the driver for Apple's gigabit
Ethernet interface in OS X; in those OSes, you might always get the
FCS, or you might only get the FCS if you capture in promiscuous mode
(you'd have to determine which is the case).

<br>

Versions of Wireshark prior to 0.9.15 will not treat an Ethernet FCS in a
captured packet as an FCS.  0.9.15 and later will attempt to determine
whether there's an FCS at the end of the frame and, if it thinks there
is, will display it as such, and will check whether it's the correct
CRC-32 value or not.
""")

question("""
I'm capturing packets on a machine on a VLAN; why don't the packets I'm
capturing have VLAN tags?
""")

answer("""
You might be capturing on what might be called a "VLAN interface" - the
way a particular OS makes VLANs plug into the networking stack might,
for example, be to have a network device object for the physical
interface, which takes VLAN packets, strips off the VLAN header and
constructs an Ethernet header, and passes that packet to an internal
network device object for the VLAN, which then passes the packets onto
various higher-level protocol implementations.

<br>

In order to see the raw Ethernet packets, rather than "de-VLANized"
packets, you would have to capture not on the virtual interface for the
VLAN, but on the interface corresponding to the physical network device,
if possible.  See <a
href="https://wiki.wireshark.org/CaptureSetup/VLAN">the Wireshark Wiki
item on VLAN capturing</a> for details.
""")

question("""
Why does Wireshark hang after I stop a capture?
""")

answer("""
The most likely reason for this is that Wireshark is trying to look up an
IP address in the capture to convert it to a name (so that, for example,
it can display the name in the source address or destination address
columns), and that lookup process is taking a very long time.

<br>

Wireshark calls a routine in the OS of the machine on which it's running
to convert of IP addresses to the corresponding names.  That routine
probably does one or more of:
</p>
<ul><li>a search of a system file listing IP addresses and names;
<li>a lookup using DNS;
<li>on UNIX systems, a lookup using NIS;
<li>on Windows systems, a NetBIOS-over-TCP query.
</ul>

<p>
If a DNS server that's used in an address lookup is not responding, the
lookup will fail, but will only fail after a timeout while the system
routine waits for a reply.

<br>

In addition, on Windows systems, if the DNS lookup of the address fails,
either because the server isn't responding or because there are no
records in the DNS that could be used to map the address to a name, a
NetBIOS-over-TCP query will be made.  That query involves sending a
message to the NetBIOS-over-TCP name service on that machine, asking for
the name and other information about the machine.  If the machine isn't
running software that responds to those queries - for example, many
non-Windows machines wouldn't be running that software - the lookup will
only fail after a timeout.  Those timeouts can cause the lookup to take
a long time.

<br>

If you disable network address-to-name translation - for example, by
turning off the "Enable network name resolution" option in the "Capture
Options" dialog box for starting a network capture - the lookups of the
address won't be done, which may speed up the process of reading the
capture file after the capture is stopped.  You can make that setting
the default by selecting "Preferences" from the "Edit" menu, turning off
the "Enable network name resolution" option in the "Name resolution"
options in the preferences disalog box, and using the "Save" button in
that dialog box; note that this will save <em>all</em> your current
preference settings.

<br>

If Wireshark hangs when reading a capture even with network name
resolution turned off, there might, for example, be a bug in one of
Wireshark's dissectors for a protocol causing it to loop infinitely.  If
you're not running the most recent release of Wireshark, you should first
upgrade to that release, as, if there's a bug of that sort, it might've
been fixed in a release after the one you're running.  If the hang
occurs in the most recent release of Wireshark, the bug should be
reported to <a href="mailto:wireshark-dev@wireshark.org">the Wireshark
developers' mailing list</a> at <code>wireshark-dev@wireshark.org</code>.

<br>

On UNIX-flavored OSes, please try to force Wireshark to dump core, by
sending it a <code>SIGABRT</code> signal (usually signal 6) with the
<code>kill</code> command, and then get a stack trace if you have a debugger
installed.  A stack trace can be obtained by using your debugger
(<code>gdb</code> in this example), the Wireshark binary, and the resulting
core file.  Here's an example of how to use the gdb command
<code>backtrace</code> to do so.
</p>

<pre>
        $ gdb wireshark core
        (gdb) backtrace
        ..... prints the stack trace
        (gdb) quit
        $
</pre>

<p>
The core dump file may be named "wireshark.core" rather than "core" on
some platforms (e.g., BSD systems).

<br>

Also, if at all possible, please send a copy of the capture file that caused
the problem.  When capturing packets, Wireshark normally writes captured
packets to a temporary file, which will probably be in <code>/tmp</code> or
<code>/var/tmp</code> on UNIX-flavored OSes, <code>\\TEMP</code> on the main system disk
(normally <code>\\Documents and Settings\\</code><var>your login name</var>
<code>\\Local Settings\\Temp</code> on the main system disk on Windows
Windows XP and Server 2003, and
<code>\\Users\\<var>your login name</var>\\AppData\\Local\\Temp</code> on the main
system disk on Windows Vista and later, so the capture file will probably be there.  If you
are capturing on a single interface, it will have a name of the form,
<code>wireshark_&lt;iface&gt;_YYYYmmddHHMMSS_XXXXXX.&lt;fmt&gt;</code>, where
&lt;fmt&gt; is the capture file format (pcap or pcapng), and &lt;iface&gt; is
the actual name of the interface you are capturing on; otherwise, if you are
capturing on multiple interfaces, it will have a name of the form,
<code>wireshark_&lt;N&gt;_interfaces_YYYYmmddHHMMSS_XXXXXX.&lt;fmt&gt;</code>, where &lt;N&gt;
is the number of simultaneous interfaces you are capturing on.  Please don't
send a trace file greater than 1 MB when compressed; instead, make it available
via FTP or HTTP, or say it's available but leave it up to a developer to ask
for it.  If the trace file contains sensitive information (e.g., passwords),
then please do not send it.
""")


#################################################################
section("Capturing packets on Windows")
#################################################################

question("""
I'm running Wireshark on Windows; why does some network interface on my
machine not show up in the list of interfaces in the "Interface:" field
in the dialog box popped up by "Capture->Start", and/or why does
Wireshark give me an error if I try to capture on that interface?
""", "capprobwin")

answer("""
If you are running Wireshark on Windows XP,
or Windows Server 2003, and this is the first time you have run a
WinPcap-based program (such as Wireshark, or TShark, or WinDump, or
Analyzer, or...) since the machine was rebooted, you need to run that
program from an account with administrator privileges; once you have run
such a program, you will not need administrator privileges to run any
such programs until you reboot.

<br>

If you are running on Windows Windows XP or Windows Server
2003 and have administrator privileges or a WinPcap-based program has
been run with those privileges since the machine rebooted, this problem
<em>might</em> clear up if you completely un-install WinPcap and then
re-install it.

<br>

If that doesn't work, then note that Wireshark relies on the WinPcap
library, on the WinPcap device driver, and on the facilities that come
with the OS on which it's running in order to do captures.

<br>

Therefore, if the OS, the WinPcap library, or the WinPcap driver don't
support capturing on a particular network interface device, Wireshark
won't be able to capture on that device.

<br>

WinPcap 2.3 has problems supporting PPP WAN interfaces on Windows NT
4.0, Windows 2000, Windows XP, and Windows Server 2003, and, to avoid
those problems, support for PPP WAN interfaces on those versions of
Windows has been disabled in WinPcap 3.0.  Regular dial-up lines, ISDN
lines, ADSL connections using PPPoE or PPPoA, and various other lines
such as T1/E1 lines are all PPP interfaces, so those interfaces might
not show up on the list of interfaces in the "Capture Options"
dialog on those OSes.

<br>

On Windows 2000, Windows XP, and Windows Server 2003, but
<strong>not</strong> Windows NT 4.0 or Windows Vista Beta 1, you should
be able to capture on the "GenericDialupAdapter" with WinPcap 3.1.  (3.1
beta releases called it the "NdisWanAdapter"; if you're using a 3.1 beta
release, you should un-install it and install the final 3.1 release.)
See <a href="https://wiki.wireshark.org/CaptureSetup/PPP">the Wireshark
Wiki item on PPP capturing</a> for details.

<br>

WinPcap prior to 3.0 does not support multiprocessor machines (note
that machines with a single multi-threaded processor, such as Intel's
new multi-threaded x86 processors, are multiprocessor machines as far as
the OS and WinPcap are concerned), and recent 2.x versions of WinPcap
refuse to operate if they detect that they're running on a
multiprocessor machine, which means that they may not show any network
interfaces.  You will need to use WinPcap 3.0 to capture on a
multiprocessor machine.

<br>

If an interface doesn't show up in the list of interfaces in the
"Interface:" field, and you know the name of the interface, try entering
that name in the "Interface:" field and capturing on that device.

<br>

If the attempt to capture on it succeeds, the interface is somehow not
being reported by the mechanism Wireshark uses to get a list of
interfaces.  Try listing the interfaces with WinDump; see <a
href="https://www.windump.org/">the WinDump Web site</a>
for information on using WinDump.

<br>

You would run WinDump with the <code>-D</code> flag; if it lists the
interface, please report this to <a
href="mailto:wireshark-dev@wireshark.org">wireshark-dev@wireshark.org</a>
giving full details of the problem, including
</p>

<ul>
<li>the operating system you're using, and the version of that operating
system;
<li>the type of network device you're using;
<li>the output of WinDump.
</ul>

<p>
If WinDump does <em>not</em> list the interface,
this is almost certainly a problem with one or more of:
</p>

<ul>
<li>the operating system you're using;
<li>the device driver for the interface you're using;
<li>the WinPcap library and/or the WinPcap device driver;
</ul>

<p>
so first check <a href="https://www.winpcap.org/misc/faq.htm">the
WinPcap FAQ</a> to see if your problem is mentioned there. If not, then see <a
href="https://www.winpcap.org/contact.htm">the WinPcap support page</a>
- check the "Submitting bugs" section.

<br>

If you are having trouble capturing on a particular network interface,
first try capturing on that device with WinDump; see <a
href="https://www.windump.org/">the WinDump Web site</a>
for information on using WinDump.

<br>

If you can capture on the interface with WinDump, send mail to <a
href="mailto:wireshark-users@wireshark.org">wireshark-users@wireshark.org</a>
giving full details of the problem, including
</p>

<ul>
<li>the operating system you're using, and the version of that operating
system;
<li>the type of network device you're using;
<li>the error message you get from Wireshark.
</ul>

<p>
If you <em>cannot</em> capture on the interface with WinDump,
this is almost certainly a problem with one or more of:
</p>

<ul>
<li>the operating system you're using;
<li>the device driver for the interface you're using;
<li>the WinPcap library and/or the WinPcap device driver;
</ul>

<p>
so first check <a href="https://www.winpcap.org/misc/faq.htm">the
WinPcap FAQ</a> to see if your problem is mentioned there. If not, then see <a
href="https://www.winpcap.org/contact.htm">the WinPcap support page</a>
- check the "Submitting bugs" section.

<br>

You may also want to ask the <a
href="mailto:wireshark-users@wireshark.org">wireshark-users@wireshark.org</a>
and the <a
href="mailto:winpcap-users@winpcap.org">winpcap-users@winpcap.org</a>
mailing lists to see if anybody happens to know about the problem and
know a workaround or fix for the problem.  (Note that you will have to
subscribe to that list in order to be allowed to mail to it; see <a
href="https://www.winpcap.org/contact.htm">the WinPcap support
page</a> for information on the mailing list.) In your mail,
please give full details of the problem, as described above, and also
indicate that the problem occurs with WinDump, not just with Wireshark.
""")

question("""
I'm running Wireshark on Windows; why do no network interfaces show up in
the list of interfaces in the "Interface:" field in the dialog box
popped up by "Capture->Start"?
""")

answer("""
This is really <a href="#capprobwin">the same question as a previous
one</a>; see the response to that question.
""")

question("""
I'm running Wireshark on Windows; why doesn't my serial port/ADSL
modem/ISDN modem show up in the list of interfaces in the "Interface:"
field in the dialog box popped up by "Capture->Start"?
""")

answer("""
Internet access on those devices is often done with the Point-to-Point
(PPP) protocol; WinPcap 2.3 has problems supporting PPP WAN interfaces
on Windows NT 4.0, Windows 2000, Windows XP, and Windows Server 2003,
and, to avoid those problems, support for PPP WAN interfaces on those
versions of Windows has been disabled in WinPcap 3.0.

<br>

On Windows 2000, Windows XP, and Windows Server 2003, but
<strong>not</strong> Windows NT 4.0 or Windows Vista Beta 1, you should
be able to capture on the "GenericDialupAdapter" with WinPcap 3.1.  (3.1
beta releases called it the "NdisWanAdapter"; if you're using a 3.1 beta
release, you should un-install it and install the final 3.1 release.)
See <a href="https://wiki.wireshark.org/CaptureSetup/PPP">the Wireshark
Wiki item on PPP capturing</a> for details.
""")

question("""
I'm running Wireshark on Windows NT 4.0/Windows 2000/Windows XP/Windows
Server 2003; my machine has a PPP (dial-up POTS, ISDN, etc.) interface,
and it shows up in the "Interface" item in the "Capture Options" dialog
box.  Why can no packets be sent on or received from that network while
I'm trying to capture traffic on that interface?""", "nt_ppp_sniff")

answer("""
Some versions of WinPcap have problems with PPP WAN interfaces on
Windows NT 4.0, Windows 2000, Windows XP, and Windows Server 2003; one
symptom that may be seen is that attempts to capture in promiscuous mode
on the interface cause the interface to be incapable of sending or
receiving packets.  You can disable promiscuous mode using the
<code>-p</code> command-line flag or the item in the "Capture Preferences"
dialog box, but this may mean that outgoing packets, or incoming
packets, won't be seen in the capture.

<br>

On Windows 2000, Windows XP, and Windows Server 2003, but
<strong>not</strong> Windows NT 4.0 or Windows Vista Beta 1, you should
be able to capture on the "GenericDialupAdapter" with WinPcap 3.1.  (3.1
beta releases called it the "NdisWanAdapter"; if you're using a 3.1 beta
release, you should un-install it and install the final 3.1 release.)
See <a href="https://wiki.wireshark.org/CaptureSetup/PPP">the Wireshark
Wiki item on PPP capturing</a> for details.
""")

question("""
I'm running Wireshark on Windows; why am I not seeing any traffic being
sent by the machine running Wireshark?""")

answer("""
If you are running some form of VPN client software, it might be causing
this problem; people have seen this problem when they have Check Point's
VPN software installed on their machine.  If that's the cause of the
problem, you will have to remove the VPN software in order to have
Wireshark (or any other application using WinPcap) see outgoing packets;
unfortunately, neither we nor the WinPcap developers know any way to
make WinPcap and the VPN software work well together.

<br>

Also, some drivers for Windows (especially some wireless network
interface drivers) apparently do not, when running in promiscuous mode,
arrange that outgoing packets are delivered to the software that
requested that the interface run promiscuously; try turning promiscuous
mode off.
""")

question("""
When I capture on Windows in promiscuous mode, I can see packets other
than those sent to or from my machine; however, those packets show up
with a "Short Frame" indication, unlike packets to or from my machine.
What should I do to arrange that I see those packets in their entirety?
""")

answer("""
In at least some cases, this appears to be the result of PGPnet running
on the network interface on which you're capturing; turn it off on that
interface.
""")

question("""
I'm trying to capture 802.11 traffic on Windows; why am I not seeing any
packets?
""", "win802_11promisc")

answer("""
At least some 802.11 card drivers on Windows appear not to see any
packets if they're running in promiscuous mode.  Try turning promiscuous
mode off; you'll only be able to see packets sent by and received by
your machine, not third-party traffic, and it'll look like Ethernet
traffic and won't include any management or control frames, but that's a
limitation of the card drivers.

<br>

See the archived <a
href="https://web.archive.org/web/20090226193157/http://www.micro-logix.com/winpcap/Supported.asp">MicroLogix's
list of cards supported with WinPcap</a> for information on
support of various adapters and drivers with WinPcap.
""")

question("""
I'm trying to capture 802.11 traffic on Windows; why am I seeing packets
received by the machine on which I'm capturing traffic, but not packets
sent by that machine?
""")

answer("""
This appears to be another problem with promiscuous mode; try turning it
off.
""")

question("""
I'm trying to capture Ethernet VLAN traffic on Windows, and I'm
capturing on a "raw" Ethernet device rather than a "VLAN interface", so
that I can see the VLAN headers; why am I seeing packets received by the
machine on which I'm capturing traffic, but not packets sent by that
machine?
""")

answer("""
The way the Windows networking code works probably means that packets
are sent on a "VLAN interface" rather than the "raw" device, so packets
sent by the machine will only be seen when you capture on the "VLAN
interface".  If so, you will be unable to see outgoing packets when
capturing on the "raw" device, so you are stuck with a choice between
seeing VLAN headers and seeing outgoing packets.
""")

#################################################################
section("Capturing packets on UN*Xes")
#################################################################

question("""
I'm running Wireshark on a UNIX-flavored OS; why does some network
interface on my machine not show up in the list of interfaces in the
"Interface:" field in the dialog box popped up by "Capture->Start",
and/or why does Wireshark give me an error if I try to capture on that
interface? """, "capprobunix")

answer("""
You may need to run Wireshark from an account with sufficient privileges
to capture packets, such as the super-user account, or may need to give
your account sufficient privileges to capture packets.  Only those
interfaces that Wireshark can open for capturing show up in that list; if
you don't have sufficient privileges to capture on any interfaces, no
interfaces will show up in the list.  See
<a href="https://wiki.wireshark.org/CaptureSetup/CapturePrivileges">the
Wireshark Wiki item on capture privileges</a> for details on how to give
a particular account or account group capture privileges on platforms
where that can be done.

<br>

If you are running Wireshark from an account with sufficient privileges,
then note that Wireshark relies on the libpcap library, and on the
facilities that come with the OS on which it's running in order to do
captures.  On some OSes, those facilities aren't present by default; see
<a href="https://wiki.wireshark.org/CaptureSetup/CaptureSupport">the
Wireshark Wiki item on adding capture support</a> for details.

<br>

And, even if you're running with an account that has sufficient
privileges to capture, and capture support is present in your OS, if the
OS or the libpcap library don't support capturing on a particular
network interface device or particular types of devices, Wireshark won't
be able to capture on that device.

<br>

On Solaris, note that libpcap 0.6.2 and earlier didn't support Token
Ring interfaces; the current version, 0.7.2, does support Token Ring,
and the current version of Wireshark works with libpcap 0.7.2 and later.

<br>

If an interface doesn't show up in the list of interfaces in the
"Interface:" field, and you know the name of the interface, try entering
that name in the "Interface:" field and capturing on that device.

<br>

If the attempt to capture on it succeeds, the interface is somehow not
being reported by the mechanism Wireshark uses to get a list of
interfaces; please report this to <a
href="mailto:wireshark-dev@wireshark.org">wireshark-dev@wireshark.org</a>
giving full details of the problem, including
</p>

<ul>
<li>the operating system you're using, and the version of that operating
system (for Linux, give both the version number of the kernel and the
name and version number of the distribution you're using);
<li>the type of network device you're using.
</ul>

<p>
If you are having trouble capturing on a particular network interface,
and you've made sure that (on platforms that require it) you've arranged
that packet capture support is present, as per the above, first try
capturing on that device with <code>tcpdump</code>.

<br>

If you can capture on the interface with <code>tcpdump</code>, send mail to
<a
href="mailto:wireshark-users@wireshark.org">wireshark-users@wireshark.org</a>
giving full details of the problem, including
</p>

<ul>
<li>the operating system you're using, and the version of that operating
system (for Linux, give both the version number of the kernel and the
name and version number of the distribution you're using);
<li>the type of network device you're using;
<li>the error message you get from Wireshark.
</ul>

<p>
If you <em>cannot</em> capture on the interface with <code>tcpdump</code>,
this is almost certainly a problem with one or more of:
</p>

<ul>
<li>the operating system you're using;
<li>the device driver for the interface you're using;
<li>the libpcap library;
</ul>

<p>
so you should report the problem to the company or organization that
produces the OS (in the case of a Linux distribution, report the problem
to whoever produces the distribution).

<br>

You may also want to ask the <a
href="mailto:wireshark-users@wireshark.org">wireshark-users@wireshark.org</a>
and the <a
href="mailto:tcpdump-workers@lists.tcpdump.org">tcpdump-workers@lists.tcpdump.org</a>
mailing lists to see if anybody happens to know about the problem and
know a workaround or fix for the problem.  In your mail, please give
full details of the problem, as described above, and also indicate that
the problem occurs with <code>tcpdump</code> not just with Wireshark.
""")

question("""
I'm running Wireshark on a UNIX-flavored OS; why do no network interfaces
show up in the list of interfaces in the "Interface:" field in the
dialog box popped up by "Capture->Start"?
""")

answer("""
This is really <a href="#capprobunix">the same question as the previous
one</a>; see the response to that question.
""")

question("""I'm capturing packets on Linux; why do the time stamps have
only 100ms resolution, rather than 1us resolution?""")

answer("""
Wireshark gets time stamps from libpcap/WinPcap, and
libpcap/WinPcap get them from the OS kernel, so Wireshark - and any other
program using libpcap, such as tcpdump - is at the mercy of the time
stamping code in the OS for time stamps.

<br>

At least on x86-based machines, Linux can get high-resolution time
stamps on newer processors with the Time Stamp Counter (TSC) register;
for example, Intel x86 processors, starting with the Pentium Pro, and
including all x86 processors since then, have had a TSC, and other
vendors probably added the TSC at some point to their families of x86
processors.

The Linux kernel must be configured with the CONFIG_X86_TSC option
enabled in order to use the TSC.  Make sure this option is enabled in
your kernel.

<br>

In addition, some Linux distributions may have bugs in their versions of
the kernel that cause packets not to be given high-resolution time
stamps even if the TSC is enabled.  See, for example, bug 61111 for Red
Hat Linux 7.2.  If your distribution has a bug such as this, you may
have to run a standard kernel from kernel.org in order to get
high-resolution time stamps.
""")

#################################################################
section("Capturing packets on wireless LANs")
#################################################################


question("""
How can I capture raw 802.11 frames, including non-data (management,
beacon) frames?
""", "raw_80211_sniff")

answer("""
That depends on the operating system on which you're running, and on the
802.11 interface on which you're capturing.

<br>

This would probably require that you capture in promiscuous mode or in
the mode called "monitor mode" or "RFMON mode".  On some platforms, or
with some cards, this might require that you capture in monitor mode -
promiscuous mode might not be sufficient.  If you want to capture
traffic on networks other than the one with which you're associated, you
will have to capture in monitor mode.

<br>

Not all operating systems support capturing non-data packets and, even
on operating systems that do support it, not all drivers, and thus not
all interfaces, support it.  Even on those that do, monitor mode might
not be supported by the operating system or by the drivers for all
interfaces.

<br>

<strong>NOTE:</strong> an interface running in monitor mode will, on
most if not all platforms, not be able to act as a regular network
interface; putting it into monitor mode will, in effect, take your
machine off of whatever network it's on as long as the interface is in
monitor mode, allowing it only to passively capture packets.

<br>

This means that you should disable name resolution when capturing in
monitor mode; otherwise, when Wireshark (or TShark, or tcpdump) tries
to display IP addresses as host names, it will probably block for a long
time trying to resolve the name because it will not be able to
communicate with any DNS or NIS servers.

<br>

See <a
href="https://wiki.wireshark.org/CaptureSetup/WLAN">the Wireshark
Wiki item on 802.11 capturing</a> for details.
""")

question("""
How do I capture on an 802.11 device in monitor mode?""",
"monitor")

answer("""
Whether you will be able to capture in monitor mode depends on the
operating system, adapter, and driver you're using.
See <a href="#raw_80211_sniff">the previous question</a> for information
on monitor mode, including a link to the Wireshark Wiki page that gives
details on 802.11 capturing.
""")

#################################################################
section("Viewing traffic")
#################################################################


question("Why am I seeing lots of packets with incorrect TCP checksums?")

answer("""
If the packets that have incorrect TCP checksums are all being sent by
the machine on which Wireshark is running, this is probably because the
network interface on which you're capturing does TCP checksum
offloading.  That means that the TCP checksum is added to the packet by
the network interface, not by the OS's TCP/IP stack; when capturing on
an interface, packets being sent by the host on which you're capturing
are directly handed to the capture interface by the OS, which means that
they are handed to the capture interface without a TCP checksum being
added to them.

<br>

The only way to prevent this from happening would be to disable TCP
checksum offloading, but
</p>

<ol>
<li>that might not even be possible on some OSes;
<li>that could reduce networking performance significantly.
</ol>

<p>
However, you can disable the check that Wireshark does of the TCP
checksum, so that it won't report any packets as having TCP checksum
errors, and so that it won't refuse to do TCP reassembly due to a packet
having an incorrect TCP checksum.  That can be set as an Wireshark
preference by selecting "Preferences" from the "Edit" menu, opening up
the "Protocols" list in the left-hand pane of the "Preferences" dialog
box, selecting "TCP", from that list, turning off the "Check the
validity of the TCP checksum when possible" option, clicking "Save" if
you want to save that setting in your preference file, and clicking
"OK".

<br>

It can also be set on the Wireshark or TShark command line with a
<code>-o tcp.check_checksum:false</code> command-line flag, or manually set
in your preferences file by adding a <code>tcp.check_checksum:false</code>
line.
""")

question("""
I've just installed Wireshark, and the traffic on my local LAN
is boring.  Where can I find more interesting captures?
""")

answer("""
We have a collection of strange and exotic sample capture
files at %s""" % (selflink("https://wiki.wireshark.org/SampleCaptures")))


question("""
Why doesn't Wireshark correctly identify RTP packets? It shows them
only as UDP.""")

answer("""
Wireshark can identify a UDP datagram as containing a packet of a
particular protocol running atop UDP only if
</p>

<ol>
<li> The protocol in question has a particular standard port
number, and the UDP source or destination port number is that port

<li> Packets of that protocol can be identified by looking for a
"signature" of some type in the packet - i.e., some data
that, if Wireshark finds it in some particular part of a
packet, means that the packet is almost certainly a packet of
that type.

<li> Some <em>other</em> traffic earlier in the capture indicated that,
for example, UDP traffic between two particular addresses and
ports will be RTP traffic.
</ol>

<p>
RTP doesn't have a standard port number, so 1) doesn't work; it doesn't,
as far as I know, have any "signature", so 2) doesn't work.

<br>

That leaves 3).  If there's RTSP traffic that sets up an RTP session,
then, at least in some cases, the RTSP dissector will set things up so
that subsequent RTP traffic will be identified.  Currently, that's the
only place we do that; there may be other places.

<br>

However, there will always be places where Wireshark is simply
<b>incapable</b> of deducing that a given UDP flow is RTP; a mechanism
would be needed to allow the user to specify that a given conversation
should be treated as RTP.  As of Wireshark 0.8.16, such a mechanism
exists; if you select a UDP or TCP packet, the right mouse button menu
will have a "Decode As..." menu item, which will pop up a dialog box
letting you specify that the source port, the destination port, or both
the source and destination ports of the packet should be dissected as
some particular protocol.
""")

question("""
Why doesn't Wireshark show Yahoo Messenger packets in captures that
contain Yahoo Messenger traffic?""")

answer("""
Wireshark only recognizes as Yahoo Messenger traffic packets to or from TCP
port 3050 that begin with "YPNS", "YHOO", or "YMSG".  TCP segments that
start with the middle of a Yahoo Messenger packet that takes more than one
TCP segment will not be recognized as Yahoo Messenger packets (even if the
TCP segment also contains the beginning of another Yahoo Messenger
packet).
""")

#################################################################
section("Filtering traffic")
#################################################################


question("""I saved a filter and tried to use its name to filter the
display; why do I get an "Unexpected end of filter string" error?""")

answer("""
You cannot use the name of a saved display filter as a filter.  To
filter the display, you can enter a display filter expression -
<strong>not</strong> the name of a saved display filter - in the
"Filter:" box at the bottom of the display, and type the &lt;Enter&gt; key or
press the "Apply" button (that does not require you to have a saved
filter), or, if you want to use a saved filter, you can press the
"Filter:" button, select the filter in the dialog box that pops up, and
press the "OK" button.""")

question("""
How can I search for, or filter, packets that have a particular string
anywhere in them?
""")

answer("""
If you want to do this when capturing, you can't.  That's a feature that
would be hard to implement in capture filters without changes to the
capture filter code, which, on many platforms, is in the OS kernel and,
on other platforms, is in the libpcap library.

<br>

After capture, you can search for text by selecting <i>Edit&#8594;Find
Packet...</i> and making sure <i>String</i> is selected. Alternately, you can
use the "contains" display filter operator or "matches" operator if it's
supported on your system.
""")

question("""
How do I filter a capture to see traffic for virus XXX?
""")

answer("""
For some viruses/worms there might be a capture filter to recognize the
virus traffic.  Check the <a
href="https://wiki.wireshark.org/CaptureFilters">CaptureFilters</a> page
on the <a href="https://wiki.wireshark.org/">Wireshark Wiki</a> to see if
anybody's added such a filter.

<br>

Note that Wireshark was not designed to be an intrusion detection system;
you might be able to use it as an IDS, but in most cases software
designed to be an IDS, such as <a href="https://www.snort.org/">Snort</a>
or <a href="https://www.prelude-siem.org/">Prelude</a>, will probably work
better.
""")

#################################################################
if __name__ == '__main__':
	sys.exit(main())
#################################################################
