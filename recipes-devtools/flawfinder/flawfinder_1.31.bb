SUMMARY = "a simple program that examines C/C++ source code and reports possible security weaknesses (“flaws”) sorted by risk level"

HOME_URL = "https://www.dwheeler.com/flawfinder/"
LICENSE = "GPL-2.0"

LIC_FILES_CHKSUM = "file://COPYING;md5=0636e73ff0215e8d672dc4c32c317bb3"


SRC_URI = "https://www.dwheeler.com/${BPN}/${BP}.tar.gz"

SRC_URI[md5sum] = "27f534e527db3eeef827c9a1b0d755c2"
SRC_URI[sha256sum] = "bca7256fdf71d778eb59c9d61fc22b95792b997cc632b222baf79cfc04887c30"

inherit autotools-brokensep

do_install () {
	sed -i s':^prefix=/usr/local:prefix=${prefix}:' ${S}/makefile
	oe_runmake install DESTDIR=${D}
	chown root:root ${D}/${bindir}/flawfinder
}

