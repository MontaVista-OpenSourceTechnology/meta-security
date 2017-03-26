SUMMARY = "analysis of C/C++ code"
HOME_URL = "http://cppcheck.sourceforge.net/"
LICENSE = "GPL-3.0"
LIC_FILES_CHKSUM = "file://COPYING;md5=d32239bcb673463ab874e80d47fae504"

DEPENDS = "libpcre"

SRCREV = "ebeaf98205092acbbef19e35893b58143c328c78"
SRC_URI = "git://github.com/danmar/cppcheck.git;branch=${PV}"

inherit autotools-brokensep

S = "${WORKDIR}/git"

RDEPENDS_${PN} = "python"
