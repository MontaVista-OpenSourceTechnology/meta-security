SUMMARY = "A library for Microsoft compression formats"
HOMEPAGE = "http://www.cabextract.org.uk/libmspack/"
SECTION = "lib"
LICENSE = "LGPL-2.1"
DEPENDS = ""

LIC_FILES_CHKSUM = "file://COPYING.LIB;beginline=1;endline=2;md5=5b1fd1f66ef926b3c8a5bb00a72a28dd"

PR .= ".2"

SRC_URI = "${DEBIAN_MIRROR}/main/libm/${BPN}/${BPN}_${PV}.orig.tar.gz \
           file://CVE-2018-14682.patch \
           file://CVE-2018-14679_80.patch \
           file://CVE-2018-18585.patch \
           file://CVE-2018-18584.patch \
           file://CVE-2018-14681.patch \
"
SRC_URI[md5sum] = "3aa3f6b9ef101463270c085478fda1da"
SRC_URI[sha256sum] = "8967f275525f5067b364cee43b73e44d0433668c39f9376dfff19f653d1c8110"

inherit autotools

S = "${WORKDIR}/${BP}alpha"