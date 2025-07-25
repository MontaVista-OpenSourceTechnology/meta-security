DESCRIPTION = "Selection of tools for developers working with Smack"
HOMEPAGE = "https://github.com/smack-team/smack"
SECTION = "Security/Access Control"
LICENSE = "LGPL-2.1-only"

LIC_FILES_CHKSUM = "file://COPYING;md5=4fbd65380cdd255951079008b364516c"

SRCREV = "4a102c7584b39ce693995ffb65e0918a9df98dd8"
SRC_URI = " \
	git://github.com/smack-team/smack.git;branch=master;protocol=https \
	file://smack_generator_make_fixup.patch \
	file://run-ptest"

PV = "1.3.1"

CVE_STATUS[CVE-2014-0363] = "cpe-incorrect: different product"
CVE_STATUS[CVE-2014-0364] = "cpe-incorrect: different product"
CVE_STATUS[CVE-2016-10027] = "cpe-incorrect: different product"

inherit autotools update-rc.d pkgconfig ptest
inherit ${@bb.utils.contains('VIRTUAL-RUNTIME_init_manager','systemd','systemd','', d)}
inherit features_check

REQUIRED_DISTRO_FEATURES = "smack"

PACKAGECONFIG ??= ""
PACKAGECONFIG:append = " ${@bb.utils.contains('DISTRO_FEATURES', 'systemd', 'systemd', '', d)}"

PACKAGECONFIG[systemd] = "--with-systemdsystemunitdir=${systemd_system_unitdir}, --without-systemdsystemunitdir, systemd"

do_compile:append () {
	oe_runmake -C ${S}/tests generator
}

do_install:append () {
	install -d ${D}${sysconfdir}/init.d
	install -d ${D}${sysconfdir}/smack
	install -d ${D}${sysconfdir}/smack/accesses.d
	install -d ${D}${sysconfdir}/smack/cipso.d
	install ${S}/init/smack.rc ${D}/${sysconfdir}/init.d/smack
}

do_install_ptest () {
	install -d ${D}${PTEST_PATH}/tests
	install ${S}/tests/generator ${D}/${PTEST_PATH}/tests
	install ${S}/tests/generate-rules.sh ${D}${PTEST_PATH}/tests
	install ${S}/tests/make_policies.bash ${D}${PTEST_PATH}/tests
}

INITSCRIPT_PACKAGES = "${PN}"
INITSCRIPT_NAME = "smack"
INITSCRIPT_PARAMS = "start 16 2 3 4 5 . stop 35 0 1 6 ."

FILES:${PN} += "${sysconfdir}/init.d/smack"
FILES:${PN}-ptest += "generator"

RDEPENDS:${PN} += "coreutils python3-core"
RDEPENDS:${PN}-ptest += "make bash bc"

BBCLASSEXTEND = "native"
