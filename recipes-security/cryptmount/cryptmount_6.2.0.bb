SUMMARY = "Linux encrypted filesystem management tool"
HOMEPAGE = "http://cryptmount.sourceforge.net/"
LIC_FILES_CHKSUM = "file://COPYING;beginline=1;endline=4;md5=6e69c425bf32ecf9b1e11d29d146d03d"
LICENSE = "GPL-2.0-only"
SRC_URI = "https://sourceforge.net/projects/cryptmount/files/${BPN}/${BPN}-6.2/${BPN}-${PV}.tar.gz"

SRC_URI[sha256sum] = "90cc49fd598d636929c70479b1305f12b011edadf4a54578ace6c0fca8cb5ed2"

inherit autotools-brokensep gettext pkgconfig systemd

EXTRA_OECONF = " --enable-cswap --enable-fsck --enable-argv0switch"

PACKAGECONFIG ?="intl luks gcrypt nls"
PACKAGECONFIG:append = " ${@bb.utils.contains('DISTRO_FEATURES', 'systemd', 'systemd', '', d)}"

PACKAGECONFIG[systemd] = "--with-systemd, --without-systemd, systemd"
PACKAGECONFIG[intl] = "--with-libintl-prefix, --without-libintl-prefix"
PACKAGECONFIG[gcrypt] = "--with-libgcrypt, --without-libgcrypt, libgcrypt"
PACKAGECONFIG[luks] = "--enable-luks, --disable-luks, cryptsetup"
PACKAGECONFIG[nls] = "--enable-nls, --disable-nls, "

SYSTEMD_PACKAGES = "${PN}"
SYSTEMD_SERVICE:${PN} = "cryptmount.service"

do_install:append () {
    if ${@bb.utils.contains('DISTRO_FEATURES','systemd','true','false',d)}; then
        install -D -m 0644 ${S}/sysinit/cryptmount.service ${D}${systemd_system_unitdir}/cryptmount.service
        if ${@bb.utils.contains('DISTRO_FEATURES','usrmerge','false','true',d)}; then
           rm -fr ${D}/usr/lib
        fi
    fi
}

FILES:${PN} += "${systemd_system_unitdir}"

RDEPENDS:${PN} = "libdevmapper"
