DESCRIPTION = "Simple initramfs image for mounting the rootfs over the verity device mapper."

# We want a clean, minimal image.
IMAGE_FEATURES = ""

PACKAGE_INSTALL = " \
    initramfs-dm-verity \
    base-files \
    busybox \
    util-linux-mount \
    udev \
    cryptsetup \
    lvm2-udevrules \
"

# Can we somehow inspect reverse dependencies to avoid these variables?
do_image[depends] += "${DM_VERITY_IMAGE}:do_image_${DM_VERITY_IMAGE_TYPE}"

# Ensure dm-verity.env is updated also when rebuilding DM_VERITY_IMAGE
do_image[nostamp] = "1"

IMAGE_FSTYPES = "${INITRAMFS_FSTYPES}"

inherit core-image

deploy_verity_hash() {
    install -D -m 0644 ${DEPLOY_DIR_IMAGE}/${DM_VERITY_IMAGE}-${MACHINE}.${DM_VERITY_IMAGE_TYPE}.verity.env ${IMAGE_ROOTFS}/${datadir}/dm-verity.env
}
IMAGE_PREPROCESS_COMMAND += "deploy_verity_hash;"
