"""Independently validate an offline Cheesecake recovery candidate."""

import argparse
import hashlib
import json
import lzma
import re
import struct
from pathlib import Path, PurePosixPath

from cheesecake_os.cpio import read_cpio
from cheesecake_os.fit import Fit

OTA_SHA = "26be0733f2183b1388763f7b329f67394f6adf93e3c4952d04b03095c6bc77de"
BOOT_SHA = "13d2b9f071e77f70360d96de030e780c46606e908d08a66502215c1c82cb5e64"
PINNED_MANIFEST_SHA = "1966d82af2a8a3a0fc8796f98935e1ed32886e2f701e77ac1a5ab7d577a384e8"
CONFIG = "/configurations/cheesecake-pvt-recovery"
BOOT_LIMIT = 13_676_544


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def regular(path: Path) -> bytes:
    require(path.is_file() and not path.is_symlink(), f"Expected a regular file: {path}")
    return path.read_bytes()


def check_ramdisk(data: bytes, serial: str, graphics_sha256: str) -> None:
    entries = read_cpio(lzma.decompress(data, format=lzma.FORMAT_ALONE))
    names = [name.removeprefix("./") for name, _ in entries]
    require(
        all(
            name == "TRAILER!!!"
            or (not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts)
            for name in names
        ),
        "Recovery ramdisk contains an unsafe path",
    )
    files = {name.removeprefix("./"): content for name, content in entries}
    require(len(files) == len(entries), "Recovery ramdisk has duplicate paths")
    usb = files.get("init.recovery.usb.rc", b"")
    props = files.get("prop.default", b"")
    bind = files.get("sbin/cheesecake-usb-bind.sh", b"")
    inventory = files.get("sbin/cheesecake-storage-inventory.sh", b"")
    fstab = files.get("etc/recovery.fstab", b"")
    require("etc/recovery.fstab" in files, "Recovery fstab is missing")
    require(
        f"write /config/usb_gadget/g1/strings/0x409/serialnumber {serial}".encode() in usb
        and b"start cheesecake-usb-bind" in usb
        and b"/sbin/cheesecake-usb-bind.sh" in usb,
        "Recovery USB config does not match the requested serial",
    )
    require(
        b"ro.adb.secure=0" in props and b"ro.twrp.headless=1" in props,
        "Recovery ramdisk is missing its headless root-ADB properties",
    )
    require(b"Binding Cheesecake TWRP ADB" in bind, "Cheesecake USB bind helper is missing")
    require(
        b"CHEESECAKE_READ_ONLY_INVENTORY=1" in inventory
        and b"/proc/mtd" in inventory
        and b"/proc/partitions" in inventory
        and b"/sys/class/ubi" in inventory,
        "Read-only Cheesecake storage inventory helper is missing",
    )
    require(
        not any(
            command in inventory
            for command in (
                b"/dev/",
                b"mount ",
                b"umount ",
                b"dd ",
                b"fastboot",
                b"flash_erase",
                b"ubiupdatevol",
                b"ubiformat",
            )
        ),
        "Storage inventory helper must not access or modify device storage",
    )
    require(
        all(not line.strip() or line.lstrip().startswith(b"#") for line in fstab.splitlines()),
        "Recovery fstab contains an unverified mount target",
    )
    require(
        digest(files.get("sbin/libminuitwrp.so", b"")) == graphics_sha256,
        "Recovery graphics library differs from the manifest",
    )
    require(
        b"/sys/devices/platform/mt_usb/cmode" not in b"\n".join(files.values()),
        "Recovery contains an unverified MT8519 USB-controller write",
    )


def validate(recovery: Path, stock_boot: Path, ramdisk_path: Path, graphics_path: Path, serial: str) -> None:
    require(re.fullmatch(r"[A-Za-z0-9_-]{4,64}", serial) is not None, "Invalid USB serial")
    require(recovery.is_dir() and not recovery.is_symlink(), "Candidate must be a real directory")
    manifest_bytes = regular(recovery / "recovery.json")
    manifest = json.loads(manifest_bytes)
    require(isinstance(manifest, dict), "Candidate manifest must be a JSON object")
    require(
        manifest.get("format") == 1
        and manifest.get("product") == "cheesecake"
        and manifest.get("build") == "NS65741/8149"
        and manifest.get("candidate") is True
        and manifest.get("serial") == serial,
        "Candidate identity or serial differs",
    )
    image_record = manifest.get("image", {})
    require(isinstance(image_record, dict), "Candidate image record must be an object")
    require(image_record.get("name") == "recovery.img", "Unexpected candidate image name")
    image_bytes = regular(recovery / "recovery.img")
    require(len(image_bytes) <= BOOT_LIMIT, "Candidate exceeds the pinned OTA boot-image bound")
    require(len(image_bytes) % 4096 == 0, "Candidate image is not 4096-byte aligned")
    require(
        image_record.get("size") == len(image_bytes)
        and image_record.get("sha256") == digest(image_bytes),
        "Candidate image hash or size differs from its manifest",
    )

    sources = manifest.get("sources", {})
    require(isinstance(sources, dict), "Candidate sources record must be an object")
    require(
        sources.get("ota_sha256") == OTA_SHA
        and sources.get("stock_boot_sha256") == BOOT_SHA
        and sources.get("manifest_sha256") == PINNED_MANIFEST_SHA,
        "Candidate source pins differ",
    )
    require(
        digest(regular(ramdisk_path)) == sources.get("ramdisk_sha256")
        and digest(regular(graphics_path)) == sources.get("graphics_sha256"),
        "TWRP build inputs differ from the candidate manifest",
    )
    stock_bytes = regular(stock_boot)
    require(digest(stock_bytes) == BOOT_SHA, "Stock boot image checksum differs")
    stock = Fit(stock_bytes)
    candidate = Fit(image_bytes)
    require(
        digest(stock.prop("/images/kernel-1", "data")) == sources.get("kernel_sha256")
        and digest(stock.prop("/images/fdt-dvt", "data")) == sources.get("fdt_sha256")
        and digest(stock.prop("/images/ramdisk-1", "data"))
        == sources.get("stock_ramdisk_sha256"),
        "Candidate source component hashes differ from the pinned stock FIT",
    )
    require(
        candidate.prop("/configurations", "default") == b"cheesecake-pvt-recovery\0",
        "Candidate does not select the Cheesecake recovery configuration",
    )
    require(
        candidate.prop(CONFIG, "kernel") == b"kernel-1\0"
        and candidate.prop(CONFIG, "fdt") == b"fdt-dvt\0"
        and candidate.prop(CONFIG, "ramdisk") == b"ramdisk-1\0",
        "Candidate recovery configuration references differ",
    )
    for node, source in (("kernel-1", "kernel_sha256"), ("fdt-dvt", "fdt_sha256")):
        path = "/images/" + node
        require(
            candidate.prop(path, "data") == stock.prop(path, "data")
            and digest(candidate.prop(path, "data")) == sources.get(source),
            "Candidate changed the pinned " + node,
        )

    ramdisk = candidate.prop("/images/ramdisk-1", "data")
    require(
        candidate.prop("/images/ramdisk-1", "compression") == b"lzma\0"
        and candidate.prop("/images/ramdisk-1/hash-1", "algo") == b"sha256\0"
        and candidate.prop("/images/ramdisk-1/hash-1", "value") == hashlib.sha256(ramdisk).digest(),
        "Candidate recovery ramdisk hash is invalid",
    )
    check_ramdisk(ramdisk, serial, sources.get("graphics_sha256", ""))
    signatures = sorted(node for node in stock.nodes if node.endswith("/signature-1"))
    require(signatures, "Pinned stock FIT has no configuration signatures")
    require(
        signatures == sorted(node for node in candidate.nodes if node.endswith("/signature-1")),
        "Candidate FIT signature nodes differ from stock",
    )
    included = candidate.prop(CONFIG + "/signature-1", "hashed-nodes").split(b"\0")
    require(
        b"/images/ramdisk-1" not in included
        and b"/images/ramdisk-1/hash-1" not in included,
        "Selected recovery ramdisk is covered by the stock signature",
    )
    for node in signatures:
        require(
            stock.signed_stream(node) == candidate.signed_stream(node),
            "Candidate changed stock FIT signature stream: " + node,
        )
    print("Validated offline Cheesecake NS65741/8149 recovery candidate for the requested serial.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recovery", required=True, type=Path)
    parser.add_argument("--stock-boot", required=True, type=Path)
    parser.add_argument("--ramdisk", required=True, type=Path)
    parser.add_argument("--graphics", required=True, type=Path)
    parser.add_argument("--serial", required=True)
    args = parser.parse_args()
    try:
        validate(args.recovery, args.stock_boot, args.ramdisk, args.graphics, args.serial)
    except (OSError, ValueError, KeyError, struct.error, lzma.LZMAError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
