# Cheesecake OS builder

This repository currently provides the independent offline validation gate for the Cheesecake [NS65741/8149](https://ftvdb.com/echo/firmware/com.amazon.cheesecake.android.os/7ef4610d48dd08558440e42e63521d52-13222532484-fire-os-6574-1-ns65741-8149-2026-09-29/) recovery candidate.

It does not yet build a rooted OS or provide a RAM-only loader.

The candidate remains based on the available 8149 OTA and is not proven compatible with the test unit's installed 0013222531716 build.

The current recovery package fits within the test unit's Fastboot-reported `boot_a` and `boot_b` capacities of 13,676,544 bytes.

## Validate a candidate

Prepare `boot.img` from the pinned local OTA with `twrp_device_amazon_cheesecake`, then validate its recovery package:

```sh
TWRP_REPO=../twrp_device_amazon_cheesecake
TWRP_TREE="$TWRP_REPO/work/twrp"
python3 -m cheesecake_os.recovery \
  --recovery "$TWRP_REPO/work/recovery-candidate" \
  --stock-boot "$TWRP_REPO/work/inputs/images/boot.img" \
  --ramdisk "$TWRP_TREE/out/target/product/cheesecake/ramdisk-recovery.img" \
  --graphics "$TWRP_TREE/out/target/product/cheesecake/system/lib/libminuitwrp.so" \
  --serial TEST_DEVICE_SERIAL
```

The validator checks the candidate manifest and serial, TWRP build-input hashes, pinned OTA and boot hashes, kernel and device-tree identity, recovery FIT references, ramdisk contents and hash, image size, and preservation of every stock FIT signature stream.

It only reads local files and prints a validation result.

The ramdisk's manual `/sbin/cheesecake-storage-inventory.sh` helper reads only procfs and sysfs metadata and prints to stdout.
After a RAM recovery boot is available, capture it on the host with `adb -s "$SERIAL" exec-out sh /sbin/cheesecake-storage-inventory.sh > storage-inventory.txt`.
Do not read raw partitions until the output establishes the runtime storage layout and confirms which filesystems are mounted.

## Device boundary

Validation establishes that the candidate matches the recorded 8149 source artifacts; it does not establish boot compatibility with the installed firmware or the UBI and recovery layout.

No install, fastboot, flash, recovery boot, or other device operation is performed by this repository stage.
