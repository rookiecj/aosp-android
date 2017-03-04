#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import sys
import argparse
import os
import os.path
import struct


"""
mtbootimg.h
https://android.googlesource.com/platform/system/core/+/master/mkbootimg/bootimg.h
#define BOOT_MAGIC "ANDROID!"
#define BOOT_MAGIC_SIZE 8
#define BOOT_NAME_SIZE 16
#define BOOT_ARGS_SIZE 512
#define BOOT_EXTRA_ARGS_SIZE 1024
struct boot_img_hdr
{
    uint8_t magic[BOOT_MAGIC_SIZE];
    uint32_t kernel_size;  /* size in bytes */
    uint32_t kernel_addr;  /* physical load addr */
    uint32_t ramdisk_size; /* size in bytes */
    uint32_t ramdisk_addr; /* physical load addr */
    uint32_t second_size;  /* size in bytes */
    uint32_t second_addr;  /* physical load addr */
    uint32_t tags_addr;    /* physical addr for kernel tags */
    uint32_t page_size;    /* flash page size we assume */
    uint32_t unused;       /* reserved for future expansion: MUST be 0 */
    /* operating system version and security patch level; for
     * version "A.B.C" and patch level "Y-M-D":
     * ver = A << 14 | B << 7 | C         (7 bits for each of A, B, C)
     * lvl = ((Y - 2000) & 127) << 4 | M  (7 bits for Y, 4 bits for M)
     * os_version = ver << 11 | lvl */
    uint32_t os_version;
    uint8_t name[BOOT_NAME_SIZE]; /* asciiz product name */
    uint8_t cmdline[BOOT_ARGS_SIZE];
    uint32_t id[8]; /* timestamp / checksum / sha1 / etc */
    /* Supplemental command line data; kept here to maintain
     * binary compatibility with older versions of mkbootimg */
    uint8_t extra_cmdline[BOOT_EXTRA_ARGS_SIZE];
} __attribute__((packed));


/*
** +-----------------+
** | boot header     | 1 page
** +-----------------+
** | kernel          | n pages
** +-----------------+
** | ramdisk         | m pages
** +-----------------+
** | second stage    | o pages
** +-----------------+
**
** n = (kernel_size + page_size - 1) / page_size
** m = (ramdisk_size + page_size - 1) / page_size
** o = (second_size + page_size - 1) / page_size
**
** 0. all entities are page_size aligned in flash
** 1. kernel and ramdisk are required (size != 0)
** 2. second is optional (second_size == 0 -> no second)
** 3. load each element (kernel, ramdisk, second) at
**    the specified physical address (kernel_addr, etc)
** 4. prepare tags at tag_addr.  kernel_args[] is
**    appended to the kernel commandline in the tags.
** 5. r0 = 0, r1 = MACHINE_TYPE, r2 = tags_addr
** 6. if second_size != 0: jump to second_addr
**    else: jump to kernel_addr
*/
"""

BOOT_MAGIC = "ANDROID!"
BOOT_MAGIC_SIZE = 8
BOOT_NAME_SIZE = 16
BOOT_ARGS_SIZE = 512
BOOT_EXTRA_ARGS_SIZE = 1024


def read_in_format(fmt, f):
    """
    return a tuple of size and value
    """
    """
    # byte order
    Character   Byte order  Size    Alignment
    @   native  native  native
    =   native  standard    none
    <   little-endian   standard    none
    >   big-endian  standard    none
    !   network (= big-endian)  standard    none

     # Map well-known type names into struct format characters.
    typeNames = {
        'int8'   :'b',
        'uint8'  :'B',
        'int16'  :'h',
        'uint16' :'H',
        'int32'  :'i',
        'uint32' :'I',
        'int64'  :'q',
        'uint64' :'Q',
        'float'  :'f',
        'double' :'d',
        'char'   :'s'}

    A format character may be preceded by an integral repeat count. For example, the format string '4h' means exactly the same as 'hhhh'.


    Whitespace characters between formats are ignored; a count and its format must not contain whitespace though.


    For the 's' format character, the count is interpreted as the size of the string, not a repeat count like for the other format characters; for example, '10s' means a single 10-byte string, while '10c' means 10 characters.
    """

    size = struct.calcsize(fmt)
    buf = f.read(size)
    # The result is a tuple even if it contains exactly one item.
    val = struct.unpack_from(fmt, buf)
    if fmt[1] < '0' or fmt[1] > '9':
        val = val[0]
    return (size, val)


def read_page(index, size, f):
    f.seek(index * size)
    return f.read(size)


def read_next_page(size, f):
    return f.read(size)


def print_header(bootimg, args):

    header = {}
    total = 0
    with open(bootimg, 'rb') as f:
        #     uint8_t magic[BOOT_MAGIC_SIZE];
        fmt = '<8c'
        size, magic = read_in_format(fmt, f)
        if args.header:
            print >> sys.stderr, size, magic
        header['magic'] = magic
        total += size

        # uint32_t kernel_size;  /* size in bytes */
        fmt = '<I'
        (size, val) = read_in_format(fmt, f)
        if args.header:
            print >> sys.stderr, 'kernel_size', size, val, hex(val)
        header['kernel_size'] = val
        total += size

        # uint32_t kernel_addr;  /* physical load addr */
        fmt = '<I'
        size, val = read_in_format(fmt, f)
        if args.header:
            print >> sys.stderr, size, val, hex(val)
        header['kernel_addr'] = val
        total += size

        # uint32_t ramdisk_size; /* size in bytes */
        fmt = '<I'
        size, val = read_in_format(fmt, f)
        if args.header:
            print >> sys.stderr, 'ramdisk_size', size, val, hex(val)
        header['ramdisk_size'] = val
        total += size

        # uint32_t ramdisk_addr; /* physical load addr */
        fmt = '<I'
        size, val = read_in_format(fmt, f)
        if args.header:
            print >> sys.stderr, size, val, hex(val)
        header['ramdisk_addr'] = val
        total += size

        # uint32_t second_size;  /* size in bytes */
        fmt = '<I'
        size, val = read_in_format(fmt, f)
        if args.header:
            print >> sys.stderr, size, val, hex(val)
        header['second_size'] = val
        total += size

        # uint32_t second_addr;  /* physical load addr */
        fmt = '<I'
        size, val = read_in_format(fmt, f)
        if args.header:
            print >> sys.stderr, size, val, hex(val)
        header['second_addr'] = val
        total += size

        # uint32_t tags_addr;    /* physical addr for kernel tags */
        fmt = '<I'
        size, val = read_in_format(fmt, f)
        if args.header:
            print >> sys.stderr, 'tags_addr', size, val, hex(val)
        header['tags_addr'] = val
        total += size

        # uint32_t page_size;    /* flash page size we assume */
        fmt = '<I'
        size, val = read_in_format(fmt, f)
        if args.header:
            print >> sys.stderr, 'page_size', size, val, hex(val)
        header['page_size'] = val
        total += size

        # uint32_t unused;       /* reserved for future expansion: MUST be 0 */
        fmt = '<I'
        size, val = read_in_format(fmt, f)
        if args.header:
            print >> sys.stderr, size, val, hex(val)
        header['unused'] = val
        total += size

        # /* operating system version and security patch level; for
        #  * version "A.B.C" and patch level "Y-M-D":
        #  * ver = A << 14 | B << 7 | C         (7 bits for each of A, B, C)
        #  * lvl = ((Y - 2000) & 127) << 4 | M  (7 bits for Y, 4 bits for M)
        #  * os_version = ver << 11 | lvl */
        # uint32_t os_version;
        fmt = '<I'
        size, val = read_in_format(fmt, f)
        if args.header:
            print >> sys.stderr, size, val, hex(val)
        header['os_version'] = val
        total += size

        # uint8_t name[BOOT_NAME_SIZE]; /* asciiz product name */
        fmt = '<16s'
        size, val = read_in_format(fmt, f)
        if args.header:
            print >> sys.stderr, size, val
        header['name'] = val
        total += size

        # uint8_t cmdline[BOOT_ARGS_SIZE];
        fmt = '<512s'
        size, val = read_in_format(fmt, f)
        if args.header:
            print >> sys.stderr, size, val
        header['cmdline'] = val
        total += size

        # uint32_t id[8]; /* timestamp / checksum / sha1 / etc */
        fmt = '<8I'
        size, val = read_in_format(fmt, f)
        if args.header:
            print >> sys.stderr, size, val
        header['id'] = val
        total += size

        # /* Supplemental command line data; kept here to maintain
        #  * binary compatibility with older versions of mkbootimg */
        # uint8_t extra_cmdline[BOOT_EXTRA_ARGS_SIZE];
        fmt = '<1024s'
        size, val = read_in_format(fmt, f)
        if args.header:
            print >> sys.stderr, size, val
        header['extra_cmdline'] = val
        total += size
    print >> sys.stderr, 'total', total
    return header


def output_kernel(bootimg, args):
    """
    ** +-----------------+
    ** | boot header     | 1 page
    ** +-----------------+
    ** | kernel          | n pages
    ** +-----------------+
    ** | ramdisk         | m pages
    ** +-----------------+
    ** | second stage    | o pages
    ** +-----------------+
    **
    ** n = (kernel_size + page_size - 1) / page_size
    ** m = (ramdisk_size + page_size - 1) / page_size
    ** o = (second_size + page_size - 1) / page_size
    **
    """
    header = print_header(bootimg, args)
    PAGE_SIZE = header['page_size']
    KERNEL_SIZE = header['kernel_size']
    print >> sys.stderr, 'kernel', KERNEL_SIZE
    # n = (KERNEL_SIZE + PAGE_SIZE - 1) / PAGE_SIZE
    with open(bootimg, 'rt') as f:
        f.seek(1 * PAGE_SIZE)
        sys.stdout.write(f.read(KERNEL_SIZE))


def output_ramdisk(bootimg, args):
    header = print_header(bootimg, args)
    PAGE_SIZE = header['page_size']
    # KERNEL_SIZE = header['kernel_size']
    RAMDISK_SIZE = header['ramdisk_size']
    n = (header['kernel_size'] + PAGE_SIZE - 1) / PAGE_SIZE
    # m = (RAMDISK_SIZE + PAGE_SIZE - 1) / PAGE_SIZE
    print >> sys.stderr, 'ramdisk', RAMDISK_SIZE
    with open(bootimg, 'rt') as f:
        f.seek((1 + n) * PAGE_SIZE)
        sys.stdout.write(f.read(RAMDISK_SIZE))


def main(argv=sys.argv):
    parser = argparse.ArgumentParser(description='boot.img manipulation tool')
    parser.add_argument(
        '--header', action='store_true', dest='header', default=False,
        help='print header')
    parser.add_argument(
        '--ramdisk', action='store_true', dest='ramdisk', default=False,
        help='output ramdisk')
    parser.add_argument(
        '--kernel', action='store_true', dest='kernel', default=False,
        help='output kernel')
    parser.add_argument('bootimg', default='boot.img', help='boot.img file')
    args = parser.parse_args(argv[1:])
    if not os.path.exists(args.bootimg):
        parser.print_help()
        return -1
    if args.header:
        print_header(args.bootimg, args)
    if args.kernel:
        output_kernel(args.bootimg, args)
    if args.ramdisk:
        output_ramdisk(args.bootimg, args)


if __name__ == '__main__':
    sys.exit(main(sys.argv))
