#!/bin/sh

# Copyright (c) 2018 Federico Kircheis

# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


# TODO:
#	* add readme/help (check how getopt works)
#	* add option for specifying debian (ubuntu) distribution, architecture and revision
#	* split script, might simply want to have a chroot env...

set -eu

# requires: debootstrap docker.io

tmpdir="$(mktemp --dry-run "/tmp/XXXXXX")/"
if [ ${DOCK_CHROOT_DIR:-} ]; then
  tmpdir="${DOCK_CHROOT_DIR}"
fi
mkdir "$tmpdir"

printf 'temporary folder: %s\n' "$tmpdir"

cachedir="${XDG_CACHE_HOME:-$HOME/.cache}/deb"
if [ ${DOCK_PACKAGE_CACHE:-} ]; then
  cachedir="$DOC_PACKAGE_KCACHE"
fi
mkdir -p "$cachedir"

imagename="${DOCK_IMAGE_NAME:-minbasedebian}"


if [ ! -f setup_debian_functions.sh ]; then
  printf 'Missing setup_debian_functions.sh\n';
  return 1
fi

sudo debootstrap \
  --arch amd64 \
  --variant=minbase \
  --cache-dir="$cachedir" \
  unstable \
  "$tmpdir" \
  https://deb.debian.org/debian/

cp setup_debian_functions.sh "$tmpdir/tmp"

# set LC_ALL to avoid issues with locale on host that are possibly not available on the chrooted environment
sudo chroot "$tmpdir" sh -c 'LC_ALL="C" . /tmp/setup_debian_functions.sh && setup_cleanup_aggressive'

# image size is approximately  60-70 mb, not as small as alpine (5mb apparently), but it's a standard (and crippled) debian system with access to it's repo!
# and we know that the base image contains only data from the debian project

sudo su -c "tar -C $tmpdir -c . | docker import - $imagename"

#docker images
#docker run --rm --interactive --tty minidebian bash

printf 'chroot environment: %s\n' "$tmpdir"
printf 'docker image: %s (you can test it with "docker run --rm --interactive --tty %s bash"\n' "$imagename" "$imagename"
