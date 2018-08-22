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

set -eu

DEBIAN_FRONTEND="noninteractive"
export DEBIAN_FRONTEND

. /tmp/setup_debian_functions.sh

setup_tmp
setup_sources
setup_locale


#default settings
SETUP_VMACHINE="${SETUP_VMACHINE:-false}"
SETUP_PACKAGES="${SETUP_PACKAGES:-}"
SETUP_CLEAN="${SETUP_CLEAN:-false}"

if [ "$SETUP_VMACHINE" != "false" ]; then
  setup_vm
  setup_disable_sudo_pwd
fi

if [ -n "${SETUP_DE:-}" ] ; then
  setup_de
  if [ "$SETUP_VMACHINE" != "false" ]; then
    setup_lightdm_autologin
  fi
  setup_tui_tools
fi

if [ -n "${SETUP_PACKAGES:-}" ]; then
  setup_additional_packages
fi

setup_cleanup_fast

if [ "$SETUP_CLEAN" = "true" ]; then
  setup_cleanup
fi
