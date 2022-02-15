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

. "C:/Windows/Temp/setup_windows_functions.ps1"

$env:PYTHONDONTWRITEBYTECODE = "disable"

# speed setup process up
setup_disable_defender_until_reboot
setup_disable_updates_until_reboot

setup_hardening
setup_theme
setup_disk
setup_privacy
setup_disable_features_services

if ($env:SETUP_KEYMAP) {
    Set-WinUserLanguageList -LanguageList "$env:SETUP_KEYMAP" -Force
}

if ($env:SETUP_VMACHINE) {
  setup_vm
}

if ($env:SETUP_CHOCO_PACKAGES) {
  setup_install_choco
}

if ($env:SETUP_CYGWIN_PACKAGES) {
  setup_install_cygwin
}

setup_cleanup_fast

if ($env:SETUP_CLEAN -eq "true" -or $env:SETUP_CLEAN -eq "no_universal_apps") {
  setup_cleanup
}

setup_clean_path
