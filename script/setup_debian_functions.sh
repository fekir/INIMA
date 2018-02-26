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

setup_tmp(){
:
# unfortunately some files (like guest additions, file copied by file provider ...) may already be there
# When remounting, they are still there, but won't be reachable
# unless we find a way to copy them over, it will not be possible to use this trick to prevent writing bytes, that will get deleted, but take space unless if overwriting with 0

#if [ $(free -m | awk '/^Mem:/{print $2}') -gt 2048 ] ; then
#  mount -o mode=1777,nosuid,nodev -t tmpfs tmpfs /tmp
#fi
}

setup_sources(){
  sed -i "/^deb cdrom:/s/^/#/" /etc/apt/sources.list

  apt-get update >/dev/null
  apt-get --no-install-recommends --assume-yes upgrade >/dev/null
  apt-get --no-install-recommends --assume-yes -q install aptitude >/dev/null
}

setup_mate(){
  # no redirect since this command will take long
  apt-get --no-install-recommends --assume-yes install task-mate-desktop
  apt-get --no-install-recommends --assume-yes install caja-open-terminal pluma eom atril >/dev/null
  update-alternatives --set x-terminal-emulator /usr/bin/mate-terminal.wrapper >/dev/null
  apt-get --assume-yes purge xterm >/dev/null
  # see https://github.com/mate-desktop/mate-panel/issues/57
  # otherwise some shortcuts in the menu, like mc, vim, htop, ... are broken since they use xterm directly...
  [ -f /usr/bin/xterm ] || ln -s /usr/bin/x-terminal-emulator /usr/bin/xterm

  apt-get --no-install-recommends --assume-yes install apt-xapian-index synaptic >/dev/null

  apt-get --no-install-recommends --assume-yes install xdg-user-dirs >/dev/null
}

setup_mate_autologin(){
  lightgdmconf='/usr/share/lightdm/lightdm.conf.d/60-lightdm-gtk-greeter.conf'
  grep -q -F '[SeatDefaults]' "$lightgdmconf" 2>/dev/null || printf '[SeatDefaults]\n' >> "$lightgdmconf"
#  printf "autologin-user=%s\n" "$USER" >> /usr/share/lightdm/lightdm.conf.d/60-lightdm-gtk-greeter.conf
# hard-coded username, no better idea...
  SSH_USERNAME=${SSH_USERNAME:-vagrant}
  printf 'autologin-user=%s\n' "$SSH_USERNAME" >> "$lightgdmconf"
}

setup_language(){
  # set selection before installing, otherwise configuration seems to get lost
  printf 'localepurge localepurge/nopurge multiselect de, en, it\n' | debconf-set-selections
  printf 'localepurge localepurge/showfreedspace boolean false' | debconf-set-selections
  DEBIAN_FRONTEND=noninteractive apt-get --no-install-recommends --assume-yes install localepurge >/dev/null
  localepurge

  # should not be part of a minimal installation
  #apt-get --no-install-recommends --assume-yes install hunspell-de-de hunspell-en-us hunspell-it >/dev/null
  #apt-get --no-install-recommends --assume-yes install aspell-de aspell-en aspell-it >/dev/null

  # set locale and keyboard

  # debconf-get-selections | grep keyboard-configuration
  # debconf-set-selections < file.conf
  #dpkg-reconfigure keyboard-configuration -f noninteractive
  # --> did not work
}

setup_vm(){
  i_setup_reduce_grub_timeout_to_0

  apt-get install --no-install-recommends --assume-yes "linux-headers-$(uname -r)" build-essential perl >/dev/null

  SSH_USERNAME=${SSH_USERNAME:-vagrant}


  if [ "${PACKER_BUILDER_TYPE#virtualbox}" != "$PACKER_BUILDER_TYPE" ]; then
    apt-get install --no-install-recommends --assume-yes dkms >/dev/null
    mount -o loop "/tmp/VBoxGuestAdditions.iso" /mnt >/dev/null
    # https://stackoverflow.com/questions/25434139/vboxlinuxadditions-run-never-exits-with-0
    sh /mnt/VBoxLinuxAdditions.run || true
    umount /mnt # fixme: remove also on failure of VBoxLinuxAdditions
    adduser "${SSH_USERNAME}" vboxsf
  fi

  # disable hibernation
  if rm /etc/initramfs-tools/conf.d/resume >/dev/null; then update-initramfs -u >/dev/null ;fi
}

setup_disable_sudo_pwd(){
  SSH_USERNAME=${SSH_USERNAME:-vagrant}
  printf "$SSH_USERNAME ALL=(ALL) NOPASSWD:ALL\n" > /tmp/sudoers_user
  chmod 0440 /tmp/sudoers_user
  mv /tmp/sudoers_user "/etc/sudoers.d/$SSH_USERNAME"
  # https://askubuntu.com/questions/98006/how-do-i-prevent-policykit-from-asking-for-a-password
}

setup_common_gui_packages(){
  apt-get --no-install-recommends --assume-yes install firefox-esr >/dev/null
  update-alternatives --set x-www-browser /usr/bin/firefox-esr 2>/dev/null || true
  update-alternatives --set x-www-browser /usr/bin/firefox 2>/dev/null || true
  update-alternatives --set gnome-www-browser /usr/bin/firefox-esr 2>/dev/null || true
  update-alternatives --set gnome-www-browser /usr/bin/firefox 2>/dev/null || true

  apt-get --no-install-recommends --assume-yes install pidgin thunderbird >/dev/null
}

setup_tui_tools(){
  apt-get --assume-yes install tmux zsh bash-completion nano htop iotop nmon tree mc dos2unix lynx powerline >/dev/null

  apt-get --assume-yes install neovim >/dev/null
  update-alternatives --set editor /usr/bin/nvim 2>/dev/null || true
  update-alternatives --set vimdiff /usr/bin/vimdiff.nvim 2>/dev/null || true
  update-alternatives --set vi /usr/bin/nvim 2>/dev/null || true
  update-alternatives --set vim /usr/bin/nvim 2>/dev/null || true
  update-alternatives --set view /usr/bin/view.nvim 2>/dev/null || true
}

setup_additional_packages() {
  apt-get update >/dev/null
  apt-get --no-install-recommends --assume-yes upgrade >/dev/null
  apt-get --assume-yes install findutils >/dev/null # xargs is located here
  # removing " should be safe since there are no packages that contains spaces
  echo "${SETUP_PACKAGES:-}" | sed 's/,/ /g' | sed 's/"//g' | xargs -r apt-get --no-install-recommends --assume-yes install
}

setup_cpp_dev_tools(){
  apt-get --no-install-recommends --assume-yes install qtcreator cmake cmake-gui cmake-curses-gui cppcheck cppcheck-gui >/dev/null
  apt-get --no-install-recommends --assume-yes install clang clang-tidy clang-format lldb g++ gdb valgrind ninja-build doxygen catch strace >/dev/null
}

setup_dev_tools(){
  apt-get --no-install-recommends --assume-yes install git tig >/dev/null
}

setup_java_dev_tools(){
  apt-get --no-install-recommends --assume-yes install default-jdk gradle maven ant >/dev/null
  apt-get --no-install-recommends --assume-yes install eclipse >/dev/null
}

install_web_dev_tools(){
  apt-get --no-install-recommends --assume-yes install php hugo tidy >/dev/null
}

i_setup_reduce_grub_timeout_to_0(){
  sed -i -e 's/^GRUB_TIMEOUT=.*$/GRUB_TIMEOUT=0/' /etc/default/grub
  update-grub >/dev/null
}

setup_cleanup_fast(){

  SSH_USERNAME=${SSH_USERNAME:-vagrant}
# instead of rm, I should
# https://www.marksanborn.net/security/securely-wipe-a-file-with-dd/
# https://wiki.archlinux.org/index.php/Securely_wipe_disk
# and then rm, in order to regain space, unless setup_cleanup is going to be called
  unset HISTFILE

  printf 'clean packages\n'
  apt-get --assume-yes autoremove --purge >/dev/null
  apt-get --assume-yes clean >/dev/null
  apt-get --assume-yes autoclean >/dev/null
  localepurge || true

  printf 'clean history, error reports and cache\n'
  rm -f "/root/.*hist*" || true
  rm -f "/home/$SSH_USERNAME/.*hist*" || true
  rm -f "/home/$SUDO_USER/.*hist*" || true
  rm -f "$HOME/.*hist*" || true

  rm -f "/root/.xsessions-errors" || true
  rm -f "/home/$SSH_USERNAME/.xsessions-errors*" || true
  rm -f "/home/$SUDO_USER/.xsessions-errors*" || true
  rm -f "$HOME/.xsessions-errors*" || true

  rm -rf "/root/.cache" || true
  rm -rf "/home/$SSH_USERNAME/.cache*" || true
  rm -rf "/home/$SUDO_USER/.cache*" || true
  rm -rf "$HOME/.cache" || true

  printf 'Stop common services that may log and clean all logs\n'
  service crond stop >/dev/null 2>/dev/null || true
  service rsyslog stop >/dev/null 2>/dev/null || true
  service auditd stop >/dev/null 2>/dev/null || true
  systemctl stop systemd-journald.socket >/dev/null 2>/dev/null || true
  systemctl stop systemd-journald.service >/dev/null 2>/dev/null || true
  service network-manager stop >/dev/null 2>/dev/null || true
  killall dhclient >/dev/null 2>/dev/null || true
  swapoff -a || true
  find /var/log -type f | while read -r f; do cat /dev/null > "$f"; done;


  printf 'Remove temporary files\n' # should be done at the end to avoid breaking running programs as much as possible
  rm -rf "/tmp/*" || true
  rm -rf "/var/tmp/*"  || true

}

setup_cleanup(){
  #apt-get --no-install-recommends --assume-yes -q install zerofree >/dev/null
  setup_cleanup_fast
  #telinit 1
  #mount -o ro,remount /
  #zerofree -v /

  # FIXME: should list all partitions
  dd if=/dev/zero of=/EMPTY bs=1M  || true
  rm -f /EMPTY
}