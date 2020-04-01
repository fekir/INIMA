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
  sed --in-place "/^deb cdrom:/s/^/#/" /etc/apt/sources.list

  # While it is a good idea to have such service, it causes to much trouble when automating package management
  # https://wiki.debian.org/UnattendedUpgrades
  apt-get --assume-yes purge unattended-upgrades >/dev/null || true

  apt-get update >/dev/null
  apt-get --no-install-recommends --assume-yes upgrade >/dev/null
}

# would be nice to be able to set them from cli instead of creating config files
setup_installer_minimal(){
  #https://wiki.ubuntu.com/ReducingDiskFootprint#Documentation
  {
    printf 'path-exclude /usr/share/doc/*\n';
    printf 'path-exclude /usr/share/doc-base/*\n';
    printf 'path-exclude /usr/share/common-licenses/*\n';
    # unless redistribuiting the machine, we do not need to keep copyright files
    printf 'path-include /usr/share/doc/*/copyright';
    printf 'path-exclude /usr/share/man/*';
    printf 'path-exclude /usr/share/man-db/*';
    printf 'path-exclude /usr/share/groff/*';
    printf 'path-exclude /usr/share/info/*';
    printf 'path-exclude /usr/share/linda/*';
    printf 'path-exclude /usr/share/lintian/*';
    printf 'path-exclude /usr/share/locale/*';
    printf 'path-exclude /usr/lib/modules/*/kernel/drivers/net/wireless/*';
  }>"/etc/dpkg/dpkg.cfg.d/01-no-doc-license-locale"

  {
    printf 'Acquire::GzipIndexes "true";printf '
    printf 'Acquire::CompressionTypes::Order:: "gz";printf '
  }>"/etc/apt/apt.conf.d/00-compress-indexes"
}

setup_lightdm_autologin(){
  # https://wiki.ubuntu.com/LightDM
  if [ ! -d '/etc/lightdm/' ]; then
    return
  fi
  mkdir '/etc/lightdm/lightdm.conf.d/' >/dev/null
  #lightdmconf='/usr/share/lightdm/lightdm.conf.d/60-lightdm-gtk-greeter.conf'
  lightdmconf='/etc/lightdm/lightdm.conf.d/99-autologin.conf'
  grep --quiet --fixed-strings '[SeatDefaults]' "$lightdmconf" 2>/dev/null || printf '[SeatDefaults]\n' >> "$lightdmconf"
#  printf "autologin-user=%s\n" "$USER" >> /usr/share/lightdm/lightdm.conf.d/60-lightdm-gtk-greeter.conf
# hard-coded username, no better idea...
  SSH_USERNAME=${SSH_USERNAME:-vagrant}
  grep --quiet --fixed-strings 'autologin-user' "$lightdmconf" 2>/dev/null || printf 'autologin-user=%s\n' "$SSH_USERNAME" >> "$lightdmconf"
}

setup_de(){
  #if dpkg --list "task-${SETUP_DE}-desktop" >/dev/null; then # FIXME: did not work on naked system
    apt-get --no-install-recommends --assume-yes install "task-${SETUP_DE}-desktop"
  #fi

  if [ "${SETUP_DE#mate}" != "$SETUP_DE" ]; then
    apt-get --no-install-recommends --assume-yes install caja-open-terminal pluma eom atril >/dev/null
    update-alternatives --set x-terminal-emulator /usr/bin/mate-terminal.wrapper >/dev/null

    # see https://github.com/mate-desktop/mate-panel/issues/57
    # otherwise some shortcuts in the menu, like mc, vim, htop, ... are broken since they use xterm directly (onl when using mate)...
    apt-get --assume-yes purge xterm >/dev/null
    [ -f /usr/bin/xterm ] || ln -s /usr/bin/x-terminal-emulator /usr/bin/xterm
  elif [ "${SETUP_DE#lxde}" != "$SETUP_DE" ]; then
    apt-get --no-install-recommends --assume-yes install obconf >/dev/null
    update-alternatives --set x-terminal-emulator /usr/bin/lxterminal >/dev/null
  elif [ "${SETUP_DE#lxqt}" != "$SETUP_DE" ]; then
    update-alternatives --set x-terminal-emulator /usr/bin/qterminal >/dev/null

    # see explanation in mate
    apt-get --assume-yes purge xterm >/dev/null
    [ -f /usr/bin/xterm ] || ln -s /usr/bin/x-terminal-emulator /usr/bin/xterm
  fi

  # FIXME: add gnome, kde, enlightenment, ...

  apt-get --no-install-recommends --assume-yes install apt-xapian-index synaptic xdg-user-dirs >/dev/null

  apt-get --no-install-recommends --assume-yes install firefox-esr >/dev/null
  update-alternatives --set x-www-browser /usr/bin/firefox-esr 2>/dev/null || true
  update-alternatives --set x-www-browser /usr/bin/firefox 2>/dev/null || true
  update-alternatives --set gnome-www-browser /usr/bin/firefox-esr 2>/dev/null || true
  update-alternatives --set gnome-www-browser /usr/bin/firefox 2>/dev/null || true

  apt-get --no-install-recommends --assume-yes install pidgin thunderbird >/dev/null
}

# TIP: change temp keyboard temp from console: "setxkbmap it" (or de, whatever)
setup_locale(){
  # setup keymap
  SETUP_KEYMAP="${SETUP_KEYMAP:-}"
  if [ -n "$SETUP_KEYMAP" ] ; then
    sudo sed -i 's/XKBLAYOUT=\"\w*"/XKBLAYOUT=\"'$SETUP_KEYMAP'\"/g' /etc/default/keyboard
  fi

  # setup monetary and time format
  UPDATE_LOCALE_PARAM_TIME=""
  # change system language, time format, monetary format
  SETUP_LC_TIME="${SETUP_LC_TIME:-}"
  if [ -n "$SETUP_LC_TIME" ] ; then
    sed -i -e "s/^#\s*$SETUP_LC_TIME.UTF-8\s*UTF-8/$SETUP_LC_TIME.UTF-8 UTF-8/g" /etc/locale.gen
    UPDATE_LOCALE_PARAM_TIME="LC_TIME=$SETUP_LC_TIME.UTF-8"
  fi

  UPDATE_LOCALE_PARAM_MONETARY=""
  SETUP_LC_MONETARY="${SETUP_LC_MONETARY:-it_IT}"
  if [ -n "$SETUP_LC_MONETARY" ] ; then
    sed -i -e "s/^#\s*$SETUP_LC_MONETARY.UTF-8\s*UTF-8/$SETUP_LC_MONETARY.UTF-8 UTF-8/g" /etc/locale.gen
    UPDATE_LOCALE_PARAM_MONETARY="LC_MONETARY=$SETUP_LC_MONETARY.UTF-8"
  fi

  locale-gen
  update-locale "$UPDATE_LOCALE_PARAM_TIME" "$UPDATE_LOCALE_PARAM_MONETARY"

  # set selection before installing, do not use it for changing existing configuration
  lang_not_to_purge='de, en, it'
  printf 'localepurge localepurge/nopurge multiselect %s\n' "$lang_not_to_purge" | debconf-set-selections
  printf 'localepurge localepurge/showfreedspace boolean false' | debconf-set-selections
  DEBIAN_FRONTEND=noninteractive apt-get --no-install-recommends --assume-yes install localepurge hardlink>/dev/null
  localepurge

  # FIXME: add dictionaries - probably easier to list packages with the others
  #apt-get --no-install-recommends --assume-yes install hunspell-de-de hunspell-en-us hunspell-it >/dev/null
  #apt-get --no-install-recommends --assume-yes install aspell-de aspell-en aspell-it >/dev/null

  # timezone
  if [ -n "${SETUP_TIMEZONE:-}" ] ; then
    zone="${SETUP_TIMEZONE#*/}"
    area="${SETUP_TIMEZONE%?$zone}"
    mv /etc/timezone /etc/timezone.back
    mv /etc/localtime /etc/localtime.back
    printf 'tzdata tzdata/Areas select %s\ntzdata tzdata/Zones/%s select %s\n' "$area" "$area" "$zone" | sudo debconf-set-selections
    sudo dpkg-reconfigure -f noninteractive tzdata || (mv /etc/timezone.back /etc/timezone; mv /etc/localtime.back /etc/localtime; exit 1)
    rm /etc/timezone.back /etc/localtime.back
  fi
}

setup_vm(){
  i_setup_reduce_grub_timeout_to_0

  SSH_USERNAME=${SSH_USERNAME:-vagrant}

  if [ "${PACKER_BUILDER_TYPE#virtualbox}" != "$PACKER_BUILDER_TYPE" ]; then
    apt-get install --no-install-recommends --assume-yes "linux-headers-$(uname -r)" build-essential perl >/dev/null
    apt-get install --no-install-recommends --assume-yes dkms >/dev/null
    mount -o loop "/tmp/VBoxGuestAdditions.iso" /mnt >/dev/null
    # https://stackoverflow.com/questions/25434139/vboxlinuxadditions-run-never-exits-with-0
    sh /mnt/VBoxLinuxAdditions.run || true
    umount /mnt # fixme: remove also on failure of VBoxLinuxAdditions
    adduser "${SSH_USERNAME}" vboxsf
  elif [ "${PACKER_BUILDER_TYPE#vmware}" != "$PACKER_BUILDER_TYPE" ]; then
    #mount -o loop /tmp/VMWareTools.iso /mnt
    #tar zxf "/mnt/VMwareTools-*.tar.gz" -C /tmp
    #umount /mnt
    #/tmp/vmware-tools-distrib/vmware-install.pl --default
    #rm -rf "/tmp/vmware-tools-distrib"
    apt-get --assume-yes install open-vm-tools # recomended by VMwareTool installer
    if [ -n "${SETUP_DE:-}" ] ; then :;
      apt-get --assume-yes install open-vm-tools-desktop # recomended by VMwareTool installer
    fi
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

setup_tui_tools(){
  apt-get --assume-yes install tmux zsh bash-completion nano htop iotop nmon tree mc dos2unix lynx powerline >/dev/null

  apt-get --assume-yes install neovim >/dev/null
  apt-get --assume-yes remove vim >/dev/null
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
  apt-get --assume-yes autoremove --purge >/dev/null;
  apt-get --assume-yes clean >/dev/null;
  apt-get --assume-yes autoclean >/dev/null;
  dpkg -l | awk '/^rc/ {printf( "%s%c", $2, 0 )}' | xargs --null --no-run-if-empty dpkg --purge;
  localepurge || true;

  printf 'clean history, error reports and cache\n';
  rm -f "/root/.*hist*" || true;
  rm -f "/home/$SSH_USERNAME/.*hist*" || true;
  rm -f "/home/$SUDO_USER/.*hist*" || true;
  rm -f "$HOME/.*hist*" || true;

  rm -f "/root/.xsessions-errors" || true;
  rm -f "/home/$SSH_USERNAME/.xsessions-errors*" || true;
  rm -f "/home/$SUDO_USER/.xsessions-errors*" || true;
  rm -f "$HOME/.xsessions-errors*" || true;

  rm -rf "/root/.cache" || true;
  rm -rf "/home/$SSH_USERNAME/.cache*" || true;
  rm -rf "/home/$SUDO_USER/.cache*" || true;
  rm -rf "$HOME/.cache" || true;

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


  printf 'Remove temporary files\n'; # should be done at the end to avoid breaking running programs as much as possible
  rm -rf "/tmp/*" || true;
  rm -rf "/var/tmp/*" || true;
  rm -rf "/var/lib/apt/lists/" || true;
  #find /var/lib/apt/lists -type f -exec rm {} \;
  rm -rf "/var/cache" || true;
  mkdir -p "/var/cache/apt/archives/partial";
}

setup_cleanup(){
  #apt-get --no-install-recommends --assume-yes -q install zerofree hardlink>/dev/null
  setup_cleanup_fast
  #telinit 1
  #mount -o ro,remount /
  #zerofree -v /

  # FIXME:
  # * should do on all partitions
  #   https://unix.stackexchange.com/questions/24182/how-to-get-the-complete-and-exact-list-of-mounted-filesystems-in-linux
  # * does not overwrite everything
  # * is very slow, try zerofree again (https://sitano.github.io/2014/08/12/upd-vagrant-box/)
  cat /dev/zero>/EMPTY || true;
  sync;
  rm -f /EMPTY;
}

setup_cleanup_aggressive(){
  setup_cleanup_fast

  # will also remove copyright, you'll probably be unable to redistribute the installed debian distribution
  printf "aggressive removal of data\n"
  rm -f "/etc/dpkg/dpkg.cfg.d/01-no-doc-license-locale"; # might make sense to leave...
  rm -f "/etc/apt/apt.conf.d/00-compress-indexes"; # created by us, seems to slow down some programs, so it OK to not set it by default

  rm -rf /usr/local/share/man/;

  # locale should be already handled by localepurge
  #rm -rf /usr/share/locale/ check effetive size, and check localepurge
  #find /usr/share/i18n/locales ! -name 'C' -type f -exec rm {} +
  rm -rf /usr/share/bug/;
  rm -rf /usr/share/common-licenses/;
  rm -rf /usr/share/doc/;
  rm -rf /usr/share/doc-base/;
  find /usr/share -type d -name doc  -exec rm -rf {} +;
  rm -rf /usr/share/gtk-doc;
  find /usr/share -type d -name help -exec rm -rf {} +;
  rm -rf /usr/share/lintian/;
  rm -rf /usr/share/man/;
  rm -rf /usr/share/man-db/;
  find /usr/share -type d -name man  -exec rm -rf {} +;
  # removing entirely causes issues.. would be nice if there is something like localepurge for it... hardlink did not make any difference
  #rm -rf /usr/share/zoneinfo/;

  hardlink /usr/share/; # might break something when upgrading, but when there be dragons when removing/"editing" data from /usr/share 

  rm -rf /var/lib/apt/lists/;

  # those needs testing
  #rm -rf /var/lib/dpkg/info;
  #mkdir -p /var/lib/dpkg/info; # when installing package, dpkg complains... not nice
}
