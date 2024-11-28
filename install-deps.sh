#!/bin/bash
##########################################################################################
#Copyright (c) KylinSoft Co., Ltd. 2024-2025.All rights reserved.
#storprototrace is licensed under the Mulan PSL v2.
#You can use this software according to the terms and conditions of the Mulan PSL v2.
#You may obtain a copy of Mulan PSL v2 at:
#	 http://license.coscl.org.cn/MulanPSL2
#THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
#EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
#MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
#See the Mulan PSL v2 for more details.
###########################################################################################

set -e

echo "installing dependencies"

if [[ $EUID -ne 0 ]]; then
  echo "This script should be run as root."
  exit 1
fi
if [ -f "/etc/os-release" ]; then
  . /etc/os-release
elif [ -f "/etc/arch-release" ]; then
  export ID=arch
else
  echo "/etc/os-release missing."
  exit 1
fi

deb_deps=(
  clang
  libbpf
  libbpf-devel
  bpftool
  make
  cmake
  gtest-devel
)

# Add support for centos/rhel/openEuler/suse
rpm_deps=(
  clang
  libbpf
  libbpf-devel
  bpftool
  make
)

case "$ID" in
  ubuntu | debian)
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${deb_deps[@]}"
    exit $?
    ;;
  centos | rhel | fedora | openEuler | suse | culinux)
    yum install -y "${rpm_deps[@]}"
    exit $?
    ;;
  *)
    echo "Please help us make the script better by sending patches with your OS $ID"
    exit 1
    ;;
esac
