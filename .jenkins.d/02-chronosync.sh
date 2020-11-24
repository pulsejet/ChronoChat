#!/usr/bin/env bash
set -x
set -e

sudo rm -Rf /usr/local/include/ChronoSync
sudo rm -f /usr/local/lib/libChronoSync*
sudo rm -f /usr/local/lib/pkgconfig/ChronoSync*

# Update ChronoSync
git clone git://github.com/named-data/ChronoSync

pushd ChronoSync >/dev/null

./waf --color=yes configure
./waf --color=yes build -j$WAF_JOBS
sudo_preserve_env PATH -- ./waf --color=yes install

popd >/dev/null

if has Linux $NODE_LABELS; then
    sudo ldconfig
fi
