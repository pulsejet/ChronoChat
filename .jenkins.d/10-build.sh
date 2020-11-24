#!/usr/bin/env bash
set -ex

git submodule sync
git submodule update --init

if [[ $JOB_NAME != *"limited-build" ]]; then
    # Build in release mode with tests
    ./waf --color=yes configure --with-tests
    ./waf --color=yes build -j$WAF_JOBS

    # Cleanup
    ./waf --color=yes distclean

    # Build in release mode without tests
    ./waf --color=yes configure
    ./waf --color=yes build -j$WAF_JOBS

    # Cleanup
    ./waf --color=yes distclean
fi

# Build in debug mode with tests
./waf --color=yes configure --debug --with-tests
./waf --color=yes build -j$WAF_JOBS

# (tests will be run against the debug version)

# Install
sudo_preserve_env PATH -- ./waf --color=yes install
