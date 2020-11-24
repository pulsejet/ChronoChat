#!/usr/bin/env bash
set -ex

if [[ $JOB_NAME != *"limited-build" ]]; then
    # Build in release mode with tests and without precompiled headers
    ./waf --color=yes configure --with-tests --without-pch
    ./waf --color=yes build -j$WAF_JOBS

    # Cleanup
    ./waf --color=yes distclean

    # Build in release mode without tests, but with "other tests"
    ./waf --color=yes configure --with-other-tests $PCH
    ./waf --color=yes build -j$WAF_JOBS

    # Cleanup
    ./waf --color=yes distclean
fi

# Build in debug mode with tests
./waf --color=yes configure --debug --with-tests
./waf --color=yes build -j$WAF_JOBS

# (tests will be run against the debug version)
