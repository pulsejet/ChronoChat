ChronoChat
==========

ChronoChat is a multiparty chat application that demostrates our synchronization primitive that we call ChronoSync.

Note that after you click to close ChronoChat, it will keep running on your system tray. To restore it to normal size window, you have to click on the system tray icon (normally on the upper right corner of your screen). Clicking on the dock won't work for now and is still on the to-do list (because I'm using qt for gui, not the native Cocoa framework).

## Known Issues
---------------

1. When you switch to a new room, you'll temporarily see yourself in two nodes for a minute or so. It won't affect others, just yourself. Hopefully it's not so disturbing.
2. Sometimes you may not get the most up-to-date chat history.

## For those who want (or is forced to) compile from source code
-----------------------------------------------------------------

### Compilation steps for OSX

1. On Mac, install MacPorts, if not yet installed (http://www.macports.org/), configure [NDN ports repository](http://named-data.net/doc/NFD/current/FAQ.html#how-to-start-using-ndn-macports-repository-on-osx) and install NFD if you don't have it yet. Install the dependencies next.

        sudo port install nfd
        sudo nfd-start
        sudo port install pkgconfig boost qt5-mac

On Ubuntu, configure [NDN PPA repository](http://named-data.net/doc/NFD/current/FAQ.html#how-to-start-using-ndn-ppa-repository-on-ubuntu-linux) and install NFD if you don't have it yet, then install dependencies

        sudo apt-get install nfd
        sudo apt-get install libcrypto++-dev libboost-all-dev qt5-default

2. Configure and install ChronoSync

        git clone git://github.com/named-data/ChronoSync
        cd ChronoSync
        ./waf configure
        ./waf
        sudo ./waf install
        sudo ldconfig  # Ubuntu only
        cd ..

3. Fetch source code

        git clone git://github.com/named-data/ChronoChat

4. Configure and build ChronoChat

        ./waf configure
        ./waf

Congratulations! `build/ChronoChat` is ready to use.  Do not forget to start NFD and configure FIB before using ChronoChat.
For ease of debugging, you can generate trusted identities in your local TPM using `debug-tools/create-cert`.
