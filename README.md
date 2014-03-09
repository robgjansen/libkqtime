# libkqtime

A library that tracks the queuing time of bytes traveling through the kernel

# Dependencies

+ cmake
+ glib
+ zlib
+ pcap

## Fedora

```
sudo yum install cmake glib2 glib2-devel zlib zlib-devel libpcap libpcap-devel
```

## Ubuntu

```
sudo apt-get install cmake libglib2.0 libglib2.0-dev zlib1g zlib1g-dev libpcap-dev
```

# Quick Setup

An out of source build, and local install is recommended:

```
cd libkqtime
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/home/user/.local
make
make install
```

Build options are specified as `-D<option>`:

 + `CMAKE_BUILD_TYPE=Debug` - enable verbose debug messages
 + `CMAKE_INSTALL_PREFIX=path/to/install` - installation root path

# For More Information...

... see the `doc` directory

