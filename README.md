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

# Using libkqtime

## Instrumenting the Application

Using libkqtime in your application is relatively straightforward. There are four main steps:

 + Initialize Library Resources
 + Regsiter Sockets
 + Deregister Sockets
 + Free Library Resources

The library is initialized with `kqtime_new`. Then, the application manages the sockets that the library should measure by calling `kqtime_register` and `kqtime_deregister`. When finished, the library resources are freed with `kqtime_free`.

The `kqtime_new` function takes a filepath as an argument. It logs the kernel statistics to a file of that name. If the filepath ends in `.gz`, then the file will be compressed inline with zlib. For example, calling

```
kqtime_new("kqtime.log.gz", 1, 1, 1)
```

would produce a file `kqtime.log.gz` in the current directory containing the logged statistics.

A socket name (an arbitrary string) may be passed into libqtime when registering a socket with `kqtime_register`. libkqtime will append this string to every log message pertaining to the registered socket.

## Visualizing Results

Use the scripts in the `tools` directory to transform the data collected in the log file by libkqtime into graphs:

```
zcat kqtime.log.gz | xz -T 6 > kqtime.log.xz
xzcat kqtime.log.xz | pypy tools/parse-kqtime.py | xz -T 6 > kqtime.dat.xz
xzcat kqtime.dat.xz | python tools/plot-kqtime.py
```

Then check for the `.pdf` files in the current directory.

# Examples

## Tor+libkqtime

### Instrument Tor

See [this branch](https://github.com/robgjansen/torclone/tree/kqtime) for the modifications made to Tor to make use of libkqtime.

```
git clone https://github.com/robgjansen/torclone.git
cd torclone
git checkout -b kqtime origin/kqtime
```

This gives a new config option that can be used like: `KQTimeLogFile "/home/user/tor/kqtime.log.gz"`. This filepath will be passed into the `kqtime_new` function, and statistics will be collected for all sockets created by Tor.

### Build, Link, and Run Tor

Assuming libkqtime was installed to `/home/user/.local`, and using the torclone branch from above, Tor should be compiled as follows:

```
CFLAGS="-I/home/user/.local/include" LDFLAGS="-L/home/user/.local/lib" LIBS="-lkqtime" ./configure --disable-asciidoc
```

### Run Tor with libkqtime

```
sudo LD_LIBRARY_PATH=/home/user/.local/lib/ LD_PRELOAD=/home/user/.local/lib/libkqtime-preload.so ./src/or/tor
```

