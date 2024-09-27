# transfile

A TFTP server for Nintendo DS. Transing <strike>your</strike> my
files since 2009.

## Background

I have _never_ been able to successfully use any FTP server or
similar TCP-based file transfer program with my Nintendo DS systems.
They always stall out almost immediately.

But what _does_ work is something like TFTP.

Sort of.

Back in 2009 and 2010, I was working on a TFTP-based alternative
to the TCP-based file transfer programs, and now, fifteen years
later, I've rewritten and released it here.

However, while testing these programs (which required fishing a
WEP-compatible access point out of storage and connecting it directly
to my computer), I found that even this strategy wasn't perfect.
There are bugs still that may be transfile or may be dependencies;
I'm not sure. It will still crash sometimes, or miswrite files (I
think that might be related to my flash card, maybe?)

I am releasing this code anyway, imperfect as it is. It is better
than the status quo, and I was able to develop it by pushing new
builds using itself. It also works with SD card storage in [modded
DSi systems](https://dsi.cfw.guide) which is super cool.

Please use it, contribute, fork, whatever. I hope it's helpful.

## Building

Builds require [devkitARM](https://devkitpro.org/wiki/devkitARM).
Once installed, building the .nds ROM is simple:

```
make
```

There is also a POSIX harness for the program in the [posix](./posix)
directory which can be used to test the TFTP side of the equation
outside the Nintendo DS environment. See [its README](./posix/README.md)
for details.
