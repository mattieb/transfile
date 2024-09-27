# POSIX test program

This is a test program to run the TFTP code on a POSIX system, where things are a bit more predictable.

## Build

The "link" target will make symbolic links for the sha1 and tftp code:

```
make link
```

This makes sure that any changes made are shared between this program and the Nintendo DS version.

The main target builds the program:

```
make
```

## Running

Change to a directory where you have some files and run the "transfile" program. It will start a TFTP server on port 6969 in the current directory.
