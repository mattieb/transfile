TARGET = transfile
CFLAGS = -DTFTP_DEBUG
INCLUDES = sha1.h tftp.h
SOURCES = sha1.c tftp.c main.c

$(TARGET): $(INCLUDES) $(SOURCES)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES)

link:
	rm -f {sha1,tftp}.*
	ln -s ../source/{sha1,tftp}.* .

clean:
	rm -f $(TARGET)

