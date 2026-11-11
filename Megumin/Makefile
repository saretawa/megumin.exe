# Megumin BYOVD PPL Removal + Credential Extraction (MinGW cross-compile)

CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -Wall -Wextra -O2 -Iinclude -municode
LDFLAGS = -ladvapi32 -lws2_32 -lpsapi
TARGET  = megumin.exe

SRCS    = src/main.c src/gio.c src/eprocess.c src/dump_remote.c src/dump_direct.c
OBJS    = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET) src/*.o