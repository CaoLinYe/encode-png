CC       ?= gcc
CFLAGS   ?= -O2 -Wall -Wextra
LDFLAGS  ?=

TARGET    = encode-png
SRCS      = main.c xxtea.c
OBJS      = $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

%.o: %.c xxtea.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)
