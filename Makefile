CFLAGS	= -O2 -Wall -Wextra -Wno-deprecated-declarations \
	  $(shell pkg-config --cflags libusb-1.0 libcrypto)
LDFLAGS	= $(shell pkg-config --libs libusb-1.0 libcrypto)
OBJS	= rkusbboot.o
PROGRAM	= rkusbboot

$(PROGRAM): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

.PHONY: clean
clean:
	$(RM) $(PROGRAM) $(OBJS)
