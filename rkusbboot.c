/*-
 * Copyright (c) 2025 FUKAUMI Naoki.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <libusb.h>
#include <openssl/rc4.h> /* XXX */

#include "rkcrc.h"

#define BUF_SIZE	4096
#define VID_ROCKCHIP	0x2207

static RC4_KEY key;
static uint8_t rkrc4[16] = {
	0x7c, 0x4e, 0x03, 0x04, 0x55, 0x05, 0x09, 0x07,
	0x2d, 0x2c, 0x7b, 0x38, 0x17, 0x0d, 0x17, 0x11
};
static uint8_t *buf, *buf_enc;

static void
send_usb(struct libusb_device_handle *h, uint16_t code, FILE *fp) {
	size_t nr;
	uint16_t crc16 = 0xffff;

	while ((nr = fread(buf, 1, BUF_SIZE, fp)) == BUF_SIZE) {
		crc16 = rkcrc16(crc16, buf, BUF_SIZE);
		libusb_control_transfer(h,
		    LIBUSB_REQUEST_TYPE_VENDOR|LIBUSB_RECIPIENT_DEVICE,
		    12, 0, code, buf, BUF_SIZE, 1000);
		usleep(1000);
	}

	if (feof(fp)) {
		if (nr >= BUF_SIZE - 2) {
			libusb_control_transfer(h,
			    LIBUSB_REQUEST_TYPE_VENDOR|LIBUSB_RECIPIENT_DEVICE,
			    12, 0, code, buf, nr, 1000);
			usleep(1000);
			nr = 0;
		}

		crc16 = rkcrc16(crc16, buf, nr);
		buf[nr++] = crc16 >> 8;
		buf[nr++] = crc16 & 0xff;
		libusb_control_transfer(h,
		    LIBUSB_REQUEST_TYPE_VENDOR|LIBUSB_RECIPIENT_DEVICE,
		    12, 0, code, buf, nr, 30000);
	}
}

static void
send_usb_enc(struct libusb_device_handle *h, uint16_t code, FILE *fp) {
	size_t nr;
	uint16_t crc16 = 0xffff;

	RC4_set_key(&key, sizeof(rkrc4), rkrc4);

	while ((nr = fread(buf, 1, BUF_SIZE, fp)) == BUF_SIZE) {
		RC4(&key, BUF_SIZE, buf, buf_enc);
		crc16 = rkcrc16(crc16, buf_enc, BUF_SIZE);
		libusb_control_transfer(h,
		    LIBUSB_REQUEST_TYPE_VENDOR|LIBUSB_RECIPIENT_DEVICE,
		    12, 0, code, buf_enc, BUF_SIZE, 1000);
		usleep(1000);
	}

	if (feof(fp)) {
		RC4(&key, nr, buf, buf_enc);
		if (nr >= BUF_SIZE - 2) {
			libusb_control_transfer(h,
			    LIBUSB_REQUEST_TYPE_VENDOR|LIBUSB_RECIPIENT_DEVICE,
			    12, 0, code, buf_enc, nr, 1000);
			usleep(1000);
			nr = 0;
		}

		crc16 = rkcrc16(crc16, buf_enc, nr);
		buf_enc[nr++] = crc16 >> 8;
		buf_enc[nr++] = crc16 & 0xff;
		libusb_control_transfer(h,
		    LIBUSB_REQUEST_TYPE_VENDOR|LIBUSB_RECIPIENT_DEVICE,
		    12, 0, code, buf_enc, nr, 30000);
	}
}

static int
usbboot(libusb_device *dev, char *tpl, char *spl, uint16_t pid) {
	struct libusb_device_handle *dev_handle;
	FILE *f_tpl, *f_spl;
	int r;

	if ((r = libusb_open(dev, &dev_handle)) != 0) {
		warnx("libusb_open failed");
		return r;
	}

	libusb_set_auto_detach_kernel_driver(dev_handle, 1);

	if ((r = libusb_claim_interface(dev_handle, 0)) != 0) {
		warnx("libusb_claim_interface failed");
		goto error1;
	}

	errno = 0;
	if ((f_tpl = fopen(tpl, "rb")) == NULL) {
		warn("fopen: %s", tpl);
		r = errno;
		goto error1;
	}

	errno = 0;
	if ((f_spl = fopen(spl, "rb")) == NULL) {
		warn("fopen: %s", spl);
		r = errno;
		goto error2;
	}

	errno = 0;
	if ((buf = malloc(BUF_SIZE)) == NULL) {
		warn("malloc: buf");
		r = errno;
		goto error3;
	}

	if ((pid & 0xff00) != 0x3500) {
		errno = 0;
		if ((buf_enc = malloc(BUF_SIZE)) == NULL) {
			warn("malloc: buf_enc");
			r = errno;
			goto error4;
		}

		printf("Download encrypted %s\n", tpl);
		send_usb_enc(dev_handle, 0x471, f_tpl);
		printf("Done.\n");

		printf("Download encrypted %s\n", spl);
		send_usb_enc(dev_handle, 0x472, f_spl);
		printf("Done.\n");

		free(buf_enc);
	} else {
		printf("Download %s\n", tpl);
		send_usb(dev_handle, 0x471, f_tpl);
		printf("Done.\n");

		printf("Download %s\n", spl);
		send_usb(dev_handle, 0x472, f_spl);
		printf("Done.\n");
	}

error4:
	free(buf);
error3:
	fclose(f_spl);
error2:
	fclose(f_tpl);
error1:
	libusb_close(dev_handle);

	return r;
}

int
main(int argc, char *argv[]) {
	libusb_device **dev_list;
	struct libusb_device_descriptor dev_desc;
	ssize_t dev_num;
	int c, i, j, o_list, o_num, o_pid, r = EXIT_FAILURE;

	o_list = o_num = o_pid = 0;
	while ((c = getopt(argc, argv, "ln:p:")) != -1) {
		switch (c) {
		case 'l':
			if (o_num|o_pid)
				goto usage;
			o_list = 1;
			r = EXIT_SUCCESS;
			break;
		case 'n':
			if (o_list|o_pid)
				goto usage;
			o_num = strtoul(optarg, NULL, 0);
			break;
		case 'p':
			if (o_list|o_num)
				goto usage;
			o_pid = strtoul(optarg, NULL, 0) & 0xffff;
			break;
		default:
			goto usage;
		};
	}

	argc -= optind;
	if ((argc != 0 && argc != 2) ||
	    (argc != 0 && o_list == 1) ||
	    (argc == 0 && o_list == 0))
		goto usage;
	argv += optind;

	if (libusb_init(NULL))
		errx(EXIT_FAILURE, "libusb_init failed");

	if ((dev_num = libusb_get_device_list(NULL, &dev_list)) < 0) {
		libusb_exit(NULL);
		errx(EXIT_FAILURE, "libusb_device_list failed");
	}

	for (i = j = 0; i < dev_num; i++) {
		if (libusb_get_device_descriptor(dev_list[i], &dev_desc))
			continue;
		if ((dev_desc.idVendor != VID_ROCKCHIP) ||
		    (dev_desc.iManufacturer != 0/* XXX */))
			continue;

		if (o_list) {
			printf("Device #%d: PID 0x%04x\n", j,
			       dev_desc.idProduct);
		} else if (o_pid == 0 && o_num == j) {
			printf("Boot #%d\n", o_num);
			r = usbboot(dev_list[i], argv[0], argv[1],
				    dev_desc.idProduct);
			break;
		} else if (o_pid == dev_desc.idProduct) {
			printf("Boot PID 0x%04x\n", dev_desc.idProduct);
			r = usbboot(dev_list[i], argv[0], argv[1],
				    dev_desc.idProduct);
			break;
		}

		j++;
	}

	libusb_free_device_list(dev_list, 1);
	libusb_exit(NULL);

	if (r != EXIT_SUCCESS)
		fprintf(stderr, "Failed.\n");

	return r;

usage:
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "%s -l\n", argv[0]);
	fprintf(stderr, "  List the Rockchip devices in MASKROM mode\n");
	fprintf(stderr, "%s [-n num|-p pid] tpl.bin spl.bin\n", argv[0]);
	fprintf(stderr, "  Boot the first (or specified) device in "
			"MASKROM mode\n");
	fprintf(stderr, "  -n num\tBoot num-th device\n");
	fprintf(stderr, "  -p pid\tBoot first device with pid\n");

	return EXIT_FAILURE;
}
