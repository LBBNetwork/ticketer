/*
 * Ticketer - generate APTicket from raw data
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "config.h"

#define DPRINT printf

unsigned char scab_header[] = {
	0x33, 0x67, 0x6D, 0x49, 0x00, 0x0C, 0x00, 0x00,
	0xEC, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x42, 0x41, 0x43, 0x53, 0x45, 0x50, 0x59, 0x54,
	0x20, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
	0x42, 0x41, 0x43, 0x53, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x31, 0x2F, 0x73, 0x6F, 0x41, 0x54, 0x41, 0x44,
	0xAC, 0x0A, 0x00, 0x00, 0x9A, 0x0A, 0x00, 0x00
};

void usage() {
	printf("usage: %s -b [raw_blob (not xml, but raw certificate!)]\n", "ticketer");
}

int main(int argc, char* argv[])
{
	char *blobfile = NULL, *img3file = NULL;
	int c;

	while ((c = getopt(argc, argv, "b:")) != -1) {
		switch (c) {
		case 'b':
			blobfile = optarg;
			break;
		default:
			usage();
			return -1;
		}
	}


	FILE *blobc;

	/* open blob container */
	blobc = fopen(blobfile, "rb+");
	if (!blobc) {
		DPRINT("Failed to open blob raw container.\n");
		usage();
		return -1;
	}

	int len;
	fseek(blobc, 0, SEEK_END);
	len = ftell(blobc);
	fseek(blobc, 0, SEEK_SET);
	DPRINT("blob length is %d\n", len);

	uint8_t *blob_buffer;

	/* allocate memory */
	blob_buffer = malloc(len);
	if (!blob_buffer) {
		DPRINT("Memory allocation failed.\n");
		return;
	}
	memset(blob_buffer, 0, len);
	fread(blob_buffer, len, 1, blobc);
	DPRINT("blob buffer is at %p\n", blob_buffer);

	DPRINT("Target size is %d, (unprepared bufsize: %d)\n", 3072, len + sizeof(scab_header));

	int pad = (3072 - (len + sizeof(scab_header)));
	if(pad > 0) {
		DPRINT("Pad bytes = %d\n", pad);
	} else {
		DPRINT("Woah, it's too large! Looks like your APTicket is malformed.\n");
		return -1;
	}

	uint8_t *finalized_buffer = malloc(3072);
	if(!finalized_buffer) {
		DPRINT("Memory allocation failed.\n");
		return -1;
	}

	memset(finalized_buffer, 0, 3072);

	DPRINT("Copying to buffer\n");
	memcpy(finalized_buffer, scab_header, sizeof(scab_header));
	memcpy(finalized_buffer + sizeof(scab_header), blob_buffer, len);

	DPRINT("Fixing up header.\n");

	uint32_t size, size2;
	size = len;
	size2 = len + 0x30;
#ifdef ENDIAN_BIG
	size = __builtin_bswap32(size);
	size2 = __builtin_bswap32(size2);
#endif
	memcpy(finalized_buffer + 0x38, &size, sizeof(uint32_t));
	memcpy(finalized_buffer + 0x3C, &size2, sizeof(uint32_t));

	FILE *apticket_img3;
	apticket_img3 = fopen("apticket.img3", "wb+");
	if(!apticket_img3) {
		DPRINT("Cannot open output file\n");
		return -1;
	}

	fwrite(finalized_buffer, 3072, 1, apticket_img3);
	fclose(apticket_img3);
	fclose(blobc);
}
