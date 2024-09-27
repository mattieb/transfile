/*
 * This file is part of transfile <https://mattiebee.dev/transfile>.
 *
 * Copyright 2024 Mattie Behrens.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * “Software”), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject
 * to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR
 * ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "sha1.h"
#include "tftp.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int handle_progress(size_t size) {
  printf("\r%lu bytes transferred", size);
  return 0;
}

int print_checksum(char *filename) {
  FILE *file;               /* file to operate on */
  void *buffer;             /* data being checksummed */
  SHA1_CTX *sha1_ctx;       /* SHA-1 context */
  size_t readsize;          /* current read size */
  unsigned char digest[20]; /* SHA-1 digest */
  int i;                    /* digest byte iterator */

  printf("\n%s...", filename);

  file = fopen(filename, "rb");
  if (ferror(file))
    TFTP_ERROR_RETURN;

  buffer = malloc(512);
  if (buffer == NULL)
    TFTP_ERROR_RETURN;

  sha1_ctx = malloc(sizeof(SHA1_CTX));
  if (sha1_ctx == NULL) {
    free(buffer);
    TFTP_ERROR_RETURN;
  }

  size_t bytes = 0;
  SHA1Init(sha1_ctx);
  do {
    readsize = fread(buffer, 1, 512, file);
    if (ferror(file)) {
      free(sha1_ctx);
      free(buffer);
      TFTP_ERROR_RETURN;
    }
    if (readsize > 0)
      SHA1Update(sha1_ctx, buffer, readsize);
    bytes += readsize;
  } while (readsize > 0);
  fclose(file);
  SHA1Final(digest, sha1_ctx);

  printf("\rlocal sha1: ");
  for (i = 0; i < 20; i++)
    printf("%02x", digest[i]);

  printf(" size: %lu\n", bytes);

  return 0;
}

void print_sha1(unsigned char *sha1) {
  int i;

  for (i = 0; i < 20; i++) {
    printf("%02x", sha1[i]);
  }
}

int handle_rq(struct tftp_rq *rq) {
  FILE *file;             /* file to operate on */
  unsigned char sha1[20]; /* SHA-1 digest from transfer */

  switch (rq->opcode) {
  case TFTP_OPCODE_RRQ:
    printf("Sending %s\n", rq->filename);

    file = fopen(rq->filename, "rb");
    if (file == NULL) {
      if (errno == ENOENT)
        tftp_send_error(rq, TFTP_ERROR_CODE_FILE_NOT_FOUND, "file not found");
      else
        tftp_send_error(rq, TFTP_ERROR_CODE_NOT_DEFINED, "internal error");
      TFTP_ERROR_RETURN;
    }

    rrq_from_file(rq, file, handle_progress, sha1);
    fclose(file);
    print_checksum(rq->filename);
    printf("rrq_from_file sha1: ");
    print_sha1(sha1);
    printf("\n");
    return 0;

  case TFTP_OPCODE_WRQ:
    printf("Writing %s\n", rq->filename);

    file = fopen(rq->filename, "wb");
    if (file == NULL) {
      tftp_send_error(rq, TFTP_ERROR_CODE_NOT_DEFINED, "internal error");
      TFTP_ERROR_RETURN;
    }

    wrq_to_file(rq, file, handle_progress, sha1);
    fclose(file);
    if (print_checksum(rq->filename))
      TFTP_ERROR_RETURN;
    printf("wrq_to_file sha1: ");
    print_sha1(sha1);
    printf("\n");
    return 0;

  default:
    return -1;
  }
}

int main() {
  int sock = tftp_sock(6969);
  tftp_serve(sock, handle_rq);
  return 0;
}
