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

#ifndef _TFTP_H
#define _TFTP_H

#include <stdint.h>
#include <stdio.h>

#define TFTP_CONFIG_RETRIES 10  /* maximum retries */
#define TFTP_CONFIG_TIMEOUT 500 /* timeout in milliseconds */

#define TFTP_OPCODE_RRQ 1
#define TFTP_OPCODE_WRQ 2
#define TFTP_OPCODE_DATA 3
#define TFTP_OPCODE_ACK 4
#define TFTP_OPCODE_ERROR 5

#define TFTP_ERROR_CODE_NOT_DEFINED 0
#define TFTP_ERROR_CODE_FILE_NOT_FOUND 1
#define TFTP_ERROR_CODE_DISK_FULL 3
#define TFTP_ERROR_CODE_ILLEGAL_TFTP_OPERATION 4

#ifdef TFTP_DEBUG
#define TFTP_DEBUG_PRINTF(x)                                                   \
  printf("%s(%d):", __FILE_NAME__, __LINE__);                                  \
  printf x;                                                                    \
  printf("\n");
#else
#define TFTP_DEBUG_PRINTF(x)
#endif /* TFTP_DEBUG */

#define TFTP_ERROR_RETURN                                                      \
  {                                                                            \
    TFTP_DEBUG_PRINTF(("error return (errno=%d)", errno));                     \
    return -1;                                                                 \
  }

#ifdef NDS
#define TFTP_MTU 1460
#define TFTP_MRU 2304
#else
#define TFTP_MTU 1500
#define TFTP_MRU 1500
#endif /* NDS */

/* IP + UDP headers = 28 bytes */
#define TFTP_MAX_RECVLEN TFTP_MRU - 28
#define TFTP_MAX_SENDLEN TFTP_MTU - 28
#define TFTP_MAX_BLKSIZE                                                       \
  TFTP_MAX_SENDLEN - sizeof(pkt->op) - sizeof(pkt->u.block)
#define TFTP_DEF_BLKSIZE 512

/* devkitARM doesn't currently define socklen_t */
#ifdef NDS
#ifndef __socklen_t_defined
typedef int socklen_t;
#define __socklen_t_defined
#endif /* !__socklen_t_defined */
#endif /* NDS */

/*
 * A TFTP packet.
 *
 * Packets are in network byte order and must be converted.
 */
struct __attribute__((packed)) tftp_packet {
  uint16_t opcode;
  union {
    uint16_t block_number;
    uint16_t error_code;
    char fields[0];
  } __attribute__((packed));
  union {
    char data[0];
    char error_message[0];
  } __attribute__((packed));
};

/*
 * A TFTP request.
 */
struct tftp_rq {
  int sock;                  /* socket fd */
  struct sockaddr_in *raddr; /* remote address */
  uint16_t opcode;           /* request opcode (e.g. TFTP_OPCODE_RRQ) */
  char *filename;            /* filename */
  char *mode;                /* mode (e.g. "octet") */
  uint16_t block_number;     /* current block number */
  unsigned int blksize;      /* block size */
};

int tftp_sock(int port);
char *tftp_nextstr(void **next, size_t *maxlen);
int tftp_serve(int sock, int (*rq_handler)(struct tftp_rq *rq));
int tftp_send_error(struct tftp_rq *rq, uint16_t error_code,
                    char *error_message);
size_t rrq_from_file(struct tftp_rq *rq, FILE *file,
                     int (*progress_handler)(size_t read), unsigned char *sha1);
size_t wrq_to_file(struct tftp_rq *rq, FILE *file,
                   int (*progress_handler)(size_t written),
                   unsigned char *sha1);

#endif /* _TFTP_H */