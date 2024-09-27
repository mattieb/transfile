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

#include "tftp.h"
#include "sha1.h"

#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>

/*
 * Create and bind a socket for serving TFTP requests.
 *
 * Returns a file descriptor for the bound socket, or -1 if an error occurred
 * (see `errno`).
 */
int tftp_sock(int port) {
  int sock;                 /* socket fd */
  struct sockaddr_in saddr; /* server address */

  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock == -1)
    return -1;

  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(port);
  saddr.sin_addr.s_addr = INADDR_ANY;
  if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)))
    return -1;

  return sock;
}

/*
 * Unpack the next string from a concatenated series of null-terminated
 * strings.
 *
 * `next` is modified to point to the string immediately after, or to NULL if
 * the end has been reached.
 *
 * `maxlen` is the maximum length to read, including the terminator, and is
 * modified by the number of bytes in the returned terminated string.
 *
 * Returns a pointer to the next string, or NULL if no complete terminated
 * string can be found.
 */
char *tftp_nextstr(void **next, size_t *maxlen) {
  char *str;  /* found string */
  size_t len; /* length of found string */

  if (*next == NULL)
    return NULL;

  len = strnlen(*next, *maxlen);
  if (len == *maxlen)
    return NULL; /* no string found */

  str = (char *)*next;

  len += 1; /* include terminator */
  *maxlen -= len;
  if (*maxlen > 0)
    *next += len;
  else
    *next = NULL; /* no more strings */

  return str;
}

#ifdef NDS
extern unsigned long volatile sgIP_timems;
/*
 * Get a millisecond timer value suitable for tracking timeouts.
 */
unsigned long tftp_timer() { return sgIP_timems; }
#else
#include <sys/timeb.h>
/*
 * Get a millisecond timer value suitable for tracking timeouts.
 */
unsigned long tftp_timer() {
  struct timeb tp;
  ftime(&tp);
  return (tp.time * 1000) + tp.millitm;
}
#endif /* NDS */

/*
 * Determine how many milliseconds have elapsed since the given millisecond
 * timer value was current.
 */
unsigned long tftp_elapsed(unsigned long since) {
  unsigned long now; /* current time */

  now = tftp_timer();
  if (now < since) {
    return (ULONG_MAX - since) + now + 1; /* timer rolled over */
  } else {
    return now - since;
  }
}

/*
 * Wait for a packet to be available until the timeout specified has passed.
 *
 * Returns 0 if ready to read, -1 with `errno` set to `ETIMEDOUT` on timeout,
 * or -1 with another value of `errno` on error.
 */

int tftp_wait(struct tftp_rq *rq, long timeout_ms) {
  struct timeval timeout;
  fd_set fds;

  timeout.tv_sec = timeout_ms / 1000;
  timeout.tv_usec = (timeout_ms % 1000) * 1000;

  FD_ZERO(&fds);
  FD_SET(rq->sock, &fds);

  switch (select(rq->sock + 1, &fds, NULL, NULL, &timeout)) {
  case 0:
    errno = ETIMEDOUT;
    return -1; /* no TFTP_ERROR_RETURN since this is normal */
  case -1:
    TFTP_ERROR_RETURN;
  default:
    return 0;
  }
}

/*
 * Wait for, prepare, and pass a TFTP request to a handler function.
 *
 * Returns the return value of the request handler fucntion, or -1 if an error
 * occurred (see `errno`).
 */
int tftp_serve(int sock, int (*rq_handler)(struct tftp_rq *rq)) {
  struct tftp_packet *packet; /* received packet */
  socklen_t caddrlen;         /* client address length */
  struct sockaddr_in caddr;   /* client address */
  ssize_t recvlen;            /* remaining received packet length */
  struct tftp_rq *rq;         /* request */
  void *fields;               /* pointer to packet fields */
  int rq_handler_ret;         /* return from rq_handler */

  packet = malloc(TFTP_MAX_RECVLEN);
  if (packet == NULL)
    TFTP_ERROR_RETURN;

  rq = malloc(sizeof(struct tftp_rq));
  if (rq == NULL) {
    free(packet);
    TFTP_ERROR_RETURN;
  }

  caddrlen = sizeof(caddr);
  recvlen = recvfrom(sock, packet, TFTP_MAX_RECVLEN, 0,
                     (struct sockaddr *)&caddr, &caddrlen);
  if (recvlen == -1) {
    free(rq);
    free(packet);
    TFTP_ERROR_RETURN;
  }

  rq->opcode = ntohs(packet->opcode);
  rq->sock = sock;
  rq->raddr = &caddr;
  switch (rq->opcode) {
  case TFTP_OPCODE_RRQ:
    rq->block_number = 1;
    break;

  case TFTP_OPCODE_WRQ:
    rq->block_number = 0;
    break;

  default:
    tftp_send_error(rq, TFTP_ERROR_CODE_ILLEGAL_TFTP_OPERATION,
                    "opcode must be RRQ or WRQ");
    free(rq);
    free(packet);
    TFTP_ERROR_RETURN;
  }

  recvlen -= sizeof(packet->opcode); /* skip over opcode */
  fields = &packet->fields;

  rq->filename = tftp_nextstr(&fields, (size_t *)&recvlen);
  if (rq->filename == NULL) {
    tftp_send_error(rq, TFTP_ERROR_CODE_ILLEGAL_TFTP_OPERATION,
                    "filename missing");
    free(rq);
    free(packet);
    errno = EAGAIN;
    TFTP_ERROR_RETURN;
  }

  rq->mode = tftp_nextstr(&fields, (size_t *)&recvlen);
  if (rq->mode == NULL || strcmp(rq->mode, "octet") != 0) {
    tftp_send_error(rq, TFTP_ERROR_CODE_ILLEGAL_TFTP_OPERATION,
                    "mode must be octet");
    free(rq);
    free(packet);
    errno = EAGAIN;
    TFTP_ERROR_RETURN;
  }

  rq->blksize = TFTP_DEF_BLKSIZE;

  TFTP_DEBUG_PRINTF(
      ("opcode=%d filename=%s mode=%s", rq->opcode, rq->filename, rq->mode));

  rq_handler_ret = rq_handler(rq);

  free(rq);
  free(packet);

  return rq_handler_ret;
}

/*
 * Compare the given address to the remote address stored in the request info.
 *
 * Returns 0 for a match, -1 for a mismatch.
 */
int tftp_addrcmp(struct tftp_rq *rq, struct sockaddr_in *addr) {
  if (addr->sin_addr.s_addr != rq->raddr->sin_addr.s_addr ||
      addr->sin_port != rq->raddr->sin_port)
    return -1;
  else
    return 0;
}

/*
 * Receive a DATA packet.
 *
 * `buffer` is the buffer to place the packet data in. `length` is the maximum
 * amount of data that can be put into that buffer. `block_number` is the
 * expected block number.
 *
 * Returns length of data received, or -1 if an error occurred (see `errno`).
 */
ssize_t tftp_recv_data(struct tftp_rq *rq, void *buffer, size_t length,
                       uint16_t block_number) {
  struct tftp_packet *packet; /* received packet */
  struct sockaddr_in raddr;   /* remote address */
  socklen_t raddrlen;         /* remote address length */
  size_t recvlen;             /* remaining received packet length */

  packet = malloc(TFTP_MAX_RECVLEN);
  if (packet == NULL)
    TFTP_ERROR_RETURN;

  raddrlen = sizeof(raddr);
  recvlen = recvfrom(rq->sock, packet, TFTP_MAX_RECVLEN, 0,
                     (struct sockaddr *)&raddr, &raddrlen);
  if (recvlen == -1) {
    free(packet);
    TFTP_ERROR_RETURN;
  }

  recvlen -= sizeof(packet->opcode);
  recvlen -= sizeof(packet->block_number);
  if (tftp_addrcmp(rq, &raddr) || recvlen > length ||
      ntohs(packet->opcode) != TFTP_OPCODE_DATA ||
      ntohs(packet->block_number) != block_number) {
    free(packet);
    errno = EAGAIN;
    TFTP_ERROR_RETURN;
  }

  TFTP_DEBUG_PRINTF(
      ("<DATA block_number=%d recvlen=%lu", block_number, recvlen));

  memcpy(buffer, packet->data, recvlen);
  free(packet);
  return recvlen;
}

/*
 * Send a DATA packet.
 *
 * `block_number` is the block number that this packet corresponds to. `buffer`
 * is the buffer holding the data to send. `length` is the number of bytes from
 * the buffer to send.
 *
 * Returns 0 if successful, or -1 if an error occurred (see `errno`).
 */
int tftp_send_data(struct tftp_rq *rq, uint16_t block_number,
                   const void *buffer, size_t length) {
  struct tftp_packet *packet; /* packet to send */
  ssize_t sendlen;            /* number of bytes sent */

  packet =
      malloc(sizeof(packet->opcode) + sizeof(packet->block_number) + length);
  if (packet == NULL)
    TFTP_ERROR_RETURN;

  packet->opcode = htons(TFTP_OPCODE_DATA);
  packet->block_number = htons(block_number);
  memcpy(packet->data, buffer, length);

  TFTP_DEBUG_PRINTF((">DATA block_number=%d length=%lu", block_number, length));

  sendlen =
      sendto(rq->sock, packet,
             sizeof(packet->opcode) + sizeof(packet->block_number) + length, 0,
             (struct sockaddr *)rq->raddr, sizeof(struct sockaddr_in));

  free(packet);
  if (sendlen == -1)
    TFTP_ERROR_RETURN;
  return 0;
}

/*
 * Receive an ACK packet.
 *
 * Returns the ACK's block number (which is guaranteed to be between 0 and
 * `UINT16_MAX`, inclusive), or -1 if an error occurred (see `errno`).
 */
int32_t tftp_recv_ack(struct tftp_rq *rq) {
  struct tftp_packet *packet; /* received packet */
  struct sockaddr_in raddr;   /* remote address */
  socklen_t raddrlen;         /* remote address len */
  size_t recvlen;             /* received packet length */
  uint16_t block_number;      /* block number in packet*/

  packet = malloc(TFTP_MAX_RECVLEN);
  if (packet == NULL)
    TFTP_ERROR_RETURN;

  raddrlen = sizeof(raddr);
  recvlen = recvfrom(rq->sock, packet, TFTP_MAX_RECVLEN, 0,
                     (struct sockaddr *)&raddr, &raddrlen);
  if (recvlen == -1) {
    free(packet);
    TFTP_ERROR_RETURN;
  }

  if (tftp_addrcmp(rq, &raddr) || (ntohs(packet->opcode) != TFTP_OPCODE_ACK)) {
    free(packet);
    errno = EAGAIN;
    TFTP_ERROR_RETURN;
  }

  block_number = ntohs(packet->block_number);
  TFTP_DEBUG_PRINTF(("<ACK block_number=%d", block_number));
  free(packet);
  return block_number;
}

/*
 * Send an ACK packet.
 *
 * `block_number` is the block to acknowledge.
 *
 * Returns 0 if successful, or -1 if an error occurred (see `errno`).
 */
int tftp_send_ack(struct tftp_rq *rq, uint16_t block_number) {
  struct tftp_packet *packet; /* packet to send */
  ssize_t sendlen;            /* number of packet bytes sent */

  packet = malloc(sizeof(packet->opcode) + sizeof(packet->block_number));
  if (packet == NULL)
    TFTP_ERROR_RETURN;

  packet->opcode = htons(TFTP_OPCODE_ACK);
  packet->block_number = htons(block_number);

  TFTP_DEBUG_PRINTF((">ACK block_number=%d", block_number));

  sendlen = sendto(rq->sock, packet,
                   sizeof(packet->opcode) + sizeof(packet->block_number), 0,
                   (struct sockaddr *)rq->raddr, sizeof(struct sockaddr_in));

  free(packet);
  if (sendlen == -1)
    TFTP_ERROR_RETURN;
  return 0;
}

/*
 * Send an ERROR packet.
 *
 * Returns 0 if successful, or -1 if an error occured (see `errno`).
 */
int tftp_send_error(struct tftp_rq *rq, uint16_t error_code,
                    char *error_message) {
  struct tftp_packet *packet; /* packet to send */
  ssize_t sendlen;            /* number of bytes sent */
  ssize_t messagelen; /* length of error message, including terminator */
  ssize_t packetlen;  /* length of packet */

  messagelen = strlen(error_message) + 1;
  packetlen = sizeof(packet->opcode) + sizeof(packet->error_code) + messagelen;

  packet = malloc(packetlen);
  if (packet == NULL)
    TFTP_ERROR_RETURN;

  packet->opcode = htons(TFTP_OPCODE_ERROR);
  packet->error_code = htons(error_code);
  strcpy(packet->error_message, error_message);

  TFTP_DEBUG_PRINTF((">ERROR code=%d message=%s", error_code, error_message));

  sendlen = sendto(rq->sock, packet, packetlen, 0, (struct sockaddr *)rq->raddr,
                   sizeof(struct sockaddr_in));

  free(packet);
  if (sendlen == -1)
    TFTP_ERROR_RETURN;
  return 0;
}

/*
 * Receive data from the remote host, acknowledging as necessary.
 *
 * `buffer` is the buffer to receive data into. `length` is the maximum amount
 * of data that can go into that buffer.
 *
 * Returns the length of data received. If this number is less than
 * `rq->blksize` (including 0), the transfer has concluded. Further reads will
 * time out.
 */
ssize_t tftp_recv(struct tftp_rq *rq, void *buffer, size_t length) {
  int retries;             /* number of retries thus far */
  unsigned long starttime; /* timer at start of current retry */
  unsigned long timeleft;  /* time left before next retry */
  ssize_t recvlen;         /* number of bytes received */

  retries = 0;
  do {
    starttime = tftp_timer();
    retries++;

    if (tftp_send_ack(rq, rq->block_number) == -1)
      TFTP_ERROR_RETURN;

    do {

      timeleft = TFTP_CONFIG_TIMEOUT - tftp_elapsed(starttime);
      if (tftp_wait(rq, timeleft) == -1) {
        if (errno == ETIMEDOUT)
          break; /* retry */
        TFTP_ERROR_RETURN;
      }

      recvlen = tftp_recv_data(rq, buffer, length, rq->block_number + 1);
      if (recvlen == -1) {
        if (errno == EAGAIN)
          continue; /* wait again */
        TFTP_ERROR_RETURN;
      }

      rq->block_number++;

      if (recvlen < rq->blksize) /* final block */
        if (tftp_send_ack(rq, rq->block_number) == -1)
          TFTP_ERROR_RETURN;

      return recvlen;

    } while (timeleft > 0);
  } while (retries < TFTP_CONFIG_RETRIES);

  errno = ETIMEDOUT;
  TFTP_ERROR_RETURN;
}

/*
 * Send data, waiting for acknowledgement from the remote host.
 *
 * `buffer` is the data to send. `length` is the maximum number of bytes from
 * the buffer to send.
 *
 * If `length` is less than `rq->blksize` (including 0), it is assumed this is
 * the final block and will end the transfer.
 *
 * Returns 0 if successful, or -1 if an error occurred (see `errno`).
 */
ssize_t tftp_send(struct tftp_rq *rq, const void *buffer, size_t length) {
  int retries;             /* number of retries thus far */
  unsigned long starttime; /* timer at start of current retry*/
  unsigned long timeleft;  /* time left before next retry */
  int32_t block_acked;     /* block number acked */

  if (length > rq->blksize) {
    errno = EINVAL;
    TFTP_ERROR_RETURN;
  }

  retries = 0;
  do {
    starttime = tftp_timer();
    retries++;

    if (tftp_send_data(rq, rq->block_number, buffer, length) == -1)
      TFTP_ERROR_RETURN;

    do {
      timeleft = TFTP_CONFIG_TIMEOUT - tftp_elapsed(starttime);
      if (tftp_wait(rq, timeleft) == -1) {
        if (errno == ETIMEDOUT)
          break; /* retry send */
        TFTP_ERROR_RETURN;
      }

      block_acked = tftp_recv_ack(rq);
      if (block_acked == -1) {
        if (errno == EAGAIN)
          continue; /* wait again */
        TFTP_ERROR_RETURN;
      }

      if (block_acked != rq->block_number)
        continue; /* wait again */

      rq->block_number++;
      return 0;
    } while (timeleft > 0);
  } while (retries < TFTP_CONFIG_RETRIES);

  errno = ETIMEDOUT;
  TFTP_ERROR_RETURN;
}

/*
 * Handle a RRQ by reading from a file.
 *
 * `file` is the file to read, and `progress_handler` will be called with
 * updates to the number of bytes read.
 *
 * `sha1` should point to a char[20] that can be used to store a SHA-1 digest of
 * the transferred data.  If set to NULL, no digest will be calculated.
 *
 * Returns the size of the file read, or -1 if an error occurred (see
 * `errno`).
 */
size_t rrq_from_file(struct tftp_rq *rq, FILE *file,
                     int (*progress_handler)(size_t read),
                     unsigned char *sha1) {
  void *buffer;       /* buffer */
  SHA1_CTX *sha1_ctx; /* SHA-1 context */
  size_t tdone;       /* transfer done so far */
  size_t readsize;    /* size of data read */

  buffer = malloc(rq->blksize);
  if (buffer == NULL) {
    tftp_send_error(rq, TFTP_ERROR_CODE_NOT_DEFINED, "internal error");
    TFTP_ERROR_RETURN;
  }

  if (sha1 == NULL) {
    sha1_ctx = NULL;
  } else {
    sha1_ctx = malloc(sizeof(SHA1_CTX));
    if (sha1_ctx == NULL) {
      free(buffer);
      TFTP_ERROR_RETURN;
    }
    SHA1Init(sha1_ctx);
  }

  tdone = 0;
  do {
    readsize = fread(buffer, 1, rq->blksize, file);

    if (ferror(file)) {
      tftp_send_error(rq, TFTP_ERROR_CODE_NOT_DEFINED, "internal error");
      free(sha1_ctx);
      free(buffer);
      TFTP_ERROR_RETURN;
    }

    if (sha1_ctx)
      SHA1Update(sha1_ctx, buffer, readsize);

    if (tftp_send(rq, buffer, readsize)) {
      free(sha1_ctx);
      free(buffer);
      TFTP_ERROR_RETURN;
    }

    tdone += readsize;
    progress_handler(tdone);
  } while (readsize > 0);

  if (sha1_ctx) {
    SHA1Final(sha1, sha1_ctx);
    free(sha1_ctx);
  }

  return tdone;
}

/*
 * Handle a WRQ by writing to a file.
 *
 * `file` is the file to write to, and `progress_handler` will be called with
 * updates to the number of bytes written.
 *
 * `sha1` should point to a char[20] that can be used to store a SHA-1 digest of
 * the transferred data.  If set to NULL, no digest will be calculated.
 *
 * Returns the size of the file written, or -1 if an error occurred (see
 * `errno`).
 */
size_t wrq_to_file(struct tftp_rq *rq, FILE *file,
                   int (*progress_handler)(size_t written),
                   unsigned char *sha1) {
  void *buffer;       /* buffer */
  SHA1_CTX *sha1_ctx; /* SHA-1 context */
  size_t tdone;       /* transfer done so far */
  size_t recvsize;    /* size of data received in one call */
  size_t writesize;   /* size of data written */

  buffer = malloc(rq->blksize);
  if (buffer == NULL) {
    tftp_send_error(rq, TFTP_ERROR_CODE_NOT_DEFINED, "internal error");
    TFTP_ERROR_RETURN;
  }

  if (sha1 == NULL) {
    sha1_ctx = NULL;
  } else {
    sha1_ctx = malloc(sizeof(SHA1_CTX));
    if (sha1_ctx == NULL) {
      free(buffer);
      TFTP_ERROR_RETURN;
    }
    SHA1Init(sha1_ctx);
  }

  tdone = 0;
  while (1) {
    recvsize = tftp_recv(rq, buffer, rq->blksize);
    if (recvsize == -1) {
      free(sha1_ctx);
      free(buffer);
      TFTP_ERROR_RETURN;
    }

    writesize = fwrite(buffer, 1, recvsize, file);
    if (writesize != recvsize) {
      tftp_send_error(rq, TFTP_ERROR_CODE_DISK_FULL, "write error");
      free(sha1_ctx);
      free(buffer);
      TFTP_ERROR_RETURN;
    }

    if (sha1_ctx)
      SHA1Update(sha1_ctx, buffer, recvsize);

    tdone += recvsize;
    progress_handler(tdone);

    if (recvsize < rq->blksize)
      break; /* end-of-file */
  }

  if (sha1_ctx) {
    SHA1Final(sha1, sha1_ctx);
    free(sha1_ctx);
  }

  free(buffer);
  return tdone;
}
