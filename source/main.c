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

#include <nds.h>

#include <dirent.h>
#include <dswifi9.h>
#include <errno.h>
#include <fat.h>
#include <nds/arm9/dldi.h>
#include <netinet/in.h>
#include <stdio.h>

void exit_wait() {
  printf("\nPress any button to exit.");
  while (1) {
    swiWaitForVBlank();
    scanKeys();
    if (keysDown())
      break;
  }
}

void print_ip_info() {
  struct in_addr ip;
  ip = Wifi_GetIPInfo(NULL, NULL, NULL, NULL);
  printf("  IP address: %s\n", inet_ntoa(ip));
}

void print_device_status(const char *path) {
  DIR *dir = opendir(path);
  if (dir == NULL)
    return;
  closedir(dir);
  printf("  Device available: %s\n", path);
}

int handle_progress(size_t size) {
  printf("\r%d bytes transferred...", size);
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
    printf("\n");
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
    printf("\n");
    print_sha1(sha1);
    printf("\n");
    return 0;

  default:
    return -1;
  }
}

int main() {
  PrintConsole main, sub;

  videoSetMode(MODE_0_2D);
  videoSetModeSub(MODE_0_2D);
  vramSetBankA(VRAM_A_MAIN_BG);
  vramSetBankC(VRAM_C_SUB_BG);
  consoleInit(&main, 3, BgType_Text4bpp, BgSize_T_256x256, 31, 0, true, true);
  consoleInit(&sub, 3, BgType_Text4bpp, BgSize_T_256x256, 31, 0, false, true);

  consoleSelect(&main);
  printf("mattiebee.dev/transfile     v0.1\n");

  printf("Filesystem:\n\n");

  if (!fatInitDefault()) {
    printf(" libfat init failed.\n");
    exit_wait();
    return -1;
  }

  print_device_status("fat:/");
  print_device_status("sd:/");
  printf("  DLDI: %s\n\n", io_dldi_data->friendlyName);

  printf("Network:\n\n");
  printf("  Connecting...\r");

  if (!Wifi_InitDefault(WFC_CONNECT)) {
    printf("  Connection failed.\n");
    exit_wait();
    return -1;
  }

  print_ip_info();

  consoleSelect(&sub);
  printf("\x1b[23;1H");

  int sock = tftp_sock(69);

  while (1) {
    printf("\nListening...\r");
    tftp_serve(sock, handle_rq);
  }

  exit_wait();
  return 0;
}
