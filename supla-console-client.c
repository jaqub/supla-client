/*
 Copyright (C) AC SOFTWARE SP. Z O.O.

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either version 2
 of the License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "client_loop.h"
#include "clientcfg.h"
#include "log.h"
#include "sthread.h"
#include "supla-client.h"
#include "tools.h"

int getch() {
  int r;
  unsigned char c;
  if ((r = read(0, &c, sizeof(c))) < 0)
    return r;

  return c;
}

int kbhit() {
  struct timeval tv = {0L, 0L};
  fd_set fds;
  FD_ZERO(&fds);
  FD_SET(0, &fds);
  return select(1, &fds, NULL, NULL, &tv);
}

int main(int argc, char *argv[]) {
  struct TSuplaClientData *suplaClient = NULL;
  Tsthread *cliThread = NULL;

  if (clientcfg_init(argc, argv) == 0) {
    clientcfg_free();
    return EXIT_FAILURE;
  }

  struct timeval runtime;
  gettimeofday(&runtime, NULL);

#if defined(__DEBUG) && defined(__SSOCKET_WRITE_TO_FILE)
  unlink("ssocket_write.raw");
#endif

  if (lifetime > 0) {
    supla_log(LOG_INFO, "Lifetime: %i sec.", lifetime);
  }

  if (input_off == 1) {
    supla_log(LOG_INFO, "Input: off");
  }

  st_mainloop_init();
  st_hook_signals();

  // CLIENT LOOP
  cliThread = sthread_simple_run(client_loop, (void *)&suplaClient, 0);

  // MAIN LOOP

  while (st_app_terminate == 0) {
		TCS_DeviceCalCfgRequest request;

    if (input_off == 0 && suplaClient != NULL && kbhit() > 0) {
      switch (getch()) {
        case '0':
          supla_client_open(suplaClient, 14, 1, 0);
          break;
        case '1':
          supla_client_open(suplaClient, 14, 1, 1);
          break;
        case '2':
          supla_client_open(suplaClient, 14, 1, 2);
          break;

        case '4':
          supla_client_open(suplaClient, 28, 0, 1);
          break;
        case '5':
          supla_client_open(suplaClient, 29, 0, 1);
          break;
        case '6':
          supla_client_open(suplaClient, 30, 0, 1);
          break;
        case '7':
          supla_client_get_registration_enabled(suplaClient);
          break;
        case 's':
          supla_client_superuser_authorization_request(suplaClient, NULL, "abcd");
          break;
        case 'c':
          memset(&request, 0, sizeof(TCS_DeviceCalCfgRequest));
          supla_client_device_calcfg_request(suplaClient, &request);
          break;
      }
    }

    if (lifetime > 0) {
      struct timeval now;
      gettimeofday(&now, NULL);

      if (now.tv_sec - runtime.tv_sec >= lifetime) {
        supla_log(LOG_INFO, "Timeout");
        break;
      }
    }

    st_mainloop_wait(1000);
  }

  // RELEASE BLOCK
  sthread_twf(cliThread);
  st_mainloop_free();
  clientcfg_free();

  return EXIT_SUCCESS;
}
