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

#ifndef CLIENTCFG_H_
#define CLIENTCFG_H_

#include "proto.h"

#ifdef __cplusplus
extern "C" {
#endif

extern char *cfg_id_file;

extern char *cfg_email;
extern char *cfg_host;
extern int cfg_port;
extern char cfg_ssl_enabled;

extern int cfg_aid;
extern char *cfg_pwd;

extern char cfg_client_GUID[SUPLA_GUID_SIZE];
extern char cfg_client_AuthKey[SUPLA_AUTHKEY_SIZE];

extern unsigned char proto_version;

extern int lifetime;
extern char input_off;

unsigned char clientcfg_init(int argc, char *argv[]);
void clientcfg_free();

#ifdef __cplusplus
}
#endif

#endif /* CLIENTCFG_H_ */
