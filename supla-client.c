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

#include <stdlib.h>
#include <string.h>

#include "lck.h"
#include "log.h"
#include "srpc.h"
#include "supla-client.h"
#include "supla-socket.h"

struct TSuplaClientData {
  void *ssd;
  void *eh;
  void *srpc;
  void *lck;

  int client_id;

  struct timeval last_ping;
  struct timeval last_call_sent;
  struct timeval last_call_recv;
  char connected;
  char registered;
  int server_activity_timeout;

  TSuplaClientCfg cfg;
};

int supla_client_socket_read(void *buf, int count, void *scd) {
  struct TSuplaClientData *clientData = scd;
  return ssocket_read(clientData->ssd, NULL, buf, count);
}

int supla_client_socket_write(void *buf, int count, void *scd) {
  return ssocket_write(((struct TSuplaClientData *)scd)->ssd, NULL, buf, count);
}

void supla_client_before_async_call(void *_srpc,
                                    unsigned _supla_int_t call_type,
                                    void *_scd) {
  struct TSuplaClientData *scd = (struct TSuplaClientData *)_scd;
  gettimeofday(&scd->last_call_sent, NULL);
}

void supla_client_on_min_version_required(void *_srpc,
                                          unsigned _supla_int_t call_type,
                                          unsigned char min_version,
                                          void *_scd) {
  struct TSuplaClientData *scd = (struct TSuplaClientData *)_scd;

  if (scd->cfg.cb_on_min_version_required) {
    scd->cfg.cb_on_min_version_required(scd, scd->cfg.user_data, call_type,
                                        min_version);
  }
}

void supla_client_on_version_error(struct TSuplaClientData *scd,
                                   TSDC_SuplaVersionError *version_error) {
  supla_log(LOG_ERR,
            "Protocol version error. Server doesn't support this client. "
            "S:%d-%d/C:%d",
            version_error->server_version_min, version_error->server_version,
            SUPLA_PROTO_VERSION);

  if (scd->cfg.cb_on_versionerror) {
    scd->cfg.cb_on_versionerror(scd, scd->cfg.user_data, SUPLA_PROTO_VERSION,
                                version_error->server_version_min,
                                version_error->server_version);
  }

  supla_client_disconnect(scd);
}

char supla_client_registered(struct TSuplaClientData *suplaClient) {
  char result;
  lck_lock(suplaClient->lck);
  result = suplaClient->registered;
  lck_unlock(suplaClient->lck);

  return result;
}

void supla_client_set_registered(struct TSuplaClientData *suplaClient, char registered) {

  lck_lock(suplaClient->lck);
  suplaClient->registered = registered;
  lck_unlock(suplaClient->lck);
}

void supla_client_on_register_result(struct TSuplaClientData *scd,
    TSC_SuplaRegisterClientResult_B *register_client_result) {

  if (register_client_result->result_code == SUPLA_RESULTCODE_TRUE) {
    supla_client_set_registered(scd, 1);

    scd->server_activity_timeout = register_client_result->activity_timeout;
    scd->client_id = register_client_result->ClientID;

    supla_log(LOG_DEBUG, "Registered.");

    if (scd->cfg.cb_on_registered)
      scd->cfg.cb_on_registered(scd, scd->cfg.user_data,
                                register_client_result);

  } else {
    switch (register_client_result->result_code) {
      case SUPLA_RESULTCODE_BAD_CREDENTIALS:
        supla_log(LOG_ERR, "Bad credentials!");
        break;

      case SUPLA_RESULTCODE_TEMPORARILY_UNAVAILABLE:
        supla_log(LOG_NOTICE, "Temporarily unavailable!");
        break;

      case SUPLA_RESULTCODE_ACCESSID_DISABLED:
        supla_log(LOG_NOTICE, "Access Identifier is disabled!");
        break;

      case SUPLA_RESULTCODE_CLIENT_DISABLED:
        supla_log(LOG_NOTICE, "Client is disabled!");
        break;

      case SUPLA_RESULTCODE_CLIENT_LIMITEXCEEDED:
        supla_log(LOG_NOTICE, "Client limit exceeded!");
        break;

      case SUPLA_RESULTCODE_GUID_ERROR:
        supla_log(LOG_NOTICE, "Incorrect client GUID!");
        break;

      case SUPLA_RESULTCODE_REGISTRATION_DISABLED:
        supla_log(LOG_NOTICE, "Registration disabled!");
        break;

      case SUPLA_RESULTCODE_ACCESSID_NOT_ASSIGNED:
        supla_log(LOG_NOTICE, "Access Identifier not assigned!");
        break;

      case SUPLA_RESULTCODE_AUTHKEY_ERROR:
        supla_log(LOG_NOTICE, "Incorrect AuthKey!");
        break;
    }

    if (scd->cfg.cb_on_registererror)
      scd->cfg.cb_on_registererror(scd, scd->cfg.user_data,
                                   register_client_result->result_code);

    supla_client_disconnect(scd);
  }
}

void supla_client_set_str(char *str, unsigned int *size, unsigned int max) {
  if (*size > max) *size = max;

  if (*size > 0)
    str[(*size) - 1] = 0;
  else
    str[0] = 0;
}

void supla_client_location_update(struct TSuplaClientData *scd,
                                  TSC_SuplaLocation *location, char gn) {
  supla_client_set_str(location->Caption, &location->CaptionSize,
                       SUPLA_LOCATION_CAPTION_MAXSIZE);

  if (scd->cfg.cb_location_update)
    scd->cfg.cb_location_update(scd, scd->cfg.user_data, location);

  if (gn == 1) srpc_cs_async_get_next(scd->srpc);
}

void supla_client_locationpack_update(struct TSuplaClientData *scd,
                                      TSC_SuplaLocationPack *pack) {
  int a;

  for (a = 0; a < pack->count; a++)
    supla_client_location_update(scd, &pack->items[a], 0);

  srpc_cs_async_get_next(scd->srpc);
}

void supla_client_channel_update_c(struct TSuplaClientData *scd,
                                   TSC_SuplaChannel_C *channel, char gn) {
  supla_client_set_str(channel->Caption, &channel->CaptionSize,
                       SUPLA_CHANNEL_CAPTION_MAXSIZE);

  if (scd->cfg.cb_channel_update)
    scd->cfg.cb_channel_update(scd, scd->cfg.user_data, channel);

  if (gn == 1) srpc_cs_async_get_next(scd->srpc);
}

void supla_client_channelgroup_update(struct TSuplaClientData *scd,
                                      TSC_SuplaChannelGroup_B *channel_group,
                                      char gn) {
  supla_client_set_str(channel_group->Caption, &channel_group->CaptionSize,
                       SUPLA_CHANNELGROUP_CAPTION_MAXSIZE);

  if (scd->cfg.cb_channelgroup_update)
    scd->cfg.cb_channelgroup_update(scd, scd->cfg.user_data, channel_group);

  if (gn == 1) srpc_cs_async_get_next(scd->srpc);
}

void supla_client_channelgroup_pack_update(struct TSuplaClientData *scd,
                                           TSC_SuplaChannelGroupPack *pack) {
  int a;

  for (a = 0; a < pack->count; a++) {
    TSC_SuplaChannelGroup_B channel_group;

    channel_group.EOL = pack->items[a].EOL;
    channel_group.Id = pack->items[a].Id;
    channel_group.LocationID = pack->items[a].LocationID;
    channel_group.Func = pack->items[a].Func;
    channel_group.AltIcon = pack->items[a].AltIcon;
    channel_group.UserIcon = 0;
    channel_group.Flags = pack->items[a].Flags;
    channel_group.CaptionSize = pack->items[a].CaptionSize;
    memcpy(channel_group.Caption, pack->items[a].Caption,
           SUPLA_CHANNELGROUP_CAPTION_MAXSIZE);

    supla_client_channelgroup_update(scd, &channel_group, 0);
  }

  srpc_cs_async_get_next(scd->srpc);
}

void supla_client_channelgroup_pack_update_b(
    struct TSuplaClientData *scd, TSC_SuplaChannelGroupPack_B *pack) {
  int a;

  for (a = 0; a < pack->count; a++)
    supla_client_channelgroup_update(scd, &pack->items[a], 0);

  srpc_cs_async_get_next(scd->srpc);
}

void supla_client_channelgroup_relation_update(
    struct TSuplaClientData *scd, TSC_SuplaChannelGroupRelation *channelgroup_relation,
    char gn) {
  if (scd->cfg.cb_channelgroup_relation_update)
    scd->cfg.cb_channelgroup_relation_update(scd, scd->cfg.user_data,
                                             channelgroup_relation);

  if (gn == 1) srpc_cs_async_get_next(scd->srpc);
}

void supla_client_channelgroup_relation_pack_update(
    struct TSuplaClientData *scd, TSC_SuplaChannelGroupRelationPack *pack) {
  int a;

  for (a = 0; a < pack->count; a++)
    supla_client_channelgroup_relation_update(scd, &pack->items[a], 0);

  srpc_cs_async_get_next(scd->srpc);
}

void supla_client_channel_value_update(struct TSuplaClientData *scd,
                                       TSC_SuplaChannelValue *channel_value,
                                       char gn) {
  if (scd->cfg.cb_channel_value_update)
    scd->cfg.cb_channel_value_update(scd, scd->cfg.user_data, channel_value);

  if (gn == 1) {
    srpc_cs_async_get_next(scd->srpc);
  }
}

void supla_client_channel_extendedvalue_update(
    struct TSuplaClientData *scd,
    TSC_SuplaChannelExtendedValue *channel_extendedvalue) {
  if (scd->cfg.cb_channel_extendedvalue_update)
    scd->cfg.cb_channel_extendedvalue_update(scd, scd->cfg.user_data,
                                             channel_extendedvalue);
}

void supla_client_channelvalue_pack_update(struct TSuplaClientData *scd,
                                           TSC_SuplaChannelValuePack *pack) {
  int a;

  if (pack && pack->count <= SUPLA_CHANNELVALUE_PACK_MAXCOUNT) {
    for (a = 0; a < pack->count; a++) {
      supla_client_channel_value_update(scd, &pack->items[a], 0);
    }
  }

  srpc_cs_async_get_next(scd->srpc);
}

void supla_client_channelextendedvalue_pack_update(
    struct TSuplaClientData *scd, TSC_SuplaChannelExtendedValuePack *pack) {
  TSC_SuplaChannelExtendedValue ev;
  int n = 0;
  int offset = 0;
  int min_size =
      sizeof(TSC_SuplaChannelExtendedValue) - SUPLA_CHANNELEXTENDEDVALUE_SIZE;

  if (pack != NULL) {
    while (pack->pack_size - offset >= min_size && n < pack->count) {
      memset(&ev, 0, sizeof(TSC_SuplaChannelExtendedValue));
      memcpy(&ev, &pack->pack[offset], min_size);
      offset += min_size;

      if (ev.value.size > 0 && ev.value.type != 0 &&
          pack->pack_size - offset >= ev.value.size) {
        memcpy(ev.value.value, &pack->pack[offset], ev.value.size);

        offset += ev.value.size;
        supla_client_channel_extendedvalue_update(scd, &ev);
      }

      n++;
    }
  }

  srpc_cs_async_get_next(scd->srpc);
}

void supla_client_channel_a2b(TSC_SuplaChannel *a, TSC_SuplaChannel_B *b) {
  b->EOL = a->EOL;
  b->Id = a->Id;
  b->LocationID = a->LocationID;
  b->Func = a->Func;
  b->AltIcon = 0;
  b->Flags = 0;
  b->ProtocolVersion = 0;
  b->online = a->online;
  memcpy(&b->value, &a->value, sizeof(TSuplaChannelValue));
  b->CaptionSize = a->CaptionSize;
  memcpy(b->Caption, a->Caption, SUPLA_CHANNEL_CAPTION_MAXSIZE);
}

void supla_client_channel_b2c(TSC_SuplaChannel_B *b, TSC_SuplaChannel_C *c) {
  c->EOL = b->EOL;
  c->Id = b->Id;
  c->DeviceID = 0;
  c->LocationID = b->LocationID;
  c->Func = b->Func;
  c->AltIcon = b->AltIcon;
  c->Type = 0;
  c->Flags = b->Flags;
  c->UserIcon = 0;
  c->ManufacturerID = 0;
  c->ProductID = 0;
  c->ProtocolVersion = 0;
  c->online = b->online;
  memcpy(&c->value, &b->value, sizeof(TSuplaChannelValue));
  c->CaptionSize = b->CaptionSize;
  memcpy(c->Caption, b->Caption, SUPLA_CHANNEL_CAPTION_MAXSIZE);
}

void supla_client_channel_update_b(struct TSuplaClientData *scd,
                                   TSC_SuplaChannel_B *channel_b, char gn) {
  TSC_SuplaChannel_C channel_c;
  memset(&channel_c, 0, sizeof(TSC_SuplaChannel_C));

  supla_client_channel_b2c(channel_b, &channel_c);
  supla_client_channel_update_c(scd, &channel_c, gn);
}

void supla_client_channel_update(struct TSuplaClientData *scd,
                                 TSC_SuplaChannel *channel, char gn) {
  TSC_SuplaChannel_B channel_b;
  memset(&channel_b, 0, sizeof(TSC_SuplaChannel_B));

  supla_client_channel_a2b(channel, &channel_b);
  supla_client_channel_update_b(scd, &channel_b, gn);
}

void supla_client_channelpack_update(struct TSuplaClientData *scd,
                                     TSC_SuplaChannelPack *pack) {
  int a;

  for (a = 0; a < pack->count; a++)
    supla_client_channel_update(scd, &pack->items[a], 0);

  srpc_cs_async_get_next(scd->srpc);
}

void supla_client_channelpack_update_b(struct TSuplaClientData *scd,
                                       TSC_SuplaChannelPack_B *pack) {
  int a;

  for (a = 0; a < pack->count; a++)
    supla_client_channel_update_b(scd, &pack->items[a], 0);

  srpc_cs_async_get_next(scd->srpc);
}

void supla_client_channelpack_update_c(struct TSuplaClientData *scd,
                                       TSC_SuplaChannelPack_C *pack) {
  int a;

  for (a = 0; a < pack->count; a++)
    supla_client_channel_update_c(scd, &pack->items[a], 0);

  srpc_cs_async_get_next(scd->srpc);
}

void supla_client_on_event(struct TSuplaClientData *scd, TSC_SuplaEvent *event) {
  supla_client_set_str(event->SenderName, &event->SenderNameSize,
                       SUPLA_SENDER_NAME_MAXSIZE);

  if (scd->cfg.cb_on_event)
    scd->cfg.cb_on_event(scd, scd->cfg.user_data, event);
}

void supla_client_on_oauth_token_request_result(
    struct TSuplaClientData *scd, TSC_OAuthTokenRequestResult *result) {
  supla_client_set_str(result->Token.Token, &result->Token.TokenSize,
                       SUPLA_OAUTH_TOKEN_MAXSIZE);

  if (scd->cfg.cb_on_oauth_token_request_result)
    scd->cfg.cb_on_oauth_token_request_result(scd, scd->cfg.user_data, result);
}

void supla_client_on_remote_call_received(void *_srpc, unsigned int rr_id,
                                          unsigned int call_type, void *_scd,
                                          unsigned char proto_version) {
  TsrpcReceivedData rd;
  char result;
  struct TSuplaClientData *scd = (struct TSuplaClientData *)_scd;

  gettimeofday(&scd->last_call_recv, NULL);

  supla_log(LOG_DEBUG, "on_remote_call_received: %i", call_type);

  if (SUPLA_RESULT_TRUE == (result = srpc_getdata(_srpc, &rd, 0))) {
    switch (rd.call_type) {
      case SUPLA_SDC_CALL_VERSIONERROR:
        if (rd.data.sdc_version_error) {
          supla_client_on_version_error(scd, rd.data.sdc_version_error);
        }
        break;
      case SUPLA_SC_CALL_REGISTER_CLIENT_RESULT:

        if (rd.data.sc_register_client_result == NULL) {
          break;
        }

        {
          TSC_SuplaRegisterClientResult_B *sc_register_client_result_b =
              (TSC_SuplaRegisterClientResult_B *)malloc(
                  sizeof(TSC_SuplaRegisterClientResult_B));

          if (sc_register_client_result_b == NULL) {
            break;
          } else {
            sc_register_client_result_b->result_code =
                rd.data.sc_register_client_result->result_code;

            sc_register_client_result_b->ClientID =
                rd.data.sc_register_client_result->ClientID;

            sc_register_client_result_b->LocationCount =
                rd.data.sc_register_client_result->LocationCount;

            sc_register_client_result_b->ChannelCount =
                rd.data.sc_register_client_result->ChannelCount;

            sc_register_client_result_b->ChannelGroupCount = 0;
            sc_register_client_result_b->Flags = 0;

            sc_register_client_result_b->activity_timeout =
                rd.data.sc_register_client_result->activity_timeout;

            sc_register_client_result_b->version =
                rd.data.sc_register_client_result->version;

            sc_register_client_result_b->version_min =
                rd.data.sc_register_client_result->version_min;

            free(rd.data.sc_register_client_result);
            rd.data.sc_register_client_result_b = sc_register_client_result_b;
          }
        }

      /* no break between SUPLA_SC_CALL_REGISTER_CLIENT_RESULT and
       * SUPLA_SC_CALL_REGISTER_CLIENT_RESULT_B!!! */
      case SUPLA_SC_CALL_REGISTER_CLIENT_RESULT_B:
        if (rd.data.sc_register_client_result_b) {
          supla_client_on_register_result(scd,
                                          rd.data.sc_register_client_result_b);
        }
        break;
      case SUPLA_SC_CALL_LOCATION_UPDATE:
        if (rd.data.sc_location) {
          supla_client_location_update(scd, rd.data.sc_location, 1);
        }
        break;
      case SUPLA_SC_CALL_LOCATIONPACK_UPDATE:
        if (rd.data.sc_location_pack) {
          supla_client_locationpack_update(scd, rd.data.sc_location_pack);
        }
        break;
      case SUPLA_SC_CALL_CHANNEL_UPDATE:
        if (rd.data.sc_channel) {
          supla_client_channel_update(scd, rd.data.sc_channel, 1);
        }
        break;
      case SUPLA_SC_CALL_CHANNEL_UPDATE_B:
        if (rd.data.sc_channel_b) {
          supla_client_channel_update_b(scd, rd.data.sc_channel_b, 1);
        }
        break;
      case SUPLA_SC_CALL_CHANNEL_UPDATE_C:
        if (rd.data.sc_channel_c) {
          supla_client_channel_update_c(scd, rd.data.sc_channel_c, 1);
        }
        break;
      case SUPLA_SC_CALL_CHANNELPACK_UPDATE:
        if (rd.data.sc_channel_pack) {
          supla_client_channelpack_update(scd, rd.data.sc_channel_pack);
        }
        break;
      case SUPLA_SC_CALL_CHANNELPACK_UPDATE_B:
        if (rd.data.sc_channel_pack_b) {
          supla_client_channelpack_update_b(scd, rd.data.sc_channel_pack_b);
        }
        break;
      case SUPLA_SC_CALL_CHANNELPACK_UPDATE_C:
        if (rd.data.sc_channel_pack_c) {
          supla_client_channelpack_update_c(scd, rd.data.sc_channel_pack_c);
        }
        break;
      case SUPLA_SC_CALL_CHANNEL_VALUE_UPDATE:
        if (rd.data.sc_channel_value) {
          supla_client_channel_value_update(scd, rd.data.sc_channel_value, 1);
        }
        break;
      case SUPLA_SC_CALL_CHANNELGROUP_PACK_UPDATE:
        if (rd.data.sc_channelgroup_pack) {
          supla_client_channelgroup_pack_update(scd,
                                                rd.data.sc_channelgroup_pack);
        }
        break;
      case SUPLA_SC_CALL_CHANNELGROUP_PACK_UPDATE_B:
        if (rd.data.sc_channelgroup_pack_b) {
          supla_client_channelgroup_pack_update_b(
              scd, rd.data.sc_channelgroup_pack_b);
        }
        break;
      case SUPLA_SC_CALL_CHANNELGROUP_RELATION_PACK_UPDATE:
        if (rd.data.sc_channelgroup_relation_pack) {
          supla_client_channelgroup_relation_pack_update(
              scd, rd.data.sc_channelgroup_relation_pack);
        }
        break;
      case SUPLA_SC_CALL_CHANNELVALUE_PACK_UPDATE:
        if (rd.data.sc_channelvalue_pack) {
          supla_client_channelvalue_pack_update(scd,
                                                rd.data.sc_channelvalue_pack);
        }
        break;
      case SUPLA_SC_CALL_CHANNELEXTENDEDVALUE_PACK_UPDATE:
        if (rd.data.sc_channelextendedvalue_pack) {
          supla_client_channelextendedvalue_pack_update(
              scd, rd.data.sc_channelextendedvalue_pack);
        }
        break;
      case SUPLA_SC_CALL_EVENT:
        if (rd.data.sc_event) {
          supla_client_on_event(scd, rd.data.sc_event);
        }
        break;
      case SUPLA_SDC_CALL_GET_REGISTRATION_ENABLED_RESULT:

        if (scd->cfg.cb_on_registration_enabled && rd.data.sdc_reg_enabled) {
          scd->cfg.cb_on_registration_enabled(scd, scd->cfg.user_data,
                                              rd.data.sdc_reg_enabled);
        }
        break;
      case SUPLA_SC_CALL_OAUTH_TOKEN_REQUEST_RESULT:
        if (scd->cfg.cb_on_oauth_token_request_result &&
            rd.data.sc_oauth_tokenrequest_result) {
          supla_client_on_oauth_token_request_result(
              scd, rd.data.sc_oauth_tokenrequest_result);
        }
        break;
      case SUPLA_SC_CALL_SUPERUSER_AUTHORIZATION_RESULT:
        if (scd->cfg.cb_on_superuser_authorization_result &&
            rd.data.sc_superuser_authorization_result) {
          scd->cfg.cb_on_superuser_authorization_result(
              scd, scd->cfg.user_data,
              rd.data.sc_superuser_authorization_result->Result ==
                  SUPLA_RESULTCODE_AUTHORIZED,
              rd.data.sc_superuser_authorization_result->Result);
        }
        break;
      case SUPLA_SC_CALL_DEVICE_CALCFG_RESULT:
        if (scd->cfg.cb_on_device_calcfg_result &&
            rd.data.sc_device_calcfg_result) {
          scd->cfg.cb_on_device_calcfg_result(scd, scd->cfg.user_data,
                                              rd.data.sc_device_calcfg_result);
        }
    }

    srpc_rd_free(&rd);

  } else if (result == (char)SUPLA_RESULT_DATA_ERROR) {
    supla_log(LOG_DEBUG, "DATA ERROR!");
  }
}

void supla_client_cfginit(TSuplaClientCfg *sclient_cfg) {
  memset(sclient_cfg, 0, sizeof(TSuplaClientCfg));
  sclient_cfg->tcp_port = 2015;
  sclient_cfg->ssl_port = 2016;
  sclient_cfg->ssl_enabled = 1;
  sclient_cfg->iterate_wait_usec = 1000000;
}

struct TSuplaClientData* supla_client_init(TSuplaClientCfg *sclient_cfg) {
  struct TSuplaClientData *scd = malloc(sizeof(struct TSuplaClientData));
  memset(scd, 0, sizeof(struct TSuplaClientData));
  memcpy(&scd->cfg, sclient_cfg, sizeof(TSuplaClientCfg));

  scd->lck = lck_init();
  scd->cfg.Email[SUPLA_EMAIL_MAXSIZE - 1] = 0;
  scd->cfg.AccessIDpwd[SUPLA_ACCESSID_PWD_MAXSIZE - 1] = 0;
  scd->cfg.Name[SUPLA_CLIENT_NAME_MAXSIZE - 1] = 0;
  scd->cfg.host = NULL;

  if (sclient_cfg->host != NULL && strlen(sclient_cfg->host) > 0) {
    scd->cfg.host = strdup(sclient_cfg->host);
  }

  scd->ssd = ssocket_client_init(
      scd->cfg.host,
      scd->cfg.ssl_enabled == 1 ? scd->cfg.ssl_port : scd->cfg.tcp_port,
      scd->cfg.ssl_enabled == 1);

  return scd;
}

void supla_client_clean(struct TSuplaClientData *suplaClient)
{
  if (suplaClient == NULL)
    return;

  if (suplaClient->eh)
    eh_free(suplaClient->eh);

  suplaClient->eh = NULL;

  if (suplaClient->srpc)
    srpc_free(suplaClient->srpc);

  suplaClient->srpc = NULL;
}

void supla_client_free(struct TSuplaClientData *suplaClient)
{
  if (suplaClient == NULL)
    return;

  supla_client_disconnect(suplaClient);
  supla_client_clean(suplaClient);

  if (suplaClient->cfg.host)
      free(suplaClient->cfg.host);

  ssocket_free(suplaClient->ssd);
  lck_free(suplaClient->lck);

  free(suplaClient);
}

int supla_client_get_id(struct TSuplaClientData *suplaClient) {
  return suplaClient->client_id;
}

char supla_client_connected(struct TSuplaClientData *suplaClient) {
  return suplaClient->connected == 1;
}

void supla_client_disconnect(struct TSuplaClientData *suplaClient) {

  if (supla_client_connected(suplaClient)) {
    suplaClient->connected = 0;

    supla_client_set_registered(suplaClient, 0);

    ssocket_supla_socket__close(suplaClient->ssd);

    if (suplaClient->cfg.cb_on_disconnected)
      suplaClient->cfg.cb_on_disconnected(suplaClient,
                                          suplaClient->cfg.user_data);
  }
}

char supla_client_connect(struct TSuplaClientData *suplaClient) {
  supla_client_disconnect(suplaClient);

  supla_client_clean(suplaClient);

  int err = 0;

  if (ssocket_client_connect(suplaClient->ssd, NULL, &err) == 1) {
    suplaClient->eh = eh_init();
    TsrpcParams srpc_params;
    srpc_params_init(&srpc_params);
    srpc_params.user_params = suplaClient;
    srpc_params.data_read = &supla_client_socket_read;
    srpc_params.data_write = &supla_client_socket_write;
    srpc_params.on_remote_call_received = &supla_client_on_remote_call_received;
    srpc_params.before_async_call = &supla_client_before_async_call;
    srpc_params.on_min_version_required = &supla_client_on_min_version_required;
    srpc_params.eh = suplaClient->eh;
    suplaClient->srpc = srpc_init(&srpc_params);

    if (suplaClient->cfg.protocol_version > 0) {
      srpc_set_proto_version(suplaClient->srpc,
                             suplaClient->cfg.protocol_version);
    }

    eh_add_fd(suplaClient->eh, ssocket_get_fd(suplaClient->ssd));
    suplaClient->connected = 1;

    supla_client_set_registered(suplaClient, 0);

    if (suplaClient->cfg.cb_on_connected)
      suplaClient->cfg.cb_on_connected(suplaClient, suplaClient->cfg.user_data);

    return 1;

  } else {
    if (suplaClient->cfg.cb_on_connerror)
      suplaClient->cfg.cb_on_connerror(suplaClient, suplaClient->cfg.user_data, err);
  }

  return 0;
}

static void supla_client_register(struct TSuplaClientData *suplaClient)
{
  if (suplaClient->cfg.cb_on_registering)
    suplaClient->cfg.cb_on_registering(suplaClient, suplaClient->cfg.user_data);

  supla_log(LOG_DEBUG, "EMAIL: %s", suplaClient->cfg.Email);

  if (strnlen(suplaClient->cfg.Email, SUPLA_EMAIL_MAXSIZE) > 0 &&
      srpc_call_allowed(suplaClient->srpc, SUPLA_CS_CALL_REGISTER_CLIENT_C)) {

    TCS_SuplaRegisterClient_C src;
    memset(&src, 0, sizeof(TCS_SuplaRegisterClient_C));

    snprintf(src.Email, SUPLA_EMAIL_MAXSIZE, "%s", suplaClient->cfg.Email);
    snprintf(src.Name, SUPLA_CLIENT_NAME_MAXSIZE, "%s", suplaClient->cfg.Name);
    snprintf(src.SoftVer, SUPLA_SOFTVER_MAXSIZE, "%s", suplaClient->cfg.SoftVer);
    snprintf(src.ServerName, SUPLA_SERVER_NAME_MAXSIZE, "%s", suplaClient->cfg.host);

    memcpy(src.AuthKey, suplaClient->cfg.AuthKey, SUPLA_AUTHKEY_SIZE);
    memcpy(src.GUID, suplaClient->cfg.clientGUID, SUPLA_GUID_SIZE);
    srpc_cs_async_registerclient_c(suplaClient->srpc, &src);

  } else if (srpc_call_allowed(suplaClient->srpc, SUPLA_CS_CALL_REGISTER_CLIENT_B)) {
    TCS_SuplaRegisterClient_B src;
    memset(&src, 0, sizeof(TCS_SuplaRegisterClient_B));

    src.AccessID = suplaClient->cfg.AccessID;

    snprintf(src.AccessIDpwd, SUPLA_ACCESSID_PWD_MAXSIZE, "%s", suplaClient->cfg.AccessIDpwd);
    snprintf(src.Name, SUPLA_CLIENT_NAME_MAXSIZE, "%s", suplaClient->cfg.Name);
    snprintf(src.SoftVer, SUPLA_SOFTVER_MAXSIZE, "%s", suplaClient->cfg.SoftVer);
    snprintf(src.ServerName, SUPLA_SERVER_NAME_MAXSIZE, "%s", suplaClient->cfg.host);

    memcpy(src.GUID, suplaClient->cfg.clientGUID, SUPLA_GUID_SIZE);
    srpc_cs_async_registerclient_b(suplaClient->srpc, &src);

  } else if (srpc_call_allowed(suplaClient->srpc, SUPLA_CS_CALL_REGISTER_CLIENT)) {
    TCS_SuplaRegisterClient src;
    memset(&src, 0, sizeof(TCS_SuplaRegisterClient));

    src.AccessID = suplaClient->cfg.AccessID;

    snprintf(src.AccessIDpwd, SUPLA_ACCESSID_PWD_MAXSIZE, "%s", suplaClient->cfg.AccessIDpwd);
    snprintf(src.Name, SUPLA_CLIENT_NAME_MAXSIZE, "%s", suplaClient->cfg.Name);
    snprintf(src.SoftVer, SUPLA_SOFTVER_MAXSIZE, "%s", suplaClient->cfg.SoftVer);

    memcpy(src.GUID, suplaClient->cfg.clientGUID, SUPLA_GUID_SIZE);
    srpc_cs_async_registerclient(suplaClient->srpc, &src);
  }
}

void supla_client_ping(struct TSuplaClientData *suplaClient) {
  struct timeval now;

  if (suplaClient->server_activity_timeout > 0) {
    gettimeofday(&now, NULL);

    int server_activity_timeout = suplaClient->server_activity_timeout - 10;

    if (now.tv_sec - suplaClient->last_ping.tv_sec >= 2 &&
        ((now.tv_sec - suplaClient->last_call_sent.tv_sec) >=
             server_activity_timeout ||
         (now.tv_sec - suplaClient->last_call_recv.tv_sec) >=
             server_activity_timeout)) {
      gettimeofday(&suplaClient->last_ping, NULL);
      srpc_dcs_async_ping_server(suplaClient->srpc);
    }
  }
}

char supla_client_iterate(struct TSuplaClientData *suplaClient, int wait_usec) {

  if (!supla_client_connected(suplaClient))
    return 0;

  if (supla_client_registered(suplaClient)) {
    supla_client_ping(suplaClient);
  } else {
    supla_client_register(suplaClient);
  }

  if (suplaClient->srpc != NULL &&
      srpc_iterate(suplaClient->srpc) == SUPLA_RESULT_FALSE) {
    supla_client_disconnect(suplaClient);
    return 0;
  }

  if (supla_client_connected(suplaClient) == 1 && suplaClient->eh != NULL) {
    eh_wait(suplaClient->eh, wait_usec);
  }

  return 1;
}

void supla_client_raise_event(struct TSuplaClientData *suplaClient) {
  eh_raise_event(suplaClient->eh);
}

void *supla_client_get_userdata(struct TSuplaClientData *suplaClient) {
  return suplaClient->cfg.user_data;
}

char supla_client_send_raw_value(struct TSuplaClientData *suplaClient, int ID,
                                 char value[SUPLA_CHANNELVALUE_SIZE],
                                 char Target) {
  char result = 0;

  lck_lock(suplaClient->lck);
  if (supla_client_registered(suplaClient) == 1) {
    if (srpc_get_proto_version(suplaClient->srpc) >= 9) {
      TCS_SuplaNewValue _value;
      memset(&_value, 0, sizeof(TCS_SuplaNewValue));
      _value.Id = ID;
      _value.Target = Target;
      memcpy(_value.value, value, SUPLA_CHANNELVALUE_SIZE);
      result = srpc_cs_async_set_value(suplaClient->srpc, &_value) ==
                       SUPLA_RESULT_FALSE
                   ? 0
                   : 1;
    } else {
      TCS_SuplaChannelNewValue_B _value;
      memset(&_value, 0, sizeof(TCS_SuplaChannelNewValue_B));
      _value.ChannelId = ID;
      memcpy(_value.value, value, SUPLA_CHANNELVALUE_SIZE);
      result = srpc_cs_async_set_channel_value_b(suplaClient->srpc, &_value) ==
                       SUPLA_RESULT_FALSE
                   ? 0
                   : 1;
    }
  }
  lck_unlock(suplaClient->lck);

  return result;
}

char supla_client_open(struct TSuplaClientData *suplaClient, int ID, char group, char open) {
  char value[SUPLA_CHANNELVALUE_SIZE];
  memset(value, 0, SUPLA_CHANNELVALUE_SIZE);
  value[0] = open;

  return supla_client_send_raw_value(
      suplaClient, ID, value, group > 0 ? SUPLA_NEW_VALUE_TARGET_GROUP
                                         : SUPLA_NEW_VALUE_TARGET_CHANNEL);
}

void _supla_client_set_rgbw_value(char *value, int color, char color_brightness,
                                  char brightness) {
  value[0] = brightness;
  value[1] = color_brightness;
  value[2] = (char)((color & 0x000000FF));        // BLUE
  value[3] = (char)((color & 0x0000FF00) >> 8);   // GREEN
  value[4] = (char)((color & 0x00FF0000) >> 16);  // RED
}

char supla_client_set_rgbw(struct TSuplaClientData* suplaClient, int ID, char group, int color,
                           char color_brightness, char brightness) {
  char result = 0;

  lck_lock(suplaClient->lck);
  if (supla_client_registered(suplaClient) == 1) {
    if (srpc_get_proto_version(suplaClient->srpc) >= 9) {
      TCS_SuplaNewValue value;
      memset(&value, 0, sizeof(TCS_SuplaNewValue));
      _supla_client_set_rgbw_value(value.value, color, color_brightness,
                                   brightness);
      value.Id = ID;
      value.Target = group > 0 ? SUPLA_NEW_VALUE_TARGET_GROUP
                               : SUPLA_NEW_VALUE_TARGET_CHANNEL;
      result = srpc_cs_async_set_value(suplaClient->srpc, &value) ==
                       SUPLA_RESULT_FALSE
                   ? 0
                   : 1;
    } else {
      TCS_SuplaChannelNewValue_B value;
      memset(&value, 0, sizeof(TCS_SuplaChannelNewValue_B));
      _supla_client_set_rgbw_value(value.value, color, color_brightness,
                                   brightness);
      value.ChannelId = ID;

      result = srpc_cs_async_set_channel_value_b(suplaClient->srpc, &value) ==
                       SUPLA_RESULT_FALSE
                   ? 0
                   : 1;
    }
  }
  lck_unlock(suplaClient->lck);

  return result;
}

char supla_client_set_dimmer(struct TSuplaClientData *suplaClient, int ID, char group,
                             char brightness) {
  return supla_client_set_rgbw(suplaClient, ID, group, 0, 0, brightness);
}

char supla_client_get_registration_enabled(struct TSuplaClientData *suplaClient) {
  return srpc_dcs_async_get_registration_enabled(suplaClient->srpc);
}

unsigned char supla_client_get_proto_version(struct TSuplaClientData *suplaClient) {
  return srpc_get_proto_version(suplaClient->srpc);
}

char supla_client_oauth_token_request(struct TSuplaClientData *suplaClient) {
  return srpc_cs_async_oauth_token_request(suplaClient->srpc) > 0;
}

char supla_client_superuser_authorization_request(struct TSuplaClientData *suplaClient,
                                                  char *email, char *password) {
  TCS_SuperUserAuthorizationRequest request;
  snprintf(
      request.Email, SUPLA_EMAIL_MAXSIZE, "%s",
      email == NULL ? suplaClient->cfg.Email : email);
  snprintf(request.Password, SUPLA_PASSWORD_MAXSIZE, "%s", password);

  return srpc_cs_async_superuser_authorization_request(suplaClient->srpc, &request);
}

char supla_client_device_calcfg_request(struct TSuplaClientData *suplaClient,
                                        TCS_DeviceCalCfgRequest *request) {
  if (request == NULL) return 0;
  return srpc_cs_async_device_calcfg_request(suplaClient->srpc, request);
}
