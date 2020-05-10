//: ----------------------------------------------------------------------------
//: Copyright (C) 2017 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    wb_profile_acl.cc
//: \details: TODO
//: \author:  Reed Morrison
//: \date:    12/30/2017
//:
//:   Licensed under the Apache License, Version 2.0 (the "License");
//:   you may not use this file except in compliance with the License.
//:   You may obtain a copy of the License at
//:
//:       http://www.apache.org/licenses/LICENSE-2.0
//:
//:   Unless required by applicable law or agreed to in writing, software
//:   distributed under the License is distributed on an "AS IS" BASIS,
//:   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//:   See the License for the specific language governing permissions and
//:   limitations under the License.
//:
//: ----------------------------------------------------------------------------


#ifndef _WAFLZ_TS_H_
#define _WAFLZ_TS_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct waflz_profile_t waflz_profile_t;
typedef struct waflz_transaction_t waflz_transaction_t;

waflz_profile_t* waflz_profile_new_load(const char* rule_dir, const char* profile_file_name);
int waflz_profile_process(waflz_transaction_t* tx);
void waflz_profile_clean(waflz_profile_t* wp);

waflz_transaction_t *waflz_new_transaction(waflz_profile_t *profile);
int waflz_transaction_add_connection(waflz_transaction_t *t, const char *client_ip, const char *host, int port, const char* method, const char *scheme);
int waflz_transaction_add_uri(waflz_transaction_t *t, const char *url, const char *uri, const char *path, const char *query, const char *protocol, const char *http_version);
int waflz_transaction_add_request_header(waflz_transaction_t *transaction, const char *key, const char *value);
void waflz_transaction_clean(waflz_transaction_t *transaction);

#ifdef __cplusplus
}
#endif

#endif
