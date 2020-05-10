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
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "waflz/engine.h"
#include "waflz/profile.h"
#include "waflz/instances.h"
#include "waflz/rqst_ctx.h"
#include "waflz/geoip2_mmdb.h"
#include "waflz/def.h"
#include "waflz/trace.h"
#include "profile.pb.h"
#include "event.pb.h"
#include "support/ndebug.h"
#include "support/file_util.h"
#include <unistd.h>
#include <iostream>
//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
#ifndef STATUS_OK
  #define STATUS_OK 0
#endif
#ifndef STATUS_ERROR
  #define STATUS_ERROR -1
#endif

// external api
typedef struct waflz_profile_t waflz_profile_t;
typedef struct waflz_transaction_t waflz_transaction_t;

waflz_profile_t* waflz_profile_new_load(const char* rule_dir, const char* profile_file_name);
int32_t waflz_profile_process(waflz_profile_t* wp, waflz_transaction_t* tx);
void waflz_profile_clean(waflz_profile_t* wp);

waflz_transaction_t *waflz_new_transaction(waflz_profile_t *profile);
int waflz_process_connection(waflz_transaction_t *t, const char *client_ip, const char *host, int port, const char* method, const char *scheme);
int waflz_process_uri(waflz_transaction_t *t, const char *url, const char *uri, const char *path, const char *query, const char *protocol, const char *http_version);
int waflz_add_request_header(waflz_transaction_t *transaction, const char *key, const char *value);
void waflz_transaction_cleanup(waflz_transaction_t *transaction);

struct waflz_profile_t {
    ns_waflz::profile* profile;
    ns_waflz::engine*  engine;
};

struct waflz_transaction_t {
    waflz_profile_t* profile;

    //int waflz_process_connection(waflz_transaction_t *t, const char *client_ip, const char *host, int port, const char* method, const char *scheme)
    const char *client_ip;
    const char *host;
    int port;
    const char *method;
    const char *scheme;

    //int waflz_process_uri(waflz_transaction_t *t, const char *url, const char *uri, const char *path, const char *query, const char *protocol, const char *http_version);
    const char *url;  //(REQUEST_URI_RAW)  "http://127.0.0.1/test.pl?param1=test&para2=test2"
    const char *uri;  //(REQUEST_URI) : This variable holds the full request URL including the query string data (e.g., /index.php?p=X). However, it will never contain a domain name, even if it was provided on the request line.
    const char *path;  //1. (REQUEST_FILENAME): This variable holds the relative request URL without the query string part (e.g., /index.php).
                       //2. (REQUEST_BASENAME): This variable holds just the filename part of REQUEST_FILENAME (e.g., index.php).
    const char *query;  //(ARGS): ARGS is a collection and can be used on its own (means all arguments including the POST Payload),
    const char *protocol;
    const char *http_version;

    //int waflz_add_request_header(waflz_transaction_t *transaction, const char *key, const char *value)
    std::vector<std::pair<const char*, const char*> > headers;  //consider std::array<N, std::pair<> >, where N is 20?

    //synthetics
    std::string rqst_line;  // GET /index.html HTTP/1.1
    std::string rqst_protocol;  // HTTP/1.1
};

//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
//static const char *s_ip = "127.0.0.1";
static int32_t get_rqst_src_addr_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        waflz_transaction_t* t = (waflz_transaction_t*)a_ctx;
        std::cout << "get_rqst_src_addr_cb: " << t->client_ip << "\n";
        *a_data = t->client_ip;  //s_ip;
        a_len = strlen(t->client_ip);  //strlen(s_ip);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_line_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        waflz_transaction_t* t = (waflz_transaction_t*)a_ctx;
        t->rqst_line.assign(t->method);
        t->rqst_line.append(" ");
        t->rqst_line.append(t->uri);
        t->rqst_line.append(" ");
        t->rqst_line.append(t->protocol);
        t->rqst_line.append("/");
        t->rqst_line.append(t->http_version);
        std::cout << "get_rqst_line_cb: " << t->rqst_line << "\n";
        //static const char s_line[] = "GET /test.pl HTTP/1.1";
        *a_data = t->rqst_line.c_str();  //s_line;
        a_len = t->rqst_line.size();  //strlen(s_line);
        return 0;
}
//! ----------------------------------------------------------------------------
//! get host callback
//! ----------------------------------------------------------------------------
static int32_t get_rqst_host_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        waflz_transaction_t* t = (waflz_transaction_t*)a_ctx;
        std::cout << "get_rqst_host_cb: " << t->host << "\n";
        //static const char s_uri[] = "127.0.0.1";
        *a_data = t->host;  //s_uri;
        a_len = strlen(t->host);  //strlen(s_uri);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_query_str_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        waflz_transaction_t* t = (waflz_transaction_t*)a_ctx;
        std::cout << "get_rqst_query_str_cb: " << t->query << "\n";
        //static const char s_line[] = "param1=test&para2=test2";  //TODO no question mark?
        *a_data = t->query;  //s_line;
        a_len = strlen(t->query);  //strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
//static const char *s_uri = "/test.pl";
static int32_t get_rqst_uri_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        waflz_transaction_t* t = (waflz_transaction_t*)a_ctx;
        std::cout << "get_rqst_uri_cb: " << t->uri << "\n";
        *a_data = t->uri;  //s_uri;
        a_len = strlen(t->uri);  //strlen(s_uri);
        return 0;
}
//: ----------------------------------------------------------------------------
//: s_get_rqst_method_cb
//: ----------------------------------------------------------------------------
//static const char *s_method = "GET";
static int32_t get_rqst_method_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        waflz_transaction_t* t = (waflz_transaction_t*)a_ctx;
        std::cout << "get_rqst_method_cb: " << t->method << "\n";
        *a_data = t->method;  //s_method;
        a_len = strlen(t->method);  //strlen(s_method);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_protocol_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        waflz_transaction_t* t = (waflz_transaction_t*)a_ctx;
        t->rqst_protocol.assign(t->protocol);
        t->rqst_protocol.append("/");
        t->rqst_protocol.append(t->http_version);
        std::cout << "get_rqst_protocol_cb: " << t->rqst_protocol << "\n";
        //static const char s_line[] = "HTTP/1.1";
        *a_data = t->rqst_protocol.c_str();  //s_line;
        a_len = t->rqst_protocol.size();  //strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_scheme_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        waflz_transaction_t* t = (waflz_transaction_t*)a_ctx;
        std::cout << "get_rqst_scheme_cb: " << t->scheme << "\n";
        //static const char s_line[] = "http";
        *a_data = t->scheme;  //s_line;
        a_len = strlen(t->scheme);  //strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_port_cb(uint32_t &a_val, void *a_ctx)
{
        waflz_transaction_t* t = (waflz_transaction_t*)a_ctx;
        std::cout << "get_rqst_port_cb: " << t->port << "\n";
        a_val = t->port;  //80;
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_url_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        waflz_transaction_t* t = (waflz_transaction_t*)a_ctx;
        std::cout << "get_rqst_url_cb: " << t->url << "\n";
        //static const char s_line[] = "127.0.0.1/test.pl?param1=test&para2=test2";
        *a_data = t->url;  //s_line;
        a_len = strlen(t->url);  //strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: s_get_rqst_path_cb
//: ----------------------------------------------------------------------------
//static const char *s_path = "/test.pl";
static int32_t get_rqst_path_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        waflz_transaction_t* t = (waflz_transaction_t*)a_ctx;
        std::cout << "get_rqst_path_cb: " << t->path << "\n";
        *a_data = t->path;  //s_path;
        a_len = strlen(t->path);  //strlen(s_path);
        return 0;
}
//: ----------------------------------------------------------------------------
//:+ get_rqst_header_size_cb
//: ----------------------------------------------------------------------------
static int32_t get_rqst_header_size_cb(uint32_t &a_val, void *a_ctx)
{
        waflz_transaction_t* t = (waflz_transaction_t*)a_ctx;
        std::cout << "get_rqst_header_size_cb: " << t->headers.size() << "\n";
        a_val = t->headers.size();  //10;
        return 0;
}
//: ----------------------------------------------------------------------------
//:+ get_rqst_header_w_idx_cb
//: ----------------------------------------------------------------------------
static const char *s_header_k0 = "Host";
static const char *s_header_v0 = "net.tutsplus.com";
static const char *s_header_k1 = "User-Agent";
static const char *s_header_v1 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.5) " \
                                 "Gecko/20091102 Firefox/3.5.5 (.NET CLR 3.5.30729)";
static const char *s_header_k2 = "Accept";
static const char *s_header_v2 = "text/html,application/xhtml+xml,application/xml;" \
                                 "q=0.9,*/*;q=0.8";
static const char *s_header_k3 = "Accept-Language";
static const char *s_header_v3 = "en-us,en;q=0.5";
static const char *s_header_k4 = "Accept-Encoding";
static const char *s_header_v4 = "gzip,deflate";
static const char *s_header_k5 = "Accept-Charset";
static const char *s_header_v5 = "ISO-8859-1,utf-8;q=0.7,*;q=0.7";
static const char *s_header_k6 = "Keep-Alive";
static const char *s_header_v6 = "300";
static const char *s_header_k7 = "Connection";
static const char *s_header_v7 = "keep-alive";
static const char *s_header_k8 = "Cookie";
static const char *s_header_v8 = "PHPSESSID=r2t5uvjq435r4q7ib3vtdjq120";
static const char *s_header_k9 = "Pragma";
static const char *s_header_v9 = "no-cache";
static const char *s_header_k10 = "Cache-Control";
static const char *s_header_v10 = "no-cache";

static int32_t get_rqst_header_w_idx_cb(const char **ao_key,
                                        uint32_t &ao_key_len,
                                        const char **ao_val,
                                        uint32_t &ao_val_len,
                                        void *a_ctx,
                                        uint32_t a_idx)
{
        waflz_transaction_t* t = (waflz_transaction_t*)a_ctx;
        *ao_key = NULL;
        ao_key_len = 0;
        *ao_val = NULL;
        ao_val_len = 0;
        if (t->headers.size() > 0 && a_idx < t->headers.size())
        {
                std::cout << "get_rqst_header_w_idx_cb: a_idx: " << a_idx << " k: [" << t->headers[a_idx].first << "] v: [" << t->headers[a_idx].second << "]\n";
                *ao_key = t->headers[a_idx].first;
                ao_key_len = strlen(t->headers[a_idx].first);
                *ao_val = t->headers[a_idx].second;
                ao_val_len = strlen(t->headers[a_idx].second);
        }
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_body_str_cb
//: ----------------------------------------------------------------------------
#define _RQST_BODY_JSON "{\"monkeys\": \"bananas\", \"koalas\": \"fruitloops\", \"seamonkeys\": \"plankton\"}"
#define _RQST_BODY_XML "<monkeys><gorilla>coco</gorilla><mandrill>dooby</mandrill><baboon>groovy</baboon></monkeys>"
static const char *g_body_str = _RQST_BODY_JSON;
static int32_t get_rqst_body_str_cb(char *ao_data,
                                    uint32_t &ao_data_len,
                                    bool &ao_is_eos,
                                    void *a_ctx,
                                    uint32_t a_to_read)
{
        ao_data_len = strlen(g_body_str);
        memcpy(ao_data, g_body_str, ao_data_len);
        ao_is_eos = true;
        return 0;
}

waflz_profile_t* waflz_profile_new_load(const char* rule_dir,
                                        const char* profile_file_name)
{
    //TODO must be a singleton
    waflz_profile_t* wp = new waflz_profile_t;
    
    wp->engine = new ns_waflz::engine();
    wp->engine->set_ruleset_dir(rule_dir); //done

    int32_t l_s = wp->engine->init(); //done
    REQUIRE((l_s == WAFLZ_STATUS_OK));

    char *l_buf;
    uint32_t l_buf_len;

    l_s = ns_waflz::read_file(profile_file_name, &l_buf, l_buf_len);
    if(l_s != WAFLZ_STATUS_OK) {
        NDBG_PRINT("error read_file: %s\n", profile_file_name);
        return nullptr;
    }

    wp->profile = new ns_waflz::profile(*wp->engine);

    l_s = wp->profile->load(l_buf, l_buf_len);
    NDBG_PRINT("error[%d]: %s\n", l_s, wp->profile->get_err_msg());
    REQUIRE((l_s == WAFLZ_STATUS_OK));
    
    ns_waflz::rqst_ctx::s_get_rqst_src_addr_cb = get_rqst_src_addr_cb;
    ns_waflz::rqst_ctx::s_get_rqst_line_cb = get_rqst_line_cb;
    ns_waflz::rqst_ctx::s_get_rqst_uri_cb = get_rqst_uri_cb;
    ns_waflz::rqst_ctx::s_get_rqst_url_cb = get_rqst_url_cb;
    ns_waflz::rqst_ctx::s_get_rqst_header_size_cb = get_rqst_header_size_cb;
    ns_waflz::rqst_ctx::s_get_rqst_header_w_idx_cb = get_rqst_header_w_idx_cb;
    ns_waflz::rqst_ctx::s_get_rqst_scheme_cb = get_rqst_scheme_cb;
    ns_waflz::rqst_ctx::s_get_rqst_port_cb = get_rqst_port_cb;
    ns_waflz::rqst_ctx::s_get_rqst_method_cb = get_rqst_method_cb;
    ns_waflz::rqst_ctx::s_get_rqst_path_cb = get_rqst_path_cb;
    ns_waflz::rqst_ctx::s_get_rqst_host_cb = get_rqst_host_cb;
    ns_waflz::rqst_ctx::s_get_rqst_protocol_cb = get_rqst_protocol_cb;
    ns_waflz::rqst_ctx::s_get_rqst_query_str_cb = get_rqst_query_str_cb;
    //--?? ns_waflz::rqst_ctx::s_get_rqst_uuid_cb = get_rqst_uuid_cb;
    //--?? ns_waflz::rqst_ctx::s_get_rqst_body_str_cb = get_rqst_body_str_cb;

    return wp;
}

int32_t waflz_profile_process(waflz_transaction_t* tx)
{
    void *l_ctx = tx;
    waflz_pb::event *l_event = NULL;
    ns_waflz::rqst_ctx *l_rqst_ctx = NULL;

    int32_t l_s = tx->profile->profile->process(&l_event, l_ctx, ns_waflz::PART_MK_ALL, &l_rqst_ctx);
    REQUIRE((l_s == WAFLZ_STATUS_OK));
    if (l_event) {
        REQUIRE((l_event->sub_event_size() >= 1));
        REQUIRE((l_event->sub_event(0).has_rule_msg()));
        //REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist IP match"));
        NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
    }
    if(l_event) { delete l_event; }
    if(l_rqst_ctx) { delete l_rqst_ctx; }
    return l_s;
}

void waflz_profile_clean(waflz_profile_t* wp)
{
    delete wp->profile;
    delete wp->engine;
    delete wp;
}

waflz_transaction_t *waflz_new_transaction(waflz_profile_t *profile)
{
    waflz_transaction_t *t = new waflz_transaction_t;
    t->profile = profile;
    return t;
}

int waflz_process_connection(waflz_transaction_t *t, const char *client_ip, const char *host, int port, const char* method, const char *scheme)
{
    t->client_ip = client_ip;
    t->host = host;
    t->port = port;
    t->method = method;
    t->scheme = scheme;
}

int waflz_process_uri(waflz_transaction_t *t, const char *url, const char *uri, const char *path, const char *query, const char *protocol, const char *http_version)
{
    t->url = url;
    t->uri = uri;
    t->path = path;
    t->query = query;
    t->protocol = protocol;
    t->http_version = http_version;
}

int waflz_add_request_header(waflz_transaction_t *t, const char *key, const char *value)
{
    t->headers.emplace_back(std::pair<const char*, const char*>(key, value));
}

void waflz_transaction_cleanup(waflz_transaction_t *transaction)
{
    delete transaction;
}

//: ----------------------------------------------------------------------------
//: benchmark tests
//: ----------------------------------------------------------------------------
TEST_CASE( "benchmark test", "[benchmark2]" )
{
        ns_waflz::trc_level_set(ns_waflz::WFLZ_TRC_LEVEL_ALL);
        ns_waflz::trc_file_open("/dev/stdout");

        // -------------------------------------------------
        // get ruleset dir
        // -------------------------------------------------
        char l_cwd[1024];
        if(getcwd(l_cwd, sizeof(l_cwd)) != NULL)
        {
                //fprintf(stdout, "Current working dir: %s\n", cwd);
        }
        std::string l_rule_dir = l_cwd;
        l_rule_dir += "/../../../../tests/data/waf/ruleset/";

        //--------------------------------------------------
        // acl
        // -------------------------------------------------
        SECTION("benchmark tests") {
                // -----------------------------------------
                // setup
                // -----------------------------------------
                //-- std::string l_profile_file_name("../../../../tests/blackbox/ruleset/template.waf.prof.json");
                //-- std::string l_profile_file_name("../../../../tests/blackbox/rules/test_bb_rtu.waf.prof.json");
                std::string l_profile_file_name("../../../../tests/blackbox/rules/test_bb_rtu-ats.waf.prof.json");
                waflz_profile_t* wp = waflz_profile_new_load(l_rule_dir.c_str(), l_profile_file_name.c_str());

                unsigned long long NUM_REQUESTS(1);
                std::cout << "Doing " << NUM_REQUESTS << " transactions...\n";
                for (unsigned long long i = 0; i < NUM_REQUESTS; i++) {
                    waflz_transaction_t* tx = waflz_new_transaction(wp);
                    
                    waflz_process_connection(tx, "127.0.0.1", "127.0.0.1", 80, "GET", "http");
                    //waflz_process_uri(tx, "http://127.0.0.1/test.pl?param1=test&para2=test2", "/test.pl?param1=test&para2=test2", "/test.pl", "param1=test&para2=test2", "HTTP", "1.1");
                    waflz_process_uri(tx, "/test.pl?param1=test&para2=test2", "/test.pl?param1=test&para2=test2", "/test.pl?param1=test&para2=test2", "param1=test&para2=test2", "HTTP", "1.1");

                    waflz_add_request_header(tx, s_header_k0, s_header_v0);
                    waflz_add_request_header(tx, s_header_k1, s_header_v1);
                    waflz_add_request_header(tx, s_header_k2, s_header_v2);
                    waflz_add_request_header(tx, s_header_k3, s_header_v3);
                    waflz_add_request_header(tx, s_header_k4, s_header_v4);
                    waflz_add_request_header(tx, s_header_k5, s_header_v5);
                    waflz_add_request_header(tx, s_header_k6, s_header_v6);
                    waflz_add_request_header(tx, s_header_k7, s_header_v7);
                    waflz_add_request_header(tx, s_header_k8, s_header_v8);
                    waflz_add_request_header(tx, s_header_k9, s_header_v9);
                    waflz_add_request_header(tx, s_header_k10, s_header_v10);
                    
                    int32_t l_s = waflz_profile_process(tx);
                    REQUIRE((l_s == WAFLZ_STATUS_OK));
                    delete tx;
                }

                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                waflz_profile_clean(wp);
        }
}
