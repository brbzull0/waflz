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
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static const char *s_ip = "127.0.0.1";
static int32_t get_rqst_src_addr_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        *a_data = s_ip;
        a_len = strlen(s_ip);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_line_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "GET /test.pl HTTP/1.1";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//! ----------------------------------------------------------------------------
//! get host callback
//! ----------------------------------------------------------------------------
static int32_t get_rqst_host_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_uri[] = "127.0.0.1";
        *a_data = s_uri;
        a_len = strlen(s_uri);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_query_str_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "param1=test&para2=test2";  //TODO no question mark?
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static const char *s_uri = "/test.pl";
static int32_t get_rqst_uri_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        *a_data = s_uri;
        a_len = strlen(s_uri);
        return 0;
}
//: ----------------------------------------------------------------------------
//: s_get_rqst_method_cb
//: ----------------------------------------------------------------------------
static const char *s_method = "GET";
static int32_t get_rqst_method_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        *a_data = s_method;
        a_len = strlen(s_method);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_protocol_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "HTTP/1.1";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_scheme_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "http";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_port_cb(uint32_t &a_val, void *a_ctx)
{
        a_val = 80;
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_url_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "127.0.0.1/test.pl?param1=test&para2=test2";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: s_get_rqst_path_cb
//: ----------------------------------------------------------------------------
static const char *s_path = "/test.pl";
static int32_t get_rqst_path_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        *a_data = s_path;
        a_len = strlen(s_path);
        return 0;
}
//: ----------------------------------------------------------------------------
//:+ get_rqst_header_size_cb
//: ----------------------------------------------------------------------------
static int32_t get_rqst_header_size_cb(uint32_t &a_val, void *a_ctx)
{
        a_val = 10;
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
        *ao_key = NULL;
        ao_key_len = 0;
        *ao_val = NULL;
        ao_val_len = 0;
        switch(a_idx)
        {
        case 0:
        {
                *ao_key = s_header_k0;
                ao_key_len = strlen(s_header_k0);
                *ao_val = s_header_v0;
                ao_val_len = strlen(s_header_v0);
                break;
        }
        case 1:
        {
                *ao_key = s_header_k1;
                ao_key_len = strlen(s_header_k1);
                *ao_val = s_header_v1;
                ao_val_len = strlen(s_header_v1);
                break;
        }
        case 2:
        {
                *ao_key = s_header_k2;
                ao_key_len = strlen(s_header_k2);
                *ao_val = s_header_v2;
                ao_val_len = strlen(s_header_v2);
                break;
        }
        case 3:
        {
                *ao_key = s_header_k3;
                ao_key_len = strlen(s_header_k3);
                *ao_val = s_header_v3;
                ao_val_len = strlen(s_header_v3);
                break;
        }
        case 4:
        {
                *ao_key = s_header_k4;
                ao_key_len = strlen(s_header_k4);
                *ao_val = s_header_v4;
                ao_val_len = strlen(s_header_v4);
                break;
        }
        case 5:
        {
                *ao_key = s_header_k5;
                ao_key_len = strlen(s_header_k5);
                *ao_val = s_header_v5;
                ao_val_len = strlen(s_header_v5);
                break;
        }
        case 6:
        {
                *ao_key = s_header_k6;
                ao_key_len = strlen(s_header_k6);
                *ao_val = s_header_v6;
                ao_val_len = strlen(s_header_v6);
                break;
        }
        case 7:
        {
                *ao_key = s_header_k7;
                ao_key_len = strlen(s_header_k7);
                *ao_val = s_header_v7;
                ao_val_len = strlen(s_header_v7);
                break;
        }
        case 8:
        {
                *ao_key = s_header_k8;
                ao_key_len = strlen(s_header_k8);
                *ao_val = s_header_v8;
                ao_val_len = strlen(s_header_v8);
                break;
        }
        case 9:
        {
                *ao_key = s_header_k9;
                ao_key_len = strlen(s_header_k9);
                *ao_val = s_header_v9;
                ao_val_len = strlen(s_header_v9);
                break;
        }
        case 10:
        {
                *ao_key = s_header_k10;
                ao_key_len = strlen(s_header_k10);
                *ao_val = s_header_v10;
                ao_val_len = strlen(s_header_v10);
                break;
        }
        default:
        {
                break;
        }
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
//: ----------------------------------------------------------------------------
//: benchmark tests
//: ----------------------------------------------------------------------------
TEST_CASE( "benchmark test", "[benchmark]" )
{
        //--ns_waflz::trc_level_set(ns_waflz::WFLZ_TRC_LEVEL_ALL);
        //--ns_waflz::trc_file_open("/dev/stdout");

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

        // -------------------------------------------------
        // geoip
        // -------------------------------------------------
        std::string l_geoip2_city_file = l_cwd;
        std::string l_geoip2_asn_file = l_cwd;
        l_geoip2_city_file += "/../../../../tests/data/waf/db/GeoLite2-City.mmdb";
        l_geoip2_asn_file += "/../../../../tests/data/waf/db/GeoLite2-ASN.mmdb";
        //--------------------------------------------------
        // acl
        // -------------------------------------------------
        SECTION("benchmark tests") {
                // -----------------------------------------
                // setup
                // -----------------------------------------
                ns_waflz::engine *l_engine = new ns_waflz::engine();

                //-- l_engine->set_geoip2_dbs(l_geoip2_city_file, l_geoip2_asn_file); //done

                l_engine->set_ruleset_dir(l_rule_dir); //done

                int32_t l_s;
                l_s = l_engine->init(); //done
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -------------------------------------------------
                // read file: profle
                // -------------------------------------------------
                char *l_buf;
                uint32_t l_buf_len;

                //-- std::string l_profile_file_name("../../../../tests/blackbox/ruleset/template.waf.prof.json");
                //-- std::string l_profile_file_name("../../../../tests/blackbox/rules/test_bb_rtu.waf.prof.json");
                std::string l_profile_file_name("../../../../tests/blackbox/rules/test_bb_rtu-ats.waf.prof.json");
                l_s = ns_waflz::read_file(l_profile_file_name.c_str(), &l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error read_file: %s\n", l_profile_file_name.c_str());
                        return /*STATUS_ERROR*/;
                }
                ns_waflz::profile *l_profile = new ns_waflz::profile(*l_engine);

                // -----------------------------------------
                // load
                // -----------------------------------------
                l_s = l_profile->load(l_buf, l_buf_len);
                NDBG_PRINT("error[%d]: %s\n", l_s, l_profile->get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_OK));

                // -----------------------------------------
                // cb
                // -----------------------------------------
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

                void *l_ctx = NULL;
                waflz_pb::event *l_event = NULL;
                ns_waflz::rqst_ctx *l_rqst_ctx = NULL;

                unsigned long long NUM_REQUESTS(100000);
                std::cout << "Doing " << NUM_REQUESTS << " transactions...\n";
                for (unsigned long long i = 0; i < NUM_REQUESTS; i++) {
                    l_s = l_profile->process(&l_event, l_ctx, ns_waflz::PART_MK_ALL, &l_rqst_ctx);
                    REQUIRE((l_s == WAFLZ_STATUS_OK));
                    if (l_event) {
                        REQUIRE((l_event->sub_event_size() >= 1));
                        REQUIRE((l_event->sub_event(0).has_rule_msg()));
                        //REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist IP match"));
                        NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                    }
                    if(l_event) { delete l_event; l_event = NULL; }
                    if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                }

                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_profile)
                {
                        delete l_profile;
                        l_profile = NULL;
                }
                if(l_engine)
                {
                        delete l_engine;
                        l_engine = NULL;
                }
        }
}
