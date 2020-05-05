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
#include <unistd.h>
#include <iostream>
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static waflz_pb::profile *init_std_profile_pb(void)
{
        // -----------------------------------------
        // setup...
        // -----------------------------------------
        waflz_pb::profile *l_pb = NULL;
        l_pb = new waflz_pb::profile();
        l_pb->set_id("my_id");
        l_pb->set_name("my_name");
        //l_pb->set_ruleset_id("OWASP-CRS-2.2.9");
        //l_pb->set_ruleset_version("2017-08-01");
        l_pb->set_ruleset_id("OWASP-CRS-3.2");
        l_pb->set_ruleset_version("2018-10-04");
        // -----------------------------------------
        // general settings -required fields
        // -----------------------------------------
        ::waflz_pb::profile_general_settings_t* l_gx = NULL;
        l_gx = l_pb->mutable_general_settings();
        l_gx->set_process_request_body(true);
        l_gx->set_xml_parser(true);
        l_gx->set_process_response_body(false);
        l_gx->set_validate_utf8_encoding(true);
        l_gx->set_max_num_args(3);
        l_gx->set_arg_name_length(100);
        l_gx->set_arg_length(400);
        l_gx->set_total_arg_length(64000);
        l_gx->set_max_file_size(1048576);
        l_gx->set_combined_file_sizes(1048576);
        l_gx->add_allowed_http_methods("GET");
        l_gx->add_allowed_request_content_types("html");
        // -----------------------------------------
        // add policies
        // -----------------------------------------
        //-- l_pb->add_policies("modsecurity_crs_21_protocol_anomalies.conf");
        //-- l_pb->add_policies("modsecurity_crs_49_inbound_blocking.conf");
        // -----------------------------------------
        // anomaly settings -required fields
        // -----------------------------------------
        l_gx->set_anomaly_threshold(1);
        // -----------------------------------------
        // access settings -required fields
        // -----------------------------------------
        ::waflz_pb::acl* l_ax = NULL;
        l_ax = l_pb->mutable_access_settings();
        ::waflz_pb::acl_lists_t* l_ax_ip = l_ax->mutable_ip();
        UNUSED(l_ax_ip);
        ::waflz_pb::acl_lists_t* l_ax_cntry = l_ax->mutable_country();
        UNUSED(l_ax_cntry);
        ::waflz_pb::acl_lists_t* l_ax_url = l_ax->mutable_url();
        UNUSED(l_ax_url);
        ::waflz_pb::acl_lists_t* l_ax_refr = l_ax->mutable_referer();
        UNUSED(l_ax_refr);
        return l_pb;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static const char *s_ip = "127.0.0.11";
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
    //-- static const char s_line[] = "bananas.com/test.pl?param1=test&para2=test2";
    //-- static const char s_line[] = "bananas.com/test.pl??exec=/bin/bash";
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
  ns_waflz::trc_level_set(ns_waflz::WFLZ_TRC_LEVEL_ALL);  //_RULE
    ns_waflz::trc_file_open("/dev/stdout");
    //std::cout << "argc:" << argc << " argv[0]:" << argv[0] << "\n";
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
        //l_rule_dir += "/../tests/data/waf/ruleset/";
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
                l_engine->set_geoip2_dbs(l_geoip2_city_file, l_geoip2_asn_file);
                l_engine->set_ruleset_dir(l_rule_dir);
                int32_t l_s;
                l_s = l_engine->init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                ns_waflz::profile *l_profile = new ns_waflz::profile(*l_engine);
                waflz_pb::profile *l_pb = init_std_profile_pb();

                // -----------------------------------------
                // load
                // -----------------------------------------
                l_s = l_profile->load(l_pb);
                NDBG_PRINT("error[%d]: %s\n", l_s, l_profile->get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                if(l_pb) { delete l_pb; l_pb = NULL;}

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
                ns_waflz::rqst_ctx::s_get_rqst_body_str_cb = get_rqst_body_str_cb;
                void *l_ctx = NULL;
                waflz_pb::event *l_event = NULL;
                ns_waflz::rqst_ctx *l_rqst_ctx = NULL;

                unsigned long long NUM_REQUESTS(1);
                std::cout << "Doing " << NUM_REQUESTS << " transactions...\n";
                for (unsigned long long i = 0; i < NUM_REQUESTS; i++) {
                    //std::cout << "Proceeding with request " << i << std::endl;
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
                if(l_pb)
                {
                        delete l_pb;
                        l_pb = NULL;
                }
                if(l_engine)
                {
                        delete l_engine;
                        l_engine = NULL;
                }
        }
}
