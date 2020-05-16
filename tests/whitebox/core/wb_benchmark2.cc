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
#include <waflz_ts.h>

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
                    int trace = 0;
                    waflz_transaction_t* tx = waflz_new_transaction(wp, trace);
                    
                    waflz_transaction_add_request_connection_uri(tx, "127.0.0.1", "127.0.0.1", 80, "GET", "http",
                                                                 "/test.pl?param1=test&para2=test2", //url
                                                                 "/test.pl?param1=test&para2=test2", //uri
                                                                 "/test.pl", //path,
                                                                 "param1=test&para2=test2", //query
                                                                 "HTTP", //protocol
                                                                 "1.1"); //protocol version

                    waflz_transaction_add_request_header(tx, s_header_k0, s_header_v0);
                    waflz_transaction_add_request_header(tx, s_header_k1, s_header_v1);
                    waflz_transaction_add_request_header(tx, s_header_k2, s_header_v2);
                    waflz_transaction_add_request_header(tx, s_header_k3, s_header_v3);
                    waflz_transaction_add_request_header(tx, s_header_k4, s_header_v4);
                    waflz_transaction_add_request_header(tx, s_header_k5, s_header_v5);
                    waflz_transaction_add_request_header(tx, s_header_k6, s_header_v6);
                    waflz_transaction_add_request_header(tx, s_header_k7, s_header_v7);
                    waflz_transaction_add_request_header(tx, s_header_k8, s_header_v8);
                    waflz_transaction_add_request_header(tx, s_header_k9, s_header_v9);
                    waflz_transaction_add_request_header(tx, s_header_k10, s_header_v10);
                    
                    int32_t l_s = waflz_profile_process(tx);
                    REQUIRE((l_s == WAFLZ_STATUS_OK));
                    waflz_transaction_cleanup(tx);
                }

                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                waflz_profile_cleanup(wp);
        }
}
