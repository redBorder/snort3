//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

// payload_injector_translate_test.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "payload_injector/payload_injector_module.h"

#include "utils/util.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

TEST_GROUP(payload_injector_translate_test)
{
    uint8_t* http2_payload;
    uint32_t payload_len;
    InjectionReturnStatus status;
};

TEST(payload_injector_translate_test, basic_hdr_translation)
{
    char http_page[] = "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: "
        "504\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<!DOCTYPE html>\n<html><head>\n<meta"
        "http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\" />\n";

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = (uint8_t*)http_page;
    control.http_page_len = strlen(http_page);
    status = PayloadInjectorModule::get_http2_payload(control, http2_payload, payload_len);
    CHECK(status == INJECTION_SUCCESS);

    uint8_t out[] = { 0x0, 0x0, 0x40, 0x1, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x7, 0x3a, 0x73, 0x74,
                      0x61, 0x74, 0x75, 0x73, 0x3, 0x34, 0x30, 0x33, 0x0, 0xa, 0x63, 0x6f, 0x6e,
                      0x6e, 0x65,
                      0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5, 0x63, 0x6c, 0x6f, 0x73, 0x65, 0xf, 0xd,
                      0x3, 0x35,
                      0x30, 0x34, 0xf, 0x10, 0x18, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x68, 0x74, 0x6d,
                      0x6c,
                      0x3b, 0x20, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65, 0x74, 0x3d, 0x55, 0x54, 0x46,
                      0x2d,
                      0x38, 0x0, 0x0, 0x62, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x3c, 0x21, 0x44, 0x4f,
                      0x43, 0x54,
                      0x59, 0x50, 0x45, 0x20, 0x68, 0x74, 0x6d, 0x6c, 0x3e, 0xa, 0x3c, 0x68, 0x74,
                      0x6d,
                      0x6c, 0x3e, 0x3c, 0x68, 0x65, 0x61, 0x64, 0x3e, 0xa, 0x3c, 0x6d, 0x65, 0x74,
                      0x61,
                      0x68, 0x74, 0x74, 0x70, 0x2d, 0x65, 0x71, 0x75, 0x69, 0x76, 0x3d, 0x22, 0x63,
                      0x6f,
                      0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x22, 0x20, 0x63,
                      0x6f,
                      0x6e, 0x74, 0x65, 0x6e, 0x74, 0x3d, 0x22, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x68,
                      0x74,
                      0x6d, 0x6c, 0x3b, 0x20, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65, 0x74, 0x3d, 0x55,
                      0x54,
                      0x46, 0x2d, 0x38, 0x22, 0x20, 0x2f, 0x3e, 0xa };
    CHECK(payload_len == sizeof(out));
    CHECK(memcmp(http2_payload, out, payload_len) == 0);

    snort_free(http2_payload);
}

TEST(payload_injector_translate_test, basic_hdr_translation2)
{
    char http_page[] =
        "HTTP/1.1 307 Proxy Redirect\r\nLocation: https://\r\nSet-Cookie: 04f2; Max-Age: 600; path=/;\r\n\r\nBody\n";

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = (uint8_t*)http_page;
    control.http_page_len = strlen(http_page);
    status = PayloadInjectorModule::get_http2_payload(control, http2_payload, payload_len);

    CHECK(status == INJECTION_SUCCESS);

    uint8_t out[] = { 0x0, 0x0, 0x36, 0x1, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x7, 0x3a, 0x73, 0x74,
                      0x61, 0x74, 0x75, 0x73, 0x3, 0x33, 0x30, 0x37, 0xf, 0x1f, 0x8, 0x68, 0x74,
                      0x74, 0x70,
                      0x73, 0x3a, 0x2f, 0x2f, 0xf, 0x28, 0x1b, 0x30, 0x34, 0x66, 0x32, 0x3b, 0x20,
                      0x4d,
                      0x61, 0x78, 0x2d, 0x41, 0x67, 0x65, 0x3a, 0x20, 0x36, 0x30, 0x30, 0x3b, 0x20,
                      0x70,
                      0x61, 0x74, 0x68, 0x3d, 0x2f, 0x3b, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0,
                      0x1, 0x42,
                      0x6f, 0x64, 0x79, 0xa };
    CHECK(payload_len == sizeof(out));
    CHECK(memcmp(http2_payload, out, payload_len) == 0);

    snort_free(http2_payload);
}

TEST(payload_injector_translate_test, only_body)
{
    char http_page[] = "\r\nbody";

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = (uint8_t*)http_page;
    control.http_page_len = strlen(http_page);
    status = PayloadInjectorModule::get_http2_payload(control, http2_payload, payload_len);

    CHECK(status == ERR_PAGE_TRANSLATION);
}

TEST(payload_injector_translate_test, no_body)
{
    char http_page[] =
        "HTTP/1.1 307 Proxy Redirect\r\nLocation: https://\r\nSet-Cookie: 04f2; Max-Age: 600; path=/;\r\n\r\n";

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = (uint8_t*)http_page;
    control.http_page_len = strlen(http_page);
    status = PayloadInjectorModule::get_http2_payload(control, http2_payload, payload_len);

    CHECK(status == ERR_PAGE_TRANSLATION);
}

TEST(payload_injector_translate_test, missing_last_rn)
{
    char http_page[] =
        "HTTP/1.1 307 Proxy Redirect\r\nLocation: https://\r\nSet-Cookie: 04f2; Max-Age: 600; path=/;\r\nBody\n";

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = (uint8_t*)http_page;
    control.http_page_len = strlen(http_page);
    status = PayloadInjectorModule::get_http2_payload(control, http2_payload, payload_len);

    CHECK(status == ERR_PAGE_TRANSLATION);
}

TEST(payload_injector_translate_test, missing_space_after_colon)
{
    char http_page[] =
        "HTTP/1.1 307 Proxy Redirect\r\nLocation:https://\r\nSet-Cookie: 04f2; Max-Age: 600; path=/;\r\n\r\nBody\n";

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = (uint8_t*)http_page;
    control.http_page_len = strlen(http_page);
    status = PayloadInjectorModule::get_http2_payload(control, http2_payload, payload_len);

    CHECK(status == ERR_PAGE_TRANSLATION);
}

TEST(payload_injector_translate_test, extra_space_before_colon)
{
    char http_page[] =
        "HTTP/1.1 307 Proxy Redirect\r\nLocation :https://\r\nSet-Cookie: 04f2; Max-Age: 600; path=/;\r\n\r\nBody\n";

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = (uint8_t*)http_page;
    control.http_page_len = strlen(http_page);
    status = PayloadInjectorModule::get_http2_payload(control, http2_payload, payload_len);

    CHECK(status == ERR_PAGE_TRANSLATION);
}

TEST(payload_injector_translate_test, unsuporrted_status)
{
    char http_page[] =
        "HTTP/1.1 200 OK\r\nLocation: https://\r\nSet-Cookie: 04f2; Max-Age: 600; path=/;\r\n\r\nBody\n";

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = (uint8_t*)http_page;
    control.http_page_len = strlen(http_page);
    status = PayloadInjectorModule::get_http2_payload(control, http2_payload, payload_len);

    CHECK(status == ERR_PAGE_TRANSLATION);
}

TEST(payload_injector_translate_test, unsupported_hdr)
{
    char http_page[] =
        "HTTP/1.1 307 Proxy Redirect\r\nLocation:https://\r\nRetry-after: 120\r\n\r\nBody\n";

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = (uint8_t*)http_page;
    control.http_page_len = strlen(http_page);
    status = PayloadInjectorModule::get_http2_payload(control, http2_payload, payload_len);

    CHECK(status == ERR_PAGE_TRANSLATION);
}

TEST(payload_injector_translate_test, hdr_ends_wo_value)
{
    char http_page[] = "HTTP/1.1 307 Proxy Redirect\r\nLocation: ";

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = (uint8_t*)http_page;
    control.http_page_len = strlen(http_page);
    status = PayloadInjectorModule::get_http2_payload(control, http2_payload, payload_len);

    CHECK(status == ERR_PAGE_TRANSLATION);
}

TEST(payload_injector_translate_test, missing_value)
{
    char http_page[] = "HTTP/1.1 307 Proxy Redirect\r\nLocation: \r\n\r\nBody\n";

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = (uint8_t*)http_page;
    control.http_page_len = strlen(http_page);
    status = PayloadInjectorModule::get_http2_payload(control, http2_payload, payload_len);

    CHECK(status == ERR_PAGE_TRANSLATION);
}

// Header value has maximum supported length + 1
TEST(payload_injector_translate_test, val_len_too_big)
{
    const uint32_t size = strlen("Location: ") + 128 + strlen("\r\n\r\nbody");
    uint8_t http_page[size];
    memset(http_page, 'a', size);
    memcpy(http_page, "Location: ", strlen("Location: "));
    memcpy(http_page+128+strlen("Location: "), "\r\n\r\nbody", strlen("\r\n\r\nbody"));

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = http_page;
    control.http_page_len = size;
    status = PayloadInjectorModule::get_http2_payload(control, http2_payload, payload_len);

    CHECK(status == ERR_PAGE_TRANSLATION);
}

// Header value has maximum supported length 127
TEST(payload_injector_translate_test, max_val)
{
    const uint32_t size = strlen("Location: ") + 127 + strlen("\r\n\r\nbody");
    uint8_t http_page[size];
    memset(http_page, 'a', size);
    memcpy(http_page, "Location: ", strlen("Location: "));
    memcpy(http_page+127+strlen("Location: "), "\r\n\r\nbody", strlen("\r\n\r\nbody"));

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = http_page;
    control.http_page_len = size;
    status = PayloadInjectorModule::get_http2_payload(control, http2_payload, payload_len);

    CHECK(status == INJECTION_SUCCESS);
    snort_free(http2_payload);
}

// Translated header is exactly 2000.
// Verify correct frame length when length is more than 1 byte.
// Verify correct behavior for body length is 1.
TEST(payload_injector_translate_test, http2_hdr_is_max)
{
    const uint32_t size = strlen("Connection: close\r\n") * 110 + strlen("Location: ") +
        strlen("\r\n\r\nb") + 17;
    uint8_t http_page[size];

    memset(http_page, 'a', size);
    uint8_t* cur_pos = http_page;
    for (int i=0; i < 110; i++)
    {
        memcpy(cur_pos, "Connection: close\r\n", strlen("Connection: close\r\n"));
        cur_pos += strlen("Connection: close\r\n");
    }
    memcpy(cur_pos, "Location: ", strlen("Location: "));
    memcpy(http_page+size-strlen("\r\n\r\nb"), "\r\n\r\nb", strlen("\r\n\r\nb"));

    InjectionControl control;
    control.http_page = http_page;
    control.http_page_len = size;
    control.stream_id = 0xf000;
    status = PayloadInjectorModule::get_http2_payload(control, http2_payload, payload_len);

    CHECK(status == INJECTION_SUCCESS);
    CHECK(payload_len == 2019);
    uint8_t hdr[] = { 0x0, 0x7, 0xd0, 0x1, 0x0, 0x0, 0x0, 0xf0, 0x0 };
    CHECK(memcmp(http2_payload, hdr, sizeof(hdr))==0);
    uint8_t body[] = { 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0xf0, 0x0, 'b' };
    CHECK(memcmp(http2_payload + 2009, body, sizeof(body))==0);
    snort_free(http2_payload);
}

// Translated header is 2001. Goes through write_indexed code path.
TEST(payload_injector_translate_test, http2_hdr_too_big)
{
    const uint32_t size = strlen("Connection: close\r\n") * 110 + strlen("Location: ") +
        strlen("\r\n\r\nbody") + 18;
    uint8_t http_page[size];

    memset(http_page, 'a', size);
    uint8_t* cur_pos = http_page;
    for (int i=0; i < 110; i++)
    {
        memcpy(cur_pos, "Connection: close\r\n", strlen("Connection: close\r\n"));
        cur_pos += strlen("Connection: close\r\n");
    }
    memcpy(cur_pos, "Location: ", strlen("Location: "));
    memcpy(http_page+size-strlen("\r\n\r\nbody"), "\r\n\r\nbody", strlen("\r\n\r\nbody"));

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = http_page;
    control.http_page_len = size;
    status = PayloadInjectorModule::get_http2_payload(control, http2_payload, payload_len);

    CHECK(status == ERR_PAGE_TRANSLATION);
}

// Translated header > 2000. Goes through write_translation code path.
TEST(payload_injector_translate_test, http2_hdr_too_big2)
{
    const uint32_t size = strlen("Connection: close\r\n") * 112 + strlen("\r\nbody");
    uint8_t http_page[size];

    uint8_t* cur_pos = http_page;
    for (int i=0; i < 112; i++)
    {
        memcpy(cur_pos, "Connection: close\r\n", strlen("Connection: close\r\n"));
        cur_pos += strlen("Connection: close\r\n");
    }
    memcpy(http_page+size-strlen("\r\nbody"), "\r\nbody", strlen("\r\nbody"));

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = http_page;
    control.http_page_len = size;
    status = PayloadInjectorModule::get_http2_payload(control, http2_payload, payload_len);
    CHECK(status == ERR_PAGE_TRANSLATION);
}

TEST(payload_injector_translate_test, payload_body_larger_than_max)
{
    static const uint32_t size = (1<<14) + 1 + strlen("HTTP/1.1 403 Forbidden\r\n\r\n");
    uint8_t http_page[size];
    memset(http_page,'a',size);
    memcpy(http_page,"HTTP/1.1 403 Forbidden\r\n\r\n", strlen("HTTP/1.1 403 Forbidden\r\n\r\n"));

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = http_page;
    control.http_page_len = size;
    status = PayloadInjectorModule::get_http2_payload(control, http2_payload, payload_len);
    CHECK(status == ERR_PAGE_TRANSLATION);
}

TEST(payload_injector_translate_test, http_page_is_nullptr)
{
    InjectionControl control;
    control.http_page = nullptr;
    control.http_page_len = 1;
    status = PayloadInjectorModule::get_http2_payload(control, http2_payload, payload_len);
    CHECK(status == ERR_PAGE_TRANSLATION);
}

TEST(payload_injector_translate_test, http_page_is_0_length)
{
    uint8_t http_page[] = {1};

    InjectionControl control;
    control.http_page = http_page;
    control.http_page_len = 0;
    status = PayloadInjectorModule::get_http2_payload(control, http2_payload, payload_len);
    CHECK(status == ERR_PAGE_TRANSLATION);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

