/*
 * STN-LABZ
 * Rictus Intelligence Module
 *
 * collector_win.c
 *
 * Windows HTTPS collection transport.
 *
 * Uses WinHTTP.
 *
 * Responsibilities:
 *
 * - HTTPS only
 * - bounded response size
 * - deterministic failure
 * - no silent HTTP error acceptance
 * - caller-owned response lifecycle
 */

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winhttp.h>

#include <stdlib.h>
#include <string.h>

#include "collector.h"


#define RICTUS_INTELLIGENCE_USER_AGENT \
    L"STN-LABZ-Rictus-Intelligence/0.2"


/*
 * ------------------------------------------------
 * UTF-8/ANSI HOST/PATH TO WIDE
 * ------------------------------------------------
 */

static int
rictus_intelligence_to_wide(
    const char *input,
    wchar_t *output,
    size_t output_count
)
{
    int result;


    if (
        input == NULL ||
        output == NULL ||
        output_count == 0
    )
    {
        return 0;
    }


    result =
        MultiByteToWideChar(
            CP_UTF8,
            0,
            input,
            -1,
            output,
            (int)output_count
        );


    if (
        result <= 0
    )
    {
        return 0;
    }


    return 1;
}


/*
 * ------------------------------------------------
 * RESPONSE FREE
 * ------------------------------------------------
 */

void
rictus_intelligence_response_free(
    rictus_intelligence_response_t *response
)
{
    if (
        response == NULL
    )
    {
        return;
    }


    if (
        response->body != NULL
    )
    {
        free(
            response->body
        );

        response->body =
            NULL;
    }


    response->body_length =
        0;

    response->http_status =
        0;
}


/*
 * ------------------------------------------------
 * COLLECT
 * ------------------------------------------------
 */

rictus_intelligence_collect_result_t
rictus_intelligence_collect(
    const rictus_intelligence_source_definition_t *source,
    rictus_intelligence_response_t *response
)
{
    HINTERNET session =
        NULL;

    HINTERNET connection =
        NULL;

    HINTERNET request =
        NULL;


    wchar_t host[
        256
    ];

    wchar_t path[
        RICTUS_INTELLIGENCE_URL_MAX
    ];


    DWORD status_code =
        0;

    DWORD status_size =
        sizeof(status_code);


    char *body =
        NULL;

    size_t body_length =
        0;

    size_t body_capacity =
        0;


    rictus_intelligence_collect_result_t
        result =
            RICTUS_INTELLIGENCE_COLLECT_OK;


    if (
        source == NULL ||
        response == NULL ||
        source->host == NULL ||
        source->path == NULL
    )
    {
        return
            RICTUS_INTELLIGENCE_COLLECT_INVALID_ARGUMENT;
    }


    memset(
        response,
        0,
        sizeof(*response)
    );


    memset(
        host,
        0,
        sizeof(host)
    );


    memset(
        path,
        0,
        sizeof(path)
    );


    if (
        !rictus_intelligence_to_wide(
            source->host,
            host,
            sizeof(host) /
                sizeof(host[0])
        ) ||
        !rictus_intelligence_to_wide(
            source->path,
            path,
            sizeof(path) /
                sizeof(path[0])
        )
    )
    {
        return
            RICTUS_INTELLIGENCE_COLLECT_INVALID_ARGUMENT;
    }


    /*
     * ------------------------------------------------
     * SESSION
     * ------------------------------------------------
     */

    session =
        WinHttpOpen(
            RICTUS_INTELLIGENCE_USER_AGENT,
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0
        );


    if (
        session == NULL
    )
    {
        return
            RICTUS_INTELLIGENCE_COLLECT_SESSION_FAILED;
    }


    /*
     * Conservative timeouts.
     */

    WinHttpSetTimeouts(
        session,
        10000,
        10000,
        15000,
        15000
    );


    /*
     * ------------------------------------------------
     * CONNECT
     * ------------------------------------------------
     */

    connection =
        WinHttpConnect(
            session,
            host,
            INTERNET_DEFAULT_HTTPS_PORT,
            0
        );


    if (
        connection == NULL
    )
    {
        result =
            RICTUS_INTELLIGENCE_COLLECT_CONNECT_FAILED;

        goto cleanup;
    }


    /*
     * ------------------------------------------------
     * REQUEST
     * ------------------------------------------------
     */

    request =
        WinHttpOpenRequest(
            connection,
            L"GET",
            path,
            NULL,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE
        );


    if (
        request == NULL
    )
    {
        result =
            RICTUS_INTELLIGENCE_COLLECT_REQUEST_FAILED;

        goto cleanup;
    }


    /*
     * Avoid transparent compression for the first
     * implementation. We want deterministic raw
     * response handling.
     */

    if (
        !WinHttpAddRequestHeaders(
            request,
            L"Accept: application/rss+xml, application/xml, text/xml, text/html\r\n",
            (DWORD)-1L,
            WINHTTP_ADDREQ_FLAG_ADD |
            WINHTTP_ADDREQ_FLAG_REPLACE
        )
    )
    {
        result =
            RICTUS_INTELLIGENCE_COLLECT_REQUEST_FAILED;

        goto cleanup;
    }


    if (
        !WinHttpSendRequest(
            request,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0,
            WINHTTP_NO_REQUEST_DATA,
            0,
            0,
            0
        )
    )
    {
        result =
            RICTUS_INTELLIGENCE_COLLECT_SEND_FAILED;

        goto cleanup;
    }


    if (
        !WinHttpReceiveResponse(
            request,
            NULL
        )
    )
    {
        result =
            RICTUS_INTELLIGENCE_COLLECT_RECEIVE_FAILED;

        goto cleanup;
    }


    /*
     * ------------------------------------------------
     * STATUS
     * ------------------------------------------------
     */

    if (
        !WinHttpQueryHeaders(
            request,
            WINHTTP_QUERY_STATUS_CODE |
            WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &status_code,
            &status_size,
            WINHTTP_NO_HEADER_INDEX
        )
    )
    {
        result =
            RICTUS_INTELLIGENCE_COLLECT_RECEIVE_FAILED;

        goto cleanup;
    }


    response->http_status =
        status_code;


    if (
        status_code < 200 ||
        status_code >= 300
    )
    {
        result =
            RICTUS_INTELLIGENCE_COLLECT_HTTP_STATUS;

        goto cleanup;
    }


    /*
     * ------------------------------------------------
     * BODY
     * ------------------------------------------------
     */

    for (;;)
    {
        DWORD available =
            0;

        DWORD read =
            0;

        size_t required;

        char *replacement;


        if (
            !WinHttpQueryDataAvailable(
                request,
                &available
            )
        )
        {
            result =
                RICTUS_INTELLIGENCE_COLLECT_RECEIVE_FAILED;

            goto cleanup;
        }


        if (
            available == 0
        )
        {
            break;
        }


        if (
            body_length >
            RICTUS_INTELLIGENCE_RESPONSE_MAX -
                (size_t)available
        )
        {
            result =
                RICTUS_INTELLIGENCE_COLLECT_TOO_LARGE;

            goto cleanup;
        }


        required =
            body_length +
            (size_t)available +
            1;


        if (
            required >
            body_capacity
        )
        {
            replacement =
                (char *)
                realloc(
                    body,
                    required
                );


            if (
                replacement == NULL
            )
            {
                result =
                    RICTUS_INTELLIGENCE_COLLECT_MEMORY_FAILED;

                goto cleanup;
            }


            body =
                replacement;

            body_capacity =
                required;
        }


        if (
            !WinHttpReadData(
                request,
                body + body_length,
                available,
                &read
            )
        )
        {
            result =
                RICTUS_INTELLIGENCE_COLLECT_RECEIVE_FAILED;

            goto cleanup;
        }


        if (
            read == 0
        )
        {
            break;
        }


        body_length +=
            (size_t)read;
    }


    if (
        body == NULL
    )
    {
        body =
            (char *)
            malloc(
                1
            );


        if (
            body == NULL
        )
        {
            result =
                RICTUS_INTELLIGENCE_COLLECT_MEMORY_FAILED;

            goto cleanup;
        }


        body_capacity =
            1;
    }


    body[
        body_length
    ] =
        '\0';


    response->body =
        body;

    response->body_length =
        body_length;


    body =
        NULL;


cleanup:


    if (
        body != NULL
    )
    {
        free(
            body
        );
    }


    if (
        request != NULL
    )
    {
        WinHttpCloseHandle(
            request
        );
    }


    if (
        connection != NULL
    )
    {
        WinHttpCloseHandle(
            connection
        );
    }


    if (
        session != NULL
    )
    {
        WinHttpCloseHandle(
            session
        );
    }


    return
        result;
}


/*
 * ------------------------------------------------
 * RESULT STRING
 * ------------------------------------------------
 */

const char *
rictus_intelligence_collect_result_string(
    rictus_intelligence_collect_result_t result
)
{
    switch (
        result
    )
    {
        case RICTUS_INTELLIGENCE_COLLECT_OK:

            return "OK";


        case RICTUS_INTELLIGENCE_COLLECT_INVALID_ARGUMENT:

            return "INVALID_ARGUMENT";


        case RICTUS_INTELLIGENCE_COLLECT_SESSION_FAILED:

            return "SESSION_FAILED";


        case RICTUS_INTELLIGENCE_COLLECT_CONNECT_FAILED:

            return "CONNECT_FAILED";


        case RICTUS_INTELLIGENCE_COLLECT_REQUEST_FAILED:

            return "REQUEST_FAILED";


        case RICTUS_INTELLIGENCE_COLLECT_SEND_FAILED:

            return "SEND_FAILED";


        case RICTUS_INTELLIGENCE_COLLECT_RECEIVE_FAILED:

            return "RECEIVE_FAILED";


        case RICTUS_INTELLIGENCE_COLLECT_HTTP_STATUS:

            return "HTTP_STATUS";


        case RICTUS_INTELLIGENCE_COLLECT_TOO_LARGE:

            return "TOO_LARGE";


        case RICTUS_INTELLIGENCE_COLLECT_MEMORY_FAILED:

            return "MEMORY_FAILED";


        default:

            return "UNKNOWN";
    }
}