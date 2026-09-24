#ifndef RICTUS_INTELLIGENCE_COLLECTOR_H
#define RICTUS_INTELLIGENCE_COLLECTOR_H

#include <stddef.h>

#include "sources.h"


#define RICTUS_INTELLIGENCE_RESPONSE_MAX \
    (1024 * 1024)


typedef enum
{
    RICTUS_INTELLIGENCE_COLLECT_OK = 0,

    RICTUS_INTELLIGENCE_COLLECT_INVALID_ARGUMENT,

    RICTUS_INTELLIGENCE_COLLECT_SESSION_FAILED,

    RICTUS_INTELLIGENCE_COLLECT_CONNECT_FAILED,

    RICTUS_INTELLIGENCE_COLLECT_REQUEST_FAILED,

    RICTUS_INTELLIGENCE_COLLECT_SEND_FAILED,

    RICTUS_INTELLIGENCE_COLLECT_RECEIVE_FAILED,

    RICTUS_INTELLIGENCE_COLLECT_HTTP_STATUS,

    RICTUS_INTELLIGENCE_COLLECT_TOO_LARGE,

    RICTUS_INTELLIGENCE_COLLECT_MEMORY_FAILED

} rictus_intelligence_collect_result_t;


typedef struct
{
    unsigned long http_status;

    char *body;

    size_t body_length;

} rictus_intelligence_response_t;


/*
 * Collect one configured HTTPS source.
 */

rictus_intelligence_collect_result_t
rictus_intelligence_collect(
    const rictus_intelligence_source_definition_t *source,
    rictus_intelligence_response_t *response
);


/*
 * Release response memory.
 */

void
rictus_intelligence_response_free(
    rictus_intelligence_response_t *response
);


const char *
rictus_intelligence_collect_result_string(
    rictus_intelligence_collect_result_t result
);


#endif