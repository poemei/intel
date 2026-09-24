#ifndef RICTUS_INTELLIGENCE_PARSER_H
#define RICTUS_INTELLIGENCE_PARSER_H

#include <stddef.h>

#include "collector.h"
#include "item.h"
#include "sources.h"


#define RICTUS_INTELLIGENCE_ITEMS_MAX \
    256


typedef enum
{
    RICTUS_INTELLIGENCE_PARSE_OK = 0,

    RICTUS_INTELLIGENCE_PARSE_INVALID_ARGUMENT,

    RICTUS_INTELLIGENCE_PARSE_UNSUPPORTED,

    RICTUS_INTELLIGENCE_PARSE_INVALID_FORMAT,

    RICTUS_INTELLIGENCE_PARSE_ITEM_LIMIT

} rictus_intelligence_parse_result_t;


typedef struct
{
    rictus_intelligence_item_t items[
        RICTUS_INTELLIGENCE_ITEMS_MAX
    ];

    size_t count;

} rictus_intelligence_item_set_t;


rictus_intelligence_parse_result_t
rictus_intelligence_parse_response(
    const rictus_intelligence_source_definition_t *source,
    const rictus_intelligence_response_t *response,
    rictus_intelligence_item_set_t *items
);


const char *
rictus_intelligence_parse_result_string(
    rictus_intelligence_parse_result_t result
);


#endif
