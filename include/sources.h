#ifndef RICTUS_INTELLIGENCE_SOURCES_H
#define RICTUS_INTELLIGENCE_SOURCES_H

#include <stddef.h>


#define RICTUS_INTELLIGENCE_URL_MAX \
    512

#define RICTUS_INTELLIGENCE_SOURCE_NAME_MAX \
    64


typedef enum
{
    RICTUS_INTELLIGENCE_TRANSPORT_NONE = 0,

    RICTUS_INTELLIGENCE_TRANSPORT_RSS,

    RICTUS_INTELLIGENCE_TRANSPORT_HTML,

    RICTUS_INTELLIGENCE_TRANSPORT_JSON

} rictus_intelligence_transport_t;


typedef struct
{
    const char *id;

    const char *name;

    const char *host;

    const char *path;

    rictus_intelligence_transport_t transport;

    int primary;

} rictus_intelligence_source_definition_t;


/*
 * Return the number of configured Intelligence
 * sources.
 */

size_t
rictus_intelligence_source_count(void);


/*
 * Return one configured source by index.
 */

const rictus_intelligence_source_definition_t *
rictus_intelligence_source_get(
    size_t index
);


/*
 * Return one configured source by ID.
 */

const rictus_intelligence_source_definition_t *
rictus_intelligence_source_find(
    const char *id
);


#endif
