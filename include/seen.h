#ifndef RICTUS_INTELLIGENCE_SEEN_H
#define RICTUS_INTELLIGENCE_SEEN_H

#include <stddef.h>

#include "item.h"


#define RICTUS_INTELLIGENCE_SEEN_MAX \
    4096


typedef struct
{
    char fingerprints[
        RICTUS_INTELLIGENCE_SEEN_MAX
    ][
        RICTUS_INTELLIGENCE_ITEM_FINGERPRINT_MAX
    ];

    size_t count;

} rictus_intelligence_seen_t;


typedef enum
{
    RICTUS_INTELLIGENCE_SEEN_OK = 0,

    RICTUS_INTELLIGENCE_SEEN_INVALID_ARGUMENT,

    RICTUS_INTELLIGENCE_SEEN_OPEN_FAILED,

    RICTUS_INTELLIGENCE_SEEN_WRITE_FAILED,

    RICTUS_INTELLIGENCE_SEEN_FULL

} rictus_intelligence_seen_result_t;


void
rictus_intelligence_seen_init(
    rictus_intelligence_seen_t *seen
);


rictus_intelligence_seen_result_t
rictus_intelligence_seen_load(
    rictus_intelligence_seen_t *seen
);


int
rictus_intelligence_seen_contains(
    const rictus_intelligence_seen_t *seen,
    const char *fingerprint
);


rictus_intelligence_seen_result_t
rictus_intelligence_seen_add(
    rictus_intelligence_seen_t *seen,
    const char *fingerprint
);


const char *
rictus_intelligence_seen_result_string(
    rictus_intelligence_seen_result_t result
);


#endif