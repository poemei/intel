#ifndef RICTUS_INTELLIGENCE_RECORD_H
#define RICTUS_INTELLIGENCE_RECORD_H

#include <stddef.h>
#include "item.h"

#define RICTUS_INTELLIGENCE_RECORD_ID_MAX 32
#define RICTUS_INTELLIGENCE_RECORD_MAX 4096

typedef struct
{
    char id[RICTUS_INTELLIGENCE_RECORD_ID_MAX];
    rictus_intelligence_item_t item;
} rictus_intelligence_record_t;

typedef struct
{
    rictus_intelligence_record_t records[RICTUS_INTELLIGENCE_RECORD_MAX];
    size_t count;
} rictus_intelligence_record_store_t;

void rictus_intelligence_record_store_init(
    rictus_intelligence_record_store_t* store
);

int rictus_intelligence_record_store_load(
    rictus_intelligence_record_store_t* store,
    const char* path
);

int rictus_intelligence_record_store_append(
    rictus_intelligence_record_store_t* store,
    const char* path,
    const rictus_intelligence_item_t* item,
    char* id,
    size_t id_size
);

const rictus_intelligence_record_t*
rictus_intelligence_record_store_find(
    const rictus_intelligence_record_store_t* store,
    const char* id
);

#endif
