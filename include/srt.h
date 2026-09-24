#ifndef RICTUS_INTELLIGENCE_SRT_H
#define RICTUS_INTELLIGENCE_SRT_H

#include <stddef.h>

#include "record.h"


#define RICTUS_INTELLIGENCE_SRT_REQUEST_MAX \
    4096

#define RICTUS_INTELLIGENCE_SRT_STATUS_MAX \
    32

#define RICTUS_INTELLIGENCE_SRT_PATH_MAX \
    1024

#define RICTUS_INTELLIGENCE_SRT_DIRECTORY \
    "C:\\stn-labz\\reports\\SRT"

#define RICTUS_INTELLIGENCE_SRT_REQUEST_PATH \
    "C:\\stn-labz\\reports\\SRT\\srt.requests"

#define RICTUS_INTELLIGENCE_SRT_ID_MAX \
    32

#define RICTUS_INTELLIGENCE_SRT_OFFICE_MAX \
    128
	
#define RICTUS_INTELLIGENCE_RAG_INPUT_DIRECTORY \
    "C:\\stn-labz\\rag\\input"

#define RICTUS_INTELLIGENCE_RAG_LINE_MAX \
    512


typedef struct
{
    char intelligence_id[
        RICTUS_INTELLIGENCE_RECORD_ID_MAX
    ];

    char status[
        RICTUS_INTELLIGENCE_SRT_STATUS_MAX
    ];

    char srt_id[
        RICTUS_INTELLIGENCE_SRT_ID_MAX
    ];

} rictus_intelligence_srt_request_t;


typedef struct
{
    rictus_intelligence_srt_request_t requests[
        RICTUS_INTELLIGENCE_SRT_REQUEST_MAX
    ];

    size_t count;

} rictus_intelligence_srt_store_t;


void
rictus_intelligence_srt_store_init(
    rictus_intelligence_srt_store_t *store
);


int
rictus_intelligence_srt_store_load(
    rictus_intelligence_srt_store_t *store,
    const char *path
);


const rictus_intelligence_srt_request_t *
rictus_intelligence_srt_store_find(
    const rictus_intelligence_srt_store_t *store,
    const char *intelligence_id
);


int
rictus_intelligence_srt_store_append(
    rictus_intelligence_srt_store_t *store,
    const char *path,
    const char *intelligence_id,
    const char *status
);



int
rictus_intelligence_srt_approve(
    rictus_intelligence_srt_store_t *store,
    const char *path,
    const char *directory,
    const char *intelligence_id,
    const char *reviewer,
    const char *reviewer_office,
    char *srt_id,
    size_t srt_id_size,
    char *approved_report_path,
    size_t approved_report_path_size
);

int
rictus_intelligence_srt_reject(
    rictus_intelligence_srt_store_t *store,
    const char *path,
    const char *intelligence_id
);


int
rictus_intelligence_srt_generate_report(
    const char *directory,
    const rictus_intelligence_record_t *record,
    const char *requested_by,
    char *report_path,
    size_t report_path_size
);


#endif
