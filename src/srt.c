/*
 * STN-LABZ
 * Rictus Intelligence Module
 *
 * srt.c
 *
 * Security Research Target handoff support.
 *
 * Responsibilities:
 *
 * - persistent operator SRT request state
 * - deterministic SRT candidate report path
 * - human-readable Markdown handoff report
 * - controlled-document header preparation
 *
 * This subsystem does not approve an SRT,
 * assign final controlled-document identity,
 * calculate the authoritative sha256 value,
 * or publish knowledge to Digit.
 */

#include <errno.h>
#include <pthread.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "srt.h"


#define RICTUS_INTELLIGENCE_SRT_LINE_MAX \
    256

#define RICTUS_INTELLIGENCE_SRT_TEXT_MAX \
    4096


/*
 * ------------------------------------------------
 * DIRECTORY TREE
 * ------------------------------------------------
 */

static int
rictus_intelligence_srt_ensure_directory(const char *path)
{
    char buffer[RICTUS_INTELLIGENCE_SRT_PATH_MAX];
    size_t i, length;
    struct stat st;

    if (path == NULL || path[0] == '\0') return 0;
    length = strlen(path);
    if (length >= sizeof(buffer)) return 0;
    memcpy(buffer, path, length + 1);

    for (i = 1; i <= length; ++i) {
        if (buffer[i] != '/' && buffer[i] != '\0') continue;
        {
            char saved = buffer[i];
            buffer[i] = '\0';
            if (buffer[0] != '\0' && mkdir(buffer, 0750) != 0 && errno != EEXIST) return 0;
            buffer[i] = saved;
        }
    }

    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/*
 * ------------------------------------------------
 * MARKDOWN TEXT NORMALIZATION
 * ------------------------------------------------
 */

static void
rictus_intelligence_srt_normalize_text(
    const char *input,
    char *output,
    size_t output_size
)
{
    size_t input_index;

    size_t output_index;


    if (
        output == NULL ||
        output_size == 0
        )
    {
        return;
    }


    output[0] =
        '\0';


    if (
        input == NULL
        )
    {
        return;
    }


    output_index =
        0;


    for (
        input_index = 0;
        input[input_index] != '\0' &&
        output_index + 1 <
            output_size;
        ++input_index
        )
    {
        char c;


        c =
            input[input_index];


        if (
            c == '\r' ||
            c == '\n' ||
            c == '\t'
            )
        {
            c =
                ' ';
        }


        if (
            c == ' ' &&
            output_index > 0 &&
            output[
                output_index - 1
            ] == ' '
            )
        {
            continue;
        }


        output[
            output_index++
        ] =
            c;
    }


    output[
        output_index
    ] =
        '\0';
}


/*
 * ------------------------------------------------
 * UTC TIMESTAMP
 * ------------------------------------------------
 */

static int
rictus_intelligence_srt_timestamp(char *output, size_t output_size)
{
    time_t now;
    struct tm utc;

    if (output == NULL || output_size == 0) return 0;
    now = time(NULL);
    if (now == (time_t)-1 || gmtime_r(&now, &utc) == NULL) return 0;
    return strftime(output, output_size, "%Y-%m-%dT%H:%M:%SZ", &utc) != 0;
}

/*
 * ------------------------------------------------
 * STORE INIT
 * ------------------------------------------------
 */

void
rictus_intelligence_srt_store_init(
    rictus_intelligence_srt_store_t *store
)
{
    if (
        store == NULL
        )
    {
        return;
    }


    memset(
        store,
        0,
        sizeof(*store)
    );
}


/*
 * ------------------------------------------------
 * STORE FIND
 * ------------------------------------------------
 */

const rictus_intelligence_srt_request_t *
rictus_intelligence_srt_store_find(
    const rictus_intelligence_srt_store_t *store,
    const char *intelligence_id
)
{
    size_t index;


    if (
        store == NULL ||
        intelligence_id == NULL ||
        intelligence_id[0] == '\0'
        )
    {
        return NULL;
    }


    for (
        index = 0;
        index < store->count;
        ++index
        )
    {
        if (
            strcasecmp(
                store
                    ->requests[index]
                    .intelligence_id,
                intelligence_id
            ) == 0
            )
        {
            return
                &store->requests[index];
        }
    }


    return NULL;
}


/*
 * ------------------------------------------------
 * STORE LOAD
 * ------------------------------------------------
 */

int
rictus_intelligence_srt_store_load(
    rictus_intelligence_srt_store_t *store,
    const char *path
)
{
    FILE *file;

    char line[
        RICTUS_INTELLIGENCE_SRT_LINE_MAX
    ];


    if (
        store == NULL ||
        path == NULL ||
        path[0] == '\0'
        )
    {
        return 0;
    }


    rictus_intelligence_srt_store_init(
        store
    );


    if (
        ((file = fopen(path, "r")) == NULL)
        )
    {
        /*
         * No request file yet is a valid empty state.
         */

        return 1;
    }


    while (
        fgets(
            line,
            sizeof(line),
            file
        ) != NULL
        )
    {
        char *context =
            NULL;

        char *intelligence_id;

        char *status;

        char *srt_id;

        rictus_intelligence_srt_request_t
            *request;


        line[
            strcspn(
                line,
                "\r\n"
            )
        ] =
            '\0';


        intelligence_id =
            strtok_r(
                line,
                "\t",
                &context
            );


        status =
            strtok_r(
                NULL,
                "\t",
                &context
            );


        srt_id =
            strtok_r(
                NULL,
                "\t",
                &context
            );


        if (
            intelligence_id == NULL ||
            status == NULL ||
            intelligence_id[0] == '\0' ||
            status[0] == '\0'
            )
        {
            continue;
        }


        if (
            store->count >=
            RICTUS_INTELLIGENCE_SRT_REQUEST_MAX
            )
        {
            fclose(
                file
            );


            return 0;
        }


        if (
            rictus_intelligence_srt_store_find(
                store,
                intelligence_id
            ) != NULL
            )
        {
            continue;
        }


        request =
            &store
                ->requests[
                    store->count
                ];


        memset(
            request,
            0,
            sizeof(*request)
        );


        if (
            snprintf(request->intelligence_id, sizeof(request->intelligence_id), "%s", intelligence_id) != 0 ||
            snprintf(request->status, sizeof(request->status), "%s", status) != 0 ||
            (
                srt_id != NULL &&
                srt_id[0] != '\0' &&
                snprintf(request->srt_id, sizeof(request->srt_id), "%s", srt_id) != 0
            )
            )
        {
            fclose(
                file
            );


            return 0;
        }


        ++store->count;
    }


    fclose(
        file
    );


    return 1;
}


/*
 * ------------------------------------------------
 * STORE APPEND
 * ------------------------------------------------
 */

int
rictus_intelligence_srt_store_append(
    rictus_intelligence_srt_store_t *store,
    const char *path,
    const char *intelligence_id,
    const char *status
)
{
    FILE *file;

    rictus_intelligence_srt_request_t
        *request;


    if (
        store == NULL ||
        path == NULL ||
        path[0] == '\0' ||
        intelligence_id == NULL ||
        intelligence_id[0] == '\0' ||
        status == NULL ||
        status[0] == '\0'
        )
    {
        return 0;
    }


    if (
        store->count >=
        RICTUS_INTELLIGENCE_SRT_REQUEST_MAX
        )
    {
        return 0;
    }


    if (
        rictus_intelligence_srt_store_find(
            store,
            intelligence_id
        ) != NULL
        )
    {
        return 0;
    }


    if (
        ((file = fopen(path, "a")) == NULL)
        )
    {
        return 0;
    }


    if (
        fprintf(
            file,
            "%s\t%s\t\n",
            intelligence_id,
            status
        ) < 0 ||
        fflush(
            file
        ) != 0
        )
    {
        fclose(
            file
        );


        return 0;
    }


    fclose(
        file
    );


    request =
        &store
            ->requests[
                store->count
            ];


    memset(
        request,
        0,
        sizeof(*request)
    );


    if (
        snprintf(request->intelligence_id, sizeof(request->intelligence_id), "%s", intelligence_id) != 0 ||
        snprintf(request->status, sizeof(request->status), "%s", status) != 0
        )
    {
        memset(
            request,
            0,
            sizeof(*request)
        );


        return 0;
    }


    ++store->count;


    return 1;
}



/*
 * ------------------------------------------------
 * STORE REWRITE
 * ------------------------------------------------
 */

static int
rictus_intelligence_srt_store_rewrite(
    const rictus_intelligence_srt_store_t *store,
    const char *path
)
{
    FILE *file;
    char temporary_path[RICTUS_INTELLIGENCE_SRT_PATH_MAX];
    size_t index;
    int written;

    if (
        store == NULL ||
        path == NULL ||
        path[0] == '\0'
        )
    {
        return 0;
    }

    written =
        snprintf(
            temporary_path,
            sizeof(temporary_path),
            "%s.tmp",
            path
        );

    if (
        written <= 0 ||
        written >= (int)sizeof(temporary_path)
        )
    {
        return 0;
    }

    if (
        ((file = fopen(temporary_path, "w")) == NULL)
        )
    {
        return 0;
    }

    for (
        index = 0;
        index < store->count;
        ++index
        )
    {
        const rictus_intelligence_srt_request_t *request =
            &store->requests[index];

        if (
            fprintf(
                file,
                "%s\t%s\t%s\n",
                request->intelligence_id,
                request->status,
                request->srt_id
            ) < 0
            )
        {
            fclose(file);
            unlink(temporary_path);
            return 0;
        }
    }

    if (
        fflush(file) != 0 ||
        fclose(file) != 0
        )
    {
        unlink(temporary_path);
        return 0;
    }

    if (rename(temporary_path, path) != 0)
    {
        unlink(temporary_path);
        return 0;
    }

    return 1;
}


/*
 * ------------------------------------------------
 * SRT ID ALLOCATION
 * ------------------------------------------------
 */

static int
rictus_intelligence_srt_allocate_id(
    const rictus_intelligence_srt_store_t *store,
    char *srt_id,
    size_t srt_id_size
)
{
    SYSTEMTIME now;
    char prefix[32];
    unsigned int highest = 0;
    size_t index;
    int written;

    if (
        store == NULL ||
        srt_id == NULL ||
        srt_id_size == 0
        )
    {
        return 0;
    }

    GetSystemTime(&now);

    written =
        snprintf(
            prefix,
            sizeof(prefix),
            "SRT-%04u%02u%02u-",
            (unsigned int)now.wYear,
            (unsigned int)now.wMonth,
            (unsigned int)now.wDay
        );

    if (
        written <= 0 ||
        written >= (int)sizeof(prefix)
        )
    {
        return 0;
    }

    for (
        index = 0;
        index < store->count;
        ++index
        )
    {
        const char *existing =
            store->requests[index].srt_id;

        unsigned int sequence;

        if (
            existing[0] == '\0' ||
            strncasecmp(
                existing,
                prefix,
                strlen(prefix)
            ) != 0
            )
        {
            continue;
        }

        sequence =
            (unsigned int)
            strtoul(
                existing + strlen(prefix),
                NULL,
                10
            );

        if (sequence > highest)
        {
            highest = sequence;
        }
    }

    if (highest >= 999)
    {
        return 0;
    }

    written =
        snprintf(
            srt_id,
            srt_id_size,
            "%s%03u",
            prefix,
            highest + 1
        );

    return
        written > 0 &&
        written < (int)srt_id_size;
}


/*
 * ------------------------------------------------
 * APPROVAL DOCUMENT
 * ------------------------------------------------
 */

static int
rictus_intelligence_srt_write_approved_report(
    const char *candidate_path,
    const char *approved_path,
    const char *intelligence_id,
    const char *srt_id,
    const char *reviewer,
    const char *reviewer_office,
    const char *review_date
)
{
    FILE *input;
    FILE *output;
    char line[RICTUS_INTELLIGENCE_SRT_TEXT_MAX];

    if (
        candidate_path == NULL ||
        approved_path == NULL ||
        intelligence_id == NULL ||
        srt_id == NULL ||
        reviewer == NULL ||
        reviewer_office == NULL ||
        review_date == NULL
        )
    {
        return 0;
    }

    if (
        fopen_s(&input, candidate_path, "r") != 0 ||
        input == NULL
        )
    {
        return 0;
    }

    if (
        fopen_s(&output, approved_path, "w") != 0 ||
        output == NULL
        )
    {
        fclose(input);
        return 0;
    }

    while (
        fgets(
            line,
            sizeof(line),
            input
        ) != NULL
        )
    {
        if (
            strncmp(
                line,
                "Root Document ID:",
                strlen("Root Document ID:")
            ) == 0
            )
        {
            fprintf(
                output,
                "Root Document ID: %s\n",
                srt_id
            );
        }
        else if (
            strncmp(
                line,
                "Revision ID:",
                strlen("Revision ID:")
            ) == 0
            )
        {
            fputs(
                "Revision ID: NONE\n",
                output
            );
        }
        else if (
            strncmp(
                line,
                "**Status**: Pending",
                strlen("**Status**: Pending")
            ) == 0
            )
        {
            fputs(
                "**Status**: Approved\n",
                output
            );
        }
        else if (
            strncmp(
                line,
                "Document ID:",
                strlen("Document ID:")
            ) == 0
            )
        {
            fprintf(
                output,
                "Document ID: %s\n",
                srt_id
            );

            fprintf(
                output,
                "Source Intelligence ID: %s\n",
                intelligence_id
            );
        }
        else if (
            strncmp(
                line,
                "Document Type: Security Research Target Candidate",
                strlen("Document Type: Security Research Target Candidate")
            ) == 0
            )
        {
            fputs(
                "Document Type: Security Research Target\n",
                output
            );
        }
        else if (
            strncmp(
                line,
                "Decision: PENDING",
                strlen("Decision: PENDING")
            ) == 0
            )
        {
            fputs("Decision: Approved\n", output);
        }
        else if (
            strncmp(
                line,
                "Reviewer: PENDING",
                strlen("Reviewer: PENDING")
            ) == 0
            )
        {
            fprintf(output, "Reviewer: %s\n", reviewer);
        }
        else if (
            strncmp(
                line,
                "Reviewer Office: PENDING",
                strlen("Reviewer Office: PENDING")
            ) == 0
            )
        {
            fprintf(
                output,
                "Reviewer Office: %s\n",
                reviewer_office
            );
        }
        else if (
            strncmp(
                line,
                "Review Date: PENDING",
                strlen("Review Date: PENDING")
            ) == 0
            )
        {
            fprintf(
                output,
                "Review Date: %s\n",
                review_date
            );
        }
        else if (
            strncmp(
                line,
                "Notes: PENDING",
                strlen("Notes: PENDING")
            ) == 0
            )
        {
            fputs(
                "Notes: Approved for Security Research Target registration.\n",
                output
            );
        }
        else
        {
            fputs(line, output);
        }

        if (ferror(output))
        {
            fclose(input);
            fclose(output);
            unlink(approved_path);
            return 0;
        }
    }

    fclose(input);

    if (
        fflush(output) != 0 ||
        fclose(output) != 0
        )
    {
        unlink(approved_path);
        return 0;
    }

    return 1;
}


/*
 * ------------------------------------------------
 * APPROVE SRT CANDIDATE
 * ------------------------------------------------
 */

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
)
{
    rictus_intelligence_srt_request_t *request;
    char candidate_path[RICTUS_INTELLIGENCE_SRT_PATH_MAX];
    char temporary_approved_path[RICTUS_INTELLIGENCE_SRT_PATH_MAX];
    char review_date[64];
    char allocated_id[RICTUS_INTELLIGENCE_SRT_ID_MAX];
    char normalized_reviewer[RICTUS_INTELLIGENCE_SRT_TEXT_MAX];
    char normalized_office[RICTUS_INTELLIGENCE_SRT_TEXT_MAX];
    char previous_status[RICTUS_INTELLIGENCE_SRT_STATUS_MAX];
    char previous_srt_id[RICTUS_INTELLIGENCE_SRT_ID_MAX];
    int written;

    if (
        store == NULL ||
        path == NULL ||
        directory == NULL ||
        intelligence_id == NULL ||
        reviewer == NULL ||
        reviewer_office == NULL ||
        srt_id == NULL ||
        srt_id_size == 0 ||
        approved_report_path == NULL ||
        approved_report_path_size == 0
        )
    {
        return 0;
    }

    request =
        (rictus_intelligence_srt_request_t *)
        rictus_intelligence_srt_store_find(
            store,
            intelligence_id
        );

    if (
        request == NULL ||
        strcasecmp(request->status, "REQUESTED") != 0 ||
        request->srt_id[0] != '\0'
        )
    {
        return 0;
    }

    if (
        !rictus_intelligence_srt_allocate_id(
            store,
            allocated_id,
            sizeof(allocated_id)
        ) ||
        !rictus_intelligence_srt_timestamp(
            review_date,
            sizeof(review_date)
        )
        )
    {
        return 0;
    }

    rictus_intelligence_srt_normalize_text(
        reviewer,
        normalized_reviewer,
        sizeof(normalized_reviewer)
    );

    rictus_intelligence_srt_normalize_text(
        reviewer_office,
        normalized_office,
        sizeof(normalized_office)
    );

    written =
        snprintf(
            candidate_path,
            sizeof(candidate_path),
            "%s/%s.srt.md",
            directory,
            intelligence_id
        );

    if (
        written <= 0 ||
        written >= (int)sizeof(candidate_path)
        )
    {
        return 0;
    }

    written =
        snprintf(
            temporary_approved_path,
            sizeof(temporary_approved_path),
            "%s\\%s.approved.tmp",
            directory,
            allocated_id
        );

    if (
        written <= 0 ||
        written >= (int)sizeof(temporary_approved_path)
        )
    {
        return 0;
    }

    if (
        !rictus_intelligence_srt_write_approved_report(
            candidate_path,
            temporary_approved_path,
            intelligence_id,
            allocated_id,
            normalized_reviewer,
            normalized_office,
            review_date
        )
        )
    {
        return 0;
    }

    snprintf(previous_status, sizeof(previous_status), "%s", request->status);

    snprintf(previous_srt_id, sizeof(previous_srt_id), "%s", request->srt_id);

    if (
        snprintf(request->status, sizeof(request->status), "%s", "APPROVED") != 0 ||
        snprintf(request->srt_id, sizeof(request->srt_id), "%s", allocated_id) != 0
        )
    {
        unlink(temporary_approved_path);
        return 0;
    }

    if (
        !rictus_intelligence_srt_store_rewrite(
            store,
            path
        )
        )
    {
        snprintf(request->status, sizeof(request->status), "%s", previous_status);

        snprintf(request->srt_id, sizeof(request->srt_id), "%s", previous_srt_id);

        unlink(temporary_approved_path);
        return 0;
    }

    written =
        snprintf(
            approved_report_path,
            approved_report_path_size,
            "%s/%s.srt.md",
            directory,
            allocated_id
        );

    if (
        written <= 0 ||
        written >= (int)approved_report_path_size
        )
    {
        return 0;
    }

    if (rename(temporary_approved_path, approved_report_path) != 0)
    {
        return 0;
    }

    /*
     * Approval creates the SRT identity. The INT candidate
     * is replaced by the approved SRT document; provenance
     * inside the approved document retains the INT identity.
     */

    if (
        !unlink(candidate_path)
        )
    {
        /*
         * The approved SRT and registry are already durable.
         * Leaving the Pending candidate beside it would make
         * state ambiguous, so report failure to the caller.
         */
        return 0;
    }

    if (
        snprintf(srt_id, srt_id_size, "%s", allocated_id) >= (int)srt_id_size
        )
    {
        return 0;
    }

    return 1;
}


/*
 * Persist a terminal human rejection. Rejected intelligence remains
 * available as evidence, but it can no longer become an SRT through
 * this registry.
 */
int
rictus_intelligence_srt_reject(
    rictus_intelligence_srt_store_t *store,
    const char *path,
    const char *intelligence_id
)
{
    rictus_intelligence_srt_request_t *request;
    char previous_status[RICTUS_INTELLIGENCE_SRT_STATUS_MAX];

    if (store == NULL || path == NULL || intelligence_id == NULL)
    {
        return 0;
    }

    request = (rictus_intelligence_srt_request_t *)
        rictus_intelligence_srt_store_find(store, intelligence_id);

    if (request == NULL ||
        strcasecmp(request->status, "REQUESTED") != 0 ||
        request->srt_id[0] != '\0')
    {
        return 0;
    }

    snprintf(previous_status, sizeof(previous_status), "%s", request->status);
    if (snprintf(request->status, sizeof(request->status), "%s", "REJECTED") != 0)
    {
        return 0;
    }

    if (!rictus_intelligence_srt_store_rewrite(store, path))
    {
        snprintf(request->status, sizeof(request->status), "%s", previous_status);
        return 0;
    }

    return 1;
}


/*
 * ------------------------------------------------
 * REPORT GENERATION
 * ------------------------------------------------
 */

int
rictus_intelligence_srt_generate_report(
    const char *directory,
    const rictus_intelligence_record_t *record,
    const char *requested_by,
    char *report_path,
    size_t report_path_size
)
{
    FILE *file;

    char timestamp[
        64
    ];

    char source[
        RICTUS_INTELLIGENCE_SRT_TEXT_MAX
    ];

    char title[
        RICTUS_INTELLIGENCE_SRT_TEXT_MAX
    ];

    char url[
        RICTUS_INTELLIGENCE_SRT_TEXT_MAX
    ];

    char published[
        RICTUS_INTELLIGENCE_SRT_TEXT_MAX
    ];

    char summary[
        RICTUS_INTELLIGENCE_SRT_TEXT_MAX
    ];

    char fingerprint[
        RICTUS_INTELLIGENCE_SRT_TEXT_MAX
    ];

    char content[
        RICTUS_INTELLIGENCE_ITEM_CONTENT_MAX
    ];

    char requester[
        RICTUS_INTELLIGENCE_SRT_TEXT_MAX
    ];

    int written;


    if (
        directory == NULL ||
        directory[0] == '\0' ||
        record == NULL ||
        requested_by == NULL ||
        requested_by[0] == '\0' ||
        report_path == NULL ||
        report_path_size == 0
        )
    {
        return 0;
    }


    if (
        !rictus_intelligence_srt_ensure_directory(
            directory
        )
        )
    {
        return 0;
    }


    written =
        snprintf(
            report_path,
            report_path_size,
            "%s/%s.srt.md",
            directory,
            record->id
        );


    if (
        written <= 0 ||
        written >=
            (int)report_path_size
        )
    {
        return 0;
    }


    if (
        !rictus_intelligence_srt_timestamp(
            timestamp,
            sizeof(timestamp)
        )
        )
    {
        return 0;
    }


    rictus_intelligence_srt_normalize_text(
        record->item.source,
        source,
        sizeof(source)
    );


    rictus_intelligence_srt_normalize_text(
        record->item.title,
        title,
        sizeof(title)
    );


    rictus_intelligence_srt_normalize_text(
        record->item.url,
        url,
        sizeof(url)
    );


    rictus_intelligence_srt_normalize_text(
        record->item.published,
        published,
        sizeof(published)
    );


    rictus_intelligence_srt_normalize_text(
        record->item.summary,
        summary,
        sizeof(summary)
    );


    rictus_intelligence_srt_normalize_text(
        record->item.fingerprint,
        fingerprint,
        sizeof(fingerprint)
    );


    if (record->item.content[0] != '\0')
    {
        snprintf(content, sizeof(content), "%s", record->item.content);
    }
    else
    {
        snprintf(content, sizeof(content), "%s", "No source content was retained.");
    }


    rictus_intelligence_srt_normalize_text(
        requested_by,
        requester,
        sizeof(requester)
    );


    if (
        ((file = fopen(report_path, "w")) == NULL)
        )
    {
        return 0;
    }


    if (
        fprintf(
            file,
            "# Security Research Target\n"
            "\n"
            "Root Document ID: PENDING\n"
            "Revision ID: PENDING\n"
            "Previous Revision: NONE\n"
            "sha256: <hash>\n"
            "\n"
            "**Status**: Pending\n"
            "\n"
            "## Record Identity\n"
            "\n"
            "Document ID: %s\n"
            "Document Type: Security Research Target Candidate\n"
            "Origin: Rictus Intelligence\n"
            "\n"
            "## Source Evidence\n"
            "\n"
            "Source: %s\n"
            "Title: %s\n"
            "URL: %s\n"
            "Published: %s\n"
            "Intelligence Fingerprint: %s\n"
            "\n"
            "## Intelligence Context\n"
            "\n"
            "%s\n"
            "\n"
            "## Source Content\n"
            "\n"
            "%s\n"
            "\n"
            "## SRT Request\n"
            "\n"
            "Requested By: %s\n"
            "Requested Through: Rictus\n"
            "Disposition: SRT CANDIDATE\n"
            "Human Review: REQUIRED\n"
            "\n"
            "## Research\n"
            "\n"
            "Status: NOT YET PERFORMED\n"
            "\n"
            "## Provenance\n"
            "\n"
            "Collected By: Rictus Intelligence\n"
            "Source Intelligence ID: %s\n"
            "Original Source: %s\n"
            "SRT Request Timestamp: %s\n"
            "\n"
            "## Human Review\n"
            "\n"
            "Decision: PENDING\n"
            "Reviewer: PENDING\n"
            "Reviewer Office: PENDING\n"
            "Review Date: PENDING\n"
            "Notes: PENDING\n",
            record->id,
            source[0] != '\0'
                ? source
                : "UNKNOWN",
            title[0] != '\0'
                ? title
                : "UNKNOWN",
            url[0] != '\0'
                ? url
                : "UNKNOWN",
            published[0] != '\0'
                ? published
                : "UNKNOWN",
            fingerprint[0] != '\0'
                ? fingerprint
                : "UNKNOWN",
            summary[0] != '\0'
                ? summary
                : "No source-derived summary was retained.",
            content,
            requester,
            record->id,
            url[0] != '\0'
                ? url
                : "UNKNOWN",
            timestamp
        ) < 0
        )
    {
        fclose(
            file
        );


        unlink(
            report_path
        );


        return 0;
    }


    if (
        fflush(
            file
        ) != 0
        )
    {
        fclose(
            file
        );


        unlink(
            report_path
        );


        return 0;
    }


    fclose(
        file
    );


    return 1;
}
