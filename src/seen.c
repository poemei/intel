/*
 * STN-LABZ
 * Rictus Intelligence Module
 *
 * seen.c
 *
 * Persistent local duplicate-detection state.
 */

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "seen.h"


#define RICTUS_INTELLIGENCE_STATE_NAME \
    "intelligence"

#define RICTUS_INTELLIGENCE_SEEN_FILENAME \
    "seen.index"


static int
rictus_intelligence_seen_paths(
    char *directory,
    size_t directory_size,
    char *path,
    size_t path_size
)
{
    int written;

    if (directory == NULL || path == NULL) return 0;

    written = snprintf(directory, directory_size, "state/%s",
        RICTUS_INTELLIGENCE_STATE_NAME);
    if (written < 0 || (size_t)written >= directory_size) return 0;

    written = snprintf(path, path_size, "%s/%s", directory,
        RICTUS_INTELLIGENCE_SEEN_FILENAME);
    return written >= 0 && (size_t)written < path_size;
}

static int
rictus_intelligence_seen_ensure_directory(const char *directory)
{
    struct stat st;

    if (directory == NULL || directory[0] == '\0') return 0;

    if (mkdir("state", 0750) != 0 && errno != EEXIST) return 0;
    if (mkdir(directory, 0750) != 0 && errno != EEXIST) return 0;

    if (stat(directory, &st) != 0) return 0;
    return S_ISDIR(st.st_mode);
}

void
rictus_intelligence_seen_init(
    rictus_intelligence_seen_t *seen
)
{
    if (
        seen == NULL
    )
    {
        return;
    }


    memset(
        seen,
        0,
        sizeof(*seen)
    );
}


int
rictus_intelligence_seen_contains(
    const rictus_intelligence_seen_t *seen,
    const char *fingerprint
)
{
    size_t index;


    if (
        seen == NULL ||
        fingerprint == NULL ||
        fingerprint[0] == '\0'
    )
    {
        return 0;
    }


    for (
        index = 0;
        index < seen->count;
        ++index
    )
    {
        if (
            strcmp(
                seen->fingerprints[index],
                fingerprint
            ) == 0
        )
        {
            return 1;
        }
    }


    return 0;
}


rictus_intelligence_seen_result_t
rictus_intelligence_seen_load(
    rictus_intelligence_seen_t *seen
)
{
    FILE *file =
        NULL;

    char line[
        RICTUS_INTELLIGENCE_ITEM_FINGERPRINT_MAX +
        16
    ];


    char directory[1024];
    char path[1024];


    if (
        seen == NULL
    )
    {
        return
            RICTUS_INTELLIGENCE_SEEN_INVALID_ARGUMENT;
    }


    rictus_intelligence_seen_init(
        seen
    );


    if (
        !rictus_intelligence_seen_paths(
            directory,
            sizeof(directory),
            path,
            sizeof(path)
        ) ||
        !rictus_intelligence_seen_ensure_directory(
            directory
        )
    )
    {
        return
            RICTUS_INTELLIGENCE_SEEN_OPEN_FAILED;
    }


    if (
        ((file = fopen(path, "r")) == NULL)
    )
    {
        /*
         * First execution is valid.
         *
         * Absence means no prior items have been
         * recorded.
         */

        return
            RICTUS_INTELLIGENCE_SEEN_OK;
    }


    while (
        fgets(
            line,
            sizeof(line),
            file
        ) != NULL
    )
    {
        size_t length;


        length =
            strlen(
                line
            );


        while (
            length > 0 &&
            (
                line[length - 1] == '\r' ||
                line[length - 1] == '\n'
            )
        )
        {
            line[
                length - 1
            ] =
                '\0';

            --length;
        }


        if (
            length == 0
        )
        {
            continue;
        }


        if (
            length >=
            RICTUS_INTELLIGENCE_ITEM_FINGERPRINT_MAX
        )
        {
            fclose(
                file
            );


            return
                RICTUS_INTELLIGENCE_SEEN_OPEN_FAILED;
        }


        if (
            seen->count >=
            RICTUS_INTELLIGENCE_SEEN_MAX
        )
        {
            fclose(
                file
            );


            return
                RICTUS_INTELLIGENCE_SEEN_FULL;
        }


        if (
            rictus_intelligence_seen_contains(
                seen,
                line
            )
        )
        {
            continue;
        }


        memcpy(
            seen->fingerprints[
                seen->count
            ],
            line,
            length + 1
        );


        seen->count++;
    }


    fclose(
        file
    );


    return
        RICTUS_INTELLIGENCE_SEEN_OK;
}


rictus_intelligence_seen_result_t
rictus_intelligence_seen_add(
    rictus_intelligence_seen_t *seen,
    const char *fingerprint
)
{
    FILE *file =
        NULL;

    size_t length;

    char directory[1024];
    char path[1024];


    if (
        seen == NULL ||
        fingerprint == NULL ||
        fingerprint[0] == '\0'
    )
    {
        return
            RICTUS_INTELLIGENCE_SEEN_INVALID_ARGUMENT;
    }


    if (
        rictus_intelligence_seen_contains(
            seen,
            fingerprint
        )
    )
    {
        return
            RICTUS_INTELLIGENCE_SEEN_OK;
    }


    if (
        seen->count >=
        RICTUS_INTELLIGENCE_SEEN_MAX
    )
    {
        return
            RICTUS_INTELLIGENCE_SEEN_FULL;
    }


    length =
        strlen(
            fingerprint
        );


    if (
        length >=
        RICTUS_INTELLIGENCE_ITEM_FINGERPRINT_MAX
    )
    {
        return
            RICTUS_INTELLIGENCE_SEEN_INVALID_ARGUMENT;
    }


    if (
        !rictus_intelligence_seen_paths(
            directory,
            sizeof(directory),
            path,
            sizeof(path)
        ) ||
        !rictus_intelligence_seen_ensure_directory(
            directory
        )
    )
    {
        return
            RICTUS_INTELLIGENCE_SEEN_OPEN_FAILED;
    }


    if (
        ((file = fopen(path, "a")) == NULL)
    )
    {
        return
            RICTUS_INTELLIGENCE_SEEN_OPEN_FAILED;
    }


    if (
        fprintf(
            file,
            "%s\n",
            fingerprint
        ) < 0
    )
    {
        fclose(
            file
        );


        return
            RICTUS_INTELLIGENCE_SEEN_WRITE_FAILED;
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


        return
            RICTUS_INTELLIGENCE_SEEN_WRITE_FAILED;
    }


    fclose(
        file
    );


    memcpy(
        seen->fingerprints[
            seen->count
        ],
        fingerprint,
        length + 1
    );


    seen->count++;


    return
        RICTUS_INTELLIGENCE_SEEN_OK;
}


const char *
rictus_intelligence_seen_result_string(
    rictus_intelligence_seen_result_t result
)
{
    switch (
        result
    )
    {
        case RICTUS_INTELLIGENCE_SEEN_OK:

            return "OK";


        case RICTUS_INTELLIGENCE_SEEN_INVALID_ARGUMENT:

            return "INVALID_ARGUMENT";


        case RICTUS_INTELLIGENCE_SEEN_OPEN_FAILED:

            return "OPEN_FAILED";


        case RICTUS_INTELLIGENCE_SEEN_WRITE_FAILED:

            return "WRITE_FAILED";


        case RICTUS_INTELLIGENCE_SEEN_FULL:

            return "FULL";


        default:

            return "UNKNOWN";
    }
}
