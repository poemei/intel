#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "record.h"

#define RECORD_LINE_MAX 65536

static unsigned long
record_hash_update(
    unsigned long hash,
    const char* text
)
{
    const unsigned char* cursor;

    if (text == NULL)
    {
        return hash;
    }

    cursor = (const unsigned char*)text;

    while (*cursor != '\0')
    {
        hash ^= *cursor++;
        hash *= 16777619UL;
    }

    return hash;
}

static int
record_make_id(
    const rictus_intelligence_record_store_t* store,
    const rictus_intelligence_item_t* item,
    char* output,
    size_t output_size
)
{
    unsigned int attempt;

    if (
        store == NULL ||
        item == NULL ||
        output == NULL ||
        output_size < 13
        )
    {
        return 0;
    }

    for (attempt = 0; attempt < 256; ++attempt)
    {
        unsigned long hash = 2166136261UL ^ (unsigned long)attempt;

        hash = record_hash_update(hash, item->fingerprint);
        hash = record_hash_update(hash, item->url);
        hash = record_hash_update(hash, item->title);

        if (
            snprintf(
                output,
                output_size,
                "INT-%08lX",
                hash
            ) <= 0
            )
        {
            return 0;
        }

        if (
            rictus_intelligence_record_store_find(
                store,
                output
            ) == NULL
            )
        {
            return 1;
        }
    }

    return 0;
}

static void
record_escape(
    const char* input,
    char* output,
    size_t output_size
)
{
    size_t i = 0;
    size_t o = 0;

    if (output == NULL || output_size == 0)
    {
        return;
    }

    output[0] = '\0';

    if (input == NULL)
    {
        return;
    }

    while (input[i] != '\0' && o + 1 < output_size)
    {
        char c = input[i++];

        if (c == '\\' || c == '\t' || c == '\r' || c == '\n')
        {
            if (o + 2 >= output_size)
            {
                break;
            }

            output[o++] = '\\';

            if (c == '\\') output[o++] = '\\';
            else if (c == '\t') output[o++] = 't';
            else if (c == '\r') output[o++] = 'r';
            else output[o++] = 'n';
        }
        else
        {
            output[o++] = c;
        }
    }

    output[o] = '\0';
}

static void
record_unescape(
    const char* input,
    char* output,
    size_t output_size
)
{
    size_t i = 0;
    size_t o = 0;

    if (output == NULL || output_size == 0)
    {
        return;
    }

    output[0] = '\0';

    if (input == NULL)
    {
        return;
    }

    while (input[i] != '\0' && o + 1 < output_size)
    {
        if (input[i] == '\\' && input[i + 1] != '\0')
        {
            ++i;

            if (input[i] == 't') output[o++] = '\t';
            else if (input[i] == 'r') output[o++] = '\r';
            else if (input[i] == 'n') output[o++] = '\n';
            else output[o++] = input[i];

            ++i;
        }
        else
        {
            output[o++] = input[i++];
        }
    }

    output[o] = '\0';
}

void
rictus_intelligence_record_store_init(
    rictus_intelligence_record_store_t* store
)
{
    if (store != NULL)
    {
        memset(store, 0, sizeof(*store));
    }
}

const rictus_intelligence_record_t*
rictus_intelligence_record_store_find(
    const rictus_intelligence_record_store_t* store,
    const char* id
)
{
    size_t i;

    if (store == NULL || id == NULL || id[0] == '\0')
    {
        return NULL;
    }

    for (i = 0; i < store->count; ++i)
    {
        if (strcasecmp(store->records[i].id, id) == 0)
        {
            return &store->records[i];
        }
    }

    return NULL;
}

int
rictus_intelligence_record_store_load(
    rictus_intelligence_record_store_t* store,
    const char* path
)
{
    FILE* file;
    char line[RECORD_LINE_MAX];

    if (store == NULL || path == NULL)
    {
        return 0;
    }

    rictus_intelligence_record_store_init(store);

    if (((file = fopen(path, "r")) == NULL))
    {
        return 1;
    }

    while (fgets(line, sizeof(line), file) != NULL)
    {
        char* context = NULL;
        char* fields[15];
        char* token;
        size_t count = 0;
        rictus_intelligence_record_t* record;

        line[strcspn(line, "\r\n")] = '\0';

        token = strtok_r(line, "\t", &context);

        while (token != NULL && count < 15)
        {
            fields[count++] = token;
            token = strtok_r(NULL, "\t", &context);
        }

        if (count != 7 && count != 8 && count != 15)
        {
            continue;
        }

        if (store->count >= RICTUS_INTELLIGENCE_RECORD_MAX)
        {
            fclose(file);
            return 0;
        }

        record = &store->records[store->count];
        memset(record, 0, sizeof(*record));

        snprintf(record->id, sizeof(record->id), "%s", fields[0]);
        record_unescape(fields[1], record->item.source, sizeof(record->item.source));
        record_unescape(fields[2], record->item.title, sizeof(record->item.title));
        record_unescape(fields[3], record->item.url, sizeof(record->item.url));
        record_unescape(fields[4], record->item.published, sizeof(record->item.published));
        record_unescape(fields[5], record->item.summary, sizeof(record->item.summary));

        if (count == 8)
        {
            record_unescape(fields[6], record->item.content, sizeof(record->item.content));
            record_unescape(fields[7], record->item.fingerprint, sizeof(record->item.fingerprint));
        }

        else if (count == 15)
        {
            record_unescape(fields[6], record->item.content, sizeof(record->item.content));
            record_unescape(fields[7], record->item.fingerprint, sizeof(record->item.fingerprint));
            record_unescape(fields[8], record->item.observed, sizeof(record->item.observed));
            record_unescape(fields[9], record->item.root_source, sizeof(record->item.root_source));
            record_unescape(fields[10], record->item.why_stn_labz_cares, sizeof(record->item.why_stn_labz_cares));
            record_unescape(fields[11], record->item.evidence, sizeof(record->item.evidence));
            record_unescape(fields[12], record->item.assessment, sizeof(record->item.assessment));
            record_unescape(fields[13], record->item.unknowns, sizeof(record->item.unknowns));
            record_unescape(fields[14], record->item.provenance, sizeof(record->item.provenance));
        }
        else
        {
            record->item.content[0] = '\0';
            record_unescape(fields[6], record->item.fingerprint, sizeof(record->item.fingerprint));
        }

        ++store->count;
    }

    fclose(file);
    return 1;
}

int
rictus_intelligence_record_store_append(
    rictus_intelligence_record_store_t* store,
    const char* path,
    const rictus_intelligence_item_t* item,
    char* id,
    size_t id_size
)
{
    FILE* file;
    char candidate[RICTUS_INTELLIGENCE_RECORD_ID_MAX];
    char source[256];
    char title[1024];
    char url[2048];
    char published[256];
    char summary[4096];
    char content[RICTUS_INTELLIGENCE_ITEM_CONTENT_MAX * 2];
    char fingerprint[128];
    char observed[128];
    char root_source[256];
    char why[RICTUS_INTELLIGENCE_ITEM_WHY_MAX * 2];
    char evidence[RICTUS_INTELLIGENCE_ITEM_EVIDENCE_MAX * 2];
    char assessment[RICTUS_INTELLIGENCE_ITEM_ASSESSMENT_MAX * 2];
    char unknowns[RICTUS_INTELLIGENCE_ITEM_UNKNOWNS_MAX * 2];
    char provenance[RICTUS_INTELLIGENCE_ITEM_PROVENANCE_MAX * 2];
    rictus_intelligence_record_t* record;

    if (
        store == NULL ||
        path == NULL ||
        item == NULL ||
        id == NULL ||
        id_size == 0 ||
        store->count >= RICTUS_INTELLIGENCE_RECORD_MAX
        )
    {
        return 0;
    }

    if (!record_make_id(store, item, candidate, sizeof(candidate)))
    {
        return 0;
    }

    record_escape(item->source, source, sizeof(source));
    record_escape(item->title, title, sizeof(title));
    record_escape(item->url, url, sizeof(url));
    record_escape(item->published, published, sizeof(published));
    record_escape(item->summary, summary, sizeof(summary));
    record_escape(item->content, content, sizeof(content));
    record_escape(item->fingerprint, fingerprint, sizeof(fingerprint));
    record_escape(item->observed, observed, sizeof(observed));
    record_escape(item->root_source, root_source, sizeof(root_source));
    record_escape(item->why_stn_labz_cares, why, sizeof(why));
    record_escape(item->evidence, evidence, sizeof(evidence));
    record_escape(item->assessment, assessment, sizeof(assessment));
    record_escape(item->unknowns, unknowns, sizeof(unknowns));
    record_escape(item->provenance, provenance, sizeof(provenance));

    if (((file = fopen(path, "a")) == NULL))
    {
        return 0;
    }

    if (
        fprintf(
            file,
            "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
            candidate,
            source,
            title,
            url,
            published,
            summary,
            content,
            fingerprint,
            observed,
            root_source,
            why,
            evidence,
            assessment,
            unknowns,
            provenance
        ) < 0 ||
        fflush(file) != 0
        )
    {
        fclose(file);
        return 0;
    }

    fclose(file);

    record = &store->records[store->count];
    memset(record, 0, sizeof(*record));
    snprintf(record->id, sizeof(record->id), "%s", candidate);
    record->item = *item;
    ++store->count;

    snprintf(id, id_size, "%s", candidate);
    return 1;
}
