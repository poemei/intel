/*
 * STN-LABZ
 * Rictus Intelligence Module
 *
 * parser.c
 *
 * Normalization layer.
 *
 * Responsibilities:
 *
 * - convert collected source material into bounded
 *   normalized Intelligence items
 * - preserve source identity
 * - preserve source URL
 * - preserve publication metadata where available
 * - generate deterministic non-security fingerprints
 *
 * Fingerprints are used only for local duplicate
 * detection.
 *
 * They are not Trust Chain hashes and are not used
 * as authoritative integrity evidence.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "parser.h"


/*
 * ------------------------------------------------
 * FNV-1A 64-BIT FINGERPRINT
 * ------------------------------------------------
 */

static uint64_t
rictus_intelligence_fnv1a(
    const unsigned char *data,
    size_t length,
    uint64_t hash
)
{
    size_t index;


    if (
        data == NULL
    )
    {
        return hash;
    }


    for (
        index = 0;
        index < length;
        ++index
    )
    {
        hash ^=
            (uint64_t)data[index];

        hash *=
            UINT64_C(
                1099511628211
            );
    }


    return hash;
}


static void
rictus_intelligence_item_fingerprint(
    rictus_intelligence_item_t *item
)
{
    uint64_t hash;


    if (
        item == NULL
    )
    {
        return;
    }


    hash =
        UINT64_C(
            14695981039346656037
        );


    hash =
        rictus_intelligence_fnv1a(
            (const unsigned char *)
            item->source,
            strlen(
                item->source
            ),
            hash
        );


    hash =
        rictus_intelligence_fnv1a(
            (const unsigned char *)
            item->title,
            strlen(
                item->title
            ),
            hash
        );


    hash =
        rictus_intelligence_fnv1a(
            (const unsigned char *)
            item->url,
            strlen(
                item->url
            ),
            hash
        );


    hash =
        rictus_intelligence_fnv1a(
            (const unsigned char *)
            item->published,
            strlen(
                item->published
            ),
            hash
        );


    (void)
    snprintf(
        item->fingerprint,
        sizeof(item->fingerprint),
        "%016llx",
        (unsigned long long)
        hash
    );
}


/*
 * ------------------------------------------------
 * BOUNDED COPY
 * ------------------------------------------------
 */

static int
rictus_intelligence_copy(
    char *destination,
    size_t destination_size,
    const char *source,
    size_t source_length
)
{
    if (
        destination == NULL ||
        destination_size == 0 ||
        source == NULL
    )
    {
        return 0;
    }


    if (
        source_length >=
        destination_size
    )
    {
        source_length =
            destination_size - 1;
    }


    memcpy(
        destination,
        source,
        source_length
    );


    destination[
        source_length
    ] =
        '\0';


    return 1;
}


/*
 * ------------------------------------------------
 * TRIM
 * ------------------------------------------------
 */

static void
rictus_intelligence_trim(
    char *value
)
{
    char *start;

    size_t length;


    if (
        value == NULL
    )
    {
        return;
    }


    start =
        value;


    while (
        *start == ' ' ||
        *start == '\t' ||
        *start == '\r' ||
        *start == '\n'
    )
    {
        ++start;
    }


    if (
        start != value
    )
    {
        memmove(
            value,
            start,
            strlen(start) + 1
        );
    }


    length =
        strlen(
            value
        );


    while (
        length > 0 &&
        (
            value[length - 1] == ' ' ||
            value[length - 1] == '\t' ||
            value[length - 1] == '\r' ||
            value[length - 1] == '\n'
        )
    )
    {
        value[
            length - 1
        ] =
            '\0';

        --length;
    }
}


/*
 * ------------------------------------------------
 * STRIP CDATA
 * ------------------------------------------------
 */

static void
rictus_intelligence_strip_cdata(
    char *value
)
{
    size_t length;


    if (
        value == NULL
    )
    {
        return;
    }


    length =
        strlen(
            value
        );


    if (
        length >= 12 &&
        strncmp(
            value,
            "<![CDATA[",
            9
        ) == 0 &&
        strcmp(
            value + length - 3,
            "]]>"
        ) == 0
    )
    {
        memmove(
            value,
            value + 9,
            length - 12
        );


        value[
            length - 12
        ] =
            '\0';
    }
}


/*
 * ------------------------------------------------
 * SIMPLE ENTITY DECODING
 * ------------------------------------------------
 */

static void
rictus_intelligence_decode_entities(
    char *value
)
{
    char output[
        RICTUS_INTELLIGENCE_ITEM_SUMMARY_MAX
    ];

    size_t input_index =
        0;

    size_t output_index =
        0;


    if (
        value == NULL
    )
    {
        return;
    }


    memset(
        output,
        0,
        sizeof(output)
    );


    while (
        value[input_index] != '\0' &&
        output_index <
            sizeof(output) - 1
    )
    {
        if (
            strncmp(
                value + input_index,
                "&amp;",
                5
            ) == 0
        )
        {
            output[
                output_index++
            ] =
                '&';

            input_index +=
                5;

            continue;
        }


        if (
            strncmp(
                value + input_index,
                "&lt;",
                4
            ) == 0
        )
        {
            output[
                output_index++
            ] =
                '<';

            input_index +=
                4;

            continue;
        }


        if (
            strncmp(
                value + input_index,
                "&gt;",
                4
            ) == 0
        )
        {
            output[
                output_index++
            ] =
                '>';

            input_index +=
                4;

            continue;
        }


        if (
            strncmp(
                value + input_index,
                "&quot;",
                6
            ) == 0
        )
        {
            output[
                output_index++
            ] =
                '"';

            input_index +=
                6;

            continue;
        }


        if (
            strncmp(
                value + input_index,
                "&#39;",
                5
            ) == 0
        )
        {
            output[
                output_index++
            ] =
                '\'';

            input_index +=
                5;

            continue;
        }


        output[
            output_index++
        ] =
            value[
                input_index++
            ];
    }


    output[
        output_index
    ] =
        '\0';


    (void)
    rictus_intelligence_copy(
        value,
        RICTUS_INTELLIGENCE_ITEM_SUMMARY_MAX,
        output,
        strlen(output)
    );
}


/*
 * ------------------------------------------------
 * REMOVE HTML TAGS
 * ------------------------------------------------
 */

static void
rictus_intelligence_strip_tags(
    char *value
)
{
    char output[
        RICTUS_INTELLIGENCE_ITEM_SUMMARY_MAX
    ];

    size_t input_index =
        0;

    size_t output_index =
        0;

    int inside_tag =
        0;


    if (
        value == NULL
    )
    {
        return;
    }


    memset(
        output,
        0,
        sizeof(output)
    );


    while (
        value[input_index] != '\0' &&
        output_index <
            sizeof(output) - 1
    )
    {
        char c;


        c =
            value[
                input_index++
            ];


        if (
            c == '<'
        )
        {
            inside_tag =
                1;

            continue;
        }


        if (
            c == '>'
        )
        {
            inside_tag =
                0;

            continue;
        }


        if (
            !inside_tag
        )
        {
            output[
                output_index++
            ] =
                c;
        }
    }


    output[
        output_index
    ] =
        '\0';


    (void)
    rictus_intelligence_copy(
        value,
        RICTUS_INTELLIGENCE_ITEM_SUMMARY_MAX,
        output,
        strlen(output)
    );


    rictus_intelligence_trim(
        value
    );
}


/*
 * ------------------------------------------------
 * XML FIELD
 * ------------------------------------------------
 */

static int
rictus_intelligence_xml_field(
    const char *begin,
    const char *end,
    const char *tag,
    char *output,
    size_t output_size
)
{
    char open_tag[
        64
    ];

    char close_tag[
        64
    ];

    const char *start;

    const char *finish;

    int written;


    if (
        begin == NULL ||
        end == NULL ||
        tag == NULL ||
        output == NULL ||
        output_size == 0 ||
        end <= begin
    )
    {
        return 0;
    }


    output[0] =
        '\0';


    written =
        snprintf(
            open_tag,
            sizeof(open_tag),
            "<%s>",
            tag
        );


    if (
        written <= 0 ||
        (size_t)written >=
            sizeof(open_tag)
    )
    {
        return 0;
    }


    written =
        snprintf(
            close_tag,
            sizeof(close_tag),
            "</%s>",
            tag
        );


    if (
        written <= 0 ||
        (size_t)written >=
            sizeof(close_tag)
    )
    {
        return 0;
    }


    start =
        strstr(
            begin,
            open_tag
        );


    if (
        start == NULL ||
        start >= end
    )
    {
        return 0;
    }


    start +=
        strlen(
            open_tag
        );


    finish =
        strstr(
            start,
            close_tag
        );


    if (
        finish == NULL ||
        finish > end
    )
    {
        return 0;
    }


    if (
        !rictus_intelligence_copy(
            output,
            output_size,
            start,
            (size_t)
            (
                finish -
                start
            )
        )
    )
    {
        return 0;
    }


    rictus_intelligence_trim(
        output
    );


    rictus_intelligence_strip_cdata(
        output
    );


    rictus_intelligence_decode_entities(
        output
    );


    return 1;
}


/*
 * ------------------------------------------------
 * NASA RSS
 * ------------------------------------------------
 */

static
rictus_intelligence_parse_result_t
rictus_intelligence_parse_rss(
    const rictus_intelligence_source_definition_t *source,
    const rictus_intelligence_response_t *response,
    rictus_intelligence_item_set_t *items
)
{
    const char *cursor;

    const char *document_end;


    cursor =
        response->body;


    document_end =
        response->body +
        response->body_length;


    while (
        cursor <
        document_end
    )
    {
        const char *item_begin;

        const char *item_end;

        rictus_intelligence_item_t
            *item;


        item_begin =
            strstr(
                cursor,
                "<item"
            );


        if (
            item_begin == NULL ||
            item_begin >=
                document_end
        )
        {
            break;
        }


        item_begin =
            strchr(
                item_begin,
                '>'
            );


        if (
            item_begin == NULL ||
            item_begin >=
                document_end
        )
        {
            return
                RICTUS_INTELLIGENCE_PARSE_INVALID_FORMAT;
        }


        ++item_begin;


        item_end =
            strstr(
                item_begin,
                "</item>"
            );


        if (
            item_end == NULL ||
            item_end >
                document_end
        )
        {
            return
                RICTUS_INTELLIGENCE_PARSE_INVALID_FORMAT;
        }


        if (
            items->count >=
            RICTUS_INTELLIGENCE_ITEMS_MAX
        )
        {
            return
                RICTUS_INTELLIGENCE_PARSE_ITEM_LIMIT;
        }


        item =
            &items->items[
                items->count
            ];


        memset(
            item,
            0,
            sizeof(*item)
        );


        (void)
        rictus_intelligence_copy(
            item->source,
            sizeof(item->source),
            source->name,
            strlen(source->name)
        );


        (void)
        rictus_intelligence_xml_field(
            item_begin,
            item_end,
            "title",
            item->title,
            sizeof(item->title)
        );


        (void)
        rictus_intelligence_xml_field(
            item_begin,
            item_end,
            "link",
            item->url,
            sizeof(item->url)
        );


        (void)
        rictus_intelligence_xml_field(
            item_begin,
            item_end,
            "pubDate",
            item->published,
            sizeof(item->published)
        );


        (void)
        rictus_intelligence_xml_field(
            item_begin,
            item_end,
            "description",
            item->summary,
            sizeof(item->summary)
        );


        rictus_intelligence_strip_tags(
            item->summary
        );


        (void)
        rictus_intelligence_copy(
            item->content,
            sizeof(item->content),
            item->summary,
            strlen(item->summary)
        );


        /*
         * Title and URL form the minimum useful
         * normalized RSS intelligence object.
         */

        if (
            item->title[0] != '\0' &&
            item->url[0] != '\0'
        )
        {
            rictus_intelligence_item_fingerprint(
                item
            );


            items->count++;
        }


        cursor =
            item_end +
            strlen(
                "</item>"
            );
    }


    if (
        items->count == 0
    )
    {
        return
            RICTUS_INTELLIGENCE_PARSE_INVALID_FORMAT;
    }


    return
        RICTUS_INTELLIGENCE_PARSE_OK;
}


/*
 * Atom is accepted under the existing RSS transport policy.  It is a
 * syndication format, not a new transport, and is required by PHP.net and
 * CERT/CC.  Entries are normalized into the same bounded item structure.
 */
static rictus_intelligence_parse_result_t
rictus_intelligence_parse_atom(
    const rictus_intelligence_source_definition_t *source,
    const rictus_intelligence_response_t *response,
    rictus_intelligence_item_set_t *items
)
{
    const char *cursor = response->body;
    const char *document_end = response->body + response->body_length;

    while (cursor < document_end)
    {
        const char *entry_begin = strstr(cursor, "<entry");
        const char *entry_end;
        const char *link;
        rictus_intelligence_item_t *item;

        if (entry_begin == NULL || entry_begin >= document_end) break;
        entry_begin = strchr(entry_begin, '>');
        if (entry_begin == NULL || entry_begin >= document_end)
            return RICTUS_INTELLIGENCE_PARSE_INVALID_FORMAT;
        ++entry_begin;
        entry_end = strstr(entry_begin, "</entry>");
        if (entry_end == NULL || entry_end > document_end)
            return RICTUS_INTELLIGENCE_PARSE_INVALID_FORMAT;
        if (items->count >= RICTUS_INTELLIGENCE_ITEMS_MAX)
            return RICTUS_INTELLIGENCE_PARSE_ITEM_LIMIT;

        item = &items->items[items->count];
        memset(item, 0, sizeof(*item));
        (void)rictus_intelligence_copy(item->source, sizeof(item->source),
            source->name, strlen(source->name));
        (void)rictus_intelligence_xml_field(entry_begin, entry_end, "title",
            item->title, sizeof(item->title));
        if (!rictus_intelligence_xml_field(entry_begin, entry_end, "published",
            item->published, sizeof(item->published)))
            (void)rictus_intelligence_xml_field(entry_begin, entry_end, "updated",
                item->published, sizeof(item->published));
        if (!rictus_intelligence_xml_field(entry_begin, entry_end, "summary",
            item->summary, sizeof(item->summary)))
            (void)rictus_intelligence_xml_field(entry_begin, entry_end, "content",
                item->summary, sizeof(item->summary));
        rictus_intelligence_strip_tags(item->summary);
        (void)rictus_intelligence_copy(item->content, sizeof(item->content),
            item->summary, strlen(item->summary));

        link = strstr(entry_begin, "<link");
        if (link != NULL && link < entry_end)
        {
            const char *tag_end = strchr(link, '>');
            const char *href = strstr(link, "href=\"");
            if (tag_end != NULL && tag_end < entry_end && href != NULL && href < tag_end)
            {
                const char *value = href + strlen("href=\"");
                const char *quote = strchr(value, '\"');
                if (quote != NULL && quote <= tag_end)
                    (void)rictus_intelligence_copy(item->url, sizeof(item->url),
                        value, (size_t)(quote - value));
            }
        }
        if (item->url[0] == '\0')
            (void)rictus_intelligence_xml_field(entry_begin, entry_end, "id",
                item->url, sizeof(item->url));

        if (item->title[0] != '\0' && item->url[0] != '\0')
        {
            rictus_intelligence_item_fingerprint(item);
            ++items->count;
        }
        cursor = entry_end + strlen("</entry>");
    }

    return items->count == 0
        ? RICTUS_INTELLIGENCE_PARSE_INVALID_FORMAT
        : RICTUS_INTELLIGENCE_PARSE_OK;
}


/*
 * ------------------------------------------------
 * HTML EVIDENCE EXTRACTION
 * ------------------------------------------------
 *
 * Converts an HTML response into bounded, readable
 * source evidence before the INT record is persisted.
 *
 * This is deliberately conservative:
 *
 * - script/style/noscript/template blocks are ignored
 * - comments and markup are ignored
 * - selected block tags create line boundaries
 * - common HTML entities are decoded
 * - repeated whitespace is collapsed
 *
 * The complete response remains the fingerprint input.
 */

static int
rictus_intelligence_html_tag_name(
    const char *input,
    size_t input_length,
    char *tag,
    size_t tag_size,
    int *closing
)
{
    size_t index;
    size_t output_index;

    if (
        input == NULL ||
        tag == NULL ||
        tag_size == 0 ||
        closing == NULL
        )
    {
        return 0;
    }

    tag[0] = '\0';
    *closing = 0;

    index = 0;

    while (
        index < input_length &&
        (
            input[index] == ' ' ||
            input[index] == '\t' ||
            input[index] == '\r' ||
            input[index] == '\n'
        )
        )
    {
        ++index;
    }

    if (
        index < input_length &&
        input[index] == '/'
        )
    {
        *closing = 1;
        ++index;
    }

    while (
        index < input_length &&
        (
            input[index] == ' ' ||
            input[index] == '\t' ||
            input[index] == '\r' ||
            input[index] == '\n'
        )
        )
    {
        ++index;
    }

    output_index = 0;

    while (
        index < input_length &&
        output_index + 1 < tag_size
        )
    {
        unsigned char c =
            (unsigned char)input[index];

        if (
            !(
                (c >= 'A' && c <= 'Z') ||
                (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9')
            )
            )
        {
            break;
        }

        if (c >= 'A' && c <= 'Z')
        {
            c =
                (unsigned char)
                (
                    c - 'A' + 'a'
                );
        }

        tag[output_index++] =
            (char)c;

        ++index;
    }

    tag[output_index] = '\0';

    return output_index != 0;
}


static int
rictus_intelligence_html_block_tag(
    const char *tag
)
{
    if (tag == NULL)
    {
        return 0;
    }

    return
        strcmp(tag, "article") == 0 ||
        strcmp(tag, "br") == 0 ||
        strcmp(tag, "dd") == 0 ||
        strcmp(tag, "div") == 0 ||
        strcmp(tag, "dt") == 0 ||
        strcmp(tag, "figcaption") == 0 ||
        strcmp(tag, "footer") == 0 ||
        strcmp(tag, "h1") == 0 ||
        strcmp(tag, "h2") == 0 ||
        strcmp(tag, "h3") == 0 ||
        strcmp(tag, "h4") == 0 ||
        strcmp(tag, "h5") == 0 ||
        strcmp(tag, "h6") == 0 ||
        strcmp(tag, "header") == 0 ||
        strcmp(tag, "li") == 0 ||
        strcmp(tag, "main") == 0 ||
        strcmp(tag, "nav") == 0 ||
        strcmp(tag, "p") == 0 ||
        strcmp(tag, "section") == 0 ||
        strcmp(tag, "td") == 0 ||
        strcmp(tag, "th") == 0 ||
        strcmp(tag, "tr") == 0 ||
        strcmp(tag, "ul") == 0 ||
        strcmp(tag, "ol") == 0;
}


static int
rictus_intelligence_html_skip_tag(
    const char *tag
)
{
    if (tag == NULL)
    {
        return 0;
    }

    return
        strcmp(tag, "script") == 0 ||
        strcmp(tag, "style") == 0 ||
        strcmp(tag, "noscript") == 0 ||
        strcmp(tag, "template") == 0 ||
        strcmp(tag, "svg") == 0;
}


static void
rictus_intelligence_html_append_boundary(
    char *output,
    size_t output_size,
    size_t *output_index
)
{
    if (
        output == NULL ||
        output_index == NULL ||
        output_size == 0 ||
        *output_index == 0 ||
        *output_index + 1 >= output_size
        )
    {
        return;
    }

    if (
        output[*output_index - 1] != '\n'
        )
    {
        output[(*output_index)++] = '\n';
        output[*output_index] = '\0';
    }
}


static int
rictus_intelligence_html_extract_text(
    const char *html,
    size_t html_length,
    char *output,
    size_t output_size
)
{
    size_t input_index;
    size_t output_index;
    unsigned int skip_depth;

    if (
        html == NULL ||
        output == NULL ||
        output_size == 0
        )
    {
        return 0;
    }

    output[0] = '\0';
    input_index = 0;
    output_index = 0;
    skip_depth = 0;

    while (
        input_index < html_length &&
        output_index + 1 < output_size
        )
    {
        if (
            html[input_index] == '<'
        )
        {
            const char *tag_end;
            char tag[32];
            int closing;

            if (
                input_index + 4 <= html_length &&
                strncmp(
                    html + input_index,
                    "<!--",
                    4
                ) == 0
                )
            {
                const char *comment_end =
                    strstr(
                        html + input_index + 4,
                        "-->"
                    );

                if (comment_end == NULL)
                {
                    break;
                }

                input_index =
                    (size_t)
                    (
                        comment_end -
                        html
                    ) +
                    3;

                continue;
            }

            tag_end =
                memchr(
                    html + input_index,
                    '>',
                    html_length - input_index
                );

            if (tag_end == NULL)
            {
                break;
            }

            if (
                rictus_intelligence_html_tag_name(
                    html + input_index + 1,
                    (size_t)
                    (
                        tag_end -
                        (html + input_index + 1)
                    ),
                    tag,
                    sizeof(tag),
                    &closing
                )
                )
            {
                if (
                    rictus_intelligence_html_skip_tag(
                        tag
                    )
                    )
                {
                    if (closing)
                    {
                        if (skip_depth > 0)
                        {
                            --skip_depth;
                        }
                    }
                    else
                    {
                        ++skip_depth;
                    }
                }
                else if (
                    skip_depth == 0 &&
                    rictus_intelligence_html_block_tag(
                        tag
                    )
                    )
                {
                    rictus_intelligence_html_append_boundary(
                        output,
                        output_size,
                        &output_index
                    );
                }
            }

            input_index =
                (size_t)
                (
                    tag_end -
                    html
                ) +
                1;

            continue;
        }

        if (skip_depth != 0)
        {
            ++input_index;
            continue;
        }

        if (
            html[input_index] == '&'
        )
        {
            struct
            {
                const char *entity;
                char value;
            }
            entities[] =
            {
                { "&amp;", '&' },
                { "&lt;", '<' },
                { "&gt;", '>' },
                { "&quot;", '"' },
                { "&#39;", '\'' },
                { "&apos;", '\'' },
                { "&nbsp;", ' ' }
            };

            size_t entity_index;
            int decoded;

            decoded = 0;

            for (
                entity_index = 0;
                entity_index <
                    sizeof(entities) /
                    sizeof(entities[0]);
                ++entity_index
                )
            {
                size_t entity_length =
                    strlen(
                        entities[entity_index].entity
                    );

                if (
                    input_index + entity_length <=
                        html_length &&
                    strncmp(
                        html + input_index,
                        entities[entity_index].entity,
                        entity_length
                    ) == 0
                    )
                {
                    output[output_index++] =
                        entities[entity_index].value;

                    input_index +=
                        entity_length;

                    decoded = 1;
                    break;
                }
            }

            if (decoded)
            {
                continue;
            }
        }

        {
            unsigned char c =
                (unsigned char)
                html[input_index++];

            if (
                c == '\r' ||
                c == '\t' ||
                c == '\f'
                )
            {
                c = ' ';
            }

            if (c == '\n')
            {
                c = ' ';
            }

            if (c == ' ')
            {
                if (
                    output_index == 0 ||
                    output[output_index - 1] == ' ' ||
                    output[output_index - 1] == '\n'
                    )
                {
                    continue;
                }
            }

            output[output_index++] =
                (char)c;
        }
    }

    while (
        output_index > 0 &&
        (
            output[output_index - 1] == ' ' ||
            output[output_index - 1] == '\n'
        )
        )
    {
        --output_index;
    }

    output[output_index] = '\0';

    return output_index != 0;
}


/*
 * ------------------------------------------------
 * NIST CSRC NEWS RECORDS
 * ------------------------------------------------
 *
 * The NIST CSRC /news document is an index page.
 * Treating the whole page as one Intelligence item
 * produces poor downstream evidence, so this parser
 * converts the cleaned results list into individual
 * bounded Intelligence records.
 *
 * Current record shape after HTML normalization:
 *
 *   <title>
 *   <date>
 *   <description>
 *
 * The source page URL remains provenance until a
 * source-specific per-record URL extractor is added.
 */

static int
rictus_intelligence_month_name(
    const char *value
)
{
    static const char *months[] =
    {
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December"
    };

    size_t index;

    if (
        value == NULL ||
        value[0] == '\0'
        )
    {
        return 0;
    }

    for (
        index = 0;
        index <
            sizeof(months) /
            sizeof(months[0]);
        ++index
        )
    {
        size_t length =
            strlen(
                months[index]
            );

        if (
            strncmp(
                value,
                months[index],
                length
            ) == 0 &&
            value[length] == ' '
            )
        {
            return 1;
        }
    }

    return 0;
}


static int
rictus_intelligence_next_line(
    const char **cursor,
    const char *end,
    char *output,
    size_t output_size
)
{
    const char *line_begin;
    const char *line_end;

    if (
        cursor == NULL ||
        *cursor == NULL ||
        end == NULL ||
        output == NULL ||
        output_size == 0 ||
        *cursor >= end
        )
    {
        return 0;
    }

    while (
        *cursor < end &&
        (
            **cursor == '\r' ||
            **cursor == '\n'
        )
        )
    {
        ++(*cursor);
    }

    if (*cursor >= end)
    {
        return 0;
    }

    line_begin =
        *cursor;

    line_end =
        memchr(
            line_begin,
            '\n',
            (size_t)(end - line_begin)
        );

    if (line_end == NULL)
    {
        line_end =
            end;
    }

    (void)
    rictus_intelligence_copy(
        output,
        output_size,
        line_begin,
        (size_t)(line_end - line_begin)
    );

    rictus_intelligence_trim(
        output
    );

    *cursor =
        line_end;

    return 1;
}


static
rictus_intelligence_parse_result_t
rictus_intelligence_parse_nist_csrc(
    const rictus_intelligence_source_definition_t *source,
    const rictus_intelligence_response_t *response,
    rictus_intelligence_item_set_t *items
)
{
    char cleaned[
        RICTUS_INTELLIGENCE_RESPONSE_MAX > 65536
            ? 65536
            : RICTUS_INTELLIGENCE_RESPONSE_MAX
    ];

    const char *cursor;
    const char *end;
    const char *results_begin;

    char line[
        RICTUS_INTELLIGENCE_ITEM_CONTENT_MAX
    ];

    char title[
        RICTUS_INTELLIGENCE_ITEM_TITLE_MAX
    ];

    char date[
        RICTUS_INTELLIGENCE_ITEM_DATE_MAX
    ];

    char description[
        RICTUS_INTELLIGENCE_ITEM_SUMMARY_MAX
    ];

    int in_results =
        0;


    if (
        source == NULL ||
        response == NULL ||
        items == NULL
        )
    {
        return
            RICTUS_INTELLIGENCE_PARSE_INVALID_ARGUMENT;
    }


    memset(
        cleaned,
        0,
        sizeof(cleaned)
    );


    if (
        !rictus_intelligence_html_extract_text(
            response->body,
            response->body_length,
            cleaned,
            sizeof(cleaned)
        )
        )
    {
        return
            RICTUS_INTELLIGENCE_PARSE_INVALID_FORMAT;
    }


    results_begin =
        strstr(
            cleaned,
            "Showing "
        );


    if (
        results_begin == NULL
        )
    {
        return
            RICTUS_INTELLIGENCE_PARSE_INVALID_FORMAT;
    }


    cursor =
        results_begin;


    end =
        cleaned +
        strlen(cleaned);


    while (
        cursor < end
        )
    {
        if (
            !rictus_intelligence_next_line(
                &cursor,
                end,
                line,
                sizeof(line)
            )
            )
        {
            break;
        }


        if (
            line[0] == '\0'
            )
        {
            continue;
        }


        if (
            !in_results
            )
        {
            if (
                strncmp(
                    line,
                    "Showing ",
                    8
                ) == 0
                )
            {
                in_results =
                    1;
            }

            continue;
        }


        /*
         * Skip pagination-only lines.
         */

        if (
            strchr(
                line,
                '|'
            ) != NULL &&
            strstr(
                line,
                " > "
            ) != NULL
            )
        {
            continue;
        }


        /*
         * The next meaningful line is the title.
         */

        strcpy_s(
            title,
            sizeof(title),
            line
        );


        if (
            !rictus_intelligence_next_line(
                &cursor,
                end,
                date,
                sizeof(date)
            )
            )
        {
            break;
        }


        if (
            !rictus_intelligence_month_name(
                date
            )
            )
        {
            /*
             * We have left the result sequence or
             * encountered an unexpected page shape.
             * Do not manufacture a record.
             */

            continue;
        }


        if (
            !rictus_intelligence_next_line(
                &cursor,
                end,
                description,
                sizeof(description)
            )
            )
        {
            break;
        }


        if (
            description[0] == '\0'
            )
        {
            continue;
        }


        if (
            items->count >=
            RICTUS_INTELLIGENCE_ITEMS_MAX
            )
        {
            return
                RICTUS_INTELLIGENCE_PARSE_ITEM_LIMIT;
        }


        {
            rictus_intelligence_item_t *item =
                &items->items[
                    items->count
                ];

            int written;


            memset(
                item,
                0,
                sizeof(*item)
            );


            (void)
            rictus_intelligence_copy(
                item->source,
                sizeof(item->source),
                source->name,
                strlen(source->name)
            );


            (void)
            rictus_intelligence_copy(
                item->title,
                sizeof(item->title),
                title,
                strlen(title)
            );


            (void)
            rictus_intelligence_copy(
                item->published,
                sizeof(item->published),
                date,
                strlen(date)
            );


            (void)
            rictus_intelligence_copy(
                item->summary,
                sizeof(item->summary),
                description,
                strlen(description)
            );


            written =
                snprintf(
                    item->url,
                    sizeof(item->url),
                    "https://%s%s",
                    source->host,
                    source->path
                );


            if (
                written <= 0 ||
                written >=
                    (int)sizeof(item->url)
                )
            {
                continue;
            }


            written =
                snprintf(
                    item->content,
                    sizeof(item->content),
                    "%s\n%s\n%s",
                    item->title,
                    item->published,
                    item->summary
                );


            if (
                written <= 0 ||
                written >=
                    (int)sizeof(item->content)
                )
            {
                continue;
            }


            rictus_intelligence_item_fingerprint(
                item
            );


            ++items->count;
        }
    }


    if (
        items->count == 0
        )
    {
        return
            RICTUS_INTELLIGENCE_PARSE_INVALID_FORMAT;
    }


    return
        RICTUS_INTELLIGENCE_PARSE_OK;
}


/*
 * ------------------------------------------------
 * SOURCE DOCUMENT
 * ------------------------------------------------
 *
 * Used for HTML sources until a source-specific
 * article parser is qualified.
 *
 * The retained evidence is normalized readable text.
 * The deterministic fingerprint remains over the
 * complete collected response so source changes are
 * detected independently of presentation cleanup.
 */

static
rictus_intelligence_parse_result_t
rictus_intelligence_parse_document(
    const rictus_intelligence_source_definition_t *source,
    const rictus_intelligence_response_t *response,
    rictus_intelligence_item_set_t *items
)
{
    rictus_intelligence_item_t
        *item;

    uint64_t hash;


    if (
        items->count >=
        RICTUS_INTELLIGENCE_ITEMS_MAX
    )
    {
        return
            RICTUS_INTELLIGENCE_PARSE_ITEM_LIMIT;
    }


    item =
        &items->items[
            items->count
        ];


    memset(
        item,
        0,
        sizeof(*item)
    );


    (void)
    rictus_intelligence_copy(
        item->source,
        sizeof(item->source),
        source->name,
        strlen(source->name)
    );


    (void)
    snprintf(
        item->title,
        sizeof(item->title),
        "%s official updates",
        source->name
    );


    (void)
    snprintf(
        item->url,
        sizeof(item->url),
        "https://%s%s",
        source->host,
        source->path
    );


    if (
        !rictus_intelligence_html_extract_text(
            response->body,
            response->body_length,
            item->content,
            sizeof(item->content)
        )
        )
    {
        return
            RICTUS_INTELLIGENCE_PARSE_INVALID_FORMAT;
    }


    hash =
        UINT64_C(
            14695981039346656037
        );


    hash =
        rictus_intelligence_fnv1a(
            (const unsigned char *)
            response->body,
            response->body_length,
            hash
        );


    (void)
    snprintf(
        item->fingerprint,
        sizeof(item->fingerprint),
        "%016llx",
        (unsigned long long)
        hash
    );


    items->count++;


    return
        RICTUS_INTELLIGENCE_PARSE_OK;
}


/*
 * ------------------------------------------------
 * STN-LABZ THREAT JSON
 * ------------------------------------------------
 */

static int
rictus_intelligence_json_string(
    const char *begin,
    const char *end,
    const char *key,
    char *output,
    size_t output_size
)
{
    char marker[128];
    const char *cursor;
    size_t used = 0;
    int written;


    if (
        begin == NULL || end == NULL || begin >= end ||
        key == NULL || output == NULL || output_size == 0
        )
    {
        return 0;
    }


    written = snprintf(marker, sizeof(marker), "\"%s\"", key);

    if (written <= 0 || written >= (int)sizeof(marker))
    {
        return 0;
    }


    cursor = begin;

    while (cursor < end)
    {
        cursor = strstr(cursor, marker);

        if (cursor == NULL || cursor >= end)
        {
            return 0;
        }


        cursor += strlen(marker);

        while (cursor < end && (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n'))
        {
            ++cursor;
        }


        if (cursor >= end || *cursor != ':')
        {
            continue;
        }


        ++cursor;

        while (cursor < end && (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n'))
        {
            ++cursor;
        }


        if (cursor >= end || *cursor != '"')
        {
            return 0;
        }


        ++cursor;

        while (cursor < end && *cursor != '"')
        {
            char value = *cursor++;


            if (value == '\\')
            {
                if (cursor >= end)
                {
                    return 0;
                }


                value = *cursor++;

                switch (value)
                {
                    case 'n': value = '\n'; break;
                    case 'r': value = '\r'; break;
                    case 't': value = '\t'; break;
                    case 'b': value = '\b'; break;
                    case 'f': value = '\f'; break;
                    case '/': value = '/'; break;
                    case '\\': value = '\\'; break;
                    case '"': value = '"'; break;
                    default: break;
                }
            }


            if (used + 1 < output_size)
            {
                output[used++] = value;
            }
        }


        if (cursor >= end)
        {
            return 0;
        }


        output[used] = '\0';

        return 1;
    }


    return 0;
}


static const char *
rictus_intelligence_json_object_end(
    const char *begin,
    const char *end
)
{
    const char *cursor;
    unsigned int depth = 0;
    int in_string = 0;
    int escaped = 0;


    for (cursor = begin; cursor < end; ++cursor)
    {
        if (in_string)
        {
            if (escaped)
            {
                escaped = 0;
            }
            else if (*cursor == '\\')
            {
                escaped = 1;
            }
            else if (*cursor == '"')
            {
                in_string = 0;
            }

            continue;
        }


        if (*cursor == '"')
        {
            in_string = 1;
        }
        else if (*cursor == '{')
        {
            ++depth;
        }
        else if (*cursor == '}')
        {
            if (depth == 0)
            {
                return NULL;
            }


            --depth;

            if (depth == 0)
            {
                return cursor + 1;
            }
        }
    }


    return NULL;
}


static rictus_intelligence_parse_result_t
rictus_intelligence_parse_stn_labz_threats(
    const rictus_intelligence_source_definition_t *source,
    const rictus_intelligence_response_t *response,
    rictus_intelligence_item_set_t *items
)
{
    const char *cursor;
    const char *document_end;


    cursor = strstr(response->body, "\"threats\"");
    document_end = response->body + response->body_length;

    if (cursor == NULL || cursor >= document_end)
    {
        return RICTUS_INTELLIGENCE_PARSE_INVALID_FORMAT;
    }


    cursor = strchr(cursor, '[');

    if (cursor == NULL || cursor >= document_end)
    {
        return RICTUS_INTELLIGENCE_PARSE_INVALID_FORMAT;
    }


    ++cursor;

    while (cursor < document_end)
    {
        const char *object_begin;
        const char *object_end;
        rictus_intelligence_item_t *item;
        char id[128];
        char type[128];
        char observed_ip[128];
        char detail_ip[128];
        char domain[512];
        char request_url[1024];
        int title_written;
        int summary_written;


        object_begin = strchr(cursor, '{');

        if (object_begin == NULL || object_begin >= document_end)
        {
            break;
        }


        object_end = rictus_intelligence_json_object_end(object_begin, document_end);

        if (object_end == NULL)
        {
            return RICTUS_INTELLIGENCE_PARSE_INVALID_FORMAT;
        }


        if (items->count >= RICTUS_INTELLIGENCE_ITEMS_MAX)
        {
            return RICTUS_INTELLIGENCE_PARSE_ITEM_LIMIT;
        }


        memset(id, 0, sizeof(id));
        memset(type, 0, sizeof(type));
        memset(observed_ip, 0, sizeof(observed_ip));
        memset(detail_ip, 0, sizeof(detail_ip));
        memset(domain, 0, sizeof(domain));
        memset(request_url, 0, sizeof(request_url));

        if (
            !rictus_intelligence_json_string(object_begin, object_end, "id", id, sizeof(id)) ||
            !rictus_intelligence_json_string(object_begin, object_end, "type", type, sizeof(type))
            )
        {
            cursor = object_end;
            continue;
        }


        (void)rictus_intelligence_json_string(object_begin, object_end, "ip", observed_ip, sizeof(observed_ip));
        (void)rictus_intelligence_json_string(object_begin, object_end, "ip_address", detail_ip, sizeof(detail_ip));
        (void)rictus_intelligence_json_string(object_begin, object_end, "domain", domain, sizeof(domain));
        (void)rictus_intelligence_json_string(object_begin, object_end, "request_url", request_url, sizeof(request_url));

        item = &items->items[items->count];
        memset(item, 0, sizeof(*item));

        (void)rictus_intelligence_copy(item->source, sizeof(item->source), source->name, strlen(source->name));
        (void)rictus_intelligence_json_string(object_begin, object_end, "created_at", item->published, sizeof(item->published));

        title_written = snprintf(
            item->title,
            sizeof(item->title),
            "STN-LABZ Threat API | %s | %s",
            type,
            request_url[0] != '\0' ? request_url : "request path not supplied"
        );

        summary_written = snprintf(
            item->summary,
            sizeof(item->summary),
            "Event ID=%s | Type=%s | Request path=%s | Source IP=%s | "
            "Reported IP=%s | Target=%s | Event time=%s",
            id, type,
            request_url[0] != '\0' ? request_url : "NOT SUPPLIED",
            detail_ip[0] != '\0' ? detail_ip : "NOT SUPPLIED",
            observed_ip[0] != '\0' ? observed_ip : "NOT SUPPLIED",
            domain[0] != '\0' ? domain : "NOT SUPPLIED",
            item->published[0] != '\0' ? item->published : "NOT SUPPLIED"
        );

        (void)snprintf(item->url, sizeof(item->url), "https://%s%s#%s", source->host, source->path, id);
        (void)rictus_intelligence_copy(item->content, sizeof(item->content), item->summary, strlen(item->summary));

        if (
            title_written > 0 && title_written < (int)sizeof(item->title) &&
            summary_written > 0 && summary_written < (int)sizeof(item->summary)
            )
        {
            rictus_intelligence_item_fingerprint(item);
            ++items->count;
        }


        cursor = object_end;
    }


    if (items->count == 0)
    {
        return RICTUS_INTELLIGENCE_PARSE_INVALID_FORMAT;
    }


    return RICTUS_INTELLIGENCE_PARSE_OK;
}


/*
 * ------------------------------------------------
 * PUBLIC PARSER
 * ------------------------------------------------
 */

rictus_intelligence_parse_result_t
rictus_intelligence_parse_response(
    const rictus_intelligence_source_definition_t *source,
    const rictus_intelligence_response_t *response,
    rictus_intelligence_item_set_t *items
)
{
    if (
        source == NULL ||
        response == NULL ||
        items == NULL ||
        response->body == NULL ||
        response->body_length == 0
    )
    {
        return
            RICTUS_INTELLIGENCE_PARSE_INVALID_ARGUMENT;
    }


    memset(
        items,
        0,
        sizeof(*items)
    );


    switch (
        source->transport
    )
    {
        case RICTUS_INTELLIGENCE_TRANSPORT_RSS:
            if (strstr(response->body, "<entry") != NULL)
                return rictus_intelligence_parse_atom(source, response, items);
            return rictus_intelligence_parse_rss(source, response, items);


        case RICTUS_INTELLIGENCE_TRANSPORT_HTML:

            if (
                source->id != NULL &&
                strcmp(
                    source->id,
                    "nist_csrc"
                ) == 0
                )
            {
                return
                    rictus_intelligence_parse_nist_csrc(
                        source,
                        response,
                        items
                    );
            }


            return
                rictus_intelligence_parse_document(
                    source,
                    response,
                    items
                );


        case RICTUS_INTELLIGENCE_TRANSPORT_JSON:

            if (
                source->id != NULL &&
                strcmp(source->id, "stn_labz_threats") == 0
                )
            {
                return
                    rictus_intelligence_parse_stn_labz_threats(
                        source,
                        response,
                        items
                    );
            }


            return RICTUS_INTELLIGENCE_PARSE_UNSUPPORTED;


        default:

            return
                RICTUS_INTELLIGENCE_PARSE_UNSUPPORTED;
    }
}


/*
 * ------------------------------------------------
 * RESULT STRING
 * ------------------------------------------------
 */

const char *
rictus_intelligence_parse_result_string(
    rictus_intelligence_parse_result_t result
)
{
    switch (
        result
    )
    {
        case RICTUS_INTELLIGENCE_PARSE_OK:

            return "OK";


        case RICTUS_INTELLIGENCE_PARSE_INVALID_ARGUMENT:

            return "INVALID_ARGUMENT";


        case RICTUS_INTELLIGENCE_PARSE_UNSUPPORTED:

            return "UNSUPPORTED";


        case RICTUS_INTELLIGENCE_PARSE_INVALID_FORMAT:

            return "INVALID_FORMAT";


        case RICTUS_INTELLIGENCE_PARSE_ITEM_LIMIT:

            return "ITEM_LIMIT";


        default:

            return "UNKNOWN";
    }
}
