/*
 * STN-LABZ
 * Rictus Intelligence Module
 *
 * intelligence.c
 *
 * Intelligence module revision 0.9.1.
 *
 * Responsibilities:
 *
 * - module identity
 * - Core API compatibility
 * - source policy
 * - qualification
 * - lifecycle
 * - worker management
 * - source collection
 * - response normalization
 * - persistent duplicate detection
 * - publication of new source evidence through Core
 *
 * This revision does not approve intelligence,
 * publish controlled knowledge, or write to the
 * corpus.
 */

#include <errno.h>
#include <pthread.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "intelligence.h"
#include "collector.h"
#include "parser.h"
#include "seen.h"
#include "record.h"
#include "srt.h"
#include "sources.h"
#include "relevance.h"
#include "doctrine.h"
#include "warning.h"
#include "warning_exercise.h"


#define RICTUS_INTELLIGENCE_COLLECTION_INTERVAL_MS \
    (15UL * 60UL * 1000UL)

#define RICTUS_INTELLIGENCE_NOTIFICATIONS_PER_CYCLE \
    3U

#define RICTUS_INTELLIGENCE_NOTIFICATION_INTERVAL_MS \
    2000U

#define RICTUS_INTELLIGENCE_IRC_MESSAGE_MAX \
    400

#define RICTUS_INTELLIGENCE_CHAIN_INDEX_PATH \
    "state/intelligence/policy.index.json"

#define RICTUS_INTELLIGENCE_CHAIN_OUTPUT_MAX \
    8192


static pthread_t g_intelligence_thread;
static int g_intelligence_thread_active;
static pthread_mutex_t g_intelligence_stop_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_intelligence_stop_cond = PTHREAD_COND_INITIALIZER;
static int g_intelligence_stop_requested;
static int g_intelligence_running;

static rictus_intelligence_seen_t
g_intelligence_seen;


static rictus_intelligence_record_store_t
g_intelligence_records;


static const char*
g_intelligence_record_path =
"intelligence.records";

#define RICTUS_INTELLIGENCE_NOTIFICATION_MAX RICTUS_INTELLIGENCE_RECORD_MAX

static const char *g_intelligence_notified_path = "intelligence.notified";
static char g_intelligence_notified[RICTUS_INTELLIGENCE_NOTIFICATION_MAX]
    [RICTUS_INTELLIGENCE_RECORD_ID_MAX];
static size_t g_intelligence_notified_count;
static char g_intelligence_pending[RICTUS_INTELLIGENCE_NOTIFICATION_MAX]
    [RICTUS_INTELLIGENCE_RECORD_ID_MAX];
static size_t g_intelligence_pending_count;
static rictus_warning_store_t g_warning_store;
static rictus_warning_exercise_store_t g_warning_exercise_store;
typedef struct { char id[64]; unsigned int attempts; unsigned int successes; unsigned int failures; unsigned int items; } rictus_intelligence_collection_metric_t;
static rictus_intelligence_collection_metric_t g_collection_metrics[32];
static size_t g_collection_metric_count;
static const char *g_collection_evaluation_path="intelligence.collection.evaluations";
#define RICTUS_THREAT_JSON_BASELINE_PATH \
    "state/intelligence/threat-json.initialized"

static int threat_json_baseline_exists(void)
{
    struct stat st;
    return stat(RICTUS_THREAT_JSON_BASELINE_PATH, &st) == 0 && S_ISREG(st.st_mode);
}

static int threat_json_baseline_store(void)
{
    static const char marker[] = "v=1\tfeed=/threats\tmode=baseline-only\n";
    int fd = open(RICTUS_THREAT_JSON_BASELINE_PATH, O_WRONLY | O_CREAT | O_EXCL, 0640);
    ssize_t written;
    if (fd < 0) return errno == EEXIST;
    written = write(fd, marker, sizeof(marker) - 1);
    if (written != (ssize_t)(sizeof(marker) - 1) || fsync(fd) != 0) {
        close(fd); unlink(RICTUS_THREAT_JSON_BASELINE_PATH); return 0;
    }
    return close(fd) == 0;
}

static int rictus_intelligence_copy(char *dst, size_t size, const char *src)
{
    int written;
    if (!dst || size == 0 || !src) return 1;
    written = snprintf(dst, size, "%s", src);
    return written < 0 || (size_t)written >= size;
}

static int rictus_intelligence_append(char *dst, size_t size, const char *src)
{
    size_t used;
    int written;
    if (!dst || size == 0 || !src) return 1;
    used = strlen(dst);
    if (used >= size) return 1;
    written = snprintf(dst + used, size - used, "%s", src);
    return written < 0 || (size_t)written >= size - used;
}

static rictus_intelligence_collection_metric_t *collection_metric(const char *id)
{
    size_t i; for(i=0;i<g_collection_metric_count;++i) if(strcmp(g_collection_metrics[i].id,id)==0)return &g_collection_metrics[i];
    if(g_collection_metric_count>=32)return NULL;
    snprintf(g_collection_metrics[g_collection_metric_count].id, sizeof(g_collection_metrics[0].id), "%s", id);
    return &g_collection_metrics[g_collection_metric_count++];
}

static void collection_record(const char *id,int success,unsigned long http_status,size_t items)
{
    FILE *file=NULL; rictus_intelligence_collection_metric_t *m=collection_metric(id);
    if(m){++m->attempts;if(success)++m->successes;else ++m->failures;m->items+=(unsigned int)items;}
    file = fopen(g_collection_evaluation_path, "ab"); if(file){fprintf(file,"v=1\tsource=%s\tresult=%s\thttp=%lu\titems=%u\n",id,success?"SUCCESS":"FAILURE",http_status,(unsigned int)items);fclose(file);}
}


static rictus_intelligence_srt_store_t
g_intelligence_srt_requests;


/*
 * Core-owned host services.
 *
 * The module does not own this structure.
 * Core guarantees that it remains valid while
 * the module is ACTIVE.
 */
static const rictus_module_host_t*
g_intelligence_host =
NULL;


static int
rictus_intelligence_reply_field_once(
    rictus_module_command_reply_fn reply,
    void *context,
    const char *label,
    const char *value
)
{
    char message[400];
    if (value == NULL || value[0] == '\0') return 1;
    snprintf(message, sizeof(message), "%s: %.*s%s",
        label, 300, value, strlen(value) > 300 ? "..." : "");
    return reply(context, message);
}


/*
 * ------------------------------------------------
 * SOURCE POLICY
 * ------------------------------------------------
 */

rictus_intelligence_source_t
rictus_intelligence_source_from_name(
    const char* name
)
{
    if (
        name == NULL ||
        name[0] == '\0'
        )
    {
        return
            RICTUS_INTELLIGENCE_SOURCE_NONE;
    }


    if (
        strcmp(
            name,
            "NASA"
        ) == 0
        )
    {
        return
            RICTUS_INTELLIGENCE_SOURCE_NASA;
    }


    if (
        strcmp(
            name,
            "SpaceX"
        ) == 0
        )
    {
        return
            RICTUS_INTELLIGENCE_SOURCE_SPACEX;
    }


    return
        RICTUS_INTELLIGENCE_SOURCE_OTHER;
}


rictus_intelligence_source_class_t
rictus_intelligence_source_class(
    rictus_intelligence_source_t source
)
{
    switch (
        source
        )
    {
    case RICTUS_INTELLIGENCE_SOURCE_NASA:
    case RICTUS_INTELLIGENCE_SOURCE_SPACEX:

        return
            RICTUS_INTELLIGENCE_SOURCE_PRIMARY;


    case RICTUS_INTELLIGENCE_SOURCE_OTHER:

        return
            RICTUS_INTELLIGENCE_SOURCE_SECONDARY;


    case RICTUS_INTELLIGENCE_SOURCE_NONE:
    default:

        return
            RICTUS_INTELLIGENCE_SOURCE_INVALID;
    }
}


const char*
rictus_intelligence_source_string(
    rictus_intelligence_source_t source
)
{
    switch (
        source
        )
    {
    case RICTUS_INTELLIGENCE_SOURCE_NASA:

        return "NASA";


    case RICTUS_INTELLIGENCE_SOURCE_SPACEX:

        return "SpaceX";


    case RICTUS_INTELLIGENCE_SOURCE_OTHER:

        return "OTHER";


    default:

        return "NONE";
    }
}


const char*
rictus_intelligence_source_class_string(
    rictus_intelligence_source_class_t source_class
)
{
    switch (
        source_class
        )
    {
    case RICTUS_INTELLIGENCE_SOURCE_PRIMARY:

        return "PRIMARY";


    case RICTUS_INTELLIGENCE_SOURCE_SECONDARY:

        return "SECONDARY";


    default:

        return "INVALID";
    }
}


/*
 * ------------------------------------------------
 * COMMAND: SHOW
 * ------------------------------------------------
 *
 * Resolves one persistent INT record and returns
 * its primary operator-facing fields.
 *
 * Parameters:
 * - command:       Parsed Core-owned command.
 * - reply:         Core-owned reply callback.
 * - reply_context: Core-owned callback context.
 * - handler_context: Unused for this command.
 *
 * Returns a module result describing command
 * handling success or callback failure.
 */
static rictus_module_result_t
rictus_intelligence_command_show(
    const rictus_module_command_t* command,
    rictus_module_command_reply_fn reply,
    void* reply_context,
    void* handler_context
)
{
    const rictus_intelligence_record_t* record;
    char id[RICTUS_INTELLIGENCE_RECORD_ID_MAX];
    char response[1536];
    char extra;
    unsigned int page = 1;
    int fields;

    (void)handler_context;

    if (command == NULL || reply == NULL)
    {
        return RICTUS_MODULE_ERR_INVALID_ARGUMENT;
    }

    if (command->arguments[0] == '\0')
    {
        if (!reply(reply_context, "Usage: !show INT-XXXXXXXX"))
        {
            return RICTUS_MODULE_ERR_START_FAILED;
        }

        return RICTUS_MODULE_OK;
    }

#ifdef _WIN32
    fields = sscanf_s(command->arguments, "%31s %u %c",
        id, (unsigned int)sizeof(id), &page, &extra, 1U);
#else
    fields = sscanf(command->arguments, "%31s %u %c", id, &page, &extra);
#endif
    if (fields < 1 || fields > 2 || page < 1 || page > 3)
    {
        return reply(reply_context, "Usage: !show INT-XXXXXXXX [1|2|3]")
            ? RICTUS_MODULE_OK : RICTUS_MODULE_ERR_START_FAILED;
    }

    record =
        rictus_intelligence_record_store_find(
            &g_intelligence_records,
            id
        );

    if (record == NULL)
    {
        snprintf(
            response,
            sizeof(response),
            "%s: NOT FOUND",
            id
        );

        if (!reply(reply_context, response))
        {
            return RICTUS_MODULE_ERR_START_FAILED;
        }

        return RICTUS_MODULE_OK;
    }

    snprintf(
        response,
        sizeof(response),
        "%s | %s | %s | page %u/3%s",
        record->id,
        record->item.source,
        record->item.title,
        page,
        page < 3 ? " | next page available" : ""
    );

    if (!reply(reply_context, response))
    {
        return RICTUS_MODULE_ERR_START_FAILED;
    }

    if (page == 1)
    {
        snprintf(
            response,
            sizeof(response),
            "Published=%s | Observed=%s | Source URL=%.*s",
            record->item.published[0] ? record->item.published : "UNKNOWN",
            record->item.observed[0] ? record->item.observed : "UNKNOWN",
            180, record->item.url[0] ? record->item.url : "UNKNOWN"
        );
        if (!reply(reply_context, response) ||
            !rictus_intelligence_reply_field_once(reply, reply_context,
                "Summary", record->item.summary) ||
            !rictus_intelligence_reply_field_once(reply, reply_context,
                "WHY STN-LABZ CARES", record->item.why_stn_labz_cares))
            return RICTUS_MODULE_ERR_START_FAILED;
    }
    else if (page == 2)
    {
        if (!rictus_intelligence_reply_field_once(reply, reply_context,
                "Technical details", record->item.content) ||
            !rictus_intelligence_reply_field_once(reply, reply_context,
                "OBSERVATION / EVIDENCE", record->item.evidence) ||
            !rictus_intelligence_reply_field_once(reply, reply_context,
                "ANALYTICAL ASSESSMENT", record->item.assessment))
            return RICTUS_MODULE_ERR_START_FAILED;
    }
    else
    {
        if (!rictus_intelligence_reply_field_once(reply, reply_context,
                "UNKNOWN", record->item.unknowns) ||
            !rictus_intelligence_reply_field_once(reply, reply_context,
                "Provenance", record->item.provenance) ||
            !rictus_intelligence_reply_field_once(reply, reply_context,
                "URL", record->item.url))
            return RICTUS_MODULE_ERR_START_FAILED;
    }

    return RICTUS_MODULE_OK;
}

static rictus_module_result_t
rictus_intelligence_command_warn(const rictus_module_command_t *command,rictus_module_command_reply_fn reply,void *context,void *unused)
{
    char response[700],exercise_id[32];const rictus_warning_record_t *record;const rictus_warning_exercise_t *exercise;size_t i;unsigned int pending=0,critical_unacked=0;(void)unused;
    if(!command||!reply)return RICTUS_MODULE_ERR_INVALID_ARGUMENT;
    if(strcasecmp(command->arguments,"exercise status")==0){unsigned int exercise_pending=0,exercise_unacked=0;for(i=0;i<g_warning_exercise_store.count;++i){if(!g_warning_exercise_store.records[i].delivered)++exercise_pending;if(g_warning_exercise_store.records[i].severity==RICTUS_EXERCISE_CRITICAL&&!g_warning_exercise_store.records[i].acknowledged)++exercise_unacked;}snprintf(response,sizeof(response),"Warning exercises=%u | delivery pending=%u | CRITICAL unacknowledged=%u | production warnings unaffected",(unsigned)g_warning_exercise_store.count,exercise_pending,exercise_unacked);return reply(context,response)?RICTUS_MODULE_OK:RICTUS_MODULE_ERR_START_FAILED;}
    if(strcasecmp(command->arguments,"exercise high")==0||strcasecmp(command->arguments,"exercise critical")==0){rictus_exercise_severity_t severity=strcasecmp(command->arguments,"exercise critical")==0?RICTUS_EXERCISE_CRITICAL:RICTUS_EXERCISE_HIGH;if(strcasecmp(command->sender,"STN_Boss")!=0&&strcasecmp(command->account,"STN_Boss")!=0)return reply(context,"Warning exercise refused: direct STN_Boss role authority required.")?RICTUS_MODULE_OK:RICTUS_MODULE_ERR_START_FAILED;if(!rictus_warning_exercise_create(&g_warning_exercise_store,severity,command->sender,exercise_id))return reply(context,"Warning exercise creation failed.")?RICTUS_MODULE_OK:RICTUS_MODULE_ERR_START_FAILED;rictus_warning_exercise_deliver(&g_warning_exercise_store,g_intelligence_host->send_message);snprintf(response,sizeof(response),"EXERCISE CREATED | %s | %s | isolated from production evidence and lifecycle state",exercise_id,severity==RICTUS_EXERCISE_CRITICAL?"CRITICAL":"HIGH");return reply(context,response)?RICTUS_MODULE_OK:RICTUS_MODULE_ERR_START_FAILED;}
    if(strncasecmp(command->arguments,"exercise show ",14)==0){exercise=rictus_warning_exercise_find(&g_warning_exercise_store,command->arguments+14);if(!exercise)return reply(context,"Warning exercise not found.")?RICTUS_MODULE_OK:RICTUS_MODULE_ERR_START_FAILED;snprintf(response,sizeof(response),"%s | [EXERCISE] %s | delivered=%s | acknowledged=%s | created by=%s",exercise->id,exercise->severity==RICTUS_EXERCISE_CRITICAL?"CRITICAL":"HIGH",exercise->delivered?"YES":"NO",exercise->acknowledged?"YES":"NO",exercise->created_by);if(!reply(context,response))return RICTUS_MODULE_ERR_START_FAILED;return reply(context,"TEST FIXTURE ONLY | no INT, production WARN, remediation, or lifecycle authority created")?RICTUS_MODULE_OK:RICTUS_MODULE_ERR_START_FAILED;}
    if(strncasecmp(command->arguments,"exercise ack ",13)==0){if(strcasecmp(command->sender,"STN_Boss")!=0&&strcasecmp(command->account,"STN_Boss")!=0)return reply(context,"Exercise acknowledgment refused: STN_Boss role required.")?RICTUS_MODULE_OK:RICTUS_MODULE_ERR_START_FAILED;if(!rictus_warning_exercise_ack(&g_warning_exercise_store,command->arguments+13,command->sender))return reply(context,"Warning exercise acknowledgment failed or exercise not found.")?RICTUS_MODULE_OK:RICTUS_MODULE_ERR_START_FAILED;snprintf(response,sizeof(response),"EXERCISE ACKNOWLEDGED | %s | receipt test only; no operational action authorized",command->arguments+13);return reply(context,response)?RICTUS_MODULE_OK:RICTUS_MODULE_ERR_START_FAILED;}
    if(strcasecmp(command->arguments,"status")==0){for(i=0;i<g_warning_store.count;++i){if(!g_warning_store.records[i].delivered)++pending;if(g_warning_store.records[i].severity==RICTUS_INTELLIGENCE_SEVERITY_CRITICAL&&!g_warning_store.records[i].acknowledged)++critical_unacked;}snprintf(response,sizeof(response),"Warnings=%u | delivery pending=%u | CRITICAL unacknowledged=%u",(unsigned)g_warning_store.count,pending,critical_unacked);return reply(context,response)?RICTUS_MODULE_OK:RICTUS_MODULE_ERR_START_FAILED;}
    if(strncasecmp(command->arguments,"show ",5)==0){record=rictus_warning_find(&g_warning_store,command->arguments+5);if(!record)return reply(context,"Warning not found.")?RICTUS_MODULE_OK:RICTUS_MODULE_ERR_START_FAILED;snprintf(response,sizeof(response),"%s | %s | confidence=%s | INT=%s | indicator=%s",record->id,rictus_intelligence_severity_string(record->severity),record->confidence==RICTUS_INTELLIGENCE_CONFIDENCE_HIGH?"HIGH":"MODERATE",record->int_id,record->indicator);if(!reply(context,response))return RICTUS_MODULE_ERR_START_FAILED;snprintf(response,sizeof(response),"Delivered=%s | acknowledged=%s | %s",record->delivered?"YES":"NO",record->acknowledged?"YES":"NO",record->reason);if(!reply(context,response))return RICTUS_MODULE_ERR_START_FAILED;return reply(context,"Acknowledgment records receipt only; no remediation or lifecycle action is authorized.")?RICTUS_MODULE_OK:RICTUS_MODULE_ERR_START_FAILED;}
    if(strncasecmp(command->arguments,"ack ",4)==0){if(!rictus_warning_ack(&g_warning_store,command->arguments+4,command->sender))return reply(context,"Warning acknowledgment failed or warning not found.")?RICTUS_MODULE_OK:RICTUS_MODULE_ERR_START_FAILED;snprintf(response,sizeof(response),"ACKNOWLEDGED | %s | by %s | receipt only; no operational action authorized",command->arguments+4,command->sender);return reply(context,response)?RICTUS_MODULE_OK:RICTUS_MODULE_ERR_START_FAILED;}
    return reply(context,"Usage: !warn status|show WARN-*|ack WARN-*|exercise status|high|critical|show EXWARN-*|ack EXWARN-*")?RICTUS_MODULE_OK:RICTUS_MODULE_ERR_START_FAILED;
}

static rictus_module_result_t
rictus_intelligence_command_sigint(const rictus_module_command_t* command,
    rictus_module_command_reply_fn reply, void* reply_context, void* handler_context)
{
    char response[256]; (void)handler_context;
    if (command == NULL || reply == NULL) return RICTUS_MODULE_ERR_INVALID_ARGUMENT;
    if (strcasecmp(command->arguments,"requirements")==0)
    {
        if(!reply(reply_context,"Requirements=5 | priority 1=2 | priority 2=2 | priority 3=1 | mode=SHADOW"))return RICTUS_MODULE_ERR_START_FAILED;
        if(!reply(reply_context,"P1: IR-001 protected-boundary warning; IR-002 bypass or compromise evidence"))return RICTUS_MODULE_ERR_START_FAILED;
        return reply(reply_context,"P2/P3: fleet pattern; deployed-version applicability; collection performance")?RICTUS_MODULE_OK:RICTUS_MODULE_ERR_START_FAILED;
    }
    if (strcasecmp(command->arguments,"gaps")==0)
    {
        if(!reply(reply_context,"Open collection gaps=3 | Sentinel outcome semantics | distinct sensor/site identity | deployed-version inventory"))return RICTUS_MODULE_ERR_START_FAILED;
        return reply(reply_context,"Gaps remain UNKNOWN evidence; they cannot raise severity, confidence, or lifecycle state.")?RICTUS_MODULE_OK:RICTUS_MODULE_ERR_START_FAILED;
    }
    if (strcasecmp(command->arguments,"sources")==0)
    {
        unsigned int attempts=0,successes=0,failures=0,items=0;size_t i;
        for(i=0;i<g_collection_metric_count;++i){attempts+=g_collection_metrics[i].attempts;successes+=g_collection_metrics[i].successes;failures+=g_collection_metrics[i].failures;items+=g_collection_metrics[i].items;}
        snprintf(response,sizeof(response),"Sources=%u | sensor=1 | discovery=1 | authoritative=%u | since hotload attempts=%u success=%u failure=%u items=%u",(unsigned int)rictus_intelligence_source_count(),(unsigned int)(rictus_intelligence_source_count()-2U),attempts,successes,failures,items);
        if(!reply(reply_context,response))return RICTUS_MODULE_ERR_START_FAILED;
        return reply(reply_context,"STN-LABZ sensors count as sensor diversity, never independent external corroboration. Evaluations are durably logged.")?RICTUS_MODULE_OK:RICTUS_MODULE_ERR_START_FAILED;
    }
    if (strcasecmp(command->arguments, "status") != 0)
        return reply(reply_context, "Usage: !sigint status|requirements|gaps|sources") ? RICTUS_MODULE_OK : RICTUS_MODULE_ERR_START_FAILED;
    snprintf(response, sizeof(response), "Intelligence %u.%u.%u | ABI %u.%u | state=ACTIVE",
        RICTUS_INTELLIGENCE_VERSION_MAJOR, RICTUS_INTELLIGENCE_VERSION_MINOR,
        RICTUS_INTELLIGENCE_VERSION_PATCH, RICTUS_MODULE_API_MAJOR, RICTUS_MODULE_API_MINOR);
    if (!reply(reply_context, response)) return RICTUS_MODULE_ERR_START_FAILED;
    snprintf(response, sizeof(response), "Records=%u | notifications pending=%u | delivered=%u | automatic reporting=%s",
        (unsigned int)g_intelligence_records.count, (unsigned int)g_intelligence_pending_count,
        (unsigned int)g_intelligence_notified_count, g_intelligence_pending_count == 0 ? "CURRENT" : "BACKLOGGED");
    return reply(reply_context, response) ? RICTUS_MODULE_OK : RICTUS_MODULE_ERR_START_FAILED;
}


/*
 * ------------------------------------------------
 * COMMAND: SRT
 * ------------------------------------------------
 *
 * Operator-directed handoff request.
 *
 * This does not create the final SRT identity.
 * The INT identifier remains the source handle
 * until the Security Research workflow accepts
 * and identifies the research target.
 */
static rictus_module_result_t
rictus_intelligence_command_srt(
    const rictus_module_command_t* command,
    rictus_module_command_reply_fn reply,
    void* reply_context,
    void* handler_context
)
{
    const rictus_intelligence_record_t*
        record;

    const rictus_intelligence_srt_request_t*
        existing;

    char response[
        1200
    ];

    char report_path[
        RICTUS_INTELLIGENCE_SRT_PATH_MAX
    ];


    (void)handler_context;


    if (
        command == NULL ||
        reply == NULL
        )
    {
        return
            RICTUS_MODULE_ERR_INVALID_ARGUMENT;
    }


    if (
        command->arguments[0] == '\0'
        )
    {
        if (
            !reply(
                reply_context,
                "Usage: !srt INT-XXXXXXXX"
            )
            )
        {
            return
                RICTUS_MODULE_ERR_START_FAILED;
        }


        return
            RICTUS_MODULE_OK;
    }


    record =
        rictus_intelligence_record_store_find(
            &g_intelligence_records,
            command->arguments
        );


    if (
        record == NULL
        )
    {
        snprintf(
            response,
            sizeof(response),
            "%s: NOT FOUND",
            command->arguments
        );


        if (
            !reply(
                reply_context,
                response
            )
            )
        {
            return
                RICTUS_MODULE_ERR_START_FAILED;
        }


        return
            RICTUS_MODULE_OK;
    }


    existing =
        rictus_intelligence_srt_store_find(
            &g_intelligence_srt_requests,
            record->id
        );


    if (
        existing != NULL
        )
    {
        if (strcasecmp(existing->status, "REJECTED") == 0)
        {
            snprintf(response, sizeof(response),
                "SRT REFUSED | %s | HUMAN DISPOSITION=REJECTED",
                record->id);
            return reply(reply_context, response)
                ? RICTUS_MODULE_OK : RICTUS_MODULE_ERR_START_FAILED;
        }

        snprintf(
            response,
            sizeof(response),
            "SRT ALREADY REQUESTED | %s",
            record->id
        );


        if (
            !reply(
                reply_context,
                response
            )
            )
        {
            return
                RICTUS_MODULE_ERR_START_FAILED;
        }


        return
            RICTUS_MODULE_OK;
    }


    memset(
        report_path,
        0,
        sizeof(report_path)
    );


    if (
        !rictus_intelligence_srt_generate_report(
            RICTUS_INTELLIGENCE_SRT_DIRECTORY,
            record,
            command->sender,
            report_path,
            sizeof(report_path)
        )
        )
    {
        printf(
            "[INTELLIGENCE] SRT report generation failed "
            "id=%s\n",
            record->id
        );


        if (
            !reply(
                reply_context,
                "SRT REQUEST FAILED | REPORT GENERATION FAILED"
            )
            )
        {
            return
                RICTUS_MODULE_ERR_START_FAILED;
        }


        return
            RICTUS_MODULE_OK;
    }


    if (
        !rictus_intelligence_srt_store_append(
            &g_intelligence_srt_requests,
            RICTUS_INTELLIGENCE_SRT_REQUEST_PATH,
            record->id,
            "REQUESTED"
        )
        )
    {
        DeleteFileA(
            report_path
        );


        printf(
            "[INTELLIGENCE] SRT request persistence failed "
            "id=%s\n",
            record->id
        );


        if (
            !reply(
                reply_context,
                "SRT REQUEST FAILED | REQUEST PERSISTENCE FAILED"
            )
            )
        {
            return
                RICTUS_MODULE_ERR_START_FAILED;
        }


        return
            RICTUS_MODULE_OK;
    }


    snprintf(
        response,
        sizeof(response),
        "SRT REQUESTED | %s | HUMAN REVIEW REQUIRED",
        record->id
    );


    if (
        !reply(
            reply_context,
            response
        )
        )
    {
        return
            RICTUS_MODULE_ERR_START_FAILED;
    }


    snprintf(
        response,
        sizeof(response),
        "Report: %s",
        report_path
    );


    if (
        !reply(
            reply_context,
            response
        )
        )
    {
        return
            RICTUS_MODULE_ERR_START_FAILED;
    }


    printf(
        "[INTELLIGENCE] SRT requested "
        "id=%s source=%s title=%s report=%s\n",
        record->id,
        record->item.source,
        record->item.title,
        report_path
    );


    return
        RICTUS_MODULE_OK;
}


static rictus_module_result_t
rictus_intelligence_command_reject(
    const rictus_module_command_t *command,
    rictus_module_command_reply_fn reply,
    void *reply_context,
    void *handler_context
)
{
    const rictus_intelligence_srt_request_t *existing;
    char response[512];

    (void)handler_context;
    if (command == NULL || reply == NULL)
        return RICTUS_MODULE_ERR_INVALID_ARGUMENT;
    if (command->arguments[0] == '\0')
        return reply(reply_context, "Usage: !reject INT-XXXXXXXX")
            ? RICTUS_MODULE_OK : RICTUS_MODULE_ERR_START_FAILED;
    if (strcasecmp(command->sender, "STN_Boss") != 0 &&
        strcasecmp(command->account, "STN_Boss") != 0)
        return reply(reply_context,
            "SRT REJECTION REFUSED | direct STN_Boss role authority required")
            ? RICTUS_MODULE_OK : RICTUS_MODULE_ERR_START_FAILED;

    existing = rictus_intelligence_srt_store_find(
        &g_intelligence_srt_requests, command->arguments);
    if (existing == NULL)
    {
        if (rictus_intelligence_record_store_find(
            &g_intelligence_records, command->arguments) == NULL)
            return reply(reply_context, "SRT REJECTION REFUSED | INT NOT FOUND")
                ? RICTUS_MODULE_OK : RICTUS_MODULE_ERR_START_FAILED;
        if (!rictus_intelligence_srt_store_append(
            &g_intelligence_srt_requests,
            RICTUS_INTELLIGENCE_SRT_REQUEST_PATH,
            command->arguments,
            "REJECTED"))
            return reply(reply_context, "SRT REJECTION FAILED | persistence failure")
                ? RICTUS_MODULE_OK : RICTUS_MODULE_ERR_START_FAILED;
        snprintf(response, sizeof(response),
            "SRT REJECTED | %s | terminal human disposition; Rictus will not advance this INT",
            command->arguments);
        return reply(reply_context, response)
            ? RICTUS_MODULE_OK : RICTUS_MODULE_ERR_START_FAILED;
    }
    if (strcasecmp(existing->status, "REJECTED") == 0)
    {
        snprintf(response, sizeof(response),
            "SRT ALREADY REJECTED | %s | terminal human disposition retained",
            command->arguments);
        return reply(reply_context, response)
            ? RICTUS_MODULE_OK : RICTUS_MODULE_ERR_START_FAILED;
    }
    if (strcasecmp(existing->status, "REQUESTED") != 0)
    {
        snprintf(response, sizeof(response),
            "SRT REJECTION REFUSED | %s | STATUS=%s",
            command->arguments, existing->status);
        return reply(reply_context, response)
            ? RICTUS_MODULE_OK : RICTUS_MODULE_ERR_START_FAILED;
    }
    if (!rictus_intelligence_srt_reject(&g_intelligence_srt_requests,
        RICTUS_INTELLIGENCE_SRT_REQUEST_PATH, command->arguments))
        return reply(reply_context, "SRT REJECTION FAILED | persistence failure")
            ? RICTUS_MODULE_OK : RICTUS_MODULE_ERR_START_FAILED;

    snprintf(response, sizeof(response),
        "SRT REJECTED | %s | terminal human disposition; Rictus will not advance this INT",
        command->arguments);
    return reply(reply_context, response)
        ? RICTUS_MODULE_OK : RICTUS_MODULE_ERR_START_FAILED;
}


/*
 * ------------------------------------------------
 * COMMAND: APPROVE
 * ------------------------------------------------
 *
 * Human-controlled transition from a Pending
 * INT-backed SRT candidate to an Approved SRT.
 *
 * Approval assigns the permanent SRT identity.
 * It does not invoke chain or rag_builder.
 */

static const char *
rictus_intelligence_reviewer_office(
    const char *sender
)
{
    if (
        sender != NULL &&
        strcasecmp(sender, "STN_Boss") == 0
        )
    {
        return "CEO / STN Boss";
    }

    return "UNRESOLVED";
}


static rictus_module_result_t
rictus_intelligence_command_approve(
    const rictus_module_command_t *command,
    rictus_module_command_reply_fn reply,
    void *reply_context,
    void *handler_context
)
{
    const rictus_intelligence_srt_request_t *existing;
    const char *office;
    char srt_id[RICTUS_INTELLIGENCE_SRT_ID_MAX];
    char report_path[RICTUS_INTELLIGENCE_SRT_PATH_MAX];
    char response[1200];

    (void)handler_context;

    if (
        command == NULL ||
        reply == NULL
        )
    {
        return RICTUS_MODULE_ERR_INVALID_ARGUMENT;
    }

    if (
        command->arguments[0] == '\0'
        )
    {
        if (
            !reply(
                reply_context,
                "Usage: !approve INT-XXXXXXXX"
            )
            )
        {
            return RICTUS_MODULE_ERR_START_FAILED;
        }

        return RICTUS_MODULE_OK;
    }

    existing =
        rictus_intelligence_srt_store_find(
            &g_intelligence_srt_requests,
            command->arguments
        );

    if (existing == NULL)
    {
        snprintf(
            response,
            sizeof(response),
            "%s: SRT CANDIDATE NOT FOUND",
            command->arguments
        );

        if (!reply(reply_context, response))
        {
            return RICTUS_MODULE_ERR_START_FAILED;
        }

        return RICTUS_MODULE_OK;
    }

    if (
        strcasecmp(existing->status, "APPROVED") == 0 &&
        existing->srt_id[0] != '\0'
        )
    {
        snprintf(
            response,
            sizeof(response),
            "SRT ALREADY APPROVED | %s -> %s",
            existing->intelligence_id,
            existing->srt_id
        );

        if (!reply(reply_context, response))
        {
            return RICTUS_MODULE_ERR_START_FAILED;
        }

        return RICTUS_MODULE_OK;
    }

    if (
        strcasecmp(existing->status, "REQUESTED") != 0
        )
    {
        snprintf(
            response,
            sizeof(response),
            "SRT APPROVAL REFUSED | %s | STATUS=%s",
            existing->intelligence_id,
            existing->status
        );

        if (!reply(reply_context, response))
        {
            return RICTUS_MODULE_ERR_START_FAILED;
        }

        return RICTUS_MODULE_OK;
    }

    office =
        rictus_intelligence_reviewer_office(
            command->sender
        );

    if (
        strcasecmp(office, "UNRESOLVED") == 0
        )
    {
        if (
            !reply(
                reply_context,
                "SRT APPROVAL REFUSED | REVIEWER OFFICE UNRESOLVED"
            )
            )
        {
            return RICTUS_MODULE_ERR_START_FAILED;
        }

        return RICTUS_MODULE_OK;
    }

    memset(srt_id, 0, sizeof(srt_id));
    memset(report_path, 0, sizeof(report_path));

    if (
        !rictus_intelligence_srt_approve(
            &g_intelligence_srt_requests,
            RICTUS_INTELLIGENCE_SRT_REQUEST_PATH,
            RICTUS_INTELLIGENCE_SRT_DIRECTORY,
            existing->intelligence_id,
            command->sender,
            office,
            srt_id,
            sizeof(srt_id),
            report_path,
            sizeof(report_path)
        )
        )
    {
        if (
            !reply(
                reply_context,
                "SRT APPROVAL FAILED"
            )
            )
        {
            return RICTUS_MODULE_ERR_START_FAILED;
        }

        return RICTUS_MODULE_OK;
    }

    snprintf(
        response,
        sizeof(response),
        "SRT APPROVED | %s -> %s",
        command->arguments,
        srt_id
    );

    if (!reply(reply_context, response))
    {
        return RICTUS_MODULE_ERR_START_FAILED;
    }

    snprintf(
        response,
        sizeof(response),
        "Report: %s",
        report_path
    );

    if (!reply(reply_context, response))
    {
        return RICTUS_MODULE_ERR_START_FAILED;
    }

    printf(
        "[INTELLIGENCE] SRT approved "
        "intelligence_id=%s srt_id=%s reviewer=%s office=%s report=%s\n",
        command->arguments,
        srt_id,
        command->sender,
        office,
        report_path
    );

    return RICTUS_MODULE_OK;
}


/*
 * ------------------------------------------------
 * COMMAND: CHAIN
 * ------------------------------------------------
 *
 * Human-controlled Trust Chain handoff.
 *
 * Preconditions:
 * - argument is an SRT-* identifier
 * - approved SRT report exists
 * - report contains **Status:** Approved
 *
 * This command invokes Chain only. It does not
 * invoke rag_builder and does not copy the report
 * into the RAG input directory.
 */

static int
rictus_intelligence_chain_read_status(
    const char *report_path,
    char *status,
    size_t status_size
)
{
    FILE *fp;
    char line[512];

    if (
        report_path == NULL ||
        status == NULL ||
        status_size == 0
        )
    {
        return 0;
    }

    status[0] = '\0';

    if (
        fopen_s(
            &fp,
            report_path,
            "rb"
        ) != 0 ||
        fp == NULL
        )
    {
        return 0;
    }

    while (
        fgets(
            line,
            sizeof(line),
            fp
        ) != NULL
        )
    {
        const char *prefix =
            "**Status:**";

        char *value;
        char *end;

        if (
            strncmp(
                line,
                prefix,
                strlen(prefix)
            ) != 0
            )
        {
            continue;
        }

        value =
            line +
            strlen(prefix);

        while (
            *value == ' ' ||
            *value == '\t'
            )
        {
            ++value;
        }

        end =
            value +
            strlen(value);

        while (
            end > value &&
            (
                end[-1] == '\r' ||
                end[-1] == '\n' ||
                end[-1] == ' ' ||
                end[-1] == '\t'
            )
            )
        {
            --end;
        }

        *end =
            '\0';

        if (
            value[0] == '\0' ||
            strlen(value) >= status_size
            )
        {
            fclose(fp);

            return 0;
        }

        rictus_intelligence_copy(
            status,
            status_size,
            value
        );

        fclose(fp);

        return 1;
    }

    fclose(fp);

    return 0;
}


static int
rictus_intelligence_chain_read_sha256(
    const char *report_path,
    char sha256[65]
)
{
    FILE *fp;
    char line[512];

    if (
        report_path == NULL ||
        sha256 == NULL
        )
    {
        return 0;
    }

    sha256[0] = '\0';

    if (
        fopen_s(
            &fp,
            report_path,
            "rb"
        ) != 0 ||
        fp == NULL
        )
    {
        return 0;
    }

    while (
        fgets(
            line,
            sizeof(line),
            fp
        ) != NULL
        )
    {
        const char *prefix =
            "sha256:";

        char *value;
        size_t i;

        if (
            strncmp(
                line,
                prefix,
                strlen(prefix)
            ) != 0
            )
        {
            continue;
        }

        value =
            line +
            strlen(prefix);

        while (
            *value == ' ' ||
            *value == '\t'
            )
        {
            ++value;
        }

        if (
            strlen(value) < 64
            )
        {
            fclose(fp);

            return 0;
        }

        for (
            i = 0;
            i < 64;
            ++i
            )
        {
            char c =
                value[i];

            if (
                !(
                    (c >= '0' && c <= '9') ||
                    (c >= 'a' && c <= 'f') ||
                    (c >= 'A' && c <= 'F')
                )
                )
            {
                fclose(fp);

                return 0;
            }

            sha256[i] =
                c;
        }

        sha256[64] =
            '\0';

        fclose(fp);

        return 1;
    }

    fclose(fp);

    return 0;
}


/*
 * Launches the system-installed Chain utility,
 * captures stdout/stderr into a caller buffer,
 * waits for process termination, and returns the
 * child exit code through exit_code.
 */
static int
rictus_intelligence_chain_execute(
    const char *report_path,
    char *output,
    size_t output_size,
    int *exit_code
)
{
    int pipefd[2];
    pid_t pid;
    size_t used = 0;
    int status;

    if (!report_path || !output || output_size < 2 || !exit_code) return 0;
    output[0] = '\0';
    *exit_code = -1;
    if (pipe(pipefd) != 0) return 0;

    pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return 0; }
    if (pid == 0) {
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execlp("chain", "chain", report_path, RICTUS_INTELLIGENCE_CHAIN_INDEX_PATH, (char *)NULL);
        _exit(127);
    }

    close(pipefd[1]);
    for (;;) {
        char buffer[512];
        ssize_t n = read(pipefd[0], buffer, sizeof(buffer));
        if (n <= 0) break;
        if (used < output_size - 1) {
            size_t available = output_size - 1 - used;
            size_t copy_size = (size_t)n < available ? (size_t)n : available;
            memcpy(output + used, buffer, copy_size);
            used += copy_size;
            output[used] = '\0';
        }
    }
    close(pipefd[0]);
    if (waitpid(pid, &status, 0) < 0) return 0;
    if (WIFEXITED(status)) *exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) *exit_code = 128 + WTERMSIG(status);
    return 1;
}

static rictus_module_result_t
rictus_intelligence_command_chain(
    const rictus_module_command_t *command,
    rictus_module_command_reply_fn reply,
    void *reply_context,
    void *handler_context
)
{
    char report_path[
        RICTUS_INTELLIGENCE_SRT_PATH_MAX
    ];

    char status[64];

    char sha256[65];

    char chain_output[
        RICTUS_INTELLIGENCE_CHAIN_OUTPUT_MAX
    ];

    char response[1200];

    int exit_code;

    int written;

    (void)handler_context;

    if (
        command == NULL ||
        reply == NULL
        )
    {
        return
            RICTUS_MODULE_ERR_INVALID_ARGUMENT;
    }

    if (
        command->arguments[0] == '\0'
        )
    {
        if (
            !reply(
                reply_context,
                "Usage: !chain SRT-YYYYMMDD-NNN"
            )
            )
        {
            return
                RICTUS_MODULE_ERR_START_FAILED;
        }

        return
            RICTUS_MODULE_OK;
    }

    if (
        strncasecmp(
            command->arguments,
            "SRT-",
            4
        ) != 0 ||
        strchr(
            command->arguments,
            '\\'
        ) != NULL ||
        strchr(
            command->arguments,
            '/'
        ) != NULL ||
        strstr(
            command->arguments,
            ".."
        ) != NULL
        )
    {
        if (
            !reply(
                reply_context,
                "CHAIN REFUSED | INVALID SRT ID"
            )
            )
        {
            return
                RICTUS_MODULE_ERR_START_FAILED;
        }

        return
            RICTUS_MODULE_OK;
    }

    written =
        snprintf(
            report_path,
            sizeof(report_path),
            "%s\\%s.srt.md",
            RICTUS_INTELLIGENCE_SRT_DIRECTORY,
            command->arguments
        );

    if (
        written <= 0 ||
        written >= (int)sizeof(report_path)
        )
    {
        if (
            !reply(
                reply_context,
                "CHAIN REFUSED | REPORT PATH INVALID"
            )
            )
        {
            return
                RICTUS_MODULE_ERR_START_FAILED;
        }

        return
            RICTUS_MODULE_OK;
    }

    if (
        GetFileAttributesA(
            report_path
        ) ==
        INVALID_FILE_ATTRIBUTES
        )
    {
        snprintf(
            response,
            sizeof(response),
            "CHAIN REFUSED | %s | REPORT NOT FOUND",
            command->arguments
        );

        if (
            !reply(
                reply_context,
                response
            )
            )
        {
            return
                RICTUS_MODULE_ERR_START_FAILED;
        }

        return
            RICTUS_MODULE_OK;
    }

    if (
        !rictus_intelligence_chain_read_status(
            report_path,
            status,
            sizeof(status)
        )
        )
    {
        if (
            !reply(
                reply_context,
                "CHAIN REFUSED | STATUS MISSING OR INVALID"
            )
            )
        {
            return
                RICTUS_MODULE_ERR_START_FAILED;
        }

        return
            RICTUS_MODULE_OK;
    }

    if (
        strcasecmp(
            status,
            "Approved"
        ) != 0
        )
    {
        snprintf(
            response,
            sizeof(response),
            "CHAIN REFUSED | %s | STATUS=%s",
            command->arguments,
            status
        );

        if (
            !reply(
                reply_context,
                response
            )
            )
        {
            return
                RICTUS_MODULE_ERR_START_FAILED;
        }

        return
            RICTUS_MODULE_OK;
    }

    printf(
        "[INTELLIGENCE] Chain requested "
        "srt_id=%s report=%s index=%s\n",
        command->arguments,
        report_path,
        RICTUS_INTELLIGENCE_CHAIN_INDEX_PATH
    );

    if (
        !rictus_intelligence_chain_execute(
            report_path,
            chain_output,
            sizeof(chain_output),
            &exit_code
        )
        )
    {
        if (
            !reply(
                reply_context,
                "CHAIN FAILED | PROCESS LAUNCH FAILED"
            )
            )
        {
            return
                RICTUS_MODULE_ERR_START_FAILED;
        }

        return
            RICTUS_MODULE_OK;
    }

    if (
        exit_code != 0 ||
        strstr(
            chain_output,
            "CHAIN:         PASS"
        ) == NULL
        )
    {
        const char *reason =
            "CHAIN REPORTED FAILURE";

        if (
            strstr(
                chain_output,
                "FAIL_"
            ) != NULL
            )
        {
            char *failure =
                strstr(
                    chain_output,
                    "FAIL_"
                );

            char *end =
                failure;

            while (
                *end != '\0' &&
                *end != '\r' &&
                *end != '\n'
                )
            {
                ++end;
            }

            if (
                (size_t)(end - failure) <
                sizeof(response) - 64
                )
            {
                char failure_text[512];
                size_t failure_length =
                    (size_t)(end - failure);

                memcpy(
                    failure_text,
                    failure,
                    failure_length
                );

                failure_text[failure_length] =
                    '\0';

                snprintf(
                    response,
                    sizeof(response),
                    "CHAIN FAIL | %s | %s",
                    command->arguments,
                    failure_text
                );

                if (
                    !reply(
                        reply_context,
                        response
                    )
                    )
                {
                    return
                        RICTUS_MODULE_ERR_START_FAILED;
                }

                return
                    RICTUS_MODULE_OK;
            }
        }

        snprintf(
            response,
            sizeof(response),
            "CHAIN FAIL | %s | %s | EXIT=%lu",
            command->arguments,
            reason,
            (unsigned long)exit_code
        );

        if (
            !reply(
                reply_context,
                response
            )
            )
        {
            return
                RICTUS_MODULE_ERR_START_FAILED;
        }

        return
            RICTUS_MODULE_OK;
    }

    if (
        !rictus_intelligence_chain_read_sha256(
            report_path,
            sha256
        )
        )
    {
        if (
            !reply(
                reply_context,
                "CHAIN FAIL | PASS REPORTED BUT STAMPED sha256 NOT FOUND"
            )
            )
        {
            return
                RICTUS_MODULE_ERR_START_FAILED;
        }

        return
            RICTUS_MODULE_OK;
    }

    snprintf(
        response,
        sizeof(response),
        "CHAIN PASS | %s",
        command->arguments
    );

    if (
        !reply(
            reply_context,
            response
        )
        )
    {
        return
            RICTUS_MODULE_ERR_START_FAILED;
    }

    snprintf(
        response,
        sizeof(response),
        "sha256: %s",
        sha256
    );

    if (
        !reply(
            reply_context,
            response
        )
        )
    {
        return
            RICTUS_MODULE_ERR_START_FAILED;
    }

    printf(
        "[INTELLIGENCE] Chain PASS "
        "srt_id=%s sha256=%s\n",
        command->arguments,
        sha256
    );

    return
        RICTUS_MODULE_OK;
}


/*
 * ------------------------------------------------
 * RAG OUTPUT RELAY
 * ------------------------------------------------
 *
 * Relays one completed rag_builder stdout/stderr
 * line through the existing command reply path.
 *
 * Empty lines are ignored.
 */
static int
rictus_intelligence_rag_reply_line(
    rictus_module_command_reply_fn reply,
    void *reply_context,
    const char *line
)
{
    char response[
        RICTUS_INTELLIGENCE_IRC_MESSAGE_MAX
    ];

    int written;


    if (
        reply == NULL ||
        line == NULL
        )
    {
        return 0;
    }


    if (
        line[0] == '\0'
        )
    {
        return 1;
    }


    written =
        snprintf(
            response,
            sizeof(response),
            "[RAG] %s",
            line
        );


    if (
        written <= 0 ||
        written >= (int)sizeof(response)
        )
    {
        return 0;
    }


    return
        reply(
            reply_context,
            response
        );
}


/*
 * ------------------------------------------------
 * RAG BUILDER EXECUTION
 * ------------------------------------------------
 *
 * Launches the system-installed rag_builder command
 * with no command-line arguments.
 *
 * rag_builder remains responsible for its own
 * preconfigured C:\stn-labz\rag input/output paths.
 *
 * stdout and stderr are redirected into one pipe
 * and relayed to the operator line-by-line while
 * rag_builder is running.
 *
 * exit_code receives the child process exit code.
 */
static int
rictus_intelligence_rag_execute(
    rictus_module_command_reply_fn reply,
    void *reply_context,
    DWORD *exit_code
)
{
    SECURITY_ATTRIBUTES
        security_attributes;

    STARTUPINFOA
        startup_info;

    PROCESS_INFORMATION
        process_info;

    HANDLE read_pipe =
        NULL;

    HANDLE write_pipe =
        NULL;

    char command_line[] =
        "rag_builder";

    char line[
        RICTUS_INTELLIGENCE_RAG_LINE_MAX
    ];

    size_t line_length =
        0;

    BOOL process_created;

    DWORD bytes_read;


    if (
        reply == NULL ||
        exit_code == NULL
        )
    {
        return 0;
    }


    *exit_code =
        (DWORD)-1;


    memset(
        &security_attributes,
        0,
        sizeof(security_attributes)
    );


    security_attributes.nLength =
        sizeof(security_attributes);

    security_attributes.bInheritHandle =
        TRUE;


    if (
        !CreatePipe(
            &read_pipe,
            &write_pipe,
            &security_attributes,
            0
        )
        )
    {
        return 0;
    }


    if (
        !SetHandleInformation(
            read_pipe,
            HANDLE_FLAG_INHERIT,
            0
        )
        )
    {
        CloseHandle(
            read_pipe
        );

        CloseHandle(
            write_pipe
        );

        return 0;
    }


    memset(
        &startup_info,
        0,
        sizeof(startup_info)
    );


    startup_info.cb =
        sizeof(startup_info);

    startup_info.dwFlags =
        STARTF_USESTDHANDLES;

    startup_info.hStdOutput =
        write_pipe;

    startup_info.hStdError =
        write_pipe;

    startup_info.hStdInput =
        GetStdHandle(
            STD_INPUT_HANDLE
        );


    memset(
        &process_info,
        0,
        sizeof(process_info)
    );


    process_created =
        CreateProcessA(
            NULL,
            command_line,
            NULL,
            NULL,
            TRUE,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &startup_info,
            &process_info
        );


    CloseHandle(
        write_pipe
    );

    write_pipe =
        NULL;


    if (
        !process_created
        )
    {
        CloseHandle(
            read_pipe
        );

        return 0;
    }


    for (;;)
    {
        char buffer[256];
        DWORD index;


        if (
            !ReadFile(
                read_pipe,
                buffer,
                sizeof(buffer),
                &bytes_read,
                NULL
            ) ||
            bytes_read == 0
            )
        {
            break;
        }


        for (
            index = 0;
            index < bytes_read;
            ++index
            )
        {
            char c =
                buffer[index];


            if (
                c == '\r'
                )
            {
                continue;
            }


            if (
                c == '\n'
                )
            {
                line[
                    line_length
                ] =
                    '\0';


                if (
                    !rictus_intelligence_rag_reply_line(
                        reply,
                        reply_context,
                        line
                    )
                    )
                {
                    CloseHandle(
                        read_pipe
                    );

                    TerminateProcess(
                        process_info.hProcess,
                        1
                    );

                    WaitForSingleObject(
                        process_info.hProcess,
                        INFINITE
                    );

                    CloseHandle(
                        process_info.hThread
                    );

                    CloseHandle(
                        process_info.hProcess
                    );

                    return 0;
                }


                line_length =
                    0;

                continue;
            }


            if (
                line_length >=
                sizeof(line) - 1
                )
            {
                line[
                    line_length
                ] =
                    '\0';


                if (
                    !rictus_intelligence_rag_reply_line(
                        reply,
                        reply_context,
                        line
                    )
                    )
                {
                    CloseHandle(
                        read_pipe
                    );

                    TerminateProcess(
                        process_info.hProcess,
                        1
                    );

                    WaitForSingleObject(
                        process_info.hProcess,
                        INFINITE
                    );

                    CloseHandle(
                        process_info.hThread
                    );

                    CloseHandle(
                        process_info.hProcess
                    );

                    return 0;
                }


                line_length =
                    0;
            }


            line[
                line_length++
            ] =
                c;
        }
    }


    CloseHandle(
        read_pipe
    );


    if (
        line_length > 0
        )
    {
        line[
            line_length
        ] =
            '\0';


        if (
            !rictus_intelligence_rag_reply_line(
                reply,
                reply_context,
                line
            )
            )
        {
            TerminateProcess(
                process_info.hProcess,
                1
            );

            WaitForSingleObject(
                process_info.hProcess,
                INFINITE
            );

            CloseHandle(
                process_info.hThread
            );

            CloseHandle(
                process_info.hProcess
            );

            return 0;
        }
    }


    WaitForSingleObject(
        process_info.hProcess,
        INFINITE
    );


    if (
        !GetExitCodeProcess(
            process_info.hProcess,
            exit_code
        )
        )
    {
        *exit_code =
            (DWORD)-1;
    }


    CloseHandle(
        process_info.hThread
    );

    CloseHandle(
        process_info.hProcess
    );


    return 1;
}


/*
 * ------------------------------------------------
 * COMMAND: RAG
 * ------------------------------------------------
 *
 * Operator-directed rag_builder handoff.
 *
 * Operation:
 * - accepts one SRT identifier;
 * - resolves the approved SRT Markdown report;
 * - copies it to C:\stn-labz\rag\input;
 * - invokes the system-installed rag_builder;
 * - relays rag_builder stdout/stderr in real time;
 * - reports PASS or FAIL from the process exit code.
 *
 * This command does not invoke Chain, change
 * rag_builder configuration, or copy corpus output
 * into Digit's corpus directory.
 */
static rictus_module_result_t
rictus_intelligence_command_rag(
    const rictus_module_command_t *command,
    rictus_module_command_reply_fn reply,
    void *reply_context,
    void *handler_context
)
{
    char source_path[
        RICTUS_INTELLIGENCE_SRT_PATH_MAX
    ];

    char destination_path[
        RICTUS_INTELLIGENCE_SRT_PATH_MAX
    ];

    char response[
        1200
    ];

    DWORD attributes;
    int exit_code;
    int written;


    (void)handler_context;


    if (
        command == NULL ||
        reply == NULL
        )
    {
        return
            RICTUS_MODULE_ERR_INVALID_ARGUMENT;
    }


    if (
        command->arguments[0] == '\0'
        )
    {
        if (
            !reply(
                reply_context,
                "Usage: !rag SRT-YYYYMMDD-NNN"
            )
            )
        {
            return
                RICTUS_MODULE_ERR_START_FAILED;
        }


        return
            RICTUS_MODULE_OK;
    }


    if (
        strncasecmp(
            command->arguments,
            "SRT-",
            4
        ) != 0 ||
        strchr(
            command->arguments,
            '\\'
        ) != NULL ||
        strchr(
            command->arguments,
            '/'
        ) != NULL ||
        strstr(
            command->arguments,
            ".."
        ) != NULL
        )
    {
        if (
            !reply(
                reply_context,
                "RAG REFUSED | INVALID SRT ID"
            )
            )
        {
            return
                RICTUS_MODULE_ERR_START_FAILED;
        }


        return
            RICTUS_MODULE_OK;
    }


    written =
        snprintf(
            source_path,
            sizeof(source_path),
            "%s\\%s.srt.md",
            RICTUS_INTELLIGENCE_SRT_DIRECTORY,
            command->arguments
        );


    if (
        written <= 0 ||
        written >= (int)sizeof(source_path)
        )
    {
        if (
            !reply(
                reply_context,
                "RAG REFUSED | SOURCE PATH INVALID"
            )
            )
        {
            return
                RICTUS_MODULE_ERR_START_FAILED;
        }


        return
            RICTUS_MODULE_OK;
    }


    attributes =
        GetFileAttributesA(
            source_path
        );


    if (
        attributes ==
            INVALID_FILE_ATTRIBUTES ||
        (
            attributes &
            FILE_ATTRIBUTE_DIRECTORY
        ) != 0
        )
    {
        snprintf(
            response,
            sizeof(response),
            "RAG REFUSED | %s | SRT NOT FOUND",
            command->arguments
        );


        if (
            !reply(
                reply_context,
                response
            )
            )
        {
            return
                RICTUS_MODULE_ERR_START_FAILED;
        }


        return
            RICTUS_MODULE_OK;
    }


    attributes =
        GetFileAttributesA(
            RICTUS_INTELLIGENCE_RAG_INPUT_DIRECTORY
        );


    if (
        attributes ==
            INVALID_FILE_ATTRIBUTES ||
        (
            attributes &
            FILE_ATTRIBUTE_DIRECTORY
        ) == 0
        )
    {
        if (
            !reply(
                reply_context,
                "RAG FAILED | INPUT DIRECTORY NOT FOUND"
            )
            )
        {
            return
                RICTUS_MODULE_ERR_START_FAILED;
        }


        return
            RICTUS_MODULE_OK;
    }


    written =
        snprintf(
            destination_path,
            sizeof(destination_path),
            "%s\\%s.srt.md",
            RICTUS_INTELLIGENCE_RAG_INPUT_DIRECTORY,
            command->arguments
        );


    if (
        written <= 0 ||
        written >=
            (int)sizeof(destination_path)
        )
    {
        if (
            !reply(
                reply_context,
                "RAG FAILED | DESTINATION PATH INVALID"
            )
            )
        {
            return
                RICTUS_MODULE_ERR_START_FAILED;
        }


        return
            RICTUS_MODULE_OK;
    }


    if (
        !CopyFileA(
            source_path,
            destination_path,
            FALSE
        )
        )
    {
        snprintf(
            response,
            sizeof(response),
            "RAG FAILED | %s | COPY FAILED | WIN32=%lu",
            command->arguments,
            (unsigned long)GetLastError()
        );


        if (
            !reply(
                reply_context,
                response
            )
            )
        {
            return
                RICTUS_MODULE_ERR_START_FAILED;
        }


        return
            RICTUS_MODULE_OK;
    }


    snprintf(
        response,
        sizeof(response),
        "RAG STAGED | %s",
        command->arguments
    );


    if (
        !reply(
            reply_context,
            response
        )
        )
    {
        return
            RICTUS_MODULE_ERR_START_FAILED;
    }


    printf(
        "[INTELLIGENCE] RAG requested "
        "srt_id=%s source=%s destination=%s\n",
        command->arguments,
        source_path,
        destination_path
    );


    if (
        !rictus_intelligence_rag_execute(
            reply,
            reply_context,
            &exit_code
        )
        )
    {
        if (
            !reply(
                reply_context,
                "RAG FAILED | PROCESS EXECUTION FAILED"
            )
            )
        {
            return
                RICTUS_MODULE_ERR_START_FAILED;
        }


        return
            RICTUS_MODULE_OK;
    }


    if (
        exit_code != 0
        )
    {
        snprintf(
            response,
            sizeof(response),
            "RAG FAIL | %s | EXIT=%lu",
            command->arguments,
            (unsigned long)exit_code
        );


        if (
            !reply(
                reply_context,
                response
            )
            )
        {
            return
                RICTUS_MODULE_ERR_START_FAILED;
        }


        printf(
            "[INTELLIGENCE] RAG FAIL "
            "srt_id=%s exit=%lu\n",
            command->arguments,
            (unsigned long)exit_code
        );


        return
            RICTUS_MODULE_OK;
    }


    snprintf(
        response,
        sizeof(response),
        "RAG PASS | %s",
        command->arguments
    );


    if (
        !reply(
            reply_context,
            response
        )
        )
    {
        return
            RICTUS_MODULE_ERR_START_FAILED;
    }


    printf(
        "[INTELLIGENCE] RAG PASS "
        "srt_id=%s\n",
        command->arguments
    );


    return
        RICTUS_MODULE_OK;
}


/*
 * ------------------------------------------------
 * PUBLISH NEW SOURCE EVIDENCE
 * ------------------------------------------------
 */

static int
rictus_intelligence_contains_ci(const char *text, const char *needle)
{
    size_t length;
    const char *cursor;
    if (text == NULL || needle == NULL || needle[0] == '\0') return 0;
    length = strlen(needle);
    for (cursor = text; *cursor != '\0'; ++cursor)
        if (strncasecmp(cursor, needle, length) == 0) return 1;
    return 0;
}


static void
rictus_intelligence_develop_item(
    const rictus_intelligence_item_t *source_item,
    const rictus_intelligence_relevance_result_t *relevance,
    rictus_intelligence_item_t *developed
)
{
    SYSTEMTIME now;
    const char *why;
    int comparative;
    int threat_sensor;
    rictus_intelligence_warning_t sensor_warning;

    *developed = *source_item;
    GetSystemTime(&now);
    snprintf(developed->observed, sizeof(developed->observed),
        "%04u-%02u-%02uT%02u:%02u:%02uZ", now.wYear, now.wMonth,
        now.wDay, now.wHour, now.wMinute, now.wSecond);

    comparative =
        strcmp(source_item->source, "WordPress Security Releases") == 0 ||
        strcmp(source_item->source, "Joomla Security Centre") == 0 ||
        strcmp(source_item->source, "Drupal Core Security Advisories") == 0;
    threat_sensor = strcmp(source_item->source, "STN-LABZ Threat API") == 0;

    if (strcmp(source_item->source, "PHP Releases") == 0)
        why = "Chaos MVC executes on PHP. Security fixes and runtime changes in PHP directly intersect the execution, request-processing, parser, memory-safety, and compatibility boundaries beneath Chaos MVC.";
    else if (comparative)
        why = "STN-LABZ does not infer that Chaos MVC is vulnerable. This advisory concerns a major PHP application and its vulnerability class intersects a comparable Chaos MVC security boundary, making it useful comparative security-research intelligence.";
    else if (threat_sensor)
        why = "This first-party Sentinel observation identifies the requested path, source address, target, and event time needed to distinguish routine probes from protected ChAoS MVC boundary hits.";
    else if (strcmp(source_item->source, "nginx Security Advisories") == 0 ||
             strcmp(source_item->source, "Apache HTTP Server Security") == 0)
        why = "HTTP-server vulnerabilities can affect request routing, proxying, TLS termination, content handling, and isolation around STN-LABZ web services. Deployment applicability must be confirmed from the asset inventory.";
    else if (strcmp(source_item->source, "MariaDB Security") == 0)
        why = "Database security changes may intersect STN-LABZ authentication, privilege, protocol, parser, and data-integrity boundaries. Product/version applicability remains to be confirmed.";
    else if (strcmp(source_item->source, "CERT/CC Vulnerability Notes") == 0)
        why = "CERT/CC provides discovery and corroboration of vulnerability classes that may intersect active STN-LABZ software or infrastructure; originating vendor evidence should be obtained before operational conclusions.";
    else
        why = relevance->reason;

    rictus_intelligence_copy(developed->why_stn_labz_cares,
        sizeof(developed->why_stn_labz_cares), why);
    if (strcmp(source_item->source, "CERT/CC Vulnerability Notes") == 0)
        rictus_intelligence_copy(developed->root_source, sizeof(developed->root_source),
            "Not established by this record; CERT/CC is discovery/corroboration.");
    else
        rictus_intelligence_copy(developed->root_source, sizeof(developed->root_source),
            source_item->source);

    snprintf(developed->evidence, sizeof(developed->evidence),
        "Established by the cited source: %s",
        source_item->summary[0] != '\0' ? source_item->summary : source_item->title);
    snprintf(developed->assessment, sizeof(developed->assessment),
        "%s%s", relevance->reason,
        comparative ? " No evidence in this INT establishes that Chaos MVC contains the cited product vulnerability." : "");
    rictus_intelligence_copy(developed->unknowns, sizeof(developed->unknowns),
        "Affected-version applicability, exposure in the STN-LABZ environment, exploitability, and required mitigation are not established unless explicitly stated in the retained source evidence.");
    if (threat_sensor)
    {
        memset(&sensor_warning, 0, sizeof(sensor_warning));
        if (rictus_intelligence_warning_evaluate(source_item, &sensor_warning))
        {
            snprintf(developed->assessment, sizeof(developed->assessment),
                "%s No successful access, ChAoS MVC applicability, or compromise is established unless explicitly present in the retained sensor evidence.",
                sensor_warning.reason);
        }
        rictus_intelligence_copy(developed->unknowns, sizeof(developed->unknowns),
            "Request outcome, repetition across distinct sites or sensors, and any effect beyond the reported pattern match are not supplied by this event.");
    }
    snprintf(developed->provenance, sizeof(developed->provenance),
        "%s%s%s", source_item->source,
        source_item->url[0] != '\0' ? " | " : "",
        source_item->url);

    if (rictus_intelligence_contains_ci(source_item->title, "CVE-") ||
        rictus_intelligence_contains_ci(source_item->summary, "CVE-"))
        rictus_intelligence_append(developed->assessment, sizeof(developed->assessment),
            " A CVE identifier is present in the retained evidence and should be correlated with the originating advisory.");
}


static int
rictus_intelligence_notification_text(
    char *output,
    size_t output_size,
    const char *input,
    size_t maximum
)
{
    size_t read_index = 0;
    size_t write_index = 0;
    int spacing = 0;

    if (output == NULL || output_size == 0 || input == NULL) return 0;
    while (input[read_index] != '\0' && write_index < maximum && write_index + 1 < output_size)
    {
        unsigned char c = (unsigned char)input[read_index++];
        if (c == '\r' || c == '\n' || c == '\t' || c < 0x20)
        {
            spacing = write_index > 0;
            continue;
        }
        if (spacing && write_index < maximum && write_index + 1 < output_size)
            output[write_index++] = ' ';
        spacing = 0;
        if (write_index >= maximum || write_index + 1 >= output_size) break;
        output[write_index++] = (char)c;
    }
    output[write_index] = '\0';
    return 1;
}


static int
rictus_intelligence_format_notification(
    char *message,
    size_t message_size,
    const char *id,
    const rictus_intelligence_item_t *item
)
{
    int length;
    char title[91];
    char summary[91];
    char url[121];
    if (message == NULL || message_size == 0 || id == NULL || item == NULL)
        return 0;
    if (!rictus_intelligence_notification_text(title, sizeof(title), item->title, 90) ||
        !rictus_intelligence_notification_text(summary, sizeof(summary),
            item->summary[0] != '\0' ? item->summary : item->title, 90) ||
        !rictus_intelligence_notification_text(url, sizeof(url),
            item->url, 120)) return 0;
    length = snprintf(message, message_size,
        "[Rictus Intel] %s - %s | SUMMARY: %s | SOURCE: %s | PM: !show %s",
        id, title, summary, url[0] ? url : "NOT SUPPLIED", id);
    return length > 0 && length < (int)message_size;
}


static int rictus_intelligence_id_list_contains(
    char ids[][RICTUS_INTELLIGENCE_RECORD_ID_MAX], size_t count, const char *id)
{
    size_t index;
    for (index = 0; index < count; ++index)
        if (strcasecmp(ids[index], id) == 0) return 1;
    return 0;
}


static int rictus_intelligence_notification_load(void)
{
    FILE *file = NULL;
    char line[RICTUS_INTELLIGENCE_RECORD_ID_MAX + 8];
    size_t index;
    g_intelligence_notified_count = 0;
    g_intelligence_pending_count = 0;
    if (fopen_s(&file, g_intelligence_notified_path, "r") == 0 && file != NULL)
    {
        while (fgets(line, sizeof(line), file) != NULL &&
            g_intelligence_notified_count < RICTUS_INTELLIGENCE_NOTIFICATION_MAX)
        {
            line[strcspn(line, "\r\n")] = '\0';
            if (line[0] != '\0' &&
                !rictus_intelligence_id_list_contains(g_intelligence_notified,
                    g_intelligence_notified_count, line))
                rictus_intelligence_copy(g_intelligence_notified[g_intelligence_notified_count++],
                    RICTUS_INTELLIGENCE_RECORD_ID_MAX, line);
        }
        fclose(file);
    }
    for (index = 0; index < g_intelligence_records.count; ++index)
    {
        const rictus_intelligence_record_t *record = &g_intelligence_records.records[index];
        if (record->item.observed[0] != '\0' &&
            !rictus_intelligence_id_list_contains(g_intelligence_notified,
                g_intelligence_notified_count, record->id) &&
            g_intelligence_pending_count < RICTUS_INTELLIGENCE_NOTIFICATION_MAX)
            rictus_intelligence_copy(g_intelligence_pending[g_intelligence_pending_count++],
                RICTUS_INTELLIGENCE_RECORD_ID_MAX, record->id);
    }
    return 1;
}


static int rictus_intelligence_notification_queue(const char *id)
{
    if (id == NULL || id[0] == '\0') return 0;
    if (rictus_intelligence_id_list_contains(g_intelligence_notified,
            g_intelligence_notified_count, id) ||
        rictus_intelligence_id_list_contains(g_intelligence_pending,
            g_intelligence_pending_count, id)) return 1;
    if (g_intelligence_pending_count >= RICTUS_INTELLIGENCE_NOTIFICATION_MAX) return 0;
    rictus_intelligence_copy(g_intelligence_pending[g_intelligence_pending_count++],
        RICTUS_INTELLIGENCE_RECORD_ID_MAX, id);
    return 1;
}


static int rictus_intelligence_notification_mark(const char *id)
{
    FILE *file = NULL;
    if (g_intelligence_notified_count >= RICTUS_INTELLIGENCE_NOTIFICATION_MAX) return 0;
    if (fopen_s(&file, g_intelligence_notified_path, "a") != 0 || file == NULL) return 0;
    if (fprintf(file, "%s\n", id) < 0 || fflush(file) != 0)
    { fclose(file); return 0; }
    fclose(file);
    rictus_intelligence_copy(g_intelligence_notified[g_intelligence_notified_count++],
        RICTUS_INTELLIGENCE_RECORD_ID_MAX, id);
    return 1;
}


static void rictus_intelligence_notification_drain(void)
{
    while (g_intelligence_pending_count > 0)
    {
        const char *id = g_intelligence_pending[0];
        const rictus_intelligence_record_t *record =
            rictus_intelligence_record_store_find(&g_intelligence_records, id);
        char message[RICTUS_INTELLIGENCE_IRC_MESSAGE_MAX];
        if (WaitForSingleObject(g_intelligence_stop_event, 0) == WAIT_OBJECT_0) return;
        if (record == NULL ||
            !rictus_intelligence_format_notification(message, sizeof(message), id, &record->item) ||
            !g_intelligence_host->send_message(message) ||
            !rictus_intelligence_notification_mark(id))
        {
            printf("[INTELLIGENCE] IRC notification deferred id=%s\n", id);
            return;
        }
        printf("[INTELLIGENCE] IRC publication PASS id=%s fingerprint=%s\n",
            id, record->item.fingerprint);
        --g_intelligence_pending_count;
        if (g_intelligence_pending_count > 0)
            memmove(g_intelligence_pending, g_intelligence_pending + 1,
                g_intelligence_pending_count * sizeof(g_intelligence_pending[0]));
        if (g_intelligence_pending_count > 0 &&
            WaitForSingleObject(g_intelligence_stop_event,
                RICTUS_INTELLIGENCE_NOTIFICATION_INTERVAL_MS) == WAIT_OBJECT_0) return;
    }
}

static int
rictus_intelligence_publish_item(
    const rictus_intelligence_item_t* item,
    int notify_operator
)
{
    char id[
        RICTUS_INTELLIGENCE_RECORD_ID_MAX
    ];

    (void)notify_operator;

    if (
        item == NULL ||
        g_intelligence_host == NULL ||
        g_intelligence_host->send_message == NULL
        )
    {
        return 0;
    }

    if (
        !rictus_intelligence_record_store_append(
            &g_intelligence_records,
            g_intelligence_record_path,
            item,
            id,
            sizeof(id)
    )
        )
    {
        printf(
            "[INTELLIGENCE] Record persistence FAILED "
            "fingerprint=%s\n",
            item->fingerprint
        );

        return 0;
    }

    {rictus_intelligence_warning_t warning;if(rictus_intelligence_warning_evaluate(item,&warning)&&warning.severity>=RICTUS_INTELLIGENCE_SEVERITY_HIGH){if(!rictus_warning_create(&g_warning_store,id,&warning))printf("[INTELLIGENCE] Warning persistence FAILED id=%s\n",id);else rictus_warning_deliver(&g_warning_store,g_intelligence_host->send_message);}}

    if (!rictus_intelligence_notification_queue(id))
    {
        printf("[INTELLIGENCE] Notification queue FULL id=%s\n", id);
        return 0;
    }
    printf("[INTELLIGENCE] IRC notification QUEUED id=%s\n", id);
    return 1;
}


/*
 * ------------------------------------------------
 * PROCESS NORMALIZED ITEM
 * ------------------------------------------------
 */

static int
rictus_intelligence_process_item(
    const rictus_intelligence_item_t* item,
    int notify_operator
)
{
    rictus_intelligence_seen_result_t
        seen_result;

    rictus_intelligence_item_t developed_item;


    if (
        item == NULL
        )
    {
        return 0;
    }


    if (
        rictus_intelligence_seen_contains(
            &g_intelligence_seen,
            item->fingerprint
        )
        )
    {
        printf(
            "[INTELLIGENCE] Known item "
            "source=%s fingerprint=%s\n",
            item->source,
            item->fingerprint
        );


        return 0;
    }


    {
        rictus_intelligence_relevance_result_t relevance_result;

        if (!rictus_intelligence_relevance_evaluate(item, &relevance_result))
        {
            printf("[INTELLIGENCE] Relevance evaluation FAILED source=%s fingerprint=%s\n", item->source, item->fingerprint);
            return 0;
        }

        if (relevance_result.relevance != RICTUS_INTELLIGENCE_RELEVANCE_RELEVANT)
        {
            printf("[INTELLIGENCE] SKIPPED IRRELEVANT source=%s fingerprint=%s reason=%s\n", item->source, item->fingerprint, relevance_result.reason);
            return 0;
        }

        printf("[INTELLIGENCE] RELEVANT source=%s fingerprint=%s domains=0x%02X reason=%s\n", item->source, item->fingerprint, relevance_result.domain_flags, relevance_result.reason);

        rictus_intelligence_develop_item(item, &relevance_result, &developed_item);
    }

    printf(
        "[INTELLIGENCE] NEW ITEM "
        "source=%s "
        "fingerprint=%s\n",
        item->source,
        item->fingerprint
    );


    printf(
        "[INTELLIGENCE] TITLE: %s\n",
        item->title
    );


    if (
        item->published[0] != '\0'
        )
    {
        printf(
            "[INTELLIGENCE] PUBLISHED: %s\n",
            item->published
        );
    }


    if (
        item->url[0] != '\0'
        )
    {
        printf(
            "[INTELLIGENCE] URL: %s\n",
            item->url
        );
    }


    seen_result = rictus_intelligence_seen_add(
        &g_intelligence_seen, developed_item.fingerprint);
    if (seen_result != RICTUS_INTELLIGENCE_SEEN_OK)
    {
        printf("[INTELLIGENCE] Seen-state failure fingerprint=%s result=%s\n",
            developed_item.fingerprint,
            rictus_intelligence_seen_result_string(seen_result));
        return 0;
    }

    return rictus_intelligence_publish_item(&developed_item, notify_operator);
}


/*
 * ------------------------------------------------
 * COLLECTION CYCLE
 * ------------------------------------------------
 */

static void
rictus_intelligence_collect_cycle(void)
{
    size_t source_count;

    size_t source_index;

    unsigned int notifications_sent =
        0;

    rictus_intelligence_item_set_t
        *items;


    items =
        (rictus_intelligence_item_set_t *)
        malloc(
            sizeof(*items)
        );


    if (
        items == NULL
        )
    {
        printf(
            "[INTELLIGENCE] Collection cycle failed: "
            "item-set allocation failed.\n"
        );


        return;
    }


    source_count =
        rictus_intelligence_source_count();


    printf(
        "[INTELLIGENCE] Collection cycle starting. "
        "sources=%u\n",
        (unsigned int)
        source_count
    );

    printf("[INTELLIGENCE] Pre-collection notification drain pending=%u.\n",
        (unsigned int)g_intelligence_pending_count);
    rictus_intelligence_notification_drain();

    for (
        source_index = 0;
        source_index < source_count;
        ++source_index
        )
    {
        const
            rictus_intelligence_source_definition_t
            * source;

        rictus_intelligence_response_t
            response;

        rictus_intelligence_collect_result_t
            collect_result;

        rictus_intelligence_parse_result_t
            parse_result;

        size_t item_index;


        if (
            WaitForSingleObject(
                g_intelligence_stop_event,
                0
            ) == WAIT_OBJECT_0
            )
        {
            free(
                items
            );


            return;
        }


        source =
            rictus_intelligence_source_get(
                source_index
            );


        if (
            source == NULL
            )
        {
            continue;
        }


        memset(
            &response,
            0,
            sizeof(response)
        );


        memset(
            items,
            0,
            sizeof(*items)
        );


        printf(
            "[INTELLIGENCE] Collecting "
            "source=%s id=%s\n",
            source->name,
            source->id
        );


        collect_result =
            rictus_intelligence_collect(
                source,
                &response
            );


        if (
            collect_result !=
            RICTUS_INTELLIGENCE_COLLECT_OK
            )
        {
            collection_record(source->id,0,response.http_status,0);
            printf(
                "[INTELLIGENCE] Collection failed "
                "source=%s result=%s http=%lu\n",
                source->name,
                rictus_intelligence_collect_result_string(
                    collect_result
                ),
                response.http_status
            );


            rictus_intelligence_response_free(
                &response
            );


            continue;
        }


        printf(
            "[INTELLIGENCE] Collection complete "
            "source=%s http=%lu bytes=%u\n",
            source->name,
            response.http_status,
            (unsigned int)
            response.body_length
        );


        parse_result =
            rictus_intelligence_parse_response(
                source,
                &response,
                items
            );


        if (
            parse_result !=
            RICTUS_INTELLIGENCE_PARSE_OK &&
            parse_result !=
            RICTUS_INTELLIGENCE_PARSE_ITEM_LIMIT
            )
        {
            collection_record(source->id,0,response.http_status,0);
            printf(
                "[INTELLIGENCE] Parse failed "
                "source=%s result=%s\n",
                source->name,
                rictus_intelligence_parse_result_string(
                    parse_result
                )
            );


            rictus_intelligence_response_free(
                &response
            );


            continue;
        }


        printf(
            "[INTELLIGENCE] Normalized "
            "source=%s items=%u\n",
            source->name,
            (unsigned int)
            items->count
        );
        collection_record(source->id,1,response.http_status,items->count);


        rictus_intelligence_response_free(
            &response
        );

        if (strcmp(source->id, "stn_labz_threats") == 0 &&
            !threat_json_baseline_exists())
        {
            int baseline_ok = 1;
            for (item_index = 0; item_index < items->count; ++item_index)
            {
                if (!rictus_intelligence_seen_contains(&g_intelligence_seen,
                        items->items[item_index].fingerprint) &&
                    rictus_intelligence_seen_add(&g_intelligence_seen,
                        items->items[item_index].fingerprint) !=
                        RICTUS_INTELLIGENCE_SEEN_OK)
                {
                    baseline_ok = 0;
                    break;
                }
            }
            if (baseline_ok && threat_json_baseline_store())
            {
                printf("[INTELLIGENCE] Threat JSON baseline established items=%u; historical replay suppressed.\n",
                    (unsigned int)items->count);
            }
            else
            {
                printf("[INTELLIGENCE] Threat JSON baseline FAILED; source processing deferred.\n");
            }
            continue;
        }


        for (
            item_index = 0;
            item_index < items->count;
            ++item_index
            )
        {
            if (
                WaitForSingleObject(
                    g_intelligence_stop_event,
                    0
                ) == WAIT_OBJECT_0
                )
            {
                free(
                    items
                );


                return;
            }


            int published;


            published =
                rictus_intelligence_process_item(
                    &items->items[
                        item_index
                    ],
                    notifications_sent <
                        RICTUS_INTELLIGENCE_NOTIFICATIONS_PER_CYCLE
                );


            if (published)
            {
                notifications_sent++;


                if (
                    notifications_sent <
                        RICTUS_INTELLIGENCE_NOTIFICATIONS_PER_CYCLE &&
                    WaitForSingleObject(
                        g_intelligence_stop_event,
                        RICTUS_INTELLIGENCE_NOTIFICATION_INTERVAL_MS
                    ) == WAIT_OBJECT_0
                )
                {
                    free(items);

                    return;
                }
            }
        }
    }


    printf(
        "[INTELLIGENCE] Collection cycle complete.\n"
    );

    printf("[INTELLIGENCE] Notification drain starting pending=%u.\n",
        (unsigned int)g_intelligence_pending_count);
    rictus_intelligence_notification_drain();

    free(
        items
    );
}


/*
 * ------------------------------------------------
 * WORKER
 * ------------------------------------------------
 */

static DWORD WINAPI
rictus_intelligence_worker(
    LPVOID parameter
)
{
    DWORD wait_result;


    (void)parameter;


    printf(
        "[INTELLIGENCE] Worker started.\n"
    );


    for (;;)
    {
        if (
            WaitForSingleObject(
                g_intelligence_stop_event,
                0
            ) == WAIT_OBJECT_0
            )
        {
            break;
        }


        rictus_intelligence_collect_cycle();


        wait_result =
            WaitForSingleObject(
                g_intelligence_stop_event,
                RICTUS_INTELLIGENCE_COLLECTION_INTERVAL_MS
            );


        if (
            wait_result ==
            WAIT_OBJECT_0
            )
        {
            break;
        }


        if (
            wait_result !=
            WAIT_TIMEOUT
            )
        {
            break;
        }
    }


    printf(
        "[INTELLIGENCE] Worker stopped.\n"
    );


    InterlockedExchange(
        &g_intelligence_running,
        0
    );


    return 0;
}


/*
 * ------------------------------------------------
 * START
 * ------------------------------------------------
 */

static rictus_module_result_t
rictus_intelligence_start(
    const rictus_module_host_t* host
)
{
    HANDLE stop_event;

    HANDLE thread;

    rictus_intelligence_seen_result_t
        seen_result;


    if (
        host == NULL ||
        host->send_message == NULL ||
        host->register_command == NULL ||
        host->unregister_command == NULL
        )
    {
        return
            RICTUS_MODULE_ERR_INVALID_ARGUMENT;
    }


    if (
        InterlockedCompareExchange(
            &g_intelligence_running,
            0,
            0
        ) != 0
        )
    {
        return
            RICTUS_MODULE_ERR_INVALID_STATE;
    }


    if (
        g_intelligence_thread != NULL ||
        g_intelligence_stop_event != NULL
        )
    {
        return
            RICTUS_MODULE_ERR_INVALID_STATE;
    }


    g_intelligence_host =
        host;


    rictus_intelligence_seen_init(
        &g_intelligence_seen
    );


    seen_result =
        rictus_intelligence_seen_load(
            &g_intelligence_seen
        );


    if (
        seen_result !=
        RICTUS_INTELLIGENCE_SEEN_OK
        )
    {
        printf(
            "[INTELLIGENCE] Seen-state load failed "
            "result=%s\n",
            rictus_intelligence_seen_result_string(
                seen_result
            )
        );


        g_intelligence_host =
            NULL;


        return
            RICTUS_MODULE_ERR_START_FAILED;
    }


    printf(
        "[INTELLIGENCE] Seen-state loaded "
        "records=%u\n",
        (unsigned int)
        g_intelligence_seen.count
    );


    rictus_intelligence_record_store_init(
        &g_intelligence_records
    );


    if (
        !rictus_intelligence_record_store_load(
            &g_intelligence_records,
            g_intelligence_record_path
        )
        )
    {
        printf(
            "[INTELLIGENCE] Record-store load failed: %s\n",
            g_intelligence_record_path
        );


        g_intelligence_host =
            NULL;


        return
            RICTUS_MODULE_ERR_START_FAILED;
    }


    printf(
        "[INTELLIGENCE] Record-store loaded records=%u\n",
        (unsigned int)
        g_intelligence_records.count
    );

    if(!rictus_warning_load(&g_warning_store)){g_intelligence_host=NULL;return RICTUS_MODULE_ERR_START_FAILED;}
    if(!rictus_warning_exercise_load(&g_warning_exercise_store)){g_intelligence_host=NULL;return RICTUS_MODULE_ERR_START_FAILED;}

    if (!rictus_intelligence_notification_load())
    {
        g_intelligence_host = NULL;
        return RICTUS_MODULE_ERR_START_FAILED;
    }

    printf("[INTELLIGENCE] Notification state loaded sent=%u pending=%u\n",
        (unsigned int)g_intelligence_notified_count,
        (unsigned int)g_intelligence_pending_count);


    rictus_intelligence_srt_store_init(
        &g_intelligence_srt_requests
    );


    if (
        !rictus_intelligence_srt_store_load(
            &g_intelligence_srt_requests,
            RICTUS_INTELLIGENCE_SRT_REQUEST_PATH
        )
        )
    {
        printf(
            "[INTELLIGENCE] SRT request-store load failed: %s\n",
            RICTUS_INTELLIGENCE_SRT_REQUEST_PATH
        );


        g_intelligence_host =
            NULL;


        return
            RICTUS_MODULE_ERR_START_FAILED;
    }


    printf(
        "[INTELLIGENCE] SRT request-store loaded records=%u\n",
        (unsigned int)
        g_intelligence_srt_requests.count
    );


    if (
        !g_intelligence_host->register_command(
            "show",
            rictus_intelligence_command_show,
            NULL
        )
        )
    {
        printf(
            "[INTELLIGENCE] Command registration failed: show\n"
        );


        g_intelligence_host =
            NULL;


        return
            RICTUS_MODULE_ERR_START_FAILED;
    }


    printf(
        "[INTELLIGENCE] Command registered: show\n"
    );


    if (
        !g_intelligence_host->register_command(
            "srt",
            rictus_intelligence_command_srt,
            NULL
        )
        )
    {
        printf(
            "[INTELLIGENCE] Command registration failed: srt\n"
        );


        (void)
            g_intelligence_host->unregister_command(
                "srt",
                NULL
            );


        (void)
            g_intelligence_host->unregister_command(
                "show",
                NULL
            );


        g_intelligence_host =
            NULL;


        return
            RICTUS_MODULE_ERR_START_FAILED;
    }


    printf(
        "[INTELLIGENCE] Command registered: srt\n"
    );


    if (
        !g_intelligence_host->register_command(
            "approve",
            rictus_intelligence_command_approve,
            NULL
        )
        )
    {
        printf(
            "[INTELLIGENCE] Command registration failed: approve\n"
        );

        (void)
            g_intelligence_host->unregister_command(
                "srt",
                NULL
            );

        (void)
            g_intelligence_host->unregister_command(
                "show",
                NULL
            );

        g_intelligence_host =
            NULL;

        return
            RICTUS_MODULE_ERR_START_FAILED;
    }


    printf(
        "[INTELLIGENCE] Command registered: approve\n"
    );


    if (
        !g_intelligence_host->register_command(
            "chain",
            rictus_intelligence_command_chain,
            NULL
        )
        )
    {
        printf(
            "[INTELLIGENCE] Command registration failed: chain\n"
        );

        (void)
            g_intelligence_host->unregister_command(
                "chain",
                NULL
            );

        (void)
            g_intelligence_host->unregister_command(
                "approve",
                NULL
            );

        (void)
            g_intelligence_host->unregister_command(
                "srt",
                NULL
            );

        (void)
            g_intelligence_host->unregister_command(
                "show",
                NULL
            );

        g_intelligence_host =
            NULL;

        return
            RICTUS_MODULE_ERR_START_FAILED;
    }


    printf(
        "[INTELLIGENCE] Command registered: chain\n"
    );


    if (
        !g_intelligence_host->register_command(
            "rag",
            rictus_intelligence_command_rag,
            NULL
        )
        )
    {
        printf(
            "[INTELLIGENCE] Command registration failed: rag\n"
        );

        (void)
            g_intelligence_host->unregister_command(
                "chain",
                NULL
            );

        (void)
            g_intelligence_host->unregister_command(
                "approve",
                NULL
            );

        (void)
            g_intelligence_host->unregister_command(
                "srt",
                NULL
            );

        (void)
            g_intelligence_host->unregister_command(
                "show",
                NULL
            );

        g_intelligence_host =
            NULL;

        return
            RICTUS_MODULE_ERR_START_FAILED;
    }


    printf(
        "[INTELLIGENCE] Command registered: rag\n"
    );

    if (!g_intelligence_host->register_command(
            "sigint", rictus_intelligence_command_sigint, NULL))
    {
        (void)g_intelligence_host->unregister_command("rag", NULL);
        (void)g_intelligence_host->unregister_command("chain", NULL);
        (void)g_intelligence_host->unregister_command("approve", NULL);
        (void)g_intelligence_host->unregister_command("srt", NULL);
        (void)g_intelligence_host->unregister_command("show", NULL);
        g_intelligence_host = NULL;
        return RICTUS_MODULE_ERR_START_FAILED;
    }
    printf("[INTELLIGENCE] Command registered: sigint\n");
    if(!g_intelligence_host->register_command("warn",rictus_intelligence_command_warn,NULL)){(void)g_intelligence_host->unregister_command("sigint",NULL);(void)g_intelligence_host->unregister_command("rag",NULL);(void)g_intelligence_host->unregister_command("chain",NULL);(void)g_intelligence_host->unregister_command("approve",NULL);(void)g_intelligence_host->unregister_command("srt",NULL);(void)g_intelligence_host->unregister_command("show",NULL);g_intelligence_host=NULL;return RICTUS_MODULE_ERR_START_FAILED;}
    if(!g_intelligence_host->register_command("reject",rictus_intelligence_command_reject,NULL)){(void)g_intelligence_host->unregister_command("warn",NULL);(void)g_intelligence_host->unregister_command("sigint",NULL);(void)g_intelligence_host->unregister_command("rag",NULL);(void)g_intelligence_host->unregister_command("chain",NULL);(void)g_intelligence_host->unregister_command("approve",NULL);(void)g_intelligence_host->unregister_command("srt",NULL);(void)g_intelligence_host->unregister_command("show",NULL);g_intelligence_host=NULL;return RICTUS_MODULE_ERR_START_FAILED;}
    printf("[INTELLIGENCE] Command registered: reject\n");
    rictus_warning_deliver(&g_warning_store,g_intelligence_host->send_message);
    rictus_warning_exercise_deliver(&g_warning_exercise_store,g_intelligence_host->send_message);


    stop_event =
        CreateEventA(
            NULL,
            TRUE,
            FALSE,
            NULL
        );


    if (
        stop_event == NULL
        )
    {
        (void)g_intelligence_host->unregister_command("reject",NULL);
        (void)g_intelligence_host->unregister_command("warn",NULL);
        (void)g_intelligence_host->unregister_command("sigint", NULL);
        (void)
            g_intelligence_host->unregister_command(
                "rag",
                NULL
            );

        (void)
            g_intelligence_host->unregister_command(
                "chain",
                NULL
            );

        (void)
            g_intelligence_host->unregister_command(
                "approve",
                NULL
            );

        (void)
            g_intelligence_host->unregister_command(
                "srt",
                NULL
            );


        (void)
            g_intelligence_host->unregister_command(
                "show",
                NULL
            );


        g_intelligence_host =
            NULL;


        return
            RICTUS_MODULE_ERR_START_FAILED;
    }


    g_intelligence_stop_event =
        stop_event;


    thread =
        CreateThread(
            NULL,
            0,
            rictus_intelligence_worker,
            NULL,
            0,
            NULL
        );


    if (
        thread == NULL
        )
    {
        CloseHandle(
            g_intelligence_stop_event
        );


        g_intelligence_stop_event =
            NULL;

        (void)g_intelligence_host->unregister_command("reject",NULL);
        (void)g_intelligence_host->unregister_command("warn",NULL);
        (void)g_intelligence_host->unregister_command("sigint", NULL);


        (void)
            g_intelligence_host->unregister_command(
                "rag",
                NULL
            );

        (void)
            g_intelligence_host->unregister_command(
                "chain",
                NULL
            );

        (void)
            g_intelligence_host->unregister_command(
                "approve",
                NULL
            );

        (void)
            g_intelligence_host->unregister_command(
                "srt",
                NULL
            );

        (void)
            g_intelligence_host->unregister_command(
                "show",
                NULL
            );


        g_intelligence_host =
            NULL;


        return
            RICTUS_MODULE_ERR_START_FAILED;
    }


    g_intelligence_thread =
        thread;


    InterlockedExchange(
        &g_intelligence_running,
        1
    );


    printf(
        "[INTELLIGENCE] Module ACTIVE.\n"
    );


    return
        RICTUS_MODULE_OK;
}


/*
 * ------------------------------------------------
 * STOP
 * ------------------------------------------------
 */

static rictus_module_result_t
rictus_intelligence_stop(void)
{
    DWORD wait_result;


    if (
        g_intelligence_thread == NULL ||
        g_intelligence_stop_event == NULL
        )
    {
        return
            RICTUS_MODULE_ERR_INVALID_STATE;
    }


    printf(
        "[INTELLIGENCE] Stop requested.\n"
    );


    if (
        !SetEvent(
            g_intelligence_stop_event
        )
        )
    {
        return
            RICTUS_MODULE_ERR_STOP_FAILED;
    }


    wait_result =
        WaitForSingleObject(
            g_intelligence_thread,
            INFINITE
        );


    if (
        wait_result !=
        WAIT_OBJECT_0
        )
    {
        return
            RICTUS_MODULE_ERR_STOP_FAILED;
    }


    CloseHandle(
        g_intelligence_thread
    );


    g_intelligence_thread =
        NULL;


    CloseHandle(
        g_intelligence_stop_event
    );


    g_intelligence_stop_event =
        NULL;

    if(!g_intelligence_host->unregister_command("reject",NULL))return RICTUS_MODULE_ERR_STOP_FAILED;
    if(!g_intelligence_host->unregister_command("warn",NULL))return RICTUS_MODULE_ERR_STOP_FAILED;
    if (!g_intelligence_host->unregister_command("sigint", NULL))
        return RICTUS_MODULE_ERR_STOP_FAILED;

    printf("[INTELLIGENCE] Command unregistered: sigint\n");


    if (
        g_intelligence_host == NULL ||
        g_intelligence_host->unregister_command == NULL ||
        !g_intelligence_host->unregister_command(
            "rag",
            NULL
        )
        )
    {
        return
            RICTUS_MODULE_ERR_STOP_FAILED;
    }


    printf(
        "[INTELLIGENCE] Command unregistered: rag\n"
    );


    if (
        !g_intelligence_host->unregister_command(
            "chain",
            NULL
        )
        )
    {
        return
            RICTUS_MODULE_ERR_STOP_FAILED;
    }


    printf(
        "[INTELLIGENCE] Command unregistered: chain\n"
    );


    if (
        !g_intelligence_host->unregister_command(
            "approve",
            NULL
        )
        )
    {
        return
            RICTUS_MODULE_ERR_STOP_FAILED;
    }


    printf(
        "[INTELLIGENCE] Command unregistered: approve\n"
    );


    if (
        !g_intelligence_host->unregister_command(
            "srt",
            NULL
        )
        )
    {
        return
            RICTUS_MODULE_ERR_STOP_FAILED;
    }


    printf(
        "[INTELLIGENCE] Command unregistered: srt\n"
    );


    if (
        !g_intelligence_host->unregister_command(
            "show",
            NULL
        )
        )
    {
        return
            RICTUS_MODULE_ERR_STOP_FAILED;
    }


    printf(
        "[INTELLIGENCE] Command unregistered: show\n"
    );


    g_intelligence_host =
        NULL;


    InterlockedExchange(
        &g_intelligence_running,
        0
    );


    printf(
        "[INTELLIGENCE] Module stopped cleanly.\n"
    );


    return
        RICTUS_MODULE_OK;
}


/*
 * ------------------------------------------------
 * QUALIFICATION
 * ------------------------------------------------
 */

static rictus_module_result_t
rictus_intelligence_qualify(
    rictus_module_qualification_result_t* result
)
{
    unsigned int executed =
        0;

    unsigned int passed =
        0;

    unsigned int failed =
        0;

    int negative_executed =
        0;

    int negative_passed =
        0;

    rictus_intelligence_item_t comparative_item;
    rictus_intelligence_item_t developed_item;
    rictus_intelligence_relevance_result_t comparative_relevance;
    rictus_intelligence_item_t policy_item;
    rictus_intelligence_warning_t warning;
    rictus_intelligence_source_evaluation_t source_evaluation;
    rictus_intelligence_response_t threat_response;
    rictus_intelligence_item_set_t *threat_items;
    const rictus_intelligence_source_definition_t *threat_source;
    static const char *const irrelevant_cisa_titles[] = {
        "Casdoor Servers contain an authentication vulnerability",
        "CISA Adds One Known Exploited Vulnerability to Catalog",
        "Pyramid Solutions NetStaX EtherNet/IP Stack vulnerability",
        "IXON VPN Client security vulnerability",
        "Rockwell Automation ArmorStart LT vulnerability"
    };
    size_t irrelevant_index;
    char notification[RICTUS_INTELLIGENCE_IRC_MESSAGE_MAX];


    if (
        result == NULL
        )
    {
        return
            RICTUS_MODULE_ERR_INVALID_ARGUMENT;
    }


    memset(
        result,
        0,
        sizeof(*result)
    );

    memset(&comparative_item, 0, sizeof(comparative_item));
    memset(&developed_item, 0, sizeof(developed_item));
    memset(&comparative_relevance, 0, sizeof(comparative_relevance));
    memset(&policy_item, 0, sizeof(policy_item));
    memset(&warning, 0, sizeof(warning));
    memset(&source_evaluation, 0, sizeof(source_evaluation));
    memset(&threat_response, 0, sizeof(threat_response));
    threat_items = (rictus_intelligence_item_set_t *)calloc(1, sizeof(*threat_items));
    if (threat_items == NULL)
    {
        return RICTUS_MODULE_ERR_QUALIFICATION;
    }
    rictus_intelligence_copy(comparative_item.source, sizeof(comparative_item.source),
        "Drupal Core Security Advisories");
    rictus_intelligence_copy(comparative_item.title, sizeof(comparative_item.title),
        "Drupal core security advisory - access control vulnerability");
    rictus_intelligence_copy(comparative_item.summary, sizeof(comparative_item.summary),
        "A security vulnerability affects authenticated file upload authorization.");
    rictus_intelligence_copy(comparative_item.url, sizeof(comparative_item.url),
        "https://www.drupal.org/security/example");


#define RICTUS_TEST(CONDITION) \
    do \
    { \
        ++executed; \
        if (CONDITION) \
        { \
            ++passed; \
        } \
        else \
        { \
            ++failed; \
        } \
    } \
    while (0)


    RICTUS_TEST(
        strcmp(
            rictus_intelligence_descriptor.id,
            RICTUS_INTELLIGENCE_ID
        ) == 0
    );


    RICTUS_TEST(
        strcmp(
            rictus_intelligence_descriptor.name,
            RICTUS_INTELLIGENCE_NAME
        ) == 0
    );


    RICTUS_TEST(
        rictus_intelligence_descriptor.version_major ==
        RICTUS_INTELLIGENCE_VERSION_MAJOR &&
        rictus_intelligence_descriptor.version_minor ==
        RICTUS_INTELLIGENCE_VERSION_MINOR &&
        rictus_intelligence_descriptor.version_patch ==
        RICTUS_INTELLIGENCE_VERSION_PATCH
    );


    RICTUS_TEST(
        rictus_intelligence_descriptor
        .required_core_api_major ==
        RICTUS_MODULE_API_MAJOR &&
        rictus_intelligence_descriptor
        .required_core_api_minor <=
        RICTUS_MODULE_API_MINOR
    );


    RICTUS_TEST(
        rictus_intelligence_descriptor.qualify ==
        rictus_intelligence_qualify &&
        rictus_intelligence_descriptor.start ==
        rictus_intelligence_start &&
        rictus_intelligence_descriptor.stop ==
        rictus_intelligence_stop
    );


    RICTUS_TEST(
        rictus_intelligence_source_from_name(
            "NASA"
        ) ==
        RICTUS_INTELLIGENCE_SOURCE_NASA &&
        rictus_intelligence_source_class(
            RICTUS_INTELLIGENCE_SOURCE_NASA
        ) ==
        RICTUS_INTELLIGENCE_SOURCE_PRIMARY
    );


    RICTUS_TEST(
        rictus_intelligence_source_from_name(
            "SpaceX"
        ) ==
        RICTUS_INTELLIGENCE_SOURCE_SPACEX &&
        rictus_intelligence_source_class(
            RICTUS_INTELLIGENCE_SOURCE_SPACEX
        ) ==
        RICTUS_INTELLIGENCE_SOURCE_PRIMARY
    );


    RICTUS_TEST(
        rictus_intelligence_source_from_name(
            "Unknown Source"
        ) ==
        RICTUS_INTELLIGENCE_SOURCE_OTHER
    );

    RICTUS_TEST(
        rictus_intelligence_source_count() == 13
    );

    RICTUS_TEST(
        rictus_intelligence_source_find("stn_labz_threats") != NULL &&
        strcmp(rictus_intelligence_source_find("stn_labz_threats")->path, "/threats") == 0 &&
        rictus_intelligence_source_find("stn_labz_threats")->transport == RICTUS_INTELLIGENCE_TRANSPORT_JSON
    );

    threat_source = rictus_intelligence_source_find("stn_labz_threats");
    threat_response.body = "{\"threats\":[{\"id\":\"t_6a960e2f2f1a9\",\"ip\":\"108.178.43.142\",\"type\":\"pattern_match\",\"details\":{\"request_url\":\"\\/wp-admin\\/\",\"ip_address\":\"172.104.10.35\",\"domain\":\"stn-labz.com\"},\"created_at\":\"2026-08-31 23:28:47\"}]}";
    threat_response.body_length = strlen(threat_response.body);
    RICTUS_TEST(threat_source != NULL &&
        rictus_intelligence_parse_response(threat_source, &threat_response, threat_items) == RICTUS_INTELLIGENCE_PARSE_OK &&
        threat_items->count == 1 &&
        strstr(threat_items->items[0].summary, "Request path=/wp-admin/") != NULL &&
        strstr(threat_items->items[0].summary, "Source IP=172.104.10.35") != NULL &&
        strstr(threat_items->items[0].summary, "Reported IP=108.178.43.142") != NULL &&
        strstr(threat_items->items[0].summary, "Target=stn-labz.com") != NULL);
    RICTUS_TEST(threat_items->count == 1 &&
        rictus_intelligence_warning_evaluate(&threat_items->items[0], &warning) &&
        warning.severity == RICTUS_INTELLIGENCE_SEVERITY_LOW &&
        !warning.automatic_reporting_authorized);

    RICTUS_TEST(
        rictus_intelligence_source_find("php_releases") != NULL &&
        rictus_intelligence_source_find("wordpress_security") != NULL &&
        rictus_intelligence_source_find("joomla_security") != NULL &&
        rictus_intelligence_source_find("drupal_core_security") != NULL
    );

    RICTUS_TEST(
        rictus_intelligence_source_find("nginx_security") != NULL &&
        rictus_intelligence_source_find("apache_httpd_security") != NULL &&
        rictus_intelligence_source_find("mariadb_security") != NULL
    );

    RICTUS_TEST(
        rictus_intelligence_source_find("cert_cc_vulnerability_notes") != NULL &&
        rictus_intelligence_source_find("cert_cc_vulnerability_notes")->primary == 0
    );

    for (irrelevant_index = 0;
        irrelevant_index < sizeof(irrelevant_cisa_titles) / sizeof(irrelevant_cisa_titles[0]);
        ++irrelevant_index)
    {
        rictus_intelligence_relevance_result_t irrelevant_result;
        memset(&policy_item, 0, sizeof(policy_item));
        rictus_intelligence_copy(policy_item.source, sizeof(policy_item.source),
            "CISA Cybersecurity Advisories");
        rictus_intelligence_copy(policy_item.title, sizeof(policy_item.title),
            irrelevant_cisa_titles[irrelevant_index]);
        rictus_intelligence_copy(policy_item.summary, sizeof(policy_item.summary),
            "A security vulnerability has been reported and requires a software update.");
        RICTUS_TEST(rictus_intelligence_relevance_evaluate(
            &policy_item, &irrelevant_result) &&
            irrelevant_result.relevance == RICTUS_INTELLIGENCE_RELEVANCE_NONE);
    }

    memset(&policy_item, 0, sizeof(policy_item));
    rictus_intelligence_copy(policy_item.source, sizeof(policy_item.source),
        "CISA Cybersecurity Advisories");
    rictus_intelligence_copy(policy_item.title, sizeof(policy_item.title),
        "PHP runtime vulnerability added to the CISA catalog");
    rictus_intelligence_copy(policy_item.summary, sizeof(policy_item.summary),
        "The vulnerability affects PHP runtime request processing.");
    RICTUS_TEST(rictus_intelligence_relevance_evaluate(
        &policy_item, &comparative_relevance) &&
        comparative_relevance.relevance == RICTUS_INTELLIGENCE_RELEVANCE_RELEVANT);

    RICTUS_TEST(
        rictus_intelligence_relevance_evaluate(
            &comparative_item, &comparative_relevance) &&
        comparative_relevance.relevance == RICTUS_INTELLIGENCE_RELEVANCE_RELEVANT
    );

    rictus_intelligence_develop_item(
        &comparative_item, &comparative_relevance, &developed_item);

    RICTUS_TEST(
        strstr(developed_item.why_stn_labz_cares,
            "does not infer that Chaos MVC is vulnerable") != NULL &&
        strstr(developed_item.assessment,
            "No evidence in this INT establishes") != NULL
    );

    RICTUS_TEST(
        rictus_intelligence_format_notification(
            notification, sizeof(notification), "INT-12345678", &developed_item) &&
        strstr(notification, "SOURCE: https://www.drupal.org/security/example") != NULL &&
        strstr(notification, "PM: !show INT-12345678") != NULL &&
        strlen(notification) < RICTUS_INTELLIGENCE_IRC_MESSAGE_MAX
    );

    rictus_intelligence_copy(policy_item.source,sizeof(policy_item.source),"STN-LABZ Threat API");
    rictus_intelligence_copy(policy_item.summary,sizeof(policy_item.summary),"Sentinel blocked WordPress /wp-login.php probe");
    RICTUS_TEST(rictus_intelligence_warning_evaluate(&policy_item,&warning)&&warning.severity==RICTUS_INTELLIGENCE_SEVERITY_LOW&&!warning.automatic_reporting_authorized&&!warning.lifecycle_escalation_authorized);
    rictus_intelligence_copy(policy_item.content,sizeof(policy_item.content),"GET /APP/CORE/MAILER.PHP?probe=1 blocked");
    RICTUS_TEST(rictus_intelligence_warning_evaluate(&policy_item,&warning)&&warning.severity==RICTUS_INTELLIGENCE_SEVERITY_HIGH&&warning.protected_boundary_hit&&warning.handling==RICTUS_INTELLIGENCE_HANDLING_OPERATOR_PM&&warning.automatic_reporting_authorized&&!warning.lifecycle_escalation_authorized&&strcmp(warning.indicator_id,"CHAOS-CORE-MAILER")==0);
    memset(&policy_item,0,sizeof(policy_item));rictus_intelligence_copy(policy_item.source,sizeof(policy_item.source),"STN-LABZ Threat API");rictus_intelligence_copy(policy_item.evidence,sizeof(policy_item.evidence),"path=/app/core/config.php result=blocked");
    RICTUS_TEST(rictus_intelligence_warning_evaluate(&policy_item,&warning)&&warning.severity==RICTUS_INTELLIGENCE_SEVERITY_HIGH&&strcmp(warning.indicator_id,"CHAOS-CORE-CONFIG")==0&&!warning.lifecycle_escalation_authorized);
    RICTUS_TEST(rictus_intelligence_protected_boundary_count()==2U&&rictus_intelligence_protected_boundary_get(2)==NULL);
    RICTUS_TEST(rictus_intelligence_source_evaluate(&policy_item,&source_evaluation)&&source_evaluation.role==RICTUS_INTELLIGENCE_SOURCE_ROLE_SENSOR&&source_evaluation.independence==RICTUS_INTELLIGENCE_INDEPENDENCE_SAME_SENSOR_NETWORK&&source_evaluation.independent_source_count==0U);
    RICTUS_TEST(rictus_intelligence_requirement_count()==5U&&rictus_intelligence_requirement_get(0)->priority==1U&&rictus_intelligence_requirement_get(4)->human_authority_required);
    RICTUS_TEST(rictus_intelligence_information_requirement_get(0)->gap_open==0&&rictus_intelligence_information_requirement_get(1)->gap_open==1&&rictus_intelligence_information_requirement_get(5)==NULL);
    {rictus_warning_exercise_store_t exercise_store;memset(&exercise_store,0,sizeof(exercise_store));rictus_intelligence_copy(exercise_store.records[0].id,sizeof(exercise_store.records[0].id),"EXWARN-12345678");exercise_store.records[0].severity=RICTUS_EXERCISE_CRITICAL;exercise_store.count=1;RICTUS_TEST(rictus_warning_exercise_find(&exercise_store,"EXWARN-12345678")!=NULL&&rictus_warning_exercise_find(&exercise_store,"EXWARN-00000000")==NULL&&exercise_store.records[0].severity==RICTUS_EXERCISE_CRITICAL);}


    RICTUS_TEST(
        rictus_intelligence_source_from_name(
            NULL
        ) ==
        RICTUS_INTELLIGENCE_SOURCE_NONE &&
        rictus_intelligence_source_from_name(
            ""
        ) ==
        RICTUS_INTELLIGENCE_SOURCE_NONE
    );


    ++executed;


    negative_executed =
        1;


    if (
        rictus_intelligence_source_from_name(
            "NASA News"
        ) ==
        RICTUS_INTELLIGENCE_SOURCE_OTHER &&
        rictus_intelligence_source_from_name(
            "SpaceX Updates"
        ) ==
        RICTUS_INTELLIGENCE_SOURCE_OTHER
        )
    {
        negative_passed =
            1;

        ++passed;
    }
    else
    {
        ++failed;
    }


#undef RICTUS_TEST


    result->tests_executed =
        executed;

    result->tests_passed =
        passed;

    result->tests_failed =
        failed;

    result->negative_test_executed =
        negative_executed;

    result->negative_test_passed =
        negative_passed;

    free(threat_items);


    if (
        executed <
        RICTUS_MODULE_MIN_TESTS ||
        passed !=
        executed ||
        failed != 0 ||
        !negative_executed ||
        !negative_passed
        )
    {
        return
            RICTUS_MODULE_ERR_QUALIFICATION;
    }


    return
        RICTUS_MODULE_OK;
}


/*
 * ------------------------------------------------
 * DESCRIPTOR
 * ------------------------------------------------
 */

const rictus_module_descriptor_t
rictus_intelligence_descriptor =
{
    RICTUS_INTELLIGENCE_ID,

    RICTUS_INTELLIGENCE_NAME,

    RICTUS_INTELLIGENCE_VERSION_MAJOR,

    RICTUS_INTELLIGENCE_VERSION_MINOR,

    RICTUS_INTELLIGENCE_VERSION_PATCH,

    RICTUS_MODULE_API_MAJOR,

    RICTUS_MODULE_API_MINOR,

    rictus_intelligence_qualify,

    rictus_intelligence_start,

    rictus_intelligence_stop
};


/*
 * ------------------------------------------------
 * DLL ABI
 * ------------------------------------------------
 */

const rictus_module_descriptor_t*
stnlabz_module_get_descriptor(void)
{
    return
        &rictus_intelligence_descriptor;
}
