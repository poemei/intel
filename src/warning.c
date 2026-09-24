#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "warning.h"

#define RECORDS "intelligence.warnings"
#define DELIVERED "intelligence.warnings.delivered"
#define ACKS "intelligence.warnings.ack"

static unsigned long hash_text(const char *s)
{
    unsigned long h = 2166136261UL;
    while (s && *s) { h ^= (unsigned char)*s++; h *= 16777619UL; }
    return h;
}

static int timestamp(char out[32])
{
    time_t now = time(NULL);
    struct tm utc;
    if (now == (time_t)-1 || gmtime_r(&now, &utc) == NULL) return 0;
    return strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", &utc) != 0;
}

static int listed(const char *path, const char *id)
{
    FILE *f = fopen(path, "r");
    char line[160];
    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (strcasecmp(line, id) == 0) { fclose(f); return 1; }
    }
    fclose(f);
    return 0;
}

const rictus_warning_record_t *rictus_warning_find(const rictus_warning_store_t *s, const char *id)
{
    size_t i;
    if (!s || !id) return NULL;
    for (i = 0; i < s->count; ++i)
        if (strcasecmp(s->records[i].id, id) == 0) return &s->records[i];
    return NULL;
}

int rictus_warning_load(rictus_warning_store_t *s)
{
    FILE *f;
    char line[1200];
    if (!s) return 0;
    memset(s, 0, sizeof(*s));
    f = fopen(RECORDS, "r");
    if (!f) return 1;
    while (s->count < RICTUS_WARNING_MAX && fgets(line, sizeof(line), f)) {
        rictus_warning_record_t *r = &s->records[s->count];
        char sev[16], conf[16];
        if (sscanf(line, "%31s\t%31s\t%15s\t%15s\t%63s\t%31s\t%511[^\r\n]",
                   r->id, r->int_id, sev, conf, r->indicator, r->created, r->reason) == 7) {
            r->severity = strcasecmp(sev, "CRITICAL") == 0 ? RICTUS_INTELLIGENCE_SEVERITY_CRITICAL : RICTUS_INTELLIGENCE_SEVERITY_HIGH;
            r->confidence = strcasecmp(conf, "HIGH") == 0 ? RICTUS_INTELLIGENCE_CONFIDENCE_HIGH : RICTUS_INTELLIGENCE_CONFIDENCE_MODERATE;
            r->delivered = listed(DELIVERED, r->id);
            r->acknowledged = listed(ACKS, r->id);
            ++s->count;
        }
    }
    fclose(f);
    return 1;
}

int rictus_warning_create(rictus_warning_store_t *s, const char *int_id, const rictus_intelligence_warning_t *w)
{
    FILE *f;
    rictus_warning_record_t *r;
    char key[128];
    if (!s || !int_id || !w || w->severity < RICTUS_INTELLIGENCE_SEVERITY_HIGH || s->count >= RICTUS_WARNING_MAX) return 0;
    snprintf(key, sizeof(key), "%s|%s|%u", int_id, w->indicator_id, (unsigned)w->severity);
    r = &s->records[s->count];
    snprintf(r->id, sizeof(r->id), "WARN-%08lX", hash_text(key));
    if (rictus_warning_find(s, r->id)) return 1;
    snprintf(r->int_id, sizeof(r->int_id), "%s", int_id);
    snprintf(r->indicator, sizeof(r->indicator), "%s", w->indicator_id);
    snprintf(r->reason, sizeof(r->reason), "%s", w->reason);
    r->severity = w->severity;
    r->confidence = w->confidence;
    if (!timestamp(r->created)) return 0;
    f = fopen(RECORDS, "a");
    if (!f) return 0;
    fprintf(f, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r->id, r->int_id,
            rictus_intelligence_severity_string(r->severity),
            r->confidence == RICTUS_INTELLIGENCE_CONFIDENCE_HIGH ? "HIGH" : "MODERATE",
            r->indicator, r->created, r->reason);
    fclose(f);
    ++s->count;
    return 1;
}

void rictus_warning_deliver(rictus_warning_store_t *s, rictus_module_send_message_fn send)
{
    size_t i;
    char message[390];
    if (!s || !send) return;
    for (i = 0; i < s->count; ++i) {
        FILE *f;
        rictus_warning_record_t *r = &s->records[i];
        if (r->delivered) continue;
        snprintf(message, sizeof(message), "PM STN_Boss :%s | %s | %s | %s | !warn show %s",
                 rictus_intelligence_severity_string(r->severity), r->id, r->indicator, r->int_id, r->id);
        if (!send(message)) return;
        if (r->severity == RICTUS_INTELLIGENCE_SEVERITY_CRITICAL) {
            snprintf(message, sizeof(message), "CRITICAL | %s | %s | ACK REQUIRED | !warn show %s", r->id, r->indicator, r->id);
            if (!send(message)) return;
        }
        f = fopen(DELIVERED, "a");
        if (!f) return;
        fprintf(f, "%s\n", r->id);
        fclose(f);
        r->delivered = 1;
    }
}

int rictus_warning_ack(rictus_warning_store_t *s, const char *id, const char *name)
{
    size_t i;
    if (!s || !id || !name) return 0;
    for (i = 0; i < s->count; ++i) {
        if (strcasecmp(s->records[i].id, id) == 0) {
            FILE *f;
            char when[32];
            if (s->records[i].acknowledged) return 1;
            if (!timestamp(when)) return 0;
            f = fopen(ACKS, "a");
            if (!f) return 0;
            fprintf(f, "%s\t%s\t%s\n", id, name, when);
            fclose(f);
            s->records[i].acknowledged = 1;
            snprintf(s->records[i].ack_by, sizeof(s->records[i].ack_by), "%s", name);
            return 1;
        }
    }
    return 0;
}
