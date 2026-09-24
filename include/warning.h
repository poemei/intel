#ifndef RICTUS_INTELLIGENCE_WARNING_H
#define RICTUS_INTELLIGENCE_WARNING_H
#include "doctrine.h"
#include "module.h"
#define RICTUS_WARNING_MAX 1024
typedef struct { char id[32],int_id[32],indicator[64],reason[512],created[32],ack_by[64]; rictus_intelligence_severity_t severity; rictus_intelligence_confidence_t confidence; int delivered,acknowledged; } rictus_warning_record_t;
typedef struct { rictus_warning_record_t records[RICTUS_WARNING_MAX]; size_t count; } rictus_warning_store_t;
int rictus_warning_load(rictus_warning_store_t *store);
int rictus_warning_create(rictus_warning_store_t *store,const char *int_id,const rictus_intelligence_warning_t *warning);
void rictus_warning_deliver(rictus_warning_store_t *store,rictus_module_send_message_fn send);
const rictus_warning_record_t *rictus_warning_find(const rictus_warning_store_t *store,const char *id);
int rictus_warning_ack(rictus_warning_store_t *store,const char *id,const char *operator_name);
#endif
