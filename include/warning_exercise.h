#ifndef RICTUS_WARNING_EXERCISE_H
#define RICTUS_WARNING_EXERCISE_H
#include "rictus_module.h"
#define RICTUS_WARNING_EXERCISE_MAX 128
typedef enum { RICTUS_EXERCISE_HIGH=1, RICTUS_EXERCISE_CRITICAL=2 } rictus_exercise_severity_t;
typedef struct { char id[32],created[32],created_by[64],ack_by[64]; rictus_exercise_severity_t severity; int private_delivered,channel_delivered,delivered,acknowledged; } rictus_warning_exercise_t;
typedef struct { rictus_warning_exercise_t records[RICTUS_WARNING_EXERCISE_MAX]; size_t count; } rictus_warning_exercise_store_t;
int rictus_warning_exercise_load(rictus_warning_exercise_store_t *store);
int rictus_warning_exercise_create(rictus_warning_exercise_store_t *store,rictus_exercise_severity_t severity,const char *operator_name,char id[32]);
void rictus_warning_exercise_deliver(rictus_warning_exercise_store_t *store,rictus_module_send_message_fn send);
const rictus_warning_exercise_t *rictus_warning_exercise_find(const rictus_warning_exercise_store_t *store,const char *id);
int rictus_warning_exercise_ack(rictus_warning_exercise_store_t *store,const char *id,const char *operator_name);
#endif
