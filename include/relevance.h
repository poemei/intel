#ifndef RICTUS_INTELLIGENCE_RELEVANCE_H
#define RICTUS_INTELLIGENCE_RELEVANCE_H
#include "item.h"
#define RICTUS_INTELLIGENCE_RELEVANCE_REASON_MAX 512
#define RICTUS_INTELLIGENCE_DOMAIN_SYSTEMS_ENGINEERING  (1u << 0)
#define RICTUS_INTELLIGENCE_DOMAIN_SOFTWARE_ENGINEERING (1u << 1)
#define RICTUS_INTELLIGENCE_DOMAIN_CYBER_SECURITY       (1u << 2)
#define RICTUS_INTELLIGENCE_DOMAIN_SPACE_DEVELOPMENT    (1u << 3)
typedef enum { RICTUS_INTELLIGENCE_RELEVANCE_NONE=0, RICTUS_INTELLIGENCE_RELEVANCE_RELEVANT } rictus_intelligence_relevance_t;
typedef struct { rictus_intelligence_relevance_t relevance; unsigned int domain_flags; char reason[RICTUS_INTELLIGENCE_RELEVANCE_REASON_MAX]; } rictus_intelligence_relevance_result_t;
/* Deterministically evaluates retained source evidence for STN-LABZ engineering relevance. */
int rictus_intelligence_relevance_evaluate(const rictus_intelligence_item_t *item, rictus_intelligence_relevance_result_t *result);
#endif
