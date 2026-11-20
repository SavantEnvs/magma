/* Type-only stand-in for liblfds 7.1.0's public header.
 * lte/gateway/c/core/oai/common/shared_ts_log.h (pulled in by log.h, which every NAS codec
 * file includes) names liblfds stack/queue element types in struct declarations. The NAS
 * codecs never call liblfds; the shared logger that does is replaced by mayhem/log_stub.c,
 * so only the incomplete-type names are needed here. */
#pragma once
struct lfds710_stack_element { void* p; };
struct lfds710_stack_state { void* p; };
struct lfds710_queue_bmm_state { void* p; };
struct lfds710_queue_bmm_element { void* p; };
