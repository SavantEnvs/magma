/* The OAI shared logger (common/log.c) needs the ITTI task stack, liblfds and a log thread.
 * The codecs only call log_message() through the OAILOG_* macros; drop the messages. */
#include <stdarg.h>
#include "lte/gateway/c/core/oai/common/log.h"
void log_message(log_thread_ctxt_t* const thread_ctxt, const log_level_t log_level,
                 const log_proto_t protocol, const char* const source_fileP,
                 const unsigned int line_numP, const char* format, ...) {
  (void)thread_ctxt; (void)log_level; (void)protocol; (void)source_fileP;
  (void)line_numP; (void)format;
}
void log_stream_hex(const log_level_t log_levelP, const log_proto_t protoP,
                    const char* const source_fileP, const unsigned int line_numP,
                    const char* const messageP, const char* const streamP,
                    const size_t sizeP) {
  (void)log_levelP; (void)protoP; (void)source_fileP; (void)line_numP;
  (void)messageP; (void)streamP; (void)sizeP;
}
