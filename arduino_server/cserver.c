#include "cserver.h"
#include "abnf.h"

// cppcheck-suppress unusedFunction
struct response handleRequest(struct stream stream) {
  return http_message(stream);
}
