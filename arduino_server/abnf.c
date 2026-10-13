#include "abnf.h"
#include "request.h"
#include "token.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HTTP_TOKEN_LENGTH 255

static bool field_line(struct stream);
static bool field_name(struct stream);
static bool field_value(struct stream);
static bool http_token(struct stream stream, char* token, size_t max_token_length);
static bool http_version(struct stream);
static bool message_body(struct stream);
enum method method(struct stream);
static bool origin_form(struct stream, char* token, size_t max_token_size);
bool request_line(struct stream, struct request_line* line);
static bool request_target(struct stream);
static bool start_line(struct stream, struct request_line* line);
static bool tchar(struct stream, char[], size_t);

static bool readTokenType(struct stream, enum tokentype);
static bool readTokenValue(struct stream, enum tokentype,
                           const char*);
// catValue is not static to allow for an informative test
void catValue(const char*, char[], size_t);

bool http_message(struct stream stream) {
#ifndef NDEBUG
  printf("starting http_message scan \n");
#endif
  initTokenizer();

  struct request_line line;
  if (!start_line(stream, &line)) {
    #ifndef NDEBUG
    printf("no valid start line found\n");
    #endif
    return false;
  }

  if (!readTokenType(stream, CRLF)) {
#ifndef NDEBUG
    printf("no valid CRLF found \n");
#endif
    return false;
  }

  while (field_line(stream) &&
         readTokenType(stream, CRLF)) {
    ;
  }

  if (!readTokenType(stream, CRLF)) {
    return false;
  }

  if (message_body(stream)) {
    ;
  }

  return true;
}

// remaining ABFN functions are stubs

static bool field_line(struct stream stream) {

  if (!field_name(stream)) {
    return false;
  }

  if (!readTokenValue(stream, VCHAR, ":")) {
    return false;
  }

  while (hasTokenType(peekToken(stream), SP)) {
    readToken(stream);
  }

  if (!field_value(stream)) {
    return false;
  }

  while (hasTokenType(peekToken(stream), SP)) {
    readToken(stream);
  }

  return false;
}

static bool field_name(struct stream stream) {
  char field_token[HTTP_TOKEN_LENGTH];

  if (!http_token(stream, field_token, sizeof(field_token))) {
    return false;
  }
  return true;
}

static bool field_value(struct stream stream) {
  if (!readTokenType(stream, VCHAR)) {
    return false;
  }

  while (readTokenType(stream, SP) ||
         readTokenType(stream, HTAB) ||
         readTokenType(stream, VCHAR)) {
    ;
  }

  return false;
}

static bool http_token(struct stream stream, char* token, size_t max_token_length) {

  if (!tchar(stream, token, max_token_length)) {
    return false;
  }

  while (tchar(stream, token, max_token_length)) {
  }
  return true;
}

static bool http_version(struct stream stream) {

  if (!readTokenValue(stream, ALPHA, "H")) {
    return false;
  }

  if (!readTokenValue(stream, ALPHA, "T")) {
    return false;
  }

  if (!readTokenValue(stream, ALPHA, "T")) {
    return false;
  }

  if (!readTokenValue(stream, ALPHA, "P")) {
    return false;
  }

  if (!readTokenValue(stream, VCHAR, "/")) {
    return false;
  }

  if (!readTokenType(stream, DIGIT)) {
    return false;
  }

  if (!readTokenValue(stream, VCHAR, ".")) {
    return false;
  }

  if (!readTokenType(stream, DIGIT)) {
    return false;
  }

#ifndef NDEBUG
  printf("reached end of http_version function. returning "
         "true\n");
#endif

  return true;
}

static bool message_body(struct stream stream) {

  while (readTokenType(stream, OCTET)) {
    ;
  }

  return true;
}

enum method method(struct stream stream) {

  //initialiseren met null termination voor de zekerheid.
    char method_token[HTTP_TOKEN_LENGTH];
    method_token[0] = '\0';

    if (!http_token(stream, method_token, sizeof(method_token))) {
        return METHOD_UNRECOGNIZED;
    }

    if (strcmp(method_token, "GET") == 0) {
        return METHOD_GET;
    }

    if (strcmp(method_token, "POST") == 0) {
        return METHOD_POST;
    }

    if (strcmp(method_token, "PUT") == 0) {
        return METHOD_PUT;
    }

    if (strcmp(method_token, "DELETE") == 0) {
        return METHOD_DELETE;
    }

    return METHOD_UNRECOGNIZED;
}

bool request_line(struct stream stream, struct request_line* line) {

  enum method line_method;
  if(method(stream) == METHOD_UNRECOGNIZED) {
    #ifndef NDEBUG
    printf("no valid method found in request line \n");
    #endif
    return false;
  }

  else {
    line->method = line_method;
  }

  if (!readTokenType(stream, SP)) {
    #ifndef NDEBUG
    printf("no valid SP found in request line \n");
    #endif
    return false;
  };

  enum target line_target[3];
  if (request_target(stream) == TARGET_UNRECOGNIZED) {
    #ifndef NDEBUG
    printf("no valid request target found in request line \n");
    #endif
    return false;
  }

  else {
    if(sizeof(line->target) == 3) {
    line->target[0] = line_target[0];
    line->target[1] = line_target[1];
    line->target[2] = line_target[2];
    }
  }

  if (!readTokenType(stream, SP)) {

  #ifndef NDEBUG
    printf("no valid SP 2 found in request line \n");
  #endif
  return false;
  };

  if (!http_version(stream)) {
  #ifndef NDEBUG
      printf(
          "no valid http version found in request line \n");
  #endif
  return false;
  }

  #ifndef NDEBUG
    printf("request line ok! \n");
  #endif
  return true;
}

static bool request_target(struct stream stream) {
  char target_token[HTTP_TOKEN_LENGTH];

  if (!origin_form(stream, target_token, sizeof(target_token))) {
    return false;
  };

#ifndef NDEBUG
  printf("request_target ok! \n");
#endif
  return true;
}

static bool origin_form(struct stream stream, char* token, size_t max_token_size) {

  // first character has to be /
  if (!readTokenValue(stream, VCHAR, "/")) {
    return false;
  }

  // Optional arguments
  if (http_token(stream, token, max_token_size)) {
    origin_form(stream, token, max_token_size);
  }

  return true;
}

static bool start_line(struct stream stream, struct request_line* line) {
  return request_line(stream, line);
}

static bool tchar(struct stream stream, char result[],
                  size_t len) {
  struct token next = peekToken(stream);

  if (next.type == DIGIT) {
    next = readToken(stream);
    catValue(next.value, result, len);
    return true;
  }

  if (next.type == ALPHA) {
    next = readToken(stream);
    catValue(next.value, result, len);
    return true;
  }

  if (next.type == VCHAR) {
    switch (next.value[0]) {
    case '!': // falls through on purpose
    case '#':
    case '$':
    case '%':
    case '&':
    case '\'':
    case '*':
    case '+':
    case '-':
    case '.':
    case '^':
    case '`':
    case '|':
    case '~':
      next = readToken(stream);
      catValue(next.value, result, len);
      return true;
    }
  }

  return false;
}

static bool readTokenType(struct stream stream,
                          enum tokentype type) {
  struct token next = peekToken(stream);

  if (!hasTokenType(next, type)) {
    return false;
  }

  readToken(stream);
  return true;
}

static bool readTokenValue(struct stream stream,
                           enum tokentype type,
                           const char* value) {
  struct token next = peekToken(stream);

  if (!hasTokenValue(next, type, value)) {
    return false;
  }

  readToken(stream);
  return true;
}

//Dit zorgt gelukkig voor null termination, dus daar hoef ik niet over na te denken.
void catValue(const char* value, char result[],
              size_t len) {
  if (len == 0) {
    return;
  }
  strncat(result, value, len - strlen(result) - 1);
}