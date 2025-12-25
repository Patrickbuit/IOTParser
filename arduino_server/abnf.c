#include "abnf.h"
#include "token.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HTTP_TOKEN_LENGTH 255

static bool field_line(struct stream);
static bool field_name(struct stream);
static bool field_value(struct stream);
static bool http_token(struct stream);
static bool http_version(struct stream);
static bool message_body(struct stream);
static bool method(struct stream);
static bool origin_form(struct stream);
static bool request_line(struct stream);
static bool request_target(struct stream);
static bool start_line(struct stream);
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

  // ABNF for http_message is an AND construction, so early
  // exit on error

  if (!start_line(stream)) {
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
  if (!http_token(stream)) {
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

static bool http_token(struct stream stream) {

  char tmp[HTTP_TOKEN_LENGTH];

  if (!tchar(stream, tmp, HTTP_TOKEN_LENGTH)) {

    return false;
  }

  while (tchar(stream, tmp, HTTP_TOKEN_LENGTH)) {
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

static bool method(struct stream stream) {

  // //Peek first letter. Depending on that, choose how to
  // parse. char firstChar = stream.peek();

  // switch(firstChar) {
  //   case 'G':

  //     const char* expectedMethod = "GET";
  //     char nullTerminatedChar[2];

  //     for(int i = 0; expectedMethod[i]; i++) {
  //       nullTerminatedChar[0] = expectedMethod[i];
  //       nullTerminatedChar[1] = "\0";
  //       if(!hasTokenValue(readToken(stream), ALPHA,
  //       nullTerminatedChar)) {
  //         return false;
  //       }
  //     }

  //   return true;

  //   case 'P':

  //   break;

  //   case 'D':

  //   break;

  //}

  return http_token(stream);
}

static bool request_line(struct stream stream) {

  if (!method(stream)) {
#ifndef NDEBUG
    printf("no valid method found in request line \n");
#endif
    return false;
  }

  if (!readTokenType(stream, SP)) {
#ifndef NDEBUG
    printf("no valid SP found in request line \n");
#endif
    return false;
  };

  if (!request_target(stream)) {

#ifndef NDEBUG
    printf(
        "no valid request target found in request line \n");
#endif

    return false;
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

  if (!origin_form(stream)) {
    return false;
  };

#ifndef NDEBUG
  printf("request_target ok! \n");
#endif
  return true;
}

static bool origin_form(struct stream stream) {

  // first character has to be //
  if (!readTokenValue(stream, VCHAR, "/")) {
    return false;
  }

  // Optional arguments
  if (http_token(stream)) {
    origin_form(stream);
  }

  return true;
}

static bool start_line(struct stream stream) {
  return request_line(stream);
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

void catValue(const char* value, char result[],
              size_t len) {
  if (len == 0) {
    return;
  }
  strncat(result, value, len - strlen(result) - 1);
}