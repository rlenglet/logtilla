// Copyright 2009 Google Inc.
// Author: Romain Lenglet <romain.lenglet@laposte.net>
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// A program that parses web access log files in the Common Log
// Format, produces an abstract representation of each entry in ASN.1,
// and outputs those entries encoded using the BER on its standard
// output.

#include <regex.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "LogEntry.h"

typedef struct {
  regex_t common_log_entry_regex;
  regex_t ip_address_regex;
} parser_state_t;

#define COMMON_LOG_ENTRY_REGEX "\\([^ ]\\+\\) \\(-\\|\"[^ ]*\"\\) \\(-\\|\"[^ ]*\"\\) \\[\\([0-9]\\{2\\}\\)/\\([A-Za-z]\\{3\\}\\)/\\([0-9]\\{4\\}\\):\\([0-9]\\{2\\}\\):\\([0-9]\\{2\\}\\):\\([0-9]\\{2\\}\\) \\([+-][0-9]\\{4\\}\\)\\] \"\\([^\"]*\\)\" \\([0-9]\\+\\) \\(-\\|[0-9]\\+\\)"

#define IP_ADDRESS_REGEX "\\([0-9]\\{1,3\\}\\)\\.\\([0-9]\\{1,3\\}\\)\\.\\([0-9]\\{1,3\\}\\)\\.\\([0-9]\\{1,3\\}\\)"

static char* MONTHS[12][2] = {
  {"Jan", "01"},
  {"Feb", "02"},
  {"Mar", "03"},
  {"Apr", "04"},
  {"May", "05"},
  {"Jun", "06"},
  {"Jul", "07"},
  {"Aug", "08"},
  {"Sep", "09"},
  {"Oct", "10"},
  {"Nov", "11"},
  {"Dec", "12"}
};

int init_parser_state(parser_state_t *parser_state) {

  if (regcomp(&parser_state->common_log_entry_regex,
	      COMMON_LOG_ENTRY_REGEX, 0)) {
    return 1;
  }

  if (regcomp(&parser_state->ip_address_regex, IP_ADDRESS_REGEX, 0)) {
    return 1;
  }

  return 0;
}

// TODO(Romain): Add a function to call
// regfree(&common_log_entry_regex) etc.

int parse_network_address(parser_state_t *parser_state, char *start_ptr,
			  char *end_ptr, NetworkAddress_t *network_address) {
  regmatch_t matched[5];
  char ip_address[4];
  char *byte_start_ptr;
  char *byte_end_ptr;
  int i;
 
  if (regexec(&parser_state->ip_address_regex, start_ptr, 5, matched, 0)) {
    // hostname
    network_address->present = NetworkAddress_PR_hostname;
    return OCTET_STRING_fromBuf(&(network_address->choice.hostname),
				start_ptr, (end_ptr-start_ptr));
  } else {
    // ip_address
    for (i = 0; i < 4; i++) {
      byte_start_ptr = &start_ptr[matched[i+1].rm_so];
      byte_end_ptr = &start_ptr[matched[i+1].rm_eo];
      ip_address[i] = strtol(byte_start_ptr, &byte_end_ptr, 10);
    }
    network_address->present = NetworkAddress_PR_ip_address;
    return OCTET_STRING_fromBuf(&(network_address->choice.ip_address),
				ip_address, 4);
  }

}

int parse_optional_name(parser_state_t *parser_state, char *start_ptr,
			char *end_ptr, UTF8String_t **name) {
  char *c;
  if (((end_ptr-start_ptr) == 1) && (*start_ptr == '-')) {
    if (*name != NULL) {
      ASN_STRUCT_FREE(asn_DEF_UTF8String, *name);
      *name = NULL;
    }
  } else {
    // Ignore surrounding double quotes:
    ++start_ptr;
    --end_ptr;
    if (*name == NULL) {
      *name = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String,
				       start_ptr, (end_ptr-start_ptr));
      if (!*name) {
	return 1;
      }
    } else {
      if (OCTET_STRING_fromBuf(*name, start_ptr, (end_ptr-start_ptr))) {
	return 1;
      }
    }
  }
  return 0;
}

int parse_time(parser_state_t *parser_state, char *line, regmatch_t *matched,
	       GeneralizedTime_t *gen_time) {
  // Optimized reimplementation of asn1c's asn_time2GT_frac.
  const unsigned int buffer_size =
    4 + 2 + 2       /* yyyymmdd */
    + 2 + 2 + 2     /* hhmmss */
    + 1 + 4         /* +hhmm */
    ;
  char *buffer = NULL;
  char *write_ptr;
  int i;

  buffer = (char*)calloc(1, buffer_size);
  if (!buffer) {
    return 1;
  }
  write_ptr = buffer;

  strncpy(write_ptr, &line[matched[2].rm_so], 4);
  write_ptr += 4;

  write_ptr[0] = '?';
  write_ptr[1] = '?';
  for (i = 0; i < 12; i++) {
    if (!strncmp(MONTHS[i][0], &line[matched[1].rm_so], 3)) {
      strncpy(write_ptr, MONTHS[i][1], 2);
    }
  }
  write_ptr += 2;

  strncpy(write_ptr, &line[matched[0].rm_so], 2);
  write_ptr += 2;

  strncpy(write_ptr, &line[matched[3].rm_so], 2);
  write_ptr += 2;

  strncpy(write_ptr, &line[matched[4].rm_so], 2);
  write_ptr += 2;

  strncpy(write_ptr, &line[matched[5].rm_so], 2);
  write_ptr += 2;

  strncpy(write_ptr, &line[matched[6].rm_so], 5);
  write_ptr += 5;

  gen_time->buf = buffer;
  gen_time->size = write_ptr - buffer;

  return 0;
}

int parse_common_log_entry(parser_state_t *parser_state, char *line,
			   LogEntry_t *log_entry) {
  int matched_count = 14;
  regmatch_t matched[matched_count];
  char *start_ptr;
  char *end_ptr;

  if (regexec(&(parser_state->common_log_entry_regex), line,
	      matched_count, matched, 0)) {
    return 1;
  }

  start_ptr = &line[matched[1].rm_so];
  end_ptr = &line[matched[1].rm_eo];
  if (parse_network_address(parser_state, start_ptr, end_ptr,
			    &(log_entry->remote_host))) {
    return 1;
  }

  start_ptr = &line[matched[2].rm_so];
  end_ptr = &line[matched[2].rm_eo];
  if (parse_optional_name(parser_state, start_ptr, end_ptr,
			  &(log_entry->client_identity))) {
    return 1;
  }

  start_ptr = &line[matched[3].rm_so];
  end_ptr = &line[matched[3].rm_eo];
  if (parse_optional_name(parser_state, start_ptr, end_ptr,
			  &(log_entry->auth_user))) {
    return 1;
  }

  parse_time(parser_state, line, &matched[4], &(log_entry->time));

  start_ptr = &line[matched[11].rm_so];
  end_ptr = &line[matched[11].rm_eo];
  if (OCTET_STRING_fromBuf(&(log_entry->request),
			   start_ptr, (end_ptr-start_ptr))) {
    return 1;
  }

  start_ptr = &line[matched[12].rm_so];
  end_ptr = &line[matched[12].rm_eo];
  log_entry->status = strtol(start_ptr, &end_ptr, 10);

  start_ptr = &line[matched[13].rm_so];
  end_ptr = &line[matched[13].rm_eo];
  if (((end_ptr-start_ptr) ==1 ) && (*start_ptr == '-')) { // "-"
    if (log_entry->length) {
      free(log_entry->length);
      log_entry->length = NULL;
    }
  } else {
    if (!log_entry->length) {
      log_entry->length = calloc(1, sizeof(long));
      if (!log_entry->length) {
	return 1;
      }
    }
    *(log_entry->length) = strtol(start_ptr, &end_ptr, 10);
  }

  return 0;
}

int parse_common_log_file(FILE *input, FILE *output) {
  char input_buffer[2048];
  parser_state_t parser_state;
  LogEntry_t *log_entry = NULL;
  char output_header_buffer[2] = {0, 0};
  char output_buffer[2048];
  asn_enc_rval_t enc_ret;

  if (init_parser_state(&parser_state)) {
    return 1;
  }

  log_entry = (LogEntry_t*) calloc(1, sizeof(LogEntry_t));
  if (!log_entry) {
    goto error;
  }

  input_buffer[0] = '\0';
  while (!feof(input)) {
    fgets(input_buffer, 2048, input);

    if (parse_common_log_entry(&parser_state, input_buffer, log_entry)) {
      goto error;
    }

    // Encode the log entry using BER and write it out:
    enc_ret = der_encode_to_buffer(&asn_DEF_LogEntry, log_entry,
				   output_buffer, 2048);
    if (enc_ret.encoded == -1) {
      goto error;
    }

    // Write out the size of the packet:
    output_header_buffer[0] = (enc_ret.encoded >> 8) & 0xff;
    output_header_buffer[1] = enc_ret.encoded & 0xff;
    fwrite(output_header_buffer, 2, 1, stdout);
    // Write out the data:
    fwrite(output_buffer, enc_ret.encoded, 1, output);

    // For debugging, replace the BER encoding above with:
    //xer_fprint(stdout, &asn_DEF_LogEntry, log_entry);
  }

  fflush(output);
  return 0;
	
 error:
  fflush(output);
  if (log_entry) {
    ASN_STRUCT_FREE(asn_DEF_LogEntry, log_entry);
  }
  return 1;
}

int main (int argc, char **argv) {
  FILE *input = NULL;
  FILE *output = stdout;

  // TODO(Romain): Get the path from a command given from Erlang on stdin.
  input = fopen("/tmp/access.log", "r");
  if (!input) {
    perror("cannot open log file");
    exit(1);
  }

  return parse_common_log_file(input, output);

  return 0;
}
