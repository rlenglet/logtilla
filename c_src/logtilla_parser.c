// Copyright 2009 Google Inc.
// Author: Romain Lenglet <romain.lenglet@berabera.info>
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

#include "ConsumerPDU.h"
#include "SupplierPDU.h"

static FILE *LOGFILE;
#define LOG(f, a) fprintf(LOGFILE, f, a); fflush(LOGFILE)

int send_supplier_pdu(SupplierPDU_t *supplier_pdu, FILE *output, int flush) {
  char output_header_buffer[2] = {0, 0};
  char output_buffer[2048];
  asn_enc_rval_t enc_ret;

  // Encode the PDU using BER and write it out:
  enc_ret = der_encode_to_buffer(&asn_DEF_SupplierPDU, supplier_pdu,
				 output_buffer, 2048);
  if (enc_ret.encoded == -1) {
    goto error;
  }

  // Write out the size of the packet as a 16-bit integer:
  output_header_buffer[0] = (enc_ret.encoded >> 8) & 0xff;
  output_header_buffer[1] = enc_ret.encoded & 0xff;
  fwrite(output_header_buffer, 2, 1, stdout);
  // Write out the data:
  fwrite(output_buffer, enc_ret.encoded, 1, output);

  if (flush) {
    fflush(stdout);
  }
  return 0;

 error:
  fflush(stdout);
  return 1;
}

typedef struct {
  regex_t combined_log_entry_regex;
  regex_t ip_address_regex;
  // The PDU to return a LogEntry which fields are set by the parser:
  SupplierPDU_t supplier_pdu;
  // Pre-allocated optional fields in the LogEntry for the common log format:
  UTF8String_t *client_identity;
  UTF8String_t *auth_user;
  long *length;
  // Pre-allocated optional fields in the LogEntry for the combined log format:
  UTF8String_t *referrer;
  UTF8String_t *user_agent;
} parser_state_t;

/**
 * The regular expression used for parsing log entries in either the
 * common log format or the combined log format.
 */
#define COMBINED_LOG_ENTRY_REGEX "\\([^ ]\\+\\) \\(-\\|\"[^\"]*\"\\) \\(-\\|\"[^\"]*\"\\) \\[\\([0-9]\\{2\\}\\)/\\([A-Za-z]\\{3\\}\\)/\\([0-9]\\{4\\}\\):\\([0-9]\\{2\\}\\):\\([0-9]\\{2\\}\\):\\([0-9]\\{2\\}\\) \\([+-][0-9]\\{4\\}\\)\\] \"\\([^\"]*\\)\" \\([0-9]\\+\\) \\(-\\|[0-9]\\+\\) \\(\"\\([^\"]*\\)\" \"\\([^\"]*\\)\"\\)\\?"

/**
 * The regular expression used for parsing IPv4 addresses.
 */
#define IP_ADDRESS_REGEX "\\([0-9]\\{1,3\\}\\)\\.\\([0-9]\\{1,3\\}\\)\\.\\([0-9]\\{1,3\\}\\)\\.\\([0-9]\\{1,3\\}\\)"

/**
 * Maps month name 3-letter abbrevations to numbers as a 2-letter
 * strings.
 */
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

parser_state_t* alloc_parser_state() {
  parser_state_t* parser_state = NULL;
  char FIXME_BUFFER[2048];

  parser_state = (parser_state_t*)calloc(1, sizeof(parser_state_t));
  if (!parser_state) {
    goto error;
  }

  if (regcomp(&parser_state->combined_log_entry_regex,
	      COMBINED_LOG_ENTRY_REGEX, 0)) {
    goto error;
  }

  if (regcomp(&parser_state->ip_address_regex, IP_ADDRESS_REGEX, 0)) {
    goto error;
  }

  parser_state->client_identity =
    OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, NULL, -1);
  if (!parser_state->client_identity) {
    goto error;
  }

  parser_state->auth_user =
    OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, NULL, -1);
  if (!parser_state->auth_user) {
    goto error;
  }

  parser_state->length = (long*)calloc(1, sizeof(long));
  if (!parser_state->length) {
    goto error;
  }

  parser_state->referrer =
    OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, NULL, -1);
  if (!parser_state->referrer) {
    goto error;
  }

  parser_state->user_agent =
    OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String, NULL, -1);
  if (!parser_state->user_agent) {
    goto error;
  }

  return parser_state;

 error:
  if (parser_state) {
    regfree(&parser_state->combined_log_entry_regex);
    regfree(&parser_state->ip_address_regex);
    if (parser_state->client_identity) {
      free(parser_state->client_identity);
    }
    if (parser_state->auth_user) {
      free(parser_state->auth_user);
    }
    if (parser_state->length) {
      free(parser_state->length);
    }
    if (parser_state->referrer) {
      free(parser_state->referrer);
    }
    if (parser_state->user_agent) {
      free(parser_state->user_agent);
    }
    free(parser_state);
    return NULL;
  }
    
}

void free_parser_state(parser_state_t *parser_state) {
  LogEntry_t *log_entry =
    &parser_state->supplier_pdu.choice.return_log_entry.argument;
  regfree(&parser_state->combined_log_entry_regex);
  regfree(&parser_state->ip_address_regex);
  log_entry->client_identity = parser_state->client_identity;
  log_entry->auth_user = parser_state->auth_user;
  log_entry->length = parser_state->length;
  log_entry->referrer = parser_state->referrer;
  log_entry->user_agent = parser_state->user_agent;
  ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_LogEntry, log_entry);
  free(parser_state);
}

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
			char *end_ptr, UTF8String_t **name,
			UTF8String_t *preallocated_string, int strip_quotes) {
  char *c;
  if (((end_ptr-start_ptr) == 1) && (*start_ptr == '-')) {    
    // Don't worry about free()ing the pointer, since it is always referrenced
    // preallocated_string or NULL:
    *name = NULL;
  } else {
    if (strip_quotes) {
      // Ignore surrounding double quotes:
      ++start_ptr;
      --end_ptr;
    }
    // Don't worry about free()ing the pointer, since it is always referrenced
    // preallocated_string or NULL:
    *name = preallocated_string;
    if (OCTET_STRING_fromBuf(*name, start_ptr, (end_ptr-start_ptr))) {
      return 1;
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

int parse_log_entry(parser_state_t *parser_state, char *line) {
  LogEntry_t *log_entry =
    &parser_state->supplier_pdu.choice.return_log_entry.argument;
  int matched_count = 17;
  regmatch_t matched[matched_count];
  char *start_ptr;
  char *end_ptr;

  if (regexec(&(parser_state->combined_log_entry_regex), line,
	      matched_count, matched, 0)) {
    return 1;
  }

  // Parse the fields that are defined both in the common log format
  // and the combined format:

  start_ptr = &line[matched[1].rm_so];
  end_ptr = &line[matched[1].rm_eo];
  if (parse_network_address(parser_state, start_ptr, end_ptr,
			    &(log_entry->remote_host))) {
    return 1;
  }

  start_ptr = &line[matched[2].rm_so];
  end_ptr = &line[matched[2].rm_eo];
  if (parse_optional_name(parser_state, start_ptr, end_ptr,
			  &(log_entry->client_identity),
			  parser_state->client_identity, 1)) {
    return 1;
  }

  start_ptr = &line[matched[3].rm_so];
  end_ptr = &line[matched[3].rm_eo];
  if (parse_optional_name(parser_state, start_ptr, end_ptr,
			  &(log_entry->auth_user),
			  parser_state->auth_user, 1)) {
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
    // Don't worry about free()ing the pointer, since it is always referrenced
    // in parser_state->length, or NULL:
    log_entry->length = NULL;
  } else {
    log_entry->length = parser_state->length;
    *(log_entry->length) = strtol(start_ptr, &end_ptr, 10);
  }

  // Parse the fields that are defined only in the combined log format:

  if (matched[14].rm_so != -1) {

    start_ptr = &line[matched[15].rm_so];
    end_ptr = &line[matched[15].rm_eo];
    if (parse_optional_name(parser_state, start_ptr, end_ptr,
			    &(log_entry->referrer),
			    parser_state->referrer, 0)) {
      return 1;
    }

    start_ptr = &line[matched[16].rm_so];
    end_ptr = &line[matched[16].rm_eo];
    if (parse_optional_name(parser_state, start_ptr, end_ptr,
			    &(log_entry->user_agent),
			    parser_state->user_agent, 0)) {
      return 1;
    }

  }

  return 0;
}

int parse_log_file(long invoke_id, FILE *input, FILE *output) {
  char input_buffer[2048];
  parser_state_t* parser_state;
  ReturnLogEntry_t *return_log_entry;

  parser_state = alloc_parser_state();
  if (!parser_state) {
    perror("unable to initialize parser");
    return 1;
  }

  // First send back a sequence of ReturnLogEntry PDUs:
  parser_state->supplier_pdu.present = SupplierPDU_PR_return_log_entry;
  return_log_entry = &parser_state->supplier_pdu.choice.return_log_entry;
  return_log_entry->linked_id = invoke_id;

  input_buffer[0] = '\0';
  while (!feof(input) && !ferror(input)) {
    fgets(input_buffer, 2048, input);

    if (parse_log_entry(parser_state, input_buffer)) {
      goto error;
    }

    if (send_supplier_pdu(&parser_state->supplier_pdu, output, 0)) {
      goto error;
    }

    // For debugging, replace the BER encoding above with:
    //xer_fprint(stdout, &asn_DEF_SupplierPDU, &parser_state->supplier_pdu);
  }

  // Notify the end of file by sending back an EndOfFile PDU:
  parser_state->supplier_pdu.present = SupplierPDU_PR_end_of_file;
  parser_state->supplier_pdu.choice.end_of_file.invoke_id = invoke_id;

  if (send_supplier_pdu(&parser_state->supplier_pdu, output, 1)) {
    goto error;
  }


  free_parser_state(parser_state);
  return 0;
	
 error:
  if (parser_state) {
    free_parser_state(parser_state);
  }
  return 1;
}

int handle_parse_log_file(ParseLogFile_t *parse_log_file_req, FILE *op_output) {
  UTF8String_t *filename_utf8;
  char *filename;
  FILE *input;

  // We assume that the filesystem accepts UTF-8-encoded filenames:
  filename_utf8 = &parse_log_file_req->argument;
  filename = malloc(filename_utf8->size + 1);
  if (!filename) {
    return 1;
  }
  memcpy(filename, filename_utf8->buf, filename_utf8->size);
  filename[filename_utf8->size] = '\0';

  input = fopen(filename, "r");
  if (input) {
    if (parse_log_file(parse_log_file_req->invoke_id, input, op_output)) {
      goto error;
    }
  } else {
    // Send back a CannotOpenFile PDU:
    SupplierPDU_t supplier_pdu;
    supplier_pdu.present = SupplierPDU_PR_cannot_open_file;
    supplier_pdu.choice.cannot_open_file.invoke_id =
      parse_log_file_req->invoke_id;

    if (send_supplier_pdu(&supplier_pdu, op_output, 1)) {
      goto error;
    }
  }
  
  free(filename);
  return 0;

 error:
  free(filename);
  return 1;
}

int handle_requests(FILE *op_input, FILE *op_output) {
  int pdu_size;
  int bytes_to_read;
  int bytes_read;
  char input_buffer[4096];
  char *input_ptr;
  asn_dec_rval_t rval;
  ConsumerPDU_t *pdu;

  while (!feof(op_input) && !ferror(op_input)) {


    LOG("handle_requests: %s\n", "before reading PDU");

    // Each PDU is prefixed with its size as a 16-bit integer. First
    // read the size:
    if (fread(input_buffer, 2, 1, op_input) == 1) {
      pdu_size = ((unsigned char)input_buffer[0] << 8) | input_buffer[1];
      LOG("handle_request: PDU size: %d\n", pdu_size);
      if (pdu_size > 4096) {
	LOG("handle_request: ERROR %s\n", "PDU size > 4096");
	return 1;
      }

      // Then, read the PDU:
      bytes_to_read = pdu_size;
      input_ptr = input_buffer;
      while (!feof(op_input) && !ferror(op_input) && (bytes_to_read > 0)) {
	bytes_read = fread(input_ptr, 1, pdu_size, op_input);
	LOG("handle_request: read %d bytes\n", bytes_read);
	input_ptr += bytes_read;
	bytes_to_read -= bytes_read;
      }
      if (bytes_to_read == 0) {
	// Decode the PDU:
	pdu = NULL;
	rval = ber_decode(NULL, &asn_DEF_ConsumerPDU, (void**)&pdu,
			  input_buffer, pdu_size);
	if (rval.code == RC_OK) {
	  LOG("handle_request: %s\n", "PDU decoded");
	  LOG("handle_request: present: %d\n", pdu->present);
	  if (pdu->present == ConsumerPDU_PR_parse_log_file) {
	    LOG("handle_request: %s\n", "PDU is of type ParseLogFile");
	    if (handle_parse_log_file(&pdu->choice.parse_log_file, op_output)) {
	      LOG("handle_request: ERROR %s\n", "handle_parse_log_file failed");
	      return 1;
	    }
	  } else {
	    LOG("handle_request: ERROR %s\n",
		"PDU is not of type ParseLogFile");
	    return 1;
	  }
	  ASN_STRUCT_FREE(asn_DEF_ConsumerPDU, pdu);
        } else {
	  LOG("handle_request: ERROR %s\n", "PDU not decoded");
	  ASN_STRUCT_FREE(asn_DEF_ConsumerPDU, pdu);
	  return 1;
	}
      }
    }
  }
  if (ferror(op_input)) {
    return 1;
  }

  return 0;
}

int main (int argc, char **argv) {
  LOGFILE = fopen("/tmp/logtilla-parser.log", "w");
  return handle_requests(stdin, stdout);
}
