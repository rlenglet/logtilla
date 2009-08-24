# Copyright 2009 Google Inc.
# Author: Romain Lenglet <romain.lenglet@berabera.info>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

erlsrcdir = $(ERLANG_INSTALL_LIB_DIR_logtilla)/src
dist_erlsrc_DATA = gen_log_analyzer.erl logtilla_test.erl
nodist_erlsrc_DATA = WebAccessLogParserOperations.erl WebAccessLog.erl

erlincdir = $(ERLANG_INSTALL_LIB_DIR_logtilla)/include
nodist_erlinc_DATA = ../asn1/WebAccessLogParserOperations.asn1 \
WebAccessLogParserOperations.hrl WebAccessLogParserOperations.asn1db \
../asn1/WebAccessLog.asn1 WebAccessLog.hrl WebAccessLog.asn1db 

erlbeamdir = $(ERLANG_INSTALL_LIB_DIR_logtilla)/ebin
nodist_erlbeam_DATA = gen_log_analyzer.beam logtilla_test.beam \
WebAccessLog.beam WebAccessLog.asn1db

gen_log_analyzer.beam: WebAccessLogParserOperations.hrl
logtilla_test.beam: WebAccessLog.hrl

CLEANFILES = $(nodist_erlbeam_DATA) WebAccessLogParserOperations.erl \
WebAccessLogParserOperations.beam WebAccessLogParserOperations.hrl \
WebAccessLogParserOperations.asn1db WebAccessLog.erl WebAccessLog.beam \
WebAccessLog.hrl WebAccessLog.asn1db

CLEANFILES += edoc-info erlang.png index.html modules-frame.html \
overview-summary.html packages-frame.html stylesheet.css \
gen_log_analyzer.html

.erl.beam:
	$(ERLC) $(ERLCFLAGS) -pa . -b beam $<

.erl.html:
	$(ERL) -noshell -run edoc_run files "$<"

WebAccessLogParserOperations.erl WebAccessLogParserOperations.beam \
WebAccessLogParserOperations.hrl WebAccessLogParserOperations.asn1db: \
../asn1/WebAccessLogParserOperations.asn1
	$(ERLC) $(ERLCFLAGS) -b ber_bin +der +optimize +driver $<

WebAccessLog.erl WebAccessLog.beam WebAccessLog.hrl WebAccessLog.asn1db: \
../asn1/WebAccessLog.asn1
	$(ERLC) $(ERLCFLAGS) -b ber_bin +der +optimize +driver $<

SUFFIXES = .erl .asn1 .beam .hrl .asn1db .html
