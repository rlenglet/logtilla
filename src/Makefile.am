# Copyright 2009 Google Inc.
# Author: Romain Lenglet <romain.lenglet@laposte.net>
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

erlasn1srcdir = $(ERLANG_INSTALL_LIB_DIR_logtilla)/src
dist_erlasn1src_DATA = logtilla_test.erl
nodist_erlasn1src_DATA = CommonLog.erl

erlasn1incdir = $(ERLANG_INSTALL_LIB_DIR_logtilla)/include
nodist_erlasn1inc_DATA = ../asn1/CommonLog.asn1 CommonLog.hrl CommonLog.asn1db

erlasn1beamdir = $(ERLANG_INSTALL_LIB_DIR_logtilla)/ebin
nodist_erlasn1beam_DATA = logtilla_test.beam CommonLog.beam CommonLog.asn1db

logtilla_test.beam: CommonLog.hrl

CLEANFILES = $(erlbeam_DATA) CommonLog.erl CommonLog.beam CommonLog.hrl \
  CommonLog.asn1db

.erl.beam:
	$(ERLC) $(ERLCFLAGS) -b beam $<

CommonLog.erl CommonLog.beam CommonLog.hrl CommonLog.asn1db: ../asn1/CommonLog.asn1
	$(ERLC) $(ERLCFLAGS) -b ber_bin +der +optimize +driver $<

SUFFIXES = .erl .asn1 .beam .hrl .asn1db
