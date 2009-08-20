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

VPATH += $(ASN1C_SKEL_DIR)
AM_CFLAGS = -I. -I$(ASN1C_SKEL_DIR)

bin_PROGRAMS = logtilla-parser
nodist_logtilla_parser_SOURCES = $(ASN1C_GENSOURCES)
logtilla_parser_SOURCES = logtilla_parser.c
logtilla_parser_LDADD = libasn1c.a

logtilla_parser.$(OBJEXT): LogEntry.h

ASN1C_GENSOURCES = LogEntry.h LogEntry.c HTTPStatusCode.h HTTPStatusCode.c \
  NetworkAddress.h NetworkAddress.c
CLEANFILES = $(ASN1C_GENSOURCES)
$(ASN1C_GENSOURCES): ../asn1/CommonLog.asn1
	$(ASN1C) -Werror -fnative-types -fno-include-deps -R $<
#	$(ASN1C) -Werror -fnative-types -fno-include-deps -gen-PER -R $<

# Build a static library from asn1c's sources.
libasn1c.a: @ASN1C_SKEL_OBJS@
	rm -f libasn1c.a
	$(AR) $(ARFLAGS) libasn1c.a $?
	$(RANLIB) libasn1c.a
CLEANFILES += libasn1c.a @ASN1C_SKEL_OBJS@
