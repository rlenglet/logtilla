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

# We need working Erlang macros.
AC_PREREQ([2.60])

AC_INIT([Logtilla], [1.0],
	[romain.lenglet@laposte.net], [logtilla])
AC_CONFIG_SRCDIR([ChangeLog])

AM_INIT_AUTOMAKE([1.10])

AC_ERLANG_NEED_ERL
AC_ERLANG_NEED_ERLC
AC_ERLANG_CHECK_LIB([asn1])
AC_ERLANG_SUBST_INSTALL_LIB_SUBDIR([logtilla], [1.0])

AC_PATH_PROG([ASN1C], [asn1c], [not found])
AS_IF([test "$ASN1C" = "not found"],
      [AC_MSG_ERROR([asn1c is required and was not found])])

# Find the path to asn1c's skeleton directory.  There is no way other
# than running asn1c and check where the links it creates point at.
AC_CACHE_CHECK([for the asn1c skeleton directory],
  [my_cv_asn1c_skel_dir],
  [cat > conftest.asn1 <<ATEOF
ConfTest DEFINITIONS IMPLICIT TAGS ::=
BEGIN
Dummy ::= INTEGER
END
ATEOF
   touch conftest.out
   "$ASN1C" conftest.asn1 > conftest.out 2>&1
   my_cv_asn1c_skel_dir=`sed -n -e 's/^Symlinked \(.*\)\/INTEGER\.h\t-> INTEGER\.h$/\1/p' conftest.out`
   ASN1C_GENFILES="Makefile.am.sample `sed -n -e 's/^\(Compiled\|Generated\) \(.*\)$/ \2/p' -e 's/^Symlinked .*-> \(.*\)$/ \1/p' conftest.out`"
   rm -f conftest.asn1 conftest.out $ASN1C_GENFILES])
AC_SUBST([ASN1C_SKEL_DIR], [$my_cv_asn1c_skel_dir])

# For no good reason, asn1c is not installed as a static library, so
# c_src/Makefile creates a libasn1c.a library. Find the list of object
# files to generate and include in libasn1c.a.
AC_SUBST([ASN1C_SKEL_OBJS],
         [`cd "$ASN1C_SKEL_DIR" ; ls *.c | grep -v 'converter-sample.c' | sed -e 's/\.c$/\.o /' | tr -d '\r\n'`])

AC_PROG_CC
AC_PROG_RANLIB

AC_CONFIG_FILES([
	Makefile
	asn1/Makefile
	c_src/Makefile
	src/Makefile])

AC_OUTPUT
