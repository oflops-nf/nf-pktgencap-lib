# Process this file with autoconf to produce a configure script.
AC_CONFIG_MACRO_DIR([m4])
AC_PREREQ([2.59])
AC_INIT([netfpga-packet-generator-c-library], [0.01], [cr409@cl.cam.ac.uk])
${CFLAGS=""}
AC_PROG_CC
AM_INIT_AUTOMAKE([-Wall foreign])
# AM_PROG_AR
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AM_PROG_CC_C_O

AC_CONFIG_SRCDIR([src])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_INSTALL
AC_PROG_AWK
AC_PROG_CPP
AC_PROG_LIBTOOL

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(strings.h unistd.h)

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL

# Checks for library functions.
AC_CHECK_FUNCS([strerror])

AC_DEFUN([AC_PROG_DOXYGEN],[
          AC_PATH_PROG([DOXYGEN],[doxygen])
          if test -z "$DOXYGEN" ; then
              AC_MSG_WARN([cannot find doxygen. Will not build source documentation])
              fi
              AM_CONDITIONAL([HAVE_DOXYGEN], [test -n "$DOXYGEN"])
              ])
AC_PROG_DOXYGEN



AC_CONFIG_FILES([Makefile \
                 doc/Doxyfile\
                 src/Makefile \
                 examples/Makefile])

AC_OUTPUT()
