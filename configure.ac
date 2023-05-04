# Netify Agent HTTP POST Sink Plugin

AC_PREREQ([2.63])
AC_INIT([Netify Agent HTTP Sink Plugin], [1.0.0],
    [https://gitlab.com/netify.ai/private/netify-sink-post/issues],
    [netify-sink-post], [http://www.netify.ai/])
AM_INIT_AUTOMAKE([1.9 tar-pax])
AC_CONFIG_SRCDIR([src/nsp-plugin.cpp])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_USE_SYSTEM_EXTENSIONS

# Set the minimum Agent version this plugin requires.
# When updating this version, remember to update .gitlab-ci.yml too.
NETIFY_MINVER=4.5.7
AC_SUBST([NETIFY_MINVER], [$NETIFY_MINVER])

# Checks for programs.
AC_PROG_CXX
AC_PROG_INSTALL
AM_PROG_LIBTOOL
PKG_PROG_PKG_CONFIG([0.23])
AX_PKG_INSTALLDIR

# Check compiler flags (gnu++11)
AX_CXX_COMPILE_STDCXX_11([ext], [optional])
AS_IF([test "$HAVE_CXX11" = "0"], [AX_CXX_COMPILE_STDCXX_0X])

# Checks for packages.
PKG_CHECK_MODULES([LIBNETIFYD], [libnetifyd >= $NETIFY_MINVER])
PKG_CHECK_MODULES([LIBCURL], [libcurl])

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T

# Checks for libraries.

# Checks for library functions.

# Get git revision
if test -e ".git"; then :
    GIT_TAG=`git log -1 --format=%h`
    GIT_DATE=`git log -1 --format=%cd`
    GIT_DATE_ISO8601=`git log -1 --format=%ci`

    GIT_LAST_COMMIT_HASH=`git log -1 --format=%H`
    GIT_LAST_COMMIT_DATE=`date -d "${GIT_DATE_ISO8601}" '+%F'`

    AC_SUBST([GIT_LAST_COMMIT_HASH], [$GIT_LAST_COMMIT_HASH])
    AC_SUBST([GIT_LAST_COMMIT_DATE], [$GIT_LAST_COMMIT_DATE])

    # On CentOS 6 `git rev-list HEAD --count` does not work
    GIT_NUM=`git log --pretty=oneline | wc -l | tr -d '[[:space:]]'`
    GIT_BRANCH=`git rev-parse --abbrev-ref HEAD`
    GIT_RELEASE="${PACKAGE_VERSION}-${GIT_BRANCH}-${GIT_NUM}-${GIT_TAG}"
else
    GIT_RELEASE="${PACKAGE_VERSION}"
    GIT_DATE=`date`
fi

AC_DEFINE_UNQUOTED(GIT_RELEASE, "${GIT_RELEASE}", [GIT Release])
AC_DEFINE_UNQUOTED(GIT_DATE, "${GIT_DATE}", [Last GIT change])
AC_SUBST([GIT_SOURCE_URL], [git@gitlab.com:netify.ai/private/netify-sink-post.git])

# Output files
AC_CONFIG_FILES([Makefile src/Makefile deploy/Makefile deploy/openwrt/Makefile deploy/debian/Makefile deploy/rpm/Makefile])
AC_CONFIG_FILES([util/generate-json-include.sh], [chmod +x util/generate-json-include.sh])

AC_OUTPUT
