# Netify HTTP POST Sink Plugin Debian Package Automake File
# Copyright (C) 2023 eGloo Incorporated

DEBFILES = changelog control rules netify-sink-post.install
DEBFILES_IN = changelog.in control.in rules.in netify-sink-post.install.in

BUILT_SOURCES = $(DEBFILES)
CLEANFILES = $(DEBFILES)
EXTRA_DIST = $(DEBFILES_IN)

%: %.in
	$(SED) \
		-e 's|[@]bindir@|$(bindir)|g' \
		-e 's|[@]datadir@|$(datadir)/$(PACKAGE_TARNAME)|g' \
		-e 's|[@]includedir@|$(includedir)|g' \
		-e 's|[@]libdir@|$(libdir)|g' \
		-e 's|[@]PACKAGE_BUGREPORT@|$(PACKAGE_BUGREPORT)|g' \
		-e 's|[@]PACKAGE_NAME@|$(PACKAGE_NAME)|g' \
		-e 's|[@]PACKAGE_TARNAME@|$(PACKAGE_TARNAME)|g' \
		-e 's|[@]PACKAGE_VERSION@|$(PACKAGE_VERSION)|g' \
		-e 's|[@]sbindir@|$(sbindir)|g' \
		-e 's|[@]sysconfdir@|$(sysconfdir)|g' \
		-e 's|[@]volatilestatedir@|$(volatilestatedir)|g' \
		-e 's|[@]NETIFY_MINVER@|$(NETIFY_MINVER)|g' \
		< "$<" > "$@"