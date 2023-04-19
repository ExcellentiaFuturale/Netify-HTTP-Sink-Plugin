# Netify HTTP POST Sink Plugin RPM Automake File
# Copyright (C) 2023 eGloo Incorporated

RPMFILES = netify-sink-post.spec
RPMFILES_IN = netify-sink-post.spec.in

BUILT_SOURCES = $(RPMFILES)
CLEANFILES = $(RPMFILES)
EXTRA_DIST = $(RPMFILES_IN)

%: %.in
	$(SED) \
		-e 's|[@]PACKAGE_BUGREPORT@|$(PACKAGE_BUGREPORT)|g' \
		-e 's|[@]PACKAGE_NAME@|$(PACKAGE_NAME)|g' \
		-e 's|[@]PACKAGE_TARNAME@|$(PACKAGE_TARNAME)|g' \
		-e 's|[@]PACKAGE_VERSION@|$(PACKAGE_VERSION)|g' \
		-e 's|[@]NETIFY_MINVER@|$(NETIFY_MINVER)|g' \
		< "$<" > "$@"
