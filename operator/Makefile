# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../Makefile.defs

TARGETS := cilium-operator cilium-operator-generic cilium-operator-aws cilium-operator-azure

.PHONY: all $(TARGETS) clean install

all: $(TARGETS)

cilium-operator: OPERATOR_TAGS=operator_aws,operator_azure
cilium-operator-generic: OPERATOR_TAGS=""
cilium-operator-aws: OPERATOR_TAGS=operator_aws
cilium-operator-azure: OPERATOR_TAGS=operator_azure

$(TARGETS):
	@$(ECHO_GO)
	$(QUIET)$(GO_BUILD) -tags $(OPERATOR_TAGS) -o $(@)

$(TARGET):
	@$(ECHO_GO)
	$(QUIET)$(GO_BUILD) -o $@

clean:
	@$(ECHO_CLEAN)
	$(QUIET)rm -f $(TARGETS)
	$(GO) clean $(GOCLEAN)
