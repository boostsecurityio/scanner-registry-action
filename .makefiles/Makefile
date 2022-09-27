#
# Makefile config
#
MAKEFLAGS       += --warn-undefined-variables
SHELL           := /usr/bin/env bash
.DEFAULT_GOAL   := help
.SHELLFLAGS     := -e -o pipefail -c
.DELETE_ON_ERROR:
.SUFFIXES:
.NOTPARALLEL:


#
# Makefile help page
#
define HELP_USAGE
	@echo Usage: make help
endef

define HELP_ERROR
@echo
	@if [ -n "$(ERROR)" ]; then \
	printf "\033[31m%s\033[0m\n" "$(ERROR)"; \
	echo; \
	exit 1; \
	fi
endef

# @echo Variables:
# @echo
# @printf "  \033[36m%-15s\033[0m %-35s %s\n" "VARNAME" "VAR DESCRIPTION" "VALUE"
define HELP_PREFIX
	@echo
	@echo Variables:
	@echo
endef

define HELP_TARGETS
	@echo
	@echo Targets:
	@echo
	@grep -hE '^[a-zA-Z_\-\.]+(.%)?:.*?## .*$$' $(MAKEFILE_LIST) | \
		sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
endef

define usage
	$(HELP_USAGE)
	$(HELP_PREFIX)
	$(HELP_TARGETS)
	$(HELP_ERROR)
endef

#
# Default variables
#
CI           ?=
CIRCLE_SHA1  ?= $(shell git rev-parse HEAD)
ERROR        ?=
PROJECT_ROOT ?= $(shell git rev-parse --show-toplevel)
PROJECT_NAME ?= scanner-registry-action

#
# Targets
#
.PHONY: .phony
.phony:

help:  ## Display usage information
help: .phony
	$(usage)
