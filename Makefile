PROJECT_ROOT ?= $(shell git rev-parse --show-toplevel)

include ${PROJECT_ROOT}/.makefiles/Makefile
include ${PROJECT_ROOT}/.makefiles/Makefile.code
ifneq ("$(wildcard ${PROJECT_ROOT}/Dockerfile)","")
  include ${PROJECT_ROOT}/.makefiles/Makefile.docker
endif
