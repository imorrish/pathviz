# Shared by the Makefiles of the demos.
#
# BIN is the pathviz binary to show ("make build" in the root of the
# repository makes it). PATHVIZ_FLAGS replaces --dangerously-skip-token, which
# the demos use in a playground (see lib.sh).
ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
BIN ?= $(ROOT)/bin/pathviz
LIB := $(ROOT)/demos/lib.sh
PATHVIZ_FLAGS ?=
SSH := ssh -o StrictHostKeyChecking=accept-new
SCP := scp -q -o StrictHostKeyChecking=accept-new

# here installs the binary on this machine and runs a demo script on it:
#   $(call here,setup.sh)
define here
	sudo install -m 0755 $(BIN) /usr/local/bin/pathviz
	cat $(LIB) $(1) | sudo PATHVIZ_FLAGS='$(PATHVIZ_FLAGS)' sh -s
endef

# there does the same on another machine of the playground:
#   $(call there,target,target.sh)
define there
	$(SCP) $(BIN) $(1):/tmp/pathviz
	$(SSH) -nT $(1) 'sudo install -m 0755 /tmp/pathviz /usr/local/bin/pathviz'
	cat $(LIB) $(2) | $(SSH) -T $(1) "sudo PATHVIZ_FLAGS='$(PATHVIZ_FLAGS)' sh -s"
endef

$(BIN):
	$(MAKE) -C $(ROOT) build
