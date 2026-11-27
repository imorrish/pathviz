# The containers demo, for the dev machine of its playground. See README.md.
#
# To run only some of the machines: make demo-containers HOSTS="docker podman"
include ../common.mk
HOSTS ?= docker podman containerd crio

.PHONY: up down $(HOSTS)

up: $(HOSTS)
	@echo "The demo runs. Open the pathviz tabs of the playground (port 7070 of every machine)."

$(HOSTS): $(BIN)
	@echo "== $@"
	$(call there,$@,$@.sh)

down:
	-@for h in $(HOSTS); do $(SSH) -nT $$h 'sudo systemctl stop pathviz' 2>/dev/null; done; true
