# The bridges demo, for the dev machine of its playground. See README.md.
include ../common.mk

.PHONY: up down

up: $(BIN)
	$(call here,setup.sh)
	@echo "The demo runs. Open the pathviz tab of the playground (port 7070 of this machine)."

# The bridges and the namespaces stay: the playground is thrown away anyway.
down:
	-@for u in pathviz pv-traffic; do sudo systemctl stop $$u 2>/dev/null; sudo systemctl reset-failed $$u 2>/dev/null; done; true
