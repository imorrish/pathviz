# The local demo: everything on this machine. See README.md.
include ../common.mk
# The address of the web UI.
LISTEN ?= 127.0.0.1:7070

.PHONY: up down

up: $(BIN)
	sudo sh demo.sh start $(BIN) $(LISTEN) $(PATHVIZ_FLAGS)

down:
	sudo sh demo.sh stop
