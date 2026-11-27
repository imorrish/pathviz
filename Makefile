# The common targets, and one entry point per demo. Every demo lives in a
# folder of its own under demos/, with a README, a playground file, and a
# Makefile.
#
#   make build test            build the binary, run the checks
#   make run                   run pathviz on this machine (needs root)
#   make playground DEMO=...   start the playground of a demo and copy the
#                              sources to its dev machine (needs labctl)
#   make sync PLAYGROUND=<id>  copy the sources there again
#   make demo-<name>           run a demo: on the dev machine of its playground,
#                              or for demo-local on any Linux machine
#   make stop-<name>           stop what the demo started on this machine
#
# FLAGS are more flags for "make run". PATHVIZ_FLAGS and LISTEN go to the demos.
DEMOS := local routing bridges containers
FLAGS ?=

.PHONY: build test run playground sync $(addprefix demo-,$(DEMOS)) $(addprefix stop-,$(DEMOS))

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/pathviz .

test:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test ./...

run: build
	sudo ./bin/pathviz $(FLAGS)

playground:
	./demos/playground.sh start $(DEMO)

sync:
	./demos/playground.sh sync $(PLAYGROUND)

$(addprefix demo-,$(DEMOS)): demo-%: build
	$(MAKE) -C demos/$* up

$(addprefix stop-,$(DEMOS)): stop-%:
	$(MAKE) -C demos/$* down
