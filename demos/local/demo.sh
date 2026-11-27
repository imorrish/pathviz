#!/bin/sh
# The local demo: everything on one Linux machine. Run it as root (the
# Makefile next to it does):
#
#   demo.sh start <pathviz binary> [address of the web UI] [more pathviz flags]
#   demo.sh stop
#
# "start" runs a web server on port 8080, a client that sends it a request
# every two seconds over the loopback interface, and PathViz, which traces the
# packets of port 8080. Every packet crosses OUTPUT and POSTROUTING on its way
# out and PREROUTING and INPUT on its way back in.
set -eu

UNITS="pathviz-local-daemon pathviz-local-web pathviz-local-send"

stop() {
	for unit in $UNITS; do
		systemctl stop "$unit" 2>/dev/null || true
		systemctl reset-failed "$unit" 2>/dev/null || true
	done
	rm -rf /tmp/pathviz-demo
}

start() {
	bin="$1"
	listen="${2:-127.0.0.1:7070}"
	# The rest of the arguments are flags for pathviz.
	shift
	[ $# -eq 0 ] || shift
	stop

	mkdir -p /tmp/pathviz-demo
	echo "Hello from the PathViz demo!" > /tmp/pathviz-demo/index.html
	systemd-run --quiet --unit pathviz-local-web python3 -m http.server 8080 --directory /tmp/pathviz-demo
	since=$(date '+%Y-%m-%d %H:%M:%S')
	systemd-run --quiet --unit pathviz-local-daemon "$bin" --listen "$listen" --port 8080 "$@"
	systemd-run --quiet --unit pathviz-local-send \
		sh -c 'while true; do curl -s -m 2 -o /dev/null http://127.0.0.1:8080/; sleep 2; done'

	# PathViz logs the address of its web UI, with the access token in it.
	# Only this start counts: an earlier one had another token.
	url=""
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		url=$(journalctl -u pathviz-local-daemon --since "$since" -o cat --no-pager 2>/dev/null | sed -n 's/.*web UI on \(http[^ ]*\).*/\1/p' | tail -n 1)
		[ -n "$url" ] && break
		sleep 0.5
	done
	if [ -z "$url" ]; then
		echo "PathViz did not start, see: journalctl -u pathviz-local-daemon" >&2
		exit 1
	fi
	echo "The demo runs. The web UI is on $url"
	echo "Stop it with: make stop-local"
}

case "${1:-}" in
start)
	[ -n "${2:-}" ] || { echo "usage: $0 start <pathviz binary> [address of the web UI] [more pathviz flags]" >&2; exit 1; }
	shift
	start "$@"
	;;
stop)
	stop
	;;
*)
	echo "usage: $0 start <pathviz binary> [address of the web UI] [more pathviz flags] | stop" >&2
	exit 1
	;;
esac
