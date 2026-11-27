# Shared by the demo scripts: a Makefile puts it in front of each of them.
# Not for running on its own.
set -eu

# start_pathviz starts PathViz as a systemd unit, with the flags it is given.
# In a playground, the pathviz tab opens the UI from outside and without the
# access token, and only the playground's owner can reach it. PATHVIZ_FLAGS
# replaces --dangerously-skip-token, e.g. with --token-file <path>.
start_pathviz() {
	stop_units pathviz
	# shellcheck disable=SC2086
	systemd-run --quiet --unit pathviz /usr/local/bin/pathviz --listen "${PATHVIZ_LISTEN:-0.0.0.0:7070}" ${PATHVIZ_FLAGS:---dangerously-skip-token} "$@"
}

# stop_units stops the units of an earlier run of a demo.
stop_units() {
	for unit in "$@"; do
		systemctl stop "$unit" 2>/dev/null || true
		systemctl reset-failed "$unit" 2>/dev/null || true
	done
}
