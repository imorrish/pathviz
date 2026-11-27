#!/bin/sh
# Start the playground of a demo and copy the sources to its dev machine, or
# copy them again to a playground that runs. It needs labctl (iximiuz Labs).
#
#   playground.sh start <demo>     e.g. playground.sh start bridges
#   playground.sh sync <playground id>
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)

sync() {
	archive=$(mktemp)
	tar czf "$archive" -C "$root" --exclude=.git --exclude=bin .
	labctl cp "$archive" "$1:/tmp/pathviz-src.tgz" >/dev/null
	rm -f -- "$archive"
	labctl ssh "$1" --machine dev -- 'mkdir -p ~/pathviz && tar xzf /tmp/pathviz-src.tgz -C ~/pathviz'
	echo "The sources are in ~/pathviz on the dev machine of the playground $1."
}

case "${1:-}" in
start)
	file="$root/demos/${2:-}/playground.yaml"
	[ -f "$file" ] || { echo "no demo \"${2:-}\": pick one of $(cd "$root/demos" && ls -d -- */ | tr -d / | tr '\n' ' ')" >&2; exit 1; }
	id=$(labctl playground start flexbox -f "$file" --quiet)
	sync "$id"
	echo "Open a shell on it with: labctl ssh $id --machine dev"
	echo "Then: cd ~/pathviz && make demo-$2"
	;;
sync)
	[ -n "${2:-}" ] || { echo "usage: $0 sync <playground id>" >&2; exit 1; }
	sync "$2"
	;;
*)
	echo "usage: $0 start <demo> | sync <playground id>" >&2
	exit 1
	;;
esac
