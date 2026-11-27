# The routing demo, for the dev machine of its playground. See README.md.
include ../common.mk
TARGET ?= target
TARGET_IP ?= 172.16.0.20
UNITS := pathviz-send-local pathviz-send-forward pathviz-send-dnat pathviz-send-blocked
# send starts a loop that fetches a URL every few seconds: $(call send,unit,url)
send = sudo systemd-run --quiet --unit $(1) sh -c 'while true; do curl -s -m 2 -o /dev/null $(2); sleep 3; done'

.PHONY: up down

up: $(BIN) down
	$(call there,$(TARGET),target.sh)
	sudo ip route replace 10.200.0.0/24 via $(TARGET_IP)
	$(call send,pathviz-send-local,http://$(TARGET_IP):8080/)
	$(call send,pathviz-send-forward,http://10.200.0.2:9000/)
	$(call send,pathviz-send-dnat,http://$(TARGET_IP):8081/)
	$(call send,pathviz-send-blocked,http://$(TARGET_IP):8082/)
	@echo "The demo runs. Open the pathviz tab of the playground (port 7070 of $(TARGET))."

down:
	-@for u in $(UNITS); do sudo systemctl stop $$u 2>/dev/null; sudo systemctl reset-failed $$u 2>/dev/null; done; true
