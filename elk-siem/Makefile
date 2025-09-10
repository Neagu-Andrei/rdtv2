##### ELK-SIEM — Host Makefile (script-driven) #####
SHELL := /bin/bash

.PHONY: up down restart setup-ilm cert-path ping help

help:
	@echo "Targets:"
	@echo "  make up           # generate cert (if missing), start ELK, apply ILM+template"
	@echo "  make down         # stop ELK stack"
	@echo "  make restart      # down + up"
	@echo "  make setup-ilm    # (re)apply ILM policy and index template"
	@echo "  make cert-path    # print path to logstash.crt (scp to victim:/tmp/logstash.crt)"
	@echo "  make ping         # quick ping to Elasticsearch"

up:
	./scripts/host-up.sh

down:
	./scripts/host-down.sh

restart: down up

setup-ilm:
	./scripts/host-setup-ilm.sh

cert-path:
	@echo "$$(pwd)/logstash/certs/logstash.crt"

ping:
	@curl -s -u "elastic:$${ELASTIC_PASSWORD:-changeme}" http://localhost:9200 | jq -r '.tagline // .name // .status' || true