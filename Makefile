SOURCES := $(shell find src -type f) project.yml

all: target/debug/net.nosial.federation_adguard.ncc target/release/net.nosial.federation_adguard.ncc
target/debug/net.nosial.federation_adguard.ncc: $(SOURCES)
	ncc build --configuration debug --log-level debug
target/release/net.nosial.federation_adguard.ncc: $(SOURCES)
	ncc build --configuration release --log-level debug

test: target/release/net.nosial.federation_adguard.ncc
	phpunit --configuration phpunit.xml

test-unit: target/release/net.nosial.federation_adguard.ncc
	phpunit --configuration phpunit.xml --exclude-group integration


docs:
	phpdoc --config phpdoc.dist.xml


clean:
	rm -f target/debug/net.nosial.federation_adguard.ncc
	rm -f target/release/net.nosial.federation_adguard.ncc
	rm -rf target/docs
	rm -rf target/cache

.PHONY: all clean test test-unit docs test-env test-env-down

TEST_COMPOSE = docker compose -f docker-compose.yml
SERVER_ENDPOINT ?= http://172.17.0.1:7000

test-env:
	$(TEST_COMPOSE) build --pull
	$(TEST_COMPOSE) up -d
	@echo "Waiting for FederationLib to be ready..."
	@for i in $$(seq 1 60); do \
		if curl -sf -o /dev/null "$(SERVER_ENDPOINT)/"; then \
			echo "The test environment is ready"; exit 0; \
		fi; \
		sleep 5; \
	done; \
	echo "The test environment did not become ready within 5 minutes"; $(TEST_COMPOSE) logs app; exit 1

test-env-down:
	$(TEST_COMPOSE) down
