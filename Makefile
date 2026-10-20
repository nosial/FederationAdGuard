all: target/debug/net.nosial.federation_adguard.ncc target/release/net.nosial.federation_adguard.ncc
target/debug/net.nosial.federation_adguard.ncc:
	ncc build --configuration debug --log-level debug
target/release/net.nosial.federation_adguard.ncc:
	ncc build --configuration release --log-level debug

test:
	phpunit --configuration phpunit.xml


docs:
	phpdoc --config phpdoc.dist.xml


clean:
	rm -f target/debug/net.nosial.federation_adguard.ncc
	rm -f target/release/net.nosial.federation_adguard.ncc
	rm -rf target/docs
	rm -rf target/cache

.PHONY: all install clean test docs