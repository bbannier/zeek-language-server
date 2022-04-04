PHONY: all update-deps

all: update-deps

update-deps: update-rs-deps update-js-deps

update-rs-deps:
	@cargo upgrade
	@rm Cargo.lock
	@cargo b

update-js-deps:
	@(cd vscode/ && yarn upgrade)
