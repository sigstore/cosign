all: protogen-go protogen-java

.PHONY: protogen-go
protogen-go:
	docker run -v ${PWD}:/defs namely/protoc-all -d . -l go

.PHONY: protogen-java
protogen-java:
	docker run -v ${PWD}:/defs namely/protoc-all -d . -l java
