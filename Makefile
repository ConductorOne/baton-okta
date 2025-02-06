GOOS = $(shell go env GOOS)
GOARCH = $(shell go env GOARCH)
BUILD_DIR = dist/${GOOS}_${GOARCH}

ifeq ($(GOOS),windows)
OUTPUT_PATH = ${BUILD_DIR}/baton-okta.exe
LAMBDA_SERVER_OUTPUT_PATH = ${BUILD_DIR}/baton-okta-lambda-server.exe
else
OUTPUT_PATH = ${BUILD_DIR}/baton-okta
LAMBDA_SERVER_OUTPUT_PATH = ${BUILD_DIR}/baton-okta-lambda-server
endif

.PHONY: build
build:
	go build -o ${OUTPUT_PATH} ./cmd/baton-okta
	# go build -o ${LAMBDA_SERVER_OUTPUT_PATH} ./cmd/baton-okta-lambda-server

.PHONY: build-lambda-server
build-lambda-server:
	go build -o ${LAMBDA_SERVER_OUTPUT_PATH} ./cmd/baton-okta-lambda-server


.PHONY: update-deps
update-deps:
	go get -d -u ./...
	go mod tidy -v
	go mod vendor

.PHONY: add-dep
add-dep:
	go mod tidy -v
	go mod vendor

.PHONY: lint
lint:
	golangci-lint run

.PHONY: sam-build
sam-build:
	DOCKER_HOST=unix://$(HOME)/.docker/run/docker.sock sam build

.PHONY: sam-run
sam-run: sam-build
	DOCKER_HOST=unix://$(HOME)/.docker/run/docker.sock sam local start-lambda --env-vars env.json
