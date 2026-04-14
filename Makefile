BINARY  := cpar
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.version=$(VERSION)
OUTDIR  := dist

TARGETS := \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64 \
	windows/arm64

.PHONY: all clean build $(TARGETS)

all: build

build: $(TARGETS)

$(TARGETS):
	$(eval OS   := $(word 1,$(subst /, ,$@)))
	$(eval ARCH := $(word 2,$(subst /, ,$@)))
	$(eval EXT  := $(if $(filter windows,$(OS)),.exe,))
	$(eval OUT  := $(OUTDIR)/$(BINARY)_$(OS)_$(ARCH)$(EXT))
	@mkdir -p $(OUTDIR)
	GOOS=$(OS) GOARCH=$(ARCH) go build -ldflags "$(LDFLAGS)" -o $(OUT) .
	@echo "built: $(OUT)"

clean:
	rm -rf $(OUTDIR)
