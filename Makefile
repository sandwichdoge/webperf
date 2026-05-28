BINARY  := webperf
DIST    := dist
PKG     := .

GOFLAGS := -trimpath
LDFLAGS := -s -w

PLATFORMS_ALL   := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64
PLATFORMS_AMD64 := linux/amd64 darwin/amd64 windows/amd64

.PHONY: all amd64

all:   PLATFORMS := $(PLATFORMS_ALL)
amd64: PLATFORMS := $(PLATFORMS_AMD64)

all amd64:
	@mkdir -p $(DIST)
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
		out="$(DIST)/$(BINARY)-$$os-$$arch$$ext"; \
		echo "  build  $$out"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
			go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o "$$out" $(PKG) || exit 1; \
	done
