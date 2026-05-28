BINARY  := webperf
DIST    := dist
PKG     := .

GOFLAGS := -trimpath
LDFLAGS := -s -w

PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: all

all:
	@mkdir -p $(DIST)
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
		out="$(DIST)/$(BINARY)-$$os-$$arch$$ext"; \
		echo "  build  $$out"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
			go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o "$$out" $(PKG) || exit 1; \
	done
