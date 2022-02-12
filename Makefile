################################################################################
# Largely this Makefile exists for developers, but it's also of use if 'go
# build' or 'go install' don't do what you want; namely installing the
# executable *and* the manpage in traditional Unix locations.
################################################################################

BINDIST=/usr/local/sbin
MANDIST=/usr/share/man/man8
MANSRC=autoreverse.8
ARCMD=autoreverse

all: $(ARCMD) USAGE.md
	@echo "'all' target built. Consider 'make help' for other targets".

$(ARCMD): version.go
	go build

.PHONY: help
help:
	@echo
	@echo Make targets for "'autoreverse'":
	@echo "	 Local targets: 'all', 'vet', 'fmt', 'clean' and 'install'"
	@echo
	@echo "	 Cross-platform targets:"
	@echo "	   'mips' - Mikrotik Router Boards"
	@echo "	   'mips64' - Ubiquiti Edge Router series"
	@echo "	   'armv71' - 32-bit Raspberry Pi3/Pi-hole, ASUS RT-AX55"
	@echo "	   'armv8' - 64-bit Raspberry Pi4/Pi-hole"
	@echo
	@echo "	 Cross-platform Windows targets: 'windowsamd64' and 'windows386'"
	@echo

.PHONY: vet
vet:
	go vet ./...
	mandoc -Tlint autoreverse.8; exit 0

.PHONY: clean
clean:
	@rm -f $(ARCMD) $(ARCMD).exe
	@echo Directory cleaned
	@echo "Warning: Never run 'go clean' as that erases the manpage (for obscure reasons)"

.PHONY: install
install: $(ARCMD)
	install -d -o 0 -g 0 -m a=rx $(BINDIST) # Ensure destination directory
	install -p -o 0 -g 0 -m a=rx $(ARCMD) $(BINDIST)
	@echo $(ARCMD) installed in $(BINDIST)
	install -d -o 0 -g 0 -m a=rx $(MANDIST) # Ensure destination directory
	install -p -m a=rx $(MANSRC) $(MANDIST)
	@echo $(MANSRC) installed in $(MANDIST)

.PHONY: fmt
fmt:
	find . -name '*.go' -type f -print | xargs gofmt -s -w

.PHONY: test tests
test tests:
	go test ./...
	go vet ./...

version.go: generate_version.sh ChangeLog.md Makefile
	sh generate_version.sh ChangeLog.md >$@

USAGE.md: $(ARCMD) generate_usage.sh Makefile
	./$(ARCMD) -h | sh generate_usage.sh >$@

# Cross-compile targets

.PHONY: mips
mips: clean
	@echo 'Building for mips Linux targets (maybe Mikrotik Router Boards)'
	@GOOS=linux GOARCH=mips $(MAKE) all
	@file $(ARCMD)

.PHONY: mips64
mips64: clean
	@echo 'Building for mips64 Linux targets (Ubiquiti er3, er6)'
	@GOOS=linux GOARCH=mips64 $(MAKE) all
	@file $(ARCMD)

.PHONY: armv71
armv71: clean
	@echo 'Building for 32-bit armv71 (ASUS RT-AX55)'
	@GOOS=linux GOARCH=arm $(MAKE) all
	@file $(ARCMD)

.PHONY: armv8
armv8: clean
	@echo 'Building for (64-bit armv8) (pi4)'
	@GOOS=linux GOARCH=arm $(MAKE) all
	@file $(ARCMD)

.PHONY: windowsamd64
windowsamd64: clean
	@echo Building for amd64 Windows
	@GOOS=windows GOARCH=amd64 $(MAKE) all
	@file $(ARCMD).exe

.PHONY: windows386
windows386: clean
	@echo Building for 386 Windows
	@GOOS=windows GOARCH=386 $(MAKE) all
	@file $(ARCMD).exe
