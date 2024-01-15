################################################################################
# This Makefile mostly exists for developers, but it's also of use if 'go
# build' or 'go install' don't do what you want; namely installing the
# executable *and* the manpage in traditional Unix locations.
################################################################################

BINDIST=/usr/local/sbin
MANDIST=/usr/share/man/man8
MANSRC=autoreverse.8
ARCMD=autoreverse

all: version.go $(ARCMD) USAGE.md
	@echo All targets built. "Consider 'make help' for other targets".

$(ARCMD): *.go */*.go Makefile $(MANSRC)
	go build

.PHONY: help
help:
	@echo
	@echo Make targets for "'autoreverse'":
	@echo "	 Local targets: 'all', 'vet', 'fmt', 'clean' and 'install'"
	@echo
	@echo "	 Cross-platform targets:"
	@echo "	   'freebsd/amd64' - OPNSense on Intel"
	@echo "	   'linux/mips' - Mikrotik Router Boards"
	@echo "	   'linux/mips64' - Ubiquiti Edge Router series"
	@echo "	   'linux/armv71' - 32-bit Raspberry Pi3/Pi-hole, ASUS RT-AX55"
	@echo "	   'linux/armv8' - 64-bit Raspberry Pi4/Pi-hole"
	@echo "	   'windows/amd64' - Windows 64bit on Intel/AMD"
	@echo "	   'windows/386' - Windows 32bit"
	@echo

.PHONY: vet
vet:
	go vet ./...
	mandoc -Tlint $(MANSRC); exit 0

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
	gofmt -s -w .

.PHONY: test tests
test tests:
	go test ./...
	go vet ./...

version.go: generate_version.sh ChangeLog.md Makefile go.mod
	sh generate_version.sh ChangeLog.md >$@

USAGE.md: $(ARCMD) usage.go generate_usage.sh Makefile
	./$(ARCMD) -h | sh generate_usage.sh >$@

# Cross-compile targets

.PHONY: freebsd/amd64
freebsd/amd64: clean
	@echo 'Building for FreeBSD/amd64 targets (maybe OPNSense Routers)'
	@GOOS=freebsd GOARCH=amd64 go build
	@file $(ARCMD)

.PHONY: freebsd/arm64
freebsd/arm64: clean
	@echo 'Building for FreeBSD/arm64 targets (maybe OPNSense Routers)'
	@GOOS=freebsd GOARCH=arm64 go build
	@file $(ARCMD)

.PHONY: linux/mips
linux/mips: clean
	@echo 'Building for Linux/mips targets (maybe Mikrotik Router Boards)'
	@GOOS=linux GOARCH=mips go build
	@file $(ARCMD)

.PHONY: linux/mips64
linux/mips64: clean
	@echo 'Building for Linux/mips64 targets (Ubiquiti er3, er6)'
	@GOOS=linux GOARCH=mips64 go build
	@file $(ARCMD)

.PHONY: linux/armv71
linux/armv71: clean
	@echo 'Building for 32-bit Linux/armv71 (ASUS RT-AX55)'
	@GOOS=linux GOARCH=arm go build
	@file $(ARCMD)

.PHONY: linux/armv8
linux/armv8: clean
	@echo 'Building for 64-bit Linux/armv8 (pi4)'
	@GOOS=linux GOARCH=arm go build
	@file $(ARCMD)

.PHONY: windows/amd64
windows/amd64: clean
	@echo Building for amd64 Windows
	@GOOS=windows GOARCH=amd64 go build
	@file $(ARCMD).exe

.PHONY: windows/386
windows/386: clean
	@echo Building for 386 Windows
	@GOOS=windows GOARCH=386 go build
	@file $(ARCMD).exe
