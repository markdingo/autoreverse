BINDIST=/usr/local/sbin
MANDIST=/usr/share/man/man8
MANSRC=autoreverse.8
ARPATH=cmd/autoreverse
ARCMD=$(ARPATH)/autoreverse

ALL=$(ARCMD)
CLEANPATHS=$(ARPATH)
ALLPKGS=database/*.go delegation/*.go *util/*.go log/*.go pregen/*.go resolver/*.go
PREGEN=pregen/version.go pregen/autoreverse.8 pregen/MANPAGE.txt

# If your version of make complains about this include directive, you can safely remove it
# without any ill-effects. It's solely to include targets only relevant to the original
# developer.
-include local/local.mk

.PHONY: help
help:
	@echo
	@echo Make targets for "'autoreverse'":
	@echo "  Local targets: 'clean', 'all' and 'install'"
	@echo
	@echo "  Cross-platform targets:"
	@echo "    'mips' - Mikrotik Router Boards"
	@echo "    'mips64' - Ubiquiti Edge Router series"
	@echo "    'armv71' - 32-bit Raspberry Pi3/Pi-hole, ASUS RT-AX55"
	@echo "    'armv8' - 64-bit Raspberry Pi4/Pi-hole"
	@echo
	@echo "  Cross-platform Windows targets: 'windowsamd64' and 'windows386'"
	@echo

all: $(ALL)

.PHONY: clean
clean: Makefile
	rm -f $(PREGEN)
	@for p in $(CLEANPATHS); do make -C $${p} clean; done

$(ARCMD): Makefile $(ARPATH)/*.go $(ALLPKGS) $(PREGEN)
	make -C $(ARPATH)

race: Makefile $(ARPATH)/*.go $(ALLPKGS) $(PREGEN)
	make -C $(ARPATH) race

.PHONY: vet
vet:
	go vet ./...

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
test tests: $(PREGEN)
	go test ./...
	go vet ./...

.PHONY: pregen
pregen: pregen/version.go pregen/autoreverse.8

# Pre-generated files needed by build
pregen/version.go: generate_version.sh ChangeLog.md Makefile
	mkdir -p pregen
	sh generate_version.sh ChangeLog.md >$@

# pregen is the "embed" directory used by autoreverse to include its manpage. Embed does
# not allow parent directory references so the choice is to either include an "embed" go
# program in the top level of the project or copy the man page to a package level
# sub-directory.
pregen/autoreverse.8: autoreverse.8
	mkdir -p pregen
	cp -f $? $@

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
