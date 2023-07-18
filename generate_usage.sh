#! /bin/sh

# Create USAGE.md markdown from the --help output supplied on stdin

cat <<'EOF'
# autoreverse usage

The following documentation is auto-generated with `autoreverse -h` from @latest. It may
not reflect the most recent changes to @master.


```
EOF

sed -e 's/[[:space:]]*$//'

cat <<'EOF'
```
EOF
