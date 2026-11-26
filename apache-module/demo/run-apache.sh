#!/usr/bin/env bash
# Runs Apache with mod_schiza in the foreground, with the access and error log in this terminal.
#
#   apache-module/demo/run-apache.sh [port]        (default 8080, Ctrl+C stops it)
#
# The backend must listen on SCHIZA_BACKEND (default 127.0.0.1:5292, the API http profile).
# SCHIZA_MODE=monitor only records verdicts instead of blocking.
set -euo pipefail

module_dir=$(cd "$(dirname "$0")/.." && pwd)
port=${1:-8080}
backend=${SCHIZA_BACKEND:-127.0.0.1:5292}
mode=${SCHIZA_MODE:-block}

make -s -C "$module_dir"

httpd=$(apxs -q SBINDIR)/$(apxs -q TARGET)
modules_dir=$(apxs -q LIBEXECDIR)
static_modules=$("$httpd" -l)

work=$(mktemp -d -t schiza-demo-XXXXXX)
trap 'rm -rf "$work"' EXIT
mkdir "$work/htdocs"
echo "<h1>Hello from Apache</h1>" > "$work/htdocs/index.html"

load_modules=""
for name in mpm_event unixd authz_core log_config dir unique_id; do
    if ! grep -q "mod_$name.c" <<< "$static_modules"; then
        load_modules+="LoadModule ${name}_module \"$modules_dir/mod_$name.so\""$'\n'
    fi
done

cat > "$work/httpd.conf" <<EOF
ServerRoot "$work"
DefaultRuntimeDir "$work"
PidFile "$work/httpd.pid"
ServerName localhost
Listen 127.0.0.1:$port
$load_modules
LoadModule schiza_module "$module_dir/.libs/mod_schiza.so"

ErrorLog /dev/stderr
LogLevel warn schiza:info
LogFormat "%h \"%r\" %>s verdict=%{schiza-verdict}n score=%{schiza-score}n %{ms}Tms" demo
CustomLog /dev/stdout demo

DocumentRoot "$work/htdocs"
DirectoryIndex index.html

SchizaEnable On
SchizaBackend $backend
SchizaTimeout 100ms
SchizaMode $mode
SchizaBreaker 5 10s
EOF

echo "Apache with mod_schiza on http://127.0.0.1:$port (mode $mode, backend $backend)"
"$httpd" -f "$work/httpd.conf" -DFOREGROUND
