#!/bin/sh
# Fake GlobalProtect CLI used by tests and local demos (GP_BIN=testdata/fake-globalprotect.sh).
case "$1" in
connect)
	echo "Retrieving configuration... portal=$3 prelogin-cookie=secretcookie"
	"$BROWSER" "https://login.example.com/saml?SAMLRequest=abc&RelayState=xyz"
	echo "There is no default browser? no: opened via \$BROWSER"
	trap 'echo "connect interrupted"; exit 130' INT
	while :; do sleep 0.1; done
	;;
launch-uri)
	case "$2" in
	*expired*)
		echo "Error: token=supersecret expired for $2" >&2
		exit 1
		;;
	esac
	echo "Connected using $2"
	;;
show)
	echo "GlobalProtect status: ${FAKE_STATUS:-Disconnected}"
	;;
disconnect)
	echo "GlobalProtect has disconnected"
	;;
*)
	echo "unknown command: $*" >&2
	exit 2
	;;
esac
