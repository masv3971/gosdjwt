#!/usr/bin/env bash

s='["2GLC42sKQveCfGfryNRN9w", "given_name", "John"]'
echo "claim: ${s}"

claimBase64=$(echo -n ${s} |base64)
echo "claimBase64: ${claimBase64}"

claimSHA256=$(echo -n ${claimBase64} | sha256sum)
echo "claimSHA256: ${claimSHA256}"

base64ClaimSHA256=$(echo -n ${claimSHA256} | awk '{print $1}' | xxd -r -p | base64)
echo "base64ClaimSHA256: ${base64ClaimSHA256}"