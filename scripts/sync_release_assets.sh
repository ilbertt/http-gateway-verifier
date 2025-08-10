#!/bin/bash

# Note: the principal corresponding to this identity must have been granted permissions to commit assets. See the README for more details.

# Note: the `data` folder must have the following structure:
# data
# ├─ release_hash_1/
# │  ├─ initramfs.cpio.gz
# │  ├─ OVMF.fd
# │  ├─ vmlinuz
# ├─ release_hash_2/
# │  ├─ initramfs.cpio.gz
# │  ├─ OVMF.fd
# │  ├─ vmlinuz
# ...

# Might take a few minutes
icx-asset --replica $IC_NETWORK --pem ./data/identity.pem sync $CANISTER_ID ./data/release-assets

# Just to confirm that we have loaded all the release assets in the canister
icx-asset --replica $IC_NETWORK --pem ./data/identity.pem ls $CANISTER_ID
