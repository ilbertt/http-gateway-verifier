#!/bin/bash

# Note: the principal corresponding to this identity must have been granted permissions to prepare and commit:
# E.g.:
# dfx canister call verifier grant_permission '(record { to_principal = principal "mn3in-rjd23-2dbpg-kf7pt-nqgdb-aw4i2-5di5n-odzb2-o2idn-5wozm-cqe"; permission = variant { Prepare } })'
# dfx canister call verifier grant_permission '(record { to_principal = principal "mn3in-rjd23-2dbpg-kf7pt-nqgdb-aw4i2-5di5n-odzb2-o2idn-5wozm-cqe"; permission = variant { Commit } })'

# Might take a few minutes
# Note: the `data` folder must have the following structure:
# data
# ├─ release_short_hash_1/
# │  ├─ initramfs.cpio.gz
# │  ├─ OVMF.fd
# │  ├─ vmlinuz
# ├─ release_short_hash_2/
# │  ├─ initramfs.cpio.gz
# │  ├─ OVMF.fd
# │  ├─ vmlinuz
# ...
icx-asset --pem ./data/identity.pem sync uxrrr-q7777-77774-qaaaq-cai ./data/release-assets

# Just to confirm that we have loaded all the release assets in the canister
icx-asset --pem ./data/identity.pem ls uxrrr-q7777-77774-qaaaq-cai
