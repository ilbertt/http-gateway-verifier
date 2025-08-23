# `http-gateway-verifier`

A canister to verify HTTP Gateways SEV-SNP attestations.

## Usage

A version of this canister is available on mainnet, with canister ID [`5slwp-diaaa-aaaae-abl7a-cai`](https://dashboard.internetcomputer.org/canister/5slwp-diaaa-aaaae-abl7a-cai). You can interact with it using its [Candid UI](https://a4gq6-oaaaa-aaaab-qaa4q-cai.raw.icp0.io/?id=5slwp-diaaa-aaaae-abl7a-cai) or with the command:

```shell
dfx canister call --ic 5slwp-diaaa-aaaae-abl7a-cai verify
```

You will be prompted to insert three fields:

-   `gateway_host` (string): the HTTP Gateway you want to obtain the attestation from. You can choose one from [SEV-SNP-enabled HTTP Gateways](https://github.com/dfinity/http-gateway-release/blob/main/attestation-guide.md#sev-snp-enabled-http-gateways).
-   `report_data` (bytes, optional): The data you want to include in the report, in order to verify that the report is fresh. Must be 64 bytes long.
-   `release_hash` (string, optional): The GitHub release hash which corresponds to the path you have uploaded the release assets to. See [Uploading Release Assets](#uploading-release-assets) for more details.

### Uploading Release Assets

The GitHub Release assets are needed in order to verify that the measurement in the report matches the measurement calculated from the assets. This way, you can verify that the HTTP Gateway was started with that initial state (memory and operative system).

#### Preparation

Make sure you have [icx-asset](https://github.com/dfinity/sdk/blob/master/src/canisters/frontend/icx-asset/README.md) installed:

```shell
cargo install icx-asset
```

Then, create an identity and save it in the `data` folder:

```shell
dfx identity new --storage-mode plaintext temp
dfx identity --identity temp get-principal # make sure you save principal string returned by this command
dfx identity export temp > ./data/identity.pem
dfx identity remove temp
```

Then, make sure you have permissions to upload assets to the canister (**Note**: you need to be a controller of the canister to make these commands work):

```shell
dfx canister call --ic 5slwp-diaaa-aaaae-abl7a-cai grant_permission '(record { to_principal = principal "<principal-id-obtained-above>"; permission = variant { Commit } })'
```

#### Upload

First, you must download the following assets from the latest [HTTP Gateway GitHub release](https://github.com/dfinity/http-gateway-release/releases) and place them in the `data/release-assets/<release-commit-hash>`:

-   `initramfs.cpio.gz`
-   `OVMF.fd`
-   `vmlinuz`

For example, for release [f54172b](https://github.com/dfinity/http-gateway-release/releases/tag/f54172b) you will download those assets into the `data/release-assets/f54172b93fe5edd126570e20d8efe8247e721cbc` folder.

> **Note**: The canister sends replicated HTTPS Outcalls to the HTTP Gateway to fetch the attestation report. The HTTP Gateway supports idempotent requests since release [f54172b](https://github.com/dfinity/http-gateway-release/releases/tag/f54172b). Releases before this one will not work.

Then, you must upload the release assets to the canister. You can use the [`sync_release_assets.sh`](./scripts/sync_release_assets.sh) script (which assumes that the [Preparation](#preparation) step has been completed):

```shell
CANISTER_ID=5slwp-diaaa-aaaae-abl7a-cai IC_NETWORK=https://icp-api.io ./scripts/sync_release_assets.sh
```

> **Note**: This command _syncs_ the content of the `data/release-assets` folder with the canister assets. You may lose data.

You can now pass the release hash (in this example, `f54172b93fe5edd126570e20d8efe8247e721cbc`) to the canister's `verify` method argument.

## Development

You can run a local instance of the verifier canister by simply running these commands in two separate terminals:

```shell
# In the first terminal (omit the --clean flag if you want to use the canister state from a previous run, not recommended)
dfx start --clean
# In the second terminal
dfx deploy verifier
```

Then, you can follow [Usage](#usage) guide, replacing the canister ID with the one obtained in the output, removing the `--ic` flag from all the dfx commands and setting the `IC_NETWORK` env variable to `http://localhost:4943` where needed.
