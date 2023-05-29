# Scanner Registry Action

Checks the `rules.yaml` and `namespace` in the registry repo.

## Example

Add the following to your `.github/workflows/scanner-registry.yml`:

```yml
name: Scan Rules DB and Namespaces
on:
  push:
    branches:
      - main

  pull_request:
    branches:
      - main
    types:
      - opened
      - synchronize

jobs:
  scan_job:
    name: Scanner Registry Action
    runs-on: "ubuntu-latest"

    steps:
      - name: Checkout
        uses: actions/checkout@v2
      - name: Scan Registry
        uses: boostsecurityio/scanner-registry-action@v1
        with:
          api_token: ${{ secrets.BOOST_API_TOKEN }}
```

## Configuration

### `api_endpoint` (Optional, str)

The url for the boost backend. Defaults to `https://api.boostsecurity.net`.

### `api_token` (Required, str)

The authentication token for the boost backend.

### `modules_path` (Optional, str)

The path to the `module.yaml` file in the registry repo. Defaults to `scanners/`.

### `rules_realm_path` (Optional, str)

The path to the `rules.yaml` file in the registry repo. Defaults to `rules-realm/`.

### `docs_url` (Optional, str)

The url for boost documentation. Defaults to `https://docs.boostsecurity.net`.
