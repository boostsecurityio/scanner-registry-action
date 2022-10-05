# Scanner Registry Action

Checks the `rules-db` and `namespace` in the registry repo.

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

### `rules_db_path` (Optional, str)

The path to the `rules-db` directory in the registry repo. Defaults to `scanners/`.

### `modules_path` (Optional, str)

The path to the `modules` directory in the registry repo. Defaults to `scanners/`.
