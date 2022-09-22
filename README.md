```yml
name: Test
on:
  push:
    branches:
      - main
      - master

  pull_request:
    branches:
      - main
      - master
    types:
      - opened
      - synchronize

jobs:
  scan_job:
    name: Test Action
    runs-on: "ubuntu-latest"

    steps:
      - name: Checkout
        uses: actions/checkout@v2
      - name: Test new action
        uses: my-test-org883/test-ga@v2
```
