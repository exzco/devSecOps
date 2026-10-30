# DAST PoC Directory

`worker-dast` reads versioned PoC templates from this directory by default:

```text
pocs/
├── poc_index.json
└── *.yaml
```

`poc_index.json` must contain entries with at least:

```json
[
  {
    "id": "example",
    "name": "Example check",
    "severity": "HIGH",
    "tags": ["http"],
    "file_path": "example.yaml"
  }
]
```

The complete directory is an immutable deployment artifact. Package it into the
DAST Worker image or mount it at `dast.poc_dir`. Updating rules requires publishing
a new Worker/rules version; there is no Server-side PoC CRUD or object-storage sync.
