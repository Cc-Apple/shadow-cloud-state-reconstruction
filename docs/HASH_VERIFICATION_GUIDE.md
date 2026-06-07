# Hash Verification Guide

This folder publishes SHA256 and size metadata for preserved artifacts without publishing raw artifacts.

## Public register

See:

```text
evidence-index/
```

If the CSV is large, it is split into part files.

## Verification

A qualified reviewer can recompute:

```powershell
Get-FileHash -Algorithm SHA256 "<artifact>"
```

and compare it against the public register.

## Boundary

SHA256 proves file identity/integrity. It does not prove malware, C2, attribution, hidden MDM, or compromise by itself.

```text
public_rows: 56508
errors: 0
```
