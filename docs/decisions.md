# Design decisions

## Why Kustomize components + overlays?

Because you want a common baseline with small per-cluster deviations.

- Shared components keep common config in one place.
- Cluster overlays keep differences small and visible.
- Argo CD works very well with this pattern.

## Why cluster directories instead of environment directories?

Because production often diverges by region and sometimes by hardware, certificates, network or identity endpoint.
A cluster folder maps directly to what Argo CD reconciles.

## Why separate operator install from operator instance config?

Because installation is often global, but actual custom resources are hardware or environment specific.
That is especially true for Local Storage.
