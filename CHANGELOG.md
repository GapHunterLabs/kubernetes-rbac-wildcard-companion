<!-- Keep a Changelog guide -> https://keepachangelog.com -->

# Kubernetes RBAC Wildcard Companion Changelog

## [Unreleased]

### Added

- A description page for the inspection in **Settings | Editor |
  Inspections**, which showed "Under construction".

### Changed

- The rating prompt's local counter keeps one-way fingerprints of findings
  instead of their file paths, and deletes the list that earlier versions
  kept.
- `PRIVACY.md` describes the values the plugin keeps in the IDE's local
  settings.

## [0.1.1]

### Fixed

- Review/star CTA now links to this plugin's own Marketplace
  reviews page instead of the vendor's generic plugin list.

## [0.1.0]

### Added

- Warning on a `Role`/`ClusterRole` rule that combines a wildcard
  (`"*"`) in `verbs` or `resources` with a sensitive resource
  (`secrets`, `pods/exec`, `clusterrolebindings`) — OWASP Kubernetes
  Top 10 K03, Overly Permissive RBAC Configurations.
- Handles both flow-style (`resources: ["secrets"]`) and block-style
  (`resources:` / `- secrets`) list shapes.

[Unreleased]: https://github.com/GapHunterLabs/kubernetes-rbac-wildcard-companion/compare/0.1.1...HEAD
[0.1.1]: https://github.com/GapHunterLabs/kubernetes-rbac-wildcard-companion/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/GapHunterLabs/kubernetes-rbac-wildcard-companion/commits/0.1.0
