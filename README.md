# Kubernetes RBAC Wildcard Companion

Warning on a `Role`/`ClusterRole` rule that combines a wildcard
(`"*"`) in `verbs` or `resources` with a sensitive resource —
`secrets`, `pods/exec`, `clusterrolebindings`. This is the most common
path to privilege escalation after a single pod is compromised in a
cluster (OWASP Kubernetes Top 10, K03 — Overly Permissive RBAC
Configurations).

## Why it exists

RBAC manifests are hand-written YAML with no compiler and no built-in
warning for an overly broad grant — `resources: ["*"]` or
`verbs: ["*"]` next to `secrets`/`pods/exec`/`clusterrolebindings` is
valid, deploys cleanly, and silently hands out cluster-wide
privilege-escalation potential. The "Kubernetes Control Center" plugin
on Marketplace covers 5 other manifest checkers (RunAsNonRoot,
ReadOnlyRootFilesystem, PrivilegeEscalation, HostNamespace, DockerSock)
but RBAC is confirmed absent from its published checker list.

## Why built this way

- **100% static text analysis** — an indentation-based line scanner,
  not a real YAML parser, so it works whether the real Kubernetes/YAML
  plugin is installed or not.
- **Handles both list shapes** YAML allows for `resources`/`verbs`:
  flow style (`resources: ["secrets"]`) and block style (`resources:`
  followed by `- secrets` on its own line, including the common case
  where the list item sits at the same indentation as its own key).
- **Two independent wildcard shapes, both covered** — a wildcard
  `resources` list (every resource, sensitive ones included) and a
  wildcard `verbs` list combined with a resource list that names a
  sensitive resource directly.

## v0.1 scope — stated honestly, not exhaustively

Only `Role`/`ClusterRole` manifests with `rules` in the standard
`rbac.authorization.k8s.io/v1` shape. Never resolves a
`RoleBinding`/`ClusterRoleBinding` to know who is actually granted the
permission — only flags the dangerous rule itself.

## Usage

Open any `.yml`/`.yaml` file whose top-level `kind:` is `Role` or
`ClusterRole`. A `rules:` entry combining a wildcard with a sensitive
resource shows a warning on that entry's line.

## Enterprise / Team Licensing

Need enterprise features, custom rules, or team licensing? Contact us at
**gaphunterlabs@gmail.com**.

## Development

```
./gradlew test           # unit tests
./gradlew buildPlugin    # generates build/distributions/*.zip
./gradlew verifyPlugin   # checks compatibility against real IDEs
```

## License

Apache-2.0. See `LICENSE`.
