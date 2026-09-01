# Demo data for screenshots

`cluster-role.yaml` — first two rules flagged (verbs wildcard on
`secrets`, resources wildcard covering all sensitive resources); third
rule (`configmaps` with specific verbs) not flagged.

## How to get the screenshot

1. `./gradlew runIde` from `kubernetes-rbac-wildcard-companion`, open
   this `demo/` folder as the project.
2. Full Screen, open `cluster-role.yaml` — warnings should appear on
   the first two `- apiGroups:` rule lines but not on the third.
3. Screenshot with all three rules visible, save into
   `kubernetes-rbac-wildcard-companion/docs/screenshots/`. Close the
   sandbox.
