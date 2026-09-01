package dev.gaphunter.kubernetesrbacwildcardcompanion.model

/** Which side of the rule carried the wildcard that made it dangerous. */
enum class WildcardSide {
    /** `verbs: ["*"]` (or includes `"*"`) against a specific sensitive resource. */
    VERBS,

    /** `resources: ["*"]` (or includes `"*"`) -- every resource, including the sensitive ones. */
    RESOURCES,
}

/**
 * One `rules:` entry in a Role/ClusterRole that combines a wildcard
 * (in `verbs` or `resources`) with a resource on the OWASP Kubernetes
 * Top 10 (K03) sensitive list.
 */
data class RbacHit(
    val sensitiveResource: String,
    val side: WildcardSide,
    val lineNumber: Int,
)
