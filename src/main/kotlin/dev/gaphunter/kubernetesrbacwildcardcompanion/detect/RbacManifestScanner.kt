package dev.gaphunter.kubernetesrbacwildcardcompanion.detect

import dev.gaphunter.kubernetesrbacwildcardcompanion.model.RbacHit
import dev.gaphunter.kubernetesrbacwildcardcompanion.model.WildcardSide

/**
 * Plain-text line scanner for Kubernetes `Role`/`ClusterRole` manifests
 * (`rbac.authorization.k8s.io/v1`) -- flags a `rules:` entry whose
 * `verbs` or `resources` includes the wildcard `"*"` combined with a
 * resource on the OWASP Kubernetes Top 10 (K03, Overly Permissive RBAC
 * Configurations) sensitive list: `secrets`, `pods/exec`,
 * `clusterrolebindings`.
 *
 * Two independent wildcard shapes both count as dangerous:
 *   - `resources: ["*"]` -- every resource, sensitive ones included,
 *     combined with any verb.
 *   - `verbs: ["*"]` -- every verb (including e.g. `create`/`delete`)
 *     against a resource list that names a sensitive resource directly.
 *
 * **Deliberately indentation-based, not a real YAML parser** -- same
 * discipline as `K8sManifestScanner` (k8s-resource-limit-companion):
 * a rule entry's own indentation defines where its block ends. Handles
 * both list shapes YAML allows for `apiGroups`/`resources`/`verbs`:
 * flow style (`resources: ["secrets", "pods"]`) and block style
 * (`resources:` followed by `- secrets` / `- pods` on their own
 * lines). Multi-doc files (`---` separators) and anchors/aliases
 * aren't specially resolved.
 *
 * **v0.1 scope, stated honestly:** only `Role`/`ClusterRole` with
 * `rules` in the standard `rbac.authorization.k8s.io/v1` shape --
 * never resolves `RoleBinding`/`ClusterRoleBinding` to know who is
 * actually granted the permission, only flags the dangerous rule
 * itself.
 */
object RbacManifestScanner {

    private val ROLE_KIND = Regex(
        """^kind:\s*["']?(Role|ClusterRole)["']?\s*$""",
        RegexOption.IGNORE_CASE,
    )
    private val RULES_KEY = Regex("""^(\s*)rules:\s*$""")
    private val RULE_ENTRY_START = Regex("""^(\s*)-\s*(.*)$""")
    private val APIGROUPS_KEY = Regex("""^(\s*)apiGroups:\s*(\[.*])?\s*$""")
    private val RESOURCES_KEY = Regex("""^(\s*)resources:\s*(\[.*])?\s*$""")
    private val VERBS_KEY = Regex("""^(\s*)verbs:\s*(\[.*])?\s*$""")
    private val BLOCK_ITEM = Regex("""^(\s*)-\s*["']?([\w./*-]+)["']?\s*$""")

    private val SENSITIVE_RESOURCES = setOf("secrets", "pods/exec", "clusterrolebindings")
    private const val WILDCARD = "*"

    fun scan(text: String): List<RbacHit> {
        if (!looksLikeRoleManifest(text)) return emptyList()

        val lines = text.lines()
        val hits = mutableListOf<RbacHit>()

        var i = 0
        while (i < lines.size) {
            val rulesMatch = RULES_KEY.find(lines[i])
            if (rulesMatch == null) {
                i++
                continue
            }
            val rulesIndent = rulesMatch.groupValues[1].length
            i++

            // Walk each `- apiGroups: ...` entry directly under this rules: list.
            // A list item (`- ...`) is allowed to sit at the SAME indentation
            // as its own `rules:` key (common, valid YAML) -- so a plain
            // isBlockEnd(line, rulesIndent) cut would wrongly treat the very
            // first `- apiGroups:` line (same indent as `rules:`) as ending
            // the block before it's ever read. A line only really ends the
            // rules: list when it's a real (non-blank/comment) line at a
            // SHALLOWER indent than rulesIndent -- a same-indent line here is
            // always the next list item, never a block-ending sibling key.
            while (i < lines.size) {
                val line = lines[i]
                val trimmed = line.trim()
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    i++
                    continue
                }
                val lineIndent = line.length - line.trimStart().length
                if (lineIndent < rulesIndent) break

                val entryMatch = RULE_ENTRY_START.find(line)
                if (entryMatch == null) {
                    i++
                    continue
                }
                val entryIndent = entryMatch.groupValues[1].length
                val bodyStart = i
                var bodyEnd = bodyStart + 1
                while (bodyEnd < lines.size && !isEntryBlockEnd(lines[bodyEnd], entryIndent)) bodyEnd++
                // The entry's own first line (`- apiGroups: [...]`) may carry a
                // key itself, so include it (with the leading `- ` stripped to
                // the same indentation as the rest of the entry's keys).
                val body = listOf(" ".repeat(entryIndent + 2) + entryMatch.groupValues[2]) +
                    lines.subList(bodyStart + 1, bodyEnd)

                hits += problemsFor(body, i + 1)
                i = bodyEnd
            }
        }

        return hits
    }

    private fun problemsFor(body: List<String>, ruleLineNumber: Int): List<RbacHit> {
        val resources = valuesFor(RESOURCES_KEY, body)
        val verbs = valuesFor(VERBS_KEY, body)
        if (resources.isEmpty() && verbs.isEmpty()) return emptyList()

        val hits = mutableListOf<RbacHit>()

        if (resources.contains(WILDCARD)) {
            for (sensitive in SENSITIVE_RESOURCES) {
                hits += RbacHit(sensitive, WildcardSide.RESOURCES, ruleLineNumber)
            }
        } else {
            val namedSensitive = resources.filter { it in SENSITIVE_RESOURCES }
            if (namedSensitive.isNotEmpty() && verbs.contains(WILDCARD)) {
                for (sensitive in namedSensitive) {
                    hits += RbacHit(sensitive, WildcardSide.VERBS, ruleLineNumber)
                }
            }
        }

        return hits
    }

    /** Reads the value list for a `keyRegex` key (`apiGroups:`/`resources:`/`verbs:`) in either flow or block form. */
    private fun valuesFor(keyRegex: Regex, body: List<String>): List<String> {
        val keyLineIndex = body.indexOfFirst { keyRegex.matches(it) }
        if (keyLineIndex < 0) return emptyList()

        val keyMatch = keyRegex.find(body[keyLineIndex])!!
        val keyIndent = keyMatch.groupValues[1].length
        val flowValue = keyMatch.groupValues.getOrNull(2)

        if (!flowValue.isNullOrBlank()) {
            return parseFlowList(flowValue)
        }

        // Block form: subsequent `- value` lines. YAML allows a list item to
        // sit at the SAME indentation as its own key (`resources:` / `-
        // secrets` both at column 2 is common and valid) as well as deeper --
        // so a block-end check keyed only on "> keyIndent" would wrongly cut
        // the list off at its very first item. Walk while each line is
        // either a list item at >= keyIndent, blank, or a comment; anything
        // else (a real line at a shallower indent, or a sibling key at
        // keyIndent that isn't a list item) ends the block.
        val values = mutableListOf<String>()
        var j = keyLineIndex + 1
        while (j < body.size) {
            val line = body[j]
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                j++
                continue
            }
            val lineIndent = line.length - line.trimStart().length
            if (lineIndent < keyIndent) break
            val itemMatch = BLOCK_ITEM.find(line) ?: break
            values += itemMatch.groupValues[2]
            j++
        }
        return values
    }

    private fun parseFlowList(flow: String): List<String> =
        flow.removePrefix("[").removeSuffix("]")
            .split(",")
            .map { it.trim().trim('"', '\'') }
            .filter { it.isNotEmpty() }

    /** True when [line] is blank/comment (doesn't end a block), or is a real line at/below [indent] (ends it). */
    private fun isBlockEnd(line: String, indent: Int): Boolean {
        val trimmed = line.trim()
        if (trimmed.isEmpty() || trimmed.startsWith("#")) return false
        val lineIndent = line.length - line.trimStart().length
        return lineIndent <= indent
    }

    /**
     * Same idea as [isBlockEnd], but for the body of one `- apiGroups: ...`
     * rules: entry, where [entryIndent] is the entry's own `-` column: a
     * line at a shallower indent always ends it, but a line at the SAME
     * indent only ends it when it's itself a new list item (the next rule)
     * -- a plain `key:`/`- value` line at entryIndent would only occur here
     * for a sibling rules: entry, since every real key inside this entry's
     * body (apiGroups/resources/verbs and their block items) sits deeper.
     */
    private fun isEntryBlockEnd(line: String, entryIndent: Int): Boolean {
        val trimmed = line.trim()
        if (trimmed.isEmpty() || trimmed.startsWith("#")) return false
        val lineIndent = line.length - line.trimStart().length
        if (lineIndent < entryIndent) return true
        if (lineIndent > entryIndent) return false
        return RULE_ENTRY_START.matches(line)
    }

    private fun looksLikeRoleManifest(text: String): Boolean =
        text.lineSequence().any { ROLE_KIND.matches(it) }
}
