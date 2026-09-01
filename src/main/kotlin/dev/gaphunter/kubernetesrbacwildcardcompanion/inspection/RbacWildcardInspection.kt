package dev.gaphunter.kubernetesrbacwildcardcompanion.inspection

import com.intellij.codeInspection.InspectionManager
import com.intellij.codeInspection.LocalInspectionTool
import com.intellij.codeInspection.ProblemDescriptor
import com.intellij.codeInspection.ProblemHighlightType
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiFile
import dev.gaphunter.kubernetesrbacwildcardcompanion.detect.RbacManifestScanner
import dev.gaphunter.kubernetesrbacwildcardcompanion.model.RbacHit
import dev.gaphunter.kubernetesrbacwildcardcompanion.model.WildcardSide
import dev.gaphunter.kubernetesrbacwildcardcompanion.review.ReviewPrompt

/**
 * Flags a `Role`/`ClusterRole` rule that combines a wildcard (`"*"`) in
 * `verbs` or `resources` with a resource on the OWASP Kubernetes Top 10
 * (K03, Overly Permissive RBAC Configurations) sensitive list --
 * `secrets`, `pods/exec`, `clusterrolebindings`. This is the most
 * common path to privilege escalation after a single pod is
 * compromised in a cluster.
 *
 * Runs via [checkFile] (whole-file text scan), same reasoning as
 * `MissingResourceLimitInspection` (k8s-resource-limit-companion):
 * detection is plain-text line scanning against indentation, not a PSI
 * walk of a specific grammar -- see `build.gradle.kts` for why no YAML
 * PSI dependency is taken.
 */
class RbacWildcardInspection : LocalInspectionTool() {

    companion object {
        const val MAX_FILE_LENGTH = 500_000
        private val YAML_FILE_NAME = Regex("""^[^.]+\.ya?ml$""", RegexOption.IGNORE_CASE)
    }

    override fun checkFile(file: PsiFile, manager: InspectionManager, isOnTheFly: Boolean): Array<ProblemDescriptor>? {
        val virtualFile = file.virtualFile ?: return null
        if (!YAML_FILE_NAME.matches(virtualFile.name)) return null

        val text = file.text
        if (text.length > MAX_FILE_LENGTH) return null

        val hits = RbacManifestScanner.scan(text)
        if (hits.isEmpty()) return null

        val document = file.viewProvider.document ?: return null
        val problems = mutableListOf<ProblemDescriptor>()

        // A single rule line can produce several hits (one per sensitive
        // resource under a resources: ["*"] wildcard) -- dedupe to one
        // problem descriptor per line so the same line isn't highlighted
        // with N overlapping warnings.
        for (hit in hits.distinctBy { it.lineNumber }) {
            val sameLineHits = hits.filter { it.lineNumber == hit.lineNumber }
            if (hit.lineNumber - 1 !in 0 until document.lineCount) continue
            val lineStartOffset = document.getLineStartOffset(hit.lineNumber - 1)
            val lineEndOffset = document.getLineEndOffset(hit.lineNumber - 1)
            val anchor = leafElementAt(file, lineStartOffset) ?: continue
            val anchorStart = anchor.textRange.startOffset
            val relativeRange = TextRange(
                (lineStartOffset - anchorStart).coerceAtLeast(0),
                (lineEndOffset - anchorStart).coerceAtMost(anchor.textLength),
            )
            if (relativeRange.startOffset >= relativeRange.endOffset) continue

            problems += manager.createProblemDescriptor(
                anchor,
                relativeRange,
                messageFor(sameLineHits),
                ProblemHighlightType.GENERIC_ERROR_OR_WARNING,
                isOnTheFly,
            )

            ReviewPrompt.recordHit(file.project, "${virtualFile.path}:${hit.lineNumber}")
        }

        return if (problems.isEmpty()) null else problems.toTypedArray()
    }

    private fun messageFor(hits: List<RbacHit>): String {
        val resources = hits.map { it.sensitiveResource }.distinct().sorted().joinToString(", ")
        return when (hits.first().side) {
            WildcardSide.RESOURCES ->
                "RBAC rule grants resources: [\"*\"] -- every resource including sensitive ones ($resources) is covered by this wildcard; a compromised pod using this role can escalate privileges (OWASP Kubernetes Top 10 K03)"
            WildcardSide.VERBS ->
                "RBAC rule grants verbs: [\"*\"] on sensitive resource(s) ($resources) -- every action (get/create/delete/...) is allowed; a compromised pod using this role can escalate privileges (OWASP Kubernetes Top 10 K03)"
        }
    }

    private fun leafElementAt(file: PsiFile, startOffset: Int): PsiElement? {
        if (startOffset < 0 || startOffset >= file.textLength) return null
        var element = file.findElementAt(startOffset) ?: return file
        while (element.firstChild != null) {
            element = element.firstChild
        }
        return element
    }
}
