package dev.gaphunter.kubernetesrbacwildcardcompanion.detect

import dev.gaphunter.kubernetesrbacwildcardcompanion.model.WildcardSide
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RbacManifestScannerTest {

    @Test
    fun `flags resources wildcard flow style on ClusterRole`() {
        val yaml = """
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRole
            metadata:
              name: dangerous-role
            rules:
            - apiGroups: [""]
              resources: ["*"]
              verbs: ["get", "list"]
        """.trimIndent()

        val hits = RbacManifestScanner.scan(yaml)

        assertTrue(hits.isNotEmpty())
        assertTrue(hits.all { it.side == WildcardSide.RESOURCES })
        assertTrue(hits.any { it.sensitiveResource == "secrets" })
        assertTrue(hits.any { it.sensitiveResource == "pods/exec" })
        assertTrue(hits.any { it.sensitiveResource == "clusterrolebindings" })
    }

    @Test
    fun `flags verbs wildcard against named sensitive resource, block style`() {
        val yaml = """
            kind: Role
            rules:
            - apiGroups:
              - ""
              resources:
              - secrets
              verbs:
              - "*"
        """.trimIndent()

        val hits = RbacManifestScanner.scan(yaml)

        assertEquals(1, hits.size)
        assertEquals("secrets", hits[0].sensitiveResource)
        assertEquals(WildcardSide.VERBS, hits[0].side)
    }

    @Test
    fun `flags verbs wildcard against pods_exec, flow style`() {
        val yaml = """
            kind: ClusterRole
            rules:
            - apiGroups: [""]
              resources: ["pods/exec"]
              verbs: ["*"]
        """.trimIndent()

        val hits = RbacManifestScanner.scan(yaml)

        assertEquals(1, hits.size)
        assertEquals("pods/exec", hits[0].sensitiveResource)
        assertEquals(WildcardSide.VERBS, hits[0].side)
    }

    @Test
    fun `does not flag specific verbs against a specific non-sensitive resource`() {
        val yaml = """
            kind: Role
            rules:
            - apiGroups: [""]
              resources: ["configmaps"]
              verbs: ["get", "list"]
        """.trimIndent()

        assertTrue(RbacManifestScanner.scan(yaml).isEmpty())
    }

    @Test
    fun `does not flag verbs wildcard against a non-sensitive resource`() {
        val yaml = """
            kind: Role
            rules:
            - apiGroups: [""]
              resources: ["configmaps"]
              verbs: ["*"]
        """.trimIndent()

        assertTrue(RbacManifestScanner.scan(yaml).isEmpty())
    }

    @Test
    fun `does not flag a resource wildcard combined with specific verbs elsewhere in same file when rule itself is safe`() {
        val yaml = """
            kind: Role
            rules:
            - apiGroups: [""]
              resources: ["pods"]
              verbs: ["get"]
        """.trimIndent()

        assertTrue(RbacManifestScanner.scan(yaml).isEmpty())
    }

    @Test
    fun `ignores non-Role manifests entirely`() {
        val yaml = """
            kind: Deployment
            metadata:
              name: whatever
            rules:
            - apiGroups: [""]
              resources: ["secrets"]
              verbs: ["*"]
        """.trimIndent()

        assertTrue(RbacManifestScanner.scan(yaml).isEmpty())
    }

    @Test
    fun `handles multiple rules entries, only flags the dangerous one`() {
        val yaml = """
            kind: ClusterRole
            rules:
            - apiGroups: [""]
              resources: ["configmaps"]
              verbs: ["get"]
            - apiGroups: [""]
              resources: ["secrets"]
              verbs: ["*"]
        """.trimIndent()

        val hits = RbacManifestScanner.scan(yaml)

        assertEquals(1, hits.size)
        assertEquals("secrets", hits[0].sensitiveResource)
        assertEquals(6, hits[0].lineNumber)
    }

    @Test
    fun `reports the correct line number for a block-style rule`() {
        val yaml = """
            kind: Role
            rules:
            - apiGroups:
              - ""
              resources:
              - secrets
              verbs:
              - "*"
        """.trimIndent()

        val hits = RbacManifestScanner.scan(yaml)

        assertEquals(1, hits.size)
        assertEquals(3, hits[0].lineNumber)
    }
}
