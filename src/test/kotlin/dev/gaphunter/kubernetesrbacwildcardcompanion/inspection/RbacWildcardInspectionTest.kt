package dev.gaphunter.kubernetesrbacwildcardcompanion.inspection

import com.intellij.testFramework.fixtures.BasePlatformTestCase

class RbacWildcardInspectionTest : BasePlatformTestCase() {

    override fun setUp() {
        super.setUp()
        myFixture.enableInspections(RbacWildcardInspection::class.java)
    }

    fun `test resources wildcard on ClusterRole produces a warning`() {
        myFixture.configureByText(
            "cluster-role.yaml",
            """
            kind: ClusterRole
            rules:
            - apiGroups: [""]
              resources: ["*"]
              verbs: ["get", "list"]
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.any { it.description?.contains("resources: [\"*\"]") == true })
    }

    fun `test verbs wildcard on secrets produces a warning`() {
        myFixture.configureByText(
            "role.yaml",
            """
            kind: Role
            rules:
            - apiGroups: [""]
              resources: ["secrets"]
              verbs: ["*"]
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.any { it.description?.contains("verbs: [\"*\"]") == true })
    }

    fun `test specific verbs on a non-sensitive resource produces no warning`() {
        myFixture.configureByText(
            "role.yaml",
            """
            kind: Role
            rules:
            - apiGroups: [""]
              resources: ["configmaps"]
              verbs: ["get", "list"]
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.none { it.description?.contains("RBAC rule") == true })
    }

    fun `test a non-yaml file is never scanned`() {
        myFixture.configureByText(
            "Notes.java",
            "String x = \"kind: Role\\nrules:\\n- resources: [\\\"secrets\\\"]\\n  verbs: [\\\"*\\\"]\";",
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.none { it.description?.contains("RBAC rule") == true })
    }

    fun `test a Deployment manifest is never scanned even if it happens to contain a rules key`() {
        myFixture.configureByText(
            "deployment.yaml",
            """
            kind: Deployment
            rules:
            - resources: ["secrets"]
              verbs: ["*"]
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.none { it.description?.contains("RBAC rule") == true })
    }
}
