from __future__ import annotations

import json
import io
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout

import generated_module_plan as plan
import prepare_release_runtime_acceptance as setup


class GeneratedModulePlanTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="web-starter-generated-plan-")
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def fixture(
        self,
        *,
        with_mcp: bool = True,
        plural: str = "assets",
        route: str = "/assets",
    ) -> Path:
        artifact = self.root / "demo-admin-asset"
        plan_path = artifact / plan.PLAN_RELATIVE
        plan_path.parent.mkdir(parents=True)
        migration = (
            self.root / "demo-admin-admin/src/main/resources/db/migration/"
            "V202607200001__create_asset_module.sql"
        )
        migration.parent.mkdir(parents=True)
        migration.write_text("CREATE TABLE biz_asset (id BIGINT);\n", encoding="utf-8")
        browser = self.root / "demo-admin-web/e2e/generated/asset-runtime.spec.ts"
        browser.parent.mkdir(parents=True)
        title = "generated asset module closes browser CRUD conflict authorization and audit loop"
        browser.write_text(f"test({title!r}, async () => {{}})\n", encoding="utf-8")
        lines = [
            "schemaVersion=1",
            "module=asset",
            "artifactId=demo-admin-asset",
            "migration=demo-admin-admin/src/main/resources/db/migration/V202607200001__create_asset_module.sql",
            f"route={route}",
            f"plural={plural}",
            f"apiPath=/api/{plural}",
            "resourceType=asset",
            "permissions=asset:list,asset:create,asset:update,asset:remove",
            "browserTest=demo-admin-web/e2e/generated/asset-runtime.spec.ts",
            f"browserTitle={title}",
            f"withMcp={'true' if with_mcp else 'false'}",
        ]
        if with_mcp:
            runtime = (
                artifact / "src/test/java/dev/example/asset/mcp/AssetMcpRuntimeIT.java"
            )
            runtime.parent.mkdir(parents=True)
            runtime.write_text("class AssetMcpRuntimeIT {}\n", encoding="utf-8")
            lines.extend([
                "mcpRuntimeTest=dev.example.asset.mcp.AssetMcpRuntimeIT",
                "mcpTools=asset.list,asset.get,asset.create,asset.update,asset.remove",
            ])
        plan_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return plan_path

    def test_discovers_exact_browser_migration_permissions_and_mcp_sources(self) -> None:
        self.fixture()
        modules = plan.discover(self.root)
        self.assertEqual(1, len(modules))
        module = modules[0]
        self.assertEqual("asset", module["module"])
        self.assertEqual("demo-admin-asset", module["artifactId"])
        self.assertEqual([
            "asset:list", "asset:create", "asset:update", "asset:remove"
        ], module["permissions"])
        self.assertEqual("dev.example.asset.mcp.AssetMcpRuntimeIT", module["mcpRuntimeTest"])
        for field in (
            "planSha256", "migrationSha256", "browserTestSha256", "mcpRuntimeTestSha256"
        ):
            self.assertRegex(module[field], r"^[0-9a-f]{64}$")

    def test_non_mcp_plan_has_an_exact_smaller_field_set(self) -> None:
        self.fixture(with_mcp=False)
        module = plan.discover(self.root)[0]
        self.assertFalse(module["withMcp"])
        self.assertNotIn("mcpRuntimeTest", module)

    def test_frontend_route_is_independent_of_the_api_resource_plural(self) -> None:
        self.fixture(plural="inventory", route="/asset-console")
        module = plan.discover(self.root)[0]
        self.assertEqual("/asset-console", module["route"])
        self.assertEqual("inventory", module["plural"])
        self.assertEqual("/api/inventory", module["apiPath"])

    def test_artifact_validation_accepts_the_max_generated_identity_length(self) -> None:
        maximum = "a" * 50 + "-" + "b" * 31
        self.assertEqual(82, len(maximum))
        self.assertIsNotNone(plan.ARTIFACT.fullmatch(maximum))
        self.assertIsNone(plan.ARTIFACT.fullmatch(maximum + "c"))

    def test_misplaced_plan_is_rejected_instead_of_silently_ignored(self) -> None:
        source = self.fixture()
        misplaced = self.root / "docs/nested/module-acceptance-plan.properties"
        misplaced.parent.mkdir(parents=True)
        misplaced.write_bytes(source.read_bytes())

        with self.assertRaisesRegex(
            (plan.GeneratedModulePlanError, ValueError),
            "declared artifact|relative",
        ):
            plan.discover(self.root)

    def test_rejects_duplicate_unknown_drifted_and_unsafe_metadata(self) -> None:
        path = self.fixture()
        cases = {
            "duplicate": path.read_text(encoding="utf-8") + "module=asset\n",
            "unknown": path.read_text(encoding="utf-8") + "command=echo unsafe\n",
            "scope-drift": path.read_text(encoding="utf-8").replace(
                "asset:remove", "asset:admin", 1
            ),
            "browser-drift": path.read_text(encoding="utf-8").replace(
                "demo-admin-web/e2e/generated/asset-runtime.spec.ts",
                "../outside.spec.ts",
                1,
            ),
        }
        for label, content in cases.items():
            with self.subTest(label=label):
                path.write_text(content, encoding="utf-8")
                with self.assertRaises(plan.GeneratedModulePlanError):
                    plan.discover(self.root)
                path.write_text(self.fixture_content(), encoding="utf-8")

    def fixture_content(self) -> str:
        return "\n".join([
            "schemaVersion=1",
            "module=asset",
            "artifactId=demo-admin-asset",
            "migration=demo-admin-admin/src/main/resources/db/migration/V202607200001__create_asset_module.sql",
            "route=/assets",
            "plural=assets",
            "apiPath=/api/assets",
            "resourceType=asset",
            "permissions=asset:list,asset:create,asset:update,asset:remove",
            "browserTest=demo-admin-web/e2e/generated/asset-runtime.spec.ts",
            "browserTitle=generated asset module closes browser CRUD conflict authorization and audit loop",
            "withMcp=true",
            "mcpRuntimeTest=dev.example.asset.mcp.AssetMcpRuntimeIT",
            "mcpTools=asset.list,asset.get,asset.create,asset.update,asset.remove",
            "",
        ])

    def test_output_is_private_exact_json_and_cannot_be_overwritten(self) -> None:
        self.fixture()
        output = self.root / "plan.json"
        self.assertEqual(0, plan.main([
            "--repository-root", str(self.root), "--output", str(output)
        ]))
        self.assertEqual(0o600, output.stat().st_mode & 0o777)
        document = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual({"schemaVersion", "modules"}, set(document))
        self.assertEqual(2, plan.main([
            "--repository-root", str(self.root), "--output", str(output)
        ]))

    def test_list_modes_emit_only_validated_explicit_test_targets(self) -> None:
        self.fixture()
        browser = io.StringIO()
        with redirect_stdout(browser):
            self.assertEqual(0, plan.main([
                "--repository-root", str(self.root), "--list-browser"
            ]))
        self.assertEqual(
            "demo-admin-asset\tdemo-admin-web/e2e/generated/asset-runtime.spec.ts\t"
            "generated asset module closes browser CRUD conflict authorization and audit loop\n",
            browser.getvalue(),
        )

        mcp = io.StringIO()
        with redirect_stdout(mcp):
            self.assertEqual(0, plan.main([
                "--repository-root", str(self.root), "--list-mcp"
            ]))
        self.assertEqual(
            "demo-admin-asset\tdev.example.asset.mcp.AssetMcpRuntimeIT\n",
            mcp.getvalue(),
        )

    def test_output_rejects_a_symbolic_link_parent(self) -> None:
        self.fixture()
        real_parent = self.root / "real-output"
        real_parent.mkdir()
        linked_parent = self.root / "linked-output"
        linked_parent.symlink_to(real_parent, target_is_directory=True)

        with self.assertRaisesRegex(
            plan.GeneratedModulePlanError, "non-symlink directory"
        ):
            plan.write_private_json(
                linked_parent / "plan.json", {"schemaVersion": 1, "modules": []}
            )

    def test_release_setup_adds_only_the_generated_crud_permissions(self) -> None:
        self.fixture()
        modules, scopes = setup._generated_runtime_inputs(self.root)
        self.assertEqual(["asset"], [module["module"] for module in modules])
        self.assertEqual([
            "system:info",
            "project:list",
            "project:create",
            "project:update",
            "project:remove",
            "audit:list",
            "asset:list",
            "asset:create",
            "asset:update",
            "asset:remove",
        ], scopes)


if __name__ == "__main__":
    unittest.main()
