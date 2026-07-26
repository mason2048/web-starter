package dev.webstarter.tooling.module;

import dev.webstarter.tooling.Checks;

public record ModuleSpec(
        String name,
        String label,
        String plural,
        String table,
        String route,
        String migrationVersion,
        long permissionIdBase,
        long menuId,
        boolean withMcp) {

    public ModuleSpec {
        name = Checks.moduleName(name);
        label = Checks.label(label);
        plural = Checks.moduleName(plural);
        table = Checks.table(table);
        route = Checks.route(route);
        migrationVersion = Checks.migrationVersion(migrationVersion);
        if (permissionIdBase <= 0 || permissionIdBase > Long.MAX_VALUE - 3) {
            throw Checks.usage("permission id base must allow four positive consecutive ids");
        }
        if (menuId <= 0) {
            throw Checks.usage("menu id must be positive");
        }
        if (menuId >= permissionIdBase && menuId <= permissionIdBase + 3) {
            throw Checks.usage("menu id must not overlap the permission id range");
        }
    }

    public String className() {
        return Checks.pascalCase(name);
    }

    public String permissionConstant() {
        return name.toUpperCase(java.util.Locale.ROOT);
    }

    public ModuleSpec withMcpEnabled(boolean enabled) {
        if (withMcp == enabled) {
            return this;
        }
        return new ModuleSpec(
                name, label, plural, table, route, migrationVersion, permissionIdBase, menuId, enabled);
    }

    public static ModuleSpec from(
            String name,
            String label,
            String plural,
            String table,
            String route,
            String migrationVersion,
            String permissionIdBase,
            String menuId,
            boolean withMcp) {
        String checkedName = Checks.moduleName(name);
        String effectivePlural = plural == null || plural.isBlank() ? checkedName + "s" : plural;
        String effectiveTable = table == null || table.isBlank() ? "biz_" + checkedName : table;
        String effectiveRoute = route == null || route.isBlank() ? "/" + effectivePlural : route;
        return new ModuleSpec(
                checkedName,
                label,
                effectivePlural,
                effectiveTable,
                effectiveRoute,
                migrationVersion,
                Checks.positiveLong(permissionIdBase, "permission id base"),
                Checks.positiveLong(menuId, "menu id"),
                withMcp);
    }
}
