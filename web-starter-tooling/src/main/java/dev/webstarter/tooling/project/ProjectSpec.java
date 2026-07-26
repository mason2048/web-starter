package dev.webstarter.tooling.project;

import dev.webstarter.tooling.Checks;

import java.nio.file.Path;

public record ProjectSpec(
        String name,
        String productName,
        String groupId,
        String packagePrefix,
        String database,
        String environmentPrefix,
        Path output) {

    public ProjectSpec {
        name = Checks.slug(name, "project name");
        productName = Checks.productName(productName);
        groupId = Checks.javaPackage(groupId, "group id");
        packagePrefix = Checks.javaPackage(packagePrefix, "package prefix");
        if (!groupId.equals(packagePrefix)) {
            throw Checks.usage("the first tooling version requires --group-id and --package-prefix to match");
        }
        database = Checks.database(database);
        environmentPrefix = Checks.environmentPrefix(environmentPrefix);
        output = output.toAbsolutePath().normalize();
    }

    public String javaPath() {
        return packagePrefix.replace('.', '/');
    }

    public String pascalName() {
        return Checks.pascalCase(name);
    }

    public String camelName() {
        String pascal = pascalName();
        return Character.toLowerCase(pascal.charAt(0)) + pascal.substring(1);
    }

    public String compactName() {
        return name.replace("-", "");
    }
}
