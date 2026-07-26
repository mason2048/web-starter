package dev.webstarter.tooling.module;

import dev.webstarter.tooling.Checks;
import dev.webstarter.tooling.ToolingException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

public record WorkspaceIdentity(Path root, String groupId, String artifactId, String version) {

    public static WorkspaceIdentity load(Path workspace) {
        Path root = Checks.existingDirectory(workspace, "workspace");
        Path pom = root.resolve("pom.xml");
        if (!Files.isRegularFile(pom, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(pom)) {
            throw new ToolingException(ToolingException.PREREQUISITE, "workspace root pom.xml is missing");
        }
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            Element project = factory.newDocumentBuilder().parse(pom.toFile()).getDocumentElement();
            String groupId = directText(project, "groupId");
            String artifactId = directText(project, "artifactId");
            String version = directText(project, "version");
            if (groupId == null || artifactId == null || version == null) {
                throw Checks.conflict("root pom must declare direct groupId, artifactId, and version elements");
            }
            Checks.javaPackage(groupId, "root group id");
            Checks.slug(artifactId, "root artifact id");
            return new WorkspaceIdentity(root, groupId, artifactId, version);
        }
        catch (ToolingException exception) {
            throw exception;
        }
        catch (Exception exception) {
            throw new ToolingException(ToolingException.PREREQUISITE, "unable to parse root pom.xml", exception);
        }
    }

    public Path adminDirectory() {
        return requiredDirectory(artifactId + "-admin");
    }

    public Path webDirectory() {
        return requiredDirectory(artifactId + "-web");
    }

    public Path packagePath() {
        return Path.of(groupId.replace('.', '/'));
    }

    private Path requiredDirectory(String name) {
        Path result = root.resolve(name);
        if (!Files.isDirectory(result, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(result)) {
            throw Checks.conflict("expected workspace module is missing: " + name);
        }
        return result;
    }

    private static String directText(Element parent, String name) {
        List<String> values = new ArrayList<>();
        for (Node child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element element && name.equals(element.getTagName())) {
                values.add(element.getTextContent().trim());
            }
        }
        return values.size() == 1 ? values.get(0) : null;
    }
}
