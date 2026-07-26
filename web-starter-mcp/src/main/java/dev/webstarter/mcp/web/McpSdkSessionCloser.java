package dev.webstarter.mcp.web;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/** Closes a known node-local SDK session without exposing an orphaned ID to a client. */
@Component
public class McpSdkSessionCloser {

    private static final Logger log = LoggerFactory.getLogger(McpSdkSessionCloser.class);
    private static final String SESSION_HEADER = "Mcp-Session-Id";
    private final HttpServletStreamableServerTransportProvider provider;

    public McpSdkSessionCloser(HttpServletStreamableServerTransportProvider provider) {
        this.provider = provider;
    }

    public void close(HttpServletRequest source, HttpServletResponse response, String sessionId) {
        try {
            provider.service(new DeleteRequest(source, sessionId), new DiscardResponse(response));
        }
        catch (IOException | ServletException | RuntimeException exception) {
            log.warn("Unable to close node-local MCP SDK session", exception);
        }
    }

    private static final class DeleteRequest extends HttpServletRequestWrapper {
        private final String sessionId;

        private DeleteRequest(HttpServletRequest request, String sessionId) {
            super(request);
            this.sessionId = sessionId;
        }

        @Override
        public String getMethod() {
            return "DELETE";
        }

        @Override
        public String getHeader(String name) {
            return SESSION_HEADER.equalsIgnoreCase(name) ? sessionId : super.getHeader(name);
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            return SESSION_HEADER.equalsIgnoreCase(name)
                    ? Collections.enumeration(List.of(sessionId))
                    : super.getHeaders(name);
        }

        @Override
        public Enumeration<String> getHeaderNames() {
            List<String> names = new ArrayList<>();
            Enumeration<String> existing = super.getHeaderNames();
            while (existing != null && existing.hasMoreElements()) {
                names.add(existing.nextElement());
            }
            if (names.stream().noneMatch(SESSION_HEADER::equalsIgnoreCase)) {
                names.add(SESSION_HEADER);
            }
            return Collections.enumeration(names);
        }
    }

    private static final class DiscardResponse extends HttpServletResponseWrapper {
        private final PrintWriter writer = new PrintWriter(java.io.OutputStream.nullOutputStream());
        private final ServletOutputStream output = new ServletOutputStream() {
            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setWriteListener(WriteListener writeListener) {
            }

            @Override
            public void write(int value) {
            }
        };

        private DiscardResponse(HttpServletResponse response) {
            super(response);
        }

        @Override public void setStatus(int status) { }
        @Override public void sendError(int status) { }
        @Override public void sendError(int status, String message) { }
        @Override public void setHeader(String name, String value) { }
        @Override public void addHeader(String name, String value) { }
        @Override public void setContentType(String type) { }
        @Override public void setCharacterEncoding(String charset) { }
        @Override public void setContentLength(int length) { }
        @Override public void setContentLengthLong(long length) { }
        @Override public PrintWriter getWriter() { return writer; }
        @Override public ServletOutputStream getOutputStream() { return output; }
        @Override public void flushBuffer() { }
    }
}
