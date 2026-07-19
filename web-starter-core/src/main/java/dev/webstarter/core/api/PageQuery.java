package dev.webstarter.core.api;

public record PageQuery(long page, long size) {

    public static final long DEFAULT_PAGE = 1;
    public static final long DEFAULT_SIZE = 20;
    public static final long MAX_SIZE = 200;

    public PageQuery {
        page = Math.max(page, DEFAULT_PAGE);
        size = size < 1 ? DEFAULT_SIZE : Math.min(size, MAX_SIZE);
    }
}
