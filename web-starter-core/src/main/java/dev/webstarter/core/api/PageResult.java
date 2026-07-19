package dev.webstarter.core.api;

import java.util.List;

public record PageResult<T>(List<T> records, long total, long page, long size) {

    public PageResult {
        records = records == null ? List.of() : List.copyOf(records);
        if (total < 0 || page < 1 || size < 1) {
            throw new IllegalArgumentException("Invalid pagination values");
        }
    }

    public static <T> PageResult<T> of(List<T> records, long total, long page, long size) {
        return new PageResult<>(records, total, page, size);
    }
}
