package dev.webstarter.system.service;

import dev.webstarter.core.api.PageResult;
import dev.webstarter.system.dto.UserCreateRequest;
import dev.webstarter.system.dto.UserPasswordResetRequest;
import dev.webstarter.system.dto.UserResponse;
import dev.webstarter.system.dto.UserUpdateRequest;

public interface UserService {
    PageResult<UserResponse> page(long page, long size, String keyword, String status);
    UserResponse get(Long id);
    UserResponse create(UserCreateRequest request);
    UserResponse update(Long id, UserUpdateRequest request);
    void resetPassword(Long id, UserPasswordResetRequest request);
    void remove(Long id);
}
