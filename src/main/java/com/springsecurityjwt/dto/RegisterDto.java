package com.springsecurityjwt.dto;


import com.springsecurityjwt.model.Role;

import javax.validation.constraints.NotNull;
import java.util.Set;

public record RegisterDto(
        @NotNull(message = "Username cannot be empty")
        String username,
        @NotNull(message = "Password cannot be empty")
        String password,
        @NotNull(message = "Name cannot be empty")
        String name,
        @NotNull(message = "Role cannot be empty")
        Set<Role> role
) {
}
