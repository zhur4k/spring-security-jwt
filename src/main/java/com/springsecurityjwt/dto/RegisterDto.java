package com.springsecurityjwt.dto;


import javax.validation.constraints.NotNull;

public record RegisterDto(
        @NotNull(message = "Username cannot be empty")
        String username,
        @NotNull(message = "Password cannot be empty")
        String password,
        @NotNull(message = "Name cannot be empty")
        String name
) {
}
