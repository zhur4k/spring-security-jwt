package com.springsecurityjwt.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/security/test")
public class SecurityJwtTestController {

    @PreAuthorize("hasAnyAuthority('USER', 'MODERATOR', 'SUPER_ADMIN')")
    @GetMapping("/user")
    public String testUser() {
        return "User";
    }

    @PreAuthorize("hasAnyAuthority('MODERATOR', 'SUPER_ADMIN')")
    @GetMapping("/moderator")
    public String testModerator() {
        return "Moderator";
    }

    @PreAuthorize("hasAuthority('SUPER_ADMIN')")
    @GetMapping("/super_admin")
    public String testSuperAdmin() {
        return "SuperAdmin";
    }
}
