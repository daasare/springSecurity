package com.playground.springSecurity.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Set;

@Getter
public enum Role {

    ADMIN(Set.of(Permission.WRITE, Permission.READ, Permission.DELETE)),
    USER(Set.of(Permission.READ));


    private final Set<Permission> permissions;

    Role(Set<Permission> permissions) {
        this.permissions = permissions;
    }

}
