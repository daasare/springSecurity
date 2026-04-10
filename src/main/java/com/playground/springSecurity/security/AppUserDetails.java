package com.playground.springSecurity.security;

import com.playground.springSecurity.entity.Users;
import com.playground.springSecurity.enums.Permission;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public class AppUserDetails implements UserDetails {

    private final Users user;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        /**
         * All roles and permissions are made "GrantedAuthority" type,
         * By making them "GrantedAuthority", it allows Spring's "Authorization"
         * Filter to do a simple "String Match" (hasRole("ADMIN")) when a user tries to access a
         * protected resource.
         * **/

        // create an empty set to collect or store all roles and permission the user have
        Set<GrantedAuthority> authorities = new HashSet<>();

        // extract and save the role assign to a user "GrantedAuthority" type
        GrantedAuthority role = new SimpleGrantedAuthority("ROLE_"+user.getRole().name());

        // extract and save all permissions assigned to a user as "GrantedAuthority" type
        Set<GrantedAuthority> permissions = user.getRole().getPermissions().stream().map(
                permission -> new SimpleGrantedAuthority(permission.name())
        ).collect(Collectors.toSet());

        authorities.add(role);
        authorities.addAll(permissions);

        return authorities;
    }

    @Override
    public @Nullable String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }
}
