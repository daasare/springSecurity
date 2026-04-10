package com.playground.springSecurity.dto;

public record RequestUserRegistrationInfo(
        String name,
        String username,
        String password,
        String role
) {}
