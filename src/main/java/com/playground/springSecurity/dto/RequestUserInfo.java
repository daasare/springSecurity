package com.playground.springSecurity.dto;

public record RequestUserInfo(
        String name,
        String username,
        String password,
        String role
) {}
