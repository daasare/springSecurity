package com.playground.springSecurity.service;

import com.playground.springSecurity.dto.RequestUserInfo;
import com.playground.springSecurity.dto.RequestUserRegistrationInfo;
import com.playground.springSecurity.entity.Users;
import com.playground.springSecurity.enums.Role;
import com.playground.springSecurity.repository.UsersRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class UsersService {

    private final UsersRepository usersRepository;
    private final PasswordEncoder passwordEncoder;

    public ResponseEntity<?> fetchAllUsers() {
        List<Users> users = usersRepository.findAll();
        if (users.isEmpty()) return ResponseEntity.ok("no user records");
        return ResponseEntity.ok(users);
    }

    public ResponseEntity<String> addUser(RequestUserInfo request) {
        Users newUser = new Users();

        newUser.setName(request.name());
        newUser.setUsername(request.username());
        newUser.setPassword(passwordEncoder.encode(request.password()));

        usersRepository.save(newUser);

        return ResponseEntity.status(HttpStatus.CREATED).body("new user added");
    }

    public ResponseEntity<?> registerUser(RequestUserRegistrationInfo info) {
        Users newUser = new Users();

        newUser.setName(info.name());
        newUser.setUsername(info.username());
        newUser.setPassword(passwordEncoder.encode(info.password()));

        // check if the role intended to assign to the new user account
        // is valid or accepted by the system
        try {
            Arrays.stream(Role.values()).forEach(
                    role -> {
                        if (role.name().equals(info.role())) {
                            newUser.setRole(role);
                        }
                    }
            );
        }catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    e.getLocalizedMessage()
            );
        }
        usersRepository.save(newUser);
        return ResponseEntity.ok("user registered successfully");
    }
}
