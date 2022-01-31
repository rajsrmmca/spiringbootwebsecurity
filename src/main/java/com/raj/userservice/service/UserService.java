package com.raj.userservice.service;

import com.raj.userservice.domain.Role;
import com.raj.userservice.domain.User;
import java.util.List;

public interface UserService {
    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String userName, String roleName);
    void addRolesToUser(String userName, List<String> roles);
    User getUser(String username);
    List<User>getUsers();
}