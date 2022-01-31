package com.raj.userservice.service;

import com.raj.userservice.domain.Role;
import com.raj.userservice.domain.User;
import com.raj.userservice.repo.RoleRepo;
import com.raj.userservice.repo.UserRepo;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.management.relation.RoleNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service @RequiredArgsConstructor @Transactional @Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {
    private final RoleRepo roleRepo;
    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;

    @Override
    public User saveUser(User user) {
        log.info("Saving new user {}", user.getName());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepo.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("Saving new role {}", role.getName());
        return roleRepo.save(role);
    }

    @Override
    public void addRoleToUser(String userName, String roleName) {
        log.info("Adding role {} to user {}", roleName, userName);
        User user = userRepo.findByUsername(userName);
        if(user == null) {
            log.error("User {} not found in db", userName);
            throw new UsernameNotFoundException("User not found in db");
        }
        Role role = roleRepo.findByName(roleName);
        user.getRoles().add(role);
    }

    @Override
    public void addRolesToUser(String userName, List<String> roles) {
        log.info("Adding roles to user {}", userName);
        User user = userRepo.findByUsername(userName);
        if(user == null) {
            log.error("User {} not found in db", userName);
            throw new UsernameNotFoundException("User not found in db");
        } else {
        roles.forEach(roleName->{
//            Role role = roleRepo.findByName(roleName);
            user.getRoles().add(roleRepo.findByName(roleName));
        });
        }
    }

    @Override
    public User getUser(String username) {
        log.info("Fetching user {}", username);
        return userRepo.findByUsername(username);
    }

    @Override
    public List<User> getUsers() {
        log.info("Fetching all users");
        return userRepo.findAll();
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepo.findByUsername(username);
        if(user == null){
            log.error("User {} not found in db", username);
            throw new UsernameNotFoundException("User not found in db");
        } else {
            log.info("User found:{}", username);
        }
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        });
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), authorities);
    }
}
