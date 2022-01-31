package com.raj.userservice;

import com.raj.userservice.domain.Role;
import com.raj.userservice.domain.User;
import com.raj.userservice.service.UserService;
import java.util.ArrayList;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class  UserserviceApplication {

	public static void main(String[] args) {
		SpringApplication.run(UserserviceApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(UserService us) {
		return args -> {
			us.saveRole(new Role(null, "ROLE_USER"));
			us.saveRole(new Role(null, "ROLE_MANAGER"));
			us.saveRole(new Role(null, "ROLE_ADMIN"));
			us.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

			us.saveUser(new User(null,"Raj Mani", "rajkumar", "12345678", new ArrayList<>()));
			us.saveUser(new User(null,"Kamal Kumar", "kamal", "12345678", new ArrayList<>()));
			us.saveUser(new User(null,"Gopi Shankar", "gopi", "12345678", new ArrayList<>()));

			us.addRoleToUser("rajkumar", "ROLE_USER");
			us.addRoleToUser("rajkumar", "ROLE_MANAGER");
			us.addRoleToUser("rajkumar", "ROLE_SUPER_ADMIN");
			us.addRoleToUser("kamal", "ROLE_USER");
			us.addRoleToUser("kamal", "ROLE_ADMIN");
			us.addRoleToUser("gopi", "ROLE_USER");
		};
	}
}
