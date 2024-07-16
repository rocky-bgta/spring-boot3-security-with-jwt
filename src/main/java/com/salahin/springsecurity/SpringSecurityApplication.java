package com.salahin.springsecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

//@SpringBootApplication(exclude = {
//	org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class}
//)
@SpringBootApplication
@EnableWebSecurity(debug = true)
public class SpringSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityApplication.class, args);
	}

}
