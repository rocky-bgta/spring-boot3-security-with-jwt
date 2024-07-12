package com.salahin.springsecurity.controllers;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {
	
	@RequestMapping({"/admin-user"})
	public String adminUser(){
		return "Hello Admin";
	}
	
	@RequestMapping({"/normal-user"})
	public String normalUser(){
		return "Hello User";
	}
	
}
