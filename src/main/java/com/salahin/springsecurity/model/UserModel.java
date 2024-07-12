package com.salahin.springsecurity.model;

import com.salahin.springsecurity.entity.RoleEntity;
import lombok.Data;

import java.util.List;
import java.util.UUID;

@Data
public class UserModel {
	private UUID id;
	private String username;
	private String password;
	private List<RoleEntity> roleList;
}
