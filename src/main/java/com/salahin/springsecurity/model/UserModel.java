package com.salahin.springsecurity.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.salahin.springsecurity.entity.RoleEntity;
import lombok.Data;

import java.util.List;
import java.util.UUID;

@Data
public class UserModel {
	private Integer id;
	private String username;

	@JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
	private String password;
	private List<RoleEntity> roleList;
}
