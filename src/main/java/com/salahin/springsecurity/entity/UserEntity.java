package com.salahin.springsecurity.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;
import org.antlr.v4.runtime.misc.NotNull;

import java.util.ArrayList;
import java.util.List;

@Data
@Entity
@Table(name = "user")
public class UserEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "id", nullable = false)
	private Integer id;

	@NotEmpty(message = "Username cannot be empty")
	@Column(name="username", nullable = false, unique = true)
	private String username;

	@NotEmpty(message = "Password cannot be empty")
	@Column(name="password", nullable = false)
	@JsonIgnore
	private String password;

	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
	@JoinColumn(name = "role_fk", referencedColumnName = "id")
	List<RoleEntity> roleList = new ArrayList<>();
}
