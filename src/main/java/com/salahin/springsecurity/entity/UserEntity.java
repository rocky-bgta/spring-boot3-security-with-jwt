package com.salahin.springsecurity.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.Data;
import org.hibernate.annotations.GenericGenerator;


import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Data
@Entity
@Table(name = "user")
public class UserEntity {
	
	@Id
	@GeneratedValue(generator = "uuid")
	@GenericGenerator(name = "uuid", strategy = "uuid2")
	@Column(name = "id",unique = true)
	private UUID id;
	
	@Column(name="username", nullable = false)
	private String username;

	@Column(name = "user_id")
	private String userId;
	
	@Column(name="password", nullable = false)
	@JsonIgnore
	private String password;
	
	@Column(name="email_verified")
	private boolean emailVerified;
	
	@Column(name="status")
	private boolean status;
	
	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
	@JoinColumn(name = "role_fk", referencedColumnName = "id")
	List<RoleEntity> roleList = new ArrayList<>();
}
