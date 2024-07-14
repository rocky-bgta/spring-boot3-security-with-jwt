package com.salahin.springsecurity.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.Data;
import org.hibernate.annotations.GenericGenerator;

import java.util.UUID;

@Data
@Entity
@Table(name = "jwt_token_info")
public class JwtTokenInfoEntity {
	
	@Id
	@GeneratedValue(generator = "uuid")
	@GenericGenerator(name = "uuid", strategy = "uuid2")
	@Column(name = "id",unique = true)
	private UUID id;
	
	@Column(name="user_id")
	private String userId;

	@Column(name="username")
	private String username;

	@Column(name="access_token")
	private String accessToken;

	@Column(name="refreshed_token")
	private String refreshedToken;

	@Column(name="status")
	private boolean status;
}
