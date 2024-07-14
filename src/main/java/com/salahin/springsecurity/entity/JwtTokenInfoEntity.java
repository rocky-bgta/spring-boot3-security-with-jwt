package com.salahin.springsecurity.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
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

	@Column(name = "token_type")
	private String tokenType;

	@Column(name="access_token")
	private String accessToken;

	@Column(name = "access_token_exp_in")
	private Long accessTokenExpIn;

	@Column(name="refreshed_token")
	private String refreshedToken;

	@Column(name = "refreshed_token_exp_in")
	private Long refreshedTokenExpIn;

	@Column(name="status")
	private boolean status;
}
