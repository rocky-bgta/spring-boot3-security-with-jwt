package com.salahin.springsecurity.entity;

import jakarta.persistence.*;
import lombok.Data;
import org.hibernate.annotations.GenericGenerator;

import java.util.UUID;

@Data
@Entity
@Table(name = "slack_user_info")
public class SlackUserInfoEntity {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "id", nullable = false)
	Long id;

	@Column(name = "organization_Id")
	private String organizationId;

	@Column(name = "user_id")
	private String userId;

	@Column(name = "organization_domain")
	private String organizationDomain;

	@Column(name = "organization_name")
	private String organizationName;

	@Column(name = "user_name")
	private String userName;

	@Column(name = "email")
	private String email;

	@Column(name = "image")
	private String image;
}
