package com.salahin.springsecurity.model;

import lombok.Data;

@Data

public class UserInfoModel {
	private String organizationId;
	private String userId;
	private String organizationDomain;
	private String organizationName;
	private String userName;
	private String email;
	private String image;
}
