package com.salahin.springsecurity.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthResponse {

    private String token_type;
    private Long expires_in;
    private String access_token;
    private List<String> roles;
    private String message;
}
