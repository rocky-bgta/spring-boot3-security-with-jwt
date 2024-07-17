package com.salahin.springsecurity.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class SlackUserInfoModel {
    @JsonIgnore
    private static final String slackDomain = "https://slack.com/";

    private boolean ok;
    private String sub;

    @JsonProperty(slackDomain+"user_id")
    private String userId;

    @JsonProperty("https://slack.com/team_id")
    private String teamId;

    private String email;
    
    @JsonProperty("email_verified")
    private boolean emailVerified;

    @JsonProperty("date_email_verified")
    private long dateEmailVerified;

    private String name;
    private String picture;

    @JsonProperty("given_name")
    private String givenName;

    @JsonProperty("family_name")
    private String familyName;

    private String locale;

    @JsonProperty(slackDomain+"team_name")
    private String teamName;

    @JsonProperty(slackDomain+"team_domain")
    private String teamDomain;

    @JsonProperty(slackDomain+"user_image_24")
    private String userImage24;

    @JsonProperty(slackDomain+"user_image_32")
    private String userImage32;

    @JsonProperty(slackDomain+"team_image_default")
    private boolean teamImageDefault;
}
