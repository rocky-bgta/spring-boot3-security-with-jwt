package com.salahin.springsecurity.service;

import com.salahin.springsecurity.entity.JwtTokenInfoEntity;
import com.salahin.springsecurity.entity.UserEntity;
import com.salahin.springsecurity.repository.JwtTokenRepository;
import com.salahin.springsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class JwtTokenService {

    @Autowired
    JwtTokenRepository jwtTokenRepository;

    @Autowired
    UserRepository userRepository;

    public void saveTokenInfo(String username, String accessToken,Long accessTokenTime,
                              String refreshToken, Long refreshTokenTime, String tokenType){
        UserEntity user = userRepository.findByUsername(username);
        JwtTokenInfoEntity jwtTokenInfoEntity = new JwtTokenInfoEntity();
        jwtTokenInfoEntity.setAccessToken(accessToken);
        jwtTokenInfoEntity.setAccessTokenExpIn(accessTokenTime);
        jwtTokenInfoEntity.setRefreshedToken(refreshToken);
        jwtTokenInfoEntity.setRefreshedTokenExpIn(refreshTokenTime);
        jwtTokenInfoEntity.setTokenType(tokenType);
        jwtTokenInfoEntity.setUserId(user.getId().toString());
        jwtTokenInfoEntity.setUsername(username);
        jwtTokenInfoEntity.setStatus(true);
        jwtTokenRepository.save(jwtTokenInfoEntity);
    }

    public void deleteAccessToken(String username){
       // UserEntity user = userRepository.findByUsername(username);
        JwtTokenInfoEntity jwtTokenInfoEntity = jwtTokenRepository.findByUsername(username);
        jwtTokenRepository.delete(jwtTokenInfoEntity);
    }


    public void updateAccessToken(String username, String accessToken, Long accessTokenTime){
        JwtTokenInfoEntity jwtTokenInfoEntity = jwtTokenRepository.findByUsername(username);
        jwtTokenInfoEntity.setAccessToken(accessToken);
        jwtTokenInfoEntity.setAccessTokenExpIn(accessTokenTime);
        jwtTokenRepository.save(jwtTokenInfoEntity);
    }

    public Boolean isAccessTokeExist(String username){
        Integer jwtTokenInfoEntity = jwtTokenRepository.countJwtTokenInfoEntityByUsername(username);
        return jwtTokenInfoEntity != 0;
    }

    public JwtTokenInfoEntity getJwtTokenInfoEntityByUsername(String username){
        JwtTokenInfoEntity jwtTokenInfoEntity = jwtTokenRepository.findByUsername(username);
        return jwtTokenInfoEntity;
    }


}
