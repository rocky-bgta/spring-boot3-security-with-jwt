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

    public void saveTokenInfo(String username, String accessToken){
        UserEntity user = userRepository.findByUsername(username);
        JwtTokenInfoEntity jwtTokenInfoEntity = new JwtTokenInfoEntity();
        jwtTokenInfoEntity.setAccessToken(accessToken);
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


}
