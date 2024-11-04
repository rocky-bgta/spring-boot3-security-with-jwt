package com.salahin.springsecurity.repository;

import com.salahin.springsecurity.entity.JwtTokenInfoEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


import java.util.UUID;

@Repository
public interface JwtTokenRepository extends JpaRepository<JwtTokenInfoEntity, UUID> {
    JwtTokenInfoEntity findByUsername(String username);

    JwtTokenInfoEntity findByAccessToken(String string);

    Integer countJwtTokenInfoEntityByUsername(String username);
}
