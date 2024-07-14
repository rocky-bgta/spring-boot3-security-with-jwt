package com.salahin.springsecurity.repository;

import com.salahin.springsecurity.entity.JwtTokenInfoEntity;
import com.salahin.springsecurity.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface JwtTokenRepository extends JpaRepository<JwtTokenInfoEntity, UUID> {
	JwtTokenInfoEntity findByUsername(String username);
	Integer countJwtTokenInfoEntityByUsername(String username);
}
