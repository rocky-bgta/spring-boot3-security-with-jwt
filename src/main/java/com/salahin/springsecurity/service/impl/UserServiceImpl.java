package com.salahin.springsecurity.service.impl;


import com.salahin.springsecurity.entity.UserEntity;
import com.salahin.springsecurity.model.UserModel;
import com.salahin.springsecurity.repository.UserRepository;
import com.salahin.springsecurity.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.modelmapper.ValidationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service("UserService")
@Slf4j
public class UserServiceImpl implements UserService {


    private final ModelMapper modelMapper;
    private final UserRepository userRepository;
    private final PasswordEncoder bcryptEncoder;

    public UserServiceImpl(ModelMapper modelMapper, UserRepository userRepository, PasswordEncoder bcryptEncoder) {
        this.modelMapper = modelMapper;
        this.userRepository = userRepository;
        this.bcryptEncoder = bcryptEncoder;
    }

    @Override
    public UserModel saveUser(UserModel userModel) {
        UserEntity userEntity; // = new UserEntity();
        userEntity = modelMapper.map(userModel, UserEntity.class);
        userEntity.setPassword(bcryptEncoder.encode(userModel.getPassword()));
        userEntity = userRepository.save(userEntity);
        userModel.setId(userEntity.getId());
        return userModel;
    }



    @Override
    public UserModel findByUsername(String username) {
        UserModel userModel = null;

        try {
            UserEntity userEntity = userRepository.findByUsername(username);
            if (userEntity != null) {
                userModel = modelMapper.map(userEntity, UserModel.class);
            }
        } catch (ValidationException e) {
            log.error("Validation failed for UserModel ", e);
            throw e;
        }
        return userModel;
    }
}
