package com.salahin.springsecurity.configuration;

import com.salahin.springsecurity.entity.RoleEntity;
import com.salahin.springsecurity.entity.UserEntity;
import com.salahin.springsecurity.repository.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class CustomUserDetailsService implements UserDetailsService {
	
	private final UserRepository userRepository;
	//private List<String> roleNames;
	
	public CustomUserDetailsService(UserRepository userRepository) {
		this.userRepository = userRepository;
	}
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		UserEntity userModel;
		userModel = userRepository.findByUsername(username);
		//roleNames = userModel.getRoleList().stream().map(roleEntity -> roleEntity.getRoleName()).collect(Collectors.toList());
		List<SimpleGrantedAuthority> roleList = new ArrayList<>();
		if (userModel != null) {
			for (RoleEntity roleEntity : userModel.getRoleList()) {
				roleList.add(new SimpleGrantedAuthority(roleEntity.getRoleName()));
			}
			return new User(userModel.getUsername(), userModel.getPassword(), roleList);
		}
		throw new UsernameNotFoundException("User not found with the name" + username);
	}
	
//	public String[] getRoleNames() {
//		if (roleNames != null)
//			return (String[]) roleNames.toArray();
//		else return new String[]{""};
//	}

}
