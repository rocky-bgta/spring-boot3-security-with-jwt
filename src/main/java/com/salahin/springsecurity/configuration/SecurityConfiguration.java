package com.salahin.springsecurity.configuration;

import com.salahin.springsecurity.exception.handler.CustomAccessDeniedHandler;
import com.salahin.springsecurity.exception.handler.CustomAuthenticationEntryPoint;
import com.salahin.springsecurity.filter.CustomJwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    private final CustomUserDetailsService customUserDetailsService;
    private final CustomJwtAuthenticationFilter customJwtAuthenticationFilter;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;
    private final CustomCorsConfiguration customCorsConfiguration;

    public SecurityConfiguration(
            CustomUserDetailsService customUserDetailsService,
            CustomJwtAuthenticationFilter customJwtAuthenticationFilter,
            CustomAuthenticationEntryPoint customAuthenticationEntryPoint,
            CustomAccessDeniedHandler customAccessDeniedHandler,
            CustomCorsConfiguration customCorsConfiguration) {
        this.customUserDetailsService = customUserDetailsService;
        this.customJwtAuthenticationFilter = customJwtAuthenticationFilter;
        this.customAuthenticationEntryPoint = customAuthenticationEntryPoint;
        this.customAccessDeniedHandler = customAccessDeniedHandler;
        this.customCorsConfiguration = customCorsConfiguration;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
	
	/*@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception{
		auth.userDetailsService(customUserDetailsService).passwordEncoder(passwordEncoder());
	}*/

    @Bean
    AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(customUserDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(corsConfig -> corsConfig.configurationSource(customCorsConfiguration))
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(new AntPathRequestMatcher("/admin-user")).hasRole("ADMIN")
                        .requestMatchers(new AntPathRequestMatcher("/normal-user")).hasAnyRole("ADMIN", "USER")

                        .requestMatchers(
                                new AntPathRequestMatcher("/authenticate"),
                                new AntPathRequestMatcher("/register"),
                                new AntPathRequestMatcher("/signing-out"),
                                new AntPathRequestMatcher("/slack/**")).permitAll()
                        .anyRequest().authenticated()
                )
                .exceptionHandling()
                // it is a Global auth exception handler
                .authenticationEntryPoint(customAuthenticationEntryPoint)
                .accessDeniedHandler(customAccessDeniedHandler)
                .and()

                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .addFilterBefore(customJwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

/*	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
	 return http.csrf().disable()
			.formLogin().disable()
			.httpBasic().disable()
			.authorizeRequests()
			.requestMatchers(AntPathRequestMatcher.antMatcher("/admin-user")).hasRole("ADMIN")
			.requestMatchers(AntPathRequestMatcher.antMatcher("/normal-user")).hasAnyRole("ADMIN","USER")
			.requestMatchers(AntPathRequestMatcher.antMatcher("/authenticate","/register")).permitAll().anyRequest().authenticated()
			.and()
			.exceptionHandling()
			.authenticationEntryPoint(jwtAuthenticationEntryPoint)
			.and()
			.sessionManagement()
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.addFilterBefore(customJwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class).build();
	}*/

	/*@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return http
				.csrf().disable()
				.authorizeHttpRequests()
				.requestMatchers("/admin-user").hasRole("ADMIN")
				.requestMatchers("/normal-user").hasAnyRole("ADMIN","USER")
				.requestMatchers("/authenticate","/register").permitAll().anyRequest().authenticated()
				.and()
				.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and()
				.addFilterBefore(customJwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
				.build();
	}*/
	
	/*@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}*/

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
