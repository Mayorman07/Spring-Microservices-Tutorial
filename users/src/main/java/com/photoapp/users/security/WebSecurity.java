package com.photoapp.users.security;

import com.photoapp.users.services.UsersService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurity {

    private final UsersService usersService;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    private final Environment environment;

    public  WebSecurity(Environment environment, UsersService usersService, BCryptPasswordEncoder bCryptPasswordEncoder){
        this.environment = environment;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.usersService = usersService;
    }

    @Bean
    protected SecurityFilterChain configure (HttpSecurity http) throws Exception{
        //configure authentication manager builder, 37 -> which method {users service that implements userdetailsservice}
        // contains details that can be used for lookups in a DB
        //The passwordEncoder(bCryptPasswordEncoder) specifies the password encoder (bcrypt in this case)
        // to compare the stored password with the user-provided password during authentication.
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);

        authenticationManagerBuilder.userDetailsService(usersService)
                .passwordEncoder(bCryptPasswordEncoder);

        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();

        //Create Authentication filter
        AuthenticationFilter authenticationFilter = new AuthenticationFilter(usersService, environment,authenticationManager);
        authenticationFilter.setFilterProcessesUrl(environment.getProperty("login.url.path"));

        http
                // Disable CSRF protection since this application is stateless (e.g., using JWTs)
                .csrf(AbstractHttpConfigurer::disable);

                // Configure authorization requests
               http.authorizeHttpRequests(authorize ->
                                authorize
                                        .requestMatchers(HttpMethod.GET, "/status/check").authenticated()
//                                        .requestMatchers(HttpMethod.GET, "/users/status/check").permitAll()  // Allow all requests to /users/status/check
                                        // Permit all POST requests to /users (e.g., for user registration) from a particular Ip address
//                                .requestMatchers(HttpMethod.POST, "/users")
//                                .access(new WebExpressionAuthorizationManager("hasIpAddress('"+environment.getProperty("gateway.ip")+"')"))
                                        .requestMatchers(new AntPathRequestMatcher("/users/**")).permitAll()
                                        // Permit all requests to /h2-console/**
                                        .requestMatchers(new AntPathRequestMatcher("/h2-console/**")).permitAll()
                                          // Any other requests must be authenticated
                                        .anyRequest().authenticated())
                                         // Add authentication filter
                                        .addFilter(authenticationFilter)

                                        .authenticationManager(authenticationManager)
                                        // Configure session management as stateless
                                        .sessionManagement((session) -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                                        );


        // Disable X-Frame-Options to allow H2 Console to be displayed in a frame
        http.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable));

        return http.build();
    }

}
