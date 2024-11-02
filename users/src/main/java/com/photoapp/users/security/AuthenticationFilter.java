package com.photoapp.users.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.photoapp.users.models.requests.LoginRequest;
import com.photoapp.users.services.UsersService;
import com.photoapp.users.shared.UserDto;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;

public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private  UsersService usersService;
    private  Environment environment;

    public AuthenticationFilter(UsersService usersService,Environment environment, AuthenticationManager authenticationManager) {
        super(authenticationManager);
        this.environment = environment;
        this.usersService = usersService;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res)
            throws AuthenticationException {
        try {

            LoginRequest loginCredentials = new ObjectMapper().readValue(req.getInputStream(), LoginRequest.class);

            return getAuthenticationManager().authenticate(
                    new UsernamePasswordAuthenticationToken(loginCredentials.getEmail(), loginCredentials.getPassword(), new ArrayList<>()));

        } catch (IOException e) {
            throw new RuntimeException(e);
        } 
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest req,
                                            HttpServletResponse res, FilterChain chain,
                                            Authentication auth) throws IOException, ServletException {

        String username = ((User)auth.getPrincipal()).getUsername();
        UserDto userDetails = usersService.getUserDetailsByEmail(username);
        String tokenSecret = environment.getProperty("token.secret.key");
        if (tokenSecret == null) {
            throw new RuntimeException("Token secret key is missing in the configuration!");
        }
        // Generate a secure key (replace with securely generated key bytes)
//        assert tokenSecret != null;
        byte[] secretKeyBytes = tokenSecret.getBytes(StandardCharsets.UTF_8);
        // Create a SecretKey using Keys.hMacShaKeyFor -> length of string determines algorithm to be used
        SecretKey secretKey = Keys.hmacShaKeyFor(secretKeyBytes);

        Instant now = Instant.now();
        // Use the SecretKey to sign a JWT
        String token = Jwts.builder()
                .subject(userDetails.getUserId())
                .expiration(Date.from(now.plusMillis(Long.parseLong(environment.getProperty("token.expiration.time")))))
                .issuedAt(Date.from(now))
                .signWith(secretKey)
                .compact();


        // Set the JWT in the response header (optional)
        res.addHeader("token", token);
        res.addHeader("userId", userDetails.getUserId());
    }
}

//Attempt auth method
// intercepts request from postman and creates authentication object and shares with auth manager which checks a Db
// or somewhere to confirm validity, then if valid stores in security context holder to allow access

//successful auth method
// take user details and generated a jwt access token and return with the http response header along with an http response code
//In simple terms, the principal refers to the currently authenticated user or entity in a security context.