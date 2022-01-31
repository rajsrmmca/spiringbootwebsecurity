package com.raj.userservice.filter;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.raj.userservice.domain.APICredentials;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private APICredentials apiCredentials;

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @SneakyThrows
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        APICredentials apiCredentials = new ObjectMapper().readValue(request.getInputStream(), APICredentials.class);
//        String username = request.getParameter("username");
//        String password = request.getParameter("password");
        String username = apiCredentials.getUsername();
        String password = apiCredentials.getPassword();
        log.info("username is {}, password is {}",username , password);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        return authenticationManager.authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication)
        throws IOException, ServletException {
        User user = (User)authentication.getPrincipal();
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
        String access_token = JWT.create()
            .withSubject(user.getUsername())
            .withExpiresAt(new Date(System.currentTimeMillis()+10*60*10000))
            .withIssuer(request.getRequestURL().toString())
            .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
            .sign(algorithm);

        String refresh_token = JWT.create()
            .withSubject(user.getUsername())
            .withExpiresAt(new Date(System.currentTimeMillis()+30*60*1000))
            .withIssuer(request.getRequestURL().toString())
            .sign(algorithm);
//        response.setHeader("access_token", access_token);
//        response.setHeader("refresh_token", refresh_token);
        Map<String, String> res = new HashMap<>();
        res.put("access_token", "Bearer "+access_token);
        res.put("refresh_token", "Bearer "+refresh_token);
        res.put("success", "true");
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), res);
    }
}
