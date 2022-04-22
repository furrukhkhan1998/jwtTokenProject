package com.example.jwttokenproject.jwtutils;

import com.example.jwttokenproject.jwtutils.JwtUserDetailsService;
import com.example.jwttokenproject.jwtutils.TokenManager;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUserDetailsService userDetailsService;
    @Autowired
    private TokenManager tokenManager;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String tokenHeader = request.getHeader("Authorization");

        String username = null;
        String token = null;
        System.out.println("The token header is " + tokenHeader);

        if(tokenHeader != null && tokenHeader.startsWith("Bearer")){ //
            token = tokenHeader.substring(7);
            try{
                username = tokenManager.getUsernameFromToken(token);
            }
            catch(IllegalArgumentException e){
                System.out.println("UNABLE TO GET JWT TOKEN");
            }
            catch (ExpiredJwtException e){
                System.out.println("JWT TOKEN HAS EXPIRED");
            }
        }
        else{
            System.out.println("Bearer String not found in token");
        }
        if(null != username && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            if(tokenManager.validateJwtToken(token, userDetails)){
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }
        filterChain.doFilter(request,response);
    }

}
