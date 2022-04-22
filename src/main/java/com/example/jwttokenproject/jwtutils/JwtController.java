package com.example.jwttokenproject.jwtutils;


import com.example.jwttokenproject.jwtutils.models.JwtRequestModel;
import com.example.jwttokenproject.jwtutils.models.JwtResponseModel;
import com.example.jwttokenproject.jwtutils.JwtUserDetailsService;
import com.example.jwttokenproject.jwtutils.TokenManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@CrossOrigin
public class JwtController {
    @Autowired
    private JwtUserDetailsService userDetailsService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private TokenManager tokenManager;

    @PostMapping("/login")
    public ResponseEntity<JwtResponseModel> createToken(@RequestBody JwtRequestModel request) throws Exception {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
        }
        catch (DisabledException e){
            throw new Exception("User_Disabled", e);
        }
        catch (BadCredentialsException e)
        {
            throw new Exception("Invalid_credentials", e);
        }

        final UserDetails userDetails = userDetailsService.loadUserByUsername(request.getUsername());
        final String jwtToken = tokenManager.generateJwtToken(userDetails);
        JwtResponseModel resp = new JwtResponseModel(jwtToken);
        return new ResponseEntity<JwtResponseModel>(resp,HttpStatus.OK);
    }


}
