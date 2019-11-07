package com.aus.asx.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Value(value = "${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuer;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        /*
         * This is where we configure the security required for our endpoints and setup
         * our app to serve as an OAuth2 Resource Server, using JWT validation.
         */
        http.authorizeRequests()
            .mvcMatchers("/actuator/**")
            .permitAll()
            .and()
            .oauth2ResourceServer()
            .jwt();
    }

    @Bean
    OAuth2TokenValidator<Jwt> audienceValidator(@Value(value = "${auth0.apiAudience}") String audience) {
        return new OAuth2TokenValidator<Jwt>() {
            @Override
            public OAuth2TokenValidatorResult validate(Jwt jwt) {
                final OAuth2Error error = new OAuth2Error("invalid_token", "The required audience is missing", null);

                if (jwt.getAudience().contains(audience)) {
                    return OAuth2TokenValidatorResult.success();
                }

                return OAuth2TokenValidatorResult.failure(error);
            }
        };
    }

    @Bean
    NimbusJwtDecoder jwtDecoder() {
        return (NimbusJwtDecoder) JwtDecoders.fromOidcIssuerLocation(issuer);
    }

    @Bean
    JwtDecoder jwtDecoder(OAuth2TokenValidator<Jwt> audienceValidator, NimbusJwtDecoder jwtDecoder) {
        /*
         * By default, Spring Security does not validate the "aud" claim of the token,
         * to ensure that this token is indeed intended for our app. Adding our own
         * validator is easy to do:
         */

        final OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuer);
        final OAuth2TokenValidator<Jwt> withAudience = new DelegatingOAuth2TokenValidator<>(withIssuer,
                audienceValidator);

        jwtDecoder.setJwtValidator(withAudience);

        return jwtDecoder;
    }
}