package com.shreeya.learn_spring_security.JwtAuth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

//@Configuration
public class JwtSecurityConfiguration {
    @Bean
    SecurityFilterChain SecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> {
            ((AuthorizeHttpRequestsConfigurer.AuthorizedUrl)requests.anyRequest()).authenticated();
        });
        http.sessionManagement((sessions) ->
                sessions.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//        http.formLogin(Customizer.withDefaults());
        http.httpBasic(Customizer.withDefaults());
        http.csrf(AbstractHttpConfigurer::disable);
        http.headers().frameOptions().sameOrigin();
http.oauth2ResourceServer(OAuth2ResourceServerConfigurer:: jwt);
        return (SecurityFilterChain)http.build();
    }

    @Bean
    DataSource dataSource(){
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }


    @Bean
    public UserDetailsService UserDetailsService(DataSource dataSource) {

        var user= User.withUsername("shreeya")
                //.password("{noop}dummy")
                .password("dummy")

                .passwordEncoder(str -> bCryptPasswordEncoder().encode(str))
                .roles("USER")
                .build();

        var admin= User.withUsername("admin")
                // .password("{noop}dummy")
                .password("dummy")
                .passwordEncoder(str -> bCryptPasswordEncoder().encode(str))
                .roles("ADMIN")
                .build();


        var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(user);
        jdbcUserDetailsManager.createUser(admin);
        return jdbcUserDetailsManager;
    }


    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();

    }

    @Bean
    public KeyPair keyPair() {
        try{var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        }
        catch(Exception e){
            throw new RuntimeException(e);
        }
    }
        @Bean
                public RSAKey rsaKey(KeyPair keyPair){
            return new RSAKey
                    .Builder((RSAPublicKey) keyPair.getPublic())
                    .privateKey(keyPair().getPrivate())
                    .keyID(UUID.randomUUID().toString())
                    .build();



    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
        // Create the JWK set from the RSA key
        JWKSet jwkSet = new JWKSet(rsaKey);

        // Return a new JWKSource lambda implementation
        return (jwkSelector, context) -> jwkSelector.select(jwkSet);
    }



    @Bean
    JwtDecoder jwtDecoder(RSAKey rsaKey)throws JOSEException {
        return NimbusJwtDecoder
                .withPublicKey(rsaKey.toRSAPublicKey())
                .build();
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

}
