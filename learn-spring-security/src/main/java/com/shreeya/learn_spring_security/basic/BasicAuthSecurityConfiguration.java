package com.shreeya.learn_spring_security.basic;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

import static org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION;

@Configuration
@EnableMethodSecurity(jsr250Enabled = true, securedEnabled = true)
public class BasicAuthSecurityConfiguration {


    @Bean

    SecurityFilterChain SecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> {
            ((AuthorizeHttpRequestsConfigurer.AuthorizedUrl)requests

                    .anyRequest()).authenticated();
        });
        http.sessionManagement((sessions) ->
            sessions.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//        http.formLogin(Customizer.withDefaults());
        http.httpBasic(Customizer.withDefaults());
        http.csrf(AbstractHttpConfigurer::disable);
        http.headers().frameOptions().sameOrigin();

        return (SecurityFilterChain)http.build();
    }

//    @Bean
//    public UserDetailsService UserDetailsService() {
//
//       var user= User.withUsername("shreeya")
//                .password("{noop}dummy")
//                .roles("USER")
//                .build();
//
//        var admin= User.withUsername("admin")
//                .password("{noop}dummy")
//                .roles("ADMIN")
//                .build();
//        return new InMemoryUserDetailsManager(user, admin);
//    }

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

}
