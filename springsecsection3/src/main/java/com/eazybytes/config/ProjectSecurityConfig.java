package com.eazybytes.config;

import javax.sql.DataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class ProjectSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeHttpRequests((requests) -> requests
                .requestMatchers("/myAccount", "/myBalance", "/myLoans", "/myCards").authenticated()
                .requestMatchers("/notices", "/contact", "/register").permitAll())
                .formLogin(Customizer.withDefaults()).httpBasic(Customizer.withDefaults());
        return http.build();
    }

    // Database details will be inserted into this bean
    // @Bean
    // public UserDetailsService userDetailsService(DataSource dataSource) {
    // return new JdbcUserDetailsManager(dataSource);
    // }

    // Deprecated because it is not recommended for production (password are treated as plain-text)
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    // Not used for production (deprecated method withDefaultPasswordEncoder())
    // @Bean
    // public InMemoryUserDetailsManager userDetailsService() {

    // /* Approach 1 where we use withDefaultPasswordEncoder() method
    // * while creating the user details
    // */

    // // UserDetails admin = User.withDefaultPasswordEncoder()
    // // .username("admin")
    // // .password("12345")
    // // .authorities("admin")
    // // .build();
    // // UserDetails user = User.withDefaultPasswordEncoder()
    // // .username("user")
    // // .password("12345")
    // // .authorities("read")
    // // .build();

    // // return new InMemoryUserDetailsManager(admin, user);

    // /**
    // * Approach 2 where we use NoOpPasswordEncoder Bean
    // * while creating the user details
    // */

    // UserDetails admin = User.withUsername("admin")
    // .password("12345")
    // .authorities("admin")
    // .build();
    // UserDetails user = User.withUsername("user")
    // .password("12345")
    // .authorities("read")
    // .build();

    // return new InMemoryUserDetailsManager(admin, user);
    // }

}
