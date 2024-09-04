package com.example.springJWT.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
// 설정 클래스 자체는 시큐리티를 위한 설정이기 때문에 밑의 어노테이션이 필요함
@EnableWebSecurity
public class SecurityConfig {

    // 회원정보 저장, 회원가입, 다시 검증할 떄 -> 비밀번호를 항상 해시로 암호화하여 검증
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // csrf-disable
        // 세션은 항상 고정이기 때문에 csrf 공격을 막아줘야 함
        // jwt는 세션을 stateless 상태로 관리하므로 csrf를 방어하지 않아도 됨
        http.csrf((auth)->auth.disable());

        // jwt 방식으로 로그인을 할 것이기 때문에
        http.formLogin((auth)-> auth.disable());
        http.httpBasic((auth)-> auth.disable());

        // 경로별 인가작업
        // login, root, join 루트에 대해서는 모든 권한을 허용
        // admin 경로는 admin이란 권한이 있어야 함
        // 다른 요청에 대해서는 로그인한 사용자만 접근할 수 있는
        http.authorizeHttpRequests((auth) -> auth
                .requestMatchers("/login", "/", "/join").permitAll()
                .requestMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated());

        // jwt는 항상 세션을 stateless로!
        http.sessionManagement((session) -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
