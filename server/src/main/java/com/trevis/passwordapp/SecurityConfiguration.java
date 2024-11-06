package com.trevis.passwordapp;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.trevis.passwordapp.dto.Token;
import com.trevis.passwordapp.filters.JWTAuthenticationFilter;
import com.trevis.passwordapp.services.JWTService;

// esse arquivo serve para configurar as rotas que nn precisam se autenticação 
// @Configuration e @EnableWebSecurity: Essas anotações dizem ao Spring que esta classe irá configurar as definições de segurança.

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    
    @Autowired
    JWTService<Token> jwtService;
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception { // HttpSecurity: Aqui você configura como as requisições HTTP serão tratadas em termos de segurança. No seu caso, está desabilitando a proteção CSRF (csrf().disable()), permitindo o acesso sem autenticação para certos endpoints (permitAll()), e exigindo autenticação para outros (anyRequest().authenticated()).
        // como mandar jwt para header depois do login?
        return http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/user").permitAll() // esses end poits permiete que façam as ações semprecisar fazer login, vc escolhe quais end poinst nn precisam de autenticação
                .requestMatchers("/user/login").permitAll() // quando testar colocar no permit all
                .anyRequest().authenticated()
            )
            .addFilterBefore(new JWTAuthenticationFilter(jwtService), UsernamePasswordAuthenticationFilter.class) // tds os end points vão chamar isso, ele manda para essa classe
            .build(); // addFilterBefore(...): Esse método insere o filtro JWTAuthenticationFilter na cadeia de filtros do Spring Security. O JWTAuthenticationFilter será executado antes do filtro padrão de autenticação baseado em nome de usuário e senha (UsernamePasswordAuthenticationFilter). O filtro JWT vai verificar se o token JWT enviado na requisição é válido e, se for, autentica o usuário automaticamente.
    }
}

// @postmapijmin  usa @requestBody no parametro


// como saber se um token é válido 

// Quando o usuário faz login com suas credenciais (usuário e senha), o sistema cria um token JWT. O token geralmente contém informações como o ID do usuário, o papel (role) do usuário, e outras informações necessárias para autenticação e autorização. O processo de geração do token inclui um passo importante: assinatura.

// Assinatura: O token é assinado com uma chave secreta (ou uma chave privada) para garantir que ele não possa ser alterado por ninguém durante a comunicação. Se o token for alterado (mesmo que uma única letra), ele será considerado inválido quando a assinatura for verificada.

// para o token existir ele precisa fazer login corretamente