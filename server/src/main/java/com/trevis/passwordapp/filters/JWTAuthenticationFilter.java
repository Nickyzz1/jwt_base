package com.trevis.passwordapp.filters;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.trevis.passwordapp.dto.Token;
import com.trevis.passwordapp.services.JWTService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
// vai no header (gearlemnte), body, pela url no path
// postman
// Este filtro é responsável por capturar o token JWT na requisição (geralmente enviado no cabeçalho Authorization), validá-lo e autenticar o usuário com base no token.
public class JWTAuthenticationFilter extends OncePerRequestFilter { // filtros personalizados

    final JWTService<Token> jwtService;
    public JWTAuthenticationFilter(JWTService<Token> jwtService) {
        this.jwtService = jwtService;
    } // tem métodos específicos

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        var jwt = getJwt(request); // getJwt: Recupera o token JWT do cabeçalho Authorization, se estiver presente.
        if (jwt == null) // getJwt(HttpServletRequest request): Este método pega o token JWT do cabeçalho da requisição. Se ele começar com Bearer , o token é extraído.
        {
            filterChain.doFilter(request, response);
            return; // Se não encontrar o token ou se o token for inválido, ele simplesmente passa para o próximo filtro (usando filterChain.doFilter(request, response)), ou seja, a requisição segue normalmente sem autenticar o usuário.
        } // ele reronar o jwt certo

        var token = jwtService.validate(jwt);
        if (token == null)
        {
            filterChain.doFilter(request, response);
            return;
        }
        
        var authentication = new UsernamePasswordAuthenticationToken("jao", null, null);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        request.setAttribute("token", token);
        filterChain.doFilter(request, response);
    }
    
    String getJwt(HttpServletRequest request) { // aquie ele filtra o jwt
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
