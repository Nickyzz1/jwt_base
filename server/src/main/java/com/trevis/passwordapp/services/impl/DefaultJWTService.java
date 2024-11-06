package com.trevis.passwordapp.services.impl;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import com.trevis.passwordapp.dto.Token;
import com.trevis.passwordapp.services.JWTService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
// cria o tolken
public class DefaultJWTService implements JWTService<Token> {
    private final String SECRET_KEY = "ouqebfdouiebfouqewfnuoqewnhfouewnfouewnh";
    private final long EXPIRATION_TIME = 1000 * 60 * 60; // 1 hora

    @Override
    public String get(Token token) { // crfia o tolken O método get(Token token) cria um JWT com base nas informações do token fornecido, como o id e o role (papel do usuário).
        var claims = new HashMap<String, Object>();
        
        claims.put("id", token.getId()); // Ao adicionar o id e o role aos claims do JWT, você está garantindo que essas informações importantes (como a identidade do usuário e seu papel) estarão disponíveis para serem acessadas sempre que o token for utilizado.

        // Essas informações podem ser usadas em diferentes partes do sistema para:
        
        // Autenticar o usuário (verificando se o token é válido e se ele contém o id correto).
        // Autorização (verificando se o usuário tem o papel adequado para acessar um recurso).

//         Aqui, o código está adicionando uma chave chamada "id" aos claims do token.
// O valor dessa chave é o ID do usuário (obtido através de token.getId()).
// O ID pode ser um identificador único para o usuário no banco de dados ou no sistema.


        claims.put("role", token.getRole());

        return get(claims);
    }

    @Override
    public Token validate(String jwt) {
        try
        {
            var map = validateJwt(jwt);

            Token token = new Token();
            token.setId(Long.parseLong(map.get("id").toString()));
            token.setRole(map.get("role").toString());

            return token;
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
            return null;
        }
    }

    private String get(Map<String, Object> customClaims) {
        SecretKey key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
        return Jwts.builder()
            .claims()
                .add(customClaims)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .and()
            .signWith(key)
            .compact();
    }

    private Map<String, Object> validateJwt(String jwt) {
        SecretKey key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
        Claims claims = Jwts.parser()
            .verifyWith(key)
            .build()
            .parseSignedClaims(jwt)
            .getPayload();
        
        return new HashMap<>(claims);
    }
}
