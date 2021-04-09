package com.upgrad.proman.service.business;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.upgrad.proman.service.common.GenericErrorCode;

import java.rmi.UnexpectedException;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoField;
import java.util.Date;
import java.util.UUID;

public class JwtTokenProvider {
    private static final String TOKEN_ISSUER="https://proman.io";
    private static Algorithm algorithm;


    public JwtTokenProvider(final String secret) {
        try{
            algorithm=Algorithm.HMAC512(secret);
        }catch (IllegalArgumentException e){
            throw new IllegalArgumentException("Something went wrong with ecnryption algorithm");
        }
    }

    public static String generateToken(final String userUuid, final ZonedDateTime issuedDateTime, final ZonedDateTime expiresDateTime){
        final Date issuedAt=new Date(issuedDateTime.getLong(ChronoField.INSTANT_SECONDS));
        final Date expiresAt=new Date(expiresDateTime.getLong(ChronoField.INSTANT_SECONDS));
        return JWT.create().withIssuer(TOKEN_ISSUER).//
            withKeyId(UUID.randomUUID().toString()).
            withAudience(userUuid).
            withIssuedAt(issuedAt).withExpiresAt(expiresAt).sign(algorithm);
    }
}
