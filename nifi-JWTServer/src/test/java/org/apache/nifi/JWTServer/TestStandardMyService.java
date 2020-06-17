/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.nifi.JWTServer;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClaims;
import org.apache.nifi.reporting.InitializationException;
import org.apache.nifi.util.TestRunner;
import org.apache.nifi.util.TestRunners;
import org.junit.Before;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.SignatureException;
import java.util.Calendar;
import java.util.Date;
import java.util.UUID;

public class TestStandardMyService {

    @Before
    public void init() {

    }
    private JwtBuilder getJWTBuilder(){
        Calendar cal = Calendar.getInstance();
        cal.setTime(new Date());
        cal.add(2, Calendar.HOUR_OF_DAY);
        Claims claims = new DefaultClaims().setId(UUID.randomUUID().toString());
        return Jwts.builder()
                .setSubject("test_subject")
                .setAudience("test_audience")
                .setExpiration(cal.getTime())
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(new Date())
                .setNotBefore(new Date())
                .claim("client_id", "test_client_id")
                .claim("client_secret", "test_client_secret")
                .setHeaderParam("alg", SignatureAlgorithm.HS256.getValue());
    }
    @Test
    public void testService() throws InitializationException, SignatureException {
        final TestRunner runner = TestRunners.newTestRunner(TestProcessor.class);
        final JWTSigningService service = new JWTSigningService();
        runner.addControllerService("test-good", service);

        runner.setProperty(service, JWTSigningService.PROP_GEN_SECURE_KEY.getName(), JWTSigningService.KEY_PROVIDER_GENERATE.getValue());
        runner.setProperty(service, JWTSigningService.PROP_SIGNING_ALGO.getName(), JWTSigningService.VALUE_RS256.getValue());
        runner.enableControllerService(service);
        runner.assertValid(service);
        JwtBuilder jwtBuilder = service.signJWT(getJWTBuilder());
        String token = jwtBuilder.compact();
        boolean isVerified = service.verifyJWT(token);
        System.out.println("isVerified = "+isVerified);
    }
    @Test
    public void testService2() throws InitializationException, IOException, SignatureException {
        final TestRunner runner = TestRunners.newTestRunner(TestProcessor.class);
        final JWTSigningService service = new JWTSigningService();
        runner.addControllerService("test-good2", service);
        File pvtKey = new File("src/test/java/resources/rsa_private.pem");
        File pubKey = new File("src/test/java/resources/rsa_public.pem");

        StringBuilder sb = new StringBuilder();
        BufferedReader reader = new BufferedReader(new FileReader(pvtKey));
        reader.lines().forEach(s -> sb.append(s));
        reader.close();

        StringBuilder sb2 = new StringBuilder();
        BufferedReader reader2 = new BufferedReader(new FileReader(pubKey));
        reader2.lines().forEach(s -> sb2.append(s));
        reader2.close();
        System.out.println(sb.toString());
        System.out.println(sb2.toString());
        runner.setProperty(service, JWTSigningService.PROP_GEN_SECURE_KEY.getName(), JWTSigningService.KEY_PROVIDER_REFER.getValue());
        runner.setProperty(service, JWTSigningService.PROP_SIGNING_ALGO.getName(), JWTSigningService.VALUE_RS384.getValue());
        runner.setProperty(service, JWTSigningService.PROP_PVT_KEY.getName(), sb.toString());
        runner.setProperty(service, JWTSigningService.PROP_PUB_KEY.getName(), sb2.toString());

        runner.enableControllerService(service);
        runner.assertValid(service);
        JwtBuilder jwtBuilder = service.signJWT(getJWTBuilder());
        String token = jwtBuilder.compact();
        boolean isVerified = service.verifyJWT(token);
        System.out.println("isVerified = "+isVerified);
    }
}
