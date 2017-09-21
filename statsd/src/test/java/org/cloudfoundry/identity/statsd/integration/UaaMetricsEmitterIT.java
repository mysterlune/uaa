/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 * <p/>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p/>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.statsd.integration;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.statsd.integration.IntegrationTestUtils.TEST_PASSWORD;
import static org.cloudfoundry.identity.statsd.integration.IntegrationTestUtils.TEST_USERNAME;
import static org.cloudfoundry.identity.statsd.integration.IntegrationTestUtils.UAA_BASE_URL;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

@RunWith(Parameterized.class)
public class UaaMetricsEmitterIT {
    public static final int WAIT_FOR_MESSAGE = 5500;
    private static DatagramSocket serverSocket;
    private static byte[] receiveData;
    private static DatagramPacket receivePacket;
    private static Map<String, String> firstBatch;
    private static List<String> gaugeFragments = Arrays.asList(
        "uaa.requests.global.completed.count",
        "uaa.requests.global.completed.count",
        "uaa.requests.global.unhealthy.time",
        "uaa.requests.global.unhealthy.count",
        "uaa.audit_service.user.authentication.count:",
        "uaa.server.inflight.count",
        "uaa.requests.global.status_1xx.count",
        "uaa.requests.global.status_2xx.count",
        "uaa.requests.global.status_3xx.count",
        "uaa.requests.global.status_4xx.count",
        "uaa.requests.global.status_5xx.count",
        "uaa.server.up.time",
        "uaa.server.idle.time"
    );
    private static Map<String, String> secondBatch;

    @Parameterized.Parameters(name = "{index}: fragment[{0}]")
    public static Object[] data() {
        return gaugeFragments.toArray();
    }

    private String statsDKey;

    public UaaMetricsEmitterIT(String statsDKey) {
        this.statsDKey = statsDKey;
    }

    @BeforeClass
    public static void setUpOnce() throws IOException {
        serverSocket = new DatagramSocket(8125);
        serverSocket.setSoTimeout(1000);
        receiveData = new byte[65535];
        receivePacket = new DatagramPacket(receiveData, receiveData.length);
        firstBatch = getMessages(gaugeFragments, WAIT_FOR_MESSAGE);
        performSimpleGet();
        performLogin();
        secondBatch = getMessages(gaugeFragments, WAIT_FOR_MESSAGE);
    }

    @Test
    public void assert_gauge_metric() throws IOException {
        String data1 = firstBatch.get(statsDKey);
        assertNotNull("Expected to find message for:"+statsDKey+" in the first batch.", data1);
        String data2 = secondBatch.get(statsDKey);
        assertNotNull("Expected to find message for:"+statsDKey+" in the second batch.", data2);
        long first = IntegrationTestUtils.getGaugeValueFromMessage(data1);
        long second = IntegrationTestUtils.getGaugeValueFromMessage(data2);
        assertThat(statsDKey+" has a positive value.", first, greaterThanOrEqualTo(0l));
        assertThat(statsDKey+" has a positive value larger than or equal to the first.", second, greaterThanOrEqualTo(first));
    }


    protected static Map<String,String> getMessages(List<String> fragments, int timeout) throws IOException {
        long startTime = System.currentTimeMillis();
        Map<String,String> results = new HashMap<>();
        do {
            receiveData = new byte[65535];
            receivePacket.setData(receiveData);
            try {
                serverSocket.receive(receivePacket);
                String message = new String(receivePacket.getData()).trim();
                System.out.println("message = " + message);
                fragments.stream().forEach(fragment -> {
                    if (message.startsWith(fragment)) {
                        results.put(fragment, message);
                    }
                });
            } catch (SocketTimeoutException e) {
                //expected so that we keep looping
            }
        } while (results.size()<fragments.size() && (System.currentTimeMillis() < (startTime + timeout)));
        return results;
    }

    public static void performLogin() {
        RestTemplate template = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.set(headers.ACCEPT, MediaType.TEXT_HTML_VALUE);
        ResponseEntity<String> loginResponse = template.exchange(UAA_BASE_URL + "/login",
                                                                 HttpMethod.GET,
                                                                 new HttpEntity<>(null, headers),
                                                                 String.class);

        if (loginResponse.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : loginResponse.getHeaders().get("Set-Cookie")) {
                headers.add("Cookie", cookie);
            }
        }
        String csrf = IntegrationTestUtils.extractCookieCsrf(loginResponse.getBody());

        LinkedMultiValueMap<String,String> body = new LinkedMultiValueMap<>();
        body.add("username", TEST_USERNAME);
        body.add("password", TEST_PASSWORD);
        body.add("X-Uaa-Csrf", csrf);
        loginResponse = template.exchange(UAA_BASE_URL + "/login.do",
                                          HttpMethod.POST,
                                          new HttpEntity<>(body, headers),
                                          String.class);
        assertEquals(HttpStatus.FOUND, loginResponse.getStatusCode());
    }

    public static void performSimpleGet() {
        RestTemplate template = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.set(headers.ACCEPT, MediaType.TEXT_HTML_VALUE);
        template.exchange(UAA_BASE_URL + "/login",
                          HttpMethod.GET,
                          new HttpEntity<>(null, headers),
                          String.class);
    }
}
