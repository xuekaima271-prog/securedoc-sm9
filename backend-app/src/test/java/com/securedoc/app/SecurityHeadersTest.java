package com.securedoc.app;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Regression coverage for API-only browser response defenses. */
@SpringBootTest
@AutoConfigureMockMvc
class SecurityHeadersTest {

    private static final String API_CSP =
            "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";

    @Autowired
    MockMvc mvc;

    @Test
    void unauthenticatedApiResponseKeepsBrowserDefenses() throws Exception {
        mvc.perform(get("/api/keys/me/status"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("Content-Security-Policy", API_CSP))
                .andExpect(header().string("Referrer-Policy", "no-referrer"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Cache-Control", containsString("no-store")));
    }

    @Test
    void validationErrorApiResponseKeepsBrowserDefenses() throws Exception {
        mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{not-json"))
                .andExpect(status().isBadRequest())
                .andExpect(header().string("Content-Security-Policy", API_CSP))
                .andExpect(header().string("Referrer-Policy", "no-referrer"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Cache-Control", containsString("no-store")));
    }

    @Test
    @WithUserDetails("bob")
    void authenticatedKeyResponseKeepsBrowserDefenses() throws Exception {
        mvc.perform(get("/api/keys/me/status"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Security-Policy", API_CSP))
                .andExpect(header().string("Referrer-Policy", "no-referrer"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Cache-Control", containsString("no-store")));
    }
}
