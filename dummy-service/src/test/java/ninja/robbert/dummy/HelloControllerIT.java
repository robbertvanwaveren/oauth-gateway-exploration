package ninja.robbert.dummy;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import org.hamcrest.Matchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.text.ParseException;
import java.time.ZonedDateTime;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import static java.util.Collections.singletonMap;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
public class HelloControllerIT {

	@TestConfiguration
	static class PlainJWTSecurityConfig {

		@Primary
		@Bean
		public JwtDecoder plainJwtDecoder() {
			final UsernameSubClaimAdapter claimAdapter = new UsernameSubClaimAdapter();
			return token -> {
				try {
					final JWT jwt = JWTParser.parse(token);
					final Map<String, Object> claims = claimAdapter.convert(jwt.getJWTClaimsSet().getClaims());
					return Jwt.withTokenValue(token)
						.headers((h) -> h.putAll(jwt.getHeader().toJSONObject()))
						.claims((c) -> c.putAll(claims)).build();
				} catch (ParseException e) {
					throw new JwtException(e.getMessage(), e);
				}
			};
		}
	}

	final WebTestClient testClient = WebTestClient.bindToServer().baseUrl("http://localhost:8081").build();

	@Test
	public void testHello_WithoutToken() {
		testClient
			.get()
			.uri("/hello")
			.exchange()
			.expectStatus().isUnauthorized()
			.expectHeader().valueEquals(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
	}

	@Test
	public void testHello_WithWrongRole() {
		final String jwt = toJwtString(defaultClaims().claim("realm_access", singletonMap("roles", Collections.singleton("wrong"))));

		testClient
			.get()
			.uri("/hello")
			.header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
			.exchange()
			.expectStatus().isForbidden()
			.expectHeader().value(HttpHeaders.WWW_AUTHENTICATE, Matchers.containsString("The request requires higher privileges than provided by the access token."));
	}

	@Test
	public void testHello_WithDummyRole() {
		final String jwt = toJwtString(defaultClaims().claim("realm_access", singletonMap("roles", Collections.singleton("dummy"))));

		testClient
			.get()
			.uri("/hello")
			.header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
			.exchange()
			.expectStatus().isOk()
			.expectBody(Map.class).isEqualTo(singletonMap("message", "Hello Subject X"));
	}

	private String toJwtString(final JWTClaimsSet.Builder claimsSetBuilder) {
		return new PlainJWT(claimsSetBuilder.build()).serialize();
	}

	private JWTClaimsSet.Builder defaultClaims() {
		return new JWTClaimsSet.Builder()
			.issuer("keycloak")
			.subject(UUID.randomUUID().toString())
			.claim("preferred_username", "Subject X")
			.expirationTime(Date.from(ZonedDateTime.now().plusDays(1).toInstant()));
	}
}
