package com.bodeganube.gateway.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

/** Prueba unitaria del filtro JWT: token ausente, invalido, expirado, permisos por rol y Tenant Isolation. */
class JwtAutenticacionFilterTest {

    private static final String SECRETO = "clave-de-prueba-de-al-menos-32-caracteres!!";

    private final JwtAutenticacionFilter filtro = new JwtAutenticacionFilter(SECRETO);

    @Test
    void elLoginEsPublicoYNoPideToken() {
        AtomicReference<ServerHttpRequest> reenviada = new AtomicReference<>();
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/api/v1/auth/login"));

        filtro.filter(exchange, cadena(reenviada)).block();

        assertThat(reenviada.get()).isNotNull();
    }

    @Test
    void sinTokenResponde401() {
        AtomicReference<ServerHttpRequest> reenviada = new AtomicReference<>();
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/productos"));

        filtro.filter(exchange, cadena(reenviada)).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(reenviada.get()).isNull();
    }

    @Test
    void tokenFirmadoConOtraClaveResponde401() {
        String falso = token("operario", "OPERARIO", null, "otra-clave-distinta-de-al-menos-32-caracteres", 60_000);
        AtomicReference<ServerHttpRequest> reenviada = new AtomicReference<>();

        MockServerWebExchange exchange = conToken(MockServerHttpRequest.get("/api/v1/productos"), falso);
        filtro.filter(exchange, cadena(reenviada)).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(reenviada.get()).isNull();
    }

    @Test
    void tokenExpiradoResponde401() {
        String expirado = token("operario", "OPERARIO", null, SECRETO, -1_000);
        AtomicReference<ServerHttpRequest> reenviada = new AtomicReference<>();

        MockServerWebExchange exchange = conToken(MockServerHttpRequest.get("/api/v1/productos"), expirado);
        filtro.filter(exchange, cadena(reenviada)).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void operarioPasaYElGatewayAgregaSuIdentidad() {
        AtomicReference<ServerHttpRequest> reenviada = new AtomicReference<>();

        MockServerWebExchange exchange = conToken(MockServerHttpRequest.post("/api/v1/picking"),
                token("operario", "OPERARIO", null, SECRETO, 60_000));
        filtro.filter(exchange, cadena(reenviada)).block();

        assertThat(reenviada.get()).isNotNull();
        assertThat(reenviada.get().getHeaders().getFirst(JwtAutenticacionFilter.X_ROL)).isEqualTo("OPERARIO");
        assertThat(reenviada.get().getHeaders().getFirst(JwtAutenticacionFilter.X_USUARIO)).isEqualTo("operario");
    }

    @Test
    void comercioSoloVeSusOrdenesAunqueMandeOtroComercioId() {
        AtomicReference<ServerHttpRequest> reenviada = new AtomicReference<>();

        MockServerWebExchange exchange = conToken(MockServerHttpRequest.get("/api/v1/ordenes?comercioId=comercio-ajeno"),
                token("tienda1", "COMERCIO", "comercio-123", SECRETO, 60_000));
        filtro.filter(exchange, cadena(reenviada)).block();

        assertThat(reenviada.get()).isNotNull();
        assertThat(reenviada.get().getURI().getQuery()).isEqualTo("comercioId=comercio-123");
        assertThat(reenviada.get().getHeaders().getFirst(JwtAutenticacionFilter.X_COMERCIO_ID)).isEqualTo("comercio-123");
    }

    @Test
    void comercioNoPuedeCrearProductosNiVerLaColaDePicking() {
        String tokenComercio = token("tienda1", "COMERCIO", "comercio-123", SECRETO, 60_000);

        MockServerWebExchange crear = conToken(MockServerHttpRequest.post("/api/v1/productos"), tokenComercio);
        filtro.filter(crear, cadena(new AtomicReference<>())).block();
        assertThat(crear.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        MockServerWebExchange picking = conToken(MockServerHttpRequest.get("/api/v1/ordenes/disponibles-picking"), tokenComercio);
        filtro.filter(picking, cadena(new AtomicReference<>())).block();
        assertThat(picking.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void lasCabecerasDeIdentidadQueMandaElClienteSeBorran() {
        AtomicReference<ServerHttpRequest> reenviada = new AtomicReference<>();
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/api/v1/auth/login")
                .header(JwtAutenticacionFilter.X_ROL, "OPERARIO")
                .header(JwtAutenticacionFilter.X_COMERCIO_ID, "comercio-ajeno"));

        filtro.filter(exchange, cadena(reenviada)).block();

        assertThat(reenviada.get().getHeaders().containsKey(JwtAutenticacionFilter.X_ROL)).isFalse();
        assertThat(reenviada.get().getHeaders().containsKey(JwtAutenticacionFilter.X_COMERCIO_ID)).isFalse();
    }

    @Test
    void noPermiteArrancarConUnaClaveCorta() {
        assertThatThrownBy(() -> new JwtAutenticacionFilter("corta"))
                .isInstanceOf(IllegalStateException.class);
    }

    private static String token(String usuario, String rol, String comercioId, String secreto, long vigenciaMs) {
        Date ahora = new Date();
        return Jwts.builder()
                .subject(usuario)
                .claim("rol", rol)
                .claim("comercioId", comercioId)
                .issuedAt(ahora)
                .expiration(new Date(ahora.getTime() + vigenciaMs))
                .signWith(Keys.hmacShaKeyFor(secreto.getBytes(StandardCharsets.UTF_8)))
                .compact();
    }

    private static MockServerWebExchange conToken(MockServerHttpRequest.BaseBuilder<?> peticion, String token) {
        return MockServerWebExchange.from(peticion.header(HttpHeaders.AUTHORIZATION, "Bearer " + token));
    }

    /** Cadena falsa que guarda la peticion que le llega (es decir, la que el gateway reenviaria). */
    private static GatewayFilterChain cadena(AtomicReference<ServerHttpRequest> reenviada) {
        return exchange -> {
            reenviada.set(exchange.getRequest());
            return Mono.empty();
        };
    }
}
