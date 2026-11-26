package com.bodeganube.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;
import reactor.core.publisher.Mono;

/**
 * Valida el JWT de los usuarios en todas las rutas /api/v1/** y aplica el control de acceso por rol (RBAC).
 *
 * - El token lo emite ms-autenticacion y se firma con la misma clave (JWT_SECRET), asi que la validacion es
 *   local: el gateway no llama a ms-autenticacion en cada peticion.
 * - OPERARIO puede usar toda la API. COMERCIO solo consulta sus ordenes y el catalogo (RF-06).
 * - Tenant Isolation: para un COMERCIO el gateway fuerza ?comercioId=<su comercio> al listar ordenes y
 *   envia su identidad en cabeceras X-Usuario, X-Rol y X-Comercio-Id. Las cabeceras que mande el cliente
 *   con esos nombres se borran antes, para que nadie pueda suplantar a otro comercio.
 */
@Component
public class JwtAutenticacionFilter implements GlobalFilter, Ordered {

    public static final String X_USUARIO = "X-Usuario";
    public static final String X_ROL = "X-Rol";
    public static final String X_COMERCIO_ID = "X-Comercio-Id";

    private static final String ROL_OPERARIO = "OPERARIO";
    private static final String ROL_COMERCIO = "COMERCIO";

    /** Lo que un COMERCIO puede pedir (solo GET): su lista de ordenes, una orden por id y el catalogo. */
    private static final Pattern COMERCIO_ORDENES = Pattern.compile("^/api/v1/ordenes(/\\d+)?/?$");
    private static final Pattern COMERCIO_PRODUCTOS = Pattern.compile("^/api/v1/productos(/[^/]+)?/?$");

    private final SecretKey clave;

    public JwtAutenticacionFilter(@Value("${app.jwt.secret}") String secreto) {
        if (secreto == null || secreto.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalStateException("app.jwt.secret debe tener al menos 32 caracteres");
        }
        this.clave = Keys.hmacShaKeyFor(secreto.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // Nunca se confia en cabeceras de identidad que vengan desde afuera.
        ServerHttpRequest limpia = exchange.getRequest().mutate()
                .headers(h -> {
                    h.remove(X_USUARIO);
                    h.remove(X_ROL);
                    h.remove(X_COMERCIO_ID);
                })
                .build();
        String ruta = limpia.getPath().value();
        HttpMethod metodo = limpia.getMethod();

        if (!requiereToken(ruta, metodo)) {
            return chain.filter(exchange.mutate().request(limpia).build());
        }

        String token = extraerToken(limpia.getHeaders().getFirst(HttpHeaders.AUTHORIZATION));
        if (token == null) {
            return responder(exchange.getResponse(), HttpStatus.UNAUTHORIZED, "Falta el token: envie Authorization: Bearer <jwt>");
        }

        Claims claims;
        try {
            claims = Jwts.parser().verifyWith(clave).build().parseSignedClaims(token).getPayload();
        } catch (JwtException | IllegalArgumentException e) {
            return responder(exchange.getResponse(), HttpStatus.UNAUTHORIZED, "Token invalido o expirado");
        }

        String rol = claims.get("rol", String.class);
        String comercioId = claims.get("comercioId", String.class);
        if (ROL_COMERCIO.equals(rol) && (comercioId == null || comercioId.isBlank())) {
            return responder(exchange.getResponse(), HttpStatus.FORBIDDEN, "El token de COMERCIO no trae comercioId");
        }
        if (!autorizado(rol, metodo, ruta)) {
            return responder(exchange.getResponse(), HttpStatus.FORBIDDEN,
                    "El rol " + rol + " no tiene permiso para " + metodo + " " + ruta);
        }

        ServerHttpRequest.Builder conIdentidad = limpia.mutate()
                .header(X_USUARIO, claims.getSubject())
                .header(X_ROL, rol);
        if (ROL_COMERCIO.equals(rol)) {
            conIdentidad.header(X_COMERCIO_ID, comercioId);
            if (HttpMethod.GET.equals(metodo) && ruta.matches("^/api/v1/ordenes/?$")) {
                URI soloSusOrdenes = UriComponentsBuilder.fromUri(limpia.getURI())
                        .replaceQueryParam("comercioId", UriUtils.encodeQueryParam(comercioId, StandardCharsets.UTF_8))
                        .build(true)
                        .toUri();
                conIdentidad.uri(soloSusOrdenes);
            }
        }
        return chain.filter(exchange.mutate().request(conIdentidad.build()).build());
    }

    /**
     * Rutas que no llevan JWT: el login, el webhook M2M (lo protege el filtro ApiKey de su ruta), la salud
     * del propio gateway y las rutas /estado de cada microservicio. Lo que no empieza con /api/ no tiene
     * ruta en el gateway y termina en 404.
     */
    static boolean requiereToken(String ruta, HttpMethod metodo) {
        if (ruta.equals("/api/v1/auth/login") && HttpMethod.POST.equals(metodo)) {
            return false;
        }
        if (ruta.startsWith("/api/v1/webhooks/")) {
            return false;
        }
        return ruta.startsWith("/api/");
    }

    static boolean autorizado(String rol, HttpMethod metodo, String ruta) {
        if (ROL_OPERARIO.equals(rol)) {
            return true;
        }
        if (ROL_COMERCIO.equals(rol) && HttpMethod.GET.equals(metodo)) {
            return COMERCIO_ORDENES.matcher(ruta).matches() || COMERCIO_PRODUCTOS.matcher(ruta).matches();
        }
        return false;
    }

    private static String extraerToken(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return null;
        }
        String token = authorization.substring("Bearer ".length()).trim();
        return token.isEmpty() ? null : token;
    }

    private static Mono<Void> responder(ServerHttpResponse response, HttpStatus status, String mensaje) {
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        String cuerpo = "{\"status\":" + status.value() + ",\"error\":\"" + status.getReasonPhrase()
                + "\",\"mensaje\":\"" + mensaje.replace("\"", "'") + "\"}";
        return response.writeWith(Mono.just(response.bufferFactory().wrap(cuerpo.getBytes(StandardCharsets.UTF_8))));
    }

    /** Corre antes que el enrutamiento, para que una peticion rechazada nunca llegue a un microservicio. */
    @Override
    public int getOrder() {
        return -100;
    }
}
