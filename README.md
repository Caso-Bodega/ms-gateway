# ms-gateway

**Spring Cloud Gateway** del caso BodegaNube (JVY0101): el único punto de entrada hacia los 4 microservicios.
Enruta cada petición, valida el JWT de los usuarios, aplica los permisos por rol, aísla los datos de cada
comercio y autentica con API key el webhook que llega desde la AWS Lambda procesadora.

En la nube queda detrás de **Amazon API Gateway** (repositorio
[bodeganube-serverless](https://github.com/Caso-Bodega/bodeganube-serverless)): Amazon API Gateway es la puerta
pública y limita el tráfico; este gateway corre dentro del clúster Docker Swarm y es el único servicio que
publica un puerto (8080).

| | |
|---|---|
| Puerto | `8080` |
| Base de datos | No usa |
| Stack | Java 17, Spring Boot 3.2, Spring Cloud Gateway 2023.0 (WebFlux + Netty), JJWT 0.12, Maven Wrapper |

## Rutas
Definidas en `src/main/resources/application.yml`. Todas usan la versión 1 de la API (`/api/v1`).

| Ruta | Destino | Acceso |
|---|---|---|
| `POST /api/v1/auth/login` | ms-autenticacion (8081) | público |
| `/api/v1/usuarios/**` | ms-autenticacion (8081) | JWT de `OPERARIO` |
| `/api/v1/ordenes/**` | ms-ordenes (8082) | JWT. `COMERCIO`: solo `GET` de sus órdenes |
| `/api/v1/productos/**` | ms-inventario (8083) | JWT. `COMERCIO`: solo `GET` del catálogo |
| `/api/v1/picking/**` | ms-picking-despacho (8084) | JWT de `OPERARIO` |
| `POST /api/v1/webhooks/ordenes` | ms-ordenes `POST /api/v1/ordenes` | **API key** en `X-Api-Key` (máquina a máquina) |
| `GET /estado/<microservicio>` | `/actuator/health` de cada microservicio | público (lo usa el pipeline de CI/CD) |
| `GET /actuator/health` | salud del propio gateway | público |

## Validación del JWT y permisos por rol (RBAC)
`JwtAutenticacionFilter` es un `GlobalFilter` que corre antes del enrutamiento:

1. Borra las cabeceras `X-Usuario`, `X-Rol` y `X-Comercio-Id` que mande el cliente (nadie puede hacerse
   pasar por otro comercio).
2. En las rutas `/api/**` (salvo el login y el webhook) exige `Authorization: Bearer <jwt>`. Sin token, con una
   firma inválida o con el token expirado responde **401**.
3. Valida la firma con la misma clave con que ms-autenticacion firma el token (`JWT_SECRET`, HMAC). La
   validación es local: el gateway no llama a ms-autenticacion en cada petición.
4. Revisa el rol del token: `OPERARIO` usa toda la API; `COMERCIO` solo puede hacer `GET` de
   `/api/v1/ordenes`, `/api/v1/ordenes/{id}` y `/api/v1/productos`. Cualquier otra cosa responde **403**.
5. **Tenant Isolation**: a un `COMERCIO` le fuerza `?comercioId=<su comercio>` al listar órdenes y reenvía su
   identidad en `X-Usuario`, `X-Rol` y `X-Comercio-Id`, que ms-ordenes usa para no mostrarle órdenes ajenas.

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login -H "Content-Type: application/json" \
  -d '{"username":"operario","password":"Operario.2026"}' | jq -r .token)
curl -i http://localhost:8080/api/v1/productos                                  # 401
curl -i http://localhost:8080/api/v1/productos -H "Authorization: Bearer $TOKEN"  # 200
```

## Autenticación máquina a máquina del webhook
La Lambda procesadora no es un usuario y no tiene JWT. Entra por `/api/v1/webhooks/ordenes`, donde el filtro
`ApiKeyGatewayFilterFactory` exige la cabecera `X-Api-Key` con la clave compartida (`WEBHOOK_API_KEY`):
- Sin cabecera o con una clave incorrecta responde **401** y la petición nunca llega a ms-ordenes.
- Con la clave correcta reescribe la ruta a `/api/v1/ordenes` y la reenvía.
- La comparación se hace en tiempo constante (`MessageDigest.isEqual`) y el gateway no arranca si la clave está
  vacía.

```bash
curl -i -X POST http://localhost:8080/api/v1/webhooks/ordenes \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: clave-local-solo-para-desarrollo" \
  -d '{"externalOrderId":"shopify-001","comercioId":"comercio-123","items":[{"productoId":"SKU-1","cantidad":1}]}'
```

## Estructura
```
src/main/java/com/bodeganube/gateway
├── MsGatewayApplication.java
└── filter/   JwtAutenticacionFilter       GlobalFilter: JWT, RBAC y Tenant Isolation
              ApiKeyGatewayFilterFactory   filtro "ApiKey" de la ruta del webhook (application.yml)
```

## Levantar el gateway desde cero

### 1. Requisitos
- JDK 17 o superior (`java -version`) y Git.
- **No hace falta instalar Maven**: el repositorio trae el Maven Wrapper (`mvnw` y `mvnw.cmd`).
- Para que las rutas respondan, los 4 microservicios tienen que estar corriendo. Lo más simple es levantar todo
  con Docker Compose (ver abajo).

### 2. Clonar, compilar y ejecutar
```bash
git clone https://github.com/Caso-Bodega/ms-gateway.git
cd ms-gateway
.\mvnw.cmd clean package        # Windows (PowerShell); en Linux, macOS o Git Bash: ./mvnw clean package
java -jar target/ms-gateway.jar
```
Queda escuchando en `http://localhost:8080`.

### 3. Probar con Postman
Importa `postman/ms-gateway.postman_collection.json` y usa *Run collection* con todo el sistema arriba
(`docker compose up -d --build` en [bodeganube-infra](https://github.com/Caso-Bodega/bodeganube-infra)). Ejecuta
18 peticiones: login de operario y comercio, 401 sin token o con token inválido, el webhook con y sin API key
(201 y luego 200 por idempotencia), el aislamiento por comercio, los 403 por rol y la salud de cada servicio.
Para probar el clúster, cambia la variable `baseUrl` a `http://<IP-del-manager>:8080`.

## Configuración

| Variable | Valor por defecto |
|---|---|
| `PORT` | `8080` |
| `JWT_SECRET` | clave de desarrollo; **debe ser la misma de ms-autenticacion** (mínimo 32 caracteres) |
| `WEBHOOK_API_KEY` | `clave-local-solo-para-desarrollo` |
| `MS_AUTENTICACION_URL` | `http://localhost:8081` |
| `MS_ORDENES_URL` | `http://localhost:8082` |
| `MS_INVENTARIO_URL` | `http://localhost:8083` |
| `MS_PICKING_URL` | `http://localhost:8084` |

En Docker Swarm `JWT_SECRET` y `WEBHOOK_API_KEY` llegan como secretos (`/run/secrets`) y las URL apuntan al
nombre de cada servicio en la red overlay (`http://ms-ordenes:8082`), que Swarm balancea entre sus réplicas.

## Pruebas automatizadas
`.\mvnw.cmd test` corre 17 pruebas:
- `JwtAutenticacionFilterTest`: login público, 401 sin token, con otra firma o expirado, identidad agregada
  para el operario, comercio limitado a sus órdenes, 403 por rol y borrado de cabeceras falsas.
- `ApiKeyGatewayFilterFactoryTest`: el webhook sin clave o con clave incorrecta no se reenvía.
- `RutasGatewayTest`: levanta el gateway con el `application.yml` real y comprueba las rutas `/api/v1`, que el
  webhook exige API key y que las rutas sin versión ya no existen.

## Docker
La imagen se construye con el `Dockerfile` de la raíz, en dos etapas (`eclipse-temurin:17-jdk-alpine` para
compilar y `eclipse-temurin:17-jre-alpine` para ejecutar). La imagen final pesa unos 100 MB, corre con el
usuario sin privilegios `bodega`, trae un `HEALTHCHECK` contra `/actuator/health/liveness` y separa el `.jar`
en capas para que un cambio de código no vuelva a subir las dependencias.

```bash
docker build -t ms-gateway .
docker run -p 8080:8080 ms-gateway
```

## CI/CD (GitHub Actions)
Pipeline en `.github/workflows/ci-cd.yml`:

| Evento | Etapas |
|---|---|
| Pull request a `develop` o `main` | **1. Build y test**: `./mvnw verify` con JDK 17 |
| Push a `develop` | 1 + **2. Imagen**: publica `ghcr.io/caso-bodega/ms-gateway:develop` |
| Push a `main` (merge del PR) | 1 + 2 (etiquetas `latest` y `sha-<commit>`) + **3. Despliegue** en el clúster Swarm de AWS (rolling update con rollback) y verificación de `http://<manager>:8080/actuator/health` |

## Ramas
`main` tiene la versión entregada, `develop` integra el trabajo en curso y cada cambio entra desde una rama
`feature/...` con un Pull Request hacia `develop`.

## Próximos pasos
- Limitar peticiones por usuario (rate limiting con Redis) además del límite global de Amazon API Gateway.
- Validar tokens firmados con RSA (RS256) para no compartir la clave HMAC entre servicios.
