package com.codigo.apigateway.filter;

import com.netflix.appinfo.InstanceInfo;
import com.netflix.discovery.EurekaClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Configuration
public class GlobalFilterConfiguration {

    @Component
    public class AuthenticationFilter implements GlobalFilter, Ordered {

        @Autowired
        private WebClient.Builder webClientBuilder;
        @Autowired
        private EurekaClient eurekaClient;
        private final AntPathMatcher antPathMatcher = new AntPathMatcher();

        private static final List<String> EXCLUDED_PATHS = List.of("/api/v1/autenticacion/**");

        @Override
        public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
            String path = exchange.getRequest().getURI().getPath();

            if(isExcludedPath(path)){
                return chain.filter(exchange);
            }

            String token = exchange.getRequest().getHeaders().getFirst("validate");

            if (token == null || token.isEmpty()){
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            String serviceUri = getServiceUri("ms-seguridad","api/v1/autenticacion/validateToken");
            System.out.println("URI DE SERVICO A CONSUMIR: " + serviceUri);

            return webClientBuilder.build()
                    .post()
                    .uri(serviceUri)
                    .header("validate",token)
                    .retrieve()
                    .bodyToMono(Boolean.class)
                    .flatMap( isValid -> {
                        if (Boolean.TRUE.equals(isValid)){
                            return chain.filter(exchange);
                        } else {
                            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                            return exchange.getResponse().setComplete();
                        }
                    })
                    .onErrorResume(e -> {
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    });

        }

        private String getServiceUri(String serviceName, String path) {
            InstanceInfo instanceInfo = eurekaClient.getNextServerFromEureka(serviceName, false);
            return instanceInfo.getHomePageUrl() + path;
        }

        private boolean isExcludedPath(String path) {
            return EXCLUDED_PATHS.stream().anyMatch(pattern -> antPathMatcher.match(pattern, path));
        }

        @Override
        public int getOrder() {
            return 0;
        }
    }
}
