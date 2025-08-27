package com.automationedge.reimbursement.security;

import com.automationedge.platform.security.jwt.JwtUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

/**
 * Filter that validates JWT tokens for /v1/tables/** endpoints.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  public static final String JWT_CLAIM_ROLES = "roles";
  private static final String AUTHORIZATION_HEADER_BEARER_TOKEN = "Bearer ";
  private static final String COOKIE_JWT_SIGNATURE = "ae_jwt_sign";
  private static final String COOKIE_JWT_PAYLOAD = "ae_jwt_payload";
  private final JwtUtil jwtUtil;

  private static Optional<String> getJwtFromCookie(HttpServletRequest request) {
    Optional<String> optionalJwt = Optional.empty();
    Cookie signatureCookie = WebUtils.getCookie(request, COOKIE_JWT_SIGNATURE);
    Cookie payloadCookie = WebUtils.getCookie(request, COOKIE_JWT_PAYLOAD);
    if (signatureCookie != null && payloadCookie != null) {
      String[] split = signatureCookie.getValue().split("\\.");
      String jwt = java.lang.String.format("%s.%s.%s", split[0], payloadCookie.getValue(), split[1]);
      optionalJwt = Optional.of(jwt);
    }

    return optionalJwt;
  }

  public static Optional<String> getJwtFromRequest(HttpServletRequest request) {
    Optional<String> optionalJwt = getJwtFromCookie(request);
    if (optionalJwt.isEmpty()) {
      optionalJwt = getJwtFromHeader(request);
    }
    return optionalJwt;
  }

  private static Optional<String> getJwtFromHeader(HttpServletRequest request) {
    Optional<String> optionalJwt = Optional.empty();
    String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
    if (StringUtils.hasText(authHeader) && authHeader.startsWith(AUTHORIZATION_HEADER_BEARER_TOKEN)) {
      String jwt = authHeader.substring(AUTHORIZATION_HEADER_BEARER_TOKEN.length());
      if (!jwt.startsWith("ott:")) {
        optionalJwt = Optional.of(jwt);
      }
    }

    return optionalJwt;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    Optional<String> optionalJwt = getJwtFromRequest(request);

    if (optionalJwt.isPresent()) {
      try {
        if (jwtUtil.validateToken(optionalJwt.get(), request.getRemoteAddr())) {
          setSecurityContext(optionalJwt.get());
        } else {
//          JwtCookieHelper.deleteJwtCookies(response);
        }
      } catch (ExpiredJwtException ex) {
        log.debug("jwt token expired");
        request.setAttribute("jwt.expired", true);
      } catch (Exception ex) {
        log.debug("Failed to get jwt token", ex);
//        JwtCookieHelper.deleteJwtCookies(response);
      }

    }

    // Continue request chain
    filterChain.doFilter(request, response);
  }

  private void setSecurityContext(String token) throws JsonProcessingException {
    Claims claims = jwtUtil.extractAllClaims(token);

    List<GrantedAuthority> authorities = new ArrayList<>();
    String role = claims.get(JWT_CLAIM_ROLES, String.class);
    authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
    log.info("authorities-{}", authorities);
    UserPrincipal userPrincipal = new UserPrincipal(claims.getSubject(), claims.get("user_id", Long.class),
        claims.get("tenant_id", Long.class));

    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
        userPrincipal, null, authorities);
    SecurityContextHolder.getContext().setAuthentication(authentication);

  }
}
