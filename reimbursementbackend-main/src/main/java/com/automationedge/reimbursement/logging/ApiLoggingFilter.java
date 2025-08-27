package com.automationedge.reimbursement.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class ApiLoggingFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(ApiLoggingFilter.class);

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpReq = (HttpServletRequest) request;
        HttpServletResponse httpRes = (HttpServletResponse) response;

        long startTime = System.currentTimeMillis();

        String method = httpReq.getMethod();
        String uri = httpReq.getRequestURI();
        String query = httpReq.getQueryString();
        String fullUrl = uri + (query != null ? "?" + query : "");

        chain.doFilter(request, response);  // Proceed with request

        long duration = System.currentTimeMillis() - startTime;
        int status = httpRes.getStatus();

        logger.info("🔎 [{}] {} | Status: {} | Duration: {} ms", method, fullUrl, status, duration);
    }
}
