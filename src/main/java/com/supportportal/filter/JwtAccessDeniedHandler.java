package com.supportportal.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.supportportal.constant.SecurityConstant;
import com.supportportal.domain.HttpResponse;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;

import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Component
public class JwtAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        var httpResponse = new HttpResponse(UNAUTHORIZED.value(), UNAUTHORIZED, UNAUTHORIZED.getReasonPhrase().toUpperCase(), SecurityConstant.ACCESS_DENIED_MESSAGE);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(UNAUTHORIZED.value());

        OutputStream os = response.getOutputStream();
        ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(os, httpResponse);
        os.flush();
    }
}
