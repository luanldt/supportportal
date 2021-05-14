package com.supportportal.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.supportportal.constant.SecurityConstant;
import com.supportportal.domain.HttpResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;

import static org.springframework.http.HttpStatus.FORBIDDEN;

@Component
public class JwtAuthenticationEntryPoint extends Http403ForbiddenEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException exception) throws IOException {
        var httpResponse = new HttpResponse(FORBIDDEN.value(), FORBIDDEN, FORBIDDEN.getReasonPhrase().toUpperCase(), SecurityConstant.FORBIDDEN_MESSAGE);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(FORBIDDEN.value());

        OutputStream os = response.getOutputStream();
        ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(os, httpResponse);
        os.flush();
    }
}
