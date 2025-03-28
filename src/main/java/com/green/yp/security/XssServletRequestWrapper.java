/* (C)2025 */
package com.green.yp.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.util.*;
import java.util.stream.StreamSupport;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;

/**
 * XssServletRequestWrapper
 * This class extends <code>HttoServletRequestWrapper</code> and uses StringEscapeUtils to sanitize input
 * strings using <code>org.apache.commons.lang.StringEscapeUtils</code>. This will have marginally better
 * performance than <code>XSSRequestWrapper</code> which uses ESAPI and JSOUP.
 */
@Slf4j
public class XssServletRequestWrapper extends HttpServletRequestWrapper {
    public XssServletRequestWrapper(HttpServletRequest request) {
        super(request);
    }

    @Override
    public String[] getParameterValues(final String parameter) {
        log.trace("Return sanitized parameter values for {}", parameter);
        List<String> parameters =
                Arrays.stream(super.getParameterValues(parameter))
                        .map(XssServletRequestWrapper::sanitizeInputString)
                        .toList();
        return parameters.toArray(new String[1]);
    }

    @Override
    public String getParameter(final String parameter) {
        log.trace("Return sanitized parameter value for {}", parameter);
        return sanitizeInputString(super.getParameter(parameter));
    }

    @Override
    public String getQueryString() {
        log.trace("Return sanitized query string");
        String queryString = super.getQueryString();
        if (StringUtils.isBlank(queryString)) {
            return null;
        }
        StringBuilder queryStringBuilder = new StringBuilder();
        Enumeration<String> parameterNames = super.getParameterNames();
        StreamSupport.stream(
                        Spliterators.spliteratorUnknownSize(
                                parameterNames.asIterator(), Spliterator.ORDERED),
                        false)
                .forEach(parameterName -> appendSanitized(parameterName, queryStringBuilder));
        return queryStringBuilder.toString();
    }

    public static String sanitizeInputString(final String userInput) {
        return StringEscapeUtils.escapeHtml(
                StringEscapeUtils.escapeXml(StringEscapeUtils.escapeJavaScript(userInput)));
    }

    private void appendSanitized(String parameterName, StringBuilder queryStringBuilder) {
        if (!queryStringBuilder.isEmpty()) {
            queryStringBuilder.append("&");
        }
        queryStringBuilder.append(parameterName).append("=").append(getParameter(parameterName));
    }
}
