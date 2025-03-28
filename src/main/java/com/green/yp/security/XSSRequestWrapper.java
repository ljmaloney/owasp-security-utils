/* (C)2025 */
package com.green.yp.security;

import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.io.IOException;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;
import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;
import org.owasp.esapi.ESAPI;

/**
 * Class extending <code>HttpServletRequestWrapper</code> and providing functionality using
 * ESAPI and JSOUP to sanitize input parameters and json payloads.
 */
@Slf4j
public final class XSSRequestWrapper extends HttpServletRequestWrapper {

    // Avoid null characters
    private static final Pattern PATTERN_NULL = Pattern.compile("\0");

    public XSSRequestWrapper(final HttpServletRequest servletRequest) {

        super(servletRequest);
    }

    @Override
    public Object getAttribute(final String name) {

        final Object attribute = super.getAttribute(name);
        if (Objects.nonNull(attribute) && attribute instanceof String) {
            return cleanXSS(attribute.toString());
        }
        return attribute;
    }

    @Override
    public String[] getParameterValues(final String parameter) {

        final String[] values = super.getParameterValues(parameter);

        if (values == null) {
            return new String[0];
        }
        return getArray(values);
    }

    @Override
    public String getParameter(final String parameter) {
        final String value = super.getParameter(parameter);
        return cleanXSS(value);
    }

    @Override
    public String getHeader(final String name) {
        final String value = super.getHeader(name);
        return cleanXSS(value);
    }

    @Override
    public Enumeration<String> getHeaders(final String name) {

        final Enumeration<String> headers = super.getHeaders(name);

        final List<String> list = new ArrayList<>();
        while (headers.hasMoreElements()) {
            list.add(cleanXSS(headers.nextElement()));
        }

        if (list.isEmpty()) {
            return headers;
        } else {
            return Collections.enumeration(list);
        }
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
        if (super.getContentType().equalsIgnoreCase("application/json")) {
            log.trace("Sanitize JSON payload");
            return new BufferedXssJsonInputStream(
                    super.getInputStream(), XSSRequestWrapper::cleanXSS);
        }
        return super.getInputStream();
    }

    @Override
    public String getRequestURI() {
        String value = super.getRequestURI();
        if (value == null) {
            return null;
        }
        return cleanXSSWithHtmlEscape(value);
    }

    @Override
    public String getRemoteAddr() {
        String value = super.getRemoteAddr();
        if (value == null) {
            return null;
        }
        return cleanXSS(value);
    }

    @Override
    public String getQueryString() {
        String value = super.getQueryString();
        if (value == null) {
            return null;
        }
        return cleanXSS(value);
    }

    @Override
    public Map<String, String[]> getParameterMap() {

        final Map<String, String[]> parameterMap = super.getParameterMap();
        if (parameterMap.isEmpty()) {
            return parameterMap;
        }

        return parameterMap.entrySet().stream()
                .collect(
                        Collectors.toUnmodifiableMap(
                                Map.Entry::getKey, entry -> getArray(entry.getValue())));
    }

    /**
     * Clean the String to avoid Reflected XSS Client issue
     */
    public static String cleanXSS(String value) {

        if (StringUtils.isNotEmpty(value)) {
            String stripedValue = getCanonicalizedString(value);
            return Jsoup.clean(stripedValue, Safelist.simpleText());
        }
        return value;
    }

    /**
     * Encode String with ESAPI
     */
    public static String getCanonicalizedString(final String value) {
        ESAPI.initialize("org.owasp.esapi.reference.DefaultSecurityConfiguration");
        String stripedValue = ESAPI.encoder().canonicalize(value);

        // Avoid null characters
        stripedValue = PATTERN_NULL.matcher(stripedValue).replaceAll("");
        return stripedValue;
    }

    /**
     * Clean and apply HTML Escape for usage in REST Urls
     */
    public static String cleanXSSWithHtmlEscape(String value) {
        return StringEscapeUtils.escapeHtml(cleanXSS(value));
    }

    private String[] getArray(final String[] values) {

        return Arrays.stream(values).map(XSSRequestWrapper::cleanXSS).toArray(String[]::new);
    }
}
