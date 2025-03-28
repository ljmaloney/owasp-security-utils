/* (C)2025 */
package com.green.yp.security;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.function.Function;
import java.util.regex.Pattern;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;

/**
 * Provides a Buffered ServletInputStream for the purpose of sanitization of JSON documents.
 * Considerations: This class is intended to work documents less than 512 bytes to 2kb. This
 * technique can have performance and memory impacts. The class attempts to parse the JSON stream
 * into a Map<String,Object>, and then sanitizes the values in the Map before writing back out.
 *
 * @author luther.maloney
 */
@Slf4j
public class BufferedXssJsonInputStream extends ServletInputStream {
    private ByteArrayInputStream byteArrayStream;
    private final Function<String, String> xssEscapeFunction;

    private Boolean finished = Boolean.FALSE;

    private static final char JSON_STRING_DELIMITER = '"';
    private static final Pattern PATTERN_NULL = Pattern.compile("\0");

    private static Encoder esapiEncoder;

    public BufferedXssJsonInputStream(
            ServletInputStream inputStream, Function<String, String> xssEscapeFunction)
            throws IOException {
        this(
                inputStream,
                512,
                xssEscapeFunction != null
                        ? xssEscapeFunction
                        : BufferedXssJsonInputStream::cleanXSS);
    }

    public BufferedXssJsonInputStream(
            ServletInputStream inputStream,
            int contentSize,
            Function<String, String> xssEscapeFunction)
            throws IOException {
        log.debug("Initializing buffered input stream to filter XSS");
        this.xssEscapeFunction = xssEscapeFunction;
        sanitizeInput(inputStream, contentSize);
    }

    private void sanitizeInput(ServletInputStream inputStream, int contentSize) throws IOException {
        StringBuilder stringBuilder = new StringBuilder(contentSize);
        StringBuilder stringToSanitize = new StringBuilder();

        int count = 0, ch, prevCh = 0;
        boolean foundString = false;
        while ((ch = inputStream.read()) != -1) {
            if (JSON_STRING_DELIMITER == (char) ch && !foundString) { // test for start delimiter
                foundString = true;
                stringToSanitize.setLength(0);
                continue;
            } else if (JSON_STRING_DELIMITER == (char) ch
                    && '\\' != (char) prevCh
                    && foundString) { // test for end delimiter
                stringBuilder
                        .append("\"")
                        .append(xssEscapeFunction.apply(stringToSanitize.toString()))
                        .append("\"");
                foundString = false;
                continue;
            }
            if (foundString) { // test for outside delimiter
                stringToSanitize.append((char) ch);
            } else {
                stringBuilder.append((char) ch);
            }
            prevCh = ch;
        }
        byteArrayStream = new ByteArrayInputStream(stringBuilder.toString().getBytes());
    }

    public static String cleanXSS(String value) {
        if (StringUtils.isNotEmpty(value)) {
            String stripedValue = getCanonicalizedString(value);
            return Jsoup.clean(stripedValue, Safelist.simpleText());
        }
        return value;
    }

    public static String getCanonicalizedString(final String value) {
        if (esapiEncoder == null) {
            ESAPI.initialize("org.owasp.esapi.reference.DefaultSecurityConfiguration");
            esapiEncoder = ESAPI.encoder();
        }
        String stripedValue = esapiEncoder.canonicalize(value);

        // Avoid null characters
        stripedValue = PATTERN_NULL.matcher(stripedValue).replaceAll("");
        return stripedValue;
    }

    @Override
    public boolean isFinished() {
        return finished.booleanValue();
    }

    @Override
    public boolean isReady() {
        return byteArrayStream != null;
    }

    @Override
    public void setReadListener(ReadListener listener) {
        //        servletInputStream.setReadListener(listener);
    }

    @Override
    public int read() throws IOException {
        int c = byteArrayStream.read();
        if (c == -1) {
            finished = Boolean.TRUE;
        }
        return c;
    }
}
