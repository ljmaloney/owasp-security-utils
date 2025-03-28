/* (C)2025 */
package com.green.yp.security;

import java.io.IOException;
import java.io.InputStream;
import java.util.regex.Pattern;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;

public class SanitizeInputStream implements XssSanitizeInterface {

    private static final char JSON_STRING_DELIMITER = '"';
    private static final Pattern PATTERN_NULL = Pattern.compile("\0");

    private final StringBuilder cleanJsonString = new StringBuilder(512);

    private static Encoder esapiEncoder;

    public SanitizeInputStream(InputStream streamToSanitize) throws IOException {
        sanitizeInput(streamToSanitize);
    }

    private void sanitizeInput(InputStream streamToSanitize) throws IOException {
        StringBuilder stringToSanitize = new StringBuilder();

        int count = 0, ch, prevCh = 0;
        boolean foundString = false;
        while ((ch = streamToSanitize.read()) != -1) {
            if (JSON_STRING_DELIMITER == (char) ch && !foundString) { // test for start delimiter
                foundString = true;
                stringToSanitize.setLength(0);
                continue;
            } else if (JSON_STRING_DELIMITER == (char) ch
                    && '\\' != (char) prevCh
                    && foundString) { // test for end delimiter
                cleanJsonString
                        .append("\"")
                        .append(cleanXSS(stringToSanitize.toString()))
                        .append("\"");
                foundString = false;
                continue;
            }
            if (foundString) { // test for outside delimiter
                stringToSanitize.append((char) ch);
            } else {
                cleanJsonString.append((char) ch);
            }
            prevCh = ch;
        }
    }

    @Override
    public Encoder getEsapiEncoder() {
        if (esapiEncoder == null) {
            ESAPI.initialize("org.owasp.esapi.reference.DefaultSecurityConfiguration");
            esapiEncoder = ESAPI.encoder();
            //            esapiEncoder = new
            // DefaultEncoder(List.of("JSONCodec","HTMLEntityCodec","PercentCodec"));
        }
        return esapiEncoder;
    }

    public byte[] getBytes() {
        return cleanJsonString.toString().getBytes();
    }

    public String toString() {
        return cleanJsonString.toString();
    }
}
