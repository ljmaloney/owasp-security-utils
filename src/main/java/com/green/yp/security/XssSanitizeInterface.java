/* (C)2025 */
package com.green.yp.security;

import java.util.regex.Pattern;
import org.apache.commons.lang3.StringUtils;
import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;
import org.owasp.esapi.Encoder;

public interface XssSanitizeInterface {

    Pattern PATTERN_NULL = Pattern.compile("\0");

    default String cleanXSS(String value) {
        if (StringUtils.isNotEmpty(value)) {
            String stripedValue = getCanonicalizedString(value);
            var cleanJson = Jsoup.clean(stripedValue, Safelist.relaxed());
            return cleanJson
                    .replace(Character.toString((char) 92), "\\")
                    .replace("\n", "\\n")
                    .replace("\t", "\\t")
                    .replace("\r", "\\r")
                    .replace(Character.toString('"'), "\"");
        }
        return value;
    }

    default String getCanonicalizedString(final String value) {
        String stripedValue = getEsapiEncoder().canonicalize(value);
        // Avoid null characters
        stripedValue = PATTERN_NULL.matcher(stripedValue).replaceAll("");

        return stripedValue;
    }

    Encoder getEsapiEncoder();
}
