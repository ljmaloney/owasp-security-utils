package com.green.yp.security

import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.servlet.ReadListener
import jakarta.servlet.ServletInputStream
import spock.lang.Specification

class BufferedXssJsonInputStreamSpec extends Specification {

    ObjectMapper mapper = new ObjectMapper()

    def "Test simple json document"() {
        given:
        def jsonMap = new HashMap<String, Object>()
        jsonMap.put("propertyOne", "SomeStringProperty")
        jsonMap.put("integerProperty", Integer.valueOf(100))
        jsonMap.put("xssString1", "CE<script></script>")
        jsonMap.put("xssString2", "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>1")
        jsonMap.put("xssString3", "data<iframe src=http://xss.rocks/scriptlet.html/>")

        when:
        BufferedXssJsonInputStream jsonInputStream =
                new BufferedXssJsonInputStream(new TestServletInputStream() {
                    def byteArrayStream = new ByteArrayInputStream(mapper.writeValueAsBytes(jsonMap))

                    @Override
                    int read() throws IOException {
                        return byteArrayStream.read()
                    }
                }, null)

        def cleanedJsonMap = new ObjectMapper().readValue(jsonInputStream, Map.class)

        then:
        cleanedJsonMap.get("propertyOne") == jsonMap.get("propertyOne")
        cleanedJsonMap.get("xssString1") == "CE"
        cleanedJsonMap.get("xssString2") == "1"
        cleanedJsonMap.get("xssString3") == "data"

    }

    def "Test JSON document with sub-document"() {
        given:
        def jsonMap = new HashMap<String, Object>()
        jsonMap.put("propertyOne", "SomeStringProperty")
        jsonMap.put("integerProperty", Integer.valueOf(100))
        def jsonSubMap = new HashMap<String, Object>()
        jsonMap.put("subDocument", jsonSubMap)
        jsonMap.put("xssString1", "CE<script></script>")
        jsonSubMap.put("xssString2", "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>1")
        jsonSubMap.put("xssString3", "data<iframe src=http://xss.rocks/scriptlet.html/>")

        when:
        BufferedXssJsonInputStream jsonInputStream =
                new BufferedXssJsonInputStream(new TestServletInputStream() {
                    def byteArrayStream = new ByteArrayInputStream(mapper.writeValueAsBytes(jsonMap))

                    @Override
                    int read() throws IOException {
                        return byteArrayStream.read()
                    }
                }, 512, XSSRequestWrapper.&cleanXSS)

        def cleanedJsonMap = new ObjectMapper().readValue(jsonInputStream, Map.class)

        then:
        cleanedJsonMap.get("propertyOne") == jsonMap.get("propertyOne")
        cleanedJsonMap.get("xssString1") == "CE"
        ((Map) cleanedJsonMap.get("subDocument")).get("xssString2") == "1"
        ((Map) cleanedJsonMap.get("subDocument")).get("xssString3") == "data"
    }

    def "Test JSON document with list of sub-documents"() {
        given:
        def jsonMap = new HashMap<String, Object>()
        jsonMap.put("propertyOne", "SomeStringProperty")
        jsonMap.put("integerProperty", Integer.valueOf(100))
        jsonMap.put("xssString1", "CE<script></script>")

        def jsonSubMap = new HashMap<String, Object>()
        jsonSubMap.put("xssString2", "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>1")
        jsonSubMap.put("xssString3", "data<iframe src=http://xss.rocks/scriptlet.html/>")

        List subDocList = new ArrayList<Map<String, Object>>()
        subDocList.add(jsonSubMap)
        jsonMap.put("subDocumentList", subDocList)

        when:
        BufferedXssJsonInputStream jsonInputStream =
                new BufferedXssJsonInputStream(new TestServletInputStream() {
                    def byteArrayStream = new ByteArrayInputStream(mapper.writeValueAsBytes(jsonMap))

                    @Override
                    int read() throws IOException {
                        return byteArrayStream.read()
                    }
                }, 512, XSSRequestWrapper.&cleanXSS)

        def cleanedJsonMap = new ObjectMapper().readValue(jsonInputStream, Map.class)

        then:
        cleanedJsonMap.get("propertyOne") == jsonMap.get("propertyOne")
        cleanedJsonMap.get("xssString1") == "CE"
        cleanedJsonMap.get("integerProperty") == jsonMap.get("integerProperty")
        getSubDocumentValue(cleanedJsonMap, 0, "subDocumentList", "xssString2") == "1"
        getSubDocumentValue(cleanedJsonMap, 0, "subDocumentList", "xssString3") == "data"
    }

    def "Test complex json document"() {
        given:
        def jsonMap = new HashMap<String, Object>()
        jsonMap.put("propertyOne", "SomeStringProperty")
        jsonMap.put("integerProperty", Integer.valueOf(100))
        jsonMap.put("xssString1", "CE<script></script>")

        def jsonSubMap = new HashMap<String, Object>()
        jsonSubMap.put("xssString2", "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>1")
        jsonSubMap.put("xssString3", "data<iframe src=http://xss.rocks/scriptlet.html/>")

        jsonMap.put("stringArray", List.of("Tortuga",
                "alpha<iframe src=http://xss.rocks/scriptlet.html/>",
                "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>omega"))

        List subDocList = new ArrayList<Map<String, Object>>()
        subDocList.add(jsonSubMap)
        jsonMap.put("subDocumentList", subDocList)

        when:
        BufferedXssJsonInputStream jsonInputStream =
                new BufferedXssJsonInputStream(new TestServletInputStream() {
                    def byteArrayStream = new ByteArrayInputStream(mapper.writeValueAsBytes(jsonMap))

                    @Override
                    int read() throws IOException {
                        return byteArrayStream.read()
                    }
                }, 512, XSSRequestWrapper.&cleanXSS)

        def cleanedJsonMap = new ObjectMapper().readValue(jsonInputStream, Map.class)

        then:
        cleanedJsonMap.get("propertyOne") == jsonMap.get("propertyOne")
        cleanedJsonMap.get("xssString1") == "CE"
        cleanedJsonMap.get("integerProperty") == jsonMap.get("integerProperty")
        cleanedJsonMap.get("stringArray") == List.of("Tortuga", "alpha", "omega")
        getSubDocumentValue(cleanedJsonMap, 0, "subDocumentList", "xssString2") == "1"
        getSubDocumentValue(cleanedJsonMap, 0, "subDocumentList", "xssString3") == "data"
    }

    def "Test JSON list document"() {
        given:
        def jsonList = new ArrayList<>()

        def jsonMap = new HashMap<String, Object>()
        jsonMap.put("propertyOne", "SomeStringProperty")
        jsonMap.put("integerProperty", Integer.valueOf(100))
        jsonMap.put("xssString1", "CE<script></script>")
        jsonList.add(jsonMap)

        def jsonSubMap = new HashMap<String, Object>()
        jsonSubMap.put("xssString2", "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>1")
        jsonSubMap.put("xssString3", "data<iframe src=http://xss.rocks/scriptlet.html/>")

        jsonMap.put("stringArray", List.of("Tortuga",
                "alpha<iframe src=http://xss.rocks/scriptlet.html/>",
                "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>omega"))

        List subDocList = new ArrayList<Map<String, Object>>()
        subDocList.add(jsonSubMap)
        jsonMap.put("subDocumentList", subDocList)

        when:
        BufferedXssJsonInputStream jsonInputStream =
                new BufferedXssJsonInputStream(new TestServletInputStream() {
                    def byteArrayStream = new ByteArrayInputStream(mapper.writeValueAsBytes(jsonList))

                    @Override
                    int read() throws IOException {
                        return byteArrayStream.read()
                    }
                }, 1024, XSSRequestWrapper.&cleanXSS)

        def cleanedList = new ObjectMapper().readValue(jsonInputStream, List.class)

        then:
        cleanedList.size() == 1
        ((Map) cleanedList.get(0)).get("propertyOne") == jsonMap.get("propertyOne")
        ((Map) cleanedList.get(0)).get("xssString1") == "CE"
        ((Map) cleanedList.get(0)).get("integerProperty") == jsonMap.get("integerProperty")
        ((Map) cleanedList.get(0)).get("stringArray") == List.of("Tortuga", "alpha", "omega")
        getSubDocumentValue(((Map) cleanedList.get(0)), 0, "subDocumentList", "xssString2") == "1"
        getSubDocumentValue(((Map) cleanedList.get(0)), 0, "subDocumentList", "xssString3") == "data"
    }

    private String getSubDocumentValue(Map jsonMap, int index, String subDocKey, String key) {
        if (jsonMap.get(subDocKey) instanceof Map) {
            return ((Map) jsonMap.get(subDocKey)).get(key).toString()
        }
        if (jsonMap.get(subDocKey) instanceof List) {
            Map<String, Object> subDocMap = ((List) jsonMap.get(subDocKey)).get(index)
            return subDocMap.get(key)
        }
        return ""
    }

    abstract class TestServletInputStream extends ServletInputStream {
        @Override
        boolean isFinished() {
            return false
        }

        @Override
        boolean isReady() {
            return false
        }

        @Override
        void setReadListener(ReadListener listener) {

        }
    }
}
