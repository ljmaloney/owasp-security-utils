package com.green.yp.security

import com.fasterxml.jackson.databind.ObjectMapper
import org.apache.commons.collections.CollectionUtils
import org.apache.commons.collections.MapUtils
import org.springframework.util.ResourceUtils
import spock.lang.Specification

import java.nio.file.Files

import static org.assertj.core.api.Assertions.assertThat

class SanitizeInputStreamSpec extends Specification {

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
        def sanitizeInputStream = new SanitizeInputStream(new ByteArrayInputStream(mapper.writeValueAsBytes(jsonMap)))
        def cleanedJsonMap = new ObjectMapper().readValue(sanitizeInputStream.toString(), Map.class)

        then:
        cleanedJsonMap.get("propertyOne") == jsonMap.get("propertyOne")
        cleanedJsonMap.get("xssString1") == "CE"
        cleanedJsonMap.get("xssString2") == "<img>1"
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
        def sanitizeInputStream = new SanitizeInputStream(new ByteArrayInputStream(mapper.writeValueAsBytes(jsonMap)))
        def cleanedJsonMap = new ObjectMapper().readValue(sanitizeInputStream.toString(), Map.class)

        then:
        cleanedJsonMap.get("propertyOne") == jsonMap.get("propertyOne")
        cleanedJsonMap.get("xssString1") == "CE"
        ((Map) cleanedJsonMap.get("subDocument")).get("xssString2") == "<img>1"
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
        def sanitizeInputStream = new SanitizeInputStream(new ByteArrayInputStream(mapper.writeValueAsBytes(jsonMap)))
        def cleanedJsonMap = new ObjectMapper().readValue(sanitizeInputStream.toString(), Map.class)

        then:
        cleanedJsonMap.get("propertyOne") == jsonMap.get("propertyOne")
        cleanedJsonMap.get("xssString1") == "CE"
        cleanedJsonMap.get("integerProperty") == jsonMap.get("integerProperty")
        getSubDocumentValue(cleanedJsonMap, 0, "subDocumentList", "xssString2") == "<img>1"
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
        def sanitizeInputStream = new SanitizeInputStream(new ByteArrayInputStream(mapper.writeValueAsBytes(jsonMap)))
        def cleanedJsonMap = new ObjectMapper().readValue(sanitizeInputStream.toString(), Map.class)

        then:
        cleanedJsonMap.get("propertyOne") == jsonMap.get("propertyOne")
        cleanedJsonMap.get("xssString1") == "CE"
        cleanedJsonMap.get("integerProperty") == jsonMap.get("integerProperty")
        cleanedJsonMap.get("stringArray") == List.of("Tortuga", "alpha", "<img>omega")
        getSubDocumentValue(cleanedJsonMap, 0, "subDocumentList", "xssString2") == "<img>1"
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
        def sanitizeInputStream = new SanitizeInputStream(new ByteArrayInputStream(mapper.writeValueAsBytes(jsonList)))
        def cleanedList = new ObjectMapper().readValue(sanitizeInputStream.toString(), List.class)

        then:
        cleanedList.size() == 1
        ((Map) cleanedList.get(0)).get("propertyOne") == jsonMap.get("propertyOne")
        ((Map) cleanedList.get(0)).get("xssString1") == "CE"
        ((Map) cleanedList.get(0)).get("integerProperty") == jsonMap.get("integerProperty")
        ((Map) cleanedList.get(0)).get("stringArray") == List.of("Tortuga", "alpha", "<img>omega")
        getSubDocumentValue(((Map) cleanedList.get(0)), 0, "subDocumentList", "xssString2") == "<img>1"
        getSubDocumentValue(((Map) cleanedList.get(0)), 0, "subDocumentList", "xssString3") == "data"
    }

    def "sanitize child-info-event"() {
        given:
        def uncleanJson = loadJsonString("child-event-info.json")
        when:
        def sanitizeInputStream = new SanitizeInputStream(new ByteArrayInputStream(uncleanJson.getBytes()))
        def sanitizedJson = sanitizeInputStream.toString()
        def parsedJsonMap = new ObjectMapper().readValue(sanitizedJson, HashMap.class)

        then:
        sanitizedJson != null
        Boolean.TRUE == MapUtils.isNotEmpty(parsedJsonMap)
        Boolean.TRUE == parsedJsonMap.get("description").toString().contains("\n")
        CollectionUtils.isNotEmpty((List) parsedJsonMap.get("eligibleRpcApc"))
        assertThat((String) parsedJsonMap.get("description")).contains("</p>\n<p>Aenean leo ligula").asBoolean()
    }

    def "sanitize document with URLs"() {
        given:
        def uncleanJson = loadJsonString("image-gallery.json")
        when:
        def sanitizeInputStream = new SanitizeInputStream(new ByteArrayInputStream(uncleanJson.getBytes()))
        def sanitizedJson = sanitizeInputStream.toString()
        def parsedJsonMap = new ObjectMapper().readValue(sanitizedJson, HashMap.class)

        then:
        sanitizedJson != null
        Boolean.TRUE == MapUtils.isNotEmpty(parsedJsonMap)
        parsedJsonMap.get("imageUrl") == "\\2023_CE_CUL_imgs_te\\e2e06d0cfa954eecbdb8493cbf06edd7_IMAGE.jpeg"
    }

    def "sanitize event description"() {
        given:
        def uncleanJson = loadJsonString("event_description.json")

        when:
        def sanitizeInputStream = new SanitizeInputStream(new ByteArrayInputStream(uncleanJson.getBytes()))
        def sanitizedJson = sanitizeInputStream.toString()

        then:
        sanitizedJson != null
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

    private String loadJsonString(String fileName) {
        File jsonFile = ResourceUtils.getFile(String.format("classpath:%s", fileName))
        return Files.readString(jsonFile.toPath())
    }
}
