package com.green.yp.security

import org.mockito.Mockito;
import jakarta.servlet.http.HttpServletRequest;
import spock.lang.Specification

class XssServletRequestWrapperSpec extends Specification {
    def "sanitize parameter values"() {
//        given:
//            def request = Mockito.mock(HttpServletRequest.class);
//            String[] parameters = ["<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>1",
//                                              "data<iframe src=http://xss.rocks/scriptlet.html/>"];
//            def xssWrapper = new XssServletRequestWrapper(request);
//        when:
//            Mockito.when(request.getParameterValues("parameter")).thenReturn(parameters);
//            String[] santiziedParams = xssWrapper.getParameterValues("parameter");
//        then:
//            santiziedParams == ["1","data"];
    }
}
