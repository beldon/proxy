package beldon.proxy.filter;

import beldon.proxy.filter.chain.ProxyFilterRequestChain;
import beldon.proxy.filter.chain.ProxyFilterRequestContentChain;
import beldon.proxy.filter.chain.ProxyFilterResponseChain;
import beldon.proxy.filter.chain.ProxyFilterResponseContentChain;
import io.netty.channel.Channel;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;

/**
 * @author Beldon
 * @create 2018-07-12 11:35
 */
public interface ProxyFilter {

    default void beforeRequest(Channel clientChannel, HttpRequest httpRequest, ProxyFilterRequestChain chain) {
        chain.doFilter(clientChannel, httpRequest);
    }


    default void beforeRequest(Channel clientChannel, HttpContent httpContent, ProxyFilterRequestContentChain chain) {
        chain.doFilter(clientChannel, httpContent);
    }

    default void afterResponse(Channel clientChannel, Channel proxyChannel, HttpResponse httpResponse
            , ProxyFilterResponseChain chain) {
        chain.doFilter(clientChannel, proxyChannel, httpResponse);
    }

    default void afterResponse(Channel clientChannel, Channel proxyChannel, HttpContent httpContent
            , ProxyFilterResponseContentChain chain) {
        chain.doFilter(clientChannel, proxyChannel, httpContent);
    }

}
