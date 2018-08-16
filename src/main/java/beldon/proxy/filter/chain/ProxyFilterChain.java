package beldon.proxy.filter.chain;

import io.netty.channel.Channel;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;

/**
 * @author Beldon
 * @create 2018-07-12 11:36
 */
public interface ProxyFilterChain{
    void doFilter(Channel clientChannel, HttpRequest httpRequest);
    void doFilter(Channel clientChannel, HttpContent httpContent);
    void doFilter(Channel clientChannel, Channel proxyChannel, HttpResponse httpResponse);
    void doFilter(Channel clientChannel, Channel proxyChannel, HttpContent httpContent);
}
