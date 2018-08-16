package beldon.proxy.filter.chain;

import io.netty.channel.Channel;
import io.netty.handler.codec.http.HttpResponse;

/**
 * @author Beldon
 * @create 2018-07-13 10:52
 */
public interface ProxyFilterResponseChain {
    void doFilter(Channel clientChannel, Channel proxyChannel, HttpResponse httpResponse);
}
