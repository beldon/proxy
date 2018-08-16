package beldon.proxy.filter.chain;

import io.netty.channel.Channel;
import io.netty.handler.codec.http.HttpRequest;

/**
 * @author Beldon
 * @create 2018-07-13 10:52
 */
public interface ProxyFilterRequestChain {
    void doFilter(Channel clientChannel, HttpRequest httpRequest);
}
