package beldon.proxy.filter.chain;

import beldon.proxy.config.ProxyFilterWrapper;
import io.netty.channel.Channel;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import lombok.extern.slf4j.Slf4j;

/**
 * @author Beldon
 * @create 2018-07-13 11:00
 */
@SuppressWarnings("Duplicates")
@Slf4j
public class DefaultProxyFilterChain implements ProxyFilterChain {

    private final ProxyFilterWrapper[] filterWrappers;

    public DefaultProxyFilterChain(ProxyFilterWrapper[] filterWrappers) {
        this.filterWrappers = filterWrappers;
    }

    @Override
    public void doFilter(Channel clientChannel, HttpRequest httpRequest) {
        new SubProxyChain(filterWrappers).doFilter(clientChannel, httpRequest);
    }

    @Override
    public void doFilter(Channel clientChannel, HttpContent httpContent) {
        new SubProxyChain(filterWrappers).doFilter(clientChannel, httpContent);
    }

    @Override
    public void doFilter(Channel clientChannel, Channel proxyChannel, HttpResponse httpResponse) {
        new SubProxyChain(filterWrappers).doFilter(clientChannel, proxyChannel, httpResponse);
    }

    @Override
    public void doFilter(Channel clientChannel, Channel proxyChannel, HttpContent httpContent) {
        new SubProxyChain(filterWrappers).doFilter(clientChannel, proxyChannel, httpContent);

    }


    private static class SubProxyChain implements ProxyFilterRequestChain, ProxyFilterRequestContentChain
            , ProxyFilterResponseChain, ProxyFilterResponseContentChain, ProxyFilterChain {

        private final ProxyFilterWrapper[] filterWrappers;
        private volatile int requestPos = 0;
        private volatile int requestContentPos = 0;

        private volatile int responsePost = 0;
        private volatile int responseContentPost = 0;

        public SubProxyChain(ProxyFilterWrapper[] filterWrappers) {
            this.filterWrappers = filterWrappers;
        }

        @Override
        public void doFilter(Channel clientChannel, HttpRequest httpRequest) {
            if (hasFilter() && requestPos < filterWrappers.length) {
                ProxyFilterWrapper filterWrapper = filterWrappers[requestPos];
                requestPos++;
                filterWrapper.getFilter().beforeRequest(clientChannel, httpRequest, this);
            }
        }

        @Override
        public void doFilter(Channel clientChannel, HttpContent httpContent) {
            if (hasFilter() && requestContentPos < filterWrappers.length) {
                ProxyFilterWrapper filterWrapper = filterWrappers[requestContentPos];
                requestContentPos++;
                filterWrapper.getFilter().beforeRequest(clientChannel, httpContent, this);
            }
        }

        @Override
        public void doFilter(Channel clientChannel, Channel proxyChannel, HttpResponse httpResponse) {
            if (hasFilter() && responsePost < filterWrappers.length) {
                ProxyFilterWrapper filterWrapper = filterWrappers[responsePost];
                responsePost++;
                filterWrapper.getFilter().afterResponse(clientChannel, proxyChannel, httpResponse, this);
            }
        }

        @Override
        public void doFilter(Channel clientChannel, Channel proxyChannel, HttpContent httpContent) {
            if (hasFilter() && responseContentPost < filterWrappers.length) {
                ProxyFilterWrapper filterWrapper = filterWrappers[responseContentPost];
                responseContentPost++;
                filterWrapper.getFilter().afterResponse(clientChannel, proxyChannel, httpContent, this);
            }
        }


        private boolean hasFilter() {
            return filterWrappers != null && filterWrappers.length > 0;
        }
    }

}
