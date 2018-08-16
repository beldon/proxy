package beldon.proxy;


import beldon.proxy.config.ProxyConfigurer;
import beldon.proxy.config.ProxyFilterRegistry;
import beldon.proxy.config.properties.ProxyProperties;
import beldon.proxy.filter.ProxyFilter;
import beldon.proxy.filter.chain.ProxyFilterRequestChain;
import beldon.proxy.filter.chain.ProxyFilterRequestContentChain;
import beldon.proxy.filter.chain.ProxyFilterResponseChain;
import beldon.proxy.filter.chain.ProxyFilterResponseContentChain;
import beldon.proxy.server.HttpProxyServer;
import beldon.proxy.server.ProxyServer;
import io.netty.channel.Channel;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;

public class ServerTest {
    public static void main(String[] args) throws Exception {
        ProxyServer proxyServer = new HttpProxyServer(proxyConfigurer());
        proxyServer.start();
    }


    public static ProxyConfigurer proxyConfigurer() {
        return new ProxyConfigurer() {
            @Override
            public void registryProxyFilter(ProxyFilterRegistry registry) {
//                registry.add(null);
//                registry.add(filter());
            }

            @Override
            public void configure(ProxyProperties config) {
                config.setPort(9999);
                config.setCaPath("ca.crt");
                config.setCaPrivatePath("ca_private.der");
            }
        };
    }

    private static ProxyFilter filter() {
        return new ProxyFilter() {
            @Override
            public void beforeRequest(Channel clientChannel, HttpRequest httpRequest, ProxyFilterRequestChain chain) {
                System.out.println("beforeRequest1");
            }

            @Override
            public void beforeRequest(Channel clientChannel, HttpContent httpContent, ProxyFilterRequestContentChain chain) {
                System.out.println("beforeRequest2");
            }

            @Override
            public void afterResponse(Channel clientChannel, Channel proxyChannel, HttpResponse httpResponse, ProxyFilterResponseChain chain) {
                System.out.println("afterResponse1");
            }

            @Override
            public void afterResponse(Channel clientChannel, Channel proxyChannel, HttpContent httpContent, ProxyFilterResponseContentChain chain) {
                System.out.println("afterResponse2");
            }
        };
    }
}
