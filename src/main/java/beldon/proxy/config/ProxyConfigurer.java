package beldon.proxy.config;


import beldon.proxy.config.properties.ProxyProperties;

/**
 * @author Beldon
 * @create 2018-07-12 12:21
 */
public interface ProxyConfigurer {

    void registryProxyFilter(ProxyFilterRegistry registry);

    void configure(ProxyProperties config);
}
