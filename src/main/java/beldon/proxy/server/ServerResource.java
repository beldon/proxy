package beldon.proxy.server;

import beldon.proxy.config.properties.ProxyProperties;
import beldon.proxy.crt.CertFactory;
import beldon.proxy.crt.CertGenerator;
import beldon.proxy.crt.CertHolder;
import beldon.proxy.filter.ProxyFilter;
import beldon.proxy.filter.chain.ProxyFilterChain;
import io.netty.handler.ssl.SslContext;

public interface ServerResource {
    CertHolder getCertHolder();

    ProxyProperties getConfigProperties();

    CertFactory getCertFactory();

    SslContext getClientSslContext();

    ProxyFilterChain getFilterChin(ProxyFilter finalFilter);

    CertGenerator getCertGenerator();
}
