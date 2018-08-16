package beldon.proxy.server;

import beldon.proxy.config.ProxyConfigurer;
import beldon.proxy.config.ProxyFilterRegistry;
import beldon.proxy.config.ProxyFilterWrapper;
import beldon.proxy.config.properties.ProxyProperties;
import beldon.proxy.crt.*;
import beldon.proxy.filter.ProxyFilter;
import beldon.proxy.filter.chain.DefaultProxyFilterChain;
import beldon.proxy.filter.chain.ProxyFilterChain;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.SSLException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * @author Beldon
 * @create 2018-07-12 18:23
 */
@Slf4j
public abstract class AbstractProxyServer implements ProxyServer, ServerResource {
    private final ProxyConfigurer configurer;
    private ProxyProperties configProperties;
    private CertHolder certHolder;
    private SslContext clientSslContext;
    private CertFactory certFactory;
    private CertGenerator certGenerator;

    protected AbstractProxyServer(ProxyConfigurer configurer) {
        this.configurer = configurer;
        initConfig();
    }

    private void initConfig() {
        configProperties = new ProxyProperties();
        configurer.configure(configProperties);

        try {
            initCert();
        } catch (Exception e) {
            log.error("load cert error", e);
        }

        try {
            clientSslContext = SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE)
                    .build();
        } catch (SSLException e) {
            log.error("create client ssl context error", e);
        }

        certFactory = new CacheCertFactory(certHolder, certGenerator);
    }

    private void initCert() throws Exception {
        certGenerator = new DefaultCertGenerator();
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        X509Certificate caCert = CertUtil.loadCert(classLoader.getResourceAsStream(configProperties.getCaPath()));
        PrivateKey caPriKey = CertUtil.loadPriKey(classLoader.getResourceAsStream(configProperties.getCaPrivatePath()));
        KeyPair keyPair = certGenerator.generateKeyPair();
        PublicKey serverPubKey = keyPair.getPublic();
        PrivateKey serverPriKey = keyPair.getPrivate();
        certHolder = new CertHolder(caCert, caPriKey, serverPubKey, serverPriKey);
    }

    @Override
    public ProxyFilterChain getFilterChin(ProxyFilter finalFilter) {
        ProxyFilterRegistry filterRegistry = new ProxyFilterRegistry();
        configurer.registryProxyFilter(filterRegistry);
        List<ProxyFilterWrapper> proxyFilterWrappers = filterRegistry.getProxyFilterWrappers();
        if (finalFilter != null) {
            ProxyFilterWrapper filterWrapper = new ProxyFilterWrapper(finalFilter);
            proxyFilterWrappers.add(filterWrapper);
        }
        ProxyFilterWrapper[] filterWrappers = proxyFilterWrappers.toArray(new ProxyFilterWrapper[proxyFilterWrappers.size()]);
        ProxyFilterChain filterChain = new DefaultProxyFilterChain(filterWrappers);
        return filterChain;
    }

    @Override
    public CertHolder getCertHolder() {
        return certHolder;
    }

    @Override
    public ProxyProperties getConfigProperties() {
        return configProperties;
    }

    @Override
    public CertFactory getCertFactory() {
        return certFactory;
    }

    @Override
    public SslContext getClientSslContext() {
        return clientSslContext;
    }

    @Override
    public CertGenerator getCertGenerator() {
        return certGenerator;
    }
}
