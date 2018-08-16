package beldon.proxy.crt;

import java.security.cert.X509Certificate;

/**
 * 证书生成工厂
 */
public interface CertFactory {

    /**
     * 根据域名生产证书
     *
     * @param host
     * @return
     */
    X509Certificate getCert(String host) throws Exception;

}
