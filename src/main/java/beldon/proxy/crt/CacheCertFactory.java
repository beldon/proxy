package beldon.proxy.crt;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class CacheCertFactory extends DefaultCertFactory {

    private Map<String, X509Certificate> caches = new ConcurrentHashMap<>();

    public CacheCertFactory(CertHolder certHolder,CertGenerator certGenerator) {
        super(certHolder, certGenerator);
    }

    @Override
    public X509Certificate getCert(String host) throws Exception {
        if (host == null || host.trim().equals("")) {
            return null;
        }
        String lowerCaseHost = host.toLowerCase();
        if (caches.containsKey(lowerCaseHost)) {
            return caches.get(lowerCaseHost);
        }
        X509Certificate cert = super.getCert(lowerCaseHost);
        caches.put(lowerCaseHost, cert);
        return cert;
    }
}
