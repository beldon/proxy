package beldon.proxy.crt;

import java.security.cert.X509Certificate;
import java.util.Date;

public class DefaultCertFactory implements CertFactory {


    private Date caNotBefore;

    private Date caNotAfter;

    private String caCertIssuer;

    private Subject issuerSubject;

    private CertHolder certHolder;

    private final CertGenerator certGenerator;


    public DefaultCertFactory(CertHolder certHolder,CertGenerator certGenerator) {
        this.certHolder = certHolder;
        this.certGenerator = certGenerator;
        loadData();
    }

    @Override
    public X509Certificate getCert(String host) throws Exception {
        if (host == null || host.trim().equals("")) {
            return null;
        }
        Subject clone = issuerSubject.clone();
        clone.setCn(host);
        String subject = clone.toString();
        return certGenerator.generateCert(certHolder.getCaPriKey(), certHolder.getServerPubKey(),
                "SHA256WithRSAEncryption", caCertIssuer, subject, caNotBefore, caNotAfter, host);
    }

    private void loadData() {
        this.issuerSubject = Subject.parse(certHolder.getCaCert().getIssuerDN().toString());
        caCertIssuer = issuerSubject.reverseToString();
        caNotBefore = certHolder.getCaCert().getNotBefore();
        caNotAfter = certHolder.getCaCert().getNotAfter();
    }

}
