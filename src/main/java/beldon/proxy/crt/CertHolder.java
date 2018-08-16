package beldon.proxy.crt;

import lombok.Data;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

@Data
public class CertHolder {
    private final X509Certificate caCert;
    private final PrivateKey caPriKey;
    private final PublicKey serverPubKey;
    private final PrivateKey serverPriKey;
}
