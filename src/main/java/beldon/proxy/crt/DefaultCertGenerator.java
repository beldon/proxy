package beldon.proxy.crt;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import sun.security.jca.JCAUtil;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

public class DefaultCertGenerator implements CertGenerator {

    static {
        Provider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
    }


    @Override
    public KeyPair generateKeyPair() {
        try {
            return generateKeyPair("RSA", 2048);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public KeyPair generateKeyPair(String algorithm, int keySize) throws NoSuchAlgorithmException {
        return generateKeyPair(algorithm, keySize, JCAUtil.getSecureRandom());
    }

    @Override
    public KeyPair generateKeyPair(String algorithm, int keySize, SecureRandom random) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm,"BC");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }

    @Override
    public Certificate generateCA(PrivateKey privateKey, PublicKey publicKey, String sigAlgName, String issuer, long period) throws IOException, OperatorCreationException, CertificateException {
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + period);
        return generateCA(privateKey, publicKey, sigAlgName, issuer, notBefore, notAfter);
    }

    @Override
    public Certificate generateCA(PrivateKey privateKey, PublicKey publicKey, String sigAlgName, String issuer, Date notBefore, Date notAfter)
            throws IOException, OperatorCreationException {
        return generateCertificate(publicKey, privateKey, sigAlgName, issuer, issuer, notBefore, notAfter);
    }

    @Override
    public X509Certificate generateCert(PrivateKey rootPrivateKey, PublicKey publicKey, String sigAlgName, String issuer, String subject, Date notBefore, Date notAfter)
            throws CertificateException, OperatorCreationException, IOException {
        return generateX509Certificate(publicKey, rootPrivateKey, sigAlgName, issuer, subject, notBefore, notAfter);

    }

    @Override
    public X509Certificate generateCert(PrivateKey caPriKey, PublicKey serverPubKey, String sigAlgName, String issuer, String subject, Date caNotBefore, Date caNotAfter, String host)
            throws CertIOException, CertificateException, OperatorCreationException {
        JcaX509v3CertificateBuilder jv3Builder = new JcaX509v3CertificateBuilder(new X500Name(issuer),
                BigInteger.valueOf(System.currentTimeMillis() + (long) (Math.random() * 10000) + 1000),
                caNotBefore,
                caNotAfter,
                new X500Name(subject),
                serverPubKey);
        //SAN扩展证书支持的域名，否则浏览器提示证书不安全
        GeneralName generalName = new GeneralName(GeneralName.dNSName, host);
        GeneralNames subjectAltName = new GeneralNames(generalName);
        jv3Builder.addExtension(Extension.subjectAlternativeName, false, subjectAltName);
        ContentSigner signer = new JcaContentSignerBuilder(sigAlgName).build(caPriKey);
        return new JcaX509CertificateConverter().getCertificate(jv3Builder.build(signer));
    }

    private X509Certificate generateX509Certificate(PublicKey publicKey, PrivateKey privateKey, String sigAlgName, String issuerDN, String subDN, Date notBefore, Date notAfter)
            throws IOException, OperatorCreationException, CertificateException {
        Certificate certificate = generateCertificate(publicKey, privateKey, sigAlgName, issuerDN, subDN, notBefore, notAfter);
        byte[] encoded = certificate.getEncoded();
        ByteArrayInputStream inStream = new ByteArrayInputStream(encoded);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certificateFactory.generateCertificate(inStream);
    }

    private Certificate generateCertificate(PublicKey publicKey, PrivateKey privateKey, String sigAlgName, String issuerDN, String subDN, Date notBefore, Date notAfter)
            throws IOException, OperatorCreationException {
        final AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(sigAlgName);
        final AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

        X500Name issuer = new X500Name(issuerDN);
//        BigInteger serial = BigInteger.TEN;
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis() + (long) (Math.random() * 10000) + 1000);
        X500Name subject = new X500Name(subDN);

        AsymmetricKeyParameter publicKeyParameter = PublicKeyFactory.createKey(publicKey.getEncoded());
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKeyParameter);

        X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, publicKeyInfo);
        BcRSAContentSignerBuilder contentSignerBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
        AsymmetricKeyParameter privateKeyParameter = PrivateKeyFactory.createKey(privateKey.getEncoded());
        ContentSigner contentSigner = contentSignerBuilder.build(privateKeyParameter);

        X509CertificateHolder certificateHolder = x509v3CertificateBuilder.build(contentSigner);
        return certificateHolder.toASN1Structure();
    }
}
