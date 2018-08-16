package beldon.proxy.crt;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

public interface CertGenerator {

    /**
     * 默认获取密码对
     * algorithm为RSA
     * keySize为2048
     *
     * @return
     */
    KeyPair generateKeyPair();

    /**
     * 生成密码对
     *
     * @param algorithm 算法，RSA
     * @param keySize   the keysize ,如 1024、2048
     * @return
     */
    KeyPair generateKeyPair(String algorithm, int keySize) throws NoSuchAlgorithmException;

    /**
     * 生成密码对
     *
     * @param algorithm 算法，RSA
     * @param keySize   the keysize ,如 1024、2048
     * @param random    the source of randomness.
     * @return
     */
    KeyPair generateKeyPair(String algorithm, int keySize, SecureRandom random) throws NoSuchAlgorithmException;


    /**
     * 生成根证书
     *
     * @param privateKey
     * @param publicKey
     * @param sigAlgName
     * @param issuer
     * @param period     有效期
     * @return
     * @throws IOException
     * @throws OperatorCreationException
     */
    Certificate generateCA(PrivateKey privateKey, PublicKey publicKey, String sigAlgName, String issuer, long period) throws IOException, OperatorCreationException, CertificateException;

    /**
     * 成功根证书
     *
     * @param privateKey
     * @param publicKey
     * @param sigAlgName
     * @param issuer
     * @param notBefore
     * @param notAfter
     * @return
     * @throws IOException
     * @throws OperatorCreationException
     * @throws CertificateException
     */
    Certificate generateCA(PrivateKey privateKey, PublicKey publicKey, String sigAlgName, String issuer, Date notBefore, Date notAfter)
            throws IOException, OperatorCreationException, CertificateException;


    X509Certificate generateCert(PrivateKey rootPrivateKey, PublicKey publicKey, String sigAlgName, String issuer, String subject, Date notBefore, Date notAfter) throws CertificateException, OperatorCreationException, IOException;


    /**
     * 获取域名签名证书
     *
     * @param caPriKey
     * @param serverPubKey
     * @param sigAlgName   SHA256 用SHA1浏览器可能会提示证书不安全
     * @param issuer
     * @param sub
     * @param caNotBefore
     * @param caNotAfter
     * @param host
     * @return
     * @throws CertIOException
     * @throws CertificateException
     * @throws OperatorCreationException
     */
    X509Certificate generateCert(PrivateKey caPriKey, PublicKey serverPubKey, String sigAlgName, String issuer, String sub, Date caNotBefore, Date caNotAfter, String host)
            throws CertIOException, CertificateException, OperatorCreationException;
}
